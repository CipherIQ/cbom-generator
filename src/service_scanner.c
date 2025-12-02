// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * This file is part of cbom-generator.
 *
 * cbom-generator is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * For commercial licensing options, contact: sales@cipheriq.io
 */

/**
 * @file service_scanner.c
 * @brief Service scanner library functions
 *
 * This module provides protocol extraction, cipher suite parsing, and
 * relationship building functions used by the YAML plugin-driven service
 * discovery system (v1.3+).
 *
 * NOTE: As of v1.5, this is a LIBRARY module, not an active scanner.
 * Service detection is performed by YAML plugins (see plugins/ directory).
 * The functions in this file are called by component_factory.c to create
 * protocol, cipher suite, and algorithm assets from extracted config.
 *
 * @deprecated Built-in service scanner (detect_apache_service, etc.)
 *             These functions are kept for reference but no longer called.
 */

#define _GNU_SOURCE

#include "service_scanner.h"
#include "cipher_suite_parser.h"
#include "error_handling.h"
#include "secure_memory.h"
#include "asset_store.h"
#include "cbom_types.h"
#include "plugin_manager.h"
#include "pqc_classifier.h"
#include "algorithm_metadata.h"
#include "detection/library_detection.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <json-c/json.h>

// Global CBOM configuration from main.c (v1.8)
extern cbom_config_t g_cbom_config;

// Forward declarations for relationship helpers
int create_service_protocol_relationship(asset_store_t* store,
                                         const char* service_id,
                                         const char* protocol_id,
                                         float confidence);
int create_protocol_suite_relationship(asset_store_t* store,
                                       const char* protocol_id,
                                       const char* suite_id,
                                       float confidence);

// Thread-local error storage
static __thread char last_error[512] = {0};

// Known weak TLS versions
static const char* WEAK_TLS_VERSIONS[] = {
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1",
    NULL
};

// Known weak cipher suites
static const char* WEAK_CIPHERS[] = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "ADH", "AECDH",
    "MD5", "PSK",
    NULL
};

// Set error message
static void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(last_error, sizeof(last_error), format, args);
    va_end(args);
}

void service_scanner_clear_error(void) {
    last_error[0] = '\0';
}

const char* service_scanner_get_last_error(void) {
    return last_error[0] ? last_error : NULL;
}

// Convert enums to strings
const char* service_type_to_string(service_type_t type) {
    switch (type) {
        case SERVICE_TYPE_WEB_SERVER: return "web_server";
        case SERVICE_TYPE_HTTPS: return "https";
        case SERVICE_TYPE_MAIL_SERVER: return "mail_server";
        case SERVICE_TYPE_SMTP_TLS: return "smtp_tls";
        case SERVICE_TYPE_SMTPS: return "smtps";
        case SERVICE_TYPE_SSH_SERVER: return "ssh_server";
        case SERVICE_TYPE_VPN: return "vpn";
        case SERVICE_TYPE_DATABASE_TLS: return "database_tls";
        default: return "unknown";
    }
}

// Internal version - avoid conflict with protocol_mapping.c
static const char* protocol_type_to_str(protocol_type_t type) {
    switch (type) {
        case PROTOCOL_TYPE_TLS: return "TLS";
        case PROTOCOL_TYPE_SSH: return "SSH";
        case PROTOCOL_TYPE_IPSEC: return "IPsec";
        case PROTOCOL_TYPE_DTLS: return "DTLS";
        case PROTOCOL_TYPE_QUIC: return "QUIC";
        case PROTOCOL_TYPE_WIREGUARD: return "WireGuard";
        case PROTOCOL_TYPE_OPENVPN: return "OpenVPN";
        default: return "unknown";
    }
}

const char* security_profile_to_string(security_profile_t profile) {
    switch (profile) {
        case SECURITY_PROFILE_MODERN: return "MODERN";
        case SECURITY_PROFILE_INTERMEDIATE: return "INTERMEDIATE";
        case SECURITY_PROFILE_OLD: return "OLD";
        case SECURITY_PROFILE_CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

// Check if service is running
bool is_service_running(const char* daemon_name) {
    if (!daemon_name) return false;

    char command[256];
    snprintf(command, sizeof(command), "pgrep %s >/dev/null 2>&1", daemon_name);
    return system(command) == 0;
}

// Get service PID
pid_t get_service_pid(const char* daemon_name) {
    if (!daemon_name) return 0;

    char command[256];
    snprintf(command, sizeof(command), "pgrep -o %s 2>/dev/null", daemon_name);

    FILE* fp = popen(command, "r");
    if (!fp) return 0;

    pid_t pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) {
        pid = 0;
    }

    pclose(fp);
    return pid;
}

// Get service version
char* get_service_version(const char* daemon_name) {
    if (!daemon_name) return NULL;

    char command[256];
    char* version_arg = NULL;

    // Different daemons use different version flags
    if (strcmp(daemon_name, "apache2") == 0 || strcmp(daemon_name, "httpd") == 0) {
        version_arg = "-v";
    } else if (strcmp(daemon_name, "nginx") == 0) {
        version_arg = "-v";
    } else if (strcmp(daemon_name, "sshd") == 0) {
        version_arg = "-V";
    } else {
        version_arg = "--version";
    }

    snprintf(command, sizeof(command), "%s %s 2>&1 | head -1", daemon_name, version_arg);

    FILE* fp = popen(command, "r");
    if (!fp) return NULL;

    char buffer[256];
    char* version = NULL;

    if (fgets(buffer, sizeof(buffer), fp)) {
        // Extract version number (simplified)
        buffer[strcspn(buffer, "\n")] = 0;
        version = strdup(buffer);
    }

    pclose(fp);
    return version;
}

// Check if TLS version is weak
bool is_weak_tls_version(const char* version) {
    if (!version) return false;

    for (int i = 0; WEAK_TLS_VERSIONS[i] != NULL; i++) {
        if (strcasecmp(version, WEAK_TLS_VERSIONS[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Check if cipher suite is weak
bool is_weak_cipher_suite(const char* cipher) {
    if (!cipher) return false;

    for (int i = 0; WEAK_CIPHERS[i] != NULL; i++) {
        if (strcasestr(cipher, WEAK_CIPHERS[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// Classify TLS security profile
security_profile_t classify_tls_security_profile(const char** enabled_versions,
                                                size_t version_count,
                                                const char** enabled_ciphers,
                                                size_t cipher_count) {
    if (!enabled_versions || version_count == 0) {
        return SECURITY_PROFILE_UNKNOWN;
    }

    bool has_tls13 = false;
    bool has_tls12 = false;
    bool has_weak_version = false;
    bool has_weak_cipher = false;

    // Check versions
    for (size_t i = 0; i < version_count; i++) {
        if (strstr(enabled_versions[i], "1.3")) has_tls13 = true;
        if (strstr(enabled_versions[i], "1.2")) has_tls12 = true;
        if (is_weak_tls_version(enabled_versions[i])) has_weak_version = true;
    }

    // Check ciphers
    if (enabled_ciphers) {
        for (size_t i = 0; i < cipher_count; i++) {
            if (is_weak_cipher_suite(enabled_ciphers[i])) {
                has_weak_cipher = true;
                break;
            }
        }
    }

    // Classify
    if (has_tls13 && !has_weak_version && !has_weak_cipher) {
        return SECURITY_PROFILE_MODERN;
    } else if (has_tls12 && !has_weak_version) {
        return SECURITY_PROFILE_INTERMEDIATE;
    } else if (has_weak_version || has_weak_cipher) {
        return SECURITY_PROFILE_OLD;
    }

    return SECURITY_PROFILE_CUSTOM;
}

// Create default configuration
service_scanner_config_t service_scanner_create_default_config(void) {
    service_scanner_config_t config = {0};

    config.scan_running_processes = true;
    config.scan_config_files = true;
    config.scan_systemd = false;  // Deferred

    config.detect_web_servers = true;
    config.detect_mail_servers = true;
    config.detect_ssh_servers = true;
    config.detect_vpn_services = false;  // Deferred
    config.detect_databases = false;  // Deferred

    config.map_network_endpoints = true;
    config.link_endpoints_to_services = true;

    config.extract_protocols = true;
    config.centralize_tls = true;  // KEY FEATURE

    config.detect_weak_configs = true;
    config.classify_security_profile = true;

    config.max_services = 100;
    config.timeout_seconds = 30;

    config.include_fixtures = false;  // Testing only

    return config;
}

void service_scanner_config_destroy(service_scanner_config_t* config) {
    if (!config) return;
    memset(config, 0, sizeof(service_scanner_config_t));
}

// Create service scanner context
service_scanner_context_t* service_scanner_create(const service_scanner_config_t* config,
                                                 struct asset_store* store) {
    if (!config || !store) {
        set_error("Invalid parameters");
        return NULL;
    }

    service_scanner_context_t* context = secure_alloc(sizeof(service_scanner_context_t));
    if (!context) {
        set_error("Failed to allocate service scanner context");
        return NULL;
    }

    context->config = *config;
    context->asset_store = store;
    context->scan_context = NULL;
    memset(&context->stats, 0, sizeof(service_scanner_stats_t));

    if (pthread_mutex_init(&context->mutex, NULL) != 0) {
        set_error("Failed to initialize mutex");
        secure_free(context, sizeof(service_scanner_context_t));
        return NULL;
    }

    return context;
}

void service_scanner_destroy(service_scanner_context_t* context) {
    if (!context) return;

    pthread_mutex_destroy(&context->mutex);
    secure_zero(context, sizeof(service_scanner_context_t));
    secure_free(context, sizeof(service_scanner_context_t));
}

// Create service metadata
service_metadata_t* service_metadata_create(const char* name, service_type_t type) {
    if (!name) return NULL;

    service_metadata_t* metadata = secure_alloc(sizeof(service_metadata_t));
    if (!metadata) return NULL;

    memset(metadata, 0, sizeof(service_metadata_t));
    metadata->name = strdup(name);
    metadata->type = type;
    metadata->scan_time = time(NULL);

    return metadata;
}

void service_metadata_destroy(service_metadata_t* metadata) {
    if (!metadata) return;

    free(metadata->name);
    free(metadata->version);
    free(metadata->daemon_name);
    free(metadata->config_file_path);
    free(metadata->ssl_cert_path);
    free(metadata->ssl_key_path);
    free(metadata->ca_cert_path);

    if (metadata->additional_config_files) {
        for (size_t i = 0; i < metadata->config_file_count; i++) {
            free(metadata->additional_config_files[i]);
        }
        free(metadata->additional_config_files);
    }

    if (metadata->used_protocol_ids) {
        for (size_t i = 0; i < metadata->used_protocol_count; i++) {
            free(metadata->used_protocol_ids[i]);
        }
        free(metadata->used_protocol_ids);
    }

    if (metadata->endpoints) {
        for (size_t i = 0; i < metadata->endpoint_count; i++) {
            free(metadata->endpoints[i].address);
            free(metadata->endpoints[i].protocol);
        }
        free(metadata->endpoints);
    }

    secure_zero(metadata, sizeof(service_metadata_t));
    secure_free(metadata, sizeof(service_metadata_t));
}

// Create protocol metadata
protocol_metadata_t* protocol_metadata_create(const char* name, protocol_type_t type) {
    if (!name) return NULL;

    protocol_metadata_t* metadata = secure_alloc(sizeof(protocol_metadata_t));
    if (!metadata) return NULL;

    memset(metadata, 0, sizeof(protocol_metadata_t));
    metadata->name = strdup(name);
    metadata->type = type;
    metadata->scan_time = time(NULL);

    return metadata;
}

void protocol_metadata_destroy(protocol_metadata_t* metadata) {
    if (!metadata) return;

    free(metadata->name);
    free(metadata->version);
    free(metadata->config_file_path);

    if (metadata->supported_cipher_suites) {
        for (size_t i = 0; i < metadata->supported_cipher_count; i++) {
            free(metadata->supported_cipher_suites[i]);
        }
        free(metadata->supported_cipher_suites);
    }

    if (metadata->enabled_cipher_suites) {
        for (size_t i = 0; i < metadata->enabled_cipher_count; i++) {
            free(metadata->enabled_cipher_suites[i]);
        }
        free(metadata->enabled_cipher_suites);
    }

    if (metadata->supported_versions) {
        for (size_t i = 0; i < metadata->supported_version_count; i++) {
            free(metadata->supported_versions[i]);
        }
        free(metadata->supported_versions);
    }

    if (metadata->enabled_versions) {
        for (size_t i = 0; i < metadata->enabled_version_count; i++) {
            free(metadata->enabled_versions[i]);
        }
        free(metadata->enabled_versions);
    }

    if (metadata->deprecated_features) {
        for (size_t i = 0; i < metadata->deprecated_count; i++) {
            free(metadata->deprecated_features[i]);
        }
        free(metadata->deprecated_features);
    }

    if (metadata->supported_curves) {
        for (size_t i = 0; i < metadata->curve_count; i++) {
            free(metadata->supported_curves[i]);
        }
        free(metadata->supported_curves);
    }

    if (metadata->version_constraints.disabled_versions) {
        for (size_t i = 0; i < metadata->version_constraints.disabled_count; i++) {
            free(metadata->version_constraints.disabled_versions[i]);
        }
        free(metadata->version_constraints.disabled_versions);
    }

    if (metadata->weak_configurations.weak_items) {
        for (size_t i = 0; i < metadata->weak_configurations.weak_count; i++) {
            free(metadata->weak_configurations.weak_items[i]);
        }
        free(metadata->weak_configurations.weak_items);
    }

    if (metadata->supported_kex) {
        for (size_t i = 0; i < metadata->kex_count; i++) {
            free(metadata->supported_kex[i]);
        }
        free(metadata->supported_kex);
    }

    if (metadata->supported_hostkey) {
        for (size_t i = 0; i < metadata->hostkey_count; i++) {
            free(metadata->supported_hostkey[i]);
        }
        free(metadata->supported_hostkey);
    }

    if (metadata->supported_mac) {
        for (size_t i = 0; i < metadata->mac_count; i++) {
            free(metadata->supported_mac[i]);
        }
        free(metadata->supported_mac);
    }

    secure_zero(metadata, sizeof(protocol_metadata_t));
    secure_free(metadata, sizeof(protocol_metadata_t));
}

// Parse Apache configuration for TLS
service_metadata_t* parse_apache_config(const char* config_path) {
    if (!config_path) return NULL;

    FILE* fp = fopen(config_path, "r");
    if (!fp) return NULL;

    service_metadata_t* metadata = service_metadata_create("Apache HTTPD", SERVICE_TYPE_WEB_SERVER);
    if (!metadata) {
        fclose(fp);
        return NULL;
    }

    metadata->config_file_path = strdup(config_path);
    metadata->daemon_name = strdup("apache2");

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Extract SSL certificate path
        if (strstr(line, "SSLCertificateFile")) {
            char path[512];
            if (sscanf(line, " SSLCertificateFile %511s", path) == 1) {
                metadata->ssl_cert_path = strdup(path);
            }
        }
        // Extract SSL key path
        else if (strstr(line, "SSLCertificateKeyFile")) {
            char path[512];
            if (sscanf(line, " SSLCertificateKeyFile %511s", path) == 1) {
                metadata->ssl_key_path = strdup(path);
            }
        }
        // Extract Listen directive
        else if (strstr(line, "Listen")) {
            int port;
            if (sscanf(line, " Listen %d", &port) == 1) {
                if (!metadata->endpoints) {
                    metadata->endpoints = malloc(sizeof(network_endpoint_t) * 10);
                    metadata->endpoint_count = 0;
                }
                if (metadata->endpoint_count < 10) {
                    metadata->endpoints[metadata->endpoint_count].address = strdup("0.0.0.0");
                    metadata->endpoints[metadata->endpoint_count].port = port;
                    metadata->endpoints[metadata->endpoint_count].protocol = strdup("tcp");
                    metadata->endpoints[metadata->endpoint_count].is_encrypted = (port == 443);
                    metadata->endpoint_count++;
                }
            }
        }
    }

    fclose(fp);
    return metadata;
}

// Parse Nginx configuration for TLS
service_metadata_t* parse_nginx_config(const char* config_path) {
    if (!config_path) return NULL;

    FILE* fp = fopen(config_path, "r");
    if (!fp) return NULL;

    service_metadata_t* metadata = service_metadata_create("Nginx", SERVICE_TYPE_WEB_SERVER);
    if (!metadata) {
        fclose(fp);
        return NULL;
    }

    metadata->config_file_path = strdup(config_path);
    metadata->daemon_name = strdup("nginx");

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Extract SSL certificate
        if (strstr(line, "ssl_certificate ")) {
            char path[512];
            if (sscanf(line, " ssl_certificate %511s", path) == 1) {
                // Remove trailing semicolon if present (Issue #3 fix)
                size_t len = strlen(path);
                if (len > 0 && path[len-1] == ';') {
                    path[len-1] = '\0';
                }
                metadata->ssl_cert_path = strdup(path);
            }
        }
        // Extract SSL key
        else if (strstr(line, "ssl_certificate_key")) {
            char path[512];
            if (sscanf(line, " ssl_certificate_key %511s;", path) == 1) {
                metadata->ssl_key_path = strdup(path);
            }
        }
        // Extract listen directive
        else if (strstr(line, "listen")) {
            int port;
            if (sscanf(line, " listen %d", &port) == 1) {
                if (!metadata->endpoints) {
                    metadata->endpoints = malloc(sizeof(network_endpoint_t) * 10);
                    metadata->endpoint_count = 0;
                }
                if (metadata->endpoint_count < 10) {
                    metadata->endpoints[metadata->endpoint_count].address = strdup("0.0.0.0");
                    metadata->endpoints[metadata->endpoint_count].port = port;
                    metadata->endpoints[metadata->endpoint_count].protocol = strdup("tcp");
                    metadata->endpoints[metadata->endpoint_count].is_encrypted = (port == 443);
                    metadata->endpoint_count++;
                }
            }
        }
    }

    fclose(fp);
    return metadata;
}

// Parse OpenSSH configuration
service_metadata_t* parse_sshd_config(const char* config_path) {
    if (!config_path) return NULL;

    FILE* fp = fopen(config_path, "r");
    if (!fp) return NULL;

    service_metadata_t* metadata = service_metadata_create("OpenSSH", SERVICE_TYPE_SSH_SERVER);
    if (!metadata) {
        fclose(fp);
        return NULL;
    }

    metadata->config_file_path = strdup(config_path);
    metadata->daemon_name = strdup("sshd");

    char line[1024];
    int default_port = 22;
    char kex_algorithms[1024] = {0};

    while (fgets(line, sizeof(line), fp)) {
        // Extract Port directive
        if (strncmp(line, "Port ", 5) == 0) {
            sscanf(line, "Port %d", &default_port);
        }
        // Extract KexAlgorithms directive
        else if (strstr(line, "KexAlgorithms") && !strstr(line, "#")) {
            char* algo_start = strchr(line, ' ');
            if (algo_start) {
                algo_start++;
                strncpy(kex_algorithms, algo_start, sizeof(kex_algorithms) - 1);
                // Remove trailing newline
                char* newline = strchr(kex_algorithms, '\n');
                if (newline) *newline = '\0';
                char* cr = strchr(kex_algorithms, '\r');
                if (cr) *cr = '\0';
            }
        }
    }

    fclose(fp);

    // Store KEX algorithms in metadata for later component creation
    if (strlen(kex_algorithms) > 0) {
        // Store in custom_data field (assuming it exists in service_metadata_t)
        // metadata->kex_algorithms = strdup(kex_algorithms);
        // For now, we'll process it in the scan function
    }

    // Add SSH endpoint
    metadata->endpoints = malloc(sizeof(network_endpoint_t));
    if (metadata->endpoints) {
        metadata->endpoints[0].address = strdup("0.0.0.0");
        metadata->endpoints[0].port = default_port;
        metadata->endpoints[0].protocol = strdup("tcp");
        metadata->endpoints[0].is_encrypted = true;
        metadata->endpoint_count = 1;
    }

    return metadata;
}

// Scan user SSH client configurations (~/.ssh/config files)
// Privacy-aware: only enabled when include_personal_data is set, redacts full paths
int scan_user_ssh_configs(service_scanner_context_t* context) {
    if (!context || !context->asset_store) return -1;
    if (!context->config.include_personal_data) return 0;  // Only when personal data is included

    DIR* home_dir = opendir("/home");
    if (!home_dir) return 0;  // /home not accessible

    int configs_found = 0;
    struct dirent* entry;

    while ((entry = readdir(home_dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Build path to user's .ssh/config
        char user_config_path[512];
        snprintf(user_config_path, sizeof(user_config_path),
                "/home/%s/.ssh/config", entry->d_name);

        // Check if file exists and is readable
        if (access(user_config_path, R_OK) != 0) {
            continue;
        }

        // Parse user's SSH client config
        protocol_metadata_t* ssh_user_protocol = parse_ssh_client_config(user_config_path);
        if (ssh_user_protocol && context->asset_store) {
            // Privacy-aware: use redacted path format and mark as user-specific
            free(ssh_user_protocol->config_file_path);
            char privacy_path[512];
            snprintf(privacy_path, sizeof(privacy_path),
                    "<user-%s>/.ssh/config", entry->d_name);
            ssh_user_protocol->config_file_path = strdup(privacy_path);

            // Update usage to include username for unique ID
            free(ssh_user_protocol->usage);
            char usage_string[512];
            snprintf(usage_string, sizeof(usage_string), "client-user-%s", entry->d_name);
            ssh_user_protocol->usage = strdup(usage_string);

            crypto_asset_t* user_protocol_asset = protocol_create_asset(ssh_user_protocol);
            if (user_protocol_asset) {
                asset_store_add(context->asset_store, user_protocol_asset);

                // Extract KEX algorithms from user config
                if (ssh_user_protocol->kex_count > 0) {
                    for (size_t i = 0; i < ssh_user_protocol->kex_count; i++) {
                        const char* kex_name = ssh_user_protocol->supported_kex[i];

                        // Create algorithm component for KEX algorithm
                        crypto_asset_t* kex_algo = crypto_asset_create(kex_name, ASSET_TYPE_ALGORITHM);
                        if (kex_algo) {
                            kex_algo->location = strdup(privacy_path);
                            kex_algo->algorithm = strdup(kex_name);

                            // Populate metadata_json with CycloneDX algorithmProperties
                            char* metadata = algorithm_populate_cdx_metadata(
                                kex_algo->metadata_json,
                                kex_name,
                                ALGO_CONTEXT_CIPHER_SUITE
                            );
                            if (metadata) {
                                if (kex_algo->metadata_json) free(kex_algo->metadata_json);
                                kex_algo->metadata_json = metadata;
                            }

                            // Add to asset store
                            asset_store_add(context->asset_store, kex_algo);

                            // Create PROTOCOL → ALGORITHM relationship
                            relationship_t* rel = relationship_create(
                                RELATIONSHIP_USES,
                                user_protocol_asset->id,
                                kex_algo->id,
                                0.90  // Slightly lower confidence for user configs
                            );
                            if (rel) {
                                asset_store_add_relationship(context->asset_store, rel);
                            }
                        }
                    }
                }

                configs_found++;

                pthread_mutex_lock(&context->mutex);
                context->stats.protocols_extracted++;
                pthread_mutex_unlock(&context->mutex);
            }
            protocol_metadata_destroy(ssh_user_protocol);
        }
    }

    closedir(home_dir);
    return configs_found;
}

// Parse SSH client configuration (/etc/ssh/ssh_config or ~/.ssh/config)
protocol_metadata_t* parse_ssh_client_config(const char* config_path) {
    if (!config_path) return NULL;

    FILE* fp = fopen(config_path, "r");
    if (!fp) return NULL;

    // Create protocol metadata for SSH client
    protocol_metadata_t* protocol = calloc(1, sizeof(protocol_metadata_t));
    if (!protocol) {
        fclose(fp);
        return NULL;
    }

    protocol->type = PROTOCOL_TYPE_SSH;
    protocol->name = strdup("SSH");
    protocol->version = strdup("2.0");
    protocol->usage = strdup("client");
    protocol->config_file_path = strdup(config_path);

    char line[1024];
    char kex_algorithms[2048] = {0};
    char ciphers[2048] = {0};
    char macs[2048] = {0};
    char hostkey_algorithms[2048] = {0};

    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        // Extract KexAlgorithms directive
        if (strstr(line, "KexAlgorithms") && !strstr(line, "#")) {
            // Find "KexAlgorithms" keyword first, then find space after it
            char* kex_keyword = strstr(line, "KexAlgorithms");
            if (kex_keyword) {
                char* algo_start = strchr(kex_keyword, ' ');
                if (algo_start) {
                    algo_start++;
                    // Skip whitespace
                    while (*algo_start == ' ' || *algo_start == '\t') algo_start++;

                strncat(kex_algorithms, algo_start, sizeof(kex_algorithms) - strlen(kex_algorithms) - 1);
                // Remove trailing newline
                char* newline = strchr(kex_algorithms, '\n');
                if (newline) *newline = '\0';
                char* cr = strchr(kex_algorithms, '\r');
                if (cr) *cr = '\0';

                // Add comma separator if we already have algorithms
                if (strlen(kex_algorithms) > 0 && kex_algorithms[strlen(kex_algorithms)-1] != ',') {
                    strncat(kex_algorithms, ",", sizeof(kex_algorithms) - strlen(kex_algorithms) - 1);
                }
            }
        }
        }
        // Extract Ciphers directive
        else if (strstr(line, "Ciphers") && !strstr(line, "#")) {
            char* algo_start = strchr(line, ' ');
            if (algo_start) {
                algo_start++;
                while (*algo_start == ' ' || *algo_start == '\t') algo_start++;

                strncat(ciphers, algo_start, sizeof(ciphers) - strlen(ciphers) - 1);
                char* newline = strchr(ciphers, '\n');
                if (newline) *newline = '\0';
                char* cr = strchr(ciphers, '\r');
                if (cr) *cr = '\0';
            }
        }
        // Extract MACs directive
        else if (strstr(line, "MACs") && !strstr(line, "#")) {
            char* algo_start = strchr(line, ' ');
            if (algo_start) {
                algo_start++;
                while (*algo_start == ' ' || *algo_start == '\t') algo_start++;

                strncat(macs, algo_start, sizeof(macs) - strlen(macs) - 1);
                char* newline = strchr(macs, '\n');
                if (newline) *newline = '\0';
                char* cr = strchr(macs, '\r');
                if (cr) *cr = '\0';
            }
        }
        // Extract HostKeyAlgorithms directive
        else if (strstr(line, "HostKeyAlgorithms") && !strstr(line, "#")) {
            char* algo_start = strchr(line, ' ');
            if (algo_start) {
                algo_start++;
                while (*algo_start == ' ' || *algo_start == '\t') algo_start++;

                strncat(hostkey_algorithms, algo_start, sizeof(hostkey_algorithms) - strlen(hostkey_algorithms) - 1);
                char* newline = strchr(hostkey_algorithms, '\n');
                if (newline) *newline = '\0';
                char* cr = strchr(hostkey_algorithms, '\r');
                if (cr) *cr = '\0';
            }
        }
    }

    fclose(fp);

    // Parse KEX algorithms into array
    if (strlen(kex_algorithms) > 0) {
        // Count algorithms
        size_t count = 1;
        for (char* p = kex_algorithms; *p; p++) {
            if (*p == ',') count++;
        }

        protocol->supported_kex = malloc(count * sizeof(char*));
        protocol->kex_count = 0;

        char* algo_copy = strdup(kex_algorithms);
        char* token = strtok(algo_copy, ",");
        while (token && protocol->kex_count < count) {
            // Trim whitespace
            while (*token == ' ' || *token == '\t') token++;
            char* end = token + strlen(token) - 1;
            while (end > token && (*end == ' ' || *end == '\t')) {
                *end = '\0';
                end--;
            }

            if (strlen(token) > 0) {
                protocol->supported_kex[protocol->kex_count++] = strdup(token);
            }
            token = strtok(NULL, ",");
        }
        free(algo_copy);
    }

    return protocol;
}

// Parse Postfix configuration
service_metadata_t* parse_postfix_config(const char* config_path) {
    if (!config_path) return NULL;

    FILE* fp = fopen(config_path, "r");
    if (!fp) return NULL;

    service_metadata_t* metadata = service_metadata_create("Postfix", SERVICE_TYPE_MAIL_SERVER);
    if (!metadata) {
        fclose(fp);
        return NULL;
    }

    metadata->config_file_path = strdup(config_path);
    metadata->daemon_name = strdup("postfix");

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Extract TLS certificate
        if (strstr(line, "smtpd_tls_cert_file")) {
            char path[512];
            if (sscanf(line, " smtpd_tls_cert_file = %511s", path) == 1) {
                metadata->ssl_cert_path = strdup(path);
            }
        }
        // Extract TLS key
        else if (strstr(line, "smtpd_tls_key_file")) {
            char path[512];
            if (sscanf(line, " smtpd_tls_key_file = %511s", path) == 1) {
                metadata->ssl_key_path = strdup(path);
            }
        }
    }

    fclose(fp);

    // Add SMTP endpoints
    metadata->endpoints = malloc(sizeof(network_endpoint_t) * 2);
    if (metadata->endpoints) {
        metadata->endpoints[0].address = strdup("0.0.0.0");
        metadata->endpoints[0].port = 25;  // SMTP
        metadata->endpoints[0].protocol = strdup("tcp");
        metadata->endpoints[0].is_encrypted = false;  // STARTTLS

        metadata->endpoints[1].address = strdup("0.0.0.0");
        metadata->endpoints[1].port = 587;  // Submission with TLS
        metadata->endpoints[1].protocol = strdup("tcp");
        metadata->endpoints[1].is_encrypted = true;

        metadata->endpoint_count = 2;
    }

    return metadata;
}

// Extract TLS protocol from configuration (CENTRALIZATION)
protocol_metadata_t* extract_tls_protocol(const char* config_path, const char* service_name) {
    if (!config_path) return NULL;

    // service_name parameter reserved for service-specific protocol extraction
    (void)service_name;

    protocol_metadata_t* protocol = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
    if (!protocol) return NULL;

    protocol->config_file_path = strdup(config_path);
    protocol->detection_method = DETECT_METHOD_CONFIG_FILE;
    protocol->confidence = 0.9;

    // Parse configuration for TLS settings
    FILE* fp = fopen(config_path, "r");
    if (!fp) {
        protocol_metadata_destroy(protocol);
        return NULL;
    }

    char line[1024];
    protocol->enabled_cipher_suites = malloc(sizeof(char*) * 50);
    protocol->enabled_versions = malloc(sizeof(char*) * 10);
    protocol->enabled_cipher_count = 0;
    protocol->enabled_version_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Apache-style SSL protocol
        if (strstr(line, "SSLProtocol")) {
            // Extract versions (e.g., "SSLProtocol all -SSLv3 -TLSv1")
            if (strstr(line, "TLSv1.3")) {
                protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.3");
            }
            if (strstr(line, "TLSv1.2") && !strstr(line, "-TLSv1.2")) {
                protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.2");
            }
        }
        // Nginx-style SSL protocols
        else if (strstr(line, "ssl_protocols")) {
            if (strstr(line, "TLSv1.3")) {
                protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.3");
            }
            if (strstr(line, "TLSv1.2")) {
                protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.2");
            }
        }
        // Extract cipher suites (Phase 7.3b - parse actual list)
        else if (strstr(line, "SSLCipherSuite")) {
            char cipher_list[1024];
            if (sscanf(line, " SSLCipherSuite %1023[^\n]", cipher_list) == 1) {
                // Store raw cipher list for later parsing
                if (protocol->enabled_cipher_count == 0) {
                    protocol->enabled_cipher_suites = malloc(sizeof(char*));
                    protocol->enabled_cipher_suites[0] = strdup(cipher_list);
                    protocol->enabled_cipher_count = 1;
                }
            }
        }
        else if (strstr(line, "ssl_ciphers")) {
            char cipher_list[1024];
            if (sscanf(line, " ssl_ciphers %1023[^;];", cipher_list) == 1) {
                // Store raw cipher list for later parsing
                if (protocol->enabled_cipher_count == 0) {
                    protocol->enabled_cipher_suites = malloc(sizeof(char*));
                    protocol->enabled_cipher_suites[0] = strdup(cipher_list);
                    protocol->enabled_cipher_count = 1;
                }
            }
        }
    }

    fclose(fp);

    // If parsing nginx config but no SSL settings found, check nginx.conf as fallback
    if (protocol->enabled_version_count == 0 && strstr(config_path, "nginx")) {
        const char* nginx_main_configs[] = {
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/ssl.conf",
            NULL
        };

        for (int i = 0; nginx_main_configs[i] != NULL; i++) {
            // Skip if same as original config
            if (strcmp(config_path, nginx_main_configs[i]) == 0) continue;

            FILE* main_fp = fopen(nginx_main_configs[i], "r");
            if (!main_fp) continue;

            while (fgets(line, sizeof(line), main_fp)) {
                if (strstr(line, "ssl_protocols")) {
                    if (strstr(line, "TLSv1.3")) {
                        protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.3");
                    }
                    if (strstr(line, "TLSv1.2")) {
                        protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.2");
                    }
                }
                else if (strstr(line, "ssl_ciphers") && protocol->enabled_cipher_count == 0) {
                    char cipher_list[1024];
                    if (sscanf(line, " ssl_ciphers %1023[^;];", cipher_list) == 1) {
                        protocol->enabled_cipher_suites = malloc(sizeof(char*));
                        protocol->enabled_cipher_suites[0] = strdup(cipher_list);
                        protocol->enabled_cipher_count = 1;
                    }
                }
            }
            fclose(main_fp);

            if (protocol->enabled_version_count > 0) break;  // Found settings, stop searching
        }
    }

    // Default to TLS 1.2 if nothing found
    if (protocol->enabled_version_count == 0) {
        protocol->enabled_versions[protocol->enabled_version_count++] = strdup("TLSv1.2");
    }

    // Classify security profile
    protocol->security_profile = classify_tls_security_profile(
        (const char**)protocol->enabled_versions,
        protocol->enabled_version_count,
        (const char**)protocol->enabled_cipher_suites,
        protocol->enabled_cipher_count);

    // Detect weak configurations
    protocol->weak_configurations.weak_items = malloc(sizeof(char*) * 20);
    protocol->weak_configurations.weak_count = 0;

    for (size_t i = 0; i < protocol->enabled_version_count; i++) {
        if (is_weak_tls_version(protocol->enabled_versions[i])) {
            if (protocol->weak_configurations.weak_count < 20) {
                char* weak_item = malloc(128);
                snprintf(weak_item, 128, "Weak TLS version: %s", protocol->enabled_versions[i]);
                protocol->weak_configurations.weak_items[protocol->weak_configurations.weak_count++] = weak_item;
                protocol->weak_configurations.uses_weak_hash = true;
            }
        }
    }

    for (size_t i = 0; i < protocol->enabled_cipher_count; i++) {
        if (is_weak_cipher_suite(protocol->enabled_cipher_suites[i])) {
            if (protocol->weak_configurations.weak_count < 20) {
                char* weak_item = malloc(128);
                snprintf(weak_item, 128, "Weak cipher: %s", protocol->enabled_cipher_suites[i]);
                protocol->weak_configurations.weak_items[protocol->weak_configurations.weak_count++] = weak_item;
                protocol->weak_configurations.allows_weak_ciphers = true;
            }
        }
    }

    return protocol;
}

// Extract SSH protocol from sshd_config
protocol_metadata_t* extract_ssh_protocol(const char* config_path) {
    if (!config_path) return NULL;

    protocol_metadata_t* protocol = protocol_metadata_create("SSH", PROTOCOL_TYPE_SSH);
    if (!protocol) return NULL;

    protocol->config_file_path = strdup(config_path);
    protocol->detection_method = DETECT_METHOD_CONFIG_FILE;
    protocol->confidence = 0.9;

    FILE* fp = fopen(config_path, "r");
    if (!fp) {
        protocol_metadata_destroy(protocol);
        return NULL;
    }

    char line[1024];
    protocol->supported_kex = malloc(sizeof(char*) * 20);
    protocol->supported_hostkey = malloc(sizeof(char*) * 20);
    protocol->supported_mac = malloc(sizeof(char*) * 20);
    protocol->kex_count = 0;
    protocol->hostkey_count = 0;
    protocol->mac_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Key exchange algorithms
        if (strncmp(line, "KexAlgorithms ", 14) == 0) {
            char* algos = line + 14;
            // Simplified parsing
            if (strstr(algos, "curve25519")) {
                protocol->supported_kex[protocol->kex_count++] = strdup("curve25519-sha256");
            }
            if (strstr(algos, "ecdh")) {
                protocol->supported_kex[protocol->kex_count++] = strdup("ecdh-sha2-nistp256");
            }
        }
        // Host key algorithms
        else if (strncmp(line, "HostKeyAlgorithms ", 18) == 0) {
            char* algos = line + 18;
            if (strstr(algos, "rsa")) {
                protocol->supported_hostkey[protocol->hostkey_count++] = strdup("rsa-sha2-512");
            }
            if (strstr(algos, "ed25519")) {
                protocol->supported_hostkey[protocol->hostkey_count++] = strdup("ssh-ed25519");
            }
        }
        // MAC algorithms
        else if (strncmp(line, "MACs ", 5) == 0) {
            char* algos = line + 5;
            if (strstr(algos, "hmac-sha2-256")) {
                protocol->supported_mac[protocol->mac_count++] = strdup("hmac-sha2-256");
            }
        }
    }

    fclose(fp);

    // Set default SSH version
    protocol->version = strdup("2.0");
    protocol->enabled_version_count = 1;
    protocol->enabled_versions = malloc(sizeof(char*));
    protocol->enabled_versions[0] = strdup("2.0");

    protocol->security_profile = SECURITY_PROFILE_MODERN;

    // Mark as server usage (extracted from sshd_config)
    protocol->usage = strdup("server");

    return protocol;
}

// Parse /proc/net/tcp for listening ports
network_endpoint_t* parse_proc_net_tcp(size_t* count) {
    if (!count) return NULL;

    FILE* fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        *count = 0;
        return NULL;
    }

    network_endpoint_t* endpoints = malloc(sizeof(network_endpoint_t) * 100);
    if (!endpoints) {
        fclose(fp);
        *count = 0;
        return NULL;
    }

    *count = 0;
    char line[512];

    // Skip header
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return NULL;
    }

    while (fgets(line, sizeof(line), fp) && *count < 100) {
        unsigned int local_addr, local_port;
        unsigned int state;

        // Parse format: sl local_address rem_address st
        if (sscanf(line, "%*d: %X:%X %*X:%*X %X", &local_addr, &local_port, &state) == 3) {
            // State 0A = LISTEN
            if (state == 0x0A) {
                endpoints[*count].address = malloc(16);
                snprintf(endpoints[*count].address, 16, "%u.%u.%u.%u",
                        local_addr & 0xFF,
                        (local_addr >> 8) & 0xFF,
                        (local_addr >> 16) & 0xFF,
                        (local_addr >> 24) & 0xFF);
                endpoints[*count].port = local_port;
                endpoints[*count].protocol = strdup("tcp");
                endpoints[*count].is_encrypted = (local_port == 443 || local_port == 22 ||
                                                 local_port == 465 || local_port == 993 ||
                                                 local_port == 995);
                (*count)++;
            }
        }
    }

    fclose(fp);
    return endpoints;
}

// ============================================================================
// Service → Library Dependency Detection (Application Library Dependencies Gap)
// ============================================================================

// Crypto library patterns for filtering
static const char* CRYPTO_LIBRARY_PATTERNS[] = {
    "libssl", "libcrypto", "libgnutls", "libgcrypt",
    "libsodium", "libnettle", "libnss", "libnspr",
    "libbotan", "libwolfssl", "libmbedtls", "libtomcrypt",
    NULL
};

/**
 * Check if library name matches crypto library patterns
 */
static bool is_crypto_library_name(const char* lib_name) {
    if (!lib_name) return false;

    for (int i = 0; CRYPTO_LIBRARY_PATTERNS[i]; i++) {
        if (strstr(lib_name, CRYPTO_LIBRARY_PATTERNS[i])) {
            return true;
        }
    }
    return false;
}

/**
 * Get binary executable path for a service
 * Method 1: From PID if service is running
 * Method 2: Search common paths for daemon_name
 */
static char* get_binary_path_for_service(const service_metadata_t* metadata) {
    if (!metadata) return NULL;

    // v1.8.1: Check for rootfs prefix in cross-arch mode
    const char* rootfs_prefix = g_cbom_config.rootfs_prefix;
    bool cross_arch = g_cbom_config.cross_arch_mode || (rootfs_prefix && rootfs_prefix[0]);

    // Method 1: From PID if running (skip in cross-arch mode - host process not relevant)
    if (!cross_arch && metadata->is_running && metadata->daemon_pid > 0) {
        char proc_path[64];
        char exe_path[PATH_MAX];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", metadata->daemon_pid);
        ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            return strdup(exe_path);
        }
    }

    // Method 2: Known daemon paths
    if (metadata->daemon_name) {
        // Check if daemon_name is already a full path (starts with '/')
        if (metadata->daemon_name[0] == '/') {
            char full_path[PATH_MAX];
            if (cross_arch && rootfs_prefix) {
                // Prepend rootfs_prefix to the absolute path
                snprintf(full_path, sizeof(full_path), "%s%s", rootfs_prefix, metadata->daemon_name);
            } else {
                snprintf(full_path, sizeof(full_path), "%s", metadata->daemon_name);
            }
            // Verify file exists (use F_OK for cross-arch, X_OK for host)
            if (access(full_path, cross_arch ? F_OK : X_OK) == 0) {
                return strdup(full_path);
            }
            // Path doesn't exist or isn't executable
            return NULL;
        }

        // Not a full path - search in standard directories
        const char* search_dirs[] = {"/usr/sbin", "/usr/bin", "/sbin", "/bin", NULL};
        for (int i = 0; search_dirs[i]; i++) {
            char path[PATH_MAX];
            if (cross_arch && rootfs_prefix) {
                // Prepend rootfs_prefix: e.g., "/mnt/rootfs" + "/usr/sbin" + "/" + "sshd"
                snprintf(path, sizeof(path), "%s%s/%s", rootfs_prefix, search_dirs[i], metadata->daemon_name);
            } else {
                snprintf(path, sizeof(path), "%s/%s", search_dirs[i], metadata->daemon_name);
            }
            // Use F_OK for cross-arch (file exists), X_OK for host (executable)
            if (access(path, cross_arch ? F_OK : X_OK) == 0) {
                return strdup(path);
            }
        }
    }

    return NULL;
}

/**
 * Find library asset by shared object name (fuzzy match)
 * Maps: libssl.so.3 → library asset with name "libssl3" or "libssl1-1"
 * Handles SO aliases: libcrypto.so → libssl (both provided by libssl package)
 * Non-static for use by application_scanner.c
 */
const char* find_library_by_soname(asset_store_t* store, const char* soname) {
    if (!store || !soname) return NULL;

    // Extract base name (libssl.so.3 → libssl)
    char base_name[128];
    strncpy(base_name, soname, sizeof(base_name) - 1);
    base_name[sizeof(base_name) - 1] = '\0';

    char* dot_so = strstr(base_name, ".so");
    if (dot_so) *dot_so = '\0';

    // SO name → package name mapping for common aliases
    // Many packages provide multiple .so files under one package name
    static const struct {
        const char* so_name;
        const char* package_base;
    } so_name_mappings[] = {
        {"libcrypto", "libssl"},        // libcrypto.so.3 provided by libssl3 package
        {"libmbedcrypto", "libmbedtls"}, // Mbed TLS components
        {"libmbedx509", "libmbedtls"},
        {NULL, NULL}
    };

    // Try with mapped name first
    const char* search_name = base_name;
    for (int i = 0; so_name_mappings[i].so_name; i++) {
        if (strcmp(base_name, so_name_mappings[i].so_name) == 0) {
            search_name = so_name_mappings[i].package_base;
            break;
        }
    }

    // Search asset store for matching library
    size_t count;
    crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &count);
    if (!assets) return NULL;

    const char* result = NULL;
    for (size_t i = 0; i < count; i++) {
        if (assets[i]->type == ASSET_TYPE_LIBRARY && assets[i]->name) {
            // Fuzzy match: "libssl3" contains "libssl", "libssl1-1" contains "libssl"
            if (strstr(assets[i]->name, search_name)) {
                result = assets[i]->id;
                break;
            }
        }
    }

    // If mapped name didn't work, try original base_name
    if (!result && search_name != base_name) {
        for (size_t i = 0; i < count; i++) {
            if (assets[i]->type == ASSET_TYPE_LIBRARY && assets[i]->name) {
                if (strstr(assets[i]->name, base_name)) {
                    result = assets[i]->id;
                    break;
                }
            }
        }
    }

    free(assets);
    return result;
}

/**
 * Detect library dependencies for a service binary using ldd
 * Creates DEPENDS_ON relationships from service to crypto libraries
 * Returns number of library dependencies found
 */
int detect_service_library_dependencies(service_scanner_context_t* context,
                                       crypto_asset_t* service_asset,
                                       const service_metadata_t* metadata) {
    if (!context || !service_asset || !metadata) return -1;

    char* binary_path = get_binary_path_for_service(metadata);
    if (!binary_path) return 0;  // Binary not found

    // Analyze binary using registry-driven helper
    binary_crypto_profile_t* profile = analyze_binary_crypto(binary_path);
    if (profile && profile->libs_count > 0) {
        int libs_found = 0;

        // v1.8.6: Include ALL libraries by default (not just crypto)
        // v1.8.6: Use atomic get-or-create to fix race condition
        for (size_t i = 0; i < profile->libs_count; i++) {
            if (!profile->libs[i].soname) {
                continue;  // Must have SONAME
            }

            // v1.8.6: include_all_dependencies defaults to true
            bool include_this_lib = profile->libs[i].is_crypto ||
                                    g_cbom_config.include_all_dependencies;
            if (!include_this_lib) continue;

            // Atomic get-or-create to prevent race conditions
            bool was_created = false;
            const char* lib_id = asset_store_get_or_create_library(
                context->asset_store,
                profile->libs[i].soname,
                profile->libs[i].resolved_path,
                &was_created);

            // v1.9.2: ALWAYS process crypto libraries (even if not newly created)
            // to ensure algorithm components and PROVIDES relationships are created.
            // The TOCTOU fix (v1.8.6) was too aggressive - it skipped algorithm creation
            // for libraries already registered by Phase 4.5 service discovery.
            if (lib_id) {
                crypto_asset_t* lib_asset = asset_store_find(context->asset_store, lib_id);
                if (lib_asset) {
                    if (profile->libs[i].is_crypto) {
                        // Populate cbom:lib: properties from crypto_registry (idempotent)
                        populate_library_metadata(lib_asset, &profile->libs[i], NULL);

                        // Create PROVIDES relationships for implemented algorithms
                        // Both asset_store_add and asset_store_add_relationship handle duplicates
                        create_library_algorithm_relationships(context->asset_store,
                                                               lib_asset,
                                                               &profile->libs[i]);
                    } else if (was_created) {
                        // Non-crypto library - minimal metadata only when newly created (v1.8)
                        struct json_object* meta = json_object_new_object();
                        if (meta) {
                            json_object_object_add(meta, "name",
                                json_object_new_string(profile->libs[i].soname));
                            json_object_object_add(meta, "type",
                                json_object_new_string("system"));
                            const char* meta_str = json_object_to_json_string(meta);
                            if (meta_str) {
                                lib_asset->metadata_json = strdup(meta_str);
                            }
                            json_object_put(meta);
                        }
                    }
                }
            }

            if (lib_id) {
                int result = create_service_library_relationship(context->asset_store,
                                                                 service_asset->id,
                                                                 lib_id,
                                                                 0.90);
                if (result == 0) {
                    libs_found++;
                }
            }
        }

        // Register embedded providers as components + relationships
        register_embedded_providers_for_asset(context->asset_store, service_asset, profile);

        free_binary_crypto_profile(profile);
        free(binary_path);
        return libs_found;
    }

    // Run ldd on the binary (with shell escaping for safety)
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ldd '%s' 2>/dev/null", binary_path);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        free(binary_path);
        return -1;
    }

    char line[1024];
    int libs_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Parse ldd output: "libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)"
        char lib_name[256] = {0};
        char lib_path[512] = {0};

        // Try to parse with =>
        if (sscanf(line, " %255s => %511s", lib_name, lib_path) >= 1) {
            // Skip if not crypto library
            if (!is_crypto_library_name(lib_name)) continue;

            // Find matching library asset
            const char* lib_id = find_library_by_soname(context->asset_store, lib_name);
            if (lib_id) {
                // Create relationship: service → library
                int result = create_service_library_relationship(context->asset_store,
                                                                service_asset->id,
                                                                lib_id,
                                                                0.90);
                if (result == 0) {
                    libs_found++;
                }
            }
        }
        // Also handle format: "/lib/x86_64-linux-gnu/libssl.so.3 (0x...)" (no =>)
        else if (sscanf(line, " %511s (", lib_path) == 1) {
            // Extract filename from path
            char* filename = strrchr(lib_path, '/');
            if (filename) {
                filename++; // Skip the '/'
                strncpy(lib_name, filename, sizeof(lib_name) - 1);

                if (is_crypto_library_name(lib_name)) {
                    const char* lib_id = find_library_by_soname(context->asset_store, lib_name);
                    if (lib_id) {
                        int result = create_service_library_relationship(context->asset_store,
                                                                        service_asset->id,
                                                                        lib_id,
                                                                        0.90);
                        if (result == 0) {
                            libs_found++;
                        }
                    }
                }
            }
        }
    }

    pclose(fp);
    free(binary_path);

    return libs_found;
}

/**
 * Count crypto library dependencies without creating assets.
 * Used for crypto relevance check before adding service to CBOM.
 * v1.7.2: Added to filter non-crypto services from YAML plugins.
 *
 * @param process_name Process name or binary path
 * @param pid Process ID (0 if not running)
 * @return Number of crypto libraries + embedded providers, 0 if none
 */
int count_crypto_library_dependencies(const char* process_name, pid_t pid) {
    if (!process_name) return 0;

    // Resolve binary path using same logic as get_binary_path_for_service
    char binary_path[PATH_MAX];
    bool found = false;

    // v1.8.1: Check for rootfs prefix in cross-arch mode
    const char* rootfs_prefix = g_cbom_config.rootfs_prefix;
    bool cross_arch = g_cbom_config.cross_arch_mode || (rootfs_prefix && rootfs_prefix[0]);

    // Method 1: Use /proc/pid/exe for running processes (host only)
    if (pid > 0 && !cross_arch) {
        char exe_link[64];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
        ssize_t len = readlink(exe_link, binary_path, sizeof(binary_path) - 1);
        if (len > 0) {
            binary_path[len] = '\0';
            if (access(binary_path, R_OK) == 0) {
                found = true;
            }
        }
    }

    // Method 2: process_name is already a full path
    if (!found && process_name[0] == '/') {
        if (cross_arch && rootfs_prefix) {
            snprintf(binary_path, sizeof(binary_path), "%s%s", rootfs_prefix, process_name);
        } else {
            strncpy(binary_path, process_name, sizeof(binary_path) - 1);
            binary_path[sizeof(binary_path) - 1] = '\0';
        }
        if (access(binary_path, R_OK) == 0) {
            found = true;
        }
    }

    // Method 3: Search standard directories
    if (!found) {
        const char* search_dirs[] = {"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/libexec", NULL};
        for (const char** dir = search_dirs; *dir && !found; dir++) {
            if (cross_arch && rootfs_prefix) {
                snprintf(binary_path, sizeof(binary_path), "%s%s/%s", rootfs_prefix, *dir, process_name);
            } else {
                snprintf(binary_path, sizeof(binary_path), "%s/%s", *dir, process_name);
            }
            if (access(binary_path, R_OK) == 0) {
                found = true;
            }
        }
    }

    if (!found) {
        return 0;  // Binary not found
    }

    // Analyze binary for crypto libraries (same as detect_service_library_dependencies)
    binary_crypto_profile_t* profile = analyze_binary_crypto(binary_path);
    if (!profile) {
        return 0;
    }

    // Count crypto libraries
    int crypto_count = 0;
    for (size_t i = 0; i < profile->libs_count; i++) {
        if (profile->libs[i].is_crypto) {
            crypto_count++;
        }
    }

    // Also count embedded providers (e.g., openssh_internal)
    crypto_count += (int)profile->embedded_providers_count;

    free_binary_crypto_profile(profile);
    return crypto_count;
}

/**
 * Simple wrapper for YAML plugins (avoids type conflicts)
 * Takes simple parameters and creates temp context internally
 */
int detect_service_library_dependencies_simple(asset_store_t* store,
                                               crypto_asset_t* service_asset,
                                               const char* process_name,
                                               pid_t pid) {
    if (!store || !service_asset) return -1;

    // Create temporary context with asset store
    service_scanner_context_t temp_ctx = {0};
    temp_ctx.asset_store = store;

    // Create temporary metadata from simple parameters
    service_metadata_t temp_metadata = {0};
    temp_metadata.daemon_name = (char*)process_name;  // Cast away const for temp use
    temp_metadata.daemon_pid = pid;
    temp_metadata.is_running = (pid > 0);

    // Call the full detection function
    return detect_service_library_dependencies(&temp_ctx, service_asset, &temp_metadata);
}

// Detect Apache service
int detect_apache_service(service_scanner_context_t* context) {
    if (!context) return -1;

    // Check if Apache is running
    bool running = is_service_running("apache2") || is_service_running("httpd");

    if (!running && !context->config.scan_config_files) {
        return 0;
    }

    // Build list of config paths to try
    const char* all_paths[10];
    int path_count = 0;

    // Production paths (always included)
    all_paths[path_count++] = "/etc/apache2/sites-enabled/default-ssl.conf";
    all_paths[path_count++] = "/etc/apache2/apache2.conf";
    all_paths[path_count++] = "/etc/httpd/conf.d/ssl.conf";
    all_paths[path_count++] = "/etc/httpd/conf/httpd.conf";

    // v1.5: Removed fixtures paths - production code should not reference test data

    all_paths[path_count] = NULL;

    for (int i = 0; all_paths[i] != NULL; i++) {
        if (access(all_paths[i], R_OK) != 0) continue;

        service_metadata_t* metadata = parse_apache_config(all_paths[i]);
        if (metadata) {
            metadata->is_running = running;
            if (running) {
                metadata->daemon_pid = get_service_pid("apache2");
                metadata->version = get_service_version("apache2");
            }

            // Create service asset
            crypto_asset_t* service_asset = service_create_asset(metadata);
            if (service_asset && context->asset_store) {
                asset_store_add(context->asset_store, service_asset);

                // Detect library dependencies
                detect_service_library_dependencies(context, service_asset, metadata);

                // Create SERVICE → CERTIFICATE relationship if cert configured (Phase 8 tweak)
                if (metadata->ssl_cert_path) {
                    const char* cert_id = find_cert_id_by_path(context->asset_store, metadata->ssl_cert_path);
                    if (cert_id) {
                        int rel_result = create_service_cert_relationship(context->asset_store,
                            service_asset->id, cert_id, 0.90);
                        fprintf(stderr, "[INFO] Created Apache→Cert relationship: %d\n", rel_result);
                    } else {
                        fprintf(stderr, "[WARN] Certificate not found in asset store: %s\n", metadata->ssl_cert_path);
                    }
                }

                // Extract TLS protocol - create separate protocol for each version (Phase 4)
                if (context->config.centralize_tls) {
                    protocol_metadata_t* tls_protocol = extract_tls_protocol(
                        all_paths[i], "Apache");
                    if (tls_protocol && tls_protocol->enabled_version_count > 0) {
                        // Create a separate protocol asset for each enabled TLS version
                        for (size_t v = 0; v < tls_protocol->enabled_version_count; v++) {
                            const char* version = tls_protocol->enabled_versions[v];

                            // Create version-specific protocol
                            protocol_metadata_t* version_protocol = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
                            if (!version_protocol) continue;

                            version_protocol->version = strdup(version);
                            version_protocol->config_file_path = tls_protocol->config_file_path ? strdup(tls_protocol->config_file_path) : NULL;
                            version_protocol->detection_method = tls_protocol->detection_method;
                            version_protocol->confidence = tls_protocol->confidence;
                            version_protocol->security_profile = tls_protocol->security_profile;

                            // Copy cipher settings for TLS 1.2 and below
                            if (tls_protocol->enabled_cipher_count > 0 && tls_protocol->enabled_cipher_suites) {
                                version_protocol->enabled_cipher_suites = malloc(sizeof(char*));
                                version_protocol->enabled_cipher_suites[0] = strdup(tls_protocol->enabled_cipher_suites[0]);
                                version_protocol->enabled_cipher_count = 1;
                            }

                            crypto_asset_t* protocol_asset = protocol_create_asset(version_protocol);
                            if (protocol_asset) {
                                asset_store_add(context->asset_store, protocol_asset);

                                // Create SERVICE → PROTOCOL relationship
                                create_service_protocol_relationship(context->asset_store,
                                    service_asset->id, protocol_asset->id, 0.95);

                                // Create cipher suites based on version
                                if (strstr(version, "1.3")) {
                                    // TLS 1.3 - fixed cipher suite list
                                    size_t suite_count;
                                    cipher_suite_metadata_t** suites = get_all_tls13_suites(&suite_count, all_paths[i]);

                                    for (size_t j = 0; j < suite_count; j++) {
                                        crypto_asset_t* suite_asset = cipher_suite_create_asset(suites[j]);
                                        if (suite_asset) {
                                            asset_store_add(context->asset_store, suite_asset);

                                            create_protocol_suite_relationship(context->asset_store,
                                                protocol_asset->id, suite_asset->id, 0.95);

                                            decompose_cipher_suite_to_algorithms(context->asset_store,
                                                suite_asset->id,
                                                suites[j]->kex_algorithm,
                                                suites[j]->auth_algorithm,
                                                suites[j]->encryption_algorithm,
                                                suites[j]->mac_algorithm);

                                            pthread_mutex_lock(&context->mutex);
                                            context->stats.protocols_extracted++;
                                            pthread_mutex_unlock(&context->mutex);
                                        }
                                        cipher_suite_metadata_destroy(suites[j]);
                                    }
                                    free(suites);
                                }
                                else {
                                    // TLS 1.2 and below - use configured cipher list or default
                                    const char* cipher_list = (tls_protocol->enabled_cipher_count > 0 &&
                                                              tls_protocol->enabled_cipher_suites[0])
                                        ? tls_protocol->enabled_cipher_suites[0]
                                        : "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256";  // Modern default
                                    const char* tls_ver = strstr(version, "1.2") ? "1.2" :
                                                         strstr(version, "1.1") ? "1.1" : "1.0";
                                    size_t suite_count;
                                    cipher_suite_metadata_t** suites = parse_cipher_list_to_suites(
                                        cipher_list,
                                        tls_ver,
                                        all_paths[i],
                                        &suite_count);

                                    if (suites) {
                                        for (size_t j = 0; j < suite_count; j++) {
                                            crypto_asset_t* suite_asset = cipher_suite_create_asset(suites[j]);
                                            if (suite_asset) {
                                                asset_store_add(context->asset_store, suite_asset);

                                                create_protocol_suite_relationship(context->asset_store,
                                                    protocol_asset->id, suite_asset->id, 0.95);

                                                decompose_cipher_suite_to_algorithms(context->asset_store,
                                                    suite_asset->id,
                                                    suites[j]->kex_algorithm,
                                                    suites[j]->auth_algorithm,
                                                    suites[j]->encryption_algorithm,
                                                    suites[j]->mac_algorithm);

                                                pthread_mutex_lock(&context->mutex);
                                                context->stats.protocols_extracted++;
                                                pthread_mutex_unlock(&context->mutex);
                                            }
                                            cipher_suite_metadata_destroy(suites[j]);
                                        }
                                        free(suites);
                                    }
                                }
                            }
                            protocol_metadata_destroy(version_protocol);
                        }
                        protocol_metadata_destroy(tls_protocol);
                    } else if (tls_protocol) {
                        protocol_metadata_destroy(tls_protocol);
                    }
                }

                pthread_mutex_lock(&context->mutex);
                context->stats.services_detected_total++;
                context->stats.apache_found++;
                if (running) context->stats.services_running++;
                else context->stats.services_configured++;
                pthread_mutex_unlock(&context->mutex);
            }

            service_metadata_destroy(metadata);
            return 1;
        }
    }

    return 0;
}

// Detect Nginx service
int detect_nginx_service(service_scanner_context_t* context) {
    if (!context) return -1;

    bool running = is_service_running("nginx");

    if (!running && !context->config.scan_config_files) {
        return 0;
    }

    // Build list of config paths to try
    const char* all_paths[10];
    int path_count = 0;

    // Production paths (always included)
    all_paths[path_count++] = "/etc/nginx/sites-enabled/default";
    all_paths[path_count++] = "/etc/nginx/nginx.conf";

    // v1.5: Removed fixtures paths - production code should not reference test data

    all_paths[path_count] = NULL;

    for (int i = 0; all_paths[i] != NULL; i++) {
        if (access(all_paths[i], R_OK) != 0) continue;

        service_metadata_t* metadata = parse_nginx_config(all_paths[i]);
        if (metadata) {
            metadata->is_running = running;
            if (running) {
                metadata->daemon_pid = get_service_pid("nginx");
                metadata->version = get_service_version("nginx");
            }

            crypto_asset_t* service_asset = service_create_asset(metadata);
            if (service_asset && context->asset_store) {
                asset_store_add(context->asset_store, service_asset);

                // Detect library dependencies
                detect_service_library_dependencies(context, service_asset, metadata);

                // Create SERVICE → CERTIFICATE relationship if cert configured (Phase 8 tweak)
                if (metadata->ssl_cert_path) {
                    const char* cert_id = find_cert_id_by_path(context->asset_store, metadata->ssl_cert_path);
                    if (cert_id) {
                        int rel_result = create_service_cert_relationship(context->asset_store,
                            service_asset->id, cert_id, 0.90);
                        fprintf(stderr, "[INFO] Created Nginx→Cert relationship: %d\n", rel_result);
                    } else {
                        fprintf(stderr, "[WARN] Certificate not found in asset store: %s\n", metadata->ssl_cert_path);
                    }
                }

                // Extract TLS protocol - create separate protocol for each version (Phase 4)
                if (context->config.centralize_tls) {
                    protocol_metadata_t* tls_protocol = extract_tls_protocol(
                        all_paths[i], "Nginx");
                    if (tls_protocol && tls_protocol->enabled_version_count > 0) {
                        // Create a separate protocol asset for each enabled TLS version
                        for (size_t v = 0; v < tls_protocol->enabled_version_count; v++) {
                            const char* version = tls_protocol->enabled_versions[v];

                            // Create version-specific protocol
                            protocol_metadata_t* version_protocol = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
                            if (!version_protocol) continue;

                            version_protocol->version = strdup(version);
                            version_protocol->config_file_path = tls_protocol->config_file_path ? strdup(tls_protocol->config_file_path) : NULL;
                            version_protocol->detection_method = tls_protocol->detection_method;
                            version_protocol->confidence = tls_protocol->confidence;
                            version_protocol->security_profile = tls_protocol->security_profile;

                            // Copy cipher settings for TLS 1.2 and below
                            if (tls_protocol->enabled_cipher_count > 0 && tls_protocol->enabled_cipher_suites) {
                                version_protocol->enabled_cipher_suites = malloc(sizeof(char*));
                                version_protocol->enabled_cipher_suites[0] = strdup(tls_protocol->enabled_cipher_suites[0]);
                                version_protocol->enabled_cipher_count = 1;
                            }

                            crypto_asset_t* protocol_asset = protocol_create_asset(version_protocol);
                            if (protocol_asset) {
                                asset_store_add(context->asset_store, protocol_asset);

                                // Create SERVICE → PROTOCOL relationship
                                create_service_protocol_relationship(context->asset_store,
                                    service_asset->id, protocol_asset->id, 0.95);

                                // Create cipher suites based on version
                                if (strstr(version, "1.3")) {
                                    // TLS 1.3 - fixed cipher suite list
                                    size_t suite_count;
                                    cipher_suite_metadata_t** suites = get_all_tls13_suites(&suite_count, all_paths[i]);

                                    for (size_t j = 0; j < suite_count; j++) {
                                        crypto_asset_t* suite_asset = cipher_suite_create_asset(suites[j]);
                                        if (suite_asset) {
                                            asset_store_add(context->asset_store, suite_asset);

                                            create_protocol_suite_relationship(context->asset_store,
                                                protocol_asset->id, suite_asset->id, 0.95);

                                            decompose_cipher_suite_to_algorithms(context->asset_store,
                                                suite_asset->id,
                                                suites[j]->kex_algorithm,
                                                suites[j]->auth_algorithm,
                                                suites[j]->encryption_algorithm,
                                                suites[j]->mac_algorithm);

                                            pthread_mutex_lock(&context->mutex);
                                            context->stats.protocols_extracted++;
                                            pthread_mutex_unlock(&context->mutex);
                                        }
                                        cipher_suite_metadata_destroy(suites[j]);
                                    }
                                    free(suites);
                                }
                                else {
                                    // TLS 1.2 and below - use configured cipher list or default
                                    const char* cipher_list = (tls_protocol->enabled_cipher_count > 0 &&
                                                              tls_protocol->enabled_cipher_suites[0])
                                        ? tls_protocol->enabled_cipher_suites[0]
                                        : "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256";  // Modern default
                                    const char* tls_ver = strstr(version, "1.2") ? "1.2" :
                                                         strstr(version, "1.1") ? "1.1" : "1.0";
                                    size_t suite_count;
                                    cipher_suite_metadata_t** suites = parse_cipher_list_to_suites(
                                        cipher_list,
                                        tls_ver,
                                        all_paths[i],
                                        &suite_count);

                                    if (suites) {
                                        for (size_t j = 0; j < suite_count; j++) {
                                            crypto_asset_t* suite_asset = cipher_suite_create_asset(suites[j]);
                                            if (suite_asset) {
                                                asset_store_add(context->asset_store, suite_asset);

                                                create_protocol_suite_relationship(context->asset_store,
                                                    protocol_asset->id, suite_asset->id, 0.95);

                                                decompose_cipher_suite_to_algorithms(context->asset_store,
                                                    suite_asset->id,
                                                    suites[j]->kex_algorithm,
                                                    suites[j]->auth_algorithm,
                                                    suites[j]->encryption_algorithm,
                                                    suites[j]->mac_algorithm);

                                                pthread_mutex_lock(&context->mutex);
                                                context->stats.protocols_extracted++;
                                                pthread_mutex_unlock(&context->mutex);
                                            }
                                            cipher_suite_metadata_destroy(suites[j]);
                                        }
                                        free(suites);
                                    }
                                }
                            }
                            protocol_metadata_destroy(version_protocol);
                        }
                        protocol_metadata_destroy(tls_protocol);
                    } else if (tls_protocol) {
                        protocol_metadata_destroy(tls_protocol);
                    }
                }

                pthread_mutex_lock(&context->mutex);
                context->stats.services_detected_total++;
                context->stats.nginx_found++;
                if (running) context->stats.services_running++;
                else context->stats.services_configured++;
                pthread_mutex_unlock(&context->mutex);
            }

            service_metadata_destroy(metadata);
            return 1;
        }
    }

    return 0;
}

// Detect OpenSSH service
int detect_openssh_service(service_scanner_context_t* context) {
    if (!context) return -1;

    bool running = is_service_running("sshd");

    if (!running && !context->config.scan_config_files) {
        return 0;
    }

    const char* config_path = "/etc/ssh/sshd_config";
    if (access(config_path, R_OK) != 0) {
        return 0;
    }

    service_metadata_t* metadata = parse_sshd_config(config_path);
    if (metadata) {
        metadata->is_running = running;
        if (running) {
            metadata->daemon_pid = get_service_pid("sshd");
            metadata->version = get_service_version("sshd");
        }

        crypto_asset_t* service_asset = service_create_asset(metadata);
        if (service_asset && context->asset_store) {
            asset_store_add(context->asset_store, service_asset);

            // Detect library dependencies
            detect_service_library_dependencies(context, service_asset, metadata);

            // Extract SSH protocol
            if (context->config.extract_protocols) {
                protocol_metadata_t* ssh_protocol = extract_ssh_protocol(config_path);
                if (ssh_protocol) {
                    crypto_asset_t* protocol_asset = protocol_create_asset(ssh_protocol);
                    if (protocol_asset) {
                        asset_store_add(context->asset_store, protocol_asset);

                        // Create SERVICE → PROTOCOL relationship (Phase 7.3b)
                        create_service_protocol_relationship(context->asset_store,
                            service_asset->id, protocol_asset->id, 0.95);

                        // Extract KEX algorithms from SSH configuration
                        FILE* kex_fp = fopen(config_path, "r");
                        if (kex_fp) {
                            char line[1024];
                            while (fgets(line, sizeof(line), kex_fp)) {
                                if (strstr(line, "KexAlgorithms") && !strstr(line, "#")) {
                                    char* algo_list = strchr(line, ' ');
                                    if (algo_list) {
                                        algo_list++;

                                        // Allocate buffer for algorithm list
                                        char* algo_copy = strdup(algo_list);
                                        if (algo_copy) {
                                            // Parse comma-separated KEX algorithms
                                            char* token = strtok(algo_copy, ",");
                                            while (token) {
                                                // Trim whitespace and newlines
                                                while (*token == ' ' || *token == '\t') token++;
                                                char* end = token + strlen(token) - 1;
                                                while (end > token && (*end == ' ' || *end == '\t' ||
                                                       *end == '\n' || *end == '\r')) {
                                                    *end = '\0';
                                                    end--;
                                                }

                                                if (strlen(token) > 0) {
                                                    // Create algorithm component for KEX algorithm
                                                    crypto_asset_t* kex_algo = crypto_asset_create(token, ASSET_TYPE_ALGORITHM);
                                                    if (kex_algo) {
                                                        kex_algo->location = strdup(config_path);
                                                        kex_algo->algorithm = strdup(token);

                                                        // Populate metadata_json with CycloneDX algorithmProperties
                                                        char* metadata = algorithm_populate_cdx_metadata(
                                                            kex_algo->metadata_json,
                                                            token,
                                                            ALGO_CONTEXT_CIPHER_SUITE
                                                        );
                                                        if (metadata) {
                                                            if (kex_algo->metadata_json) free(kex_algo->metadata_json);
                                                            kex_algo->metadata_json = metadata;
                                                        }

                                                        // Add to asset store
                                                        asset_store_add(context->asset_store, kex_algo);

                                                        // Create PROTOCOL → ALGORITHM relationship
                                                        relationship_t* rel = relationship_create(
                                                            RELATIONSHIP_USES,
                                                            protocol_asset->id,
                                                            kex_algo->id,
                                                            0.95  // High confidence from config
                                                        );
                                                        if (rel) {
                                                            asset_store_add_relationship(context->asset_store, rel);
                                                        }
                                                    }
                                                }

                                                token = strtok(NULL, ",");
                                            }

                                            free(algo_copy);
                                        }
                                    }
                                    break;  // Found KexAlgorithms, done
                                }
                            }
                            fclose(kex_fp);
                        }

                        pthread_mutex_lock(&context->mutex);
                        context->stats.protocols_extracted++;
                        pthread_mutex_unlock(&context->mutex);
                    }
                    protocol_metadata_destroy(ssh_protocol);
                }
            }

            pthread_mutex_lock(&context->mutex);
            context->stats.services_detected_total++;
            context->stats.openssh_found++;
            if (running) context->stats.services_running++;
            else context->stats.services_configured++;
            pthread_mutex_unlock(&context->mutex);
        }

        service_metadata_destroy(metadata);
    }

    // Extract SSH client protocol (system-wide config)
    if (context->config.extract_protocols) {
        const char* client_config_path = "/etc/ssh/ssh_config";
        if (access(client_config_path, R_OK) == 0) {
            protocol_metadata_t* ssh_client_protocol = parse_ssh_client_config(client_config_path);
            if (ssh_client_protocol && context->asset_store) {
                crypto_asset_t* client_protocol_asset = protocol_create_asset(ssh_client_protocol);
                if (client_protocol_asset) {
                    asset_store_add(context->asset_store, client_protocol_asset);

                    // Extract KEX algorithms from client config
                    if (ssh_client_protocol->kex_count > 0) {
                        for (size_t i = 0; i < ssh_client_protocol->kex_count; i++) {
                            const char* kex_name = ssh_client_protocol->supported_kex[i];

                            // Create algorithm component for KEX algorithm
                            crypto_asset_t* kex_algo = crypto_asset_create(kex_name, ASSET_TYPE_ALGORITHM);
                            if (kex_algo) {
                                kex_algo->location = strdup(client_config_path);
                                kex_algo->algorithm = strdup(kex_name);

                                // Populate metadata_json with CycloneDX algorithmProperties
                                char* metadata = algorithm_populate_cdx_metadata(
                                    kex_algo->metadata_json,
                                    kex_name,
                                    ALGO_CONTEXT_CIPHER_SUITE
                                );
                                if (metadata) {
                                    if (kex_algo->metadata_json) free(kex_algo->metadata_json);
                                    kex_algo->metadata_json = metadata;
                                }

                                // Add to asset store
                                asset_store_add(context->asset_store, kex_algo);

                                // Create PROTOCOL → ALGORITHM relationship
                                relationship_t* rel = relationship_create(
                                    RELATIONSHIP_USES,
                                    client_protocol_asset->id,
                                    kex_algo->id,
                                    0.95  // High confidence from config
                                );
                                if (rel) {
                                    asset_store_add_relationship(context->asset_store, rel);
                                }
                            }
                        }
                    }

                    pthread_mutex_lock(&context->mutex);
                    context->stats.protocols_extracted++;
                    pthread_mutex_unlock(&context->mutex);
                }
                protocol_metadata_destroy(ssh_client_protocol);
            }
        }

        // Scan user SSH client configs (privacy-aware, opt-in)
        scan_user_ssh_configs(context);
    }

    return metadata != NULL ? 1 : 0;
}

// Detect Postfix service
int detect_postfix_service(service_scanner_context_t* context) {
    if (!context) return -1;

    bool running = is_service_running("master");  // Postfix master process

    if (!running && !context->config.scan_config_files) {
        return 0;
    }

    const char* config_path = "/etc/postfix/main.cf";
    if (access(config_path, R_OK) != 0) {
        return 0;
    }

    service_metadata_t* metadata = parse_postfix_config(config_path);
    if (metadata) {
        metadata->is_running = running;
        if (running) {
            metadata->daemon_pid = get_service_pid("master");
        }

        crypto_asset_t* service_asset = service_create_asset(metadata);
        if (service_asset && context->asset_store) {
            asset_store_add(context->asset_store, service_asset);

            // Detect library dependencies
            detect_service_library_dependencies(context, service_asset, metadata);

            pthread_mutex_lock(&context->mutex);
            context->stats.services_detected_total++;
            context->stats.postfix_found++;
            if (running) context->stats.services_running++;
            else context->stats.services_configured++;
            pthread_mutex_unlock(&context->mutex);
        }

        service_metadata_destroy(metadata);
        return 1;
    }

    return 0;
}

// Create service asset
struct crypto_asset* service_create_asset(const service_metadata_t* metadata) {
    if (!metadata) return NULL;

    crypto_asset_t* asset = crypto_asset_create(metadata->name, ASSET_TYPE_SERVICE);
    if (!asset) return NULL;

    // Set version
    if (metadata->version) {
        free(asset->algorithm);
        asset->algorithm = strdup(metadata->version);
    }

    // Set location (config file)
    if (metadata->config_file_path) {
        asset->location = strdup(metadata->config_file_path);
    }

    // Generate normalized ID: service|name|version|daemon
    char id_string[512];
    snprintf(id_string, sizeof(id_string), "service|%s|%s|%s",
            metadata->name,
            metadata->version ? metadata->version : "unknown",
            metadata->daemon_name ? metadata->daemon_name : "unknown");

    free(asset->id);
    asset->id = strdup(id_string);

    // Store detailed metadata as JSON
    asset->metadata_json = service_create_detailed_json_metadata(metadata);

    return asset;
}

// Create protocol asset
struct crypto_asset* protocol_create_asset(const protocol_metadata_t* metadata) {
    if (!metadata) return NULL;

    crypto_asset_t* asset = crypto_asset_create(metadata->name, ASSET_TYPE_PROTOCOL);
    if (!asset) return NULL;

    // Set version (both in algorithm for backwards compat and version for bom-ref)
    if (metadata->version) {
        free(asset->algorithm);
        asset->algorithm = strdup(metadata->version);
        asset->version = strdup(metadata->version);
    }

    // Set location (config file)
    if (metadata->config_file_path) {
        asset->location = strdup(metadata->config_file_path);
    }

    // Generate normalized ID: protocol|name|version|usage (or config path if usage not set)
    char id_string[512];
    if (metadata->usage) {
        snprintf(id_string, sizeof(id_string), "protocol|%s|%s|%s",
                metadata->name,
                metadata->version ? metadata->version : "unknown",
                metadata->usage);
    } else {
        snprintf(id_string, sizeof(id_string), "protocol|%s|%s",
                metadata->name,
                metadata->version ? metadata->version : "unknown");
    }

    free(asset->id);
    asset->id = strdup(id_string);

    // Store detailed metadata as JSON
    asset->metadata_json = protocol_create_detailed_json_metadata(metadata);

    return asset;
}

// Create service JSON metadata
char* service_create_detailed_json_metadata(const service_metadata_t* metadata) {
    if (!metadata) return NULL;

    json_object* root = json_object_new_object();
    if (!root) return NULL;

    json_object_object_add(root, "service_type",
        json_object_new_string(service_type_to_string(metadata->type)));

    if (metadata->name) {
        json_object_object_add(root, "name", json_object_new_string(metadata->name));
    }
    if (metadata->version) {
        json_object_object_add(root, "version", json_object_new_string(metadata->version));
    }
    if (metadata->daemon_name) {
        json_object_object_add(root, "daemon_name", json_object_new_string(metadata->daemon_name));
    }

    json_object_object_add(root, "is_running", json_object_new_boolean(metadata->is_running));

    if (metadata->daemon_pid > 0) {
        json_object_object_add(root, "pid", json_object_new_int(metadata->daemon_pid));
    }

    // SSL certificate path (Issue #3 fix - required for post-scan relationship matching)
    if (metadata->ssl_cert_path) {
        json_object_object_add(root, "ssl_cert_path", json_object_new_string(metadata->ssl_cert_path));
    }

    // Network endpoints
    if (metadata->endpoints && metadata->endpoint_count > 0) {
        json_object* endpoints_array = json_object_new_array();
        for (size_t i = 0; i < metadata->endpoint_count; i++) {
            json_object* ep = json_object_new_object();
            json_object_object_add(ep, "address", json_object_new_string(metadata->endpoints[i].address));
            json_object_object_add(ep, "port", json_object_new_int(metadata->endpoints[i].port));
            json_object_object_add(ep, "protocol", json_object_new_string(metadata->endpoints[i].protocol));
            json_object_object_add(ep, "encrypted", json_object_new_boolean(metadata->endpoints[i].is_encrypted));
            json_object_array_add(endpoints_array, ep);
        }
        json_object_object_add(root, "endpoints", endpoints_array);
    }

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = NULL;
    if (json_str) {
        result = malloc(strlen(json_str) + 1);
        if (result) strcpy(result, json_str);
    }

    json_object_put(root);
    return result;
}

// Create protocol JSON metadata
char* protocol_create_detailed_json_metadata(const protocol_metadata_t* metadata) {
    if (!metadata) return NULL;

    json_object* root = json_object_new_object();
    if (!root) return NULL;

    json_object_object_add(root, "protocol_type",
        json_object_new_string(protocol_type_to_str(metadata->type)));

    if (metadata->version) {
        json_object_object_add(root, "version", json_object_new_string(metadata->version));
    }

    // Enabled versions
    if (metadata->enabled_versions && metadata->enabled_version_count > 0) {
        json_object* versions_array = json_object_new_array();
        for (size_t i = 0; i < metadata->enabled_version_count; i++) {
            json_object_array_add(versions_array, json_object_new_string(metadata->enabled_versions[i]));
        }
        json_object_object_add(root, "enabled_versions", versions_array);
    }

    // Enabled cipher suites
    if (metadata->enabled_cipher_suites && metadata->enabled_cipher_count > 0) {
        json_object* ciphers_array = json_object_new_array();
        for (size_t i = 0; i < metadata->enabled_cipher_count; i++) {
            json_object_array_add(ciphers_array, json_object_new_string(metadata->enabled_cipher_suites[i]));
        }
        json_object_object_add(root, "enabled_cipher_suites", ciphers_array);
    }

    // Security profile
    json_object_object_add(root, "security_profile",
        json_object_new_string(security_profile_to_string(metadata->security_profile)));

    // Weak configurations
    if (metadata->weak_configurations.weak_count > 0) {
        json_object* weak_array = json_object_new_array();
        for (size_t i = 0; i < metadata->weak_configurations.weak_count; i++) {
            json_object_array_add(weak_array, json_object_new_string(metadata->weak_configurations.weak_items[i]));
        }
        json_object_object_add(root, "weak_configurations", weak_array);
    }

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = NULL;
    if (json_str) {
        result = malloc(strlen(json_str) + 1);
        if (result) strcpy(result, json_str);
    }

    json_object_put(root);
    return result;
}

// Scan running services
int service_scanner_scan_running_services(service_scanner_context_t* context) {
    if (!context) return -1;

    int total = 0;

    if (context->config.detect_web_servers) {
        total += detect_apache_service(context);
        total += detect_nginx_service(context);
    }

    if (context->config.detect_ssh_servers) {
        total += detect_openssh_service(context);
    }

    if (context->config.detect_mail_servers) {
        total += detect_postfix_service(context);
    }

    return total;
}

// Scan all services
int service_scanner_scan_all(service_scanner_context_t* context) {
    if (!context) return -1;

    int total = 0;

    if (context->config.scan_running_processes || context->config.scan_config_files) {
        total = service_scanner_scan_running_services(context);
    }

    return total;
}

// ============================================================================
// PQC Analysis Functions (Phase 8.0)
// ============================================================================

/**
 * Calculate PQC readiness score for a service
 *
 * Traverses: SERVICE → PROTOCOL → CIPHER_SUITE graph
 * Aggregates PQC safety scores from all cipher suites
 *
 * @param service_id Service asset ID
 * @param store Asset store
 * @return Readiness score (0-100, or -1.0 on error)
 */
float calculate_service_pqc_readiness(const char* service_id, asset_store_t* store) {
    if (!service_id || !store) return -1.0f;

    // Get all relationships from the service
    size_t rel_count;
    relationship_t** all_rels = asset_store_get_relationships(store, &rel_count);
    if (!all_rels) return -1.0f;

    // Find PROTOCOL assets that this service USES
    pqc_readiness_score_t score = pqc_readiness_score_init();
    bool found_any_protocols = false;

    for (size_t i = 0; i < rel_count; i++) {
        relationship_t* rel = all_rels[i];
        if (!rel) continue;

        // Check if this is SERVICE → PROTOCOL relationship
        if (rel->type == RELATIONSHIP_USES &&
            rel->source_asset_id && strcmp(rel->source_asset_id, service_id) == 0) {

            const char* protocol_id = rel->target_asset_id;
            if (!protocol_id) continue;

            found_any_protocols = true;

            // Now find CIPHER_SUITE assets from this PROTOCOL
            for (size_t j = 0; j < rel_count; j++) {
                relationship_t* suite_rel = all_rels[j];
                if (!suite_rel) continue;

                // Check if this is PROTOCOL → SUITE relationship
                if (suite_rel->type == RELATIONSHIP_PROVIDES &&
                    suite_rel->source_asset_id && strcmp(suite_rel->source_asset_id, protocol_id) == 0) {

                    const char* suite_id = suite_rel->target_asset_id;
                    if (!suite_id) continue;

                    // Find the cipher suite asset
                    crypto_asset_t* suite_asset = asset_store_find(store, suite_id);
                    if (!suite_asset) continue;

                    // Extract PQC category from suite asset properties
                    // The PQC category should be stored in the asset metadata
                    // For simplicity, classify based on asset name/properties
                    pqc_category_t category = PQC_TRANSITIONAL;  // Default for most TLS suites

                    // Check if suite uses quantum-vulnerable KEX (ECDHE, DHE, RSA)
                    // Most TLS 1.2/1.3 suites use ECDHE - quantum-vulnerable
                    if (suite_asset->name) {
                        if (strstr(suite_asset->name, "Kyber") ||
                            strstr(suite_asset->name, "ML-KEM") ||
                            strstr(suite_asset->name, "Dilithium") ||
                            strstr(suite_asset->name, "ML-DSA")) {
                            category = PQC_SAFE;
                        } else if (strstr(suite_asset->name, "RC4") ||
                                  strstr(suite_asset->name, "DES") ||
                                  strstr(suite_asset->name, "NULL")) {
                            category = PQC_DEPRECATED;
                        } else if (strstr(suite_asset->name, "AES") ||
                                  strstr(suite_asset->name, "ChaCha20")) {
                            // Modern cipher, but quantum-vulnerable KEX
                            category = PQC_TRANSITIONAL;
                        }
                    }

                    pqc_readiness_score_update(&score, category);
                }
            }
        }
    }

    // If no cipher suites found, check if service uses deprecated protocols
    if (!found_any_protocols) {
        return 50.0f;  // Unknown/neutral score
    }

    if (score.total_count == 0) {
        return 50.0f;  // No cipher suites = neutral
    }

    // Finalize and return score
    pqc_readiness_score_finalize(&score);
    return score.readiness_score;
}

/**
 * Generate PQC migration recommendations for a service
 *
 * @param service_id Service asset ID
 * @param store Asset store
 * @param count Output: number of recommendations
 * @return Array of recommendation strings (caller must free)
 */
char** generate_service_pqc_recommendations(const char* service_id,
                                           asset_store_t* store,
                                           size_t* count) {
    if (!service_id || !store || !count) return NULL;

    *count = 0;

    // Calculate readiness score first
    float readiness = calculate_service_pqc_readiness(service_id, store);

    // Allocate recommendations array (max 5 recommendations)
    char** recommendations = malloc(sizeof(char*) * 5);
    if (!recommendations) return NULL;

    size_t rec_count = 0;

    // Generate recommendations based on score
    if (readiness < 30.0f) {
        // CRITICAL: Mostly unsafe/deprecated
        recommendations[rec_count++] = strdup(
            "CRITICAL: Migrate to PQC-safe cipher suites immediately (Kyber, Dilithium)");
        recommendations[rec_count++] = strdup(
            "Replace ECDHE key exchange with hybrid X25519+Kyber768 or pure Kyber-768");
        recommendations[rec_count++] = strdup(
            "Update TLS configuration to support PQC cipher suites");
    } else if (readiness < 60.0f) {
        // MODERATE: Transitional algorithms
        recommendations[rec_count++] = strdup(
            "Plan migration to PQC-safe algorithms within 12-24 months");
        recommendations[rec_count++] = strdup(
            "Consider hybrid cipher suites (X25519Kyber768) for gradual transition");
        recommendations[rec_count++] = strdup(
            "Test PQC cipher suite compatibility with clients");
    } else if (readiness < 90.0f) {
        // GOOD: Mostly safe, some improvements possible
        recommendations[rec_count++] = strdup(
            "Service has reasonable PQC readiness - consider completing migration");
        recommendations[rec_count++] = strdup(
            "Replace remaining classical key exchange with pure PQC alternatives");
    } else {
        // EXCELLENT: PQC-ready
        recommendations[rec_count++] = strdup(
            "Service is PQC-ready - maintain current configuration");
        recommendations[rec_count++] = strdup(
            "Monitor for new NIST-finalized PQC standards and updates");
    }

    *count = rec_count;
    return recommendations;
}

// Get statistics
service_scanner_stats_t service_scanner_get_stats(const service_scanner_context_t* context) {
    if (!context) {
        service_scanner_stats_t empty = {0};
        return empty;
    }
    return context->stats;
}
