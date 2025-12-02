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

#define _GNU_SOURCE

#include "package_scanner.h"
#include "error_handling.h"
#include "secure_memory.h"
#include "asset_store.h"
#include "cbom_types.h"
#include "plugin_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <json-c/json.h>

// Thread-local error storage
static __thread char last_error[512] = {0};

// Known cryptographic libraries
static const char* CRYPTO_LIBRARIES[] = {
    "openssl", "libssl", "libcrypto",
    "libressl",
    "boringssl",
    "gnutls", "libgnutls",
    "wolfssl", "libwolfssl",
    "mbedtls", "libmbedtls",
    "libgcrypt",
    "nettle", "libnettle",
    "cryptography",  // Python
    "pycryptodome", "pycrypto", "m2crypto",  // Python
    "bcrypt", "node-forge",  // Node.js
    "openssl", "bcrypt", "rbnacl",  // Ruby
    NULL
};

// Set error message
static void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(last_error, sizeof(last_error), format, args);
    va_end(args);
}

// Clear error message
void package_scanner_clear_error(void) {
    last_error[0] = '\0';
}

// Get last error message
const char* package_scanner_get_last_error(void) {
    return last_error[0] ? last_error : NULL;
}

// Convert package manager enum to string
const char* package_manager_to_string(package_manager_t manager) {
    switch (manager) {
        case PKG_MANAGER_APT: return "apt";
        case PKG_MANAGER_RPM: return "rpm";
        case PKG_MANAGER_PACMAN: return "pacman";
        case PKG_MANAGER_PIP: return "pip";
        case PKG_MANAGER_NPM: return "npm";
        case PKG_MANAGER_GEM: return "gem";
        case PKG_MANAGER_SNAP: return "snap";
        case PKG_MANAGER_FLATPAK: return "flatpak";
        default: return "unknown";
    }
}

// Convert string to package manager enum
package_manager_t package_manager_from_string(const char* name) {
    if (!name) return PKG_MANAGER_UNKNOWN;

    if (strcasecmp(name, "apt") == 0 || strcasecmp(name, "dpkg") == 0) {
        return PKG_MANAGER_APT;
    } else if (strcasecmp(name, "rpm") == 0 || strcasecmp(name, "yum") == 0 || strcasecmp(name, "dnf") == 0) {
        return PKG_MANAGER_RPM;
    } else if (strcasecmp(name, "pacman") == 0) {
        return PKG_MANAGER_PACMAN;
    } else if (strcasecmp(name, "pip") == 0) {
        return PKG_MANAGER_PIP;
    } else if (strcasecmp(name, "npm") == 0) {
        return PKG_MANAGER_NPM;
    } else if (strcasecmp(name, "gem") == 0 || strcasecmp(name, "rubygems") == 0) {
        return PKG_MANAGER_GEM;
    } else if (strcasecmp(name, "snap") == 0) {
        return PKG_MANAGER_SNAP;
    } else if (strcasecmp(name, "flatpak") == 0) {
        return PKG_MANAGER_FLATPAK;
    }

    return PKG_MANAGER_UNKNOWN;
}

// Check if package manager is available on system
bool package_manager_available(package_manager_t manager) {
    switch (manager) {
        case PKG_MANAGER_APT:
            return access("/usr/bin/dpkg", X_OK) == 0 ||
                   access("/var/lib/dpkg/status", R_OK) == 0;

        case PKG_MANAGER_RPM:
            return access("/usr/bin/rpm", X_OK) == 0 ||
                   access("/var/lib/rpm", R_OK) == 0;

        case PKG_MANAGER_PACMAN:
            return access("/usr/bin/pacman", X_OK) == 0 ||
                   access("/var/lib/pacman", R_OK) == 0;

        case PKG_MANAGER_PIP:
            return access("/usr/bin/pip3", X_OK) == 0 ||
                   access("/usr/bin/pip", X_OK) == 0;

        case PKG_MANAGER_NPM:
            return access("/usr/bin/npm", X_OK) == 0;

        case PKG_MANAGER_GEM:
            return access("/usr/bin/gem", X_OK) == 0;

        default:
            return false;
    }
}

// Convert FIPS level to string
const char* fips_level_to_string(fips_level_t level) {
    switch (level) {
        case FIPS_LEVEL_140_3_L1: return "140-3-L1";
        case FIPS_LEVEL_140_3_L2: return "140-3-L2";
        case FIPS_LEVEL_140_3_L3: return "140-3-L3";
        case FIPS_LEVEL_140_3_L4: return "140-3-L4";
        case FIPS_LEVEL_140_2: return "140-2";
        case FIPS_NOT_CERTIFIED: return "NOT_CERTIFIED";
        default: return "UNKNOWN";
    }
}

// Check if package is a cryptographic library
bool is_crypto_library(const char* package_name) {
    if (!package_name) return false;

    // Convert to lowercase for comparison
    char* lower_name = strdup(package_name);
    if (!lower_name) return false;

    for (char* p = lower_name; *p; p++) {
        *p = tolower(*p);
    }

    bool is_crypto = false;
    for (int i = 0; CRYPTO_LIBRARIES[i] != NULL; i++) {
        if (strstr(lower_name, CRYPTO_LIBRARIES[i]) != NULL) {
            is_crypto = true;
            break;
        }
    }

    free(lower_name);
    return is_crypto;
}

// Detect FIPS level from package name and version (STUB - not validated)
fips_level_t detect_fips_level_basic(const char* package_name, const char* version) {
    if (!package_name) return FIPS_UNKNOWN;

    // Check package name for FIPS indicators
    char* lower_name = strdup(package_name);
    char* lower_version = version ? strdup(version) : NULL;

    if (!lower_name) return FIPS_UNKNOWN;

    for (char* p = lower_name; *p; p++) *p = tolower(*p);
    if (lower_version) {
        for (char* p = lower_version; *p; p++) *p = tolower(*p);
    }

    fips_level_t level = FIPS_NOT_CERTIFIED;  // Default

    // Check for FIPS in package name
    if (strstr(lower_name, "fips") != NULL) {
        level = FIPS_LEVEL_140_3_L1;  // Default to Level 1
    }

    // Check for FIPS in version string
    if (lower_version && strstr(lower_version, "fips") != NULL) {
        level = FIPS_LEVEL_140_3_L1;
    }

    free(lower_name);
    free(lower_version);

    return level;
}

// Check if FIPS mode is enabled on system
bool is_fips_enabled_system(void) {
    FILE* fp = fopen("/proc/sys/crypto/fips_enabled", "r");
    if (!fp) return false;

    char buffer[8];
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        fclose(fp);
        return buffer[0] == '1';
    }

    fclose(fp);
    return false;
}

// Detect implemented algorithms for a crypto library
char** detect_implemented_algorithms(const char* library_name, const char* version,
                                     size_t* count) {
    if (!library_name || !count) return NULL;

    // Version parameter reserved for future version-specific algorithm detection
    (void)version;

    *count = 0;

    // Simplified algorithm detection based on library name
    // In production, this would query library symbols or configuration

    char** algorithms = malloc(sizeof(char*) * 50);
    if (!algorithms) return NULL;

    char* lower_name = strdup(library_name);
    if (!lower_name) {
        free(algorithms);
        return NULL;
    }
    for (char* p = lower_name; *p; p++) *p = tolower(*p);

    // OpenSSL family
    if (strstr(lower_name, "openssl") || strstr(lower_name, "libssl") ||
        strstr(lower_name, "libcrypto")) {
        algorithms[(*count)++] = strdup("AES");
        algorithms[(*count)++] = strdup("RSA");
        algorithms[(*count)++] = strdup("ECDSA");
        algorithms[(*count)++] = strdup("SHA-256");
        algorithms[(*count)++] = strdup("SHA-384");
        algorithms[(*count)++] = strdup("SHA-512");
        algorithms[(*count)++] = strdup("HMAC");
        algorithms[(*count)++] = strdup("ChaCha20");
        algorithms[(*count)++] = strdup("Poly1305");
    }
    // GnuTLS
    else if (strstr(lower_name, "gnutls")) {
        algorithms[(*count)++] = strdup("AES");
        algorithms[(*count)++] = strdup("RSA");
        algorithms[(*count)++] = strdup("ECDSA");
        algorithms[(*count)++] = strdup("SHA-256");
        algorithms[(*count)++] = strdup("SHA-512");
    }
    // WolfSSL
    else if (strstr(lower_name, "wolfssl")) {
        algorithms[(*count)++] = strdup("AES");
        algorithms[(*count)++] = strdup("RSA");
        algorithms[(*count)++] = strdup("ECDSA");
        algorithms[(*count)++] = strdup("SHA-256");
        algorithms[(*count)++] = strdup("ChaCha20");
    }
    // Python cryptography
    else if (strstr(lower_name, "cryptography")) {
        algorithms[(*count)++] = strdup("AES");
        algorithms[(*count)++] = strdup("RSA");
        algorithms[(*count)++] = strdup("ECDSA");
        algorithms[(*count)++] = strdup("SHA-256");
        algorithms[(*count)++] = strdup("HMAC");
    }
    // Generic crypto package
    else {
        algorithms[(*count)++] = strdup("AES");
        algorithms[(*count)++] = strdup("SHA-256");
    }

    free(lower_name);

    if (*count == 0) {
        free(algorithms);
        return NULL;
    }

    return algorithms;
}

// Create default configuration
package_scanner_config_t package_scanner_create_default_config(void) {
    package_scanner_config_t config = {0};

    // Enable all package managers by default
    config.scan_system_packages = true;
    config.scan_app_packages = true;

    config.scan_apt = true;
    config.scan_rpm = true;
    config.scan_pacman = true;
    config.scan_pip = true;
    config.scan_npm = true;
    config.scan_gem = true;
    config.scan_snap = false;  // Deferred
    config.scan_flatpak = false;  // Deferred

    // Resource limits
    config.max_packages = 10000;
    config.timeout_seconds = 30;

    // FIPS detection (STUB ONLY)
    config.detect_fips_basic = true;
    config.fips_validation_online = false;  // Deferred to future

    // Filter options
    config.crypto_only = true;  // Only scan crypto packages
    config.include_patterns = NULL;
    config.include_pattern_count = 0;
    config.exclude_patterns = NULL;
    config.exclude_pattern_count = 0;

    return config;
}

// Destroy configuration
void package_scanner_config_destroy(package_scanner_config_t* config) {
    if (!config) return;

    if (config->include_patterns) {
        for (size_t i = 0; i < config->include_pattern_count; i++) {
            free(config->include_patterns[i]);
        }
        free(config->include_patterns);
    }

    if (config->exclude_patterns) {
        for (size_t i = 0; i < config->exclude_pattern_count; i++) {
            free(config->exclude_patterns[i]);
        }
        free(config->exclude_patterns);
    }

    memset(config, 0, sizeof(package_scanner_config_t));
}

// Create package scanner context
package_scanner_context_t* package_scanner_create(const package_scanner_config_t* config,
                                                 struct asset_store* store) {
    if (!config || !store) {
        set_error("Invalid parameters: config or store is NULL");
        return NULL;
    }

    package_scanner_context_t* context = secure_alloc(sizeof(package_scanner_context_t));
    if (!context) {
        set_error("Failed to allocate package scanner context");
        return NULL;
    }

    // Copy configuration
    context->config = *config;
    context->asset_store = store;
    context->scan_context = NULL;

    // Initialize statistics
    memset(&context->stats, 0, sizeof(package_scanner_stats_t));

    // Initialize mutex
    if (pthread_mutex_init(&context->mutex, NULL) != 0) {
        set_error("Failed to initialize mutex");
        secure_free(context, sizeof(package_scanner_context_t));
        return NULL;
    }

    return context;
}

// Destroy package scanner context
void package_scanner_destroy(package_scanner_context_t* context) {
    if (!context) return;

    pthread_mutex_destroy(&context->mutex);
    secure_zero(context, sizeof(package_scanner_context_t));
    secure_free(context, sizeof(package_scanner_context_t));
}

// Extract package metadata
package_metadata_t* package_extract_metadata(const char* name, const char* version,
                                            package_manager_t manager) {
    if (!name) return NULL;

    package_metadata_t* metadata = secure_alloc(sizeof(package_metadata_t));
    if (!metadata) return NULL;

    memset(metadata, 0, sizeof(package_metadata_t));

    // Basic metadata
    metadata->name = strdup(name);
    metadata->version = version ? strdup(version) : NULL;
    metadata->package_manager = manager;
    metadata->package_type = (manager == PKG_MANAGER_APT ||
                             manager == PKG_MANAGER_RPM ||
                             manager == PKG_MANAGER_PACMAN) ?
                             PACKAGE_TYPE_SYSTEM : PACKAGE_TYPE_APPLICATION;

    // Check if crypto library
    metadata->is_crypto_library = is_crypto_library(name);

    // Detect implemented algorithms (if crypto library)
    if (metadata->is_crypto_library) {
        metadata->implemented_algorithms = detect_implemented_algorithms(
            name, version, &metadata->algorithm_count);
    }

    // FIPS detection (STUB ONLY - not validated)
    if (metadata->is_crypto_library) {
        metadata->fips_level = detect_fips_level_basic(name, version);
        metadata->fips_detected = true;
        metadata->fips_method = FIPS_DETECT_PACKAGE_NAME;

        if (is_fips_enabled_system()) {
            metadata->fips_method = FIPS_DETECT_PROC_FLAG;
            metadata->fips_detection_note = strdup("System FIPS mode enabled");
        }
    } else {
        metadata->fips_level = FIPS_NOT_CERTIFIED;
        metadata->fips_detected = false;
    }

    // Detection metadata
    metadata->detection_method = strdup("package_manager_query");
    metadata->confidence = 1.0;
    metadata->scan_time = time(NULL);

    return metadata;
}

// Destroy package metadata
void package_metadata_destroy(package_metadata_t* metadata) {
    if (!metadata) return;

    free(metadata->name);
    free(metadata->version);
    free(metadata->install_path);
    free(metadata->description);
    free(metadata->fips_module_id);
    free(metadata->fips_detection_note);
    free(metadata->provider);
    free(metadata->architecture);
    free(metadata->detection_method);

    if (metadata->implemented_algorithms) {
        for (size_t i = 0; i < metadata->algorithm_count; i++) {
            free(metadata->implemented_algorithms[i]);
        }
        free(metadata->implemented_algorithms);
    }

    if (metadata->dependencies) {
        for (size_t i = 0; i < metadata->dependency_count; i++) {
            free(metadata->dependencies[i]);
        }
        free(metadata->dependencies);
    }

    secure_zero(metadata, sizeof(package_metadata_t));
    secure_free(metadata, sizeof(package_metadata_t));
}

// Create detailed JSON metadata
char* package_create_detailed_json_metadata(const package_metadata_t* metadata) {
    if (!metadata) return NULL;

    json_object* root = json_object_new_object();
    if (!root) return NULL;

    // Package information
    if (metadata->name) {
        json_object_object_add(root, "name", json_object_new_string(metadata->name));
    }
    if (metadata->version) {
        json_object_object_add(root, "version", json_object_new_string(metadata->version));
    }

    json_object_object_add(root, "package_manager",
        json_object_new_string(package_manager_to_string(metadata->package_manager)));

    json_object_object_add(root, "is_crypto_library",
        json_object_new_boolean(metadata->is_crypto_library));

    // Implemented algorithms
    if (metadata->implemented_algorithms && metadata->algorithm_count > 0) {
        json_object* algos_array = json_object_new_array();
        for (size_t i = 0; i < metadata->algorithm_count; i++) {
            json_object_array_add(algos_array,
                json_object_new_string(metadata->implemented_algorithms[i]));
        }
        json_object_object_add(root, "implemented_algorithms", algos_array);
    }

    // FIPS metadata (STUB ONLY - not validated)
    json_object_object_add(root, "fips_level",
        json_object_new_string(fips_level_to_string(metadata->fips_level)));
    json_object_object_add(root, "fips_detected",
        json_object_new_boolean(metadata->fips_detected));

    if (metadata->fips_detection_note) {
        json_object_object_add(root, "fips_detection_note",
            json_object_new_string(metadata->fips_detection_note));
    }

    // Include FIPS limitation warning
    json_object_object_add(root, "fips_validation_status",
        json_object_new_string("STUB_ONLY_NOT_VALIDATED"));

    // Installation metadata
    if (metadata->install_path) {
        json_object_object_add(root, "install_path",
            json_object_new_string(metadata->install_path));
    }
    if (metadata->architecture) {
        json_object_object_add(root, "architecture",
            json_object_new_string(metadata->architecture));
    }

    // Convert to string
    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = NULL;
    if (json_str) {
        result = malloc(strlen(json_str) + 1);
        if (result) {
            strcpy(result, json_str);
        }
    }

    json_object_put(root);
    return result;
}

// Create package asset
struct crypto_asset* package_create_asset(const package_metadata_t* metadata) {
    if (!metadata) return NULL;

    // Create asset name
    char asset_name[256];
    snprintf(asset_name, sizeof(asset_name), "%s", metadata->name);

    crypto_asset_t* asset = crypto_asset_create(asset_name, ASSET_TYPE_LIBRARY);
    if (!asset) return NULL;

    // Set version as algorithm field (will be extracted to properties)
    if (metadata->version) {
        free(asset->algorithm);
        asset->algorithm = strdup(metadata->version);
    }

    // Set location
    if (metadata->install_path) {
        asset->location = strdup(metadata->install_path);
    }

    // Generate normalized ID: library|name|version|package_manager
    char id_string[512];
    snprintf(id_string, sizeof(id_string), "library|%s|%s|%s",
            metadata->name,
            metadata->version ? metadata->version : "unknown",
            package_manager_to_string(metadata->package_manager));

    // Free default ID and set normalized ID
    free(asset->id);
    asset->id = strdup(id_string);

    // Store detailed metadata as JSON
    asset->metadata_json = package_create_detailed_json_metadata(metadata);

    return asset;
}

// Scan APT packages
int scan_apt_packages(package_scanner_context_t* context) {
    if (!context) return -1;

    if (!package_manager_available(PKG_MANAGER_APT)) {
        return 0;  // Not available, skip
    }

    FILE* fp = fopen("/var/lib/dpkg/status", "r");
    if (!fp) {
        pthread_mutex_lock(&context->mutex);
        context->stats.permission_errors++;
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }

    char line[1024];
    char* current_package = NULL;
    char* current_version = NULL;
    int packages_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Parse Package: field
        if (strncmp(line, "Package: ", 9) == 0) {
            free(current_package);
            current_package = strdup(line + 9);
            if (current_package) {
                // Remove newline
                current_package[strcspn(current_package, "\n")] = 0;
            }
        }
        // Parse Version: field
        else if (strncmp(line, "Version: ", 9) == 0) {
            free(current_version);
            current_version = strdup(line + 9);
            if (current_version) {
                current_version[strcspn(current_version, "\n")] = 0;
            }
        }
        // Empty line = end of package entry
        else if (line[0] == '\n' && current_package) {
            // Check if this is a crypto library
            if (!context->config.crypto_only || is_crypto_library(current_package)) {
                // Extract metadata
                package_metadata_t* metadata = package_extract_metadata(
                    current_package, current_version, PKG_MANAGER_APT);

                if (metadata) {
                    // Create asset
                    crypto_asset_t* asset = package_create_asset(metadata);
                    if (asset && context->asset_store) {
                        asset_store_add(context->asset_store, asset);
                        packages_found++;

                        // Phase 4: Create PROVIDES relationships for implemented algorithms
                        if (metadata->implemented_algorithms && metadata->algorithm_count > 0) {
                            for (size_t alg_idx = 0; alg_idx < metadata->algorithm_count; alg_idx++) {
                                const char* algo_name = metadata->implemented_algorithms[alg_idx];
                                if (!algo_name || strlen(algo_name) == 0) continue;

                                // Generate algorithm bom-ref (v1.5: use algo: prefix for consistency)
                                char algo_ref[128];
                                snprintf(algo_ref, sizeof(algo_ref), "algo:%s", algo_name);
                                // Lowercase (after prefix)
                                for (char* p = algo_ref + 5; *p; p++) {  // Skip "algo:" prefix
                                    *p = tolower(*p);
                                }

                                // v1.5: Create algorithm component if it doesn't exist
                                crypto_asset_t* algo_asset = malloc(sizeof(crypto_asset_t));
                                if (algo_asset) {
                                    memset(algo_asset, 0, sizeof(crypto_asset_t));
                                    algo_asset->type = ASSET_TYPE_ALGORITHM;
                                    algo_asset->name = strdup(algo_name);
                                    algo_asset->id = strdup(algo_ref);  // Use algo: bom-ref as ID
                                    algo_asset->algorithm = strdup(algo_name);

                                    // Try to add (will be deduplicated if already exists)
                                    asset_store_add(context->asset_store, algo_asset);
                                }

                                // Create PROVIDES relationship from library to algorithm
                                relationship_t* provides_rel = relationship_create(
                                    RELATIONSHIP_PROVIDES,
                                    asset->id,      // From: library
                                    algo_ref,       // To: algorithm (by bom-ref)
                                    0.85            // Confidence
                                );

                                if (provides_rel) {
                                    asset_store_add_relationship(context->asset_store, provides_rel);
                                }
                            }
                        }

                        pthread_mutex_lock(&context->mutex);
                        context->stats.apt_packages++;
                        if (metadata->is_crypto_library) {
                            context->stats.crypto_packages_found++;

                            // Count specific libraries
                            if (strstr(current_package, "openssl")) {
                                context->stats.openssl_found++;
                            } else if (strstr(current_package, "gnutls")) {
                                context->stats.gnutls_found++;
                            }

                            // FIPS statistics
                            if (metadata->fips_level != FIPS_NOT_CERTIFIED &&
                                metadata->fips_level != FIPS_UNKNOWN) {
                                context->stats.fips_certified_packages++;
                            } else {
                                context->stats.fips_not_certified_packages++;
                            }
                        }
                        pthread_mutex_unlock(&context->mutex);
                    }

                    package_metadata_destroy(metadata);
                }
            }

            free(current_package);
            free(current_version);
            current_package = NULL;
            current_version = NULL;
        }
    }

    free(current_package);
    free(current_version);
    fclose(fp);

    pthread_mutex_lock(&context->mutex);
    context->stats.packages_scanned_total += packages_found;
    pthread_mutex_unlock(&context->mutex);

    return packages_found;
}

// Scan RPM packages
int scan_rpm_packages(package_scanner_context_t* context) {
    if (!context) return -1;

    if (!package_manager_available(PKG_MANAGER_RPM)) {
        return 0;  // Not available
    }

    // Use rpm command to query packages
    FILE* fp = popen("rpm -qa --queryformat '%{NAME}|%{VERSION}\\n' 2>/dev/null", "r");
    if (!fp) {
        pthread_mutex_lock(&context->mutex);
        context->stats.missing_package_managers++;
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }

    char line[512];
    int packages_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Parse format: name|version
        char* separator = strchr(line, '|');
        if (!separator) continue;

        *separator = '\0';
        char* name = line;
        char* version = separator + 1;
        version[strcspn(version, "\n")] = 0;

        // Check if crypto library
        if (!context->config.crypto_only || is_crypto_library(name)) {
            package_metadata_t* metadata = package_extract_metadata(
                name, version, PKG_MANAGER_RPM);

            if (metadata) {
                crypto_asset_t* asset = package_create_asset(metadata);
                if (asset && context->asset_store) {
                    asset_store_add(context->asset_store, asset);
                    packages_found++;

                    pthread_mutex_lock(&context->mutex);
                    context->stats.rpm_packages++;
                    if (metadata->is_crypto_library) {
                        context->stats.crypto_packages_found++;
                    }
                    pthread_mutex_unlock(&context->mutex);
                }

                package_metadata_destroy(metadata);
            }
        }
    }

    pclose(fp);

    pthread_mutex_lock(&context->mutex);
    context->stats.packages_scanned_total += packages_found;
    pthread_mutex_unlock(&context->mutex);

    return packages_found;
}

// Scan Pacman packages
int scan_pacman_packages(package_scanner_context_t* context) {
    if (!context) return -1;

    if (!package_manager_available(PKG_MANAGER_PACMAN)) {
        return 0;
    }

    FILE* fp = popen("pacman -Q 2>/dev/null", "r");
    if (!fp) {
        pthread_mutex_lock(&context->mutex);
        context->stats.missing_package_managers++;
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }

    char line[512];
    int packages_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Format: name version
        char name[256], version[128];
        if (sscanf(line, "%255s %127s", name, version) == 2) {
            if (!context->config.crypto_only || is_crypto_library(name)) {
                package_metadata_t* metadata = package_extract_metadata(
                    name, version, PKG_MANAGER_PACMAN);

                if (metadata) {
                    crypto_asset_t* asset = package_create_asset(metadata);
                    if (asset && context->asset_store) {
                        asset_store_add(context->asset_store, asset);
                        packages_found++;

                        pthread_mutex_lock(&context->mutex);
                        context->stats.pacman_packages++;
                        if (metadata->is_crypto_library) {
                            context->stats.crypto_packages_found++;
                        }
                        pthread_mutex_unlock(&context->mutex);
                    }

                    package_metadata_destroy(metadata);
                }
            }
        }
    }

    pclose(fp);

    pthread_mutex_lock(&context->mutex);
    context->stats.packages_scanned_total += packages_found;
    pthread_mutex_unlock(&context->mutex);

    return packages_found;
}

// Scan pip packages
int scan_pip_packages(package_scanner_context_t* context) {
    if (!context) return -1;

    if (!package_manager_available(PKG_MANAGER_PIP)) {
        return 0;
    }

    // Try pip3 first, then pip
    FILE* fp = popen("pip3 list --format=json 2>/dev/null || pip list --format=json 2>/dev/null", "r");
    if (!fp) {
        pthread_mutex_lock(&context->mutex);
        context->stats.missing_package_managers++;
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }

    // Read entire JSON output
    char* json_output = NULL;
    size_t json_size = 0;
    size_t json_capacity = 4096;

    json_output = malloc(json_capacity);
    if (!json_output) {
        pclose(fp);
        return -1;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        if (json_size + len >= json_capacity) {
            json_capacity *= 2;
            char* new_output = realloc(json_output, json_capacity);
            if (!new_output) {
                free(json_output);
                pclose(fp);
                return -1;
            }
            json_output = new_output;
        }
        strcpy(json_output + json_size, buffer);
        json_size += len;
    }

    pclose(fp);

    // Parse JSON
    json_object* packages = json_tokener_parse(json_output);
    free(json_output);

    if (!packages || !json_object_is_type(packages, json_type_array)) {
        if (packages) json_object_put(packages);
        return -1;
    }

    int packages_found = 0;
    int array_len = json_object_array_length(packages);

    for (int i = 0; i < array_len; i++) {
        json_object* pkg = json_object_array_get_idx(packages, i);
        if (!pkg) continue;

        json_object* name_obj, *version_obj;
        if (json_object_object_get_ex(pkg, "name", &name_obj) &&
            json_object_object_get_ex(pkg, "version", &version_obj)) {

            const char* name = json_object_get_string(name_obj);
            const char* version = json_object_get_string(version_obj);

            if (!context->config.crypto_only || is_crypto_library(name)) {
                package_metadata_t* metadata = package_extract_metadata(
                    name, version, PKG_MANAGER_PIP);

                if (metadata) {
                    crypto_asset_t* asset = package_create_asset(metadata);
                    if (asset && context->asset_store) {
                        asset_store_add(context->asset_store, asset);
                        packages_found++;

                        pthread_mutex_lock(&context->mutex);
                        context->stats.pip_packages++;
                        if (metadata->is_crypto_library) {
                            context->stats.crypto_packages_found++;
                        }
                        pthread_mutex_unlock(&context->mutex);
                    }

                    package_metadata_destroy(metadata);
                }
            }
        }
    }

    json_object_put(packages);

    pthread_mutex_lock(&context->mutex);
    context->stats.packages_scanned_total += packages_found;
    pthread_mutex_unlock(&context->mutex);

    return packages_found;
}

// Scan npm packages
int scan_npm_packages(package_scanner_context_t* context) {
    if (!context) return -1;

    if (!package_manager_available(PKG_MANAGER_NPM)) {
        return 0;
    }

    FILE* fp = popen("npm list -g --json --depth=0 2>/dev/null", "r");
    if (!fp) {
        pthread_mutex_lock(&context->mutex);
        context->stats.missing_package_managers++;
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }

    // Read JSON output
    char* json_output = NULL;
    size_t json_size = 0;
    size_t json_capacity = 8192;

    json_output = malloc(json_capacity);
    if (!json_output) {
        pclose(fp);
        return -1;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        if (json_size + len >= json_capacity) {
            json_capacity *= 2;
            char* new_output = realloc(json_output, json_capacity);
            if (!new_output) {
                free(json_output);
                pclose(fp);
                return -1;
            }
            json_output = new_output;
        }
        strcpy(json_output + json_size, buffer);
        json_size += len;
    }

    pclose(fp);

    // Parse JSON
    json_object* root = json_tokener_parse(json_output);
    free(json_output);

    if (!root) return -1;

    int packages_found = 0;

    json_object* dependencies;
    if (json_object_object_get_ex(root, "dependencies", &dependencies)) {
        // Iterate over dependencies object
        json_object_object_foreach(dependencies, name, pkg_obj) {
            if (pkg_obj) {
                json_object* version_obj;
                const char* version = NULL;
                if (json_object_object_get_ex(pkg_obj, "version", &version_obj)) {
                    version = json_object_get_string(version_obj);
                }

                if (!context->config.crypto_only || is_crypto_library(name)) {
                    package_metadata_t* metadata = package_extract_metadata(
                        name, version, PKG_MANAGER_NPM);

                    if (metadata) {
                        crypto_asset_t* asset = package_create_asset(metadata);
                        if (asset && context->asset_store) {
                            asset_store_add(context->asset_store, asset);
                            packages_found++;

                            pthread_mutex_lock(&context->mutex);
                            context->stats.npm_packages++;
                            if (metadata->is_crypto_library) {
                                context->stats.crypto_packages_found++;
                            }
                            pthread_mutex_unlock(&context->mutex);
                        }

                        package_metadata_destroy(metadata);
                    }
                }
            }
        }
    }

    json_object_put(root);

    pthread_mutex_lock(&context->mutex);
    context->stats.packages_scanned_total += packages_found;
    pthread_mutex_unlock(&context->mutex);

    return packages_found;
}

// Scan RubyGems packages
int scan_gem_packages(package_scanner_context_t* context) {
    if (!context) return -1;

    if (!package_manager_available(PKG_MANAGER_GEM)) {
        return 0;
    }

    FILE* fp = popen("gem list --local 2>/dev/null", "r");
    if (!fp) {
        pthread_mutex_lock(&context->mutex);
        context->stats.missing_package_managers++;
        pthread_mutex_unlock(&context->mutex);
        return -1;
    }

    char line[512];
    int packages_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Format: name (version1, version2, ...)
        char name[256], version[128];
        if (sscanf(line, "%255s (%127[^)])", name, version) == 2) {
            // Extract first version if multiple
            char* comma = strchr(version, ',');
            if (comma) *comma = '\0';

            if (!context->config.crypto_only || is_crypto_library(name)) {
                package_metadata_t* metadata = package_extract_metadata(
                    name, version, PKG_MANAGER_GEM);

                if (metadata) {
                    crypto_asset_t* asset = package_create_asset(metadata);
                    if (asset && context->asset_store) {
                        asset_store_add(context->asset_store, asset);
                        packages_found++;

                        pthread_mutex_lock(&context->mutex);
                        context->stats.gem_packages++;
                        if (metadata->is_crypto_library) {
                            context->stats.crypto_packages_found++;
                        }
                        pthread_mutex_unlock(&context->mutex);
                    }

                    package_metadata_destroy(metadata);
                }
            }
        }
    }

    pclose(fp);

    pthread_mutex_lock(&context->mutex);
    context->stats.packages_scanned_total += packages_found;
    pthread_mutex_unlock(&context->mutex);

    return packages_found;
}

// Scan system packages (APT, RPM, Pacman)
int package_scanner_scan_system(package_scanner_context_t* context) {
    if (!context) return -1;

    int total = 0;

    if (context->config.scan_apt) {
        int count = scan_apt_packages(context);
        if (count > 0) total += count;
    }

    if (context->config.scan_rpm) {
        int count = scan_rpm_packages(context);
        if (count > 0) total += count;
    }

    if (context->config.scan_pacman) {
        int count = scan_pacman_packages(context);
        if (count > 0) total += count;
    }

    return total;
}

// Scan application packages (pip, npm, gems)
int package_scanner_scan_applications(package_scanner_context_t* context) {
    if (!context) return -1;

    int total = 0;

    if (context->config.scan_pip) {
        int count = scan_pip_packages(context);
        if (count > 0) total += count;
    }

    if (context->config.scan_npm) {
        int count = scan_npm_packages(context);
        if (count > 0) total += count;
    }

    if (context->config.scan_gem) {
        int count = scan_gem_packages(context);
        if (count > 0) total += count;
    }

    return total;
}

// Scan all packages
int package_scanner_scan_all(package_scanner_context_t* context) {
    if (!context) return -1;

    int total = 0;

    if (context->config.scan_system_packages) {
        int count = package_scanner_scan_system(context);
        if (count > 0) total += count;
    }

    if (context->config.scan_app_packages) {
        int count = package_scanner_scan_applications(context);
        if (count > 0) total += count;
    }

    return total;
}

// Get statistics
package_scanner_stats_t package_scanner_get_stats(const package_scanner_context_t* context) {
    if (!context) {
        package_scanner_stats_t empty = {0};
        return empty;
    }

    return context->stats;
}
