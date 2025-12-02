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
 * @file component_factory.c
 * @brief Component factory implementation
 */

#define _GNU_SOURCE
#include "component_factory.h"
#include "certificate_scanner.h"
#include "key_scanner.h"
#include "pqc_classifier.h"
#include "secure_memory.h"
#include "cipher_suite_parser.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/x509.h>

// Forward declaration for service library dependency detection
extern int detect_service_library_dependencies_simple(struct asset_store* store,
                                                      struct crypto_asset* service_asset,
                                                      const char* process_name,
                                                      pid_t pid);

// Forward declarations for protocol/cipher processing
extern int create_service_protocol_relationship(struct asset_store* store,
                                               const char* service_id,
                                               const char* protocol_id,
                                               float confidence);

extern int create_protocol_suite_relationship(struct asset_store* store,
                                             const char* protocol_id,
                                             const char* suite_id,
                                             float confidence);

extern int decompose_cipher_suite_to_algorithms(struct asset_store* store,
                                                const char* suite_id,
                                                const char* kex,
                                                const char* auth,
                                                const char* enc,
                                                const char* mac);

// Helper: Load certificate metadata from file
static cert_metadata_t* load_certificate_metadata(const char* cert_path) {
    cert_format_t format = cert_detect_format(cert_path);
    X509* cert = cert_load_from_file(cert_path, format);

    if (!cert) {
        return NULL;
    }

    cert_metadata_t* metadata = cert_extract_metadata(cert, cert_path);
    X509_free(cert);

    return metadata;
}

// Helper: Create JSON metadata object from certificate path
static struct json_object* create_cert_json_metadata_obj(const char* cert_path) {
    cert_format_t format = cert_detect_format(cert_path);
    X509* cert = cert_load_from_file(cert_path, format);
    if (!cert) return NULL;

    cert_metadata_t* metadata = cert_extract_metadata(cert, cert_path);
    if (!metadata) {
        X509_free(cert);
        return NULL;
    }

    char* json_str = cert_create_detailed_json_metadata(metadata, cert);
    struct json_object* json_obj = NULL;

    if (json_str) {
        json_obj = json_tokener_parse(json_str);
        free(json_str);
    }

    cert_metadata_destroy(metadata);
    X509_free(cert);

    return json_obj;
}

// Helper: Create metadata JSON for service component
static char* create_service_metadata_json(service_instance_t* service) {
    struct json_object* root = json_object_new_object();

    json_object_object_add(root, "service_name", json_object_new_string(service->service_name));
    json_object_object_add(root, "detected_by", json_object_new_string(service->detected_by));
    json_object_object_add(root, "detection_method", json_object_new_string(service->detection_method));

    if (service->pid > 0) {
        json_object_object_add(root, "pid", json_object_new_int64(service->pid));
    }

    if (service->process_name) {
        json_object_object_add(root, "process_name", json_object_new_string(service->process_name));
    }

    if (service->port > 0) {
        json_object_object_add(root, "port", json_object_new_int64(service->port));
        json_object_object_add(root, "protocol", json_object_new_string(service->protocol ? service->protocol : "tcp"));
    }

    if (service->bind_address) {
        json_object_object_add(root, "bind_address", json_object_new_string(service->bind_address));
    }

    json_object_object_add(root, "tls_enabled", json_object_new_boolean(service->tls_enabled));

    if (service->config_dir) {
        json_object_object_add(root, "config_dir", json_object_new_string(service->config_dir));
    }

    if (service->config_file_path) {
        json_object_object_add(root, "config_file", json_object_new_string(service->config_file_path));
    }

    if (service->version) {
        json_object_object_add(root, "version", json_object_new_string(service->version));
    }

    if (service->package_name) {
        json_object_object_add(root, "package_name", json_object_new_string(service->package_name));
    }

    json_object_object_add(root, "confidence", json_object_new_double(service->confidence));
    json_object_object_add(root, "discovered_at", json_object_new_int64(service->discovered_at));

    // v1.5: Add application-specific properties for services
    json_object_object_add(root, "is_daemon", json_object_new_boolean(true));

    // Infer category from service name
    const char* category = "network_server";
    if (service->service_name) {
        const char* name = service->service_name;
        if (strstr(name, "nginx") || strstr(name, "apache") || strstr(name, "httpd") || strstr(name, "caddy")) {
            category = "web_server";
        } else if (strstr(name, "postgres") || strstr(name, "mysql") || strstr(name, "mariadb") || strstr(name, "mongo") || strstr(name, "redis")) {
            category = "database_server";
        } else if (strstr(name, "sshd")) {
            category = "ssh_server";
        } else if (strstr(name, "docker") || strstr(name, "containerd") || strstr(name, "podman")) {
            category = "container_runtime";
        } else if (strstr(name, "openvpn") || strstr(name, "wireguard")) {
            category = "vpn_server";
        } else if (strstr(name, "dns") || strstr(name, "bind")) {
            category = "dns_server";
        }
    }
    json_object_object_add(root, "category", json_object_new_string(category));

    // Role: All YAML plugin-detected components are services (server daemons)
    json_object_object_add(root, "role", json_object_new_string("service"));

    if (service->binary_path) {
        json_object_object_add(root, "binary_path", json_object_new_string(service->binary_path));
    }

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = strdup(json_str);

    json_object_put(root);  // This also frees json_str

    return result;
}

// Helper: Create metadata JSON for protocol component
static char* create_protocol_metadata_json(const char* protocol_name, const char* version) {
    struct json_object* root = json_object_new_object();

    // v1.5.1: Use correct field names that match CycloneDX output expectations
    json_object_object_add(root, "protocol_type", json_object_new_string(protocol_name));  // "TLS", "SSH", etc.
    json_object_object_add(root, "version", json_object_new_string(version));  // "1.2", "2.0", etc.
    json_object_object_add(root, "component_type", json_object_new_string("protocol"));

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = strdup(json_str);

    json_object_put(root);  // This also frees json_str

    return result;
}

// Helper: Convert key_type_t to algorithm string
static const char* key_type_to_algo_string(key_type_t type) {
    switch (type) {
        case KEY_TYPE_RSA: return "RSA";
        case KEY_TYPE_ECDSA: return "ECDSA";
        case KEY_TYPE_ED25519: return "Ed25519";
        case KEY_TYPE_ED448: return "Ed448";
        case KEY_TYPE_DSA: return "DSA";
        case KEY_TYPE_DH: return "DH";
        default: return "Unknown";
    }
}

// Helper: Create metadata JSON for key component
static char* create_key_metadata_json(const char* key_path, const char* algorithm, int key_size) {
    struct json_object* root = json_object_new_object();

    json_object_object_add(root, "key_path", json_object_new_string(key_path));
    json_object_object_add(root, "component_type", json_object_new_string("private_key"));

    if (algorithm) {
        json_object_object_add(root, "algorithm", json_object_new_string(algorithm));
    }
    if (key_size > 0) {
        json_object_object_add(root, "key_size", json_object_new_int(key_size));
    }

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = strdup(json_str);

    json_object_put(root);  // This also frees json_str

    return result;
}

crypto_asset_t* component_factory_create_service(
    service_instance_t* service,
    asset_store_t* store
) {
    if (!service || !store) {
        return NULL;
    }

    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) {
        return NULL;
    }

    memset(asset, 0, sizeof(crypto_asset_t));

    // Set basic properties
    asset->type = ASSET_TYPE_APPLICATION;
    asset->name = strdup(service->service_name);

    if (service->version) {
        asset->version = strdup(service->version);
    }

    if (service->config_file_path) {
        asset->location = strdup(service->config_file_path);
    } else if (service->config_dir) {
        asset->location = strdup(service->config_dir);
    }

    // Create metadata JSON
    asset->metadata_json = create_service_metadata_json(service);

    // Generate content-addressed ID
    asset->id = generate_asset_id(asset);

    return asset;
}

crypto_asset_t* component_factory_create_certificate(
    const char* cert_path,
    const char* service_id,
    asset_store_t* store
) {
    (void)service_id;  // Reserved for future relationship creation

    if (!cert_path || !store) {
        return NULL;
    }

    // Use existing certificate scanner to extract metadata
    cert_metadata_t* cert_meta = load_certificate_metadata(cert_path);
    if (!cert_meta) {
        fprintf(stderr, "Failed to load certificate: %s\n", cert_path);
        return NULL;
    }

    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) {
        cert_metadata_destroy(cert_meta);
        return NULL;
    }

    memset(asset, 0, sizeof(crypto_asset_t));

    // Set basic properties
    asset->type = ASSET_TYPE_CERTIFICATE;
    asset->name = strdup(cert_meta->subject);  // Use subject DN as name
    asset->location = strdup(cert_path);

    // Extract algorithm info
    if (cert_meta->public_key_algorithm) {
        asset->algorithm = strdup(cert_meta->public_key_algorithm);
    }

    asset->key_size = cert_meta->public_key_size;

    // Apply PQC assessment using correct API
    if (cert_meta->public_key_algorithm) {
        pqc_category_t pqc_cat = classify_algorithm_pqc_safety(
            cert_meta->public_key_algorithm,
            cert_meta->public_key_size,
            PRIMITIVE_SIGNATURE  // Certificates use signature algorithms
        );
        asset->is_pqc_ready = (pqc_cat == PQC_SAFE);
        asset->is_weak = (pqc_cat == PQC_DEPRECATED || pqc_cat == PQC_UNSAFE);
    }

    // Create detailed metadata JSON - need to reload cert for full function
    struct json_object* json_obj = create_cert_json_metadata_obj(cert_path);
    if (json_obj) {
        asset->metadata_json = strdup(json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PLAIN));
        json_object_put(json_obj);
    }

    // Generate content-addressed ID
    asset->id = generate_asset_id(asset);

    // Cleanup
    cert_metadata_destroy(cert_meta);

    return asset;
}

crypto_asset_t* component_factory_create_private_key(
    const char* key_path,
    const char* cert_id,
    asset_store_t* store
) {
    (void)cert_id;  // Reserved for future relationship creation

    if (!key_path || !store) {
        return NULL;
    }

    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) {
        return NULL;
    }

    memset(asset, 0, sizeof(crypto_asset_t));

    // Set basic properties
    asset->type = ASSET_TYPE_KEY;
    asset->location = strdup(key_path);

    // Parse key to extract algorithm and key size
    const char* algo_name = NULL;
    int key_bits = 0;

    EVP_PKEY* pkey = key_load_pem(key_path, NULL);
    if (pkey) {
        key_type_t type = key_get_type(pkey);
        key_bits = EVP_PKEY_bits(pkey);

        algo_name = key_type_to_algo_string(type);
        asset->algorithm = strdup(algo_name);
        asset->key_size = key_bits;

        // Generate meaningful name: "RSA-2048 Private Key"
        char name_buf[128];
        snprintf(name_buf, sizeof(name_buf), "%s-%d Private Key", algo_name, key_bits);
        asset->name = strdup(name_buf);

        EVP_PKEY_free(pkey);
    } else {
        // Fallback to file path if parse fails
        asset->name = strdup(key_path);
    }

    // Create metadata JSON with algorithm info
    asset->metadata_json = create_key_metadata_json(key_path, algo_name, key_bits);

    // Generate content-addressed ID
    asset->id = generate_asset_id(asset);

    return asset;
}

crypto_asset_t* component_factory_create_protocol(
    const char* protocol_name,
    const char* version,
    const char* service_id,
    asset_store_t* store
) {
    (void)service_id;  // Reserved for future relationship creation

    if (!protocol_name || !version || !store) {
        return NULL;
    }

    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) {
        return NULL;
    }

    memset(asset, 0, sizeof(crypto_asset_t));

    // Set basic properties
    asset->type = ASSET_TYPE_PROTOCOL;

    // Format name as "TLS 1.2"
    char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "%s %s", protocol_name, version);
    asset->name = strdup(name_buf);
    asset->version = strdup(version);

    // Create metadata JSON
    asset->metadata_json = create_protocol_metadata_json(protocol_name, version);

    // Generate content-addressed ID
    asset->id = generate_asset_id(asset);

    return asset;
}

crypto_asset_t* component_factory_create_cipher_suite(
    const char* cipher_suite,
    const char* protocol_id,
    asset_store_t* store
) {
    (void)protocol_id;  // Reserved for future relationship creation

    if (!cipher_suite || !store) {
        return NULL;
    }

    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) {
        return NULL;
    }

    memset(asset, 0, sizeof(crypto_asset_t));

    // Set basic properties
    asset->type = ASSET_TYPE_CIPHER_SUITE;
    asset->name = strdup(cipher_suite);

    // Parse cipher suite name for algorithm hints
    // e.g., "ECDHE-RSA-AES256-GCM-SHA384" -> algorithm = "ECDHE-RSA"
    char* first_hyphen = strchr(cipher_suite, '-');
    if (first_hyphen) {
        char* second_hyphen = strchr(first_hyphen + 1, '-');
        if (second_hyphen) {
            size_t algo_len = second_hyphen - cipher_suite;
            char* algo = malloc(algo_len + 1);
            if (algo) {
                strncpy(algo, cipher_suite, algo_len);
                algo[algo_len] = '\0';
                asset->algorithm = algo;
            }
        }
    }

    // Apply PQC assessment to key exchange algorithm
    if (asset->algorithm) {
        pqc_category_t pqc_cat = classify_algorithm_pqc_safety(
            asset->algorithm,
            0,  // Key size unknown for cipher suite string
            PRIMITIVE_KEY_EXCHANGE  // Cipher suites use key exchange
        );
        asset->is_pqc_ready = (pqc_cat == PQC_SAFE);
        asset->is_weak = (pqc_cat == PQC_DEPRECATED || pqc_cat == PQC_UNSAFE);
    }

    // Create simple metadata JSON
    struct json_object* root = json_object_new_object();
    json_object_object_add(root, "cipher_suite", json_object_new_string(cipher_suite));
    json_object_object_add(root, "component_type", json_object_new_string("cipher_suite"));

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    asset->metadata_json = strdup(json_str);
    json_object_put(root);  // This also frees json_str

    // Generate content-addressed ID
    asset->id = generate_asset_id(asset);

    return asset;
}

int component_factory_process_service(
    service_instance_t* service,
    crypto_config_t* config,
    asset_store_t* store
) {
    if (!service || !config || !store) {
        return -1;
    }

    // NOTE: YAML plugins are curated for crypto-relevant services.
    // We trust the plugin author's judgment that a plugin exists because
    // the service uses crypto (TLS, SSH, certificates, etc.).
    // Aggressive filtering was removed in v1.7.2 because it caused
    // false negatives for services like dropbear, chrony where binary
    // analysis failed (binary not found, cross-arch mode, etc.).

    // 1. Create service component
    crypto_asset_t* service_asset = component_factory_create_service(service, store);
    if (!service_asset) {
        fprintf(stderr, "Failed to create service component for %s\n", service->service_name);
        return -1;
    }

    int result = asset_store_add(store, service_asset);
    if (result != 0 && result != 1) {  // 0 = added, 1 = duplicate
        fprintf(stderr, "Failed to add service component to store\n");
        crypto_asset_destroy(service_asset);
        return -1;
    }

    // Detect library dependencies (optional - doesn't fail service creation)
    // Priority: binary_path > process_name > service_name
    // binary_path enables library detection even for stopped services
    const char* proc_name = NULL;
    if (service->binary_path) {
        // Binary detection provides direct path to executable
        proc_name = service->binary_path;
    } else if (service->process_name) {
        // Running process provides process name
        proc_name = service->process_name;
    } else {
        // Fallback to service name for config-detected services
        proc_name = service->service_name;
    }

    if (proc_name) {
        int lib_count = detect_service_library_dependencies_simple(
            store,
            service_asset,
            proc_name,
            service->pid
        );

        if (lib_count > 0) {
            fprintf(stderr, "[INFO] %s: %d crypto library dependencies (via %s)\n",
                    service->service_name, lib_count,
                    service->binary_path ? "binary_path" :
                    service->process_name ? "process_name" : "service_name");
        }
        // Ignore errors/0 results - service creation continues regardless
    }

    const char* service_id = service_asset->id;

    // 2. Create certificate components
    char* first_cert_id = NULL;
    for (int i = 0; i < config->certificate_count; i++) {
        crypto_asset_t* cert_asset = component_factory_create_certificate(
            config->certificate_paths[i],
            service_id,
            store
        );

        if (cert_asset) {
            result = asset_store_add(store, cert_asset);
            if (result == 0 || result == 1) {
                // Create SERVICE → CERTIFICATE relationship
                relationship_t* rel = relationship_create(RELATIONSHIP_AUTHENTICATES_WITH, service_id, cert_asset->id, 0.90);
                if (rel) {
                    asset_store_add_relationship(store, rel);
                }

                // Remember first cert for key association
                if (i == 0 && !first_cert_id) {
                    first_cert_id = strdup(cert_asset->id);
                }
            } else {
                crypto_asset_destroy(cert_asset);
            }
        }
    }

    // 3. Create private key components
    for (int i = 0; i < config->private_key_count; i++) {
        const char* associated_cert_id = (i < config->certificate_count && first_cert_id) ? first_cert_id : NULL;

        crypto_asset_t* key_asset = component_factory_create_private_key(
            config->private_key_paths[i],
            associated_cert_id,
            store
        );

        if (key_asset) {
            result = asset_store_add(store, key_asset);
            if (result == 0 || result == 1) {
                // Create CERTIFICATE → KEY relationship if cert exists
                if (associated_cert_id) {
                    relationship_t* rel = relationship_create(RELATIONSHIP_AUTHENTICATES_WITH,
                                      associated_cert_id, key_asset->id, 0.90);
                    if (rel) {
                        asset_store_add_relationship(store, rel);
                    }
                }
            } else {
                crypto_asset_destroy(key_asset);
            }
        }
    }

    // 4. Create protocol components (multiple versions if configured)
    // v1.5.1: Support TLS version ranges (TLSv1.2 + TLSv1.3 → 2 protocol assets)
    char** protocol_ids = NULL;
    int protocol_id_count = 0;

    // Check if plugin defines a crypto protocol
    bool has_plugin_protocol = false;
    if (service->plugin) {
        yaml_plugin_t* plugin = (yaml_plugin_t*)service->plugin;
        has_plugin_protocol = (plugin->metadata.crypto_protocol != NULL);
    }

    bool should_create_protocol = has_plugin_protocol ||  // Plugin defines protocol (SSH, TLS, etc.)
                                  config->min_tls_version ||
                                  config->tls_version_count > 0 ||
                                  config->tls_enabled ||
                                  config->certificate_count > 0 ||
                                  config->cipher_count > 0 ||
                                  service->tls_enabled;

    if (should_create_protocol) {
        // v1.5.1: Get protocol type from plugin metadata (not hardcoded to "TLS")
        const char* protocol_type = "TLS";  // Default to TLS
        if (service->plugin) {
            yaml_plugin_t* plugin = (yaml_plugin_t*)service->plugin;
            if (plugin->metadata.crypto_protocol) {
                protocol_type = plugin->metadata.crypto_protocol;  // Use "SSH", "IPSec", etc. from plugin
            }
        }

        // v1.5.1: Create protocol for EACH TLS version (fixes KNOWN_ISSUES.md #4)
        int versions_to_create = (config->tls_version_count > 0) ? config->tls_version_count : 1;
        protocol_ids = malloc(versions_to_create * sizeof(char*));

        for (int v = 0; v < versions_to_create; v++) {
            // Get version for this iteration
            const char* protocol_version = NULL;
            if (config->tls_version_count > 0) {
                protocol_version = config->tls_versions[v];  // Use array version
            } else if (config->min_tls_version) {
                protocol_version = config->min_tls_version;  // Fallback to single version
            } else {
                protocol_version = (strcmp(protocol_type, "SSH") == 0) ? "2.0" : "1.2";  // Default
            }

            crypto_asset_t* protocol_asset = component_factory_create_protocol(
                protocol_type,       // Use plugin-defined protocol type
                protocol_version,    // Specific version (1.2, 1.3, etc.)
                service_id,
                store
            );

            if (protocol_asset) {
                result = asset_store_add(store, protocol_asset);
                if (result == 0 || result == 1) {
                    // Create SERVICE → PROTOCOL relationship
                    create_service_protocol_relationship(store, service_id,
                                                        protocol_asset->id, 0.95);

                    protocol_ids[protocol_id_count++] = strdup(protocol_asset->id);
                } else {
                    crypto_asset_destroy(protocol_asset);
                }
            }
        }
    }

    // 5. Create cipher suite components with advanced parsing
    // v1.5.1: Associate cipher suites with appropriate protocol versions
    // v1.5.2: Add default cipher fallback when configs don't specify ciphers
    // v1.9.1: Skip TLS cipher suites for SSH protocol (SSH KEX handled via library path)
    bool is_ssh_protocol = false;
    if (service->plugin) {
        yaml_plugin_t* plugin = (yaml_plugin_t*)service->plugin;
        if (plugin->metadata.crypto_protocol &&
            strcasecmp(plugin->metadata.crypto_protocol, "SSH") == 0) {
            is_ssh_protocol = true;
        }
    }

    if (protocol_id_count > 0 && !is_ssh_protocol) {
        // Default cipher lists when config doesn't specify ciphers
        static const char* DEFAULT_TLS13_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256";
        static const char* DEFAULT_TLS12_CIPHERS = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256";

        // For each TLS version, create its cipher suites
        for (int v = 0; v < protocol_id_count; v++) {
            const char* protocol_id = protocol_ids[v];
            const char* tls_version = (config->tls_version_count > 0) ?
                                     config->tls_versions[v] :
                                     (config->min_tls_version ? config->min_tls_version : "1.2");

            // Determine cipher list: use config if available, otherwise use defaults
            const char* cipher_list = NULL;
            if (config->cipher_count > 0) {
                cipher_list = config->cipher_suites[0];
            } else {
                // Use default ciphers based on TLS version
                if (strstr(tls_version, "1.3") || strstr(tls_version, "1-3")) {
                    cipher_list = DEFAULT_TLS13_CIPHERS;
                } else {
                    cipher_list = DEFAULT_TLS12_CIPHERS;
                }
            }

            // Parse cipher list (from config or defaults)
            size_t suite_count = 0;
            cipher_suite_metadata_t** suites = parse_cipher_list_to_suites(
                cipher_list,
                tls_version,
                config->config_file,
                &suite_count
            );

            // Create cipher suite assets and relationships
            for (size_t j = 0; j < suite_count && suites; j++) {
                // Note: Cipher suite filtering by TLS version handled by parser
                // parse_cipher_list_to_suites() already filters based on tls_version parameter

                crypto_asset_t* suite_asset = cipher_suite_create_asset(suites[j]);
                if (suite_asset) {
                    result = asset_store_add(store, suite_asset);
                    if (result == 0 || result == 1) {
                        // Create PROTOCOL → CIPHER_SUITE relationship
                        create_protocol_suite_relationship(store, protocol_id, suite_asset->id, 0.95);

                        // Decompose cipher suite to algorithms (SUITE→ALGORITHM relationships)
                        decompose_cipher_suite_to_algorithms(store,
                            suite_asset->id,
                            suites[j]->kex_algorithm,
                            suites[j]->auth_algorithm,
                            suites[j]->encryption_algorithm,
                            suites[j]->mac_algorithm
                        );
                    } else {
                        crypto_asset_destroy(suite_asset);
                    }
                }
                // Free suite metadata
                cipher_suite_metadata_destroy(suites[j]);
            }
            free(suites);
        }
    }

    // Cleanup protocol IDs array
    for (int i = 0; i < protocol_id_count; i++) {
        free(protocol_ids[i]);
    }
    free(protocol_ids);

    // Cleanup
    if (first_cert_id) {
        free(first_cert_id);
    }

    return 0;
}
