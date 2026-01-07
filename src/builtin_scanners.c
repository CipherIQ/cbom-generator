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

#include "plugin_manager.h"
#include "error_handling.h"
#include "certificate_scanner.h"
#include "key_scanner.h"
#include "package_scanner.h"
#include "service_scanner.h"
#include "filesystem_scanner.h"
#include "openpgp_parser.h"
#include "asset_store.h"
#include "dedup.h"
#include "tui.h"
#include "cbom_types.h"
#include "detection/library_detection.h"  // v1.8.1 - SONAME extraction
#include "crypto_registry.h"              // v1.8.5 - Library registry lookup
#include <json-c/json.h>                  // v1.8.5 - Metadata JSON handling

// Global config from main.c (for cross_arch_mode check)
extern cbom_config_t g_cbom_config;
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>

// TUI-aware logging - suppress output when TUI is active
static void log_printf(const char* format, ...) {
    // Suppress logging when TUI is active to prevent display corruption
    if (g_output_mode == OUTPUT_MODE_TUI) {
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);  // Write to stderr, not stdout
    va_end(args);
    fflush(stderr);
}

// ============================================================================
// Crypto Config Detection Helpers
// ============================================================================

// Check if string contains any crypto keyword
static bool contains_crypto_keyword(const char* str) {
    if (!str) return false;
    return strstr(str, "ssl") || strstr(str, "tls") ||
           strstr(str, "crypto") || strstr(str, "cert");
}

// Check if directory name looks like a component name (not a description)
// "openssl-lib" → true (valid identifier)
// "117 openssl cmake bug" → false (has spaces, starts with digit)
static bool is_component_name(const char* name) {
    if (!name || !*name) return false;
    // Starts with digit → likely a ticket/test number
    if (isdigit((unsigned char)name[0])) return false;
    // Contains space → likely a description, not an identifier
    if (strchr(name, ' ') != NULL) return false;
    return true;
}

// Check if path contains standard crypto directories
static bool in_standard_crypto_path(const char* path) {
    if (!path) return false;
    return strstr(path, "/etc/ssl/") || strstr(path, "/etc/pki/") ||
           strstr(path, "/etc/ssh/") || strstr(path, "/.ssh/") ||
           strstr(path, "/.gnupg/");
}

// Forward declaration to avoid circular dependency
struct asset_store;

// Forward declaration
static int fs_scanner_file_callback(const file_info_t* file_info, 
                                   filesystem_scan_context_t* context, 
                                   struct asset_store* store, 
                                   void* user_data);

// Filesystem scanner callback to create crypto assets
static int fs_scanner_file_callback(const file_info_t* file_info,
                                   filesystem_scan_context_t* context,
                                   struct asset_store* store,
                                   void* user_data) {
    (void)context; // Suppress unused parameter warning

    if (!file_info || !store) {
        return FS_SCAN_ERROR_INVALID_PARAM;
    }

    // Extract scan_context from user_data
    scan_context_t* scan_ctx = (scan_context_t*)user_data;
    dedup_context_t* dedup_ctx = scan_ctx ? scan_ctx->dedup_ctx : NULL;

    // Only process crypto-related file types
    if (file_info->type != FILE_TYPE_CERTIFICATE &&
        file_info->type != FILE_TYPE_KEY &&
        file_info->type != FILE_TYPE_OPENPGP_KEY &&
        file_info->type != FILE_TYPE_LIBRARY &&
        file_info->type != FILE_TYPE_CONFIG) {
        return FS_SCAN_SUCCESS;
    }

    // Check if this file should be suppressed due to deduplication
    if (dedup_ctx && dedup_ctx->mode != DEDUP_MODE_OFF) {
        // Compute file hash for dedup check
        char *file_sha256 = dedup_compute_file_sha256(file_info->path);

        // Check if file should be suppressed (already has authoritative component)
        if (dedup_should_suppress_file(dedup_ctx, file_info->path, file_sha256)) {
            // Increment suppression counter
            pthread_mutex_lock(&dedup_ctx->mutex);
            dedup_ctx->stats.files_suppressed++;
            pthread_mutex_unlock(&dedup_ctx->mutex);

            // Suppression logged via stats.files_suppressed counter

            if (file_sha256) free(file_sha256);
            return FS_SCAN_SUCCESS;  // Skip this file, it's already been processed
        }

        if (file_sha256) free(file_sha256);
    }
    
    // Create a crypto asset based on the file type
    crypto_asset_t* asset = NULL;
    
    switch (file_info->type) {
        case FILE_TYPE_CERTIFICATE:
            // Skip certificate files - the dedicated certificate scanner handles them with proper
            // metadata extraction (subject DN, extensions, fingerprint, etc.)
            // Creating basic assets here would cause duplicates with incomplete certificateProperties
            return FS_SCAN_SUCCESS;
            
        case FILE_TYPE_KEY:
            // Skip key files - the dedicated key scanner handles them with proper
            // metadata extraction (key type, size, SHA-256 hash ID)
            // Creating basic assets here would cause duplicates
            return FS_SCAN_SUCCESS;
            
        case FILE_TYPE_OPENPGP_KEY:
            // Use OpenPGP parser to create a proper asset with metadata
            asset = parse_openpgp_key(file_info->path);
            break;
            
        case FILE_TYPE_LIBRARY: {
            // Extract SONAME for proper library naming (v1.8.1)
            // This ensures libraries are named by their SONAME (e.g., "libssl.so.3")
            // rather than full paths, enabling proper dependency resolution
            char* soname = get_soname_cached(file_info->path);
            const char* lib_name = soname ? soname : file_info->path;

            // v1.9.4: Filter non-crypto libraries BEFORE creating asset
            // Previously, ALL .so/.a files were included, causing 85+ non-crypto
            // libraries (Python modules, Lua, COBOL, etc.) to appear as "unknown"
            // in the visualizer's crypto family chart.

            // 1. Look up library in crypto registry
            const crypto_library_info_t* reg_info = NULL;
            if (soname) {
                reg_info = find_crypto_lib_by_soname(soname);
            }

            // 2. Get library dependencies via ELF analysis
            binary_crypto_profile_t* profile = analyze_binary_crypto(file_info->path);

            // 3. Check if binary has crypto library dependencies
            bool has_crypto_deps = false;
            if (profile) {
                for (size_t i = 0; i < profile->libs_count; i++) {
                    if (profile->libs[i].is_crypto) {
                        has_crypto_deps = true;
                        break;
                    }
                }
            }

            // 4. Check path for crypto keywords
            bool path_has_crypto = strstr(file_info->path, "ssl") ||
                                   strstr(file_info->path, "crypto") ||
                                   strstr(file_info->path, "tls") ||
                                   strstr(file_info->path, "cert");

            // Only create asset if library is crypto-related
            if (!reg_info && !has_crypto_deps && !path_has_crypto) {
                // Not a crypto library - skip it
                if (profile) free_binary_crypto_profile(profile);
                if (soname) free(soname);
                return FS_SCAN_SUCCESS;
            }

            // Now create the asset for crypto-related library
            asset = crypto_asset_create(lib_name, ASSET_TYPE_LIBRARY);
            if (asset) {
                asset->location = strdup(file_info->path);  // Keep full path for traceability

                // Build comprehensive metadata with registry info and dependencies
                if (reg_info || profile) {
                    // Create detected_library_t for populate_library_metadata()
                    detected_library_t lib_info = {0};
                    lib_info.soname = soname;
                    lib_info.resolved_path = file_info->path;

                    if (reg_info) {
                        lib_info.is_crypto = 1;
                        lib_info.crypto_lib_id = reg_info->id;

                        // Set algorithm hint from registry
                        if (reg_info->algorithms && reg_info->algorithms[0]) {
                            asset->algorithm = strdup(reg_info->algorithms[0]);
                        }
                    } else if (has_crypto_deps && profile) {
                        // v1.9.4: Library not in registry but has crypto dependencies
                        // Infer crypto family from the primary crypto dependency
                        for (size_t i = 0; i < profile->libs_count; i++) {
                            if (profile->libs[i].is_crypto && profile->libs[i].crypto_lib_id) {
                                lib_info.is_crypto = 1;
                                lib_info.crypto_lib_id = profile->libs[i].crypto_lib_id;
                                break;  // Use first crypto dependency as family
                            }
                        }
                    }

                    // Populate metadata (cbom:lib:implements, version, confidence)
                    populate_library_metadata(asset, lib_info.is_crypto ? &lib_info : NULL, NULL);

                    // v1.9.3: Create algorithm components and PROVIDES relationships
                    if (reg_info) {
                        create_library_algorithm_relationships(store, asset, &lib_info);
                    }

                    // Add dependency list to metadata_json
                    if (profile && profile->libs_count > 0) {
                        // Parse existing metadata (if any)
                        struct json_object* meta = NULL;
                        if (asset->metadata_json) {
                            meta = json_tokener_parse(asset->metadata_json);
                            free(asset->metadata_json);
                            asset->metadata_json = NULL;
                        }
                        if (!meta) {
                            meta = json_object_new_object();
                        }

                        // Add library dependencies array
                        struct json_object* deps_array = json_object_new_array();
                        for (size_t i = 0; i < profile->libs_count; i++) {
                            if (profile->libs[i].soname) {
                                json_object_array_add(deps_array,
                                    json_object_new_string(profile->libs[i].soname));
                            }
                        }
                        json_object_object_add(meta, "library_dependencies", deps_array);

                        // Serialize back
                        const char* meta_str = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
                        if (meta_str) {
                            asset->metadata_json = strdup(meta_str);
                        }
                        json_object_put(meta);
                    }
                } else if (path_has_crypto) {
                    // Fallback: crypto detected by path only
                    asset->algorithm = strdup("SSL/TLS");
                }
            }
            if (profile) free_binary_crypto_profile(profile);
            if (soname) free(soname);
            break;
        }
            
        case FILE_TYPE_CONFIG:
            {
                // Extract filename from path
                const char* filename = strrchr(file_info->path, '/');
                filename = filename ? filename + 1 : file_info->path;

                // Extract parent directory name
                char parent_dir[256] = {0};
                if (filename != file_info->path) {
                    const char* parent_end = filename - 1;  // points to '/'
                    const char* parent_start = parent_end - 1;
                    while (parent_start > file_info->path && *parent_start != '/') {
                        parent_start--;
                    }
                    if (*parent_start == '/') parent_start++;
                    size_t len = (size_t)(parent_end - parent_start);
                    if (len < sizeof(parent_dir)) {
                        strncpy(parent_dir, parent_start, len);
                        parent_dir[len] = '\0';
                    }
                }

                bool should_flag = false;

                // 1. Filename contains crypto keyword → flag
                if (contains_crypto_keyword(filename)) {
                    should_flag = true;
                }
                // 2. Parent dir contains keyword AND is a component name → flag
                else if (contains_crypto_keyword(parent_dir) && is_component_name(parent_dir)) {
                    should_flag = true;
                }
                // 3. In standard crypto path → flag
                else if (in_standard_crypto_path(file_info->path)) {
                    should_flag = true;
                }

                if (should_flag) {
                    asset = crypto_asset_create(file_info->path, ASSET_TYPE_SERVICE);
                    if (asset) {
                        asset->location = strdup(file_info->path);
                        asset->algorithm = strdup("Configuration");
                    }
                }
            }
            break;
            
        default:
            return FS_SCAN_SUCCESS;
    }
    
    // Add the asset to the store if created
    if (asset) {
        int add_result = asset_store_add(store, asset);
        if (add_result != 0) {
            crypto_asset_destroy(asset);
            return FS_SCAN_ERROR_IO_ERROR;
        }
    }
    
    return FS_SCAN_SUCCESS;
}

// Example first-party certificate scanner plugin
static plugin_metadata_t cert_scanner_metadata = {
    .name = "builtin_cert_scanner",
    .version = "1.0.0",
    .description = "Built-in certificate scanner",
    .author = "CBOM Generator Team",
    .api_version = CBOM_PLUGIN_API_VERSION,
    .type = PLUGIN_TYPE_SCANNER,
    .subtype = SCANNER_TYPE_CERTIFICATE,
    .is_signed = true,
    .is_trusted = true
};

static int cert_scanner_init(plugin_instance_t* instance, const char* config) {
    (void)instance; (void)config; // Suppress unused parameter warnings
    log_printf("INFO: Initializing built-in certificate scanner\n");
    return PLUGIN_SUCCESS;
}

static int cert_scanner_cleanup(plugin_instance_t* instance) {
    (void)instance; // Suppress unused parameter warning
    log_printf("INFO: Cleaning up built-in certificate scanner\n");
    return PLUGIN_SUCCESS;
}

static int cert_scanner_scan(plugin_instance_t* instance, scan_context_t* context, struct asset_store* store) {
    (void)instance; // Suppress unused parameter warning
    
    // Extract target path from context
    const char* target_path = ".";  // Default fallback
    if (context && context->target_path) {
        target_path = context->target_path;
    }
    
    log_printf("INFO: Certificate scanner: starting scan of %s\n", target_path);
    
    // Create certificate scanner configuration with target path
    cert_scanner_config_t config = cert_scanner_create_default_config();
    
    // Replace default system-wide paths with the target path
    if (config.scan_paths) {
        for (size_t i = 0; i < config.scan_path_count; i++) {
            free(config.scan_paths[i]);
        }
        free(config.scan_paths);
    }
    
    // Set single target path
    config.scan_path_count = 1;
    config.scan_paths = malloc(sizeof(char*));
    if (config.scan_paths) {
        config.scan_paths[0] = strdup(target_path);
    }
    
    // Create certificate scanner context
    cert_scanner_context_t* cert_context = cert_scanner_create(&config, store);
    if (!cert_context) {
        const char* error = cert_scanner_get_last_error();
        log_printf("ERROR: Failed to create certificate scanner: %s\n", error ? error : "Unknown error");
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Set scan context for dedup support
    cert_context->scan_context = (struct scan_context*)context;

    // Issue #5: Set error collector for detailed error reporting
    if (context) {
        cert_context->error_collector = context->error_collector;
    }

    // Scan all configured paths
    int result = cert_scanner_scan_paths(cert_context);
    if (result < 0) {
        const char* error = cert_scanner_get_last_error();
        log_printf("ERROR: Certificate scanning failed: %s\n", error ? error : "Unknown error");
        cert_scanner_destroy(cert_context);
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // Get and report statistics
    cert_scanner_stats_t stats = cert_scanner_get_stats(cert_context);
    log_printf("INFO: === Certificate Scanning Summary ===\n");
    log_printf("INFO: Total certificates detected: %zu, parsed: %zu\n",
           stats.certs_detected_total, stats.certs_parsed_ok);

    // Report bundle vs individual file breakdown (Issue #2 fix)
    if (stats.bundles_processed > 0) {
        log_printf("INFO: Bundle files: %zu (%zu certs extracted, %zu failed)\n",
               stats.bundles_processed, stats.certs_from_bundles, stats.bundle_certs_failed);
    }
    if (stats.individual_files_processed > 0) {
        size_t individual_parsed = stats.individual_files_processed - stats.individual_file_failures;
        log_printf("INFO: Individual files: %zu (%zu parsed, %zu failed)\n",
               stats.individual_files_processed, individual_parsed, stats.individual_file_failures);

        // Calculate and display actual failure rate
        float actual_failure_rate = (stats.individual_file_failures * 100.0f) / stats.individual_files_processed;
        log_printf("INFO: Actual failure rate: %.1f%%\n", actual_failure_rate);
    }

    // Report certificate properties
    log_printf("INFO: Certificate properties - weak: %zu, expired: %zu, self-signed: %zu\n",
           stats.weak_certificates, stats.expired_certificates, stats.self_signed_certificates);

    // Report detailed diagnostics
    log_printf("INFO: Files scanned: %zu, extension matched: %zu, with parsable certs: %zu\n",
           stats.files_scanned_total, stats.files_extension_matched, stats.files_with_parsable_certs);
    log_printf("INFO: Format breakdown - PEM: %zu/%zu, DER: %zu/%zu, PKCS12: %zu/%zu\n",
           stats.pem_parsed_ok, stats.pem_detected,
           stats.der_parsed_ok, stats.der_detected,
           stats.pkcs12_parsed_ok, stats.pkcs12_detected);
    
    // Store statistics globally for CBOM output (declared in main.c)
    extern cert_scanner_stats_t g_cert_scanner_stats;
    g_cert_scanner_stats = stats;
    
    // Cleanup
    cert_scanner_destroy(cert_context);
    
    return PLUGIN_SUCCESS;
}

static const plugin_metadata_t* cert_scanner_get_metadata(void) {
    return &cert_scanner_metadata;
}

static plugin_interface_t cert_scanner_interface = {
    .api_version = CBOM_PLUGIN_API_VERSION,
    .get_metadata = cert_scanner_get_metadata,
    .init = cert_scanner_init,
    .cleanup = cert_scanner_cleanup,
    .scan = cert_scanner_scan,
    .analyze = NULL
};

// Example first-party filesystem scanner plugin
static plugin_metadata_t fs_scanner_metadata = {
    .name = "builtin_fs_scanner",
    .version = "1.0.0",
    .description = "Built-in filesystem scanner",
    .author = "CBOM Generator Team",
    .api_version = CBOM_PLUGIN_API_VERSION,
    .type = PLUGIN_TYPE_SCANNER,
    .subtype = SCANNER_TYPE_FILESYSTEM,
    .is_signed = true,
    .is_trusted = true
};

static int fs_scanner_init(plugin_instance_t* instance, const char* config) {
    (void)instance; (void)config; // Suppress unused parameter warnings
    log_printf("INFO: Initializing built-in filesystem scanner\n");
    return PLUGIN_SUCCESS;
}

static int fs_scanner_cleanup(plugin_instance_t* instance) {
    (void)instance; // Suppress unused parameter warning
    log_printf("INFO: Cleaning up built-in filesystem scanner\n");
    return PLUGIN_SUCCESS;
}

static int fs_scanner_scan(plugin_instance_t* instance, scan_context_t* context, struct asset_store* store) {
    (void)instance; // Suppress unused parameter warning
    
    // Extract target path from context
    const char* target_path = ".";  // Default
    if (context && context->target_path) {
        target_path = context->target_path;
    }
    
    log_printf("INFO: Filesystem scanner: starting scan\n");
    
    // Create filesystem scanner configuration
    filesystem_scan_config_t* config = filesystem_scan_config_create_default();
    if (!config) {
        log_printf("ERROR: Failed to create filesystem scanner configuration\n");
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // Add common crypto-related file types
    filesystem_scan_config_add_file_type(config, FILE_TYPE_CERTIFICATE);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_KEY);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_OPENPGP_KEY);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_CONFIG);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_LIBRARY);
    
    // Add common paths to scan (don't restrict to specific paths, scan everything)
    // filesystem_scan_config_add_include_path(config, "/etc/ssl");
    // filesystem_scan_config_add_include_path(config, "/usr/share/ca-certificates");
    // filesystem_scan_config_add_include_path(config, "/usr/local/share/ca-certificates");
    // filesystem_scan_config_add_include_path(config, "/opt");
    
    // Exclude virtual filesystems and large directories that are unlikely to contain crypto assets
    filesystem_scan_config_add_exclude_path(config, "/proc");
    filesystem_scan_config_add_exclude_path(config, "/sys");
    filesystem_scan_config_add_exclude_path(config, "/dev");
    filesystem_scan_config_add_exclude_path(config, "/run");
    filesystem_scan_config_add_exclude_path(config, "/tmp");
    filesystem_scan_config_add_exclude_path(config, "/var/tmp");
    
    // Limit depth to avoid scanning too deep
    config->max_depth = 32;  // Maximum depth
    config->max_files = 1000000000;  // Effectively unlimited (1 billion files)
    
    // Create resource manager for the scanner
    resource_manager_t* resource_manager = resource_manager_create(NULL);
    if (!resource_manager) {
        log_printf("ERROR: Failed to create resource manager for filesystem scanner\n");
        filesystem_scan_config_destroy(config);
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // Create filesystem scanner
    filesystem_scanner_t* scanner = filesystem_scanner_create(config, resource_manager);
    if (!scanner) {
        log_printf("ERROR: Failed to create filesystem scanner\n");
        resource_manager_destroy(resource_manager);
        filesystem_scan_config_destroy(config);
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // Set up a callback to create crypto assets for discovered files
    scanner->file_callback = fs_scanner_file_callback;
    scanner->callback_user_data = context;  // Pass scan_context so callback can access dedup_ctx
    
    // Perform the scan starting from the target path
    log_printf("INFO: Starting filesystem scan of: %s\n", target_path);
    int result = filesystem_scanner_scan(scanner, target_path, store);
    
    // Get and report statistics
    filesystem_scan_stats_t stats = filesystem_scanner_get_stats(scanner);
    log_printf("INFO: Filesystem scan complete - processed %zu files, scanned %zu directories\n",
           stats.total_files_processed, stats.total_directories_scanned);
    log_printf("INFO: Skipped %zu files, encountered %zu errors (%zu permission, %zu I/O)\n",
           stats.total_files_skipped, stats.total_errors, 
           stats.permission_errors, stats.io_errors);
    
    // Cleanup
    filesystem_scanner_destroy(scanner);
    resource_manager_destroy(resource_manager);
    filesystem_scan_config_destroy(config);
    
    if (result != FS_SCAN_SUCCESS) {
        log_printf("ERROR: Filesystem scanning failed: %s\n", filesystem_scan_error_string(result));
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    return PLUGIN_SUCCESS;
}

static const plugin_metadata_t* fs_scanner_get_metadata(void) {
    return &fs_scanner_metadata;
}

static plugin_interface_t fs_scanner_interface = {
    .api_version = CBOM_PLUGIN_API_VERSION,
    .get_metadata = fs_scanner_get_metadata,
    .init = fs_scanner_init,
    .cleanup = fs_scanner_cleanup,
    .scan = fs_scanner_scan,
    .analyze = NULL
};

// Key scanner plugin
static plugin_metadata_t key_scanner_metadata = {
    .name = "builtin_key_scanner",
    .version = "1.0.0",
    .description = "Built-in key material scanner",
    .author = "CBOM Generator Team",
    .api_version = CBOM_PLUGIN_API_VERSION,
    .type = PLUGIN_TYPE_SCANNER,
    .subtype = SCANNER_TYPE_FILESYSTEM,
    .is_signed = true,
    .is_trusted = true
};

static int key_scanner_init(plugin_instance_t* instance, const char* config) {
    (void)instance; (void)config;
    log_printf("INFO: Initializing built-in key scanner\n");
    return PLUGIN_SUCCESS;
}

static int key_scanner_cleanup(plugin_instance_t* instance) {
    (void)instance;
    log_printf("INFO: Cleaning up built-in key scanner\n");
    return PLUGIN_SUCCESS;
}

static int key_scanner_scan(plugin_instance_t* instance, scan_context_t* context, struct asset_store* store) {
    (void)instance;

    // Extract target path from context
    const char* target_path = ".";
    if (context && context->target_path) {
        target_path = context->target_path;
    }

    log_printf("INFO: Key scanner: starting scan of %s\n", target_path);

    // Create key scanner configuration
    key_scanner_config_t config = key_scanner_create_default_config();

    // Set scan paths
    config.scan_paths = malloc(sizeof(char*));
    if (config.scan_paths) {
        config.scan_paths[0] = strdup(target_path);
        config.scan_path_count = 1;
    }

    // Create key scanner context
    key_scanner_context_t* key_context = key_scanner_create(&config, store);
    if (!key_context) {
        log_printf("ERROR: Failed to create key scanner context\n");
        key_scanner_config_destroy(&config);
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Set scan context for deduplication
    key_context->scan_context = (struct scan_context*)context;

    // Scan all configured paths
    int result = key_scanner_scan_paths(key_context);
    if (result < 0) {
        const char* error = key_scanner_get_last_error();
        log_printf("ERROR: Key scanning failed: %s\n", error ? error : "Unknown error");
    }

    // Get statistics
    key_scanner_stats_t stats = key_scanner_get_stats(key_context);
    log_printf("INFO: Key scan complete - detected %zu keys, parsed %zu, weak: %zu\n",
           stats.keys_detected_total, stats.keys_parsed_ok, stats.weak_keys);
    log_printf("INFO: Files scanned: %zu, with keys: %zu\n",
           stats.files_scanned_total, stats.files_with_keys);
    log_printf("INFO: Key types - RSA: %zu, ECDSA: %zu, Ed25519: %zu, DSA: %zu\n",
           stats.rsa_keys, stats.ecdsa_keys, stats.ed25519_keys, stats.dsa_keys);
    log_printf("INFO: Storage - Plaintext: %zu, Encrypted: %zu\n",
           stats.plaintext_keys, stats.encrypted_keys);

    // Cleanup
    key_scanner_destroy(key_context);
    key_scanner_config_destroy(&config);

    return PLUGIN_SUCCESS;
}

static const plugin_metadata_t* key_scanner_get_metadata(void) {
    return &key_scanner_metadata;
}

static plugin_interface_t key_scanner_interface = {
    .api_version = CBOM_PLUGIN_API_VERSION,
    .get_metadata = key_scanner_get_metadata,
    .init = key_scanner_init,
    .cleanup = key_scanner_cleanup,
    .scan = key_scanner_scan,
    .analyze = NULL
};

// Package scanner plugin
static plugin_metadata_t package_scanner_metadata = {
    .name = "builtin_package_scanner",
    .version = "1.0.0",
    .description = "Built-in package manager scanner (APT, RPM, Pacman, pip, npm, gem)",
    .author = "CBOM Generator Team",
    .api_version = CBOM_PLUGIN_API_VERSION,
    .type = PLUGIN_TYPE_SCANNER,
    .subtype = SCANNER_TYPE_FILESYSTEM,
    .is_signed = true,
    .is_trusted = true
};

static int package_scanner_init(plugin_instance_t* instance, const char* config) {
    (void)instance; (void)config;
    log_printf("INFO: Initializing built-in package scanner\n");
    return PLUGIN_SUCCESS;
}

static int package_scanner_cleanup(plugin_instance_t* instance) {
    (void)instance;
    log_printf("INFO: Cleaning up built-in package scanner\n");
    return PLUGIN_SUCCESS;
}

static int package_scanner_scan(plugin_instance_t* instance, scan_context_t* context, struct asset_store* store) {
    (void)instance;

    // Skip package scanning in cross-arch mode (host package manager returns wrong info)
    if (g_cbom_config.cross_arch_mode) {
        log_printf("INFO: Package scanner: SKIPPED (cross-arch mode - host package manager disabled)\n");
        return PLUGIN_SUCCESS;
    }

    log_printf("INFO: Package scanner: starting scan\n");

    // Create package scanner configuration
    package_scanner_config_t config = package_scanner_create_default_config();

    // Create package scanner context
    package_scanner_context_t* pkg_context = package_scanner_create(&config, store);
    if (!pkg_context) {
        log_printf("ERROR: Failed to create package scanner context\n");
        package_scanner_config_destroy(&config);
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Set scan context for deduplication
    pkg_context->scan_context = (struct scan_context*)context;

    // Scan all package managers
    int result = package_scanner_scan_all(pkg_context);
    if (result < 0) {
        const char* error = package_scanner_get_last_error();
        log_printf("ERROR: Package scanning failed: %s\n", error ? error : "Unknown error");
    }

    // Get statistics
    package_scanner_stats_t stats = package_scanner_get_stats(pkg_context);
    log_printf("INFO: Package scan complete - scanned %zu packages, found %zu crypto libraries\n",
           stats.packages_scanned_total, stats.crypto_packages_found);
    log_printf("INFO: Package managers - APT: %zu, RPM: %zu, Pacman: %zu, pip: %zu, npm: %zu, gem: %zu\n",
           stats.apt_packages, stats.rpm_packages, stats.pacman_packages,
           stats.pip_packages, stats.npm_packages, stats.gem_packages);
    log_printf("INFO: Crypto libraries - OpenSSL: %zu, GnuTLS: %zu, WolfSSL: %zu\n",
           stats.openssl_found, stats.gnutls_found, stats.wolfssl_found);
    log_printf("INFO: FIPS status - Certified: %zu, Not certified: %zu (STUB DETECTION ONLY)\n",
           stats.fips_certified_packages, stats.fips_not_certified_packages);

    // Cleanup
    package_scanner_destroy(pkg_context);
    package_scanner_config_destroy(&config);

    return PLUGIN_SUCCESS;
}

static const plugin_metadata_t* package_scanner_get_metadata(void) {
    return &package_scanner_metadata;
}

static plugin_interface_t package_scanner_interface = {
    .api_version = CBOM_PLUGIN_API_VERSION,
    .get_metadata = package_scanner_get_metadata,
    .init = package_scanner_init,
    .cleanup = package_scanner_cleanup,
    .scan = package_scanner_scan,
    .analyze = NULL
};

// RE-ENABLED: Service scanner for protocol discovery (v1.6.4)
// Provides SSH/TLS protocol detection for OpenSSH, nginx, apache without --discover-services
static plugin_metadata_t service_scanner_metadata = {
    .name = "builtin_service_scanner",
    .version = "1.6.4",
    .description = "Built-in service discovery scanner (Apache, Nginx, OpenSSH) - protocol extraction",
    .author = "CBOM Generator Team",
    .api_version = CBOM_PLUGIN_API_VERSION,
    .type = PLUGIN_TYPE_SCANNER,
    .subtype = SCANNER_TYPE_FILESYSTEM,
    .is_signed = true,
    .is_trusted = true
};

// Service scanner functions
// Provides SSH/TLS protocol detection for OpenSSH, nginx, apache without --discover-services
static int service_scanner_init(plugin_instance_t* instance, const char* config) {
    (void)instance; (void)config;
    log_printf("INFO: Initializing built-in service scanner\n");
    return PLUGIN_SUCCESS;
}

static int service_scanner_cleanup(plugin_instance_t* instance) {
    (void)instance;
    log_printf("INFO: Cleaning up built-in service scanner\n");
    return PLUGIN_SUCCESS;
}

static int service_scanner_scan(plugin_instance_t* instance, scan_context_t* context, struct asset_store* store) {
    (void)instance;

    log_printf("INFO: Service scanner: starting scan\n");

    // Create service scanner configuration
    service_scanner_config_t config = service_scanner_create_default_config();

    // Enable user SSH config scanning when personal data is included (Phase 4)
    config.include_personal_data = g_cbom_config.include_personal_data;

    // Enable test fixtures when requested (for testing)
    config.include_fixtures = g_cbom_config.include_fixtures;

    // Create service scanner context
    service_scanner_context_t* svc_context = service_scanner_create(&config, store);
    if (!svc_context) {
        log_printf("ERROR: Failed to create service scanner context\n");
        service_scanner_config_destroy(&config);
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Set scan context for deduplication
    svc_context->scan_context = (struct scan_context*)context;

    // Scan all services
    int result = service_scanner_scan_all(svc_context);
    if (result < 0) {
        const char* error = service_scanner_get_last_error();
        log_printf("ERROR: Service scanning failed: %s\n", error ? error : "Unknown error");
    }

    // Get statistics
    service_scanner_stats_t stats = service_scanner_get_stats(svc_context);
    log_printf("INFO: Service scan complete - detected %zu services (%zu running, %zu configured)\n",
           stats.services_detected_total, stats.services_running, stats.services_configured);
    log_printf("INFO: Services - Apache: %zu, Nginx: %zu, OpenSSH: %zu, Postfix: %zu\n",
           stats.apache_found, stats.nginx_found, stats.openssh_found, stats.postfix_found);
    log_printf("INFO: Protocols - TLS: %zu, SSH: %zu, Total: %zu\n",
           stats.tls_protocols, stats.ssh_protocols, stats.protocols_extracted);
    log_printf("INFO: Security - Modern: %zu, Intermediate: %zu, Old: %zu\n",
           stats.modern_profile, stats.intermediate_profile, stats.old_profile);

    // Cleanup
    service_scanner_destroy(svc_context);
    service_scanner_config_destroy(&config);

    return PLUGIN_SUCCESS;
}

static const plugin_metadata_t* service_scanner_get_metadata(void) {
    return &service_scanner_metadata;
}

static plugin_interface_t service_scanner_interface = {
    .api_version = CBOM_PLUGIN_API_VERSION,
    .get_metadata = service_scanner_get_metadata,
    .init = service_scanner_init,
    .cleanup = service_scanner_cleanup,
    .scan = service_scanner_scan,
    .analyze = NULL
};

// Registry of built-in scanners
typedef struct {
    const char* name;
    const plugin_interface_t* interface;
} builtin_scanner_t;

static builtin_scanner_t builtin_scanners[] = {
    {"builtin_cert_scanner", &cert_scanner_interface},
    {"builtin_key_scanner", &key_scanner_interface},
    {"builtin_package_scanner", &package_scanner_interface},
    {"builtin_service_scanner", &service_scanner_interface},  // RE-ENABLED v1.6.4
    {"builtin_fs_scanner", &fs_scanner_interface},
    {NULL, NULL} // Sentinel
};

// Function to register all built-in scanners
int plugin_manager_register_builtin_scanners(plugin_manager_t* manager) {
    if (!manager) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    int registered_count = 0;
    int failed_count = 0;
    
    for (int i = 0; builtin_scanners[i].name != NULL; i++) {
        const builtin_scanner_t* scanner = &builtin_scanners[i];
        
        // Create a plugin instance for the built-in scanner
        plugin_instance_t* instance = calloc(1, sizeof(plugin_instance_t));
        if (!instance) {
            failed_count++;
            continue;
        }
        
        // Set up the instance
        instance->instance_id = plugin_generate_instance_id(manager);
        instance->interface = *scanner->interface;
        instance->library_path = malloc(8);
        if (instance->library_path) {
            strcpy(instance->library_path, "builtin");
        }
        instance->active_limits = manager->default_limits;
        
        // Get metadata
        if (instance->interface.get_metadata) {
            const plugin_metadata_t* metadata = instance->interface.get_metadata();
            if (metadata) {
                instance->metadata = *metadata;
            }
        }
        
        // Initialize atomic variables
        atomic_init(&instance->is_initialized, false);
        atomic_init(&instance->is_active, false);
        atomic_init(&instance->invocation_count, 0);
        atomic_init(&instance->error_count, 0);
        
        clock_gettime(CLOCK_MONOTONIC, &instance->load_time);
        
        // Mark as trusted built-in plugin
        instance->has_required_capabilities = true;
        
        // Add to plugin list
        pthread_rwlock_wrlock(&manager->plugins_lock);
        instance->next = manager->plugins;
        manager->plugins = instance;
        manager->plugin_count++;
        pthread_rwlock_unlock(&manager->plugins_lock);
        
        registered_count++;
        atomic_fetch_add(&manager->total_plugins_loaded, 1);
        
        log_printf("INFO: Registered built-in scanner: %s v%s (ID: %u)\n", 
                 instance->metadata.name, instance->metadata.version, instance->instance_id);
    }
    
    if (failed_count > 0) {
        log_printf("WARNING: Failed to register %d built-in scanners\n", failed_count);
    }
    
    log_printf("INFO: Successfully registered %d built-in scanners\n", registered_count);
    return registered_count > 0 ? PLUGIN_SUCCESS : PLUGIN_ERROR_LOAD_FAILED;
}

// Helper function to create a mock scan context for testing
scan_context_t* create_mock_scan_context(void) {
    // This would be defined elsewhere in the real implementation
    // For now, return NULL as a placeholder
    return NULL;
}
