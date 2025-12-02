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
#include "config.h"
#include "privacy.h"
#include "resource_manager.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <json-c/json.h>
#include <errno.h>

// Get default network configuration
static network_config_t get_default_network_config(void) {
    network_config_t config = {
        .no_network = true,              // Default: no network (offline-first)
        .enable_ocsp = false,
        .enable_crl = false,
        .revocation_timeout = CBOM_DEFAULT_REVOCATION_TIMEOUT,
        .cache_directory = NULL,         // Will be set to ~/.cbom/cache
        .cache_ttl_hours = CBOM_DEFAULT_CACHE_TTL_HOURS,
        .allow_stale_cache = true
    };
    return config;
}

// Get default scan configuration
static scan_config_t get_default_scan_config(void) {
    scan_config_t config = {
        .deterministic = true,
        .thread_count = CBOM_DEFAULT_THREAD_COUNT,
        .include_paths = NULL,
        .include_path_count = 0,
        .exclude_paths = NULL,
        .exclude_path_count = 0,
        .max_file_size = CBOM_DEFAULT_MAX_FILE_SIZE,
        .max_total_size = CBOM_DEFAULT_MAX_TOTAL_SIZE
    };
    return config;
}

// Get default output configuration
static output_config_t get_default_output_config(void) {
    output_config_t config = {
        .output_file = strdup("cbom.json"),
        .format = strdup("json"),
        .validate_schema = true,
        .include_metadata = true,
        .include_errors = true,
        .pretty_print = true
    };
    return config;
}

// Create default configuration
cbom_config_t* cbom_config_get_default(void) {
    cbom_config_t* config = secure_alloc(sizeof(cbom_config_t));
    if (!config) return NULL;
    
    config->network = get_default_network_config();
    config->scan = get_default_scan_config();
    config->output = get_default_output_config();
    config->privacy = NULL;  // Will be created when needed
    config->resources = NULL; // Will be created when needed
    config->config_file_path = NULL;
    config->verbose = false;
    config->debug = false;
    
    // Set default cache directory
    const char* home = getenv("HOME");
    if (home) {
        size_t len = strlen(home) + 32;
        config->network.cache_directory = secure_alloc(len);
        if (config->network.cache_directory) {
            snprintf(config->network.cache_directory, len, "%s/.cbom/cache", home);
        }
    } else {
        config->network.cache_directory = strdup("/tmp/cbom_cache");
    }
    
    return config;
}

// Create configuration
cbom_config_t* cbom_config_create(void) {
    return cbom_config_get_default();
}

// Destroy configuration
void cbom_config_destroy(cbom_config_t* config) {
    if (!config) return;
    
    // Free network config
    if (config->network.cache_directory) {
        secure_free(config->network.cache_directory, strlen(config->network.cache_directory));
    }
    
    // Free scan config
    if (config->scan.include_paths) {
        for (size_t i = 0; i < config->scan.include_path_count; i++) {
            if (config->scan.include_paths[i]) {
                free(config->scan.include_paths[i]);
            }
        }
        free(config->scan.include_paths);
    }
    
    if (config->scan.exclude_paths) {
        for (size_t i = 0; i < config->scan.exclude_path_count; i++) {
            if (config->scan.exclude_paths[i]) {
                free(config->scan.exclude_paths[i]);
            }
        }
        free(config->scan.exclude_paths);
    }
    
    // Free output config
    if (config->output.output_file) {
        free(config->output.output_file);
    }
    if (config->output.format) {
        free(config->output.format);
    }
    
    // Free privacy config
    if (config->privacy) {
        // Note: privacy_config_t destruction would be handled by privacy module
        free(config->privacy);
    }
    
    // Free resource limits
    if (config->resources) {
        // Note: resource_limits_t destruction would be handled by resource manager
        free(config->resources);
    }
    
    if (config->config_file_path) {
        free(config->config_file_path);
    }
    
    secure_free(config, sizeof(cbom_config_t));
}

// Load configuration from JSON
cbom_config_t* cbom_config_load_from_json(const char* json_content) {
    if (!json_content) return NULL;
    
    json_object* root = json_tokener_parse(json_content);
    if (!root) return NULL;
    
    cbom_config_t* config = cbom_config_get_default();
    if (!config) {
        json_object_put(root);
        return NULL;
    }
    
    // Parse network configuration
    json_object* network_obj;
    if (json_object_object_get_ex(root, "network", &network_obj)) {
        json_object* no_network_obj;
        if (json_object_object_get_ex(network_obj, "no_network", &no_network_obj)) {
            config->network.no_network = json_object_get_boolean(no_network_obj);
        }
        
        json_object* enable_ocsp_obj;
        if (json_object_object_get_ex(network_obj, "enable_ocsp", &enable_ocsp_obj)) {
            config->network.enable_ocsp = json_object_get_boolean(enable_ocsp_obj);
        }
        
        json_object* enable_crl_obj;
        if (json_object_object_get_ex(network_obj, "enable_crl", &enable_crl_obj)) {
            config->network.enable_crl = json_object_get_boolean(enable_crl_obj);
        }
        
        json_object* timeout_obj;
        if (json_object_object_get_ex(network_obj, "revocation_timeout", &timeout_obj)) {
            config->network.revocation_timeout = json_object_get_int(timeout_obj);
        }
        
        json_object* cache_ttl_obj;
        if (json_object_object_get_ex(network_obj, "cache_ttl_hours", &cache_ttl_obj)) {
            config->network.cache_ttl_hours = json_object_get_int(cache_ttl_obj);
        }
    }
    
    // Parse scan configuration
    json_object* scan_obj;
    if (json_object_object_get_ex(root, "scan", &scan_obj)) {
        json_object* deterministic_obj;
        if (json_object_object_get_ex(scan_obj, "deterministic", &deterministic_obj)) {
            config->scan.deterministic = json_object_get_boolean(deterministic_obj);
        }
        
        json_object* thread_count_obj;
        if (json_object_object_get_ex(scan_obj, "thread_count", &thread_count_obj)) {
            config->scan.thread_count = json_object_get_int(thread_count_obj);
        }
    }
    
    // Parse output configuration
    json_object* output_obj;
    if (json_object_object_get_ex(root, "output", &output_obj)) {
        json_object* format_obj;
        if (json_object_object_get_ex(output_obj, "format", &format_obj)) {
            if (config->output.format) free(config->output.format);
            config->output.format = strdup(json_object_get_string(format_obj));
        }
        
        json_object* validate_schema_obj;
        if (json_object_object_get_ex(output_obj, "validate_schema", &validate_schema_obj)) {
            config->output.validate_schema = json_object_get_boolean(validate_schema_obj);
        }
    }
    
    json_object_put(root);
    return config;
}

// Load configuration from file
cbom_config_t* cbom_config_load_from_file(const char* config_path) {
    if (!config_path) return NULL;
    
    FILE* file = fopen(config_path, "r");
    if (!file) return NULL;
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024 * 1024) { // Max 1MB config file
        fclose(file);
        return NULL;
    }
    
    // Read file content
    char* content = secure_alloc(file_size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(content, 1, file_size, file);
    fclose(file);
    
    if (read_size != (size_t)file_size) {
        secure_free(content, file_size + 1);
        return NULL;
    }
    
    content[file_size] = '\0';
    
    cbom_config_t* config = cbom_config_load_from_json(content);
    secure_free(content, file_size + 1);
    
    if (config) {
        config->config_file_path = strdup(config_path);
    }
    
    return config;
}

// Parse command line arguments
cbom_config_t* cbom_config_parse_args(int argc, char** argv) {
    cbom_config_t* config = cbom_config_get_default();
    if (!config) return NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-network") == 0) {
            config->network.no_network = true;
        } else if (strcmp(argv[i], "--enable-network") == 0) {
            config->network.no_network = false;
        } else if (strcmp(argv[i], "--ocsp") == 0) {
            config->network.enable_ocsp = true;
            config->network.no_network = false; // Implies network enabled
        } else if (strcmp(argv[i], "--crl") == 0) {
            config->network.enable_crl = true;
            config->network.no_network = false; // Implies network enabled
        } else if (strcmp(argv[i], "--revocation-timeout") == 0 && i + 1 < argc) {
            config->network.revocation_timeout = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            if (config->output.output_file) free(config->output.output_file);
            config->output.output_file = strdup(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            if (config->output.format) free(config->output.format);
            config->output.format = strdup(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            config->scan.thread_count = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            // Load configuration from file and merge
            cbom_config_t* file_config = cbom_config_load_from_file(argv[i + 1]);
            if (file_config) {
                cbom_config_merge(config, file_config);
                cbom_config_destroy(file_config);
            }
            i++;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config->verbose = true;
        } else if (strcmp(argv[i], "--debug") == 0) {
            config->debug = true;
        }
    }
    
    return config;
}

// Merge configurations (override takes precedence)
void cbom_config_merge(cbom_config_t* base, const cbom_config_t* override) {
    if (!base || !override) return;
    
    // Merge network config
    if (!override->network.no_network) {
        base->network.no_network = false;
    }
    if (override->network.enable_ocsp) {
        base->network.enable_ocsp = true;
    }
    if (override->network.enable_crl) {
        base->network.enable_crl = true;
    }
    if (override->network.revocation_timeout != CBOM_DEFAULT_REVOCATION_TIMEOUT) {
        base->network.revocation_timeout = override->network.revocation_timeout;
    }
    
    // Merge scan config
    if (override->scan.thread_count != CBOM_DEFAULT_THREAD_COUNT) {
        base->scan.thread_count = override->scan.thread_count;
    }
    
    // Merge output config
    if (override->output.format && strcmp(override->output.format, "json") != 0) {
        if (base->output.format) free(base->output.format);
        base->output.format = strdup(override->output.format);
    }
    
    if (override->verbose) {
        base->verbose = true;
    }
    if (override->debug) {
        base->debug = true;
    }
}

// Network configuration helpers
bool cbom_config_is_network_enabled(const cbom_config_t* config) {
    return config && !config->network.no_network;
}

bool cbom_config_should_check_revocation(const cbom_config_t* config) {
    return config && !config->network.no_network && 
           (config->network.enable_ocsp || config->network.enable_crl);
}

int cbom_config_get_revocation_timeout(const cbom_config_t* config) {
    return config ? config->network.revocation_timeout : CBOM_DEFAULT_REVOCATION_TIMEOUT;
}

// Revocation cache management
revocation_cache_t* revocation_cache_create(const char* cache_dir) {
    if (!cache_dir) return NULL;
    
    revocation_cache_t* cache = secure_alloc(sizeof(revocation_cache_t));
    if (!cache) return NULL;
    
    cache->entries = NULL;
    cache->entry_count = 0;
    cache->capacity = 0;
    
    // Create cache file path
    size_t path_len = strlen(cache_dir) + 32;
    cache->cache_file_path = secure_alloc(path_len);
    if (!cache->cache_file_path) {
        secure_free(cache, sizeof(revocation_cache_t));
        return NULL;
    }
    snprintf(cache->cache_file_path, path_len, "%s/revocation_cache.json", cache_dir);
    
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        secure_free(cache->cache_file_path, path_len);
        secure_free(cache, sizeof(revocation_cache_t));
        return NULL;
    }
    
    // Create cache directory if it doesn't exist
    mkdir(cache_dir, 0755);
    
    return cache;
}

void revocation_cache_destroy(revocation_cache_t* cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->mutex);
    
    // Free cache entries
    if (cache->entries) {
        for (size_t i = 0; i < cache->entry_count; i++) {
            if (cache->entries[i]) {
                if (cache->entries[i]->cert_fingerprint) {
                    free(cache->entries[i]->cert_fingerprint);
                }
                if (cache->entries[i]->revocation_reason) {
                    free(cache->entries[i]->revocation_reason);
                }
                secure_free(cache->entries[i], sizeof(revocation_cache_entry_t));
            }
        }
        secure_free(cache->entries, cache->capacity * sizeof(revocation_cache_entry_t*));
    }
    
    if (cache->cache_file_path) {
        secure_free(cache->cache_file_path, strlen(cache->cache_file_path));
    }
    
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
    
    secure_free(cache, sizeof(revocation_cache_t));
}

// Check revocation status
revocation_status_t revocation_cache_check(revocation_cache_t* cache,
                                          const char* cert_fingerprint,
                                          const cbom_config_t* config) {
    if (!cache || !cert_fingerprint || !config) {
        return REVOCATION_STATUS_UNKNOWN;
    }
    
    pthread_mutex_lock(&cache->mutex);
    
    // Look for cached entry
    for (size_t i = 0; i < cache->entry_count; i++) {
        if (cache->entries[i] && cache->entries[i]->cert_fingerprint &&
            strcmp(cache->entries[i]->cert_fingerprint, cert_fingerprint) == 0) {
            
            // Check if cache entry is still valid
            time_t now = time(NULL);
            time_t age_hours = (now - cache->entries[i]->cached_time) / 3600;
            
            if (age_hours < config->network.cache_ttl_hours) {
                // Cache hit - return cached status
                revocation_status_t status = cache->entries[i]->is_revoked ? 
                    REVOCATION_STATUS_REVOKED : REVOCATION_STATUS_VALID;
                pthread_mutex_unlock(&cache->mutex);
                return status;
            } else if (config->network.no_network && config->network.allow_stale_cache) {
                // Stale cache but network disabled - return stale data with cache miss status
                pthread_mutex_unlock(&cache->mutex);
                return REVOCATION_STATUS_CACHE_MISS;
            }
        }
    }
    
    pthread_mutex_unlock(&cache->mutex);
    
    // Cache miss
    if (config->network.no_network) {
        return REVOCATION_STATUS_CACHE_MISS;
    }
    
    // Would perform network check here in real implementation
    // For now, return unknown
    return REVOCATION_STATUS_UNKNOWN;
}

// Convert revocation status to string
const char* revocation_status_to_string(revocation_status_t status) {
    switch (status) {
        case REVOCATION_STATUS_UNKNOWN: return "unknown";
        case REVOCATION_STATUS_VALID: return "valid";
        case REVOCATION_STATUS_REVOKED: return "revoked";
        case REVOCATION_STATUS_CACHE_MISS: return "cache_miss";
        case REVOCATION_STATUS_NETWORK_ERROR: return "network_error";
        case REVOCATION_STATUS_TIMEOUT: return "timeout";
        default: return "unknown";
    }
}

// Check if status is cache miss vs revocation failed
bool is_cache_miss_vs_revocation_failed(revocation_status_t status) {
    return status == REVOCATION_STATUS_CACHE_MISS;
}

// Print help
void cbom_config_print_help(void) {
    printf("Configuration Options:\n");
    printf("  --config PATH           Load configuration from JSON file\n");
    printf("  --output PATH           Output file path (default: cbom.json)\n");
    printf("  --format FORMAT         Output format: json, cyclonedx (default: json)\n");
    printf("  --threads N             Number of worker threads (default: auto)\n");
    printf("  --verbose               Enable verbose logging\n");
    printf("  --debug                 Enable debug mode\n");
    printf("\n");
    printf("Network Options (default: --no-network):\n");
    printf("  --no-network            Disable all network operations (default)\n");
    printf("  --enable-network        Enable network operations\n");
    printf("  --ocsp                  Enable OCSP revocation checking\n");
    printf("  --crl                   Enable CRL revocation checking\n");
    printf("  --revocation-timeout N  Timeout for revocation checks in seconds (default: 10)\n");
    printf("\n");
    printf("Cache Behavior:\n");
    printf("  - Stale cache + network disabled = cache miss (not error)\n");
    printf("  - Cache TTL: 24 hours (configurable)\n");
    printf("  - Cache location: ~/.cbom/cache/\n");
    printf("\n");
}

// Validate configuration
config_validation_result_t* cbom_config_validate(const cbom_config_t* config) {
    config_validation_result_t* result = secure_alloc(sizeof(config_validation_result_t));
    if (!result) return NULL;
    
    result->valid = true;
    result->errors = NULL;
    result->error_count = 0;
    result->warnings = NULL;
    result->warning_count = 0;
    
    if (!config) {
        result->valid = false;
        result->errors = secure_alloc(sizeof(char*));
        if (result->errors) {
            result->errors[0] = strdup("Configuration is NULL");
            result->error_count = 1;
        }
        return result;
    }
    
    // Validate network configuration
    if (config->network.revocation_timeout <= 0 || config->network.revocation_timeout > 300) {
        result->valid = false;
        // Would add error to errors array
    }
    
    // Validate thread count
    if (config->scan.thread_count < 0 || config->scan.thread_count > 64) {
        result->valid = false;
        // Would add error to errors array
    }
    
    // Validate output format
    if (config->output.format) {
        if (strcmp(config->output.format, "json") != 0 && 
            strcmp(config->output.format, "cyclonedx") != 0) {
            result->valid = false;
            // Would add error to errors array
        }
    }
    
    return result;
}

void config_validation_result_destroy(config_validation_result_t* result) {
    if (!result) return;
    
    if (result->errors) {
        for (size_t i = 0; i < result->error_count; i++) {
            if (result->errors[i]) {
                free(result->errors[i]);
            }
        }
        secure_free(result->errors, result->error_count * sizeof(char*));
    }
    
    if (result->warnings) {
        for (size_t i = 0; i < result->warning_count; i++) {
            if (result->warnings[i]) {
                free(result->warnings[i]);
            }
        }
        secure_free(result->warnings, result->warning_count * sizeof(char*));
    }
    
    secure_free(result, sizeof(config_validation_result_t));
}
