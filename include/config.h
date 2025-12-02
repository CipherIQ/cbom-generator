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

#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Network configuration
typedef struct {
    bool no_network;             // Disable all network operations (default: true)
    bool enable_ocsp;            // Enable OCSP checking (default: false)
    bool enable_crl;             // Enable CRL checking (default: false)
    int revocation_timeout;      // Timeout for revocation checks in seconds (default: 10)
    char* cache_directory;       // Local cache directory path
    int cache_ttl_hours;         // Cache TTL in hours (default: 24)
    bool allow_stale_cache;      // Allow stale cache when network disabled (default: true)
} network_config_t;

// Scanning configuration
typedef struct {
    bool deterministic;          // Deterministic output mode (default: true)
    int thread_count;            // Number of worker threads (default: CPU count)
    char** include_paths;        // Paths to include in scan
    size_t include_path_count;
    char** exclude_paths;        // Paths to exclude from scan
    size_t exclude_path_count;
    size_t max_file_size;        // Maximum file size to process
    size_t max_total_size;       // Maximum total size to process
} scan_config_t;

// Output configuration
typedef struct {
    char* output_file;           // Output file path
    char* format;                // Output format (json, cyclonedx)
    bool validate_schema;        // Validate output against schema
    bool include_metadata;       // Include metadata in output
    bool include_errors;         // Include errors array in output
    bool pretty_print;           // Pretty print JSON output
} output_config_t;

// Forward declarations to avoid circular dependencies
struct privacy_config;
struct resource_limits;

// Main configuration structure
typedef struct {
    network_config_t network;
    scan_config_t scan;
    output_config_t output;
    struct privacy_config* privacy;
    struct resource_limits* resources;
    char* config_file_path;      // Path to configuration file
    bool verbose;                // Verbose logging
    bool debug;                  // Debug mode
} cbom_config_t;

// Configuration validation result
typedef struct {
    bool valid;
    char** errors;
    size_t error_count;
    char** warnings;
    size_t warning_count;
} config_validation_result_t;

// Revocation cache entry
typedef struct {
    char* cert_fingerprint;      // Certificate fingerprint (SHA-256)
    bool is_revoked;             // Revocation status
    time_t cached_time;          // When this was cached
    time_t next_update;          // When to update next
    char* revocation_reason;     // Reason for revocation (if any)
} revocation_cache_entry_t;

// Revocation cache
typedef struct {
    revocation_cache_entry_t** entries;
    size_t entry_count;
    size_t capacity;
    char* cache_file_path;       // Persistent cache file
    pthread_mutex_t mutex;       // Thread safety
} revocation_cache_t;

// Configuration management
cbom_config_t* cbom_config_create(void);
void cbom_config_destroy(cbom_config_t* config);
cbom_config_t* cbom_config_get_default(void);

// Configuration loading
cbom_config_t* cbom_config_load_from_file(const char* config_path);
cbom_config_t* cbom_config_load_from_json(const char* json_content);
bool cbom_config_save_to_file(const cbom_config_t* config, const char* config_path);

// Configuration parsing
cbom_config_t* cbom_config_parse_args(int argc, char** argv);
void cbom_config_merge(cbom_config_t* base, const cbom_config_t* override);

// Configuration validation
config_validation_result_t* cbom_config_validate(const cbom_config_t* config);
void config_validation_result_destroy(config_validation_result_t* result);

// Network configuration helpers
bool cbom_config_is_network_enabled(const cbom_config_t* config);
bool cbom_config_should_check_revocation(const cbom_config_t* config);
int cbom_config_get_revocation_timeout(const cbom_config_t* config);

// Revocation cache management
revocation_cache_t* revocation_cache_create(const char* cache_dir);
void revocation_cache_destroy(revocation_cache_t* cache);
bool revocation_cache_load(revocation_cache_t* cache);
bool revocation_cache_save(revocation_cache_t* cache);

// Revocation cache operations
typedef enum {
    REVOCATION_STATUS_UNKNOWN,
    REVOCATION_STATUS_VALID,
    REVOCATION_STATUS_REVOKED,
    REVOCATION_STATUS_CACHE_MISS,
    REVOCATION_STATUS_NETWORK_ERROR,
    REVOCATION_STATUS_TIMEOUT
} revocation_status_t;

revocation_status_t revocation_cache_check(revocation_cache_t* cache, 
                                          const char* cert_fingerprint,
                                          const cbom_config_t* config);
bool revocation_cache_update(revocation_cache_t* cache,
                            const char* cert_fingerprint,
                            bool is_revoked,
                            const char* reason);
void revocation_cache_cleanup_expired(revocation_cache_t* cache, int ttl_hours);

// Cache behavior documentation
const char* revocation_status_to_string(revocation_status_t status);
bool is_cache_miss_vs_revocation_failed(revocation_status_t status);

// CLI argument parsing
void cbom_config_print_help(void);
bool cbom_config_parse_network_args(network_config_t* config, int argc, char** argv);
bool cbom_config_parse_scan_args(scan_config_t* config, int argc, char** argv);
bool cbom_config_parse_output_args(output_config_t* config, int argc, char** argv);

// Configuration file schema validation
bool cbom_config_validate_json_schema(const char* json_content);

// Default values
#define CBOM_DEFAULT_THREAD_COUNT 0  // 0 = auto-detect CPU count
#define CBOM_DEFAULT_REVOCATION_TIMEOUT 10
#define CBOM_DEFAULT_CACHE_TTL_HOURS 24
#define CBOM_DEFAULT_MAX_FILE_SIZE (1024 * 1024 * 1024)  // 1GB
#define CBOM_DEFAULT_MAX_TOTAL_SIZE (100ULL * 1024 * 1024 * 1024)  // 100GB

// Configuration file paths
#define CBOM_SYSTEM_CONFIG_PATH "/etc/cbom/config.json"
#define CBOM_USER_CONFIG_PATH "~/.cbom/config.json"
#define CBOM_LOCAL_CONFIG_PATH "./cbom.json"

#ifdef __cplusplus
}
#endif

#endif // CONFIG_H
