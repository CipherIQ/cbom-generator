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

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#define _GNU_SOURCE

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include "error_handling.h"

// Plugin API versioning
#define CBOM_PLUGIN_API_VERSION_MAJOR 1
#define CBOM_PLUGIN_API_VERSION_MINOR 0
#define CBOM_PLUGIN_API_VERSION_PATCH 0
#define CBOM_PLUGIN_API_VERSION ((CBOM_PLUGIN_API_VERSION_MAJOR << 16) | \
                                (CBOM_PLUGIN_API_VERSION_MINOR << 8) | \
                                CBOM_PLUGIN_API_VERSION_PATCH)

// Plugin configuration
#define PLUGIN_MAX_NAME_LENGTH 64
#define PLUGIN_MAX_VERSION_LENGTH 16
#define PLUGIN_MAX_DESCRIPTION_LENGTH 256
#define PLUGIN_MAX_AUTHOR_LENGTH 64
#define PLUGIN_MAX_PLUGINS 128  // Increased for v1.7: 69+ YAML + 5 built-in + headroom
#define PLUGIN_SIGNATURE_SIZE 64
#define PLUGIN_HASH_SIZE 32

// Plugin types
typedef enum {
    PLUGIN_TYPE_SCANNER = 1,
    PLUGIN_TYPE_ANALYZER = 2,
    PLUGIN_TYPE_FORMATTER = 3,
    PLUGIN_TYPE_VALIDATOR = 4
} plugin_type_t;

// Plugin scanner subtypes
typedef enum {
    SCANNER_TYPE_FILESYSTEM = 1,
    SCANNER_TYPE_PROCESS = 2,
    SCANNER_TYPE_NETWORK = 3,
    SCANNER_TYPE_CERTIFICATE = 4,
    SCANNER_TYPE_PACKAGE = 5,
    SCANNER_TYPE_MEMORY = 6,
    SCANNER_TYPE_LIBRARY = 7
} scanner_subtype_t;

// Plugin implementation types (v1.3)
typedef enum {
    PLUGIN_IMPL_BINARY = 1,  // Compiled .so plugin (existing)
    PLUGIN_IMPL_YAML = 2     // Declarative YAML plugin (v1.3)
} plugin_impl_type_t;

// Plugin security policy
typedef enum {
    PLUGIN_SECURITY_STRICT = 0,    // Require signature verification
    PLUGIN_SECURITY_PERMISSIVE = 1, // Allow unsigned plugins (development)
    PLUGIN_SECURITY_DISABLED = 2   // No security checks (testing only)
} plugin_security_policy_t;

// Plugin load flags
typedef enum {
    PLUGIN_LOAD_DEFAULT = 0,
    PLUGIN_LOAD_LAZY = 1,          // Load on first use
    PLUGIN_LOAD_IMMEDIATE = 2,     // Load immediately
    PLUGIN_LOAD_ISOLATED = 4       // Load with maximum isolation
} plugin_load_flags_t;

// Plugin resource limits
typedef struct {
    size_t max_memory_bytes;       // Maximum memory usage
    uint32_t max_execution_time_ms; // Maximum execution time
    uint32_t max_file_descriptors; // Maximum open file descriptors
    uint32_t max_threads;          // Maximum threads
    bool allow_network_access;     // Allow network operations
    bool allow_filesystem_write;   // Allow filesystem writes
} plugin_resource_limits_t;

// Plugin metadata structure
typedef struct {
    char name[PLUGIN_MAX_NAME_LENGTH];
    char version[PLUGIN_MAX_VERSION_LENGTH];
    char description[PLUGIN_MAX_DESCRIPTION_LENGTH];
    char author[PLUGIN_MAX_AUTHOR_LENGTH];
    uint32_t api_version;
    plugin_type_t type;
    uint32_t subtype;              // Scanner subtype, etc.
    
    // Capabilities and requirements
    char** required_capabilities;  // Linux capabilities needed
    size_t required_capabilities_count;
    char** supported_formats;      // File formats supported
    size_t supported_formats_count;
    
    // Resource requirements
    plugin_resource_limits_t resource_limits;
    
    // Security information
    uint8_t signature[PLUGIN_SIGNATURE_SIZE];
    uint8_t hash[PLUGIN_HASH_SIZE];
    bool is_signed;
    bool is_trusted;
} plugin_metadata_t;

// Forward declarations (must be before scan_context_t)
typedef struct plugin_instance plugin_instance_t;
typedef struct plugin_manager plugin_manager_t;
typedef struct asset_store asset_store_t;
typedef struct dedup_context dedup_context_t;

// Scan context structure - contains information passed to scanner plugins
typedef struct scan_context {
    const char* target_path;        // Target directory/file to scan
    const char* scan_type;          // Type of scan being performed (optional)
    void* user_data;                // Additional user data (optional)
    dedup_context_t* dedup_ctx;     // Deduplication context (optional)
    error_collector_t* error_collector;  // Error collector for detailed error reporting (Issue #5)
} scan_context_t;

// Plugin interface functions
typedef int (*plugin_init_func_t)(plugin_instance_t* instance, const char* config);
typedef int (*plugin_cleanup_func_t)(plugin_instance_t* instance);
typedef int (*plugin_scan_func_t)(plugin_instance_t* instance, scan_context_t* context, asset_store_t* store);
typedef int (*plugin_analyze_func_t)(plugin_instance_t* instance, void* data, void* result);
typedef const plugin_metadata_t* (*plugin_get_metadata_func_t)(void);

// Plugin interface structure (ABI stable)
typedef struct {
    uint32_t api_version;
    plugin_get_metadata_func_t get_metadata;
    plugin_init_func_t init;
    plugin_cleanup_func_t cleanup;
    plugin_scan_func_t scan;       // For scanner plugins
    plugin_analyze_func_t analyze; // For analyzer plugins
} plugin_interface_t;

// Plugin instance structure
struct plugin_instance {
    uint32_t instance_id;
    plugin_metadata_t metadata;
    plugin_interface_t interface;

    // Plugin implementation (v1.3: support binary and YAML plugins)
    plugin_impl_type_t impl_type;  // PLUGIN_IMPL_BINARY or PLUGIN_IMPL_YAML
    void* handle;                   // dlopen handle (binary plugins only)
    char* library_path;             // Path to .so file (binary) or .yaml file (YAML)
    void* yaml_plugin;              // YAML plugin data (yaml_plugin_t*, YAML plugins only)
    
    // Runtime state
    _Atomic bool is_initialized;
    _Atomic bool is_active;
    _Atomic uint64_t invocation_count;
    _Atomic uint64_t error_count;
    
    // Resource tracking
    size_t current_memory_usage;
    uint32_t current_file_descriptors;
    uint32_t current_threads;
    
    // Security context
    plugin_resource_limits_t active_limits;
    bool has_required_capabilities;
    
    // Timing information
    struct timespec load_time;
    struct timespec last_used;
    uint64_t total_execution_time_ns;
    
    // Linked list for plugin manager
    struct plugin_instance* next;
};

// Plugin trust root configuration
typedef struct {
    char* trust_root_path;         // Path to trust root certificates
    char* test_keys_path;          // Path to test keys (fixtures/plugin-keys/)
    char* production_keys_path;    // Path to production keys (separate from test)
    bool allow_test_keys;          // Allow test keys (development mode)
    uint32_t key_rotation_days;    // Key rotation policy in days
} plugin_trust_config_t;

// Plugin manager structure
struct plugin_manager {
    plugin_instance_t* plugins;
    uint32_t plugin_count;
    uint32_t max_plugins;
    
    // Security configuration
    plugin_security_policy_t security_policy;
    plugin_trust_config_t trust_config;
    
    // Resource management
    plugin_resource_limits_t default_limits;
    bool sandboxing_enabled;
    bool seccomp_enabled;
    
    // Synchronization
    pthread_mutex_t manager_mutex;
    pthread_rwlock_t plugins_lock;
    
    // Statistics
    _Atomic uint64_t total_plugins_loaded;
    _Atomic uint64_t total_plugins_failed;
    _Atomic uint64_t total_invocations;
    _Atomic uint64_t total_errors;
    
    // Configuration
    char* plugin_directory;
    plugin_load_flags_t default_load_flags;
    uint32_t plugin_timeout_ms;

    // Plugin whitelist filtering (set by scan profiles)
    char** plugin_whitelist;            // Plugin names to load (NULL = load all)
    size_t whitelist_count;             // Number of whitelisted plugins (0 = disabled)
};

// Plugin manager functions
plugin_manager_t* plugin_manager_create(const char* plugin_directory,
                                       plugin_security_policy_t security_policy);
int plugin_manager_set_trust_config(plugin_manager_t* manager, 
                                   const plugin_trust_config_t* trust_config);
int plugin_manager_set_default_limits(plugin_manager_t* manager,
                                     const plugin_resource_limits_t* limits);
void plugin_manager_destroy(plugin_manager_t* manager);

// Plugin loading and management
int plugin_manager_load_plugin(plugin_manager_t* manager, const char* plugin_path,
                              plugin_load_flags_t flags);
int plugin_manager_load_directory(plugin_manager_t* manager, const char* directory,
                                 plugin_load_flags_t flags);
int plugin_manager_unload_plugin(plugin_manager_t* manager, uint32_t instance_id);
plugin_instance_t* plugin_manager_get_plugin(plugin_manager_t* manager, uint32_t instance_id);
plugin_instance_t* plugin_manager_find_plugin(plugin_manager_t* manager, const char* name);

// YAML plugin loading (v1.3)
int plugin_manager_load_yaml_plugin(plugin_manager_t* manager, const char* yaml_path);
int plugin_manager_scan_yaml_directory(plugin_manager_t* manager, const char* directory);

// Plugin whitelist filtering (set by scan profiles)
void plugin_manager_set_whitelist(plugin_manager_t* manager,
                                  const char** names, size_t count);

// Plugin execution
int plugin_manager_execute_scanner(plugin_manager_t* manager, uint32_t instance_id,
                                  scan_context_t* context, asset_store_t* store);
int plugin_manager_execute_analyzer(plugin_manager_t* manager, uint32_t instance_id,
                                   void* data, void* result);

// Plugin enumeration
plugin_instance_t** plugin_manager_list_plugins(plugin_manager_t* manager, 
                                               plugin_type_t type, size_t* count);
plugin_instance_t** plugin_manager_list_scanners(plugin_manager_t* manager,
                                                scanner_subtype_t subtype, size_t* count);

// Plugin security and verification
int plugin_verify_signature(const char* plugin_path, const plugin_trust_config_t* trust_config);
int plugin_verify_hash(const char* plugin_path, const uint8_t* expected_hash);
bool plugin_check_capabilities(const plugin_metadata_t* metadata);
int plugin_apply_sandboxing(plugin_instance_t* instance);

// Resource management and monitoring
int plugin_enforce_resource_limits(plugin_instance_t* instance);
int plugin_monitor_resources(plugin_instance_t* instance);
void plugin_update_resource_usage(plugin_instance_t* instance);

// Plugin statistics and monitoring
typedef struct {
    uint32_t total_plugins;
    uint32_t active_plugins;
    uint32_t failed_plugins;
    uint64_t total_invocations;
    uint64_t total_errors;
    double average_execution_time_ms;
    size_t total_memory_usage;
    uint32_t total_file_descriptors;
} plugin_statistics_t;

plugin_statistics_t plugin_manager_get_statistics(plugin_manager_t* manager);

// Utility functions
plugin_resource_limits_t plugin_create_default_limits(void);
plugin_trust_config_t plugin_create_default_trust_config(void);
int plugin_validate_api_version(uint32_t plugin_version);
const char* plugin_type_to_string(plugin_type_t type);
const char* scanner_subtype_to_string(scanner_subtype_t subtype);
uint32_t plugin_generate_instance_id(plugin_manager_t* manager);

// First-party scanner registration
int plugin_manager_register_builtin_scanners(plugin_manager_t* manager);

// Plugin development helpers (for first-party plugins)
#define PLUGIN_EXPORT __attribute__((visibility("default")))
#define PLUGIN_INTERFACE_SYMBOL "cbom_plugin_interface"

// Macro for plugin interface declaration
#define DECLARE_PLUGIN_INTERFACE(name) \
    PLUGIN_EXPORT const plugin_interface_t* cbom_plugin_interface(void)

// Error codes
#define PLUGIN_SUCCESS 0
#define PLUGIN_ERROR_INVALID_PARAM -1
#define PLUGIN_ERROR_NOT_FOUND -2
#define PLUGIN_ERROR_LOAD_FAILED -3
#define PLUGIN_ERROR_SIGNATURE_INVALID -4
#define PLUGIN_ERROR_API_VERSION_MISMATCH -5
#define PLUGIN_ERROR_RESOURCE_LIMIT -6
#define PLUGIN_ERROR_PERMISSION_DENIED -7
#define PLUGIN_ERROR_TIMEOUT -8
#define PLUGIN_ERROR_SANDBOX_FAILED -9

#endif // PLUGIN_MANAGER_H
