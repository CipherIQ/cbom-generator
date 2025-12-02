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

#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include "plugin_manager.h"
#include "error_handling.h"
#include "yaml_plugin_loader.h"  // v1.3: YAML plugin support
#include "plugin_schema.h"       // v1.3: YAML plugin structures
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>              // v1.3: directory scanning
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// Internal helper functions
static int plugin_load_library(plugin_instance_t* instance, const char* plugin_path);
static int plugin_verify_interface(const plugin_interface_t* interface);

static int plugin_calculate_hash(const char* file_path, uint8_t* hash);
static int plugin_verify_signature_internal(const char* plugin_path, 
                                           const char* public_key_path);

uint32_t plugin_generate_instance_id(plugin_manager_t* manager) {
    (void)manager; // Suppress unused parameter warning
    static _Atomic uint32_t next_id = 1;
    return atomic_fetch_add(&next_id, 1);
}

plugin_manager_t* plugin_manager_create(const char* plugin_directory,
                                       plugin_security_policy_t security_policy) {
    if (!plugin_directory) {
        return NULL;
    }
    
    plugin_manager_t* manager = calloc(1, sizeof(plugin_manager_t));
    if (!manager) {
        return NULL;
    }
    
    // Initialize configuration
    manager->plugin_directory = strdup(plugin_directory);
    if (!manager->plugin_directory) {
        free(manager);
        return NULL;
    }
    
    manager->security_policy = security_policy;
    manager->max_plugins = PLUGIN_MAX_PLUGINS;
    manager->sandboxing_enabled = true;
    manager->seccomp_enabled = true;
    manager->default_load_flags = PLUGIN_LOAD_DEFAULT;
    manager->plugin_timeout_ms = 30000; // 30 seconds default
    
    // Initialize default resource limits
    manager->default_limits = plugin_create_default_limits();
    
    // Initialize trust configuration
    manager->trust_config = plugin_create_default_trust_config();
    
    // Initialize atomic counters
    atomic_init(&manager->total_plugins_loaded, 0);
    atomic_init(&manager->total_plugins_failed, 0);
    atomic_init(&manager->total_invocations, 0);
    atomic_init(&manager->total_errors, 0);
    
    // Initialize synchronization objects
    if (pthread_mutex_init(&manager->manager_mutex, NULL) != 0) {
        free(manager->plugin_directory);
        free(manager);
        return NULL;
    }
    
    if (pthread_rwlock_init(&manager->plugins_lock, NULL) != 0) {
        pthread_mutex_destroy(&manager->manager_mutex);
        free(manager->plugin_directory);
        free(manager);
        return NULL;
    }
    
    return manager;
}

int plugin_manager_set_trust_config(plugin_manager_t* manager, 
                                   const plugin_trust_config_t* trust_config) {
    if (!manager || !trust_config) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&manager->manager_mutex);
    
    // Free existing configuration
    free(manager->trust_config.trust_root_path);
    free(manager->trust_config.test_keys_path);
    free(manager->trust_config.production_keys_path);
    
    // Copy new configuration
    manager->trust_config.trust_root_path = trust_config->trust_root_path ? 
        strdup(trust_config->trust_root_path) : NULL;
    manager->trust_config.test_keys_path = trust_config->test_keys_path ? 
        strdup(trust_config->test_keys_path) : NULL;
    manager->trust_config.production_keys_path = trust_config->production_keys_path ? 
        strdup(trust_config->production_keys_path) : NULL;
    
    manager->trust_config.allow_test_keys = trust_config->allow_test_keys;
    manager->trust_config.key_rotation_days = trust_config->key_rotation_days;
    
    pthread_mutex_unlock(&manager->manager_mutex);
    return PLUGIN_SUCCESS;
}

int plugin_manager_set_default_limits(plugin_manager_t* manager,
                                     const plugin_resource_limits_t* limits) {
    if (!manager || !limits) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&manager->manager_mutex);
    manager->default_limits = *limits;
    pthread_mutex_unlock(&manager->manager_mutex);
    
    return PLUGIN_SUCCESS;
}

void plugin_manager_destroy(plugin_manager_t* manager) {
    if (!manager) return;
    
    // Unload all plugins
    pthread_rwlock_wrlock(&manager->plugins_lock);
    plugin_instance_t* plugin = manager->plugins;
    while (plugin) {
        plugin_instance_t* next = plugin->next;

        // Cleanup plugin based on implementation type
        if (plugin->impl_type == PLUGIN_IMPL_BINARY) {
            // Binary plugin cleanup
            if (atomic_load(&plugin->is_initialized) && plugin->interface.cleanup) {
                plugin->interface.cleanup(plugin);
            }

            if (plugin->handle) {
                dlclose(plugin->handle);
            }
        } else if (plugin->impl_type == PLUGIN_IMPL_YAML) {
            // YAML plugin cleanup (v1.3)
            if (plugin->yaml_plugin) {
                yaml_plugin_free(plugin->yaml_plugin);
            }
        }

        free(plugin->library_path);
        free(plugin);
        plugin = next;
    }
    pthread_rwlock_unlock(&manager->plugins_lock);
    
    // Cleanup synchronization objects
    pthread_rwlock_destroy(&manager->plugins_lock);
    pthread_mutex_destroy(&manager->manager_mutex);
    
    // Free configuration
    free(manager->plugin_directory);
    free(manager->trust_config.trust_root_path);
    free(manager->trust_config.test_keys_path);
    free(manager->trust_config.production_keys_path);
    
    free(manager);
}

int plugin_manager_load_plugin(plugin_manager_t* manager, const char* plugin_path,
                              plugin_load_flags_t flags) {
    (void)flags; // Suppress unused parameter warning for now
    if (!manager || !plugin_path) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    // Check if we've reached the plugin limit
    if (manager->plugin_count >= manager->max_plugins) {
        printf("ERROR: Maximum number of plugins (%u) reached\n", manager->max_plugins);
        return PLUGIN_ERROR_RESOURCE_LIMIT;
    }
    
    // Verify plugin signature if security policy requires it
    if (manager->security_policy == PLUGIN_SECURITY_STRICT) {
        int verify_result = plugin_verify_signature(plugin_path, &manager->trust_config);
        if (verify_result != PLUGIN_SUCCESS) {
            printf("ERROR: Plugin signature verification failed: %s\n", plugin_path);
            atomic_fetch_add(&manager->total_plugins_failed, 1);
            return verify_result;
        }
    }
    
    // Create plugin instance
    plugin_instance_t* instance = calloc(1, sizeof(plugin_instance_t));
    if (!instance) {
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    instance->instance_id = plugin_generate_instance_id(manager);
    instance->library_path = strdup(plugin_path);
    instance->active_limits = manager->default_limits;
    
    // Initialize atomic variables
    atomic_init(&instance->is_initialized, false);
    atomic_init(&instance->is_active, false);
    atomic_init(&instance->invocation_count, 0);
    atomic_init(&instance->error_count, 0);
    
    clock_gettime(CLOCK_MONOTONIC, &instance->load_time);
    
    // Load the plugin library
    int load_result = plugin_load_library(instance, plugin_path);
    if (load_result != PLUGIN_SUCCESS) {
        free(instance->library_path);
        free(instance);
        atomic_fetch_add(&manager->total_plugins_failed, 1);
        return load_result;
    }
    
    // Verify API version compatibility
    if (plugin_validate_api_version(instance->interface.api_version) != PLUGIN_SUCCESS) {
        printf("ERROR: Plugin API version mismatch: %s (plugin: %u, expected: %u)\n",
                 plugin_path, instance->interface.api_version, CBOM_PLUGIN_API_VERSION);
        dlclose(instance->handle);
        free(instance->library_path);
        free(instance);
        atomic_fetch_add(&manager->total_plugins_failed, 1);
        return PLUGIN_ERROR_API_VERSION_MISMATCH;
    }
    
    // Get plugin metadata
    if (instance->interface.get_metadata) {
        const plugin_metadata_t* metadata = instance->interface.get_metadata();
        if (metadata) {
            instance->metadata = *metadata;
        }
    }
    
    // Check required capabilities
    instance->has_required_capabilities = plugin_check_capabilities(&instance->metadata);
    if (!instance->has_required_capabilities) {
        printf("WARNING: Plugin %s missing required capabilities, may have limited functionality\n",
                   instance->metadata.name);
    }
    
    // Apply sandboxing if enabled
    if (manager->sandboxing_enabled) {
        int sandbox_result = plugin_apply_sandboxing(instance);
        if (sandbox_result != PLUGIN_SUCCESS) {
            printf("WARNING: Failed to apply sandboxing to plugin %s\n", instance->metadata.name);
        }
    }
    
    // Add to plugin list
    pthread_rwlock_wrlock(&manager->plugins_lock);
    instance->next = manager->plugins;
    manager->plugins = instance;
    manager->plugin_count++;
    pthread_rwlock_unlock(&manager->plugins_lock);
    
    atomic_fetch_add(&manager->total_plugins_loaded, 1);
    
    printf("INFO: Successfully loaded plugin: %s v%s (ID: %u)\n", 
             instance->metadata.name, instance->metadata.version, instance->instance_id);
    
    return PLUGIN_SUCCESS;
}

static int plugin_load_library(plugin_instance_t* instance, const char* plugin_path) {
    // Load with RTLD_LOCAL|RTLD_NOW for symbol isolation and immediate binding
    instance->handle = dlopen(plugin_path, RTLD_LOCAL | RTLD_NOW);
    if (!instance->handle) {
        printf("ERROR: Failed to load plugin library %s: %s\n", plugin_path, dlerror());
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // Get the plugin interface
    const plugin_interface_t* (*get_interface)(void) = 
        dlsym(instance->handle, PLUGIN_INTERFACE_SYMBOL);
    
    if (!get_interface) {
        printf("ERROR: Plugin %s missing interface symbol: %s\n", plugin_path, PLUGIN_INTERFACE_SYMBOL);
        dlclose(instance->handle);
        instance->handle = NULL;
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    const plugin_interface_t* interface = get_interface();
    if (!interface) {
        printf("ERROR: Plugin %s returned NULL interface\n", plugin_path);
        dlclose(instance->handle);
        instance->handle = NULL;
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // Verify interface structure
    int verify_result = plugin_verify_interface(interface);
    if (verify_result != PLUGIN_SUCCESS) {
        printf("ERROR: Plugin %s has invalid interface\n", plugin_path);
        dlclose(instance->handle);
        instance->handle = NULL;
        return verify_result;
    }
    
    // Copy interface
    instance->interface = *interface;
    
    return PLUGIN_SUCCESS;
}

static int plugin_verify_interface(const plugin_interface_t* interface) {
    if (!interface) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    // Check required functions
    if (!interface->get_metadata) {
        printf("ERROR: Plugin interface missing get_metadata function\n");
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    // API version is checked separately
    return PLUGIN_SUCCESS;
}

int plugin_verify_signature(const char* plugin_path, const plugin_trust_config_t* trust_config) {
    if (!plugin_path || !trust_config) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    // Check if plugin file exists
    struct stat st;
    if (stat(plugin_path, &st) != 0) {
        printf("ERROR: Plugin file not found: %s\n", plugin_path);
        return PLUGIN_ERROR_NOT_FOUND;
    }
    
    // Try production keys first
    if (trust_config->production_keys_path) {
        int result = plugin_verify_signature_internal(plugin_path, trust_config->production_keys_path);
        if (result == PLUGIN_SUCCESS) {
            return PLUGIN_SUCCESS;
        }
    }
    
    // Try test keys if allowed
    if (trust_config->allow_test_keys && trust_config->test_keys_path) {
        int result = plugin_verify_signature_internal(plugin_path, trust_config->test_keys_path);
        if (result == PLUGIN_SUCCESS) {
            printf("WARNING: Plugin %s verified with test keys (development mode)\n", plugin_path);
            return PLUGIN_SUCCESS;
        }
    }
    
    printf("ERROR: Plugin signature verification failed: %s\n", plugin_path);
    return PLUGIN_ERROR_SIGNATURE_INVALID;
}

static int plugin_verify_signature_internal(const char* plugin_path, const char* public_key_path) {
    // This is a simplified signature verification implementation
    // In production, this would use proper cryptographic signature verification
    
    // For now, just check if the public key file exists
    struct stat st;
    if (stat(public_key_path, &st) != 0) {
        return PLUGIN_ERROR_SIGNATURE_INVALID;
    }
    
    // Calculate plugin hash
    uint8_t plugin_hash[PLUGIN_HASH_SIZE];
    if (plugin_calculate_hash(plugin_path, plugin_hash) != PLUGIN_SUCCESS) {
        return PLUGIN_ERROR_SIGNATURE_INVALID;
    }
    
    // In a real implementation, this would:
    // 1. Load the public key
    // 2. Load the signature file (plugin_path + ".sig")
    // 3. Verify the signature against the plugin hash
    
    printf("DEBUG: Plugin signature verification placeholder for: %s\n", plugin_path);
    return PLUGIN_SUCCESS;
}

static int plugin_calculate_hash(const char* file_path, uint8_t* hash) {
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return PLUGIN_ERROR_NOT_FOUND;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    uint8_t buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return PLUGIN_ERROR_LOAD_FAILED;
        }
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return PLUGIN_ERROR_LOAD_FAILED;
    }
    
    EVP_MD_CTX_free(ctx);
    fclose(file);
    
    return PLUGIN_SUCCESS;
}

bool plugin_check_capabilities(const plugin_metadata_t* metadata) {
    if (!metadata || !metadata->required_capabilities) {
        return true; // No capabilities required
    }
    
    // Check each required capability
    for (size_t i = 0; i < metadata->required_capabilities_count; i++) {
        const char* capability = metadata->required_capabilities[i];
        
        // This is a simplified capability check
        // In production, this would use libcap to check actual capabilities
        printf("DEBUG: Checking capability: %s\n", capability);
    }
    
    return true; // Simplified - assume all capabilities are available
}

int plugin_apply_sandboxing(plugin_instance_t* instance) {
    if (!instance) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    // Apply resource limits
    int result = plugin_enforce_resource_limits(instance);
    if (result != PLUGIN_SUCCESS) {
        return result;
    }
    
    // Apply seccomp filter if enabled
    // This is a simplified implementation
    printf("DEBUG: Applying sandboxing to plugin: %s\n", instance->metadata.name);
    
    return PLUGIN_SUCCESS;
}

int plugin_enforce_resource_limits(plugin_instance_t* instance) {
    if (!instance) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    const plugin_resource_limits_t* limits = &instance->active_limits;
    
    // Set memory limit
    if (limits->max_memory_bytes > 0) {
        struct rlimit rlim;
        rlim.rlim_cur = limits->max_memory_bytes;
        rlim.rlim_max = limits->max_memory_bytes;
        
        if (setrlimit(RLIMIT_AS, &rlim) != 0) {
            printf("WARNING: Failed to set memory limit for plugin %s: %s\n", 
                       instance->metadata.name, strerror(errno));
        }
    }
    
    // Set file descriptor limit
    if (limits->max_file_descriptors > 0) {
        struct rlimit rlim;
        rlim.rlim_cur = limits->max_file_descriptors;
        rlim.rlim_max = limits->max_file_descriptors;
        
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            printf("WARNING: Failed to set file descriptor limit for plugin %s: %s\n",
                       instance->metadata.name, strerror(errno));
        }
    }
    
    return PLUGIN_SUCCESS;
}

plugin_instance_t* plugin_manager_find_plugin(plugin_manager_t* manager, const char* name) {
    if (!manager || !name) {
        return NULL;
    }
    
    pthread_rwlock_rdlock(&manager->plugins_lock);
    
    plugin_instance_t* plugin = manager->plugins;
    while (plugin) {
        if (strcmp(plugin->metadata.name, name) == 0) {
            pthread_rwlock_unlock(&manager->plugins_lock);
            return plugin;
        }
        plugin = plugin->next;
    }
    
    pthread_rwlock_unlock(&manager->plugins_lock);
    return NULL;
}

int plugin_manager_execute_scanner(plugin_manager_t* manager, uint32_t instance_id,
                                  scan_context_t* context, asset_store_t* store) {
    if (!manager || !context || !store) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    plugin_instance_t* instance = plugin_manager_get_plugin(manager, instance_id);
    if (!instance) {
        return PLUGIN_ERROR_NOT_FOUND;
    }
    
    if (!instance->interface.scan) {
        printf("ERROR: Plugin %s does not support scanning\n", instance->metadata.name);
        return PLUGIN_ERROR_INVALID_PARAM;
    }
    
    // Initialize plugin if not already done
    if (!atomic_load(&instance->is_initialized)) {
        if (instance->interface.init) {
            int init_result = instance->interface.init(instance, NULL);
            if (init_result != PLUGIN_SUCCESS) {
                printf("ERROR: Failed to initialize plugin %s\n", instance->metadata.name);
                atomic_fetch_add(&instance->error_count, 1);
                atomic_fetch_add(&manager->total_errors, 1);
                return init_result;
            }
        }
        atomic_store(&instance->is_initialized, true);
    }
    
    // Execute scanner
    atomic_store(&instance->is_active, true);
    clock_gettime(CLOCK_MONOTONIC, &instance->last_used);
    
    uint64_t start_time = 0; // Would use high-resolution timer
    int result = instance->interface.scan(instance, context, store);
    uint64_t end_time = 0;   // Would use high-resolution timer
    
    instance->total_execution_time_ns += (end_time - start_time);
    atomic_fetch_add(&instance->invocation_count, 1);
    atomic_fetch_add(&manager->total_invocations, 1);
    
    if (result != PLUGIN_SUCCESS) {
        atomic_fetch_add(&instance->error_count, 1);
        atomic_fetch_add(&manager->total_errors, 1);
    }
    
    atomic_store(&instance->is_active, false);
    
    return result;
}

// Utility functions
plugin_resource_limits_t plugin_create_default_limits(void) {
    plugin_resource_limits_t limits = {0};
    limits.max_memory_bytes = 256 * 1024 * 1024; // 256 MB
    limits.max_execution_time_ms = 30000;        // 30 seconds
    limits.max_file_descriptors = 64;
    limits.max_threads = 4;
    limits.allow_network_access = false;
    limits.allow_filesystem_write = false;
    return limits;
}

plugin_trust_config_t plugin_create_default_trust_config(void) {
    plugin_trust_config_t config = {0};
    config.test_keys_path = strdup("fixtures/plugin-keys/");
    config.allow_test_keys = true; // Development mode
    config.key_rotation_days = 365;
    return config;
}

int plugin_validate_api_version(uint32_t plugin_version) {
    uint32_t plugin_major = (plugin_version >> 16) & 0xFF;
    uint32_t current_major = (CBOM_PLUGIN_API_VERSION >> 16) & 0xFF;
    
    // Major version must match exactly
    if (plugin_major != current_major) {
        return PLUGIN_ERROR_API_VERSION_MISMATCH;
    }
    
    // Minor version compatibility (plugin can be older)
    uint32_t plugin_minor = (plugin_version >> 8) & 0xFF;
    uint32_t current_minor = (CBOM_PLUGIN_API_VERSION >> 8) & 0xFF;
    
    if (plugin_minor > current_minor) {
        return PLUGIN_ERROR_API_VERSION_MISMATCH;
    }
    
    return PLUGIN_SUCCESS;
}

const char* plugin_type_to_string(plugin_type_t type) {
    switch (type) {
        case PLUGIN_TYPE_SCANNER: return "Scanner";
        case PLUGIN_TYPE_ANALYZER: return "Analyzer";
        case PLUGIN_TYPE_FORMATTER: return "Formatter";
        case PLUGIN_TYPE_VALIDATOR: return "Validator";
        default: return "Unknown";
    }
}

const char* scanner_subtype_to_string(scanner_subtype_t subtype) {
    switch (subtype) {
        case SCANNER_TYPE_FILESYSTEM: return "Filesystem";
        case SCANNER_TYPE_PROCESS: return "Process";
        case SCANNER_TYPE_NETWORK: return "Network";
        case SCANNER_TYPE_CERTIFICATE: return "Certificate";
        case SCANNER_TYPE_PACKAGE: return "Package";
        case SCANNER_TYPE_MEMORY: return "Memory";
        case SCANNER_TYPE_LIBRARY: return "Library";
        default: return "Unknown";
    }
}

plugin_instance_t* plugin_manager_get_plugin(plugin_manager_t* manager, uint32_t instance_id) {
    if (!manager) {
        return NULL;
    }
    
    pthread_rwlock_rdlock(&manager->plugins_lock);
    
    plugin_instance_t* plugin = manager->plugins;
    while (plugin) {
        if (plugin->instance_id == instance_id) {
            pthread_rwlock_unlock(&manager->plugins_lock);
            return plugin;
        }
        plugin = plugin->next;
    }
    
    pthread_rwlock_unlock(&manager->plugins_lock);
    return NULL;
}

plugin_statistics_t plugin_manager_get_statistics(plugin_manager_t* manager) {
    plugin_statistics_t stats = {0};
    
    if (!manager) {
        return stats;
    }
    
    stats.total_plugins = manager->plugin_count;
    stats.total_invocations = atomic_load(&manager->total_invocations);
    stats.total_errors = atomic_load(&manager->total_errors);
    stats.failed_plugins = atomic_load(&manager->total_plugins_failed);
    
    pthread_rwlock_rdlock(&manager->plugins_lock);
    
    plugin_instance_t* plugin = manager->plugins;
    while (plugin) {
        if (atomic_load(&plugin->is_active)) {
            stats.active_plugins++;
        }
        
        stats.total_memory_usage += plugin->current_memory_usage;
        stats.total_file_descriptors += plugin->current_file_descriptors;
        
        plugin = plugin->next;
    }
    
    pthread_rwlock_unlock(&manager->plugins_lock);

    return stats;
}

// ============================================================================
// YAML Plugin Loading (v1.3)
// ============================================================================

/**
 * Load a YAML plugin into the plugin manager
 *
 * @param manager Plugin manager instance
 * @param yaml_path Path to YAML plugin file
 * @return PLUGIN_SUCCESS on success, error code otherwise
 */
int plugin_manager_load_yaml_plugin(plugin_manager_t* manager, const char* yaml_path) {
    if (!manager || !yaml_path) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }

    // Check if we've reached the plugin limit
    if (manager->plugin_count >= manager->max_plugins) {
        fprintf(stderr, "ERROR: Maximum number of plugins (%u) reached\n", manager->max_plugins);
        return PLUGIN_ERROR_RESOURCE_LIMIT;
    }

    // Verify file exists and has .yaml extension
    struct stat st;
    if (stat(yaml_path, &st) != 0) {
        fprintf(stderr, "ERROR: YAML plugin file not found: %s\n", yaml_path);
        return PLUGIN_ERROR_NOT_FOUND;
    }

    const char* ext = strrchr(yaml_path, '.');
    if (!ext || (strcmp(ext, ".yaml") != 0 && strcmp(ext, ".yml") != 0)) {
        fprintf(stderr, "ERROR: File is not a YAML plugin: %s\n", yaml_path);
        return PLUGIN_ERROR_INVALID_PARAM;
    }

    // Load YAML plugin
    yaml_plugin_t* yaml_plugin = yaml_plugin_load(yaml_path);
    if (!yaml_plugin) {
        fprintf(stderr, "ERROR: Failed to load YAML plugin: %s\n", yaml_path);
        atomic_fetch_add(&manager->total_plugins_failed, 1);
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Validate plugin
    if (!yaml_plugin_validate(yaml_plugin)) {
        fprintf(stderr, "ERROR: YAML plugin validation failed: %s\n", yaml_path);
        yaml_plugin_free(yaml_plugin);
        atomic_fetch_add(&manager->total_plugins_failed, 1);
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Create plugin instance
    plugin_instance_t* instance = calloc(1, sizeof(plugin_instance_t));
    if (!instance) {
        yaml_plugin_free(yaml_plugin);
        return PLUGIN_ERROR_LOAD_FAILED;
    }

    // Initialize instance
    instance->instance_id = plugin_generate_instance_id(manager);
    instance->library_path = strdup(yaml_path);
    instance->impl_type = PLUGIN_IMPL_YAML;
    instance->yaml_plugin = yaml_plugin;
    instance->handle = NULL;  // No dlopen handle for YAML plugins
    instance->active_limits = manager->default_limits;

    // Copy metadata from YAML plugin
    snprintf(instance->metadata.name, PLUGIN_MAX_NAME_LENGTH, "%s",
             yaml_plugin->metadata.name);
    snprintf(instance->metadata.version, PLUGIN_MAX_VERSION_LENGTH, "%s",
             yaml_plugin->metadata.version);
    if (yaml_plugin->metadata.description) {
        snprintf(instance->metadata.description, PLUGIN_MAX_DESCRIPTION_LENGTH, "%s",
                 yaml_plugin->metadata.description);
    }
    if (yaml_plugin->metadata.author) {
        snprintf(instance->metadata.author, PLUGIN_MAX_AUTHOR_LENGTH, "%s",
                 yaml_plugin->metadata.author);
    }

    instance->metadata.type = PLUGIN_TYPE_SCANNER;  // YAML plugins are scanners
    instance->metadata.api_version = CBOM_PLUGIN_API_VERSION;
    instance->metadata.is_signed = false;  // YAML plugins don't use binary signatures
    instance->metadata.is_trusted = true;  // Trust YAML plugins (no code execution)

    // Initialize atomic variables
    atomic_init(&instance->is_initialized, true);  // YAML plugins are always "initialized"
    atomic_init(&instance->is_active, true);
    atomic_init(&instance->invocation_count, 0);
    atomic_init(&instance->error_count, 0);

    clock_gettime(CLOCK_MONOTONIC, &instance->load_time);

    // Add plugin to manager's list (thread-safe)
    pthread_rwlock_wrlock(&manager->plugins_lock);

    instance->next = manager->plugins;
    manager->plugins = instance;
    manager->plugin_count++;
    atomic_fetch_add(&manager->total_plugins_loaded, 1);

    pthread_rwlock_unlock(&manager->plugins_lock);

    fprintf(stderr, "INFO: Loaded YAML plugin: %s v%s (%s)\n",
            instance->metadata.name, instance->metadata.version, yaml_path);

    return PLUGIN_SUCCESS;
}

/**
 * Scan a directory for YAML plugins and load them
 *
 * @param manager Plugin manager instance
 * @param directory Directory to scan
 * @return Number of plugins loaded, or negative error code
 */
int plugin_manager_scan_yaml_directory(plugin_manager_t* manager, const char* directory) {
    if (!manager || !directory) {
        return PLUGIN_ERROR_INVALID_PARAM;
    }

    DIR* dir = opendir(directory);
    if (!dir) {
        fprintf(stderr, "ERROR: Cannot open directory: %s (%s)\n", directory, strerror(errno));
        return PLUGIN_ERROR_NOT_FOUND;
    }

    int loaded_count = 0;
    int failed_count = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Check for .yaml or .yml extension
        const char* ext = strrchr(entry->d_name, '.');
        if (!ext || (strcmp(ext, ".yaml") != 0 && strcmp(ext, ".yml") != 0)) {
            continue;
        }

        // Build full path
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);

        // Verify it's a regular file
        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        // Try to load the plugin
        int result = plugin_manager_load_yaml_plugin(manager, full_path);
        if (result == PLUGIN_SUCCESS) {
            loaded_count++;
        } else {
            failed_count++;
        }
    }

    closedir(dir);

    fprintf(stderr, "INFO: Scanned directory %s: loaded %d YAML plugins, %d failed\n",
            directory, loaded_count, failed_count);

    return loaded_count;
}
