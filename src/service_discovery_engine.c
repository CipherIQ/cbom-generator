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
 * @file service_discovery_engine.c
 * @brief Service discovery engine implementation
 */

#define _GNU_SOURCE
#include "service_discovery_engine.h"
#include "plugin_schema.h"
#include "secure_memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

// v1.8.1: Global config for cross-arch mode check
#include "cbom_types.h"
extern cbom_config_t g_cbom_config;

// Forward declarations for detector functions
extern bool process_detector_detect(const process_detection_config_t* config,
                                      service_instance_t* instance);
extern bool port_detector_detect(const port_detection_config_t* config,
                                  service_instance_t* instance,
                                  bool enable_tls_probe,
                                  int timeout_ms);
extern bool config_file_detector_detect(const config_file_detection_config_t* config,
                                          service_instance_t* instance);
extern bool systemd_detector_detect(const systemd_detection_config_t* config,
                                      service_instance_t* instance);
extern bool package_detector_detect(const package_detection_config_t* config,
                                      service_instance_t* instance);
extern bool binary_detector_find(const char** paths, int path_count, char* found_path);

/**
 * Cache entry for discovered services
 */
typedef struct cache_entry {
    char* plugin_name;
    service_instance_t* instance;
    time_t cached_at;
    struct cache_entry* next;
} cache_entry_t;

/**
 * Service discovery engine structure
 */
struct service_discovery_engine {
    discovery_config_t config;
    discovery_statistics_t stats;
    cache_entry_t* cache_head;
    pthread_mutex_t mutex;
    time_t created_at;
};

service_discovery_engine_t* service_discovery_engine_create(void) {
    discovery_config_t default_config = service_discovery_default_config();
    return service_discovery_engine_create_with_config(&default_config);
}

service_discovery_engine_t* service_discovery_engine_create_with_config(
    const discovery_config_t* config) {
    if (!config) {
        return NULL;
    }

    service_discovery_engine_t* engine = secure_alloc(sizeof(service_discovery_engine_t));
    if (!engine) {
        return NULL;
    }

    memset(engine, 0, sizeof(service_discovery_engine_t));
    engine->config = *config;
    engine->created_at = time(NULL);

    if (pthread_mutex_init(&engine->mutex, NULL) != 0) {
        secure_free(engine, sizeof(service_discovery_engine_t));
        return NULL;
    }

    return engine;
}

void service_discovery_engine_destroy(service_discovery_engine_t* engine) {
    if (!engine) {
        return;
    }

    // Clear cache
    service_discovery_clear_cache(engine);

    pthread_mutex_destroy(&engine->mutex);
    secure_zero(engine, sizeof(service_discovery_engine_t));
    secure_free(engine, sizeof(service_discovery_engine_t));
}

discovery_config_t service_discovery_default_config(void) {
    discovery_config_t config = {
        .enable_process_detection = true,
        .enable_port_detection = true,
        .enable_config_detection = true,
        .enable_systemd_detection = true,
        .enable_package_detection = true,
        .enable_tls_probe = true,
        .tls_probe_timeout_ms = 2000,
        .cache_ttl_seconds = 300,
        .use_cache = true,
        .max_services = 0  // Unlimited
    };
    return config;
}

void service_discovery_clear_cache(service_discovery_engine_t* engine) {
    if (!engine) {
        return;
    }

    pthread_mutex_lock(&engine->mutex);

    cache_entry_t* current = engine->cache_head;
    while (current) {
        cache_entry_t* next = current->next;
        free(current->plugin_name);
        service_instance_free(current->instance);
        secure_free(current, sizeof(cache_entry_t));
        current = next;
    }

    engine->cache_head = NULL;

    pthread_mutex_unlock(&engine->mutex);
}

service_instance_t* service_discovery_get_cached(
    service_discovery_engine_t* engine,
    const char* plugin_name) {
    if (!engine || !plugin_name || !engine->config.use_cache) {
        return NULL;
    }

    pthread_mutex_lock(&engine->mutex);

    time_t now = time(NULL);
    cache_entry_t* current = engine->cache_head;

    while (current) {
        if (strcmp(current->plugin_name, plugin_name) == 0) {
            // Check if expired
            if (now - current->cached_at > engine->config.cache_ttl_seconds) {
                // Expired, remove from cache
                pthread_mutex_unlock(&engine->mutex);
                return NULL;
            }

            // Clone and return
            service_instance_t* clone = service_instance_clone(current->instance);
            pthread_mutex_unlock(&engine->mutex);
            return clone;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&engine->mutex);
    return NULL;
}

int service_discovery_cache_service(
    service_discovery_engine_t* engine,
    const char* plugin_name,
    const service_instance_t* instance) {
    if (!engine || !plugin_name || !instance || !engine->config.use_cache) {
        return -1;
    }

    pthread_mutex_lock(&engine->mutex);

    // Check if already cached
    cache_entry_t* current = engine->cache_head;
    while (current) {
        if (strcmp(current->plugin_name, plugin_name) == 0) {
            // Update existing entry
            service_instance_free(current->instance);
            current->instance = service_instance_clone(instance);
            current->cached_at = time(NULL);
            pthread_mutex_unlock(&engine->mutex);
            return 0;
        }
        current = current->next;
    }

    // Create new cache entry
    cache_entry_t* entry = secure_alloc(sizeof(cache_entry_t));
    if (!entry) {
        pthread_mutex_unlock(&engine->mutex);
        return -1;
    }

    entry->plugin_name = strdup(plugin_name);
    entry->instance = service_instance_clone(instance);
    entry->cached_at = time(NULL);
    entry->next = engine->cache_head;
    engine->cache_head = entry;

    pthread_mutex_unlock(&engine->mutex);
    return 0;
}

bool service_discovery_try_detection_method(
    service_discovery_engine_t* engine,
    detection_method_t* method,
    service_instance_t* instance) {
    if (!engine || !method || !instance) {
        return false;
    }

    pthread_mutex_lock(&engine->mutex);
    engine->stats.methods_tried++;
    pthread_mutex_unlock(&engine->mutex);

    bool detected = false;

    switch (method->type) {
        case DETECTION_METHOD_PROCESS:
            // v1.8.1: Skip process detection in cross-arch mode
            // Host processes are irrelevant when scanning a foreign rootfs
            if (g_cbom_config.cross_arch_mode ||
                (g_cbom_config.rootfs_prefix && g_cbom_config.rootfs_prefix[0])) {
                // Skip process detection entirely in cross-arch mode
                break;
            }
            if (engine->config.enable_process_detection) {
                detected = process_detector_detect(&method->config.process, instance);
                if (detected) {
                    service_instance_set_detection_info(instance, NULL, "process", 1.0f);
                    pthread_mutex_lock(&engine->mutex);
                    engine->stats.process_detections++;
                    pthread_mutex_unlock(&engine->mutex);
                }
            }
            break;

        case DETECTION_METHOD_PORT:
            if (engine->config.enable_port_detection) {
                detected = port_detector_detect(&method->config.port, instance,
                                                engine->config.enable_tls_probe,
                                                engine->config.tls_probe_timeout_ms);
                if (detected) {
                    service_instance_set_detection_info(instance, NULL, "port", 1.0f);
                    pthread_mutex_lock(&engine->mutex);
                    engine->stats.port_detections++;
                    pthread_mutex_unlock(&engine->mutex);
                }
            }
            break;

        case DETECTION_METHOD_CONFIG_FILE:
            if (engine->config.enable_config_detection) {
                detected = config_file_detector_detect(&method->config.config_file, instance);
                if (detected) {
                    service_instance_set_detection_info(instance, NULL, "config_file", 1.0f);
                    pthread_mutex_lock(&engine->mutex);
                    engine->stats.config_file_detections++;
                    pthread_mutex_unlock(&engine->mutex);
                }
            }
            break;

        case DETECTION_METHOD_SYSTEMD:
            if (engine->config.enable_systemd_detection) {
                detected = systemd_detector_detect(&method->config.systemd, instance);
                if (detected) {
                    service_instance_set_detection_info(instance, NULL, "systemd", 1.0f);
                    pthread_mutex_lock(&engine->mutex);
                    engine->stats.systemd_detections++;
                    pthread_mutex_unlock(&engine->mutex);
                }
            }
            break;

        case DETECTION_METHOD_PACKAGE:
            if (engine->config.enable_package_detection) {
                detected = package_detector_detect(&method->config.package, instance);
                if (detected) {
                    service_instance_set_detection_info(instance, NULL, "package", 1.0f);
                    pthread_mutex_lock(&engine->mutex);
                    engine->stats.package_detections++;
                    pthread_mutex_unlock(&engine->mutex);
                }
            }
            break;

        case DETECTION_METHOD_BINARY: {
            // Binary detection: check if executable exists
            char found_path[4096] = {0};
            detected = binary_detector_find(
                (const char**)method->config.binary.binary_paths,
                method->config.binary.path_count,
                found_path);

            if (detected) {
                // Store binary path in service instance for library detection
                if (instance->binary_path) {
                    free(instance->binary_path);
                }
                instance->binary_path = strdup(found_path);

                service_instance_set_detection_info(instance, NULL, "binary",
                    method->config.binary.confidence > 0.0f ? method->config.binary.confidence : 0.95f);
                pthread_mutex_lock(&engine->mutex);
                engine->stats.binary_detections++;
                pthread_mutex_unlock(&engine->mutex);
            }
            break;
        }

        default:
            fprintf(stderr, "Unknown detection method type: %d\n", method->type);
            break;
    }

    if (!detected) {
        pthread_mutex_lock(&engine->mutex);
        engine->stats.failed_detections++;
        pthread_mutex_unlock(&engine->mutex);
    }

    return detected;
}

service_instance_t* service_discovery_discover_service(
    service_discovery_engine_t* engine,
    yaml_plugin_t* plugin) {
    if (!engine || !plugin) {
        return NULL;
    }

    // Check cache first
    service_instance_t* cached = service_discovery_get_cached(engine, plugin->metadata.name);
    if (cached) {
        return cached;
    }

    // Phase 5: Multi-criteria detection - try ALL methods and validate
    service_instance_t* instance = service_instance_create();
    if (!instance) {
        return NULL;
    }

    // Set plugin reference and name
    instance->plugin = plugin;
    service_instance_set_name(instance, plugin->metadata.name);
    service_instance_set_detection_info(instance, plugin->metadata.name, NULL, 1.0f);

    // Track which methods succeeded
    int success_count = 0;
    bool binary_succeeded = false;
    bool package_server_succeeded = false;
    int first_success_index = -1;
    detection_method_type_t primary_method = DETECTION_METHOD_PROCESS;

    // Try each detection method and accumulate results
    for (int i = 0; i < plugin->detection.method_count; i++) {
        if (service_discovery_try_detection_method(engine, &plugin->detection.methods[i], instance)) {
            success_count++;
            if (first_success_index < 0) {
                first_success_index = i;
                primary_method = plugin->detection.methods[i].type;
            }

            // Track high-confidence methods
            if (plugin->detection.methods[i].type == DETECTION_METHOD_BINARY) {
                binary_succeeded = true;
            }
            if (plugin->detection.methods[i].type == DETECTION_METHOD_PACKAGE) {
                // Check if server package was found (high confidence)
                if (instance->package_name && plugin->detection.methods[i].config.package.server_count > 0) {
                    for (int j = 0; j < plugin->detection.methods[i].config.package.server_count; j++) {
                        if (strcmp(instance->package_name, plugin->detection.methods[i].config.package.server_packages[j]) == 0) {
                            package_server_succeeded = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Phase 5: Multi-criteria validation rules
    bool detection_valid = false;
    float final_confidence = 0.70f;

    if (binary_succeeded || package_server_succeeded) {
        // High confidence: Binary OR server package exists
        detection_valid = true;
        final_confidence = 0.95f;
    } else if (success_count >= 2) {
        // Medium confidence: Multiple methods succeeded
        detection_valid = true;
        final_confidence = 0.85f;
    } else if (success_count == 1) {
        // Single method: Only accept if it's a strong method
        detection_method_type_t method = plugin->detection.methods[first_success_index].type;
        if (method == DETECTION_METHOD_PROCESS || method == DETECTION_METHOD_SYSTEMD) {
            // Process or systemd alone is acceptable
            detection_valid = true;
            final_confidence = 0.75f;
        } else {
            // Config-only, port-only, or package-only (without server) → REJECT
            detection_valid = false;
        }
    } else {
        // No methods succeeded
        detection_valid = false;
    }

    if (!detection_valid) {
        service_instance_free(instance);
        return NULL;
    }

    // Update service name based on detection results
    // Priority: process_name > systemd_service > package_name > binary_path > plugin name
    const char* detected_name = NULL;

    if (instance->process_name && instance->process_name[0] != '\0') {
        detected_name = instance->process_name;
    } else if (instance->systemd_service && instance->systemd_service[0] != '\0') {
        detected_name = instance->systemd_service;
    } else if (instance->package_name && instance->package_name[0] != '\0') {
        detected_name = instance->package_name;
    } else if (instance->binary_path && instance->binary_path[0] != '\0') {
        // Extract binary name from path
        char* basename = strrchr(instance->binary_path, '/');
        detected_name = basename ? (basename + 1) : instance->binary_path;
    }

    // If no detected name, try to get from plugin's detection config
    if (!detected_name) {
        for (int j = 0; j < plugin->detection.method_count; j++) {
            if (plugin->detection.methods[j].type == DETECTION_METHOD_PROCESS &&
                plugin->detection.methods[j].config.process.process_name_count > 0) {
                detected_name = plugin->detection.methods[j].config.process.process_names[0];
                break;
            }
        }
    }

    if (detected_name) {
        // Phase 4: Filter out obvious non-service artifacts
        const char* artifact_patterns[] = {
            "/etc/ssl/", "/etc/ca-certificates", "/etc/pki/",
            ".crt", ".pem", ".key", ".conf.d/", NULL
        };
        bool is_artifact = false;
        for (int i = 0; artifact_patterns[i] != NULL; i++) {
            if (strstr(detected_name, artifact_patterns[i]) != NULL) {
                is_artifact = true;
                break;
            }
        }

        if (is_artifact) {
            // This is a certificate/config artifact, not a service
            service_instance_free(instance);
            return NULL;
        }

        service_instance_set_name(instance, detected_name);
        service_instance_set_detection_info(instance, detected_name,
            primary_method == DETECTION_METHOD_PROCESS ? "process" :
            primary_method == DETECTION_METHOD_PORT ? "port" :
            primary_method == DETECTION_METHOD_CONFIG_FILE ? "config" :
            primary_method == DETECTION_METHOD_SYSTEMD ? "systemd" :
            primary_method == DETECTION_METHOD_PACKAGE ? "package" :
            primary_method == DETECTION_METHOD_BINARY ? "binary" : "unknown",
            final_confidence);
    }

    // Set final confidence
    instance->confidence = final_confidence;

    // Cache and return
    service_discovery_cache_service(engine, plugin->metadata.name, instance);

    pthread_mutex_lock(&engine->mutex);
    engine->stats.services_discovered++;
    pthread_mutex_unlock(&engine->mutex);

    return instance;
}

service_instance_t** service_discovery_discover_all(
    service_discovery_engine_t* engine,
    plugin_manager_t* manager,
    size_t* count) {
    if (!engine || !manager || !count) {
        return NULL;
    }

    *count = 0;

    // Allocate result array (max plugins size)
    // Use malloc() instead of secure_alloc() since we'll resize with realloc()
    size_t max_services = 128;
    service_instance_t** services = malloc(max_services * sizeof(service_instance_t*));
    if (!services) {
        return NULL;
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Iterate through all plugins in manager
    pthread_rwlock_rdlock(&manager->plugins_lock);

    plugin_instance_t* current = manager->plugins;
    while (current) {
        // Only process YAML plugins
        if (current->impl_type == PLUGIN_IMPL_YAML && current->yaml_plugin) {
            yaml_plugin_t* yaml_plugin = (yaml_plugin_t*)current->yaml_plugin;

            // Try to discover this service
            service_instance_t* instance = service_discovery_discover_service(engine, yaml_plugin);
            if (instance) {
                // Check max services limit
                if (engine->config.max_services > 0 && *count >= (size_t)engine->config.max_services) {
                    service_instance_free(instance);
                    break;
                }

                // Add to result array
                services[*count] = instance;
                (*count)++;

                // Resize if needed
                if (*count >= max_services) {
                    max_services *= 2;
                    service_instance_t** new_services = realloc(services, max_services * sizeof(service_instance_t*));
                    if (!new_services) {
                        break;
                    }
                    services = new_services;
                }
            }
        }

        current = current->next;
    }

    pthread_rwlock_unlock(&manager->plugins_lock);

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // Update statistics
    pthread_mutex_lock(&engine->mutex);
    double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                        (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;
    engine->stats.total_time_ms += elapsed_ms;
    pthread_mutex_unlock(&engine->mutex);

    return services;
}

discovery_statistics_t service_discovery_get_statistics(
    const service_discovery_engine_t* engine) {
    if (!engine) {
        discovery_statistics_t empty = {0};
        return empty;
    }

    pthread_mutex_lock((pthread_mutex_t*)&engine->mutex);
    discovery_statistics_t stats = engine->stats;
    pthread_mutex_unlock((pthread_mutex_t*)&engine->mutex);

    return stats;
}

void service_discovery_reset_statistics(service_discovery_engine_t* engine) {
    if (!engine) {
        return;
    }

    pthread_mutex_lock(&engine->mutex);
    memset(&engine->stats, 0, sizeof(discovery_statistics_t));
    pthread_mutex_unlock(&engine->mutex);
}

int service_discovery_set_config(service_discovery_engine_t* engine,
                                  const discovery_config_t* config) {
    if (!engine || !config) {
        return -1;
    }

    pthread_mutex_lock(&engine->mutex);
    engine->config = *config;
    pthread_mutex_unlock(&engine->mutex);

    return 0;
}

int service_discovery_get_config(const service_discovery_engine_t* engine,
                                  discovery_config_t* config) {
    if (!engine || !config) {
        return -1;
    }

    pthread_mutex_lock((pthread_mutex_t*)&engine->mutex);
    *config = engine->config;
    pthread_mutex_unlock((pthread_mutex_t*)&engine->mutex);

    return 0;
}
