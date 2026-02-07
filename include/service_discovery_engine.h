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
 * @file service_discovery_engine.h
 * @brief Service discovery engine for YAML plugin-driven detection
 *
 * This engine executes detection methods defined in YAML plugins to discover
 * running services on the system. Supports 5 detection method types:
 * - Process detection (/proc scanning)
 * - Port detection (/proc/net/tcp + TLS probe)
 * - Config file detection (glob patterns)
 * - Systemd detection (systemctl)
 * - Package detection (dpkg/rpm/pacman)
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef SERVICE_DISCOVERY_ENGINE_H
#define SERVICE_DISCOVERY_ENGINE_H

#include "service_discovery.h"
#include "plugin_schema.h"
#include "plugin_manager.h"
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Service discovery engine context
 *
 * Opaque structure managing discovery state and statistics
 */
typedef struct service_discovery_engine service_discovery_engine_t;

/**
 * Discovery statistics
 */
typedef struct {
    size_t services_discovered;      /**< Total services discovered */
    size_t methods_tried;            /**< Total detection methods attempted */
    size_t process_detections;       /**< Successful process detections */
    size_t port_detections;          /**< Successful port detections */
    size_t config_file_detections;   /**< Successful config file detections */
    size_t systemd_detections;       /**< Successful systemd detections */
    size_t package_detections;       /**< Successful package detections */
    size_t binary_detections;        /**< Successful binary detections */
    size_t failed_detections;        /**< Failed detection attempts */
    double total_time_ms;            /**< Total discovery time in milliseconds */
} discovery_statistics_t;

/**
 * Discovery configuration
 */
typedef struct {
    bool enable_process_detection;   /**< Enable process detection (default: true) */
    bool enable_port_detection;      /**< Enable port detection (default: true) */
    bool enable_config_detection;    /**< Enable config file detection (default: true) */
    bool enable_systemd_detection;   /**< Enable systemd detection (default: true) */
    bool enable_package_detection;   /**< Enable package detection (default: true) */
    bool enable_tls_probe;           /**< Enable TLS handshake probe (default: true) */
    int tls_probe_timeout_ms;        /**< TLS probe timeout in milliseconds (default: 2000) */
    int cache_ttl_seconds;           /**< Cache TTL in seconds (default: 300) */
    bool use_cache;                  /**< Enable caching (default: true) */
    int max_services;                /**< Maximum services to discover (0 = unlimited) */
    bool config_only_mode;           /**< Config-only: skip process/port/systemd/package detection */
} discovery_config_t;

/**
 * Create service discovery engine
 *
 * @return Allocated engine or NULL on error
 */
service_discovery_engine_t* service_discovery_engine_create(void);

/**
 * Create engine with custom configuration
 *
 * @param config Discovery configuration
 * @return Allocated engine or NULL on error
 */
service_discovery_engine_t* service_discovery_engine_create_with_config(
    const discovery_config_t* config);

/**
 * Destroy service discovery engine
 *
 * @param engine Engine to destroy (can be NULL)
 */
void service_discovery_engine_destroy(service_discovery_engine_t* engine);

/**
 * Discover a single service using its YAML plugin
 *
 * Attempts all detection methods in the plugin's detection section.
 * Returns on first successful detection (OR semantics).
 *
 * @param engine Discovery engine
 * @param plugin YAML plugin with detection methods
 * @return Discovered service instance or NULL if not detected
 */
service_instance_t* service_discovery_discover_service(
    service_discovery_engine_t* engine,
    yaml_plugin_t* plugin);

/**
 * Discover all services from all YAML plugins in plugin manager
 *
 * @param engine Discovery engine
 * @param manager Plugin manager containing YAML plugins
 * @param count Output parameter for number of services discovered
 * @return Array of service instances (caller must free) or NULL on error
 */
service_instance_t** service_discovery_discover_all(
    service_discovery_engine_t* engine,
    plugin_manager_t* manager,
    size_t* count);

/**
 * Try a specific detection method
 *
 * @param engine Discovery engine
 * @param method Detection method to try
 * @param instance Output parameter - populated on success
 * @return true if detection succeeded, false otherwise
 */
bool service_discovery_try_detection_method(
    service_discovery_engine_t* engine,
    detection_method_t* method,
    service_instance_t* instance);

/**
 * Clear discovery cache
 *
 * @param engine Discovery engine
 */
void service_discovery_clear_cache(service_discovery_engine_t* engine);

/**
 * Get discovery statistics
 *
 * @param engine Discovery engine
 * @return Statistics structure
 */
discovery_statistics_t service_discovery_get_statistics(
    const service_discovery_engine_t* engine);

/**
 * Reset discovery statistics
 *
 * @param engine Discovery engine
 */
void service_discovery_reset_statistics(service_discovery_engine_t* engine);

/**
 * Get default discovery configuration
 *
 * @return Default configuration
 */
discovery_config_t service_discovery_default_config(void);

/**
 * Set discovery configuration
 *
 * @param engine Discovery engine
 * @param config New configuration
 * @return 0 on success, -1 on error
 */
int service_discovery_set_config(service_discovery_engine_t* engine,
                                  const discovery_config_t* config);

/**
 * Get current configuration
 *
 * @param engine Discovery engine
 * @param config Output parameter for configuration
 * @return 0 on success, -1 on error
 */
int service_discovery_get_config(const service_discovery_engine_t* engine,
                                  discovery_config_t* config);

/**
 * Check if a service is in cache
 *
 * @param engine Discovery engine
 * @param plugin_name Plugin name
 * @return Cached instance or NULL if not in cache/expired
 */
service_instance_t* service_discovery_get_cached(
    service_discovery_engine_t* engine,
    const char* plugin_name);

/**
 * Add service to cache
 *
 * @param engine Discovery engine
 * @param plugin_name Plugin name
 * @param instance Service instance (will be cloned)
 * @return 0 on success, -1 on error
 */
int service_discovery_cache_service(
    service_discovery_engine_t* engine,
    const char* plugin_name,
    const service_instance_t* instance);

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_DISCOVERY_ENGINE_H */
