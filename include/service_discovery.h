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
 * @file service_discovery.h
 * @brief Service discovery structures for YAML plugin-driven detection
 *
 * This module defines structures for representing discovered service instances
 * detected via YAML plugin detection methods (process, port, config_file, etc.).
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef SERVICE_DISCOVERY_H
#define SERVICE_DISCOVERY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Service instance representing a discovered service
 *
 * Populated by detection methods and used for config extraction
 */
typedef struct {
    // Identity
    char* service_name;           /**< Service name from plugin (e.g., "PostgreSQL SSL/TLS Scanner") */
    char* detected_by;            /**< Plugin name that detected it */
    char* detection_method;       /**< Which method found it (process/port/config_file/systemd/package) */

    // Process information (DETECTION_METHOD_PROCESS)
    pid_t pid;                    /**< Process ID (0 if not process-based) */
    char* process_name;           /**< Actual process name from /proc/[pid]/comm */
    char* command_line;           /**< Full command line from /proc/[pid]/cmdline */

    // Network information (DETECTION_METHOD_PORT)
    uint16_t port;                /**< Listening port (0 if not network-based) */
    char* bind_address;           /**< Bind address (e.g., "0.0.0.0", "127.0.0.1") */
    char* protocol;               /**< "tcp" or "udp" */
    bool tls_enabled;             /**< TLS detected via handshake probe */

    // Filesystem information (DETECTION_METHOD_CONFIG_FILE)
    char* config_dir;             /**< Configuration directory */
    char* config_file_path;       /**< Path to config file that was detected */
    char* install_dir;            /**< Installation directory (optional) */
    char* data_dir;               /**< Data directory (optional) */

    // Systemd information (DETECTION_METHOD_SYSTEMD)
    char* systemd_service;        /**< Systemd service name (e.g., "postgresql.service") */
    bool systemd_active;          /**< Whether systemd service is active */

    // Package information (DETECTION_METHOD_PACKAGE)
    char* package_name;           /**< Package name (e.g., "postgresql") */
    char* package_version;        /**< Package version if detected */

    // Binary information (DETECTION_METHOD_BINARY)
    char* binary_path;            /**< Path to executable binary (for library detection via ldd) */

    // Service metadata
    char* version;                /**< Service version (if detected) */
    time_t discovered_at;         /**< When discovered (timestamp) */
    float confidence;             /**< Detection confidence (0.0-1.0) */

    // Reference to plugin (yaml_plugin_t* from plugin_schema.h, stored as void* to avoid type conflicts)
    void* plugin;                 /**< Plugin that detected this service (cast to yaml_plugin_t* when used) */
} service_instance_t;

/**
 * Create a new service instance
 *
 * @return Allocated service instance or NULL on error
 */
service_instance_t* service_instance_create(void);

/**
 * Free a service instance and all its fields
 *
 * @param instance Service instance to free (can be NULL)
 */
void service_instance_free(service_instance_t* instance);

/**
 * Create a deep copy of a service instance
 *
 * @param instance Instance to copy
 * @return New instance or NULL on error
 */
service_instance_t* service_instance_clone(const service_instance_t* instance);

/**
 * Convert service instance to JSON string for debugging
 *
 * @param instance Service instance
 * @return JSON string (caller must free) or NULL on error
 */
char* service_instance_to_json(const service_instance_t* instance);

/**
 * Set service name
 *
 * @param instance Service instance
 * @param name Service name (will be duplicated)
 * @return 0 on success, -1 on error
 */
int service_instance_set_name(service_instance_t* instance, const char* name);

/**
 * Set detection metadata
 *
 * @param instance Service instance
 * @param detected_by Plugin name
 * @param method Detection method name
 * @param confidence Confidence (0.0-1.0)
 * @return 0 on success, -1 on error
 */
int service_instance_set_detection_info(service_instance_t* instance,
                                         const char* detected_by,
                                         const char* method,
                                         float confidence);

/**
 * Set process information
 *
 * @param instance Service instance
 * @param pid Process ID
 * @param process_name Process name
 * @param command_line Command line
 * @return 0 on success, -1 on error
 */
int service_instance_set_process_info(service_instance_t* instance,
                                       pid_t pid,
                                       const char* process_name,
                                       const char* command_line);

/**
 * Set network information
 *
 * @param instance Service instance
 * @param port Port number
 * @param bind_address Bind address
 * @param protocol "tcp" or "udp"
 * @param tls_enabled TLS detected
 * @return 0 on success, -1 on error
 */
int service_instance_set_network_info(service_instance_t* instance,
                                       uint16_t port,
                                       const char* bind_address,
                                       const char* protocol,
                                       bool tls_enabled);

/**
 * Set config directory
 *
 * @param instance Service instance
 * @param config_dir Configuration directory path
 * @return 0 on success, -1 on error
 */
int service_instance_set_config_dir(service_instance_t* instance,
                                     const char* config_dir);

/**
 * Set config file path
 *
 * @param instance Service instance
 * @param config_file_path Full path to config file
 * @return 0 on success, -1 on error
 */
int service_instance_set_config_file(service_instance_t* instance,
                                      const char* config_file_path);

/**
 * Set systemd information
 *
 * @param instance Service instance
 * @param service_name Systemd service name
 * @param active Whether service is active
 * @return 0 on success, -1 on error
 */
int service_instance_set_systemd_info(service_instance_t* instance,
                                       const char* service_name,
                                       bool active);

/**
 * Set package information
 *
 * @param instance Service instance
 * @param package_name Package name
 * @param version Package version (optional)
 * @return 0 on success, -1 on error
 */
int service_instance_set_package_info(service_instance_t* instance,
                                       const char* package_name,
                                       const char* version);

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_DISCOVERY_H */
