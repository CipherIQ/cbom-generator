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
 * @file service_discovery.c
 * @brief Service discovery instance management
 */

#define _GNU_SOURCE
#include "service_discovery.h"
#include "plugin_schema.h"
#include "secure_memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <json-c/json.h>

service_instance_t* service_instance_create(void) {
    service_instance_t* instance = secure_alloc(sizeof(service_instance_t));
    if (!instance) {
        return NULL;
    }

    memset(instance, 0, sizeof(service_instance_t));
    instance->discovered_at = time(NULL);
    instance->confidence = 1.0f;  // Default confidence

    return instance;
}

void service_instance_free(service_instance_t* instance) {
    if (!instance) {
        return;
    }

    // Free all string fields (using free() for strdup'd strings)
    free(instance->service_name);
    free(instance->detected_by);
    free(instance->detection_method);
    free(instance->process_name);
    free(instance->command_line);
    free(instance->bind_address);
    free(instance->protocol);
    free(instance->config_dir);
    free(instance->config_file_path);
    free(instance->install_dir);
    free(instance->data_dir);
    free(instance->systemd_service);
    free(instance->package_name);
    free(instance->package_version);
    free(instance->binary_path);
    free(instance->version);

    // Note: plugin pointer is not owned by instance, don't free it

    secure_zero(instance, sizeof(service_instance_t));
    secure_free(instance, sizeof(service_instance_t));
}

service_instance_t* service_instance_clone(const service_instance_t* instance) {
    if (!instance) {
        return NULL;
    }

    service_instance_t* clone = service_instance_create();
    if (!clone) {
        return NULL;
    }

    // Copy all fields
    #define DUP_STRING(field) \
        if (instance->field) { \
            clone->field = strdup(instance->field); \
            if (!clone->field) { \
                service_instance_free(clone); \
                return NULL; \
            } \
        }

    DUP_STRING(service_name);
    DUP_STRING(detected_by);
    DUP_STRING(detection_method);
    DUP_STRING(process_name);
    DUP_STRING(command_line);
    DUP_STRING(bind_address);
    DUP_STRING(protocol);
    DUP_STRING(config_dir);
    DUP_STRING(config_file_path);
    DUP_STRING(install_dir);
    DUP_STRING(data_dir);
    DUP_STRING(systemd_service);
    DUP_STRING(package_name);
    DUP_STRING(package_version);
    DUP_STRING(binary_path);
    DUP_STRING(version);

    #undef DUP_STRING

    // Copy numeric/primitive fields
    clone->pid = instance->pid;
    clone->port = instance->port;
    clone->tls_enabled = instance->tls_enabled;
    clone->systemd_active = instance->systemd_active;
    clone->discovered_at = instance->discovered_at;
    clone->confidence = instance->confidence;
    clone->plugin = instance->plugin;

    return clone;
}

char* service_instance_to_json(const service_instance_t* instance) {
    if (!instance) {
        return NULL;
    }

    struct json_object* root = json_object_new_object();
    if (!root) {
        return NULL;
    }

    // Add fields
    if (instance->service_name) {
        json_object_object_add(root, "service_name", json_object_new_string(instance->service_name));
    }
    if (instance->detected_by) {
        json_object_object_add(root, "detected_by", json_object_new_string(instance->detected_by));
    }
    if (instance->detection_method) {
        json_object_object_add(root, "detection_method", json_object_new_string(instance->detection_method));
    }

    // Process info
    if (instance->pid > 0) {
        json_object_object_add(root, "pid", json_object_new_int64(instance->pid));
    }
    if (instance->process_name) {
        json_object_object_add(root, "process_name", json_object_new_string(instance->process_name));
    }

    // Network info
    if (instance->port > 0) {
        json_object_object_add(root, "port", json_object_new_int(instance->port));
    }
    if (instance->bind_address) {
        json_object_object_add(root, "bind_address", json_object_new_string(instance->bind_address));
    }
    if (instance->protocol) {
        json_object_object_add(root, "protocol", json_object_new_string(instance->protocol));
    }
    json_object_object_add(root, "tls_enabled", json_object_new_boolean(instance->tls_enabled));

    // Config info
    if (instance->config_dir) {
        json_object_object_add(root, "config_dir", json_object_new_string(instance->config_dir));
    }
    if (instance->config_file_path) {
        json_object_object_add(root, "config_file_path", json_object_new_string(instance->config_file_path));
    }

    // Systemd info
    if (instance->systemd_service) {
        json_object_object_add(root, "systemd_service", json_object_new_string(instance->systemd_service));
        json_object_object_add(root, "systemd_active", json_object_new_boolean(instance->systemd_active));
    }

    // Package info
    if (instance->package_name) {
        json_object_object_add(root, "package_name", json_object_new_string(instance->package_name));
    }
    if (instance->package_version) {
        json_object_object_add(root, "package_version", json_object_new_string(instance->package_version));
    }

    // Metadata
    json_object_object_add(root, "discovered_at", json_object_new_int64(instance->discovered_at));
    json_object_object_add(root, "confidence", json_object_new_double(instance->confidence));

    // Convert to string
    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char* result = json_str ? strdup(json_str) : NULL;

    json_object_put(root);
    return result;
}

int service_instance_set_name(service_instance_t* instance, const char* name) {
    if (!instance || !name) {
        return -1;
    }

    free(instance->service_name);
    instance->service_name = strdup(name);
    return instance->service_name ? 0 : -1;
}

int service_instance_set_detection_info(service_instance_t* instance,
                                         const char* detected_by,
                                         const char* method,
                                         float confidence) {
    if (!instance) {
        return -1;
    }

    if (detected_by) {
        free(instance->detected_by);
        instance->detected_by = strdup(detected_by);
        if (!instance->detected_by) return -1;
    }

    if (method) {
        free(instance->detection_method);
        instance->detection_method = strdup(method);
        if (!instance->detection_method) return -1;
    }

    instance->confidence = confidence;
    return 0;
}

int service_instance_set_process_info(service_instance_t* instance,
                                       pid_t pid,
                                       const char* process_name,
                                       const char* command_line) {
    if (!instance) {
        return -1;
    }

    instance->pid = pid;

    if (process_name) {
        free(instance->process_name);
        instance->process_name = strdup(process_name);
        if (!instance->process_name) return -1;
    }

    if (command_line) {
        free(instance->command_line);
        instance->command_line = strdup(command_line);
        if (!instance->command_line) return -1;
    }

    return 0;
}

int service_instance_set_network_info(service_instance_t* instance,
                                       uint16_t port,
                                       const char* bind_address,
                                       const char* protocol,
                                       bool tls_enabled) {
    if (!instance) {
        return -1;
    }

    instance->port = port;
    instance->tls_enabled = tls_enabled;

    if (bind_address) {
        free(instance->bind_address);
        instance->bind_address = strdup(bind_address);
        if (!instance->bind_address) return -1;
    }

    if (protocol) {
        free(instance->protocol);
        instance->protocol = strdup(protocol);
        if (!instance->protocol) return -1;
    }

    return 0;
}

int service_instance_set_config_dir(service_instance_t* instance,
                                     const char* config_dir) {
    if (!instance || !config_dir) {
        return -1;
    }

    free(instance->config_dir);
    instance->config_dir = strdup(config_dir);
    return instance->config_dir ? 0 : -1;
}

int service_instance_set_config_file(service_instance_t* instance,
                                      const char* config_file_path) {
    if (!instance || !config_file_path) {
        return -1;
    }

    free(instance->config_file_path);
    instance->config_file_path = strdup(config_file_path);
    return instance->config_file_path ? 0 : -1;
}

int service_instance_set_systemd_info(service_instance_t* instance,
                                       const char* service_name,
                                       bool active) {
    if (!instance || !service_name) {
        return -1;
    }

    free(instance->systemd_service);
    instance->systemd_service = strdup(service_name);
    if (!instance->systemd_service) {
        return -1;
    }

    instance->systemd_active = active;
    return 0;
}

int service_instance_set_package_info(service_instance_t* instance,
                                       const char* package_name,
                                       const char* version) {
    if (!instance || !package_name) {
        return -1;
    }

    free(instance->package_name);
    instance->package_name = strdup(package_name);
    if (!instance->package_name) {
        return -1;
    }

    if (version) {
        free(instance->package_version);
        instance->package_version = strdup(version);
        if (!instance->package_version) {
            return -1;
        }
    }

    return 0;
}
