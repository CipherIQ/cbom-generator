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
 * Simple test for service discovery engine
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "service_discovery.h"
#include "service_discovery_engine.h"
#include "plugin_manager.h"
#include "yaml_plugin_loader.h"
#include "plugin_schema.h"
#include "secure_memory.h"

int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("Service Discovery Engine Test (v1.3 Phase 2)\n");
    printf("=================================================================\n\n");

    // Initialize secure memory
    printf("Initializing secure memory system...\n");
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory system\n");
        return 1;
    }
    printf("✓ Secure memory initialized\n\n");

    // Create plugin manager
    printf("Test 1: Creating plugin manager...\n");
    plugin_manager_t* manager = plugin_manager_create("plugins", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    printf("✓ Plugin manager created\n\n");

    // Load YAML plugins
    printf("Test 2: Loading YAML plugins from plugins/ directory...\n");
    int loaded = plugin_manager_scan_yaml_directory(manager, "plugins");
    printf("✓ Loaded %d YAML plugins\n\n", loaded);

    if (loaded == 0) {
        printf("⚠ No YAML plugins loaded - cannot test service discovery\n");
        printf("  Make sure postgresql.yaml, mysql.yaml, redis.yaml exist in plugins/ directory\n");
        plugin_manager_destroy(manager);
        return 0;
    }

    // Create service discovery engine
    printf("Test 3: Creating service discovery engine...\n");
    service_discovery_engine_t* engine = service_discovery_engine_create();
    assert(engine != NULL);
    printf("✓ Service discovery engine created\n\n");

    // Discover all services
    printf("Test 4: Discovering services from all loaded plugins...\n");
    size_t count = 0;
    service_instance_t** services = service_discovery_discover_all(engine, manager, &count);

    printf("✓ Discovery complete: found %zu service(s)\n\n", count);

    // Display discovered services
    if (count > 0) {
        printf("=================================================================\n");
        printf("Discovered Services:\n");
        printf("=================================================================\n");

        for (size_t i = 0; i < count; i++) {
            service_instance_t* svc = services[i];

            printf("\n[%zu] %s\n", i + 1, svc->service_name ? svc->service_name : "Unknown");
            printf("    Detected by: %s\n", svc->detected_by ? svc->detected_by : "Unknown");
            printf("    Method: %s\n", svc->detection_method ? svc->detection_method : "Unknown");
            printf("    Confidence: %.2f\n", svc->confidence);

            if (svc->pid > 0) {
                printf("    PID: %d\n", (int)svc->pid);
            }
            if (svc->process_name) {
                printf("    Process: %s\n", svc->process_name);
            }
            if (svc->port > 0) {
                printf("    Port: %d (%s)\n", svc->port, svc->protocol ? svc->protocol : "tcp");
                printf("    Bind address: %s\n", svc->bind_address ? svc->bind_address : "unknown");
                printf("    TLS enabled: %s\n", svc->tls_enabled ? "yes" : "no");
            }
            if (svc->config_dir) {
                printf("    Config dir: %s\n", svc->config_dir);
            }
            if (svc->systemd_service) {
                printf("    Systemd service: %s (%s)\n",
                       svc->systemd_service,
                       svc->systemd_active ? "active" : "inactive");
            }
            if (svc->package_name) {
                printf("    Package: %s", svc->package_name);
                if (svc->package_version) {
                    printf(" (version: %s)", svc->package_version);
                }
                printf("\n");
            }
        }

        printf("\n");
    }

    // Display statistics
    printf("=================================================================\n");
    printf("Discovery Statistics:\n");
    printf("=================================================================\n");

    discovery_statistics_t stats = service_discovery_get_statistics(engine);
    printf("Services discovered: %zu\n", stats.services_discovered);
    printf("Detection methods tried: %zu\n", stats.methods_tried);
    printf("  - Process detections: %zu\n", stats.process_detections);
    printf("  - Port detections: %zu\n", stats.port_detections);
    printf("  - Config file detections: %zu\n", stats.config_file_detections);
    printf("  - Systemd detections: %zu\n", stats.systemd_detections);
    printf("  - Package detections: %zu\n", stats.package_detections);
    printf("  - Failed detections: %zu\n", stats.failed_detections);
    printf("Total discovery time: %.2f ms\n", stats.total_time_ms);

    printf("\n");

    // Cleanup
    printf("Cleaning up...\n");

    if (services) {
        for (size_t i = 0; i < count; i++) {
            service_instance_free(services[i]);
        }
        free(services);
    }

    service_discovery_engine_destroy(engine);
    plugin_manager_destroy(manager);

    printf("\n=================================================================\n");
    printf("✓✓✓ Service Discovery Engine Test PASSED\n");
    printf("=================================================================\n");

    return 0;
}
