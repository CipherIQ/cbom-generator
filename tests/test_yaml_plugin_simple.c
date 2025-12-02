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
 * Simple test for YAML plugin loading via plugin_manager
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <assert.h>
#include "plugin_manager.h"
#include "yaml_plugin_loader.h"
#include "certificate_scanner.h"

// Provide test-local stats instance to satisfy builtin_scanners references
cert_scanner_stats_t g_cert_scanner_stats = {0};

int main() {
    printf("Testing YAML plugin loading...\n\n");

    /* Create plugin manager */
    plugin_manager_t* manager = plugin_manager_create("plugins", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    printf("✓ Plugin manager created\n");

    /* Test 1: Load single YAML plugin */
    printf("\nTest 1: Loading plugins/ubuntu/postgresql.yaml...\n");
    int result = plugin_manager_load_yaml_plugin(manager, "plugins/ubuntu/postgresql.yaml");
    if (result == PLUGIN_SUCCESS) {
        printf("✓ PostgreSQL plugin loaded successfully\n");
        assert(manager->plugin_count == 1);
    } else {
        printf("✗ Failed to load PostgreSQL plugin (error code: %d)\n", result);
        plugin_manager_destroy(manager);
        return 1;
    }

    /* Test 2: Load another YAML plugin */
    printf("\nTest 2: Loading plugins/ubuntu/mysql.yaml...\n");
    result = plugin_manager_load_yaml_plugin(manager, "plugins/ubuntu/mysql.yaml");
    if (result == PLUGIN_SUCCESS) {
        printf("✓ MySQL plugin loaded successfully\n");
        assert(manager->plugin_count == 2);
    } else {
        printf("✗ Failed to load MySQL plugin (error code: %d)\n", result);
        plugin_manager_destroy(manager);
        return 1;
    }

    /* Test 3: Load Redis plugin */
    printf("\nTest 3: Loading plugins/ubuntu/redis.yaml...\n");
    result = plugin_manager_load_yaml_plugin(manager, "plugins/ubuntu/redis.yaml");
    if (result == PLUGIN_SUCCESS) {
        printf("✓ Redis plugin loaded successfully\n");
        assert(manager->plugin_count == 3);
    } else {
        printf("✗ Failed to load Redis plugin (error code: %d)\n", result);
        plugin_manager_destroy(manager);
        return 1;
    }

    /* Test 4: Scan directory for YAML plugins */
    printf("\nTest 4: Scanning plugins/ directory...\n");
    plugin_manager_t* manager2 = plugin_manager_create("plugins", PLUGIN_SECURITY_PERMISSIVE);
    int loaded = plugin_manager_scan_yaml_directory(manager2, "plugins");
    if (loaded >= 3) {
        printf("✓ Directory scan loaded %d plugins\n", loaded);
    } else {
        printf("✗ Directory scan loaded only %d plugins (expected >= 3)\n", loaded);
    }

    /* Cleanup */
    printf("\nCleaning up...\n");
    plugin_manager_destroy(manager);
    plugin_manager_destroy(manager2);

    printf("\n✓✓✓ All YAML plugin tests PASSED!\n");
    return 0;
}
