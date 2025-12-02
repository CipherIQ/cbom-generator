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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>

#include "filesystem_scanner.h"
#include "asset_store.h"
#include "resource_manager.h"
#include "secure_memory.h"

// Simple test without certificate scanner dependencies
int main(void) {
    printf("Starting simple filesystem scanner tests...\n\n");
    
    // Initialize secure memory system
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory system\n");
        return 1;
    }
    
    // Test 1: Configuration creation
    printf("Test 1: Configuration creation...\n");
    printf("Creating default config...\n");
    filesystem_scan_config_t* config = filesystem_scan_config_create_default();
    printf("Config created: %p\n", (void*)config);
    assert(config != NULL);
    assert(config->skip_permission_errors == true);
    assert(config->auto_detect_container == true);
    printf("✓ Configuration creation test passed!\n\n");
    
    // Test 2: Container detection
    printf("Test 2: Container detection...\n");
    container_context_t* context = detect_container_environment();
    assert(context != NULL);
    printf("Container detected: %s\n", context->is_container ? "yes" : "no");
    if (context->is_container) {
        printf("Runtime type: %s\n", context->runtime_type ? context->runtime_type : "unknown");
    }
    container_context_destroy(context);
    printf("✓ Container detection test passed!\n\n");
    
    // Test 3: File type detection
    printf("Test 3: File type detection...\n");
    // Note: .pem uses content-based detection (can contain certs or keys)
    assert(detect_file_type_by_extension("test.pem") == FILE_TYPE_UNKNOWN);
    assert(detect_file_type_by_extension("test.crt") == FILE_TYPE_CERTIFICATE);
    assert(detect_file_type_by_extension("test.key") == FILE_TYPE_KEY);
    assert(detect_file_type_by_extension("test.conf") == FILE_TYPE_CONFIG);
    assert(detect_file_type_by_extension("test.so") == FILE_TYPE_LIBRARY);
    assert(detect_file_type_by_extension("test.unknown") == FILE_TYPE_UNKNOWN);
    printf("✓ File type detection test passed!\n\n");
    
    // Test 4: Path filtering
    printf("Test 4: Path filtering...\n");
    filesystem_scan_config_add_include_path(config, "/usr/lib");
    filesystem_scan_config_add_include_path(config, "/etc");
    
    assert(should_include_path("/usr/lib/ssl", config) == true);
    assert(should_include_path("/etc/ssl", config) == true);
    assert(should_include_path("/home/user", config) == false);
    
    filesystem_scan_config_add_exclude_path(config, "/proc");
    filesystem_scan_config_add_exclude_path(config, "/sys");
    
    assert(should_exclude_path("/proc/cpuinfo", config) == true);
    assert(should_exclude_path("/sys/devices", config) == true);
    assert(should_exclude_path("/usr/lib/ssl", config) == false);
    printf("✓ Path filtering test passed!\n\n");
    
    // Test 5: Resource limits
    printf("Test 5: Resource limits...\n");
    resource_limits_t limits = {
        .max_open_files = 10,
        .max_total_bytes = 1024 * 1024, // 1MB
        .max_bytes_per_file = 64 * 1024, // 64KB
        .max_concurrency = 4,
        .memory_watermark = 512 * 1024,  // 512KB
        .temp_dir_path = NULL,
        .enforce_noexec = false
    };
    
    resource_manager_t* manager = resource_manager_create(&limits);
    assert(manager != NULL);
    
    assert(check_file_size_limit(32 * 1024, manager) == true);  // 32KB - should pass
    assert(check_file_size_limit(128 * 1024, manager) == false); // 128KB - should fail
    
    resource_manager_destroy(manager);
    printf("✓ Resource limits test passed!\n\n");
    
    // Test 6: Scanner creation and basic functionality
    printf("Test 6: Scanner creation...\n");
    
    // Create resource manager
    manager = resource_manager_create(NULL);
    assert(manager != NULL);
    
    // Create filesystem scanner
    filesystem_scanner_t* scanner = filesystem_scanner_create(config, manager);
    assert(scanner != NULL);
    
    // Test error handling
    assert(filesystem_scanner_create(NULL, NULL) == NULL);
    
    // Get statistics (should be empty initially)
    filesystem_scan_stats_t stats = filesystem_scanner_get_stats(scanner);
    assert(stats.total_files_processed == 0);
    assert(stats.total_directories_scanned == 0);
    
    printf("✓ Scanner creation test passed!\n\n");
    
    // Test 7: Error string conversion
    printf("Test 7: Error handling...\n");
    assert(strcmp(filesystem_scan_error_string(FS_SCAN_SUCCESS), "Success") == 0);
    assert(strcmp(filesystem_scan_error_string(FS_SCAN_ERROR_PERMISSION_DENIED), "Permission denied") == 0);
    assert(strcmp(filesystem_scan_error_string(FS_SCAN_ERROR_NOT_FOUND), "File not found") == 0);
    printf("✓ Error handling test passed!\n\n");
    
    // Cleanup
    filesystem_scanner_destroy(scanner);
    resource_manager_destroy(manager);
    filesystem_scan_config_destroy(config);
    
    printf("All simple filesystem scanner tests passed!\n");
    return 0;
}
