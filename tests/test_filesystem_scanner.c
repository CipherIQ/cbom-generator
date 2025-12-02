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

// Test helper functions
static void create_test_directory_structure(const char* base_path);
static void cleanup_test_directory(const char* base_path);
static int test_file_callback(const file_info_t* file_info, 
                             filesystem_scan_context_t* context, 
                             asset_store_t* store, 
                             void* user_data);

// Test data structure
typedef struct {
    size_t files_found;
    size_t certificates_found;
    size_t keys_found;
    size_t executables_found;
    size_t config_files_found;
} test_callback_data_t;

// Test file callback implementation
static int test_file_callback(const file_info_t* file_info, 
                             filesystem_scan_context_t* context, 
                             asset_store_t* store, 
                             void* user_data) {
    (void)context; // Suppress unused parameter warning
    (void)store;   // Suppress unused parameter warning
    
    if (!file_info || !user_data) {
        return FS_SCAN_ERROR_INVALID_PARAM;
    }
    
    test_callback_data_t* data = (test_callback_data_t*)user_data;
    data->files_found++;
    
    printf("Found file: %s (type: %d, size: %zu)\n", 
           file_info->path, file_info->type, file_info->size);
    
    switch (file_info->type) {
        case FILE_TYPE_CERTIFICATE:
            data->certificates_found++;
            break;
        case FILE_TYPE_KEY:
            data->keys_found++;
            break;
        case FILE_TYPE_EXECUTABLE:
            data->executables_found++;
            break;
        case FILE_TYPE_CONFIG:
            data->config_files_found++;
            break;
        default:
            break;
    }
    
    return FS_SCAN_SUCCESS;
}

// Create test directory structure
static void create_test_directory_structure(const char* base_path) {
    char path[1024];
    
    // Create base directory
    mkdir(base_path, 0755);
    
    // Create subdirectories
    snprintf(path, sizeof(path), "%s/certs", base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/keys", base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/config", base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/bin", base_path);
    mkdir(path, 0755);
    
    // Create test certificate files
    snprintf(path, sizeof(path), "%s/certs/test.pem", base_path);
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        ssize_t result = write(fd, "-----BEGIN CERTIFICATE-----\ntest certificate data\n-----END CERTIFICATE-----\n", 75);
        (void)result; // Suppress unused warning
        close(fd);
    }
    
    snprintf(path, sizeof(path), "%s/certs/test.crt", base_path);
    fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        ssize_t result = write(fd, "-----BEGIN CERTIFICATE-----\ntest certificate data\n-----END CERTIFICATE-----\n", 75);
        (void)result; // Suppress unused warning
        close(fd);
    }
    
    // Create test key files
    snprintf(path, sizeof(path), "%s/keys/test.key", base_path);
    fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) {
        ssize_t result = write(fd, "-----BEGIN PRIVATE KEY-----\ntest private key data\n-----END PRIVATE KEY-----\n", 71);
        (void)result; // Suppress unused warning
        close(fd);
    }
    
    // Create test config files
    snprintf(path, sizeof(path), "%s/config/test.conf", base_path);
    fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        ssize_t result = write(fd, "# Test configuration file\nssl_certificate /path/to/cert.pem\n", 58);
        (void)result; // Suppress unused warning
        close(fd);
    }
    
    snprintf(path, sizeof(path), "%s/config/test.json", base_path);
    fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        ssize_t result = write(fd, "{\"ssl\": {\"certificate\": \"/path/to/cert.pem\"}}\n", 45);
        (void)result; // Suppress unused warning
        close(fd);
    }
    
    // Create test executable (ELF file)
    snprintf(path, sizeof(path), "%s/bin/test_binary", base_path);
    fd = open(path, O_CREAT | O_WRONLY, 0755);
    if (fd >= 0) {
        // Write ELF magic number
        unsigned char elf_header[] = {0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
        ssize_t result = write(fd, elf_header, sizeof(elf_header));
        (void)result; // Suppress unused warning
        close(fd);
    }
    
    // Create a file that should be skipped (no read permission)
    snprintf(path, sizeof(path), "%s/no_access.txt", base_path);
    fd = open(path, O_CREAT | O_WRONLY, 0000);
    if (fd >= 0) {
        ssize_t result = write(fd, "no access file\n", 15);
        (void)result; // Suppress unused warning
        close(fd);
    }
}

// Cleanup test directory
static void cleanup_test_directory(const char* base_path) {
    char command[1024];
    snprintf(command, sizeof(command), "rm -rf %s", base_path);
    int result = system(command);
    (void)result; // Suppress unused warning
}

// Test basic configuration creation
void test_config_creation(void) {
    printf("Testing configuration creation...\n");
    
    filesystem_scan_config_t* config = filesystem_scan_config_create_default();
    assert(config != NULL);
    assert(config->max_depth == DEFAULT_MAX_DEPTH);
    assert(config->max_files == DEFAULT_MAX_FILES);
    assert(config->skip_permission_errors == true);
    assert(config->auto_detect_container == true);
    
    // Test adding include paths
    int result = filesystem_scan_config_add_include_path(config, "/test/path");
    assert(result == FS_SCAN_SUCCESS);
    assert(config->include_path_count == 1);
    assert(strcmp(config->include_paths[0], "/test/path") == 0);
    
    // Test adding exclude paths
    result = filesystem_scan_config_add_exclude_path(config, "/exclude/path");
    assert(result == FS_SCAN_SUCCESS);
    assert(config->exclude_path_count == 1);
    assert(strcmp(config->exclude_paths[0], "/exclude/path") == 0);
    
    // Test adding file types
    result = filesystem_scan_config_add_file_type(config, FILE_TYPE_CERTIFICATE);
    assert(result == FS_SCAN_SUCCESS);
    assert(config->file_type_count == 1);
    assert(config->file_types[0] == FILE_TYPE_CERTIFICATE);
    
    filesystem_scan_config_destroy(config);
    printf("Configuration creation test passed!\n");
}

// Test container detection
void test_container_detection(void) {
    printf("Testing container detection...\n");
    
    container_context_t* context = detect_container_environment();
    if (context == NULL) {
        printf("Container detection returned NULL - this is expected on host systems\n");
        printf("Container detection test passed!\n");
        return;
    }
    
    printf("Container detected: %s\n", context->is_container ? "yes" : "no");
    if (context->is_container) {
        printf("Runtime type: %s\n", context->runtime_type ? context->runtime_type : "unknown");
        printf("Container ID: %s\n", context->container_id ? context->container_id : "unknown");
    }
    
    container_context_destroy(context);
    printf("Container detection test passed!\n");
}

// Test file type detection
void test_file_type_detection(void) {
    printf("Testing file type detection...\n");
    
    // Test extension-based detection
    // Note: .pem uses content-based detection (can contain certs or keys)
    assert(detect_file_type_by_extension("test.pem") == FILE_TYPE_UNKNOWN);
    assert(detect_file_type_by_extension("test.crt") == FILE_TYPE_CERTIFICATE);
    assert(detect_file_type_by_extension("test.key") == FILE_TYPE_KEY);
    assert(detect_file_type_by_extension("test.conf") == FILE_TYPE_CONFIG);
    assert(detect_file_type_by_extension("test.so") == FILE_TYPE_LIBRARY);
    assert(detect_file_type_by_extension("test.unknown") == FILE_TYPE_UNKNOWN);
    
    printf("File type detection test passed!\n");
}

// Test path filtering
void test_path_filtering(void) {
    printf("Testing path filtering...\n");
    
    filesystem_scan_config_t* config = filesystem_scan_config_create_default();
    assert(config != NULL);
    
    // Test include paths
    filesystem_scan_config_add_include_path(config, "/usr/lib");
    filesystem_scan_config_add_include_path(config, "/etc");
    
    assert(should_include_path("/usr/lib/ssl", config) == true);
    assert(should_include_path("/etc/ssl", config) == true);
    assert(should_include_path("/home/user", config) == false);
    
    // Test exclude paths
    filesystem_scan_config_add_exclude_path(config, "/proc");
    filesystem_scan_config_add_exclude_path(config, "/sys");
    
    assert(should_exclude_path("/proc/cpuinfo", config) == true);
    assert(should_exclude_path("/sys/devices", config) == true);
    assert(should_exclude_path("/usr/lib/ssl", config) == false);
    
    filesystem_scan_config_destroy(config);
    printf("Path filtering test passed!\n");
}

// Test resource limits
void test_resource_limits(void) {
    printf("Testing resource limits...\n");
    
    // Create resource manager with limits
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
    
    // Test file size limit checking
    assert(check_file_size_limit(32 * 1024, manager) == true);  // 32KB - should pass
    assert(check_file_size_limit(128 * 1024, manager) == false); // 128KB - should fail
    
    resource_manager_destroy(manager);
    printf("Resource limits test passed!\n");
}

// Test filesystem scanning
void test_filesystem_scanning(void) {
    printf("Testing filesystem scanning...\n");
    
    const char* test_dir = "/tmp/cbom_fs_test";
    
    // Create test directory structure
    create_test_directory_structure(test_dir);
    
    // Create scanner configuration
    filesystem_scan_config_t* config = filesystem_scan_config_create_default();
    assert(config != NULL);
    
    // Add file types to scan
    filesystem_scan_config_add_file_type(config, FILE_TYPE_CERTIFICATE);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_KEY);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_CONFIG);
    filesystem_scan_config_add_file_type(config, FILE_TYPE_EXECUTABLE);
    
    // Create resource manager
    resource_manager_t* manager = resource_manager_create(NULL);
    assert(manager != NULL);
    
    // Create filesystem scanner
    filesystem_scanner_t* scanner = filesystem_scanner_create(config, manager);
    assert(scanner != NULL);
    
    // Set up callback
    test_callback_data_t callback_data = {0};
    scanner->file_callback = test_file_callback;
    scanner->callback_user_data = &callback_data;
    
    // Create asset store
    asset_store_t* store = asset_store_create(64);
    assert(store != NULL);
    
    // Perform scan
    int result = filesystem_scanner_scan(scanner, test_dir, store);
    assert(result == FS_SCAN_SUCCESS);
    
    // Verify results
    printf("Scan results:\n");
    printf("  Total files found: %zu\n", callback_data.files_found);
    printf("  Certificates found: %zu\n", callback_data.certificates_found);
    printf("  Keys found: %zu\n", callback_data.keys_found);
    printf("  Executables found: %zu\n", callback_data.executables_found);
    printf("  Config files found: %zu\n", callback_data.config_files_found);
    
    // We should find at least some files
    assert(callback_data.files_found > 0);
    assert(callback_data.certificates_found >= 2); // test.pem, test.crt
    assert(callback_data.keys_found >= 1);         // test.key
    assert(callback_data.config_files_found >= 2); // test.conf, test.json
    assert(callback_data.executables_found >= 1);  // test_binary
    
    // Get scan statistics
    filesystem_scan_stats_t stats = filesystem_scanner_get_stats(scanner);
    printf("Scan statistics:\n");
    printf("  Files processed: %zu\n", stats.total_files_processed);
    printf("  Files skipped: %zu\n", stats.total_files_skipped);
    printf("  Directories scanned: %zu\n", stats.total_directories_scanned);
    printf("  Permission errors: %zu\n", stats.permission_errors);
    
    // Should have processed some files and encountered at least one permission error
    assert(stats.total_files_processed > 0);
    assert(stats.total_directories_scanned > 0);
    // Permission errors expected due to no_access.txt file
    assert(stats.permission_errors >= 1);
    
    // Cleanup
    asset_store_destroy(store);
    filesystem_scanner_destroy(scanner);
    resource_manager_destroy(manager);
    filesystem_scan_config_destroy(config);
    cleanup_test_directory(test_dir);
    
    printf("Filesystem scanning test passed!\n");
}

// Test error handling
void test_error_handling(void) {
    printf("Testing error handling...\n");
    
    // Test invalid parameters
    assert(filesystem_scanner_create(NULL, NULL) == NULL);
    
    filesystem_scan_config_t* config = filesystem_scan_config_create_default();
    assert(config != NULL);
    
    filesystem_scanner_t* scanner = filesystem_scanner_create(config, NULL);
    assert(scanner != NULL);
    
    // Test scanning non-existent directory
    asset_store_t* store = asset_store_create(64);
    assert(store != NULL);
    
    int result = filesystem_scanner_scan(scanner, "/non/existent/path", store);
    // Should handle gracefully (may return error or success depending on implementation)
    
    // Test error string conversion
    assert(strcmp(filesystem_scan_error_string(FS_SCAN_SUCCESS), "Success") == 0);
    assert(strcmp(filesystem_scan_error_string(FS_SCAN_ERROR_PERMISSION_DENIED), "Permission denied") == 0);
    
    // Cleanup
    asset_store_destroy(store);
    filesystem_scanner_destroy(scanner);
    filesystem_scan_config_destroy(config);
    
    printf("Error handling test passed!\n");
}

// Main test function
int main(void) {
    printf("Starting filesystem scanner tests...\n\n");
    
    // Initialize secure memory
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory\n");
        return 1;
    }
    
    test_config_creation();
    test_container_detection();
    test_file_type_detection();
    test_path_filtering();
    test_resource_limits();
    test_filesystem_scanning();
    test_error_handling();
    
    printf("\nAll filesystem scanner tests passed!\n");
    
    // Cleanup secure memory
    secure_memory_cleanup();
    
    return 0;
}
