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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "resource_manager.h"
#include "secure_memory.h"

// Test resource manager creation and destruction
static bool test_resource_manager_creation(void) {
    printf("Running test: resource_manager_creation... ");
    
    // Test with default limits
    resource_manager_t* manager = resource_manager_create(NULL);
    if (!manager) {
        printf("FAILED - Could not create resource manager with default limits\n");
        return false;
    }
    
    resource_manager_destroy(manager);
    
    // Test with custom limits
    resource_limits_t limits = {
        .max_open_files = 100,
        .max_total_bytes = 1024 * 1024,
        .max_bytes_per_file = 64 * 1024,
        .max_concurrency = 4,
        .memory_watermark = 128 * 1024,
        .temp_dir_path = NULL, // Let resource manager find temp dir
        .enforce_noexec = false
    };
    
    manager = resource_manager_create(&limits);
    if (!manager) {
        printf("FAILED - Could not create resource manager with custom limits\n");
        return false;
    }
    
    resource_manager_destroy(manager);
    
    printf("PASSED\n");
    return true;
}

// Test file handle limits
static bool test_file_handle_limits(void) {
    printf("Running test: file_handle_limits... ");
    
    resource_limits_t limits = {
        .max_open_files = 2,
        .max_total_bytes = 1024 * 1024,
        .max_bytes_per_file = 64 * 1024,
        .max_concurrency = 4,
        .memory_watermark = 128 * 1024,
        .temp_dir_path = NULL,
        .enforce_noexec = false
    };
    
    resource_manager_t* manager = resource_manager_create(&limits);
    if (!manager) {
        printf("FAILED - Could not create resource manager\n");
        
        return false;
    }
    
    // Create test files
    char temp_file1[] = "/tmp/cbom_test1_XXXXXX";
    char temp_file2[] = "/tmp/cbom_test2_XXXXXX";
    char temp_file3[] = "/tmp/cbom_test3_XXXXXX";
    
    int temp_fd1 = mkstemp(temp_file1);
    int temp_fd2 = mkstemp(temp_file2);
    int temp_fd3 = mkstemp(temp_file3);
    
    if (temp_fd1 < 0 || temp_fd2 < 0 || temp_fd3 < 0) {
        printf("FAILED - Could not create test files\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Write some data to files
    ssize_t w1 = write(temp_fd1, "test data 1", 11);
    ssize_t w2 = write(temp_fd2, "test data 2", 11);
    ssize_t w3 = write(temp_fd3, "test data 3", 11);
    (void)w1; (void)w2; (void)w3; // Suppress unused variable warnings
    close(temp_fd1);
    close(temp_fd2);
    close(temp_fd3);
    
    // Test opening files within limit
    int fd1 = resource_manager_open_file(manager, temp_file1, O_RDONLY);
    if (fd1 < 0) {
        printf("FAILED - Could not open first file\n");
        goto cleanup;
    }
    
    int fd2 = resource_manager_open_file(manager, temp_file2, O_RDONLY);
    if (fd2 < 0) {
        printf("FAILED - Could not open second file\n");
        goto cleanup;
    }
    
    // Test exceeding file handle limit
    int fd3 = resource_manager_open_file(manager, temp_file3, O_RDONLY);
    if (fd3 >= 0) {
        printf("FAILED - Should not be able to open third file (exceeds limit)\n");
        resource_manager_close_file(manager, fd3);
        goto cleanup;
    }
    
    // Close files and test that we can open again
    resource_manager_close_file(manager, fd1);
    resource_manager_close_file(manager, fd2);
    
    fd3 = resource_manager_open_file(manager, temp_file3, O_RDONLY);
    if (fd3 < 0) {
        printf("FAILED - Should be able to open file after closing others\n");
        goto cleanup;
    }
    
    resource_manager_close_file(manager, fd3);
    
    printf("PASSED\n");
    
cleanup:
    unlink(temp_file1);
    unlink(temp_file2);
    unlink(temp_file3);
    resource_manager_destroy(manager);
    
    return true;
}

// Test memory limits
static bool test_memory_limits(void) {
    printf("Running test: memory_limits... ");
    
    resource_limits_t limits = {
        .max_open_files = 100,
        .max_total_bytes = 1024 * 1024,
        .max_bytes_per_file = 64 * 1024,
        .max_concurrency = 4,
        .memory_watermark = 1024, // Very small limit for testing
        .temp_dir_path = NULL,
        .enforce_noexec = false
    };
    
    resource_manager_t* manager = resource_manager_create(&limits);
    if (!manager) {
        printf("FAILED - Could not create resource manager\n");
        
        return false;
    }
    
    // Test allocation within limit
    void* ptr1 = resource_manager_allocate_memory(manager, 512);
    if (!ptr1) {
        printf("FAILED - Could not allocate memory within limit\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Test allocation exceeding limit
    void* ptr2 = resource_manager_allocate_memory(manager, 1024);
    if (ptr2) {
        printf("FAILED - Should not be able to allocate memory exceeding limit\n");
        resource_manager_free_memory(manager, ptr2, 1024);
        resource_manager_free_memory(manager, ptr1, 512);
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Test allocation after freeing
    resource_manager_free_memory(manager, ptr1, 512);
    ptr2 = resource_manager_allocate_memory(manager, 512);
    if (!ptr2) {
        printf("FAILED - Should be able to allocate memory after freeing\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    resource_manager_free_memory(manager, ptr2, 512);
    resource_manager_destroy(manager);
    
    
    printf("PASSED\n");
    return true;
}

// Test concurrency limits
static bool test_concurrency_limits(void) {
    printf("Running test: concurrency_limits... ");
    
    resource_limits_t limits = {
        .max_open_files = 100,
        .max_total_bytes = 1024 * 1024,
        .max_bytes_per_file = 64 * 1024,
        .max_concurrency = 2, // Small limit for testing
        .memory_watermark = 128 * 1024,
        .temp_dir_path = NULL,
        .enforce_noexec = false
    };
    
    resource_manager_t* manager = resource_manager_create(&limits);
    if (!manager) {
        printf("FAILED - Could not create resource manager\n");
        
        return false;
    }
    
    // Test starting operations within limit
    if (resource_manager_start_operation(manager) != 0) {
        printf("FAILED - Could not start first operation\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    if (resource_manager_start_operation(manager) != 0) {
        printf("FAILED - Could not start second operation\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Test exceeding concurrency limit
    if (resource_manager_start_operation(manager) == 0) {
        printf("FAILED - Should not be able to start third operation (exceeds limit)\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Test ending operations
    resource_manager_end_operation(manager);
    if (resource_manager_start_operation(manager) != 0) {
        printf("FAILED - Should be able to start operation after ending one\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    resource_manager_end_operation(manager);
    resource_manager_end_operation(manager);
    
    resource_manager_destroy(manager);
    
    
    printf("PASSED\n");
    return true;
}

// Test temporary file creation
static bool test_temp_file_creation(void) {
    printf("Running test: temp_file_creation... ");
    
    resource_limits_t limits = {
        .max_open_files = 100,
        .max_total_bytes = 1024 * 1024,
        .max_bytes_per_file = 64 * 1024,
        .max_concurrency = 4,
        .memory_watermark = 128 * 1024,
        .temp_dir_path = NULL,
        .enforce_noexec = false
    };
    
    resource_manager_t* manager = resource_manager_create(&limits);
    if (!manager) {
        printf("FAILED - Could not create resource manager\n");
        
        return false;
    }
    
    // Test temporary file creation
    char* temp_path = NULL;
    int fd = resource_manager_create_temp_file(manager, &temp_path);
    if (fd < 0 || !temp_path) {
        printf("FAILED - Could not create temporary file\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Verify file exists and is writable
    ssize_t written = write(fd, "test", 4);
    if (written != 4) {
        printf("FAILED - Could not write to temporary file\n");
        close(fd);
        unlink(temp_path);
        free(temp_path);
        resource_manager_destroy(manager);
        
        return false;
    }
    
    close(fd);
    unlink(temp_path);
    free(temp_path);
    
    // Test temporary directory creation
    char* temp_dir_path = NULL;
    if (resource_manager_create_temp_dir(manager, &temp_dir_path) != 0 || !temp_dir_path) {
        printf("FAILED - Could not create temporary directory\n");
        resource_manager_destroy(manager);
        
        return false;
    }
    
    // Verify directory exists
    struct stat st;
    if (stat(temp_dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        printf("FAILED - Temporary directory does not exist or is not a directory\n");
        rmdir(temp_dir_path);
        free(temp_dir_path);
        resource_manager_destroy(manager);
        
        return false;
    }
    
    rmdir(temp_dir_path);
    free(temp_dir_path);
    resource_manager_destroy(manager);
    
    
    printf("PASSED\n");
    return true;
}

// Test streaming mode
static bool test_streaming_mode(void) {
    printf("Running test: streaming_mode... ");
    
    resource_manager_t* manager = resource_manager_create(NULL);
    if (!manager) {
        printf("FAILED - Could not create resource manager\n");
        return false;
    }
    
    // Test enabling streaming mode
    if (!resource_manager_enable_streaming_mode(manager)) {
        printf("FAILED - Could not enable streaming mode\n");
        resource_manager_destroy(manager);
        return false;
    }
    
    // Test getting chunk size
    size_t chunk_size = resource_manager_get_chunk_size(manager);
    if (chunk_size == 0) {
        printf("FAILED - Chunk size should be non-zero\n");
        resource_manager_destroy(manager);
        return false;
    }
    
    // Test disabling streaming mode
    resource_manager_disable_streaming_mode(manager);
    
    resource_manager_destroy(manager);
    
    printf("PASSED\n");
    return true;
}

// Test resource statistics
static bool test_resource_statistics(void) {
    printf("Running test: resource_statistics... ");
    
    resource_manager_t* manager = resource_manager_create(NULL);
    if (!manager) {
        printf("FAILED - Could not create resource manager\n");
        return false;
    }
    
    // Get initial stats
    resource_stats_t stats = resource_manager_get_stats(manager);
    if (stats.file_handle_utilization < 0 || stats.file_handle_utilization > 100) {
        printf("FAILED - Invalid file handle utilization\n");
        resource_manager_destroy(manager);
        return false;
    }
    
    if (stats.memory_utilization < 0 || stats.memory_utilization > 100) {
        printf("FAILED - Invalid memory utilization\n");
        resource_manager_destroy(manager);
        return false;
    }
    
    if (stats.operation_utilization < 0 || stats.operation_utilization > 100) {
        printf("FAILED - Invalid operation utilization\n");
        resource_manager_destroy(manager);
        return false;
    }
    
    resource_manager_destroy(manager);
    
    printf("PASSED\n");
    return true;
}

// Test file handle pool
static bool test_file_handle_pool(void) {
    printf("Running test: file_handle_pool... ");
    
    file_handle_pool_t* pool = file_handle_pool_create(2);
    if (!pool) {
        printf("FAILED - Could not create file handle pool\n");
        return false;
    }
    
    // Create test files
    char temp_file1[] = "/tmp/cbom_pool_test1_XXXXXX";
    char temp_file2[] = "/tmp/cbom_pool_test2_XXXXXX";
    
    int temp_fd1 = mkstemp(temp_file1);
    int temp_fd2 = mkstemp(temp_file2);
    
    if (temp_fd1 < 0 || temp_fd2 < 0) {
        printf("FAILED - Could not create test files\n");
        file_handle_pool_destroy(pool);
        return false;
    }
    
    close(temp_fd1);
    close(temp_fd2);
    
    // Test getting file handles from pool
    int fd1 = file_handle_pool_get(pool, temp_file1, O_RDONLY);
    if (fd1 < 0) {
        printf("FAILED - Could not get file handle from pool\n");
        goto pool_cleanup;
    }
    
    int fd2 = file_handle_pool_get(pool, temp_file2, O_RDONLY);
    if (fd2 < 0) {
        printf("FAILED - Could not get second file handle from pool\n");
        goto pool_cleanup;
    }
    
    // Test returning file handles to pool
    file_handle_pool_return(pool, fd1);
    file_handle_pool_return(pool, fd2);
    
    // Test getting same file handle again (should reuse)
    int fd1_again = file_handle_pool_get(pool, temp_file1, O_RDONLY);
    if (fd1_again < 0) {
        printf("FAILED - Could not reuse file handle from pool\n");
        goto pool_cleanup;
    }
    
    file_handle_pool_return(pool, fd1_again);
    
    printf("PASSED\n");
    
pool_cleanup:
    unlink(temp_file1);
    unlink(temp_file2);
    file_handle_pool_destroy(pool);
    return true;
}

// Main test runner
int run_resource_manager_tests(void) {
    int passed = 0;
    int total = 8;
    
    if (test_resource_manager_creation()) passed++;
    if (test_file_handle_limits()) passed++;
    if (test_memory_limits()) passed++;
    if (test_concurrency_limits()) passed++;
    if (test_temp_file_creation()) passed++;
    if (test_streaming_mode()) passed++;
    if (test_resource_statistics()) passed++;
    if (test_file_handle_pool()) passed++;
    
    printf("Tests run: %d, Passed: %d\n", total, passed);
    
    if (passed == total) {
        printf("Resource manager tests PASSED!\n");
        return 0;
    } else {
        printf("Resource manager tests FAILED!\n");
        return 1;
    }
}
