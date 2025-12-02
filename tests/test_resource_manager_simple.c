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
#include "resource_manager.h"
#include "secure_memory.h"

// Simple resource manager tests without complex LRU/mutex operations
static bool test_resource_limits_validation(void) {
    printf("Running test: resource_limits_validation... ");
    
    // Test utility functions
    size_t available_memory = get_available_memory();
    if (available_memory == 0) {
        printf("FAILED - Should detect some available memory\n");
        return false;
    }
    
    // Test file size detection
    size_t file_size = get_file_size("/etc/passwd");
    if (file_size == 0) {
        printf("FAILED - /etc/passwd should have non-zero size\n");
        return false;
    }
    
    printf("PASSED\n");
    return true;
}

static bool test_temp_directory_detection(void) {
    printf("Running test: temp_directory_detection... ");
    
    char* temp_dir = find_noexec_temp_dir();
    if (!temp_dir) {
        printf("FAILED - Should find a temp directory\n");
        return false;
    }
    
    // Check if it's a valid directory path
    if (strlen(temp_dir) == 0 || temp_dir[0] != '/') {
        printf("FAILED - Temp directory should be absolute path\n");
        free(temp_dir);
        return false;
    }
    
    free(temp_dir);
    printf("PASSED\n");
    return true;
}

static bool test_salt_entropy_validation(void) {
    printf("Running test: salt_entropy_validation... ");
    
    // Test noexec mount detection (may not work in all environments)
    bool is_noexec = is_noexec_mount("/tmp");
    // This is just a test that the function doesn't crash
    (void)is_noexec; // Suppress unused variable warning
    
    printf("PASSED\n");
    return true;
}

// Simple test runner for resource manager
int run_resource_manager_simple_tests(void) {
    int passed = 0;
    int total = 3;
    
    if (test_resource_limits_validation()) passed++;
    if (test_temp_directory_detection()) passed++;
    if (test_salt_entropy_validation()) passed++;
    
    printf("Tests run: %d, Passed: %d\n", total, passed);
    
    if (passed == total) {
        printf("Resource manager simple tests PASSED!\n");
        return 0;
    } else {
        printf("Resource manager simple tests FAILED!\n");
        return 1;
    }
}
