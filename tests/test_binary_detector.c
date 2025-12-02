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
 * @file test_binary_detector.c
 * @brief Unit tests for binary detector (Phase 1: YAML Plugin False Positive Elimination)
 */

#include "detection/binary_detector.h"
#include "cbom_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

// v1.8.1: Mock global config for testing (non-cross-arch mode by default)
cbom_config_t g_cbom_config = {0};

// Test counter
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    printf("[TEST] %s...\n", #name); \
    if (test_##name()) { \
        printf("[PASS] %s\n\n", #name); \
        tests_passed++; \
    } else { \
        printf("[FAIL] %s\n\n", #name); \
        tests_failed++; \
    }

// Helper: Create a temporary executable
static bool create_temp_executable(const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) return false;
    fprintf(f, "#!/bin/bash\necho 'test'\n");
    fclose(f);
    chmod(path, 0755);  // Make executable
    return true;
}

// Helper: Create a temporary non-executable file
static bool create_temp_file(const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) return false;
    fprintf(f, "test content\n");
    fclose(f);
    chmod(path, 0644);  // Non-executable
    return true;
}

// Test 1: is_executable with valid executable
static bool test_is_executable_valid() {
    const char* path = "/tmp/test_binary_valid.sh";
    create_temp_executable(path);

    bool result = binary_detector_is_executable(path);

    unlink(path);
    return result == true;
}

// Test 2: is_executable with non-existent file
static bool test_is_executable_nonexistent() {
    bool result = binary_detector_is_executable("/tmp/nonexistent_file_12345");
    return result == false;
}

// Test 3: is_executable with non-executable file
static bool test_is_executable_no_permission() {
    const char* path = "/tmp/test_binary_no_exec.txt";
    create_temp_file(path);

    bool result = binary_detector_is_executable(path);

    unlink(path);
    return result == false;
}

// Test 4: is_executable with NULL path
static bool test_is_executable_null() {
    bool result = binary_detector_is_executable(NULL);
    return result == false;
}

// Test 5: is_executable with empty string
static bool test_is_executable_empty() {
    bool result = binary_detector_is_executable("");
    return result == false;
}

// Test 6: is_executable with system binary
static bool test_is_executable_system_binary() {
    // /bin/sh should exist on all Linux systems
    bool result = binary_detector_is_executable("/bin/sh");
    return result == true;
}

// Test 7: find with single valid path
static bool test_find_single_valid() {
    const char* path = "/tmp/test_find_single.sh";
    create_temp_executable(path);

    const char* paths[] = {path};
    char found[4096] = {0};
    bool result = binary_detector_find(paths, 1, found);

    unlink(path);
    return result == true && strcmp(found, path) == 0;
}

// Test 8: find with multiple paths, first valid
static bool test_find_multiple_first_valid() {
    const char* path1 = "/tmp/test_find_multi1.sh";
    create_temp_executable(path1);

    const char* paths[] = {path1, "/tmp/nonexistent"};
    char found[4096] = {0};
    bool result = binary_detector_find(paths, 2, found);

    unlink(path1);
    return result == true && strcmp(found, path1) == 0;
}

// Test 9: find with multiple paths, second valid
static bool test_find_multiple_second_valid() {
    const char* path2 = "/tmp/test_find_multi2.sh";
    create_temp_executable(path2);

    const char* paths[] = {"/tmp/nonexistent", path2};
    char found[4096] = {0};
    bool result = binary_detector_find(paths, 2, found);

    unlink(path2);
    return result == true && strcmp(found, path2) == 0;
}

// Test 10: find with no valid paths
static bool test_find_no_valid() {
    const char* paths[] = {"/tmp/nonexistent1", "/tmp/nonexistent2"};
    char found[4096] = {0};
    bool result = binary_detector_find(paths, 2, found);

    return result == false;
}

// Test 11: find with NULL paths
static bool test_find_null_paths() {
    char found[4096] = {0};
    bool result = binary_detector_find(NULL, 0, found);
    return result == false;
}

// Test 12: find with NULL found buffer
static bool test_find_null_buffer() {
    const char* paths[] = {"/bin/sh"};
    bool result = binary_detector_find(paths, 1, NULL);
    return result == false;
}

// Test 13: expand_pattern with glob (simple wildcard)
static bool test_expand_pattern_glob() {
    // Create test file matching pattern
    const char* path = "/tmp/test_glob_nginx";
    create_temp_executable(path);

    char found[4096] = {0};
    bool result = binary_detector_expand_pattern("/tmp/test_glob_*", found);

    unlink(path);

    // Should find the file (pattern matches)
    return result == true && strstr(found, "test_glob_") != NULL;
}

// Test 14: expand_pattern with no matches
static bool test_expand_pattern_no_match() {
    char found[4096] = {0};
    bool result = binary_detector_expand_pattern("/tmp/nonexistent_pattern_*", found);

    return result == false;
}

int main(void) {
    printf("=== Binary Detector Unit Tests ===\n\n");

    TEST(is_executable_valid);
    TEST(is_executable_nonexistent);
    TEST(is_executable_no_permission);
    TEST(is_executable_null);
    TEST(is_executable_empty);
    TEST(is_executable_system_binary);
    TEST(find_single_valid);
    TEST(find_multiple_first_valid);
    TEST(find_multiple_second_valid);
    TEST(find_no_valid);
    TEST(find_null_paths);
    TEST(find_null_buffer);
    TEST(expand_pattern_glob);
    TEST(expand_pattern_no_match);

    printf("=== Test Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
