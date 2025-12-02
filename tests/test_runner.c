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

#include "secure_memory.h"

// External test functions
extern int run_asset_store_tests(void);
extern int run_normalization_tests(void);
extern int run_error_handling_tests(void);
extern int run_cyclonedx_converter_tests(void);
extern int run_resource_manager_tests(void);
extern int run_privacy_tests(void);
extern int run_config_tests(void);
extern int run_privacy_simple_tests(void);
extern int run_resource_manager_simple_tests(void);
extern int run_thread_pool_tests(void);
extern int run_timeout_manager_tests(void);
extern int run_plugin_manager_tests(void);
extern int run_filesystem_scanner_tests(void);
extern int run_crypto_registry_tests(void);
extern int run_library_detection_tests(void);
extern int run_embedded_providers_tests(void);

int main(void) {
    printf("CBOM Generator Test Suite\n");
    printf("========================\n\n");
    
    // Initialize secure memory
    if (secure_memory_init() != 0) {
        printf("Failed to initialize secure memory\n");
        return 1;
    }
    
    int total_failures = 0;
    
    // Run asset store tests
    printf("Asset Store Tests:\n");
    printf("-----------------\n");
    int asset_store_result = run_asset_store_tests();
    if (asset_store_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run normalization tests
    printf("Normalization Tests:\n");
    printf("-------------------\n");
    int normalization_result = run_normalization_tests();
    if (normalization_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run error handling tests
    printf("Error Handling Tests:\n");
    printf("--------------------\n");
    int error_handling_result = run_error_handling_tests();
    if (error_handling_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run CycloneDX converter tests
    printf("CycloneDX Converter Tests:\n");
    printf("-------------------------\n");
    int cyclonedx_result = run_cyclonedx_converter_tests();
    if (cyclonedx_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run resource manager simple tests
    printf("Resource Manager Tests (Simple):\n");
    printf("-------------------------------\n");
    int resource_simple_result = run_resource_manager_simple_tests();
    if (resource_simple_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run privacy simple tests
    printf("Privacy Tests (Simple):\n");
    printf("----------------------\n");
    int privacy_simple_result = run_privacy_simple_tests();
    if (privacy_simple_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run configuration tests
    printf("Configuration Tests:\n");
    printf("-------------------\n");
    int config_result = run_config_tests();
    if (config_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run thread pool tests
    printf("Thread Pool Tests:\n");
    printf("------------------\n");
    int thread_pool_result = run_thread_pool_tests();
    if (thread_pool_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run timeout manager tests
    printf("Timeout Manager Tests:\n");
    printf("---------------------\n");
    int timeout_manager_result = run_timeout_manager_tests();
    if (timeout_manager_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run plugin manager tests
    printf("Plugin Manager Tests:\n");
    printf("--------------------\n");
    int plugin_manager_result = run_plugin_manager_tests();
    if (plugin_manager_result != 0) {
        total_failures++;
    }
    printf("\n");

    // Run crypto registry tests
    printf("Crypto Registry Tests:\n");
    printf("---------------------\n");
    int crypto_registry_result = run_crypto_registry_tests();
    if (crypto_registry_result != 0) {
        total_failures++;
    }
    printf("\n");

    // Run library detection tests
    printf("Library Detection Tests:\n");
    printf("-----------------------\n");
    int library_detection_result = run_library_detection_tests();
    if (library_detection_result != 0) {
        total_failures++;
    }
    printf("\n");

    // Run embedded providers tests
    printf("Embedded Providers Tests:\n");
    printf("-----------------------\n");
    int embedded_providers_result = run_embedded_providers_tests();
    if (embedded_providers_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Run filesystem scanner tests
    printf("Filesystem Scanner Tests:\n");
    printf("------------------------\n");
    int filesystem_scanner_result = run_filesystem_scanner_tests();
    if (filesystem_scanner_result != 0) {
        total_failures++;
    }
    printf("\n");
    
    // Cleanup
    secure_memory_cleanup();
    
    // Summary
    printf("========================\n");
    if (total_failures == 0) {
        printf("All test suites PASSED!\n");
        return 0;
    } else {
        printf("%d test suite(s) FAILED!\n", total_failures);
        return 1;
    }
}
