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
#include <assert.h>
#include <time.h>
#include "pqc_report.h"
#include "asset_store.h"
#include "cbom_types.h"
#include "pqc_classifier.h"
#include "secure_memory.h"

// Helper: Create test algorithm asset
static crypto_asset_t* create_test_algorithm(const char* name, const char* algorithm, int key_size) {
    crypto_asset_t* asset = (crypto_asset_t*)secure_alloc(sizeof(crypto_asset_t));
    if (!asset) return NULL;

    memset(asset, 0, sizeof(crypto_asset_t));
    asset->id = strdup("test-id");
    asset->name = strdup(name);
    asset->algorithm = algorithm ? strdup(algorithm) : NULL;
    asset->type = ASSET_TYPE_ALGORITHM;
    asset->key_size = key_size;

    return asset;
}

// Test 1: Report generation succeeds
static void test_report_generation(void) {
    printf("Testing report file generation...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    // Add a test asset
    crypto_asset_t* rsa1024 = create_test_algorithm("RSA-1024", "RSA", 1024);
    assert(rsa1024 != NULL);
    assert(asset_store_add(store, rsa1024) == 0);

    // Generate report to tmpfile
    FILE* report = tmpfile();
    assert(report != NULL);

    int result = pqc_generate_migration_report(store, report);
    assert(result == 0);

    // Verify file has content
    fseek(report, 0, SEEK_END);
    long size = ftell(report);
    assert(size > 500);  // Report should have substantial content

    fclose(report);
    asset_store_destroy(store);

    printf("✓ Report generation test passed\n");
}

// Test 2: Report contains all required sections
static void test_report_sections(void) {
    printf("Testing report sections...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    // Create tmpfile for report
    FILE* report = tmpfile();
    assert(report != NULL);

    int result = pqc_generate_migration_report(store, report);
    assert(result == 0);

    // Read report content
    fseek(report, 0, SEEK_SET);
    char* buffer = (char*)malloc(8192);
    assert(buffer != NULL);
    size_t bytes = fread(buffer, 1, 8191, report);
    buffer[bytes] = '\0';

    // Verify required sections exist
    assert(strstr(buffer, "EXECUTIVE SUMMARY") != NULL);
    assert(strstr(buffer, "VULNERABILITY BREAKDOWN") != NULL);
    assert(strstr(buffer, "MIGRATION PRIORITY") != NULL);
    assert(strstr(buffer, "NIST PQC STANDARDS") != NULL || strstr(buffer, "FIPS") != NULL);
    assert(strstr(buffer, "RECOMMENDATIONS") != NULL);
    assert(strstr(buffer, "KEY MILESTONES") != NULL);

    free(buffer);
    fclose(report);
    asset_store_destroy(store);

    printf("✓ Report sections test passed\n");
}

// Test 3: Empty store handling
static void test_empty_store(void) {
    printf("Testing empty store handling...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    FILE* report = tmpfile();
    assert(report != NULL);

    int result = pqc_generate_migration_report(store, report);
    assert(result == 0);  // Should succeed even with empty store

    // Verify report was generated
    fseek(report, 0, SEEK_END);
    long size = ftell(report);
    assert(size > 0);

    fclose(report);
    asset_store_destroy(store);

    printf("✓ Empty store test passed\n");
}

// Test 4: Mixed assets (SAFE, TRANSITIONAL, UNSAFE)
static void test_mixed_assets(void) {
    printf("Testing mixed asset types...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    // Add SAFE asset (Kyber-768)
    crypto_asset_t* kyber = create_test_algorithm("Kyber-768", "Kyber-768", 768);
    assert(kyber != NULL);
    assert(asset_store_add(store, kyber) == 0);

    // Add TRANSITIONAL asset (RSA-2048)
    crypto_asset_t* rsa2048 = create_test_algorithm("RSA-2048", "RSA", 2048);
    assert(rsa2048 != NULL);
    assert(asset_store_add(store, rsa2048) == 0);

    // Add UNSAFE asset (RSA-1024)
    crypto_asset_t* rsa1024 = create_test_algorithm("RSA-1024", "RSA", 1024);
    assert(rsa1024 != NULL);
    assert(asset_store_add(store, rsa1024) == 0);

    FILE* report = tmpfile();
    assert(report != NULL);

    int result = pqc_generate_migration_report(store, report);
    assert(result == 0);

    // Read and verify report contains break years
    fseek(report, 0, SEEK_SET);
    char buffer[4096];
    size_t bytes = fread(buffer, 1, sizeof(buffer)-1, report);
    buffer[bytes] = '\0';

    assert(strstr(buffer, "2030") != NULL);  // Break year for RSA-1024
    assert(strstr(buffer, "2035") != NULL);  // Break year for RSA-2048

    fclose(report);
    asset_store_destroy(store);

    printf("✓ Mixed assets test passed\n");
}

// Test 5: NULL parameter handling
static void test_null_parameters(void) {
    printf("Testing NULL parameter handling...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    FILE* report = tmpfile();
    assert(report != NULL);

    // NULL store should fail gracefully
    assert(pqc_generate_migration_report(NULL, report) == -1);

    // NULL output should fail gracefully
    assert(pqc_generate_migration_report(store, NULL) == -1);

    // Both NULL should fail gracefully
    assert(pqc_generate_migration_report(NULL, NULL) == -1);

    fclose(report);
    asset_store_destroy(store);

    printf("✓ NULL parameter handling test passed\n");
}

int main(void) {
    printf("=== PQC Report Generator Test Suite ===\n\n");

    // Initialize secure memory
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory subsystem\n");
        return 1;
    }

    // Run all tests
    test_report_generation();
    test_report_sections();
    test_empty_store();
    test_mixed_assets();
    test_null_parameters();

    // Cleanup
    secure_memory_cleanup();

    printf("\n=== All PQC Report Tests Passed ===\n");
    printf("Total: 5 test suites\n");
    printf("\n✅ v1.2 PQC Report Generator VERIFIED:\n");
    printf("  ✅ Report generation works\n");
    printf("  ✅ All sections present\n");
    printf("  ✅ Empty store handled gracefully\n");
    printf("  ✅ Break year estimates in output\n");
    printf("  ✅ NULL parameters handled safely\n");

    return 0;
}
