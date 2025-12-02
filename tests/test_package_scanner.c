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
#include <unistd.h>
#include "package_scanner.h"
#include "asset_store.h"
#include "secure_memory.h"

// Test 1: Package manager availability detection
static void test_package_manager_available(void) {
    printf("Testing package manager availability detection...\n");

    // Test string conversion
    assert(strcmp(package_manager_to_string(PKG_MANAGER_APT), "apt") == 0);
    assert(strcmp(package_manager_to_string(PKG_MANAGER_RPM), "rpm") == 0);
    assert(strcmp(package_manager_to_string(PKG_MANAGER_PIP), "pip") == 0);

    // Test enum conversion
    assert(package_manager_from_string("apt") == PKG_MANAGER_APT);
    assert(package_manager_from_string("rpm") == PKG_MANAGER_RPM);
    assert(package_manager_from_string("dpkg") == PKG_MANAGER_APT);

    printf("✓ Package manager detection tests passed\n");
}

// Test 2: Crypto library detection
static void test_crypto_library_detection(void) {
    printf("Testing crypto library detection...\n");

    // Should be detected as crypto
    assert(is_crypto_library("openssl") == true);
    assert(is_crypto_library("libssl3") == true);
    assert(is_crypto_library("libcrypto") == true);
    assert(is_crypto_library("gnutls") == true);
    assert(is_crypto_library("python3-cryptography") == true);

    // Should NOT be detected as crypto
    assert(is_crypto_library("bash") == false);
    assert(is_crypto_library("gcc") == false);
    assert(is_crypto_library("python3") == false);

    printf("✓ Crypto library detection tests passed\n");
}

// Test 3: FIPS detection (stub)
static void test_fips_detection_basic(void) {
    printf("Testing FIPS detection (STUB ONLY)...\n");

    // Test FIPS string conversion
    assert(strcmp(fips_level_to_string(FIPS_LEVEL_140_3_L1), "140-3-L1") == 0);
    assert(strcmp(fips_level_to_string(FIPS_LEVEL_140_2), "140-2") == 0);
    assert(strcmp(fips_level_to_string(FIPS_NOT_CERTIFIED), "NOT_CERTIFIED") == 0);

    // Test basic FIPS detection from package name
    fips_level_t level = detect_fips_level_basic("openssl-fips", "3.0.8");
    assert(level == FIPS_LEVEL_140_3_L1);

    // Test non-FIPS package
    level = detect_fips_level_basic("openssl", "3.0.8");
    assert(level == FIPS_NOT_CERTIFIED);

    // Test with FIPS in version
    level = detect_fips_level_basic("libcrypto", "3.0.8-fips");
    assert(level == FIPS_LEVEL_140_3_L1);

    printf("✓ FIPS detection tests passed (STUB ONLY)\n");
}

// Test 4: Package scanner configuration
static void test_package_scanner_config(void) {
    printf("Testing package scanner configuration...\n");

    package_scanner_config_t config = package_scanner_create_default_config();

    assert(config.scan_system_packages == true);
    assert(config.scan_app_packages == true);
    assert(config.scan_apt == true);
    assert(config.scan_rpm == true);
    assert(config.scan_pip == true);
    assert(config.crypto_only == true);
    assert(config.detect_fips_basic == true);
    assert(config.fips_validation_online == false);  // Deferred
    assert(config.max_packages > 0);

    package_scanner_config_destroy(&config);

    printf("✓ Package scanner configuration tests passed\n");
}

// Test 5: Package scanner context
static void test_package_scanner_context(void) {
    printf("Testing package scanner context...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    package_scanner_config_t config = package_scanner_create_default_config();
    package_scanner_context_t* context = package_scanner_create(&config, store);
    assert(context != NULL);
    assert(context->asset_store == store);

    // Test statistics initialization
    package_scanner_stats_t stats = package_scanner_get_stats(context);
    assert(stats.packages_scanned_total == 0);
    assert(stats.crypto_packages_found == 0);

    package_scanner_destroy(context);
    asset_store_destroy(store);

    // Test with NULL parameters
    context = package_scanner_create(NULL, store);
    assert(context == NULL);

    printf("✓ Package scanner context tests passed\n");
}

// Test 6: Package metadata extraction
static void test_package_metadata_extraction(void) {
    printf("Testing package metadata extraction...\n");

    package_metadata_t* metadata = package_extract_metadata(
        "openssl", "3.0.8", PKG_MANAGER_APT);
    assert(metadata != NULL);
    assert(strcmp(metadata->name, "openssl") == 0);
    assert(strcmp(metadata->version, "3.0.8") == 0);
    assert(metadata->package_manager == PKG_MANAGER_APT);
    assert(metadata->is_crypto_library == true);
    assert(metadata->fips_detected == true);
    assert(metadata->algorithm_count > 0);  // Should detect algorithms

    package_metadata_destroy(metadata);

    printf("✓ Package metadata extraction tests passed\n");
}

// Test 7: Algorithm detection
static void test_algorithm_detection(void) {
    printf("Testing algorithm detection...\n");

    size_t count = 0;
    char** algorithms = detect_implemented_algorithms("openssl", "3.0.8", &count);
    assert(algorithms != NULL);
    assert(count > 0);

    // Check for common algorithms
    bool has_aes = false, has_rsa = false, has_sha256 = false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(algorithms[i], "AES") == 0) has_aes = true;
        if (strcmp(algorithms[i], "RSA") == 0) has_rsa = true;
        if (strcmp(algorithms[i], "SHA-256") == 0) has_sha256 = true;
        free(algorithms[i]);
    }
    free(algorithms);

    assert(has_aes == true);
    assert(has_rsa == true);
    assert(has_sha256 == true);

    printf("✓ Algorithm detection tests passed\n");
}

// Test 8: Package asset creation
static void test_package_asset_creation(void) {
    printf("Testing package asset creation...\n");

    package_metadata_t* metadata = package_extract_metadata(
        "libssl3", "3.0.8", PKG_MANAGER_APT);
    assert(metadata != NULL);

    crypto_asset_t* asset = package_create_asset(metadata);
    assert(asset != NULL);
    assert(asset->type == ASSET_TYPE_LIBRARY);
    assert(asset->id != NULL);
    assert(asset->name != NULL);
    assert(asset->metadata_json != NULL);

    // Verify ID format: library|name|version|package_manager
    assert(strstr(asset->id, "library|") != NULL);
    assert(strstr(asset->id, "libssl3") != NULL);
    assert(strstr(asset->id, "3.0.8") != NULL);
    assert(strstr(asset->id, "apt") != NULL);

    package_metadata_destroy(metadata);

    printf("✓ Package asset creation tests passed\n");
}

// Test 9: JSON metadata generation
static void test_json_metadata_generation(void) {
    printf("Testing JSON metadata generation...\n");

    package_metadata_t* metadata = package_extract_metadata(
        "openssl", "3.0.8", PKG_MANAGER_APT);
    assert(metadata != NULL);

    char* json = package_create_detailed_json_metadata(metadata);
    assert(json != NULL);

    // Verify JSON contains expected fields
    assert(strstr(json, "\"name\"") != NULL);
    assert(strstr(json, "\"version\"") != NULL);
    assert(strstr(json, "\"package_manager\"") != NULL);
    assert(strstr(json, "\"fips_level\"") != NULL);
    assert(strstr(json, "\"fips_validation_status\"") != NULL);
    assert(strstr(json, "STUB_ONLY_NOT_VALIDATED") != NULL);  // FIPS limitation warning

    free(json);
    package_metadata_destroy(metadata);

    printf("✓ JSON metadata generation tests passed\n");
}

// Test 10: FIPS limitation documentation
static void test_fips_limitation_documented(void) {
    printf("Testing FIPS limitation documentation (CRITICAL)...\n");

    // Test that FIPS validation status is always marked as stub
    package_metadata_t* metadata = package_extract_metadata(
        "openssl-fips", "3.0.8-fips", PKG_MANAGER_APT);
    assert(metadata != NULL);

    char* json = package_create_detailed_json_metadata(metadata);
    assert(json != NULL);

    // CRITICAL: Must document FIPS is stub only
    assert(strstr(json, "STUB_ONLY_NOT_VALIDATED") != NULL);

    free(json);
    package_metadata_destroy(metadata);

    printf("✓ CRITICAL: FIPS limitation properly documented ✓\n");
}

// Test 11: Package scanner statistics
static void test_package_scanner_statistics(void) {
    printf("Testing package scanner statistics...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    package_scanner_config_t config = package_scanner_create_default_config();
    package_scanner_context_t* context = package_scanner_create(&config, store);
    assert(context != NULL);

    // Initial statistics should be zero
    package_scanner_stats_t stats = package_scanner_get_stats(context);
    assert(stats.packages_scanned_total == 0);
    assert(stats.crypto_packages_found == 0);
    assert(stats.apt_packages == 0);
    assert(stats.pip_packages == 0);

    package_scanner_destroy(context);
    asset_store_destroy(store);

    printf("✓ Package scanner statistics tests passed\n");
}

// Test 12: Graceful handling of missing package managers
static void test_missing_package_managers(void) {
    printf("Testing graceful handling of missing package managers...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    package_scanner_config_t config = package_scanner_create_default_config();
    package_scanner_context_t* context = package_scanner_create(&config, store);
    assert(context != NULL);

    // Try to scan - should not crash even if package managers missing
    // Just returns 0 or -1, doesn't crash
    (void)package_scanner_scan_all(context);

    package_scanner_destroy(context);
    asset_store_destroy(store);

    printf("✓ Missing package manager handling tests passed\n");
}

// Test 13: Crypto library name matching
static void test_crypto_library_names(void) {
    printf("Testing crypto library name matching...\n");

    // System libraries
    assert(is_crypto_library("openssl") == true);
    assert(is_crypto_library("libssl3") == true);
    assert(is_crypto_library("libssl1.1") == true);
    assert(is_crypto_library("libcrypto3") == true);
    assert(is_crypto_library("gnutls30") == true);
    assert(is_crypto_library("libgnutls-deb0-28") == true);
    assert(is_crypto_library("wolfssl") == true);
    assert(is_crypto_library("mbedtls") == true);

    // Python packages
    assert(is_crypto_library("python3-cryptography") == true);
    assert(is_crypto_library("pycryptodome") == true);

    // Node packages
    assert(is_crypto_library("bcrypt") == true);
    assert(is_crypto_library("node-forge") == true);

    // Ruby gems
    assert(is_crypto_library("ruby-openssl") == true);

    printf("✓ Crypto library name matching tests passed\n");
}

// Test 14: FIPS system check
static void test_fips_system_check(void) {
    printf("Testing FIPS system check...\n");

    // This checks /proc/sys/crypto/fips_enabled
    // Just verify it doesn't crash
    bool fips_enabled = is_fips_enabled_system();
    printf("   System FIPS mode: %s\n", fips_enabled ? "enabled" : "disabled");

    printf("✓ FIPS system check tests passed\n");
}

// Test 15: Package type classification
static void test_package_type_classification(void) {
    printf("Testing package type classification...\n");

    // System packages
    package_metadata_t* apt_meta = package_extract_metadata("openssl", "3.0.8", PKG_MANAGER_APT);
    assert(apt_meta != NULL);
    assert(apt_meta->package_type == PACKAGE_TYPE_SYSTEM);
    package_metadata_destroy(apt_meta);

    // Application packages
    package_metadata_t* pip_meta = package_extract_metadata("cryptography", "41.0.0", PKG_MANAGER_PIP);
    assert(pip_meta != NULL);
    assert(pip_meta->package_type == PACKAGE_TYPE_APPLICATION);
    package_metadata_destroy(pip_meta);

    printf("✓ Package type classification tests passed\n");
}

// Main test runner
int main(void) {
    printf("=== Package Scanner Test Suite ===\n\n");

    // Initialize secure memory subsystem
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory subsystem\n");
        return 1;
    }

    // Run all tests
    test_package_manager_available();
    test_crypto_library_detection();
    test_fips_detection_basic();
    test_package_scanner_config();
    test_package_scanner_context();
    test_package_metadata_extraction();
    test_algorithm_detection();
    test_package_asset_creation();
    test_json_metadata_generation();

    // CRITICAL test
    printf("\n=== CRITICAL FIPS LIMITATION TEST ===\n");
    test_fips_limitation_documented();
    printf("=== END CRITICAL TEST ===\n\n");

    test_package_scanner_statistics();
    test_missing_package_managers();
    test_crypto_library_names();
    test_fips_system_check();
    test_package_type_classification();

    // Cleanup
    secure_memory_cleanup();

    printf("\n=== All Package Scanner Tests Passed ===\n");
    return 0;
}
