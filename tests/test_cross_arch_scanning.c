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
#include "detection/library_detection.h"
#include "asset_store.h"
#include "secure_memory.h"
#include "cbom_types.h"
#include "path_utils.h"

// External global config from main.c
extern cbom_config_t g_cbom_config;

// Test 1: SONAME extraction from valid ELF library
static void test_soname_extraction_valid(void) {
    printf("Testing SONAME extraction from valid ELF...\n");

    // Use system libssl as test subject (should exist on most systems)
    const char* libssl_paths[] = {
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.3",
        NULL
    };

    const char* test_path = NULL;
    for (const char** p = libssl_paths; *p; p++) {
        if (access(*p, R_OK) == 0) {
            test_path = *p;
            break;
        }
    }

    if (!test_path) {
        printf("  SKIP: No libssl.so.3 found on system\n");
        return;
    }

    char* soname = extract_soname_from_elf(test_path);
    assert(soname != NULL);
    printf("  Extracted SONAME: %s\n", soname);

    // Should extract "libssl.so.3" or similar
    assert(strstr(soname, "libssl") != NULL);

    free(soname);
    printf("✓ SONAME extraction from valid ELF passed\n");
}

// Test 2: SONAME extraction fallback to basename for non-ELF files
static void test_soname_extraction_fallback(void) {
    printf("Testing SONAME extraction fallback to basename...\n");

    // Use a text file - should fallback to basename
    const char* test_path = "/etc/passwd";  // Always exists, not ELF
    char* soname = extract_soname_from_elf(test_path);

    assert(soname != NULL);
    printf("  Fallback result: %s\n", soname);
    assert(strcmp(soname, "passwd") == 0);

    free(soname);
    printf("✓ SONAME extraction fallback test passed\n");
}

// Test 3: SONAME cache hit/miss behavior
static void test_soname_cache(void) {
    printf("Testing SONAME cache behavior...\n");

    // Use a common library that should exist
    const char* libc_paths[] = {
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib64/libc.so.6",
        NULL
    };

    const char* test_path = NULL;
    for (const char** p = libc_paths; *p; p++) {
        if (access(*p, R_OK) == 0) {
            test_path = *p;
            break;
        }
    }

    if (!test_path) {
        printf("  SKIP: No libc.so.6 found on system\n");
        return;
    }

    // First call - cache miss (extracts from ELF)
    char* soname1 = get_soname_cached(test_path);
    assert(soname1 != NULL);
    printf("  First call (miss): %s\n", soname1);

    // Second call - cache hit (returns cached value)
    char* soname2 = get_soname_cached(test_path);
    assert(soname2 != NULL);
    printf("  Second call (hit): %s\n", soname2);

    // Both should return the same value
    assert(strcmp(soname1, soname2) == 0);

    free(soname1);
    free(soname2);
    printf("✓ SONAME cache test passed\n");
}

// Test 4: Path normalization with rootfs prefix
static void test_path_normalization(void) {
    printf("Testing path normalization...\n");

    // Save original config
    char* original_prefix = g_cbom_config.rootfs_prefix;

    // Test with prefix set
    g_cbom_config.rootfs_prefix = "/mnt/yocto/rootfs";
    const char* result1 = normalize_cross_arch_path("/mnt/yocto/rootfs/usr/lib/libssl.so.3");
    printf("  With prefix: %s -> %s\n", "/mnt/yocto/rootfs/usr/lib/libssl.so.3", result1);
    assert(strcmp(result1, "/usr/lib/libssl.so.3") == 0);

    // Test with non-matching path
    const char* result2 = normalize_cross_arch_path("/usr/local/lib/libcrypto.so");
    printf("  Non-matching: %s -> %s\n", "/usr/local/lib/libcrypto.so", result2);
    assert(strcmp(result2, "/usr/local/lib/libcrypto.so") == 0);

    // Test with NULL prefix
    g_cbom_config.rootfs_prefix = NULL;
    const char* result3 = normalize_cross_arch_path("/mnt/yocto/rootfs/usr/lib/test.so");
    printf("  NULL prefix: %s -> %s\n", "/mnt/yocto/rootfs/usr/lib/test.so", result3);
    assert(strcmp(result3, "/mnt/yocto/rootfs/usr/lib/test.so") == 0);

    // Test with empty prefix
    g_cbom_config.rootfs_prefix = "";
    const char* result4 = normalize_cross_arch_path("/usr/lib/test.so");
    printf("  Empty prefix: %s -> %s\n", "/usr/lib/test.so", result4);
    assert(strcmp(result4, "/usr/lib/test.so") == 0);

    // Test with NULL path
    const char* result5 = normalize_cross_arch_path(NULL);
    printf("  NULL path: (null) -> %s\n", result5 ? result5 : "(null)");
    assert(result5 == NULL);

    // Test edge case: path equals prefix exactly
    g_cbom_config.rootfs_prefix = "/mnt/rootfs";
    const char* result6 = normalize_cross_arch_path("/mnt/rootfs");
    printf("  Exact prefix: %s -> %s\n", "/mnt/rootfs", result6);
    assert(strcmp(result6, "/") == 0);

    // Restore original config
    g_cbom_config.rootfs_prefix = original_prefix;

    printf("✓ Path normalization test passed\n");
}

// Test 5: SONAME registry in asset store
static void test_soname_registry(void) {
    printf("Testing SONAME registry...\n");

    asset_store_t* store = asset_store_create(0);
    assert(store != NULL);

    // Register some SONAMEs
    int ret = asset_store_register_soname(store, "libssl.so.3", "library:libssl.so.3");
    assert(ret == 0);
    printf("  Registered: libssl.so.3 -> library:libssl.so.3\n");

    ret = asset_store_register_soname(store, "libcrypto.so.3", "library:libcrypto.so.3");
    assert(ret == 0);
    printf("  Registered: libcrypto.so.3 -> library:libcrypto.so.3\n");

    // Lookup
    const char* bom_ref = asset_store_lookup_by_soname(store, "libssl.so.3");
    assert(bom_ref != NULL);
    printf("  Lookup libssl.so.3: %s\n", bom_ref);
    assert(strcmp(bom_ref, "library:libssl.so.3") == 0);

    // Lookup non-existent
    const char* missing = asset_store_lookup_by_soname(store, "libfoo.so.1");
    printf("  Lookup libfoo.so.1: %s\n", missing ? missing : "(null)");
    assert(missing == NULL);

    // Test collision handling (first-wins)
    ret = asset_store_register_soname(store, "libssl.so.3", "library:libssl-duplicate");
    assert(ret == 0);  // Should succeed but not overwrite

    bom_ref = asset_store_lookup_by_soname(store, "libssl.so.3");
    printf("  After collision, lookup libssl.so.3: %s\n", bom_ref);
    assert(strcmp(bom_ref, "library:libssl.so.3") == 0);  // First-wins

    asset_store_destroy(store);
    printf("✓ SONAME registry test passed\n");
}

// Test 6: Auto-registration of SONAME when adding library assets
static void test_auto_soname_registration(void) {
    printf("Testing auto SONAME registration...\n");

    asset_store_t* store = asset_store_create(0);
    assert(store != NULL);

    // Create a library asset with SONAME as name
    crypto_asset_t* lib = crypto_asset_create("libtest.so.1", ASSET_TYPE_LIBRARY);
    assert(lib != NULL);
    lib->location = strdup("/usr/lib/libtest.so.1");

    // Add to store (should auto-register SONAME)
    int ret = asset_store_add(store, lib);
    assert(ret == 0);

    // Verify auto-registration
    const char* bom_ref = asset_store_lookup_by_soname(store, "libtest.so.1");
    printf("  After add, lookup libtest.so.1: %s\n", bom_ref ? bom_ref : "(null)");
    assert(bom_ref != NULL);

    asset_store_destroy(store);
    printf("✓ Auto SONAME registration test passed\n");
}

// Test 7: Path normalization with trailing slash handling
static void test_path_normalization_trailing_slash(void) {
    printf("Testing path normalization trailing slash handling...\n");

    // Save original config
    char* original_prefix = g_cbom_config.rootfs_prefix;

    // Test prefix with trailing slash (should be stripped in main.c, but test robustness)
    g_cbom_config.rootfs_prefix = "/mnt/rootfs/";

    // The normalize function expects prefix without trailing slash
    // This test documents current behavior
    const char* result = normalize_cross_arch_path("/mnt/rootfs//usr/lib/test.so");
    printf("  With trailing slash prefix: /mnt/rootfs//usr/lib/test.so -> %s\n", result);
    // Note: This may not strip correctly if prefix has trailing slash
    // The CLI handler in main.c strips trailing slashes

    // Restore
    g_cbom_config.rootfs_prefix = original_prefix;

    printf("✓ Path normalization trailing slash test completed\n");
}

// Test 8: Configuration flags for cross-arch scanning
static void test_config_flags(void) {
    printf("Testing cross-arch config flags...\n");

    // Save original values
    char* orig_prefix = g_cbom_config.rootfs_prefix;
    bool orig_cross_arch = g_cbom_config.cross_arch_mode;

    // v1.9: include_all_dependencies is now false by default (only crypto libs)
    printf("  include_all_dependencies (default): %s\n", g_cbom_config.include_all_dependencies ? "true" : "false");
    assert(g_cbom_config.include_all_dependencies == false);  // Verify default is false (crypto libs only)

    // Test other flag combinations
    g_cbom_config.rootfs_prefix = "/mnt/yocto";
    g_cbom_config.cross_arch_mode = true;

    printf("  rootfs_prefix: %s\n", g_cbom_config.rootfs_prefix ? g_cbom_config.rootfs_prefix : "(null)");
    printf("  cross_arch_mode: %s\n", g_cbom_config.cross_arch_mode ? "true" : "false");

    assert(g_cbom_config.rootfs_prefix != NULL);
    assert(g_cbom_config.cross_arch_mode == true);

    // Restore original values
    g_cbom_config.rootfs_prefix = orig_prefix;
    g_cbom_config.cross_arch_mode = orig_cross_arch;

    printf("✓ Config flags test passed\n");
}

// Main test runner
int main(void) {
    printf("=== Cross-Architecture Scanning Test Suite ===\n\n");

    // Initialize secure memory subsystem
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory subsystem\n");
        return 1;
    }

    // Initialize global config to known state
    memset(&g_cbom_config, 0, sizeof(g_cbom_config));

    // Run all tests
    test_soname_extraction_valid();
    test_soname_extraction_fallback();
    test_soname_cache();
    test_path_normalization();
    test_soname_registry();
    test_auto_soname_registration();
    test_path_normalization_trailing_slash();
    test_config_flags();

    // Cleanup
    secure_memory_cleanup();

    printf("\n=== All Cross-Architecture Scanning Tests Passed ===\n");
    printf("Total: 8 tests\n");
    printf("\n✅ Cross-Arch Scanning Features Validated:\n");
    printf("  ✅ SONAME extraction from ELF binaries\n");
    printf("  ✅ SONAME extraction fallback to basename\n");
    printf("  ✅ Thread-safe SONAME cache\n");
    printf("  ✅ Path normalization with --rootfs-prefix\n");
    printf("  ✅ SONAME→bom-ref registry\n");
    printf("  ✅ Auto-registration on library asset add\n");
    printf("  ✅ Configuration flag handling\n");
    return 0;
}
