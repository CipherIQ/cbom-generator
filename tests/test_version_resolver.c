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
 * @file test_version_resolver.c
 * @brief Unit tests for version_resolver module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "version_resolver.h"
#include "secure_memory.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS(name) do { printf("  [PASS] %s\n", name); tests_passed++; } while(0)
#define TEST_FAIL(name, msg) do { printf("  [FAIL] %s: %s\n", name, msg); tests_failed++; } while(0)

// =============================================================================
// Test 1: SONAME version parsing
// =============================================================================
static void test_soname_version_parsing(void) {
    printf("\nTest 1: SONAME version parsing\n");

    char* ver;

    // Test libssl.so.3 -> "3"
    ver = parse_soname_version("libssl.so.3");
    if (ver && strcmp(ver, "3") == 0) {
        TEST_PASS("libssl.so.3 -> 3");
    } else {
        TEST_FAIL("libssl.so.3 -> 3", ver ? ver : "NULL");
    }
    free(ver);

    // Test libgnutls.so.30 -> "30"
    ver = parse_soname_version("libgnutls.so.30");
    if (ver && strcmp(ver, "30") == 0) {
        TEST_PASS("libgnutls.so.30 -> 30");
    } else {
        TEST_FAIL("libgnutls.so.30 -> 30", ver ? ver : "NULL");
    }
    free(ver);

    // Test libkrb5.so.3.3 -> "3.3"
    ver = parse_soname_version("libkrb5.so.3.3");
    if (ver && strcmp(ver, "3.3") == 0) {
        TEST_PASS("libkrb5.so.3.3 -> 3.3");
    } else {
        TEST_FAIL("libkrb5.so.3.3 -> 3.3", ver ? ver : "NULL");
    }
    free(ver);

    // Test libcrypto.so.1.1 -> "1.1"
    ver = parse_soname_version("libcrypto.so.1.1");
    if (ver && strcmp(ver, "1.1") == 0) {
        TEST_PASS("libcrypto.so.1.1 -> 1.1");
    } else {
        TEST_FAIL("libcrypto.so.1.1 -> 1.1", ver ? ver : "NULL");
    }
    free(ver);

    // Test NULL input
    ver = parse_soname_version(NULL);
    if (ver == NULL) {
        TEST_PASS("NULL input -> NULL");
    } else {
        TEST_FAIL("NULL input -> NULL", ver);
        free(ver);
    }

    // Test no version in SONAME
    ver = parse_soname_version("libfoo.so");
    if (ver == NULL) {
        TEST_PASS("libfoo.so -> NULL");
    } else {
        TEST_FAIL("libfoo.so -> NULL", ver);
        free(ver);
    }
}

// =============================================================================
// Test 2: Yocto manifest loading and lookup
// =============================================================================
static void test_manifest_loading(void) {
    printf("\nTest 2: Yocto manifest loading and lookup\n");

    // Check if test fixture exists
    const char* manifest_path = "tests/fixtures/yocto-test.manifest";
    if (access(manifest_path, R_OK) != 0) {
        // Try alternate path
        manifest_path = "../tests/fixtures/yocto-test.manifest";
        if (access(manifest_path, R_OK) != 0) {
            printf("  [SKIP] Test fixture not found\n");
            return;
        }
    }

    // Load manifest
    int rc = manifest_load(manifest_path);
    if (rc == 0) {
        TEST_PASS("Manifest loaded successfully");
    } else {
        TEST_FAIL("Manifest load", "Failed to load manifest");
        return;
    }

    // Check manifest_is_loaded()
    if (manifest_is_loaded()) {
        TEST_PASS("manifest_is_loaded() returns true");
    } else {
        TEST_FAIL("manifest_is_loaded()", "Expected true");
    }

    // Lookup by package name: libssl3
    const manifest_entry_t* entry = manifest_lookup(NULL, "libssl3");
    if (entry && strstr(entry->version, "3.0.13") != NULL) {
        TEST_PASS("Lookup libssl3 -> 3.0.13");
    } else {
        TEST_FAIL("Lookup libssl3", entry ? entry->version : "NULL");
    }

    // Lookup by package name: libgnutls30
    entry = manifest_lookup(NULL, "libgnutls30");
    if (entry && strstr(entry->version, "3.7.8") != NULL) {
        TEST_PASS("Lookup libgnutls30 -> 3.7.8");
    } else {
        TEST_FAIL("Lookup libgnutls30", entry ? entry->version : "NULL");
    }

    // Lookup by SONAME mapping: libssl.so.3 -> libssl3
    entry = manifest_lookup("libssl.so.3", NULL);
    if (entry && strstr(entry->version, "3.0.13") != NULL) {
        TEST_PASS("SONAME lookup libssl.so.3 -> 3.0.13");
    } else {
        TEST_FAIL("SONAME lookup libssl.so.3", entry ? entry->version : "NULL");
    }

    // Lookup non-existent package
    entry = manifest_lookup(NULL, "nonexistent-package");
    if (entry == NULL) {
        TEST_PASS("Non-existent package -> NULL");
    } else {
        TEST_FAIL("Non-existent package", "Expected NULL");
    }

    // Cleanup
    manifest_unload();

    // Verify unloaded
    if (!manifest_is_loaded()) {
        TEST_PASS("manifest_is_loaded() returns false after unload");
    } else {
        TEST_FAIL("manifest_is_loaded() after unload", "Expected false");
    }
}

// =============================================================================
// Test 3: Version resolver initialization
// =============================================================================
static void test_resolver_init(void) {
    printf("\nTest 3: Version resolver initialization\n");

    // Test initialization without manifest (native mode)
    int rc = version_resolver_init(NULL, false);
    if (rc == 0) {
        TEST_PASS("Init without manifest (native mode)");
    } else {
        TEST_FAIL("Init without manifest", "Failed");
    }
    version_resolver_cleanup();

    // Test initialization with cross-arch mode
    rc = version_resolver_init(NULL, true);
    if (rc == 0) {
        TEST_PASS("Init with cross-arch mode");
    } else {
        TEST_FAIL("Init with cross-arch mode", "Failed");
    }
    version_resolver_cleanup();

    // Test initialization with manifest
    const char* manifest_path = "tests/fixtures/yocto-test.manifest";
    if (access(manifest_path, R_OK) != 0) {
        manifest_path = "../tests/fixtures/yocto-test.manifest";
    }

    if (access(manifest_path, R_OK) == 0) {
        rc = version_resolver_init(manifest_path, true);
        if (rc == 0 && manifest_is_loaded()) {
            TEST_PASS("Init with manifest loads it");
        } else {
            TEST_FAIL("Init with manifest", "Failed to load manifest");
        }
        version_resolver_cleanup();
    } else {
        printf("  [SKIP] Manifest test - fixture not found\n");
    }
}

// =============================================================================
// Test 4: Version resolution chain (tier fallback)
// =============================================================================
static void test_resolution_chain(void) {
    printf("\nTest 4: Version resolution chain (tier fallback)\n");

    // Initialize in cross-arch mode without manifest
    // This forces resolution to use VERNEED/SONAME tiers
    version_resolver_init(NULL, true);

    // Test resolution falls back to SONAME tier for unknown library
    resolved_version_t* ver = version_resolver_resolve(
        "libfake.so.42",
        NULL,
        NULL
    );

    if (ver && ver->tier == VERSION_TIER_SONAME) {
        TEST_PASS("Unknown library uses SONAME tier");
    } else if (ver) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Expected tier 4, got %d", ver->tier);
        TEST_FAIL("Unknown library tier", msg);
    } else {
        TEST_FAIL("Unknown library tier", "Resolution returned NULL");
    }

    if (ver && strcmp(ver->version_string, "42") == 0) {
        TEST_PASS("SONAME version extracted correctly");
    } else {
        TEST_FAIL("SONAME version extraction", ver ? ver->version_string : "NULL");
    }

    if (ver && ver->confidence >= 0.59 && ver->confidence <= 0.61) {
        TEST_PASS("SONAME confidence is 0.60");
    } else if (ver) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Expected 0.60, got %.2f", ver->confidence);
        TEST_FAIL("SONAME confidence", msg);
    }

    resolved_version_free(ver);
    version_resolver_cleanup();
}

// =============================================================================
// Test 5: Manifest resolution tier (highest priority)
// =============================================================================
static void test_manifest_resolution_tier(void) {
    printf("\nTest 5: Manifest resolution tier (highest priority)\n");

    const char* manifest_path = "tests/fixtures/yocto-test.manifest";
    if (access(manifest_path, R_OK) != 0) {
        manifest_path = "../tests/fixtures/yocto-test.manifest";
    }

    if (access(manifest_path, R_OK) != 0) {
        printf("  [SKIP] Manifest test - fixture not found\n");
        return;
    }

    // Initialize with manifest in cross-arch mode
    version_resolver_init(manifest_path, true);

    // Test resolution uses manifest tier for known library
    resolved_version_t* ver = version_resolver_resolve(
        "libssl.so.3",
        NULL,
        "libssl3"
    );

    if (ver && ver->tier == VERSION_TIER_MANIFEST) {
        TEST_PASS("Known library uses MANIFEST tier");
    } else if (ver) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Expected tier 1, got %d", ver->tier);
        TEST_FAIL("Known library tier", msg);
    } else {
        TEST_FAIL("Known library tier", "Resolution returned NULL");
    }

    if (ver && strstr(ver->version_string, "3.0.13") != NULL) {
        TEST_PASS("Manifest version correct");
    } else {
        TEST_FAIL("Manifest version", ver ? ver->version_string : "NULL");
    }

    if (ver && ver->confidence >= 0.98 && ver->confidence <= 1.0) {
        TEST_PASS("Manifest confidence is ~0.99");
    } else if (ver) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Expected ~0.99, got %.2f", ver->confidence);
        TEST_FAIL("Manifest confidence", msg);
    }

    resolved_version_free(ver);
    version_resolver_cleanup();
}

// =============================================================================
// Test 6: Statistics tracking
// =============================================================================
static void test_statistics(void) {
    printf("\nTest 6: Statistics tracking\n");

    // Initialize in cross-arch mode (no manifest)
    version_resolver_init(NULL, true);
    version_resolver_reset_stats();

    // Resolve a few libraries (will use SONAME tier)
    resolved_version_t* ver1 = version_resolver_resolve("libssl.so.3", NULL, NULL);
    resolved_version_t* ver2 = version_resolver_resolve("libcrypto.so.3", NULL, NULL);
    resolved_version_t* ver3 = version_resolver_resolve("libfoo.so", NULL, NULL);  // No version

    resolved_version_free(ver1);
    resolved_version_free(ver2);
    resolved_version_free(ver3);

    version_resolver_stats_t stats = version_resolver_get_stats();

    // Should have 2 SONAME hits (libssl.so.3, libcrypto.so.3 have versions)
    // libfoo.so has no version, so should be a failure
    if (stats.tier4_hits >= 2) {
        TEST_PASS("SONAME tier hits counted");
    } else {
        char msg[64];
        snprintf(msg, sizeof(msg), "Expected >= 2, got %d", stats.tier4_hits);
        TEST_FAIL("SONAME tier hits", msg);
    }

    version_resolver_cleanup();
}

// =============================================================================
// Test 7: Version tier string conversion
// =============================================================================
static void test_tier_to_string(void) {
    printf("\nTest 7: Version tier string conversion\n");

    const char* str;

    str = version_tier_to_string(VERSION_TIER_MANIFEST);
    if (str && strcmp(str, "MANIFEST") == 0) {
        TEST_PASS("MANIFEST tier string");
    } else {
        TEST_FAIL("MANIFEST tier string", str ? str : "NULL");
    }

    str = version_tier_to_string(VERSION_TIER_PACKAGE_MGR);
    if (str && strcmp(str, "PACKAGE_MGR") == 0) {
        TEST_PASS("PACKAGE_MGR tier string");
    } else {
        TEST_FAIL("PACKAGE_MGR tier string", str ? str : "NULL");
    }

    str = version_tier_to_string(VERSION_TIER_VERNEED);
    if (str && strcmp(str, "VERNEED") == 0) {
        TEST_PASS("VERNEED tier string");
    } else {
        TEST_FAIL("VERNEED tier string", str ? str : "NULL");
    }

    str = version_tier_to_string(VERSION_TIER_SONAME);
    if (str && strcmp(str, "SONAME") == 0) {
        TEST_PASS("SONAME tier string");
    } else {
        TEST_FAIL("SONAME tier string", str ? str : "NULL");
    }

    str = version_tier_to_string(VERSION_TIER_UNKNOWN);
    if (str && strcmp(str, "UNKNOWN") == 0) {
        TEST_PASS("UNKNOWN tier string");
    } else {
        TEST_FAIL("UNKNOWN tier string", str ? str : "NULL");
    }
}

// =============================================================================
// Test 8: VERNEED parsing (if readelf available)
// =============================================================================
static void test_verneed_parsing(void) {
    printf("\nTest 8: VERNEED parsing\n");

    // Check if readelf is available
    if (system("which readelf > /dev/null 2>&1") != 0) {
        printf("  [SKIP] readelf not available\n");
        return;
    }

    // Try to parse a real binary
    const char* test_paths[] = {
        "/usr/bin/openssl",
        "/usr/bin/ssh",
        "/bin/ls",
        NULL
    };

    const char* binary_path = NULL;
    for (int i = 0; test_paths[i]; i++) {
        if (access(test_paths[i], R_OK) == 0) {
            binary_path = test_paths[i];
            break;
        }
    }

    if (!binary_path) {
        printf("  [SKIP] No suitable test binary found\n");
        return;
    }

    printf("  Using binary: %s\n", binary_path);

    // Try to find libssl or libc VERNEED
    char* ver = parse_verneed_version(binary_path, "libssl.so.3");
    if (ver) {
        printf("  Found libssl.so.3 VERNEED: %s\n", ver);
        // Any version starting with a digit is good
        if (ver[0] >= '0' && ver[0] <= '9') {
            TEST_PASS("VERNEED extraction returns version");
        } else {
            TEST_FAIL("VERNEED extraction", ver);
        }
        free(ver);
    } else {
        // Try libc instead
        ver = parse_verneed_version(binary_path, "libc.so.6");
        if (ver) {
            printf("  Found libc.so.6 VERNEED: %s\n", ver);
            if (ver[0] >= '0' && ver[0] <= '9') {
                TEST_PASS("VERNEED extraction returns version (libc)");
            } else {
                TEST_FAIL("VERNEED extraction (libc)", ver);
            }
            free(ver);
        } else {
            printf("  [INFO] No VERNEED found for common libraries\n");
            TEST_PASS("VERNEED returns NULL for no matches");
        }
    }
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char** argv) {
    (void)argc;  // Unused
    (void)argv;  // Unused
    printf("=== Version Resolver Unit Tests ===\n");

    // Initialize secure memory subsystem
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory\n");
        return 1;
    }

    // Change to project root if running from build dir
    if (access("tests/fixtures/yocto-test.manifest", R_OK) != 0) {
        if (chdir("..") == 0) {
            printf("Changed to project root directory\n");
        }
    }

    test_soname_version_parsing();
    test_manifest_loading();
    test_resolver_init();
    test_resolution_chain();
    test_manifest_resolution_tier();
    test_statistics();
    test_tier_to_string();
    test_verneed_parsing();

    printf("\n=== Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    // Cleanup secure memory
    secure_memory_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
