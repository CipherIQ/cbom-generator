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
#include <assert.h>
#include <unistd.h>

#include "crypto_registry.h"

// Test 1: NULL path is no-op
static void test_null_path_noop(void) {
    printf("Test 1: NULL path is no-op... ");

    char errbuf[256];
    int result = crypto_registry_load_from_file(NULL, errbuf, sizeof(errbuf));
    assert(result == 0);

    printf("PASS\n");
}

// Test 2: Built-in registry unchanged
static void test_builtin_registry_unchanged(void) {
    printf("Test 2: Built-in registry unchanged... ");

    // Test built-in OpenSSL lookup
    const crypto_library_info_t *lib = find_crypto_lib_by_soname("libssl.so.3");
    assert(lib != NULL);
    assert(strcmp(lib->id, "openssl") == 0);

    // Test built-in package lookup
    lib = find_crypto_lib_by_pkg("libssl3");
    assert(lib != NULL);
    assert(strcmp(lib->id, "openssl") == 0);

    // Test built-in embedded app lookup
    const embedded_crypto_app_info_t *app = find_embedded_crypto_by_binary("ssh", NULL);
    assert(app != NULL);
    assert(strcmp(app->provider_id, "openssh_internal") == 0);

    printf("PASS\n");
}

// Test 3: Load YAML with custom library
static void test_yaml_custom_library(void) {
    printf("Test 3: Load YAML with custom library... ");

    // Create temporary YAML file
    FILE *f = fopen("/tmp/test-crypto-registry.yaml", "w");
    assert(f != NULL);

    fprintf(f,
        "version: 1\n"
        "crypto_libraries:\n"
        "  - id: yocto_openssl\n"
        "    pkg_patterns:\n"
        "      - openssl-yocto\n"
        "    soname_patterns:\n"
        "      - libyocto_ssl.so\n"
        "    algorithms:\n"
        "      - RSA\n"
        "      - AES\n"
    );
    fclose(f);

    // Load registry
    char errbuf[256];
    int result = crypto_registry_load_from_file("/tmp/test-crypto-registry.yaml", errbuf, sizeof(errbuf));
    assert(result == 0);

    // Test lookup
    const crypto_library_info_t *lib = find_crypto_lib_by_soname("libyocto_ssl.so.1");
    assert(lib != NULL);
    assert(strcmp(lib->id, "yocto_openssl") == 0);

    // Cleanup
    unlink("/tmp/test-crypto-registry.yaml");
    crypto_registry_cleanup();

    printf("PASS\n");
}

// Test 4: Invalid YAML returns error
static void test_invalid_yaml_error(void) {
    printf("Test 4: Invalid YAML returns error... ");

    // Create invalid YAML file
    FILE *f = fopen("/tmp/test-invalid.yaml", "w");
    assert(f != NULL);
    fprintf(f, "invalid: [unclosed\n");
    fclose(f);

    char errbuf[256];
    int result = crypto_registry_load_from_file("/tmp/test-invalid.yaml", errbuf, sizeof(errbuf));
    assert(result != 0);
    assert(strlen(errbuf) > 0);

    unlink("/tmp/test-invalid.yaml");

    printf("PASS\n");
}

// Test 5: Embedded apps loading
static void test_embedded_apps_yaml(void) {
    printf("Test 5: Load embedded apps from YAML... ");

    FILE *f = fopen("/tmp/test-embedded.yaml", "w");
    assert(f != NULL);
    fprintf(f,
        "version: 1\n"
        "embedded_crypto_apps:\n"
        "  - provider_id: busybox_crypto\n"
        "    binary_names:\n"
        "      - busybox\n"
        "    algorithms:\n"
        "      - AES\n"
        "      - SHA-256\n"
    );
    fclose(f);

    char errbuf[256];
    int result = crypto_registry_load_from_file("/tmp/test-embedded.yaml", errbuf, sizeof(errbuf));
    assert(result == 0);

    const embedded_crypto_app_info_t *app = find_embedded_crypto_by_binary("busybox", NULL);
    assert(app != NULL);
    assert(strcmp(app->provider_id, "busybox_crypto") == 0);

    unlink("/tmp/test-embedded.yaml");
    crypto_registry_cleanup();

    printf("PASS\n");
}

int run_crypto_registry_tests(void) {
    printf("Running crypto registry YAML tests...\n\n");

    test_null_path_noop();
    test_builtin_registry_unchanged();
    test_yaml_custom_library();
    test_invalid_yaml_error();
    test_embedded_apps_yaml();

    printf("\nAll crypto registry tests passed!\n");
    return 0;
}

// Main for standalone execution
#ifndef TEST_RUNNER_INTEGRATION
int main(void) {
    return run_crypto_registry_tests();
}
#endif
