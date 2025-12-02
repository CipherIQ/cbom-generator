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
 * @file test_kernel_crypto_detector.c
 * @brief Unit tests for kernel crypto detector (v1.8.3)
 *
 * Tests detection of:
 * - Linux Kernel Crypto API (AF_ALG sockets)
 * - Statically linked crypto (Go, Rust)
 * - Embedded crypto symbols (hybrid nm + mmap approach)
 */

#include "detection/kernel_crypto_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

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

/**
 * Helper: Create a test binary with specific content embedded.
 */
static bool create_test_binary(const char* path, const char* content) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;

    // Write some ELF-like header bytes (fake but enough for mmap test)
    unsigned char header[] = {0x7f, 'E', 'L', 'F', 0, 0, 0, 0};
    fwrite(header, 1, sizeof(header), f);

    // Write some padding
    for (int i = 0; i < 100; i++) {
        fputc(0, f);
    }

    // Write the test content
    if (content) {
        fwrite(content, 1, strlen(content), f);
    }

    // Write more padding
    for (int i = 0; i < 100; i++) {
        fputc(0, f);
    }

    fclose(f);
    chmod(path, 0755);
    return true;
}

// Test 1: detect_kernel_crypto_usage with NULL path
static bool test_kernel_crypto_null() {
    bool result = detect_kernel_crypto_usage(NULL, NULL);
    return result == false;
}

// Test 2: detect_kernel_crypto_usage with non-existent file
static bool test_kernel_crypto_nonexistent() {
    bool result = detect_kernel_crypto_usage("/tmp/nonexistent_file_12345", NULL);
    return result == false;
}

// Test 3: detect_kernel_crypto_usage with AF_ALG marker
static bool test_kernel_crypto_af_alg() {
    const char* path = "/tmp/test_kc_afalg.bin";
    create_test_binary(path, "AF_ALG socket test algif_hash sha256");

    kernel_crypto_info_t info = {0};
    bool result = detect_kernel_crypto_usage(path, &info);

    printf("  Found: uses_af_alg=%d, algo_count=%zu\n", info.uses_af_alg, info.algorithm_count);

    kernel_crypto_info_free(&info);
    unlink(path);

    return result == true;
}

// Test 4: detect_kernel_crypto_usage with no crypto markers
static bool test_kernel_crypto_no_markers() {
    const char* path = "/tmp/test_kc_nocrypto.bin";
    create_test_binary(path, "just some regular text with no crypto markers");

    bool result = detect_kernel_crypto_usage(path, NULL);

    unlink(path);
    return result == false;
}

// Test 5: detect_static_crypto with NULL path
static bool test_static_crypto_null() {
    bool result = detect_static_crypto(NULL, NULL);
    return result == false;
}

// Test 6: detect_static_crypto with Go markers
static bool test_static_crypto_go() {
    const char* path = "/tmp/test_sc_go.bin";
    create_test_binary(path, "go binary with crypto/tls and crypto/aes packages");

    static_crypto_info_t info = {0};
    bool result = detect_static_crypto(path, &info);

    printf("  Found: has_static=%d, lang=%s, pkg_count=%zu\n",
           info.has_static_crypto, info.language ? info.language : "null", info.package_count);

    bool lang_ok = info.language && strcmp(info.language, "Go") == 0;

    static_crypto_info_free(&info);
    unlink(path);

    return result == true && lang_ok;
}

// Test 7: detect_static_crypto with Rust markers
static bool test_static_crypto_rust() {
    const char* path = "/tmp/test_sc_rust.bin";
    create_test_binary(path, "rust binary with ring:: and rustls:: crates");

    static_crypto_info_t info = {0};
    bool result = detect_static_crypto(path, &info);

    printf("  Found: has_static=%d, lang=%s, pkg_count=%zu\n",
           info.has_static_crypto, info.language ? info.language : "null", info.package_count);

    bool lang_ok = info.language && strcmp(info.language, "Rust") == 0;

    static_crypto_info_free(&info);
    unlink(path);

    return result == true && lang_ok;
}

// Test 8: detect_static_crypto with no crypto markers
static bool test_static_crypto_no_markers() {
    const char* path = "/tmp/test_sc_nocrypto.bin";
    create_test_binary(path, "just some regular binary content");

    bool result = detect_static_crypto(path, NULL);

    unlink(path);
    return result == false;
}

// Test 9: detect_embedded_crypto_symbols with NULL path
static bool test_embedded_symbols_null() {
    bool result = detect_embedded_crypto_symbols(NULL, NULL);
    return result == false;
}

// Test 10: detect_embedded_crypto_symbols with crypto function names
static bool test_embedded_symbols_found() {
    const char* path = "/tmp/test_es_crypto.bin";
    // Need at least 2 symbols to pass the threshold
    create_test_binary(path, "crypto symbols: AES_encrypt and SHA256_Init and AES_decrypt");

    embedded_crypto_info_t info = {0};
    bool result = detect_embedded_crypto_symbols(path, &info);

    printf("  Found: has_embedded=%d, sym_count=%zu\n", info.has_embedded_symbols, info.symbol_count);

    embedded_crypto_info_free(&info);
    unlink(path);

    return result == true;
}

// Test 11: detect_embedded_crypto_symbols with single symbol (should fail threshold)
static bool test_embedded_symbols_single() {
    const char* path = "/tmp/test_es_single.bin";
    // Only 1 symbol - should not pass threshold of 2
    create_test_binary(path, "only one symbol: AES_encrypt but nothing else");

    bool result = detect_embedded_crypto_symbols(path, NULL);

    unlink(path);
    return result == false;  // Should fail - below threshold
}

// Test 12: detect_embedded_crypto_symbols with no crypto symbols
static bool test_embedded_symbols_none() {
    const char* path = "/tmp/test_es_none.bin";
    create_test_binary(path, "no crypto symbols here, just normal code");

    bool result = detect_embedded_crypto_symbols(path, NULL);

    unlink(path);
    return result == false;
}

// Test 13: kernel_crypto_info_free with NULL (should not crash)
static bool test_kernel_info_free_null() {
    kernel_crypto_info_free(NULL);
    return true;  // If we get here, it didn't crash
}

// Test 14: static_crypto_info_free with NULL (should not crash)
static bool test_static_info_free_null() {
    static_crypto_info_free(NULL);
    return true;  // If we get here, it didn't crash
}

// Test 15: embedded_crypto_info_free with NULL (should not crash)
static bool test_embedded_info_free_null() {
    embedded_crypto_info_free(NULL);
    return true;  // If we get here, it didn't crash
}

// Test 16: Real binary test - check cryptsetup if available (skip if not found)
static bool test_real_binary_cryptsetup() {
    const char* cryptsetup_path = "/usr/sbin/cryptsetup";

    if (access(cryptsetup_path, R_OK) != 0) {
        printf("  [SKIP] cryptsetup not found at %s\n", cryptsetup_path);
        return true;  // Skip test
    }

    kernel_crypto_info_t info = {0};
    (void)detect_kernel_crypto_usage(cryptsetup_path, &info);

    printf("  cryptsetup: uses_af_alg=%d, algo_count=%zu\n", info.uses_af_alg, info.algorithm_count);
    if (info.algorithm_count > 0) {
        printf("  Algorithms: ");
        for (size_t i = 0; i < info.algorithm_count && i < 5; i++) {
            printf("%s ", info.algorithms[i]);
        }
        printf("\n");
    }

    kernel_crypto_info_free(&info);

    // cryptsetup typically uses kernel crypto - but we accept either result
    return true;  // Just checking it doesn't crash
}

// Test 17: Real binary test - check ssh if available (dynamic linked, should fail)
static bool test_real_binary_ssh() {
    const char* ssh_path = "/usr/bin/ssh";

    if (access(ssh_path, R_OK) != 0) {
        printf("  [SKIP] ssh not found at %s\n", ssh_path);
        return true;  // Skip test
    }

    // ssh uses dynamic OpenSSL - should NOT match static crypto
    static_crypto_info_t info = {0};
    bool result = detect_static_crypto(ssh_path, &info);

    printf("  ssh static crypto: has_static=%d\n", info.has_static_crypto);

    static_crypto_info_free(&info);

    // ssh is dynamically linked, so static crypto should be false
    return result == false;
}

// Test 18: Hybrid nm detection - test with openssl binary (if available)
static bool test_hybrid_nm_openssl() {
    const char* openssl_path = "/usr/bin/openssl";

    if (access(openssl_path, R_OK) != 0) {
        printf("  [SKIP] openssl not found at %s\n", openssl_path);
        return true;  // Skip test
    }

    embedded_crypto_info_t info = {0};
    (void)detect_embedded_crypto_symbols(openssl_path, &info);

    printf("  openssl: has_embedded=%d, sym_count=%zu\n",
           info.has_embedded_symbols, info.symbol_count);

    if (info.symbol_count > 0) {
        printf("  Symbols found: ");
        for (size_t i = 0; i < info.symbol_count && i < 5; i++) {
            printf("%s ", info.symbols[i]);
        }
        printf("\n");
    }

    embedded_crypto_info_free(&info);

    // openssl binary should have crypto symbols
    // (either via nm if unstripped, or mmap if stripped)
    return true;  // Just checking it doesn't crash; result depends on system
}

// Test 19: Hybrid detection fallback - stripped binary simulation
// This tests that mmap fallback works when nm doesn't find symbols
static bool test_hybrid_mmap_fallback() {
    const char* path = "/tmp/test_hybrid_stripped.bin";
    // Create test binary without real symbol table, but with embedded strings
    // The fake ELF header won't have .symtab, so it will use mmap fallback
    create_test_binary(path, "embedded: AES_encrypt SHA256_Init AES_decrypt SHA256_Final");

    embedded_crypto_info_t info = {0};
    bool result = detect_embedded_crypto_symbols(path, &info);

    printf("  stripped sim: has_embedded=%d, sym_count=%zu\n",
           info.has_embedded_symbols, info.symbol_count);

    embedded_crypto_info_free(&info);
    unlink(path);

    // Should detect via mmap fallback (fake binary has no .symtab section)
    return result == true;
}

int main(void) {
    printf("=== Kernel Crypto Detector Unit Tests (v1.8.3) ===\n\n");

    // Null/error handling tests
    TEST(kernel_crypto_null);
    TEST(kernel_crypto_nonexistent);
    TEST(static_crypto_null);
    TEST(embedded_symbols_null);

    // Functional tests with test binaries
    TEST(kernel_crypto_af_alg);
    TEST(kernel_crypto_no_markers);
    TEST(static_crypto_go);
    TEST(static_crypto_rust);
    TEST(static_crypto_no_markers);
    TEST(embedded_symbols_found);
    TEST(embedded_symbols_single);
    TEST(embedded_symbols_none);

    // Free function safety tests
    TEST(kernel_info_free_null);
    TEST(static_info_free_null);
    TEST(embedded_info_free_null);

    // Real binary tests (may be skipped if binaries not found)
    TEST(real_binary_cryptsetup);
    TEST(real_binary_ssh);

    // Hybrid nm+mmap detection tests (v1.8.3)
    TEST(hybrid_nm_openssl);
    TEST(hybrid_mmap_fallback);

    printf("=== Test Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
