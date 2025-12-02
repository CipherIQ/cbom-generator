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

#include "asset_store.h"
#include "secure_memory.h"

// Simple test framework
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_test_##name(void) { \
        printf("Running test: %s... ", #name); \
        tests_run++; \
        test_##name(); \
        tests_passed++; \
        printf("PASSED\n"); \
    } \
    static void test_##name(void)

#define ASSERT(condition) \
    do { \
        if (!(condition)) { \
            printf("FAILED\n  Assertion failed: %s\n  File: %s, Line: %d\n", \
                   #condition, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while(0)

TEST(secure_memory_basic) {
    // Test secure memory allocation
    void *ptr = secure_alloc(1024);
    ASSERT(ptr != NULL);
    
    // Test secure zero
    memset(ptr, 0xFF, 1024);
    secure_zero(ptr, 1024);
    
    // Verify memory is zeroed
    unsigned char *bytes = (unsigned char*)ptr;
    for (int i = 0; i < 1024; i++) {
        ASSERT(bytes[i] == 0);
    }
    
    secure_free(ptr, 1024);
}

TEST(asset_store_creation) {
    asset_store_t *store = asset_store_create(64);
    ASSERT(store != NULL);
    ASSERT(store->bucket_count == 64);
    ASSERT(store->asset_count == 0);
    ASSERT(store->deterministic_mode == true);
    
    asset_store_destroy(store);
}

TEST(crypto_asset_creation) {
    crypto_asset_t *asset = crypto_asset_create("test-cert", ASSET_TYPE_CERTIFICATE);
    ASSERT(asset != NULL);
    ASSERT(strcmp(asset->name, "test-cert") == 0);
    ASSERT(asset->type == ASSET_TYPE_CERTIFICATE);
    ASSERT(asset->id != NULL);
    ASSERT(strlen(asset->id) == 64); // SHA-256 hex string
    
    crypto_asset_destroy(asset);
}

TEST(asset_store_add_find) {
    asset_store_t *store = asset_store_create(64);
    ASSERT(store != NULL);
    
    crypto_asset_t *asset = crypto_asset_create("test-key", ASSET_TYPE_KEY);
    ASSERT(asset != NULL);
    
    // Add asset to store
    int result = asset_store_add(store, asset);
    ASSERT(result == 0);
    ASSERT(store->asset_count == 1);
    
    // Find asset by ID
    crypto_asset_t *found = asset_store_find(store, asset->id);
    ASSERT(found != NULL);
    ASSERT(found == asset);
    ASSERT(strcmp(found->name, "test-key") == 0);
    
    // Try to add same asset again
    crypto_asset_t *duplicate = crypto_asset_create("test-key", ASSET_TYPE_KEY);
    ASSERT(duplicate != NULL);
    
    // Should detect duplicate (same content-addressed ID)
    result = asset_store_add(store, duplicate);
    ASSERT(result == 1); // Duplicate detected
    ASSERT(store->asset_count == 1); // Count unchanged
    
    crypto_asset_destroy(duplicate);
    asset_store_destroy(store);
}

TEST(deterministic_sorting) {
    asset_store_t *store = asset_store_create(64);
    ASSERT(store != NULL);
    
    // Create assets in random order
    crypto_asset_t *cert = crypto_asset_create("certificate", ASSET_TYPE_CERTIFICATE);
    crypto_asset_t *key = crypto_asset_create("private-key", ASSET_TYPE_KEY);
    crypto_asset_t *algo = crypto_asset_create("aes-256", ASSET_TYPE_ALGORITHM);
    
    ASSERT(cert != NULL && key != NULL && algo != NULL);
    
    // Add in random order
    asset_store_add(store, key);
    asset_store_add(store, cert);
    asset_store_add(store, algo);
    
    // Get sorted assets
    size_t count;
    crypto_asset_t **sorted = asset_store_get_sorted(store, NULL, &count);
    ASSERT(sorted != NULL);
    ASSERT(count == 3);
    
    // Verify deterministic order (by type, then ID, then name)
    ASSERT(sorted[0]->type <= sorted[1]->type);
    ASSERT(sorted[1]->type <= sorted[2]->type);
    
    free(sorted);
    asset_store_destroy(store);
}

TEST(asset_id_deterministic) {
    // Create two identical assets
    crypto_asset_t *asset1 = crypto_asset_create("test", ASSET_TYPE_ALGORITHM);
    crypto_asset_t *asset2 = crypto_asset_create("test", ASSET_TYPE_ALGORITHM);
    
    ASSERT(asset1 != NULL && asset2 != NULL);
    ASSERT(strcmp(asset1->id, asset2->id) == 0); // Same content = same ID
    
    // Modify one asset
    asset2->algorithm = strdup("AES-256");
    char *new_id = generate_asset_id(asset2);
    ASSERT(new_id != NULL);
    ASSERT(strcmp(asset1->id, new_id) != 0); // Different content = different ID
    
    free(new_id);
    crypto_asset_destroy(asset1);
    crypto_asset_destroy(asset2);
}

TEST(asset_store_stats) {
    asset_store_t *store = asset_store_create(64);
    ASSERT(store != NULL);
    
    // Add various assets
    crypto_asset_t *cert = crypto_asset_create("cert", ASSET_TYPE_CERTIFICATE);
    crypto_asset_t *key = crypto_asset_create("key", ASSET_TYPE_KEY);
    crypto_asset_t *weak_algo = crypto_asset_create("md5", ASSET_TYPE_ALGORITHM);
    
    weak_algo->is_weak = true;
    
    asset_store_add(store, cert);
    asset_store_add(store, key);
    asset_store_add(store, weak_algo);
    
    asset_store_stats_t stats = asset_store_get_stats(store);
    ASSERT(stats.total_assets == 3);
    ASSERT(stats.assets_by_type[ASSET_TYPE_CERTIFICATE] == 1);
    ASSERT(stats.assets_by_type[ASSET_TYPE_KEY] == 1);
    ASSERT(stats.assets_by_type[ASSET_TYPE_ALGORITHM] == 1);
    ASSERT(stats.weak_assets == 1);
    ASSERT(stats.load_factor > 0.0);
    
    asset_store_destroy(store);
}

int run_asset_store_tests(void) {
    // Run tests
    run_test_secure_memory_basic();
    run_test_asset_store_creation();
    run_test_crypto_asset_creation();
    run_test_asset_store_add_find();
    run_test_deterministic_sorting();
    run_test_asset_id_deterministic();
    run_test_asset_store_stats();
    
    printf("Tests run: %d, Passed: %d\n", tests_run, tests_passed);
    
    if (tests_run == tests_passed) {
        printf("Asset store tests PASSED!\n");
        return 0;
    } else {
        printf("Asset store tests FAILED!\n");
        return 1;
    }
}
