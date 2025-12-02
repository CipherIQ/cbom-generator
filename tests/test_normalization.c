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

#include "normalization.h"
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

TEST(normalize_algorithm_name) {
    char *result = normalize_algorithm_name("AES-256-GCM");
    ASSERT(result != NULL);
    ASSERT(strcmp(result, "AES_256_GCM") == 0);
    free(result);
    
    result = normalize_algorithm_name("sha 256");
    ASSERT(result != NULL);
    ASSERT(strcmp(result, "SHA_256") == 0);
    free(result);
    
    result = normalize_algorithm_name(NULL);
    ASSERT(result != NULL);
    ASSERT(strcmp(result, "") == 0);
    free(result);
}

TEST(normalize_hex_string) {
    char *result = normalize_hex_string("a1:b2:c3:d4");
    ASSERT(result != NULL);
    ASSERT(strcmp(result, "A1B2C3D4") == 0);
    free(result);
    
    result = normalize_hex_string("1a 2b 3c 4d");
    ASSERT(result != NULL);
    ASSERT(strcmp(result, "1A2B3C4D") == 0);
    free(result);
    
    result = normalize_hex_string("1a-2b-3c-4d");
    ASSERT(result != NULL);
    ASSERT(strcmp(result, "1A2B3C4D") == 0);
    free(result);
}

TEST(normalize_algorithm_asset) {
    crypto_asset_t *asset = crypto_asset_create("AES-256-GCM", ASSET_TYPE_ALGORITHM);
    ASSERT(asset != NULL);
    asset->key_size = 256;
    
    json_object *normalized = normalize_algorithm_asset(asset);
    ASSERT(normalized != NULL);
    
    // Check that all required fields are present
    json_object *name_obj, *key_size_obj, *mode_obj, *padding_obj;
    ASSERT(json_object_object_get_ex(normalized, "name", &name_obj));
    ASSERT(json_object_object_get_ex(normalized, "key_size", &key_size_obj));
    ASSERT(json_object_object_get_ex(normalized, "mode", &mode_obj));
    ASSERT(json_object_object_get_ex(normalized, "padding", &padding_obj));
    
    // Check field values
    ASSERT(strcmp(json_object_get_string(name_obj), "AES_256_GCM") == 0);
    ASSERT(json_object_get_int64(key_size_obj) == 256);
    
    json_object_put(normalized);
    crypto_asset_destroy(asset);
}

TEST(normalize_key_asset) {
    crypto_asset_t *asset = crypto_asset_create("RSA-2048", ASSET_TYPE_KEY);
    ASSERT(asset != NULL);
    asset->algorithm = strdup("RSA");
    asset->key_size = 2048;
    
    json_object *normalized = normalize_key_asset(asset);
    ASSERT(normalized != NULL);
    
    // Check that all required fields are present
    json_object *key_type_obj, *key_size_obj, *curve_obj, *hash_obj, *private_obj;
    ASSERT(json_object_object_get_ex(normalized, "key_type", &key_type_obj));
    ASSERT(json_object_object_get_ex(normalized, "key_size", &key_size_obj));
    ASSERT(json_object_object_get_ex(normalized, "curve", &curve_obj));
    ASSERT(json_object_object_get_ex(normalized, "public_key_hash", &hash_obj));
    ASSERT(json_object_object_get_ex(normalized, "is_private", &private_obj));
    
    // Check field values
    ASSERT(strcmp(json_object_get_string(key_type_obj), "RSA") == 0);
    ASSERT(json_object_get_int64(key_size_obj) == 2048);
    ASSERT(json_object_get_boolean(private_obj) == 0); // Default to false
    
    json_object_put(normalized);
    crypto_asset_destroy(asset);
}

TEST(serialize_json_deterministic) {
    json_object *json_obj = json_object_new_object();
    ASSERT(json_obj != NULL);
    
    // Add fields in non-alphabetical order
    json_object_object_add(json_obj, "zebra", json_object_new_string("last"));
    json_object_object_add(json_obj, "alpha", json_object_new_string("first"));
    json_object_object_add(json_obj, "beta", json_object_new_int(42));
    
    char *serialized = serialize_json_deterministic(json_obj);
    ASSERT(serialized != NULL);
    
    // Should be compact (no extra whitespace) and keys should be sorted
    ASSERT(strstr(serialized, "\"alpha\":\"first\"") != NULL);
    ASSERT(strstr(serialized, "\"beta\":42") != NULL);
    ASSERT(strstr(serialized, "\"zebra\":\"last\"") != NULL);
    
    // Should not contain extra whitespace
    ASSERT(strstr(serialized, " ") == NULL);
    ASSERT(strstr(serialized, "\n") == NULL);
    ASSERT(strstr(serialized, "\t") == NULL);
    
    free(serialized);
    json_object_put(json_obj);
}

TEST(generate_content_addressed_id) {
    json_object *json_obj = json_object_new_object();
    ASSERT(json_obj != NULL);
    
    json_object_object_add(json_obj, "name", json_object_new_string("test"));
    json_object_object_add(json_obj, "value", json_object_new_int(123));
    
    char *id1 = generate_content_addressed_id(json_obj);
    ASSERT(id1 != NULL);
    ASSERT(strlen(id1) == 64); // SHA-256 hex string
    
    // Generate ID again - should be identical
    char *id2 = generate_content_addressed_id(json_obj);
    ASSERT(id2 != NULL);
    ASSERT(strcmp(id1, id2) == 0);
    
    // Modify object - should generate different ID
    json_object_object_add(json_obj, "value", json_object_new_int(456));
    char *id3 = generate_content_addressed_id(json_obj);
    ASSERT(id3 != NULL);
    ASSERT(strcmp(id1, id3) != 0);
    
    free(id1);
    free(id2);
    free(id3);
    json_object_put(json_obj);
}

TEST(normalization_deterministic) {
    // Create two identical assets
    crypto_asset_t *asset1 = crypto_asset_create("AES-256", ASSET_TYPE_ALGORITHM);
    crypto_asset_t *asset2 = crypto_asset_create("AES-256", ASSET_TYPE_ALGORITHM);
    
    ASSERT(asset1 != NULL && asset2 != NULL);
    asset1->key_size = 256;
    asset2->key_size = 256;
    
    // Normalize both
    json_object *norm1 = normalize_asset(asset1);
    json_object *norm2 = normalize_asset(asset2);
    
    ASSERT(norm1 != NULL && norm2 != NULL);
    
    // Generate IDs
    char *id1 = generate_content_addressed_id(norm1);
    char *id2 = generate_content_addressed_id(norm2);
    
    ASSERT(id1 != NULL && id2 != NULL);
    ASSERT(strcmp(id1, id2) == 0); // Should be identical
    
    free(id1);
    free(id2);
    json_object_put(norm1);
    json_object_put(norm2);
    crypto_asset_destroy(asset1);
    crypto_asset_destroy(asset2);
}

TEST(test_vectors_validation) {
    // This test runs the built-in test vector validation
    int result = validate_normalization_test_vectors();
    ASSERT(result == 0); // Should pass all test vectors
}

int run_normalization_tests(void) {
    // Run tests
    run_test_normalize_algorithm_name();
    run_test_normalize_hex_string();
    run_test_normalize_algorithm_asset();
    run_test_normalize_key_asset();
    run_test_serialize_json_deterministic();
    run_test_generate_content_addressed_id();
    run_test_normalization_deterministic();
    run_test_test_vectors_validation();
    
    printf("Tests run: %d, Passed: %d\n", tests_run, tests_passed);
    
    if (tests_run == tests_passed) {
        printf("Normalization tests PASSED!\n");
        return 0;
    } else {
        printf("Normalization tests FAILED!\n");
        return 1;
    }
}
