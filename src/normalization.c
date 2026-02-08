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
#include "normalization.h"
#include "asset_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sha256_portable.h"

// Utility function to normalize algorithm names
char* normalize_algorithm_name(const char *name) {
    if (name == NULL) {
        return strdup("");
    }
    
    size_t len = strlen(name);
    char *normalized = malloc(len + 1);
    if (normalized == NULL) {
        return NULL;
    }
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c == ' ' || c == '-') {
            normalized[j++] = '_';
        } else {
            normalized[j++] = toupper(c);
        }
    }
    normalized[j] = '\0';
    
    return normalized;
}

// Utility function to normalize hex strings
char* normalize_hex_string(const char *hex) {
    if (hex == NULL) {
        return strdup("");
    }
    
    size_t len = strlen(hex);
    char *normalized = malloc(len + 1);
    if (normalized == NULL) {
        return NULL;
    }
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = hex[i];
        if (c != ':' && c != ' ' && c != '-') {
            normalized[j++] = toupper(c);
        }
    }
    normalized[j] = '\0';
    
    return normalized;
}

// Utility function to normalize version strings
char* normalize_version_string(const char *version) {
    if (version == NULL) {
        return strdup("");
    }
    
    // For now, just trim whitespace and return as-is
    // More sophisticated semantic version normalization could be added
    char *normalized = strdup(version);
    if (normalized == NULL) {
        return NULL;
    }
    
    // Trim leading/trailing whitespace
    char *start = normalized;
    while (isspace(*start)) start++;
    
    char *end = start + strlen(start) - 1;
    while (end > start && isspace(*end)) end--;
    *(end + 1) = '\0';
    
    if (start != normalized) {
        memmove(normalized, start, strlen(start) + 1);
    }
    
    return normalized;
}

// Normalize algorithm assets
json_object* normalize_algorithm_asset(const crypto_asset_t *asset) {
    if (asset == NULL || asset->type != ASSET_TYPE_ALGORITHM) {
        return NULL;
    }
    
    json_object *normalized = json_object_new_object();
    if (normalized == NULL) {
        return NULL;
    }
    
    // Fields in specified order: name, key_size, mode, padding
    char *norm_name = normalize_algorithm_name(asset->name);
    json_object_object_add(normalized, "name", 
                          json_object_new_string(norm_name ? norm_name : ""));
    free(norm_name);
    
    json_object_object_add(normalized, "key_size", 
                          json_object_new_int64(asset->key_size));
    
    // Extract mode and padding from algorithm string if present
    // For now, use empty strings - could be enhanced to parse algorithm details
    json_object_object_add(normalized, "mode", json_object_new_string(""));
    json_object_object_add(normalized, "padding", json_object_new_string(""));
    
    return normalized;
}

// Normalize certificate assets
json_object* normalize_certificate_asset(const crypto_asset_t *asset) {
    if (asset == NULL || asset->type != ASSET_TYPE_CERTIFICATE) {
        return NULL;
    }
    
    json_object *normalized = json_object_new_object();
    if (normalized == NULL) {
        return NULL;
    }
    
    // For now, create minimal normalized representation
    // Full certificate parsing would be implemented in a real scanner
    json_object_object_add(normalized, "subject_dn", 
                          json_object_new_string(asset->name ? asset->name : ""));
    json_object_object_add(normalized, "issuer_dn", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "serial_number", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "public_key_algorithm", 
                          json_object_new_string(asset->algorithm ? asset->algorithm : ""));
    json_object_object_add(normalized, "public_key_size", 
                          json_object_new_int64(asset->key_size));
    json_object_object_add(normalized, "signature_algorithm", 
                          json_object_new_string(asset->hash_algorithm ? asset->hash_algorithm : ""));
    json_object_object_add(normalized, "not_before", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "not_after", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "fingerprint_sha256", 
                          json_object_new_string(""));
    
    return normalized;
}

// Normalize key assets
json_object* normalize_key_asset(const crypto_asset_t *asset) {
    if (asset == NULL || asset->type != ASSET_TYPE_KEY) {
        return NULL;
    }
    
    json_object *normalized = json_object_new_object();
    if (normalized == NULL) {
        return NULL;
    }
    
    char *norm_algorithm = normalize_algorithm_name(asset->algorithm);
    json_object_object_add(normalized, "key_type", 
                          json_object_new_string(norm_algorithm ? norm_algorithm : ""));
    free(norm_algorithm);
    
    json_object_object_add(normalized, "key_size", 
                          json_object_new_int64(asset->key_size));
    json_object_object_add(normalized, "curve", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "public_key_hash", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "is_private", 
                          json_object_new_boolean(false)); // Default to false for security
    
    return normalized;
}

// Normalize library assets
json_object* normalize_library_asset(const crypto_asset_t *asset) {
    if (asset == NULL || asset->type != ASSET_TYPE_LIBRARY) {
        return NULL;
    }
    
    json_object *normalized = json_object_new_object();
    if (normalized == NULL) {
        return NULL;
    }
    
    json_object_object_add(normalized, "name", 
                          json_object_new_string(asset->name ? asset->name : ""));
    
    char *norm_version = normalize_version_string(asset->version);
    json_object_object_add(normalized, "version", 
                          json_object_new_string(norm_version ? norm_version : ""));
    free(norm_version);
    
    json_object_object_add(normalized, "vendor", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "build_hash", 
                          json_object_new_string(""));
    
    return normalized;
}

// Normalize protocol assets
json_object* normalize_protocol_asset(const crypto_asset_t *asset) {
    if (asset == NULL || asset->type != ASSET_TYPE_PROTOCOL) {
        return NULL;
    }
    
    json_object *normalized = json_object_new_object();
    if (normalized == NULL) {
        return NULL;
    }
    
    json_object_object_add(normalized, "protocol", 
                          json_object_new_string(asset->name ? asset->name : ""));
    json_object_object_add(normalized, "version", 
                          json_object_new_string(asset->version ? asset->version : ""));
    
    // Create empty cipher suites array for now
    json_object *cipher_suites = json_object_new_array();
    json_object_object_add(normalized, "cipher_suites", cipher_suites);
    
    json_object_object_add(normalized, "key_exchange", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "authentication", 
                          json_object_new_string(""));
    
    return normalized;
}

// Normalize service assets
json_object* normalize_service_asset(const crypto_asset_t *asset) {
    if (asset == NULL || asset->type != ASSET_TYPE_SERVICE) {
        return NULL;
    }
    
    json_object *normalized = json_object_new_object();
    if (normalized == NULL) {
        return NULL;
    }
    
    json_object_object_add(normalized, "service_name", 
                          json_object_new_string(asset->name ? asset->name : ""));
    json_object_object_add(normalized, "service_type", 
                          json_object_new_string(""));
    json_object_object_add(normalized, "config_hash", 
                          json_object_new_string(""));
    
    // Create empty ports array for now
    json_object *ports = json_object_new_array();
    json_object_object_add(normalized, "listening_ports", ports);
    
    // Create empty certificates array for now
    json_object *certificates = json_object_new_array();
    json_object_object_add(normalized, "certificates", certificates);
    
    return normalized;
}

// Generic normalization dispatcher
json_object* normalize_asset(const crypto_asset_t *asset) {
    if (asset == NULL) {
        return NULL;
    }
    
    switch (asset->type) {
        case ASSET_TYPE_ALGORITHM:
            return normalize_algorithm_asset(asset);
        case ASSET_TYPE_CERTIFICATE:
            return normalize_certificate_asset(asset);
        case ASSET_TYPE_KEY:
            return normalize_key_asset(asset);
        case ASSET_TYPE_LIBRARY:
            return normalize_library_asset(asset);
        case ASSET_TYPE_PROTOCOL:
            return normalize_protocol_asset(asset);
        case ASSET_TYPE_SERVICE:
            return normalize_service_asset(asset);
        default:
            return NULL;
    }
}

// Serialize JSON with deterministic ordering
char* serialize_json_deterministic(json_object *json_obj) {
    if (json_obj == NULL) {
        return NULL;
    }
    
    // json-c automatically sorts object keys, and we use JSON_C_TO_STRING_PLAIN
    // for compact output without extra whitespace
    const char *json_str = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PLAIN);
    if (json_str == NULL) {
        return NULL;
    }
    
    return strdup(json_str);
}

// Generate content-addressed ID from normalized JSON
char* generate_content_addressed_id(json_object *normalized_json) {
    if (normalized_json == NULL) {
        return NULL;
    }
    
    char *json_str = serialize_json_deterministic(normalized_json);
    if (json_str == NULL) {
        return NULL;
    }
    
    // Calculate SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)json_str, strlen(json_str), hash);
    
    // Convert to lowercase hex string
    char *hex_id = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (hex_id == NULL) {
        free(json_str);
        return NULL;
    }
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_id + (i * 2), "%02x", hash[i]);
    }
    hex_id[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    free(json_str);
    return hex_id;
}

// Test vectors for validation (JSON keys are sorted alphabetically by json-c)
static const normalization_test_vector_t test_vectors[] = {
    {
        .description = "AES-256-GCM algorithm",
        .type = ASSET_TYPE_ALGORITHM,
        .input_json = "{\"name\":\"AES-256-GCM\",\"key_size\":256}",
        .expected_normalized_json = "{\"name\":\"AES_256_GCM\",\"key_size\":256,\"mode\":\"\",\"padding\":\"\"}",
        .expected_id = "0ca99974c101c72ba4462ea93131ed2c4ce6f99417c3a4c2f77ae8c0f95910ce"
    },
    {
        .description = "RSA-2048 key",
        .type = ASSET_TYPE_KEY,
        .input_json = "{\"name\":\"RSA-2048\",\"algorithm\":\"RSA\",\"key_size\":2048}",
        .expected_normalized_json = "{\"key_type\":\"RSA\",\"key_size\":2048,\"curve\":\"\",\"public_key_hash\":\"\",\"is_private\":false}",
        .expected_id = "971fea92f5353ab3e6a72d020fadabb34ac6edde4114f707d1921c575d056e56"
    }
};

const normalization_test_vector_t* get_test_vectors(size_t *count) {
    if (count != NULL) {
        *count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    }
    return test_vectors;
}

int validate_normalization_test_vectors(void) {
    size_t count;
    const normalization_test_vector_t *vectors = get_test_vectors(&count);
    
    int passed = 0;
    int failed = 0;
    
    printf("Validating normalization test vectors...\n");
    
    for (size_t i = 0; i < count; i++) {
        const normalization_test_vector_t *vector = &vectors[i];
        
        printf("Test %zu: %s... ", i + 1, vector->description);
        
        // Create test asset
        crypto_asset_t *asset = crypto_asset_create("test", vector->type);
        if (asset == NULL) {
            printf("FAILED (asset creation)\n");
            failed++;
            continue;
        }
        
        // Parse input JSON to set asset properties
        json_object *input_json = json_tokener_parse(vector->input_json);
        if (input_json != NULL) {
            json_object *name_obj, *algorithm_obj, *key_size_obj;
            
            if (json_object_object_get_ex(input_json, "name", &name_obj)) {
                free(asset->name);
                asset->name = strdup(json_object_get_string(name_obj));
            }
            if (json_object_object_get_ex(input_json, "algorithm", &algorithm_obj)) {
                asset->algorithm = strdup(json_object_get_string(algorithm_obj));
            }
            if (json_object_object_get_ex(input_json, "key_size", &key_size_obj)) {
                asset->key_size = json_object_get_int64(key_size_obj);
            }
            
            json_object_put(input_json);
        }
        
        // Normalize asset
        json_object *normalized = normalize_asset(asset);
        if (normalized == NULL) {
            printf("FAILED (normalization)\n");
            crypto_asset_destroy(asset);
            failed++;
            continue;
        }
        
        // Check normalized JSON
        char *actual_json = serialize_json_deterministic(normalized);
        if (actual_json == NULL || strcmp(actual_json, vector->expected_normalized_json) != 0) {
            printf("FAILED (JSON mismatch)\n");
            printf("  Expected: %s\n", vector->expected_normalized_json);
            printf("  Actual:   %s\n", actual_json ? actual_json : "NULL");
            free(actual_json);
            json_object_put(normalized);
            crypto_asset_destroy(asset);
            failed++;
            continue;
        }
        
        // Check generated ID
        char *actual_id = generate_content_addressed_id(normalized);
        if (actual_id == NULL || strcmp(actual_id, vector->expected_id) != 0) {
            printf("FAILED (ID mismatch)\n");
            printf("  Expected: %s\n", vector->expected_id);
            printf("  Actual:   %s\n", actual_id ? actual_id : "NULL");
            free(actual_id);
            free(actual_json);
            json_object_put(normalized);
            crypto_asset_destroy(asset);
            failed++;
            continue;
        }
        
        printf("PASSED\n");
        passed++;
        
        free(actual_id);
        free(actual_json);
        json_object_put(normalized);
        crypto_asset_destroy(asset);
    }
    
    printf("\nNormalization test results: %d passed, %d failed\n", passed, failed);
    return (failed == 0) ? 0 : -1;
}
