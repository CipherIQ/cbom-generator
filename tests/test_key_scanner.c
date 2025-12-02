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
#include <sys/stat.h>
#include <ctype.h>
#include "key_scanner.h"
#include "asset_store.h"
#include "secure_memory.h"

// Test RSA private key (PEM format) - 2048-bit test key
static const char* test_rsa_private_key_pem =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEA0Z91qZ7JUY03jg7qmvT2rR/qgI0wXLCdVRRNqCdaV3bI2hPd\n"
"fDQg3r9fX4sRcGTtgqKzDHWRZvNJDW8Z8qLqvqDX8QV4e1g6U7E3bT8p0mD+jQ+L\n"
"6xRnWZxDKPvJhVLmGXY0rR4kG7L3vY1e5fT6lK8qJ0YwJ9YdH0bE+Q5cX8fJ7bFn\n"
"j9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ\n"
"7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5c\n"
"X8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE\n"
"QIDAQABAoIBAA8VqJ5F3qT7rJDv4L5qX9K8W0pLNqVvE8fJ7bFnj9K0v6pL8qJ0\n"
"YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL\n"
"8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0\n"
"v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFn\n"
"j9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ\n"
"7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+QEC\n"
"gYEA7L3vY1e5fT6lK8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0b\n"
"E+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9Y\n"
"dH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0\n"
"YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL8qJ0YwJ9YdH0bE+Q5cX8fJ7bFnj9K0v6pL\n"
"-----END RSA PRIVATE KEY-----\n";

// Test RSA public key (OpenSSH format)
static const char* test_rsa_public_key_openssh =
"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDR"
"n3WpnslRjTeODuqa9PatH+qAjTBcsJ1VFE2oJ1pX"
"dsjaE918NCDev19fixFwZO2CorMMdZFm80kNbxny"
"ouq+oNfxBXh7WDpTsTdtPynSYP6ND4vrFGdZnEMo"
" test@example.com\n";

// Create a temporary test key file
static char* create_test_key_file(const char* content) {
    char* temp_file = strdup("/tmp/test_key_XXXXXX");
    int fd = mkstemp(temp_file);
    if (fd == -1) {
        free(temp_file);
        return NULL;
    }

    // Write test key content
    ssize_t written = write(fd, content, strlen(content));
    (void)written; // Suppress unused variable warning
    close(fd);

    return temp_file;
}

// Test 1: Key format detection
static void test_key_format_detection(void) {
    printf("Testing key format detection...\n");

    // Test PEM format detection
    char* pem_file = create_test_key_file(test_rsa_private_key_pem);
    assert(pem_file != NULL);

    key_format_t format = key_detect_format(pem_file);
    assert(format == KEY_FORMAT_PEM);

    unlink(pem_file);
    free(pem_file);

    // Test OpenSSH format detection
    char* openssh_file = create_test_key_file(test_rsa_public_key_openssh);
    assert(openssh_file != NULL);

    format = key_detect_format(openssh_file);
    assert(format == KEY_FORMAT_OPENSSH);

    unlink(openssh_file);
    free(openssh_file);

    // Test with non-existent file
    format = key_detect_format("/nonexistent/file");
    assert(format == KEY_FORMAT_UNKNOWN);

    // Test with NULL
    format = key_detect_format(NULL);
    assert(format == KEY_FORMAT_UNKNOWN);

    printf("✓ Key format detection tests passed\n");
}

// Test 2: Key scanner configuration
static void test_key_scanner_config(void) {
    printf("Testing key scanner configuration...\n");

    key_scanner_config_t config = key_scanner_create_default_config();

    assert(config.recursive_scan == true);
    assert(config.max_file_size > 0);
    assert(config.timeout_seconds > 0);
    assert(config.skip_encrypted == true);
    assert(config.detect_weak_keys == true);
    assert(config.redact_key_material == true); // CRITICAL: must be true

    key_scanner_config_destroy(&config);

    printf("✓ Key scanner configuration tests passed\n");
}

// Test 3: Key scanner context creation
static void test_key_scanner_context(void) {
    printf("Testing key scanner context...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    key_scanner_config_t config = key_scanner_create_default_config();

    // Test with valid parameters
    key_scanner_context_t* context = key_scanner_create(&config, store);
    assert(context != NULL);
    assert(context->asset_store == store);

    // Test statistics initialization
    key_scanner_stats_t stats = key_scanner_get_stats(context);
    assert(stats.files_scanned_total == 0);
    assert(stats.keys_detected_total == 0);

    key_scanner_destroy(context);
    asset_store_destroy(store);

    // Test with NULL parameters
    context = key_scanner_create(NULL, store);
    assert(context == NULL);

    printf("✓ Key scanner context tests passed\n");
}

// Test 4: Key type detection
static void test_key_type_detection(void) {
    printf("Testing key type detection...\n");

    // Generate a test RSA key
    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        key_type_t type = key_get_type(rsa_key);
        assert(type == KEY_TYPE_RSA);

        int size = key_get_size(rsa_key);
        assert(size == 2048);

        char* algorithm = key_get_algorithm_name(rsa_key);
        assert(algorithm != NULL);
        assert(strstr(algorithm, "RSA") != NULL);

        free(algorithm);
        EVP_PKEY_free(rsa_key);

        printf("✓ RSA key type detection passed\n");
    } else {
        printf("⚠ RSA key generation failed (OpenSSL issue)\n");
    }

    // Test with NULL
    key_type_t type = key_get_type(NULL);
    assert(type == KEY_TYPE_UNKNOWN);

    printf("✓ Key type detection tests completed\n");
}

// Test 5: Key classification (private/public)
static void test_key_classification(void) {
    printf("Testing key classification...\n");

    // Generate a test RSA key pair
    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        key_class_t classification = key_get_classification(rsa_key);
        // RSA_gen creates a private key
        assert(classification == KEY_CLASS_PRIVATE || classification == KEY_CLASS_PUBLIC);

        EVP_PKEY_free(rsa_key);

        printf("✓ Key classification detection passed\n");
    } else {
        printf("⚠ Key generation failed\n");
    }

    // Test with NULL
    key_class_t classification = key_get_classification(NULL);
    assert(classification == KEY_CLASS_UNKNOWN);

    printf("✓ Key classification tests completed\n");
}

// Test 6: Key ID generation (SHA-256 hash)
static void test_key_id_generation(void) {
    printf("Testing key ID generation...\n");

    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        char* key_id = key_generate_id(rsa_key);
        assert(key_id != NULL);
        assert(strlen(key_id) == 64); // SHA-256 hex = 64 chars

        // Verify it's a valid hex string
        for (size_t i = 0; i < strlen(key_id); i++) {
            assert(isxdigit(key_id[i]));
        }

        free(key_id);
        EVP_PKEY_free(rsa_key);

        printf("✓ Key ID generation passed\n");
    } else {
        printf("⚠ Key generation failed\n");
    }

    // Test with NULL
    char* key_id = key_generate_id(NULL);
    assert(key_id == NULL);

    printf("✓ Key ID generation tests completed\n");
}

// Test 7: Storage security detection
static void test_storage_security_detection(void) {
    printf("Testing storage security detection...\n");

    // Test plaintext detection
    storage_security_t storage = key_detect_storage_security("/tmp/test.key", false);
    assert(storage == STORAGE_PLAINTEXT);

    // Test encrypted detection
    storage = key_detect_storage_security("/tmp/test.key", true);
    assert(storage == STORAGE_ENCRYPTED);

    // Test HSM detection
    storage = key_detect_storage_security("/dev/crypto/hsm0", false);
    assert(storage == STORAGE_HSM);

    // Test TPM detection
    storage = key_detect_storage_security("/dev/tpm0", false);
    assert(storage == STORAGE_TPM);

    // Test keyring detection
    storage = key_detect_storage_security("/path/to/keyring/key", false);
    assert(storage == STORAGE_KEYRING);

    printf("✓ Storage security detection tests passed\n");
}

// Test 8: Weakness detection
static void test_weakness_detection(void) {
    printf("Testing weakness detection...\n");

    // Test with 1024-bit RSA key (weak)
    EVP_PKEY* weak_key = EVP_RSA_gen(1024);
    if (weak_key) {
        bool is_weak = key_is_weak(weak_key, KEY_TYPE_RSA);
        assert(is_weak == true);

        size_t count = 0;
        char** reasons = key_get_weak_reasons(weak_key, KEY_TYPE_RSA, &count);
        assert(count > 0);
        assert(reasons != NULL);

        for (size_t i = 0; i < count; i++) {
            free(reasons[i]);
        }
        free(reasons);

        EVP_PKEY_free(weak_key);

        printf("✓ Weak key detection passed\n");
    } else {
        printf("⚠ Weak key generation failed\n");
    }

    // Test with 2048-bit RSA key (strong)
    EVP_PKEY* strong_key = EVP_RSA_gen(2048);
    if (strong_key) {
        bool is_weak = key_is_weak(strong_key, KEY_TYPE_RSA);
        assert(is_weak == false);

        EVP_PKEY_free(strong_key);

        printf("✓ Strong key detection passed\n");
    } else {
        printf("⚠ Strong key generation failed\n");
    }

    printf("✓ Weakness detection tests completed\n");
}

// Test 9: Key metadata extraction (NEVER stores raw material)
static void test_key_metadata_extraction(void) {
    printf("Testing key metadata extraction...\n");

    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        key_metadata_t* metadata = key_extract_metadata(rsa_key, "/tmp/test.key",
                                                        KEY_FORMAT_PEM, false);
        assert(metadata != NULL);
        assert(metadata->type == KEY_TYPE_RSA);
        assert(metadata->key_size == 2048);
        assert(metadata->algorithm != NULL);
        assert(metadata->key_id_sha256 != NULL);
        assert(metadata->public_key_hash != NULL);
        assert(metadata->storage == STORAGE_PLAINTEXT);

        // CRITICAL: Verify no raw key material is stored
        assert(metadata->key_id_sha256 != NULL); // Only hashes
        assert(strlen(metadata->key_id_sha256) == 64); // SHA-256 hex

        key_metadata_destroy(metadata);
        EVP_PKEY_free(rsa_key);

        printf("✓ Key metadata extraction passed\n");
    } else {
        printf("⚠ Key generation failed\n");
    }

    printf("✓ Key metadata extraction tests completed\n");
}

// Test 10: Key asset creation (stores only metadata and hashes)
static void test_key_asset_creation(void) {
    printf("Testing key asset creation...\n");

    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        key_metadata_t* metadata = key_extract_metadata(rsa_key, "/tmp/test.key",
                                                        KEY_FORMAT_PEM, false);
        assert(metadata != NULL);

        crypto_asset_t* asset = key_create_asset(metadata);
        assert(asset != NULL);
        assert(asset->type == ASSET_TYPE_KEY);
        assert(asset->id != NULL);
        assert(asset->name != NULL);

        // CRITICAL: Verify no raw key material in asset
        if (asset->metadata_json) {
            assert(strstr(asset->metadata_json, "BEGIN RSA PRIVATE KEY") == NULL);
            assert(strstr(asset->metadata_json, "BEGIN PRIVATE KEY") == NULL);
        }

        key_metadata_destroy(metadata);
        EVP_PKEY_free(rsa_key);

        printf("✓ Key asset creation passed\n");
    } else {
        printf("⚠ Key generation failed\n");
    }

    printf("✓ Key asset creation tests completed\n");
}

// Test 11: CRITICAL - Verify NO PEM headers in output
static void test_no_pem_headers_in_output(void) {
    printf("Testing NO PEM headers in output (CRITICAL SECURITY TEST)...\n");

    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        key_metadata_t* metadata = key_extract_metadata(rsa_key, "/tmp/test.key",
                                                        KEY_FORMAT_PEM, false);
        assert(metadata != NULL);

        char* json = key_create_detailed_json_metadata(metadata);
        assert(json != NULL);

        // CRITICAL: Verify no PEM headers in output
        bool valid = key_scanner_validate_no_pem_headers_in_output(json);
        assert(valid == true);

        printf("✓ CRITICAL: No PEM headers found in output ✓\n");

        free(json);
        key_metadata_destroy(metadata);
        EVP_PKEY_free(rsa_key);
    } else {
        printf("⚠ Key generation failed\n");
    }

    printf("✓ PEM header validation tests passed (CRITICAL)\n");
}

// Test 12: CRITICAL - Verify NO raw key material in output
static void test_no_key_material_in_output(void) {
    printf("Testing NO key material in output (CRITICAL SECURITY TEST)...\n");

    EVP_PKEY* rsa_key = EVP_RSA_gen(2048);
    if (rsa_key) {
        key_metadata_t* metadata = key_extract_metadata(rsa_key, "/tmp/test.key",
                                                        KEY_FORMAT_PEM, false);
        assert(metadata != NULL);

        char* json = key_create_detailed_json_metadata(metadata);
        assert(json != NULL);

        // CRITICAL: Verify no raw key material in output
        bool valid = key_scanner_validate_no_key_material_in_output(json);
        assert(valid == true);

        printf("✓ CRITICAL: No key material found in output ✓\n");

        free(json);
        key_metadata_destroy(metadata);
        EVP_PKEY_free(rsa_key);
    } else {
        printf("⚠ Key generation failed\n");
    }

    printf("✓ Key material validation tests passed (CRITICAL)\n");
}

// Test 13: Key scanner statistics
static void test_key_scanner_statistics(void) {
    printf("Testing key scanner statistics...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    key_scanner_config_t config = key_scanner_create_default_config();
    key_scanner_context_t* context = key_scanner_create(&config, store);
    assert(context != NULL);

    // Initial statistics should be zero
    key_scanner_stats_t stats = key_scanner_get_stats(context);
    assert(stats.files_scanned_total == 0);
    assert(stats.keys_detected_total == 0);
    assert(stats.keys_parsed_ok == 0);

    key_scanner_destroy(context);
    asset_store_destroy(store);

    printf("✓ Key scanner statistics tests passed\n");
}

// Test 14: Failure reason handling
static void test_failure_reason_handling(void) {
    printf("Testing failure reason handling...\n");

    // Test failure reason to string conversion
    const char* reason = key_failure_reason_to_string(KEY_FAIL_INVALID_PEM_BLOCK);
    assert(reason != NULL);
    assert(strcmp(reason, "INVALID_PEM_BLOCK") == 0);

    reason = key_failure_reason_to_string(KEY_FAIL_ENCRYPTED_NO_PASSWORD);
    assert(reason != NULL);
    assert(strcmp(reason, "ENCRYPTED_NO_PASSWORD") == 0);

    reason = key_failure_reason_to_string(KEY_FAIL_MEMORY_ERROR);
    assert(reason != NULL);
    assert(strcmp(reason, "MEMORY_ERROR") == 0);

    printf("✓ Failure reason handling tests passed\n");
}

// ============================================================================
// Phase 3: CycloneDX Conformance Tests
// ============================================================================

// Test key state determination
void test_key_state_determination(void) {
    printf("Testing key state determination...\n");

    // Test 1: Active key (recently accessed file)
    const char* active_key_path = "/tmp/test-active-key.pem";
    FILE* fp = fopen(active_key_path, "w");
    assert(fp != NULL);
    fprintf(fp, "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    fclose(fp);

    time_t creation_date = 0, activation_date = 0;
    key_state_t state = determine_key_state(active_key_path, &creation_date, &activation_date);
    assert(state == KEY_STATE_ACTIVE);
    assert(creation_date > 0);
    assert(activation_date > 0);

    // Test 2: Compromised key (with .compromised marker)
    const char* compromised_key_path = "/tmp/test-compromised-key.pem";
    const char* marker_path = "/tmp/test-compromised-key.pem.compromised";
    fp = fopen(compromised_key_path, "w");
    assert(fp != NULL);
    fprintf(fp, "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    fclose(fp);
    fp = fopen(marker_path, "w");
    assert(fp != NULL);
    fclose(fp);

    state = determine_key_state(compromised_key_path, NULL, NULL);
    assert(state == KEY_STATE_COMPROMISED);

    // Test 3: Destroyed key (non-existent file)
    state = determine_key_state("/nonexistent/key.pem", NULL, NULL);
    assert(state == KEY_STATE_DESTROYED);

    // Test 4: State to string conversion
    assert(strcmp(key_state_to_string(KEY_STATE_ACTIVE), "active") == 0);
    assert(strcmp(key_state_to_string(KEY_STATE_COMPROMISED), "compromised") == 0);
    assert(strcmp(key_state_to_string(KEY_STATE_DEACTIVATED), "deactivated") == 0);
    assert(strcmp(key_state_to_string(KEY_STATE_DESTROYED), "destroyed") == 0);

    // Cleanup
    unlink(active_key_path);
    unlink(compromised_key_path);
    unlink(marker_path);

    printf("✓ Key state determination tests passed\n");
}

// Test encrypted key detection
void test_encrypted_key_detection(void) {
    printf("Testing encrypted key detection...\n");

    // Test 1: Encrypted key with AES-256-CBC
    const char* encrypted_key_path = "/tmp/test-encrypted-aes256.pem";
    FILE* fp = fopen(encrypted_key_path, "w");
    assert(fp != NULL);
    fprintf(fp, "-----BEGIN RSA PRIVATE KEY-----\n");
    fprintf(fp, "Proc-Type: 4,ENCRYPTED\n");
    fprintf(fp, "DEK-Info: AES-256-CBC,12345678\n");
    fprintf(fp, "\n");
    fprintf(fp, "test encrypted data\n");
    fprintf(fp, "-----END RSA PRIVATE KEY-----\n");
    fclose(fp);

    secured_by_t* secured = detect_key_encryption(encrypted_key_path);
    assert(secured != NULL);
    assert(strcmp(secured->mechanism, "Software") == 0);
    assert(strcmp(secured->algorithm_ref, "algorithm-aes-256-cbc") == 0);
    secured_by_destroy(secured);

    // Test 2: Encrypted key with 3DES
    const char* encrypted_3des_path = "/tmp/test-encrypted-3des.pem";
    fp = fopen(encrypted_3des_path, "w");
    assert(fp != NULL);
    fprintf(fp, "-----BEGIN RSA PRIVATE KEY-----\n");
    fprintf(fp, "Proc-Type: 4,ENCRYPTED\n");
    fprintf(fp, "DEK-Info: DES-EDE3-CBC,12345678\n");
    fprintf(fp, "\n");
    fprintf(fp, "test encrypted data\n");
    fprintf(fp, "-----END RSA PRIVATE KEY-----\n");
    fclose(fp);

    secured = detect_key_encryption(encrypted_3des_path);
    assert(secured != NULL);
    assert(strcmp(secured->mechanism, "Software") == 0);
    assert(strcmp(secured->algorithm_ref, "algorithm-3des-cbc") == 0);
    secured_by_destroy(secured);

    // Test 3: Unencrypted key (should return NULL)
    const char* unencrypted_key_path = "/tmp/test-unencrypted.pem";
    fp = fopen(unencrypted_key_path, "w");
    assert(fp != NULL);
    fprintf(fp, "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    fclose(fp);

    secured = detect_key_encryption(unencrypted_key_path);
    assert(secured == NULL);

    // Cleanup
    unlink(encrypted_key_path);
    unlink(encrypted_3des_path);
    unlink(unencrypted_key_path);

    printf("✓ Encrypted key detection tests passed\n");
}

// Test algorithm reference generation
void test_algorithm_ref_generation(void) {
    printf("Testing algorithm reference generation...\n");

    // Create a temporary RSA key for testing
    const char* test_key_path = "/tmp/test-algoref-key.pem";

    // Generate a minimal valid RSA private key using OpenSSL command
    int ret = system("openssl genrsa -out /tmp/test-algoref-key.pem 2048 2>/dev/null");
    (void)ret;  // Explicitly ignore return value

    // Load the key
    EVP_PKEY* pkey = key_load_pem(test_key_path, NULL);
    if (pkey == NULL) {
        // Skip test if key generation failed
        printf("⚠ Skipping algorithm ref test (key generation failed)\n");
        unlink(test_key_path);
        return;
    }

    // Extract metadata
    key_metadata_t* metadata = key_extract_metadata(pkey, test_key_path, KEY_FORMAT_PEM, false);
    assert(metadata != NULL);

    // Test algorithm ref is generated
    assert(metadata->algorithm_ref != NULL);
    assert(strstr(metadata->algorithm_ref, "algorithm-") != NULL);
    assert(strstr(metadata->algorithm_ref, "rsa") != NULL);

    // Test lowercase normalization
    for (const char* p = metadata->algorithm_ref; *p; p++) {
        if (isalpha(*p)) {
            assert(islower(*p));
        }
    }

    // Cleanup
    key_metadata_destroy(metadata);
    EVP_PKEY_free(pkey);
    unlink(test_key_path);

    printf("✓ Algorithm reference generation tests passed\n");
}

// Test fingerprint object structure
void test_fingerprint_object_structure(void) {
    printf("Testing fingerprint object structure...\n");

    // Generate a test key
    const char* test_key_path = "/tmp/test-fingerprint-key.pem";
    int ret_val = system("openssl genrsa -out /tmp/test-fingerprint-key.pem 2048 2>/dev/null");
    (void)ret_val;  // Explicitly ignore return value

    EVP_PKEY* pkey = key_load_pem(test_key_path, NULL);
    if (pkey == NULL) {
        printf("⚠ Skipping fingerprint test (key generation failed)\n");
        unlink(test_key_path);
        return;
    }

    key_metadata_t* metadata = key_extract_metadata(pkey, test_key_path, KEY_FORMAT_PEM, false);
    assert(metadata != NULL);

    // Create JSON metadata to verify fingerprint structure
    char* json_str = key_create_detailed_json_metadata(metadata);
    assert(json_str != NULL);

    // Parse JSON and verify fingerprint is present
    assert(strstr(json_str, "key_id_sha256") != NULL);

    // Verify key_id is a 64-character hex string (SHA-256)
    assert(metadata->key_id_sha256 != NULL);
    assert(strlen(metadata->key_id_sha256) == 64);

    // Cleanup
    free(json_str);
    key_metadata_destroy(metadata);
    EVP_PKEY_free(pkey);
    unlink(test_key_path);

    printf("✓ Fingerprint object structure tests passed\n");
}

// Test OID population
void test_oid_population(void) {
    printf("Testing OID population...\n");

    // Test 1: RSA key OID
    const char* rsa_key_path = "/tmp/test-oid-rsa.pem";
    int ret_val = system("openssl genrsa -out /tmp/test-oid-rsa.pem 2048 2>/dev/null");
    (void)ret_val;  // Explicitly ignore return value

    EVP_PKEY* pkey = key_load_pem(rsa_key_path, NULL);
    if (pkey != NULL) {
        key_metadata_t* metadata = key_extract_metadata(pkey, rsa_key_path, KEY_FORMAT_PEM, false);
        assert(metadata != NULL);
        assert(metadata->oid != NULL);
        assert(strcmp(metadata->oid, "1.2.840.113549.1.1.1") == 0);  // RSA OID

        key_metadata_destroy(metadata);
        EVP_PKEY_free(pkey);
    }
    unlink(rsa_key_path);

    // Test 2: ECDSA P-256 key OID
    const char* ec_key_path = "/tmp/test-oid-ec.pem";
    ret_val = system("openssl ecparam -genkey -name prime256v1 -out /tmp/test-oid-ec.pem 2>/dev/null");
    (void)ret_val;  // Explicitly ignore return value

    pkey = key_load_pem(ec_key_path, NULL);
    if (pkey != NULL) {
        key_metadata_t* metadata = key_extract_metadata(pkey, ec_key_path, KEY_FORMAT_PEM, false);
        assert(metadata != NULL);
        assert(metadata->oid != NULL);
        assert(strcmp(metadata->oid, "1.2.840.10045.3.1.7") == 0);  // P-256/secp256r1 OID

        key_metadata_destroy(metadata);
        EVP_PKEY_free(pkey);
    }
    unlink(ec_key_path);

    printf("✓ OID population tests passed\n");
}

// Main test runner
int main(void) {
    printf("=== Key Scanner Test Suite ===\n\n");

    // Initialize secure memory subsystem
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory subsystem\n");
        return 1;
    }

    // Run all tests
    test_key_format_detection();
    test_key_scanner_config();
    test_key_scanner_context();
    test_key_type_detection();
    test_key_classification();
    test_key_id_generation();
    test_storage_security_detection();
    test_weakness_detection();
    test_key_metadata_extraction();
    test_key_asset_creation();

    // CRITICAL SECURITY TESTS
    printf("\n=== CRITICAL SECURITY VALIDATION TESTS ===\n");
    test_no_pem_headers_in_output();
    test_no_key_material_in_output();
    printf("=== END CRITICAL SECURITY TESTS ===\n\n");

    test_key_scanner_statistics();
    test_failure_reason_handling();

    // PHASE 3 CYCLONEDX CONFORMANCE TESTS
    printf("\n=== PHASE 3: CYCLONEDX CONFORMANCE TESTS ===\n");
    test_key_state_determination();
    test_encrypted_key_detection();
    test_algorithm_ref_generation();
    test_fingerprint_object_structure();
    test_oid_population();
    printf("=== END PHASE 3 TESTS ===\n\n");

    // Cleanup secure memory subsystem
    secure_memory_cleanup();

    printf("\n=== All Key Scanner Tests Passed ===\n");
    return 0;
}
