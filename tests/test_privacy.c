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
#include <unistd.h>
#include "privacy.h"
#include "secure_memory.h"

// Test privacy context creation
static bool test_privacy_context_creation(void) {
    printf("Running test: privacy_context_creation... ");
    
    // Test with default config (should fail without salt)
    privacy_config_t config = privacy_get_default_config();
    privacy_context_t* context = privacy_context_create(&config);
    if (context) {
        printf("FAILED - Should not create context without salt when no_personal_data is true\n");
        privacy_context_destroy(context);
        return false;
    }
    
    // Test with salt
    config.salt = strdup("0123456789abcdef0123456789abcdef"); // 32 hex chars = 16 bytes
    config.salt_length = strlen(config.salt);
    
    context = privacy_context_create(&config);
    if (!context) {
        printf("FAILED - Could not create privacy context with salt\n");
        free(config.salt);
        return false;
    }
    
    privacy_context_destroy(context);
    free(config.salt);
    
    printf("PASSED\n");
    return true;
}

// Test salt validation
static bool test_salt_validation(void) {
    printf("Running test: salt_validation... ");
    
    // Test valid salt
    const char* valid_salt = "0123456789abcdef0123456789abcdef";
    if (!privacy_validate_salt_entropy(valid_salt, strlen(valid_salt))) {
        printf("FAILED - Valid salt should pass validation\n");
        return false;
    }
    
    // Test too short salt
    const char* short_salt = "short";
    if (privacy_validate_salt_entropy(short_salt, strlen(short_salt))) {
        printf("FAILED - Short salt should fail validation\n");
        return false;
    }
    
    // Test low entropy salt
    const char* low_entropy_salt = "aaaaaaaaaaaaaaaa"; // 16 chars but low entropy
    if (privacy_validate_salt_entropy(low_entropy_salt, strlen(low_entropy_salt))) {
        printf("FAILED - Low entropy salt should fail validation\n");
        return false;
    }
    
    printf("PASSED\n");
    return true;
}

// Test salt generation
static bool test_salt_generation(void) {
    printf("Running test: salt_generation... ");
    
    char* salt = privacy_generate_salt(32);
    if (!salt) {
        printf("FAILED - Could not generate salt\n");
        return false;
    }
    
    // Check length
    if (strlen(salt) != 64) { // 32 bytes * 2 hex chars
        printf("FAILED - Generated salt has wrong length: %zu\n", strlen(salt));
        free(salt);
        return false;
    }
    
    // Check that it passes validation
    if (!privacy_validate_salt_entropy(salt, strlen(salt))) {
        printf("FAILED - Generated salt should pass validation\n");
        free(salt);
        return false;
    }
    
    free(salt);
    
    printf("PASSED\n");
    return true;
}

// Test username redaction
static bool test_username_redaction(void) {
    printf("Running test: username_redaction... ");
    
    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup("0123456789abcdef0123456789abcdef");
    config.salt_length = strlen(config.salt);
    
    privacy_context_t* context = privacy_context_create(&config);
    if (!context) {
        printf("FAILED - Could not create privacy context\n");
        free(config.salt);
        return false;
    }
    
    // Test path with username
    const char* path_with_user = "/home/alice/documents/cert.pem";
    redaction_result_t* result = privacy_redact_username(context, path_with_user);
    
    if (!result) {
        printf("FAILED - Could not redact username\n");
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    if (!result->was_redacted) {
        printf("FAILED - Username should have been redacted\n");
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Check that username is not in redacted text
    if (strstr(result->redacted_text, "alice")) {
        printf("FAILED - Username still present in redacted text: %s\n", result->redacted_text);
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    redaction_result_destroy(result);
    
    // Test path without username
    const char* path_without_user = "/etc/ssl/certs/cert.pem";
    result = privacy_redact_username(context, path_without_user);
    
    if (!result) {
        printf("FAILED - Could not process path without username\n");
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    if (result->was_redacted) {
        printf("FAILED - Path without username should not be redacted\n");
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    redaction_result_destroy(result);
    privacy_context_destroy(context);
    free(config.salt);
    
    printf("PASSED\n");
    return true;
}

// Test home path redaction
static bool test_home_path_redaction(void) {
    printf("Running test: home_path_redaction... ");
    
    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup("0123456789abcdef0123456789abcdef");
    config.salt_length = strlen(config.salt);
    
    privacy_context_t* context = privacy_context_create(&config);
    if (!context) {
        printf("FAILED - Could not create privacy context\n");
        free(config.salt);
        return false;
    }
    
    // Test home directory path
    const char* home_path = "/home/bob/private/key.pem";
    redaction_result_t* result = privacy_redact_home_path(context, home_path);
    
    if (!result) {
        printf("FAILED - Could not redact home path\n");
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    if (!result->was_redacted) {
        printf("FAILED - Home path should have been redacted\n");
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Check that specific username is not in redacted text
    if (strstr(result->redacted_text, "bob")) {
        printf("FAILED - Username still present in redacted home path: %s\n", result->redacted_text);
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    redaction_result_destroy(result);
    privacy_context_destroy(context);
    free(config.salt);
    
    printf("PASSED\n");
    return true;
}

// Test secret detection
static bool test_secret_detection(void) {
    printf("Running test: secret_detection... ");
    
    // Test PEM header detection
    const char* pem_content = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAK...";
    if (!privacy_contains_secrets(pem_content)) {
        printf("FAILED - Should detect PEM header as secret\n");
        return false;
    }
    
    // Test private key detection
    const char* private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...";
    if (!privacy_contains_secrets(private_key)) {
        printf("FAILED - Should detect private key as secret\n");
        return false;
    }
    
    // Test normal text
    const char* normal_text = "This is just normal text without secrets";
    if (privacy_contains_secrets(normal_text)) {
        printf("FAILED - Should not detect normal text as secret\n");
        return false;
    }
    
    printf("PASSED\n");
    return true;
}

// Test evidence sanitization
static bool test_evidence_sanitization(void) {
    printf("Running test: evidence_sanitization... ");
    
    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup("0123456789abcdef0123456789abcdef");
    config.salt_length = strlen(config.salt);
    
    privacy_context_t* context = privacy_context_create(&config);
    if (!context) {
        printf("FAILED - Could not create privacy context\n");
        free(config.salt);
        return false;
    }
    
    // Test evidence with secrets
    const char* evidence_with_secret = "Found certificate: -----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAK...";
    redaction_result_t* result = privacy_sanitize_evidence(context, evidence_with_secret);
    
    if (!result) {
        printf("FAILED - Could not sanitize evidence\n");
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    if (!result->was_redacted) {
        printf("FAILED - Evidence with secrets should be redacted\n");
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Check that PEM content is not in sanitized evidence
    if (strstr(result->redacted_text, "-----BEGIN CERTIFICATE-----")) {
        printf("FAILED - PEM content still present in sanitized evidence\n");
        redaction_result_destroy(result);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    redaction_result_destroy(result);
    privacy_context_destroy(context);
    free(config.salt);
    
    printf("PASSED\n");
    return true;
}

// Test consistent hashing
static bool test_consistent_hashing(void) {
    printf("Running test: consistent_hashing... ");
    
    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup("0123456789abcdef0123456789abcdef");
    config.salt_length = strlen(config.salt);
    
    privacy_context_t* context = privacy_context_create(&config);
    if (!context) {
        printf("FAILED - Could not create privacy context\n");
        free(config.salt);
        return false;
    }
    
    const char* input = "test_input";
    
    // Hash same input multiple times
    char* hash1 = privacy_hash_with_salt(context, input);
    char* hash2 = privacy_hash_with_salt(context, input);
    
    if (!hash1 || !hash2) {
        printf("FAILED - Could not generate hashes\n");
        if (hash1) free(hash1);
        if (hash2) free(hash2);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Should be identical
    if (strcmp(hash1, hash2) != 0) {
        printf("FAILED - Same input should produce same hash\n");
        free(hash1);
        free(hash2);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Hash different input
    char* hash3 = privacy_hash_with_salt(context, "different_input");
    if (!hash3) {
        printf("FAILED - Could not generate hash for different input\n");
        free(hash1);
        free(hash2);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Should be different
    if (strcmp(hash1, hash3) == 0) {
        printf("FAILED - Different inputs should produce different hashes\n");
        free(hash1);
        free(hash2);
        free(hash3);
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    free(hash1);
    free(hash2);
    free(hash3);
    privacy_context_destroy(context);
    free(config.salt);
    
    printf("PASSED\n");
    return true;
}

// Test referential integrity
static bool test_referential_integrity(void) {
    printf("Running test: referential_integrity... ");
    
    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup("0123456789abcdef0123456789abcdef");
    config.salt_length = strlen(config.salt);
    
    privacy_context_t* context = privacy_context_create(&config);
    if (!context) {
        printf("FAILED - Could not create privacy context\n");
        free(config.salt);
        return false;
    }
    
    // Test consistent mapping
    const char* inputs[] = {"input1", "input2", "input1", "input3"};
    const char* outputs[] = {"output1", "output2", "output1", "output3"};
    
    if (!privacy_validate_referential_integrity(context, inputs, outputs, 4)) {
        printf("FAILED - Valid referential integrity should pass\n");
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    // Test inconsistent mapping
    const char* bad_outputs[] = {"output1", "output2", "different_output", "output3"};
    
    if (privacy_validate_referential_integrity(context, inputs, bad_outputs, 4)) {
        printf("FAILED - Invalid referential integrity should fail\n");
        privacy_context_destroy(context);
        free(config.salt);
        return false;
    }
    
    privacy_context_destroy(context);
    free(config.salt);
    
    printf("PASSED\n");
    return true;
}

// Main test runner
int run_privacy_tests(void) {
    int passed = 0;
    int total = 9; // Fixed count
    
    if (test_privacy_context_creation()) passed++;
    if (test_salt_validation()) passed++;
    if (test_salt_generation()) passed++;
    if (test_username_redaction()) passed++;
    if (test_home_path_redaction()) passed++;
    if (test_secret_detection()) passed++;
    if (test_evidence_sanitization()) passed++;
    if (test_consistent_hashing()) passed++;
    if (test_referential_integrity()) passed++;
    
    printf("Tests run: %d, Passed: %d\n", total, passed);
    
    if (passed == total) {
        printf("Privacy tests PASSED!\n");
        return 0;
    } else {
        printf("Privacy tests FAILED!\n");
        return 1;
    }
}
