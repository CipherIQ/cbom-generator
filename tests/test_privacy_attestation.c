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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "privacy.h"
#include "slsa_provenance.h"
#include "attestation.h"
#include "secure_memory.h"

// Test privacy default configuration
void test_privacy_default_config(void) {
    printf("Testing privacy default configuration...\n");

    privacy_config_t config = privacy_get_default_config();
    (void)config;  // Used in assertions

    assert(config.no_personal_data == true);  // Privacy-by-default
    assert(config.redact_usernames == true);
    assert(config.redact_home_paths == true);
    assert(config.redact_hostnames == true);
    assert(config.sanitize_evidence == true);

    printf("  ✓ Privacy default configuration correct\n");
}

// Test hostname redaction
void test_hostname_redaction(void) {
    printf("Testing hostname redaction...\n");

    // Set up test salt
    const char* test_salt = "test_salt_with_enough_entropy_1234567890";

    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup(test_salt);
    config.salt_length = strlen(test_salt);

    privacy_context_t* context = privacy_context_create(&config);
    assert(context != NULL);
    assert(context->initialized == true);

    // Test hostname detection
    const char* test_text = "user@example.com";
    assert(contains_hostname(test_text) == true);

    // Test hostname extraction
    char* hostname = extract_hostname_from_text(test_text);
    assert(hostname != NULL);
    assert(strcmp(hostname, "example.com") == 0);
    secure_free(hostname, strlen(hostname));

    // Test hostname redaction
    redaction_result_t* result = privacy_redact_hostname(context, test_text);
    assert(result != NULL);
    assert(result->was_redacted == true);
    assert(strstr(result->redacted_text, "example.com") == NULL);
    assert(strstr(result->redacted_text, "<host-") != NULL);

    redaction_result_destroy(result);
    privacy_context_destroy(context);
    // Note: config.salt is freed by privacy_context_destroy()

    printf("  ✓ Hostname redaction working correctly\n");
}

// Test pseudonymization with consistent hashing
void test_pseudonymization(void) {
    printf("Testing pseudonymization with consistent hashing...\n");

    const char* test_salt = "test_salt_with_enough_entropy_1234567890";

    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup(test_salt);
    config.salt_length = strlen(test_salt);

    privacy_context_t* context = privacy_context_create(&config);
    assert(context != NULL);

    // Test hostname pseudonymization
    char* pseudo1 = privacy_pseudonymize_hostname(context, "example.com");
    char* pseudo2 = privacy_pseudonymize_hostname(context, "example.com");
    assert(pseudo1 != NULL && pseudo2 != NULL);
    assert(strcmp(pseudo1, pseudo2) == 0);  // Consistent hashing
    free(pseudo1);
    free(pseudo2);

    // Test path pseudonymization
    char* path1 = privacy_pseudonymize_path(context, "/etc/ssl/certs/test.pem");
    char* path2 = privacy_pseudonymize_path(context, "/etc/ssl/certs/test.pem");
    assert(path1 != NULL && path2 != NULL);
    assert(strcmp(path1, path2) == 0);  // Consistent hashing
    free(path1);
    free(path2);

    privacy_context_destroy(context);
    // Note: config.salt is freed by privacy_context_destroy()

    printf("  ✓ Pseudonymization produces consistent hashes\n");
}

// Test file path redaction
void test_file_path_redaction(void) {
    printf("Testing file path redaction...\n");

    const char* test_salt = "test_salt_with_enough_entropy_1234567890";

    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup(test_salt);
    config.salt_length = strlen(test_salt);

    privacy_context_t* context = privacy_context_create(&config);
    assert(context != NULL);

    // Test home path redaction
    const char* test_path = "/home/testuser/documents/cert.pem";
    redaction_result_t* result = privacy_redact_file_path(context, test_path);

    assert(result != NULL);
    assert(result->was_redacted == true);
    assert(strstr(result->redacted_text, "testuser") == NULL);

    redaction_result_destroy(result);
    privacy_context_destroy(context);
    // Note: config.salt is freed by privacy_context_destroy()

    printf("  ✓ File path redaction working correctly\n");
}

// Test secret detection and sanitization
void test_secret_sanitization(void) {
    printf("Testing secret sanitization...\n");

    const char* test_salt = "test_salt_with_enough_entropy_1234567890";

    privacy_config_t config = privacy_get_default_config();
    config.salt = strdup(test_salt);
    config.salt_length = strlen(test_salt);

    privacy_context_t* context = privacy_context_create(&config);
    assert(context != NULL);

    // Test PEM header detection
    const char* pem_text = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkW...";
    (void)pem_text;  // Used in assertions below
    assert(privacy_contains_secrets(pem_text) == true);

    // Test private key detection
    const char* key_text = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk...";
    assert(privacy_contains_secrets(key_text) == true);

    // Test redaction of private keys
    redaction_result_t* result = privacy_redact_private_keys(context, key_text);
    assert(result != NULL);
    assert(result->was_redacted == true);
    assert(strstr(result->redacted_text, "PRIVATE KEY") == NULL);
    assert(strstr(result->redacted_text, "[REDACTED") != NULL);

    redaction_result_destroy(result);
    privacy_context_destroy(context);
    // Note: config.salt is freed by privacy_context_destroy()

    printf("  ✓ Secret sanitization working correctly\n");
}

// Test SLSA provenance default configuration
void test_slsa_default_config(void) {
    printf("Testing SLSA provenance default configuration...\n");

    slsa_provenance_config_t config = slsa_get_default_config();
    (void)config;  // Used in assertions

    assert(config.reproducible == true);
    assert(config.dependency_count == 0);

    printf("  ✓ SLSA default configuration correct\n");
}

// Test SLSA git information retrieval
void test_slsa_git_info(void) {
    printf("Testing SLSA git information retrieval...\n");

    char* commit_sha = slsa_get_git_commit_sha();
    // May be NULL if not in git repository
    if (commit_sha) {
        assert(strlen(commit_sha) == 40);  // Git SHA-1 is 40 hex chars
        free(commit_sha);
    }

    char* repository = slsa_get_git_repository();
    if (repository) {
        free(repository);
    }

    char* branch = slsa_get_git_branch();
    if (branch) {
        free(branch);
    }

    printf("  ✓ SLSA git information retrieval working\n");
}

// Test SLSA build metadata
void test_slsa_build_metadata(void) {
    printf("Testing SLSA build metadata...\n");

    char* timestamp = slsa_get_build_timestamp();
    assert(timestamp != NULL);
    assert(strlen(timestamp) > 0);
    // Should be ISO 8601 format
    assert(strstr(timestamp, "T") != NULL);
    assert(strstr(timestamp, "Z") != NULL);
    secure_free(timestamp, strlen(timestamp));

    char* platform = slsa_get_build_platform();
    assert(platform != NULL);
    assert(strlen(platform) > 0);
    secure_free(platform, strlen(platform));

    printf("  ✓ SLSA build metadata generation working\n");
}

// Test SLSA provenance generation
void test_slsa_provenance_generation(void) {
    printf("Testing SLSA provenance generation...\n");

    slsa_provenance_config_t config = slsa_get_default_config();
    slsa_populate_config_from_env(&config);

    slsa_provenance_context_t* context = slsa_provenance_create(&config);
    assert(context != NULL);
    assert(context->initialized == true);

    // Generate provenance
    json_object* provenance = slsa_generate_provenance(context, "test.json",
                                                        "abc123def456");
    assert(provenance != NULL);

    // Verify structure
    json_object* type_obj = NULL;
    assert(json_object_object_get_ex(provenance, "_type", &type_obj));
    const char* type_str = json_object_get_string(type_obj);
    (void)type_str;  // Used in assertion
    assert(strstr(type_str, "slsa.dev/provenance") != NULL);

    json_object* subject_obj = NULL;
    (void)subject_obj;  // Retrieved for validation
    assert(json_object_object_get_ex(provenance, "subject", &subject_obj));

    json_object* predicate_obj = NULL;
    (void)predicate_obj;  // Retrieved for validation
    assert(json_object_object_get_ex(provenance, "predicate", &predicate_obj));

    json_object_put(provenance);
    slsa_provenance_destroy(context);

    // Note: config strings are freed by slsa_provenance_destroy()
    // No need to free them here (they were copied by slsa_provenance_create)

    printf("  ✓ SLSA provenance generation working\n");
}

// Test attestation default configuration
void test_attestation_default_config(void) {
    printf("Testing attestation default configuration...\n");

    attestation_config_t config = attestation_get_default_config();
    (void)config;  // Used in assertions

    assert(config.method == SIGNATURE_METHOD_DSSE);
    assert(config.include_slsa == true);
    assert(config.signing_key_path == NULL);
    assert(config.key_password == NULL);

    printf("  ✓ Attestation default configuration correct\n");
}

// Test base64 encoding/decoding
void test_base64_encoding(void) {
    printf("Testing base64 encoding/decoding...\n");

    const char* test_data = "Hello, World! This is a test.";
    size_t test_len = strlen(test_data);

    // Encode
    char* encoded = attestation_base64_encode((unsigned char*)test_data, test_len);
    assert(encoded != NULL);
    assert(strlen(encoded) > 0);

    // Decode
    size_t decoded_len = 0;
    unsigned char* decoded = attestation_base64_decode(encoded, &decoded_len);
    assert(decoded != NULL);
    assert(decoded_len == test_len);
    assert(memcmp(decoded, test_data, test_len) == 0);

    free(encoded);
    free(decoded);

    printf("  ✓ Base64 encoding/decoding working correctly\n");
}

// Test SHA-256 computation
void test_sha256_computation(void) {
    printf("Testing SHA-256 computation...\n");

    const char* test_data = "test data";
    char* hash = attestation_compute_sha256((unsigned char*)test_data, strlen(test_data));

    assert(hash != NULL);
    assert(strlen(hash) == 64);  // SHA-256 is 64 hex characters

    // Verify consistency
    char* hash2 = attestation_compute_sha256((unsigned char*)test_data, strlen(test_data));
    assert(hash2 != NULL);
    assert(strcmp(hash, hash2) == 0);

    free(hash);
    free(hash2);

    printf("  ✓ SHA-256 computation working correctly\n");
}

// Test DSSE envelope creation
void test_dsse_envelope_creation(void) {
    printf("Testing DSSE envelope creation...\n");

    const char* test_payload = "{\"test\":\"data\"}";
    const char* payload_type = "application/json";

    dsse_envelope_t* envelope = dsse_create_envelope(test_payload, payload_type);
    assert(envelope != NULL);
    assert(envelope->payload != NULL);
    assert(envelope->payloadType != NULL);
    assert(strcmp(envelope->payloadType, payload_type) == 0);
    assert(envelope->signature_count == 0);

    // Convert to JSON
    json_object* json = dsse_envelope_to_json(envelope);
    assert(json != NULL);

    json_object* payload_obj = NULL;
    (void)payload_obj;  // Retrieved for validation
    assert(json_object_object_get_ex(json, "payload", &payload_obj));

    json_object* payload_type_obj = NULL;
    (void)payload_type_obj;  // Retrieved for validation
    assert(json_object_object_get_ex(json, "payloadType", &payload_type_obj));

    json_object_put(json);
    dsse_envelope_destroy(envelope);

    printf("  ✓ DSSE envelope creation working correctly\n");
}

// Test runner
int main(void) {
    printf("\n=== Privacy and Attestation Test Suite ===\n\n");

    // Initialize secure memory system
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory\n");
        return 1;
    }

    test_privacy_default_config();
    test_hostname_redaction();
    test_pseudonymization();
    test_file_path_redaction();
    test_secret_sanitization();
    test_slsa_default_config();
    test_slsa_git_info();
    test_slsa_build_metadata();
    test_slsa_provenance_generation();
    test_attestation_default_config();
    test_base64_encoding();
    test_sha256_computation();
    test_dsse_envelope_creation();

    printf("\n=== All Privacy and Attestation Tests Passed ===\n\n");

    // Cleanup secure memory
    // Note: Do not cleanup regex patterns - they are static globals and
    // cleanup can cause issues when called from test context
    secure_memory_cleanup();

    return 0;
}
