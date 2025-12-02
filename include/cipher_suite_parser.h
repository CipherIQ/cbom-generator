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

#ifndef CIPHER_SUITE_PARSER_H
#define CIPHER_SUITE_PARSER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Forward declarations
struct crypto_asset;

// Cipher suite metadata structure
typedef struct {
    char* name;                    // IANA name (TLS_AES_256_GCM_SHA384)
    char* openssl_name;            // OpenSSL name (ECDHE-RSA-AES256-GCM-SHA384)
    char* protocol_family;         // "TLS", "SSH"
    char* protocol_version;        // "1.3", "1.2", "2.0"

    // Phase 4: CycloneDX conformance fields
    char* iana_id;                 // IANA hex identifier (e.g., "0x13,0x02")
    char** algorithm_refs;         // Array of algorithm bom-refs
    size_t algorithm_count;        // Number of algorithm references

    // Algorithm components
    char* kex_algorithm;           // "ECDHE", "DHE", "RSA", "curve25519"
    char* auth_algorithm;          // "RSA", "ECDSA", "PSK"
    char* encryption_algorithm;    // "AES-256", "ChaCha20"
    char* encryption_mode;         // "GCM", "CBC", "CCM"
    char* mac_algorithm;           // "SHA384", "SHA256", "POLY1305"

    // Security properties
    uint32_t security_strength;    // Bits (e.g., 256, 128)
    bool is_aead;                  // Authenticated encryption
    bool is_quantum_vulnerable;    // Vulnerable to quantum attacks
    bool is_deprecated;            // Deprecated/weak cipher

    // PQC assessment (Phase 8.0)
    int pqc_category;              // pqc_category_t from pqc_classifier.h
    char* pqc_alternative;         // Suggested PQC replacement
    int pqc_urgency;               // pqc_urgency_t from pqc_classifier.h

    // Detection context
    char* config_file_path;        // Where detected
    int line_number;               // Line in config
    char* detection_method;        // "config_parser"
    float confidence;              // 0.0-1.0
} cipher_suite_metadata_t;

// OpenSSL cipher list parser (Phase 7.3b - subset grammar)
char** parse_openssl_cipher_list(const char* cipher_string, size_t* count);

// Parse cipher list string and create suite metadata array
cipher_suite_metadata_t** parse_cipher_list_to_suites(const char* cipher_string,
                                                      const char* protocol_version,
                                                      const char* config_file_path,
                                                      size_t* count);

// Cipher suite metadata extraction
cipher_suite_metadata_t* parse_cipher_suite(const char* cipher_name,
                                            const char* protocol_family,
                                            const char* protocol_version);

// Name mapping
const char* openssl_to_iana_name(const char* openssl_name);
const char* iana_to_openssl_name(const char* iana_name);

// Component extraction
char* extract_kex_algorithm(const char* cipher_name);
char* extract_auth_algorithm(const char* cipher_name);
char* extract_encryption_algorithm(const char* cipher_name);
char* extract_mac_algorithm(const char* cipher_name);

// Security analysis
uint32_t calculate_cipher_suite_strength(const cipher_suite_metadata_t* suite);
bool is_cipher_suite_quantum_vulnerable(const cipher_suite_metadata_t* suite);
bool is_cipher_suite_deprecated(const cipher_suite_metadata_t* suite);
bool is_cipher_suite_weak(const char* cipher_name);

// PQC assessment (Phase 8.0)
void assess_cipher_suite_pqc(cipher_suite_metadata_t* suite);

// Asset creation
struct crypto_asset* cipher_suite_create_asset(const cipher_suite_metadata_t* metadata);
char* cipher_suite_create_json_metadata(const cipher_suite_metadata_t* metadata);

// Metadata management
cipher_suite_metadata_t* cipher_suite_metadata_create(const char* name);
void cipher_suite_metadata_destroy(cipher_suite_metadata_t* metadata);

// Utility functions
bool is_tls13_cipher(const char* cipher_name);
bool is_aead_cipher(const char* cipher_name);
const char* get_cipher_suite_family(const char* cipher_name);

// Get all TLS 1.3 cipher suites (fixed list for Phase 7.3a)
cipher_suite_metadata_t** get_all_tls13_suites(size_t* count, const char* config_file_path);

#endif // CIPHER_SUITE_PARSER_H
