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

#ifndef ALGORITHM_METADATA_H
#define ALGORITHM_METADATA_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cryptographic primitive types
typedef enum {
    PRIMITIVE_SYMMETRIC_CIPHER,  // AES, ChaCha20, 3DES
    PRIMITIVE_ASYMMETRIC_CIPHER, // RSA encryption
    PRIMITIVE_HASH_FUNCTION,     // SHA-256, SHA-1, MD5
    PRIMITIVE_MAC,               // HMAC, CMAC
    PRIMITIVE_SIGNATURE,         // RSA, ECDSA, Ed25519
    PRIMITIVE_KEY_EXCHANGE,      // ECDH, DH, RSA-KEM
    PRIMITIVE_KDF,               // PBKDF2, HKDF
    PRIMITIVE_RNG,               // DRBG, hardware RNG
    PRIMITIVE_UNKNOWN
} crypto_primitive_t;

// Block cipher modes
typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CTR,
    MODE_GCM,
    MODE_CCM,
    MODE_CFB,
    MODE_OFB,
    MODE_XTS,
    MODE_NONE,
    MODE_UNKNOWN
} cipher_mode_t;

// Padding schemes
typedef enum {
    PADDING_PKCS1,      // PKCS#1 v1.5
    PADDING_OAEP,       // PKCS#1 OAEP
    PADDING_PSS,        // PKCS#1 PSS
    PADDING_PKCS7,      // PKCS#7 padding
    PADDING_NONE,
    PADDING_UNKNOWN
} padding_scheme_t;

// NIST quantum security categories (NIST IR 8413)
typedef enum {
    QUANTUM_CAT_0 = 0,  // No quantum security (broken)
    QUANTUM_CAT_1 = 1,  // AES-128, SHA-256
    QUANTUM_CAT_2 = 2,  // AES-192
    QUANTUM_CAT_3 = 3,  // AES-256, SHA-384
    QUANTUM_CAT_4 = 4,  // SHA-512
    QUANTUM_CAT_5 = 5,  // Highest security
    QUANTUM_CAT_UNKNOWN = -1
} quantum_security_category_t;

// Algorithm context for context-aware classification (Phase 1.5)
// RSA can be signature OR encryption depending on usage
typedef enum {
    ALGO_CONTEXT_CERTIFICATE_SIGNATURE,  // Algorithm used for certificate signatures
    ALGO_CONTEXT_KEY_ENCRYPTION,         // Algorithm used for key exchange/encryption
    ALGO_CONTEXT_CIPHER_SUITE,           // Algorithm in TLS/SSH cipher suite
    ALGO_CONTEXT_GENERAL,                // Multi-purpose or unknown context
    ALGO_CONTEXT_UNKNOWN
} algorithm_context_t;

// CycloneDX algorithm properties structure (static const data)
// This maps algorithm names to CycloneDX algorithmProperties fields
// Per OWASP CycloneDX Authoritative Guide to CBOM (Second Edition, October 2025)
typedef struct {
    const char* algorithm_name;          // Canonical algorithm name (e.g., "RSA-2048")
    const char* algorithm_family;        // Algorithm family (e.g., "AES", "RSA", "ECDH", "ML-KEM")
    const char* cdx_primitive;           // CycloneDX primitive: "signature", "hash", "ae", etc.
    const char* mode;                    // Cipher mode: "gcm", "cbc", "ctr", etc.
    const char* padding;                 // Padding scheme: "pkcs7", "oaep", etc.
    const char* curve;                   // ECC curve: "P-256", "P-384", "curve25519", etc.
    const char* const* crypto_functions; // NULL-terminated array: ["sign", "verify", NULL]
    int key_size;                        // Key size in bits
    int security_bits;                   // Classical security strength (NIST SP 800-57)
    int nist_quantum_security_level;     // NIST quantum security level (0, 1, 3, 5)
    const char* certification_level;     // Certification: "none", "fips140-3-l1", etc.
    algorithm_context_t context;         // Usage context (for multi-use algorithms)
} algorithm_cdx_properties_t;

// Granular algorithm metadata
typedef struct {
    // Core identification
    char* algorithm_name;        // Full algorithm name (e.g., "RSA", "AES-256-GCM")
    char* primitive;             // Primitive type name (e.g., "RSA", "AES")
    crypto_primitive_t primitive_type;  // Primitive enum

    // Operational details
    char* mode;                  // Mode of operation (e.g., "GCM", "CBC")
    cipher_mode_t mode_type;     // Mode enum
    char* padding;               // Padding scheme (e.g., "OAEP", "PSS")
    padding_scheme_t padding_type;  // Padding enum

    // Key/parameter details
    int key_len;                 // Key length in bits (e.g., 256, 2048, 384)
    char* key_len_str;           // Key length as string
    char* oid;                   // ASN.1 Object Identifier
    char* parameters;            // Additional parameters (e.g., curve name, salt length)

    // Security strength
    int security_bits;           // Classical security strength (NIST SP 800-57)
    quantum_security_category_t quantum_category;  // Quantum security category
    bool is_pqc_safe;            // Post-quantum safe
    bool is_deprecated;          // Deprecated/weak algorithm

    // Usage context
    char* usage_context;         // Where/how used (e.g., "signature", "encryption", "key-exchange")
} algorithm_granular_t;

// Algorithm metadata functions
algorithm_granular_t* algorithm_metadata_create(void);
void algorithm_metadata_destroy(algorithm_granular_t* metadata);

// Parse algorithm from X.509 certificate
algorithm_granular_t* algorithm_parse_from_x509_public_key(void* x509_cert);
algorithm_granular_t* algorithm_parse_from_x509_signature(void* x509_cert);

// Parse algorithm from OID
algorithm_granular_t* algorithm_parse_from_oid(const char* oid);

// OID mapping functions
const char* algorithm_oid_to_name(const char* oid);
const char* algorithm_name_to_oid(const char* name);
crypto_primitive_t algorithm_get_primitive_type(const char* algorithm_name);

// Security strength calculation
int algorithm_calculate_security_bits(const algorithm_granular_t* metadata);
quantum_security_category_t algorithm_get_quantum_category(const algorithm_granular_t* metadata);
bool algorithm_is_pqc_safe(const algorithm_granular_t* metadata);
bool algorithm_is_deprecated(const algorithm_granular_t* metadata);

// String conversion utilities
const char* primitive_type_to_string(crypto_primitive_t type);
const char* cipher_mode_to_string(cipher_mode_t mode);
const char* padding_scheme_to_string(padding_scheme_t padding);
const char* quantum_category_to_string(quantum_security_category_t category);

// JSON export
void* algorithm_to_json_properties(const algorithm_granular_t* metadata);  // Returns json_object*

// ============================================================================
// CycloneDX algorithmProperties support (Phase 1 - Algorithm Properties Enhancement)
// ============================================================================

/**
 * Get CycloneDX algorithm properties for a given algorithm name.
 *
 * Returns pointer to STATIC metadata structure.
 * DO NOT FREE the returned pointer.
 * The crypto_functions array points to static string literals.
 * Lifetime: entire program execution.
 *
 * @param algo_name Algorithm name (e.g., "RSA-2048", "AES-256-GCM")
 * @param context   Usage context for multi-use algorithms (e.g., RSA)
 * @return Pointer to static properties, or NULL if unknown algorithm
 */
const algorithm_cdx_properties_t* algorithm_get_cdx_properties(
    const char* algo_name,
    algorithm_context_t context
);

/**
 * Normalize algorithm name to canonical form.
 * Handles variations like "RSA-2048", "RSA2048", "rsaEncryption".
 *
 * @param input     Input algorithm name
 * @param output    Output buffer for canonical name
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int algorithm_normalize_name(const char* input, char* output, size_t output_len);

/**
 * Get CycloneDX algorithmProperties as JSON string.
 * Caller must free the returned string.
 *
 * @param algo_name Algorithm name
 * @param context   Usage context
 * @return JSON string with algorithmProperties, or NULL on error
 */
char* algorithm_get_cdx_properties_json(const char* algo_name, algorithm_context_t context);

/**
 * Populate metadata_json field of crypto_asset with CycloneDX algorithmProperties.
 * This merges with existing metadata if present.
 *
 * @param metadata_json Pointer to metadata_json string (may be NULL)
 * @param algo_name     Algorithm name
 * @param context       Usage context
 * @return Updated metadata_json string (caller must free), or NULL on error
 */
char* algorithm_populate_cdx_metadata(const char* existing_metadata,
                                       const char* algo_name,
                                       algorithm_context_t context);

#ifdef __cplusplus
}
#endif

#endif // ALGORITHM_METADATA_H
