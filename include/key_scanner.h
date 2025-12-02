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

#ifndef KEY_SCANNER_H
#define KEY_SCANNER_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <time.h>
#include <stddef.h>

// Forward declarations
struct asset_store;
struct crypto_asset;
struct scan_context;

// Key types enumeration
typedef enum {
    KEY_TYPE_RSA,                    // RSA key
    KEY_TYPE_ECDSA,                  // ECDSA key
    KEY_TYPE_ED25519,                // Ed25519 key
    KEY_TYPE_ED448,                  // Ed448 key
    KEY_TYPE_DSA,                    // DSA key (legacy)
    KEY_TYPE_DH,                     // Diffie-Hellman key
    KEY_TYPE_AES,                    // AES symmetric key
    KEY_TYPE_CHACHA20,               // ChaCha20 symmetric key
    KEY_TYPE_HMAC,                   // HMAC key
    KEY_TYPE_GENERIC_SECRET,         // Generic secret key
    KEY_TYPE_UNKNOWN
} key_type_t;

// Key format enumeration
typedef enum {
    KEY_FORMAT_PEM,                  // PEM format (BEGIN/END blocks)
    KEY_FORMAT_DER,                  // DER binary format
    KEY_FORMAT_OPENSSH,              // OpenSSH format (ssh-rsa, ssh-ed25519, etc.)
    KEY_FORMAT_PKCS8,                // PKCS#8 format
    KEY_FORMAT_PKCS1,                // PKCS#1 format (RSA only)
    KEY_FORMAT_SEC1,                 // SEC1 format (EC only)
    KEY_FORMAT_RAW,                  // Raw key bytes
    KEY_FORMAT_UNKNOWN
} key_format_t;

// Key storage security level
typedef enum {
    STORAGE_PLAINTEXT,               // Plaintext key file
    STORAGE_ENCRYPTED,               // Password-protected/encrypted key
    STORAGE_HSM,                     // Hardware Security Module
    STORAGE_TPM,                     // Trusted Platform Module
    STORAGE_KEYRING,                 // OS keyring/keychain
    STORAGE_UNKNOWN
} storage_security_t;

// Key classification (private/public/symmetric)
typedef enum {
    KEY_CLASS_PRIVATE,               // Private key
    KEY_CLASS_PUBLIC,                // Public key
    KEY_CLASS_SYMMETRIC,             // Symmetric key
    KEY_CLASS_PAIR,                  // Key pair (both private and public)
    KEY_CLASS_UNKNOWN
} key_class_t;

// Key state enumeration (NIST SP 800-57 lifecycle states)
typedef enum {
    KEY_STATE_PRE_ACTIVATION,        // Generated but not yet active
    KEY_STATE_ACTIVE,                // Currently in use
    KEY_STATE_SUSPENDED,             // Temporarily inactive
    KEY_STATE_DEACTIVATED,           // No longer used for protection
    KEY_STATE_COMPROMISED,           // Security breach suspected
    KEY_STATE_DESTROYED,             // Permanently removed
    KEY_STATE_UNKNOWN
} key_state_t;

// Key parsing failure reasons
typedef enum {
    KEY_FAIL_INVALID_PEM_BLOCK,      // Bad BEGIN/END, base64 decode fail
    KEY_FAIL_DER_TRUNCATED,          // DER truncated
    KEY_FAIL_DER_OVERLONG,           // DER overlong
    KEY_FAIL_ENCRYPTED_NO_PASSWORD,  // Encrypted key without password
    KEY_FAIL_WRONG_PASSWORD,         // Incorrect password
    KEY_FAIL_UNSUPPORTED_ENCRYPTION, // Unsupported encryption algorithm
    KEY_FAIL_UNSUPPORTED_KEY_TYPE,   // Unsupported key type
    KEY_FAIL_TOO_LARGE,              // Size caps exceeded
    KEY_FAIL_TIMEOUT,                // Per-file timeout
    KEY_FAIL_SANITY_LIMIT_HIT,       // Recursion/size limits
    KEY_FAIL_MEMORY_ERROR,           // Memory allocation failure
    KEY_FAIL_IO_ERROR,               // File I/O error
    KEY_FAIL_UNKNOWN,                // Unknown error
    KEY_FAIL_REASON_COUNT            // Total number of failure reasons
} key_failure_reason_t;

// Key lifecycle metadata
typedef struct {
    time_t creation_date;            // Key creation date (0 if unknown)
    time_t activation_date;          // Key activation date (0 if unknown)
    time_t expiration_date;          // Key expiration date (0 if unknown)
    time_t last_rotation_date;       // Last rotation date (0 if unknown)
    bool has_expiration;             // Whether key has expiration
    bool is_expired;                 // Whether key is expired
    int days_until_expiration;       // Days until expiration (-1 if N/A)
} key_lifecycle_t;

// Key encryption/protection metadata (for securedBy property)
typedef struct {
    char* mechanism;                 // Protection mechanism ("Software", "Hardware", "HSM")
    char* algorithm_ref;             // bom-ref of encryption algorithm (if encrypted)
} secured_by_t;

// Key usage enumeration
typedef enum {
    KEY_USAGE_ENCRYPTION,            // Encryption/decryption
    KEY_USAGE_SIGNING,               // Digital signatures
    KEY_USAGE_KEY_AGREEMENT,         // Key exchange/agreement
    KEY_USAGE_AUTHENTICATION,        // Authentication
    KEY_USAGE_CERTIFICATE,           // Associated with certificate
    KEY_USAGE_SSH,                   // SSH authentication
    KEY_USAGE_TLS,                   // TLS/SSL
    KEY_USAGE_CODE_SIGNING,          // Code signing
    KEY_USAGE_UNKNOWN
} key_usage_t;

// Key metadata structure
typedef struct {
    key_type_t type;                 // Key type (RSA, ECDSA, etc.)
    key_class_t classification;      // Private/public/symmetric
    key_format_t format;             // Key format (PEM, DER, etc.)
    storage_security_t storage;      // Storage security level

    // CycloneDX conformance fields (Phase 3)
    key_state_t state;               // Key state (NIST SP 800-57 lifecycle)
    char* algorithm_ref;             // Algorithm bom-ref for relatedCryptoMaterialProperties
    char* oid;                       // Algorithm OID (at cryptoProperties level)
    secured_by_t* secured_by;        // Encryption protection metadata (NULL if not encrypted)

    // Key parameters
    int key_size;                    // Key size in bits
    char* algorithm;                 // Algorithm name (e.g., "RSA-2048", "ECDSA-P256")
    char* curve_name;                // EC curve name (if applicable)
    char* curve_oid;                 // EC curve OID (if applicable)

    // Key identifiers (hashes only, never raw material)
    char* key_id_sha256;             // SHA-256 hash of key material
    char* public_key_hash;           // SHA-256 hash of public key
    char* fingerprint;               // Key fingerprint (format-specific)

    // File information
    char* file_path;                 // Path to key file
    char* file_path_hash;            // Hashed path (privacy mode)
    bool is_encrypted;               // Whether key file is encrypted

    // Lifecycle information
    key_lifecycle_t lifecycle;       // Lifecycle metadata

    // Usage information
    key_usage_t* usages;             // Array of usage types
    size_t usage_count;              // Number of usages

    // Associated certificate (if any)
    char* associated_cert_id;        // Certificate asset ID (if linked)

    // Weakness detection
    bool is_weak;                    // Overall weakness flag
    bool weak_key_size;              // Key size below recommended threshold
    char** weak_reasons;             // Array of weakness descriptions
    size_t weak_reason_count;        // Number of weakness reasons

    // Detection metadata
    char* detection_method;          // How key was detected
    float confidence;                // Detection confidence (0.0-1.0)
    time_t scan_time;                // When key was scanned
} key_metadata_t;

// Key scanner statistics
typedef struct {
    // File-level counters
    size_t files_scanned_total;
    size_t files_with_keys;          // Files containing keys

    // Key-level counters
    size_t keys_detected_total;      // Total keys detected
    size_t keys_parsed_ok;           // Successfully parsed keys
    size_t keys_failed_total;        // Failed to parse keys
    size_t keys_failed_by_reason[KEY_FAIL_REASON_COUNT]; // Failures by reason

    // Format breakdown
    size_t pem_detected;
    size_t der_detected;
    size_t openssh_detected;
    size_t pem_parsed_ok;
    size_t der_parsed_ok;
    size_t openssh_parsed_ok;

    // Key classification counters
    size_t private_keys_found;
    size_t public_keys_found;
    size_t symmetric_keys_found;
    size_t key_pairs_found;

    // Key type counters
    size_t rsa_keys;
    size_t ecdsa_keys;
    size_t ed25519_keys;
    size_t dsa_keys;
    size_t dh_keys;

    // Storage security counters
    size_t plaintext_keys;
    size_t encrypted_keys;
    size_t hsm_keys;
    size_t tpm_keys;

    // Weakness counters
    size_t weak_keys;
    size_t expired_keys;

    // Performance metrics
    double average_processing_time_ms;
    size_t timeouts_hit;
    size_t cache_hits;
    size_t cache_misses;
} key_scanner_stats_t;

// Key scanner configuration
typedef struct {
    char** scan_paths;               // Paths to scan for keys
    size_t scan_path_count;
    bool recursive_scan;             // Recursive directory scanning
    size_t max_file_size;            // Maximum file size to process
    int timeout_seconds;             // Timeout per key file

    // Password handling
    char** passwords;                // Passwords to try for encrypted keys
    size_t password_count;
    bool skip_encrypted;             // Skip encrypted keys without password

    // Detection options
    bool detect_weak_keys;           // Enable weak key detection
    bool extract_public_from_private; // Extract public key from private key
    bool link_to_certificates;       // Link keys to certificates

    // Privacy options
    bool hash_file_paths;            // Hash file paths for privacy
    bool redact_key_material;        // Redact all key material (default: true)
} key_scanner_config_t;

// Key scanner context
typedef struct {
    key_scanner_config_t config;
    struct asset_store* asset_store; // Asset store for results
    struct scan_context* scan_context; // Scan context with dedup info

    // Statistics tracking
    key_scanner_stats_t stats;

    // Thread safety
    pthread_mutex_t mutex;           // Mutex for updating stats
} key_scanner_context_t;

// Main key scanner functions
key_scanner_context_t* key_scanner_create(const key_scanner_config_t* config,
                                         struct asset_store* store);
void key_scanner_destroy(key_scanner_context_t* context);

int key_scanner_scan_file(key_scanner_context_t* context, const char* file_path);
int key_scanner_scan_directory(key_scanner_context_t* context, const char* dir_path);
int key_scanner_scan_paths(key_scanner_context_t* context);

// Key format detection
key_format_t key_detect_format(const char* file_path);
key_format_t key_detect_format_from_content(const unsigned char* data, size_t len);
bool key_is_encrypted(const char* file_path);

// Key parsing functions (secure memory usage)
EVP_PKEY* key_load_from_file(const char* file_path, key_format_t format,
                             const char* password);
EVP_PKEY* key_load_pem(const char* file_path, const char* password);
EVP_PKEY* key_load_der(const char* file_path);
EVP_PKEY* key_load_openssh(const char* file_path);

// Key metadata extraction (never stores raw key material)
key_metadata_t* key_extract_metadata(EVP_PKEY* pkey, const char* file_path,
                                     key_format_t format, bool is_encrypted);
key_type_t key_get_type(EVP_PKEY* pkey);
key_class_t key_get_classification(EVP_PKEY* pkey);
int key_get_size(EVP_PKEY* pkey);
char* key_get_algorithm_name(EVP_PKEY* pkey);
char* key_get_curve_name(EVP_PKEY* pkey);

// Key identification (SHA-256 hashes only, never raw material)
char* key_generate_id(EVP_PKEY* pkey);
char* key_get_public_key_hash(EVP_PKEY* pkey);
char* key_get_fingerprint(EVP_PKEY* pkey, key_format_t format);

// Storage security detection
storage_security_t key_detect_storage_security(const char* file_path, bool is_encrypted);
bool key_is_in_hsm(const char* file_path);
bool key_is_in_tpm(const char* file_path);
bool key_is_in_keyring(const char* file_path);

// Lifecycle metadata extraction
key_lifecycle_t key_extract_lifecycle(const char* file_path);
bool key_is_expired(const key_lifecycle_t* lifecycle);
int key_days_until_expiration(const key_lifecycle_t* lifecycle);

// Usage detection
key_usage_t* key_detect_usages(const char* file_path, EVP_PKEY* pkey, size_t* count);
key_usage_t key_detect_primary_usage(const char* file_path);

// Weakness detection
bool key_is_weak(EVP_PKEY* pkey, key_type_t type);
bool key_has_weak_size(EVP_PKEY* pkey, key_type_t type);
char** key_get_weak_reasons(EVP_PKEY* pkey, key_type_t type, size_t* count);

// Key state detection (Phase 3 - CycloneDX conformance)
key_state_t determine_key_state(const char* key_path, time_t* creation_date,
                                 time_t* activation_date);
const char* key_state_to_string(key_state_t state);

// Encryption detection (Phase 3 - CycloneDX conformance)
secured_by_t* detect_key_encryption(const char* key_path);
void secured_by_destroy(secured_by_t* secured_by);

// Key asset creation (stores only metadata and hashes)
struct crypto_asset* key_create_asset(const key_metadata_t* metadata);
char* key_create_detailed_json_metadata(const key_metadata_t* metadata);

// Utility functions
void key_metadata_destroy(key_metadata_t* metadata);
void key_lifecycle_destroy(key_lifecycle_t* lifecycle);

// Default configuration
key_scanner_config_t key_scanner_create_default_config(void);
void key_scanner_config_destroy(key_scanner_config_t* config);

// Error handling
const char* key_scanner_get_last_error(void);
void key_scanner_clear_error(void);

// Failure reason utilities
const char* key_failure_reason_to_string(key_failure_reason_t reason);
void key_scanner_record_failure(key_scanner_context_t* context, key_failure_reason_t reason);

// Statistics
key_scanner_stats_t key_scanner_get_stats(const key_scanner_context_t* context);

// Security validation (for testing)
bool key_scanner_validate_no_key_material_in_output(const char* output);
bool key_scanner_validate_no_pem_headers_in_output(const char* output);

#endif // KEY_SCANNER_H
