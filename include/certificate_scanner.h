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

#ifndef CERTIFICATE_SCANNER_H
#define CERTIFICATE_SCANNER_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <time.h>
#include <stddef.h>
#include "error_handling.h"

// Forward declarations
struct asset_store;
struct crypto_asset;

// Certificate parsing failure reasons (stable taxonomy)
typedef enum {
    CERT_FAIL_INVALID_PEM_BLOCK,     // Bad BEGIN/END, base64 decode fail
    CERT_FAIL_DER_TRUNCATED,         // DER truncated
    CERT_FAIL_DER_OVERLONG,          // DER overlong
    CERT_FAIL_P12_BAD_PASSWORD,      // P12 bad password
    CERT_FAIL_P12_UNSUPPORTED_PBE,   // P12 unsupported PBE
    CERT_FAIL_P12_NO_MAC,            // P12 no MAC
    CERT_FAIL_UNSUPPORTED_SIGALG,    // Unsupported signature algorithm
    CERT_FAIL_UNSUPPORTED_KEY_TYPE,  // Unsupported key type
    CERT_FAIL_TOO_LARGE,             // Size caps exceeded
    CERT_FAIL_TOO_DEEP,              // Chain depth exceeded
    CERT_FAIL_TIMEOUT,               // Per-file timeout
    CERT_FAIL_SANITY_LIMIT_HIT,      // Extension count, recursion limits
    CERT_FAIL_MEMORY_ERROR,          // Memory allocation failure
    CERT_FAIL_IO_ERROR,              // File I/O error
    CERT_FAIL_UNKNOWN,               // Unknown error
    CERT_FAIL_REASON_COUNT           // Total number of failure reasons
} cert_failure_reason_t;

// Format confidence levels
typedef enum {
    FORMAT_CONFIDENCE_LOW,           // Heuristic detection
    FORMAT_CONFIDENCE_MEDIUM,        // Strong indicators
    FORMAT_CONFIDENCE_HIGH           // Definitive format markers
} format_confidence_t;

// Certificate validity status
typedef enum {
    VALIDITY_VALID,
    VALIDITY_NOT_YET_VALID,
    VALIDITY_EXPIRED
} validity_status_t;



// Enhanced statistics structure
typedef struct {
    // File-level counters
    size_t files_scanned_total;
    size_t files_extension_matched;      // Files that passed extension filter
    size_t files_with_parsable_certs;    // Files with valid certificate format
    size_t files_quarantined;            // Files marked as quarantined
    
    // Certificate-level counters (payloads inside files)
    size_t certs_detected_total;         // Total certificate payloads detected
    size_t certs_parsed_ok;              // Successfully parsed certificates
    size_t certs_failed_total;           // Failed to parse certificates
    size_t certs_failed_by_reason[CERT_FAIL_REASON_COUNT]; // Failures by reason

    // Bundle-specific counters (Issue #2 fix)
    size_t bundles_processed;            // Number of bundle files processed
    size_t certs_from_bundles;           // Certificates extracted from bundles
    size_t bundle_files_with_failures;   // Bundle files where some certs failed
    size_t bundle_certs_failed;          // Certificates that failed within bundles
    size_t individual_files_processed;   // Count of non-bundle files
    size_t individual_file_failures;     // Non-bundle files that failed completely

    // Format breakdown - detected
    size_t pem_detected;
    size_t der_detected;
    size_t pkcs12_detected;
    
    // Format breakdown - parsed successfully
    size_t pem_parsed_ok;
    size_t der_parsed_ok;
    size_t pkcs12_parsed_ok;
    
    // Certificate properties
    size_t weak_certificates;
    size_t expired_certificates;
    size_t self_signed_certificates;
    size_t ca_certificates;
    
    // Trust validation counters (4.1.2 enhancement)
    size_t trust_valid_certificates;
    size_t trust_expired_certificates;
    size_t trust_not_yet_valid_certificates;
    size_t trust_revoked_certificates;
    size_t trust_untrusted_ca_certificates;
    size_t trust_self_signed_certificates;
    size_t trust_chain_incomplete_certificates;
    size_t trust_weak_signature_certificates;
    size_t trust_unknown_certificates;
    
    // Performance metrics
    double average_processing_time_ms;
    size_t timeouts_hit;
    size_t cache_hits;
    size_t cache_misses;
    
    // Multi-payload containers
    size_t multi_cert_pem_files;         // PEM files with multiple certificates
    size_t multi_cert_p12_files;         // P12 files with multiple certificates
    size_t total_cert_payloads_in_files; // Total certificate payloads found
    
    // Legacy compatibility fields
    size_t certificates_found;           // Legacy: same as certs_detected_total
    size_t certificates_processed;       // Legacy: same as certs_parsed_ok
} cert_scanner_stats_t;

// Certificate format types
typedef enum {
    CERT_FORMAT_PEM,
    CERT_FORMAT_DER,
    CERT_FORMAT_PKCS12,
    CERT_FORMAT_JKS,        // Deferred to plugin
    CERT_FORMAT_UNKNOWN
} cert_format_t;

// Certificate usage types
typedef enum {
    CERT_USAGE_TLS_SERVER,
    CERT_USAGE_TLS_CLIENT,
    CERT_USAGE_CODE_SIGNING,
    CERT_USAGE_EMAIL_PROTECTION,
    CERT_USAGE_TIME_STAMPING,
    CERT_USAGE_CA_CERTIFICATE,
    CERT_USAGE_UNKNOWN
} cert_usage_t;

// Trust status enumeration
typedef enum {
    TRUST_VALID,
    TRUST_EXPIRED,
    TRUST_NOT_YET_VALID,
    TRUST_REVOKED,
    TRUST_UNTRUSTED_CA,
    TRUST_SELF_SIGNED,
    TRUST_CHAIN_INCOMPLETE,
    TRUST_WEAK_SIGNATURE,
    TRUST_UNKNOWN
} trust_status_t;

// Certificate extension structure
typedef struct {
    char* oid;                   // Extension OID
    bool critical;               // Critical flag
    char* value;                 // Extension value (parsed)
    char* raw_value;             // Raw ASN.1 value
} cert_extension_t;

// Trust chain validation result
typedef struct {
    trust_status_t status;
    char** chain_subjects;       // Full certificate chain
    size_t chain_length;
    char* root_ca;               // Root CA name
    char* validation_error;      // Error message if invalid
    time_t validation_time;      // When validation was performed
    bool is_ca_trusted;          // Is CA in system trust store
} trust_chain_result_t;

// Weak signature detection flags
typedef struct {
    bool uses_md5;               // MD5 signature algorithm
    bool uses_sha1;              // SHA-1 signature algorithm
    bool weak_rsa_key;           // RSA key < 2048 bits
    bool weak_ecc_curve;         // Weak ECC curve
    char** weak_algorithms;      // List of weak algorithms found
    size_t weak_count;
} weak_signature_flags_t;

// CA information
typedef struct {
    char* ca_name;               // Certificate Authority name
    char* ca_oid;                // CA OID if available
    bool is_public_ca;           // Public vs. private CA
    bool is_self_signed;         // Self-signed certificate
    char* ca_key_id;             // Authority Key Identifier
} ca_info_t;

// Public key parameters
typedef struct {
    char* algorithm;             // RSA, ECDSA, Ed25519, etc.
    int key_size;                // Key size in bits
    char* curve_name;            // ECC curve name
    char* public_key_hash;       // SHA-256 of public key
    char* key_usage;             // Key usage extensions
    char* extended_key_usage;    // Extended key usage
} public_key_params_t;

// Certificate Policy structure (Issue #8)
typedef struct {
    char* oid;              // Policy OID (required)
    char* qualifier;        // CPS URI or User Notice (optional, can be NULL)
} cert_policy_t;

// Certificate metadata structure
typedef struct {
    cert_usage_t usage;
    char* subject;
    char* issuer;
    time_t not_before;
    time_t not_after;
    char* signature_algorithm;
    char* public_key_algorithm;
    cert_extension_t* extensions;
    size_t extension_count;
    trust_chain_result_t trust_validation;
    weak_signature_flags_t weak_signatures;
    ca_info_t ca_info;
    public_key_params_t public_key_params;
    char** san_entries;          // Subject Alternative Names
    size_t san_count;
    char* serial_number;
    char* serial_number_hex;         // Normalized uppercase hex format
    char* fingerprint_sha1;
    char* fingerprint_sha256;
    cert_format_t format;
    
    // Key identifiers for relationship mapping
    char* authority_key_id;          // AKI (hex)
    char* subject_key_id;            // SKI (hex)
    
    // Certificate constraints and usage
    bool is_ca;                      // BasicConstraints CA flag
    int path_length;                 // BasicConstraints pathLenConstraint (-1 if not set)
    char** key_usage;                // KeyUsage extension values
    size_t key_usage_count;
    char** extended_key_usage;       // ExtendedKeyUsage extension values  
    size_t extended_key_usage_count;
    
    // Validity status
    validity_status_t validity_status;
    
    // Enhanced fields for 4.1 completion
    char* signature_hash;            // Hash algorithm (SHA256, SHA1, etc.)
    char* public_key_oid;            // Public key algorithm OID
    char* signature_oid;             // Signature algorithm OID
    int public_key_size;             // Key size in bits
    char* ec_curve_name;             // EC curve name (if applicable)
    char* ec_curve_oid;              // EC curve OID (if applicable)
    
    // Subject Alternative Names
    char** san_dns;                  // DNS names
    size_t san_dns_count;
    char** san_ip;                   // IP addresses
    size_t san_ip_count;
    char** san_uri;                  // URIs
    size_t san_uri_count;
    char** san_email;                // Email addresses
    size_t san_email_count;
    char** san_rid;                  // Registered IDs
    size_t san_rid_count;

    // Authority Information Access (Issue #8)
    char** aia_ocsp_urls;            // OCSP responder URLs
    size_t aia_ocsp_count;
    char** aia_ca_issuers_urls;      // CA Issuers URLs
    size_t aia_ca_issuers_count;

    // Certificate Policies (Issue #8)
    cert_policy_t* cert_policies;    // Array of certificate policies
    size_t cert_policy_count;

    // RFC2253 normalized DN forms
    char* subject_rfc2253;           // RFC2253 normalized subject
    char* issuer_rfc2253;            // RFC2253 normalized issuer
    
    // Normalized UTC times
    char* not_before_utc;            // ISO 8601 UTC format
    char* not_after_utc;             // ISO 8601 UTC format
} cert_metadata_t;

// Certificate scanner configuration
typedef struct {
    bool validate_trust_chains;  // Enable trust chain validation
    bool check_revocation;       // Enable OCSP/CRL checking
    bool detect_weak_signatures; // Enable weak signature detection
    char* trust_store_path;      // Path to system trust store
    char** scan_paths;           // Paths to scan for certificates
    size_t scan_path_count;
    bool recursive_scan;         // Recursive directory scanning
    size_t max_file_size;        // Maximum file size to process
    int timeout_seconds;         // Timeout per certificate
} cert_scanner_config_t;

// Forward declarations
struct asset_store;
struct scan_context;

// Certificate scanner context
typedef struct {
    cert_scanner_config_t config;
    X509_STORE* trust_store;     // OpenSSL trust store
    struct asset_store* asset_store;  // Asset store for results
    struct scan_context* scan_context;  // Scan context with dedup info
    error_collector_t* error_collector;  // Error collector for detailed error reporting (Issue #5)

    // Enhanced statistics tracking
    cert_scanner_stats_t stats;

    // Legacy counters (for backward compatibility)
    size_t certificates_found;
    size_t certificates_processed;
    size_t weak_certificates;
    size_t expired_certificates;
} cert_scanner_context_t;

// Main certificate scanner functions
cert_scanner_context_t* cert_scanner_create(const cert_scanner_config_t* config, 
                                           struct asset_store* store);
void cert_scanner_destroy(cert_scanner_context_t* context);

int cert_scanner_scan_file(cert_scanner_context_t* context, const char* file_path);
int cert_scanner_scan_directory(cert_scanner_context_t* context, const char* dir_path);
int cert_scanner_scan_paths(cert_scanner_context_t* context);

// Certificate parsing functions
cert_format_t cert_detect_format(const char* file_path);
X509* cert_load_from_file(const char* file_path, cert_format_t format);
X509* cert_load_pem(const char* file_path);
X509* cert_load_der(const char* file_path);
int cert_load_pkcs12(const char* file_path, const char* password, 
                     X509** cert, EVP_PKEY** pkey, STACK_OF(X509)** ca_certs);

// Certificate metadata extraction
cert_metadata_t* cert_extract_metadata(X509* cert, const char* file_path);
char* cert_get_subject_name(X509* cert);
char* cert_get_issuer_name(X509* cert);
char* cert_get_serial_number(X509* cert);
char* cert_get_fingerprint_sha256(X509* cert);
char* cert_get_fingerprint_sha1(X509* cert);

// Certificate extension parsing
cert_extension_t* cert_parse_extensions(X509* cert, size_t* count);
char** cert_get_san_entries(X509* cert, size_t* count);
cert_usage_t cert_determine_usage(X509* cert);

// Public key analysis
public_key_params_t cert_analyze_public_key(X509* cert);
char* cert_get_public_key_algorithm(X509* cert);
int cert_get_public_key_size(X509* cert);
char* cert_get_curve_name(X509* cert);

// Trust chain validation
trust_chain_result_t cert_validate_trust_chain(cert_scanner_context_t* context, X509* cert);
X509_STORE* cert_load_system_trust_store(const char* trust_store_path);
bool cert_is_self_signed(X509* cert);

// Weakness detection
weak_signature_flags_t cert_detect_weaknesses(X509* cert);
bool cert_uses_weak_signature_algorithm(X509* cert);
bool cert_has_weak_public_key(X509* cert);
char** cert_list_weak_algorithms(X509* cert, size_t* count);

// CA information extraction
ca_info_t cert_extract_ca_info(X509* cert);
bool cert_is_ca_certificate(X509* cert);
char* cert_get_authority_key_id(X509* cert);

// Enhanced metadata extraction functions
char* cert_get_subject_key_id(X509* cert);
int cert_get_path_length_constraint(X509* cert);
char** cert_get_key_usage_strings(X509* cert, size_t* count);
char** cert_get_extended_key_usage_strings(X509* cert, size_t* count);
char* cert_get_serial_number_hex(X509* cert);

// Certificate asset creation
struct crypto_asset* cert_create_asset(const cert_metadata_t* metadata, const char* file_path, X509* cert);
char* cert_generate_asset_id(const cert_metadata_t* metadata);
char* cert_create_detailed_json_metadata(const cert_metadata_t* metadata, X509* cert);

// Utility functions
void cert_metadata_destroy(cert_metadata_t* metadata);
void cert_extension_destroy(cert_extension_t* extension);
void trust_chain_result_destroy(trust_chain_result_t* result);
void weak_signature_flags_destroy(weak_signature_flags_t* flags);
void ca_info_destroy(ca_info_t* info);
void public_key_params_destroy(public_key_params_t* params);

// Default configuration
cert_scanner_config_t cert_scanner_create_default_config(void);

// Error handling
const char* cert_scanner_get_last_error(void);
void cert_scanner_clear_error(void);

// Failure reason utilities
const char* cert_failure_reason_to_string(cert_failure_reason_t reason);
void cert_scanner_record_failure(cert_scanner_context_t* context, cert_failure_reason_t reason, const char* file_path);
void cert_scanner_record_parsing_failure(cert_scanner_context_t* context, cert_failure_reason_t reason, const char* file_path);
format_confidence_t cert_assess_format_confidence(const char* file_path, cert_format_t format);

cert_scanner_stats_t cert_scanner_get_stats(cert_scanner_context_t* context);

// CBOM diagnostic generation
typedef struct {
    char* name;
    char* value;
} cbom_diagnostic_entry_t;

cbom_diagnostic_entry_t* cert_scanner_generate_cbom_diagnostics(cert_scanner_context_t* context, size_t* count);
void cbom_diagnostic_entries_destroy(cbom_diagnostic_entry_t* entries, size_t count);

#endif // CERTIFICATE_SCANNER_H
