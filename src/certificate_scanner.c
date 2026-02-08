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

#include "certificate_scanner.h"
#include "error_handling.h"
#include "secure_memory.h"
#include "asset_store.h"
#include "cbom_types.h"
#include "plugin_manager.h"
#include "dedup.h"
#include "algorithm_metadata.h"
#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#ifndef __EMSCRIPTEN__
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif
#include <json-c/json.h>
#include <ctype.h>

#ifndef __EMSCRIPTEN__

// Thread-local error storage
static __thread char last_error[256] = {0};

// Check if BIO content looks like a private key PEM header (without loading it)
// This is used to detect key files and delegate to key_scanner without prompting
static bool is_pem_private_key_header(BIO* bio) {
    if (!bio) return false;

    char buffer[256];
    bool found_private_key = false;

    // Save position and read from start
    long pos = BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL);  // Get current position
    BIO_reset(bio);

    // Look for private key headers in first few lines
    int lines_checked = 0;
    while (BIO_gets(bio, buffer, sizeof(buffer)) > 0 && lines_checked < 10) {
        lines_checked++;
        if (strstr(buffer, "-----BEGIN") && strstr(buffer, "PRIVATE KEY-----")) {
            found_private_key = true;
            break;
        }
        if (strstr(buffer, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
            found_private_key = true;
            break;
        }
    }

    BIO_reset(bio);
    (void)pos;  // Unused, reset to beginning is fine
    return found_private_key;
}

// Forward declarations for internal functions
static int cert_load_and_process_file(cert_scanner_context_t* context, const char* file_path, cert_format_t format);
static int cert_load_and_process_pem_file(cert_scanner_context_t* context, const char* file_path);
static int cert_load_and_process_der_file(cert_scanner_context_t* context, const char* file_path);
static int cert_load_and_process_pkcs12_file(cert_scanner_context_t* context, const char* file_path);
static bool cert_process_single_certificate(cert_scanner_context_t* context, X509* cert,
                                           const char* file_path, cert_format_t format);
static bool is_valid_url(const char* url);
static void cert_get_authority_info_access(X509* cert, cert_metadata_t* metadata);
static void cert_get_certificate_policies(X509* cert, cert_metadata_t* metadata);

// Helper function to convert ASN1_TIME to time_t
static time_t asn1_time_to_time_t(const ASN1_TIME* asn1_time) {
    if (!asn1_time) return 0;
    
    struct tm tm_time = {0};
    const char* str = (const char*)asn1_time->data;
    
    if (asn1_time->type == V_ASN1_UTCTIME) {
        // YYMMDDHHMMSSZ format
        if (strlen(str) >= 12) {
            int year = (str[0] - '0') * 10 + (str[1] - '0');
            year += (year < 70) ? 2000 : 1900; // Y2K handling
            
            tm_time.tm_year = year - 1900;
            tm_time.tm_mon = (str[2] - '0') * 10 + (str[3] - '0') - 1;
            tm_time.tm_mday = (str[4] - '0') * 10 + (str[5] - '0');
            tm_time.tm_hour = (str[6] - '0') * 10 + (str[7] - '0');
            tm_time.tm_min = (str[8] - '0') * 10 + (str[9] - '0');
            tm_time.tm_sec = (str[10] - '0') * 10 + (str[11] - '0');
        }
    } else if (asn1_time->type == V_ASN1_GENERALIZEDTIME) {
        // YYYYMMDDHHMMSSZ format
        if (strlen(str) >= 14) {
            int year = (str[0] - '0') * 1000 + (str[1] - '0') * 100 + 
                      (str[2] - '0') * 10 + (str[3] - '0');
            
            tm_time.tm_year = year - 1900;
            tm_time.tm_mon = (str[4] - '0') * 10 + (str[5] - '0') - 1;
            tm_time.tm_mday = (str[6] - '0') * 10 + (str[7] - '0');
            tm_time.tm_hour = (str[8] - '0') * 10 + (str[9] - '0');
            tm_time.tm_min = (str[10] - '0') * 10 + (str[11] - '0');
            tm_time.tm_sec = (str[12] - '0') * 10 + (str[13] - '0');
        }
    }
    
    return mktime(&tm_time);
}

// Set error message
static void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(last_error, sizeof(last_error), format, args);
    va_end(args);
}

// Clear error message
void cert_scanner_clear_error(void) {
    last_error[0] = '\0';
}

// Get last error message
const char* cert_scanner_get_last_error(void) {
    return last_error[0] ? last_error : NULL;
}

// Convert failure reason to string
const char* cert_failure_reason_to_string(cert_failure_reason_t reason) {
    switch (reason) {
        case CERT_FAIL_INVALID_PEM_BLOCK: return "INVALID_PEM_BLOCK";
        case CERT_FAIL_DER_TRUNCATED: return "DER_TRUNCATED";
        case CERT_FAIL_DER_OVERLONG: return "DER_OVERLONG";
        case CERT_FAIL_P12_BAD_PASSWORD: return "P12_BAD_PASSWORD";
        case CERT_FAIL_P12_UNSUPPORTED_PBE: return "P12_UNSUPPORTED_PBE";
        case CERT_FAIL_P12_NO_MAC: return "P12_NO_MAC";
        case CERT_FAIL_UNSUPPORTED_SIGALG: return "UNSUPPORTED_SIGALG";
        case CERT_FAIL_UNSUPPORTED_KEY_TYPE: return "UNSUPPORTED_KEY_TYPE";
        case CERT_FAIL_TOO_LARGE: return "TOO_LARGE";
        case CERT_FAIL_TOO_DEEP: return "TOO_DEEP";
        case CERT_FAIL_TIMEOUT: return "TIMEOUT";
        case CERT_FAIL_SANITY_LIMIT_HIT: return "SANITY_LIMIT_HIT";
        case CERT_FAIL_MEMORY_ERROR: return "MEMORY_ERROR";
        case CERT_FAIL_IO_ERROR: return "IO_ERROR";
        case CERT_FAIL_UNKNOWN: return "UNKNOWN";
        default: return "INVALID_REASON";
    }
}

// Record failure reason (Issue #5: Enhanced error reporting)
void cert_scanner_record_failure(cert_scanner_context_t* context, cert_failure_reason_t reason, const char* file_path) {
    if (!context || reason < 0 || reason >= CERT_FAIL_REASON_COUNT) {
        fprintf(stderr, "ERROR: Invalid failure recording - context=%p, reason=%d, max=%d\n",
               context, reason, CERT_FAIL_REASON_COUNT);
        return;
    }

    // Update internal stats (existing behavior)
    context->stats.certs_failed_by_reason[reason]++;

    // Issue #5: Log to error collector for detailed error reporting
    if (context->error_collector) {
        error_category_t category;
        error_severity_t severity;

        // Map failure reason to error category and severity
        switch (reason) {
            case CERT_FAIL_IO_ERROR:
                category = ERROR_CATEGORY_IO;
                severity = ERROR_SEVERITY_ERROR;
                break;
            case CERT_FAIL_MEMORY_ERROR:
                category = ERROR_CATEGORY_MEMORY;
                severity = ERROR_SEVERITY_ERROR;
                break;
            case CERT_FAIL_INVALID_PEM_BLOCK:
            case CERT_FAIL_DER_TRUNCATED:
            case CERT_FAIL_DER_OVERLONG:
            case CERT_FAIL_P12_BAD_PASSWORD:
            case CERT_FAIL_P12_UNSUPPORTED_PBE:
            case CERT_FAIL_P12_NO_MAC:
            case CERT_FAIL_UNSUPPORTED_SIGALG:
            case CERT_FAIL_UNSUPPORTED_KEY_TYPE:
                category = ERROR_CATEGORY_VALIDATION;
                severity = ERROR_SEVERITY_WARNING;
                break;
            case CERT_FAIL_TOO_LARGE:
            case CERT_FAIL_TOO_DEEP:
            case CERT_FAIL_SANITY_LIMIT_HIT:
                category = ERROR_CATEGORY_SECURITY;
                severity = ERROR_SEVERITY_WARNING;
                break;
            case CERT_FAIL_TIMEOUT:
                category = ERROR_CATEGORY_TIMEOUT;
                severity = ERROR_SEVERITY_WARNING;
                break;
            default:
                category = ERROR_CATEGORY_UNKNOWN;
                severity = ERROR_SEVERITY_ERROR;
                break;
        }

        // Capture OpenSSL error if available (use ERR_peek_error to not consume the error)
        unsigned long ssl_error = ERR_peek_error();
        int error_code = ssl_error ? (int)ssl_error : 0;
        char ssl_error_str[256] = "";
        if (ssl_error) {
            ERR_error_string_n(ssl_error, ssl_error_str, sizeof(ssl_error_str));
        }

        // Suppress MEMORY_ERROR messages that provide no useful information:
        // - 0x0480006C ("no start line"): normal end-of-bundle behavior
        // - ssl_error == 0: no OpenSSL context (e.g., duplicate rejection, allocation)
        if (reason == CERT_FAIL_MEMORY_ERROR && (ssl_error == 0x0480006C || ssl_error == 0)) {
            ERR_clear_error();
            return;
        }

        // Format descriptive error message
        char message[512];
        if (ssl_error_str[0]) {
            snprintf(message, sizeof(message),
                     "Certificate parsing failed: %s - %s",
                     cert_failure_reason_to_string(reason),
                     ssl_error_str);
        } else {
            snprintf(message, sizeof(message),
                     "Certificate parsing failed: %s",
                     cert_failure_reason_to_string(reason));
        }

        // Log to error collector with file path as context
        error_collector_add(context->error_collector,
                           category,
                           severity,
                           error_code,
                           "certificate_scanner",
                           message,
                           file_path ? file_path : "unknown");
    }
}

// Record post-detection parsing failure (counts toward failed_total)
// Issue #5: Enhanced error reporting with error collector integration
void cert_scanner_record_parsing_failure(cert_scanner_context_t* context, cert_failure_reason_t reason, const char* file_path) {
    if (!context || reason < 0 || reason >= CERT_FAIL_REASON_COUNT) {
        return;
    }

    // Update internal stats (existing behavior)
    context->stats.certs_failed_total++;
    context->stats.certs_failed_by_reason[reason]++;

    // Issue #5: Delegate to cert_scanner_record_failure for error collector integration
    // Note: We don't increment stats again since we already did it above
    // Just need to log to error collector
    if (context->error_collector) {
        error_category_t category;
        error_severity_t severity;

        // Map failure reason to error category and severity (same mapping as record_failure)
        switch (reason) {
            case CERT_FAIL_IO_ERROR:
                category = ERROR_CATEGORY_IO;
                severity = ERROR_SEVERITY_ERROR;
                break;
            case CERT_FAIL_MEMORY_ERROR:
                category = ERROR_CATEGORY_MEMORY;
                severity = ERROR_SEVERITY_ERROR;
                break;
            case CERT_FAIL_INVALID_PEM_BLOCK:
            case CERT_FAIL_DER_TRUNCATED:
            case CERT_FAIL_DER_OVERLONG:
            case CERT_FAIL_P12_BAD_PASSWORD:
            case CERT_FAIL_P12_UNSUPPORTED_PBE:
            case CERT_FAIL_P12_NO_MAC:
            case CERT_FAIL_UNSUPPORTED_SIGALG:
            case CERT_FAIL_UNSUPPORTED_KEY_TYPE:
                category = ERROR_CATEGORY_VALIDATION;
                severity = ERROR_SEVERITY_WARNING;
                break;
            case CERT_FAIL_TOO_LARGE:
            case CERT_FAIL_TOO_DEEP:
            case CERT_FAIL_SANITY_LIMIT_HIT:
                category = ERROR_CATEGORY_SECURITY;
                severity = ERROR_SEVERITY_WARNING;
                break;
            case CERT_FAIL_TIMEOUT:
                category = ERROR_CATEGORY_TIMEOUT;
                severity = ERROR_SEVERITY_WARNING;
                break;
            default:
                category = ERROR_CATEGORY_UNKNOWN;
                severity = ERROR_SEVERITY_ERROR;
                break;
        }

        // Capture OpenSSL error if available
        unsigned long ssl_error = ERR_peek_error();
        int error_code = ssl_error ? (int)ssl_error : 0;
        char ssl_error_str[256] = "";
        if (ssl_error) {
            ERR_error_string_n(ssl_error, ssl_error_str, sizeof(ssl_error_str));
        }

        // Suppress MEMORY_ERROR messages that provide no useful information:
        // - 0x0480006C ("no start line"): normal end-of-bundle behavior
        // - ssl_error == 0: no OpenSSL context (e.g., duplicate rejection, allocation)
        // Stats are already updated above, just skip the scary console message
        if (reason == CERT_FAIL_MEMORY_ERROR && (ssl_error == 0x0480006C || ssl_error == 0)) {
            ERR_clear_error();
            return;
        }

        // Format descriptive error message
        char message[512];
        if (ssl_error_str[0]) {
            snprintf(message, sizeof(message),
                     "Certificate parsing failed (post-detection): %s - %s",
                     cert_failure_reason_to_string(reason),
                     ssl_error_str);
        } else {
            snprintf(message, sizeof(message),
                     "Certificate parsing failed (post-detection): %s",
                     cert_failure_reason_to_string(reason));
        }

        // Log to error collector
        error_collector_add(context->error_collector,
                           category,
                           severity,
                           error_code,
                           "certificate_scanner",
                           message,
                           file_path ? file_path : "unknown");
    }
}

// Load and process certificates from a file (handles multi-payload containers)
static int cert_load_and_process_file(cert_scanner_context_t* context, const char* file_path, cert_format_t format) {
    if (!context || !file_path) return -1;
    
    int processed_count = 0;
    
    switch (format) {
        case CERT_FORMAT_PEM:
            processed_count = cert_load_and_process_pem_file(context, file_path);
            break;
        case CERT_FORMAT_DER:
            processed_count = cert_load_and_process_der_file(context, file_path);
            break;
        case CERT_FORMAT_PKCS12:
            processed_count = cert_load_and_process_pkcs12_file(context, file_path);
            break;
        default:
            cert_scanner_record_failure(context, CERT_FAIL_UNKNOWN, file_path);
            return -1;
    }
    
    return processed_count;
}

// Forward declaration for CSR processing (Issue #7)
static bool cert_process_single_csr(cert_scanner_context_t* context, X509_REQ *req, const char* file_path);

// Process PEM file (may contain multiple certificates)
static int cert_load_and_process_pem_file(cert_scanner_context_t* context, const char* file_path) {
    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        cert_scanner_record_failure(context, CERT_FAIL_IO_ERROR, file_path);
        return -1;
    }

    BIO* bio = BIO_new_fp(fp, BIO_NOCLOSE);
    if (!bio) {
        fclose(fp);
        cert_scanner_record_failure(context, CERT_FAIL_MEMORY_ERROR, file_path);
        return -1;
    }
    
    int cert_count = 0;
    int processed_count = 0;
    X509* cert;
    
    // Read all certificates from the PEM file
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        cert_count++;
        context->stats.certs_detected_total++;
        
        if (cert_process_single_certificate(context, cert, file_path, CERT_FORMAT_PEM)) {
            processed_count++;
            context->stats.certs_parsed_ok++;
            context->stats.pem_parsed_ok++;
        } else {
            // Error already recorded by cert_process_single_certificate
        }
        
        X509_free(cert);
    }
    
    // Check if we found multiple certificates in this PEM file (bundle)
    if (cert_count > 1) {
        context->stats.multi_cert_pem_files++;
        // Track bundle statistics (Issue #2 fix)
        context->stats.bundles_processed++;
        context->stats.certs_from_bundles += processed_count;
        if (processed_count < cert_count) {
            context->stats.bundle_files_with_failures++;
            // Track how many certs failed within bundles
            context->stats.bundle_certs_failed += (cert_count - processed_count);
        }
    } else if (cert_count == 1) {
        // Track individual file statistics (Issue #2 fix)
        context->stats.individual_files_processed++;
        if (processed_count == 0) {
            // Single-cert file that failed completely
            context->stats.individual_file_failures++;
        }
    }

    context->stats.total_cert_payloads_in_files += cert_count;

    // If no certificates were found, try parsing as CSR (Issue #7)
    if (cert_count == 0) {
        BIO_reset(bio);
        X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
        if (req) {
            // It's a CSR!
            bool csr_processed = cert_process_single_csr(context, req, file_path);
            X509_REQ_free(req);
            BIO_free(bio);
            fclose(fp);

            if (csr_processed) {
                return 1;  // Success - processed as CSR
            } else {
                cert_scanner_record_failure(context, CERT_FAIL_MEMORY_ERROR, file_path);
                return -1;
            }
        }

        // Try to detect if this is a private or public key (delegate to key scanner)
        // Check for private key PEM header first (avoids loading encrypted keys which would prompt)
        if (is_pem_private_key_header(bio)) {
            // This is a private key file - let key_scanner handle it
            BIO_free(bio);
            fclose(fp);
            return 0;  // Return 0 to indicate "not a certificate" (not an error)
        }

        // Try to read as public key (public keys are never encrypted, no prompt risk)
        BIO_reset(bio);
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (pkey) {
            // This is a public key file - skip it, let key_scanner handle it
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            fclose(fp);
            return 0;  // Return 0 to indicate "not a certificate" (not an error)
        }

        // Not a cert, not a CSR, not a key - mark as invalid PEM
        BIO_free(bio);
        fclose(fp);
        cert_scanner_record_failure(context, CERT_FAIL_INVALID_PEM_BLOCK, file_path);
        return -1;
    }

    // Normal path - certs were processed successfully
    BIO_free(bio);
    fclose(fp);
    return processed_count;
}

// Process DER file (typically contains one certificate)
static int cert_load_and_process_der_file(cert_scanner_context_t* context, const char* file_path) {
    FILE* fp = fopen(file_path, "rb");
    if (!fp) {
        cert_scanner_record_failure(context, CERT_FAIL_IO_ERROR, file_path);
        return -1;
    }

    X509* cert = d2i_X509_fp(fp, NULL);
    fclose(fp);

    if (!cert) {
        // Pre-detection failure - file doesn't contain valid DER certificate
        // Check OpenSSL error to determine specific failure reason
        unsigned long err = ERR_get_error();
        if (err) {
            const char* err_str = ERR_reason_error_string(err);
            if (strstr(err_str, "truncated") || strstr(err_str, "short")) {
                cert_scanner_record_failure(context, CERT_FAIL_DER_TRUNCATED, file_path);
            } else if (strstr(err_str, "too long") || strstr(err_str, "overlong")) {
                cert_scanner_record_failure(context, CERT_FAIL_DER_OVERLONG, file_path);
            } else {
                cert_scanner_record_failure(context, CERT_FAIL_UNKNOWN, file_path);
            }
        } else {
            cert_scanner_record_failure(context, CERT_FAIL_DER_TRUNCATED, file_path);
        }
        return -1;
    }
    
    // Certificate detected successfully
    context->stats.certs_detected_total++;
    context->stats.total_cert_payloads_in_files++;

    // DER files typically contain a single certificate (Issue #2 fix)
    context->stats.individual_files_processed++;

    if (cert_process_single_certificate(context, cert, file_path, CERT_FORMAT_DER)) {
        context->stats.certs_parsed_ok++;
        context->stats.der_parsed_ok++;
        X509_free(cert);
        return 1;
    } else {
        // Individual DER file failed to parse
        context->stats.individual_file_failures++;
        X509_free(cert);
        return -1;
    }
}

// Process PKCS#12 file (may contain multiple certificates and keys)
static int cert_load_and_process_pkcs12_file(cert_scanner_context_t* context, const char* file_path) {
    FILE* fp = fopen(file_path, "rb");
    if (!fp) {
        cert_scanner_record_failure(context, CERT_FAIL_IO_ERROR, file_path);
        return -1;
    }

    PKCS12* p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if (!p12) {
        cert_scanner_record_failure(context, CERT_FAIL_P12_BAD_PASSWORD, file_path);
        return -1;
    }

    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    STACK_OF(X509)* ca_certs = NULL;

    // Try to parse with empty password first, then NULL
    int parse_result = PKCS12_parse(p12, "", &pkey, &cert, &ca_certs);
    if (!parse_result) {
        parse_result = PKCS12_parse(p12, NULL, &pkey, &cert, &ca_certs);
    }

    if (!parse_result) {
        PKCS12_free(p12);
        cert_scanner_record_failure(context, CERT_FAIL_P12_BAD_PASSWORD, file_path);
        return -1;
    }
    
    int processed_count = 0;
    int cert_count = 0;
    
    // Process main certificate
    if (cert) {
        cert_count++;
        context->stats.certs_detected_total++;
        if (cert_process_single_certificate(context, cert, file_path, CERT_FORMAT_PKCS12)) {
            processed_count++;
            context->stats.certs_parsed_ok++;
            context->stats.pkcs12_parsed_ok++;
        }
        X509_free(cert);
    }
    
    // Process CA certificates
    if (ca_certs) {
        int ca_count = sk_X509_num(ca_certs);
        for (int i = 0; i < ca_count; i++) {
            X509* ca_cert = sk_X509_value(ca_certs, i);
            if (ca_cert) {
                cert_count++;
                context->stats.certs_detected_total++;
                if (cert_process_single_certificate(context, ca_cert, file_path, CERT_FORMAT_PKCS12)) {
                    processed_count++;
                    context->stats.certs_parsed_ok++;
                    context->stats.pkcs12_parsed_ok++;
                }
            }
        }
        sk_X509_pop_free(ca_certs, X509_free);
    }
    
    // Check if we found multiple certificates in this P12 file
    if (cert_count > 1) {
        context->stats.multi_cert_p12_files++;
        // Track bundle statistics for P12 files (Issue #2 fix)
        context->stats.bundles_processed++;
        context->stats.certs_from_bundles += processed_count;
        if (processed_count < cert_count) {
            context->stats.bundle_files_with_failures++;
            context->stats.bundle_certs_failed += (cert_count - processed_count);
        }
    } else if (cert_count == 1) {
        // Track individual P12 file statistics (Issue #2 fix)
        context->stats.individual_files_processed++;
        if (processed_count == 0) {
            context->stats.individual_file_failures++;
        }
    }

    context->stats.total_cert_payloads_in_files += cert_count;
    
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    
    PKCS12_free(p12);
    
    return processed_count;
}

// Process a single CSR (Certificate Signing Request) - Issue #7
static bool cert_process_single_csr(cert_scanner_context_t* context,
                                    X509_REQ *req,
                                    const char* file_path) {
    if (!context || !req || !file_path) return false;

    // Extract subject name from CSR
    X509_NAME *subject = X509_REQ_get_subject_name(req);
    char subject_str[512] = {0};
    if (subject) {
        X509_NAME_oneline(subject, subject_str, sizeof(subject_str));
    }

    // Get public key from CSR
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
    int key_size = pubkey ? EVP_PKEY_bits(pubkey) : 0;

    // Get algorithm
    const char *algo = "Unknown";
    if (pubkey) {
        switch (EVP_PKEY_id(pubkey)) {
            case EVP_PKEY_RSA: algo = "RSA"; break;
            case EVP_PKEY_EC: algo = "ECDSA"; break;
            case EVP_PKEY_ED25519: algo = "Ed25519"; break;
            case EVP_PKEY_ED448: algo = "Ed448"; break;
            default: algo = "Unknown"; break;
        }
    }

    // Create CSR asset
    const char *asset_name = strlen(subject_str) > 0 ? subject_str : file_path;
    crypto_asset_t *asset = crypto_asset_create(asset_name, ASSET_TYPE_CERTIFICATE_REQUEST);
    if (!asset) {
        if (pubkey) EVP_PKEY_free(pubkey);
        return false;
    }

    asset->location = strdup(file_path);
    asset->key_size = key_size;
    if (algo) {
        asset->algorithm = strdup(algo);
    }

    // Build CSR metadata JSON
    json_object *metadata = json_object_new_object();
    json_object_object_add(metadata, "subject", json_object_new_string(asset_name));
    json_object_object_add(metadata, "type", json_object_new_string("CERTIFICATE_REQUEST"));
    json_object_object_add(metadata, "format", json_object_new_string("PKCS#10"));

    if (pubkey) {
        json_object_object_add(metadata, "public_key_algorithm", json_object_new_string(algo));
        json_object_object_add(metadata, "public_key_size", json_object_new_int(key_size));
        EVP_PKEY_free(pubkey);
    }

    asset->metadata_json = strdup(json_object_to_json_string(metadata));
    json_object_put(metadata);

    // Add to asset store
    int result = asset_store_add(context->asset_store, asset);

    return (result == 0);
}

// Process a single certificate and add it to the asset store
static bool cert_process_single_certificate(cert_scanner_context_t* context, X509* cert, 
                                          const char* file_path, cert_format_t format) {
    if (!context || !cert || !file_path) return false;
    
    // Extract metadata
    cert_metadata_t* metadata = cert_extract_metadata(cert, file_path);
    if (!metadata) {
        cert_scanner_record_parsing_failure(context, CERT_FAIL_MEMORY_ERROR, file_path);
        return false;
    }
    
    metadata->format = format;
    
    // Validate trust chain if enabled (4.1.2 enhancement)
    if (context->config.validate_trust_chains) {
        metadata->trust_validation = cert_validate_trust_chain(context, cert);
        
        // Update trust validation counters
        switch (metadata->trust_validation.status) {
            case TRUST_VALID:
                context->stats.trust_valid_certificates++;
                break;
            case TRUST_EXPIRED:
                context->stats.trust_expired_certificates++;
                break;
            case TRUST_NOT_YET_VALID:
                context->stats.trust_not_yet_valid_certificates++;
                break;
            case TRUST_REVOKED:
                context->stats.trust_revoked_certificates++;
                break;
            case TRUST_UNTRUSTED_CA:
                context->stats.trust_untrusted_ca_certificates++;
                break;
            case TRUST_SELF_SIGNED:
                context->stats.trust_self_signed_certificates++;
                break;
            case TRUST_CHAIN_INCOMPLETE:
                context->stats.trust_chain_incomplete_certificates++;
                break;
            case TRUST_WEAK_SIGNATURE:
                context->stats.trust_weak_signature_certificates++;
                break;
            default:
                context->stats.trust_unknown_certificates++;
                break;
        }
    } else {
        // Initialize with unknown status when validation is disabled
        metadata->trust_validation.status = TRUST_UNKNOWN;
        metadata->trust_validation.validation_time = time(NULL);
        context->stats.trust_unknown_certificates++;
    }
    
    // Create asset and add to store (pass X509 cert for algorithm metadata)
    struct crypto_asset* asset = cert_create_asset(metadata, file_path, cert);
    if (!asset) {
        cert_metadata_destroy(metadata);
        cert_scanner_record_parsing_failure(context, CERT_FAIL_MEMORY_ERROR, file_path);
        return false;
    }

    if (asset_store_add((asset_store_t*)context->asset_store, (crypto_asset_t*)asset) != 0) {
        // Asset store add failed - clean up the asset
        crypto_asset_destroy(asset);
        cert_metadata_destroy(metadata);
        cert_scanner_record_parsing_failure(context, CERT_FAIL_MEMORY_ERROR, file_path);
        return false;
    }

    // Register file with dedup system (if enabled)
    if (context->scan_context && context->scan_context->dedup_ctx) {
        dedup_context_t* dedup_ctx = context->scan_context->dedup_ctx;
        if (dedup_ctx->mode != DEDUP_MODE_OFF) {
            char *file_sha256 = dedup_compute_file_sha256(file_path);
            if (file_sha256) {
                dedup_register_file(dedup_ctx, file_path, file_sha256, asset->id);
                dedup_add_evidence(dedup_ctx, asset->id, file_path, file_sha256);
                free(file_sha256);
            }
        }
    }

    context->certificates_processed++;
    
    // Update detailed statistics
    if (asset->is_weak) {
        context->weak_certificates++;
        context->stats.weak_certificates++;
    }
    
    if (metadata->not_after < time(NULL)) {
        context->expired_certificates++;
        context->stats.expired_certificates++;
    }
    
    if (cert_is_self_signed(cert)) {
        context->stats.self_signed_certificates++;
    }
    
    if (cert_is_ca_certificate(cert)) {
        context->stats.ca_certificates++;
    }
    
    cert_metadata_destroy(metadata);
    return true;
}

// Assess format detection confidence
format_confidence_t cert_assess_format_confidence(const char* file_path, cert_format_t format) {
    if (!file_path || format == CERT_FORMAT_UNKNOWN) {
        return FORMAT_CONFIDENCE_LOW;
    }
    
    // Check file extension for confidence
    const char* ext = strrchr(file_path, '.');
    bool extension_matches = false;
    
    if (ext) {
        ext++; // Skip the dot
        switch (format) {
            case CERT_FORMAT_PEM:
                if (strcasecmp(ext, "pem") == 0 || strcasecmp(ext, "crt") == 0 || 
                    strcasecmp(ext, "cer") == 0 || strcasecmp(ext, "key") == 0 ||
                    strcasecmp(ext, "pub") == 0) {
                    extension_matches = true;
                }
                break;
            case CERT_FORMAT_DER:
                if (strcasecmp(ext, "der") == 0 || strcasecmp(ext, "cer") == 0) {
                    extension_matches = true;
                }
                break;
            case CERT_FORMAT_PKCS12:
                if (strcasecmp(ext, "p12") == 0 || strcasecmp(ext, "pfx") == 0) {
                    extension_matches = true;
                }
                break;
            default:
                break;
        }
    }
    
    // Read first few bytes to check magic bytes/headers
    FILE* fp = fopen(file_path, "rb");
    if (!fp) {
        return extension_matches ? FORMAT_CONFIDENCE_MEDIUM : FORMAT_CONFIDENCE_LOW;
    }
    
    unsigned char header[32];
    size_t read_bytes = fread(header, 1, sizeof(header), fp);
    fclose(fp);
    
    if (read_bytes < 4) {
        return FORMAT_CONFIDENCE_LOW;
    }
    
    bool magic_matches = false;
    
    switch (format) {
        case CERT_FORMAT_PEM:
            // Check for "-----BEGIN" marker
            if (read_bytes >= 11 && memcmp(header, "-----BEGIN ", 11) == 0) {
                magic_matches = true;
            }
            break;
        case CERT_FORMAT_DER:
            // Check for ASN.1 DER sequence tag (0x30)
            if (header[0] == 0x30 && (header[1] & 0x80)) {
                // Definite long form length encoding
                magic_matches = true;
            } else if (header[0] == 0x30 && header[1] < 0x80) {
                // Definite short form length encoding
                magic_matches = true;
            }
            break;
        case CERT_FORMAT_PKCS12:
            // Check for PKCS#12 magic bytes (ASN.1 sequence)
            if (header[0] == 0x30 && header[1] == 0x82) {
                // Common PKCS#12 pattern
                magic_matches = true;
            }
            break;
        default:
            break;
    }
    
    // Determine confidence level
    if (extension_matches && magic_matches) {
        return FORMAT_CONFIDENCE_HIGH;
    } else if (extension_matches || magic_matches) {
        return FORMAT_CONFIDENCE_MEDIUM;
    } else {
        return FORMAT_CONFIDENCE_LOW;
    }
}

// Create default configuration
cert_scanner_config_t cert_scanner_create_default_config(void) {
    cert_scanner_config_t config = {0};
    config.validate_trust_chains = true;
    config.check_revocation = false;  // Default --no-network
    config.detect_weak_signatures = true;
    config.trust_store_path = strdup("/etc/ssl/certs");
    config.recursive_scan = true;
    config.max_file_size = 10 * 1024 * 1024;  // 10MB max
    config.timeout_seconds = 30;
    
    // Default scan paths
    const char* default_paths[] = {
        "/etc/ssl/certs",
        "/etc/pki",
        "/usr/share/ca-certificates",
        "/etc/ssl/private",
        "/home",  // Will need permission handling
        "/root"   // Will need permission handling
    };
    
    config.scan_path_count = sizeof(default_paths) / sizeof(default_paths[0]);
    config.scan_paths = malloc(config.scan_path_count * sizeof(char*));
    if (config.scan_paths) {
        for (size_t i = 0; i < config.scan_path_count; i++) {
            config.scan_paths[i] = strdup(default_paths[i]);
        }
    }
    
    return config;
}

// Create certificate scanner context
cert_scanner_context_t* cert_scanner_create(const cert_scanner_config_t* config, 
                                           struct asset_store* store) {
    if (!config || !store) {
        set_error("Invalid parameters: config and store cannot be NULL");
        return NULL;
    }
    
    // Initialize secure memory if not already done
    static bool secure_memory_initialized = false;
    if (!secure_memory_initialized) {
        if (secure_memory_init() != 0) {
            set_error("Failed to initialize secure memory");
            return NULL;
        }
        secure_memory_initialized = true;
    }
    
    cert_scanner_context_t* context = secure_alloc(sizeof(cert_scanner_context_t));
    if (!context) {
        set_error("Failed to allocate memory for scanner context");
        return NULL;
    }
    
    // Deep copy configuration
    context->config = *config;
    context->config.trust_store_path = config->trust_store_path ? strdup(config->trust_store_path) : NULL;
    
    // Deep copy scan paths
    if (config->scan_paths && config->scan_path_count > 0) {
        context->config.scan_paths = malloc(config->scan_path_count * sizeof(char*));
        if (context->config.scan_paths) {
            for (size_t i = 0; i < config->scan_path_count; i++) {
                context->config.scan_paths[i] = config->scan_paths[i] ? strdup(config->scan_paths[i]) : NULL;
            }
        }
    } else {
        context->config.scan_paths = NULL;
        context->config.scan_path_count = 0;
    }
    
    context->asset_store = store;
    
    // Initialize OpenSSL trust store if trust chain validation is enabled
    if (config->validate_trust_chains) {
        context->trust_store = cert_load_system_trust_store(config->trust_store_path);
        if (!context->trust_store) {
            set_error("Failed to load system trust store from %s", 
                     config->trust_store_path ? config->trust_store_path : "default path");
            secure_free(context, sizeof(cert_scanner_context_t));
            return NULL;
        }
    }
    
    // Initialize statistics
    context->certificates_found = 0;
    context->certificates_processed = 0;
    context->weak_certificates = 0;
    context->expired_certificates = 0;
    
    // Initialize enhanced statistics structure
    memset(&context->stats, 0, sizeof(cert_scanner_stats_t));
    
    return context;
}

// Destroy certificate scanner context
void cert_scanner_destroy(cert_scanner_context_t* context) {
    if (!context) return;
    
    if (context->trust_store) {
        X509_STORE_free(context->trust_store);
    }
    
    // Free configuration strings
    free(context->config.trust_store_path);
    if (context->config.scan_paths) {
        for (size_t i = 0; i < context->config.scan_path_count; i++) {
            free(context->config.scan_paths[i]);
        }
        free(context->config.scan_paths);
    }
    
    secure_free(context, sizeof(cert_scanner_context_t));
}

// Detect certificate format from file
cert_format_t cert_detect_format(const char* file_path) {
    if (!file_path) return CERT_FORMAT_UNKNOWN;
    
    FILE* file = fopen(file_path, "rb");
    if (!file) return CERT_FORMAT_UNKNOWN;
    
    char buffer[32];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);
    
    if (bytes_read < 10) return CERT_FORMAT_UNKNOWN;
    
    // Check for PEM format
    if (strncmp(buffer, "-----BEGIN", 10) == 0) {
        return CERT_FORMAT_PEM;
    }
    
    // Check for DER format (ASN.1 sequence tag)
    if ((unsigned char)buffer[0] == 0x30) {
        return CERT_FORMAT_DER;
    }
    
    // Check for PKCS#12 format (starts with specific bytes)
    if (bytes_read >= 4 && 
        (unsigned char)buffer[0] == 0x30 && 
        (unsigned char)buffer[1] == 0x82) {
        // This is a heuristic - PKCS#12 files often start this way
        return CERT_FORMAT_PKCS12;
    }
    
    return CERT_FORMAT_UNKNOWN;
}

// Load certificate from PEM file
X509* cert_load_pem(const char* file_path) {
    FILE* file = fopen(file_path, "r");
    if (!file) {
        set_error("Failed to open PEM file: %s", strerror(errno));
        return NULL;
    }
    
    X509* cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    
    if (!cert) {
        set_error("Failed to parse PEM certificate: %s", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    
    return cert;
}

// Load certificate from DER file
X509* cert_load_der(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        set_error("Failed to open DER file: %s", strerror(errno));
        return NULL;
    }
    
    X509* cert = d2i_X509_fp(file, NULL);
    fclose(file);
    
    if (!cert) {
        set_error("Failed to parse DER certificate: %s", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    
    return cert;
}

// Load PKCS#12 file (certificate, private key, and CA certificates)
int cert_load_pkcs12(const char* file_path, const char* password, 
                     X509** cert, EVP_PKEY** pkey, STACK_OF(X509)** ca_certs) {
    if (!file_path || !cert) {
        set_error("Invalid parameters for PKCS#12 loading");
        return -1;
    }
    
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        set_error("Failed to open PKCS#12 file: %s", strerror(errno));
        return -1;
    }
    
    PKCS12* p12 = d2i_PKCS12_fp(file, NULL);
    fclose(file);
    
    if (!p12) {
        set_error("Failed to parse PKCS#12 file: %s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    
    int result = PKCS12_parse(p12, password, pkey, cert, ca_certs);
    PKCS12_free(p12);
    
    if (!result) {
        set_error("Failed to parse PKCS#12 contents: %s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    
    return 0;
}

// Load certificate from file based on detected format
X509* cert_load_from_file(const char* file_path, cert_format_t format) {
    if (!file_path) {
        set_error("File path cannot be NULL");
        return NULL;
    }
    
    if (format == CERT_FORMAT_UNKNOWN) {
        format = cert_detect_format(file_path);
    }
    
    switch (format) {
        case CERT_FORMAT_PEM:
            return cert_load_pem(file_path);
        case CERT_FORMAT_DER:
            return cert_load_der(file_path);
        case CERT_FORMAT_PKCS12: {
            X509* cert = NULL;
            EVP_PKEY* pkey = NULL;
            STACK_OF(X509)* ca_certs = NULL;
            
            // Try empty password first, then NULL
            if (cert_load_pkcs12(file_path, "", &cert, &pkey, &ca_certs) == 0 ||
                cert_load_pkcs12(file_path, NULL, &cert, &pkey, &ca_certs) == 0) {
                
                // Clean up private key and CA certs (we only want the certificate)
                if (pkey) EVP_PKEY_free(pkey);
                if (ca_certs) sk_X509_pop_free(ca_certs, X509_free);
                
                return cert;
            }
            return NULL;
        }
        default:
            set_error("Unsupported certificate format");
            return NULL;
    }
}

// Get subject name from certificate
char* cert_get_subject_name(X509* cert) {
    if (!cert) return NULL;
    
    X509_NAME* subject = X509_get_subject_name(cert);
    if (!subject) return NULL;
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    
    X509_NAME_print_ex(bio, subject, 0, XN_FLAG_ONELINE);
    
    char* buffer;
    long len = BIO_get_mem_data(bio, &buffer);
    char* result = strndup(buffer, len);
    
    BIO_free(bio);
    return result;
}

// Get issuer name from certificate
char* cert_get_issuer_name(X509* cert) {
    if (!cert) return NULL;
    
    X509_NAME* issuer = X509_get_issuer_name(cert);
    if (!issuer) return NULL;
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    
    X509_NAME_print_ex(bio, issuer, 0, XN_FLAG_ONELINE);
    
    char* buffer;
    long len = BIO_get_mem_data(bio, &buffer);
    char* result = strndup(buffer, len);
    
    BIO_free(bio);
    return result;
}

// Get certificate serial number
char* cert_get_serial_number(X509* cert) {
    if (!cert) return NULL;
    
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) return NULL;
    
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) return NULL;
    
    char* result = BN_bn2hex(bn);
    BN_free(bn);
    
    return result;
}

// Calculate SHA-256 fingerprint
char* cert_get_fingerprint_sha256(X509* cert) {
    if (!cert) return NULL;
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len;
    
    if (!X509_digest(cert, EVP_sha256(), digest, &digest_len)) {
        return NULL;
    }
    
    char* result = malloc(digest_len * 2 + 1);
    if (!result) return NULL;
    
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(result + i * 2, "%02x", digest[i]);
    }
    result[digest_len * 2] = '\0';
    
    return result;
}

// Calculate SHA-1 fingerprint
char* cert_get_fingerprint_sha1(X509* cert) {
    if (!cert) return NULL;
    
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len;
    
    if (!X509_digest(cert, EVP_sha1(), digest, &digest_len)) {
        return NULL;
    }
    
    char* result = malloc(digest_len * 2 + 1);
    if (!result) return NULL;
    
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(result + i * 2, "%02x", digest[i]);
    }
    result[digest_len * 2] = '\0';
    
    return result;
}

// Enhanced metadata extraction functions (4.1.1)
static char* extract_authority_key_id(X509* cert) {
    if (!cert) return NULL;
    
    AUTHORITY_KEYID* akid = X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
    if (!akid || !akid->keyid) {
        if (akid) AUTHORITY_KEYID_free(akid);
        return NULL;
    }
    
    // Convert to hex string
    char* hex_str = malloc(akid->keyid->length * 2 + 1);
    if (!hex_str) {
        AUTHORITY_KEYID_free(akid);
        return NULL;
    }
    
    for (int i = 0; i < akid->keyid->length; i++) {
        sprintf(hex_str + i * 2, "%02X", akid->keyid->data[i]);
    }
    hex_str[akid->keyid->length * 2] = '\0';
    
    AUTHORITY_KEYID_free(akid);
    return hex_str;
}

static char* extract_subject_key_id(X509* cert) {
    if (!cert) return NULL;
    
    ASN1_OCTET_STRING* skid = X509_get_ext_d2i(cert, NID_subject_key_identifier, NULL, NULL);
    if (!skid) return NULL;
    
    // Convert to hex string
    char* hex_str = malloc(skid->length * 2 + 1);
    if (!hex_str) {
        ASN1_OCTET_STRING_free(skid);
        return NULL;
    }
    
    for (int i = 0; i < skid->length; i++) {
        sprintf(hex_str + i * 2, "%02X", skid->data[i]);
    }
    hex_str[skid->length * 2] = '\0';
    
    ASN1_OCTET_STRING_free(skid);
    return hex_str;
}

static char* extract_serial_number_hex(X509* cert) {
    if (!cert) return NULL;
    
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) return NULL;
    
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) return NULL;
    
    char* hex_str = BN_bn2hex(bn);
    BN_free(bn);
    
    return hex_str; // Already uppercase hex from OpenSSL
}

// Extract signature hash algorithm (4.1 enhancement - fixed)
static char* extract_signature_hash(X509* cert) {
    if (!cert) return NULL;
    
    const X509_ALGOR* sig_alg;
    const ASN1_BIT_STRING* sig;
    X509_get0_signature(&sig, &sig_alg, cert);
    
    if (!sig_alg) return NULL;
    
    int nid = OBJ_obj2nid(sig_alg->algorithm);
    
    // Map specific signature algorithm NIDs to hash algorithms
    switch (nid) {
        case NID_sha1WithRSAEncryption:
        case NID_ecdsa_with_SHA1:
            return strdup("SHA1");
        case NID_sha256WithRSAEncryption:
        case NID_ecdsa_with_SHA256:
            return strdup("SHA256");
        case NID_sha384WithRSAEncryption:
        case NID_ecdsa_with_SHA384:
            return strdup("SHA384");
        case NID_sha512WithRSAEncryption:
        case NID_ecdsa_with_SHA512:
            return strdup("SHA512");
        case NID_md5WithRSAEncryption:
            return strdup("MD5");
        case NID_rsassaPss:
            // For RSA-PSS, need to extract hash from parameters
            return strdup("SHA256"); // Default for PSS, could be extracted from params
        case NID_ED25519:
        case NID_ED448:
            return strdup("NONE"); // EdDSA doesn't use separate hash
        default: {
            // Fallback: try to extract from algorithm name
            const char* sn = OBJ_nid2sn(nid);
            if (sn) {
                if (strstr(sn, "sha256") || strstr(sn, "SHA256")) return strdup("SHA256");
                if (strstr(sn, "sha384") || strstr(sn, "SHA384")) return strdup("SHA384");
                if (strstr(sn, "sha512") || strstr(sn, "SHA512")) return strdup("SHA512");
                if (strstr(sn, "sha1") || strstr(sn, "SHA1")) return strdup("SHA1");
                if (strstr(sn, "md5") || strstr(sn, "MD5")) return strdup("MD5");
            }
            return strdup("UNKNOWN");
        }
    }
}

// Extract public key algorithm OID (4.1 enhancement - fixed)
static char* extract_public_key_oid(X509* cert) {
    if (!cert) return NULL;
    
    X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(cert);
    if (!pubkey) return NULL;
    
    ASN1_OBJECT* alg_obj = NULL;
    if (X509_PUBKEY_get0_param(&alg_obj, NULL, NULL, NULL, pubkey) != 1) {
        return NULL;
    }
    
    if (!alg_obj) return NULL;
    
    char oid_buf[128];
    if (OBJ_obj2txt(oid_buf, sizeof(oid_buf), alg_obj, 1) <= 0) {
        return NULL;
    }
    
    return strdup(oid_buf);
}

// Extract signature algorithm OID (4.1 enhancement - fixed)
static char* extract_signature_oid(X509* cert) {
    if (!cert) return NULL;
    
    const X509_ALGOR* sig_alg;
    const ASN1_BIT_STRING* sig;
    X509_get0_signature(&sig, &sig_alg, cert);
    
    if (!sig_alg || !sig_alg->algorithm) return NULL;
    
    char oid_buf[128];
    if (OBJ_obj2txt(oid_buf, sizeof(oid_buf), sig_alg->algorithm, 1) <= 0) {
        return NULL;
    }
    
    return strdup(oid_buf);
}

// Extract public key size (4.1 enhancement)
static int extract_public_key_size(X509* cert) {
    if (!cert) return 0;
    
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return 0;
    
    int key_size = EVP_PKEY_bits(pkey);
    EVP_PKEY_free(pkey);
    
    return key_size;
}

// Extract EC curve information (4.1 enhancement)
static char* extract_ec_curve_name(X509* cert) {
    if (!cert) return NULL;
    
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return NULL;
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    // Use OpenSSL 3.0+ compatible approach
    char curve_name[64];
    size_t curve_name_len = sizeof(curve_name);
    
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, 
                                       curve_name, sizeof(curve_name), &curve_name_len) == 1) {
        EVP_PKEY_free(pkey);
        return strdup(curve_name);
    }
    
    EVP_PKEY_free(pkey);
    return NULL;
}

// Extract EC curve OID (4.1 enhancement)
static char* extract_ec_curve_oid(X509* cert) {
    if (!cert) return NULL;
    
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return NULL;
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    // Get curve name first, then convert to OID
    char curve_name[64];
    size_t curve_name_len = sizeof(curve_name);
    
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, 
                                       curve_name, sizeof(curve_name), &curve_name_len) == 1) {
        int nid = OBJ_sn2nid(curve_name);
        if (nid != NID_undef) {
            char oid_buf[128];
            OBJ_obj2txt(oid_buf, sizeof(oid_buf), OBJ_nid2obj(nid), 1);
            EVP_PKEY_free(pkey);
            return strdup(oid_buf);
        }
    }
    
    EVP_PKEY_free(pkey);
    return NULL;
}

// Extract Subject Alternative Names (4.1 enhancement)
static void extract_subject_alt_names(X509* cert, cert_metadata_t* metadata) {
    if (!cert || !metadata) return;
    
    STACK_OF(GENERAL_NAME)* san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!san_names) return;
    
    int san_count = sk_GENERAL_NAME_num(san_names);
    
    // Count each type first
    int dns_count = 0, ip_count = 0, uri_count = 0, email_count = 0, rid_count = 0;
    
    for (int i = 0; i < san_count; i++) {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(san_names, i);
        switch (gen->type) {
            case GEN_DNS: dns_count++; break;
            case GEN_IPADD: ip_count++; break;
            case GEN_URI: uri_count++; break;
            case GEN_EMAIL: email_count++; break;
            case GEN_RID: rid_count++; break;
        }
    }
    
    // Allocate arrays
    if (dns_count > 0) {
        metadata->san_dns = malloc(dns_count * sizeof(char*));
        metadata->san_dns_count = 0;
    }
    if (ip_count > 0) {
        metadata->san_ip = malloc(ip_count * sizeof(char*));
        metadata->san_ip_count = 0;
    }
    if (uri_count > 0) {
        metadata->san_uri = malloc(uri_count * sizeof(char*));
        metadata->san_uri_count = 0;
    }
    if (email_count > 0) {
        metadata->san_email = malloc(email_count * sizeof(char*));
        metadata->san_email_count = 0;
    }
    if (rid_count > 0) {
        metadata->san_rid = malloc(rid_count * sizeof(char*));
        metadata->san_rid_count = 0;
    }
    
    // Extract values
    for (int i = 0; i < san_count; i++) {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(san_names, i);
        char* value = NULL;
        
        switch (gen->type) {
            case GEN_DNS:
                if (gen->d.dNSName) {
                    value = malloc(gen->d.dNSName->length + 1);
                    memcpy(value, gen->d.dNSName->data, gen->d.dNSName->length);
                    value[gen->d.dNSName->length] = '\0';
                    metadata->san_dns[metadata->san_dns_count++] = value;
                }
                break;
            case GEN_IPADD:
                if (gen->d.iPAddress) {
                    // Convert IP address to string
                    if (gen->d.iPAddress->length == 4) {
                        // IPv4
                        value = malloc(16);
                        snprintf(value, 16, "%d.%d.%d.%d",
                                gen->d.iPAddress->data[0], gen->d.iPAddress->data[1],
                                gen->d.iPAddress->data[2], gen->d.iPAddress->data[3]);
                    } else if (gen->d.iPAddress->length == 16) {
                        // IPv6 - simplified representation
                        value = malloc(40);
                        snprintf(value, 40, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                gen->d.iPAddress->data[0], gen->d.iPAddress->data[1],
                                gen->d.iPAddress->data[2], gen->d.iPAddress->data[3],
                                gen->d.iPAddress->data[4], gen->d.iPAddress->data[5],
                                gen->d.iPAddress->data[6], gen->d.iPAddress->data[7],
                                gen->d.iPAddress->data[8], gen->d.iPAddress->data[9],
                                gen->d.iPAddress->data[10], gen->d.iPAddress->data[11],
                                gen->d.iPAddress->data[12], gen->d.iPAddress->data[13],
                                gen->d.iPAddress->data[14], gen->d.iPAddress->data[15]);
                    }
                    if (value) {
                        metadata->san_ip[metadata->san_ip_count++] = value;
                    }
                }
                break;
            case GEN_URI:
                if (gen->d.uniformResourceIdentifier) {
                    value = malloc(gen->d.uniformResourceIdentifier->length + 1);
                    memcpy(value, gen->d.uniformResourceIdentifier->data, gen->d.uniformResourceIdentifier->length);
                    value[gen->d.uniformResourceIdentifier->length] = '\0';
                    metadata->san_uri[metadata->san_uri_count++] = value;
                }
                break;
            case GEN_EMAIL:
                if (gen->d.rfc822Name) {
                    value = malloc(gen->d.rfc822Name->length + 1);
                    memcpy(value, gen->d.rfc822Name->data, gen->d.rfc822Name->length);
                    value[gen->d.rfc822Name->length] = '\0';
                    metadata->san_email[metadata->san_email_count++] = value;
                }
                break;
            case GEN_RID:
                if (gen->d.registeredID) {
                    char oid_buf[128];
                    OBJ_obj2txt(oid_buf, sizeof(oid_buf), gen->d.registeredID, 1);
                    metadata->san_rid[metadata->san_rid_count++] = strdup(oid_buf);
                }
                break;
        }
    }
    
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
}

// Extract RFC2253 normalized DN (4.1 enhancement)
static char* extract_rfc2253_dn(X509_NAME* name) {
    if (!name) return NULL;
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    
    char* result = malloc(len + 1);
    if (result) {
        memcpy(result, data, len);
        result[len] = '\0';
    }
    
    BIO_free(bio);
    return result;
}

// Convert time_t to ISO 8601 UTC string (4.1 enhancement)
static char* time_to_iso8601_utc(time_t timestamp) {
    if (timestamp == 0) return NULL;
    
    struct tm* utc_tm = gmtime(&timestamp);
    if (!utc_tm) return NULL;
    
    char* result = malloc(32);
    if (!result) return NULL;
    
    strftime(result, 32, "%Y-%m-%dT%H:%M:%SZ", utc_tm);
    return result;
}

// Check if certificate is self-signed
bool cert_is_self_signed(X509* cert) {
    if (!cert) return false;
    
    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME* issuer = X509_get_issuer_name(cert);
    
    if (!subject || !issuer) return false;
    
    return X509_NAME_cmp(subject, issuer) == 0;
}

// Determine certificate usage from extensions
cert_usage_t cert_determine_usage(X509* cert) {
    if (!cert) return CERT_USAGE_UNKNOWN;
    
    // Check if it's a CA certificate
    if (cert_is_ca_certificate(cert)) {
        return CERT_USAGE_CA_CERTIFICATE;
    }
    
    // Check Extended Key Usage extension
    EXTENDED_KEY_USAGE* ext_key_usage = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (ext_key_usage) {
        for (int i = 0; i < sk_ASN1_OBJECT_num(ext_key_usage); i++) {
            ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(ext_key_usage, i);
            int nid = OBJ_obj2nid(obj);
            
            switch (nid) {
                case NID_server_auth:
                    EXTENDED_KEY_USAGE_free(ext_key_usage);
                    return CERT_USAGE_TLS_SERVER;
                case NID_client_auth:
                    EXTENDED_KEY_USAGE_free(ext_key_usage);
                    return CERT_USAGE_TLS_CLIENT;
                case NID_code_sign:
                    EXTENDED_KEY_USAGE_free(ext_key_usage);
                    return CERT_USAGE_CODE_SIGNING;
                case NID_email_protect:
                    EXTENDED_KEY_USAGE_free(ext_key_usage);
                    return CERT_USAGE_EMAIL_PROTECTION;
                case NID_time_stamp:
                    EXTENDED_KEY_USAGE_free(ext_key_usage);
                    return CERT_USAGE_TIME_STAMPING;
            }
        }
        EXTENDED_KEY_USAGE_free(ext_key_usage);
    }
    
    return CERT_USAGE_UNKNOWN;
}

// Check if certificate is a CA certificate
bool cert_is_ca_certificate(X509* cert) {
    if (!cert) return false;
    
    BASIC_CONSTRAINTS* basic_constraints = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (basic_constraints) {
        bool is_ca = basic_constraints->ca != 0;
        BASIC_CONSTRAINTS_free(basic_constraints);
        return is_ca;
    }
    
    return false;
}

// Get public key algorithm name
char* cert_get_public_key_algorithm(X509* cert) {
    if (!cert) return NULL;
    
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return NULL;
    
    int key_type = EVP_PKEY_base_id(pkey);
    char* result = NULL;
    
    switch (key_type) {
        case EVP_PKEY_RSA:
            result = strdup("RSA");
            break;
        case EVP_PKEY_EC:
            result = strdup("ECDSA");
            break;
        case EVP_PKEY_ED25519:
            result = strdup("Ed25519");
            break;
        case EVP_PKEY_ED448:
            result = strdup("Ed448");
            break;
        case EVP_PKEY_DSA:
            result = strdup("DSA");
            break;
        default:
            result = strdup("Unknown");
            break;
    }
    
    EVP_PKEY_free(pkey);
    return result;
}

// Get public key size in bits
int cert_get_public_key_size(X509* cert) {
    if (!cert) return 0;
    
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return 0;
    
    int size = EVP_PKEY_bits(pkey);
    EVP_PKEY_free(pkey);
    
    return size;
}

// Get ECC curve name
char* cert_get_curve_name(X509* cert) {
    if (!cert) return NULL;
    
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return NULL;
    
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    // For now, just return a generic ECC indicator
    // In a full implementation, we would extract the actual curve name
    char* result = strdup("ECC");
    
    EVP_PKEY_free(pkey);
    return result;
}

// Analyze public key parameters
public_key_params_t cert_analyze_public_key(X509* cert) {
    public_key_params_t params = {0};
    
    if (!cert) return params;
    
    params.algorithm = cert_get_public_key_algorithm(cert);
    params.key_size = cert_get_public_key_size(cert);
    params.curve_name = cert_get_curve_name(cert);
    params.public_key_hash = cert_get_fingerprint_sha256(cert);
    
    // Get key usage extensions
    ASN1_BIT_STRING* key_usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (key_usage) {
        // Simple key usage extraction without deprecated functions
        int usage_bits = ASN1_BIT_STRING_get_bit(key_usage, 0);
        if (usage_bits >= 0) {
            params.key_usage = strdup("Key usage present");
        }
        ASN1_BIT_STRING_free(key_usage);
    }
    
    // Get extended key usage
    EXTENDED_KEY_USAGE* ext_key_usage = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (ext_key_usage) {
        // Simple extended key usage extraction
        int count = sk_ASN1_OBJECT_num(ext_key_usage);
        if (count > 0) {
            params.extended_key_usage = strdup("Extended key usage present");
        }
        EXTENDED_KEY_USAGE_free(ext_key_usage);
    }
    
    return params;
}

// Detect weak signatures and algorithms
weak_signature_flags_t cert_detect_weaknesses(X509* cert) {
    weak_signature_flags_t flags = {0};
    
    if (!cert) return flags;
    
    // Check signature algorithm
    const X509_ALGOR* sig_alg;
    X509_get0_signature(NULL, &sig_alg, cert);
    
    if (sig_alg) {
        int nid = OBJ_obj2nid(sig_alg->algorithm);
        
        // Check for weak signature algorithms
        if (nid == NID_md5WithRSAEncryption || nid == NID_md5WithRSA) {
            flags.uses_md5 = true;
        }
        if (nid == NID_sha1WithRSAEncryption || nid == NID_sha1WithRSA ||
            nid == NID_ecdsa_with_SHA1 || nid == NID_dsaWithSHA1) {
            flags.uses_sha1 = true;
        }
    }
    
    // Check public key strength
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey) {
        int key_type = EVP_PKEY_base_id(pkey);
        int key_size = EVP_PKEY_bits(pkey);
        
        if (key_type == EVP_PKEY_RSA && key_size < 2048) {
            flags.weak_rsa_key = true;
        }
        
        if (key_type == EVP_PKEY_EC) {
            // Check for weak curves (this is a simplified check)
            if (key_size < 224) {
                flags.weak_ecc_curve = true;
            }
        }
        
        EVP_PKEY_free(pkey);
    }
    
    return flags;
}

// Load system trust store
X509_STORE* cert_load_system_trust_store(const char* trust_store_path) {
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        set_error("Failed to create X509 store");
        return NULL;
    }
    
    // Set default verification parameters
    X509_STORE_set_verify_cb(store, NULL);
    
    // Load system CA certificates
    const char* ca_path = trust_store_path ? trust_store_path : "/etc/ssl/certs";
    
    if (X509_STORE_load_locations(store, NULL, ca_path) != 1) {
        // Try alternative paths
        if (X509_STORE_load_locations(store, "/etc/ssl/cert.pem", NULL) != 1 &&
            X509_STORE_load_locations(store, "/etc/pki/tls/certs/ca-bundle.crt", NULL) != 1) {
            set_error("Failed to load CA certificates from %s", ca_path);
            X509_STORE_free(store);
            return NULL;
        }
    }
    
    return store;
}

// Validate certificate trust chain
trust_chain_result_t cert_validate_trust_chain(cert_scanner_context_t* context, X509* cert) {
    trust_chain_result_t result = {0};
    result.status = TRUST_UNKNOWN;
    result.validation_time = time(NULL);
    
    if (!context || !cert || !context->trust_store) {
        result.status = TRUST_CHAIN_INCOMPLETE;
        result.validation_error = strdup("Invalid parameters or no trust store");
        return result;
    }
    
    // Check if self-signed
    if (cert_is_self_signed(cert)) {
        result.status = TRUST_SELF_SIGNED;
        result.validation_error = strdup("Certificate is self-signed");
        return result;
    }
    
    // Create store context for validation
    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        result.status = TRUST_CHAIN_INCOMPLETE;
        result.validation_error = strdup("Failed to create store context");
        return result;
    }
    
    // Initialize store context
    if (X509_STORE_CTX_init(store_ctx, context->trust_store, cert, NULL) != 1) {
        result.status = TRUST_CHAIN_INCOMPLETE;
        result.validation_error = strdup("Failed to initialize store context");
        X509_STORE_CTX_free(store_ctx);
        return result;
    }
    
    // Perform verification
    int verify_result = X509_verify_cert(store_ctx);
    
    if (verify_result == 1) {
        result.status = TRUST_VALID;
        result.is_ca_trusted = true;
        
        // Get the verified chain
        STACK_OF(X509)* chain = X509_STORE_CTX_get1_chain(store_ctx);
        if (chain) {
            int chain_len = sk_X509_num(chain);
            result.chain_subjects = malloc(chain_len * sizeof(char*));
            result.chain_length = chain_len;
            
            for (int i = 0; i < chain_len; i++) {
                X509* chain_cert = sk_X509_value(chain, i);
                result.chain_subjects[i] = cert_get_subject_name(chain_cert);
            }
            
            // Get root CA name
            if (chain_len > 0) {
                X509* root_cert = sk_X509_value(chain, chain_len - 1);
                result.root_ca = cert_get_subject_name(root_cert);
            }
            
            sk_X509_pop_free(chain, X509_free);
        }
    } else {
        int error = X509_STORE_CTX_get_error(store_ctx);
        
        // Enhanced OpenSSL error mapping (4.1.2)
        switch (error) {
            case X509_V_ERR_CERT_HAS_EXPIRED:
                result.status = TRUST_EXPIRED;
                break;
            case X509_V_ERR_CERT_NOT_YET_VALID:
                result.status = TRUST_NOT_YET_VALID;
                break;
            case X509_V_ERR_CERT_REVOKED:
                result.status = TRUST_REVOKED;
                break;
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                result.status = TRUST_UNTRUSTED_CA;
                break;
            case X509_V_ERR_CERT_CHAIN_TOO_LONG:
                result.status = TRUST_CHAIN_INCOMPLETE;
                break;
            case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
                result.status = TRUST_WEAK_SIGNATURE;
                break;
            case X509_V_ERR_UNABLE_TO_GET_CRL:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_CRL_NOT_YET_VALID:
                result.status = TRUST_CHAIN_INCOMPLETE;
                break;
            default:
                result.status = TRUST_UNKNOWN;
                break;
        }
        
        result.validation_error = strdup(X509_verify_cert_error_string(error));
    }
    
    X509_STORE_CTX_free(store_ctx);
    return result;
}

// Extract certificate metadata
cert_metadata_t* cert_extract_metadata(X509* cert, const char* file_path) {
    if (!cert) return NULL;
    
    cert_metadata_t* metadata = secure_alloc(sizeof(cert_metadata_t));
    if (!metadata) return NULL;
    
    // Initialize all fields to zero/NULL to prevent crashes in cleanup
    memset(metadata, 0, sizeof(cert_metadata_t));
    
    // Basic certificate information
    metadata->subject = cert_get_subject_name(cert);
    metadata->issuer = cert_get_issuer_name(cert);
    metadata->serial_number = cert_get_serial_number(cert);
    metadata->fingerprint_sha1 = cert_get_fingerprint_sha1(cert);
    metadata->fingerprint_sha256 = cert_get_fingerprint_sha256(cert);
    
    // Validity period
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    
    if (not_before) {
        metadata->not_before = asn1_time_to_time_t(not_before);
    }
    if (not_after) {
        metadata->not_after = asn1_time_to_time_t(not_after);
    }
    
    // Signature algorithm
    const X509_ALGOR* sig_alg;
    X509_get0_signature(NULL, &sig_alg, cert);
    if (sig_alg) {
        int nid = OBJ_obj2nid(sig_alg->algorithm);
        metadata->signature_algorithm = strdup(OBJ_nid2sn(nid));
    }
    
    // Public key algorithm
    metadata->public_key_algorithm = cert_get_public_key_algorithm(cert);
    
    // Certificate usage
    metadata->usage = cert_determine_usage(cert);
    
    // Public key parameters
    metadata->public_key_params = cert_analyze_public_key(cert);
    
    // Weakness detection
    metadata->weak_signatures = cert_detect_weaknesses(cert);
    
    // Format detection
    if (file_path) {
        metadata->format = cert_detect_format(file_path);
    }
    
    // Extract Authority Key Identifier (AKI)
    metadata->authority_key_id = extract_authority_key_id(cert);
    
    // Extract Subject Key Identifier (SKI)
    metadata->subject_key_id = extract_subject_key_id(cert);
    
    // Extract serial number in hex format
    metadata->serial_number_hex = extract_serial_number_hex(cert);
    
    // Extract enhanced algorithm information (4.1 enhancement)
    metadata->signature_hash = extract_signature_hash(cert);
    metadata->public_key_oid = extract_public_key_oid(cert);
    metadata->signature_oid = extract_signature_oid(cert);
    metadata->public_key_size = extract_public_key_size(cert);
    metadata->ec_curve_name = extract_ec_curve_name(cert);
    metadata->ec_curve_oid = extract_ec_curve_oid(cert);
    
    // Extract Subject Alternative Names
    extract_subject_alt_names(cert, metadata);
    
    // Extract RFC2253 normalized DN forms
    X509_NAME* subject_name = X509_get_subject_name(cert);
    X509_NAME* issuer_name = X509_get_issuer_name(cert);
    metadata->subject_rfc2253 = extract_rfc2253_dn(subject_name);
    metadata->issuer_rfc2253 = extract_rfc2253_dn(issuer_name);
    
    // Extract normalized UTC times
    metadata->not_before_utc = time_to_iso8601_utc(metadata->not_before);
    metadata->not_after_utc = time_to_iso8601_utc(metadata->not_after);
    
    // Extract BasicConstraints
    metadata->is_ca = cert_is_ca_certificate(cert);
    metadata->path_length = cert_get_path_length_constraint(cert);
    
    // Extract KeyUsage
    metadata->key_usage = cert_get_key_usage_strings(cert, &metadata->key_usage_count);
    
    // Extract ExtendedKeyUsage
    metadata->extended_key_usage = cert_get_extended_key_usage_strings(cert, &metadata->extended_key_usage_count);

    // Extract Authority Information Access (Issue #8)
    cert_get_authority_info_access(cert, metadata);

    // Extract Certificate Policies (Issue #8)
    cert_get_certificate_policies(cert, metadata);

    // Generate normalized serial number in hex
    metadata->serial_number_hex = cert_get_serial_number_hex(cert);
    
    // Determine validity status
    time_t now = time(NULL);
    if (now < metadata->not_before) {
        metadata->validity_status = VALIDITY_NOT_YET_VALID;
    } else if (now > metadata->not_after) {
        metadata->validity_status = VALIDITY_EXPIRED;
    } else {
        metadata->validity_status = VALIDITY_VALID;
    }
    
    return metadata;
}

// Create crypto asset from certificate metadata
struct crypto_asset* cert_create_asset(const cert_metadata_t* metadata, const char* file_path, X509* cert) {
    if (!metadata) return NULL;

    struct crypto_asset* asset = crypto_asset_create(metadata->subject, ASSET_TYPE_CERTIFICATE);
    if (!asset) return NULL;
    
    // Set basic properties
    asset->location = file_path ? strdup(file_path) : NULL;
    asset->algorithm = metadata->public_key_algorithm ? strdup(metadata->public_key_algorithm) : NULL;
    
    // Determine if certificate is weak
    asset->is_weak = metadata->weak_signatures.uses_md5 || 
                     metadata->weak_signatures.uses_sha1 ||
                     metadata->weak_signatures.weak_rsa_key ||
                     metadata->weak_signatures.weak_ecc_curve;
    
    // PQC readiness (simplified - certificates are generally not PQC ready yet)
    asset->is_pqc_ready = false;
    
    // Generate content-addressed ID
    asset->id = cert_generate_asset_id(metadata);

    // Create detailed JSON metadata with algorithm granularity (4.1.2 + 5.2 enhancement)
    asset->metadata_json = cert_create_detailed_json_metadata(metadata, cert);

    return asset;
}

// Generate asset ID from certificate metadata
char* cert_generate_asset_id(const cert_metadata_t* metadata) {
    if (!metadata) return NULL;
    
    // Create normalized string for hashing
    char* normalized = malloc(1024);
    if (!normalized) return NULL;
    
    snprintf(normalized, 1024, "cert:%s:%s:%s:%ld:%ld",
             metadata->subject ? metadata->subject : "",
             metadata->issuer ? metadata->issuer : "",
             metadata->serial_number ? metadata->serial_number : "",
             metadata->not_before,
             metadata->not_after);
    
    // Calculate SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)normalized, strlen(normalized), hash);
    
    // Convert to hex string
    char* id = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (id) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(id + i * 2, "%02x", hash[i]);
        }
        id[SHA256_DIGEST_LENGTH * 2] = '\0';
    }
    
    free(normalized);
    return id;
}

// Helper function to check if certificate is self-signed from metadata
static bool cert_is_self_signed_from_metadata(const cert_metadata_t* metadata) {
    if (!metadata || !metadata->subject || !metadata->issuer) return false;
    return strcmp(metadata->subject, metadata->issuer) == 0;
}

// Create detailed JSON metadata for certificate (4.1.2 + 5.2 enhancement)
char* cert_create_detailed_json_metadata(const cert_metadata_t* metadata, X509* cert) {
    if (!metadata) return NULL;

    json_object* cert_obj = json_object_new_object();
    if (!cert_obj) return NULL;

    // Basic certificate information
    json_object_object_add(cert_obj, "subject", json_object_new_string(metadata->subject ? metadata->subject : ""));
    json_object_object_add(cert_obj, "issuer", json_object_new_string(metadata->issuer ? metadata->issuer : ""));
    json_object_object_add(cert_obj, "serial_number", json_object_new_string(metadata->serial_number ? metadata->serial_number : ""));
    
    // Separate signature vs. public-key algorithm (4.1 enhancement)
    json_object_object_add(cert_obj, "signature_algorithm", json_object_new_string(metadata->signature_algorithm ? metadata->signature_algorithm : ""));
    json_object_object_add(cert_obj, "public_key_algorithm", json_object_new_string(metadata->public_key_algorithm ? metadata->public_key_algorithm : ""));
    
    // Enhanced algorithm information
    if (metadata->signature_hash) {
        json_object_object_add(cert_obj, "signature_hash", json_object_new_string(metadata->signature_hash));
    }
    if (metadata->public_key_oid) {
        json_object_object_add(cert_obj, "public_key_oid", json_object_new_string(metadata->public_key_oid));
    }
    if (metadata->signature_oid) {
        json_object_object_add(cert_obj, "signature_oid", json_object_new_string(metadata->signature_oid));
    }
    
    // Key size and curve information
    if (metadata->public_key_size > 0) {
        json_object_object_add(cert_obj, "public_key_size", json_object_new_int(metadata->public_key_size));
    }
    if (metadata->ec_curve_name) {
        json_object_object_add(cert_obj, "ec_curve_name", json_object_new_string(metadata->ec_curve_name));
    }
    if (metadata->ec_curve_oid) {
        json_object_object_add(cert_obj, "ec_curve_oid", json_object_new_string(metadata->ec_curve_oid));
    }
    
    // Validity information
    json_object_object_add(cert_obj, "not_before", json_object_new_int64(metadata->not_before));
    json_object_object_add(cert_obj, "not_after", json_object_new_int64(metadata->not_after));
    
    // Fingerprints (4.1 enhancement - ensure SHA256 is included)
    json_object_object_add(cert_obj, "fingerprint_sha1", json_object_new_string(metadata->fingerprint_sha1 ? metadata->fingerprint_sha1 : ""));
    json_object_object_add(cert_obj, "fingerprint_sha256", json_object_new_string(metadata->fingerprint_sha256 ? metadata->fingerprint_sha256 : ""));
    
    // RFC2253 normalized DN forms (4.1 enhancement)
    if (metadata->subject_rfc2253) {
        json_object_object_add(cert_obj, "subject_rfc2253", json_object_new_string(metadata->subject_rfc2253));
    }
    if (metadata->issuer_rfc2253) {
        json_object_object_add(cert_obj, "issuer_rfc2253", json_object_new_string(metadata->issuer_rfc2253));
    }
    
    // Normalized UTC times (4.1 enhancement)
    if (metadata->not_before_utc) {
        json_object_object_add(cert_obj, "not_before_utc", json_object_new_string(metadata->not_before_utc));
    }
    if (metadata->not_after_utc) {
        json_object_object_add(cert_obj, "not_after_utc", json_object_new_string(metadata->not_after_utc));
    }
    
    // Certificate properties
    json_object_object_add(cert_obj, "is_ca", json_object_new_boolean(metadata->is_ca));
    json_object_object_add(cert_obj, "is_self_signed", json_object_new_boolean(cert_is_self_signed_from_metadata(metadata)));
    
    // Enhanced metadata (4.1.1)
    if (metadata->authority_key_id) {
        json_object_object_add(cert_obj, "authority_key_id", json_object_new_string(metadata->authority_key_id));
    }
    if (metadata->subject_key_id) {
        json_object_object_add(cert_obj, "subject_key_id", json_object_new_string(metadata->subject_key_id));
    }
    if (metadata->serial_number_hex) {
        json_object_object_add(cert_obj, "serial_number_hex", json_object_new_string(metadata->serial_number_hex));
    }
    
    json_object_object_add(cert_obj, "path_length", json_object_new_int(metadata->path_length));
    
    // Key usage information
    if (metadata->key_usage && metadata->key_usage_count > 0) {
        json_object* key_usage_array = json_object_new_array();
        for (size_t i = 0; i < metadata->key_usage_count; i++) {
            json_object_array_add(key_usage_array, json_object_new_string(metadata->key_usage[i]));
        }
        json_object_object_add(cert_obj, "key_usage", key_usage_array);
    }
    
    if (metadata->extended_key_usage && metadata->extended_key_usage_count > 0) {
        json_object* eku_array = json_object_new_array();
        for (size_t i = 0; i < metadata->extended_key_usage_count; i++) {
            json_object_array_add(eku_array, json_object_new_string(metadata->extended_key_usage[i]));
        }
        json_object_object_add(cert_obj, "extended_key_usage", eku_array);
    }

    // Authority Information Access (Issue #8)
    if (metadata->aia_ocsp_count > 0 || metadata->aia_ca_issuers_count > 0) {
        json_object* aia_obj = json_object_new_object();

        if (metadata->aia_ocsp_count > 0) {
            json_object* ocsp_array = json_object_new_array();
            for (size_t i = 0; i < metadata->aia_ocsp_count; i++) {
                json_object_array_add(ocsp_array, json_object_new_string(metadata->aia_ocsp_urls[i]));
            }
            json_object_object_add(aia_obj, "ocsp", ocsp_array);
        }

        if (metadata->aia_ca_issuers_count > 0) {
            json_object* ca_issuers_array = json_object_new_array();
            for (size_t i = 0; i < metadata->aia_ca_issuers_count; i++) {
                json_object_array_add(ca_issuers_array, json_object_new_string(metadata->aia_ca_issuers_urls[i]));
            }
            json_object_object_add(aia_obj, "caIssuers", ca_issuers_array);
        }

        json_object_object_add(cert_obj, "authorityInfoAccess", aia_obj);
    }

    // Certificate Policies (Issue #8)
    if (metadata->cert_policy_count > 0) {
        json_object* policies_array = json_object_new_array();

        for (size_t i = 0; i < metadata->cert_policy_count; i++) {
            json_object* policy_obj = json_object_new_object();
            json_object_object_add(policy_obj, "policyIdentifier",
                                  json_object_new_string(metadata->cert_policies[i].oid));

            if (metadata->cert_policies[i].qualifier) {
                json_object* qualifiers_array = json_object_new_array();
                json_object* qual_obj = json_object_new_object();

                // Determine qualifier type (CPS if it's a URL, userNotice otherwise)
                const char* type = strstr(metadata->cert_policies[i].qualifier, "http") ? "cps" : "userNotice";
                json_object_object_add(qual_obj, "type", json_object_new_string(type));
                json_object_object_add(qual_obj, "qualifier",
                                      json_object_new_string(metadata->cert_policies[i].qualifier));

                json_object_array_add(qualifiers_array, qual_obj);
                json_object_object_add(policy_obj, "policyQualifiers", qualifiers_array);
            }

            json_object_array_add(policies_array, policy_obj);
        }

        json_object_object_add(cert_obj, "certificatePolicies", policies_array);
    }

    // Validity status
    const char* validity_status_str = "UNKNOWN";
    switch (metadata->validity_status) {
        case VALIDITY_VALID: validity_status_str = "VALID"; break;
        case VALIDITY_NOT_YET_VALID: validity_status_str = "NOT_YET_VALID"; break;
        case VALIDITY_EXPIRED: validity_status_str = "EXPIRED"; break;
        default: break;
    }
    json_object_object_add(cert_obj, "validity_status", json_object_new_string(validity_status_str));
    
    // Trust validation status (4.1.2 enhancement)
    const char* trust_status_str = "UNKNOWN";
    switch (metadata->trust_validation.status) {
        case TRUST_VALID: trust_status_str = "VALID"; break;
        case TRUST_EXPIRED: trust_status_str = "EXPIRED"; break;
        case TRUST_NOT_YET_VALID: trust_status_str = "NOT_YET_VALID"; break;
        case TRUST_REVOKED: trust_status_str = "REVOKED"; break;
        case TRUST_UNTRUSTED_CA: trust_status_str = "UNTRUSTED_CA"; break;
        case TRUST_SELF_SIGNED: trust_status_str = "SELF_SIGNED"; break;
        case TRUST_CHAIN_INCOMPLETE: trust_status_str = "CHAIN_INCOMPLETE"; break;
        case TRUST_WEAK_SIGNATURE: trust_status_str = "WEAK_SIGNATURE"; break;
        default: trust_status_str = "UNKNOWN"; break;
    }
    json_object_object_add(cert_obj, "cbom:cert:trust_status", json_object_new_string(trust_status_str));
    
    // Trust validation details
    if (metadata->trust_validation.validation_error) {
        json_object_object_add(cert_obj, "cbom:cert:trust_error", json_object_new_string(metadata->trust_validation.validation_error));
    }
    json_object_object_add(cert_obj, "cbom:cert:trust_validation_time", json_object_new_int64(metadata->trust_validation.validation_time));
    json_object_object_add(cert_obj, "cbom:cert:ca_trusted", json_object_new_boolean(metadata->trust_validation.is_ca_trusted));
    
    // Subject Alternative Names (4.1 enhancement)
    if (metadata->san_dns && metadata->san_dns_count > 0) {
        json_object* san_dns_array = json_object_new_array();
        for (size_t i = 0; i < metadata->san_dns_count; i++) {
            json_object_array_add(san_dns_array, json_object_new_string(metadata->san_dns[i]));
        }
        json_object_object_add(cert_obj, "san_dns", san_dns_array);
    }
    
    if (metadata->san_ip && metadata->san_ip_count > 0) {
        json_object* san_ip_array = json_object_new_array();
        for (size_t i = 0; i < metadata->san_ip_count; i++) {
            json_object_array_add(san_ip_array, json_object_new_string(metadata->san_ip[i]));
        }
        json_object_object_add(cert_obj, "san_ip", san_ip_array);
    }
    
    if (metadata->san_uri && metadata->san_uri_count > 0) {
        json_object* san_uri_array = json_object_new_array();
        for (size_t i = 0; i < metadata->san_uri_count; i++) {
            json_object_array_add(san_uri_array, json_object_new_string(metadata->san_uri[i]));
        }
        json_object_object_add(cert_obj, "san_uri", san_uri_array);
    }
    
    if (metadata->san_email && metadata->san_email_count > 0) {
        json_object* san_email_array = json_object_new_array();
        for (size_t i = 0; i < metadata->san_email_count; i++) {
            json_object_array_add(san_email_array, json_object_new_string(metadata->san_email[i]));
        }
        json_object_object_add(cert_obj, "san_email", san_email_array);
    }
    
    if (metadata->san_rid && metadata->san_rid_count > 0) {
        json_object* san_rid_array = json_object_new_array();
        for (size_t i = 0; i < metadata->san_rid_count; i++) {
            json_object_array_add(san_rid_array, json_object_new_string(metadata->san_rid[i]));
        }
        json_object_object_add(cert_obj, "san_rid", san_rid_array);
    }

    // === Phase 5.2: Add Granular Algorithm Metadata (Req 1.5, 1.6, 1.7) ===
    if (cert) {
        // Parse public key algorithm metadata
        algorithm_granular_t* pubkey_algo = algorithm_parse_from_x509_public_key(cert);
        if (pubkey_algo) {
            // Add public key algorithm granularity
            json_object* pubkey_properties = (json_object*)algorithm_to_json_properties(pubkey_algo);
            if (pubkey_properties && json_object_array_length(pubkey_properties) > 0) {
                // Merge properties into cert_obj
                for (size_t i = 0; i < json_object_array_length(pubkey_properties); i++) {
                    json_object* prop = json_object_array_get_idx(pubkey_properties, i);
                    json_object* name_obj = NULL;
                    json_object* value_obj = NULL;
                    if (json_object_object_get_ex(prop, "name", &name_obj) &&
                        json_object_object_get_ex(prop, "value", &value_obj)) {
                        const char* name = json_object_get_string(name_obj);
                        const char* value = json_object_get_string(value_obj);
                        // Prefix with "pubkey:" to distinguish from signature algorithm
                        char prefixed_name[256];
                        snprintf(prefixed_name, sizeof(prefixed_name), "pubkey:%s", name);
                        json_object_object_add(cert_obj, prefixed_name, json_object_new_string(value));
                    }
                }
                json_object_put(pubkey_properties);
            }
            algorithm_metadata_destroy(pubkey_algo);
        }

        // Parse signature algorithm metadata
        algorithm_granular_t* sig_algo = algorithm_parse_from_x509_signature(cert);
        if (sig_algo) {
            // Add signature algorithm granularity
            json_object* sig_properties = (json_object*)algorithm_to_json_properties(sig_algo);
            if (sig_properties && json_object_array_length(sig_properties) > 0) {
                // Merge properties into cert_obj
                for (size_t i = 0; i < json_object_array_length(sig_properties); i++) {
                    json_object* prop = json_object_array_get_idx(sig_properties, i);
                    json_object* name_obj = NULL;
                    json_object* value_obj = NULL;
                    if (json_object_object_get_ex(prop, "name", &name_obj) &&
                        json_object_object_get_ex(prop, "value", &value_obj)) {
                        const char* name = json_object_get_string(name_obj);
                        const char* value = json_object_get_string(value_obj);
                        // Prefix with "sig:" to distinguish from public key algorithm
                        char prefixed_name[256];
                        snprintf(prefixed_name, sizeof(prefixed_name), "sig:%s", name);
                        json_object_object_add(cert_obj, prefixed_name, json_object_new_string(value));
                    }
                }
                json_object_put(sig_properties);
            }
            algorithm_metadata_destroy(sig_algo);
        }
    }

    // Convert to JSON string
    const char* json_str = json_object_to_json_string(cert_obj);
    char* result = json_str ? strdup(json_str) : NULL;

    json_object_put(cert_obj);
    return result;
}

// Scan a single certificate file
int cert_scanner_scan_file(cert_scanner_context_t* context, const char* file_path) {
    if (!context || !file_path) {
        set_error("Invalid parameters");
        return -1;
    }
    
    // Increment files scanned total
    context->stats.files_scanned_total++;
    
    // Check file size limit
    struct stat st;
    if (stat(file_path, &st) != 0) {
        set_error("Failed to stat file %s: %s", file_path, strerror(errno));
        cert_scanner_record_failure(context, CERT_FAIL_IO_ERROR, file_path);
        return -1;
    }

    if ((size_t)st.st_size > context->config.max_file_size) {
        set_error("File %s exceeds size limit (%zu bytes)", file_path, context->config.max_file_size);
        cert_scanner_record_failure(context, CERT_FAIL_TOO_LARGE, file_path);
        return -1;
    }
    
    // Check file extension first (cheap filter)
    const char* ext = strrchr(file_path, '.');
    if (ext) {
        ext++; // Skip the dot
        if (strcasecmp(ext, "pem") == 0 || strcasecmp(ext, "crt") == 0 || 
            strcasecmp(ext, "cer") == 0 || strcasecmp(ext, "der") == 0 ||
            strcasecmp(ext, "p12") == 0 || strcasecmp(ext, "pfx") == 0 ||
            strcasecmp(ext, "key") == 0 || strcasecmp(ext, "pub") == 0) {
            context->stats.files_extension_matched++;
        }
    }
    
    // Detect certificate format
    cert_format_t format = cert_detect_format(file_path);
    
    if (format == CERT_FORMAT_UNKNOWN) {
        // Not a certificate file, skip silently
        return 0;
    }
    
    // Count format detection
    context->stats.files_with_parsable_certs++;
    switch (format) {
        case CERT_FORMAT_PEM:
            context->stats.pem_detected++;
            break;
        case CERT_FORMAT_DER:
            context->stats.der_detected++;
            break;
        case CERT_FORMAT_PKCS12:
            context->stats.pkcs12_detected++;
            break;
        default:
            break;
    }
    
    // Try to load and parse certificates from the file
    int cert_count = cert_load_and_process_file(context, file_path, format);
    if (cert_count < 0) {
        // Error already recorded by cert_load_and_process_file
        return -1;
    }
    
    context->certificates_found += cert_count;
    
    return 0;
}

// Scan directory for certificates
int cert_scanner_scan_directory(cert_scanner_context_t* context, const char* dir_path) {
    if (!context || !dir_path) {
        set_error("Invalid parameters");
        return -1;
    }
    
    DIR* dir = opendir(dir_path);
    if (!dir) {
        // Permission denied or directory doesn't exist - not an error
        return 0;
    }
    
    struct dirent* entry;
    int processed = 0;
    int files_checked = 0;
    static atomic_size_t global_file_counter = 0;  // Atomic: thread-safe across parallel scanners
    static time_t last_progress = 0;
    if (last_progress == 0) last_progress = time(NULL);

    while ((entry = readdir(dir)) != NULL) {
        files_checked++;
        size_t current_count = atomic_fetch_add(&global_file_counter, 1) + 1;

        // Progress reporting: every 1000 files OR every 10 seconds
        time_t now = time(NULL);
        if (current_count % 1000 == 0 || (now - last_progress) >= 10) {
            tui_log(TUI_MSG_SCANNER_PROGRESS, SCANNER_CERTIFICATE,
                    "Certificate scanner", current_count, context->certificates_found, NULL, dir_path);
            last_progress = now;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char* full_path = malloc(strlen(dir_path) + strlen(entry->d_name) + 2);
        if (!full_path) continue;
        
        sprintf(full_path, "%s/%s", dir_path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                // Pre-filter by file extension to avoid scanning non-certificate files
                const char* name = entry->d_name;
                size_t len = strlen(name);
                bool is_likely_cert = false;
                
                if (len > 4) {
                    const char* ext = name + len - 4;
                    if (strcasecmp(ext, ".pem") == 0 || 
                        strcasecmp(ext, ".crt") == 0 ||
                        strcasecmp(ext, ".cer") == 0 ||
                        strcasecmp(ext, ".der") == 0) {
                        is_likely_cert = true;
                    }
                }
                
                // Check for .p12, .pfx extensions
                if (!is_likely_cert && len >= 4) {
                    const char* ext3 = name + len - 3;
                    if (strcasecmp(ext3, ".p12") == 0 || strcasecmp(ext3, ".pfx") == 0) {
                        is_likely_cert = true;
                    }
                }
                
                // Only scan files that look like certificates
                if (is_likely_cert) {
                    if (cert_scanner_scan_file(context, full_path) == 0) {
                        processed++;
                    }
                }
            } else if (S_ISDIR(st.st_mode) && context->config.recursive_scan) {
                // Directory - recurse if enabled, but skip common non-certificate directories
                const char* dirname = entry->d_name;
                if (strcmp(dirname, "proc") != 0 && 
                    strcmp(dirname, "sys") != 0 && 
                    strcmp(dirname, "dev") != 0 &&
                    strcmp(dirname, "tmp") != 0 &&
                    strncmp(dirname, ".", 1) != 0) {  // Skip hidden directories
                    processed += cert_scanner_scan_directory(context, full_path);
                }
            }
        }
        
        free(full_path);
    }
    
    closedir(dir);
    return processed;
}

// Scan all configured paths
int cert_scanner_scan_paths(cert_scanner_context_t* context) {
    if (!context) {
        set_error("Invalid context");
        return -1;
    }
    
    int total_processed = 0;
    
    for (size_t i = 0; i < context->config.scan_path_count; i++) {
        const char* path = context->config.scan_paths[i];
        if (!path) continue;
        
        struct stat st;
        if (stat(path, &st) != 0) {
            // Path doesn't exist or no permission - skip
            continue;
        }
        
        if (S_ISREG(st.st_mode)) {
            // Single file
            if (cert_scanner_scan_file(context, path) == 0) {
                total_processed++;
            }
        } else if (S_ISDIR(st.st_mode)) {
            // Directory
            total_processed += cert_scanner_scan_directory(context, path);
        }
    }
    
    return total_processed;
}

// Get scanner statistics
cert_scanner_stats_t cert_scanner_get_stats(cert_scanner_context_t* context) {
    cert_scanner_stats_t stats = {0};
    
    if (context) {
        // Copy all statistics from context
        stats = context->stats;
        
        // Populate legacy compatibility fields
        stats.certificates_found = context->stats.certs_detected_total;
        stats.certificates_processed = context->stats.certs_parsed_ok;
        
        // Validate counter consistency: detected_total = parsed_ok + failed_total
        size_t expected_detected = stats.certs_parsed_ok + stats.certs_failed_total;
        if (stats.certs_detected_total != expected_detected) {
            fprintf(stderr, "WARNING: Counter inconsistency detected!\n");
            fprintf(stderr, "  certs_detected_total: %zu\n", stats.certs_detected_total);
            fprintf(stderr, "  certs_parsed_ok: %zu\n", stats.certs_parsed_ok);
            fprintf(stderr, "  certs_failed_total: %zu\n", stats.certs_failed_total);
            fprintf(stderr, "  Expected detected (parsed + failed): %zu\n", expected_detected);

            // Auto-correct the failed_total to maintain consistency
            stats.certs_failed_total = stats.certs_detected_total - stats.certs_parsed_ok;
            fprintf(stderr, "  Auto-corrected certs_failed_total to: %zu\n", stats.certs_failed_total);
        }

        // Validate failure breakdown consistency
        size_t total_failures_by_reason = 0;
        for (int i = 0; i < CERT_FAIL_REASON_COUNT; i++) {
            total_failures_by_reason += stats.certs_failed_by_reason[i];
        }

        fprintf(stderr, "INFO: Failure breakdown validation:\n");
        fprintf(stderr, "  Total failures by reason sum: %zu\n", total_failures_by_reason);
        fprintf(stderr, "  Post-detection failures (failed_total): %zu\n", stats.certs_failed_total);
        fprintf(stderr, "  Pre-detection failures: %zu\n", total_failures_by_reason - stats.certs_failed_total);
    }
    
    return stats;
}

// Generate CBOM diagnostic entries
cbom_diagnostic_entry_t* cert_scanner_generate_cbom_diagnostics(cert_scanner_context_t* context, size_t* count) {
    if (!context || !count) return NULL;
    
    // Calculate total number of diagnostic entries
    size_t total_entries = 20 + CERT_FAIL_REASON_COUNT; // Base entries + failure reasons
    cbom_diagnostic_entry_t* entries = calloc(total_entries, sizeof(cbom_diagnostic_entry_t));
    if (!entries) return NULL;
    
    size_t idx = 0;
    
    // Helper macro for adding entries
    #define ADD_DIAGNOSTIC(name_str, value_fmt, ...) do { \
        if (asprintf(&entries[idx].name, name_str) < 0 || \
            asprintf(&entries[idx].value, value_fmt, __VA_ARGS__) < 0) { \
            cbom_diagnostic_entries_destroy(entries, idx); \
            return NULL; \
        } \
        idx++; \
    } while(0)
    
    // File-level diagnostics
    ADD_DIAGNOSTIC("cbom:diagnostics:files_scanned_total", "%zu", context->stats.files_scanned_total);
    ADD_DIAGNOSTIC("cbom:diagnostics:files_extension_matched", "%zu", context->stats.files_extension_matched);
    ADD_DIAGNOSTIC("cbom:diagnostics:files_with_parsable_certs", "%zu", context->stats.files_with_parsable_certs);
    ADD_DIAGNOSTIC("cbom:diagnostics:files_quarantined", "%zu", context->stats.files_quarantined);
    
    // Certificate-level diagnostics
    ADD_DIAGNOSTIC("cbom:diagnostics:certs_detected_total", "%zu", context->stats.certs_detected_total);
    ADD_DIAGNOSTIC("cbom:diagnostics:certs_parsed_ok", "%zu", context->stats.certs_parsed_ok);
    ADD_DIAGNOSTIC("cbom:diagnostics:certs_failed_total", "%zu", context->stats.certs_failed_total);
    
    // Format breakdown - detected
    ADD_DIAGNOSTIC("cbom:diagnostics:pem_detected", "%zu", context->stats.pem_detected);
    ADD_DIAGNOSTIC("cbom:diagnostics:der_detected", "%zu", context->stats.der_detected);
    ADD_DIAGNOSTIC("cbom:diagnostics:pkcs12_detected", "%zu", context->stats.pkcs12_detected);
    
    // Format breakdown - parsed successfully
    ADD_DIAGNOSTIC("cbom:diagnostics:pem_parsed_ok", "%zu", context->stats.pem_parsed_ok);
    ADD_DIAGNOSTIC("cbom:diagnostics:der_parsed_ok", "%zu", context->stats.der_parsed_ok);
    ADD_DIAGNOSTIC("cbom:diagnostics:pkcs12_parsed_ok", "%zu", context->stats.pkcs12_parsed_ok);
    
    // Multi-payload containers
    ADD_DIAGNOSTIC("cbom:diagnostics:multi_cert_pem_files", "%zu", context->stats.multi_cert_pem_files);
    ADD_DIAGNOSTIC("cbom:diagnostics:multi_cert_p12_files", "%zu", context->stats.multi_cert_p12_files);
    ADD_DIAGNOSTIC("cbom:diagnostics:total_cert_payloads_in_files", "%zu", context->stats.total_cert_payloads_in_files);
    
    // Certificate properties
    ADD_DIAGNOSTIC("cbom:diagnostics:weak_certificates", "%zu", context->stats.weak_certificates);
    ADD_DIAGNOSTIC("cbom:diagnostics:expired_certificates", "%zu", context->stats.expired_certificates);
    ADD_DIAGNOSTIC("cbom:diagnostics:self_signed_certificates", "%zu", context->stats.self_signed_certificates);
    ADD_DIAGNOSTIC("cbom:diagnostics:ca_certificates", "%zu", context->stats.ca_certificates);
    
    // Failure reasons breakdown
    for (int i = 0; i < CERT_FAIL_REASON_COUNT; i++) {
        if (context->stats.certs_failed_by_reason[i] > 0) {
            if (asprintf(&entries[idx].name, "cbom:diagnostics:certs_failed_by_reason:%s", 
                        cert_failure_reason_to_string((cert_failure_reason_t)i)) < 0 ||
                asprintf(&entries[idx].value, "%zu", context->stats.certs_failed_by_reason[i]) < 0) {
                cbom_diagnostic_entries_destroy(entries, idx);
                return NULL;
            }
            idx++;
        }
    }
    
    #undef ADD_DIAGNOSTIC
    
    *count = idx;
    return entries;
}

// Cleanup CBOM diagnostic entries
void cbom_diagnostic_entries_destroy(cbom_diagnostic_entry_t* entries, size_t count) {
    if (!entries) return;
    
    for (size_t i = 0; i < count; i++) {
        free(entries[i].name);
        free(entries[i].value);
    }
    free(entries);
}

// Enhanced metadata extraction functions

// Extract Subject Key Identifier (SKI)
char* cert_get_subject_key_id(X509* cert) {
    if (!cert) return NULL;
    
    ASN1_OCTET_STRING* ski = X509_get_ext_d2i(cert, NID_subject_key_identifier, NULL, NULL);
    if (!ski) return NULL;
    
    char* hex_ski = malloc(ski->length * 2 + 1);
    if (!hex_ski) {
        ASN1_OCTET_STRING_free(ski);
        return NULL;
    }
    
    for (int i = 0; i < ski->length; i++) {
        sprintf(hex_ski + (i * 2), "%02X", ski->data[i]);
    }
    hex_ski[ski->length * 2] = '\0';
    
    ASN1_OCTET_STRING_free(ski);
    return hex_ski;
}

// Extract path length constraint from BasicConstraints
int cert_get_path_length_constraint(X509* cert) {
    if (!cert) return -1;
    
    BASIC_CONSTRAINTS* basic_constraints = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (!basic_constraints) return -1;
    
    int path_length = -1;
    if (basic_constraints->pathlen) {
        path_length = ASN1_INTEGER_get(basic_constraints->pathlen);
    }
    
    BASIC_CONSTRAINTS_free(basic_constraints);
    return path_length;
}

// Extract KeyUsage extension as string array
char** cert_get_key_usage_strings(X509* cert, size_t* count) {
    if (!cert || !count) return NULL;
    
    *count = 0;
    ASN1_BIT_STRING* key_usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (!key_usage) return NULL;
    
    // Map key usage bits to strings
    const char* usage_names[] = {
        "digitalSignature",    // 0
        "nonRepudiation",      // 1
        "keyEncipherment",     // 2
        "dataEncipherment",    // 3
        "keyAgreement",        // 4
        "keyCertSign",         // 5
        "cRLSign",             // 6
        "encipherOnly",        // 7
        "decipherOnly"         // 8
    };
    
    char** usage_strings = malloc(9 * sizeof(char*));
    if (!usage_strings) {
        ASN1_BIT_STRING_free(key_usage);
        return NULL;
    }
    
    size_t usage_count = 0;
    for (int i = 0; i < 9; i++) {
        if (ASN1_BIT_STRING_get_bit(key_usage, i)) {
            usage_strings[usage_count] = strdup(usage_names[i]);
            usage_count++;
        }
    }
    
    ASN1_BIT_STRING_free(key_usage);
    
    if (usage_count == 0) {
        free(usage_strings);
        return NULL;
    }
    
    *count = usage_count;
    return usage_strings;
}

// Extract ExtendedKeyUsage extension as string array
char** cert_get_extended_key_usage_strings(X509* cert, size_t* count) {
    if (!cert || !count) return NULL;
    
    *count = 0;
    EXTENDED_KEY_USAGE* ext_key_usage = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (!ext_key_usage) return NULL;
    
    int eku_count = sk_ASN1_OBJECT_num(ext_key_usage);
    if (eku_count <= 0) {
        EXTENDED_KEY_USAGE_free(ext_key_usage);
        return NULL;
    }
    
    char** eku_strings = malloc(eku_count * sizeof(char*));
    if (!eku_strings) {
        EXTENDED_KEY_USAGE_free(ext_key_usage);
        return NULL;
    }
    
    size_t valid_count = 0;
    for (int i = 0; i < eku_count; i++) {
        ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(ext_key_usage, i);
        if (obj) {
            int nid = OBJ_obj2nid(obj);
            const char* name = OBJ_nid2sn(nid);
            if (name) {
                eku_strings[valid_count] = strdup(name);
                valid_count++;
            }
        }
    }
    
    EXTENDED_KEY_USAGE_free(ext_key_usage);
    
    if (valid_count == 0) {
        free(eku_strings);
        return NULL;
    }
    
    *count = valid_count;
    return eku_strings;
}

// Get serial number in normalized hex format
char* cert_get_serial_number_hex(X509* cert) {
    if (!cert) return NULL;
    
    ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(cert);
    if (!serial_asn1) return NULL;
    
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial_asn1, NULL);
    if (!bn) return NULL;
    
    char* hex_str = BN_bn2hex(bn);
    BN_free(bn);
    
    // Convert to uppercase for consistency
    if (hex_str) {
        for (char* p = hex_str; *p; p++) {
            *p = toupper(*p);
        }
    }
    
    return hex_str;
}

// Validate URL format (Issue #8 - prevents malformed URLs)
static bool is_valid_url(const char* url) {
    if (!url) return false;

    // Must start with http:// or https://
    if (strncmp(url, "http://", 7) != 0 &&
        strncmp(url, "https://", 8) != 0) {
        return false;
    }

    // Sanity checks
    size_t len = strlen(url);
    if (len > 2048) return false;      // Too long
    if (len < 10) return false;        // Too short (http://a.b minimum)
    if (strchr(url, ' ')) return false; // No spaces allowed

    return true;
}

// Extract Authority Information Access extension (Issue #8)
static void cert_get_authority_info_access(X509* cert, cert_metadata_t* metadata) {
    if (!cert || !metadata) return;

    AUTHORITY_INFO_ACCESS* aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (!aia) {
        // Missing extension - normal, just return
        return;
    }

    int aia_count = sk_ACCESS_DESCRIPTION_num(aia);

    // Count OCSP and CA Issuers separately
    int ocsp_count = 0, ca_issuer_count = 0;
    for (int i = 0; i < aia_count; i++) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        int nid = OBJ_obj2nid(ad->method);
        if (nid == NID_ad_OCSP) ocsp_count++;
        else if (nid == NID_ad_ca_issuers) ca_issuer_count++;
    }

    // Allocate arrays
    if (ocsp_count > 0) {
        metadata->aia_ocsp_urls = secure_alloc(ocsp_count * sizeof(char*));
        if (!metadata->aia_ocsp_urls) {
            fprintf(stderr, "ERROR: Memory allocation failed for AIA OCSP URLs\n");
            AUTHORITY_INFO_ACCESS_free(aia);
            return;
        }
    }
    if (ca_issuer_count > 0) {
        metadata->aia_ca_issuers_urls = secure_alloc(ca_issuer_count * sizeof(char*));
        if (!metadata->aia_ca_issuers_urls) {
            fprintf(stderr, "ERROR: Memory allocation failed for AIA CA Issuers URLs\n");
            if (metadata->aia_ocsp_urls) {
                secure_free(metadata->aia_ocsp_urls, ocsp_count * sizeof(char*));
                metadata->aia_ocsp_urls = NULL;
            }
            AUTHORITY_INFO_ACCESS_free(aia);
            return;
        }
    }

    // Extract URLs
    int ocsp_idx = 0, ca_idx = 0;
    for (int i = 0; i < aia_count; i++) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        int nid = OBJ_obj2nid(ad->method);

        if (ad->location && ad->location->type == GEN_URI) {
            ASN1_STRING* uri = ad->location->d.uniformResourceIdentifier;
            const char* url = (const char*)ASN1_STRING_get0_data(uri);

            // Validate URL before storing
            if (is_valid_url(url)) {
                if (nid == NID_ad_OCSP && ocsp_idx < ocsp_count) {
                    metadata->aia_ocsp_urls[ocsp_idx++] = strdup(url);
                } else if (nid == NID_ad_ca_issuers && ca_idx < ca_issuer_count) {
                    metadata->aia_ca_issuers_urls[ca_idx++] = strdup(url);
                }
            } else {
                // Log warning but continue
                size_t url_len = strlen(url);
                fprintf(stderr, "WARNING: Invalid URL in AIA: %.*s\n",
                       (int)(url_len < 100 ? url_len : 100), url);
            }
        }
    }

    metadata->aia_ocsp_count = ocsp_idx;
    metadata->aia_ca_issuers_count = ca_idx;

    AUTHORITY_INFO_ACCESS_free(aia);
}

// Extract Certificate Policies extension (Issue #8)
static void cert_get_certificate_policies(X509* cert, cert_metadata_t* metadata) {
    if (!cert || !metadata) return;

    CERTIFICATEPOLICIES* policies = X509_get_ext_d2i(cert, NID_certificate_policies, NULL, NULL);
    if (!policies) {
        // Missing extension - normal, just return
        return;
    }

    int policy_count = sk_POLICYINFO_num(policies);
    if (policy_count == 0) {
        CERTIFICATEPOLICIES_free(policies);
        return;
    }

    // Allocate policy array
    metadata->cert_policies = secure_alloc(policy_count * sizeof(cert_policy_t));
    if (!metadata->cert_policies) {
        fprintf(stderr, "ERROR: Memory allocation failed for certificate policies\n");
        CERTIFICATEPOLICIES_free(policies);
        return;
    }

    // Initialize all policies to NULL
    for (int i = 0; i < policy_count; i++) {
        metadata->cert_policies[i].oid = NULL;
        metadata->cert_policies[i].qualifier = NULL;
    }

    // Extract policies
    int valid_count = 0;
    for (int i = 0; i < policy_count; i++) {
        POLICYINFO* policy = sk_POLICYINFO_value(policies, i);
        if (!policy) continue;

        // Extract OID (required)
        char oid_buf[128];
        int oid_len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), policy->policyid, 1);
        if (oid_len <= 0 || (size_t)oid_len >= sizeof(oid_buf)) {
            fprintf(stderr, "WARNING: Invalid policy OID at index %d\n", i);
            continue;  // Skip invalid OID
        }

        metadata->cert_policies[valid_count].oid = strdup(oid_buf);
        metadata->cert_policies[valid_count].qualifier = NULL;  // Default

        // Extract qualifier (optional)
        if (policy->qualifiers && sk_POLICYQUALINFO_num(policy->qualifiers) > 0) {
            POLICYQUALINFO* qual = sk_POLICYQUALINFO_value(policy->qualifiers, 0);
            if (qual) {
                int qual_nid = OBJ_obj2nid(qual->pqualid);

                if (qual_nid == NID_id_qt_cps && qual->d.cpsuri) {
                    // CPS URI
                    const char* cps = (const char*)ASN1_STRING_get0_data(qual->d.cpsuri);
                    if (cps && is_valid_url(cps)) {
                        metadata->cert_policies[valid_count].qualifier = strdup(cps);
                    }
                } else if (qual_nid == NID_id_qt_unotice) {
                    // User Notice
                    metadata->cert_policies[valid_count].qualifier = strdup("user-notice");
                }
            }
        }

        valid_count++;
    }

    metadata->cert_policy_count = valid_count;
    CERTIFICATEPOLICIES_free(policies);
}

// Cleanup functions
void cert_metadata_destroy(cert_metadata_t* metadata) {
    if (!metadata) return;
    
    free(metadata->subject);
    free(metadata->issuer);
    free(metadata->signature_algorithm);
    free(metadata->public_key_algorithm);
    free(metadata->serial_number);
    free(metadata->serial_number_hex);
    free(metadata->fingerprint_sha1);
    free(metadata->fingerprint_sha256);
    free(metadata->authority_key_id);
    free(metadata->subject_key_id);
    
    // Clean up key usage arrays
    if (metadata->key_usage) {
        for (size_t i = 0; i < metadata->key_usage_count; i++) {
            free(metadata->key_usage[i]);
        }
        free(metadata->key_usage);
    }
    
    if (metadata->extended_key_usage) {
        for (size_t i = 0; i < metadata->extended_key_usage_count; i++) {
            free(metadata->extended_key_usage[i]);
        }
        free(metadata->extended_key_usage);
    }

    // Clean up AIA URLs (Issue #8)
    // CRITICAL: Free strings BEFORE freeing array
    if (metadata->aia_ocsp_urls) {
        for (size_t i = 0; i < metadata->aia_ocsp_count; i++) {
            free(metadata->aia_ocsp_urls[i]);  // strdup() strings freed with free()
        }
        // Array allocated with secure_alloc(), so free with secure_free()
        size_t ocsp_size = metadata->aia_ocsp_count * sizeof(char*);
        secure_free(metadata->aia_ocsp_urls, ocsp_size);
    }

    if (metadata->aia_ca_issuers_urls) {
        for (size_t i = 0; i < metadata->aia_ca_issuers_count; i++) {
            free(metadata->aia_ca_issuers_urls[i]);  // strdup() strings freed with free()
        }
        // Array allocated with secure_alloc(), so free with secure_free()
        size_t ca_issuers_size = metadata->aia_ca_issuers_count * sizeof(char*);
        secure_free(metadata->aia_ca_issuers_urls, ca_issuers_size);
    }

    // Clean up Certificate Policies (Issue #8)
    if (metadata->cert_policies) {
        for (size_t i = 0; i < metadata->cert_policy_count; i++) {
            free(metadata->cert_policies[i].oid);        // strdup() strings freed with free()
            free(metadata->cert_policies[i].qualifier);  // Safe even if NULL
        }
        // Array allocated with secure_alloc(), so free with secure_free()
        size_t policies_size = metadata->cert_policy_count * sizeof(cert_policy_t);
        secure_free(metadata->cert_policies, policies_size);
    }

    // Clean up extensions
    if (metadata->extensions) {
        for (size_t i = 0; i < metadata->extension_count; i++) {
            cert_extension_destroy(&metadata->extensions[i]);
        }
        free(metadata->extensions);
    }
    
    // Clean up SAN entries
    if (metadata->san_entries) {
        for (size_t i = 0; i < metadata->san_count; i++) {
            free(metadata->san_entries[i]);
        }
        free(metadata->san_entries);
    }
    
    // Clean up enhanced fields (4.1 enhancement)
    free(metadata->signature_hash);
    free(metadata->public_key_oid);
    free(metadata->signature_oid);
    free(metadata->ec_curve_name);
    free(metadata->ec_curve_oid);
    
    // Clean up SAN arrays
    if (metadata->san_dns) {
        for (size_t i = 0; i < metadata->san_dns_count; i++) {
            free(metadata->san_dns[i]);
        }
        free(metadata->san_dns);
    }
    if (metadata->san_ip) {
        for (size_t i = 0; i < metadata->san_ip_count; i++) {
            free(metadata->san_ip[i]);
        }
        free(metadata->san_ip);
    }
    if (metadata->san_uri) {
        for (size_t i = 0; i < metadata->san_uri_count; i++) {
            free(metadata->san_uri[i]);
        }
        free(metadata->san_uri);
    }
    if (metadata->san_email) {
        for (size_t i = 0; i < metadata->san_email_count; i++) {
            free(metadata->san_email[i]);
        }
        free(metadata->san_email);
    }
    if (metadata->san_rid) {
        for (size_t i = 0; i < metadata->san_rid_count; i++) {
            free(metadata->san_rid[i]);
        }
        free(metadata->san_rid);
    }
    
    // Clean up RFC2253 DN forms
    free(metadata->subject_rfc2253);
    free(metadata->issuer_rfc2253);
    
    // Clean up UTC time strings
    free(metadata->not_before_utc);
    free(metadata->not_after_utc);
    
    // Clean up nested structures
    trust_chain_result_destroy(&metadata->trust_validation);
    weak_signature_flags_destroy(&metadata->weak_signatures);
    ca_info_destroy(&metadata->ca_info);
    public_key_params_destroy(&metadata->public_key_params);
    
    secure_free(metadata, sizeof(cert_metadata_t));
}

void cert_extension_destroy(cert_extension_t* extension) {
    if (!extension) return;
    
    free(extension->oid);
    free(extension->value);
    free(extension->raw_value);
}

void trust_chain_result_destroy(trust_chain_result_t* result) {
    if (!result) return;
    
    if (result->chain_subjects) {
        for (size_t i = 0; i < result->chain_length; i++) {
            free(result->chain_subjects[i]);
        }
        free(result->chain_subjects);
    }
    
    free(result->root_ca);
    free(result->validation_error);
}

void weak_signature_flags_destroy(weak_signature_flags_t* flags) {
    if (!flags) return;
    
    if (flags->weak_algorithms) {
        for (size_t i = 0; i < flags->weak_count; i++) {
            free(flags->weak_algorithms[i]);
        }
        free(flags->weak_algorithms);
    }
}

void ca_info_destroy(ca_info_t* info) {
    if (!info) return;
    
    free(info->ca_name);
    free(info->ca_oid);
    free(info->ca_key_id);
}

void public_key_params_destroy(public_key_params_t* params) {
    if (!params) return;

    free(params->algorithm);
    free(params->curve_name);
    free(params->public_key_hash);
    free(params->key_usage);
    free(params->extended_key_usage);
}

#else /* __EMSCRIPTEN__ — WASM stubs for certificate scanner */

/*
 * WASM build: certificate parsing requires OpenSSL which is not available.
 * These stubs provide the public API so builtin_scanners.c links correctly.
 * All scanning functions return 0 (no certificates found).
 * Phase 2 will replace these with a JS bridge to pkijs.
 */

static __thread char last_error[256] = "Crypto parsing not available in WASM";

static void set_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_error, sizeof(last_error), fmt, args);
    va_end(args);
}

const char* cert_scanner_get_last_error(void) {
    return last_error;
}

void cert_scanner_clear_error(void) {
    last_error[0] = '\0';
}

cert_scanner_config_t cert_scanner_create_default_config(void) {
    cert_scanner_config_t config = {0};
    config.validate_trust_chains = false;
    config.check_revocation = false;
    config.detect_weak_signatures = false;
    config.recursive_scan = true;
    config.max_file_size = 10 * 1024 * 1024;
    config.timeout_seconds = 30;
    return config;
}

cert_scanner_context_t* cert_scanner_create(const cert_scanner_config_t* config,
                                           struct asset_store* store) {
    if (!config || !store) return NULL;

    cert_scanner_context_t* ctx = calloc(1, sizeof(cert_scanner_context_t));
    if (!ctx) return NULL;

    ctx->config = *config;
    ctx->asset_store = store;
    return ctx;
}

void cert_scanner_destroy(cert_scanner_context_t* context) {
    if (!context) return;
    free(context->config.trust_store_path);
    if (context->config.scan_paths) {
        for (size_t i = 0; i < context->config.scan_path_count; i++) {
            free(context->config.scan_paths[i]);
        }
        free(context->config.scan_paths);
    }
    free(context);
}

int cert_scanner_scan_file(cert_scanner_context_t* context, const char* file_path) {
    (void)context; (void)file_path;
    return 0;
}

int cert_scanner_scan_directory(cert_scanner_context_t* context, const char* dir_path) {
    (void)context; (void)dir_path;
    return 0;
}

int cert_scanner_scan_paths(cert_scanner_context_t* context) {
    (void)context;
    return 0;
}

cert_scanner_stats_t cert_scanner_get_stats(cert_scanner_context_t* context) {
    cert_scanner_stats_t stats = {0};
    if (context) {
        stats = context->stats;
    }
    return stats;
}

cert_format_t cert_detect_format(const char* file_path) {
    (void)file_path;
    return CERT_FORMAT_UNKNOWN;
}

const char* cert_failure_reason_to_string(cert_failure_reason_t reason) {
    switch (reason) {
        case CERT_FAIL_INVALID_PEM_BLOCK: return "INVALID_PEM_BLOCK";
        case CERT_FAIL_DER_TRUNCATED: return "DER_TRUNCATED";
        case CERT_FAIL_DER_OVERLONG: return "DER_OVERLONG";
        case CERT_FAIL_P12_BAD_PASSWORD: return "P12_BAD_PASSWORD";
        case CERT_FAIL_P12_UNSUPPORTED_PBE: return "P12_UNSUPPORTED_PBE";
        case CERT_FAIL_P12_NO_MAC: return "P12_NO_MAC";
        case CERT_FAIL_UNSUPPORTED_SIGALG: return "UNSUPPORTED_SIGALG";
        case CERT_FAIL_UNSUPPORTED_KEY_TYPE: return "UNSUPPORTED_KEY_TYPE";
        case CERT_FAIL_TOO_LARGE: return "TOO_LARGE";
        case CERT_FAIL_TOO_DEEP: return "TOO_DEEP";
        case CERT_FAIL_TIMEOUT: return "TIMEOUT";
        case CERT_FAIL_SANITY_LIMIT_HIT: return "SANITY_LIMIT_HIT";
        case CERT_FAIL_MEMORY_ERROR: return "MEMORY_ERROR";
        case CERT_FAIL_IO_ERROR: return "IO_ERROR";
        case CERT_FAIL_UNKNOWN: return "UNKNOWN";
        default: return "INVALID_REASON";
    }
}

void cert_scanner_record_failure(cert_scanner_context_t* context,
                                 cert_failure_reason_t reason,
                                 const char* file_path) {
    (void)context; (void)reason; (void)file_path;
}

void cert_scanner_record_parsing_failure(cert_scanner_context_t* context,
                                         cert_failure_reason_t reason,
                                         const char* file_path) {
    (void)context; (void)reason; (void)file_path;
}

format_confidence_t cert_assess_format_confidence(const char* file_path,
                                                  cert_format_t format) {
    (void)file_path; (void)format;
    return FORMAT_CONFIDENCE_LOW;
}

void cert_metadata_destroy(cert_metadata_t* metadata) {
    if (!metadata) return;
    free(metadata->subject);
    free(metadata->issuer);
    free(metadata->signature_algorithm);
    free(metadata->public_key_algorithm);
    free(metadata->serial_number);
    free(metadata->serial_number_hex);
    free(metadata->fingerprint_sha1);
    free(metadata->fingerprint_sha256);
    free(metadata);
}

void cert_extension_destroy(cert_extension_t* ext) {
    if (!ext) return;
    free(ext->oid);
    free(ext->value);
    free(ext->raw_value);
}

void trust_chain_result_destroy(trust_chain_result_t* result) {
    if (!result) return;
    if (result->chain_subjects) {
        for (size_t i = 0; i < result->chain_length; i++) {
            free(result->chain_subjects[i]);
        }
        free(result->chain_subjects);
    }
    free(result->root_ca);
    free(result->validation_error);
}

void weak_signature_flags_destroy(weak_signature_flags_t* flags) {
    if (!flags) return;
    if (flags->weak_algorithms) {
        for (size_t i = 0; i < flags->weak_count; i++) {
            free(flags->weak_algorithms[i]);
        }
        free(flags->weak_algorithms);
    }
}

void ca_info_destroy(ca_info_t* info) {
    if (!info) return;
    free(info->ca_name);
    free(info->ca_oid);
    free(info->ca_key_id);
}

void public_key_params_destroy(public_key_params_t* params) {
    if (!params) return;
    free(params->algorithm);
    free(params->curve_name);
    free(params->public_key_hash);
    free(params->key_usage);
    free(params->extended_key_usage);
}

char* cert_generate_asset_id(const cert_metadata_t* metadata) {
    (void)metadata;
    return NULL;
}

cbom_diagnostic_entry_t* cert_scanner_generate_cbom_diagnostics(
    cert_scanner_context_t* context, size_t* count) {
    (void)context;
    if (count) *count = 0;
    return NULL;
}

void cbom_diagnostic_entries_destroy(cbom_diagnostic_entry_t* entries, size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        free(entries[i].name);
        free(entries[i].value);
    }
    free(entries);
}

#endif /* __EMSCRIPTEN__ */
