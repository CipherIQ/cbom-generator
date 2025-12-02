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

// Issue #5: Error remediation and impact assessment system
#include "error_remediation.h"
#include <string.h>
#include <stdio.h>

// Remediation mappings for certificate failures
typedef struct {
    cert_failure_reason_t reason;
    const char* impact_level;      // "critical", "high", "medium", "low"
    const char* suggestion;         // Remediation guidance
    const char* details;            // Additional technical details
} cert_error_remediation_t;

// Certificate error remediation database
static const cert_error_remediation_t CERT_REMEDIATIONS[] = {
    {
        CERT_FAIL_MEMORY_ERROR,
        "high",
        "Check for corrupted certificate files or increase available memory. Verify file integrity with 'openssl x509 -in <file> -text -noout'",
        "Memory errors during certificate parsing often indicate corrupted files, especially with error:0480006C (PEM no start line). This may also occur with malformed PEM headers or certificate bundles."
    },
    {
        CERT_FAIL_IO_ERROR,
        "medium",
        "Check file permissions and disk space. Verify file exists and is readable",
        "I/O errors typically indicate permission issues or missing files. Ensure the scanner has read access to certificate directories."
    },
    {
        CERT_FAIL_INVALID_PEM_BLOCK,
        "low",
        "Verify certificate format. Expected PEM format with '-----BEGIN CERTIFICATE-----' header. Try converting with 'openssl x509 -inform DER -outform PEM'",
        "Invalid PEM blocks may indicate DER-encoded certificates with .pem extension, corrupted base64 encoding, or non-certificate files."
    },
    {
        CERT_FAIL_DER_TRUNCATED,
        "medium",
        "File appears to be truncated or incomplete. Re-download or regenerate the certificate",
        "DER truncation errors indicate the file was corrupted during transfer or storage. Check file size against expected size."
    },
    {
        CERT_FAIL_DER_OVERLONG,
        "medium",
        "DER encoding uses overlong form (potential security issue). Regenerate certificate with compliant encoding",
        "Overlong DER encoding violates X.690 standard and may indicate malicious certificate crafting or buggy certificate generation."
    },
    {
        CERT_FAIL_P12_BAD_PASSWORD,
        "high",
        "PKCS#12 file requires password. Provide password or convert to PEM format using 'openssl pkcs12 -in <file> -out <file>.pem'",
        "PKCS#12 files (.p12, .pfx) typically contain encrypted private keys and require a password. The scanner tries empty password and NULL."
    },
    {
        CERT_FAIL_P12_UNSUPPORTED_PBE,
        "medium",
        "PKCS#12 uses unsupported password-based encryption. Convert to PEM using OpenSSL 3.0+",
        "Some legacy PBE algorithms are no longer supported in OpenSSL 3.0. Use 'openssl pkcs12 -legacy' option for conversion."
    },
    {
        CERT_FAIL_P12_NO_MAC,
        "low",
        "PKCS#12 file has no MAC (integrity check). This is unusual but may be intentional",
        "PKCS#12 files should include MAC for integrity verification. Missing MAC may indicate file corruption or non-standard generation."
    },
    {
        CERT_FAIL_UNSUPPORTED_SIGALG,
        "high",
        "Certificate uses unsupported signature algorithm. Verify OpenSSL version supports this algorithm",
        "Some newer signature algorithms (e.g., Ed25519, dilithium) may not be supported in older OpenSSL versions. Upgrade to OpenSSL 3.0+ if needed."
    },
    {
        CERT_FAIL_UNSUPPORTED_KEY_TYPE,
        "high",
        "Certificate uses unsupported public key type. Verify OpenSSL version supports this key type",
        "Post-quantum algorithms and newer ECC curves may require OpenSSL 3.0+ or special provider modules."
    },
    {
        CERT_FAIL_TOO_LARGE,
        "medium",
        "Certificate file exceeds size limit. Increase --max-file-size or verify file is not corrupted",
        "Unusually large certificate files may indicate bundles, corrupted files, or security threats. Default limit prevents resource exhaustion."
    },
    {
        CERT_FAIL_TOO_DEEP,
        "medium",
        "Certificate chain exceeds maximum depth. This may indicate a circular chain or misconfiguration",
        "Maximum chain depth prevents infinite loops in chain validation. Verify certificate issuers form a valid trust chain."
    },
    {
        CERT_FAIL_TIMEOUT,
        "low",
        "Certificate processing exceeded timeout limit. Increase timeout or simplify certificate structure",
        "Timeouts prevent denial-of-service from complex certificates. Check for excessive extensions or nested structures."
    },
    {
        CERT_FAIL_SANITY_LIMIT_HIT,
        "medium",
        "Certificate has excessive extensions or complex structure. This may indicate malformed certificate",
        "Sanity limits prevent resource exhaustion from pathological certificates with thousands of extensions."
    },
    {
        CERT_FAIL_UNKNOWN,
        "medium",
        "Unknown certificate parsing error. Check OpenSSL error logs for details",
        "Unclassified errors should be investigated. Enable debug logging and check OpenSSL error queue for specific error codes."
    }
};

#define REMEDIATION_COUNT (sizeof(CERT_REMEDIATIONS) / sizeof(CERT_REMEDIATIONS[0]))

// Get remediation suggestion for a certificate failure
const char* error_get_remediation_suggestion(cert_failure_reason_t reason) {
    for (size_t i = 0; i < REMEDIATION_COUNT; i++) {
        if (CERT_REMEDIATIONS[i].reason == reason) {
            return CERT_REMEDIATIONS[i].suggestion;
        }
    }
    return "Contact system administrator or check OpenSSL documentation";
}

// Get error impact level
const char* error_get_impact_level(cert_failure_reason_t reason) {
    for (size_t i = 0; i < REMEDIATION_COUNT; i++) {
        if (CERT_REMEDIATIONS[i].reason == reason) {
            return CERT_REMEDIATIONS[i].impact_level;
        }
    }
    return "unknown";
}

// Get detailed error explanation
const char* error_get_details(cert_failure_reason_t reason) {
    for (size_t i = 0; i < REMEDIATION_COUNT; i++) {
        if (CERT_REMEDIATIONS[i].reason == reason) {
            return CERT_REMEDIATIONS[i].details;
        }
    }
    return "No additional details available";
}

// Check if error is actionable (user can fix it)
bool error_is_actionable(cert_failure_reason_t reason) {
    switch (reason) {
        case CERT_FAIL_IO_ERROR:
        case CERT_FAIL_P12_BAD_PASSWORD:
        case CERT_FAIL_TOO_LARGE:
        case CERT_FAIL_TIMEOUT:
        case CERT_FAIL_INVALID_PEM_BLOCK:
            return true;
        default:
            return false;
    }
}

// Get error category for impact assessment
const char* error_get_category_name(cert_failure_reason_t reason) {
    // Map to user-friendly category names
    switch (reason) {
        case CERT_FAIL_IO_ERROR:
            return "File Access";
        case CERT_FAIL_MEMORY_ERROR:
            return "Parsing / Corruption";
        case CERT_FAIL_INVALID_PEM_BLOCK:
        case CERT_FAIL_DER_TRUNCATED:
        case CERT_FAIL_DER_OVERLONG:
            return "Format Validation";
        case CERT_FAIL_P12_BAD_PASSWORD:
        case CERT_FAIL_P12_UNSUPPORTED_PBE:
        case CERT_FAIL_P12_NO_MAC:
            return "PKCS#12 / Password";
        case CERT_FAIL_UNSUPPORTED_SIGALG:
        case CERT_FAIL_UNSUPPORTED_KEY_TYPE:
            return "Algorithm Support";
        case CERT_FAIL_TOO_LARGE:
        case CERT_FAIL_TOO_DEEP:
        case CERT_FAIL_SANITY_LIMIT_HIT:
            return "Resource Limits";
        case CERT_FAIL_TIMEOUT:
            return "Timeout";
        default:
            return "Unknown";
    }
}

// Extract failure reason from error message
// Message format: "Certificate parsing failed: REASON_NAME - details"
cert_failure_reason_t error_extract_failure_reason_from_message(const char* message) {
    if (!message) return CERT_FAIL_UNKNOWN;

    // Look for common patterns in certificate error messages
    if (strstr(message, "MEMORY_ERROR")) return CERT_FAIL_MEMORY_ERROR;
    if (strstr(message, "IO_ERROR")) return CERT_FAIL_IO_ERROR;
    if (strstr(message, "INVALID_PEM_BLOCK")) return CERT_FAIL_INVALID_PEM_BLOCK;
    if (strstr(message, "DER_TRUNCATED")) return CERT_FAIL_DER_TRUNCATED;
    if (strstr(message, "DER_OVERLONG")) return CERT_FAIL_DER_OVERLONG;
    if (strstr(message, "P12_BAD_PASSWORD")) return CERT_FAIL_P12_BAD_PASSWORD;
    if (strstr(message, "P12_UNSUPPORTED_PBE")) return CERT_FAIL_P12_UNSUPPORTED_PBE;
    if (strstr(message, "P12_NO_MAC")) return CERT_FAIL_P12_NO_MAC;
    if (strstr(message, "UNSUPPORTED_SIGALG")) return CERT_FAIL_UNSUPPORTED_SIGALG;
    if (strstr(message, "UNSUPPORTED_KEY_TYPE")) return CERT_FAIL_UNSUPPORTED_KEY_TYPE;
    if (strstr(message, "TOO_LARGE")) return CERT_FAIL_TOO_LARGE;
    if (strstr(message, "TOO_DEEP")) return CERT_FAIL_TOO_DEEP;
    if (strstr(message, "TIMEOUT")) return CERT_FAIL_TIMEOUT;
    if (strstr(message, "SANITY_LIMIT_HIT")) return CERT_FAIL_SANITY_LIMIT_HIT;

    return CERT_FAIL_UNKNOWN;
}

// Check if this is a certificate scanner error that should have remediation
bool error_is_certificate_scanner_error(const char* component) {
    return component && (strcmp(component, "certificate_scanner") == 0);
}
