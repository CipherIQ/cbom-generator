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

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <json-c/json.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Signature methods
typedef enum {
    SIGNATURE_METHOD_DSSE,   // Dead Simple Signing Envelope
    SIGNATURE_METHOD_PGP     // PGP/GPG signature
} signature_method_t;

// Attestation configuration
typedef struct {
    signature_method_t method;  // Signature method
    char* signing_key_path;     // Path to private key file
    char* key_password;         // Password for encrypted keys (optional)
    bool include_slsa;          // Include SLSA provenance
} attestation_config_t;

// DSSE signature
typedef struct {
    char* keyid;                // Key identifier (fingerprint)
    char* sig;                  // Base64-encoded signature
} dsse_signature_t;

// DSSE envelope
typedef struct {
    char* payload;              // Base64-encoded payload
    char* payloadType;          // Payload type (e.g., "application/vnd.cyclonedx+json")
    dsse_signature_t** signatures;  // Array of signatures
    size_t signature_count;     // Number of signatures
} dsse_envelope_t;

// Attestation context
typedef struct {
    attestation_config_t config;
    void* signing_key;          // EVP_PKEY* (OpenSSL key)
    char* key_fingerprint;      // Key fingerprint/identifier
    bool initialized;
} attestation_context_t;

// Attestation functions
attestation_context_t* attestation_create(const attestation_config_t* config);
void attestation_destroy(attestation_context_t* context);

// DSSE envelope creation and signing
dsse_envelope_t* dsse_create_envelope(const char* payload, const char* payload_type);
int dsse_add_signature(dsse_envelope_t* envelope,
                       attestation_context_t* context,
                       const char* payload);
void dsse_envelope_destroy(dsse_envelope_t* envelope);

// Sign CBOM file
int attestation_sign_cbom_file(attestation_context_t* context,
                               const char* cbom_file_path,
                               const char* output_path);

// Sign CBOM JSON object
json_object* attestation_sign_cbom_json(attestation_context_t* context,
                                        json_object* cbom);

// Convert DSSE envelope to JSON
json_object* dsse_envelope_to_json(const dsse_envelope_t* envelope);

// Write DSSE envelope to file
int dsse_write_to_file(const dsse_envelope_t* envelope, const char* output_path);

// Utility functions
char* attestation_compute_sha256(const unsigned char* data, size_t len);
char* attestation_base64_encode(const unsigned char* data, size_t len);
unsigned char* attestation_base64_decode(const char* encoded, size_t* out_len);

// Key loading
int attestation_load_private_key(attestation_context_t* context);
char* attestation_get_key_fingerprint(attestation_context_t* context);

// Signature generation
int attestation_sign_data(attestation_context_t* context,
                          const unsigned char* data,
                          size_t data_len,
                          unsigned char** signature,
                          size_t* signature_len);

// Default configuration
attestation_config_t attestation_get_default_config(void);

#ifdef __cplusplus
}
#endif

#endif // ATTESTATION_H
