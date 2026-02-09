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

#ifndef CRYPTO_PARSER_INTERFACE_H
#define CRYPTO_PARSER_INTERFACE_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/**
 * Crypto Parser Abstraction Layer
 *
 * Provides a backend-agnostic interface for certificate and key parsing.
 * Native builds use the OpenSSL backend; WASM builds use a stub (Phase 1)
 * or JavaScript bridge via pkijs (Phase 2).
 *
 * No OpenSSL headers are included here — backends handle that internally.
 */

/* Parsed certificate (lightweight subset — not the scanner's full cert_metadata_t) */
typedef struct {
    char* subject;
    char* issuer;
    time_t not_before;
    time_t not_after;
    char* serial_number;
    char* signature_algorithm;
    char* public_key_algorithm;
    int   public_key_size;
    char* fingerprint_sha256;
    bool  is_ca;
    char* extended_json;      /* JSON blob: SANs, extensions, AIA, policies */
    void* native_handle;      /* Opaque: X509* (OpenSSL), NULL (stub/WASM) */
} crypto_parsed_cert_t;

/* Parsed key (lightweight subset) */
typedef struct {
    char* algorithm;
    int   key_size;
    char* curve_name;
    bool  is_private;
    bool  is_encrypted;
    char* fingerprint;
    void* native_handle;      /* Opaque: EVP_PKEY* (OpenSSL), NULL (stub/WASM) */
} crypto_parsed_key_t;

/* Backend function pointer table */
typedef struct {
    const char* backend_name;

    /**
     * Parse a single certificate from raw data.
     * Returns 0 on success, -1 on failure.
     * On success, caller must call free_cert() when done.
     */
    int  (*parse_certificate)(const unsigned char* data, size_t len,
                              const char* path, crypto_parsed_cert_t* out);

    /**
     * Parse a single key from raw data.
     * Returns 0 on success, -1 on failure.
     * On success, caller must call free_key() when done.
     */
    int  (*parse_key)(const unsigned char* data, size_t len,
                      const char* path, const char* password,
                      crypto_parsed_key_t* out);

    /**
     * Parse a certificate bundle (multi-cert PEM, PKCS#12).
     * Fires callback for each certificate found.
     * Returns number of certificates parsed, or -1 on error.
     */
    int  (*parse_certificate_bundle)(const unsigned char* data, size_t len,
                                     const char* path,
                                     void (*callback)(const crypto_parsed_cert_t* cert,
                                                      void* user_data),
                                     void* user_data);

    void (*free_cert)(crypto_parsed_cert_t* cert);
    void (*free_key)(crypto_parsed_key_t* key);
} crypto_parser_ops_t;

/* Global backend management */
int  crypto_parser_init(const crypto_parser_ops_t* ops);
const crypto_parser_ops_t* crypto_parser_get_ops(void);
bool crypto_parser_is_available(void);
void crypto_parser_shutdown(void);

/* Backend accessors */
const crypto_parser_ops_t* crypto_parser_openssl_ops(void);
const crypto_parser_ops_t* crypto_parser_stub_ops(void);
const crypto_parser_ops_t* crypto_parser_jsbridge_ops(void);

/* JS bridge lifecycle (WASM only — reads pre-parsed cert metadata from JSON) */
int  jsbridge_parser_init(const char* json_path);
void jsbridge_parser_shutdown(void);

/* JS bridge key iteration (WASM only — iterates pre-parsed key metadata) */
int  jsbridge_iterate_keys(void (*callback)(const char* path, void* user_data),
                           void* user_data);

#endif /* CRYPTO_PARSER_INTERFACE_H */
