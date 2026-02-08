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

#include "crypto_parser_interface.h"

/**
 * Stub crypto parser backend for WASM builds.
 *
 * All parse operations return -1 (not available).
 * Phase 2 will replace this with a JavaScript bridge to pkijs.
 */

static int stub_parse_certificate(const unsigned char* data, size_t len,
                                  const char* path, crypto_parsed_cert_t* out) {
    (void)data; (void)len; (void)path; (void)out;
    return -1;
}

static int stub_parse_key(const unsigned char* data, size_t len,
                          const char* path, const char* password,
                          crypto_parsed_key_t* out) {
    (void)data; (void)len; (void)path; (void)password; (void)out;
    return -1;
}

static int stub_parse_certificate_bundle(const unsigned char* data, size_t len,
                                         const char* path,
                                         void (*callback)(const crypto_parsed_cert_t*, void*),
                                         void* user_data) {
    (void)data; (void)len; (void)path; (void)callback; (void)user_data;
    return -1;
}

static void stub_free_cert(crypto_parsed_cert_t* cert) {
    (void)cert;
}

static void stub_free_key(crypto_parsed_key_t* key) {
    (void)key;
}

static const crypto_parser_ops_t stub_ops = {
    .backend_name = "stub",
    .parse_certificate = stub_parse_certificate,
    .parse_key = stub_parse_key,
    .parse_certificate_bundle = stub_parse_certificate_bundle,
    .free_cert = stub_free_cert,
    .free_key = stub_free_key,
};

const crypto_parser_ops_t* crypto_parser_stub_ops(void) {
    return &stub_ops;
}
