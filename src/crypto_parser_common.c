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
#include <stddef.h>

/**
 * Crypto parser global state management.
 *
 * Stores the active backend ops pointer. Initialized once at startup
 * via crypto_parser_init() — OpenSSL backend for native, stub for WASM.
 */

static const crypto_parser_ops_t* g_crypto_ops = NULL;

int crypto_parser_init(const crypto_parser_ops_t* ops) {
    if (ops == NULL) {
        return -1;
    }
    g_crypto_ops = ops;
    return 0;
}

const crypto_parser_ops_t* crypto_parser_get_ops(void) {
    return g_crypto_ops;
}

bool crypto_parser_is_available(void) {
    return g_crypto_ops != NULL && g_crypto_ops->parse_certificate != NULL;
}

void crypto_parser_shutdown(void) {
    g_crypto_ops = NULL;
}
