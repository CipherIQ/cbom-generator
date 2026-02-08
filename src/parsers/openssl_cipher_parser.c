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

/**
 * @file openssl_cipher_parser.c
 * @brief OpenSSL cipher string parser
 *
 * Expands OpenSSL cipher strings (e.g., "HIGH:!aNULL") to individual cipher names.
 * Uses OpenSSL's cipher list functions to resolve cipher strings.
 *
 * Special parser: doesn't parse a file, instead expands cipher string passed in context.
 */

#define _GNU_SOURCE
#include "config_parser.h"
#ifndef __EMSCRIPTEN__
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Parse OpenSSL cipher string
 *
 * @param filepath Ignored (cipher string passed in context)
 * @param directives Output: array of cipher directives
 * @param count Output: number of ciphers
 * @param context Cipher string to expand (e.g., "HIGH:!aNULL")
 * @return 0 on success, -1 on error
 */
int openssl_cipher_parser_parse(
    const char* filepath,
    config_directive_t** directives,
    int* count,
    void* context
) {
    (void)filepath; // Not used - cipher string passed in context

    const char* cipher_string = (const char*)context;
    if (!cipher_string) {
        return -1;
    }

    // Create SSL context
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        return -1;
    }

    // Set cipher list
    if (!SSL_CTX_set_cipher_list(ctx, cipher_string)) {
        SSL_CTX_free(ctx);
        return -1;
    }

    // Create SSL object to get cipher list
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return -1;
    }

    // Get cipher stack
    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);
    if (!ciphers) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    int num_ciphers = sk_SSL_CIPHER_num(ciphers);
    if (num_ciphers == 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Allocate directive array
    config_directive_t* result = malloc(num_ciphers * sizeof(config_directive_t));
    if (!result) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Extract cipher names
    for (int i = 0; i < num_ciphers; i++) {
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);

        result[i].key = strdup("cipher");
        result[i].value = strdup(SSL_CIPHER_get_name(cipher));
        result[i].context = NULL;
        result[i].line_number = i + 1;
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    *directives = result;
    *count = num_ciphers;
    return 0;
}

/**
 * Parse cipher string from value (helper function)
 *
 * @param cipher_string OpenSSL cipher string
 * @param cipher_names Output: array of cipher names (caller must free)
 * @param count Output: number of ciphers
 * @return 0 on success, -1 on error
 */
int openssl_cipher_expand(
    const char* cipher_string,
    char*** cipher_names,
    int* count
) {
    if (!cipher_string || !cipher_names || !count) {
        return -1;
    }

    config_directive_t* directives = NULL;
    int directive_count = 0;

    if (openssl_cipher_parser_parse(NULL, &directives, &directive_count,
                                      (void*)cipher_string) < 0) {
        return -1;
    }

    // Extract cipher names
    char** names = malloc(directive_count * sizeof(char*));
    if (!names) {
        config_directives_free(directives, directive_count);
        return -1;
    }

    for (int i = 0; i < directive_count; i++) {
        names[i] = strdup(directives[i].value);
    }

    config_directives_free(directives, directive_count);

    *cipher_names = names;
    *count = directive_count;
    return 0;
}

/**
 * Free cipher names array
 */
void openssl_cipher_names_free(char** cipher_names, int count) {
    if (!cipher_names) return;

    for (int i = 0; i < count; i++) {
        free(cipher_names[i]);
    }
    free(cipher_names);
}

/**
 * Register OpenSSL cipher parser
 */
void openssl_cipher_parser_register(void) {
    config_parser_register(
        PARSER_TYPE_OPENSSL_CIPHER,
        "openssl_cipher",
        openssl_cipher_parser_parse,
        config_directives_free
    );
}
