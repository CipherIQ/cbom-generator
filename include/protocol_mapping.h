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

#ifndef PROTOCOL_MAPPING_H
#define PROTOCOL_MAPPING_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol types
typedef enum {
    PROTOCOL_TLS,
    PROTOCOL_SSH,
    PROTOCOL_IPSEC,
    PROTOCOL_JWT,
    PROTOCOL_UNKNOWN
} protocol_type_t;

// Protocol version
typedef struct {
    protocol_type_t type;
    char* version;           // e.g., "1.3", "2", "v2"
    char** cipher_suites;    // Array of cipher suite names
    size_t cipher_suite_count;
} protocol_version_t;

// Protocol relationship chain
typedef struct {
    char* service_id;        // Service BOM-ref
    char* protocol_id;       // Protocol BOM-ref
    char* cipher_suite_id;   // Cipher suite BOM-ref
    char** algorithm_ids;    // Array of algorithm BOM-refs
    size_t algorithm_count;
} protocol_chain_t;

// Protocol mapping context
typedef struct {
    protocol_chain_t** chains;
    size_t chain_count;
    bool initialized;
} protocol_mapping_context_t;

// Protocol mapping functions
protocol_mapping_context_t* protocol_mapping_create(void);
void protocol_mapping_destroy(protocol_mapping_context_t* context);

// Add protocol chain relationship
int protocol_mapping_add_chain(protocol_mapping_context_t* context,
                                const char* service_id,
                                const char* protocol_id,
                                const char* cipher_suite_id,
                                const char** algorithm_ids,
                                size_t algorithm_count);

// TLS cipher suite parsing
char** tls_parse_cipher_suite_algorithms(const char* cipher_suite, size_t* count);

// Protocol detection helpers
protocol_type_t protocol_detect_from_config(const char* config_file);
protocol_version_t* protocol_parse_tls_config(const char* config_content);

// Utility functions
const char* protocol_type_to_string(protocol_type_t type);

#ifdef __cplusplus
}
#endif

#endif // PROTOCOL_MAPPING_H
