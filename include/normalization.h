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

#ifndef NORMALIZATION_H
#define NORMALIZATION_H

#include "cbom_types.h"
#include <json-c/json.h>

// Normalization specification version
#define NORMALIZATION_SPEC_VERSION "1.0"

// Asset-specific normalization functions
json_object* normalize_algorithm_asset(const crypto_asset_t *asset);
json_object* normalize_certificate_asset(const crypto_asset_t *asset);
json_object* normalize_key_asset(const crypto_asset_t *asset);
json_object* normalize_library_asset(const crypto_asset_t *asset);
json_object* normalize_protocol_asset(const crypto_asset_t *asset);
json_object* normalize_service_asset(const crypto_asset_t *asset);

// Generic normalization dispatcher
json_object* normalize_asset(const crypto_asset_t *asset);

// Content-addressed ID generation
char* generate_content_addressed_id(json_object *normalized_json);

// JSON serialization with deterministic ordering
char* serialize_json_deterministic(json_object *json_obj);

// Utility functions for normalization
char* normalize_algorithm_name(const char *name);
char* normalize_dn_string(const char *dn);
char* normalize_version_string(const char *version);
char* normalize_hex_string(const char *hex);

// Test vector validation
typedef struct {
    const char *description;
    asset_type_t type;
    const char *input_json;
    const char *expected_normalized_json;
    const char *expected_id;
} normalization_test_vector_t;

// Validate implementation against test vectors
int validate_normalization_test_vectors(void);
const normalization_test_vector_t* get_test_vectors(size_t *count);

#endif // NORMALIZATION_H
