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

#ifndef SCHEMA_VALIDATION_H
#define SCHEMA_VALIDATION_H

#include <stdbool.h>
#include <json-c/json.h>

// Schema validation result
typedef struct {
    bool is_valid;
    char *error_message;
    int error_count;
} schema_validation_result_t;

// Validate JSON against CycloneDX schema
schema_validation_result_t validate_cyclonedx_schema(json_object *bom_json);

// Load schema from file
json_object* load_schema_from_file(const char *schema_path);

// Free validation result
void free_validation_result(schema_validation_result_t *result);

// Basic JSON structure validation (simplified for walking skeleton)
bool validate_basic_cyclonedx_structure(json_object *bom_json);

#endif // SCHEMA_VALIDATION_H
