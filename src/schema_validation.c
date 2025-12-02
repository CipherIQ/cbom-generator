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
#include "schema_validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Load schema from file
json_object* load_schema_from_file(const char *schema_path) {
    FILE *file = fopen(schema_path, "r");
    if (file == NULL) {
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(file);
        return NULL;
    }
    
    // Read file content
    char *content = malloc(file_size + 1);
    if (content == NULL) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(content, 1, file_size, file);
    content[read_size] = '\0';
    fclose(file);
    
    // Parse JSON
    json_object *schema = json_tokener_parse(content);
    free(content);
    
    return schema;
}

// Basic CycloneDX structure validation (simplified for walking skeleton)
bool validate_basic_cyclonedx_structure(json_object *bom_json) {
    if (bom_json == NULL || !json_object_is_type(bom_json, json_type_object)) {
        return false;
    }
    
    // Check required fields
    json_object *bom_format, *spec_version;
    
    if (!json_object_object_get_ex(bom_json, "bomFormat", &bom_format)) {
        return false;
    }
    
    if (!json_object_object_get_ex(bom_json, "specVersion", &spec_version)) {
        return false;
    }
    
    // Check bomFormat value
    const char *format_str = json_object_get_string(bom_format);
    if (format_str == NULL || strcmp(format_str, "CycloneDX") != 0) {
        return false;
    }
    
    // Check specVersion value (Phase D - support 1.6 and 1.7)
    const char *version_str = json_object_get_string(spec_version);
    if (version_str == NULL ||
        (strcmp(version_str, "1.6") != 0 && strcmp(version_str, "1.7") != 0)) {
        return false;
    }
    
    // Check optional but expected fields
    json_object *metadata, *components;
    
    if (json_object_object_get_ex(bom_json, "metadata", &metadata)) {
        if (!json_object_is_type(metadata, json_type_object)) {
            return false;
        }
    }
    
    if (json_object_object_get_ex(bom_json, "components", &components)) {
        if (!json_object_is_type(components, json_type_array)) {
            return false;
        }
    }
    
    return true;
}

// Validate JSON against CycloneDX schema (simplified implementation)
schema_validation_result_t validate_cyclonedx_schema(json_object *bom_json) {
    schema_validation_result_t result = {0};
    
    if (bom_json == NULL) {
        result.is_valid = false;
        result.error_message = strdup("BOM JSON is NULL");
        result.error_count = 1;
        return result;
    }
    
    // For the walking skeleton, just do basic structure validation
    if (validate_basic_cyclonedx_structure(bom_json)) {
        result.is_valid = true;
        result.error_message = NULL;
        result.error_count = 0;
    } else {
        result.is_valid = false;
        result.error_message = strdup("BOM does not conform to basic CycloneDX structure (1.6/1.7)");
        result.error_count = 1;
    }
    
    return result;
}

// Free validation result
void free_validation_result(schema_validation_result_t *result) {
    if (result == NULL) {
        return;
    }
    
    if (result->error_message) {
        free(result->error_message);
        result->error_message = NULL;
    }
    
    result->is_valid = false;
    result->error_count = 0;
}
