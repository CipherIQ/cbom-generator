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

#ifndef CYCLONEDX_CONVERTER_H
#define CYCLONEDX_CONVERTER_H

#include <stdbool.h>
#include <stddef.h>
#include "cbom_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// CycloneDX component types (FROZEN v1.0)
typedef enum {
    CYCLONEDX_COMPONENT_LIBRARY,        // For algorithms, protocols, libraries
    CYCLONEDX_COMPONENT_DATA,           // For keys, certificates
    CYCLONEDX_COMPONENT_OPERATING_SYSTEM // For services, host components
} cyclonedx_component_type_t;

// Property validation result
typedef enum {
    PROPERTY_VALID,
    PROPERTY_INVALID_NAMESPACE,
    PROPERTY_INVALID_TYPE,
    PROPERTY_INVALID_VALUE,
    PROPERTY_MISSING_REQUIRED,
    PROPERTY_UNKNOWN_COMPONENT_TYPE
} property_validation_result_t;

// Property definition for validation
typedef struct {
    const char* name;           // Property name (including cbom: prefix)
    const char* expected_type;  // "string", "integer", "boolean", "array"
    bool required;              // Is this property required?
    const char** allowed_values; // NULL for any value, or array of allowed values
} property_definition_t;

// Component type mapping
typedef struct {
    asset_type_t cbom_type;
    cyclonedx_component_type_t cyclonedx_type;
    const char* type_name;
    const property_definition_t* required_properties;
    size_t required_property_count;
    const property_definition_t* optional_properties;
    size_t optional_property_count;
} component_type_mapping_t;

// CycloneDX converter context
typedef struct {
    bool strict_validation;     // Reject unknown properties vs warn
    bool schema_validation;     // Validate against CycloneDX schema
    char* schema_path;          // Path to CycloneDX schema file
    size_t validation_errors;   // Count of validation errors
    char** error_messages;      // Array of error messages
} cyclonedx_converter_t;

// Core conversion functions
cyclonedx_converter_t* cyclonedx_converter_create(bool strict_validation);
void cyclonedx_converter_destroy(cyclonedx_converter_t* converter);

// Component type validation
bool is_valid_component_type(asset_type_t cbom_type);
cyclonedx_component_type_t map_to_cyclonedx_type(asset_type_t cbom_type);
const char* get_cyclonedx_type_name(cyclonedx_component_type_t type);

// Property validation
property_validation_result_t validate_property(
    const char* property_name,
    const char* property_value,
    asset_type_t asset_type
);

property_validation_result_t validate_component_properties(
    const crypto_asset_t* asset,
    char*** missing_properties,
    size_t* missing_count
);

// Namespace validation
bool is_valid_cbom_property(const char* property_name);
bool has_cbom_namespace(const char* property_name);

// Property extraction for CycloneDX format
char** extract_cyclonedx_properties(const crypto_asset_t* asset, size_t* count);
char* format_property_for_cyclonedx(const char* name, const char* value);

// JSON conversion
char* convert_asset_to_cyclonedx_component(
    const crypto_asset_t* asset,
    cyclonedx_converter_t* converter
);

char* convert_cbom_to_cyclonedx(
    const crypto_asset_t** assets,
    size_t asset_count,
    const relationship_t** relationships,
    size_t relationship_count,
    cyclonedx_converter_t* converter
);

// Schema validation
bool validate_against_cyclonedx_schema(
    const char* json_content,
    const char* schema_path,
    char** validation_errors
);

// Error handling
const char** get_validation_errors(cyclonedx_converter_t* converter, size_t* count);
void clear_validation_errors(cyclonedx_converter_t* converter);

// Testing support
bool run_property_drift_tests(void);
bool run_component_type_validation_tests(void);

#ifdef __cplusplus
}
#endif

#endif // CYCLONEDX_CONVERTER_H
