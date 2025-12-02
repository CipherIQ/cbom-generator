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

#include "cyclonedx_converter.h"
#include "error_handling.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <time.h>

// FROZEN v1.0 - Component type mappings (DO NOT MODIFY)
static const component_type_mapping_t COMPONENT_TYPE_MAPPINGS[] = {
    {
        .cbom_type = ASSET_TYPE_ALGORITHM,
        .cyclonedx_type = CYCLONEDX_COMPONENT_LIBRARY,
        .type_name = "library"
    },
    {
        .cbom_type = ASSET_TYPE_KEY,
        .cyclonedx_type = CYCLONEDX_COMPONENT_DATA,
        .type_name = "data"
    },
    {
        .cbom_type = ASSET_TYPE_CERTIFICATE,
        .cyclonedx_type = CYCLONEDX_COMPONENT_DATA,
        .type_name = "data"
    },
    {
        .cbom_type = ASSET_TYPE_LIBRARY,
        .cyclonedx_type = CYCLONEDX_COMPONENT_LIBRARY,
        .type_name = "library"
    },
    {
        .cbom_type = ASSET_TYPE_PROTOCOL,
        .cyclonedx_type = CYCLONEDX_COMPONENT_LIBRARY,
        .type_name = "library"
    },
    {
        .cbom_type = ASSET_TYPE_SERVICE,
        .cyclonedx_type = CYCLONEDX_COMPONENT_OPERATING_SYSTEM,
        .type_name = "operating-system"
    }
};

static const size_t COMPONENT_TYPE_MAPPING_COUNT = 
    sizeof(COMPONENT_TYPE_MAPPINGS) / sizeof(COMPONENT_TYPE_MAPPINGS[0]);

// FROZEN v1.0 - Algorithm property definitions
static const property_definition_t ALGORITHM_REQUIRED_PROPERTIES[] = {
    {"cbom:algo:primitive", "string", true, NULL},
    {"cbom:algo:key_length", "integer", true, NULL},
    {"cbom:algo:classical_strength", "integer", true, NULL},
    {"cbom:algo:pqc_status", "string", true, 
     (const char*[]){"Safe", "Transitional", "Deprecated", "Unsafe", NULL}}
};

static const property_definition_t ALGORITHM_OPTIONAL_PROPERTIES[] = {
    {"cbom:algo:mode", "string", false, NULL},
    {"cbom:algo:padding", "string", false, NULL},
    {"cbom:algo:oid", "string", false, NULL},
    {"cbom:algo:pqc_alternative", "string", false, NULL}
};

// FROZEN v1.0 - Certificate property definitions
static const property_definition_t CERTIFICATE_REQUIRED_PROPERTIES[] = {
    {"cbom:cert:subject", "string", true, NULL},
    {"cbom:cert:issuer", "string", true, NULL},
    {"cbom:cert:not_before", "string", true, NULL},
    {"cbom:cert:not_after", "string", true, NULL},
    {"cbom:cert:signature_algorithm", "string", true, NULL},
    {"cbom:cert:fingerprint_sha256", "string", true, NULL}
};

static const property_definition_t CERTIFICATE_OPTIONAL_PROPERTIES[] = {
    {"cbom:cert:public_key_algorithm", "string", false, NULL},
    {"cbom:cert:key_size", "integer", false, NULL},
    {"cbom:cert:usage", "array", false, NULL},
    {"cbom:cert:trust_status", "string", false,
     (const char*[]){"VALID", "EXPIRED", "UNTRUSTED_CA", "REVOKED", "SELF_SIGNED", NULL}},
    {"cbom:cert:is_ca", "boolean", false, NULL},
    {"cbom:cert:is_self_signed", "boolean", false, NULL}
};

// FROZEN v1.0 - Key property definitions
static const property_definition_t KEY_REQUIRED_PROPERTIES[] = {
    {"cbom:key:type", "string", true, NULL},
    {"cbom:key:size", "integer", true, NULL},
    {"cbom:key:format", "string", true, NULL}
};

static const property_definition_t KEY_OPTIONAL_PROPERTIES[] = {
    {"cbom:key:storage_security", "string", false,
     (const char*[]){"HSM", "ENCRYPTED", "PLAINTEXT", NULL}},
    {"cbom:key:is_private", "boolean", false, NULL},
    {"cbom:key:curve_name", "string", false, NULL}
};

// FROZEN v1.0 - Protocol property definitions
static const property_definition_t PROTOCOL_REQUIRED_PROPERTIES[] = {
    {"cbom:proto:name", "string", true, NULL},
    {"cbom:proto:version", "string", true, NULL}
};

static const property_definition_t PROTOCOL_OPTIONAL_PROPERTIES[] = {
    {"cbom:proto:supported_versions", "array", false, NULL},
    {"cbom:proto:enabled_versions", "array", false, NULL},
    {"cbom:proto:cipher_suites", "array", false, NULL},
    {"cbom:proto:security_profile", "string", false,
     (const char*[]){"MODERN", "INTERMEDIATE", "OLD", "CUSTOM", NULL}},
    {"cbom:proto:weak_config_flags", "array", false, NULL}
};

// FROZEN v1.0 - Library property definitions
static const property_definition_t LIBRARY_REQUIRED_PROPERTIES[] = {
    {"cbom:lib:name", "string", true, NULL},
    {"cbom:lib:version", "string", true, NULL}
};

static const property_definition_t LIBRARY_OPTIONAL_PROPERTIES[] = {
    {"cbom:lib:fips_level", "string", false, NULL},
    {"cbom:lib:implements", "array", false, NULL},
    {"cbom:lib:package_manager", "string", false, NULL}
};

// FROZEN v1.0 - Service property definitions
static const property_definition_t SERVICE_REQUIRED_PROPERTIES[] = {
    {"cbom:svc:name", "string", true, NULL},
    {"cbom:svc:daemon_name", "string", true, NULL}
};

static const property_definition_t SERVICE_OPTIONAL_PROPERTIES[] = {
    {"cbom:svc:listen_addresses", "array", false, NULL},
    {"cbom:svc:listen_ports", "array", false, NULL},
    {"cbom:svc:config_file", "string", false, NULL},
    {"cbom:svc:used_protocols", "array", false, NULL}
};

// Detection context properties (common to all types)
static const property_definition_t DETECTION_CONTEXT_PROPERTIES[] = {
    {"cbom:ctx:detection_method", "string", false, NULL},
    {"cbom:ctx:file_path", "string", false, NULL},
    {"cbom:ctx:confidence", "number", false, NULL},
    {"cbom:ctx:scanner_name", "string", false, NULL},
    {"cbom:ctx:detection_time", "string", false, NULL}
};

// Get property definitions for asset type
static const property_definition_t* get_required_properties(asset_type_t type, size_t* count) {
    switch (type) {
        case ASSET_TYPE_ALGORITHM:
            *count = sizeof(ALGORITHM_REQUIRED_PROPERTIES) / sizeof(ALGORITHM_REQUIRED_PROPERTIES[0]);
            return ALGORITHM_REQUIRED_PROPERTIES;
        case ASSET_TYPE_CERTIFICATE:
            *count = sizeof(CERTIFICATE_REQUIRED_PROPERTIES) / sizeof(CERTIFICATE_REQUIRED_PROPERTIES[0]);
            return CERTIFICATE_REQUIRED_PROPERTIES;
        case ASSET_TYPE_KEY:
            *count = sizeof(KEY_REQUIRED_PROPERTIES) / sizeof(KEY_REQUIRED_PROPERTIES[0]);
            return KEY_REQUIRED_PROPERTIES;
        case ASSET_TYPE_PROTOCOL:
            *count = sizeof(PROTOCOL_REQUIRED_PROPERTIES) / sizeof(PROTOCOL_REQUIRED_PROPERTIES[0]);
            return PROTOCOL_REQUIRED_PROPERTIES;
        case ASSET_TYPE_LIBRARY:
            *count = sizeof(LIBRARY_REQUIRED_PROPERTIES) / sizeof(LIBRARY_REQUIRED_PROPERTIES[0]);
            return LIBRARY_REQUIRED_PROPERTIES;
        case ASSET_TYPE_SERVICE:
            *count = sizeof(SERVICE_REQUIRED_PROPERTIES) / sizeof(SERVICE_REQUIRED_PROPERTIES[0]);
            return SERVICE_REQUIRED_PROPERTIES;
        default:
            *count = 0;
            return NULL;
    }
}

static const property_definition_t* get_optional_properties(asset_type_t type, size_t* count) {
    switch (type) {
        case ASSET_TYPE_ALGORITHM:
            *count = sizeof(ALGORITHM_OPTIONAL_PROPERTIES) / sizeof(ALGORITHM_OPTIONAL_PROPERTIES[0]);
            return ALGORITHM_OPTIONAL_PROPERTIES;
        case ASSET_TYPE_CERTIFICATE:
            *count = sizeof(CERTIFICATE_OPTIONAL_PROPERTIES) / sizeof(CERTIFICATE_OPTIONAL_PROPERTIES[0]);
            return CERTIFICATE_OPTIONAL_PROPERTIES;
        case ASSET_TYPE_KEY:
            *count = sizeof(KEY_OPTIONAL_PROPERTIES) / sizeof(KEY_OPTIONAL_PROPERTIES[0]);
            return KEY_OPTIONAL_PROPERTIES;
        case ASSET_TYPE_PROTOCOL:
            *count = sizeof(PROTOCOL_OPTIONAL_PROPERTIES) / sizeof(PROTOCOL_OPTIONAL_PROPERTIES[0]);
            return PROTOCOL_OPTIONAL_PROPERTIES;
        case ASSET_TYPE_LIBRARY:
            *count = sizeof(LIBRARY_OPTIONAL_PROPERTIES) / sizeof(LIBRARY_OPTIONAL_PROPERTIES[0]);
            return LIBRARY_OPTIONAL_PROPERTIES;
        case ASSET_TYPE_SERVICE:
            *count = sizeof(SERVICE_OPTIONAL_PROPERTIES) / sizeof(SERVICE_OPTIONAL_PROPERTIES[0]);
            return SERVICE_OPTIONAL_PROPERTIES;
        default:
            *count = 0;
            return NULL;
    }
}

cyclonedx_converter_t* cyclonedx_converter_create(bool strict_validation) {
    cyclonedx_converter_t* converter = secure_alloc(sizeof(cyclonedx_converter_t));
    if (!converter) {
        return NULL;
    }
    
    converter->strict_validation = strict_validation;
    converter->schema_validation = true;
    converter->schema_path = NULL;
    converter->validation_errors = 0;
    converter->error_messages = NULL;
    
    return converter;
}

void cyclonedx_converter_destroy(cyclonedx_converter_t* converter) {
    if (!converter) return;
    
    if (converter->schema_path) {
        secure_free(converter->schema_path, strlen(converter->schema_path));
    }
    
    if (converter->error_messages) {
        for (size_t i = 0; i < converter->validation_errors; i++) {
            if (converter->error_messages[i]) {
                secure_free(converter->error_messages[i], strlen(converter->error_messages[i]));
            }
        }
        secure_free(converter->error_messages, converter->validation_errors * sizeof(char*));
    }
    
    secure_free(converter, sizeof(cyclonedx_converter_t));
}

bool is_valid_component_type(asset_type_t cbom_type) {
    for (size_t i = 0; i < COMPONENT_TYPE_MAPPING_COUNT; i++) {
        if (COMPONENT_TYPE_MAPPINGS[i].cbom_type == cbom_type) {
            return true;
        }
    }
    return false;
}

cyclonedx_component_type_t map_to_cyclonedx_type(asset_type_t cbom_type) {
    for (size_t i = 0; i < COMPONENT_TYPE_MAPPING_COUNT; i++) {
        if (COMPONENT_TYPE_MAPPINGS[i].cbom_type == cbom_type) {
            return COMPONENT_TYPE_MAPPINGS[i].cyclonedx_type;
        }
    }
    // This should never happen if is_valid_component_type() is checked first
    return CYCLONEDX_COMPONENT_LIBRARY; // Default fallback
}

const char* get_cyclonedx_type_name(cyclonedx_component_type_t type) {
    for (size_t i = 0; i < COMPONENT_TYPE_MAPPING_COUNT; i++) {
        if (COMPONENT_TYPE_MAPPINGS[i].cyclonedx_type == type) {
            return COMPONENT_TYPE_MAPPINGS[i].type_name;
        }
    }
    return "library"; // Default fallback
}

bool is_valid_cbom_property(const char* property_name) {
    if (!property_name) return false;
    return strncmp(property_name, "cbom:", 5) == 0;
}

bool has_cbom_namespace(const char* property_name) {
    return is_valid_cbom_property(property_name);
}

static bool is_valid_property_value(const char* value, const char* expected_type, 
                                   const char** allowed_values) {
    if (!value || !expected_type) return false;
    
    // Check allowed values if specified
    if (allowed_values) {
        for (size_t i = 0; allowed_values[i] != NULL; i++) {
            if (strcmp(value, allowed_values[i]) == 0) {
                return true;
            }
        }
        return false; // Value not in allowed list
    }
    
    // Basic type validation (simplified for this implementation)
    if (strcmp(expected_type, "string") == 0) {
        return true; // Any string is valid
    } else if (strcmp(expected_type, "integer") == 0) {
        char* endptr;
        strtol(value, &endptr, 10);
        return *endptr == '\0'; // Valid if entire string was consumed
    } else if (strcmp(expected_type, "boolean") == 0) {
        return strcmp(value, "true") == 0 || strcmp(value, "false") == 0;
    } else if (strcmp(expected_type, "number") == 0) {
        char* endptr;
        strtod(value, &endptr);
        return *endptr == '\0'; // Valid if entire string was consumed
    } else if (strcmp(expected_type, "array") == 0) {
        // For arrays, we expect JSON array format - simplified check
        return value[0] == '[' && value[strlen(value) - 1] == ']';
    }
    
    return false;
}

property_validation_result_t validate_property(const char* property_name,
                                              const char* property_value,
                                              asset_type_t asset_type) {
    if (!property_name || !property_value) {
        return PROPERTY_INVALID_TYPE;
    }
    
    // Check namespace
    if (!is_valid_cbom_property(property_name)) {
        return PROPERTY_INVALID_NAMESPACE;
    }
    
    // Get property definitions for this asset type
    size_t required_count, optional_count;
    const property_definition_t* required_props = get_required_properties(asset_type, &required_count);
    const property_definition_t* optional_props = get_optional_properties(asset_type, &optional_count);
    
    // Check required properties
    for (size_t i = 0; i < required_count; i++) {
        if (strcmp(property_name, required_props[i].name) == 0) {
            if (is_valid_property_value(property_value, required_props[i].expected_type,
                                       required_props[i].allowed_values)) {
                return PROPERTY_VALID;
            } else {
                return PROPERTY_INVALID_VALUE;
            }
        }
    }
    
    // Check optional properties
    for (size_t i = 0; i < optional_count; i++) {
        if (strcmp(property_name, optional_props[i].name) == 0) {
            if (is_valid_property_value(property_value, optional_props[i].expected_type,
                                       optional_props[i].allowed_values)) {
                return PROPERTY_VALID;
            } else {
                return PROPERTY_INVALID_VALUE;
            }
        }
    }
    
    // Check detection context properties (common to all types)
    size_t ctx_count = sizeof(DETECTION_CONTEXT_PROPERTIES) / sizeof(DETECTION_CONTEXT_PROPERTIES[0]);
    for (size_t i = 0; i < ctx_count; i++) {
        if (strcmp(property_name, DETECTION_CONTEXT_PROPERTIES[i].name) == 0) {
            if (is_valid_property_value(property_value, DETECTION_CONTEXT_PROPERTIES[i].expected_type,
                                       DETECTION_CONTEXT_PROPERTIES[i].allowed_values)) {
                return PROPERTY_VALID;
            } else {
                return PROPERTY_INVALID_VALUE;
            }
        }
    }
    
    // Property not found in definitions - this is a warning, not an error
    return PROPERTY_VALID; // Allow unknown properties for forward compatibility
}

property_validation_result_t validate_component_properties(const crypto_asset_t* asset,
                                                          char*** missing_properties,
                                                          size_t* missing_count) {
    if (!asset || !missing_properties || !missing_count) {
        return PROPERTY_INVALID_TYPE;
    }
    
    *missing_properties = NULL;
    *missing_count = 0;
    
    // Validate component type
    if (!is_valid_component_type(asset->type)) {
        return PROPERTY_UNKNOWN_COMPONENT_TYPE;
    }
    
    // Get required properties for this asset type
    size_t required_count;
    const property_definition_t* required_props = get_required_properties(asset->type, &required_count);
    
    if (!required_props || required_count == 0) {
        return PROPERTY_VALID; // No required properties
    }
    
    // Check which required properties are missing
    char** missing = secure_alloc(required_count * sizeof(char*));
    if (!missing) {
        return PROPERTY_INVALID_TYPE;
    }
    
    size_t missing_idx = 0;
    
    for (size_t i = 0; i < required_count; i++) {
        bool found = false;
        
        // This is a simplified check - in a real implementation,
        // we would check the asset's metadata/properties structure
        // For now, we assume all required properties are present
        // TODO: Implement actual property checking against asset metadata
        found = true;
        
        if (!found) {
            missing[missing_idx] = secure_alloc(strlen(required_props[i].name) + 1);
            if (missing[missing_idx]) {
                strcpy(missing[missing_idx], required_props[i].name);
                missing_idx++;
            }
        }
    }
    
    if (missing_idx > 0) {
        *missing_properties = missing;
        *missing_count = missing_idx;
        return PROPERTY_MISSING_REQUIRED;
    } else {
        secure_free(missing, required_count * sizeof(char*));
        return PROPERTY_VALID;
    }
}

char* convert_asset_to_cyclonedx_component(const crypto_asset_t* asset,
                                          cyclonedx_converter_t* converter) {
    if (!asset || !converter) {
        return NULL;
    }
    
    // Validate component type
    if (!is_valid_component_type(asset->type)) {
        // Add error message
        converter->validation_errors++;
        return NULL;
    }
    
    json_object* component = json_object_new_object();
    if (!component) {
        return NULL;
    }
    
    // Add required CycloneDX fields
    json_object* type_obj = json_object_new_string(get_cyclonedx_type_name(map_to_cyclonedx_type(asset->type)));
    json_object* name_obj = json_object_new_string(asset->name ? asset->name : "unknown");
    json_object* bom_ref_obj = json_object_new_string(asset->id ? asset->id : "unknown");
    
    json_object_object_add(component, "type", type_obj);
    json_object_object_add(component, "name", name_obj);
    json_object_object_add(component, "bom-ref", bom_ref_obj);
    
    // Add properties array (simplified - would extract from asset metadata)
    json_object* properties = json_object_new_array();
    json_object_object_add(component, "properties", properties);
    
    // Convert to string
    const char* json_string = json_object_to_json_string(component);
    char* result = NULL;
    if (json_string) {
        size_t len = strlen(json_string);
        result = secure_alloc(len + 1);
        if (result) {
            strcpy(result, json_string);
        }
    }
    
    json_object_put(component);
    return result;
}

char* convert_cbom_to_cyclonedx(const crypto_asset_t** assets, size_t asset_count,
                               const relationship_t** relationships, size_t relationship_count,
                               cyclonedx_converter_t* converter) {
    if (!assets || !converter) {
        return NULL;
    }
    
    // Suppress unused parameter warnings for now - relationships will be implemented later
    (void)relationships;
    (void)relationship_count;
    
    json_object* bom = json_object_new_object();
    if (!bom) {
        return NULL;
    }
    
    // Add CycloneDX metadata
    json_object* bom_format = json_object_new_string("CycloneDX");
    json_object* spec_version = json_object_new_string("1.6");
    json_object* version = json_object_new_int(1);
    
    json_object_object_add(bom, "bomFormat", bom_format);
    json_object_object_add(bom, "specVersion", spec_version);
    json_object_object_add(bom, "version", version);
    
    // Add metadata block
    json_object* metadata = json_object_new_object();
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    json_object* timestamp_obj = json_object_new_string(timestamp);
    json_object_object_add(metadata, "timestamp", timestamp_obj);
    json_object_object_add(bom, "metadata", metadata);
    
    // Add components
    json_object* components = json_object_new_array();
    for (size_t i = 0; i < asset_count; i++) {
        char* component_json = convert_asset_to_cyclonedx_component(assets[i], converter);
        if (component_json) {
            json_object* component = json_tokener_parse(component_json);
            if (component) {
                json_object_array_add(components, component);
            }
            secure_free(component_json, strlen(component_json));
        }
    }
    json_object_object_add(bom, "components", components);
    
    // Convert to string
    const char* json_string = json_object_to_json_string_ext(bom, JSON_C_TO_STRING_PRETTY);
    char* result = NULL;
    if (json_string) {
        size_t len = strlen(json_string);
        result = secure_alloc(len + 1);
        if (result) {
            strcpy(result, json_string);
        }
    }
    
    json_object_put(bom);
    return result;
}

// Testing functions
bool run_property_drift_tests(void) {
    // Test that component type mappings haven't changed
    if (COMPONENT_TYPE_MAPPING_COUNT != 6) {
        printf("ERROR: Property drift detected: Component type mapping count changed\n");
        return false;
    }
    
    // Test specific mappings
    if (map_to_cyclonedx_type(ASSET_TYPE_ALGORITHM) != CYCLONEDX_COMPONENT_LIBRARY) {
        printf("ERROR: Property drift detected: Algorithm mapping changed\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_CERTIFICATE) != CYCLONEDX_COMPONENT_DATA) {
        printf("ERROR: Property drift detected: Certificate mapping changed\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_SERVICE) != CYCLONEDX_COMPONENT_OPERATING_SYSTEM) {
        printf("ERROR: Property drift detected: Service mapping changed\n");
        return false;
    }
    
    printf("INFO: Property drift tests passed - mappings are stable\n");
    return true;
}

bool run_component_type_validation_tests(void) {
    // Test valid component types
    if (!is_valid_component_type(ASSET_TYPE_ALGORITHM)) {
        printf("ERROR: Component type validation failed: Algorithm should be valid\n");
        return false;
    }
    
    if (!is_valid_component_type(ASSET_TYPE_CERTIFICATE)) {
        printf("ERROR: Component type validation failed: Certificate should be valid\n");
        return false;
    }
    
    // Test invalid component type (using a value outside the enum range)
    if (is_valid_component_type((asset_type_t)999)) {
        printf("ERROR: Component type validation failed: Invalid type should be rejected\n");
        return false;
    }
    
    printf("INFO: Component type validation tests passed\n");
    return true;
}

bool validate_against_cyclonedx_schema(const char* json_content, const char* schema_path,
                                      char** validation_errors) {
    // Suppress unused parameter warning - schema_path will be used when full validation is implemented
    (void)schema_path;
    
    // Placeholder implementation - would use a JSON schema validator
    // For now, just basic JSON validation
    if (!json_content) {
        if (validation_errors) {
            *validation_errors = secure_alloc(32);
            if (*validation_errors) {
                strcpy(*validation_errors, "JSON content is NULL");
            }
        }
        return false;
    }
    
    json_object* obj = json_tokener_parse(json_content);
    if (!obj) {
        if (validation_errors) {
            *validation_errors = secure_alloc(64);
            if (*validation_errors) {
                strcpy(*validation_errors, "Invalid JSON format");
            }
        }
        return false;
    }
    
    json_object_put(obj);
    return true;
}

const char** get_validation_errors(cyclonedx_converter_t* converter, size_t* count) {
    if (!converter || !count) {
        return NULL;
    }
    
    *count = converter->validation_errors;
    return (const char**)converter->error_messages;
}

void clear_validation_errors(cyclonedx_converter_t* converter) {
    if (!converter) return;
    
    if (converter->error_messages) {
        for (size_t i = 0; i < converter->validation_errors; i++) {
            if (converter->error_messages[i]) {
                secure_free(converter->error_messages[i], strlen(converter->error_messages[i]));
            }
        }
        secure_free(converter->error_messages, converter->validation_errors * sizeof(char*));
        converter->error_messages = NULL;
    }
    
    converter->validation_errors = 0;
}
