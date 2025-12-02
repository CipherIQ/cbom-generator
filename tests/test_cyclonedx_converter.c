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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "cyclonedx_converter.h"
#include "cbom_types.h"
#include "error_handling.h"
#include "secure_memory.h"

// Test data structures
static crypto_asset_t* create_test_algorithm(void) {
    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) return NULL;
    
    memset(asset, 0, sizeof(crypto_asset_t));
    asset->id = strdup("algo-aes-256-gcm-001");
    asset->type = ASSET_TYPE_ALGORITHM;
    asset->name = strdup("AES-256-GCM");
    asset->algorithm = strdup("AES-256-GCM");
    asset->key_size = 256;
    asset->is_weak = false;
    asset->is_pqc_ready = false;
    asset->metadata_json = NULL; // Simplified for testing
    
    return asset;
}

static crypto_asset_t* create_test_certificate(void) {
    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) return NULL;
    
    memset(asset, 0, sizeof(crypto_asset_t));
    asset->id = strdup("cert-example-com-001");
    asset->type = ASSET_TYPE_CERTIFICATE;
    asset->name = strdup("example.com Certificate");
    asset->location = strdup("/etc/ssl/certs/example.pem");
    asset->algorithm = strdup("RSA-2048");
    asset->key_size = 2048;
    asset->is_weak = false;
    asset->is_pqc_ready = false;
    asset->metadata_json = NULL; // Simplified for testing
    
    return asset;
}

static crypto_asset_t* create_test_service(void) {
    crypto_asset_t* asset = malloc(sizeof(crypto_asset_t));
    if (!asset) return NULL;
    
    memset(asset, 0, sizeof(crypto_asset_t));
    asset->id = strdup("svc-apache-httpd-001");
    asset->type = ASSET_TYPE_SERVICE;
    asset->name = strdup("Apache HTTPD");
    asset->version = strdup("2.4.41");
    asset->location = strdup("/usr/sbin/httpd");
    asset->is_weak = false;
    asset->is_pqc_ready = false;
    asset->metadata_json = NULL; // Simplified for testing
    
    return asset;
}

static void free_test_asset(crypto_asset_t* asset) {
    if (!asset) return;
    
    free(asset->id);
    free(asset->name);
    free(asset->version);
    free(asset->location);
    free(asset->algorithm);
    free(asset->hash_algorithm);
    free(asset->metadata_json);
    free(asset);
}

// Test component type mapping (FROZEN v1.0)
static bool test_component_type_mapping(void) {
    printf("Testing component type mapping...\n");
    
    // Test algorithm -> library mapping
    if (!is_valid_component_type(ASSET_TYPE_ALGORITHM)) {
        printf("FAIL: Algorithm should be valid component type\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_ALGORITHM) != CYCLONEDX_COMPONENT_LIBRARY) {
        printf("FAIL: Algorithm should map to library component type\n");
        return false;
    }
    
    if (strcmp(get_cyclonedx_type_name(CYCLONEDX_COMPONENT_LIBRARY), "library") != 0) {
        printf("FAIL: Library component type name should be 'library'\n");
        return false;
    }
    
    // Test certificate -> data mapping
    if (!is_valid_component_type(ASSET_TYPE_CERTIFICATE)) {
        printf("FAIL: Certificate should be valid component type\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_CERTIFICATE) != CYCLONEDX_COMPONENT_DATA) {
        printf("FAIL: Certificate should map to data component type\n");
        return false;
    }
    
    if (strcmp(get_cyclonedx_type_name(CYCLONEDX_COMPONENT_DATA), "data") != 0) {
        printf("FAIL: Data component type name should be 'data'\n");
        return false;
    }
    
    // Test key -> data mapping
    if (!is_valid_component_type(ASSET_TYPE_KEY)) {
        printf("FAIL: Key should be valid component type\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_KEY) != CYCLONEDX_COMPONENT_DATA) {
        printf("FAIL: Key should map to data component type\n");
        return false;
    }
    
    // Test library -> library mapping
    if (!is_valid_component_type(ASSET_TYPE_LIBRARY)) {
        printf("FAIL: Library should be valid component type\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_LIBRARY) != CYCLONEDX_COMPONENT_LIBRARY) {
        printf("FAIL: Library should map to library component type\n");
        return false;
    }
    
    // Test protocol -> library mapping
    if (!is_valid_component_type(ASSET_TYPE_PROTOCOL)) {
        printf("FAIL: Protocol should be valid component type\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_PROTOCOL) != CYCLONEDX_COMPONENT_LIBRARY) {
        printf("FAIL: Protocol should map to library component type\n");
        return false;
    }
    
    // Test service -> operating-system mapping
    if (!is_valid_component_type(ASSET_TYPE_SERVICE)) {
        printf("FAIL: Service should be valid component type\n");
        return false;
    }
    
    if (map_to_cyclonedx_type(ASSET_TYPE_SERVICE) != CYCLONEDX_COMPONENT_OPERATING_SYSTEM) {
        printf("FAIL: Service should map to operating-system component type\n");
        return false;
    }
    
    if (strcmp(get_cyclonedx_type_name(CYCLONEDX_COMPONENT_OPERATING_SYSTEM), "operating-system") != 0) {
        printf("FAIL: Operating system component type name should be 'operating-system'\n");
        return false;
    }
    
    // Test invalid component type
    if (is_valid_component_type((asset_type_t)999)) {
        printf("FAIL: Invalid component type should be rejected\n");
        return false;
    }
    
    printf("PASS: Component type mapping tests passed\n");
    return true;
}

// Test property namespace validation
static bool test_property_namespace_validation(void) {
    printf("Testing property namespace validation...\n");
    
    // Test valid cbom: properties
    if (!is_valid_cbom_property("cbom:algo:primitive")) {
        printf("FAIL: 'cbom:algo:primitive' should be valid\n");
        return false;
    }
    
    if (!is_valid_cbom_property("cbom:cert:subject")) {
        printf("FAIL: 'cbom:cert:subject' should be valid\n");
        return false;
    }
    
    if (!is_valid_cbom_property("cbom:ctx:detection_method")) {
        printf("FAIL: 'cbom:ctx:detection_method' should be valid\n");
        return false;
    }
    
    // Test invalid properties (wrong namespace)
    if (is_valid_cbom_property("invalid:property")) {
        printf("FAIL: 'invalid:property' should be invalid\n");
        return false;
    }
    
    if (is_valid_cbom_property("property_without_namespace")) {
        printf("FAIL: 'property_without_namespace' should be invalid\n");
        return false;
    }
    
    if (is_valid_cbom_property("")) {
        printf("FAIL: Empty string should be invalid\n");
        return false;
    }
    
    if (is_valid_cbom_property(NULL)) {
        printf("FAIL: NULL should be invalid\n");
        return false;
    }
    
    printf("PASS: Property namespace validation tests passed\n");
    return true;
}

// Test property value validation
static bool test_property_value_validation(void) {
    printf("Testing property value validation...\n");
    
    // Test algorithm property validation
    property_validation_result_t result;
    
    // Valid algorithm primitive
    result = validate_property("cbom:algo:primitive", "block_cipher", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid algorithm primitive should pass validation\n");
        return false;
    }
    
    // Valid PQC status with allowed values
    result = validate_property("cbom:algo:pqc_status", "Safe", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid PQC status 'Safe' should pass validation\n");
        return false;
    }
    
    result = validate_property("cbom:algo:pqc_status", "Transitional", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid PQC status 'Transitional' should pass validation\n");
        return false;
    }
    
    // Invalid PQC status
    result = validate_property("cbom:algo:pqc_status", "InvalidStatus", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_INVALID_VALUE) {
        printf("FAIL: Invalid PQC status should fail validation\n");
        return false;
    }
    
    // Test certificate property validation
    result = validate_property("cbom:cert:trust_status", "VALID", ASSET_TYPE_CERTIFICATE);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid certificate trust status should pass validation\n");
        return false;
    }
    
    result = validate_property("cbom:cert:trust_status", "INVALID_STATUS", ASSET_TYPE_CERTIFICATE);
    if (result != PROPERTY_INVALID_VALUE) {
        printf("FAIL: Invalid certificate trust status should fail validation\n");
        return false;
    }
    
    // Test integer validation
    result = validate_property("cbom:algo:key_length", "256", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid integer key length should pass validation\n");
        return false;
    }
    
    result = validate_property("cbom:algo:key_length", "not_a_number", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_INVALID_VALUE) {
        printf("FAIL: Invalid integer should fail validation\n");
        return false;
    }
    
    // Test boolean validation
    result = validate_property("cbom:cert:is_ca", "true", ASSET_TYPE_CERTIFICATE);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid boolean 'true' should pass validation\n");
        return false;
    }
    
    result = validate_property("cbom:cert:is_ca", "false", ASSET_TYPE_CERTIFICATE);
    if (result != PROPERTY_VALID) {
        printf("FAIL: Valid boolean 'false' should pass validation\n");
        return false;
    }
    
    result = validate_property("cbom:cert:is_ca", "maybe", ASSET_TYPE_CERTIFICATE);
    if (result != PROPERTY_INVALID_VALUE) {
        printf("FAIL: Invalid boolean should fail validation\n");
        return false;
    }
    
    // Test invalid namespace
    result = validate_property("invalid:property", "value", ASSET_TYPE_ALGORITHM);
    if (result != PROPERTY_INVALID_NAMESPACE) {
        printf("FAIL: Invalid namespace should fail validation\n");
        return false;
    }
    
    printf("PASS: Property value validation tests passed\n");
    return true;
}

// Test CycloneDX component conversion
static bool test_cyclonedx_component_conversion(void) {
    printf("Testing CycloneDX component conversion...\n");
    
    cyclonedx_converter_t* converter = cyclonedx_converter_create(true);
    if (!converter) {
        printf("FAIL: Failed to create converter\n");
        return false;
    }
    
    // Test algorithm conversion
    crypto_asset_t* algorithm = create_test_algorithm();
    if (!algorithm) {
        printf("FAIL: Failed to create test algorithm\n");
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    char* component_json = convert_asset_to_cyclonedx_component(algorithm, converter);
    if (!component_json) {
        printf("FAIL: Failed to convert algorithm to CycloneDX component\n");
        free_test_asset(algorithm);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    // Verify the JSON contains expected fields
    if (!strstr(component_json, "\"type\": \"library\"")) {
        printf("FAIL: Algorithm component should have type 'library'\n");
        secure_free(component_json, strlen(component_json));
        free_test_asset(algorithm);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(component_json, "\"name\": \"AES-256-GCM\"")) {
        printf("FAIL: Algorithm component should have correct name\n");
        secure_free(component_json, strlen(component_json));
        free_test_asset(algorithm);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(component_json, "\"bom-ref\": \"algo-aes-256-gcm-001\"")) {
        printf("FAIL: Algorithm component should have correct bom-ref\n");
        secure_free(component_json, strlen(component_json));
        free_test_asset(algorithm);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    secure_free(component_json, strlen(component_json));
    free_test_asset(algorithm);
    
    // Test certificate conversion
    crypto_asset_t* certificate = create_test_certificate();
    if (!certificate) {
        printf("FAIL: Failed to create test certificate\n");
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    component_json = convert_asset_to_cyclonedx_component(certificate, converter);
    if (!component_json) {
        printf("FAIL: Failed to convert certificate to CycloneDX component\n");
        free_test_asset(certificate);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    // Verify certificate maps to data type
    if (!strstr(component_json, "\"type\": \"data\"")) {
        printf("FAIL: Certificate component should have type 'data'\n");
        secure_free(component_json, strlen(component_json));
        free_test_asset(certificate);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    secure_free(component_json, strlen(component_json));
    free_test_asset(certificate);
    
    // Test service conversion
    crypto_asset_t* service = create_test_service();
    if (!service) {
        printf("FAIL: Failed to create test service\n");
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    component_json = convert_asset_to_cyclonedx_component(service, converter);
    if (!component_json) {
        printf("FAIL: Failed to convert service to CycloneDX component\n");
        free_test_asset(service);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    // Verify service maps to operating-system type
    if (!strstr(component_json, "\"type\": \"operating-system\"")) {
        printf("FAIL: Service component should have type 'operating-system'\n");
        secure_free(component_json, strlen(component_json));
        free_test_asset(service);
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    secure_free(component_json, strlen(component_json));
    free_test_asset(service);
    cyclonedx_converter_destroy(converter);
    
    printf("PASS: CycloneDX component conversion tests passed\n");
    return true;
}

// Test full CBOM to CycloneDX conversion
static bool test_full_cbom_conversion(void) {
    printf("Testing full CBOM to CycloneDX conversion...\n");
    
    cyclonedx_converter_t* converter = cyclonedx_converter_create(true);
    if (!converter) {
        printf("FAIL: Failed to create converter\n");
        return false;
    }
    
    // Create test assets
    crypto_asset_t* assets[3];
    assets[0] = create_test_algorithm();
    assets[1] = create_test_certificate();
    assets[2] = create_test_service();
    
    if (!assets[0] || !assets[1] || !assets[2]) {
        printf("FAIL: Failed to create test assets\n");
        for (int i = 0; i < 3; i++) {
            if (assets[i]) free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    // Convert to CycloneDX
    char* cyclonedx_json = convert_cbom_to_cyclonedx((const crypto_asset_t**)assets, 3, NULL, 0, converter);
    if (!cyclonedx_json) {
        printf("FAIL: Failed to convert CBOM to CycloneDX\n");
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    // Verify CycloneDX structure
    if (!strstr(cyclonedx_json, "\"bomFormat\":\"CycloneDX\"")) {
        printf("FAIL: CycloneDX JSON should have bomFormat field\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(cyclonedx_json, "\"specVersion\":\"1.6\"")) {
        printf("FAIL: CycloneDX JSON should have specVersion 1.6\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(cyclonedx_json, "\"components\"")) {
        printf("FAIL: CycloneDX JSON should have components array\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(cyclonedx_json, "\"metadata\"")) {
        printf("FAIL: CycloneDX JSON should have metadata block\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    // Verify all three component types are present (compact format)
    if (!strstr(cyclonedx_json, "\"type\":\"library\"")) {
        printf("FAIL: CycloneDX JSON should contain library component\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(cyclonedx_json, "\"type\":\"data\"")) {
        printf("FAIL: CycloneDX JSON should contain data component\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    if (!strstr(cyclonedx_json, "\"type\":\"operating-system\"")) {
        printf("FAIL: CycloneDX JSON should contain operating-system component\n");
        secure_free(cyclonedx_json, strlen(cyclonedx_json));
        for (int i = 0; i < 3; i++) {
            free_test_asset(assets[i]);
        }
        cyclonedx_converter_destroy(converter);
        return false;
    }
    
    secure_free(cyclonedx_json, strlen(cyclonedx_json));
    for (int i = 0; i < 3; i++) {
        free_test_asset(assets[i]);
    }
    cyclonedx_converter_destroy(converter);
    
    printf("PASS: Full CBOM to CycloneDX conversion tests passed\n");
    return true;
}

// Test property drift detection
static bool test_property_drift_detection(void) {
    printf("Testing property drift detection...\n");
    
    if (!run_property_drift_tests()) {
        printf("FAIL: Property drift tests failed\n");
        return false;
    }
    
    if (!run_component_type_validation_tests()) {
        printf("FAIL: Component type validation tests failed\n");
        return false;
    }
    
    printf("PASS: Property drift detection tests passed\n");
    return true;
}

// Test JSON schema validation
static bool test_json_schema_validation(void) {
    printf("Testing JSON schema validation...\n");
    
    // Test valid JSON
    const char* valid_json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\"}";
    char* errors = NULL;
    
    if (!validate_against_cyclonedx_schema(valid_json, NULL, &errors)) {
        printf("FAIL: Valid JSON should pass schema validation\n");
        if (errors) secure_free(errors, strlen(errors));
        return false;
    }
    
    // Test invalid JSON
    const char* invalid_json = "{invalid json}";
    if (validate_against_cyclonedx_schema(invalid_json, NULL, &errors)) {
        printf("FAIL: Invalid JSON should fail schema validation\n");
        if (errors) secure_free(errors, strlen(errors));
        return false;
    }
    
    if (errors) {
        secure_free(errors, strlen(errors));
    }
    
    // Test NULL input
    if (validate_against_cyclonedx_schema(NULL, NULL, &errors)) {
        printf("FAIL: NULL JSON should fail schema validation\n");
        if (errors) secure_free(errors, strlen(errors));
        return false;
    }
    
    if (errors) {
        secure_free(errors, strlen(errors));
    }
    
    printf("PASS: JSON schema validation tests passed\n");
    return true;
}

int run_cyclonedx_converter_tests(void) {
    printf("Running CycloneDX Converter Tests...\n\n");
    
    bool all_passed = true;
    
    // Run all test suites
    all_passed &= test_component_type_mapping();
    all_passed &= test_property_namespace_validation();
    all_passed &= test_property_value_validation();
    all_passed &= test_cyclonedx_component_conversion();
    all_passed &= test_full_cbom_conversion();
    all_passed &= test_property_drift_detection();
    all_passed &= test_json_schema_validation();
    
    printf("\n=== Test Results ===\n");
    if (all_passed) {
        printf("ALL TESTS PASSED\n");
        printf("✓ Component type mappings are frozen and stable\n");
        printf("✓ Property namespaces are validated correctly\n");
        printf("✓ Property values are validated against expected types\n");
        printf("✓ CycloneDX conversion produces valid output\n");
        printf("✓ Property drift detection is working\n");
        printf("✓ JSON schema validation is functional\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED\n");
        printf("❌ Review failed tests above\n");
        return 1;
    }
}
