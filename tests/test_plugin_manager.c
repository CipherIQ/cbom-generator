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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include "plugin_manager.h"

// Mock plugin interface for testing
static plugin_metadata_t test_plugin_metadata = {
    .name = "test_scanner",
    .version = "1.0.0",
    .description = "Test scanner plugin",
    .author = "Test Author",
    .api_version = CBOM_PLUGIN_API_VERSION,
    .type = PLUGIN_TYPE_SCANNER,
    .subtype = SCANNER_TYPE_FILESYSTEM,
    .is_signed = false,
    .is_trusted = true
};

static int test_plugin_init(plugin_instance_t* instance, const char* config) {
    return PLUGIN_SUCCESS;
}

static int test_plugin_cleanup(plugin_instance_t* instance) {
    return PLUGIN_SUCCESS;
}

static int test_plugin_scan(plugin_instance_t* instance, scan_context_t* context, asset_store_t* store) {
    // Mock scan implementation
    return PLUGIN_SUCCESS;
}

static const plugin_metadata_t* test_plugin_get_metadata(void) {
    return &test_plugin_metadata;
}

static plugin_interface_t test_plugin_interface = {
    .api_version = CBOM_PLUGIN_API_VERSION,
    .get_metadata = test_plugin_get_metadata,
    .init = test_plugin_init,
    .cleanup = test_plugin_cleanup,
    .scan = test_plugin_scan,
    .analyze = NULL
};

// Mock plugin interface function
const plugin_interface_t* cbom_plugin_interface(void) {
    return &test_plugin_interface;
}

// Test functions
static void test_plugin_manager_creation_and_destruction(void) {
    printf("Testing plugin manager creation and destruction...\n");
    
    // Test valid creation
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    assert(strcmp(manager->plugin_directory, "plugins/") == 0);
    assert(manager->security_policy == PLUGIN_SECURITY_PERMISSIVE);
    assert(manager->max_plugins == PLUGIN_MAX_PLUGINS);
    plugin_manager_destroy(manager);
    
    // Test invalid parameters
    manager = plugin_manager_create(NULL, PLUGIN_SECURITY_STRICT);
    assert(manager == NULL);
    
    printf("✓ Plugin manager creation and destruction tests passed\n");
}

static void test_plugin_trust_configuration(void) {
    printf("Testing plugin trust configuration...\n");
    
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_STRICT);
    assert(manager != NULL);
    
    // Test setting trust configuration
    plugin_trust_config_t trust_config = {0};
    trust_config.trust_root_path = malloc(strlen("fixtures/plugin-keys/") + 1);
    strcpy(trust_config.trust_root_path, "fixtures/plugin-keys/");
    trust_config.test_keys_path = malloc(strlen("fixtures/plugin-keys/") + 1);
    strcpy(trust_config.test_keys_path, "fixtures/plugin-keys/");
    trust_config.production_keys_path = malloc(strlen("/etc/cbom/plugin-keys/") + 1);
    strcpy(trust_config.production_keys_path, "/etc/cbom/plugin-keys/");
    trust_config.allow_test_keys = true;
    trust_config.key_rotation_days = 90;
    
    int result = plugin_manager_set_trust_config(manager, &trust_config);
    assert(result == PLUGIN_SUCCESS);
    
    // Verify configuration was set
    assert(strcmp(manager->trust_config.trust_root_path, "fixtures/plugin-keys/") == 0);
    assert(manager->trust_config.allow_test_keys == true);
    assert(manager->trust_config.key_rotation_days == 90);
    
    free(trust_config.trust_root_path);
    free(trust_config.test_keys_path);
    free(trust_config.production_keys_path);
    plugin_manager_destroy(manager);
    
    printf("✓ Plugin trust configuration tests passed\n");
}

static void test_plugin_resource_limits(void) {
    printf("Testing plugin resource limits...\n");
    
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    
    // Test setting default limits
    plugin_resource_limits_t limits = {0};
    limits.max_memory_bytes = 128 * 1024 * 1024; // 128 MB
    limits.max_execution_time_ms = 15000;        // 15 seconds
    limits.max_file_descriptors = 32;
    limits.max_threads = 2;
    limits.allow_network_access = false;
    limits.allow_filesystem_write = false;
    
    int result = plugin_manager_set_default_limits(manager, &limits);
    assert(result == PLUGIN_SUCCESS);
    
    // Verify limits were set
    assert(manager->default_limits.max_memory_bytes == 128 * 1024 * 1024);
    assert(manager->default_limits.max_execution_time_ms == 15000);
    assert(manager->default_limits.max_file_descriptors == 32);
    assert(manager->default_limits.max_threads == 2);
    assert(manager->default_limits.allow_network_access == false);
    assert(manager->default_limits.allow_filesystem_write == false);
    
    plugin_manager_destroy(manager);
    
    printf("✓ Plugin resource limits tests passed\n");
}

static void test_plugin_api_version_validation(void) {
    printf("Testing plugin API version validation...\n");
    
    // Test exact version match
    assert(plugin_validate_api_version(CBOM_PLUGIN_API_VERSION) == PLUGIN_SUCCESS);
    
    // Test major version mismatch
    uint32_t wrong_major = ((CBOM_PLUGIN_API_VERSION_MAJOR + 1) << 16) | 
                          (CBOM_PLUGIN_API_VERSION_MINOR << 8) | 
                          CBOM_PLUGIN_API_VERSION_PATCH;
    assert(plugin_validate_api_version(wrong_major) == PLUGIN_ERROR_API_VERSION_MISMATCH);
    
    // Test minor version compatibility (older plugin should work)
    if (CBOM_PLUGIN_API_VERSION_MINOR > 0) {
        uint32_t older_minor_version = CBOM_PLUGIN_API_VERSION_MINOR - 1;
        uint32_t older_minor = (CBOM_PLUGIN_API_VERSION_MAJOR << 16) | 
                              (older_minor_version << 8) | 
                              CBOM_PLUGIN_API_VERSION_PATCH;
        assert(plugin_validate_api_version(older_minor) == PLUGIN_SUCCESS);
    }
    
    // Test newer minor version (should fail)
    uint32_t newer_minor = (CBOM_PLUGIN_API_VERSION_MAJOR << 16) | 
                          ((CBOM_PLUGIN_API_VERSION_MINOR + 1) << 8) | 
                          CBOM_PLUGIN_API_VERSION_PATCH;
    assert(plugin_validate_api_version(newer_minor) == PLUGIN_ERROR_API_VERSION_MISMATCH);
    
    printf("✓ Plugin API version validation tests passed\n");
}

static void test_plugin_utility_functions(void) {
    printf("Testing plugin utility functions...\n");
    
    // Test plugin type to string conversion
    assert(strcmp(plugin_type_to_string(PLUGIN_TYPE_SCANNER), "Scanner") == 0);
    assert(strcmp(plugin_type_to_string(PLUGIN_TYPE_ANALYZER), "Analyzer") == 0);
    assert(strcmp(plugin_type_to_string(PLUGIN_TYPE_FORMATTER), "Formatter") == 0);
    assert(strcmp(plugin_type_to_string(PLUGIN_TYPE_VALIDATOR), "Validator") == 0);
    
    // Test scanner subtype to string conversion
    assert(strcmp(scanner_subtype_to_string(SCANNER_TYPE_FILESYSTEM), "Filesystem") == 0);
    assert(strcmp(scanner_subtype_to_string(SCANNER_TYPE_PROCESS), "Process") == 0);
    assert(strcmp(scanner_subtype_to_string(SCANNER_TYPE_CERTIFICATE), "Certificate") == 0);
    assert(strcmp(scanner_subtype_to_string(SCANNER_TYPE_PACKAGE), "Package") == 0);
    
    // Test default limits creation
    plugin_resource_limits_t limits = plugin_create_default_limits();
    assert(limits.max_memory_bytes > 0);
    assert(limits.max_execution_time_ms > 0);
    assert(limits.max_file_descriptors > 0);
    assert(limits.max_threads > 0);
    
    // Test default trust config creation
    plugin_trust_config_t trust_config = plugin_create_default_trust_config();
    assert(trust_config.test_keys_path != NULL);
    assert(trust_config.allow_test_keys == true);
    assert(trust_config.key_rotation_days > 0);
    
    free(trust_config.test_keys_path);
    
    printf("✓ Plugin utility functions tests passed\n");
}

static void test_plugin_capability_checking(void) {
    printf("Testing plugin capability checking...\n");
    
    // Test plugin with no required capabilities
    plugin_metadata_t metadata = {0};
    metadata.required_capabilities = NULL;
    metadata.required_capabilities_count = 0;
    
    bool result = plugin_check_capabilities(&metadata);
    assert(result == true);
    
    // Test plugin with required capabilities
    const char* capabilities[] = {"CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"};
    metadata.required_capabilities = (char**)capabilities;
    metadata.required_capabilities_count = 2;
    
    result = plugin_check_capabilities(&metadata);
    // In the simplified implementation, this should return true
    assert(result == true);
    
    printf("✓ Plugin capability checking tests passed\n");
}

static void test_plugin_statistics(void) {
    printf("Testing plugin statistics...\n");
    
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    
    // Get initial statistics
    plugin_statistics_t stats = plugin_manager_get_statistics(manager);
    assert(stats.total_plugins == 0);
    assert(stats.active_plugins == 0);
    assert(stats.total_invocations == 0);
    assert(stats.total_errors == 0);
    
    printf("  Total plugins: %u\n", stats.total_plugins);
    printf("  Active plugins: %u\n", stats.active_plugins);
    printf("  Total invocations: %lu\n", stats.total_invocations);
    printf("  Total errors: %lu\n", stats.total_errors);
    printf("  Memory usage: %zu bytes\n", stats.total_memory_usage);
    
    plugin_manager_destroy(manager);
    
    printf("✓ Plugin statistics tests passed\n");
}

static void test_plugin_security_policies(void) {
    printf("Testing plugin security policies...\n");
    
    // Test strict security policy
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_STRICT);
    assert(manager != NULL);
    assert(manager->security_policy == PLUGIN_SECURITY_STRICT);
    plugin_manager_destroy(manager);
    
    // Test permissive security policy
    manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    assert(manager->security_policy == PLUGIN_SECURITY_PERMISSIVE);
    plugin_manager_destroy(manager);
    
    // Test disabled security policy
    manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_DISABLED);
    assert(manager != NULL);
    assert(manager->security_policy == PLUGIN_SECURITY_DISABLED);
    plugin_manager_destroy(manager);
    
    printf("✓ Plugin security policies tests passed\n");
}

static void test_plugin_sandboxing_and_limits(void) {
    printf("Testing plugin sandboxing and resource limits...\n");
    
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    
    // Create a mock plugin instance
    plugin_instance_t instance = {0};
    instance.instance_id = 1;
    strcpy(instance.metadata.name, "test_plugin");
    instance.active_limits = plugin_create_default_limits();
    
    // Test resource limit enforcement
    int result = plugin_enforce_resource_limits(&instance);
    // Should succeed (or warn) but not fail completely
    assert(result == PLUGIN_SUCCESS);
    
    // Test sandboxing application
    result = plugin_apply_sandboxing(&instance);
    assert(result == PLUGIN_SUCCESS);
    
    plugin_manager_destroy(manager);
    
    printf("✓ Plugin sandboxing and resource limits tests passed\n");
}

static void test_plugin_interface_verification(void) {
    printf("Testing plugin interface verification...\n");
    
    // Test valid interface
    plugin_interface_t valid_interface = {
        .api_version = CBOM_PLUGIN_API_VERSION,
        .get_metadata = test_plugin_get_metadata,
        .init = test_plugin_init,
        .cleanup = test_plugin_cleanup,
        .scan = test_plugin_scan,
        .analyze = NULL
    };
    
    // This function is internal, so we can't test it directly
    // But we can verify that our test interface is properly structured
    assert(valid_interface.get_metadata != NULL);
    assert(valid_interface.api_version == CBOM_PLUGIN_API_VERSION);
    
    // Test interface metadata retrieval
    const plugin_metadata_t* metadata = valid_interface.get_metadata();
    assert(metadata != NULL);
    assert(strcmp(metadata->name, "test_scanner") == 0);
    assert(strcmp(metadata->version, "1.0.0") == 0);
    assert(metadata->api_version == CBOM_PLUGIN_API_VERSION);
    assert(metadata->type == PLUGIN_TYPE_SCANNER);
    
    printf("✓ Plugin interface verification tests passed\n");
}

static void test_plugin_error_handling(void) {
    printf("Testing plugin error handling...\n");
    
    // Test invalid parameters
    plugin_manager_t* manager = plugin_manager_create("plugins/", PLUGIN_SECURITY_PERMISSIVE);
    assert(manager != NULL);
    
    // Test loading non-existent plugin
    int result = plugin_manager_load_plugin(manager, "non_existent_plugin.so", PLUGIN_LOAD_DEFAULT);
    assert(result != PLUGIN_SUCCESS);
    
    // Test finding non-existent plugin
    plugin_instance_t* instance = plugin_manager_find_plugin(manager, "non_existent");
    assert(instance == NULL);
    
    // Test getting non-existent plugin by ID
    instance = plugin_manager_get_plugin(manager, 999);
    assert(instance == NULL);
    
    plugin_manager_destroy(manager);
    
    printf("✓ Plugin error handling tests passed\n");
}

int run_plugin_manager_tests(void) {
    printf("Running plugin manager tests...\n\n");
    
    test_plugin_manager_creation_and_destruction();
    test_plugin_trust_configuration();
    test_plugin_resource_limits();
    test_plugin_api_version_validation();
    test_plugin_utility_functions();
    test_plugin_capability_checking();
    test_plugin_statistics();
    test_plugin_security_policies();
    test_plugin_sandboxing_and_limits();
    test_plugin_interface_verification();
    test_plugin_error_handling();
    
    printf("\n✅ All plugin manager tests passed!\n");
    return 0;
}
