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
#include <unistd.h>
#include <sys/stat.h>
#include "config.h"
#include "secure_memory.h"

// Test default configuration creation
static bool test_default_config_creation(void) {
    printf("Running test: default_config_creation... ");
    
    cbom_config_t* config = cbom_config_get_default();
    if (!config) {
        printf("FAILED - Could not create default configuration\n");
        return false;
    }
    
    // Check default values
    if (!config->network.no_network) {
        printf("FAILED - Default should be no_network=true\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->network.enable_ocsp) {
        printf("FAILED - Default should be enable_ocsp=false\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->network.revocation_timeout != 10) {
        printf("FAILED - Default revocation timeout should be 10 seconds\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->scan.deterministic) {
        printf("FAILED - Default should be deterministic=true\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->output.format || strcmp(config->output.format, "json") != 0) {
        printf("FAILED - Default output format should be 'json'\n");
        cbom_config_destroy(config);
        return false;
    }
    
    cbom_config_destroy(config);
    
    printf("PASSED\n");
    return true;
}

// Test JSON configuration loading
static bool test_json_config_loading(void) {
    printf("Running test: json_config_loading... ");
    
    const char* json_config = 
        "{\n"
        "  \"network\": {\n"
        "    \"no_network\": false,\n"
        "    \"enable_ocsp\": true,\n"
        "    \"revocation_timeout\": 30\n"
        "  },\n"
        "  \"scan\": {\n"
        "    \"thread_count\": 8,\n"
        "    \"deterministic\": false\n"
        "  },\n"
        "  \"output\": {\n"
        "    \"format\": \"cyclonedx\",\n"
        "    \"validate_schema\": false\n"
        "  }\n"
        "}";
    
    cbom_config_t* config = cbom_config_load_from_json(json_config);
    if (!config) {
        printf("FAILED - Could not load configuration from JSON\n");
        return false;
    }
    
    // Check loaded values
    if (config->network.no_network) {
        printf("FAILED - Should have loaded no_network=false\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->network.enable_ocsp) {
        printf("FAILED - Should have loaded enable_ocsp=true\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->network.revocation_timeout != 30) {
        printf("FAILED - Should have loaded revocation_timeout=30\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->scan.thread_count != 8) {
        printf("FAILED - Should have loaded thread_count=8\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->scan.deterministic) {
        printf("FAILED - Should have loaded deterministic=false\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->output.format || strcmp(config->output.format, "cyclonedx") != 0) {
        printf("FAILED - Should have loaded format='cyclonedx'\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->output.validate_schema) {
        printf("FAILED - Should have loaded validate_schema=false\n");
        cbom_config_destroy(config);
        return false;
    }
    
    cbom_config_destroy(config);
    
    printf("PASSED\n");
    return true;
}

// Test command line argument parsing
static bool test_cli_argument_parsing(void) {
    printf("Running test: cli_argument_parsing... ");
    
    // Test basic arguments
    char* argv[] = {
        "cbom-generator",
        "--enable-network",
        "--ocsp",
        "--revocation-timeout", "20",
        "--output", "test_output.json",
        "--format", "cyclonedx",
        "--threads", "4",
        "--verbose"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    cbom_config_t* config = cbom_config_parse_args(argc, argv);
    if (!config) {
        printf("FAILED - Could not parse command line arguments\n");
        return false;
    }
    
    // Check parsed values
    if (config->network.no_network) {
        printf("FAILED - Should have parsed --enable-network\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->network.enable_ocsp) {
        printf("FAILED - Should have parsed --ocsp\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->network.revocation_timeout != 20) {
        printf("FAILED - Should have parsed --revocation-timeout 20\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->output.output_file || strcmp(config->output.output_file, "test_output.json") != 0) {
        printf("FAILED - Should have parsed --output test_output.json\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->output.format || strcmp(config->output.format, "cyclonedx") != 0) {
        printf("FAILED - Should have parsed --format cyclonedx\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (config->scan.thread_count != 4) {
        printf("FAILED - Should have parsed --threads 4\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!config->verbose) {
        printf("FAILED - Should have parsed --verbose\n");
        cbom_config_destroy(config);
        return false;
    }
    
    cbom_config_destroy(config);
    
    printf("PASSED\n");
    return true;
}

// Test network configuration helpers
static bool test_network_config_helpers(void) {
    printf("Running test: network_config_helpers... ");
    
    cbom_config_t* config = cbom_config_get_default();
    if (!config) {
        printf("FAILED - Could not create configuration\n");
        return false;
    }
    
    // Test default network disabled
    if (cbom_config_is_network_enabled(config)) {
        printf("FAILED - Network should be disabled by default\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (cbom_config_should_check_revocation(config)) {
        printf("FAILED - Revocation checking should be disabled by default\n");
        cbom_config_destroy(config);
        return false;
    }
    
    // Enable network and OCSP
    config->network.no_network = false;
    config->network.enable_ocsp = true;
    
    if (!cbom_config_is_network_enabled(config)) {
        printf("FAILED - Network should be enabled\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!cbom_config_should_check_revocation(config)) {
        printf("FAILED - Revocation checking should be enabled\n");
        cbom_config_destroy(config);
        return false;
    }
    
    // Test timeout helper
    int timeout = cbom_config_get_revocation_timeout(config);
    if (timeout != 10) {
        printf("FAILED - Default timeout should be 10 seconds\n");
        cbom_config_destroy(config);
        return false;
    }
    
    cbom_config_destroy(config);
    
    printf("PASSED\n");
    return true;
}

// Test configuration merging
static bool test_config_merging(void) {
    printf("Running test: config_merging... ");
    
    cbom_config_t* base = cbom_config_get_default();
    cbom_config_t* override = cbom_config_get_default();
    
    if (!base || !override) {
        printf("FAILED - Could not create configurations\n");
        if (base) cbom_config_destroy(base);
        if (override) cbom_config_destroy(override);
        return false;
    }
    
    // Modify override config
    override->network.no_network = false;
    override->network.enable_ocsp = true;
    override->scan.thread_count = 16;
    if (override->output.format) free(override->output.format);
    override->output.format = strdup("cyclonedx");
    override->verbose = true;
    
    // Merge configurations
    cbom_config_merge(base, override);
    
    // Check merged values
    if (base->network.no_network) {
        printf("FAILED - Should have merged no_network=false\n");
        cbom_config_destroy(base);
        cbom_config_destroy(override);
        return false;
    }
    
    if (!base->network.enable_ocsp) {
        printf("FAILED - Should have merged enable_ocsp=true\n");
        cbom_config_destroy(base);
        cbom_config_destroy(override);
        return false;
    }
    
    if (base->scan.thread_count != 16) {
        printf("FAILED - Should have merged thread_count=16\n");
        cbom_config_destroy(base);
        cbom_config_destroy(override);
        return false;
    }
    
    if (!base->output.format || strcmp(base->output.format, "cyclonedx") != 0) {
        printf("FAILED - Should have merged format='cyclonedx'\n");
        cbom_config_destroy(base);
        cbom_config_destroy(override);
        return false;
    }
    
    if (!base->verbose) {
        printf("FAILED - Should have merged verbose=true\n");
        cbom_config_destroy(base);
        cbom_config_destroy(override);
        return false;
    }
    
    cbom_config_destroy(base);
    cbom_config_destroy(override);
    
    printf("PASSED\n");
    return true;
}

// Test revocation cache
static bool test_revocation_cache(void) {
    printf("Running test: revocation_cache... ");
    
    // Create temporary cache directory
    char temp_dir[] = "/tmp/cbom_cache_test_XXXXXX";
    if (!mkdtemp(temp_dir)) {
        printf("FAILED - Could not create temporary directory\n");
        return false;
    }
    
    revocation_cache_t* cache = revocation_cache_create(temp_dir);
    if (!cache) {
        printf("FAILED - Could not create revocation cache\n");
        rmdir(temp_dir);
        return false;
    }
    
    // Create test configuration
    cbom_config_t* config = cbom_config_get_default();
    if (!config) {
        printf("FAILED - Could not create configuration\n");
        revocation_cache_destroy(cache);
        rmdir(temp_dir);
        return false;
    }
    
    // Test cache miss with network disabled
    const char* test_fingerprint = "abcdef1234567890";
    revocation_status_t status = revocation_cache_check(cache, test_fingerprint, config);
    
    if (status != REVOCATION_STATUS_CACHE_MISS) {
        printf("FAILED - Should return cache miss when network disabled and no cache entry\n");
        cbom_config_destroy(config);
        revocation_cache_destroy(cache);
        rmdir(temp_dir);
        return false;
    }
    
    // Test status string conversion
    const char* status_str = revocation_status_to_string(status);
    if (strcmp(status_str, "cache_miss") != 0) {
        printf("FAILED - Status string should be 'cache_miss'\n");
        cbom_config_destroy(config);
        revocation_cache_destroy(cache);
        rmdir(temp_dir);
        return false;
    }
    
    // Test cache miss vs revocation failed distinction
    if (!is_cache_miss_vs_revocation_failed(status)) {
        printf("FAILED - Should distinguish cache miss from revocation failure\n");
        cbom_config_destroy(config);
        revocation_cache_destroy(cache);
        rmdir(temp_dir);
        return false;
    }
    
    cbom_config_destroy(config);
    revocation_cache_destroy(cache);
    rmdir(temp_dir);
    
    printf("PASSED\n");
    return true;
}

// Test configuration validation
static bool test_config_validation(void) {
    printf("Running test: config_validation... ");
    
    cbom_config_t* config = cbom_config_get_default();
    if (!config) {
        printf("FAILED - Could not create configuration\n");
        return false;
    }
    
    // Test valid configuration
    config_validation_result_t* result = cbom_config_validate(config);
    if (!result) {
        printf("FAILED - Could not validate configuration\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (!result->valid) {
        printf("FAILED - Default configuration should be valid\n");
        config_validation_result_destroy(result);
        cbom_config_destroy(config);
        return false;
    }
    
    config_validation_result_destroy(result);
    
    // Test invalid configuration
    config->network.revocation_timeout = -1; // Invalid timeout
    result = cbom_config_validate(config);
    
    if (!result) {
        printf("FAILED - Could not validate invalid configuration\n");
        cbom_config_destroy(config);
        return false;
    }
    
    if (result->valid) {
        printf("FAILED - Invalid configuration should fail validation\n");
        config_validation_result_destroy(result);
        cbom_config_destroy(config);
        return false;
    }
    
    config_validation_result_destroy(result);
    cbom_config_destroy(config);
    
    printf("PASSED\n");
    return true;
}

// Main test runner
int run_config_tests(void) {
    int passed = 0;
    int total = 7;
    
    if (test_default_config_creation()) passed++;
    if (test_json_config_loading()) passed++;
    if (test_cli_argument_parsing()) passed++;
    if (test_network_config_helpers()) passed++;
    if (test_config_merging()) passed++;
    if (test_revocation_cache()) passed++;
    if (test_config_validation()) passed++;
    
    printf("Tests run: %d, Passed: %d\n", total, passed);
    
    if (passed == total) {
        printf("Configuration tests PASSED!\n");
        return 0;
    } else {
        printf("Configuration tests FAILED!\n");
        return 1;
    }
}
