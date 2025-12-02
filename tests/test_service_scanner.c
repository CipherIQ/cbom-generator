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
#include <unistd.h>
#include "service_scanner.h"
#include "asset_store.h"
#include "secure_memory.h"

// Test 1: Service type string conversion
static void test_service_type_conversion(void) {
    printf("Testing service type string conversion...\n");

    assert(strcmp(service_type_to_string(SERVICE_TYPE_WEB_SERVER), "web_server") == 0);
    assert(strcmp(service_type_to_string(SERVICE_TYPE_HTTPS), "https") == 0);
    assert(strcmp(service_type_to_string(SERVICE_TYPE_SSH_SERVER), "ssh_server") == 0);
    assert(strcmp(service_type_to_string(SERVICE_TYPE_MAIL_SERVER), "mail_server") == 0);

    printf("✓ Service type conversion tests passed\n");
}

// Test 2: Security profile string conversion
static void test_security_profile_string(void) {
    printf("Testing security profile string conversion...\n");

    assert(strcmp(security_profile_to_string(SECURITY_PROFILE_MODERN), "MODERN") == 0);
    assert(strcmp(security_profile_to_string(SECURITY_PROFILE_INTERMEDIATE), "INTERMEDIATE") == 0);
    assert(strcmp(security_profile_to_string(SECURITY_PROFILE_OLD), "OLD") == 0);

    printf("✓ Security profile string conversion tests passed\n");
}

// Test 3: Security profile classification
static void test_security_profile_classification(void) {
    printf("Testing security profile classification...\n");

    // Modern profile: TLS 1.3
    const char* modern_versions[] = {"TLSv1.3", "TLSv1.2"};
    const char* strong_ciphers[] = {"AES-256-GCM-SHA384"};
    security_profile_t profile = classify_tls_security_profile(modern_versions, 2, strong_ciphers, 1);
    assert(profile == SECURITY_PROFILE_MODERN);

    // Intermediate profile: TLS 1.2 only
    const char* intermediate_versions[] = {"TLSv1.2"};
    profile = classify_tls_security_profile(intermediate_versions, 1, strong_ciphers, 1);
    assert(profile == SECURITY_PROFILE_INTERMEDIATE);

    // Old profile: TLS 1.0
    const char* old_versions[] = {"TLSv1.0", "TLSv1.1"};
    profile = classify_tls_security_profile(old_versions, 2, NULL, 0);
    assert(profile == SECURITY_PROFILE_OLD);

    printf("✓ Security profile classification tests passed\n");
}

// Test 4: Weak TLS version detection
static void test_weak_tls_version_detection(void) {
    printf("Testing weak TLS version detection...\n");

    assert(is_weak_tls_version("SSLv3") == true);
    assert(is_weak_tls_version("TLSv1.0") == true);
    assert(is_weak_tls_version("TLSv1.1") == true);
    assert(is_weak_tls_version("TLSv1.2") == false);
    assert(is_weak_tls_version("TLSv1.3") == false);

    printf("✓ Weak TLS version detection tests passed\n");
}

// Test 5: Weak cipher suite detection
static void test_weak_cipher_suite_detection(void) {
    printf("Testing weak cipher suite detection...\n");

    assert(is_weak_cipher_suite("RC4-SHA") == true);
    assert(is_weak_cipher_suite("DES-CBC3-SHA") == true);
    assert(is_weak_cipher_suite("NULL-SHA256") == true);
    assert(is_weak_cipher_suite("EXPORT-RC4-MD5") == true);
    assert(is_weak_cipher_suite("AES-256-GCM-SHA384") == false);
    assert(is_weak_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384") == false);

    printf("✓ Weak cipher suite detection tests passed\n");
}

// Test 6: Service scanner configuration
static void test_service_scanner_config(void) {
    printf("Testing service scanner configuration...\n");

    service_scanner_config_t config = service_scanner_create_default_config();

    assert(config.scan_running_processes == true);
    assert(config.scan_config_files == true);
    assert(config.detect_web_servers == true);
    assert(config.detect_ssh_servers == true);
    assert(config.detect_mail_servers == true);
    assert(config.centralize_tls == true);  // KEY FEATURE
    assert(config.extract_protocols == true);
    assert(config.max_services > 0);

    service_scanner_config_destroy(&config);

    printf("✓ Service scanner configuration tests passed\n");
}

// Test 7: Service scanner context
static void test_service_scanner_context(void) {
    printf("Testing service scanner context...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    service_scanner_config_t config = service_scanner_create_default_config();
    service_scanner_context_t* context = service_scanner_create(&config, store);
    assert(context != NULL);
    assert(context->asset_store == store);

    // Test statistics initialization
    service_scanner_stats_t stats = service_scanner_get_stats(context);
    assert(stats.services_detected_total == 0);
    assert(stats.protocols_extracted == 0);

    service_scanner_destroy(context);
    asset_store_destroy(store);

    // Test with NULL parameters
    context = service_scanner_create(NULL, store);
    assert(context == NULL);

    printf("✓ Service scanner context tests passed\n");
}

// Test 8: Service metadata creation
static void test_service_metadata_creation(void) {
    printf("Testing service metadata creation...\n");

    service_metadata_t* metadata = service_metadata_create("Apache HTTPD", SERVICE_TYPE_WEB_SERVER);
    assert(metadata != NULL);
    assert(strcmp(metadata->name, "Apache HTTPD") == 0);
    assert(metadata->type == SERVICE_TYPE_WEB_SERVER);

    service_metadata_destroy(metadata);

    printf("✓ Service metadata creation tests passed\n");
}

// Test 9: Protocol metadata creation
static void test_protocol_metadata_creation(void) {
    printf("Testing protocol metadata creation...\n");

    protocol_metadata_t* metadata = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
    assert(metadata != NULL);
    assert(strcmp(metadata->name, "TLS") == 0);
    assert(metadata->type == PROTOCOL_TYPE_TLS);

    protocol_metadata_destroy(metadata);

    printf("✓ Protocol metadata creation tests passed\n");
}

// Test 10: Service JSON metadata generation
static void test_service_json_metadata(void) {
    printf("Testing service JSON metadata generation...\n");

    service_metadata_t* metadata = service_metadata_create("Nginx", SERVICE_TYPE_WEB_SERVER);
    assert(metadata != NULL);

    metadata->version = strdup("1.18.0");
    metadata->daemon_name = strdup("nginx");
    metadata->is_running = true;

    char* json = service_create_detailed_json_metadata(metadata);
    assert(json != NULL);
    assert(strstr(json, "\"name\"") != NULL);
    assert(strstr(json, "\"version\"") != NULL);
    assert(strstr(json, "\"is_running\"") != NULL);

    free(json);
    service_metadata_destroy(metadata);

    printf("✓ Service JSON metadata generation tests passed\n");
}

// Test 11: Protocol JSON metadata generation
static void test_protocol_json_metadata(void) {
    printf("Testing protocol JSON metadata generation...\n");

    protocol_metadata_t* metadata = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
    assert(metadata != NULL);

    metadata->version = strdup("1.3");
    metadata->security_profile = SECURITY_PROFILE_MODERN;

    char* json = protocol_create_detailed_json_metadata(metadata);
    assert(json != NULL);
    assert(strstr(json, "\"protocol_type\"") != NULL);
    assert(strstr(json, "\"version\"") != NULL);
    assert(strstr(json, "\"security_profile\"") != NULL);
    assert(strstr(json, "MODERN") != NULL);

    free(json);
    protocol_metadata_destroy(metadata);

    printf("✓ Protocol JSON metadata generation tests passed\n");
}

// Test 12: Service asset creation
static void test_service_asset_creation(void) {
    printf("Testing service asset creation...\n");

    service_metadata_t* metadata = service_metadata_create("Apache HTTPD", SERVICE_TYPE_WEB_SERVER);
    assert(metadata != NULL);

    metadata->version = strdup("2.4.52");
    metadata->daemon_name = strdup("apache2");
    metadata->config_file_path = strdup("/etc/apache2/apache2.conf");

    crypto_asset_t* asset = service_create_asset(metadata);
    assert(asset != NULL);
    assert(asset->type == ASSET_TYPE_SERVICE);
    assert(asset->id != NULL);
    assert(strstr(asset->id, "service|") != NULL);
    assert(strstr(asset->id, "Apache HTTPD") != NULL);

    service_metadata_destroy(metadata);

    printf("✓ Service asset creation tests passed\n");
}

// Test 13: Protocol asset creation
static void test_protocol_asset_creation(void) {
    printf("Testing protocol asset creation...\n");

    protocol_metadata_t* metadata = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
    assert(metadata != NULL);

    metadata->version = strdup("1.3");
    metadata->config_file_path = strdup("/etc/nginx/nginx.conf");

    crypto_asset_t* asset = protocol_create_asset(metadata);
    assert(asset != NULL);
    assert(asset->type == ASSET_TYPE_PROTOCOL);
    assert(asset->id != NULL);
    assert(strstr(asset->id, "protocol|") != NULL);
    assert(strstr(asset->id, "TLS") != NULL);

    protocol_metadata_destroy(metadata);

    printf("✓ Protocol asset creation tests passed\n");
}

// Test 14: Service scanner statistics
static void test_service_scanner_statistics(void) {
    printf("Testing service scanner statistics...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    service_scanner_config_t config = service_scanner_create_default_config();
    service_scanner_context_t* context = service_scanner_create(&config, store);
    assert(context != NULL);

    service_scanner_stats_t stats = service_scanner_get_stats(context);
    assert(stats.services_detected_total == 0);
    assert(stats.apache_found == 0);
    assert(stats.protocols_extracted == 0);

    service_scanner_destroy(context);
    asset_store_destroy(store);

    printf("✓ Service scanner statistics tests passed\n");
}

// Test 15: TLS centralization concept
static void test_tls_centralization_concept(void) {
    printf("Testing TLS centralization concept...\n");

    // Verify that TLS protocol extraction is separate from service
    // This tests the architectural principle: service USES protocol

    service_metadata_t* apache = service_metadata_create("Apache", SERVICE_TYPE_WEB_SERVER);
    protocol_metadata_t* tls = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);

    assert(apache != NULL);
    assert(tls != NULL);

    // Different asset types
    crypto_asset_t* service_asset = service_create_asset(apache);
    crypto_asset_t* protocol_asset = protocol_create_asset(tls);

    assert(service_asset->type == ASSET_TYPE_SERVICE);
    assert(protocol_asset->type == ASSET_TYPE_PROTOCOL);

    // Different normalized IDs
    assert(strstr(service_asset->id, "service|") != NULL);
    assert(strstr(protocol_asset->id, "protocol|") != NULL);

    service_metadata_destroy(apache);
    protocol_metadata_destroy(tls);

    printf("✓ TLS centralization concept tests passed\n");
}

// Test 16: Service running detection
static void test_service_running_detection(void) {
    printf("Testing service running detection...\n");

    // Test with a process that should not exist
    bool running = is_service_running("nonexistent_daemon_xyz");
    assert(running == false);

    printf("✓ Service running detection tests passed\n");
}

// Test 17: Graceful handling of missing services
static void test_missing_services_handling(void) {
    printf("Testing graceful handling of missing services...\n");

    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    service_scanner_config_t config = service_scanner_create_default_config();
    service_scanner_context_t* context = service_scanner_create(&config, store);
    assert(context != NULL);

    // Scan for services - should not crash even if none found
    int result = service_scanner_scan_all(context);
    // Result may be 0 (none found) or positive (found some)
    // Just verify no crash
    (void)result;

    service_scanner_destroy(context);
    asset_store_destroy(store);

    printf("✓ Missing services handling tests passed\n");
}

// Test 18: Protocol asset type verification (Phase 8 polish)
static void test_protocol_asset_type(void) {
    printf("Testing protocol asset type (type=protocol)...\n");

    // Create TLS protocol
    protocol_metadata_t* tls_protocol = protocol_metadata_create("TLS", PROTOCOL_TYPE_TLS);
    assert(tls_protocol != NULL);
    tls_protocol->version = strdup("1.3");

    crypto_asset_t* protocol_asset = protocol_create_asset(tls_protocol);
    assert(protocol_asset != NULL);
    assert(protocol_asset->type == ASSET_TYPE_PROTOCOL);
    assert(strcmp(protocol_asset->name, "TLS") == 0);

    protocol_metadata_destroy(tls_protocol);

    // Create SSH protocol
    protocol_metadata_t* ssh_protocol = protocol_metadata_create("SSH", PROTOCOL_TYPE_SSH);
    assert(ssh_protocol != NULL);
    ssh_protocol->version = strdup("2.0");

    crypto_asset_t* ssh_asset = protocol_create_asset(ssh_protocol);
    assert(ssh_asset != NULL);
    assert(ssh_asset->type == ASSET_TYPE_PROTOCOL);
    assert(strcmp(ssh_asset->name, "SSH") == 0);

    protocol_metadata_destroy(ssh_protocol);

    printf("✓ Protocol asset type tests passed (ASSET_TYPE_PROTOCOL verified)\n");
}

// Main test runner
int main(void) {
    printf("=== Service Scanner Test Suite ===\n\n");

    // Initialize secure memory subsystem
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory subsystem\n");
        return 1;
    }

    // Run all tests
    test_service_type_conversion();
    test_security_profile_string();
    test_security_profile_classification();
    test_weak_tls_version_detection();
    test_weak_cipher_suite_detection();
    test_service_scanner_config();
    test_service_scanner_context();
    test_service_metadata_creation();
    test_protocol_metadata_creation();
    test_service_json_metadata();
    test_protocol_json_metadata();
    test_service_asset_creation();
    test_protocol_asset_creation();
    test_service_scanner_statistics();
    test_tls_centralization_concept();
    test_service_running_detection();
    test_missing_services_handling();
    test_protocol_asset_type();  // Phase 8 polish

    // Cleanup
    secure_memory_cleanup();

    printf("\n=== All Service Scanner Tests Passed ===\n");
    printf("Total: 18 tests\n");
    return 0;
}
