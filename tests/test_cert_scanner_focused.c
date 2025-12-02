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
#include <sys/stat.h>
#include "certificate_scanner.h"
#include "asset_store.h"

int main(void) {
    printf("=== Focused Certificate Scanner Test ===\n\n");
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Create asset store
    asset_store_t* store = asset_store_create(16);
    if (!store) {
        printf("❌ Failed to create asset store\n");
        return 1;
    }
    
    // Create scanner configuration
    cert_scanner_config_t config = cert_scanner_create_default_config();
    config.validate_trust_chains = false; // Disable for test
    
    // Override scan paths to only look at our test certificates
    if (config.scan_paths) {
        for (size_t i = 0; i < config.scan_path_count; i++) {
            free(config.scan_paths[i]);
        }
        free(config.scan_paths);
    }
    
    config.scan_path_count = 1;
    config.scan_paths = malloc(sizeof(char*));
    config.scan_paths[0] = strdup("../fixtures/test-certificates");
    
    printf("📁 Scanning directory: %s\n", config.scan_paths[0]);
    
    // Create certificate scanner
    cert_scanner_context_t* context = cert_scanner_create(&config, (struct asset_store*)store);
    if (!context) {
        printf("❌ Failed to create certificate scanner context\n");
        const char* error = cert_scanner_get_last_error();
        if (error) {
            printf("   Error: %s\n", error);
        }
        asset_store_destroy(store);
        return 1;
    }
    
    printf("✅ Certificate scanner created successfully\n");
    
    // Test individual file scanning first
    const char* test_file = "../fixtures/test-certificates/simple-test.pem";
    printf("\n🔍 Testing individual file scan: %s\n", test_file);
    
    // Check if file exists
    struct stat st;
    if (stat(test_file, &st) != 0) {
        printf("⚠️  Test file not found, creating it...\n");
        
        // Create the directory if it doesn't exist
        int mkdir_result = system("mkdir -p ../fixtures/test-certificates");
        (void)mkdir_result; // Suppress unused variable warning
        
        // Create a simple test certificate
        FILE* f = fopen(test_file, "w");
        if (f) {
            fprintf(f, "-----BEGIN CERTIFICATE-----\n");
            fprintf(f, "MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n");
            fprintf(f, "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n");
            fprintf(f, "aWRnaXRzIFB0eSBMdGQwHhcNMTMwODI3MjM1NDA3WhcNMTQwODI3MjM1NDA3WjBF\n");
            fprintf(f, "MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n");
            fprintf(f, "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n");
            fprintf(f, "CgKCAQEAwJK/EPUBZkP8wLp8VnwHwB8CH75c8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJ\n");
            fprintf(f, "r8nN8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJ\n");
            fprintf(f, "r8nN8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJ\n");
            fprintf(f, "QIDAQABo1AwTjAdBgNVHQ4EFgQUhBjMhTTsvAyUlC4IWZzHshBOCggwHwYDVR0j\n");
            fprintf(f, "BBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwDAYDVR0TBAUwAwEB/zANBgkqhkiG\n");
            fprintf(f, "9w0BAQUFAAOCAQEAAoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYT\n");
            fprintf(f, "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\n");
            fprintf(f, "aXRzIFB0eSBMdGQwHhcNMTMwODI3MjM1NDA3WhcNMTQwODI3MjM1NDA3WjBFMQsw\n");
            fprintf(f, "CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\n");
            fprintf(f, "ZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n");
            fprintf(f, "AQEAwJK/EPUBZkP8wLp8VnwHwB8CH75c8yNZ1r8kJNkJr8nN8yNZ1r8kJNkJr8nN\n");
            fprintf(f, "-----END CERTIFICATE-----\n");
            fclose(f);
            printf("✅ Test certificate created\n");
        }
    }
    
    // Test format detection
    cert_format_t format = cert_detect_format(test_file);
    printf("📋 Detected format: %s\n", 
           format == CERT_FORMAT_PEM ? "PEM" :
           format == CERT_FORMAT_DER ? "DER" :
           format == CERT_FORMAT_PKCS12 ? "PKCS12" : "UNKNOWN");
    
    // Test certificate loading
    X509* cert = cert_load_from_file(test_file, format);
    if (cert) {
        printf("✅ Certificate loaded successfully\n");
        
        // Extract some basic information
        char* subject = cert_get_subject_name(cert);
        char* issuer = cert_get_issuer_name(cert);
        char* serial = cert_get_serial_number(cert);
        char* fingerprint = cert_get_fingerprint_sha256(cert);
        
        printf("   Subject: %s\n", subject ? subject : "N/A");
        printf("   Issuer: %s\n", issuer ? issuer : "N/A");
        printf("   Serial: %s\n", serial ? serial : "N/A");
        printf("   SHA256: %s\n", fingerprint ? fingerprint : "N/A");
        
        // Check if self-signed
        bool self_signed = cert_is_self_signed(cert);
        printf("   Self-signed: %s\n", self_signed ? "Yes" : "No");
        
        // Check weakness
        weak_signature_flags_t weak_flags = cert_detect_weaknesses(cert);
        printf("   Weak signatures: MD5=%s, SHA1=%s, Weak RSA=%s\n",
               weak_flags.uses_md5 ? "Yes" : "No",
               weak_flags.uses_sha1 ? "Yes" : "No",
               weak_flags.weak_rsa_key ? "Yes" : "No");
        
        // Cleanup
        free(subject);
        free(issuer);
        free(serial);
        free(fingerprint);
        X509_free(cert);
    } else {
        printf("❌ Failed to load certificate\n");
        const char* error = cert_scanner_get_last_error();
        if (error) {
            printf("   Error: %s\n", error);
        }
    }
    
    // Test file scanning
    printf("\n🔍 Testing file scanning...\n");
    int scan_result = cert_scanner_scan_file(context, test_file);
    if (scan_result == 0) {
        printf("✅ File scan completed successfully\n");
    } else {
        printf("❌ File scan failed\n");
        const char* error = cert_scanner_get_last_error();
        if (error) {
            printf("   Error: %s\n", error);
        }
    }
    
    // Test directory scanning
    printf("\n📁 Testing directory scanning...\n");
    int dir_result = cert_scanner_scan_paths(context);
    printf("📊 Directory scan processed %d items\n", dir_result);
    
    // Get statistics
    cert_scanner_stats_t stats = cert_scanner_get_stats(context);
    printf("\n📈 Scanner Statistics:\n");
    printf("   Certificates found: %zu\n", stats.certificates_found);
    printf("   Certificates processed: %zu\n", stats.certificates_processed);
    printf("   Weak certificates: %zu\n", stats.weak_certificates);
    printf("   Expired certificates: %zu\n", stats.expired_certificates);
    
    // Check asset store
    asset_store_stats_t asset_stats = asset_store_get_stats(store);
    printf("\n🗄️  Asset Store Statistics:\n");
    printf("   Total assets: %zu\n", asset_stats.total_assets);
    printf("   Certificate assets: %zu\n", asset_stats.assets_by_type[ASSET_TYPE_CERTIFICATE]);
    printf("   Weak assets: %zu\n", asset_stats.weak_assets);
    
    // Test success criteria
    bool test_passed = true;
    
    if (stats.certificates_found == 0) {
        printf("⚠️  Warning: No certificates found\n");
    }
    
    if (asset_stats.total_assets == 0) {
        printf("❌ No assets were added to the store\n");
        test_passed = false;
    }
    
    // Cleanup
    cert_scanner_destroy(context);
    asset_store_destroy(store);
    
    // Cleanup configuration
    free(config.trust_store_path);
    if (config.scan_paths) {
        for (size_t i = 0; i < config.scan_path_count; i++) {
            free(config.scan_paths[i]);
        }
        free(config.scan_paths);
    }
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    printf("\n=== Test Result ===\n");
    if (test_passed) {
        printf("✅ Certificate scanner focused test PASSED!\n");
        return 0;
    } else {
        printf("❌ Certificate scanner focused test FAILED!\n");
        return 1;
    }
}
