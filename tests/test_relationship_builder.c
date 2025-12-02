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
#include "asset_store.h"
#include "key_manager.h"
#include "cbom_types.h"

// Test helper: Create a test key asset
static crypto_asset_t* create_test_key(const char *id, const char *name) {
    crypto_asset_t *key = crypto_asset_create(name, ASSET_TYPE_KEY);
    if (!key) return NULL;

    // Override ID
    if (key->id) free(key->id);
    key->id = strdup(id);

    // Set metadata with SPKI hash
    char metadata[256];
    snprintf(metadata, sizeof(metadata),
             "{\"spki_hash\":\"%s\",\"key_type\":\"private_key\"}", id);
    key->metadata_json = strdup(metadata);

    return key;
}

// Test helper: Create a test certificate asset
static crypto_asset_t* create_test_cert(const char *id, const char *name,
                                       const char *key_id,
                                       const char *issuer_dn,
                                       const char *subject_dn) {
    crypto_asset_t *cert = crypto_asset_create(name, ASSET_TYPE_CERTIFICATE);
    if (!cert) return NULL;

    // Override ID
    if (cert->id) free(cert->id);
    cert->id = strdup(id);

    // Link to key if provided
    if (key_id) {
        cert->key_id = strdup(key_id);
    }

    // Set metadata with DNs
    char metadata[512];
    snprintf(metadata, sizeof(metadata),
             "{\"subject_rfc2253\":\"%s\",\"issuer_rfc2253\":\"%s\",\"self_signed\":%s}",
             subject_dn, issuer_dn,
             strcmp(subject_dn, issuer_dn) == 0 ? "true" : "false");
    cert->metadata_json = strdup(metadata);

    return cert;
}

// Test 1: Key-Certificate Matching
void test_key_cert_matching_basic() {
    printf("Test 1: Key-Certificate Matching (Basic)...\n");

    asset_store_t *store = asset_store_create(16);
    assert(store != NULL);

    // Create a key
    crypto_asset_t *key1 = create_test_key("key-001", "Test Private Key");
    assert(key1 != NULL);
    asset_store_add(store, key1);

    // Create a certificate linked to that key
    crypto_asset_t *cert1 = create_test_cert("cert-001", "Test Certificate",
                                             "key-001", // key_id
                                             "CN=CA",    // issuer
                                             "CN=Test"); // subject
    assert(cert1 != NULL);
    asset_store_add(store, cert1);

    // Run matching
    int matches = key_manager_match_keys_to_certificates(store);

    printf("  Created %d SIGNS relationships\n", matches);
    assert(matches == 1);

    // Verify relationship exists
    size_t rel_count = 0;
    relationship_t **rels = asset_store_get_relationships(store, &rel_count);
    assert(rels != NULL);
    assert(rel_count >= 1);

    bool found_signs = false;
    for (size_t i = 0; i < rel_count; i++) {
        if (rels[i]->type == RELATIONSHIP_SIGNS) {
            assert(strcmp(rels[i]->source_asset_id, "key-001") == 0);
            assert(strcmp(rels[i]->target_asset_id, "cert-001") == 0);
            assert(rels[i]->confidence == 1.0f);
            found_signs = true;
            break;
        }
    }

    assert(found_signs);
    printf("  ✓ PASS: SIGNS relationship created correctly\n");

    asset_store_destroy(store);
}

// Test 2: Certificate Chain Building
void test_cert_chain_building() {
    printf("Test 2: Certificate Chain Building...\n");

    asset_store_t *store = asset_store_create(16);
    assert(store != NULL);

    // Create root CA (self-signed)
    crypto_asset_t *root = create_test_cert("cert-root", "Root CA",
                                            NULL,
                                            "CN=Root CA",  // issuer
                                            "CN=Root CA"); // subject (same = self-signed)
    asset_store_add(store, root);

    // Create intermediate CA (issued by root)
    crypto_asset_t *intermediate = create_test_cert("cert-intermediate", "Intermediate CA",
                                                    NULL,
                                                    "CN=Root CA",          // issuer
                                                    "CN=Intermediate CA"); // subject
    asset_store_add(store, intermediate);

    // Create leaf certificate (issued by intermediate)
    crypto_asset_t *leaf = create_test_cert("cert-leaf", "Leaf Certificate",
                                            NULL,
                                            "CN=Intermediate CA", // issuer
                                            "CN=example.com");    // subject
    asset_store_add(store, leaf);

    // Build chains
    int chains = key_manager_build_certificate_chains(store);

    printf("  Created %d ISSUED_BY relationships\n", chains);
    assert(chains == 2); // leaf→intermediate, intermediate→root

    // Verify relationships
    size_t rel_count = 0;
    relationship_t **rels = asset_store_get_relationships(store, &rel_count);
    assert(rels != NULL);
    assert(rel_count >= 2);

    int issued_by_count = 0;
    for (size_t i = 0; i < rel_count; i++) {
        if (rels[i]->type == RELATIONSHIP_ISSUED_BY) {
            issued_by_count++;
            assert(rels[i]->confidence == 1.0f);
        }
    }

    assert(issued_by_count == 2);
    printf("  ✓ PASS: Certificate chains built correctly\n");

    asset_store_destroy(store);
}

// Test 3: No Relationships for Self-Signed
void test_self_signed_no_chain() {
    printf("Test 3: Self-Signed Certificates (No Chain)...\n");

    asset_store_t *store = asset_store_create(16);

    // Create self-signed certificate
    crypto_asset_t *cert = create_test_cert("cert-selfsigned", "Self-Signed",
                                            NULL,
                                            "CN=Self",  // issuer
                                            "CN=Self"); // subject (same)
    asset_store_add(store, cert);

    // Try to build chains
    int chains = key_manager_build_certificate_chains(store);

    printf("  Created %d ISSUED_BY relationships\n", chains);
    assert(chains == 0); // Self-signed should not create chain

    printf("  ✓ PASS: Self-signed certificates correctly skipped\n");

    asset_store_destroy(store);
}

// Test 4: Multiple Keys to Multiple Certs
void test_multiple_key_cert_matches() {
    printf("Test 4: Multiple Key-Certificate Matches...\n");

    asset_store_t *store = asset_store_create(16);

    // Create 3 key-cert pairs
    for (int i = 1; i <= 3; i++) {
        char key_id[32], cert_id[32];
        char key_name[64], cert_name[64];

        snprintf(key_id, sizeof(key_id), "key-%03d", i);
        snprintf(cert_id, sizeof(cert_id), "cert-%03d", i);
        snprintf(key_name, sizeof(key_name), "Key %d", i);
        snprintf(cert_name, sizeof(cert_name), "Cert %d", i);

        crypto_asset_t *key = create_test_key(key_id, key_name);
        crypto_asset_t *cert = create_test_cert(cert_id, cert_name,
                                                key_id, "CN=CA", "CN=Test");

        asset_store_add(store, key);
        asset_store_add(store, cert);
    }

    // Match all
    int matches = key_manager_match_keys_to_certificates(store);

    printf("  Created %d SIGNS relationships\n", matches);
    assert(matches == 3);

    printf("  ✓ PASS: Multiple key-cert pairs matched correctly\n");

    asset_store_destroy(store);
}

int main() {
    printf("\n====== Relationship Builder Tests ======\n\n");

    test_key_cert_matching_basic();
    test_cert_chain_building();
    test_self_signed_no_chain();
    test_multiple_key_cert_matches();

    printf("\n====== All Tests PASSED ======\n\n");

    return 0;
}
