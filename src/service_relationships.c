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

#include "asset_store.h"
#include "cbom_types.h"
#include "algorithm_metadata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <json-c/json.h>

// Forward declaration
const char* find_cert_id_by_path(asset_store_t* store, const char* cert_path);

// Create SERVICE → PROTOCOL relationship
int create_service_protocol_relationship(asset_store_t* store,
                                        const char* service_id,
                                        const char* protocol_id,
                                        float confidence) {
    if (!store || !service_id || !protocol_id) return -1;

    relationship_t* rel = relationship_create(RELATIONSHIP_USES,
                                             service_id,
                                             protocol_id,
                                             confidence);
    if (!rel) return -1;

    int result = asset_store_add_relationship(store, rel);
    if (result != 0) {
        relationship_destroy(rel);
    }

    return result;
}

// Create PROTOCOL → CIPHER_SUITE relationship
int create_protocol_suite_relationship(asset_store_t* store,
                                      const char* protocol_id,
                                      const char* suite_id,
                                      float confidence) {
    if (!store || !protocol_id || !suite_id) return -1;

    relationship_t* rel = relationship_create(RELATIONSHIP_PROVIDES,
                                             protocol_id,
                                             suite_id,
                                             confidence);
    if (!rel) return -1;

    int result = asset_store_add_relationship(store, rel);
    if (result != 0) {
        relationship_destroy(rel);
    }

    return result;
}

// Create SERVICE → CERTIFICATE relationship
int create_service_cert_relationship(asset_store_t* store,
                                     const char* service_id,
                                     const char* cert_id,
                                     float confidence) {
    if (!store || !service_id || !cert_id) return -1;

    relationship_t* rel = relationship_create(RELATIONSHIP_AUTHENTICATES_WITH,
                                             service_id,
                                             cert_id,
                                             confidence);
    if (!rel) return -1;

    int result = asset_store_add_relationship(store, rel);
    if (result != 0) {
        relationship_destroy(rel);
    }

    return result;
}

// Create CIPHER_SUITE → ALGORITHM relationship
int create_suite_algorithm_relationship(asset_store_t* store,
                                       const char* suite_id,
                                       const char* algorithm_id,
                                       float confidence) {
    if (!store || !suite_id || !algorithm_id) return -1;

    relationship_t* rel = relationship_create(RELATIONSHIP_USES,
                                             suite_id,
                                             algorithm_id,
                                             confidence);
    if (!rel) return -1;

    int result = asset_store_add_relationship(store, rel);
    if (result != 0) {
        relationship_destroy(rel);
    }

    return result;
}

// Issue #3: Build service-certificate relationships after all scanners complete
// This must run AFTER cert scanner finishes to ensure all certs are in asset store
int build_service_cert_relationships(asset_store_t* store) {
    if (!store) return 0;

    int relationships_created = 0;

    // Get all assets
    size_t count = 0;
    crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &count);
    if (!assets) return 0;

    // Debug: Show asset store stats
    int service_count = 0, cert_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (assets[i]->type == ASSET_TYPE_SERVICE) service_count++;
        if (assets[i]->type == ASSET_TYPE_CERTIFICATE) cert_count++;
    }

    // Find all service assets and create cert relationships
    for (size_t i = 0; i < count; i++) {
        if (assets[i]->type != ASSET_TYPE_SERVICE) continue;

        // Parse service metadata to get cert path
        if (!assets[i]->metadata_json) continue;

        json_object *metadata = json_tokener_parse(assets[i]->metadata_json);
        if (!metadata) continue;

        // Look for SSL cert path in metadata
        json_object *ssl_cert_obj = json_object_object_get(metadata, "ssl_cert_path");
        if (ssl_cert_obj) {
            const char *cert_path = json_object_get_string(ssl_cert_obj);
            if (cert_path) {
                const char *cert_id = find_cert_id_by_path(store, cert_path);
                if (cert_id) {
                    int result = create_service_cert_relationship(store,
                                                                 assets[i]->id,
                                                                 cert_id,
                                                                 0.90);
                    if (result == 0) {
                        relationships_created++;
                        fprintf(stderr, "[INFO Issue #3] Created service→cert relationship: %s → %s\n",
                               assets[i]->name, cert_path);
                    }
                }
            }
        }

        json_object_put(metadata);
    }

    free(assets);
    return relationships_created;
}

// Helper: Find certificate asset by file path
const char* find_cert_id_by_path(asset_store_t* store, const char* cert_path) {
    if (!store || !cert_path) return NULL;

    // Canonicalize cert_path to absolute path (Issue #3 regression fix)
    char canonical_cert_path[PATH_MAX];
    char* resolved = realpath(cert_path, canonical_cert_path);
    const char* search_path = resolved ? canonical_cert_path : cert_path;

    // Iterate through assets to find matching certificate
    size_t count;
    crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &count);
    if (!assets) return NULL;

    int certs_checked = 0;

    const char* result = NULL;
    for (size_t i = 0; i < count; i++) {
        if (assets[i]->type == ASSET_TYPE_CERTIFICATE) {
            certs_checked++;

            // Method 1: Direct path comparison (with canonicalization)
            if (assets[i]->location) {
                char canonical_asset_path[PATH_MAX];
                char* resolved_asset = realpath(assets[i]->location, canonical_asset_path);
                const char* asset_path = resolved_asset ? canonical_asset_path : assets[i]->location;

                if (strcmp(asset_path, search_path) == 0) {
                    result = assets[i]->id;
                    break;
                }
            }
        }
    }

    // Method 2: Subject DN matching (Issue #3 - simple and works)
    // Match by loading cert and comparing subject DN (asset->name = subject)
    if (!result) {

        FILE *fp = fopen(cert_path, "r");
        if (fp) {
            BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);
            if (bio) {
                X509 *search_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                if (search_cert) {
                    // Use EXACT SAME format as cert scanner (XN_FLAG_ONELINE)
                    X509_NAME *subject = X509_get_subject_name(search_cert);
                    BIO *subject_bio = BIO_new(BIO_s_mem());
                    X509_NAME_print_ex(subject_bio, subject, 0, XN_FLAG_ONELINE);

                    char *subject_str = NULL;
                    long subject_len = BIO_get_mem_data(subject_bio, &subject_str);
                    char subject_copy[512];
                    if (subject_len > 0 && subject_len < 512) {
                        memcpy(subject_copy, subject_str, subject_len);
                        subject_copy[subject_len] = '\0';
                    } else {
                        subject_copy[0] = '\0';
                    }
                    BIO_free(subject_bio);

                    // Find asset with matching name
                    for (size_t i = 0; i < count; i++) {
                        if (assets[i]->type == ASSET_TYPE_CERTIFICATE && assets[i]->name) {
                            // Skip assets where name is a file path (CSRs/keys misclassified as certs)
                            if (strchr(assets[i]->name, '/') != NULL) {
                                continue;  // Name contains '/' - it's a filepath, not a subject DN
                            }

                            if (strcmp(assets[i]->name, subject_copy) == 0) {
                                result = assets[i]->id;
                                break;
                            }
                        }
                    }

                    X509_free(search_cert);
                }
                BIO_free(bio);
            }
            fclose(fp);
        }
    }

    free(assets);
    return result;
}

// Helper: Create algorithm asset from name and key size
crypto_asset_t* create_algorithm_asset_from_components(const char* algorithm_name, int key_size) {
    if (!algorithm_name) return NULL;

    crypto_asset_t* asset = crypto_asset_create(algorithm_name, ASSET_TYPE_ALGORITHM);
    if (!asset) return NULL;

    // Set algorithm properties
    if (asset->algorithm) free(asset->algorithm);
    asset->algorithm = strdup(algorithm_name);
    asset->key_size = key_size;

    // Generate content-addressed ID using SHA-256
    char id_string[256];
    snprintf(id_string, sizeof(id_string), "algorithm|%s|%d",
            algorithm_name, key_size);

    // Use OpenSSL SHA-256 for proper hashing
    unsigned char hash[32];
    SHA256((unsigned char*)id_string, strlen(id_string), hash);

    char* sha256_id = malloc(64 + 1);
    if (sha256_id) {
        for (int i = 0; i < 32; i++) {
            sprintf(sha256_id + i * 2, "%02x", hash[i]);
        }
        free(asset->id);
        asset->id = sha256_id;
    }

    // Populate metadata_json with CycloneDX algorithmProperties
    // Use CIPHER_SUITE context since this function is called from cipher suite decomposition
    char* metadata = algorithm_populate_cdx_metadata(
        asset->metadata_json,
        algorithm_name,
        ALGO_CONTEXT_CIPHER_SUITE
    );
    if (metadata) {
        if (asset->metadata_json) free(asset->metadata_json);
        asset->metadata_json = metadata;
    }

    return asset;
}

// v1.9.2: Get existing algorithm or create new one (prevents duplicates)
// Uses canonical ID generation consistent with create_algorithm_asset_from_components
crypto_asset_t* get_or_create_algorithm_asset(asset_store_t* store,
                                              const char* algorithm_name,
                                              int key_size) {
    if (!store || !algorithm_name) return NULL;

    // Generate canonical ID (same formula as create_algorithm_asset_from_components)
    char id_string[256];
    snprintf(id_string, sizeof(id_string), "algorithm|%s|%d", algorithm_name, key_size);

    // Compute SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)id_string, strlen(id_string), hash);

    char canonical_id[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(canonical_id + i * 2, "%02x", hash[i]);
    }

    // Check if algorithm already exists in the store
    crypto_asset_t* existing = asset_store_find(store, canonical_id);
    if (existing) {
        return existing;  // Return existing, don't create duplicate
    }

    // Create new algorithm asset with canonical ID
    crypto_asset_t* asset = create_algorithm_asset_from_components(algorithm_name, key_size);
    if (asset) {
        asset_store_add(store, asset);
    }

    return asset;
}

// Decompose cipher suite and create SUITE→ALGORITHM relationships
// v1.9.2: Uses get_or_create_algorithm_asset to prevent duplicate algorithms
int decompose_cipher_suite_to_algorithms(asset_store_t* store,
                                         const char* suite_id,
                                         const char* kex,
                                         const char* auth,
                                         const char* enc,
                                         const char* mac) {
    if (!store || !suite_id) return -1;

    int relationships_created = 0;

    // Create KEX algorithm asset and relationship
    if (kex && strlen(kex) > 0) {
        crypto_asset_t* kex_asset = get_or_create_algorithm_asset(store, kex, 0);
        if (kex_asset) {
            create_suite_algorithm_relationship(store, suite_id, kex_asset->id, 0.95);
            relationships_created++;
        }
    }

    // Create auth algorithm asset and relationship (avoid duplicate if same as KEX)
    if (auth && strlen(auth) > 0 && (!kex || strcmp(auth, kex) != 0)) {
        crypto_asset_t* auth_asset = get_or_create_algorithm_asset(store, auth, 0);
        if (auth_asset) {
            create_suite_algorithm_relationship(store, suite_id, auth_asset->id, 0.95);
            relationships_created++;
        }
    }

    // Create encryption algorithm asset and relationship
    if (enc && strlen(enc) > 0) {
        // Extract key size from encryption algorithm name (e.g., "AES-256-GCM" → 256)
        int enc_key_size = 256;  // Default
        if (strstr(enc, "128")) enc_key_size = 128;
        else if (strstr(enc, "192")) enc_key_size = 192;
        else if (strstr(enc, "256")) enc_key_size = 256;

        crypto_asset_t* enc_asset = get_or_create_algorithm_asset(store, enc, enc_key_size);
        if (enc_asset) {
            create_suite_algorithm_relationship(store, suite_id, enc_asset->id, 0.95);
            relationships_created++;
        }
    }

    // Create MAC algorithm asset and relationship (avoid duplicate if same as enc)
    if (mac && strlen(mac) > 0 && (!enc || strstr(enc, mac) == NULL)) {
        crypto_asset_t* mac_asset = get_or_create_algorithm_asset(store, mac, 0);
        if (mac_asset) {
            create_suite_algorithm_relationship(store, suite_id, mac_asset->id, 0.95);
            relationships_created++;
        }
    }

    return relationships_created;
}

// Create SERVICE → LIBRARY relationship (Application Library Dependencies Gap)
int create_service_library_relationship(asset_store_t* store,
                                        const char* service_id,
                                        const char* library_id,
                                        float confidence) {
    if (!store || !service_id || !library_id) return -1;

    // Use RELATIONSHIP_DEPENDS_ON for service→library
    relationship_t* rel = relationship_create(RELATIONSHIP_DEPENDS_ON,
                                             service_id,
                                             library_id,
                                             confidence);
    if (!rel) return -1;

    int result = asset_store_add_relationship(store, rel);
    if (result != 0) {
        relationship_destroy(rel);
    }

    return result;
}
