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

#include "key_manager.h"
#include "secure_memory.h"
#include "asset_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <json-c/json.h>

// Structure to track unique keys
typedef struct key_entry {
    char *spki_hash;           // SHA-256 hash of SPKI
    char *key_id;              // Asset ID for the key component
    EVP_PKEY *public_key;      // The actual public key (for comparison)
    char *algorithm;           // Key algorithm (RSA, EC, etc.)
    int key_size;              // Key size in bits
    struct key_entry *next;    // Linked list
} key_entry_t;

// Global key registry
static key_entry_t *key_registry = NULL;
static size_t key_count = 0;

// Extract SPKI hash from X.509 certificate
static char* extract_spki_hash(X509 *cert) {
    if (!cert) return NULL;
    
    // Get the SubjectPublicKeyInfo
    X509_PUBKEY *pubkey_info = X509_get_X509_PUBKEY(cert);
    if (!pubkey_info) return NULL;
    
    // Encode the SPKI to DER format
    unsigned char *spki_der = NULL;
    int spki_len = i2d_X509_PUBKEY(pubkey_info, &spki_der);
    if (spki_len <= 0 || !spki_der) return NULL;
    
    // Calculate SHA-256 hash of the SPKI
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(spki_der, spki_len, hash);
    
    // Convert to hex string
    char *hash_str = secure_alloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (hash_str) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(hash_str + (i * 2), "%02x", hash[i]);
        }
        hash_str[SHA256_DIGEST_LENGTH * 2] = '\0';
    }
    
    OPENSSL_free(spki_der);
    return hash_str;
}

// Get key algorithm name from EVP_PKEY
static char* get_key_algorithm(EVP_PKEY *pkey) {
    if (!pkey) return NULL;
    
    int key_type = EVP_PKEY_base_id(pkey);
    const char *alg_name = NULL;
    
    switch (key_type) {
        case EVP_PKEY_RSA:
            alg_name = "RSA";
            break;
        case EVP_PKEY_EC:
            alg_name = "ECDSA";
            break;
        case EVP_PKEY_DSA:
            alg_name = "DSA";
            break;
        case EVP_PKEY_DH:
            alg_name = "DH";
            break;
        default:
            alg_name = "Unknown";
            break;
    }
    
    return strdup(alg_name);
}

// Get key size in bits
static int get_key_size(EVP_PKEY *pkey) {
    if (!pkey) return 0;
    return EVP_PKEY_bits(pkey);
}

// Find existing key entry by SPKI hash
static key_entry_t* find_key_entry(const char *spki_hash) {
    if (!spki_hash) return NULL;
    
    key_entry_t *entry = key_registry;
    while (entry) {
        if (entry->spki_hash && strcmp(entry->spki_hash, spki_hash) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

// Create a new key entry
static key_entry_t* create_key_entry(const char *spki_hash, EVP_PKEY *pkey) {
    if (!spki_hash || !pkey) return NULL;
    
    key_entry_t *entry = secure_alloc(sizeof(key_entry_t));
    if (!entry) return NULL;
    
    // Copy SPKI hash
    entry->spki_hash = strdup(spki_hash);
    
    // Generate key ID (use SPKI hash as ID)
    entry->key_id = strdup(spki_hash);
    
    // Reference the public key
    entry->public_key = pkey;
    EVP_PKEY_up_ref(pkey); // Increment reference count
    
    // Get algorithm and key size
    entry->algorithm = get_key_algorithm(pkey);
    entry->key_size = get_key_size(pkey);
    
    // Add to registry
    entry->next = key_registry;
    key_registry = entry;
    key_count++;
    
    return entry;
}

// Register a certificate's public key and return the key ID
char* key_manager_register_certificate_key(X509 *cert, asset_store_t *store) {
    if (!cert || !store) return NULL;
    
    // Extract SPKI hash
    char *spki_hash = extract_spki_hash(cert);
    if (!spki_hash) return NULL;
    
    // Check if key already exists
    key_entry_t *existing = find_key_entry(spki_hash);
    if (existing) {
        // Key already registered, return existing ID
        secure_free(spki_hash, strlen(spki_hash) + 1);
        
        // Return a copy of the key ID
        return strdup(existing->key_id);
    }
    
    // Extract public key from certificate
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        secure_free(spki_hash, strlen(spki_hash) + 1);
        return NULL;
    }
    
    // Create new key entry
    key_entry_t *entry = create_key_entry(spki_hash, pkey);
    if (!entry) {
        EVP_PKEY_free(pkey);
        secure_free(spki_hash, strlen(spki_hash) + 1);
        return NULL;
    }
    
    // Create KEY asset in the store
    crypto_asset_t *key_asset = crypto_asset_create(entry->key_id, ASSET_TYPE_KEY);
    if (key_asset) {
        // Set algorithm
        if (entry->algorithm) {
            key_asset->algorithm = strdup(entry->algorithm);
        }
        
        // Set key size
        key_asset->key_size = entry->key_size;
        
        // Create metadata JSON
        json_object *metadata = json_object_new_object();
        if (metadata) {
            json_object_object_add(metadata, "key_type", json_object_new_string("public_key"));
            json_object_object_add(metadata, "spki_hash", json_object_new_string(entry->spki_hash));
            
            if (entry->algorithm) {
                json_object_object_add(metadata, "algorithm", json_object_new_string(entry->algorithm));
            }
            
            json_object_object_add(metadata, "key_size_bits", json_object_new_int(entry->key_size));
            
            // Determine if key is weak
            bool is_weak = false;
            if (entry->algorithm && strcmp(entry->algorithm, "RSA") == 0 && entry->key_size < 2048) {
                is_weak = true;
            } else if (entry->algorithm && strcmp(entry->algorithm, "ECDSA") == 0 && entry->key_size < 256) {
                is_weak = true;
            }
            json_object_object_add(metadata, "is_weak", json_object_new_boolean(is_weak));
            key_asset->is_weak = is_weak;
            
            const char *metadata_str = json_object_to_json_string(metadata);
            if (metadata_str) {
                key_asset->metadata_json = strdup(metadata_str);
            }
            
            json_object_put(metadata);
        }
        
        // Add to asset store
        asset_store_add(store, key_asset);
    }
    
    EVP_PKEY_free(pkey);
    
    // Return a copy of the key ID
    char *key_id_copy = strdup(entry->key_id);
    secure_free(spki_hash, strlen(spki_hash) + 1);
    return key_id_copy;
}

// Get statistics about registered keys
key_manager_stats_t key_manager_get_stats(void) {
    key_manager_stats_t stats = {0};
    
    key_entry_t *entry = key_registry;
    while (entry) {
        stats.total_keys++;
        stats.unique_keys++;
        
        if (entry->algorithm) {
            if (strcmp(entry->algorithm, "RSA") == 0) {
                stats.rsa_keys++;
                if (entry->key_size < 2048) {
                    stats.weak_keys++;
                }
            } else if (strcmp(entry->algorithm, "ECDSA") == 0) {
                stats.ec_keys++;
                if (entry->key_size < 256) {
                    stats.weak_keys++;
                }
            } else {
                stats.other_keys++;
            }
        }
        
        entry = entry->next;
    }
    
    return stats;
}

// Issue #4: File caching for performance

// Cache for loaded private keys
typedef struct {
    char *filepath;
    EVP_PKEY *pkey;
} key_cache_entry_t;

static key_cache_entry_t *key_cache = NULL;
static size_t key_cache_size = 0;
static size_t key_cache_capacity = 0;

// Cache for loaded certificates
typedef struct {
    char *filepath;
    X509 *cert;
} cert_cache_entry_t;

static cert_cache_entry_t *cert_cache = NULL;
static size_t cert_cache_size = 0;
static size_t cert_cache_capacity = 0;

// Initialize caches
static void init_matching_caches() {
    key_cache_capacity = 500;
    key_cache = calloc(key_cache_capacity, sizeof(key_cache_entry_t));
    key_cache_size = 0;

    cert_cache_capacity = 1000;
    cert_cache = calloc(cert_cache_capacity, sizeof(cert_cache_entry_t));
    cert_cache_size = 0;
}

// Cleanup caches
static void cleanup_matching_caches() {
    if (key_cache) {
        for (size_t i = 0; i < key_cache_size; i++) {
            if (key_cache[i].filepath) free(key_cache[i].filepath);
            if (key_cache[i].pkey) EVP_PKEY_free(key_cache[i].pkey);
        }
        free(key_cache);
        key_cache = NULL;
        key_cache_size = 0;
    }

    if (cert_cache) {
        for (size_t i = 0; i < cert_cache_size; i++) {
            if (cert_cache[i].filepath) free(cert_cache[i].filepath);
            if (cert_cache[i].cert) X509_free(cert_cache[i].cert);
        }
        free(cert_cache);
        cert_cache = NULL;
        cert_cache_size = 0;
    }
}

// Issue #4: Helper functions for file-based key matching

// Password callback that returns empty password (prevents stdin prompts)
static int no_password_callback(char *buf, int size, int rwflag, void *userdata) {
    (void)buf; (void)size; (void)rwflag; (void)userdata;
    return 0;  // Return 0 = no password provided, causes decrypt to fail silently
}

// Load private key from file for matching purposes (no cache)
static EVP_PKEY *load_private_key_for_matching(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return NULL;

    // Use no_password_callback to prevent stdin prompts for encrypted keys
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, no_password_callback, NULL);
    fclose(fp);

    return pkey;
}

// Get or load private key with caching
static EVP_PKEY *get_cached_private_key(const char *filepath) {
    // Check cache first
    for (size_t i = 0; i < key_cache_size; i++) {
        if (strcmp(key_cache[i].filepath, filepath) == 0) {
            return key_cache[i].pkey;  // Cache hit!
        }
    }

    // Load from file
    EVP_PKEY *pkey = load_private_key_for_matching(filepath);

    // Add to cache if space available
    if (pkey && key_cache_size < key_cache_capacity) {
        key_cache[key_cache_size].filepath = strdup(filepath);
        key_cache[key_cache_size].pkey = pkey;
        key_cache_size++;
    }

    return pkey;
}

// Load certificate from file for matching purposes (no cache)
static X509 *load_certificate_for_matching(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return NULL;

    BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);
    fclose(fp);

    return cert;
}

// Get or load certificate with caching
static X509 *get_cached_certificate(const char *filepath) {
    // Check cache first
    for (size_t i = 0; i < cert_cache_size; i++) {
        if (strcmp(cert_cache[i].filepath, filepath) == 0) {
            return cert_cache[i].cert;  // Cache hit!
        }
    }

    // Load from file
    X509 *cert = load_certificate_for_matching(filepath);

    // Add to cache if space available
    if (cert && cert_cache_size < cert_cache_capacity) {
        cert_cache[cert_cache_size].filepath = strdup(filepath);
        cert_cache[cert_cache_size].cert = cert;
        cert_cache_size++;
    }

    return cert;
}

// Compare two public keys for equality
static bool public_keys_equal(EVP_PKEY *key1, EVP_PKEY *key2) {
    if (!key1 || !key2) return false;

    // Use OpenSSL 3.0+ key comparison function
    return EVP_PKEY_eq(key1, key2) == 1;
}

// Check if private key file matches certificate file (with caching)
static bool private_key_matches_certificate(const char *key_path, const char *cert_path) {
    EVP_PKEY *priv_key = get_cached_private_key(key_path);
    if (!priv_key) return false;

    X509 *cert = get_cached_certificate(cert_path);
    if (!cert) return false;

    EVP_PKEY *cert_pubkey = X509_get_pubkey(cert);
    if (!cert_pubkey) return false;

    bool match = public_keys_equal(priv_key, cert_pubkey);

    EVP_PKEY_free(cert_pubkey);
    // Don't free priv_key or cert - they're cached!

    return match;
}

// Issue #4: Match private keys to their certificates using SPKI hash
// Creates RELATIONSHIP_SIGNS relationships for cryptographic matches
int key_manager_match_keys_to_certificates(asset_store_t *store) {
    if (!store) return 0;

    int matches_created = 0;

    // Initialize caching for performance
    init_matching_caches();

    // Get all assets from store (sorted for determinism)
    size_t asset_count = 0;
    crypto_asset_t **assets = asset_store_get_sorted(store, NULL, &asset_count);
    if (!assets) {
        cleanup_matching_caches();
        return 0;
    }

    // Debug counters
    int total_keys = 0, keys_with_location = 0, private_key_files = 0;
    int match_attempts = 0;

    // Iterate through all key assets
    for (size_t i = 0; i < asset_count; i++) {
        crypto_asset_t *key_asset = assets[i];
        if (!key_asset || key_asset->type != ASSET_TYPE_KEY) continue;

        total_keys++;
        if (key_asset->location) keys_with_location++;

        bool matched = false;

        // Method 1: Quick match via key_id (for keys extracted from certificates)
        for (size_t j = 0; j < asset_count; j++) {
            crypto_asset_t *cert_asset = assets[j];
            if (!cert_asset || cert_asset->type != ASSET_TYPE_CERTIFICATE) continue;

            // Check if certificate's key_id matches our key's id
            if (cert_asset->key_id && strcmp(cert_asset->key_id, key_asset->id) == 0) {
                // Create SIGNS relationship (key signs certificate)
                relationship_t *rel = relationship_create(
                    RELATIONSHIP_SIGNS,
                    key_asset->id,      // source: private key
                    cert_asset->id,     // target: certificate
                    1.0                 // confidence: cryptographic match = definite
                );

                if (rel && asset_store_add_relationship(store, rel) == 0) {
                    matches_created++;
                    matched = true;
                }
            }
        }

        // Method 2: File-based cryptographic matching (for separate private key files)
        // Only try if not already matched and key has a file location
        if (!matched && key_asset->location && strlen(key_asset->location) > 0) {
            // Check if this looks like a private key file (not extracted from cert)
            if (strstr(key_asset->location, "/keys/") ||
                strstr(key_asset->location, "_key-") ||
                strstr(key_asset->location, "privkey")) {

                private_key_files++;

                for (size_t j = 0; j < asset_count; j++) {
                    crypto_asset_t *cert_asset = assets[j];
                    if (!cert_asset || cert_asset->type != ASSET_TYPE_CERTIFICATE) continue;
                    if (!cert_asset->location) continue;

                    // Skip non-matchable certificate types
                    if (strstr(cert_asset->location, "/csr/") ||           // Certificate Signing Requests
                        strstr(cert_asset->location, "privkey") ||         // Private key files
                        strstr(cert_asset->location, "_key-") ||           // Key files
                        strstr(cert_asset->location, "/keys/") ||          // Keys directory
                        strstr(cert_asset->location, "ca-certificates.crt")) {  // Bundles
                        continue;
                    }

                    match_attempts++;

                    // Try cryptographic match
                    if (private_key_matches_certificate(key_asset->location, cert_asset->location)) {
                        relationship_t *rel = relationship_create(
                            RELATIONSHIP_SIGNS,
                            key_asset->id,
                            cert_asset->id,
                            1.0  // Cryptographic match is definite
                        );

                        if (rel && asset_store_add_relationship(store, rel) == 0) {
                            matches_created++;
                            matched = true;
                            fprintf(stderr, "[INFO] MATCH: Key %s → Cert %s\n",
                                   key_asset->name, cert_asset->name);
                            break; // Found match for this key, move to next key
                        }
                    }
                }
            }
        }
    }

    cleanup_matching_caches();
    return matches_created;
}

// Issue #4: Build certificate chains by matching issuer/subject DNs
// Creates RELATIONSHIP_ISSUED_BY relationships for certificate hierarchies
int key_manager_build_certificate_chains(asset_store_t *store) {
    if (!store) return 0;

    int chains_created = 0;

    // Get all assets from store (sorted for determinism)
    size_t asset_count = 0;
    crypto_asset_t **assets = asset_store_get_sorted(store, NULL, &asset_count);
    if (!assets) return 0;

    // Iterate through all certificate assets
    for (size_t i = 0; i < asset_count; i++) {
        crypto_asset_t *cert = assets[i];
        if (!cert || cert->type != ASSET_TYPE_CERTIFICATE) continue;

        // Parse metadata JSON to get DNs
        if (!cert->metadata_json) continue;

        json_object *metadata = json_tokener_parse(cert->metadata_json);
        if (!metadata) continue;

        json_object *issuer_obj = json_object_object_get(metadata, "issuer_rfc2253");
        json_object *subject_obj = json_object_object_get(metadata, "subject_rfc2253");

        if (!issuer_obj || !subject_obj) {
            json_object_put(metadata);
            continue;
        }

        const char *issuer_dn = json_object_get_string(issuer_obj);
        const char *subject_dn = json_object_get_string(subject_obj);

        // Skip self-signed certificates (issuer == subject)
        if (strcmp(issuer_dn, subject_dn) == 0) {
            json_object_put(metadata);
            continue;
        }

        // Find parent certificate (its subject DN matches our issuer DN)
        for (size_t j = 0; j < asset_count; j++) {
            if (i == j) continue;

            crypto_asset_t *parent_cert = assets[j];
            if (!parent_cert || parent_cert->type != ASSET_TYPE_CERTIFICATE) continue;
            if (!parent_cert->metadata_json) continue;

            json_object *parent_metadata = json_tokener_parse(parent_cert->metadata_json);
            if (!parent_metadata) continue;

            json_object *parent_subject_obj = json_object_object_get(parent_metadata, "subject_rfc2253");
            if (!parent_subject_obj) {
                json_object_put(parent_metadata);
                continue;
            }

            const char *parent_subject = json_object_get_string(parent_subject_obj);

            // Check if parent's subject matches our issuer
            if (strcmp(parent_subject, issuer_dn) == 0) {
                // Create ISSUED_BY relationship (cert issued by parent CA)
                relationship_t *rel = relationship_create(
                    RELATIONSHIP_ISSUED_BY,
                    cert->id,           // source: child certificate
                    parent_cert->id,    // target: parent CA certificate
                    1.0                 // confidence: DN match = definite
                );

                if (rel && asset_store_add_relationship(store, rel) == 0) {
                    chains_created++;
                }

                json_object_put(parent_metadata);
                break; // One issuer per certificate
            }

            json_object_put(parent_metadata);
        }

        json_object_put(metadata);
    }

    return chains_created;
}

// Cleanup key manager resources
void key_manager_cleanup(void) {
    key_entry_t *entry = key_registry;
    while (entry) {
        key_entry_t *next = entry->next;

        if (entry->spki_hash) free(entry->spki_hash);
        if (entry->key_id) free(entry->key_id);
        if (entry->algorithm) free(entry->algorithm);
        if (entry->public_key) EVP_PKEY_free(entry->public_key);

        secure_free(entry, sizeof(key_entry_t));
        entry = next;
    }

    key_registry = NULL;
    key_count = 0;
}
