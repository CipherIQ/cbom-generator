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
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <json-c/json.h>

#define DEFAULT_BUCKET_COUNT 1024
#define LOAD_FACTOR_THRESHOLD 0.75

// Forward declaration for internal SONAME registry function (v1.8)
static int asset_store_register_soname_internal(asset_store_t* store,
                                                 const char* soname,
                                                 const char* bom_ref);

// Hash function for asset IDs
static uint32_t hash_string(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

asset_store_t* asset_store_create(size_t initial_bucket_count) {
    if (initial_bucket_count == 0) {
        initial_bucket_count = DEFAULT_BUCKET_COUNT;
    }
    
    asset_store_t *store = malloc(sizeof(asset_store_t));
    if (store == NULL) {
        return NULL;
    }
    
    store->buckets = calloc(initial_bucket_count, sizeof(crypto_asset_t*));
    if (store->buckets == NULL) {
        free(store);
        return NULL;
    }
    
    store->bucket_count = initial_bucket_count;
    store->asset_count = 0;
    store->deterministic_mode = true; // Default to deterministic

    // Initialize relationships (Phase 7.3a)
    store->relationships = NULL;
    store->relationship_count = 0;
    store->relationship_capacity = 0;

    // Initialize SONAME registry (v1.8)
    store->soname_map = NULL;
    store->soname_map_count = 0;
    store->soname_map_capacity = 0;

    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store->buckets);
        free(store);
        return NULL;
    }

    return store;
}

void asset_store_destroy(asset_store_t *store) {
    if (store == NULL) {
        return;
    }
    
    pthread_mutex_lock(&store->mutex);
    
    // Free all assets
    for (size_t i = 0; i < store->bucket_count; i++) {
        crypto_asset_t *current = store->buckets[i];
        while (current != NULL) {
            crypto_asset_t *next = current->next;
            crypto_asset_destroy(current);
            current = next;
        }
    }

    // Free all relationships (Phase 7.3a)
    if (store->relationships) {
        for (size_t i = 0; i < store->relationship_count; i++) {
            relationship_destroy(store->relationships[i]);
        }
        free(store->relationships);
    }

    // Free SONAME registry (v1.8)
    if (store->soname_map) {
        for (size_t i = 0; i < store->soname_map_count; i++) {
            free(store->soname_map[i].soname);
            free(store->soname_map[i].bom_ref);
        }
        free(store->soname_map);
    }

    free(store->buckets);
    pthread_mutex_unlock(&store->mutex);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

crypto_asset_t* crypto_asset_create(const char *name, asset_type_t type) {
    if (name == NULL) {
        return NULL;
    }
    
    crypto_asset_t *asset = malloc(sizeof(crypto_asset_t));
    if (asset == NULL) {
        return NULL;
    }
    
    memset(asset, 0, sizeof(crypto_asset_t));
    
    asset->name = strdup(name);
    if (asset->name == NULL) {
        free(asset);
        return NULL;
    }
    
    asset->type = type;
    asset->is_weak = false;
    asset->is_pqc_ready = false;
    asset->key_size = 0;
    asset->next = NULL;
    
    // Generate content-addressed ID
    asset->id = generate_asset_id(asset);
    if (asset->id == NULL) {
        free(asset->name);
        free(asset);
        return NULL;
    }
    
    return asset;
}

void crypto_asset_destroy(crypto_asset_t *asset) {
    if (asset == NULL) {
        return;
    }
    
    // Free the ID (allocated with malloc)
    if (asset->id) {
        free(asset->id);
    }
    if (asset->name) {
        free(asset->name);
    }
    if (asset->version) {
        free(asset->version);
    }
    if (asset->location) {
        free(asset->location);
    }
    if (asset->algorithm) {
        free(asset->algorithm);
    }
    if (asset->hash_algorithm) {
        free(asset->hash_algorithm);
    }
    if (asset->metadata_json) {
        free(asset->metadata_json);
    }
    if (asset->key_id) {
        free(asset->key_id);
    }
    
    // Zero the structure
    secure_zero(asset, sizeof(crypto_asset_t));
    free(asset);
}

char* generate_asset_id(const crypto_asset_t *asset) {
    if (asset == NULL) {
        return NULL;
    }
    
    // Create JSON representation for hashing
    json_object *json_obj = json_object_new_object();
    if (json_obj == NULL) {
        return NULL;
    }
    
    // Add fields in deterministic order
    json_object_object_add(json_obj, "algorithm", 
                          json_object_new_string(asset->algorithm ? asset->algorithm : ""));
    json_object_object_add(json_obj, "hash_algorithm", 
                          json_object_new_string(asset->hash_algorithm ? asset->hash_algorithm : ""));
    json_object_object_add(json_obj, "key_size", 
                          json_object_new_int64(asset->key_size));
    json_object_object_add(json_obj, "location", 
                          json_object_new_string(asset->location ? asset->location : ""));
    json_object_object_add(json_obj, "name", 
                          json_object_new_string(asset->name));
    json_object_object_add(json_obj, "type", 
                          json_object_new_int(asset->type));
    json_object_object_add(json_obj, "version", 
                          json_object_new_string(asset->version ? asset->version : ""));
    
    // Get JSON string
    const char *json_str = json_object_to_json_string(json_obj);
    if (json_str == NULL) {
        json_object_put(json_obj);
        return NULL;
    }
    
    // Calculate SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)json_str, strlen(json_str), hash);
    
    // Convert to hex string
    char *hex_id = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (hex_id == NULL) {
        json_object_put(json_obj);
        return NULL;
    }
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_id + (i * 2), "%02x", hash[i]);
    }
    hex_id[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    json_object_put(json_obj);
    return hex_id;
}

int asset_store_add(asset_store_t *store, crypto_asset_t *asset) {
    if (store == NULL || asset == NULL || asset->id == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&store->mutex);
    
    uint32_t hash = hash_string(asset->id);
    size_t bucket_index = hash % store->bucket_count;
    
    // Check if asset already exists
    crypto_asset_t *current = store->buckets[bucket_index];
    while (current != NULL) {
        if (strcmp(current->id, asset->id) == 0) {
            pthread_mutex_unlock(&store->mutex);
            return 1; // Asset already exists
        }
        current = current->next;
    }
    
    // Add asset to bucket
    asset->next = store->buckets[bucket_index];
    store->buckets[bucket_index] = asset;
    store->asset_count++;

    // Auto-register SONAME for library assets (v1.8)
    // This enables cross-arch dependency resolution
    if (asset->type == ASSET_TYPE_LIBRARY && asset->name) {
        asset_store_register_soname_internal(store, asset->name, asset->id);
    }

    pthread_mutex_unlock(&store->mutex);
    return 0;
}

crypto_asset_t* asset_store_find(asset_store_t *store, const char *id) {
    if (store == NULL || id == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&store->mutex);
    
    uint32_t hash = hash_string(id);
    size_t bucket_index = hash % store->bucket_count;
    
    crypto_asset_t *current = store->buckets[bucket_index];
    while (current != NULL) {
        if (strcmp(current->id, id) == 0) {
            pthread_mutex_unlock(&store->mutex);
            return current;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&store->mutex);
    return NULL;
}

// v1.8.1: Remove asset from store by ID
int asset_store_remove(asset_store_t *store, const char *id) {
    if (store == NULL || id == NULL) {
        return -1;
    }

    pthread_mutex_lock(&store->mutex);

    uint32_t hash = hash_string(id);
    size_t bucket_index = hash % store->bucket_count;

    crypto_asset_t *current = store->buckets[bucket_index];
    crypto_asset_t *prev = NULL;

    while (current != NULL) {
        if (current->id && strcmp(current->id, id) == 0) {
            // Found - unlink from bucket
            if (prev == NULL) {
                // First in bucket
                store->buckets[bucket_index] = current->next;
            } else {
                prev->next = current->next;
            }
            store->asset_count--;

            pthread_mutex_unlock(&store->mutex);

            // Destroy the removed asset
            crypto_asset_destroy(current);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    pthread_mutex_unlock(&store->mutex);
    return -1;  // Not found
}

int asset_deterministic_compare(const crypto_asset_t *a, const crypto_asset_t *b) {
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    
    // Sort by type first
    if (a->type != b->type) {
        return (int)a->type - (int)b->type;
    }
    
    // Then by ID (content-addressed, so deterministic)
    if (a->id && b->id) {
        int id_cmp = strcmp(a->id, b->id);
        if (id_cmp != 0) {
            return id_cmp;
        }
    }
    
    // Finally by name
    if (a->name && b->name) {
        return strcmp(a->name, b->name);
    }
    
    return 0;
}

crypto_asset_t** asset_store_get_sorted(asset_store_t *store, asset_compare_fn compare_fn, size_t *count) {
    if (store == NULL || count == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&store->mutex);
    
    *count = store->asset_count;
    if (*count == 0) {
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }
    
    crypto_asset_t **assets = malloc(sizeof(crypto_asset_t*) * (*count));
    if (assets == NULL) {
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }
    
    // Collect all assets
    size_t index = 0;
    for (size_t i = 0; i < store->bucket_count; i++) {
        crypto_asset_t *current = store->buckets[i];
        while (current != NULL && index < *count) {
            assets[index++] = current;
            current = current->next;
        }
    }
    
    // Sort assets
    if (compare_fn == NULL) {
        compare_fn = asset_deterministic_compare;
    }
    
    // Simple bubble sort for now (can be optimized later)
    for (size_t i = 0; i < *count - 1; i++) {
        for (size_t j = 0; j < *count - i - 1; j++) {
            if (compare_fn(assets[j], assets[j + 1]) > 0) {
                crypto_asset_t *temp = assets[j];
                assets[j] = assets[j + 1];
                assets[j + 1] = temp;
            }
        }
    }
    
    pthread_mutex_unlock(&store->mutex);
    return assets;
}

asset_store_stats_t asset_store_get_stats(asset_store_t *store) {
    asset_store_stats_t stats = {0};
    
    if (store == NULL) {
        return stats;
    }
    
    pthread_mutex_lock(&store->mutex);
    
    stats.total_assets = store->asset_count;
    stats.load_factor = (double)store->asset_count / (double)store->bucket_count;
    
    // Count assets by type and properties
    for (size_t i = 0; i < store->bucket_count; i++) {
        crypto_asset_t *current = store->buckets[i];
        while (current != NULL) {
            if (current->type <= ASSET_TYPE_UNKNOWN) {
                stats.assets_by_type[current->type]++;
            }
            if (current->is_weak) {
                stats.weak_assets++;
            }
            if (current->is_pqc_ready) {
                stats.pqc_ready_assets++;
            }
            current = current->next;
        }
    }
    
    pthread_mutex_unlock(&store->mutex);
    return stats;
}

// Relationship operations (Phase 7.3a)

// Create a relationship
relationship_t* relationship_create(relationship_type_t type,
                                    const char* source_id,
                                    const char* target_id,
                                    float confidence) {
    if (!source_id || !target_id) return NULL;

    relationship_t* rel = malloc(sizeof(relationship_t));
    if (!rel) return NULL;

    memset(rel, 0, sizeof(relationship_t));

    // Generate relationship ID
    char id_string[256];
    snprintf(id_string, sizeof(id_string), "%s->%s", source_id, target_id);
    rel->id = strdup(id_string);

    rel->type = type;
    rel->source_asset_id = strdup(source_id);
    rel->target_asset_id = strdup(target_id);
    rel->confidence = confidence;
    rel->description = NULL;

    return rel;
}

// Destroy a relationship
void relationship_destroy(relationship_t *relationship) {
    if (!relationship) return;

    free(relationship->id);
    free(relationship->source_asset_id);
    free(relationship->target_asset_id);
    free(relationship->description);
    free(relationship);
}

// Add relationship to store
int asset_store_add_relationship(asset_store_t *store, relationship_t *relationship) {
    if (!store || !relationship) return -1;

    pthread_mutex_lock(&store->mutex);

    // Initialize relationships array if needed
    if (!store->relationships) {
        store->relationship_capacity = 100;
        store->relationships = malloc(sizeof(relationship_t*) * store->relationship_capacity);
        if (!store->relationships) {
            pthread_mutex_unlock(&store->mutex);
            return -1;
        }
        store->relationship_count = 0;
    }

    // Resize if needed
    if (store->relationship_count >= store->relationship_capacity) {
        size_t new_capacity = store->relationship_capacity * 2;
        relationship_t** new_array = realloc(store->relationships,
                                             sizeof(relationship_t*) * new_capacity);
        if (!new_array) {
            pthread_mutex_unlock(&store->mutex);
            return -1;
        }
        store->relationships = new_array;
        store->relationship_capacity = new_capacity;
    }

    // Check for duplicate relationship (same source + target)
    for (size_t i = 0; i < store->relationship_count; i++) {
        if (strcmp(store->relationships[i]->source_asset_id, relationship->source_asset_id) == 0 &&
            strcmp(store->relationships[i]->target_asset_id, relationship->target_asset_id) == 0) {
            // Duplicate relationship - skip
            pthread_mutex_unlock(&store->mutex);
            return 0;  // Success but not added
        }
    }

    // Add relationship
    store->relationships[store->relationship_count++] = relationship;

    pthread_mutex_unlock(&store->mutex);
    return 0;
}

// Get all relationships
relationship_t** asset_store_get_relationships(asset_store_t *store, size_t *count) {
    if (!store || !count) return NULL;

    pthread_mutex_lock(&store->mutex);

    *count = store->relationship_count;
    relationship_t** result = NULL;

    if (store->relationship_count > 0) {
        result = malloc(sizeof(relationship_t*) * store->relationship_count);
        if (result) {
            memcpy(result, store->relationships,
                   sizeof(relationship_t*) * store->relationship_count);
        }
    }

    pthread_mutex_unlock(&store->mutex);
    return result;
}

/**
 * Generate unique asset ID with prefix
 *
 * @param prefix Prefix for the ID (e.g., "cert", "key", "protocol")
 * @return Newly allocated ID string (caller must free)
 */
char* asset_store_generate_id(const char* prefix) {
    static unsigned long counter = 0;
    static pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&id_mutex);
    unsigned long id_num = ++counter;
    pthread_mutex_unlock(&id_mutex);

    // Format: prefix-timestamp-counter
    char* id = malloc(256);
    if (!id) return NULL;

    snprintf(id, 256, "%s-%ld-%lu",
             prefix ? prefix : "asset",
             (long)time(NULL),
             id_num);

    return id;
}

// ============================================================================
// SONAME Registry - Cross-arch dependency resolution (v1.8)
// ============================================================================

/**
 * Register a SONAME→bom-ref mapping.
 * Called internally when adding library assets.
 * First-wins on collision (duplicate SONAME ignored with debug log).
 * NOTE: Caller must hold store->mutex.
 */
static int asset_store_register_soname_internal(asset_store_t* store,
                                                 const char* soname,
                                                 const char* bom_ref) {
    if (!store || !soname || !bom_ref) return -1;

    // Check for collision (first-wins)
    for (size_t i = 0; i < store->soname_map_count; i++) {
        if (strcmp(store->soname_map[i].soname, soname) == 0) {
#ifdef DEBUG
            fprintf(stderr, "DEBUG: SONAME collision: %s already mapped to %s, ignoring %s\n",
                    soname, store->soname_map[i].bom_ref, bom_ref);
#endif
            return 0;  // First-wins, not an error
        }
    }

    // Grow registry if needed
    if (store->soname_map_count >= store->soname_map_capacity) {
        size_t new_capacity = store->soname_map_capacity == 0 ? 64 : store->soname_map_capacity * 2;
        soname_mapping_t* new_map = realloc(store->soname_map,
                                             new_capacity * sizeof(soname_mapping_t));
        if (!new_map) return -1;
        store->soname_map = new_map;
        store->soname_map_capacity = new_capacity;
    }

    // Add mapping
    store->soname_map[store->soname_map_count].soname = strdup(soname);
    store->soname_map[store->soname_map_count].bom_ref = strdup(bom_ref);
    store->soname_map_count++;

#ifdef DEBUG
    fprintf(stderr, "DEBUG: SONAME registry: %s -> %s\n", soname, bom_ref);
#endif

    return 0;
}

int asset_store_register_soname(asset_store_t* store, const char* soname, const char* bom_ref) {
    if (!store || !soname || !bom_ref) return -1;

    pthread_mutex_lock(&store->mutex);
    int result = asset_store_register_soname_internal(store, soname, bom_ref);
    pthread_mutex_unlock(&store->mutex);

    return result;
}

const char* asset_store_lookup_by_soname(asset_store_t* store, const char* soname) {
    if (!store || !soname) return NULL;

    pthread_mutex_lock(&store->mutex);

    for (size_t i = 0; i < store->soname_map_count; i++) {
        if (strcmp(store->soname_map[i].soname, soname) == 0) {
            const char* result = store->soname_map[i].bom_ref;
            pthread_mutex_unlock(&store->mutex);
            return result;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "DEBUG: SONAME lookup FAILED: %s not in registry (%zu entries)\n",
            soname, store->soname_map_count);
#endif

    pthread_mutex_unlock(&store->mutex);
    return NULL;
}

// ============================================================================
// Atomic Get-or-Create for Libraries (v1.8.6 - Race Condition Fix)
// ============================================================================

/**
 * Internal add function - assumes mutex is already held.
 * Returns 0 on success, 1 if asset already exists, -1 on error.
 */
static int asset_store_add_internal(asset_store_t *store, crypto_asset_t *asset) {
    if (store == NULL || asset == NULL || asset->id == NULL) {
        return -1;
    }

    uint32_t hash = hash_string(asset->id);
    size_t bucket_index = hash % store->bucket_count;

    // Check if asset already exists
    crypto_asset_t *current = store->buckets[bucket_index];
    while (current != NULL) {
        if (strcmp(current->id, asset->id) == 0) {
            return 1; // Asset already exists
        }
        current = current->next;
    }

    // Add asset to bucket
    asset->next = store->buckets[bucket_index];
    store->buckets[bucket_index] = asset;
    store->asset_count++;

    // Auto-register SONAME for library assets
    if (asset->type == ASSET_TYPE_LIBRARY && asset->name) {
        asset_store_register_soname_internal(store, asset->name, asset->id);
    }

    return 0;
}

/**
 * Internal SONAME lookup - assumes mutex is already held.
 */
static const char* asset_store_lookup_by_soname_internal(asset_store_t* store, const char* soname) {
    if (!store || !soname) return NULL;

    for (size_t i = 0; i < store->soname_map_count; i++) {
        if (strcmp(store->soname_map[i].soname, soname) == 0) {
            return store->soname_map[i].bom_ref;
        }
    }
    return NULL;
}

const char* asset_store_get_or_create_library(asset_store_t* store,
                                               const char* soname,
                                               const char* location,
                                               bool* was_created) {
    if (!store || !soname) return NULL;

    if (was_created) *was_created = false;

    pthread_mutex_lock(&store->mutex);

    // Fast path: check SONAME registry
    const char* existing = asset_store_lookup_by_soname_internal(store, soname);
    if (existing) {
        pthread_mutex_unlock(&store->mutex);
        return existing;
    }

    // Slow path: create new library asset while holding lock
    crypto_asset_t* lib_asset = crypto_asset_create(soname, ASSET_TYPE_LIBRARY);
    if (!lib_asset) {
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }

    if (location) {
        lib_asset->location = strdup(location);
    }

    // Add to store using internal function (no double-lock)
    int result = asset_store_add_internal(store, lib_asset);
    if (result == 1) {
        // Another thread beat us - this shouldn't happen since we hold the lock,
        // but handle it gracefully (could occur with matching ID from different SONAME)
        pthread_mutex_unlock(&store->mutex);
        crypto_asset_destroy(lib_asset);
        // Look up again to get the winning thread's ID
        return asset_store_lookup_by_soname(store, soname);
    } else if (result != 0) {
        pthread_mutex_unlock(&store->mutex);
        crypto_asset_destroy(lib_asset);
        return NULL;
    }

    // Success - we created and added the library
    const char* lib_id = lib_asset->id;
    if (was_created) *was_created = true;

    pthread_mutex_unlock(&store->mutex);
    return lib_id;
}
