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

#ifndef ASSET_STORE_H
#define ASSET_STORE_H

#include "cbom_types.h"
#include <pthread.h>

// SONAME→bom-ref mapping for dependency resolution (v1.8)
typedef struct {
    char* soname;       // e.g., "libssl.so.3"
    char* bom_ref;      // CycloneDX bom-ref (e.g., "library:libssl.so.3")
} soname_mapping_t;

// Complete asset store definition
struct asset_store {
    crypto_asset_t **buckets;    // Hash table buckets
    size_t bucket_count;         // Number of buckets
    size_t asset_count;          // Total number of assets
    pthread_mutex_t mutex;       // Thread safety mutex
    bool deterministic_mode;     // Enable deterministic output

    // Relationship storage (Phase 7.3a)
    relationship_t **relationships;  // Relationship array
    size_t relationship_count;       // Number of relationships
    size_t relationship_capacity;    // Allocated capacity

    // SONAME→bom-ref registry for cross-arch dependency resolution (v1.8)
    soname_mapping_t* soname_map;
    size_t soname_map_count;
    size_t soname_map_capacity;
};

// Asset store operations
asset_store_t* asset_store_create(size_t initial_bucket_count);
void asset_store_destroy(asset_store_t *store);

// Asset operations
int asset_store_add(asset_store_t *store, crypto_asset_t *asset);
crypto_asset_t* asset_store_find(asset_store_t *store, const char *id);
int asset_store_remove(asset_store_t *store, const char *id);

// Asset creation and destruction
crypto_asset_t* crypto_asset_create(const char *name, asset_type_t type);
void crypto_asset_destroy(crypto_asset_t *asset);

// Asset ID generation (SHA-256 content-addressed)
char* generate_asset_id(const crypto_asset_t *asset);
char* asset_store_generate_id(const char* prefix);

// Deterministic sorting
typedef int (*asset_compare_fn)(const crypto_asset_t *a, const crypto_asset_t *b);
crypto_asset_t** asset_store_get_sorted(asset_store_t *store, asset_compare_fn compare_fn, size_t *count);

// Default deterministic comparison function
int asset_deterministic_compare(const crypto_asset_t *a, const crypto_asset_t *b);

// Asset store statistics
typedef struct {
    size_t total_assets;
    size_t assets_by_type[ASSET_TYPE_UNKNOWN + 1];
    size_t weak_assets;
    size_t pqc_ready_assets;
    double load_factor;
} asset_store_stats_t;

asset_store_stats_t asset_store_get_stats(asset_store_t *store);

// Relationship operations (Phase 7.3a)
int asset_store_add_relationship(asset_store_t *store, relationship_t *relationship);
relationship_t** asset_store_get_relationships(asset_store_t *store, size_t *count);
relationship_t* relationship_create(relationship_type_t type,
                                    const char* source_id,
                                    const char* target_id,
                                    float confidence);
void relationship_destroy(relationship_t *relationship);

// SONAME registry operations (v1.8 - Cross-arch dependency resolution)

/**
 * Register a SONAME→bom-ref mapping for dependency resolution.
 * First-wins on collision (duplicate SONAME ignored with debug log).
 *
 * @param store   The asset store
 * @param soname  The SONAME (e.g., "libssl.so.3")
 * @param bom_ref The bom-ref to map to (e.g., "library:libssl.so.3")
 * @return 0 on success, non-zero on error
 */
int asset_store_register_soname(asset_store_t* store, const char* soname, const char* bom_ref);

/**
 * Look up bom-ref by SONAME for dependency resolution.
 * Thread-safe lookup.
 *
 * @param store  The asset store
 * @param soname The SONAME to look up
 * @return The bom-ref string (do NOT free), or NULL if not found
 */
const char* asset_store_lookup_by_soname(asset_store_t* store, const char* soname);

/**
 * Atomically get or create a library asset by SONAME.
 * Fixes TOCTOU race condition in parallel scanning (v1.8.6).
 *
 * This function is thread-safe and ensures only one library asset
 * is created per SONAME, even when multiple threads race to create it.
 *
 * @param store       The asset store
 * @param soname      The SONAME (e.g., "libssl.so.3")
 * @param location    Optional file path (can be NULL)
 * @param was_created Optional output flag: true if new asset was created
 * @return The library's bom-ref (do NOT free), or NULL on error
 */
const char* asset_store_get_or_create_library(asset_store_t* store,
                                               const char* soname,
                                               const char* location,
                                               bool* was_created);

#endif // ASSET_STORE_H
