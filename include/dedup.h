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

#ifndef DEDUP_H
#define DEDUP_H

#include "cbom_types.h"
#include "asset_store.h"
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Note: dedup_mode_t is defined in cbom_types.h

// Evidence structure for tracking file occurrences
typedef struct evidence_occurrence {
    char *location;              // File path
    char *file_sha256;           // SHA-256 hash of file content
    time_t discovered_time;      // When this occurrence was discovered
    struct evidence_occurrence *next;
} evidence_occurrence_t;

// Component evidence (merged from multiple sources)
typedef struct {
    evidence_occurrence_t *occurrences;  // Linked list of occurrences
    size_t occurrence_count;             // Number of occurrences
} component_evidence_t;

// Deduplication statistics
typedef struct {
    size_t certs_merged;             // Number of certificate duplicates merged
    size_t keys_merged;              // Number of key duplicates merged
    size_t openpgp_merged;           // Number of OpenPGP key duplicates merged
    size_t files_suppressed;         // Number of raw file components suppressed
    size_t bundles_created;          // Number of bundle components created
    size_t collisions;               // Number of hash collisions detected
} dedup_stats_t;

// Deduplication context
typedef struct dedup_context {
    dedup_mode_t mode;                   // Deduplication mode
    bool emit_bundles;                   // Whether to emit bundle components

    // Runtime indexes
    void *by_file_sha256;                // Hash table: file_sha256 -> bom_ref
    void *by_file_path;                  // Hash table: absolute_path -> bom_ref

    // Evidence tracking
    void *evidence_map;                  // Hash table: bom_ref -> component_evidence_t

    // Statistics
    dedup_stats_t stats;

    // Thread safety
    pthread_mutex_t mutex;
} dedup_context_t;

// Deduplication context management
dedup_context_t *dedup_context_create(dedup_mode_t mode, bool emit_bundles);
void dedup_context_destroy(dedup_context_t *ctx);

// Core deduplication function
// Returns: bom_ref of the authoritative component (existing or newly created)
// If asset is merged into existing component, the function updates evidence
char *dedup_merge_or_create_component(
    dedup_context_t *ctx,
    asset_store_t *store,
    crypto_asset_t *asset,
    const char *file_path,
    const char *file_sha256
);

// Evidence management
void dedup_add_evidence(
    dedup_context_t *ctx,
    const char *bom_ref,
    const char *location,
    const char *file_sha256
);

component_evidence_t *dedup_get_evidence(
    dedup_context_t *ctx,
    const char *bom_ref
);

// Check if a file should be suppressed (already parsed as cert/key/pgp)
bool dedup_should_suppress_file(
    dedup_context_t *ctx,
    const char *file_path,
    const char *file_sha256
);

// Register a file as the authoritative source for a component
void dedup_register_file(
    dedup_context_t *ctx,
    const char *file_path,
    const char *file_sha256,
    const char *bom_ref
);

// Get authoritative component for a file
char *dedup_get_component_for_file(
    dedup_context_t *ctx,
    const char *file_path,
    const char *file_sha256
);

// Bundle handling (strict mode only)
char *dedup_create_or_get_bundle(
    dedup_context_t *ctx,
    asset_store_t *store,
    const char *bundle_file_path
);

void dedup_link_cert_to_bundle(
    dedup_context_t *ctx,
    const char *bundle_ref,
    const char *cert_ref
);

// Statistics
dedup_stats_t dedup_get_stats(dedup_context_t *ctx);
void dedup_print_stats(const dedup_stats_t *stats);

// Helper: Compute file SHA-256
char *dedup_compute_file_sha256(const char *file_path);

// v1.8.1: Merge duplicate services by name
// When both YAML plugin and filesystem scanner find the same service,
// keeps the richer entry (YAML plugin) and transfers relationships
int dedup_merge_duplicate_services(asset_store_t *store);

#ifdef __cplusplus
}
#endif

#endif // DEDUP_H
