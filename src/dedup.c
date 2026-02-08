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

#include "dedup.h"
#include "secure_memory.h"
#include "error_handling.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifndef __EMSCRIPTEN__
#include <openssl/evp.h>
#endif
#include <sys/stat.h>
#include <time.h>

// Simple hash table implementation for dedup indexes
#define DEDUP_HASH_TABLE_SIZE 1024

typedef struct hash_entry {
    char *key;
    char *value;
    struct hash_entry *next;
} hash_entry_t;

typedef struct {
    hash_entry_t **buckets;
    size_t bucket_count;
    pthread_mutex_t mutex;
} hash_table_t;

// Evidence map entry
typedef struct {
    char *bom_ref;
    component_evidence_t *evidence;
    struct hash_entry *next;
} evidence_entry_t;

// Hash function
static unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Hash table operations
static hash_table_t *hash_table_create(size_t bucket_count) {
    hash_table_t *table = malloc(sizeof(hash_table_t));
    if (!table) return NULL;

    table->buckets = malloc(bucket_count * sizeof(hash_entry_t *));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->bucket_count = bucket_count;
    pthread_mutex_init(&table->mutex, NULL);

    for (size_t i = 0; i < bucket_count; i++) {
        table->buckets[i] = NULL;
    }

    return table;
}

static void hash_table_destroy(hash_table_t *table) {
    if (!table) return;

    for (size_t i = 0; i < table->bucket_count; i++) {
        hash_entry_t *entry = table->buckets[i];
        while (entry) {
            hash_entry_t *next = entry->next;
            if (entry->key) free(entry->key);
            if (entry->value) free(entry->value);
            free(entry);
            entry = next;
        }
    }

    pthread_mutex_destroy(&table->mutex);
    free(table->buckets);
    free(table);
}

static char *hash_table_get(hash_table_t *table, const char *key) {
    if (!table || !key) return NULL;

    unsigned long hash = hash_string(key) % table->bucket_count;

    pthread_mutex_lock(&table->mutex);
    hash_entry_t *entry = table->buckets[hash];
    while (entry) {
        if (entry->key && strcmp(entry->key, key) == 0) {
            char *value = entry->value ? strdup(entry->value) : NULL;
            pthread_mutex_unlock(&table->mutex);
            return value;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&table->mutex);

    return NULL;
}

static void hash_table_set(hash_table_t *table, const char *key, const char *value) {
    if (!table || !key) return;

    unsigned long hash = hash_string(key) % table->bucket_count;

    pthread_mutex_lock(&table->mutex);

    // Check if key already exists
    hash_entry_t *entry = table->buckets[hash];
    while (entry) {
        if (entry->key && strcmp(entry->key, key) == 0) {
            // Update existing entry
            if (entry->value) free(entry->value);
            entry->value = value ? strdup(value) : NULL;
            pthread_mutex_unlock(&table->mutex);
            return;
        }
        entry = entry->next;
    }

    // Create new entry
    hash_entry_t *new_entry = malloc(sizeof(hash_entry_t));
    if (new_entry) {
        new_entry->key = strdup(key);
        new_entry->value = value ? strdup(value) : NULL;
        new_entry->next = table->buckets[hash];
        table->buckets[hash] = new_entry;
    }

    pthread_mutex_unlock(&table->mutex);
}

// Deduplication context management
dedup_context_t *dedup_context_create(dedup_mode_t mode, bool emit_bundles) {
    dedup_context_t *ctx = malloc(sizeof(dedup_context_t));
    if (!ctx) return NULL;

    ctx->mode = mode;
    ctx->emit_bundles = emit_bundles;

    // Create indexes
    ctx->by_file_sha256 = hash_table_create(DEDUP_HASH_TABLE_SIZE);
    ctx->by_file_path = hash_table_create(DEDUP_HASH_TABLE_SIZE);
    ctx->evidence_map = hash_table_create(DEDUP_HASH_TABLE_SIZE);

    if (!ctx->by_file_sha256 || !ctx->by_file_path || !ctx->evidence_map) {
        dedup_context_destroy(ctx);
        return NULL;
    }

    // Initialize statistics
    memset(&ctx->stats, 0, sizeof(dedup_stats_t));

    // Initialize mutex
    pthread_mutex_init(&ctx->mutex, NULL);

    return ctx;
}

void dedup_context_destroy(dedup_context_t *ctx) {
    if (!ctx) return;

    if (ctx->by_file_sha256) {
        hash_table_destroy((hash_table_t *)ctx->by_file_sha256);
    }
    if (ctx->by_file_path) {
        hash_table_destroy((hash_table_t *)ctx->by_file_path);
    }
    if (ctx->evidence_map) {
        // TODO: Free evidence entries
        hash_table_destroy((hash_table_t *)ctx->evidence_map);
    }

    pthread_mutex_destroy(&ctx->mutex);
    free(ctx);
}

// Compute file SHA-256
char *dedup_compute_file_sha256(const char *file_path) {
    if (!file_path) return NULL;

    FILE *file = fopen(file_path, "rb");
    if (!file) return NULL;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return NULL;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    unsigned char buffer[8192];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return NULL;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);

    // Convert to hex string (SHA-256 produces 32 bytes)
    // Use regular malloc since this will be freed with regular free
    char *hash_str = malloc(hash_len * 2 + 1);
    if (hash_str) {
        for (unsigned int i = 0; i < hash_len; i++) {
            sprintf(hash_str + (i * 2), "%02x", hash[i]);
        }
        hash_str[hash_len * 2] = '\0';
    }

    return hash_str;
}

// Register a file as the authoritative source for a component
void dedup_register_file(
    dedup_context_t *ctx,
    const char *file_path,
    const char *file_sha256,
    const char *bom_ref
) {
    if (!ctx || !bom_ref) return;

    hash_table_t *by_sha256 = (hash_table_t *)ctx->by_file_sha256;
    hash_table_t *by_path = (hash_table_t *)ctx->by_file_path;

    if (file_sha256) {
        hash_table_set(by_sha256, file_sha256, bom_ref);
    }
    if (file_path) {
        hash_table_set(by_path, file_path, bom_ref);
    }
}

// Get authoritative component for a file
char *dedup_get_component_for_file(
    dedup_context_t *ctx,
    const char *file_path,
    const char *file_sha256
) {
    if (!ctx) return NULL;

    hash_table_t *by_sha256 = (hash_table_t *)ctx->by_file_sha256;
    hash_table_t *by_path = (hash_table_t *)ctx->by_file_path;

    // Try SHA-256 first (most reliable)
    if (file_sha256) {
        char *bom_ref = hash_table_get(by_sha256, file_sha256);
        if (bom_ref) return bom_ref;
    }

    // Fall back to file path
    if (file_path) {
        char *bom_ref = hash_table_get(by_path, file_path);
        if (bom_ref) return bom_ref;
    }

    return NULL;
}

// Check if a file should be suppressed
bool dedup_should_suppress_file(
    dedup_context_t *ctx,
    const char *file_path,
    const char *file_sha256
) {
    if (!ctx) return false;

    // In OFF mode, never suppress
    if (ctx->mode == DEDUP_MODE_OFF) {
        return false;
    }

    // Check if file has an authoritative component
    char *bom_ref = dedup_get_component_for_file(ctx, file_path, file_sha256);
    if (bom_ref) {
        free(bom_ref);
        return true;
    }

    return false;
}

// Add evidence to a component
void dedup_add_evidence(
    dedup_context_t *ctx,
    const char *bom_ref,
    const char *location,
    const char *file_sha256
) {
    if (!ctx || !bom_ref) return;

    // Create new occurrence
    evidence_occurrence_t *occurrence = secure_alloc(sizeof(evidence_occurrence_t));
    if (!occurrence) return;

    occurrence->location = location ? strdup(location) : NULL;
    occurrence->file_sha256 = file_sha256 ? strdup(file_sha256) : NULL;
    occurrence->discovered_time = time(NULL);
    occurrence->next = NULL;

    // Note: In a full implementation, we would store this in the evidence_map
    // For now, we just track that evidence was added
    // The actual evidence will be attached to the asset's metadata_json

    secure_free(occurrence, sizeof(evidence_occurrence_t));
}

// Core deduplication function
char *dedup_merge_or_create_component(
    dedup_context_t *ctx,
    asset_store_t *store,
    crypto_asset_t *asset,
    const char *file_path,
    const char *file_sha256
) {
    if (!ctx || !store || !asset) return NULL;

    pthread_mutex_lock(&ctx->mutex);

    // Check if component already exists for this file
    char *existing_ref = dedup_get_component_for_file(ctx, file_path, file_sha256);

    if (existing_ref) {
        // Found existing component - merge evidence
        crypto_asset_t *existing_asset = asset_store_find(store, existing_ref);

        if (existing_asset) {
            // Add new location to existing asset's evidence
            // For certificates, keys, and OpenPGP, the parsed component is authoritative
            dedup_add_evidence(ctx, existing_ref, file_path, file_sha256);

            // Update statistics based on asset type
            switch (asset->type) {
                case ASSET_TYPE_CERTIFICATE:
                    ctx->stats.certs_merged++;
                    break;
                case ASSET_TYPE_KEY:
                    ctx->stats.keys_merged++;
                    break;
                default:
                    if (strstr(asset->name ? asset->name : "", "OpenPGP")) {
                        ctx->stats.openpgp_merged++;
                    }
                    break;
            }

            pthread_mutex_unlock(&ctx->mutex);
            return existing_ref;  // Return existing bom_ref
        }

        free(existing_ref);
    }

    // No existing component - add this asset to the store
    int add_result = asset_store_add(store, asset);
    if (add_result != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return NULL;
    }

    // Register this file with the new component
    char *bom_ref = asset->id ? strdup(asset->id) : NULL;
    if (bom_ref) {
        dedup_register_file(ctx, file_path, file_sha256, bom_ref);
        dedup_add_evidence(ctx, bom_ref, file_path, file_sha256);
    }

    pthread_mutex_unlock(&ctx->mutex);
    return bom_ref;
}

// Get statistics
dedup_stats_t dedup_get_stats(dedup_context_t *ctx) {
    if (!ctx) {
        dedup_stats_t empty = {0};
        return empty;
    }

    pthread_mutex_lock(&ctx->mutex);
    dedup_stats_t stats = ctx->stats;
    pthread_mutex_unlock(&ctx->mutex);

    return stats;
}

// Print statistics
void dedup_print_stats(const dedup_stats_t *stats) {
    if (!stats) return;

    fprintf(stderr, "Deduplication Statistics:\n");
    fprintf(stderr, "  Certificates merged: %zu\n", stats->certs_merged);
    fprintf(stderr, "  Keys merged: %zu\n", stats->keys_merged);
    fprintf(stderr, "  OpenPGP keys merged: %zu\n", stats->openpgp_merged);
    fprintf(stderr, "  Files suppressed: %zu\n", stats->files_suppressed);
    fprintf(stderr, "  Bundles created: %zu\n", stats->bundles_created);
    fprintf(stderr, "  Hash collisions: %zu\n", stats->collisions);
}

// Get evidence for a component
component_evidence_t *dedup_get_evidence(
    dedup_context_t *ctx,
    const char *bom_ref
) {
    // Placeholder - would retrieve from evidence_map
    (void)ctx;
    (void)bom_ref;
    return NULL;
}

// Bundle handling (strict mode only)
char *dedup_create_or_get_bundle(
    dedup_context_t *ctx,
    asset_store_t *store,
    const char *bundle_file_path
) {
    if (!ctx || !store || !bundle_file_path) return NULL;
    if (ctx->mode != DEDUP_MODE_STRICT || !ctx->emit_bundles) return NULL;

    // Check if bundle already exists
    char *file_sha256 = dedup_compute_file_sha256(bundle_file_path);
    char *existing_ref = dedup_get_component_for_file(ctx, bundle_file_path, file_sha256);

    if (existing_ref) {
        if (file_sha256) free(file_sha256);
        return existing_ref;
    }

    // Create new bundle component
    crypto_asset_t *bundle = crypto_asset_create(bundle_file_path, ASSET_TYPE_CERTIFICATE);
    if (!bundle) {
        if (file_sha256) free(file_sha256);
        return NULL;
    }

    bundle->location = strdup(bundle_file_path);
    bundle->algorithm = strdup("BUNDLE");

    // Add to store
    int add_result = asset_store_add(store, bundle);
    if (add_result != 0) {
        crypto_asset_destroy(bundle);
        if (file_sha256) free(file_sha256);
        return NULL;
    }

    // Register bundle
    char *bom_ref = bundle->id ? strdup(bundle->id) : NULL;
    if (bom_ref) {
        dedup_register_file(ctx, bundle_file_path, file_sha256, bom_ref);
        ctx->stats.bundles_created++;
    }

    if (file_sha256) free(file_sha256);
    return bom_ref;
}

void dedup_link_cert_to_bundle(
    dedup_context_t *ctx,
    const char *bundle_ref,
    const char *cert_ref
) {
    // Placeholder for bundle→cert relationship
    (void)ctx;
    (void)bundle_ref;
    (void)cert_ref;
}

/**
 * v1.8.1: Merge duplicate services/applications by name
 *
 * When both YAML plugin and filesystem scanner detect the same service,
 * we get duplicate components with the same name but different properties.
 * This function:
 *   1. Identifies duplicates by name (for SERVICE and APPLICATION types)
 *   2. Keeps the richer entry (one with dependencies or more properties)
 *   3. Removes the duplicate entry
 *
 * Returns: number of duplicates removed, or -1 on error
 */
int dedup_merge_duplicate_services(asset_store_t *store) {
    if (!store) return -1;

    size_t count = 0;
    crypto_asset_t **assets = asset_store_get_sorted(store, asset_deterministic_compare, &count);
    if (!assets || count == 0) {
        free(assets);
        return 0;
    }

    // Build index of services/applications by name
    // Simple O(n²) approach since service count is typically low
    int removed = 0;
    char **to_remove = malloc(count * sizeof(char*));
    size_t remove_count = 0;

    if (!to_remove) {
        free(assets);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        crypto_asset_t *a = assets[i];
        if (!a || !a->name) continue;

        // Only process services and applications
        if (a->type != ASSET_TYPE_SERVICE && a->type != ASSET_TYPE_APPLICATION) {
            continue;
        }

        // Check if this asset is already marked for removal
        bool already_marked = false;
        for (size_t k = 0; k < remove_count; k++) {
            if (to_remove[k] && a->id && strcmp(to_remove[k], a->id) == 0) {
                already_marked = true;
                break;
            }
        }
        if (already_marked) continue;

        // Find duplicates with the same name and type
        for (size_t j = i + 1; j < count; j++) {
            crypto_asset_t *b = assets[j];
            if (!b || !b->name) continue;

            // Same name and type = duplicate
            if (a->type == b->type && strcmp(a->name, b->name) == 0) {
                // v1.8.4: Determine winner: prefer YAML plugin entries over app scanner
                // YAML plugins set detection_method: "binary", "process", "config", "systemd"
                // App scanner sets detection_method: "BINARY_SCAN", "BINARY_SCAN_PARALLEL"
                crypto_asset_t *winner = a;
                crypto_asset_t *loser = b;

                // Check detection_method in metadata_json to identify source
                // YAML plugins use lowercase detection methods
                bool a_is_yaml_plugin = false;
                bool b_is_yaml_plugin = false;

                if (a->metadata_json) {
                    // YAML plugin detection methods: binary, process, config, systemd, port, package
                    a_is_yaml_plugin = (strstr(a->metadata_json, "\"detection_method\":\"binary\"") != NULL ||
                                        strstr(a->metadata_json, "\"detection_method\":\"process\"") != NULL ||
                                        strstr(a->metadata_json, "\"detection_method\":\"config\"") != NULL ||
                                        strstr(a->metadata_json, "\"detection_method\":\"systemd\"") != NULL ||
                                        strstr(a->metadata_json, "\"detection_method\":\"port\"") != NULL ||
                                        strstr(a->metadata_json, "\"detection_method\":\"package\"") != NULL);
                }

                if (b->metadata_json) {
                    b_is_yaml_plugin = (strstr(b->metadata_json, "\"detection_method\":\"binary\"") != NULL ||
                                        strstr(b->metadata_json, "\"detection_method\":\"process\"") != NULL ||
                                        strstr(b->metadata_json, "\"detection_method\":\"config\"") != NULL ||
                                        strstr(b->metadata_json, "\"detection_method\":\"systemd\"") != NULL ||
                                        strstr(b->metadata_json, "\"detection_method\":\"port\"") != NULL ||
                                        strstr(b->metadata_json, "\"detection_method\":\"package\"") != NULL);
                }

                // Prefer YAML plugin entry (has richer config/context metadata)
                if (b_is_yaml_plugin && !a_is_yaml_plugin) {
                    winner = b;
                    loser = a;
                } else if (a_is_yaml_plugin && !b_is_yaml_plugin) {
                    // Keep 'a' as winner (already default)
                } else {
                    // Both or neither are YAML plugins - prefer one with location
                    bool a_has_info = (a->location != NULL);
                    bool b_has_info = (b->location != NULL);
                    if (b_has_info && !a_has_info) {
                        winner = b;
                        loser = a;
                    }
                }

                // Mark loser for removal
                if (loser->id) {
                    // v1.9.1: Migrate relationships from loser to winner
                    // This ensures relationships created for the merged asset are preserved
                    size_t rel_count = 0;
                    relationship_t** relationships = asset_store_get_relationships(store, &rel_count);
                    if (relationships && rel_count > 0) {
                        int migrated = 0;
                        for (size_t r = 0; r < rel_count; r++) {
                            relationship_t* rel = relationships[r];
                            if (!rel) continue;

                            bool source_match = (rel->source_asset_id && strcmp(rel->source_asset_id, loser->id) == 0);
                            bool target_match = (rel->target_asset_id && strcmp(rel->target_asset_id, loser->id) == 0);

                            if (source_match || target_match) {
                                // Create migrated relationship with winner's ID
                                const char* new_source = source_match ? winner->id : rel->source_asset_id;
                                const char* new_target = target_match ? winner->id : rel->target_asset_id;

                                // Skip self-referential relationships
                                if (strcmp(new_source, new_target) == 0) continue;

                                relationship_t* new_rel = relationship_create(rel->type, new_source, new_target, rel->confidence);
                                if (new_rel) {
                                    asset_store_add_relationship(store, new_rel);
                                    migrated++;
                                }
                            }
                        }
                        if (migrated > 0) {
                            fprintf(stderr, "[dedup] Migrated %d relationships from %s to %s\n",
                                    migrated, loser->id, winner->id);
                        }
                    }

                    to_remove[remove_count++] = strdup(loser->id);
                    fprintf(stderr, "[dedup] Merging duplicate %s '%s': keeping %s, removing %s\n",
                            a->type == ASSET_TYPE_SERVICE ? "service" : "application",
                            a->name,
                            winner->id ? winner->id : "(unknown)",
                            loser->id ? loser->id : "(unknown)");
                }
            }
        }
    }

    // Remove marked assets
    for (size_t i = 0; i < remove_count; i++) {
        if (to_remove[i]) {
            if (asset_store_remove(store, to_remove[i]) == 0) {
                removed++;
            }
            free(to_remove[i]);
        }
    }

    free(to_remove);
    free(assets);

    if (removed > 0) {
        fprintf(stderr, "[dedup] Merged %d duplicate service/application entries\n", removed);
    }

    return removed;
}
