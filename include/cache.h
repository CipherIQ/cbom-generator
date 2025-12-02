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

#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "cbom_types.h"

// Cache entry structure with file validation
typedef struct {
    char *file_path;             // Full path to cached file
    char *content_hash;          // SHA-256 hash of file content
    time_t mtime;                // File modification time
    ino_t inode;                 // File inode number
    off_t file_size;             // File size in bytes
    time_t cache_time;           // When this entry was cached
    char *asset_ids;             // JSON array of asset IDs found in this file
    size_t asset_count;          // Number of assets found
    bool is_encrypted;           // Whether cache data is encrypted
} cache_entry_t;

// Cache configuration
typedef struct {
    char *cache_dir;             // Cache directory path
    int retention_days;          // Cache retention period (default: 7)
    bool enable_encryption;      // Enable AES-256-GCM encryption
    char *encryption_key;        // 32-byte encryption key (hex)
    size_t max_cache_size_mb;    // Maximum cache size in MB
    bool enable_compression;     // Enable cache compression
} cache_config_t;

// Cache statistics
typedef struct {
    size_t total_entries;        // Total cache entries
    size_t cache_hits;           // Number of cache hits
    size_t cache_misses;         // Number of cache misses
    size_t expired_entries;      // Number of expired entries
    size_t invalid_entries;      // Number of invalid entries (file changed)
    double hit_rate;             // Cache hit rate percentage
    size_t cache_size_bytes;     // Total cache size in bytes
    time_t last_cleanup;         // Last cleanup timestamp
} cache_stats_t;

// Cache handle
typedef struct cache_handle cache_handle_t;

// Cache operations
cache_handle_t* cache_create(const cache_config_t *config);
void cache_destroy(cache_handle_t *cache);

// Cache entry operations
int cache_get_entry(cache_handle_t *cache, const char *file_path, cache_entry_t **entry);
int cache_put_entry(cache_handle_t *cache, const char *file_path, 
                   const char **asset_ids, size_t asset_count);
int cache_invalidate_entry(cache_handle_t *cache, const char *file_path);
bool cache_is_file_cached(cache_handle_t *cache, const char *file_path);

// File validation
bool cache_validate_file(const cache_entry_t *entry, const char *file_path);
int cache_update_file_metadata(cache_entry_t *entry, const char *file_path);

// Cache maintenance
int cache_cleanup_expired(cache_handle_t *cache);
int cache_cleanup_invalid(cache_handle_t *cache);
int cache_enforce_size_limit(cache_handle_t *cache);
int cache_full_cleanup(cache_handle_t *cache);

// Cache statistics and reporting
cache_stats_t cache_get_stats(cache_handle_t *cache);
void cache_reset_stats(cache_handle_t *cache);
int cache_export_stats(cache_handle_t *cache, const char *output_file);

// Cache entry management
cache_entry_t* cache_entry_create(const char *file_path);
void cache_entry_destroy(cache_entry_t *entry);
cache_entry_t* cache_entry_clone(const cache_entry_t *entry);

// Encryption support
int cache_encrypt_data(const char *plaintext, size_t plaintext_len,
                      const char *key, char **ciphertext, size_t *ciphertext_len);
int cache_decrypt_data(const char *ciphertext, size_t ciphertext_len,
                      const char *key, char **plaintext, size_t *plaintext_len);

// Utility functions
char* cache_generate_file_hash(const char *file_path);
bool cache_is_entry_expired(const cache_entry_t *entry, int retention_days);
int cache_create_directory(const char *cache_dir);

#endif // CACHE_H
