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
#include "cache.h"
#include "secure_memory.h"
#include "error_handling.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <libgen.h>
#ifndef __EMSCRIPTEN__
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif
#include <json-c/json.h>

#ifdef __EMSCRIPTEN__

/* ── WASM stubs: caching disabled (no OpenSSL for hashing/encryption) ─ */

cache_handle_t* cache_create(const cache_config_t *config) { (void)config; return NULL; }
void cache_destroy(cache_handle_t *cache) { (void)cache; }
int cache_get_entry(cache_handle_t *cache, const char *file_path, cache_entry_t **entry) {
    (void)cache; (void)file_path; if (entry) *entry = NULL; return -1;
}
int cache_put_entry(cache_handle_t *cache, const char *file_path,
                   const char **asset_ids, size_t asset_count) {
    (void)cache; (void)file_path; (void)asset_ids; (void)asset_count; return 0;
}
int cache_invalidate_entry(cache_handle_t *cache, const char *file_path) {
    (void)cache; (void)file_path; return 0;
}
bool cache_is_file_cached(cache_handle_t *cache, const char *file_path) {
    (void)cache; (void)file_path; return false;
}
bool cache_validate_file(const cache_entry_t *entry, const char *file_path) {
    (void)entry; (void)file_path; return false;
}
int cache_update_file_metadata(cache_entry_t *entry, const char *file_path) {
    (void)entry; (void)file_path; return 0;
}
int cache_cleanup_expired(cache_handle_t *cache) { (void)cache; return 0; }
int cache_cleanup_invalid(cache_handle_t *cache) { (void)cache; return 0; }
int cache_enforce_size_limit(cache_handle_t *cache) { (void)cache; return 0; }
int cache_full_cleanup(cache_handle_t *cache) { (void)cache; return 0; }
cache_stats_t cache_get_stats(cache_handle_t *cache) {
    (void)cache; cache_stats_t s = {0}; return s;
}
void cache_reset_stats(cache_handle_t *cache) { (void)cache; }
int cache_export_stats(cache_handle_t *cache, const char *output_file) {
    (void)cache; (void)output_file; return 0;
}
cache_entry_t* cache_entry_create(const char *file_path) { (void)file_path; return NULL; }
void cache_entry_destroy(cache_entry_t *entry) { (void)entry; }
cache_entry_t* cache_entry_clone(const cache_entry_t *entry) { (void)entry; return NULL; }
int cache_encrypt_data(const char *plaintext, size_t plaintext_len,
                      const char *key, char **ciphertext, size_t *ciphertext_len) {
    (void)plaintext; (void)plaintext_len; (void)key; (void)ciphertext; (void)ciphertext_len; return -1;
}
int cache_decrypt_data(const char *ciphertext, size_t ciphertext_len,
                      const char *key, char **plaintext, size_t *plaintext_len) {
    (void)ciphertext; (void)ciphertext_len; (void)key; (void)plaintext; (void)plaintext_len; return -1;
}
char* cache_generate_file_hash(const char *file_path) { (void)file_path; return NULL; }
bool cache_is_entry_expired(const cache_entry_t *entry, int retention_days) {
    (void)entry; (void)retention_days; return true;
}
int cache_create_directory(const char *cache_dir) { (void)cache_dir; return 0; }

#else /* !__EMSCRIPTEN__ */

#define CACHE_VERSION "1.0"
#define CACHE_METADATA_FILE "cache_metadata.json"
#define CACHE_ENTRY_EXTENSION ".cache"
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define AES_TAG_SIZE 16

// Internal cache handle structure
struct cache_handle {
    cache_config_t config;
    cache_stats_t stats;
    pthread_mutex_t mutex;
    char *metadata_file_path;
    bool initialized;
};

// Default cache configuration
static const cache_config_t DEFAULT_CACHE_CONFIG = {
    .cache_dir = NULL,           // Will be set to ~/.cbom/cache
    .retention_days = 7,
    .enable_encryption = true,
    .encryption_key = NULL,      // Will be generated
    .max_cache_size_mb = 512,
    .enable_compression = false  // Disabled for now
};

// Generate a secure random encryption key
static char* generate_encryption_key(void) {
    unsigned char key_bytes[AES_KEY_SIZE];
    if (RAND_bytes(key_bytes, AES_KEY_SIZE) != 1) {
        return NULL;
    }
    
    char *hex_key = malloc(AES_KEY_SIZE * 2 + 1);
    if (hex_key == NULL) {
        return NULL;
    }
    
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        sprintf(hex_key + (i * 2), "%02x", key_bytes[i]);
    }
    hex_key[AES_KEY_SIZE * 2] = '\0';
    
    return hex_key;
}

// Convert hex string to bytes (currently unused but may be needed for encryption)
static int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
    if (strlen(hex) != bytes_len * 2) {
        return -1;
    }
    
    for (size_t i = 0; i < bytes_len; i++) {
        if (sscanf(hex + (i * 2), "%02hhx", &bytes[i]) != 1) {
            return -1;
        }
    }
    
    return 0;
}

// Suppress unused function warning for now
__attribute__((unused)) static int _hex_to_bytes_wrapper(const char *hex, unsigned char *bytes, size_t bytes_len) {
    return hex_to_bytes(hex, bytes, bytes_len);
}

// Get default cache directory
static char* get_default_cache_dir(void) {
    const char *home = getenv("HOME");
    if (home == NULL) {
        home = "/tmp";
    }
    
    char *cache_dir = malloc(strlen(home) + 20);
    if (cache_dir == NULL) {
        return NULL;
    }
    
    sprintf(cache_dir, "%s/.cbom/cache", home);
    return cache_dir;
}

// Create cache directory if it doesn't exist
int cache_create_directory(const char *cache_dir) {
    if (cache_dir == NULL) {
        return -1;
    }
    
    struct stat st;
    if (stat(cache_dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // Directory already exists
        } else {
            return -1; // Path exists but is not a directory
        }
    }
    
    // Create parent directories recursively
    char *dir_copy = strdup(cache_dir);
    if (dir_copy == NULL) {
        return -1;
    }
    
    char *parent = dirname(dir_copy);
    if (strcmp(parent, cache_dir) != 0) {
        if (cache_create_directory(parent) != 0) {
            free(dir_copy);
            return -1;
        }
    }
    
    free(dir_copy);
    
    if (mkdir(cache_dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    
    return 0;
}

// Load cache metadata
static int load_cache_metadata(cache_handle_t *cache) {
    FILE *file = fopen(cache->metadata_file_path, "r");
    if (file == NULL) {
        // No metadata file exists, start fresh
        return 0;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(file);
        return -1;
    }
    
    if (fread(buffer, 1, file_size, file) != (size_t)file_size) {
        free(buffer);
        fclose(file);
        return -1;
    }
    buffer[file_size] = '\0';
    fclose(file);
    
    json_object *root = json_tokener_parse(buffer);
    free(buffer);
    
    if (root == NULL) {
        return -1;
    }
    
    // Load statistics
    json_object *stats_obj;
    if (json_object_object_get_ex(root, "stats", &stats_obj)) {
        json_object *val;
        
        if (json_object_object_get_ex(stats_obj, "cache_hits", &val)) {
            cache->stats.cache_hits = json_object_get_int64(val);
        }
        if (json_object_object_get_ex(stats_obj, "cache_misses", &val)) {
            cache->stats.cache_misses = json_object_get_int64(val);
        }
        if (json_object_object_get_ex(stats_obj, "last_cleanup", &val)) {
            cache->stats.last_cleanup = json_object_get_int64(val);
        }
    }
    
    json_object_put(root);
    return 0;
}

// Save cache metadata
static int save_cache_metadata(cache_handle_t *cache) {
    json_object *root = json_object_new_object();
    if (root == NULL) {
        return -1;
    }
    
    // Add version
    json_object_object_add(root, "version", json_object_new_string(CACHE_VERSION));
    json_object_object_add(root, "created", json_object_new_int64(time(NULL)));
    
    // Add statistics
    json_object *stats_obj = json_object_new_object();
    json_object_object_add(stats_obj, "cache_hits", 
                          json_object_new_int64(cache->stats.cache_hits));
    json_object_object_add(stats_obj, "cache_misses", 
                          json_object_new_int64(cache->stats.cache_misses));
    json_object_object_add(stats_obj, "last_cleanup", 
                          json_object_new_int64(cache->stats.last_cleanup));
    json_object_object_add(root, "stats", stats_obj);
    
    // Write to file
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    if (json_str == NULL) {
        json_object_put(root);
        return -1;
    }
    
    FILE *file = fopen(cache->metadata_file_path, "w");
    if (file == NULL) {
        json_object_put(root);
        return -1;
    }
    
    if (fprintf(file, "%s", json_str) < 0) {
        fclose(file);
        json_object_put(root);
        return -1;
    }
    
    fclose(file);
    json_object_put(root);
    return 0;
}

cache_handle_t* cache_create(const cache_config_t *config) {
    cache_handle_t *cache = malloc(sizeof(cache_handle_t));
    if (cache == NULL) {
        return NULL;
    }
    
    memset(cache, 0, sizeof(cache_handle_t));
    
    // Initialize configuration with defaults
    cache->config = DEFAULT_CACHE_CONFIG;
    
    if (config != NULL) {
        if (config->cache_dir != NULL) {
            cache->config.cache_dir = strdup(config->cache_dir);
        }
        if (config->retention_days > 0) {
            cache->config.retention_days = config->retention_days;
        }
        cache->config.enable_encryption = config->enable_encryption;
        if (config->encryption_key != NULL) {
            cache->config.encryption_key = strdup(config->encryption_key);
        }
        if (config->max_cache_size_mb > 0) {
            cache->config.max_cache_size_mb = config->max_cache_size_mb;
        }
        cache->config.enable_compression = config->enable_compression;
    }
    
    // Set default cache directory if not provided
    if (cache->config.cache_dir == NULL) {
        cache->config.cache_dir = get_default_cache_dir();
        if (cache->config.cache_dir == NULL) {
            cache_destroy(cache);
            return NULL;
        }
    }
    
    // Generate encryption key if not provided and encryption is enabled
    if (cache->config.enable_encryption && cache->config.encryption_key == NULL) {
        cache->config.encryption_key = generate_encryption_key();
        if (cache->config.encryption_key == NULL) {
            cache_destroy(cache);
            return NULL;
        }
    }
    
    // Create cache directory
    if (cache_create_directory(cache->config.cache_dir) != 0) {
        cache_destroy(cache);
        return NULL;
    }
    
    // Set metadata file path
    size_t path_len = strlen(cache->config.cache_dir) + strlen(CACHE_METADATA_FILE) + 2;
    cache->metadata_file_path = malloc(path_len);
    if (cache->metadata_file_path == NULL) {
        cache_destroy(cache);
        return NULL;
    }
    snprintf(cache->metadata_file_path, path_len, "%s/%s", 
             cache->config.cache_dir, CACHE_METADATA_FILE);
    
    // Initialize mutex
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        cache_destroy(cache);
        return NULL;
    }
    
    // Load existing metadata
    if (load_cache_metadata(cache) != 0) {
        // Non-fatal error, continue with fresh cache
    }
    
    cache->initialized = true;
    return cache;
}

void cache_destroy(cache_handle_t *cache) {
    if (cache == NULL) {
        return;
    }
    
    if (cache->initialized) {
        pthread_mutex_lock(&cache->mutex);
        
        // Save metadata before destroying
        save_cache_metadata(cache);
        
        pthread_mutex_unlock(&cache->mutex);
        pthread_mutex_destroy(&cache->mutex);
    }
    
    // Free configuration
    if (cache->config.cache_dir) {
        free(cache->config.cache_dir);
    }
    if (cache->config.encryption_key) {
        secure_free(cache->config.encryption_key, strlen(cache->config.encryption_key));
    }
    if (cache->metadata_file_path) {
        free(cache->metadata_file_path);
    }
    
    free(cache);
}

// Generate SHA-256 hash of file content
char* cache_generate_file_hash(const char *file_path) {
    if (file_path == NULL) {
        return NULL;
    }
    
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        return NULL;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fclose(file);
        return NULL;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    unsigned char buffer[8192];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return NULL;
        }
    }
    
    fclose(file);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len;
    
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Convert to hex string
    char *hex_hash = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (hex_hash == NULL) {
        return NULL;
    }
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    return hex_hash;
}

// Check if cache entry is expired
bool cache_is_entry_expired(const cache_entry_t *entry, int retention_days) {
    if (entry == NULL) {
        return true;
    }
    
    time_t now = time(NULL);
    time_t expiry_time = entry->cache_time + (retention_days * 24 * 60 * 60);
    
    return now > expiry_time;
}

// Validate file against cache entry
bool cache_validate_file(const cache_entry_t *entry, const char *file_path) {
    if (entry == NULL || file_path == NULL) {
        return false;
    }
    
    struct stat st;
    if (stat(file_path, &st) != 0) {
        return false; // File doesn't exist
    }
    
    // Check modification time and inode
    if (st.st_mtime != entry->mtime || st.st_ino != entry->inode || 
        st.st_size != entry->file_size) {
        return false;
    }
    
    // Optionally verify content hash for extra security
    char *current_hash = cache_generate_file_hash(file_path);
    if (current_hash == NULL) {
        return false;
    }
    
    bool valid = (strcmp(current_hash, entry->content_hash) == 0);
    free(current_hash);
    
    return valid;
}

// Update file metadata in cache entry
int cache_update_file_metadata(cache_entry_t *entry, const char *file_path) {
    if (entry == NULL || file_path == NULL) {
        return -1;
    }
    
    struct stat st;
    if (stat(file_path, &st) != 0) {
        return -1;
    }
    
    // Update metadata
    entry->mtime = st.st_mtime;
    entry->inode = st.st_ino;
    entry->file_size = st.st_size;
    entry->cache_time = time(NULL);
    
    // Update content hash
    if (entry->content_hash) {
        free(entry->content_hash);
    }
    entry->content_hash = cache_generate_file_hash(file_path);
    if (entry->content_hash == NULL) {
        return -1;
    }
    
    return 0;
}

cache_entry_t* cache_entry_create(const char *file_path) {
    if (file_path == NULL) {
        return NULL;
    }
    
    cache_entry_t *entry = malloc(sizeof(cache_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    
    memset(entry, 0, sizeof(cache_entry_t));
    
    entry->file_path = strdup(file_path);
    if (entry->file_path == NULL) {
        free(entry);
        return NULL;
    }
    
    // Initialize file metadata
    if (cache_update_file_metadata(entry, file_path) != 0) {
        cache_entry_destroy(entry);
        return NULL;
    }
    
    return entry;
}

void cache_entry_destroy(cache_entry_t *entry) {
    if (entry == NULL) {
        return;
    }
    
    if (entry->file_path) {
        free(entry->file_path);
    }
    if (entry->content_hash) {
        free(entry->content_hash);
    }
    if (entry->asset_ids) {
        free(entry->asset_ids);
    }
    
    secure_zero(entry, sizeof(cache_entry_t));
    free(entry);
}

cache_entry_t* cache_entry_clone(const cache_entry_t *entry) {
    if (entry == NULL) {
        return NULL;
    }
    
    cache_entry_t *clone = malloc(sizeof(cache_entry_t));
    if (clone == NULL) {
        return NULL;
    }
    
    memcpy(clone, entry, sizeof(cache_entry_t));
    
    // Deep copy strings
    clone->file_path = entry->file_path ? strdup(entry->file_path) : NULL;
    clone->content_hash = entry->content_hash ? strdup(entry->content_hash) : NULL;
    clone->asset_ids = entry->asset_ids ? strdup(entry->asset_ids) : NULL;
    
    return clone;
}

// Get cache file path for a given file
static char* get_cache_file_path(cache_handle_t *cache, const char *file_path) {
    if (cache == NULL || file_path == NULL) {
        return NULL;
    }
    
    // Generate hash of file path for cache filename
    char *path_hash = cache_generate_file_hash(file_path);
    if (path_hash == NULL) {
        return NULL;
    }
    
    size_t cache_path_len = strlen(cache->config.cache_dir) + strlen(path_hash) + 
                           strlen(CACHE_ENTRY_EXTENSION) + 2;
    char *cache_file_path = malloc(cache_path_len);
    if (cache_file_path == NULL) {
        free(path_hash);
        return NULL;
    }
    
    snprintf(cache_file_path, cache_path_len, "%s/%s%s", 
             cache->config.cache_dir, path_hash, CACHE_ENTRY_EXTENSION);
    
    free(path_hash);
    return cache_file_path;
}

// Serialize cache entry to JSON
static char* serialize_cache_entry(const cache_entry_t *entry) {
    if (entry == NULL) {
        return NULL;
    }
    
    json_object *root = json_object_new_object();
    if (root == NULL) {
        return NULL;
    }
    
    json_object_object_add(root, "file_path", json_object_new_string(entry->file_path));
    json_object_object_add(root, "content_hash", json_object_new_string(entry->content_hash));
    json_object_object_add(root, "mtime", json_object_new_int64(entry->mtime));
    json_object_object_add(root, "inode", json_object_new_int64(entry->inode));
    json_object_object_add(root, "file_size", json_object_new_int64(entry->file_size));
    json_object_object_add(root, "cache_time", json_object_new_int64(entry->cache_time));
    json_object_object_add(root, "asset_count", json_object_new_int64(entry->asset_count));
    json_object_object_add(root, "is_encrypted", json_object_new_boolean(entry->is_encrypted));
    
    if (entry->asset_ids) {
        json_object_object_add(root, "asset_ids", json_object_new_string(entry->asset_ids));
    }
    
    const char *json_str = json_object_to_json_string(root);
    char *result = json_str ? strdup(json_str) : NULL;
    
    json_object_put(root);
    return result;
}

// Deserialize cache entry from JSON
static cache_entry_t* deserialize_cache_entry(const char *json_str) {
    if (json_str == NULL) {
        return NULL;
    }
    
    json_object *root = json_tokener_parse(json_str);
    if (root == NULL) {
        return NULL;
    }
    
    cache_entry_t *entry = malloc(sizeof(cache_entry_t));
    if (entry == NULL) {
        json_object_put(root);
        return NULL;
    }
    
    memset(entry, 0, sizeof(cache_entry_t));
    
    json_object *val;
    
    if (json_object_object_get_ex(root, "file_path", &val)) {
        entry->file_path = strdup(json_object_get_string(val));
    }
    if (json_object_object_get_ex(root, "content_hash", &val)) {
        entry->content_hash = strdup(json_object_get_string(val));
    }
    if (json_object_object_get_ex(root, "mtime", &val)) {
        entry->mtime = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "inode", &val)) {
        entry->inode = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "file_size", &val)) {
        entry->file_size = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "cache_time", &val)) {
        entry->cache_time = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "asset_count", &val)) {
        entry->asset_count = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "is_encrypted", &val)) {
        entry->is_encrypted = json_object_get_boolean(val);
    }
    if (json_object_object_get_ex(root, "asset_ids", &val)) {
        entry->asset_ids = strdup(json_object_get_string(val));
    }
    
    json_object_put(root);
    return entry;
}

int cache_get_entry(cache_handle_t *cache, const char *file_path, cache_entry_t **entry) {
    if (cache == NULL || file_path == NULL || entry == NULL) {
        return -1;
    }
    
    *entry = NULL;
    
    pthread_mutex_lock(&cache->mutex);
    
    char *cache_file_path = get_cache_file_path(cache, file_path);
    if (cache_file_path == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    FILE *file = fopen(cache_file_path, "r");
    if (file == NULL) {
        free(cache_file_path);
        cache->stats.cache_misses++;
        pthread_mutex_unlock(&cache->mutex);
        return 0; // Cache miss, not an error
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(file);
        free(cache_file_path);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    if (fread(buffer, 1, file_size, file) != (size_t)file_size) {
        free(buffer);
        fclose(file);
        free(cache_file_path);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    buffer[file_size] = '\0';
    fclose(file);
    free(cache_file_path);
    
    cache_entry_t *cached_entry = deserialize_cache_entry(buffer);
    free(buffer);
    
    if (cached_entry == NULL) {
        cache->stats.invalid_entries++;
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    // Check if entry is expired
    if (cache_is_entry_expired(cached_entry, cache->config.retention_days)) {
        cache_entry_destroy(cached_entry);
        cache->stats.expired_entries++;
        cache->stats.cache_misses++;
        pthread_mutex_unlock(&cache->mutex);
        return 0; // Expired entry, treat as cache miss
    }
    
    // Validate file hasn't changed
    if (!cache_validate_file(cached_entry, file_path)) {
        cache_entry_destroy(cached_entry);
        cache->stats.invalid_entries++;
        cache->stats.cache_misses++;
        pthread_mutex_unlock(&cache->mutex);
        return 0; // File changed, treat as cache miss
    }
    
    *entry = cached_entry;
    cache->stats.cache_hits++;
    cache->stats.hit_rate = (double)cache->stats.cache_hits / 
                           (cache->stats.cache_hits + cache->stats.cache_misses) * 100.0;
    
    pthread_mutex_unlock(&cache->mutex);
    return 1; // Cache hit
}

int cache_put_entry(cache_handle_t *cache, const char *file_path, 
                   const char **asset_ids, size_t asset_count) {
    if (cache == NULL || file_path == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->mutex);
    
    cache_entry_t *entry = cache_entry_create(file_path);
    if (entry == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    entry->asset_count = asset_count;
    
    // Serialize asset IDs to JSON array
    if (asset_ids != NULL && asset_count > 0) {
        json_object *array = json_object_new_array();
        if (array == NULL) {
            cache_entry_destroy(entry);
            pthread_mutex_unlock(&cache->mutex);
            return -1;
        }
        
        for (size_t i = 0; i < asset_count; i++) {
            json_object_array_add(array, json_object_new_string(asset_ids[i]));
        }
        
        const char *json_str = json_object_to_json_string(array);
        entry->asset_ids = json_str ? strdup(json_str) : NULL;
        json_object_put(array);
        
        if (entry->asset_ids == NULL) {
            cache_entry_destroy(entry);
            pthread_mutex_unlock(&cache->mutex);
            return -1;
        }
    }
    
    // Serialize entry to JSON
    char *serialized = serialize_cache_entry(entry);
    if (serialized == NULL) {
        cache_entry_destroy(entry);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    // Write to cache file
    char *cache_file_path = get_cache_file_path(cache, file_path);
    if (cache_file_path == NULL) {
        free(serialized);
        cache_entry_destroy(entry);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    FILE *file = fopen(cache_file_path, "w");
    if (file == NULL) {
        free(cache_file_path);
        free(serialized);
        cache_entry_destroy(entry);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    if (fprintf(file, "%s", serialized) < 0) {
        fclose(file);
        free(cache_file_path);
        free(serialized);
        cache_entry_destroy(entry);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    fclose(file);
    free(cache_file_path);
    free(serialized);
    cache_entry_destroy(entry);
    
    cache->stats.total_entries++;
    
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

bool cache_is_file_cached(cache_handle_t *cache, const char *file_path) {
    cache_entry_t *entry = NULL;
    int result = cache_get_entry(cache, file_path, &entry);
    
    if (result == 1 && entry != NULL) {
        cache_entry_destroy(entry);
        return true;
    }
    
    return false;
}

int cache_invalidate_entry(cache_handle_t *cache, const char *file_path) {
    if (cache == NULL || file_path == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->mutex);
    
    char *cache_file_path = get_cache_file_path(cache, file_path);
    if (cache_file_path == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    int result = unlink(cache_file_path);
    free(cache_file_path);
    
    if (result == 0) {
        cache->stats.total_entries--;
    }
    
    pthread_mutex_unlock(&cache->mutex);
    return result;
}

int cache_cleanup_expired(cache_handle_t *cache) {
    if (cache == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->mutex);
    
    DIR *dir = opendir(cache->config.cache_dir);
    if (dir == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    struct dirent *entry;
    int cleaned_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, CACHE_ENTRY_EXTENSION) == NULL) {
            continue; // Not a cache entry file
        }
        
        char *full_path = malloc(strlen(cache->config.cache_dir) + strlen(entry->d_name) + 2);
        if (full_path == NULL) {
            continue;
        }
        
        sprintf(full_path, "%s/%s", cache->config.cache_dir, entry->d_name);
        
        // Read and check if expired
        FILE *file = fopen(full_path, "r");
        if (file == NULL) {
            free(full_path);
            continue;
        }
        
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        char *buffer = malloc(file_size + 1);
        if (buffer == NULL) {
            fclose(file);
            free(full_path);
            continue;
        }
        
        if (fread(buffer, 1, file_size, file) == (size_t)file_size) {
            buffer[file_size] = '\0';
            cache_entry_t *cached_entry = deserialize_cache_entry(buffer);
            
            if (cached_entry != NULL) {
                if (cache_is_entry_expired(cached_entry, cache->config.retention_days)) {
                    unlink(full_path);
                    cleaned_count++;
                    cache->stats.expired_entries++;
                }
                cache_entry_destroy(cached_entry);
            }
        }
        
        free(buffer);
        fclose(file);
        free(full_path);
    }
    
    closedir(dir);
    
    cache->stats.last_cleanup = time(NULL);
    cache->stats.total_entries -= cleaned_count;
    
    pthread_mutex_unlock(&cache->mutex);
    return cleaned_count;
}

int cache_cleanup_invalid(cache_handle_t *cache) {
    if (cache == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->mutex);
    
    DIR *dir = opendir(cache->config.cache_dir);
    if (dir == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    struct dirent *entry;
    int cleaned_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, CACHE_ENTRY_EXTENSION) == NULL) {
            continue;
        }
        
        char *full_path = malloc(strlen(cache->config.cache_dir) + strlen(entry->d_name) + 2);
        if (full_path == NULL) {
            continue;
        }
        
        sprintf(full_path, "%s/%s", cache->config.cache_dir, entry->d_name);
        
        FILE *file = fopen(full_path, "r");
        if (file == NULL) {
            free(full_path);
            continue;
        }
        
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        char *buffer = malloc(file_size + 1);
        if (buffer == NULL) {
            fclose(file);
            free(full_path);
            continue;
        }
        
        if (fread(buffer, 1, file_size, file) == (size_t)file_size) {
            buffer[file_size] = '\0';
            cache_entry_t *cached_entry = deserialize_cache_entry(buffer);
            
            if (cached_entry != NULL) {
                if (!cache_validate_file(cached_entry, cached_entry->file_path)) {
                    unlink(full_path);
                    cleaned_count++;
                    cache->stats.invalid_entries++;
                }
                cache_entry_destroy(cached_entry);
            }
        }
        
        free(buffer);
        fclose(file);
        free(full_path);
    }
    
    closedir(dir);
    cache->stats.total_entries -= cleaned_count;
    
    pthread_mutex_unlock(&cache->mutex);
    return cleaned_count;
}

int cache_full_cleanup(cache_handle_t *cache) {
    if (cache == NULL) {
        return -1;
    }
    
    int expired = cache_cleanup_expired(cache);
    int invalid = cache_cleanup_invalid(cache);
    
    return (expired >= 0 && invalid >= 0) ? (expired + invalid) : -1;
}

cache_stats_t cache_get_stats(cache_handle_t *cache) {
    cache_stats_t stats = {0};
    
    if (cache == NULL) {
        return stats;
    }
    
    pthread_mutex_lock(&cache->mutex);
    stats = cache->stats;
    pthread_mutex_unlock(&cache->mutex);
    
    return stats;
}

void cache_reset_stats(cache_handle_t *cache) {
    if (cache == NULL) {
        return;
    }
    
    pthread_mutex_lock(&cache->mutex);
    memset(&cache->stats, 0, sizeof(cache_stats_t));
    pthread_mutex_unlock(&cache->mutex);
}

int cache_export_stats(cache_handle_t *cache, const char *output_file) {
    if (cache == NULL || output_file == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->mutex);
    
    json_object *root = json_object_new_object();
    if (root == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    json_object_object_add(root, "total_entries", 
                          json_object_new_int64(cache->stats.total_entries));
    json_object_object_add(root, "cache_hits", 
                          json_object_new_int64(cache->stats.cache_hits));
    json_object_object_add(root, "cache_misses", 
                          json_object_new_int64(cache->stats.cache_misses));
    json_object_object_add(root, "expired_entries", 
                          json_object_new_int64(cache->stats.expired_entries));
    json_object_object_add(root, "invalid_entries", 
                          json_object_new_int64(cache->stats.invalid_entries));
    json_object_object_add(root, "hit_rate", 
                          json_object_new_double(cache->stats.hit_rate));
    json_object_object_add(root, "cache_size_bytes", 
                          json_object_new_int64(cache->stats.cache_size_bytes));
    json_object_object_add(root, "last_cleanup", 
                          json_object_new_int64(cache->stats.last_cleanup));
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    if (json_str == NULL) {
        json_object_put(root);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    FILE *file = fopen(output_file, "w");
    if (file == NULL) {
        json_object_put(root);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    if (fprintf(file, "%s", json_str) < 0) {
        fclose(file);
        json_object_put(root);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    fclose(file);
    json_object_put(root);
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

#endif /* !__EMSCRIPTEN__ */
