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
#include "resource_manager.h"
#include "secure_memory.h"
#include "error_handling.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

// Default resource limits
static const resource_limits_t DEFAULT_LIMITS = {
    .max_open_files = 1024,
#if SIZE_MAX > 0xFFFFFFFF
    .max_total_bytes = 100ULL * 1024 * 1024 * 1024, // 100GB
    .max_bytes_per_file = 1024 * 1024 * 1024,        // 1GB
    .memory_watermark = 512 * 1024 * 1024,           // 512MB
#else
    .max_total_bytes = (size_t)2 * 1024 * 1024 * 1024 - 1, // ~2GB (32-bit max)
    .max_bytes_per_file = 256 * 1024 * 1024,         // 256MB
    .memory_watermark = 64 * 1024 * 1024,            // 64MB
#endif
    .max_concurrency = 32,
    .temp_dir_path = NULL,
    .enforce_noexec = true
};

// Hash function for file paths
static size_t hash_path(const char* path, size_t bucket_count) {
    size_t hash = 5381;
    for (const char* p = path; *p; p++) {
        hash = ((hash << 5) + hash) + *p;
    }
    return hash % bucket_count;
}

// Check if a path is on a noexec mount
bool is_noexec_mount(const char* path) {
    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) {
        return false; // Assume not noexec if we can't check
    }
    return (vfs.f_flag & ST_NOEXEC) != 0;
}

// Find a suitable noexec temporary directory
char* find_noexec_temp_dir(void) {
    const char* candidates[] = {
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        NULL
    };
    
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], W_OK) == 0) {
            if (is_noexec_mount(candidates[i])) {
                return strdup(candidates[i]);
            }
        }
    }
    
    // Fallback to /tmp even if not noexec (common on dev systems)
    return strdup("/tmp");
}

// Get available system memory
size_t get_available_memory(void) {
    FILE* meminfo = fopen("/proc/meminfo", "r");
    if (!meminfo) {
        return 1024 * 1024 * 1024; // Default to 1GB if can't read
    }
    
    char line[256];
    size_t available = 0;
    
    while (fgets(line, sizeof(line), meminfo)) {
        if (strncmp(line, "MemAvailable:", 13) == 0) {
            sscanf(line, "MemAvailable: %zu kB", &available);
            available *= 1024; // Convert to bytes
            break;
        }
    }
    
    fclose(meminfo);
    return available > 0 ? available : 1024 * 1024 * 1024;
}

// Get file size
size_t get_file_size(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return st.st_size;
}

// Create file handle pool
file_handle_pool_t* file_handle_pool_create(size_t max_size) {
    file_handle_pool_t* pool = secure_alloc(sizeof(file_handle_pool_t));
    if (!pool) return NULL;
    
    pool->bucket_count = max_size / 4; // 4 entries per bucket on average
    if (pool->bucket_count < 16) pool->bucket_count = 16;
    
    pool->buckets = secure_alloc(pool->bucket_count * sizeof(file_handle_entry_t*));
    if (!pool->buckets) {
        secure_free(pool, sizeof(file_handle_pool_t));
        return NULL;
    }
    
    memset(pool->buckets, 0, pool->bucket_count * sizeof(file_handle_entry_t*));
    pool->lru_head = NULL;
    pool->lru_tail = NULL;
    pool->pool_size = 0;
    pool->max_pool_size = max_size;
    
    if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
        secure_free(pool->buckets, pool->bucket_count * sizeof(file_handle_entry_t*));
        secure_free(pool, sizeof(file_handle_pool_t));
        return NULL;
    }
    
    return pool;
}

// Destroy file handle pool
void file_handle_pool_destroy(file_handle_pool_t* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->mutex);
    
    // Close all file handles and free entries
    for (size_t i = 0; i < pool->bucket_count; i++) {
        file_handle_entry_t* entry = pool->buckets[i];
        while (entry) {
            file_handle_entry_t* next = entry->next;
            if (entry->fd >= 0) {
                close(entry->fd);
            }
            if (entry->path) {
                secure_free(entry->path, strlen(entry->path));
            }
            secure_free(entry, sizeof(file_handle_entry_t));
            entry = next;
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    pthread_mutex_destroy(&pool->mutex);
    
    secure_free(pool->buckets, pool->bucket_count * sizeof(file_handle_entry_t*));
    secure_free(pool, sizeof(file_handle_pool_t));
}

// Get file handle from pool (or open new one)
int file_handle_pool_get(file_handle_pool_t* pool, const char* path, int flags) {
    if (!pool || !path) return -1;
    
    pthread_mutex_lock(&pool->mutex);
    
    size_t bucket = hash_path(path, pool->bucket_count);
    file_handle_entry_t* entry = pool->buckets[bucket];
    
    // Look for existing entry
    while (entry) {
        if (entry->path && strcmp(entry->path, path) == 0 && !entry->in_use) {
            entry->in_use = true;
            entry->last_used = time(NULL);
            
            // Move to head of LRU list
            if (entry != pool->lru_head) {
                // Remove from current position
                if (entry->next) entry->next = entry->next;
                if (entry == pool->lru_tail) pool->lru_tail = entry->next;
                
                // Add to head
                entry->next = pool->lru_head;
                pool->lru_head = entry;
                if (!pool->lru_tail) pool->lru_tail = entry;
            }
            
            pthread_mutex_unlock(&pool->mutex);
            return entry->fd;
        }
        entry = entry->next;
    }
    
    // Need to open new file
    int fd = open(path, flags);
    if (fd < 0) {
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    
    // Check if we need to evict entries
    if (pool->pool_size >= pool->max_pool_size) {
        file_handle_pool_evict_lru(pool);
    }
    
    // Create new entry
    entry = secure_alloc(sizeof(file_handle_entry_t));
    if (!entry) {
        close(fd);
        pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    
    entry->fd = fd;
    entry->path = strdup(path);
    entry->last_used = time(NULL);
    entry->in_use = true;
    entry->next = pool->buckets[bucket];
    pool->buckets[bucket] = entry;
    pool->pool_size++;
    
    // Add to head of LRU list
    entry->next = pool->lru_head;
    pool->lru_head = entry;
    if (!pool->lru_tail) pool->lru_tail = entry;
    
    pthread_mutex_unlock(&pool->mutex);
    return fd;
}

// Return file handle to pool
void file_handle_pool_return(file_handle_pool_t* pool, int fd) {
    if (!pool || fd < 0) return;
    
    pthread_mutex_lock(&pool->mutex);
    
    // Find the entry with this fd
    for (size_t i = 0; i < pool->bucket_count; i++) {
        file_handle_entry_t* entry = pool->buckets[i];
        while (entry) {
            if (entry->fd == fd && entry->in_use) {
                entry->in_use = false;
                entry->last_used = time(NULL);
                break;
            }
            entry = entry->next;
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
}

// Evict least recently used entry
void file_handle_pool_evict_lru(file_handle_pool_t* pool) {
    if (!pool || !pool->lru_tail) return;
    
    file_handle_entry_t* lru = pool->lru_tail;
    if (lru->in_use) return; // Can't evict in-use entry
    
    // Remove from LRU list
    pool->lru_tail = lru->next;
    if (pool->lru_head == lru) pool->lru_head = NULL;
    
    // Remove from hash bucket
    size_t bucket = hash_path(lru->path, pool->bucket_count);
    file_handle_entry_t** entry_ptr = &pool->buckets[bucket];
    while (*entry_ptr && *entry_ptr != lru) {
        entry_ptr = &(*entry_ptr)->next;
    }
    if (*entry_ptr) {
        *entry_ptr = lru->next;
    }
    
    // Close file and free entry
    if (lru->fd >= 0) {
        close(lru->fd);
    }
    if (lru->path) {
        secure_free(lru->path, strlen(lru->path));
    }
    secure_free(lru, sizeof(file_handle_entry_t));
    pool->pool_size--;
}

// Create resource manager
resource_manager_t* resource_manager_create(const resource_limits_t* limits) {
    resource_manager_t* manager = secure_alloc(sizeof(resource_manager_t));
    if (!manager) return NULL;
    
    // Set limits (use defaults if not provided)
    if (limits) {
        manager->limits = *limits;
    } else {
        manager->limits = DEFAULT_LIMITS;
    }
    
    // Set up temp directory
    if (!manager->limits.temp_dir_path) {
        manager->limits.temp_dir_path = find_noexec_temp_dir();
    }
    
    // Validate temp directory - silently use fallback if not noexec
    if (manager->limits.enforce_noexec && !is_noexec_mount(manager->limits.temp_dir_path)) {
        manager->fallback_temp_dir = find_noexec_temp_dir();
    }
    
    // Initialize usage tracking
    memset(&manager->usage, 0, sizeof(resource_usage_t));
    if (pthread_mutex_init(&manager->usage.mutex, NULL) != 0) {
        secure_free(manager, sizeof(resource_manager_t));
        return NULL;
    }
    
    // Create file handle pool
    manager->file_pool = file_handle_pool_create(manager->limits.max_open_files);
    if (!manager->file_pool) {
        pthread_mutex_destroy(&manager->usage.mutex);
        secure_free(manager, sizeof(resource_manager_t));
        return NULL;
    }
    
    manager->streaming_mode = false;
    
    if (pthread_mutex_init(&manager->mutex, NULL) != 0) {
        file_handle_pool_destroy(manager->file_pool);
        pthread_mutex_destroy(&manager->usage.mutex);
        secure_free(manager, sizeof(resource_manager_t));
        return NULL;
    }
    
    return manager;
}

// Destroy resource manager
void resource_manager_destroy(resource_manager_t* manager) {
    if (!manager) return;
    
    pthread_mutex_lock(&manager->mutex);
    
    if (manager->file_pool) {
        file_handle_pool_destroy(manager->file_pool);
    }
    
    if (manager->limits.temp_dir_path) {
        free(manager->limits.temp_dir_path);
    }
    
    if (manager->fallback_temp_dir) {
        free(manager->fallback_temp_dir);
    }
    
    pthread_mutex_unlock(&manager->mutex);
    pthread_mutex_destroy(&manager->mutex);
    pthread_mutex_destroy(&manager->usage.mutex);
    
    secure_free(manager, sizeof(resource_manager_t));
}

// Check if we can open a file
bool resource_manager_can_open_file(resource_manager_t* manager, size_t file_size) {
    if (!manager) return false;
    
    pthread_mutex_lock(&manager->usage.mutex);
    
    bool can_open = true;
    
    // Check file size limit
    if (file_size > manager->limits.max_bytes_per_file) {
        can_open = false;
    }
    
    // Check total bytes limit
    if (manager->usage.total_bytes_processed + file_size > manager->limits.max_total_bytes) {
        can_open = false;
    }
    
    // Check file handle limit
    if (manager->usage.open_files >= manager->limits.max_open_files) {
        can_open = false;
    }
    
    pthread_mutex_unlock(&manager->usage.mutex);
    return can_open;
}

// Check if we can allocate memory
bool resource_manager_can_allocate_memory(resource_manager_t* manager, size_t size) {
    if (!manager) return false;
    
    pthread_mutex_lock(&manager->usage.mutex);
    
    bool can_allocate = (manager->usage.memory_usage + size) <= manager->limits.memory_watermark;
    
    pthread_mutex_unlock(&manager->usage.mutex);
    return can_allocate;
}

// Check if we can start an operation
bool resource_manager_can_start_operation(resource_manager_t* manager) {
    if (!manager) return false;
    
    pthread_mutex_lock(&manager->usage.mutex);
    
    bool can_start = manager->usage.active_operations < manager->limits.max_concurrency;
    
    pthread_mutex_unlock(&manager->usage.mutex);
    return can_start;
}

// Open file through resource manager
int resource_manager_open_file(resource_manager_t* manager, const char* path, int flags) {
    if (!manager || !path) return -1;
    
    size_t file_size = get_file_size(path);
    if (!resource_manager_can_open_file(manager, file_size)) {
        errno = EDQUOT; // Quota exceeded
        return -1;
    }
    
    int fd = file_handle_pool_get(manager->file_pool, path, flags);
    if (fd >= 0) {
        pthread_mutex_lock(&manager->usage.mutex);
        manager->usage.open_files++;
        manager->usage.total_bytes_processed += file_size;
        pthread_mutex_unlock(&manager->usage.mutex);
    }
    
    return fd;
}

// Close file through resource manager
void resource_manager_close_file(resource_manager_t* manager, int fd) {
    if (!manager || fd < 0) return;
    
    file_handle_pool_return(manager->file_pool, fd);
    
    pthread_mutex_lock(&manager->usage.mutex);
    if (manager->usage.open_files > 0) {
        manager->usage.open_files--;
    }
    pthread_mutex_unlock(&manager->usage.mutex);
}

// Allocate memory through resource manager
void* resource_manager_allocate_memory(resource_manager_t* manager, size_t size) {
    if (!manager || !resource_manager_can_allocate_memory(manager, size)) {
        return NULL;
    }
    
    void* ptr = secure_alloc(size);
    if (ptr) {
        pthread_mutex_lock(&manager->usage.mutex);
        manager->usage.memory_usage += size;
        pthread_mutex_unlock(&manager->usage.mutex);
    }
    
    return ptr;
}

// Free memory through resource manager
void resource_manager_free_memory(resource_manager_t* manager, void* ptr, size_t size) {
    if (!manager || !ptr) return;
    
    secure_free(ptr, size);
    
    pthread_mutex_lock(&manager->usage.mutex);
    if (manager->usage.memory_usage >= size) {
        manager->usage.memory_usage -= size;
    }
    pthread_mutex_unlock(&manager->usage.mutex);
}

// Start operation
int resource_manager_start_operation(resource_manager_t* manager) {
    if (!manager || !resource_manager_can_start_operation(manager)) {
        return -1;
    }
    
    pthread_mutex_lock(&manager->usage.mutex);
    manager->usage.active_operations++;
    pthread_mutex_unlock(&manager->usage.mutex);
    
    return 0;
}

// End operation
void resource_manager_end_operation(resource_manager_t* manager) {
    if (!manager) return;
    
    pthread_mutex_lock(&manager->usage.mutex);
    if (manager->usage.active_operations > 0) {
        manager->usage.active_operations--;
    }
    pthread_mutex_unlock(&manager->usage.mutex);
}

// Create temporary file
int resource_manager_create_temp_file(resource_manager_t* manager, char** temp_path) {
    if (!manager || !temp_path) return -1;
    
    const char* temp_dir = manager->limits.temp_dir_path;
    
    // Use fallback if primary temp dir is not noexec
    if (manager->limits.enforce_noexec && !is_noexec_mount(temp_dir) && manager->fallback_temp_dir) {
        temp_dir = manager->fallback_temp_dir;
    }

    char template[PATH_MAX];
    snprintf(template, sizeof(template), "%s/cbom_XXXXXX", temp_dir);
    
    int fd = mkstemp(template);
    if (fd >= 0) {
        *temp_path = strdup(template);
    }
    
    return fd;
}

// Create temporary directory
int resource_manager_create_temp_dir(resource_manager_t* manager, char** temp_dir_path) {
    if (!manager || !temp_dir_path) return -1;
    
    const char* temp_dir = manager->limits.temp_dir_path;
    
    // Use fallback if primary temp dir is not noexec
    if (manager->limits.enforce_noexec && !is_noexec_mount(temp_dir) && manager->fallback_temp_dir) {
        temp_dir = manager->fallback_temp_dir;
    }

    char template[PATH_MAX];
    snprintf(template, sizeof(template), "%s/cbom_dir_XXXXXX", temp_dir);
    
    if (mkdtemp(template)) {
        *temp_dir_path = strdup(template);
        return 0;
    }
    
    return -1;
}

// Validate temp path
bool resource_manager_validate_temp_path(resource_manager_t* manager, const char* path) {
    if (!manager || !path) return false;
    
    if (manager->limits.enforce_noexec) {
        return is_noexec_mount(path);
    }
    
    return true;
}

// Enable streaming mode
bool resource_manager_enable_streaming_mode(resource_manager_t* manager) {
    if (!manager) return false;
    
    pthread_mutex_lock(&manager->mutex);
    manager->streaming_mode = true;
    pthread_mutex_unlock(&manager->mutex);
    
    return true;
}

// Disable streaming mode
void resource_manager_disable_streaming_mode(resource_manager_t* manager) {
    if (!manager) return;
    
    pthread_mutex_lock(&manager->mutex);
    manager->streaming_mode = false;
    pthread_mutex_unlock(&manager->mutex);
}

// Get chunk size for streaming
size_t resource_manager_get_chunk_size(resource_manager_t* manager) {
    if (!manager) return 64 * 1024; // Default 64KB
    
    // Use 1/10th of memory watermark as chunk size
    return manager->limits.memory_watermark / 10;
}

// Get resource statistics
resource_stats_t resource_manager_get_stats(resource_manager_t* manager) {
    resource_stats_t stats = {0};
    
    if (!manager) return stats;
    
    pthread_mutex_lock(&manager->usage.mutex);
    
    stats.file_handle_utilization = (double)manager->usage.open_files / manager->limits.max_open_files * 100.0;
    stats.memory_utilization = (double)manager->usage.memory_usage / manager->limits.memory_watermark * 100.0;
    stats.operation_utilization = (double)manager->usage.active_operations / manager->limits.max_concurrency * 100.0;
    stats.total_bytes_processed = manager->usage.total_bytes_processed;
    
    // Calculate cache hit rate (simplified)
    stats.cache_hit_rate = 85.0; // Placeholder - would track actual hits/misses
    
    pthread_mutex_unlock(&manager->usage.mutex);
    
    return stats;
}

// Parse resource limits from command line arguments
resource_limits_t* parse_resource_limits_from_args(int argc, char** argv) {
    resource_limits_t* limits = secure_alloc(sizeof(resource_limits_t));
    if (!limits) return NULL;
    
    *limits = DEFAULT_LIMITS;
    
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--max-open-files") == 0) {
            limits->max_open_files = strtoul(argv[i + 1], NULL, 10);
            i++;
        } else if (strcmp(argv[i], "--max-total-bytes") == 0) {
            limits->max_total_bytes = strtoull(argv[i + 1], NULL, 10);
            i++;
        } else if (strcmp(argv[i], "--max-bytes-per-file") == 0) {
            limits->max_bytes_per_file = strtoull(argv[i + 1], NULL, 10);
            i++;
        } else if (strcmp(argv[i], "--max-concurrency") == 0) {
            limits->max_concurrency = strtoul(argv[i + 1], NULL, 10);
            i++;
        }
    }
    
    return limits;
}

// Print help for resource limit options
void print_resource_limits_help(void) {
    printf("Resource Limit Options:\n");
    printf("  --max-open-files N      Maximum number of open file handles (default: 1024)\n");
    printf("  --max-total-bytes N     Maximum total bytes to process (default: 100GB)\n");
    printf("  --max-bytes-per-file N  Maximum bytes per individual file (default: 1GB)\n");
    printf("  --max-concurrency N     Maximum concurrent operations (default: 32)\n");
    printf("\n");
}
