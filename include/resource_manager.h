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

#ifndef RESOURCE_MANAGER_H
#define RESOURCE_MANAGER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Resource limits configuration
typedef struct {
    size_t max_open_files;       // Maximum number of open file handles
    size_t max_total_bytes;      // Maximum total bytes to process
    size_t max_bytes_per_file;   // Maximum bytes per individual file
    size_t max_concurrency;      // Maximum concurrent operations
    size_t memory_watermark;     // Memory usage threshold for back-pressure
    char* temp_dir_path;         // Temporary directory path (must be noexec)
    bool enforce_noexec;         // Enforce noexec mount for temp directory
} resource_limits_t;

// Resource usage tracking
typedef struct {
    size_t open_files;           // Currently open file handles
    size_t total_bytes_processed; // Total bytes processed so far
    size_t memory_usage;         // Current memory usage estimate
    size_t active_operations;    // Currently active operations
    pthread_mutex_t mutex;       // Thread safety
} resource_usage_t;

// File handle pool entry
typedef struct file_handle_entry {
    int fd;                      // File descriptor
    char* path;                  // File path
    time_t last_used;            // Last access time for LRU
    bool in_use;                 // Currently in use flag
    struct file_handle_entry* next; // LRU linked list
} file_handle_entry_t;

// File handle pool with LRU eviction
typedef struct {
    file_handle_entry_t** buckets; // Hash table buckets
    size_t bucket_count;         // Number of hash buckets
    file_handle_entry_t* lru_head; // LRU list head (most recent)
    file_handle_entry_t* lru_tail; // LRU list tail (least recent)
    size_t pool_size;            // Current pool size
    size_t max_pool_size;        // Maximum pool size
    pthread_mutex_t mutex;       // Thread safety
} file_handle_pool_t;

// Resource manager
typedef struct {
    resource_limits_t limits;    // Resource limits configuration
    resource_usage_t usage;      // Current resource usage
    file_handle_pool_t* file_pool; // File handle pool
    bool streaming_mode;         // Enable streaming mode for large datasets
    char* fallback_temp_dir;     // Fallback temp directory if primary fails
    pthread_mutex_t mutex;       // Thread safety
} resource_manager_t;

// Resource manager operations
resource_manager_t* resource_manager_create(const resource_limits_t* limits);
void resource_manager_destroy(resource_manager_t* manager);

// Resource limit checking
bool resource_manager_can_open_file(resource_manager_t* manager, size_t file_size);
bool resource_manager_can_allocate_memory(resource_manager_t* manager, size_t size);
bool resource_manager_can_start_operation(resource_manager_t* manager);

// Resource allocation/deallocation
int resource_manager_open_file(resource_manager_t* manager, const char* path, int flags);
void resource_manager_close_file(resource_manager_t* manager, int fd);
void* resource_manager_allocate_memory(resource_manager_t* manager, size_t size);
void resource_manager_free_memory(resource_manager_t* manager, void* ptr, size_t size);
int resource_manager_start_operation(resource_manager_t* manager);
void resource_manager_end_operation(resource_manager_t* manager);

// Temporary file handling with noexec enforcement
int resource_manager_create_temp_file(resource_manager_t* manager, char** temp_path);
int resource_manager_create_temp_dir(resource_manager_t* manager, char** temp_dir_path);
bool resource_manager_validate_temp_path(resource_manager_t* manager, const char* path);

// Streaming mode for large datasets
bool resource_manager_enable_streaming_mode(resource_manager_t* manager);
void resource_manager_disable_streaming_mode(resource_manager_t* manager);
size_t resource_manager_get_chunk_size(resource_manager_t* manager);

// Resource usage reporting
typedef struct {
    double file_handle_utilization;  // Percentage of file handles used
    double memory_utilization;       // Percentage of memory limit used
    double operation_utilization;    // Percentage of concurrency limit used
    size_t total_bytes_processed;    // Total bytes processed
    size_t cache_hit_rate;           // File handle pool cache hit rate
} resource_stats_t;

resource_stats_t resource_manager_get_stats(resource_manager_t* manager);

// File handle pool operations
file_handle_pool_t* file_handle_pool_create(size_t max_size);
void file_handle_pool_destroy(file_handle_pool_t* pool);
int file_handle_pool_get(file_handle_pool_t* pool, const char* path, int flags);
void file_handle_pool_return(file_handle_pool_t* pool, int fd);
void file_handle_pool_evict_lru(file_handle_pool_t* pool);

// Utility functions
bool is_noexec_mount(const char* path);
char* find_noexec_temp_dir(void);
size_t get_available_memory(void);
size_t get_file_size(const char* path);

// CLI argument parsing helpers
resource_limits_t* parse_resource_limits_from_args(int argc, char** argv);
void print_resource_limits_help(void);

#ifdef __cplusplus
}
#endif

#endif // RESOURCE_MANAGER_H
