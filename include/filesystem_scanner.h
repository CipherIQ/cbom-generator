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

#ifndef FILESYSTEM_SCANNER_H
#define FILESYSTEM_SCANNER_H

#include "cbom_types.h"
#include "resource_manager.h"
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// File type enumeration for filtering
typedef enum {
    FILE_TYPE_UNKNOWN = 0,
    FILE_TYPE_CERTIFICATE,      // .pem, .crt, .cer, .der, .p12, .pfx
    FILE_TYPE_KEY,              // .key, .pem (private keys)
    FILE_TYPE_OPENPGP_KEY,      // .asc, .gpg, GPG-KEY files
    FILE_TYPE_EXECUTABLE,       // ELF binaries
    FILE_TYPE_LIBRARY,          // .so, .a files
    FILE_TYPE_CONFIG,           // Configuration files (.conf, .cfg, .ini, .json, .xml, .yaml)
    FILE_TYPE_PACKAGE,          // Package files (.deb, .rpm, .pkg)
    FILE_TYPE_ARCHIVE,          // .tar, .zip, .jar, .war
    FILE_TYPE_TEXT,             // Plain text files
    FILE_TYPE_DIRECTORY
} file_type_t;

// Container detection result
typedef struct {
    bool is_container;           // Running in container
    char* container_id;          // Container ID (if available)
    char* runtime_type;          // docker, podman, lxc, etc.
    char* image_name;            // Container image name
    char** mounted_volumes;      // List of mounted volumes
    size_t volume_count;
    char** network_namespaces;   // Network namespace info
    size_t namespace_count;
} container_context_t;

// File system scan configuration
typedef struct {
    // Scanning scope
    bool host_scan;              // Scan host filesystem instead of container
    char** include_paths;        // Paths to include
    size_t include_path_count;
    char** exclude_paths;        // Paths to exclude
    size_t exclude_path_count;
    char** mount_excludes;       // Mount types to exclude (nfs, smb, fuse)
    size_t mount_exclude_count;
    
    // File filtering
    file_type_t* file_types;     // File types to scan
    size_t file_type_count;
    char** file_extensions;      // File extensions to include
    size_t extension_count;
    
    // Traversal limits
    int max_depth;               // Maximum directory depth (-1 = unlimited)
    size_t max_files;            // Maximum number of files to process
    bool follow_symlinks;        // Follow symbolic links
    bool cross_filesystems;      // Cross filesystem boundaries
    
    // Permission handling
    bool skip_permission_errors; // Skip files with permission errors
    bool require_read_access;    // Only process readable files
    
    // Container/namespace behavior
    bool auto_detect_container;  // Automatically detect container environment
    bool respect_namespaces;     // Respect container namespaces
    char* container_runtime;     // Preferred container runtime
} filesystem_scan_config_t;

// Forward declaration - scan_context_t is defined in plugin_manager.h
typedef struct scan_context scan_context_t;

// Filesystem-specific scan context for tracking progress
typedef struct {
    // Progress tracking
    size_t files_scanned;        // Number of files processed
    size_t files_skipped;        // Number of files skipped
    size_t directories_scanned;  // Number of directories processed
    size_t bytes_processed;      // Total bytes processed
    
    // Error tracking
    size_t permission_errors;    // Permission denied errors
    size_t io_errors;            // I/O errors
    size_t timeout_errors;       // Timeout errors
    size_t other_errors;         // Other errors
    
    // Resource usage
    size_t current_open_files;   // Currently open file handles
    size_t peak_memory_usage;    // Peak memory usage
    
    // Thread safety
    pthread_mutex_t mutex;       // Mutex for updating counters
} filesystem_scan_context_t;

// File information structure
typedef struct {
    char* path;                  // Full file path
    file_type_t type;            // Detected file type
    size_t size;                 // File size in bytes
    mode_t mode;                 // File permissions
    uid_t uid;                   // Owner user ID
    gid_t gid;                   // Owner group ID
    time_t mtime;                // Last modification time
    time_t atime;                // Last access time
    dev_t device;                // Device ID
    ino_t inode;                 // Inode number
    bool is_symlink;             // Is symbolic link
    char* symlink_target;        // Symlink target (if applicable)
} file_info_t;

// Directory traversal callback function
typedef int (*file_callback_t)(const file_info_t* file_info, 
                              filesystem_scan_context_t* context, 
                              asset_store_t* store, 
                              void* user_data);

// File system scanner structure
typedef struct {
    filesystem_scan_config_t config;
    resource_manager_t* resource_manager;
    container_context_t* container_context;
    filesystem_scan_context_t* scan_context;
    
    // Callbacks
    file_callback_t file_callback;
    void* callback_user_data;
    
    // Internal state
    bool is_scanning;
    pthread_t* worker_threads;
    size_t thread_count;
    
    // Work queue for parallel processing
    struct work_queue* work_queue;
} filesystem_scanner_t;

// Work queue entry for parallel processing
typedef struct work_item {
    char* path;                  // Directory or file path
    int depth;                   // Current depth
    struct work_item* next;      // Next item in queue
} work_item_t;

// Work queue structure
typedef struct work_queue {
    work_item_t* head;           // Queue head
    work_item_t* tail;           // Queue tail
    size_t count;                // Number of items
    pthread_mutex_t mutex;       // Queue mutex
    pthread_cond_t not_empty;    // Condition variable for non-empty queue
    pthread_cond_t not_full;     // Condition variable for non-full queue
    bool shutdown;               // Shutdown flag
} work_queue_t;

// File system scanner operations
filesystem_scanner_t* filesystem_scanner_create(const filesystem_scan_config_t* config,
                                               resource_manager_t* resource_manager);
void filesystem_scanner_destroy(filesystem_scanner_t* scanner);

// Configuration management
filesystem_scan_config_t* filesystem_scan_config_create_default(void);
void filesystem_scan_config_destroy(filesystem_scan_config_t* config);
int filesystem_scan_config_add_include_path(filesystem_scan_config_t* config, const char* path);
int filesystem_scan_config_add_exclude_path(filesystem_scan_config_t* config, const char* path);
int filesystem_scan_config_add_file_type(filesystem_scan_config_t* config, file_type_t type);

// Container detection
container_context_t* detect_container_environment(void);
void container_context_destroy(container_context_t* context);
bool should_scan_host_filesystem(const filesystem_scan_config_t* config, 
                                const container_context_t* context);
char** get_excluded_mount_points(const filesystem_scan_config_t* config);

// Scanning operations
int filesystem_scanner_scan(filesystem_scanner_t* scanner, 
                           const char* root_path,
                           asset_store_t* store);
int filesystem_scanner_scan_parallel(filesystem_scanner_t* scanner,
                                    const char* root_path,
                                    asset_store_t* store,
                                    size_t thread_count);

// File type detection
file_type_t detect_file_type(const char* path, const struct stat* st);
file_type_t detect_file_type_by_extension(const char* path);
file_type_t detect_file_type_by_content(const char* path);
bool is_supported_file_type(file_type_t type, const filesystem_scan_config_t* config);

// Path filtering
bool should_include_path(const char* path, const filesystem_scan_config_t* config);
bool should_exclude_path(const char* path, const filesystem_scan_config_t* config);
bool is_excluded_mount_type(const char* path, const filesystem_scan_config_t* config);

// Permission handling
bool can_access_file(const char* path, int access_mode);
int handle_permission_error(const char* path, filesystem_scan_context_t* context);
bool should_skip_permission_error(const filesystem_scan_config_t* config);

// Directory traversal
int traverse_directory(filesystem_scanner_t* scanner,
                      const char* dir_path,
                      int current_depth,
                      asset_store_t* store);
int process_directory_entry(filesystem_scanner_t* scanner,
                           const char* entry_path,
                           int current_depth,
                           asset_store_t* store);

// Work queue operations
work_queue_t* work_queue_create(size_t max_size);
void work_queue_destroy(work_queue_t* queue);
int work_queue_push(work_queue_t* queue, const char* path, int depth);
work_item_t* work_queue_pop(work_queue_t* queue);
void work_queue_shutdown(work_queue_t* queue);

// Worker thread function
void* filesystem_scanner_worker(void* arg);

// Scan context operations
filesystem_scan_context_t* filesystem_scan_context_create(void);
void filesystem_scan_context_destroy(filesystem_scan_context_t* context);
void filesystem_scan_context_update_progress(filesystem_scan_context_t* context,
                                            size_t files_processed,
                                            size_t bytes_processed);
void filesystem_scan_context_record_error(filesystem_scan_context_t* context, const char* error_type);

// File information operations
file_info_t* file_info_create(const char* path, const struct stat* st);
void file_info_destroy(file_info_t* info);

// Utility functions
bool is_regular_file(mode_t mode);
bool is_directory(mode_t mode);
bool is_symlink(mode_t mode);
bool is_executable(mode_t mode);
char* resolve_symlink(const char* path);
char* get_file_extension(const char* path);
size_t get_directory_size(const char* path);

// Mount point detection
bool is_mount_point(const char* path);
char* get_mount_type(const char* path);
bool is_network_filesystem(const char* path);
bool is_virtual_filesystem(const char* path);

// Resource limit enforcement
bool check_file_size_limit(size_t file_size, const resource_manager_t* manager);
bool check_total_bytes_limit(size_t additional_bytes, const resource_manager_t* manager);
int enforce_scan_limits(filesystem_scanner_t* scanner, const file_info_t* file_info);

// Error handling
typedef enum {
    FS_SCAN_SUCCESS = 0,
    FS_SCAN_ERROR_INVALID_PARAM = -1,
    FS_SCAN_ERROR_PERMISSION_DENIED = -2,
    FS_SCAN_ERROR_NOT_FOUND = -3,
    FS_SCAN_ERROR_IO_ERROR = -4,
    FS_SCAN_ERROR_RESOURCE_LIMIT = -5,
    FS_SCAN_ERROR_TIMEOUT = -6,
    FS_SCAN_ERROR_INTERRUPTED = -7,
    FS_SCAN_ERROR_OUT_OF_MEMORY = -8
} filesystem_scan_error_t;

const char* filesystem_scan_error_string(filesystem_scan_error_t error);

// Statistics and reporting
typedef struct {
    size_t total_files_found;
    size_t total_files_processed;
    size_t total_files_skipped;
    size_t total_directories_scanned;
    size_t total_bytes_processed;
    size_t total_errors;
    size_t permission_errors;
    size_t io_errors;
    size_t timeout_errors;
    double scan_duration_seconds;
    double files_per_second;
    double bytes_per_second;
} filesystem_scan_stats_t;

filesystem_scan_stats_t filesystem_scanner_get_stats(const filesystem_scanner_t* scanner);

#ifdef __cplusplus
}
#endif

#endif // FILESYSTEM_SCANNER_H
