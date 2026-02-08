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
#include "filesystem_scanner.h"
#include "resource_manager.h"
#include "secure_memory.h"
#include "error_handling.h"
#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <mntent.h>
#include <pthread.h>
#include <ctype.h>

// Default configuration values
#define DEFAULT_MAX_DEPTH 32
#define DEFAULT_MAX_FILES 1000000
#define DEFAULT_WORK_QUEUE_SIZE 1000

// File extension mappings for type detection
static const struct {
    const char* extension;
    file_type_t type;
} file_extension_map[] = {
    // Certificate files
    // Note: .pem removed - use content-based detection since PEM can contain certs or keys
    {".crt", FILE_TYPE_CERTIFICATE},
    {".cer", FILE_TYPE_CERTIFICATE},
    {".der", FILE_TYPE_CERTIFICATE},
    {".p12", FILE_TYPE_CERTIFICATE},
    {".pfx", FILE_TYPE_CERTIFICATE},
    {".p7b", FILE_TYPE_CERTIFICATE},
    {".p7c", FILE_TYPE_CERTIFICATE},
    
    // Key files
    {".key", FILE_TYPE_KEY},
    {".priv", FILE_TYPE_KEY},
    {".private", FILE_TYPE_KEY},
    
    // OpenPGP key files
    {".asc", FILE_TYPE_OPENPGP_KEY},
    {".gpg", FILE_TYPE_OPENPGP_KEY},
    {".pgp", FILE_TYPE_OPENPGP_KEY},
    
    // Library files
    {".so", FILE_TYPE_LIBRARY},
    {".a", FILE_TYPE_LIBRARY},
    {".dylib", FILE_TYPE_LIBRARY},
    
    // Configuration files
    {".conf", FILE_TYPE_CONFIG},
    {".cfg", FILE_TYPE_CONFIG},
    {".ini", FILE_TYPE_CONFIG},
    {".json", FILE_TYPE_CONFIG},
    {".xml", FILE_TYPE_CONFIG},
    {".yaml", FILE_TYPE_CONFIG},
    {".yml", FILE_TYPE_CONFIG},
    {".toml", FILE_TYPE_CONFIG},
    
    // Package files
    {".deb", FILE_TYPE_PACKAGE},
    {".rpm", FILE_TYPE_PACKAGE},
    {".pkg", FILE_TYPE_PACKAGE},
    {".apk", FILE_TYPE_PACKAGE},
    
    // Archive files
    {".tar", FILE_TYPE_ARCHIVE},
    {".gz", FILE_TYPE_ARCHIVE},
    {".zip", FILE_TYPE_ARCHIVE},
    {".jar", FILE_TYPE_ARCHIVE},
    {".war", FILE_TYPE_ARCHIVE},
    {".ear", FILE_TYPE_ARCHIVE},
    
    // Text files
    {".txt", FILE_TYPE_TEXT},
    {".log", FILE_TYPE_TEXT},
    {".md", FILE_TYPE_TEXT},
    
    {NULL, FILE_TYPE_UNKNOWN}
};

// Container detection patterns
static const char* container_indicators[] = {
    "/.dockerenv",
    "/run/.containerenv",
    "/proc/1/cgroup",
    NULL
};

// Create default filesystem scan configuration
filesystem_scan_config_t* filesystem_scan_config_create_default(void) {
    filesystem_scan_config_t* config = secure_alloc(sizeof(filesystem_scan_config_t));
    if (!config) return NULL;
    
    memset(config, 0, sizeof(filesystem_scan_config_t));
    
    // Set default values
    config->host_scan = false;
    config->max_depth = DEFAULT_MAX_DEPTH;
    config->max_files = DEFAULT_MAX_FILES;
    config->follow_symlinks = false;
    config->cross_filesystems = false;
    config->skip_permission_errors = true;
    config->require_read_access = true;
    config->auto_detect_container = true;
    config->respect_namespaces = true;
    
    return config;
}

// Destroy filesystem scan configuration
void filesystem_scan_config_destroy(filesystem_scan_config_t* config) {
    if (!config) return;
    
    // Free include paths
    if (config->include_paths) {
        for (size_t i = 0; i < config->include_path_count; i++) {
            if (config->include_paths[i]) {
                free(config->include_paths[i]);
            }
        }
        free(config->include_paths);
    }
    
    // Free exclude paths
    if (config->exclude_paths) {
        for (size_t i = 0; i < config->exclude_path_count; i++) {
            if (config->exclude_paths[i]) {
                free(config->exclude_paths[i]);
            }
        }
        free(config->exclude_paths);
    }
    
    // Free mount excludes
    if (config->mount_excludes) {
        for (size_t i = 0; i < config->mount_exclude_count; i++) {
            if (config->mount_excludes[i]) {
                free(config->mount_excludes[i]);
            }
        }
        free(config->mount_excludes);
    }
    
    // Free file types
    if (config->file_types) {
        free(config->file_types);
    }
    
    // Free file extensions
    if (config->file_extensions) {
        for (size_t i = 0; i < config->extension_count; i++) {
            if (config->file_extensions[i]) {
                free(config->file_extensions[i]);
            }
        }
        free(config->file_extensions);
    }
    
    if (config->container_runtime) {
        free(config->container_runtime);
    }
    
    secure_free(config, sizeof(filesystem_scan_config_t));
}

// Add include path to configuration
int filesystem_scan_config_add_include_path(filesystem_scan_config_t* config, const char* path) {
    if (!config || !path) return FS_SCAN_ERROR_INVALID_PARAM;
    
    // Reallocate include paths array
    char** new_paths = realloc(config->include_paths, 
                              (config->include_path_count + 1) * sizeof(char*));
    if (!new_paths) return FS_SCAN_ERROR_OUT_OF_MEMORY;
    
    config->include_paths = new_paths;
    config->include_paths[config->include_path_count] = strdup(path);
    if (!config->include_paths[config->include_path_count]) {
        return FS_SCAN_ERROR_OUT_OF_MEMORY;
    }
    
    config->include_path_count++;
    return FS_SCAN_SUCCESS;
}

// Add exclude path to configuration
int filesystem_scan_config_add_exclude_path(filesystem_scan_config_t* config, const char* path) {
    if (!config || !path) return FS_SCAN_ERROR_INVALID_PARAM;
    
    // Reallocate exclude paths array
    char** new_paths = realloc(config->exclude_paths, 
                              (config->exclude_path_count + 1) * sizeof(char*));
    if (!new_paths) return FS_SCAN_ERROR_OUT_OF_MEMORY;
    
    config->exclude_paths = new_paths;
    config->exclude_paths[config->exclude_path_count] = strdup(path);
    if (!config->exclude_paths[config->exclude_path_count]) {
        return FS_SCAN_ERROR_OUT_OF_MEMORY;
    }
    
    config->exclude_path_count++;
    return FS_SCAN_SUCCESS;
}

// Add file type to configuration
int filesystem_scan_config_add_file_type(filesystem_scan_config_t* config, file_type_t type) {
    if (!config) return FS_SCAN_ERROR_INVALID_PARAM;
    
    // Reallocate file types array
    file_type_t* new_types = realloc(config->file_types, 
                                    (config->file_type_count + 1) * sizeof(file_type_t));
    if (!new_types) return FS_SCAN_ERROR_OUT_OF_MEMORY;
    
    config->file_types = new_types;
    config->file_types[config->file_type_count] = type;
    config->file_type_count++;
    
    return FS_SCAN_SUCCESS;
}

// Detect container environment
container_context_t* detect_container_environment(void) {
    container_context_t* context = secure_alloc(sizeof(container_context_t));
    if (!context) return NULL;
    
    memset(context, 0, sizeof(container_context_t));
    
    // Check for container indicators
    for (int i = 0; container_indicators[i]; i++) {
        if (access(container_indicators[i], F_OK) == 0) {
            context->is_container = true;
            break;
        }
    }
    
    if (context->is_container) {
        // Try to detect container runtime
        if (access("/.dockerenv", F_OK) == 0) {
            context->runtime_type = strdup("docker");
        } else if (access("/run/.containerenv", F_OK) == 0) {
            context->runtime_type = strdup("podman");
        }
        
        // Try to get container ID from cgroup
        FILE* cgroup_file = fopen("/proc/1/cgroup", "r");
        if (cgroup_file) {
            char line[256];
            while (fgets(line, sizeof(line), cgroup_file)) {
                // Look for container ID in cgroup path
                char* docker_pos = strstr(line, "/docker/");
                if (docker_pos) {
                    char* id_start = docker_pos + 8;
                    char* id_end = strchr(id_start, '\n');
                    if (id_end) {
                        *id_end = '\0';
                        context->container_id = strndup(id_start, 64);
                        break;
                    }
                }
            }
            fclose(cgroup_file);
        }
    }
    
    return context;
}

// Destroy container context
void container_context_destroy(container_context_t* context) {
    if (!context) return;
    
    if (context->container_id) free(context->container_id);
    if (context->runtime_type) free(context->runtime_type);
    if (context->image_name) free(context->image_name);
    
    if (context->mounted_volumes) {
        for (size_t i = 0; i < context->volume_count; i++) {
            if (context->mounted_volumes[i]) {
                free(context->mounted_volumes[i]);
            }
        }
        free(context->mounted_volumes);
    }
    
    if (context->network_namespaces) {
        for (size_t i = 0; i < context->namespace_count; i++) {
            if (context->network_namespaces[i]) {
                free(context->network_namespaces[i]);
            }
        }
        free(context->network_namespaces);
    }
    
    secure_free(context, sizeof(container_context_t));
}

// Determine if should scan host filesystem
bool should_scan_host_filesystem(const filesystem_scan_config_t* config, 
                                const container_context_t* context) {
    if (!config || !context) return true;
    
    // If explicitly requested host scan, do it
    if (config->host_scan) return true;
    
    // If not in container, scan host
    if (!context->is_container) return true;
    
    // If in container but not respecting namespaces, scan host
    if (!config->respect_namespaces) return true;
    
    // Otherwise, scan container filesystem
    return false;
}

// Get excluded mount points
char** get_excluded_mount_points(const filesystem_scan_config_t* config) {
    if (!config || !config->mount_excludes) return NULL;
    
    // Return copy of mount excludes
    char** excludes = malloc((config->mount_exclude_count + 1) * sizeof(char*));
    if (!excludes) return NULL;
    
    for (size_t i = 0; i < config->mount_exclude_count; i++) {
        excludes[i] = strdup(config->mount_excludes[i]);
    }
    excludes[config->mount_exclude_count] = NULL;
    
    return excludes;
}

// Detect file type by extension
file_type_t detect_file_type_by_extension(const char* path) {
    if (!path) return FILE_TYPE_UNKNOWN;
    
    // Check for GPG-KEY pattern in filename (no extension needed)
    const char* filename = strrchr(path, '/');
    filename = filename ? filename + 1 : path;
    if (strstr(filename, "GPG-KEY")) {
        return FILE_TYPE_OPENPGP_KEY;
    }
    
    const char* ext = strrchr(path, '.');
    if (!ext) return FILE_TYPE_UNKNOWN;
    
    // Convert to lowercase for comparison
    char ext_lower[32];
    strncpy(ext_lower, ext, sizeof(ext_lower) - 1);
    ext_lower[sizeof(ext_lower) - 1] = '\0';
    
    for (char* p = ext_lower; *p; p++) {
        *p = tolower(*p);
    }
    
    // Look up in extension map
    for (int i = 0; file_extension_map[i].extension; i++) {
        if (strcmp(ext_lower, file_extension_map[i].extension) == 0) {
            return file_extension_map[i].type;
        }
    }
    
    return FILE_TYPE_UNKNOWN;
}

// Detect file type by content (magic numbers)
file_type_t detect_file_type_by_content(const char* path) {
    if (!path) return FILE_TYPE_UNKNOWN;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return FILE_TYPE_UNKNOWN;

    // Read enough bytes to capture full PEM header (e.g., "-----BEGIN RSA PRIVATE KEY-----")
    unsigned char buffer[256];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    close(fd);

    if (bytes_read < 4) return FILE_TYPE_UNKNOWN;
    
    // Check for ELF magic number
    if (bytes_read >= 4 &&
        buffer[0] == 0x7f && buffer[1] == 'E' &&
        buffer[2] == 'L' && buffer[3] == 'F') {
        // v1.9.2: Distinguish libraries from executables by filename pattern
        // Libraries like liboqs.so.0.13.0 have ".so" in the name but not as final extension
        if (strstr(path, ".so")) {
            return FILE_TYPE_LIBRARY;
        }
        return FILE_TYPE_EXECUTABLE;
    }
    
    // Check for PEM format
    if (bytes_read >= 11 && strncmp((char*)buffer, "-----BEGIN ", 11) == 0) {
        // Null-terminate the buffer for string operations
        char header[257];
        size_t copy_len = bytes_read < 256 ? bytes_read : 256;
        memcpy(header, buffer, copy_len);
        header[copy_len] = '\0';

        // Check if it's an OpenPGP key
        if (strstr(header, "PGP PUBLIC KEY") || strstr(header, "PGP PRIVATE KEY")) {
            return FILE_TYPE_OPENPGP_KEY;
        }
        // Check for private/public key PEM headers
        if (strstr(header, "PRIVATE KEY") || strstr(header, "PUBLIC KEY")) {
            return FILE_TYPE_KEY;
        }
        // Default to certificate for other PEM content (e.g., CERTIFICATE, CERTIFICATE REQUEST)
        return FILE_TYPE_CERTIFICATE;
    }
    
    // Check for DER format (ASN.1)
    if (bytes_read >= 2 && buffer[0] == 0x30 && (buffer[1] & 0x80)) {
        return FILE_TYPE_CERTIFICATE;
    }
    
    return FILE_TYPE_UNKNOWN;
}

// Detect file type
file_type_t detect_file_type(const char* path, const struct stat* st) {
    if (!path || !st) return FILE_TYPE_UNKNOWN;
    
    // Check if it's a directory
    if (S_ISDIR(st->st_mode)) {
        return FILE_TYPE_DIRECTORY;
    }
    
    // Check if it's a regular file
    if (!S_ISREG(st->st_mode)) {
        return FILE_TYPE_UNKNOWN;
    }
    
    // Try extension-based detection first
    file_type_t type = detect_file_type_by_extension(path);
    if (type != FILE_TYPE_UNKNOWN) {
        return type;
    }
    
    // Fall back to content-based detection
    return detect_file_type_by_content(path);
}

// Check if file type is supported
bool is_supported_file_type(file_type_t type, const filesystem_scan_config_t* config) {
    if (!config || !config->file_types) {
        // If no specific types configured, support all except unknown
        return type != FILE_TYPE_UNKNOWN;
    }
    
    // Check if type is in the configured list
    for (size_t i = 0; i < config->file_type_count; i++) {
        if (config->file_types[i] == type) {
            return true;
        }
    }
    
    return false;
}

// Check if path should be included
bool should_include_path(const char* path, const filesystem_scan_config_t* config) {
    if (!path || !config) return true;
    
    // If no include paths specified, include everything
    if (!config->include_paths || config->include_path_count == 0) {
        return true;
    }
    
    // Check if path matches any include pattern
    for (size_t i = 0; i < config->include_path_count; i++) {
        if (strncmp(path, config->include_paths[i], strlen(config->include_paths[i])) == 0) {
            return true;
        }
    }
    
    return false;
}

// Check if path should be excluded
bool should_exclude_path(const char* path, const filesystem_scan_config_t* config) {
    if (!path || !config) return false;
    
    // Check exclude paths
    if (config->exclude_paths) {
        for (size_t i = 0; i < config->exclude_path_count; i++) {
            if (strncmp(path, config->exclude_paths[i], strlen(config->exclude_paths[i])) == 0) {
                return true;
            }
        }
    }
    
    return false;
}

// Get mount type for a path
char* get_mount_type(const char* path) {
    if (!path) return NULL;
    
    FILE* mounts = setmntent("/proc/mounts", "r");
    if (!mounts) return NULL;
    
    struct mntent* entry;
    char* mount_type = NULL;
    size_t best_match_len = 0;
    
    while ((entry = getmntent(mounts)) != NULL) {
        size_t mount_len = strlen(entry->mnt_dir);
        
        // Check if path is under this mount point
        if (strncmp(path, entry->mnt_dir, mount_len) == 0 && 
            (path[mount_len] == '/' || path[mount_len] == '\0') &&
            mount_len > best_match_len) {
            
            if (mount_type) free(mount_type);
            mount_type = strdup(entry->mnt_type);
            best_match_len = mount_len;
        }
    }
    
    endmntent(mounts);
    return mount_type;
}

// Check if path is on excluded mount type
bool is_excluded_mount_type(const char* path, const filesystem_scan_config_t* config) {
    if (!path || !config || !config->mount_excludes) return false;
    
    char* mount_type = get_mount_type(path);
    if (!mount_type) return false;
    
    bool excluded = false;
    for (size_t i = 0; i < config->mount_exclude_count; i++) {
        if (strcmp(mount_type, config->mount_excludes[i]) == 0) {
            excluded = true;
            break;
        }
    }
    
    free(mount_type);
    return excluded;
}

// Check if can access file
bool can_access_file(const char* path, int access_mode) {
    return access(path, access_mode) == 0;
}

// Handle permission error
int handle_permission_error(const char* path, filesystem_scan_context_t* context) {
    if (!context) return FS_SCAN_ERROR_PERMISSION_DENIED;
    
    pthread_mutex_lock(&context->mutex);
    context->permission_errors++;
    pthread_mutex_unlock(&context->mutex);
    
    printf("WARNING: Permission denied accessing: %s\n", path);
    return FS_SCAN_ERROR_PERMISSION_DENIED;
}

// Check if should skip permission errors
bool should_skip_permission_error(const filesystem_scan_config_t* config) {
    return config && config->skip_permission_errors;
}

// Create scan context
filesystem_scan_context_t* filesystem_scan_context_create(void) {
    filesystem_scan_context_t* context = secure_alloc(sizeof(filesystem_scan_context_t));
    if (!context) return NULL;
    
    memset(context, 0, sizeof(filesystem_scan_context_t));
    
    if (pthread_mutex_init(&context->mutex, NULL) != 0) {
        secure_free(context, sizeof(filesystem_scan_context_t));
        return NULL;
    }
    
    return context;
}

// Destroy scan context
void filesystem_scan_context_destroy(filesystem_scan_context_t* context) {
    if (!context) return;
    
    pthread_mutex_destroy(&context->mutex);
    secure_free(context, sizeof(filesystem_scan_context_t));
}

// Update scan progress
void filesystem_scan_context_update_progress(filesystem_scan_context_t* context,
                                            size_t files_processed,
                                            size_t bytes_processed) {
    if (!context) return;
    
    pthread_mutex_lock(&context->mutex);
    context->files_scanned += files_processed;
    context->bytes_processed += bytes_processed;
    pthread_mutex_unlock(&context->mutex);
}

// Record error in scan context
void filesystem_scan_context_record_error(filesystem_scan_context_t* context, const char* error_type) {
    if (!context || !error_type) return;
    
    pthread_mutex_lock(&context->mutex);
    
    if (strcmp(error_type, "permission") == 0) {
        context->permission_errors++;
    } else if (strcmp(error_type, "io") == 0) {
        context->io_errors++;
    } else if (strcmp(error_type, "timeout") == 0) {
        context->timeout_errors++;
    } else {
        context->other_errors++;
    }
    
    pthread_mutex_unlock(&context->mutex);
}

// Create file info structure
file_info_t* file_info_create(const char* path, const struct stat* st) {
    if (!path || !st) return NULL;
    
    file_info_t* info = secure_alloc(sizeof(file_info_t));
    if (!info) return NULL;
    
    info->path = strdup(path);
    if (!info->path) {
        secure_free(info, sizeof(file_info_t));
        return NULL;
    }
    
    info->type = detect_file_type(path, st);
    info->size = st->st_size;
    info->mode = st->st_mode;
    info->uid = st->st_uid;
    info->gid = st->st_gid;
    info->mtime = st->st_mtime;
    info->atime = st->st_atime;
    info->device = st->st_dev;
    info->inode = st->st_ino;
    info->is_symlink = S_ISLNK(st->st_mode);
    
    // Resolve symlink target if applicable
    if (info->is_symlink) {
        info->symlink_target = resolve_symlink(path);
    }
    
    return info;
}

// Destroy file info structure
void file_info_destroy(file_info_t* info) {
    if (!info) return;
    
    if (info->path) free(info->path);
    if (info->symlink_target) free(info->symlink_target);
    
    secure_free(info, sizeof(file_info_t));
}

// Resolve symlink
char* resolve_symlink(const char* path) {
    if (!path) return NULL;
    
    char* resolved = malloc(PATH_MAX);
    if (!resolved) return NULL;
    
    ssize_t len = readlink(path, resolved, PATH_MAX - 1);
    if (len == -1) {
        free(resolved);
        return NULL;
    }
    
    resolved[len] = '\0';
    return resolved;
}

// Get file extension
char* get_file_extension(const char* path) {
    if (!path) return NULL;
    
    const char* ext = strrchr(path, '.');
    return ext ? strdup(ext) : NULL;
}

// Check file size limit
bool check_file_size_limit(size_t file_size, const resource_manager_t* manager) {
    if (!manager) return true;
    
    return resource_manager_can_open_file((resource_manager_t*)manager, file_size);
}

// Check total bytes limit
bool check_total_bytes_limit(size_t additional_bytes, const resource_manager_t* manager) {
    if (!manager) return true;
    
    // This would check against total bytes processed limit
    // For now, just return true
    (void)additional_bytes;
    return true;
}

// Enforce scan limits
int enforce_scan_limits(filesystem_scanner_t* scanner, const file_info_t* file_info) {
    if (!scanner || !file_info) return FS_SCAN_ERROR_INVALID_PARAM;
    
    // Check file size limit
    if (!check_file_size_limit(file_info->size, scanner->resource_manager)) {
        return FS_SCAN_ERROR_RESOURCE_LIMIT;
    }
    
    // Check total bytes limit
    if (!check_total_bytes_limit(file_info->size, scanner->resource_manager)) {
        return FS_SCAN_ERROR_RESOURCE_LIMIT;
    }
    
    return FS_SCAN_SUCCESS;
}

// Convert error code to string
const char* filesystem_scan_error_string(filesystem_scan_error_t error) {
    switch (error) {
        case FS_SCAN_SUCCESS: return "Success";
        case FS_SCAN_ERROR_INVALID_PARAM: return "Invalid parameter";
        case FS_SCAN_ERROR_PERMISSION_DENIED: return "Permission denied";
        case FS_SCAN_ERROR_NOT_FOUND: return "File not found";
        case FS_SCAN_ERROR_IO_ERROR: return "I/O error";
        case FS_SCAN_ERROR_RESOURCE_LIMIT: return "Resource limit exceeded";
        case FS_SCAN_ERROR_TIMEOUT: return "Timeout";
        case FS_SCAN_ERROR_INTERRUPTED: return "Interrupted";
        case FS_SCAN_ERROR_OUT_OF_MEMORY: return "Out of memory";
        default: return "Unknown error";
    }
}

// Utility functions
bool is_regular_file(mode_t mode) {
    return S_ISREG(mode);
}

bool is_directory(mode_t mode) {
    return S_ISDIR(mode);
}

bool is_symlink(mode_t mode) {
    return S_ISLNK(mode);
}

bool is_executable(mode_t mode) {
    return (mode & S_IXUSR) || (mode & S_IXGRP) || (mode & S_IXOTH);
}

// Create filesystem scanner
filesystem_scanner_t* filesystem_scanner_create(const filesystem_scan_config_t* config,
                                               resource_manager_t* resource_manager) {
    if (!config) return NULL;
    
    filesystem_scanner_t* scanner = secure_alloc(sizeof(filesystem_scanner_t));
    if (!scanner) return NULL;
    
    // Copy configuration
    scanner->config = *config;
    scanner->resource_manager = resource_manager;
    scanner->is_scanning = false;
    
    // Detect container environment if enabled
    if (config->auto_detect_container) {
        scanner->container_context = detect_container_environment();
    }
    
    // Create scan context
    scanner->scan_context = filesystem_scan_context_create();
    if (!scanner->scan_context) {
        container_context_destroy(scanner->container_context);
        secure_free(scanner, sizeof(filesystem_scanner_t));
        return NULL;
    }
    
    return scanner;
}

// Destroy filesystem scanner
void filesystem_scanner_destroy(filesystem_scanner_t* scanner) {
    if (!scanner) return;
    
    // Wait for scanning to complete
    if (scanner->is_scanning) {
        // Would implement proper shutdown here
    }
    
    if (scanner->container_context) {
        container_context_destroy(scanner->container_context);
    }
    
    if (scanner->scan_context) {
        filesystem_scan_context_destroy(scanner->scan_context);
    }
    
    // Work queue functionality not implemented yet
    // if (scanner->work_queue) {
    //     work_queue_destroy(scanner->work_queue);
    // }
    
    if (scanner->worker_threads) {
        free(scanner->worker_threads);
    }
    
    secure_free(scanner, sizeof(filesystem_scanner_t));
}

// Process directory entry
int process_directory_entry(filesystem_scanner_t* scanner,
                           const char* entry_path,
                           int current_depth,
                           asset_store_t* store) {
    if (!scanner || !entry_path || !store) {
        return FS_SCAN_ERROR_INVALID_PARAM;
    }
    
    struct stat st;
    int stat_result = lstat(entry_path, &st);
    if (stat_result != 0) {
        if (errno == EACCES && should_skip_permission_error(&scanner->config)) {
            handle_permission_error(entry_path, scanner->scan_context);
            return FS_SCAN_SUCCESS; // Continue scanning
        }
        filesystem_scan_context_record_error(scanner->scan_context, "io");
        return FS_SCAN_ERROR_IO_ERROR;
    }
    
    // Create file info
    file_info_t* file_info = file_info_create(entry_path, &st);
    if (!file_info) {
        return FS_SCAN_ERROR_OUT_OF_MEMORY;
    }
    
    int result = FS_SCAN_SUCCESS;
    
    // Check if this is a directory
    if (S_ISDIR(st.st_mode)) {
        // Check depth limit
        if (scanner->config.max_depth >= 0 && current_depth >= scanner->config.max_depth) {
            file_info_destroy(file_info);
            return FS_SCAN_SUCCESS; // Skip but continue
        }
        
        // Recursively traverse directory
        result = traverse_directory(scanner, entry_path, current_depth + 1, store);
        
        pthread_mutex_lock(&scanner->scan_context->mutex);
        scanner->scan_context->directories_scanned++;
        pthread_mutex_unlock(&scanner->scan_context->mutex);
    } else if (S_ISREG(st.st_mode)) {
        // Check if file type is supported
        if (is_supported_file_type(file_info->type, &scanner->config)) {
            // Enforce resource limits
            int limit_result = enforce_scan_limits(scanner, file_info);
            if (limit_result != FS_SCAN_SUCCESS) {
                file_info_destroy(file_info);
                return limit_result;
            }
            
            // Call file callback if provided
            if (scanner->file_callback) {
                result = scanner->file_callback(file_info, scanner->scan_context, 
                                              store, scanner->callback_user_data);
            }
            
            // Update progress
            filesystem_scan_context_update_progress(scanner->scan_context, 1, file_info->size);
        } else {
            pthread_mutex_lock(&scanner->scan_context->mutex);
            scanner->scan_context->files_skipped++;
            pthread_mutex_unlock(&scanner->scan_context->mutex);
        }
    }
    
    file_info_destroy(file_info);
    return result;
}

// Traverse directory
int traverse_directory(filesystem_scanner_t* scanner,
                      const char* dir_path,
                      int current_depth,
                      asset_store_t* store) {
    if (!scanner || !dir_path || !store) {
        return FS_SCAN_ERROR_INVALID_PARAM;
    }
    
    // Check if path should be excluded
    if (should_exclude_path(dir_path, &scanner->config)) {
        return FS_SCAN_SUCCESS;
    }
    
    // Check if path should be included
    if (!should_include_path(dir_path, &scanner->config)) {
        return FS_SCAN_SUCCESS;
    }
    
    // Check mount type exclusions
    if (is_excluded_mount_type(dir_path, &scanner->config)) {
        return FS_SCAN_SUCCESS;
    }
    
    // Check access permissions
    if (!can_access_file(dir_path, R_OK | X_OK)) {
        if (should_skip_permission_error(&scanner->config)) {
            handle_permission_error(dir_path, scanner->scan_context);
            return FS_SCAN_SUCCESS;
        }
        return FS_SCAN_ERROR_PERMISSION_DENIED;
    }
    
    DIR* dir = opendir(dir_path);
    if (!dir) {
        if (errno == EACCES && should_skip_permission_error(&scanner->config)) {
            handle_permission_error(dir_path, scanner->scan_context);
            return FS_SCAN_SUCCESS;
        }
        filesystem_scan_context_record_error(scanner->scan_context, "io");
        return FS_SCAN_ERROR_IO_ERROR;
    }
    
    struct dirent* entry;
    int result = FS_SCAN_SUCCESS;
    int files_checked __attribute__((unused)) = 0;
    static atomic_size_t global_file_counter = 0;  // Atomic: thread-safe across parallel scanners
    static time_t last_progress = 0;
    if (last_progress == 0) last_progress = time(NULL);

    // v1.9.2: Two-pass directory traversal (files first, then directories)
    // This ensures root-level files like liboqs.so are scanned before recursing into
    // subdirectories that may contain thousands of files and hit resource limits.

    // Collect directory entries for deferred processing
    #define MAX_SUBDIRS 1024
    char* subdirs[MAX_SUBDIRS];
    size_t subdir_count = 0;

    // Pass 1: Process files immediately, collect directories for later
    while ((entry = readdir(dir)) != NULL) {
        files_checked++;
        size_t current_count = atomic_fetch_add(&global_file_counter, 1) + 1;

        // Progress reporting: every 1000 files OR every 10 seconds
        time_t now = time(NULL);
        if (current_count % 1000 == 0 || (now - last_progress) >= 10) {
            tui_log(TUI_MSG_SCANNER_PROGRESS, SCANNER_FILESYSTEM,
                    "Filesystem scanner", current_count, scanner->scan_context->files_scanned, NULL, dir_path);
            last_progress = now;
        }

        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct full path
        char entry_path[PATH_MAX];
        int path_result = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                                  dir_path, entry->d_name);
        if (path_result >= (int)sizeof(entry_path)) {
            // Path too long, skip
            continue;
        }

        // Check if this is a directory (using d_type if available, fallback to stat)
        bool is_dir = false;
        #ifdef _DIRENT_HAVE_D_TYPE
        if (entry->d_type != DT_UNKNOWN) {
            is_dir = (entry->d_type == DT_DIR);
        } else
        #endif
        {
            struct stat st;
            if (lstat(entry_path, &st) == 0) {
                is_dir = S_ISDIR(st.st_mode);
            }
        }

        if (is_dir) {
            // Defer directory processing - save path for later
            if (subdir_count < MAX_SUBDIRS) {
                subdirs[subdir_count++] = strdup(entry_path);
            }
        } else {
            // Process file immediately
            int entry_result = process_directory_entry(scanner, entry_path, current_depth, store);

            // Continue on recoverable errors
            if (entry_result != FS_SCAN_SUCCESS &&
                entry_result != FS_SCAN_ERROR_PERMISSION_DENIED &&
                entry_result != FS_SCAN_ERROR_IO_ERROR &&
                entry_result != FS_SCAN_ERROR_NOT_FOUND) {
                // Fatal error - stop scanning but cleanup first
                result = entry_result;
                goto cleanup_subdirs;
            }
        }
    }

    // Pass 2: Now recurse into subdirectories
    for (size_t i = 0; i < subdir_count && result == FS_SCAN_SUCCESS; i++) {
        int entry_result = process_directory_entry(scanner, subdirs[i], current_depth, store);

        // Continue on recoverable errors
        if (entry_result != FS_SCAN_SUCCESS &&
            entry_result != FS_SCAN_ERROR_PERMISSION_DENIED &&
            entry_result != FS_SCAN_ERROR_IO_ERROR &&
            entry_result != FS_SCAN_ERROR_NOT_FOUND) {
            result = entry_result;
        }
    }

cleanup_subdirs:
    // Free allocated subdirectory paths
    for (size_t i = 0; i < subdir_count; i++) {
        free(subdirs[i]);
    }
    #undef MAX_SUBDIRS
    
    closedir(dir);
    return result;
}

// Main scan function
int filesystem_scanner_scan(filesystem_scanner_t* scanner, 
                           const char* root_path,
                           asset_store_t* store) {
    if (!scanner || !root_path || !store) {
        return FS_SCAN_ERROR_INVALID_PARAM;
    }
    
    scanner->is_scanning = true;
    
    // Determine actual root path based on container context
    const char* scan_path = root_path;
    if (scanner->container_context && 
        !should_scan_host_filesystem(&scanner->config, scanner->container_context)) {
        // Scanning container filesystem - use provided path
        scan_path = root_path;
    }
    
    fprintf(stderr, "INFO: Starting filesystem scan of: %s\n", scan_path);

    // Start traversal from root
    int result = traverse_directory(scanner, scan_path, 0, store);

    scanner->is_scanning = false;

    // Print scan summary
    filesystem_scan_stats_t stats = filesystem_scanner_get_stats(scanner);
    fprintf(stderr, "INFO: Filesystem scan completed\n");
    fprintf(stderr, "  Files processed: %zu\n", stats.total_files_processed);
    fprintf(stderr, "  Files skipped: %zu\n", stats.total_files_skipped);
    fprintf(stderr, "  Directories scanned: %zu\n", stats.total_directories_scanned);
    fprintf(stderr, "  Bytes processed: %zu\n", stats.total_bytes_processed);
    fprintf(stderr, "  Errors: %zu (permission: %zu, I/O: %zu)\n",
           stats.total_errors, stats.permission_errors, stats.io_errors);
    
    return result;
}

// Get scan statistics
filesystem_scan_stats_t filesystem_scanner_get_stats(const filesystem_scanner_t* scanner) {
    filesystem_scan_stats_t stats = {0};
    
    if (!scanner || !scanner->scan_context) {
        return stats;
    }
    
    filesystem_scan_context_t* context = scanner->scan_context;
    
    pthread_mutex_lock(&context->mutex);
    
    stats.total_files_processed = context->files_scanned;
    stats.total_files_skipped = context->files_skipped;
    stats.total_directories_scanned = context->directories_scanned;
    stats.total_bytes_processed = context->bytes_processed;
    stats.permission_errors = context->permission_errors;
    stats.io_errors = context->io_errors;
    stats.timeout_errors = context->timeout_errors;
    stats.total_errors = context->permission_errors + context->io_errors + 
                        context->timeout_errors + context->other_errors;
    
    pthread_mutex_unlock(&context->mutex);
    
    return stats;
}
