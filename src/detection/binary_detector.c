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

// src/detection/binary_detector.c
#define _DEFAULT_SOURCE  // For lstat() on glibc
#include "detection/binary_detector.h"
#include "cbom_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef __EMSCRIPTEN__
#include <wordexp.h>
#endif
#include <errno.h>
#ifdef __linux__
#include <linux/limits.h>
#elif !defined(PATH_MAX)
#define PATH_MAX 4096
#endif

// v1.8.1: Access global config for cross-arch mode
extern cbom_config_t g_cbom_config;

/**
 * Check if single path is executable
 */
bool binary_detector_is_executable(const char* path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    // Check if file exists and is executable
    if (access(path, X_OK) == 0) {
        // Additional check: verify it's a regular file or symlink, not a directory
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Expand glob pattern to first matching executable
 */
bool binary_detector_expand_pattern(const char* pattern, char* found_path) {
    if (!pattern || !found_path) {
        return false;
    }

    // Check if pattern contains glob characters
    bool has_glob = (strchr(pattern, '*') != NULL) ||
                    (strchr(pattern, '?') != NULL) ||
                    (strchr(pattern, '[') != NULL);

    // If no glob characters, just check the literal path
    if (!has_glob) {
        if (binary_detector_is_executable(pattern)) {
            strncpy(found_path, pattern, 4095);
            found_path[4095] = '\0';
            return true;
        }
        return false;
    }

#ifdef __EMSCRIPTEN__
    // WASM: no wordexp, no binary executables to discover
    (void)found_path;
    return false;
#else
    // Use wordexp for glob expansion
    wordexp_t exp_result;
    int ret = wordexp(pattern, &exp_result, WRDE_NOCMD);  // WRDE_NOCMD prevents command execution

    if (ret != 0) {
        // Pattern expansion failed
        return false;
    }

    // Check each expanded path
    bool found = false;
    for (size_t i = 0; i < exp_result.we_wordc; i++) {
        const char* expanded_path = exp_result.we_wordv[i];
        if (binary_detector_is_executable(expanded_path)) {
            strncpy(found_path, expanded_path, 4095);
            found_path[4095] = '\0';
            found = true;
            break;
        }
    }

    wordfree(&exp_result);
    return found;
#endif
}

/**
 * Find executable binary from array of paths
 * v1.8.1: In cross-arch mode, prepends rootfs_prefix to paths
 */
bool binary_detector_find(const char** paths, int path_count, char* found_path) {
    if (!paths || path_count <= 0 || !found_path) {
        return false;
    }

    // v1.8.1: Check for cross-arch mode
    const char* rootfs_prefix = g_cbom_config.rootfs_prefix;
    bool cross_arch = g_cbom_config.cross_arch_mode || (rootfs_prefix && rootfs_prefix[0]);

    // Try each path in order
    for (int i = 0; i < path_count; i++) {
        const char* path = paths[i];
        if (!path) {
            continue;
        }

        // v1.8.1: Build full path with rootfs_prefix in cross-arch mode
        char full_path[PATH_MAX];
        if (cross_arch && rootfs_prefix && path[0] == '/') {
            snprintf(full_path, sizeof(full_path), "%s%s", rootfs_prefix, path);
        } else {
            strncpy(full_path, path, sizeof(full_path) - 1);
            full_path[sizeof(full_path) - 1] = '\0';
        }

        // Check if path contains glob pattern
        bool has_glob = (strchr(full_path, '*') != NULL) ||
                        (strchr(full_path, '?') != NULL) ||
                        (strchr(full_path, '[') != NULL);

        if (has_glob) {
            // Expand pattern and check
            if (binary_detector_expand_pattern(full_path, found_path)) {
                return true;
            }
        } else {
            // v1.8.7: In cross-arch mode, use lstat() directly (not access())
            // because access() follows symlinks. BusyBox applets are symlinks
            // to /bin/busybox with absolute paths that don't resolve on the host.
            // lstat() checks if the symlink FILE exists without following it.
            if (cross_arch) {
                struct stat st;
                if (lstat(full_path, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
                    strncpy(found_path, full_path, 4095);
                    found_path[4095] = '\0';
                    return true;
                }
            } else {
                // Host mode: use normal executable check
                if (binary_detector_is_executable(full_path)) {
                    strncpy(found_path, full_path, 4095);
                    found_path[4095] = '\0';
                    return true;
                }
            }
        }
    }

    return false;
}
