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

/**
 * @file path_resolver.c
 * @brief Path resolution implementation
 */

#define _GNU_SOURCE
#include "path_resolver.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

bool path_is_absolute(const char* path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    // Unix absolute paths start with '/'
    return (path[0] == '/');
}

char* path_dirname(const char* path) {
    if (!path) {
        return NULL;
    }

    // Use dirname() - but it modifies input, so copy first
    char* path_copy = strdup(path);
    if (!path_copy) {
        return NULL;
    }

    char* dir = dirname(path_copy);
    char* result = strdup(dir);

    free(path_copy);
    return result;
}

char* path_join(const char* dir, const char* file) {
    if (!dir || !file) {
        return NULL;
    }

    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);

    // Check if dir ends with '/'
    bool has_slash = (dir_len > 0 && dir[dir_len - 1] == '/');

    // Check if file starts with '/'
    bool file_starts_slash = (file[0] == '/');

    // Calculate result length
    size_t result_len = dir_len + file_len + (has_slash || file_starts_slash ? 0 : 1) + 1;

    char* result = malloc(result_len);
    if (!result) {
        return NULL;
    }

    strcpy(result, dir);

    if (!has_slash && !file_starts_slash) {
        strcat(result, "/");
    }

    strcat(result, file);

    return result;
}

char* path_resolve(
    const char* path,
    const char* config_file,
    const char* config_dir
) {
    if (!path) {
        return NULL;
    }

    // If absolute, return as-is
    if (path_is_absolute(path)) {
        return strdup(path);
    }

    // Relative path - try config file directory first
    if (config_file) {
        char* config_file_dir = path_dirname(config_file);
        if (config_file_dir) {
            char* resolved = path_join(config_file_dir, path);
            free(config_file_dir);

            if (resolved) {
                // Check if exists
                struct stat st;
                if (stat(resolved, &st) == 0) {
                    return resolved;
                }
                free(resolved);
            }
        }
    }

    // Fallback: try config directory
    if (config_dir) {
        char* resolved = path_join(config_dir, path);
        if (resolved) {
            // Check if exists
            struct stat st;
            if (stat(resolved, &st) == 0) {
                return resolved;
            }

            // Even if doesn't exist, return this path
            // (caller may want to use it anyway)
            return resolved;
        }
    }

    // Last resort: return path as-is
    return strdup(path);
}
