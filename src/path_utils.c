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
#include "path_utils.h"
#include "cbom_types.h"
#include <string.h>
#include <stdlib.h>

// Global CBOM configuration from main.c
extern cbom_config_t g_cbom_config;

const char* normalize_cross_arch_path(const char* full_path) {
    if (!full_path) return NULL;

    // If no rootfs prefix configured, return original path
    if (!g_cbom_config.rootfs_prefix || g_cbom_config.rootfs_prefix[0] == '\0') {
        return full_path;
    }

    size_t prefix_len = strlen(g_cbom_config.rootfs_prefix);

    // Check if path starts with the prefix
    if (strncmp(full_path, g_cbom_config.rootfs_prefix, prefix_len) == 0) {
        // Return path after prefix (e.g., "/usr/lib/libssl.so.3")
        const char* normalized = full_path + prefix_len;

        // If the result doesn't start with '/', it might be empty or a relative path
        // In that case, return "/" to indicate root
        if (*normalized == '\0') {
            return "/";
        }

        return normalized;
    }

    // Prefix doesn't match, return original path
    return full_path;
}

char* normalize_cross_arch_path_dup(const char* full_path) {
    const char* normalized = normalize_cross_arch_path(full_path);
    if (!normalized) return NULL;
    return strdup(normalized);
}
