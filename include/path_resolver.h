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
 * @file path_resolver.h
 * @brief Path resolution for config files
 *
 * Resolves relative paths to absolute paths using config file location
 * and config directory as fallback.
 */

#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include <stdbool.h>

/**
 * Resolve a path (relative or absolute)
 *
 * Strategy:
 * 1. If path is absolute (/path/to/file), return as-is
 * 2. If path is relative (./file or ../file):
 *    a. Try: dirname(config_file) + relative_path
 *    b. Fallback: config_dir + relative_path
 *    c. Use first that exists
 *
 * @param path Path to resolve (may be relative)
 * @param config_file Path to config file (for relative resolution)
 * @param config_dir Config directory (fallback for relative resolution)
 * @return Resolved absolute path (caller must free), or NULL on error
 */
char* path_resolve(
    const char* path,
    const char* config_file,
    const char* config_dir
);

/**
 * Check if path is absolute
 *
 * @param path Path to check
 * @return true if absolute, false if relative
 */
bool path_is_absolute(const char* path);

/**
 * Get directory name from path
 *
 * @param path File path
 * @return Directory path (caller must free), or NULL on error
 */
char* path_dirname(const char* path);

/**
 * Join two paths
 *
 * @param dir Directory path
 * @param file File path
 * @return Joined path (caller must free), or NULL on error
 */
char* path_join(const char* dir, const char* file);

#endif // PATH_RESOLVER_H
