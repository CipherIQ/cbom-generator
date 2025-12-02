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

#ifndef PATH_UTILS_H
#define PATH_UTILS_H

/**
 * @file path_utils.h
 * @brief Path normalization utilities for cross-architecture scanning (v1.8)
 *
 * When scanning cross-compiled rootfs images (e.g., Yocto ARM64 from x86_64 host),
 * paths in the CBOM should reflect the target's filesystem layout, not the host's.
 * The --rootfs-prefix flag allows stripping the host mount prefix from all paths.
 */

/**
 * Normalize a path by stripping the rootfs prefix (if configured)
 *
 * Example:
 *   g_cbom_config.rootfs_prefix = "/mnt/yocto/rootfs"
 *   normalize_cross_arch_path("/mnt/yocto/rootfs/usr/lib/libssl.so.3")
 *   Returns: "/usr/lib/libssl.so.3"
 *
 * @param full_path The full path to normalize
 * @return Pointer to the normalized path (within the same string, not a copy).
 *         Returns the original path if no prefix is configured or prefix doesn't match.
 */
const char* normalize_cross_arch_path(const char* full_path);

/**
 * Allocate a copy of the normalized path
 * This is useful when you need to store the normalized path.
 *
 * @param full_path The full path to normalize
 * @return Newly allocated normalized path string (caller must free), or NULL on error
 */
char* normalize_cross_arch_path_dup(const char* full_path);

#endif // PATH_UTILS_H
