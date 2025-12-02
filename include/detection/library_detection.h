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

#pragma once

#include <stddef.h>
#include "asset_store.h"
#include "cbom_types.h"

typedef struct {
    const char *soname;        // e.g. "libcrypto.so.3"
    const char *resolved_path; // filesystem path for the .so, if found
    const char *pkg_name;      // package name, if known
    int         is_crypto;     // 0/1
    const char *crypto_lib_id; // matches crypto_library_info_t.id, or NULL
} detected_library_t;

typedef struct {
    const char *provider_id;   // e.g. "openssh_internal"
    const char **algorithms;   // pointer to registry's NULL-terminated array
} embedded_crypto_provider_t;

typedef struct {
    const char *binary_path;     // "/usr/sbin/sshd"
    const char *binary_pkg_name; // "openssh-server", if known
    detected_library_t *libs;    // heap-allocated array
    size_t libs_count;
    embedded_crypto_provider_t *embedded_providers; // typically 0 or 1
    size_t embedded_providers_count;
} binary_crypto_profile_t;

/**
 * Analyze a single ELF binary:
 * - detect dynamic libraries (using existing ldd-based logic or ELF helpers),
 * - classify which libraries are crypto using crypto_registry,
 * - detect embedded crypto providers (OpenSSH, wireguard-go, age, etc.).
 *
 * Returns a heap-allocated profile that must be freed with free_binary_crypto_profile().
 */
binary_crypto_profile_t *analyze_binary_crypto(const char *binary_path);

/**
 * Free all heap-allocated fields inside the profile.
 */
void free_binary_crypto_profile(binary_crypto_profile_t *profile);

/**
 * Register embedded crypto providers as assets and create DEPENDS_ON relationships
 * from the owner asset to each provider.
 */
void register_embedded_providers_for_asset(
    asset_store_t *store,
    crypto_asset_t *owner_asset,
    const binary_crypto_profile_t *profile
);

/**
 * Populate library asset metadata with cbom:lib:* properties from crypto_registry.
 * Used for ELF-detected libraries and embedded providers to achieve metadata parity
 * with package-scanned libraries.
 *
 * @param lib_asset The library asset to populate (must not be NULL)
 * @param lib_info  ELF-detected library info (NULL for embedded providers)
 * @param embedded_info Embedded provider info (NULL for ELF-detected libraries)
 */
void populate_library_metadata(
    crypto_asset_t *lib_asset,
    const detected_library_t *lib_info,
    const embedded_crypto_provider_t *embedded_info
);

/**
 * Create PROVIDES relationships from a library to its implemented algorithms.
 * Should be called after populate_library_metadata() and asset_store_add().
 *
 * @param store     The asset store to add relationships to
 * @param lib_asset The library asset (must already be in store)
 * @param lib_info  ELF-detected library info with crypto_lib_id
 */
void create_library_algorithm_relationships(
    asset_store_t *store,
    crypto_asset_t *lib_asset,
    const detected_library_t *lib_info
);

/**
 * Extract SONAME from ELF binary using in-process parsing.
 * Avoids spawning external readelf process for better performance.
 * Supports both 32-bit and 64-bit ELF, and cross-architecture binaries.
 *
 * @param library_path Absolute path to the ELF shared library
 * @return Dynamically allocated SONAME string (caller must free), or
 *         basename of path as fallback if SONAME extraction fails
 */
char* extract_soname_from_elf(const char* library_path);

/**
 * Get SONAME with caching - thread-safe cached wrapper.
 * Uses a path→SONAME cache to avoid repeated ELF parsing.
 *
 * @param library_path Absolute path to the ELF shared library
 * @return Dynamically allocated SONAME string (caller must free)
 */
char* get_soname_cached(const char* library_path);
