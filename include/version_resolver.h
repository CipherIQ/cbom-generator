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
 * @file version_resolver.h
 * @brief Hybrid version detection for cross-architecture scanning
 *
 * Provides a tiered version resolution system:
 *   Tier 1: Yocto manifest lookup (exact versions, highest confidence)
 *   Tier 2: Package manager query (dpkg/rpm, native only)
 *   Tier 3: ELF VERNEED parsing (cross-arch, minimum API version)
 *   Tier 4: SONAME parsing (fallback, major version only)
 */

#ifndef VERSION_RESOLVER_H
#define VERSION_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Version resolution tier (source of version information)
 */
typedef enum {
    VERSION_TIER_UNKNOWN = 0,
    VERSION_TIER_MANIFEST = 1,      // Yocto manifest lookup (confidence: 0.99)
    VERSION_TIER_PACKAGE_MGR = 2,   // dpkg/rpm/pacman query (confidence: 0.95)
    VERSION_TIER_VERNEED = 3,       // ELF VERNEED section (confidence: 0.80)
    VERSION_TIER_SONAME = 4         // SONAME parsing (confidence: 0.60)
} version_tier_t;

/**
 * Resolved version information
 */
typedef struct {
    char* version_string;       // Version string (e.g., "3.0.13", "3.0.0", "3")
    version_tier_t tier;        // Which tier provided this version
    float confidence;           // Confidence level (0.0-1.0)
    bool is_minimum_version;    // True for VERNEED (lower bound, not exact)
    char* source_description;   // Human-readable source (e.g., "Yocto manifest")
    char* package_name;         // Package name (if known)
} resolved_version_t;

/**
 * Yocto manifest entry
 */
typedef struct {
    char* package_name;         // e.g., "libssl3"
    char* version;              // e.g., "3.0.13-r0"
    char* architecture;         // e.g., "aarch64"
} manifest_entry_t;

/**
 * Initialize the version resolver
 * Must be called before using version_resolver_resolve()
 *
 * @param yocto_manifest_path Path to Yocto manifest file (or NULL)
 * @param cross_arch_mode True to skip package manager queries
 * @return 0 on success, -1 on error
 */
int version_resolver_init(const char* yocto_manifest_path, bool cross_arch_mode);

/**
 * Cleanup version resolver resources
 */
void version_resolver_cleanup(void);

/**
 * Resolve library version using tiered approach
 *
 * Resolution order:
 *   1. Yocto manifest (if loaded)
 *   2. Package manager (if not cross_arch_mode)
 *   3. ELF VERNEED section
 *   4. SONAME parsing
 *
 * @param soname Library SONAME (e.g., "libssl.so.3")
 * @param library_path Full path to library file (for VERNEED, may be NULL)
 * @param pkg_name Package name hint (for manifest/dpkg lookup, may be NULL)
 * @return Resolved version (caller must free with resolved_version_free), or NULL
 */
resolved_version_t* version_resolver_resolve(
    const char* soname,
    const char* library_path,
    const char* pkg_name
);

/**
 * Free a resolved version structure
 */
void resolved_version_free(resolved_version_t* version);

/**
 * Get human-readable tier name
 */
const char* version_tier_to_string(version_tier_t tier);

/**
 * Parse version from ELF VERNEED section
 * Used internally but exposed for testing
 *
 * @param binary_path Path to ELF binary
 * @param target_soname SONAME to find version for (e.g., "libssl.so.3")
 * @return Version string (caller must free), or NULL if not found
 */
char* parse_verneed_version(const char* binary_path, const char* target_soname);

/**
 * Parse version from SONAME
 * Extracts version number from library name (e.g., "libssl.so.3" -> "3")
 *
 * @param soname Library SONAME
 * @return Version string (caller must free), or NULL if not extractable
 */
char* parse_soname_version(const char* soname);

/**
 * Load Yocto manifest file
 *
 * @param manifest_path Path to .manifest file
 * @return 0 on success, -1 on error
 */
int manifest_load(const char* manifest_path);

/**
 * Lookup version in loaded manifest
 *
 * @param soname Library SONAME (tries to map to package name)
 * @param pkg_name Package name (direct lookup)
 * @return Manifest entry (do not free), or NULL if not found
 */
const manifest_entry_t* manifest_lookup(const char* soname, const char* pkg_name);

/**
 * Unload manifest and free resources
 */
void manifest_unload(void);

/**
 * Check if manifest is loaded
 */
bool manifest_is_loaded(void);

/**
 * Version resolver statistics
 */
typedef struct {
    int tier1_hits;         // Manifest lookups successful
    int tier2_hits;         // Package manager lookups successful
    int tier3_hits;         // VERNEED parsing successful
    int tier4_hits;         // SONAME parsing successful
    int resolution_failures; // No version found
} version_resolver_stats_t;

/**
 * Get resolver statistics
 */
version_resolver_stats_t version_resolver_get_stats(void);

/**
 * Reset resolver statistics
 */
void version_resolver_reset_stats(void);

#endif /* VERSION_RESOLVER_H */
