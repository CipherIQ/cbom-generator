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
 * @file application_scanner.h
 * @brief Application scanner for detecting crypto-using executables
 *
 * Comprehensive scanner that inventories all applications (both client tools and
 * server daemons) that link to cryptographic libraries. Fulfills REQUIREMENTS.md
 * Requirement 4 AC 4.4 and Requirement 6 AC 6.2.
 *
 * @author CBOM Generator Team
 * @date 2025-11-22
 * @version 1.5.0
 */

#ifndef APPLICATION_SCANNER_H
#define APPLICATION_SCANNER_H

#include "cbom_types.h"
#include "asset_store.h"
#include "thread_pool.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Application scanner configuration
 */
typedef struct {
    bool scan_usr_bin;           /**< Scan /usr/bin (default: true) */
    bool scan_usr_sbin;          /**< Scan /usr/sbin (default: true) */
    bool scan_usr_local;         /**< Scan /usr/local/bin, /usr/local/sbin (default: false) */
    bool scan_opt;               /**< Scan /opt (default: false) */
    int max_applications;        /**< Maximum applications to detect (0 = unlimited) */
    int thread_count;            /**< Parallel ldd execution (default: 4) */
    bool extract_versions;       /**< Attempt version extraction (default: true) */
    char** excluded_paths;       /**< Binary paths to skip (already detected by YAML plugins) */
    int excluded_path_count;     /**< Number of excluded paths */
} application_scanner_config_t;

/**
 * Application information structure
 */
typedef struct {
    char* name;                  /**< Binary name (e.g., "ssh") */
    char* binary_path;           /**< Full path (/usr/bin/ssh) */
    char* version;               /**< Extracted version (may be NULL) */
    char* category;              /**< Inferred category */
    bool is_daemon;              /**< Is this a daemon/service? */
    char** linked_libraries;     /**< Crypto libraries from ldd */
    int lib_count;               /**< Number of linked libraries */
} application_info_t;

/**
 * Initialize application scanner with configuration
 *
 * @param config Scanner configuration (NULL for defaults)
 * @return 0 on success, -1 on error
 */
int application_scanner_init(const application_scanner_config_t* config);

/**
 * Scan system for crypto-using applications (sequential)
 *
 * Scans configured directories for ELF executables, runs ldd to detect crypto
 * library dependencies, creates application components and relationships.
 *
 * @param asset_store Asset store to add applications and relationships
 * @return Number of applications detected, or -1 on error
 */
int application_scanner_scan(asset_store_t* asset_store);

/**
 * Scan a single directory for crypto-using applications (parallel)
 *
 * Uses thread pool to parallelize ldd calls across binaries for faster scanning.
 * Creates a sub-pool internally to avoid recursive submission to parent pool.
 *
 * @param asset_store Asset store to add applications and relationships
 * @param target_path Directory to scan (e.g., "/usr/bin")
 * @param thread_count Number of threads for parallel ldd execution (0 = auto)
 * @return Number of applications detected, or -1 on error
 */
int application_scanner_scan_directory_parallel(
    asset_store_t* asset_store,
    const char* target_path,
    int thread_count
);

/**
 * Cleanup application scanner resources
 */
void application_scanner_cleanup(void);

/**
 * Check if file is an ELF executable
 *
 * @param path File path to check
 * @return true if file is ELF executable with X_OK permission
 */
bool application_scanner_is_elf_executable(const char* path);

/**
 * Run ldd on binary and return library list (native-only, includes transitive dependencies)
 *
 * @param binary_path Path to binary
 * @param lib_count Output: number of libraries found
 * @return Array of library names (caller must free), or NULL on error
 */
char** application_scanner_run_ldd(const char* binary_path, int* lib_count);

/**
 * Run readelf on binary and return library list (cross-arch compatible, direct dependencies only)
 *
 * @param binary_path Path to binary
 * @param lib_count Output: number of libraries found
 * @return Array of library names (caller must free), or NULL on error
 */
char** application_scanner_run_readelf(const char* binary_path, int* lib_count);

/**
 * Extract library dependencies using configured method (readelf or ldd)
 * Uses readelf by default for cross-architecture compatibility.
 * Use --use-ldd flag to switch to ldd mode.
 *
 * @param binary_path Path to binary
 * @param lib_count Output: number of libraries found
 * @return Array of library names (caller must free), or NULL on error
 */
char** application_scanner_extract_libraries(const char* binary_path, int* lib_count);

/**
 * Filter library list to only crypto-relevant libraries
 *
 * @param all_libs All libraries from ldd
 * @param lib_count Number of libraries
 * @param crypto_count Output: number of crypto libraries found
 * @return Array of crypto library names (caller must free), or NULL if none
 */
char** application_scanner_filter_crypto_libraries(char** all_libs, int lib_count, int* crypto_count);

/**
 * Extract version information from binary
 *
 * Tries --version, -V, -v flags and parses output
 *
 * @param binary_path Path to binary
 * @return Version string (caller must free), or NULL if extraction failed
 */
char* application_scanner_extract_version(const char* binary_path);

/**
 * Infer application category from name and path
 *
 * @param name Binary name
 * @param path Full path
 * @return Category string (caller must free)
 */
char* application_scanner_infer_category(const char* name, const char* path);

/**
 * Create application info structure
 *
 * @return Allocated application_info_t or NULL on error
 */
application_info_t* application_info_create(void);

/**
 * Free application info structure
 *
 * @param info Application info to free
 */
void application_info_free(application_info_t* info);

#ifdef __cplusplus
}
#endif

#endif // APPLICATION_SCANNER_H
