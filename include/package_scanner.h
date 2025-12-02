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

#ifndef PACKAGE_SCANNER_H
#define PACKAGE_SCANNER_H

#include <stdbool.h>
#include <time.h>
#include <stddef.h>
#include <pthread.h>

// Forward declarations
struct asset_store;
struct crypto_asset;
struct scan_context;

// Package manager enumeration
typedef enum {
    PKG_MANAGER_APT,             // Debian/Ubuntu APT
    PKG_MANAGER_RPM,             // RedHat/CentOS/Fedora RPM
    PKG_MANAGER_PACMAN,          // Arch Linux Pacman
    PKG_MANAGER_PIP,             // Python pip
    PKG_MANAGER_NPM,             // Node.js npm
    PKG_MANAGER_GEM,             // RubyGems
    PKG_MANAGER_SNAP,            // Snap packages (future)
    PKG_MANAGER_FLATPAK,         // Flatpak (future)
    PKG_MANAGER_UNKNOWN
} package_manager_t;

// FIPS certification level (metadata stub only - NOT validated)
typedef enum {
    FIPS_LEVEL_140_3_L1,         // FIPS 140-3 Level 1
    FIPS_LEVEL_140_3_L2,         // FIPS 140-3 Level 2
    FIPS_LEVEL_140_3_L3,         // FIPS 140-3 Level 3
    FIPS_LEVEL_140_3_L4,         // FIPS 140-3 Level 4
    FIPS_LEVEL_140_2,            // FIPS 140-2 (legacy)
    FIPS_NOT_CERTIFIED,          // Not FIPS certified
    FIPS_UNKNOWN                 // FIPS status unknown
} fips_level_t;

// FIPS detection method (for transparency)
typedef enum {
    FIPS_DETECT_PACKAGE_NAME,    // Detected from package name
    FIPS_DETECT_VERSION_STRING,  // Detected from version string
    FIPS_DETECT_PROC_FLAG,       // Detected from /proc/sys/crypto/fips_enabled
    FIPS_DETECT_CONFIG_FILE,     // Detected from configuration
    FIPS_DETECT_NONE             // No FIPS detection performed
} fips_detection_method_t;

// Package type (system vs application)
typedef enum {
    PACKAGE_TYPE_SYSTEM,         // System package (apt, rpm, pacman)
    PACKAGE_TYPE_APPLICATION,    // Application package (pip, npm, gem)
    PACKAGE_TYPE_UNKNOWN
} package_type_t;

// Package metadata structure
typedef struct {
    char* name;                  // Package name
    char* version;               // Version string
    package_manager_t package_manager;  // Source package manager
    package_type_t package_type; // System or application package
    char* install_path;          // Installation location
    char* description;           // Package description

    // Cryptographic library metadata
    bool is_crypto_library;      // Is this a cryptographic library
    char** implemented_algorithms;  // List of algorithms library implements
    size_t algorithm_count;

    // FIPS metadata (STUB ONLY - not validated against NIST CMVP)
    fips_level_t fips_level;     // FIPS certification level
    char* fips_module_id;        // FIPS module ID (if known)
    bool fips_detected;          // FIPS detection attempted
    fips_detection_method_t fips_method;  // How FIPS was detected
    char* fips_detection_note;   // Additional FIPS detection info

    // Package relationships
    char** dependencies;         // Package dependencies
    size_t dependency_count;
    char* provider;              // Package provider/repository

    // Installation metadata
    time_t install_date;         // Installation date
    size_t installed_size;       // Installed size in bytes
    char* architecture;          // Architecture (x86_64, arm64, etc.)

    // Detection metadata
    char* detection_method;      // How package was detected
    float confidence;            // Detection confidence
    time_t scan_time;            // When scanned
} package_metadata_t;

// Package scanner statistics
typedef struct {
    // Total package counters
    size_t packages_scanned_total;
    size_t crypto_packages_found;
    size_t non_crypto_packages;

    // Per package manager counters
    size_t apt_packages;
    size_t rpm_packages;
    size_t pacman_packages;
    size_t pip_packages;
    size_t npm_packages;
    size_t gem_packages;
    size_t snap_packages;
    size_t flatpak_packages;

    // Crypto library counters
    size_t openssl_found;
    size_t libressl_found;
    size_t boringssl_found;
    size_t gnutls_found;
    size_t wolfssl_found;
    size_t mbedtls_found;
    size_t other_crypto_libs;

    // FIPS statistics (stub detection)
    size_t fips_certified_packages;
    size_t fips_not_certified_packages;
    size_t fips_unknown_packages;
    size_t fips_detection_failures;

    // Error tracking
    size_t parse_errors;
    size_t permission_errors;
    size_t missing_package_managers;

    // Performance metrics
    double average_processing_time_ms;
} package_scanner_stats_t;

// Package scanner configuration
typedef struct {
    // Scan scope
    bool scan_system_packages;   // APT/RPM/Pacman
    bool scan_app_packages;      // pip/npm/gems

    // Specific package manager flags
    bool scan_apt;
    bool scan_rpm;
    bool scan_pacman;
    bool scan_pip;
    bool scan_npm;
    bool scan_gem;
    bool scan_snap;
    bool scan_flatpak;

    // Resource limits
    size_t max_packages;         // Maximum packages to scan
    int timeout_seconds;         // Timeout per package manager

    // FIPS detection options (STUB ONLY)
    bool detect_fips_basic;      // Enable basic FIPS detection
    bool fips_validation_online; // Future: NIST CMVP validation (deferred)

    // Filter options
    bool crypto_only;            // Only scan crypto-related packages
    char** include_patterns;     // Package name patterns to include
    size_t include_pattern_count;
    char** exclude_patterns;     // Package name patterns to exclude
    size_t exclude_pattern_count;
} package_scanner_config_t;

// Package scanner context
typedef struct {
    package_scanner_config_t config;
    struct asset_store* asset_store;
    struct scan_context* scan_context;  // For dedup support

    // Statistics
    package_scanner_stats_t stats;

    // Thread safety
    pthread_mutex_t mutex;
} package_scanner_context_t;

// Main package scanner API
package_scanner_context_t* package_scanner_create(
    const package_scanner_config_t* config,
    struct asset_store* store);
void package_scanner_destroy(package_scanner_context_t* context);

// Scanning operations
int package_scanner_scan_system(package_scanner_context_t* context);
int package_scanner_scan_applications(package_scanner_context_t* context);
int package_scanner_scan_all(package_scanner_context_t* context);

// Per-manager scanners
int scan_apt_packages(package_scanner_context_t* context);
int scan_rpm_packages(package_scanner_context_t* context);
int scan_pacman_packages(package_scanner_context_t* context);
int scan_pip_packages(package_scanner_context_t* context);
int scan_npm_packages(package_scanner_context_t* context);
int scan_gem_packages(package_scanner_context_t* context);

// FIPS detection (STUB - not validated against NIST CMVP)
fips_level_t detect_fips_level_basic(const char* package_name,
                                     const char* version);
bool is_fips_enabled_system(void);
const char* fips_level_to_string(fips_level_t level);

// Crypto library detection
bool is_crypto_library(const char* package_name);
char** detect_implemented_algorithms(const char* library_name,
                                     const char* version,
                                     size_t* count);

// Metadata operations
package_metadata_t* package_extract_metadata(const char* name,
                                            const char* version,
                                            package_manager_t manager);
void package_metadata_destroy(package_metadata_t* metadata);

// Asset creation
struct crypto_asset* package_create_asset(const package_metadata_t* metadata);
char* package_create_detailed_json_metadata(const package_metadata_t* metadata);

// Configuration
package_scanner_config_t package_scanner_create_default_config(void);
void package_scanner_config_destroy(package_scanner_config_t* config);

// Statistics
package_scanner_stats_t package_scanner_get_stats(
    const package_scanner_context_t* context);

// Error handling
const char* package_scanner_get_last_error(void);
void package_scanner_clear_error(void);

// Utility functions
const char* package_manager_to_string(package_manager_t manager);
package_manager_t package_manager_from_string(const char* name);
bool package_manager_available(package_manager_t manager);

#endif // PACKAGE_SCANNER_H
