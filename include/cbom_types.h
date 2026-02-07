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

#ifndef CBOM_TYPES_H
#define CBOM_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

// Asset type enumeration
typedef enum {
    ASSET_TYPE_ALGORITHM = 0,
    ASSET_TYPE_CERTIFICATE,
    ASSET_TYPE_CERTIFICATE_REQUEST,  // Issue #7: CSRs (Certificate Signing Requests)
    ASSET_TYPE_KEY,
    ASSET_TYPE_LIBRARY,
    ASSET_TYPE_PROTOCOL,
    ASSET_TYPE_SERVICE,
    ASSET_TYPE_APPLICATION,      // Application component (client apps and server daemons) - v1.5
    ASSET_TYPE_CIPHER_SUITE,     // Cipher suite component (TLS/SSH cipher suites)
    ASSET_TYPE_UNKNOWN
} asset_type_t;

// Cryptographic asset structure
typedef struct crypto_asset {
    char *id;                    // SHA-256 content-addressed ID
    char *name;                  // Asset name
    asset_type_t type;           // Asset type
    char *version;               // Version string (optional)
    char *location;              // File path or service location
    char *algorithm;             // Cryptographic algorithm
    uint32_t key_size;           // Key size in bits (0 if not applicable)
    char *hash_algorithm;        // Hash algorithm used
    bool is_weak;                // True if considered cryptographically weak
    bool is_pqc_ready;           // True if post-quantum ready
    char *metadata_json;         // Additional metadata as JSON string
    char *key_id;                // ID of associated KEY component (for certificates)
    struct crypto_asset *next;   // Linked list pointer
} crypto_asset_t;

// Forward declaration for asset store (defined in asset_store.h)
typedef struct asset_store asset_store_t;

// Relationship types
typedef enum {
    RELATIONSHIP_IMPLEMENTS,     // Library implements algorithm
    RELATIONSHIP_USES,          // Service uses protocol, protocol uses algorithm
    RELATIONSHIP_DEPENDS_ON,    // Certificate depends on key
    RELATIONSHIP_PROVIDES,      // Protocol provides cipher suite
    RELATIONSHIP_CONTAINS,      // Package contains library
    RELATIONSHIP_CONFIGURES,    // Service configures protocol
    RELATIONSHIP_LISTENS_ON,    // Service listens on port/address
    RELATIONSHIP_AUTHENTICATES_WITH, // Service authenticates with certificate
    RELATIONSHIP_SIGNS,         // Private key signs certificate (Issue #4)
    RELATIONSHIP_ISSUED_BY      // Certificate issued by parent CA (Issue #4)
} relationship_type_t;

// Relationship structure
typedef struct {
    char* id;                   // Unique relationship ID
    relationship_type_t type;
    char* source_asset_id;
    char* target_asset_id;
    float confidence;           // Confidence level (0.0-1.0)
    char* description;
} relationship_t;

// Deduplication mode enumeration
typedef enum {
    DEDUP_MODE_OFF = 0,      // Legacy behavior - no deduplication
    DEDUP_MODE_SAFE,         // Apply rules for certs, keys, OpenPGP (default)
    DEDUP_MODE_STRICT        // Safe mode + bundle modeling + relationship pruning
} dedup_mode_t;

// Configuration flags
typedef struct {
    bool deterministic;          // Deterministic output mode (default: true)
    bool no_personal_data;       // Redact personal data (default: true for privacy-by-default)
    bool include_personal_data;  // Include personal data (inverse of no_personal_data)
    bool no_network;             // Disable network operations (default: false)
    bool enable_attestation;     // Enable CBOM attestation with digital signature (default: false)
    char *signature_method;      // Signature method: "dsse" or "pgp" (default: NULL)
    char *signing_key_path;      // Path to signing key (default: NULL)
    int thread_count;            // Number of worker threads (default: CPU count)
    char *output_file;           // Output file path
    char *format;                // Output format (json, cyclonedx)
    char *cyclonedx_spec_version; // CycloneDX spec version (default: "1.6", supported: "1.6", "1.7")
    char **target_paths;         // Array of target directories to scan
    size_t target_path_count;    // Number of target directories
    dedup_mode_t dedup_mode;     // Deduplication mode (default: DEDUP_MODE_SAFE)
    bool emit_bundles;           // Emit bundle components (default: false)
    bool tui_enabled;            // Enable TUI mode (default: false)
    char *error_log_file;        // Error log file path (default: NULL)
    char *pqc_report_path;       // PQC migration report file path (default: NULL)
    bool discover_services;      // Enable service discovery via YAML plugins (default: false)
    char *plugin_dir;            // Custom plugin directory (default: "plugins/")
    bool include_fixtures;       // Include test fixtures in service detection (default: false)
    char *crypto_registry_path;  // External crypto registry YAML file (default: NULL)
    bool skip_builtin_service_scanner;  // Skip built-in service scanner when YAML plugins discover services
    bool use_ldd_for_libraries;         // Use ldd instead of readelf for library detection (default: false)
    bool skip_package_resolution;       // DEPRECATED: Use cross_arch_mode instead (kept for backward compat)
    bool cross_arch_mode;               // Cross-architecture scanning mode (skips host package manager)
    char *yocto_manifest_path;          // Path to Yocto manifest file for version lookup (default: NULL)
    bool include_all_dependencies;      // Include ALL library dependencies (default: true since v1.8.6)
    char *rootfs_prefix;                // Rootfs prefix to strip from paths (v1.8 --rootfs-prefix)
    char *scan_profile;                 // Industry scan profile name or path (Pro feature)
    char **plugin_whitelist;            // Plugin names to load (NULL = load all, set by scan profile)
    size_t plugin_whitelist_count;      // Number of whitelisted plugins
    bool plugin_config_only;            // Config-only mode: skip process/port detection (set by scan profile)
} cbom_config_t;

#endif // CBOM_TYPES_H
