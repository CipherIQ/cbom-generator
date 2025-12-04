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
 * @file application_scanner.c
 * @brief Application scanner implementation - comprehensive binary scanning
 *
 * Scans /usr/bin, /usr/sbin for all ELF executables, detects crypto library
 * dependencies via ldd, creates application components with proper CycloneDX
 * type: application (per CBOM_PROPERTY_GUIDE_V1.1.md).
 *
 * Fulfills:
 * - REQUIREMENTS.md Requirement 4 AC 4.4: "determine which algorithms the application actually uses"
 * - REQUIREMENTS.md Requirement 6 AC 6.2: "record 'uses' relationships between applications and crypto assets"
 */

#define _GNU_SOURCE
#include "application_scanner.h"
#include "service_scanner.h"  // For library relationship functions
#include "secure_memory.h"
#include "detection/library_detection.h"
#include "detection/kernel_crypto_detector.h"  // v1.8.2: Kernel crypto API + static crypto detection
#include "thread_pool.h"      // For parallel execution
#include "tui.h"              // For TUI progress updates
#include <json-c/json.h>
#include <openssl/sha.h>       // v1.8.6: Content-addressed application IDs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>
#include <time.h>              // For progress timing
#include <stdatomic.h>         // For atomic counters

// find_library_by_soname is static in service_scanner.c, declare extern here
extern const char* find_library_by_soname(asset_store_t* store, const char* soname);

// Global CBOM configuration from main.c
extern cbom_config_t g_cbom_config;  // Named differently to avoid conflict with local g_cbom_config

// Global file counter for TUI progress (cumulative across all directories)
static int g_total_files_scanned = 0;

// Local application scanner configuration
static application_scanner_config_t app_scanner_config = {
    .scan_usr_bin = true,
    .scan_usr_sbin = true,
    .scan_usr_local = false,
    .scan_opt = false,
    .max_applications = 0,  // Unlimited
    .thread_count = 4,
    .extract_versions = false,  // Disabled by default - too slow for large scans
    .excluded_paths = NULL,
    .excluded_path_count = 0
};

// Atomic counters for parallel progress tracking
static atomic_size_t g_parallel_binaries_analyzed = 0;
static atomic_size_t g_total_assets_detected = 0;  // Cumulative across all directories

/**
 * v1.8.6: Generate deterministic application ID using SHA-256 hash of path.
 *
 * This replaces the timestamp-based asset_store_generate_id("app") which caused
 * non-determinism: the same binary scanned at different times would get different
 * IDs, causing deduplication to fail and app counts to vary between runs.
 *
 * Content-addressed IDs ensure:
 * - Same path always produces the same ID
 * - Parallel threads generate identical IDs for the same binary
 * - Deduplication works correctly across runs
 *
 * @param path Full path to the binary (e.g., "/usr/bin/ssh")
 * @return Newly allocated ID string (caller must free), or NULL on error
 */
static char* generate_application_id(const char* path) {
    if (!path) return NULL;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)path, strlen(path), hash);

    // Format: "app:" + 16 hex chars (8 bytes of hash) for readability
    // 16 hex chars = 64 bits = effectively unique for millions of apps
    char* id = malloc(4 + 16 + 1);  // "app:" + 16 hex chars + null = 21 bytes
    if (!id) return NULL;

    snprintf(id, 21, "app:%02x%02x%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7]);
    return id;
}

// Work item for parallel binary analysis
typedef struct {
    char* binary_path;           // Full path to binary (owned, must free)
    char* binary_name;           // Just the filename (owned, must free)
    asset_store_t* store;        // Shared asset store (thread-safe)
    const char* dir_path;        // Directory being scanned (for TUI)
    atomic_int* detected_count;  // Shared counter for detected apps
    int result;                  // Output: 0=success, -1=failure
} binary_analysis_work_t;

int application_scanner_init(const application_scanner_config_t* config) {
    if (config) {
        app_scanner_config = *config;
    }
    // Reset counters for new scan session
    atomic_store(&g_parallel_binaries_analyzed, 0);
    atomic_store(&g_total_assets_detected, 0);
    return 0;
}

/**
 * Check if binary path should be excluded (already detected by YAML plugins)
 *
 * @param path Binary path to check
 * @return true if path should be skipped, false otherwise
 *
 * NOTE: v1.8.1 - Exclusion disabled. YAML-detected services need binary analysis
 * for library dependencies. Deduplication handles any duplicate components.
 */
static bool is_excluded_path(const char* path) {
    (void)path;  // Unused - exclusion disabled
    return false;  // Never exclude - let deduplication handle duplicates
}

void application_scanner_cleanup(void) {
    // No persistent state to cleanup
}

application_info_t* application_info_create(void) {
    application_info_t* info = malloc(sizeof(application_info_t));
    if (!info) return NULL;

    memset(info, 0, sizeof(application_info_t));
    return info;
}

void application_info_free(application_info_t* info) {
    if (!info) return;

    free(info->name);
    free(info->binary_path);
    free(info->version);
    free(info->category);

    if (info->linked_libraries) {
        for (int i = 0; i < info->lib_count; i++) {
            free(info->linked_libraries[i]);
        }
        free(info->linked_libraries);
    }

    free(info);  // Use regular free, not secure_free
}

bool application_scanner_is_elf_executable(const char* path) {
    if (!path) return false;

    // Check executable permission
    if (access(path, X_OK) != 0) {
        return false;
    }

    // Check if regular file
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }

    if (!S_ISREG(st.st_mode)) {
        return false;  // Not a regular file (directory, symlink, etc.)
    }

    // Read ELF magic bytes
    FILE* f = fopen(path, "rb");
    if (!f) return false;

    unsigned char magic[4];
    size_t read_bytes = fread(magic, 1, 4, f);
    fclose(f);

    if (read_bytes != 4) return false;

    // ELF magic: 0x7F 'E' 'L' 'F'
    return (magic[0] == 0x7F && magic[1] == 'E' &&
            magic[2] == 'L' && magic[3] == 'F');
}

/**
 * Extract dynamic library dependencies using readelf (cross-architecture compatible)
 * @param binary_path Path to ELF binary
 * @param lib_count Output: number of libraries found
 * @return Array of library names (caller must free), or NULL on failure
 */
char** application_scanner_run_readelf(const char* binary_path, int* lib_count) {
    if (!binary_path || !lib_count) return NULL;

    *lib_count = 0;

    // Run readelf command to extract NEEDED entries from dynamic section
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "readelf -d '%s' 2>/dev/null | grep NEEDED", binary_path);

    FILE* fp = popen(cmd, "r");
    if (!fp) return NULL;

    // Parse readelf output
    char** libraries = NULL;
    int count = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        // Parse format: " 0x0000000000000001 (NEEDED)             Shared library: [libfoo.so.1]"
        char* bracket_start = strchr(line, '[');
        char* bracket_end = strchr(line, ']');

        if (bracket_start && bracket_end && bracket_end > bracket_start) {
            bracket_start++;  // Skip '['
            size_t len = bracket_end - bracket_start;

            // Reallocate array for new entry
            char** new_ptr = realloc(libraries, (count + 2) * sizeof(char*));
            if (!new_ptr) {
                // Cleanup on realloc failure
                if (libraries) {
                    for (int i = 0; i < count; i++) {
                        free(libraries[i]);
                    }
                    free(libraries);
                }
                pclose(fp);
                return NULL;
            }

            libraries = new_ptr;
            libraries[count] = strndup(bracket_start, len);
            if (!libraries[count]) {
                // Cleanup on strndup failure
                for (int i = 0; i < count; i++) {
                    free(libraries[i]);
                }
                free(libraries);
                pclose(fp);
                return NULL;
            }
            count++;
            libraries[count] = NULL;  // NULL-terminate array
        }
    }

    pclose(fp);
    *lib_count = count;

    return libraries;
}

char** application_scanner_run_ldd(const char* binary_path, int* lib_count) {
    if (!binary_path || !lib_count) return NULL;

    *lib_count = 0;

    // Run ldd command
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "ldd '%s' 2>/dev/null", binary_path);

    FILE* fp = popen(cmd, "r");
    if (!fp) return NULL;

    // Parse ldd output
    char** libraries = NULL;
    int count = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        // Parse: "libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)"
        char lib_name[256];

        // Try format with =>
        if (sscanf(line, " %255s =>", lib_name) == 1) {
            char** new_ptr = realloc(libraries, (count + 2) * sizeof(char*));
            if (!new_ptr) {
                // Cleanup on realloc failure
                if (libraries) {
                    for (int i = 0; i < count; i++) {
                        free(libraries[i]);
                    }
                    free(libraries);
                }
                pclose(fp);
                return NULL;
            }
            libraries = new_ptr;
            libraries[count++] = strdup(lib_name);
            libraries[count] = NULL;
        }
        // Also handle format without => : "/lib/ld-linux.so.2 (0x...)"
        else if (sscanf(line, " %255s (", lib_name) == 1) {
            // Extract basename
            char* base = strrchr(lib_name, '/');
            if (base) {
                char** new_ptr = realloc(libraries, (count + 2) * sizeof(char*));
                if (!new_ptr) {
                    // Cleanup on realloc failure
                    if (libraries) {
                        for (int i = 0; i < count; i++) {
                            free(libraries[i]);
                        }
                        free(libraries);
                    }
                    pclose(fp);
                    return NULL;
                }
                libraries = new_ptr;
                libraries[count++] = strdup(base + 1);
                libraries[count] = NULL;
            }
        }
    }

    pclose(fp);
    *lib_count = count;

    return libraries;
}

/**
 * Extract library dependencies using configured method (readelf or ldd)
 * @param binary_path Path to ELF binary
 * @param lib_count Output: number of libraries found
 * @return Array of library names (caller must free), or NULL on failure
 */
char** application_scanner_extract_libraries(const char* binary_path, int* lib_count) {
    if (!binary_path || !lib_count) return NULL;

    // Check global CBOM config for library detection method
    if (g_cbom_config.use_ldd_for_libraries) {
        // Use ldd (native-only, includes transitive dependencies)
        return application_scanner_run_ldd(binary_path, lib_count);
    } else {
        // Use readelf (cross-architecture compatible, direct dependencies only)
        return application_scanner_run_readelf(binary_path, lib_count);
    }
}

char* application_scanner_extract_version(const char* binary_path) {
    if (!binary_path) return NULL;

    // Try common version flags
    const char* version_flags[] = {"--version", "-V", "-v", NULL};

    for (int i = 0; version_flags[i] != NULL; i++) {
        char cmd[4096];
        snprintf(cmd, sizeof(cmd), "'%s' %s 2>&1 | head -1", binary_path, version_flags[i]);

        FILE* fp = popen(cmd, "r");
        if (!fp) continue;

        char version_line[256] = {0};
        char* result = NULL;

        // Read version line
        if (fgets(version_line, sizeof(version_line), fp)) {
            version_line[strcspn(version_line, "\n")] = '\0';

            // If we got output and it's not an error message
            if (strlen(version_line) > 0 &&
                !strstr(version_line, "invalid") &&
                !strstr(version_line, "unknown") &&
                !strstr(version_line, "illegal") &&
                !strstr(version_line, "not found")) {
                result = strdup(version_line);
            }
        }

        // Always close the pipe before returning or continuing
        pclose(fp);

        // If we found a valid version, return it
        if (result) {
            return result;
        }
    }

    return NULL;  // Version extraction failed
}

char* application_scanner_infer_category(const char* name, const char* path) {
    if (!name) return strdup("application");

    (void)path;  // Reserved for future path-based inference

    // Network clients
    if (strstr(name, "ssh") && !strstr(name, "sshd")) {
        return strdup("network_client");
    }
    if (strstr(name, "curl") || strstr(name, "wget") || strstr(name, "http")) {
        return strdup("network_client");
    }
    if (strstr(name, "ftp") || strstr(name, "sftp") || strstr(name, "scp")) {
        return strdup("network_client");
    }
    if (strstr(name, "telnet") || strstr(name, "nc") || strstr(name, "netcat")) {
        return strdup("network_client");
    }

    // Crypto tools
    if (strstr(name, "openssl") || strstr(name, "gpg") || strstr(name, "age")) {
        return strdup("crypto_tool");
    }
    if (strstr(name, "certbot") || strstr(name, "acme") || strstr(name, "keygen")) {
        return strdup("crypto_tool");
    }

    // VPN clients
    if (strstr(name, "vpn") || strstr(name, "wireguard") || strstr(name, "wg-")) {
        return strdup("vpn_client");
    }

    // Database clients
    if (strstr(name, "mysql") && !strstr(name, "mysqld")) {
        return strdup("database_client");
    }
    if (strstr(name, "psql") || strstr(name, "pg_")) {
        return strdup("database_client");
    }
    if (strstr(name, "redis-cli") || strstr(name, "mongosh")) {
        return strdup("database_client");
    }

    // Package managers
    if (strstr(name, "apt") || strstr(name, "pip") || strstr(name, "npm")) {
        return strdup("package_manager");
    }
    if (strstr(name, "gem") || strstr(name, "cargo") || strstr(name, "go get")) {
        return strdup("package_manager");
    }

    // Runtime/interpreters
    if (strcmp(name, "python") == 0 || strcmp(name, "python3") == 0) {
        return strdup("runtime");
    }
    if (strcmp(name, "ruby") == 0 || strcmp(name, "node") == 0) {
        return strdup("runtime");
    }

    // Default
    return strdup("application");
}

// Scan single directory for applications
static int scan_directory_for_applications(const char* dir_path, asset_store_t* asset_store, int* detected_count) {
    if (!dir_path || !asset_store || !detected_count) return -1;

    DIR* dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "[WARN] Cannot open directory: %s\n", dir_path);
        return 0;  // Not an error, just skip
    }

    struct dirent* entry;
    int local_count = 0;
    int files_scanned = 0;
    int elf_count = 0;
    int ldd_success = 0;
    int crypto_linked = 0;
    time_t last_progress = time(NULL);  // For TUI progress timing

    fprintf(stderr, "[INFO] Application Scanner: Scanning %s...\n", dir_path);

    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        files_scanned++;
        g_total_files_scanned++;  // Increment global cumulative counter

        // TUI progress update: every 25 files OR every 2 seconds
        time_t now = time(NULL);
        if (g_total_files_scanned % 25 == 0 || (now - last_progress) >= 2) {
            tui_log(TUI_MSG_SCANNER_PROGRESS, SCANNER_APPLICATION,
                    "Application Scanner", g_total_files_scanned, *detected_count + local_count, NULL, dir_path);
            last_progress = now;
        }

        // Build full path
        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        // Check if ELF executable
        if (!application_scanner_is_elf_executable(full_path)) {
            continue;
        }

        // Skip shared libraries - they should be type: library, not application
        // Library detection handles these via library_detection.c
        if (strstr(entry->d_name, ".so") != NULL) {
            continue;
        }

        elf_count++;

        // Check if path is excluded (already detected by YAML plugins)
        if (is_excluded_path(full_path)) {
            // Skipped: already detected by YAML plugin
            continue;
        }

        // Progress logging every 100 ELF binaries (disabled for production)
        // if (elf_count % 100 == 0) {
        //     fprintf(stderr, "INFO: Scanned %d ELF executables, %d crypto-linked...\n", elf_count, crypto_linked);
        // }

        // Analyze binary for crypto-related libraries/providers
        binary_crypto_profile_t* profile = analyze_binary_crypto(full_path);
        if (!profile) {
            continue;  // Not ELF or analysis failed
        }

        if (profile->libs_count == 0) {
            free_binary_crypto_profile(profile);
            continue;
        }

        ldd_success++;  // align with previous counter semantics (ldd succeeded)

        // Count crypto-linked libraries
        int crypto_count = 0;
        for (size_t i = 0; i < profile->libs_count; i++) {
            if (profile->libs[i].is_crypto) crypto_count++;
        }

        // v1.8.2: Enhanced crypto detection - check for kernel crypto API, static linking, and embedded symbols
        // v1.9.0: Store algorithm info for PQC classification before freeing
        const char* alternate_detection_method = NULL;
        bool has_alternate_crypto = false;
        char* alternate_algorithms_json = NULL;  // Store algorithms for PQC classification

        if (crypto_count == 0 && profile->embedded_providers_count == 0) {
            // No dynamic crypto libraries found - check for other crypto patterns
            kernel_crypto_info_t kinfo = {0};
            static_crypto_info_t sinfo = {0};
            embedded_crypto_info_t einfo = {0};

            if (detect_kernel_crypto_usage(full_path, &kinfo)) {
                has_alternate_crypto = true;
                alternate_detection_method = "KERNEL_CRYPTO_API";
                // v1.9.0: Serialize algorithms to JSON for PQC classification
                if (kinfo.algorithm_count > 0 && kinfo.algorithms) {
                    struct json_object* arr = json_object_new_array();
                    for (size_t j = 0; j < kinfo.algorithm_count; j++) {
                        if (kinfo.algorithms[j]) {
                            json_object_array_add(arr, json_object_new_string(kinfo.algorithms[j]));
                        }
                    }
                    alternate_algorithms_json = strdup(json_object_to_json_string(arr));
                    json_object_put(arr);
                }
            } else if (detect_static_crypto(full_path, &sinfo)) {
                has_alternate_crypto = true;
                alternate_detection_method = "STATIC_LINKED";
                // v1.9.0: Serialize packages to JSON for PQC classification
                if (sinfo.package_count > 0 && sinfo.packages) {
                    struct json_object* arr = json_object_new_array();
                    for (size_t j = 0; j < sinfo.package_count; j++) {
                        if (sinfo.packages[j]) {
                            json_object_array_add(arr, json_object_new_string(sinfo.packages[j]));
                        }
                    }
                    alternate_algorithms_json = strdup(json_object_to_json_string(arr));
                    json_object_put(arr);
                }
            } else if (detect_embedded_crypto_symbols(full_path, &einfo)) {
                has_alternate_crypto = true;
                alternate_detection_method = "SYMBOL_ANALYSIS";
                // v1.9.0: Serialize symbols to JSON for PQC classification
                if (einfo.symbol_count > 0 && einfo.symbols) {
                    struct json_object* arr = json_object_new_array();
                    for (size_t j = 0; j < einfo.symbol_count; j++) {
                        if (einfo.symbols[j]) {
                            json_object_array_add(arr, json_object_new_string(einfo.symbols[j]));
                        }
                    }
                    alternate_algorithms_json = strdup(json_object_to_json_string(arr));
                    json_object_put(arr);
                }
            }

            kernel_crypto_info_free(&kinfo);
            static_crypto_info_free(&sinfo);
            embedded_crypto_info_free(&einfo);

            if (!has_alternate_crypto) {
                free_binary_crypto_profile(profile);
                continue;  // Not crypto-relevant
            }
        }

        crypto_linked++;

        // Extract version (best effort)
        char* version = NULL;
        if (app_scanner_config.extract_versions) {
            version = application_scanner_extract_version(full_path);
        }

        // Infer category
        char* category = application_scanner_infer_category(entry->d_name, full_path);

        // Create application component (use malloc, not secure_alloc - matches crypto_asset_destroy)
        crypto_asset_t* app_asset = malloc(sizeof(crypto_asset_t));
        if (!app_asset) {
            // Cleanup and continue
            if (version) free(version);
            if (category) free(category);
            free_binary_crypto_profile(profile);
            continue;
        }

        memset(app_asset, 0, sizeof(crypto_asset_t));

        app_asset->type = ASSET_TYPE_APPLICATION;
        app_asset->name = strdup(entry->d_name);
        app_asset->version = version;  // Transfer ownership (don't free later)
        app_asset->location = strdup(full_path);

        // v1.8.6: Content-addressed ID from path hash (deterministic)
        app_asset->id = generate_application_id(full_path);

        // Classify application role: service (daemon), client, or utility
        const char* role = "utility";  // Default
        const char* name_lower = entry->d_name;

        // Heuristic 1: Path-based detection (/sbin/ → service)
        if (strstr(full_path, "/sbin/") != NULL) {
            role = "service";
        }
        // Heuristic 2: Name patterns for services (ends with 'd' or contains 'server')
        else if (strlen(name_lower) > 1 &&
                 (name_lower[strlen(name_lower)-1] == 'd' ||  // sshd, nginx, dockerd
                  strstr(name_lower, "server") ||              // redis-server
                  strstr(name_lower, "daemon"))) {             // various daemons
            role = "service";
        }
        // Heuristic 3: Known client patterns
        else if (strstr(name_lower, "client") ||
                 strcmp(name_lower, "ssh") == 0 ||
                 strcmp(name_lower, "curl") == 0 ||
                 strcmp(name_lower, "wget") == 0 ||
                 strcmp(name_lower, "git") == 0) {
            role = "client";
        }

        // Build metadata JSON (extended with role classification)
        struct json_object* metadata_root = json_object_new_object();
        json_object_object_add(metadata_root, "binary_path", json_object_new_string(full_path));
        json_object_object_add(metadata_root, "category", json_object_new_string(category ? category : ""));
        json_object_object_add(metadata_root, "role", json_object_new_string(role));
        json_object_object_add(metadata_root, "is_daemon", json_object_new_boolean(strcmp(role, "service") == 0));
        // v1.8.2: Use alternate detection method if found via kernel/static/symbol analysis
        const char* detection_method = alternate_detection_method ? alternate_detection_method : "BINARY_SCAN";
        json_object_object_add(metadata_root, "detection_method", json_object_new_string(detection_method));

        // Attach embedded crypto providers if detected
        if (profile && profile->embedded_providers_count > 0 && profile->embedded_providers) {
            struct json_object* providers_arr = json_object_new_array();
            for (size_t i = 0; i < profile->embedded_providers_count; i++) {
                struct json_object* provider_obj = json_object_new_object();
                json_object_object_add(provider_obj, "provider_id",
                                       json_object_new_string(profile->embedded_providers[i].provider_id));
                struct json_object* alg_arr = json_object_new_array();
                if (profile->embedded_providers[i].algorithms) {
                    for (const char** alg = profile->embedded_providers[i].algorithms; *alg != NULL; alg++) {
                        json_object_array_add(alg_arr, json_object_new_string(*alg));
                    }
                }
                json_object_object_add(provider_obj, "algorithms", alg_arr);
                json_object_array_add(providers_arr, provider_obj);
            }
            json_object_object_add(metadata_root, "embedded_crypto_providers", providers_arr);
        }

        // v1.9.0: Add alternate detection algorithms for PQC classification
        if (alternate_algorithms_json) {
            struct json_object* algos = json_tokener_parse(alternate_algorithms_json);
            if (algos) {
                json_object_object_add(metadata_root, "alternate_algorithms", algos);
            }
            free(alternate_algorithms_json);
            alternate_algorithms_json = NULL;
        }

        const char* metadata_str = json_object_to_json_string_ext(metadata_root, JSON_C_TO_STRING_PLAIN);
        app_asset->metadata_json = strdup(metadata_str ? metadata_str : "{}");
        json_object_put(metadata_root);

        // Add to asset store
        int result = asset_store_add(asset_store, app_asset);
        if (result == 0 || result == 1) {  // 0=added, 1=duplicate
            local_count++;

            // Register embedded providers as components + relationships
            register_embedded_providers_for_asset(asset_store, app_asset, profile);

            // Create application → library dependencies
            // v1.8.6: Include ALL libraries by default (not just crypto)
            // v1.8.6: Use atomic get-or-create to fix race condition
            for (size_t i = 0; i < profile->libs_count; i++) {
                if (!profile->libs[i].soname) continue;  // Must have SONAME

                // v1.8.6: include_all_dependencies defaults to true
                bool include_this_lib = profile->libs[i].is_crypto ||
                                        g_cbom_config.include_all_dependencies;
                if (!include_this_lib) continue;

                // Atomic get-or-create to prevent race conditions
                bool was_created = false;
                const char* lib_id = asset_store_get_or_create_library(
                    asset_store,
                    profile->libs[i].soname,
                    profile->libs[i].resolved_path,
                    &was_created);

                // v1.9.2: ALWAYS process crypto libraries (even if not newly created)
                // to ensure algorithm components and PROVIDES relationships are created.
                // The TOCTOU fix (v1.8.6) was too aggressive - it skipped algorithm creation
                // for libraries already registered by Phase 4.5 service discovery.
                if (lib_id) {
                    crypto_asset_t* lib_asset = asset_store_find(asset_store, lib_id);
                    if (lib_asset) {
                        if (profile->libs[i].is_crypto) {
                            // Populate cbom:lib: properties from crypto_registry (idempotent)
                            populate_library_metadata(lib_asset, &profile->libs[i], NULL);

                            // Create PROVIDES relationships for implemented algorithms
                            // Both asset_store_add and asset_store_add_relationship handle duplicates
                            create_library_algorithm_relationships(asset_store,
                                                                   lib_asset,
                                                                   &profile->libs[i]);
                        } else if (was_created) {
                            // Non-crypto library - minimal metadata only when newly created (v1.8)
                            struct json_object* meta = json_object_new_object();
                            if (meta) {
                                json_object_object_add(meta, "name",
                                    json_object_new_string(profile->libs[i].soname));
                                json_object_object_add(meta, "type",
                                    json_object_new_string("system"));
                                const char* meta_str = json_object_to_json_string(meta);
                                if (meta_str) {
                                    lib_asset->metadata_json = strdup(meta_str);
                                }
                                json_object_put(meta);
                            }
                        }
                    }
                }

                if (lib_id) {
                    create_service_library_relationship(asset_store,
                                                        app_asset->id,
                                                        lib_id,
                                                        0.90);
                }
            }
        }

        // Cleanup (version already transferred to app_asset, don't free)
        if (category) {
            free(category);
            category = NULL;
        }
        // Note: version NOT freed here - ownership transferred to app_asset
        version = NULL;  // Mark as transferred

        free_binary_crypto_profile(profile);

        // Check max limit
        if (app_scanner_config.max_applications > 0 && (*detected_count + local_count) >= app_scanner_config.max_applications) {
            break;
        }
    }

    closedir(dir);
    *detected_count += local_count;

    fprintf(stderr, "[INFO] Application Scanner: %s complete\n", dir_path);
    fprintf(stderr, "[INFO]   Files scanned: %d, ELF executables: %d, ldd succeeded: %d\n", files_scanned, elf_count, ldd_success);
    fprintf(stderr, "[INFO]   Crypto-linked: %d, Applications added: %d\n", crypto_linked, local_count);
    return local_count;
}

int application_scanner_scan(asset_store_t* asset_store) {
    if (!asset_store) {
        fprintf(stderr, "[ERROR] Application scanner: asset_store is NULL\n");
        return -1;
    }

    int total_detected = 0;
    g_total_files_scanned = 0;  // Reset global counter at start of scan

    fprintf(stderr, "[INFO] Application Scanner: Starting comprehensive binary scan (sequential)...\n");

    // Scan each target path directly as provided by the user (no hardcoded paths)
    extern cbom_config_t g_cbom_config;  // Access global config for target paths
    for (size_t i = 0; i < g_cbom_config.target_path_count && i < 32; i++) {
        const char* target = g_cbom_config.target_paths[i];
        fprintf(stderr, "[INFO] Application Scanner: Scanning %s\n", target);

        int result = scan_directory_for_applications(target, asset_store, &total_detected);
        if (result < 0) {
            fprintf(stderr, "[WARN] Application Scanner: %s scan had errors\n", target);
        }
    }

    fprintf(stderr, "[INFO] Application Scanner: COMPLETE - Total applications detected: %d\n", total_detected);
    return total_detected;
}

// =============================================================================
// PARALLEL IMPLEMENTATION
// =============================================================================

/**
 * Worker function for parallel binary analysis
 * Runs in thread pool worker thread
 */
static int binary_analysis_worker(void* data, void* context) {
    (void)context;  // Unused
    binary_analysis_work_t* work = (binary_analysis_work_t*)data;
    if (!work || !work->binary_path || !work->store) {
        return -1;
    }

    // Check if path is excluded (already detected by YAML plugins)
    if (is_excluded_path(work->binary_path)) {
        // Worker owns these strings - free them before returning
        free(work->binary_path);
        free(work->binary_name);
        work->binary_path = NULL;
        work->binary_name = NULL;
        work->result = 0;  // Not an error, just skipped
        return 0;
    }

    // Skip shared libraries - they should be type: library, not application
    // Library detection handles these via library_detection.c
    if (strstr(work->binary_name, ".so") != NULL) {
        free(work->binary_path);
        free(work->binary_name);
        work->binary_path = NULL;
        work->binary_name = NULL;
        work->result = 0;
        return 0;
    }

    // Increment counter at START - count ALL binaries analyzed (not just crypto ones)
    size_t analyzed = atomic_fetch_add(&g_parallel_binaries_analyzed, 1) + 1;

    // Report progress every 10 binaries for responsive TUI
    if (analyzed % 10 == 0) {
        size_t detected = atomic_load(&g_total_assets_detected);  // Use cumulative counter
        tui_log(TUI_MSG_SCANNER_PROGRESS, SCANNER_APPLICATION,
                "Application Scanner", analyzed, detected, NULL, work->dir_path);
    }

    // Analyze binary for crypto-related libraries/providers
    binary_crypto_profile_t* profile = analyze_binary_crypto(work->binary_path);
    if (!profile) {
        // Worker owns these strings - free them before returning
        free(work->binary_path);
        free(work->binary_name);
        work->binary_path = NULL;
        work->binary_name = NULL;
        work->result = 0;  // Not an error - just not ELF or analysis failed
        return 0;
    }

    if (profile->libs_count == 0) {
        free_binary_crypto_profile(profile);
        // Worker owns these strings - free them before returning
        free(work->binary_path);
        free(work->binary_name);
        work->binary_path = NULL;
        work->binary_name = NULL;
        work->result = 0;
        return 0;
    }

    // Count crypto-linked libraries
    int crypto_count = 0;
    for (size_t i = 0; i < profile->libs_count; i++) {
        if (profile->libs[i].is_crypto) crypto_count++;
    }

    // v1.8.4: Track alternate detection method for kernel crypto/static linking
    // v1.9.0: Store algorithm info for PQC classification before freeing
    const char* alternate_detection_method = NULL;
    char* alternate_algorithms_json = NULL;  // Store algorithms for PQC classification

    if (crypto_count == 0 && profile->embedded_providers_count == 0) {
        // v1.8.4: Try kernel crypto/static linking detection before skipping
        kernel_crypto_info_t kinfo = {0};
        static_crypto_info_t sinfo = {0};
        embedded_crypto_info_t einfo = {0};

        bool has_other_crypto = false;

        if (detect_kernel_crypto_usage(work->binary_path, &kinfo)) {
            has_other_crypto = true;
            alternate_detection_method = "KERNEL_CRYPTO_API";
            // v1.9.0: Serialize algorithms to JSON for PQC classification
            if (kinfo.algorithm_count > 0 && kinfo.algorithms) {
                struct json_object* arr = json_object_new_array();
                for (size_t j = 0; j < kinfo.algorithm_count; j++) {
                    if (kinfo.algorithms[j]) {
                        json_object_array_add(arr, json_object_new_string(kinfo.algorithms[j]));
                    }
                }
                alternate_algorithms_json = strdup(json_object_to_json_string(arr));
                json_object_put(arr);
            }
        } else if (detect_static_crypto(work->binary_path, &sinfo)) {
            has_other_crypto = true;
            alternate_detection_method = "STATIC_LINKED";
            // v1.9.0: Serialize packages to JSON for PQC classification
            if (sinfo.package_count > 0 && sinfo.packages) {
                struct json_object* arr = json_object_new_array();
                for (size_t j = 0; j < sinfo.package_count; j++) {
                    if (sinfo.packages[j]) {
                        json_object_array_add(arr, json_object_new_string(sinfo.packages[j]));
                    }
                }
                alternate_algorithms_json = strdup(json_object_to_json_string(arr));
                json_object_put(arr);
            }
        } else if (detect_embedded_crypto_symbols(work->binary_path, &einfo)) {
            has_other_crypto = true;
            alternate_detection_method = "SYMBOL_ANALYSIS";
            // v1.9.0: Serialize symbols to JSON for PQC classification
            if (einfo.symbol_count > 0 && einfo.symbols) {
                struct json_object* arr = json_object_new_array();
                for (size_t j = 0; j < einfo.symbol_count; j++) {
                    if (einfo.symbols[j]) {
                        json_object_array_add(arr, json_object_new_string(einfo.symbols[j]));
                    }
                }
                alternate_algorithms_json = strdup(json_object_to_json_string(arr));
                json_object_put(arr);
            }
        }

        // Clean up detection info structures
        kernel_crypto_info_free(&kinfo);
        static_crypto_info_free(&sinfo);
        embedded_crypto_info_free(&einfo);

        if (!has_other_crypto) {
            free_binary_crypto_profile(profile);
            // Worker owns these strings - free them before returning
            free(work->binary_path);
            free(work->binary_name);
            work->binary_path = NULL;
            work->binary_name = NULL;
            work->result = 0;
            return 0;
        }
        // Has crypto through kernel API, static linking, or embedded symbols - continue
    }

    // Extract version (best effort) - DISABLED in parallel mode (subprocess overhead)
    char* version = NULL;
    // if (app_scanner_config.extract_versions) {
    //     version = application_scanner_extract_version(work->binary_path);
    // }

    // Infer category
    char* category = application_scanner_infer_category(work->binary_name, work->binary_path);

    // Create application component
    crypto_asset_t* app_asset = malloc(sizeof(crypto_asset_t));
    if (!app_asset) {
        if (version) free(version);
        if (category) free(category);
        free_binary_crypto_profile(profile);
        // Worker owns these strings - free them before returning
        free(work->binary_path);
        free(work->binary_name);
        work->binary_path = NULL;
        work->binary_name = NULL;
        work->result = -1;
        return -1;
    }

    memset(app_asset, 0, sizeof(crypto_asset_t));

    app_asset->type = ASSET_TYPE_APPLICATION;
    app_asset->name = strdup(work->binary_name);
    app_asset->version = version;
    app_asset->location = strdup(work->binary_path);
    // v1.8.6: Content-addressed ID from path hash (deterministic)
    app_asset->id = generate_application_id(work->binary_path);

    // Classify application role
    const char* role = "utility";
    if (strstr(work->binary_path, "/sbin/") != NULL) {
        role = "service";
    } else if (strlen(work->binary_name) > 1 &&
               (work->binary_name[strlen(work->binary_name)-1] == 'd' ||
                strstr(work->binary_name, "server") ||
                strstr(work->binary_name, "daemon"))) {
        role = "service";
    } else if (strstr(work->binary_name, "client") ||
               strcmp(work->binary_name, "ssh") == 0 ||
               strcmp(work->binary_name, "curl") == 0 ||
               strcmp(work->binary_name, "wget") == 0 ||
               strcmp(work->binary_name, "git") == 0) {
        role = "client";
    }

    // Build metadata JSON
    struct json_object* metadata_root = json_object_new_object();
    json_object_object_add(metadata_root, "binary_path", json_object_new_string(work->binary_path));
    json_object_object_add(metadata_root, "category", json_object_new_string(category ? category : ""));
    json_object_object_add(metadata_root, "role", json_object_new_string(role));
    json_object_object_add(metadata_root, "is_daemon", json_object_new_boolean(strcmp(role, "service") == 0));
    // v1.8.4: Use alternate detection method if set, otherwise default to BINARY_SCAN_PARALLEL
    const char* detection_method = (alternate_detection_method && alternate_detection_method[0])
                                   ? alternate_detection_method
                                   : "BINARY_SCAN_PARALLEL";
    json_object_object_add(metadata_root, "detection_method", json_object_new_string(detection_method));

    // Attach embedded crypto providers if detected
    if (profile->embedded_providers_count > 0 && profile->embedded_providers) {
        struct json_object* providers_arr = json_object_new_array();
        for (size_t i = 0; i < profile->embedded_providers_count; i++) {
            struct json_object* provider_obj = json_object_new_object();
            json_object_object_add(provider_obj, "provider_id",
                                   json_object_new_string(profile->embedded_providers[i].provider_id));
            struct json_object* alg_arr = json_object_new_array();
            if (profile->embedded_providers[i].algorithms) {
                for (const char** alg = profile->embedded_providers[i].algorithms; *alg != NULL; alg++) {
                    json_object_array_add(alg_arr, json_object_new_string(*alg));
                }
            }
            json_object_object_add(provider_obj, "algorithms", alg_arr);
            json_object_array_add(providers_arr, provider_obj);
        }
        json_object_object_add(metadata_root, "embedded_crypto_providers", providers_arr);
    }

    // v1.9.0: Add alternate detection algorithms for PQC classification
    if (alternate_algorithms_json) {
        struct json_object* algos = json_tokener_parse(alternate_algorithms_json);
        if (algos) {
            json_object_object_add(metadata_root, "alternate_algorithms", algos);
        }
        free(alternate_algorithms_json);
        alternate_algorithms_json = NULL;
    }

    const char* metadata_str = json_object_to_json_string_ext(metadata_root, JSON_C_TO_STRING_PLAIN);
    app_asset->metadata_json = strdup(metadata_str ? metadata_str : "{}");
    json_object_put(metadata_root);

    // Add to asset store (thread-safe)
    int result = asset_store_add(work->store, app_asset);

    if (result == 0 || result == 1) {
        atomic_fetch_add(work->detected_count, 1);
        atomic_fetch_add(&g_total_assets_detected, 1);  // Cumulative counter for progress

        // Register embedded providers
        register_embedded_providers_for_asset(work->store, app_asset, profile);

        // v1.8.6: Include ALL libraries by default (not just crypto)
        // v1.8.6: Use atomic get-or-create to fix race condition in parallel scanner
        for (size_t i = 0; i < profile->libs_count; i++) {
            if (!profile->libs[i].soname) {
                continue;
            }

            // v1.8.6: include_all_dependencies defaults to true
            bool include_this_lib = profile->libs[i].is_crypto ||
                                    g_cbom_config.include_all_dependencies;
            if (!include_this_lib) {
                continue;
            }

            // Atomic get-or-create to prevent race conditions
            bool was_created = false;
            const char* lib_id = asset_store_get_or_create_library(
                work->store,
                profile->libs[i].soname,
                profile->libs[i].resolved_path,
                &was_created);

            // If we created the library, populate metadata
            if (was_created && lib_id) {
                crypto_asset_t* lib_asset = asset_store_find(work->store, lib_id);
                if (lib_asset) {
                    if (profile->libs[i].is_crypto) {
                        populate_library_metadata(lib_asset, &profile->libs[i], NULL);

                        // Create PROVIDES relationships for implemented algorithms
                        create_library_algorithm_relationships(work->store,
                                                               lib_asset,
                                                               &profile->libs[i]);
                    } else {
                        // Non-crypto library - minimal metadata (v1.8)
                        struct json_object* meta = json_object_new_object();
                        if (meta) {
                            json_object_object_add(meta, "name",
                                json_object_new_string(profile->libs[i].soname));
                            json_object_object_add(meta, "type",
                                json_object_new_string("system"));
                            const char* meta_str = json_object_to_json_string(meta);
                            if (meta_str) {
                                lib_asset->metadata_json = strdup(meta_str);
                            }
                            json_object_put(meta);
                        }
                    }
                }
            }

            if (lib_id) {
                create_service_library_relationship(work->store, app_asset->id, lib_id, 0.90);
            }
        }
    }

    // Cleanup
    if (category) free(category);
    free_binary_crypto_profile(profile);

    // Worker owns these strings - free them before returning
    free(work->binary_path);
    free(work->binary_name);
    work->binary_path = NULL;
    work->binary_name = NULL;

    work->result = 0;
    return 0;
}

/**
 * Parallel directory scan implementation
 */
int application_scanner_scan_directory_parallel(
    asset_store_t* asset_store,
    const char* target_path,
    int thread_count
) {
    if (!asset_store || !target_path) {
        fprintf(stderr, "[ERROR] application_scanner_scan_directory_parallel: NULL argument\n");
        return -1;
    }

    DIR* dir = opendir(target_path);
    if (!dir) {
        fprintf(stderr, "[WARN] Cannot open directory: %s\n", target_path);
        return 0;
    }

    // Phase 1: Collect ELF binaries (single-threaded, fast)
    char** binary_paths = NULL;
    char** binary_names = NULL;
    size_t binary_count = 0;
    size_t binary_capacity = 256;

    binary_paths = malloc(binary_capacity * sizeof(char*));
    binary_names = malloc(binary_capacity * sizeof(char*));
    if (!binary_paths || !binary_names) {
        closedir(dir);
        free(binary_paths);
        free(binary_names);
        return -1;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", target_path, entry->d_name);

        if (!application_scanner_is_elf_executable(full_path)) {
            continue;
        }

        // Grow arrays if needed
        if (binary_count >= binary_capacity) {
            binary_capacity *= 2;
            char** new_paths = realloc(binary_paths, binary_capacity * sizeof(char*));
            char** new_names = realloc(binary_names, binary_capacity * sizeof(char*));
            if (!new_paths || !new_names) {
                break;  // Continue with what we have
            }
            binary_paths = new_paths;
            binary_names = new_names;
        }

        binary_paths[binary_count] = strdup(full_path);
        binary_names[binary_count] = strdup(entry->d_name);
        binary_count++;
    }
    closedir(dir);

    if (binary_count == 0) {
        free(binary_paths);
        free(binary_names);
        return 0;
    }

    fprintf(stderr, "[INFO] Application Scanner (parallel): Found %zu ELF binaries in %s\n",
            binary_count, target_path);

    // Phase 2: Create thread pool and submit work items
    int pool_threads = (thread_count > 0) ? thread_count : app_scanner_config.thread_count;
    if (pool_threads < 1) pool_threads = 4;
    if (pool_threads > 16) pool_threads = 16;  // Cap at 16 to avoid subprocess exhaustion

    thread_pool_t* pool = thread_pool_create((uint32_t)pool_threads, binary_count + 16);
    if (!pool) {
        fprintf(stderr, "[ERROR] Failed to create thread pool for application scanner\n");
        // Fallback: return without parallel processing
        for (size_t i = 0; i < binary_count; i++) {
            free(binary_paths[i]);
            free(binary_names[i]);
        }
        free(binary_paths);
        free(binary_names);
        return -1;
    }

    // Allocate work items
    binary_analysis_work_t* work_items = malloc(binary_count * sizeof(binary_analysis_work_t));
    atomic_int detected_count = ATOMIC_VAR_INIT(0);  // Proper atomic initialization

    if (!work_items) {
        thread_pool_destroy(pool);
        for (size_t i = 0; i < binary_count; i++) {
            free(binary_paths[i]);
            free(binary_names[i]);
        }
        free(binary_paths);
        free(binary_names);
        return -1;
    }

    // Submit work items
    for (size_t i = 0; i < binary_count; i++) {
        work_items[i] = (binary_analysis_work_t){
            .binary_path = binary_paths[i],  // Transfer ownership
            .binary_name = binary_names[i],  // Transfer ownership
            .store = asset_store,
            .dir_path = target_path,
            .detected_count = &detected_count,
            .result = 0
        };
        thread_pool_submit(pool, binary_analysis_worker, &work_items[i], NULL, WORK_PRIORITY_NORMAL);
    }

    // Wait for all work to complete
    thread_pool_wait_all(pool);

    // Cleanup
    int total_detected = atomic_load(&detected_count);

    // IMPORTANT: Destroy pool BEFORE freeing work_items to ensure all workers have exited
    // Workers may still be accessing work_items even after wait_all() returns
    thread_pool_destroy(pool);

    // Note: binary_path and binary_name are now freed by workers (ownership transferred)
    // Only free the arrays and work_items structure
    free(work_items);
    free(binary_paths);
    free(binary_names);

    // Final TUI progress update for this directory
    size_t final_analyzed = atomic_load(&g_parallel_binaries_analyzed);
    tui_log(TUI_MSG_SCANNER_PROGRESS, SCANNER_APPLICATION,
            "Application Scanner", final_analyzed, total_detected, NULL, target_path);

    fprintf(stderr, "[INFO] Application Scanner (parallel): %s complete - %d apps detected\n",
            target_path, total_detected);

    return total_detected;
}
