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
 * @file version_resolver.c
 * @brief Hybrid version detection for cross-architecture scanning
 *
 * Implements tiered version resolution:
 *   Tier 1: Yocto manifest lookup
 *   Tier 2: Package manager query (dpkg/rpm, native only)
 *   Tier 3: ELF VERNEED parsing
 *   Tier 4: SONAME parsing
 */

#define _GNU_SOURCE

#include "version_resolver.h"
#include "cbom_types.h"
#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

// Global CBOM configuration from main.c
extern cbom_config_t g_cbom_config;

// Manifest storage
static manifest_entry_t* g_manifest_entries = NULL;
static size_t g_manifest_count = 0;
static size_t g_manifest_capacity = 0;
static bool g_manifest_loaded = false;
static pthread_mutex_t g_manifest_mutex = PTHREAD_MUTEX_INITIALIZER;

// Resolver state
static bool g_resolver_initialized = false;
static bool g_cross_arch_mode = false;

// Statistics
static version_resolver_stats_t g_stats = {0};
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// Version symbol patterns for VERNEED parsing
typedef struct {
    const char* prefix;      // e.g., "OPENSSL_"
    const char* separator;   // Version separator in tag: "." or "_"
} version_pattern_t;

static const version_pattern_t VERSION_PATTERNS[] = {
    {"OPENSSL_", "."},       // OPENSSL_3.0.3 → 3.0.3
    {"GNUTLS_", "_"},        // GNUTLS_3_6_0 → 3.6.0
    {"GLIBC_", "."},         // GLIBC_2.34 → 2.34
    {"gssapi_krb5_", "_"},   // gssapi_krb5_2_MIT → 2
    {"LIBSELINUX_", "."},    // LIBSELINUX_1.0 → 1.0
    {"CURL_OPENSSL_", "."},  // CURL_OPENSSL_4 → 4
    {"NETTLE_", "_"},        // NETTLE_8 → 8
    {"HOGWEED_", "_"},       // HOGWEED_6 → 6
    {"GCC_", "."},           // GCC_3.0 → 3.0
    {NULL, NULL}
};

// Forward declarations for internal functions
static char* resolve_via_package_manager(const char* library_path, const char* pkg_name);
static char* extract_version_from_tag(const char* tag);

// ============================================================================
// Public API Implementation
// ============================================================================

int version_resolver_init(const char* yocto_manifest_path, bool cross_arch_mode) {
    if (g_resolver_initialized) {
        // Already initialized - update config
        g_cross_arch_mode = cross_arch_mode;
        if (yocto_manifest_path && !g_manifest_loaded) {
            return manifest_load(yocto_manifest_path);
        }
        return 0;
    }

    g_cross_arch_mode = cross_arch_mode;
    g_resolver_initialized = true;

    // Reset statistics
    version_resolver_reset_stats();

    // Load manifest if provided
    if (yocto_manifest_path) {
        return manifest_load(yocto_manifest_path);
    }

    return 0;
}

void version_resolver_cleanup(void) {
    manifest_unload();
    g_resolver_initialized = false;
    g_cross_arch_mode = false;
}

resolved_version_t* version_resolver_resolve(
    const char* soname,
    const char* library_path,
    const char* pkg_name)
{
    if (!soname) return NULL;

    resolved_version_t* result = NULL;

    // Tier 1: Yocto manifest (if loaded)
    if (g_manifest_loaded) {
        const manifest_entry_t* entry = manifest_lookup(soname, pkg_name);
        if (entry && entry->version) {
            result = secure_alloc(sizeof(resolved_version_t));
            if (result) {
                result->version_string = strdup(entry->version);
                result->tier = VERSION_TIER_MANIFEST;
                result->confidence = 0.99f;
                result->is_minimum_version = false;
                result->source_description = strdup("Yocto manifest");
                result->package_name = entry->package_name ? strdup(entry->package_name) : NULL;

                pthread_mutex_lock(&g_stats_mutex);
                g_stats.tier1_hits++;
                pthread_mutex_unlock(&g_stats_mutex);

                return result;
            }
        }
    }

    // Tier 2: Package manager (native mode only)
    // Check both cross_arch_mode and legacy skip_package_resolution flag
    bool skip_pkg_mgr = g_cross_arch_mode || g_cbom_config.cross_arch_mode ||
                        g_cbom_config.skip_package_resolution;

    if (!skip_pkg_mgr) {
        char* version = resolve_via_package_manager(library_path, pkg_name);
        if (version) {
            result = secure_alloc(sizeof(resolved_version_t));
            if (result) {
                result->version_string = version;
                result->tier = VERSION_TIER_PACKAGE_MGR;
                result->confidence = 0.95f;
                result->is_minimum_version = false;
                result->source_description = strdup("Package manager (dpkg/rpm)");
                result->package_name = pkg_name ? strdup(pkg_name) : NULL;

                pthread_mutex_lock(&g_stats_mutex);
                g_stats.tier2_hits++;
                pthread_mutex_unlock(&g_stats_mutex);

                return result;
            }
            free(version);
        }
    }

    // Tier 3: ELF VERNEED section
    if (library_path) {
        char* version = parse_verneed_version(library_path, soname);
        if (version) {
            result = secure_alloc(sizeof(resolved_version_t));
            if (result) {
                result->version_string = version;
                result->tier = VERSION_TIER_VERNEED;
                result->confidence = 0.80f;
                result->is_minimum_version = true;  // VERNEED gives minimum required
                result->source_description = strdup("ELF VERNEED section");
                result->package_name = pkg_name ? strdup(pkg_name) : NULL;

                pthread_mutex_lock(&g_stats_mutex);
                g_stats.tier3_hits++;
                pthread_mutex_unlock(&g_stats_mutex);

                return result;
            }
            free(version);
        }
    }

    // Tier 4: SONAME parsing (fallback)
    {
        char* version = parse_soname_version(soname);
        if (version) {
            result = secure_alloc(sizeof(resolved_version_t));
            if (result) {
                result->version_string = version;
                result->tier = VERSION_TIER_SONAME;
                result->confidence = 0.60f;
                result->is_minimum_version = false;
                result->source_description = strdup("SONAME parsing");
                result->package_name = pkg_name ? strdup(pkg_name) : NULL;

                pthread_mutex_lock(&g_stats_mutex);
                g_stats.tier4_hits++;
                pthread_mutex_unlock(&g_stats_mutex);

                return result;
            }
            free(version);
        }
    }

    // No version found
    pthread_mutex_lock(&g_stats_mutex);
    g_stats.resolution_failures++;
    pthread_mutex_unlock(&g_stats_mutex);

    return NULL;
}

void resolved_version_free(resolved_version_t* version) {
    if (!version) return;

    if (version->version_string) free(version->version_string);
    if (version->source_description) free(version->source_description);
    if (version->package_name) free(version->package_name);

    secure_free(version, sizeof(resolved_version_t));
}

const char* version_tier_to_string(version_tier_t tier) {
    switch (tier) {
        case VERSION_TIER_MANIFEST:    return "MANIFEST";
        case VERSION_TIER_PACKAGE_MGR: return "PACKAGE_MGR";
        case VERSION_TIER_VERNEED:     return "VERNEED";
        case VERSION_TIER_SONAME:      return "SONAME";
        default:                       return "UNKNOWN";
    }
}

version_resolver_stats_t version_resolver_get_stats(void) {
    pthread_mutex_lock(&g_stats_mutex);
    version_resolver_stats_t stats = g_stats;
    pthread_mutex_unlock(&g_stats_mutex);
    return stats;
}

void version_resolver_reset_stats(void) {
    pthread_mutex_lock(&g_stats_mutex);
    memset(&g_stats, 0, sizeof(g_stats));
    pthread_mutex_unlock(&g_stats_mutex);
}

// ============================================================================
// VERNEED Parser Implementation
// ============================================================================

#ifdef __EMSCRIPTEN__
/* WASM: readelf not available. VERNEED parsing requires in-process
 * ELF .gnu.version_r section reader (future enhancement). */
char* parse_verneed_version(const char* binary_path, const char* target_soname) {
    (void)binary_path; (void)target_soname;
    return NULL;
}
#else
char* parse_verneed_version(const char* binary_path, const char* target_soname) {
    if (!binary_path) return NULL;

    // Run readelf -V to get version info
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "readelf -V '%s' 2>/dev/null", binary_path);

    FILE* fp = popen(cmd, "r");
    if (!fp) return NULL;

    char line[512];
    char current_file[256] = {0};
    char best_version[128] = {0};
    int best_version_major = -1;
    int best_version_minor = -1;
    int best_version_patch = -1;

    // Parse output looking for version needs section
    while (fgets(line, sizeof(line), fp)) {
        // Look for "File: libssl.so.3" lines
        char* file_ptr = strstr(line, "File:");
        if (file_ptr) {
            // Extract filename
            if (sscanf(file_ptr, "File: %255s", current_file) == 1) {
                // Remove trailing whitespace/newlines
                char* end = current_file + strlen(current_file) - 1;
                while (end > current_file && isspace(*end)) {
                    *end-- = '\0';
                }
            }
            continue;
        }

        // Look for "Name: OPENSSL_3.0.0" lines
        char* name_ptr = strstr(line, "Name:");
        if (name_ptr && current_file[0] != '\0') {
            // Check if this is for our target library
            bool matches = false;
            if (target_soname) {
                // Check if current_file matches target SONAME
                matches = (strstr(current_file, target_soname) != NULL);
            } else {
                // No specific target - check any crypto library
                matches = (strstr(current_file, "ssl") != NULL ||
                          strstr(current_file, "crypto") != NULL ||
                          strstr(current_file, "gnutls") != NULL);
            }

            if (matches) {
                char version_tag[128];
                if (sscanf(name_ptr, "Name: %127s", version_tag) == 1) {
                    // Extract version from tag
                    char* version = extract_version_from_tag(version_tag);
                    if (version) {
                        // Parse version components for comparison
                        int major = 0, minor = 0, patch = 0;
                        sscanf(version, "%d.%d.%d", &major, &minor, &patch);

                        // Keep the highest version
                        if (major > best_version_major ||
                            (major == best_version_major && minor > best_version_minor) ||
                            (major == best_version_major && minor == best_version_minor && patch > best_version_patch)) {
                            strncpy(best_version, version, sizeof(best_version) - 1);
                            best_version[sizeof(best_version) - 1] = '\0';
                            best_version_major = major;
                            best_version_minor = minor;
                            best_version_patch = patch;
                        }
                        free(version);
                    }
                }
            }
        }
    }

    pclose(fp);

    if (best_version[0] != '\0') {
        return strdup(best_version);
    }

    return NULL;
}
#endif /* __EMSCRIPTEN__ */

/**
 * Extract semantic version from version tag (e.g., "OPENSSL_3.0.3" -> "3.0.3")
 */
static char* __attribute__((unused)) extract_version_from_tag(const char* tag) {
    if (!tag) return NULL;

    // Try each known pattern
    for (int i = 0; VERSION_PATTERNS[i].prefix != NULL; i++) {
        const char* prefix = VERSION_PATTERNS[i].prefix;
        size_t prefix_len = strlen(prefix);

        if (strncasecmp(tag, prefix, prefix_len) == 0) {
            const char* version_part = tag + prefix_len;

            // Skip if no version part
            if (*version_part == '\0') continue;

            // For underscore-separated versions (GNUTLS_3_6_0), convert to dots
            if (strcmp(VERSION_PATTERNS[i].separator, "_") == 0) {
                char* result = strdup(version_part);
                if (!result) return NULL;

                // Convert underscores to dots, stop at non-version chars
                for (char* p = result; *p; p++) {
                    if (*p == '_') {
                        *p = '.';
                    } else if (!isdigit(*p) && *p != '.') {
                        *p = '\0';  // Stop at non-version character
                        break;
                    }
                }

                // Trim trailing dots
                size_t len = strlen(result);
                while (len > 0 && result[len - 1] == '.') {
                    result[--len] = '\0';
                }

                if (len > 0) return result;
                free(result);
                continue;
            }

            // For dot-separated versions, just extract the version number
            char* result = strdup(version_part);
            if (!result) return NULL;

            // Trim at non-version characters
            for (char* p = result; *p; p++) {
                if (!isdigit(*p) && *p != '.') {
                    *p = '\0';
                    break;
                }
            }

            // Trim trailing dots
            size_t len = strlen(result);
            while (len > 0 && result[len - 1] == '.') {
                result[--len] = '\0';
            }

            if (len > 0) return result;
            free(result);
        }
    }

    // No known pattern matched - try generic number extraction
    // Look for digits after underscore or at end
    const char* p = tag;
    while (*p && !isdigit(*p)) p++;

    if (*p) {
        char* result = strdup(p);
        if (!result) return NULL;

        // Trim at non-version characters
        for (char* q = result; *q; q++) {
            if (!isdigit(*q) && *q != '.' && *q != '_') {
                *q = '\0';
                break;
            }
            if (*q == '_') *q = '.';
        }

        size_t len = strlen(result);
        while (len > 0 && result[len - 1] == '.') {
            result[--len] = '\0';
        }

        if (len > 0) return result;
        free(result);
    }

    return NULL;
}

// ============================================================================
// SONAME Parser Implementation
// ============================================================================

char* parse_soname_version(const char* soname) {
    if (!soname) return NULL;

    // Find the last .so occurrence
    const char* so_pos = strstr(soname, ".so");
    if (!so_pos) return NULL;

    // Check if there's a version after .so (e.g., .so.3 or .so.1.1)
    const char* version_start = so_pos + 3; // Skip ".so"
    if (*version_start == '.') {
        version_start++; // Skip the dot after .so
        if (*version_start >= '0' && *version_start <= '9') {
            return strdup(version_start);
        }
    }

    return NULL;
}

// ============================================================================
// Package Manager Resolution
// ============================================================================

#ifdef __EMSCRIPTEN__
/* WASM: no package managers available in browser environment. */
static char* resolve_via_package_manager(const char* library_path, const char* pkg_name) {
    (void)library_path; (void)pkg_name;
    return NULL;
}
#else
static char* resolve_via_package_manager(const char* library_path, const char* pkg_name) {
    if (!library_path && !pkg_name) return NULL;

    char cmd[512];
    FILE* fp = NULL;
    char buffer[256];
    char* result = NULL;

    // Try to get package version using dpkg --status
    const char* query_pkg = pkg_name;

    // If no package name, try to resolve from path
    if (!query_pkg && library_path) {
        // Quick dpkg -S to get package name
        snprintf(cmd, sizeof(cmd), "dpkg -S '%s' 2>/dev/null | head -1 | cut -d: -f1", library_path);
        fp = popen(cmd, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                buffer[strcspn(buffer, "\n")] = 0;
                if (buffer[0] != '\0') {
                    // Got package name, now get version
                    snprintf(cmd, sizeof(cmd), "dpkg-query -W -f='${Version}' '%s' 2>/dev/null", buffer);
                    pclose(fp);
                    fp = popen(cmd, "r");
                    if (fp && fgets(buffer, sizeof(buffer), fp)) {
                        buffer[strcspn(buffer, "\n")] = 0;
                        if (buffer[0] != '\0') {
                            result = strdup(buffer);
                        }
                    }
                }
            }
            if (fp) pclose(fp);
        }
        if (result) return result;
    }

    // Try dpkg-query for known package name
    if (query_pkg) {
        snprintf(cmd, sizeof(cmd), "dpkg-query -W -f='${Version}' '%s' 2>/dev/null", query_pkg);
        fp = popen(cmd, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                buffer[strcspn(buffer, "\n")] = 0;
                if (buffer[0] != '\0') {
                    result = strdup(buffer);
                }
            }
            pclose(fp);
        }
        if (result) return result;
    }

    // Try rpm -q
    if (query_pkg) {
        snprintf(cmd, sizeof(cmd), "rpm -q --queryformat '%%{VERSION}' '%s' 2>/dev/null", query_pkg);
        fp = popen(cmd, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                buffer[strcspn(buffer, "\n")] = 0;
                if (buffer[0] != '\0' && strncmp(buffer, "package", 7) != 0) {
                    result = strdup(buffer);
                }
            }
            pclose(fp);
        }
    }

    return result;
}
#endif /* __EMSCRIPTEN__ */

// ============================================================================
// Yocto Manifest Implementation
// ============================================================================

int manifest_load(const char* manifest_path) {
    if (!manifest_path) return -1;

    pthread_mutex_lock(&g_manifest_mutex);

    // Unload existing manifest if any
    if (g_manifest_loaded) {
        for (size_t i = 0; i < g_manifest_count; i++) {
            free(g_manifest_entries[i].package_name);
            free(g_manifest_entries[i].version);
            free(g_manifest_entries[i].architecture);
        }
        free(g_manifest_entries);
        g_manifest_entries = NULL;
        g_manifest_count = 0;
        g_manifest_capacity = 0;
        g_manifest_loaded = false;
    }

    FILE* fp = fopen(manifest_path, "r");
    if (!fp) {
        pthread_mutex_unlock(&g_manifest_mutex);
        fprintf(stderr, "[version_resolver] Failed to open manifest: %s\n", manifest_path);
        return -1;
    }

    char line[1024];
    int line_num __attribute__((unused)) = 0;
    int entries_loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        // Skip empty lines and comments
        char* trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        if (*trimmed == '\0' || *trimmed == '#') continue;

        // Parse: PACKAGE_NAME ARCH VERSION
        // Example: "libssl3 aarch64 3.0.13-r0"
        char pkg_name[256], arch[64], version[256];

        if (sscanf(trimmed, "%255s %63s %255s", pkg_name, arch, version) == 3) {
            // Grow array if needed
            if (g_manifest_count >= g_manifest_capacity) {
                size_t new_cap = g_manifest_capacity == 0 ? 256 : g_manifest_capacity * 2;
                manifest_entry_t* new_entries = realloc(g_manifest_entries,
                                                        new_cap * sizeof(manifest_entry_t));
                if (!new_entries) {
                    fclose(fp);
                    pthread_mutex_unlock(&g_manifest_mutex);
                    fprintf(stderr, "[version_resolver] Memory allocation failed\n");
                    return -1;
                }
                g_manifest_entries = new_entries;
                g_manifest_capacity = new_cap;
            }

            // Add entry
            g_manifest_entries[g_manifest_count].package_name = strdup(pkg_name);
            g_manifest_entries[g_manifest_count].version = strdup(version);
            g_manifest_entries[g_manifest_count].architecture = strdup(arch);
            g_manifest_count++;
            entries_loaded++;
        }
    }

    fclose(fp);
    g_manifest_loaded = true;

    fprintf(stderr, "[version_resolver] Loaded %d entries from manifest: %s\n",
            entries_loaded, manifest_path);

    pthread_mutex_unlock(&g_manifest_mutex);
    return 0;
}

const manifest_entry_t* manifest_lookup(const char* soname, const char* pkg_name) {
    if (!g_manifest_loaded) return NULL;

    pthread_mutex_lock(&g_manifest_mutex);

    // Strategy 1: Direct package name match
    if (pkg_name) {
        for (size_t i = 0; i < g_manifest_count; i++) {
            if (strcasecmp(g_manifest_entries[i].package_name, pkg_name) == 0) {
                pthread_mutex_unlock(&g_manifest_mutex);
                return &g_manifest_entries[i];
            }
        }
    }

    // Strategy 2: Map SONAME to common package name patterns
    // libssl.so.3 -> try "libssl3", "libssl", "openssl"
    if (soname) {
        // Extract base name from SONAME (e.g., "libssl" from "libssl.so.3")
        char base_name[128] = {0};
        const char* so_pos = strstr(soname, ".so");
        if (so_pos) {
            size_t base_len = so_pos - soname;
            if (base_len > 0 && base_len < sizeof(base_name)) {
                strncpy(base_name, soname, base_len);
                base_name[base_len] = '\0';
            }
        }

        // Extract version number from SONAME (e.g., "3" from "libssl.so.3")
        char version_suffix[16] = {0};
        if (so_pos) {
            const char* ver_start = so_pos + 3;
            if (*ver_start == '.') {
                ver_start++;
                // Get first version component only
                int i = 0;
                while (ver_start[i] && isdigit(ver_start[i]) && i < 15) {
                    version_suffix[i] = ver_start[i];
                    i++;
                }
            }
        }

        // Try different package name patterns
        const char* patterns[] = {
            NULL,  // Will be set to base_name + version_suffix (e.g., "libssl3")
            NULL,  // Will be set to base_name (e.g., "libssl")
            NULL   // Sentinel
        };

        char pattern1[144];
        if (base_name[0] && version_suffix[0]) {
            snprintf(pattern1, sizeof(pattern1), "%s%s", base_name, version_suffix);
            patterns[0] = pattern1;
        }
        patterns[1] = base_name[0] ? base_name : NULL;

        for (int p = 0; patterns[p] != NULL; p++) {
            for (size_t i = 0; i < g_manifest_count; i++) {
                if (strcasecmp(g_manifest_entries[i].package_name, patterns[p]) == 0) {
                    pthread_mutex_unlock(&g_manifest_mutex);
                    return &g_manifest_entries[i];
                }
            }
        }

        // Strategy 3: Substring match (e.g., "ssl" matches "openssl", "libssl3")
        if (base_name[0]) {
            // Remove "lib" prefix for matching
            const char* match_name = base_name;
            if (strncmp(match_name, "lib", 3) == 0) {
                match_name += 3;
            }

            for (size_t i = 0; i < g_manifest_count; i++) {
                if (strcasestr(g_manifest_entries[i].package_name, match_name) != NULL) {
                    pthread_mutex_unlock(&g_manifest_mutex);
                    return &g_manifest_entries[i];
                }
            }
        }
    }

    pthread_mutex_unlock(&g_manifest_mutex);
    return NULL;
}

void manifest_unload(void) {
    pthread_mutex_lock(&g_manifest_mutex);

    if (g_manifest_entries) {
        for (size_t i = 0; i < g_manifest_count; i++) {
            free(g_manifest_entries[i].package_name);
            free(g_manifest_entries[i].version);
            free(g_manifest_entries[i].architecture);
        }
        free(g_manifest_entries);
        g_manifest_entries = NULL;
    }
    g_manifest_count = 0;
    g_manifest_capacity = 0;
    g_manifest_loaded = false;

    pthread_mutex_unlock(&g_manifest_mutex);
}

bool manifest_is_loaded(void) {
    return g_manifest_loaded;
}
