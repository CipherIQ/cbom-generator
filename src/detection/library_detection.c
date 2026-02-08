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

#include "detection/library_detection.h"
#include "crypto_registry.h"
#include "asset_store.h"
#include "cbom_types.h"
#include "service_scanner.h"  // for create_service_library_relationship
#include "application_scanner.h"  // for application_scanner_extract_libraries
#include "version_resolver.h"  // v1.7 - Cross-arch version detection

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <ctype.h>
#include <json-c/json.h>
#include <libgen.h>

#ifndef __EMSCRIPTEN__
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#endif

// Global CBOM configuration from main.c
extern cbom_config_t g_cbom_config;

// Internal structure for ldd parsing
typedef struct {
    char* soname;
    char* resolved_path;
} ldd_entry_t;

#ifdef __EMSCRIPTEN__
/* WASM: stub — no ELF binaries in browser environment */
static int is_elf_executable(const char* path) {
    (void)path;
    return 0;
}
#else
// Simple ELF check (matches existing pattern)
static int is_elf_executable(const char* path) {
    if (!path) return 0;

    if (access(path, X_OK) != 0) {
        return 0;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }

    if (!S_ISREG(st.st_mode)) {
        return 0;
    }

    FILE* f = fopen(path, "rb");
    if (!f) return 0;

    unsigned char magic[4];
    size_t read_bytes = fread(magic, 1, 4, f);
    fclose(f);

    if (read_bytes != 4) return 0;

    return (magic[0] == 0x7F && magic[1] == 'E' &&
            magic[2] == 'L' && magic[3] == 'F');
}
#endif /* __EMSCRIPTEN__ */

// Simple cache for path -> package resolution
typedef struct {
    char* path;
    char* pkg_name; // NULL means negative cache entry
} pkg_cache_entry_t;

static pkg_cache_entry_t* pkg_cache = NULL;
static size_t pkg_cache_count = 0;
static size_t pkg_cache_capacity = 0;
static bool pkg_cache_initialized = false;
static pthread_mutex_t pkg_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// SONAME Cache - Thread-safe cache for path→SONAME resolution (v1.8)
// ============================================================================

typedef struct {
    char* path;
    char* soname;
} soname_cache_entry_t;

static soname_cache_entry_t* soname_cache = NULL;
static size_t soname_cache_count = 0;
static size_t soname_cache_capacity = 0;
static bool soname_cache_initialized = false;
static pthread_mutex_t soname_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static void free_soname_cache(void) {
    if (!soname_cache_initialized) return;

    for (size_t i = 0; i < soname_cache_count; i++) {
        free(soname_cache[i].path);
        if (soname_cache[i].soname) free(soname_cache[i].soname);
    }
    free(soname_cache);
    soname_cache = NULL;
    soname_cache_count = 0;
    soname_cache_capacity = 0;
    soname_cache_initialized = false;
}

#ifdef __EMSCRIPTEN__
/* WASM: stub — no ELF parsing, return basename as fallback */
char* extract_soname_from_elf(const char* library_path) {
    if (!library_path) return NULL;
    char* path_copy = strdup(library_path);
    if (!path_copy) return NULL;
    char* base = basename(path_copy);
    char* result = strdup(base);
    free(path_copy);
    return result;
}
#else
/**
 * Extract SONAME from ELF binary using in-process parsing
 * This avoids spawning readelf for every library (performance improvement)
 *
 * @param library_path Path to the ELF shared library
 * @return Dynamically allocated SONAME string, or basename as fallback. Caller must free.
 */
char* extract_soname_from_elf(const char* library_path) {
    if (!library_path) return NULL;

    int fd = open(library_path, O_RDONLY);
    if (fd < 0) {
#ifdef DEBUG
        fprintf(stderr, "DEBUG: SONAME: cannot open %s\n", library_path);
#endif
        // Fallback: return basename
        char* path_copy = strdup(library_path);
        if (!path_copy) return NULL;
        char* base = basename(path_copy);
        char* result = strdup(base);
        free(path_copy);
        return result;
    }

    // Read ELF identifier
    unsigned char e_ident[EI_NIDENT];
    if (read(fd, e_ident, EI_NIDENT) != EI_NIDENT) {
        close(fd);
        char* path_copy = strdup(library_path);
        if (!path_copy) return NULL;
        char* base = basename(path_copy);
        char* result = strdup(base);
        free(path_copy);
        return result;
    }

    // Verify ELF magic
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        close(fd);
#ifdef DEBUG
        fprintf(stderr, "DEBUG: SONAME: %s is not an ELF file\n", library_path);
#endif
        char* path_copy = strdup(library_path);
        if (!path_copy) return NULL;
        char* base = basename(path_copy);
        char* result = strdup(base);
        free(path_copy);
        return result;
    }

    char* soname = NULL;
    int elf_class = e_ident[EI_CLASS];

    if (elf_class == ELFCLASS64) {
        // 64-bit ELF
        Elf64_Ehdr ehdr;
        lseek(fd, 0, SEEK_SET);
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
            close(fd);
            goto fallback;
        }

        // Find .dynamic section
        Elf64_Shdr* shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
        if (!shdrs) {
            close(fd);
            goto fallback;
        }

        lseek(fd, ehdr.e_shoff, SEEK_SET);
        if (read(fd, shdrs, ehdr.e_shnum * sizeof(Elf64_Shdr)) !=
            (ssize_t)(ehdr.e_shnum * sizeof(Elf64_Shdr))) {
            free(shdrs);
            close(fd);
            goto fallback;
        }

        // Find .dynamic and .dynstr sections
        Elf64_Shdr* dynamic_shdr = NULL;
        Elf64_Shdr* dynstr_shdr = NULL;

        for (int i = 0; i < ehdr.e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_DYNAMIC) {
                dynamic_shdr = &shdrs[i];
            }
            if (shdrs[i].sh_type == SHT_STRTAB && i != ehdr.e_shstrndx) {
                // First STRTAB that's not section header string table is usually .dynstr
                if (!dynstr_shdr) {
                    dynstr_shdr = &shdrs[i];
                }
            }
        }

        // Also try to find .dynstr by link from .dynamic
        if (dynamic_shdr && dynamic_shdr->sh_link < ehdr.e_shnum) {
            dynstr_shdr = &shdrs[dynamic_shdr->sh_link];
        }

        if (dynamic_shdr && dynstr_shdr) {
            // Read .dynstr
            char* dynstr = malloc(dynstr_shdr->sh_size);
            if (dynstr) {
                lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
                if (read(fd, dynstr, dynstr_shdr->sh_size) == (ssize_t)dynstr_shdr->sh_size) {
                    // Read .dynamic entries
                    size_t dyn_count = dynamic_shdr->sh_size / sizeof(Elf64_Dyn);
                    Elf64_Dyn* dyns = malloc(dynamic_shdr->sh_size);
                    if (dyns) {
                        lseek(fd, dynamic_shdr->sh_offset, SEEK_SET);
                        if (read(fd, dyns, dynamic_shdr->sh_size) == (ssize_t)dynamic_shdr->sh_size) {
                            for (size_t i = 0; i < dyn_count; i++) {
                                if (dyns[i].d_tag == DT_SONAME) {
                                    size_t str_offset = dyns[i].d_un.d_val;
                                    if (str_offset < dynstr_shdr->sh_size) {
                                        soname = strdup(dynstr + str_offset);
#ifdef DEBUG
                                        fprintf(stderr, "DEBUG: SONAME: extracted '%s' from %s\n",
                                                soname, library_path);
#endif
                                    }
                                    break;
                                }
                            }
                        }
                        free(dyns);
                    }
                }
                free(dynstr);
            }
        }

        free(shdrs);
    } else if (elf_class == ELFCLASS32) {
        // 32-bit ELF
        Elf32_Ehdr ehdr;
        lseek(fd, 0, SEEK_SET);
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
            close(fd);
            goto fallback;
        }

        Elf32_Shdr* shdrs = malloc(ehdr.e_shnum * sizeof(Elf32_Shdr));
        if (!shdrs) {
            close(fd);
            goto fallback;
        }

        lseek(fd, ehdr.e_shoff, SEEK_SET);
        if (read(fd, shdrs, ehdr.e_shnum * sizeof(Elf32_Shdr)) !=
            (ssize_t)(ehdr.e_shnum * sizeof(Elf32_Shdr))) {
            free(shdrs);
            close(fd);
            goto fallback;
        }

        Elf32_Shdr* dynamic_shdr = NULL;
        Elf32_Shdr* dynstr_shdr = NULL;

        for (int i = 0; i < ehdr.e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_DYNAMIC) {
                dynamic_shdr = &shdrs[i];
            }
            if (shdrs[i].sh_type == SHT_STRTAB && i != ehdr.e_shstrndx) {
                if (!dynstr_shdr) {
                    dynstr_shdr = &shdrs[i];
                }
            }
        }

        if (dynamic_shdr && dynamic_shdr->sh_link < ehdr.e_shnum) {
            dynstr_shdr = &shdrs[dynamic_shdr->sh_link];
        }

        if (dynamic_shdr && dynstr_shdr) {
            char* dynstr = malloc(dynstr_shdr->sh_size);
            if (dynstr) {
                lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
                if (read(fd, dynstr, dynstr_shdr->sh_size) == (ssize_t)dynstr_shdr->sh_size) {
                    size_t dyn_count = dynamic_shdr->sh_size / sizeof(Elf32_Dyn);
                    Elf32_Dyn* dyns = malloc(dynamic_shdr->sh_size);
                    if (dyns) {
                        lseek(fd, dynamic_shdr->sh_offset, SEEK_SET);
                        if (read(fd, dyns, dynamic_shdr->sh_size) == (ssize_t)dynamic_shdr->sh_size) {
                            for (size_t i = 0; i < dyn_count; i++) {
                                if (dyns[i].d_tag == DT_SONAME) {
                                    size_t str_offset = dyns[i].d_un.d_val;
                                    if (str_offset < dynstr_shdr->sh_size) {
                                        soname = strdup(dynstr + str_offset);
                                    }
                                    break;
                                }
                            }
                        }
                        free(dyns);
                    }
                }
                free(dynstr);
            }
        }

        free(shdrs);
    }

    close(fd);

    if (soname) {
        return soname;
    }

fallback:
#ifdef DEBUG
    fprintf(stderr, "DEBUG: SONAME: fallback to basename for %s\n", library_path);
#endif
    {
        char* path_copy = strdup(library_path);
        if (!path_copy) return NULL;
        char* base = basename(path_copy);
        char* result = strdup(base);
        free(path_copy);
        return result;
    }
}
#endif /* __EMSCRIPTEN__ */

/**
 * Get SONAME from cache or extract from ELF
 * Thread-safe cached wrapper around extract_soname_from_elf()
 *
 * @param library_path Path to the ELF shared library
 * @return Dynamically allocated SONAME string. Caller must free.
 */
char* get_soname_cached(const char* library_path) {
    if (!library_path) return NULL;

    pthread_mutex_lock(&soname_cache_mutex);

    // Initialize cache on first use
    if (!soname_cache_initialized) {
        soname_cache_initialized = true;
        atexit(free_soname_cache);
    }

    // Check cache
    for (size_t i = 0; i < soname_cache_count; i++) {
        if (strcmp(soname_cache[i].path, library_path) == 0) {
#ifdef DEBUG
            fprintf(stderr, "DEBUG: SONAME cache HIT: %s -> %s\n",
                    library_path, soname_cache[i].soname ? soname_cache[i].soname : "NULL");
#endif
            char* result = soname_cache[i].soname ? strdup(soname_cache[i].soname) : NULL;
            pthread_mutex_unlock(&soname_cache_mutex);
            return result;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "DEBUG: SONAME cache MISS: %s\n", library_path);
#endif

    // Unlock while extracting (I/O-bound operation)
    pthread_mutex_unlock(&soname_cache_mutex);
    char* soname = extract_soname_from_elf(library_path);
    pthread_mutex_lock(&soname_cache_mutex);

    // Re-check cache (another thread may have added it)
    for (size_t i = 0; i < soname_cache_count; i++) {
        if (strcmp(soname_cache[i].path, library_path) == 0) {
            char* result = soname_cache[i].soname ? strdup(soname_cache[i].soname) : NULL;
            if (soname) free(soname);
            pthread_mutex_unlock(&soname_cache_mutex);
            return result;
        }
    }

    // Grow cache if needed
    if (soname_cache_count == soname_cache_capacity) {
        size_t new_cap = soname_cache_capacity == 0 ? 64 : soname_cache_capacity * 2;
        soname_cache_entry_t* new_cache = realloc(soname_cache, new_cap * sizeof(soname_cache_entry_t));
        if (!new_cache) {
            pthread_mutex_unlock(&soname_cache_mutex);
            return soname;  // Return result even if not cached
        }
        soname_cache = new_cache;
        soname_cache_capacity = new_cap;
    }

    // Add to cache
    soname_cache[soname_cache_count].path = strdup(library_path);
    soname_cache[soname_cache_count].soname = soname ? strdup(soname) : NULL;
    soname_cache_count++;

    pthread_mutex_unlock(&soname_cache_mutex);
    return soname;
}

static void free_pkg_cache(void) {
    if (!pkg_cache_initialized) return;

    for (size_t i = 0; i < pkg_cache_count; i++) {
        free(pkg_cache[i].path);
        if (pkg_cache[i].pkg_name) free(pkg_cache[i].pkg_name);
    }
    free(pkg_cache);
    pkg_cache = NULL;
    pkg_cache_count = 0;
    pkg_cache_capacity = 0;
    pkg_cache_initialized = false;
}

#ifdef __EMSCRIPTEN__
/* WASM: stub — no package managers in browser environment */
static char* resolve_package_for_path_uncached(const char* path) {
    (void)path;
    return NULL;
}
#else
// Minimal package resolution via system tools (best-effort) - uncached
static char* resolve_package_for_path_uncached(const char* path) {
    if (!path) return NULL;

    char cmd[512];
    FILE* fp = NULL;
    char buffer[256];
    char* result = NULL;

    // Try dpkg -S
    snprintf(cmd, sizeof(cmd), "dpkg -S '%s' 2>/dev/null | head -1", path);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            char* colon = strchr(buffer, ':');
            if (colon) {
                *colon = '\0';
                result = strdup(buffer);
            }
        }
        pclose(fp);
    }
    if (result) return result;

    // Try rpm -qf
    snprintf(cmd, sizeof(cmd), "rpm -qf '%s' 2>/dev/null", path);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            if (strncmp(buffer, "file ", 5) != 0) { // rpm prints "file ... is not owned" on failure
                result = strdup(buffer);
            }
        }
        pclose(fp);
    }
    if (result) return result;

    // Try pacman -Qo
    snprintf(cmd, sizeof(cmd), "pacman -Qo '%s' 2>/dev/null | head -1", path);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            // Expect: "<path> is owned by pkg version"
            char pkg[128];
            if (sscanf(buffer, "%*s %*s %127s", pkg) == 1) {
                result = strdup(pkg);
            }
        }
        pclose(fp);
    }

    return result;
}
#endif /* __EMSCRIPTEN__ */

// Cached wrapper (thread-safe)
static char* cached_resolve_package_for_path(const char* path) {
    if (!path) return NULL;

    // Skip package resolution for cross-arch scanning (host package manager is wrong)
    if (g_cbom_config.cross_arch_mode || g_cbom_config.skip_package_resolution) {
        return NULL;
    }

    pthread_mutex_lock(&pkg_cache_mutex);

    if (!pkg_cache_initialized) {
        pkg_cache_initialized = true;
        atexit(free_pkg_cache);
    }

    // Check cache
    for (size_t i = 0; i < pkg_cache_count; i++) {
        if (strcmp(pkg_cache[i].path, path) == 0) {
#ifdef DEBUG
            fprintf(stderr, "DEBUG: pkg cache hit for %s (%s)\n", path,
                    pkg_cache[i].pkg_name ? pkg_cache[i].pkg_name : "none");
#endif
            char* result = pkg_cache[i].pkg_name ? strdup(pkg_cache[i].pkg_name) : NULL;
            pthread_mutex_unlock(&pkg_cache_mutex);
            return result;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "DEBUG: pkg cache miss for %s\n", path);
#endif

    // Unlock while calling external tool (slow operation)
    pthread_mutex_unlock(&pkg_cache_mutex);
    char* pkg = resolve_package_for_path_uncached(path);
    pthread_mutex_lock(&pkg_cache_mutex);

    // Re-check cache (another thread may have added it while we were unlocked)
    for (size_t i = 0; i < pkg_cache_count; i++) {
        if (strcmp(pkg_cache[i].path, path) == 0) {
            // Another thread added it - use that result
            char* result = pkg_cache[i].pkg_name ? strdup(pkg_cache[i].pkg_name) : NULL;
            if (pkg) free(pkg);  // Free our result
            pthread_mutex_unlock(&pkg_cache_mutex);
            return result;
        }
    }

    // Grow cache if needed
    if (pkg_cache_count == pkg_cache_capacity) {
        size_t new_cap = pkg_cache_capacity == 0 ? 32 : pkg_cache_capacity * 2;
        pkg_cache_entry_t* new_cache = realloc(pkg_cache, new_cap * sizeof(pkg_cache_entry_t));
        if (!new_cache) {
            pthread_mutex_unlock(&pkg_cache_mutex);
            return pkg; // Return result even if not cached
        }
        pkg_cache = new_cache;
        pkg_cache_capacity = new_cap;
    }

    pkg_cache[pkg_cache_count].path = strdup(path);
    pkg_cache[pkg_cache_count].pkg_name = pkg ? strdup(pkg) : NULL;
    pkg_cache_count++;

    pthread_mutex_unlock(&pkg_cache_mutex);
    return pkg;
}

#ifdef __EMSCRIPTEN__
/* WASM: stub — no ldd/readelf in browser environment */
static ldd_entry_t* collect_ldd_entries(const char* binary_path, size_t* out_count) {
    (void)binary_path;
    if (out_count) *out_count = 0;
    return NULL;
}

/* WASM: stub — no ELF binary analysis in browser */
binary_crypto_profile_t* analyze_binary_crypto(const char* binary_path) {
    (void)binary_path;
    return NULL;
}
#else
// Parse ldd output and collect libraries (soname + resolved path)
static ldd_entry_t* collect_ldd_entries(const char* binary_path, size_t* out_count) {
    if (out_count) *out_count = 0;
    if (!binary_path || !out_count) return NULL;

    // Use application_scanner_extract_libraries() which supports both readelf and ldd
    // readelf mode (default): Returns library names only (no paths)
    // ldd mode (--use-ldd flag): Returns library names with paths
    int lib_count = 0;
    char** libraries = application_scanner_extract_libraries(binary_path, &lib_count);

    if (!libraries || lib_count == 0) {
        if (libraries) {
            for (int i = 0; i < lib_count; i++) {
                free(libraries[i]);
            }
            free(libraries);
        }
        return NULL;
    }

    // Convert from simple string array to ldd_entry_t array
    ldd_entry_t* entries = calloc(lib_count, sizeof(ldd_entry_t));
    if (!entries) {
        for (int i = 0; i < lib_count; i++) {
            free(libraries[i]);
        }
        free(libraries);
        return NULL;
    }

    // Populate entries from library names
    // Note: readelf mode provides library names only (soname), no resolved paths
    // ldd mode (if enabled via --use-ldd) provides library names extracted from full output
    for (int i = 0; i < lib_count; i++) {
        entries[i].soname = libraries[i];  // Transfer ownership
        entries[i].resolved_path = NULL;   // No path info from readelf/simple ldd parsing
    }

    free(libraries);  // Free array itself, strings transferred to entries
    *out_count = lib_count;
    return entries;
}

binary_crypto_profile_t* analyze_binary_crypto(const char* binary_path) {
    if (!binary_path) return NULL;

    if (!is_elf_executable(binary_path)) {
        return NULL;
    }

    binary_crypto_profile_t* profile = calloc(1, sizeof(binary_crypto_profile_t));
    if (!profile) return NULL;

    profile->binary_path = strdup(binary_path);
    profile->binary_pkg_name = cached_resolve_package_for_path(binary_path);

    // Collect dynamic libraries via ldd
    size_t ldd_count = 0;
    ldd_entry_t* ldd_entries = collect_ldd_entries(binary_path, &ldd_count);

    if (ldd_entries && ldd_count > 0) {
        profile->libs = calloc(ldd_count, sizeof(detected_library_t));
        if (profile->libs) {
            profile->libs_count = ldd_count;

            for (size_t i = 0; i < ldd_count; i++) {
                profile->libs[i].soname = ldd_entries[i].soname;
                profile->libs[i].resolved_path = ldd_entries[i].resolved_path;
                profile->libs[i].pkg_name = cached_resolve_package_for_path(ldd_entries[i].resolved_path);

                const crypto_library_info_t* info = NULL;
                if (profile->libs[i].pkg_name) {
                    info = find_crypto_lib_by_pkg(profile->libs[i].pkg_name);
                }
                if (!info) {
                    info = find_crypto_lib_by_soname(profile->libs[i].soname);
                }

                if (info) {
                    profile->libs[i].is_crypto = 1;
                    profile->libs[i].crypto_lib_id = info->id;
                } else {
                    profile->libs[i].is_crypto = 0;
                    profile->libs[i].crypto_lib_id = NULL;
                }
            }
        } else {
            // If allocation fails, free earlier ldd_entries strings
            for (size_t i = 0; i < ldd_count; i++) {
                free(ldd_entries[i].soname);
                free(ldd_entries[i].resolved_path);
            }
        }
    }

    if (ldd_entries) {
        free(ldd_entries);
    }

    // Embedded crypto detection
    const char* base = strrchr(binary_path, '/');
    const char* binary_name = base ? base + 1 : binary_path;

    const embedded_crypto_app_info_t* embedded =
        find_embedded_crypto_by_binary(binary_name, profile->binary_pkg_name);

    if (embedded) {
        profile->embedded_providers = calloc(1, sizeof(embedded_crypto_provider_t));
        if (profile->embedded_providers) {
            profile->embedded_providers_count = 1;
            profile->embedded_providers[0].provider_id = embedded->provider_id;
            profile->embedded_providers[0].algorithms = embedded->algorithms;
        }
    }

    return profile;
}
#endif /* __EMSCRIPTEN__ */

void free_binary_crypto_profile(binary_crypto_profile_t* profile) {
    if (!profile) return;

    if (profile->binary_path) {
        free((char*)profile->binary_path);
    }
    if (profile->binary_pkg_name) {
        free((char*)profile->binary_pkg_name);
    }

    if (profile->libs) {
        for (size_t i = 0; i < profile->libs_count; i++) {
            if (profile->libs[i].soname) free((char*)profile->libs[i].soname);
            if (profile->libs[i].resolved_path) free((char*)profile->libs[i].resolved_path);
            if (profile->libs[i].pkg_name) free((char*)profile->libs[i].pkg_name);
        }
        free(profile->libs);
    }

    if (profile->embedded_providers) {
        free(profile->embedded_providers);
    }

    free(profile);
}

// Helper: find asset by name and type in store
static crypto_asset_t* find_asset_by_name_and_type(asset_store_t* store,
                                                   const char* name,
                                                   asset_type_t type) {
    if (!store || !name) return NULL;

    size_t count = 0;
    crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &count);
    if (!assets) return NULL;

    crypto_asset_t* found = NULL;
    for (size_t i = 0; i < count; i++) {
        if (assets[i] && assets[i]->type == type && assets[i]->name &&
            strcmp(assets[i]->name, name) == 0) {
            found = assets[i];
            break;
        }
    }

    free(assets);
    return found;
}

void register_embedded_providers_for_asset(asset_store_t* store,
                                           crypto_asset_t* owner_asset,
                                           const binary_crypto_profile_t* profile) {
    if (!store || !owner_asset || !profile ||
        profile->embedded_providers_count == 0 ||
        !profile->embedded_providers) {
        return;
    }

    for (size_t i = 0; i < profile->embedded_providers_count; i++) {
        const embedded_crypto_provider_t* provider = &profile->embedded_providers[i];
        if (!provider || !provider->provider_id) continue;

        // Find or create provider asset
        crypto_asset_t* provider_asset = find_asset_by_name_and_type(store,
                                                                     provider->provider_id,
                                                                     ASSET_TYPE_LIBRARY);
        if (!provider_asset) {
            provider_asset = crypto_asset_create(provider->provider_id, ASSET_TYPE_LIBRARY);
            if (!provider_asset) continue;

            provider_asset->location = strdup("embedded");

            // Populate cbom:lib: properties using helper function
            populate_library_metadata(provider_asset, NULL, provider);

            asset_store_add(store, provider_asset);

            // Create PROVIDES relationships for implemented algorithms
            // (Fixes bug where embedded providers didn't have algorithm relationships)
            if (provider->algorithms) {
                for (const char** alg = provider->algorithms; *alg != NULL; alg++) {
                    const char* algo_name = *alg;
                    if (!algo_name || strlen(algo_name) == 0) continue;

                    // Generate algorithm bom-ref (use algo: prefix for consistency)
                    // v1.9.2: Use get_or_create to prevent duplicate algorithms
                    crypto_asset_t* algo_asset = get_or_create_algorithm_asset(store, algo_name, 0);
                    if (algo_asset) {
                        // Create PROVIDES relationship from embedded provider to algorithm
                        relationship_t* provides_rel = relationship_create(
                            RELATIONSHIP_PROVIDES,
                            provider_asset->id,  // From: embedded provider library
                            algo_asset->id,      // To: algorithm (by asset ID)
                            0.90                 // High confidence for embedded providers
                        );

                        if (provides_rel) {
                            int res = asset_store_add_relationship(store, provides_rel);
                            if (res != 0) {
                                relationship_destroy(provides_rel);
                            }
                        }
                    }
                }
            }
        }

        // Create DEPENDS_ON relationship owner -> provider
        relationship_t* rel = relationship_create(RELATIONSHIP_DEPENDS_ON,
                                                  owner_asset->id,
                                                  provider_asset->id,
                                                  0.90f);
        if (rel) {
            int res = asset_store_add_relationship(store, rel);
            if (res != 0) {
                relationship_destroy(rel);
            }
        }
    }
}

// Helper: Extract version from SONAME (e.g., libkrb5.so.3 → "3", libssl.so.1.1 → "1.1")
static char* extract_version_from_soname(const char* soname) {
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

void populate_library_metadata(crypto_asset_t* lib_asset,
                               const detected_library_t* lib_info,
                               const embedded_crypto_provider_t* embedded_info) {
    if (!lib_asset) return;

    struct json_object* meta = json_object_new_object();
    if (!meta) return;

    if (embedded_info && embedded_info->provider_id) {
        // Embedded provider (openssh_internal, wireguard_internal, age_internal)
        json_object_object_add(meta, "name",
                              json_object_new_string(embedded_info->provider_id));
        json_object_object_add(meta, "embedded_provider",
                              json_object_new_string("true"));

        // Version: Use "embedded" as placeholder for embedded providers
        json_object_object_add(meta, "version",
                              json_object_new_string("embedded"));

        // Confidence: Embedded providers have high confidence (0.90)
        json_object_object_add(meta, "confidence",
                              json_object_new_double(0.90));

        // Add algorithms as array for metadata display
        // Note: PROVIDES relationships are created in register_embedded_providers_for_asset()
        if (embedded_info->algorithms) {
            json_object* algos_array = json_object_new_array();
            for (const char** alg = embedded_info->algorithms; *alg != NULL; alg++) {
                json_object_array_add(algos_array, json_object_new_string(*alg));
            }
            json_object_object_add(meta, "implemented_algorithms", algos_array);
        }
    } else if (lib_info && lib_info->is_crypto && lib_info->crypto_lib_id) {
        // ELF-detected crypto library (libkrb5.so.3, libgssapi_krb5.so.2, etc.)
        const crypto_library_info_t* info = NULL;

        // Try finding by package name first, then by SONAME
        if (lib_info->pkg_name) {
            info = find_crypto_lib_by_pkg(lib_info->pkg_name);
        }
        if (!info && lib_info->soname) {
            info = find_crypto_lib_by_soname(lib_info->soname);
        }

        if (info) {
            json_object_object_add(meta, "name",
                                  json_object_new_string(info->id));

            // Use tiered version resolver for accurate version detection
            resolved_version_t* resolved = version_resolver_resolve(
                lib_info->soname,
                lib_info->resolved_path,
                lib_info->pkg_name
            );

            if (resolved && resolved->version_string) {
                json_object_object_add(meta, "version",
                    json_object_new_string(resolved->version_string));

                // Add version resolution metadata for PQC assessment accuracy
                json_object_object_add(meta, "cbom:version:tier",
                    json_object_new_int(resolved->tier));
                json_object_object_add(meta, "cbom:version:confidence",
                    json_object_new_double(resolved->confidence));
                if (resolved->source_description) {
                    json_object_object_add(meta, "cbom:version:source",
                        json_object_new_string(resolved->source_description));
                }
                if (resolved->is_minimum_version) {
                    json_object_object_add(meta, "cbom:version:is_minimum",
                        json_object_new_boolean(true));
                }

                resolved_version_free(resolved);
            } else {
                // Fallback to SONAME parsing if resolver fails
                char* version = extract_version_from_soname(lib_info->soname);
                if (version) {
                    json_object_object_add(meta, "version", json_object_new_string(version));
                    free(version);
                } else {
                    json_object_object_add(meta, "version", json_object_new_string("unknown"));
                }
            }

            // Confidence: Differentiate based on detection quality
            float confidence = 0.90f;  // Base for ELF detection
            if (lib_info->pkg_name && lib_info->resolved_path) {
                confidence = 0.95f;  // Package + SONAME match = high confidence
            } else if (lib_info->pkg_name) {
                confidence = 0.90f;  // Package-only match
            } else {
                confidence = 0.85f;  // SONAME-only match
            }
            json_object_object_add(meta, "confidence",
                                  json_object_new_double(confidence));

            // Add algorithms as array (main.c will convert to individual cbom:lib:implements properties)
            if (info->algorithms) {
                json_object* algos_array = json_object_new_array();
                for (const char** alg = info->algorithms; *alg != NULL; alg++) {
                    json_object_array_add(algos_array, json_object_new_string(*alg));
                }
                json_object_object_add(meta, "implemented_algorithms", algos_array);
            }
        }
    }

    // Serialize metadata to JSON string
    const char* meta_str = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    if (meta_str) {
        lib_asset->metadata_json = strdup(meta_str);
    }
    json_object_put(meta);
}

void create_library_algorithm_relationships(asset_store_t *store,
                                            crypto_asset_t *lib_asset,
                                            const detected_library_t *lib_info) {
    if (!store || !lib_asset || !lib_info) return;
    if (!lib_info->is_crypto || !lib_info->crypto_lib_id) return;

    // Look up the crypto library info to get algorithms
    const crypto_library_info_t* info = NULL;

    // Try finding by package name first, then by SONAME
    if (lib_info->pkg_name) {
        info = find_crypto_lib_by_pkg(lib_info->pkg_name);
    }
    if (!info && lib_info->soname) {
        info = find_crypto_lib_by_soname(lib_info->soname);
    }

    if (!info || !info->algorithms) return;

    // Create PROVIDES relationships for each algorithm
    for (const char** alg = info->algorithms; *alg != NULL; alg++) {
        const char* algo_name = *alg;
        if (!algo_name || strlen(algo_name) == 0) continue;

        // v1.9.2: Use get_or_create to prevent duplicate algorithms
        crypto_asset_t* algo_asset = get_or_create_algorithm_asset(store, algo_name, 0);
        if (algo_asset) {
            // Create PROVIDES relationship from library to algorithm
            relationship_t* provides_rel = relationship_create(
                RELATIONSHIP_PROVIDES,
                lib_asset->id,     // From: system library
                algo_asset->id,    // To: algorithm (by asset ID)
                0.85               // Confidence for ELF-detected libraries
            );

            if (provides_rel) {
                int res = asset_store_add_relationship(store, provides_rel);
                if (res != 0) {
                    relationship_destroy(provides_rel);
                }
            }
        }
    }
}
