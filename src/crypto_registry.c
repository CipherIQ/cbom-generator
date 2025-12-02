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

#include "crypto_registry.h"
#include "yaml_parser.h"
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

// OpenSSL
static const char* OPENSSL_PKG_PATTERNS[] = {
    "libssl", "libssl3", "libcrypto3", "libssl-dev", NULL
};
static const char* OPENSSL_SONAME_PATTERNS[] = {
    "libssl.so", "libcrypto.so", NULL
};
static const char* OPENSSL_ALGORITHMS[] = {
    // Note: SHA-1 omitted as it's disabled by default in OpenSSL 3.0+
    // Libraries implementing deprecated algorithms are assessed based on actual usage
    "RSA", "ECDSA", "AES", "ChaCha20-Poly1305",
    "SHA-256", "SHA-384", "X25519", "P-256", "P-384", NULL
};

// libgcrypt
static const char* LIBGCRYPT_PKG_PATTERNS[] = {
    "libgcrypt", "libgcrypt20", "libgcrypt20-dev", NULL
};
static const char* LIBGCRYPT_SONAME_PATTERNS[] = {
    "libgcrypt.so", NULL
};
static const char* LIBGCRYPT_ALGORITHMS[] = {
    "RSA", "DSA", "ECDSA", "AES", "Twofish", "SHA-1", "SHA-256", NULL
};

// libsodium
static const char* LIBSODIUM_PKG_PATTERNS[] = {
    "libsodium", "libsodium-dev", NULL
};
static const char* LIBSODIUM_SONAME_PATTERNS[] = {
    "libsodium.so", NULL
};
static const char* LIBSODIUM_ALGORITHMS[] = {
    "X25519", "Ed25519", "ChaCha20-Poly1305", "BLAKE2b", NULL
};

// nettle / hogweed
static const char* NETTLE_PKG_PATTERNS[] = {
    "libnettle", "libhogweed", NULL
};
static const char* NETTLE_SONAME_PATTERNS[] = {
    "libnettle.so", "libhogweed.so", NULL
};
static const char* NETTLE_ALGORITHMS[] = {
    "RSA", "ECDSA", "AES", "ChaCha20", "SHA-256", NULL
};

// Kerberos / GSSAPI
static const char* KRB5_PKG_PATTERNS[] = {
    "libkrb5", "libgssapi-krb5", "libk5crypto", "krb5-kdc", NULL
};
static const char* KRB5_SONAME_PATTERNS[] = {
    "libgssapi_krb5.so", "libkrb5.so", "libk5crypto.so", NULL
};
static const char* KRB5_ALGORITHMS[] = {
    "AES", "3DES", "RC4", "HMAC-SHA1", "HMAC-SHA256", NULL
};

// v1.8.6: libcrypt (password hashing - crypt(), bcrypt, yescrypt, etc.)
static const char* LIBCRYPT_PKG_PATTERNS[] = {
    "libcrypt", "libcrypt1", "libxcrypt", NULL
};
static const char* LIBCRYPT_SONAME_PATTERNS[] = {
    "libcrypt.so", NULL
};
static const char* LIBCRYPT_ALGORITHMS[] = {
    "crypt", "bcrypt", "yescrypt", "sha512crypt", "sha256crypt", "md5crypt", "des-crypt", NULL
};

// v1.9.2: liboqs - Open Quantum Safe (PQC library)
static const char* LIBOQS_PKG_PATTERNS[] = {
    "liboqs", "liboqs-dev", NULL
};
static const char* LIBOQS_SONAME_PATTERNS[] = {
    "liboqs.so", NULL
};
static const char* LIBOQS_ALGORITHMS[] = {
    // NIST finalized KEMs
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    // NIST finalized signatures
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    // Other PQC algorithms
    "Falcon-512", "Falcon-1024",
    "SPHINCS+-SHA2-128f", "SPHINCS+-SHA2-192f", "SPHINCS+-SHA2-256f",
    "BIKE-L1", "BIKE-L3", "BIKE-L5",
    "HQC-128", "HQC-192", "HQC-256",
    "Classic-McEliece-348864",
    NULL
};

static const crypto_library_info_t CRYPTO_LIBRARIES[] = {
    {.id = "openssl", .pkg_patterns = OPENSSL_PKG_PATTERNS, .soname_patterns = OPENSSL_SONAME_PATTERNS, .algorithms = OPENSSL_ALGORITHMS},
    {.id = "libgcrypt", .pkg_patterns = LIBGCRYPT_PKG_PATTERNS, .soname_patterns = LIBGCRYPT_SONAME_PATTERNS, .algorithms = LIBGCRYPT_ALGORITHMS},
    {.id = "libsodium", .pkg_patterns = LIBSODIUM_PKG_PATTERNS, .soname_patterns = LIBSODIUM_SONAME_PATTERNS, .algorithms = LIBSODIUM_ALGORITHMS},
    {.id = "nettle", .pkg_patterns = NETTLE_PKG_PATTERNS, .soname_patterns = NETTLE_SONAME_PATTERNS, .algorithms = NETTLE_ALGORITHMS},
    {.id = "krb5", .pkg_patterns = KRB5_PKG_PATTERNS, .soname_patterns = KRB5_SONAME_PATTERNS, .algorithms = KRB5_ALGORITHMS},
    {.id = "libcrypt", .pkg_patterns = LIBCRYPT_PKG_PATTERNS, .soname_patterns = LIBCRYPT_SONAME_PATTERNS, .algorithms = LIBCRYPT_ALGORITHMS},
    {.id = "liboqs", .pkg_patterns = LIBOQS_PKG_PATTERNS, .soname_patterns = LIBOQS_SONAME_PATTERNS, .algorithms = LIBOQS_ALGORITHMS},
    {NULL, NULL, NULL, NULL}
};

// OpenSSH embedded crypto
static const char* OPENSSH_BINARIES[] = {
    "ssh", "sshd", "ssh-keygen", NULL
};
static const char* OPENSSH_PACKAGES[] = {
    "openssh-server", "openssh-client", NULL
};
static const char* OPENSSH_ALGORITHMS[] = {
    "chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr",
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ssh-ed25519", "sntrup761x25519-sha512@openssh.com", NULL
};

// wireguard-go embedded crypto
static const char* WG_BINARIES[] = {
    "wireguard-go", NULL
};
static const char* WG_ALGORITHMS[] = {
    "ChaCha20", "Poly1305", "BLAKE2s", "Curve25519", NULL
};

// age embedded crypto
static const char* AGE_BINARIES[] = {
    "age", NULL
};
static const char* AGE_ALGORITHMS[] = {
    "X25519", "ChaCha20-Poly1305", "HMAC-SHA256", NULL
};

static const embedded_crypto_app_info_t EMBEDDED_APPS[] = {
    {.provider_id = "openssh_internal", .binary_names = OPENSSH_BINARIES, .package_names = OPENSSH_PACKAGES, .algorithms = OPENSSH_ALGORITHMS},
    {.provider_id = "wireguard_internal", .binary_names = WG_BINARIES, .package_names = NULL, .algorithms = WG_ALGORITHMS},
    {.provider_id = "age_internal", .binary_names = AGE_BINARIES, .package_names = NULL, .algorithms = AGE_ALGORITHMS},
    {NULL, NULL, NULL, NULL}
};

// ============================================================================
// Dynamic registry storage (loaded from YAML)
// ============================================================================
// IMPORTANT: crypto_registry_load_from_file() is called ONCE at startup,
//            before any threads are created. No mid-process reload support.
// ============================================================================

// Soft limits for security (prevent YAML bombs)
#define MAX_DYNAMIC_LIBRARIES 100
#define MAX_DYNAMIC_APPS 50

// Dynamic crypto libraries (allocated from YAML)
static crypto_library_info_t *dynamic_crypto_libraries = NULL;
static size_t dynamic_crypto_libraries_count = 0;
static size_t dynamic_crypto_libraries_capacity = 0;

// Dynamic embedded apps (allocated from YAML)
static embedded_crypto_app_info_t *dynamic_embedded_apps = NULL;
static size_t dynamic_embedded_apps_count = 0;
static size_t dynamic_embedded_apps_capacity = 0;

// Flag indicating if dynamic registry was loaded
static bool dynamic_registry_loaded = false;

// ============================================================================
// YAML Loader Helper Functions
// ============================================================================

// Helper: Parse YAML sequence into NULL-terminated string array
static const char** parse_string_array_from_yaml(yaml_doc_t* doc, yaml_node_t* node) {
    if (!node || !yaml_is_sequence(node)) {
        return NULL;
    }

    // Get array items
    int count = 0;
    yaml_node_t** items = yaml_get_array(doc, node, &count);
    if (!items || count == 0) {
        // Empty array - allocate just NULL terminator
        const char** arr = malloc(sizeof(char*));
        if (arr) {
            arr[0] = NULL;
        }
        free(items);
        return arr;
    }

    // Allocate array (+1 for NULL terminator)
    const char** arr = malloc(sizeof(char*) * (count + 1));
    if (!arr) {
        free(items);
        return NULL;
    }

    // Extract string values
    for (int i = 0; i < count; i++) {
        const char* str = yaml_get_string(doc, items[i]);
        if (str) {
            arr[i] = strdup(str);
        } else {
            arr[i] = NULL;
        }
    }
    arr[count] = NULL;

    free(items);
    return arr;
}

// Load crypto registry from YAML file
// Returns: 0 on success, -1 on error
// If errbuf != NULL, writes error message on failure
int crypto_registry_load_from_file(const char *path, char *errbuf, size_t errbuf_len) {
    // NULL path = no-op (not an error)
    if (path == NULL) {
        return 0;
    }

    // Load YAML file using wrapper (enforces 1MB/32-depth limits)
    yaml_doc_t* doc = yaml_load_file(path);
    if (!doc || !doc->is_valid) {
        if (errbuf) {
            const char* err = yaml_get_error(doc);
            snprintf(errbuf, errbuf_len, "Failed to parse YAML: %s",
                     err ? err : "unknown error");
        }
        if (doc) {
            yaml_free(doc);
        }
        return -1;
    }

    // Get root node
    yaml_node_t* root = yaml_get_node(doc, "");
    if (!root || !yaml_is_mapping(root)) {
        if (errbuf) {
            snprintf(errbuf, errbuf_len, "Root node must be a YAML mapping");
        }
        yaml_free(doc);
        return -1;
    }

    // Parse version field
    yaml_node_t* version_node = yaml_get_mapping_value(doc, root, "version");
    int version = 0;
    if (version_node) {
        yaml_get_int(doc, version_node, &version);
    }

    if (version != 1) {
        if (errbuf) {
            snprintf(errbuf, errbuf_len, "Unsupported schema version: %d (expected 1)", version);
        }
        yaml_free(doc);
        return -1;
    }

    // Parse crypto_libraries section
    yaml_node_t* libs_node = yaml_get_mapping_value(doc, root, "crypto_libraries");
    if (libs_node && yaml_is_sequence(libs_node)) {
        int lib_count = 0;
        yaml_node_t** lib_items = yaml_get_array(doc, libs_node, &lib_count);

        // Enforce soft limit (security)
        if (lib_count > MAX_DYNAMIC_LIBRARIES) {
            if (errbuf) {
                snprintf(errbuf, errbuf_len,
                         "Too many crypto libraries in YAML: %d (max: %d)",
                         lib_count, MAX_DYNAMIC_LIBRARIES);
            }
            free(lib_items);
            yaml_free(doc);
            return -1;
        }

        if (lib_count > 0) {
            // Allocate dynamic array
            dynamic_crypto_libraries = malloc(sizeof(crypto_library_info_t) * lib_count);
            if (!dynamic_crypto_libraries) {
                if (errbuf) snprintf(errbuf, errbuf_len, "Memory allocation failed");
                free(lib_items);
                yaml_free(doc);
                return -1;
            }
            dynamic_crypto_libraries_capacity = lib_count;

            // Parse each library
            for (int i = 0; i < lib_count; i++) {
                yaml_node_t* lib_node = lib_items[i];
                if (!lib_node || !yaml_is_mapping(lib_node)) continue;

                crypto_library_info_t *lib = &dynamic_crypto_libraries[dynamic_crypto_libraries_count];
                memset(lib, 0, sizeof(crypto_library_info_t));

                // Parse id
                yaml_node_t* id_node = yaml_get_mapping_value(doc, lib_node, "id");
                if (id_node) {
                    const char* id_str = yaml_get_string(doc, id_node);
                    if (id_str) {
                        lib->id = strdup(id_str);
                    }
                }

                // Parse pkg_patterns
                yaml_node_t* pkg_node = yaml_get_mapping_value(doc, lib_node, "pkg_patterns");
                if (pkg_node) {
                    lib->pkg_patterns = parse_string_array_from_yaml(doc, pkg_node);
                }

                // Parse soname_patterns
                yaml_node_t* soname_node = yaml_get_mapping_value(doc, lib_node, "soname_patterns");
                if (soname_node) {
                    lib->soname_patterns = parse_string_array_from_yaml(doc, soname_node);
                }

                // Parse algorithms
                yaml_node_t* algo_node = yaml_get_mapping_value(doc, lib_node, "algorithms");
                if (algo_node) {
                    lib->algorithms = parse_string_array_from_yaml(doc, algo_node);
                }

                dynamic_crypto_libraries_count++;
            }
        }

        free(lib_items);
    }

    // Parse embedded_crypto_apps section
    yaml_node_t* apps_node = yaml_get_mapping_value(doc, root, "embedded_crypto_apps");
    if (apps_node && yaml_is_sequence(apps_node)) {
        int app_count = 0;
        yaml_node_t** app_items = yaml_get_array(doc, apps_node, &app_count);

        // Enforce soft limit (security)
        if (app_count > MAX_DYNAMIC_APPS) {
            if (errbuf) {
                snprintf(errbuf, errbuf_len,
                         "Too many embedded apps in YAML: %d (max: %d)",
                         app_count, MAX_DYNAMIC_APPS);
            }
            free(app_items);
            yaml_free(doc);
            return -1;
        }

        if (app_count > 0) {
            // Allocate dynamic array
            dynamic_embedded_apps = malloc(sizeof(embedded_crypto_app_info_t) * app_count);
            if (!dynamic_embedded_apps) {
                if (errbuf) snprintf(errbuf, errbuf_len, "Memory allocation failed");
                free(app_items);
                yaml_free(doc);
                return -1;
            }
            dynamic_embedded_apps_capacity = app_count;

            // Parse each app
            for (int i = 0; i < app_count; i++) {
                yaml_node_t* app_node = app_items[i];
                if (!app_node || !yaml_is_mapping(app_node)) continue;

                embedded_crypto_app_info_t *app = &dynamic_embedded_apps[dynamic_embedded_apps_count];
                memset(app, 0, sizeof(embedded_crypto_app_info_t));

                // Parse provider_id
                yaml_node_t* id_node = yaml_get_mapping_value(doc, app_node, "provider_id");
                if (id_node) {
                    const char* id_str = yaml_get_string(doc, id_node);
                    if (id_str) {
                        app->provider_id = strdup(id_str);
                    }
                }

                // Parse binary_names
                yaml_node_t* bin_node = yaml_get_mapping_value(doc, app_node, "binary_names");
                if (bin_node) {
                    app->binary_names = parse_string_array_from_yaml(doc, bin_node);
                }

                // Parse package_names
                yaml_node_t* pkg_node = yaml_get_mapping_value(doc, app_node, "package_names");
                if (pkg_node) {
                    app->package_names = parse_string_array_from_yaml(doc, pkg_node);
                }

                // Parse algorithms
                yaml_node_t* algo_node = yaml_get_mapping_value(doc, app_node, "algorithms");
                if (algo_node) {
                    app->algorithms = parse_string_array_from_yaml(doc, algo_node);
                }

                dynamic_embedded_apps_count++;
            }
        }

        free(app_items);
    }

    // Cleanup
    yaml_free(doc);

    dynamic_registry_loaded = true;
    return 0;
}

// ============================================================================
// Pattern Matching and Lookup Functions
// ============================================================================

/**
 * Substring pattern match - used for SONAME and package patterns.
 * E.g., "libcrypto.so.3" matches pattern "libcrypto.so"
 * E.g., "libssl3" matches pattern "libssl"
 */
static bool match_pattern(const char* value, const char* pattern) {
    if (!value || !pattern) {
        return false;
    }
    return strstr(value, pattern) != NULL;
}

/**
 * v1.8.6: Exact pattern match - used for binary and package names in embedded apps.
 * Prevents false positives like "apache2-utils" matching "apache2" pattern.
 * Binary names like "ssh", "sshd" require exact matches.
 */
static bool match_pattern_exact(const char* value, const char* pattern) {
    if (!value || !pattern) {
        return false;
    }
    return strcmp(value, pattern) == 0;
}

const crypto_library_info_t* find_crypto_lib_by_soname(const char* soname) {
    if (!soname) {
        return NULL;
    }

    // Search built-in registry first
    for (size_t i = 0; CRYPTO_LIBRARIES[i].id != NULL; i++) {
        const char* const* patterns = CRYPTO_LIBRARIES[i].soname_patterns;
        if (!patterns) continue;

        for (size_t j = 0; patterns[j] != NULL; j++) {
            if (match_pattern(soname, patterns[j])) {
                return &CRYPTO_LIBRARIES[i];
            }
        }
    }

    // Search dynamic registry if loaded
    if (dynamic_registry_loaded && dynamic_crypto_libraries) {
        for (size_t i = 0; i < dynamic_crypto_libraries_count; i++) {
            const char* const* patterns = dynamic_crypto_libraries[i].soname_patterns;
            if (!patterns) continue;

            for (size_t j = 0; patterns[j] != NULL; j++) {
                if (match_pattern(soname, patterns[j])) {
                    return &dynamic_crypto_libraries[i];
                }
            }
        }
    }

    return NULL;
}

const crypto_library_info_t* find_crypto_lib_by_pkg(const char* pkg_name) {
    if (!pkg_name) {
        return NULL;
    }

    // Search built-in registry first
    for (size_t i = 0; CRYPTO_LIBRARIES[i].id != NULL; i++) {
        const char* const* patterns = CRYPTO_LIBRARIES[i].pkg_patterns;
        if (!patterns) continue;

        for (size_t j = 0; patterns[j] != NULL; j++) {
            if (match_pattern(pkg_name, patterns[j])) {
                return &CRYPTO_LIBRARIES[i];
            }
        }
    }

    // Search dynamic registry if loaded
    if (dynamic_registry_loaded && dynamic_crypto_libraries) {
        for (size_t i = 0; i < dynamic_crypto_libraries_count; i++) {
            const char* const* patterns = dynamic_crypto_libraries[i].pkg_patterns;
            if (!patterns) continue;

            for (size_t j = 0; patterns[j] != NULL; j++) {
                if (match_pattern(pkg_name, patterns[j])) {
                    return &dynamic_crypto_libraries[i];
                }
            }
        }
    }

    return NULL;
}

const embedded_crypto_app_info_t* find_embedded_crypto_by_binary(
    const char* binary_name,
    const char* pkg_name
) {
    if (!binary_name && !pkg_name) {
        return NULL;
    }

    // Search built-in registry first
    for (size_t i = 0; EMBEDDED_APPS[i].provider_id != NULL; i++) {
        const embedded_crypto_app_info_t* info = &EMBEDDED_APPS[i];

        // v1.8.6: Use exact matching for binary names to prevent false positives
        if (binary_name && info->binary_names) {
            for (size_t j = 0; info->binary_names[j] != NULL; j++) {
                if (match_pattern_exact(binary_name, info->binary_names[j])) {
                    return info;
                }
            }
        }

        // v1.8.6: Use exact matching for package names to prevent false positives
        if (pkg_name && info->package_names) {
            for (size_t j = 0; info->package_names[j] != NULL; j++) {
                if (match_pattern_exact(pkg_name, info->package_names[j])) {
                    return info;
                }
            }
        }
    }

    // Search dynamic registry if loaded
    if (dynamic_registry_loaded && dynamic_embedded_apps) {
        for (size_t i = 0; i < dynamic_embedded_apps_count; i++) {
            const embedded_crypto_app_info_t* info = &dynamic_embedded_apps[i];

            // v1.8.6: Use exact matching for binary names to prevent false positives
            if (binary_name && info->binary_names) {
                for (size_t j = 0; info->binary_names[j] != NULL; j++) {
                    if (match_pattern_exact(binary_name, info->binary_names[j])) {
                        return info;
                    }
                }
            }

            // v1.8.6: Use exact matching for package names to prevent false positives
            if (pkg_name && info->package_names) {
                for (size_t j = 0; info->package_names[j] != NULL; j++) {
                    if (match_pattern_exact(pkg_name, info->package_names[j])) {
                        return info;
                    }
                }
            }
        }
    }

    return NULL;
}

// ============================================================================
// Dynamic Registry Cleanup
// ============================================================================

// Cleanup dynamic registry
// Called ONCE at program exit (not mid-process)
void crypto_registry_cleanup(void) {
    // Free dynamic crypto libraries
    for (size_t i = 0; i < dynamic_crypto_libraries_count; i++) {
        crypto_library_info_t *lib = &dynamic_crypto_libraries[i];

        // Free id
        if (lib->id) {
            free((void*)lib->id);
        }

        // Free pkg_patterns array
        if (lib->pkg_patterns) {
            for (size_t j = 0; lib->pkg_patterns[j] != NULL; j++) {
                free((void*)lib->pkg_patterns[j]);
            }
            free((void*)lib->pkg_patterns);
        }

        // Free soname_patterns array
        if (lib->soname_patterns) {
            for (size_t j = 0; lib->soname_patterns[j] != NULL; j++) {
                free((void*)lib->soname_patterns[j]);
            }
            free((void*)lib->soname_patterns);
        }

        // Free algorithms array
        if (lib->algorithms) {
            for (size_t j = 0; lib->algorithms[j] != NULL; j++) {
                free((void*)lib->algorithms[j]);
            }
            free((void*)lib->algorithms);
        }
    }

    free(dynamic_crypto_libraries);
    dynamic_crypto_libraries = NULL;
    dynamic_crypto_libraries_count = 0;
    dynamic_crypto_libraries_capacity = 0;

    // Free dynamic embedded apps
    for (size_t i = 0; i < dynamic_embedded_apps_count; i++) {
        embedded_crypto_app_info_t *app = &dynamic_embedded_apps[i];

        // Free provider_id
        if (app->provider_id) {
            free((void*)app->provider_id);
        }

        // Free binary_names array
        if (app->binary_names) {
            for (size_t j = 0; app->binary_names[j] != NULL; j++) {
                free((void*)app->binary_names[j]);
            }
            free((void*)app->binary_names);
        }

        // Free package_names array
        if (app->package_names) {
            for (size_t j = 0; app->package_names[j] != NULL; j++) {
                free((void*)app->package_names[j]);
            }
            free((void*)app->package_names);
        }

        // Free algorithms array
        if (app->algorithms) {
            for (size_t j = 0; app->algorithms[j] != NULL; j++) {
                free((void*)app->algorithms[j]);
            }
            free((void*)app->algorithms);
        }
    }

    free(dynamic_embedded_apps);
    dynamic_embedded_apps = NULL;
    dynamic_embedded_apps_count = 0;
    dynamic_embedded_apps_capacity = 0;

    dynamic_registry_loaded = false;
}
