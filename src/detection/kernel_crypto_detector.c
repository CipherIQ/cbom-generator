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
 * @file kernel_crypto_detector.c
 * @brief Kernel crypto API and static crypto detection (v1.8.3)
 *
 * Detects cryptographic usage through methods not visible via dynamic library analysis:
 * - Linux Kernel Crypto API (AF_ALG sockets)
 * - Statically linked crypto (Go, Rust, static OpenSSL)
 * - Embedded crypto symbols
 */

#define _GNU_SOURCE
#include "detection/kernel_crypto_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

// Minimum printable string length to consider
#define MIN_STRING_LEN 4

// Maximum file size to memory-map (100MB)
#define MAX_FILE_SIZE (100 * 1024 * 1024)

// AF_ALG / Kernel Crypto API markers
static const char* KERNEL_CRYPTO_MARKERS[] = {
    "algif_aead",
    "algif_hash",
    "algif_skcipher",
    "algif_rng",
    "algif_akcipher",
    "AF_ALG",
    NULL
};

// Kernel crypto algorithm name patterns
static const char* KERNEL_ALGO_PATTERNS[] = {
    "cbc(aes)",
    "xts(aes)",
    "gcm(aes)",
    "ccm(aes)",
    "ctr(aes)",
    "ecb(aes)",
    "sha256",
    "sha384",
    "sha512",
    "sha1",
    "md5",
    "hmac(sha256)",
    "hmac(sha512)",
    "rsa",
    "ecdsa",
    "drbg_nopr_sha256",
    NULL
};

// Go crypto package markers
static const char* GO_CRYPTO_MARKERS[] = {
    "crypto/tls",
    "crypto/aes",
    "crypto/rsa",
    "crypto/ecdsa",
    "crypto/sha256",
    "crypto/sha512",
    "crypto/cipher",
    "crypto/hmac",
    "crypto/x509",
    "golang.org/x/crypto",
    "crypto/rand",
    NULL
};

// Rust crypto crate markers
static const char* RUST_CRYPTO_MARKERS[] = {
    "ring::",
    "rustls::",
    "openssl::",
    "native_tls::",
    "webpki::",
    "aes_gcm::",
    "chacha20poly1305::",
    "x25519_dalek::",
    "ed25519_dalek::",
    NULL
};

// Embedded crypto function symbols (found in statically linked binaries)
static const char* CRYPTO_SYMBOLS[] = {
    "AES_encrypt",
    "AES_decrypt",
    "AES_set_encrypt_key",
    "AES_set_decrypt_key",
    "SHA256_Init",
    "SHA256_Update",
    "SHA256_Final",
    "SHA512_Init",
    "SHA512_Update",
    "SHA512_Final",
    "EVP_EncryptInit",
    "EVP_DecryptInit",
    "EVP_DigestInit",
    "EVP_CIPHER_CTX_new",
    "EVP_MD_CTX_new",
    "OPENSSL_init_crypto",
    "gcry_cipher_open",
    "gcry_md_open",
    "gcry_pk_encrypt",
    "nettle_aes_encrypt",
    "nettle_sha256_digest",
    NULL
};

/**
 * Check if character is printable ASCII.
 */
static inline bool is_printable(unsigned char c) {
    return (c >= 0x20 && c <= 0x7e);
}

/**
 * Search for a pattern in memory-mapped binary data.
 * Uses a simple sliding window approach for printable strings.
 *
 * @param data Pointer to memory-mapped binary data
 * @param data_size Size of the data
 * @param pattern Pattern to search for
 * @return true if pattern found
 */
static bool find_string_in_data(const unsigned char* data, size_t data_size, const char* pattern) {
    if (!data || !pattern || data_size == 0) {
        return false;
    }

    size_t pattern_len = strlen(pattern);
    if (pattern_len == 0 || pattern_len > data_size) {
        return false;
    }

    // Slide through the data looking for the pattern
    for (size_t i = 0; i <= data_size - pattern_len; i++) {
        if (memcmp(data + i, pattern, pattern_len) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Memory-map a binary file for efficient string searching.
 *
 * @param binary_path Path to binary
 * @param data Output pointer to mapped data
 * @param size Output size of mapped data
 * @return true on success
 */
static bool mmap_binary(const char* binary_path, unsigned char** data, size_t* size) {
    if (!binary_path || !data || !size) {
        return false;
    }

    *data = NULL;
    *size = 0;

    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    // Check file size limits
    if (st.st_size == 0 || st.st_size > MAX_FILE_SIZE) {
        close(fd);
        return false;
    }

    // Memory-map the file
    void* mapped = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED) {
        return false;
    }

    *data = (unsigned char*)mapped;
    *size = st.st_size;
    return true;
}

/**
 * Unmap a memory-mapped binary.
 */
static void munmap_binary(unsigned char* data, size_t size) {
    if (data && size > 0) {
        munmap(data, size);
    }
}

// Forward declaration (defined below)
static void add_symbol(embedded_crypto_info_t* info, const char* sym);

/**
 * Check if binary has a symbol table (.symtab section).
 * Unstripped binaries have .symtab, stripped binaries do not.
 *
 * @param binary_path Path to binary
 * @return true if binary has symbol table (unstripped)
 */
static bool binary_has_symtab(const char* binary_path) {
    if (!binary_path) return false;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "readelf --sections '%s' 2>/dev/null | grep -q '\\.symtab'",
             binary_path);

    return system(cmd) == 0;
}

/**
 * Detect crypto symbols using nm (for unstripped binaries).
 * More accurate than mmap string search - only matches actual symbols.
 *
 * @param binary_path Path to binary
 * @param info Optional output structure
 * @return true if 2+ crypto symbols found
 */
static bool detect_symbols_via_nm(const char* binary_path, embedded_crypto_info_t* info) {
    if (!binary_path) return false;

    char cmd[1024];
    // Use nm -D for dynamic symbols, nm for static symbols
    // Try both: nm first (includes static), then nm -D (dynamic only)
    snprintf(cmd, sizeof(cmd),
             "(nm '%s' 2>/dev/null; nm -D '%s' 2>/dev/null) | sort -u",
             binary_path, binary_path);

    FILE* fp = popen(cmd, "r");
    if (!fp) return false;

    char line[512];
    int symbol_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        // nm output format: "address type symbol_name"
        // We only care about the symbol name
        for (const char** sym = CRYPTO_SYMBOLS; *sym; sym++) {
            if (strstr(line, *sym)) {
                symbol_count++;
                if (info) {
                    add_symbol(info, *sym);
                }
                break;  // Don't double-count same symbol on same line
            }
        }
    }

    pclose(fp);

    // Require at least 2 symbols to reduce false positives
    if (symbol_count >= 2) {
        if (info) {
            info->has_embedded_symbols = true;
        }
        return true;
    }

    // Clean up if threshold not met
    if (info && info->symbol_count > 0) {
        for (size_t i = 0; i < info->symbol_count; i++) {
            free(info->symbols[i]);
        }
        free(info->symbols);
        info->symbols = NULL;
        info->symbol_count = 0;
        info->has_embedded_symbols = false;
    }

    return false;
}

/**
 * Detect crypto symbols via mmap string search (fallback for stripped binaries).
 * Less accurate than nm but works on stripped binaries.
 *
 * @param binary_path Path to binary
 * @param info Optional output structure
 * @return true if 2+ crypto symbols found
 */
static bool detect_symbols_via_mmap(const char* binary_path, embedded_crypto_info_t* info) {
    if (!binary_path) return false;

    unsigned char* data = NULL;
    size_t size = 0;

    if (!mmap_binary(binary_path, &data, &size)) {
        return false;
    }

    bool found = false;
    int symbol_count = 0;

    // Look for crypto function symbols
    for (const char** sym = CRYPTO_SYMBOLS; *sym; sym++) {
        if (find_string_in_data(data, size, *sym)) {
            found = true;
            symbol_count++;
            if (info) {
                add_symbol(info, *sym);
            }
        }
    }

    // Require at least 2 symbols to reduce false positives
    if (symbol_count < 2) {
        found = false;
        if (info) {
            for (size_t i = 0; i < info->symbol_count; i++) {
                free(info->symbols[i]);
            }
            free(info->symbols);
            info->symbols = NULL;
            info->symbol_count = 0;
            info->has_embedded_symbols = false;
        }
    } else if (info) {
        info->has_embedded_symbols = true;
    }

    munmap_binary(data, size);
    return found;
}

/**
 * Add an algorithm to the kernel_crypto_info_t list.
 */
static void add_algorithm(kernel_crypto_info_t* info, const char* algo) {
    if (!info || !algo) return;

    // Check for duplicates
    for (size_t i = 0; i < info->algorithm_count; i++) {
        if (strcmp(info->algorithms[i], algo) == 0) {
            return;  // Already in list
        }
    }

    // Grow array
    char** new_algos = realloc(info->algorithms, (info->algorithm_count + 1) * sizeof(char*));
    if (!new_algos) return;

    info->algorithms = new_algos;
    info->algorithms[info->algorithm_count] = strdup(algo);
    if (info->algorithms[info->algorithm_count]) {
        info->algorithm_count++;
    }
}

/**
 * Add a package to the static_crypto_info_t list.
 */
static void add_package(static_crypto_info_t* info, const char* pkg) {
    if (!info || !pkg) return;

    // Check for duplicates
    for (size_t i = 0; i < info->package_count; i++) {
        if (strcmp(info->packages[i], pkg) == 0) {
            return;  // Already in list
        }
    }

    // Grow array
    char** new_pkgs = realloc(info->packages, (info->package_count + 1) * sizeof(char*));
    if (!new_pkgs) return;

    info->packages = new_pkgs;
    info->packages[info->package_count] = strdup(pkg);
    if (info->packages[info->package_count]) {
        info->package_count++;
    }
}

/**
 * Add a symbol to the embedded_crypto_info_t list.
 */
static void add_symbol(embedded_crypto_info_t* info, const char* sym) {
    if (!info || !sym) return;

    // Check for duplicates
    for (size_t i = 0; i < info->symbol_count; i++) {
        if (strcmp(info->symbols[i], sym) == 0) {
            return;  // Already in list
        }
    }

    // Grow array
    char** new_syms = realloc(info->symbols, (info->symbol_count + 1) * sizeof(char*));
    if (!new_syms) return;

    info->symbols = new_syms;
    info->symbols[info->symbol_count] = strdup(sym);
    if (info->symbols[info->symbol_count]) {
        info->symbol_count++;
    }
}

bool detect_kernel_crypto_usage(const char* binary_path, kernel_crypto_info_t* info) {
    if (!binary_path) {
        return false;
    }

    unsigned char* data = NULL;
    size_t size = 0;

    if (!mmap_binary(binary_path, &data, &size)) {
        return false;
    }

    bool found = false;

    // Check for AF_ALG markers
    for (const char** marker = KERNEL_CRYPTO_MARKERS; *marker; marker++) {
        if (find_string_in_data(data, size, *marker)) {
            found = true;
            if (info) {
                info->uses_af_alg = true;
            }
            break;  // One marker is enough
        }
    }

    // If AF_ALG detected, also look for algorithm names
    if (found && info) {
        for (const char** algo = KERNEL_ALGO_PATTERNS; *algo; algo++) {
            if (find_string_in_data(data, size, *algo)) {
                add_algorithm(info, *algo);
            }
        }
    }

    munmap_binary(data, size);
    return found;
}

bool detect_static_crypto(const char* binary_path, static_crypto_info_t* info) {
    if (!binary_path) {
        return false;
    }

    unsigned char* data = NULL;
    size_t size = 0;

    if (!mmap_binary(binary_path, &data, &size)) {
        return false;
    }

    bool found = false;
    const char* detected_language = NULL;

    // Check Go crypto markers
    for (const char** marker = GO_CRYPTO_MARKERS; *marker; marker++) {
        if (find_string_in_data(data, size, *marker)) {
            found = true;
            detected_language = "Go";
            if (info) {
                add_package(info, *marker);
            }
        }
    }

    // Check Rust crypto markers (only if not already Go)
    if (!found) {
        for (const char** marker = RUST_CRYPTO_MARKERS; *marker; marker++) {
            if (find_string_in_data(data, size, *marker)) {
                found = true;
                detected_language = "Rust";
                if (info) {
                    add_package(info, *marker);
                }
            }
        }
    }

    if (found && info) {
        info->has_static_crypto = true;
        info->language = detected_language;
    }

    munmap_binary(data, size);
    return found;
}

bool detect_embedded_crypto_symbols(const char* binary_path, embedded_crypto_info_t* info) {
    if (!binary_path) {
        return false;
    }

    // Hybrid approach (v1.8.3):
    // 1. If binary has symbol table (.symtab), use nm for accurate detection
    // 2. If stripped (no .symtab), fall back to mmap string search
    //
    // nm provides more accurate results because it only matches actual symbols,
    // not help text or usage messages that might contain crypto keywords.

    if (binary_has_symtab(binary_path)) {
        // Unstripped binary - use nm for accurate symbol detection
        return detect_symbols_via_nm(binary_path, info);
    } else {
        // Stripped binary - fall back to mmap string search
        return detect_symbols_via_mmap(binary_path, info);
    }
}

void kernel_crypto_info_free(kernel_crypto_info_t* info) {
    if (!info) return;

    for (size_t i = 0; i < info->algorithm_count; i++) {
        free(info->algorithms[i]);
    }
    free(info->algorithms);

    info->algorithms = NULL;
    info->algorithm_count = 0;
    info->uses_af_alg = false;
}

void static_crypto_info_free(static_crypto_info_t* info) {
    if (!info) return;

    for (size_t i = 0; i < info->package_count; i++) {
        free(info->packages[i]);
    }
    free(info->packages);

    info->packages = NULL;
    info->package_count = 0;
    info->has_static_crypto = false;
    info->language = NULL;
}

void embedded_crypto_info_free(embedded_crypto_info_t* info) {
    if (!info) return;

    for (size_t i = 0; i < info->symbol_count; i++) {
        free(info->symbols[i]);
    }
    free(info->symbols);

    info->symbols = NULL;
    info->symbol_count = 0;
    info->has_embedded_symbols = false;
}
