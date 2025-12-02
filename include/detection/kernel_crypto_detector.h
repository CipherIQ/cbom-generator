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
 * @file kernel_crypto_detector.h
 * @brief Kernel crypto API and static crypto detection (v1.8.3)
 *
 * Detects applications using cryptography through methods not visible
 * via dynamic library analysis:
 * - Linux Kernel Crypto API (AF_ALG sockets)
 * - Statically linked crypto (Go, Rust)
 * - Embedded crypto symbols
 */

#ifndef KERNEL_CRYPTO_DETECTOR_H
#define KERNEL_CRYPTO_DETECTOR_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Information about Kernel Crypto API usage (AF_ALG sockets).
 */
typedef struct {
    bool uses_af_alg;           // Binary uses AF_ALG socket interface
    char** algorithms;          // Detected algorithm names (e.g., "cbc(aes)", "sha256")
    size_t algorithm_count;
} kernel_crypto_info_t;

/**
 * Information about statically linked crypto (Go, Rust, etc.).
 */
typedef struct {
    bool has_static_crypto;     // Binary has statically linked crypto
    const char* language;       // "Go", "Rust", "C" (static OpenSSL), or NULL
    char** packages;            // Detected crypto packages/crates
    size_t package_count;
} static_crypto_info_t;

/**
 * Information about embedded crypto symbols (without .so dependencies).
 */
typedef struct {
    bool has_embedded_symbols;  // Binary has crypto function symbols
    char** symbols;             // Detected crypto symbol names
    size_t symbol_count;
} embedded_crypto_info_t;

/**
 * Detect Linux Kernel Crypto API usage (AF_ALG sockets).
 *
 * Searches binary for AF_ALG-related strings like:
 * - algif_aead, algif_hash, algif_skcipher
 * - Algorithm names: cbc(aes), sha256, sha512
 *
 * @param binary_path Path to the binary to analyze
 * @param info Optional output structure for detailed info
 * @return true if kernel crypto usage detected
 */
bool detect_kernel_crypto_usage(const char* binary_path, kernel_crypto_info_t* info);

/**
 * Detect statically linked crypto libraries.
 *
 * Detects:
 * - Go: crypto/tls, crypto/aes, golang.org/x/crypto
 * - Rust: ring::, rustls::, native_tls::
 * - C: OpenSSL symbols without libssl.so dependency
 *
 * @param binary_path Path to the binary to analyze
 * @param info Optional output structure for detailed info
 * @return true if static crypto detected
 */
bool detect_static_crypto(const char* binary_path, static_crypto_info_t* info);

/**
 * Detect embedded crypto function symbols.
 *
 * Uses a hybrid approach (v1.8.3):
 * - Unstripped binaries: uses nm for accurate symbol table analysis
 * - Stripped binaries: falls back to mmap string search
 *
 * Looks for crypto function symbols (e.g., AES_encrypt, SHA256_Init)
 * that are defined in the binary itself rather than imported from .so files.
 *
 * @param binary_path Path to the binary to analyze
 * @param info Optional output structure for detailed info
 * @return true if 2+ embedded crypto symbols found
 */
bool detect_embedded_crypto_symbols(const char* binary_path, embedded_crypto_info_t* info);

/**
 * Free kernel_crypto_info_t contents.
 */
void kernel_crypto_info_free(kernel_crypto_info_t* info);

/**
 * Free static_crypto_info_t contents.
 */
void static_crypto_info_free(static_crypto_info_t* info);

/**
 * Free embedded_crypto_info_t contents.
 */
void embedded_crypto_info_free(embedded_crypto_info_t* info);

#endif // KERNEL_CRYPTO_DETECTOR_H
