// SPDX-License-Identifier: GPL-3.0-or-later
// Portable SHA256 — uses OpenSSL on native, simple hash on WASM
#ifndef SHA256_PORTABLE_H
#define SHA256_PORTABLE_H

#ifdef __EMSCRIPTEN__

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LENGTH 32

// Simple deterministic hash for WASM (not cryptographic — used only for ID generation)
static inline unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md) {
    static unsigned char buf[32];
    if (!md) md = buf;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= d[i];
        h *= 1099511628211ULL;
    }
    for (int block = 0; block < 4; block++) {
        uint64_t v = h ^ ((uint64_t)block * 2654435761ULL);
        v *= 1099511628211ULL;
        for (int i = 0; i < 8; i++)
            md[block * 8 + i] = (unsigned char)((v >> (i * 8)) & 0xFF);
    }
    return md;
}

#else
#include <openssl/sha.h>
#endif

#endif // SHA256_PORTABLE_H
