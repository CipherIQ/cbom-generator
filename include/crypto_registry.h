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

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *id;                  // e.g. "openssl"
    const char **pkg_patterns;       // e.g. ["libssl", "libssl3", "libcrypto3", "libssl-dev", NULL]
    const char **soname_patterns;    // e.g. ["libssl.so", "libcrypto.so", NULL]
    const char **algorithms;         // high-level names, NULL-terminated
} crypto_library_info_t;

typedef struct {
    const char *provider_id;         // e.g. "openssh_internal"
    const char **binary_names;       // e.g. ["ssh", "sshd", "ssh-keygen", NULL]
    const char **package_names;      // e.g. ["openssh-server", "openssh-client", NULL]
    const char **algorithms;         // NULL-terminated
} embedded_crypto_app_info_t;

const crypto_library_info_t *find_crypto_lib_by_soname(const char *soname);
const crypto_library_info_t *find_crypto_lib_by_pkg(const char *pkg_name);
const embedded_crypto_app_info_t *find_embedded_crypto_by_binary(
    const char *binary_name,
    const char *pkg_name
);

// YAML registry extension (v1.6)
int crypto_registry_load_from_file(const char *path, char *errbuf, size_t errbuf_len);
void crypto_registry_cleanup(void);

#ifdef __cplusplus
}
#endif
