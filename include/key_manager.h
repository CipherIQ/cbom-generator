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

#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "asset_store.h"

// Key manager for SPKI deduplication and first-class KEY components

// Register a certificate's public key and return the key ID
// If the key already exists (same SPKI), returns existing key ID
// If new key, creates a KEY component and returns its ID
char* key_manager_register_certificate_key(X509 *cert, asset_store_t *store);

// Get statistics about registered keys
typedef struct {
    size_t total_keys;
    size_t unique_keys;
    size_t rsa_keys;
    size_t ec_keys;
    size_t other_keys;
    size_t weak_keys;
} key_manager_stats_t;

key_manager_stats_t key_manager_get_stats(void);

// Cleanup key manager resources
void key_manager_cleanup(void);

// Issue #4: Relationship building functions

// Match private keys to their certificates using SPKI hash comparison
// Creates RELATIONSHIP_SIGNS relationships
// Returns number of key-cert matches created
int key_manager_match_keys_to_certificates(asset_store_t *store);

// Build certificate chains by matching issuer → subject DNs
// Creates RELATIONSHIP_ISSUED_BY relationships
// Returns number of chain relationships created
int key_manager_build_certificate_chains(asset_store_t *store);

#endif // KEY_MANAGER_H
