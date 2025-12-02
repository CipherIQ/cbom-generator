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
 * @file component_factory.h
 * @brief Component factory for converting Phase 2/3 outputs to crypto_asset_t
 *
 * This module bridges the gap between service discovery (Phase 2) and config
 * extraction (Phase 3) outputs and the asset_store, creating crypto_asset_t
 * objects with full metadata and PQC assessment.
 *
 * Design:
 * - Reuses certificate_scanner.c for cert metadata extraction
 * - Reuses pqc_classifier.c for quantum vulnerability assessment
 * - Uses secure_alloc/secure_free for all memory operations
 * - Generates content-addressed IDs via asset_store
 */

#ifndef COMPONENT_FACTORY_H
#define COMPONENT_FACTORY_H

#include "service_discovery.h"
#include "config_extractor.h"
#include "asset_store.h"
#include "cbom_types.h"

/**
 * Process a discovered service and its extracted configuration
 *
 * Creates crypto_asset_t objects for:
 * - Service itself (ASSET_TYPE_SERVICE)
 * - Certificates from config (ASSET_TYPE_CERTIFICATE)
 * - Private keys from config (ASSET_TYPE_KEY)
 * - Protocols (ASSET_TYPE_PROTOCOL)
 * - Cipher suites (ASSET_TYPE_CIPHER_SUITE)
 *
 * Also builds relationships:
 * - SERVICE → CERTIFICATE (uses)
 * - SERVICE → PROTOCOL (uses)
 * - PROTOCOL → CIPHER_SUITE (contains)
 * - CERTIFICATE → KEY (authenticates_with, if found)
 *
 * @param service Service instance from Phase 2 discovery
 * @param config Extracted crypto config from Phase 3
 * @param store Asset store to add components to
 * @return 0 on success, -1 on error
 */
int component_factory_process_service(
    service_instance_t* service,
    crypto_config_t* config,
    asset_store_t* store
);

/**
 * Create a service component
 *
 * Converts service_instance_t to crypto_asset_t(ASSET_TYPE_SERVICE)
 *
 * @param service Service instance from Phase 2
 * @param store Asset store (for ID generation)
 * @return Allocated crypto_asset_t or NULL on error
 */
crypto_asset_t* component_factory_create_service(
    service_instance_t* service,
    asset_store_t* store
);

/**
 * Create a certificate component from config path
 *
 * Loads certificate from filesystem, extracts full metadata using
 * certificate_scanner_scan_file(), applies PQC assessment.
 *
 * @param cert_path Path to certificate file (from crypto_config_t)
 * @param service_id ID of parent service (for relationships)
 * @param store Asset store (for ID generation)
 * @return Allocated crypto_asset_t or NULL on error
 */
crypto_asset_t* component_factory_create_certificate(
    const char* cert_path,
    const char* service_id,
    asset_store_t* store
);

/**
 * Create a private key component from config path
 *
 * @param key_path Path to private key file (from crypto_config_t)
 * @param cert_id ID of associated certificate (for relationships)
 * @param store Asset store (for ID generation)
 * @return Allocated crypto_asset_t or NULL on error
 */
crypto_asset_t* component_factory_create_private_key(
    const char* key_path,
    const char* cert_id,
    asset_store_t* store
);

/**
 * Create a protocol component
 *
 * Creates crypto_asset_t(ASSET_TYPE_PROTOCOL) for TLS/SSH/etc.
 *
 * @param protocol_name Protocol name (e.g., "TLS", "SSH")
 * @param version Protocol version (e.g., "1.2", "1.3")
 * @param service_id ID of parent service (for relationships)
 * @param store Asset store (for ID generation)
 * @return Allocated crypto_asset_t or NULL on error
 */
crypto_asset_t* component_factory_create_protocol(
    const char* protocol_name,
    const char* version,
    const char* service_id,
    asset_store_t* store
);

/**
 * Create a cipher suite component
 *
 * Creates crypto_asset_t(ASSET_TYPE_CIPHER_SUITE) for individual cipher.
 *
 * @param cipher_suite Cipher suite name (e.g., "ECDHE-RSA-AES256-GCM-SHA384")
 * @param protocol_id ID of parent protocol (for relationships)
 * @param store Asset store (for ID generation)
 * @return Allocated crypto_asset_t or NULL on error
 */
crypto_asset_t* component_factory_create_cipher_suite(
    const char* cipher_suite,
    const char* protocol_id,
    asset_store_t* store
);

#endif // COMPONENT_FACTORY_H
