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
 * @file config_extractor.h
 * @brief Configuration extraction engine
 *
 * Orchestrates config file parsing and crypto directive extraction
 * using YAML plugin rules.
 */

#ifndef CONFIG_EXTRACTOR_H
#define CONFIG_EXTRACTOR_H

#include "plugin_schema.h"
#include "service_discovery.h"
#include "config_parser.h"
#include <time.h>

/**
 * Extracted cryptographic configuration
 */
typedef struct {
    // Certificate paths
    char** certificate_paths;
    int certificate_count;

    // Private key paths
    char** private_key_paths;
    int private_key_count;

    // CA certificate paths
    char** ca_cert_paths;
    int ca_cert_count;

    // Protocol configuration
    char* min_tls_version;      // Backward compat: lowest version in array
    char* max_tls_version;      // Backward compat: highest version in array
    char** tls_versions;        // Array of all TLS versions (e.g., ["1.2", "1.3"])
    int tls_version_count;      // Number of versions in array

    // Cipher suites
    char** cipher_suites;
    int cipher_count;

    // Other crypto settings
    bool tls_enabled;
    bool client_cert_required;
    bool prefer_server_ciphers;

    // Metadata
    char* config_file;
    time_t extracted_at;
} crypto_config_t;

/**
 * Initialize config extractor system
 * Initializes parser registry and registers all parsers
 *
 * @return 0 on success, -1 on error
 */
int config_extractor_init(void);

/**
 * Destroy config extractor system
 */
void config_extractor_destroy(void);

/**
 * Extract crypto config from a service using YAML plugin rules
 *
 * @param instance Service instance with detection info
 * @param plugin YAML plugin with extraction rules
 * @return Crypto config (caller must free), or NULL on error
 */
crypto_config_t* config_extractor_extract(
    service_instance_t* instance,
    void* plugin  // yaml_plugin_t*, but void* to avoid type conflicts
);

/**
 * Free crypto config
 *
 * @param config Config to free
 */
void crypto_config_free(crypto_config_t* config);

/**
 * Print crypto config (for debugging)
 *
 * @param config Config to print
 */
void crypto_config_print(const crypto_config_t* config);

#endif // CONFIG_EXTRACTOR_H
