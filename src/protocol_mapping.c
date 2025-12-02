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
#include "protocol_mapping.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Convert protocol type to string
const char* protocol_type_to_string(protocol_type_t type) {
    switch (type) {
        case PROTOCOL_TLS: return "TLS";
        case PROTOCOL_SSH: return "SSH";
        case PROTOCOL_IPSEC: return "IPsec";
        case PROTOCOL_JWT: return "JWT";
        default: return "UNKNOWN";
    }
}

// Create protocol mapping context
protocol_mapping_context_t* protocol_mapping_create(void) {
    protocol_mapping_context_t* context = secure_alloc(sizeof(protocol_mapping_context_t));
    if (!context) return NULL;

    context->chains = NULL;
    context->chain_count = 0;
    context->initialized = true;

    return context;
}

// Destroy protocol chain
static void protocol_chain_destroy(protocol_chain_t* chain) {
    if (!chain) return;

    if (chain->service_id) free(chain->service_id);
    if (chain->protocol_id) free(chain->protocol_id);
    if (chain->cipher_suite_id) free(chain->cipher_suite_id);

    if (chain->algorithm_ids) {
        for (size_t i = 0; i < chain->algorithm_count; i++) {
            if (chain->algorithm_ids[i]) free(chain->algorithm_ids[i]);
        }
        free(chain->algorithm_ids);
    }

    secure_free(chain, sizeof(protocol_chain_t));
}

// Destroy protocol mapping context
void protocol_mapping_destroy(protocol_mapping_context_t* context) {
    if (!context) return;

    if (context->chains) {
        for (size_t i = 0; i < context->chain_count; i++) {
            protocol_chain_destroy(context->chains[i]);
        }
        free(context->chains);
    }

    secure_free(context, sizeof(protocol_mapping_context_t));
}

// Add protocol chain relationship
int protocol_mapping_add_chain(protocol_mapping_context_t* context,
                                const char* service_id,
                                const char* protocol_id,
                                const char* cipher_suite_id,
                                const char** algorithm_ids,
                                size_t algorithm_count) {
    if (!context || !service_id || !protocol_id) return -1;

    protocol_chain_t* chain = secure_alloc(sizeof(protocol_chain_t));
    if (!chain) return -1;

    chain->service_id = strdup(service_id);
    chain->protocol_id = strdup(protocol_id);
    chain->cipher_suite_id = cipher_suite_id ? strdup(cipher_suite_id) : NULL;

    if (algorithm_ids && algorithm_count > 0) {
        chain->algorithm_ids = malloc(sizeof(char*) * algorithm_count);
        if (chain->algorithm_ids) {
            for (size_t i = 0; i < algorithm_count; i++) {
                chain->algorithm_ids[i] = strdup(algorithm_ids[i]);
            }
            chain->algorithm_count = algorithm_count;
        }
    } else {
        chain->algorithm_ids = NULL;
        chain->algorithm_count = 0;
    }

    // Add chain to context
    context->chains = realloc(context->chains,
                              sizeof(protocol_chain_t*) * (context->chain_count + 1));
    if (!context->chains) {
        protocol_chain_destroy(chain);
        return -1;
    }

    context->chains[context->chain_count] = chain;
    context->chain_count++;

    return 0;
}

// Parse TLS cipher suite to extract algorithms
// Simplified implementation - returns common algorithm names
char** tls_parse_cipher_suite_algorithms(const char* cipher_suite, size_t* count) {
    if (!cipher_suite || !count) return NULL;

    // Simplified parsing - just identify common patterns
    char** algorithms = NULL;
    size_t algo_count = 0;

    // Check for common algorithms in cipher suite name
    if (strstr(cipher_suite, "AES")) {
        algorithms = realloc(algorithms, sizeof(char*) * (algo_count + 1));
        algorithms[algo_count++] = strdup("AES");
    }
    if (strstr(cipher_suite, "GCM")) {
        algorithms = realloc(algorithms, sizeof(char*) * (algo_count + 1));
        algorithms[algo_count++] = strdup("GCM");
    }
    if (strstr(cipher_suite, "SHA256")) {
        algorithms = realloc(algorithms, sizeof(char*) * (algo_count + 1));
        algorithms[algo_count++] = strdup("SHA256");
    }
    if (strstr(cipher_suite, "SHA384")) {
        algorithms = realloc(algorithms, sizeof(char*) * (algo_count + 1));
        algorithms[algo_count++] = strdup("SHA384");
    }
    if (strstr(cipher_suite, "ECDHE")) {
        algorithms = realloc(algorithms, sizeof(char*) * (algo_count + 1));
        algorithms[algo_count++] = strdup("ECDHE");
    }
    if (strstr(cipher_suite, "RSA")) {
        algorithms = realloc(algorithms, sizeof(char*) * (algo_count + 1));
        algorithms[algo_count++] = strdup("RSA");
    }

    *count = algo_count;
    return algorithms;
}

// Detect protocol from configuration file (stub)
protocol_type_t protocol_detect_from_config(const char* config_file) {
    if (!config_file) return PROTOCOL_UNKNOWN;

    if (strstr(config_file, "nginx") || strstr(config_file, "apache")) {
        return PROTOCOL_TLS;
    }
    if (strstr(config_file, "ssh")) {
        return PROTOCOL_SSH;
    }

    return PROTOCOL_UNKNOWN;
}

// Parse TLS configuration (stub - returns NULL for now)
protocol_version_t* protocol_parse_tls_config(const char* config_content) {
    // This would parse nginx/apache config files to extract TLS settings
    // Stub implementation for Phase 5 completion
    (void)config_content;
    return NULL;
}
