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

#include "cipher_suite_parser.h"
#include "cbom_types.h"
#include "asset_store.h"
#include "secure_memory.h"
#include "pqc_classifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <json-c/json.h>

// TLS 1.3 cipher suite definitions (fixed list - no parser needed)
typedef struct {
    const char* iana_name;
    const char* aead_algorithm;
    const char* hash_algorithm;
    uint32_t security_bits;
    bool is_quantum_vulnerable;
    const char* iana_id;           // Phase 4: IANA hex identifier
} tls13_suite_info_t;

static const tls13_suite_info_t TLS13_SUITES[] = {
    {"TLS_AES_256_GCM_SHA384", "AES-256-GCM", "SHA384", 256, false, "0x13,0x02"},
    {"TLS_AES_128_GCM_SHA256", "AES-128-GCM", "SHA256", 128, false, "0x13,0x01"},
    {"TLS_CHACHA20_POLY1305_SHA256", "ChaCha20-Poly1305", "SHA256", 256, false, "0x13,0x03"},
    {"TLS_AES_128_CCM_SHA256", "AES-128-CCM", "SHA256", 128, false, "0x13,0x04"},
    {"TLS_AES_128_CCM_8_SHA256", "AES-128-CCM-8", "SHA256", 128, false, "0x13,0x05"},
    {NULL, NULL, NULL, 0, false, NULL}  // Sentinel
};

// Create cipher suite metadata
cipher_suite_metadata_t* cipher_suite_metadata_create(const char* name) {
    if (!name) return NULL;

    cipher_suite_metadata_t* metadata = secure_alloc(sizeof(cipher_suite_metadata_t));
    if (!metadata) return NULL;

    memset(metadata, 0, sizeof(cipher_suite_metadata_t));
    metadata->name = strdup(name);
    metadata->confidence = 1.0;  // High confidence for fixed suites

    return metadata;
}

// Destroy cipher suite metadata
void cipher_suite_metadata_destroy(cipher_suite_metadata_t* metadata) {
    if (!metadata) return;

    free(metadata->name);
    free(metadata->openssl_name);
    free(metadata->protocol_family);
    free(metadata->protocol_version);
    free(metadata->kex_algorithm);
    free(metadata->auth_algorithm);
    free(metadata->encryption_algorithm);
    free(metadata->encryption_mode);
    free(metadata->mac_algorithm);
    free(metadata->config_file_path);
    free(metadata->detection_method);
    free(metadata->pqc_alternative);  // Phase 8.0

    // Phase 4: Clean up CycloneDX conformance fields
    if (metadata->iana_id) {
        free(metadata->iana_id);
        metadata->iana_id = NULL;
    }
    if (metadata->algorithm_refs) {
        for (size_t i = 0; i < metadata->algorithm_count; i++) {
            free(metadata->algorithm_refs[i]);
        }
        free(metadata->algorithm_refs);
        metadata->algorithm_refs = NULL;
    }

    secure_zero(metadata, sizeof(cipher_suite_metadata_t));
    secure_free(metadata, sizeof(cipher_suite_metadata_t));
}

// Check if cipher is TLS 1.3
bool is_tls13_cipher(const char* cipher_name) {
    if (!cipher_name) return false;

    for (int i = 0; TLS13_SUITES[i].iana_name != NULL; i++) {
        if (strcmp(cipher_name, TLS13_SUITES[i].iana_name) == 0) {
            return true;
        }
    }
    return false;
}

// Check if cipher is AEAD
bool is_aead_cipher(const char* cipher_name) {
    if (!cipher_name) return false;
    return (strstr(cipher_name, "GCM") != NULL ||
            strstr(cipher_name, "CCM") != NULL ||
            strstr(cipher_name, "POLY1305") != NULL ||
            strstr(cipher_name, "CHACHA20") != NULL);
}

// Get cipher suite family
const char* get_cipher_suite_family(const char* cipher_name) {
    if (!cipher_name) return "UNKNOWN";

    if (strncmp(cipher_name, "TLS_", 4) == 0) {
        return "TLS";
    } else if (strstr(cipher_name, "@openssh.com") != NULL) {
        return "SSH";
    }

    return "UNKNOWN";
}

// Phase 4: Generate and store algorithm bom-refs in cipher suite metadata
// Converts algorithm names to bom-refs (e.g., "AES-256-GCM" → "algorithm-aes-256-gcm")
static void store_algorithm_refs(cipher_suite_metadata_t* metadata) {
    if (!metadata) return;

    // Count non-null algorithms
    size_t count = 0;
    if (metadata->kex_algorithm && strlen(metadata->kex_algorithm) > 0) count++;
    if (metadata->auth_algorithm && strlen(metadata->auth_algorithm) > 0 &&
        (!metadata->kex_algorithm || strcmp(metadata->auth_algorithm, metadata->kex_algorithm) != 0)) count++;
    if (metadata->encryption_algorithm && strlen(metadata->encryption_algorithm) > 0) count++;
    if (metadata->mac_algorithm && strlen(metadata->mac_algorithm) > 0) count++;

    if (count == 0) return;

    // Allocate array for algorithm refs
    metadata->algorithm_refs = malloc(sizeof(char*) * count);
    if (!metadata->algorithm_refs) return;

    metadata->algorithm_count = 0;

    // Generate bom-refs for each algorithm (v1.5: use algo: prefix)
    if (metadata->kex_algorithm && strlen(metadata->kex_algorithm) > 0) {
        size_t ref_len = strlen("algo:") + strlen(metadata->kex_algorithm) + 1;
        metadata->algorithm_refs[metadata->algorithm_count] = malloc(ref_len);
        if (metadata->algorithm_refs[metadata->algorithm_count]) {
            snprintf(metadata->algorithm_refs[metadata->algorithm_count], ref_len,
                    "algo:%s", metadata->kex_algorithm);
            // Lowercase (after prefix)
            for (char* p = metadata->algorithm_refs[metadata->algorithm_count] + 5; *p; p++) {
                *p = tolower(*p);
            }
            metadata->algorithm_count++;
        }
    }

    if (metadata->auth_algorithm && strlen(metadata->auth_algorithm) > 0 &&
        (!metadata->kex_algorithm || strcmp(metadata->auth_algorithm, metadata->kex_algorithm) != 0)) {
        size_t ref_len = strlen("algo:") + strlen(metadata->auth_algorithm) + 1;
        metadata->algorithm_refs[metadata->algorithm_count] = malloc(ref_len);
        if (metadata->algorithm_refs[metadata->algorithm_count]) {
            snprintf(metadata->algorithm_refs[metadata->algorithm_count], ref_len,
                    "algo:%s", metadata->auth_algorithm);
            // Lowercase (after prefix)
            for (char* p = metadata->algorithm_refs[metadata->algorithm_count] + 5; *p; p++) {
                *p = tolower(*p);
            }
            metadata->algorithm_count++;
        }
    }

    if (metadata->encryption_algorithm && strlen(metadata->encryption_algorithm) > 0) {
        size_t ref_len = strlen("algo:") + strlen(metadata->encryption_algorithm) + 1;
        metadata->algorithm_refs[metadata->algorithm_count] = malloc(ref_len);
        if (metadata->algorithm_refs[metadata->algorithm_count]) {
            snprintf(metadata->algorithm_refs[metadata->algorithm_count], ref_len,
                    "algo:%s", metadata->encryption_algorithm);
            // Lowercase (after prefix)
            for (char* p = metadata->algorithm_refs[metadata->algorithm_count] + 5; *p; p++) {
                *p = tolower(*p);
            }
            metadata->algorithm_count++;
        }
    }

    if (metadata->mac_algorithm && strlen(metadata->mac_algorithm) > 0) {
        size_t ref_len = strlen("algo:") + strlen(metadata->mac_algorithm) + 1;
        metadata->algorithm_refs[metadata->algorithm_count] = malloc(ref_len);
        if (metadata->algorithm_refs[metadata->algorithm_count]) {
            snprintf(metadata->algorithm_refs[metadata->algorithm_count], ref_len,
                    "algo:%s", metadata->mac_algorithm);
            // Lowercase (after prefix)
            for (char* p = metadata->algorithm_refs[metadata->algorithm_count] + 5; *p; p++) {
                *p = tolower(*p);
            }
            metadata->algorithm_count++;
        }
    }
}

// Parse TLS 1.3 cipher suite (from fixed list)
cipher_suite_metadata_t* parse_cipher_suite(const char* cipher_name,
                                            const char* protocol_family,
                                            const char* protocol_version) {
    if (!cipher_name) return NULL;

    // Find in TLS 1.3 suite list
    const tls13_suite_info_t* suite_info = NULL;
    for (int i = 0; TLS13_SUITES[i].iana_name != NULL; i++) {
        if (strcmp(cipher_name, TLS13_SUITES[i].iana_name) == 0) {
            suite_info = &TLS13_SUITES[i];
            break;
        }
    }

    if (!suite_info) return NULL;  // Not a TLS 1.3 suite

    cipher_suite_metadata_t* metadata = cipher_suite_metadata_create(cipher_name);
    if (!metadata) return NULL;

    // Set protocol info
    metadata->protocol_family = strdup(protocol_family ? protocol_family : "TLS");
    metadata->protocol_version = strdup(protocol_version ? protocol_version : "1.3");

    // TLS 1.3 always uses ECDHE for key exchange
    metadata->kex_algorithm = strdup("ECDHE");

    // Extract AEAD and hash from suite info
    metadata->encryption_algorithm = strdup(suite_info->aead_algorithm);
    metadata->mac_algorithm = strdup(suite_info->hash_algorithm);

    // TLS 1.3 uses AEAD
    metadata->is_aead = true;
    metadata->encryption_mode = strdup("AEAD");

    // Security properties
    metadata->security_strength = suite_info->security_bits;
    metadata->is_quantum_vulnerable = suite_info->is_quantum_vulnerable;
    metadata->is_deprecated = false;  // TLS 1.3 suites are modern

    // Phase 4: IANA hex identifier
    if (suite_info->iana_id) {
        metadata->iana_id = strdup(suite_info->iana_id);
    }

    // Phase 4: Generate and store algorithm bom-refs
    store_algorithm_refs(metadata);

    // Detection method
    metadata->detection_method = strdup("config_parser");

    return metadata;
}

// Calculate cipher suite security strength
uint32_t calculate_cipher_suite_strength(const cipher_suite_metadata_t* suite) {
    if (!suite) return 0;
    return suite->security_strength;
}

// Check if cipher suite is quantum vulnerable
bool is_cipher_suite_quantum_vulnerable(const cipher_suite_metadata_t* suite) {
    if (!suite) return true;

    // RSA and ECDHE key exchange are quantum-vulnerable
    // AEAD ciphers themselves are quantum-resistant
    if (suite->kex_algorithm) {
        if (strstr(suite->kex_algorithm, "RSA") != NULL ||
            strstr(suite->kex_algorithm, "ECDHE") != NULL ||
            strstr(suite->kex_algorithm, "DHE") != NULL) {
            return true;
        }
    }

    return suite->is_quantum_vulnerable;
}

// Check if cipher suite is deprecated
bool is_cipher_suite_deprecated(const cipher_suite_metadata_t* suite) {
    if (!suite) return false;
    return suite->is_deprecated;
}

// PQC assessment for cipher suite (Phase 8.0)
void assess_cipher_suite_pqc(cipher_suite_metadata_t* suite) {
    if (!suite) return;

    // Default to unknown
    suite->pqc_category = PQC_UNKNOWN;
    suite->pqc_alternative = NULL;
    suite->pqc_urgency = URGENCY_UNKNOWN;

    // Classify based on key exchange algorithm
    // TLS 1.2/1.3 use ECDHE, DHE, or RSA for KEX - all quantum-vulnerable

    if (suite->kex_algorithm) {
        // Check for hybrid PQC KEX (experimental)
        if (detect_hybrid_algorithm(suite->kex_algorithm)) {
            suite->pqc_category = PQC_SAFE;
            suite->pqc_urgency = URGENCY_LOW;
            suite->pqc_alternative = strdup("Already hybrid (classical + PQC)");
            return;
        }

        // Check for PQC-only KEX (NIST-finalized)
        if (is_nist_finalized_pqc(suite->kex_algorithm)) {
            suite->pqc_category = PQC_SAFE;
            suite->pqc_urgency = URGENCY_LOW;
            suite->pqc_alternative = strdup("Already using PQC key exchange");
            return;
        }

        // Classical KEX algorithms
        if (strstr(suite->kex_algorithm, "RSA") ||
            strstr(suite->kex_algorithm, "ECDHE") ||
            strstr(suite->kex_algorithm, "DHE")) {

            // Check if deprecated
            if (suite->is_deprecated || is_cipher_suite_weak(suite->name)) {
                suite->pqc_category = PQC_DEPRECATED;
                suite->pqc_urgency = URGENCY_CRITICAL;
            } else {
                // Quantum-vulnerable but classically strong
                suite->pqc_category = PQC_TRANSITIONAL;
                suite->pqc_urgency = URGENCY_HIGH;
            }

            // Suggest PQC alternative based on KEX type
            char alt_buffer[256];
            if (strstr(suite->kex_algorithm, "ECDHE") || strstr(suite->kex_algorithm, "ECDH")) {
                // Suggest hybrid first for ECDHE (easier transition)
                if (strstr(suite->kex_algorithm, "X25519")) {
                    snprintf(alt_buffer, sizeof(alt_buffer),
                            "X25519Kyber768 (hybrid) or Kyber-768 (ML-KEM-768)");
                } else {
                    snprintf(alt_buffer, sizeof(alt_buffer),
                            "Kyber-768 (ML-KEM-768) or hybrid ECDH+Kyber");
                }
            } else if (strstr(suite->kex_algorithm, "RSA")) {
                snprintf(alt_buffer, sizeof(alt_buffer),
                        "Kyber-1024 (ML-KEM-1024) for RSA key transport");
            } else if (strstr(suite->kex_algorithm, "DHE") || strstr(suite->kex_algorithm, "DH")) {
                snprintf(alt_buffer, sizeof(alt_buffer),
                        "Kyber-1024 (ML-KEM-1024) or hybrid DH+Kyber");
            } else {
                snprintf(alt_buffer, sizeof(alt_buffer),
                        "Kyber-768 (ML-KEM-768) or Kyber-1024 (ML-KEM-1024)");
            }
            suite->pqc_alternative = strdup(alt_buffer);
            return;
        }
    }

    // If no KEX algorithm identified, check encryption
    // Symmetric ciphers >=256 bits are quantum-resistant
    if (suite->encryption_algorithm && suite->security_strength >= 256) {
        suite->pqc_category = PQC_SAFE;
        suite->pqc_urgency = URGENCY_LOW;
        suite->pqc_alternative = strdup("Symmetric cipher is quantum-resistant");
        return;
    }

    // Default: unknown or insufficient information
    suite->pqc_category = PQC_UNKNOWN;
    suite->pqc_urgency = URGENCY_UNKNOWN;
    suite->pqc_alternative = strdup("Unable to assess PQC readiness");
}

// Check if cipher suite is weak
bool is_cipher_suite_weak(const char* cipher_name) {
    if (!cipher_name) return false;

    // Weak indicators
    const char* weak_patterns[] = {
        "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "ADH", "MD5",
        NULL
    };

    for (int i = 0; weak_patterns[i] != NULL; i++) {
        if (strcasestr(cipher_name, weak_patterns[i]) != NULL) {
            return true;
        }
    }

    return false;
}

// Create cipher suite JSON metadata
char* cipher_suite_create_json_metadata(const cipher_suite_metadata_t* metadata) {
    if (!metadata) return NULL;

    json_object* root = json_object_new_object();
    if (!root) return NULL;

    if (metadata->name) {
        json_object_object_add(root, "name", json_object_new_string(metadata->name));
    }

    if (metadata->protocol_family) {
        json_object_object_add(root, "protocol_family", json_object_new_string(metadata->protocol_family));
    }

    if (metadata->protocol_version) {
        json_object_object_add(root, "protocol_version", json_object_new_string(metadata->protocol_version));
    }

    // Phase 4: IANA hex identifier
    if (metadata->iana_id) {
        json_object_object_add(root, "iana_id", json_object_new_string(metadata->iana_id));
    }

    if (metadata->kex_algorithm) {
        json_object_object_add(root, "kex_algorithm", json_object_new_string(metadata->kex_algorithm));
    }

    if (metadata->encryption_algorithm) {
        json_object_object_add(root, "encryption_algorithm", json_object_new_string(metadata->encryption_algorithm));
    }

    if (metadata->mac_algorithm) {
        json_object_object_add(root, "hash_algorithm", json_object_new_string(metadata->mac_algorithm));
    }

    // Phase 4: Algorithm references array
    if (metadata->algorithm_refs && metadata->algorithm_count > 0) {
        json_object* algo_refs_array = json_object_new_array();
        for (size_t i = 0; i < metadata->algorithm_count; i++) {
            json_object_array_add(algo_refs_array,
                json_object_new_string(metadata->algorithm_refs[i]));
        }
        json_object_object_add(root, "algorithm_refs", algo_refs_array);
    }

    json_object_object_add(root, "security_strength_bits", json_object_new_int(metadata->security_strength));
    json_object_object_add(root, "is_aead", json_object_new_boolean(metadata->is_aead));
    json_object_object_add(root, "is_quantum_vulnerable", json_object_new_boolean(metadata->is_quantum_vulnerable));

    // Detection context
    if (metadata->config_file_path) {
        json_object_object_add(root, "cbom:ctx:file_path", json_object_new_string(metadata->config_file_path));
    }
    if (metadata->line_number > 0) {
        json_object_object_add(root, "cbom:ctx:line_number", json_object_new_int(metadata->line_number));
    }
    if (metadata->detection_method) {
        json_object_object_add(root, "cbom:ctx:detection_method", json_object_new_string(metadata->detection_method));
    }

    char conf_str[16];
    snprintf(conf_str, sizeof(conf_str), "%.2f", metadata->confidence);
    json_object_object_add(root, "cbom:ctx:confidence", json_object_new_string(conf_str));

    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = NULL;
    if (json_str) {
        result = malloc(strlen(json_str) + 1);
        if (result) strcpy(result, json_str);
    }

    json_object_put(root);
    return result;
}

// Create cipher suite asset with SHA-256 content-addressed ID
struct crypto_asset* cipher_suite_create_asset(const cipher_suite_metadata_t* metadata) {
    if (!metadata) return NULL;

    crypto_asset_t* asset = crypto_asset_create(metadata->name, ASSET_TYPE_CIPHER_SUITE);
    if (!asset) return NULL;

    // Generate SHA-256 content-addressed ID
    char id_string[512];
    snprintf(id_string, sizeof(id_string), "cipher|%s|%s|%s",
            metadata->protocol_family ? metadata->protocol_family : "TLS",
            metadata->protocol_version ? metadata->protocol_version : "1.3",
            metadata->name);

    // Compute SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)id_string, strlen(id_string), hash);

    char* sha256_id = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (sha256_id) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(sha256_id + i * 2, "%02x", hash[i]);
        }
        free(asset->id);
        asset->id = sha256_id;
    }

    // Set algorithm field
    if (metadata->encryption_algorithm) {
        free(asset->algorithm);
        asset->algorithm = strdup(metadata->encryption_algorithm);
    }

    // Set key size
    asset->key_size = metadata->security_strength;

    // Set weakness flag
    asset->is_weak = is_cipher_suite_weak(metadata->name);
    asset->is_pqc_ready = !metadata->is_quantum_vulnerable;

    // Set location
    if (metadata->config_file_path) {
        asset->location = strdup(metadata->config_file_path);
    }

    // Store detailed metadata
    asset->metadata_json = cipher_suite_create_json_metadata(metadata);

    return asset;
}

// OpenSSL to IANA cipher name mapping (TLS 1.2 common ciphers)
typedef struct {
    const char* openssl_name;
    const char* iana_name;
    const char* kex;
    const char* auth;
    const char* enc;
    const char* mac;
    uint32_t strength;
    const char* iana_id;           // Phase 4: IANA hex identifier
} tls12_cipher_map_t;

static const tls12_cipher_map_t TLS12_CIPHER_MAP[] = {
    {"ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES-256-GCM", "SHA384", 256, "0xC0,0x30"},
    {"ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES-128-GCM", "SHA256", 128, "0xC0,0x2F"},
    {"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AES-256-GCM", "SHA384", 256, "0xC0,0x2C"},
    {"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AES-128-GCM", "SHA256", 128, "0xC0,0x2B"},
    {"DHE-RSA-AES256-GCM-SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "AES-256-GCM", "SHA384", 256, "0x00,0x9F"},
    {"DHE-RSA-AES128-GCM-SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "AES-128-GCM", "SHA256", 128, "0x00,0x9E"},
    {"ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES-256-CBC", "SHA384", 256, "0xC0,0x28"},
    {"ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "AES-128-CBC", "SHA256", 128, "0xC0,0x27"},
    {"AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", "AES-256-GCM", "SHA384", 256, "0x00,0x9D"},
    {"AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AES-128-GCM", "SHA256", 128, "0x00,0x9C"},
    {"AES256-SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", "AES-256-CBC", "SHA256", 256, "0x00,0x3D"},
    {"AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES-128-CBC", "SHA1", 128, "0x00,0x2F"},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

// Parse OpenSSL cipher list (subset: literals + ! exclusions)
char** parse_openssl_cipher_list(const char* cipher_string, size_t* count) {
    if (!cipher_string || !count) return NULL;

    *count = 0;
    char** result = malloc(sizeof(char*) * 100);
    if (!result) return NULL;

    char* ciphers = strdup(cipher_string);
    if (!ciphers) {
        free(result);
        return NULL;
    }

    // Track excluded ciphers
    char* excluded[50];
    size_t excluded_count = 0;

    // Parse colon-delimited list
    char* token = strtok(ciphers, ":");
    while (token && *count < 100) {
        // Trim whitespace
        while (*token == ' ' || *token == '\t') token++;

        // Handle exclusion (!)
        if (token[0] == '!') {
            // Add to excluded list
            if (excluded_count < 50) {
                excluded[excluded_count++] = strdup(token + 1);
            }
        } else {
            // Add to result (if not excluded)
            bool is_excluded = false;
            for (size_t i = 0; i < excluded_count; i++) {
                if (strcasecmp(token, excluded[i]) == 0 ||
                    strstr(token, excluded[i]) != NULL) {
                    is_excluded = true;
                    break;
                }
            }

            if (!is_excluded) {
                result[*count] = strdup(token);
                (*count)++;
            }
        }

        token = strtok(NULL, ":");
    }

    // Clean up
    for (size_t i = 0; i < excluded_count; i++) {
        free(excluded[i]);
    }
    free(ciphers);

    if (*count == 0) {
        free(result);
        return NULL;
    }

    return result;
}

// Parse TLS 1.2 cipher suite from OpenSSL name
cipher_suite_metadata_t* parse_tls12_cipher(const char* openssl_name,
                                            const char* protocol_version,
                                            const char* config_file_path) {
    if (!openssl_name) return NULL;

    // Find in mapping table
    const tls12_cipher_map_t* mapping = NULL;
    for (int i = 0; TLS12_CIPHER_MAP[i].openssl_name != NULL; i++) {
        if (strcasecmp(openssl_name, TLS12_CIPHER_MAP[i].openssl_name) == 0) {
            mapping = &TLS12_CIPHER_MAP[i];
            break;
        }
    }

    if (!mapping) return NULL;

    cipher_suite_metadata_t* suite = cipher_suite_metadata_create(mapping->iana_name);
    if (!suite) return NULL;

    // Set OpenSSL name
    suite->openssl_name = strdup(openssl_name);

    // Set protocol info
    suite->protocol_family = strdup("TLS");
    suite->protocol_version = strdup(protocol_version ? protocol_version : "1.2");

    // Decompose TLS 1.2 cipher
    suite->kex_algorithm = strdup(mapping->kex);
    suite->auth_algorithm = strdup(mapping->auth);
    suite->encryption_algorithm = strdup(mapping->enc);

    // Check if AEAD
    if (strstr(mapping->enc, "GCM") || strstr(mapping->enc, "CCM")) {
        suite->is_aead = true;
        suite->encryption_mode = strdup("AEAD");
        suite->mac_algorithm = NULL;  // Implicit with AEAD
    } else {
        suite->is_aead = false;
        suite->encryption_mode = strdup("CBC");
        suite->mac_algorithm = strdup(mapping->mac);
    }

    // Security properties
    suite->security_strength = mapping->strength;
    suite->is_quantum_vulnerable = true;  // All TLS 1.2 KEX vulnerable
    suite->is_deprecated = (strstr(mapping->mac, "SHA1") != NULL ||
                           strstr(mapping->enc, "3DES") != NULL);

    // Phase 4: IANA hex identifier
    if (mapping->iana_id) {
        suite->iana_id = strdup(mapping->iana_id);
    }

    // Phase 4: Generate and store algorithm bom-refs
    store_algorithm_refs(suite);

    // Detection context
    if (config_file_path) {
        suite->config_file_path = strdup(config_file_path);
    }
    suite->detection_method = strdup("openssl_cipher_list");
    suite->confidence = 0.9;

    return suite;
}

// Get all TLS 1.3 cipher suites
cipher_suite_metadata_t** get_all_tls13_suites(size_t* count, const char* config_file_path) {
    if (!count) return NULL;

    size_t suite_count = 0;
    for (int i = 0; TLS13_SUITES[i].iana_name != NULL; i++) {
        suite_count++;
    }

    cipher_suite_metadata_t** suites = malloc(sizeof(cipher_suite_metadata_t*) * suite_count);
    if (!suites) {
        *count = 0;
        return NULL;
    }

    *count = 0;
    for (int i = 0; TLS13_SUITES[i].iana_name != NULL; i++) {
        cipher_suite_metadata_t* suite = parse_cipher_suite(
            TLS13_SUITES[i].iana_name, "TLS", "1.3");

        if (suite) {
            // Add detection context
            if (config_file_path) {
                suite->config_file_path = strdup(config_file_path);
            }
            suite->line_number = 0;  // Unknown for now
            suite->detection_method = strdup("tls13_default_suites");
            suite->confidence = 0.95;

            suites[(*count)++] = suite;
        }
    }

    return suites;
}

// Parse cipher list and create suite metadata array (Phase 7.3b)
cipher_suite_metadata_t** parse_cipher_list_to_suites(const char* cipher_string,
                                                      const char* protocol_version,
                                                      const char* config_file_path,
                                                      size_t* count) {
    if (!cipher_string || !count) return NULL;

    // Parse OpenSSL cipher list
    size_t cipher_count;
    char** cipher_names = parse_openssl_cipher_list(cipher_string, &cipher_count);
    if (!cipher_names) {
        *count = 0;
        return NULL;
    }

    cipher_suite_metadata_t** suites = malloc(sizeof(cipher_suite_metadata_t*) * cipher_count);
    if (!suites) {
        for (size_t i = 0; i < cipher_count; i++) free(cipher_names[i]);
        free(cipher_names);
        *count = 0;
        return NULL;
    }

    *count = 0;
    for (size_t i = 0; i < cipher_count; i++) {
        cipher_suite_metadata_t* suite = NULL;

        // Check if TLS 1.3 suite
        if (is_tls13_cipher(cipher_names[i])) {
            suite = parse_cipher_suite(cipher_names[i], "TLS", "1.3");
        } else {
            // Try TLS 1.2 parsing
            suite = parse_tls12_cipher(cipher_names[i], protocol_version, config_file_path);
        }

        if (suite) {
            suites[(*count)++] = suite;
        }

        free(cipher_names[i]);
    }
    free(cipher_names);

    if (*count == 0) {
        free(suites);
        return NULL;
    }

    return suites;
}
