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

#ifndef PQC_CLASSIFIER_H
#define PQC_CLASSIFIER_H

#include <stdbool.h>
#include <stdint.h>
#include "algorithm_metadata.h"
#include "cbom_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PQC Safety Categories
 *
 * Classification based on NIST IR 8413 "Status Report on the Third Round of the
 * NIST Post-Quantum Cryptography Standardization Process" (2022-03).
 *
 * SCOPE LIMITATION: Only NIST-finalized algorithms (Kyber, Dilithium, SPHINCS+)
 * are classified as PQC_SAFE. Experimental or draft algorithms are not supported.
 */
typedef enum {
    PQC_SAFE = 0,           // NIST-finalized PQC algorithms (Kyber, Dilithium, SPHINCS+)
                            // OR quantum-resistant symmetric (AES-256, SHA-256+)
    PQC_TRANSITIONAL = 1,   // Classical algorithms meeting current standards but quantum-vulnerable
                            // (RSA >= 2048, ECDSA >= 256)
    PQC_DEPRECATED = 2,     // Weak algorithms no longer recommended (MD5, SHA-1, DES, RC4)
    PQC_UNSAFE = 3,         // Quantum-vulnerable with insufficient classical strength
                            // (RSA < 2048, ECDSA < 256, DSA)
    PQC_UNKNOWN = 4         // Unable to classify
} pqc_category_t;

/**
 * Migration Urgency Levels
 *
 * Indicates priority for transitioning to PQC algorithms.
 */
typedef enum {
    URGENCY_CRITICAL = 0,   // Deprecated/weak algorithms - immediate action required
    URGENCY_HIGH = 1,       // Quantum-vulnerable asymmetric algorithms - plan migration
    URGENCY_MEDIUM = 2,     // Classical algorithms with sufficient strength - monitor
    URGENCY_LOW = 3,        // Quantum-resistant algorithms - no action needed
    URGENCY_UNKNOWN = 4
} pqc_urgency_t;

/**
 * PQC Assessment Result
 *
 * Complete assessment of an algorithm's PQC readiness.
 */
typedef struct {
    pqc_category_t category;        // PQC safety category
    pqc_urgency_t urgency;          // Migration urgency level
    char* alternative;              // Suggested PQC alternative (owned, must be freed)
    char* rationale;                // Explanation for classification (owned, must be freed)
    float confidence;               // Confidence score (0.0-1.0)
    bool is_hybrid;                 // True if hybrid classical+PQC algorithm detected
    int break_year_estimate;        // Estimated year quantum computers can break (0 = N/A)
    const char* source;             // Standards reference ("NIST IR 8413", etc.)
} pqc_assessment_t;

/**
 * PQC Readiness Score
 *
 * Aggregated PQC readiness metrics for multiple components.
 */
typedef struct {
    uint32_t total_count;           // Total number of components assessed
    uint32_t safe_count;            // Count of PQC_SAFE components
    uint32_t transitional_count;    // Count of PQC_TRANSITIONAL components
    uint32_t deprecated_count;      // Count of PQC_DEPRECATED components
    uint32_t unsafe_count;          // Count of PQC_UNSAFE components
    float readiness_score;          // Overall readiness (0-100 scale)
} pqc_readiness_score_t;

// === Core Classification Functions ===

/**
 * Classify algorithm's PQC safety category
 *
 * @param algorithm_name Full algorithm name (e.g., "RSA", "AES-256-GCM", "Kyber-768")
 * @param key_size Key size in bits (use 0 if not applicable)
 * @param primitive_type Algorithm primitive type
 * @return PQC safety category
 */
pqc_category_t classify_algorithm_pqc_safety(
    const char* algorithm_name,
    int key_size,
    crypto_primitive_t primitive_type
);

/**
 * Classify algorithm metadata for PQC safety
 *
 * @param metadata Algorithm metadata structure
 * @return PQC safety category
 */
pqc_category_t classify_algorithm_metadata_pqc(const algorithm_granular_t* metadata);

/**
 * Perform comprehensive PQC assessment
 *
 * @param metadata Algorithm metadata structure
 * @return PQC assessment result (caller must free with pqc_assessment_destroy)
 */
pqc_assessment_t* assess_algorithm_pqc(const algorithm_granular_t* metadata);

/**
 * Destroy PQC assessment result
 *
 * @param assessment Assessment to free
 */
void pqc_assessment_destroy(pqc_assessment_t* assessment);

// === PQC Alternative Suggestions ===

/**
 * Suggest PQC alternative for classical algorithm
 *
 * @param algorithm_name Classical algorithm name
 * @param key_size Key size in bits
 * @param primitive_type Algorithm primitive type
 * @return Suggested PQC algorithm name (caller must free), or NULL if no suggestion
 */
char* suggest_pqc_alternative(
    const char* algorithm_name,
    int key_size,
    crypto_primitive_t primitive_type
);

/**
 * Get migration urgency for algorithm
 *
 * @param category PQC safety category
 * @param is_deprecated True if algorithm is deprecated
 * @return Migration urgency level
 */
pqc_urgency_t get_migration_urgency(pqc_category_t category, bool is_deprecated);

/**
 * Get estimated break year for algorithm
 *
 * Based on NIST IR 8413 + NSA CNSA 2.0 guidance:
 * - RSA-1024, MD5, SHA-1, RC4, DES → 2030 (already weakened classically)
 * - RSA-2048, ECDSA-P256, ECDH-P256 → 2035 (NIST baseline, NSA CNSA 2.0 deadline)
 * - RSA-3072, ECDSA-P384 → 2040 (conservative estimate)
 * - RSA-4096, ECDSA-P521 → 2045 (optimistic, assumes slower quantum progress)
 *
 * @param algorithm_name Algorithm name
 * @param key_size Key size in bits
 * @return Estimated break year, or 0 if not quantum-vulnerable
 */
int pqc_get_break_year_estimate(const char* algorithm_name, int key_size);

// === Hybrid Algorithm Detection ===

/**
 * Detect if algorithm is hybrid (classical + PQC)
 *
 * Detects patterns like:
 * - X25519Kyber768
 * - X25519-Kyber768
 * - SecP256r1Kyber768
 * - ECDH-Kyber768
 *
 * @param algorithm_name Algorithm name to check
 * @return True if hybrid algorithm detected
 */
bool detect_hybrid_algorithm(const char* algorithm_name);

/**
 * Extract classical and PQC components from hybrid algorithm
 *
 * @param hybrid_name Hybrid algorithm name
 * @param classical_out Output buffer for classical component (min 64 bytes)
 * @param pqc_out Output buffer for PQC component (min 64 bytes)
 * @return True if successfully parsed
 */
bool parse_hybrid_algorithm(
    const char* hybrid_name,
    char* classical_out,
    char* pqc_out
);

// === Readiness Scoring ===

/**
 * Calculate PQC readiness score for asset
 *
 * @param asset Cryptographic asset to assess
 * @return Readiness score (0.0 = unsafe, 1.0 = fully PQC-safe)
 */
float calculate_asset_pqc_readiness(const crypto_asset_t* asset);

/**
 * Initialize PQC readiness score structure
 *
 * @return Initialized readiness score (all zeros)
 */
pqc_readiness_score_t pqc_readiness_score_init(void);

/**
 * Update readiness score with new assessment
 *
 * @param score Readiness score to update (in/out)
 * @param category PQC category of new component
 */
void pqc_readiness_score_update(pqc_readiness_score_t* score, pqc_category_t category);

/**
 * Finalize readiness score calculation
 *
 * Calculates overall readiness_score (0-100) based on component counts.
 *
 * Scoring formula:
 * - PQC_SAFE: 100 points
 * - PQC_TRANSITIONAL: 60 points
 * - PQC_DEPRECATED: 20 points
 * - PQC_UNSAFE: 0 points
 *
 * @param score Readiness score to finalize (in/out)
 */
void pqc_readiness_score_finalize(pqc_readiness_score_t* score);

// === String Conversion Utilities ===

/**
 * Convert PQC category to string
 *
 * @param category PQC category
 * @return String representation (e.g., "SAFE", "TRANSITIONAL")
 */
const char* pqc_category_to_string(pqc_category_t category);

/**
 * Convert urgency level to string
 *
 * @param urgency Urgency level
 * @return String representation (e.g., "HIGH", "MEDIUM", "LOW")
 */
const char* pqc_urgency_to_string(pqc_urgency_t urgency);

/**
 * Convert PQC category from string
 *
 * @param str String representation
 * @return PQC category enum value
 */
pqc_category_t pqc_category_from_string(const char* str);

// === NIST-Finalized Algorithm Detection ===

/**
 * Check if algorithm is NIST-finalized PQC algorithm
 *
 * Currently recognizes:
 * - Kyber (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
 * - Dilithium (ML-DSA-44, ML-DSA-65, ML-DSA-87)
 * - SPHINCS+ variants
 *
 * @param algorithm_name Algorithm name to check
 * @return True if NIST-finalized PQC algorithm
 */
bool is_nist_finalized_pqc(const char* algorithm_name);

// === Library Algorithm Classification ===

/**
 * Classify library by its implemented algorithms
 *
 * Libraries are classified based on the WORST (most vulnerable) algorithm
 * they implement. This follows the security principle that the weakest
 * link determines the overall security posture.
 *
 * Example: A library implementing [AES-256 (SAFE), RSA-2048 (TRANSITIONAL)]
 *          is classified as TRANSITIONAL.
 *
 * @param algorithms Array of algorithm name strings
 * @param count Number of algorithms in array
 * @param rationale_out Output buffer for rationale string (min 256 bytes)
 * @param rationale_size Size of rationale buffer
 * @return PQC category based on WORST algorithm, or PQC_UNKNOWN if empty
 */
pqc_category_t classify_library_by_algorithms(
    const char** algorithms,
    size_t count,
    char* rationale_out,
    size_t rationale_size
);

// === Alternate Detection Algorithm Classification (v1.9.0) ===

/**
 * Normalize algorithm name from alternate detection methods.
 *
 * Handles detection patterns from:
 * - Kernel Crypto API: "gcm(aes)" → "AES-256-GCM", "sha256" → "SHA-256"
 * - Go crypto packages: "crypto/aes" → "AES", "crypto/rsa" → "RSA"
 * - Rust crates: "ring::" → "AES-256-GCM", "rustls::" → "TLS-1.3"
 * - Embedded symbols: "SHA256_Init" → "SHA-256", "AES_encrypt" → "AES"
 *
 * @param raw_name    Raw algorithm name from detection
 * @param normalized  Output buffer for normalized name
 * @param norm_size   Size of output buffer (min 64 bytes recommended)
 * @return true if successfully normalized, false if unknown pattern
 */
bool pqc_normalize_alternate_algorithm(
    const char* raw_name,
    char* normalized,
    size_t norm_size
);

/**
 * Classify application PQC status from alternate detection algorithms.
 *
 * Uses WORST-case classification (most vulnerable algorithm determines status).
 *
 * Classification rules:
 * - Hash functions (SHA-256, SHA-512): PQC_SAFE (quantum-resistant)
 * - Symmetric 256-bit (AES-256-GCM): PQC_SAFE
 * - Symmetric 128-bit (AES-128-CBC): PQC_TRANSITIONAL
 * - Asymmetric (RSA, ECDSA): PQC_TRANSITIONAL
 * - Deprecated (MD5, SHA-1, DES): PQC_DEPRECATED
 *
 * @param algorithms     Array of algorithm names (raw from detection)
 * @param count          Number of algorithms
 * @param detection_type Detection method: "KERNEL_CRYPTO_API", "STATIC_LINKED", "SYMBOL_ANALYSIS"
 * @param rationale_out  Output buffer for rationale string
 * @param rationale_size Size of rationale buffer (min 256 bytes recommended)
 * @return PQC category based on WORST detected algorithm
 */
pqc_category_t classify_app_from_alternate_detection(
    const char** algorithms,
    size_t count,
    const char* detection_type,
    char* rationale_out,
    size_t rationale_size
);

#ifdef __cplusplus
}
#endif

#endif // PQC_CLASSIFIER_H
