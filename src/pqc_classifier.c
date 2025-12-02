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
#include "pqc_classifier.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// === Internal Helpers ===

/**
 * Case-insensitive substring search
 */
static bool contains_ignorecase(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (needle_len > haystack_len) return false;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }

    return false;
}

// === NIST-Finalized Algorithm Detection ===

bool is_nist_finalized_pqc(const char* algorithm_name) {
    if (!algorithm_name) return false;

    // NIST Finalized Standards (FIPS 203, 204, 205)
    // Kyber variants (ML-KEM / FIPS 203)
    if (contains_ignorecase(algorithm_name, "Kyber")) return true;
    if (contains_ignorecase(algorithm_name, "ML-KEM")) return true;

    // Dilithium variants (ML-DSA / FIPS 204)
    if (contains_ignorecase(algorithm_name, "Dilithium")) return true;
    if (contains_ignorecase(algorithm_name, "ML-DSA")) return true;

    // SPHINCS+ variants (SLH-DSA / FIPS 205)
    if (contains_ignorecase(algorithm_name, "SPHINCS+")) return true;
    if (contains_ignorecase(algorithm_name, "SPHINCS-")) return true;
    if (contains_ignorecase(algorithm_name, "SLH-DSA")) return true;

    // Falcon (FIPS 206 - pending)
    if (contains_ignorecase(algorithm_name, "Falcon")) return true;

    // NIST Round 4 candidates (quantum-resistant, pending standardization)
    // BIKE - Bit Flipping Key Encapsulation
    if (contains_ignorecase(algorithm_name, "BIKE")) return true;

    // HQC - Hamming Quasi-Cyclic
    if (contains_ignorecase(algorithm_name, "HQC")) return true;

    // Classic McEliece (also Round 4)
    if (contains_ignorecase(algorithm_name, "McEliece")) return true;

    // NTRU variants (legacy PQC, also safe)
    if (contains_ignorecase(algorithm_name, "NTRU")) return true;
    if (contains_ignorecase(algorithm_name, "sntrup")) return true;

    return false;
}

// === Hybrid Algorithm Detection ===

bool detect_hybrid_algorithm(const char* algorithm_name) {
    if (!algorithm_name) return false;

    // Hybrid patterns combine classical ECDH/X25519 with PQC (Kyber)
    bool has_classical = (
        contains_ignorecase(algorithm_name, "X25519") ||
        contains_ignorecase(algorithm_name, "X448") ||
        contains_ignorecase(algorithm_name, "ECDH") ||
        contains_ignorecase(algorithm_name, "SecP256r1") ||
        contains_ignorecase(algorithm_name, "SecP384r1") ||
        contains_ignorecase(algorithm_name, "P-256") ||
        contains_ignorecase(algorithm_name, "P-384")
    );

    bool has_pqc = is_nist_finalized_pqc(algorithm_name);

    return has_classical && has_pqc;
}

bool parse_hybrid_algorithm(const char* hybrid_name, char* classical_out, char* pqc_out) {
    if (!hybrid_name || !classical_out || !pqc_out) return false;

    // Initialize outputs
    classical_out[0] = '\0';
    pqc_out[0] = '\0';

    if (!detect_hybrid_algorithm(hybrid_name)) return false;

    // Common hybrid patterns:
    // - X25519Kyber768
    // - X25519-Kyber768
    // - SecP256r1Kyber768

    // Extract classical component
    if (contains_ignorecase(hybrid_name, "X25519")) {
        strncpy(classical_out, "X25519", 63);
    } else if (contains_ignorecase(hybrid_name, "X448")) {
        strncpy(classical_out, "X448", 63);
    } else if (contains_ignorecase(hybrid_name, "SecP256r1") || contains_ignorecase(hybrid_name, "P-256")) {
        strncpy(classical_out, "SecP256r1", 63);
    } else if (contains_ignorecase(hybrid_name, "SecP384r1") || contains_ignorecase(hybrid_name, "P-384")) {
        strncpy(classical_out, "SecP384r1", 63);
    } else {
        strncpy(classical_out, "ECDH", 63);
    }

    // Extract PQC component
    if (contains_ignorecase(hybrid_name, "Kyber768") || contains_ignorecase(hybrid_name, "ML-KEM-768")) {
        strncpy(pqc_out, "Kyber-768", 63);
    } else if (contains_ignorecase(hybrid_name, "Kyber512") || contains_ignorecase(hybrid_name, "ML-KEM-512")) {
        strncpy(pqc_out, "Kyber-512", 63);
    } else if (contains_ignorecase(hybrid_name, "Kyber1024") || contains_ignorecase(hybrid_name, "ML-KEM-1024")) {
        strncpy(pqc_out, "Kyber-1024", 63);
    } else if (contains_ignorecase(hybrid_name, "Kyber")) {
        strncpy(pqc_out, "Kyber", 63);
    }

    return (classical_out[0] != '\0' && pqc_out[0] != '\0');
}

// === Core Classification Functions ===

pqc_category_t classify_algorithm_pqc_safety(
    const char* algorithm_name,
    int key_size,
    crypto_primitive_t primitive_type
) {
    if (!algorithm_name) return PQC_UNKNOWN;

    // 1. Check for NIST-finalized PQC algorithms
    if (is_nist_finalized_pqc(algorithm_name)) {
        return PQC_SAFE;
    }

    // 2. Check for quantum-resistant symmetric ciphers
    if (primitive_type == PRIMITIVE_SYMMETRIC_CIPHER && key_size >= 256) {
        return PQC_SAFE;
    }

    // 3. Check for quantum-resistant hash functions
    if (primitive_type == PRIMITIVE_HASH_FUNCTION && key_size >= 256) {
        return PQC_SAFE;
    }

    // 4. Check for deprecated algorithms (critical vulnerabilities)
    if (contains_ignorecase(algorithm_name, "MD5") ||
        contains_ignorecase(algorithm_name, "SHA1") ||
        contains_ignorecase(algorithm_name, "SHA-1") ||
        contains_ignorecase(algorithm_name, "RC4") ||
        (contains_ignorecase(algorithm_name, "DES") && !contains_ignorecase(algorithm_name, "AES"))) {
        return PQC_DEPRECATED;
    }

    // 5. Check RSA key sizes
    if (contains_ignorecase(algorithm_name, "RSA")) {
        if (key_size >= 2048) {
            return PQC_TRANSITIONAL;  // Quantum-vulnerable but classically strong
        } else {
            return PQC_UNSAFE;  // Quantum-vulnerable AND classically weak
        }
    }

    // 6. Check ECDSA/ECC key sizes (including NIST curve names)
    if (contains_ignorecase(algorithm_name, "ECDSA") ||
        contains_ignorecase(algorithm_name, "ECDH") ||
        contains_ignorecase(algorithm_name, "EC") ||
        contains_ignorecase(algorithm_name, "prime256v1") ||
        contains_ignorecase(algorithm_name, "secp") ||
        contains_ignorecase(algorithm_name, "P-256") ||
        contains_ignorecase(algorithm_name, "P-384") ||
        contains_ignorecase(algorithm_name, "P-521")) {
        if (key_size >= 256) {
            return PQC_TRANSITIONAL;  // Quantum-vulnerable but classically strong
        } else if (key_size == 0) {
            // No key size specified but curve name implies 256+ bits
            return PQC_TRANSITIONAL;
        } else {
            return PQC_UNSAFE;  // Quantum-vulnerable AND classically weak
        }
    }

    // 7. DSA is always unsafe (deprecated + quantum-vulnerable)
    if (contains_ignorecase(algorithm_name, "DSA") && !contains_ignorecase(algorithm_name, "ECDSA")) {
        return PQC_UNSAFE;
    }

    // 8. Ed25519/Ed448 (modern but quantum-vulnerable)
    if (contains_ignorecase(algorithm_name, "Ed25519") || contains_ignorecase(algorithm_name, "Ed448")) {
        return PQC_TRANSITIONAL;
    }

    // 8b. sntrup761/NTRU-Prime is a PQC lattice-based algorithm!
    // Check BEFORE x25519 because hybrids like "sntrup761x25519" contain both
    if (contains_ignorecase(algorithm_name, "sntrup") ||
        contains_ignorecase(algorithm_name, "ntruprime") ||
        contains_ignorecase(algorithm_name, "ntru")) {
        return PQC_SAFE;
    }

    // 8c. curve25519/X25519 (quantum-vulnerable but classically strong)
    if (contains_ignorecase(algorithm_name, "curve25519") ||
        contains_ignorecase(algorithm_name, "X25519") ||
        contains_ignorecase(algorithm_name, "x25519")) {
        return PQC_TRANSITIONAL;
    }

    // 8d. AES symmetric cipher (quantum-resistant with 256-bit keys)
    if (contains_ignorecase(algorithm_name, "AES")) {
        // AES-256 is quantum-safe, AES-128 needs Grover's → 2x key size
        if (key_size >= 256 || contains_ignorecase(algorithm_name, "256")) {
            return PQC_SAFE;
        }
        return PQC_TRANSITIONAL;  // AES-128/192 still usable
    }

    // 8e. ChaCha20/Salsa20 symmetric ciphers
    if (contains_ignorecase(algorithm_name, "ChaCha20") ||
        contains_ignorecase(algorithm_name, "Salsa20") ||
        contains_ignorecase(algorithm_name, "Camellia")) {
        return PQC_TRANSITIONAL;
    }

    // 8f. Modern hash functions (SHA-2, SHA-3, BLAKE)
    if (contains_ignorecase(algorithm_name, "SHA-256") ||
        contains_ignorecase(algorithm_name, "SHA256") ||
        contains_ignorecase(algorithm_name, "SHA-384") ||
        contains_ignorecase(algorithm_name, "SHA384") ||
        contains_ignorecase(algorithm_name, "SHA-512") ||
        contains_ignorecase(algorithm_name, "SHA512") ||
        contains_ignorecase(algorithm_name, "SHA3") ||
        contains_ignorecase(algorithm_name, "BLAKE")) {
        return PQC_TRANSITIONAL;
    }

    // 9. DH/DHE key exchange (quantum-vulnerable)
    if (contains_ignorecase(algorithm_name, "DH") || contains_ignorecase(algorithm_name, "DHE")) {
        if (key_size >= 2048) {
            return PQC_TRANSITIONAL;
        } else {
            return PQC_UNSAFE;
        }
    }

    // 10. Unknown algorithms - cannot classify
    return PQC_UNKNOWN;
}

pqc_category_t classify_algorithm_metadata_pqc(const algorithm_granular_t* metadata) {
    if (!metadata) return PQC_UNKNOWN;

    return classify_algorithm_pqc_safety(
        metadata->algorithm_name,
        metadata->key_len,
        metadata->primitive_type
    );
}

// === PQC Alternative Suggestions ===

char* suggest_pqc_alternative(
    const char* algorithm_name,
    int key_size,
    crypto_primitive_t primitive_type
) {
    if (!algorithm_name) return NULL;

    char* suggestion = NULL;

    // RSA alternatives (signature and key exchange)
    if (contains_ignorecase(algorithm_name, "RSA")) {
        if (key_size >= 4096) {
            suggestion = strdup("Dilithium-5 (ML-DSA-87)");
        } else if (key_size >= 3072) {
            suggestion = strdup("Dilithium-3 (ML-DSA-65)");
        } else {
            suggestion = strdup("Dilithium-2 (ML-DSA-44)");
        }
        return suggestion;
    }

    // ECDSA alternatives (signature)
    if (contains_ignorecase(algorithm_name, "ECDSA")) {
        if (key_size >= 384) {
            suggestion = strdup("Dilithium-3 (ML-DSA-65)");
        } else if (key_size >= 256) {
            suggestion = strdup("Dilithium-2 (ML-DSA-44)");
        } else {
            suggestion = strdup("Dilithium-2 (ML-DSA-44)");
        }
        return suggestion;
    }

    // Ed25519/Ed448 alternatives (signature)
    if (contains_ignorecase(algorithm_name, "Ed25519")) {
        suggestion = strdup("Dilithium-2 (ML-DSA-44)");
        return suggestion;
    }
    if (contains_ignorecase(algorithm_name, "Ed448")) {
        suggestion = strdup("Dilithium-3 (ML-DSA-65)");
        return suggestion;
    }

    // ECDH/DH alternatives (key exchange)
    if ((contains_ignorecase(algorithm_name, "ECDH") ||
         contains_ignorecase(algorithm_name, "DH")) &&
        primitive_type == PRIMITIVE_KEY_EXCHANGE) {
        if (key_size >= 4096) {
            suggestion = strdup("Kyber-1024 (ML-KEM-1024)");
        } else if (key_size >= 2048) {
            suggestion = strdup("Kyber-768 (ML-KEM-768)");
        } else {
            suggestion = strdup("Kyber-512 (ML-KEM-512)");
        }
        return suggestion;
    }

    // X25519/X448 alternatives (modern key exchange)
    if (contains_ignorecase(algorithm_name, "X25519")) {
        suggestion = strdup("Kyber-768 (ML-KEM-768) or X25519Kyber768 (hybrid)");
        return suggestion;
    }
    if (contains_ignorecase(algorithm_name, "X448")) {
        suggestion = strdup("Kyber-1024 (ML-KEM-1024)");
        return suggestion;
    }

    // DSA alternative
    if (contains_ignorecase(algorithm_name, "DSA") && !contains_ignorecase(algorithm_name, "ECDSA")) {
        suggestion = strdup("Dilithium-3 (ML-DSA-65)");
        return suggestion;
    }

    // Deprecated hash alternatives
    if (contains_ignorecase(algorithm_name, "MD5") || contains_ignorecase(algorithm_name, "SHA1") || contains_ignorecase(algorithm_name, "SHA-1")) {
        suggestion = strdup("SHA-256 or SHA-384");
        return suggestion;
    }

    // Deprecated cipher alternatives
    if (contains_ignorecase(algorithm_name, "RC4") || contains_ignorecase(algorithm_name, "DES")) {
        suggestion = strdup("AES-256-GCM or ChaCha20-Poly1305");
        return suggestion;
    }

    return NULL;  // No suggestion available
}

pqc_urgency_t get_migration_urgency(pqc_category_t category, bool is_deprecated) {
    if (is_deprecated) {
        return URGENCY_CRITICAL;  // Deprecated algorithms need immediate replacement
    }

    switch (category) {
        case PQC_SAFE:
            return URGENCY_LOW;  // Already PQC-safe
        case PQC_TRANSITIONAL:
            return URGENCY_HIGH;  // Quantum-vulnerable but classically strong - plan migration
        case PQC_DEPRECATED:
            return URGENCY_CRITICAL;  // Deprecated - immediate action required
        case PQC_UNSAFE:
            return URGENCY_CRITICAL;  // Unsafe - immediate action required
        case PQC_UNKNOWN:
        default:
            return URGENCY_UNKNOWN;
    }
}

int pqc_get_break_year_estimate(const char* algorithm_name, int key_size) {
    if (!algorithm_name) return 0;

    // Based on NIST IR 8413 + NSA CNSA 2.0 guidance

    // IMPORTANT: Check PQC algorithms FIRST to avoid false matches
    // (e.g., "ML-DSA-65" contains "DSA" but should not match classical DSA)
    if (is_nist_finalized_pqc(algorithm_name)) {
        return 0;  // N/A - quantum-resistant
    }

    // Symmetric algorithms (quantum-resistant with Grover caveat)
    if (contains_ignorecase(algorithm_name, "AES") ||
        contains_ignorecase(algorithm_name, "ChaCha20") ||
        contains_ignorecase(algorithm_name, "SHA-256") ||
        contains_ignorecase(algorithm_name, "SHA-384") ||
        contains_ignorecase(algorithm_name, "SHA-512") ||
        contains_ignorecase(algorithm_name, "SHA3")) {
        return 0;  // N/A - quantum-resistant (with sufficient key/output length)
    }

    // Now check classical algorithms (quantum-vulnerable)

    // RSA algorithms (key-size dependent)
    if (contains_ignorecase(algorithm_name, "RSA")) {
        if (key_size == 0) return 0;       // Can't determine without key size
        if (key_size < 2048) return 2030;  // Already weakened by classical attacks
        if (key_size == 2048) return 2035; // NIST baseline, NSA CNSA 2.0 deadline
        if (key_size == 3072) return 2040; // Conservative estimate, ~3072-bit quantum resistance
        if (key_size >= 4096) return 2045; // Optimistic, assumes slower quantum progress
    }

    // ECDSA/ECDH algorithms (curve-size dependent)
    if (contains_ignorecase(algorithm_name, "ECDSA") ||
        contains_ignorecase(algorithm_name, "ECDH") ||
        contains_ignorecase(algorithm_name, "ECC")) {
        if (key_size <= 256) return 2035;  // P-256: NSA CNSA 2.0 deadline
        if (key_size <= 384) return 2040;  // P-384: Medium-term vulnerable
        if (key_size >= 521) return 2045;  // P-521: Conservative estimate
    }

    // DSA (deprecated, quantum-vulnerable)
    if (contains_ignorecase(algorithm_name, "DSA")) {
        if (key_size < 3072) return 2030;  // Weak DSA
        return 2035;  // Even strong DSA vulnerable by 2035
    }

    // DH (Diffie-Hellman)
    if (contains_ignorecase(algorithm_name, "DH") ||
        contains_ignorecase(algorithm_name, "Diffie-Hellman")) {
        if (key_size < 2048) return 2030;
        if (key_size == 2048) return 2035;
        if (key_size >= 3072) return 2040;
    }

    // Deprecated/weak algorithms (already classically broken or highly vulnerable)
    // Check for specific deprecated algorithms to avoid false matches
    if (contains_ignorecase(algorithm_name, "MD5") ||
        contains_ignorecase(algorithm_name, "RC4") ||
        (contains_ignorecase(algorithm_name, "DES") && !contains_ignorecase(algorithm_name, "3DES"))) {
        return 2030;  // CRITICAL: Migrate immediately
    }

    // SHA-1 specifically (not SHA-256, SHA-384, SHA-512 which are checked above)
    if (contains_ignorecase(algorithm_name, "SHA-1") ||
        (contains_ignorecase(algorithm_name, "SHA1") && !contains_ignorecase(algorithm_name, "SHA-1"))) {
        return 2030;
    }

    return 0;  // Unknown or not quantum-vulnerable
}

// === Comprehensive PQC Assessment ===

pqc_assessment_t* assess_algorithm_pqc(const algorithm_granular_t* metadata) {
    if (!metadata) return NULL;

    pqc_assessment_t* assessment = secure_alloc(sizeof(pqc_assessment_t));
    if (!assessment) return NULL;

    memset(assessment, 0, sizeof(pqc_assessment_t));

    // Classify algorithm
    assessment->category = classify_algorithm_metadata_pqc(metadata);

    // Determine migration urgency
    assessment->urgency = get_migration_urgency(assessment->category, metadata->is_deprecated);

    // Suggest PQC alternative
    assessment->alternative = suggest_pqc_alternative(
        metadata->algorithm_name,
        metadata->key_len,
        metadata->primitive_type
    );

    // Detect hybrid algorithms
    assessment->is_hybrid = detect_hybrid_algorithm(metadata->algorithm_name);

    // Estimate break year for quantum-vulnerable algorithms
    assessment->break_year_estimate = pqc_get_break_year_estimate(
        metadata->algorithm_name,
        metadata->key_len
    );

    // Set confidence based on available information
    if (metadata->algorithm_name && metadata->key_len > 0) {
        assessment->confidence = 0.95f;  // High confidence with full metadata
    } else if (metadata->algorithm_name) {
        assessment->confidence = 0.75f;  // Medium confidence without key size
    } else {
        assessment->confidence = 0.5f;   // Low confidence with minimal info
    }

    // Set source reference
    assessment->source = "NIST IR 8413";

    // Generate rationale
    char rationale_buf[512];
    if (assessment->category == PQC_SAFE) {
        if (is_nist_finalized_pqc(metadata->algorithm_name)) {
            snprintf(rationale_buf, sizeof(rationale_buf),
                    "NIST-finalized post-quantum algorithm");
        } else {
            snprintf(rationale_buf, sizeof(rationale_buf),
                    "Quantum-resistant %s with %d-bit security",
                    metadata->primitive_type == PRIMITIVE_SYMMETRIC_CIPHER ? "symmetric cipher" : "hash function",
                    metadata->key_len);
        }
    } else if (assessment->category == PQC_TRANSITIONAL) {
        snprintf(rationale_buf, sizeof(rationale_buf),
                "Quantum-vulnerable but meets current classical security standards (%d-bit key)",
                metadata->key_len);
    } else if (assessment->category == PQC_DEPRECATED) {
        snprintf(rationale_buf, sizeof(rationale_buf),
                "Deprecated algorithm with known vulnerabilities");
    } else if (assessment->category == PQC_UNSAFE) {
        snprintf(rationale_buf, sizeof(rationale_buf),
                "Quantum-vulnerable with insufficient classical security (%d-bit key)",
                metadata->key_len);
    } else {
        snprintf(rationale_buf, sizeof(rationale_buf),
                "Unable to classify PQC safety");
    }

    assessment->rationale = strdup(rationale_buf);

    return assessment;
}

void pqc_assessment_destroy(pqc_assessment_t* assessment) {
    if (!assessment) return;

    if (assessment->alternative) free(assessment->alternative);
    if (assessment->rationale) free(assessment->rationale);

    secure_free(assessment, sizeof(pqc_assessment_t));
}

// === Readiness Scoring ===

float calculate_asset_pqc_readiness(const crypto_asset_t* asset) {
    if (!asset) return 0.0f;

    // Extract algorithm information from asset
    // For now, use simple heuristic based on asset type and properties

    // Certificates: check signature algorithm
    // Keys: check key type and size
    // Protocols/Cipher suites: check KEX and encryption
    // Libraries: aggregate algorithms

    // TODO: This needs to traverse asset properties to extract algorithm info
    // For now, return neutral score
    return 0.5f;
}

pqc_readiness_score_t pqc_readiness_score_init(void) {
    pqc_readiness_score_t score;
    memset(&score, 0, sizeof(pqc_readiness_score_t));
    return score;
}

void pqc_readiness_score_update(pqc_readiness_score_t* score, pqc_category_t category) {
    if (!score) return;

    score->total_count++;

    switch (category) {
        case PQC_SAFE:
            score->safe_count++;
            break;
        case PQC_TRANSITIONAL:
            score->transitional_count++;
            break;
        case PQC_DEPRECATED:
            score->deprecated_count++;
            break;
        case PQC_UNSAFE:
            score->unsafe_count++;
            break;
        case PQC_UNKNOWN:
        default:
            // Don't increment category counters for unknown
            break;
    }
}

void pqc_readiness_score_finalize(pqc_readiness_score_t* score) {
    if (!score || score->total_count == 0) {
        if (score) score->readiness_score = 0.0f;
        return;
    }

    // Weighted scoring:
    // - PQC_SAFE: 100 points
    // - PQC_TRANSITIONAL: 60 points  (quantum-vulnerable but classically strong)
    // - PQC_DEPRECATED: 20 points    (known vulnerabilities)
    // - PQC_UNSAFE: 0 points         (weak on both fronts)

    float weighted_sum = (
        (score->safe_count * 100.0f) +
        (score->transitional_count * 60.0f) +
        (score->deprecated_count * 20.0f) +
        (score->unsafe_count * 0.0f)
    );

    score->readiness_score = weighted_sum / (float)score->total_count;
}

// === String Conversion Utilities ===

const char* pqc_category_to_string(pqc_category_t category) {
    switch (category) {
        case PQC_SAFE:          return "SAFE";
        case PQC_TRANSITIONAL:  return "TRANSITIONAL";
        case PQC_DEPRECATED:    return "DEPRECATED";
        case PQC_UNSAFE:        return "UNSAFE";
        case PQC_UNKNOWN:       return "UNKNOWN";
        default:                return "UNKNOWN";
    }
}

const char* pqc_urgency_to_string(pqc_urgency_t urgency) {
    switch (urgency) {
        case URGENCY_CRITICAL:  return "CRITICAL";
        case URGENCY_HIGH:      return "HIGH";
        case URGENCY_MEDIUM:    return "MEDIUM";
        case URGENCY_LOW:       return "LOW";
        case URGENCY_UNKNOWN:   return "UNKNOWN";
        default:                return "UNKNOWN";
    }
}

pqc_category_t pqc_category_from_string(const char* str) {
    if (!str) return PQC_UNKNOWN;

    if (strcasecmp(str, "SAFE") == 0) return PQC_SAFE;
    if (strcasecmp(str, "TRANSITIONAL") == 0) return PQC_TRANSITIONAL;
    if (strcasecmp(str, "DEPRECATED") == 0) return PQC_DEPRECATED;
    if (strcasecmp(str, "UNSAFE") == 0) return PQC_UNSAFE;

    return PQC_UNKNOWN;
}

// === Library Algorithm Classification ===

pqc_category_t classify_library_by_algorithms(
    const char** algorithms,
    size_t count,
    char* rationale_out,
    size_t rationale_size
) {
    if (!algorithms || count == 0) {
        if (rationale_out && rationale_size > 0) {
            snprintf(rationale_out, rationale_size,
                    "No implemented algorithms found; unable to assess PQC status");
        }
        return PQC_UNKNOWN;
    }

    pqc_category_t worst_category = PQC_SAFE;  // Start optimistic
    const char* worst_algo = NULL;

    // Track counts for rationale
    int safe_count = 0, transitional_count = 0, deprecated_count = 0, unsafe_count = 0;

    for (size_t i = 0; i < count && algorithms[i] != NULL; i++) {
        const char* algo = algorithms[i];

        // Classify this algorithm
        // For libraries implementing algorithms, assume reasonable default key sizes:
        // - RSA: assume 2048+ (modern libraries support this minimum)
        // - ECDSA/ECC: assume 256+ (P-256 is the minimum modern curve)
        // This prevents marking libraries as UNSAFE just because key size is unknown
        crypto_primitive_t primitive = algorithm_get_primitive_type(algo);
        int assumed_key_size = 0;
        if (contains_ignorecase(algo, "RSA")) {
            assumed_key_size = 2048;  // Assume modern RSA key size
        } else if (contains_ignorecase(algo, "ECDSA") || contains_ignorecase(algo, "EC") ||
                   contains_ignorecase(algo, "P-256") || contains_ignorecase(algo, "P-384") ||
                   contains_ignorecase(algo, "secp")) {
            assumed_key_size = 256;  // Assume P-256 minimum
        }
        pqc_category_t cat = classify_algorithm_pqc_safety(algo, assumed_key_size, primitive);

        switch (cat) {
            case PQC_SAFE: safe_count++; break;
            case PQC_TRANSITIONAL: transitional_count++; break;
            case PQC_DEPRECATED: deprecated_count++; break;
            case PQC_UNSAFE: unsafe_count++; break;
            default: break;
        }

        // Track worst case (higher enum value = worse)
        // Skip UNKNOWN - we only track known classifications for worst-case
        if (cat != PQC_UNKNOWN && (int)cat > (int)worst_category) {
            worst_category = cat;
            worst_algo = algo;
        }
    }

    // Build rationale
    if (rationale_out && rationale_size > 0) {
        if (worst_category == PQC_SAFE) {
            snprintf(rationale_out, rationale_size,
                    "All %zu implemented algorithms are quantum-resistant",
                    count);
        } else {
            snprintf(rationale_out, rationale_size,
                    "Implements %s (%s); %d safe, %d transitional, %d deprecated, %d unsafe of %zu total",
                    worst_algo ? worst_algo : "unknown",
                    pqc_category_to_string(worst_category),
                    safe_count, transitional_count, deprecated_count, unsafe_count,
                    count);
        }
    }

    return worst_category;
}
