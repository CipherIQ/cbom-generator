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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "pqc_classifier.h"
#include "algorithm_metadata.h"
#include "secure_memory.h"

// Test 1: NIST-finalized PQC algorithm detection
static void test_nist_finalized_pqc_detection(void) {
    printf("Testing NIST-finalized PQC algorithm detection...\n");

    // Kyber variants
    assert(is_nist_finalized_pqc("Kyber-768") == true);
    assert(is_nist_finalized_pqc("ML-KEM-512") == true);
    assert(is_nist_finalized_pqc("ML-KEM-768") == true);
    assert(is_nist_finalized_pqc("ml-kem-1024") == true);  // Case insensitive

    // Dilithium variants
    assert(is_nist_finalized_pqc("Dilithium3") == true);
    assert(is_nist_finalized_pqc("ML-DSA-44") == true);
    assert(is_nist_finalized_pqc("ML-DSA-65") == true);
    assert(is_nist_finalized_pqc("dilithium") == true);  // Case insensitive

    // SPHINCS+ variants
    assert(is_nist_finalized_pqc("SPHINCS+-SHA2-128s") == true);
    assert(is_nist_finalized_pqc("sphincs+-shake-256f") == true);  // Case insensitive

    // Classical algorithms (NOT PQC)
    assert(is_nist_finalized_pqc("RSA") == false);
    assert(is_nist_finalized_pqc("ECDSA") == false);
    assert(is_nist_finalized_pqc("AES-256-GCM") == false);

    printf("✓ NIST-finalized PQC algorithm detection tests passed\n");
}

// Test 2: Hybrid algorithm detection
static void test_hybrid_algorithm_detection(void) {
    printf("Testing hybrid algorithm detection...\n");

    // Valid hybrid algorithms
    assert(detect_hybrid_algorithm("X25519Kyber768") == true);
    assert(detect_hybrid_algorithm("X25519-Kyber768") == true);
    assert(detect_hybrid_algorithm("SecP256r1Kyber768") == true);
    assert(detect_hybrid_algorithm("P-256Dilithium") == true);
    assert(detect_hybrid_algorithm("ECDH-Kyber768") == true);

    // Not hybrid (classical only)
    assert(detect_hybrid_algorithm("X25519") == false);
    assert(detect_hybrid_algorithm("ECDH") == false);
    assert(detect_hybrid_algorithm("RSA") == false);

    // Not hybrid (PQC only)
    assert(detect_hybrid_algorithm("Kyber-768") == false);
    assert(detect_hybrid_algorithm("Dilithium3") == false);

    printf("✓ Hybrid algorithm detection tests passed\n");
}

// Test 3: Parse hybrid algorithm components
static void test_parse_hybrid_algorithm(void) {
    printf("Testing hybrid algorithm parsing...\n");

    char classical[64];
    char pqc[64];

    // Test X25519Kyber768
    assert(parse_hybrid_algorithm("X25519Kyber768", classical, pqc) == true);
    assert(strcmp(classical, "X25519") == 0);
    assert(strcmp(pqc, "Kyber-768") == 0);

    // Test SecP256r1 variant
    assert(parse_hybrid_algorithm("SecP256r1Kyber512", classical, pqc) == true);
    assert(strcmp(classical, "SecP256r1") == 0);
    assert(strcmp(pqc, "Kyber-512") == 0);

    // Test ML-KEM variant
    assert(parse_hybrid_algorithm("X25519ML-KEM-768", classical, pqc) == true);
    assert(strcmp(classical, "X25519") == 0);
    assert(strcmp(pqc, "Kyber-768") == 0);

    printf("✓ Hybrid algorithm parsing tests passed\n");
}

// Test 4: PQC classification - SAFE category
static void test_pqc_classification_safe(void) {
    printf("Testing PQC classification - SAFE category...\n");

    // NIST-finalized PQC algorithms
    assert(classify_algorithm_pqc_safety("Kyber-768", 768, PRIMITIVE_KEY_EXCHANGE) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("ML-KEM-512", 512, PRIMITIVE_KEY_EXCHANGE) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("Dilithium3", 0, PRIMITIVE_SIGNATURE) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("ML-DSA-65", 0, PRIMITIVE_SIGNATURE) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("SPHINCS+-SHA2-128s", 0, PRIMITIVE_SIGNATURE) == PQC_SAFE);

    // Quantum-resistant symmetric ciphers
    assert(classify_algorithm_pqc_safety("AES-256-GCM", 256, PRIMITIVE_SYMMETRIC_CIPHER) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("ChaCha20", 256, PRIMITIVE_SYMMETRIC_CIPHER) == PQC_SAFE);

    // Quantum-resistant hash functions
    assert(classify_algorithm_pqc_safety("SHA-256", 256, PRIMITIVE_HASH_FUNCTION) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("SHA-384", 384, PRIMITIVE_HASH_FUNCTION) == PQC_SAFE);
    assert(classify_algorithm_pqc_safety("SHA-512", 512, PRIMITIVE_HASH_FUNCTION) == PQC_SAFE);

    printf("✓ PQC classification SAFE tests passed\n");
}

// Test 5: PQC classification - TRANSITIONAL category
static void test_pqc_classification_transitional(void) {
    printf("Testing PQC classification - TRANSITIONAL category...\n");

    // RSA with sufficient key size
    assert(classify_algorithm_pqc_safety("RSA", 2048, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);
    assert(classify_algorithm_pqc_safety("RSA", 3072, PRIMITIVE_ASYMMETRIC_CIPHER) == PQC_TRANSITIONAL);
    assert(classify_algorithm_pqc_safety("RSA", 4096, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);

    // ECDSA with sufficient key size
    assert(classify_algorithm_pqc_safety("ECDSA", 256, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);
    assert(classify_algorithm_pqc_safety("ECDSA-P256", 256, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);
    assert(classify_algorithm_pqc_safety("ECDSA", 384, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);

    // Ed25519/Ed448
    assert(classify_algorithm_pqc_safety("Ed25519", 256, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);
    assert(classify_algorithm_pqc_safety("Ed448", 448, PRIMITIVE_SIGNATURE) == PQC_TRANSITIONAL);

    // DH with sufficient key size
    assert(classify_algorithm_pqc_safety("DH", 2048, PRIMITIVE_KEY_EXCHANGE) == PQC_TRANSITIONAL);
    assert(classify_algorithm_pqc_safety("DHE", 3072, PRIMITIVE_KEY_EXCHANGE) == PQC_TRANSITIONAL);

    printf("✓ PQC classification TRANSITIONAL tests passed\n");
}

// Test 6: PQC classification - DEPRECATED category
static void test_pqc_classification_deprecated(void) {
    printf("Testing PQC classification - DEPRECATED category...\n");

    // Deprecated hash algorithms
    assert(classify_algorithm_pqc_safety("MD5", 128, PRIMITIVE_HASH_FUNCTION) == PQC_DEPRECATED);
    assert(classify_algorithm_pqc_safety("SHA1", 160, PRIMITIVE_HASH_FUNCTION) == PQC_DEPRECATED);
    assert(classify_algorithm_pqc_safety("SHA-1", 160, PRIMITIVE_HASH_FUNCTION) == PQC_DEPRECATED);

    // Deprecated ciphers
    assert(classify_algorithm_pqc_safety("RC4", 128, PRIMITIVE_SYMMETRIC_CIPHER) == PQC_DEPRECATED);
    assert(classify_algorithm_pqc_safety("DES", 56, PRIMITIVE_SYMMETRIC_CIPHER) == PQC_DEPRECATED);
    assert(classify_algorithm_pqc_safety("3DES", 168, PRIMITIVE_SYMMETRIC_CIPHER) == PQC_DEPRECATED);

    printf("✓ PQC classification DEPRECATED tests passed\n");
}

// Test 7: PQC classification - UNSAFE category
static void test_pqc_classification_unsafe(void) {
    printf("Testing PQC classification - UNSAFE category...\n");

    // RSA with insufficient key size
    assert(classify_algorithm_pqc_safety("RSA", 1024, PRIMITIVE_SIGNATURE) == PQC_UNSAFE);
    assert(classify_algorithm_pqc_safety("RSA", 512, PRIMITIVE_ASYMMETRIC_CIPHER) == PQC_UNSAFE);

    // ECDSA with insufficient key size
    assert(classify_algorithm_pqc_safety("ECDSA", 192, PRIMITIVE_SIGNATURE) == PQC_UNSAFE);
    assert(classify_algorithm_pqc_safety("ECDSA-P192", 192, PRIMITIVE_SIGNATURE) == PQC_UNSAFE);

    // DSA (always unsafe)
    assert(classify_algorithm_pqc_safety("DSA", 2048, PRIMITIVE_SIGNATURE) == PQC_UNSAFE);
    assert(classify_algorithm_pqc_safety("DSA", 3072, PRIMITIVE_SIGNATURE) == PQC_UNSAFE);

    // DH with insufficient key size
    assert(classify_algorithm_pqc_safety("DH", 1024, PRIMITIVE_KEY_EXCHANGE) == PQC_UNSAFE);
    assert(classify_algorithm_pqc_safety("DHE", 512, PRIMITIVE_KEY_EXCHANGE) == PQC_UNSAFE);

    printf("✓ PQC classification UNSAFE tests passed\n");
}

// Test 8: PQC alternative suggestions
static void test_pqc_alternative_suggestions(void) {
    printf("Testing PQC alternative suggestions...\n");

    char* alt;

    // RSA alternatives
    alt = suggest_pqc_alternative("RSA", 2048, PRIMITIVE_SIGNATURE);
    assert(alt != NULL);
    assert(strstr(alt, "Dilithium") != NULL || strstr(alt, "ML-DSA") != NULL);
    free(alt);

    alt = suggest_pqc_alternative("RSA", 4096, PRIMITIVE_SIGNATURE);
    assert(alt != NULL);
    assert(strstr(alt, "Dilithium-5") != NULL || strstr(alt, "ML-DSA-87") != NULL);
    free(alt);

    // ECDSA alternatives
    alt = suggest_pqc_alternative("ECDSA", 256, PRIMITIVE_SIGNATURE);
    assert(alt != NULL);
    assert(strstr(alt, "Dilithium") != NULL || strstr(alt, "ML-DSA") != NULL);
    free(alt);

    // ECDH alternatives (key exchange)
    alt = suggest_pqc_alternative("ECDH", 256, PRIMITIVE_KEY_EXCHANGE);
    assert(alt != NULL);
    assert(strstr(alt, "Kyber") != NULL || strstr(alt, "ML-KEM") != NULL);
    free(alt);

    // X25519 alternative (should suggest hybrid)
    alt = suggest_pqc_alternative("X25519", 256, PRIMITIVE_KEY_EXCHANGE);
    assert(alt != NULL);
    assert(strstr(alt, "Kyber") != NULL || strstr(alt, "hybrid") != NULL);
    free(alt);

    // MD5/SHA1 alternatives
    alt = suggest_pqc_alternative("MD5", 128, PRIMITIVE_HASH_FUNCTION);
    assert(alt != NULL);
    assert(strstr(alt, "SHA-256") != NULL || strstr(alt, "SHA-384") != NULL);
    free(alt);

    alt = suggest_pqc_alternative("SHA1", 160, PRIMITIVE_HASH_FUNCTION);
    assert(alt != NULL);
    assert(strstr(alt, "SHA-256") != NULL);
    free(alt);

    // RC4/DES alternatives
    alt = suggest_pqc_alternative("RC4", 128, PRIMITIVE_SYMMETRIC_CIPHER);
    assert(alt != NULL);
    assert(strstr(alt, "AES-256") != NULL || strstr(alt, "ChaCha20") != NULL);
    free(alt);

    printf("✓ PQC alternative suggestion tests passed\n");
}

// Test 9: Migration urgency levels
static void test_migration_urgency(void) {
    printf("Testing migration urgency levels...\n");

    // SAFE = LOW urgency
    assert(get_migration_urgency(PQC_SAFE, false) == URGENCY_LOW);

    // TRANSITIONAL = HIGH urgency
    assert(get_migration_urgency(PQC_TRANSITIONAL, false) == URGENCY_HIGH);

    // DEPRECATED = CRITICAL urgency
    assert(get_migration_urgency(PQC_DEPRECATED, false) == URGENCY_CRITICAL);

    // UNSAFE = CRITICAL urgency
    assert(get_migration_urgency(PQC_UNSAFE, false) == URGENCY_CRITICAL);

    // Any deprecated algorithm = CRITICAL (overrides category)
    assert(get_migration_urgency(PQC_SAFE, true) == URGENCY_CRITICAL);
    assert(get_migration_urgency(PQC_TRANSITIONAL, true) == URGENCY_CRITICAL);

    printf("✓ Migration urgency tests passed\n");
}

// Test 10: Comprehensive PQC assessment
static void test_comprehensive_assessment(void) {
    printf("Testing comprehensive PQC assessment...\n");

    // Create algorithm metadata for RSA-2048
    algorithm_granular_t* metadata = algorithm_metadata_create();
    assert(metadata != NULL);

    metadata->algorithm_name = strdup("RSA");
    metadata->key_len = 2048;
    metadata->primitive_type = PRIMITIVE_SIGNATURE;
    metadata->is_deprecated = false;

    // Perform assessment
    pqc_assessment_t* assessment = assess_algorithm_pqc(metadata);
    assert(assessment != NULL);
    assert(assessment->category == PQC_TRANSITIONAL);
    assert(assessment->urgency == URGENCY_HIGH);
    assert(assessment->alternative != NULL);
    assert(strstr(assessment->alternative, "Dilithium") != NULL);
    assert(assessment->rationale != NULL);
    assert(assessment->confidence > 0.9f);
    assert(assessment->is_hybrid == false);
    assert(strcmp(assessment->source, "NIST IR 8413") == 0);

    pqc_assessment_destroy(assessment);
    algorithm_metadata_destroy(metadata);

    printf("✓ Comprehensive assessment tests passed\n");
}

// Test 11: Readiness scoring
static void test_readiness_scoring(void) {
    printf("Testing PQC readiness scoring...\n");

    pqc_readiness_score_t score = pqc_readiness_score_init();
    assert(score.total_count == 0);
    assert(score.safe_count == 0);
    assert(score.transitional_count == 0);
    assert(score.deprecated_count == 0);
    assert(score.unsafe_count == 0);
    assert(score.readiness_score == 0.0f);

    // Add various algorithms
    pqc_readiness_score_update(&score, PQC_SAFE);       // 100 points
    pqc_readiness_score_update(&score, PQC_SAFE);       // 100 points
    pqc_readiness_score_update(&score, PQC_TRANSITIONAL);  // 60 points
    pqc_readiness_score_update(&score, PQC_DEPRECATED);    // 20 points
    pqc_readiness_score_update(&score, PQC_UNSAFE);        // 0 points

    assert(score.total_count == 5);
    assert(score.safe_count == 2);
    assert(score.transitional_count == 1);
    assert(score.deprecated_count == 1);
    assert(score.unsafe_count == 1);

    // Finalize score
    pqc_readiness_score_finalize(&score);

    // Expected: (100 + 100 + 60 + 20 + 0) / 5 = 280 / 5 = 56.0
    assert(score.readiness_score >= 55.0f && score.readiness_score <= 57.0f);

    printf("✓ Readiness scoring tests passed (score: %.1f%%)\n", score.readiness_score);
}

// Test 12: String conversion utilities
static void test_string_conversion(void) {
    printf("Testing string conversion utilities...\n");

    // Category to string
    assert(strcmp(pqc_category_to_string(PQC_SAFE), "SAFE") == 0);
    assert(strcmp(pqc_category_to_string(PQC_TRANSITIONAL), "TRANSITIONAL") == 0);
    assert(strcmp(pqc_category_to_string(PQC_DEPRECATED), "DEPRECATED") == 0);
    assert(strcmp(pqc_category_to_string(PQC_UNSAFE), "UNSAFE") == 0);
    assert(strcmp(pqc_category_to_string(PQC_UNKNOWN), "UNKNOWN") == 0);

    // Urgency to string
    assert(strcmp(pqc_urgency_to_string(URGENCY_CRITICAL), "CRITICAL") == 0);
    assert(strcmp(pqc_urgency_to_string(URGENCY_HIGH), "HIGH") == 0);
    assert(strcmp(pqc_urgency_to_string(URGENCY_MEDIUM), "MEDIUM") == 0);
    assert(strcmp(pqc_urgency_to_string(URGENCY_LOW), "LOW") == 0);

    // String to category
    assert(pqc_category_from_string("SAFE") == PQC_SAFE);
    assert(pqc_category_from_string("safe") == PQC_SAFE);  // Case insensitive
    assert(pqc_category_from_string("TRANSITIONAL") == PQC_TRANSITIONAL);
    assert(pqc_category_from_string("DEPRECATED") == PQC_DEPRECATED);
    assert(pqc_category_from_string("UNSAFE") == PQC_UNSAFE);
    assert(pqc_category_from_string("UNKNOWN") == PQC_UNKNOWN);
    assert(pqc_category_from_string("invalid") == PQC_UNKNOWN);

    printf("✓ String conversion tests passed\n");
}

// Test 14: Break year estimation (NEW - v1.2)
static void test_break_year_estimation(void) {
    printf("Testing break year estimation...\n");

    // RSA key size variations
    assert(pqc_get_break_year_estimate("RSA", 1024) == 2030);
    assert(pqc_get_break_year_estimate("RSA", 2048) == 2035);
    assert(pqc_get_break_year_estimate("RSA", 3072) == 2040);
    assert(pqc_get_break_year_estimate("RSA", 4096) == 2045);

    // ECDSA variations
    assert(pqc_get_break_year_estimate("ECDSA", 256) == 2035);
    assert(pqc_get_break_year_estimate("ECDSA", 384) == 2040);
    assert(pqc_get_break_year_estimate("ECDSA", 521) == 2045);

    // ECDH variations
    assert(pqc_get_break_year_estimate("ECDH", 256) == 2035);
    assert(pqc_get_break_year_estimate("ECDH", 384) == 2040);

    // Deprecated algorithms (CRITICAL - 2030)
    assert(pqc_get_break_year_estimate("MD5", 128) == 2030);
    assert(pqc_get_break_year_estimate("SHA-1", 160) == 2030);
    assert(pqc_get_break_year_estimate("RC4", 128) == 2030);
    assert(pqc_get_break_year_estimate("DES", 56) == 2030);

    // PQC-safe algorithms (no break year)
    assert(pqc_get_break_year_estimate("ML-KEM-768", 0) == 0);
    assert(pqc_get_break_year_estimate("ML-DSA-65", 0) == 0);
    assert(pqc_get_break_year_estimate("Kyber-768", 0) == 0);
    assert(pqc_get_break_year_estimate("Dilithium-3", 0) == 0);

    // Symmetric algorithms (quantum-resistant)
    assert(pqc_get_break_year_estimate("AES-256", 256) == 0);
    assert(pqc_get_break_year_estimate("ChaCha20", 256) == 0);
    assert(pqc_get_break_year_estimate("SHA-256", 256) == 0);

    printf("✓ Break year estimation tests passed\n");
}

// Test 15: Assessment with break years (NEW - v1.2)
static void test_assessment_with_break_years(void) {
    printf("Testing full assessment includes break years...\n");

    // RSA-2048: TRANSITIONAL with break year 2035
    algorithm_granular_t* rsa2048 = algorithm_metadata_create();
    assert(rsa2048 != NULL);
    rsa2048->algorithm_name = strdup("RSA");
    rsa2048->key_len = 2048;
    rsa2048->primitive_type = PRIMITIVE_SIGNATURE;

    pqc_assessment_t* assessment = assess_algorithm_pqc(rsa2048);
    assert(assessment != NULL);
    assert(assessment->category == PQC_TRANSITIONAL);
    assert(assessment->break_year_estimate == 2035);
    assert(assessment->urgency == URGENCY_HIGH);

    pqc_assessment_destroy(assessment);
    algorithm_metadata_destroy(rsa2048);

    // RSA-1024: UNSAFE with break year 2030
    algorithm_granular_t* rsa1024 = algorithm_metadata_create();
    assert(rsa1024 != NULL);
    rsa1024->algorithm_name = strdup("RSA");
    rsa1024->key_len = 1024;
    rsa1024->primitive_type = PRIMITIVE_SIGNATURE;

    assessment = assess_algorithm_pqc(rsa1024);
    assert(assessment != NULL);
    assert(assessment->category == PQC_UNSAFE);
    assert(assessment->break_year_estimate == 2030);
    assert(assessment->urgency == URGENCY_CRITICAL);

    pqc_assessment_destroy(assessment);
    algorithm_metadata_destroy(rsa1024);

    // ML-KEM-768: SAFE with no break year
    algorithm_granular_t* kyber = algorithm_metadata_create();
    assert(kyber != NULL);
    kyber->algorithm_name = strdup("Kyber-768");
    kyber->key_len = 768;
    kyber->primitive_type = PRIMITIVE_KEY_EXCHANGE;

    assessment = assess_algorithm_pqc(kyber);
    assert(assessment != NULL);
    assert(assessment->category == PQC_SAFE);
    assert(assessment->break_year_estimate == 0);

    pqc_assessment_destroy(assessment);
    algorithm_metadata_destroy(kyber);

    printf("✓ Assessment with break years tests passed\n");
}

// Test 16: Edge cases (NEW - v1.2)
static void test_edge_cases(void) {
    printf("Testing edge cases...\n");

    // Mixed key sizes (same algorithm, different break years)
    assert(pqc_get_break_year_estimate("RSA", 2048) != pqc_get_break_year_estimate("RSA", 4096));
    assert(pqc_get_break_year_estimate("RSA", 2048) == 2035);
    assert(pqc_get_break_year_estimate("RSA", 4096) == 2045);

    // Unknown algorithm (graceful handling)
    assert(pqc_get_break_year_estimate("UnknownAlgo", 0) == 0);
    assert(pqc_get_break_year_estimate("FakeAlgorithm", 2048) == 0);

    // NULL algorithm name
    assert(pqc_get_break_year_estimate(NULL, 2048) == 0);

    // Zero key size for RSA (should return 0 since we can't determine)
    assert(pqc_get_break_year_estimate("RSA", 0) == 0);

    // Edge case: exactly at threshold
    assert(pqc_get_break_year_estimate("ECDSA", 256) == 2035);
    assert(pqc_get_break_year_estimate("ECDSA", 384) == 2040);
    assert(pqc_get_break_year_estimate("ECDSA", 521) == 2045);

    printf("✓ Edge case tests passed\n");
}

// Main test runner
int main(void) {
    printf("=== PQC Classifier Test Suite ===\n\n");

    // Initialize secure memory subsystem
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory subsystem\n");
        return 1;
    }

    // Run all tests
    test_nist_finalized_pqc_detection();
    test_hybrid_algorithm_detection();
    test_parse_hybrid_algorithm();
    test_pqc_classification_safe();
    test_pqc_classification_transitional();
    test_pqc_classification_deprecated();
    test_pqc_classification_unsafe();
    test_pqc_alternative_suggestions();
    test_migration_urgency();
    test_comprehensive_assessment();
    test_readiness_scoring();
    test_string_conversion();

    // NEW: v1.2 break year estimation tests
    test_break_year_estimation();
    test_assessment_with_break_years();
    test_edge_cases();

    // Cleanup
    secure_memory_cleanup();

    printf("\n=== All PQC Classifier Tests Passed ===\n");
    printf("Total: 15 test suites\n");
    printf("\n✅ Phase 8.0 Step 1 & 2 Acceptance Criteria VERIFIED:\n");
    printf("  ✅ NIST-finalized algorithm detection works\n");
    printf("  ✅ PQC safety classification works (4 categories)\n");
    printf("  ✅ Hybrid algorithm detection works\n");
    printf("  ✅ PQC alternative suggestions work\n");
    printf("  ✅ Migration urgency levels work\n");
    printf("  ✅ Readiness scoring works\n");

    return 0;
}
