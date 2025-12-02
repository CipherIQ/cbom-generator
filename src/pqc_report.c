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
#include "pqc_report.h"
#include "pqc_classifier.h"
#include "cbom_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Assessment statistics structure
typedef struct {
    int total_assets;
    int pqc_safe;
    int transitional;
    int deprecated;
    int unsafe;
    int unknown;
    int hybrid;

    // By asset type
    int vulnerable_certificates;
    int vulnerable_keys;
    int vulnerable_algorithms;

    // By break year
    int break_2030;
    int break_2035;
    int break_2040;
    int break_2045;
} pqc_assessment_stats_t;

/**
 * Analyze asset store and gather PQC statistics
 */
static pqc_assessment_stats_t analyze_pqc_readiness(asset_store_t* store) {
    pqc_assessment_stats_t stats = {0};

    if (!store) return stats;

    size_t asset_count = 0;
    crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &asset_count);

    if (!assets) return stats;

    stats.total_assets = asset_count;

    for (size_t i = 0; i < asset_count; i++) {
        crypto_asset_t* asset = assets[i];
        if (!asset) continue;

        const char* algo_name = asset->algorithm ? asset->algorithm : asset->name;
        if (!algo_name || algo_name[0] == '\0') continue;

        // Classify algorithm
        pqc_category_t category = classify_algorithm_pqc_safety(algo_name, asset->key_size, PRIMITIVE_UNKNOWN);

        // Count by category
        switch (category) {
            case PQC_SAFE:
                stats.pqc_safe++;
                break;
            case PQC_TRANSITIONAL:
                stats.transitional++;
                if (asset->type == ASSET_TYPE_CERTIFICATE) stats.vulnerable_certificates++;
                else if (asset->type == ASSET_TYPE_KEY) stats.vulnerable_keys++;
                else if (asset->type == ASSET_TYPE_ALGORITHM) stats.vulnerable_algorithms++;
                break;
            case PQC_DEPRECATED:
                stats.deprecated++;
                if (asset->type == ASSET_TYPE_CERTIFICATE) stats.vulnerable_certificates++;
                else if (asset->type == ASSET_TYPE_KEY) stats.vulnerable_keys++;
                else if (asset->type == ASSET_TYPE_ALGORITHM) stats.vulnerable_algorithms++;
                break;
            case PQC_UNSAFE:
                stats.unsafe++;
                if (asset->type == ASSET_TYPE_CERTIFICATE) stats.vulnerable_certificates++;
                else if (asset->type == ASSET_TYPE_KEY) stats.vulnerable_keys++;
                else if (asset->type == ASSET_TYPE_ALGORITHM) stats.vulnerable_algorithms++;
                break;
            default:
                stats.unknown++;
                break;
        }

        // Count hybrid algorithms
        if (detect_hybrid_algorithm(algo_name)) {
            stats.hybrid++;
        }

        // Count by break year
        int break_year = pqc_get_break_year_estimate(algo_name, asset->key_size);
        if (break_year == 2030) stats.break_2030++;
        else if (break_year == 2035) stats.break_2035++;
        else if (break_year == 2040) stats.break_2040++;
        else if (break_year >= 2045) stats.break_2045++;
    }

    free(assets);
    return stats;
}

int pqc_generate_migration_report(asset_store_t* store, FILE* output) {
    if (!store || !output) return -1;

    pqc_assessment_stats_t stats = analyze_pqc_readiness(store);

    // Header
    fprintf(output, "═══════════════════════════════════════════════════════════════\n");
    fprintf(output, "       POST-QUANTUM CRYPTOGRAPHY MIGRATION REPORT\n");
    fprintf(output, "═══════════════════════════════════════════════════════════════\n\n");

    // Timestamp
    time_t now = time(NULL);
    struct tm* tm_info = gmtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", tm_info);
    fprintf(output, "Generated: %s\n", timestamp);
    fprintf(output, "Standards: NIST IR 8413, NSA CNSA 2.0, FIPS 203/204/205\n\n");

    // Executive Summary
    fprintf(output, "EXECUTIVE SUMMARY\n");
    fprintf(output, "─────────────────\n");
    fprintf(output, "Total Cryptographic Assets: %d\n", stats.total_assets);

    int total_vulnerable = stats.transitional + stats.deprecated + stats.unsafe;
    float vulnerable_pct = stats.total_assets > 0 ? (total_vulnerable * 100.0f) / stats.total_assets : 0.0f;
    float safe_pct = stats.total_assets > 0 ? (stats.pqc_safe * 100.0f) / stats.total_assets : 0.0f;

    fprintf(output, "PQC-Safe Assets: %d (%.1f%%)\n", stats.pqc_safe, safe_pct);
    fprintf(output, "Quantum-Vulnerable Assets: %d (%.1f%%)\n", total_vulnerable, vulnerable_pct);
    fprintf(output, "Hybrid Deployments: %d\n\n", stats.hybrid);

    // Vulnerability Breakdown by Break Year
    fprintf(output, "VULNERABILITY BREAKDOWN BY BREAK YEAR\n");
    fprintf(output, "──────────────────────────────────────\n");
    fprintf(output, "🚨 CRITICAL (Break by 2030):   %4d assets  [IMMEDIATE ACTION]\n", stats.break_2030);
    fprintf(output, "   └─ MD5, SHA-1, RC4, DES, RSA-1024 (already weakened classically)\n\n");

    fprintf(output, "⚠️  HIGH (Break by 2035):       %4d assets  [PLAN MIGRATION NOW]\n", stats.break_2035);
    fprintf(output, "   └─ RSA-2048, ECDSA-P256, ECDH-P256 (NIST baseline, NSA CNSA 2.0 deadline)\n\n");

    fprintf(output, "⚡ MEDIUM (Break by 2040):     %4d assets  [MONITOR CLOSELY]\n", stats.break_2040);
    fprintf(output, "   └─ RSA-3072, ECDSA-P384 (conservative estimate)\n\n");

    fprintf(output, "ℹ️  LOW (Break by 2045+):       %4d assets  [LONG-TERM PLAN]\n", stats.break_2045);
    fprintf(output, "   └─ RSA-4096, ECDSA-P521 (optimistic, slower quantum progress)\n\n");

    // Vulnerable Assets by Type
    fprintf(output, "VULNERABLE ASSETS BY TYPE\n");
    fprintf(output, "─────────────────────────\n");
    fprintf(output, "Certificates: %d\n", stats.vulnerable_certificates);
    fprintf(output, "Private Keys: %d\n", stats.vulnerable_keys);
    fprintf(output, "Algorithms:   %d\n\n", stats.vulnerable_algorithms);

    // Migration Priority Timeline
    fprintf(output, "MIGRATION PRIORITY TIMELINE\n");
    fprintf(output, "────────────────────────────\n");
    fprintf(output, "2024-2027: Pilot PQC deployments, migrate CRITICAL assets (%d by 2030)\n", stats.break_2030);
    fprintf(output, "2027-2030: Phase 1 migration complete\n");
    fprintf(output, "2030-2035: Phase 2 migration (%d assets by 2035)\n", stats.break_2035);
    fprintf(output, "2035-2040: Phase 3 migration (%d assets by 2040)\n", stats.break_2040);
    fprintf(output, "2040-2045: Phase 4 migration (%d assets by 2045)\n\n", stats.break_2045);

    // NIST Standards Reference
    fprintf(output, "NIST PQC STANDARDS\n");
    fprintf(output, "──────────────────\n");
    fprintf(output, "• FIPS 203: Module-Lattice-Based Key-Encapsulation (ML-KEM)\n");
    fprintf(output, "  └─ ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5)\n\n");

    fprintf(output, "• FIPS 204: Module-Lattice-Based Digital Signatures (ML-DSA)\n");
    fprintf(output, "  └─ ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), ML-DSA-87 (Level 5)\n\n");

    fprintf(output, "• FIPS 205: Stateless Hash-Based Digital Signatures (SLH-DSA)\n");
    fprintf(output, "  └─ SLH-DSA-SHA2 variants (Levels 1, 3, 5)\n\n");

    // Recommendations
    fprintf(output, "RECOMMENDATIONS\n");
    fprintf(output, "───────────────\n");

    if (stats.break_2030 > 0) {
        fprintf(output, "1. 🚨 URGENT: Migrate %d critical assets before 2030\n", stats.break_2030);
        fprintf(output, "   • Replace MD5/SHA-1 with SHA-256 or SHA3-256\n");
        fprintf(output, "   • Retire RSA-1024 immediately (vulnerable to classical attacks)\n");
        fprintf(output, "   • Replace RC4, DES, 3DES with AES-256-GCM\n");
        fprintf(output, "   • These are CRITICAL - already vulnerable to classical attacks\n\n");
    }

    if (stats.break_2035 > 0) {
        fprintf(output, "%d. ⚠️  HIGH PRIORITY: Plan migration for %d assets (2030-2035)\n",
                stats.break_2030 > 0 ? 2 : 1, stats.break_2035);
        fprintf(output, "   • RSA-2048 → ML-DSA-65 (Dilithium3)\n");
        fprintf(output, "   • ECDSA-P256 → ML-DSA-65 (Dilithium3)\n");
        fprintf(output, "   • ECDH-P256 → ML-KEM-768 (Kyber768)\n");
        fprintf(output, "   • NSA CNSA 2.0 deadline: 2035\n\n");
    }

    if (stats.break_2040 > 0 || stats.break_2045 > 0) {
        int next_num = (stats.break_2030 > 0 ? 2 : 1) + (stats.break_2035 > 0 ? 1 : 0);
        fprintf(output, "%d. ⚡ MEDIUM-TERM: Prepare migration for %d assets (2035-2045)\n",
                next_num, stats.break_2040 + stats.break_2045);
        fprintf(output, "   • RSA-3072/4096 → ML-DSA-87 (Dilithium5)\n");
        fprintf(output, "   • ECDSA-P384/P521 → ML-DSA-87 (Dilithium5)\n");
        fprintf(output, "   • Monitor quantum computing progress\n\n");
    }

    int rec_num = 1 + (stats.break_2030 > 0 ? 1 : 0) + (stats.break_2035 > 0 ? 1 : 0) +
                  ((stats.break_2040 > 0 || stats.break_2045 > 0) ? 1 : 0);

    fprintf(output, "%d. 🔄 TRANSITIONAL: Consider hybrid modes for gradual migration\n", rec_num);
    fprintf(output, "   • X25519-ML-KEM-768 for key exchange\n");
    fprintf(output, "   • P256-ML-DSA-65 for signatures\n");
    fprintf(output, "   • Maintains backward compatibility while adding quantum resistance\n\n");

    rec_num++;
    fprintf(output, "%d. 📚 RESOURCES:\n", rec_num);
    fprintf(output, "   • NIST PQC Project:\n");
    fprintf(output, "     https://csrc.nist.gov/projects/post-quantum-cryptography\n");
    fprintf(output, "   • CISA Post-Quantum Cryptography Initiative:\n");
    fprintf(output, "     https://www.cisa.gov/quantum\n");
    fprintf(output, "   • NSA CNSA 2.0 Suite:\n");
    fprintf(output, "     https://media.defense.gov/2022/Sep/07/2003071834\n\n");

    // Summary Statistics
    fprintf(output, "SUMMARY STATISTICS\n");
    fprintf(output, "──────────────────\n");
    fprintf(output, "├─ Total Assets:        %d\n", stats.total_assets);
    fprintf(output, "├─ PQC-Safe:            %d (%.1f%%)\n", stats.pqc_safe, safe_pct);
    fprintf(output, "├─ Transitional:        %d (%.1f%%)\n", stats.transitional,
            stats.total_assets > 0 ? (stats.transitional * 100.0f) / stats.total_assets : 0.0f);
    fprintf(output, "├─ Deprecated:          %d (%.1f%%)\n", stats.deprecated,
            stats.total_assets > 0 ? (stats.deprecated * 100.0f) / stats.total_assets : 0.0f);
    fprintf(output, "├─ Unsafe:              %d (%.1f%%)\n", stats.unsafe,
            stats.total_assets > 0 ? (stats.unsafe * 100.0f) / stats.total_assets : 0.0f);
    fprintf(output, "└─ Hybrid:              %d\n\n", stats.hybrid);

    // Assessment Matrix
    fprintf(output, "RISK ASSESSMENT MATRIX\n");
    fprintf(output, "──────────────────────\n");
    fprintf(output, "┌─────────────────┬──────────┬─────────────────────────┐\n");
    fprintf(output, "│ Break Year      │ Assets   │ Priority Level          │\n");
    fprintf(output, "├─────────────────┼──────────┼─────────────────────────┤\n");
    fprintf(output, "│ 2030 (CRITICAL) │ %8d │ IMMEDIATE ACTION        │\n", stats.break_2030);
    fprintf(output, "│ 2035 (HIGH)     │ %8d │ PLAN NOW                │\n", stats.break_2035);
    fprintf(output, "│ 2040 (MEDIUM)   │ %8d │ MONITOR CLOSELY         │\n", stats.break_2040);
    fprintf(output, "│ 2045+ (LOW)     │ %8d │ LONG-TERM PLANNING      │\n", stats.break_2045);
    fprintf(output, "└─────────────────┴──────────┴─────────────────────────┘\n\n");

    // Readiness Score
    int total_classified = stats.pqc_safe + stats.transitional + stats.deprecated + stats.unsafe;
    float readiness_score = 0.0f;
    if (total_classified > 0) {
        readiness_score = ((stats.pqc_safe * 100.0f) +
                          (stats.transitional * 60.0f) +
                          (stats.deprecated * 20.0f) +
                          (stats.unsafe * 0.0f)) / total_classified;
    }

    fprintf(output, "PQC READINESS SCORE\n");
    fprintf(output, "───────────────────\n");
    fprintf(output, "Overall Score: %.1f / 100\n", readiness_score);

    if (readiness_score >= 80.0f) {
        fprintf(output, "Rating: ⭐⭐⭐⭐⭐ EXCELLENT - Strong PQC readiness\n");
    } else if (readiness_score >= 60.0f) {
        fprintf(output, "Rating: ⭐⭐⭐⭐ GOOD - Acceptable PQC readiness\n");
    } else if (readiness_score >= 40.0f) {
        fprintf(output, "Rating: ⭐⭐⭐ MODERATE - Significant migration needed\n");
    } else if (readiness_score >= 20.0f) {
        fprintf(output, "Rating: ⭐⭐ POOR - Urgent migration required\n");
    } else {
        fprintf(output, "Rating: ⭐ CRITICAL - Immediate action required\n");
    }
    fprintf(output, "\n");

    // Migration Action Plan
    fprintf(output, "MIGRATION ACTION PLAN\n");
    fprintf(output, "─────────────────────\n");

    if (stats.break_2030 > 0) {
        fprintf(output, "PHASE 0 (2024-2027): CRITICAL ASSETS\n");
        fprintf(output, "  ├─ Scope: %d assets requiring immediate migration\n", stats.break_2030);
        fprintf(output, "  ├─ Timeline: Complete by 2027\n");
        fprintf(output, "  ├─ Actions:\n");
        fprintf(output, "  │  • Audit all MD5, SHA-1, RC4, DES usage\n");
        fprintf(output, "  │  • Replace with SHA-256, AES-256-GCM\n");
        fprintf(output, "  │  • Retire RSA-1024 certificates and keys\n");
        fprintf(output, "  └─ Priority: 🚨 CRITICAL\n\n");
    }

    if (stats.break_2035 > 0) {
        fprintf(output, "PHASE 1 (2027-2030): HIGH PRIORITY ASSETS\n");
        fprintf(output, "  ├─ Scope: %d assets (RSA-2048, ECDSA-P256)\n", stats.break_2035);
        fprintf(output, "  ├─ Timeline: Complete by 2030\n");
        fprintf(output, "  ├─ Actions:\n");
        fprintf(output, "  │  • Deploy hybrid RSA-2048 + ML-DSA-65\n");
        fprintf(output, "  │  • Transition ECDH-P256 to X25519-ML-KEM-768\n");
        fprintf(output, "  │  • Update certificate issuance to PQC algorithms\n");
        fprintf(output, "  └─ Priority: ⚠️  HIGH\n\n");
    }

    if (stats.break_2040 > 0) {
        fprintf(output, "PHASE 2 (2030-2035): MEDIUM PRIORITY ASSETS\n");
        fprintf(output, "  ├─ Scope: %d assets (RSA-3072, ECDSA-P384)\n", stats.break_2040);
        fprintf(output, "  ├─ Timeline: Complete by 2035\n");
        fprintf(output, "  ├─ Actions:\n");
        fprintf(output, "  │  • Migrate to ML-DSA-87 (Dilithium5)\n");
        fprintf(output, "  │  • Monitor quantum computing advances\n");
        fprintf(output, "  └─ Priority: ⚡ MEDIUM\n\n");
    }

    if (stats.break_2045 > 0) {
        fprintf(output, "PHASE 3 (2035-2040): LOW PRIORITY ASSETS\n");
        fprintf(output, "  ├─ Scope: %d assets (RSA-4096, ECDSA-P521)\n", stats.break_2045);
        fprintf(output, "  ├─ Timeline: Complete by 2040\n");
        fprintf(output, "  ├─ Actions:\n");
        fprintf(output, "  │  • Long-term planning for final migration\n");
        fprintf(output, "  │  • Continue monitoring quantum threats\n");
        fprintf(output, "  └─ Priority: ℹ️  LOW\n\n");
    }

    // Key Milestones
    fprintf(output, "KEY MILESTONES\n");
    fprintf(output, "──────────────────\n");
    fprintf(output, "2024-2025: Inventory and assessment (CURRENT)\n");
    fprintf(output, "2025-2027: Pilot PQC deployments in non-critical systems\n");
    fprintf(output, "2027-2030: Production migration of critical assets\n");
    fprintf(output, "2030:      NSA recommends PQC transition complete\n");
    fprintf(output, "2035:      NSA CNSA 2.0 deadline for quantum-vulnerable algorithms\n");
    fprintf(output, "2040-2045: Complete remaining long-term migrations\n\n");

    // Testing and Validation
    fprintf(output, "TESTING & VALIDATION\n");
    fprintf(output, "────────────────────\n");
    fprintf(output, "Before deploying PQC algorithms:\n");
    fprintf(output, "  1. Verify interoperability with existing systems\n");
    fprintf(output, "  2. Performance test on production-like workloads\n");
    fprintf(output, "  3. Validate certificate chain with PQC root CAs\n");
    fprintf(output, "  4. Test hybrid mode fallback to classical algorithms\n");
    fprintf(output, "  5. Monitor for PQC-specific vulnerabilities and updates\n\n");

    // Compliance and Governance
    fprintf(output, "COMPLIANCE & GOVERNANCE\n");
    fprintf(output, "───────────────────────\n");
    fprintf(output, "Regulatory Requirements:\n");
    fprintf(output, "  • NIST SP 800-131A: Transition away from deprecated algorithms\n");
    fprintf(output, "  • NSA CNSA 2.0: Quantum-resistant algorithms by 2035\n");
    fprintf(output, "  • FIPS 140-3: Approved PQC algorithms in cryptographic modules\n");
    fprintf(output, "  • Industry Standards: Monitor sector-specific PQC requirements\n\n");

    // Footer
    fprintf(output, "═══════════════════════════════════════════════════════════════\n");
    fprintf(output, "END OF REPORT\n");
    fprintf(output, "═══════════════════════════════════════════════════════════════\n");
    fprintf(output, "\n");
    fprintf(output, "For detailed asset-level analysis, see CBOM JSON output.\n");
    fprintf(output, "Generated by cbom-generator\n");
    fprintf(output, "\n");

    return 0;
}
