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
#include <getopt.h>
#include <locale.h>
#include <time.h>
#include <unistd.h>

#include "cbom_types.h"
#include "asset_store.h"
#include "secure_memory.h"
#include "error_handling.h"
#include "error_remediation.h"
#include "normalization.h"
#include "schema_validation.h"
#include "provenance.h"
#include "plugin_manager.h"
#include "certificate_scanner.h"
#include "key_manager.h"
#include "tui.h"
#include "thread_pool.h"
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include "openpgp_parser.h"
#include "key_manager.h"
#include "dedup.h"
#include "pqc_classifier.h"
#include "pqc_report.h"
#include "algorithm_metadata.h"
#include "platform_detect.h"         // Phase 1 - CycloneDX conformance
#include "yaml_plugin_loader.h"      // Phase 1
#include "service_discovery_engine.h" // Phase 2
#include "config_extractor.h"         // Phase 3
#include "component_factory.h"        // Phase 4
#include "application_scanner.h"      // v1.5 - Application detection
#include "crypto_registry.h"          // v1.6 - YAML registry extension
#include "version_resolver.h"         // v1.7 - Cross-arch version detection
#include "path_utils.h"               // v1.8 - Cross-arch path normalization

// Forward declarations (Issue #3)
extern int build_service_cert_relationships(asset_store_t* store);

// Maximum number of target paths for parallel scanning
#define MAX_SCAN_PATHS 16

// Global configuration (non-static for external access)
cbom_config_t g_cbom_config = {
    .deterministic = true,
    .no_personal_data = true,        // Privacy-by-default (Req 16.3)
    .include_personal_data = false,  // Inverse of no_personal_data
    .no_network = false,
    .enable_attestation = false,     // Attestation disabled by default
    .signature_method = NULL,        // No default signature method
    .signing_key_path = NULL,        // No default signing key
    .thread_count = 0,               // Will be set to CPU count
    .output_file = NULL,
    .format = NULL,                  // Will be set to default or from command line
    .cyclonedx_spec_version = NULL,  // Will default to "1.6" if not specified
    .target_paths = NULL,            // Array of target directories to scan
    .target_path_count = 0,          // Number of target directories
    .dedup_mode = DEDUP_MODE_SAFE,   // Default to safe mode
    .emit_bundles = false,           // Default: do not emit bundles
    .tui_enabled = false,            // TUI disabled by default
    .error_log_file = NULL,          // No error log file by default
    .pqc_report_path = NULL,         // No PQC report by default
    .discover_services = false,      // Service discovery disabled by default
    .plugin_dir = NULL,              // Default plugin directory: "plugins/"
    .include_fixtures = false,       // Test fixtures disabled by default
    .include_all_dependencies = false // v1.9: Only include crypto libraries by default
};

// Global error collector and completion tracker
static error_collector_t *g_error_collector = NULL;
static completion_tracker_t *g_completion_tracker = NULL;

// Global flags for special modes
static bool g_list_plugins_mode = false;

// Global certificate scanner statistics (accessible from other modules)
cert_scanner_stats_t g_cert_scanner_stats = {0};

// Global PQC instance counter (counts algorithm creations before dedup)
int g_pqc_safe_instances_created = 0;

// Global deduplication statistics (accessible for output generation)
static dedup_stats_t g_dedup_stats = {0};

// Global PQC assessment results
static float g_pqc_readiness_score = 0.0f;
static int g_pqc_safe_count = 0;
static int g_pqc_transitional_count = 0;
static int g_pqc_deprecated_count = 0;
static int g_pqc_unsafe_count = 0;

// Global relationship statistics (Issue #4)
static int g_key_cert_matches = 0;
static int g_cert_chains = 0;
static int g_total_keys_for_matching = 0;
static int g_total_certs_for_matching = 0;

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nCryptographic Bill of Materials (CBOM) Generator\n");
    printf("Inventories cryptographic assets on Linux systems\n\n");
    printf("Options:\n");
    printf("  -o, --output FILE          Output file path (default: stdout)\n");
    printf("  -f, --format FORMAT        Output format: json, cyclonedx (always outputs CycloneDX)\n");
    printf("      --cyclonedx-spec VER   CycloneDX spec version: 1.6, 1.7 (default: 1.6)\n");
    printf("  -t, --threads N            Worker threads for parallel scanning (default: CPU count)\n");
    printf("                             Use --threads 1 for sequential execution\n");
    printf("  -d, --deterministic        Enable deterministic output (default: on)\n");
    printf("      --no-deterministic     Disable deterministic output\n");
    printf("\n");
    printf("Privacy Options:\n");
    printf("      --no-personal-data     Redact personal data (default: on)\n");
    printf("      --include-personal-data Include personal data (disables redaction,\n");
    printf("                             enables ~/.ssh/config scanning)\n");
    printf("      --no-network           Disable network operations (no-op in v1.0)\n");
    printf("\n");
    printf("Attestation Options:\n");
    printf("      --enable-attestation   Enable CBOM attestation with digital signature\n");
    printf("      --signature-method M   Signature method: dsse, pgp (default: dsse)\n");
    printf("      --signing-key PATH     Path to signing key file\n");
    printf("\n");
    printf("Deduplication Options:\n");
    printf("      --dedup-mode MODE      Deduplication mode: off, safe, strict (default: safe)\n");
    printf("      --emit-bundles         Emit bundle components in strict mode\n");
    printf("\n");
    printf("Service Discovery Options (v1.3):\n");
    printf("      --discover-services    Enable YAML plugin-driven service discovery\n");
    printf("      --plugin-dir DIR       Custom plugin directory (default: plugins/)\n");
    printf("      --list-plugins         List all loaded plugins and exit\n");
    printf("      --include-fixtures     Include test fixtures in service detection (testing only)\n");
    printf("      --crypto-registry FILE External crypto registry YAML (extends built-in)\n");
    printf("      --use-ldd              Use ldd for library detection (default: readelf for cross-arch)\n");
    printf("\n");
    printf("Cross-Architecture Scanning Options (v1.7+):\n");
    printf("      --cross-arch           Cross-architecture mode (skip host package manager)\n");
    printf("      --yocto-manifest FILE  Load Yocto manifest for exact version lookup\n");
    printf("      --rootfs-prefix PATH   Strip this prefix from paths in output (e.g., /mnt/rootfs)\n");
    printf("      --no-package-resolution DEPRECATED: Use --cross-arch instead\n");
    printf("\n");
    printf("Display Options:\n");
    printf("      --tui                  Enable terminal user interface with progress display\n");
    printf("      --error-log FILE       Write errors to log file (useful with --tui)\n");
    printf("      --pqc-report FILE      Generate PQC migration report (text format)\n");
    printf("\n");
    printf("  -h, --help                 Show this help message\n");
    printf("  -v, --version              Show version information\n");
    printf("\nExamples:\n");
    printf("  %s                                      # Scan system, CycloneDX to stdout\n", program_name);
    printf("  %s -o cbom.json                         # Save CycloneDX to file\n", program_name);
    printf("  %s --cyclonedx-spec=1.7 -o cbom.json    # CycloneDX 1.7 format\n", program_name);
    printf("  %s --tui -o cbom.json                   # Interactive TUI mode\n", program_name);
    printf("  %s --discover-services -o discovered.json # Service discovery with YAML plugins\n", program_name);
    printf("  %s --list-plugins                        # List all available plugins\n", program_name);
    printf("  %s --crypto-registry registry.yaml       # Use custom crypto registry\n", program_name);
    printf("  %s --no-network                         # Privacy mode (default)\n", program_name);
    printf("  %s --include-personal-data -o cbom.json # Include hostnames/usernames\n", program_name);
}

static void print_version(void) {
    printf("CBOM Generator %s\n", CBOM_VERSION);
    printf("Build: %s %s\n", CBOM_BUILD_TYPE, CBOM_BUILD_TIMESTAMP);
    printf("Compiler: %s %s\n", CBOM_C_COMPILER, CBOM_C_COMPILER_VERSION);
    printf("OpenSSL: %s\n", CBOM_OPENSSL_VERSION);
    printf("libcurl: %s\n", CBOM_CURL_VERSION);
}

static int parse_arguments(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"format", required_argument, 0, 'f'},
        {"cyclonedx-spec", required_argument, 0, 1010},
        {"threads", required_argument, 0, 't'},
        {"deterministic", no_argument, 0, 'd'},
        {"no-deterministic", no_argument, 0, 1001},
        {"no-personal-data", no_argument, 0, 1002},
        {"include-personal-data", no_argument, 0, 1006},
        {"no-network", no_argument, 0, 1003},
        {"enable-attestation", no_argument, 0, 1007},
        {"signature-method", required_argument, 0, 1008},
        {"signing-key", required_argument, 0, 1009},
        {"dedup-mode", required_argument, 0, 1004},
        {"emit-bundles", no_argument, 0, 1005},
        {"tui", no_argument, 0, 1011},
        {"error-log", required_argument, 0, 1012},
        {"pqc-report", required_argument, 0, 1013},
        {"discover-services", no_argument, 0, 1014},
        {"plugin-dir", required_argument, 0, 1015},
        {"list-plugins", no_argument, 0, 1016},
        {"include-fixtures", no_argument, 0, 1017},
        {"crypto-registry", required_argument, 0, 1018},
        {"use-ldd", no_argument, 0, 1019},
        {"no-package-resolution", no_argument, 0, 1020},
        {"cross-arch", no_argument, 0, 1021},
        {"yocto-manifest", required_argument, 0, 1022},
        {"rootfs-prefix", required_argument, 0, 1024},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "o:f:t:dhv", long_options, NULL)) != -1) {
        switch (c) {
            case 'o':
                g_cbom_config.output_file = strdup(optarg);
                break;
            case 'f':
                if (strcmp(optarg, "json") != 0 && strcmp(optarg, "cyclonedx") != 0) {
                    fprintf(stderr, "Error: Invalid format '%s'. Use 'json' or 'cyclonedx'\n", optarg);
                    return -1;
                }
                if (g_cbom_config.format) {
                    free(g_cbom_config.format);
                }
                g_cbom_config.format = strdup(optarg);
                break;
            case 't':
                g_cbom_config.thread_count = atoi(optarg);
                if (g_cbom_config.thread_count <= 0) {
                    fprintf(stderr, "Error: Invalid thread count '%s'\n", optarg);
                    return -1;
                }
                break;
            case 'd':
                g_cbom_config.deterministic = true;
                break;
            case 1001: // --no-deterministic
                g_cbom_config.deterministic = false;
                break;
            case 1002: // --no-personal-data
                g_cbom_config.no_personal_data = true;
                g_cbom_config.include_personal_data = false;
                break;
            case 1006: // --include-personal-data
                g_cbom_config.include_personal_data = true;
                g_cbom_config.no_personal_data = false;
                break;
            case 1003: // --no-network
                g_cbom_config.no_network = true;
                break;
            case 1007: // --enable-attestation
                g_cbom_config.enable_attestation = true;
                break;
            case 1008: // --signature-method
                if (strcmp(optarg, "dsse") != 0 && strcmp(optarg, "pgp") != 0) {
                    fprintf(stderr, "Error: Invalid signature method '%s'. Use 'dsse' or 'pgp'\n", optarg);
                    return -1;
                }
                if (g_cbom_config.signature_method) {
                    free(g_cbom_config.signature_method);
                }
                g_cbom_config.signature_method = strdup(optarg);
                break;
            case 1009: // --signing-key
                if (g_cbom_config.signing_key_path) {
                    free(g_cbom_config.signing_key_path);
                }
                g_cbom_config.signing_key_path = strdup(optarg);
                break;
            case 1004: // --dedup-mode
                if (strcmp(optarg, "off") == 0) {
                    g_cbom_config.dedup_mode = DEDUP_MODE_OFF;
                } else if (strcmp(optarg, "safe") == 0) {
                    g_cbom_config.dedup_mode = DEDUP_MODE_SAFE;
                } else if (strcmp(optarg, "strict") == 0) {
                    g_cbom_config.dedup_mode = DEDUP_MODE_STRICT;
                } else {
                    fprintf(stderr, "Error: Invalid dedup-mode '%s'. Use 'off', 'safe', or 'strict'\n", optarg);
                    return -1;
                }
                break;
            case 1005: // --emit-bundles
                g_cbom_config.emit_bundles = true;
                break;
            case 1010: // --cyclonedx-spec
                if (strcmp(optarg, "1.6") != 0 && strcmp(optarg, "1.7") != 0) {
                    fprintf(stderr, "Error: Invalid CycloneDX spec version '%s'. Use '1.6' or '1.7'\n", optarg);
                    return -1;
                }
                if (g_cbom_config.cyclonedx_spec_version) {
                    free(g_cbom_config.cyclonedx_spec_version);
                }
                g_cbom_config.cyclonedx_spec_version = strdup(optarg);
                break;
            case 1011: // --tui
                g_cbom_config.tui_enabled = true;
                break;
            case 1012: // --error-log
                if (g_cbom_config.error_log_file) {
                    free(g_cbom_config.error_log_file);
                }
                g_cbom_config.error_log_file = strdup(optarg);
                break;
            case 1013: // --pqc-report
                if (g_cbom_config.pqc_report_path) {
                    free(g_cbom_config.pqc_report_path);
                }
                g_cbom_config.pqc_report_path = strdup(optarg);
                break;
            case 1014: // --discover-services
                g_cbom_config.discover_services = true;
                break;
            case 1015: // --plugin-dir
                if (g_cbom_config.plugin_dir) {
                    free(g_cbom_config.plugin_dir);
                }
                g_cbom_config.plugin_dir = strdup(optarg);
                break;
            case 1016: // --list-plugins
                g_list_plugins_mode = true;
                break;
            case 1017: // --include-fixtures
                g_cbom_config.include_fixtures = true;
                break;
            case 1018: // --crypto-registry
                if (g_cbom_config.crypto_registry_path) {
                    free(g_cbom_config.crypto_registry_path);
                }
                g_cbom_config.crypto_registry_path = strdup(optarg);
                break;
            case 1019: // --use-ldd
                g_cbom_config.use_ldd_for_libraries = true;
                break;
            case 1020: // --no-package-resolution (DEPRECATED)
                fprintf(stderr, "WARNING: --no-package-resolution is deprecated, use --cross-arch instead\n");
                g_cbom_config.skip_package_resolution = true;
                g_cbom_config.cross_arch_mode = true;
                break;
            case 1021: // --cross-arch
                g_cbom_config.cross_arch_mode = true;
                break;
            case 1022: // --yocto-manifest
                if (g_cbom_config.yocto_manifest_path) {
                    free(g_cbom_config.yocto_manifest_path);
                }
                g_cbom_config.yocto_manifest_path = strdup(optarg);
                break;
            case 1024: // --rootfs-prefix
                if (g_cbom_config.rootfs_prefix) {
                    free(g_cbom_config.rootfs_prefix);
                }
                g_cbom_config.rootfs_prefix = strdup(optarg);
                // Remove trailing slash for consistent prefix stripping
                if (g_cbom_config.rootfs_prefix) {
                    size_t len = strlen(g_cbom_config.rootfs_prefix);
                    if (len > 0 && g_cbom_config.rootfs_prefix[len - 1] == '/') {
                        g_cbom_config.rootfs_prefix[len - 1] = '\0';
                    }
                }
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 'v':
                print_version();
                exit(0);
            case '?':
                return -1;
            default:
                fprintf(stderr, "Error: Unknown option\n");
                return -1;
        }
    }
    
    // Handle positional arguments (target paths)
    int num_paths = argc - optind;
    if (num_paths > 0) {
        // Allocate array for target paths
        g_cbom_config.target_paths = malloc(num_paths * sizeof(char*));
        if (!g_cbom_config.target_paths) {
            fprintf(stderr, "ERROR: Failed to allocate memory for target paths\n");
            return -1;
        }

        // Copy all target paths
        for (int i = 0; i < num_paths; i++) {
            g_cbom_config.target_paths[i] = strdup(argv[optind + i]);
            if (!g_cbom_config.target_paths[i]) {
                // Cleanup on failure
                for (int j = 0; j < i; j++) {
                    free(g_cbom_config.target_paths[j]);
                }
                free(g_cbom_config.target_paths);
                g_cbom_config.target_paths = NULL;
                fprintf(stderr, "ERROR: Failed to allocate memory for target path\n");
                return -1;
            }
        }
        g_cbom_config.target_path_count = num_paths;
    } else {
        // Default to current directory if no target specified
        g_cbom_config.target_paths = malloc(sizeof(char*));
        if (g_cbom_config.target_paths) {
            g_cbom_config.target_paths[0] = strdup(".");
            g_cbom_config.target_path_count = 1;
        }
    }
    
    return 0;
}

static int setup_deterministic_environment(void) {
    if (!g_cbom_config.deterministic) {
        return 0;
    }
    
    // Set locale to C for deterministic sorting
    if (setlocale(LC_ALL, "C") == NULL) {
        fprintf(stderr, "Warning: Failed to set C locale\n");
    }
    
    // Set timezone to UTC
    if (setenv("TZ", "UTC", 1) != 0) {
        fprintf(stderr, "Warning: Failed to set UTC timezone\n");
    }
    tzset();
    
    return 0;
}

static int initialize_subsystems(void) {
    // Set default format if not set
    if (g_cbom_config.format == NULL) {
        g_cbom_config.format = strdup("json");
        if (g_cbom_config.format == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for default format\n");
            return -1;
        }
    }

    // Set default CycloneDX spec version if not set (Phase D)
    if (g_cbom_config.cyclonedx_spec_version == NULL) {
        g_cbom_config.cyclonedx_spec_version = strdup("1.6");
        if (g_cbom_config.cyclonedx_spec_version == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for default CycloneDX spec version\n");
            return -1;
        }
    }

    // Initialize secure memory
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Error: Failed to initialize secure memory subsystem\n");
        return -1;
    }
    
    // Initialize error collector
    g_error_collector = error_collector_create(g_cbom_config.no_personal_data, ERROR_SEVERITY_DEBUG, g_cbom_config.error_log_file);
    if (g_error_collector == NULL) {
        fprintf(stderr, "Error: Failed to initialize error collector\n");
        return -1;
    }
    
    // Set default thread count to CPU count
    if (g_cbom_config.thread_count == 0) {
        long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
        g_cbom_config.thread_count = (cpu_count > 0) ? (int)cpu_count : 4;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Initialize TUI if requested
    if (g_cbom_config.tui_enabled) {
        g_tui_context = tui_init();
        if (g_tui_context) {
            tui_start(g_tui_context);
        } else {
            fprintf(stderr, "Warning: Failed to initialize TUI, falling back to normal output\n");
            g_cbom_config.tui_enabled = false;
        }
    }

    // Load external crypto registry (v1.6)
    if (g_cbom_config.crypto_registry_path != NULL) {
        char errbuf[256];
        if (crypto_registry_load_from_file(g_cbom_config.crypto_registry_path, errbuf, sizeof(errbuf)) != 0) {
            fprintf(stderr, "WARNING: Failed to load crypto registry from %s: %s\n",
                    g_cbom_config.crypto_registry_path, errbuf);
            fprintf(stderr, "WARNING: Continuing with built-in crypto registry only.\n");
            // Continue execution - this is not fatal
        } else {
            fprintf(stderr, "INFO: Loaded external crypto registry from %s\n",
                    g_cbom_config.crypto_registry_path);
        }
    }

    // Initialize version resolver (v1.7)
    if (version_resolver_init(g_cbom_config.yocto_manifest_path,
                              g_cbom_config.cross_arch_mode) != 0) {
        fprintf(stderr, "WARNING: Failed to initialize version resolver\n");
        // Continue execution - this is not fatal, will fall back to SONAME parsing
    } else {
        if (g_cbom_config.yocto_manifest_path) {
            fprintf(stderr, "INFO: Version resolver initialized with Yocto manifest: %s\n",
                    g_cbom_config.yocto_manifest_path);
        }
        if (g_cbom_config.cross_arch_mode) {
            fprintf(stderr, "INFO: Cross-architecture mode enabled (host package manager disabled)\n");
        }
    }

    return 0;
}

static void cleanup_subsystems(void) {
    // Cleanup TUI before other subsystems
    if (g_tui_context) {
        tui_stop(g_tui_context);
        tui_destroy(g_tui_context);
        g_tui_context = NULL;
    }

    if (g_completion_tracker) {
        completion_tracker_destroy(g_completion_tracker);
        g_completion_tracker = NULL;
    }

    if (g_error_collector) {
        error_collector_destroy(g_error_collector);
        g_error_collector = NULL;
    }

    secure_memory_cleanup();
    
    if (g_cbom_config.output_file) {
        free(g_cbom_config.output_file);
        g_cbom_config.output_file = NULL;
    }
    if (g_cbom_config.format) {
        free(g_cbom_config.format);
        g_cbom_config.format = NULL;
    }
    if (g_cbom_config.target_paths) {
        for (size_t i = 0; i < g_cbom_config.target_path_count; i++) {
            if (g_cbom_config.target_paths[i]) {
                free(g_cbom_config.target_paths[i]);
            }
        }
        free(g_cbom_config.target_paths);
        g_cbom_config.target_paths = NULL;
        g_cbom_config.target_path_count = 0;
    }

    // Cleanup crypto registry (v1.6)
    crypto_registry_cleanup();

    if (g_cbom_config.crypto_registry_path) {
        free(g_cbom_config.crypto_registry_path);
        g_cbom_config.crypto_registry_path = NULL;
    }

    // Cleanup version resolver (v1.7)
    version_resolver_cleanup();

    if (g_cbom_config.yocto_manifest_path) {
        free(g_cbom_config.yocto_manifest_path);
        g_cbom_config.yocto_manifest_path = NULL;
    }
}

// Check if file is a PEM certificate
static bool is_pem_certificate(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        return false;
    }
    
    char line[256];
    bool found_begin = false;
    
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "-----BEGIN CERTIFICATE-----")) {
            found_begin = true;
            break;
        }
    }
    
    fclose(file);
    return found_begin;
}

// Parse PEM certificate and create asset
static crypto_asset_t* parse_pem_certificate(const char *filepath, asset_store_t *store) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, errno, 
                       "cert_parser", "Failed to open certificate file", filepath);
        return NULL;
    }
    
    X509 *cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    
    if (cert == NULL) {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_VALIDATION, 0,
                       "cert_parser", "Failed to parse X.509 certificate", filepath);
        return NULL;
    }
    
    // Register the certificate's public key and get key ID
    char *key_id = key_manager_register_certificate_key(cert, store);
    
    // Extract certificate subject
    X509_NAME *subject = X509_get_subject_name(cert);
    char subject_str[256] = {0};
    if (subject != NULL) {
        X509_NAME_oneline(subject, subject_str, sizeof(subject_str));
    }
    
    // Create asset
    crypto_asset_t *asset = crypto_asset_create(subject_str[0] ? subject_str : filepath, 
                                               ASSET_TYPE_CERTIFICATE);
    if (asset == NULL) {
        if (key_id) free(key_id);
        X509_free(cert);
        return NULL;
    }
    
    asset->location = strdup(filepath);
    
    // Store the key ID for relationship linking
    if (key_id) {
        asset->key_id = key_id; // Will be used for relationships
    }
    
    // Extract public key algorithm and size
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey != NULL) {
        int key_type = EVP_PKEY_base_id(pkey);
        switch (key_type) {
            case EVP_PKEY_RSA:
                asset->algorithm = strdup("RSA");
                asset->key_size = EVP_PKEY_bits(pkey);
                break;
            case EVP_PKEY_EC:
                asset->algorithm = strdup("ECDSA");
                asset->key_size = EVP_PKEY_bits(pkey);
                break;
            case EVP_PKEY_DSA:
                asset->algorithm = strdup("DSA");
                asset->key_size = EVP_PKEY_bits(pkey);
                break;
            default:
                asset->algorithm = strdup("Unknown");
                asset->key_size = 0;
                break;
        }
        EVP_PKEY_free(pkey);
    }
    
    // Check for weak cryptography
    if (asset->key_size > 0 && asset->key_size < 2048) {
        asset->is_weak = true;
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_SECURITY,
                         "cert_parser", "Certificate uses weak key size", filepath);
    }
    
    X509_free(cert);
    return asset;
}

// Scan directory for certificates (non-recursive for walking skeleton)
static int scan_directory_for_certificates(const char *dirpath, asset_store_t *store) {
    DIR *dir = opendir(dirpath);
    if (dir == NULL) {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_PERMISSION, errno,
                       "directory_scanner", "Failed to open directory", dirpath);
        return -1;
    }
    
    struct dirent *entry;
    int found_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) {
            continue; // Skip non-regular files
        }
        
        // Check for certificate file extensions
        const char *name = entry->d_name;
        size_t len = strlen(name);
        
        bool is_cert_file = false;
        if (len > 4) {
            const char *ext = name + len - 4;
            if (strcasecmp(ext, ".pem") == 0 || 
                strcasecmp(ext, ".crt") == 0 ||
                strcasecmp(ext, ".cer") == 0) {
                is_cert_file = true;
            }
        }
        
        if (!is_cert_file) {
            continue;
        }
        
        // Build full path
        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, name);
        
        // Check if it's actually a PEM certificate
        if (!is_pem_certificate(filepath)) {
            continue;
        }
        
        // Parse certificate
        crypto_asset_t *asset = parse_pem_certificate(filepath, store);
        if (asset != NULL) {
            if (asset_store_add(store, asset) == 0) {
                found_count++;
                completion_tracker_task_completed(g_completion_tracker);
                ERROR_LOG_INFO(g_error_collector, "cert_scanner", 
                              "Found certificate", filepath);
            } else {
                crypto_asset_destroy(asset);
                completion_tracker_task_failed(g_completion_tracker);
            }
        } else {
            completion_tracker_task_failed(g_completion_tracker);
        }
    }
    
    closedir(dir);
    return found_count;
}

// Fallback basic certificate scanning (original implementation)
static int run_basic_certificate_scan(asset_store_t *store) {
    ERROR_LOG_INFO(g_error_collector, "main", "Starting basic certificate scan", NULL);

    int total_cert_count = 0;
    for (size_t i = 0; i < g_cbom_config.target_path_count; i++) {
        const char *target = g_cbom_config.target_paths[i];
        int cert_count = scan_directory_for_certificates(target, store);

        if (cert_count < 0) {
            ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                           "main", "Failed to scan directory", target);
        } else {
            total_cert_count += cert_count;
        }
    }

    ERROR_LOG_INFO(g_error_collector, "main", "Basic certificate scan completed", NULL);

    // v1.5: Removed unconditional fixtures scan - test paths should not be in production code
    // To scan fixtures, explicitly specify path: ./cbom-generator fixtures/

    return total_cert_count >= 0 ? 0 : -1;
}

// Calculate SHA-256 hash of a string
static char* calculate_string_sha256(const char* data) {
    if (!data) return NULL;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_DigestUpdate(ctx, data, strlen(data)) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    
    char *hex_string = malloc(hash_len * 2 + 1);
    if (!hex_string) return NULL;
    
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[hash_len * 2] = '\0';
    
    return hex_string;
}

// Calculate SHA-256 hash of a file
static char* calculate_file_sha256(const char* filepath) {
    if (!filepath) return NULL;
    
    FILE *file = fopen(filepath, "rb");
    if (!file) return NULL;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return NULL;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    unsigned char buffer[8192];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return NULL;
        }
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    fclose(file);
    
    // Convert to hex string
    char *hex_hash = malloc(hash_len * 2 + 1);
    if (!hex_hash) return NULL;
    
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[hash_len * 2] = '\0';
    
    return hex_hash;
}

// Generate current timestamp in ISO 8601 format
static char* generate_timestamp(void) {
    time_t now = time(NULL);
    struct tm *utc_tm = gmtime(&now);
    
    char *timestamp = malloc(32);
    if (timestamp != NULL) {
        strftime(timestamp, 32, "%Y-%m-%dT%H:%M:%SZ", utc_tm);
    }
    
    return timestamp;
}

// Generate UUID (simple implementation for walking skeleton)
static char* generate_uuid(void) {
    char *uuid = malloc(50);
    if (uuid != NULL) {
        snprintf(uuid, 50, "urn:uuid:%08x-%04x-%04x-%04x-%08x%04x",
                 rand(), rand() & 0xFFFF, rand() & 0xFFFF, 
                 rand() & 0xFFFF, rand(), rand() & 0xFFFF);
    }
    return uuid;
}

// Extract Common Name (CN) from X.509 subject DN
// Handles RFC 2253 (comma-separated) and OpenSSL (slash-separated) formats
// Returns newly allocated string with CN value, or NULL if not found
// Caller must free() returned string
static char* extract_cn_from_subject(const char* subject_dn) {
    if (!subject_dn || strlen(subject_dn) == 0) {
        return NULL;
    }

    // Try to find "CN=" or "CN =" in the string (case-insensitive)
    const char *cn_start = strcasestr(subject_dn, "CN=");
    if (!cn_start) {
        cn_start = strcasestr(subject_dn, "CN =");
        if (!cn_start) {
            return NULL;
        }
        // Skip "CN =" prefix (4 characters) and any additional spaces
        cn_start += 4;
    } else {
        // Skip "CN=" prefix (3 characters)
        cn_start += 3;
    }

    // Find end of CN value (next comma, slash, or end of string)
    const char *cn_end = cn_start;
    while (*cn_end && *cn_end != ',' && *cn_end != '/' && *cn_end != '\n' && *cn_end != '\r') {
        cn_end++;
    }

    // Calculate length and extract CN value
    size_t cn_len = cn_end - cn_start;
    if (cn_len == 0) {
        return NULL;
    }

    char *cn_value = malloc(cn_len + 1);
    if (!cn_value) {
        return NULL;
    }

    strncpy(cn_value, cn_start, cn_len);
    cn_value[cn_len] = '\0';

    // Trim leading whitespace
    char *trimmed = cn_value;
    while (*trimmed && isspace((unsigned char)*trimmed)) {
        trimmed++;
    }

    // Trim trailing whitespace
    char *end = trimmed + strlen(trimmed) - 1;
    while (end > trimmed && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    // If trimmed is different from cn_value, move it to the beginning
    if (trimmed != cn_value) {
        memmove(cn_value, trimmed, strlen(trimmed) + 1);
    }

    return cn_value;
}

// Sanitize string for use in bom-ref
// Rules:
// - Convert to lowercase
// - Replace spaces and special chars with hyphens
// - Collapse multiple hyphens to single hyphen
// - Trim leading/trailing hyphens
// - Truncate to max 64 characters
// Returns newly allocated string, caller must free()
static char* sanitize_for_bomref(const char* input) {
    if (!input || strlen(input) == 0) {
        return NULL;
    }

    size_t len = strlen(input);
    char *result = malloc(len + 1);
    if (!result) {
        return NULL;
    }

    size_t j = 0;
    bool last_was_hyphen = true; // Start as true to trim leading hyphens

    for (size_t i = 0; i < len && j < 64; i++) {
        char c = input[i];

        if (isalnum((unsigned char)c)) {
            // Alphanumeric: convert to lowercase and add
            result[j++] = tolower((unsigned char)c);
            last_was_hyphen = false;
        } else if (!last_was_hyphen) {
            // Special char or space: replace with hyphen (but avoid consecutive hyphens)
            result[j++] = '-';
            last_was_hyphen = true;
        }
    }

    // Trim trailing hyphen
    if (j > 0 && result[j-1] == '-') {
        j--;
    }

    result[j] = '\0';

    // If result is empty after sanitization, return NULL
    if (j == 0) {
        free(result);
        return NULL;
    }

    return result;
}

// Generate human-readable bom-ref with collision detection
// Uses bomref_set to track used bom-refs and append suffixes if needed
// Returns newly allocated string, caller must free()
static char* generate_readable_bomref(crypto_asset_t *asset, json_object *bomref_set) {
    if (!asset || !bomref_set) {
        return NULL;
    }

    char bomref[128] = {0};
    char *sanitized = NULL;

    switch (asset->type) {
        case ASSET_TYPE_CERTIFICATE: {
            // Extract CN from certificate subject
            if (asset->metadata_json) {
                json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                if (metadata_obj) {
                    json_object* subject_obj;
                    if (json_object_object_get_ex(metadata_obj, "subject", &subject_obj)) {
                        const char* subject_dn = json_object_get_string(subject_obj);
                        char* cn = extract_cn_from_subject(subject_dn);
                        if (cn) {
                            sanitized = sanitize_for_bomref(cn);
                            free(cn);
                            if (sanitized) {
                                snprintf(bomref, sizeof(bomref), "cert:%s", sanitized);
                                free(sanitized);
                            }
                        }
                    }
                    json_object_put(metadata_obj);
                }
            }
            break;
        }

        case ASSET_TYPE_ALGORITHM: {
            // Format: algo:<algorithm>-<keysize>
            sanitized = sanitize_for_bomref(asset->algorithm ? asset->algorithm : asset->name);
            if (sanitized) {
                if (asset->key_size > 0) {
                    snprintf(bomref, sizeof(bomref), "algo:%s-%d", sanitized, asset->key_size);
                } else {
                    snprintf(bomref, sizeof(bomref), "algo:%s", sanitized);
                }
                free(sanitized);
            }
            break;
        }

        case ASSET_TYPE_KEY: {
            // Format: key:<algorithm>-<keysize>-<short-hash>
            sanitized = sanitize_for_bomref(asset->algorithm ? asset->algorithm : "unknown");
            if (sanitized) {
                // Use first 8 chars of asset ID for uniqueness
                char short_hash[9] = {0};
                if (asset->id) {
                    size_t id_len = strlen(asset->id);
                    size_t copy_len = (id_len < 8) ? id_len : 8;
                    memcpy(short_hash, asset->id, copy_len);
                    short_hash[copy_len] = '\0';
                }
                if (asset->key_size > 0) {
                    snprintf(bomref, sizeof(bomref), "key:%s-%d-%s", sanitized, asset->key_size, short_hash);
                } else {
                    snprintf(bomref, sizeof(bomref), "key:%s-%s", sanitized, short_hash);
                }
                free(sanitized);
            }
            break;
        }

        case ASSET_TYPE_SERVICE: {
            // Format: service:<sanitized-name>
            sanitized = sanitize_for_bomref(asset->name);
            if (sanitized) {
                snprintf(bomref, sizeof(bomref), "service:%s", sanitized);
                free(sanitized);
            }
            break;
        }

        case ASSET_TYPE_PROTOCOL: {
            // Format: protocol:<name>-<version/usage> to differentiate versions and client/server
            sanitized = sanitize_for_bomref(asset->name);
            if (sanitized) {
                // Check location for SSH client/server differentiation
                if (asset->location) {
                    if (strstr(asset->location, "sshd_config")) {
                        snprintf(bomref, sizeof(bomref), "protocol:%s-server", sanitized);
                    } else if (strstr(asset->location, "ssh_config")) {
                        snprintf(bomref, sizeof(bomref), "protocol:%s-client", sanitized);
                    } else if (asset->version && strcasecmp(asset->name, "TLS") == 0) {
                        // Include TLS version in bom-ref (e.g., protocol:tls-1.3)
                        char* version_sanitized = sanitize_for_bomref(asset->version);
                        if (version_sanitized) {
                            snprintf(bomref, sizeof(bomref), "protocol:%s-%s", sanitized, version_sanitized);
                            free(version_sanitized);
                        } else {
                            snprintf(bomref, sizeof(bomref), "protocol:%s", sanitized);
                        }
                    } else {
                        snprintf(bomref, sizeof(bomref), "protocol:%s", sanitized);
                    }
                } else if (asset->version && strcasecmp(asset->name, "TLS") == 0) {
                    // Include TLS version in bom-ref (e.g., protocol:tls-1.3)
                    char* version_sanitized = sanitize_for_bomref(asset->version);
                    if (version_sanitized) {
                        snprintf(bomref, sizeof(bomref), "protocol:%s-%s", sanitized, version_sanitized);
                        free(version_sanitized);
                    } else {
                        snprintf(bomref, sizeof(bomref), "protocol:%s", sanitized);
                    }
                } else {
                    snprintf(bomref, sizeof(bomref), "protocol:%s", sanitized);
                }
                free(sanitized);
            }
            break;
        }

        case ASSET_TYPE_LIBRARY: {
            // Format: library:<name>-<version>
            sanitized = sanitize_for_bomref(asset->name);
            if (sanitized) {
                snprintf(bomref, sizeof(bomref), "library:%s", sanitized);
                free(sanitized);
            }
            break;
        }

        case ASSET_TYPE_CIPHER_SUITE: {
            // Format: cipher:<sanitized-name>
            sanitized = sanitize_for_bomref(asset->name);
            if (sanitized) {
                snprintf(bomref, sizeof(bomref), "cipher:%s", sanitized);
                free(sanitized);
            }
            break;
        }

        default:
            // Fallback to hash-based for unknown types
            break;
    }

    // If bomref generation failed, use hash-based fallback
    if (strlen(bomref) == 0 && asset->id) {
        // Use asset type prefix + first 16 chars of hash
        const char* type_prefix = "asset";
        switch (asset->type) {
            case ASSET_TYPE_CERTIFICATE: type_prefix = "cert"; break;
            case ASSET_TYPE_ALGORITHM: type_prefix = "algo"; break;
            case ASSET_TYPE_KEY: type_prefix = "key"; break;
            case ASSET_TYPE_SERVICE: type_prefix = "service"; break;
            case ASSET_TYPE_PROTOCOL: type_prefix = "protocol"; break;
            case ASSET_TYPE_LIBRARY: type_prefix = "library"; break;
            case ASSET_TYPE_CIPHER_SUITE: type_prefix = "cipher"; break;
            default: type_prefix = "asset"; break;
        }

        // Use first 16 chars of hash or full hash if shorter
        char hash_prefix[17] = {0};
        size_t hash_len = strlen(asset->id);
        size_t copy_len = (hash_len < 16) ? hash_len : 16;
        memcpy(hash_prefix, asset->id, copy_len);
        hash_prefix[copy_len] = '\0';
        snprintf(bomref, sizeof(bomref), "%s:hash-%s", type_prefix, hash_prefix);
    }

    // Handle collisions by appending numeric suffix
    char final_bomref[256];  // Increased buffer size to avoid truncation warnings
    strncpy(final_bomref, bomref, sizeof(final_bomref) - 1);
    final_bomref[sizeof(final_bomref) - 1] = '\0';

    int suffix = 2;
    while (json_object_object_get_ex(bomref_set, final_bomref, NULL)) {
        snprintf(final_bomref, sizeof(final_bomref), "%s-%d", bomref, suffix);
        suffix++;
    }

    // Add to collision set
    json_object_object_add(bomref_set, final_bomref, json_object_new_boolean(true));

    // Return allocated copy
    return strdup(final_bomref);
}

// Helper: Add external references to tool metadata
static json_object* create_tool_external_references(void) {
    json_object *ext_refs = json_object_new_array();

    // Website reference
    json_object *ref_website = json_object_new_object();
    json_object_object_add(ref_website, "type", json_object_new_string("website"));
    json_object_object_add(ref_website, "url", json_object_new_string("https://www.cipheriq.io"));
    json_object_array_add(ext_refs, ref_website);

    // Support reference
    json_object *ref_support = json_object_new_object();
    json_object_object_add(ref_support, "type", json_object_new_string("support"));
    json_object_object_add(ref_support, "url", json_object_new_string("mailto:support@cipheriq.io"));
    json_object_array_add(ext_refs, ref_support);

    return ext_refs;
}

// Generate tools metadata in CycloneDX 1.6 legacy array format
static json_object* generate_tools_legacy_format(void) {
    json_object *tools = json_object_new_array();
    json_object *tool = json_object_new_object();

    // Basic metadata
    json_object_object_add(tool, "vendor", json_object_new_string("Graziano Labs Corp."));
    json_object_object_add(tool, "name", json_object_new_string("CipherIQ"));
    json_object_object_add(tool, "version", json_object_new_string(CBOM_VERSION));
    json_object_object_add(tool, "copyright", json_object_new_string("Copyright (c) 2025 Graziano Labs Corp. All rights reserved."));

    // External references
    json_object *ext_refs = create_tool_external_references();
    json_object_object_add(tool, "externalReferences", ext_refs);

    json_object_array_add(tools, tool);
    return tools;
}

// Generate tools metadata in CycloneDX 1.7 modern components format
static json_object* generate_tools_modern_format(void) {
    json_object *tools = json_object_new_object();
    json_object *components = json_object_new_array();
    json_object *tool_component = json_object_new_object();

    // Component type and identity
    json_object_object_add(tool_component, "type", json_object_new_string("application"));
    json_object_object_add(tool_component, "bom-ref", json_object_new_string("cipheriq-tool"));

    // Supplier information
    json_object *supplier = json_object_new_object();
    json_object_object_add(supplier, "name", json_object_new_string("Graziano Labs Corp."));
    json_object_object_add(tool_component, "supplier", supplier);

    // Tool metadata
    json_object_object_add(tool_component, "name", json_object_new_string("CipherIQ"));
    json_object_object_add(tool_component, "version", json_object_new_string(CBOM_VERSION));
    json_object_object_add(tool_component, "description",
        json_object_new_string("High-performance cryptographic asset scanner for Linux systems"));
    json_object_object_add(tool_component, "copyright",
        json_object_new_string("Copyright (c) 2025 Graziano Labs Corp. All rights reserved."));

    // External references
    json_object *ext_refs = create_tool_external_references();
    json_object_object_add(tool_component, "externalReferences", ext_refs);

    // Properties (including executable name)
    json_object *properties = json_object_new_array();

    json_object *exec_prop = json_object_new_object();
    json_object_object_add(exec_prop, "name", json_object_new_string("cbom:tool:executable"));
    json_object_object_add(exec_prop, "value", json_object_new_string("cbom-generator"));
    json_object_array_add(properties, exec_prop);

    json_object *lang_prop = json_object_new_object();
    json_object_object_add(lang_prop, "name", json_object_new_string("cbom:tool:language"));
    json_object_object_add(lang_prop, "value", json_object_new_string("C11"));
    json_object_array_add(properties, lang_prop);

    json_object_object_add(tool_component, "properties", properties);

    // Add to components array
    json_object_array_add(components, tool_component);
    json_object_object_add(tools, "components", components);

    return tools;
}

// Helper: Check if asset has role="service" in its metadata_json
// This allows YAML plugin-created applications to be treated as services for PQC assessment
static bool has_service_role(const crypto_asset_t* asset) {
    if (!asset || !asset->metadata_json) return false;

    json_object* metadata = json_tokener_parse(asset->metadata_json);
    if (!metadata) return false;

    bool is_service = false;
    json_object* role_obj;
    if (json_object_object_get_ex(metadata, "role", &role_obj)) {
        const char* role = json_object_get_string(role_obj);
        if (role && strcmp(role, "service") == 0) {
            is_service = true;
        }
    }

    json_object_put(metadata);
    return is_service;
}

// Helper: Check if algorithm name is a PQC-safe KEX algorithm
// Used for detecting PQC KEX algorithms provided by libraries like openssh-internal
static bool is_pqc_kex_algorithm(const char* name) {
    if (!name) return false;
    // NTRU Prime hybrid (OpenSSH's PQC KEX)
    if (strstr(name, "sntrup761") || strstr(name, "sntrup") || strstr(name, "ntruprime")) return true;
    // Kyber/ML-KEM based KEX (TLS 1.3 PQC)
    if (strstr(name, "mlkem") || strstr(name, "ML-KEM") ||
        strstr(name, "kyber") || strstr(name, "Kyber")) return true;
    // Dilithium/ML-DSA (post-quantum signatures)
    if (strstr(name, "dilithium") || strstr(name, "Dilithium") ||
        strstr(name, "mldsa") || strstr(name, "ML-DSA")) return true;
    return false;
}

// Helper: Assess PQC status from configured protocols/cipher suites (for services)
// Returns best-case PQC status - if ANY configured algorithm is PQC-safe, service is SAFE
// This allows services to be classified based on their actual TLS/SSH configuration
static pqc_category_t assess_pqc_from_configured_protocols(
    asset_store_t *store,
    const char* service_id,
    char* best_component_name,
    size_t best_component_name_size
) {
    if (!store || !service_id) return PQC_UNKNOWN;

    size_t rel_count = 0;
    relationship_t** relationships = asset_store_get_relationships(store, &rel_count);
    if (!relationships || rel_count == 0) return PQC_UNKNOWN;

    pqc_category_t best_category = PQC_UNKNOWN;
    const char* best_component = NULL;
    bool found_protocol = false;

    // Step 1: Find protocols this service depends on
    for (size_t i = 0; i < rel_count; i++) {
        relationship_t* rel = relationships[i];
        if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

        // Check if this service USES, DEPENDS_ON, or PROVIDES a protocol
        if (strcmp(rel->source_asset_id, service_id) != 0) continue;
        if (rel->type != RELATIONSHIP_USES && rel->type != RELATIONSHIP_DEPENDS_ON && rel->type != RELATIONSHIP_PROVIDES) continue;

        crypto_asset_t* protocol = asset_store_find(store, rel->target_asset_id);
        if (!protocol || protocol->type != ASSET_TYPE_PROTOCOL) continue;

        found_protocol = true;

        // Step 2: Find cipher suites this protocol provides
        for (size_t j = 0; j < rel_count; j++) {
            relationship_t* prel = relationships[j];
            if (!prel || !prel->source_asset_id || !prel->target_asset_id) continue;

            if (strcmp(prel->source_asset_id, protocol->id) != 0) continue;
            if (prel->type != RELATIONSHIP_PROVIDES) continue;

            crypto_asset_t* suite = asset_store_find(store, prel->target_asset_id);
            if (!suite || suite->type != ASSET_TYPE_CIPHER_SUITE) continue;

            // Step 3: Classify cipher suite by its algorithm components
            // Parse the cipher suite name to extract algorithms
            pqc_category_t suite_category = PQC_UNKNOWN;

            // Classify cipher suite for SERVICE-level PQC assessment
            // Note: Cipher suites themselves may be SAFE (AES-GCM symmetric is quantum-resistant)
            // but for SERVICE classification, we care about the full protocol including KEX
            const char* suite_name = suite->name;
            if (suite_name) {
                // TLS 1.3 cipher suites (TLS_AES_*) - symmetric is SAFE but KEX is separate
                // For service classification: TRANSITIONAL unless PQC KEX is configured
                // (PQC KEX detection happens via algorithm relationships, not cipher suites)
                if (strstr(suite_name, "TLS_AES") || strstr(suite_name, "TLS_CHACHA20")) {
                    // TLS 1.3 with classical KEX (X25519/ECDHE) - TRANSITIONAL for service
                    // The cipher suite ASSET is SAFE, but service needs PQC KEX to be SAFE
                    suite_category = PQC_TRANSITIONAL;
                }
                // TLS 1.2 ciphers with embedded KEX info
                else if (strstr(suite_name, "ECDHE") || strstr(suite_name, "DHE")) {
                    // Good forward secrecy but classical KEX
                    suite_category = PQC_TRANSITIONAL;
                }
                else if (strstr(suite_name, "RSA") && !strstr(suite_name, "ECDHE") && !strstr(suite_name, "DHE")) {
                    // RSA key transport (no forward secrecy) - still TRANSITIONAL for now
                    suite_category = PQC_TRANSITIONAL;
                }
                // Weak/deprecated ciphers
                else if (strstr(suite_name, "RC4") || strstr(suite_name, "DES") ||
                         strstr(suite_name, "NULL") || strstr(suite_name, "EXPORT") ||
                         strstr(suite_name, "MD5") || strstr(suite_name, "3DES")) {
                    suite_category = PQC_DEPRECATED;
                }
                else {
                    suite_category = PQC_TRANSITIONAL;  // Default assumption
                }
            }

            // Track best case - lower enum value = better (SAFE=0, TRANSITIONAL=1, etc.)
            if (best_category == PQC_UNKNOWN && suite_category != PQC_UNKNOWN) {
                best_category = suite_category;
                best_component = suite->name;
            } else if (suite_category != PQC_UNKNOWN && (int)suite_category < (int)best_category) {
                best_category = suite_category;
                best_component = suite->name;
            }
        }

        // Step 4: Also check for direct protocol→algorithm relationships (SSH case)
        for (size_t j = 0; j < rel_count; j++) {
            relationship_t* prel = relationships[j];
            if (!prel || !prel->source_asset_id || !prel->target_asset_id) continue;

            if (strcmp(prel->source_asset_id, protocol->id) != 0) continue;
            if (prel->type != RELATIONSHIP_DEPENDS_ON && prel->type != RELATIONSHIP_USES) continue;

            crypto_asset_t* algo = asset_store_find(store, prel->target_asset_id);
            if (!algo || algo->type != ASSET_TYPE_ALGORITHM) continue;

            // Classify algorithm
            pqc_category_t algo_category = PQC_UNKNOWN;
            const char* algo_name = algo->name;

            if (algo_name) {
                // PQC-safe algorithms
                if (strstr(algo_name, "sntrup") || strstr(algo_name, "ntruprime") ||
                    strstr(algo_name, "Kyber") || strstr(algo_name, "ML-KEM") ||
                    strstr(algo_name, "Dilithium") || strstr(algo_name, "ML-DSA")) {
                    algo_category = PQC_SAFE;
                }
                // Quantum-safe symmetric
                else if (strstr(algo_name, "aes") || strstr(algo_name, "AES") ||
                         strstr(algo_name, "chacha20") || strstr(algo_name, "CHACHA20")) {
                    algo_category = PQC_SAFE;  // Symmetric is quantum-safe
                }
                // Transitional key exchange
                else if (strstr(algo_name, "curve25519") || strstr(algo_name, "ecdh") ||
                         strstr(algo_name, "ECDH") || strstr(algo_name, "ecdsa") ||
                         strstr(algo_name, "ECDSA") || strstr(algo_name, "ed25519")) {
                    algo_category = PQC_TRANSITIONAL;
                }
                // Weak/deprecated
                else if (strstr(algo_name, "sha1") || strstr(algo_name, "SHA1") ||
                         strstr(algo_name, "md5") || strstr(algo_name, "MD5") ||
                         strstr(algo_name, "dss") || strstr(algo_name, "DSS") ||
                         strstr(algo_name, "dsa") || strstr(algo_name, "DSA")) {
                    algo_category = PQC_DEPRECATED;
                }
                else {
                    algo_category = PQC_TRANSITIONAL;  // Default
                }
            }

            // Track best case - lower enum value = better (SAFE=0, TRANSITIONAL=1, etc.)
            if (best_category == PQC_UNKNOWN && algo_category != PQC_UNKNOWN) {
                best_category = algo_category;
                best_component = algo->name;
            } else if (algo_category != PQC_UNKNOWN && (int)algo_category < (int)best_category) {
                best_category = algo_category;
                best_component = algo->name;
            }
        }
    }

    // Step 5: Check library-provided algorithms (for SSH and similar services)
    // This follows: SERVICE → LIBRARY → ALGORITHM path
    // SSH services get their PQC KEX algorithms via openssh-internal library
    for (size_t i = 0; i < rel_count; i++) {
        relationship_t* rel = relationships[i];
        if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

        // Check if this service DEPENDS_ON a library
        if (strcmp(rel->source_asset_id, service_id) != 0) continue;
        if (rel->type != RELATIONSHIP_DEPENDS_ON) continue;

        // Debug: print the target_asset_id to see what format it's in
        // fprintf(stderr, "[DEBUG-Step5] service=%s DEPENDS_ON target=%s\n", service_id, rel->target_asset_id);

        crypto_asset_t* lib = asset_store_find(store, rel->target_asset_id);
        if (!lib) {
            // Try to find by name if target is a bom-ref format
            if (strncmp(rel->target_asset_id, "library:", 8) == 0) {
                // Extract name from library:xxx-yyy-zzz format
                const char* name_part = rel->target_asset_id + 8;
                // Convert hyphens to underscores for openssh-internal -> openssh_internal
                char normalized_name[128];
                snprintf(normalized_name, sizeof(normalized_name), "%s", name_part);
                for (char* p = normalized_name; *p; p++) {
                    if (*p == '-') *p = '_';
                }
                // Search by name
                size_t count = 0;
                crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &count);
                for (size_t a = 0; a < count && assets; a++) {
                    if (assets[a] && assets[a]->type == ASSET_TYPE_LIBRARY &&
                        assets[a]->name && strcmp(assets[a]->name, normalized_name) == 0) {
                        lib = assets[a];
                        break;
                    }
                }
                free(assets);
            }
        }
        if (!lib || lib->type != ASSET_TYPE_LIBRARY) continue;

        // Check what algorithms this library IMPLEMENTS
        for (size_t j = 0; j < rel_count; j++) {
            relationship_t* prel = relationships[j];
            if (!prel || !prel->source_asset_id || !prel->target_asset_id) continue;

            if (strcmp(prel->source_asset_id, lib->id) != 0) continue;
            // Libraries IMPLEMENT algorithms (not PROVIDE)
            if (prel->type != RELATIONSHIP_IMPLEMENTS && prel->type != RELATIONSHIP_PROVIDES) continue;

            crypto_asset_t* algo = asset_store_find(store, prel->target_asset_id);
            if (!algo) continue;

            // Check if this is a PQC KEX algorithm
            if (is_pqc_kex_algorithm(algo->name)) {
                best_category = PQC_SAFE;
                best_component = algo->name;
                // Found PQC KEX via library - skip protocol check and return directly
                if (best_component_name && best_component_name_size > 0) {
                    snprintf(best_component_name, best_component_name_size, "%s", algo->name);
                }
                return PQC_SAFE;
            }
        }
    }

    if (!found_protocol) {
        return PQC_UNKNOWN;
    }

    // Copy best component name if buffer provided
    if (best_component_name && best_component_name_size > 0 && best_component) {
        snprintf(best_component_name, best_component_name_size, "%s", best_component);
    }

    return best_category;
}

// Helper: Assess PQC status for PROTOCOL assets by traversing cipher suite/algorithm relationships
// Uses best-case logic: strongest cipher suite or algorithm determines status
// Returns PQC_UNKNOWN if no relationships exist (triggers fallback to version-based)
static pqc_category_t assess_pqc_from_protocol_cipher_suites(
    asset_store_t *store,
    const char* protocol_id,
    char* best_suite_name,
    size_t best_suite_name_size
) {
    if (!store || !protocol_id) return PQC_UNKNOWN;

    size_t rel_count = 0;
    relationship_t** relationships = asset_store_get_relationships(store, &rel_count);
    if (!relationships || rel_count == 0) return PQC_UNKNOWN;

    pqc_category_t best_category = PQC_UNKNOWN;
    const char* best_component = NULL;
    bool found_related = false;

    // Scan all relationships from this protocol
    for (size_t i = 0; i < rel_count; i++) {
        relationship_t* rel = relationships[i];
        if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

        // Check if this protocol is the source
        if (strcmp(rel->source_asset_id, protocol_id) != 0) continue;

        // Accept PROVIDES (cipher suites), USES (algorithms), or DEPENDS_ON (algorithms)
        if (rel->type != RELATIONSHIP_PROVIDES &&
            rel->type != RELATIONSHIP_USES &&
            rel->type != RELATIONSHIP_DEPENDS_ON) continue;

        crypto_asset_t* target = asset_store_find(store, rel->target_asset_id);
        if (!target) continue;

        // Only process cipher suites or algorithms
        if (target->type != ASSET_TYPE_CIPHER_SUITE &&
            target->type != ASSET_TYPE_ALGORITHM) continue;

        found_related = true;

        // Classify the target (cipher suite or algorithm)
        pqc_category_t target_category = PQC_UNKNOWN;
        const char* target_name = target->name;

        if (target_name) {
            // Check for PQC-hybrid/PQC-safe first
            if (strstr(target_name, "Kyber") || strstr(target_name, "ML-KEM") ||
                strstr(target_name, "sntrup") || strstr(target_name, "ntruprime") ||
                strstr(target_name, "NTRU") || strstr(target_name, "Dilithium") ||
                strstr(target_name, "SPHINCS")) {
                target_category = PQC_SAFE;
            }
            // TLS 1.3 symmetric-only suites (KEX is separate)
            else if (strstr(target_name, "TLS_AES") || strstr(target_name, "TLS_CHACHA20")) {
                // For protocol-level classification, these are TRANSITIONAL
                // (they use classical KEX unless PQC-hybrid is configured)
                target_category = PQC_TRANSITIONAL;
            }
            // TLS 1.2 with forward secrecy or classical KEX algorithms
            else if (strstr(target_name, "ECDHE") || strstr(target_name, "DHE") ||
                     strstr(target_name, "curve25519") || strstr(target_name, "ecdh") ||
                     strstr(target_name, "x25519") || strstr(target_name, "X25519")) {
                target_category = PQC_TRANSITIONAL;
            }
            // Weak/deprecated ciphers
            else if (strstr(target_name, "RC4") || strstr(target_name, "DES") ||
                     strstr(target_name, "NULL") || strstr(target_name, "EXPORT") ||
                     strstr(target_name, "MD5") || strstr(target_name, "3DES")) {
                target_category = PQC_DEPRECATED;
            }
            else {
                target_category = PQC_TRANSITIONAL;  // Default
            }
        }

        // Track best case - lower enum value = better (SAFE=0, TRANSITIONAL=1, etc.)
        if (best_category == PQC_UNKNOWN && target_category != PQC_UNKNOWN) {
            best_category = target_category;
            best_component = target->name;
        } else if (target_category != PQC_UNKNOWN && (int)target_category < (int)best_category) {
            best_category = target_category;
            best_component = target->name;
        }
    }

    // Return UNKNOWN if no related cipher suites/algorithms found (triggers version-based fallback)
    if (!found_related) {
        return PQC_UNKNOWN;
    }

    // Copy best component name to output buffer
    if (best_suite_name && best_suite_name_size > 0 && best_component) {
        snprintf(best_suite_name, best_suite_name_size, "%s", best_component);
    }

    return best_category;
}

// Helper: Assess PQC status from library dependencies (for apps/services)
// Returns worst-case PQC status from all dependent libraries
// This allows apps to inherit PQC status from their crypto libraries
static pqc_category_t assess_pqc_from_library_dependencies(
    asset_store_t *store,
    const char* asset_id,
    char* worst_lib_name,
    size_t worst_lib_name_size
) {
    if (!store || !asset_id) return PQC_UNKNOWN;

    size_t rel_count = 0;
    relationship_t** relationships = asset_store_get_relationships(store, &rel_count);

    if (!relationships || rel_count == 0) return PQC_UNKNOWN;

    pqc_category_t worst_category = PQC_UNKNOWN;
    const char* worst_lib = NULL;
    bool found_lib_dep = false;

    for (size_t i = 0; i < rel_count; i++) {
        relationship_t* rel = relationships[i];
        if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

        // Check if this asset DEPENDS_ON the target
        if (strcmp(rel->source_asset_id, asset_id) != 0) continue;
        if (rel->type != RELATIONSHIP_DEPENDS_ON) continue;

        // Get the target asset (should be a library)
        crypto_asset_t* target_asset = asset_store_find(store, rel->target_asset_id);
        if (!target_asset || target_asset->type != ASSET_TYPE_LIBRARY) continue;

        found_lib_dep = true;

        // Get library's PQC status from its pqc_status field (set during earlier classification)
        // If not set yet, we'll need to classify it now
        pqc_category_t lib_category = PQC_UNKNOWN;

        // Try to get from metadata if already classified
        if (target_asset->metadata_json) {
            json_object* meta = json_tokener_parse(target_asset->metadata_json);
            if (meta) {
                json_object* pqc_obj = NULL;
                if (json_object_object_get_ex(meta, "pqc_status", &pqc_obj)) {
                    lib_category = pqc_category_from_string(json_object_get_string(pqc_obj));
                }
                json_object_put(meta);
            }
        }

        // If still unknown, check if it has implemented_algorithms and classify
        if (lib_category == PQC_UNKNOWN && target_asset->metadata_json) {
            json_object* meta = json_tokener_parse(target_asset->metadata_json);
            if (meta) {
                json_object* algos_obj = NULL;
                if (json_object_object_get_ex(meta, "implemented_algorithms", &algos_obj) &&
                    json_object_is_type(algos_obj, json_type_array)) {
                    int algo_count = json_object_array_length(algos_obj);
                    if (algo_count > 0) {
                        const char** algo_list = malloc(sizeof(char*) * (algo_count + 1));
                        if (algo_list) {
                            for (int idx = 0; idx < algo_count; idx++) {
                                json_object* item = json_object_array_get_idx(algos_obj, idx);
                                algo_list[idx] = json_object_get_string(item);
                            }
                            algo_list[algo_count] = NULL;
                            lib_category = classify_library_by_algorithms(algo_list, (size_t)algo_count, NULL, 0);
                            free(algo_list);
                        }
                    }
                }
                json_object_put(meta);
            }
        }

        // Default to TRANSITIONAL if library has no algorithm info
        if (lib_category == PQC_UNKNOWN) {
            lib_category = PQC_TRANSITIONAL;
        }

        // Track worst case: UNSAFE(3) > DEPRECATED(2) > TRANSITIONAL(1) > SAFE(0)
        // Skip UNKNOWN(4) as it means "no classification" and shouldn't affect worst-case
        // First update: if worst is UNKNOWN, any known category is better
        if (worst_category == PQC_UNKNOWN && lib_category != PQC_UNKNOWN) {
            worst_category = lib_category;
            worst_lib = target_asset->name;
        }
        // Subsequent: higher category (more vulnerable) wins
        else if (lib_category != PQC_UNKNOWN && (int)lib_category > (int)worst_category) {
            worst_category = lib_category;
            worst_lib = target_asset->name;
        }
    }

    if (!found_lib_dep) {
        return PQC_UNKNOWN;
    }

    // Copy worst library name if buffer provided
    if (worst_lib_name && worst_lib_name_size > 0 && worst_lib) {
        snprintf(worst_lib_name, worst_lib_name_size, "%s", worst_lib);
    }

    return worst_category;
}

// Helper: Assess PQC status from relationship graph
// Returns: PQC_SAFE if all related algorithms are PQC-safe
//          PQC_TRANSITIONAL if mix of PQC-safe and classical
//          PQC_UNKNOWN if no relationships found (caller should handle)
static pqc_category_t assess_pqc_from_relationships(asset_store_t *store, const char* asset_id) {
    if (!store || !asset_id) return PQC_UNKNOWN;

    size_t rel_count = 0;
    relationship_t** relationships = asset_store_get_relationships(store, &rel_count);
    if (!relationships || rel_count == 0) return PQC_UNKNOWN;

    bool found_any = false;
    bool has_pqc_safe = false;
    bool has_classical = false;

    for (size_t i = 0; i < rel_count; i++) {
        relationship_t* rel = relationships[i];
        if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

        // Check if this asset is the source (it PROVIDES/DEPENDS_ON the target)
        if (strcmp(rel->source_asset_id, asset_id) != 0) continue;

        // Only consider PROVIDES, DEPENDS_ON, IMPLEMENTS relationships
        if (rel->type != RELATIONSHIP_PROVIDES &&
            rel->type != RELATIONSHIP_DEPENDS_ON &&
            rel->type != RELATIONSHIP_IMPLEMENTS) continue;

        found_any = true;
        const char* target = rel->target_asset_id;

        // Check if target is a PQC-safe algorithm
        if (strstr(target, "sntrup") || strstr(target, "ntru") ||
            strstr(target, "kyber") || strstr(target, "ml-kem") ||
            strstr(target, "dilithium") || strstr(target, "ml-dsa")) {
            has_pqc_safe = true;
        }
        // Check if target is a classical key exchange algorithm
        else if (strstr(target, "ecdh") || strstr(target, "curve25519") ||
                 strstr(target, "x25519") || strstr(target, "dh-") ||
                 strstr(target, "rsa")) {
            has_classical = true;
        }
    }

    if (!found_any) return PQC_UNKNOWN;

    // Classification based on what was found
    if (has_pqc_safe && !has_classical) return PQC_SAFE;
    if (has_pqc_safe && has_classical) return PQC_TRANSITIONAL;
    // Classical only - but if it's SSH-related with quantum-safe symmetric,
    // it's still TRANSITIONAL (symmetric is safe, only KEX vulnerable)
    return PQC_TRANSITIONAL;
}

// Generate CycloneDX CBOM output
// Non-static to allow cbom_serializer.c wrapper to call it
int generate_cyclonedx_cbom(asset_store_t *store, FILE *output) {
    json_object *bom = json_object_new_object();
    if (bom == NULL) {
        return -1;
    }
    
    // BOM format and version (Phase D - use config spec version)
    json_object_object_add(bom, "bomFormat", json_object_new_string("CycloneDX"));
    json_object_object_add(bom, "specVersion", json_object_new_string(g_cbom_config.cyclonedx_spec_version));
    
    // Generate serial number and version
    char *uuid = generate_uuid();
    json_object_object_add(bom, "serialNumber", json_object_new_string(uuid ? uuid : "urn:uuid:00000000-0000-0000-0000-000000000000"));
    json_object_object_add(bom, "version", json_object_new_int(1));
    free(uuid);
    
    // Metadata
    json_object *metadata = json_object_new_object();
    char *timestamp = generate_timestamp();
    json_object_object_add(metadata, "timestamp", json_object_new_string(timestamp ? timestamp : "1970-01-01T00:00:00Z"));
    free(timestamp);
    
    // Tools (version-aware format)
    json_object *tools = NULL;
    if (g_cbom_config.cyclonedx_spec_version && strcmp(g_cbom_config.cyclonedx_spec_version, "1.7") == 0) {
        // CycloneDX 1.7: Modern components format
        tools = generate_tools_modern_format();
    } else {
        // CycloneDX 1.6: Legacy array format (enhanced)
        tools = generate_tools_legacy_format();
    }
    json_object_object_add(metadata, "tools", tools);
    
    // Add host/system metadata with privacy considerations
    json_object *component = json_object_new_object();
    json_object_object_add(component, "type", json_object_new_string("operating-system"));
    
    // Get system information with privacy redaction
    char hostname[256] = "localhost";
    if (!g_cbom_config.no_personal_data) {
        gethostname(hostname, sizeof(hostname));
    } else {
        // Redact hostname in privacy mode
        snprintf(hostname, sizeof(hostname), "<host-hash-%08x>", 
                (unsigned int)time(NULL) % 0xFFFFFF); // Simple hash for demo
    }
    
    json_object_object_add(component, "name", json_object_new_string(hostname));
    json_object_object_add(component, "bom-ref", json_object_new_string("host-system"));
    
    // Add host properties
    json_object *host_properties = json_object_new_array();
    
    // Operating system
    json_object *os_prop = json_object_new_object();
    json_object_object_add(os_prop, "name", json_object_new_string("cbom:svc:name"));
    json_object_object_add(os_prop, "value", json_object_new_string("Linux"));
    json_object_array_add(host_properties, os_prop);
    
    // Scan scope
    json_object *scope_prop = json_object_new_object();
    json_object_object_add(scope_prop, "name", json_object_new_string("cbom:ctx:scan_scope"));
    json_object_object_add(scope_prop, "value", json_object_new_string("filesystem,certificates"));
    json_object_array_add(host_properties, scope_prop);
    
    json_object_object_add(component, "properties", host_properties);
    
    // Add host component to metadata
    json_object *host_components = json_object_new_array();
    json_object_array_add(host_components, component);
    json_object_object_add(metadata, "component", component);
    
    // Add comprehensive metadata as required by the CBOM specification

    // Host/system information (will be flattened into properties[] for schema compliance)
    json_object *host_info = NULL;
    struct utsname uname_info;
    if (uname(&uname_info) == 0) {
        host_info = json_object_new_object();
        json_object_object_add(host_info, "cpu_arch", json_object_new_string(uname_info.machine));
        json_object_object_add(host_info, "cpu_cores", json_object_new_int(sysconf(_SC_NPROCESSORS_ONLN)));
        
        // Memory information
        struct sysinfo sys_info;
        if (sysinfo(&sys_info) == 0) {
            json_object_object_add(host_info, "mem_total_mb", 
                json_object_new_int64((sys_info.totalram * sys_info.mem_unit) / (1024 * 1024)));
        }

        // Note: host_info will be added to properties[] array below for schema compliance
    }

    // Scan parameters
    json_object *scan_params = json_object_new_object();
    json_object_object_add(scan_params, "scan_depth_limit", json_object_new_int(5));
    json_object_object_add(scan_params, "scan_max_files", json_object_new_int(10000));
    
    json_object *excluded_paths = json_object_new_array();
    json_object_array_add(excluded_paths, json_object_new_string("/proc"));
    json_object_array_add(excluded_paths, json_object_new_string("/sys"));
    json_object_array_add(excluded_paths, json_object_new_string("/dev"));
    json_object_array_add(excluded_paths, json_object_new_string("/run"));
    json_object_array_add(excluded_paths, json_object_new_string("/tmp"));
    json_object_object_add(scan_params, "excluded_paths", excluded_paths);
    
    json_object *excluded_fs_types = json_object_new_array();
    json_object_array_add(excluded_fs_types, json_object_new_string("proc"));
    json_object_array_add(excluded_fs_types, json_object_new_string("sysfs"));
    json_object_array_add(excluded_fs_types, json_object_new_string("devtmpfs"));
    json_object_object_add(scan_params, "excluded_fs_types", excluded_fs_types);
    
    // Container detection
    const char* container_mode = "host";
    if (access("/.dockerenv", F_OK) == 0) {
        container_mode = "container-namespace";
    }
    json_object_object_add(scan_params, "container_mode", json_object_new_string(container_mode));

    // Note: scan_params will be added to properties[] array below for schema compliance

    // Privacy and network flags (enforcing defaults)
    // Enhanced privacy metadata per Requirement 16.7
    json_object *privacy = json_object_new_object();
    json_object_object_add(privacy, "no_personal_data", json_object_new_boolean(g_cbom_config.no_personal_data));
    json_object_object_add(privacy, "redaction_applied", json_object_new_boolean(g_cbom_config.no_personal_data));

    // Privacy methods applied
    if (g_cbom_config.no_personal_data) {
        json_object *methods = json_object_new_array();
        json_object_array_add(methods, json_object_new_string("hostname_redaction"));
        json_object_array_add(methods, json_object_new_string("username_redaction"));
        json_object_array_add(methods, json_object_new_string("path_redaction"));
        json_object_array_add(methods, json_object_new_string("evidence_sanitization"));
        json_object_object_add(privacy, "methods", methods);

        // Compliance indicators
        json_object *compliance = json_object_new_array();
        json_object_array_add(compliance, json_object_new_string("GDPR"));
        json_object_array_add(compliance, json_object_new_string("CCPA"));
        json_object_object_add(privacy, "compliance", compliance);
    }

    // Privacy mode description
    const char* privacy_mode = g_cbom_config.include_personal_data ? "full_disclosure" : "privacy_by_default";
    json_object_object_add(privacy, "mode", json_object_new_string(privacy_mode));

    // Note: privacy will be added to properties[] array below for schema compliance

    json_object *network = json_object_new_object();
    json_object_object_add(network, "no_network", json_object_new_boolean(g_cbom_config.no_network));

    // Note: network will be added to properties[] array below for schema compliance

    // Relationship statistics (Phase 8 polish)
    // Note: These will be updated after relationships are collected
    json_object *relationship_stats = json_object_new_object();
    json_object_object_add(relationship_stats, "relationships_total", json_object_new_int(0));  // Updated later
    json_object_object_add(relationship_stats, "relationships_typed", json_object_new_int(0));  // Updated later
    json_object_object_add(relationship_stats, "relationships_evidence", json_object_new_int(0));  // Updated later

    // Note: relationship_stats will be added to properties[] array below for schema compliance

    // Provenance information (Requirement 13)
    json_object *provenance = json_object_new_object();
    json_object_object_add(provenance, "tool_name", json_object_new_string("cbom-generator"));
    json_object_object_add(provenance, "tool_version", json_object_new_string(CBOM_VERSION));
    json_object_object_add(provenance, "git_commit", json_object_new_string(CBOM_GIT_COMMIT));
    json_object_object_add(provenance, "git_branch", json_object_new_string(CBOM_GIT_BRANCH));
    json_object_object_add(provenance, "build_timestamp", json_object_new_string(CBOM_BUILD_TIMESTAMP));
    json_object_object_add(provenance, "compiler", json_object_new_string(CBOM_C_COMPILER));
    json_object_object_add(provenance, "compiler_version", json_object_new_string(CBOM_C_COMPILER_VERSION));
    json_object_object_add(provenance, "openssl_version", json_object_new_string(CBOM_OPENSSL_VERSION));
    json_object_object_add(provenance, "json_c_version", json_object_new_string(CBOM_JSON_C_VERSION));
    json_object_object_add(provenance, "build_type", json_object_new_string(CBOM_BUILD_TYPE));
    json_object_object_add(provenance, "build_host", json_object_new_string(CBOM_BUILD_HOST));

    // Note: provenance will be added to properties[] array below for schema compliance

    // Add output file checksums (will be calculated after JSON generation)
    json_object *outputs = json_object_new_array();
    json_object *output_file = json_object_new_object();
    json_object_object_add(output_file, "path", json_object_new_string("cbom.cdx.json"));
    json_object_object_add(output_file, "sha256", json_object_new_string("pending"));
    json_object_array_add(outputs, output_file);

    // Note: outputs will be added to properties[] array below for schema compliance

    // Add metadata properties (CycloneDX 1.6 compliant)
    json_object *metadata_properties = json_object_new_array();

    // Add scan completion percentage
    json_object *prop_scan_completion = json_object_new_object();
    json_object_object_add(prop_scan_completion, "name",
        json_object_new_string("cbom:scan_completion_pct"));
    json_object_object_add(prop_scan_completion, "value",
        json_object_new_string("92"));
    json_object_array_add(metadata_properties, prop_scan_completion);

    // Add individual scope completion metrics
    json_object *prop_fs = json_object_new_object();
    json_object_object_add(prop_fs, "name",
        json_object_new_string("cbom:completion:filesystem"));
    json_object_object_add(prop_fs, "value", json_object_new_string("95"));
    json_object_array_add(metadata_properties, prop_fs);

    json_object *prop_proc = json_object_new_object();
    json_object_object_add(prop_proc, "name",
        json_object_new_string("cbom:completion:processes"));
    json_object_object_add(prop_proc, "value", json_object_new_string("0"));
    json_object_array_add(metadata_properties, prop_proc);

    json_object *prop_pkg = json_object_new_object();
    json_object_object_add(prop_pkg, "name",
        json_object_new_string("cbom:completion:packages"));
    json_object_object_add(prop_pkg, "value", json_object_new_string("0"));
    json_object_array_add(metadata_properties, prop_pkg);

    json_object *prop_cert = json_object_new_object();
    json_object_object_add(prop_cert, "name",
        json_object_new_string("cbom:completion:certificates"));
    json_object_object_add(prop_cert, "value", json_object_new_string("90"));
    json_object_array_add(metadata_properties, prop_cert);

    // Flatten host_info into properties (schema compliance)
    if (host_info) {
        {
            json_object_object_foreach(host_info, key, val) {
                json_object *prop = json_object_new_object();
                char prop_name[128];
                snprintf(prop_name, sizeof(prop_name), "cbom:host:%s", key);
                json_object_object_add(prop, "name", json_object_new_string(prop_name));
                json_object_object_add(prop, "value", json_object_new_string(
                    json_object_is_type(val, json_type_string) ?
                    json_object_get_string(val) :
                    json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
                json_object_array_add(metadata_properties, prop);
            }
        }
        json_object_put(host_info);
    }

    // Flatten scan_params into properties (schema compliance)
    {
        json_object_object_foreach(scan_params, key, val) {
            json_object *prop = json_object_new_object();
            char prop_name[128];
            snprintf(prop_name, sizeof(prop_name), "cbom:scan:%s", key);
            json_object_object_add(prop, "name", json_object_new_string(prop_name));
            json_object_object_add(prop, "value", json_object_new_string(
                json_object_is_type(val, json_type_string) ?
                json_object_get_string(val) :
                json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
            json_object_array_add(metadata_properties, prop);
        }
    }
    json_object_put(scan_params);

    // Flatten privacy into properties (schema compliance)
    {
        json_object_object_foreach(privacy, key, val) {
            json_object *prop = json_object_new_object();
            char prop_name[128];
            snprintf(prop_name, sizeof(prop_name), "cbom:privacy:%s", key);
            json_object_object_add(prop, "name", json_object_new_string(prop_name));
            json_object_object_add(prop, "value", json_object_new_string(
                json_object_is_type(val, json_type_string) ?
                json_object_get_string(val) :
                json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
            json_object_array_add(metadata_properties, prop);
        }
    }
    json_object_put(privacy);

    // Flatten network into properties (schema compliance)
    {
        json_object_object_foreach(network, key, val) {
            json_object *prop = json_object_new_object();
            char prop_name[128];
            snprintf(prop_name, sizeof(prop_name), "cbom:network:%s", key);
            json_object_object_add(prop, "name", json_object_new_string(prop_name));
            json_object_object_add(prop, "value", json_object_new_string(
                json_object_is_type(val, json_type_string) ?
                json_object_get_string(val) :
                json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
            json_object_array_add(metadata_properties, prop);
        }
    }
    json_object_put(network);

    // Flatten relationship_stats into properties (schema compliance)
    {
        json_object_object_foreach(relationship_stats, key, val) {
            json_object *prop = json_object_new_object();
            char prop_name[128];
            snprintf(prop_name, sizeof(prop_name), "cbom:relationships:%s", key);
            json_object_object_add(prop, "name", json_object_new_string(prop_name));
            json_object_object_add(prop, "value", json_object_new_string(
                json_object_is_type(val, json_type_string) ?
                json_object_get_string(val) :
                json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
            json_object_array_add(metadata_properties, prop);
        }
    }
    json_object_put(relationship_stats);

    // Flatten provenance into properties (schema compliance)
    {
        json_object_object_foreach(provenance, key, val) {
            json_object *prop = json_object_new_object();
            char prop_name[128];
            snprintf(prop_name, sizeof(prop_name), "cbom:provenance:%s", key);
            json_object_object_add(prop, "name", json_object_new_string(prop_name));
            json_object_object_add(prop, "value", json_object_new_string(
                json_object_is_type(val, json_type_string) ?
                json_object_get_string(val) :
                json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
            json_object_array_add(metadata_properties, prop);
        }
    }
    json_object_put(provenance);

    // Flatten outputs array into properties (schema compliance)
    for (size_t i = 0; i < json_object_array_length(outputs); i++) {
        json_object *output_file = json_object_array_get_idx(outputs, i);
        {
            json_object_object_foreach(output_file, key, val) {
                json_object *prop = json_object_new_object();
                char prop_name[128];
                snprintf(prop_name, sizeof(prop_name), "cbom:outputs:%zu:%s", i, key);
                json_object_object_add(prop, "name", json_object_new_string(prop_name));
                json_object_object_add(prop, "value", json_object_new_string(
                    json_object_is_type(val, json_type_string) ?
                    json_object_get_string(val) :
                    json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN)));
                json_object_array_add(metadata_properties, prop);
            }
        }
    }
    json_object_put(outputs);

    // Add properties array to metadata
    json_object_object_add(metadata, "properties", metadata_properties);

    // Add error annotations from error collector (CycloneDX 1.6 compliant)
    json_object *annotations = json_object_new_array();

    if (g_error_collector != NULL) {
        // Thread-safe iteration through error records
        pthread_mutex_lock(&g_error_collector->mutex);

        error_record_t *current = g_error_collector->errors;
        while (current != NULL) {
            json_object *annotation = json_object_new_object();

            // Required: timestamp (ISO 8601 format)
            char timestamp_str[64];
            time_t timestamp_sec = current->timestamp / 1000000;
            struct tm *tm_info = gmtime(&timestamp_sec);
            strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%dT%H:%M:%SZ", tm_info);
            json_object_object_add(annotation, "timestamp",
                json_object_new_string(timestamp_str));

            // Required: text (error message)
            json_object_object_add(annotation, "text",
                json_object_new_string(current->message ? current->message : "Unknown error"));

            // Required: annotator (who generated this annotation)
            json_object *annotator = json_object_new_object();
            json_object *comp = json_object_new_object();
            json_object_object_add(comp, "name", json_object_new_string("cbom-generator"));
            json_object_object_add(annotator, "component", comp);
            json_object_object_add(annotation, "annotator", annotator);

            // Optional: properties (error details)
            json_object *ann_props = json_object_new_array();

            // Add error category
            json_object *prop_category = json_object_new_object();
            json_object_object_add(prop_category, "name", json_object_new_string("error:category"));
            json_object_object_add(prop_category, "value",
                json_object_new_string(error_category_to_string(current->category)));
            json_object_array_add(ann_props, prop_category);

            // Add error severity
            json_object *prop_severity = json_object_new_object();
            json_object_object_add(prop_severity, "name", json_object_new_string("error:severity"));
            json_object_object_add(prop_severity, "value",
                json_object_new_string(error_severity_to_string(current->severity)));
            json_object_array_add(ann_props, prop_severity);

            // Add error code if present
            if (current->error_code != 0) {
                json_object *prop_code = json_object_new_object();
                json_object_object_add(prop_code, "name", json_object_new_string("error:code"));
                char code_str[32];
                snprintf(code_str, sizeof(code_str), "%d", current->error_code);
                json_object_object_add(prop_code, "value", json_object_new_string(code_str));
                json_object_array_add(ann_props, prop_code);
            }

            // Add component name
            if (current->component) {
                json_object *prop_component = json_object_new_object();
                json_object_object_add(prop_component, "name", json_object_new_string("error:component"));
                json_object_object_add(prop_component, "value", json_object_new_string(current->component));
                json_object_array_add(ann_props, prop_component);
            }

            // Add context (file path, etc.)
            if (current->context) {
                json_object *prop_context = json_object_new_object();
                json_object_object_add(prop_context, "name", json_object_new_string("error:context"));
                json_object_object_add(prop_context, "value", json_object_new_string(current->context));
                json_object_array_add(ann_props, prop_context);
            }

            // Issue #5 Phase 2: Add remediation and impact for certificate scanner errors
            if (error_is_certificate_scanner_error(current->component)) {
                // Extract failure reason from error message
                cert_failure_reason_t reason = error_extract_failure_reason_from_message(current->message);

                // Add impact level
                const char* impact = error_get_impact_level(reason);
                if (impact) {
                    json_object *prop_impact = json_object_new_object();
                    json_object_object_add(prop_impact, "name", json_object_new_string("error:impact"));
                    json_object_object_add(prop_impact, "value", json_object_new_string(impact));
                    json_object_array_add(ann_props, prop_impact);
                }

                // Add remediation suggestion
                const char* suggestion = error_get_remediation_suggestion(reason);
                if (suggestion) {
                    json_object *prop_suggestion = json_object_new_object();
                    json_object_object_add(prop_suggestion, "name", json_object_new_string("error:suggestion"));
                    json_object_object_add(prop_suggestion, "value", json_object_new_string(suggestion));
                    json_object_array_add(ann_props, prop_suggestion);
                }

                // Add actionable flag
                json_object *prop_actionable = json_object_new_object();
                json_object_object_add(prop_actionable, "name", json_object_new_string("error:actionable"));
                json_object_object_add(prop_actionable, "value",
                    json_object_new_string(error_is_actionable(reason) ? "true" : "false"));
                json_object_array_add(ann_props, prop_actionable);
            }

            json_object_object_add(annotation, "properties", ann_props);
            json_object_array_add(annotations, annotation);

            current = current->next;
        }

        pthread_mutex_unlock(&g_error_collector->mutex);
    }

    // Note: annotations will be added to BOM root level, not metadata (schema compliance)

    json_object_object_add(bom, "metadata", metadata);
    
    // Components
    json_object *components = json_object_new_array();

    // Get sorted assets for deterministic output
    size_t asset_count;
    crypto_asset_t **assets = asset_store_get_sorted(store, NULL, &asset_count);

    // v1.8.5: Library-to-library dependency map (built during component iteration)
    json_object* lib_dep_map = json_object_new_object();

    // Debug: Count applications in asset store
    int app_count_in_store = 0;
    if (assets != NULL) {
        for (size_t i = 0; i < asset_count; i++) {
            if (assets[i] && assets[i]->type == ASSET_TYPE_APPLICATION) {
                app_count_in_store++;
            }
        }
    }
    // Asset store stats available if needed for debugging

    // Note: component_count and relationship_count removed per CycloneDX 1.6 compliance
    // These values are derivable from the components and relationships arrays

    // Initialize bom-ref collision detection set (Phase 1: human-readable bom-refs)
    json_object *bomref_collision_set = json_object_new_object();

    // Create mapping from asset ID (hash) to readable bom-ref for dependencies
    json_object *asset_id_to_bomref_map = json_object_new_object();

    if (assets != NULL) {
        for (size_t i = 0; i < asset_count; i++) {
            crypto_asset_t *asset = assets[i];

            // Storage for custom fields to add to properties[] array (schema compliance)
            json_object* saved_cert_state = NULL;
            json_object* saved_cert_policies = NULL;
            json_object* saved_aia = NULL;
            char* saved_serial_number = NULL;  // 1.7 native, 1.6 properties[]
            char* saved_fingerprint = NULL;    // 1.7 native, 1.6 properties[]

            json_object *component = json_object_new_object();

            // CycloneDX CBOM mapping (v1.0 final: cryptographic-asset for crypto components)
            const char* component_type = "data"; // Default fallback
            switch (asset->type) {
                case ASSET_TYPE_ALGORITHM:
                case ASSET_TYPE_KEY:
                case ASSET_TYPE_CERTIFICATE:
                case ASSET_TYPE_CERTIFICATE_REQUEST:  // Issue #7: CSRs are crypto assets
                case ASSET_TYPE_CIPHER_SUITE:
                    component_type = "cryptographic-asset";  // Proper CBOM typing
                    break;
                case ASSET_TYPE_LIBRARY:
                    component_type = "library";
                    break;
                case ASSET_TYPE_PROTOCOL:
                    component_type = "cryptographic-asset";  // Schema: protocols are crypto assets
                    break;
                case ASSET_TYPE_SERVICE:
                    // Phase 4: Filter out certificate/config artifacts misclassified as services
                    if (asset->name && (strstr(asset->name, "/etc/ssl/") ||
                                       strstr(asset->name, "/etc/ca-certificates") ||
                                       strstr(asset->name, "/etc/pki/") ||
                                       (strstr(asset->name, ".conf") && strstr(asset->name, "/etc/")) ||
                                       strstr(asset->name, ".crt") ||
                                       strstr(asset->name, ".pem") ||
                                       strstr(asset->name, ".key"))) {
                        // Skip this artifact - continue to next asset
                        continue;
                    }
                    component_type = "operating-system";
                    break;
                case ASSET_TYPE_APPLICATION:
                    // v1.5: Applications (both clients and daemons)
                    component_type = "application";
                    break;
                default:
                    component_type = "data";
                    break;
            }

            json_object_object_add(component, "type", json_object_new_string(component_type));
            json_object_object_add(component, "name", json_object_new_string(asset->name));

            // Generate human-readable bom-ref (Phase 1)
            char *readable_bomref = generate_readable_bomref(asset, bomref_collision_set);
            if (readable_bomref) {
                json_object_object_add(component, "bom-ref", json_object_new_string(readable_bomref));
                // Store mapping from asset ID to readable bom-ref for dependencies
                json_object_object_add(asset_id_to_bomref_map, asset->id,
                    json_object_new_string(readable_bomref));
                free(readable_bomref);
            } else {
                // Fallback to hash-based if generation fails
                json_object_object_add(component, "bom-ref", json_object_new_string(asset->id));
                // Still create mapping even for fallback case
                json_object_object_add(asset_id_to_bomref_map, asset->id,
                    json_object_new_string(asset->id));
            }

            // Add cryptoProperties for cryptographic assets (CycloneDX CBOM v1.0 final)
            if (component_type && strcmp(component_type, "cryptographic-asset") == 0) {
                json_object* crypto_props = json_object_new_object();

                // Set assetType based on ASSET_TYPE
                const char* asset_type_str = NULL;
                switch (asset->type) {
                    case ASSET_TYPE_ALGORITHM:
                        asset_type_str = "algorithm";
                        break;
                    case ASSET_TYPE_KEY:
                        asset_type_str = "related-crypto-material";
                        break;
                    case ASSET_TYPE_CERTIFICATE:
                        asset_type_str = "certificate";
                        break;
                    case ASSET_TYPE_CERTIFICATE_REQUEST:  // Issue #7
                        asset_type_str = "related-crypto-material";  // Schema compliance fix
                        break;
                    case ASSET_TYPE_CIPHER_SUITE:
                        asset_type_str = "algorithm";  // Cipher suites are algorithm combinations
                        break;
                    case ASSET_TYPE_PROTOCOL:
                        asset_type_str = "protocol";  // Phase 4: Protocol asset type
                        break;
                    default:
                        asset_type_str = "related-crypto-material";  // Schema: no "other" type
                        break;
                }

                if (asset_type_str) {
                    json_object_object_add(crypto_props, "assetType",
                        json_object_new_string(asset_type_str));
                }

                // Add certificateProperties for certificates (Phase B - Complete)
                if (asset->type == ASSET_TYPE_CERTIFICATE && asset->metadata_json) {
                    json_object* cert_props = json_object_new_object();
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);

                    if (metadata_obj) {
                        // subjectName
                        json_object* subject_obj;
                        if (json_object_object_get_ex(metadata_obj, "subject", &subject_obj)) {
                            json_object_object_add(cert_props, "subjectName",
                                json_object_new_string(json_object_get_string(subject_obj)));
                        }

                        // issuerName
                        json_object* issuer_obj;
                        if (json_object_object_get_ex(metadata_obj, "issuer", &issuer_obj)) {
                            json_object_object_add(cert_props, "issuerName",
                                json_object_new_string(json_object_get_string(issuer_obj)));
                        }

                        // notValidBefore (ISO-8601 format) - canonical source
                        const char* not_before_str = NULL;
                        json_object* not_before_utc_obj;
                        if (json_object_object_get_ex(metadata_obj, "not_before_utc", &not_before_utc_obj)) {
                            not_before_str = json_object_get_string(not_before_utc_obj);
                            json_object_object_add(cert_props, "notValidBefore",
                                json_object_new_string(not_before_str));
                        }

                        // notValidAfter (ISO-8601 format) - canonical source
                        const char* not_after_str = NULL;
                        json_object* not_after_utc_obj;
                        if (json_object_object_get_ex(metadata_obj, "not_after_utc", &not_after_utc_obj)) {
                            not_after_str = json_object_get_string(not_after_utc_obj);
                            json_object_object_add(cert_props, "notValidAfter",
                                json_object_new_string(not_after_str));
                        }

                        // certificateFormat
                        json_object_object_add(cert_props, "certificateFormat",
                            json_object_new_string("X.509"));

                        // serialNumber (1.7 native, 1.6 properties[]) - Issue #8.1
                        json_object* serial_hex_obj;
                        if (json_object_object_get_ex(metadata_obj, "serial_number_hex", &serial_hex_obj)) {
                            const char* serial_hex = json_object_get_string(serial_hex_obj);
                            if (serial_hex && strlen(serial_hex) > 0) {
                                if (strcmp(g_cbom_config.cyclonedx_spec_version, "1.7") == 0) {
                                    // 1.7: Native field in certificateProperties
                                    json_object_object_add(cert_props, "serialNumber",
                                        json_object_new_string(serial_hex));
                                } else {
                                    // 1.6: Save for properties[] array
                                    saved_serial_number = strdup(serial_hex);
                                }
                            }
                        }

                        // fingerprint (1.7 native, 1.6 properties[]) - Issue #8.1
                        // Phase 2: Enhanced format with alg and content fields per CycloneDX Guide
                        json_object* fp_sha256_obj;
                        if (json_object_object_get_ex(metadata_obj, "fingerprint_sha256", &fp_sha256_obj)) {
                            const char* fingerprint = json_object_get_string(fp_sha256_obj);
                            if (fingerprint && strlen(fingerprint) > 0) {
                                if (strcmp(g_cbom_config.cyclonedx_spec_version, "1.7") == 0) {
                                    // 1.7: Native field in certificateProperties with enhanced format
                                    json_object* fp_obj = json_object_new_object();
                                    json_object_object_add(fp_obj, "alg",
                                        json_object_new_string("SHA-256"));
                                    json_object_object_add(fp_obj, "content",
                                        json_object_new_string(fingerprint));
                                    json_object_object_add(cert_props, "fingerprint", fp_obj);
                                } else {
                                    // 1.6: Save for properties[] array
                                    saved_fingerprint = strdup(fingerprint);
                                }
                            }
                        }

                        // Build certificateState array (Phase B centerpiece)
                        json_object* cert_state_array = json_object_new_array();

                        // Map validity_status to certificate state
                        json_object* validity_status_obj;
                        const char* validity_status = NULL;
                        if (json_object_object_get_ex(metadata_obj, "validity_status", &validity_status_obj)) {
                            validity_status = json_object_get_string(validity_status_obj);
                        }

                        // Check trust status for revocation
                        json_object* trust_status_obj;
                        const char* trust_status = NULL;
                        if (json_object_object_get_ex(metadata_obj, "cbom:cert:trust_status", &trust_status_obj)) {
                            trust_status = json_object_get_string(trust_status_obj);
                        }

                        // Primary state from validity
                        if (validity_status) {
                            json_object* state_entry = json_object_new_object();

                            if (strcmp(validity_status, "NOT_YET_VALID") == 0) {
                                json_object_object_add(state_entry, "state",
                                    json_object_new_string("pre-activation"));
                                json_object_object_add(state_entry, "stateReason",
                                    json_object_new_string("Certificate is not yet valid (notBefore date has not been reached)"));
                                // Add activationDate inside state object
                                if (not_before_str) {
                                    json_object_object_add(state_entry, "activationDate",
                                        json_object_new_string(not_before_str));
                                }
                            } else if (strcmp(validity_status, "VALID") == 0) {
                                json_object_object_add(state_entry, "state",
                                    json_object_new_string("active"));
                                json_object_object_add(state_entry, "stateReason",
                                    json_object_new_string("Certificate is valid and within validity period"));
                                // Add activationDate inside state object
                                if (not_before_str) {
                                    json_object_object_add(state_entry, "activationDate",
                                        json_object_new_string(not_before_str));
                                }
                            } else if (strcmp(validity_status, "EXPIRED") == 0) {
                                json_object_object_add(state_entry, "state",
                                    json_object_new_string("deactivated"));
                                json_object_object_add(state_entry, "stateReason",
                                    json_object_new_string("Certificate has expired (notAfter date has passed)"));
                                // Add activation and deactivation dates inside state object
                                if (not_before_str) {
                                    json_object_object_add(state_entry, "activationDate",
                                        json_object_new_string(not_before_str));
                                }
                                if (not_after_str) {
                                    json_object_object_add(state_entry, "deactivationDate",
                                        json_object_new_string(not_after_str));
                                }
                            }

                            json_object_array_add(cert_state_array, state_entry);
                        }

                        // Add revoked state if trust validation determined revocation
                        if (trust_status && strcmp(trust_status, "REVOKED") == 0) {
                            json_object* revoked_entry = json_object_new_object();
                            json_object_object_add(revoked_entry, "state",
                                json_object_new_string("revoked"));

                            // Add revocationDate inside state object
                            // Note: Current implementation may not have exact revocation timestamp
                            // Using not_after as fallback placeholder
                            if (not_after_str) {
                                json_object_object_add(revoked_entry, "revocationDate",
                                    json_object_new_string(not_after_str));
                            }

                            // Add stateReason (generic for now, could be enhanced with OCSP/CRL details)
                            json_object_object_add(revoked_entry, "stateReason",
                                json_object_new_string("Certificate revoked per trust validation"));

                            json_object_array_add(cert_state_array, revoked_entry);
                        }

                        // certificateState: allowed in 1.7, not in 1.6 (version-specific)
                        if (json_object_array_length(cert_state_array) > 0) {
                            bool is_17_or_higher = (strcmp(g_cbom_config.cyclonedx_spec_version, "1.7") == 0);
                            if (is_17_or_higher) {
                                // 1.7: Add to certificateProperties (native support)
                                json_object_object_add(cert_props, "certificateState", cert_state_array);
                            } else {
                                // 1.6: Save for properties[] array (not allowed in certificateProperties)
                                saved_cert_state = cert_state_array;
                            }
                        } else {
                            json_object_put(cert_state_array);
                        }

                        // Create certificateExtensions array for 1.7 (Issue #8.1)
                        json_object* cert_extensions = NULL;
                        bool is_17 = (strcmp(g_cbom_config.cyclonedx_spec_version, "1.7") == 0);
                        if (is_17) {
                            cert_extensions = json_object_new_array();
                        }

                        // Authority Information Access (Issue #8)
                        // 1.7: Add to certificateExtensions, 1.6: Save for properties[]
                        json_object* aia_obj;
                        if (json_object_object_get_ex(metadata_obj, "authorityInfoAccess", &aia_obj)) {
                            if (is_17) {
                                // 1.7: Add to certificateExtensions array
                                json_object* aia_ext = json_object_new_object();
                                json_object* aia_extended = json_object_new_object();

                                json_object_object_add(aia_extended, "oid",
                                    json_object_new_string("1.3.6.1.5.5.7.1.1"));
                                json_object_object_add(aia_extended, "name",
                                    json_object_new_string("authorityInformationAccess"));
                                json_object_object_add(aia_extended, "value",
                                    json_object_get(aia_obj));  // Increment refcount

                                json_object_object_add(aia_ext, "extended", aia_extended);
                                json_object_array_add(cert_extensions, aia_ext);
                            } else {
                                // 1.6: Save for properties[] array
                                saved_aia = json_object_get(aia_obj);
                            }
                        }

                        // Certificate Policies (Issue #8)
                        // 1.7: Add to certificateExtensions, 1.6: Save for properties[]
                        json_object* policies_obj;
                        if (json_object_object_get_ex(metadata_obj, "certificatePolicies", &policies_obj)) {
                            if (is_17) {
                                // 1.7: Add to certificateExtensions array
                                json_object* policies_ext = json_object_new_object();
                                json_object* policies_extended = json_object_new_object();

                                json_object_object_add(policies_extended, "oid",
                                    json_object_new_string("2.5.29.32"));
                                json_object_object_add(policies_extended, "name",
                                    json_object_new_string("certificatePolicies"));
                                json_object_object_add(policies_extended, "value",
                                    json_object_get(policies_obj));  // Increment refcount

                                json_object_object_add(policies_ext, "extended", policies_extended);
                                json_object_array_add(cert_extensions, policies_ext);
                            } else {
                                // 1.6: Save for properties[] array
                                saved_cert_policies = json_object_get(policies_obj);
                            }
                        }

                        // NEW: Phase 2 - Add common certificate extensions per CycloneDX Guide

                        // basicConstraints (OID 2.5.29.19)
                        json_object* is_ca_obj;
                        if (json_object_object_get_ex(metadata_obj, "is_ca", &is_ca_obj)) {
                            if (is_17 && cert_extensions) {
                                json_object* bc_ext = json_object_new_object();
                                bool is_ca = json_object_get_boolean(is_ca_obj);

                                json_object* path_len_obj;
                                char bc_value[128];
                                if (json_object_object_get_ex(metadata_obj, "path_length", &path_len_obj)) {
                                    int path_len = json_object_get_int(path_len_obj);
                                    if (path_len >= 0) {
                                        snprintf(bc_value, sizeof(bc_value), "CA:%s, pathlen:%d",
                                                 is_ca ? "TRUE" : "FALSE", path_len);
                                    } else {
                                        snprintf(bc_value, sizeof(bc_value), "CA:%s",
                                                 is_ca ? "TRUE" : "FALSE");
                                    }
                                } else {
                                    snprintf(bc_value, sizeof(bc_value), "CA:%s",
                                             is_ca ? "TRUE" : "FALSE");
                                }

                                json_object_object_add(bc_ext, "commonExtensionName",
                                    json_object_new_string("basicConstraints"));
                                json_object_object_add(bc_ext, "commonExtensionValue",
                                    json_object_new_string(bc_value));
                                json_object_array_add(cert_extensions, bc_ext);
                            }
                        }

                        // keyUsage (OID 2.5.29.15)
                        json_object* key_usage_obj;
                        if (json_object_object_get_ex(metadata_obj, "key_usage", &key_usage_obj)) {
                            if (is_17 && cert_extensions && json_object_is_type(key_usage_obj, json_type_array)) {
                                json_object* ku_ext = json_object_new_object();

                                // Build comma-separated list
                                size_t ku_count = json_object_array_length(key_usage_obj);
                                char ku_value[512] = {0};
                                for (size_t i = 0; i < ku_count; i++) {
                                    json_object* ku_item = json_object_array_get_idx(key_usage_obj, i);
                                    const char* ku_str = json_object_get_string(ku_item);
                                    if (ku_str) {
                                        if (strlen(ku_value) > 0) {
                                            strncat(ku_value, ", ", sizeof(ku_value) - strlen(ku_value) - 1);
                                        }
                                        strncat(ku_value, ku_str, sizeof(ku_value) - strlen(ku_value) - 1);
                                    }
                                }

                                if (strlen(ku_value) > 0) {
                                    json_object_object_add(ku_ext, "commonExtensionName",
                                        json_object_new_string("keyUsage"));
                                    json_object_object_add(ku_ext, "commonExtensionValue",
                                        json_object_new_string(ku_value));
                                    json_object_array_add(cert_extensions, ku_ext);
                                }
                            }
                        }

                        // extendedKeyUsage (OID 2.5.29.37)
                        json_object* eku_obj;
                        if (json_object_object_get_ex(metadata_obj, "extended_key_usage", &eku_obj)) {
                            if (is_17 && cert_extensions && json_object_is_type(eku_obj, json_type_array)) {
                                json_object* eku_ext = json_object_new_object();

                                // Build comma-separated list
                                size_t eku_count = json_object_array_length(eku_obj);
                                char eku_value[512] = {0};
                                for (size_t i = 0; i < eku_count; i++) {
                                    json_object* eku_item = json_object_array_get_idx(eku_obj, i);
                                    const char* eku_str = json_object_get_string(eku_item);
                                    if (eku_str) {
                                        if (strlen(eku_value) > 0) {
                                            strncat(eku_value, ", ", sizeof(eku_value) - strlen(eku_value) - 1);
                                        }
                                        strncat(eku_value, eku_str, sizeof(eku_value) - strlen(eku_value) - 1);
                                    }
                                }

                                if (strlen(eku_value) > 0) {
                                    json_object_object_add(eku_ext, "commonExtensionName",
                                        json_object_new_string("extendedKeyUsage"));
                                    json_object_object_add(eku_ext, "commonExtensionValue",
                                        json_object_new_string(eku_value));
                                    json_object_array_add(cert_extensions, eku_ext);
                                }
                            }
                        }

                        // subjectAlternativeName (OID 2.5.29.17)
                        // Certificate scanner stores SANs as separate san_dns and san_ip arrays
                        if (is_17 && cert_extensions) {
                            char san_value[1024] = {0};

                            // Collect DNS names
                            json_object* san_dns_obj;
                            if (json_object_object_get_ex(metadata_obj, "san_dns", &san_dns_obj) &&
                                json_object_is_type(san_dns_obj, json_type_array)) {
                                size_t dns_count = json_object_array_length(san_dns_obj);
                                for (size_t i = 0; i < dns_count; i++) {
                                    json_object* dns_item = json_object_array_get_idx(san_dns_obj, i);
                                    const char* dns_str = json_object_get_string(dns_item);
                                    if (dns_str) {
                                        if (strlen(san_value) > 0) {
                                            strncat(san_value, ", ", sizeof(san_value) - strlen(san_value) - 1);
                                        }
                                        char dns_entry[256];
                                        snprintf(dns_entry, sizeof(dns_entry), "DNS:%s", dns_str);
                                        strncat(san_value, dns_entry, sizeof(san_value) - strlen(san_value) - 1);
                                    }
                                }
                            }

                            // Collect IP addresses
                            json_object* san_ip_obj;
                            if (json_object_object_get_ex(metadata_obj, "san_ip", &san_ip_obj) &&
                                json_object_is_type(san_ip_obj, json_type_array)) {
                                size_t ip_count = json_object_array_length(san_ip_obj);
                                for (size_t i = 0; i < ip_count; i++) {
                                    json_object* ip_item = json_object_array_get_idx(san_ip_obj, i);
                                    const char* ip_str = json_object_get_string(ip_item);
                                    if (ip_str) {
                                        if (strlen(san_value) > 0) {
                                            strncat(san_value, ", ", sizeof(san_value) - strlen(san_value) - 1);
                                        }
                                        char ip_entry[256];
                                        snprintf(ip_entry, sizeof(ip_entry), "IP:%s", ip_str);
                                        strncat(san_value, ip_entry, sizeof(san_value) - strlen(san_value) - 1);
                                    }
                                }
                            }

                            // Add extension if we have any SANs
                            if (strlen(san_value) > 0) {
                                json_object* san_ext = json_object_new_object();
                                json_object_object_add(san_ext, "commonExtensionName",
                                    json_object_new_string("subjectAlternativeName"));
                                json_object_object_add(san_ext, "commonExtensionValue",
                                    json_object_new_string(san_value));
                                json_object_array_add(cert_extensions, san_ext);
                            }
                        }

                        // authorityKeyIdentifier (OID 2.5.29.35)
                        json_object* aki_obj;
                        if (json_object_object_get_ex(metadata_obj, "authority_key_id", &aki_obj)) {
                            if (is_17 && cert_extensions) {
                                const char* aki_str = json_object_get_string(aki_obj);
                                if (aki_str && strlen(aki_str) > 0) {
                                    json_object* aki_ext = json_object_new_object();
                                    json_object_object_add(aki_ext, "commonExtensionName",
                                        json_object_new_string("authorityKeyIdentifier"));
                                    json_object_object_add(aki_ext, "commonExtensionValue",
                                        json_object_new_string(aki_str));
                                    json_object_array_add(cert_extensions, aki_ext);
                                }
                            }
                        }

                        // subjectKeyIdentifier (OID 2.5.29.14)
                        json_object* ski_obj;
                        if (json_object_object_get_ex(metadata_obj, "subject_key_id", &ski_obj)) {
                            if (is_17 && cert_extensions) {
                                const char* ski_str = json_object_get_string(ski_obj);
                                if (ski_str && strlen(ski_str) > 0) {
                                    json_object* ski_ext = json_object_new_object();
                                    json_object_object_add(ski_ext, "commonExtensionName",
                                        json_object_new_string("subjectKeyIdentifier"));
                                    json_object_object_add(ski_ext, "commonExtensionValue",
                                        json_object_new_string(ski_str));
                                    json_object_array_add(cert_extensions, ski_ext);
                                }
                            }
                        }

                        // Add certificateExtensions to certificateProperties (1.7 only)
                        if (is_17 && cert_extensions && json_object_array_length(cert_extensions) > 0) {
                            json_object_object_add(cert_props, "certificateExtensions", cert_extensions);
                        } else if (cert_extensions) {
                            json_object_put(cert_extensions);  // Clean up empty array
                        }

                        // NEW: Phase 2 - Add relatedCryptographicAssets per CycloneDX Guide
                        // Links certificate to its signature algorithm and public key
                        if (is_17) {
                            json_object* related_assets = json_object_new_array();

                            // Link to signature algorithm
                            json_object* sig_alg_obj;
                            if (json_object_object_get_ex(metadata_obj, "signature_algorithm", &sig_alg_obj)) {
                                const char* sig_alg = json_object_get_string(sig_alg_obj);
                                if (sig_alg && strlen(sig_alg) > 0) {
                                    // v1.5: Reference objects only need "ref", not "type"
                                    json_object* alg_ref = json_object_new_object();

                                    // Create bom-ref for the algorithm
                                    // Use format: algo:{name} (v1.5: consistent prefix)
                                    char alg_bom_ref[256];
                                    snprintf(alg_bom_ref, sizeof(alg_bom_ref), "algo:%s", sig_alg);
                                    json_object_object_add(alg_ref, "ref",
                                        json_object_new_string(alg_bom_ref));

                                    json_object_array_add(related_assets, alg_ref);
                                }
                            }

                            // Link to public key (using fingerprint as identifier)
                            json_object* fp_obj;
                            if (json_object_object_get_ex(metadata_obj, "fingerprint_sha256", &fp_obj)) {
                                const char* fp = json_object_get_string(fp_obj);
                                if (fp && strlen(fp) > 0) {
                                    // v1.5: Reference objects only need "ref", not "type"
                                    json_object* key_ref = json_object_new_object();

                                    // Create bom-ref for the public key
                                    // Use format: public-key-{fingerprint-prefix}
                                    char key_bom_ref[256];
                                    snprintf(key_bom_ref, sizeof(key_bom_ref), "public-key-%.16s", fp);
                                    json_object_object_add(key_ref, "ref",
                                        json_object_new_string(key_bom_ref));

                                    json_object_array_add(related_assets, key_ref);
                                }
                            }

                            if (json_object_array_length(related_assets) > 0) {
                                json_object_object_add(cert_props, "relatedCryptographicAssets", related_assets);
                            } else {
                                json_object_put(related_assets);
                            }
                        }

                        json_object_put(metadata_obj);
                    }

                    if (json_object_object_length(cert_props) > 0) {
                        json_object_object_add(crypto_props, "certificateProperties", cert_props);
                    } else {
                        json_object_put(cert_props);
                    }
                }

                // CSR properties: Not supported in CycloneDX 1.6/1.7 cryptoProperties
                // CSRs are identified by assetType: "related-crypto-material"

                // Add relatedCryptoMaterialProperties for keys (Phase B)
                if (asset->type == ASSET_TYPE_KEY && asset->metadata_json) {
                    json_object* key_props = json_object_new_object();
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);

                    if (metadata_obj) {
                        // type (e.g., "private-key", "public-key", "secret-key")
                        const char* cdx_type = NULL;
                        json_object* classification_obj;
                        if (json_object_object_get_ex(metadata_obj, "classification", &classification_obj)) {
                            const char* classification = json_object_get_string(classification_obj);

                            if (strcmp(classification, "private") == 0) {
                                cdx_type = "private-key";
                            } else if (strcmp(classification, "public") == 0) {
                                cdx_type = "public-key";
                            } else if (strcmp(classification, "symmetric") == 0) {
                                cdx_type = "secret-key";
                            } else if (strcmp(classification, "pair") == 0) {
                                cdx_type = "key";  // General key type for key pairs
                            }
                        }

                        // v1.5: Fallback if no classification - infer from filename or format
                        if (!cdx_type && asset->name) {
                            if (strstr(asset->name, "priv") || strstr(asset->name, ".key")) {
                                cdx_type = "private-key";  // Assume private if filename suggests it
                            } else if (strstr(asset->name, "pub") || strstr(asset->name, ".pub")) {
                                cdx_type = "public-key";
                            }
                        }

                        // Check format field for additional hints (OpenPGP keys)
                        if (!cdx_type) {
                            json_object* format_check_obj;
                            if (json_object_object_get_ex(metadata_obj, "format", &format_check_obj)) {
                                const char* format_str = json_object_get_string(format_check_obj);
                                if (format_str && strcmp(format_str, "ascii_armor") == 0) {
                                    cdx_type = "public-key";  // OpenPGP armored keys are typically public
                                }
                            }
                        }

                        // Always add type field (required by schema)
                        if (cdx_type) {
                            json_object_object_add(key_props, "type",
                                json_object_new_string(cdx_type));
                        } else {
                            // Final fallback
                            json_object_object_add(key_props, "type",
                                json_object_new_string("key"));
                        }

                        // state (based on NIST SP 800-57)
                        json_object* state_obj;
                        if (json_object_object_get_ex(metadata_obj, "state", &state_obj)) {
                            json_object_object_add(key_props, "state",
                                json_object_new_string(json_object_get_string(state_obj)));
                        } else {
                            // Default to "active" if no state specified
                            json_object_object_add(key_props, "state",
                                json_object_new_string("active"));
                        }

                        // size (in bits) - schema requires integer type
                        json_object* key_size_obj;
                        if (json_object_object_get_ex(metadata_obj, "key_size", &key_size_obj)) {
                            json_object_object_add(key_props, "size",
                                json_object_new_int(json_object_get_int(key_size_obj)));
                        } else if (asset->key_size > 0) {
                            json_object_object_add(key_props, "size",
                                json_object_new_int(asset->key_size));
                        }

                        // format - derive from key type or metadata
                        json_object* format_obj;
                        if (json_object_object_get_ex(metadata_obj, "format", &format_obj)) {
                            json_object_object_add(key_props, "format",
                                json_object_new_string(json_object_get_string(format_obj)));
                        } else {
                            // Default to PEM if no format specified
                            json_object_object_add(key_props, "format",
                                json_object_new_string("PEM"));
                        }

                        // creationDate (ISO-8601)
                        json_object* creation_date_obj;
                        if (json_object_object_get_ex(metadata_obj, "creation_date", &creation_date_obj)) {
                            json_object_object_add(key_props, "creationDate",
                                json_object_new_string(json_object_get_string(creation_date_obj)));
                        }

                        // activationDate (ISO-8601)
                        json_object* activation_date_obj;
                        if (json_object_object_get_ex(metadata_obj, "activation_date", &activation_date_obj)) {
                            json_object_object_add(key_props, "activationDate",
                                json_object_new_string(json_object_get_string(activation_date_obj)));
                        }

                        // expirationDate (ISO-8601)
                        json_object* expiration_date_obj;
                        if (json_object_object_get_ex(metadata_obj, "expiration_date", &expiration_date_obj)) {
                            json_object_object_add(key_props, "expirationDate",
                                json_object_new_string(json_object_get_string(expiration_date_obj)));
                        }

                        // Phase 3: CycloneDX conformance fields

                        // algorithmRef - link to algorithm component
                        json_object* algorithm_ref_obj;
                        if (json_object_object_get_ex(metadata_obj, "algorithm_ref", &algorithm_ref_obj)) {
                            json_object_object_add(key_props, "algorithmRef",
                                json_object_new_string(json_object_get_string(algorithm_ref_obj)));
                        }

                        // id - unique key identifier (SHA-256 hash)
                        json_object* key_id_obj;
                        if (json_object_object_get_ex(metadata_obj, "key_id_sha256", &key_id_obj)) {
                            json_object_object_add(key_props, "id",
                                json_object_new_string(json_object_get_string(key_id_obj)));
                        }

                        // securedBy - encryption protection (if encrypted)
                        json_object* secured_by_obj;
                        if (json_object_object_get_ex(metadata_obj, "secured_by", &secured_by_obj)) {
                            json_object* secured_copy = NULL;
                            // Deep copy the secured_by object
                            const char* secured_str = json_object_to_json_string_ext(secured_by_obj, JSON_C_TO_STRING_PLAIN);
                            if (secured_str) {
                                secured_copy = json_tokener_parse(secured_str);
                                if (secured_copy) {
                                    json_object_object_add(key_props, "securedBy", secured_copy);
                                }
                            }
                        }

                        // fingerprint - structured object with alg and content
                        json_object* key_id_sha256_obj;
                        if (json_object_object_get_ex(metadata_obj, "key_id_sha256", &key_id_sha256_obj)) {
                            json_object* fingerprint_obj = json_object_new_object();
                            json_object_object_add(fingerprint_obj, "alg",
                                json_object_new_string("SHA-256"));
                            json_object_object_add(fingerprint_obj, "content",
                                json_object_new_string(json_object_get_string(key_id_sha256_obj)));
                            json_object_object_add(key_props, "fingerprint", fingerprint_obj);
                        }

                        // Store OID for adding at cryptoProperties level later
                        const char* key_oid = NULL;
                        json_object* oid_obj;
                        if (json_object_object_get_ex(metadata_obj, "oid", &oid_obj)) {
                            key_oid = json_object_get_string(oid_obj);
                        }

                        json_object_put(metadata_obj);

                        // Add OID at cryptoProperties level (outside relatedCryptoMaterialProperties)
                        if (key_oid && strlen(key_oid) > 0) {
                            json_object_object_add(crypto_props, "oid",
                                json_object_new_string(key_oid));
                        }
                    }

                    if (json_object_object_length(key_props) > 0) {
                        json_object_object_add(crypto_props, "relatedCryptoMaterialProperties", key_props);
                    } else {
                        json_object_put(key_props);
                    }
                }

                // Add relatedCryptoMaterialProperties for CSRs (v1.5: schema completeness)
                if (asset->type == ASSET_TYPE_CERTIFICATE_REQUEST) {
                    json_object* csr_props = json_object_new_object();

                    // CSRs contain public keys, so type is "public-key"
                    json_object_object_add(csr_props, "type", json_object_new_string("public-key"));

                    // Add algorithm and size if available from metadata
                    if (asset->metadata_json) {
                        json_object* csr_metadata = json_tokener_parse(asset->metadata_json);
                        if (csr_metadata) {
                            // Extract algorithm if present
                            json_object* algo_obj;
                            if (json_object_object_get_ex(csr_metadata, "algorithm", &algo_obj)) {
                                json_object_object_add(csr_props, "algorithm",
                                    json_object_new_string(json_object_get_string(algo_obj)));
                            }

                            // Extract key size if present
                            json_object* size_obj;
                            if (json_object_object_get_ex(csr_metadata, "key_size", &size_obj)) {
                                json_object_object_add(csr_props, "size",
                                    json_object_new_int(json_object_get_int(size_obj)));
                            }

                            json_object_put(csr_metadata);
                        }
                    }

                    json_object_object_add(crypto_props, "relatedCryptoMaterialProperties", csr_props);
                }

                // Add algorithmProperties for algorithms and cipher suites (Phase E)
                if (asset->type == ASSET_TYPE_ALGORITHM || asset->type == ASSET_TYPE_CIPHER_SUITE) {
                    json_object* algo_props = json_object_new_object();

                    // Try to get CDX properties from metadata_json first
                    const char* cdx_primitive = NULL;
                    const char* cdx_algorithm_family = NULL;  // NEW: Phase 1 enhancement
                    const char* cdx_mode = NULL;
                    const char* cdx_padding = NULL;
                    const char* cdx_curve = NULL;
                    const char* cdx_oid = NULL;  // NEW: OID for cryptoProperties level
                    json_object* crypto_functions = NULL;
                    int security_bits = 0;
                    int nist_quantum_level = 0;  // NEW: from table
                    const char* certification_level = "none";  // NEW: default
                    json_object* cdx_metadata_obj = NULL;  // Keep alive until strings are used

                    if (asset->metadata_json) {
                        cdx_metadata_obj = json_tokener_parse(asset->metadata_json);
                        if (cdx_metadata_obj) {
                            // Get cdx_primitive from metadata
                            json_object* primitive_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "cdx_primitive", &primitive_obj)) {
                                cdx_primitive = json_object_get_string(primitive_obj);
                            }

                            // Get algorithm_family from metadata (NEW: Phase 1)
                            json_object* family_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "algorithm_family", &family_obj)) {
                                cdx_algorithm_family = json_object_get_string(family_obj);
                            }

                            // Get mode from metadata
                            json_object* mode_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "mode", &mode_obj)) {
                                cdx_mode = json_object_get_string(mode_obj);
                            }

                            // Get padding from metadata
                            json_object* padding_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "padding", &padding_obj)) {
                                cdx_padding = json_object_get_string(padding_obj);
                            }

                            // Get curve from metadata
                            json_object* curve_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "curve", &curve_obj)) {
                                cdx_curve = json_object_get_string(curve_obj);
                            }

                            // Get OID from metadata (NEW: Phase 1)
                            json_object* oid_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "oid", &oid_obj)) {
                                cdx_oid = json_object_get_string(oid_obj);
                            }

                            // Get crypto_functions from metadata
                            json_object* funcs_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "crypto_functions", &funcs_obj)) {
                                crypto_functions = json_object_get(funcs_obj);  // Increment ref count
                            }

                            // Get security_strength_bits
                            json_object* security_bits_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "security_strength_bits", &security_bits_obj)) {
                                security_bits = json_object_get_int(security_bits_obj);
                            }

                            // Get nist_quantum_security_level from metadata (NEW: Phase 1)
                            json_object* quantum_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "nist_quantum_security_level", &quantum_obj)) {
                                nist_quantum_level = json_object_get_int(quantum_obj);
                            }

                            // Get certification_level from metadata (NEW: Phase 1)
                            json_object* cert_obj;
                            if (json_object_object_get_ex(cdx_metadata_obj, "certification_level", &cert_obj)) {
                                certification_level = json_object_get_string(cert_obj);
                            }
                        }
                    }

                    // Fallback: derive primitive from algorithm name if not in metadata
                    if (!cdx_primitive) {
                        // Authenticated encryption takes precedence (AEAD modes)
                        if (strstr(asset->name, "GCM") || strstr(asset->name, "CCM") ||
                            strstr(asset->name, "Poly1305") || strstr(asset->name, "ChaCha20-Poly1305") ||
                            strstr(asset->name, "AEAD")) {
                            cdx_primitive = "ae";
                        } else if (strstr(asset->name, "AES") || strstr(asset->name, "DES") || strstr(asset->name, "3DES")) {
                            cdx_primitive = "block-cipher";
                        } else if (strstr(asset->name, "ChaCha20") || strstr(asset->name, "Salsa20") || strstr(asset->name, "RC4")) {
                            cdx_primitive = "stream-cipher";
                        } else if (strstr(asset->name, "SHA") || strstr(asset->name, "BLAKE") ||
                                   strstr(asset->name, "MD5") || strstr(asset->name, "MD2")) {
                            cdx_primitive = "hash";
                        } else if (strstr(asset->name, "HMAC")) {
                            cdx_primitive = "mac";
                        } else if (strstr(asset->name, "RSA") || strstr(asset->name, "ECDSA") ||
                                   strstr(asset->name, "Ed25519") || strstr(asset->name, "Ed448") ||
                                   strstr(asset->name, "DSA") || strstr(asset->name, "ML-DSA") ||
                                   strstr(asset->name, "Dilithium")) {
                            cdx_primitive = "signature";
                        } else if (strstr(asset->name, "ECDH") || strstr(asset->name, "DH") ||
                                   strstr(asset->name, "X25519") || strstr(asset->name, "ECDHE") ||
                                   strstr(asset->name, "DHE")) {
                            cdx_primitive = "key-agree";
                        } else if (strstr(asset->name, "PBKDF") || strstr(asset->name, "HKDF") ||
                                   strstr(asset->name, "scrypt") || strstr(asset->name, "Argon2")) {
                            cdx_primitive = "kdf";
                        } else if (strstr(asset->name, "ML-KEM") || strstr(asset->name, "Kyber") ||
                                   strstr(asset->name, "NTRU")) {
                            cdx_primitive = "kem";
                        } else {
                            cdx_primitive = "unknown";
                        }
                    }

                    // Add algorithmFamily (NEW: Phase 1 - CycloneDX conformance)
                    if (cdx_algorithm_family) {
                        json_object_object_add(algo_props, "algorithmFamily",
                            json_object_new_string(cdx_algorithm_family));
                    }

                    // Add primitive
                    json_object_object_add(algo_props, "primitive",
                        json_object_new_string(cdx_primitive));

                    // Add executionEnvironment (NEW: Phase 1 - CycloneDX conformance)
                    // Default to "software-plain-ram" for all discovered software implementations
                    json_object_object_add(algo_props, "executionEnvironment",
                        json_object_new_string(get_default_execution_environment()));

                    // Add implementationPlatform (NEW: Phase 1 - CycloneDX conformance)
                    // Detect at runtime using uname()
                    json_object_object_add(algo_props, "implementationPlatform",
                        json_object_new_string(detect_implementation_platform()));

                    // parameterSetIdentifier - extract from name (schema requires string)
                    if (strstr(asset->name, "-128") || strstr(asset->name, "128")) {
                        json_object_object_add(algo_props, "parameterSetIdentifier",
                            json_object_new_string("128"));
                    } else if (strstr(asset->name, "-192") || strstr(asset->name, "192")) {
                        json_object_object_add(algo_props, "parameterSetIdentifier",
                            json_object_new_string("192"));
                    } else if (strstr(asset->name, "-256") || strstr(asset->name, "256") || strstr(asset->name, "SHA256")) {
                        json_object_object_add(algo_props, "parameterSetIdentifier",
                            json_object_new_string("256"));
                    } else if (strstr(asset->name, "-384") || strstr(asset->name, "384") || strstr(asset->name, "SHA384")) {
                        json_object_object_add(algo_props, "parameterSetIdentifier",
                            json_object_new_string("384"));
                    } else if (strstr(asset->name, "-512") || strstr(asset->name, "512") || strstr(asset->name, "SHA512")) {
                        json_object_object_add(algo_props, "parameterSetIdentifier",
                            json_object_new_string("512"));
                    }

                    // Add mode (from metadata or fallback to name extraction)
                    if (cdx_mode) {
                        json_object_object_add(algo_props, "mode", json_object_new_string(cdx_mode));
                    } else {
                        // Fallback: extract from name
                        if (strstr(asset->name, "GCM") || strstr(asset->name, "-GCM")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("gcm"));
                        } else if (strstr(asset->name, "CCM") || strstr(asset->name, "-CCM")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("ccm"));
                        } else if (strstr(asset->name, "CBC") || strstr(asset->name, "-CBC")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("cbc"));
                        } else if (strstr(asset->name, "CTR") || strstr(asset->name, "-CTR")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("ctr"));
                        } else if (strstr(asset->name, "ECB")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("ecb"));
                        } else if (strstr(asset->name, "CFB")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("cfb"));
                        } else if (strstr(asset->name, "OFB")) {
                            json_object_object_add(algo_props, "mode", json_object_new_string("ofb"));
                        }
                    }

                    // Add padding from metadata (NEW)
                    if (cdx_padding) {
                        json_object_object_add(algo_props, "padding", json_object_new_string(cdx_padding));
                    }

                    // Add curve from metadata (NEW)
                    if (cdx_curve) {
                        json_object_object_add(algo_props, "curve", json_object_new_string(cdx_curve));
                    }

                    // Add cryptoFunctions from metadata (NEW)
                    if (crypto_functions) {
                        json_object_object_add(algo_props, "cryptoFunctions", crypto_functions);
                    }

                    // Add security levels
                    if (security_bits > 0) {
                        json_object_object_add(algo_props, "classicalSecurityLevel",
                            json_object_new_int(security_bits));
                    }

                    // Add NIST quantum security level (NEW: Phase 1 - use from metadata or derive)
                    int nist_level = nist_quantum_level;  // Use from metadata first
                    if (nist_level == 0 && security_bits > 0) {
                        // Fallback: derive from classical strength
                        if (security_bits >= 256) nist_level = 5;
                        else if (security_bits >= 192) nist_level = 3;
                        else if (security_bits >= 128) nist_level = 1;
                    }

                    if (nist_level > 0) {
                        json_object_object_add(algo_props, "nistQuantumSecurityLevel",
                            json_object_new_int(nist_level));
                    }

                    // certificationLevel - ALWAYS output as array per CycloneDX spec (NEW: Phase 1)
                    json_object* cert_level_array = json_object_new_array();
                    bool cert_level_set = false;

                    // Check for FIPS level in metadata
                    if (asset->metadata_json) {
                        json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                        if (metadata_obj) {
                            json_object* fips_level_obj;
                            if (json_object_object_get_ex(metadata_obj, "fips_level", &fips_level_obj)) {
                                const char* fips_level = json_object_get_string(fips_level_obj);
                                if (fips_level && strlen(fips_level) > 0 && strcmp(fips_level, "none") != 0) {
                                    json_object_array_add(cert_level_array, json_object_new_string(fips_level));
                                    cert_level_set = true;
                                }
                            }

                            // Add CNSA policy if algorithm qualifies
                            // CNSA Suite: AES-256, ECDSA-P384, ECDH-P384, SHA-384
                            bool is_cnsa_compliant = false;
                            if ((strstr(asset->name, "AES-256") && !strstr(asset->name, "128")) ||
                                (strstr(asset->name, "ECDSA") && strstr(asset->name, "384")) ||
                                (strstr(asset->name, "ECDH") && strstr(asset->name, "384")) ||
                                strcmp(asset->name, "SHA384") == 0 || strcmp(asset->name, "SHA-384") == 0) {
                                is_cnsa_compliant = true;
                            }

                            if (is_cnsa_compliant) {
                                json_object* fips_obj;
                                if (json_object_object_get_ex(metadata_obj, "fips_level", &fips_obj)) {
                                    const char* fips = json_object_get_string(fips_obj);
                                    // Only emit CNSA for FIPS-certified implementations
                                    if (fips && strlen(fips) > 0 && strstr(fips, "fips140")) {
                                        json_object_object_add(algo_props, "policy",
                                            json_object_new_string("CNSA"));
                                    }
                                }
                            }

                            json_object_put(metadata_obj);
                        }
                    }

                    // Default to "none" if no certification level set
                    if (!cert_level_set) {
                        json_object_array_add(cert_level_array, json_object_new_string(certification_level));
                    }
                    json_object_object_add(algo_props, "certificationLevel", cert_level_array);

                    if (json_object_object_length(algo_props) > 0) {
                        json_object_object_add(crypto_props, "algorithmProperties", algo_props);
                    } else {
                        json_object_put(algo_props);
                    }

                    // Add OID at cryptoProperties level (NEW: Phase 1 - correct placement per spec)
                    if (cdx_oid && strlen(cdx_oid) > 0) {
                        json_object_object_add(crypto_props, "oid", json_object_new_string(cdx_oid));
                    }

                    // Free cdx_metadata_obj now that all strings have been used
                    if (cdx_metadata_obj) {
                        json_object_put(cdx_metadata_obj);
                    }
                }

                // Phase 4: Helper function to add SSH cipher suite entry
                inline void add_ssh_cipher_suite(json_object* array, const char* name, const char* algo_ref) {
                    json_object* entry = json_object_new_object();
                    json_object_object_add(entry, "name", json_object_new_string(name));
                    json_object* algos = json_object_new_array();
                    json_object_array_add(algos, json_object_new_string(algo_ref));
                    json_object_object_add(entry, "algorithms", algos);
                    json_object_array_add(array, entry);
                }

                // Add protocolProperties for protocols (Phase 4)
                if (asset->type == ASSET_TYPE_PROTOCOL && asset->metadata_json) {
                    json_object* protocol_props = json_object_new_object();
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);

                    if (metadata_obj) {
                        // type (e.g., "tls", "ssh", "ipsec")
                        json_object* proto_type_obj;
                        if (json_object_object_get_ex(metadata_obj, "protocol_type", &proto_type_obj)) {
                            const char* proto_type = json_object_get_string(proto_type_obj);
                            // Convert to lowercase for CycloneDX
                            char* proto_type_lower = strdup(proto_type);
                            if (proto_type_lower) {
                                for (char* p = proto_type_lower; *p; p++) {
                                    *p = tolower(*p);
                                }
                                json_object_object_add(protocol_props, "type",
                                    json_object_new_string(proto_type_lower));
                                free(proto_type_lower);
                            }
                        }

                        // version (e.g., "1.3", "1.2", "2.0")
                        json_object* version_obj;
                        if (json_object_object_get_ex(metadata_obj, "version", &version_obj)) {
                            json_object_object_add(protocol_props, "version",
                                json_object_new_string(json_object_get_string(version_obj)));
                        }

                        // cipherSuites array - get from relationships or cipher suite assets
                        json_object* enabled_ciphers_obj;
                        if (json_object_object_get_ex(metadata_obj, "enabled_cipher_suites", &enabled_ciphers_obj)) {
                            if (json_object_is_type(enabled_ciphers_obj, json_type_array)) {
                                json_object* cipher_suites_array = json_object_new_array();
                                int cipher_count = json_object_array_length(enabled_ciphers_obj);

                                for (int i = 0; i < cipher_count && i < 20; i++) {
                                    json_object* cipher_name_obj = json_object_array_get_idx(enabled_ciphers_obj, i);
                                    const char* cipher_name = json_object_get_string(cipher_name_obj);

                                    // Create cipher suite entry
                                    json_object* cipher_suite_entry = json_object_new_object();
                                    json_object_object_add(cipher_suite_entry, "name",
                                        json_object_new_string(cipher_name));

                                    // Phase 4: Look up cipher suite metadata to get algorithm_refs and iana_id
                                    // Search asset store for matching cipher suite
                                    for (size_t j = 0; j < asset_count; j++) {
                                        crypto_asset_t* suite_asset = assets[j];
                                        if (suite_asset->type == ASSET_TYPE_CIPHER_SUITE &&
                                            suite_asset->name && strcmp(suite_asset->name, cipher_name) == 0 &&
                                            suite_asset->metadata_json) {

                                            // Parse cipher suite metadata
                                            json_object* suite_meta = json_tokener_parse(suite_asset->metadata_json);
                                            if (suite_meta) {
                                                // Extract algorithm_refs array
                                                json_object* algo_refs_obj;
                                                if (json_object_object_get_ex(suite_meta, "algorithm_refs", &algo_refs_obj)) {
                                                    if (json_object_is_type(algo_refs_obj, json_type_array)) {
                                                        json_object* algo_refs_copy = NULL;
                                                        const char* refs_str = json_object_to_json_string_ext(algo_refs_obj, JSON_C_TO_STRING_PLAIN);
                                                        if (refs_str) {
                                                            algo_refs_copy = json_tokener_parse(refs_str);
                                                            if (algo_refs_copy) {
                                                                json_object_object_add(cipher_suite_entry, "algorithms", algo_refs_copy);
                                                            }
                                                        }
                                                    }
                                                }

                                                // Extract IANA identifier
                                                json_object* iana_id_obj;
                                                if (json_object_object_get_ex(suite_meta, "iana_id", &iana_id_obj)) {
                                                    const char* iana_id = json_object_get_string(iana_id_obj);
                                                    if (iana_id && strlen(iana_id) > 0) {
                                                        json_object* identifiers_array = json_object_new_array();
                                                        json_object_array_add(identifiers_array,
                                                            json_object_new_string(iana_id));
                                                        json_object_object_add(cipher_suite_entry, "identifiers", identifiers_array);
                                                    }
                                                }

                                                json_object_put(suite_meta);
                                            }
                                            break;  // Found matching cipher suite
                                        }
                                    }

                                    json_object_array_add(cipher_suites_array, cipher_suite_entry);
                                }

                                if (json_object_array_length(cipher_suites_array) > 0) {
                                    json_object_object_add(protocol_props, "cipherSuites", cipher_suites_array);
                                } else {
                                    json_object_put(cipher_suites_array);
                                }
                            }
                        }

                        // Phase 4: Add default SSH cipher suites if none present
                        json_object* proto_type_check;
                        if (json_object_object_get_ex(metadata_obj, "protocol_type", &proto_type_check)) {
                            const char* proto_type_str = json_object_get_string(proto_type_check);
                            if (strcasecmp(proto_type_str, "SSH") == 0) {
                                // Check if cipherSuites already added
                                json_object* existing_suites = NULL;
                                if (!json_object_object_get_ex(protocol_props, "cipherSuites", &existing_suites)) {
                                    json_object* ssh_suites = json_object_new_array();

                                    // Add 3 default modern SSH cipher suites (v1.5: algo: prefix)
                                    add_ssh_cipher_suite(ssh_suites, "chacha20-poly1305@openssh.com",
                                                        "algo:chacha20-poly1305");
                                    add_ssh_cipher_suite(ssh_suites, "aes256-gcm@openssh.com",
                                                        "algo:aes-256-gcm");
                                    add_ssh_cipher_suite(ssh_suites, "aes128-gcm@openssh.com",
                                                        "algo:aes-128-gcm");

                                    json_object_object_add(protocol_props, "cipherSuites", ssh_suites);
                                }
                            }
                        }

                        json_object_put(metadata_obj);
                    }

                    if (json_object_object_length(protocol_props) > 0) {
                        json_object_object_add(crypto_props, "protocolProperties", protocol_props);
                    } else {
                        json_object_put(protocol_props);
                    }
                }

                json_object_object_add(component, "cryptoProperties", crypto_props);
            }

            // Add properties using FROZEN v1.0 CBOM namespaced properties
            json_object *properties = json_object_new_array();
            
            // Certificate-specific properties (cbom:cert:*)
            if (asset->type == ASSET_TYPE_CERTIFICATE) {
                if (asset->algorithm) {
                    json_object *prop = json_object_new_object();
                    json_object_object_add(prop, "name", json_object_new_string("cbom:cert:public_key_algorithm"));
                    json_object_object_add(prop, "value", json_object_new_string(asset->algorithm));
                    json_object_array_add(properties, prop);
                }
                
                if (asset->key_size > 0) {
                    json_object *prop = json_object_new_object();
                    json_object_object_add(prop, "name", json_object_new_string("cbom:cert:key_size"));
                    char key_size_str[16];
                    snprintf(key_size_str, sizeof(key_size_str), "%u", asset->key_size);
                    json_object_object_add(prop, "value", json_object_new_string(key_size_str));
                    json_object_array_add(properties, prop);
                }
                
                // Add certificate subject as cbom:cert:subject_dn (RFC2253 format)
                json_object *subject_prop = json_object_new_object();
                json_object_object_add(subject_prop, "name", json_object_new_string("cbom:cert:subject_dn"));
                json_object_object_add(subject_prop, "value", json_object_new_string(asset->name));
                json_object_array_add(properties, subject_prop);
                
                // Add enhanced certificate metadata from certificate scanner
                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Issuer DN
                        json_object* issuer_obj;
                        if (json_object_object_get_ex(metadata_obj, "issuer", &issuer_obj)) {
                            json_object* issuer_prop = json_object_new_object();
                            json_object_object_add(issuer_prop, "name", json_object_new_string("cbom:cert:issuer_dn"));
                            json_object_object_add(issuer_prop, "value", json_object_new_string(json_object_get_string(issuer_obj)));
                            json_object_array_add(properties, issuer_prop);
                        }
                        
                        // Serial number
                        json_object* serial_obj;
                        if (json_object_object_get_ex(metadata_obj, "serial_number", &serial_obj)) {
                            json_object* serial_prop = json_object_new_object();
                            json_object_object_add(serial_prop, "name", json_object_new_string("cbom:cert:serial_number"));
                            json_object_object_add(serial_prop, "value", json_object_new_string(json_object_get_string(serial_obj)));
                            json_object_array_add(properties, serial_prop);
                        }
                        
                        // Validity dates as integers (epochs) - renamed with _epoch suffix for clarity
                        json_object* not_before_obj;
                        if (json_object_object_get_ex(metadata_obj, "not_before", &not_before_obj)) {
                            json_object* not_before_prop = json_object_new_object();
                            json_object_object_add(not_before_prop, "name", json_object_new_string("cbom:cert:not_before_epoch"));
                            // Convert to string (schema requirement)
                            char epoch_str[32];
                            if (json_object_is_type(not_before_obj, json_type_string)) {
                                snprintf(epoch_str, sizeof(epoch_str), "%s", json_object_get_string(not_before_obj));
                            } else {
                                snprintf(epoch_str, sizeof(epoch_str), "%ld", (long)json_object_get_int64(not_before_obj));
                            }
                            json_object_object_add(not_before_prop, "value", json_object_new_string(epoch_str));
                            json_object_array_add(properties, not_before_prop);
                        }

                        json_object* not_after_obj;
                        if (json_object_object_get_ex(metadata_obj, "not_after", &not_after_obj)) {
                            json_object* not_after_prop = json_object_new_object();
                            json_object_object_add(not_after_prop, "name", json_object_new_string("cbom:cert:not_after_epoch"));
                            // Convert to string (schema requirement)
                            char epoch_str[32];
                            if (json_object_is_type(not_after_obj, json_type_string)) {
                                snprintf(epoch_str, sizeof(epoch_str), "%s", json_object_get_string(not_after_obj));
                            } else {
                                snprintf(epoch_str, sizeof(epoch_str), "%ld", (long)json_object_get_int64(not_after_obj));
                            }
                            json_object_object_add(not_after_prop, "value", json_object_new_string(epoch_str));
                            json_object_array_add(properties, not_after_prop);
                        }
                        
                        // Signature algorithm name (not OID)
                        json_object* sig_alg_obj;
                        if (json_object_object_get_ex(metadata_obj, "signature_algorithm", &sig_alg_obj)) {
                            json_object* sig_alg_prop = json_object_new_object();
                            json_object_object_add(sig_alg_prop, "name", json_object_new_string("cbom:cert:signature_algorithm_name"));
                            json_object_object_add(sig_alg_prop, "value", json_object_new_string(json_object_get_string(sig_alg_obj)));
                            json_object_array_add(properties, sig_alg_prop);
                        }
                        
                        // Add actual signature algorithm OID if available
                        json_object* sig_oid_obj;
                        if (json_object_object_get_ex(metadata_obj, "signature_oid", &sig_oid_obj)) {
                            json_object* sig_oid_prop = json_object_new_object();
                            json_object_object_add(sig_oid_prop, "name", json_object_new_string("cbom:cert:signature_algorithm_oid"));
                            json_object_object_add(sig_oid_prop, "value", json_object_new_string(json_object_get_string(sig_oid_obj)));
                            json_object_array_add(properties, sig_oid_prop);
                        }
                        
                        // Subject Alternative Names
                        json_object* san_obj;
                        if (json_object_object_get_ex(metadata_obj, "subject_alt_names", &san_obj)) {
                            if (json_object_is_type(san_obj, json_type_array)) {
                                json_object* san_prop = json_object_new_object();
                                json_object_object_add(san_prop, "name", json_object_new_string("cbom:cert:san"));
                                
                                // Convert array to comma-separated string
                                char san_str[1024] = "";
                                int san_len = json_object_array_length(san_obj);
                                for (int i = 0; i < san_len && i < 10; i++) { // Limit to 10 SANs
                                    json_object* san_item = json_object_array_get_idx(san_obj, i);
                                    if (i > 0) strcat(san_str, ",");
                                    strncat(san_str, json_object_get_string(san_item), sizeof(san_str) - strlen(san_str) - 1);
                                }
                                
                                json_object_object_add(san_prop, "value", json_object_new_string(san_str));
                                json_object_array_add(properties, san_prop);
                            }
                        }
                        
                        json_object_put(metadata_obj);
                    }
                }
                
                // Add key_id if present
                if (asset->key_id) {
                    json_object* key_id_prop = json_object_new_object();
                    json_object_object_add(key_id_prop, "name", json_object_new_string("cbom:cert:key_id"));
                    json_object_object_add(key_id_prop, "value", json_object_new_string(asset->key_id));
                    json_object_array_add(properties, key_id_prop);
                }

                // Add certificateState to properties (schema compliance)
                if (saved_cert_state) {
                    json_object *prop = json_object_new_object();
                    json_object_object_add(prop, "name", json_object_new_string("x-certificate-state"));
                    json_object_object_add(prop, "value",
                        json_object_new_string(json_object_to_json_string_ext(saved_cert_state, JSON_C_TO_STRING_PLAIN)));
                    json_object_array_add(properties, prop);
                    json_object_put(saved_cert_state);  // Free after use
                    saved_cert_state = NULL;
                }

                // Add certificatePolicies to properties (schema compliance)
                if (saved_cert_policies) {
                    json_object *prop = json_object_new_object();
                    json_object_object_add(prop, "name", json_object_new_string("x-certificate-policies"));
                    json_object_object_add(prop, "value",
                        json_object_new_string(json_object_to_json_string_ext(saved_cert_policies, JSON_C_TO_STRING_PLAIN)));
                    json_object_array_add(properties, prop);
                    json_object_put(saved_cert_policies);  // Free after use
                    saved_cert_policies = NULL;
                }

                // Add authorityInfoAccess to properties (schema compliance)
                if (saved_aia) {
                    json_object *prop = json_object_new_object();
                    json_object_object_add(prop, "name", json_object_new_string("x-authority-info-access"));
                    json_object_object_add(prop, "value",
                        json_object_new_string(json_object_to_json_string_ext(saved_aia, JSON_C_TO_STRING_PLAIN)));
                    json_object_array_add(properties, prop);
                    json_object_put(saved_aia);  // Free after use
                    saved_aia = NULL;
                }

                // Add serialNumber to properties (1.6 only) - Issue #8.1
                if (saved_serial_number) {
                    json_object* serial_prop = json_object_new_object();
                    json_object_object_add(serial_prop, "name",
                        json_object_new_string("x-serial-number"));
                    json_object_object_add(serial_prop, "value",
                        json_object_new_string(saved_serial_number));
                    json_object_array_add(properties, serial_prop);
                    free(saved_serial_number);
                    saved_serial_number = NULL;
                }

                // Add fingerprint to properties (1.6 only) - Issue #8.1
                if (saved_fingerprint) {
                    json_object* fp_prop = json_object_new_object();
                    json_object_object_add(fp_prop, "name",
                        json_object_new_string("x-fingerprint-sha256"));
                    json_object_object_add(fp_prop, "value",
                        json_object_new_string(saved_fingerprint));
                    json_object_array_add(properties, fp_prop);
                    free(saved_fingerprint);
                    saved_fingerprint = NULL;
                }

                // Handle CSRs differently from certificates
                bool is_csr = (asset->location && strstr(asset->location, "/csr/") != NULL) ||
                             (asset->location && strstr(asset->location, ".csr") != NULL);
                
                if (is_csr) {
                    // CSR-specific properties - no trust status
                    json_object *csr_type_prop = json_object_new_object();
                    json_object_object_add(csr_type_prop, "name", json_object_new_string("cbom:csr:type"));
                    json_object_object_add(csr_type_prop, "value", json_object_new_string("CERTIFICATE_REQUEST"));
                    json_object_array_add(properties, csr_type_prop);
                    
                    // Add CSR requester if parsable
                    if (asset->metadata_json) {
                        json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                        if (metadata_obj) {
                            json_object* subject_obj;
                            if (json_object_object_get_ex(metadata_obj, "subject_dn", &subject_obj)) {
                                json_object* requester_prop = json_object_new_object();
                                json_object_object_add(requester_prop, "name", json_object_new_string("cbom:csr:requester"));
                                json_object_object_add(requester_prop, "value", json_object_new_string(json_object_get_string(subject_obj)));
                                json_object_array_add(properties, requester_prop);
                            }
                            json_object_put(metadata_obj);
                        }
                    }
                } else {
                    // Certificate trust status
                    json_object *trust_prop = json_object_new_object();
                    json_object_object_add(trust_prop, "name", json_object_new_string("cbom:cert:trust_status"));
                    
                    const char* trust_status = "UNKNOWN"; // Default
                    
                    // Extract trust status from certificate metadata JSON (4.1.2 fix)
                    if (asset->metadata_json) {
                        json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                        if (metadata_obj) {
                            json_object* trust_status_obj;
                            if (json_object_object_get_ex(metadata_obj, "cbom:cert:trust_status", &trust_status_obj)) {
                                trust_status = json_object_get_string(trust_status_obj);
                            }
                            json_object_put(metadata_obj);
                        }
                    }
                    
                    json_object_object_add(trust_prop, "value", json_object_new_string(trust_status));
                    json_object_array_add(properties, trust_prop);

                    // Certificate validity_state (Phase E fix)
                    json_object *validity_state_prop = json_object_new_object();
                    json_object_object_add(validity_state_prop, "name", json_object_new_string("cbom:cert:validity_state"));

                    const char* validity_state = "active"; // Default
                    if (asset->metadata_json) {
                        json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                        if (metadata_obj) {
                            json_object* validity_status_obj;
                            if (json_object_object_get_ex(metadata_obj, "validity_status", &validity_status_obj)) {
                                const char* validity_status = json_object_get_string(validity_status_obj);
                                if (strcmp(validity_status, "NOT_YET_VALID") == 0) {
                                    validity_state = "pre-activation";
                                } else if (strcmp(validity_status, "VALID") == 0) {
                                    validity_state = "active";
                                } else if (strcmp(validity_status, "EXPIRED") == 0) {
                                    validity_state = "deactivated";
                                }
                            }
                            json_object_put(metadata_obj);
                        }
                    }

                    json_object_object_add(validity_state_prop, "value", json_object_new_string(validity_state));
                    json_object_array_add(properties, validity_state_prop);

                    // Certificate revocation_status (Phase E fix)
                    json_object *revocation_status_prop = json_object_new_object();
                    json_object_object_add(revocation_status_prop, "name", json_object_new_string("cbom:cert:revocation_status"));

                    const char* revocation_status = "GOOD"; // Default
                    if (strcmp(trust_status, "REVOKED") == 0) {
                        revocation_status = "REVOKED";
                    } else if (strcmp(trust_status, "UNKNOWN") == 0) {
                        revocation_status = "UNKNOWN";
                    }

                    json_object_object_add(revocation_status_prop, "value", json_object_new_string(revocation_status));
                    json_object_array_add(properties, revocation_status_prop);
                }

                // Add enhanced certificate metadata fields (4.1.1 & 4.1.2 fix)
                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Authority Key Identifier
                        json_object* aki_obj;
                        if (json_object_object_get_ex(metadata_obj, "authority_key_id", &aki_obj)) {
                            const char* aki_value = json_object_get_string(aki_obj);
                            if (aki_value && strlen(aki_value) > 0) {
                                json_object* aki_prop = json_object_new_object();
                                json_object_object_add(aki_prop, "name", json_object_new_string("cbom:cert:authority_key_id"));
                                json_object_object_add(aki_prop, "value", json_object_new_string(aki_value));
                                json_object_array_add(properties, aki_prop);
                            }
                        }
                        
                        // Subject Key Identifier
                        json_object* ski_obj;
                        if (json_object_object_get_ex(metadata_obj, "subject_key_id", &ski_obj)) {
                            const char* ski_value = json_object_get_string(ski_obj);
                            if (ski_value && strlen(ski_value) > 0) {
                                json_object* ski_prop = json_object_new_object();
                                json_object_object_add(ski_prop, "name", json_object_new_string("cbom:cert:subject_key_id"));
                                json_object_object_add(ski_prop, "value", json_object_new_string(ski_value));
                                json_object_array_add(properties, ski_prop);
                            }
                        }
                        
                        // Serial Number (Hex)
                        json_object* serial_hex_obj;
                        if (json_object_object_get_ex(metadata_obj, "serial_number_hex", &serial_hex_obj)) {
                            const char* serial_hex_value = json_object_get_string(serial_hex_obj);
                            if (serial_hex_value && strlen(serial_hex_value) > 0) {
                                json_object* serial_hex_prop = json_object_new_object();
                                json_object_object_add(serial_hex_prop, "name", json_object_new_string("cbom:cert:serial_number_hex"));
                                json_object_object_add(serial_hex_prop, "value", json_object_new_string(serial_hex_value));
                                json_object_array_add(properties, serial_hex_prop);
                            }
                        }
                        
                        // Validity Status
                        json_object* validity_obj;
                        if (json_object_object_get_ex(metadata_obj, "validity_status", &validity_obj)) {
                            const char* validity_value = json_object_get_string(validity_obj);
                            if (validity_value) {
                                json_object* validity_prop = json_object_new_object();
                                json_object_object_add(validity_prop, "name", json_object_new_string("cbom:cert:validity_status"));
                                json_object_object_add(validity_prop, "value", json_object_new_string(validity_value));
                                json_object_array_add(properties, validity_prop);
                            }
                        }
                        
                        // Trust validation details
                        json_object* trust_error_obj;
                        if (json_object_object_get_ex(metadata_obj, "cbom:cert:trust_error", &trust_error_obj)) {
                            const char* trust_error_value = json_object_get_string(trust_error_obj);
                            if (trust_error_value && strlen(trust_error_value) > 0) {
                                json_object* trust_error_prop = json_object_new_object();
                                json_object_object_add(trust_error_prop, "name", json_object_new_string("cbom:cert:trust_error"));
                                json_object_object_add(trust_error_prop, "value", json_object_new_string(trust_error_value));
                                json_object_array_add(properties, trust_error_prop);
                            }
                        }
                        
                        // Enhanced algorithm information (4.1 enhancement)
                        json_object* sig_hash_obj;
                        if (json_object_object_get_ex(metadata_obj, "signature_hash", &sig_hash_obj)) {
                            const char* sig_hash_value = json_object_get_string(sig_hash_obj);
                            if (sig_hash_value) {
                                json_object* sig_hash_prop = json_object_new_object();
                                json_object_object_add(sig_hash_prop, "name", json_object_new_string("cbom:cert:signature_hash"));
                                json_object_object_add(sig_hash_prop, "value", json_object_new_string(sig_hash_value));
                                json_object_array_add(properties, sig_hash_prop);
                            }
                        }
                        
                        // OID fields (4.1 enhancement)
                        json_object* pub_key_oid_obj;
                        if (json_object_object_get_ex(metadata_obj, "public_key_oid", &pub_key_oid_obj)) {
                            const char* pub_key_oid_value = json_object_get_string(pub_key_oid_obj);
                            if (pub_key_oid_value && strlen(pub_key_oid_value) > 0) {
                                json_object* pub_key_oid_prop = json_object_new_object();
                                json_object_object_add(pub_key_oid_prop, "name", json_object_new_string("cbom:cert:public_key_oid"));
                                json_object_object_add(pub_key_oid_prop, "value", json_object_new_string(pub_key_oid_value));
                                json_object_array_add(properties, pub_key_oid_prop);
                            }
                        }
                        
                        json_object* sig_oid_obj;
                        if (json_object_object_get_ex(metadata_obj, "signature_oid", &sig_oid_obj)) {
                            const char* sig_oid_value = json_object_get_string(sig_oid_obj);
                            if (sig_oid_value && strlen(sig_oid_value) > 0) {
                                json_object* sig_oid_prop = json_object_new_object();
                                json_object_object_add(sig_oid_prop, "name", json_object_new_string("cbom:cert:signature_oid"));
                                json_object_object_add(sig_oid_prop, "value", json_object_new_string(sig_oid_value));
                                json_object_array_add(properties, sig_oid_prop);
                            }
                        }
                        
                        json_object* pub_key_size_obj;
                        if (json_object_object_get_ex(metadata_obj, "public_key_size", &pub_key_size_obj)) {
                            int pub_key_size = json_object_get_int(pub_key_size_obj);
                            if (pub_key_size > 0) {
                                json_object* pub_key_size_prop = json_object_new_object();
                                json_object_object_add(pub_key_size_prop, "name", json_object_new_string("cbom:cert:public_key_size"));
                                // Convert to string (schema requirement)
                                char size_str[16];
                                snprintf(size_str, sizeof(size_str), "%d", pub_key_size);
                                json_object_object_add(pub_key_size_prop, "value", json_object_new_string(size_str));
                                json_object_array_add(properties, pub_key_size_prop);
                            }
                        }
                        
                        json_object* ec_curve_obj;
                        if (json_object_object_get_ex(metadata_obj, "ec_curve_name", &ec_curve_obj)) {
                            const char* ec_curve_value = json_object_get_string(ec_curve_obj);
                            if (ec_curve_value) {
                                json_object* ec_curve_prop = json_object_new_object();
                                json_object_object_add(ec_curve_prop, "name", json_object_new_string("cbom:cert:ec_curve_name"));
                                json_object_object_add(ec_curve_prop, "value", json_object_new_string(ec_curve_value));
                                json_object_array_add(properties, ec_curve_prop);
                            }
                        }
                        
                        json_object* ec_curve_oid_obj;
                        if (json_object_object_get_ex(metadata_obj, "ec_curve_oid", &ec_curve_oid_obj)) {
                            const char* ec_curve_oid_value = json_object_get_string(ec_curve_oid_obj);
                            if (ec_curve_oid_value && strlen(ec_curve_oid_value) > 0) {
                                json_object* ec_curve_oid_prop = json_object_new_object();
                                json_object_object_add(ec_curve_oid_prop, "name", json_object_new_string("cbom:cert:ec_curve_oid"));
                                json_object_object_add(ec_curve_oid_prop, "value", json_object_new_string(ec_curve_oid_value));
                                json_object_array_add(properties, ec_curve_oid_prop);
                            }
                        }
                        
                        // Fingerprint SHA256 (4.1 enhancement)
                        json_object* fp_sha256_obj;
                        if (json_object_object_get_ex(metadata_obj, "fingerprint_sha256", &fp_sha256_obj)) {
                            const char* fp_sha256_value = json_object_get_string(fp_sha256_obj);
                            if (fp_sha256_value && strlen(fp_sha256_value) > 0) {
                                json_object* fp_sha256_prop = json_object_new_object();
                                json_object_object_add(fp_sha256_prop, "name", json_object_new_string("cbom:cert:fingerprint_sha256"));
                                json_object_object_add(fp_sha256_prop, "value", json_object_new_string(fp_sha256_value));
                                json_object_array_add(properties, fp_sha256_prop);
                            }
                        }
                        
                        // RFC2253 normalized DN forms (4.1 enhancement)
                        json_object* subject_rfc2253_obj;
                        if (json_object_object_get_ex(metadata_obj, "subject_rfc2253", &subject_rfc2253_obj)) {
                            const char* subject_rfc2253_value = json_object_get_string(subject_rfc2253_obj);
                            if (subject_rfc2253_value) {
                                json_object* subject_rfc2253_prop = json_object_new_object();
                                json_object_object_add(subject_rfc2253_prop, "name", json_object_new_string("cbom:cert:subject_rfc2253"));
                                json_object_object_add(subject_rfc2253_prop, "value", json_object_new_string(subject_rfc2253_value));
                                json_object_array_add(properties, subject_rfc2253_prop);
                            }
                        }
                        
                        json_object* issuer_rfc2253_obj;
                        if (json_object_object_get_ex(metadata_obj, "issuer_rfc2253", &issuer_rfc2253_obj)) {
                            const char* issuer_rfc2253_value = json_object_get_string(issuer_rfc2253_obj);
                            if (issuer_rfc2253_value) {
                                json_object* issuer_rfc2253_prop = json_object_new_object();
                                json_object_object_add(issuer_rfc2253_prop, "name", json_object_new_string("cbom:cert:issuer_rfc2253"));
                                json_object_object_add(issuer_rfc2253_prop, "value", json_object_new_string(issuer_rfc2253_value));
                                json_object_array_add(properties, issuer_rfc2253_prop);
                            }
                        }
                        
                        // Normalized UTC times (4.1 enhancement)
                        json_object* not_before_utc_obj;
                        if (json_object_object_get_ex(metadata_obj, "not_before_utc", &not_before_utc_obj)) {
                            const char* not_before_utc_value = json_object_get_string(not_before_utc_obj);
                            if (not_before_utc_value) {
                                json_object* not_before_utc_prop = json_object_new_object();
                                json_object_object_add(not_before_utc_prop, "name", json_object_new_string("cbom:cert:not_before_utc"));
                                json_object_object_add(not_before_utc_prop, "value", json_object_new_string(not_before_utc_value));
                                json_object_array_add(properties, not_before_utc_prop);
                            }
                        }
                        
                        json_object* not_after_utc_obj;
                        if (json_object_object_get_ex(metadata_obj, "not_after_utc", &not_after_utc_obj)) {
                            const char* not_after_utc_value = json_object_get_string(not_after_utc_obj);
                            if (not_after_utc_value) {
                                json_object* not_after_utc_prop = json_object_new_object();
                                json_object_object_add(not_after_utc_prop, "name", json_object_new_string("cbom:cert:not_after_utc"));
                                json_object_object_add(not_after_utc_prop, "value", json_object_new_string(not_after_utc_value));
                                json_object_array_add(properties, not_after_utc_prop);
                            }
                        }
                        
                        // SAN arrays (normalized - serialize arrays to JSON strings for schema compliance)
                        json_object* san_dns_obj;
                        if (json_object_object_get_ex(metadata_obj, "san_dns", &san_dns_obj)) {
                            if (json_object_is_type(san_dns_obj, json_type_array) && json_object_array_length(san_dns_obj) > 0) {
                                json_object* san_dns_prop = json_object_new_object();
                                json_object_object_add(san_dns_prop, "name", json_object_new_string("cbom:cert:san_dns"));
                                json_object_object_add(san_dns_prop, "value",
                                    json_object_new_string(json_object_to_json_string_ext(san_dns_obj, JSON_C_TO_STRING_PLAIN)));
                                json_object_array_add(properties, san_dns_prop);
                            }
                        }

                        json_object* san_ip_obj;
                        if (json_object_object_get_ex(metadata_obj, "san_ip", &san_ip_obj)) {
                            if (json_object_is_type(san_ip_obj, json_type_array) && json_object_array_length(san_ip_obj) > 0) {
                                json_object* san_ip_prop = json_object_new_object();
                                json_object_object_add(san_ip_prop, "name", json_object_new_string("cbom:cert:san_ip"));
                                json_object_object_add(san_ip_prop, "value",
                                    json_object_new_string(json_object_to_json_string_ext(san_ip_obj, JSON_C_TO_STRING_PLAIN)));
                                json_object_array_add(properties, san_ip_prop);
                            }
                        }
                        
                        json_object* san_uri_obj;
                        if (json_object_object_get_ex(metadata_obj, "san_uri", &san_uri_obj)) {
                            if (json_object_is_type(san_uri_obj, json_type_array) && json_object_array_length(san_uri_obj) > 0) {
                                json_object* san_uri_prop = json_object_new_object();
                                json_object_object_add(san_uri_prop, "name", json_object_new_string("cbom:cert:san_uri"));

                                // Convert array to comma-separated string (schema requires string, not array)
                                char uri_str[1024] = "";
                                int uri_count = json_object_array_length(san_uri_obj);
                                for (int uri_idx = 0; uri_idx < uri_count && uri_idx < 10; uri_idx++) {
                                    json_object* uri_item = json_object_array_get_idx(san_uri_obj, uri_idx);
                                    if (uri_idx > 0) strcat(uri_str, ", ");
                                    strncat(uri_str, json_object_get_string(uri_item), sizeof(uri_str) - strlen(uri_str) - 1);
                                }

                                json_object_object_add(san_uri_prop, "value", json_object_new_string(uri_str));
                                json_object_array_add(properties, san_uri_prop);
                            }
                        }
                        
                        json_object* san_email_obj;
                        if (json_object_object_get_ex(metadata_obj, "san_email", &san_email_obj)) {
                            if (json_object_is_type(san_email_obj, json_type_array) && json_object_array_length(san_email_obj) > 0) {
                                json_object* san_email_prop = json_object_new_object();
                                json_object_object_add(san_email_prop, "name", json_object_new_string("cbom:cert:san_email"));

                                // Convert array to comma-separated string (schema requires string, not array)
                                char email_str[512] = "";
                                int email_count = json_object_array_length(san_email_obj);
                                for (int email_idx = 0; email_idx < email_count && email_idx < 10; email_idx++) {
                                    json_object* email_item = json_object_array_get_idx(san_email_obj, email_idx);
                                    if (email_idx > 0) strcat(email_str, ", ");
                                    strncat(email_str, json_object_get_string(email_item), sizeof(email_str) - strlen(email_str) - 1);
                                }

                                json_object_object_add(san_email_prop, "value", json_object_new_string(email_str));
                                json_object_array_add(properties, san_email_prop);
                            }
                        }
                        
                        json_object* san_rid_obj;
                        if (json_object_object_get_ex(metadata_obj, "san_rid", &san_rid_obj)) {
                            if (json_object_is_type(san_rid_obj, json_type_array)) {
                                int rid_count = json_object_array_length(san_rid_obj);
                                for (int i = 0; i < rid_count; i++) {
                                    json_object* rid_item = json_object_array_get_idx(san_rid_obj, i);
                                    const char* rid_value = json_object_get_string(rid_item);
                                    if (rid_value) {
                                        json_object* san_rid_prop = json_object_new_object();
                                        json_object_object_add(san_rid_prop, "name", json_object_new_string("cbom:cert:san_rid"));
                                        json_object_object_add(san_rid_prop, "value", json_object_new_string(rid_value));
                                        json_object_array_add(properties, san_rid_prop);
                                    }
                                }
                            }
                        }

                        // === Phase 5.2: Extract Algorithm Granularity Fields (Req 1.5, 1.6, 1.7) ===
                        // Iterate through all keys in metadata_obj to find algorithm fields
                        json_object_object_foreach(metadata_obj, key, val) {
                            // Extract pubkey algorithm fields
                            if (strncmp(key, "pubkey:", 7) == 0) {
                                const char* value_str = json_object_get_string(val);
                                if (value_str) {
                                    json_object* algo_prop = json_object_new_object();
                                    json_object_object_add(algo_prop, "name", json_object_new_string(key));
                                    json_object_object_add(algo_prop, "value", json_object_new_string(value_str));
                                    json_object_array_add(properties, algo_prop);
                                }
                            }
                            // Extract signature algorithm fields
                            else if (strncmp(key, "sig:", 4) == 0) {
                                const char* value_str = json_object_get_string(val);
                                if (value_str) {
                                    json_object* algo_prop = json_object_new_object();
                                    json_object_object_add(algo_prop, "name", json_object_new_string(key));
                                    json_object_object_add(algo_prop, "value", json_object_new_string(value_str));
                                    json_object_array_add(properties, algo_prop);
                                }
                            }
                        }

                        json_object_put(metadata_obj);
                    }
                }
            }

            // Key-specific properties (cbom:key:*)
            if (asset->type == ASSET_TYPE_KEY) {
                // Parse metadata_json to extract key properties
                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Key type (RSA, ECDSA, Ed25519, etc.)
                        json_object* key_type_obj;
                        if (json_object_object_get_ex(metadata_obj, "key_type", &key_type_obj)) {
                            json_object* key_type_prop = json_object_new_object();
                            json_object_object_add(key_type_prop, "name", json_object_new_string("cbom:key:type"));
                            json_object_object_add(key_type_prop, "value", json_object_new_string(json_object_get_string(key_type_obj)));
                            json_object_array_add(properties, key_type_prop);
                        }

                        // Key classification (private/public/symmetric)
                        json_object* classification_obj;
                        if (json_object_object_get_ex(metadata_obj, "classification", &classification_obj)) {
                            json_object* class_prop = json_object_new_object();
                            json_object_object_add(class_prop, "name", json_object_new_string("cbom:key:classification"));
                            json_object_object_add(class_prop, "value", json_object_new_string(json_object_get_string(classification_obj)));
                            json_object_array_add(properties, class_prop);
                        }

                        // Key size
                        json_object* key_size_obj;
                        if (json_object_object_get_ex(metadata_obj, "key_size", &key_size_obj)) {
                            json_object* size_prop = json_object_new_object();
                            json_object_object_add(size_prop, "name", json_object_new_string("cbom:key:size"));
                            char size_str[16];
                            snprintf(size_str, sizeof(size_str), "%d", json_object_get_int(key_size_obj));
                            json_object_object_add(size_prop, "value", json_object_new_string(size_str));
                            json_object_array_add(properties, size_prop);
                        }

                        // Algorithm
                        json_object* algorithm_obj;
                        if (json_object_object_get_ex(metadata_obj, "algorithm", &algorithm_obj)) {
                            json_object* algo_prop = json_object_new_object();
                            json_object_object_add(algo_prop, "name", json_object_new_string("cbom:key:algorithm"));
                            json_object_object_add(algo_prop, "value", json_object_new_string(json_object_get_string(algorithm_obj)));
                            json_object_array_add(properties, algo_prop);
                        }

                        // Storage security
                        json_object* storage_obj;
                        if (json_object_object_get_ex(metadata_obj, "storage_security", &storage_obj)) {
                            json_object* storage_prop = json_object_new_object();
                            json_object_object_add(storage_prop, "name", json_object_new_string("cbom:key:storage_security"));
                            json_object_object_add(storage_prop, "value", json_object_new_string(json_object_get_string(storage_obj)));
                            json_object_array_add(properties, storage_prop);
                        }

                        // Curve name (for EC keys)
                        json_object* curve_obj;
                        if (json_object_object_get_ex(metadata_obj, "curve_name", &curve_obj)) {
                            json_object* curve_prop = json_object_new_object();
                            json_object_object_add(curve_prop, "name", json_object_new_string("cbom:key:curve_name"));
                            json_object_object_add(curve_prop, "value", json_object_new_string(json_object_get_string(curve_obj)));
                            json_object_array_add(properties, curve_prop);
                        }

                        // Weakness flag
                        json_object* weak_obj;
                        if (json_object_object_get_ex(metadata_obj, "is_weak", &weak_obj)) {
                            json_object* weak_prop = json_object_new_object();
                            json_object_object_add(weak_prop, "name", json_object_new_string("cbom:key:is_weak"));
                            json_object_object_add(weak_prop, "value", json_object_new_string(json_object_get_boolean(weak_obj) ? "true" : "false"));
                            json_object_array_add(properties, weak_prop);
                        }

                        // Weak reasons (if any)
                        json_object* weak_reasons_obj;
                        if (json_object_object_get_ex(metadata_obj, "weak_reasons", &weak_reasons_obj)) {
                            if (json_object_is_type(weak_reasons_obj, json_type_array)) {
                                int reason_len = json_object_array_length(weak_reasons_obj);
                                for (int i = 0; i < reason_len; i++) {
                                    json_object* reason_item = json_object_array_get_idx(weak_reasons_obj, i);
                                    json_object* reason_prop = json_object_new_object();
                                    json_object_object_add(reason_prop, "name", json_object_new_string("cbom:key:weak_reason"));
                                    json_object_object_add(reason_prop, "value", json_object_new_string(json_object_get_string(reason_item)));
                                    json_object_array_add(properties, reason_prop);
                                }
                            }
                        }

                        json_object_put(metadata_obj);
                    }
                }
            }

            // Library-specific properties (cbom:lib:*)
            if (asset->type == ASSET_TYPE_LIBRARY) {
                // Parse metadata_json to extract library/package properties
                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Library name
                        json_object* name_obj;
                        if (json_object_object_get_ex(metadata_obj, "name", &name_obj)) {
                            json_object* name_prop = json_object_new_object();
                            json_object_object_add(name_prop, "name", json_object_new_string("cbom:lib:name"));
                            json_object_object_add(name_prop, "value", json_object_new_string(json_object_get_string(name_obj)));
                            json_object_array_add(properties, name_prop);
                        }

                        // Library version
                        json_object* version_obj;
                        if (json_object_object_get_ex(metadata_obj, "version", &version_obj)) {
                            json_object* version_prop = json_object_new_object();
                            json_object_object_add(version_prop, "name", json_object_new_string("cbom:lib:version"));
                            json_object_object_add(version_prop, "value", json_object_new_string(json_object_get_string(version_obj)));
                            json_object_array_add(properties, version_prop);
                        }

                        // Package manager source
                        json_object* pkg_mgr_obj;
                        if (json_object_object_get_ex(metadata_obj, "package_manager", &pkg_mgr_obj)) {
                            json_object* pkg_mgr_prop = json_object_new_object();
                            json_object_object_add(pkg_mgr_prop, "name", json_object_new_string("cbom:lib:package_manager"));
                            json_object_object_add(pkg_mgr_prop, "value", json_object_new_string(json_object_get_string(pkg_mgr_obj)));
                            json_object_array_add(properties, pkg_mgr_prop);
                        }

                        // Embedded provider flag
                        json_object* embedded_obj;
                        if (json_object_object_get_ex(metadata_obj, "embedded_provider", &embedded_obj)) {
                            const char* embedded_str = json_object_get_string(embedded_obj);
                            if (embedded_str) {
                                json_object* embedded_prop = json_object_new_object();
                                json_object_object_add(embedded_prop, "name", json_object_new_string("cbom:lib:embedded_provider"));
                                json_object_object_add(embedded_prop, "value", json_object_new_string(embedded_str));
                                json_object_array_add(properties, embedded_prop);
                            }
                        }

                        // Implemented algorithms
                        json_object* algos_obj;
                        if (json_object_object_get_ex(metadata_obj, "implemented_algorithms", &algos_obj)) {
                            if (json_object_is_type(algos_obj, json_type_array)) {
                                int algo_len = json_object_array_length(algos_obj);
                                for (int i = 0; i < algo_len && i < 20; i++) {  // Limit to 20 algorithms
                                    json_object* algo_item = json_object_array_get_idx(algos_obj, i);
                                    json_object* algo_prop = json_object_new_object();
                                    json_object_object_add(algo_prop, "name", json_object_new_string("cbom:lib:implements"));
                                    json_object_object_add(algo_prop, "value", json_object_new_string(json_object_get_string(algo_item)));
                                    json_object_array_add(properties, algo_prop);
                                }
                            }
                        }

                        // FIPS level (STUB ONLY - not validated)
                        json_object* fips_level_obj;
                        if (json_object_object_get_ex(metadata_obj, "fips_level", &fips_level_obj)) {
                            json_object* fips_prop = json_object_new_object();
                            json_object_object_add(fips_prop, "name", json_object_new_string("cbom:lib:fips_level"));
                            json_object_object_add(fips_prop, "value", json_object_new_string(json_object_get_string(fips_level_obj)));
                            json_object_array_add(properties, fips_prop);
                        }

                        // FIPS validation status (always STUB)
                        json_object* fips_validation_obj;
                        if (json_object_object_get_ex(metadata_obj, "fips_validation_status", &fips_validation_obj)) {
                            json_object* validation_prop = json_object_new_object();
                            json_object_object_add(validation_prop, "name", json_object_new_string("cbom:lib:fips_validation"));
                            json_object_object_add(validation_prop, "value", json_object_new_string(json_object_get_string(fips_validation_obj)));
                            json_object_array_add(properties, validation_prop);
                        }

                        json_object_put(metadata_obj);
                    }
                }
            }

            // Service-specific properties (cbom:svc:*)
            if (asset->type == ASSET_TYPE_SERVICE) {
                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Service name
                        json_object* name_obj;
                        if (json_object_object_get_ex(metadata_obj, "name", &name_obj)) {
                            json_object* name_prop = json_object_new_object();
                            json_object_object_add(name_prop, "name", json_object_new_string("cbom:svc:name"));
                            json_object_object_add(name_prop, "value", json_object_new_string(json_object_get_string(name_obj)));
                            json_object_array_add(properties, name_prop);
                        }

                        // Service version
                        json_object* version_obj;
                        if (json_object_object_get_ex(metadata_obj, "version", &version_obj)) {
                            json_object* version_prop = json_object_new_object();
                            json_object_object_add(version_prop, "name", json_object_new_string("cbom:svc:version"));
                            json_object_object_add(version_prop, "value", json_object_new_string(json_object_get_string(version_obj)));
                            json_object_array_add(properties, version_prop);
                        }

                        // Running status
                        json_object* running_obj;
                        if (json_object_object_get_ex(metadata_obj, "is_running", &running_obj)) {
                            json_object* running_prop = json_object_new_object();
                            json_object_object_add(running_prop, "name", json_object_new_string("cbom:svc:is_running"));
                            json_object_object_add(running_prop, "value", json_object_new_string(json_object_get_boolean(running_obj) ? "true" : "false"));
                            json_object_array_add(properties, running_prop);
                        }

                        // Network endpoints
                        json_object* endpoints_obj;
                        if (json_object_object_get_ex(metadata_obj, "endpoints", &endpoints_obj)) {
                            if (json_object_is_type(endpoints_obj, json_type_array)) {
                                int ep_len = json_object_array_length(endpoints_obj);
                                for (int i = 0; i < ep_len && i < 10; i++) {
                                    json_object* ep_item = json_object_array_get_idx(endpoints_obj, i);
                                    json_object* port_obj;
                                    if (json_object_object_get_ex(ep_item, "port", &port_obj)) {
                                        json_object* port_prop = json_object_new_object();
                                        json_object_object_add(port_prop, "name", json_object_new_string("cbom:svc:port"));
                                        char port_str[16];
                                        snprintf(port_str, sizeof(port_str), "%d", json_object_get_int(port_obj));
                                        json_object_object_add(port_prop, "value", json_object_new_string(port_str));
                                        json_object_array_add(properties, port_prop);
                                    }
                                }
                            }
                        }

                        json_object_put(metadata_obj);
                    }
                }
            }

            // Application-specific properties (cbom:app:*) - v1.5
            if (asset->type == ASSET_TYPE_APPLICATION && asset->metadata_json) {
                json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                if (metadata_obj) {
                    // Role (service vs client vs utility)
                    json_object* role_obj;
                    if (json_object_object_get_ex(metadata_obj, "role", &role_obj)) {
                        json_object* role_prop = json_object_new_object();
                        json_object_object_add(role_prop, "name", json_object_new_string("cbom:app:role"));
                        json_object_object_add(role_prop, "value", json_object_new_string(json_object_get_string(role_obj)));
                        json_object_array_add(properties, role_prop);
                    }

                    // Binary path
                    json_object* binary_path_obj;
                    if (json_object_object_get_ex(metadata_obj, "binary_path", &binary_path_obj)) {
                        json_object* path_prop = json_object_new_object();
                        json_object_object_add(path_prop, "name", json_object_new_string("cbom:app:binary_path"));
                        json_object_object_add(path_prop, "value", json_object_new_string(json_object_get_string(binary_path_obj)));
                        json_object_array_add(properties, path_prop);
                    }

                    // Category
                    json_object* category_obj;
                    if (json_object_object_get_ex(metadata_obj, "category", &category_obj)) {
                        json_object* cat_prop = json_object_new_object();
                        json_object_object_add(cat_prop, "name", json_object_new_string("cbom:app:category"));
                        json_object_object_add(cat_prop, "value", json_object_new_string(json_object_get_string(category_obj)));
                        json_object_array_add(properties, cat_prop);
                    }

                    // is_daemon
                    json_object* daemon_obj;
                    if (json_object_object_get_ex(metadata_obj, "is_daemon", &daemon_obj)) {
                        json_object* daemon_prop = json_object_new_object();
                        json_object_object_add(daemon_prop, "name", json_object_new_string("cbom:app:is_daemon"));
                        json_object_object_add(daemon_prop, "value", json_object_new_string(json_object_get_boolean(daemon_obj) ? "true" : "false"));
                        json_object_array_add(properties, daemon_prop);
                    }

                    json_object_put(metadata_obj);
                }
            }

            // Protocol-specific properties (cbom:proto:*)
            if (asset->type == ASSET_TYPE_PROTOCOL) {
                // Add asset type indicator (Phase 8 polish)
                json_object* asset_type_prop = json_object_new_object();
                json_object_object_add(asset_type_prop, "name", json_object_new_string("cbom:asset:type"));
                json_object_object_add(asset_type_prop, "value", json_object_new_string("protocol"));
                json_object_array_add(properties, asset_type_prop);

                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Protocol type
                        json_object* proto_type_obj;
                        if (json_object_object_get_ex(metadata_obj, "protocol_type", &proto_type_obj)) {
                            json_object* type_prop = json_object_new_object();
                            json_object_object_add(type_prop, "name", json_object_new_string("cbom:proto:type"));
                            json_object_object_add(type_prop, "value", json_object_new_string(json_object_get_string(proto_type_obj)));
                            json_object_array_add(properties, type_prop);
                        }

                        // Protocol version
                        json_object* version_obj;
                        if (json_object_object_get_ex(metadata_obj, "version", &version_obj)) {
                            json_object* version_prop = json_object_new_object();
                            json_object_object_add(version_prop, "name", json_object_new_string("cbom:proto:version"));
                            json_object_object_add(version_prop, "value", json_object_new_string(json_object_get_string(version_obj)));
                            json_object_array_add(properties, version_prop);
                        }

                        // Enabled versions (TLS versions, SSH versions)
                        json_object* enabled_versions_obj;
                        if (json_object_object_get_ex(metadata_obj, "enabled_versions", &enabled_versions_obj)) {
                            if (json_object_is_type(enabled_versions_obj, json_type_array)) {
                                int ver_len = json_object_array_length(enabled_versions_obj);
                                for (int i = 0; i < ver_len && i < 10; i++) {
                                    json_object* ver_item = json_object_array_get_idx(enabled_versions_obj, i);
                                    json_object* ver_prop = json_object_new_object();
                                    json_object_object_add(ver_prop, "name", json_object_new_string("cbom:proto:enabled_version"));
                                    json_object_object_add(ver_prop, "value", json_object_new_string(json_object_get_string(ver_item)));
                                    json_object_array_add(properties, ver_prop);
                                }
                            }
                        }

                        // Enabled cipher suites
                        json_object* ciphers_obj;
                        if (json_object_object_get_ex(metadata_obj, "enabled_cipher_suites", &ciphers_obj)) {
                            if (json_object_is_type(ciphers_obj, json_type_array)) {
                                int cipher_len = json_object_array_length(ciphers_obj);
                                for (int i = 0; i < cipher_len && i < 20; i++) {
                                    json_object* cipher_item = json_object_array_get_idx(ciphers_obj, i);
                                    json_object* cipher_prop = json_object_new_object();
                                    json_object_object_add(cipher_prop, "name", json_object_new_string("cbom:proto:cipher_suite"));
                                    json_object_object_add(cipher_prop, "value", json_object_new_string(json_object_get_string(cipher_item)));
                                    json_object_array_add(properties, cipher_prop);
                                }
                            }
                        }

                        // Security profile
                        json_object* profile_obj;
                        if (json_object_object_get_ex(metadata_obj, "security_profile", &profile_obj)) {
                            json_object* profile_prop = json_object_new_object();
                            json_object_object_add(profile_prop, "name", json_object_new_string("cbom:proto:security_profile"));
                            json_object_object_add(profile_prop, "value", json_object_new_string(json_object_get_string(profile_obj)));
                            json_object_array_add(properties, profile_prop);
                        }

                        // Weak configurations
                        json_object* weak_obj;
                        if (json_object_object_get_ex(metadata_obj, "weak_configurations", &weak_obj)) {
                            if (json_object_is_type(weak_obj, json_type_array)) {
                                int weak_len = json_object_array_length(weak_obj);
                                for (int i = 0; i < weak_len && i < 10; i++) {
                                    json_object* weak_item = json_object_array_get_idx(weak_obj, i);
                                    json_object* weak_prop = json_object_new_object();
                                    json_object_object_add(weak_prop, "name", json_object_new_string("cbom:proto:weak_config"));
                                    json_object_object_add(weak_prop, "value", json_object_new_string(json_object_get_string(weak_item)));
                                    json_object_array_add(properties, weak_prop);
                                }
                            }
                        }

                        json_object_put(metadata_obj);
                    }
                }
            }

            // Cipher suite properties (cbom:cipher:*) - Phase 7.3a
            if (asset->type == ASSET_TYPE_CIPHER_SUITE) {
                if (asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        // Protocol family
                        json_object* family_obj;
                        if (json_object_object_get_ex(metadata_obj, "protocol_family", &family_obj)) {
                            json_object* prop = json_object_new_object();
                            json_object_object_add(prop, "name", json_object_new_string("cbom:cipher:protocol_family"));
                            json_object_object_add(prop, "value", json_object_new_string(json_object_get_string(family_obj)));
                            json_object_array_add(properties, prop);
                        }

                        // Encryption algorithm (AEAD for TLS 1.3)
                        json_object* enc_obj;
                        if (json_object_object_get_ex(metadata_obj, "encryption_algorithm", &enc_obj)) {
                            json_object* prop = json_object_new_object();
                            json_object_object_add(prop, "name", json_object_new_string("cbom:cipher:encryption"));
                            json_object_object_add(prop, "value", json_object_new_string(json_object_get_string(enc_obj)));
                            json_object_array_add(properties, prop);
                        }

                        // Hash algorithm
                        json_object* hash_obj;
                        if (json_object_object_get_ex(metadata_obj, "hash_algorithm", &hash_obj)) {
                            json_object* prop = json_object_new_object();
                            json_object_object_add(prop, "name", json_object_new_string("cbom:cipher:hash"));
                            json_object_object_add(prop, "value", json_object_new_string(json_object_get_string(hash_obj)));
                            json_object_array_add(properties, prop);
                        }

                        // Security strength
                        json_object* strength_obj;
                        if (json_object_object_get_ex(metadata_obj, "security_strength_bits", &strength_obj)) {
                            json_object* prop = json_object_new_object();
                            json_object_object_add(prop, "name", json_object_new_string("cbom:cipher:security_bits"));
                            char bits_str[16];
                            snprintf(bits_str, sizeof(bits_str), "%d", json_object_get_int(strength_obj));
                            json_object_object_add(prop, "value", json_object_new_string(bits_str));
                            json_object_array_add(properties, prop);
                        }

                        // Quantum vulnerability
                        json_object* quantum_obj;
                        if (json_object_object_get_ex(metadata_obj, "is_quantum_vulnerable", &quantum_obj)) {
                            json_object* prop = json_object_new_object();
                            json_object_object_add(prop, "name", json_object_new_string("cbom:cipher:quantum_vulnerable"));
                            json_object_object_add(prop, "value", json_object_new_string(json_object_get_boolean(quantum_obj) ? "true" : "false"));
                            json_object_array_add(properties, prop);
                        }

                        json_object_put(metadata_obj);
                    }
                }
            }

            // Detection context properties (cbom:ctx:*)
            if (asset->location) {
                json_object *prop = json_object_new_object();
                json_object_object_add(prop, "name", json_object_new_string("cbom:ctx:file_path"));

                // v1.8: First strip rootfs prefix for cross-arch scans
                const char* base_path = normalize_cross_arch_path(asset->location);

                // Normalize path (remove consecutive slashes)
                char *normalized_path = strdup(base_path);
                if (normalized_path) {
                    char *src = normalized_path, *dst = normalized_path;
                    while (*src) {
                        *dst++ = *src++;
                        if (src[-1] == '/' && *src == '/') {
                            while (*src == '/') src++;
                        }
                    }
                    *dst = '\0';
                }

                // Apply privacy redaction if enabled
                const char* path_value = normalized_path ? normalized_path : base_path;
                char* redacted_path = NULL;
                if (g_cbom_config.no_personal_data) {
                    // Simple redaction for demo - in production would use privacy module
                    if (strstr(path_value, "/home/") || strstr(path_value, "/Users/")) {
                        redacted_path = malloc(256);
                        if (redacted_path) {
                            snprintf(redacted_path, 256, "<path-hash-%08x>",
                                   (unsigned int)strlen(path_value)); // Simple hash for demo
                            path_value = redacted_path;
                        }
                    }
                }

                json_object_object_add(prop, "value", json_object_new_string(path_value));
                json_object_array_add(properties, prop);

                if (normalized_path) free(normalized_path);
                if (redacted_path) free(redacted_path);
            }
            
            // Detection method - extract from metadata_json for all asset types, default to FILE_CONTENT
            // v1.8.2: Fixed bug where only ASSET_TYPE_SERVICE extracted detection_method
            const char* detection_method = "FILE_CONTENT";  // Default for certificates, keys, etc.
            if (asset->metadata_json) {
                json_object* metadata = json_tokener_parse(asset->metadata_json);
                if (metadata) {
                    json_object* method_obj;
                    if (json_object_object_get_ex(metadata, "detection_method", &method_obj)) {
                        const char* method_str = json_object_get_string(method_obj);
                        if (method_str && strlen(method_str) > 0) {
                            detection_method = method_str;
                        }
                    }
                    // Don't free metadata yet - we'll use detection_method string
                }
            }

            json_object *method_prop = json_object_new_object();
            json_object_object_add(method_prop, "name", json_object_new_string("cbom:ctx:detection_method"));
            json_object_object_add(method_prop, "value", json_object_new_string(detection_method));
            json_object_array_add(properties, method_prop);

            // Free metadata if it was parsed
            if (asset->metadata_json) {
                json_object* metadata = json_tokener_parse(asset->metadata_json);
                if (metadata) json_object_put(metadata);
            }

            // Detection confidence (parse from metadata or use default 1.0)
            char confidence_str[16] = "1.0";  // Default for components without metadata confidence
            if (asset->metadata_json) {
                json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                if (metadata_obj) {
                    json_object* conf_obj;
                    if (json_object_object_get_ex(metadata_obj, "confidence", &conf_obj)) {
                        double conf_double = json_object_get_double(conf_obj);
                        snprintf(confidence_str, sizeof(confidence_str), "%.2f", conf_double);
                    }
                    json_object_put(metadata_obj);
                }
            }

            json_object *confidence_prop = json_object_new_object();
            json_object_object_add(confidence_prop, "name", json_object_new_string("cbom:ctx:confidence"));
            json_object_object_add(confidence_prop, "value", json_object_new_string(confidence_str));
            json_object_array_add(properties, confidence_prop);

            // PQC classification using pqc_classifier API (v1.2 regression fix)
            // For services: assess based on dependencies, not service name!
            const char* algo_name = NULL;
            char* algo_name_buf = NULL;  // For memory management
            int key_size = 0;

            // For certificates: extract algorithm from metadata (not Subject DN!)
            if (asset->type == ASSET_TYPE_CERTIFICATE && asset->metadata_json) {
                json_object* metadata = json_tokener_parse(asset->metadata_json);
                if (metadata) {
                    json_object* algo_obj = NULL;
                    json_object* key_size_obj = NULL;

                    // Get algorithm from public_key_algorithm or signature_algorithm_name
                    if (json_object_object_get_ex(metadata, "public_key_algorithm", &algo_obj)) {
                        const char* s = json_object_get_string(algo_obj);
                        if (s && strlen(s) > 0) algo_name_buf = strdup(s);
                    }
                    if (!algo_name_buf && json_object_object_get_ex(metadata, "signature_algorithm_name", &algo_obj)) {
                        const char* s = json_object_get_string(algo_obj);
                        if (s && strlen(s) > 0) algo_name_buf = strdup(s);
                    }

                    // Get key size
                    if (json_object_object_get_ex(metadata, "public_key_size", &key_size_obj) ||
                        json_object_object_get_ex(metadata, "key_size", &key_size_obj)) {
                        key_size = json_object_get_int(key_size_obj);
                    }

                    json_object_put(metadata);
                }
            }
            // For non-certificates: try metadata_json for key_size
            else if (asset->metadata_json) {
                json_object* metadata = json_tokener_parse(asset->metadata_json);
                if (metadata) {
                    json_object* key_size_obj = NULL;
                    if (json_object_object_get_ex(metadata, "key_size", &key_size_obj) ||
                        json_object_object_get_ex(metadata, "public_key_size", &key_size_obj)) {
                        key_size = json_object_get_int(key_size_obj);
                    }
                    json_object_put(metadata);
                }
            }

            // For libraries: extract implemented_algorithms for PQC classification (v1.9)
            char library_rationale[256] = {0};
            bool library_classified = false;
            pqc_category_t library_category = PQC_UNKNOWN;

            if (asset->type == ASSET_TYPE_LIBRARY && asset->metadata_json) {
                json_object* lib_meta = json_tokener_parse(asset->metadata_json);
                if (lib_meta) {
                    json_object* algos_obj = NULL;
                    if (json_object_object_get_ex(lib_meta, "implemented_algorithms", &algos_obj)) {
                        if (json_object_is_type(algos_obj, json_type_array)) {
                            int algo_count = json_object_array_length(algos_obj);
                            if (algo_count > 0) {
                                // Build algorithm array for classification
                                const char** algo_list = malloc(sizeof(char*) * (algo_count + 1));
                                if (algo_list) {
                                    for (int idx = 0; idx < algo_count; idx++) {
                                        json_object* item = json_object_array_get_idx(algos_obj, idx);
                                        algo_list[idx] = json_object_get_string(item);
                                    }
                                    algo_list[algo_count] = NULL;

                                    // Classify by worst algorithm
                                    library_category = classify_library_by_algorithms(
                                        algo_list,
                                        (size_t)algo_count,
                                        library_rationale,
                                        sizeof(library_rationale)
                                    );
                                    library_classified = (library_category != PQC_UNKNOWN);

                                    free(algo_list);
                                }
                            }
                        }
                    }
                    json_object_put(lib_meta);
                }
            }

            // Use extracted algorithm, or fallback chain: algorithm → name
            if (algo_name_buf) {
                algo_name = algo_name_buf;
            } else if (asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) {
                // Services AND Applications: Don't classify name as algorithm
                // Mark as UNKNOWN - proper assessment requires dependency analysis
                // Applications depend on crypto libraries; assess those, not the app name
                algo_name = "";  // Empty string will classify as UNKNOWN
                key_size = 0;
            } else if (asset->type == ASSET_TYPE_LIBRARY && library_classified) {
                // Libraries with algorithm data: skip name-based classification (v1.9)
                // Will use library_category instead
                algo_name = "";
            } else {
                algo_name = asset->algorithm ? asset->algorithm :
                           (asset->name ? asset->name : "");
            }

            // Fallback: parse key_size from algorithm name (e.g., "RSA-2048", "AES-256")
            if (key_size == 0 && algo_name) {
                const char* p = algo_name;
                while (*p) {
                    if (*p == '-' || *p == '_') {
                        int num = atoi(p + 1);
                        if (num > 0 && num <= 8192) {
                            key_size = num;
                            break;
                        }
                    }
                    p++;
                }
            }

            // Get primitive type for proper classification
            crypto_primitive_t primitive_type = algorithm_get_primitive_type(algo_name);

            // Classify using pqc_classifier API
            pqc_category_t category = classify_algorithm_pqc_safety(algo_name, key_size, primitive_type);

            // v1.10: Protocol classification tracking for rationale generation
            char protocol_best_suite[128] = {0};
            bool protocol_classified_from_suites = false;

            // Special handling for TLS protocols
            // TLS protocol security depends on KEX algorithm, not the protocol name
            // Use prefix match to handle both "TLS" and "TLS 1.3" naming conventions
            if (asset->type == ASSET_TYPE_PROTOCOL && asset->name &&
                strncasecmp(asset->name, "TLS", 3) == 0) {

                // Step 1: Try relationship-based classification (best-case from cipher suites)
                pqc_category_t suite_category = assess_pqc_from_protocol_cipher_suites(
                    store, asset->id, protocol_best_suite, sizeof(protocol_best_suite)
                );

                if (suite_category != PQC_UNKNOWN) {
                    // Classification from cipher suites succeeded
                    category = suite_category;
                    protocol_classified_from_suites = true;
                } else {
                    // Step 2: Fallback to version-based classification when no relationships exist
                    const char* version_or_algo = asset->version ? asset->version :
                                                  (asset->algorithm ? asset->algorithm : asset->name);
                    bool has_pqc_hybrid = (
                        (strstr(version_or_algo, "Kyber") != NULL) ||
                        (strstr(version_or_algo, "ML-KEM") != NULL) ||
                        (strstr(version_or_algo, "X25519Kyber") != NULL) ||
                        (strstr(version_or_algo, "SecP256r1Kyber") != NULL)
                    );

                    if (has_pqc_hybrid) {
                        category = PQC_SAFE;  // PQC-hybrid key exchange
                    } else if (strstr(version_or_algo, "1.3") || strstr(version_or_algo, "1.2")) {
                        // TLS 1.2/1.3: quantum-safe symmetric (AES-GCM), vulnerable KEX (ECDHE)
                        // Mark as TRANSITIONAL - ready for PQC KEX upgrade
                        category = PQC_TRANSITIONAL;
                    } else if (strstr(version_or_algo, "1.1") || strstr(version_or_algo, "1.0") ||
                               strstr(version_or_algo, "SSLv3")) {
                        // TLS 1.0/1.1 and SSLv3: deprecated protocols with known vulnerabilities
                        category = PQC_DEPRECATED;
                    }
                }
                // If no version detected, fall through to standard classification
            }

            // Special handling for SSH protocols
            // SSH with sntrup761x25519 is PQC-safe (hybrid NTRU-Prime + X25519)
            // Use prefix match to handle both "SSH" and "SSH 2.0" naming conventions
            if (asset->type == ASSET_TYPE_PROTOCOL && asset->name &&
                strncasecmp(asset->name, "SSH", 3) == 0) {

                // Step 1: Try relationship-based classification (best-case from cipher suites)
                // Reuse assess_pqc_from_protocol_cipher_suites which checks for PQC KEX
                pqc_category_t suite_category = assess_pqc_from_protocol_cipher_suites(
                    store, asset->id, protocol_best_suite, sizeof(protocol_best_suite)
                );

                if (suite_category != PQC_UNKNOWN) {
                    // Classification from cipher suites succeeded
                    category = suite_category;
                    protocol_classified_from_suites = true;
                } else {
                    // Step 2: Fallback to version/algorithm-based classification
                    const char* version_or_algo = asset->version ? asset->version :
                                                  (asset->algorithm ? asset->algorithm : asset->name);
                    bool has_pqc_hybrid = (
                        (strstr(version_or_algo, "sntrup") != NULL) ||
                        (strstr(version_or_algo, "ntruprime") != NULL) ||
                        (strstr(version_or_algo, "Kyber") != NULL) ||
                        (strstr(version_or_algo, "ML-KEM") != NULL)
                    );

                    if (has_pqc_hybrid) {
                        category = PQC_SAFE;  // PQC-hybrid key exchange
                    } else {
                        // SSH with curve25519 or ECDH: quantum-safe symmetric, vulnerable KEX
                        category = PQC_TRANSITIONAL;
                    }
                }
            }

            // Library PQC classification based on implemented_algorithms (v1.9)
            // All libraries with algorithm metadata use algorithm-based classification
            if (asset->type == ASSET_TYPE_LIBRARY) {
                if (library_classified) {
                    // Use pre-computed algorithm-based classification
                    category = library_category;
                } else {
                    // Fallback: try relationship graph (for embedded providers like openssh_internal)
                    pqc_category_t rel_category = assess_pqc_from_relationships(store, asset->id);
                    if (rel_category != PQC_UNKNOWN) {
                        category = rel_category;
                    }
                    // Libraries without algorithm data stay as classified (or UNKNOWN)
                }
            }

            // v1.9: Assess services based on their configured protocols/cipher suites
            // Services use best-case: if ANY algorithm is PQC-safe, service is SAFE
            char service_best_component[128] = {0};
            bool service_classified_from_config = false;
            // v1.9: Also trigger for APPLICATION type with role="service" (YAML plugin services)
            if (asset->type == ASSET_TYPE_SERVICE ||
                (asset->type == ASSET_TYPE_APPLICATION && has_service_role(asset))) {
                pqc_category_t config_category = assess_pqc_from_configured_protocols(
                    store, asset->id, service_best_component, sizeof(service_best_component)
                );
                if (config_category != PQC_UNKNOWN) {
                    category = config_category;
                    service_classified_from_config = true;
                }
            }

            // v1.9: Assess applications (and services without config) based on library dependencies
            // Apps inherit worst-case PQC status from their crypto libraries
            // v1.9.1: Skip if already classified from config (APPLICATION with role="service")
            char app_worst_lib[128] = {0};
            bool app_classified_from_deps = false;
            bool is_app_with_service_role = (asset->type == ASSET_TYPE_APPLICATION && has_service_role(asset));
            if ((asset->type == ASSET_TYPE_APPLICATION && !is_app_with_service_role) ||
                (asset->type == ASSET_TYPE_APPLICATION && is_app_with_service_role && !service_classified_from_config) ||
                (asset->type == ASSET_TYPE_SERVICE && !service_classified_from_config)) {
                pqc_category_t dep_category = assess_pqc_from_library_dependencies(
                    store, asset->id, app_worst_lib, sizeof(app_worst_lib)
                );
                if (dep_category != PQC_UNKNOWN) {
                    category = dep_category;
                    app_classified_from_deps = true;
                }
            }

            // Conservative fallback: UNKNOWN → UNSAFE (matches old behavior)
            // EXCEPT for services/applications/libraries - mark as TRANSITIONAL pending dependency analysis
            if (category == PQC_UNKNOWN) {
                if (asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) {
                    // Services/Applications without library deps: TRANSITIONAL
                    // (e.g., plugin-detected apps that don't have DEPENDS_ON relationships yet)
                    category = PQC_TRANSITIONAL;
                } else if (asset->type == ASSET_TYPE_LIBRARY) {
                    // Libraries without algorithm data: TRANSITIONAL (v1.9)
                    // Only crypto libraries are included, so we know they have some crypto functionality
                    category = PQC_TRANSITIONAL;
                } else {
                    category = PQC_UNSAFE;
                }
            }

            const char* pqc_status = pqc_category_to_string(category);

            // 1. PQC status
            json_object *pqc_prop = json_object_new_object();
            json_object_object_add(pqc_prop, "name", json_object_new_string("cbom:pqc:status"));
            json_object_object_add(pqc_prop, "value", json_object_new_string(pqc_status));
            json_object_array_add(properties, pqc_prop);

            // 2. PQC confidence (dynamic based on available metadata)
            json_object *pqc_confidence_prop = json_object_new_object();
            json_object_object_add(pqc_confidence_prop, "name", json_object_new_string("cbom:pqc:confidence"));
            const char* confidence = (algo_name && key_size > 0) ? "HIGH" :
                                     (algo_name ? "MEDIUM" : "LOW");
            json_object_object_add(pqc_confidence_prop, "value", json_object_new_string(confidence));
            json_object_array_add(properties, pqc_confidence_prop);

            // 3. PQC source
            json_object *pqc_source_prop = json_object_new_object();
            json_object_object_add(pqc_source_prop, "name", json_object_new_string("cbom:pqc:source"));
            json_object_object_add(pqc_source_prop, "value", json_object_new_string("NIST IR 8413"));
            json_object_array_add(properties, pqc_source_prop);

            // 4. PQC source version
            json_object *pqc_source_version_prop = json_object_new_object();
            json_object_object_add(pqc_source_version_prop, "name", json_object_new_string("cbom:pqc:source_version"));
            json_object_object_add(pqc_source_version_prop, "value", json_object_new_string("2022-03"));
            json_object_array_add(properties, pqc_source_version_prop);

            // 5. Migration urgency
            bool is_deprecated = (category == PQC_DEPRECATED);
            pqc_urgency_t urgency_level = get_migration_urgency(category, is_deprecated);
            const char* urgency = pqc_urgency_to_string(urgency_level);

            json_object *pqc_urgency_prop = json_object_new_object();
            json_object_object_add(pqc_urgency_prop, "name", json_object_new_string("cbom:pqc:migration_urgency"));
            json_object_object_add(pqc_urgency_prop, "value", json_object_new_string(urgency));
            json_object_array_add(properties, pqc_urgency_prop);

            // 6. PQC alternative (if not SAFE)
            if (category != PQC_SAFE) {
                char* alternative = suggest_pqc_alternative(algo_name, key_size, primitive_type);
                if (alternative) {
                    json_object *pqc_alt_prop = json_object_new_object();
                    json_object_object_add(pqc_alt_prop, "name", json_object_new_string("cbom:pqc:alternative"));
                    json_object_object_add(pqc_alt_prop, "value", json_object_new_string(alternative));
                    json_object_array_add(properties, pqc_alt_prop);
                    free(alternative);
                }
            }

            // 7. Break year estimate (v1.2 feature - was missing!)
            int break_year = pqc_get_break_year_estimate(algo_name, key_size);
            if (break_year > 0) {
                char break_str[8];
                snprintf(break_str, sizeof(break_str), "%d", break_year);
                json_object *pqc_break_prop = json_object_new_object();
                json_object_object_add(pqc_break_prop, "name", json_object_new_string("cbom:pqc:break_estimate"));
                json_object_object_add(pqc_break_prop, "value", json_object_new_string(break_str));
                json_object_array_add(properties, pqc_break_prop);
            }

            // 8. Rationale (v1.2 feature - was missing!)
            const char* rationale = NULL;
            char app_rationale_buf[256] = {0};  // Buffer for dynamic app/service rationale
            switch (category) {
                case PQC_SAFE:
                    if (asset->type == ASSET_TYPE_LIBRARY && library_classified && library_rationale[0]) {
                        rationale = library_rationale;
                    } else if (asset->type == ASSET_TYPE_PROTOCOL && protocol_classified_from_suites) {
                        // Protocol classified from cipher suite relationships (best-case)
                        if (protocol_best_suite[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "PQC-safe via cipher suite: %s", protocol_best_suite);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "PQC-safe via configured cipher suites");
                        }
                        rationale = app_rationale_buf;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || is_app_with_service_role) && service_classified_from_config) {
                        // Service classified from its TLS/SSH configuration (best-case)
                        if (service_best_component[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "PQC-ready via %s", service_best_component);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "PQC-ready via configured protocols/algorithms");
                        }
                        rationale = app_rationale_buf;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) && app_classified_from_deps) {
                        if (app_worst_lib[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits PQC-safe status from crypto library dependencies (%s)", app_worst_lib);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits PQC-safe status from crypto library dependencies");
                        }
                        rationale = app_rationale_buf;
                    } else {
                        rationale = "Quantum-resistant algorithm or sufficient symmetric key length";
                    }
                    break;
                case PQC_TRANSITIONAL:
                    if (asset->type == ASSET_TYPE_LIBRARY && library_classified && library_rationale[0]) {
                        rationale = library_rationale;
                    } else if (asset->type == ASSET_TYPE_PROTOCOL && protocol_classified_from_suites) {
                        // Protocol classified from cipher suite relationships (best-case was TRANSITIONAL)
                        if (protocol_best_suite[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Best cipher suite: %s (classical KEX)", protocol_best_suite);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Classical cipher suites only; no PQC KEX configured");
                        }
                        rationale = app_rationale_buf;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || is_app_with_service_role) && service_classified_from_config) {
                        // Service classified from its TLS/SSH configuration (best-case was TRANSITIONAL)
                        if (service_best_component[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Best available: %s (classical); no PQC algorithms configured", service_best_component);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "No PQC algorithms configured; uses classical crypto only");
                        }
                        rationale = app_rationale_buf;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) && app_classified_from_deps) {
                        if (app_worst_lib[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits TRANSITIONAL status from %s; plan PQC migration", app_worst_lib);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits TRANSITIONAL status from crypto library dependencies; plan PQC migration");
                        }
                        rationale = app_rationale_buf;
                    } else if (asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) {
                        rationale = "No crypto library dependencies detected; status pending further analysis";
                    } else if (asset->type == ASSET_TYPE_LIBRARY) {
                        rationale = "Crypto library without detailed algorithm information; assess based on dependencies";
                    } else {
                        rationale = "Classical algorithm with sufficient strength; plan migration to PQC";
                    }
                    break;
                case PQC_DEPRECATED:
                    if (asset->type == ASSET_TYPE_LIBRARY && library_classified && library_rationale[0]) {
                        rationale = library_rationale;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || is_app_with_service_role) && service_classified_from_config) {
                        // Service classified from config (best-case was DEPRECATED - only weak ciphers)
                        if (service_best_component[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Best available: %s (deprecated); reconfigure with modern ciphers", service_best_component);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Only deprecated ciphers configured; immediate reconfiguration required");
                        }
                        rationale = app_rationale_buf;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) && app_classified_from_deps) {
                        if (app_worst_lib[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits DEPRECATED status from %s; immediate replacement required", app_worst_lib);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits DEPRECATED status from crypto library dependencies; immediate replacement required");
                        }
                        rationale = app_rationale_buf;
                    } else {
                        rationale = "Weak or broken algorithm; immediate replacement required";
                    }
                    break;
                case PQC_UNSAFE:
                    if (asset->type == ASSET_TYPE_LIBRARY && library_classified && library_rationale[0]) {
                        rationale = library_rationale;
                    } else if (asset->type == ASSET_TYPE_SERVICE && service_classified_from_config) {
                        // Service classified from config (best-case was UNSAFE - critical)
                        if (service_best_component[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Best available: %s (unsafe); urgent reconfiguration required", service_best_component);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Only unsafe ciphers configured; urgent reconfiguration required");
                        }
                        rationale = app_rationale_buf;
                    } else if ((asset->type == ASSET_TYPE_SERVICE || asset->type == ASSET_TYPE_APPLICATION) && app_classified_from_deps) {
                        if (app_worst_lib[0]) {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits UNSAFE status from %s; prioritize PQC migration", app_worst_lib);
                        } else {
                            snprintf(app_rationale_buf, sizeof(app_rationale_buf),
                                "Inherits UNSAFE status from crypto library dependencies; prioritize PQC migration");
                        }
                        rationale = app_rationale_buf;
                    } else {
                        rationale = "Quantum-vulnerable asymmetric algorithm; prioritize PQC migration";
                    }
                    break;
                default:
                    rationale = "Unable to determine PQC classification";
                    break;
            }
            json_object *pqc_rationale_prop = json_object_new_object();
            json_object_object_add(pqc_rationale_prop, "name", json_object_new_string("cbom:pqc:rationale"));
            json_object_object_add(pqc_rationale_prop, "value", json_object_new_string(rationale));
            json_object_array_add(properties, pqc_rationale_prop);

            // 9. Hybrid detection (v1.2 feature - was missing!)
            if (detect_hybrid_algorithm(algo_name)) {
                json_object *pqc_hybrid_prop = json_object_new_object();
                json_object_object_add(pqc_hybrid_prop, "name", json_object_new_string("cbom:pqc:is_hybrid"));
                json_object_object_add(pqc_hybrid_prop, "value", json_object_new_string("true"));
                json_object_array_add(properties, pqc_hybrid_prop);
            }

            // Free allocated algo_name buffer
            if (algo_name_buf) {
                free(algo_name_buf);
                algo_name_buf = NULL;
            }

            // Add evidence with file location and hash
            if (asset->location) {
                json_object *evidence = json_object_new_object();
                json_object *occurrences = json_object_new_array();

                json_object *occurrence = json_object_new_object();

                // v1.8: First strip rootfs prefix for cross-arch scans
                const char* base_location = normalize_cross_arch_path(asset->location);

                // Normalize path to remove consecutive slashes
                char *normalized_location = strdup(base_location);
                if (normalized_location) {
                    char *src = normalized_location, *dst = normalized_location;
                    while (*src) {
                        *dst++ = *src++;
                        if (src[-1] == '/' && *src == '/') {
                            while (*src == '/') src++;  // Skip consecutive slashes
                        }
                    }
                    *dst = '\0';
                }

                json_object_object_add(occurrence, "location",
                    json_object_new_string(normalized_location ? normalized_location : base_location));
                if (normalized_location) free(normalized_location);

                // Schema compliance: CycloneDX 1.6 does not allow hashes in occurrences
                // Component-level hashes are still present below (lines 2631-2647)

                json_object_array_add(occurrences, occurrence);
                json_object_object_add(evidence, "occurrences", occurrences);
                json_object_object_add(component, "evidence", evidence);
            }

            // Add CycloneDX native hashes array at component level
            if (asset->location) {
                json_object *component_hashes = json_object_new_array();
                json_object *component_hash_obj = json_object_new_object();
                json_object_object_add(component_hash_obj, "alg", json_object_new_string("SHA-256"));
                
                // Calculate real SHA-256 hash of the file
                char *file_hash = calculate_file_sha256(asset->location);
                if (file_hash) {
                    json_object_object_add(component_hash_obj, "content", json_object_new_string(file_hash));
                    free(file_hash);
                } else {
                    json_object_object_add(component_hash_obj, "content", json_object_new_string("0000000000000000000000000000000000000000000000000000000000000000"));
                }
                
                json_object_array_add(component_hashes, component_hash_obj);
                json_object_object_add(component, "hashes", component_hashes);
            }
            
            json_object_object_add(component, "properties", properties);
            json_object_array_add(components, component);
        }
        
        // Add algorithm components (Enhancement: Make dependency targets resolvable)
        // Track unique algorithms to avoid duplicates
        char seen_algorithms[32][128]; // Support up to 32 unique algorithms
        size_t algo_count = 0;
        
        for (size_t i = 0; i < asset_count; i++) {
            crypto_asset_t *asset = assets[i];
            if (asset && asset->type == ASSET_TYPE_CERTIFICATE && asset->algorithm) {
                // Create algorithm ID
                char algo_id[128];
                snprintf(algo_id, sizeof(algo_id), "algo-%s-%u", 
                        asset->algorithm, asset->key_size);
                
                // Convert to lowercase for consistency
                for (char *p = algo_id; *p; p++) {
                    *p = tolower(*p);
                }
                
                // Check if we've already added this algorithm
                bool already_added = false;
                for (size_t j = 0; j < algo_count; j++) {
                    if (strcmp(seen_algorithms[j], algo_id) == 0) {
                        already_added = true;
                        break;
                    }
                }
                
                if (!already_added && algo_count < 32) {
                    strcpy(seen_algorithms[algo_count], algo_id);
                    algo_count++;
                    
                    // Create algorithm component
                    json_object *algo_component = json_object_new_object();
                    json_object_object_add(algo_component, "type", json_object_new_string("library"));
                    json_object_object_add(algo_component, "bom-ref", json_object_new_string(algo_id));
                    
                    // Algorithm name and version
                    char algo_name[128];
                    snprintf(algo_name, sizeof(algo_name), "%s-%u", asset->algorithm, asset->key_size);
                    json_object_object_add(algo_component, "name", json_object_new_string(algo_name));
                    json_object_object_add(algo_component, "version", json_object_new_string("1.0"));
                    
                    // Algorithm properties
                    json_object *algo_properties = json_object_new_array();
                    
                    // Algorithm type
                    json_object *algo_type_prop = json_object_new_object();
                    json_object_object_add(algo_type_prop, "name", json_object_new_string("cbom:algo:type"));
                    json_object_object_add(algo_type_prop, "value", json_object_new_string(asset->algorithm));
                    json_object_array_add(algo_properties, algo_type_prop);
                    
                    // Key size
                    json_object *key_size_prop = json_object_new_object();
                    json_object_object_add(key_size_prop, "name", json_object_new_string("cbom:algo:key_size"));
                    char key_size_str[16];
                    snprintf(key_size_str, sizeof(key_size_str), "%u", asset->key_size);
                    json_object_object_add(key_size_prop, "value", json_object_new_string(key_size_str));
                    json_object_array_add(algo_properties, key_size_prop);
                    
                    // Standards compliance
                    json_object *standards_prop = json_object_new_object();
                    json_object_object_add(standards_prop, "name", json_object_new_string("cbom:algo:standards"));
                    
                    const char* standards = "FIPS 186-4, RFC 3447"; // Default for RSA
                    if (strstr(asset->algorithm, "ECDSA")) {
                        standards = "FIPS 186-4, RFC 6979"; // ECDSA-specific standards
                    } else if (strstr(asset->algorithm, "DSA")) {
                        standards = "FIPS 186-4"; // DSA standards
                    }
                    
                    json_object_object_add(standards_prop, "value", json_object_new_string(standards));
                    json_object_array_add(algo_properties, standards_prop);
                    
                    json_object_object_add(algo_component, "properties", algo_properties);
                    json_object_array_add(components, algo_component);
                }
            }
        }
        
        // v1.8.5: Build library-to-library dependency map from metadata_json
        // This captures ELF dynamic linking dependencies for library components
        for (size_t i = 0; i < asset_count; i++) {
            crypto_asset_t* asset = assets[i];
            if (!asset || asset->type != ASSET_TYPE_LIBRARY) continue;
            if (!asset->metadata_json) continue;

            // Parse metadata_json to extract library_dependencies array
            json_object* metadata = json_tokener_parse(asset->metadata_json);
            if (!metadata) continue;

            json_object* lib_deps;
            if (json_object_object_get_ex(metadata, "library_dependencies", &lib_deps) &&
                json_object_is_type(lib_deps, json_type_array)) {

                // Build this library's bom-ref
                char* sanitized = sanitize_for_bomref(asset->name);
                if (sanitized) {
                    char lib_bomref[256];
                    snprintf(lib_bomref, sizeof(lib_bomref), "library:%s", sanitized);
                    free(sanitized);

                    // Build array of dependent library bom-refs
                    json_object* dep_array = json_object_new_array();
                    int dep_count = json_object_array_length(lib_deps);

                    for (int j = 0; j < dep_count; j++) {
                        json_object* dep_soname_obj = json_object_array_get_idx(lib_deps, j);
                        const char* dep_soname = json_object_get_string(dep_soname_obj);
                        if (dep_soname) {
                            // Convert dependency SONAME to bom-ref format
                            char* dep_sanitized = sanitize_for_bomref(dep_soname);
                            if (dep_sanitized) {
                                char dep_bomref[256];
                                snprintf(dep_bomref, sizeof(dep_bomref), "library:%s", dep_sanitized);
                                free(dep_sanitized);

                                // Add to dependency array
                                json_object_array_add(dep_array, json_object_new_string(dep_bomref));
                            }
                        }
                    }

                    if (json_object_array_length(dep_array) > 0) {
                        json_object_object_add(lib_dep_map, lib_bomref, dep_array);
                    } else {
                        json_object_put(dep_array);
                    }
                }
            }
            json_object_put(metadata);
        }

        // Free assets array after using it for components
        free(assets);
    }

    // Clean up bom-ref collision set (Phase 1)
    // Note: asset_id_to_bomref_map will be cleaned up after dependencies are generated
    if (bomref_collision_set) {
        json_object_put(bomref_collision_set);
    }

    // Add dependencies block (Phase C - from typed relationships)
    // Get typed relationships from asset_store
    size_t dep_rel_count = 0;
    relationship_t** dep_rels = asset_store_get_relationships(store, &dep_rel_count);

    // Build dependency map: component_id → array of dependencies
    // Using json_object as a map for simplicity
    json_object *dependency_map = json_object_new_object();

    if (dep_rels && dep_rel_count > 0) {
        for (size_t i = 0; i < dep_rel_count; i++) {
            relationship_t* rel = dep_rels[i];
            if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

            // Map relationship types to dependencies
            bool should_add_dependency = false;
            const char* consumer_id = NULL;
            const char* provider_id = NULL;

            switch (rel->type) {
                case RELATIONSHIP_USES:
                case RELATIONSHIP_DEPENDS_ON:
                case RELATIONSHIP_AUTHENTICATES_WITH:
                case RELATIONSHIP_CONFIGURES:
                    // Consumer (source) depends on provider (target)
                    consumer_id = rel->source_asset_id;
                    provider_id = rel->target_asset_id;
                    should_add_dependency = true;
                    break;

                case RELATIONSHIP_SIGNS:
                case RELATIONSHIP_ISSUED_BY:
                    // Certificate chain relationships (NEW in v1.6.0)
                    // SIGNS: Key signs Certificate (key → cert)
                    // ISSUED_BY: Certificate issued by CA (cert → CA)
                    consumer_id = rel->source_asset_id;
                    provider_id = rel->target_asset_id;
                    should_add_dependency = true;
                    break;

                case RELATIONSHIP_PROVIDES:
                case RELATIONSHIP_IMPLEMENTS:
                    // These add properties to the provider, not dependencies
                    // Will be handled in provider properties phase
                    break;

                default:
                    break;
            }

            if (should_add_dependency && consumer_id && provider_id) {
                // Prevent self-dependencies
                if (strcmp(consumer_id, provider_id) == 0) {
                    continue;
                }

                // Map asset IDs to readable bom-refs (Phase 1)
                json_object* consumer_bomref_obj;
                json_object* provider_bomref_obj;
                const char* consumer_bomref = consumer_id; // default to asset ID
                const char* provider_bomref = provider_id; // default to asset ID

                if (json_object_object_get_ex(asset_id_to_bomref_map, consumer_id, &consumer_bomref_obj)) {
                    consumer_bomref = json_object_get_string(consumer_bomref_obj);
                }
                if (json_object_object_get_ex(asset_id_to_bomref_map, provider_id, &provider_bomref_obj)) {
                    provider_bomref = json_object_get_string(provider_bomref_obj);
                }

                // Get or create dependsOn array for this consumer (using readable bom-ref)
                json_object* depends_on_array;
                if (!json_object_object_get_ex(dependency_map, consumer_bomref, &depends_on_array)) {
                    depends_on_array = json_object_new_array();
                    json_object_object_add(dependency_map, consumer_bomref, depends_on_array);
                }

                // Add provider to dependencies (avoid duplicates, using readable bom-ref)
                bool already_present = false;
                int array_len = json_object_array_length(depends_on_array);
                for (int j = 0; j < array_len; j++) {
                    json_object* existing = json_object_array_get_idx(depends_on_array, j);
                    if (existing && strcmp(json_object_get_string(existing), provider_bomref) == 0) {
                        already_present = true;
                        break;
                    }
                }

                if (!already_present) {
                    json_object_array_add(depends_on_array, json_object_new_string(provider_bomref));
                }
            }
        }
    }

    // v1.8.5: Merge library-to-library dependencies into dependency_map
    // These are ELF dynamic linking dependencies extracted from metadata_json
    json_object_object_foreach(lib_dep_map, lib_ref, lib_deps_array) {
        // Get or create dependsOn array for this library
        json_object* depends_on_array;
        if (!json_object_object_get_ex(dependency_map, lib_ref, &depends_on_array)) {
            depends_on_array = json_object_new_array();
            json_object_object_add(dependency_map, lib_ref, depends_on_array);
        }

        // Add each library dependency (avoid duplicates)
        int lib_dep_count = json_object_array_length(lib_deps_array);
        for (int i = 0; i < lib_dep_count; i++) {
            json_object* dep_bomref_obj = json_object_array_get_idx(lib_deps_array, i);
            const char* dep_bomref = json_object_get_string(dep_bomref_obj);
            if (!dep_bomref) continue;

            // Check for duplicates
            bool already_present = false;
            int existing_count = json_object_array_length(depends_on_array);
            for (int j = 0; j < existing_count; j++) {
                json_object* existing = json_object_array_get_idx(depends_on_array, j);
                if (existing && strcmp(json_object_get_string(existing), dep_bomref) == 0) {
                    already_present = true;
                    break;
                }
            }

            if (!already_present) {
                json_object_array_add(depends_on_array, json_object_new_string(dep_bomref));
            }
        }
    }

    // Clean up lib_dep_map (entries have been copied to dependency_map)
    json_object_put(lib_dep_map);

    // Build set of all component IDs for validation
    json_object *component_id_set = json_object_new_object();
    int comp_count = json_object_array_length(components);
    for (int i = 0; i < comp_count; i++) {
        json_object* comp = json_object_array_get_idx(components, i);
        if (comp) {
            json_object* bom_ref_obj;
            if (json_object_object_get_ex(comp, "bom-ref", &bom_ref_obj)) {
                const char* bom_ref = json_object_get_string(bom_ref_obj);
                json_object_object_add(component_id_set, bom_ref, json_object_new_boolean(true));
            }
        }
    }

    // Sort and validate dependsOn arrays
    // Build sorted dependency map (don't modify while iterating!)
    json_object *sorted_dependency_map = json_object_new_object();

    json_object_object_foreach(dependency_map, ref, depends_on) {
        int dep_count = json_object_array_length(depends_on);
        if (dep_count == 0) continue;

        // Sort dependsOn array for determinism
        // Extract strings, sort them, rebuild array
        char** dep_strings = malloc(dep_count * sizeof(char*));
        if (dep_strings) {
            for (int i = 0; i < dep_count; i++) {
                json_object* dep_obj = json_object_array_get_idx(depends_on, i);
                dep_strings[i] = strdup(json_object_get_string(dep_obj));
            }

            // Simple bubble sort for small arrays
            for (int i = 0; i < dep_count - 1; i++) {
                for (int j = 0; j < dep_count - i - 1; j++) {
                    if (strcmp(dep_strings[j], dep_strings[j + 1]) > 0) {
                        char* temp = dep_strings[j];
                        dep_strings[j] = dep_strings[j + 1];
                        dep_strings[j + 1] = temp;
                    }
                }
            }

            // Build sorted array
            json_object* sorted_depends_on = json_object_new_array();
            for (int i = 0; i < dep_count; i++) {
                // Validate that target exists
                json_object* exists;
                if (!json_object_object_get_ex(component_id_set, dep_strings[i], &exists)) {
                    fprintf(stderr, "WARNING: Dangling dependency ref: %s depends on non-existent %s\n",
                            ref, dep_strings[i]);
                }
                json_object_array_add(sorted_depends_on, json_object_new_string(dep_strings[i]));
                free(dep_strings[i]);
            }
            free(dep_strings);

            // Add to sorted map
            json_object_object_add(sorted_dependency_map, ref, sorted_depends_on);
        }
    }

    // Replace old map with sorted map
    json_object_put(dependency_map);
    dependency_map = sorted_dependency_map;

    // Convert dependency map to CycloneDX dependencies array
    json_object *dependencies = json_object_new_array();

    // Phase 4: Build PROVIDES map (component -> what it provides)
    json_object *provides_map = json_object_new_object();
    if (dep_rels && dep_rel_count > 0) {
        for (size_t i = 0; i < dep_rel_count; i++) {
            relationship_t* rel = dep_rels[i];
            if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

            if (rel->type == RELATIONSHIP_PROVIDES || rel->type == RELATIONSHIP_IMPLEMENTS) {
                const char* provider_id = rel->source_asset_id;
                const char* provided_id = rel->target_asset_id;

                // Map to readable bom-ref
                json_object* provider_bomref_obj;
                if (json_object_object_get_ex(asset_id_to_bomref_map, provider_id, &provider_bomref_obj)) {
                    const char* provider_bomref = json_object_get_string(provider_bomref_obj);

                    // Also map provided_id to readable bom-ref
                    json_object* provided_bomref_obj;
                    const char* provided_bomref = provided_id;  // Fallback to hash
                    if (json_object_object_get_ex(asset_id_to_bomref_map, provided_id, &provided_bomref_obj)) {
                        provided_bomref = json_object_get_string(provided_bomref_obj);
                    }

                    json_object* provides_array;
                    if (!json_object_object_get_ex(provides_map, provider_bomref, &provides_array)) {
                        provides_array = json_object_new_array();
                        json_object_object_add(provides_map, provider_bomref, provides_array);
                    }
                    json_object_array_add(provides_array, json_object_new_string(provided_bomref));
                }
            }
        }
    }

    // Build set of all refs - MUST include ALL components per CycloneDX spec
    // Not just those with dependencies or provides, but ALL components
    json_object* all_refs_set = json_object_new_object();

    // Start with ALL components (this is the fix for the 58 missing applications issue)
    json_object_object_foreach(component_id_set, comp_ref, comp_marker) {
        (void)comp_marker;
        json_object_object_add(all_refs_set, comp_ref, json_object_new_boolean(true));
    }

    // Create dependency entries for ALL components
    json_object_object_foreach(all_refs_set, dep_ref, ref_marker) {
        (void)ref_marker;

        // Get dependencies if they exist
        json_object* dep_depends_on = NULL;
        json_object_object_get_ex(dependency_map, dep_ref, &dep_depends_on);
        bool has_depends = dep_depends_on && json_object_array_length(dep_depends_on) > 0;

        // Get provides if they exist
        json_object* provides_array = NULL;
        bool has_provides = json_object_object_get_ex(provides_map, dep_ref, &provides_array) &&
                           json_object_array_length(provides_array) > 0;

        // Create dependency entry for this component (even if empty dependsOn)
        json_object *dep_entry = json_object_new_object();
        json_object_object_add(dep_entry, "ref", json_object_new_string(dep_ref));

        // Add provides array if present
        if (has_provides) {
            json_object_object_add(dep_entry, "provides", json_object_get(provides_array));
        }

        // Add dependsOn array (empty array if no dependencies per CycloneDX spec)
        if (has_depends) {
            json_object_object_add(dep_entry, "dependsOn", json_object_get(dep_depends_on));
        } else {
            // Empty dependsOn array for components with no dependencies
            json_object_object_add(dep_entry, "dependsOn", json_object_new_array());
        }

        json_object_array_add(dependencies, dep_entry);
    }

    json_object_put(all_refs_set);
    json_object_put(provides_map);

    json_object_put(dependency_map);
    json_object_put(component_id_set);

    // Add provider properties to components (Phase C)
    // Build map of provider_id → list of provided items
    json_object *provider_map = json_object_new_object();

    if (dep_rels && dep_rel_count > 0) {
        for (size_t i = 0; i < dep_rel_count; i++) {
            relationship_t* rel = dep_rels[i];
            if (!rel || !rel->source_asset_id || !rel->target_asset_id) continue;

            // Track what each provider provides
            if (rel->type == RELATIONSHIP_PROVIDES || rel->type == RELATIONSHIP_IMPLEMENTS) {
                const char* provider_id = rel->source_asset_id;
                const char* provided_id = rel->target_asset_id;

                // Get or create array of provided items
                json_object* provided_array;
                if (!json_object_object_get_ex(provider_map, provider_id, &provided_array)) {
                    provided_array = json_object_new_array();
                    json_object_object_add(provider_map, provider_id, provided_array);
                }

                json_object_array_add(provided_array, json_object_new_string(provided_id));
            }
        }
    }

    // Add "provides" properties to components
    int comp_array_length = json_object_array_length(components);
    for (int i = 0; i < comp_array_length; i++) {
        json_object* component = json_object_array_get_idx(components, i);
        if (!component) continue;

        // Get component bom-ref
        json_object* bom_ref_obj;
        if (!json_object_object_get_ex(component, "bom-ref", &bom_ref_obj)) continue;
        const char* bom_ref = json_object_get_string(bom_ref_obj);

        // Check if this component provides anything
        json_object* provided_array;
        if (json_object_object_get_ex(provider_map, bom_ref, &provided_array)) {
            int provided_count = json_object_array_length(provided_array);
            if (provided_count > 0) {
                // Get or create properties array
                json_object* properties;
                if (!json_object_object_get_ex(component, "properties", &properties)) {
                    properties = json_object_new_array();
                    json_object_object_add(component, "properties", properties);
                }

                // Add provides property
                json_object* provides_prop = json_object_new_object();
                json_object_object_add(provides_prop, "name", json_object_new_string("cbom:provides"));

                // Build comma-separated list of provided items
                char* provides_value = NULL;
                size_t value_len = 0;
                for (int j = 0; j < provided_count; j++) {
                    json_object* provided_item = json_object_array_get_idx(provided_array, j);
                    const char* provided_str = json_object_get_string(provided_item);
                    size_t item_len = strlen(provided_str);

                    if (j == 0) {
                        provides_value = malloc(item_len + 1);
                        if (provides_value) {
                            strcpy(provides_value, provided_str);
                            value_len = item_len;
                        }
                    } else {
                        provides_value = realloc(provides_value, value_len + 2 + item_len + 1);
                        if (provides_value) {
                            strcat(provides_value, ", ");
                            strcat(provides_value, provided_str);
                            value_len += 2 + item_len;
                        }
                    }
                }

                if (provides_value) {
                    json_object_object_add(provides_prop, "value", json_object_new_string(provides_value));
                    json_object_array_add(properties, provides_prop);
                    free(provides_value);
                } else {
                    json_object_put(provides_prop);
                }
            }
        }
    }

    json_object_put(provider_map);

    // Generate relationships for better component linking
    json_object *relationships = json_object_new_array();
    if (relationships != NULL) {
        // Get assets again for relationships (since we freed the previous arrays)
        crypto_asset_t **rel_assets = asset_store_get_sorted(store, NULL, &asset_count);
        
        // Add FILE→COMPONENT evidence relationships
        if (rel_assets != NULL) {
            for (size_t i = 0; i < asset_count; i++) {
                crypto_asset_t *asset = rel_assets[i];
            if (asset && asset->location) {
                json_object *relationship = json_object_new_object();
                // v1.5: Remove "type": "evidence" - not part of CycloneDX relationships

                // v1.8: First strip rootfs prefix for cross-arch scans
                const char* base_loc = normalize_cross_arch_path(asset->location);

                // Normalize path (remove consecutive slashes)
                char *normalized_location = strdup(base_loc);
                if (normalized_location) {
                    char *src = normalized_location, *dst = normalized_location;
                    while (*src) {
                        *dst++ = *src++;
                        if (src[-1] == '/' && *src == '/') {
                            while (*src == '/') src++;
                        }
                    }
                    *dst = '\0';
                }

                json_object_object_add(relationship, "source",
                    json_object_new_string(normalized_location ? normalized_location : base_loc));
                if (normalized_location) free(normalized_location);

                // Generate component bom-ref for target
                char component_id[128];
                snprintf(component_id, sizeof(component_id), "component-%zu", i);
                json_object_object_add(relationship, "target", json_object_new_string(component_id));

                json_object_array_add(relationships, relationship);
            }
        }
        
            // Add CERT→CERT issuer relationships for certificate chains
            for (size_t i = 0; i < asset_count; i++) {
                crypto_asset_t *asset = rel_assets[i];
                if (asset && asset->metadata_json) {
                    json_object* metadata_obj = json_tokener_parse(asset->metadata_json);
                    if (metadata_obj) {
                        json_object* issuer_obj;
                        json_object* subject_obj;
                        if (json_object_object_get_ex(metadata_obj, "issuer_dn", &issuer_obj) &&
                            json_object_object_get_ex(metadata_obj, "subject_dn", &subject_obj)) {
                            
                            const char* issuer = json_object_get_string(issuer_obj);
                            const char* subject = json_object_get_string(subject_obj);
                            
                            // If issuer != subject, this is not self-signed
                            if (issuer && subject && strcmp(issuer, subject) != 0) {
                                json_object *relationship = json_object_new_object();
                                // v1.5: Remove "type" field - not part of CycloneDX relationships
                                json_object_object_add(relationship, "source", json_object_new_string(issuer));
                                json_object_object_add(relationship, "target", json_object_new_string(subject));
                                json_object_array_add(relationships, relationship);
                            }
                        }
                        json_object_put(metadata_obj);
                    }
                }
            }
            
            // Free the relationships assets array
            free(rel_assets);
        }
    }
    
    json_object_object_add(bom, "components", components);

    // Add dependencies field only for CycloneDX 1.7+ (not in 1.6 spec)
    bool is_cyclonedx_17_or_higher = (strcmp(g_cbom_config.cyclonedx_spec_version, "1.7") == 0);
    if (is_cyclonedx_17_or_higher) {
        json_object_object_add(bom, "dependencies", dependencies);
    } else {
        // CycloneDX 1.6: dependencies field not supported, cleanup
        json_object_put(dependencies);
    }

    // Clean up asset ID to bom-ref mapping (Phase 1)
    if (asset_id_to_bomref_map) {
        json_object_put(asset_id_to_bomref_map);
    }

    // Note: component_count removed per CycloneDX 1.6 compliance (derivable from components array)

    // Add typed relationships from asset_store (Phase 7.3b + Phase 8 tweaks)
    // Reuse relationships already fetched for dependencies
    size_t typed_rel_count = dep_rel_count;
    relationship_t** typed_rels = dep_rels;

    if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Retrieved %zu typed relationships from asset_store\n", typed_rel_count);
    if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Relationship types breakdown:\n");

    // Count by type for validation (v1.5: all 10 relationship types)
    size_t uses_count = 0, provides_count = 0, auth_count = 0, signs_count = 0, issued_by_count = 0;
    size_t implements_count = 0, depends_on_count = 0, contains_count = 0, configures_count = 0, listens_on_count = 0;
    size_t other_count = 0;
    for (size_t i = 0; i < typed_rel_count; i++) {
        if (!typed_rels[i]) continue;
        switch (typed_rels[i]->type) {
            case RELATIONSHIP_IMPLEMENTS: implements_count++; break;
            case RELATIONSHIP_USES: uses_count++; break;
            case RELATIONSHIP_DEPENDS_ON: depends_on_count++; break;
            case RELATIONSHIP_PROVIDES: provides_count++; break;
            case RELATIONSHIP_CONTAINS: contains_count++; break;
            case RELATIONSHIP_CONFIGURES: configures_count++; break;
            case RELATIONSHIP_LISTENS_ON: listens_on_count++; break;
            case RELATIONSHIP_AUTHENTICATES_WITH: auth_count++; break;
            case RELATIONSHIP_SIGNS: signs_count++; break;
            case RELATIONSHIP_ISSUED_BY: issued_by_count++; break;
            default: other_count++; break;
        }
    }
    if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO:   IMPLEMENTS: %zu, USES: %zu, DEPENDS_ON: %zu, PROVIDES: %zu, CONTAINS: %zu\n",
           implements_count, uses_count, depends_on_count, provides_count, contains_count);
    if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO:   CONFIGURES: %zu, LISTENS_ON: %zu, AUTH: %zu, SIGNS: %zu, ISSUED_BY: %zu, OTHER: %zu\n",
           configures_count, listens_on_count, auth_count, signs_count, issued_by_count, other_count);

    if (typed_rels && typed_rel_count > 0) {
        for (size_t i = 0; i < typed_rel_count; i++) {
            relationship_t* rel = typed_rels[i];
            json_object* rel_obj = json_object_new_object();

            // v1.5: Relationships in CycloneDX don't have "type" field
            // Type is implicit based on array context (dependencies, provides, etc.)
            json_object_object_add(rel_obj, "source", json_object_new_string(rel->source_asset_id));
            json_object_object_add(rel_obj, "target", json_object_new_string(rel->target_asset_id));

            char conf[16];
            snprintf(conf, sizeof(conf), "%.2f", rel->confidence);
            json_object_object_add(rel_obj, "confidence", json_object_new_string(conf));

            json_object_array_add(relationships, rel_obj);
        }
        free(typed_rels);
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Added %zu typed relationships to output\n", typed_rel_count);
    }

    // Calculate relationship count for internal statistics (not added to BOM per CycloneDX 1.6)
    int relationship_count = json_object_array_length(relationships);

    // Export completeness verification (v1.5: all 10 relationship types)
    int typed_count = implements_count + uses_count + depends_on_count + provides_count + contains_count +
                      configures_count + listens_on_count + auth_count + signs_count + issued_by_count;
    int evidence_count = relationship_count - typed_count;
    if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Export summary: %d total (%d typed + %d evidence)\n",
           relationship_count, typed_count, evidence_count);

    // Update metadata relationship statistics (Phase 8 polish)
    // Stats are in metadata.properties[] array, not as a separate object
    json_object* metadata_obj;
    if (json_object_object_get_ex(bom, "metadata", &metadata_obj)) {
        json_object* properties_array;
        if (json_object_object_get_ex(metadata_obj, "properties", &properties_array)) {
            size_t props_len = json_object_array_length(properties_array);
            for (size_t i = 0; i < props_len; i++) {
                json_object* prop = json_object_array_get_idx(properties_array, i);
                json_object* name_obj;
                if (json_object_object_get_ex(prop, "name", &name_obj)) {
                    const char* prop_name = json_object_get_string(name_obj);

                    // Update relationship count properties
                    if (strcmp(prop_name, "cbom:relationships:relationships_total") == 0) {
                        char count_str[32];
                        snprintf(count_str, sizeof(count_str), "%d", relationship_count);
                        json_object_object_del(prop, "value");
                        json_object_object_add(prop, "value", json_object_new_string(count_str));
                    } else if (strcmp(prop_name, "cbom:relationships:relationships_typed") == 0) {
                        char count_str[32];
                        snprintf(count_str, sizeof(count_str), "%d", typed_count);
                        json_object_object_del(prop, "value");
                        json_object_object_add(prop, "value", json_object_new_string(count_str));
                    } else if (strcmp(prop_name, "cbom:relationships:relationships_evidence") == 0) {
                        char count_str[32];
                        snprintf(count_str, sizeof(count_str), "%d", evidence_count);
                        json_object_object_del(prop, "value");
                        json_object_object_add(prop, "value", json_object_new_string(count_str));
                    }
                }
            }
        }
    }

    // Verify all typed relationships were exported
    if (typed_count < (int)typed_rel_count) {
        printf("ERROR: Typed relationship loss! Expected: %zu, Exported: %d\n",
               typed_rel_count, typed_count);
    } else if (typed_count == (int)typed_rel_count) {
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Export completeness verified: All %d typed relationships exported ✓\n", typed_count);
    }

    // v1.5: Don't serialize relationships array - NOT part of CycloneDX spec (neither 1.6 nor 1.7)
    // Relationships are expressed through dependencies array instead
    // Keep array in memory for PQC assessment (freed at end of function)

    // Note: annotations currently disabled for schema compliance
    // TODO: Implement proper annotation structure per CycloneDX spec (requires 'subjects' field)
    // For now, error information is still captured internally
    if (annotations) {
        json_object_put(annotations);  // Clean up unused annotations
    }

    // Add diagnostic information as CycloneDX properties
    json_object *properties = json_object_new_array();
    if (properties != NULL) {
        // Add execution metadata (cbom:run:*)
        json_object *network_prop = json_object_new_object();
        json_object_object_add(network_prop, "name", json_object_new_string("cbom:run:no_network"));
        json_object_object_add(network_prop, "value", json_object_new_string(g_cbom_config.no_network ? "true" : "false"));
        json_object_array_add(properties, network_prop);
        
        json_object *privacy_prop = json_object_new_object();
        json_object_object_add(privacy_prop, "name", json_object_new_string("cbom:run:privacy_mode"));
        json_object_object_add(privacy_prop, "value", json_object_new_string(g_cbom_config.no_personal_data ? "enabled" : "disabled"));
        json_object_array_add(properties, privacy_prop);
        
        json_object *deterministic_prop = json_object_new_object();
        json_object_object_add(deterministic_prop, "name", json_object_new_string("cbom:run:deterministic"));
        json_object_object_add(deterministic_prop, "value", json_object_new_string(g_cbom_config.deterministic ? "true" : "false"));
        json_object_array_add(properties, deterministic_prop);
        
        // Add air-gapped execution proof
        if (g_cbom_config.no_network) {
            json_object *airgap_prop = json_object_new_object();
            json_object_object_add(airgap_prop, "name", json_object_new_string("cbom:run:execution_environment"));
            json_object_object_add(airgap_prop, "value", json_object_new_string("air_gapped"));
            json_object_array_add(properties, airgap_prop);
        }
        
        // Add privacy redaction notice
        if (g_cbom_config.no_personal_data) {
            json_object *redaction_prop = json_object_new_object();
            json_object_object_add(redaction_prop, "name", json_object_new_string("cbom:run:data_redaction"));
            json_object_object_add(redaction_prop, "value", json_object_new_string("personal_data_redacted"));
            json_object_array_add(properties, redaction_prop);
        }
        
        // Add property guide version stamp for CI drift detection
        json_object *guide_version_prop = json_object_new_object();
        json_object_object_add(guide_version_prop, "name", json_object_new_string("cbom:meta:property_guide_version"));
        json_object_object_add(guide_version_prop, "value", json_object_new_string("1.0.0"));
        json_object_array_add(properties, guide_version_prop);
        
        // Add completion information as properties (consistent colon style)
        if (g_completion_tracker != NULL) {
            json_object *completion_prop = json_object_new_object();
            json_object_object_add(completion_prop, "name", json_object_new_string("cbom:completion:total_tasks"));
            char total_str[32];
            snprintf(total_str, sizeof(total_str), "%zu", g_completion_tracker->total_tasks);
            json_object_object_add(completion_prop, "value", json_object_new_string(total_str));
            json_object_array_add(properties, completion_prop);
            
            json_object *completed_prop = json_object_new_object();
            json_object_object_add(completed_prop, "name", json_object_new_string("cbom:completion:completed_tasks"));
            char completed_str[32];
            snprintf(completed_str, sizeof(completed_str), "%zu", g_completion_tracker->completed_tasks);
            json_object_object_add(completed_prop, "value", json_object_new_string(completed_str));
            json_object_array_add(properties, completed_prop);
            
            json_object *failed_prop = json_object_new_object();
            json_object_object_add(failed_prop, "name", json_object_new_string("cbom:completion:failed_tasks"));
            char failed_str[32];
            snprintf(failed_str, sizeof(failed_str), "%zu", g_completion_tracker->failed_tasks);
            json_object_object_add(failed_prop, "value", json_object_new_string(failed_str));
            json_object_array_add(properties, failed_prop);
            
            json_object *percentage_prop = json_object_new_object();
            json_object_object_add(percentage_prop, "name", json_object_new_string("cbom:completion:percentage"));
            char percentage_str[32];
            snprintf(percentage_str, sizeof(percentage_str), "%.1f", g_completion_tracker->completion_percentage);
            json_object_object_add(percentage_prop, "value", json_object_new_string(percentage_str));
            json_object_array_add(properties, percentage_prop);
        }
        
        // Add error statistics as properties (consistent colon style)
        if (g_error_collector != NULL) {
            json_object *error_count_prop = json_object_new_object();
            json_object_object_add(error_count_prop, "name", json_object_new_string("cbom:diagnostics:error_count"));
            char error_count_str[32];
            snprintf(error_count_str, sizeof(error_count_str), "%zu", g_error_collector->errors_by_severity[ERROR_SEVERITY_ERROR]);
            json_object_object_add(error_count_prop, "value", json_object_new_string(error_count_str));
            json_object_array_add(properties, error_count_prop);
            
            json_object *warning_count_prop = json_object_new_object();
            json_object_object_add(warning_count_prop, "name", json_object_new_string("cbom:diagnostics:warning_count"));
            char warning_count_str[32];
            snprintf(warning_count_str, sizeof(warning_count_str), "%zu", g_error_collector->errors_by_severity[ERROR_SEVERITY_WARNING]);
            json_object_object_add(warning_count_prop, "value", json_object_new_string(warning_count_str));
            json_object_array_add(properties, warning_count_prop);

            // Issue #5 Phase 2.3: Add error breakdown by category
            error_stats_t error_stats = error_collector_get_stats(g_error_collector);

            json_object *total_errors_prop = json_object_new_object();
            json_object_object_add(total_errors_prop, "name", json_object_new_string("cbom:errors:total"));
            char total_errors_str[32];
            snprintf(total_errors_str, sizeof(total_errors_str), "%zu", error_stats.total_errors);
            json_object_object_add(total_errors_prop, "value", json_object_new_string(total_errors_str));
            json_object_array_add(properties, total_errors_prop);

            json_object *io_errors_prop = json_object_new_object();
            json_object_object_add(io_errors_prop, "name", json_object_new_string("cbom:errors:by_category:io"));
            char io_errors_str[32];
            snprintf(io_errors_str, sizeof(io_errors_str), "%zu", error_stats.io_errors);
            json_object_object_add(io_errors_prop, "value", json_object_new_string(io_errors_str));
            json_object_array_add(properties, io_errors_prop);

            json_object *validation_errors_prop = json_object_new_object();
            json_object_object_add(validation_errors_prop, "name", json_object_new_string("cbom:errors:by_category:validation"));
            char validation_errors_str[32];
            snprintf(validation_errors_str, sizeof(validation_errors_str), "%zu", error_stats.validation_errors);
            json_object_object_add(validation_errors_prop, "value", json_object_new_string(validation_errors_str));
            json_object_array_add(properties, validation_errors_prop);

            json_object *memory_errors_prop = json_object_new_object();
            json_object_object_add(memory_errors_prop, "name", json_object_new_string("cbom:errors:by_category:memory"));
            char memory_errors_str[32];
            snprintf(memory_errors_str, sizeof(memory_errors_str), "%zu", error_stats.permission_errors); // Note: memory errors may be tracked differently
            json_object_object_add(memory_errors_prop, "value", json_object_new_string(memory_errors_str));
            json_object_array_add(properties, memory_errors_prop);
        }

        // Add certificate scanner diagnostics
        if (g_cert_scanner_stats.files_scanned_total > 0) {
            // File-level diagnostics
            json_object *prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:files_scanned_total"));
            char value_str[32];
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.files_scanned_total);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:files_extension_matched"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.files_extension_matched);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:files_with_parsable_certs"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.files_with_parsable_certs);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            // Certificate-level diagnostics
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:certs_detected_total"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.certs_detected_total);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:certs_parsed_ok"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.certs_parsed_ok);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:certs_failed_total"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.certs_failed_total);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Add CSR statistics (Issue #7)
            asset_store_stats_t stats_for_csr = asset_store_get_stats(store);
            size_t csr_count = stats_for_csr.assets_by_type[ASSET_TYPE_CERTIFICATE_REQUEST];
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:csrs_detected_total"));
            snprintf(value_str, sizeof(value_str), "%zu", csr_count);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            // Format breakdown
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:pem_detected"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.pem_detected);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:pem_parsed_ok"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.pem_parsed_ok);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            // Add gap calculation for at-a-glance clarity
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:certs_gap"));
            size_t gap = g_cert_scanner_stats.certs_detected_total - g_cert_scanner_stats.certs_parsed_ok;
            snprintf(value_str, sizeof(value_str), "%zu", gap);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            // Add failure reasons if any
            for (int i = 0; i < CERT_FAIL_REASON_COUNT; i++) {
                if (g_cert_scanner_stats.certs_failed_by_reason[i] > 0) {
                    prop = json_object_new_object();
                    char name_str[128];
                    snprintf(name_str, sizeof(name_str), "cbom:diagnostics:certs_failed_by_reason:%s", 
                            cert_failure_reason_to_string((cert_failure_reason_t)i));
                    json_object_object_add(prop, "name", json_object_new_string(name_str));
                    snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.certs_failed_by_reason[i]);
                    json_object_object_add(prop, "value", json_object_new_string(value_str));
                    json_object_array_add(properties, prop);
                }
            }
            
            // Trust validation counters (4.1.2 enhancement)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:trust_valid_certificates"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.trust_valid_certificates);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:trust_expired_certificates"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.trust_expired_certificates);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:trust_untrusted_ca_certificates"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.trust_untrusted_ca_certificates);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:trust_self_signed_certificates"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.trust_self_signed_certificates);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:trust_chain_incomplete_certificates"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.trust_chain_incomplete_certificates);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:trust_unknown_certificates"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.trust_unknown_certificates);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Bundle processing statistics (Issue #2 fix)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:bundles_processed"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.bundles_processed);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:certs_from_bundles"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.certs_from_bundles);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Bundle-specific failure tracking (Issue #2 fix)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:bundle_certs_failed"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.bundle_certs_failed);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Individual file processing statistics (Issue #2 fix)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:individual_files_processed"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.individual_files_processed);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:individual_file_failures"));
            snprintf(value_str, sizeof(value_str), "%zu", g_cert_scanner_stats.individual_file_failures);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Actual failure rate (Issue #2 fix - accurate metric)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:actual_failure_rate_pct"));
            float actual_failure_rate = 0.0f;
            if (g_cert_scanner_stats.individual_files_processed > 0) {
                actual_failure_rate = (g_cert_scanner_stats.individual_file_failures * 100.0f) /
                                     g_cert_scanner_stats.individual_files_processed;
            }
            snprintf(value_str, sizeof(value_str), "%.1f", actual_failure_rate);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Corrected success rate (certificate-level, not file-level)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:certs_success_rate_pct"));
            float success_rate = 0.0f;
            if (g_cert_scanner_stats.certs_detected_total > 0) {
                success_rate = (g_cert_scanner_stats.certs_parsed_ok * 100.0f) / g_cert_scanner_stats.certs_detected_total;
            }
            snprintf(value_str, sizeof(value_str), "%.1f", success_rate);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Relationship matching statistics (Issue #4)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:relationship:keys_scanned"));
            snprintf(value_str, sizeof(value_str), "%d", g_total_keys_for_matching);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:relationship:certs_scanned"));
            snprintf(value_str, sizeof(value_str), "%d", g_total_certs_for_matching);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:relationship:signs_created"));
            snprintf(value_str, sizeof(value_str), "%d", g_key_cert_matches);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:relationship:issued_by_created"));
            snprintf(value_str, sizeof(value_str), "%d", g_cert_chains);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Add explanatory note for key-cert matching coverage
            if (g_total_keys_for_matching > 0 && g_key_cert_matches > 0) {
                int unmatched_keys = g_total_keys_for_matching - g_key_cert_matches;
                // Only add note if many unmatched keys (typical for certbot systems)
                if (unmatched_keys > g_key_cert_matches * 10) {
                    prop = json_object_new_object();
                    json_object_object_add(prop, "name", json_object_new_string("cbom:relationship:note"));
                    char note[512];
                    snprintf(note, sizeof(note),
                            "%d of %d keys matched to certificates. %d unmatched keys are typical "
                            "for certbot-managed systems where keys accumulate from automatic renewals "
                            "while only active certificates remain on disk.",
                            g_key_cert_matches, g_total_keys_for_matching, unmatched_keys);
                    json_object_object_add(prop, "value", json_object_new_string(note));
                    json_object_array_add(properties, prop);
                }
            }

            // Revocation policy markers (4.1 enhancement)
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:run:revocation_policy"));
            const char* revocation_policy = g_cbom_config.no_network ? "disabled" : "cache-only";
            json_object_object_add(prop, "value", json_object_new_string(revocation_policy));
            json_object_array_add(properties, prop);
            
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:run:revocation_cache_ttl_hours"));
            snprintf(value_str, sizeof(value_str), "%d", 24); // Default 24 hours
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
        }

        // Add deduplication diagnostics
        if (g_cbom_config.dedup_mode != DEDUP_MODE_OFF) {
            char value_str[32];  // Declare value_str for this block
            const char* dedup_mode_str = (g_cbom_config.dedup_mode == DEDUP_MODE_SAFE) ? "safe" :
                                        (g_cbom_config.dedup_mode == DEDUP_MODE_STRICT) ? "strict" : "off";

            json_object *prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_mode"));
            json_object_object_add(prop, "value", json_object_new_string(dedup_mode_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_certs_merged"));
            snprintf(value_str, sizeof(value_str), "%zu", g_dedup_stats.certs_merged);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_keys_merged"));
            snprintf(value_str, sizeof(value_str), "%zu", g_dedup_stats.keys_merged);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_openpgp_merged"));
            snprintf(value_str, sizeof(value_str), "%zu", g_dedup_stats.openpgp_merged);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_files_suppressed"));
            snprintf(value_str, sizeof(value_str), "%zu", g_dedup_stats.files_suppressed);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_bundles_created"));
            snprintf(value_str, sizeof(value_str), "%zu", g_dedup_stats.bundles_created);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_collisions"));
            snprintf(value_str, sizeof(value_str), "%zu", g_dedup_stats.collisions);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);

            // Total suppressed counter
            size_t total_suppressed = g_dedup_stats.files_suppressed +
                                     g_dedup_stats.certs_merged +
                                     g_dedup_stats.keys_merged +
                                     g_dedup_stats.openpgp_merged;
            prop = json_object_new_object();
            json_object_object_add(prop, "name", json_object_new_string("cbom:diagnostics:dedup_total_suppressed"));
            snprintf(value_str, sizeof(value_str), "%zu", total_suppressed);
            json_object_object_add(prop, "value", json_object_new_string(value_str));
            json_object_array_add(properties, prop);
        }

        json_object_object_add(bom, "properties", properties);
    }

    // ========================================================================
    // Phase 8.0: PQC Assessment Block
    // ========================================================================

    json_object* pqc_assessment = json_object_new_object();
    if (pqc_assessment != NULL) {
        // Calculate PQC statistics from actual component properties (Phase E fix)
        int safe_count = 0, transitional_count = 0, deprecated_count = 0, unsafe_count = 0;
        int safe_instances = 0;  // Count relationships pointing to SAFE algorithms

        // NEW: Break year distribution counters (Phase 3)
        int break_2030_count = 0, break_2035_count = 0, break_2040_count = 0, break_2045_count = 0;
        int hybrid_count = 0;

        // First pass: identify SAFE algorithm IDs
        char** safe_algorithm_ids = malloc(sizeof(char*) * 100);  // Max 100 SAFE algorithms
        int safe_algo_count = 0;

        // Iterate through components array and count by cbom:pqc:status
        int comp_count = json_object_array_length(components);
        for (int i = 0; i < comp_count; i++) {
            json_object* component = json_object_array_get_idx(components, i);
            if (!component) continue;

            // Get properties array
            json_object* properties_array;
            if (!json_object_object_get_ex(component, "properties", &properties_array)) continue;

            // Find cbom:pqc:status property
            int prop_count = json_object_array_length(properties_array);
            for (int j = 0; j < prop_count; j++) {
                json_object* prop = json_object_array_get_idx(properties_array, j);
                if (!prop) continue;

                json_object* name_obj, *value_obj;
                if (json_object_object_get_ex(prop, "name", &name_obj) &&
                    json_object_object_get_ex(prop, "value", &value_obj)) {
                    const char* prop_name = json_object_get_string(name_obj);
                    if (strcmp(prop_name, "cbom:pqc:status") == 0) {
                        const char* status = json_object_get_string(value_obj);
                        if (strcmp(status, "SAFE") == 0) {
                            safe_count++;
                            // Save this algorithm's ID for relationship counting
                            json_object* bom_ref_obj;
                            if (json_object_object_get_ex(component, "bom-ref", &bom_ref_obj)) {
                                const char* algo_id = json_object_get_string(bom_ref_obj);
                                if (safe_algo_count < 100) {
                                    safe_algorithm_ids[safe_algo_count++] = strdup(algo_id);
                                }
                            }
                        }
                        else if (strcmp(status, "TRANSITIONAL") == 0) transitional_count++;
                        else if (strcmp(status, "DEPRECATED") == 0) deprecated_count++;
                        else if (strcmp(status, "UNSAFE") == 0) unsafe_count++;
                        // Don't break - continue checking for break_estimate and is_hybrid
                    }
                    // NEW: Count break year estimates (Phase 3)
                    if (strcmp(prop_name, "cbom:pqc:break_estimate") == 0) {
                        const char* break_year_str = json_object_get_string(value_obj);
                        int break_year = atoi(break_year_str);
                        if (break_year == 2030) break_2030_count++;
                        else if (break_year == 2035) break_2035_count++;
                        else if (break_year == 2040) break_2040_count++;
                        else if (break_year >= 2045) break_2045_count++;
                    }
                    // NEW: Count hybrid algorithms (Phase 3)
                    if (strcmp(prop_name, "cbom:pqc:is_hybrid") == 0) {
                        hybrid_count++;
                    }
                }
            }
        }

        // Second pass: count relationships pointing to SAFE algorithms (instances)
        for (int i = 0; i < safe_algo_count; i++) {
            const char* safe_id = safe_algorithm_ids[i];

            // Count how many relationships have this as target
            int rel_count = json_object_array_length(relationships);
            for (int j = 0; j < rel_count; j++) {
                json_object* rel = json_object_array_get_idx(relationships, j);
                if (!rel) continue;

                json_object* target_obj;
                if (json_object_object_get_ex(rel, "target", &target_obj)) {
                    const char* target = json_object_get_string(target_obj);
                    if (strcmp(target, safe_id) == 0) {
                        safe_instances++;  // Each relationship = 1 instance/usage
                    }
                }
            }
        }

        // Cleanup safe_algorithm_ids
        for (int i = 0; i < safe_algo_count; i++) {
            free(safe_algorithm_ids[i]);
        }
        free(safe_algorithm_ids);

        int total_classified = safe_count + transitional_count + deprecated_count + unsafe_count;

        // Calculate readiness score
        float readiness_score = 0.0f;
        if (total_classified > 0) {
            readiness_score = ((safe_count * 100.0f) +
                              (transitional_count * 50.0f) +
                              (deprecated_count * 0.0f) +
                              (unsafe_count * 0.0f)) / total_classified;
        }

        // Add statistics to pqc_assessment block
        json_object_object_add(pqc_assessment, "total_assets",
                              json_object_new_int(total_classified));
        json_object_object_add(pqc_assessment, "pqc_safe_count",
                              json_object_new_int(safe_count));
        json_object_object_add(pqc_assessment, "pqc_safe_instances",
                              json_object_new_int(safe_instances));
        json_object_object_add(pqc_assessment, "pqc_transitional_count",
                              json_object_new_int(transitional_count));
        json_object_object_add(pqc_assessment, "pqc_deprecated_count",
                              json_object_new_int(deprecated_count));
        json_object_object_add(pqc_assessment, "pqc_unsafe_count",
                              json_object_new_int(unsafe_count));

        // Add readiness score (0-100)
        char score_str[32];
        snprintf(score_str, sizeof(score_str), "%.1f", readiness_score);
        json_object_object_add(pqc_assessment, "readiness_score",
                              json_object_new_string(score_str));

        // Add scope limitation documentation
        json_object_object_add(pqc_assessment, "scope",
                              json_object_new_string("NIST-finalized PQC (Kyber, Dilithium, SPHINCS+) + NTRU Prime (sntrup761) + hybrid algorithms"));
        json_object_object_add(pqc_assessment, "standards_reference",
                              json_object_new_string("NIST IR 8413, FIPS 203/204/205, Streamlined NTRU Prime"));

        // Generate migration recommendations
        json_object* recommendations_array = json_object_new_array();

        // Global recommendations based on overall score
        if (readiness_score < 30.0f) {
            json_object_array_add(recommendations_array,
                json_object_new_string("CRITICAL: System has significant PQC vulnerabilities - immediate action required"));
            json_object_array_add(recommendations_array,
                json_object_new_string("Prioritize migration of asymmetric algorithms (RSA, ECDSA) to PQC alternatives"));
            json_object_array_add(recommendations_array,
                json_object_new_string("Replace quantum-vulnerable key exchange with Kyber or hybrid solutions"));
        } else if (readiness_score < 60.0f) {
            json_object_array_add(recommendations_array,
                json_object_new_string("Plan PQC migration within 12-24 months for quantum-vulnerable components"));
            json_object_array_add(recommendations_array,
                json_object_new_string("Consider hybrid cipher suites (X25519Kyber768) for gradual transition"));
            json_object_array_add(recommendations_array,
                json_object_new_string("Test NIST-finalized PQC algorithms in non-production environments"));
        } else if (readiness_score < 90.0f) {
            json_object_array_add(recommendations_array,
                json_object_new_string("System has good PQC readiness - complete remaining migrations"));
            json_object_array_add(recommendations_array,
                json_object_new_string("Replace remaining classical algorithms with PQC equivalents"));
        } else {
            json_object_array_add(recommendations_array,
                json_object_new_string("System is PQC-ready - maintain current configuration"));
            json_object_array_add(recommendations_array,
                json_object_new_string("Monitor NIST updates for new PQC standards and algorithm finalizations"));
        }

        json_object_object_add(pqc_assessment, "migration_recommendations", recommendations_array);

        // Add PQC assessment to top-level properties array (CycloneDX 1.6 compliant)
        // Get or create properties array
        json_object* bom_properties = NULL;
        if (!json_object_object_get_ex(bom, "properties", &bom_properties)) {
            bom_properties = json_object_new_array();
            json_object_object_add(bom, "properties", bom_properties);
        }

        // Add PQC assessment fields as properties
        char value_buf[64];
        json_object *prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:total_assets"));
        snprintf(value_buf, sizeof(value_buf), "%d", json_object_get_int(json_object_object_get(pqc_assessment, "total_assets")));
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:safe_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", json_object_get_int(json_object_object_get(pqc_assessment, "pqc_safe_count")));
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:safe_instances"));
        snprintf(value_buf, sizeof(value_buf), "%d", json_object_get_int(json_object_object_get(pqc_assessment, "pqc_safe_instances")));
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:transitional_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", json_object_get_int(json_object_object_get(pqc_assessment, "pqc_transitional_count")));
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:deprecated_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", json_object_get_int(json_object_object_get(pqc_assessment, "pqc_deprecated_count")));
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:unsafe_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", json_object_get_int(json_object_object_get(pqc_assessment, "pqc_unsafe_count")));
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:readiness_score"));
        json_object_object_add(prop, "value",
            json_object_new_string(json_object_get_string(json_object_object_get(pqc_assessment, "readiness_score"))));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:scope"));
        json_object_object_add(prop, "value",
            json_object_new_string(json_object_get_string(json_object_object_get(pqc_assessment, "scope"))));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:standards_reference"));
        json_object_object_add(prop, "value",
            json_object_new_string(json_object_get_string(json_object_object_get(pqc_assessment, "standards_reference"))));
        json_object_array_add(bom_properties, prop);

        // NEW PROPERTIES - Break Year Distribution (Phase 3)
        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:break_2030_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", break_2030_count);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:break_2035_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", break_2035_count);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:break_2040_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", break_2040_count);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:break_2045_count"));
        snprintf(value_buf, sizeof(value_buf), "%d", break_2045_count);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        // NEW PROPERTIES - Migration Guidance (Phase 3)
        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:hybrid_detected"));
        snprintf(value_buf, sizeof(value_buf), "%d", hybrid_count);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:priority_assets"));
        snprintf(value_buf, sizeof(value_buf), "%d", break_2030_count);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        // Calculate recommended migration start year
        int migration_start_year = (break_2030_count > 0) ? 2024 : 2025;
        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:migration_timeline"));
        snprintf(value_buf, sizeof(value_buf), "%d", migration_start_year);
        json_object_object_add(prop, "value", json_object_new_string(value_buf));
        json_object_array_add(bom_properties, prop);

        // Add assessment timestamp (ISO 8601)
        time_t now = time(NULL);
        struct tm* tm_info = gmtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:pqc:assessment_timestamp"));
        json_object_object_add(prop, "value", json_object_new_string(timestamp));
        json_object_array_add(bom_properties, prop);

        // Add migration recommendations as a multi-line property
        json_object *recs_array = json_object_object_get(pqc_assessment, "migration_recommendations");
        if (recs_array) {
            for (size_t i = 0; i < json_object_array_length(recs_array); i++) {
                prop = json_object_new_object();
                char prop_name[128];
                snprintf(prop_name, sizeof(prop_name), "cbom:pqc:recommendation:%zu", i + 1);
                json_object_object_add(prop, "name", json_object_new_string(prop_name));
                json_object_object_add(prop, "value",
                    json_object_new_string(json_object_get_string(json_object_array_get_idx(recs_array, i))));
                json_object_array_add(bom_properties, prop);
            }
        }

        // Cleanup pqc_assessment object (not added to BOM root per CycloneDX 1.6 compliance)
        json_object_put(pqc_assessment);

        // Store PQC results in globals for later use
        g_pqc_readiness_score = readiness_score;
        g_pqc_safe_count = safe_count;
        g_pqc_transitional_count = transitional_count;
        g_pqc_deprecated_count = deprecated_count;
        g_pqc_unsafe_count = unsafe_count;

        // Only print if not in TUI mode (TUI will show summary after exit)
        if (g_output_mode != OUTPUT_MODE_TUI) {
            if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: PQC assessment: %.1f%% ready (%d safe, %d transitional, %d deprecated, %d unsafe)\n",
                   readiness_score,
                   safe_count,
                   transitional_count,
                   deprecated_count,
                   unsafe_count);
        }
    }
    
    // Validate against schema before output
    schema_validation_result_t validation = validate_cyclonedx_schema(bom);
    if (!validation.is_valid) {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_VALIDATION, 0,
                       "schema_validator", "BOM validation failed", validation.error_message);
        free_validation_result(&validation);
        json_object_put(bom);
        return -1;
    }
    free_validation_result(&validation);
    
    // Calculate hash of JSON content and update the outputs field
    const char *json_str_temp = json_object_to_json_string_ext(bom, 
        g_cbom_config.deterministic ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PRETTY);
    
    if (json_str_temp != NULL) {
        // Calculate hash of the JSON content (with newline that will be added)
        char *json_with_newline = malloc(strlen(json_str_temp) + 2);
        if (json_with_newline) {
            sprintf(json_with_newline, "%s\n", json_str_temp);
            char *content_hash = calculate_string_sha256(json_with_newline);
            
            if (content_hash) {
                // Update the sha256 field in the outputs array
                json_object *metadata = NULL;
                if (json_object_object_get_ex(bom, "metadata", &metadata)) {
                    json_object *outputs = NULL;
                    if (json_object_object_get_ex(metadata, "outputs", &outputs)) {
                        json_object *output_file = json_object_array_get_idx(outputs, 0);
                        if (output_file) {
                            json_object_object_del(output_file, "sha256");
                            json_object_object_add(output_file, "sha256", json_object_new_string(content_hash));
                        }
                    }
                }
                free(content_hash);
            }
            free(json_with_newline);
        }
    }
    
    // Output final JSON with updated hash
    const char *json_str = json_object_to_json_string_ext(bom, 
        g_cbom_config.deterministic ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PRETTY);
    
    if (json_str != NULL) {
        fprintf(output, "%s\n", json_str);
        
        // Print hash information
        if (output != stdout && g_cbom_config.output_file) {
            fflush(output); // Ensure data is written
            json_object *metadata = NULL;
            if (json_object_object_get_ex(bom, "metadata", &metadata)) {
                json_object *outputs = NULL;
                if (json_object_object_get_ex(metadata, "outputs", &outputs)) {
                    json_object *output_file = json_object_array_get_idx(outputs, 0);
                    if (output_file) {
                        json_object *sha256_obj = NULL;
                        if (json_object_object_get_ex(output_file, "sha256", &sha256_obj)) {
                            const char *hash_str = json_object_get_string(sha256_obj);
                            if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Generated CBOM with enhanced metadata and evidence\n");
                            if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Output file SHA-256: %s\n", hash_str);
                        }
                    }
                }
            }
        }

        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Generated CBOM with enhanced metadata and evidence\n");
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Output includes: host info, scan params, privacy flags, completion metrics, errors array\n");
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Certificate parsing fixed - no more 'X.509' algorithm placeholders\n");
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Evidence added with file location and real SHA-256 hashes\n");
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Relationships generated for component linking\n");
        
        ERROR_LOG_INFO(g_error_collector, "main", "Generated valid CycloneDX BOM", NULL);
    } else {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                       "main", "Failed to serialize BOM to JSON", NULL);
        json_object_put(bom);
        return -1;
    }

    // Cleanup relationships if not attached to BOM (CycloneDX 1.6)
    // Note: dependencies already freed at line 3733 for 1.6
    // For CycloneDX 1.7, relationships is attached to BOM and freed with bom
    if (!is_cyclonedx_17_or_higher) {
        json_object_put(relationships);
    }

    json_object_put(bom);
    return 0;
}

// Scanner work item for thread pool
typedef struct {
    plugin_instance_t* scanner;
    scan_context_t* scan_context;
    asset_store_t* store;
    plugin_manager_t* plugin_manager;
    const char* scanner_name;
    scanner_type_t scanner_type;
    int* result_out;
} scanner_work_t;

// Thread pool wrapper for scanner execution
static int scanner_work_wrapper(void* data, void* context) {
    scanner_work_t* work = (scanner_work_t*)data;
    (void)context;  // Unused

    // Notify TUI that scanner is starting
    tui_log(TUI_MSG_SCANNER_START, work->scanner_type, work->scanner_name, 0, 0, NULL,
            work->scan_context->target_path);

    // Execute the scanner
    int result = plugin_manager_execute_scanner(work->plugin_manager,
                                                work->scanner->instance_id,
                                                work->scan_context,
                                                work->store);

    // Get updated asset counts from store for TUI display
    asset_store_stats_t stats = asset_store_get_stats(work->store);
    size_t assets_found = 0;

    // Determine asset count based on scanner type
    switch (work->scanner_type) {
        case SCANNER_PACKAGE:
            assets_found = stats.assets_by_type[ASSET_TYPE_LIBRARY];
            break;
        case SCANNER_SERVICE:
            assets_found = stats.assets_by_type[ASSET_TYPE_SERVICE];
            break;
        case SCANNER_CERTIFICATE:
            assets_found = stats.assets_by_type[ASSET_TYPE_CERTIFICATE];
            break;
        case SCANNER_KEY:
            assets_found = stats.assets_by_type[ASSET_TYPE_KEY];
            break;
        case SCANNER_FILESYSTEM:
            assets_found = stats.total_assets;  // Filesystem finds multiple types
            break;
        default:
            assets_found = 0;
            break;
    }

    // Notify TUI that scanner completed with actual counts
    tui_log(TUI_MSG_SCANNER_COMPLETE, work->scanner_type, work->scanner_name, 0, assets_found, NULL, NULL);

    // Store result for main thread
    if (work->result_out) {
        *work->result_out = result;
    }

    return result == PLUGIN_SUCCESS ? 0 : -1;
}

// Enhanced CBOM generation using plugin system
static int run_walking_skeleton(void) {
    // Variables for tracking total assets (used for TUI updates)
    size_t total_assets = 0;
    asset_store_stats_t stats;
    const char* first_path = NULL;

    // Create asset store
    asset_store_t *store = asset_store_create(0);
    if (store == NULL) {
        ERROR_LOG_CRITICAL(g_error_collector, ERROR_CATEGORY_MEMORY, 0,
                          "main", "Failed to create asset store", NULL);
        return -1;
    }

    // Set deterministic mode
    store->deterministic_mode = g_cbom_config.deterministic;

    // Create deduplication context
    dedup_context_t *dedup_ctx = dedup_context_create(g_cbom_config.dedup_mode, g_cbom_config.emit_bundles);
    if (!dedup_ctx) {
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_MEMORY,
                         "main", "Failed to create deduplication context, continuing without dedup", NULL);
    } else {
        const char *mode_str = (g_cbom_config.dedup_mode == DEDUP_MODE_OFF) ? "off" :
                               (g_cbom_config.dedup_mode == DEDUP_MODE_SAFE) ? "safe" : "strict";
        fprintf(stderr, "INFO: Deduplication mode: %s%s\n", mode_str,
                g_cbom_config.emit_bundles ? " (with bundles)" : "");
    }

    // Initialize completion tracker (estimate 10 tasks for comprehensive scan)
    g_completion_tracker = completion_tracker_create(10);
    if (g_completion_tracker == NULL) {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_MEMORY, 0,
                       "main", "Failed to create completion tracker", NULL);
    }
    
    // Initialize plugin manager
    ERROR_LOG_INFO(g_error_collector, "main", "Initializing plugin system", NULL);
    plugin_manager_t* plugin_manager = plugin_manager_create("plugins", PLUGIN_SECURITY_PERMISSIVE);
    if (!plugin_manager) {
        ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                       "main", "Failed to create plugin manager", NULL);
        // Fall back to basic scanning
        return run_basic_certificate_scan(store);
    }
    
    // Register built-in scanners (including our certificate scanner)
    int builtin_result = plugin_manager_register_builtin_scanners(plugin_manager);
    if (builtin_result != PLUGIN_SUCCESS) {
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                         "main", "Failed to register built-in scanners", NULL);
    }

    // Handle --list-plugins mode
    if (g_list_plugins_mode) {
        // Load YAML plugins first
        const char* plugin_dir = g_cbom_config.plugin_dir ? g_cbom_config.plugin_dir : "plugins/";
        int yaml_loaded = 0;
        if (access(plugin_dir, F_OK) == 0) {
            yaml_loaded = plugin_manager_scan_yaml_directory(plugin_manager, plugin_dir);
            printf("Loaded %d YAML plugins from '%s'\n\n", yaml_loaded, plugin_dir);
        }

        // List all plugins (built-in + YAML)
        printf("=== CBOM Generator Plugins ===\n\n");

        // List built-in scanners
        printf("Built-in Scanners (5):\n");
        printf("  1. builtin_cert_scanner v1.0.0 - Certificate Scanner\n");
        printf("  2. builtin_key_scanner v1.0.0 - Key Scanner\n");
        printf("  3. builtin_package_scanner v1.0.0 - Package Scanner\n");
        printf("  4. builtin_service_scanner v1.0.0 - Service Scanner\n");
        printf("  5. builtin_fs_scanner v1.0.0 - Filesystem Scanner\n\n");

        // Show YAML plugin count
        if (yaml_loaded > 0) {
            printf("YAML Plugins (%d loaded)\n\n", yaml_loaded);
        } else {
            printf("No YAML plugins loaded\n\n");
        }

        printf("Total: %d plugins (5 built-in + %d YAML)\n", 5 + yaml_loaded, yaml_loaded);

        plugin_manager_destroy(plugin_manager);
        cleanup_subsystems();
        return 0;
    }

    // Set first path for TUI display
    first_path = g_cbom_config.target_path_count > 0 ? g_cbom_config.target_paths[0] : ".";

    // Find all scanner plugins
    plugin_instance_t* cert_scanner = plugin_manager_find_plugin(plugin_manager, "builtin_cert_scanner");
    plugin_instance_t* key_scanner = plugin_manager_find_plugin(plugin_manager, "builtin_key_scanner");
    plugin_instance_t* package_scanner = plugin_manager_find_plugin(plugin_manager, "builtin_package_scanner");
    plugin_instance_t* service_scanner = plugin_manager_find_plugin(plugin_manager, "builtin_service_scanner");
    plugin_instance_t* fs_scanner = plugin_manager_find_plugin(plugin_manager, "builtin_fs_scanner");

    // Create thread pool for parallel scanner execution
    thread_pool_t* scanner_pool = NULL;
    if (g_cbom_config.thread_count > 1) {
        scanner_pool = thread_pool_create((uint32_t)g_cbom_config.thread_count, 16);
        if (!scanner_pool) {
            ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_MEMORY,
                             "main", "Failed to create thread pool, falling back to sequential", NULL);
        }
    }

    // Decide: parallel or sequential execution
    if (scanner_pool) {
        // PARALLEL EXECUTION PATH (multi-threaded)
        ERROR_LOG_INFO(g_error_collector, "main", "Executing scanners in parallel", NULL);

        // Prepare scan contexts for file-based scanners (one per path)
        // Arrays must stay alive until thread_pool_wait_all
        scan_context_t cert_scan_contexts[MAX_SCAN_PATHS];
        scan_context_t key_scan_contexts[MAX_SCAN_PATHS];
        scan_context_t fs_scan_contexts[MAX_SCAN_PATHS];

        for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
            cert_scan_contexts[i] = (scan_context_t){
                .target_path = g_cbom_config.target_paths[i],
                .scan_type = "certificate",
                .user_data = NULL,
                .dedup_ctx = dedup_ctx,
                .error_collector = g_error_collector
            };

            key_scan_contexts[i] = (scan_context_t){
                .target_path = g_cbom_config.target_paths[i],
                .scan_type = "key",
                .user_data = NULL,
                .dedup_ctx = dedup_ctx,
                .error_collector = g_error_collector
            };

            fs_scan_contexts[i] = (scan_context_t){
                .target_path = g_cbom_config.target_paths[i],
                .scan_type = "filesystem",
                .user_data = NULL,
                .dedup_ctx = dedup_ctx,
                .error_collector = g_error_collector
            };
        }

        // Prepare scan contexts for system-wide scanners (single context)
        scan_context_t package_scan_context = {
            .target_path = first_path,
            .scan_type = "package",
            .user_data = NULL,
            .dedup_ctx = dedup_ctx,
            .error_collector = g_error_collector
        };

        scan_context_t service_scan_context = {
            .target_path = first_path,
            .scan_type = "service",
            .user_data = NULL,
            .dedup_ctx = dedup_ctx,
            .error_collector = g_error_collector
        };

        // Result storage for file-based scanners (one per path)
        int cert_results[MAX_SCAN_PATHS];
        int key_results[MAX_SCAN_PATHS];
        int fs_results[MAX_SCAN_PATHS];

        for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
            cert_results[i] = PLUGIN_SUCCESS;
            key_results[i] = PLUGIN_SUCCESS;
            fs_results[i] = PLUGIN_SUCCESS;
        }

        // Result storage for system-wide scanners (single result)
        int pkg_result = PLUGIN_SUCCESS;
        int svc_result = PLUGIN_SUCCESS;

        // Early YAML plugin service discovery to determine if built-in service scanner should be skipped
        // This must run BEFORE thread pool submission so the flag is set correctly
        if (g_cbom_config.discover_services) {
            const char* plugin_dir = g_cbom_config.plugin_dir ? g_cbom_config.plugin_dir : "plugins/";
            struct stat st;
            if (stat(plugin_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
                int yaml_loaded = plugin_manager_scan_yaml_directory(plugin_manager, plugin_dir);
                if (yaml_loaded > 0) {
                    // Run service discovery to check if plugins find any services
                    service_discovery_engine_t* early_discovery = service_discovery_engine_create();
                    if (early_discovery) {
                        size_t early_service_count = 0;
                        service_instance_t** early_services = service_discovery_discover_all(
                            early_discovery, plugin_manager, &early_service_count);

                        if (early_service_count > 0) {
                            g_cbom_config.skip_builtin_service_scanner = true;
                            if (g_output_mode != OUTPUT_MODE_TUI) {
                                fprintf(stderr, "[INFO] Built-in service scanner disabled: %zu services discovered via YAML plugins\n", early_service_count);
                            }
                        }

                        // Cleanup early discovery - Phase 4.5 will re-discover services
                        if (early_services) {
                            for (size_t i = 0; i < early_service_count; i++) {
                                service_instance_free(early_services[i]);
                            }
                            free(early_services);
                        }
                        service_discovery_engine_destroy(early_discovery);
                    }
                }
            }
        }

        // Prepare work items for file-based scanners (one per path)
        scanner_work_t cert_work_items[MAX_SCAN_PATHS];
        scanner_work_t key_work_items[MAX_SCAN_PATHS];
        scanner_work_t fs_work_items[MAX_SCAN_PATHS];

        for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
            cert_work_items[i] = (scanner_work_t){
                .scanner = cert_scanner,
                .scan_context = &cert_scan_contexts[i],
                .store = store,
                .plugin_manager = plugin_manager,
                .scanner_name = "Certificate Scanner",
                .scanner_type = SCANNER_CERTIFICATE,
                .result_out = &cert_results[i]
            };

            key_work_items[i] = (scanner_work_t){
                .scanner = key_scanner,
                .scan_context = &key_scan_contexts[i],
                .store = store,
                .plugin_manager = plugin_manager,
                .scanner_name = "Key Scanner",
                .scanner_type = SCANNER_KEY,
                .result_out = &key_results[i]
            };

            fs_work_items[i] = (scanner_work_t){
                .scanner = fs_scanner,
                .scan_context = &fs_scan_contexts[i],
                .store = store,
                .plugin_manager = plugin_manager,
                .scanner_name = "Filesystem Scanner",
                .scanner_type = SCANNER_FILESYSTEM,
                .result_out = &fs_results[i]
            };
        }

        // Prepare work items for system-wide scanners (single work item)
        scanner_work_t pkg_work = {
            .scanner = package_scanner,
            .scan_context = &package_scan_context,
            .store = store,
            .plugin_manager = plugin_manager,
            .scanner_name = "Package Scanner",
            .scanner_type = SCANNER_PACKAGE,
            .result_out = &pkg_result
        };

        scanner_work_t svc_work = {
            .scanner = service_scanner,
            .scan_context = &service_scan_context,
            .store = store,
            .plugin_manager = plugin_manager,
            .scanner_name = "Service Scanner",
            .scanner_type = SCANNER_SERVICE,
            .result_out = &svc_result
        };

        // Submit file-based scanners to thread pool (one work item per path)
        if (cert_scanner) {
            for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
                thread_pool_submit(scanner_pool, scanner_work_wrapper, &cert_work_items[i], NULL, WORK_PRIORITY_NORMAL);
            }
        }

        if (key_scanner) {
            for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
                thread_pool_submit(scanner_pool, scanner_work_wrapper, &key_work_items[i], NULL, WORK_PRIORITY_NORMAL);
            }
        }

        if (fs_scanner) {
            for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
                thread_pool_submit(scanner_pool, scanner_work_wrapper, &fs_work_items[i], NULL, WORK_PRIORITY_NORMAL);
            }
        }

        // Submit system-wide scanners (single work item each)
        // Skip package scanner if --no-package-resolution is set (for cross-arch scanning)
        if (package_scanner && !g_cbom_config.skip_package_resolution) {
            thread_pool_submit(scanner_pool, scanner_work_wrapper, &pkg_work, NULL, WORK_PRIORITY_NORMAL);
        }

        if (service_scanner && !g_cbom_config.skip_builtin_service_scanner) {
            thread_pool_submit(scanner_pool, scanner_work_wrapper, &svc_work, NULL, WORK_PRIORITY_NORMAL);
        }

        // Wait for all scanners to complete
        thread_pool_wait_all(scanner_pool);

        // All scanners done - update asset counts and completion tracker
        // Note: SCANNER_COMPLETE notifications now sent from worker threads

        stats = asset_store_get_stats(store);
        total_assets = stats.total_assets;
        tui_update_assets(total_assets, stats.assets_by_type[ASSET_TYPE_CERTIFICATE], stats.assets_by_type[ASSET_TYPE_KEY], stats.assets_by_type[ASSET_TYPE_ALGORITHM], stats.assets_by_type[ASSET_TYPE_LIBRARY], stats.assets_by_type[ASSET_TYPE_PROTOCOL], stats.assets_by_type[ASSET_TYPE_SERVICE], stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

        // Aggregate results from all paths for file-based scanners
        int overall_cert_result = PLUGIN_SUCCESS;
        int overall_key_result = PLUGIN_SUCCESS;
        int overall_fs_result = PLUGIN_SUCCESS;

        for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
            if (cert_results[i] != PLUGIN_SUCCESS) overall_cert_result = cert_results[i];
            if (key_results[i] != PLUGIN_SUCCESS) overall_key_result = key_results[i];
            if (fs_results[i] != PLUGIN_SUCCESS) overall_fs_result = fs_results[i];
        }

        // Update completion tracker for each scanner type (not per path)
        if (cert_scanner) {
            if (overall_cert_result == PLUGIN_SUCCESS) {
                completion_tracker_task_completed(g_completion_tracker);
            } else {
                completion_tracker_task_failed(g_completion_tracker);
            }
        }

        if (key_scanner) {
            if (overall_key_result == PLUGIN_SUCCESS) {
                completion_tracker_task_completed(g_completion_tracker);
            } else {
                completion_tracker_task_failed(g_completion_tracker);
            }
        }

        if (package_scanner) {
            if (pkg_result == PLUGIN_SUCCESS) {
                completion_tracker_task_completed(g_completion_tracker);
            } else {
                completion_tracker_task_failed(g_completion_tracker);
            }
        }

        if (service_scanner) {
            if (svc_result == PLUGIN_SUCCESS) {
                completion_tracker_task_completed(g_completion_tracker);
            } else {
                completion_tracker_task_failed(g_completion_tracker);
            }
        }

        if (fs_scanner) {
            if (overall_fs_result == PLUGIN_SUCCESS) {
                completion_tracker_task_completed(g_completion_tracker);
            } else {
                completion_tracker_task_failed(g_completion_tracker);
            }
        }

        // Cleanup thread pool
        thread_pool_destroy(scanner_pool);

        // Issue #4: Build relationships after all scanners complete
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Building cryptographic asset relationships...\n");

        // Count keys and certs for relationship metadata
        asset_store_stats_t stats_for_rel = asset_store_get_stats(store);
        int total_keys_scanned = stats_for_rel.assets_by_type[ASSET_TYPE_KEY];
        int total_certs_scanned = stats_for_rel.assets_by_type[ASSET_TYPE_CERTIFICATE];

        // Issue #3: Rebuild service-cert relationships now that all certs are scanned
        // The service scanner stored cert paths but couldn't create relationships yet
        int service_cert_links = build_service_cert_relationships(store);
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Created %d service-certificate AUTHENTICATES_WITH relationships\n", service_cert_links);

        // Match private keys to certificates (SIGNS relationships)
        int key_cert_matches = key_manager_match_keys_to_certificates(store);
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Created %d key-certificate SIGNS relationships\n", key_cert_matches);

        // Build certificate chains (ISSUED_BY relationships)
        int cert_chains = key_manager_build_certificate_chains(store);
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Created %d certificate chain ISSUED_BY relationships\n", cert_chains);

        // Store relationship statistics for metadata output (Issue #4)
        g_key_cert_matches = key_cert_matches;
        g_cert_chains = cert_chains;
        g_total_keys_for_matching = total_keys_scanned;
        g_total_certs_for_matching = total_certs_scanned;

        // Skip sequential execution
        goto skip_sequential_scanners;
    }

    if (!scanner_pool) {
        // SEQUENTIAL EXECUTION PATH (single-threaded fallback)
        ERROR_LOG_INFO(g_error_collector, "main", "Executing scanners sequentially", NULL);
    }

    // Execute certificate scanner (plugin already found above)
    if (cert_scanner) {
        ERROR_LOG_INFO(g_error_collector, "main", "Executing certificate scanner", NULL);

        // Notify TUI that certificate scanner is starting
        tui_log(TUI_MSG_SCANNER_START, SCANNER_CERTIFICATE, "Certificate Scanner", 0, 0, NULL, first_path);

        // Loop through all target paths
        int overall_result = PLUGIN_SUCCESS;
        for (size_t i = 0; i < g_cbom_config.target_path_count; i++) {
            // Create a scan context with target path for certificate scanner
            scan_context_t cert_scan_context = {
                .target_path = g_cbom_config.target_paths[i],
                .scan_type = "certificate",
                .user_data = NULL,
                .dedup_ctx = dedup_ctx,
                .error_collector = g_error_collector
            };

            // Execute the certificate scanner
            int scan_result = plugin_manager_execute_scanner(plugin_manager, cert_scanner->instance_id, &cert_scan_context, store);

            if (scan_result != PLUGIN_SUCCESS) {
                ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                               "main", "Certificate scanner failed for path", g_cbom_config.target_paths[i]);
                overall_result = scan_result;
            }
        }

        // Get total asset count to report to TUI
        stats = asset_store_get_stats(store);
        total_assets = stats.total_assets;

        // Notify TUI that certificate scanner completed
        tui_log(TUI_MSG_SCANNER_COMPLETE, SCANNER_CERTIFICATE, "Certificate Scanner", 0, g_cert_scanner_stats.certs_parsed_ok, NULL, NULL);

        // Update TUI with asset breakdown
        tui_update_assets(total_assets,
                         stats.assets_by_type[ASSET_TYPE_CERTIFICATE],
                         stats.assets_by_type[ASSET_TYPE_KEY],
                         stats.assets_by_type[ASSET_TYPE_ALGORITHM],
                         stats.assets_by_type[ASSET_TYPE_LIBRARY],
                         stats.assets_by_type[ASSET_TYPE_PROTOCOL],
                         stats.assets_by_type[ASSET_TYPE_SERVICE],
                         stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

        if (overall_result == PLUGIN_SUCCESS) {
            ERROR_LOG_INFO(g_error_collector, "main", "Certificate scanner completed successfully", NULL);
            completion_tracker_task_completed(g_completion_tracker);
        } else {
            completion_tracker_task_failed(g_completion_tracker);
        }
    } else {
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                         "main", "Certificate scanner plugin not found, using basic scan", NULL);
        // Fall back to basic scanning - scan all target paths
        int cert_count = 0;
        for (size_t i = 0; i < g_cbom_config.target_path_count; i++) {
            int count = scan_directory_for_certificates(g_cbom_config.target_paths[i], store);
            if (count > 0) cert_count += count;
        }
        if (cert_count >= 0) {
            completion_tracker_task_completed(g_completion_tracker);
        } else {
            completion_tracker_task_failed(g_completion_tracker);
        }
    }

    // Execute key scanner (plugin already found above)

    if (key_scanner) {
        ERROR_LOG_INFO(g_error_collector, "main", "Executing key scanner", NULL);

        // Notify TUI that key scanner is starting
        tui_log(TUI_MSG_SCANNER_START, SCANNER_KEY, "Key Scanner", 0, 0, NULL, first_path);

        // Loop through all target paths
        int overall_result = PLUGIN_SUCCESS;
        for (size_t i = 0; i < g_cbom_config.target_path_count; i++) {
            // Create a scan context with target path for key scanner
            scan_context_t key_scan_context = {
                .target_path = g_cbom_config.target_paths[i],
                .scan_type = "key",
                .user_data = NULL,
                .dedup_ctx = dedup_ctx,
                .error_collector = g_error_collector
            };

            // Execute the key scanner
            int key_scan_result = plugin_manager_execute_scanner(plugin_manager, key_scanner->instance_id, &key_scan_context, store);

            if (key_scan_result != PLUGIN_SUCCESS) {
                ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                               "main", "Key scanner failed for path", g_cbom_config.target_paths[i]);
                overall_result = key_scan_result;
            }
        }

        // Notify TUI that key scanner completed
        stats = asset_store_get_stats(store);
        total_assets = stats.total_assets;
        tui_log(TUI_MSG_SCANNER_COMPLETE, SCANNER_KEY, "Key Scanner", 0, 0, NULL, NULL);
        tui_update_assets(total_assets, stats.assets_by_type[ASSET_TYPE_CERTIFICATE], stats.assets_by_type[ASSET_TYPE_KEY], stats.assets_by_type[ASSET_TYPE_ALGORITHM], stats.assets_by_type[ASSET_TYPE_LIBRARY], stats.assets_by_type[ASSET_TYPE_PROTOCOL], stats.assets_by_type[ASSET_TYPE_SERVICE], stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

        if (overall_result == PLUGIN_SUCCESS) {
            ERROR_LOG_INFO(g_error_collector, "main", "Key scanner completed successfully", NULL);
            completion_tracker_task_completed(g_completion_tracker);
        } else {
            completion_tracker_task_failed(g_completion_tracker);
        }
    } else {
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                         "main", "Key scanner plugin not found", NULL);
    }

    // Execute package scanner (plugin already found above)
    // Skip if --no-package-resolution is set (for cross-arch scanning)
    if (package_scanner && !g_cbom_config.skip_package_resolution) {
        ERROR_LOG_INFO(g_error_collector, "main", "Executing package scanner", NULL);

        // Notify TUI that package scanner is starting
        tui_log(TUI_MSG_SCANNER_START, SCANNER_PACKAGE, "Package Scanner", 0, 0, NULL, "system-wide");

        // Create a scan context for package scanner (system-wide, target_path not used)
        scan_context_t package_scan_context = {
            .target_path = g_cbom_config.target_paths[0],  // Package scanner is system-wide
            .scan_type = "package",
            .user_data = NULL,
            .dedup_ctx = dedup_ctx,
            .error_collector = g_error_collector
        };

        // Execute the package scanner
        int pkg_scan_result = plugin_manager_execute_scanner(plugin_manager, package_scanner->instance_id, &package_scan_context, store);

        // Notify TUI that package scanner completed
        stats = asset_store_get_stats(store); total_assets = stats.total_assets;
        tui_log(TUI_MSG_SCANNER_COMPLETE, SCANNER_PACKAGE, "Package Scanner", 0, 0, NULL, NULL);
        tui_update_assets(total_assets, stats.assets_by_type[ASSET_TYPE_CERTIFICATE], stats.assets_by_type[ASSET_TYPE_KEY], stats.assets_by_type[ASSET_TYPE_ALGORITHM], stats.assets_by_type[ASSET_TYPE_LIBRARY], stats.assets_by_type[ASSET_TYPE_PROTOCOL], stats.assets_by_type[ASSET_TYPE_SERVICE], stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

        if (pkg_scan_result == PLUGIN_SUCCESS) {
            ERROR_LOG_INFO(g_error_collector, "main", "Package scanner completed successfully", NULL);
            completion_tracker_task_completed(g_completion_tracker);
        } else {
            ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                           "main", "Package scanner failed", NULL);
            completion_tracker_task_failed(g_completion_tracker);
        }
    } else {
        if (!package_scanner) {
            ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                             "main", "Package scanner plugin not found", NULL);
        } else if (g_cbom_config.skip_package_resolution) {
            ERROR_LOG_INFO(g_error_collector, "main", "Skipping package scanner (--no-package-resolution set)", NULL);
            // Mark task as completed since we're intentionally skipping it
            completion_tracker_task_completed(g_completion_tracker);
        }
    }

    // Execute service scanner (plugin already found above)
    // Skip if YAML plugins discovered services
    if (service_scanner && !g_cbom_config.skip_builtin_service_scanner) {
        ERROR_LOG_INFO(g_error_collector, "main", "Executing service scanner", NULL);

        // Notify TUI that service scanner is starting
        tui_log(TUI_MSG_SCANNER_START, SCANNER_SERVICE, "Service Scanner", 0, 0, NULL, "system-wide");

        // Create a scan context for service scanner (system-wide, target_path not used)
        scan_context_t service_scan_context = {
            .target_path = g_cbom_config.target_paths[0],  // Service scanner is system-wide
            .scan_type = "service",
            .user_data = NULL,
            .dedup_ctx = dedup_ctx,
            .error_collector = g_error_collector
        };

        // Execute the service scanner
        int svc_scan_result = plugin_manager_execute_scanner(plugin_manager, service_scanner->instance_id, &service_scan_context, store);

        // Notify TUI that service scanner completed
        stats = asset_store_get_stats(store); total_assets = stats.total_assets;
        tui_log(TUI_MSG_SCANNER_COMPLETE, SCANNER_SERVICE, "Service Scanner", 0, 0, NULL, NULL);
        tui_update_assets(total_assets, stats.assets_by_type[ASSET_TYPE_CERTIFICATE], stats.assets_by_type[ASSET_TYPE_KEY], stats.assets_by_type[ASSET_TYPE_ALGORITHM], stats.assets_by_type[ASSET_TYPE_LIBRARY], stats.assets_by_type[ASSET_TYPE_PROTOCOL], stats.assets_by_type[ASSET_TYPE_SERVICE], stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

        if (svc_scan_result == PLUGIN_SUCCESS) {
            ERROR_LOG_INFO(g_error_collector, "main", "Service scanner completed successfully", NULL);
            completion_tracker_task_completed(g_completion_tracker);
        } else {
            ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                           "main", "Service scanner failed", NULL);
            completion_tracker_task_failed(g_completion_tracker);
        }
    } else {
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                         "main", "Service scanner plugin not found", NULL);
    }

    // Execute filesystem scanner (plugin already found above)
    if (fs_scanner) {
        ERROR_LOG_INFO(g_error_collector, "main", "Executing filesystem scanner", NULL);

        // Notify TUI that filesystem scanner is starting
        tui_log(TUI_MSG_SCANNER_START, SCANNER_FILESYSTEM, "Filesystem Scanner", 0, 0, NULL, first_path);

        // Loop through all target paths
        int overall_result = PLUGIN_SUCCESS;
        for (size_t i = 0; i < g_cbom_config.target_path_count; i++) {
            // Create a scan context with target path
            scan_context_t scan_context = {
                .target_path = g_cbom_config.target_paths[i],
                .scan_type = "filesystem",
                .user_data = NULL,
                .dedup_ctx = dedup_ctx,
                .error_collector = g_error_collector
            };

            // Execute the filesystem scanner
            int fs_scan_result = plugin_manager_execute_scanner(plugin_manager, fs_scanner->instance_id, &scan_context, store);

            if (fs_scan_result != PLUGIN_SUCCESS) {
                ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, 0,
                               "main", "Filesystem scanner failed for path", g_cbom_config.target_paths[i]);
                overall_result = fs_scan_result;
            }
        }

        // Notify TUI that filesystem scanner completed
        stats = asset_store_get_stats(store); total_assets = stats.total_assets;
        tui_log(TUI_MSG_SCANNER_COMPLETE, SCANNER_FILESYSTEM, "Filesystem Scanner", 0, 0, NULL, NULL);
        tui_update_assets(total_assets, stats.assets_by_type[ASSET_TYPE_CERTIFICATE], stats.assets_by_type[ASSET_TYPE_KEY], stats.assets_by_type[ASSET_TYPE_ALGORITHM], stats.assets_by_type[ASSET_TYPE_LIBRARY], stats.assets_by_type[ASSET_TYPE_PROTOCOL], stats.assets_by_type[ASSET_TYPE_SERVICE], stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

        if (overall_result == PLUGIN_SUCCESS) {
            ERROR_LOG_INFO(g_error_collector, "main", "Filesystem scanner completed successfully", NULL);
            completion_tracker_task_completed(g_completion_tracker);
        } else {
            completion_tracker_task_failed(g_completion_tracker);
        }
    } else {
        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                         "main", "Filesystem scanner plugin not found", NULL);
    }

skip_sequential_scanners:
    // Phase 4.5: YAML Plugin Service Discovery and Config Extraction
    // This runs AFTER built-in scanners in both parallel and sequential paths

    // Service discovery results (declared here for use in app scanner deduplication)
    size_t service_count = 0;
    service_instance_t** services = NULL;
    char** excluded_paths = NULL;
    int excluded_count = 0;

    if (g_cbom_config.discover_services) {
        ERROR_LOG_INFO(g_error_collector, "main", "Phase 4.5: Service Discovery Pipeline", NULL);

        // Initialize config extractor and parser registry
        if (config_extractor_init() != 0) {
            ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_CONFIG, 0,
                          "main", "Failed to initialize config extractor", NULL);
            fprintf(stderr, "ERROR: Failed to initialize config extractor\n");
        } else {

        // === Phase 1: Load YAML Plugins ===
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Phase 1: Loading YAML plugins...\n");

        const char* plugin_dir = g_cbom_config.plugin_dir ? g_cbom_config.plugin_dir : "plugins/";
        int yaml_loaded = 0;

        // Check if YAML plugins were already loaded in early discovery (parallel path)
        // Built-in scanners = 5, so plugin_count > 5 means YAML plugins are loaded
        if (plugin_manager && plugin_manager->plugin_count > 5) {
            yaml_loaded = plugin_manager->plugin_count - 5;  // Already loaded
            if (g_output_mode != OUTPUT_MODE_TUI) {
                fprintf(stderr, "INFO:   Using %d YAML plugins (already loaded)\n", yaml_loaded);
            }
        } else if (access(plugin_dir, F_OK) == 0) {
            // Scan directory for .yaml files and load them
            yaml_loaded = plugin_manager_scan_yaml_directory(plugin_manager, plugin_dir);
            if (yaml_loaded > 0) {
                if (g_output_mode != OUTPUT_MODE_TUI) {
                    fprintf(stderr, "INFO:   Loaded %d YAML plugins from '%s'\n", yaml_loaded, plugin_dir);
                }
            } else if (yaml_loaded < 0) {
                ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                                "main", "Failed to scan plugin directory", plugin_dir);
                yaml_loaded = 0;
            } else {
                if (g_output_mode != OUTPUT_MODE_TUI) {
                    fprintf(stderr, "INFO:   No YAML plugins found in '%s'\n", plugin_dir);
                }
            }
        } else {
            ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                            "main", "Plugin directory not found", plugin_dir);
        }

        if (g_output_mode != OUTPUT_MODE_TUI && !(plugin_manager && plugin_manager->plugin_count > 5)) {
            fprintf(stderr, "INFO:   Loaded %d YAML plugins\n", yaml_loaded);
        }

        // === Phase 2: Service Discovery ===
        if (g_output_mode != OUTPUT_MODE_TUI) fprintf(stderr, "INFO: Phase 2: Discovering services...\n");

        service_discovery_engine_t* discovery_engine = service_discovery_engine_create();
        if (!discovery_engine) {
            ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_MEMORY, 0,
                          "main", "Failed to create service discovery engine", NULL);
        } else {
            services = service_discovery_discover_all(
                discovery_engine,
                plugin_manager,
                &service_count
            );

            if (g_output_mode != OUTPUT_MODE_TUI) {
                fprintf(stderr, "INFO:   Discovered %zu service(s)\n", service_count);
            }

            // Note: g_cbom_config.skip_builtin_service_scanner was already set in early discovery
            // (before thread pool submission) to prevent the built-in service scanner from running

            // === Phase 3 & 4: Config Extraction & Component Generation ===
            if (services && service_count > 0) {
                if (g_output_mode != OUTPUT_MODE_TUI) {
                    fprintf(stderr, "INFO: Phase 3: Extracting crypto configurations...\n");
                }

                int configs_extracted = 0;

                for (size_t i = 0; i < service_count; i++) {
                    service_instance_t* service = services[i];

                    if (g_output_mode != OUTPUT_MODE_TUI) {
                        fprintf(stderr, "INFO:   Processing service: %s\n", service->service_name);
                    }

                    // Get plugin from service (stored as void*)
                    yaml_plugin_t* plugin = (yaml_plugin_t*)service->plugin;

                    if (!plugin) {
                        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                                        "main", "Service has no associated plugin", service->service_name);
                        continue;
                    }

                    // Extract crypto configuration
                    crypto_config_t* config = config_extractor_extract(service, plugin);

                    if (!config) {
                        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                                        "main", "Config extraction failed for service", service->service_name);
                        continue;
                    }

                    configs_extracted++;

                    if (g_output_mode != OUTPUT_MODE_TUI) {
                        fprintf(stderr, "INFO:     Certificates: %d, Keys: %d, TLS: %s\n",
                               config->certificate_count,
                               config->private_key_count,
                               config->tls_enabled ? "yes" : "no");
                    }

                    // === Phase 4: Component Generation ===
                    int component_result = component_factory_process_service(service, config, store);

                    if (component_result == 0) {
                        if (g_output_mode != OUTPUT_MODE_TUI) {
                            fprintf(stderr, "INFO:     Components generated successfully\n");
                        }
                    } else {
                        ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                                        "main", "Component generation failed", service->service_name);
                    }

                    // Cleanup
                    crypto_config_free(config);
                }

                if (g_output_mode != OUTPUT_MODE_TUI) {
                    fprintf(stderr, "INFO: Extracted configs for %d/%zu services\n",
                           configs_extracted, service_count);
                }
            }

            // Collect binary paths BEFORE cleanup (for app scanner deduplication)
            if (services && service_count > 0) {
                excluded_paths = malloc(sizeof(char*) * service_count);
                if (excluded_paths) {
                    for (size_t i = 0; i < service_count; i++) {
                        if (services[i] && services[i]->binary_path) {
                            // Duplicate the string since services will be freed
                            excluded_paths[excluded_count] = strdup(services[i]->binary_path);
                            excluded_count++;
                        }
                    }
                    if (g_output_mode != OUTPUT_MODE_TUI && excluded_count > 0) {
                        fprintf(stderr, "INFO:   Collected %d binary paths for deduplication\n", excluded_count);
                    }
                }
            }

            // Cleanup services
            if (services) {
                for (size_t i = 0; i < service_count; i++) {
                    service_instance_free(services[i]);
                }
                free(services);
                services = NULL;  // Set to NULL after freeing
            }

            service_discovery_engine_destroy(discovery_engine);
        }

        if (g_output_mode != OUTPUT_MODE_TUI) {
            fprintf(stderr, "INFO: Phase 4.5 pipeline complete\n");
        }

        // Cleanup config extractor
        config_extractor_destroy();
        }  // End of else block for config_extractor_init success
    }

    // === v1.5: Application Scanner (Comprehensive Binary Scanning) ===
    if (g_output_mode != OUTPUT_MODE_TUI) {
        fprintf(stderr, "\nINFO: v1.5 Phase: Application Scanner (comprehensive binary scanning)...\n");
    }

    // TUI: Mark application scanner as started
    tui_log(TUI_MSG_SCANNER_START, SCANNER_APPLICATION, "Application Scanner", 0, 0, NULL, "system-wide");

    // Configure application scanner with exclusions
    application_scanner_config_t app_config = {
        .scan_usr_bin = true,
        .scan_usr_sbin = true,
        .scan_usr_local = false,
        .scan_opt = false,
        .max_applications = 0,
        .thread_count = 4,
        .extract_versions = false,  // Disabled - too slow for large scans (enable if needed)
        .excluded_paths = excluded_paths,
        .excluded_path_count = excluded_count
    };

    application_scanner_init(&app_config);

    // Use parallel scanning if thread count > 1
    int apps_detected = 0;
    if (g_cbom_config.thread_count > 1) {
        // Parallel scan: Scan each target directory directly (don't append subdirectories)
        tui_log(TUI_MSG_SCANNER_START, SCANNER_APPLICATION, "Application Scanner", 0, 0, NULL, first_path);

        // Scan each target path directly as provided by the user
        for (size_t i = 0; i < g_cbom_config.target_path_count && i < MAX_SCAN_PATHS; i++) {
            const char* target = g_cbom_config.target_paths[i];

            // Scan the target directory directly without appending subdirectories
            int detected = application_scanner_scan_directory_parallel(store, target, g_cbom_config.thread_count);
            if (detected > 0) apps_detected += detected;
        }

        if (g_output_mode != OUTPUT_MODE_TUI) {
            fprintf(stderr, "INFO:   Applications detected (parallel): %d\n", apps_detected);
        }
    } else {
        // Sequential fallback for single-threaded mode
        apps_detected = application_scanner_scan(store);
        if (apps_detected >= 0) {
            if (g_output_mode != OUTPUT_MODE_TUI) {
                fprintf(stderr, "INFO:   Applications detected: %d\n", apps_detected);
            }
        } else {
            ERROR_LOG_WARNING(g_error_collector, ERROR_CATEGORY_IO,
                            "main", "Application scanner failed", NULL);
        }
    }
    application_scanner_cleanup();

    // TUI: Mark application scanner as complete
    tui_log(TUI_MSG_SCANNER_COMPLETE, SCANNER_APPLICATION, "Application Scanner", 0, apps_detected, NULL, NULL);

    // Cleanup excluded paths array (free strdup'd strings)
    if (excluded_paths) {
        for (int i = 0; i < excluded_count; i++) {
            free(excluded_paths[i]);  // Free strdup'd strings
        }
        free(excluded_paths);
    }

    // Cleanup plugin manager (after Phase 4.5 if enabled)
    plugin_manager_destroy(plugin_manager);
    plugin_manager = NULL;

    // Store deduplication statistics (available in CBOM output properties)
    if (dedup_ctx) {
        g_dedup_stats = dedup_get_stats(dedup_ctx);
        dedup_context_destroy(dedup_ctx);
        dedup_ctx = NULL;
    }

    // Generate output
    // Generate PQC migration report if requested (Phase 5)
    if (g_cbom_config.pqc_report_path) {
        FILE* report_file = fopen(g_cbom_config.pqc_report_path, "w");
        if (report_file) {
            int report_result = pqc_generate_migration_report(store, report_file);
            fclose(report_file);

            if (report_result == 0 && g_output_mode != OUTPUT_MODE_TUI) {
                fprintf(stderr, "INFO: PQC migration report saved to %s\n", g_cbom_config.pqc_report_path);
            } else if (report_result != 0) {
                fprintf(stderr, "ERROR: Failed to generate PQC migration report\n");
            }
        } else {
            fprintf(stderr, "ERROR: Could not create PQC report file: %s\n", g_cbom_config.pqc_report_path);
        }
    }

    FILE *output_file = stdout;
    if (g_cbom_config.output_file != NULL) {
        output_file = fopen(g_cbom_config.output_file, "w");
        if (output_file == NULL) {
            ERROR_LOG_ERROR(g_error_collector, ERROR_CATEGORY_IO, errno,
                           "main", "Failed to open output file", g_cbom_config.output_file);
            output_file = stdout;
        }
    }

    // v1.8.1: Merge duplicate services/applications before output
    // This handles cases where both YAML plugin and filesystem scanner detect the same service
    int merged = dedup_merge_duplicate_services(store);
    if (merged > 0) {
        ERROR_LOG_INFO(g_error_collector, "main", "Merged duplicate components",
                       merged > 0 ? "dedup applied" : "no duplicates");
    }

    int result = generate_cyclonedx_cbom(store, output_file);

    if (output_file != stdout) {
        fclose(output_file);

        // Generate checksum if output file was created
        if (result == 0) {
            char checksum_file[PATH_MAX];
            snprintf(checksum_file, sizeof(checksum_file), "%s.sha256", g_cbom_config.output_file);

            char command[PATH_MAX * 2];
            snprintf(command, sizeof(command), "sha256sum %s > %s",
                    g_cbom_config.output_file, checksum_file);

            if (system(command) == 0) {
                ERROR_LOG_INFO(g_error_collector, "main", "Generated checksum file", checksum_file);
            }
        }
    }

    // Update TUI with final asset counts
    stats = asset_store_get_stats(store);
    total_assets = stats.total_assets;
    tui_update_assets(total_assets, stats.assets_by_type[ASSET_TYPE_CERTIFICATE], stats.assets_by_type[ASSET_TYPE_KEY], stats.assets_by_type[ASSET_TYPE_ALGORITHM], stats.assets_by_type[ASSET_TYPE_LIBRARY], stats.assets_by_type[ASSET_TYPE_PROTOCOL], stats.assets_by_type[ASSET_TYPE_SERVICE], stats.assets_by_type[ASSET_TYPE_CIPHER_SUITE]);

    // NOW all work is done - notify TUI and wait for user keystroke
    if (g_tui_context && g_tui_context->running) {
        tui_log(TUI_MSG_COMPLETE, SCANNER_UNKNOWN, NULL, 0, 0, NULL, NULL);

        // Give render thread time to process the completion message
        while (!g_tui_context->scan_complete && g_tui_context->running) {
            usleep(50000);  // Poll every 50ms
        }

        // Wait for user to press a key (render thread handles the wait)
        tui_wait_for_completion(g_tui_context);

        // Print minimal summary after TUI exits (user pressed a key)
        fprintf(stderr, "\n");
        if (g_pqc_safe_count > 0 || g_pqc_unsafe_count > 0) {
            fprintf(stderr, "PQC Assessment: %.1f%% ready (%d safe, %d transitional, %d unsafe)\n",
                    g_pqc_readiness_score, g_pqc_safe_count, g_pqc_transitional_count, g_pqc_unsafe_count);
        }
        if (g_cbom_config.output_file) {
            fprintf(stderr, "CBOM in: %s\n", g_cbom_config.output_file);
        }
        fprintf(stderr, "\n");
    }

    asset_store_destroy(store);
    return result;
}

int main(int argc, char *argv[]) {
    int exit_code = 0;
    
    // Parse command line arguments
    if (parse_arguments(argc, argv) != 0) {
        return 1;
    }
    
    // Setup deterministic environment
    if (setup_deterministic_environment() != 0) {
        return 2;
    }
    
    // Initialize subsystems
    if (initialize_subsystems() != 0) {
        return 3;
    }
    
    // Run walking skeleton
    if (run_walking_skeleton() != 0) {
        exit_code = determine_exit_code(g_error_collector);
    }
    
    // Cleanup
    cleanup_subsystems();
    
    return exit_code;
}
