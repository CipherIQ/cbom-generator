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

#ifndef SLSA_PROVENANCE_H
#define SLSA_PROVENANCE_H

#include <json-c/json.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// SLSA Provenance configuration
typedef struct {
    // Build source information
    char* git_repository;        // Git repository URL
    char* git_commit_sha;        // Git commit SHA
    char* git_branch;            // Git branch name
    char* git_tag;               // Git tag (optional)

    // Build environment
    char* build_type;            // "Release", "Debug", etc.
    char* build_timestamp;       // ISO 8601 timestamp
    char* build_platform;        // OS and architecture

    // Builder information
    char* builder_identity;      // Builder identity (e.g., CI system)
    char* builder_version;       // Builder version

    // Toolchain information
    char* compiler_name;         // Compiler name (GCC, Clang)
    char* compiler_version;      // Compiler version
    char* openssl_version;       // OpenSSL version
    char* libcurl_version;       // libcurl version

    // Build dependencies
    char** build_dependencies;   // Array of dependency strings
    size_t dependency_count;     // Number of dependencies

    // Build flags and parameters
    char* build_flags;           // Compiler flags used
    bool reproducible;           // Whether build is reproducible
} slsa_provenance_config_t;

// SLSA Provenance context
typedef struct {
    slsa_provenance_config_t config;
    time_t generation_time;
    bool initialized;
} slsa_provenance_context_t;

// Provenance generation functions
slsa_provenance_context_t* slsa_provenance_create(const slsa_provenance_config_t* config);
void slsa_provenance_destroy(slsa_provenance_context_t* context);

// Generate SLSA v0.2 provenance as JSON object
json_object* slsa_generate_provenance(slsa_provenance_context_t* context,
                                      const char* cbom_file_path,
                                      const char* cbom_sha256);

// Add provenance to CBOM metadata
int slsa_add_provenance_to_cbom(json_object* cbom, json_object* provenance);

// Utility functions
char* slsa_get_git_commit_sha(void);
char* slsa_get_git_repository(void);
char* slsa_get_git_branch(void);
char* slsa_get_build_timestamp(void);
char* slsa_get_build_platform(void);

// Default configuration with build-time values
slsa_provenance_config_t slsa_get_default_config(void);

// Populate configuration from environment and build metadata
int slsa_populate_config_from_env(slsa_provenance_config_t* config);

#ifdef __cplusplus
}
#endif

#endif // SLSA_PROVENANCE_H
