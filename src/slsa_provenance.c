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
#include "slsa_provenance.h"
#include "secure_memory.h"
#include "../build/src/provenance.h"  // Generated build-time configuration
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

// Get default SLSA provenance configuration
slsa_provenance_config_t slsa_get_default_config(void) {
    slsa_provenance_config_t config = {
        .git_repository = NULL,
        .git_commit_sha = NULL,
        .git_branch = NULL,
        .git_tag = NULL,
        .build_type = NULL,
        .build_timestamp = NULL,
        .build_platform = NULL,
        .builder_identity = NULL,
        .builder_version = NULL,
        .compiler_name = NULL,
        .compiler_version = NULL,
        .openssl_version = NULL,
        .libcurl_version = NULL,
        .build_dependencies = NULL,
        .dependency_count = 0,
        .build_flags = NULL,
        .reproducible = true
    };
    return config;
}

// Get git commit SHA
char* slsa_get_git_commit_sha(void) {
    FILE* pipe = popen("git rev-parse HEAD 2>/dev/null", "r");
    if (!pipe) return NULL;

    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe)) {
        // Remove trailing newline
        buffer[strcspn(buffer, "\n")] = '\0';
        pclose(pipe);
        return strdup(buffer);
    }

    pclose(pipe);
    return NULL;
}

// Get git repository URL
char* slsa_get_git_repository(void) {
    FILE* pipe = popen("git config --get remote.origin.url 2>/dev/null", "r");
    if (!pipe) return NULL;

    char buffer[512];
    if (fgets(buffer, sizeof(buffer), pipe)) {
        buffer[strcspn(buffer, "\n")] = '\0';
        pclose(pipe);
        return strdup(buffer);
    }

    pclose(pipe);
    return NULL;
}

// Get git branch name
char* slsa_get_git_branch(void) {
    FILE* pipe = popen("git rev-parse --abbrev-ref HEAD 2>/dev/null", "r");
    if (!pipe) return NULL;

    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe)) {
        buffer[strcspn(buffer, "\n")] = '\0';
        pclose(pipe);
        return strdup(buffer);
    }

    pclose(pipe);
    return NULL;
}

// Get build timestamp in ISO 8601 format
char* slsa_get_build_timestamp(void) {
    time_t now = time(NULL);
    struct tm* utc_time = gmtime(&now);

    char* timestamp = secure_alloc(32);
    if (!timestamp) return NULL;

    strftime(timestamp, 32, "%Y-%m-%dT%H:%M:%SZ", utc_time);
    return timestamp;
}

// Get build platform (OS + architecture)
char* slsa_get_build_platform(void) {
    struct utsname sys_info;
    if (uname(&sys_info) != 0) {
        return strdup("unknown");
    }

    char* platform = secure_alloc(256);
    if (!platform) return NULL;

    snprintf(platform, 256, "%s/%s", sys_info.sysname, sys_info.machine);
    return platform;
}

// Populate configuration from environment variables and build metadata
int slsa_populate_config_from_env(slsa_provenance_config_t* config) {
    if (!config) return -1;

    // Get git information (may fail if not in git repository)
    config->git_repository = slsa_get_git_repository();
    config->git_commit_sha = slsa_get_git_commit_sha();
    config->git_branch = slsa_get_git_branch();

    // Get environment variables
    const char* ci_system = getenv("CI");
    if (ci_system) {
        config->builder_identity = strdup(ci_system);
    } else {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            config->builder_identity = strdup(hostname);
        }
    }

    // Get build timestamp
    config->build_timestamp = slsa_get_build_timestamp();

    // Get build platform
    config->build_platform = slsa_get_build_platform();

    // Get build-time values from CMake config
#ifdef CBOM_BUILD_TYPE
    config->build_type = strdup(CBOM_BUILD_TYPE);
#endif

#ifdef CBOM_C_COMPILER
    config->compiler_name = strdup(CBOM_C_COMPILER);
#endif

#ifdef CBOM_C_COMPILER_VERSION
    config->compiler_version = strdup(CBOM_C_COMPILER_VERSION);
#endif

#ifdef CBOM_OPENSSL_VERSION
    config->openssl_version = strdup(CBOM_OPENSSL_VERSION);
#endif

#ifdef CBOM_CURL_VERSION
    config->libcurl_version = strdup(CBOM_CURL_VERSION);
#endif

    return 0;
}

// Create SLSA provenance context
slsa_provenance_context_t* slsa_provenance_create(const slsa_provenance_config_t* config) {
    if (!config) return NULL;

    slsa_provenance_context_t* context = secure_alloc(sizeof(slsa_provenance_context_t));
    if (!context) return NULL;

    // Copy configuration
    context->config = *config;

    // Duplicate all string fields
    if (config->git_repository) context->config.git_repository = strdup(config->git_repository);
    if (config->git_commit_sha) context->config.git_commit_sha = strdup(config->git_commit_sha);
    if (config->git_branch) context->config.git_branch = strdup(config->git_branch);
    if (config->git_tag) context->config.git_tag = strdup(config->git_tag);
    if (config->build_type) context->config.build_type = strdup(config->build_type);
    if (config->build_timestamp) context->config.build_timestamp = strdup(config->build_timestamp);
    if (config->build_platform) context->config.build_platform = strdup(config->build_platform);
    if (config->builder_identity) context->config.builder_identity = strdup(config->builder_identity);
    if (config->builder_version) context->config.builder_version = strdup(config->builder_version);
    if (config->compiler_name) context->config.compiler_name = strdup(config->compiler_name);
    if (config->compiler_version) context->config.compiler_version = strdup(config->compiler_version);
    if (config->openssl_version) context->config.openssl_version = strdup(config->openssl_version);
    if (config->libcurl_version) context->config.libcurl_version = strdup(config->libcurl_version);
    if (config->build_flags) context->config.build_flags = strdup(config->build_flags);

    // Copy dependencies array
    if (config->build_dependencies && config->dependency_count > 0) {
        context->config.build_dependencies = secure_alloc(sizeof(char*) * config->dependency_count);
        if (context->config.build_dependencies) {
            for (size_t i = 0; i < config->dependency_count; i++) {
                context->config.build_dependencies[i] = strdup(config->build_dependencies[i]);
            }
        }
    }

    context->generation_time = time(NULL);
    context->initialized = true;

    return context;
}

// Destroy SLSA provenance context
void slsa_provenance_destroy(slsa_provenance_context_t* context) {
    if (!context) return;

    // Free all string fields
    if (context->config.git_repository) free(context->config.git_repository);
    if (context->config.git_commit_sha) free(context->config.git_commit_sha);
    if (context->config.git_branch) free(context->config.git_branch);
    if (context->config.git_tag) free(context->config.git_tag);
    if (context->config.build_type) free(context->config.build_type);
    if (context->config.build_timestamp) free(context->config.build_timestamp);
    if (context->config.build_platform) free(context->config.build_platform);
    if (context->config.builder_identity) free(context->config.builder_identity);
    if (context->config.builder_version) free(context->config.builder_version);
    if (context->config.compiler_name) free(context->config.compiler_name);
    if (context->config.compiler_version) free(context->config.compiler_version);
    if (context->config.openssl_version) free(context->config.openssl_version);
    if (context->config.libcurl_version) free(context->config.libcurl_version);
    if (context->config.build_flags) free(context->config.build_flags);

    // Free dependencies array
    if (context->config.build_dependencies) {
        for (size_t i = 0; i < context->config.dependency_count; i++) {
            if (context->config.build_dependencies[i]) {
                free(context->config.build_dependencies[i]);
            }
        }
        secure_free(context->config.build_dependencies, sizeof(char*) * context->config.dependency_count);
    }

    secure_free(context, sizeof(slsa_provenance_context_t));
}

// Generate SLSA v0.2 provenance as JSON object
json_object* slsa_generate_provenance(slsa_provenance_context_t* context,
                                      const char* cbom_file_path,
                                      const char* cbom_sha256) {
    if (!context || !context->initialized) return NULL;

    json_object* provenance = json_object_new_object();

    // SLSA predicate type (v0.2)
    json_object_object_add(provenance, "_type",
                          json_object_new_string("https://slsa.dev/provenance/v0.2"));

    // Subject (the CBOM being attested)
    json_object* subject = json_object_new_array();
    json_object* subject_item = json_object_new_object();

    json_object_object_add(subject_item, "name",
                          json_object_new_string(cbom_file_path ? cbom_file_path : "cbom.json"));

    // Add digest
    if (cbom_sha256) {
        json_object* digest = json_object_new_object();
        json_object_object_add(digest, "sha256", json_object_new_string(cbom_sha256));
        json_object_object_add(subject_item, "digest", digest);
    }

    json_object_array_add(subject, subject_item);
    json_object_object_add(provenance, "subject", subject);

    // Predicate
    json_object* predicate = json_object_new_object();

    // Builder
    json_object* builder = json_object_new_object();
    if (context->config.builder_identity) {
        json_object_object_add(builder, "id",
                              json_object_new_string(context->config.builder_identity));
    }
    json_object_object_add(predicate, "builder", builder);

    // Build type
    if (context->config.build_type) {
        json_object_object_add(predicate, "buildType",
                              json_object_new_string(context->config.build_type));
    }

    // Invocation
    json_object* invocation = json_object_new_object();
    if (context->config.build_timestamp) {
        json_object_object_add(invocation, "timestamp",
                              json_object_new_string(context->config.build_timestamp));
    }
    if (context->config.build_platform) {
        json_object_object_add(invocation, "platform",
                              json_object_new_string(context->config.build_platform));
    }
    json_object_object_add(predicate, "invocation", invocation);

    // Materials (source and dependencies)
    json_object* materials = json_object_new_array();

    // Git source material
    if (context->config.git_repository && context->config.git_commit_sha) {
        json_object* git_material = json_object_new_object();
        json_object_object_add(git_material, "uri",
                              json_object_new_string(context->config.git_repository));

        json_object* git_digest = json_object_new_object();
        json_object_object_add(git_digest, "gitCommit",
                              json_object_new_string(context->config.git_commit_sha));
        json_object_object_add(git_material, "digest", git_digest);

        json_object_array_add(materials, git_material);
    }

    // Build dependencies
    if (context->config.build_dependencies) {
        for (size_t i = 0; i < context->config.dependency_count; i++) {
            json_object* dep = json_object_new_object();
            json_object_object_add(dep, "uri",
                                  json_object_new_string(context->config.build_dependencies[i]));
            json_object_array_add(materials, dep);
        }
    }

    json_object_object_add(predicate, "materials", materials);

    // Metadata
    json_object* metadata = json_object_new_object();

    // Build started/finished
    if (context->config.build_timestamp) {
        json_object_object_add(metadata, "buildStartedOn",
                              json_object_new_string(context->config.build_timestamp));
        json_object_object_add(metadata, "buildFinishedOn",
                              json_object_new_string(context->config.build_timestamp));
    }

    // Completeness
    json_object* completeness = json_object_new_object();
    json_object_object_add(completeness, "parameters", json_object_new_boolean(true));
    json_object_object_add(completeness, "environment", json_object_new_boolean(true));
    json_object_object_add(completeness, "materials", json_object_new_boolean(true));
    json_object_object_add(metadata, "completeness", completeness);

    // Reproducible
    json_object_object_add(metadata, "reproducible",
                          json_object_new_boolean(context->config.reproducible));

    json_object_object_add(predicate, "metadata", metadata);

    // Add predicate to provenance
    json_object_object_add(provenance, "predicate", predicate);

    return provenance;
}

// Add SLSA provenance to CBOM metadata
int slsa_add_provenance_to_cbom(json_object* cbom, json_object* provenance) {
    if (!cbom || !provenance) return -1;

    json_object* metadata = NULL;
    if (!json_object_object_get_ex(cbom, "metadata", &metadata)) {
        // Create metadata if it doesn't exist
        metadata = json_object_new_object();
        json_object_object_add(cbom, "metadata", metadata);
    }

    // Add provenance to metadata
    json_object_object_add(metadata, "slsa_provenance", json_object_get(provenance));

    return 0;
}
