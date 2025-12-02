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
 * @file config_extractor.c
 * @brief Configuration extraction engine implementation
 */

#define _GNU_SOURCE
#include "config_extractor.h"
#include "config_parser.h"
#include "config_types.h"
#include "variable_expander.h"
#include "path_resolver.h"
#include "plugin_schema.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

int config_extractor_init(void) {
    return config_parser_registry_init();
}

void config_extractor_destroy(void) {
    config_parser_registry_destroy();
}

/**
 * Extract version number from TLS version string
 * Examples: "TLSv1.2" → "1.2", "TLSv1.3" → "1.3", "SSLv3" → "3"
 */
static char* extract_tls_version_number(const char* version_str) {
    if (!version_str) return NULL;

    // Handle TLSv1.2, TLSv1.3 format
    const char* v_pos = strstr(version_str, "TLSv");
    if (v_pos) {
        const char* num_start = v_pos + 4; // Skip "TLSv"
        return strdup(num_start);
    }

    // Handle SSLv3, SSLv2 format
    v_pos = strstr(version_str, "SSLv");
    if (v_pos) {
        const char* num_start = v_pos + 4; // Skip "SSLv"
        return strdup(num_start);
    }

    // Already a version number like "1.2" or "1.3"
    if (strchr(version_str, '.') || isdigit((unsigned char)version_str[0])) {
        return strdup(version_str);
    }

    return NULL;
}

/**
 * Apply directive mapping to crypto config
 */
static int apply_crypto_mapping(
    crypto_config_t* config,
    const crypto_directive_rule_t* rule,
    const config_directive_t* directive,
    const char* config_file
) {
    if (!config || !rule || !directive) {
        return -1;
    }

    const char* maps_to = rule->maps_to;
    const char* value = directive->value;

    if (!maps_to || !value) {
        return 0;
    }

    // Map based on maps_to field
    if (strcmp(maps_to, "certificate.path") == 0) {
        // Resolve path
        char* resolved = path_resolve(value, config_file, NULL);
        if (resolved) {
            config->certificate_paths = realloc(config->certificate_paths,
                (config->certificate_count + 1) * sizeof(char*));
            config->certificate_paths[config->certificate_count++] = resolved;
        }
    }
    else if (strcmp(maps_to, "private_key.path") == 0) {
        char* resolved = path_resolve(value, config_file, NULL);
        if (resolved) {
            config->private_key_paths = realloc(config->private_key_paths,
                (config->private_key_count + 1) * sizeof(char*));
            config->private_key_paths[config->private_key_count++] = resolved;
        }
    }
    else if (strcmp(maps_to, "ca_cert.path") == 0) {
        char* resolved = path_resolve(value, config_file, NULL);
        if (resolved) {
            config->ca_cert_paths = realloc(config->ca_cert_paths,
                (config->ca_cert_count + 1) * sizeof(char*));
            config->ca_cert_paths[config->ca_cert_count++] = resolved;
        }
    }
    else if (strcmp(maps_to, "protocol.min_version") == 0) {
        // Parse space-separated TLS versions (e.g., "TLSv1.2 TLSv1.3")
        char** version_strings = NULL;
        int count = 0;

        if (config_convert_to_string_list(value, ' ', &version_strings, &count) == 0 && count > 0) {
            // Allocate tls_versions array
            config->tls_versions = malloc(count * sizeof(char*));
            if (config->tls_versions) {
                config->tls_version_count = 0;

                // Extract version numbers from each string
                for (int i = 0; i < count; i++) {
                    char* version_num = extract_tls_version_number(version_strings[i]);
                    if (version_num) {
                        config->tls_versions[config->tls_version_count++] = version_num;
                    }
                    free(version_strings[i]);
                }

                // Set min_tls_version to lowest version (backward compatibility)
                if (config->tls_version_count > 0) {
                    free(config->min_tls_version);
                    config->min_tls_version = strdup(config->tls_versions[0]);
                }
            }
            free(version_strings);
        } else {
            // Single version or parse failed - use old behavior
            free(config->min_tls_version);
            config->min_tls_version = strdup(value);
        }
    }
    else if (strcmp(maps_to, "protocol.max_version") == 0) {
        free(config->max_tls_version);
        config->max_tls_version = strdup(value);
    }
    else if (strcmp(maps_to, "service.tls_enabled") == 0) {
        bool bool_value = false;
        if (config_convert_to_bool(value, &bool_value) == 0) {
            config->tls_enabled = bool_value;
        }
    }
    else if (strcmp(maps_to, "service.client_cert_required") == 0) {
        bool bool_value = false;
        if (config_convert_to_bool(value, &bool_value) == 0) {
            config->client_cert_required = bool_value;
        }
    }
    else if (strcmp(maps_to, "service.prefer_server_ciphers") == 0) {
        bool bool_value = false;
        if (config_convert_to_bool(value, &bool_value) == 0) {
            config->prefer_server_ciphers = bool_value;
        }
    }
    else if (strcmp(maps_to, "cipher_suites") == 0) {
        // Parse as string list
        char** items = NULL;
        int count = 0;

        if (config_convert_to_string_list(value, ' ', &items, &count) == 0) {
            // Add to cipher suites
            for (int i = 0; i < count; i++) {
                config->cipher_suites = realloc(config->cipher_suites,
                    (config->cipher_count + 1) * sizeof(char*));
                config->cipher_suites[config->cipher_count++] = items[i];
            }
            free(items); // Free array but not items (transferred to config)
        }
    }

    return 0;
}

crypto_config_t* config_extractor_extract(
    service_instance_t* instance,
    void* plugin_ptr
) {
    if (!instance || !plugin_ptr) {
        return NULL;
    }

    yaml_plugin_t* plugin = (yaml_plugin_t*)plugin_ptr;

    // Allocate crypto config
    crypto_config_t* config = calloc(1, sizeof(crypto_config_t));
    if (!config) {
        return NULL;
    }

    config->extracted_at = time(NULL);

    // Iterate through config extraction rules from plugin
    plugin_config_extraction_t* extraction = &plugin->config_extraction;

    int files_attempted = 0;
    int files_parsed = 0;
    int directives_found = 0;

    for (int i = 0; i < extraction->file_count; i++) {
        config_file_rule_t* file_rule = &extraction->files[i];
        files_attempted++;

        // Substitute variables in path
        char* expanded_path = variable_expand(file_rule->path, instance);
        if (!expanded_path) {
            // Variable expansion failed - likely missing config_dir or other variable
            continue;
        }

        // Parse config file
        config_directive_t* directives = NULL;
        int directive_count = 0;

        int ret = config_parser_parse(
            file_rule->parser_type,
            expanded_path,
            &directives,
            &directive_count
        );

        if (ret != 0) {
            // File doesn't exist or parse failed
            free(expanded_path);
            continue;
        }

        files_parsed++;

        // Store config file path
        if (!config->config_file) {
            config->config_file = strdup(expanded_path);
        }

        // Extract crypto directives according to rules
        for (int j = 0; j < file_rule->directive_count; j++) {
            crypto_directive_rule_t* directive_rule = &file_rule->directives[j];

            // Find matching directive in parsed config
            for (int k = 0; k < directive_count; k++) {
                if (strcmp(directives[k].key, directive_rule->key) == 0) {
                    // Apply mapping
                    apply_crypto_mapping(config, directive_rule,
                                        &directives[k], expanded_path);
                    directives_found++;
                }
            }
        }

        config_directives_free(directives, directive_count);
        free(expanded_path);
    }

    return config;
}

void crypto_config_free(crypto_config_t* config) {
    if (!config) {
        return;
    }

    for (int i = 0; i < config->certificate_count; i++) {
        free(config->certificate_paths[i]);
    }
    free(config->certificate_paths);

    for (int i = 0; i < config->private_key_count; i++) {
        free(config->private_key_paths[i]);
    }
    free(config->private_key_paths);

    for (int i = 0; i < config->ca_cert_count; i++) {
        free(config->ca_cert_paths[i]);
    }
    free(config->ca_cert_paths);

    for (int i = 0; i < config->cipher_count; i++) {
        free(config->cipher_suites[i]);
    }
    free(config->cipher_suites);

    for (int i = 0; i < config->tls_version_count; i++) {
        free(config->tls_versions[i]);
    }
    free(config->tls_versions);

    free(config->min_tls_version);
    free(config->max_tls_version);
    free(config->config_file);

    free(config);
}

void crypto_config_print(const crypto_config_t* config) {
    if (!config) {
        printf("No crypto config\n");
        return;
    }

    printf("Crypto Configuration:\n");
    printf("===================\n");

    if (config->config_file) {
        printf("Config file: %s\n", config->config_file);
    }

    printf("TLS enabled: %s\n", config->tls_enabled ? "yes" : "no");

    if (config->certificate_count > 0) {
        printf("\nCertificates (%d):\n", config->certificate_count);
        for (int i = 0; i < config->certificate_count; i++) {
            printf("  - %s\n", config->certificate_paths[i]);
        }
    }

    if (config->private_key_count > 0) {
        printf("\nPrivate Keys (%d):\n", config->private_key_count);
        for (int i = 0; i < config->private_key_count; i++) {
            printf("  - %s\n", config->private_key_paths[i]);
        }
    }

    if (config->ca_cert_count > 0) {
        printf("\nCA Certificates (%d):\n", config->ca_cert_count);
        for (int i = 0; i < config->ca_cert_count; i++) {
            printf("  - %s\n", config->ca_cert_paths[i]);
        }
    }

    if (config->min_tls_version || config->max_tls_version) {
        printf("\nProtocol:\n");
        if (config->min_tls_version) {
            printf("  Min version: %s\n", config->min_tls_version);
        }
        if (config->max_tls_version) {
            printf("  Max version: %s\n", config->max_tls_version);
        }
    }

    if (config->cipher_count > 0) {
        printf("\nCipher Suites (%d):\n", config->cipher_count);
        for (int i = 0; i < config->cipher_count; i++) {
            printf("  - %s\n", config->cipher_suites[i]);
        }
    }

    printf("\n");
}
