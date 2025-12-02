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
 * @file yaml_config_parser.c
 * @brief YAML configuration file parser
 *
 * Parses YAML config files and flattens them to key-value directives.
 * Reuses the YAML parser from Phase 1.
 * Uses dot notation for nested keys (e.g., "server.tls.cert").
 */

#define _GNU_SOURCE
#include "config_parser.h"
#include "yaml_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Helper to flatten YAML node recursively
 */
static int flatten_yaml_node(
    yaml_doc_t* doc,
    yaml_node_t* node,
    const char* prefix,
    config_directive_t** directives,
    int* count,
    int* capacity
) {
    if (!node || !doc) return 0;

    if (yaml_is_scalar(node)) {
        // Leaf node: store as directive
        if (*count >= *capacity) {
            *capacity *= 2;
            config_directive_t* new_dirs = realloc(*directives,
                *capacity * sizeof(config_directive_t));
            if (!new_dirs) return -1;
            *directives = new_dirs;
        }

        const char* value = yaml_get_string(doc, node);
        if (!value) value = "";

        (*directives)[*count].key = prefix ? strdup(prefix) : strdup("");
        (*directives)[*count].value = strdup(value);
        (*directives)[*count].context = NULL;
        (*directives)[*count].line_number = 0;
        (*count)++;

        return 0;
    }

    if (yaml_is_mapping(node)) {
        // Map node: iterate through key-value pairs
        int key_count = 0;
        const char** keys = yaml_get_mapping_keys(doc, node, &key_count);

        if (keys) {
            for (int i = 0; i < key_count; i++) {
                const char* key = keys[i];

                // Build new prefix: "prefix.key"
                char new_prefix[512];
                if (prefix && prefix[0]) {
                    snprintf(new_prefix, sizeof(new_prefix), "%s.%s", prefix, key);
                } else {
                    snprintf(new_prefix, sizeof(new_prefix), "%s", key);
                }

                // Get value for this key
                yaml_node_t* value_node = yaml_get_mapping_value(doc, node, key);
                if (value_node) {
                    // Recursively flatten value
                    if (flatten_yaml_node(doc, value_node, new_prefix,
                                          directives, count, capacity) < 0) {
                        free((void*)keys);
                        return -1;
                    }
                }
            }
            free((void*)keys);
        }

        return 0;
    }

    if (yaml_is_sequence(node)) {
        // Sequence node: get items and store as comma-separated list
        int item_count = 0;
        yaml_node_t** items = yaml_get_array(doc, node, &item_count);

        if (items && item_count > 0) {
            char value[4096] = "";
            bool first = true;

            for (int i = 0; i < item_count; i++) {
                if (yaml_is_scalar(items[i])) {
                    const char* item_value = yaml_get_string(doc, items[i]);
                    if (item_value) {
                        if (!first) strcat(value, ",");
                        strcat(value, item_value);
                        first = false;
                    }
                }
            }

            if (value[0]) {
                if (*count >= *capacity) {
                    *capacity *= 2;
                    config_directive_t* new_dirs = realloc(*directives,
                        *capacity * sizeof(config_directive_t));
                    if (!new_dirs) {
                        free(items);
                        return -1;
                    }
                    *directives = new_dirs;
                }

                (*directives)[*count].key = prefix ? strdup(prefix) : strdup("");
                (*directives)[*count].value = strdup(value);
                (*directives)[*count].context = NULL;
                (*directives)[*count].line_number = 0;
                (*count)++;
            }

            free(items);
        }

        return 0;
    }

    return 0;
}

/**
 * Parse YAML config file
 */
int yaml_config_parser_parse(
    const char* filepath,
    config_directive_t** directives,
    int* count,
    void* context
) {
    (void)context; // Unused

    // Load YAML document using Phase 1 parser
    yaml_doc_t* doc = yaml_load_file(filepath);
    if (!doc || !doc->is_valid) {
        if (doc) yaml_free(doc);
        return -1;
    }

    // Allocate initial directive array
    int capacity = 32;
    config_directive_t* result = malloc(capacity * sizeof(config_directive_t));
    if (!result) {
        yaml_free(doc);
        return -1;
    }

    int size = 0;

    // Get root node
    yaml_node_t* root = yaml_document_get_root_node(&doc->document);
    if (!root) {
        free(result);
        yaml_free(doc);
        return -1;
    }

    // Flatten YAML tree to directives
    if (flatten_yaml_node(doc, root, NULL, &result, &size, &capacity) < 0) {
        config_directives_free(result, size);
        yaml_free(doc);
        return -1;
    }

    yaml_free(doc);

    *directives = result;
    *count = size;
    return 0;
}

/**
 * Register YAML config parser
 */
void yaml_config_parser_register(void) {
    config_parser_register(
        PARSER_TYPE_YAML,
        "yaml",
        yaml_config_parser_parse,
        config_directives_free
    );
}
