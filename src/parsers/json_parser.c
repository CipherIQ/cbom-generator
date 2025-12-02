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
 * @file json_parser.c
 * @brief JSON configuration file parser
 *
 * Parses JSON config files and flattens them to key-value directives.
 * Uses jansson library for JSON parsing.
 * Uses dot notation for nested keys (e.g., "server.tls.cert").
 */

#define _GNU_SOURCE
#include "config_parser.h"
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Helper to flatten JSON object recursively
 */
static int flatten_json_value(
    json_t* value,
    const char* prefix,
    config_directive_t** directives,
    int* count,
    int* capacity
) {
    if (!value) return 0;

    if (json_is_string(value)) {
        // String value: store as directive
        if (*count >= *capacity) {
            *capacity *= 2;
            config_directive_t* new_dirs = realloc(*directives,
                *capacity * sizeof(config_directive_t));
            if (!new_dirs) return -1;
            *directives = new_dirs;
        }

        (*directives)[*count].key = prefix ? strdup(prefix) : strdup("");
        (*directives)[*count].value = strdup(json_string_value(value));
        (*directives)[*count].context = NULL;
        (*directives)[*count].line_number = 0;
        (*count)++;

        return 0;
    }

    if (json_is_integer(value)) {
        // Integer value: convert to string
        if (*count >= *capacity) {
            *capacity *= 2;
            config_directive_t* new_dirs = realloc(*directives,
                *capacity * sizeof(config_directive_t));
            if (!new_dirs) return -1;
            *directives = new_dirs;
        }

        char int_str[32];
        snprintf(int_str, sizeof(int_str), "%lld",
                 (long long)json_integer_value(value));

        (*directives)[*count].key = prefix ? strdup(prefix) : strdup("");
        (*directives)[*count].value = strdup(int_str);
        (*directives)[*count].context = NULL;
        (*directives)[*count].line_number = 0;
        (*count)++;

        return 0;
    }

    if (json_is_boolean(value)) {
        // Boolean value: convert to string
        if (*count >= *capacity) {
            *capacity *= 2;
            config_directive_t* new_dirs = realloc(*directives,
                *capacity * sizeof(config_directive_t));
            if (!new_dirs) return -1;
            *directives = new_dirs;
        }

        (*directives)[*count].key = prefix ? strdup(prefix) : strdup("");
        (*directives)[*count].value = strdup(json_is_true(value) ? "true" : "false");
        (*directives)[*count].context = NULL;
        (*directives)[*count].line_number = 0;
        (*count)++;

        return 0;
    }

    if (json_is_object(value)) {
        // Object: iterate through key-value pairs
        const char* key;
        json_t* val;

        json_object_foreach(value, key, val) {
            // Build new prefix: "prefix.key"
            char new_prefix[512];
            if (prefix && prefix[0]) {
                snprintf(new_prefix, sizeof(new_prefix), "%s.%s", prefix, key);
            } else {
                snprintf(new_prefix, sizeof(new_prefix), "%s", key);
            }

            // Recursively flatten value
            if (flatten_json_value(val, new_prefix, directives, count, capacity) < 0) {
                return -1;
            }
        }

        return 0;
    }

    if (json_is_array(value)) {
        // Array: store as comma-separated list
        char list[4096] = "";
        bool first = true;

        size_t index;
        json_t* element;

        json_array_foreach(value, index, element) {
            if (json_is_string(element)) {
                if (!first) strcat(list, ",");
                strcat(list, json_string_value(element));
                first = false;
            } else if (json_is_integer(element)) {
                char int_str[32];
                snprintf(int_str, sizeof(int_str), "%lld",
                         (long long)json_integer_value(element));
                if (!first) strcat(list, ",");
                strcat(list, int_str);
                first = false;
            }
        }

        if (list[0]) {
            if (*count >= *capacity) {
                *capacity *= 2;
                config_directive_t* new_dirs = realloc(*directives,
                    *capacity * sizeof(config_directive_t));
                if (!new_dirs) return -1;
                *directives = new_dirs;
            }

            (*directives)[*count].key = prefix ? strdup(prefix) : strdup("");
            (*directives)[*count].value = strdup(list);
            (*directives)[*count].context = NULL;
            (*directives)[*count].line_number = 0;
            (*count)++;
        }

        return 0;
    }

    return 0;
}

/**
 * Parse JSON config file
 */
int json_parser_parse(
    const char* filepath,
    config_directive_t** directives,
    int* count,
    void* context
) {
    (void)context; // Unused

    // Load JSON file
    json_error_t error;
    json_t* root = json_load_file(filepath, 0, &error);
    if (!root) {
        return -1;
    }

    // Allocate initial directive array
    int capacity = 32;
    config_directive_t* result = malloc(capacity * sizeof(config_directive_t));
    if (!result) {
        json_decref(root);
        return -1;
    }

    int size = 0;

    // Flatten JSON to directives
    if (flatten_json_value(root, NULL, &result, &size, &capacity) < 0) {
        config_directives_free(result, size);
        json_decref(root);
        return -1;
    }

    json_decref(root);

    *directives = result;
    *count = size;
    return 0;
}

/**
 * Register JSON parser
 */
void json_parser_register(void) {
    config_parser_register(
        PARSER_TYPE_JSON,
        "json",
        json_parser_parse,
        config_directives_free
    );
}
