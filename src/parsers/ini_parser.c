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
 * @file ini_parser.c
 * @brief INI-style configuration file parser
 *
 * Parses INI files with sections, key=value pairs, and comments.
 * Used for PostgreSQL, MySQL, Redis configurations.
 */

#define _GNU_SOURCE
#include "config_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * Trim leading and trailing whitespace from a string (in-place)
 */
static char* trim(char* str) {
    if (!str) return NULL;

    // Trim leading whitespace
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') return str;

    // Trim trailing whitespace
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    *(end + 1) = '\0';
    return str;
}

/**
 * Remove quotes from a string if present
 */
static char* unquote(char* str) {
    if (!str || strlen(str) < 2) return str;

    size_t len = strlen(str);

    // Check for matching quotes
    if ((str[0] == '"' && str[len - 1] == '"') ||
        (str[0] == '\'' && str[len - 1] == '\'')) {
        str[len - 1] = '\0';
        return str + 1;
    }

    return str;
}

/**
 * Parse INI file
 *
 * Format:
 *   [section]
 *   key = value
 *   key value
 *   # comment
 *   ; comment
 */
int ini_parser_parse(
    const char* filepath,
    config_directive_t** directives,
    int* count,
    void* context
) {
    (void)context; // Unused

    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        return -1;
    }

    config_directive_t* result = NULL;
    int capacity = 32;
    int size = 0;

    result = malloc(capacity * sizeof(config_directive_t));
    if (!result) {
        fclose(fp);
        return -1;
    }

    char line[4096];
    char current_section[256] = "";
    int line_number = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_number++;

        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';

        // Trim whitespace
        char* trimmed = trim(line);

        // Skip empty lines and comments
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }

        // Check for section header [section]
        if (*trimmed == '[') {
            char* end = strchr(trimmed, ']');
            if (end) {
                size_t len = end - trimmed - 1;
                if (len < sizeof(current_section)) {
                    strncpy(current_section, trimmed + 1, len);
                    current_section[len] = '\0';
                }
                continue;
            }
        }

        // Parse key=value or key value
        char* separator = strchr(trimmed, '=');
        if (!separator) {
            // Try space-separated (key value)
            separator = strchr(trimmed, ' ');
            if (!separator) {
                separator = strchr(trimmed, '\t');
            }
        }

        if (separator) {
            // Extract key
            size_t key_len = separator - trimmed;
            char* key = malloc(key_len + 1);
            if (!key) {
                // Cleanup and return error
                config_directives_free(result, size);
                fclose(fp);
                return -1;
            }

            strncpy(key, trimmed, key_len);
            key[key_len] = '\0';
            key = trim(key);

            // Extract value
            char* value_start = separator + 1;
            while (isspace((unsigned char)*value_start)) value_start++;

            // Remove quotes if present
            value_start = unquote(value_start);

            // Resize array if needed
            if (size >= capacity) {
                capacity *= 2;
                config_directive_t* new_result = realloc(result,
                    capacity * sizeof(config_directive_t));
                if (!new_result) {
                    free(key);
                    config_directives_free(result, size);
                    fclose(fp);
                    return -1;
                }
                result = new_result;
            }

            // Store directive
            result[size].key = strdup(key);
            result[size].value = strdup(value_start);
            result[size].context = current_section[0] ? strdup(current_section) : NULL;
            result[size].line_number = line_number;

            free(key);
            size++;
        }
    }

    fclose(fp);

    *directives = result;
    *count = size;
    return 0;
}

/**
 * Register INI parser
 */
void ini_parser_register(void) {
    config_parser_register(
        PARSER_TYPE_INI,
        "ini",
        ini_parser_parse,
        config_directives_free
    );
}
