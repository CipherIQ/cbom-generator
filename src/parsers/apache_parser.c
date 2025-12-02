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
 * @file apache_parser.c
 * @brief Apache/httpd configuration file parser (crypto-focused)
 *
 * Parses Apache-style configs focusing on SSL/TLS directives.
 * Handles nested contexts (<VirtualHost>, <Directory>) with context stack.
 * Simplified: no includes, no conditionals, only crypto directives.
 */

#define _GNU_SOURCE
#include "config_parser.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * Context stack for tracking nested blocks
 */
typedef struct {
    char** contexts;
    int depth;
    int capacity;
} context_stack_t;

static context_stack_t* context_stack_create(void) {
    context_stack_t* stack = malloc(sizeof(context_stack_t));
    if (!stack) return NULL;

    stack->contexts = malloc(16 * sizeof(char*));
    if (!stack->contexts) {
        free(stack);
        return NULL;
    }

    stack->depth = 0;
    stack->capacity = 16;
    return stack;
}

static int context_stack_push(context_stack_t* stack, const char* context) {
    if (!stack || !context) return -1;

    if (stack->depth >= stack->capacity) {
        stack->capacity *= 2;
        char** new_contexts = realloc(stack->contexts,
            stack->capacity * sizeof(char*));
        if (!new_contexts) return -1;
        stack->contexts = new_contexts;
    }

    stack->contexts[stack->depth++] = strdup(context);
    return 0;
}

static void context_stack_pop(context_stack_t* stack) {
    if (!stack || stack->depth <= 0) return;
    free(stack->contexts[--stack->depth]);
}

static char* context_stack_to_string(context_stack_t* stack) {
    if (!stack || stack->depth == 0) return NULL;

    size_t total_len = 0;
    for (int i = 0; i < stack->depth; i++) {
        total_len += strlen(stack->contexts[i]) + 1; // +1 for '/'
    }

    char* result = malloc(total_len + 1);
    if (!result) return NULL;

    result[0] = '\0';

    for (int i = 0; i < stack->depth; i++) {
        if (i > 0) strcat(result, "/");
        strcat(result, stack->contexts[i]);
    }

    return result;
}

static void context_stack_destroy(context_stack_t* stack) {
    if (!stack) return;

    for (int i = 0; i < stack->depth; i++) {
        free(stack->contexts[i]);
    }
    free(stack->contexts);
    free(stack);
}

/**
 * Check if directive is crypto-related
 * Only parse SSL*, TLS*, Certificate*, Cipher* directives
 */
static bool is_crypto_directive(const char* key) {
    if (!key) return false;

    return (strncasecmp(key, "SSL", 3) == 0 ||
            strncasecmp(key, "TLS", 3) == 0 ||
            strncasecmp(key, "Certificate", 11) == 0 ||
            strncasecmp(key, "Cipher", 6) == 0);
}

/**
 * Trim leading and trailing whitespace (in-place)
 */
static void trim_inplace(char* str) {
    if (!str) return;

    // Trim leading whitespace
    char* src = str;
    while (isspace((unsigned char)*src)) src++;

    if (src != str) {
        memmove(str, src, strlen(src) + 1);
    }

    // Trim trailing whitespace
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

/**
 * Parse Apache config file
 */
int apache_parser_parse(
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
    int capacity = 64;
    int size = 0;

    result = malloc(capacity * sizeof(config_directive_t));
    if (!result) {
        fclose(fp);
        return -1;
    }

    context_stack_t* stack = context_stack_create();
    if (!stack) {
        free(result);
        fclose(fp);
        return -1;
    }

    char line[4096];
    int line_number = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_number++;

        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';

        // Trim whitespace
        trim_inplace(line);

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        // Check for context open: <VirtualHost *:443>
        if (line[0] == '<' && line[1] != '/') {
            char* close = strchr(line, '>');
            if (close) {
                *close = '\0';
                context_stack_push(stack, line + 1);
            }
            continue;
        }

        // Check for context close: </VirtualHost>
        if (line[0] == '<' && line[1] == '/') {
            context_stack_pop(stack);
            continue;
        }

        // Parse directive: key value [value...]
        char* space = strchr(line, ' ');
        if (!space) {
            space = strchr(line, '\t');
        }

        if (space) {
            // Extract key
            *space = '\0';
            char* key = line;

            // Only process crypto directives
            if (!is_crypto_directive(key)) {
                continue;
            }

            // Extract value (rest of line)
            char* value = space + 1;
            while (isspace((unsigned char)*value)) value++;

            // Remove quotes if present
            if (*value == '"') {
                value++;
                char* end_quote = strchr(value, '"');
                if (end_quote) *end_quote = '\0';
            }

            // Resize if needed
            if (size >= capacity) {
                capacity *= 2;
                config_directive_t* new_result = realloc(result,
                    capacity * sizeof(config_directive_t));
                if (!new_result) {
                    config_directives_free(result, size);
                    context_stack_destroy(stack);
                    fclose(fp);
                    return -1;
                }
                result = new_result;
            }

            // Store directive
            result[size].key = strdup(key);
            result[size].value = strdup(value);
            result[size].context = context_stack_to_string(stack);
            result[size].line_number = line_number;
            size++;
        }
    }

    context_stack_destroy(stack);
    fclose(fp);

    *directives = result;
    *count = size;
    return 0;
}

/**
 * Register Apache parser
 */
void apache_parser_register(void) {
    config_parser_register(
        PARSER_TYPE_APACHE,
        "apache",
        apache_parser_parse,
        config_directives_free
    );
}
