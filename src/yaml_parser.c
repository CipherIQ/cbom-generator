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
 * @file yaml_parser.c
 * @brief Safe YAML parser wrapper implementation
 *
 * Provides safe wrappers around libyaml with error handling, size limits,
 * and TUI-aware logging.
 */

#define _GNU_SOURCE
#include "yaml_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>

/* Forward declarations */
extern int g_output_mode;  /* From main.c/tui.h */
#define OUTPUT_MODE_TUI 1

/**
 * TUI-aware logging - suppress output when TUI is active
 */
static void log_printf(const char* format, ...) {
    if (g_output_mode == OUTPUT_MODE_TUI) {
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
}

/**
 * Check file size and validate it's within limits
 */
static bool check_file_size(const char* filepath, size_t* size_out) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        log_printf("ERROR: Cannot stat file '%s': %s\n", filepath, strerror(errno));
        return false;
    }

    if (!S_ISREG(st.st_mode)) {
        log_printf("ERROR: '%s' is not a regular file\n", filepath);
        return false;
    }

    if ((size_t)st.st_size > YAML_MAX_FILE_SIZE) {
        log_printf("ERROR: File '%s' exceeds maximum size (%zu > %d bytes)\n",
                   filepath, (size_t)st.st_size, YAML_MAX_FILE_SIZE);
        return false;
    }

    if (size_out) {
        *size_out = (size_t)st.st_size;
    }

    return true;
}

yaml_doc_t* yaml_load_file(const char* filepath) {
    if (!filepath) {
        log_printf("ERROR: NULL filepath provided to yaml_load_file\n");
        return NULL;
    }

    /* Check file size first */
    size_t file_size = 0;
    if (!check_file_size(filepath, &file_size)) {
        return NULL;
    }

    /* Open file */
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        log_printf("ERROR: Cannot open YAML file '%s': %s\n", filepath, strerror(errno));
        return NULL;
    }

    /* Allocate document structure */
    yaml_doc_t* doc = calloc(1, sizeof(yaml_doc_t));
    if (!doc) {
        log_printf("ERROR: Failed to allocate memory for YAML document\n");
        fclose(file);
        return NULL;
    }

    doc->filepath = strdup(filepath);
    doc->file_size = file_size;
    doc->is_valid = false;

    /* Initialize parser */
    if (!yaml_parser_initialize(&doc->parser)) {
        log_printf("ERROR: Failed to initialize YAML parser\n");
        free(doc->filepath);
        free(doc);
        fclose(file);
        return NULL;
    }

    /* Set input file */
    yaml_parser_set_input_file(&doc->parser, file);

    /* Load document */
    if (!yaml_parser_load(&doc->parser, &doc->document)) {
        log_printf("ERROR: Failed to parse YAML file '%s': %s at line %zu, column %zu\n",
                   filepath,
                   doc->parser.problem ? doc->parser.problem : "unknown error",
                   doc->parser.problem_mark.line + 1,
                   doc->parser.problem_mark.column + 1);
        yaml_parser_delete(&doc->parser);
        free(doc->filepath);
        free(doc);
        fclose(file);
        return NULL;
    }

    fclose(file);
    doc->is_valid = true;

    return doc;
}

yaml_node_t* yaml_get_node(yaml_doc_t* doc, const char* path) {
    if (!doc || !doc->is_valid || !path) {
        return NULL;
    }

    /* Get root node */
    yaml_node_t* node = yaml_document_get_root_node(&doc->document);
    if (!node) {
        return NULL;
    }

    /* Parse path (e.g., "plugin.name") */
    char* path_copy = strdup(path);
    if (!path_copy) {
        return NULL;
    }

    char* token = strtok(path_copy, ".");
    while (token && node) {
        if (node->type != YAML_MAPPING_NODE) {
            free(path_copy);
            return NULL;
        }

        /* Search for key in mapping */
        yaml_node_t* found = NULL;
        for (yaml_node_pair_t* pair = node->data.mapping.pairs.start;
             pair < node->data.mapping.pairs.top; pair++) {

            yaml_node_t* key_node = yaml_document_get_node(&doc->document, pair->key);
            if (key_node && key_node->type == YAML_SCALAR_NODE) {
                const char* key_value = (const char*)key_node->data.scalar.value;
                if (strcmp(key_value, token) == 0) {
                    found = yaml_document_get_node(&doc->document, pair->value);
                    break;
                }
            }
        }

        node = found;
        token = strtok(NULL, ".");
    }

    free(path_copy);
    return node;
}

const char* yaml_get_string(yaml_doc_t* doc, yaml_node_t* node) {
    if (!doc || !node || node->type != YAML_SCALAR_NODE) {
        return NULL;
    }

    return (const char*)node->data.scalar.value;
}

bool yaml_get_int(yaml_doc_t* doc, yaml_node_t* node, int* value) {
    if (!doc || !node || !value || node->type != YAML_SCALAR_NODE) {
        return false;
    }

    const char* str = (const char*)node->data.scalar.value;
    char* endptr = NULL;
    long val = strtol(str, &endptr, 10);

    if (endptr == str || *endptr != '\0') {
        return false;  /* Not a valid integer */
    }

    *value = (int)val;
    return true;
}

bool yaml_get_bool(yaml_doc_t* doc, yaml_node_t* node, bool* value) {
    if (!doc || !node || !value || node->type != YAML_SCALAR_NODE) {
        return false;
    }

    const char* str = (const char*)node->data.scalar.value;

    /* Recognize common boolean values (case-insensitive) */
    if (strcasecmp(str, "true") == 0 || strcasecmp(str, "yes") == 0 ||
        strcasecmp(str, "on") == 0 || strcmp(str, "1") == 0) {
        *value = true;
        return true;
    }

    if (strcasecmp(str, "false") == 0 || strcasecmp(str, "no") == 0 ||
        strcasecmp(str, "off") == 0 || strcmp(str, "0") == 0) {
        *value = false;
        return true;
    }

    return false;  /* Not a recognized boolean value */
}

yaml_node_t** yaml_get_array(yaml_doc_t* doc, yaml_node_t* node, int* count) {
    if (!doc || !node || !count) {
        return NULL;
    }

    if (node->type != YAML_SEQUENCE_NODE) {
        return NULL;
    }

    /* Count items */
    int item_count = 0;
    for (yaml_node_item_t* item = node->data.sequence.items.start;
         item < node->data.sequence.items.top; item++) {
        item_count++;
    }

    if (item_count == 0) {
        *count = 0;
        return NULL;
    }

    /* Allocate array */
    yaml_node_t** array = calloc(item_count, sizeof(yaml_node_t*));
    if (!array) {
        return NULL;
    }

    /* Fill array */
    int i = 0;
    for (yaml_node_item_t* item = node->data.sequence.items.start;
         item < node->data.sequence.items.top; item++) {
        array[i++] = yaml_document_get_node(&doc->document, *item);
    }

    *count = item_count;
    return array;
}

yaml_node_t* yaml_get_mapping_value(yaml_doc_t* doc, yaml_node_t* node, const char* key) {
    if (!doc || !node || !key || node->type != YAML_MAPPING_NODE) {
        return NULL;
    }

    for (yaml_node_pair_t* pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {

        yaml_node_t* key_node = yaml_document_get_node(&doc->document, pair->key);
        if (key_node && key_node->type == YAML_SCALAR_NODE) {
            const char* key_value = (const char*)key_node->data.scalar.value;
            if (strcmp(key_value, key) == 0) {
                return yaml_document_get_node(&doc->document, pair->value);
            }
        }
    }

    return NULL;
}

const char** yaml_get_mapping_keys(yaml_doc_t* doc, yaml_node_t* node, int* count) {
    if (!doc || !node || !count || node->type != YAML_MAPPING_NODE) {
        return NULL;
    }

    /* Count keys */
    int key_count = 0;
    for (yaml_node_pair_t* pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {
        key_count++;
    }

    if (key_count == 0) {
        *count = 0;
        return NULL;
    }

    /* Allocate array */
    const char** keys = calloc(key_count, sizeof(const char*));
    if (!keys) {
        return NULL;
    }

    /* Fill array */
    int i = 0;
    for (yaml_node_pair_t* pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {

        yaml_node_t* key_node = yaml_document_get_node(&doc->document, pair->key);
        if (key_node && key_node->type == YAML_SCALAR_NODE) {
            keys[i++] = (const char*)key_node->data.scalar.value;
        }
    }

    *count = key_count;
    return keys;
}

bool yaml_is_scalar(yaml_node_t* node) {
    return node && node->type == YAML_SCALAR_NODE;
}

bool yaml_is_sequence(yaml_node_t* node) {
    return node && node->type == YAML_SEQUENCE_NODE;
}

bool yaml_is_mapping(yaml_node_t* node) {
    return node && node->type == YAML_MAPPING_NODE;
}

const char* yaml_node_type_string(yaml_node_t* node) {
    if (!node) {
        return "null";
    }

    switch (node->type) {
        case YAML_SCALAR_NODE:
            return "scalar";
        case YAML_SEQUENCE_NODE:
            return "sequence";
        case YAML_MAPPING_NODE:
            return "mapping";
        default:
            return "unknown";
    }
}

void yaml_free(yaml_doc_t* doc) {
    if (!doc) {
        return;
    }

    if (doc->is_valid) {
        yaml_document_delete(&doc->document);
    }

    yaml_parser_delete(&doc->parser);
    free(doc->filepath);
    free(doc);
}

bool yaml_validate_file(const char* filepath) {
    yaml_doc_t* doc = yaml_load_file(filepath);
    if (!doc) {
        return false;
    }

    bool valid = doc->is_valid;
    yaml_free(doc);
    return valid;
}

const char* yaml_get_error(yaml_doc_t* doc) {
    if (!doc) {
        return "Document is NULL";
    }

    if (doc->parser.error != YAML_NO_ERROR) {
        return doc->parser.problem ? doc->parser.problem : "Unknown YAML parser error";
    }

    return NULL;
}
