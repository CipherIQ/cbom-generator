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
 * @file config_parser_registry.c
 * @brief Configuration parser registry implementation
 */

#define _GNU_SOURCE
#include "config_parser.h"
#include "secure_memory.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_PARSERS 16

/**
 * Parser registry structure
 */
typedef struct {
    config_parser_t parsers[MAX_PARSERS];
    int count;
    pthread_mutex_t mutex;
    bool initialized;
} parser_registry_t;

static parser_registry_t g_registry = {0};

int config_parser_registry_init(void) {
    if (g_registry.initialized) {
        return 0;
    }

    memset(&g_registry, 0, sizeof(parser_registry_t));

    if (pthread_mutex_init(&g_registry.mutex, NULL) != 0) {
        return -1;
    }

    g_registry.initialized = true;

    // Register built-in parsers
    config_parser_register_builtins();

    return 0;
}

void config_parser_registry_destroy(void) {
    if (!g_registry.initialized) {
        return;
    }

    pthread_mutex_lock(&g_registry.mutex);

    // Free all registered parsers
    for (int i = 0; i < g_registry.count; i++) {
        free(g_registry.parsers[i].name);
    }

    g_registry.count = 0;
    g_registry.initialized = false;

    pthread_mutex_unlock(&g_registry.mutex);
    pthread_mutex_destroy(&g_registry.mutex);
}

int config_parser_register(
    parser_type_t type,
    const char* name,
    parser_func_t parse_func,
    parser_free_func_t free_func
) {
    if (!g_registry.initialized) {
        return -1;
    }

    if (!name || !parse_func || !free_func) {
        return -1;
    }

    pthread_mutex_lock(&g_registry.mutex);

    // Check if already registered
    for (int i = 0; i < g_registry.count; i++) {
        if (g_registry.parsers[i].type == type) {
            pthread_mutex_unlock(&g_registry.mutex);
            return -1;
        }
    }

    // Check capacity
    if (g_registry.count >= MAX_PARSERS) {
        pthread_mutex_unlock(&g_registry.mutex);
        return -1;
    }

    // Add parser
    config_parser_t* parser = &g_registry.parsers[g_registry.count];
    parser->type = type;
    parser->name = strdup(name);
    parser->parse = parse_func;
    parser->free_func = free_func;

    g_registry.count++;

    pthread_mutex_unlock(&g_registry.mutex);
    return 0;
}

config_parser_t* config_parser_get(parser_type_t type) {
    if (!g_registry.initialized) {
        return NULL;
    }

    pthread_mutex_lock(&g_registry.mutex);

    for (int i = 0; i < g_registry.count; i++) {
        if (g_registry.parsers[i].type == type) {
            config_parser_t* parser = &g_registry.parsers[i];
            pthread_mutex_unlock(&g_registry.mutex);
            return parser;
        }
    }

    pthread_mutex_unlock(&g_registry.mutex);
    return NULL;
}

int config_parser_parse(
    parser_type_t type,
    const char* filepath,
    config_directive_t** directives,
    int* count
) {
    if (!filepath || !directives || !count) {
        return -1;
    }

    config_parser_t* parser = config_parser_get(type);
    if (!parser) {
        return -1;
    }

    return parser->parse(filepath, directives, count, NULL);
}

void config_directive_free(config_directive_t* directive) {
    if (!directive) {
        return;
    }

    free(directive->key);
    free(directive->value);
    free(directive->context);

    directive->key = NULL;
    directive->value = NULL;
    directive->context = NULL;
}

void config_directives_free(config_directive_t* directives, int count) {
    if (!directives) {
        return;
    }

    for (int i = 0; i < count; i++) {
        config_directive_free(&directives[i]);
    }

    free(directives);
}

// Forward declarations for parser registration functions
extern void ini_parser_register(void);
extern void apache_parser_register(void);
extern void nginx_parser_register(void);
extern void yaml_config_parser_register(void);
extern void json_parser_register(void);
extern void openssl_cipher_parser_register(void);

void config_parser_register_builtins(void) {
    // Parsers will register themselves when their modules are loaded
    // This function provides a central place to call all registration functions

    ini_parser_register();
    apache_parser_register();
    nginx_parser_register();
    yaml_config_parser_register();
    json_parser_register();
    openssl_cipher_parser_register();
}
