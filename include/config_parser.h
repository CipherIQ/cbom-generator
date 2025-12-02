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
 * @file config_parser.h
 * @brief Configuration file parser framework
 *
 * Provides a registry-based system for parsing various configuration
 * file formats (INI, Apache, Nginx, YAML, JSON, OpenSSL cipher strings).
 *
 * Phase 3 of v1.3 Plugin Architecture
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "plugin_schema.h"
#include <stdbool.h>
#include <stddef.h>

/**
 * Configuration directive extracted from a config file
 * Represents a single key-value pair with context information
 */
typedef struct {
    char* key;              /**< Directive name (e.g., "ssl_cert_file") */
    char* value;            /**< Directive value (e.g., "/etc/ssl/cert.pem") */
    char* context;          /**< Context where found (e.g., "server", "VirtualHost") */
    int line_number;        /**< Line number in config file */
} config_directive_t;

/**
 * Parser function signature
 *
 * @param filepath Path to config file to parse
 * @param directives Output: array of directives (caller must free)
 * @param count Output: number of directives in array
 * @param context Optional parser-specific context data
 * @return 0 on success, -1 on error
 */
typedef int (*parser_func_t)(
    const char* filepath,
    config_directive_t** directives,
    int* count,
    void* context
);

/**
 * Directive free function signature
 *
 * @param directives Array of directives to free
 * @param count Number of directives
 */
typedef void (*parser_free_func_t)(
    config_directive_t* directives,
    int count
);

/**
 * Registered parser entry
 */
typedef struct {
    parser_type_t type;           /**< Parser type enum */
    char* name;                   /**< Parser name (e.g., "ini") */
    parser_func_t parse;          /**< Parse function */
    parser_free_func_t free_func; /**< Free function */
} config_parser_t;

/**
 * Initialize the parser registry
 * Must be called before using any parser functions
 *
 * @return 0 on success, -1 on error
 */
int config_parser_registry_init(void);

/**
 * Destroy the parser registry
 * Frees all registered parsers
 */
void config_parser_registry_destroy(void);

/**
 * Register a config file parser
 *
 * @param type Parser type
 * @param name Parser name
 * @param parse_func Parse function
 * @param free_func Free function
 * @return 0 on success, -1 on error
 */
int config_parser_register(
    parser_type_t type,
    const char* name,
    parser_func_t parse_func,
    parser_free_func_t free_func
);

/**
 * Get a registered parser by type
 *
 * @param type Parser type
 * @return Parser or NULL if not found
 */
config_parser_t* config_parser_get(parser_type_t type);

/**
 * Parse a config file using the appropriate parser
 *
 * @param type Parser type to use
 * @param filepath Path to config file
 * @param directives Output: array of directives
 * @param count Output: number of directives
 * @return 0 on success, -1 on error
 */
int config_parser_parse(
    parser_type_t type,
    const char* filepath,
    config_directive_t** directives,
    int* count
);

/**
 * Free a single directive
 *
 * @param directive Directive to free
 */
void config_directive_free(config_directive_t* directive);

/**
 * Free an array of directives
 *
 * @param directives Array to free
 * @param count Number of directives
 */
void config_directives_free(config_directive_t* directives, int count);

/**
 * Register all built-in parsers
 * Called by config_parser_registry_init()
 */
void config_parser_register_builtins(void);

#endif // CONFIG_PARSER_H
