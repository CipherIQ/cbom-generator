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
 * @file config_types.h
 * @brief Configuration value types and type conversion
 *
 * Provides type definitions and conversion functions for config directive values.
 */

#ifndef CONFIG_TYPES_H
#define CONFIG_TYPES_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Configuration value types (from plugin_schema.h)
 */
typedef enum {
    CONFIG_TYPE_STRING,
    CONFIG_TYPE_BOOLEAN,
    CONFIG_TYPE_INTEGER,
    CONFIG_TYPE_PATH,
    CONFIG_TYPE_STRING_LIST
} config_value_type_t;

/**
 * Typed configuration value
 */
typedef struct {
    config_value_type_t type;

    union {
        char* string_value;
        bool bool_value;
        int int_value;
        char* path_value;
        struct {
            char** items;
            int count;
        } list_value;
    } data;
} config_value_t;

/**
 * Convert string to boolean
 * Recognizes: "on", "true", "1", "yes", "enabled" as true
 *
 * @param str String to convert
 * @param value Output: boolean value
 * @return 0 on success, -1 on error
 */
int config_convert_to_bool(const char* str, bool* value);

/**
 * Convert string to integer
 *
 * @param str String to convert
 * @param value Output: integer value
 * @return 0 on success, -1 on error
 */
int config_convert_to_int(const char* str, int* value);

/**
 * Convert string to path (validates existence)
 *
 * @param str String to convert
 * @param value Output: path string (caller must free)
 * @return 0 on success, -1 on error
 */
int config_convert_to_path(const char* str, char** value);

/**
 * Convert string to string list (split by delimiter)
 * Common delimiters: space, comma, colon
 *
 * @param str String to convert
 * @param delimiter Delimiter character (e.g., ',' or ' ')
 * @param items Output: array of strings (caller must free)
 * @param count Output: number of items
 * @return 0 on success, -1 on error
 */
int config_convert_to_string_list(
    const char* str,
    char delimiter,
    char*** items,
    int* count
);

/**
 * Convert string to typed value
 *
 * @param str String to convert
 * @param type Target type
 * @param value Output: typed value (caller must free)
 * @return 0 on success, -1 on error
 */
int config_convert_value(
    const char* str,
    config_value_type_t type,
    config_value_t** value
);

/**
 * Free a typed value
 *
 * @param value Value to free
 */
void config_value_free(config_value_t* value);

/**
 * Free a string list
 *
 * @param items Array of strings
 * @param count Number of items
 */
void config_string_list_free(char** items, int count);

#endif // CONFIG_TYPES_H
