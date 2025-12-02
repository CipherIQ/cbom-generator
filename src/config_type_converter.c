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
 * @file config_type_converter.c
 * @brief Configuration type conversion implementation
 */

#define _GNU_SOURCE
#include "config_types.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>

int config_convert_to_bool(const char* str, bool* value) {
    if (!str || !value) {
        return -1;
    }

    // Normalize to lowercase for comparison
    char* lower = strdup(str);
    if (!lower) return -1;

    for (char* p = lower; *p; p++) {
        *p = tolower((unsigned char)*p);
    }

    // Check for true values
    if (strcmp(lower, "on") == 0 ||
        strcmp(lower, "true") == 0 ||
        strcmp(lower, "1") == 0 ||
        strcmp(lower, "yes") == 0 ||
        strcmp(lower, "enabled") == 0) {
        *value = true;
        free(lower);
        return 0;
    }

    // Check for false values
    if (strcmp(lower, "off") == 0 ||
        strcmp(lower, "false") == 0 ||
        strcmp(lower, "0") == 0 ||
        strcmp(lower, "no") == 0 ||
        strcmp(lower, "disabled") == 0) {
        *value = false;
        free(lower);
        return 0;
    }

    free(lower);
    return -1;
}

int config_convert_to_int(const char* str, int* value) {
    if (!str || !value) {
        return -1;
    }

    char* endptr;
    long result = strtol(str, &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0') {
        return -1;
    }

    *value = (int)result;
    return 0;
}

int config_convert_to_path(const char* str, char** value) {
    if (!str || !value) {
        return -1;
    }

    // Check if path exists
    struct stat st;
    if (stat(str, &st) != 0) {
        // Path doesn't exist - still return it but caller should validate
        *value = strdup(str);
        return 0;
    }

    // Path exists - return it
    *value = strdup(str);
    return 0;
}

int config_convert_to_string_list(
    const char* str,
    char delimiter,
    char*** items,
    int* count
) {
    if (!str || !items || !count) {
        return -1;
    }

    // Count delimiter occurrences to estimate array size
    int capacity = 16;
    char** result = malloc(capacity * sizeof(char*));
    if (!result) {
        return -1;
    }

    int size = 0;
    const char* start = str;
    const char* end;

    while (*start) {
        // Skip leading whitespace
        while (isspace((unsigned char)*start)) start++;

        if (*start == '\0') break;

        // Find next delimiter
        end = strchr(start, delimiter);
        if (!end) {
            end = start + strlen(start);
        }

        // Extract token
        size_t len = end - start;
        char* token = malloc(len + 1);
        if (!token) {
            config_string_list_free(result, size);
            return -1;
        }

        strncpy(token, start, len);
        token[len] = '\0';

        // Trim trailing whitespace
        char* trim_end = token + len - 1;
        while (trim_end > token && isspace((unsigned char)*trim_end)) {
            *trim_end = '\0';
            trim_end--;
        }

        // Resize if needed
        if (size >= capacity) {
            capacity *= 2;
            char** new_result = realloc(result, capacity * sizeof(char*));
            if (!new_result) {
                free(token);
                config_string_list_free(result, size);
                return -1;
            }
            result = new_result;
        }

        result[size++] = token;

        // Move to next token
        start = (*end == '\0') ? end : end + 1;
    }

    *items = result;
    *count = size;
    return 0;
}

int config_convert_value(
    const char* str,
    config_value_type_t type,
    config_value_t** value
) {
    if (!str || !value) {
        return -1;
    }

    config_value_t* result = malloc(sizeof(config_value_t));
    if (!result) {
        return -1;
    }

    result->type = type;

    switch (type) {
        case CONFIG_TYPE_STRING:
            result->data.string_value = strdup(str);
            if (!result->data.string_value) {
                free(result);
                return -1;
            }
            break;

        case CONFIG_TYPE_BOOLEAN:
            if (config_convert_to_bool(str, &result->data.bool_value) < 0) {
                free(result);
                return -1;
            }
            break;

        case CONFIG_TYPE_INTEGER:
            if (config_convert_to_int(str, &result->data.int_value) < 0) {
                free(result);
                return -1;
            }
            break;

        case CONFIG_TYPE_PATH:
            if (config_convert_to_path(str, &result->data.path_value) < 0) {
                free(result);
                return -1;
            }
            break;

        case CONFIG_TYPE_STRING_LIST:
            // Try space delimiter first, then comma
            if (strchr(str, ',')) {
                if (config_convert_to_string_list(str, ',',
                        &result->data.list_value.items,
                        &result->data.list_value.count) < 0) {
                    free(result);
                    return -1;
                }
            } else {
                if (config_convert_to_string_list(str, ' ',
                        &result->data.list_value.items,
                        &result->data.list_value.count) < 0) {
                    free(result);
                    return -1;
                }
            }
            break;

        default:
            free(result);
            return -1;
    }

    *value = result;
    return 0;
}

void config_value_free(config_value_t* value) {
    if (!value) return;

    switch (value->type) {
        case CONFIG_TYPE_STRING:
            free(value->data.string_value);
            break;

        case CONFIG_TYPE_PATH:
            free(value->data.path_value);
            break;

        case CONFIG_TYPE_STRING_LIST:
            config_string_list_free(value->data.list_value.items,
                                   value->data.list_value.count);
            break;

        default:
            break;
    }

    free(value);
}

void config_string_list_free(char** items, int count) {
    if (!items) return;

    for (int i = 0; i < count; i++) {
        free(items[i]);
    }
    free(items);
}
