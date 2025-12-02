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
 * @file variable_expander.c
 * @brief Variable substitution implementation
 */

#define _GNU_SOURCE
#include "variable_expander.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * Replace a variable in string
 */
static char* replace_variable(
    const char* str,
    const char* var_name,
    const char* var_value
) {
    if (!str || !var_name || !var_value) {
        return strdup(str ? str : "");
    }

    char var_pattern[256];
    snprintf(var_pattern, sizeof(var_pattern), "${%s}", var_name);

    const char* pos = strstr(str, var_pattern);
    if (!pos) {
        return strdup(str);
    }

    // Calculate new length
    size_t prefix_len = pos - str;
    size_t suffix_len = strlen(pos + strlen(var_pattern));
    size_t new_len = prefix_len + strlen(var_value) + suffix_len + 1;

    char* result = malloc(new_len);
    if (!result) {
        return NULL;
    }

    // Build new string
    strncpy(result, str, prefix_len);
    result[prefix_len] = '\0';
    strcat(result, var_value);
    strcat(result, pos + strlen(var_pattern));

    return result;
}

char* variable_expand(const char* str, const service_instance_t* instance) {
    if (!str) {
        return NULL;
    }

    if (!instance) {
        return strdup(str);
    }

    char* result = strdup(str);
    if (!result) {
        return NULL;
    }

    // Expand ${DETECTED_CONFIG_DIR}
    if (instance->config_dir) {
        char* expanded = replace_variable(result, "DETECTED_CONFIG_DIR",
                                          instance->config_dir);
        if (!expanded) {
            free(result);
            return NULL;
        }
        free(result);
        result = expanded;
    }

    // Expand ${PID}
    if (instance->pid > 0) {
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", (int)instance->pid);

        char* expanded = replace_variable(result, "PID", pid_str);
        if (!expanded) {
            free(result);
            return NULL;
        }
        free(result);
        result = expanded;
    }

    // Expand ${PORT}
    if (instance->port > 0) {
        char port_str[32];
        snprintf(port_str, sizeof(port_str), "%d", instance->port);

        char* expanded = replace_variable(result, "PORT", port_str);
        if (!expanded) {
            free(result);
            return NULL;
        }
        free(result);
        result = expanded;
    }

    return result;
}

bool variable_contains_vars(const char* str) {
    if (!str) {
        return false;
    }

    return (strstr(str, "${") != NULL);
}
