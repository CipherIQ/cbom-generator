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
 * @file variable_expander.h
 * @brief Variable substitution for config paths
 *
 * Expands variables like ${DETECTED_CONFIG_DIR}, ${PID}, ${PORT} in paths.
 */

#ifndef VARIABLE_EXPANDER_H
#define VARIABLE_EXPANDER_H

#include "service_discovery.h"

/**
 * Expand variables in a string
 *
 * Supported variables:
 * - ${DETECTED_CONFIG_DIR} - From service instance config_dir
 * - ${PID} - From service instance pid
 * - ${PORT} - From service instance port
 *
 * @param str String containing variables
 * @param instance Service instance with variable values
 * @return Expanded string (caller must free), or NULL on error
 */
char* variable_expand(const char* str, const service_instance_t* instance);

/**
 * Check if string contains variables
 *
 * @param str String to check
 * @return true if contains ${...} variables, false otherwise
 */
bool variable_contains_vars(const char* str);

#endif // VARIABLE_EXPANDER_H
