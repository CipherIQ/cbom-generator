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
 * @file config_detector.h
 * @brief Config file-based service detection
 *
 * Detects services by configuration file presence using glob patterns
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef CONFIG_DETECTOR_H
#define CONFIG_DETECTOR_H

#include "plugin_schema.h"
#include "service_discovery.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detect service by configuration file presence
 *
 * Checks if any of the configured file paths exist (supports glob patterns).
 * Populates instance with config_dir and config_file_path.
 *
 * @param config Config file detection configuration from YAML plugin
 * @param instance Output parameter - populated on success
 * @return true if config file detected, false otherwise
 */
bool config_file_detector_detect(const config_file_detection_config_t* config,
                                  service_instance_t* instance);

/**
 * Check if a config file exists and is readable
 *
 * Supports glob patterns like /etc/postgresql/STAR/main/postgresql.conf
 *
 * @param path File path (may contain glob patterns)
 * @param resolved_path Output parameter - actual resolved path (caller must free)
 * @return true if file found and readable, false otherwise
 */
bool config_file_detector_find_file(const char* path, char** resolved_path);

/**
 * Extract config directory from file path
 *
 * @param file_path Full path to config file
 * @return Directory path (caller must free) or NULL on error
 */
char* config_file_detector_get_directory(const char* file_path);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_DETECTOR_H */
