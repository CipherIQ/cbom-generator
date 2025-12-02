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
 * @file process_detector.h
 * @brief Process-based service detection
 *
 * Detects services by scanning /proc for matching process names and command lines
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef PROCESS_DETECTOR_H
#define PROCESS_DETECTOR_H

#include "plugin_schema.h"
#include "service_discovery.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detect service by process name or command line
 *
 * Scans /proc for processes matching the configured names or command patterns.
 * Populates instance with pid, process_name, command_line, and config_dir (if extractable).
 *
 * @param config Process detection configuration from YAML plugin
 * @param instance Output parameter - populated on success
 * @return true if process detected, false otherwise
 */
bool process_detector_detect(const process_detection_config_t* config,
                               service_instance_t* instance);

/**
 * Extract configuration directory from command line
 *
 * Looks for common patterns like:
 * -  `-c /path/to/config`
 * - `--config=/path/to/config`
 * - `-D /path/to/data`
 * - `--data-dir=/path/to/data`
 *
 * @param cmdline Command line string
 * @param config_dir Output parameter - allocated config directory (caller must free)
 * @return true if config dir extracted, false otherwise
 */
bool process_detector_extract_config_dir(const char* cmdline, char** config_dir);

/**
 * Check if command line matches a regex pattern
 *
 * @param cmdline Command line to check
 * @param pattern POSIX regex pattern
 * @return true if matches, false otherwise
 */
bool process_detector_matches_pattern(const char* cmdline, const char* pattern);

/**
 * Get process name from PID
 *
 * Reads /proc/[pid]/comm
 *
 * @param pid Process ID
 * @return Process name (caller must free) or NULL on error
 */
char* process_detector_get_process_name(pid_t pid);

/**
 * Get command line from PID
 *
 * Reads /proc/[pid]/cmdline and replaces NULLs with spaces
 *
 * @param pid Process ID
 * @return Command line (caller must free) or NULL on error
 */
char* process_detector_get_command_line(pid_t pid);

#ifdef __cplusplus
}
#endif

#endif /* PROCESS_DETECTOR_H */
