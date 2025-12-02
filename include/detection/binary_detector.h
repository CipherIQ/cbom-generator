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

// include/detection/binary_detector.h
#ifndef BINARY_DETECTOR_H
#define BINARY_DETECTOR_H

#include <stdbool.h>

/**
 * Binary Detector
 *
 * Detects services by verifying their binary executables exist and are executable.
 * Supports glob patterns for version-specific paths with wildcards.
 *
 * Phase 1 of YAML Plugin False Positive Elimination Plan
 */

/**
 * Find executable binary from array of paths
 *
 * Searches through paths array and returns first executable found.
 * Supports glob patterns using wordexp() for shell-style expansion.
 *
 * @param paths Array of path strings to check
 * @param path_count Number of paths in array
 * @param found_path Output buffer for found path (allocated by caller, min 4096 bytes)
 * @return true if executable binary found, false otherwise
 */
bool binary_detector_find(const char** paths, int path_count, char* found_path);

/**
 * Check if single path is executable
 *
 * @param path Path to check
 * @return true if file exists and is executable (X_OK permission)
 */
bool binary_detector_is_executable(const char* path);

/**
 * Expand glob pattern to first matching executable
 *
 * Uses wordexp() to expand shell patterns with wildcards
 * Returns first match that passes executable check.
 *
 * @param pattern Glob pattern with wildcards
 * @param found_path Output buffer for expanded path (min 4096 bytes)
 * @return true if pattern matched and executable found
 */
bool binary_detector_expand_pattern(const char* pattern, char* found_path);

#endif // BINARY_DETECTOR_H
