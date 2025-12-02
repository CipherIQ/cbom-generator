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
 * @file config_detector.c
 * @brief Config file-based service detection implementation
 */

#define _GNU_SOURCE
#include "detection/config_detector.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glob.h>
#include <libgen.h>
#include <sys/stat.h>

char* config_file_detector_get_directory(const char* file_path) {
    if (!file_path) {
        return NULL;
    }

    char* path_copy = strdup(file_path);
    if (!path_copy) {
        return NULL;
    }

    char* dir = dirname(path_copy);
    char* result = strdup(dir);

    free(path_copy);
    return result;
}

bool config_file_detector_find_file(const char* path, char** resolved_path) {
    if (!path || !resolved_path) {
        return false;
    }

    *resolved_path = NULL;

    glob_t glob_result;
    memset(&glob_result, 0, sizeof(glob_result));

    // Expand glob pattern
    int ret = glob(path, GLOB_TILDE | GLOB_BRACE, NULL, &glob_result);

    if (ret == 0 && glob_result.gl_pathc > 0) {
        // Check each match for readability
        for (size_t i = 0; i < glob_result.gl_pathc; i++) {
            const char* match = glob_result.gl_pathv[i];

            // Check if file exists and is readable
            if (access(match, R_OK) == 0) {
                // Check if it's a regular file
                struct stat st;
                if (stat(match, &st) == 0 && S_ISREG(st.st_mode)) {
                    *resolved_path = strdup(match);
                    globfree(&glob_result);
                    return true;
                }
            }
        }
    }

    if (ret == 0) {
        globfree(&glob_result);
    }

    return false;
}

bool config_file_detector_detect(const config_file_detection_config_t* config,
                                  service_instance_t* instance) {
    if (!config || !instance) {
        return false;
    }

    if (config->path_count == 0) {
        return false;
    }

    // Try each configured path
    for (int i = 0; i < config->path_count; i++) {
        char* resolved_path = NULL;

        if (config_file_detector_find_file(config->paths[i], &resolved_path)) {
            // File found!
            char* config_dir = config_file_detector_get_directory(resolved_path);

            service_instance_set_config_dir(instance, config_dir);
            service_instance_set_config_file(instance, resolved_path);

            free(config_dir);
            free(resolved_path);
            return true;
        }
    }

    // No files found
    // If required=true, detection fails
    // If required=false, detection succeeds (service may be installed but not configured)
    return !config->required;
}
