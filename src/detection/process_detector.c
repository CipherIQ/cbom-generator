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
 * @file process_detector.c
 * @brief Process-based service detection implementation
 */

#define _GNU_SOURCE
#include "detection/process_detector.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <regex.h>
#include <libgen.h>

char* process_detector_get_process_name(pid_t pid) {
    char comm_path[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

    FILE* fp = fopen(comm_path, "r");
    if (!fp) {
        return NULL;
    }

    char process_name[256];
    if (!fgets(process_name, sizeof(process_name), fp)) {
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    // Remove trailing newline
    process_name[strcspn(process_name, "\n")] = '\0';

    return strdup(process_name);
}

char* process_detector_get_command_line(pid_t pid) {
    char cmdline_path[256];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

    FILE* fp = fopen(cmdline_path, "r");
    if (!fp) {
        return NULL;
    }

    char cmdline[4096];
    size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);

    if (len == 0) {
        return NULL;
    }

    cmdline[len] = '\0';

    // Replace NULLs with spaces for readability
    for (size_t i = 0; i < len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }

    // Trim trailing spaces
    while (len > 0 && isspace(cmdline[len - 1])) {
        cmdline[--len] = '\0';
    }

    return strdup(cmdline);
}

bool process_detector_matches_pattern(const char* cmdline, const char* pattern) {
    if (!cmdline || !pattern) {
        return false;
    }

    regex_t regex;
    int ret = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
    if (ret != 0) {
        return false;
    }

    ret = regexec(&regex, cmdline, 0, NULL, 0);
    regfree(&regex);

    return (ret == 0);
}

bool process_detector_extract_config_dir(const char* cmdline, char** config_dir) {
    if (!cmdline || !config_dir) {
        return false;
    }

    *config_dir = NULL;

    // Common config patterns
    const char* patterns[] = {
        "-c ", "--config=", "--config ", "-D ", "--data-dir=", "--data-dir ",
        "-f ", "--file=", "--file "
    };

    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        const char* found = strstr(cmdline, patterns[i]);
        if (found) {
            const char* path_start = found + strlen(patterns[i]);

            // Skip whitespace
            while (*path_start && isspace(*path_start)) {
                path_start++;
            }

            if (!*path_start) {
                continue;
            }

            // Find end of path (space, quote, or null)
            const char* path_end = path_start;
            while (*path_end && !isspace(*path_end) && *path_end != '"' && *path_end != '\'') {
                path_end++;
            }

            size_t path_len = path_end - path_start;
            if (path_len == 0) {
                continue;
            }

            // Allocate and copy path
            char* path = malloc(path_len + 1);
            if (!path) {
                return false;
            }

            strncpy(path, path_start, path_len);
            path[path_len] = '\0';

            // Extract directory
            char* path_copy = strdup(path);
            char* dir = dirname(path_copy);
            *config_dir = strdup(dir);

            free(path);
            free(path_copy);

            return (*config_dir != NULL);
        }
    }

    return false;
}

bool process_detector_detect(const process_detection_config_t* config,
                               service_instance_t* instance) {
    if (!config || !instance) {
        return false;
    }

    // Must have at least one process name or command pattern
    if (config->process_name_count == 0 && config->command_pattern_count == 0) {
        return false;
    }

    DIR* proc = opendir("/proc");
    if (!proc) {
        return false;
    }

    struct dirent* entry;
    bool detected = false;

    while ((entry = readdir(proc)) != NULL) {
        // Skip non-numeric entries
        if (!isdigit(entry->d_name[0])) {
            continue;
        }

        pid_t pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        // Get process name
        char* process_name = process_detector_get_process_name(pid);
        if (!process_name) {
            continue;
        }

        // Check if matches any configured process name
        bool name_matched = false;
        for (int i = 0; i < config->process_name_count; i++) {
            if (strcmp(process_name, config->process_names[i]) == 0) {
                name_matched = true;
                break;
            }
        }

        // If no process names configured or name matched, check command patterns
        bool pattern_matched = false;
        char* command_line = NULL;

        if (name_matched || config->process_name_count == 0) {
            command_line = process_detector_get_command_line(pid);
            if (command_line) {
                // Check command patterns
                for (int i = 0; i < config->command_pattern_count; i++) {
                    if (process_detector_matches_pattern(command_line, config->command_patterns[i])) {
                        pattern_matched = true;
                        break;
                    }
                }

                // Phase 4: Check exclude patterns (reject if any match)
                if (pattern_matched && config->exclude_pattern_count > 0) {
                    for (int i = 0; i < config->exclude_pattern_count; i++) {
                        if (process_detector_matches_pattern(command_line, config->exclude_patterns[i])) {
                            // Matched exclude pattern - reject this process
                            pattern_matched = false;
                            break;
                        }
                    }
                }
            }
        }

        // Detection succeeds if:
        // 1. Name matched (and no patterns configured), OR
        // 2. Pattern matched (and no names configured), OR
        // 3. Both name and pattern matched
        bool success = false;

        if (config->process_name_count > 0 && config->command_pattern_count > 0) {
            // Both configured - need both to match
            success = name_matched && pattern_matched;
        } else if (config->process_name_count > 0) {
            // Only names configured
            success = name_matched;
        } else {
            // Only patterns configured
            success = pattern_matched;
        }

        if (success) {
            // Populate instance
            service_instance_set_process_info(instance, pid, process_name, command_line);

            // Try to extract config dir from command line
            if (command_line) {
                char* config_dir = NULL;
                if (process_detector_extract_config_dir(command_line, &config_dir)) {
                    service_instance_set_config_dir(instance, config_dir);
                    free(config_dir);
                }
            }

            detected = true;

            free(process_name);
            free(command_line);
            break;
        }

        free(process_name);
        free(command_line);
    }

    closedir(proc);
    return detected;
}
