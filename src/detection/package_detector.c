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
 * @file package_detector.c
 * @brief Package manager-based service detection implementation
 */

#define _GNU_SOURCE
#include "detection/package_detector.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char* package_detector_get_available_manager(void) {
    // Check dpkg
    if (system("which dpkg >/dev/null 2>&1") == 0) {
        return "dpkg";
    }

    // Check rpm
    if (system("which rpm >/dev/null 2>&1") == 0) {
        return "rpm";
    }

    // Check pacman
    if (system("which pacman >/dev/null 2>&1") == 0) {
        return "pacman";
    }

    return NULL;
}

bool package_detector_check_dpkg(const char* package_name, char** version) {
    if (!package_name) {
        return false;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "dpkg -l %s 2>/dev/null | grep ^ii", package_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return false;
    }

    char output[512];
    bool installed = false;

    if (fgets(output, sizeof(output), fp)) {
        // Format: ii  package-name  version  ...
        // Parse version if requested
        if (version) {
            char pkg[128], ver[128];
            if (sscanf(output, "%*s %127s %127s", pkg, ver) == 2) {
                *version = strdup(ver);
            }
        }
        installed = true;
    }

    pclose(fp);
    return installed;
}

bool package_detector_check_rpm(const char* package_name, char** version) {
    if (!package_name) {
        return false;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rpm -q %s 2>/dev/null", package_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return false;
    }

    char output[512];
    bool installed = false;

    if (fgets(output, sizeof(output), fp)) {
        // Check for "not installed" message
        if (strstr(output, "not installed") == NULL) {
            output[strcspn(output, "\n")] = '\0';

            // Format: package-name-version-release.arch
            // Extract version if requested
            if (version) {
                *version = strdup(output);
            }

            installed = true;
        }
    }

    pclose(fp);
    return installed;
}

bool package_detector_check_pacman(const char* package_name, char** version) {
    if (!package_name) {
        return false;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "pacman -Q %s 2>/dev/null", package_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return false;
    }

    char output[512];
    bool installed = false;

    if (fgets(output, sizeof(output), fp)) {
        // Format: package-name version
        if (version) {
            char pkg[128], ver[128];
            if (sscanf(output, "%127s %127s", pkg, ver) == 2) {
                *version = strdup(ver);
            }
        }
        installed = true;
    }

    pclose(fp);
    return installed;
}

bool package_detector_detect(const package_detection_config_t* config,
                               service_instance_t* instance) {
    if (!config || !instance) {
        return false;
    }

    if (config->package_name_count == 0) {
        return false;
    }

    // Auto-detect package manager
    const char* manager = package_detector_get_available_manager();
    if (!manager) {
        return false;
    }

    // Phase 2: Enhanced validation with server/exclude package lists
    bool has_any_package = false;
    bool has_server_package = false;
    bool has_only_exclude = true;  // Assume true until proven otherwise
    char* found_package = NULL;
    char* found_version = NULL;

    // Check if any server packages exist (highest priority)
    if (config->server_count > 0) {
        for (int i = 0; i < config->server_count; i++) {
            const char* pkg = config->server_packages[i];
            char* ver = NULL;
            bool installed = false;

            if (strcmp(manager, "dpkg") == 0) {
                installed = package_detector_check_dpkg(pkg, &ver);
            } else if (strcmp(manager, "rpm") == 0) {
                installed = package_detector_check_rpm(pkg, &ver);
            } else if (strcmp(manager, "pacman") == 0) {
                installed = package_detector_check_pacman(pkg, &ver);
            }

            if (installed) {
                has_server_package = true;
                has_any_package = true;
                has_only_exclude = false;
                if (!found_package) {
                    found_package = strdup(pkg);
                    found_version = ver;  // Take ownership
                } else {
                    free(ver);
                }
            }
        }
    }

    // Check regular package names
    for (int i = 0; i < config->package_name_count; i++) {
        const char* pkg = config->package_names[i];
        char* ver = NULL;
        bool installed = false;

        if (strcmp(manager, "dpkg") == 0) {
            installed = package_detector_check_dpkg(pkg, &ver);
        } else if (strcmp(manager, "rpm") == 0) {
            installed = package_detector_check_rpm(pkg, &ver);
        } else if (strcmp(manager, "pacman") == 0) {
            installed = package_detector_check_pacman(pkg, &ver);
        }

        if (installed) {
            has_any_package = true;
            // Check if this is an exclude package
            bool is_excluded = false;
            for (int j = 0; j < config->exclude_count; j++) {
                if (strcmp(pkg, config->exclude_packages[j]) == 0) {
                    is_excluded = true;
                    break;
                }
            }
            if (!is_excluded) {
                has_only_exclude = false;
            }

            if (!found_package) {
                found_package = strdup(pkg);
                found_version = ver;  // Take ownership
            } else {
                free(ver);
            }
        }
    }

    // Validation logic (Phase 2)
    bool detected = false;
    float confidence = config->confidence > 0.0f ? config->confidence : 0.90f;

    if (has_server_package) {
        // Server package exists - high confidence detection
        detected = true;
        confidence = 0.95f;
    } else if (has_any_package && !has_only_exclude) {
        // Some non-excluded packages exist - medium confidence
        detected = true;
        confidence = 0.85f;
    } else if (has_only_exclude) {
        // Only client/utility packages exist - REJECT
        detected = false;
    }

    if (detected && found_package) {
        service_instance_set_package_info(instance, found_package, found_version);
        instance->confidence = confidence;
    }

    free(found_package);
    free(found_version);

    return detected;
}
