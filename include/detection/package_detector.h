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
 * @file package_detector.h
 * @brief Package manager-based service detection
 *
 * Detects services via package managers (dpkg, rpm, pacman)
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef PACKAGE_DETECTOR_H
#define PACKAGE_DETECTOR_H

#include "plugin_schema.h"
#include "service_discovery.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detect service by installed package
 *
 * Checks if any of the configured package names are installed.
 * Supports dpkg (Debian/Ubuntu), rpm (RHEL/Fedora/CentOS), pacman (Arch).
 * Populates instance with package_name and package_version.
 *
 * @param config Package detection configuration from YAML plugin
 * @param instance Output parameter - populated on success
 * @return true if package detected, false otherwise
 */
bool package_detector_detect(const package_detection_config_t* config,
                               service_instance_t* instance);

/**
 * Check if a package is installed via dpkg (Debian/Ubuntu)
 *
 * @param package_name Package name
 * @param version Output parameter - package version (caller must free)
 * @return true if installed, false otherwise
 */
bool package_detector_check_dpkg(const char* package_name, char** version);

/**
 * Check if a package is installed via rpm (RHEL/Fedora/CentOS)
 *
 * @param package_name Package name
 * @param version Output parameter - package version (caller must free)
 * @return true if installed, false otherwise
 */
bool package_detector_check_rpm(const char* package_name, char** version);

/**
 * Check if a package is installed via pacman (Arch Linux)
 *
 * @param package_name Package name
 * @param version Output parameter - package version (caller must free)
 * @return true if installed, false otherwise
 */
bool package_detector_check_pacman(const char* package_name, char** version);

/**
 * Auto-detect which package manager is available
 *
 * @return Package manager command ("dpkg", "rpm", "pacman") or NULL
 */
const char* package_detector_get_available_manager(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKAGE_DETECTOR_H */
