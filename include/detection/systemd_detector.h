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
 * @file systemd_detector.h
 * @brief Systemd-based service detection
 *
 * Detects services via systemd service manager
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef SYSTEMD_DETECTOR_H
#define SYSTEMD_DETECTOR_H

#include "plugin_schema.h"
#include "service_discovery.h"
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detect service via systemd
 *
 * Checks if any of the configured systemd service names are active.
 * Populates instance with systemd_service, systemd_active, and pid.
 *
 * @param config Systemd detection configuration from YAML plugin
 * @param instance Output parameter - populated on success
 * @return true if systemd service detected, false otherwise
 */
bool systemd_detector_detect(const systemd_detection_config_t* config,
                               service_instance_t* instance);

/**
 * Check if a systemd service is active
 *
 * @param service_name Systemd service name (e.g., "postgresql.service")
 * @return true if service is active, false otherwise
 */
bool systemd_detector_is_active(const char* service_name);

/**
 * Get main PID of a systemd service
 *
 * @param service_name Systemd service name
 * @return PID or 0 if not found/running
 */
pid_t systemd_detector_get_pid(const char* service_name);

/**
 * Check if systemd is available on the system
 *
 * @return true if systemd is available, false otherwise
 */
bool systemd_detector_available(void);

#ifdef __cplusplus
}
#endif

#endif /* SYSTEMD_DETECTOR_H */
