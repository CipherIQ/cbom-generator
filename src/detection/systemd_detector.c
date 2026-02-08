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
 * @file systemd_detector.c
 * @brief Systemd-based service detection implementation
 */

#define _GNU_SOURCE
#include "detection/systemd_detector.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
/* WASM: systemd detection requires systemctl — unavailable in browser.
 * Full stub returning empty results for all functions. */

bool systemd_detector_detect(const systemd_detection_config_t* config,
                               service_instance_t* instance) {
    (void)config; (void)instance;
    return false;
}

bool systemd_detector_is_active(const char* service_name) {
    (void)service_name;
    return false;
}

pid_t systemd_detector_get_pid(const char* service_name) {
    (void)service_name;
    return 0;
}

bool systemd_detector_available(void) {
    return false;
}

#else /* !__EMSCRIPTEN__ */

#include <unistd.h>

bool systemd_detector_available(void) {
    // Check if systemctl command is available
    int ret = system("which systemctl >/dev/null 2>&1");
    return (ret == 0);
}

bool systemd_detector_is_active(const char* service_name) {
    if (!service_name) {
        return false;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "systemctl is-active %s 2>/dev/null", service_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return false;
    }

    char status[32];
    bool active = false;

    if (fgets(status, sizeof(status), fp)) {
        status[strcspn(status, "\n")] = '\0';
        active = (strcmp(status, "active") == 0);
    }

    pclose(fp);
    return active;
}

pid_t systemd_detector_get_pid(const char* service_name) {
    if (!service_name) {
        return 0;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
            "systemctl show %s --property=MainPID --value 2>/dev/null",
            service_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return 0;
    }

    char pid_str[32];
    pid_t pid = 0;

    if (fgets(pid_str, sizeof(pid_str), fp)) {
        pid = (pid_t)atoi(pid_str);
    }

    pclose(fp);
    return pid;
}

bool systemd_detector_detect(const systemd_detection_config_t* config,
                               service_instance_t* instance) {
    if (!config || !instance) {
        return false;
    }

    if (config->service_name_count == 0) {
        return false;
    }

    // Check if systemd is available
    if (!systemd_detector_available()) {
        return false;
    }

    // Try each configured service name
    for (int i = 0; i < config->service_name_count; i++) {
        const char* service_name = config->service_names[i];

        if (systemd_detector_is_active(service_name)) {
            // Service is active!
            pid_t pid = systemd_detector_get_pid(service_name);

            service_instance_set_systemd_info(instance, service_name, true);

            if (pid > 0) {
                // Also set process info
                service_instance_set_process_info(instance, pid, NULL, NULL);
            }

            return true;
        }
    }

    return false;
}

#endif /* __EMSCRIPTEN__ */
