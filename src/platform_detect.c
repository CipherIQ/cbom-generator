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

#include "platform_detect.h"
#include <string.h>
#include <stdbool.h>

#ifndef __EMSCRIPTEN__
#include <sys/utsname.h>
#include <pthread.h>
#endif

/**
 * Platform detection module for CycloneDX CBOM conformance.
 *
 * Implements runtime detection of:
 * - Implementation platform (CPU architecture)
 * - Execution environment (software vs hardware)
 */

#ifdef __EMSCRIPTEN__

/* WASM: no uname() or pthread — hardcode wasm32 platform */
const char* detect_implementation_platform(void) {
    return "wasm32";
}

#else /* native Linux */

// Cached platform string for thread safety
static const char* cached_platform = NULL;
static pthread_once_t platform_init_once = PTHREAD_ONCE_INIT;

// Platform detection state
static struct utsname platform_info;
static bool platform_detected = false;

/**
 * Initialize platform detection (called once via pthread_once)
 */
static void init_platform_detection(void) {
    if (uname(&platform_info) == 0) {
        platform_detected = true;
    }
}

const char* detect_implementation_platform(void) {
    // Thread-safe initialization
    pthread_once(&platform_init_once, init_platform_detection);

    // Return cached result if available
    if (cached_platform != NULL) {
        return cached_platform;
    }

    // Platform detection failed
    if (!platform_detected) {
        cached_platform = "unknown";
        return cached_platform;
    }

    // Map machine type to CycloneDX platform identifiers
    const char* machine = platform_info.machine;

    // x86_64 (Intel/AMD 64-bit)
    if (strcmp(machine, "x86_64") == 0 || strcmp(machine, "amd64") == 0) {
        cached_platform = "x86_64";
    }
    // x86 (Intel/AMD 32-bit)
    else if (strcmp(machine, "i686") == 0 || strcmp(machine, "i386") == 0 ||
             strcmp(machine, "i486") == 0 || strcmp(machine, "i586") == 0) {
        cached_platform = "x86";
    }
    // aarch64 (ARM 64-bit)
    else if (strcmp(machine, "aarch64") == 0 || strcmp(machine, "arm64") == 0) {
        cached_platform = "aarch64";
    }
    // arm (ARM 32-bit)
    else if (strcmp(machine, "armv7l") == 0 || strcmp(machine, "armv6l") == 0 ||
             strcmp(machine, "armv5tel") == 0 || strncmp(machine, "arm", 3) == 0) {
        cached_platform = "arm";
    }
    // ppc64 (PowerPC 64-bit)
    else if (strcmp(machine, "ppc64") == 0 || strcmp(machine, "ppc64le") == 0) {
        cached_platform = "ppc64";
    }
    // s390x (IBM Z)
    else if (strcmp(machine, "s390x") == 0 || strcmp(machine, "s390") == 0) {
        cached_platform = "s390x";
    }
    // mips64 (MIPS 64-bit)
    else if (strcmp(machine, "mips64") == 0 || strcmp(machine, "mips64el") == 0) {
        cached_platform = "mips64";
    }
    // riscv64 (RISC-V 64-bit)
    else if (strcmp(machine, "riscv64") == 0) {
        cached_platform = "riscv64";
    }
    // Unknown architecture - return raw value for debugging
    else {
        // For unknown architectures, use the raw value
        // This ensures we don't lose information
        cached_platform = "unknown";
    }

    return cached_platform;
}

#endif /* __EMSCRIPTEN__ */

const char* detect_execution_environment(const char* component_path) {
    // Default to software implementation
    if (component_path == NULL || component_path[0] == '\0') {
        return "software-plain-ram";
    }

    // Check for HSM/TPM/hardware security module indicators
    // Device paths typically indicate hardware
    if (strstr(component_path, "/dev/") != NULL) {
        // Check for specific hardware security devices
        if (strstr(component_path, "tpm") != NULL ||
            strstr(component_path, "TPM") != NULL) {
            return "hardware";
        }
        if (strstr(component_path, "hsm") != NULL ||
            strstr(component_path, "HSM") != NULL) {
            return "hardware";
        }
        if (strstr(component_path, "pkcs11") != NULL ||
            strstr(component_path, "PKCS11") != NULL) {
            return "hardware";
        }
        // Generic device path might be hardware
        return "hardware";
    }

    // Check for PKCS#11 module paths
    if (strstr(component_path, "pkcs11") != NULL ||
        strstr(component_path, "PKCS11") != NULL ||
        strstr(component_path, "softhsm") != NULL ||
        strstr(component_path, "opensc") != NULL) {
        // Note: SoftHSM is software emulation, but we classify as hardware
        // because it uses the hardware interface
        return "hardware";
    }

    // Check for TEE (Trusted Execution Environment) indicators
    if (strstr(component_path, "/dev/tee") != NULL ||
        strstr(component_path, "optee") != NULL ||
        strstr(component_path, "trustzone") != NULL ||
        strstr(component_path, "sgx") != NULL ||
        strstr(component_path, "enclave") != NULL) {
        return "software-tee";
    }

    // Default for all software implementations
    return "software-plain-ram";
}

const char* get_default_execution_environment(void) {
    return "software-plain-ram";
}
