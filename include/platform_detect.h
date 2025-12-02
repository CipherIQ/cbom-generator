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

#ifndef PLATFORM_DETECT_H
#define PLATFORM_DETECT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Platform detection module for CycloneDX CBOM conformance.
 *
 * Provides runtime detection of:
 * - Implementation platform (CPU architecture)
 * - Execution environment (software vs hardware)
 *
 * Per OWASP CycloneDX Authoritative Guide to CBOM (Second Edition, October 2025)
 */

/**
 * Detects the current hardware platform at runtime.
 *
 * Uses uname() to determine CPU architecture and maps to CycloneDX
 * platform identifiers.
 *
 * @return Platform identifier string. One of:
 *         - "x86_64" (Intel/AMD 64-bit)
 *         - "x86" (Intel/AMD 32-bit)
 *         - "aarch64" (ARM 64-bit)
 *         - "arm" (ARM 32-bit)
 *         - "ppc64" (PowerPC 64-bit)
 *         - "s390x" (IBM Z)
 *         - "mips64" (MIPS 64-bit)
 *         - "riscv64" (RISC-V 64-bit)
 *         - "unknown" (unrecognized architecture)
 *
 * @note Returns pointer to static string - do not free.
 * @note Thread-safe after initial call (cached result).
 */
const char* detect_implementation_platform(void);

/**
 * Determines the execution environment for a cryptographic component.
 *
 * Analyzes the component path to determine if it runs in software
 * or hardware (HSM, TPM, secure enclave).
 *
 * @param component_path Path to the component (may be NULL)
 * @return Execution environment string. One of:
 *         - "software-plain-ram" (default for software implementations)
 *         - "hardware" (HSM, TPM, or hardware security module)
 *         - "software-tee" (Trusted Execution Environment)
 *
 * @note Returns pointer to static string - do not free.
 */
const char* detect_execution_environment(const char* component_path);

/**
 * Get the default execution environment.
 *
 * @return "software-plain-ram"
 */
const char* get_default_execution_environment(void);

#ifdef __cplusplus
}
#endif

#endif // PLATFORM_DETECT_H
