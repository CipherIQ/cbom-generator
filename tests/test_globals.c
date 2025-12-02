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

// Global stubs for test linking
#include "cbom_types.h"

// Stub global config (referenced by builtin_scanners.c as g_cbom_config)
cbom_config_t g_cbom_config = {
    .deterministic = true,
    .no_personal_data = true,
    .include_personal_data = false,
    .no_network = false,
    .enable_attestation = false,
    .signature_method = NULL,
    .signing_key_path = NULL,
    .thread_count = 1,
    .output_file = NULL,
    .format = NULL,
    .cyclonedx_spec_version = NULL,
    .target_paths = NULL,
    .target_path_count = 0,
    .dedup_mode = DEDUP_MODE_SAFE,
    .emit_bundles = false,
    .tui_enabled = false,
    .error_log_file = NULL,
    .pqc_report_path = NULL,
    .discover_services = false,
    .plugin_dir = NULL,
    .include_fixtures = false,
    .crypto_registry_path = NULL,
    .skip_builtin_service_scanner = false,
    .use_ldd_for_libraries = false,
    .skip_package_resolution = false,
    .cross_arch_mode = false,
    .yocto_manifest_path = NULL
};

// Alias for older code that may reference g_config
cbom_config_t *g_config = &g_cbom_config;
