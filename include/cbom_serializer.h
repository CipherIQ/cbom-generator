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
 * @file cbom_serializer.h
 * @brief CycloneDX CBOM serialization API
 *
 * This module provides CycloneDX output generation, extracted from main.c
 * for better code organization. It generates CycloneDX 1.6 or 1.7 format
 * with full cryptographic properties, relationships, and metadata.
 */

#ifndef CBOM_SERIALIZER_H
#define CBOM_SERIALIZER_H

#include "asset_store.h"
#include <stdio.h>

/**
 * Generate CycloneDX CBOM output
 *
 * Creates a complete CycloneDX BOM including:
 * - Metadata (timestamp, tools, host info)
 * - Components (certificates, keys, protocols, services, cipher suites)
 * - Dependencies array (relationship graph)
 * - Properties arrays (custom crypto properties)
 *
 * Format controlled by g_config.cyclonedx_spec_version:
 * - "1.6" → CycloneDX 1.6 format
 * - "1.7" → CycloneDX 1.7 format (with native certificate fields)
 *
 * @param store Asset store containing all discovered crypto assets
 * @param output File stream to write JSON output to
 * @return 0 on success, -1 on error
 */
int cbom_serializer_generate_cyclonedx(asset_store_t *store, FILE *output);

#endif // CBOM_SERIALIZER_H
