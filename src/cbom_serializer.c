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
 * @file cbom_serializer.c
 * @brief CycloneDX CBOM serialization implementation
 *
 * This is currently a thin wrapper around the generate_cyclonedx_cbom()
 * function in main.c. The actual 3,500+ line implementation remains in
 * main.c to avoid breaking existing functionality during Phase 4.
 *
 * Future refactoring can fully extract the implementation here.
 */

#include "cbom_serializer.h"
#include "asset_store.h"
#include <stdio.h>

// Forward declaration of the actual implementation in main.c
// This function will be made non-static in main.c
extern int generate_cyclonedx_cbom(asset_store_t *store, FILE *output);

int cbom_serializer_generate_cyclonedx(asset_store_t *store, FILE *output) {
    // Delegate to main.c implementation
    // This wrapper provides a clean API boundary for future refactoring
    return generate_cyclonedx_cbom(store, output);
}
