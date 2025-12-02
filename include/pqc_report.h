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

#ifndef PQC_REPORT_H
#define PQC_REPORT_H

#include "asset_store.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate human-readable PQC migration report
 *
 * Creates a comprehensive text report with:
 * - Executive summary with vulnerability breakdown
 * - Assets grouped by break year (2030/2035/2040/2045)
 * - Migration timeline and recommendations
 * - NIST standards reference (FIPS 203/204/205)
 *
 * @param store Asset store containing scanned cryptographic assets
 * @param output File stream to write report to
 * @return 0 on success, -1 on error
 */
int pqc_generate_migration_report(asset_store_t* store, FILE* output);

#ifdef __cplusplus
}
#endif

#endif // PQC_REPORT_H
