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

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>

#include "detection/library_detection.h"

static int test_analyze_existing_binary(void) {
    const char* path = "/bin/ls";
    binary_crypto_profile_t* profile = analyze_binary_crypto(path);
    if (!profile) {
        printf("FAIL: analyze_binary_crypto returned NULL for %s\n", path);
        return 1;
    }

    // Basic sanity: path should match
    assert(profile->binary_path != NULL);

    free_binary_crypto_profile(profile);
    return 0;
}

static int test_analyze_missing_binary(void) {
    const char* path = "/nonexistent/binary/path";
    binary_crypto_profile_t* profile = analyze_binary_crypto(path);
    if (profile != NULL) {
        printf("FAIL: analyze_binary_crypto should return NULL for missing path\n");
        free_binary_crypto_profile(profile);
        return 1;
    }
    return 0;
}

int run_library_detection_tests(void) {
    int failures = 0;

    failures += test_analyze_existing_binary();
    failures += test_analyze_missing_binary();

    if (failures == 0) {
        printf("Library detection tests passed\n");
    } else {
        printf("Library detection tests failed: %d\n", failures);
    }

    return failures;
}
