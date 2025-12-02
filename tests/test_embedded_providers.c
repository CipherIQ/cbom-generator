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
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "asset_store.h"
#include "detection/library_detection.h"

int run_embedded_providers_tests(void) {
    asset_store_t* store = asset_store_create(16);
    assert(store != NULL);

    crypto_asset_t* owner = crypto_asset_create("owner_app", ASSET_TYPE_APPLICATION);
    assert(owner != NULL);
    asset_store_add(store, owner);

    // Build synthetic profile with one embedded provider
    binary_crypto_profile_t profile = {0};
    embedded_crypto_provider_t providers[1];
    const char* algs[] = {"alg1", "alg2", NULL};
    providers[0].provider_id = "test_provider";
    providers[0].algorithms = algs;
    profile.embedded_providers = providers;
    profile.embedded_providers_count = 1;

    register_embedded_providers_for_asset(store, owner, &profile);

    // Verify provider asset exists
    size_t count = 0;
    crypto_asset_t** assets = asset_store_get_sorted(store, NULL, &count);
    bool found_provider = false;
    for (size_t i = 0; i < count; i++) {
        if (assets[i]->type == ASSET_TYPE_LIBRARY &&
            strcmp(assets[i]->name, "test_provider") == 0) {
            found_provider = true;
        }
    }
    free(assets);
    assert(found_provider);

    // Verify DEPENDS_ON relationship exists
    size_t rel_count = 0;
    relationship_t** rels = asset_store_get_relationships(store, &rel_count);
    bool found_dep = false;
    for (size_t i = 0; i < rel_count; i++) {
        if (rels[i]->type == RELATIONSHIP_DEPENDS_ON &&
            strcmp(rels[i]->source_asset_id, owner->id) == 0) {
            found_dep = true;
        }
    }
    free(rels);
    assert(found_dep);

    asset_store_destroy(store);
    printf("Embedded providers tests passed\n");
    return 0;
}
