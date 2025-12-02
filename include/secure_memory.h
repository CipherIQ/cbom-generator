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

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>

// Secure memory allocation functions
void* secure_alloc(size_t size);
void secure_free(void *ptr, size_t size);
void secure_zero(void *ptr, size_t size);

// Memory pool for sensitive data
typedef struct secure_pool {
    void *memory;
    size_t size;
    size_t used;
    struct secure_pool *next;
} secure_pool_t;

// Initialize secure memory subsystem
int secure_memory_init(void);

// Cleanup secure memory subsystem
void secure_memory_cleanup(void);

// Get secure memory pool
secure_pool_t* get_secure_pool(size_t min_size);

// Return secure memory pool
void return_secure_pool(secure_pool_t *pool);

#endif // SECURE_MEMORY_H
