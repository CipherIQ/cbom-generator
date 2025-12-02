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
#include "secure_memory.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

static secure_pool_t *pool_list = NULL;
static size_t page_size = 0;

int secure_memory_init(void) {
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) {
        return -1;
    }
    return 0;
}

void secure_memory_cleanup(void) {
    secure_pool_t *current = pool_list;
    while (current != NULL) {
        secure_pool_t *next = current->next;
        if (current->memory != NULL) {
            secure_zero(current->memory, current->size);
            munmap(current->memory, current->size);
        }
        free(current);
        current = next;
    }
    pool_list = NULL;
}

void* secure_alloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    // Align size to page boundary
    size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    
    // Allocate memory with mmap for better security
    void *ptr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    
    // Lock memory to prevent swapping
    if (mlock(ptr, aligned_size) != 0) {
        // Non-fatal error, continue without locking
    }
    
    return ptr;
}

void secure_free(void *ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return;
    }
    
    // Zero memory before freeing
    secure_zero(ptr, size);
    
    // Align size to page boundary
    size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    
    // Unlock memory
    munlock(ptr, aligned_size);
    
    // Unmap memory
    munmap(ptr, aligned_size);
}

void secure_zero(void *ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return;
    }
    
    // Use explicit_bzero if available, otherwise volatile memset
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr, size);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
#endif
}

secure_pool_t* get_secure_pool(size_t min_size) {
    // Find existing pool with sufficient space
    secure_pool_t *current = pool_list;
    while (current != NULL) {
        if (current->size - current->used >= min_size) {
            return current;
        }
        current = current->next;
    }
    
    // Create new pool
    secure_pool_t *new_pool = malloc(sizeof(secure_pool_t));
    if (new_pool == NULL) {
        return NULL;
    }
    
    // Allocate at least one page or requested size, whichever is larger
    size_t pool_size = (min_size > page_size) ? min_size : page_size;
    pool_size = ((pool_size + page_size - 1) / page_size) * page_size;
    
    new_pool->memory = secure_alloc(pool_size);
    if (new_pool->memory == NULL) {
        free(new_pool);
        return NULL;
    }
    
    new_pool->size = pool_size;
    new_pool->used = 0;
    new_pool->next = pool_list;
    pool_list = new_pool;
    
    return new_pool;
}

void return_secure_pool(secure_pool_t *pool) {
    if (pool == NULL) {
        return;
    }
    
    // Reset usage counter (memory remains allocated)
    pool->used = 0;
    
    // Zero the memory for security
    secure_zero(pool->memory, pool->size);
}
