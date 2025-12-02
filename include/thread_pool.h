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

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

// Thread pool configuration limits
#define THREAD_POOL_MIN_THREADS 1
#define THREAD_POOL_MAX_THREADS 32
#define THREAD_POOL_DEFAULT_THREADS 0  // Use CPU core count
#define WORK_QUEUE_DEFAULT_SIZE 1024
#define WARNING_BUFFER_SIZE 256
#define MAX_WARNINGS_PER_THREAD 100

// Work item priority levels
typedef enum {
    WORK_PRIORITY_LOW = 0,
    WORK_PRIORITY_NORMAL = 1,
    WORK_PRIORITY_HIGH = 2,
    WORK_PRIORITY_CRITICAL = 3
} work_priority_t;

// Work item function signature
typedef int (*work_function_t)(void* data, void* context);

// Work item structure
typedef struct work_item {
    work_function_t function;
    void* data;
    void* context;
    work_priority_t priority;
    uint64_t sequence_id;
    struct timespec submit_time;
    struct work_item* next;
} work_item_t;

// Work queue with atomic indices for thread safety
typedef struct {
    work_item_t** items;
    _Atomic size_t head;
    _Atomic size_t tail;
    _Atomic size_t count;
    size_t capacity;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} work_queue_t;

// Per-thread statistics
typedef struct {
    uint32_t thread_id;
    _Atomic uint64_t tasks_completed;
    _Atomic uint64_t tasks_stolen;
    _Atomic uint64_t tasks_failed;
    _Atomic uint64_t total_work_time_ns;
    _Atomic uint64_t idle_time_ns;
    struct timespec last_activity;
    
    // Pre-allocated warning buffer to prevent null pointer writes
    char warning_buffer[WARNING_BUFFER_SIZE];
    _Atomic size_t warning_count;
    char warnings[MAX_WARNINGS_PER_THREAD][WARNING_BUFFER_SIZE];
} thread_stats_t;

// Worker thread context
typedef struct {
    uint32_t thread_id;
    pthread_t pthread;
    work_queue_t* local_queue;  // For work stealing
    thread_stats_t stats;
    _Atomic bool should_exit;
    _Atomic bool is_active;
    struct thread_pool* pool;   // Back reference
} worker_thread_t;

// Thread pool structure
typedef struct thread_pool {
    worker_thread_t* workers;
    uint32_t thread_count;
    work_queue_t global_queue;
    
    // Thread pool state
    _Atomic bool is_running;
    _Atomic bool shutdown_requested;
    _Atomic uint64_t next_sequence_id;
    
    // Performance monitoring
    _Atomic uint64_t total_tasks_submitted;
    _Atomic uint64_t total_tasks_completed;
    _Atomic uint64_t total_tasks_failed;
    struct timespec start_time;
    
    // Configuration
    size_t queue_capacity;
    bool enable_work_stealing;
    uint32_t steal_attempts;
    
    // Synchronization
    pthread_mutex_t pool_mutex;
    pthread_cond_t all_idle;
} thread_pool_t;

// Thread pool performance metrics
typedef struct {
    uint64_t total_tasks_submitted;
    uint64_t total_tasks_completed;
    uint64_t total_tasks_failed;
    uint64_t total_work_time_ns;
    uint64_t total_idle_time_ns;
    double cpu_utilization;
    double throughput_tasks_per_sec;
    uint64_t queue_depth;
    uint32_t active_threads;
    thread_stats_t* per_thread_stats;
    uint32_t thread_count;
} thread_pool_metrics_t;

// Function declarations
thread_pool_t* thread_pool_create(uint32_t thread_count, size_t queue_capacity);
int thread_pool_submit(thread_pool_t* pool, work_function_t function, 
                      void* data, void* context, work_priority_t priority);
int thread_pool_wait_all(thread_pool_t* pool);
int thread_pool_shutdown(thread_pool_t* pool, bool wait_for_completion);
void thread_pool_destroy(thread_pool_t* pool);

// Performance and monitoring
thread_pool_metrics_t* thread_pool_get_metrics(thread_pool_t* pool);
void thread_pool_metrics_destroy(thread_pool_metrics_t* metrics);
int thread_pool_set_work_stealing(thread_pool_t* pool, bool enable, uint32_t steal_attempts);

// Utility functions
uint32_t thread_pool_get_optimal_thread_count(void);
int thread_pool_validate_config(uint32_t thread_count, size_t queue_capacity);

// Work queue operations (internal)
work_queue_t* work_queue_create(size_t capacity);
void work_queue_destroy(work_queue_t* queue);
int work_queue_push(work_queue_t* queue, work_item_t* item);
work_item_t* work_queue_pop(work_queue_t* queue);
work_item_t* work_queue_steal(work_queue_t* queue);
bool work_queue_is_empty(work_queue_t* queue);
size_t work_queue_size(work_queue_t* queue);

#endif // THREAD_POOL_H
