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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>
#include "thread_pool.h"

// Test data structures
typedef struct {
    _Atomic int counter;
    int expected_value;
    int sleep_ms;
} test_work_data_t;

typedef struct {
    _Atomic int completed_tasks;
    _Atomic int failed_tasks;
    int total_tasks;
} test_context_t;

// Test work functions
static int simple_work_function(void* data, void* context) {
    test_work_data_t* work_data = (test_work_data_t*)data;
    test_context_t* test_context = (test_context_t*)context;
    
    if (work_data->sleep_ms > 0) {
        usleep(work_data->sleep_ms * 1000);
    }
    
    atomic_fetch_add(&work_data->counter, 1);
    atomic_fetch_add(&test_context->completed_tasks, 1);
    
    return 0;
}

static int failing_work_function(void* data, void* context) {
    (void)data; // Suppress unused parameter warning
    test_context_t* test_context = (test_context_t*)context;
    atomic_fetch_add(&test_context->failed_tasks, 1);
    return -1; // Simulate failure
}

static int cpu_intensive_work(void* data, void* context) {
    int* iterations = (int*)data;
    test_context_t* test_context = (test_context_t*)context;
    
    // Simulate CPU-intensive work
    volatile int sum = 0;
    for (int i = 0; i < *iterations; i++) {
        sum += i * i;
    }
    
    atomic_fetch_add(&test_context->completed_tasks, 1);
    return 0;
}

// Test functions
static void test_thread_pool_creation_and_destruction(void) {
    printf("Testing thread pool creation and destruction...\n");
    
    // Test with default thread count
    thread_pool_t* pool = thread_pool_create(THREAD_POOL_DEFAULT_THREADS, WORK_QUEUE_DEFAULT_SIZE);
    assert(pool != NULL);
    assert(pool->thread_count > 0);
    assert(pool->thread_count <= THREAD_POOL_MAX_THREADS);
    thread_pool_destroy(pool);
    
    // Test with specific thread count
    pool = thread_pool_create(4, 512);
    assert(pool != NULL);
    assert(pool->thread_count == 4);
    assert(pool->queue_capacity == 512);
    thread_pool_destroy(pool);
    
    // Test invalid configurations
    // Note: thread_count=0 is valid (auto-detect), so it should succeed
    pool = thread_pool_create(0, 512);
    assert(pool != NULL);  // 0 means auto-detect (valid)
    thread_pool_destroy(pool);

    pool = thread_pool_create(THREAD_POOL_MAX_THREADS + 1, 512);
    assert(pool == NULL);  // Exceeds max threads (invalid)

    pool = thread_pool_create(4, 0);
    assert(pool == NULL);  // Zero queue capacity (invalid)
    
    printf("✓ Thread pool creation and destruction tests passed\n");
}

static void test_basic_task_submission_and_execution(void) {
    printf("Testing basic task submission and execution...\n");
    
    thread_pool_t* pool = thread_pool_create(2, 64);
    assert(pool != NULL);
    
    test_work_data_t work_data;
    atomic_init(&work_data.counter, 0);
    work_data.expected_value = 10;
    work_data.sleep_ms = 0;
    
    test_context_t context;
    atomic_init(&context.completed_tasks, 0);
    atomic_init(&context.failed_tasks, 0);
    context.total_tasks = 10;
    
    // Submit multiple tasks
    for (int i = 0; i < 10; i++) {
        int result = thread_pool_submit(pool, simple_work_function, &work_data, &context, WORK_PRIORITY_NORMAL);
        assert(result == 0);
        (void)result; // Suppress unused warning
    }
    
    // Wait for all tasks to complete
    int wait_result = thread_pool_wait_all(pool);
    assert(wait_result == 0);
    (void)wait_result; // Suppress unused warning
    
    // Verify results
    assert(atomic_load(&work_data.counter) == 10);
    assert(atomic_load(&context.completed_tasks) == 10);
    assert(atomic_load(&context.failed_tasks) == 0);
    
    thread_pool_destroy(pool);
    printf("✓ Basic task submission and execution tests passed\n");
}

static void test_work_queue_operations(void) {
    printf("Testing work queue operations...\n");
    
    work_queue_t* queue = work_queue_create(10);
    assert(queue != NULL);
    assert(work_queue_is_empty(queue));
    assert(work_queue_size(queue) == 0);
    
    // Create test work items
    work_item_t* items[5];
    for (int i = 0; i < 5; i++) {
        items[i] = malloc(sizeof(work_item_t));
        items[i]->function = simple_work_function;
        items[i]->data = NULL;
        items[i]->context = NULL;
        items[i]->priority = WORK_PRIORITY_NORMAL;
        items[i]->sequence_id = i;
        
        int result = work_queue_push(queue, items[i]);
        assert(result == 0);
        (void)result; // Suppress unused warning
    }
    
    assert(!work_queue_is_empty(queue));
    assert(work_queue_size(queue) == 5);
    
    // Pop items and verify order
    for (int i = 0; i < 5; i++) {
        work_item_t* item = work_queue_pop(queue);
        assert(item != NULL);
        assert(item->sequence_id == (uint64_t)i);
        free(item);
    }
    
    assert(work_queue_is_empty(queue));
    assert(work_queue_size(queue) == 0);
    
    work_queue_destroy(queue);
    printf("✓ Work queue operations tests passed\n");
}

static void test_work_stealing(void) {
    printf("Testing work stealing...\n");
    
    thread_pool_t* pool = thread_pool_create(4, 128);
    assert(pool != NULL);
    
    // Enable work stealing
    int result = thread_pool_set_work_stealing(pool, true, 3);
    assert(result == 0);
    (void)result; // Suppress unused warning
    
    test_work_data_t work_data;
    atomic_init(&work_data.counter, 0);
    work_data.sleep_ms = 10; // Small delay to encourage work stealing
    
    test_context_t context;
    atomic_init(&context.completed_tasks, 0);
    atomic_init(&context.failed_tasks, 0);
    context.total_tasks = 100;
    
    // Submit many tasks quickly
    for (int i = 0; i < 100; i++) {
        result = thread_pool_submit(pool, simple_work_function, &work_data, &context, WORK_PRIORITY_NORMAL);
        assert(result == 0);
    }
    
    thread_pool_wait_all(pool);
    
    // Verify all tasks completed
    assert(atomic_load(&work_data.counter) == 100);
    assert(atomic_load(&context.completed_tasks) == 100);
    
    // Check that work stealing occurred
    thread_pool_metrics_t* metrics = thread_pool_get_metrics(pool);
    assert(metrics != NULL);
    
    uint64_t total_stolen = 0;
    for (uint32_t i = 0; i < metrics->thread_count; i++) {
        total_stolen += atomic_load(&metrics->per_thread_stats[i].tasks_stolen);
    }
    
    printf("  Total tasks stolen: %lu\n", total_stolen);
    // Work stealing should have occurred with this workload
    assert(total_stolen > 0);
    
    thread_pool_metrics_destroy(metrics);
    thread_pool_destroy(pool);
    printf("✓ Work stealing tests passed\n");
}

static void test_error_handling_and_failed_tasks(void) {
    printf("Testing error handling and failed tasks...\n");
    
    thread_pool_t* pool = thread_pool_create(2, 32);
    assert(pool != NULL);
    
    test_context_t context;
    atomic_init(&context.completed_tasks, 0);
    atomic_init(&context.failed_tasks, 0);
    context.total_tasks = 10;
    
    // Submit tasks that will fail
    for (int i = 0; i < 10; i++) {
        int result = thread_pool_submit(pool, failing_work_function, NULL, &context, WORK_PRIORITY_NORMAL);
        assert(result == 0);
        (void)result; // Suppress unused warning
    }
    
    thread_pool_wait_all(pool);
    
    // Verify failure tracking
    assert(atomic_load(&context.failed_tasks) == 10);
    
    thread_pool_metrics_t* metrics = thread_pool_get_metrics(pool);
    assert(metrics != NULL);
    assert(metrics->total_tasks_failed == 10);
    
    // Check that warnings were recorded
    bool found_warnings = false;
    for (uint32_t i = 0; i < metrics->thread_count; i++) {
        if (atomic_load(&metrics->per_thread_stats[i].warning_count) > 0) {
            found_warnings = true;
            break;
        }
    }
    assert(found_warnings);
    (void)found_warnings; // Suppress unused warning
    
    thread_pool_metrics_destroy(metrics);
    thread_pool_destroy(pool);
    printf("✓ Error handling and failed tasks tests passed\n");
}

static void test_performance_metrics(void) {
    printf("Testing performance metrics...\n");
    
    thread_pool_t* pool = thread_pool_create(4, 64);
    assert(pool != NULL);
    
    int iterations = 10000;
    test_context_t context;
    atomic_init(&context.completed_tasks, 0);
    atomic_init(&context.failed_tasks, 0);
    context.total_tasks = 20;
    
    // Submit CPU-intensive tasks
    for (int i = 0; i < 20; i++) {
        int result = thread_pool_submit(pool, cpu_intensive_work, &iterations, &context, WORK_PRIORITY_NORMAL);
        assert(result == 0);
        (void)result; // Suppress unused warning
    }
    
    thread_pool_wait_all(pool);
    
    thread_pool_metrics_t* metrics = thread_pool_get_metrics(pool);
    assert(metrics != NULL);
    
    printf("  Tasks submitted: %lu\n", metrics->total_tasks_submitted);
    printf("  Tasks completed: %lu\n", metrics->total_tasks_completed);
    printf("  Tasks failed: %lu\n", metrics->total_tasks_failed);
    printf("  CPU utilization: %.2f%%\n", metrics->cpu_utilization * 100.0);
    printf("  Throughput: %.2f tasks/sec\n", metrics->throughput_tasks_per_sec);
    printf("  Active threads: %u\n", metrics->active_threads);
    
    assert(metrics->total_tasks_submitted == 20);
    assert(metrics->total_tasks_completed == 20);
    assert(metrics->total_tasks_failed == 0);
    assert(metrics->cpu_utilization >= 0.0 && metrics->cpu_utilization <= 1.0);
    assert(metrics->throughput_tasks_per_sec > 0.0);
    
    // Verify per-thread statistics
    for (uint32_t i = 0; i < metrics->thread_count; i++) {
        thread_stats_t* stats = &metrics->per_thread_stats[i];
        assert(stats->thread_id == i);
        printf("  Thread %u: completed=%lu, work_time=%lu ns\n", 
               i, atomic_load(&stats->tasks_completed), atomic_load(&stats->total_work_time_ns));
    }
    
    thread_pool_metrics_destroy(metrics);
    thread_pool_destroy(pool);
    printf("✓ Performance metrics tests passed\n");
}

static void test_atomic_operations_and_thread_safety(void) {
    printf("Testing atomic operations and thread safety...\n");
    
    thread_pool_t* pool = thread_pool_create(8, 256);
    assert(pool != NULL);
    
    // Shared counter that all threads will increment
    _Atomic int shared_counter = 0;
    test_context_t context;
    atomic_init(&context.completed_tasks, 0);
    atomic_init(&context.failed_tasks, 0);
    context.total_tasks = 1000;
    
    // Work function that increments shared counter
    int increment_counter_work(void* data, void* context) {
        _Atomic int* counter = (_Atomic int*)data;
        test_context_t* test_context = (test_context_t*)context;
        
        atomic_fetch_add(counter, 1);
        atomic_fetch_add(&test_context->completed_tasks, 1);
        return 0;
    }
    
    // Submit many tasks that all increment the same counter
    for (int i = 0; i < 1000; i++) {
        int result = thread_pool_submit(pool, increment_counter_work, &shared_counter, &context, WORK_PRIORITY_NORMAL);
        assert(result == 0);
        (void)result; // Suppress unused warning
    }
    
    thread_pool_wait_all(pool);
    
    // Verify atomic operations worked correctly
    assert(atomic_load(&shared_counter) == 1000);
    assert(atomic_load(&context.completed_tasks) == 1000);
    
    thread_pool_destroy(pool);
    printf("✓ Atomic operations and thread safety tests passed\n");
}

static void test_shutdown_and_cleanup(void) {
    printf("Testing shutdown and cleanup...\n");
    
    thread_pool_t* pool = thread_pool_create(4, 64);
    assert(pool != NULL);
    
    test_work_data_t work_data;
    atomic_init(&work_data.counter, 0);
    work_data.sleep_ms = 50; // Longer delay
    
    test_context_t context;
    atomic_init(&context.completed_tasks, 0);
    atomic_init(&context.failed_tasks, 0);
    context.total_tasks = 10;
    
    // Submit tasks
    for (int i = 0; i < 10; i++) {
        int result = thread_pool_submit(pool, simple_work_function, &work_data, &context, WORK_PRIORITY_NORMAL);
        assert(result == 0);
        (void)result; // Suppress unused warning
    }
    
    // Test graceful shutdown (wait for completion)
    int result = thread_pool_shutdown(pool, true);
    assert(result == 0);
    (void)result; // Suppress unused warning
    
    // Verify all tasks completed
    assert(atomic_load(&work_data.counter) == 10);
    assert(atomic_load(&context.completed_tasks) == 10);
    
    thread_pool_destroy(pool);
    
    // Test immediate shutdown (don't wait)
    pool = thread_pool_create(2, 32);
    assert(pool != NULL);
    
    atomic_store(&work_data.counter, 0);
    atomic_store(&context.completed_tasks, 0);
    work_data.sleep_ms = 100; // Even longer delay
    
    for (int i = 0; i < 5; i++) {
        thread_pool_submit(pool, simple_work_function, &work_data, &context, WORK_PRIORITY_NORMAL);
    }
    
    // Immediate shutdown
    result = thread_pool_shutdown(pool, false);
    assert(result == 0);
    
    thread_pool_destroy(pool);
    printf("✓ Shutdown and cleanup tests passed\n");
}

static void test_configuration_validation(void) {
    printf("Testing configuration validation...\n");
    
    // Test thread count validation
    assert(thread_pool_validate_config(0, 512) != 0);
    assert(thread_pool_validate_config(THREAD_POOL_MAX_THREADS + 1, 512) != 0);
    assert(thread_pool_validate_config(4, 0) != 0);
    assert(thread_pool_validate_config(4, SIZE_MAX) != 0);
    assert(thread_pool_validate_config(4, 512) == 0);
    
    // Test optimal thread count
    uint32_t optimal = thread_pool_get_optimal_thread_count();
    assert(optimal >= THREAD_POOL_MIN_THREADS);
    assert(optimal <= THREAD_POOL_MAX_THREADS);
    
    printf("  Optimal thread count: %u\n", optimal);
    printf("✓ Configuration validation tests passed\n");
}

int run_thread_pool_tests(void) {
    printf("Running thread pool tests...\n\n");
    
    test_thread_pool_creation_and_destruction();
    test_basic_task_submission_and_execution();
    test_work_queue_operations();
    test_work_stealing();
    test_error_handling_and_failed_tasks();
    test_performance_metrics();
    test_atomic_operations_and_thread_safety();
    test_shutdown_and_cleanup();
    test_configuration_validation();
    
    printf("\n✅ All thread pool tests passed!\n");
    return 0;
}
