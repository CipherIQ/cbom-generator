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
#include <pthread.h>
#include "timeout_manager.h"

// Test data structures
typedef struct {
    int value;
    int sleep_ms;
    bool should_fail;
    _Atomic int call_count;
} test_operation_data_t;

// Test operation functions
static timeout_result_t simple_operation(void* data, timeout_context_t* context) {
    test_operation_data_t* op_data = (test_operation_data_t*)data;
    atomic_fetch_add(&op_data->call_count, 1);
    
    if (op_data->sleep_ms > 0) {
        usleep(op_data->sleep_ms * 1000);
    }
    
    // Check if we should simulate failure
    if (op_data->should_fail) {
        return TIMEOUT_ERROR;
    }
    
    // Check for timeout during operation
    if (timeout_context_is_expired(context)) {
        return TIMEOUT_EXPIRED;
    }
    
    if (timeout_context_is_cancelled(context)) {
        return TIMEOUT_CANCELLED;
    }
    
    op_data->value = 42;
    return TIMEOUT_SUCCESS;
}

static timeout_result_t long_running_operation(void* data, timeout_context_t* context) {
    test_operation_data_t* op_data = (test_operation_data_t*)data;
    atomic_fetch_add(&op_data->call_count, 1);
    
    // Simulate long-running operation with periodic timeout checks
    for (int i = 0; i < 100; i++) {
        usleep(10000); // 10ms
        
        if (timeout_context_is_expired(context) || timeout_context_is_cancelled(context)) {
            return timeout_context_is_expired(context) ? TIMEOUT_EXPIRED : TIMEOUT_CANCELLED;
        }
    }
    
    op_data->value = 100;
    return TIMEOUT_SUCCESS;
}

static timeout_result_t failing_operation(void* data, timeout_context_t* context) {
    (void)context; // Suppress unused parameter warning
    test_operation_data_t* op_data = (test_operation_data_t*)data;
    atomic_fetch_add(&op_data->call_count, 1);
    
    if (op_data->sleep_ms > 0) {
        usleep(op_data->sleep_ms * 1000);
    }
    
    return TIMEOUT_ERROR; // Always fail
}

// Test functions
static void test_timeout_manager_creation_and_destruction(void) {
    printf("Testing timeout manager creation and destruction...\n");
    
    // Test valid creation
    timeout_manager_t* manager = timeout_manager_create(10000, 5000);
    assert(manager != NULL);
    assert(manager->global_timeout_ms == 10000);
    assert(manager->default_timeout_ms == 5000);
    timeout_manager_destroy(manager);
    
    // Test invalid configurations
    manager = timeout_manager_create(0, 5000);
    assert(manager == NULL);
    
    manager = timeout_manager_create(10000, TIMEOUT_MAX_MS + 1);
    assert(manager == NULL);
    
    printf("✓ Timeout manager creation and destruction tests passed\n");
}

static void test_timeout_context_creation_and_management(void) {
    printf("Testing timeout context creation and management...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 1000);
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    (void)result; // Suppress unused warning
    
    // Create timeout context
    timeout_context_t* context = timeout_context_create(manager, "test_operation", 2000, NULL);
    assert(context != NULL);
    assert(context->timeout_ms == 2000);
    assert(strcmp(context->operation_name, "test_operation") == 0);
    assert(!timeout_context_is_expired(context));
    assert(!timeout_context_is_cancelled(context));
    
    // Test remaining time
    uint64_t remaining = timeout_context_get_remaining_ms(context);
    assert(remaining > 1500 && remaining <= 2000);
    (void)remaining; // Suppress unused warning
    
    // Test cancellation
    timeout_context_cancel(context);
    assert(timeout_context_is_cancelled(context));
    
    timeout_context_destroy(context);
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Timeout context creation and management tests passed\n");
}

static void test_simple_timeout_execution(void) {
    printf("Testing simple timeout execution...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 1000);
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    
    // Test successful operation
    test_operation_data_t op_data = {0};
    atomic_init(&op_data.call_count, 0);
    op_data.sleep_ms = 100;
    op_data.should_fail = false;
    
    timeout_result_t timeout_result = timeout_execute_simple(manager, "test_op", 2000, 
                                                           simple_operation, &op_data);
    
    assert(timeout_result == TIMEOUT_SUCCESS);
    assert(op_data.value == 42);
    assert(atomic_load(&op_data.call_count) == 1);
    
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Simple timeout execution tests passed\n");
}

static void test_timeout_expiration(void) {
    printf("Testing timeout expiration...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 1000);
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    
    // Test operation that times out
    test_operation_data_t op_data = {0};
    atomic_init(&op_data.call_count, 0);
    op_data.sleep_ms = 2000; // Sleep longer than timeout
    op_data.should_fail = false;
    
    timeout_result_t timeout_result = timeout_execute_simple(manager, "timeout_test", 500, 
                                                           simple_operation, &op_data);
    
    assert(timeout_result == TIMEOUT_EXPIRED);
    assert(atomic_load(&op_data.call_count) == 1);
    
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Timeout expiration tests passed\n");
}

static void test_retry_policies(void) {
    printf("Testing retry policies...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 5000);
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    
    // Test exponential backoff retry policy with short delays for testing
    retry_policy_t retry_policy = retry_policy_create_exponential(3, 10, 50, 2.0);
    
    timeout_context_t* context = timeout_context_create(manager, "retry_test", 1000, &retry_policy);
    assert(context != NULL);
    
    test_operation_data_t op_data = {0};
    atomic_init(&op_data.call_count, 0);
    op_data.sleep_ms = 5; // Much shorter sleep for testing
    op_data.should_fail = true; // Will fail and retry
    
    timeout_result_t timeout_result = timeout_execute_with_retry(context, failing_operation, &op_data);
    
    assert(timeout_result == TIMEOUT_ERROR); // Final result after all retries
    assert(atomic_load(&op_data.call_count) == 3); // Should have tried 3 times
    assert(context->current_attempt == 3);
    
    // Note: Context is still in manager's active list, will be cleaned up by manager
    
    // Test fixed delay retry policy with short delays for testing
    retry_policy = retry_policy_create_fixed(2, 20);
    context = timeout_context_create(manager, "fixed_retry_test", 500, &retry_policy);
    assert(context != NULL);
    
    atomic_store(&op_data.call_count, 0);
    timeout_result = timeout_execute_with_retry(context, failing_operation, &op_data);
    
    assert(timeout_result == TIMEOUT_ERROR);
    assert(atomic_load(&op_data.call_count) == 2); // Should have tried 2 times
    
    // Note: Context is still in manager's active list, will be cleaned up by manager
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Retry policies tests passed\n");
}

static void test_retry_delay_calculation(void) {
    printf("Testing retry delay calculation...\n");
    
    // Test exponential backoff
    retry_policy_t policy = retry_policy_create_exponential(5, 100, 5000, 2.0);
    policy.jitter_enabled = false; // Disable jitter for predictable testing
    
    uint32_t delay1 = timeout_calculate_retry_delay(&policy, 1);
    uint32_t delay2 = timeout_calculate_retry_delay(&policy, 2);
    uint32_t delay3 = timeout_calculate_retry_delay(&policy, 3);
    
    assert(delay1 == 100);  // 100 * 2^0
    assert(delay2 == 200);  // 100 * 2^1
    assert(delay3 == 400);  // 100 * 2^2
    
    // Test linear backoff
    policy = retry_policy_create_linear(5, 100, 50);
    policy.jitter_enabled = false;
    
    delay1 = timeout_calculate_retry_delay(&policy, 1);
    delay2 = timeout_calculate_retry_delay(&policy, 2);
    delay3 = timeout_calculate_retry_delay(&policy, 3);
    
    assert(delay1 == 100);  // 100 + 50*0
    assert(delay2 == 150);  // 100 + 50*1
    assert(delay3 == 200);  // 100 + 50*2
    
    // Test fixed delay
    policy = retry_policy_create_fixed(3, 300);
    
    delay1 = timeout_calculate_retry_delay(&policy, 1);
    delay2 = timeout_calculate_retry_delay(&policy, 2);
    delay3 = timeout_calculate_retry_delay(&policy, 3);
    
    assert(delay1 == 300);
    assert(delay2 == 300);
    assert(delay3 == 300);
    
    printf("✓ Retry delay calculation tests passed\n");
}

static void test_global_timeout(void) {
    printf("Testing global timeout...\n");
    
    timeout_manager_t* manager = timeout_manager_create(2000, 1000); // 2 second global timeout
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    
    // Check initial state
    assert(!timeout_manager_is_global_timeout_expired(manager));
    uint64_t remaining = timeout_manager_get_global_remaining_ms(manager);
    assert(remaining > 1500 && remaining <= 2000);
    
    // Create a context and wait for global timeout
    timeout_context_t* context = timeout_context_create(manager, "global_timeout_test", 5000, NULL);
    assert(context != NULL);
    
    test_operation_data_t op_data = {0};
    atomic_init(&op_data.call_count, 0);
    op_data.sleep_ms = 3000; // Sleep longer than global timeout
    
    timeout_result_t timeout_result = timeout_execute_with_retry(context, simple_operation, &op_data);
    
    // Should be cancelled due to global timeout
    assert(timeout_result == TIMEOUT_CANCELLED || timeout_result == TIMEOUT_EXPIRED);
    assert(timeout_context_is_cancelled(context));
    
    timeout_context_destroy(context);
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Global timeout tests passed\n");
}

static void test_cooperative_cancellation(void) {
    printf("Testing cooperative cancellation...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 5000);
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    
    timeout_context_t* context = timeout_context_create(manager, "cancellation_test", 5000, NULL);
    assert(context != NULL);
    
    test_operation_data_t op_data = {0};
    atomic_init(&op_data.call_count, 0);
    op_data.sleep_ms = 0;
    
    // Start operation in a separate thread and cancel it
    pthread_t operation_thread;
    
    typedef struct {
        timeout_context_t* context;
        timeout_operation_t operation;
        void* data;
        timeout_result_t result;
    } thread_data_t;
    
    thread_data_t thread_data = {
        .context = context,
        .operation = long_running_operation,
        .data = &op_data,
        .result = TIMEOUT_ERROR
    };
    
    void* operation_thread_func(void* arg) {
        thread_data_t* td = (thread_data_t*)arg;
        td->result = timeout_execute_with_retry(td->context, td->operation, td->data);
        return NULL;
    }
    
    pthread_create(&operation_thread, NULL, operation_thread_func, &thread_data);
    
    // Let operation start, then cancel it
    usleep(100000); // 100ms
    timeout_context_cancel(context);
    
    pthread_join(operation_thread, NULL);
    
    assert(thread_data.result == TIMEOUT_CANCELLED);
    assert(timeout_context_is_cancelled(context));
    
    timeout_context_destroy(context);
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Cooperative cancellation tests passed\n");
}

static void test_graceful_degradation(void) {
    printf("Testing graceful degradation...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 5000);
    assert(manager != NULL);
    assert(manager->graceful_degradation_enabled == true);
    
    // Test missing tool handling
    bool should_continue = timeout_should_continue_on_missing_tool(manager, "missing_tool");
    assert(should_continue == true);
    
    // Test permission error handling
    should_continue = timeout_should_continue_on_permission_error(manager, "restricted_operation");
    assert(should_continue == true);
    
    // Test with degradation disabled
    manager->graceful_degradation_enabled = false;
    should_continue = timeout_should_continue_on_missing_tool(manager, "missing_tool");
    assert(should_continue == false);
    
    timeout_manager_destroy(manager);
    
    printf("✓ Graceful degradation tests passed\n");
}

static void test_timeout_statistics(void) {
    printf("Testing timeout statistics...\n");
    
    timeout_manager_t* manager = timeout_manager_create(10000, 1000);
    assert(manager != NULL);
    
    int result = timeout_manager_start(manager);
    assert(result == 0);
    
    // Execute some operations to generate statistics
    test_operation_data_t op_data = {0};
    atomic_init(&op_data.call_count, 0);
    op_data.sleep_ms = 100;
    op_data.should_fail = false;
    
    // Successful operation
    timeout_result_t timeout_result = timeout_execute_simple(manager, "stats_test1", 2000, 
                                                           simple_operation, &op_data);
    assert(timeout_result == TIMEOUT_SUCCESS);
    
    // Failed operation with retries
    retry_policy_t retry_policy = retry_policy_create_fixed(2, 100);
    timeout_context_t* context = timeout_context_create(manager, "stats_test2", 3000, &retry_policy);
    atomic_store(&op_data.call_count, 0);
    timeout_result = timeout_execute_with_retry(context, failing_operation, &op_data);
    timeout_context_destroy(context);
    
    // Get statistics
    timeout_statistics_t stats = timeout_manager_get_statistics(manager);
    
    printf("  Total contexts created: %lu\n", stats.total_contexts_created);
    printf("  Total timeouts: %lu\n", stats.total_timeouts);
    printf("  Total cancellations: %lu\n", stats.total_cancellations);
    printf("  Active contexts: %lu\n", stats.active_contexts);
    printf("  Global remaining: %lu ms\n", stats.global_remaining_ms);
    
    assert(stats.total_contexts_created >= 2);
    assert(stats.global_remaining_ms > 0);
    
    timeout_manager_stop(manager);
    timeout_manager_destroy(manager);
    
    printf("✓ Timeout statistics tests passed\n");
}

static void test_utility_functions(void) {
    printf("Testing utility functions...\n");
    
    // Test configuration validation
    assert(timeout_validate_config(500) == 0);
    assert(timeout_validate_config(TIMEOUT_MIN_MS - 1) != 0);
    assert(timeout_validate_config(TIMEOUT_MAX_MS + 1) != 0);
    
    // Test monotonic time support
    assert(timeout_is_monotonic_supported() == true);
    
    // Test time arithmetic
    struct timespec base = {.tv_sec = 10, .tv_nsec = 500000000}; // 10.5 seconds
    struct timespec result = timeout_add_ms(base, 1500); // Add 1.5 seconds
    
    assert(result.tv_sec == 12);
    assert(result.tv_nsec == 0);
    
    // Test time comparison
    struct timespec time1 = {.tv_sec = 10, .tv_nsec = 0};
    struct timespec time2 = {.tv_sec = 10, .tv_nsec = 1};
    struct timespec time3 = {.tv_sec = 11, .tv_nsec = 0};
    
    assert(timeout_compare_timespec(&time1, &time2) < 0);
    assert(timeout_compare_timespec(&time2, &time1) > 0);
    assert(timeout_compare_timespec(&time1, &time1) == 0);
    assert(timeout_compare_timespec(&time1, &time3) < 0);
    
    printf("✓ Utility functions tests passed\n");
}

int run_timeout_manager_tests(void) {
    printf("Running timeout manager tests...\n\n");
    
    test_timeout_manager_creation_and_destruction();
    test_timeout_context_creation_and_management();
    test_simple_timeout_execution();
    test_timeout_expiration();
    test_retry_policies();
    test_retry_delay_calculation();
    test_global_timeout();
    test_cooperative_cancellation();
    test_graceful_degradation();
    test_timeout_statistics();
    test_utility_functions();
    
    printf("\n✅ All timeout manager tests passed!\n");
    return 0;
}
