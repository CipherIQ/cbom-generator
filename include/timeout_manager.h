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

#ifndef TIMEOUT_MANAGER_H
#define TIMEOUT_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>

// Timeout configuration limits
#define TIMEOUT_MIN_MS 100
#define TIMEOUT_MAX_MS (24 * 60 * 60 * 1000)  // 24 hours
#define TIMEOUT_DEFAULT_GLOBAL_MS (10 * 60 * 1000)  // 10 minutes
#define TIMEOUT_DEFAULT_PER_TASK_MS (30 * 1000)     // 30 seconds
#define RETRY_MAX_ATTEMPTS 5
#define RETRY_BASE_DELAY_MS 100
#define RETRY_MAX_DELAY_MS 30000

// Timeout result codes
typedef enum {
    TIMEOUT_SUCCESS = 0,
    TIMEOUT_EXPIRED = 1,
    TIMEOUT_CANCELLED = 2,
    TIMEOUT_ERROR = -1
} timeout_result_t;

// Retry policy configuration
typedef enum {
    RETRY_POLICY_NONE,
    RETRY_POLICY_FIXED_DELAY,
    RETRY_POLICY_EXPONENTIAL_BACKOFF,
    RETRY_POLICY_LINEAR_BACKOFF
} retry_policy_type_t;

typedef struct {
    retry_policy_type_t type;
    uint32_t max_attempts;
    uint32_t base_delay_ms;
    uint32_t max_delay_ms;
    double backoff_multiplier;  // For exponential backoff
    uint32_t linear_increment_ms;  // For linear backoff
    bool jitter_enabled;        // Add random jitter to delays
} retry_policy_t;

// Timeout context for individual operations
typedef struct timeout_context {
    uint64_t context_id;
    struct timespec deadline;
    struct timespec start_time;
    _Atomic bool is_cancelled;
    _Atomic bool is_expired;
    _Atomic bool is_destroyed;
    uint32_t timeout_ms;
    retry_policy_t retry_policy;
    uint32_t current_attempt;
    char operation_name[64];
    
    // Linked list for timeout manager
    struct timeout_context* next;
    struct timeout_context* prev;
} timeout_context_t;

// Global timeout manager
typedef struct {
    // Global wall-clock timeout
    struct timespec global_deadline;
    _Atomic bool global_timeout_enabled;
    _Atomic bool global_timeout_expired;
    uint32_t global_timeout_ms;
    
    // Active timeout contexts
    timeout_context_t* active_contexts;
    pthread_mutex_t contexts_mutex;
    _Atomic uint64_t next_context_id;
    
    // Timeout monitoring thread
    pthread_t monitor_thread;
    _Atomic bool monitor_running;
    int timerfd;  // Linux timerfd for efficient timeout monitoring
    
    // Statistics
    _Atomic uint64_t total_timeouts;
    _Atomic uint64_t total_cancellations;
    _Atomic uint64_t total_retries;
    
    // Configuration
    uint32_t default_timeout_ms;
    retry_policy_t default_retry_policy;
    bool graceful_degradation_enabled;
} timeout_manager_t;

// Timeout callback function signature
typedef timeout_result_t (*timeout_operation_t)(void* data, timeout_context_t* context);

// Function declarations

// Timeout manager lifecycle
timeout_manager_t* timeout_manager_create(uint32_t global_timeout_ms, uint32_t default_timeout_ms);
int timeout_manager_start(timeout_manager_t* manager);
int timeout_manager_stop(timeout_manager_t* manager);
void timeout_manager_destroy(timeout_manager_t* manager);

// Global timeout control
int timeout_manager_set_global_timeout(timeout_manager_t* manager, uint32_t timeout_ms);
bool timeout_manager_is_global_timeout_expired(timeout_manager_t* manager);
uint64_t timeout_manager_get_global_remaining_ms(timeout_manager_t* manager);

// Timeout context management
timeout_context_t* timeout_context_create(timeout_manager_t* manager, 
                                         const char* operation_name,
                                         uint32_t timeout_ms,
                                         const retry_policy_t* retry_policy);
void timeout_context_destroy(timeout_context_t* context);
bool timeout_context_is_expired(timeout_context_t* context);
bool timeout_context_is_cancelled(timeout_context_t* context);
uint64_t timeout_context_get_remaining_ms(timeout_context_t* context);
void timeout_context_cancel(timeout_context_t* context);

// Timeout-aware operations
timeout_result_t timeout_execute_with_retry(timeout_context_t* context,
                                           timeout_operation_t operation,
                                           void* data);
timeout_result_t timeout_execute_simple(timeout_manager_t* manager,
                                       const char* operation_name,
                                       uint32_t timeout_ms,
                                       timeout_operation_t operation,
                                       void* data);

// Retry policy helpers
retry_policy_t retry_policy_create_none(void);
retry_policy_t retry_policy_create_fixed(uint32_t max_attempts, uint32_t delay_ms);
retry_policy_t retry_policy_create_exponential(uint32_t max_attempts, 
                                              uint32_t base_delay_ms,
                                              uint32_t max_delay_ms,
                                              double multiplier);
retry_policy_t retry_policy_create_linear(uint32_t max_attempts,
                                         uint32_t base_delay_ms,
                                         uint32_t increment_ms);

// Graceful degradation helpers
bool timeout_should_continue_on_missing_tool(timeout_manager_t* manager, const char* tool_name);
bool timeout_should_continue_on_permission_error(timeout_manager_t* manager, const char* operation);
void timeout_log_degradation(timeout_manager_t* manager, const char* reason, const char* fallback);

// Utility functions
int timeout_validate_config(uint32_t timeout_ms);
uint32_t timeout_calculate_retry_delay(const retry_policy_t* policy, uint32_t attempt);
bool timeout_is_monotonic_supported(void);
struct timespec timeout_get_monotonic_time(void);
struct timespec timeout_add_ms(struct timespec base, uint32_t ms);
int timeout_compare_timespec(const struct timespec* a, const struct timespec* b);

// Statistics and monitoring
typedef struct {
    uint64_t total_contexts_created;
    uint64_t total_timeouts;
    uint64_t total_cancellations;
    uint64_t total_retries;
    uint64_t active_contexts;
    uint64_t global_remaining_ms;
    bool global_timeout_expired;
    double average_execution_time_ms;
    uint32_t current_retry_attempts;
} timeout_statistics_t;

timeout_statistics_t timeout_manager_get_statistics(timeout_manager_t* manager);

#endif // TIMEOUT_MANAGER_H
