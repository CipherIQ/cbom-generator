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

#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include "timeout_manager.h"
#include "error_handling.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <math.h>
#include <stdio.h>

// Internal helper functions
static void* timeout_monitor_thread(void* arg);
static int timeout_setup_timerfd(timeout_manager_t* manager);
static void timeout_check_contexts(timeout_manager_t* manager);
static void timeout_add_context(timeout_manager_t* manager, timeout_context_t* context);
static void timeout_remove_context(timeout_manager_t* manager, timeout_context_t* context);
static uint32_t timeout_add_jitter(uint32_t delay_ms);

timeout_manager_t* timeout_manager_create(uint32_t global_timeout_ms, uint32_t default_timeout_ms) {
    if (timeout_validate_config(global_timeout_ms) != 0 || 
        timeout_validate_config(default_timeout_ms) != 0) {
        return NULL;
    }
    
    timeout_manager_t* manager = calloc(1, sizeof(timeout_manager_t));
    if (!manager) {
        return NULL;
    }
    
    // Initialize configuration
    manager->global_timeout_ms = global_timeout_ms;
    manager->default_timeout_ms = default_timeout_ms;
    manager->graceful_degradation_enabled = true;
    
    // Initialize atomic variables
    atomic_init(&manager->global_timeout_enabled, false);
    atomic_init(&manager->global_timeout_expired, false);
    atomic_init(&manager->next_context_id, 1);
    atomic_init(&manager->monitor_running, false);
    atomic_init(&manager->total_timeouts, 0);
    atomic_init(&manager->total_cancellations, 0);
    atomic_init(&manager->total_retries, 0);
    
    // Initialize mutex
    if (pthread_mutex_init(&manager->contexts_mutex, NULL) != 0) {
        free(manager);
        return NULL;
    }
    
    // Set up default retry policy
    manager->default_retry_policy = retry_policy_create_exponential(3, 100, 5000, 2.0);
    
    // Initialize timerfd (will be set up when started)
    manager->timerfd = -1;
    
    return manager;
}

int timeout_manager_start(timeout_manager_t* manager) {
    if (!manager || atomic_load(&manager->monitor_running)) {
        return -1;
    }
    
    // Set up timerfd for efficient timeout monitoring
    if (timeout_setup_timerfd(manager) != 0) {
        return -1;
    }
    
    // Set global deadline if global timeout is configured
    if (manager->global_timeout_ms > 0) {
        manager->global_deadline = timeout_add_ms(timeout_get_monotonic_time(), 
                                                 manager->global_timeout_ms);
        atomic_store(&manager->global_timeout_enabled, true);
    }
    
    // Start monitoring thread
    atomic_store(&manager->monitor_running, true);
    if (pthread_create(&manager->monitor_thread, NULL, timeout_monitor_thread, manager) != 0) {
        atomic_store(&manager->monitor_running, false);
        if (manager->timerfd >= 0) {
            close(manager->timerfd);
            manager->timerfd = -1;
        }
        return -1;
    }
    
    return 0;
}

int timeout_manager_stop(timeout_manager_t* manager) {
    if (!manager || !atomic_load(&manager->monitor_running)) {
        return -1;
    }
    
    // Signal monitor thread to stop
    atomic_store(&manager->monitor_running, false);
    
    // Wake up monitor thread by writing to timerfd
    if (manager->timerfd >= 0) {
        struct itimerspec timer_spec = {0};
        timer_spec.it_value.tv_nsec = 1; // Immediate expiration
        timerfd_settime(manager->timerfd, 0, &timer_spec, NULL);
    }
    
    // Wait for monitor thread to finish
    pthread_join(manager->monitor_thread, NULL);
    
    // Close timerfd
    if (manager->timerfd >= 0) {
        close(manager->timerfd);
        manager->timerfd = -1;
    }
    
    return 0;
}

void timeout_manager_destroy(timeout_manager_t* manager) {
    if (!manager) return;
    
    // Stop monitoring if running
    if (atomic_load(&manager->monitor_running)) {
        timeout_manager_stop(manager);
    }
    
    // Cancel and cleanup all active contexts
    pthread_mutex_lock(&manager->contexts_mutex);
    timeout_context_t* context = manager->active_contexts;
    while (context) {
        timeout_context_t* next = context->next;
        timeout_context_cancel(context);
        timeout_context_destroy(context);
        context = next;
    }
    pthread_mutex_unlock(&manager->contexts_mutex);
    
    // Cleanup synchronization objects
    pthread_mutex_destroy(&manager->contexts_mutex);
    
    free(manager);
}

static int timeout_setup_timerfd(timeout_manager_t* manager) {
    manager->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (manager->timerfd < 0) {
        return -1;
    }
    
    // Set up initial timer (will be updated as contexts are added)
    struct itimerspec timer_spec = {0};
    timer_spec.it_value.tv_sec = 1; // Check every second initially
    timer_spec.it_interval.tv_sec = 1; // Repeat every second
    
    if (timerfd_settime(manager->timerfd, 0, &timer_spec, NULL) < 0) {
        close(manager->timerfd);
        manager->timerfd = -1;
        return -1;
    }
    
    return 0;
}

static void* timeout_monitor_thread(void* arg) {
    timeout_manager_t* manager = (timeout_manager_t*)arg;
    
    while (atomic_load(&manager->monitor_running)) {
        // Wait for timer expiration with a timeout to avoid blocking indefinitely
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(manager->timerfd, &readfds);
        
        struct timeval timeout = {1, 0}; // 1 second timeout
        int select_result = select(manager->timerfd + 1, &readfds, NULL, NULL, &timeout);
        
        if (select_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; // Error occurred
        }
        
        if (!atomic_load(&manager->monitor_running)) {
            break;
        }
        
        if (select_result > 0 && FD_ISSET(manager->timerfd, &readfds)) {
            // Read from timerfd to clear the event
            uint64_t expirations;
            ssize_t read_result = read(manager->timerfd, &expirations, sizeof(expirations));
            (void)read_result; // Suppress unused result warning
        }
        
        // Check global timeout
        if (atomic_load(&manager->global_timeout_enabled) && 
            !atomic_load(&manager->global_timeout_expired)) {
            struct timespec now = timeout_get_monotonic_time();
            if (timeout_compare_timespec(&now, &manager->global_deadline) >= 0) {
                atomic_store(&manager->global_timeout_expired, true);
                
                // Cancel all active contexts (use trylock to avoid deadlock)
                if (pthread_mutex_trylock(&manager->contexts_mutex) == 0) {
                    timeout_context_t* context = manager->active_contexts;
                    while (context) {
                        timeout_context_cancel(context);
                        context = context->next;
                    }
                    pthread_mutex_unlock(&manager->contexts_mutex);
                }
            }
        }
        
        // Check individual context timeouts
        timeout_check_contexts(manager);
    }
    
    return NULL;
}

static void timeout_check_contexts(timeout_manager_t* manager) {
    struct timespec now = timeout_get_monotonic_time();
    
    // Use trylock to avoid deadlock with other operations
    if (pthread_mutex_trylock(&manager->contexts_mutex) != 0) {
        return; // Skip this check if mutex is busy
    }
    
    timeout_context_t* context = manager->active_contexts;
    while (context) {
        timeout_context_t* next = context->next;
        
        if (!atomic_load(&context->is_cancelled) && 
            !atomic_load(&context->is_expired) &&
            timeout_compare_timespec(&now, &context->deadline) >= 0) {
            
            atomic_store(&context->is_expired, true);
            atomic_fetch_add(&manager->total_timeouts, 1);
        }
        
        context = next;
    }
    
    pthread_mutex_unlock(&manager->contexts_mutex);
}

timeout_context_t* timeout_context_create(timeout_manager_t* manager, 
                                         const char* operation_name,
                                         uint32_t timeout_ms,
                                         const retry_policy_t* retry_policy) {
    if (!manager || !operation_name) {
        return NULL;
    }
    
    if (timeout_ms == 0) {
        timeout_ms = manager->default_timeout_ms;
    }
    
    if (timeout_validate_config(timeout_ms) != 0) {
        return NULL;
    }
    
    timeout_context_t* context = calloc(1, sizeof(timeout_context_t));
    if (!context) {
        return NULL;
    }
    
    // Initialize context
    context->context_id = atomic_fetch_add(&manager->next_context_id, 1);
    context->timeout_ms = timeout_ms;
    context->current_attempt = 0;
    strncpy(context->operation_name, operation_name, sizeof(context->operation_name) - 1);
    
    // Set timing
    context->start_time = timeout_get_monotonic_time();
    context->deadline = timeout_add_ms(context->start_time, timeout_ms);
    
    // Initialize atomic flags
    atomic_init(&context->is_cancelled, false);
    atomic_init(&context->is_expired, false);
    atomic_init(&context->is_destroyed, false);
    
    // Set retry policy
    if (retry_policy) {
        context->retry_policy = *retry_policy;
    } else {
        context->retry_policy = manager->default_retry_policy;
    }
    
    // Add to manager's active contexts
    timeout_add_context(manager, context);
    
    return context;
}

void timeout_context_destroy(timeout_context_t* context) {
    if (!context) return;
    
    // Check if already destroyed
    if (atomic_exchange(&context->is_destroyed, true)) {
        return; // Already destroyed
    }
    
    // Note: Context should be removed from manager's list before destruction
    // This is the caller's responsibility to avoid circular dependencies
    free(context);
}

static void timeout_add_context(timeout_manager_t* manager, timeout_context_t* context) {
    pthread_mutex_lock(&manager->contexts_mutex);
    
    // Add to front of linked list
    context->next = manager->active_contexts;
    context->prev = NULL;
    
    if (manager->active_contexts) {
        manager->active_contexts->prev = context;
    }
    
    manager->active_contexts = context;
    
    pthread_mutex_unlock(&manager->contexts_mutex);
}

static void timeout_remove_context(timeout_manager_t* manager, timeout_context_t* context) {
    pthread_mutex_lock(&manager->contexts_mutex);
    
    // Remove from linked list
    if (context->prev) {
        context->prev->next = context->next;
    } else {
        manager->active_contexts = context->next;
    }
    
    if (context->next) {
        context->next->prev = context->prev;
    }
    
    // Clear the context's list pointers to prevent double-removal
    context->prev = NULL;
    context->next = NULL;
    
    pthread_mutex_unlock(&manager->contexts_mutex);
}

bool timeout_context_is_expired(timeout_context_t* context) {
    if (!context) return true;
    
    if (atomic_load(&context->is_expired)) {
        return true;
    }
    
    struct timespec now = timeout_get_monotonic_time();
    return timeout_compare_timespec(&now, &context->deadline) >= 0;
}

bool timeout_context_is_cancelled(timeout_context_t* context) {
    return context ? atomic_load(&context->is_cancelled) : true;
}

uint64_t timeout_context_get_remaining_ms(timeout_context_t* context) {
    if (!context || timeout_context_is_expired(context) || timeout_context_is_cancelled(context)) {
        return 0;
    }
    
    struct timespec now = timeout_get_monotonic_time();
    if (timeout_compare_timespec(&now, &context->deadline) >= 0) {
        return 0;
    }
    
    uint64_t remaining_ns = (context->deadline.tv_sec - now.tv_sec) * 1000000000ULL +
                           (context->deadline.tv_nsec - now.tv_nsec);
    return remaining_ns / 1000000; // Convert to milliseconds
}

void timeout_context_cancel(timeout_context_t* context) {
    if (context) {
        atomic_store(&context->is_cancelled, true);
    }
}

timeout_result_t timeout_execute_with_retry(timeout_context_t* context,
                                           timeout_operation_t operation,
                                           void* data) {
    if (!context || !operation) {
        return TIMEOUT_ERROR;
    }
    
    timeout_result_t result = TIMEOUT_ERROR;
    
    while (context->current_attempt < context->retry_policy.max_attempts) {
        // Check for timeout or cancellation before each attempt
        if (timeout_context_is_expired(context)) {
            result = TIMEOUT_EXPIRED;
            break;
        }
        
        if (timeout_context_is_cancelled(context)) {
            result = TIMEOUT_CANCELLED;
            break;
        }
        
        context->current_attempt++;
        
        // Execute the operation
        result = operation(data, context);
        
        if (result == TIMEOUT_SUCCESS) {
            break; // Success, no retry needed
        }
        
        if (result == TIMEOUT_CANCELLED || result == TIMEOUT_EXPIRED) {
            break; // Don't retry on timeout/cancellation
        }
        
        // Calculate retry delay
        if (context->current_attempt < context->retry_policy.max_attempts) {
            uint32_t delay_ms = timeout_calculate_retry_delay(&context->retry_policy, 
                                                            context->current_attempt);
            
            // Check if we have enough time left for the delay
            if (timeout_context_get_remaining_ms(context) <= delay_ms) {
                result = TIMEOUT_EXPIRED;
                break;
            }
            
            // Sleep for retry delay
            struct timespec delay = {
                .tv_sec = delay_ms / 1000,
                .tv_nsec = (delay_ms % 1000) * 1000000
            };
            nanosleep(&delay, NULL);
        }
    }
    
    return result;
}

timeout_result_t timeout_execute_simple(timeout_manager_t* manager,
                                       const char* operation_name,
                                       uint32_t timeout_ms,
                                       timeout_operation_t operation,
                                       void* data) {
    if (!manager || !operation_name || !operation) {
        return TIMEOUT_ERROR;
    }
    
    timeout_context_t* context = timeout_context_create(manager, operation_name, 
                                                       timeout_ms, NULL);
    if (!context) {
        return TIMEOUT_ERROR;
    }
    
    timeout_result_t result = timeout_execute_with_retry(context, operation, data);
    
    timeout_remove_context(manager, context);
    timeout_context_destroy(context);
    
    return result;
}

// Retry policy creation functions
retry_policy_t retry_policy_create_none(void) {
    retry_policy_t policy = {0};
    policy.type = RETRY_POLICY_NONE;
    policy.max_attempts = 1;
    return policy;
}

retry_policy_t retry_policy_create_fixed(uint32_t max_attempts, uint32_t delay_ms) {
    retry_policy_t policy = {0};
    policy.type = RETRY_POLICY_FIXED_DELAY;
    policy.max_attempts = max_attempts;
    policy.base_delay_ms = delay_ms;
    policy.max_delay_ms = delay_ms;
    return policy;
}

retry_policy_t retry_policy_create_exponential(uint32_t max_attempts, 
                                              uint32_t base_delay_ms,
                                              uint32_t max_delay_ms,
                                              double multiplier) {
    retry_policy_t policy = {0};
    policy.type = RETRY_POLICY_EXPONENTIAL_BACKOFF;
    policy.max_attempts = max_attempts;
    policy.base_delay_ms = base_delay_ms;
    policy.max_delay_ms = max_delay_ms;
    policy.backoff_multiplier = multiplier;
    policy.jitter_enabled = true;
    return policy;
}

retry_policy_t retry_policy_create_linear(uint32_t max_attempts,
                                         uint32_t base_delay_ms,
                                         uint32_t increment_ms) {
    retry_policy_t policy = {0};
    policy.type = RETRY_POLICY_LINEAR_BACKOFF;
    policy.max_attempts = max_attempts;
    policy.base_delay_ms = base_delay_ms;
    policy.linear_increment_ms = increment_ms;
    policy.jitter_enabled = true;
    return policy;
}

uint32_t timeout_calculate_retry_delay(const retry_policy_t* policy, uint32_t attempt) {
    if (!policy || attempt == 0) {
        return 0;
    }
    
    uint32_t delay_ms = 0;
    
    switch (policy->type) {
        case RETRY_POLICY_NONE:
            return 0;
            
        case RETRY_POLICY_FIXED_DELAY:
            delay_ms = policy->base_delay_ms;
            break;
            
        case RETRY_POLICY_EXPONENTIAL_BACKOFF:
            delay_ms = policy->base_delay_ms * (uint32_t)pow(policy->backoff_multiplier, attempt - 1);
            if (delay_ms > policy->max_delay_ms) {
                delay_ms = policy->max_delay_ms;
            }
            break;
            
        case RETRY_POLICY_LINEAR_BACKOFF:
            delay_ms = policy->base_delay_ms + (policy->linear_increment_ms * (attempt - 1));
            if (policy->max_delay_ms > 0 && delay_ms > policy->max_delay_ms) {
                delay_ms = policy->max_delay_ms;
            }
            break;
    }
    
    // Add jitter if enabled
    if (policy->jitter_enabled && delay_ms > 0) {
        delay_ms = timeout_add_jitter(delay_ms);
    }
    
    return delay_ms;
}

static uint32_t timeout_add_jitter(uint32_t delay_ms) {
    // Add up to 25% random jitter
    uint32_t jitter = rand() % (delay_ms / 4 + 1);
    return delay_ms + jitter;
}

// Graceful degradation helpers
bool timeout_should_continue_on_missing_tool(timeout_manager_t* manager, const char* tool_name) {
    if (!manager || !manager->graceful_degradation_enabled) {
        return false;
    }
    
    timeout_log_degradation(manager, "Missing tool", tool_name);
    return true;
}

bool timeout_should_continue_on_permission_error(timeout_manager_t* manager, const char* operation) {
    if (!manager || !manager->graceful_degradation_enabled) {
        return false;
    }
    
    timeout_log_degradation(manager, "Permission denied", operation);
    return true;
}

void timeout_log_degradation(timeout_manager_t* manager, const char* reason, const char* fallback) {
    (void)manager; // Suppress unused parameter warning
    // Log graceful degradation event
    printf("WARNING: Graceful degradation: %s, continuing with: %s\n", reason, fallback ? fallback : "reduced functionality");
}

// Utility functions
int timeout_validate_config(uint32_t timeout_ms) {
    if (timeout_ms < TIMEOUT_MIN_MS || timeout_ms > TIMEOUT_MAX_MS) {
        return -1;
    }
    return 0;
}

bool timeout_is_monotonic_supported(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) == 0;
}

struct timespec timeout_get_monotonic_time(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
}

struct timespec timeout_add_ms(struct timespec base, uint32_t ms) {
    struct timespec result = base;
    
    uint64_t total_ns = (uint64_t)result.tv_nsec + (uint64_t)ms * 1000000;
    result.tv_sec += total_ns / 1000000000;
    result.tv_nsec = total_ns % 1000000000;
    
    return result;
}

int timeout_compare_timespec(const struct timespec* a, const struct timespec* b) {
    if (a->tv_sec < b->tv_sec) return -1;
    if (a->tv_sec > b->tv_sec) return 1;
    if (a->tv_nsec < b->tv_nsec) return -1;
    if (a->tv_nsec > b->tv_nsec) return 1;
    return 0;
}

// Global timeout management
int timeout_manager_set_global_timeout(timeout_manager_t* manager, uint32_t timeout_ms) {
    if (!manager || timeout_validate_config(timeout_ms) != 0) {
        return -1;
    }
    
    manager->global_timeout_ms = timeout_ms;
    manager->global_deadline = timeout_add_ms(timeout_get_monotonic_time(), timeout_ms);
    atomic_store(&manager->global_timeout_enabled, true);
    atomic_store(&manager->global_timeout_expired, false);
    
    return 0;
}

bool timeout_manager_is_global_timeout_expired(timeout_manager_t* manager) {
    return manager ? atomic_load(&manager->global_timeout_expired) : true;
}

uint64_t timeout_manager_get_global_remaining_ms(timeout_manager_t* manager) {
    if (!manager || !atomic_load(&manager->global_timeout_enabled) || 
        atomic_load(&manager->global_timeout_expired)) {
        return 0;
    }
    
    struct timespec now = timeout_get_monotonic_time();
    if (timeout_compare_timespec(&now, &manager->global_deadline) >= 0) {
        return 0;
    }
    
    uint64_t remaining_ns = (manager->global_deadline.tv_sec - now.tv_sec) * 1000000000ULL +
                           (manager->global_deadline.tv_nsec - now.tv_nsec);
    return remaining_ns / 1000000; // Convert to milliseconds
}

timeout_statistics_t timeout_manager_get_statistics(timeout_manager_t* manager) {
    timeout_statistics_t stats = {0};
    
    if (!manager) {
        return stats;
    }
    
    stats.total_timeouts = atomic_load(&manager->total_timeouts);
    stats.total_cancellations = atomic_load(&manager->total_cancellations);
    stats.total_retries = atomic_load(&manager->total_retries);
    stats.global_timeout_expired = atomic_load(&manager->global_timeout_expired);
    stats.global_remaining_ms = timeout_manager_get_global_remaining_ms(manager);
    
    // Count active contexts
    pthread_mutex_lock(&manager->contexts_mutex);
    timeout_context_t* context = manager->active_contexts;
    while (context) {
        stats.active_contexts++;
        stats.total_contexts_created++;
        stats.current_retry_attempts += context->current_attempt;
        context = context->next;
    }
    pthread_mutex_unlock(&manager->contexts_mutex);
    
    return stats;
}
