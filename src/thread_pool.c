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

#include "thread_pool.h"
#include "error_handling.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifndef __EMSCRIPTEN__
#include <sys/sysinfo.h>
#endif
#include <time.h>
#include <stdio.h>

#ifdef __EMSCRIPTEN__

/* ── WASM stubs: synchronous single-threaded execution ────────────── */

uint32_t thread_pool_get_optimal_thread_count(void) { return 1; }
int thread_pool_validate_config(uint32_t thread_count, size_t queue_capacity) {
    (void)thread_count; (void)queue_capacity; return 0;
}

thread_pool_t* thread_pool_create(uint32_t thread_count, size_t queue_capacity) {
    (void)thread_count;
    thread_pool_t* pool = calloc(1, sizeof(thread_pool_t));
    if (!pool) return NULL;
    pool->thread_count = 1;
    pool->queue_capacity = queue_capacity;
    atomic_init(&pool->is_running, true);
    atomic_init(&pool->shutdown_requested, false);
    atomic_init(&pool->next_sequence_id, 1);
    atomic_init(&pool->total_tasks_submitted, 0);
    atomic_init(&pool->total_tasks_completed, 0);
    atomic_init(&pool->total_tasks_failed, 0);
    clock_gettime(CLOCK_MONOTONIC, &pool->start_time);
    return pool;
}

int thread_pool_submit(thread_pool_t* pool, work_function_t function,
                      void* data, void* context, work_priority_t priority) {
    if (!pool || !function || !atomic_load(&pool->is_running)) return -1;
    (void)priority;
    atomic_fetch_add(&pool->total_tasks_submitted, 1);
    int result = function(data, context);
    if (result != 0) atomic_fetch_add(&pool->total_tasks_failed, 1);
    atomic_fetch_add(&pool->total_tasks_completed, 1);
    return 0;
}

int thread_pool_wait_all(thread_pool_t* pool) { (void)pool; return 0; }
int thread_pool_shutdown(thread_pool_t* pool, bool wait_for_completion) {
    if (!pool) return -1;
    (void)wait_for_completion;
    atomic_store(&pool->is_running, false);
    return 0;
}

void thread_pool_destroy(thread_pool_t* pool) { free(pool); }

thread_pool_metrics_t* thread_pool_get_metrics(thread_pool_t* pool) {
    if (!pool) return NULL;
    thread_pool_metrics_t* m = calloc(1, sizeof(thread_pool_metrics_t));
    if (!m) return NULL;
    m->total_tasks_submitted = atomic_load(&pool->total_tasks_submitted);
    m->total_tasks_completed = atomic_load(&pool->total_tasks_completed);
    m->total_tasks_failed = atomic_load(&pool->total_tasks_failed);
    m->thread_count = 1;
    return m;
}

void thread_pool_metrics_destroy(thread_pool_metrics_t* metrics) {
    if (!metrics) return;
    free(metrics->per_thread_stats);
    free(metrics);
}

int thread_pool_set_work_stealing(thread_pool_t* pool, bool enable, uint32_t steal_attempts) {
    (void)pool; (void)enable; (void)steal_attempts; return 0;
}

work_queue_t* work_queue_create(size_t capacity) { (void)capacity; return NULL; }
void work_queue_destroy(work_queue_t* queue) { (void)queue; }
int work_queue_push(work_queue_t* queue, work_item_t* item) { (void)queue; (void)item; return -1; }
work_item_t* work_queue_pop(work_queue_t* queue) { (void)queue; return NULL; }
work_item_t* work_queue_steal(work_queue_t* queue) { (void)queue; return NULL; }
bool work_queue_is_empty(work_queue_t* queue) { (void)queue; return true; }
size_t work_queue_size(work_queue_t* queue) { (void)queue; return 0; }

#else /* !__EMSCRIPTEN__ */

// Internal helper functions
static void* worker_thread_main(void* arg);
static work_item_t* try_steal_work(thread_pool_t* pool, uint32_t current_thread_id);
static uint64_t get_time_ns(void);
static void update_thread_stats(thread_stats_t* stats, uint64_t work_time_ns, bool task_failed);

uint32_t thread_pool_get_optimal_thread_count(void) {
    int cpu_count = get_nprocs();
    if (cpu_count <= 0) {
        return 4; // Fallback default
    }
    
    // Cap at maximum allowed threads
    if (cpu_count > THREAD_POOL_MAX_THREADS) {
        return THREAD_POOL_MAX_THREADS;
    }
    
    return (uint32_t)cpu_count;
}

int thread_pool_validate_config(uint32_t thread_count, size_t queue_capacity) {
    if (thread_count < THREAD_POOL_MIN_THREADS || thread_count > THREAD_POOL_MAX_THREADS) {
        return -1;
    }
    
    if (queue_capacity == 0 || queue_capacity > SIZE_MAX / sizeof(work_item_t*)) {
        return -1;
    }
    
    return 0;
}

work_queue_t* work_queue_create(size_t capacity) {
    work_queue_t* queue = calloc(1, sizeof(work_queue_t));
    if (!queue) {
        return NULL;
    }
    
    queue->items = calloc(capacity, sizeof(work_item_t*));
    if (!queue->items) {
        free(queue);
        return NULL;
    }
    
    queue->capacity = capacity;
    atomic_init(&queue->head, 0);
    atomic_init(&queue->tail, 0);
    atomic_init(&queue->count, 0);
    
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        free(queue->items);
        free(queue);
        return NULL;
    }
    
    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->mutex);
        free(queue->items);
        free(queue);
        return NULL;
    }
    
    if (pthread_cond_init(&queue->not_full, NULL) != 0) {
        pthread_cond_destroy(&queue->not_empty);
        pthread_mutex_destroy(&queue->mutex);
        free(queue->items);
        free(queue);
        return NULL;
    }
    
    return queue;
}

static void work_queue_cleanup(work_queue_t* queue) {
    if (!queue) return;
    
    pthread_mutex_lock(&queue->mutex);
    
    // Free any remaining work items
    size_t count = atomic_load(&queue->count);
    size_t head = atomic_load(&queue->head);
    for (size_t i = 0; i < count; i++) {
        size_t index = (head + i) % queue->capacity;
        work_item_t* item = queue->items[index];
        if (item) {
            free(item);
            queue->items[index] = NULL;
        }
    }
    
    pthread_mutex_unlock(&queue->mutex);
    
    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->mutex);
    free(queue->items);
    // Don't free the queue itself - it might be embedded
}

void work_queue_destroy(work_queue_t* queue) {
    if (!queue) return;
    
    work_queue_cleanup(queue);
    free(queue); // Only free if it was allocated separately
}

int work_queue_push(work_queue_t* queue, work_item_t* item) {
    if (!queue || !item) {
        return -1;
    }
    
    pthread_mutex_lock(&queue->mutex);
    
    // Wait for space if queue is full
    while (atomic_load(&queue->count) >= queue->capacity) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }
    
    size_t tail = atomic_load(&queue->tail);
    queue->items[tail % queue->capacity] = item;
    atomic_fetch_add(&queue->tail, 1);
    atomic_fetch_add(&queue->count, 1);
    
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

work_item_t* work_queue_pop(work_queue_t* queue) {
    if (!queue) {
        return NULL;
    }
    
    pthread_mutex_lock(&queue->mutex);
    
    while (atomic_load(&queue->count) == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }
    
    size_t head = atomic_load(&queue->head);
    work_item_t* item = queue->items[head % queue->capacity];
    queue->items[head % queue->capacity] = NULL;
    atomic_fetch_add(&queue->head, 1);
    atomic_fetch_sub(&queue->count, 1);
    
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    
    return item;
}

work_item_t* work_queue_steal(work_queue_t* queue) {
    if (!queue) {
        return NULL;
    }
    
    // Try to steal without blocking
    if (pthread_mutex_trylock(&queue->mutex) != 0) {
        return NULL;
    }
    
    if (atomic_load(&queue->count) == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }
    
    size_t head = atomic_load(&queue->head);
    work_item_t* item = queue->items[head % queue->capacity];
    if (item) {
        queue->items[head % queue->capacity] = NULL;
        atomic_fetch_add(&queue->head, 1);
        atomic_fetch_sub(&queue->count, 1);
        pthread_cond_signal(&queue->not_full);
    }
    
    pthread_mutex_unlock(&queue->mutex);
    return item;
}

bool work_queue_is_empty(work_queue_t* queue) {
    return queue ? atomic_load(&queue->count) == 0 : true;
}

size_t work_queue_size(work_queue_t* queue) {
    return queue ? atomic_load(&queue->count) : 0;
}

thread_pool_t* thread_pool_create(uint32_t thread_count, size_t queue_capacity) {
    // Validate configuration
    if (thread_count == THREAD_POOL_DEFAULT_THREADS) {
        thread_count = thread_pool_get_optimal_thread_count();
    }
    
    if (thread_pool_validate_config(thread_count, queue_capacity) != 0) {
        return NULL;
    }
    
    thread_pool_t* pool = calloc(1, sizeof(thread_pool_t));
    if (!pool) {
        return NULL;
    }
    
    // Initialize global work queue
    pool->global_queue.items = calloc(queue_capacity, sizeof(work_item_t*));
    if (!pool->global_queue.items) {
        free(pool);
        return NULL;
    }
    
    pool->global_queue.capacity = queue_capacity;
    atomic_init(&pool->global_queue.head, 0);
    atomic_init(&pool->global_queue.tail, 0);
    atomic_init(&pool->global_queue.count, 0);
    
    if (pthread_mutex_init(&pool->global_queue.mutex, NULL) != 0) {
        free(pool->global_queue.items);
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->global_queue.not_empty, NULL) != 0) {
        pthread_mutex_destroy(&pool->global_queue.mutex);
        free(pool->global_queue.items);
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->global_queue.not_full, NULL) != 0) {
        pthread_cond_destroy(&pool->global_queue.not_empty);
        pthread_mutex_destroy(&pool->global_queue.mutex);
        free(pool->global_queue.items);
        free(pool);
        return NULL;
    }
    
    // Initialize pool state
    pool->thread_count = thread_count;
    pool->queue_capacity = queue_capacity;
    pool->enable_work_stealing = true;
    pool->steal_attempts = 3;
    atomic_init(&pool->is_running, false);
    atomic_init(&pool->shutdown_requested, false);
    atomic_init(&pool->next_sequence_id, 1);
    atomic_init(&pool->total_tasks_submitted, 0);
    atomic_init(&pool->total_tasks_completed, 0);
    atomic_init(&pool->total_tasks_failed, 0);
    
    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0) {
        work_queue_cleanup(&pool->global_queue);
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->all_idle, NULL) != 0) {
        pthread_mutex_destroy(&pool->pool_mutex);
        work_queue_cleanup(&pool->global_queue);
        free(pool);
        return NULL;
    }
    
    // Allocate worker threads
    pool->workers = calloc(thread_count, sizeof(worker_thread_t));
    if (!pool->workers) {
        pthread_cond_destroy(&pool->all_idle);
        pthread_mutex_destroy(&pool->pool_mutex);
        work_queue_cleanup(&pool->global_queue);
        free(pool);
        return NULL;
    }
    
    // Initialize worker threads
    clock_gettime(CLOCK_MONOTONIC, &pool->start_time);
    atomic_store(&pool->is_running, true);
    
    for (uint32_t i = 0; i < thread_count; i++) {
        worker_thread_t* worker = &pool->workers[i];
        worker->thread_id = i;
        worker->pool = pool;
        atomic_init(&worker->should_exit, false);
        atomic_init(&worker->is_active, false);
        
        // Initialize per-thread statistics
        atomic_init(&worker->stats.tasks_completed, 0);
        atomic_init(&worker->stats.tasks_stolen, 0);
        atomic_init(&worker->stats.tasks_failed, 0);
        atomic_init(&worker->stats.total_work_time_ns, 0);
        atomic_init(&worker->stats.idle_time_ns, 0);
        atomic_init(&worker->stats.warning_count, 0);
        worker->stats.thread_id = i;
        
        // Create local work queue for work stealing
        worker->local_queue = work_queue_create(queue_capacity / thread_count);
        if (!worker->local_queue) {
            // Cleanup and return error
            for (uint32_t j = 0; j < i; j++) {
                atomic_store(&pool->workers[j].should_exit, true);
                pthread_join(pool->workers[j].pthread, NULL);
                work_queue_destroy(pool->workers[j].local_queue);
            }
            free(pool->workers);
            pthread_cond_destroy(&pool->all_idle);
            pthread_mutex_destroy(&pool->pool_mutex);
            work_queue_cleanup(&pool->global_queue);
            free(pool);
            return NULL;
        }
        
        // Create worker thread
        if (pthread_create(&worker->pthread, NULL, worker_thread_main, worker) != 0) {
            work_queue_destroy(worker->local_queue);
            // Cleanup previous threads
            for (uint32_t j = 0; j < i; j++) {
                atomic_store(&pool->workers[j].should_exit, true);
                pthread_join(pool->workers[j].pthread, NULL);
                work_queue_destroy(pool->workers[j].local_queue);
            }
            free(pool->workers);
            pthread_cond_destroy(&pool->all_idle);
            pthread_mutex_destroy(&pool->pool_mutex);
            work_queue_cleanup(&pool->global_queue);
            free(pool);
            return NULL;
        }
    }
    
    return pool;
}

static void* worker_thread_main(void* arg) {
    worker_thread_t* worker = (worker_thread_t*)arg;
    thread_pool_t* pool = worker->pool;
    
    while (!atomic_load(&worker->should_exit)) {
        work_item_t* item = NULL;
        uint64_t idle_start = get_time_ns();
        
        // Try to get work from local queue first
        item = work_queue_steal(worker->local_queue);
        
        // If no local work, try global queue
        if (!item) {
            pthread_mutex_lock(&pool->global_queue.mutex);
            while (atomic_load(&pool->global_queue.count) == 0 && 
                   !atomic_load(&worker->should_exit)) {
                pthread_cond_wait(&pool->global_queue.not_empty, &pool->global_queue.mutex);
            }
            
            if (!atomic_load(&worker->should_exit) && atomic_load(&pool->global_queue.count) > 0) {
                size_t head = atomic_load(&pool->global_queue.head);
                item = pool->global_queue.items[head % pool->global_queue.capacity];
                if (item) {
                    pool->global_queue.items[head % pool->global_queue.capacity] = NULL;
                    atomic_fetch_add(&pool->global_queue.head, 1);
                    atomic_fetch_sub(&pool->global_queue.count, 1);
                    pthread_cond_signal(&pool->global_queue.not_full);
                }
            }
            pthread_mutex_unlock(&pool->global_queue.mutex);
        }
        
        // Try work stealing if still no work
        if (!item && pool->enable_work_stealing) {
            item = try_steal_work(pool, worker->thread_id);
            if (item) {
                atomic_fetch_add(&worker->stats.tasks_stolen, 1);
            }
        }
        
        uint64_t idle_time = get_time_ns() - idle_start;
        atomic_fetch_add(&worker->stats.idle_time_ns, idle_time);
        
        if (item) {
            atomic_store(&worker->is_active, true);
            clock_gettime(CLOCK_MONOTONIC, &worker->stats.last_activity);
            
            uint64_t work_start = get_time_ns();
            int result = item->function(item->data, item->context);
            uint64_t work_time = get_time_ns() - work_start;
            
            update_thread_stats(&worker->stats, work_time, result != 0);
            
            if (result != 0) {
                atomic_fetch_add(&pool->total_tasks_failed, 1);
                
                // Add warning to pre-allocated buffer
                size_t warning_idx = atomic_fetch_add(&worker->stats.warning_count, 1);
                if (warning_idx < MAX_WARNINGS_PER_THREAD) {
                    snprintf(worker->stats.warnings[warning_idx], WARNING_BUFFER_SIZE,
                            "Task failed with code %d", result);
                }
            }
            
            atomic_fetch_add(&pool->total_tasks_completed, 1);
            free(item);
            atomic_store(&worker->is_active, false);
            
            // Signal that a worker has become idle
            pthread_cond_signal(&pool->all_idle);
        }
    }
    
    return NULL;
}

static work_item_t* try_steal_work(thread_pool_t* pool, uint32_t current_thread_id) {
    for (uint32_t attempt = 0; attempt < pool->steal_attempts; attempt++) {
        // Try to steal from a random other thread
        uint32_t target_thread = (current_thread_id + attempt + 1) % pool->thread_count;
        if (target_thread == current_thread_id) continue;
        
        work_item_t* stolen = work_queue_steal(pool->workers[target_thread].local_queue);
        if (stolen) {
            return stolen;
        }
    }
    return NULL;
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void update_thread_stats(thread_stats_t* stats, uint64_t work_time_ns, bool task_failed) {
    atomic_fetch_add(&stats->total_work_time_ns, work_time_ns);
    atomic_fetch_add(&stats->tasks_completed, 1);
    
    if (task_failed) {
        atomic_fetch_add(&stats->tasks_failed, 1);
    }
}

int thread_pool_submit(thread_pool_t* pool, work_function_t function, 
                      void* data, void* context, work_priority_t priority) {
    if (!pool || !function || !atomic_load(&pool->is_running)) {
        return -1;
    }
    
    work_item_t* item = malloc(sizeof(work_item_t));
    if (!item) {
        return -1;
    }
    
    item->function = function;
    item->data = data;
    item->context = context;
    item->priority = priority;
    item->sequence_id = atomic_fetch_add(&pool->next_sequence_id, 1);
    clock_gettime(CLOCK_MONOTONIC, &item->submit_time);
    item->next = NULL;
    
    int result = work_queue_push(&pool->global_queue, item);
    if (result == 0) {
        atomic_fetch_add(&pool->total_tasks_submitted, 1);
    } else {
        free(item);
    }
    
    return result;
}

int thread_pool_wait_all(thread_pool_t* pool) {
    if (!pool) {
        return -1;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    // Wait until all queues are empty and all threads are idle
    while (atomic_load(&pool->global_queue.count) > 0) {
        bool all_idle = true;
        for (uint32_t i = 0; i < pool->thread_count; i++) {
            if (atomic_load(&pool->workers[i].is_active) || 
                !work_queue_is_empty(pool->workers[i].local_queue)) {
                all_idle = false;
                break;
            }
        }
        
        if (all_idle && atomic_load(&pool->global_queue.count) == 0) {
            break;
        }
        
        pthread_cond_wait(&pool->all_idle, &pool->pool_mutex);
    }
    
    pthread_mutex_unlock(&pool->pool_mutex);
    return 0;
}

int thread_pool_shutdown(thread_pool_t* pool, bool wait_for_completion) {
    if (!pool) {
        return -1;
    }
    
    atomic_store(&pool->shutdown_requested, true);
    
    if (wait_for_completion) {
        thread_pool_wait_all(pool);
    }
    
    // Signal all worker threads to exit
    for (uint32_t i = 0; i < pool->thread_count; i++) {
        atomic_store(&pool->workers[i].should_exit, true);
    }
    
    // Wake up all waiting threads
    pthread_cond_broadcast(&pool->global_queue.not_empty);
    
    // Wait for all threads to finish
    for (uint32_t i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->workers[i].pthread, NULL);
    }
    
    atomic_store(&pool->is_running, false);
    return 0;
}

void thread_pool_destroy(thread_pool_t* pool) {
    if (!pool) return;
    
    thread_pool_shutdown(pool, false);
    
    // Cleanup worker threads
    for (uint32_t i = 0; i < pool->thread_count; i++) {
        work_queue_destroy(pool->workers[i].local_queue);
    }
    free(pool->workers);
    
    // Cleanup global queue (embedded, so don't free the queue itself)
    work_queue_cleanup(&pool->global_queue);
    
    // Cleanup synchronization objects
    pthread_cond_destroy(&pool->all_idle);
    pthread_mutex_destroy(&pool->pool_mutex);
    
    free(pool);
}

thread_pool_metrics_t* thread_pool_get_metrics(thread_pool_t* pool) {
    if (!pool) {
        return NULL;
    }
    
    thread_pool_metrics_t* metrics = malloc(sizeof(thread_pool_metrics_t));
    if (!metrics) {
        return NULL;
    }
    
    metrics->total_tasks_submitted = atomic_load(&pool->total_tasks_submitted);
    metrics->total_tasks_completed = atomic_load(&pool->total_tasks_completed);
    metrics->total_tasks_failed = atomic_load(&pool->total_tasks_failed);
    metrics->queue_depth = atomic_load(&pool->global_queue.count);
    metrics->thread_count = pool->thread_count;
    
    // Calculate runtime
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    uint64_t runtime_ns = (current_time.tv_sec - pool->start_time.tv_sec) * 1000000000ULL +
                         (current_time.tv_nsec - pool->start_time.tv_nsec);
    
    // Aggregate per-thread statistics
    metrics->total_work_time_ns = 0;
    metrics->total_idle_time_ns = 0;
    metrics->active_threads = 0;
    
    metrics->per_thread_stats = malloc(pool->thread_count * sizeof(thread_stats_t));
    if (metrics->per_thread_stats) {
        for (uint32_t i = 0; i < pool->thread_count; i++) {
            metrics->per_thread_stats[i] = pool->workers[i].stats;
            metrics->total_work_time_ns += atomic_load(&pool->workers[i].stats.total_work_time_ns);
            metrics->total_idle_time_ns += atomic_load(&pool->workers[i].stats.idle_time_ns);
            
            if (atomic_load(&pool->workers[i].is_active)) {
                metrics->active_threads++;
            }
        }
    }
    
    // Calculate derived metrics
    if (runtime_ns > 0) {
        metrics->cpu_utilization = (double)metrics->total_work_time_ns / 
                                  (double)(runtime_ns * pool->thread_count);
        metrics->throughput_tasks_per_sec = (double)metrics->total_tasks_completed * 
                                           1000000000.0 / (double)runtime_ns;
    } else {
        metrics->cpu_utilization = 0.0;
        metrics->throughput_tasks_per_sec = 0.0;
    }
    
    return metrics;
}

void thread_pool_metrics_destroy(thread_pool_metrics_t* metrics) {
    if (!metrics) return;
    
    free(metrics->per_thread_stats);
    free(metrics);
}

int thread_pool_set_work_stealing(thread_pool_t* pool, bool enable, uint32_t steal_attempts) {
    if (!pool) {
        return -1;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    pool->enable_work_stealing = enable;
    pool->steal_attempts = steal_attempts;
    pthread_mutex_unlock(&pool->pool_mutex);

    return 0;
}

#endif /* !__EMSCRIPTEN__ */
