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

/**
 * TUI Message Queue Implementation
 */

#define _POSIX_C_SOURCE 199309L

#include "tui_queue.h"
#include "secure_memory.h"
#include <string.h>
#include <errno.h>
#include <time.h>

tui_queue_t* tui_queue_create(size_t max_size) {
    tui_queue_t* queue = (tui_queue_t*)secure_alloc(sizeof(tui_queue_t));
    if (!queue) {
        return NULL;
    }

    memset(queue, 0, sizeof(tui_queue_t));
    queue->max_size = max_size > 0 ? max_size : 1000;
    queue->shutdown = 0;

    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        secure_free(queue, sizeof(tui_queue_t));
        return NULL;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->lock);
        secure_free(queue, sizeof(tui_queue_t));
        return NULL;
    }

    return queue;
}

void tui_queue_destroy(tui_queue_t* queue) {
    if (!queue) {
        return;
    }

    pthread_mutex_lock(&queue->lock);

    // Free all nodes
    tui_queue_node_t* current = queue->head;
    while (current) {
        tui_queue_node_t* next = current->next;
        secure_free(current, sizeof(tui_queue_node_t));
        current = next;
    }

    pthread_mutex_unlock(&queue->lock);

    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->lock);
    secure_free(queue, sizeof(tui_queue_t));
}

int tui_queue_push(tui_queue_t* queue, const tui_message_t* message) {
    if (!queue || !message) {
        return -1;
    }

    pthread_mutex_lock(&queue->lock);

    // Check if queue is full
    if (queue->size >= queue->max_size) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    // Create new node
    tui_queue_node_t* node = (tui_queue_node_t*)secure_alloc(sizeof(tui_queue_node_t));
    if (!node) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    memcpy(&node->message, message, sizeof(tui_message_t));
    node->next = NULL;

    // Add to queue
    if (queue->tail) {
        queue->tail->next = node;
    } else {
        queue->head = node;
    }
    queue->tail = node;
    queue->size++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);

    return 0;
}

int tui_queue_pop(tui_queue_t* queue, tui_message_t* message, int timeout_ms) {
    if (!queue || !message) {
        return -1;
    }

    pthread_mutex_lock(&queue->lock);

    // Wait for message or timeout
    if (queue->size == 0 && timeout_ms > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        int result = pthread_cond_timedwait(&queue->not_empty, &queue->lock, &ts);
        if (result == ETIMEDOUT || queue->size == 0) {
            pthread_mutex_unlock(&queue->lock);
            return -1;
        }
    } else if (queue->size == 0) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    // Pop message
    tui_queue_node_t* node = queue->head;
    if (!node) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    memcpy(message, &node->message, sizeof(tui_message_t));
    queue->head = node->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    queue->size--;

    pthread_mutex_unlock(&queue->lock);

    secure_free(node, sizeof(tui_queue_node_t));
    return 0;
}

int tui_queue_peek(tui_queue_t* queue, tui_message_t* message) {
    if (!queue || !message) {
        return -1;
    }

    pthread_mutex_lock(&queue->lock);

    if (queue->size == 0) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    memcpy(message, &queue->head->message, sizeof(tui_message_t));

    pthread_mutex_unlock(&queue->lock);
    return 0;
}

size_t tui_queue_size(tui_queue_t* queue) {
    if (!queue) {
        return 0;
    }

    pthread_mutex_lock(&queue->lock);
    size_t size = queue->size;
    pthread_mutex_unlock(&queue->lock);

    return size;
}

void tui_queue_shutdown(tui_queue_t* queue) {
    if (!queue) {
        return;
    }

    pthread_mutex_lock(&queue->lock);
    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
}
