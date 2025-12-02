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
 * TUI Message Queue
 * Thread-safe message queue for TUI updates
 */

#ifndef TUI_QUEUE_H
#define TUI_QUEUE_H

#include <stddef.h>
#include <time.h>
#include <pthread.h>

// Message types for TUI updates
typedef enum {
    TUI_MSG_SCANNER_START,      // Scanner begins
    TUI_MSG_SCANNER_PROGRESS,   // Files scanned update
    TUI_MSG_SCANNER_COMPLETE,   // Scanner finished
    TUI_MSG_ASSETS_FOUND,       // Asset count update
    TUI_MSG_CURRENT_FILE,       // Currently processing file
    TUI_MSG_ERROR,              // Error occurred
    TUI_MSG_COMPLETE            // All work done
} tui_message_type_t;

// Scanner types for identification
typedef enum {
    SCANNER_CERTIFICATE,
    SCANNER_KEY,
    SCANNER_PACKAGE,
    SCANNER_SERVICE,
    SCANNER_FILESYSTEM,
    SCANNER_APPLICATION,   // v1.6 - Application scanner
    SCANNER_OUTPUT,
    SCANNER_UNKNOWN
} scanner_type_t;

// TUI message structure
typedef struct {
    tui_message_type_t type;
    scanner_type_t scanner;
    char scanner_name[64];
    size_t files_scanned;
    size_t assets_found;
    char current_file[256];
    char target_path[256];     // Current target directory being scanned
    time_t timestamp;
    // Asset type breakdown (for TUI_MSG_ASSETS_FOUND)
    size_t cert_count;
    size_t key_count;
    size_t lib_count;
    size_t protocol_count;
    size_t algorithm_count;
    size_t service_count;
    size_t suite_count;
} tui_message_t;

// Queue node
typedef struct tui_queue_node {
    tui_message_t message;
    struct tui_queue_node* next;
} tui_queue_node_t;

// Thread-safe message queue
typedef struct {
    tui_queue_node_t* head;
    tui_queue_node_t* tail;
    size_t size;
    size_t max_size;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    int shutdown;
} tui_queue_t;

// Queue operations
tui_queue_t* tui_queue_create(size_t max_size);
void tui_queue_destroy(tui_queue_t* queue);
int tui_queue_push(tui_queue_t* queue, const tui_message_t* message);
int tui_queue_pop(tui_queue_t* queue, tui_message_t* message, int timeout_ms);
int tui_queue_peek(tui_queue_t* queue, tui_message_t* message);
size_t tui_queue_size(tui_queue_t* queue);
void tui_queue_shutdown(tui_queue_t* queue);

#endif // TUI_QUEUE_H
