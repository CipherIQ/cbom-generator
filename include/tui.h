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
 * Terminal User Interface for CBOM Generator
 * Minimalist TUI with progress reporting
 */

#ifndef TUI_H
#define TUI_H

#include "tui_queue.h"
#include <stdbool.h>
#include <pthread.h>

// Output mode
typedef enum {
    OUTPUT_MODE_NORMAL,  // printf/fprintf to stdout/stderr
    OUTPUT_MODE_TUI,     // Route to message queue + ncurses
    OUTPUT_MODE_SILENT   // Suppress all output
} output_mode_t;

// Scanner state tracking
typedef struct {
    scanner_type_t type;
    char name[64];
    bool started;
    bool completed;
    size_t files_scanned;
    size_t assets_found;
    char current_file[256];
    char target_path[256];
} scanner_state_t;

// TUI context
typedef struct {
    tui_queue_t* queue;
    pthread_t thread;
    pthread_mutex_t state_lock;
    bool running;
    bool shutdown;
    bool scan_complete;      // Scan finished, waiting for user keystroke

    // Tracking
    scanner_state_t scanners[7];  // cert, key, package, service, filesystem, application, output
    size_t total_components;
    size_t cert_count;
    size_t key_count;
    size_t lib_count;
    size_t protocol_count;
    size_t algorithm_count;
    size_t service_count;
    size_t suite_count;
    time_t start_time;
    int completed_scanners;
    int total_scanners;

    // Display
    int term_width;
    int term_height;

    // stderr redirection (stdout must remain for ncurses)
    int saved_stderr;
    int null_fd;
} tui_context_t;

// Global TUI state
extern tui_context_t* g_tui_context;
extern output_mode_t g_output_mode;

// TUI lifecycle
tui_context_t* tui_init(void);
void tui_start(tui_context_t* ctx);
void tui_stop(tui_context_t* ctx);
void tui_wait_for_completion(tui_context_t* ctx);  // Wait for user keystroke after scan
void tui_destroy(tui_context_t* ctx);

// Logging interface (used by scanners)
void tui_log(tui_message_type_t type, scanner_type_t scanner,
             const char* scanner_name, size_t files, size_t found,
             const char* current_file, const char* target_path);

// Update total assets with breakdown
void tui_update_assets(size_t total, size_t certs, size_t keys, size_t algos,
                       size_t libs, size_t protos, size_t svcs, size_t suites);

// Helper to convert scanner name to type
scanner_type_t tui_scanner_type_from_name(const char* name);

#endif // TUI_H
