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
 * Terminal User Interface Implementation
 */

#define _GNU_SOURCE

#include "tui.h"
#include "secure_memory.h"
#include "provenance.h"
#include <ncurses.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>

// Global state
tui_context_t* g_tui_context = NULL;
output_mode_t g_output_mode = OUTPUT_MODE_NORMAL;

// Forward declarations
static void* tui_render_thread(void* arg);
static void tui_render_frame(tui_context_t* ctx);
static void tui_draw_header(tui_context_t* ctx, int* row);
static void tui_draw_scanners(tui_context_t* ctx, int* row);
static void tui_draw_footer(tui_context_t* ctx, int* row);
static void tui_process_messages(tui_context_t* ctx);
static char tui_scanner_icon(scanner_state_t* scanner);

tui_context_t* tui_init(void) {
    // Check if terminal is interactive
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        return NULL;
    }

    tui_context_t* ctx = (tui_context_t*)secure_alloc(sizeof(tui_context_t));
    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(tui_context_t));

    // Create message queue (increased from 1000 to handle large scans)
    ctx->queue = tui_queue_create(10000);
    if (!ctx->queue) {
        secure_free(ctx, sizeof(tui_context_t));
        return NULL;
    }

    // Initialize mutex
    if (pthread_mutex_init(&ctx->state_lock, NULL) != 0) {
        tui_queue_destroy(ctx->queue);
        secure_free(ctx, sizeof(tui_context_t));
        return NULL;
    }

    ctx->running = false;
    ctx->shutdown = false;
    ctx->scan_complete = false;
    ctx->start_time = time(NULL);
    ctx->total_scanners = 6;
    ctx->saved_stderr = -1;
    ctx->null_fd = -1;

    // Initialize scanner states (6 scanners - Output Generation removed as it's post-processing)
    const char* scanner_names[] = {
        "Certificate Scanner",
        "Key Scanner",
        "Package Scanner",
        "Service Scanner",
        "Filesystem Scanner",
        "Application Scanner"
    };

    for (int i = 0; i < 6; i++) {
        ctx->scanners[i].type = (scanner_type_t)i;
        strncpy(ctx->scanners[i].name, scanner_names[i], sizeof(ctx->scanners[i].name) - 1);
    }

    return ctx;
}

void tui_start(tui_context_t* ctx) {
    if (!ctx || ctx->running) {
        return;
    }

    // Flush stderr before redirecting (stdout must remain for ncurses!)
    fflush(stderr);

    // Redirect ONLY stderr to /dev/null to suppress error messages
    // stdout MUST remain connected to terminal for ncurses to work
    ctx->saved_stderr = dup(STDERR_FILENO);
    ctx->null_fd = open("/dev/null", O_WRONLY);
    if (ctx->null_fd >= 0) {
        dup2(ctx->null_fd, STDERR_FILENO);
    }

    // Initialize ncurses
    initscr();
    clear();  // Clear screen immediately
    refresh();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);
    curs_set(0);  // Hide cursor

    // Get terminal size
    getmaxyx(stdscr, ctx->term_height, ctx->term_width);

    // Check minimum size
    if (ctx->term_height < 15 || ctx->term_width < 60) {
        endwin();
        fprintf(stderr, "Terminal too small for TUI (need at least 60x15)\n");
        g_output_mode = OUTPUT_MODE_NORMAL;
        return;
    }

    ctx->running = true;

    // Start render thread
    if (pthread_create(&ctx->thread, NULL, tui_render_thread, ctx) != 0) {
        endwin();
        ctx->running = false;
        return;
    }

    g_output_mode = OUTPUT_MODE_TUI;
}

void tui_wait_for_completion(tui_context_t* ctx) {
    if (!ctx || !ctx->running) {
        return;
    }

    // Wait for render thread to finish (it will wait for user keystroke)
    pthread_join(ctx->thread, NULL);

    // Clean up ncurses
    endwin();

    // Restore stderr
    if (ctx->saved_stderr >= 0) {
        dup2(ctx->saved_stderr, STDERR_FILENO);
        close(ctx->saved_stderr);
        ctx->saved_stderr = -1;
    }
    if (ctx->null_fd >= 0) {
        close(ctx->null_fd);
        ctx->null_fd = -1;
    }

    ctx->running = false;
    g_output_mode = OUTPUT_MODE_NORMAL;
}

void tui_stop(tui_context_t* ctx) {
    if (!ctx || !ctx->running) {
        return;
    }

    ctx->shutdown = true;
    tui_queue_shutdown(ctx->queue);

    pthread_join(ctx->thread, NULL);

    endwin();

    // Restore stderr only (stdout was never redirected)
    if (ctx->saved_stderr >= 0) {
        dup2(ctx->saved_stderr, STDERR_FILENO);
        close(ctx->saved_stderr);
        ctx->saved_stderr = -1;
    }
    if (ctx->null_fd >= 0) {
        close(ctx->null_fd);
        ctx->null_fd = -1;
    }

    ctx->running = false;
    g_output_mode = OUTPUT_MODE_NORMAL;
}

void tui_destroy(tui_context_t* ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->running) {
        tui_stop(ctx);
    }

    tui_queue_destroy(ctx->queue);
    pthread_mutex_destroy(&ctx->state_lock);
    secure_free(ctx, sizeof(tui_context_t));

    g_tui_context = NULL;
}

static void* tui_render_thread(void* arg) {
    tui_context_t* ctx = (tui_context_t*)arg;

    // Give ncurses time to fully initialize
    usleep(100000);

    while (1) {
        // Process messages
        tui_process_messages(ctx);

        // Render frame
        tui_render_frame(ctx);

        // PRIORITY CHECK: If scan is complete, wait for user before exiting
        if (ctx->scan_complete) {
            // Flush any buffered input
            flushinp();

            // Switch to blocking mode and raw mode for proper input
            nodelay(stdscr, FALSE);
            raw();  // Enable raw mode to catch all input

            // Draw final frame with "Press any key to exit" message
            tui_render_frame(ctx);
            refresh();  // Force display update

            // Wait for any keystroke (blocking, will wait until key is pressed)
            int ch;
            do {
                ch = getch();
            } while (ch == ERR);  // Loop until we get a real keystroke

            // Give user a moment to see the screen before clearing
            usleep(100000);

            // Now we can exit
            break;
        }

        // Check for forced shutdown (Ctrl+C or error)
        if (ctx->shutdown) {
            break;
        }

        // Sleep for 100ms (10 FPS)
        usleep(100000);
    }

    return NULL;
}

static void tui_process_messages(tui_context_t* ctx) {
    tui_message_t msg;

    // Process all available messages
    while (tui_queue_pop(ctx->queue, &msg, 0) == 0) {
        pthread_mutex_lock(&ctx->state_lock);

        scanner_state_t* scanner = &ctx->scanners[msg.scanner];

        switch (msg.type) {
            case TUI_MSG_SCANNER_START:
                scanner->started = true;
                scanner->completed = false;
                if (msg.target_path[0]) {
                    size_t len = strlen(msg.target_path);
                    if (len >= sizeof(scanner->target_path)) {
                        len = sizeof(scanner->target_path) - 1;
                    }
                    memcpy(scanner->target_path, msg.target_path, len);
                    scanner->target_path[len] = '\0';
                }
                break;

            case TUI_MSG_SCANNER_PROGRESS:
                scanner->files_scanned = msg.files_scanned;
                scanner->assets_found = msg.assets_found;
                if (msg.current_file[0]) {
                    size_t len = strlen(msg.current_file);
                    if (len >= sizeof(scanner->current_file)) {
                        len = sizeof(scanner->current_file) - 1;
                    }
                    memcpy(scanner->current_file, msg.current_file, len);
                    scanner->current_file[len] = '\0';
                }
                if (msg.target_path[0]) {
                    size_t len = strlen(msg.target_path);
                    if (len >= sizeof(scanner->target_path)) {
                        len = sizeof(scanner->target_path) - 1;
                    }
                    memcpy(scanner->target_path, msg.target_path, len);
                    scanner->target_path[len] = '\0';
                }
                break;

            case TUI_MSG_SCANNER_COMPLETE:
                // Only increment completed_scanners if not already completed
                if (!scanner->completed) {
                    ctx->completed_scanners++;
                }
                scanner->completed = true;
                // Only update counts if non-zero (preserve progress counts)
                if (msg.files_scanned > 0) {
                    scanner->files_scanned = msg.files_scanned;
                }
                if (msg.assets_found > 0) {
                    scanner->assets_found = msg.assets_found;
                }
                break;

            case TUI_MSG_ASSETS_FOUND:
                ctx->total_components = msg.assets_found;
                ctx->cert_count = msg.cert_count;
                ctx->key_count = msg.key_count;
                ctx->lib_count = msg.lib_count;
                ctx->protocol_count = msg.protocol_count;
                ctx->algorithm_count = msg.algorithm_count;
                ctx->service_count = msg.service_count;
                ctx->suite_count = msg.suite_count;
                break;

            case TUI_MSG_COMPLETE:
                ctx->scan_complete = true;
                break;

            default:
                break;
        }

        pthread_mutex_unlock(&ctx->state_lock);
    }
}

static void tui_render_frame(tui_context_t* ctx) {
    pthread_mutex_lock(&ctx->state_lock);

    clear();

    int row = 0;
    tui_draw_header(ctx, &row);
    tui_draw_scanners(ctx, &row);
    tui_draw_footer(ctx, &row);

    refresh();

    pthread_mutex_unlock(&ctx->state_lock);
}

static void tui_draw_header(tui_context_t* ctx, int* row) {
    time_t elapsed = time(NULL) - ctx->start_time;
    int hours = elapsed / 3600;
    int mins = (elapsed % 3600) / 60;
    int secs = elapsed % 60;

    // Calculate progress excluding non-scanner phases (Output, Service)
    // Only count active data collection scanners: Cert, Key, Package, Filesystem, Application
    int active_scanners = 0;
    int completed_active = 0;
    for (int i = 0; i < ctx->total_scanners; i++) {
        if (ctx->scanners[i].type != SCANNER_OUTPUT &&
            ctx->scanners[i].type != SCANNER_SERVICE) {
            active_scanners++;
            if (ctx->scanners[i].completed) {
                completed_active++;
            }
        }
    }

    int progress = active_scanners > 0
        ? (completed_active * 100) / active_scanners
        : 0;

    // Top border with branding
#ifdef CIPHERIQ_PRO
    mvprintw(*row, 0, "+- CipherIQ Professional Edition ");
    int title_len = 33;  // Length of "+- CipherIQ Professional Edition "
    const char* branding = "v" CIQ_PRO_VERSION " -+";
#else
    mvprintw(*row, 0, "+- CBOM Generator ");
    int title_len = 18;  // Length of "+- CBOM Generator "
    const char* branding = "CipherIQ v" CBOM_VERSION " -+";
#endif
    int branding_len = strlen(branding);
    int fill_start = title_len;
    int fill_end = ctx->term_width - branding_len - 1;  // -1 for space

    for (int i = fill_start; i < fill_end; i++) {
        addch('-');
    }
    mvprintw(*row, fill_end, " %s", branding);  // Add space before branding
    (*row)++;

    // Empty line
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Progress and time
    char progress_bar[50];
    int bar_width = 20;
    int filled = (progress * bar_width) / 100;
    for (int i = 0; i < bar_width; i++) {
        progress_bar[i] = i < filled ? '#' : '-';
    }
    progress_bar[bar_width] = '\0';

    mvprintw(*row, 2, "Progress: [%s] %3d%%", progress_bar, progress);
    mvprintw(*row, ctx->term_width - 20, "Time: %02d:%02d:%02d", hours, mins, secs);
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Empty line
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Section divider
    mvprintw(*row, 0, "+- Scanning Progress ");
    for (int i = 21; i < ctx->term_width - 1; i++) {
        addch('-');
    }
    addch('+');
    (*row)++;

    // Empty line
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;
}

static void tui_draw_scanners(tui_context_t* ctx, int* row) {
    // Labels for what each scanner finds
    const char* found_labels[] = {
        "certs", "keys", "pkgs", "svcs", "files", "apps"
    };

    for (int i = 0; i < ctx->total_scanners; i++) {
        scanner_state_t* scanner = &ctx->scanners[i];
        if (scanner->type == SCANNER_SERVICE) continue;  // Deprecated, skip display
        char icon = tui_scanner_icon(scanner);

        mvprintw(*row, 0, "|");
        mvprintw(*row, 2, " [%c] %-20s", icon, scanner->name);

        if (scanner->completed || scanner->started) {
            const char* label = (i < 6) ? found_labels[i] : "items";
            if (scanner->files_scanned > 0) {
                mvprintw(*row, 30, "%6zu files  %4zu %s",
                         scanner->files_scanned, scanner->assets_found, label);
            } else {
                mvprintw(*row, 30, "System-wide  %4zu %s", scanner->assets_found, label);
            }
        } else {
            mvprintw(*row, 30, "Pending");
        }

        mvprintw(*row, ctx->term_width - 1, "|");
        (*row)++;
    }

    // Empty line
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;
}

static void tui_draw_footer(tui_context_t* ctx, int* row) {
    // Section divider
    mvprintw(*row, 0, "+- Status ");
    for (int i = 10; i < ctx->term_width - 1; i++) {
        addch('-');
    }
    addch('+');
    (*row)++;

    // Empty line
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Find active scanner and build status message
    char scanner_status[512];
    const char* status = "Initializing...";

    // Calculate progress excluding non-scanner phases (Output, Service)
    int active_scanners = 0;
    int completed_active = 0;
    for (int i = 0; i < ctx->total_scanners; i++) {
        if (ctx->scanners[i].type != SCANNER_OUTPUT &&
            ctx->scanners[i].type != SCANNER_SERVICE) {
            active_scanners++;
            if (ctx->scanners[i].completed) {
                completed_active++;
            }
        }
    }

    if (ctx->scan_complete) {
        status = "COMPLETE";
    } else if (completed_active >= active_scanners) {
        // All active scanners done - generating output
        status = "Complete - generating output...";
    } else {
        // Find which scanner is currently active
        bool found_active = false;
        for (int i = 0; i < ctx->total_scanners; i++) {
            if (ctx->scanners[i].started && !ctx->scanners[i].completed) {
                if (ctx->scanners[i].target_path[0]) {
                    snprintf(scanner_status, sizeof(scanner_status), "Scanning: %s", ctx->scanners[i].target_path);
                    status = scanner_status;
                } else {
                    status = "Scanning...";
                }
                found_active = true;
                break;
            }
        }
        if (!found_active && ctx->completed_scanners > 0) {
            status = "Processing...";
        }
    }

    // Build asset breakdown string
    char assets_line[256];
    snprintf(assets_line, sizeof(assets_line),
             "Total Assets: %zu (%zu certs, %zu keys, %zu algos, %zu libs, %zu protos, %zu svcs, %zu suites)",
             ctx->total_components, ctx->cert_count, ctx->key_count,
             ctx->algorithm_count, ctx->lib_count, ctx->protocol_count, ctx->service_count, ctx->suite_count);
    mvprintw(*row, 2, "%s", assets_line);
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Current status (truncate if too long)
    char display_status[512];
    int max_status_len = ctx->term_width - 6;
    if ((int)strlen(status) > max_status_len) {
        snprintf(display_status, sizeof(display_status), "...%s",
                 status + strlen(status) - max_status_len + 3);
    } else {
        strncpy(display_status, status, sizeof(display_status) - 1);
        display_status[sizeof(display_status) - 1] = '\0';
    }
    mvprintw(*row, 2, "%s", display_status);
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Empty line
    mvprintw(*row, 0, "|");
    mvprintw(*row, ctx->term_width - 1, "|");
    (*row)++;

    // Bottom border with company branding
    const char* company = "Graziano Labs Corp. -+";
    int company_len = strlen(company);
    mvprintw(*row, 0, "+");
    for (int i = 1; i < ctx->term_width - company_len - 1; i++) {  // -1 for space
        addch('-');
    }
    mvprintw(*row, ctx->term_width - company_len - 1, " %s", company);  // Add space before company
    (*row)++;

    // Help text - dynamic based on completion state
    if (ctx->scan_complete) {
        mvprintw(*row, 2, "Press any key to exit");
    } else {
        mvprintw(*row, 2, "Press Ctrl+C to abort");
    }
}

static char tui_scanner_icon(scanner_state_t* scanner) {
    if (scanner->completed) {
        return 'X';
    } else if (scanner->started) {
        return '>';
    } else {
        return ' ';
    }
}

void tui_log(tui_message_type_t type, scanner_type_t scanner,
             const char* scanner_name, size_t files, size_t found,
             const char* current_file, const char* target_path) {

    if (g_output_mode == OUTPUT_MODE_TUI && g_tui_context && g_tui_context->queue) {
        tui_message_t msg = {0};
        msg.type = type;
        msg.scanner = scanner;
        if (scanner_name) {
            strncpy(msg.scanner_name, scanner_name, sizeof(msg.scanner_name) - 1);
        }
        msg.files_scanned = files;
        msg.assets_found = found;
        if (current_file) {
            strncpy(msg.current_file, current_file, sizeof(msg.current_file) - 1);
        }
        if (target_path) {
            strncpy(msg.target_path, target_path, sizeof(msg.target_path) - 1);
        }
        msg.timestamp = time(NULL);

        tui_queue_push(g_tui_context->queue, &msg);
    } else if (g_output_mode == OUTPUT_MODE_NORMAL) {
        // Fallback to normal printf with rate limiting for console
        if (type == TUI_MSG_SCANNER_PROGRESS) {
            // Rate limit console output: print when files count crosses 100-file boundaries
            // TUI updates remain at every 10 files (handled in TUI mode above)
            // Track per-scanner to avoid cross-scanner interference
            static size_t last_printed_files[8] = {0};  // One per scanner_type_t

            int scanner_idx = (int)scanner;
            if (scanner_idx < 0 || scanner_idx >= 8) scanner_idx = 7;  // SCANNER_UNKNOWN

            // Print every 100 files (when we cross a new 100-boundary)
            size_t current_hundred = files / 100;
            size_t last_hundred = last_printed_files[scanner_idx] / 100;

            if (current_hundred > last_hundred || last_printed_files[scanner_idx] == 0) {
                printf("INFO: %s: scanned %zu files globally, found %zu assets\n",
                       scanner_name ? scanner_name : "scanner", files, found);
                fflush(stdout);
                last_printed_files[scanner_idx] = files;
            }
        }
    }
}

void tui_update_assets(size_t total, size_t certs, size_t keys, size_t algos,
                       size_t libs, size_t protos, size_t svcs, size_t suites) {
    if (g_output_mode != OUTPUT_MODE_TUI || !g_tui_context || !g_tui_context->queue) {
        return;
    }

    tui_message_t msg = {0};
    msg.type = TUI_MSG_ASSETS_FOUND;
    msg.scanner = SCANNER_UNKNOWN;
    msg.assets_found = total;
    msg.cert_count = certs;
    msg.key_count = keys;
    msg.algorithm_count = algos;
    msg.lib_count = libs;
    msg.protocol_count = protos;
    msg.service_count = svcs;
    msg.suite_count = suites;
    msg.timestamp = time(NULL);

    tui_queue_push(g_tui_context->queue, &msg);
}

scanner_type_t tui_scanner_type_from_name(const char* name) {
    if (!name) return SCANNER_UNKNOWN;

    if (strstr(name, "certificate") || strstr(name, "Certificate")) {
        return SCANNER_CERTIFICATE;
    } else if (strstr(name, "key") || strstr(name, "Key")) {
        return SCANNER_KEY;
    } else if (strstr(name, "package") || strstr(name, "Package")) {
        return SCANNER_PACKAGE;
    } else if (strstr(name, "service") || strstr(name, "Service")) {
        return SCANNER_SERVICE;
    } else if (strstr(name, "filesystem") || strstr(name, "Filesystem")) {
        return SCANNER_FILESYSTEM;
    } else if (strstr(name, "output") || strstr(name, "Output")) {
        return SCANNER_OUTPUT;
    }

    return SCANNER_UNKNOWN;
}
