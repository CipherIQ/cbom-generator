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

#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <json-c/json.h>

// Error categories
typedef enum {
    ERROR_CATEGORY_CONFIG = 0,
    ERROR_CATEGORY_PERMISSION,
    ERROR_CATEGORY_IO,
    ERROR_CATEGORY_TIMEOUT,
    ERROR_CATEGORY_VALIDATION,
    ERROR_CATEGORY_SECURITY,
    ERROR_CATEGORY_MEMORY,
    ERROR_CATEGORY_NETWORK,
    ERROR_CATEGORY_UNKNOWN
} error_category_t;

// Error severity levels
typedef enum {
    ERROR_SEVERITY_DEBUG = 0,
    ERROR_SEVERITY_INFO,
    ERROR_SEVERITY_WARNING,
    ERROR_SEVERITY_ERROR,
    ERROR_SEVERITY_CRITICAL
} error_severity_t;

// Individual error record
typedef struct error_record {
    uint64_t timestamp;          // Unix timestamp in microseconds
    error_category_t category;   // Error category
    error_severity_t severity;   // Error severity
    int error_code;              // System error code (errno, etc.)
    char *component;             // Component that generated the error
    char *message;               // Error message (sensitive data redacted)
    char *context;               // Additional context (file path, etc.)
    struct error_record *next;   // Linked list pointer
} error_record_t;

// Error collector
typedef struct {
    error_record_t *errors;      // Linked list of errors
    size_t error_count;          // Total number of errors
    size_t errors_by_category[ERROR_CATEGORY_UNKNOWN + 1]; // Count by category
    size_t errors_by_severity[ERROR_SEVERITY_CRITICAL + 1]; // Count by severity
    bool redact_sensitive_data;  // Redact sensitive information
    error_severity_t min_log_level; // Minimum severity to log
    FILE *log_file;              // Optional error log file
    pthread_mutex_t mutex;       // Thread safety
} error_collector_t;

// Completion tracking
typedef struct {
    size_t total_tasks;          // Total number of tasks
    size_t completed_tasks;      // Number of completed tasks
    size_t failed_tasks;         // Number of failed tasks
    size_t skipped_tasks;        // Number of skipped tasks
    double completion_percentage; // Completion percentage (0.0 - 100.0)
    pthread_mutex_t mutex;       // Thread safety
} completion_tracker_t;

// Standardized exit codes
#define EXIT_SUCCESS 0           // Success
#define EXIT_CONFIG_ERROR 1      // Configuration error
#define EXIT_PERMISSION_ERROR 2  // Permission/access error
#define EXIT_IO_ERROR 3          // I/O error
#define EXIT_CRITICAL_ERROR 4    // Critical system error

// Error collector operations
error_collector_t* error_collector_create(bool redact_sensitive_data, error_severity_t min_log_level, const char *log_file_path);
void error_collector_destroy(error_collector_t *collector);

// Error recording
int error_collector_add(error_collector_t *collector, 
                       error_category_t category,
                       error_severity_t severity,
                       int error_code,
                       const char *component,
                       const char *message,
                       const char *context);

// Convenience macros for error recording
#define ERROR_LOG_DEBUG(collector, component, message, context) \
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_DEBUG, 0, component, message, context)

#define ERROR_LOG_INFO(collector, component, message, context) \
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_INFO, 0, component, message, context)

#define ERROR_LOG_WARNING(collector, category, component, message, context) \
    error_collector_add(collector, category, ERROR_SEVERITY_WARNING, 0, component, message, context)

#define ERROR_LOG_ERROR(collector, category, error_code, component, message, context) \
    error_collector_add(collector, category, ERROR_SEVERITY_ERROR, error_code, component, message, context)

#define ERROR_LOG_CRITICAL(collector, category, error_code, component, message, context) \
    error_collector_add(collector, category, ERROR_SEVERITY_CRITICAL, error_code, component, message, context)

// Error statistics
typedef struct {
    size_t total_errors;
    size_t critical_errors;
    size_t error_errors;
    size_t warning_errors;
    size_t config_errors;
    size_t permission_errors;
    size_t io_errors;
    size_t timeout_errors;
    size_t validation_errors;
    size_t security_errors;
} error_stats_t;

error_stats_t error_collector_get_stats(error_collector_t *collector);

// JSON output for BOM integration
json_object* error_collector_to_json(error_collector_t *collector);

// Completion tracking operations
completion_tracker_t* completion_tracker_create(size_t total_tasks);
void completion_tracker_destroy(completion_tracker_t *tracker);

int completion_tracker_task_completed(completion_tracker_t *tracker);
int completion_tracker_task_failed(completion_tracker_t *tracker);
int completion_tracker_task_skipped(completion_tracker_t *tracker);

double completion_tracker_get_percentage(completion_tracker_t *tracker);
json_object* completion_tracker_to_json(completion_tracker_t *tracker);

// Exit code determination
int determine_exit_code(error_collector_t *collector);

// Utility functions
const char* error_category_to_string(error_category_t category);
const char* error_severity_to_string(error_severity_t severity);
char* redact_sensitive_data(const char *input);

#endif // ERROR_HANDLING_H
