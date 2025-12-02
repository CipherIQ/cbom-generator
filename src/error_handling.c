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
#include "error_handling.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <regex.h>

// Get current timestamp in microseconds
static uint64_t get_timestamp_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

// Create error collector
error_collector_t* error_collector_create(bool redact_sensitive_data, error_severity_t min_log_level, const char *log_file_path) {
    error_collector_t *collector = malloc(sizeof(error_collector_t));
    if (collector == NULL) {
        return NULL;
    }

    memset(collector, 0, sizeof(error_collector_t));
    collector->redact_sensitive_data = redact_sensitive_data;
    collector->min_log_level = min_log_level;
    collector->log_file = NULL;

    // Open log file if path provided
    if (log_file_path != NULL) {
        collector->log_file = fopen(log_file_path, "a");
        if (collector->log_file == NULL) {
            fprintf(stderr, "Warning: Failed to open error log file '%s'\n", log_file_path);
            // Continue without log file
        }
    }

    if (pthread_mutex_init(&collector->mutex, NULL) != 0) {
        if (collector->log_file != NULL) {
            fclose(collector->log_file);
        }
        free(collector);
        return NULL;
    }

    return collector;
}

// Destroy error collector
void error_collector_destroy(error_collector_t *collector) {
    if (collector == NULL) {
        return;
    }
    
    pthread_mutex_lock(&collector->mutex);
    
    // Free all error records
    error_record_t *current = collector->errors;
    while (current != NULL) {
        error_record_t *next = current->next;

        if (current->component) {
            free(current->component);
        }
        if (current->message) {
            free(current->message);  // Fix: Use free() not secure_free() - message allocated with strdup()/malloc()
        }
        if (current->context) {
            free(current->context);
        }

        secure_free(current, sizeof(error_record_t));
        current = next;
    }
    
    // Close log file if open
    if (collector->log_file != NULL) {
        fclose(collector->log_file);
        collector->log_file = NULL;
    }

    pthread_mutex_unlock(&collector->mutex);
    pthread_mutex_destroy(&collector->mutex);
    free(collector);
}

// Redact sensitive data from strings
char* redact_sensitive_data(const char *input) {
    if (input == NULL) {
        return NULL;
    }
    
    size_t len = strlen(input);
    char *output = malloc(len + 100); // Extra space for replacements
    if (output == NULL) {
        return NULL;
    }
    
    strcpy(output, input);
    
    // Simple pattern matching and replacement
    char *pos;
    
    // Replace password values
    pos = strstr(output, "password=");
    if (pos != NULL) {
        char *start = pos + 9; // After "password="
        char *end = start;
        while (*end && *end != ' ' && *end != '&' && *end != '\n') {
            end++;
        }
        if (end > start) {
            memmove(start + 10, end, strlen(end) + 1);
            memcpy(start, "[REDACTED]", 10);
        }
    }
    
    // Replace home directories
    pos = strstr(output, "/home/");
    if (pos != NULL) {
        char *start = pos;
        char *end = start + 6; // After "/home/"
        while (*end && *end != '/') {
            end++;
        }
        if (end > start + 6) {
            memmove(start + 10, end, strlen(end) + 1);
            memcpy(start, "[REDACTED]", 10);
        }
    }
    
    return output;
}

// Add error to collector
int error_collector_add(error_collector_t *collector, 
                       error_category_t category,
                       error_severity_t severity,
                       int error_code,
                       const char *component,
                       const char *message,
                       const char *context) {
    if (collector == NULL) {
        return -1;
    }
    
    // Skip if below minimum log level
    if (severity < collector->min_log_level) {
        return 0;
    }
    
    pthread_mutex_lock(&collector->mutex);
    
    // Create new error record
    error_record_t *record = secure_alloc(sizeof(error_record_t));
    if (record == NULL) {
        pthread_mutex_unlock(&collector->mutex);
        return -1;
    }
    
    memset(record, 0, sizeof(error_record_t));
    record->timestamp = get_timestamp_us();
    record->category = category;
    record->severity = severity;
    record->error_code = error_code;
    
    // Copy component name
    if (component != NULL) {
        record->component = strdup(component);
    }
    
    // Copy and potentially redact message
    if (message != NULL) {
        if (collector->redact_sensitive_data) {
            record->message = redact_sensitive_data(message);
        } else {
            record->message = strdup(message);
        }
    }
    
    // Copy and potentially redact context
    if (context != NULL) {
        if (collector->redact_sensitive_data) {
            record->context = redact_sensitive_data(context);
        } else {
            record->context = strdup(context);
        }
    }
    
    // Add to linked list
    record->next = collector->errors;
    collector->errors = record;
    
    // Update counters
    collector->error_count++;
    if (category <= ERROR_CATEGORY_UNKNOWN) {
        collector->errors_by_category[category]++;
    }
    if (severity <= ERROR_SEVERITY_CRITICAL) {
        collector->errors_by_severity[severity]++;
    }
    
    pthread_mutex_unlock(&collector->mutex);

    // Log to stderr for immediate feedback
    if (severity >= ERROR_SEVERITY_WARNING) {
        fprintf(stderr, "[%s] %s: %s",
                error_severity_to_string(severity),
                component ? component : "unknown",
                record->message ? record->message : "no message");
        if (record->context) {
            fprintf(stderr, " (%s)", record->context);
        }
        fprintf(stderr, "\n");
    }

    // Log to file if configured (thread-safe, already protected by mutex above)
    if (collector->log_file != NULL && severity >= ERROR_SEVERITY_WARNING) {
        // Get current timestamp
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

        // Write to log file with timestamp
        fprintf(collector->log_file, "[%s] [%s] %s: %s",
                timestamp,
                error_severity_to_string(severity),
                component ? component : "unknown",
                record->message ? record->message : "no message");
        if (record->context) {
            fprintf(collector->log_file, " (%s)", record->context);
        }
        fprintf(collector->log_file, "\n");

        // Flush immediately for real-time visibility (important for TUI)
        fflush(collector->log_file);
    }

    return 0;
}

// Get error statistics
error_stats_t error_collector_get_stats(error_collector_t *collector) {
    error_stats_t stats = {0};
    
    if (collector == NULL) {
        return stats;
    }
    
    pthread_mutex_lock(&collector->mutex);
    
    stats.total_errors = collector->error_count;
    stats.critical_errors = collector->errors_by_severity[ERROR_SEVERITY_CRITICAL];
    stats.error_errors = collector->errors_by_severity[ERROR_SEVERITY_ERROR];
    stats.warning_errors = collector->errors_by_severity[ERROR_SEVERITY_WARNING];
    stats.config_errors = collector->errors_by_category[ERROR_CATEGORY_CONFIG];
    stats.permission_errors = collector->errors_by_category[ERROR_CATEGORY_PERMISSION];
    stats.io_errors = collector->errors_by_category[ERROR_CATEGORY_IO];
    stats.timeout_errors = collector->errors_by_category[ERROR_CATEGORY_TIMEOUT];
    stats.validation_errors = collector->errors_by_category[ERROR_CATEGORY_VALIDATION];
    stats.security_errors = collector->errors_by_category[ERROR_CATEGORY_SECURITY];
    
    pthread_mutex_unlock(&collector->mutex);
    
    return stats;
}

// Convert error collector to JSON for BOM integration
json_object* error_collector_to_json(error_collector_t *collector) {
    if (collector == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&collector->mutex);
    
    json_object *errors_array = json_object_new_array();
    if (errors_array == NULL) {
        pthread_mutex_unlock(&collector->mutex);
        return NULL;
    }
    
    // Add errors in reverse order (most recent first)
    error_record_t *current = collector->errors;
    while (current != NULL) {
        json_object *error_obj = json_object_new_object();
        if (error_obj != NULL) {
            json_object_object_add(error_obj, "timestamp", 
                                  json_object_new_int64(current->timestamp));
            json_object_object_add(error_obj, "category", 
                                  json_object_new_string(error_category_to_string(current->category)));
            json_object_object_add(error_obj, "severity", 
                                  json_object_new_string(error_severity_to_string(current->severity)));
            json_object_object_add(error_obj, "error_code", 
                                  json_object_new_int(current->error_code));
            json_object_object_add(error_obj, "component", 
                                  json_object_new_string(current->component ? current->component : ""));
            json_object_object_add(error_obj, "message", 
                                  json_object_new_string(current->message ? current->message : ""));
            json_object_object_add(error_obj, "context", 
                                  json_object_new_string(current->context ? current->context : ""));
            
            json_object_array_add(errors_array, error_obj);
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&collector->mutex);
    
    return errors_array;
}

// Create completion tracker
completion_tracker_t* completion_tracker_create(size_t total_tasks) {
    completion_tracker_t *tracker = malloc(sizeof(completion_tracker_t));
    if (tracker == NULL) {
        return NULL;
    }
    
    memset(tracker, 0, sizeof(completion_tracker_t));
    tracker->total_tasks = total_tasks;
    
    if (pthread_mutex_init(&tracker->mutex, NULL) != 0) {
        free(tracker);
        return NULL;
    }
    
    return tracker;
}

// Destroy completion tracker
void completion_tracker_destroy(completion_tracker_t *tracker) {
    if (tracker == NULL) {
        return;
    }
    
    pthread_mutex_destroy(&tracker->mutex);
    free(tracker);
}

// Mark task as completed
int completion_tracker_task_completed(completion_tracker_t *tracker) {
    if (tracker == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&tracker->mutex);
    tracker->completed_tasks++;
    tracker->completion_percentage = (double)(tracker->completed_tasks + tracker->failed_tasks + tracker->skipped_tasks) 
                                   / (double)tracker->total_tasks * 100.0;
    pthread_mutex_unlock(&tracker->mutex);
    
    return 0;
}

// Mark task as failed
int completion_tracker_task_failed(completion_tracker_t *tracker) {
    if (tracker == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&tracker->mutex);
    tracker->failed_tasks++;
    tracker->completion_percentage = (double)(tracker->completed_tasks + tracker->failed_tasks + tracker->skipped_tasks) 
                                   / (double)tracker->total_tasks * 100.0;
    pthread_mutex_unlock(&tracker->mutex);
    
    return 0;
}

// Mark task as skipped
int completion_tracker_task_skipped(completion_tracker_t *tracker) {
    if (tracker == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&tracker->mutex);
    tracker->skipped_tasks++;
    tracker->completion_percentage = (double)(tracker->completed_tasks + tracker->failed_tasks + tracker->skipped_tasks) 
                                   / (double)tracker->total_tasks * 100.0;
    pthread_mutex_unlock(&tracker->mutex);
    
    return 0;
}

// Get completion percentage
double completion_tracker_get_percentage(completion_tracker_t *tracker) {
    if (tracker == NULL) {
        return 0.0;
    }
    
    pthread_mutex_lock(&tracker->mutex);
    double percentage = tracker->completion_percentage;
    pthread_mutex_unlock(&tracker->mutex);
    
    return percentage;
}

// Convert completion tracker to JSON
json_object* completion_tracker_to_json(completion_tracker_t *tracker) {
    if (tracker == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&tracker->mutex);
    
    json_object *completion_obj = json_object_new_object();
    if (completion_obj != NULL) {
        json_object_object_add(completion_obj, "total_tasks", 
                              json_object_new_int64(tracker->total_tasks));
        json_object_object_add(completion_obj, "completed_tasks", 
                              json_object_new_int64(tracker->completed_tasks));
        json_object_object_add(completion_obj, "failed_tasks", 
                              json_object_new_int64(tracker->failed_tasks));
        json_object_object_add(completion_obj, "skipped_tasks", 
                              json_object_new_int64(tracker->skipped_tasks));
        json_object_object_add(completion_obj, "completion_percentage", 
                              json_object_new_double(tracker->completion_percentage));
    }
    
    pthread_mutex_unlock(&tracker->mutex);
    
    return completion_obj;
}

// Determine appropriate exit code based on errors
int determine_exit_code(error_collector_t *collector) {
    if (collector == NULL) {
        return EXIT_SUCCESS;
    }
    
    pthread_mutex_lock(&collector->mutex);
    
    int exit_code = EXIT_SUCCESS;
    
    // Critical errors -> critical exit code
    if (collector->errors_by_severity[ERROR_SEVERITY_CRITICAL] > 0) {
        exit_code = EXIT_CRITICAL_ERROR;
    }
    // Configuration errors
    else if (collector->errors_by_category[ERROR_CATEGORY_CONFIG] > 0) {
        exit_code = EXIT_CONFIG_ERROR;
    }
    // Permission errors
    else if (collector->errors_by_category[ERROR_CATEGORY_PERMISSION] > 0) {
        exit_code = EXIT_PERMISSION_ERROR;
    }
    // I/O errors
    else if (collector->errors_by_category[ERROR_CATEGORY_IO] > 0) {
        exit_code = EXIT_IO_ERROR;
    }
    // Any other errors
    else if (collector->errors_by_severity[ERROR_SEVERITY_ERROR] > 0) {
        exit_code = EXIT_CRITICAL_ERROR;
    }
    
    pthread_mutex_unlock(&collector->mutex);
    
    return exit_code;
}

// Utility functions
const char* error_category_to_string(error_category_t category) {
    switch (category) {
        case ERROR_CATEGORY_CONFIG: return "config";
        case ERROR_CATEGORY_PERMISSION: return "permission";
        case ERROR_CATEGORY_IO: return "io";
        case ERROR_CATEGORY_TIMEOUT: return "timeout";
        case ERROR_CATEGORY_VALIDATION: return "validation";
        case ERROR_CATEGORY_SECURITY: return "security";
        case ERROR_CATEGORY_MEMORY: return "memory";
        case ERROR_CATEGORY_NETWORK: return "network";
        default: return "unknown";
    }
}

const char* error_severity_to_string(error_severity_t severity) {
    switch (severity) {
        case ERROR_SEVERITY_DEBUG: return "debug";
        case ERROR_SEVERITY_INFO: return "info";
        case ERROR_SEVERITY_WARNING: return "warning";
        case ERROR_SEVERITY_ERROR: return "error";
        case ERROR_SEVERITY_CRITICAL: return "critical";
        default: return "unknown";
    }
}
