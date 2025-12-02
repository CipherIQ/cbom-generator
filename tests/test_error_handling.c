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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include "error_handling.h"
#include "secure_memory.h"

// Simple test framework
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_test_##name(void) { \
        printf("Running test: %s... ", #name); \
        tests_run++; \
        test_##name(); \
        tests_passed++; \
        printf("PASSED\n"); \
    } \
    static void test_##name(void)

#define ASSERT(condition) \
    do { \
        if (!(condition)) { \
            printf("FAILED\n  Assertion failed: %s\n  File: %s, Line: %d\n", \
                   #condition, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while(0)

TEST(error_collector_creation) {
    error_collector_t *collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    ASSERT(collector != NULL);
    ASSERT(collector->redact_sensitive_data == false);
    ASSERT(collector->min_log_level == ERROR_SEVERITY_DEBUG);
    ASSERT(collector->error_count == 0);
    
    error_collector_destroy(collector);
}

TEST(error_recording) {
    error_collector_t *collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    ASSERT(collector != NULL);
    
    // Add various types of errors
    int result = error_collector_add(collector, ERROR_CATEGORY_CONFIG, ERROR_SEVERITY_ERROR, 
                                   ENOENT, "config_parser", "Configuration file not found", "/etc/cbom.conf");
    ASSERT(result == 0);
    
    result = error_collector_add(collector, ERROR_CATEGORY_PERMISSION, ERROR_SEVERITY_WARNING, 
                                EACCES, "file_scanner", "Permission denied", "/root/private.key");
    ASSERT(result == 0);
    
    result = error_collector_add(collector, ERROR_CATEGORY_IO, ERROR_SEVERITY_CRITICAL, 
                                EIO, "disk_reader", "I/O error reading file", "/dev/sda1");
    ASSERT(result == 0);
    
    // Check error count
    ASSERT(collector->error_count == 3);
    
    // Check category counts
    ASSERT(collector->errors_by_category[ERROR_CATEGORY_CONFIG] == 1);
    ASSERT(collector->errors_by_category[ERROR_CATEGORY_PERMISSION] == 1);
    ASSERT(collector->errors_by_category[ERROR_CATEGORY_IO] == 1);
    
    // Check severity counts
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_ERROR] == 1);
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_WARNING] == 1);
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_CRITICAL] == 1);
    
    error_collector_destroy(collector);
}

TEST(error_filtering_by_severity) {
    // Create collector that only logs warnings and above
    error_collector_t *collector = error_collector_create(false, ERROR_SEVERITY_WARNING, NULL);
    ASSERT(collector != NULL);
    
    // Add errors of different severities
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_DEBUG, 
                       0, "test", "Debug message", NULL);
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_INFO, 
                       0, "test", "Info message", NULL);
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_WARNING, 
                       0, "test", "Warning message", NULL);
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_ERROR, 
                       0, "test", "Error message", NULL);
    
    // Only warning and error should be recorded
    ASSERT(collector->error_count == 2);
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_DEBUG] == 0);
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_INFO] == 0);
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_WARNING] == 1);
    ASSERT(collector->errors_by_severity[ERROR_SEVERITY_ERROR] == 1);
    
    error_collector_destroy(collector);
}

TEST(sensitive_data_redaction) {
    error_collector_t *collector = error_collector_create(true, ERROR_SEVERITY_DEBUG, NULL);
    ASSERT(collector != NULL);
    
    // Add error with sensitive data
    error_collector_add(collector, ERROR_CATEGORY_CONFIG, ERROR_SEVERITY_ERROR, 
                       0, "test", "Failed to connect with password=secret123", 
                       "/home/user/config.txt");
    
    ASSERT(collector->error_count == 1);
    
    // Check that sensitive data was redacted
    error_record_t *error = collector->errors;
    ASSERT(error != NULL);
    ASSERT(strstr(error->message, "secret123") == NULL); // Password should be redacted
    ASSERT(strstr(error->context, "/home/user") == NULL); // Home path should be redacted
    
    error_collector_destroy(collector);
}

TEST(error_statistics) {
    error_collector_t *collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    ASSERT(collector != NULL);
    
    // Add various errors
    error_collector_add(collector, ERROR_CATEGORY_CONFIG, ERROR_SEVERITY_ERROR, 0, "test", "Config error 1", NULL);
    error_collector_add(collector, ERROR_CATEGORY_CONFIG, ERROR_SEVERITY_WARNING, 0, "test", "Config warning", NULL);
    error_collector_add(collector, ERROR_CATEGORY_PERMISSION, ERROR_SEVERITY_CRITICAL, 0, "test", "Permission critical", NULL);
    error_collector_add(collector, ERROR_CATEGORY_IO, ERROR_SEVERITY_ERROR, 0, "test", "IO error", NULL);
    
    error_stats_t stats = error_collector_get_stats(collector);
    
    ASSERT(stats.total_errors == 4);
    ASSERT(stats.config_errors == 2);
    ASSERT(stats.permission_errors == 1);
    ASSERT(stats.io_errors == 1);
    ASSERT(stats.critical_errors == 1);
    ASSERT(stats.error_errors == 2);
    ASSERT(stats.warning_errors == 1);
    
    error_collector_destroy(collector);
}

TEST(error_json_output) {
    error_collector_t *collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    ASSERT(collector != NULL);
    
    // Add a test error
    error_collector_add(collector, ERROR_CATEGORY_VALIDATION, ERROR_SEVERITY_ERROR, 
                       42, "validator", "Invalid certificate", "cert.pem");
    
    json_object *errors_json = error_collector_to_json(collector);
    ASSERT(errors_json != NULL);
    ASSERT(json_object_is_type(errors_json, json_type_array));
    ASSERT(json_object_array_length(errors_json) == 1);
    
    // Check first error object
    json_object *error_obj = json_object_array_get_idx(errors_json, 0);
    ASSERT(error_obj != NULL);
    
    json_object *category_obj, *severity_obj, *component_obj, *message_obj;
    ASSERT(json_object_object_get_ex(error_obj, "category", &category_obj));
    ASSERT(json_object_object_get_ex(error_obj, "severity", &severity_obj));
    ASSERT(json_object_object_get_ex(error_obj, "component", &component_obj));
    ASSERT(json_object_object_get_ex(error_obj, "message", &message_obj));
    
    ASSERT(strcmp(json_object_get_string(category_obj), "validation") == 0);
    ASSERT(strcmp(json_object_get_string(severity_obj), "error") == 0);
    ASSERT(strcmp(json_object_get_string(component_obj), "validator") == 0);
    ASSERT(strcmp(json_object_get_string(message_obj), "Invalid certificate") == 0);
    
    json_object_put(errors_json);
    error_collector_destroy(collector);
}

TEST(completion_tracker) {
    completion_tracker_t *tracker = completion_tracker_create(10);
    ASSERT(tracker != NULL);
    ASSERT(tracker->total_tasks == 10);
    ASSERT(tracker->completed_tasks == 0);
    ASSERT(completion_tracker_get_percentage(tracker) == 0.0);
    
    // Complete some tasks
    completion_tracker_task_completed(tracker);
    completion_tracker_task_completed(tracker);
    completion_tracker_task_completed(tracker);
    
    ASSERT(tracker->completed_tasks == 3);
    ASSERT(completion_tracker_get_percentage(tracker) == 30.0);
    
    // Fail some tasks
    completion_tracker_task_failed(tracker);
    completion_tracker_task_failed(tracker);
    
    ASSERT(tracker->failed_tasks == 2);
    ASSERT(completion_tracker_get_percentage(tracker) == 50.0);
    
    // Skip some tasks
    completion_tracker_task_skipped(tracker);
    
    ASSERT(tracker->skipped_tasks == 1);
    ASSERT(completion_tracker_get_percentage(tracker) == 60.0);
    
    completion_tracker_destroy(tracker);
}

TEST(completion_tracker_json) {
    completion_tracker_t *tracker = completion_tracker_create(5);
    ASSERT(tracker != NULL);
    
    completion_tracker_task_completed(tracker);
    completion_tracker_task_failed(tracker);
    completion_tracker_task_skipped(tracker);
    
    json_object *completion_json = completion_tracker_to_json(tracker);
    ASSERT(completion_json != NULL);
    
    json_object *total_obj, *completed_obj, *failed_obj, *skipped_obj, *percentage_obj;
    ASSERT(json_object_object_get_ex(completion_json, "total_tasks", &total_obj));
    ASSERT(json_object_object_get_ex(completion_json, "completed_tasks", &completed_obj));
    ASSERT(json_object_object_get_ex(completion_json, "failed_tasks", &failed_obj));
    ASSERT(json_object_object_get_ex(completion_json, "skipped_tasks", &skipped_obj));
    ASSERT(json_object_object_get_ex(completion_json, "completion_percentage", &percentage_obj));
    
    ASSERT(json_object_get_int64(total_obj) == 5);
    ASSERT(json_object_get_int64(completed_obj) == 1);
    ASSERT(json_object_get_int64(failed_obj) == 1);
    ASSERT(json_object_get_int64(skipped_obj) == 1);
    ASSERT(json_object_get_double(percentage_obj) == 60.0);
    
    json_object_put(completion_json);
    completion_tracker_destroy(tracker);
}

TEST(exit_code_determination) {
    error_collector_t *collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    ASSERT(collector != NULL);
    
    // No errors -> success
    ASSERT(determine_exit_code(collector) == EXIT_SUCCESS);
    
    // Config error
    error_collector_add(collector, ERROR_CATEGORY_CONFIG, ERROR_SEVERITY_ERROR, 0, "test", "Config error", NULL);
    ASSERT(determine_exit_code(collector) == EXIT_CONFIG_ERROR);
    
    error_collector_destroy(collector);
    
    // Permission error
    collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    error_collector_add(collector, ERROR_CATEGORY_PERMISSION, ERROR_SEVERITY_ERROR, 0, "test", "Permission error", NULL);
    ASSERT(determine_exit_code(collector) == EXIT_PERMISSION_ERROR);
    
    error_collector_destroy(collector);
    
    // Critical error
    collector = error_collector_create(false, ERROR_SEVERITY_DEBUG, NULL);
    error_collector_add(collector, ERROR_CATEGORY_UNKNOWN, ERROR_SEVERITY_CRITICAL, 0, "test", "Critical error", NULL);
    ASSERT(determine_exit_code(collector) == EXIT_CRITICAL_ERROR);
    
    error_collector_destroy(collector);
}

int run_error_handling_tests(void) {
    // Run tests
    run_test_error_collector_creation();
    run_test_error_recording();
    run_test_error_filtering_by_severity();
    run_test_sensitive_data_redaction();
    run_test_error_statistics();
    run_test_error_json_output();
    run_test_completion_tracker();
    run_test_completion_tracker_json();
    run_test_exit_code_determination();
    
    printf("Tests run: %d, Passed: %d\n", tests_run, tests_passed);
    
    if (tests_run == tests_passed) {
        printf("Error handling tests PASSED!\n");
        return 0;
    } else {
        printf("Error handling tests FAILED!\n");
        return 1;
    }
}
