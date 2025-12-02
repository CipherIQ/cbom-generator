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
 * @file test_config_parsers.c
 * @brief Test config file parsers
 *
 * Tests INI, Apache, and Nginx parsers with sample config files
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "config_parser.h"
#include "config_types.h"
#include "secure_memory.h"

static int test_count = 0;
static int pass_count = 0;

#define TEST_START(name) \
    printf("\n=== Test: %s ===\n", name); \
    test_count++;

#define TEST_PASS() \
    printf("✓ PASS\n"); \
    pass_count++;

#define TEST_FAIL(msg) \
    printf("✗ FAIL: %s\n", msg);

void test_ini_parser(void) {
    TEST_START("INI Parser (PostgreSQL config)");

    config_directive_t* directives = NULL;
    int count = 0;

    int ret = config_parser_parse(
        PARSER_TYPE_INI,
        "tests/config_samples/test_postgresql.conf",
        &directives,
        &count
    );

    if (ret != 0) {
        TEST_FAIL("Failed to parse INI file");
        return;
    }

    printf("Parsed %d directives\n", count);

    // Check for expected directives
    bool found_ssl = false;
    bool found_cert = false;
    bool found_key = false;

    for (int i = 0; i < count; i++) {
        printf("  [%s] %s = %s\n",
               directives[i].context ? directives[i].context : "root",
               directives[i].key,
               directives[i].value);

        if (strcmp(directives[i].key, "ssl") == 0 &&
            strcmp(directives[i].value, "on") == 0) {
            found_ssl = true;
        }
        if (strcmp(directives[i].key, "ssl_cert_file") == 0) {
            found_cert = true;
        }
        if (strcmp(directives[i].key, "ssl_key_file") == 0) {
            found_key = true;
        }
    }

    config_directives_free(directives, count);

    if (found_ssl && found_cert && found_key) {
        TEST_PASS();
    } else {
        TEST_FAIL("Missing expected directives");
    }
}

void test_apache_parser(void) {
    TEST_START("Apache Parser (SSL directives)");

    config_directive_t* directives = NULL;
    int count = 0;

    int ret = config_parser_parse(
        PARSER_TYPE_APACHE,
        "tests/config_samples/test_apache.conf",
        &directives,
        &count
    );

    if (ret != 0) {
        TEST_FAIL("Failed to parse Apache file");
        return;
    }

    printf("Parsed %d directives\n", count);

    // Check for expected SSL directives
    bool found_engine = false;
    bool found_cert = false;
    bool found_protocol = false;

    for (int i = 0; i < count; i++) {
        printf("  [%s] %s = %s\n",
               directives[i].context ? directives[i].context : "root",
               directives[i].key,
               directives[i].value);

        if (strcmp(directives[i].key, "SSLEngine") == 0) {
            found_engine = true;
        }
        if (strcmp(directives[i].key, "SSLCertificateFile") == 0) {
            found_cert = true;
        }
        if (strcmp(directives[i].key, "SSLProtocol") == 0) {
            found_protocol = true;
        }
    }

    config_directives_free(directives, count);

    if (found_engine && found_cert && found_protocol) {
        TEST_PASS();
    } else {
        TEST_FAIL("Missing expected SSL directives");
    }
}

void test_nginx_parser(void) {
    TEST_START("Nginx Parser (ssl_* directives)");

    config_directive_t* directives = NULL;
    int count = 0;

    int ret = config_parser_parse(
        PARSER_TYPE_NGINX,
        "tests/config_samples/test_nginx.conf",
        &directives,
        &count
    );

    if (ret != 0) {
        TEST_FAIL("Failed to parse Nginx file");
        return;
    }

    printf("Parsed %d directives\n", count);

    // Check for expected ssl_* directives
    bool found_cert = false;
    bool found_key = false;
    bool found_protocols = false;

    for (int i = 0; i < count; i++) {
        printf("  [%s] %s = %s\n",
               directives[i].context ? directives[i].context : "root",
               directives[i].key,
               directives[i].value);

        if (strcmp(directives[i].key, "ssl_certificate") == 0) {
            found_cert = true;
        }
        if (strcmp(directives[i].key, "ssl_certificate_key") == 0) {
            found_key = true;
        }
        if (strcmp(directives[i].key, "ssl_protocols") == 0) {
            found_protocols = true;
        }
    }

    config_directives_free(directives, count);

    if (found_cert && found_key && found_protocols) {
        TEST_PASS();
    } else {
        TEST_FAIL("Missing expected ssl_* directives");
    }
}

void test_type_conversion(void) {
    TEST_START("Type Conversion");

    // Test boolean conversion
    bool bool_val;
    if (config_convert_to_bool("on", &bool_val) == 0 && bool_val == true) {
        printf("  ✓ Boolean 'on' -> true\n");
    } else {
        TEST_FAIL("Boolean conversion failed");
        return;
    }

    if (config_convert_to_bool("off", &bool_val) == 0 && bool_val == false) {
        printf("  ✓ Boolean 'off' -> false\n");
    } else {
        TEST_FAIL("Boolean conversion failed");
        return;
    }

    // Test integer conversion
    int int_val;
    if (config_convert_to_int("5432", &int_val) == 0 && int_val == 5432) {
        printf("  ✓ Integer '5432' -> 5432\n");
    } else {
        TEST_FAIL("Integer conversion failed");
        return;
    }

    // Test string list conversion
    char** items = NULL;
    int count = 0;
    if (config_convert_to_string_list("TLSv1.2 TLSv1.3", ' ', &items, &count) == 0) {
        printf("  ✓ String list: %d items\n", count);
        if (count == 2 &&
            strcmp(items[0], "TLSv1.2") == 0 &&
            strcmp(items[1], "TLSv1.3") == 0) {
            printf("    - %s\n", items[0]);
            printf("    - %s\n", items[1]);
        }
        config_string_list_free(items, count);
    } else {
        TEST_FAIL("String list conversion failed");
        return;
    }

    TEST_PASS();
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    printf("=================================================================\n");
    printf("Config Parser Test Suite (v1.3 Phase 3)\n");
    printf("=================================================================\n");

    // Initialize secure memory
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory\n");
        return 1;
    }

    // Initialize parser registry
    if (config_parser_registry_init() != 0) {
        fprintf(stderr, "Failed to initialize parser registry\n");
        return 1;
    }

    // Run tests
    test_ini_parser();
    test_apache_parser();
    test_nginx_parser();
    test_type_conversion();

    // Cleanup
    config_parser_registry_destroy();

    // Summary
    printf("\n=================================================================\n");
    printf("Test Summary: %d/%d tests passed\n", pass_count, test_count);
    printf("=================================================================\n");

    if (pass_count == test_count) {
        printf("✓✓✓ ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("✗✗✗ SOME TESTS FAILED\n");
        return 1;
    }
}
