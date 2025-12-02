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
 * @file plugin_schema.c
 * @brief Plugin schema helper functions and memory management
 *
 * Implements free functions and type-to-string conversions for plugin_schema structures.
 */

#include "plugin_schema.h"
#include <stdlib.h>
#include <string.h>

void yaml_plugin_metadata_free(yaml_plugin_metadata_t* metadata) {
    if (!metadata) {
        return;
    }

    free(metadata->plugin_schema_version);
    free(metadata->name);
    free(metadata->version);
    free(metadata->author);
    free(metadata->category);
    free(metadata->description);
    free(metadata->requires_cbom_version);

    /* Zero out structure for safety */
    memset(metadata, 0, sizeof(yaml_plugin_metadata_t));
}

static void free_string_array(char** array, int count) {
    if (!array) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(array[i]);
    }
    free(array);
}

static void detection_method_free(detection_method_t* method) {
    if (!method) {
        return;
    }

    switch (method->type) {
        case DETECTION_METHOD_PROCESS:
            free_string_array(method->config.process.process_names,
                            method->config.process.process_name_count);
            free_string_array(method->config.process.command_patterns,
                            method->config.process.command_pattern_count);
            break;

        case DETECTION_METHOD_PORT:
            free(method->config.port.ports);
            free(method->config.port.protocol);
            break;

        case DETECTION_METHOD_CONFIG_FILE:
            free_string_array(method->config.config_file.paths,
                            method->config.config_file.path_count);
            break;

        case DETECTION_METHOD_SYSTEMD:
            free_string_array(method->config.systemd.service_names,
                            method->config.systemd.service_name_count);
            break;

        case DETECTION_METHOD_PACKAGE:
            free_string_array(method->config.package.package_names,
                            method->config.package.package_name_count);
            break;

        default:
            break;
    }
}

void plugin_detection_free(plugin_detection_t* detection) {
    if (!detection) {
        return;
    }

    if (detection->methods) {
        for (int i = 0; i < detection->method_count; i++) {
            detection_method_free(&detection->methods[i]);
        }
        free(detection->methods);
    }

    memset(detection, 0, sizeof(plugin_detection_t));
}

static void crypto_directive_rule_free(crypto_directive_rule_t* directive) {
    if (!directive) {
        return;
    }

    free(directive->key);
    free(directive->default_value);
    free(directive->maps_to);
    free(directive->separator);
    free_string_array(directive->enum_values, directive->enum_count);

    memset(directive, 0, sizeof(crypto_directive_rule_t));
}

static void config_file_rule_free(config_file_rule_t* rule) {
    if (!rule) {
        return;
    }

    free(rule->path);
    free(rule->encoding);

    if (rule->directives) {
        for (int i = 0; i < rule->directive_count; i++) {
            crypto_directive_rule_free(&rule->directives[i]);
        }
        free(rule->directives);
    }

    memset(rule, 0, sizeof(config_file_rule_t));
}

void plugin_config_extraction_free(plugin_config_extraction_t* config) {
    if (!config) {
        return;
    }

    if (config->files) {
        for (int i = 0; i < config->file_count; i++) {
            config_file_rule_free(&config->files[i]);
        }
        free(config->files);
    }

    memset(config, 0, sizeof(plugin_config_extraction_t));
}

void yaml_plugin_free(yaml_plugin_t* plugin) {
    if (!plugin) {
        return;
    }

    yaml_plugin_metadata_free(&plugin->metadata);
    plugin_detection_free(&plugin->detection);
    plugin_config_extraction_free(&plugin->config_extraction);

    free(plugin);
}

const char* detection_method_type_to_string(detection_method_type_t type) {
    switch (type) {
        case DETECTION_METHOD_PROCESS:
            return "process";
        case DETECTION_METHOD_PORT:
            return "port";
        case DETECTION_METHOD_CONFIG_FILE:
            return "config_file";
        case DETECTION_METHOD_SYSTEMD:
            return "systemd";
        case DETECTION_METHOD_PACKAGE:
            return "package";
        default:
            return "unknown";
    }
}

const char* directive_type_to_string(directive_type_t type) {
    switch (type) {
        case DIRECTIVE_TYPE_STRING:
            return "string";
        case DIRECTIVE_TYPE_BOOLEAN:
            return "boolean";
        case DIRECTIVE_TYPE_INTEGER:
            return "integer";
        case DIRECTIVE_TYPE_PATH:
            return "path";
        case DIRECTIVE_TYPE_STRING_LIST:
            return "string_list";
        default:
            return "unknown";
    }
}

const char* parser_type_to_string(parser_type_t type) {
    switch (type) {
        case PARSER_TYPE_INI:
            return "ini";
        case PARSER_TYPE_APACHE:
            return "apache";
        case PARSER_TYPE_NGINX:
            return "nginx";
        case PARSER_TYPE_YAML:
            return "yaml";
        case PARSER_TYPE_JSON:
            return "json";
        case PARSER_TYPE_CUSTOM:
            return "custom";
        default:
            return "unknown";
    }
}
