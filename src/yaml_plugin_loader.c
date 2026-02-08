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
 * @file yaml_plugin_loader.c
 * @brief YAML plugin loader implementation
 *
 * Parses YAML plugin files into plugin_schema structures with validation.
 */

#define _GNU_SOURCE
#include "yaml_plugin_loader.h"
#include "yaml_parser.h"
#include "plugin_schema.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <strings.h>

/* Forward declarations */
extern int g_output_mode;
#define OUTPUT_MODE_TUI 1

static void log_printf(const char* format, ...) {
    if (g_output_mode == OUTPUT_MODE_TUI) {
        return;
    }
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
}

bool yaml_plugin_validate_version(const char* schema_version) {
    if (!schema_version) {
        return false;
    }
    return strcmp(schema_version, YAML_PLUGIN_SCHEMA_VERSION) == 0;
}

bool yaml_plugin_parse_detection_type(const char* type_str, detection_method_type_t* type) {
    if (!type_str || !type) {
        return false;
    }

    if (strcmp(type_str, "process") == 0) {
        *type = DETECTION_METHOD_PROCESS;
    } else if (strcmp(type_str, "port") == 0) {
        *type = DETECTION_METHOD_PORT;
    } else if (strcmp(type_str, "config_file") == 0) {
        *type = DETECTION_METHOD_CONFIG_FILE;
    } else if (strcmp(type_str, "systemd") == 0) {
        *type = DETECTION_METHOD_SYSTEMD;
    } else if (strcmp(type_str, "package") == 0) {
        *type = DETECTION_METHOD_PACKAGE;
    } else if (strcmp(type_str, "binary") == 0) {
        *type = DETECTION_METHOD_BINARY;
    } else {
        return false;
    }

    return true;
}

bool yaml_plugin_parse_directive_type(const char* type_str, directive_type_t* type) {
    if (!type_str || !type) {
        return false;
    }

    if (strcmp(type_str, "string") == 0) {
        *type = DIRECTIVE_TYPE_STRING;
    } else if (strcmp(type_str, "boolean") == 0) {
        *type = DIRECTIVE_TYPE_BOOLEAN;
    } else if (strcmp(type_str, "integer") == 0) {
        *type = DIRECTIVE_TYPE_INTEGER;
    } else if (strcmp(type_str, "path") == 0) {
        *type = DIRECTIVE_TYPE_PATH;
    } else if (strcmp(type_str, "string_list") == 0) {
        *type = DIRECTIVE_TYPE_STRING_LIST;
    } else {
        return false;
    }

    return true;
}

bool yaml_plugin_parse_parser_type(const char* parser_str, parser_type_t* type) {
    if (!parser_str || !type) {
        return false;
    }

    if (strcmp(parser_str, "ini") == 0) {
        *type = PARSER_TYPE_INI;
    } else if (strcmp(parser_str, "apache") == 0) {
        *type = PARSER_TYPE_APACHE;
    } else if (strcmp(parser_str, "nginx") == 0) {
        *type = PARSER_TYPE_NGINX;
    } else if (strcmp(parser_str, "yaml") == 0) {
        *type = PARSER_TYPE_YAML;
    } else if (strcmp(parser_str, "json") == 0) {
        *type = PARSER_TYPE_JSON;
    } else if (strcmp(parser_str, "custom") == 0) {
        *type = PARSER_TYPE_CUSTOM;
    } else {
        return false;
    }

    return true;
}

bool yaml_plugin_load_metadata(yaml_doc_t* doc, yaml_plugin_metadata_t* metadata) {
    if (!doc || !metadata) {
        return false;
    }

    yaml_node_t* plugin_node = yaml_get_node(doc, "plugin");
    if (!plugin_node || !yaml_is_mapping(plugin_node)) {
        log_printf("ERROR: Missing or invalid 'plugin' section\n");
        return false;
    }

    /* Required: plugin_schema_version */
    yaml_node_t* version_node = yaml_get_mapping_value(doc, plugin_node, "plugin_schema_version");
    if (!version_node) {
        log_printf("ERROR: Missing required field 'plugin.plugin_schema_version'\n");
        return false;
    }
    const char* schema_version = yaml_get_string(doc, version_node);
    if (!yaml_plugin_validate_version(schema_version)) {
        log_printf("ERROR: Unsupported plugin_schema_version '%s' (expected '%s')\n",
                   schema_version, YAML_PLUGIN_SCHEMA_VERSION);
        return false;
    }
    metadata->plugin_schema_version = strdup(schema_version);

    /* Required: name */
    yaml_node_t* name_node = yaml_get_mapping_value(doc, plugin_node, "name");
    if (!name_node) {
        log_printf("ERROR: Missing required field 'plugin.name'\n");
        return false;
    }
    metadata->name = strdup(yaml_get_string(doc, name_node));

    /* Required: version */
    yaml_node_t* plugin_version_node = yaml_get_mapping_value(doc, plugin_node, "version");
    if (!plugin_version_node) {
        log_printf("ERROR: Missing required field 'plugin.version'\n");
        return false;
    }
    metadata->version = strdup(yaml_get_string(doc, plugin_version_node));

    /* Optional: author */
    yaml_node_t* author_node = yaml_get_mapping_value(doc, plugin_node, "author");
    if (author_node) {
        metadata->author = strdup(yaml_get_string(doc, author_node));
    }

    /* Optional: category */
    yaml_node_t* category_node = yaml_get_mapping_value(doc, plugin_node, "category");
    if (category_node) {
        metadata->category = strdup(yaml_get_string(doc, category_node));
    }

    /* Optional: description */
    yaml_node_t* desc_node = yaml_get_mapping_value(doc, plugin_node, "description");
    if (desc_node) {
        metadata->description = strdup(yaml_get_string(doc, desc_node));
    }

    /* Optional: priority (default 50) */
    yaml_node_t* priority_node = yaml_get_mapping_value(doc, plugin_node, "priority");
    if (priority_node) {
        yaml_get_int(doc, priority_node, &metadata->priority);
    } else {
        metadata->priority = 50;
    }

    /* Optional: requires_cbom_version */
    yaml_node_t* requires_node = yaml_get_mapping_value(doc, plugin_node, "requires_cbom_version");
    if (requires_node) {
        metadata->requires_cbom_version = strdup(yaml_get_string(doc, requires_node));
    }

    /* Optional: crypto_protocol (v1.5.1) */
    yaml_node_t* protocol_node = yaml_get_mapping_value(doc, plugin_node, "crypto_protocol");
    if (protocol_node) {
        metadata->crypto_protocol = strdup(yaml_get_string(doc, protocol_node));
    }

    return true;
}

/* Helper: Load string array from YAML sequence */
static char** load_string_array(yaml_doc_t* doc, yaml_node_t* node, int* count) {
    if (!node || !yaml_is_sequence(node)) {
        *count = 0;
        return NULL;
    }

    yaml_node_t** items = yaml_get_array(doc, node, count);
    if (!items || *count == 0) {
        return NULL;
    }

    char** strings = calloc(*count, sizeof(char*));
    for (int i = 0; i < *count; i++) {
        const char* str = yaml_get_string(doc, items[i]);
        strings[i] = str ? strdup(str) : NULL;
    }

    free(items);
    return strings;
}

/* Helper: Load uint16 array from YAML sequence */
static uint16_t* load_port_array(yaml_doc_t* doc, yaml_node_t* node, int* count) {
    if (!node || !yaml_is_sequence(node)) {
        *count = 0;
        return NULL;
    }

    yaml_node_t** items = yaml_get_array(doc, node, count);
    if (!items || *count == 0) {
        return NULL;
    }

    uint16_t* ports = calloc(*count, sizeof(uint16_t));
    for (int i = 0; i < *count; i++) {
        int port_val = 0;
        if (yaml_get_int(doc, items[i], &port_val)) {
            ports[i] = (uint16_t)port_val;
        }
    }

    free(items);
    return ports;
}

/* Load single detection method */
static bool load_detection_method(yaml_doc_t* doc, yaml_node_t* method_node, detection_method_t* method) {
    if (!yaml_is_mapping(method_node)) {
        return false;
    }

    /* Required: type */
    yaml_node_t* type_node = yaml_get_mapping_value(doc, method_node, "type");
    if (!type_node) {
        log_printf("ERROR: Detection method missing 'type' field\n");
        return false;
    }

    const char* type_str = yaml_get_string(doc, type_node);
    if (!yaml_plugin_parse_detection_type(type_str, &method->type)) {
        log_printf("ERROR: Invalid detection method type '%s'\n", type_str);
        return false;
    }

    /* Parse type-specific fields */
    switch (method->type) {
        case DETECTION_METHOD_PROCESS: {
            yaml_node_t* names_node = yaml_get_mapping_value(doc, method_node, "names");
            method->config.process.process_names = load_string_array(doc, names_node, &method->config.process.process_name_count);

            yaml_node_t* patterns_node = yaml_get_mapping_value(doc, method_node, "command_patterns");
            method->config.process.command_patterns = load_string_array(doc, patterns_node, &method->config.process.command_pattern_count);

            // Phase 4: Parse exclude_patterns
            yaml_node_t* exclude_node = yaml_get_mapping_value(doc, method_node, "exclude_patterns");
            if (exclude_node) {
                method->config.process.exclude_patterns = load_string_array(doc, exclude_node,
                                                                           &method->config.process.exclude_pattern_count);
            } else {
                method->config.process.exclude_patterns = NULL;
                method->config.process.exclude_pattern_count = 0;
            }
            break;
        }

        case DETECTION_METHOD_PORT: {
            yaml_node_t* ports_node = yaml_get_mapping_value(doc, method_node, "ports");
            method->config.port.ports = load_port_array(doc, ports_node, &method->config.port.port_count);

            yaml_node_t* protocol_node = yaml_get_mapping_value(doc, method_node, "protocol");
            if (protocol_node) {
                method->config.port.protocol = strdup(yaml_get_string(doc, protocol_node));
            } else {
                method->config.port.protocol = strdup("tcp");
            }

            yaml_node_t* check_ssl_node = yaml_get_mapping_value(doc, method_node, "check_ssl");
            if (check_ssl_node) {
                yaml_get_bool(doc, check_ssl_node, &method->config.port.check_ssl);
            }

            // Phase 3: Parse validate_process and expected_processes
            yaml_node_t* validate_node = yaml_get_mapping_value(doc, method_node, "validate_process");
            if (validate_node) {
                yaml_get_bool(doc, validate_node, &method->config.port.validate_process);
            } else {
                method->config.port.validate_process = false;
            }

            yaml_node_t* expected_node = yaml_get_mapping_value(doc, method_node, "expected_processes");
            if (expected_node) {
                method->config.port.expected_processes = load_string_array(doc, expected_node,
                                                                          &method->config.port.expected_process_count);
            } else {
                method->config.port.expected_processes = NULL;
                method->config.port.expected_process_count = 0;
            }
            break;
        }

        case DETECTION_METHOD_CONFIG_FILE: {
            yaml_node_t* paths_node = yaml_get_mapping_value(doc, method_node, "paths");
            method->config.config_file.paths = load_string_array(doc, paths_node, &method->config.config_file.path_count);

            yaml_node_t* required_node = yaml_get_mapping_value(doc, method_node, "required");
            if (required_node) {
                yaml_get_bool(doc, required_node, &method->config.config_file.required);
            }
            break;
        }

        case DETECTION_METHOD_SYSTEMD: {
            yaml_node_t* services_node = yaml_get_mapping_value(doc, method_node, "service_names");
            method->config.systemd.service_names = load_string_array(doc, services_node, &method->config.systemd.service_name_count);
            break;
        }

        case DETECTION_METHOD_PACKAGE: {
            yaml_node_t* packages_node = yaml_get_mapping_value(doc, method_node, "package_names");
            method->config.package.package_names = load_string_array(doc, packages_node, &method->config.package.package_name_count);

            // Phase 2: Parse exclude_packages and server_packages
            yaml_node_t* exclude_node = yaml_get_mapping_value(doc, method_node, "exclude_packages");
            if (exclude_node) {
                method->config.package.exclude_packages = load_string_array(doc, exclude_node, &method->config.package.exclude_count);
            } else {
                method->config.package.exclude_packages = NULL;
                method->config.package.exclude_count = 0;
            }

            yaml_node_t* server_node = yaml_get_mapping_value(doc, method_node, "server_packages");
            if (server_node) {
                method->config.package.server_packages = load_string_array(doc, server_node, &method->config.package.server_count);
            } else {
                method->config.package.server_packages = NULL;
                method->config.package.server_count = 0;
            }

            // Parse optional confidence field
            yaml_node_t* confidence_node = yaml_get_mapping_value(doc, method_node, "confidence");
            if (confidence_node && confidence_node->type == YAML_SCALAR_NODE) {
                const char* confidence_str = (const char*)confidence_node->data.scalar.value;
                method->config.package.confidence = atof(confidence_str);
            } else {
                method->config.package.confidence = 0.90f;  // Default
            }
            break;
        }

        case DETECTION_METHOD_BINARY: {
            yaml_node_t* paths_node = yaml_get_mapping_value(doc, method_node, "paths");
            method->config.binary.binary_paths = load_string_array(doc, paths_node, &method->config.binary.path_count);

            // Parse optional 'required' field (default: true)
            yaml_node_t* required_node = yaml_get_mapping_value(doc, method_node, "required");
            if (required_node && required_node->type == YAML_SCALAR_NODE) {
                const char* required_str = (const char*)required_node->data.scalar.value;
                method->config.binary.required = (strcmp(required_str, "true") == 0 ||
                                                  strcmp(required_str, "yes") == 0);
            } else {
                method->config.binary.required = true;  // Default
            }

            // Parse optional 'confidence' field (default: 0.95)
            yaml_node_t* confidence_node = yaml_get_mapping_value(doc, method_node, "confidence");
            if (confidence_node && confidence_node->type == YAML_SCALAR_NODE) {
                const char* confidence_str = (const char*)confidence_node->data.scalar.value;
                method->config.binary.confidence = atof(confidence_str);
            } else {
                method->config.binary.confidence = 0.95f;  // Default
            }
            break;
        }

        default:
            return false;
    }

    return true;
}

bool yaml_plugin_load_detection(yaml_doc_t* doc, plugin_detection_t* detection) {
    if (!doc || !detection) {
        return false;
    }

    yaml_node_t* detection_node = yaml_get_node(doc, "detection");
    if (!detection_node || !yaml_is_mapping(detection_node)) {
        log_printf("ERROR: Missing or invalid 'detection' section\n");
        return false;
    }

    /* Required: methods array */
    yaml_node_t* methods_node = yaml_get_mapping_value(doc, detection_node, "methods");
    if (!methods_node || !yaml_is_sequence(methods_node)) {
        log_printf("ERROR: Missing or invalid 'detection.methods' array\n");
        return false;
    }

    int method_count = 0;
    yaml_node_t** method_items = yaml_get_array(doc, methods_node, &method_count);
    if (!method_items || method_count == 0) {
        log_printf("ERROR: 'detection.methods' array is empty\n");
        return false;
    }

    detection->methods = calloc(method_count, sizeof(detection_method_t));
    detection->method_count = method_count;

    for (int i = 0; i < method_count; i++) {
        if (!load_detection_method(doc, method_items[i], &detection->methods[i])) {
            free(method_items);
            return false;
        }
    }

    free(method_items);
    return true;
}

/* Load single crypto directive */
static bool load_crypto_directive(yaml_doc_t* doc, yaml_node_t* directive_node, crypto_directive_rule_t* directive) {
    if (!yaml_is_mapping(directive_node)) {
        return false;
    }

    /* Required: key */
    yaml_node_t* key_node = yaml_get_mapping_value(doc, directive_node, "key");
    if (!key_node) {
        return false;
    }
    directive->key = strdup(yaml_get_string(doc, key_node));

    /* Required: type */
    yaml_node_t* type_node = yaml_get_mapping_value(doc, directive_node, "type");
    if (!type_node) {
        return false;
    }
    const char* type_str = yaml_get_string(doc, type_node);
    if (!yaml_plugin_parse_directive_type(type_str, &directive->type)) {
        return false;
    }

    /* Optional: default */
    yaml_node_t* default_node = yaml_get_mapping_value(doc, directive_node, "default");
    if (default_node) {
        directive->default_value = strdup(yaml_get_string(doc, default_node));
    }

    /* Optional: maps_to */
    yaml_node_t* maps_to_node = yaml_get_mapping_value(doc, directive_node, "maps_to");
    if (maps_to_node) {
        directive->maps_to = strdup(yaml_get_string(doc, maps_to_node));
    }

    /* Optional: optional (default true) */
    yaml_node_t* optional_node = yaml_get_mapping_value(doc, directive_node, "optional");
    if (optional_node) {
        yaml_get_bool(doc, optional_node, &directive->optional);
    } else {
        directive->optional = true;
    }

    /* Optional: resolve (for path type) */
    yaml_node_t* resolve_node = yaml_get_mapping_value(doc, directive_node, "resolve");
    if (resolve_node) {
        yaml_get_bool(doc, resolve_node, &directive->resolve_path);
    }

    /* Optional: enum */
    yaml_node_t* enum_node = yaml_get_mapping_value(doc, directive_node, "enum");
    if (enum_node) {
        directive->enum_values = load_string_array(doc, enum_node, &directive->enum_count);
    }

    /* Optional: separator (for string_list type) */
    yaml_node_t* separator_node = yaml_get_mapping_value(doc, directive_node, "separator");
    if (separator_node) {
        directive->separator = strdup(yaml_get_string(doc, separator_node));
    }

    return true;
}

/* Load single config file rule */
static bool load_config_file_rule(yaml_doc_t* doc, yaml_node_t* file_node, config_file_rule_t* rule) {
    if (!yaml_is_mapping(file_node)) {
        return false;
    }

    /* Required: path */
    yaml_node_t* path_node = yaml_get_mapping_value(doc, file_node, "path");
    if (!path_node) {
        return false;
    }
    rule->path = strdup(yaml_get_string(doc, path_node));

    /* Required: parser */
    yaml_node_t* parser_node = yaml_get_mapping_value(doc, file_node, "parser");
    if (!parser_node) {
        return false;
    }
    const char* parser_str = yaml_get_string(doc, parser_node);
    if (!yaml_plugin_parse_parser_type(parser_str, &rule->parser_type)) {
        return false;
    }

    /* Optional: encoding */
    yaml_node_t* encoding_node = yaml_get_mapping_value(doc, file_node, "encoding");
    if (encoding_node) {
        rule->encoding = strdup(yaml_get_string(doc, encoding_node));
    } else {
        rule->encoding = strdup("utf-8");
    }

    /* Optional: crypto_directives */
    yaml_node_t* directives_node = yaml_get_mapping_value(doc, file_node, "crypto_directives");
    if (directives_node && yaml_is_sequence(directives_node)) {
        int directive_count = 0;
        yaml_node_t** directive_items = yaml_get_array(doc, directives_node, &directive_count);

        if (directive_items && directive_count > 0) {
            rule->directives = calloc(directive_count, sizeof(crypto_directive_rule_t));
            rule->directive_count = directive_count;

            for (int i = 0; i < directive_count; i++) {
                if (!load_crypto_directive(doc, directive_items[i], &rule->directives[i])) {
                    free(directive_items);
                    return false;
                }
            }

            free(directive_items);
        }
    }

    return true;
}

bool yaml_plugin_load_config_extraction(yaml_doc_t* doc, plugin_config_extraction_t* config_extraction) {
    if (!doc || !config_extraction) {
        return false;
    }

    yaml_node_t* config_node = yaml_get_node(doc, "config_extraction");
    if (!config_node) {
        /* config_extraction is optional */
        config_extraction->files = NULL;
        config_extraction->file_count = 0;
        return true;
    }

    if (!yaml_is_mapping(config_node)) {
        return false;
    }

    /* Optional: files array */
    yaml_node_t* files_node = yaml_get_mapping_value(doc, config_node, "files");
    if (!files_node || !yaml_is_sequence(files_node)) {
        config_extraction->files = NULL;
        config_extraction->file_count = 0;
        return true;
    }

    int file_count = 0;
    yaml_node_t** file_items = yaml_get_array(doc, files_node, &file_count);
    if (!file_items || file_count == 0) {
        config_extraction->files = NULL;
        config_extraction->file_count = 0;
        return true;
    }

    config_extraction->files = calloc(file_count, sizeof(config_file_rule_t));
    config_extraction->file_count = file_count;

    for (int i = 0; i < file_count; i++) {
        if (!load_config_file_rule(doc, file_items[i], &config_extraction->files[i])) {
            free(file_items);
            return false;
        }
    }

    free(file_items);
    return true;
}

yaml_plugin_t* yaml_plugin_load(const char* filepath) {
    if (!filepath) {
        log_printf("ERROR: NULL filepath provided to yaml_plugin_load\n");
        return NULL;
    }

    /* Load YAML document */
    yaml_doc_t* doc = yaml_load_file(filepath);
    if (!doc) {
        return NULL;
    }

    /* Allocate plugin structure */
    yaml_plugin_t* plugin = calloc(1, sizeof(yaml_plugin_t));
    if (!plugin) {
        log_printf("ERROR: Failed to allocate memory for plugin\n");
        yaml_doc_free(doc);
        return NULL;
    }

    /* Load metadata section */
    if (!yaml_plugin_load_metadata(doc, &plugin->metadata)) {
        log_printf("ERROR: Failed to load plugin metadata from '%s'\n", filepath);
        yaml_plugin_free(plugin);
        yaml_doc_free(doc);
        return NULL;
    }

    /* Load detection section */
    if (!yaml_plugin_load_detection(doc, &plugin->detection)) {
        log_printf("ERROR: Failed to load plugin detection from '%s'\n", filepath);
        yaml_plugin_free(plugin);
        yaml_doc_free(doc);
        return NULL;
    }

    /* Load config_extraction section (optional) */
    if (!yaml_plugin_load_config_extraction(doc, &plugin->config_extraction)) {
        log_printf("ERROR: Failed to load plugin config_extraction from '%s'\n", filepath);
        yaml_plugin_free(plugin);
        yaml_doc_free(doc);
        return NULL;
    }

    yaml_doc_free(doc);
    return plugin;
}

bool yaml_plugin_validate(const yaml_plugin_t* plugin) {
    if (!plugin) {
        return false;
    }

    /* Validate metadata */
    if (!plugin->metadata.name || !plugin->metadata.version || !plugin->metadata.plugin_schema_version) {
        return false;
    }

    /* Validate detection has at least one method */
    if (plugin->detection.method_count == 0) {
        return false;
    }

    return true;
}

const char* yaml_plugin_summary(const yaml_plugin_t* plugin) {
    static char summary[512];

    if (!plugin) {
        return "NULL plugin";
    }

    snprintf(summary, sizeof(summary),
             "Plugin '%s' v%s (%s), %d detection methods, %d config files",
             plugin->metadata.name ? plugin->metadata.name : "unknown",
             plugin->metadata.version ? plugin->metadata.version : "unknown",
             plugin->metadata.category ? plugin->metadata.category : "uncategorized",
             plugin->detection.method_count,
             plugin->config_extraction.file_count);

    return summary;
}
