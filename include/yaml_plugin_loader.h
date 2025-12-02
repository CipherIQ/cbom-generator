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
 * @file yaml_plugin_loader.h
 * @brief YAML plugin loader for CBOM Generator v1.3
 *
 * Loads and parses YAML plugin files into plugin_schema structures.
 * Validates schema version compatibility and required fields.
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef YAML_PLUGIN_LOADER_H
#define YAML_PLUGIN_LOADER_H

#include "plugin_schema.h"
#include "yaml_parser.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load YAML plugin from file
 *
 * Parses a YAML plugin file and validates it against the plugin schema.
 * Returns a fully populated yaml_plugin_t structure on success.
 *
 * @param filepath Path to YAML plugin file
 * @return Parsed plugin structure, or NULL on error
 *
 * @note Caller must free returned plugin with yaml_plugin_free()
 * @note Validates plugin_schema_version compatibility
 * @note Validates all required fields are present
 * @note Logs detailed error messages to stderr (TUI-aware)
 *
 * Example:
 * @code
 * yaml_plugin_t* plugin = yaml_plugin_load("plugins/postgresql.yaml");
 * if (plugin) {
 *     printf("Loaded plugin: %s v%s\n", plugin->metadata.name, plugin->metadata.version);
 *     yaml_plugin_free(plugin);
 * }
 * @endcode
 */
yaml_plugin_t* yaml_plugin_load(const char* filepath);

/**
 * Validate plugin schema version compatibility
 *
 * Checks if the provided schema version is compatible with this loader.
 * Currently only supports version "1.0".
 *
 * @param schema_version Schema version string (e.g., "1.0")
 * @return true if compatible, false otherwise
 *
 * @note Future versions may support multiple schema versions
 */
bool yaml_plugin_validate_version(const char* schema_version);

/**
 * Load plugin metadata section
 *
 * Internal helper function to parse the "plugin" section of YAML file
 *
 * @param doc YAML document
 * @param metadata Output metadata structure
 * @return true on success, false on error
 */
bool yaml_plugin_load_metadata(yaml_doc_t* doc, yaml_plugin_metadata_t* metadata);

/**
 * Load plugin detection section
 *
 * Internal helper function to parse the "detection" section of YAML file
 *
 * @param doc YAML document
 * @param detection Output detection structure
 * @return true on success, false on error
 */
bool yaml_plugin_load_detection(yaml_doc_t* doc, plugin_detection_t* detection);

/**
 * Load plugin config extraction section
 *
 * Internal helper function to parse the "config_extraction" section of YAML file
 *
 * @param doc YAML document
 * @param config_extraction Output config extraction structure
 * @return true on success, false on error
 */
bool yaml_plugin_load_config_extraction(yaml_doc_t* doc, plugin_config_extraction_t* config_extraction);

/**
 * Parse detection method type from string
 *
 * @param type_str Type string (e.g., "process", "port")
 * @param type Output detection method type
 * @return true if valid type, false otherwise
 */
bool yaml_plugin_parse_detection_type(const char* type_str, detection_method_type_t* type);

/**
 * Parse directive type from string
 *
 * @param type_str Type string (e.g., "string", "boolean", "path")
 * @param type Output directive type
 * @return true if valid type, false otherwise
 */
bool yaml_plugin_parse_directive_type(const char* type_str, directive_type_t* type);

/**
 * Parse parser type from string
 *
 * @param parser_str Parser string (e.g., "ini", "apache", "nginx")
 * @param type Output parser type
 * @return true if valid parser, false otherwise
 */
bool yaml_plugin_parse_parser_type(const char* parser_str, parser_type_t* type);

/**
 * Validate loaded plugin for completeness
 *
 * Checks that all required fields are present and valid
 *
 * @param plugin Plugin structure to validate
 * @return true if valid, false otherwise
 */
bool yaml_plugin_validate(const yaml_plugin_t* plugin);

/**
 * Get string representation of plugin summary
 *
 * Returns a human-readable summary of the plugin for logging/debugging
 *
 * @param plugin Plugin structure
 * @return Formatted string (statically allocated, do not free)
 */
const char* yaml_plugin_summary(const yaml_plugin_t* plugin);

#ifdef __cplusplus
}
#endif

#endif /* YAML_PLUGIN_LOADER_H */
