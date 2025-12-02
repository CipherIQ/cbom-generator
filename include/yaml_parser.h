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
 * @file yaml_parser.h
 * @brief Safe YAML parser wrapper for CBOM Generator v1.3
 *
 * Provides a safe, error-handling wrapper around libyaml for parsing
 * plugin configuration files.
 *
 * Features:
 * - File size limits (max 1MB)
 * - Depth limits (max 32 levels)
 * - UTF-8 validation
 * - Detailed error reporting with line numbers
 * - TUI-aware logging
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef YAML_PARSER_H
#define YAML_PARSER_H

#include <yaml.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * YAML parser safety limits
 */
#define YAML_MAX_FILE_SIZE (1024 * 1024)  /**< Max 1MB file size */
#define YAML_MAX_DEPTH 32                  /**< Max 32 levels of nesting */
#define YAML_MAX_RECURSION 100             /**< Max 100 recursive calls */

/**
 * YAML document wrapper
 *
 * Encapsulates libyaml structures with validity tracking
 */
typedef struct {
    yaml_document_t document;  /**< libyaml document structure */
    yaml_parser_t parser;      /**< libyaml parser structure */
    bool is_valid;             /**< Document validity flag */
    char* filepath;            /**< Original file path (for error reporting) */
    size_t file_size;          /**< File size in bytes */
} yaml_doc_t;

/**
 * Load YAML document from file
 *
 * @param filepath Path to YAML file
 * @return Parsed YAML document, or NULL on error
 *
 * @note Caller must free returned document with yaml_free()
 * @note Returns NULL if file exceeds YAML_MAX_FILE_SIZE
 * @note Logs detailed error messages to stderr (TUI-aware)
 */
yaml_doc_t* yaml_load_file(const char* filepath);

/**
 * Get YAML node by path
 *
 * Navigates the document tree using dot-separated path notation.
 * Example: "plugin.name" retrieves document.plugin.name
 *
 * @param doc YAML document
 * @param path Dot-separated path (e.g., "plugin.name")
 * @return YAML node at path, or NULL if not found
 *
 * @note Returns NULL if path is invalid or node doesn't exist
 * @note Path must use dot notation for nested keys
 */
yaml_node_t* yaml_get_node(yaml_doc_t* doc, const char* path);

/**
 * Get string value from YAML node
 *
 * @param doc YAML document
 * @param node YAML node
 * @return String value, or NULL if node is not a scalar string
 *
 * @note Returned string is owned by the document, do not free
 * @note Returns NULL if node is NULL or not a string
 */
const char* yaml_get_string(yaml_doc_t* doc, yaml_node_t* node);

/**
 * Get integer value from YAML node
 *
 * @param doc YAML document
 * @param node YAML node
 * @param value Pointer to store integer value
 * @return true if successful, false if node is not an integer
 *
 * @note Returns false if node is NULL or not a valid integer
 */
bool yaml_get_int(yaml_doc_t* doc, yaml_node_t* node, int* value);

/**
 * Get boolean value from YAML node
 *
 * Recognizes: true/false, yes/no, on/off (case-insensitive)
 *
 * @param doc YAML document
 * @param node YAML node
 * @param value Pointer to store boolean value
 * @return true if successful, false if node is not a boolean
 *
 * @note Returns false if node is NULL or not a recognized boolean
 */
bool yaml_get_bool(yaml_doc_t* doc, yaml_node_t* node, bool* value);

/**
 * Get array items from YAML sequence node
 *
 * @param doc YAML document
 * @param node YAML node (must be sequence type)
 * @param count Pointer to store array length
 * @return Array of YAML nodes, or NULL if node is not a sequence
 *
 * @note Caller must free returned array with free()
 * @note Returns NULL if node is NULL or not a sequence
 * @note count is set to 0 if array is empty
 */
yaml_node_t** yaml_get_array(yaml_doc_t* doc, yaml_node_t* node, int* count);

/**
 * Get mapping value by key
 *
 * @param doc YAML document
 * @param node YAML node (must be mapping type)
 * @param key Key to look up
 * @return YAML node for value, or NULL if key not found
 *
 * @note Returns NULL if node is not a mapping or key doesn't exist
 */
yaml_node_t* yaml_get_mapping_value(yaml_doc_t* doc, yaml_node_t* node, const char* key);

/**
 * Get all keys from YAML mapping node
 *
 * @param doc YAML document
 * @param node YAML node (must be mapping type)
 * @param count Pointer to store key count
 * @return Array of key strings, or NULL if node is not a mapping
 *
 * @note Caller must free returned array with free()
 * @note Returned strings are owned by the document, do not free
 */
const char** yaml_get_mapping_keys(yaml_doc_t* doc, yaml_node_t* node, int* count);

/**
 * Check if YAML node is scalar
 *
 * @param node YAML node
 * @return true if node is a scalar, false otherwise
 */
bool yaml_is_scalar(yaml_node_t* node);

/**
 * Check if YAML node is sequence
 *
 * @param node YAML node
 * @return true if node is a sequence, false otherwise
 */
bool yaml_is_sequence(yaml_node_t* node);

/**
 * Check if YAML node is mapping
 *
 * @param node YAML node
 * @return true if node is a mapping, false otherwise
 */
bool yaml_is_mapping(yaml_node_t* node);

/**
 * Get YAML node type as string
 *
 * @param node YAML node
 * @return String representation of node type
 */
const char* yaml_node_type_string(yaml_node_t* node);

/**
 * Free YAML document
 *
 * Cleans up all libyaml structures and allocated memory
 *
 * @param doc YAML document to free
 */
void yaml_free(yaml_doc_t* doc);

/**
 * Validate YAML file without parsing
 *
 * Checks if file exists, is readable, and has valid YAML syntax
 *
 * @param filepath Path to YAML file
 * @return true if file is valid YAML, false otherwise
 *
 * @note Logs validation errors to stderr (TUI-aware)
 */
bool yaml_validate_file(const char* filepath);

/**
 * Get last YAML parser error
 *
 * @param doc YAML document (may be NULL if parsing failed)
 * @return Error message string, or NULL if no error
 *
 * @note Returned string is statically allocated, do not free
 */
const char* yaml_get_error(yaml_doc_t* doc);

#ifdef __cplusplus
}
#endif

#endif /* YAML_PARSER_H */
