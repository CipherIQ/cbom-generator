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
 * @file plugin_schema.h
 * @brief YAML plugin schema definitions for CBOM Generator v1.3
 *
 * Defines data structures for declarative YAML-based plugins that enable
 * service detection and configuration extraction without C code.
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef PLUGIN_SCHEMA_H
#define PLUGIN_SCHEMA_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * YAML plugin schema version - must match version in YAML files
 */
#define YAML_PLUGIN_SCHEMA_VERSION "1.0"

/**
 * Maximum string lengths for YAML plugins (uses plugin_manager.h constants where applicable)
 */
#define YAML_PLUGIN_MAX_PATH_LENGTH 4096

/**
 * YAML plugin metadata - identifies and describes the YAML plugin
 *
 * Required fields: plugin_schema_version, name, version
 * Optional fields: author, category, description, priority, requires_cbom_version
 */
typedef struct {
    char* plugin_schema_version;  /**< Schema version (must be "1.0") */
    char* name;                    /**< Plugin name (required) */
    char* version;                 /**< Semantic version (required, e.g., "1.0.0") */
    char* author;                  /**< Plugin author (optional) */
    char* category;                /**< Category: "database", "web_server", etc. (optional) */
    char* description;             /**< Human-readable description (optional) */
    int priority;                  /**< Priority for execution order (default: 50, range: 0-100) */
    char* requires_cbom_version;   /**< Minimum CBOM version required (optional) */
    char* crypto_protocol;         /**< Protocol type: "TLS", "SSH", "IPSec", etc. (v1.5.1, optional) */
} yaml_plugin_metadata_t;

/**
 * Detection method types
 *
 * Defines how the plugin detects if a service is running
 */
typedef enum {
    DETECTION_METHOD_PROCESS,      /**< Detect via running process name/command */
    DETECTION_METHOD_PORT,         /**< Detect via listening network port */
    DETECTION_METHOD_CONFIG_FILE,  /**< Detect via configuration file presence */
    DETECTION_METHOD_SYSTEMD,      /**< Detect via systemd service */
    DETECTION_METHOD_PACKAGE,      /**< Detect via installed package */
    DETECTION_METHOD_BINARY        /**< Detect via executable binary presence */
} detection_method_type_t;

/**
 * Process detection configuration
 *
 * Detects services by process name or command line pattern
 * Phase 4: Enhanced with exclude patterns for disambiguation
 */
typedef struct {
    char** process_names;          /**< Array of process names (e.g., "postgres") */
    int process_name_count;        /**< Number of process names */
    char** command_patterns;       /**< Array of regex patterns for command line (must match) */
    int command_pattern_count;     /**< Number of command patterns */
    char** exclude_patterns;       /**< Array of regex patterns to reject (Phase 4) */
    int exclude_pattern_count;     /**< Number of exclude patterns (Phase 4) */
} process_detection_config_t;

/**
 * Port detection configuration
 *
 * Detects services by listening network ports
 * Phase 3: Enhanced with process ownership validation
 */
typedef struct {
    uint16_t* ports;               /**< Array of port numbers (e.g., 5432, 5433) */
    int port_count;                /**< Number of ports */
    char* protocol;                /**< Protocol: "tcp" or "udp" (default: "tcp") */
    bool check_ssl;                /**< Perform TLS handshake test (default: false) */
    bool validate_process;         /**< Verify which process owns the port (Phase 3) */
    char** expected_processes;     /**< Expected process names that should own port (Phase 3) */
    int expected_process_count;    /**< Number of expected processes (Phase 3) */
} port_detection_config_t;

/**
 * Config file detection configuration
 *
 * Detects services by configuration file presence
 */
typedef struct {
    char** paths;                  /**< Array of file paths (glob patterns supported) */
    int path_count;                /**< Number of paths */
    bool required;                 /**< Must exist or detection fails (default: false) */
} config_file_detection_config_t;

/**
 * Systemd detection configuration
 *
 * Detects services via systemd service manager
 */
typedef struct {
    char** service_names;          /**< Array of systemd service names */
    int service_name_count;        /**< Number of service names */
} systemd_detection_config_t;

/**
 * Package detection configuration
 *
 * Detects services by installed package
 * Phase 2: Enhanced with server/client package differentiation
 */
typedef struct {
    char** package_names;          /**< Array of package names (any match) */
    int package_name_count;        /**< Number of package names */
    char** exclude_packages;       /**< Client/utility packages to reject (e.g., mysql-common) */
    int exclude_count;             /**< Number of exclude packages */
    char** server_packages;        /**< Server packages required (e.g., mysql-server) */
    int server_count;              /**< Number of server packages */
    float confidence;              /**< Detection confidence (default: 0.90) */
} package_detection_config_t;

/**
 * Binary detection configuration
 *
 * Detects services by verifying executable binary exists
 * Supports glob patterns (e.g., /usr/lib/postgresql/WILDCARD/bin/postgres where WILDCARD is *)
 */
typedef struct {
    char** binary_paths;           /**< Array of binary paths to check */
    int path_count;                /**< Number of paths */
    bool required;                 /**< At least one must exist (default: true) */
    float confidence;              /**< Detection confidence (0.0-1.0, default: 0.95) */
} binary_detection_config_t;

/**
 * Detection method - union of all detection configs
 *
 * A plugin can define multiple detection methods; if ANY succeeds, the service is detected
 */
typedef struct {
    detection_method_type_t type;  /**< Detection method type */
    union {
        process_detection_config_t process;         /**< Process detection config */
        port_detection_config_t port;               /**< Port detection config */
        config_file_detection_config_t config_file; /**< Config file detection config */
        systemd_detection_config_t systemd;         /**< Systemd detection config */
        package_detection_config_t package;         /**< Package detection config */
        binary_detection_config_t binary;           /**< Binary detection config */
    } config;
} detection_method_t;

/**
 * Plugin detection configuration
 *
 * Contains all detection methods for the plugin
 */
typedef struct {
    detection_method_t* methods;   /**< Array of detection methods */
    int method_count;              /**< Number of detection methods (min: 1) */
} plugin_detection_t;

/**
 * Config directive types
 *
 * Defines the expected type of configuration directive values
 */
typedef enum {
    DIRECTIVE_TYPE_STRING,         /**< String value */
    DIRECTIVE_TYPE_BOOLEAN,        /**< Boolean value (true/false, on/off, yes/no) */
    DIRECTIVE_TYPE_INTEGER,        /**< Integer value */
    DIRECTIVE_TYPE_PATH,           /**< File path (may need resolution) */
    DIRECTIVE_TYPE_STRING_LIST     /**< List of strings (with separator) */
} directive_type_t;

/**
 * Crypto directive rule
 *
 * Defines how to extract a specific cryptographic directive from a config file
 */
typedef struct {
    char* key;                     /**< Directive key in config file (e.g., "ssl_cert_file") */
    directive_type_t type;         /**< Value type */
    char* default_value;           /**< Default value if not present (optional) */
    char* maps_to;                 /**< Where to store extracted value (e.g., "certificate.path") */
    bool optional;                 /**< Is directive optional (default: true) */
    bool resolve_path;             /**< Resolve relative paths (for PATH type) */
    char** enum_values;            /**< Valid values (for enum validation, optional) */
    int enum_count;                /**< Number of enum values */
    char* separator;               /**< Separator for STRING_LIST type (default: ",") */
} crypto_directive_rule_t;

/**
 * Parser types
 *
 * Defines the config file parser to use
 */
typedef enum {
    PARSER_TYPE_INI,               /**< INI-style parser (key=value) */
    PARSER_TYPE_APACHE,            /**< Apache-style parser (Directive Value) */
    PARSER_TYPE_NGINX,             /**< Nginx-style parser (directive value;) */
    PARSER_TYPE_YAML,              /**< YAML parser */
    PARSER_TYPE_JSON,              /**< JSON parser */
    PARSER_TYPE_OPENSSL_CIPHER,    /**< OpenSSL cipher string parser */
    PARSER_TYPE_CUSTOM             /**< Custom parser (requires C code) */
} parser_type_t;

/**
 * Config file extraction rule
 *
 * Defines how to extract cryptographic directives from a single config file
 */
typedef struct {
    char* path;                    /**< Path to config file (variables supported, e.g., "${DETECTED_CONFIG_DIR}/postgresql.conf") */
    parser_type_t parser_type;     /**< Parser to use */
    char* encoding;                /**< File encoding (default: "utf-8") */
    crypto_directive_rule_t* directives; /**< Directives to extract */
    int directive_count;           /**< Number of directives */
} config_file_rule_t;

/**
 * Config extraction configuration
 *
 * Contains all config file extraction rules for the plugin
 */
typedef struct {
    config_file_rule_t* files;     /**< Array of config files */
    int file_count;                /**< Number of config files */
} plugin_config_extraction_t;

/**
 * Complete YAML plugin structure
 *
 * Represents a fully parsed YAML plugin with all sections
 */
typedef struct {
    yaml_plugin_metadata_t metadata;          /**< Plugin metadata */
    plugin_detection_t detection;             /**< Detection configuration */
    plugin_config_extraction_t config_extraction; /**< Config extraction configuration */

    /**
     * Output mapping and validation sections omitted for Phase 1
     * (will be added in Phase 3)
     */
} yaml_plugin_t;

/**
 * Free YAML plugin metadata structure
 *
 * @param metadata Pointer to metadata structure to free
 */
void yaml_plugin_metadata_free(yaml_plugin_metadata_t* metadata);

/**
 * Free plugin detection structure
 *
 * @param detection Pointer to detection structure to free
 */
void plugin_detection_free(plugin_detection_t* detection);

/**
 * Free config extraction structure
 *
 * @param config Pointer to config extraction structure to free
 */
void plugin_config_extraction_free(plugin_config_extraction_t* config);

/**
 * Free complete YAML plugin structure
 *
 * @param plugin Pointer to plugin structure to free
 */
void yaml_plugin_free(yaml_plugin_t* plugin);

/**
 * Helper function: Convert detection method type to string
 *
 * @param type Detection method type
 * @return String representation of the type
 */
const char* detection_method_type_to_string(detection_method_type_t type);

/**
 * Helper function: Convert directive type to string
 *
 * @param type Directive type
 * @return String representation of the type
 */
const char* directive_type_to_string(directive_type_t type);

/**
 * Helper function: Convert parser type to string
 *
 * @param type Parser type
 * @return String representation of the type
 */
const char* parser_type_to_string(parser_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* PLUGIN_SCHEMA_H */
