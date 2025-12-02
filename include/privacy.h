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

#ifndef PRIVACY_H
#define PRIVACY_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Privacy configuration
typedef struct {
    bool no_personal_data;       // Enable privacy-by-default mode (default: true)
    char* salt;                  // Salt for consistent hashing (from CBOM_SALT env var)
    size_t salt_length;          // Length of salt in bytes
    char* consent_note_path;     // Path to legal compliance consent note
    bool redact_usernames;       // Redact usernames from paths
    bool redact_home_paths;      // Redact home directory paths
    bool redact_hostnames;       // Redact hostnames
    bool sanitize_evidence;      // Sanitize evidence to never include secrets
} privacy_config_t;

// Privacy context for consistent hashing
typedef struct {
    privacy_config_t config;
    uint8_t* hash_key;           // Derived key for HMAC-SHA256
    size_t hash_key_length;      // Length of hash key
    bool initialized;            // Whether privacy system is initialized
} privacy_context_t;

// Redaction result
typedef struct {
    char* redacted_text;         // Redacted/pseudonymized text
    bool was_redacted;           // Whether any redaction occurred
    char* redaction_type;        // Type of redaction applied
} redaction_result_t;

// Privacy system initialization
privacy_context_t* privacy_context_create(const privacy_config_t* config);
void privacy_context_destroy(privacy_context_t* context);
void privacy_cleanup_global_resources(void);  // Cleanup static global regex patterns

// Salt management
bool privacy_load_salt_from_env(privacy_config_t* config);
bool privacy_load_salt_from_config(privacy_config_t* config, const char* config_path);
bool privacy_validate_salt_entropy(const char* salt, size_t length);
char* privacy_generate_salt(size_t length);

// Basic redaction functions
redaction_result_t* privacy_redact_username(privacy_context_t* context, const char* text);
redaction_result_t* privacy_redact_home_path(privacy_context_t* context, const char* path);
redaction_result_t* privacy_redact_hostname(privacy_context_t* context, const char* text);
redaction_result_t* privacy_redact_file_path(privacy_context_t* context, const char* path);

// Evidence sanitization
redaction_result_t* privacy_sanitize_evidence(privacy_context_t* context, const char* evidence);
bool privacy_contains_secrets(const char* text);
redaction_result_t* privacy_redact_pem_headers(privacy_context_t* context, const char* text);
redaction_result_t* privacy_redact_private_keys(privacy_context_t* context, const char* text);

// Consistent hashing with salt
char* privacy_hash_with_salt(privacy_context_t* context, const char* input);
char* privacy_pseudonymize_path(privacy_context_t* context, const char* path);
char* privacy_pseudonymize_hostname(privacy_context_t* context, const char* hostname);

// Referential integrity validation
bool privacy_validate_referential_integrity(privacy_context_t* context, 
                                           const char** inputs, 
                                           const char** outputs, 
                                           size_t count);

// Utility functions
void redaction_result_destroy(redaction_result_t* result);
bool is_username_in_path(const char* path);
bool is_home_directory_path(const char* path);
bool contains_hostname(const char* text);
char* extract_username_from_path(const char* path);
char* extract_hostname_from_text(const char* text);

// CLI argument parsing
privacy_config_t* privacy_parse_config_from_args(int argc, char** argv);
void privacy_print_help(void);

// Default configuration
privacy_config_t privacy_get_default_config(void);

// Minimum entropy requirements
#define PRIVACY_MIN_SALT_ENTROPY_BITS 128
#define PRIVACY_MIN_SALT_LENGTH_BYTES 16

// Common redaction patterns
#define PRIVACY_USERNAME_PLACEHOLDER "<user>"
#define PRIVACY_HOME_PATH_PLACEHOLDER "<home>"
#define PRIVACY_HOSTNAME_PLACEHOLDER "<host>"
#define PRIVACY_PATH_HASH_PREFIX "<path-hash-"
#define PRIVACY_HOST_HASH_PREFIX "<host-hash-"

#ifdef __cplusplus
}
#endif

#endif // PRIVACY_H
