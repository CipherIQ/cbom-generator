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
#include "privacy.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#ifndef __EMSCRIPTEN__
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#endif
#include <regex.h>
#include <errno.h>

// Compiled regex patterns for efficiency
static regex_t username_regex;
static regex_t home_path_regex;
static regex_t hostname_regex;
static regex_t pem_header_regex;
static regex_t private_key_regex;
static bool regex_compiled = false;

// Compile regex patterns once
static bool compile_regex_patterns(void) {
    if (regex_compiled) return true;
    
    // Username pattern: /home/username or /Users/username
    if (regcomp(&username_regex, "/home/([^/]+)|/Users/([^/]+)", REG_EXTENDED) != 0) {
        return false;
    }
    
    // Home directory pattern
    if (regcomp(&home_path_regex, "^(/home/[^/]+|/Users/[^/]+|~)", REG_EXTENDED) != 0) {
        regfree(&username_regex);
        return false;
    }
    
    // Hostname pattern (basic)
    if (regcomp(&hostname_regex, "@([a-zA-Z0-9.-]+)", REG_EXTENDED) != 0) {
        regfree(&username_regex);
        regfree(&home_path_regex);
        return false;
    }
    
    // PEM header pattern
    if (regcomp(&pem_header_regex, "-----BEGIN [A-Z ]+-----", REG_EXTENDED) != 0) {
        regfree(&username_regex);
        regfree(&home_path_regex);
        regfree(&hostname_regex);
        return false;
    }
    
    // Private key pattern
    if (regcomp(&private_key_regex, "-----BEGIN [A-Z ]*PRIVATE KEY", REG_EXTENDED) != 0) {
        regfree(&username_regex);
        regfree(&home_path_regex);
        regfree(&hostname_regex);
        regfree(&pem_header_regex);
        return false;
    }
    
    regex_compiled = true;
    return true;
}

// Cleanup regex patterns
static void cleanup_regex_patterns(void) {
    if (regex_compiled) {
        regfree(&username_regex);
        regfree(&home_path_regex);
        regfree(&hostname_regex);
        regfree(&pem_header_regex);
        regfree(&private_key_regex);
        regex_compiled = false;
    }
}

// Public cleanup function for global resources
void privacy_cleanup_global_resources(void) {
    cleanup_regex_patterns();
}

// Get default privacy configuration
privacy_config_t privacy_get_default_config(void) {
    privacy_config_t config = {
        .no_personal_data = true,    // Privacy-by-default
        .salt = NULL,
        .salt_length = 0,
        .consent_note_path = NULL,
        .redact_usernames = true,
        .redact_home_paths = true,
        .redact_hostnames = true,
        .sanitize_evidence = true
    };
    return config;
}

// Load salt from environment variable
bool privacy_load_salt_from_env(privacy_config_t* config) {
    if (!config) return false;
    
    const char* env_salt = getenv("CBOM_SALT");
    if (!env_salt) {
        return false;
    }
    
    size_t salt_len = strlen(env_salt);
    if (!privacy_validate_salt_entropy(env_salt, salt_len)) {
        printf("ERROR: CBOM_SALT does not meet minimum entropy requirements (≥128 bits)\n");
        return false;
    }
    
    config->salt = strdup(env_salt);
    config->salt_length = salt_len;
    return true;
}

// Load salt from configuration file
bool privacy_load_salt_from_config(privacy_config_t* config, const char* config_path) {
    if (!config || !config_path) return false;
    
    FILE* file = fopen(config_path, "r");
    if (!file) return false;
    
    char line[1024];
    bool found_salt = false;
    
    while (fgets(line, sizeof(line), file)) {
        // Simple key=value parsing
        char* equals = strchr(line, '=');
        if (!equals) continue;
        
        *equals = '\0';
        char* key = line;
        char* value = equals + 1;
        
        // Trim whitespace
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;
        
        char* end = value + strlen(value) - 1;
        while (end > value && (*end == '\n' || *end == '\r' || *end == ' ')) {
            *end = '\0';
            end--;
        }
        
        if (strcmp(key, "salt") == 0) {
            if (privacy_validate_salt_entropy(value, strlen(value))) {
                config->salt = strdup(value);
                config->salt_length = strlen(value);
                found_salt = true;
            }
            break;
        }
    }
    
    fclose(file);
    return found_salt;
}

// Validate salt entropy (simplified check)
bool privacy_validate_salt_entropy(const char* salt, size_t length) {
    if (!salt || length < PRIVACY_MIN_SALT_LENGTH_BYTES) {
        return false;
    }
    
    // Simple entropy check: ensure salt has sufficient variety
    int unique_chars = 0;
    bool seen[256] = {false};
    
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)salt[i];
        if (!seen[c]) {
            seen[c] = true;
            unique_chars++;
        }
    }
    
    // Require at least 8 unique characters for minimum entropy
    return unique_chars >= 8;
}

// Generate cryptographically secure salt
char* privacy_generate_salt(size_t length) {
    if (length < PRIVACY_MIN_SALT_LENGTH_BYTES) {
        length = PRIVACY_MIN_SALT_LENGTH_BYTES;
    }
    
    unsigned char* random_bytes = secure_alloc(length);
    if (!random_bytes) return NULL;
    
    if (RAND_bytes(random_bytes, length) != 1) {
        secure_free(random_bytes, length);
        return NULL;
    }
    
    // Convert to hex string
    char* salt = secure_alloc(length * 2 + 1);
    if (!salt) {
        secure_free(random_bytes, length);
        return NULL;
    }
    
    for (size_t i = 0; i < length; i++) {
        sprintf(salt + i * 2, "%02x", random_bytes[i]);
    }
    salt[length * 2] = '\0';
    
    secure_free(random_bytes, length);
    return salt;
}

// Create privacy context
privacy_context_t* privacy_context_create(const privacy_config_t* config) {
    if (!config) return NULL;
    
    privacy_context_t* context = secure_alloc(sizeof(privacy_context_t));
    if (!context) return NULL;
    
    context->config = *config;
    context->initialized = false;
    
    // Copy salt if provided
    if (config->salt) {
        context->config.salt = strdup(config->salt);
        context->config.salt_length = config->salt_length;
    }
    
    // Copy consent note path if provided
    if (config->consent_note_path) {
        context->config.consent_note_path = strdup(config->consent_note_path);
    }
    
    // If no_personal_data is enabled but no salt provided, fail
    if (context->config.no_personal_data && !context->config.salt) {
        printf("ERROR: --no-personal-data requires salt (set CBOM_SALT environment variable)\n");
        privacy_context_destroy(context);
        return NULL;
    }
    
    // Derive HMAC key from salt
    if (context->config.salt) {
        context->hash_key_length = SHA256_DIGEST_LENGTH;
        context->hash_key = secure_alloc(context->hash_key_length);
        if (!context->hash_key) {
            privacy_context_destroy(context);
            return NULL;
        }
        
        // Use SHA-256 of salt as HMAC key
        SHA256((unsigned char*)context->config.salt, context->config.salt_length, context->hash_key);
    }
    
    // Compile regex patterns
    if (!compile_regex_patterns()) {
        printf("ERROR: Failed to compile regex patterns for privacy redaction\n");
        privacy_context_destroy(context);
        return NULL;
    }
    
    context->initialized = true;
    return context;
}

// Destroy privacy context
void privacy_context_destroy(privacy_context_t* context) {
    if (!context) return;

    if (context->config.salt) {
        secure_free(context->config.salt, context->config.salt_length);
    }

    if (context->config.consent_note_path) {
        free(context->config.consent_note_path);
    }

    if (context->hash_key) {
        secure_free(context->hash_key, context->hash_key_length);
    }

    secure_free(context, sizeof(privacy_context_t));
    // Note: Do not cleanup regex patterns here - they are static globals
    // that should persist for the lifetime of the program
}

// Create redaction result
static redaction_result_t* create_redaction_result(const char* text, bool redacted, const char* type) {
    redaction_result_t* result = secure_alloc(sizeof(redaction_result_t));
    if (!result) return NULL;
    
    result->redacted_text = text ? strdup(text) : NULL;
    result->was_redacted = redacted;
    result->redaction_type = type ? strdup(type) : NULL;
    
    return result;
}

// Destroy redaction result
void redaction_result_destroy(redaction_result_t* result) {
    if (!result) return;
    
    if (result->redacted_text) {
        free(result->redacted_text);
    }
    
    if (result->redaction_type) {
        free(result->redaction_type);
    }
    
    secure_free(result, sizeof(redaction_result_t));
}

// Hash with salt using HMAC-SHA256
char* privacy_hash_with_salt(privacy_context_t* context, const char* input) {
    if (!context || !context->initialized || !input || !context->hash_key) {
        return NULL;
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len;
    
    if (!HMAC(EVP_sha256(), context->hash_key, context->hash_key_length,
              (unsigned char*)input, strlen(input), hash, &hash_len)) {
        return NULL;
    }
    
    // Convert to hex string (first 8 bytes for readability)
    char* hex_hash = secure_alloc(17); // 8 bytes * 2 + null terminator
    if (!hex_hash) return NULL;
    
    for (int i = 0; i < 8; i++) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    hex_hash[16] = '\0';
    
    return hex_hash;
}

// Check if path contains username
bool is_username_in_path(const char* path) {
    if (!path || !regex_compiled) return false;
    return regexec(&username_regex, path, 0, NULL, 0) == 0;
}

// Check if path is home directory
bool is_home_directory_path(const char* path) {
    if (!path || !regex_compiled) return false;
    return regexec(&home_path_regex, path, 0, NULL, 0) == 0;
}

// Check if text contains hostname
bool contains_hostname(const char* text) {
    if (!text || !regex_compiled) return false;
    return regexec(&hostname_regex, text, 0, NULL, 0) == 0;
}

// Extract username from path
char* extract_username_from_path(const char* path) {
    if (!path || !regex_compiled) return NULL;
    
    regmatch_t matches[3];
    if (regexec(&username_regex, path, 3, matches, 0) != 0) {
        return NULL;
    }
    
    // Check which group matched
    int group = (matches[1].rm_so != -1) ? 1 : 2;
    if (matches[group].rm_so == -1) return NULL;
    
    size_t len = matches[group].rm_eo - matches[group].rm_so;
    char* username = secure_alloc(len + 1);
    if (!username) return NULL;
    
    strncpy(username, path + matches[group].rm_so, len);
    username[len] = '\0';
    
    return username;
}

// Redact username from text
redaction_result_t* privacy_redact_username(privacy_context_t* context, const char* text) {
    if (!context || !text || !context->config.redact_usernames) {
        return create_redaction_result(text, false, NULL);
    }
    
    if (!is_username_in_path(text)) {
        return create_redaction_result(text, false, NULL);
    }
    
    char* username = extract_username_from_path(text);
    if (!username) {
        return create_redaction_result(text, false, NULL);
    }
    
    // Replace username with placeholder or hash
    char* redacted = strdup(text);
    if (!redacted) {
        secure_free(username, strlen(username));
        return create_redaction_result(text, false, NULL);
    }
    
    char* pos = strstr(redacted, username);
    if (pos) {
        if (context->config.no_personal_data && context->hash_key) {
            // Use consistent hash
            char* hash = privacy_hash_with_salt(context, username);
            if (hash) {
                char replacement[64];
                snprintf(replacement, sizeof(replacement), "<user-%s>", hash);
                
                // Simple replacement (would need more sophisticated logic for multiple occurrences)
                size_t old_len = strlen(username);
                size_t new_len = strlen(replacement);
                
                if (new_len <= old_len) {
                    strcpy(pos, replacement);
                    // Shift remaining text
                    memmove(pos + new_len, pos + old_len, strlen(pos + old_len) + 1);
                }
                
                secure_free(hash, strlen(hash));
            }
        } else {
            // Use simple placeholder
            strcpy(pos, PRIVACY_USERNAME_PLACEHOLDER);
            memmove(pos + strlen(PRIVACY_USERNAME_PLACEHOLDER), pos + strlen(username),
                   strlen(pos + strlen(username)) + 1);
        }
    }
    
    secure_free(username, strlen(username));
    
    redaction_result_t* result = create_redaction_result(redacted, true, "username");
    free(redacted);
    return result;
}

// Redact home path
redaction_result_t* privacy_redact_home_path(privacy_context_t* context, const char* path) {
    if (!context || !path || !context->config.redact_home_paths) {
        return create_redaction_result(path, false, NULL);
    }
    
    if (!is_home_directory_path(path)) {
        return create_redaction_result(path, false, NULL);
    }
    
    // Simple home path redaction
    char* redacted = strdup(path);
    if (!redacted) {
        return create_redaction_result(path, false, NULL);
    }
    
    if (strncmp(path, "/home/", 6) == 0) {
        char* slash = strchr(path + 6, '/');
        if (slash) {
            size_t prefix_len = slash - path;
            if (context->config.no_personal_data && context->hash_key) {
                char* home_part = strndup(path, prefix_len);
                char* hash = privacy_hash_with_salt(context, home_part);
                if (hash) {
                    snprintf(redacted, strlen(path) + 32, "<home-%s>%s", hash, slash);
                    secure_free(hash, strlen(hash));
                }
                free(home_part);
            } else {
                snprintf(redacted, strlen(path) + 16, "%s%s", PRIVACY_HOME_PATH_PLACEHOLDER, slash);
            }
        }
    }
    
    redaction_result_t* result = create_redaction_result(redacted, true, "home_path");
    free(redacted);
    return result;
}

// Check if text contains secrets
bool privacy_contains_secrets(const char* text) {
    if (!text || !regex_compiled) return false;
    
    // Check for PEM headers or private key patterns
    return (regexec(&pem_header_regex, text, 0, NULL, 0) == 0) ||
           (regexec(&private_key_regex, text, 0, NULL, 0) == 0);
}

// Redact PEM headers
redaction_result_t* privacy_redact_pem_headers(privacy_context_t* context, const char* text) {
    if (!context || !text) {
        return create_redaction_result(text, false, NULL);
    }
    
    if (!privacy_contains_secrets(text)) {
        return create_redaction_result(text, false, NULL);
    }
    
    // Simple redaction: replace entire content with placeholder
    char* redacted = strdup("[REDACTED: PEM content]");
    return create_redaction_result(redacted, true, "pem_content");
}

// Extract hostname from text
char* extract_hostname_from_text(const char* text) {
    if (!text || !regex_compiled) return NULL;

    regmatch_t matches[2];
    if (regexec(&hostname_regex, text, 2, matches, 0) != 0) {
        return NULL;
    }

    // Extract hostname from group 1
    if (matches[1].rm_so == -1) return NULL;

    size_t len = matches[1].rm_eo - matches[1].rm_so;
    char* hostname = secure_alloc(len + 1);
    if (!hostname) return NULL;

    strncpy(hostname, text + matches[1].rm_so, len);
    hostname[len] = '\0';

    return hostname;
}

// Redact hostname from text
redaction_result_t* privacy_redact_hostname(privacy_context_t* context, const char* text) {
    if (!context || !text || !context->config.redact_hostnames) {
        return create_redaction_result(text, false, NULL);
    }

    if (!contains_hostname(text)) {
        return create_redaction_result(text, false, NULL);
    }

    char* hostname = extract_hostname_from_text(text);
    if (!hostname) {
        return create_redaction_result(text, false, NULL);
    }

    // Replace hostname with placeholder or hash
    char* redacted = strdup(text);
    if (!redacted) {
        secure_free(hostname, strlen(hostname));
        return create_redaction_result(text, false, NULL);
    }

    // Find @hostname pattern in text
    char hostname_pattern[512];
    snprintf(hostname_pattern, sizeof(hostname_pattern), "@%s", hostname);

    char* pos = strstr(redacted, hostname_pattern);
    if (pos) {
        if (context->config.no_personal_data && context->hash_key) {
            // Use consistent hash
            char* hash = privacy_hash_with_salt(context, hostname);
            if (hash) {
                char replacement[64];
                snprintf(replacement, sizeof(replacement), "@<host-%s>", hash);

                size_t old_len = strlen(hostname_pattern);
                size_t new_len = strlen(replacement);

                // Allocate new string with enough space
                size_t total_len = strlen(redacted) - old_len + new_len + 1;
                char* new_redacted = malloc(total_len);
                if (new_redacted) {
                    size_t prefix_len = pos - redacted;
                    strncpy(new_redacted, redacted, prefix_len);
                    strcpy(new_redacted + prefix_len, replacement);
                    strcpy(new_redacted + prefix_len + new_len, pos + old_len);

                    free(redacted);
                    redacted = new_redacted;
                }

                secure_free(hash, strlen(hash));
            }
        } else {
            // Use simple placeholder
            char replacement[32];
            snprintf(replacement, sizeof(replacement), "@%s", PRIVACY_HOSTNAME_PLACEHOLDER);

            size_t old_len = strlen(hostname_pattern);
            size_t new_len = strlen(replacement);

            if (new_len <= old_len) {
                strcpy(pos, replacement);
                memmove(pos + new_len, pos + old_len, strlen(pos + old_len) + 1);
            }
        }
    }

    secure_free(hostname, strlen(hostname));

    redaction_result_t* result = create_redaction_result(redacted, true, "hostname");
    free(redacted);
    return result;
}

// Pseudonymize hostname with consistent hash
char* privacy_pseudonymize_hostname(privacy_context_t* context, const char* hostname) {
    if (!context || !hostname || !context->hash_key) {
        return hostname ? strdup(hostname) : NULL;
    }

    char* hash = privacy_hash_with_salt(context, hostname);
    if (!hash) {
        return strdup(hostname);
    }

    char* pseudonym = malloc(64);
    if (!pseudonym) {
        secure_free(hash, strlen(hash));
        return strdup(hostname);
    }

    snprintf(pseudonym, 64, "host-%s", hash);
    secure_free(hash, strlen(hash));

    return pseudonym;
}

// Pseudonymize file path with consistent hash
char* privacy_pseudonymize_path(privacy_context_t* context, const char* path) {
    if (!context || !path || !context->hash_key) {
        return path ? strdup(path) : NULL;
    }

    char* hash = privacy_hash_with_salt(context, path);
    if (!hash) {
        return strdup(path);
    }

    char* pseudonym = malloc(64);
    if (!pseudonym) {
        secure_free(hash, strlen(hash));
        return strdup(path);
    }

    snprintf(pseudonym, 64, "%s%s>", PRIVACY_PATH_HASH_PREFIX, hash);
    secure_free(hash, strlen(hash));

    return pseudonym;
}

// Redact file path (comprehensive redaction)
redaction_result_t* privacy_redact_file_path(privacy_context_t* context, const char* path) {
    if (!context || !path) {
        return create_redaction_result(path, false, NULL);
    }

    // First apply home path redaction
    redaction_result_t* home_result = privacy_redact_home_path(context, path);
    if (!home_result) {
        return create_redaction_result(path, false, NULL);
    }

    // Then apply username redaction
    redaction_result_t* username_result = privacy_redact_username(context, home_result->redacted_text);

    bool was_redacted = home_result->was_redacted || (username_result && username_result->was_redacted);

    redaction_result_t* final_result = create_redaction_result(
        username_result ? username_result->redacted_text : home_result->redacted_text,
        was_redacted,
        was_redacted ? "file_path" : NULL
    );

    redaction_result_destroy(home_result);
    if (username_result) {
        redaction_result_destroy(username_result);
    }

    return final_result;
}

// Redact private keys from text
redaction_result_t* privacy_redact_private_keys(privacy_context_t* context, const char* text) {
    if (!context || !text) {
        return create_redaction_result(text, false, NULL);
    }

    if (!regex_compiled) {
        return create_redaction_result(text, false, NULL);
    }

    // Check if text contains private key pattern
    if (regexec(&private_key_regex, text, 0, NULL, 0) != 0) {
        return create_redaction_result(text, false, NULL);
    }

    // Replace entire content with placeholder
    char* redacted = strdup("[REDACTED: Private key material]");
    return create_redaction_result(redacted, true, "private_key");
}

// Sanitize evidence
redaction_result_t* privacy_sanitize_evidence(privacy_context_t* context, const char* evidence) {
    if (!context || !evidence || !context->config.sanitize_evidence) {
        return create_redaction_result(evidence, false, NULL);
    }

    // Check if evidence contains secrets
    if (privacy_contains_secrets(evidence)) {
        return privacy_redact_pem_headers(context, evidence);
    }

    // Apply other redactions
    redaction_result_t* username_result = privacy_redact_username(context, evidence);
    if (!username_result) {
        return create_redaction_result(evidence, false, NULL);
    }

    redaction_result_t* path_result = privacy_redact_home_path(context, username_result->redacted_text);
    redaction_result_destroy(username_result);

    if (!path_result) {
        return create_redaction_result(evidence, false, NULL);
    }

    // Apply hostname redaction
    redaction_result_t* hostname_result = privacy_redact_hostname(context, path_result->redacted_text);
    redaction_result_destroy(path_result);

    return hostname_result;
}

// Validate referential integrity
bool privacy_validate_referential_integrity(privacy_context_t* context,
                                           const char** inputs,
                                           const char** outputs,
                                           size_t count) {
    if (!context || !inputs || !outputs) return false;
    
    // Simple check: ensure same inputs produce same outputs
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (strcmp(inputs[i], inputs[j]) == 0) {
                if (strcmp(outputs[i], outputs[j]) != 0) {
                    return false; // Same input should produce same output
                }
            }
        }
    }
    
    return true;
}

// Parse privacy configuration from command line arguments
privacy_config_t* privacy_parse_config_from_args(int argc, char** argv) {
    privacy_config_t* config = secure_alloc(sizeof(privacy_config_t));
    if (!config) return NULL;
    
    *config = privacy_get_default_config();
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-personal-data") == 0) {
            config->no_personal_data = true;
        } else if (strcmp(argv[i], "--allow-personal-data") == 0) {
            config->no_personal_data = false;
        } else if (strcmp(argv[i], "--consent-note-path") == 0 && i + 1 < argc) {
            config->consent_note_path = strdup(argv[i + 1]);
            i++;
        }
    }
    
    // Try to load salt from environment
    if (config->no_personal_data) {
        if (!privacy_load_salt_from_env(config)) {
            printf("WARNING: --no-personal-data enabled but no CBOM_SALT environment variable found\n");
        }
    }
    
    return config;
}

// Print privacy help
void privacy_print_help(void) {
    printf("Privacy Options:\n");
    printf("  --no-personal-data      Enable privacy-by-default mode (default: on)\n");
    printf("  --allow-personal-data   Disable privacy-by-default mode\n");
    printf("  --consent-note-path PATH Path to legal compliance consent note\n");
    printf("\n");
    printf("Environment Variables:\n");
    printf("  CBOM_SALT              Salt for consistent hashing (required for --no-personal-data)\n");
    printf("                         Must be at least 16 bytes with sufficient entropy\n");
    printf("\n");
}
