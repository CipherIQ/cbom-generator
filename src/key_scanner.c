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

#include "key_scanner.h"
#include "error_handling.h"
#include "secure_memory.h"
#include "asset_store.h"
#include "cbom_types.h"
#include "key_manager.h"
#include "plugin_manager.h"
#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#ifndef __EMSCRIPTEN__
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#endif
#include <json-c/json.h>

#ifndef __EMSCRIPTEN__

// Thread-local error storage
static __thread char last_error[256] = {0};

// Password callback that returns provided password or empty (prevents stdin prompts)
static int password_callback(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag;
    if (userdata && size > 0) {
        const char *password = (const char *)userdata;
        int len = (int)strlen(password);
        if (len > size - 1) len = size - 1;
        memcpy(buf, password, len);
        buf[len] = '\0';
        return len;
    }
    return 0;  // Return 0 = no password, prevents stdin prompt
}

// Forward declarations for internal functions
static bool key_process_single_key(key_scanner_context_t* context, EVP_PKEY* pkey,
                                   const char* file_path, key_format_t format,
                                   bool is_encrypted);
static int key_load_and_process_pem_file(key_scanner_context_t* context, const char* file_path);
static int key_load_and_process_der_file(key_scanner_context_t* context, const char* file_path);
static int key_load_and_process_openssh_file(key_scanner_context_t* context, const char* file_path);

// Set error message
static void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(last_error, sizeof(last_error), format, args);
    va_end(args);
}

// Clear error message
void key_scanner_clear_error(void) {
    last_error[0] = '\0';
}

// Get last error message
const char* key_scanner_get_last_error(void) {
    return last_error[0] ? last_error : NULL;
}

// Convert failure reason to string
const char* key_failure_reason_to_string(key_failure_reason_t reason) {
    switch (reason) {
        case KEY_FAIL_INVALID_PEM_BLOCK: return "INVALID_PEM_BLOCK";
        case KEY_FAIL_DER_TRUNCATED: return "DER_TRUNCATED";
        case KEY_FAIL_DER_OVERLONG: return "DER_OVERLONG";
        case KEY_FAIL_ENCRYPTED_NO_PASSWORD: return "ENCRYPTED_NO_PASSWORD";
        case KEY_FAIL_WRONG_PASSWORD: return "WRONG_PASSWORD";
        case KEY_FAIL_UNSUPPORTED_ENCRYPTION: return "UNSUPPORTED_ENCRYPTION";
        case KEY_FAIL_UNSUPPORTED_KEY_TYPE: return "UNSUPPORTED_KEY_TYPE";
        case KEY_FAIL_TOO_LARGE: return "TOO_LARGE";
        case KEY_FAIL_TIMEOUT: return "TIMEOUT";
        case KEY_FAIL_SANITY_LIMIT_HIT: return "SANITY_LIMIT_HIT";
        case KEY_FAIL_MEMORY_ERROR: return "MEMORY_ERROR";
        case KEY_FAIL_IO_ERROR: return "IO_ERROR";
        case KEY_FAIL_UNKNOWN: return "UNKNOWN";
        default: return "INVALID_REASON";
    }
}

// Record failure reason
void key_scanner_record_failure(key_scanner_context_t* context, key_failure_reason_t reason) {
    if (!context || reason < 0 || reason >= KEY_FAIL_REASON_COUNT) {
        return;
    }

    pthread_mutex_lock(&context->mutex);
    context->stats.keys_failed_total++;
    context->stats.keys_failed_by_reason[reason]++;
    pthread_mutex_unlock(&context->mutex);
}

// Create default configuration
key_scanner_config_t key_scanner_create_default_config(void) {
    key_scanner_config_t config = {0};
    config.scan_paths = NULL;
    config.scan_path_count = 0;
    config.recursive_scan = true;
    config.max_file_size = 1024 * 1024; // 1 MB max
    config.timeout_seconds = 5;
    config.passwords = NULL;
    config.password_count = 0;
    config.skip_encrypted = false;  // v1.5: Detect encrypted keys (metadata only, never expose key material)
    config.detect_weak_keys = true;
    config.extract_public_from_private = true;
    config.link_to_certificates = true;
    config.hash_file_paths = false;
    config.redact_key_material = true; // ALWAYS redact by default
    return config;
}

// Destroy configuration
void key_scanner_config_destroy(key_scanner_config_t* config) {
    if (!config) return;

    if (config->scan_paths) {
        for (size_t i = 0; i < config->scan_path_count; i++) {
            free(config->scan_paths[i]);
        }
        free(config->scan_paths);
    }

    if (config->passwords) {
        for (size_t i = 0; i < config->password_count; i++) {
            if (config->passwords[i]) {
                size_t len = strlen(config->passwords[i]);
                secure_zero(config->passwords[i], len);
                secure_free(config->passwords[i], len);
            }
        }
        free(config->passwords);
    }

    memset(config, 0, sizeof(key_scanner_config_t));
}

// Create key scanner context
key_scanner_context_t* key_scanner_create(const key_scanner_config_t* config,
                                         struct asset_store* store) {
    if (!config || !store) {
        set_error("Invalid parameters: config or store is NULL");
        return NULL;
    }

    key_scanner_context_t* context = secure_alloc(sizeof(key_scanner_context_t));
    if (!context) {
        set_error("Failed to allocate key scanner context");
        return NULL;
    }

    // Copy configuration
    context->config = *config;
    context->asset_store = store;
    context->scan_context = NULL; // Will be set during scan

    // Initialize statistics
    memset(&context->stats, 0, sizeof(key_scanner_stats_t));

    // Initialize mutex
    if (pthread_mutex_init(&context->mutex, NULL) != 0) {
        set_error("Failed to initialize mutex");
        secure_free(context, sizeof(key_scanner_context_t));
        return NULL;
    }

    return context;
}

// Destroy key scanner context
void key_scanner_destroy(key_scanner_context_t* context) {
    if (!context) return;

    pthread_mutex_destroy(&context->mutex);
    secure_zero(context, sizeof(key_scanner_context_t));
    secure_free(context, sizeof(key_scanner_context_t));
}

// Detect key format from file path
key_format_t key_detect_format(const char* file_path) {
    if (!file_path) return KEY_FORMAT_UNKNOWN;

    FILE* fp = fopen(file_path, "rb");
    if (!fp) return KEY_FORMAT_UNKNOWN;

    unsigned char buffer[256];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);

    if (bytes_read == 0) return KEY_FORMAT_UNKNOWN;

    return key_detect_format_from_content(buffer, bytes_read);
}

// Detect key format from content
key_format_t key_detect_format_from_content(const unsigned char* data, size_t len) {
    if (!data || len < 10) return KEY_FORMAT_UNKNOWN;

    // Create a null-terminated copy for string operations (strstr requires null terminator)
    // Limit to first 512 bytes for PEM header detection
    size_t check_len = (len > 512) ? 512 : len;
    char* safe_buffer = secure_alloc(check_len + 1);
    if (!safe_buffer) return KEY_FORMAT_UNKNOWN;

    memcpy(safe_buffer, data, check_len);
    safe_buffer[check_len] = '\0';

    // Check for PEM format (BEGIN ... PRIVATE KEY/PUBLIC KEY)
    bool is_pem = false;
    if (strstr(safe_buffer, "-----BEGIN") != NULL) {
        if (strstr(safe_buffer, "PRIVATE KEY") != NULL ||
            strstr(safe_buffer, "PUBLIC KEY") != NULL ||
            strstr(safe_buffer, "RSA PRIVATE KEY") != NULL ||
            strstr(safe_buffer, "EC PRIVATE KEY") != NULL) {
            is_pem = true;
        }
    }

    secure_free(safe_buffer, check_len + 1);

    if (is_pem) {
        return KEY_FORMAT_PEM;
    }

    // Check for OpenSSH format
    if (len > 7 && (memcmp(data, "ssh-rsa", 7) == 0 ||
                    memcmp(data, "ssh-dss", 7) == 0 ||
                    memcmp(data, "ecdsa-", 6) == 0 ||
                    memcmp(data, "ssh-ed25519", 11) == 0)) {
        return KEY_FORMAT_OPENSSH;
    }

    // Check for DER format (ASN.1 SEQUENCE tag)
    if (data[0] == 0x30) {
        return KEY_FORMAT_DER;
    }

    return KEY_FORMAT_UNKNOWN;
}

// Check if key is encrypted
bool key_is_encrypted(const char* file_path) {
    if (!file_path) return false;

    FILE* fp = fopen(file_path, "r");
    if (!fp) return false;

    char buffer[512];
    bool is_encrypted = false;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "ENCRYPTED") != NULL ||
            strstr(buffer, "Proc-Type: 4,ENCRYPTED") != NULL) {
            is_encrypted = true;
            break;
        }
    }

    fclose(fp);
    return is_encrypted;
}

// Detect key type from PEM header line (without loading the key)
static key_type_t key_detect_type_from_pem_header(const char* file_path) {
    if (!file_path) return KEY_TYPE_UNKNOWN;

    FILE* fp = fopen(file_path, "r");
    if (!fp) return KEY_TYPE_UNKNOWN;

    char line[256];
    key_type_t type = KEY_TYPE_UNKNOWN;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "-----BEGIN RSA PRIVATE KEY-----")) {
            type = KEY_TYPE_RSA;
            break;
        }
        if (strstr(line, "-----BEGIN EC PRIVATE KEY-----")) {
            type = KEY_TYPE_ECDSA;
            break;
        }
        if (strstr(line, "-----BEGIN DSA PRIVATE KEY-----")) {
            type = KEY_TYPE_DSA;
            break;
        }
        if (strstr(line, "-----BEGIN DH PRIVATE KEY-----") ||
            strstr(line, "-----BEGIN DH PARAMETERS-----")) {
            type = KEY_TYPE_DH;
            break;
        }
        if (strstr(line, "-----BEGIN PRIVATE KEY-----") ||
            strstr(line, "-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
            // PKCS#8 format - could be any type, default to RSA (most common)
            type = KEY_TYPE_RSA;
            break;
        }
        if (strstr(line, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
            // OpenSSH format - could be any type, check further if needed
            type = KEY_TYPE_UNKNOWN;
            break;
        }
    }

    fclose(fp);
    return type;
}

// Convert key type to algorithm name string
static const char* key_type_to_algorithm_string(key_type_t type) {
    switch (type) {
        case KEY_TYPE_RSA: return "RSA";
        case KEY_TYPE_ECDSA: return "ECDSA";
        case KEY_TYPE_ED25519: return "Ed25519";
        case KEY_TYPE_ED448: return "Ed448";
        case KEY_TYPE_DSA: return "DSA";
        case KEY_TYPE_DH: return "DH";
        default: return "Unknown";
    }
}

// Load PEM key from file (handles encrypted keys)
EVP_PKEY* key_load_pem(const char* file_path, const char* password) {
    if (!file_path) return NULL;

    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        set_error("Failed to open key file: %s", file_path);
        return NULL;
    }

    EVP_PKEY* pkey = NULL;

    // Try to read as private key first
    // Use password_callback to prevent stdin prompts for encrypted keys
    pkey = PEM_read_PrivateKey(fp, NULL, password_callback, (void*)password);

    if (!pkey) {
        // Rewind and try as public key
        rewind(fp);
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }

    fclose(fp);

    if (!pkey) {
        set_error("Failed to parse PEM key from: %s", file_path);
    }

    return pkey;
}

// Load DER key from file
EVP_PKEY* key_load_der(const char* file_path) {
    if (!file_path) return NULL;

    FILE* fp = fopen(file_path, "rb");
    if (!fp) {
        set_error("Failed to open key file: %s", file_path);
        return NULL;
    }

    EVP_PKEY* pkey = NULL;

    // Try to read as private key first
    pkey = d2i_PrivateKey_fp(fp, NULL);

    if (!pkey) {
        // Rewind and try as public key
        rewind(fp);
        pkey = d2i_PUBKEY_fp(fp, NULL);
    }

    fclose(fp);

    if (!pkey) {
        set_error("Failed to parse DER key from: %s", file_path);
    }

    return pkey;
}

// Load OpenSSH key from file (public keys only)
EVP_PKEY* key_load_openssh(const char* file_path) {
    if (!file_path) return NULL;

    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        set_error("Failed to open key file: %s", file_path);
        return NULL;
    }

    char line[4096];
    EVP_PKEY* pkey = NULL;

    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        // Parse OpenSSH public key format
        char* space = strchr(line, ' ');
        if (space) {
            // Extract base64 encoded key
            char* key_data = space + 1;
            char* end = strchr(key_data, ' ');
            if (end) *end = '\0';

            // Create BIO from base64 data
            BIO* bio = BIO_new_mem_buf(key_data, -1);
            if (bio) {
                BIO* b64 = BIO_new(BIO_f_base64());
                bio = BIO_push(b64, bio);
                BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

                // Try to read public key
                pkey = d2i_PUBKEY_bio(bio, NULL);
                BIO_free_all(bio);

                if (pkey) break;
            }
        }
    }

    fclose(fp);

    if (!pkey) {
        set_error("Failed to parse OpenSSH key from: %s", file_path);
    }

    return pkey;
}

// Load key from file (auto-detect format)
EVP_PKEY* key_load_from_file(const char* file_path, key_format_t format,
                             const char* password) {
    if (!file_path) return NULL;

    switch (format) {
        case KEY_FORMAT_PEM:
        case KEY_FORMAT_PKCS8:
        case KEY_FORMAT_PKCS1:
            return key_load_pem(file_path, password);

        case KEY_FORMAT_DER:
            return key_load_der(file_path);

        case KEY_FORMAT_OPENSSH:
            return key_load_openssh(file_path);

        default:
            set_error("Unsupported key format");
            return NULL;
    }
}

// Get key type from EVP_PKEY
key_type_t key_get_type(EVP_PKEY* pkey) {
    if (!pkey) return KEY_TYPE_UNKNOWN;

    int type = EVP_PKEY_id(pkey);

    switch (type) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA2:
            return KEY_TYPE_RSA;

        case EVP_PKEY_EC:
            return KEY_TYPE_ECDSA;

        case EVP_PKEY_ED25519:
            return KEY_TYPE_ED25519;

        case EVP_PKEY_ED448:
            return KEY_TYPE_ED448;

        case EVP_PKEY_DSA:
        case EVP_PKEY_DSA1:
        case EVP_PKEY_DSA2:
        case EVP_PKEY_DSA3:
        case EVP_PKEY_DSA4:
            return KEY_TYPE_DSA;

        case EVP_PKEY_DH:
            return KEY_TYPE_DH;

        default:
            return KEY_TYPE_UNKNOWN;
    }
}

// Get key classification (private/public/symmetric)
key_class_t key_get_classification(EVP_PKEY* pkey) {
    if (!pkey) return KEY_CLASS_UNKNOWN;

    // Suppress OpenSSL 3.0 deprecation warnings for this function
    // These APIs still work and are the most reliable way to check key type
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // For Ed25519/Ed448, use raw private key check
    int type = EVP_PKEY_id(pkey);
    if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) {
        size_t priv_len = 0;
        if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) == 1 && priv_len > 0) {
            return KEY_CLASS_PRIVATE;
        }
        return KEY_CLASS_PUBLIC;
    }

    // For RSA keys, check for private exponent
    if (type == EVP_PKEY_RSA) {
        const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
        if (rsa) {
            const BIGNUM *d = NULL;
            RSA_get0_key(rsa, NULL, NULL, &d);
            if (d != NULL) {
                return KEY_CLASS_PRIVATE;  // Has private exponent
            }
        }
        return KEY_CLASS_PUBLIC;
    }

    // For EC keys, check for private scalar
    if (type == EVP_PKEY_EC) {
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (ec) {
            const BIGNUM *priv_key = EC_KEY_get0_private_key(ec);
            if (priv_key != NULL) {
                return KEY_CLASS_PRIVATE;  // Has private scalar
            }
        }
        return KEY_CLASS_PUBLIC;
    }

    // For other key types (DSA/DH), assume private if loaded from file
    // (public keys are typically extracted from certificates, not standalone files)
    if (type == EVP_PKEY_DSA || type == EVP_PKEY_DH) {
        return KEY_CLASS_PRIVATE;  // Standalone DSA/DH keys are typically private
    }

#pragma GCC diagnostic pop

    return KEY_CLASS_UNKNOWN;
}

// Get key size in bits
int key_get_size(EVP_PKEY* pkey) {
    if (!pkey) return 0;

    return EVP_PKEY_bits(pkey);
}

// Get algorithm name
char* key_get_algorithm_name(EVP_PKEY* pkey) {
    if (!pkey) return NULL;

    key_type_t type = key_get_type(pkey);
    int size = key_get_size(pkey);

    char* algorithm = malloc(64);
    if (!algorithm) return NULL;

    switch (type) {
        case KEY_TYPE_RSA:
            snprintf(algorithm, 64, "RSA-%d", size);
            break;
        case KEY_TYPE_ECDSA:
            snprintf(algorithm, 64, "ECDSA-%d", size);
            break;
        case KEY_TYPE_ED25519:
            snprintf(algorithm, 64, "Ed25519");
            break;
        case KEY_TYPE_ED448:
            snprintf(algorithm, 64, "Ed448");
            break;
        case KEY_TYPE_DSA:
            snprintf(algorithm, 64, "DSA-%d", size);
            break;
        case KEY_TYPE_DH:
            snprintf(algorithm, 64, "DH-%d", size);
            break;
        default:
            snprintf(algorithm, 64, "Unknown");
            break;
    }

    return algorithm;
}

// Get EC curve name (OpenSSL 3.0+ compatible)
char* key_get_curve_name(EVP_PKEY* pkey) {
    if (!pkey || key_get_type(pkey) != KEY_TYPE_ECDSA) {
        return NULL;
    }

    // For OpenSSL 3.0+, use EVP_PKEY_get_utf8_string_param
    char curve_name[256] = {0};
    size_t len = 0;

    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                       curve_name, sizeof(curve_name), &len) == 1) {
        char* result = malloc(strlen(curve_name) + 1);
        if (result) {
            strcpy(result, curve_name);
        }
        return result;
    }

    return NULL;
}

// Generate key ID (SHA-256 hash of public key)
char* key_generate_id(EVP_PKEY* pkey) {
    if (!pkey) return NULL;

    // Extract public key in DER format
    unsigned char* der = NULL;
    int der_len = i2d_PUBKEY(pkey, &der);

    if (der_len <= 0 || !der) {
        return NULL;
    }

    // Compute SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der, der_len, hash);

    // Free DER data immediately (don't keep key material in memory)
    OPENSSL_free(der);

    // Convert to hex string
    char* hex = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!hex) return NULL;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }

    return hex;
}

// Get public key hash
char* key_get_public_key_hash(EVP_PKEY* pkey) {
    // Same as key_generate_id for public keys
    return key_generate_id(pkey);
}

// Get key fingerprint (format-specific)
char* key_get_fingerprint(EVP_PKEY* pkey, key_format_t format) {
    if (!pkey) return NULL;

    // For now, use SHA-256 hash as fingerprint for all formats
    // format parameter reserved for future format-specific fingerprinting
    (void)format; // Suppress unused parameter warning
    return key_generate_id(pkey);
}

// Detect storage security level
storage_security_t key_detect_storage_security(const char* file_path, bool is_encrypted) {
    if (!file_path) return STORAGE_UNKNOWN;

    // Check for HSM paths
    if (strstr(file_path, "/dev/crypto") ||
        strstr(file_path, "pkcs11") ||
        strstr(file_path, "hsm")) {
        return STORAGE_HSM;
    }

    // Check for TPM paths
    if (strstr(file_path, "/dev/tpm") ||
        strstr(file_path, "tpm2")) {
        return STORAGE_TPM;
    }

    // Check for keyring paths
    if (strstr(file_path, "keyring") ||
        strstr(file_path, "keychain")) {
        return STORAGE_KEYRING;
    }

    // Otherwise, encrypted or plaintext
    return is_encrypted ? STORAGE_ENCRYPTED : STORAGE_PLAINTEXT;
}

// Check if key is in HSM
bool key_is_in_hsm(const char* file_path) {
    return key_detect_storage_security(file_path, false) == STORAGE_HSM;
}

// Check if key is in TPM
bool key_is_in_tpm(const char* file_path) {
    return key_detect_storage_security(file_path, false) == STORAGE_TPM;
}

// Check if key is in keyring
bool key_is_in_keyring(const char* file_path) {
    return key_detect_storage_security(file_path, false) == STORAGE_KEYRING;
}

// Extract lifecycle metadata
key_lifecycle_t key_extract_lifecycle(const char* file_path) {
    key_lifecycle_t lifecycle = {0};

    if (!file_path) return lifecycle;

    struct stat st;
    if (stat(file_path, &st) == 0) {
        lifecycle.creation_date = st.st_ctime;
        // Other lifecycle metadata would require parsing certificate associations
        // or key metadata files (not available in basic key files)
    }

    return lifecycle;
}

// Check if key is expired
bool key_is_expired(const key_lifecycle_t* lifecycle) {
    if (!lifecycle || !lifecycle->has_expiration) return false;

    time_t now = time(NULL);
    return lifecycle->expiration_date > 0 && now > lifecycle->expiration_date;
}

// Get days until expiration
int key_days_until_expiration(const key_lifecycle_t* lifecycle) {
    if (!lifecycle || !lifecycle->has_expiration) return -1;

    time_t now = time(NULL);
    if (lifecycle->expiration_date <= now) return 0;

    return (lifecycle->expiration_date - now) / (24 * 60 * 60);
}

// Detect key usages
key_usage_t* key_detect_usages(const char* file_path, EVP_PKEY* pkey, size_t* count) {
    if (!file_path || !pkey || !count) return NULL;

    // Allocate array for possible usages
    key_usage_t* usages = malloc(sizeof(key_usage_t) * 8);
    if (!usages) return NULL;

    *count = 0;

    // Detect usage based on file path
    if (strstr(file_path, "ssh")) {
        usages[(*count)++] = KEY_USAGE_SSH;
    }
    if (strstr(file_path, "ssl") || strstr(file_path, "tls")) {
        usages[(*count)++] = KEY_USAGE_TLS;
    }
    if (strstr(file_path, "code-sign") || strstr(file_path, "codesign")) {
        usages[(*count)++] = KEY_USAGE_CODE_SIGNING;
    }

    // Default usage based on key type
    if (*count == 0) {
        key_class_t classification = key_get_classification(pkey);
        if (classification == KEY_CLASS_PRIVATE) {
            usages[(*count)++] = KEY_USAGE_SIGNING;
        } else if (classification == KEY_CLASS_PUBLIC) {
            usages[(*count)++] = KEY_USAGE_ENCRYPTION;
        }
    }

    return usages;
}

// Detect primary usage
key_usage_t key_detect_primary_usage(const char* file_path) {
    if (!file_path) return KEY_USAGE_UNKNOWN;

    if (strstr(file_path, "ssh")) return KEY_USAGE_SSH;
    if (strstr(file_path, "ssl") || strstr(file_path, "tls")) return KEY_USAGE_TLS;
    if (strstr(file_path, "code-sign")) return KEY_USAGE_CODE_SIGNING;

    return KEY_USAGE_UNKNOWN;
}

// Check if key is weak
bool key_is_weak(EVP_PKEY* pkey, key_type_t type) {
    if (!pkey) return false;

    int size = key_get_size(pkey);

    switch (type) {
        case KEY_TYPE_RSA:
            return size < 2048; // RSA keys < 2048 bits are weak

        case KEY_TYPE_ECDSA:
            return size < 224; // ECDSA keys < 224 bits are weak

        case KEY_TYPE_DSA:
            return size < 2048; // DSA keys < 2048 bits are weak

        case KEY_TYPE_DH:
            return size < 2048; // DH keys < 2048 bits are weak

        default:
            return false;
    }
}

// Check if key has weak size
bool key_has_weak_size(EVP_PKEY* pkey, key_type_t type) {
    return key_is_weak(pkey, type);
}

// Get weak reasons
char** key_get_weak_reasons(EVP_PKEY* pkey, key_type_t type, size_t* count) {
    if (!pkey || !count) return NULL;

    *count = 0;
    char** reasons = malloc(sizeof(char*) * 10);
    if (!reasons) return NULL;

    int size = key_get_size(pkey);

    switch (type) {
        case KEY_TYPE_RSA:
            if (size < 2048) {
                reasons[*count] = malloc(128);
                snprintf(reasons[*count], 128, "RSA key size %d bits is below recommended 2048 bits", size);
                (*count)++;
            }
            break;

        case KEY_TYPE_ECDSA:
            if (size < 224) {
                reasons[*count] = malloc(128);
                snprintf(reasons[*count], 128, "ECDSA key size %d bits is below recommended 224 bits", size);
                (*count)++;
            }
            break;

        case KEY_TYPE_DSA:
            if (size < 2048) {
                reasons[*count] = malloc(128);
                snprintf(reasons[*count], 128, "DSA key size %d bits is below recommended 2048 bits", size);
                (*count)++;
            }
            // DSA is deprecated
            reasons[*count] = malloc(128);
            snprintf(reasons[*count], 128, "DSA algorithm is deprecated");
            (*count)++;
            break;

        case KEY_TYPE_DH:
            if (size < 2048) {
                reasons[*count] = malloc(128);
                snprintf(reasons[*count], 128, "DH key size %d bits is below recommended 2048 bits", size);
                (*count)++;
            }
            break;

        default:
            break;
    }

    if (*count == 0) {
        free(reasons);
        return NULL;
    }

    return reasons;
}

// ============================================================================
// Phase 3: CycloneDX Conformance Functions
// ============================================================================

// Determine key state based on filesystem attributes and metadata
// Returns key state according to NIST SP 800-57 lifecycle model
key_state_t determine_key_state(const char* key_path, time_t* creation_date,
                                 time_t* activation_date) {
    if (!key_path) return KEY_STATE_UNKNOWN;

    struct stat file_stat;
    if (stat(key_path, &file_stat) != 0) {
        return KEY_STATE_DESTROYED;  // File doesn't exist
    }

    time_t now = time(NULL);

    // Use filesystem timestamps as approximations
    if (creation_date) {
        *creation_date = file_stat.st_ctime;  // Creation time
    }
    if (activation_date) {
        *activation_date = file_stat.st_mtime; // Last modification (activation)
    }

    // Check file permissions to infer state
    if (!(file_stat.st_mode & S_IRUSR)) {
        return KEY_STATE_DESTROYED;  // Not readable = destroyed
    }

    // Check if key has been accessed recently
    time_t last_access = file_stat.st_atime;
    time_t days_since_access = (now - last_access) / (24 * 3600);

    if (days_since_access > 90) {
        return KEY_STATE_DEACTIVATED;  // Not accessed in 90 days
    }

    // Check for .compromised marker file
    char compromised_marker[PATH_MAX];
    snprintf(compromised_marker, sizeof(compromised_marker), "%s.compromised", key_path);
    if (access(compromised_marker, F_OK) == 0) {
        return KEY_STATE_COMPROMISED;
    }

    // Default to active state
    return KEY_STATE_ACTIVE;
}

// Convert key state enum to string for JSON output
const char* key_state_to_string(key_state_t state) {
    switch (state) {
        case KEY_STATE_PRE_ACTIVATION: return "pre-activation";
        case KEY_STATE_ACTIVE: return "active";
        case KEY_STATE_SUSPENDED: return "suspended";
        case KEY_STATE_DEACTIVATED: return "deactivated";
        case KEY_STATE_COMPROMISED: return "compromised";
        case KEY_STATE_DESTROYED: return "destroyed";
        case KEY_STATE_UNKNOWN:
        default: return "unknown";
    }
}

// Detect if a PEM key is encrypted and determine encryption algorithm
// Returns secured_by_t structure with mechanism and algorithm reference
// Returns NULL if key is not encrypted
secured_by_t* detect_key_encryption(const char* key_path) {
    if (!key_path) return NULL;

    FILE* fp = fopen(key_path, "r");
    if (!fp) return NULL;

    char line[256];
    bool is_encrypted = false;
    char* encryption_info = NULL;

    // Read PEM headers to detect encryption
    while (fgets(line, sizeof(line), fp)) {
        // Check for encrypted key marker
        if (strstr(line, "Proc-Type: 4,ENCRYPTED")) {
            is_encrypted = true;
        }
        // Extract encryption algorithm from DEK-Info
        if (strstr(line, "DEK-Info:")) {
            // Skip "DEK-Info: " prefix
            const char* info_start = line + strlen("DEK-Info:");
            while (*info_start == ' ') info_start++;
            encryption_info = strdup(info_start);
            // Remove trailing newline
            char* newline = strchr(encryption_info, '\n');
            if (newline) *newline = '\0';
            break;
        }
        // Stop at BEGIN block (headers done)
        if (strstr(line, "-----BEGIN")) {
            break;
        }
    }
    fclose(fp);

    if (!is_encrypted) {
        if (encryption_info) free(encryption_info);
        return NULL;
    }

    // Create secured_by structure
    secured_by_t* secured = secure_alloc(sizeof(secured_by_t));
    if (!secured) {
        if (encryption_info) free(encryption_info);
        return NULL;
    }

    // Set mechanism to Software (PEM encrypted keys are software-based)
    secured->mechanism = strdup("Software");

    // Map encryption algorithm from DEK-Info to algorithm bom-ref
    if (encryption_info) {
        if (strstr(encryption_info, "AES-256-CBC")) {
            secured->algorithm_ref = strdup("algo:aes-256-cbc");
        } else if (strstr(encryption_info, "AES-128-CBC")) {
            secured->algorithm_ref = strdup("algo:aes-128-cbc");
        } else if (strstr(encryption_info, "AES-192-CBC")) {
            secured->algorithm_ref = strdup("algo:aes-192-cbc");
        } else if (strstr(encryption_info, "DES-EDE3-CBC")) {
            secured->algorithm_ref = strdup("algo:3des-cbc");
        } else if (strstr(encryption_info, "DES-CBC")) {
            secured->algorithm_ref = strdup("algo:des-cbc");
        } else {
            // Unknown encryption algorithm
            secured->algorithm_ref = NULL;
        }
        free(encryption_info);
    } else {
        secured->algorithm_ref = NULL;
    }

    return secured;
}

// Cleanup secured_by structure
void secured_by_destroy(secured_by_t* secured_by) {
    if (!secured_by) return;

    if (secured_by->mechanism) {
        free(secured_by->mechanism);
        secured_by->mechanism = NULL;
    }
    if (secured_by->algorithm_ref) {
        free(secured_by->algorithm_ref);
        secured_by->algorithm_ref = NULL;
    }

    secure_free(secured_by, sizeof(secured_by_t));
}

// Lookup OID for key algorithm based on key type and parameters
// Returns NULL if OID cannot be determined
static char* lookup_key_algorithm_oid(key_type_t type, const char* curve_name) {
    const char* oid = NULL;

    switch (type) {
        case KEY_TYPE_RSA:
            // RSA encryption and signature OID (PKCS#1)
            oid = "1.2.840.113549.1.1.1";
            break;

        case KEY_TYPE_ECDSA:
            // ECDSA curve-specific OIDs
            if (curve_name) {
                if (strcmp(curve_name, "prime256v1") == 0 || strcmp(curve_name, "secp256r1") == 0 ||
                    strcmp(curve_name, "P-256") == 0) {
                    oid = "1.2.840.10045.3.1.7";  // secp256r1 / P-256
                } else if (strcmp(curve_name, "secp384r1") == 0 || strcmp(curve_name, "P-384") == 0) {
                    oid = "1.3.132.0.34";  // secp384r1 / P-384
                } else if (strcmp(curve_name, "secp521r1") == 0 || strcmp(curve_name, "P-521") == 0) {
                    oid = "1.3.132.0.35";  // secp521r1 / P-521
                } else if (strcmp(curve_name, "secp224r1") == 0 || strcmp(curve_name, "P-224") == 0) {
                    oid = "1.3.132.0.33";  // secp224r1 / P-224
                } else if (strcmp(curve_name, "secp192r1") == 0 || strcmp(curve_name, "P-192") == 0) {
                    oid = "1.2.840.10045.3.1.1";  // secp192r1 / P-192
                } else {
                    // Generic ECDSA OID if specific curve not recognized
                    oid = "1.2.840.10045.2.1";  // ecPublicKey
                }
            } else {
                oid = "1.2.840.10045.2.1";  // Generic ecPublicKey
            }
            break;

        case KEY_TYPE_ED25519:
            // Ed25519 signature algorithm
            oid = "1.3.101.112";
            break;

        case KEY_TYPE_ED448:
            // Ed448 signature algorithm
            oid = "1.3.101.113";
            break;

        case KEY_TYPE_DSA:
            // DSA signature algorithm
            oid = "1.2.840.10040.4.1";
            break;

        case KEY_TYPE_DH:
            // Diffie-Hellman key agreement (PKCS#3)
            oid = "1.2.840.113549.1.3.1";
            break;

        case KEY_TYPE_AES:
            // AES has different OIDs based on key size, but we don't have that info here
            // Return NULL and let algorithm metadata handle it
            return NULL;

        case KEY_TYPE_CHACHA20:
            // ChaCha20 OID
            oid = "1.2.840.113549.1.9.16.3.18";
            break;

        default:
            return NULL;
    }

    if (oid) {
        return strdup(oid);
    }
    return NULL;
}

// Extract key metadata (NEVER stores raw key material)
key_metadata_t* key_extract_metadata(EVP_PKEY* pkey, const char* file_path,
                                     key_format_t format, bool is_encrypted) {
    if (!pkey || !file_path) return NULL;

    key_metadata_t* metadata = secure_alloc(sizeof(key_metadata_t));
    if (!metadata) return NULL;

    memset(metadata, 0, sizeof(key_metadata_t));

    // Extract basic key information
    metadata->type = key_get_type(pkey);
    metadata->classification = key_get_classification(pkey);
    metadata->format = format;
    metadata->storage = key_detect_storage_security(file_path, is_encrypted);
    metadata->key_size = key_get_size(pkey);
    metadata->algorithm = key_get_algorithm_name(pkey);
    metadata->is_encrypted = is_encrypted;

    // Phase 3: CycloneDX conformance fields
    time_t creation_date = 0, activation_date = 0;
    metadata->state = determine_key_state(file_path, &creation_date, &activation_date);
    metadata->secured_by = detect_key_encryption(file_path);

    // Generate algorithm bom-ref (v1.5: use algo: prefix for consistency)
    if (metadata->algorithm) {
        size_t ref_len = strlen("algo:") + strlen(metadata->algorithm) + 1;
        metadata->algorithm_ref = malloc(ref_len);
        if (metadata->algorithm_ref) {
            snprintf(metadata->algorithm_ref, ref_len, "algo:%s", metadata->algorithm);
            // Lowercase the algorithm name in the ref (after prefix)
            for (char* p = metadata->algorithm_ref + 5; *p; p++) {  // Skip "algo:"
                *p = tolower(*p);
            }
        }
    } else {
        metadata->algorithm_ref = NULL;
    }

    // Get curve name for EC keys (needed for OID lookup)
    if (metadata->type == KEY_TYPE_ECDSA) {
        metadata->curve_name = key_get_curve_name(pkey);
        // Curve OID would require additional OpenSSL API calls
        metadata->curve_oid = NULL;
    }

    // Phase 3: OID lookup based on key type and curve
    metadata->oid = lookup_key_algorithm_oid(metadata->type, metadata->curve_name);

    // Generate key identifiers (SHA-256 hashes only, NEVER raw material)
    metadata->key_id_sha256 = key_generate_id(pkey);
    metadata->public_key_hash = key_get_public_key_hash(pkey);
    metadata->fingerprint = key_get_fingerprint(pkey, format);

    // Store file path
    metadata->file_path = malloc(strlen(file_path) + 1);
    if (metadata->file_path) {
        strcpy(metadata->file_path, file_path);
    }

    // Extract lifecycle metadata
    metadata->lifecycle = key_extract_lifecycle(file_path);

    // Detect usages
    metadata->usages = key_detect_usages(file_path, pkey, &metadata->usage_count);

    // Detect weaknesses
    metadata->is_weak = key_is_weak(pkey, metadata->type);
    metadata->weak_key_size = key_has_weak_size(pkey, metadata->type);
    metadata->weak_reasons = key_get_weak_reasons(pkey, metadata->type, &metadata->weak_reason_count);

    // Set detection metadata
    metadata->detection_method = malloc(64);
    if (metadata->detection_method) {
        strcpy(metadata->detection_method, "file_system_scan");
    }
    metadata->confidence = 1.0; // High confidence for parsed keys
    metadata->scan_time = time(NULL);

    return metadata;
}

// Destroy key metadata
void key_metadata_destroy(key_metadata_t* metadata) {
    if (!metadata) return;

    free(metadata->algorithm);
    free(metadata->curve_name);
    free(metadata->curve_oid);
    free(metadata->key_id_sha256);
    free(metadata->public_key_hash);
    free(metadata->fingerprint);
    free(metadata->file_path);
    free(metadata->file_path_hash);
    free(metadata->associated_cert_id);
    free(metadata->detection_method);

    // Phase 3: Clean up CycloneDX conformance fields
    if (metadata->algorithm_ref) {
        free(metadata->algorithm_ref);
        metadata->algorithm_ref = NULL;
    }
    if (metadata->oid) {
        free(metadata->oid);
        metadata->oid = NULL;
    }
    if (metadata->secured_by) {
        secured_by_destroy(metadata->secured_by);
        metadata->secured_by = NULL;
    }

    if (metadata->usages) {
        free(metadata->usages);
    }

    if (metadata->weak_reasons) {
        for (size_t i = 0; i < metadata->weak_reason_count; i++) {
            free(metadata->weak_reasons[i]);
        }
        free(metadata->weak_reasons);
    }

    secure_zero(metadata, sizeof(key_metadata_t));
    secure_free(metadata, sizeof(key_metadata_t));
}

// Create key asset (stores only metadata and hashes, NEVER raw material)
struct crypto_asset* key_create_asset(const key_metadata_t* metadata) {
    if (!metadata) return NULL;

    // Use crypto_asset_create to allocate (matches certificate scanner pattern)
    char asset_name[256];
    snprintf(asset_name, sizeof(asset_name), "%s Key", metadata->algorithm ? metadata->algorithm : "Unknown");

    crypto_asset_t* asset = crypto_asset_create(asset_name, ASSET_TYPE_KEY);
    if (!asset) return NULL;

    // Set asset ID (SHA-256 hash)
    if (metadata->key_id_sha256) {
        free(asset->id); // Free the default ID
        asset->id = strdup(metadata->key_id_sha256);
    }

    // Set asset location
    if (metadata->file_path) {
        asset->location = strdup(metadata->file_path);
    }

    // Set algorithm
    if (metadata->algorithm) {
        free(asset->algorithm); // Free default
        asset->algorithm = strdup(metadata->algorithm);
    }

    // Set weakness flag
    asset->is_weak = metadata->is_weak;

    // Set PQC readiness (keys are generally not PQC ready)
    asset->is_pqc_ready = false;

    // Store metadata as JSON (NEVER includes raw key material)
    asset->metadata_json = key_create_detailed_json_metadata(metadata);

    return asset;
}

// Create detailed JSON metadata (NEVER includes raw key material)
char* key_create_detailed_json_metadata(const key_metadata_t* metadata) {
    if (!metadata) return NULL;

    json_object* root = json_object_new_object();
    if (!root) return NULL;

    // Key type and classification
    const char* type_str = "unknown";
    switch (metadata->type) {
        case KEY_TYPE_RSA: type_str = "RSA"; break;
        case KEY_TYPE_ECDSA: type_str = "ECDSA"; break;
        case KEY_TYPE_ED25519: type_str = "Ed25519"; break;
        case KEY_TYPE_ED448: type_str = "Ed448"; break;
        case KEY_TYPE_DSA: type_str = "DSA"; break;
        case KEY_TYPE_DH: type_str = "DH"; break;
        default: break;
    }
    json_object_object_add(root, "key_type", json_object_new_string(type_str));

    const char* class_str = "unknown";
    switch (metadata->classification) {
        case KEY_CLASS_PRIVATE: class_str = "private"; break;
        case KEY_CLASS_PUBLIC: class_str = "public"; break;
        case KEY_CLASS_SYMMETRIC: class_str = "symmetric"; break;
        case KEY_CLASS_PAIR: class_str = "pair"; break;
        default: break;
    }
    json_object_object_add(root, "classification", json_object_new_string(class_str));

    // Key size and algorithm
    json_object_object_add(root, "key_size", json_object_new_int(metadata->key_size));
    if (metadata->algorithm) {
        json_object_object_add(root, "algorithm", json_object_new_string(metadata->algorithm));
    }

    // Curve information for EC keys
    if (metadata->curve_name) {
        json_object_object_add(root, "curve_name", json_object_new_string(metadata->curve_name));
    }

    // Key identifiers (SHA-256 hashes only, NEVER raw material)
    if (metadata->key_id_sha256) {
        json_object_object_add(root, "key_id_sha256", json_object_new_string(metadata->key_id_sha256));
    }
    if (metadata->public_key_hash) {
        json_object_object_add(root, "public_key_hash", json_object_new_string(metadata->public_key_hash));
    }

    // Storage security
    const char* storage_str = "unknown";
    switch (metadata->storage) {
        case STORAGE_PLAINTEXT: storage_str = "plaintext"; break;
        case STORAGE_ENCRYPTED: storage_str = "encrypted"; break;
        case STORAGE_HSM: storage_str = "hsm"; break;
        case STORAGE_TPM: storage_str = "tpm"; break;
        case STORAGE_KEYRING: storage_str = "keyring"; break;
        default: break;
    }
    json_object_object_add(root, "storage_security", json_object_new_string(storage_str));

    // Phase 3: CycloneDX conformance fields
    // Key state (NIST SP 800-57)
    const char* state_str = key_state_to_string(metadata->state);
    json_object_object_add(root, "state", json_object_new_string(state_str));

    // Algorithm reference
    if (metadata->algorithm_ref) {
        json_object_object_add(root, "algorithm_ref", json_object_new_string(metadata->algorithm_ref));
    }

    // OID
    if (metadata->oid) {
        json_object_object_add(root, "oid", json_object_new_string(metadata->oid));
    }

    // Secured by (encryption protection)
    if (metadata->secured_by) {
        json_object* secured_obj = json_object_new_object();
        if (metadata->secured_by->mechanism) {
            json_object_object_add(secured_obj, "mechanism",
                json_object_new_string(metadata->secured_by->mechanism));
        }
        if (metadata->secured_by->algorithm_ref) {
            json_object_object_add(secured_obj, "algorithm_ref",
                json_object_new_string(metadata->secured_by->algorithm_ref));
        }
        json_object_object_add(root, "secured_by", secured_obj);
    }

    // Format (for CycloneDX output)
    const char* format_str = "unknown";
    switch (metadata->format) {
        case KEY_FORMAT_PEM: format_str = "PEM"; break;
        case KEY_FORMAT_DER: format_str = "DER"; break;
        case KEY_FORMAT_OPENSSH: format_str = "OpenSSH"; break;
        case KEY_FORMAT_PKCS8: format_str = "PKCS#8"; break;
        case KEY_FORMAT_PKCS1: format_str = "PKCS#1"; break;
        case KEY_FORMAT_SEC1: format_str = "SEC1"; break;
        case KEY_FORMAT_RAW: format_str = "RAW"; break;
        default: break;
    }
    json_object_object_add(root, "format", json_object_new_string(format_str));

    // Weakness information
    json_object_object_add(root, "is_weak", json_object_new_boolean(metadata->is_weak));
    if (metadata->weak_reason_count > 0 && metadata->weak_reasons) {
        json_object* weak_array = json_object_new_array();
        for (size_t i = 0; i < metadata->weak_reason_count; i++) {
            json_object_array_add(weak_array, json_object_new_string(metadata->weak_reasons[i]));
        }
        json_object_object_add(root, "weak_reasons", weak_array);
    }

    // Convert to string
    const char* json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char* result = NULL;
    if (json_str) {
        result = malloc(strlen(json_str) + 1);
        if (result) {
            strcpy(result, json_str);
        }
    }

    json_object_put(root);
    return result;
}

// Process single key (main processing function)
static bool key_process_single_key(key_scanner_context_t* context, EVP_PKEY* pkey,
                                   const char* file_path, key_format_t format,
                                   bool is_encrypted) {
    if (!context || !pkey || !file_path) return false;

    // Extract metadata (NEVER stores raw key material)
    key_metadata_t* metadata = key_extract_metadata(pkey, file_path, format, is_encrypted);
    if (!metadata) {
        key_scanner_record_failure(context, KEY_FAIL_MEMORY_ERROR);
        return false;
    }

    // Create asset (stores only metadata and hashes)
    crypto_asset_t* asset = key_create_asset(metadata);
    if (!asset) {
        key_metadata_destroy(metadata);
        key_scanner_record_failure(context, KEY_FAIL_MEMORY_ERROR);
        return false;
    }

    // Add to asset store
    if (context->asset_store) {
        asset_store_add(context->asset_store, asset);
    }

    // Update statistics
    pthread_mutex_lock(&context->mutex);

    switch (metadata->classification) {
        case KEY_CLASS_PRIVATE:
            context->stats.private_keys_found++;
            break;
        case KEY_CLASS_PUBLIC:
            context->stats.public_keys_found++;
            break;
        case KEY_CLASS_SYMMETRIC:
            context->stats.symmetric_keys_found++;
            break;
        case KEY_CLASS_PAIR:
            context->stats.key_pairs_found++;
            break;
        default:
            break;
    }

    switch (metadata->type) {
        case KEY_TYPE_RSA: context->stats.rsa_keys++; break;
        case KEY_TYPE_ECDSA: context->stats.ecdsa_keys++; break;
        case KEY_TYPE_ED25519: context->stats.ed25519_keys++; break;
        case KEY_TYPE_DSA: context->stats.dsa_keys++; break;
        case KEY_TYPE_DH: context->stats.dh_keys++; break;
        default: break;
    }

    if (metadata->is_weak) {
        context->stats.weak_keys++;
    }

    pthread_mutex_unlock(&context->mutex);

    // Cleanup
    key_metadata_destroy(metadata);

    return true;
}

// Process encrypted PEM key using only header metadata (no decryption)
static int key_process_encrypted_pem_from_headers(key_scanner_context_t* context, const char* file_path) {
    if (!context || !file_path) return -1;

    // 1. Detect key type from PEM header
    key_type_t key_type = key_detect_type_from_pem_header(file_path);

    // 2. Get encryption info
    secured_by_t* secured_by = detect_key_encryption(file_path);

    // 3. Create partial metadata manually (since we can't extract from EVP_PKEY)
    key_metadata_t* metadata = secure_alloc(sizeof(key_metadata_t));
    if (!metadata) {
        if (secured_by) {
            free(secured_by->mechanism);
            free(secured_by->algorithm_ref);
            free(secured_by);
        }
        return -1;
    }
    memset(metadata, 0, sizeof(key_metadata_t));

    metadata->type = key_type;
    metadata->classification = KEY_CLASS_PRIVATE;  // Encrypted = private key
    metadata->format = KEY_FORMAT_PEM;
    metadata->storage = STORAGE_ENCRYPTED;
    metadata->is_encrypted = true;
    metadata->secured_by = secured_by;
    metadata->key_size = 0;  // Unknown without decryption
    metadata->algorithm = strdup(key_type_to_algorithm_string(key_type));
    metadata->state = KEY_STATE_ACTIVE;  // Assume active
    metadata->file_path = strdup(file_path);

    // 4. Generate key ID from file path (content-addressed)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)file_path, strlen(file_path), hash);
    char key_id[65];
    snprintf(key_id, sizeof(key_id),
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
             hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
             hash[16], hash[17], hash[18], hash[19], hash[20], hash[21], hash[22], hash[23],
             hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31]);
    metadata->key_id_sha256 = strdup(key_id);

    // 5. Create crypto asset using standard function
    crypto_asset_t* asset = key_create_asset(metadata);
    if (!asset) {
        key_metadata_destroy(metadata);
        return -1;
    }

    // 6. Register with asset store
    if (context->asset_store) {
        asset_store_add(context->asset_store, asset);
    }

    // Update stats (thread-safe)
    pthread_mutex_lock(&context->mutex);
    context->stats.private_keys_found++;
    context->stats.encrypted_keys++;
    context->stats.pem_detected++;
    switch (key_type) {
        case KEY_TYPE_RSA: context->stats.rsa_keys++; break;
        case KEY_TYPE_ECDSA: context->stats.ecdsa_keys++; break;
        case KEY_TYPE_ED25519: context->stats.ed25519_keys++; break;
        case KEY_TYPE_ED448: context->stats.ed25519_keys++; break;  // Count with Ed25519
        case KEY_TYPE_DSA: context->stats.dsa_keys++; break;
        case KEY_TYPE_DH: context->stats.dh_keys++; break;
        default: break;
    }
    pthread_mutex_unlock(&context->mutex);

    // Cleanup metadata (asset owns its own copies)
    key_metadata_destroy(metadata);

    return 0;  // Success - key reported with partial metadata
}

// Load and process PEM file
static int key_load_and_process_pem_file(key_scanner_context_t* context, const char* file_path) {
    if (!context || !file_path) return -1;

    bool is_encrypted = key_is_encrypted(file_path);

    // If encrypted and skip_encrypted is set, skip entirely
    if (is_encrypted && context->config.skip_encrypted) {
        key_scanner_record_failure(context, KEY_FAIL_ENCRYPTED_NO_PASSWORD);
        return -1;
    }

    // If encrypted and no password available, process from headers only
    if (is_encrypted && context->config.password_count == 0) {
        return key_process_encrypted_pem_from_headers(context, file_path);
    }

    // Try to load key (with password if encrypted and available)
    const char* password = NULL;
    if (is_encrypted && context->config.password_count > 0) {
        password = context->config.passwords[0]; // Try first password
    }

    EVP_PKEY* pkey = key_load_pem(file_path, password);
    if (!pkey) {
        if (is_encrypted) {
            key_scanner_record_failure(context, KEY_FAIL_WRONG_PASSWORD);
        } else {
            key_scanner_record_failure(context, KEY_FAIL_INVALID_PEM_BLOCK);
        }
        return -1;
    }

    // Process the key
    bool success = key_process_single_key(context, pkey, file_path, KEY_FORMAT_PEM, is_encrypted);

    // Clean up key from memory immediately
    EVP_PKEY_free(pkey);

    if (success) {
        pthread_mutex_lock(&context->mutex);
        context->stats.keys_detected_total++;
        context->stats.keys_parsed_ok++;
        context->stats.pem_detected++;
        context->stats.pem_parsed_ok++;
        pthread_mutex_unlock(&context->mutex);
        return 1;
    }

    return -1;
}

// Load and process DER file
static int key_load_and_process_der_file(key_scanner_context_t* context, const char* file_path) {
    if (!context || !file_path) return -1;

    EVP_PKEY* pkey = key_load_der(file_path);
    if (!pkey) {
        key_scanner_record_failure(context, KEY_FAIL_DER_TRUNCATED);
        return -1;
    }

    bool success = key_process_single_key(context, pkey, file_path, KEY_FORMAT_DER, false);

    // Clean up key from memory immediately
    EVP_PKEY_free(pkey);

    if (success) {
        pthread_mutex_lock(&context->mutex);
        context->stats.keys_detected_total++;
        context->stats.keys_parsed_ok++;
        context->stats.der_detected++;
        context->stats.der_parsed_ok++;
        pthread_mutex_unlock(&context->mutex);
        return 1;
    }

    return -1;
}

// Load and process OpenSSH file
static int key_load_and_process_openssh_file(key_scanner_context_t* context, const char* file_path) {
    if (!context || !file_path) return -1;

    EVP_PKEY* pkey = key_load_openssh(file_path);
    if (!pkey) {
        key_scanner_record_failure(context, KEY_FAIL_INVALID_PEM_BLOCK);
        return -1;
    }

    bool success = key_process_single_key(context, pkey, file_path, KEY_FORMAT_OPENSSH, false);

    // Clean up key from memory immediately
    EVP_PKEY_free(pkey);

    if (success) {
        pthread_mutex_lock(&context->mutex);
        context->stats.keys_detected_total++;
        context->stats.keys_parsed_ok++;
        context->stats.openssh_detected++;
        context->stats.openssh_parsed_ok++;
        pthread_mutex_unlock(&context->mutex);
        return 1;
    }

    return -1;
}

// Scan single key file
int key_scanner_scan_file(key_scanner_context_t* context, const char* file_path) {
    if (!context || !file_path) return -1;

    pthread_mutex_lock(&context->mutex);
    context->stats.files_scanned_total++;
    pthread_mutex_unlock(&context->mutex);

    // Detect format
    key_format_t format = key_detect_format(file_path);
    if (format == KEY_FORMAT_UNKNOWN) {
        return 0; // Not a key file
    }

    int result = 0;

    switch (format) {
        case KEY_FORMAT_PEM:
            result = key_load_and_process_pem_file(context, file_path);
            break;

        case KEY_FORMAT_DER:
            result = key_load_and_process_der_file(context, file_path);
            break;

        case KEY_FORMAT_OPENSSH:
            result = key_load_and_process_openssh_file(context, file_path);
            break;

        default:
            key_scanner_record_failure(context, KEY_FAIL_UNSUPPORTED_KEY_TYPE);
            result = -1;
            break;
    }

    if (result > 0) {
        pthread_mutex_lock(&context->mutex);
        context->stats.files_with_keys++;
        pthread_mutex_unlock(&context->mutex);
    }

    return result;
}

// Scan directory for keys
int key_scanner_scan_directory(key_scanner_context_t* context, const char* dir_path) {
    if (!context || !dir_path) return -1;

    DIR* dir = opendir(dir_path);
    if (!dir) {
        return -1;
    }

    int total_keys = 0;
    int files_checked = 0;
    struct dirent* entry;
    static atomic_size_t global_file_counter = 0;  // Atomic: thread-safe across parallel scanners
    static time_t last_progress = 0;
    if (last_progress == 0) last_progress = time(NULL);

    while ((entry = readdir(dir)) != NULL) {
        files_checked++;
        size_t current_count = atomic_fetch_add(&global_file_counter, 1) + 1;

        // Progress reporting: every 1000 files OR every 10 seconds
        time_t now = time(NULL);
        if (current_count % 1000 == 0 || (now - last_progress) >= 10) {
            tui_log(TUI_MSG_SCANNER_PROGRESS, SCANNER_KEY,
                    "Key scanner", current_count, (size_t)total_keys, NULL, dir_path);
            last_progress = now;
        }

        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Build full path
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            // Recurse if enabled, but skip hidden directories (same as certificate scanner)
            if (context->config.recursive_scan) {
                const char* dirname = entry->d_name;
                if (strncmp(dirname, ".", 1) != 0) {  // Skip hidden directories (.cache, .config, etc.)
                    int keys = key_scanner_scan_directory(context, full_path);
                    if (keys > 0) total_keys += keys;
                }
            }
        } else if (S_ISREG(st.st_mode)) {
            // Scan file
            int result = key_scanner_scan_file(context, full_path);
            if (result > 0) total_keys += result;
        }
    }

    closedir(dir);
    return total_keys;
}

// Scan configured paths
int key_scanner_scan_paths(key_scanner_context_t* context) {
    if (!context) return -1;

    int total_keys = 0;

    for (size_t i = 0; i < context->config.scan_path_count; i++) {
        const char* path = context->config.scan_paths[i];
        if (!path) continue;

        struct stat st;
        if (stat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            int keys = key_scanner_scan_directory(context, path);
            if (keys > 0) total_keys += keys;
        } else if (S_ISREG(st.st_mode)) {
            int result = key_scanner_scan_file(context, path);
            if (result > 0) total_keys += result;
        }
    }

    return total_keys;
}

// Get statistics
key_scanner_stats_t key_scanner_get_stats(const key_scanner_context_t* context) {
    if (!context) {
        key_scanner_stats_t empty = {0};
        return empty;
    }

    return context->stats;
}

// Security validation: check for key material in output (for testing)
bool key_scanner_validate_no_key_material_in_output(const char* output) {
    if (!output) return true;

    // Check for common key material patterns (this should NEVER be found)
    const char* forbidden_patterns[] = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "MII", // Common base64 prefix for keys
        NULL
    };

    for (int i = 0; forbidden_patterns[i] != NULL; i++) {
        if (strstr(output, forbidden_patterns[i]) != NULL) {
            return false; // FAIL: Found key material
        }
    }

    return true; // PASS: No key material found
}

// Security validation: check for PEM headers in output (for testing)
bool key_scanner_validate_no_pem_headers_in_output(const char* output) {
    if (!output) return true;

    // Check for PEM headers (this should NEVER be found)
    const char* forbidden_headers[] = {
        "-----BEGIN",
        "-----END",
        NULL
    };

    for (int i = 0; forbidden_headers[i] != NULL; i++) {
        if (strstr(output, forbidden_headers[i]) != NULL) {
            return false; // FAIL: Found PEM header
        }
    }

    return true; // PASS: No PEM headers found
}

#else /* __EMSCRIPTEN__ — WASM stubs for key scanner */

/*
 * WASM build: key parsing requires OpenSSL which is not available.
 * These stubs provide the public API so builtin_scanners.c links correctly.
 * All scanning functions return 0 (no keys found).
 * Phase 2 will replace these with a JS bridge to pkijs.
 */

static __thread char last_error[256] = "Key parsing not available in WASM";

__attribute__((unused))
static void set_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_error, sizeof(last_error), fmt, args);
    va_end(args);
}

const char* key_scanner_get_last_error(void) {
    return last_error;
}

void key_scanner_clear_error(void) {
    last_error[0] = '\0';
}

key_scanner_config_t key_scanner_create_default_config(void) {
    key_scanner_config_t config = {0};
    config.recursive_scan = true;
    config.max_file_size = 1024 * 1024;
    config.timeout_seconds = 5;
    config.detect_weak_keys = false;
    config.redact_key_material = true;
    return config;
}

void key_scanner_config_destroy(key_scanner_config_t* config) {
    if (!config) return;
    if (config->scan_paths) {
        for (size_t i = 0; i < config->scan_path_count; i++) {
            free(config->scan_paths[i]);
        }
        free(config->scan_paths);
    }
    if (config->passwords) {
        for (size_t i = 0; i < config->password_count; i++) {
            free(config->passwords[i]);
        }
        free(config->passwords);
    }
    memset(config, 0, sizeof(key_scanner_config_t));
}

key_scanner_context_t* key_scanner_create(const key_scanner_config_t* config,
                                         struct asset_store* store) {
    if (!config || !store) return NULL;

    key_scanner_context_t* ctx = calloc(1, sizeof(key_scanner_context_t));
    if (!ctx) return NULL;

    ctx->config = *config;
    ctx->asset_store = store;
    pthread_mutex_init(&ctx->mutex, NULL);
    return ctx;
}

void key_scanner_destroy(key_scanner_context_t* context) {
    if (!context) return;
    pthread_mutex_destroy(&context->mutex);
    free(context);
}

int key_scanner_scan_file(key_scanner_context_t* context, const char* file_path) {
    (void)context; (void)file_path;
    return 0;
}

int key_scanner_scan_directory(key_scanner_context_t* context, const char* dir_path) {
    (void)context; (void)dir_path;
    return 0;
}

int key_scanner_scan_paths(key_scanner_context_t* context) {
    (void)context;
    return 0;
}

key_scanner_stats_t key_scanner_get_stats(const key_scanner_context_t* context) {
    key_scanner_stats_t stats = {0};
    if (context) {
        stats = context->stats;
    }
    return stats;
}

key_format_t key_detect_format(const char* file_path) {
    (void)file_path;
    return KEY_FORMAT_UNKNOWN;
}

key_format_t key_detect_format_from_content(const unsigned char* data, size_t len) {
    (void)data; (void)len;
    return KEY_FORMAT_UNKNOWN;
}

bool key_is_encrypted(const char* file_path) {
    (void)file_path;
    return false;
}

storage_security_t key_detect_storage_security(const char* file_path, bool is_encrypted) {
    (void)file_path; (void)is_encrypted;
    return STORAGE_UNKNOWN;
}

bool key_is_in_hsm(const char* file_path) { (void)file_path; return false; }
bool key_is_in_tpm(const char* file_path) { (void)file_path; return false; }
bool key_is_in_keyring(const char* file_path) { (void)file_path; return false; }

key_lifecycle_t key_extract_lifecycle(const char* file_path) {
    (void)file_path;
    key_lifecycle_t lc = {0};
    return lc;
}

bool key_is_expired(const key_lifecycle_t* lifecycle) {
    (void)lifecycle;
    return false;
}

int key_days_until_expiration(const key_lifecycle_t* lifecycle) {
    (void)lifecycle;
    return -1;
}

key_usage_t key_detect_primary_usage(const char* file_path) {
    (void)file_path;
    return KEY_USAGE_UNKNOWN;
}

key_state_t determine_key_state(const char* key_path, time_t* creation_date,
                                 time_t* activation_date) {
    (void)key_path; (void)creation_date; (void)activation_date;
    return KEY_STATE_UNKNOWN;
}

const char* key_state_to_string(key_state_t state) {
    switch (state) {
        case KEY_STATE_PRE_ACTIVATION: return "pre-activation";
        case KEY_STATE_ACTIVE: return "active";
        case KEY_STATE_SUSPENDED: return "suspended";
        case KEY_STATE_DEACTIVATED: return "deactivated";
        case KEY_STATE_COMPROMISED: return "compromised";
        case KEY_STATE_DESTROYED: return "destroyed";
        default: return "unknown";
    }
}

secured_by_t* detect_key_encryption(const char* key_path) {
    (void)key_path;
    return NULL;
}

void secured_by_destroy(secured_by_t* secured_by) {
    if (!secured_by) return;
    free(secured_by->mechanism);
    free(secured_by->algorithm_ref);
    free(secured_by);
}

struct crypto_asset* key_create_asset(const key_metadata_t* metadata) {
    (void)metadata;
    return NULL;
}

char* key_create_detailed_json_metadata(const key_metadata_t* metadata) {
    (void)metadata;
    return NULL;
}

void key_metadata_destroy(key_metadata_t* metadata) {
    if (!metadata) return;
    free(metadata->algorithm);
    free(metadata->curve_name);
    free(metadata->curve_oid);
    free(metadata->key_id_sha256);
    free(metadata->public_key_hash);
    free(metadata->fingerprint);
    free(metadata->file_path);
    free(metadata->file_path_hash);
    free(metadata->associated_cert_id);
    free(metadata->detection_method);
    free(metadata->algorithm_ref);
    free(metadata->oid);
    if (metadata->usages) free(metadata->usages);
    if (metadata->weak_reasons) {
        for (size_t i = 0; i < metadata->weak_reason_count; i++) {
            free(metadata->weak_reasons[i]);
        }
        free(metadata->weak_reasons);
    }
    if (metadata->secured_by) {
        secured_by_destroy(metadata->secured_by);
    }
    free(metadata);
}

void key_lifecycle_destroy(key_lifecycle_t* lifecycle) {
    (void)lifecycle;
}

const char* key_failure_reason_to_string(key_failure_reason_t reason) {
    switch (reason) {
        case KEY_FAIL_INVALID_PEM_BLOCK: return "INVALID_PEM_BLOCK";
        case KEY_FAIL_DER_TRUNCATED: return "DER_TRUNCATED";
        case KEY_FAIL_DER_OVERLONG: return "DER_OVERLONG";
        case KEY_FAIL_ENCRYPTED_NO_PASSWORD: return "ENCRYPTED_NO_PASSWORD";
        case KEY_FAIL_WRONG_PASSWORD: return "WRONG_PASSWORD";
        case KEY_FAIL_UNSUPPORTED_ENCRYPTION: return "UNSUPPORTED_ENCRYPTION";
        case KEY_FAIL_UNSUPPORTED_KEY_TYPE: return "UNSUPPORTED_KEY_TYPE";
        case KEY_FAIL_TOO_LARGE: return "TOO_LARGE";
        case KEY_FAIL_TIMEOUT: return "TIMEOUT";
        case KEY_FAIL_SANITY_LIMIT_HIT: return "SANITY_LIMIT_HIT";
        case KEY_FAIL_MEMORY_ERROR: return "MEMORY_ERROR";
        case KEY_FAIL_IO_ERROR: return "IO_ERROR";
        case KEY_FAIL_UNKNOWN: return "UNKNOWN";
        default: return "INVALID_REASON";
    }
}

void key_scanner_record_failure(key_scanner_context_t* context, key_failure_reason_t reason) {
    (void)context; (void)reason;
}

bool key_scanner_validate_no_key_material_in_output(const char* output) {
    (void)output;
    return true;
}

bool key_scanner_validate_no_pem_headers_in_output(const char* output) {
    (void)output;
    return true;
}

#endif /* __EMSCRIPTEN__ */
