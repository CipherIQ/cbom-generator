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

#include "openpgp_parser.h"
#include "error_handling.h"
#include "secure_memory.h"
#include "asset_store.h"
#include "cbom_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <json-c/json.h>
#include <ctype.h>

// Thread-local error storage
static __thread char last_error[256] = {0};

// Check if file contains OpenPGP key data
bool is_openpgp_key_file(const char *filepath) {
    if (!filepath) return false;
    
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        return false;
    }
    
    char buffer[256];
    bool is_pgp = false;
    
    // Read first few lines to check for PGP headers
    while (fgets(buffer, sizeof(buffer), file)) {
        if (strstr(buffer, "-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
            strstr(buffer, "-----BEGIN PGP PRIVATE KEY BLOCK-----") ||
            strstr(buffer, "-----BEGIN PGP MESSAGE-----")) {
            is_pgp = true;
            break;
        }
        // Stop after checking first few lines
        if (ftell(file) > 1024) break;
    }
    
    fclose(file);
    return is_pgp;
}

// Extract OpenPGP key fingerprint from ASCII armor
static char* extract_pgp_fingerprint(const char *filepath) {
    // For now, return a placeholder fingerprint based on file hash
    // In a full implementation, this would parse the actual PGP key structure
    FILE *file = fopen(filepath, "r");
    if (!file) return NULL;
    
    // Read file content for basic fingerprint generation
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024 * 1024) { // Limit to 1MB
        fclose(file);
        return NULL;
    }
    
    char *content = secure_alloc(file_size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(content, 1, file_size, file);
    content[read_size] = '\0';
    fclose(file);
    
    // Generate a simple fingerprint-like hash from content
    // This is a placeholder - real implementation would parse PGP packets
    unsigned long hash = 5381;
    for (size_t i = 0; i < read_size; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)content[i];
    }
    
    secure_free(content, file_size + 1);
    
    char *fingerprint = secure_alloc(65); // 64 chars + null terminator for safety
    if (fingerprint) {
        snprintf(fingerprint, 65, "%08lX%08lX%08lX%08lX%08lX", 
                hash, hash >> 8, hash >> 16, hash >> 24, hash >> 32);
    }
    
    return fingerprint;
}

// Extract key creation time from PGP key (placeholder implementation)
static time_t extract_pgp_creation_time(const char *filepath) {
    // Placeholder: return file modification time
    // Real implementation would parse PGP packet timestamps
    struct stat st;
    if (stat(filepath, &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

// Extract key expiry time from PGP key (placeholder implementation)
static time_t extract_pgp_expiry_time(const char *filepath) {
    (void)filepath; // Suppress unused parameter warning
    // Placeholder: assume no expiry for now
    // Real implementation would parse PGP packet expiry information
    return 0;
}

// Extract user ID from PGP key
static char* extract_pgp_user_id(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return NULL;
    
    char line[512];
    char *user_id = NULL;
    
    // Look for user ID in the ASCII armor comments or key data
    while (fgets(line, sizeof(line), file)) {
        // Skip PGP headers
        if (strstr(line, "-----BEGIN") || strstr(line, "-----END")) continue;
        if (strstr(line, "Version:")) continue;
        if (strlen(line) < 10) continue;
        
        // Look for base64-like content that might contain user info
        // This is a very basic extraction - real implementation would decode packets
        if (strstr(line, "=") && strlen(line) > 20) {
            // Extract filename as user ID for now
            const char *filename = strrchr(filepath, '/');
            if (filename) {
                filename++; // Skip the '/'
                user_id = secure_alloc(strlen(filename) + 1);
                if (user_id) {
                    strcpy(user_id, filename);
                }
            }
            break;
        }
    }
    
    fclose(file);
    return user_id;
}

// Parse OpenPGP key file and create asset
crypto_asset_t* parse_openpgp_key(const char *filepath) {
    if (!filepath || !is_openpgp_key_file(filepath)) {
        return NULL;
    }
    
    // Extract key information
    char *fingerprint = extract_pgp_fingerprint(filepath);
    char *user_id = extract_pgp_user_id(filepath);
    time_t creation_time = extract_pgp_creation_time(filepath);
    time_t expiry_time = extract_pgp_expiry_time(filepath);
    
    if (!fingerprint) {
        if (user_id) secure_free(user_id, strlen(user_id) + 1);
        snprintf(last_error, sizeof(last_error), "Failed to extract fingerprint from %s", filepath);
        return NULL;
    }
    
    // Create asset with fingerprint as name
    crypto_asset_t *asset = crypto_asset_create(fingerprint, ASSET_TYPE_KEY);
    if (asset == NULL) {
        secure_free(fingerprint, 65);
        if (user_id) secure_free(user_id, strlen(user_id) + 1);
        return NULL;
    }
    
    // Set location
    asset->location = strdup(filepath);
    
    // Set algorithm to OpenPGP
    asset->algorithm = strdup("OpenPGP");
    
    // Create metadata JSON
    json_object *metadata = json_object_new_object();
    if (metadata) {
        json_object_object_add(metadata, "key_type", json_object_new_string("openpgp"));
        json_object_object_add(metadata, "fingerprint", json_object_new_string(fingerprint));
        
        if (user_id) {
            json_object_object_add(metadata, "user_id", json_object_new_string(user_id));
        }
        
        if (creation_time > 0) {
            json_object_object_add(metadata, "creation_time", json_object_new_int64(creation_time));
        }
        
        if (expiry_time > 0) {
            json_object_object_add(metadata, "expiry_time", json_object_new_int64(expiry_time));
        }
        
        // Determine if file path suggests it's a GPG key
        if (strstr(filepath, "GPG-KEY") || strstr(filepath, ".gpg") || strstr(filepath, ".asc")) {
            json_object_object_add(metadata, "format", json_object_new_string("ascii_armor"));
        }
        
        const char *metadata_str = json_object_to_json_string(metadata);
        if (metadata_str) {
            asset->metadata_json = strdup(metadata_str);
        }
        
        json_object_put(metadata);
    }
    
    secure_free(fingerprint, 65);
    if (user_id) secure_free(user_id, strlen(user_id) + 1);
    
    return asset;
}

// Check if file extension suggests OpenPGP key
bool has_openpgp_extension(const char *filepath) {
    if (!filepath) return false;
    
    const char *ext = strrchr(filepath, '.');
    if (!ext) {
        // Check for GPG-KEY pattern in filename
        return (strstr(filepath, "GPG-KEY") != NULL);
    }
    
    return (strcasecmp(ext, ".asc") == 0 ||
            strcasecmp(ext, ".gpg") == 0 ||
            strcasecmp(ext, ".pgp") == 0);
}
