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
#include "attestation.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

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

// Base64 encoding using OpenSSL
char* attestation_base64_encode(const unsigned char* data, size_t len) {
    if (!data || len == 0) return NULL;

    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    char* encoded = malloc(buffer_ptr->length + 1);
    if (!encoded) {
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(encoded, buffer_ptr->data, buffer_ptr->length);
    encoded[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return encoded;
}

// Base64 decoding using OpenSSL
unsigned char* attestation_base64_decode(const char* encoded, size_t* out_len) {
    if (!encoded) return NULL;

    size_t len = strlen(encoded);
    unsigned char* decoded = malloc(len);
    if (!decoded) return NULL;

    BIO *bio, *b64;
    bio = BIO_new_mem_buf(encoded, len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_len = BIO_read(bio, decoded, len);
    BIO_free_all(bio);

    if (decoded_len < 0) {
        free(decoded);
        return NULL;
    }

    if (out_len) *out_len = decoded_len;
    return decoded;
}

// Compute SHA-256 hash
char* attestation_compute_sha256(const unsigned char* data, size_t len) {
    if (!data || len == 0) return NULL;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return NULL;

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    if (EVP_DigestUpdate(mdctx, data, len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);

    // Convert to hex string
    char* hex = malloc(hash_len * 2 + 1);
    if (!hex) return NULL;

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[hash_len * 2] = '\0';

    return hex;
}

// Get default attestation configuration
attestation_config_t attestation_get_default_config(void) {
    attestation_config_t config = {
        .method = SIGNATURE_METHOD_DSSE,
        .signing_key_path = NULL,
        .key_password = NULL,
        .include_slsa = true
    };
    return config;
}

// Load private key from file
int attestation_load_private_key(attestation_context_t* context) {
    if (!context || !context->config.signing_key_path) {
        return -1;
    }

    FILE* key_file = fopen(context->config.signing_key_path, "r");
    if (!key_file) {
        fprintf(stderr, "Error: Cannot open signing key file: %s\n",
                context->config.signing_key_path);
        return -1;
    }

    // Use password_callback to prevent stdin prompts for encrypted keys
    EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, NULL, password_callback,
                                          (void*)context->config.key_password);
    fclose(key_file);

    if (!pkey) {
        fprintf(stderr, "Error: Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    context->signing_key = pkey;
    return 0;
}

// Get key fingerprint
char* attestation_get_key_fingerprint(attestation_context_t* context) {
    if (!context || !context->signing_key) {
        return NULL;
    }

    EVP_PKEY* pkey = (EVP_PKEY*)context->signing_key;

    // Get public key in DER format
    unsigned char* der = NULL;
    int der_len = i2d_PUBKEY(pkey, &der);
    if (der_len < 0 || !der) {
        return NULL;
    }

    // Compute SHA-256 of public key
    char* fingerprint = attestation_compute_sha256(der, der_len);
    OPENSSL_free(der);

    // Return first 16 chars as short fingerprint
    if (fingerprint && strlen(fingerprint) > 16) {
        fingerprint[16] = '\0';
    }

    return fingerprint;
}

// Sign data with private key
int attestation_sign_data(attestation_context_t* context,
                          const unsigned char* data,
                          size_t data_len,
                          unsigned char** signature,
                          size_t* signature_len) {
    if (!context || !context->signing_key || !data || !signature || !signature_len) {
        return -1;
    }

    EVP_PKEY* pkey = (EVP_PKEY*)context->signing_key;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestSignUpdate(mdctx, data, data_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Determine signature length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Allocate signature buffer
    unsigned char* sig = malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Generate signature
    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) != 1) {
        free(sig);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    *signature = sig;
    *signature_len = sig_len;
    return 0;
}

// Create attestation context
attestation_context_t* attestation_create(const attestation_config_t* config) {
    if (!config) return NULL;

    attestation_context_t* context = secure_alloc(sizeof(attestation_context_t));
    if (!context) return NULL;

    context->config = *config;
    if (config->signing_key_path) {
        context->config.signing_key_path = strdup(config->signing_key_path);
    }
    if (config->key_password) {
        context->config.key_password = strdup(config->key_password);
    }

    context->signing_key = NULL;
    context->key_fingerprint = NULL;
    context->initialized = false;

    // Load signing key
    if (attestation_load_private_key(context) != 0) {
        attestation_destroy(context);
        return NULL;
    }

    // Get key fingerprint
    context->key_fingerprint = attestation_get_key_fingerprint(context);

    context->initialized = true;
    return context;
}

// Destroy attestation context
void attestation_destroy(attestation_context_t* context) {
    if (!context) return;

    if (context->config.signing_key_path) {
        free(context->config.signing_key_path);
    }
    if (context->config.key_password) {
        secure_free(context->config.key_password, strlen(context->config.key_password));
    }
    if (context->signing_key) {
        EVP_PKEY_free((EVP_PKEY*)context->signing_key);
    }
    if (context->key_fingerprint) {
        free(context->key_fingerprint);
    }

    secure_free(context, sizeof(attestation_context_t));
}

// Create DSSE envelope
dsse_envelope_t* dsse_create_envelope(const char* payload, const char* payload_type) {
    if (!payload || !payload_type) return NULL;

    dsse_envelope_t* envelope = secure_alloc(sizeof(dsse_envelope_t));
    if (!envelope) return NULL;

    // Base64 encode payload
    envelope->payload = attestation_base64_encode((const unsigned char*)payload,
                                                   strlen(payload));
    envelope->payloadType = strdup(payload_type);
    envelope->signatures = NULL;
    envelope->signature_count = 0;

    return envelope;
}

// Add signature to DSSE envelope
int dsse_add_signature(dsse_envelope_t* envelope,
                       attestation_context_t* context,
                       const char* payload) {
    if (!envelope || !context || !payload) return -1;

    // Create PAE (Pre-Authentication Encoding)
    // PAE = "DSSEv1" + SP + LEN(payloadType) + SP + payloadType + SP + LEN(payload) + SP + payload
    char pae_header[256];
    snprintf(pae_header, sizeof(pae_header), "DSSEv1 %zu %s %zu ",
             strlen(envelope->payloadType), envelope->payloadType, strlen(payload));

    size_t pae_len = strlen(pae_header) + strlen(payload);
    char* pae = malloc(pae_len + 1);
    if (!pae) return -1;

    strcpy(pae, pae_header);
    strcat(pae, payload);

    // Sign the PAE
    unsigned char* signature = NULL;
    size_t signature_len = 0;

    if (attestation_sign_data(context, (unsigned char*)pae, pae_len,
                              &signature, &signature_len) != 0) {
        free(pae);
        return -1;
    }

    free(pae);

    // Create signature structure
    dsse_signature_t* sig = secure_alloc(sizeof(dsse_signature_t));
    if (!sig) {
        free(signature);
        return -1;
    }

    sig->keyid = context->key_fingerprint ? strdup(context->key_fingerprint) : strdup("unknown");
    sig->sig = attestation_base64_encode(signature, signature_len);
    free(signature);

    // Add to envelope
    envelope->signatures = realloc(envelope->signatures,
                                   sizeof(dsse_signature_t*) * (envelope->signature_count + 1));
    envelope->signatures[envelope->signature_count] = sig;
    envelope->signature_count++;

    return 0;
}

// Destroy DSSE envelope
void dsse_envelope_destroy(dsse_envelope_t* envelope) {
    if (!envelope) return;

    if (envelope->payload) free(envelope->payload);
    if (envelope->payloadType) free(envelope->payloadType);

    if (envelope->signatures) {
        for (size_t i = 0; i < envelope->signature_count; i++) {
            if (envelope->signatures[i]) {
                if (envelope->signatures[i]->keyid) free(envelope->signatures[i]->keyid);
                if (envelope->signatures[i]->sig) free(envelope->signatures[i]->sig);
                secure_free(envelope->signatures[i], sizeof(dsse_signature_t));
            }
        }
        free(envelope->signatures);
    }

    secure_free(envelope, sizeof(dsse_envelope_t));
}

// Convert DSSE envelope to JSON
json_object* dsse_envelope_to_json(const dsse_envelope_t* envelope) {
    if (!envelope) return NULL;

    json_object* json = json_object_new_object();

    json_object_object_add(json, "payload", json_object_new_string(envelope->payload));
    json_object_object_add(json, "payloadType", json_object_new_string(envelope->payloadType));

    json_object* signatures = json_object_new_array();
    for (size_t i = 0; i < envelope->signature_count; i++) {
        json_object* sig = json_object_new_object();
        json_object_object_add(sig, "keyid",
                              json_object_new_string(envelope->signatures[i]->keyid));
        json_object_object_add(sig, "sig",
                              json_object_new_string(envelope->signatures[i]->sig));
        json_object_array_add(signatures, sig);
    }
    json_object_object_add(json, "signatures", signatures);

    return json;
}

// Write DSSE envelope to file
int dsse_write_to_file(const dsse_envelope_t* envelope, const char* output_path) {
    if (!envelope || !output_path) return -1;

    json_object* json = dsse_envelope_to_json(envelope);
    if (!json) return -1;

    const char* json_str = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY);

    FILE* output = fopen(output_path, "w");
    if (!output) {
        json_object_put(json);
        return -1;
    }

    fprintf(output, "%s\n", json_str);
    fclose(output);

    json_object_put(json);
    return 0;
}

// Sign CBOM JSON object
json_object* attestation_sign_cbom_json(attestation_context_t* context, json_object* cbom) {
    if (!context || !cbom) return NULL;

    // Convert CBOM to string
    const char* cbom_str = json_object_to_json_string(cbom);

    // Create DSSE envelope
    dsse_envelope_t* envelope = dsse_create_envelope(cbom_str,
                                                      "application/vnd.cyclonedx+json");
    if (!envelope) return NULL;

    // Add signature
    if (dsse_add_signature(envelope, context, cbom_str) != 0) {
        dsse_envelope_destroy(envelope);
        return NULL;
    }

    // Convert to JSON
    json_object* result = dsse_envelope_to_json(envelope);
    dsse_envelope_destroy(envelope);

    return result;
}

// Sign CBOM file
int attestation_sign_cbom_file(attestation_context_t* context,
                               const char* cbom_file_path,
                               const char* output_path) {
    if (!context || !cbom_file_path || !output_path) return -1;

    // Read CBOM file
    json_object* cbom = json_object_from_file(cbom_file_path);
    if (!cbom) {
        fprintf(stderr, "Error: Failed to read CBOM file: %s\n", cbom_file_path);
        return -1;
    }

    // Sign CBOM
    json_object* signed_envelope = attestation_sign_cbom_json(context, cbom);
    json_object_put(cbom);

    if (!signed_envelope) {
        return -1;
    }

    // Write signed envelope to file
    const char* json_str = json_object_to_json_string_ext(signed_envelope,
                                                          JSON_C_TO_STRING_PRETTY);
    FILE* output = fopen(output_path, "w");
    if (!output) {
        json_object_put(signed_envelope);
        return -1;
    }

    fprintf(output, "%s\n", json_str);
    fclose(output);

    json_object_put(signed_envelope);
    return 0;
}
