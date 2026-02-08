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
#include "algorithm_metadata.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __EMSCRIPTEN__
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#endif
#include <json-c/json.h>

// OID to algorithm name mapping table
typedef struct {
    const char* oid;
    const char* name;
    crypto_primitive_t primitive;
} oid_mapping_t;

// Comprehensive OID mapping table
static const oid_mapping_t oid_mappings[] = {
    // RSA algorithms
    {"1.2.840.113549.1.1.1", "RSA", PRIMITIVE_ASYMMETRIC_CIPHER},
    {"1.2.840.113549.1.1.5", "SHA1WithRSAEncryption", PRIMITIVE_SIGNATURE},
    {"1.2.840.113549.1.1.11", "SHA256WithRSAEncryption", PRIMITIVE_SIGNATURE},
    {"1.2.840.113549.1.1.12", "SHA384WithRSAEncryption", PRIMITIVE_SIGNATURE},
    {"1.2.840.113549.1.1.13", "SHA512WithRSAEncryption", PRIMITIVE_SIGNATURE},
    {"1.2.840.113549.1.1.14", "SHA224WithRSAEncryption", PRIMITIVE_SIGNATURE},
    {"1.2.840.113549.1.1.4", "MD5WithRSAEncryption", PRIMITIVE_SIGNATURE},

    // ECDSA algorithms
    {"1.2.840.10045.2.1", "EC", PRIMITIVE_ASYMMETRIC_CIPHER},
    {"1.2.840.10045.4.1", "ECDSAWithSHA1", PRIMITIVE_SIGNATURE},
    {"1.2.840.10045.4.3.2", "ECDSAWithSHA256", PRIMITIVE_SIGNATURE},
    {"1.2.840.10045.4.3.3", "ECDSAWithSHA384", PRIMITIVE_SIGNATURE},
    {"1.2.840.10045.4.3.4", "ECDSAWithSHA512", PRIMITIVE_SIGNATURE},

    // EC curves
    {"1.2.840.10045.3.1.7", "prime256v1", PRIMITIVE_ASYMMETRIC_CIPHER},
    {"1.3.132.0.34", "secp384r1", PRIMITIVE_ASYMMETRIC_CIPHER},
    {"1.3.132.0.35", "secp521r1", PRIMITIVE_ASYMMETRIC_CIPHER},
    {"1.3.132.0.10", "secp256k1", PRIMITIVE_ASYMMETRIC_CIPHER},

    // Hash algorithms
    {"1.3.14.3.2.26", "SHA1", PRIMITIVE_HASH_FUNCTION},
    {"2.16.840.1.101.3.4.2.1", "SHA256", PRIMITIVE_HASH_FUNCTION},
    {"2.16.840.1.101.3.4.2.2", "SHA384", PRIMITIVE_HASH_FUNCTION},
    {"2.16.840.1.101.3.4.2.3", "SHA512", PRIMITIVE_HASH_FUNCTION},
    {"2.16.840.1.101.3.4.2.4", "SHA224", PRIMITIVE_HASH_FUNCTION},
    {"1.2.840.113549.2.5", "MD5", PRIMITIVE_HASH_FUNCTION},

    // AES algorithms
    {"2.16.840.1.101.3.4.1.2", "AES-128-CBC", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.6", "AES-128-GCM", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.22", "AES-192-CBC", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.26", "AES-192-GCM", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.42", "AES-256-CBC", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.46", "AES-256-GCM", PRIMITIVE_SYMMETRIC_CIPHER},

    // EdDSA
    {"1.3.101.112", "Ed25519", PRIMITIVE_SIGNATURE},
    {"1.3.101.113", "Ed448", PRIMITIVE_SIGNATURE},

    // X25519/X448 (ECDH)
    {"1.3.101.110", "X25519", PRIMITIVE_KEY_EXCHANGE},
    {"1.3.101.111", "X448", PRIMITIVE_KEY_EXCHANGE},

    // SSH-style algorithm names (for OID lookup)
    {"1.3.101.110", "curve25519-sha256", PRIMITIVE_KEY_EXCHANGE},
    {"1.2.840.113549.1.1.11", "rsa-sha2-256", PRIMITIVE_SIGNATURE},
    {"1.2.840.113549.1.1.13", "rsa-sha2-512", PRIMITIVE_SIGNATURE},
    {"1.2.840.10045.4.3.2", "ecdsa-sha2-nistp256", PRIMITIVE_SIGNATURE},
    {"1.2.840.10045.4.3.3", "ecdsa-sha2-nistp384", PRIMITIVE_SIGNATURE},
    {"1.2.840.10045.4.3.4", "ecdsa-sha2-nistp521", PRIMITIVE_SIGNATURE},

    // ECDH (key exchange) SSH-style names
    {"1.2.840.10045.3.1.7", "ecdh-sha2-nistp256", PRIMITIVE_KEY_EXCHANGE},
    {"1.3.132.0.34", "ecdh-sha2-nistp384", PRIMITIVE_KEY_EXCHANGE},
    {"1.3.132.0.35", "ecdh-sha2-nistp521", PRIMITIVE_KEY_EXCHANGE},

    // AES SSH-style names
    {"2.16.840.1.101.3.4.1.6", "aes128-gcm@openssh.com", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.46", "aes256-gcm@openssh.com", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.2", "aes128-cbc", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.22", "aes192-cbc", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.42", "aes256-cbc", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.1", "aes128-ctr", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.21", "aes192-ctr", PRIMITIVE_SYMMETRIC_CIPHER},
    {"2.16.840.1.101.3.4.1.41", "aes256-ctr", PRIMITIVE_SYMMETRIC_CIPHER},

    // ChaCha20-Poly1305
    {"1.2.840.113549.1.9.16.3.18", "chacha20-poly1305@openssh.com", PRIMITIVE_SYMMETRIC_CIPHER},

    // NIST-finalized Post-Quantum Cryptography (PQC) algorithms
    // Source: NIST FIPS 203, 204, 205 (2024)
    // NOTE: These are draft OIDs pending final NIST assignment

    // Kyber / ML-KEM (Module Lattice Key Encapsulation Mechanism) - FIPS 203
    // Draft OIDs from NIST SP 800-227 (draft)
    {"2.16.840.1.101.3.4.4.1", "ML-KEM-512", PRIMITIVE_KEY_EXCHANGE},
    {"2.16.840.1.101.3.4.4.2", "ML-KEM-768", PRIMITIVE_KEY_EXCHANGE},
    {"2.16.840.1.101.3.4.4.3", "ML-KEM-1024", PRIMITIVE_KEY_EXCHANGE},
    // Legacy Kyber names (NIST Round 3)
    {"1.3.6.1.4.1.2.267.7.4.4", "Kyber-512", PRIMITIVE_KEY_EXCHANGE},
    {"1.3.6.1.4.1.2.267.7.6.5", "Kyber-768", PRIMITIVE_KEY_EXCHANGE},
    {"1.3.6.1.4.1.2.267.7.8.7", "Kyber-1024", PRIMITIVE_KEY_EXCHANGE},

    // Dilithium / ML-DSA (Module Lattice Digital Signature Algorithm) - FIPS 204
    // Draft OIDs from NIST SP 800-208 (draft)
    {"2.16.840.1.101.3.4.3.17", "ML-DSA-44", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.18", "ML-DSA-65", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.19", "ML-DSA-87", PRIMITIVE_SIGNATURE},
    // Legacy Dilithium names (NIST Round 3)
    {"1.3.6.1.4.1.2.267.7.4.4", "Dilithium2", PRIMITIVE_SIGNATURE},
    {"1.3.6.1.4.1.2.267.7.6.5", "Dilithium3", PRIMITIVE_SIGNATURE},
    {"1.3.6.1.4.1.2.267.7.8.7", "Dilithium5", PRIMITIVE_SIGNATURE},

    // SPHINCS+ (Stateless Hash-based Signature Scheme) - FIPS 205
    // Draft OIDs from NIST SP 800-208 (draft)
    {"2.16.840.1.101.3.4.3.20", "SPHINCS+-SHA2-128s", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.21", "SPHINCS+-SHA2-128f", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.22", "SPHINCS+-SHA2-192s", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.23", "SPHINCS+-SHA2-192f", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.24", "SPHINCS+-SHA2-256s", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.25", "SPHINCS+-SHA2-256f", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.26", "SPHINCS+-SHAKE-128s", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.27", "SPHINCS+-SHAKE-128f", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.28", "SPHINCS+-SHAKE-192s", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.29", "SPHINCS+-SHAKE-192f", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.30", "SPHINCS+-SHAKE-256s", PRIMITIVE_SIGNATURE},
    {"2.16.840.1.101.3.4.3.31", "SPHINCS+-SHAKE-256f", PRIMITIVE_SIGNATURE},

    // Falcon (Compact lattice signature) - NIST Round 3 alternate
    // Note: May be finalized in future FIPS standard
    {"1.3.9999.3.6", "Falcon-512", PRIMITIVE_SIGNATURE},
    {"1.3.9999.3.9", "Falcon-1024", PRIMITIVE_SIGNATURE},

    // Hybrid PQC algorithms (experimental - for detection only)
    // X25519 + Kyber768 hybrid (IETF draft-ietf-tls-hybrid-design)
    {"1.3.9999.99.1", "X25519Kyber768Draft00", PRIMITIVE_KEY_EXCHANGE},
    {"1.3.9999.99.2", "SecP256r1Kyber768Draft00", PRIMITIVE_KEY_EXCHANGE},

    {NULL, NULL, PRIMITIVE_UNKNOWN}  // Sentinel
};

// Create algorithm metadata structure
algorithm_granular_t* algorithm_metadata_create(void) {
    algorithm_granular_t* metadata = secure_alloc(sizeof(algorithm_granular_t));
    if (!metadata) return NULL;

    memset(metadata, 0, sizeof(algorithm_granular_t));
    metadata->primitive_type = PRIMITIVE_UNKNOWN;
    metadata->mode_type = MODE_UNKNOWN;
    metadata->padding_type = PADDING_UNKNOWN;
    metadata->quantum_category = QUANTUM_CAT_UNKNOWN;
    metadata->key_len = 0;
    metadata->security_bits = 0;
    metadata->is_pqc_safe = false;
    metadata->is_deprecated = false;

    return metadata;
}

// Destroy algorithm metadata
void algorithm_metadata_destroy(algorithm_granular_t* metadata) {
    if (!metadata) return;

    if (metadata->algorithm_name) free(metadata->algorithm_name);
    if (metadata->primitive) free(metadata->primitive);
    if (metadata->mode) free(metadata->mode);
    if (metadata->padding) free(metadata->padding);
    if (metadata->key_len_str) free(metadata->key_len_str);
    if (metadata->oid) free(metadata->oid);
    if (metadata->parameters) free(metadata->parameters);
    if (metadata->usage_context) free(metadata->usage_context);

    secure_free(metadata, sizeof(algorithm_granular_t));
}

// Map OID to algorithm name
const char* algorithm_oid_to_name(const char* oid) {
    if (!oid) return NULL;

    for (size_t i = 0; oid_mappings[i].oid != NULL; i++) {
        if (strcmp(oid, oid_mappings[i].oid) == 0) {
            return oid_mappings[i].name;
        }
    }

    return NULL;
}

// Map algorithm name to OID
const char* algorithm_name_to_oid(const char* name) {
    if (!name) return NULL;

    for (size_t i = 0; oid_mappings[i].oid != NULL; i++) {
        if (strcasecmp(name, oid_mappings[i].name) == 0) {
            return oid_mappings[i].oid;
        }
    }

    return NULL;
}

// Get primitive type from algorithm name
crypto_primitive_t algorithm_get_primitive_type(const char* algorithm_name) {
    if (!algorithm_name) return PRIMITIVE_UNKNOWN;

    // Check OID mapping table
    for (size_t i = 0; oid_mappings[i].oid != NULL; i++) {
        if (strcasecmp(algorithm_name, oid_mappings[i].name) == 0) {
            return oid_mappings[i].primitive;
        }
    }

    // Pattern matching for common algorithms
    if (strstr(algorithm_name, "RSA")) return PRIMITIVE_SIGNATURE;
    if (strstr(algorithm_name, "ECDSA")) return PRIMITIVE_SIGNATURE;
    if (strstr(algorithm_name, "SHA") || strstr(algorithm_name, "MD")) return PRIMITIVE_HASH_FUNCTION;
    if (strstr(algorithm_name, "AES")) return PRIMITIVE_SYMMETRIC_CIPHER;
    if (strstr(algorithm_name, "Ed25519") || strstr(algorithm_name, "Ed448")) return PRIMITIVE_SIGNATURE;

    return PRIMITIVE_UNKNOWN;
}

// Convert primitive type to string
const char* primitive_type_to_string(crypto_primitive_t type) {
    switch (type) {
        case PRIMITIVE_SYMMETRIC_CIPHER: return "symmetric_cipher";
        case PRIMITIVE_ASYMMETRIC_CIPHER: return "asymmetric_cipher";
        case PRIMITIVE_HASH_FUNCTION: return "hash_function";
        case PRIMITIVE_MAC: return "mac";
        case PRIMITIVE_SIGNATURE: return "signature";
        case PRIMITIVE_KEY_EXCHANGE: return "key_exchange";
        case PRIMITIVE_KDF: return "kdf";
        case PRIMITIVE_RNG: return "rng";
        default: return "unknown";
    }
}

// Convert cipher mode to string
const char* cipher_mode_to_string(cipher_mode_t mode) {
    switch (mode) {
        case MODE_ECB: return "ECB";
        case MODE_CBC: return "CBC";
        case MODE_CTR: return "CTR";
        case MODE_GCM: return "GCM";
        case MODE_CCM: return "CCM";
        case MODE_CFB: return "CFB";
        case MODE_OFB: return "OFB";
        case MODE_XTS: return "XTS";
        case MODE_NONE: return "none";
        default: return "unknown";
    }
}

// Convert padding scheme to string
const char* padding_scheme_to_string(padding_scheme_t padding) {
    switch (padding) {
        case PADDING_PKCS1: return "PKCS1";
        case PADDING_OAEP: return "OAEP";
        case PADDING_PSS: return "PSS";
        case PADDING_PKCS7: return "PKCS7";
        case PADDING_NONE: return "none";
        default: return "unknown";
    }
}

// Convert quantum category to string
const char* quantum_category_to_string(quantum_security_category_t category) {
    switch (category) {
        case QUANTUM_CAT_0: return "0";
        case QUANTUM_CAT_1: return "1";
        case QUANTUM_CAT_2: return "2";
        case QUANTUM_CAT_3: return "3";
        case QUANTUM_CAT_4: return "4";
        case QUANTUM_CAT_5: return "5";
        default: return "unknown";
    }
}

#ifdef __EMSCRIPTEN__

/* WASM: no OpenSSL — X.509 parsing not available */
algorithm_granular_t* algorithm_parse_from_x509_public_key(void* x509_cert) {
    (void)x509_cert;
    return NULL;
}

algorithm_granular_t* algorithm_parse_from_x509_signature(void* x509_cert) {
    (void)x509_cert;
    return NULL;
}

#else /* native Linux */

// Parse algorithm from X.509 public key
algorithm_granular_t* algorithm_parse_from_x509_public_key(void* x509_cert) {
    if (!x509_cert) return NULL;

    X509* cert = (X509*)x509_cert;
    algorithm_granular_t* metadata = algorithm_metadata_create();
    if (!metadata) return NULL;

    // Get public key
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        algorithm_metadata_destroy(metadata);
        return NULL;
    }

    // Get key type
    int key_type = EVP_PKEY_base_id(pkey);

    // Get public key algorithm OID
    char oid_buf[128];
    const X509_ALGOR* pubkey_alg = X509_get0_tbs_sigalg(cert);
    if (pubkey_alg) {
        const ASN1_OBJECT* obj = NULL;
        X509_ALGOR_get0(&obj, NULL, NULL, pubkey_alg);
        if (obj) {
            OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
            metadata->oid = strdup(oid_buf);
        }
    }

    // Parse based on key type
    switch (key_type) {
        case EVP_PKEY_RSA: {
            metadata->primitive = strdup("RSA");
            metadata->primitive_type = PRIMITIVE_SIGNATURE;
            metadata->usage_context = strdup("public_key");

            int key_bits = EVP_PKEY_bits(pkey);
            metadata->key_len = key_bits;

            char key_len_buf[32];
            snprintf(key_len_buf, sizeof(key_len_buf), "%d", key_bits);
            metadata->key_len_str = strdup(key_len_buf);

            char alg_name[64];
            snprintf(alg_name, sizeof(alg_name), "RSA-%d", key_bits);
            metadata->algorithm_name = strdup(alg_name);

            // Calculate security bits (RSA)
            if (key_bits >= 15360) metadata->security_bits = 256;
            else if (key_bits >= 7680) metadata->security_bits = 192;
            else if (key_bits >= 3072) metadata->security_bits = 128;
            else if (key_bits >= 2048) metadata->security_bits = 112;
            else if (key_bits >= 1024) metadata->security_bits = 80;
            else metadata->security_bits = 0;

            metadata->is_deprecated = (key_bits < 2048);
            break;
        }

        case EVP_PKEY_EC: {
            metadata->primitive = strdup("ECDSA");
            metadata->primitive_type = PRIMITIVE_SIGNATURE;
            metadata->usage_context = strdup("public_key");

            int key_bits = EVP_PKEY_bits(pkey);
            metadata->key_len = key_bits;

            char key_len_buf[32];
            snprintf(key_len_buf, sizeof(key_len_buf), "%d", key_bits);
            metadata->key_len_str = strdup(key_len_buf);

            // Get curve name using OpenSSL 3.0 API
            char curve_name_buf[128];
            size_t curve_name_len = sizeof(curve_name_buf);
            if (EVP_PKEY_get_utf8_string_param(pkey, "group", curve_name_buf,
                                                sizeof(curve_name_buf), &curve_name_len) > 0) {
                metadata->parameters = strdup(curve_name_buf);

                char alg_name[256];
                snprintf(alg_name, sizeof(alg_name), "ECDSA-%s", curve_name_buf);
                metadata->algorithm_name = strdup(alg_name);
            }

            if (!metadata->algorithm_name) {
                char alg_name[64];
                snprintf(alg_name, sizeof(alg_name), "ECDSA-P%d", key_bits);
                metadata->algorithm_name = strdup(alg_name);
            }

            // Calculate security bits (ECDSA)
            if (key_bits >= 512) metadata->security_bits = 256;
            else if (key_bits >= 384) metadata->security_bits = 192;
            else if (key_bits >= 256) metadata->security_bits = 128;
            else metadata->security_bits = key_bits / 2;

            metadata->is_deprecated = (key_bits < 256);
            break;
        }

        case EVP_PKEY_ED25519:
            metadata->primitive = strdup("Ed25519");
            metadata->primitive_type = PRIMITIVE_SIGNATURE;
            metadata->usage_context = strdup("public_key");
            metadata->key_len = 256;
            metadata->key_len_str = strdup("256");
            metadata->algorithm_name = strdup("Ed25519");
            metadata->security_bits = 128;
            metadata->oid = strdup("1.3.101.112");
            break;

        case EVP_PKEY_ED448:
            metadata->primitive = strdup("Ed448");
            metadata->primitive_type = PRIMITIVE_SIGNATURE;
            metadata->usage_context = strdup("public_key");
            metadata->key_len = 448;
            metadata->key_len_str = strdup("448");
            metadata->algorithm_name = strdup("Ed448");
            metadata->security_bits = 224;
            metadata->oid = strdup("1.3.101.113");
            break;

        default:
            metadata->primitive = strdup("Unknown");
            metadata->primitive_type = PRIMITIVE_UNKNOWN;
            break;
    }

    EVP_PKEY_free(pkey);
    return metadata;
}

// Parse algorithm from X.509 signature
algorithm_granular_t* algorithm_parse_from_x509_signature(void* x509_cert) {
    if (!x509_cert) return NULL;

    X509* cert = (X509*)x509_cert;
    algorithm_granular_t* metadata = algorithm_metadata_create();
    if (!metadata) return NULL;

    // Get signature algorithm
    const X509_ALGOR* sig_alg = X509_get0_tbs_sigalg(cert);
    if (!sig_alg) {
        algorithm_metadata_destroy(metadata);
        return NULL;
    }

    // Get OID
    const ASN1_OBJECT* alg_obj = NULL;
    X509_ALGOR_get0(&alg_obj, NULL, NULL, sig_alg);
    if (alg_obj) {
        char oid_buf[128];
        OBJ_obj2txt(oid_buf, sizeof(oid_buf), alg_obj, 1);
        metadata->oid = strdup(oid_buf);

        // Map OID to name
        const char* alg_name = algorithm_oid_to_name(oid_buf);
        if (alg_name) {
            metadata->algorithm_name = strdup(alg_name);
            metadata->primitive_type = algorithm_get_primitive_type(alg_name);
        } else {
            int nid = OBJ_obj2nid(alg_obj);
            const char* sn = OBJ_nid2sn(nid);
            if (sn) {
                metadata->algorithm_name = strdup(sn);
                metadata->primitive_type = algorithm_get_primitive_type(sn);
            }
        }
    }

    // Extract primitive and hash from signature algorithm
    if (metadata->algorithm_name) {
        // Parse compound names like "SHA256WithRSAEncryption"
        if (strstr(metadata->algorithm_name, "SHA256") || strstr(metadata->algorithm_name, "sha256")) {
            if (!metadata->primitive) metadata->primitive = strdup("SHA256");
            metadata->security_bits = 128;
        } else if (strstr(metadata->algorithm_name, "SHA384")) {
            if (!metadata->primitive) metadata->primitive = strdup("SHA384");
            metadata->security_bits = 192;
        } else if (strstr(metadata->algorithm_name, "SHA512")) {
            if (!metadata->primitive) metadata->primitive = strdup("SHA512");
            metadata->security_bits = 256;
        } else if (strstr(metadata->algorithm_name, "SHA1")) {
            if (!metadata->primitive) metadata->primitive = strdup("SHA1");
            metadata->security_bits = 80;
            metadata->is_deprecated = true;
        } else if (strstr(metadata->algorithm_name, "MD5")) {
            if (!metadata->primitive) metadata->primitive = strdup("MD5");
            metadata->security_bits = 0;
            metadata->is_deprecated = true;
        } else if (strstr(metadata->algorithm_name, "RSA")) {
            if (!metadata->primitive) metadata->primitive = strdup("RSA");
        } else if (strstr(metadata->algorithm_name, "ECDSA")) {
            if (!metadata->primitive) metadata->primitive = strdup("ECDSA");
        }
    }

    metadata->usage_context = strdup("signature");
    metadata->primitive_type = PRIMITIVE_SIGNATURE;

    return metadata;
}

#endif /* __EMSCRIPTEN__ */

// Parse algorithm from OID
algorithm_granular_t* algorithm_parse_from_oid(const char* oid) {
    if (!oid) return NULL;

    algorithm_granular_t* metadata = algorithm_metadata_create();
    if (!metadata) return NULL;

    metadata->oid = strdup(oid);

    const char* alg_name = algorithm_oid_to_name(oid);
    if (alg_name) {
        metadata->algorithm_name = strdup(alg_name);
        metadata->primitive_type = algorithm_get_primitive_type(alg_name);
        metadata->primitive = strdup(alg_name);
    } else {
#ifndef __EMSCRIPTEN__
        // Try OpenSSL OBJ lookup
        ASN1_OBJECT* obj = OBJ_txt2obj(oid, 1);
        if (obj) {
            int nid = OBJ_obj2nid(obj);
            const char* sn = OBJ_nid2sn(nid);
            if (sn) {
                metadata->algorithm_name = strdup(sn);
                metadata->primitive = strdup(sn);
            }
            ASN1_OBJECT_free(obj);
        }
#endif
    }

    return metadata;
}

// Calculate security strength in bits (NIST SP 800-57 Part 1)
int algorithm_calculate_security_bits(const algorithm_granular_t* metadata) {
    if (!metadata) return 0;

    // If already calculated, return it
    if (metadata->security_bits > 0) {
        return metadata->security_bits;
    }

    // Calculate based on primitive type and key length
    switch (metadata->primitive_type) {
        case PRIMITIVE_SYMMETRIC_CIPHER:
            return metadata->key_len;  // Symmetric key length = security bits

        case PRIMITIVE_SIGNATURE:
        case PRIMITIVE_ASYMMETRIC_CIPHER:
            // RSA/DH key length mapping
            if (metadata->key_len >= 15360) return 256;
            if (metadata->key_len >= 7680) return 192;
            if (metadata->key_len >= 3072) return 128;
            if (metadata->key_len >= 2048) return 112;
            if (metadata->key_len >= 1024) return 80;
            // ECC: security bits ~= key_len/2
            if (metadata->key_len < 512) return metadata->key_len / 2;
            return metadata->key_len;

        case PRIMITIVE_HASH_FUNCTION:
            // Hash output length (simplified)
            if (strstr(metadata->algorithm_name, "512")) return 256;
            if (strstr(metadata->algorithm_name, "384")) return 192;
            if (strstr(metadata->algorithm_name, "256")) return 128;
            if (strstr(metadata->algorithm_name, "224")) return 112;
            if (strstr(metadata->algorithm_name, "1")) return 80;  // SHA-1
            return 0;  // MD5 and weaker

        default:
            return 0;
    }
}

// Get quantum security category (NIST IR 8413)
quantum_security_category_t algorithm_get_quantum_category(const algorithm_granular_t* metadata) {
    if (!metadata) return QUANTUM_CAT_UNKNOWN;

    int security_bits = metadata->security_bits > 0 ?
                        metadata->security_bits :
                        algorithm_calculate_security_bits(metadata);

    // Map classical security bits to quantum categories
    if (security_bits >= 256) return QUANTUM_CAT_5;
    if (security_bits >= 192) return QUANTUM_CAT_3;
    if (security_bits >= 128) return QUANTUM_CAT_1;
    if (security_bits >= 112) return QUANTUM_CAT_1;  // Minimum acceptable
    return QUANTUM_CAT_0;  // Broken or deprecated
}

// Check if algorithm is PQC-safe
bool algorithm_is_pqc_safe(const algorithm_granular_t* metadata) {
    if (!metadata || !metadata->algorithm_name) return false;

    // Only NIST-finalized PQC algorithms are considered safe
    if (strstr(metadata->algorithm_name, "Kyber")) return true;
    if (strstr(metadata->algorithm_name, "Dilithium")) return true;
    if (strstr(metadata->algorithm_name, "SPHINCS+")) return true;

    // Symmetric ciphers with >= 256-bit keys are quantum-resistant
    if (metadata->primitive_type == PRIMITIVE_SYMMETRIC_CIPHER && metadata->key_len >= 256) {
        return true;
    }

    // Hash functions with >= 256-bit output are quantum-resistant
    if (metadata->primitive_type == PRIMITIVE_HASH_FUNCTION && metadata->key_len >= 256) {
        return true;
    }

    return false;
}

// Check if algorithm is deprecated
bool algorithm_is_deprecated(const algorithm_granular_t* metadata) {
    if (!metadata) return false;

    // If already marked, return it
    if (metadata->is_deprecated) return true;

    if (!metadata->algorithm_name) return false;

    // Deprecated hash algorithms
    if (strstr(metadata->algorithm_name, "MD5")) return true;
    if (strstr(metadata->algorithm_name, "SHA1") || strstr(metadata->algorithm_name, "SHA-1")) return true;

    // Deprecated ciphers
    if (strstr(metadata->algorithm_name, "DES") && !strstr(metadata->algorithm_name, "AES")) return true;
    if (strstr(metadata->algorithm_name, "RC4")) return true;

    // Weak RSA keys
    if (metadata->primitive_type == PRIMITIVE_SIGNATURE &&
        strstr(metadata->algorithm_name, "RSA") &&
        metadata->key_len < 2048) return true;

    // Weak ECC keys
    if (metadata->primitive_type == PRIMITIVE_SIGNATURE &&
        (strstr(metadata->algorithm_name, "ECDSA") || strstr(metadata->algorithm_name, "EC")) &&
        metadata->key_len < 256) return true;

    return false;
}

// Export algorithm metadata as JSON properties array
void* algorithm_to_json_properties(const algorithm_granular_t* metadata) {
    if (!metadata) return NULL;

    json_object* properties = json_object_new_array();

    // Add all granular fields as properties
    if (metadata->primitive) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:primitive"));
        json_object_object_add(prop, "value", json_object_new_string(metadata->primitive));
        json_object_array_add(properties, prop);
    }

    if (metadata->mode) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:mode"));
        json_object_object_add(prop, "value", json_object_new_string(metadata->mode));
        json_object_array_add(properties, prop);
    }

    if (metadata->padding) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:padding"));
        json_object_object_add(prop, "value", json_object_new_string(metadata->padding));
        json_object_array_add(properties, prop);
    }

    if (metadata->key_len > 0) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:key_length"));
        json_object_object_add(prop, "value", json_object_new_string(metadata->key_len_str ?
                                                                      metadata->key_len_str : "0"));
        json_object_array_add(properties, prop);
    }

    if (metadata->oid) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:oid"));
        json_object_object_add(prop, "value", json_object_new_string(metadata->oid));
        json_object_array_add(properties, prop);
    }

    if (metadata->security_bits > 0) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:security_bits"));
        char bits_str[32];
        snprintf(bits_str, sizeof(bits_str), "%d", metadata->security_bits);
        json_object_object_add(prop, "value", json_object_new_string(bits_str));
        json_object_array_add(properties, prop);
    }

    if (metadata->parameters) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:parameters"));
        json_object_object_add(prop, "value", json_object_new_string(metadata->parameters));
        json_object_array_add(properties, prop);
    }

    // Add quantum category
    quantum_security_category_t q_cat = algorithm_get_quantum_category(metadata);
    if (q_cat != QUANTUM_CAT_UNKNOWN) {
        json_object* prop = json_object_new_object();
        json_object_object_add(prop, "name", json_object_new_string("cbom:algo:quantum_category"));
        json_object_object_add(prop, "value", json_object_new_string(quantum_category_to_string(q_cat)));
        json_object_array_add(properties, prop);
    }

    // Add PQC safety and deprecation status
    json_object* pqc_prop = json_object_new_object();
    json_object_object_add(pqc_prop, "name", json_object_new_string("cbom:algo:pqc_safe"));
    json_object_object_add(pqc_prop, "value",
                          json_object_new_string(algorithm_is_pqc_safe(metadata) ? "true" : "false"));
    json_object_array_add(properties, pqc_prop);

    json_object* deprecated_prop = json_object_new_object();
    json_object_object_add(deprecated_prop, "name", json_object_new_string("cbom:algo:deprecated"));
    json_object_object_add(deprecated_prop, "value",
                          json_object_new_string(algorithm_is_deprecated(metadata) ? "true" : "false"));
    json_object_array_add(properties, deprecated_prop);

    return properties;
}

// ============================================================================
// CycloneDX algorithmProperties support (Phase 1 - Algorithm Properties Enhancement)
// ============================================================================

// Static crypto function arrays (NULL-terminated)
static const char* FUNCS_SIGNATURE[] = {"sign", "verify", NULL};
static const char* FUNCS_PKE[] = {"sign", "verify", "encrypt", "decrypt", NULL};
static const char* FUNCS_ENCRYPT_ONLY[] = {"encrypt", "decrypt", NULL};
static const char* FUNCS_HASH[] = {"digest", NULL};
static const char* FUNCS_AE[] = {"encrypt", "decrypt", NULL};
static const char* FUNCS_KEY_AGREE[] = {"derive", NULL};
static const char* FUNCS_MAC[] = {"tag", NULL};
static const char* FUNCS_KEM[] = {"encapsulate", "decapsulate", NULL};
static const char* FUNCS_KEYGEN[] = {"generate", "keygen", NULL};

// Comprehensive CycloneDX algorithm properties lookup table
// This table maps algorithm names to CycloneDX algorithmProperties
// Format: {name, family, primitive, mode, padding, curve, functions, key_size, security_bits, quantum_level, cert_level, context}
static const algorithm_cdx_properties_t CDX_ALGORITHM_TABLE[] = {
    // ========== RSA Algorithms (context-dependent) ==========
    // RSA for certificate signatures
    {"RSA-1024", "RSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 1024, 80, 0, "none", ALGO_CONTEXT_CERTIFICATE_SIGNATURE},
    {"RSA-2048", "RSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 2048, 112, 0, "none", ALGO_CONTEXT_CERTIFICATE_SIGNATURE},
    {"RSA-3072", "RSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 3072, 128, 0, "none", ALGO_CONTEXT_CERTIFICATE_SIGNATURE},
    {"RSA-4096", "RSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 4096, 152, 0, "none", ALGO_CONTEXT_CERTIFICATE_SIGNATURE},

    // RSA for key encryption (PKE - Public Key Encryption)
    {"RSA-1024", "RSA", "pke", NULL, NULL, NULL, FUNCS_ENCRYPT_ONLY, 1024, 80, 0, "none", ALGO_CONTEXT_KEY_ENCRYPTION},
    {"RSA-2048", "RSA", "pke", NULL, NULL, NULL, FUNCS_ENCRYPT_ONLY, 2048, 112, 0, "none", ALGO_CONTEXT_KEY_ENCRYPTION},
    {"RSA-3072", "RSA", "pke", NULL, NULL, NULL, FUNCS_ENCRYPT_ONLY, 3072, 128, 0, "none", ALGO_CONTEXT_KEY_ENCRYPTION},
    {"RSA-4096", "RSA", "pke", NULL, NULL, NULL, FUNCS_ENCRYPT_ONLY, 4096, 152, 0, "none", ALGO_CONTEXT_KEY_ENCRYPTION},

    // RSA general purpose (all functions)
    {"RSA-1024", "RSA", "pke", NULL, NULL, NULL, FUNCS_PKE, 1024, 80, 0, "none", ALGO_CONTEXT_GENERAL},
    {"RSA-2048", "RSA", "pke", NULL, NULL, NULL, FUNCS_PKE, 2048, 112, 0, "none", ALGO_CONTEXT_GENERAL},
    {"RSA-3072", "RSA", "pke", NULL, NULL, NULL, FUNCS_PKE, 3072, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"RSA-4096", "RSA", "pke", NULL, NULL, NULL, FUNCS_PKE, 4096, 152, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== ECDSA Algorithms ==========
    {"ECDSA-P256", "ECDSA", "signature", NULL, NULL, "P-256", FUNCS_SIGNATURE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDSA-P384", "ECDSA", "signature", NULL, NULL, "P-384", FUNCS_SIGNATURE, 384, 192, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDSA-P521", "ECDSA", "signature", NULL, NULL, "P-521", FUNCS_SIGNATURE, 521, 256, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDSA-prime256v1", "ECDSA", "signature", NULL, NULL, "P-256", FUNCS_SIGNATURE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDSA-secp384r1", "ECDSA", "signature", NULL, NULL, "P-384", FUNCS_SIGNATURE, 384, 192, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDSA-secp521r1", "ECDSA", "signature", NULL, NULL, "P-521", FUNCS_SIGNATURE, 521, 256, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== EdDSA Algorithms ==========
    {"Ed25519", "EdDSA", "signature", NULL, NULL, "curve25519", FUNCS_SIGNATURE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"Ed448", "EdDSA", "signature", NULL, NULL, "curve448", FUNCS_SIGNATURE, 448, 224, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== Hash Algorithms ==========
    {"SHA-1", "SHA-1", "hash", NULL, NULL, NULL, FUNCS_HASH, 160, 80, 0, "none", ALGO_CONTEXT_GENERAL},
    {"SHA-224", "SHA-2", "hash", NULL, NULL, NULL, FUNCS_HASH, 224, 112, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SHA-256", "SHA-2", "hash", NULL, NULL, NULL, FUNCS_HASH, 256, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SHA-384", "SHA-2", "hash", NULL, NULL, NULL, FUNCS_HASH, 384, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"SHA-512", "SHA-2", "hash", NULL, NULL, NULL, FUNCS_HASH, 512, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"SHA3-224", "SHA-3", "hash", NULL, NULL, NULL, FUNCS_HASH, 224, 112, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SHA3-256", "SHA-3", "hash", NULL, NULL, NULL, FUNCS_HASH, 256, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SHA3-384", "SHA-3", "hash", NULL, NULL, NULL, FUNCS_HASH, 384, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"SHA3-512", "SHA-3", "hash", NULL, NULL, NULL, FUNCS_HASH, 512, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"MD5", "MD5", "hash", NULL, NULL, NULL, FUNCS_HASH, 128, 0, 0, "none", ALGO_CONTEXT_GENERAL},
    {"BLAKE2b", "BLAKE2", "hash", NULL, NULL, NULL, FUNCS_HASH, 512, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"BLAKE2s", "BLAKE2", "hash", NULL, NULL, NULL, FUNCS_HASH, 256, 128, 1, "none", ALGO_CONTEXT_GENERAL},

    // ========== Authenticated Encryption (AE) ==========
    {"AES-128-GCM", "AES", "ae", "gcm", NULL, NULL, FUNCS_AE, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"AES-192-GCM", "AES", "ae", "gcm", NULL, NULL, FUNCS_AE, 192, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"AES-256-GCM", "AES", "ae", "gcm", NULL, NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"AES-128-CCM", "AES", "ae", "ccm", NULL, NULL, FUNCS_AE, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"AES-256-CCM", "AES", "ae", "ccm", NULL, NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"ChaCha20-Poly1305", "ChaCha20-Poly1305", "ae", NULL, NULL, NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},

    // ========== Block Ciphers ==========
    {"AES-128-CBC", "AES", "block-cipher", "cbc", "pkcs7", NULL, FUNCS_AE, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"AES-192-CBC", "AES", "block-cipher", "cbc", "pkcs7", NULL, FUNCS_AE, 192, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"AES-256-CBC", "AES", "block-cipher", "cbc", "pkcs7", NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"AES-128-CTR", "AES", "block-cipher", "ctr", NULL, NULL, FUNCS_AE, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"AES-256-CTR", "AES", "block-cipher", "ctr", NULL, NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"AES-128-ECB", "AES", "block-cipher", "ecb", "pkcs7", NULL, FUNCS_AE, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"AES-256-ECB", "AES", "block-cipher", "ecb", "pkcs7", NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"3DES-CBC", "3DES", "block-cipher", "cbc", "pkcs7", NULL, FUNCS_AE, 168, 112, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DES-CBC", "DES", "block-cipher", "cbc", "pkcs7", NULL, FUNCS_AE, 56, 56, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== Stream Ciphers ==========
    {"ChaCha20", "ChaCha20", "stream-cipher", NULL, NULL, NULL, FUNCS_AE, 256, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"RC4", "RC4", "stream-cipher", NULL, NULL, NULL, FUNCS_AE, 128, 0, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== Key Agreement ==========
    {"ECDH-P256", "ECDH", "key-agree", NULL, NULL, "P-256", FUNCS_KEY_AGREE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDH-P384", "ECDH", "key-agree", NULL, NULL, "P-384", FUNCS_KEY_AGREE, 384, 192, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDH-P521", "ECDH", "key-agree", NULL, NULL, "P-521", FUNCS_KEY_AGREE, 521, 256, 0, "none", ALGO_CONTEXT_GENERAL},
    {"X25519", "ECDH", "key-agree", NULL, NULL, "curve25519", FUNCS_KEY_AGREE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"X448", "ECDH", "key-agree", NULL, NULL, "curve448", FUNCS_KEY_AGREE, 448, 224, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DH-2048", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 2048, 112, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DH-3072", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 3072, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DH-4096", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 4096, 152, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ECDHE", "ECDH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 0, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DHE", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 0, 112, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== MAC Algorithms ==========
    {"HMAC-SHA1", "HMAC", "mac", NULL, NULL, NULL, FUNCS_MAC, 160, 80, 0, "none", ALGO_CONTEXT_GENERAL},
    {"HMAC-SHA256", "HMAC", "mac", NULL, NULL, NULL, FUNCS_MAC, 256, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"HMAC-SHA384", "HMAC", "mac", NULL, NULL, NULL, FUNCS_MAC, 384, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"HMAC-SHA512", "HMAC", "mac", NULL, NULL, NULL, FUNCS_MAC, 512, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"CMAC-AES", "CMAC", "mac", NULL, NULL, NULL, FUNCS_MAC, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"Poly1305", "Poly1305", "mac", NULL, NULL, NULL, FUNCS_MAC, 128, 128, 1, "none", ALGO_CONTEXT_GENERAL},

    // ========== KDF Algorithms ==========
    {"PBKDF2", "PBKDF2", "kdf", NULL, NULL, NULL, FUNCS_KEYGEN, 0, 0, 0, "none", ALGO_CONTEXT_GENERAL},
    {"HKDF", "HKDF", "kdf", NULL, NULL, NULL, FUNCS_KEYGEN, 0, 0, 0, "none", ALGO_CONTEXT_GENERAL},
    {"scrypt", "scrypt", "kdf", NULL, NULL, NULL, FUNCS_KEYGEN, 0, 0, 0, "none", ALGO_CONTEXT_GENERAL},
    {"Argon2", "Argon2", "kdf", NULL, NULL, NULL, FUNCS_KEYGEN, 0, 0, 0, "none", ALGO_CONTEXT_GENERAL},

    // ========== PQC - ML-KEM (Kyber) ==========
    {"ML-KEM-512", "ML-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"ML-KEM-768", "ML-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"ML-KEM-1024", "ML-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"Kyber-512", "ML-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"Kyber-768", "ML-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"Kyber-1024", "ML-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},

    // ========== PQC - ML-DSA (Dilithium) ==========
    {"ML-DSA-44", "ML-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"ML-DSA-65", "ML-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"ML-DSA-87", "ML-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"Dilithium2", "ML-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"Dilithium3", "ML-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"Dilithium5", "ML-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},

    // ========== PQC - SLH-DSA (SPHINCS+) ==========
    {"SLH-DSA-SHA2-128s", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SLH-DSA-SHA2-128f", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SLH-DSA-SHA2-192s", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"SLH-DSA-SHA2-192f", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"SLH-DSA-SHA2-256s", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"SLH-DSA-SHA2-256f", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"SPHINCS+-SHA2-128s", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SPHINCS+-SHA2-128f", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"SPHINCS+-SHA2-192s", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"SPHINCS+-SHA2-192f", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"SPHINCS+-SHA2-256s", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"SPHINCS+-SHA2-256f", "SLH-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},

    // ========== PQC - FN-DSA (Falcon) ==========
    {"FN-DSA-512", "FN-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"FN-DSA-1024", "FN-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},
    {"Falcon-512", "FN-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 128, 1, "none", ALGO_CONTEXT_GENERAL},
    {"Falcon-1024", "FN-DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 0, 256, 5, "none", ALGO_CONTEXT_GENERAL},

    // ========== Hybrid PQC ==========
    {"X25519Kyber768", "Hybrid-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},
    {"P256Kyber768", "Hybrid-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},

    // ========== SSH KEX Algorithms ==========
    {"curve25519-sha256", "ECDH", "key-agree", NULL, NULL, "curve25519", FUNCS_KEY_AGREE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"curve25519-sha256@libssh.org", "ECDH", "key-agree", NULL, NULL, "curve25519", FUNCS_KEY_AGREE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ecdh-sha2-nistp256", "ECDH", "key-agree", NULL, NULL, "P-256", FUNCS_KEY_AGREE, 256, 128, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ecdh-sha2-nistp384", "ECDH", "key-agree", NULL, NULL, "P-384", FUNCS_KEY_AGREE, 384, 192, 0, "none", ALGO_CONTEXT_GENERAL},
    {"ecdh-sha2-nistp521", "ECDH", "key-agree", NULL, NULL, "P-521", FUNCS_KEY_AGREE, 521, 256, 0, "none", ALGO_CONTEXT_GENERAL},
    {"diffie-hellman-group14-sha256", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 2048, 112, 0, "none", ALGO_CONTEXT_GENERAL},
    {"diffie-hellman-group16-sha512", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 4096, 152, 0, "none", ALGO_CONTEXT_GENERAL},
    {"diffie-hellman-group18-sha512", "DH", "key-agree", NULL, NULL, NULL, FUNCS_KEY_AGREE, 8192, 192, 0, "none", ALGO_CONTEXT_GENERAL},
    {"sntrup761x25519-sha512@openssh.com", "Hybrid-KEM", "kem", NULL, NULL, NULL, FUNCS_KEM, 0, 192, 3, "none", ALGO_CONTEXT_GENERAL},

    // ========== DSA (legacy) ==========
    {"DSA-1024", "DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 1024, 80, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DSA-2048", "DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 2048, 112, 0, "none", ALGO_CONTEXT_GENERAL},
    {"DSA-3072", "DSA", "signature", NULL, NULL, NULL, FUNCS_SIGNATURE, 3072, 128, 0, "none", ALGO_CONTEXT_GENERAL},

    // Sentinel
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, NULL, ALGO_CONTEXT_UNKNOWN}
};

// Algorithm name variant mappings for normalization
typedef struct {
    const char* variant;
    const char* canonical;
} algo_name_variant_t;

static const algo_name_variant_t NAME_VARIANTS[] = {
    // RSA variants
    {"RSA", "RSA-2048"},
    {"rsaEncryption", "RSA-2048"},
    {"RSA2048", "RSA-2048"},
    {"RSA4096", "RSA-4096"},
    {"RSA3072", "RSA-3072"},
    {"RSA1024", "RSA-1024"},

    // SHA variants
    {"SHA256", "SHA-256"},
    {"SHA384", "SHA-384"},
    {"SHA512", "SHA-512"},
    {"SHA224", "SHA-224"},
    {"SHA1", "SHA-1"},
    {"sha256", "SHA-256"},
    {"sha384", "SHA-384"},
    {"sha512", "SHA-512"},
    {"sha256WithRSAEncryption", "SHA-256"},
    {"sha384WithRSAEncryption", "SHA-384"},
    {"sha512WithRSAEncryption", "SHA-512"},
    {"SHA256WithRSAEncryption", "SHA-256"},
    {"SHA384WithRSAEncryption", "SHA-384"},
    {"SHA512WithRSAEncryption", "SHA-512"},

    // AES variants
    {"AES256GCM", "AES-256-GCM"},
    {"AES128GCM", "AES-128-GCM"},
    {"aes-256-gcm", "AES-256-GCM"},
    {"aes-128-gcm", "AES-128-GCM"},
    {"AES256CBC", "AES-256-CBC"},
    {"AES128CBC", "AES-128-CBC"},
    {"aes-256-cbc", "AES-256-CBC"},
    {"aes-128-cbc", "AES-128-CBC"},

    // ECDSA variants
    {"ECDSA", "ECDSA-P256"},
    {"ecdsaWithSHA256", "ECDSA-P256"},
    {"ecdsaWithSHA384", "ECDSA-P384"},
    {"ecdsa-with-SHA256", "ECDSA-P256"},
    {"ecdsa-with-SHA384", "ECDSA-P384"},

    // EC curve variants
    {"prime256v1", "ECDSA-P256"},
    {"secp384r1", "ECDSA-P384"},
    {"secp521r1", "ECDSA-P521"},
    {"P-256", "ECDSA-P256"},
    {"P-384", "ECDSA-P384"},
    {"P-521", "ECDSA-P521"},

    // HMAC variants
    {"HMAC-SHA-256", "HMAC-SHA256"},
    {"HMAC-SHA-384", "HMAC-SHA384"},
    {"HMAC-SHA-512", "HMAC-SHA512"},
    {"hmac-sha256", "HMAC-SHA256"},
    {"hmac-sha384", "HMAC-SHA384"},

    // PQC legacy names
    {"Kyber512", "Kyber-512"},
    {"Kyber768", "Kyber-768"},
    {"Kyber1024", "Kyber-1024"},

    {NULL, NULL}  // Sentinel
};

// Normalize algorithm name to canonical form
int algorithm_normalize_name(const char* input, char* output, size_t output_len) {
    if (!input || !output || output_len == 0) return -1;

    // First check variant mappings
    for (size_t i = 0; NAME_VARIANTS[i].variant != NULL; i++) {
        if (strcasecmp(input, NAME_VARIANTS[i].variant) == 0) {
            strncpy(output, NAME_VARIANTS[i].canonical, output_len - 1);
            output[output_len - 1] = '\0';
            return 0;
        }
    }

    // If no variant match, try to extract key size and normalize format
    char normalized[256];
    strncpy(normalized, input, sizeof(normalized) - 1);
    normalized[sizeof(normalized) - 1] = '\0';

    // Convert to uppercase for comparison
    for (char* p = normalized; *p; p++) {
        if (*p >= 'a' && *p <= 'z') {
            *p = *p - 'a' + 'A';
        }
    }

    // Check if already in canonical form in the table
    for (size_t i = 0; CDX_ALGORITHM_TABLE[i].algorithm_name != NULL; i++) {
        if (strcasecmp(normalized, CDX_ALGORITHM_TABLE[i].algorithm_name) == 0) {
            strncpy(output, CDX_ALGORITHM_TABLE[i].algorithm_name, output_len - 1);
            output[output_len - 1] = '\0';
            return 0;
        }
    }

    // Return input as-is if no normalization found
    strncpy(output, input, output_len - 1);
    output[output_len - 1] = '\0';
    return 0;
}

// Get CycloneDX algorithm properties for a given algorithm name
const algorithm_cdx_properties_t* algorithm_get_cdx_properties(
    const char* algo_name,
    algorithm_context_t context
) {
    if (!algo_name) return NULL;

    // Normalize the algorithm name
    char normalized[256];
    algorithm_normalize_name(algo_name, normalized, sizeof(normalized));

    // First pass: look for exact match with context
    for (size_t i = 0; CDX_ALGORITHM_TABLE[i].algorithm_name != NULL; i++) {
        if (strcasecmp(normalized, CDX_ALGORITHM_TABLE[i].algorithm_name) == 0) {
            // For context-dependent algorithms (RSA), match context
            if (CDX_ALGORITHM_TABLE[i].context == context ||
                CDX_ALGORITHM_TABLE[i].context == ALGO_CONTEXT_GENERAL) {
                return &CDX_ALGORITHM_TABLE[i];
            }
        }
    }

    // Second pass: look for any match (fallback to GENERAL context)
    for (size_t i = 0; CDX_ALGORITHM_TABLE[i].algorithm_name != NULL; i++) {
        if (strcasecmp(normalized, CDX_ALGORITHM_TABLE[i].algorithm_name) == 0) {
            return &CDX_ALGORITHM_TABLE[i];
        }
    }

    // Third pass: pattern matching for algorithms with size in name
    // Extract base algorithm and key size from name like "RSA-2048" or "AES-256-GCM"
    char base_algo[64] = {0};
    int key_size = 0;

    // Try to parse common patterns
    if (sscanf(normalized, "RSA-%d", &key_size) == 1 ||
        sscanf(normalized, "RSA%d", &key_size) == 1) {
        snprintf(base_algo, sizeof(base_algo), "RSA-%d", key_size);
    } else if (sscanf(normalized, "AES-%d-GCM", &key_size) == 1 ||
               sscanf(normalized, "AES%dGCM", &key_size) == 1) {
        snprintf(base_algo, sizeof(base_algo), "AES-%d-GCM", key_size);
    } else if (sscanf(normalized, "AES-%d-CBC", &key_size) == 1 ||
               sscanf(normalized, "AES%dCBC", &key_size) == 1) {
        snprintf(base_algo, sizeof(base_algo), "AES-%d-CBC", key_size);
    }

    if (base_algo[0] != '\0') {
        for (size_t i = 0; CDX_ALGORITHM_TABLE[i].algorithm_name != NULL; i++) {
            if (strcasecmp(base_algo, CDX_ALGORITHM_TABLE[i].algorithm_name) == 0) {
                if (CDX_ALGORITHM_TABLE[i].context == context ||
                    CDX_ALGORITHM_TABLE[i].context == ALGO_CONTEXT_GENERAL) {
                    return &CDX_ALGORITHM_TABLE[i];
                }
            }
        }
    }

    // Log unknown algorithm for future enhancement tracking
    // fprintf(stderr, "DEBUG: Unknown algorithm '%s' (normalized: '%s') - no CDX properties\n",
    //         algo_name, normalized);

    return NULL;  // Unknown algorithm
}

// Get CycloneDX algorithmProperties as JSON string
char* algorithm_get_cdx_properties_json(const char* algo_name, algorithm_context_t context) {
    const algorithm_cdx_properties_t* props = algorithm_get_cdx_properties(algo_name, context);
    if (!props) return NULL;

    json_object* obj = json_object_new_object();
    if (!obj) return NULL;

    // Add algorithm_family (NEW: Phase 1)
    if (props->algorithm_family) {
        json_object_object_add(obj, "algorithm_family",
            json_object_new_string(props->algorithm_family));
    }

    // Add primitive (required)
    if (props->cdx_primitive) {
        json_object_object_add(obj, "cdx_primitive",
            json_object_new_string(props->cdx_primitive));
    }

    // Add mode (optional)
    if (props->mode) {
        json_object_object_add(obj, "mode",
            json_object_new_string(props->mode));
    }

    // Add padding (optional)
    if (props->padding) {
        json_object_object_add(obj, "padding",
            json_object_new_string(props->padding));
    }

    // Add curve (optional)
    if (props->curve) {
        json_object_object_add(obj, "curve",
            json_object_new_string(props->curve));
    }

    // Add crypto_functions array
    if (props->crypto_functions) {
        json_object* funcs = json_object_new_array();
        for (int i = 0; props->crypto_functions[i] != NULL; i++) {
            json_object_array_add(funcs,
                json_object_new_string(props->crypto_functions[i]));
        }
        json_object_object_add(obj, "crypto_functions", funcs);
    }

    // Add security_bits
    if (props->security_bits > 0) {
        json_object_object_add(obj, "security_strength_bits",
            json_object_new_int(props->security_bits));
    }

    // Add nist_quantum_security_level (NEW: Phase 1)
    json_object_object_add(obj, "nist_quantum_security_level",
        json_object_new_int(props->nist_quantum_security_level));

    // Add certification_level (NEW: Phase 1)
    if (props->certification_level) {
        json_object_object_add(obj, "certification_level",
            json_object_new_string(props->certification_level));
    }

    // Add OID from mapping table (NEW: Phase 1)
    const char* oid = algorithm_name_to_oid(algo_name);
    if (oid) {
        json_object_object_add(obj, "oid", json_object_new_string(oid));
    }

    const char* json_str = json_object_to_json_string(obj);
    char* result = strdup(json_str);
    json_object_put(obj);

    return result;
}

// Populate metadata_json with CycloneDX algorithmProperties
char* algorithm_populate_cdx_metadata(const char* existing_metadata,
                                       const char* algo_name,
                                       algorithm_context_t context) {
    const algorithm_cdx_properties_t* props = algorithm_get_cdx_properties(algo_name, context);

    // Create or parse existing metadata
    json_object* obj = NULL;
    if (existing_metadata && strlen(existing_metadata) > 0) {
        obj = json_tokener_parse(existing_metadata);
    }
    if (!obj) {
        obj = json_object_new_object();
    }
    if (!obj) return NULL;

    // Add CDX properties if found
    if (props) {
        // Add algorithm_family (NEW: Phase 1)
        if (props->algorithm_family) {
            json_object_object_add(obj, "algorithm_family",
                json_object_new_string(props->algorithm_family));
        }

        // Add primitive
        if (props->cdx_primitive) {
            json_object_object_add(obj, "cdx_primitive",
                json_object_new_string(props->cdx_primitive));
        }

        // Add mode
        if (props->mode) {
            json_object_object_add(obj, "mode",
                json_object_new_string(props->mode));
        }

        // Add padding
        if (props->padding) {
            json_object_object_add(obj, "padding",
                json_object_new_string(props->padding));
        }

        // Add curve
        if (props->curve) {
            json_object_object_add(obj, "curve",
                json_object_new_string(props->curve));
        }

        // Add crypto_functions array
        if (props->crypto_functions) {
            json_object* funcs = json_object_new_array();
            for (int i = 0; props->crypto_functions[i] != NULL; i++) {
                json_object_array_add(funcs,
                    json_object_new_string(props->crypto_functions[i]));
            }
            json_object_object_add(obj, "crypto_functions", funcs);
        }

        // Add security_bits
        if (props->security_bits > 0) {
            json_object_object_add(obj, "security_strength_bits",
                json_object_new_int(props->security_bits));
        }

        // Add nist_quantum_security_level (NEW: Phase 1)
        json_object_object_add(obj, "nist_quantum_security_level",
            json_object_new_int(props->nist_quantum_security_level));

        // Add certification_level (NEW: Phase 1)
        if (props->certification_level) {
            json_object_object_add(obj, "certification_level",
                json_object_new_string(props->certification_level));
        }

        // Add OID from mapping table (NEW: Phase 1)
        const char* oid = algorithm_name_to_oid(algo_name);
        if (oid) {
            json_object_object_add(obj, "oid", json_object_new_string(oid));
        }
    }

    const char* json_str = json_object_to_json_string(obj);
    char* result = strdup(json_str);
    json_object_put(obj);

    return result;
}
