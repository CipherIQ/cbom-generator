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

#include "crypto_parser_interface.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * OpenSSL crypto parser backend.
 *
 * Implements the crypto_parser_ops_t interface using OpenSSL.
 * This provides the foundation for Phase 2 where the WASM build
 * will swap in a pkijs-based JavaScript bridge with the same interface.
 */

/* Helper: extract X509 subject as one-line string */
static char* x509_get_subject_oneline(X509* cert) {
    X509_NAME* name = X509_get_subject_name(cert);
    if (!name) return NULL;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;

    X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);

    char* data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    char* result = NULL;
    if (len > 0 && data) {
        result = strndup(data, (size_t)len);
    }
    BIO_free(bio);
    return result;
}

/* Helper: extract X509 issuer as one-line string */
static char* x509_get_issuer_oneline(X509* cert) {
    X509_NAME* name = X509_get_issuer_name(cert);
    if (!name) return NULL;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;

    X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);

    char* data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    char* result = NULL;
    if (len > 0 && data) {
        result = strndup(data, (size_t)len);
    }
    BIO_free(bio);
    return result;
}

/* Helper: extract serial number as hex string */
static char* x509_get_serial_hex(X509* cert) {
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) return NULL;

    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) return NULL;

    char* hex = BN_bn2hex(bn);
    BN_free(bn);
    if (!hex) return NULL;

    char* result = strdup(hex);
    OPENSSL_free(hex);
    return result;
}

/* Helper: extract SHA-256 fingerprint */
static char* x509_get_fingerprint_sha256(X509* cert) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len;

    if (!X509_digest(cert, EVP_sha256(), digest, &digest_len)) {
        return NULL;
    }

    char* result = malloc(digest_len * 2 + 1);
    if (!result) return NULL;

    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(result + i * 2, "%02x", digest[i]);
    }
    result[digest_len * 2] = '\0';
    return result;
}

/* Helper: get signature algorithm name */
static char* x509_get_sig_algorithm(X509* cert) {
    const X509_ALGOR* sig_alg = X509_get0_tbs_sigalg(cert);
    if (!sig_alg) return NULL;

    const ASN1_OBJECT* obj = NULL;
    X509_ALGOR_get0(&obj, NULL, NULL, sig_alg);
    if (!obj) return NULL;

    int nid = OBJ_obj2nid(obj);
    if (nid != NID_undef) {
        return strdup(OBJ_nid2sn(nid));
    }

    char buf[128];
    OBJ_obj2txt(buf, sizeof(buf), obj, 0);
    return strdup(buf);
}

/* Helper: get public key algorithm name */
static char* x509_get_pubkey_algorithm(X509* cert) {
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (!pkey) return NULL;

    int type = EVP_PKEY_base_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA: return strdup("RSA");
        case EVP_PKEY_EC:  return strdup("EC");
        case EVP_PKEY_DSA: return strdup("DSA");
        case EVP_PKEY_DH:  return strdup("DH");
        case EVP_PKEY_ED25519: return strdup("Ed25519");
        case EVP_PKEY_ED448: return strdup("Ed448");
        default: return strdup("unknown");
    }
}

/* Helper: ASN1_TIME to time_t */
static time_t asn1_time_to_time_t(const ASN1_TIME* asn1_time) {
    if (!asn1_time) return 0;

    struct tm tm_time;
    memset(&tm_time, 0, sizeof(tm_time));

    if (ASN1_TIME_to_tm(asn1_time, &tm_time) != 1) {
        return 0;
    }

    return timegm(&tm_time);
}

/* Helper: check if certificate is a CA */
static bool x509_is_ca(X509* cert) {
    BASIC_CONSTRAINTS* bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (!bc) return false;
    bool is_ca = bc->ca ? true : false;
    BASIC_CONSTRAINTS_free(bc);
    return is_ca;
}

/* Helper: password callback to prevent stdin prompts */
static int crypto_parser_password_cb(char* buf, int size, int rwflag, void* userdata) {
    (void)rwflag;
    const char* password = (const char*)userdata;
    if (!password) return 0;

    int len = (int)strlen(password);
    if (len > size) len = size;
    memcpy(buf, password, (size_t)len);
    return len;
}

/* Try to detect if data is PEM or DER */
static bool data_is_pem(const unsigned char* data, size_t len) {
    if (len < 11) return false;
    return memcmp(data, "-----BEGIN ", 11) == 0;
}

/* ------------------------------------------------------------------ */
/*  Interface implementation                                           */
/* ------------------------------------------------------------------ */

static int openssl_parse_certificate(const unsigned char* data, size_t len,
                                     const char* path,
                                     crypto_parsed_cert_t* out) {
    if (!data || len == 0 || !out) return -1;
    (void)path;

    memset(out, 0, sizeof(*out));

    X509* cert = NULL;

    if (data_is_pem(data, len)) {
        BIO* bio = BIO_new_mem_buf(data, (int)len);
        if (!bio) return -1;
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
    } else {
        const unsigned char* p = data;
        cert = d2i_X509(NULL, &p, (long)len);
    }

    if (!cert) return -1;

    out->subject = x509_get_subject_oneline(cert);
    out->issuer = x509_get_issuer_oneline(cert);
    out->not_before = asn1_time_to_time_t(X509_get0_notBefore(cert));
    out->not_after = asn1_time_to_time_t(X509_get0_notAfter(cert));
    out->serial_number = x509_get_serial_hex(cert);
    out->signature_algorithm = x509_get_sig_algorithm(cert);
    out->public_key_algorithm = x509_get_pubkey_algorithm(cert);
    out->public_key_size = EVP_PKEY_bits(X509_get0_pubkey(cert));
    out->fingerprint_sha256 = x509_get_fingerprint_sha256(cert);
    out->is_ca = x509_is_ca(cert);
    out->extended_json = NULL;  /* Phase 2: populate with SANs, extensions, etc. */
    out->native_handle = cert;  /* Caller owns — freed via free_cert() */

    return 0;
}

static int openssl_parse_key(const unsigned char* data, size_t len,
                             const char* path, const char* password,
                             crypto_parsed_key_t* out) {
    if (!data || len == 0 || !out) return -1;
    (void)path;

    memset(out, 0, sizeof(*out));

    EVP_PKEY* pkey = NULL;
    bool is_private = false;

    if (data_is_pem(data, len)) {
        BIO* bio = BIO_new_mem_buf(data, (int)len);
        if (!bio) return -1;

        /* Try private key first */
        pkey = PEM_read_bio_PrivateKey(bio, NULL, crypto_parser_password_cb, (void*)password);
        if (pkey) {
            is_private = true;
        } else {
            /* Rewind and try public key */
            BIO_reset(bio);
            pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        }
        BIO_free(bio);
    } else {
        const unsigned char* p = data;
        pkey = d2i_PrivateKey(EVP_PKEY_NONE, NULL, &p, (long)len);
        if (pkey) {
            is_private = true;
        } else {
            p = data;
            pkey = d2i_PUBKEY(NULL, &p, (long)len);
        }
    }

    if (!pkey) return -1;

    int type = EVP_PKEY_base_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA: out->algorithm = strdup("RSA"); break;
        case EVP_PKEY_EC:  out->algorithm = strdup("EC");  break;
        case EVP_PKEY_DSA: out->algorithm = strdup("DSA"); break;
        case EVP_PKEY_DH:  out->algorithm = strdup("DH");  break;
        case EVP_PKEY_ED25519: out->algorithm = strdup("Ed25519"); break;
        case EVP_PKEY_ED448:   out->algorithm = strdup("Ed448");   break;
        default: out->algorithm = strdup("unknown"); break;
    }

    out->key_size = EVP_PKEY_bits(pkey);
    out->curve_name = NULL;
    if (type == EVP_PKEY_EC) {
        char curve_buf[64] = {0};
        size_t curve_len = sizeof(curve_buf);
        if (EVP_PKEY_get_utf8_string_param(pkey, "group", curve_buf, curve_len, &curve_len) == 1) {
            out->curve_name = strdup(curve_buf);
        }
    }

    out->is_private = is_private;
    out->is_encrypted = false;  /* Already decrypted at this point */
    out->fingerprint = NULL;    /* Phase 2: compute key fingerprint */
    out->native_handle = pkey;  /* Caller owns — freed via free_key() */

    return 0;
}

static int openssl_parse_certificate_bundle(const unsigned char* data, size_t len,
                                            const char* path,
                                            void (*callback)(const crypto_parsed_cert_t*, void*),
                                            void* user_data) {
    if (!data || len == 0 || !callback) return -1;
    (void)path;

    BIO* bio = BIO_new_mem_buf(data, (int)len);
    if (!bio) return -1;

    int count = 0;

    while (1) {
        X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert) {
            /* Clear error — could be end of PEM chain or actual error */
            ERR_clear_error();
            break;
        }

        crypto_parsed_cert_t parsed;
        memset(&parsed, 0, sizeof(parsed));

        parsed.subject = x509_get_subject_oneline(cert);
        parsed.issuer = x509_get_issuer_oneline(cert);
        parsed.not_before = asn1_time_to_time_t(X509_get0_notBefore(cert));
        parsed.not_after = asn1_time_to_time_t(X509_get0_notAfter(cert));
        parsed.serial_number = x509_get_serial_hex(cert);
        parsed.signature_algorithm = x509_get_sig_algorithm(cert);
        parsed.public_key_algorithm = x509_get_pubkey_algorithm(cert);
        parsed.public_key_size = EVP_PKEY_bits(X509_get0_pubkey(cert));
        parsed.fingerprint_sha256 = x509_get_fingerprint_sha256(cert);
        parsed.is_ca = x509_is_ca(cert);
        parsed.extended_json = NULL;
        parsed.native_handle = cert;

        callback(&parsed, user_data);

        /* Free the parsed cert strings — callback should have copied what it needs */
        free(parsed.subject);
        free(parsed.issuer);
        free(parsed.serial_number);
        free(parsed.signature_algorithm);
        free(parsed.public_key_algorithm);
        free(parsed.fingerprint_sha256);
        X509_free(cert);

        count++;
    }

    BIO_free(bio);
    return count;
}

static void openssl_free_cert(crypto_parsed_cert_t* cert) {
    if (!cert) return;

    free(cert->subject);
    free(cert->issuer);
    free(cert->serial_number);
    free(cert->signature_algorithm);
    free(cert->public_key_algorithm);
    free(cert->fingerprint_sha256);
    free(cert->extended_json);

    if (cert->native_handle) {
        X509_free((X509*)cert->native_handle);
    }

    memset(cert, 0, sizeof(*cert));
}

static void openssl_free_key(crypto_parsed_key_t* key) {
    if (!key) return;

    free(key->algorithm);
    free(key->curve_name);
    free(key->fingerprint);

    if (key->native_handle) {
        EVP_PKEY_free((EVP_PKEY*)key->native_handle);
    }

    memset(key, 0, sizeof(*key));
}

/* ------------------------------------------------------------------ */
/*  Backend accessor                                                   */
/* ------------------------------------------------------------------ */

static const crypto_parser_ops_t openssl_ops = {
    .backend_name = "openssl",
    .parse_certificate = openssl_parse_certificate,
    .parse_key = openssl_parse_key,
    .parse_certificate_bundle = openssl_parse_certificate_bundle,
    .free_cert = openssl_free_cert,
    .free_key = openssl_free_key,
};

const crypto_parser_ops_t* crypto_parser_openssl_ops(void) {
    return &openssl_ops;
}
