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

/*
 * JS Bridge Crypto Parser — reads pre-parsed certificate/key metadata from
 * a JSON file written by the JavaScript layer (cert-parser.js via wasm-bridge.js).
 *
 * Flow:
 *   JS: parse certs with pkijs → write JSON to /scan/.cert-metadata.json
 *   C:  jsbridge_parser_init() reads the JSON file, builds in-memory lookup tables
 *   C:  parse_certificate(path, ...) looks up path in table, fills crypto_parsed_cert_t
 *   C:  parse_key(path, ...) looks up path in table, fills crypto_parsed_key_t
 *
 * The lookup tables use json-c's json_object (internally a hash map) keyed
 * by absolute MEMFS path for O(1) access per file.
 */

#define _GNU_SOURCE
#include "crypto_parser_interface.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/*  Module state                                                       */
/* ------------------------------------------------------------------ */

/* Cert lookup: absolute path → json_array of cert JSON objects (supports chains) */
static json_object* g_cert_lookup = NULL;

/* Key lookup: absolute path → json_object for the key */
static json_object* g_key_lookup = NULL;

/* The parsed root JSON (kept alive so lookup entries remain valid) */
static json_object* g_root_json = NULL;

/* Scan prefix prepended to relative filePaths for key matching */
static const char* SCAN_PREFIX = "/scan/";

/* ------------------------------------------------------------------ */
/*  JSON helpers                                                       */
/* ------------------------------------------------------------------ */

static char* json_get_string_dup(json_object* obj, const char* key) {
    json_object* val = NULL;
    if (!json_object_object_get_ex(obj, key, &val)) return NULL;
    const char* s = json_object_get_string(val);
    return s ? strdup(s) : NULL;
}

static int json_get_int_val(json_object* obj, const char* key, int default_val) {
    json_object* val = NULL;
    if (!json_object_object_get_ex(obj, key, &val)) return default_val;
    return json_object_get_int(val);
}

static bool json_get_bool_val(json_object* obj, const char* key) {
    json_object* val = NULL;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    return json_object_get_boolean(val) ? true : false;
}

/* ------------------------------------------------------------------ */
/*  Data conversion helpers                                            */
/* ------------------------------------------------------------------ */

/**
 * Parse an ISO 8601 date string to time_t (UTC).
 * Accepts: "2024-01-01T00:00:00.000Z" or "2024-01-01T00:00:00Z"
 * Uses sscanf (not strptime) for Emscripten compatibility.
 */
static time_t iso8601_to_time_t(const char* iso) {
    if (!iso || iso[0] == '\0') return 0;

    struct tm tm;
    memset(&tm, 0, sizeof(tm));

    int matched = sscanf(iso, "%d-%d-%dT%d:%d:%d",
                         &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                         &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if (matched < 6) return 0;

    tm.tm_year -= 1900;
    tm.tm_mon -= 1;

    return timegm(&tm);
}

/**
 * Strip colons from a fingerprint string.
 * Converts "ab:cd:ef:01:23" to "abcdef0123".
 * Returns a newly allocated string (caller must free).
 */
static char* strip_colons(const char* fingerprint) {
    if (!fingerprint) return NULL;

    size_t len = strlen(fingerprint);
    char* result = malloc(len + 1);
    if (!result) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (fingerprint[i] != ':') {
            result[j++] = fingerprint[i];
        }
    }
    result[j] = '\0';
    return result;
}

/**
 * Populate a crypto_parsed_cert_t from a JSON cert object.
 */
static int fill_cert_from_json(json_object* cert_obj, crypto_parsed_cert_t* out) {
    if (!cert_obj || !out) return -1;

    memset(out, 0, sizeof(*out));

    out->subject = json_get_string_dup(cert_obj, "subject");
    out->issuer = json_get_string_dup(cert_obj, "issuer");
    out->serial_number = json_get_string_dup(cert_obj, "serialNumber");
    out->signature_algorithm = json_get_string_dup(cert_obj, "signatureAlgorithm");
    out->public_key_algorithm = json_get_string_dup(cert_obj, "publicKeyAlgorithm");
    out->public_key_size = json_get_int_val(cert_obj, "publicKeySize", 0);
    out->is_ca = json_get_bool_val(cert_obj, "isCa");

    /* Convert ISO 8601 dates to time_t */
    char* not_before_str = json_get_string_dup(cert_obj, "notBefore");
    char* not_after_str = json_get_string_dup(cert_obj, "notAfter");
    out->not_before = iso8601_to_time_t(not_before_str);
    out->not_after = iso8601_to_time_t(not_after_str);
    free(not_before_str);
    free(not_after_str);

    /* Convert colon-separated fingerprint to plain hex */
    char* raw_fp = json_get_string_dup(cert_obj, "fingerprintSha256");
    out->fingerprint_sha256 = strip_colons(raw_fp);
    free(raw_fp);

    out->extended_json = NULL;
    out->native_handle = NULL;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Lookup table construction                                          */
/* ------------------------------------------------------------------ */

/**
 * Build the full MEMFS path used as lookup key.
 * Concatenates SCAN_PREFIX + filePath.
 * Returns a newly allocated string (caller must free).
 */
static char* build_lookup_key(const char* file_path) {
    if (!file_path) return NULL;

    size_t prefix_len = strlen(SCAN_PREFIX);
    size_t path_len = strlen(file_path);
    char* key = malloc(prefix_len + path_len + 1);
    if (!key) return NULL;

    memcpy(key, SCAN_PREFIX, prefix_len);
    memcpy(key + prefix_len, file_path, path_len);
    key[prefix_len + path_len] = '\0';
    return key;
}

/**
 * Build lookup tables from the parsed JSON root object.
 * Creates g_cert_lookup (path → json_array) and g_key_lookup (path → json_object).
 */
static int build_lookup_tables(json_object* root) {
    g_cert_lookup = json_object_new_object();
    g_key_lookup = json_object_new_object();
    if (!g_cert_lookup || !g_key_lookup) return -1;

    /* Build cert lookup table */
    json_object* certs_arr = NULL;
    if (json_object_object_get_ex(root, "certs", &certs_arr) &&
        json_object_is_type(certs_arr, json_type_array)) {

        size_t n = json_object_array_length(certs_arr);
        for (size_t i = 0; i < n; i++) {
            json_object* cert = json_object_array_get_idx(certs_arr, i);
            if (!cert) continue;

            char* file_path = json_get_string_dup(cert, "filePath");
            if (!file_path) continue;

            char* key = build_lookup_key(file_path);
            free(file_path);
            if (!key) continue;

            /* Append to existing array or create new one */
            json_object* existing = NULL;
            if (json_object_object_get_ex(g_cert_lookup, key, &existing)) {
                json_object_array_add(existing, json_object_get(cert));
            } else {
                json_object* arr = json_object_new_array();
                json_object_array_add(arr, json_object_get(cert));
                json_object_object_add(g_cert_lookup, key, arr);
            }
            free(key);
        }
    }

    /* Build key lookup table */
    json_object* keys_arr = NULL;
    if (json_object_object_get_ex(root, "keys", &keys_arr) &&
        json_object_is_type(keys_arr, json_type_array)) {

        size_t n = json_object_array_length(keys_arr);
        for (size_t i = 0; i < n; i++) {
            json_object* key_obj = json_object_array_get_idx(keys_arr, i);
            if (!key_obj) continue;

            char* file_path = json_get_string_dup(key_obj, "filePath");
            if (!file_path) continue;

            char* key = build_lookup_key(file_path);
            free(file_path);
            if (!key) continue;

            json_object_object_add(g_key_lookup, key, json_object_get(key_obj));
            free(key);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public lifecycle                                                   */
/* ------------------------------------------------------------------ */

int jsbridge_parser_init(const char* json_path) {
    if (!json_path) return -1;

    /* Read the JSON file */
    FILE* f = fopen(json_path, "r");
    if (!f) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(f);
        return -1;
    }

    char* buf = malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    buf[nread] = '\0';

    /* Parse JSON */
    g_root_json = json_tokener_parse(buf);
    free(buf);

    if (!g_root_json) {
        return -1;
    }

    /* Build lookup tables */
    if (build_lookup_tables(g_root_json) != 0) {
        json_object_put(g_root_json);
        g_root_json = NULL;
        return -1;
    }

    return 0;
}

void jsbridge_parser_shutdown(void) {
    if (g_cert_lookup) {
        json_object_put(g_cert_lookup);
        g_cert_lookup = NULL;
    }
    if (g_key_lookup) {
        json_object_put(g_key_lookup);
        g_key_lookup = NULL;
    }
    if (g_root_json) {
        json_object_put(g_root_json);
        g_root_json = NULL;
    }
}

/* Forward declarations */
static void jsbridge_free_cert_fields(crypto_parsed_cert_t* cert);

/* ------------------------------------------------------------------ */
/*  Interface implementation: parse_certificate                        */
/* ------------------------------------------------------------------ */

static int jsbridge_parse_certificate(const unsigned char* data, size_t len,
                                      const char* path,
                                      crypto_parsed_cert_t* out) {
    (void)data;
    (void)len;

    if (!path || !out || !g_cert_lookup) return -1;

    json_object* arr = NULL;
    if (!json_object_object_get_ex(g_cert_lookup, path, &arr)) return -1;

    /* Return the first certificate (leaf) */
    if (json_object_array_length(arr) == 0) return -1;

    json_object* cert_obj = json_object_array_get_idx(arr, 0);
    return fill_cert_from_json(cert_obj, out);
}

/* ------------------------------------------------------------------ */
/*  Interface implementation: parse_key                                */
/* ------------------------------------------------------------------ */

static int jsbridge_parse_key(const unsigned char* data, size_t len,
                              const char* path, const char* password,
                              crypto_parsed_key_t* out) {
    (void)data;
    (void)len;
    (void)password;

    if (!path || !out || !g_key_lookup) return -1;

    json_object* key_obj = NULL;
    if (!json_object_object_get_ex(g_key_lookup, path, &key_obj)) return -1;

    memset(out, 0, sizeof(*out));

    out->algorithm = json_get_string_dup(key_obj, "algorithm");
    out->key_size = json_get_int_val(key_obj, "keySize", 0);
    out->curve_name = json_get_string_dup(key_obj, "namedCurve");
    out->is_private = true;
    out->is_encrypted = false;
    out->fingerprint = NULL;
    out->native_handle = NULL;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Interface implementation: parse_certificate_bundle                 */
/* ------------------------------------------------------------------ */

static int jsbridge_parse_certificate_bundle(
    const unsigned char* data, size_t len,
    const char* path,
    void (*callback)(const crypto_parsed_cert_t* cert, void* user_data),
    void* user_data) {

    (void)data;
    (void)len;

    if (!path || !callback || !g_cert_lookup) return -1;

    json_object* arr = NULL;
    if (!json_object_object_get_ex(g_cert_lookup, path, &arr)) return -1;

    size_t n = json_object_array_length(arr);
    int count = 0;

    for (size_t i = 0; i < n; i++) {
        json_object* cert_obj = json_object_array_get_idx(arr, i);
        if (!cert_obj) continue;

        crypto_parsed_cert_t parsed;
        if (fill_cert_from_json(cert_obj, &parsed) == 0) {
            callback(&parsed, user_data);
            /* Caller copies what it needs in the callback;
               free our temporary copy */
            jsbridge_free_cert_fields(&parsed);
            count++;
        }
    }

    return count;
}

/* ------------------------------------------------------------------ */
/*  Interface implementation: free_cert / free_key                     */
/* ------------------------------------------------------------------ */

static void jsbridge_free_cert_fields(crypto_parsed_cert_t* cert) {
    if (!cert) return;
    free(cert->subject);
    free(cert->issuer);
    free(cert->serial_number);
    free(cert->signature_algorithm);
    free(cert->public_key_algorithm);
    free(cert->fingerprint_sha256);
    free(cert->extended_json);
    /* native_handle is NULL for jsbridge */
}

static void jsbridge_free_cert(crypto_parsed_cert_t* cert) {
    if (!cert) return;
    jsbridge_free_cert_fields(cert);
    memset(cert, 0, sizeof(*cert));
}

static void jsbridge_free_key(crypto_parsed_key_t* key) {
    if (!key) return;
    free(key->algorithm);
    free(key->curve_name);
    free(key->fingerprint);
    /* native_handle is NULL for jsbridge */
    memset(key, 0, sizeof(*key));
}

/* ------------------------------------------------------------------ */
/*  Ops struct and accessor                                            */
/* ------------------------------------------------------------------ */

static const crypto_parser_ops_t jsbridge_ops = {
    .backend_name = "jsbridge",
    .parse_certificate = jsbridge_parse_certificate,
    .parse_key = jsbridge_parse_key,
    .parse_certificate_bundle = jsbridge_parse_certificate_bundle,
    .free_cert = jsbridge_free_cert,
    .free_key = jsbridge_free_key,
};

const crypto_parser_ops_t* crypto_parser_jsbridge_ops(void) {
    return &jsbridge_ops;
}
