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

// WASM stub implementations for modules excluded from the Emscripten build.
// These modules depend on OpenSSL, dlfcn, or other Linux-only APIs.

#ifdef __EMSCRIPTEN__

#define _GNU_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <json-c/json.h>
#include "cbom_types.h"
#include "key_manager.h"
#include "attestation.h"
#include "plugin_manager.h"
#include "privacy.h"
#include "dedup.h"
#include "detection/port_detector.h"
#include "component_factory.h"

// ── json_parser.c stubs ─────────────────────────────────────────────

void json_parser_register(void) {}

// ── key_manager.c stubs ────────────────────────────────────────────

key_manager_stats_t key_manager_get_stats(void) {
    key_manager_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    return stats;
}

void key_manager_cleanup(void) {}

// ── attestation.c stubs ────────────────────────────────────────────

attestation_config_t attestation_get_default_config(void) {
    attestation_config_t config;
    memset(&config, 0, sizeof(config));
    return config;
}

attestation_context_t* attestation_create(const attestation_config_t* config) {
    (void)config;
    return NULL;
}

void attestation_destroy(attestation_context_t* context) { (void)context; }

int attestation_load_private_key(attestation_context_t* context) {
    (void)context;
    return -1;
}

char* attestation_get_key_fingerprint(attestation_context_t* context) {
    (void)context;
    return NULL;
}

int attestation_sign_data(attestation_context_t* context,
                          const unsigned char* data, size_t data_len,
                          unsigned char** signature, size_t* signature_len) {
    (void)context; (void)data; (void)data_len;
    (void)signature; (void)signature_len;
    return -1;
}

char* attestation_compute_sha256(const unsigned char* data, size_t len) {
    (void)data; (void)len;
    return NULL;
}

char* attestation_base64_encode(const unsigned char* data, size_t len) {
    (void)data; (void)len;
    return NULL;
}

unsigned char* attestation_base64_decode(const char* encoded, size_t* out_len) {
    (void)encoded; (void)out_len;
    return NULL;
}

dsse_envelope_t* dsse_create_envelope(const char* payload, const char* payload_type) {
    (void)payload; (void)payload_type;
    return NULL;
}

int dsse_add_signature(dsse_envelope_t* envelope, attestation_context_t* context,
                       const char* payload) {
    (void)envelope; (void)context; (void)payload;
    return -1;
}

void dsse_envelope_destroy(dsse_envelope_t* envelope) { (void)envelope; }

json_object* dsse_envelope_to_json(const dsse_envelope_t* envelope) {
    (void)envelope;
    return NULL;
}

int dsse_write_to_file(const dsse_envelope_t* envelope, const char* output_path) {
    (void)envelope; (void)output_path;
    return -1;
}

json_object* attestation_sign_cbom_json(attestation_context_t* context,
                                        json_object* cbom) {
    (void)context;
    return cbom;
}

int attestation_sign_cbom_file(attestation_context_t* context,
                               const char* cbom_file_path,
                               const char* output_path) {
    (void)context; (void)cbom_file_path; (void)output_path;
    return -1;
}

// ── plugin_manager.c stubs ─────────────────────────────────────────

uint32_t plugin_generate_instance_id(plugin_manager_t* manager) {
    (void)manager;
    return 0;
}

plugin_manager_t* plugin_manager_create(const char* plugin_directory,
                                        plugin_security_policy_t security_policy) {
    (void)plugin_directory; (void)security_policy;
    // Return a valid but empty plugin manager so main.c proceeds to output
    plugin_manager_t* manager = calloc(1, sizeof(plugin_manager_t));
    return manager;
}

int plugin_manager_set_trust_config(plugin_manager_t* manager,
                                    const plugin_trust_config_t* trust_config) {
    (void)manager; (void)trust_config;
    return 0;
}

int plugin_manager_set_default_limits(plugin_manager_t* manager,
                                      const plugin_resource_limits_t* limits) {
    (void)manager; (void)limits;
    return 0;
}

void plugin_manager_destroy(plugin_manager_t* manager) { free(manager); }

int plugin_manager_load_plugin(plugin_manager_t* manager, const char* plugin_path,
                               plugin_load_flags_t flags) {
    (void)manager; (void)plugin_path; (void)flags;
    return -1;
}

int plugin_verify_signature(const char* plugin_path,
                            const plugin_trust_config_t* trust_config) {
    (void)plugin_path; (void)trust_config;
    return -1;
}

bool plugin_check_capabilities(const plugin_metadata_t* metadata) {
    (void)metadata;
    return false;
}

int plugin_apply_sandboxing(plugin_instance_t* instance) {
    (void)instance;
    return 0;
}

int plugin_enforce_resource_limits(plugin_instance_t* instance) {
    (void)instance;
    return 0;
}

plugin_instance_t* plugin_manager_find_plugin(plugin_manager_t* manager,
                                              const char* name) {
    (void)manager; (void)name;
    return NULL;
}

plugin_instance_t* plugin_manager_get_plugin(plugin_manager_t* manager,
                                             uint32_t instance_id) {
    (void)manager; (void)instance_id;
    return NULL;
}

int plugin_manager_execute_scanner(plugin_manager_t* manager,
                                   uint32_t instance_id,
                                   scan_context_t* context,
                                   asset_store_t* store) {
    (void)manager; (void)instance_id; (void)context; (void)store;
    return -1;
}

plugin_resource_limits_t plugin_create_default_limits(void) {
    plugin_resource_limits_t limits;
    memset(&limits, 0, sizeof(limits));
    return limits;
}

plugin_trust_config_t plugin_create_default_trust_config(void) {
    plugin_trust_config_t config;
    memset(&config, 0, sizeof(config));
    return config;
}

int plugin_validate_api_version(uint32_t plugin_version) {
    (void)plugin_version;
    return 0;
}

const char* plugin_type_to_string(plugin_type_t type) {
    (void)type;
    return "unknown";
}

const char* scanner_subtype_to_string(scanner_subtype_t subtype) {
    (void)subtype;
    return "unknown";
}

plugin_statistics_t plugin_manager_get_statistics(plugin_manager_t* manager) {
    (void)manager;
    plugin_statistics_t stats;
    memset(&stats, 0, sizeof(stats));
    return stats;
}

int plugin_manager_load_yaml_plugin(plugin_manager_t* manager,
                                    const char* yaml_path) {
    (void)manager; (void)yaml_path;
    return -1;
}

int plugin_manager_scan_yaml_directory(plugin_manager_t* manager,
                                      const char* directory) {
    (void)manager; (void)directory;
    return -1;
}

void plugin_manager_set_whitelist(plugin_manager_t* manager,
                                  const char** names, size_t count) {
    (void)manager; (void)names; (void)count;
}

/* plugin_manager_register_builtin_scanners — defined in builtin_scanners.c (still compiled) */

int plugin_manager_load_directory(plugin_manager_t* manager,
                                  const char* directory,
                                  plugin_load_flags_t flags) {
    (void)manager; (void)directory; (void)flags;
    return 0;
}

int plugin_manager_unload_plugin(plugin_manager_t* manager,
                                 uint32_t instance_id) {
    (void)manager; (void)instance_id;
    return 0;
}

int plugin_manager_execute_analyzer(plugin_manager_t* manager,
                                    uint32_t instance_id,
                                    void* data, void* result) {
    (void)manager; (void)instance_id; (void)data; (void)result;
    return -1;
}

plugin_instance_t** plugin_manager_list_plugins(plugin_manager_t* manager,
                                                plugin_type_t type,
                                                size_t* count) {
    (void)manager; (void)type;
    if (count) *count = 0;
    return NULL;
}

plugin_instance_t** plugin_manager_list_scanners(plugin_manager_t* manager,
                                                 scanner_subtype_t subtype,
                                                 size_t* count) {
    (void)manager; (void)subtype;
    if (count) *count = 0;
    return NULL;
}

int plugin_verify_hash(const char* plugin_path, const uint8_t* expected_hash) {
    (void)plugin_path; (void)expected_hash;
    return -1;
}

int plugin_monitor_resources(plugin_instance_t* instance) {
    (void)instance;
    return 0;
}

void plugin_update_resource_usage(plugin_instance_t* instance) {
    (void)instance;
}

// ── privacy.c stubs ────────────────────────────────────────────────

void privacy_cleanup_global_resources(void) {}

privacy_config_t privacy_get_default_config(void) {
    privacy_config_t config;
    memset(&config, 0, sizeof(config));
    return config;
}

bool privacy_load_salt_from_env(privacy_config_t* config) {
    (void)config;
    return false;
}

bool privacy_load_salt_from_config(privacy_config_t* config,
                                   const char* config_path) {
    (void)config; (void)config_path;
    return false;
}

bool privacy_validate_salt_entropy(const char* salt, size_t length) {
    (void)salt; (void)length;
    return false;
}

char* privacy_generate_salt(size_t length) {
    (void)length;
    return NULL;
}

privacy_context_t* privacy_context_create(const privacy_config_t* config) {
    (void)config;
    return NULL;
}

void privacy_context_destroy(privacy_context_t* context) { (void)context; }

void redaction_result_destroy(redaction_result_t* result) {
    if (result) {
        free(result->redacted_text);
        free(result);
    }
}

char* privacy_hash_with_salt(privacy_context_t* context, const char* input) {
    (void)context; (void)input;
    return NULL;
}

bool is_username_in_path(const char* path) { (void)path; return false; }
bool is_home_directory_path(const char* path) { (void)path; return false; }
bool contains_hostname(const char* text) { (void)text; return false; }

char* extract_username_from_path(const char* path) { (void)path; return NULL; }
char* extract_hostname_from_text(const char* text) { (void)text; return NULL; }

redaction_result_t* privacy_redact_username(privacy_context_t* context,
                                            const char* text) {
    (void)context; (void)text;
    return NULL;
}

redaction_result_t* privacy_redact_home_path(privacy_context_t* context,
                                             const char* path) {
    (void)context; (void)path;
    return NULL;
}

bool privacy_contains_secrets(const char* text) { (void)text; return false; }

redaction_result_t* privacy_redact_pem_headers(privacy_context_t* context,
                                               const char* text) {
    (void)context; (void)text;
    return NULL;
}

redaction_result_t* privacy_redact_hostname(privacy_context_t* context,
                                            const char* text) {
    (void)context; (void)text;
    return NULL;
}

char* privacy_pseudonymize_hostname(privacy_context_t* context,
                                    const char* hostname) {
    (void)context;
    return hostname ? strdup(hostname) : NULL;
}

char* privacy_pseudonymize_path(privacy_context_t* context, const char* path) {
    (void)context;
    return path ? strdup(path) : NULL;
}

redaction_result_t* privacy_redact_file_path(privacy_context_t* context,
                                             const char* path) {
    (void)context; (void)path;
    return NULL;
}

redaction_result_t* privacy_redact_private_keys(privacy_context_t* context,
                                                const char* text) {
    (void)context; (void)text;
    return NULL;
}

redaction_result_t* privacy_sanitize_evidence(privacy_context_t* context,
                                              const char* evidence) {
    (void)context; (void)evidence;
    return NULL;
}

bool privacy_validate_referential_integrity(privacy_context_t* context,
                                            const char** inputs,
                                            const char** outputs,
                                            size_t count) {
    (void)context; (void)inputs; (void)outputs; (void)count;
    return true;
}

privacy_config_t* privacy_parse_config_from_args(int argc, char** argv) {
    (void)argc; (void)argv;
    return NULL;
}

void privacy_print_help(void) {}

// ── dedup.c stubs ──────────────────────────────────────────────────

char* dedup_compute_file_sha256(const char* file_path) {
    (void)file_path;
    return NULL;
}

dedup_context_t* dedup_context_create(dedup_mode_t mode, bool emit_bundles) {
    (void)mode; (void)emit_bundles;
    return NULL;
}

void dedup_context_destroy(dedup_context_t* ctx) { (void)ctx; }

void dedup_register_file(dedup_context_t* ctx, const char* file_path,
                         const char* file_sha256, const char* bom_ref) {
    (void)ctx; (void)file_path; (void)file_sha256; (void)bom_ref;
}

char* dedup_get_component_for_file(dedup_context_t* ctx,
                                   const char* file_path,
                                   const char* file_sha256) {
    (void)ctx; (void)file_path; (void)file_sha256;
    return NULL;
}

bool dedup_should_suppress_file(dedup_context_t* ctx, const char* file_path,
                                const char* file_sha256) {
    (void)ctx; (void)file_path; (void)file_sha256;
    return false;
}

void dedup_add_evidence(dedup_context_t* ctx, const char* bom_ref,
                        const char* location, const char* file_sha256) {
    (void)ctx; (void)bom_ref; (void)location; (void)file_sha256;
}

char* dedup_merge_or_create_component(dedup_context_t* ctx,
                                      asset_store_t* store,
                                      crypto_asset_t* asset,
                                      const char* file_path,
                                      const char* file_sha256) {
    (void)ctx; (void)store; (void)asset; (void)file_path; (void)file_sha256;
    return NULL;
}

dedup_stats_t dedup_get_stats(dedup_context_t* ctx) {
    (void)ctx;
    dedup_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    return stats;
}

void dedup_print_stats(const dedup_stats_t* stats) { (void)stats; }

component_evidence_t* dedup_get_evidence(dedup_context_t* ctx,
                                         const char* bom_ref) {
    (void)ctx; (void)bom_ref;
    return NULL;
}

char* dedup_create_or_get_bundle(dedup_context_t* ctx, asset_store_t* store,
                                 const char* bundle_file_path) {
    (void)ctx; (void)store; (void)bundle_file_path;
    return NULL;
}

void dedup_link_cert_to_bundle(dedup_context_t* ctx, const char* bundle_ref,
                               const char* cert_ref) {
    (void)ctx; (void)bundle_ref; (void)cert_ref;
}

int dedup_merge_duplicate_services(asset_store_t* store) {
    (void)store;
    return 0;
}

// ── service_relationships.c stubs ──────────────────────────────────

int build_service_cert_relationships(asset_store_t* store) {
    (void)store;
    return 0;
}

int create_service_protocol_relationship(asset_store_t* store,
                                         const char* service_id,
                                         const char* protocol_id,
                                         float confidence) {
    (void)store; (void)service_id; (void)protocol_id; (void)confidence;
    return 0;
}

int create_protocol_suite_relationship(asset_store_t* store,
                                       const char* protocol_id,
                                       const char* suite_id,
                                       float confidence) {
    (void)store; (void)protocol_id; (void)suite_id; (void)confidence;
    return 0;
}

int create_service_cert_relationship(asset_store_t* store,
                                     const char* service_id,
                                     const char* cert_id,
                                     float confidence) {
    (void)store; (void)service_id; (void)cert_id; (void)confidence;
    return 0;
}

int create_suite_algorithm_relationship(asset_store_t* store,
                                        const char* suite_id,
                                        const char* algorithm_id,
                                        float confidence) {
    (void)store; (void)suite_id; (void)algorithm_id; (void)confidence;
    return 0;
}

const char* find_cert_id_by_path(asset_store_t* store, const char* cert_path) {
    (void)store; (void)cert_path;
    return NULL;
}

crypto_asset_t* get_or_create_algorithm_asset(asset_store_t* store,
                                              const char* algorithm_name,
                                              int key_size) {
    (void)store; (void)algorithm_name; (void)key_size;
    return NULL;
}

crypto_asset_t* create_algorithm_asset_from_components(const char* algorithm_name,
                                                       int key_size) {
    (void)algorithm_name; (void)key_size;
    return NULL;
}

int decompose_cipher_suite_to_algorithms(asset_store_t* store,
                                         const char* suite_id,
                                         const char* kex,
                                         const char* auth,
                                         const char* enc,
                                         const char* mac) {
    (void)store; (void)suite_id; (void)kex; (void)auth; (void)enc; (void)mac;
    return 0;
}

int create_service_library_relationship(asset_store_t* store,
                                        const char* service_id,
                                        const char* library_id,
                                        float confidence) {
    (void)store; (void)service_id; (void)library_id; (void)confidence;
    return 0;
}

/* detect_service_library_dependencies_simple — defined in service_scanner.c (has its own WASM stub) */

// ── component_factory.c stubs ──────────────────────────────────────

int component_factory_process_service(service_instance_t* service,
                                      crypto_config_t* config,
                                      asset_store_t* store) {
    (void)service; (void)config; (void)store;
    return 0;
}

crypto_asset_t* component_factory_create_service(service_instance_t* service,
                                                 asset_store_t* store) {
    (void)service; (void)store;
    return NULL;
}

crypto_asset_t* component_factory_create_certificate(const char* cert_path,
                                                     const char* service_id,
                                                     asset_store_t* store) {
    (void)cert_path; (void)service_id; (void)store;
    return NULL;
}

crypto_asset_t* component_factory_create_private_key(const char* key_path,
                                                     const char* cert_id,
                                                     asset_store_t* store) {
    (void)key_path; (void)cert_id; (void)store;
    return NULL;
}

crypto_asset_t* component_factory_create_protocol(const char* protocol_name,
                                                  const char* version,
                                                  const char* service_id,
                                                  asset_store_t* store) {
    (void)protocol_name; (void)version; (void)service_id; (void)store;
    return NULL;
}

crypto_asset_t* component_factory_create_cipher_suite(const char* cipher_suite,
                                                      const char* protocol_id,
                                                      asset_store_t* store) {
    (void)cipher_suite; (void)protocol_id; (void)store;
    return NULL;
}

// ── port_detector.c stubs ──────────────────────────────────────────

char* port_detector_hex_to_address(unsigned long hex_addr, bool is_ipv6) {
    (void)hex_addr; (void)is_ipv6;
    return NULL;
}

bool port_detector_find_listening_port(const uint16_t* ports, int port_count,
                                      const char* protocol,
                                      uint16_t* found_port,
                                      char** bind_address) {
    (void)ports; (void)port_count; (void)protocol;
    (void)found_port; (void)bind_address;
    return false;
}

bool port_detector_probe_tls(uint16_t port, int timeout_ms) {
    (void)port; (void)timeout_ms;
    return false;
}

bool port_detector_detect(const port_detection_config_t* config,
                          service_instance_t* instance,
                          bool enable_tls_probe, int timeout_ms) {
    (void)config; (void)instance; (void)enable_tls_probe; (void)timeout_ms;
    return false;
}

// ── openssl_cipher_parser.c stubs ──────────────────────────────────

void openssl_cipher_parser_register(void) {}

int openssl_cipher_expand(const char* cipher_string, char*** cipher_names,
                          int* count) {
    (void)cipher_string; (void)cipher_names;
    if (count) *count = 0;
    return -1;
}

void openssl_cipher_names_free(char** cipher_names, int count) {
    (void)cipher_names; (void)count;
}

#endif /* __EMSCRIPTEN__ */
