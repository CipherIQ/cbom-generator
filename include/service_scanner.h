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

#ifndef SERVICE_SCANNER_H
#define SERVICE_SCANNER_H

#include <stdbool.h>
#include <time.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/types.h>

// Forward declarations
struct asset_store;
struct crypto_asset;
struct scan_context;

// Service type enumeration
typedef enum {
    SERVICE_TYPE_WEB_SERVER,         // Apache, Nginx
    SERVICE_TYPE_HTTPS,              // HTTP over TLS
    SERVICE_TYPE_MAIL_SERVER,        // Postfix, Sendmail
    SERVICE_TYPE_SMTP_TLS,           // SMTP with STARTTLS
    SERVICE_TYPE_SMTPS,              // SMTP over TLS
    SERVICE_TYPE_IMAP_TLS,           // IMAP with STARTTLS
    SERVICE_TYPE_IMAPS,              // IMAP over TLS
    SERVICE_TYPE_SSH_SERVER,         // OpenSSH daemon
    SERVICE_TYPE_VPN,                // VPN service
    SERVICE_TYPE_DATABASE_TLS,       // Database with TLS
    SERVICE_TYPE_CUSTOM,             // Custom service
    SERVICE_TYPE_UNKNOWN
} service_type_t;

// Protocol type enumeration (core cryptographic protocols)
typedef enum {
    PROTOCOL_TYPE_TLS,               // Transport Layer Security
    PROTOCOL_TYPE_SSH,               // Secure Shell
    PROTOCOL_TYPE_IPSEC,             // IP Security
    PROTOCOL_TYPE_DTLS,              // Datagram TLS
    PROTOCOL_TYPE_QUIC,              // QUIC
    PROTOCOL_TYPE_WIREGUARD,         // WireGuard VPN
    PROTOCOL_TYPE_OPENVPN,           // OpenVPN
    PROTOCOL_TYPE_UNKNOWN
} protocol_type_t;

// Security profile classification
typedef enum {
    SECURITY_PROFILE_MODERN,         // Modern security (TLS 1.3, strong ciphers)
    SECURITY_PROFILE_INTERMEDIATE,   // Intermediate (TLS 1.2+, reasonable ciphers)
    SECURITY_PROFILE_OLD,            // Old/legacy (TLS 1.0/1.1, weak ciphers)
    SECURITY_PROFILE_CUSTOM,         // Custom configuration
    SECURITY_PROFILE_UNKNOWN
} security_profile_t;

// Detection method
typedef enum {
    DETECT_METHOD_PROCESS,           // Detected from running process
    DETECT_METHOD_CONFIG_FILE,       // Detected from config file
    DETECT_METHOD_SYSTEMD,           // Detected from systemd service
    DETECT_METHOD_NETWORK_ENDPOINT,  // Detected from /proc/net/tcp
    DETECT_METHOD_UNKNOWN
} detection_method_t;

// Network endpoint structure
typedef struct {
    char* address;                   // IP address (e.g., "0.0.0.0", "127.0.0.1")
    int port;                        // Port number
    char* protocol;                  // "tcp" or "udp"
    bool is_encrypted;               // Whether endpoint uses encryption
} network_endpoint_t;

// Version constraints structure
typedef struct {
    char* min_version;               // Minimum allowed version
    char* max_version;               // Maximum allowed version
    bool allow_fallback;             // Allow version fallback
    char** disabled_versions;        // Explicitly disabled versions
    size_t disabled_count;
} version_constraints_t;

// Weak configuration flags
typedef struct {
    bool allows_weak_ciphers;        // RC4, DES, etc.
    bool allows_null_encryption;     // NULL cipher suites
    bool allows_anonymous_auth;      // Anonymous authentication
    bool allows_export_ciphers;      // Export-grade ciphers
    bool uses_weak_hash;             // MD5, SHA-1 in signatures
    char** weak_items;               // List of weak config items
    size_t weak_count;
} weak_config_flags_t;

// Service metadata structure
typedef struct {
    service_type_t type;
    char* name;                      // Service name (e.g., "Apache HTTPD")
    char* version;                   // Service version
    char* daemon_name;               // Process/daemon name
    pid_t daemon_pid;                // Process ID (if running)
    bool is_running;                 // Is service currently running

    // Network configuration
    network_endpoint_t* endpoints;   // Listening endpoints
    size_t endpoint_count;

    // Service configuration
    char* config_file_path;          // Main configuration file
    char** additional_config_files;  // Additional config files
    size_t config_file_count;

    // Protocol usage (IDs of protocol assets this service uses)
    char** used_protocol_ids;        // Protocol asset IDs
    size_t used_protocol_count;

    // Certificate usage
    char* ssl_cert_path;             // SSL certificate path
    char* ssl_key_path;              // SSL private key path
    char* ca_cert_path;              // CA certificate path

    // Detection metadata
    detection_method_t detection_method;
    float confidence;                // Detection confidence
    time_t scan_time;
} service_metadata_t;

// Protocol metadata structure (centralized for TLS/SSH/etc.)
typedef struct {
    protocol_type_t type;
    char* name;                      // "TLS", "SSH", "IPsec"
    char* version;                   // Protocol version (e.g., "1.3", "2.0")
    char* usage;                     // Protocol usage: "server", "client", or NULL

    // Cipher suite configuration
    char** supported_cipher_suites;  // All supported cipher suites
    size_t supported_cipher_count;
    char** enabled_cipher_suites;    // Currently enabled cipher suites
    size_t enabled_cipher_count;

    // Version configuration
    char** supported_versions;       // Supported protocol versions
    size_t supported_version_count;
    char** enabled_versions;         // Enabled protocol versions
    size_t enabled_version_count;

    // Security configuration
    version_constraints_t version_constraints;
    weak_config_flags_t weak_configurations;
    security_profile_t security_profile;
    char** deprecated_features;
    size_t deprecated_count;

    // Source configuration
    char* config_file_path;          // Where configuration was found

    // TLS-specific fields
    bool supports_sni;               // Server Name Indication
    bool supports_alpn;              // Application Layer Protocol Negotiation
    bool supports_ocsp_stapling;     // OCSP stapling
    char** supported_curves;         // Supported elliptic curves
    size_t curve_count;

    // SSH-specific fields
    char** supported_kex;            // Key exchange algorithms
    size_t kex_count;
    char** supported_hostkey;        // Host key algorithms
    size_t hostkey_count;
    char** supported_mac;            // MAC algorithms
    size_t mac_count;

    // Detection metadata
    detection_method_t detection_method;
    float confidence;
    time_t scan_time;
} protocol_metadata_t;

// Service scanner statistics
typedef struct {
    // Service detection counters
    size_t services_detected_total;
    size_t services_running;
    size_t services_configured;

    // Per-service counters
    size_t apache_found;
    size_t nginx_found;
    size_t openssh_found;
    size_t postfix_found;
    size_t postgres_found;
    size_t mysql_found;

    // Protocol counters
    size_t protocols_extracted;
    size_t tls_protocols;
    size_t ssh_protocols;
    size_t ipsec_protocols;

    // Configuration analysis
    size_t configs_parsed;
    size_t configs_parse_failed;
    size_t weak_configs_found;

    // Network endpoints
    size_t endpoints_detected;
    size_t encrypted_endpoints;

    // Weakness detection
    size_t weak_tls_versions;        // TLS 1.0/1.1
    size_t weak_cipher_suites;       // RC4, DES, NULL
    size_t missing_features;         // Missing SNI, OCSP, etc.

    // Security profiles
    size_t modern_profile;
    size_t intermediate_profile;
    size_t old_profile;

    // Error tracking
    size_t permission_errors;
    size_t parse_errors;
    size_t process_scan_failures;
} service_scanner_stats_t;

// Service scanner configuration
typedef struct {
    // Detection options
    bool scan_running_processes;     // Scan for running services
    bool scan_config_files;          // Parse configuration files
    bool scan_systemd;               // Scan systemd services

    // Service selection
    bool detect_web_servers;         // Apache, Nginx
    bool detect_mail_servers;        // Postfix, Dovecot
    bool detect_ssh_servers;         // OpenSSH
    bool detect_vpn_services;        // OpenVPN, WireGuard
    bool detect_databases;           // PostgreSQL, MySQL

    // Network scanning
    bool map_network_endpoints;      // Parse /proc/net/tcp
    bool link_endpoints_to_services; // Map ports to services

    // Protocol extraction
    bool extract_protocols;          // Extract protocol metadata
    bool centralize_tls;             // Centralize TLS cipher suites

    // Privacy settings (for user config scanning)
    bool include_personal_data;      // Scan user configs when enabled

    // Weakness detection
    bool detect_weak_configs;        // Enable weakness detection
    bool classify_security_profile;  // Classify security profiles

    // Resource limits
    size_t max_services;             // Maximum services to scan
    int timeout_seconds;             // Timeout per service

    // Testing options
    bool include_fixtures;           // Include test fixtures in config paths
} service_scanner_config_t;

// Service scanner context
typedef struct {
    service_scanner_config_t config;
    struct asset_store* asset_store;
    struct scan_context* scan_context;  // For dedup support

    // Statistics
    service_scanner_stats_t stats;

    // Thread safety
    pthread_mutex_t mutex;
} service_scanner_context_t;

// Main service scanner API
service_scanner_context_t* service_scanner_create(
    const service_scanner_config_t* config,
    struct asset_store* store);
void service_scanner_destroy(service_scanner_context_t* context);

// Scanning operations
int service_scanner_scan_all(service_scanner_context_t* context);
int service_scanner_scan_running_services(service_scanner_context_t* context);
int service_scanner_scan_config_files(service_scanner_context_t* context);

// Service detection
int detect_apache_service(service_scanner_context_t* context);
int detect_nginx_service(service_scanner_context_t* context);
int detect_openssh_service(service_scanner_context_t* context);
int detect_postfix_service(service_scanner_context_t* context);

// Configuration parsing
service_metadata_t* parse_apache_config(const char* config_path);
service_metadata_t* parse_nginx_config(const char* config_path);
service_metadata_t* parse_sshd_config(const char* config_path);
protocol_metadata_t* parse_ssh_client_config(const char* config_path);
int scan_user_ssh_configs(service_scanner_context_t* context);
service_metadata_t* parse_postfix_config(const char* config_path);

// Protocol extraction (TLS centralization)
protocol_metadata_t* extract_tls_protocol(const char* config_path,
                                         const char* service_name);
protocol_metadata_t* extract_ssh_protocol(const char* config_path);

// Network endpoint detection
network_endpoint_t* parse_proc_net_tcp(size_t* count);
int map_endpoints_to_services(service_scanner_context_t* context,
                              network_endpoint_t* endpoints,
                              size_t count);

// Weakness detection
bool is_weak_tls_version(const char* version);
bool is_weak_cipher_suite(const char* cipher);
security_profile_t classify_tls_security_profile(
    const char** enabled_versions,
    size_t version_count,
    const char** enabled_ciphers,
    size_t cipher_count);

// Metadata operations
service_metadata_t* service_metadata_create(const char* name, service_type_t type);
void service_metadata_destroy(service_metadata_t* metadata);
protocol_metadata_t* protocol_metadata_create(const char* name, protocol_type_t type);
void protocol_metadata_destroy(protocol_metadata_t* metadata);

// Asset creation
struct crypto_asset* service_create_asset(const service_metadata_t* metadata);
struct crypto_asset* protocol_create_asset(const protocol_metadata_t* metadata);
char* service_create_detailed_json_metadata(const service_metadata_t* metadata);
char* protocol_create_detailed_json_metadata(const protocol_metadata_t* metadata);

// Relationship creation (Phase 7.3a)
int create_service_protocol_relationship(struct asset_store* store,
                                         const char* service_id,
                                         const char* protocol_id,
                                         float confidence);
int create_protocol_suite_relationship(struct asset_store* store,
                                      const char* protocol_id,
                                      const char* suite_id,
                                      float confidence);
int create_service_cert_relationship(struct asset_store* store,
                                     const char* service_id,
                                     const char* cert_id,
                                     float confidence);
int create_suite_algorithm_relationship(struct asset_store* store,
                                       const char* suite_id,
                                       const char* algorithm_id,
                                       float confidence);
int create_service_library_relationship(struct asset_store* store,
                                        const char* service_id,
                                        const char* library_id,
                                        float confidence);

// Service library dependency detection (Application Library Dependencies Gap)
int detect_service_library_dependencies(service_scanner_context_t* context,
                                       struct crypto_asset* service_asset,
                                       const service_metadata_t* metadata);

// Simple wrapper for YAML plugins (avoids type conflicts with plugin_schema.h)
int detect_service_library_dependencies_simple(struct asset_store* store,
                                               struct crypto_asset* service_asset,
                                               const char* process_name,
                                               pid_t pid);

// Count crypto library dependencies without creating assets (v1.7.2)
// Used for crypto relevance check before adding service to CBOM
int count_crypto_library_dependencies(const char* process_name, pid_t pid);

// PQC analysis (Phase 8.0)
float calculate_service_pqc_readiness(const char* service_id,
                                      struct asset_store* store);
char** generate_service_pqc_recommendations(const char* service_id,
                                           struct asset_store* store,
                                           size_t* count);

// Algorithm decomposition (Phase 8 completeness tweaks)
struct crypto_asset* create_algorithm_asset_from_components(const char* algorithm_name,
                                                            int key_size);
int decompose_cipher_suite_to_algorithms(struct asset_store* store,
                                         const char* suite_id,
                                         const char* kex,
                                         const char* auth,
                                         const char* enc,
                                         const char* mac);
const char* find_cert_id_by_path(struct asset_store* store, const char* cert_path);

// Configuration
service_scanner_config_t service_scanner_create_default_config(void);
void service_scanner_config_destroy(service_scanner_config_t* config);

// Statistics
service_scanner_stats_t service_scanner_get_stats(
    const service_scanner_context_t* context);

// Error handling
const char* service_scanner_get_last_error(void);
void service_scanner_clear_error(void);

// Utility functions
const char* service_type_to_string(service_type_t type);
const char* security_profile_to_string(security_profile_t profile);
bool is_service_running(const char* daemon_name);
pid_t get_service_pid(const char* daemon_name);
char* get_service_version(const char* daemon_name);

#endif // SERVICE_SCANNER_H
