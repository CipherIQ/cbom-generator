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

/**
 * @file port_detector.h
 * @brief Port-based service detection with TLS probing
 *
 * Detects services by listening ports with optional TLS handshake testing
 *
 * @author CBOM Generator Team
 * @date 2025-11-17
 * @version 1.0
 */

#ifndef PORT_DETECTOR_H
#define PORT_DETECTOR_H

#include "plugin_schema.h"
#include "service_discovery.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detect service by listening port
 *
 * Parses /proc/net/tcp and /proc/net/tcp6 for listening ports.
 * Optionally performs TLS handshake probe.
 * Populates instance with port, bind_address, protocol, and tls_enabled.
 *
 * @param config Port detection configuration from YAML plugin
 * @param instance Output parameter - populated on success
 * @param enable_tls_probe Whether to perform TLS handshake test
 * @param timeout_ms TLS probe timeout in milliseconds
 * @return true if port detected, false otherwise
 */
bool port_detector_detect(const port_detection_config_t* config,
                           service_instance_t* instance,
                           bool enable_tls_probe,
                           int timeout_ms);

/**
 * Probe port for TLS support
 *
 * Attempts TLS handshake on specified port
 *
 * @param port Port number
 * @param timeout_ms Timeout in milliseconds
 * @return true if TLS handshake succeeds, false otherwise
 */
bool port_detector_probe_tls(uint16_t port, int timeout_ms);

/**
 * Parse /proc/net/tcp for listening ports
 *
 * @param ports Array of ports to check
 * @param port_count Number of ports
 * @param protocol "tcp" or "udp"
 * @param found_port Output parameter - detected port number
 * @param bind_address Output parameter - bind address (caller must free)
 * @return true if any port found listening, false otherwise
 */
bool port_detector_find_listening_port(const uint16_t* ports,
                                        int port_count,
                                        const char* protocol,
                                        uint16_t* found_port,
                                        char** bind_address);

/**
 * Convert hex address to string
 *
 * @param hex_addr Hex address from /proc/net/tcp
 * @param is_ipv6 Whether address is IPv6
 * @return Address string (caller must free) or NULL on error
 */
char* port_detector_hex_to_address(unsigned long hex_addr, bool is_ipv6);

#ifdef __cplusplus
}
#endif

#endif /* PORT_DETECTOR_H */
