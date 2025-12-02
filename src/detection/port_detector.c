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
 * @file port_detector.c
 * @brief Port-based service detection implementation with TLS probing
 */

#define _GNU_SOURCE
#include "detection/port_detector.h"
#include "secure_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

char* port_detector_hex_to_address(unsigned long hex_addr, bool is_ipv6) {
    if (is_ipv6) {
        // IPv6 not yet implemented
        return strdup("::");
    }

    struct in_addr addr;
    addr.s_addr = (in_addr_t)hex_addr;

    char addr_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str))) {
        return NULL;
    }

    return strdup(addr_str);
}

bool port_detector_find_listening_port(const uint16_t* ports,
                                        int port_count,
                                        const char* protocol,
                                        uint16_t* found_port,
                                        char** bind_address) {
    if (!ports || port_count == 0 || !found_port || !bind_address) {
        return false;
    }

    *found_port = 0;
    *bind_address = NULL;

    // Determine which /proc file to read
    const char* proc_file = "/proc/net/tcp";
    if (protocol && strcmp(protocol, "udp") == 0) {
        proc_file = "/proc/net/udp";
    }

    FILE* fp = fopen(proc_file, "r");
    if (!fp) {
        return false;
    }

    char line[256];
    // Skip header
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    bool found = false;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long local_addr, remote_addr;
        int local_port, remote_port, state;

        // Parse line
        int parsed = sscanf(line, "%*d: %lx:%x %lx:%x %x",
                           &local_addr, &local_port,
                           &remote_addr, &remote_port, &state);

        if (parsed != 5) {
            continue;
        }

        // Check if listening (state 0x0A = LISTEN for TCP)
        if (strcmp(protocol ? protocol : "tcp", "tcp") == 0) {
            if (state != 0x0A) {  // Not listening
                continue;
            }
        }

        // Check if port matches any configured port
        for (int i = 0; i < port_count; i++) {
            if (local_port == ports[i]) {
                *found_port = (uint16_t)local_port;
                *bind_address = port_detector_hex_to_address(local_addr, false);
                found = true;
                break;
            }
        }

        if (found) {
            break;
        }
    }

    fclose(fp);
    return found;
}

/**
 * Get process name that owns a specific port (Phase 3)
 *
 * Maps: port to inode (from /proc/net/tcp) to PID (from /proc/PID/fd) to process name
 *
 * @param port Port number to check
 * @param protocol "tcp" or "udp"
 * @param process_name Output buffer for process name (min 256 bytes)
 * @return true if process found, false otherwise
 */
static bool port_detector_get_process_for_port(uint16_t port, const char* protocol, char* process_name) {
    if (!protocol || !process_name) {
        return false;
    }

    // Read /proc/net/tcp to find inode for this port
    const char* proc_file = strcmp(protocol, "udp") == 0 ? "/proc/net/udp" : "/proc/net/tcp";
    FILE* fp = fopen(proc_file, "r");
    if (!fp) {
        return false;
    }

    char line[256];
    unsigned long inode = 0;
    bool found_inode = false;

    // Skip header
    if (fgets(line, sizeof(line), fp)) {
        while (fgets(line, sizeof(line), fp)) {
            unsigned long local_addr;
            int local_port;
            unsigned long remote_addr;
            int remote_port;
            int state;
            unsigned long ino;

            // Parse: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
            if (sscanf(line, "%*d: %lx:%x %lx:%x %x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                      &local_addr, &local_port, &remote_addr, &remote_port, &state, &ino) == 6) {
                if (local_port == port) {
                    inode = ino;
                    found_inode = true;
                    break;
                }
            }
        }
    }
    fclose(fp);

    if (!found_inode || inode == 0) {
        return false;
    }

    // Search /proc/*/fd/* for socket with this inode
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "find /proc/*/fd -lname 'socket:\\[%lu\\]' 2>/dev/null | head -1", inode);

    FILE* find_fp = popen(cmd, "r");
    if (!find_fp) {
        return false;
    }

    char fd_path[256] = {0};
    if (!fgets(fd_path, sizeof(fd_path), find_fp)) {
        pclose(find_fp);
        return false;
    }
    pclose(find_fp);

    // Extract PID from path: /proc/PID/fd/N
    fd_path[strcspn(fd_path, "\n")] = '\0';
    int pid = 0;
    if (sscanf(fd_path, "/proc/%d/fd/", &pid) != 1 || pid <= 0) {
        return false;
    }

    // Read process name from /proc/PID/comm
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

    FILE* comm_fp = fopen(comm_path, "r");
    if (!comm_fp) {
        return false;
    }

    if (fgets(process_name, 256, comm_fp)) {
        process_name[strcspn(process_name, "\n")] = '\0';
        fclose(comm_fp);
        return true;
    }

    fclose(comm_fp);
    return false;
}

bool port_detector_probe_tls(uint16_t port, int timeout_ms) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return false;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        return false;
    }

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Connect to localhost
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        SSL_CTX_free(ctx);
        return false;
    }

    // Create SSL connection
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        close(sock);
        SSL_CTX_free(ctx);
        return false;
    }

    SSL_set_fd(ssl, sock);

    // Attempt TLS handshake
    bool tls_supported = (SSL_connect(ssl) > 0);

    // Cleanup
    if (tls_supported) {
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return tls_supported;
}

bool port_detector_detect(const port_detection_config_t* config,
                           service_instance_t* instance,
                           bool enable_tls_probe,
                           int timeout_ms) {
    if (!config || !instance) {
        return false;
    }

    if (config->port_count == 0) {
        return false;
    }

    // Find listening port
    uint16_t found_port = 0;
    char* bind_address = NULL;

    const char* protocol = config->protocol ? config->protocol : "tcp";

    if (!port_detector_find_listening_port(config->ports, config->port_count,
                                            protocol, &found_port, &bind_address)) {
        return false;
    }

    // Phase 3: Validate process ownership if requested
    if (config->validate_process && config->expected_process_count > 0) {
        char actual_process[256] = {0};
        if (!port_detector_get_process_for_port(found_port, protocol, actual_process)) {
            // Could not determine process - reject detection
            free(bind_address);
            return false;
        }

        // Check if actual process matches any expected process
        bool process_matches = false;
        for (int i = 0; i < config->expected_process_count; i++) {
            const char* expected = config->expected_processes[i];
            // Support partial match (e.g., "nginx" matches "nginx: worker process")
            if (strstr(actual_process, expected) != NULL) {
                process_matches = true;
                break;
            }
        }

        if (!process_matches) {
            // Wrong process owns this port - reject detection
            free(bind_address);
            return false;
        }
    }

    // Populate instance
    bool tls_detected = false;

    // Perform TLS probe if requested and it's TCP
    if (enable_tls_probe && config->check_ssl &&
        strcmp(protocol, "tcp") == 0 && found_port > 0) {
        tls_detected = port_detector_probe_tls(found_port, timeout_ms);
    }

    service_instance_set_network_info(instance, found_port, bind_address,
                                       protocol, tls_detected);

    free(bind_address);
    return true;
}
