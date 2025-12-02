#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (c) 2025 Graziano Labs Corp.
#
# This file is part of cbom-generator.
#
# cbom-generator is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# For commercial licensing options, contact: sales@cipheriq.io
#
# scripts/create_plugin.sh - Fast plugin generation from template
# Usage: ./scripts/create_plugin.sh <name> <category> <port> [process_name] [parser]

set -e

PLUGIN_NAME="$1"
CATEGORY="$2"
PORT="$3"
PROCESS_NAME="${4:-${PLUGIN_NAME,,}}"
PARSER="${5:-ini}"

if [ -z "$PLUGIN_NAME" ] || [ -z "$CATEGORY" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <name> <category> <port> [process_name] [parser]"
    echo ""
    echo "Arguments:"
    echo "  name          - Service name (e.g., Tomcat, Cassandra)"
    echo "  category      - Category (database, web_server, mail_server, etc.)"
    echo "  port          - Primary port number"
    echo "  process_name  - Process name (optional, defaults to lowercase name)"
    echo "  parser        - Config parser (optional, defaults to 'ini')"
    echo ""
    echo "Examples:"
    echo "  $0 Tomcat application_server 8443 java apache"
    echo "  $0 Cassandra database 9042"
    echo "  $0 HAProxy load_balancer 443"
    exit 1
fi

PLUGIN_FILE="plugins/${PLUGIN_NAME,,}.yaml"

# Check if plugin already exists
if [ -f "$PLUGIN_FILE" ]; then
    echo "✗ Plugin already exists: $PLUGIN_FILE"
    echo "  Remove it first or use a different name"
    exit 1
fi

# Create plugin file
cat > "$PLUGIN_FILE" << EOF
# plugins/${PLUGIN_NAME,,}.yaml
plugin:
  plugin_schema_version: "1.0"
  name: "$PLUGIN_NAME TLS Scanner"
  version: "1.0.0"
  author: "CipherIQ Team"
  category: "$CATEGORY"
  description: "Detects $PLUGIN_NAME instances and extracts TLS configuration"
  priority: 50

detection:
  methods:
    - type: process
      names:
        - "${PROCESS_NAME}"

    - type: port
      ports: [$PORT]
      protocol: "tcp"
      check_ssl: true

    - type: config_file
      paths:
        - "/etc/${PLUGIN_NAME,,}/config"
        - "/etc/${PLUGIN_NAME,,}/${PLUGIN_NAME,,}.conf"
        - "/opt/${PLUGIN_NAME,,}/conf/config"
      required: false

config_extraction:
  files:
    - path: "\${DETECTED_CONFIG_DIR}/config"
      parser: "$PARSER"
      crypto_directives:
        - key: "ssl.enabled"
          type: "boolean"
          maps_to: "service.tls_enabled"

        - key: "ssl.certificate"
          type: "path"
          resolve: true
          maps_to: "certificate.path"

        - key: "ssl.key"
          type: "path"
          resolve: true
          maps_to: "private_key.path"

        - key: "ssl.ca_cert"
          type: "path"
          resolve: true
          maps_to: "ca_cert.path"

        - key: "ssl.protocols"
          type: "string"
          maps_to: "protocol.min_version"

        - key: "ssl.ciphers"
          type: "string_list"
          separator: ":"
          maps_to: "protocol.cipher_suites"
EOF

echo "✓ Created $PLUGIN_FILE"
echo ""
echo "Next steps:"
echo "1. Edit $PLUGIN_FILE and customize for $PLUGIN_NAME specifics:"
echo "   - Add more process names if needed"
echo "   - Add additional ports"
echo "   - Update config file paths"
echo "   - Customize crypto_directives for actual config format"
echo ""
echo "2. Test loading:"
echo "   ./build/cbom-generator --plugin-dir plugins --list-plugins | grep '$PLUGIN_NAME'"
echo ""
echo "3. Validate:"
echo "   ./tests/validate_plugin.sh $PLUGIN_FILE"
