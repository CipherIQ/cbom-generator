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
# Validate that pinned schemas haven't changed

set -e

SCHEMA_DIR="tests/schemas"
CYCLONE_DX_SCHEMA="$SCHEMA_DIR/cyclonedx-1.6.schema.json"
CYCLONE_DX_URL="https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json"

echo "Validating pinned schemas..."

# Create schema directory if it doesn't exist
mkdir -p "$SCHEMA_DIR"

# Check if CycloneDX schema exists and validate checksum
if [[ -f "$CYCLONE_DX_SCHEMA" ]]; then
    # Calculate current checksum
    CURRENT_CHECKSUM=$(sha256sum "$CYCLONE_DX_SCHEMA" | cut -d' ' -f1)
    
    # Read expected checksum
    EXPECTED_CHECKSUM_FILE="$SCHEMA_DIR/cyclonedx-1.6.schema.json.sha256"
    if [[ -f "$EXPECTED_CHECKSUM_FILE" ]]; then
        EXPECTED_CHECKSUM=$(cat "$EXPECTED_CHECKSUM_FILE" | tr -d '\n\r ')
        
        if [[ "$CURRENT_CHECKSUM" != "$EXPECTED_CHECKSUM" ]]; then
            echo "ERROR: CycloneDX schema checksum mismatch!"
            echo "Expected: $EXPECTED_CHECKSUM"
            echo "Current:  $CURRENT_CHECKSUM"
            echo "Schema file may have been modified or corrupted."
            exit 1
        else
            echo "✓ CycloneDX schema checksum validated"
        fi
    else
        echo "WARNING: No checksum file found for CycloneDX schema"
        echo "Creating checksum file: $EXPECTED_CHECKSUM_FILE"
        echo "$CURRENT_CHECKSUM" > "$EXPECTED_CHECKSUM_FILE"
    fi
else
    echo "CycloneDX schema not found, downloading..."
    
    # Download schema
    if command -v curl >/dev/null 2>&1; then
        curl -s -o "$CYCLONE_DX_SCHEMA" "$CYCLONE_DX_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$CYCLONE_DX_SCHEMA" "$CYCLONE_DX_URL"
    else
        echo "ERROR: Neither curl nor wget available for downloading schema"
        exit 1
    fi
    
    # Generate checksum
    SCHEMA_CHECKSUM=$(sha256sum "$CYCLONE_DX_SCHEMA" | cut -d' ' -f1)
    echo "$SCHEMA_CHECKSUM" > "$SCHEMA_DIR/cyclonedx-1.6.schema.json.sha256"
    
    echo "✓ Downloaded and pinned CycloneDX schema (checksum: $SCHEMA_CHECKSUM)"
fi

# Validate schema is valid JSON
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import json; json.load(open('$CYCLONE_DX_SCHEMA'))" >/dev/null 2>&1; then
        echo "ERROR: CycloneDX schema is not valid JSON"
        exit 1
    fi
    echo "✓ CycloneDX schema is valid JSON"
elif command -v jq >/dev/null 2>&1; then
    if ! jq empty "$CYCLONE_DX_SCHEMA" >/dev/null 2>&1; then
        echo "ERROR: CycloneDX schema is not valid JSON"
        exit 1
    fi
    echo "✓ CycloneDX schema is valid JSON"
else
    echo "WARNING: Neither python3 nor jq available, skipping JSON validation"
fi

echo "Schema validation complete"
