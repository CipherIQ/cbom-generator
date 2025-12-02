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

# Property mapping validation script
# This script ensures that the CycloneDX property mappings haven't drifted
# from the FROZEN v1.0 specification

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== CBOM Property Mapping Validation ==="
echo "Validating against FROZEN v1.0 specification..."

# Check if property guide exists
PROPERTY_GUIDE="$PROJECT_ROOT/docs/CBOM_PROPERTY_GUIDE.md"
if [[ ! -f "$PROPERTY_GUIDE" ]]; then
    echo "ERROR: Property guide not found at $PROPERTY_GUIDE"
    exit 1
fi

# Verify property guide version
if ! grep -q "Version.*1\.0" "$PROPERTY_GUIDE"; then
    echo "ERROR: Property guide version is not 1.0"
    exit 1
fi

if ! grep -q "Status.*FROZEN" "$PROPERTY_GUIDE"; then
    echo "ERROR: Property guide is not marked as FROZEN"
    exit 1
fi

echo "✓ Property guide version 1.0 is FROZEN"

# Check component type mappings in source code
CONVERTER_SOURCE="$PROJECT_ROOT/src/cyclonedx_converter.c"
if [[ ! -f "$CONVERTER_SOURCE" ]]; then
    echo "ERROR: CycloneDX converter source not found at $CONVERTER_SOURCE"
    exit 1
fi

# Verify FROZEN comment exists
if ! grep -q "FROZEN v1.0 - Component type mappings (DO NOT MODIFY)" "$CONVERTER_SOURCE"; then
    echo "ERROR: FROZEN comment not found in converter source"
    exit 1
fi

echo "✓ Source code contains FROZEN v1.0 marker"

# Verify specific component type mappings
declare -A EXPECTED_MAPPINGS=(
    ["ASSET_TYPE_ALGORITHM"]="CYCLONEDX_COMPONENT_LIBRARY"
    ["ASSET_TYPE_KEY"]="CYCLONEDX_COMPONENT_DATA"
    ["ASSET_TYPE_CERTIFICATE"]="CYCLONEDX_COMPONENT_DATA"
    ["ASSET_TYPE_LIBRARY"]="CYCLONEDX_COMPONENT_LIBRARY"
    ["ASSET_TYPE_PROTOCOL"]="CYCLONEDX_COMPONENT_LIBRARY"
    ["ASSET_TYPE_SERVICE"]="CYCLONEDX_COMPONENT_OPERATING_SYSTEM"
)

for cbom_type in "${!EXPECTED_MAPPINGS[@]}"; do
    expected_cyclonedx="${EXPECTED_MAPPINGS[$cbom_type]}"
    
    # Check if mapping exists in source
    if ! grep -A 3 "\.cbom_type = $cbom_type" "$CONVERTER_SOURCE" | grep -q "\.cyclonedx_type = $expected_cyclonedx"; then
        echo "ERROR: Mapping drift detected for $cbom_type"
        echo "Expected: $cbom_type -> $expected_cyclonedx"
        exit 1
    fi
done

echo "✓ All component type mappings are correct"

# Verify property namespace prefixes
declare -a EXPECTED_NAMESPACES=(
    "cbom:algo:"
    "cbom:cert:"
    "cbom:key:"
    "cbom:proto:"
    "cbom:lib:"
    "cbom:svc:"
    "cbom:ctx:"
)

for namespace in "${EXPECTED_NAMESPACES[@]}"; do
    if ! grep -q "\"$namespace" "$CONVERTER_SOURCE"; then
        echo "ERROR: Property namespace $namespace not found in source"
        exit 1
    fi
done

echo "✓ All property namespaces are present"

# Verify required property counts haven't changed
declare -A EXPECTED_REQUIRED_COUNTS=(
    ["ALGORITHM_REQUIRED_PROPERTIES"]=4
    ["CERTIFICATE_REQUIRED_PROPERTIES"]=6
    ["KEY_REQUIRED_PROPERTIES"]=3
    ["PROTOCOL_REQUIRED_PROPERTIES"]=2
    ["LIBRARY_REQUIRED_PROPERTIES"]=2
    ["SERVICE_REQUIRED_PROPERTIES"]=2
)

for prop_array in "${!EXPECTED_REQUIRED_COUNTS[@]}"; do
    expected_count="${EXPECTED_REQUIRED_COUNTS[$prop_array]}"
    
    # Count array elements in source more precisely
    actual_count=$(awk "/static const property_definition_t $prop_array\[\]/{flag=1; next} flag && /^};/{flag=0} flag && /\{\"cbom:/{count++} END{print count+0}" "$CONVERTER_SOURCE")
    
    if [[ "$actual_count" -ne "$expected_count" ]]; then
        echo "ERROR: Property count drift detected for $prop_array"
        echo "Expected: $expected_count, Found: $actual_count"
        exit 1
    fi
done

echo "✓ Required property counts are stable"

# Check for forbidden component types
declare -a FORBIDDEN_TYPES=(
    "application"
    "framework"
    "container"
    "device"
    "file"
    "firmware"
)

for forbidden_type in "${FORBIDDEN_TYPES[@]}"; do
    if grep -q "\"$forbidden_type\"" "$CONVERTER_SOURCE"; then
        echo "ERROR: Forbidden component type '$forbidden_type' found in source"
        exit 1
    fi
done

echo "✓ No forbidden component types found"

# Verify CycloneDX version is pinned to 1.6
if ! grep -q 'json_object_new_string("1.6")' "$CONVERTER_SOURCE"; then
    echo "ERROR: CycloneDX spec version is not pinned to 1.6"
    exit 1
fi

echo "✓ CycloneDX spec version is pinned to 1.6"

# Build and run property drift tests if build directory exists
BUILD_DIR="$PROJECT_ROOT/build"
if [[ -d "$BUILD_DIR" ]]; then
    echo "Running property drift tests..."
    
    cd "$BUILD_DIR"
    if make cbom-tests >/dev/null 2>&1; then
        if ./cbom-tests 2>/dev/null | grep -q "Property drift detection tests passed"; then
            echo "✓ Property drift tests passed"
        else
            echo "ERROR: Property drift tests failed"
            exit 1
        fi
    else
        echo "WARNING: Could not build tests to verify property drift"
    fi
fi

echo ""
echo "=== Property Mapping Validation Complete ==="
echo "✅ All property mappings are stable and compliant with FROZEN v1.0 spec"
echo "✅ Component type mappings are correct"
echo "✅ Property namespaces are preserved"
echo "✅ Required property counts are stable"
echo "✅ No forbidden component types detected"
echo "✅ CycloneDX version is pinned correctly"

exit 0
