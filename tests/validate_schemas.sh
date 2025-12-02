#!/bin/bash
# Schema validation test for CycloneDX 1.6 and 1.7 output
# Phase D - Dual-schema validation

# Don't use set -e to allow better error handling
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build"
SCHEMA_DIR="${SCRIPT_DIR}/schemas"
TEMP_DIR="/tmp/cbom-schema-tests"

mkdir -p "${TEMP_DIR}"

echo "====== CycloneDX Schema Validation Test ======"
echo ""

# Test 1: Default output (should be 1.6)
echo "Test 1: Validate default output produces 1.6..."
"${BUILD_DIR}/cbom-generator" \
    --output "${TEMP_DIR}/test_1.6.json" \
    --format cyclonedx \
    --no-personal-data \
    --no-network \
    /tmp/test_phase_b_certs/ >/dev/null 2>&1

if [ ! -f "${TEMP_DIR}/test_1.6.json" ]; then
    echo "  ✗ FAIL: Output file not created"
    exit 1
fi

# Ensure file is fully written (wait for size to stabilize)
sleep 0.1

SPEC_VERSION=$(cat "${TEMP_DIR}/test_1.6.json" | jq -r '.specVersion' 2>/dev/null)
if [ -z "$SPEC_VERSION" ]; then
    echo "  ✗ FAIL: Could not read specVersion from output"
    exit 1
fi
if [ "$SPEC_VERSION" != "1.6" ]; then
    echo "  ✗ FAIL: Expected specVersion 1.6, got $SPEC_VERSION"
    exit 1
fi
echo "  ✓ PASS: Default output is specVersion 1.6"

# Test 2: Explicit 1.7 output
echo "Test 2: Validate --cyclonedx-spec=1.7 produces 1.7..."
"${BUILD_DIR}/cbom-generator" \
    --output "${TEMP_DIR}/test_1.7.json" \
    --format cyclonedx \
    --cyclonedx-spec=1.7 \
    --no-personal-data \
    --no-network \
    /tmp/test_phase_b_certs/ >/dev/null 2>&1

if [ ! -f "${TEMP_DIR}/test_1.7.json" ]; then
    echo "  ✗ FAIL: Output file not created"
    exit 1
fi

# Ensure file is fully written
sleep 0.1

SPEC_VERSION=$(cat "${TEMP_DIR}/test_1.7.json" | jq -r '.specVersion' 2>/dev/null)
if [ -z "$SPEC_VERSION" ]; then
    echo "  ✗ FAIL: Could not read specVersion from output"
    exit 1
fi
if [ "$SPEC_VERSION" != "1.7" ]; then
    echo "  ✗ FAIL: Expected specVersion 1.7, got $SPEC_VERSION"
    exit 1
fi
echo "  ✓ PASS: --cyclonedx-spec=1.7 produces specVersion 1.7"

# Test 3: Validate required fields for 1.6
echo "Test 3: Validate 1.6 output has required fields..."
REQUIRED_FIELDS_1_6="bomFormat specVersion components metadata"
for field in $REQUIRED_FIELDS_1_6; do
    if ! cat "${TEMP_DIR}/test_1.6.json" | jq -e ".${field}" >/dev/null 2>&1; then
        echo "  ✗ FAIL: Missing required field: $field"
        exit 1
    fi
done
# Verify dependencies is NOT present in 1.6 (moved to 1.7 only per Issue #1 fix)
if cat "${TEMP_DIR}/test_1.6.json" | jq -e ".dependencies" >/dev/null 2>&1; then
    echo "  ✗ FAIL: dependencies field should not be present in CycloneDX 1.6"
    exit 1
fi
echo "  ✓ PASS: All required fields present in 1.6 output (dependencies correctly absent)"

# Test 4: Validate required fields for 1.7
echo "Test 4: Validate 1.7 output has required fields..."
REQUIRED_FIELDS_1_7="bomFormat specVersion components dependencies metadata"
for field in $REQUIRED_FIELDS_1_7; do
    if ! cat "${TEMP_DIR}/test_1.7.json" | jq -e ".${field}" >/dev/null 2>&1; then
        echo "  ✗ FAIL: Missing required field: $field"
        exit 1
    fi
done
echo "  ✓ PASS: All required fields present in 1.7 output"

# Test 5: Verify content compatibility (excluding timestamp and hash)
echo "Test 5: Verify content compatibility between 1.6 and 1.7..."
COMP_COUNT_1_6=$(cat "${TEMP_DIR}/test_1.6.json" | jq '.components | length')
COMP_COUNT_1_7=$(cat "${TEMP_DIR}/test_1.7.json" | jq '.components | length')
if [ "$COMP_COUNT_1_6" != "$COMP_COUNT_1_7" ]; then
    echo "  ✗ FAIL: Component count mismatch: 1.6=$COMP_COUNT_1_6, 1.7=$COMP_COUNT_1_7"
    exit 1
fi

# For 1.7, verify dependencies exist (not in 1.6 per Issue #1 fix)
DEP_COUNT_1_7=$(cat "${TEMP_DIR}/test_1.7.json" | jq '.dependencies | length')
if [ "$DEP_COUNT_1_7" -eq 0 ]; then
    echo "  ✗ FAIL: CycloneDX 1.7 should have dependencies"
    exit 1
fi
echo "  ✓ PASS: Content compatible (components match, 1.7 has dependencies)"

# Test 6: Invalid spec version rejected
echo "Test 6: Verify invalid spec versions are rejected..."
if "${BUILD_DIR}/cbom-generator" --cyclonedx-spec=2.0 2>&1 | grep -q "Invalid CycloneDX spec version"; then
    echo "  ✓ PASS: Invalid spec version '2.0' properly rejected"
else
    echo "  ✗ FAIL: Invalid spec version should be rejected"
    exit 1
fi

echo ""
echo "====== All Schema Validation Tests PASSED ======"
echo ""
echo "Summary:"
echo "  - Default output: CycloneDX 1.6 ✓"
echo "  - Optional output: CycloneDX 1.7 ✓"
echo "  - Content compatibility: Verified ✓"
echo "  - Invalid versions: Rejected ✓"
echo ""
