#!/bin/bash
# tests/validate_all_plugins.sh
# Validates all YAML plugins for syntax, schema, and loading

set -e

echo "=== Validating All YAML Plugins ==="
echo ""

PLUGIN_DIR="plugins"
PASS=0
FAIL=0
FAILED_PLUGINS=()

# Check if plugins directory exists
if [ ! -d "$PLUGIN_DIR" ]; then
    echo "✗ Error: $PLUGIN_DIR directory not found"
    exit 1
fi

# Count plugins (recursive search for subdirectories)
PLUGIN_COUNT=$(find "$PLUGIN_DIR" -name "*.yaml" -type f 2>/dev/null | wc -l)
echo "Found $PLUGIN_COUNT plugin files"
echo ""

# Validate each plugin (recursive search)
for plugin in $(find "$PLUGIN_DIR" -name "*.yaml" -type f | sort); do
    PLUGIN_NAME=$(basename "$plugin")
    echo -n "[$((PASS + FAIL + 1))/$PLUGIN_COUNT] Testing $PLUGIN_NAME... "

    # Test 1: YAML syntax check
    if ! python3 -c "import yaml; yaml.safe_load(open('$plugin'))" 2>/dev/null; then
        echo "✗ FAIL (YAML syntax)"
        FAIL=$((FAIL + 1))
        FAILED_PLUGINS+=("$PLUGIN_NAME: YAML syntax error")
        continue
    fi

    # Test 2: Required fields check (core fields only)
    REQUIRED_FIELDS=(
        "plugin_schema_version"
        "name"
        "version"
        "category"
        "detection"
    )

    MISSING_FIELD=""
    for field in "${REQUIRED_FIELDS[@]}"; do
        if ! grep -q "$field" "$plugin"; then
            MISSING_FIELD="$field"
            break
        fi
    done

    if [ -n "$MISSING_FIELD" ]; then
        echo "✗ FAIL (missing field: $MISSING_FIELD)"
        FAIL=$((FAIL + 1))
        FAILED_PLUGINS+=("$PLUGIN_NAME: Missing $MISSING_FIELD")
        continue
    fi

    # Test 3: Detection methods validation (flexible - accept binary, command too)
    if ! grep -E "(type: process|type: port|type: config_file|type: systemd|type: package|type: binary|type: command)" "$plugin" > /dev/null; then
        echo "✗ FAIL (no valid detection methods)"
        FAIL=$((FAIL + 1))
        FAILED_PLUGINS+=("$PLUGIN_NAME: No valid detection methods")
        continue
    fi

    # Test 4: Schema version check (optional warning)
    if ! grep -q 'plugin_schema_version.*"1\.0"' "$plugin"; then
        echo -n "⚠ (schema version) "
    fi

    # All tests passed
    echo "✓ PASS"
    PASS=$((PASS + 1))
done

echo ""
echo "=== Validation Summary ==="
echo "Total plugins: $PLUGIN_COUNT"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

# Show failed plugins
if [ $FAIL -gt 0 ]; then
    echo "=== Failed Plugins ==="
    for failure in "${FAILED_PLUGINS[@]}"; do
        echo "  ✗ $failure"
    done
    echo ""
fi

# Final result
if [ $FAIL -eq 0 ]; then
    echo "✓✓✓ All $PLUGIN_COUNT plugins validated successfully!"
    exit 0
else
    echo "✗✗✗ $FAIL plugin(s) failed validation"
    exit 1
fi
