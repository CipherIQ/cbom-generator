#!/bin/bash
set -euo pipefail

FIXTURE_TAR="wasm/tests/fixtures/yocto-qemuarm64-rootfs.tar.gz"
REFERENCE="wasm/tests/fixtures/yocto-qemuarm64-native-reference.json"
WASM_OUT="/tmp/wasm-regression-cbom.json"

echo "=== WASM Regression Test ==="
echo ""

# Check prerequisites
if [ ! -f "$FIXTURE_TAR" ]; then
  echo "ERROR: Fixture not found: $FIXTURE_TAR"
  echo "Run: ./wasm/tests/fixtures/package-yocto-rootfs.sh \$ROOTFS"
  exit 1
fi

if [ ! -f "$REFERENCE" ]; then
  echo "ERROR: Native reference CBOM not found: $REFERENCE"
  echo "Generate it with the native build first."
  exit 1
fi

echo "Fixture: $FIXTURE_TAR ($(du -sh "$FIXTURE_TAR" | cut -f1))"
echo "Reference: $REFERENCE ($(cat "$REFERENCE" | jq '.components | length') components)"
echo ""

# --- WASM scan ---
echo "--- Running WASM scan ---"
time node wasm/tests/run-scan.mjs \
  --input "$FIXTURE_TAR" \
  --plugin-set embedded \
  --registry yocto \
  --output "$WASM_OUT"

echo ""
echo "WASM output: $(cat "$WASM_OUT" | jq '.components | length') components"
echo ""

# --- Compare against committed native reference ---
echo "--- Comparing against native reference ---"
node wasm/scripts/compare-cbom.js "$REFERENCE" "$WASM_OUT"
