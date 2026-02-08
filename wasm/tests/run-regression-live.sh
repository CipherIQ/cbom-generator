#!/bin/bash
set -euo pipefail

ROOTFS="${1:?Usage: $0 <rootfs-path>}"
NATIVE_OUT="/tmp/native-live-cbom.json"
WASM_TAR="/tmp/rootfs-live.tar.gz"
WASM_OUT="/tmp/wasm-live-cbom.json"

echo "=== Live Native vs WASM Regression ==="
echo "Rootfs: $ROOTFS"
echo ""

# Native scan
echo "--- Native scan ---"
time ./build/cbom-generator \
  --cross-arch \
  --discover-services \
  --plugin-dir plugins/embedded \
  --crypto-registry registry/crypto-registry-yocto.yaml \
  --format cyclonedx --cyclonedx-spec=1.7 \
  -o "$NATIVE_OUT" \
  "$ROOTFS/usr/bin" "$ROOTFS/usr/sbin" "$ROOTFS/usr/lib" "$ROOTFS/etc"

echo "Native: $(cat "$NATIVE_OUT" | jq '.components | length') components"
echo ""

# Package rootfs for WASM (same as what a user would upload)
echo "--- Packaging rootfs for WASM ---"
./wasm/tests/fixtures/package-yocto-rootfs.sh "$ROOTFS" "$WASM_TAR"
echo ""

# WASM scan
echo "--- WASM scan ---"
time node wasm/tests/run-scan.mjs \
  --input "$WASM_TAR" \
  --plugin-set embedded \
  --registry yocto \
  --output "$WASM_OUT"

echo "WASM: $(cat "$WASM_OUT" | jq '.components | length') components"
echo ""

# Compare
echo "--- Comparing ---"
node wasm/scripts/compare-cbom.js "$NATIVE_OUT" "$WASM_OUT"

# Cleanup
rm -f "$WASM_TAR"
