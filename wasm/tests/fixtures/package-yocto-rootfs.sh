#!/bin/bash
set -euo pipefail

# Usage: ./package-yocto-rootfs.sh <rootfs-path> [output.tar.gz]
ROOTFS="${1:?Usage: $0 <rootfs-path> [output.tar.gz]}"
OUTPUT="${2:-wasm/tests/fixtures/yocto-qemuarm64-rootfs.tar.gz}"

if [ ! -d "$ROOTFS/usr" ] || [ ! -d "$ROOTFS/etc" ]; then
  echo "ERROR: $ROOTFS does not look like a rootfs (missing usr/ or etc/)"
  exit 1
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "Packaging rootfs from: $ROOTFS"
echo "Target: $OUTPUT"

# Copy only the directories the scanner needs.
# Use rsync to preserve symlinks and permissions.
# Include: usr/bin, usr/sbin, usr/lib, usr/lib64, etc, lib
# Exclude: large non-crypto files to keep fixture small

for dir in usr/bin usr/sbin usr/lib usr/lib64 etc lib; do
  if [ -d "$ROOTFS/$dir" ]; then
    mkdir -p "$TMPDIR/rootfs/$dir"
    # --copy-links dereferences symlinks; exit code 23 = dangling symlinks (expected
    # in Yocto rootfs where busybox applets point outside the copied subtree)
    rsync -a --copy-links \
      "$ROOTFS/$dir/" "$TMPDIR/rootfs/$dir/" 2>/dev/null || {
      rc=$?
      if [ $rc -ne 23 ]; then exit $rc; fi
    }
    echo "  Copied $dir/ ($(du -sh "$TMPDIR/rootfs/$dir" | cut -f1))"
  fi
done

# Also copy usr/local if it exists
if [ -d "$ROOTFS/usr/local" ]; then
  mkdir -p "$TMPDIR/rootfs/usr/local"
  rsync -a --copy-links \
    "$ROOTFS/usr/local/" "$TMPDIR/rootfs/usr/local/" 2>/dev/null || {
    rc=$?
    if [ $rc -ne 23 ]; then exit $rc; fi
  }
  echo "  Copied usr/local/ ($(du -sh "$TMPDIR/rootfs/usr/local" | cut -f1))"
fi

# Report what we captured
echo ""
echo "Fixture contents:"
echo "  Total files: $(find "$TMPDIR/rootfs" -type f | wc -l)"
echo "  ELF binaries: $(find "$TMPDIR/rootfs" -type f -exec file {} \; 2>/dev/null | grep -c 'ELF' || echo 0)"
echo "  Certificates: $(find "$TMPDIR/rootfs" -name '*.pem' -o -name '*.crt' -o -name '*.cer' | wc -l)"
echo "  Config files: $(find "$TMPDIR/rootfs/etc" -name '*.conf' -o -name '*_config' -o -name 'sshd_config' 2>/dev/null | wc -l)"
echo "  Total size: $(du -sh "$TMPDIR/rootfs" | cut -f1)"

# Package
mkdir -p "$(dirname "$OUTPUT")"
tar czf "$OUTPUT" -C "$TMPDIR" rootfs/
echo ""
echo "Created: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
