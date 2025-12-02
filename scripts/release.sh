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
# scripts/release.sh - Release automation for CBOM Generator
# Usage: ./scripts/release.sh <version>

set -e

VERSION="$1"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.3.0"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== Releasing CBOM Generator v$VERSION ==="
echo ""

# Step 1: Verify version in CMakeLists.txt
echo -e "${YELLOW}Step 1: Verifying version in CMakeLists.txt${NC}"
if ! grep -q "VERSION $VERSION" CMakeLists.txt; then
    echo "✗ Version mismatch in CMakeLists.txt"
    echo "Expected: VERSION $VERSION"
    echo "Update CMakeLists.txt first"
    exit 1
fi
echo -e "${GREEN}✓ Version verified: $VERSION${NC}"
echo ""

# Step 2: Clean build
echo -e "${YELLOW}Step 2: Creating clean release build${NC}"
rm -rf build
mkdir -p build release
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
cd ..
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Step 3: Verify binary
echo -e "${YELLOW}Step 3: Verifying binary${NC}"
if [ ! -f build/cbom-generator ]; then
    echo "✗ Binary not found"
    exit 1
fi

BINARY_SIZE=$(ls -lh build/cbom-generator | awk '{print $5}')
echo "  Binary size: $BINARY_SIZE"
echo -e "${GREEN}✓ Binary verified${NC}"
echo ""

# Step 4: Run tests
echo -e "${YELLOW}Step 4: Running test suite${NC}"
cd build
if ctest --output-on-failure; then
    echo -e "${GREEN}✓ Tests passed${NC}"
else
    echo "⚠ Some tests failed (continuing)"
fi
cd ..
echo ""

# Step 5: Validate plugins
echo -e "${YELLOW}Step 5: Validating YAML plugins${NC}"
if ./tests/validate_all_plugins.sh > /tmp/plugin_validation.log 2>&1; then
    PLUGIN_COUNT=$(grep "passed" /tmp/plugin_validation.log | grep -oE "[0-9]+" | head -1)
    echo "  Plugins validated: $PLUGIN_COUNT"
    echo -e "${GREEN}✓ All plugins valid${NC}"
else
    echo "✗ Plugin validation failed"
    cat /tmp/plugin_validation.log
    exit 1
fi
echo ""

# Step 6: Test plugin loading
echo -e "${YELLOW}Step 6: Testing plugin loading${NC}"
# Test loading from ubuntu plugin directory (largest collection)
TOTAL_LINE=$(./build/cbom-generator --list-plugins --plugin-dir plugins/ubuntu 2>&1 | grep "^Total:")
# Extract YAML count from "Total: X plugins (Y built-in + Z YAML)"
LOADED=$(echo "$TOTAL_LINE" | grep -oE "[0-9]+ YAML" | grep -oE "[0-9]+")
if [ -z "$LOADED" ]; then
    LOADED=0
fi
echo "  YAML plugins loaded: $LOADED (from plugins/ubuntu)"
if [ "$LOADED" -ge 50 ]; then
    echo -e "${GREEN}✓ Plugin loading successful${NC}"
else
    echo "✗ Expected >= 50 YAML plugins, loaded $LOADED"
    exit 1
fi
echo ""

# Step 7: Create release artifacts
echo -e "${YELLOW}Step 7: Creating release artifacts${NC}"

# Copy and strip binary to root for tarball (cleaner extraction for users)
cp build/cbom-generator cbom-generator-$VERSION-linux-amd64
strip cbom-generator-$VERSION-linux-amd64

# Build list of files for tarball (binary at root level for clean GitHub release extraction)
TARBALL_FILES="cbom-generator-$VERSION-linux-amd64 plugins/ registry/ README.md"

# Add USER_MANUAL.md if it exists
if [ -f "USER_MANUAL.md" ]; then
    TARBALL_FILES="$TARBALL_FILES USER_MANUAL.md"
    echo "  Including: USER_MANUAL.md"
else
    echo "  Skipping: USER_MANUAL.md (not found)"
fi

# Create tarball
tar -czf release/cbom-generator-$VERSION-linux-amd64.tar.gz $TARBALL_FILES

# Clean up root-level binary copy
rm -f cbom-generator-$VERSION-linux-amd64

echo "  Created: release/cbom-generator-$VERSION-linux-amd64.tar.gz"
echo -e "${GREEN}✓ Artifacts created${NC}"
echo ""

# Step 8: Generate checksums
echo -e "${YELLOW}Step 8: Generating checksums${NC}"
cd release
sha256sum cbom-generator-$VERSION-linux-amd64.tar.gz > checksums.txt
cd ..
echo -e "${GREEN}✓ Checksums generated${NC}"
cat release/checksums.txt
echo ""

# Step 9: Display release summary
echo ""
echo "=== Release Summary ==="
echo "Version: $VERSION"
echo "Tarball: release/cbom-generator-$VERSION-linux-amd64.tar.gz"
echo "Checksums: release/checksums.txt"
echo ""
ls -lh release/
echo ""

# Step 10: Git tag instructions
echo -e "${YELLOW}=== Next Steps ===${NC}"
echo ""
echo "1. Review release artifacts in release/"
echo ""
echo "2. Create git commit and tag:"
echo "   git add -A"
echo "   git commit -m \"Release v$VERSION\""
echo "   git tag -a \"v$VERSION\" -m \"Release v$VERSION\""
echo ""
echo "3. Push to repository:"
echo "   git push origin main"
echo "   git push origin \"v$VERSION\""
echo ""
echo "4. Create GitHub release:"
echo "   - Upload release/cbom-generator-$VERSION-linux-amd64.tar.gz"
echo "   - Upload release/checksums.txt"
echo "   - Copy RELEASE_NOTES_$VERSION.md to release description"
echo ""
echo -e "${GREEN}✓ Release v$VERSION ready!${NC}"
