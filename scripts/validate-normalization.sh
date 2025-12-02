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
# Validate normalization test vectors for backwards compatibility

set -e

echo "Validating normalization test vectors..."

# Build the project if not already built
if [[ ! -f "build/cbom-tests" ]]; then
    echo "Building project..."
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
fi

# Run normalization tests specifically
echo "Running normalization validation..."
if ./build/cbom-tests 2>&1 | grep -q "Normalization test results: .* passed, 0 failed"; then
    echo "✓ All normalization test vectors passed"
else
    echo "ERROR: Normalization test vectors failed"
    echo "This indicates a backwards compatibility break in normalization rules"
    echo "If this is intentional, update the specification version and test vectors"
    exit 1
fi

# Check that the normalization specification exists
if [[ ! -f "docs/NORMALIZATION.md" ]]; then
    echo "ERROR: Normalization specification not found at docs/NORMALIZATION.md"
    exit 1
fi

echo "✓ Normalization specification found"

# Validate that test vectors are frozen (check for specific expected IDs)
EXPECTED_VECTORS=(
    "0ca99974c101c72ba4462ea93131ed2c4ce6f99417c3a4c2f77ae8c0f95910ce"
    "971fea92f5353ab3e6a72d020fadabb34ac6edde4114f707d1921c575d056e56"
)

echo "Validating frozen test vector IDs..."
for expected_id in "${EXPECTED_VECTORS[@]}"; do
    if grep -q "$expected_id" src/normalization.c; then
        echo "✓ Found expected test vector ID: $expected_id"
    else
        echo "ERROR: Missing expected test vector ID: $expected_id"
        echo "Test vectors may have been modified without version increment"
        exit 1
    fi
done

echo "Normalization validation complete"
