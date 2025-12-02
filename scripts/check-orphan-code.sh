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
# Check for orphaned source files not included in build or tests

set -e

echo "Checking for orphaned source files..."

# Find all .c and .h files
ALL_C_FILES=$(find src/ -name "*.c" -type f | sort)
ALL_H_FILES=$(find include/ src/ -name "*.h" -type f | sort)
TEST_FILES=$(find tests/ -name "*.c" -type f 2>/dev/null | sort || true)

# Extract files referenced in CMakeLists.txt (including variable definitions)
CMAKE_REFERENCED=$(grep -E "(add_executable|add_library|target_sources|set.*SOURCES)" CMakeLists.txt | \
                  grep -oE '[a-zA-Z0-9_/.-]+\.(c|h)' | sort | uniq || true)

# Also check for files in SOURCES variable definitions
SOURCES_VARS=$(grep -A 10 "set.*SOURCES" CMakeLists.txt | \
              grep -oE '[a-zA-Z0-9_/.-]+\.(c|h)' | sort | uniq || true)

# Combine all referenced files
ALL_REFERENCED="$CMAKE_REFERENCED $SOURCES_VARS"

# Check for orphaned .c files
ORPHANED_C=""
for file in $ALL_C_FILES; do
    # Skip main.c as it's explicitly handled
    if [[ "$file" == "src/main.c" ]]; then
        continue
    fi
    
    # Check if file is referenced in build system
    if ! echo "$ALL_REFERENCED" | grep -q "$(basename "$file")"; then
        # Check if it's a test file
        if ! echo "$TEST_FILES" | grep -q "$file"; then
            ORPHANED_C="$ORPHANED_C $file"
        fi
    fi
done

# Check for orphaned .h files
ORPHANED_H=""
for file in $ALL_H_FILES; do
    # Skip generated files
    if [[ "$file" == *".in" ]] || [[ "$file" == *"provenance.h" ]]; then
        continue
    fi
    
    # Check if header is included anywhere
    if ! grep -r "#include.*$(basename "$file")" src/ include/ tests/ >/dev/null 2>&1; then
        ORPHANED_H="$ORPHANED_H $file"
    fi
done

# Report results
if [[ -n "$ORPHANED_C" ]] || [[ -n "$ORPHANED_H" ]]; then
    echo "ERROR: Found orphaned source files:"
    if [[ -n "$ORPHANED_C" ]]; then
        echo "Orphaned .c files:"
        for file in $ORPHANED_C; do
            echo "  - $file"
        done
    fi
    if [[ -n "$ORPHANED_H" ]]; then
        echo "Orphaned .h files:"
        for file in $ORPHANED_H; do
            echo "  - $file"
        done
    fi
    echo ""
    echo "All source files must be:"
    echo "1. Referenced in CMakeLists.txt build targets, OR"
    echo "2. Included in test builds, OR" 
    echo "3. Included by other source files"
    exit 1
else
    echo "✓ No orphaned source files found"
fi
