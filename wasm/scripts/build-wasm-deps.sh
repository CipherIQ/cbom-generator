#!/usr/bin/env bash
# build-wasm-deps.sh — Download and compile C dependencies for Emscripten/WASM
#
# Builds static .a archives of json-c, libyaml, and jansson for wasm32.
# Idempotent: skips downloads if cached, skips builds if .a already exists.
#
# Usage:
#   source ../emsdk/emsdk_env.sh   # activate Emscripten first
#   bash wasm/scripts/build-wasm-deps.sh
#
# Requires: emcc, emcmake, emmake, cmake, curl
set -euo pipefail

# --- Configuration -----------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS_DIR="$REPO_ROOT/deps"
CACHE_DIR="$DEPS_DIR/.cache"

# Pinned versions
JSONC_VERSION="0.17-20230812"
JSONC_TAG="json-c-${JSONC_VERSION}"
JSONC_DIR="json-c-${JSONC_TAG}"
JSONC_URL="https://github.com/json-c/json-c/archive/refs/tags/${JSONC_TAG}.tar.gz"
JSONC_ARCHIVE="${JSONC_TAG}.tar.gz"

LIBYAML_VERSION="0.2.5"
LIBYAML_DIR="libyaml-${LIBYAML_VERSION}"
LIBYAML_URL="https://github.com/yaml/libyaml/archive/refs/tags/${LIBYAML_VERSION}.tar.gz"
LIBYAML_ARCHIVE="libyaml-${LIBYAML_VERSION}.tar.gz"

JANSSON_VERSION="2.14"
JANSSON_DIR="jansson-${JANSSON_VERSION}"
JANSSON_URL="https://github.com/akheron/jansson/archive/refs/tags/v${JANSSON_VERSION}.tar.gz"
JANSSON_ARCHIVE="jansson-${JANSSON_VERSION}.tar.gz"

# --- Helpers -----------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
info() { echo -e "  ${YELLOW}INFO${NC} $1"; }

# Track results for summary
declare -A RESULTS

check_emscripten() {
    if ! command -v emcc &>/dev/null; then
        echo "Error: emcc not found. Activate Emscripten first:"
        echo "  source ../emsdk/emsdk_env.sh"
        exit 1
    fi
    info "Emscripten $(emcc --version | head -1 | grep -oP '\d+\.\d+\.\d+')"
}

download() {
    local url="$1"
    local dest="$2"

    if [[ -f "$dest" ]]; then
        info "Cached: $(basename "$dest")"
        return 0
    fi

    echo "  Downloading $(basename "$dest")..."
    curl -fsSL -o "$dest" "$url"
}

extract() {
    local archive="$1"
    local dest_dir="$2"
    local strip_name="$3"

    if [[ -d "$dest_dir" ]]; then
        info "Already extracted: $(basename "$dest_dir")"
        return 0
    fi

    echo "  Extracting to $(basename "$dest_dir")..."
    mkdir -p "$dest_dir"
    tar xzf "$archive" -C "$dest_dir" --strip-components=1
}

# --- Build functions ---------------------------------------------------------

build_jsonc() {
    echo ""
    echo "=== json-c ${JSONC_VERSION} ==="

    local src_dir="$DEPS_DIR/$JSONC_DIR"
    local build_dir="$src_dir/build-wasm"
    local output="$build_dir/libjson-c.a"

    if [[ -f "$output" ]]; then
        pass "json-c (already built: $output)"
        RESULTS[json-c]="PASS"
        return 0
    fi

    download "$JSONC_URL" "$CACHE_DIR/$JSONC_ARCHIVE"
    extract "$CACHE_DIR/$JSONC_ARCHIVE" "$src_dir" "$JSONC_DIR"

    echo "  Building with Emscripten..."
    (
        cd "$src_dir"
        emcmake cmake -B build-wasm \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_TESTING=OFF \
            -DBUILD_APPS=OFF \
            -DDISABLE_EXTRA_LIBS=ON
        emmake cmake --build build-wasm --parallel "$(nproc)"
    )

    if [[ -f "$output" ]]; then
        pass "json-c → $(basename "$output") ($(du -h "$output" | cut -f1))"
        RESULTS[json-c]="PASS"
    else
        # Search for .a in case output path differs
        local found
        found=$(find "$build_dir" -name "*.a" -print -quit 2>/dev/null || true)
        if [[ -n "$found" ]]; then
            pass "json-c → $found ($(du -h "$found" | cut -f1))"
            RESULTS[json-c]="PASS"
        else
            fail "json-c — no .a archive produced"
            RESULTS[json-c]="FAIL"
        fi
    fi
}

build_libyaml() {
    echo ""
    echo "=== libyaml ${LIBYAML_VERSION} ==="

    local src_dir="$DEPS_DIR/$LIBYAML_DIR"
    local build_dir="$src_dir/build-wasm"
    local output="$build_dir/libyaml.a"

    if [[ -f "$output" ]]; then
        pass "libyaml (already built: $output)"
        RESULTS[libyaml]="PASS"
        return 0
    fi

    download "$LIBYAML_URL" "$CACHE_DIR/$LIBYAML_ARCHIVE"
    extract "$CACHE_DIR/$LIBYAML_ARCHIVE" "$src_dir" "$LIBYAML_DIR"

    echo "  Building with Emscripten..."
    (
        cd "$src_dir"
        emcmake cmake -B build-wasm \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_TESTING=OFF \
            -DINSTALL_CMAKE_DIR=OFF
        emmake cmake --build build-wasm --parallel "$(nproc)"
    )

    if [[ -f "$output" ]]; then
        pass "libyaml → $(basename "$output") ($(du -h "$output" | cut -f1))"
        RESULTS[libyaml]="PASS"
    else
        local found
        found=$(find "$build_dir" -name "*.a" -print -quit 2>/dev/null || true)
        if [[ -n "$found" ]]; then
            pass "libyaml → $found ($(du -h "$found" | cut -f1))"
            RESULTS[libyaml]="PASS"
        else
            fail "libyaml — no .a archive produced"
            RESULTS[libyaml]="FAIL"
        fi
    fi
}

build_jansson() {
    echo ""
    echo "=== jansson ${JANSSON_VERSION} ==="

    local src_dir="$DEPS_DIR/$JANSSON_DIR"
    local build_dir="$src_dir/build-wasm"
    local output="$build_dir/lib/libjansson.a"

    if [[ -f "$output" ]]; then
        pass "jansson (already built: $output)"
        RESULTS[jansson]="PASS"
        return 0
    fi

    download "$JANSSON_URL" "$CACHE_DIR/$JANSSON_ARCHIVE"
    extract "$CACHE_DIR/$JANSSON_ARCHIVE" "$src_dir" "$JANSSON_DIR"

    echo "  Building with Emscripten..."
    (
        cd "$src_dir"
        emcmake cmake -B build-wasm \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DJANSSON_BUILD_DOCS=OFF \
            -DJANSSON_EXAMPLES=OFF \
            -DJANSSON_WITHOUT_TESTS=ON
        emmake cmake --build build-wasm --parallel "$(nproc)"
    )

    if [[ -f "$output" ]]; then
        pass "jansson → $(basename "$output") ($(du -h "$output" | cut -f1))"
        RESULTS[jansson]="PASS"
    else
        local found
        found=$(find "$build_dir" -name "*.a" -print -quit 2>/dev/null || true)
        if [[ -n "$found" ]]; then
            pass "jansson → $found ($(du -h "$found" | cut -f1))"
            RESULTS[jansson]="PASS"
        else
            fail "jansson — no .a archive produced"
            RESULTS[jansson]="FAIL"
        fi
    fi
}

# --- Main --------------------------------------------------------------------

echo "╔══════════════════════════════════════════════╗"
echo "║  WASM Dependency Build — cbom-generator      ║"
echo "╚══════════════════════════════════════════════╝"

check_emscripten
mkdir -p "$CACHE_DIR"

build_jsonc
build_libyaml
build_jansson

# --- Summary -----------------------------------------------------------------

echo ""
echo "════════════════════════════════════════════════"
echo "  SUMMARY"
echo "════════════════════════════════════════════════"

exit_code=0
for lib in json-c libyaml jansson; do
    status="${RESULTS[$lib]:-UNKNOWN}"
    if [[ "$status" == "PASS" ]]; then
        echo -e "  ${GREEN}PASS${NC}  $lib"
    else
        echo -e "  ${RED}FAIL${NC}  $lib"
        exit_code=1
    fi
done

echo "════════════════════════════════════════════════"

if [[ $exit_code -eq 0 ]]; then
    echo -e "  ${GREEN}All dependencies compiled successfully.${NC}"
else
    echo -e "  ${RED}Some dependencies failed. See output above.${NC}"
fi

exit $exit_code
