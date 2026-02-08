# cbom-generator WASM Build

Browser-native WebAssembly build of cbom-generator for client-side cryptographic
asset analysis. Parses certificates, keys, and configurations entirely in the
browser with no server-side processing.

## Prerequisites

- Emscripten SDK 3.1.50+
- Node.js 18+
- CMake 3.16+

## Quick Start

```bash
# 1. Build C dependencies for WASM
npm run build:deps

# 2. Build WASM module
npm run build:wasm

# 3. Run tests
npm test
```

## Architecture

See `../docs/CBOM_WASM_Design_Document.md` for the full design document.

## Directory Structure

```
wasm/
├── src/js/          # JavaScript bridge modules
├── web/             # Browser UI
├── tests/
│   ├── unit/        # JS module unit tests
│   ├── browser/     # Playwright browser tests
│   └── fixtures/    # WASM-specific test fixtures
└── scripts/         # Build and packaging scripts
```
