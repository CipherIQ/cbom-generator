# cbom-generator WASM Build

Browser-native WebAssembly build of cbom-generator for client-side cryptographic
asset analysis. Scans firmware images for certificates, keys, algorithms, and
service configurations entirely in the browser — no server-side processing.

## Prerequisites

- [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html) 3.1.50+
- Node.js 18+
- CMake 3.16+

## Building

All commands run from the `wasm/` directory.

### 1. Install JS dependencies

```bash
npm install
```

### 2. Build C dependencies for Emscripten

Compiles json-c, libyaml, and jansson as static WASM libraries:

```bash
npm run build:deps
```

### 3. Activate Emscripten and build the WASM module

```bash
source ../emsdk/emsdk_env.sh   # adjust path to your emsdk install
npm run build:wasm
```

This produces `build-wasm/cbom-generator.js` (Emscripten glue) and
`build-wasm/cbom-generator.wasm` in the repository root.

### 4. Bundle the scanner web UI

```bash
npm run build:js              # readable output (912 KB)
npm run build:js -- --minify  # production output (429 KB)
```

This produces `dist/scanner.html` — a self-contained single-file scanner with
all JavaScript bundled inline (no CDN, no ES module imports).

## Testing the scanner in a browser

The scanner needs HTTP to load the WASM binary, plugins, and registry files.
Serve the repository root with any static server:

```bash
cd ..                          # back to cbom-generator root
python3 -m http.server 8080
```

Then open:

- **Development UI** (ES modules, needs import map):
  `http://localhost:8080/wasm/web/`

- **Bundled UI** (self-contained, no CDN):
  `http://localhost:8080/wasm/dist/scanner.html`

Drop a firmware image (`.tar.gz`, `.tgz`, `.zip`, `.tar`) onto the dropzone,
select the target platform, and the scan runs entirely client-side. Results
include component counts, PQC readiness score, and a filterable component table.

## Production deployment

Copy these files into a single directory on any static host:

```
scanner.html              from wasm/dist/
cbom-generator.js         from build-wasm/
cbom-generator.wasm       from build-wasm/
plugins/*.yaml            from plugins/
registry/*.yaml           from registry/
```

No backend required. Works on S3, GitHub Pages, Netlify, or any static CDN.

## Running tests

```bash
npm test                   # JS unit tests
npm run test:archive       # archive extraction tests
npm run test:certs         # certificate parser tests
npm run test:bridge        # WASM bridge integration tests
```

From the repository root, the WASM regression test compares scan output
against a native reference CBOM:

```bash
bash wasm/tests/run-regression.sh
```

## Architecture

See `../docs/CBOM_WASM_Design_Document.md` for the full design document.

## Directory Structure

```
wasm/
├── src/js/              # JavaScript bridge modules
│   ├── archive.js       # tar.gz/zip extraction (fflate)
│   ├── cert-parser.js   # X.509 certificate parsing (pkijs)
│   ├── cbom-summary.js  # CBOM summary extraction
│   ├── wasm-bridge.js   # Node.js WASM scanner interface
│   └── explorer-integration.js  # cbom-explorer bridge
├── web/
│   └── index.html       # Development scanner UI
├── dist/                # Built output (gitignored)
│   └── scanner.html     # Bundled self-contained scanner
├── tests/
│   ├── unit/            # JS module unit tests
│   ├── browser/         # Playwright browser tests
│   └── fixtures/        # WASM-specific test fixtures
└── scripts/
    ├── build-wasm-deps.sh   # C dependency compilation
    ├── build-web.mjs        # esbuild bundler
    └── compare-cbom.js      # CBOM comparison tool
```
