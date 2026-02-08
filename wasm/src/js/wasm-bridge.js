/**
 * WASM bridge module for cbom-generator.
 *
 * Wires archive extraction and cert parsing to the WASM module:
 * mounts files into Emscripten MEMFS, writes pre-parsed cert metadata,
 * calls callMain(), and reads the CycloneDX output.
 *
 * Each scan() call creates a fresh Emscripten Module instance (~2ms)
 * to avoid C-side global state corruption (getopt optind, etc.) between
 * successive callMain() invocations.
 *
 * @module wasm-bridge
 */

// ── MEMFS helpers ────────────────────────────────────────────────────

/**
 * Get the parent directory of a path.
 * @param {string} path
 * @returns {string}
 */
function parentDir(path) {
    const idx = path.lastIndexOf('/');
    if (idx <= 0) return '/';
    return path.substring(0, idx);
}

/**
 * Create directories recursively in Emscripten MEMFS.
 * Equivalent to `mkdir -p`.
 * @param {Object} FS - Emscripten FS object
 * @param {string} path - Absolute path to create
 */
function mkdirp(FS, path) {
    if (path === '/' || path === '') return;

    try {
        FS.stat(path);
        return; // already exists
    } catch {
        // doesn't exist — create parent first, then this dir
    }

    mkdirp(FS, parentDir(path));
    try {
        FS.mkdir(path);
    } catch {
        // already exists — ignore
    }
}

// ── WasmScanner class ────────────────────────────────────────────────

class WasmScanner {
    /** @type {function} Emscripten factory function */
    #factory;
    /** @type {Object} Options passed to initScanner */
    #options;
    /** @type {Object|null} Most recent Module instance (for getModule) */
    #lastModule = null;

    /**
     * @param {function} factory - Emscripten module factory function
     * @param {Object} options - Options from initScanner
     */
    constructor(factory, options) {
        this.#factory = factory;
        this.#options = options;
    }

    /**
     * Scan files and produce a CycloneDX CBOM.
     *
     * Creates a fresh WASM module instance per scan to ensure clean
     * C-side global state (getopt, malloc, file handles, etc.).
     *
     * @param {Map<string, Uint8Array>} files - Extracted files (path → content)
     * @param {Object} certData - Pre-parsed cert/key metadata from cert-parser.js
     * @param {Object} [options]
     * @param {string} [options.format='cyclonedx-1.6'] - 'cyclonedx-1.6' or 'cyclonedx-1.7'
     * @param {function} [options.onProgress] - Progress callback
     * @returns {Promise<{cbom: Object, warnings: string[]}>}
     */
    async scan(files, certData, options = {}) {
        const {
            format = 'cyclonedx-1.6',
            onProgress = null,
        } = options;

        const warnings = [];

        // ── 1. Create fresh Module instance ──
        const Module = await this.#factory({
            print: this.#options.onStdout || (() => {}),
            printErr: this.#options.onStderr || (() => {}),
        });
        this.#lastModule = Module;
        const FS = Module.FS;

        // ── 2. Prepare MEMFS directories ──
        mkdirp(FS, '/scan');
        mkdirp(FS, '/output');

        // ── 3. Mount extracted files ──
        let mounted = 0;
        for (const [path, data] of files) {
            const fullPath = '/scan/' + path;
            mkdirp(FS, parentDir(fullPath));
            FS.writeFile(fullPath, data);
            mounted++;

            if (onProgress) {
                onProgress({
                    phase: 'mounting',
                    filesMounted: mounted,
                    totalFiles: files.size,
                    currentFile: path,
                });
            }
        }

        // ── 4. Write cert metadata JSON ──
        if (certData) {
            const metadataJson = JSON.stringify(certData);
            FS.writeFile('/scan/.cert-metadata.json', metadataJson);
        }

        // ── 5. Build callMain arguments ──
        const specVersion = format === 'cyclonedx-1.7' ? '1.7' : '1.6';
        const args = [
            '/scan',
            '-o', '/output/cbom.json',
            '--format', 'cyclonedx',
            '--cyclonedx-spec', specVersion,
        ];

        // ── 6. Execute scan ──
        if (onProgress) {
            onProgress({ phase: 'scanning' });
        }

        let exitCode;
        try {
            exitCode = Module.callMain(args);
        } catch (e) {
            // Emscripten throws on exit() — check status code
            if (typeof e === 'object' && typeof e.status === 'number') {
                exitCode = e.status;
            } else {
                throw new Error(`WASM scan failed: ${e.message || e}`);
            }
        }

        // ── 7. Read output ──
        if (onProgress) {
            onProgress({ phase: 'reading-output' });
        }

        let outputData;
        try {
            outputData = FS.readFile('/output/cbom.json', { encoding: 'utf8' });
        } catch {
            throw new Error(
                `Scan produced no output (exit code: ${exitCode}). ` +
                'The WASM module may have encountered an error.'
            );
        }

        let cbom;
        try {
            cbom = JSON.parse(outputData);
        } catch (e) {
            throw new Error(`Failed to parse CBOM output as JSON: ${e.message}`);
        }

        return { cbom, warnings };
    }

    /**
     * Clean up between scans.
     *
     * Since each scan() creates a fresh Module instance, this method
     * simply clears the reference to the last module. No MEMFS cleanup
     * is needed — the old module and its MEMFS are garbage collected.
     */
    reset() {
        this.#lastModule = null;
    }

    /**
     * Get the most recent Emscripten Module instance.
     * Returns the Module from the last scan() call, or null if
     * no scan has been performed yet or reset() was called.
     * @returns {Object|null}
     */
    getModule() {
        return this.#lastModule;
    }
}

// ── Module initialization ────────────────────────────────────────────

/**
 * Initialize the WASM scanner.
 *
 * Loads the Emscripten glue code and returns a WasmScanner that
 * creates fresh Module instances per scan (~2ms overhead).
 *
 * @param {Object} [options]
 * @param {string} [options.wasmUrl] - Path or URL to cbom-generator.js glue code.
 *   In Node.js: auto-detected relative to build-wasm/.
 *   In browser: must be provided or set via import map.
 * @param {function} [options.onStdout] - Callback for stdout lines
 * @param {function} [options.onStderr] - Callback for stderr lines
 * @returns {Promise<WasmScanner>}
 */
export async function initScanner(options = {}) {
    const { wasmUrl = null, onStdout = null, onStderr = null } = options;

    // Resolve module path
    let modulePath = wasmUrl;
    if (!modulePath) {
        // Auto-detect: assume build-wasm/ is sibling to wasm/ in project root
        const { dirname, join } = await import('node:path');
        const { fileURLToPath } = await import('node:url');
        const thisDir = dirname(fileURLToPath(import.meta.url));
        modulePath = join(thisDir, '..', '..', '..', 'build-wasm', 'cbom-generator.js');
    }

    // Dynamic import of the Emscripten glue code
    const glueModule = await import(modulePath);
    const factory = glueModule.default;

    if (typeof factory !== 'function') {
        throw new Error('WASM glue code did not export a factory function');
    }

    // Verify factory works by creating a test Module instance
    const testModule = await factory({
        print: () => {},
        printErr: () => {},
    });

    if (typeof testModule.callMain !== 'function') {
        throw new Error('WASM module does not export callMain()');
    }
    if (!testModule.FS) {
        throw new Error('WASM module does not export FS');
    }

    return new WasmScanner(factory, { onStdout, onStderr });
}
