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

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..', '..', '..');

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

    // ── Plugin and registry loading ──────────────────────────────────

    /**
     * Load plugin YAML files from disk.
     * @param {string} pluginSet - 'ubuntu' or 'embedded'
     * @returns {Object<string, string>} filename → YAML content
     */
    static _loadPluginFiles(pluginSet) {
        const dir = join(PROJECT_ROOT, 'plugins', pluginSet);
        const plugins = {};
        for (const file of readdirSync(dir)) {
            if (file.endsWith('.yaml') || file.endsWith('.yml')) {
                plugins[file] = readFileSync(join(dir, file), 'utf8');
            }
        }
        return plugins;
    }

    /**
     * Load a crypto registry YAML file from disk.
     * @param {string} registry - 'ubuntu', 'yocto', 'openwrt', or 'alpine'
     * @returns {string} YAML content
     */
    static _loadRegistryFile(registry) {
        const validRegistries = ['ubuntu', 'yocto', 'openwrt', 'alpine'];
        if (!validRegistries.includes(registry)) {
            throw new Error(
                `Unknown registry: ${registry}. Available: ${validRegistries.join(', ')}`
            );
        }
        const filePath = join(PROJECT_ROOT, 'registry', `crypto-registry-${registry}.yaml`);
        return readFileSync(filePath, 'utf8');
    }

    /**
     * Mount plugin YAML files into MEMFS at /plugins/.
     * @param {Object} FS - Emscripten FS object
     * @param {string} pluginSet - 'ubuntu' or 'embedded'
     */
    _mountPlugins(FS, pluginSet) {
        mkdirp(FS, '/plugins');
        const plugins = WasmScanner._loadPluginFiles(pluginSet);
        for (const [filename, content] of Object.entries(plugins)) {
            FS.writeFile(`/plugins/${filename}`, content);
        }
    }

    /**
     * Mount a crypto registry YAML file into MEMFS at /registry/.
     * @param {Object} FS - Emscripten FS object
     * @param {string} registry - 'ubuntu', 'yocto', 'openwrt', or 'alpine'
     */
    _mountRegistry(FS, registry) {
        mkdirp(FS, '/registry');
        const content = WasmScanner._loadRegistryFile(registry);
        FS.writeFile(`/registry/crypto-registry-${registry}.yaml`, content);
    }

    // ── Scan path detection ──────────────────────────────────────────

    /**
     * Determine which directories to pass as scan targets.
     *
     * The native tool accepts multiple directory paths as positional args.
     * When the user uploads a Yocto/Buildroot rootfs tar.gz, the extracted
     * archive has a standard Linux directory layout. We detect this and pass
     * the same paths a user would on the command line.
     *
     * Three modes:
     * 1. User provides explicit scanPaths in options -> use those directly
     * 2. Archive has rootfs structure (usr/bin, usr/lib, etc) -> smart detection
     * 3. Fallback -> scan /scan (entire archive)
     *
     * @param {Object} FS - Emscripten FS object
     * @param {Object} options
     * @param {string[]|null} options.scanPaths - Explicit paths or null
     * @returns {string[]}
     */
    _determineScanPaths(FS, options) {
        // Mode 1: User explicitly provides paths
        if (options.scanPaths && options.scanPaths.length > 0) {
            return options.scanPaths.map(p => `/scan/${p.replace(/^\//, '')}`);
        }

        // Mode 2: Detect rootfs structure in MEMFS
        // Check /scan/ directly first, then check inside a single top-level
        // directory (common in rootfs archives: rootfs/, firmware/, etc.)
        const prefixes = ['/scan'];

        try {
            const topLevel = FS.readdir('/scan').filter(e => e !== '.' && e !== '..');
            if (topLevel.length === 1) {
                try {
                    const st = FS.stat(`/scan/${topLevel[0]}`);
                    if (FS.isDir(st.mode)) {
                        prefixes.push(`/scan/${topLevel[0]}`);
                    }
                } catch { /* ignore */ }
            }
        } catch { /* ignore */ }

        const rootfsSuffixes = [
            '/usr/bin',
            '/usr/sbin',
            '/usr/lib',
            '/usr/lib64',
            '/usr/local/bin',
            '/usr/local/lib',
            '/etc',
            '/lib',
        ];

        for (const prefix of prefixes) {
            const detected = rootfsSuffixes
                .map(suffix => prefix + suffix)
                .filter(p => {
                    try {
                        const st = FS.stat(p);
                        return FS.isDir(st.mode);
                    } catch {
                        return false;
                    }
                });

            if (detected.length > 0) {
                return detected;
            }
        }

        // Mode 3: Fallback — scan entire archive
        return ['/scan'];
    }

    // ── Main scan method ─────────────────────────────────────────────

    /**
     * Scan files and produce a CycloneDX CBOM.
     *
     * Creates a fresh WASM module instance per scan to ensure clean
     * C-side global state (getopt, malloc, file handles, etc.).
     *
     * @param {Map<string, Uint8Array>} files - Extracted files (path -> content)
     * @param {Object} certData - Pre-parsed cert/key metadata from cert-parser.js
     * @param {Object} [options]
     * @param {string} [options.specVersion='1.7'] - CycloneDX spec version: '1.6' or '1.7'
     * @param {string} [options.pluginSet='embedded'] - Plugin set: 'ubuntu' or 'embedded'
     * @param {string} [options.registry='yocto'] - Crypto registry: 'ubuntu', 'yocto', 'openwrt', 'alpine'
     * @param {boolean} [options.discoverServices=true] - Enable config-only service discovery
     * @param {string[]} [options.scanPaths] - Override auto-detected scan directories
     * @param {function} [options.onProgress] - Progress callback
     * @returns {Promise<{cbom: Object, warnings: string[]}>}
     */
    async scan(files, certData, options = {}) {
        const {
            specVersion = '1.7',
            pluginSet = 'embedded',
            registry = 'yocto',
            discoverServices = true,
            scanPaths = null,
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

        // ── 4. Mount plugins and registry ──
        this._mountPlugins(FS, pluginSet);
        this._mountRegistry(FS, registry);

        // ── 5. Write cert metadata JSON ──
        if (certData) {
            const metadataJson = JSON.stringify(certData);
            FS.writeFile('/scan/.cert-metadata.json', metadataJson);
        }

        // ── 6. Build callMain arguments ──
        // --cross-arch is ALWAYS on in WASM.
        // Reason: WASM host is wasm32-unknown-emscripten, target binaries are
        // ARM64/x86_64/MIPS/etc. Cross-arch mode uses file-based ELF parsing
        // (fopen/fread) instead of dlopen/dlinfo, which is exactly what works
        // in WASM.
        const argv = [];
        argv.push('--cross-arch');

        // Config-only service discovery (default: on).
        // This enables YAML plugins to parse config files (nginx.conf, sshd_config,
        // etc.) found in the scanned directories. Process/port/systemd detection
        // is already guarded out by Emscripten #ifdefs, so --discover-services
        // activates only the config-based detection path.
        if (discoverServices) {
            argv.push('--discover-services');
        }

        // Plugin directory — mounted in MEMFS by _mountPlugins()
        argv.push('--plugin-dir', '/plugins');

        // Crypto registry — specific to target platform
        argv.push('--crypto-registry', `/registry/crypto-registry-${registry}.yaml`);

        // Output format
        argv.push('--format', 'cyclonedx');
        argv.push('--cyclonedx-spec', specVersion);
        argv.push('-o', '/output/cbom.json');

        // Cert metadata (WASM-specific — tells the C-side jsbridge parser
        // where to find pre-parsed certificate metadata from pkijs)
        if (certData) {
            argv.push('--cert-metadata', '/scan/.cert-metadata.json');
        }

        // Scan paths — MULTIPLE positional arguments, just like native CLI
        const scanTargets = this._determineScanPaths(FS, { scanPaths });
        argv.push(...scanTargets);

        // ── 7. Execute scan ──
        if (onProgress) {
            onProgress({ phase: 'scanning' });
        }

        let exitCode;
        try {
            exitCode = Module.callMain(argv);
        } catch (e) {
            // Emscripten throws on exit() — check status code
            if (typeof e === 'object' && typeof e.status === 'number') {
                exitCode = e.status;
            } else {
                throw new Error(`WASM scan failed: ${e.message || e}`);
            }
        }

        // ── 8. Read output ──
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
        modulePath = join(PROJECT_ROOT, 'build-wasm', 'cbom-generator.js');
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
