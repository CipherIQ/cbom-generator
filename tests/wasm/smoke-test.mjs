/**
 * WASM Smoke Test for cbom-generator
 *
 * Validates that the WASM build produces a working module that can:
 * 1. Be instantiated via the ES module factory
 * 2. Create files in Emscripten MEMFS
 * 3. Run cbom-generator via callMain()
 * 4. Produce valid CycloneDX JSON output
 */

import { strict as assert } from 'node:assert';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { statSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(__dirname, '..', '..', 'build-wasm');

// ── 1. Check build artifacts exist ──────────────────────────────────

const wasmPath = join(wasmDir, 'cbom-generator.wasm');
const jsPath = join(wasmDir, 'cbom-generator.js');

let wasmStat, jsStat;
try {
    wasmStat = statSync(wasmPath);
    jsStat = statSync(jsPath);
} catch (e) {
    console.error('Build artifacts not found. Run the WASM build first:');
    console.error('  source ../emsdk/emsdk_env.sh');
    console.error('  emcmake cmake -B build-wasm -DCMAKE_BUILD_TYPE=Release');
    console.error('  emmake cmake --build build-wasm');
    process.exit(1);
}

assert(wasmStat.size > 0, 'cbom-generator.wasm is empty');
assert(jsStat.size > 0, 'cbom-generator.js is empty');

// ── 2. Check WASM size < 2MB ────────────────────────────────────────

const wasmSizeKB = wasmStat.size / 1024;
const wasmSizeMB = wasmSizeKB / 1024;
assert(wasmSizeMB < 2, `WASM size ${wasmSizeMB.toFixed(2)} MB exceeds 2 MB limit`);
console.log(`  WASM size: ${wasmSizeKB.toFixed(0)} KB (${wasmSizeMB.toFixed(2)} MB)`);

// ── 3. Import and instantiate module ────────────────────────────────

const createCbomGenerator = (await import(jsPath)).default;
const Module = await createCbomGenerator({
    // Suppress Emscripten stdout/stderr noise during test
    print: () => {},
    printErr: (text) => {
        // Only show errors, suppress info/warnings
        if (text.startsWith('[error]')) console.error('  ' + text);
    },
});

assert(typeof Module.callMain === 'function', 'callMain() not exported');
assert(typeof Module.FS === 'object', 'FS not exported');
console.log('  Module instantiated successfully');

// ── 4. Create test fixture in MEMFS ─────────────────────────────────

Module.FS.mkdir('/scan');
Module.FS.writeFile('/scan/test.conf', [
    '# Test configuration file',
    'ssl_protocols TLSv1.2 TLSv1.3;',
    'ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;',
    'ssl_certificate /etc/ssl/certs/server.pem;',
    'ssl_certificate_key /etc/ssl/private/server.key;',
].join('\n'));

// ── 5. Run cbom-generator ───────────────────────────────────────────

let exitCode;
try {
    exitCode = Module.callMain([
        '-o', '/output.json',
        '--format', 'cyclonedx',
        '/scan'
    ]);
} catch (e) {
    // Emscripten may throw on exit() calls; that's OK
    exitCode = typeof e.status === 'number' ? e.status : -1;
}

console.log(`  Exit code: ${exitCode}`);

// ── 6. Read and validate output ─────────────────────────────────────

let outputData;
try {
    outputData = Module.FS.readFile('/output.json', { encoding: 'utf8' });
} catch (e) {
    console.error('Failed to read output file from MEMFS');
    process.exit(1);
}

assert(outputData.length > 0, 'Output file is empty');

const cbom = JSON.parse(outputData);

assert.equal(cbom.bomFormat, 'CycloneDX', 'bomFormat should be CycloneDX');
assert(cbom.specVersion, 'specVersion must be present');
assert(cbom.metadata, 'metadata must be present');
assert(Array.isArray(cbom.components), 'components must be an array');

console.log(`  Spec version: ${cbom.specVersion}`);
console.log(`  Components found: ${cbom.components.length}`);
console.log(`  Serial number: ${cbom.serialNumber || 'N/A'}`);

// ── Done ────────────────────────────────────────────────────────────

console.log('\nAll WASM smoke tests passed!');
