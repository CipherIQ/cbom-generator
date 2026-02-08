#!/usr/bin/env node
/**
 * Headless WASM scan runner.
 *
 * Simulates what the browser does:
 *   1. Read tar.gz from disk
 *   2. Extract via archive.js
 *   3. Parse certs via cert-parser.js
 *   4. Init WASM scanner via wasm-bridge.js
 *   5. Run scan with proper --cross-arch flags
 *   6. Write output CBOM to disk
 *
 * Usage: node run-scan.mjs --input <file.tar.gz> [options]
 *   --input <path>        Input archive (tar.gz, tar, zip)
 *   --output <path>       Output CBOM JSON (default: /tmp/wasm-cbom.json)
 *   --plugin-set <name>   'ubuntu' or 'embedded' (default: embedded)
 *   --registry <name>     'ubuntu', 'yocto', 'openwrt', 'alpine' (default: yocto)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { extractArchive } from '../src/js/archive.js';
import { parseCryptoAssets } from '../src/js/cert-parser.js';
import { initScanner } from '../src/js/wasm-bridge.js';

// ── Parse CLI args ───────────────────────────────────────────────────

const { values: opts } = parseArgs({
    options: {
        input: { type: 'string', short: 'i' },
        output: { type: 'string', short: 'o', default: '/tmp/wasm-cbom.json' },
        'plugin-set': { type: 'string', default: 'embedded' },
        registry: { type: 'string', default: 'yocto' },
    },
    strict: true,
});

if (!opts.input) {
    console.error('Usage: node run-scan.mjs --input <file.tar.gz> [--output <out.json>] [--plugin-set embedded] [--registry yocto]');
    process.exit(2);
}

const pluginSet = opts['plugin-set'];
const registry = opts.registry;

// ── Run scan ─────────────────────────────────────────────────────────

const t0 = performance.now();

// Step 1: Read archive from disk
console.log(`Reading: ${opts.input}`);
const archiveData = readFileSync(opts.input);
const t1 = performance.now();
console.log(`  Read ${(archiveData.length / 1024 / 1024).toFixed(1)} MB in ${(t1 - t0).toFixed(0)}ms`);

// Step 2: Extract archive
console.log('Extracting archive...');
const { files, symlinks } = await extractArchive(archiveData, {
    onProgress: ({ filesExtracted }) => {
        if (filesExtracted % 100 === 0) {
            process.stdout.write(`  Extracted ${filesExtracted} files\r`);
        }
    },
});
const t2 = performance.now();
console.log(`  Extracted ${files.size} files, ${symlinks.size} symlinks in ${(t2 - t1).toFixed(0)}ms`);

// Step 3: Parse certificates
console.log('Parsing certificates...');
const certData = await parseCryptoAssets(files);
const t3 = performance.now();
console.log(`  Found ${certData.certs.length} certs, ${certData.keys.length} keys in ${(t3 - t2).toFixed(0)}ms`);
if (certData.warnings.length > 0) {
    console.log(`  Warnings: ${certData.warnings.length}`);
}

// Step 4: Initialize WASM scanner
console.log('Initializing WASM scanner...');
const scanner = await initScanner({
    onStderr: (line) => {
        // Show important stderr lines (INFO/WARNING/ERROR)
        if (line.startsWith('INFO:') || line.startsWith('WARNING:') || line.startsWith('ERROR:') ||
            line.startsWith('[INFO]') || line.startsWith('[WARN]') || line.startsWith('[ERROR]')) {
            console.log(`  [C] ${line}`);
        }
    },
});
const t4 = performance.now();
console.log(`  Initialized in ${(t4 - t3).toFixed(0)}ms`);

// Step 5: Run WASM scan
console.log(`Scanning (pluginSet=${pluginSet}, registry=${registry})...`);
const { cbom, summary, warnings, scanTimeMs } = await scanner.scan(files, certData, {
    pluginSet,
    registry,
    discoverServices: true,
    symlinks,
    onProgress: ({ phase }) => {
        if (phase === 'scanning') {
            process.stdout.write('  Scanning...\r');
        }
    },
});
const t5 = performance.now();
console.log(`  Scan completed in ${(t5 - t4).toFixed(0)}ms`);

// Step 6: Write output
writeFileSync(opts.output, JSON.stringify(cbom, null, 2));
const t6 = performance.now();

// ── Summary ──────────────────────────────────────────────────────────

console.log('');
console.log('=== WASM Scan Summary ===');
console.log(`Output: ${opts.output}`);
console.log(`Components: ${summary.totalComponents}`);
console.log(`  Applications:  ${summary.applications}`);
console.log(`  Libraries:     ${summary.libraries}`);
console.log(`  Certificates:  ${summary.certificates}`);
console.log(`  Algorithms:    ${summary.algorithms}`);
console.log(`  Protocols:     ${summary.protocols}`);
console.log(`  Keys:          ${summary.keys}`);
console.log(`Dependencies: ${cbom.dependencies?.length || 0}`);
console.log(`PQC Readiness: ${summary.pqcReadiness.score}%`);
console.log(`  Safe: ${summary.pqcReadiness.safe}  Transitional: ${summary.pqcReadiness.transitional}  Unsafe: ${summary.pqcReadiness.unsafe}  Deprecated: ${summary.pqcReadiness.deprecated}`);
console.log(`Scan time: ${scanTimeMs}ms`);
console.log(`Total time: ${((t6 - t0) / 1000).toFixed(1)}s`);

if (warnings.length > 0) {
    console.log(`Warnings: ${warnings.length}`);
}
