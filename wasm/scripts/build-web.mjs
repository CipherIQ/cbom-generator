#!/usr/bin/env node
/**
 * Bundle wasm/web/index.html into a self-contained dist/scanner.html.
 *
 * Extracts the inline <script type="module"> from index.html, bundles all
 * JS (local modules + npm packages) with esbuild into a single IIFE, then
 * produces a standalone HTML file with no import map or module dependencies.
 *
 * Usage: node scripts/build-web.mjs [--minify]
 */

import { readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(__dirname, '..');
const webDir = resolve(wasmDir, 'web');
const distDir = resolve(wasmDir, 'dist');

const minify = process.argv.includes('--minify');

// ── 1. Read source HTML ─────────────────────────────────────────────

const htmlPath = resolve(webDir, 'index.html');
const html = readFileSync(htmlPath, 'utf8');

// ── 2. Extract inline module script ─────────────────────────────────

const scriptRe = /<script type="module">([\s\S]*?)<\/script>/;
const match = html.match(scriptRe);
if (!match) {
    console.error('ERROR: Could not find <script type="module"> in index.html');
    process.exit(1);
}
const jsCode = match[1];

// Write to a temp entry file in web/ so relative imports resolve correctly
const entryPath = resolve(webDir, '.bundle-entry.js');
writeFileSync(entryPath, jsCode);

// ── 3. Bundle with esbuild ──────────────────────────────────────────

let result;
try {
    result = await esbuild.build({
        entryPoints: [entryPath],
        bundle: true,
        format: 'iife',
        platform: 'browser',
        write: false,
        minify,
        target: ['es2020'],
        logLevel: 'warning',
    });
} finally {
    // Clean up temp file
    try { unlinkSync(entryPath); } catch {}
}

if (result.errors.length > 0) {
    console.error('esbuild errors:', result.errors);
    process.exit(1);
}

const bundledJs = result.outputFiles[0].text;

// ── 4. Reconstruct HTML ─────────────────────────────────────────────

let output = html;

// Strip the import map
output = output.replace(/<script type="importmap">[\s\S]*?<\/script>\n?/, '');

// Replace module script with bundled IIFE.
// Use split/join instead of .replace() because the bundled JS contains '$'
// characters that .replace() interprets as special patterns ($', $&, etc.).
const scriptTag = match[0];
const idx = output.indexOf(scriptTag);
output = output.slice(0, idx) + `<script>\n${bundledJs}</script>` + output.slice(idx + scriptTag.length);

// Rewrite asset paths for flat deployment layout.
// esbuild may convert const→var and single→double quotes, so match flexibly.
output = output.replace(
    /(?:const|var) WASM_BASE = ["'][^"']*["']/,
    'var WASM_BASE = "."'
);
output = output.replace(
    /(?:const|var) PLUGIN_BASE = ["'][^"']*["']/,
    'var PLUGIN_BASE = "./plugins"'
);
output = output.replace(
    /(?:const|var) REGISTRY_BASE = ["'][^"']*["']/,
    'var REGISTRY_BASE = "./registry"'
);

// Rewrite explorer URL for website deployment (explore.html alongside scanner)
output = output.replace(
    /(?:const|var) explorerUrl = ["'][^"']*["']/,
    'var explorerUrl = "./explore.html"'
);

// ── 5. Write output ─────────────────────────────────────────────────

mkdirSync(distDir, { recursive: true });
const outPath = resolve(distDir, 'scanner.html');
writeFileSync(outPath, output);

const sizeKB = (Buffer.byteLength(output) / 1024).toFixed(0);
console.log(`Built: ${outPath} (${sizeKB} KB${minify ? ', minified' : ''})`);
