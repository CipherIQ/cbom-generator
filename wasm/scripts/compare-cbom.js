#!/usr/bin/env node
/**
 * Content-based CBOM comparator.
 *
 * Compares two CycloneDX CBOM JSON files using content-based matching
 * (component name, subject DN) instead of bom-ref IDs, which differ
 * between native and WASM builds due to path-based hashing.
 *
 * Usage: node compare-cbom.js <native.json> <wasm.json>
 * Exit:  0 = structurally equivalent, 1 = different
 */

import { readFileSync } from 'node:fs';

// ── CLI args ─────────────────────────────────────────────────────────

const args = process.argv.slice(2);
if (args.length !== 2) {
    console.error('Usage: node compare-cbom.js <native.json> <wasm.json>');
    process.exit(2);
}

const [nativePath, wasmPath] = args;

// ── Load ─────────────────────────────────────────────────────────────

const native = JSON.parse(readFileSync(nativePath, 'utf8'));
const wasm = JSON.parse(readFileSync(wasmPath, 'utf8'));

// ── Hex-escape decoder ──────────────────────────────────────────────

function decodeHexEscapes(s) {
    // OpenSSL prints non-ASCII as \XX hex pairs (UTF-8 bytes) — decode properly
    return s.replace(/(\\[0-9A-Fa-f]{2})+/g, (match) => {
        const bytes = [];
        for (const m of match.matchAll(/\\([0-9A-Fa-f]{2})/g)) {
            bytes.push(parseInt(m[1], 16));
        }
        return Buffer.from(bytes).toString('utf8');
    });
}

// ── DN Normalization ─────────────────────────────────────────────────

function normalizeDN(dn) {
    if (!dn || typeof dn !== 'string') return '';
    // Decode \C3\BAs style hex escapes first
    dn = decodeHexEscapes(dn);
    // Parse DN respecting quoted values (commas inside quotes are not delimiters)
    // Then normalize: lowercase, strip quotes, trim whitespace around = and ,
    const parts = [];
    let current = '';
    let inQuote = false;
    for (let i = 0; i < dn.length; i++) {
        const ch = dn[i];
        if (ch === '"') {
            inQuote = !inQuote;
            continue; // strip quotes
        }
        if (ch === ',' && !inQuote) {
            parts.push(current);
            current = '';
            continue;
        }
        current += ch;
    }
    if (current) parts.push(current);

    // Merge continuation parts (no '=' means it's a value with unquoted comma)
    const merged = [];
    for (const raw of parts) {
        const s = raw.trim();
        if (!s) continue;
        if (s.includes('=') || merged.length === 0) {
            merged.push(s);
        } else {
            merged[merged.length - 1] += ', ' + s;
        }
    }

    return merged
        .map(s => {
            const eq = s.indexOf('=');
            if (eq === -1) return s.toLowerCase();
            const key = s.substring(0, eq).trim().toLowerCase();
            // Normalize value: lowercase, collapse ", " to "," for consistent matching
            const val = s.substring(eq + 1).trim().toLowerCase().replace(/,\s+/g, ',');
            return key + '=' + val;
        })
        .join(',');
}

// ── Categorization ───────────────────────────────────────────────────

function categorizeComponents(components) {
    const cats = {
        algorithms: [],
        certificates: [],
        keys: [],
        libraries: [],
        applications: [],
        services: [],
        protocols: [],
        other: [],
    };

    for (const comp of components || []) {
        const type = comp.type;
        const assetType = comp.cryptoProperties?.assetType;

        if (type === 'cryptographic-asset') {
            if (assetType === 'algorithm') cats.algorithms.push(comp);
            else if (assetType === 'certificate') cats.certificates.push(comp);
            else if (assetType === 'related-crypto-material') cats.keys.push(comp);
            else if (assetType === 'protocol') cats.protocols.push(comp);
            else cats.other.push(comp);
        } else if (type === 'library') {
            cats.libraries.push(comp);
        } else if (type === 'application') {
            cats.applications.push(comp);
        } else if (type === 'service') {
            cats.services.push(comp);
        } else {
            cats.other.push(comp);
        }
    }

    return cats;
}

// ── Content-based match key generation ───────────────────────────────

function getMatchKey(comp) {
    const type = comp.type;
    const assetType = comp.cryptoProperties?.assetType;

    if (type === 'cryptographic-asset' && assetType === 'certificate') {
        // Certificate: use bom-ref if it's CN-based (not hash-based)
        const bomRef = comp['bom-ref'] || '';
        if (bomRef.startsWith('cert:') && !bomRef.startsWith('cert:hash-')) {
            return bomRef.toLowerCase();
        }
        // Hash-based bom-refs differ between native/WASM — fall back to DN
        const cert = comp.cryptoProperties?.certificateProperties;
        if (cert) {
            const subj = normalizeDN(cert.subjectName);
            const issuer = normalizeDN(cert.issuerName);
            if (subj) return `cert:${subj}|${issuer}`;
        }
        return `cert:${(comp.name || '').toLowerCase()}`;
    }

    if (type === 'cryptographic-asset' && assetType === 'algorithm') {
        // Algorithm: match by name
        return `algo:${(comp.name || '').toLowerCase()}`;
    }

    if (type === 'library') {
        // Library: match by name (soname)
        return `lib:${(comp.name || '').toLowerCase()}`;
    }

    if (type === 'application') {
        // Normalize: strip .service suffix, map well-known daemon/unit name aliases
        let appName = (comp.name || '').toLowerCase().replace(/\.service$/, '');
        const aliases = { 'dbus': 'dbus-daemon' };
        appName = aliases[appName] || appName;
        return `app:${appName}`;
    }

    if (type === 'service') {
        return `svc:${(comp.name || '').toLowerCase()}`;
    }

    if (type === 'cryptographic-asset' && assetType === 'protocol') {
        return `proto:${(comp.name || '').toLowerCase()}`;
    }

    // Other: match by name
    return `other:${(comp.name || '').toLowerCase()}`;
}

// ── Matching logic ───────────────────────────────────────────────────

function buildMatchMap(components) {
    const map = new Map();
    for (const comp of components) {
        const key = getMatchKey(comp);
        // If duplicate key, keep first (dedup)
        if (!map.has(key)) {
            map.set(key, comp);
        }
    }
    return map;
}

// Extract the last CN= value from a cert name (which is typically a full DN)
function extractCN(name) {
    if (!name) return '';
    name = decodeHexEscapes(name);
    const m = name.match(/CN\s*=\s*(.+?)(?:,|$)/i);
    return m ? m[1].trim().toLowerCase() : name.trim().toLowerCase();
}

function compareCategory(nativeComps, wasmComps, label) {
    const nativeMap = buildMatchMap(nativeComps);
    const wasmMap = buildMatchMap(wasmComps);

    const matched = [];
    const missingInWasm = [];
    const extraInWasm = [];
    const wasmMatched = new Set();

    for (const [key] of nativeMap) {
        if (wasmMap.has(key)) {
            matched.push(key);
            wasmMatched.add(key);
        } else {
            missingInWasm.push(key);
        }
    }

    for (const [key] of wasmMap) {
        if (!nativeMap.has(key) && !wasmMatched.has(key)) {
            extraInWasm.push(key);
        }
    }

    // Second pass for certificates: try CN-based matching on unmatched items
    if (label === 'Certificates' && missingInWasm.length > 0 && extraInWasm.length > 0) {
        const extraMap = new Map();
        for (const key of extraInWasm) {
            const comp = wasmMap.get(key);
            if (comp) extraMap.set(extractCN(comp.name), key);
        }
        const resolved = [];
        for (const key of missingInWasm) {
            const comp = nativeMap.get(key);
            if (comp) {
                const cn = extractCN(comp.name);
                if (extraMap.has(cn)) {
                    matched.push(key);
                    const wasmKey = extraMap.get(cn);
                    extraInWasm.splice(extraInWasm.indexOf(wasmKey), 1);
                    extraMap.delete(cn);
                    resolved.push(key);
                }
            }
        }
        for (const key of resolved) {
            missingInWasm.splice(missingInWasm.indexOf(key), 1);
        }
    }

    return { matched, missingInWasm, extraInWasm, nativeCount: nativeMap.size, wasmCount: wasmMap.size };
}

// ── Comparison ───────────────────────────────────────────────────────

const nativeCats = categorizeComponents(native.components);
const wasmCats = categorizeComponents(wasm.components);

const categoryNames = {
    algorithms: 'Algorithms',
    certificates: 'Certificates',
    keys: 'Keys',
    libraries: 'Libraries',
    applications: 'Applications',
    services: 'Services',
    protocols: 'Protocols',
    other: 'Other',
};

// ── Output ───────────────────────────────────────────────────────────

function formatBreakdown(cats) {
    const parts = [];
    for (const [key, label] of Object.entries(categoryNames)) {
        if (cats[key].length > 0) {
            parts.push(`${cats[key].length} ${label.toLowerCase()}`);
        }
    }
    return parts.join(', ');
}

console.log('=== CBOM Comparison (content-based) ===');
console.log(`Native: ${native.components?.length || 0} components (${formatBreakdown(nativeCats)})`);
console.log(`WASM:   ${wasm.components?.length || 0} components (${formatBreakdown(wasmCats)})`);
console.log('');

let allMatch = true;
let totalMatched = 0;
let totalNative = 0;
const results = {};

for (const [key, label] of Object.entries(categoryNames)) {
    const result = compareCategory(nativeCats[key], wasmCats[key], label);
    results[key] = result;
    totalMatched += result.matched.length;
    totalNative += result.nativeCount;

    if (result.missingInWasm.length === 0 && result.extraInWasm.length === 0
        && result.nativeCount === result.wasmCount) {
        const pct = result.nativeCount > 0
            ? Math.round(result.matched.length / result.nativeCount * 100)
            : 100;
        console.log(`${label.padEnd(14)} MATCH (${result.matched.length}/${result.nativeCount} — ${pct}%)`);
    } else {
        allMatch = false;
        const pct = result.nativeCount > 0
            ? Math.round(result.matched.length / result.nativeCount * 100)
            : 0;
        console.log(`${label.padEnd(14)} ${result.matched.length}/${result.nativeCount} matched (${pct}%)`);
        if (result.missingInWasm.length > 0) {
            const show = result.missingInWasm.slice(0, 5);
            console.log(`  Missing in WASM: ${show.join(', ')}${result.missingInWasm.length > 5 ? ` ... and ${result.missingInWasm.length - 5} more` : ''}`);
        }
        if (result.extraInWasm.length > 0) {
            const show = result.extraInWasm.slice(0, 5);
            console.log(`  Extra in WASM:   ${show.join(', ')}${result.extraInWasm.length > 5 ? ` ... and ${result.extraInWasm.length - 5} more` : ''}`);
        }
    }
}

const totalPct = totalNative > 0 ? Math.round(totalMatched / totalNative * 100) : 100;
console.log('');
console.log(`Total:         ${totalMatched}/${totalNative} matched (${totalPct}%)`);

// Critical categories: WASM must not MISS any native components.
// Extra detections in WASM are acceptable (e.g., WASM ELF-only scanner
// picks up strongswan plugin .so files that native cross-arch skips).
const criticalCategories = ['algorithms', 'certificates', 'keys', 'libraries', 'protocols'];
const criticalPass = criticalCategories.every(k => {
    const r = results[k];
    return r.missingInWasm.length === 0;
});

console.log('');
if (allMatch) {
    console.log('RESULT: PASS (100% match)');
    process.exit(0);
} else if (criticalPass && totalPct >= 90) {
    console.log(`RESULT: PASS (critical categories match, ${totalPct}% overall)`);
    process.exit(0);
} else {
    console.log('RESULT: DIFFERENCES FOUND');
    if (!criticalPass) console.log('  Critical category mismatch detected');
    process.exit(1);
}
