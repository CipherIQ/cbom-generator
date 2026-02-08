#!/usr/bin/env node
/**
 * Structural CBOM comparator.
 *
 * Compares two CycloneDX CBOM JSON files after normalizing volatile fields.
 * Reports per-category match/mismatch with clear output.
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

// ── Normalization ────────────────────────────────────────────────────

function normalizeDN(dn) {
    if (!dn || typeof dn !== 'string') return dn;
    // "CN = foo, O = bar" → "CN=foo,O=bar"
    return dn
        .split(',')
        .map(s => s.trim())
        .map(s => {
            const eq = s.indexOf('=');
            if (eq === -1) return s;
            return s.substring(0, eq).trim() + '=' + s.substring(eq + 1).trim();
        })
        .join(',');
}

function normalizeFingerprint(fp) {
    if (!fp || typeof fp !== 'string') return fp;
    // "AB:CD:EF" → "abcdef"
    return fp.toLowerCase().replace(/[:\s]/g, '');
}

function normalizeComponent(comp) {
    const c = JSON.parse(JSON.stringify(comp));

    // Normalize certificate-related fields
    if (c.cryptoProperties) {
        const cp = c.cryptoProperties;
        if (cp.certificateProperties) {
            const cert = cp.certificateProperties;
            if (cert.subjectName) cert.subjectName = normalizeDN(cert.subjectName);
            if (cert.issuerName) cert.issuerName = normalizeDN(cert.issuerName);
            if (cert.thumbprint) cert.thumbprint = normalizeFingerprint(cert.thumbprint);
        }
    }

    // Normalize fingerprints in properties
    if (c.properties) {
        for (const prop of c.properties) {
            if (prop.name && prop.name.includes('fingerprint')) {
                prop.value = normalizeFingerprint(prop.value);
            }
            if (prop.name && (prop.name.includes('subject') || prop.name.includes('issuer'))
                && prop.value && prop.value.includes('=')) {
                prop.value = normalizeDN(prop.value);
            }
        }
    }

    return c;
}

function normalizeCbom(cbom) {
    const c = JSON.parse(JSON.stringify(cbom));

    // Remove volatile fields
    delete c.serialNumber;
    if (c.metadata) {
        delete c.metadata.timestamp;
        delete c.metadata.tools;
        delete c.metadata.component;

        // Remove volatile metadata properties
        if (c.metadata.properties) {
            c.metadata.properties = c.metadata.properties.filter(p => {
                const name = p.name || '';
                return !name.startsWith('cbom:host:')
                    && !name.startsWith('cbom:scan:')
                    && !name.startsWith('cbom:completion:')
                    && !name.startsWith('cbom:scan_completion');
            });
        }
    }

    // Normalize components
    if (c.components) {
        c.components = c.components.map(normalizeComponent);
        c.components.sort((a, b) => (a['bom-ref'] || '').localeCompare(b['bom-ref'] || ''));
    }

    // Normalize dependencies
    if (c.dependencies) {
        c.dependencies.sort((a, b) => (a.ref || '').localeCompare(b.ref || ''));
        for (const dep of c.dependencies) {
            if (dep.dependsOn) dep.dependsOn.sort();
            if (dep.provides) dep.provides.sort();
        }
    }

    return c;
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

function getBomRefs(components) {
    return new Set(components.map(c => c['bom-ref']).filter(Boolean));
}

// ── Comparison ───────────────────────────────────────────────────────

const normNative = normalizeCbom(native);
const normWasm = normalizeCbom(wasm);

const nativeCats = categorizeComponents(normNative.components);
const wasmCats = categorizeComponents(normWasm.components);

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

console.log('=== CBOM Comparison ===');
console.log(`Native: ${normNative.components?.length || 0} components (${formatBreakdown(nativeCats)})`);
console.log(`WASM:   ${normWasm.components?.length || 0} components (${formatBreakdown(wasmCats)})`);
console.log('');

let allMatch = true;

for (const [key, label] of Object.entries(categoryNames)) {
    const nativeRefs = getBomRefs(nativeCats[key]);
    const wasmRefs = getBomRefs(wasmCats[key]);

    const missing = [...nativeRefs].filter(r => !wasmRefs.has(r));
    const extra = [...wasmRefs].filter(r => !nativeRefs.has(r));

    if (missing.length === 0 && extra.length === 0 && nativeRefs.size === wasmRefs.size) {
        console.log(`${label.padEnd(14)} MATCH (${nativeRefs.size}/${nativeRefs.size})`);
    } else {
        allMatch = false;
        const matched = [...nativeRefs].filter(r => wasmRefs.has(r)).length;
        console.log(`${label.padEnd(14)} MISMATCH (${matched}/${nativeRefs.size} matched)`);
        if (missing.length > 0) {
            console.log(`  Missing in WASM: ${missing.join(', ')}`);
        }
        if (extra.length > 0) {
            console.log(`  Extra in WASM:   ${extra.join(', ')}`);
        }
    }
}

// Dependencies comparison
const nativeDeps = new Set((normNative.dependencies || []).map(d => d.ref));
const wasmDeps = new Set((normWasm.dependencies || []).map(d => d.ref));
const depMissing = [...nativeDeps].filter(r => !wasmDeps.has(r));
const depExtra = [...wasmDeps].filter(r => !nativeDeps.has(r));

console.log('');
if (depMissing.length === 0 && depExtra.length === 0 && nativeDeps.size === wasmDeps.size) {
    console.log(`Dependencies:  MATCH (${nativeDeps.size}/${nativeDeps.size})`);
} else {
    allMatch = false;
    const depMatched = [...nativeDeps].filter(r => wasmDeps.has(r)).length;
    console.log(`Dependencies:  MISMATCH (${depMatched}/${nativeDeps.size} matched)`);
    if (depMissing.length > 0) {
        console.log(`  Missing in WASM: ${depMissing.slice(0, 10).join(', ')}${depMissing.length > 10 ? ` ... and ${depMissing.length - 10} more` : ''}`);
    }
    if (depExtra.length > 0) {
        console.log(`  Extra in WASM:   ${depExtra.slice(0, 10).join(', ')}${depExtra.length > 10 ? ` ... and ${depExtra.length - 10} more` : ''}`);
    }
}

console.log('');
if (allMatch) {
    console.log('RESULT: PASS');
    process.exit(0);
} else {
    console.log('RESULT: DIFFERENCES FOUND');
    process.exit(1);
}
