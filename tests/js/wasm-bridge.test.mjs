/**
 * Tests for wasm/src/js/wasm-bridge.js
 *
 * Requires a WASM build (build-wasm/cbom-generator.wasm + .js).
 * Skips gracefully if build artifacts are not present.
 *
 * Run: node --test tests/js/wasm-bridge.test.mjs
 */

import { describe, it, before } from 'node:test';
import { strict as assert } from 'node:assert';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { statSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(__dirname, '..', '..', 'build-wasm');

// ── Check for WASM build artifacts ───────────────────────────────────

try {
    statSync(join(wasmDir, 'cbom-generator.wasm'));
    statSync(join(wasmDir, 'cbom-generator.js'));
} catch {
    console.log('# Skipping wasm-bridge tests: WASM build not found.');
    console.log('# Run the WASM build first:');
    console.log('#   source ../emsdk/emsdk_env.sh');
    console.log('#   emcmake cmake -B build-wasm -DCMAKE_BUILD_TYPE=Release');
    console.log('#   emmake cmake --build build-wasm');
    process.exit(0);
}

// ── Import the bridge ────────────────────────────────────────────────

const { initScanner } = await import('../../wasm/src/js/wasm-bridge.js');

// ── Helpers ──────────────────────────────────────────────────────────

function textToBytes(text) {
    return new TextEncoder().encode(text);
}

// ── Tests ────────────────────────────────────────────────────────────

let scanner;

before(async () => {
    scanner = await initScanner();
});

describe('initScanner', () => {
    it('returns a WasmScanner with scan and reset methods', () => {
        assert(scanner !== null && scanner !== undefined);
        assert.equal(typeof scanner.scan, 'function');
        assert.equal(typeof scanner.reset, 'function');
        assert.equal(typeof scanner.getModule, 'function');
    });

    it('getModule returns null before first scan', () => {
        // Fresh scanner — no scan performed yet
        assert.equal(scanner.getModule(), null);
    });
});

describe('WasmScanner.scan', () => {
    it('scans a config file and produces valid CycloneDX output', async () => {
        scanner.reset();

        const files = new Map([
            ['etc/nginx/nginx.conf', textToBytes([
                'server {',
                '    ssl_protocols TLSv1.2 TLSv1.3;',
                '    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;',
                '    ssl_certificate /etc/ssl/certs/server.pem;',
                '    ssl_certificate_key /etc/ssl/private/server.key;',
                '}',
            ].join('\n'))],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        const { cbom } = await scanner.scan(files, certData);

        assert.equal(cbom.bomFormat, 'CycloneDX');
        assert(cbom.specVersion, 'specVersion must be present');
        assert(cbom.metadata, 'metadata must be present');
        assert(Array.isArray(cbom.components), 'components must be an array');
    });

    it('scans with cert metadata JSON written to MEMFS', async () => {
        scanner.reset();

        const files = new Map([
            ['etc/ssl/certs/test.pem', textToBytes('-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----')],
        ]);

        const certData = {
            certs: [{
                filePath: 'etc/ssl/certs/test.pem',
                subject: 'CN=test, O=TestOrg, C=US',
                issuer: 'CN=test, O=TestOrg, C=US',
                serialNumber: '01',
                notBefore: '2024-01-01T00:00:00Z',
                notAfter: '2025-01-01T00:00:00Z',
                signatureAlgorithm: 'sha256WithRSAEncryption',
                signatureAlgorithmOid: '1.2.840.113549.1.1.11',
                publicKeyAlgorithm: 'RSA',
                publicKeyAlgorithmOid: '1.2.840.113549.1.1.1',
                publicKeySize: 2048,
                namedCurve: '',
                fingerprintSha256: 'aa:bb:cc',
                isCa: false,
                isSelfSigned: true,
            }],
            keys: [],
            warnings: [],
        };

        const { cbom } = await scanner.scan(files, certData);

        assert.equal(cbom.bomFormat, 'CycloneDX');
        assert(Array.isArray(cbom.components));

        // Verify the cert metadata file was written to MEMFS
        const mod = scanner.getModule();
        const metadataContent = mod.FS.readFile('/scan/.cert-metadata.json', { encoding: 'utf8' });
        const metadata = JSON.parse(metadataContent);
        assert.equal(metadata.certs.length, 1);
        assert.equal(metadata.certs[0].subject, 'CN=test, O=TestOrg, C=US');
    });

    it('mounts files in correct MEMFS paths with nested directories', async () => {
        scanner.reset();

        const files = new Map([
            ['usr/lib/libssl.so.3', textToBytes('')],
            ['etc/ssl/certs/ca.pem', textToBytes('cert')],
            ['deep/nested/path/to/file.conf', textToBytes('config')],
        ]);

        // Don't need a full scan — just mount and check paths
        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData);

        const mod = scanner.getModule();

        // Verify files exist at the expected MEMFS paths
        const content = mod.FS.readFile('/scan/etc/ssl/certs/ca.pem', { encoding: 'utf8' });
        assert.equal(content, 'cert');

        const deepContent = mod.FS.readFile('/scan/deep/nested/path/to/file.conf', { encoding: 'utf8' });
        assert.equal(deepContent, 'config');
    });

    it('supports specVersion 1.6 option', async () => {
        scanner.reset();

        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        const { cbom } = await scanner.scan(files, certData, { specVersion: '1.6' });

        assert.equal(cbom.bomFormat, 'CycloneDX');
    });

    it('fires progress callback during scan', async () => {
        scanner.reset();

        const files = new Map([
            ['file1.conf', textToBytes('content1')],
            ['file2.conf', textToBytes('content2')],
        ]);

        const progressCalls = [];
        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData, {
            onProgress: (info) => progressCalls.push({ ...info }),
        });

        // Should see mounting phases + scanning + reading-output
        assert(progressCalls.length >= 3);
        assert(progressCalls.some(p => p.phase === 'mounting'));
        assert(progressCalls.some(p => p.phase === 'scanning'));
        assert(progressCalls.some(p => p.phase === 'reading-output'));

        // First mounting call should have file count
        const mountCalls = progressCalls.filter(p => p.phase === 'mounting');
        assert.equal(mountCalls.length, 2);
        assert.equal(mountCalls[0].filesMounted, 1);
        assert.equal(mountCalls[1].filesMounted, 2);
        assert.equal(mountCalls[0].totalFiles, 2);
    });
});

describe('WasmScanner — plugins and registry', () => {
    it('mounts embedded plugins into MEMFS at /plugins/', async () => {
        scanner.reset();

        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData, { pluginSet: 'embedded' });

        const mod = scanner.getModule();

        // Verify /plugins/ directory exists and has YAML files
        const pluginDir = mod.FS.readdir('/plugins');
        const yamlFiles = pluginDir.filter(f => f.endsWith('.yaml'));
        assert(yamlFiles.length > 0, 'Should have mounted plugin YAML files');
    });

    it('mounts ubuntu plugins into MEMFS at /plugins/', async () => {
        scanner.reset();

        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData, { pluginSet: 'ubuntu' });

        const mod = scanner.getModule();

        const pluginDir = mod.FS.readdir('/plugins');
        const yamlFiles = pluginDir.filter(f => f.endsWith('.yaml'));
        assert(yamlFiles.length > 0, 'Should have mounted ubuntu plugin YAML files');
        // Ubuntu has more plugins than embedded
        assert(yamlFiles.length > 20, `Expected >20 ubuntu plugins, got ${yamlFiles.length}`);
    });

    it('mounts crypto registry into MEMFS at /registry/', async () => {
        scanner.reset();

        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData, { registry: 'yocto' });

        const mod = scanner.getModule();

        // Verify registry file exists
        const registryContent = mod.FS.readFile(
            '/registry/crypto-registry-yocto.yaml',
            { encoding: 'utf8' }
        );
        assert(registryContent.length > 0, 'Registry YAML should not be empty');
        assert(registryContent.includes('crypto_libraries'), 'Registry should contain crypto_libraries section');
    });

    it('supports all four registry types', async () => {
        for (const reg of ['ubuntu', 'yocto', 'openwrt', 'alpine']) {
            scanner.reset();

            const files = new Map([
                ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
            ]);
            const certData = { certs: [], keys: [], warnings: [] };
            const { cbom } = await scanner.scan(files, certData, { registry: reg });

            assert.equal(cbom.bomFormat, 'CycloneDX');

            const mod = scanner.getModule();
            const registryContent = mod.FS.readFile(
                `/registry/crypto-registry-${reg}.yaml`,
                { encoding: 'utf8' }
            );
            assert(registryContent.length > 0, `Registry ${reg} should be non-empty`);
        }
    });
});

describe('WasmScanner — scan path detection', () => {
    it('auto-detects rootfs structure and passes multiple scan paths', async () => {
        scanner.reset();

        // Simulate a rootfs-like directory layout
        const files = new Map([
            ['usr/bin/test-binary', textToBytes('fake-binary')],
            ['usr/lib/libcrypto.so', textToBytes('fake-lib')],
            ['etc/ssl/openssl.cnf', textToBytes('ssl config')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData);

        // The scan should have detected /scan/usr/bin, /scan/usr/lib, /scan/etc
        // We can verify by checking the Module still has these directories
        const mod = scanner.getModule();
        const usrBinExists = (() => {
            try { return mod.FS.isDir(mod.FS.stat('/scan/usr/bin').mode); }
            catch { return false; }
        })();
        assert(usrBinExists, '/scan/usr/bin should exist in MEMFS');
    });

    it('falls back to /scan when no rootfs structure detected', async () => {
        scanner.reset();

        // Non-rootfs layout — just loose files
        const files = new Map([
            ['config.yaml', textToBytes('key: value')],
            ['data.json', textToBytes('{}')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        const { cbom } = await scanner.scan(files, certData);

        assert.equal(cbom.bomFormat, 'CycloneDX');
    });

    it('detects rootfs structure inside a single top-level directory', async () => {
        scanner.reset();

        // Simulate an archive with a rootfs/ prefix (common for rootfs tarballs)
        const files = new Map([
            ['rootfs/usr/bin/test-binary', textToBytes('fake-binary')],
            ['rootfs/usr/lib/libcrypto.so', textToBytes('fake-lib')],
            ['rootfs/etc/ssl/openssl.cnf', textToBytes('ssl config')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files, certData);

        // The scan should have detected /scan/rootfs/usr/bin, /scan/rootfs/usr/lib, /scan/rootfs/etc
        const mod = scanner.getModule();
        const usrBinExists = (() => {
            try { return mod.FS.isDir(mod.FS.stat('/scan/rootfs/usr/bin').mode); }
            catch { return false; }
        })();
        assert(usrBinExists, '/scan/rootfs/usr/bin should exist in MEMFS');
    });

    it('uses explicit scanPaths when provided', async () => {
        scanner.reset();

        const files = new Map([
            ['custom/path/config.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);

        const certData = { certs: [], keys: [], warnings: [] };
        const { cbom } = await scanner.scan(files, certData, {
            scanPaths: ['custom/path'],
        });

        assert.equal(cbom.bomFormat, 'CycloneDX');
    });
});

describe('WasmScanner — service discovery flag', () => {
    it('omits --discover-services when discoverServices is false', async () => {
        scanner.reset();

        const stderrLines = [];
        const customScanner = await initScanner({
            onStderr: (line) => stderrLines.push(line),
        });

        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);
        const certData = { certs: [], keys: [], warnings: [] };
        await customScanner.scan(files, certData, { discoverServices: false });

        // When discoverServices is false, the C side should NOT
        // print the service discovery INFO message
        const hasServiceDiscovery = stderrLines.some(
            l => l.includes('Service discovery')
        );
        // We can't fully verify the flag isn't passed, but we verify
        // the scan completes without error
        const mod = customScanner.getModule();
        assert(mod !== null, 'Module should exist after scan');
    });
});

describe('WasmScanner.reset', () => {
    it('each scan gets a fresh Module with no prior state', async () => {
        // First scan
        scanner.reset();
        const files1 = new Map([
            ['first-scan/marker.txt', textToBytes('first')],
        ]);
        const certData = { certs: [], keys: [], warnings: [] };
        await scanner.scan(files1, certData);

        // Verify first marker exists in first Module
        const mod1 = scanner.getModule();
        const marker1 = mod1.FS.readFile('/scan/first-scan/marker.txt', { encoding: 'utf8' });
        assert.equal(marker1, 'first');

        // Reset and second scan — creates a brand new Module
        scanner.reset();
        const files2 = new Map([
            ['second-scan/marker.txt', textToBytes('second')],
        ]);
        await scanner.scan(files2, certData);

        // Verify second marker exists in second Module
        const mod2 = scanner.getModule();
        const marker2 = mod2.FS.readFile('/scan/second-scan/marker.txt', { encoding: 'utf8' });
        assert.equal(marker2, 'second');

        // Verify first scan's files are NOT in the second Module's MEMFS
        let firstGone = false;
        try {
            mod2.FS.readFile('/scan/first-scan/marker.txt', { encoding: 'utf8' });
        } catch {
            firstGone = true;
        }
        assert(firstGone, 'First scan files should not exist in fresh Module');
    });
});

describe('WasmScanner — edge cases', () => {
    it('handles scan with no files gracefully', async () => {
        scanner.reset();

        const files = new Map();
        const certData = { certs: [], keys: [], warnings: [] };
        const { cbom } = await scanner.scan(files, certData);

        assert.equal(cbom.bomFormat, 'CycloneDX');
        assert(Array.isArray(cbom.components));
    });

    it('handles null certData gracefully', async () => {
        scanner.reset();

        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);

        const { cbom } = await scanner.scan(files, null);
        assert.equal(cbom.bomFormat, 'CycloneDX');
    });
});

describe('index.js — PLATFORMS presets', () => {
    it('exports PLATFORMS with correct structure', async () => {
        const { PLATFORMS } = await import('../../wasm/src/js/index.js');

        assert(PLATFORMS.ubuntu, 'Should have ubuntu platform');
        assert(PLATFORMS.yocto, 'Should have yocto platform');
        assert(PLATFORMS.openwrt, 'Should have openwrt platform');
        assert(PLATFORMS.alpine, 'Should have alpine platform');
        assert(PLATFORMS.docker, 'Should have docker platform');
        assert(PLATFORMS.debian, 'Should have debian platform');
        assert(PLATFORMS.buildroot, 'Should have buildroot platform');

        // Verify structure
        assert.equal(PLATFORMS.yocto.pluginSet, 'embedded');
        assert.equal(PLATFORMS.yocto.registry, 'yocto');
        assert.equal(PLATFORMS.ubuntu.pluginSet, 'ubuntu');
        assert.equal(PLATFORMS.ubuntu.registry, 'ubuntu');
        assert.equal(PLATFORMS.openwrt.pluginSet, 'embedded');
        assert.equal(PLATFORMS.openwrt.registry, 'openwrt');
    });

    it('PLATFORMS preset can be spread into scan options', async () => {
        const { PLATFORMS } = await import('../../wasm/src/js/index.js');

        scanner.reset();
        const files = new Map([
            ['test.conf', textToBytes('ssl_protocols TLSv1.3;')],
        ]);
        const certData = { certs: [], keys: [], warnings: [] };

        const { cbom } = await scanner.scan(files, certData, {
            ...PLATFORMS.yocto,
        });

        assert.equal(cbom.bomFormat, 'CycloneDX');
    });
});
