/**
 * Tests for wasm/src/js/cert-parser.js
 *
 * Uses Node.js built-in test runner. Generates test certificates and keys
 * with OpenSSL at runtime so tests are self-contained.
 *
 * Run: node --test tests/js/cert-parser.test.mjs
 */

import { describe, it, before } from 'node:test';
import { strict as assert } from 'node:assert';
import { execSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseCryptoAssets, isCryptoFile } from '../../wasm/src/js/cert-parser.js';

// ── Fixture generation helpers ───────────────────────────────────────

let tmpDir;

function openssl(args) {
    return execSync(`openssl ${args}`, { cwd: tmpDir, stdio: ['pipe', 'pipe', 'pipe'] });
}

function opensslText(args) {
    return openssl(args).toString().trim();
}

function readFixture(name) {
    return readFileSync(join(tmpDir, name));
}

function readFixtureText(name) {
    return readFileSync(join(tmpDir, name), 'utf8');
}

function filesToMap(entries) {
    const map = new Map();
    for (const [path, data] of entries) {
        const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        map.set(path, bytes);
    }
    return map;
}

/**
 * Check if OpenSSL supports Ed25519 key generation.
 */
function hasEd25519Support() {
    try {
        execSync('openssl genpkey -algorithm Ed25519 -out /dev/null 2>&1');
        return true;
    } catch {
        return false;
    }
}

// ── Setup ────────────────────────────────────────────────────────────

before(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cert-parser-test-'));

    // RSA-2048 self-signed CA cert
    openssl('req -x509 -newkey rsa:2048 -keyout rsa2048-ca.key -out rsa2048-ca.pem -days 365 -nodes -subj "/CN=TestCA/O=TestOrg/C=US" -addext "basicConstraints=critical,CA:TRUE"');

    // RSA-4096 cert signed by the CA
    openssl('genrsa -out rsa4096.key 4096');
    openssl('req -new -key rsa4096.key -out rsa4096.csr -subj "/CN=server.example.com/O=ExampleCorp/C=US"');
    openssl('x509 -req -in rsa4096.csr -CA rsa2048-ca.pem -CAkey rsa2048-ca.key -CAcreateserial -out rsa4096.pem -days 365');

    // ECDSA P-256 self-signed cert
    openssl('ecparam -genkey -name prime256v1 -out ec256.key');
    openssl('req -new -x509 -key ec256.key -out ec256.pem -days 365 -subj "/CN=ec256test/C=DE"');

    // ECDSA P-384 self-signed cert
    openssl('ecparam -genkey -name secp384r1 -out ec384.key');
    openssl('req -new -x509 -key ec384.key -out ec384.pem -days 365 -subj "/CN=ec384test/C=FR"');

    // DER-encoded certificate (convert PEM to DER)
    openssl('x509 -in rsa2048-ca.pem -outform DER -out rsa2048-ca.der');

    // PKCS#8 RSA key (standard format for PrivateKeyInfo)
    openssl('pkcs8 -topk8 -in rsa2048-ca.key -out rsa2048-pkcs8.key -nocrypt');

    // PKCS#8 EC key
    openssl('pkcs8 -topk8 -in ec256.key -out ec256-pkcs8.key -nocrypt');

    // PEM chain file: CA cert + server cert + another cert
    const caPem = readFixtureText('rsa2048-ca.pem');
    const serverPem = readFixtureText('rsa4096.pem');
    const ec256Pem = readFixtureText('ec256.pem');
    writeFileSync(join(tmpDir, 'chain.pem'), `${serverPem}\n${caPem}\n${ec256Pem}`);

    // Ed25519 (if supported)
    if (hasEd25519Support()) {
        openssl('genpkey -algorithm Ed25519 -out ed25519.key');
        openssl('req -new -x509 -key ed25519.key -out ed25519.pem -days 365 -subj "/CN=ed25519test/C=JP"');
        openssl('pkcs8 -topk8 -in ed25519.key -out ed25519-pkcs8.key -nocrypt');
    }
});

// ── Tests ────────────────────────────────────────────────────────────

describe('isCryptoFile', () => {
    it('matches cert/key file extensions', () => {
        const dummy = new Uint8Array([0x00]);
        assert(isCryptoFile('etc/ssl/certs/server.pem', dummy));
        assert(isCryptoFile('server.crt', dummy));
        assert(isCryptoFile('server.cer', dummy));
        assert(isCryptoFile('key.der', dummy));
        assert(isCryptoFile('private.key', dummy));
        assert(isCryptoFile('store.p12', dummy));
        assert(isCryptoFile('store.pfx', dummy));
    });

    it('matches path patterns', () => {
        const dummy = new Uint8Array([0x00]);
        assert(isCryptoFile('etc/ssl/certs/ca.txt', dummy));
        assert(isCryptoFile('etc/pki/tls/cert.txt', dummy));
        assert(isCryptoFile('usr/share/ssh/moduli', dummy));
    });

    it('matches PEM headers in content', () => {
        const certPem = new TextEncoder().encode('-----BEGIN CERTIFICATE-----\nMIIB...');
        assert(isCryptoFile('unknown-file', certPem));

        const keyPem = new TextEncoder().encode('-----BEGIN PRIVATE KEY-----\nMIIE...');
        assert(isCryptoFile('some/path/file', keyPem));
    });

    it('matches DER magic bytes', () => {
        const der = new Uint8Array([0x30, 0x82, 0x03, 0x45, 0x00]);
        assert(isCryptoFile('unknown-file', der));
    });

    it('rejects non-crypto files', () => {
        const readme = new TextEncoder().encode('# README\nThis is a readme file.');
        assert(!isCryptoFile('README.md', readme));

        const binary = new Uint8Array([0x7f, 0x45, 0x4c, 0x46]); // ELF
        assert(!isCryptoFile('usr/bin/ls', binary));
    });
});

describe('parseCryptoAssets — certificates', () => {
    it('parses RSA-2048 self-signed certificate', async () => {
        const pem = readFixture('rsa2048-ca.pem');
        const files = filesToMap([['etc/ssl/certs/ca.pem', pem]]);

        const { certs, keys, warnings } = await parseCryptoAssets(files);

        assert.equal(certs.length, 1);
        const cert = certs[0];
        assert.equal(cert.filePath, 'etc/ssl/certs/ca.pem');
        assert(cert.subject.includes('CN=TestCA'));
        assert(cert.subject.includes('O=TestOrg'));
        assert(cert.subject.includes('C=US'));
        assert.equal(cert.issuer, cert.subject); // self-signed
        assert.equal(cert.publicKeyAlgorithm, 'RSA');
        assert.equal(cert.publicKeyAlgorithmOid, '1.2.840.113549.1.1.1');
        assert.equal(cert.publicKeySize, 2048);
        assert.equal(cert.signatureAlgorithm, 'sha256WithRSAEncryption');
        assert.equal(cert.signatureAlgorithmOid, '1.2.840.113549.1.1.11');
        assert.equal(cert.namedCurve, '');
        assert.equal(cert.isCa, true);
        assert.equal(cert.isSelfSigned, true);
        assert(cert.serialNumber.length > 0);
        assert(cert.notBefore.endsWith('Z'));
        assert(cert.notAfter.endsWith('Z'));
        assert(cert.fingerprintSha256.includes(':'));
    });

    it('parses RSA-4096 CA-signed certificate', async () => {
        const pem = readFixture('rsa4096.pem');
        const files = filesToMap([['etc/ssl/certs/server.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);

        assert.equal(certs.length, 1);
        const cert = certs[0];
        assert(cert.subject.includes('CN=server.example.com'));
        assert(cert.issuer.includes('CN=TestCA')); // signed by CA
        assert.notEqual(cert.subject, cert.issuer);
        assert.equal(cert.publicKeyAlgorithm, 'RSA');
        assert.equal(cert.publicKeySize, 4096);
        assert.equal(cert.isSelfSigned, false);
    });

    it('parses ECDSA P-256 certificate', async () => {
        const pem = readFixture('ec256.pem');
        const files = filesToMap([['etc/ssl/certs/ec.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);

        assert.equal(certs.length, 1);
        const cert = certs[0];
        assert(cert.subject.includes('CN=ec256test'));
        assert.equal(cert.publicKeyAlgorithm, 'EC');
        assert.equal(cert.publicKeyAlgorithmOid, '1.2.840.10045.2.1');
        assert.equal(cert.publicKeySize, 256);
        assert.equal(cert.namedCurve, 'P-256');
        assert(cert.signatureAlgorithm.includes('ecdsa'));
    });

    it('parses ECDSA P-384 certificate', async () => {
        const pem = readFixture('ec384.pem');
        const files = filesToMap([['etc/ssl/certs/ec384.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);

        assert.equal(certs.length, 1);
        const cert = certs[0];
        assert(cert.subject.includes('CN=ec384test'));
        assert.equal(cert.publicKeyAlgorithm, 'EC');
        assert.equal(cert.publicKeySize, 384);
        assert.equal(cert.namedCurve, 'P-384');
    });

    it('parses Ed25519 certificate (if supported)', async () => {
        if (!hasEd25519Support()) {
            return; // Skip on systems without Ed25519 support
        }

        const pem = readFixture('ed25519.pem');
        const files = filesToMap([['etc/ssl/certs/ed25519.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);

        assert.equal(certs.length, 1);
        const cert = certs[0];
        assert(cert.subject.includes('CN=ed25519test'));
        assert.equal(cert.publicKeyAlgorithm, 'Ed25519');
        assert.equal(cert.publicKeySize, 256);
    });

    it('parses DER-encoded certificate', async () => {
        const der = readFixture('rsa2048-ca.der');
        const files = filesToMap([['etc/ssl/certs/ca.der', der]]);

        const { certs } = await parseCryptoAssets(files);

        assert.equal(certs.length, 1);
        const cert = certs[0];
        assert(cert.subject.includes('CN=TestCA'));
        assert.equal(cert.publicKeyAlgorithm, 'RSA');
        assert.equal(cert.publicKeySize, 2048);
    });

    it('parses PEM chain file with 3 certificates', async () => {
        const chain = readFixture('chain.pem');
        const files = filesToMap([['etc/ssl/certs/chain.pem', chain]]);

        const { certs } = await parseCryptoAssets(files);

        assert.equal(certs.length, 3);
        // All should have the same filePath since they come from one file
        assert(certs.every(c => c.filePath === 'etc/ssl/certs/chain.pem'));
        // Verify different subjects
        const subjects = certs.map(c => c.subject);
        assert(subjects.some(s => s.includes('CN=server.example.com')));
        assert(subjects.some(s => s.includes('CN=TestCA')));
        assert(subjects.some(s => s.includes('CN=ec256test')));
    });
});

describe('parseCryptoAssets — keys', () => {
    it('parses RSA-2048 private key (PKCS#8 PEM)', async () => {
        const pem = readFixture('rsa2048-pkcs8.key');
        const files = filesToMap([['etc/ssl/private/server.key', pem]]);

        const { keys } = await parseCryptoAssets(files);

        assert.equal(keys.length, 1);
        const key = keys[0];
        assert.equal(key.filePath, 'etc/ssl/private/server.key');
        assert.equal(key.algorithm, 'RSA');
        assert.equal(key.algorithmOid, '1.2.840.113549.1.1.1');
        assert.equal(key.keySize, 2048);
        assert.equal(key.namedCurve, '');
        assert.equal(key.format, 'PEM');
    });

    it('parses legacy RSA private key (PKCS#1 PEM)', async () => {
        const pem = readFixture('rsa2048-ca.key');
        const files = filesToMap([['etc/ssl/private/legacy.key', pem]]);

        const { keys } = await parseCryptoAssets(files);

        assert.equal(keys.length, 1);
        const key = keys[0];
        assert.equal(key.algorithm, 'RSA');
        assert.equal(key.keySize, 2048);
        assert.equal(key.format, 'PEM');
    });

    it('parses EC P-256 private key (PKCS#8 PEM)', async () => {
        const pem = readFixture('ec256-pkcs8.key');
        const files = filesToMap([['etc/ssl/private/ec.key', pem]]);

        const { keys } = await parseCryptoAssets(files);

        assert.equal(keys.length, 1);
        const key = keys[0];
        assert.equal(key.algorithm, 'EC');
        assert.equal(key.keySize, 256);
        assert.equal(key.namedCurve, 'P-256');
        assert.equal(key.format, 'PEM');
    });

    it('parses legacy EC private key (SEC1 PEM)', async () => {
        const pem = readFixture('ec256.key');
        const files = filesToMap([['etc/ssl/private/ec-legacy.key', pem]]);

        const { keys } = await parseCryptoAssets(files);

        // SEC1 key file may contain EC PARAMETERS + EC PRIVATE KEY blocks
        assert(keys.length >= 1);
        const ecKey = keys.find(k => k.algorithm === 'EC');
        assert(ecKey);
        assert.equal(ecKey.namedCurve, 'P-256');
        assert.equal(ecKey.format, 'PEM');
    });
});

describe('parseCryptoAssets — fingerprint accuracy', () => {
    it('SHA-256 fingerprint matches OpenSSL output', async () => {
        const pem = readFixture('rsa2048-ca.pem');
        const files = filesToMap([['etc/ssl/certs/ca.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);
        assert.equal(certs.length, 1);

        // Get OpenSSL fingerprint for comparison
        const opensslOutput = opensslText(`x509 -in ${join(tmpDir, 'rsa2048-ca.pem')} -fingerprint -sha256 -noout`);
        // Format: "sha256 Fingerprint=AB:CD:EF:..." or "SHA256 Fingerprint=AB:CD:EF:..."
        const opensslFp = opensslOutput.split('=')[1].toLowerCase();
        assert.equal(certs[0].fingerprintSha256, opensslFp);
    });
});

describe('parseCryptoAssets — error handling', () => {
    it('adds warning for corrupt/invalid file', async () => {
        const junk = new TextEncoder().encode('-----BEGIN CERTIFICATE-----\nnotvalidbase64!!!\n-----END CERTIFICATE-----');
        const files = filesToMap([['etc/ssl/certs/corrupt.pem', junk]]);

        const { certs, warnings } = await parseCryptoAssets(files);

        assert.equal(certs.length, 0);
        assert(warnings.length > 0);
        assert(warnings.some(w => w.includes('corrupt.pem')));
    });

    it('adds warning for encrypted private key', async () => {
        // Create encrypted key
        openssl('rsa -in rsa2048-ca.key -aes256 -passout pass:test123 -out encrypted.key');

        const pem = readFixture('encrypted.key');
        const files = filesToMap([['etc/ssl/private/encrypted.key', pem]]);

        const { keys, warnings } = await parseCryptoAssets(files);

        assert.equal(keys.length, 0);
        assert(warnings.some(w => w.includes('encrypted') && w.includes('encrypted.key')));
    });

    it('does not crash on binary junk with .pem extension', async () => {
        const junk = new Uint8Array(256);
        for (let i = 0; i < 256; i++) junk[i] = i;
        const files = filesToMap([['etc/ssl/certs/junk.pem', junk]]);

        // Should not throw
        const { certs, keys } = await parseCryptoAssets(files);
        assert.equal(certs.length, 0);
        assert.equal(keys.length, 0);
    });

    it('skips non-crypto files', async () => {
        const readme = new TextEncoder().encode('# README\nThis is just a readme file.');
        const config = new TextEncoder().encode('server {\n  listen 80;\n}');
        const files = filesToMap([
            ['README.md', readme],
            ['etc/nginx/nginx.conf', config],
            ['usr/bin/program', new Uint8Array([0x7f, 0x45, 0x4c, 0x46])],
        ]);

        const { certs, keys, warnings } = await parseCryptoAssets(files);

        assert.equal(certs.length, 0);
        assert.equal(keys.length, 0);
        assert.equal(warnings.length, 0);
    });
});

describe('parseCryptoAssets — progress callback', () => {
    it('fires progress callback for each crypto file', async () => {
        const certPem = readFixture('rsa2048-ca.pem');
        const keyPem = readFixture('rsa2048-pkcs8.key');
        const files = filesToMap([
            ['etc/ssl/certs/ca.pem', certPem],
            ['etc/ssl/private/server.key', keyPem],
            ['README.md', 'not a crypto file'],
        ]);

        const progressCalls = [];
        await parseCryptoAssets(files, {
            onProgress: (info) => progressCalls.push({ ...info }),
        });

        // Should fire for the two crypto files, not the README
        assert.equal(progressCalls.length, 2);
        assert(progressCalls.some(p => p.currentFile === 'etc/ssl/certs/ca.pem'));
        assert(progressCalls.some(p => p.currentFile === 'etc/ssl/private/server.key'));
        // Last call should have cumulative counts
        const last = progressCalls[progressCalls.length - 1];
        assert(last.certsFound >= 1);
        assert(last.keysFound >= 1);
    });
});

describe('parseCryptoAssets — self-signed and CA detection', () => {
    it('detects self-signed certificate', async () => {
        const pem = readFixture('rsa2048-ca.pem');
        const files = filesToMap([['ca.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);
        assert.equal(certs[0].isSelfSigned, true);
    });

    it('detects non-self-signed certificate', async () => {
        const pem = readFixture('rsa4096.pem');
        const files = filesToMap([['server.pem', pem]]);

        const { certs } = await parseCryptoAssets(files);
        assert.equal(certs[0].isSelfSigned, false);
    });

    it('detects CA flag', async () => {
        const caPem = readFixture('rsa2048-ca.pem');
        const serverPem = readFixture('rsa4096.pem');
        const files = filesToMap([
            ['etc/ssl/certs/ca.pem', caPem],
            ['etc/ssl/certs/server.pem', serverPem],
        ]);

        const { certs } = await parseCryptoAssets(files);

        const ca = certs.find(c => c.subject.includes('CN=TestCA'));
        const server = certs.find(c => c.subject.includes('CN=server.example.com'));
        assert.equal(ca.isCa, true);
        assert.equal(server.isCa, false);
    });
});
