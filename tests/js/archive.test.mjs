/**
 * Tests for wasm/src/js/archive.js
 *
 * Uses Node.js built-in test runner and programmatic fixture creation.
 * Run: node --test tests/js/archive.test.mjs
 */

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { gzipSync, zipSync, strToU8 } from '../../wasm/node_modules/fflate/esm/index.mjs';
import { extractArchive, detectFormat } from '../../wasm/src/js/archive.js';

// ── Tar fixture builder ─────────────────────────────────────────────

const TAR_BLOCK = 512;

function encodeOctal(num, len) {
    const s = num.toString(8);
    // Pad with leading zeros, leave room for trailing null
    return s.padStart(len - 1, '0') + '\0';
}

function writeString(buf, offset, str, length) {
    const encoded = new TextEncoder().encode(str);
    buf.set(encoded.subarray(0, length), offset);
}

function computeChecksum(header) {
    // Checksum is calculated with the checksum field filled with spaces
    let sum = 0;
    for (let i = 0; i < TAR_BLOCK; i++) {
        // Checksum field at 148..155 is treated as spaces
        if (i >= 148 && i < 156) {
            sum += 0x20;
        } else {
            sum += header[i];
        }
    }
    return sum;
}

/**
 * Build a valid POSIX tar archive from an array of file entries.
 * @param {Array<{name: string, data: Uint8Array|string, typeflag?: number}>} files
 * @returns {Uint8Array}
 */
function createTarBuffer(files) {
    const blocks = [];

    for (const file of files) {
        const header = new Uint8Array(TAR_BLOCK);
        const data = typeof file.data === 'string'
            ? new TextEncoder().encode(file.data)
            : file.data;
        const typeflag = file.typeflag ?? 0x30; // '0' = regular file

        // name (0, 100)
        writeString(header, 0, file.name, 100);
        // mode (100, 8)
        writeString(header, 100, encodeOctal(0o644, 8), 8);
        // uid (108, 8)
        writeString(header, 108, encodeOctal(0, 8), 8);
        // gid (116, 8)
        writeString(header, 116, encodeOctal(0, 8), 8);
        // size (124, 12)
        writeString(header, 124, encodeOctal(data.length, 12), 12);
        // mtime (136, 12)
        writeString(header, 136, encodeOctal(0, 12), 12);
        // typeflag (156, 1)
        header[156] = typeflag;
        // magic (257, 6)
        writeString(header, 257, 'ustar\0', 6);
        // version (263, 2)
        writeString(header, 263, '00', 2);

        // Compute and write checksum (148, 8)
        const chksum = computeChecksum(header);
        writeString(header, 148, encodeOctal(chksum, 7) + ' ', 8);

        blocks.push(header);

        if (data.length > 0) {
            // File data padded to 512-byte boundary
            const paddedSize = Math.ceil(data.length / TAR_BLOCK) * TAR_BLOCK;
            const dataBlock = new Uint8Array(paddedSize);
            dataBlock.set(data);
            blocks.push(dataBlock);
        }
    }

    // End-of-archive: two zero blocks
    blocks.push(new Uint8Array(TAR_BLOCK));
    blocks.push(new Uint8Array(TAR_BLOCK));

    // Concatenate all blocks
    const totalSize = blocks.reduce((sum, b) => sum + b.length, 0);
    const result = new Uint8Array(totalSize);
    let offset = 0;
    for (const block of blocks) {
        result.set(block, offset);
        offset += block.length;
    }
    return result;
}

// ── Tests ───────────────────────────────────────────────────────────

describe('detectFormat', () => {
    it('detects gzip (tar.gz)', () => {
        const header = new Uint8Array(512);
        header[0] = 0x1f;
        header[1] = 0x8b;
        assert.equal(detectFormat(header), 'tar.gz');
    });

    it('detects bzip2 (tar.bz2)', () => {
        const header = new Uint8Array(512);
        header[0] = 0x42; // B
        header[1] = 0x5a; // Z
        header[2] = 0x68; // h
        assert.equal(detectFormat(header), 'tar.bz2');
    });

    it('detects xz (tar.xz)', () => {
        const header = new Uint8Array(512);
        header.set([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]);
        assert.equal(detectFormat(header), 'tar.xz');
    });

    it('detects zip', () => {
        const header = new Uint8Array(512);
        header.set([0x50, 0x4b, 0x03, 0x04]);
        assert.equal(detectFormat(header), 'zip');
    });

    it('detects tar (ustar magic)', () => {
        const header = new Uint8Array(512);
        writeString(header, 257, 'ustar', 5);
        assert.equal(detectFormat(header), 'tar');
    });

    it('returns single for non-archive content', () => {
        const header = new TextEncoder().encode('Hello, world!');
        assert.equal(detectFormat(header), 'single');
    });

    it('returns unknown for empty input', () => {
        assert.equal(detectFormat(new Uint8Array(0)), 'unknown');
        assert.equal(detectFormat(null), 'unknown');
    });
});

describe('extractArchive', () => {
    it('extracts tar.gz with multiple files', async () => {
        const tar = createTarBuffer([
            { name: 'readme.txt', data: 'Hello World' },
            { name: 'config/app.conf', data: 'ssl_protocols TLSv1.3;' },
            { name: 'certs/server.pem', data: '-----BEGIN CERTIFICATE-----' },
        ]);
        const tgz = gzipSync(tar);

        const files = await extractArchive(tgz);

        assert.equal(files.size, 3);
        assert(files.has('readme.txt'));
        assert(files.has('config/app.conf'));
        assert(files.has('certs/server.pem'));

        const readme = new TextDecoder().decode(files.get('readme.txt'));
        assert.equal(readme, 'Hello World');
    });

    it('extracts zip archives', async () => {
        const zipData = zipSync({
            'doc.txt': strToU8('Document content'),
            'data/config.yaml': strToU8('key: value'),
        });

        const files = await extractArchive(zipData);

        assert.equal(files.size, 2);
        assert(files.has('doc.txt'));
        assert(files.has('data/config.yaml'));

        const doc = new TextDecoder().decode(files.get('doc.txt'));
        assert.equal(doc, 'Document content');
    });

    it('extracts plain tar archives', async () => {
        const tar = createTarBuffer([
            { name: 'file1.txt', data: 'content1' },
            { name: 'file2.txt', data: 'content2' },
        ]);

        const files = await extractArchive(tar);

        assert.equal(files.size, 2);
        const content1 = new TextDecoder().decode(files.get('file1.txt'));
        assert.equal(content1, 'content1');
    });

    it('handles single file passthrough', async () => {
        const data = new TextEncoder().encode('ssl_ciphers ECDHE-RSA-AES256;');
        const files = await extractArchive(data);

        assert.equal(files.size, 1);
        assert(files.has('file'));
    });

    it('uses File.name for single file passthrough', async () => {
        const content = new TextEncoder().encode('certificate data');
        // Simulate a File-like object
        const fakeFile = {
            name: 'server.pem',
            arrayBuffer: async () => content.buffer,
        };

        const files = await extractArchive(fakeFile);

        assert.equal(files.size, 1);
        assert(files.has('server.pem'));
    });

    it('accepts ArrayBuffer input', async () => {
        const data = new TextEncoder().encode('plain text content');
        const files = await extractArchive(data.buffer);

        assert.equal(files.size, 1);
        assert(files.has('file'));
    });

    it('normalizes paths and rejects traversal', async () => {
        const tar = createTarBuffer([
            { name: '../etc/passwd', data: 'root:x:0:0' },
            { name: 'safe/file.txt', data: 'safe content' },
            { name: '/absolute/path.txt', data: 'abs content' },
            { name: './dotslash/file.txt', data: 'dot content' },
        ]);
        const tgz = gzipSync(tar);

        const files = await extractArchive(tgz);

        // ../etc/passwd should be rejected
        assert(!files.has('../etc/passwd'));
        assert(!files.has('etc/passwd'));
        // /absolute should be normalized to absolute/path.txt
        assert(files.has('absolute/path.txt'));
        // ./dotslash should be normalized
        assert(files.has('dotslash/file.txt'));
        // safe file always present
        assert(files.has('safe/file.txt'));
    });

    it('detects zip bombs by compression ratio', async () => {
        // Create highly compressible data (all zeros)
        const bigData = new Uint8Array(1024 * 1024); // 1MB of zeros
        const tar = createTarBuffer([{ name: 'bomb.bin', data: bigData }]);
        const tgz = gzipSync(tar);

        // The compression ratio of 1MB zeros should be enormous
        // Set a very low threshold to trigger detection
        await assert.rejects(
            () => extractArchive(tgz, { maxCompressionRatio: 2 }),
            /zip bomb/i
        );
    });

    it('enforces file count limit', async () => {
        const files = [];
        for (let i = 0; i < 10; i++) {
            files.push({ name: `file${i}.txt`, data: `content ${i}` });
        }
        const tar = createTarBuffer(files);
        const tgz = gzipSync(tar);

        await assert.rejects(
            () => extractArchive(tgz, { maxFileCount: 5 }),
            /file count limit/i
        );
    });

    it('enforces extracted size limit', async () => {
        const largeContent = new Uint8Array(1024).fill(0x41); // 1KB of 'A'
        const tar = createTarBuffer([
            { name: 'large1.bin', data: largeContent },
            { name: 'large2.bin', data: largeContent },
        ]);
        const tgz = gzipSync(tar);

        await assert.rejects(
            () => extractArchive(tgz, { maxExtractedSize: 1500 }),
            /size limit/i
        );
    });

    it('skips symlinks', async () => {
        const tar = createTarBuffer([
            { name: 'real.txt', data: 'real content' },
            { name: 'link.txt', data: '', typeflag: 0x32 }, // '2' = symlink
        ]);
        const tgz = gzipSync(tar);

        const files = await extractArchive(tgz);

        assert.equal(files.size, 1);
        assert(files.has('real.txt'));
        assert(!files.has('link.txt'));
    });

    it('skips zero-byte files', async () => {
        const tar = createTarBuffer([
            { name: 'nonempty.txt', data: 'has content' },
            { name: 'empty.txt', data: '' },
        ]);
        const tgz = gzipSync(tar);

        const files = await extractArchive(tgz);

        assert.equal(files.size, 1);
        assert(files.has('nonempty.txt'));
        assert(!files.has('empty.txt'));
    });

    it('skips directories', async () => {
        const tar = createTarBuffer([
            { name: 'dir/', data: '', typeflag: 0x35 }, // '5' = directory
            { name: 'dir/file.txt', data: 'in directory' },
        ]);
        const tgz = gzipSync(tar);

        const files = await extractArchive(tgz);

        assert.equal(files.size, 1);
        assert(files.has('dir/file.txt'));
    });

    it('fires progress callback', async () => {
        const tar = createTarBuffer([
            { name: 'a.txt', data: 'aaa' },
            { name: 'b.txt', data: 'bbb' },
            { name: 'c.txt', data: 'ccc' },
        ]);
        const tgz = gzipSync(tar);

        const progressCalls = [];
        await extractArchive(tgz, {
            onProgress: (info) => progressCalls.push({ ...info }),
        });

        assert.equal(progressCalls.length, 3);
        assert.equal(progressCalls[0].filesExtracted, 1);
        assert.equal(progressCalls[0].currentFile, 'a.txt');
        assert.equal(progressCalls[2].filesExtracted, 3);
        assert(progressCalls[2].bytesExtracted > 0);
    });

    it('throws on unsupported bz2 format', async () => {
        const bz2Header = new Uint8Array(512);
        bz2Header[0] = 0x42; // B
        bz2Header[1] = 0x5a; // Z
        bz2Header[2] = 0x68; // h
        bz2Header[3] = 0x39; // block size

        await assert.rejects(
            () => extractArchive(bz2Header),
            /unsupported archive format/i
        );
    });

    it('throws on empty input', async () => {
        await assert.rejects(
            () => extractArchive(new Uint8Array(0)),
            /empty/i
        );
    });
});
