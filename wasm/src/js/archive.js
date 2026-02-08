/**
 * Archive extraction module for cbom-generator WASM edition.
 *
 * Extracts tar.gz, zip, tar, and single files into a flat Map<string, Uint8Array>
 * suitable for mounting into Emscripten MEMFS.
 *
 * @module archive
 */

import { gunzipSync, unzipSync } from 'fflate';

// ── Tar parser ──────────────────────────────────────────────────────

const TAR_BLOCK = 512;
const TYPEFLAG_FILE = 0x30;      // '0'
const TYPEFLAG_FILE_ALT = 0;     // '\0' (legacy)
const TYPEFLAG_DIR = 0x35;       // '5'
const TYPEFLAG_SYMLINK = 0x32;   // '2'

function readString(buf, offset, length) {
    let end = offset;
    const limit = offset + length;
    while (end < limit && buf[end] !== 0) end++;
    return new TextDecoder().decode(buf.subarray(offset, end));
}

function parseOctal(buf, offset, length) {
    const str = readString(buf, offset, length).trim();
    if (str.length === 0) return 0;
    return parseInt(str, 8) || 0;
}

function isZeroBlock(buf, offset) {
    for (let i = offset; i < offset + TAR_BLOCK && i < buf.length; i++) {
        if (buf[i] !== 0) return false;
    }
    return true;
}

/**
 * Parse a tar archive buffer into an array of file entries.
 * @param {Uint8Array} buf - Raw tar data
 * @returns {Array<{name: string, data: Uint8Array, typeflag: number, linkname?: string}>}
 */
function parseTar(buf) {
    const entries = [];
    let offset = 0;

    while (offset + TAR_BLOCK <= buf.length) {
        if (isZeroBlock(buf, offset)) break;

        const name = readString(buf, offset, 100);
        const size = parseOctal(buf, offset + 124, 12);
        const typeflag = buf[offset + 156];
        const linkname = readString(buf, offset + 157, 100);
        const prefix = readString(buf, offset + 345, 155);

        const fullName = prefix ? prefix + '/' + name : name;

        offset += TAR_BLOCK;

        const entry = {
            name: fullName,
            data: buf.slice(offset, offset + size),
            typeflag,
        };
        if (typeflag === TYPEFLAG_SYMLINK && linkname) {
            entry.linkname = linkname;
        }
        entries.push(entry);

        // Advance past file data (padded to 512-byte boundary)
        offset += Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
    }

    return entries;
}

// ── Path normalization ──────────────────────────────────────────────

/**
 * Normalize and validate an extracted file path.
 * Returns null if the path is unsafe (traversal, absolute).
 * @param {string} raw
 * @returns {string|null}
 */
function normalizePath(raw) {
    // Strip leading ./ and /
    let p = raw.replace(/^\.\//, '').replace(/^\/+/, '');
    // Collapse consecutive slashes
    p = p.replace(/\/\/+/g, '/');
    // Strip trailing slashes
    p = p.replace(/\/+$/, '');

    if (p.length === 0) return null;

    // Reject any path component that is '..'
    const parts = p.split('/');
    for (const part of parts) {
        if (part === '..') return null;
    }

    // Reject if still absolute somehow
    if (p.startsWith('/')) return null;

    return p;
}

// ── Format detection ────────────────────────────────────────────────

/**
 * Detect archive format from magic bytes.
 * @param {Uint8Array} header - First 512 bytes of the file
 * @returns {'tar.gz'|'tar.bz2'|'tar.xz'|'tar'|'zip'|'single'|'unknown'}
 */
export function detectFormat(header) {
    if (!header || header.length === 0) return 'unknown';

    // gzip: 1f 8b
    if (header.length >= 2 && header[0] === 0x1f && header[1] === 0x8b) {
        return 'tar.gz';
    }

    // bzip2: 42 5a 68 ("BZh")
    if (header.length >= 3 && header[0] === 0x42 && header[1] === 0x5a && header[2] === 0x68) {
        return 'tar.bz2';
    }

    // xz: fd 37 7a 58 5a 00
    if (header.length >= 6 &&
        header[0] === 0xfd && header[1] === 0x37 && header[2] === 0x7a &&
        header[3] === 0x58 && header[4] === 0x5a && header[5] === 0x00) {
        return 'tar.xz';
    }

    // zip: 50 4b 03 04 ("PK\x03\x04")
    if (header.length >= 4 &&
        header[0] === 0x50 && header[1] === 0x4b && header[2] === 0x03 && header[3] === 0x04) {
        return 'zip';
    }

    // tar: "ustar" at offset 257
    if (header.length >= 263) {
        const magic = readString(header, 257, 5);
        if (magic === 'ustar') return 'tar';
    }

    // Has content but not a recognized archive
    if (header.length > 0) return 'single';

    return 'unknown';
}

// ── Main extraction ─────────────────────────────────────────────────

/**
 * Extract an archive into a flat file map with optional symlink info.
 * @param {File|ArrayBuffer|Uint8Array} input - The archive file
 * @param {Object} [options]
 * @param {number} [options.maxExtractedSize=1073741824] - Max total extracted size in bytes (default: 1GB)
 * @param {number} [options.maxFileCount=500000] - Max number of files
 * @param {number} [options.maxCompressionRatio=100] - Zip bomb detection threshold
 * @param {function} [options.onProgress] - Callback: ({filesExtracted, bytesExtracted, currentFile})
 * @returns {Promise<{files: Map<string, Uint8Array>, symlinks: Map<string, string>}>}
 * @throws {Error} if archive is invalid, too large, or a zip bomb
 */
export async function extractArchive(input, options = {}) {
    const {
        maxExtractedSize = 1024 * 1024 * 1024,
        maxFileCount = 500_000,
        maxCompressionRatio = 100,
        onProgress = null,
    } = options;

    // Normalize input to Uint8Array
    let data;
    if (input instanceof Uint8Array) {
        data = input;
    } else if (input instanceof ArrayBuffer) {
        data = new Uint8Array(input);
    } else if (typeof input === 'object' && typeof input.arrayBuffer === 'function') {
        // File or Blob
        data = new Uint8Array(await input.arrayBuffer());
    } else {
        throw new Error('Input must be a Uint8Array, ArrayBuffer, or File/Blob');
    }

    if (data.length === 0) {
        throw new Error('Input is empty');
    }

    const headerSlice = data.subarray(0, Math.min(data.length, 512));
    const format = detectFormat(headerSlice);

    const files = new Map();
    const symlinks = new Map();
    let totalBytes = 0;
    let fileCount = 0;

    function addFile(path, content) {
        const normalized = normalizePath(path);
        if (!normalized) return; // skip unsafe paths

        // Skip zero-byte files
        if (content.length === 0) return;

        fileCount++;
        if (fileCount > maxFileCount) {
            throw new Error(`File count limit exceeded (max ${maxFileCount})`);
        }

        totalBytes += content.length;
        if (totalBytes > maxExtractedSize) {
            throw new Error(`Extracted size limit exceeded (max ${maxExtractedSize} bytes)`);
        }

        files.set(normalized, content);

        if (onProgress) {
            onProgress({
                filesExtracted: fileCount,
                bytesExtracted: totalBytes,
                currentFile: normalized,
            });
        }
    }

    switch (format) {
        case 'tar.gz': {
            const decompressed = gunzipSync(data);

            // Zip bomb check
            if (data.length > 0 && decompressed.length / data.length > maxCompressionRatio) {
                throw new Error(
                    `Suspected zip bomb: compression ratio ${(decompressed.length / data.length).toFixed(1)} ` +
                    `exceeds threshold ${maxCompressionRatio}`
                );
            }

            const entries = parseTar(decompressed);
            for (const entry of entries) {
                if (entry.typeflag === TYPEFLAG_DIR) continue;
                if (entry.typeflag === TYPEFLAG_SYMLINK) {
                    const normalized = normalizePath(entry.name);
                    if (normalized && entry.linkname) symlinks.set(normalized, entry.linkname);
                    continue;
                }
                if (entry.typeflag !== TYPEFLAG_FILE && entry.typeflag !== TYPEFLAG_FILE_ALT) continue;
                addFile(entry.name, entry.data);
            }
            break;
        }

        case 'zip': {
            const zipEntries = unzipSync(data);
            for (const [path, content] of Object.entries(zipEntries)) {
                // Skip directories (paths ending with /)
                if (path.endsWith('/')) continue;

                totalBytes += content.length;
                if (data.length > 0 && totalBytes / data.length > maxCompressionRatio) {
                    throw new Error(
                        `Suspected zip bomb: compression ratio ${(totalBytes / data.length).toFixed(1)} ` +
                        `exceeds threshold ${maxCompressionRatio}`
                    );
                }
                // Reset totalBytes since addFile will re-add
                totalBytes -= content.length;

                addFile(path, content);
            }
            break;
        }

        case 'tar': {
            const entries = parseTar(data);
            for (const entry of entries) {
                if (entry.typeflag === TYPEFLAG_DIR) continue;
                if (entry.typeflag === TYPEFLAG_SYMLINK) {
                    const normalized = normalizePath(entry.name);
                    if (normalized && entry.linkname) symlinks.set(normalized, entry.linkname);
                    continue;
                }
                if (entry.typeflag !== TYPEFLAG_FILE && entry.typeflag !== TYPEFLAG_FILE_ALT) continue;
                addFile(entry.name, entry.data);
            }
            break;
        }

        case 'single': {
            const name = (typeof input === 'object' && input.name) ? input.name : 'file';
            addFile(name, data);
            break;
        }

        case 'tar.bz2':
        case 'tar.xz':
        case 'unknown':
        default:
            throw new Error(`Unsupported archive format: ${format}`);
    }

    return { files, symlinks };
}
