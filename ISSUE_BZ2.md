# Feature: Add .tar.bz2 support to WASM scanner

## Summary

The browser-based CBOM Scanner currently supports `.tar.gz`, `.tgz`, `.zip`, and `.tar` archives. This issue tracks adding `.tar.bz2` support.

## What already exists

The archive module (`wasm/src/js/archive.js`) has most of the plumbing in place:

- **Magic byte detection** (line 125): `detectFormat()` already identifies bzip2 files via the `BZh` magic header (`0x42 0x5a 0x68`) and returns `'tar.bz2'`.
- **Switch case stub** (line 296): The extraction switch has a `case 'tar.bz2'` that currently throws `"Unsupported archive format: tar.bz2"`.
- **Tar parser**: `parseTar()` works on raw tar data regardless of how it was compressed — already used for both `.tar.gz` and plain `.tar`.

## What's missing

1. **A bzip2 decompression library** — `fflate` (current dependency) only handles deflate/gzip/zlib, not bzip2.
2. **~10 lines of glue code** in the `case 'tar.bz2'` branch: decompress, zip-bomb check, feed to `parseTar()`.
3. **UI updates**: file input `accept` attribute and dropzone "Supports" text.

## Library options

| Library | Size (min+gz) | API | Notes |
|---------|---------------|-----|-------|
| `bz2` | ~8 KB | `bz2.decompress(buffer)` | Lightweight, pure JS, synchronous |
| `compressjs` | ~25 KB | `Bzip2.decompressFile(stream)` | Full suite (bz2, lzma, etc.), heavier |
| `wasm-bz2` | ~15 KB | WASM-based | Fastest, but adds WASM-in-WASM complexity |

**Recommended**: `bz2` — smallest footprint, synchronous API matching the `gunzipSync` pattern already used for `.tar.gz`.

## Implementation steps

### 1. Add dependency

```bash
cd wasm && npm install bz2
```

### 2. Update `wasm/src/js/archive.js`

Add import:
```js
import bz2 from 'bz2';
```

Replace the `case 'tar.bz2'` stub (~line 296) with:
```js
case 'tar.bz2': {
    const decompressed = new Uint8Array(bz2.decompress(data));

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
```

### 3. Update `wasm/web/index.html`

- File input `accept` attribute: add `.tar.bz2`, `.tbz2`
- Dropzone formats text: `"Supports .tar.gz, .tgz, .tar.bz2, .zip, .tar"`

### 4. Rebuild and test

```bash
node wasm/scripts/build-web.mjs
# Test with a .tar.bz2 archive in browser
```

## Files modified

- `wasm/package.json` — add `bz2` dependency
- `wasm/src/js/archive.js` — import + case implementation (~12 lines)
- `wasm/web/index.html` — accept attribute + formats text (2 lines)

## Effort estimate

Small — the architecture is already in place. This is a library addition + filling in an existing stub.
