# WASM Build Dependencies

C libraries compiled with Emscripten for the WASM build of cbom-generator.
These are only needed for the WASM target; the native build uses system packages.

## Pinned Versions

| Library | Version | Purpose | Source |
|---------|---------|---------|--------|
| json-c | 0.17 | JSON serialization | https://github.com/json-c/json-c |
| libyaml | 0.2.5 | YAML plugin parsing | https://github.com/yaml/libyaml |
| jansson | 2.14 | JSON schema validation | https://github.com/akheron/jansson |

## Build Instructions

Automated by `wasm/scripts/build-wasm-deps.sh` (implemented in Phase 1).

```bash
cd wasm && npm run build:deps
```

Each library is downloaded, patched if needed, and compiled with `emcc` to produce
static `.a` archives that are linked into the final WASM module.

## Notes

- OpenSSL is NOT compiled for WASM; crypto parsing uses a lightweight JS bridge instead
- libcurl and ncurses are not needed in the browser environment
- pthreads are replaced by Emscripten's `-pthread` or single-threaded mode
