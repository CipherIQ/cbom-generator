# WASM Build Dependencies

C libraries compiled with Emscripten for the WASM build of cbom-generator.
These are only needed for the WASM target; the native build uses system packages.

## Pinned Versions

| Library | Version | Purpose | Source |
|---------|---------|---------|--------|
| json-c | 0.17-20230812 | JSON serialization | https://github.com/json-c/json-c |
| libyaml | 0.2.5 | YAML plugin parsing | https://github.com/yaml/libyaml |
| jansson | 2.14 | JSON schema validation | https://github.com/akheron/jansson |

## Build Instructions

```bash
# 1. Activate Emscripten
source ../emsdk/emsdk_env.sh

# 2. Run the build script (from repo root)
bash wasm/scripts/build-wasm-deps.sh
```

The script downloads each library tarball (cached in `deps/.cache/`), extracts
to `deps/<lib>-<version>/`, and compiles with `emcmake`/`emmake` to produce
static `.a` archives in each library's `build-wasm/` directory.

## Output Archives

After a successful build:
- `deps/json-c-json-c-0.17-20230812/build-wasm/libjson-c.a`
- `deps/libyaml-0.2.5/build-wasm/libyaml.a`
- `deps/jansson-2.14/build-wasm/lib/libjansson.a`

## Notes

- OpenSSL is NOT compiled for WASM; crypto parsing uses a lightweight JS bridge instead
- libcurl and ncurses are not needed in the browser environment
- pthreads are replaced by Emscripten's `-pthread` or single-threaded mode
- The script is idempotent — safe to re-run; it skips cached downloads and existing builds
