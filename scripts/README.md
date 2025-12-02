# CBOM Generator Scripts

This directory contains automation and validation scripts for development, testing, and release workflows.

## Script Overview

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `create_plugin.sh` | Generate YAML plugin templates | Adding new service plugins |
| `release.sh` | Automate release process | Creating new releases |
| `validate-cbom.sh` | Comprehensive CBOM validation | Testing generated output |
| `validate-schemas.sh` | CycloneDX schema validation | CI/CD, schema updates |
| `validate-normalization.sh` | Asset ID normalization tests | After normalization changes |
| `validate-property-mappings.sh` | Property mapping drift detection | Before releases |
| `check-orphan-code.sh` | Find unused source files | Code cleanup |

---

## Development Scripts

### create_plugin.sh

**Purpose**: Quickly generate YAML plugin templates for new service detectors.

```bash
# Usage
./scripts/create_plugin.sh <name> <category> <port> [process_name] [parser]

# Examples
./scripts/create_plugin.sh Tomcat application_server 8443 java apache
./scripts/create_plugin.sh Cassandra database 9042
./scripts/create_plugin.sh HAProxy load_balancer 443
```

**Arguments**:
- `name` - Service name (e.g., Tomcat, Cassandra)
- `category` - Category (database, web_server, mail_server, application_server, etc.)
- `port` - Primary TLS/SSL port number
- `process_name` - (optional) Process name, defaults to lowercase name
- `parser` - (optional) Config parser type, defaults to `ini`

**Output**: Creates `plugins/<name>.yaml` with detection methods and config extraction template.

**Next Steps After Creation**:
1. Edit the generated file to customize for actual service specifics
2. Test loading: `./build/cbom-generator --plugin-dir plugins --list-plugins`
3. Validate: `./tests/validate_plugin.sh plugins/<name>.yaml`

---

### check-orphan-code.sh

**Purpose**: Find source files not included in build or tests (dead code detection).

```bash
./scripts/check-orphan-code.sh
```

**What it checks**:
- `.c` files in `src/` not referenced in CMakeLists.txt
- `.h` files in `include/` and `src/` not included anywhere
- Test files in `tests/` are excluded from orphan detection

**Exit Codes**:
- `0` - No orphan files found
- `1` - Orphan files detected (lists them)

**Use Case**: Run before commits to ensure no dead code accumulates.

---

## Release Scripts

### release.sh

**Purpose**: Automate the complete release workflow.

```bash
./scripts/release.sh <version>

# Example
./scripts/release.sh 1.3.0
```

**What it does** (10 steps):
1. Verifies version in CMakeLists.txt
2. Creates clean release build
3. Verifies binary exists
4. Runs test suite
5. Validates all 50+ plugins
6. Tests plugin loading
7. Creates release artifacts (binary, tarball)
8. Generates SHA-256 checksums
9. Displays release summary
10. Provides git tag instructions

**Output**:
```
release/
├── cbom-generator-<version>-linux-amd64.tar.gz
└── checksums.txt
```

**Prerequisites**:
- Version must match in CMakeLists.txt
- All tests must pass
- RELEASE_NOTES_<version>.md must exist

---

## Validation Scripts

### validate-cbom.sh

**Purpose**: Comprehensive validation of generated CBOM files.

```bash
./scripts/validate-cbom.sh [cbom-file]

# Examples
./scripts/validate-cbom.sh cbom.json
./scripts/validate-cbom.sh  # defaults to cbom-etc-1.7.cdx.json
```

**Validation Tests**:
1. **JSON Syntax** - Valid JSON parsing
2. **CycloneDX Structure** - Required fields (bomFormat, specVersion, metadata, components)
3. **Component Inventory** - Counts by type, crypto assets, dependencies
4. **Certificate Analysis** - Certificate properties, CycloneDX 1.7 native fields
5. **Data Quality** - Property value types, bom-ref uniqueness
6. **Official Validator** - cyclonedx-cli (if installed)

**Dependencies**:
- `python3` (required)
- `cyclonedx-cli` (optional, for official validation)

**Install Official Validator**:
```bash
npm install -g @cyclonedx/cyclonedx-cli
```

---

### validate-schemas.sh

**Purpose**: Validate pinned CycloneDX schemas haven't been modified.

```bash
./scripts/validate-schemas.sh
```

**What it does**:
1. Checks if CycloneDX 1.6 schema exists in `tests/schemas/`
2. Validates SHA-256 checksum against pinned value
3. Downloads schema if missing
4. Verifies schema is valid JSON

**Files**:
- `tests/schemas/cyclonedx-1.6.schema.json` - Pinned schema
- `tests/schemas/cyclonedx-1.6.schema.json.sha256` - Checksum file

**Use Case**: CI/CD to ensure schema integrity, detect unauthorized modifications.

---

### validate-normalization.sh

**Purpose**: Validate asset ID normalization rules haven't drifted.

```bash
./scripts/validate-normalization.sh
```

**What it validates**:
1. Builds project if needed
2. Runs normalization tests from `cbom-tests`
3. Verifies `docs/NORMALIZATION.md` exists
4. Checks frozen test vector IDs in source code

**Frozen Test Vectors**:
The script verifies specific SHA-256 test vector IDs exist in `src/normalization.c` to detect backwards compatibility breaks.

**When to Run**: After any changes to normalization rules, before releases.

---

### validate-property-mappings.sh

**Purpose**: Detect property mapping drift from FROZEN v1.0 specification.

```bash
./scripts/validate-property-mappings.sh
```

**What it validates**:
1. **Property Guide** - `docs/CBOM_PROPERTY_GUIDE.md` exists, version 1.0, marked FROZEN
2. **Source Code** - `src/cyclonedx_converter.c` contains FROZEN marker
3. **Component Type Mappings** - 6 mappings verified:
   - `ASSET_TYPE_ALGORITHM` → `CYCLONEDX_COMPONENT_LIBRARY`
   - `ASSET_TYPE_KEY` → `CYCLONEDX_COMPONENT_DATA`
   - `ASSET_TYPE_CERTIFICATE` → `CYCLONEDX_COMPONENT_DATA`
   - `ASSET_TYPE_LIBRARY` → `CYCLONEDX_COMPONENT_LIBRARY`
   - `ASSET_TYPE_PROTOCOL` → `CYCLONEDX_COMPONENT_LIBRARY`
   - `ASSET_TYPE_SERVICE` → `CYCLONEDX_COMPONENT_OPERATING_SYSTEM`
4. **Property Namespaces** - 7 namespaces verified (cbom:algo:, cbom:cert:, etc.)
5. **Required Property Counts** - Stable counts for each asset type
6. **Forbidden Types** - No application, framework, container, device, file, firmware
7. **CycloneDX Version** - Pinned to 1.6

**Exit Codes**:
- `0` - All validations passed
- `1` - Drift detected (details printed)

**When to Run**: Before every release, after CycloneDX converter changes.

---

## CI/CD Integration

### Recommended Pipeline

```yaml
# Example GitHub Actions workflow
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check orphan code
        run: ./scripts/check-orphan-code.sh

      - name: Validate schemas
        run: ./scripts/validate-schemas.sh

      - name: Build
        run: cmake -B build && cmake --build build

      - name: Validate normalization
        run: ./scripts/validate-normalization.sh

      - name: Validate property mappings
        run: ./scripts/validate-property-mappings.sh

      - name: Run tests
        run: cd build && ctest

      - name: Generate CBOM
        run: ./build/cbom-generator -o test-cbom.json

      - name: Validate CBOM
        run: ./scripts/validate-cbom.sh test-cbom.json
```

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:
```bash
#!/bin/bash
./scripts/check-orphan-code.sh || exit 1
./scripts/validate-property-mappings.sh || exit 1
```

---

## Script Dependencies

| Script | Required | Optional |
|--------|----------|----------|
| `create_plugin.sh` | bash | - |
| `release.sh` | bash, cmake, make | - |
| `validate-cbom.sh` | bash, python3 | cyclonedx-cli |
| `validate-schemas.sh` | bash, sha256sum | python3 or jq, curl or wget |
| `validate-normalization.sh` | bash, cmake | - |
| `validate-property-mappings.sh` | bash, grep, awk | - |
| `check-orphan-code.sh` | bash, find, grep | - |


---

Copyright © 2025 Graziano Labs Corp. All rights reserved.