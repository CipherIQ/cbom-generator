# CBOM Generator

Scan Linux systems to inventory certificates, keys, algorithms, and cryptographic libraries. Generates standardized CycloneDX 1.6/1.7 Cryptographic Bills of Materials (CBOM) with PQC safety classification for quantum migration planning. Supports HR 7535 and NSM-10 compliance workflows.

## Overview

The CBOM Generator inventories cryptographic assets including algorithms, keys, certificates, libraries, protocols, applications and services to assess Post-Quantum Cryptography (PQC) readiness and security posture.

**Scope**: Scans Linux distributions including Ubuntu, Debian, RHEL, CentOS, Fedora, Alpine, and embedded Linux systems built with Yocto, Buildroot, and OpenWrt. Designed for security-critical environments including:

- **IoT/OT Systems** - Industrial controllers, sensors, gateways
- **Medical Devices** - FDA-regulated healthcare equipment
- **Robotics** - Autonomous systems, manufacturing robots
- **Automotive** - Connected vehicles, V2X infrastructure
- **Aerospace/Defense** - Avionics, satellite systems
- **Smart Infrastructure** - Building automation, smart grid, utilities
- **Edge Computing** - 5G nodes, edge servers, CDN appliances

The CBOM Generator generates actionable CBOMs - not just listing crypto assets, but showing exactly what needs PQC migration, in what order, with full dependency context. No SBOM required.

### Full CipherIQ Documentation
#### Read the full CipherIQ **[documentation](https://www.cipheriq.io)** website.

## License

This project is dual-licensed:

### Open Source License (GPL-3.0-or-later)

cbom-generator is free software: you can redistribute it and/or modify it under 
the terms of the GNU General Public License as published by the Free Software 
Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for the full license text.

### Commercial License

For organizations that cannot comply with the GPL-3.0 license terms (for example, 
if you want to integrate cbom-generator into proprietary software without releasing 
your source code), we offer commercial licenses.

**Commercial licenses include:**
- Freedom from GPL copyleft requirements
- Priority support
- Custom feature development (optional)

For pricing and terms, contact: **sales@cipheriq.io**


## Features

- **Comprehensive Scanning**: Discovers cryptographic assets across the entire Linux system
- **Terminal User Interface**: Real-time progress display with asset breakdown and scanner status
- **True Multi-threading**: Parallel scanner execution on all CPU cores (1.6x+ speedup measured)
- **CycloneDX Output**: Industry-standard SBOM format with cryptographic extensions
  - **CycloneDX 1.6** - Default, full backward compatibility
  - **CycloneDX 1.7** - Native certificate properties and extensions support
- **Enhanced Certificate Support**:
  - Full X.509 certificate discovery and parsing
  - Certificate chain validation and trust analysis
  - Enhanced metadata extraction (AIA, certificate policies, serial numbers, fingerprints)
  - Lifecycle state tracking
- **Key Material Scanner**:
  - Discovers private/public keys in 7 formats (PEM, DER, OpenSSH, PKCS#8, PKCS#1, SEC1, RAW)
  - 10 key types supported (RSA, ECDSA, Ed25519, Ed448, DSA, DH, AES, ChaCha20, HMAC, generic)
  - NIST SP 800-57 lifecycle tracking (active, pre-activation, suspended, deactivated, compromised, destroyed)
  - Weakness detection (RSA <2048, ECDSA <256, deprecated algorithms)
  - Only stores SHA-256 hashes, NEVER raw key material
- **Service Discovery**:
  - Automatic detection of services with TLS/SSH config extraction
  - 5 detection methods (process, port, config file, systemd, package)
  - Config parsers for Apache, Nginx, OpenSSH, Postfix, and more
  - Complete SERVICE→PROTOCOL→CIPHER_SUITE→ALGORITHM dependency chains
- **Application Scanner**:
  - Comprehensive detection of all crypto-using applications
  - Client tools (ssh, curl, wget, gpg) and server daemons (nginx, sshd)
  - Automatic category classification (15 categories: network_client, crypto_tool, vpn_client, etc.)
  - All library dependencies tracked by default - complete dependency graphs for security analysis
  - Smart deduplication with YAML plugin-detected services (zero duplicates)
  - Security: Only detects linkage, never executes binaries
- **Protocol Analysis**:
  - 7 protocol types (TLS, SSH, IPsec, DTLS, QUIC, WireGuard, OpenVPN)
  - TLS version and cipher suite extraction
  - Weak configuration detection (SSLv3, TLS 1.0/1.1, RC4, DES, NULL ciphers)
  - TLS 1.3 cipher suite support (5 AEAD suites)
  - OpenSSH PQC hybrid KEX detection (sntrup761x25519-sha512@openssh.com)
- **Relationship Graph**:
  - 4-level dependency architecture (SERVICE→PROTOCOL→CIPHER_SUITE→ALGORITHM)
  - Typed relationship edges with confidence scores
  - Complete PQC readiness traceability from service to algorithm
  - Several hundreds relationships tracked in typical system scans
- **PQC Assessment**:
  - 4-category classification (SAFE, TRANSITIONAL, DEPRECATED, UNSAFE)
  - 48 NIST-finalized OIDs with quantum vulnerability analysis
  - Hybrid algorithm detection (classical+PQC combinations)
  - Break year estimation (2030/2035/2040/2045 based on NIST IR 8413 + NSA CNSA 2.0)
  - Migration report generator with executive summary and timeline
- **Security Hardened**: Secure memory handling and privacy-by-default design
- **Reproducible Builds**: Deterministic output and build reproducibility
- **Plugin Architecture**: Extensible scanner and assessment plugins
- **88 YAML Service Plugins**:
  - **60 Enterprise Services**: PostgreSQL, MySQL, Nginx, Apache, Docker, Kubernetes, and more
  - **28 Embedded Linux**: strongSwan, K3s, wpa_supplicant, lighttpd, mosquitto, dropbear, and more
- **Crypto Registry**:
  - 4 distribution-specific registries (Ubuntu, Yocto, OpenWrt, Alpine)
  - Extensible YAML format for custom crypto library detection
  - No recompilation needed to add new libraries

## Installation

For complete installation instructions including release tarball installation, plugin setup, and troubleshooting, see **[INSTALL.md](INSTALL.md)**.

**Quick Install from Release:**
```bash
# Download and verify
wget https://github.com/CipherIQ/cbom-generator/releases/download/v1.9.3/cbom-generator-1.9.3-linux-amd64.tar.gz
wget https://github.com/CipherIQ/cbom-generator/releases/download/v1.9.3/checksums.txt
sha256sum -c checksums.txt

# Extract and install
tar -xzf cbom-generator-1.9.3-linux-amd64.tar.gz
sudo install -m 755 cbom-generator-1.9.3-linux-amd64 /usr/local/bin/cbom-generator
sudo mkdir -p /usr/local/share/cbom-generator
sudo cp -r plugins/ /usr/local/share/cbom-generator/
sudo cp -r registry/ /usr/local/share/cbom-generator/
```

## Building from Source

### Prerequisites

- GCC 9+ or Clang 10+ with C11 support
- CMake 3.16+
- OpenSSL 3.0+ (3.5+ recommended for PQC support)
- json-c 0.15+
- libyaml 0.2.2+
- jansson 2.13+
- libcurl
- ncurses
- pthread

For detailed dependency installation on Ubuntu/Debian, RHEL/CentOS, and other distributions, see **[INSTALL.md](INSTALL.md)**.

### Quick Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

## Usage

### Basic Scanning

```bash
# Scan directories /usr/bin and /etc of current system (outputs CycloneDX 1.6 to stdout)
./cbom-generator /usr/bin /etc

# Save CycloneDX output to file
./cbom-generator --output /tmp/cbom.json  /usr/bin /etc

# Generate CycloneDX 1.7 format with service discovery
./cbom-generator --cyclonedx-spec=1.7 --discover-services --plugin-dir plugins --output cbom.json  /usr/bin /etc

# Privacy-compliant scan (recommended for production)
./cbom-generator --no-personal-data --cyclonedx-spec=1.7 --output cbom.json
```

### Terminal User Interface

```bash
# Enable TUI with real-time progress
./cbom-generator --tui --output cbom.json  /usr/bin /etc

# TUI with error logging to file (recommended for debugging)
./cbom-generator --tui --error-log /tmp/cbom-errors.log --output cbom.json  /usr/bin /etc
```

**TUI Features**:
- Real-time progress bars and file counters
- Asset breakdown by type (certificates, keys, algorithms, libraries, protocols, services, cipher suites)
- Live directory path display
- Clean completion summary with PQC assessment
- Optional error logging to file

### Service Discovery with YAML Plugins

```bash
# Discover running services with full crypto analysis
./cbom-generator \
  --discover-services \
  --plugin-dir /usr/local/share/cbom-generator/plugins/ubuntu \
  --cyclonedx-spec=1.7 \
  --output services-cbom.json \
   /usr/bin /etc

# List available plugins
./cbom-generator --list-plugins --plugin-dir plugins/ubuntu
```

### Cross-Architecture Scanning (Yocto/Embedded)

The canonical way to scan cross-compiled rootfs images (e.g., ARM64 Yocto builds from x86_64 host):

```bash
# Define the rootfs path in your Yocto build directory
ROOTFS=/mnt/yocto-builds/yocto-cbom/poky/build-qemu/tmp/work/qemuarm64-poky-linux/core-image-minimal/1.0/rootfs

# Scan cross-compiled ARM64 rootfs from x86_64 host
./cbom-generator \
  --cross-arch \
  --discover-services \
  --plugin-dir plugins/embedded \
  --crypto-registry registry/crypto-registry-yocto.yaml \
  --cyclonedx-spec=1.7 \
  -o yocto-cbom.json \
  $ROOTFS/usr/bin $ROOTFS/usr/sbin $ROOTFS/usr/lib $ROOTFS/etc
```

**What it does:**
- Uses VERNEED/SONAME version detection from ELF binaries
- Works with embedded plugins for IoT services (dropbear, wpa_supplicant, etc.)

**Important:** Never use `--cross-arch` with host paths like `/usr/bin` - use paths within the target rootfs.

### PQC Migration Report

Generate a comprehensive Post-Quantum Cryptography migration assessment:

```bash
# Generate CBOM + PQC migration report
./cbom-generator /etc/ssl/certs \
  --discover-services \
  --plugin-dir /usr/local/share/cbom-generator/plugins/ubuntu \
  --cyclonedx-spec=1.7 \
  --output cbom.json \
  --pqc-report migration-report.txt \
   /usr/bin /etc

# View migration priorities and timeline
cat migration-report.txt
```

**Report includes:**
- Executive summary with vulnerability breakdown
- Assets grouped by break year (2030/2035/2040/2045)
- Migration timeline with phased approach
- NIST standards reference (FIPS 203/204/205)
- Prioritized recommendations and action items
- Risk assessment matrix
- Compliance guidance (NSA CNSA 2.0, FIPS 140-3)

**Sample Report Output:**
```
═══════════════════════════════════════════════════════════════
       POST-QUANTUM CRYPTOGRAPHY MIGRATION REPORT
═══════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
─────────────────
Total Cryptographic Assets: 241
PQC-Safe Assets: 8 (3.3%)
Quantum-Vulnerable Assets: 190 (78.8%)
Hybrid Deployments: 2

VULNERABILITY BREAKDOWN BY BREAK YEAR
──────────────────────────────────────
🚨 CRITICAL (Break by 2030):      5 assets  [IMMEDIATE ACTION]
⚠️  HIGH (Break by 2035):         44 assets  [PLAN MIGRATION NOW]
⚡ MEDIUM (Break by 2040):        0 assets  [MONITOR CLOSELY]
ℹ️  LOW (Break by 2045+):          0 assets  [LONG-TERM PLAN]
```

## Service Plugins

The CBOM Generator includes 88 YAML-based service plugins for automatic service detection and crypto configuration extraction:

### Enterprise Plugins (60 services)

Located in `plugins/ubuntu/`:
- **Databases**: PostgreSQL, MySQL, MariaDB, MongoDB, Redis, CouchDB, Cassandra, InfluxDB
- **Web Servers**: Nginx, Apache, Caddy, HAProxy, Traefik
- **Message Brokers**: RabbitMQ, Kafka, ActiveMQ, NATS
- **VPN/Security**: OpenVPN, WireGuard, strongSwan, stunnel
- **Containers**: Docker, Kubernetes, containerd
- **Monitoring**: Prometheus, Grafana, Elasticsearch

### Embedded Plugins (28 services)

Located in `plugins/embedded/`:
- **Core System**: systemd-cryptsetup, chrony, NetworkManager, avahi
- **Web/API**: lighttpd, uhttpd, node-red
- **IoT/MQTT**: mosquitto, dbus
- **SSH**: dropbear (lightweight SSH)
- **VPN**: strongSwan, WireGuard, tinc
- **Wireless**: wpa_supplicant, iwd, hostapd, bluez
- **Containers**: k3s, balena-engine

### Usage Examples

```bash
# Use enterprise plugins on Ubuntu/Debian servers
./cbom-generator \
  --discover-services \
  --plugin-dir plugins/ubuntu \
  --cyclonedx-spec=1.7 \
  --output enterprise-cbom.json \
   /usr/bin /etc

```

## Crypto Registry

The Crypto Registry enables detection of cryptographic libraries across different distributions without recompilation:

### Available Registries

| Registry | Libraries | Use Case |
|----------|-----------|----------|
| `crypto-registry-ubuntu.yaml` | 16 | Ubuntu, Debian, Raspberry Pi OS, Armbian |
| `crypto-registry-yocto.yaml` | 26 | Yocto, Buildroot embedded systems |
| `crypto-registry-openwrt.yaml` | 6 | OpenWrt routers |
| `crypto-registry-alpine.yaml` | 8 | Alpine Linux, Docker containers |

### Usage Examples

```bash
# Standard scan with Ubuntu registry
./cbom-generator \
 --cyclonedx-spec=1.7 \
  --crypto-registry registry/crypto-registry-ubuntu.yaml \
  --output cbom.json \
  /usr/bin /etc

# Yocto/embedded scan with appropriate registryANm-generator \
  --cross-arch \
  --crypto-registry registry/crypto-registry-yocto.yaml \
  --discover-services \
  --plugin-dir plugins/embedded \
  --cyclonedx-spec=1.7 \
  --output embedded-cbom.json \
  $ROOTFS/usr/bin $ROOTFS/usr/lib

# OpenWrt router scan
./cbom-generator \
 --cyclonedx-spec=1.7 \
 --discover-services \
 --plugin-dir plugins/embedded \
  --crypto-registry registry/crypto-registry-openwrt.yaml \
  --output openwrt-cbom.json \
  $ROOTFS/usr/bin $ROOTFS/usr/lib
```

### Custom Registry

> Refer to the CipherIQ full **[documentation](https://www.cipheriq.io)** to
create custom registries for proprietary or vendor-specific crypto libraries:

```yaml
version: 1
crypto_libraries:
  - id: my_custom_tls
    pkg_patterns:
      - my-tls-package
    soname_patterns:
      - libmytls.so
    algorithms:
      - RSA
      - AES-GCM
```

## Working with CycloneDX JSON Output

The cbom-generator outputs CycloneDX-formatted JSON to stdout and diagnostic messages to stderr. Use `jq` for processing:

### Basic Queries

```bash
# Check format and component count
cat cbom.json | jq '.bomFormat, .specVersion, (.components | length)'

# List all certificates
cat cbom.json | jq -r '.components[] | select(."bom-ref" | startswith("cert:")) | ."bom-ref"'

# Count certificates
cat cbom.json | jq '[.components[] | select(."bom-ref" | startswith("cert:"))] | length'

# List services and their dependencies
cat cbom.json | jq '.dependencies[] | select(.ref | startswith("service:"))'

# List algorithms
cat cbom.json | jq -r '.components[] | select(."bom-ref" | startswith("algo:")) | .name' | sort -u
```

### PQC Assessment Queries

```bash
# Get PQC summary metadata
cat cbom.json | jq '.properties[] | select(.name | startswith("cbom:pqc"))'

# Find vulnerable algorithms
cat cbom.json | jq '.components[] | select(.properties[]?.name == "cbom:pqc:status" and .properties[]?.value == "UNSAFE") | {name, ref: ."bom-ref"}'

# List algorithms with PQC status
cat cbom.json | jq '.components[] | select(.properties[]?.name == "cbom:pqc:status") | {name: .name, status: [.properties[] | select(.name == "cbom:pqc:status") | .value][0]}'

# Get completion statistics
cat cbom.json | jq '.properties[] | select(.name | startswith("cbom.completion"))'
```

### Dependency Graph Queries

```bash
# Service dependencies (SERVICE→PROTOCOL→LIBRARY)
cat cbom.json | jq '.dependencies[] | select(.ref | startswith("service:")) | {ref, dependsOn}'

# Cipher suite decomposition (CIPHER→ALGORITHM)
cat cbom.json | jq '.dependencies[] | select(.ref | startswith("cipher:")) | {ref, dependsOn}'

# Protocol relationships
cat cbom.json | jq '.components[] | select(."bom-ref" | startswith("protocol:")) | {name: .name, ref: ."bom-ref"}'
```

## Human-Readable bom-refs

The CBOM Generator uses semantic, human-readable identifiers for all components:

### Component Examples

**Certificates**:
```json
{
  "bom-ref": "cert:digicert-assured-id-root-ca",
  "name": "C = US, O = DigiCert Inc, CN = DigiCert Assured ID Root CA",
  "type": "cryptographic-asset"
}
```

**Algorithms**:
```json
{
  "bom-ref": "algo:aes-256-gcm-256",
  "name": "AES-256-GCM",
  "type": "cryptographic-asset"
}
```

**Services**:
```json
{
  "bom-ref": "service:nginx",
  "name": "Nginx",
  "type": "application"
}
```

**Protocols**:
```json
{
  "bom-ref": "protocol:tls-tlsv1-3",
  "name": "TLS",
  "type": "cryptographic-asset"
}
```

**Cipher Suites**:
```json
{
  "bom-ref": "cipher:tls-ecdhe-rsa-with-aes-256-gcm-sha384",
  "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "type": "cryptographic-asset"
}
```

**Libraries**:
```json
{
  "bom-ref": "library:libssl-so-3",
  "name": "libssl.so.3",
  "type": "library"
}
```

### Dependencies with Readable Refs

```json
{
  "dependencies": [
    {
      "ref": "service:nginx",
      "dependsOn": [
        "library:libcrypto-so-3",
        "library:libssl-so-3",
        "protocol:tls-tlsv1-2",
        "protocol:tls-tlsv1-3"
      ]
    },
    {
      "ref": "service:openssh",
      "dependsOn": [
        "library:libcrypto-so-3",
        "library:libgssapi-krb5-so-2",
        "library:openssh-internal",
        "protocol:ssh-server"
      ]
    },
    {
      "ref": "cipher:tls-ecdhe-rsa-with-aes-256-gcm-sha384",
      "dependsOn": [
        "algo:aes-256-gcm-256",
        "algo:ecdhe",
        "algo:rsa"
      ]
    }
  ]
}
```

### Metadata Schema Compliance

All custom metadata in `metadata.properties[]` array (CycloneDX compliant):

```json
{
  "metadata": {
    "properties": [
      {"name": "cbom:host:cpu_arch", "value": "x86_64"},
      {"name": "cbom:provenance:tool_version", "value": "1.9.3"},
      {"name": "cbom:pqc:readiness_score", "value": "49.6"},
      {"name": "cbom:pqc:safe_count", "value": "14"},
      {"name": "cbom:pqc:unsafe_count", "value": "8"},
      {"name": "cbom:pqc:break_2030_count", "value": "5"},
      {"name": "cbom:pqc:break_2035_count", "value": "51"}
    ]
  }
}
```

## Advanced Options

```bash
# Parallel scanning with custom thread count
./cbom-generator --threads 8 --output cbom.json /usr/bin /etc

# Error logging to file
./cbom-generator --error-log /tmp/errors.log --output cbom.json  /usr/bin /etc

# Full system scan with all options
sudo ./cbom-generator \
  --discover-services \
  --plugin-dir /usr/local/share/cbom-generator/plugins/ubuntu \
  --crypto-registry /usr/local/share/cbom-generator/registry/crypto-registry-ubuntu.yaml \
  --cyclonedx-spec=1.7 \
  --no-personal-data \
  --pqc-report /tmp/pqc-migration.txt \
  --output /tmp/full-cbom.json \
   /usr/bin /etc /usr/sbin
```

## Contributing

1. Follow C11 standard and project coding style
2. All new code must include unit tests
3. Run static analysis: `make static-analysis`
4. Ensure no orphaned code: `make check-orphan-code`
5. Validate reproducible builds


## Documentation


- **[Installation Guide](INSTALL.md)** - Complete installation instructions for end users
- **[User Manual](USER_MANUAL.md)** - Comprehensive usage guide and CLI reference

---

Copyright © 2025 Graziano Labs Corp. All rights reserved.