# CBOM Generator - Installation Guide

**Target Audience**: End users and system administrators

---

## Overview

The CBOM Generator can be installed using three methods:

1. **From Release Tarball** (Recommended) - Pre-built binary with plugins
2. **From Source** - Build from source code
3. **Portable Execution** - Run directly from extracted directory

---

## Prerequisites

### Runtime Dependencies

The CBOM Generator requires the following libraries:

| Library | Version | Purpose |
|---------|---------|---------|
| **OpenSSL** | 3.0+ | Certificate parsing, cryptographic operations |
| **json-c** | 0.15+ | JSON output generation |
| **libcurl** | Latest | Network operations (optional) |
| **libyaml** | 0.2.2+ | YAML plugin loading |
| **jansson** | 2.13+ | JSON parsing for plugins |
| **ncurses** | Latest | Terminal UI (TUI) display |
| **pthread** | glibc | Multi-threading support |

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libssl3 libjson-c5 libcurl4 libyaml-0-2 libjansson4 libncurses6
```

**RHEL/CentOS:**
```bash
sudo yum install openssl-libs json-c libcurl libyaml jansson ncurses-libs
```

**Verify OpenSSL version:**
```bash
openssl version
# Must be: OpenSSL 3.0 or newer (3.5+ recommended for PQC support)
```

---

## Method 1: Installation from Release Tarball

**Recommended for production deployments.**

### Step 1: Download Release Artifacts

Download the latest release from GitHub:
- `cbom-generator-VERSION-linux-amd64.tar.gz`
- `checksums.txt`

```bash
# Replace VERSION with actual version (e.g., 1.0.0)
wget https://github.com/CipherIQ/cbom-generation/releases/download/vVERSION/cbom-generator-VERSION-linux-amd64.tar.gz
wget https://github.com/CipherIQ/cbom-generation/releases/download/vVERSION/checksums.txt
```

### Step 2: Verify Checksums

**CRITICAL**: Always verify checksums before installation to ensure integrity.

```bash
sha256sum -c checksums.txt
# Expected output:
# cbom-generator-VERSION-linux-amd64.tar.gz: OK
```

If verification fails, **DO NOT INSTALL** - re-download the files.

### Step 3: Extract Tarball

```bash
tar -xzf cbom-generator-VERSION-linux-amd64.tar.gz
```

**Tarball contents:**
```
cbom-generator-VERSION-linux-amd64    # Main binary (~600KB)
plugins/                               # 88 YAML service plugins
├── ubuntu/                            # 60 enterprise service plugins
│   ├── postgresql.yaml
│   ├── nginx.yaml
│   └── ...
└── embedded/                          # 28 embedded/IoT plugins
    ├── dropbear.yaml
    ├── wpa_supplicant.yaml
    └── ...
registry/                              # 4 crypto registry files
├── crypto-registry-ubuntu.yaml
├── crypto-registry-yocto.yaml
├── crypto-registry-openwrt.yaml
└── crypto-registry-alpine.yaml
README.md                              # Quick start guide
USER_MANUAL.md                         # Comprehensive manual (full CLI reference)
```

Replace `VERSION` with the actual version number (e.g., `1.9.3`).

### Step 4: System-Wide Installation

**Install binary:**
```bash
sudo install -m 755 -o root -g root \
  cbom-generator-VERSION-linux-amd64 \
  /usr/local/bin/cbom-generator
```

**Install plugins and registry:**
```bash
sudo mkdir -p /usr/local/share/cbom-generator
sudo cp -r plugins/ /usr/local/share/cbom-generator/
sudo cp -r registry/ /usr/local/share/cbom-generator/
sudo chmod -R 755 /usr/local/share/cbom-generator/
```

**Install documentation (optional):**
```bash
sudo mkdir -p /usr/local/share/doc/cbom-generator
sudo cp README.md USER_MANUAL.md \
  /usr/local/share/doc/cbom-generator/
```

### Step 5: Verify Installation

```bash
# Check version
cbom-generator --version
# Expected: CBOM Generator 1.9.0

# List plugins
cbom-generator --plugin-dir /usr/local/share/cbom-generator/plugins --list-plugins
# Expected: Loaded 69 YAML plugins from '/usr/local/share/cbom-generator/plugins'

# Test basic scan (see USER_MANUAL.md for full CLI reference)
cbom-generator --plugin-dir /usr/local/share/cbom-generator/plugins \
  --output /tmp/test.json --no-personal-data --cyclonedx-spec=1.7 /etc/ssl/certs
# Should complete without errors
```

### Alternative: User-Level Installation

For non-root installations:

```bash
# Create user directories
mkdir -p ~/.local/bin
mkdir -p ~/.cbom/plugins
mkdir -p ~/.cbom/registry

# Install binary
cp cbom-generator-VERSION-linux-amd64 ~/.local/bin/cbom-generator
chmod +x ~/.local/bin/cbom-generator

# Install plugins and registry
cp -r plugins/* ~/.cbom/plugins/
cp -r registry/* ~/.cbom/registry/

# Add to PATH (add to ~/.bashrc or ~/.profile)
export PATH="$HOME/.local/bin:$PATH"

# Verify
cbom-generator --version
cbom-generator --plugin-dir ~/.cbom/plugins --list-plugins
```

---

## Method 2: Installation from Source

**Recommended for developers and contributors.**

### Prerequisites

**Build dependencies:**
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake \
  libssl-dev libjson-c-dev libcurl4-openssl-dev \
  libyaml-dev libjansson-dev

# RHEL/CentOS
sudo yum install gcc cmake make \
  openssl-devel json-c-devel libcurl-devel \
  libyaml-devel jansson-devel
```

### Build Steps

```bash
# Clone repository
git clone https://github.com/your-org/cryptoBOM.git
cd cryptoBOM

# Configure for release build
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build (uses all CPU cores)
cmake --build build

# Run tests
cd build && ctest
cd ..

# Install system-wide
sudo cmake --install build

# Plugins are included in repository
sudo mkdir -p /usr/local/share/cbom-generator
sudo cp -r plugins/ /usr/local/share/cbom-generator/
```

### Verify Build

```bash
./build/cbom-generator --version
./build/cbom-generator --plugin-dir plugins --list-plugins
```

---

## Method 3: Portable Execution

Run cbom-generator without installation:

```bash
# Extract tarball
tar -xzf cbom-generator-VERSION-linux-amd64.tar.gz

# Run directly (plugins and registry in same directory)
./cbom-generator-VERSION-linux-amd64 \
  --plugin-dir plugins/ubuntu \
  --crypto-registry registry/crypto-registry-ubuntu.yaml \
  --output cbom.json \
  --no-personal-data \
  --cyclonedx-spec=1.7

# For frequent use, create a wrapper script
cat > cbom.sh << 'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/cbom-generator-"*"-linux-amd64" \
  --plugin-dir "$DIR/plugins/ubuntu" \
  --crypto-registry "$DIR/registry/crypto-registry-ubuntu.yaml" \
  "$@"
EOF
chmod +x cbom.sh

# Run wrapper (see USER_MANUAL.md for full CLI reference)
./cbom.sh --version
./cbom.sh --list-plugins
```

---

## Configuration

### Plugin Directory

The CBOM Generator looks for plugins in the following order:

1. **CLI flag**: `--plugin-dir /custom/path` (highest priority)
2. **Default**: `plugins/` (relative to current working directory)

**Common plugin directory locations:**

| Location | Use Case |
|----------|----------|
| `/usr/local/share/cbom-generator/plugins` | System-wide installation |
| `~/.cbom/plugins` | User-level installation |
| `./plugins` | Portable execution |
| `/opt/cbom-generator/plugins` | Enterprise deployment |

**Example usage:**
```bash
# System location
cbom-generator --plugin-dir /usr/local/share/cbom-generator/plugins --list-plugins

# User location
cbom-generator --plugin-dir ~/.cbom/plugins --discover-services

# Custom location
cbom-generator --plugin-dir /opt/custom-plugins --output scan.json
```

### Creating Plugin Directory Symlink

For convenience with system-wide installation:

```bash
# Create symlink in current directory
ln -s /usr/local/share/cbom-generator/plugins plugins

# Now you can use default plugin directory
cbom-generator --list-plugins
```

### Security Hardening: Noexec Temp Directory

For production deployments, the CBOM Generator supports noexec-mounted temporary directories as a security hardening measure.

**Why noexec matters:**
- Prevents execution of any files written to temp directories
- Blocks potential code execution attacks via temp directory exploitation
- Follows CIS benchmark recommendations for system hardening
- Standard practice in cloud/container deployments

**Default Behavior:**
- The scanner silently falls back to `/tmp` if no noexec directory is available
- This is normal on desktop/development systems - no warnings are displayed
- Production systems should configure a noexec temp mount for defense-in-depth

**Recommended Setup (Production):**
```bash
# Create a dedicated noexec temp directory
sudo mkdir -p /var/tmp/cbom
sudo mount -t tmpfs -o noexec,nosuid,size=100M tmpfs /var/tmp/cbom

# Make permanent (add to /etc/fstab)
echo "tmpfs /var/tmp/cbom tmpfs noexec,nosuid,size=100M 0 0" | sudo tee -a /etc/fstab

# Verify mount options
mount | grep /var/tmp/cbom
# Expected: tmpfs on /var/tmp/cbom type tmpfs (rw,nosuid,noexec,...)
```

**Alternative: Mount /tmp with noexec (System-wide):**
```bash
# Check current /tmp mount
mount | grep /tmp

# If /tmp is a separate partition, add noexec to /etc/fstab:
# tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0
```

**Note:** Many container runtimes (Docker, Kubernetes) and cloud VMs already mount `/tmp` with noexec by default.

---

## Troubleshooting

### Missing Dependencies

**Error**: `error while loading shared libraries: libssl.so.3`

**Solution**:
```bash
# Install OpenSSL 3.0.x
sudo apt-get install libssl3

# Verify
ldd /usr/local/bin/cbom-generator | grep ssl
```

**Error**: `error while loading shared libraries: libyaml-0.so.2`

**Solution**:
```bash
sudo apt-get install libyaml-0-2
```

### Plugin Loading Issues

**Error**: `No YAML plugins found in 'plugins/'`

**Possible causes:**
1. Plugin directory doesn't exist
2. Wrong plugin directory path
3. Insufficient permissions

**Solution**:
```bash
# Check plugin directory exists
ls -la /usr/local/share/cbom-generator/plugins

# Verify permissions
sudo chmod -R 755 /usr/local/share/cbom-generator/plugins

# Use absolute path
cbom-generator --plugin-dir /usr/local/share/cbom-generator/plugins --list-plugins
```

**Error**: `Failed to parse YAML plugin: [file]`

**Solution**:
```bash
# Validate plugin syntax
python3 -c "import yaml; yaml.safe_load(open('plugins/postgresql.yaml'))"

# Check for file corruption
sha256sum plugins/*.yaml
```

### Permission Problems

**Error**: `Permission denied` when scanning `/etc/ssl`

**Solution**:
```bash
# Run with sudo for system directories
sudo cbom-generator --output /tmp/cbom.json

# Or scan user-accessible directories only
cbom-generator --output cbom.json ~/.ssh
```

### OpenSSL Version Mismatch

**Error**: `OpenSSL version 2.x detected (3.0+ required)`

**Solution**:
The CBOM Generator requires OpenSSL 3.0 or newer. OpenSSL 3.5+ is recommended for full PQC algorithm support.

Options:
1. Upgrade to OpenSSL 3.0+ (most modern distributions include this)
2. Build OpenSSL from source if on an older distribution
3. Use Docker container with newer OpenSSL

```bash
# Check installed OpenSSL
openssl version

# Check binary dependencies
ldd /usr/local/bin/cbom-generator | grep libssl
```

### Binary Not Found After Installation

**Error**: `cbom-generator: command not found`

**Solution**:
```bash
# Verify installation
ls -la /usr/local/bin/cbom-generator

# Check PATH
echo $PATH | grep /usr/local/bin

# If missing, add to PATH
export PATH="/usr/local/bin:$PATH"

# Make permanent (add to ~/.bashrc)
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Uninstallation

### System-Wide Removal

```bash
# Remove binary
sudo rm /usr/local/bin/cbom-generator

# Remove plugins
sudo rm -rf /usr/local/share/cbom-generator

# Remove documentation (if installed)
sudo rm -rf /usr/local/share/doc/cbom-generator
```

### User-Level Removal

```bash
# Remove binary
rm ~/.local/bin/cbom-generator

# Remove plugins
rm -rf ~/.cbom/plugins

# Remove from PATH (edit ~/.bashrc manually)
```

### Verify Removal

```bash
# Should not find binary
which cbom-generator

# Should show command not found
cbom-generator --version
```

---

## Platform Support

**Currently Supported:**
- Linux x86_64 (AMD64/Intel 64-bit)
- Kernel: 3.10+
- glibc: 2.17+

**Tested Distributions:**
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- RHEL/CentOS 8, 9
- Fedora 38+

**Not Yet Supported:**
- Linux ARM64 (planned for v1.4)
- macOS (planned for v2.0)
- Windows (no current plans)

---

## Cross-Architecture Scanning for Yocto/Embedded Systems

**For embedded Linux developers using Yocto, Buildroot, or OpenWrt.**

The CBOM Generator supports scanning cross-compiled rootfs images (e.g., ARM64 Yocto images from an x86_64 development host) using the `--cross-arch` flag. This enables cryptographic asset discovery in embedded systems without requiring the target architecture's package manager.

### Why Cross-Architecture Scanning?

| Challenge | Solution |
|-----------|----------|
| Target is ARM64, host is x86_64 | `--cross-arch` disables host package manager queries |
| No dpkg/rpm in embedded rootfs | ELF VERNEED + SONAME version detection |
| Embedded-specific crypto libs | `--crypto-registry crypto-registry-yocto.yaml` |
| IoT/embedded services | `--plugin-dir plugins/embedded` (28 plugins) |

### Quick Start: Yocto Rootfs Scan

```bash
# Define your Yocto build paths
YOCTO_BUILD=/path/to/poky/build-qemu
ROOTFS=$YOCTO_BUILD/tmp/work/qemuarm64-poky-linux/core-image-minimal/1.0/rootfs

# Scan the embedded rootfs
cbom-generator \
  --cross-arch \
  --discover-services \
  --plugin-dir /usr/local/share/cbom-generator/plugins/embedded \
  --crypto-registry /usr/local/share/cbom-generator/registry/crypto-registry-yocto.yaml \
  --format cyclonedx --cyclonedx-spec=1.7 \
  --no-personal-data \
  -o embedded-cbom.json \
  $ROOTFS/usr/bin \
  $ROOTFS/usr/sbin \
  $ROOTFS/usr/lib \
  $ROOTFS/etc
```

### With Yocto Manifest (Best Accuracy)

When available, the Yocto build manifest provides exact package versions:

```bash
YOCTO_BUILD=/path/to/poky/build-qemu
ROOTFS=$YOCTO_BUILD/tmp/work/qemuarm64-poky-linux/core-image-minimal/1.0/rootfs
MANIFEST=$YOCTO_BUILD/tmp/deploy/images/qemuarm64/core-image-minimal-qemuarm64.manifest

cbom-generator \
  --cross-arch \
  --yocto-manifest $MANIFEST \
  --discover-services \
  --plugin-dir /usr/local/share/cbom-generator/plugins/embedded \
  --crypto-registry /usr/local/share/cbom-generator/registry/crypto-registry-yocto.yaml \
  --format cyclonedx --cyclonedx-spec=1.7 \
  --no-personal-data \
  -o yocto-cbom.json \
  $ROOTFS/usr/bin $ROOTFS/usr/sbin $ROOTFS/usr/lib $ROOTFS/etc
```

### Version Detection Tiers

The scanner uses a tiered approach for version resolution:

| Tier | Source | Confidence | Use Case |
|------|--------|------------|----------|
| 1 | Yocto Manifest | 99% | Best: `--yocto-manifest FILE` |
| 2 | ELF VERNEED | 80% | Cross-arch: minimum API version |
| 3 | SONAME Parsing | 60% | Fallback: major version only |

### Embedded Plugins (28 Services)

The `plugins/embedded/` directory includes plugins for IoT and embedded services:

- **Security/VPN**: strongSwan, WireGuard, tinc, wpa_supplicant
- **SSH**: Dropbear (lightweight SSH)
- **Web**: lighttpd, uhttpd (OpenWrt)
- **IoT/MQTT**: Mosquitto, Node-RED
- **Containers**: K3s, balena-engine
- **System**: systemd-cryptsetup, chrony, NetworkManager
- **Wireless**: iwd, BlueZ, hostapd

### Crypto Registries

Four distribution-specific registries are provided:

| Registry | Libraries | Use Case |
|----------|-----------|----------|
| `crypto-registry-yocto.yaml` | 26 | Yocto/Buildroot (mbedTLS, wolfSSL, libtomcrypt) |
| `crypto-registry-openwrt.yaml` | 6 | OpenWrt routers (mbedTLS, ustream-ssl) |
| `crypto-registry-alpine.yaml` | 8 | Alpine Linux containers (LibreSSL) |
| `crypto-registry-ubuntu.yaml` | 16 | Desktop/server Ubuntu |

### Important Notes

1. **Never use `--cross-arch` with host paths** like `/usr/bin` — that's contradictory
2. **Scan multiple directories** for comprehensive coverage:
   - `$ROOTFS/usr/bin` — user binaries
   - `$ROOTFS/usr/sbin` — system binaries
   - `$ROOTFS/usr/lib` — libraries (for version detection)
   - `$ROOTFS/etc` — configuration files
3. **Use embedded plugins** for Yocto/IoT services
4. **Use distribution-specific registry** matching your target

### Further Reading

- `USER_MANUAL.md` Section 5.4 — Full `--cross-arch` CLI reference

---

## Next Steps

After installation:

1. **Read the Quick Start**: See `README.md` for basic usage examples
2. **Review User Manual**: See `USER_MANUAL.md` for comprehensive CLI reference and feature guide
3. **Run Your First Scan**:
   ```bash
   cbom-generator --plugin-dir /usr/local/share/cbom-generator/plugins \
     --output my-cbom.json --no-personal-data --cyclonedx-spec=1.7
   ```
4. **Explore Service Discovery**:
   ```bash
   cbom-generator --discover-services \
     --plugin-dir /usr/local/share/cbom-generator/plugins \
     --cyclonedx-spec=1.7 --output services.json
   ```
5. **Check PQC Readiness**:
   ```bash
   cbom-generator --output cbom.json --pqc-report migration.txt
   cat migration.txt  # Human-readable PQC migration report
   ```
6. **Cross-Architecture Scanning** (Yocto/embedded):
   ```bash
   # See dedicated section above for full examples
   ```

---

## Additional Resources

- **User Manual**: https://github.com/CipherIQ/cbom-generation/USER_MANUAL.md (full CLI reference)

- **Issue Tracker**: https://github.com/yCipherIQ/cbom-generation/issues


---

## Support

For installation issues:
1. Check this troubleshooting section
2. Review GitHub issues for similar problems
3. Create a new issue with:
   - OS and version (`uname -a`)
   - OpenSSL version (`openssl version`)
   - Error messages
   - Steps to reproduce

---
