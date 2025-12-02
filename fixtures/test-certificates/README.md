# Test Certificate Fixtures

This directory contains test certificates and cryptographic fixtures for the CBOM Generator test suite.

## Certificate Types

- `test-rsa-2048.pem` - RSA 2048-bit certificate (modern, secure)
- `test-rsa-1024.pem` - RSA 1024-bit certificate (weak, deprecated)
- `test-ecdsa-p256.pem` - ECDSA P-256 certificate (modern, secure)
- `test-expired.pem` - Expired certificate for testing expiration detection
- `test-self-signed.pem` - Self-signed certificate
- `test-weak-md5.pem` - Certificate with MD5 signature (weak)

## Key Files

- `test-rsa-private.pem` - RSA private key (for testing key detection)
- `test-ecdsa-private.pem` - ECDSA private key
- `test-encrypted-key.pem` - Password-protected private key

## Configuration Files

- `minimal-nginx.conf` - Minimal nginx configuration with SSL
- `minimal-apache.conf` - Minimal Apache configuration with SSL
- `minimal-ssh.conf` - Minimal SSH daemon configuration

## Usage

These fixtures are used by the test suite to verify:
1. Certificate parsing and metadata extraction
2. Key material detection and classification
3. Configuration file parsing
4. Weak cryptography detection
5. Deterministic output generation

All certificates are self-signed test certificates created specifically for testing purposes.