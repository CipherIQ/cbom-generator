# Plugin Keys Directory

This directory contains test keys for plugin signature verification during development.

## Key Rotation Policy

- Test keys are rotated every 365 days
- Production keys are stored separately and managed by the security team
- Test keys should NEVER be used in production environments

## Key Files

- `test-plugin-key.pem` - Test private key for signing plugins during development
- `test-plugin-key.pub` - Test public key for verifying plugin signatures
- `test-plugin-cert.pem` - Test certificate for plugin signing

## Usage

These keys are used by the plugin manager when `allow_test_keys` is enabled in the trust configuration. This should only be enabled during development and testing.

## Security Notice

⚠️ **WARNING**: These are test keys only. Do not use in production!

Production plugin signing should use:
1. Hardware Security Modules (HSM) for key storage
2. Proper certificate authority chain
3. Regular key rotation (recommended: 90 days)
4. Separate signing infrastructure

## Key Generation

Test keys were generated using:

```bash
# Generate private key
openssl genrsa -out test-plugin-key.pem 2048

# Generate public key
openssl rsa -in test-plugin-key.pem -pubout -out test-plugin-key.pub

# Generate self-signed certificate
openssl req -new -x509 -key test-plugin-key.pem -out test-plugin-cert.pem -days 365
```