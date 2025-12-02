# PQC Test Fixtures

This directory contains test certificates and keys for validating PQC assessment functionality.

## Test Certificates

### RSA Test Certificates

| File | Key Size | Expected Break Year | Expected PQC Status | Expected Urgency |
|------|----------|---------------------|---------------------|------------------|
| `test-rsa-1024.crt` | 1024 bits | 2030 | UNSAFE | CRITICAL |
| `test-rsa-2048.crt` | 2048 bits | 2035 | TRANSITIONAL | HIGH |
| `test-rsa-3072.crt` | 3072 bits | 2040 | TRANSITIONAL | HIGH |
| `test-rsa-4096.crt` | 4096 bits | 2045 | TRANSITIONAL | HIGH |

### ECDSA Test Certificates

| File | Curve / Key Size | Expected Break Year | Expected PQC Status | Expected Urgency |
|------|------------------|---------------------|---------------------|------------------|
| `test-ecdsa-p256.crt` | P-256 (256 bits) | 2035 | TRANSITIONAL | HIGH |
| `test-ecdsa-p384.crt` | P-384 (384 bits) | 2040 | TRANSITIONAL | HIGH |

## Usage

### Basic Scanning

```bash
# Scan RSA-2048 certificate
../build/cbom-generator test-rsa-2048.crt -o test-2048.json

# Verify classification
cat test-2048.json | jq '.components[] | select(.properties[]?.name == "cbom:pqc:status")'

# Check break year estimate
cat test-2048.json | jq '.components[] | select(.properties[]?.name == "cbom:pqc:break_estimate")'
```

### Validation Tests

```bash
# Test RSA-1024 (should be UNSAFE, break year 2030)
../build/cbom-generator test-rsa-1024.crt -o test-1024.json
jq -r '.components[] | select(.properties[]?.name == "cbom:pqc:status").properties[] | select(.name == "cbom:pqc:status").value' test-1024.json
# Expected output: UNSAFE

# Test RSA-2048 (should be TRANSITIONAL, break year 2035)
../build/cbom-generator test-rsa-2048.crt -o test-2048.json
jq -r '.components[] | select(.properties[]?.name == "cbom:pqc:status").properties[] | select(.name == "cbom:pqc:status").value' test-2048.json
# Expected output: TRANSITIONAL

jq -r '.components[] | select(.properties[]?.name == "cbom:pqc:break_estimate").properties[] | select(.name == "cbom:pqc:break_estimate").value' test-2048.json
# Expected output: 2035
```

## Standards Reference

Break year estimates based on:
- **NIST IR 8413**: "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process" (2022-03)
- **NSA CNSA 2.0**: Commercial National Security Algorithm Suite 2.0 (2022-09)

### Break Year Rationale

- **2030**: RSA-1024, MD5, SHA-1, RC4, DES (already weakened classically)
- **2035**: RSA-2048, ECDSA-P256, ECDH-P256 (NIST baseline, NSA CNSA 2.0 deadline)
- **2040**: RSA-3072, ECDSA-P384 (conservative estimate)
- **2045**: RSA-4096, ECDSA-P521 (optimistic, assumes slower quantum progress)

## File Generation Commands

```bash
# RSA keys
openssl genrsa -out test-rsa-1024.key 1024
openssl genrsa -out test-rsa-2048.key 2048
openssl genrsa -out test-rsa-3072.key 3072
openssl genrsa -out test-rsa-4096.key 4096

# RSA certificates
openssl req -new -x509 -key test-rsa-1024.key -out test-rsa-1024.crt -days 365 -subj "/CN=RSA-1024-Test/O=PQC-Test/C=US"
openssl req -new -x509 -key test-rsa-2048.key -out test-rsa-2048.crt -days 365 -subj "/CN=RSA-2048-Test/O=PQC-Test/C=US"
openssl req -new -x509 -key test-rsa-3072.key -out test-rsa-3072.crt -days 365 -subj "/CN=RSA-3072-Test/O=PQC-Test/C=US"
openssl req -new -x509 -key test-rsa-4096.key -out test-rsa-4096.crt -days 365 -subj "/CN=RSA-4096-Test/O=PQC-Test/C=US"

# ECDSA keys
openssl ecparam -name prime256v1 -genkey -out test-ecdsa-p256.key
openssl ecparam -name secp384r1 -genkey -out test-ecdsa-p384.key

# ECDSA certificates
openssl req -new -x509 -key test-ecdsa-p256.key -out test-ecdsa-p256.crt -days 365 -subj "/CN=ECDSA-P256-Test/O=PQC-Test/C=US"
openssl req -new -x509 -key test-ecdsa-p384.key -out test-ecdsa-p384.crt -days 365 -subj "/CN=ECDSA-P384-Test/O=PQC-Test/C=US"
```

## Integration Testing

These fixtures are used in:
- Unit tests (`tests/test_pqc_classifier.c`)
- Integration tests for break year estimation
- Regression tests for RSA-2048 vs RSA-1024 classification
- Migration report generation tests
