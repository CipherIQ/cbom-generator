#!/bin/bash
# Setup test directory
mkdir -p /tmp/phase3-test-keys
cd /tmp/phase3-test-keys

echo "Creating test keys for Phase 3 validation..."

# 1. RSA private key (unencrypted)
openssl genrsa -out rsa_private_2048.pem 2048
echo "✓ Created RSA 2048 private key (unencrypted)"

# 2. RSA private key (encrypted with AES-256-CBC)
openssl genrsa -aes256 -passout pass:testpass -out rsa_private_2048_encrypted.pem 2048
echo "✓ Created RSA 2048 private key (AES-256-CBC encrypted)"

# 3. RSA public key
openssl rsa -in rsa_private_2048.pem -pubout -out rsa_public_2048.pem
echo "✓ Created RSA 2048 public key"

# 4. EC private key (unencrypted)
openssl ecparam -genkey -name secp256r1 -out ec_private_p256.pem
echo "✓ Created EC P-256 private key (unencrypted)"

# 5. EC private key (encrypted with AES-128-CBC)
openssl ecparam -genkey -name secp256r1 | \
  openssl ec -aes128 -passout pass:testpass -out ec_private_p256_encrypted.pem
echo "✓ Created EC P-256 private key (AES-128-CBC encrypted)"

# 6. EC public key
openssl ec -in ec_private_p256.pem -pubout -out ec_public_p256.pem
echo "✓ Created EC P-256 public key"

# 7. Ed25519 key pair
openssl genpkey -algorithm ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem
echo "✓ Created Ed25519 key pair"

# 8. RSA key in PKCS#8 format
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa_private_4096_pkcs8.pem
echo "✓ Created RSA 4096 key in PKCS#8 format"

# 9. Old key (deactivated - modify timestamp)
openssl genrsa -out rsa_old_deactivated.pem 2048
touch -t 202001010000 rsa_old_deactivated.pem  # Old timestamp
echo "✓ Created old RSA key (for deactivation test)"

# 10. Compromised key (with marker)
openssl genrsa -out rsa_compromised.pem 2048
touch rsa_compromised.pem.compromised  # Marker file
echo "✓ Created compromised RSA key (with marker)"

# 11. DER format keys
openssl rsa -in rsa_private_2048.pem -outform DER -out rsa_private_2048.der
openssl rsa -in rsa_private_2048.pem -pubout -outform DER -out rsa_public_2048.der
echo "✓ Created RSA keys in DER format"

# 12. SSH keys
ssh-keygen -t rsa -b 2048 -f ssh_rsa_key -N "" -C "test@example.com"
ssh-keygen -t ed25519 -f ssh_ed25519_key -N "" -C "test@example.com"
echo "✓ Created SSH keys"

echo ""
echo "Test key generation complete!"
echo "Keys created in: /tmp/phase3-test-keys"
ls -lh /tmp/phase3-test-keys