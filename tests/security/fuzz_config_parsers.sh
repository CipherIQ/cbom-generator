#!/bin/bash
# tests/security/fuzz_config_parsers.sh
# Fuzzing test for config parsers (INI, Apache, Nginx, etc.)

set -e

echo "=== Fuzzing Config Parsers ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create fuzzing corpus directory
mkdir -p tests/security/fuzz/config_corpus

echo "Creating malformed config test files..."

# INI parser fuzzing
cat > tests/security/fuzz/config_corpus/evil.ini << 'EOF'
[[[[[[[[[[[[[[[[[
key = $(whoami)
$(rm -rf /)
[section]
# Path traversal
ssl_cert = ../../../../../../etc/shadow
# Command injection
ssl_key = $(cat /etc/passwd)
# Overflow attempt
long_value = EOF
python3 -c 'print("A" * 100000)' >> tests/security/fuzz/config_corpus/evil.ini

# Apache parser fuzzing
cat > tests/security/fuzz/config_corpus/evil_apache.conf << 'EOF'
<VirtualHost *:80>
  <VirtualHost *:80>
    <VirtualHost *:80>
      <VirtualHost *:80>
        <VirtualHost *:80>
          # Deeply nested (stack overflow attempt)
        </VirtualHost>
      </VirtualHost>
    </VirtualHost>
  </VirtualHost>
</VirtualHost>

SSLCertificateFile $(whoami)
SSLCipherSuite EOF
python3 -c 'print("A" * 50000)' >> tests/security/fuzz/config_corpus/evil_apache.conf

# Nginx parser fuzzing
cat > tests/security/fuzz/config_corpus/evil_nginx.conf << 'EOF'
server {
  ssl_certificate $(whoami);
  # Command injection attempt
  ssl_key `cat /etc/passwd`;
  # Nested blocks
  location / {
    location /a {
      location /b {
        location /c {
          # Deep nesting
        }
      }
    }
  }
}
# Infinite loop attempt
include evil_nginx.conf;
EOF

# YAML parser fuzzing (for services)
cat > tests/security/fuzz/config_corpus/evil.yaml << 'EOF'
# Anchor bomb
a: &anchor
  - *anchor
  - *anchor
  - *anchor
  - *anchor

# Null bytes
key: "value\x00\x00"

# Command injection
ssl:
  cert: "$(rm -rf /)"
  key: "`whoami`"
EOF

# JSON parser fuzzing
cat > tests/security/fuzz/config_corpus/evil.json << 'EOF'
{
  "tls": true,
  "tlscert": "../../../../../../etc/shadow",
  "command": "$(whoami)",
  "nested": {
    "deep": {
      "very": {
        "extremely": {
          "ridiculously": {
            "absurdly": {
              "infinitely": "deep"
            }
          }
        }
      }
    }
  }
}
EOF

# Postfix-style config fuzzing
cat > tests/security/fuzz/config_corpus/evil_postfix.cf << 'EOF'
smtp_tls_cert_file = $(cat /etc/shadow)
smtp_tls_key_file = `whoami`
# Injection via continuation
smtp_tls_CAfile = /etc/ssl/ca.pem
    && rm -rf /
# Buffer overflow
smtp_tls_ciphers = EOF
python3 -c 'print("A" * 200000)' >> tests/security/fuzz/config_corpus/evil_postfix.cf

echo "Created 6 malformed config test files"
echo ""

# Note: Config parser fuzzing requires actual service instances
# This is a placeholder for the fuzzing framework

echo -e "${YELLOW}Note: Config parser fuzzing requires running services${NC}"
echo "Config corpus created in: tests/security/fuzz/config_corpus/"
echo ""
echo "To test manually:"
echo "  1. Start a test service (nginx, apache, etc.)"
echo "  2. Point config to malformed files"
echo "  3. Run: ./build/cbom-generator --discover-services"
echo ""

# For now, just validate files were created
FILES_CREATED=$(ls -1 tests/security/fuzz/config_corpus/ | wc -l)

if [ $FILES_CREATED -eq 6 ]; then
    echo -e "${GREEN}✓ Config fuzzing corpus created ($FILES_CREATED files)${NC}"
    echo "Corpus location: tests/security/fuzz/config_corpus/"
    exit 0
else
    echo -e "${RED}✗ Failed to create all fuzzing files${NC}"
    exit 1
fi
