#!/bin/bash
# tests/security/fuzz_yaml_parser.sh
# Fuzzing test for YAML plugin parser

set -e

echo "=== Fuzzing YAML Plugin Parser ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create fuzzing corpus directory
mkdir -p tests/security/fuzz/yaml_corpus

echo "Creating malformed YAML test files..."

# Test 1: Unclosed brackets
cat > tests/security/fuzz/yaml_corpus/malformed_1.yaml << 'EOF'
plugin:
  name: "Test"
  [[[[[[[[[[[[[[[[[[[[[  # Unclosed brackets
  version: "1.0"
EOF

# Test 2: Command injection attempt
cat > tests/security/fuzz/yaml_corpus/malformed_2.yaml << 'EOF'
$(whoami)
plugin:
  name: "$(rm -rf /)"
  version: "1.0"
EOF

# Test 3: Extremely deep nesting (DoS attempt)
cat > tests/security/fuzz/yaml_corpus/malformed_3.yaml << 'EOF'
# Extremely deep nesting
plugin:
  a: {b: {c: {d: {e: {f: {g: {h: {i: {j: {k: {l: {m: {n: {o: {p: {q: {r: {s: {t: {u: {v: {w: {x: {y: {z: {aa: {bb: {cc: {dd: {ee: {ff: "too deep"}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
EOF

# Test 4: Giant file (exceeds 1MB limit)
cat > tests/security/fuzz/yaml_corpus/malformed_4.yaml << 'EOF'
plugin:
  name: "Large"
  version: "1.0"
  description: "EOF
python3 -c 'print("A" * 2000000)' >> tests/security/fuzz/yaml_corpus/malformed_4.yaml
echo '"' >> tests/security/fuzz/yaml_corpus/malformed_4.yaml

# Test 5: Invalid UTF-8
printf 'plugin:\n  name: "Test\\xFF\\xFE Invalid UTF-8"\n  version: "1.0"\n' > tests/security/fuzz/yaml_corpus/malformed_5.yaml

# Test 6: Null bytes
printf 'plugin:\n  name: "Test\\x00\\x00\\x00"\n  version: "1.0"\n' > tests/security/fuzz/yaml_corpus/malformed_6.yaml

# Test 7: Billion laughs attack (XML bomb adapted for YAML)
cat > tests/security/fuzz/yaml_corpus/malformed_7.yaml << 'EOF'
plugin: &a
  name: &b
    - *a
    - *a
    - *a
    - *a
    - *a
    - *a
    - *a
    - *a
    - *a
    - *a
EOF

# Test 8: Path traversal in plugin paths
cat > tests/security/fuzz/yaml_corpus/malformed_8.yaml << 'EOF'
plugin:
  plugin_schema_version: "1.0"
  name: "PathTraversal"
  version: "1.0"
detection:
  methods:
    - type: config_file
      paths:
        - "../../../etc/passwd"
        - "../../../../../../etc/shadow"
config_extraction:
  files:
    - path: "${DETECTED_CONFIG_DIR}/../../../etc/shadow"
      parser: "ini"
      crypto_directives: []
EOF

# Test 9: Missing required fields
cat > tests/security/fuzz/yaml_corpus/malformed_9.yaml << 'EOF'
plugin:
  name: "Incomplete"
  # Missing version, detection, config_extraction
EOF

# Test 10: Invalid schema version
cat > tests/security/fuzz/yaml_corpus/malformed_10.yaml << 'EOF'
plugin:
  plugin_schema_version: "999.0"
  name: "BadVersion"
  version: "1.0"
EOF

echo "Created 10 malformed YAML test files"
echo ""

# Run fuzzing
echo "Running fuzzing tests..."
echo ""

CRASHES=0
HANGS=0
GRACEFUL=0

for fuzz_file in tests/security/fuzz/yaml_corpus/*.yaml; do
    BASENAME=$(basename $fuzz_file)
    echo -n "Testing $BASENAME... "

    # Try to load plugin (should not crash)
    timeout 5 ./build/cbom-generator --plugin-dir tests/security/fuzz/yaml_corpus --list-plugins &>/dev/null
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 139 ]; then
        echo -e "${RED}CRASH (segfault)${NC}"
        CRASHES=$((CRASHES + 1))
    elif [ $EXIT_CODE -eq 134 ]; then
        echo -e "${RED}CRASH (abort)${NC}"
        CRASHES=$((CRASHES + 1))
    elif [ $EXIT_CODE -eq 124 ]; then
        echo -e "${YELLOW}TIMEOUT (possible hang)${NC}"
        HANGS=$((HANGS + 1))
    else
        echo -e "${GREEN}OK (graceful failure)${NC}"
        GRACEFUL=$((GRACEFUL + 1))
    fi
done

# Summary
echo ""
echo "=== Fuzzing Summary ==="
echo "Total tests: 10"
echo -e "Graceful failures: ${GREEN}$GRACEFUL${NC}"
echo -e "Timeouts/Hangs: ${YELLOW}$HANGS${NC}"
echo -e "Crashes: ${RED}$CRASHES${NC}"
echo ""

# Clean up
rm -rf tests/security/fuzz/yaml_corpus

if [ $CRASHES -eq 0 ] && [ $HANGS -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ No crashes or hangs detected (robust error handling)${NC}"
    exit 0
else
    echo -e "${RED}✗✗✗ $CRASHES crash(es) and $HANGS hang(s) detected${NC}"
    exit 1
fi
