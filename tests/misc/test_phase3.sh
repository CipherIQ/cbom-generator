#!/bin/bash
#
# Phase 3 Complete Test Suite
# Generates test keys, runs CBOM generator, and validates output
#
# Usage: bash test_phase3.sh [cbom-generator-path]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CBOM_GENERATOR="${1:-./cbom-generator}"
TEST_DIR="/tmp/phase3-test-$$"
RESULTS_DIR="$TEST_DIR/results"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

print_header() {
    echo ""
    echo "========================================================================"
    echo "$1"
    echo "========================================================================"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing=0
    
    if ! command -v openssl &> /dev/null; then
        log_error "openssl not found"
        missing=1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq not found"
        missing=1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found"
        missing=1
    fi
    
    if [ ! -f "$CBOM_GENERATOR" ]; then
        log_error "CBOM generator not found at: $CBOM_GENERATOR"
        log_info "Usage: $0 [path-to-cbom-generator]"
        missing=1
    elif [ ! -x "$CBOM_GENERATOR" ]; then
        log_error "CBOM generator is not executable: $CBOM_GENERATOR"
        log_info "Try: chmod +x $CBOM_GENERATOR"
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Setup test environment
setup_test_env() {
    print_header "PHASE 3 TEST SETUP"
    
    log_info "Creating test directory: $TEST_DIR"
    mkdir -p "$TEST_DIR"
    mkdir -p "$RESULTS_DIR"
    
    cd "$TEST_DIR"
    log_success "Test environment ready"
}

# Generate test keys
generate_test_keys() {
    print_header "GENERATING TEST KEYS"
    
    mkdir -p keys
    cd keys
    
    log_info "Creating RSA keys..."
    openssl genrsa -out rsa_2048.pem 2048 2>/dev/null
    openssl rsa -in rsa_2048.pem -pubout -out rsa_2048_pub.pem 2>/dev/null
    openssl genrsa -out rsa_4096.pem 4096 2>/dev/null
    log_success "RSA keys created"
    
    log_info "Creating EC keys..."
    openssl ecparam -genkey -name secp256r1 -out ec_p256.pem 2>/dev/null
    openssl ec -in ec_p256.pem -pubout -out ec_p256_pub.pem 2>/dev/null
    openssl ecparam -genkey -name secp384r1 -out ec_p384.pem 2>/dev/null
    openssl ec -in ec_p384.pem -pubout -out ec_p384_pub.pem 2>/dev/null
    log_success "EC keys created"
    
    log_info "Creating Ed25519 keys..."
    openssl genpkey -algorithm ed25519 -out ed25519.pem 2>/dev/null
    openssl pkey -in ed25519.pem -pubout -out ed25519_pub.pem 2>/dev/null
    log_success "Ed25519 keys created"
    
    log_info "Creating encrypted keys..."
    openssl genrsa -aes256 -passout pass:test123 -out rsa_encrypted_aes256.pem 2048 2>/dev/null
    openssl genrsa -aes128 -passout pass:test123 -out rsa_encrypted_aes128.pem 2048 2>/dev/null
    openssl genrsa -des3 -passout pass:test123 -out rsa_encrypted_3des.pem 2048 2>/dev/null
    log_success "Encrypted keys created"
    
    log_info "Creating keys with different states..."
    # Active key (current)
    openssl genrsa -out key_active.pem 2048 2>/dev/null
    
    # Deactivated key (old)
    openssl genrsa -out key_deactivated.pem 2048 2>/dev/null
    touch -t 202001010000 key_deactivated.pem
    
    # Compromised key (with marker)
    openssl genrsa -out key_compromised.pem 2048 2>/dev/null
    touch key_compromised.pem.compromised
    
    log_success "State test keys created"
    
    log_info "Creating DER format keys..."
    openssl rsa -in rsa_2048.pem -outform DER -out rsa_2048.der 2>/dev/null
    openssl rsa -in rsa_2048.pem -pubout -outform DER -out rsa_2048_pub.der 2>/dev/null
    log_success "DER format keys created"
    
    cd ..
    
    local key_count=$(find keys -type f -name "*.pem" -o -name "*.der" | wc -l)
    log_success "Generated $key_count test keys"
}

# Run CBOM generator
run_generator() {
    print_header "RUNNING CBOM GENERATOR"
    
    log_info "Generating CBOM from test keys..."
    log_info "Command: $CBOM_GENERATOR --output $RESULTS_DIR/phase3.json keys/"
    
    # Run generator and capture exit code
    # Syntax: cbom-generator --output <output.json> <input-directory>
    "$CBOM_GENERATOR" --output "$RESULTS_DIR/phase3.json" keys/ > "$RESULTS_DIR/generator.log" 2>&1
    local exit_code=$?
    
    if [ $exit_code -eq 0 ] && [ -f "$RESULTS_DIR/phase3.json" ]; then
        log_success "CBOM generation successful"
    else
        log_error "CBOM generation failed (exit code: $exit_code)"
        log_info "Generator log:"
        cat "$RESULTS_DIR/generator.log"
        exit 1
    fi
}

# Validate structure
validate_structure() {
    print_header "VALIDATING CBOM STRUCTURE"
    
    local cbom="$RESULTS_DIR/phase3.json"
    
    log_info "Checking JSON validity..."
    if jq empty "$cbom" 2>/dev/null; then
        log_success "Valid JSON"
    else
        log_error "Invalid JSON"
        return 1
    fi
    
    log_info "Checking for key components..."
    local key_count=$(jq '[.components[] | select(.cryptoProperties.assetType=="related-crypto-material")] | length' "$cbom")
    
    if [ "$key_count" -gt 0 ]; then
        log_success "Found $key_count key components"
    else
        log_error "No key components found"
        return 1
    fi
    
    log_info "Checking structure..."
    local has_props=$(jq '[.components[] | select(.cryptoProperties.assetType=="related-crypto-material") | 
                           .cryptoProperties | has("relatedCryptoMaterialProperties")] | all' "$cbom")
    
    if [ "$has_props" = "true" ]; then
        log_success "All keys use relatedCryptoMaterialProperties"
    else
        log_warn "Some keys missing relatedCryptoMaterialProperties"
    fi
}

# Check required fields
check_required_fields() {
    print_header "CHECKING REQUIRED FIELDS"
    
    local cbom="$RESULTS_DIR/phase3.json"
    
    check_field() {
        local field="$1"
        local description="$2"
        
        local missing=$(jq "[.components[] | 
                            select(.cryptoProperties.assetType==\"related-crypto-material\") | 
                            .cryptoProperties.relatedCryptoMaterialProperties | 
                            select(has(\"$field\") | not)] | length" "$cbom")
        
        if [ "$missing" -eq 0 ]; then
            log_success "$description: Present in all keys"
            return 0
        else
            log_error "$description: Missing in $missing keys"
            return 1
        fi
    }
    
    local failed=0
    
    check_field "type" "type field" || failed=$((failed + 1))
    check_field "state" "state field" || failed=$((failed + 1))
    check_field "size" "size field" || failed=$((failed + 1))
    check_field "format" "format field" || failed=$((failed + 1))
    check_field "algorithmRef" "algorithmRef field" || failed=$((failed + 1))
    
    return $failed
}

# Check field values
check_field_values() {
    print_header "VALIDATING FIELD VALUES"
    
    local cbom="$RESULTS_DIR/phase3.json"
    
    log_info "Checking 'type' field values..."
    local invalid_types=$(jq '[.components[] | 
                              select(.cryptoProperties.assetType=="related-crypto-material") | 
                              .cryptoProperties.relatedCryptoMaterialProperties.type | 
                              select(. != "private-key" and . != "public-key" and . != "secret-key")] | 
                              length' "$cbom")
    
    if [ "$invalid_types" -eq 0 ]; then
        log_success "All type values are valid"
    else
        log_error "$invalid_types keys have invalid type values"
    fi
    
    log_info "Checking 'state' field values..."
    local invalid_states=$(jq '[.components[] | 
                               select(.cryptoProperties.assetType=="related-crypto-material") | 
                               .cryptoProperties.relatedCryptoMaterialProperties.state | 
                               select(. != "active" and . != "deactivated" and . != "compromised" and 
                                      . != "destroyed" and . != "suspended" and . != "pre-activation")] | 
                               length' "$cbom")
    
    if [ "$invalid_states" -eq 0 ]; then
        log_success "All state values are valid"
    else
        log_error "$invalid_states keys have invalid state values"
    fi
    
    log_info "Checking 'size' field values..."
    local invalid_sizes=$(jq '[.components[] | 
                              select(.cryptoProperties.assetType=="related-crypto-material") | 
                              .cryptoProperties.relatedCryptoMaterialProperties.size | 
                              select(. <= 0)] | 
                              length' "$cbom")
    
    if [ "$invalid_sizes" -eq 0 ]; then
        log_success "All size values are positive"
    else
        log_error "$invalid_sizes keys have invalid size values"
    fi
}

# Run Python validator
run_python_validator() {
    print_header "RUNNING PYTHON VALIDATOR"
    
    local validator="$SCRIPT_DIR/validate_phase3.py"
    local cbom="$RESULTS_DIR/phase3.json"
    
    if [ ! -f "$validator" ]; then
        log_warn "Python validator not found at: $validator"
        log_info "Skipping Python validation"
        return 0
    fi
    
    log_info "Running validator..."
    if python3 "$validator" "$cbom" 2>&1 | tee "$RESULTS_DIR/validation.log"; then
        log_success "Validation passed"
        return 0
    else
        log_warn "Validation found issues"
        return 1
    fi
}

# Validate against schema
validate_schema() {
    print_header "SCHEMA VALIDATION"
    
    local cbom="$RESULTS_DIR/phase3.json"
    
    if ! command -v cyclonedx-cli &> /dev/null; then
        log_warn "cyclonedx-cli not found, skipping schema validation"
        log_info "Install with: npm install -g @cyclonedx/cyclonedx-cli"
        return 0
    fi
    
    log_info "Validating against CycloneDX schema..."
    if cyclonedx-cli validate --input-file "$cbom" --schema-version 1.7 2>&1 | tee "$RESULTS_DIR/schema.log"; then
        log_success "Schema validation passed"
        return 0
    else
        log_error "Schema validation failed"
        return 1
    fi
}

# Generate report
generate_report() {
    print_header "TEST REPORT"
    
    local cbom="$RESULTS_DIR/phase3.json"
    local report="$RESULTS_DIR/report.txt"
    
    {
        echo "PHASE 3 TEST REPORT"
        echo "==================="
        echo ""
        echo "Test Date: $(date)"
        echo "Test Directory: $TEST_DIR"
        echo "Generator: $CBOM_GENERATOR"
        echo ""
        
        echo "KEY STATISTICS"
        echo "--------------"
        local total_keys=$(jq '[.components[] | select(.cryptoProperties.assetType=="related-crypto-material")] | length' "$cbom")
        echo "Total keys found: $total_keys"
        
        local private_keys=$(jq '[.components[] | select(.cryptoProperties.assetType=="related-crypto-material") | 
                                  .cryptoProperties.relatedCryptoMaterialProperties | 
                                  select(.type=="private-key")] | length' "$cbom")
        echo "Private keys: $private_keys"
        
        local public_keys=$(jq '[.components[] | select(.cryptoProperties.assetType=="related-crypto-material") | 
                                 .cryptoProperties.relatedCryptoMaterialProperties | 
                                 select(.type=="public-key")] | length' "$cbom")
        echo "Public keys: $public_keys"
        
        echo ""
        echo "FIELD COVERAGE"
        echo "--------------"
        
        for field in type state size format algorithmRef; do
            local count=$(jq "[.components[] | select(.cryptoProperties.assetType==\"related-crypto-material\") | 
                              .cryptoProperties.relatedCryptoMaterialProperties | 
                              select(has(\"$field\"))] | length" "$cbom")
            local pct=$((count * 100 / total_keys))
            echo "$field: $count/$total_keys ($pct%)"
        done
        
        echo ""
        echo "FILES"
        echo "-----"
        echo "CBOM output: $RESULTS_DIR/phase3.json"
        echo "Generator log: $RESULTS_DIR/generator.log"
        echo "Validation log: $RESULTS_DIR/validation.log"
        echo "This report: $RESULTS_DIR/report.txt"
        
    } | tee "$report"
    
    log_success "Report saved to: $report"
}

# Cleanup
cleanup() {
    if [ "$KEEP_TEST_DIR" != "1" ]; then
        log_info "Cleaning up test directory..."
        rm -rf "$TEST_DIR"
    else
        log_info "Test directory preserved: $TEST_DIR"
    fi
}

# Main execution
main() {
    print_header "PHASE 3 AUTOMATED TEST SUITE"
    
    check_prerequisites
    setup_test_env
    generate_test_keys
    run_generator
    
    local test_failed=0
    
    validate_structure || test_failed=1
    check_required_fields || test_failed=1
    check_field_values || test_failed=1
    run_python_validator || test_failed=1
    validate_schema || test_failed=1
    
    generate_report
    
    print_header "TEST SUMMARY"
    
    if [ $test_failed -eq 0 ]; then
        log_success "ALL TESTS PASSED ✓"
        log_info "Phase 3 implementation is complete and conformant!"
        echo ""
        echo "Next steps:"
        echo "  1. Review the CBOM output: $RESULTS_DIR/phase3.json"
        echo "  2. Check the detailed report: $RESULTS_DIR/report.txt"
        echo "  3. Proceed to Phase 4 implementation"
    else
        log_warn "SOME TESTS FAILED"
        log_info "Phase 3 implementation needs more work"
        echo ""
        echo "To fix:"
        echo "  1. Review the validation log: $RESULTS_DIR/validation.log"
        echo "  2. Check missing fields and implement detection logic"
        echo "  3. Re-run this test suite to verify fixes"
        KEEP_TEST_DIR=1
    fi
    
    echo ""
    echo "Test directory: $TEST_DIR"
    echo ""
    
    cleanup
    
    exit $test_failed
}

# Run main
main