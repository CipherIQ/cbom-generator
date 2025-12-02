#!/bin/bash
# tests/performance/baseline_benchmark.sh
# Baseline performance benchmarking for Phase 5

set -e

echo "=== CBOM Generator v1.3 - Performance Baseline ==="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create results directory
mkdir -p tests/performance/results
RESULTS_FILE="tests/performance/results/baseline_$(date +%Y%m%d_%H%M%S).txt"

echo "Results will be saved to: $RESULTS_FILE"
echo ""

# Benchmark 1: Plugin loading (50 plugins)
echo -e "${YELLOW}Benchmark 1: Plugin loading (50 plugins)${NC}"
echo "Target: <500ms"
PLUGIN_START=$(date +%s%N)
./build/cbom-generator --list-plugins > /dev/null 2>&1
PLUGIN_END=$(date +%s%N)
PLUGIN_TIME=$(( (PLUGIN_END - PLUGIN_START) / 1000000 ))
echo "  Time: ${PLUGIN_TIME}ms"
if [ $PLUGIN_TIME -lt 500 ]; then
    echo -e "  ${GREEN}✓ PASS${NC} (target: <500ms)"
else
    echo "  ⚠ SLOW (target: <500ms)"
fi
echo ""

# Benchmark 2: Certificate scanning (limit 50)
echo -e "${YELLOW}Benchmark 2: Certificate scanning (50 certs)${NC}"
echo "Target: <5 seconds"
CERT_START=$(date +%s%N)
timeout 30 ./build/cbom-generator --no-personal-data --no-network --output /tmp/bench_certs.json /etc/ssl/certs 2>/dev/null || true
CERT_END=$(date +%s%N)
CERT_TIME=$(( (CERT_END - CERT_START) / 1000000000 ))
echo "  Time: ${CERT_TIME}s"
if [ $CERT_TIME -lt 5 ]; then
    echo -e "  ${GREEN}✓ PASS${NC} (target: <5s)"
else
    echo "  ⚠ SLOW (target: <5s)"
fi
rm -f /tmp/bench_certs.json
echo ""

# Benchmark 3: Service discovery (0 services expected)
echo -e "${YELLOW}Benchmark 3: Service discovery (no services)${NC}"
echo "Target: <2 seconds"
DISC_START=$(date +%s%N)
./build/cbom-generator --discover-services --no-personal-data --no-network --output /tmp/bench_disc.json . 2>/dev/null
DISC_END=$(date +%s%N)
DISC_TIME=$(( (DISC_END - DISC_START) / 1000000000 ))
echo "  Time: ${DISC_TIME}s"
if [ $DISC_TIME -lt 2 ]; then
    echo -e "  ${GREEN}✓ PASS${NC} (target: <2s)"
else
    echo "  ⚠ SLOW (target: <2s)"
fi
rm -f /tmp/bench_disc.json
echo ""

# Benchmark 4: Memory usage
echo -e "${YELLOW}Benchmark 4: Memory usage${NC}"
echo "Target: <512 MB"
MEMORY_OUTPUT=$(/usr/bin/time -v ./build/cbom-generator --no-personal-data --no-network --output /tmp/bench_mem.json /etc/ssl/certs 2>&1 | grep "Maximum resident set")
MEMORY_KB=$(echo "$MEMORY_OUTPUT" | grep -oE "[0-9]+" | head -1)
MEMORY_MB=$(( MEMORY_KB / 1024 ))
echo "  Memory: ${MEMORY_MB}MB"
if [ $MEMORY_MB -lt 512 ]; then
    echo -e "  ${GREEN}✓ PASS${NC} (target: <512MB)"
else
    echo "  ⚠ HIGH (target: <512MB)"
fi
rm -f /tmp/bench_mem.json
echo ""

# Benchmark 5: Output generation
echo -e "${YELLOW}Benchmark 5: Full scan with output${NC}"
echo "Target: <10 seconds"
FULL_START=$(date +%s%N)
./build/cbom-generator --no-personal-data --no-network --output /tmp/bench_full.json /etc/ssl/certs 2>/dev/null
FULL_END=$(date +%s%N)
FULL_TIME=$(( (FULL_END - FULL_START) / 1000000000 ))
OUTPUT_SIZE=$(ls -lh /tmp/bench_full.json | awk '{print $5}')
echo "  Time: ${FULL_TIME}s"
echo "  Output size: ${OUTPUT_SIZE}"
if [ $FULL_TIME -lt 10 ]; then
    echo -e "  ${GREEN}✓ PASS${NC} (target: <10s)"
else
    echo "  ⚠ SLOW (target: <10s)"
fi
rm -f /tmp/bench_full.json
echo ""

# Save results
cat > "$RESULTS_FILE" << EOF
CBOM Generator v1.3 - Performance Baseline
Generated: $(date)

Benchmark Results:
==================

1. Plugin Loading (50 plugins):    ${PLUGIN_TIME}ms  (target: <500ms)
2. Certificate Scanning:            ${CERT_TIME}s     (target: <5s)
3. Service Discovery:               ${DISC_TIME}s     (target: <2s)
4. Memory Usage:                    ${MEMORY_MB}MB    (target: <512MB)
5. Full Scan + Output:              ${FULL_TIME}s     (target: <10s)

Output Size: ${OUTPUT_SIZE}

System Info:
CPU Cores: $(nproc)
Total RAM: $(free -h | grep Mem | awk '{print $2}')
Kernel: $(uname -r)
EOF

echo "=== Summary ==="
echo "All benchmarks complete!"
echo "Results saved to: $RESULTS_FILE"
echo ""
cat "$RESULTS_FILE"
