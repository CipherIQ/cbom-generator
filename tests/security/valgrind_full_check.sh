#!/bin/bash
# tests/security/valgrind_full_check.sh
# Full memory leak analysis using Valgrind

set -e

echo "=== Valgrind Full Memory Leak Analysis ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo -e "${RED}✗ Valgrind not installed${NC}"
    echo "Install with: sudo apt-get install valgrind"
    exit 1
fi

# Create output directory
mkdir -p tests/security/valgrind_logs
cd tests/security/valgrind_logs

# Clean old logs
rm -f *.log

echo "Running 3 valgrind tests..."
echo ""

# Test 1: Basic certificate scan
echo -e "${YELLOW}Test 1: Basic certificate scan (limit 10)${NC}"
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=scan_certs.log \
         ../../../build/cbom-generator \
         --no-personal-data \
         --no-network \
         --output /tmp/valgrind_test1.json \
         /etc/ssl/certs 2>&1 | grep -E "(HEAP|LEAK)" || true

if [ -f scan_certs.log ]; then
    echo -e "${GREEN}✓ Test 1 complete${NC}"
else
    echo -e "${RED}✗ Test 1 failed${NC}"
fi

# Test 2: Service discovery (with 50 plugins)
echo ""
echo -e "${YELLOW}Test 2: Service discovery (50 plugins)${NC}"
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=service_discovery.log \
         ../../../build/cbom-generator \
         --discover-services \
         --no-personal-data \
         --no-network \
         --output /tmp/valgrind_test2.json \
         . 2>&1 | grep -E "(HEAP|LEAK)" || true

if [ -f service_discovery.log ]; then
    echo -e "${GREEN}✓ Test 2 complete${NC}"
else
    echo -e "${RED}✗ Test 2 failed${NC}"
fi

# Test 3: Plugin loading only
echo ""
echo -e "${YELLOW}Test 3: Plugin loading (list plugins)${NC}"
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=plugin_loading.log \
         ../../../build/cbom-generator \
         --list-plugins 2>&1 | grep -E "(HEAP|LEAK)" || true

if [ -f plugin_loading.log ]; then
    echo -e "${GREEN}✓ Test 3 complete${NC}"
else
    echo -e "${RED}✗ Test 3 failed${NC}"
fi

# Analyze results
echo ""
echo "=== Leak Analysis ==="
echo ""

TOTAL_LEAKS=0
CRITICAL_LEAKS=0

for log in *.log; do
    echo "=== $log ==="

    # Extract leak summary
    DEFINITELY_LOST=$(grep "definitely lost:" $log | grep -oE "[0-9,]+ bytes" | head -1 | tr -d ',' | awk '{print $1}')
    INDIRECTLY_LOST=$(grep "indirectly lost:" $log | grep -oE "[0-9,]+ bytes" | head -1 | tr -d ',' | awk '{print $1}')
    POSSIBLY_LOST=$(grep "possibly lost:" $log | grep -oE "[0-9,]+ bytes" | head -1 | tr -d ',' | awk '{print $1}')
    STILL_REACHABLE=$(grep "still reachable:" $log | grep -oE "[0-9,]+ bytes" | head -1 | tr -d ',' | awk '{print $1}')

    # Default to 0 if not found
    DEFINITELY_LOST=${DEFINITELY_LOST:-0}
    INDIRECTLY_LOST=${INDIRECTLY_LOST:-0}
    POSSIBLY_LOST=${POSSIBLY_LOST:-0}
    STILL_REACHABLE=${STILL_REACHABLE:-0}

    echo "  Definitely lost: $DEFINITELY_LOST bytes"
    echo "  Indirectly lost: $INDIRECTLY_LOST bytes"
    echo "  Possibly lost:   $POSSIBLY_LOST bytes"
    echo "  Still reachable: $STILL_REACHABLE bytes"

    # Count leaks
    if [ "$DEFINITELY_LOST" -gt 0 ]; then
        CRITICAL_LEAKS=$((CRITICAL_LEAKS + 1))
        TOTAL_LEAKS=$((TOTAL_LEAKS + 1))
    fi

    if [ "$INDIRECTLY_LOST" -gt 0 ]; then
        TOTAL_LEAKS=$((TOTAL_LEAKS + 1))
    fi

    echo ""
done

# Final result
echo "=== Summary ==="
echo "Tests run: 3"
echo "Critical leaks (definitely lost): $CRITICAL_LEAKS"
echo "Total leak categories: $TOTAL_LEAKS"
echo ""

# Clean up temp files
rm -f /tmp/valgrind_test*.json

# Exit code
if [ $CRITICAL_LEAKS -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ Zero critical memory leaks detected!${NC}"
    echo ""
    echo "Note: 'Still reachable' is acceptable (global allocations)"
    echo "Logs saved in: tests/security/valgrind_logs/"
    exit 0
else
    echo -e "${RED}✗✗✗ $CRITICAL_LEAKS critical memory leak(s) detected${NC}"
    echo ""
    echo "Review logs in: tests/security/valgrind_logs/"
    echo "Focus on 'definitely lost' sections"
    exit 1
fi
