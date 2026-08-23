#!/bin/sh
set -e

echo "=== Running karicheck Delegation & Glue Verification Tests ==="

# Check karicheck binary exists, if not build it
if [ ! -f ./karicheck ]; then
    echo "[+] Building karicheck..."
    make karicheck
fi

# Test 1: missing_glue.zone should produce a warning about missing glue A/AAAA
echo "[+] Test 1: Testing missing in-bailiwick glue record..."
OUT1=$(./karicheck zone missing-glue.example. tests/zones/missing_glue.zone 2>&1 || true)
if echo "$OUT1" | grep -q "delegation will fail to resolve"; then
    echo "  PASS: Missing in-bailiwick glue warning detected successfully."
else
    echo "  FAIL: Expected missing glue warning not found in output:"
    echo "$OUT1"
    exit 1
fi

# Test 2: missing_apex_ns.zone should produce an error and exit with non-zero status
echo "[+] Test 2: Testing missing apex NS record..."
set +e
OUT2=$(./karicheck zone missing-apex-ns.example. tests/zones/missing_apex_ns.zone 2>&1)
EXIT2=$?
set -e

if [ $EXIT2 -ne 0 ] && echo "$OUT2" | grep -q "No NS record found at zone apex"; then
    echo "  PASS: Missing apex NS record correctly failed with error."
else
    echo "  FAIL: Expected missing apex NS error or non-zero exit code (exit=$EXIT2):"
    echo "$OUT2"
    exit 1
fi

# Test 3: Normal valid zone (valid_glue.zone) should pass with exit code 0
echo "[+] Test 3: Testing normal valid zone (valid_glue.zone)..."
OUT3=$(./karicheck zone valid.example. tests/zones/valid_glue.zone 2>&1)
if echo "$OUT3" | grep -q "No NS record found at zone apex"; then
    echo "  FAIL: Unexpected apex NS error on valid zone."
    exit 1
fi
if echo "$OUT3" | grep -q "delegation will fail to resolve"; then
    echo "  FAIL: Unexpected missing glue warning on valid zone."
    exit 1
fi
echo "  PASS: Normal zone (valid_glue.zone) passed with zero exit code."

# Test 4: Comprehensive zone (example.com.zone) should not have false positive glue warnings or apex NS error
echo "[+] Test 4: Testing comprehensive sample zone (example.com.zone)..."
OUT4=$(./karicheck zone example.com. tests/zones/example.com.zone 2>&1 || true)
if echo "$OUT4" | grep -q "No NS record found at zone apex"; then
    echo "  FAIL: Unexpected apex NS error on example.com.zone."
    exit 1
fi
if echo "$OUT4" | grep -q "delegation will fail to resolve"; then
    echo "  FAIL: Unexpected missing glue warning on example.com.zone."
    exit 1
fi
echo "  PASS: example.com.zone passed without false positive delegation/glue warnings."

echo "=== All karicheck Delegation & Glue Tests Passed! ==="
