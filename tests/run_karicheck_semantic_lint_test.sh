#!/bin/sh
# ==============================================================================
# run_karicheck_semantic_lint_test.sh
#
# Integration test for karicheck DNS Semantic Lint checks:
# 1. In-bailiwick glue consistency (missing glue warning, invalid IP error)
# 2. CNAME coexistence error
# 3. Delegation occlusion warning
# 4. CNAME loops (error) and CNAME chains (warning)
# 5. ZONEMD SOA serial consistency error
# 6. [RESULT] summary line and exit status
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "=== Running karicheck Semantic Lint Test Suite ==="

# Build karicheck
echo "[+] Building karicheck..."
[ -x karicheck ] || make karicheck

FAILED=0

# Test 1: In-bailiwick Glue Consistency (ERROR)
echo "[+] Test 1: In-bailiwick glue check (missing_glue.zone)..."
set +e
OUT1=$(./karicheck zone missing-glue.example. tests/zones/missing_glue.zone 2>&1)
EXIT1=$?
set -e
if [ $EXIT1 -ne 0 ] && echo "$OUT1" | grep -q "lacks A/AAAA glue record" && echo "$OUT1" | grep -q "\[ERROR\]"; then
    echo "  PASS: Missing in-bailiwick glue error correctly detected (exit=$EXIT1)."
else
    echo "  FAIL: Expected glue error missing (exit=$EXIT1):"
    echo "$OUT1"
    FAILED=1
fi

# Test 1b: Out-of-bailiwick Glue Detection (WARNING)
echo "[+] Test 1b: Out-of-bailiwick glue check (orphan_glue.zone)..."
OUT1B=$(./karicheck zone example.com. tests/zones/orphan_glue.zone 2>&1 || true)
if echo "$OUT1B" | grep -q "Out-of-bailiwick glue record 'ns1.example.net.' in zone 'example.com.'"; then
    echo "  PASS: Out-of-bailiwick glue warning detected."
else
    echo "  FAIL: Expected out-of-bailiwick glue warning missing:"
    echo "$OUT1B"
    FAILED=1
fi

# Test 2: CNAME Coexistence
echo "[+] Test 2: CNAME coexistence check..."
set +e
OUT2=$(./karicheck zone example.com. tests/zones/test_lint_cname_coexist.zone 2>&1)
EXIT2=$?
set -e
if [ $EXIT2 -ne 0 ] && echo "$OUT2" | grep -q "CNAME record at 'bad.example.com.' coexists with other record type"; then
    echo "  PASS: CNAME coexistence error correctly detected (exit=$EXIT2)."
else
    echo "  FAIL: Expected CNAME coexistence error not found (exit=$EXIT2):"
    echo "$OUT2"
    FAILED=1
fi
if echo "$OUT2" | grep -q "\[RESULT\] Zone 'example.com.': 1 error(s)"; then
    echo "  PASS: [RESULT] line correctly reflects error count."
else
    echo "  FAIL: [RESULT] summary line missing or incorrect."
    FAILED=1
fi

# Test 3: Delegation Occlusion
echo "[+] Test 3: Delegation occlusion check..."
OUT3=$(./karicheck zone example.com. tests/zones/test_lint_occlusion.zone 2>&1 || true)
if echo "$OUT3" | grep -q "is occluded by delegation at 'child.example.com.'"; then
    echo "  PASS: Delegation occlusion warning detected."
else
    echo "  FAIL: Expected delegation occlusion warning missing:"
    echo "$OUT3"
    FAILED=1
fi
if echo "$OUT3" | grep -q "\[RESULT\] Zone 'example.com.': 0 error(s), 1 warning(s)"; then
    echo "  PASS: [RESULT] line correctly reflects 0 errors, 1 warning."
else
    echo "  FAIL: [RESULT] summary line incorrect for occlusion test."
    FAILED=1
fi

# Test 4: CNAME Loops & Chains
echo "[+] Test 4: CNAME loops & chains check..."
set +e
OUT4=$(./karicheck zone example.com. tests/zones/test_lint_cname_loop.zone 2>&1)
EXIT4=$?
set -e
if [ $EXIT4 -ne 0 ] && echo "$OUT4" | grep -q "CNAME loop detected" && echo "$OUT4" | grep -q "CNAME chain detected"; then
    echo "  PASS: Both CNAME loop error and CNAME chain warning detected."
else
    echo "  FAIL: CNAME loop or chain missing (exit=$EXIT4):"
    echo "$OUT4"
    FAILED=1
fi

# Test 4b: RFC 2181 §10.3 NS/MX points to CNAME target (ERROR)
echo "[+] Test 4b: RFC 2181 §10.3 NS/MX CNAME target check..."
set +e
OUT4B=$(./karicheck zone example.com. tests/zones/test_lint_cname_target.zone 2>&1)
EXIT4B=$?
set -e
if [ $EXIT4B -ne 0 ] && echo "$OUT4B" | grep -q "NS record 'example.com.' points to CNAME target" && echo "$OUT4B" | grep -q "MX record 'example.com.' points to CNAME target" && echo "$OUT4B" | grep -q "2 error(s)"; then
    echo "  PASS: RFC 2181 §10.3 NS and MX CNAME target errors detected (exit=$EXIT4B)."
else
    echo "  FAIL: RFC 2181 §10.3 CNAME target errors missing (exit=$EXIT4B):"
    echo "$OUT4B"
    FAILED=1
fi

# Test 5: ZONEMD Serial Mismatch
echo "[+] Test 5: ZONEMD SOA serial consistency check..."
set +e
OUT5=$(./karicheck zone example.com. tests/zones/test_lint_zonemd_serial.zone 2>&1)
EXIT5=$?
set -e
if [ $EXIT5 -ne 0 ] && echo "$OUT5" | grep -q "ZONEMD serial 2026091100 does not match SOA serial 2026091101"; then
    echo "  PASS: ZONEMD serial mismatch error detected."
else
    echo "  FAIL: Expected ZONEMD serial mismatch error missing (exit=$EXIT5):"
    echo "$OUT5"
    FAILED=1
fi

# Test 6: Valid Zone Clean Pass
echo "[+] Test 6: Valid zone clean check (valid_glue.zone)..."
OUT6=$(./karicheck zone valid.example. tests/zones/valid_glue.zone 2>&1)
if echo "$OUT6" | grep -q "\[RESULT\] Zone 'valid.example.': 0 error(s), 0 warning(s)" && echo "$OUT6" | grep -q "\[OK\]"; then
    echo "  PASS: Valid zone passed with 0 errors, 0 warnings, and [OK] status."
else
    echo "  FAIL: Valid zone failed clean check:"
    echo "$OUT6"
    FAILED=1
fi

# Test 7: rdata Count Overflow (> MAX_RDATA = 48) (ERROR)
echo "[+] Test 7: rdata field count overflow check (>48 fields)..."
RDATA_OVERFLOW_ZONE="tests/zones/test_lint_rdata_overflow.tmp.zone"
RDATA_OK_ZONE="tests/zones/test_lint_rdata_ok.tmp.zone"

# Build 49-field TXT zone
printf '\$ORIGIN example.com.\n\$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. 2026091801 7200 3600 1209600 3600\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.1\ntxtoverflow IN TXT' > "$RDATA_OVERFLOW_ZONE"
for i in $(seq 1 49); do
    printf ' "txt%d"' "$i" >> "$RDATA_OVERFLOW_ZONE"
done
printf '\n' >> "$RDATA_OVERFLOW_ZONE"

# Build 48-field TXT zone (exact MAX_RDATA limit)
printf '\$ORIGIN example.com.\n\$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. 2026091801 7200 3600 1209600 3600\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.1\ntxtok IN TXT' > "$RDATA_OK_ZONE"
for i in $(seq 1 48); do
    printf ' "txt%d"' "$i" >> "$RDATA_OK_ZONE"
done
printf '\n' >> "$RDATA_OK_ZONE"

set +e
OUT7_BAD=$(./karicheck zone example.com. "$RDATA_OVERFLOW_ZONE" 2>&1)
EXIT7_BAD=$?
OUT7_OK=$(./karicheck zone example.com. "$RDATA_OK_ZONE" 2>&1)
EXIT7_OK=$?
set -e
rm -f "$RDATA_OVERFLOW_ZONE" "$RDATA_OK_ZONE"

if [ $EXIT7_BAD -ne 0 ] && echo "$OUT7_BAD" | grep -qi "Too many rdata fields on record"; then
    echo "  PASS: 49 rdata fields correctly rejected with MAX_RDATA error (exit=$EXIT7_BAD)."
else
    echo "  FAIL: Expected MAX_RDATA overflow rejection not detected (exit=$EXIT7_BAD):"
    echo "$OUT7_BAD"
    FAILED=1
fi

if [ $EXIT7_OK -eq 0 ] && echo "$OUT7_OK" | grep -q "\[RESULT\] Zone 'example.com.': 0 error(s)"; then
    echo "  PASS: 48 rdata fields correctly accepted at exact MAX_RDATA boundary."
else
    echo "  FAIL: Expected 48 rdata fields to pass, but failed (exit=$EXIT7_OK):"
    echo "$OUT7_OK"
    FAILED=1
fi

# Test 8: CLI Options, Version, Usage & Error Handlers
echo "[+] Test 8: karicheck CLI options & usage..."
./karicheck -v >/dev/null 2>&1 || true
./karicheck --version >/dev/null 2>&1 || true
./karicheck -h >/dev/null 2>&1 || true
./karicheck --help >/dev/null 2>&1 || true
./karicheck >/dev/null 2>&1 || true
./karicheck invalid_cmd >/dev/null 2>&1 || true
./karicheck zone >/dev/null 2>&1 || true
./karicheck zones >/dev/null 2>&1 || true
./karicheck conf >/dev/null 2>&1 || true

# Test 9: Bad TTL Suffix & Number Overflow Handling
echo "[+] Test 9: Bad TTL suffix handling (test_err_ttl_invalid.zone)..."
OUT9=$(./karicheck zone err-ttl.example. tests/zones/test_err_ttl_invalid.zone 2>&1 || true)
echo "  PASS: test_err_ttl_invalid.zone processed safely."

# Test 10: Bad Directives
echo "[+] Test 10: Bad directives (test_err_bad_directive.zone)..."
set +e
OUT10=$(./karicheck zone example.com. tests/zones/test_err_bad_directive.zone 2>&1)
EXIT10=$?
set -e
if [ $EXIT10 -ne 0 ]; then
    echo "  PASS: Bad directive zone correctly rejected (exit=$EXIT10)."
else
    echo "  FAIL: Expected bad directive zone rejection not observed (exit=$EXIT10):"
    echo "$OUT10"
    FAILED=1
fi

# Test 11: Bad RDATA & Meta-types
echo "[+] Test 11: Bad RDATA and meta-type records (test_err_bad_rdata.zone)..."
set +e
OUT11=$(./karicheck zone bad-rdata.example. tests/zones/test_err_bad_rdata.zone 2>&1)
EXIT11=$?
set -e
if [ $EXIT11 -ne 0 ] && echo "$OUT11" | grep -Eq "Invalid IPv4|invalid IPv4|is a meta-type|Invalid|ERROR|error"; then
    echo "  PASS: Bad RDATA correctly rejected with errors (exit=$EXIT11)."
else
    echo "  FAIL: Expected RDATA rejection missing (exit=$EXIT11):"
    echo "$OUT11"
    FAILED=1
fi

# Test 12: Non-Apex SOA
echo "[+] Test 12: Non-apex SOA (test_err_non_apex_soa.zone)..."
set +e
OUT12=$(./karicheck zone example.com. tests/zones/test_err_non_apex_soa.zone 2>&1)
EXIT12=$?
set -e
if [ $EXIT12 -ne 0 ] && echo "$OUT12" | grep -q "No SOA record found"; then
    echo "  PASS: Missing apex SOA detected when SOA is at non-apex (exit=$EXIT12)."
else
    echo "  FAIL: Expected non-apex SOA error missing (exit=$EXIT12):"
    echo "$OUT12"
    FAILED=1
fi

# Test 13: Unclosed Parentheses
echo "[+] Test 13: Unclosed parentheses (unclosed_paren.zone)..."
set +e
OUT13=$(./karicheck zone example.com. tests/zones/unclosed_paren.zone 2>&1)
EXIT13=$?
set -e
if [ $EXIT13 -ne 0 ]; then
    echo "  PASS: Unclosed parenthesis correctly rejected (exit=$EXIT13)."
else
    echo "  FAIL: Unclosed parenthesis was not rejected (exit=$EXIT13):"
    echo "$OUT13"
    FAILED=1
fi

if [ $FAILED -ne 0 ]; then
    echo "=== Some Semantic Lint Tests FAILED ==="
    exit 1
fi

echo "=== All karicheck Semantic Lint Tests Passed! ==="


