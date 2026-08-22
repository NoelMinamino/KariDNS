#!/bin/sh
# Test zone parser parenthesis balance and nesting checks via karicheck
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"

echo "[+] 1. Testing unclosed parenthesis zone (should fail with Unbalanced parenthesis)..."
set +e
"$BIN_DIR/karicheck" zone example.com "$ZONES_DIR/unclosed_paren.zone" > out1.txt 2>&1
RET1=$?
set -e
cat out1.txt
if [ $RET1 -eq 0 ]; then
    echo "FAIL: Expected karicheck to reject unclosed_paren.zone"
    exit 1
fi
grep -i "Unbalanced parenthesis" out1.txt || {
    echo "FAIL: Error message did not contain 'Unbalanced parenthesis'"
    exit 1
}
echo "[+] Case 1 passed."

echo "[+] 2. Testing unmatched closing parenthesis zone (should fail with Unmatched ')'...)..."
set +e
"$BIN_DIR/karicheck" zone example.com "$ZONES_DIR/unmatched_close_paren.zone" > out2.txt 2>&1
RET2=$?
set -e
cat out2.txt
if [ $RET2 -eq 0 ]; then
    echo "FAIL: Expected karicheck to reject unmatched_close_paren.zone"
    exit 1
fi
grep -i "Unmatched ')'" out2.txt || {
    echo "FAIL: Error message did not contain \"Unmatched ')'\""
    exit 1
}
echo "[+] Case 2 passed."

echo "[+] 3. Testing nested parentheses zone (should fail with Nested parentheses...)..."
set +e
"$BIN_DIR/karicheck" zone example.com "$ZONES_DIR/nested_paren.zone" > out3.txt 2>&1
RET3=$?
set -e
cat out3.txt
if [ $RET3 -eq 0 ]; then
    echo "FAIL: Expected karicheck to reject nested_paren.zone"
    exit 1
fi
grep -i "Nested parentheses" out3.txt || {
    echo "FAIL: Error message did not contain 'Nested parentheses'"
    exit 1
}
echo "[+] Case 3 passed."

echo "[+] 4. Verifying valid zone passes regression check..."
"$BIN_DIR/karicheck" zone example.com "$ZONES_DIR/ttl_suffix_test.zone" > out4.txt 2>&1
cat out4.txt
echo "[+] Valid zone check passed."

rm -f out1.txt out2.txt out3.txt out4.txt
echo "[+] All parenthesis balance and nesting test cases passed successfully!"
exit 0
