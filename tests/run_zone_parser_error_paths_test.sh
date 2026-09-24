#!/bin/sh
# ==============================================================================
# run_zone_parser_error_paths_test.sh
#
# Integration test for zone parser negative paths, anomalous directives,
# $GENERATE ranges/modifiers, and malformed RDATA handling.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "=== Running Zone Parser Error Paths & Negative Test Suite ==="

# Build karicheck if needed
if [ ! -x "./karicheck" ]; then
    echo "[+] Building karicheck..."
    make karicheck >/dev/null 2>&1 || true
fi

FAILED=0

run_check_zone() {
    _desc="$1"
    _domain="$2"
    _file="$3"
    _expect_fail="$4"

    echo "[+] Testing ${_desc} (${_file})..."
    set +e
    _out=$(./karicheck zone "${_domain}" "${_file}" 2>&1)
    _rc=$?
    set -e

    if [ "${_expect_fail}" = "1" ]; then
        if [ "${_rc}" -ne 0 ]; then
            echo "  PASS: Correctly rejected/flagged error (rc=${_rc})"
        else
            echo "  FAIL: Expected failure but passed (rc=0):"
            echo "${_out}"
            FAILED=1
        fi
    else
        if [ "${_rc}" -eq 0 ]; then
            echo "  PASS: Successfully parsed/handled (rc=0)"
        else
            echo "  FAIL: Expected success but failed (rc=${_rc}):"
            echo "${_out}"
            FAILED=1
        fi
    fi
}

# 1. Invalid TTL Suffixes & Overflow
run_check_zone "Invalid TTL suffixes & overflow" "err-ttl.example." "tests/zones/test_err_ttl_invalid.zone" 0

# 2. Bad Directives
run_check_zone "Bad Directives (\$ORIGIN / \$GENERATE)" "example.com." "tests/zones/test_err_bad_directive.zone" 1

# 3. Bad RDATA & Meta-types
run_check_zone "Bad RDATA formats" "bad-rdata.example." "tests/zones/test_err_bad_rdata.zone" 1

# 4. Non-Apex SOA
run_check_zone "Non-apex SOA" "example.com." "tests/zones/test_err_non_apex_soa.zone" 1

# 5. Unclosed Parentheses
run_check_zone "Unclosed parentheses" "example.com." "tests/zones/unclosed_paren.zone" 1

# 6. Inline generated anomaly zones in temporary directory
TMP_ZONE_DIR="/tmp/karidns_zone_err_$$"
mkdir -p "${TMP_ZONE_DIR}"
trap 'rm -rf "${TMP_ZONE_DIR}"' EXIT INT TERM

# 6a. $GENERATE invalid modifiers
cat << 'EOF' > "${TMP_ZONE_DIR}/bad_gen_mod.zone"
$ORIGIN example.com.
$TTL 300
@ SOA ns host 1 2 3 4 5
@ NS ns
$GENERATE 1-3 host${1,3,z} A 192.0.2.$
EOF
run_check_zone "\$GENERATE invalid modifier 'z'" "example.com." "${TMP_ZONE_DIR}/bad_gen_mod.zone" 1

# 6b. $GENERATE start > stop
cat << 'EOF' > "${TMP_ZONE_DIR}/bad_gen_range.zone"
$ORIGIN example.com.
$TTL 300
@ SOA ns host 1 2 3 4 5
@ NS ns
$GENERATE 10-2 host$ A 192.0.2.$
EOF
run_check_zone "\$GENERATE inverted range 10-2" "example.com." "${TMP_ZONE_DIR}/bad_gen_range.zone" 1

# 6c. Trailing escape at EOF
cat << 'EOF' > "${TMP_ZONE_DIR}/trailing_escape.zone"
$ORIGIN example.com.
$TTL 300
@ SOA ns host 1 2 3 4 5
@ NS ns
txtrec IN TXT "trailing escape \
EOF
run_check_zone "TXT trailing escape at EOF" "example.com." "${TMP_ZONE_DIR}/trailing_escape.zone" 1

# 6d. Unterminated quoted string
cat << 'EOF' > "${TMP_ZONE_DIR}/unterminated_quote.zone"
$ORIGIN example.com.
$TTL 300
@ SOA ns host 1 2 3 4 5
@ NS ns
txtrec IN TXT "unclosed quote
EOF
run_check_zone "TXT unterminated quote" "example.com." "${TMP_ZONE_DIR}/unterminated_quote.zone" 1

if [ "${FAILED}" -ne 0 ]; then
    echo "=== Some Zone Parser Error Path Tests FAILED ==="
    exit 1
fi

echo "=== All Zone Parser Error Path Tests PASSED ==="
exit 0
