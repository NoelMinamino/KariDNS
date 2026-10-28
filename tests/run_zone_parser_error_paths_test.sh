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
run_check_zone "Invalid TTL suffixes & overflow (an error since BIND compat batch 1: it used to be 3600)" "err-ttl.example." "tests/zones/test_err_ttl_invalid.zone" 1

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

# 6e. RFC 3597 section 5 (D15-2): the generic form "\# len hex" of a KNOWN type must carry RDATA that is valid for the
#     type.  "PTR \# 0" and "NS \# 3 010203" used to be accepted and served as raw octets, which the wire decoder of
#     a secondary refuses.  karicheck reports the record at its own line; an unknown type may be empty.
check_generic() {
    _desc="$1"; _rr="$2"; _line="$3"; _reason="$4"
    printf '$ORIGIN example.com.\n$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n%s\n' "${_rr}" > "${TMP_ZONE_DIR}/generic.zone"
    echo "[+] Testing ${_desc}..."
    set +e
    _out=$(./karicheck zone example.com. "${TMP_ZONE_DIR}/generic.zone" 2>&1)
    _rc=$?
    set -e
    if [ "${_rc}" -ne 0 ] && echo "${_out}" | grep -Eq "at line ${_line}([^0-9]|\$)" && echo "${_out}" | grep -q "${_reason}"; then
        echo "  PASS: rejected at line ${_line} (${_reason})"
    else
        echo "  FAIL: rc=${_rc}, expected 'at line ${_line}' and '${_reason}':"
        echo "${_out}"
        FAILED=1
    fi
}
check_generic "generic PTR with empty RDATA" 'x IN PTR \# 0' 6 "not terminated"
check_generic "generic NS with a label that runs past the end" 'x IN NS \# 3 010203' 6 "runs past the end"
check_generic "generic NS with a compressed name" 'x IN NS \# 2 C00C' 6 "compressed"
check_generic "generic NS with a trailing octet" 'x IN NS \# 6 036E733100FF' 6 "trailing octets"
check_generic "generic MX without an exchange" 'x IN MX \# 2 000A' 6 "not terminated"
check_generic "generic TXT longer than its RDATA" 'x IN TXT \# 2 0361' 6 "not valid for this record type"

printf '$ORIGIN example.com.\n$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nok1 PTR \\# 5 036e733100\nok2 TYPE65534 \\# 0\nok3 MX \\# 7 000a036e733100\n' > "${TMP_ZONE_DIR}/generic_ok.zone"
run_check_zone "valid generic RDATA of known types and an empty unknown type" "example.com." "${TMP_ZONE_DIR}/generic_ok.zone" 0

if [ "${FAILED}" -ne 0 ]; then
    echo "=== Some Zone Parser Error Path Tests FAILED ==="
    exit 1
fi

echo "=== All Zone Parser Error Path Tests PASSED ==="
exit 0
