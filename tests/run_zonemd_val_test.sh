#!/bin/sh
# RFC 8976 ZONEMD verification in karicheck.
# - Scheme / hash algorithm range warnings and short RDATA (fewer than 4 fields).
# - The RFC 8976 Appendix A test vectors A.1 .. A.5 are VALID (K-01: owner names and RDATA names in canonical,
#   lower-case form, RFC 4034 section 6.2 / RFC 6840 section 5.1; A.2 also has a non-apex ZONEMD that is digested
#   like any other RR, and MX targets without addresses that are only warnings, K-02).
# - A modified zone, a duplicated (scheme, hash) tuple and a digest of the wrong size fail with the errors counted
#   in the [RESULT] line (RFC 8976 section 4, K-04).
set -e

KARICHECK="./karicheck"
if [ ! -x "$KARICHECK" ]; then
    if [ -x "./tools/karicheck" ]; then
        KARICHECK="./tools/karicheck"
    else
        echo "[+] Building karicheck..."
        make karicheck
    fi
fi

TMP_DIR=$(mktemp -d /tmp/zonemd_val.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "[-] FAIL: $1"
    exit 1
}

echo "[+] Testing invalid ZONEMD scheme and halg range checks in karicheck..."

OUT=$("$KARICHECK" zone example. tests/zones/zonemd_invalid_val.zone 2>&1 || true)
echo "$OUT"

SCHEME_WARN_COUNT=$(echo "$OUT" | grep -c "ZONEMD scheme '257' is not a valid number (0-255)" || true)
if [ "$SCHEME_WARN_COUNT" -eq 1 ]; then
    echo "[+] Scheme range check warning confirmed (exactly 1 time)."
else
    fail "Expected scheme warning exactly 1 time, got $SCHEME_WARN_COUNT."
fi

HALG_WARN_COUNT=$(echo "$OUT" | grep -c "ZONEMD hash algorithm '257' is not a valid number (0-255)" || true)
if [ "$HALG_WARN_COUNT" -eq 1 ]; then
    echo "[+] Hash algorithm range check warning confirmed (exactly 1 time)."
else
    fail "Expected hash algorithm warning exactly 1 time, got $HALG_WARN_COUNT."
fi

echo "[+] Testing incomplete ZONEMD (fewer than 4 fields) in karicheck..."
OUT_SHORT=$("$KARICHECK" zone example. tests/zones/zonemd_short_rdata.zone 2>&1 || true)
echo "$OUT_SHORT"

if echo "$OUT_SHORT" | grep -q "fewer than 4 fields"; then
    echo "[+] Fewer than 4 fields warning confirmed."
else
    fail "Expected 'fewer than 4 fields' warning not found in output."
fi

# check_vector <label> <zone> <file> <number of VALID lines> <expected [RESULT] counts>
# Exit status 0, every supported ZONEMD VALID, and the [RESULT] counts equal the printed [ERROR]/[WARNING] lines.
check_vector() {
    label=$1; zone=$2; file=$3; nvalid=$4; counts=$5
    echo "[+] RFC 8976 Appendix $label ($zone)..."
    rc=0
    out=$("$KARICHECK" zone "$zone" "$file" 2>&1) || rc=$?
    echo "$out"
    [ "$rc" -eq 0 ] || fail "$label: exit status $rc"
    got=$(echo "$out" | grep -c "^\[OK\] ZONEMD (Scheme 1, Hash [12]) for '$zone' is VALID\.$" || true)
    [ "$got" -eq "$nvalid" ] || fail "$label: $got VALID lines, expected $nvalid"
    echo "$out" | grep -q "^\[RESULT\] Zone '$zone': $counts$" || fail "$label: expected [RESULT] '$counts'"
    e=$(echo "$out" | grep -c "^\[ERROR\]" || true)
    w=$(echo "$out" | grep -c "^\[WARNING\]" || true)
    [ "$counts" = "$e error(s), $w warning(s)" ] || fail "$label: printed $e errors / $w warnings, [RESULT] says '$counts'"
}

check_vector A.1 example. tests/zones/zonemd_a1.zone 1 "0 error(s), 0 warning(s)"
# A.2 warnings: out-of-zone foo.test., non-apex ZONEMD, MX targets MAIL1 and Mail2.Example. without addresses,
# occluded.sub (all of them stay in or out of the digest as RFC 8976 section 3.3.1.1 says).
check_vector A.2 example. tests/zones/zonemd_a2.zone 1 "0 error(s), 5 warning(s)"
OUT=$("$KARICHECK" zone example. tests/zones/zonemd_a2.zone 2>&1)
for w in "out-of-zone record 'foo.test.' TXT ignored" "ZONEMD record 'non-apex.example.' is not at the zone apex" \
         "In-bailiwick MX target 'MAIL1.example.' has no A/AAAA record" \
         "In-bailiwick MX target 'Mail2.Example.' has no A/AAAA record" \
         "Record 'occluded.sub.example. TXT' is occluded by delegation"; do
    echo "$OUT" | grep "^\[WARNING\]" | grep -qF "$w" || fail "A.2: warning '$w' missing"
done
check_vector A.3 example. tests/zones/zonemd_a3.zone 2 "0 error(s), 0 warning(s)"
OUT=$("$KARICHECK" zone example. tests/zones/zonemd_a3.zone 2>&1)
[ "$(echo "$OUT" | grep -c "^\[INFO\] ZONEMD (Scheme [0-9]*, Hash [0-9]*) for 'example.' is not verified")" -eq 2 ] ||
    fail "A.3: the two private-range ZONEMD RRs are not reported as not verified"
check_vector A.4 uri.arpa. tests/zones/zonemd_a4.zone 1 "0 error(s), 0 warning(s)"
check_vector A.5 root-servers.net. tests/zones/zonemd_a5.zone 1 "0 error(s), 0 warning(s)"

# check_fail <label> <file> <message> <expected [RESULT] counts>
check_fail() {
    label=$1; file=$2; msg=$3; counts=$4
    echo "[+] $label..."
    rc=0
    out=$("$KARICHECK" zone example. "$file" 2>&1) || rc=$?
    echo "$out"
    [ "$rc" -eq 1 ] || fail "$label: exit status $rc, expected 1"
    echo "$out" | grep "^\[ERROR\]" | grep -qF "$msg" || fail "$label: error '$msg' missing"
    echo "$out" | grep -q "^\[RESULT\] Zone 'example.': $counts$" || fail "$label: expected [RESULT] '$counts'"
    echo "$out" | grep -q "^\[FAIL\] Zone 'example.'" || fail "$label: no [FAIL] line"
}

# A changed RR: both supported digests no longer match; each mismatch is one counted error.
sed 's/This example has multiple digests/This example has been modified/' tests/zones/zonemd_a3.zone > "$TMP_DIR/a3_mod.zone"
check_fail "A.3 with a modified TXT RR" "$TMP_DIR/a3_mod.zone" "ZONEMD (Scheme 1, Hash 1) for 'example.' is INVALID." \
    "2 error(s), 0 warning(s)"
out=$("$KARICHECK" zone example. "$TMP_DIR/a3_mod.zone" 2>&1 || true)
echo "$out" | grep -q "^\[ERROR\] ZONEMD (Scheme 1, Hash 2) for 'example.' is INVALID\.$" || fail "A.3 modified: SHA-512 not INVALID"

# Only the case of an owner name changed: the digest is the same (canonical form, RFC 4034 section 6.2).
sed 's/^ns1\.example\./NS1.Example./' tests/zones/zonemd_a3.zone > "$TMP_DIR/a3_case.zone"
check_vector "A.3 with NS1.Example. in mixed case" example. "$TMP_DIR/a3_case.zone" 2 "0 error(s), 0 warning(s)"

# RFC 8976 section 4 step 4: two ZONEMD RRs with the same scheme and hash algorithm; neither is used.
{ cat tests/zones/zonemd_a1.zone; printf 'example. 86400 IN ZONEMD 2018031900 1 1 %s\n' \
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; } \
    > "$TMP_DIR/a1_dup.zone"
check_fail "A.1 with a second SHA-384 ZONEMD" "$TMP_DIR/a1_dup.zone" \
    "Zone 'example.' has more than one ZONEMD with Scheme 1 and Hash 1" "1 error(s), 0 warning(s)"
out=$("$KARICHECK" zone example. "$TMP_DIR/a1_dup.zone" 2>&1 || true)
if echo "$out" | grep -q "is VALID"; then fail "A.1 duplicate: a ZONEMD was reported VALID"; fi

# RFC 8976 section 4 step 5d: a SHA-384 digest that is not 48 octets.
sed 's/777f98b8e730044c )/777f98b8 )/' tests/zones/zonemd_a1.zone > "$TMP_DIR/a1_short.zone"
check_fail "A.1 with a 44-octet SHA-384 digest" "$TMP_DIR/a1_short.zone" \
    "ZONEMD (Scheme 1, Hash 1) for 'example.': the digest is not 48 octets" "1 error(s), 0 warning(s)"

# K-02: other errors do not stop the ZONEMD verification.
{ cat tests/zones/zonemd_a1.zone; echo 'example. 86400 IN NS ns3.example.'; } > "$TMP_DIR/a1_err.zone"
rc=0
out=$("$KARICHECK" zone example. "$TMP_DIR/a1_err.zone" 2>&1) || rc=$?
echo "$out"
[ "$rc" -eq 1 ] || fail "A.1 + NS without glue: exit status $rc"
echo "$out" | grep -q "^\[ERROR\] In-bailiwick NS target 'ns3.example.' lacks A/AAAA glue" || fail "A.1 + NS: no glue error"
echo "$out" | grep -q "^\[ERROR\] ZONEMD (Scheme 1, Hash 1) for 'example.' is INVALID\.$" ||
    fail "A.1 + NS: the ZONEMD was not verified although the zone changed"
echo "$out" | grep -q "^\[RESULT\] Zone 'example.': 2 error(s), 0 warning(s)$" || fail "A.1 + NS: wrong [RESULT]"

echo "[+] All ZONEMD validation tests passed successfully."
exit 0
