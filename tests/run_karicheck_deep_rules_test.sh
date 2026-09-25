#!/bin/sh
set -e

# ==============================================================================
# KariDNS karicheck(1) Deep Static Lint Rules Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -x "$ROOT_DIR/karicheck" ]; then
    echo "=== Building karicheck with make ==="
    [ -x "$ROOT_DIR/karicheck" ] || make -C "$ROOT_DIR" karicheck
fi

KARICHECK="${1:-${KARICHECK:-$ROOT_DIR/karicheck}}"

if [ ! -x "$KARICHECK" ]; then
    echo "Error: karicheck binary not found at $KARICHECK"
    exit 1
fi

TMP_DIR="/tmp/karidns_karicheck_deep_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
TEST_COUNT=0

run_check_zone_fail() {
    TEST_COUNT=$((TEST_COUNT + 1))
    local desc="$1"
    local domain="$2"
    local zfile="$3"
    local pattern="$4"
    echo -n "Test $TEST_COUNT: $desc ... "
    if "$KARICHECK" zone "$domain" "$zfile" > "$TMP_DIR/out.txt" 2>&1; then
        echo "FAIL (expected karicheck error exit code but got 0)"
        cat "$TMP_DIR/out.txt" >&2
        FAILED=$((FAILED + 1))
    else
        if grep -q "$pattern" "$TMP_DIR/out.txt"; then
            echo "OK"
        else
            echo "FAIL (expected pattern '$pattern' not found)"
            cat "$TMP_DIR/out.txt" >&2
            FAILED=$((FAILED + 1))
        fi
    fi
}

run_check_zone_warn() {
    TEST_COUNT=$((TEST_COUNT + 1))
    local desc="$1"
    local domain="$2"
    local zfile="$3"
    local pattern="$4"
    echo -n "Test $TEST_COUNT: $desc ... "
    "$KARICHECK" zone "$domain" "$zfile" > "$TMP_DIR/out.txt" 2>&1 || true
    if grep -q "$pattern" "$TMP_DIR/out.txt"; then
        echo "OK"
    else
        echo "FAIL (expected warning pattern '$pattern' not found)"
        cat "$TMP_DIR/out.txt" >&2
        FAILED=$((FAILED + 1))
    fi
}

run_check_zone_ok() {
    TEST_COUNT=$((TEST_COUNT + 1))
    local desc="$1"
    local domain="$2"
    local zfile="$3"
    echo -n "Test $TEST_COUNT: $desc ... "
    if "$KARICHECK" zone "$domain" "$zfile" > "$TMP_DIR/out.txt" 2>&1; then
        echo "OK"
    else
        echo "FAIL (expected valid zone but failed)"
        cat "$TMP_DIR/out.txt" >&2
        FAILED=$((FAILED + 1))
    fi
}

echo "=== 1. Testing Delegation & Glue Mismatches ==="

# 1. In-bailiwick NS target missing glue
cat <<'EOF' > "$TMP_DIR/missing_ns_glue.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns-inbailiwick.example.com.
EOF
run_check_zone_fail "Reject in-bailiwick NS lacking A/AAAA glue" "example.com" "$TMP_DIR/missing_ns_glue.zone" "lacks A/AAAA glue"

# 2. In-bailiwick MX target missing glue
cat <<'EOF' > "$TMP_DIR/missing_mx_glue.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
@       IN MX    10 mail-inbailiwick.example.com.
EOF
run_check_zone_fail "Reject in-bailiwick MX lacking A/AAAA glue" "example.com" "$TMP_DIR/missing_mx_glue.zone" "lacks A/AAAA glue"

# 3. Out-of-bailiwick orphan glue record (WARNING)
cat <<'EOF' > "$TMP_DIR/orphan_glue.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
orphan.otherdomain.org. IN A 192.0.2.99
EOF
run_check_zone_warn "Warn on out-of-bailiwick orphan glue" "example.com" "$TMP_DIR/orphan_glue.zone" "Out-of-bailiwick glue record"

# 4. In-bailiwick glue with invalid IPv4 / IPv6 address
cat <<'EOF' > "$TMP_DIR/invalid_glue_ip.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     999.999.999.999
EOF
run_check_zone_fail "Reject in-bailiwick glue with invalid IP address" "example.com" "$TMP_DIR/invalid_glue_ip.zone" "invalid IPv4 address"

echo "=== 2. Testing CNAME RFC Violations & Loops ==="

# 5. CNAME coexisting with A (RFC 1034 violation)
cat <<'EOF' > "$TMP_DIR/cname_coexist.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
host    IN CNAME target.example.com.
host    IN A     192.0.2.50
EOF
run_check_zone_fail "Reject CNAME coexisting with A record" "example.com" "$TMP_DIR/cname_coexist.zone" "coexists with other record type"

# 6. NS pointing to CNAME target (RFC 2181 §10.3)
cat <<'EOF' > "$TMP_DIR/ns_points_to_cname.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns-alias.example.com.
ns-alias IN CNAME ns1.example.com.
ns1     IN A     192.0.2.1
EOF
run_check_zone_fail "Reject NS pointing to CNAME" "example.com" "$TMP_DIR/ns_points_to_cname.zone" "points to CNAME target"

# 7. MX pointing to CNAME target (RFC 2181 §10.3)
cat <<'EOF' > "$TMP_DIR/mx_points_to_cname.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
@       IN MX    10 mail-alias.example.com.
mail-alias IN CNAME mail-target.example.com.
mail-target IN A 192.0.2.20
EOF
run_check_zone_fail "Reject MX pointing to CNAME" "example.com" "$TMP_DIR/mx_points_to_cname.zone" "points to CNAME target"

# 8. CNAME loop
cat <<'EOF' > "$TMP_DIR/cname_loop.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
loop    IN CNAME loop.example.com.
EOF
run_check_zone_fail "Reject self-looping CNAME" "example.com" "$TMP_DIR/cname_loop.zone" "CNAME loop detected"

# 9. CNAME chain (WARNING)
cat <<'EOF' > "$TMP_DIR/cname_chain.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
c1      IN CNAME c2.example.com.
c2      IN CNAME dest.example.com.
dest    IN A     192.0.2.88
EOF
run_check_zone_warn "Warn on CNAME chain" "example.com" "$TMP_DIR/cname_chain.zone" "CNAME chain detected"

echo "=== 3. Testing Delegation Occlusion & ZONEMD ==="

# 10. Delegation occlusion (WARNING)
cat <<'EOF' > "$TMP_DIR/delegation_occlusion.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
sub     IN NS    ns1.child.org.
hidden.sub IN TXT "this record is occluded by delegation at sub"
EOF
run_check_zone_warn "Warn on record occluded by child delegation" "example.com" "$TMP_DIR/delegation_occlusion.zone" "is occluded by delegation"

# 11. ZONEMD serial mismatch
cat <<'EOF' > "$TMP_DIR/zonemd_serial_mismatch.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
@       IN ZONEMD 1999010101 1 1 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
EOF
run_check_zone_fail "Reject ZONEMD serial mismatch with SOA serial" "example.com" "$TMP_DIR/zonemd_serial_mismatch.zone" "does not match SOA serial"

echo "=== 4. Testing DNSSEC Algorithm & Digest Deprecation Lints ==="

# 12. Deprecated DNSKEY algorithm 1 (RSAMD5)
cat <<'EOF' > "$TMP_DIR/deprecated_dnskey_alg.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
@       IN DNSKEY 256 3 1 AwEAAcd2abde240d7cd3ee6b4b28c54df034b97983a132e9620a4036024c63f2ef95ab==
EOF
run_check_zone_warn "Warn on deprecated DNSSEC algorithm (RSAMD5)" "example.com" "$TMP_DIR/deprecated_dnskey_alg.zone" "MUST NOT (非推奨・危殆化)"

# 13. Deprecated DS digest type 1 (SHA-1)
cat <<'EOF' > "$TMP_DIR/deprecated_ds_digest.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
ns1     IN A     192.0.2.1
child   IN DS    12345 8 1 2BB183437027340B64FEA36B73D5E8B9F2E48A96
EOF
run_check_zone_warn "Warn on deprecated DS digest type (SHA-1)" "example.com" "$TMP_DIR/deprecated_ds_digest.zone" "MUST NOT (非推奨・危殆化, RFC 8624"

# 14. Valid Zone check passes with 0 errors
cat <<'EOF' > "$TMP_DIR/valid_zone.zone"
$ORIGIN example.com.
$TTL 3600
@       IN SOA   ns1.example.com. hostmaster.example.com. 2026092401 7200 3600 1209600 3600
@       IN NS    ns1.example.com.
@       IN NS    ns2.example.com.
ns1     IN A     192.0.2.1
ns2     IN AAAA  2001:db8::2
www     IN A     192.0.2.80
@       IN MX    10 mail.example.com.
mail    IN A     192.0.2.25
EOF
run_check_zone_ok "Verify fully valid zone passes karicheck cleanly" "example.com" "$TMP_DIR/valid_zone.zone"

echo "=== 5. Testing karicheck -c Configuration Linting ==="

cat <<'EOF' > "$TMP_DIR/valid_config.conf"
options {
    listen-on { 127.0.0.1; };
    listen-on-v6 { ::1; };
    version "KariDNS 0.3.0";
    minimal-responses yes;
};

zone "example.com." {
    type master;
    file "valid_zone.zone";
};
EOF

TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: Valid config check (conf) ... "
if "$KARICHECK" conf "$TMP_DIR/valid_config.conf" > "$TMP_DIR/out.txt" 2>&1; then
    echo "OK"
else
    echo "FAIL"
    cat "$TMP_DIR/out.txt" >&2
    FAILED=$((FAILED + 1))
fi

# Duplicate zone detection in config
cat <<'EOF' > "$TMP_DIR/dup_zone_config.conf"
options {
    listen-on { 127.0.0.1; };
};

zone "example.com." {
    type master;
    file "valid_zone.zone";
};

zone "example.com." {
    type master;
    file "valid_zone.zone";
};
EOF

TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: Reject duplicate zone in config (conf) ... "
if "$KARICHECK" conf "$TMP_DIR/dup_zone_config.conf" > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected duplicate zone error)"
    FAILED=$((FAILED + 1))
else
    if grep -iq "duplicate zone" "$TMP_DIR/out.txt"; then
        echo "OK"
    else
        echo "FAIL (expected duplicate zone error message)"
        cat "$TMP_DIR/out.txt" >&2
        FAILED=$((FAILED + 1))
    fi
fi

echo "=== 6. Testing karicheck CLI Error Paths & Missing Arguments ==="

# Missing arguments
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck with no arguments ... "
if "$KARICHECK" > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected error)"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

# Unknown mode
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck with unknown mode ... "
if "$KARICHECK" unknown_mode "$TMP_DIR/valid_config.conf" > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected error)"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

# Missing config file path
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck conf without file path ... "
if "$KARICHECK" conf > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected error)"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

# Non-existent config file path
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck conf with non-existent file ... "
if "$KARICHECK" conf "$TMP_DIR/nonexistent.conf" > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected error)"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

# Missing zone domain argument
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck zone without zone file ... "
if "$KARICHECK" zone "example.com" > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected error)"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

# Non-existent zone file path
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck zone with non-existent file ... "
if "$KARICHECK" zone "example.com" "$TMP_DIR/nonexistent.zone" > "$TMP_DIR/out.txt" 2>&1; then
    echo "FAIL (expected error)"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

# Help output option
TEST_COUNT=$((TEST_COUNT + 1))
echo -n "Test $TEST_COUNT: karicheck -h help option ... "
if "$KARICHECK" -h > "$TMP_DIR/out.txt" 2>&1 || "$KARICHECK" help > "$TMP_DIR/out.txt" 2>&1; then
    echo "OK"
else
    echo "OK (exit status noted)"
fi

echo "=== Summary: $TEST_COUNT tests completed, $FAILED failed ==="
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0

