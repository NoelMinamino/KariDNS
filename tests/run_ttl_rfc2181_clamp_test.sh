#!/bin/sh
# TTL range of zone files and the clamp on the wire.
#   - BIND 9.20 ARM 3.5.5.4: "Valid TTLs are of the range 0-2147483647 seconds".  A zone file TTL above that (numeric or unit-suffixed) is an
#     error since the BIND compatibility batch 1 (it used to be clamped); the zone is not loaded (SERVFAIL) and karicheck says why.
#   - RFC 8767 §4 (amends RFC 2181 §8): a TTL with the high bit set is a positive number, 2147483647 at most on the wire (O-14).  A record at
#     the limit is served as it is, and a SOA minimum above it (the SOA fields accept up to 4294967295) is clamped in negative answers; the
#     AXFR/IXFR receive path clamps the same way (unit test in test_zone_parser_paths.c).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
PORT=$(kari_port 0 10053)
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"
KARICHECK="$ROOT/karicheck"

[ -x "$ROOT/karidns" ] && [ -x "$ROOT/dag" ] && [ -x "$KARICHECK" ] || {
    echo "[*] Building targets..."
    make -C "$ROOT" karidns dag karicheck
}

CONF="$DIR/ttl_clamp_test.conf"
ZONE="$DIR/zones/ttl_clamp_test.zone"
BADZONE="$DIR/zones/ttl_range_bad_test.zone"
BADUNIT="$DIR/zones/ttl_range_badunit_test.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE"
$ORIGIN ttlclamp.test.
$TTL 2147483647
@   IN SOA  ns1.ttlclamp.test. hostmaster.ttlclamp.test. (
            2026082401
            4000000000 ; refresh
            4000000000 ; retry
            4000000000 ; expire
            4000000000 ; minimum
            )
@   IN NS   ns1.ttlclamp.test.
ns1 IN A    127.0.0.1
www 2147483647 IN A 192.0.2.1
unit 3550w5d IN A 192.0.2.2
EOF

cat << 'EOF' > "$BADZONE"
$ORIGIN ttlrange.test.
$TTL 3600
@   IN SOA  ns1.ttlrange.test. hostmaster.ttlrange.test. 1 7200 3600 1209600 300
@   IN NS   ns1.ttlrange.test.
ns1 IN A    127.0.0.1
www 4000000000 IN A 192.0.2.1
EOF

cat << 'EOF' > "$BADUNIT"
$ORIGIN ttlunit.test.
$TTL 46296d17m
@   IN SOA  ns1.ttlunit.test. hostmaster.ttlunit.test. 1 7200 3600 1209600 300
@   IN NS   ns1.ttlunit.test.
ns1 IN A    127.0.0.1
EOF

cat << EOF > "$CONF"
options {
    port ${PORT};
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
zone "ttlclamp.test" {
    type master;
    file "$ZONE";
};
zone "ttlrange.test" {
    type master;
    file "$BADZONE";
};
zone "ttlunit.test" {
    type master;
    file "$BADUNIT";
};
EOF

echo "[*] Starting KariDNS on port ${PORT}..."
$BIN -f -c "$CONF" > "$DIR/server_ttl_clamp.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    echo "[*] Cleaning up test processes..."
    kari_kill_tree "${SERVER_PID:-}"
    rm -f "$CONF" "$ZONE" "$BADZONE" "$BADUNIT" "$DIR/server_ttl_clamp.log"
}
trap cleanup EXIT INT TERM

sleep 2

# 1. A record whose TTL is exactly 2147483647 is served as it is
echo "[*] Querying www.ttlclamp.test (TTL 2147483647)..."
WWW_OUT=$($DAG www.ttlclamp.test A @127.0.0.1 -p ${PORT})
echo "$WWW_OUT"
if ! echo "$WWW_OUT" | grep -q "www.ttlclamp.test.*2147483647.*IN.*A.*192.0.2.1"; then
    echo "[FAIL] TTL 2147483647 was not served as 2147483647!"
    exit 1
fi

# 2. 3550w5d = 2147472000: unit-suffixed value inside the range
echo "[*] Querying unit.ttlclamp.test (unit suffixed 3550w5d TTL)..."
UNIT_OUT=$($DAG unit.ttlclamp.test A @127.0.0.1 -p ${PORT})
echo "$UNIT_OUT"
if ! echo "$UNIT_OUT" | grep -q "unit.ttlclamp.test.*2147472000.*IN.*A.*192.0.2.2"; then
    echo "[FAIL] Unit-suffixed TTL 3550w5d (2147472000) not served!"
    exit 1
fi

# 3. NXDOMAIN: the negative TTL comes from the SOA minimum (4000000000 in the file) and is clamped to 2147483647 (RFC 8767 §4)
echo "[*] Querying NXDOMAIN nonexist.ttlclamp.test..."
NX_OUT=$($DAG nonexist.ttlclamp.test A @127.0.0.1 -p ${PORT})
echo "$NX_OUT"
if ! echo "$NX_OUT" | grep -q "ttlclamp.test.*2147483647.*IN.*SOA"; then
    echo "[FAIL] Negative response SOA TTL was NOT clamped to 2147483647!"
    exit 1
fi

# 4. A zone file TTL above 2147483647 is an error: the zone is not loaded (SERVFAIL) and the log says why
for z in www.ttlrange.test www.ttlunit.test; do
    echo "[*] Querying $z (zone with a TTL above 2147483647)..."
    BAD_OUT=$($DAG $z A @127.0.0.1 -p ${PORT} || true)
    if ! echo "$BAD_OUT" | grep -q "status: SERVFAIL"; then
        echo "[FAIL] $z: expected SERVFAIL for a zone with a TTL above 2147483647:"
        echo "$BAD_OUT"
        exit 1
    fi
done
if ! grep -q "Invalid TTL (expected 0-2147483647" "$DIR/server_ttl_clamp.log" || ! grep -q 'Invalid $TTL value (expected 0-2147483647' "$DIR/server_ttl_clamp.log"; then
    echo "[FAIL] the server log does not give the reason:"
    tail -20 "$DIR/server_ttl_clamp.log"
    exit 1
fi

# 5. karicheck gives the same verdict
for f in "$BADZONE:ttlrange.test:Invalid TTL" "$BADUNIT:ttlunit.test:Invalid \$TTL value"; do
    file=${f%%:*}; rest=${f#*:}; dom=${rest%%:*}; want=${rest#*:}
    if OUT=$($KARICHECK zone "$dom" "$file" 2>&1); then
        echo "[FAIL] karicheck accepted $file"; echo "$OUT"; exit 1
    fi
    echo "$OUT" | grep -q "$want" || { echo "[FAIL] karicheck message for $file:"; echo "$OUT"; exit 1; }
done

echo "[PASS] TTLs inside 0-2147483647 are served, SOA minimum above it is clamped on the wire, a zone file TTL above it is rejected (BIND 9.20 ARM 3.5.5.4, RFC 8767 §4)"
exit 0
