#!/bin/sh
# run_nsec3_nxdomain_perf_test.sh - NSEC3 negative answers must not scan the zone (R-34).
#
# RFC 5155 §7.2.2: an NXDOMAIN answer with DO=1 carries the NSEC3 records that match the closest encloser and
# cover the next closer name and the wildcard. KariDNS finds the covering records by binary search in a sorted
# per-chain index (dns_zone_parser.c build_nsec3_index(), dns_query_engine.c find_covering_nsec3()); before
# that it scanned every record of the zone for each of them, so random-subdomain traffic with DO=1 cost
# O(zone size) per query.
#
# Two zones with the same NAMES (default 30000) A records are signed with dnssec-signzone, one with NSEC and
# one with NSEC3 (no salt, 0 iterations). dnsperf sends DO=1 queries for non-existent names to each zone and
# the NSEC3 rate must be at least half of the NSEC rate (with the linear scan it was about 1 %).
# The DNSSEC proof of one answer is checked too (RFC 5155 §7.2.2: closest encloser match, next closer cover and
# wildcard cover; 2 or 3 NSEC3 RRs, since one RR can cover both names).
#
# Needs dnsperf, dnssec-keygen and dnssec-signzone; SKIP otherwise (CI does not install dnsperf).
# Environment: NAMES (zone size), SECONDS_PER_RUN (dnsperf -l).

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="$BASE_DIR/karidns"
DAG="$BASE_DIR/dag"
PORT=15471
NAMES="${NAMES:-30000}"
SECONDS_PER_RUN="${SECONDS_PER_RUN:-5}"

echo "=== NSEC3 NXDOMAIN performance vs NSEC (R-34) ==="

for t in dnsperf dnssec-keygen dnssec-signzone; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "  [SKIP] $t is not installed"
        echo "=== SKIPPED ==="
        exit 0
    fi
done

[ -x "$KARIDNS" ] && [ -x "$DAG" ] || make -C "$BASE_DIR" karidns dag >/dev/null || exit 1

TMP_DIR="$(mktemp -d /tmp/karidns_n3perf.XXXXXX)"
chmod 755 "$TMP_DIR"
PID=""
cleanup() {
    kari_kill_tree "$PID"
    kari_kill_conf "$TMP_DIR/k.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

# sign ZONE SIGNZONE-OPTIONS...
sign() {
    _z=$1; shift
    {
        echo "\$TTL 300"
        echo "\$ORIGIN $_z."
        echo "@ IN SOA ns1 hostmaster 1 3600 600 86400 60"
        echo "@ IN NS ns1"
        echo "ns1 IN A 192.0.2.1"
        awk -v n="$NAMES" 'BEGIN { for (i = 0; i < n; i++) printf "h%d IN A 192.0.2.%d\n", i, i % 250 + 2 }'
    } > "$TMP_DIR/$_z.zone"
    (cd "$TMP_DIR" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$_z" >/dev/null 2>&1 \
        && dnssec-keygen -q -a ECDSAP256SHA256 "$_z" >/dev/null 2>&1 \
        && dnssec-signzone -q -S -K . "$@" -o "$_z" -f "$_z.signed" "$_z.zone" >/dev/null 2>&1)
    [ -s "$TMP_DIR/$_z.signed" ]
}

if ! sign nsec.test || ! sign nsec3.test -3 - -H 0; then
    echo "  [SKIP] dnssec-signzone failed"
    echo "=== SKIPPED ==="
    exit 0
fi
chmod 644 "$TMP_DIR"/*.signed

cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "nsec.test" { type master; file "$TMP_DIR/nsec.test.signed"; };
zone "nsec3.test" { type master; file "$TMP_DIR/nsec3.test.signed"; };
EOF

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/k.log" 2>&1 &
PID=$!
i=0
while [ $i -lt 100 ]; do
    "$DAG" nsec3.test SOA @127.0.0.1 -p $PORT +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster && break
    sleep 0.2; i=$((i + 1))
done

# Proof check: nx.a.nsec3.test -> closest encloser nsec3.test, next closer a.nsec3.test, wildcard *.nsec3.test
out=$("$DAG" nx.a.nsec3.test A @127.0.0.1 -p $PORT +dnssec +time=2 +tries=1 +nohexdump 2>&1)
n3=$(echo "$out" | awk '$4 == "NSEC3"' | wc -l | tr -d ' ')
if echo "$out" | grep -q "status: NXDOMAIN" && [ "$n3" -ge 2 ] && [ "$n3" -le 3 ]; then
    pass "nx.a.nsec3.test: NXDOMAIN with $n3 NSEC3 RRs"
else
    fail "nx.a.nsec3.test: expected NXDOMAIN with 2 or 3 NSEC3 RRs, got $n3"
fi

# qps ZONE: DO=1 queries for 2000 distinct non-existent names
qps() {
    awk -v z="$1" 'BEGIN { for (i = 0; i < 2000; i++) printf "nx%d.%s A\n", i, z }' > "$TMP_DIR/q.$1"
    dnsperf -s 127.0.0.1 -p $PORT -d "$TMP_DIR/q.$1" -c 4 -l "$SECONDS_PER_RUN" -D > "$TMP_DIR/perf.$1" 2>&1
    if ! grep -q "NXDOMAIN .*(100.00%)" "$TMP_DIR/perf.$1"; then
        fail "$1: not every response was NXDOMAIN"
        sed -n '/Response codes/p' "$TMP_DIR/perf.$1"
    fi
    awk '/Queries per second/ { printf "%d\n", $4 }' "$TMP_DIR/perf.$1"
}
q_nsec=$(qps nsec.test)
q_nsec3=$(qps nsec3.test)
echo "  NXDOMAIN qps with DO=1 ($NAMES names): NSEC $q_nsec, NSEC3 $q_nsec3"
if [ -z "$q_nsec" ] || [ -z "$q_nsec3" ] || [ "$q_nsec" -eq 0 ]; then
    fail "dnsperf gave no rate"
    cat "$TMP_DIR/perf.nsec.test"
elif [ $((q_nsec3 * 2)) -ge "$q_nsec" ]; then
    pass "NSEC3 NXDOMAIN rate is at least 50 % of the NSEC rate"
else
    fail "NSEC3 NXDOMAIN rate $q_nsec3 is below 50 % of the NSEC rate $q_nsec"
fi

kill -0 "$PID" 2>/dev/null || fail "the server exited during the test"
if [ $FAILED -ne 0 ]; then
    echo "--- k.log (tail) ---"; tail -15 "$TMP_DIR/k.log"
    echo "=== FAILED ==="
    exit 1
fi
echo "=== PASSED ==="
exit 0
