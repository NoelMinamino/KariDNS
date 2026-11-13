#!/bin/sh
# run_dnssec_denial_gap_test.sh - a signed zone whose denial chain has a gap is logged (0.7, audit Low "NSEC/NSEC3 proof missing").
#
# RFC 4035 §3.1.3 (NSEC) and RFC 5155 §7.2 (NSEC3) say which proofs a negative or wildcard answer carries.  When the zone does not hold one
# (a record removed from a signed file) the server answers as before, without it, and says so once a minute per zone: "[DNSSEC] zone 'z':
# no <proof> for '<name>' ...", category dnssec, warning (docs/karidns.md, logging categories).
#
# Zones (dnssec-signzone):
#   gap.test   NSEC, the NSEC of b.gap.test removed: NXDOMAIN for bb.gap.test (no covering NSEC) and NODATA for b.gap.test (no NSEC
#              at the name); five queries give one line (the minute of the zone).
#   gap3.test  NSEC3, the NSEC3 of the apex removed: NXDOMAIN for x.gap3.test (no NSEC3 of the closest encloser).
#   ok.test, ok3.test  the same zones whole (NSEC, NSEC3) with a wildcard: NXDOMAIN, NODATA, wildcard answer and wildcard NODATA log nothing.
#
# Needs dnssec-keygen, dnssec-signzone and nsec3hash; SKIP otherwise.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"

echo "=== DNSSEC: a gap in the denial chain is logged (RFC 4035 3.1.3, RFC 5155 7.2) ==="
for t in dnssec-keygen dnssec-signzone nsec3hash; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] $t is not installed"
        exit 0
    fi
done
[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PORT=$(kari_port 0 15541)
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-denialgap.XXXXXX")
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT='user "nobody"; group "nobody";'
SERVER_PID=""
PASS=0
FAIL=0

cleanup() {
    set +e
    kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$W/k.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

ok() { PASS=$((PASS + 1)); echo "[PASS] $*"; }
bad() { FAIL=$((FAIL + 1)); echo "[FAIL] $*"; }

for z in gap.test gap3.test ok.test ok3.test; do
    cat > "$W/$z.zone" <<EOF
\$TTL 300
\$ORIGIN $z.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
a IN A 192.0.2.10
b IN A 192.0.2.11
c IN A 192.0.2.12
*.w IN A 192.0.2.20
EOF
    ( cd "$W" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$z" >/dev/null 2>&1 &&
                 dnssec-keygen -q -a ECDSAP256SHA256 "$z" >/dev/null 2>&1 ) || { echo "[SKIP] dnssec-keygen failed"; exit 0; }
    for k in "$W"/K"$z".+*.key; do echo "\$INCLUDE $k" >> "$W/$z.zone"; done
done
sign() {
    _z=$1; shift
    ( cd "$W" && dnssec-signzone -q -S -K . -O full "$@" -o "$_z" -f "$_z.signed" "$_z.zone" >/dev/null 2>&1 ) ||
        { echo "[SKIP] dnssec-signzone failed ($_z)"; exit 0; }
}
sign gap.test
sign ok.test
sign gap3.test -3 AA11 -H 0
sign ok3.test -3 AA11 -H 0

# the gaps: the NSEC of b.gap.test, the NSEC3 of the apex of gap3.test (the RRSIGs stay: they cover nothing then)
awk '!($1 == "b.gap.test." && $4 == "NSEC")' "$W/gap.test.signed" > "$W/gap.test.cut"
H=$(nsec3hash AA11 1 0 gap3.test | awk '{ print toupper($1) }')
[ -n "$H" ] || { echo "[SKIP] nsec3hash printed nothing"; exit 0; }
awk -v o="$H.GAP3.TEST." '!(toupper($1) == o && $4 == "NSEC3")' "$W/gap3.test.signed" > "$W/gap3.test.cut"
[ "$(wc -l < "$W/gap.test.cut")" -lt "$(wc -l < "$W/gap.test.signed")" ] || { bad "the NSEC of b.gap.test was not removed"; exit 1; }
[ "$(wc -l < "$W/gap3.test.cut")" -lt "$(wc -l < "$W/gap3.test.signed")" ] || { bad "the NSEC3 of the apex of gap3.test was not removed"; exit 1; }
chmod 644 "$W"/*.cut "$W"/*.signed

cat > "$W/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "gap.test" { type master; file "$W/gap.test.cut"; };
zone "gap3.test" { type master; file "$W/gap3.test.cut"; };
zone "ok.test" { type master; file "$W/ok.test.signed"; };
zone "ok3.test" { type master; file "$W/ok3.test.signed"; };
EOF

"$BIN" -f "$W/k.conf" > "$W/server.log" 2>&1 &
SERVER_PID=$!
i=0
until "$DAG" ok3.test SOA @127.0.0.1 -p $PORT +short +nohexdump +tries=1 +time=1 2>/dev/null | grep -q hostmaster; do
    i=$((i + 1)); [ $i -le 40 ] || { tail -n 30 "$W/server.log"; bad "karidns did not start"; exit 1; }
    sleep 0.25
done

# ask NAME TYPE: the status of a DO=1 answer
ask() {
    "$DAG" "$1" "$2" @127.0.0.1 -p $PORT +dnssec +norec +nohexdump +tries=1 +time=2 2>/dev/null | sed -n 's/.*status: \([A-Z]*\),.*/\1/p'
}

# the healthy zones first: nothing may be said
for z in ok.test ok3.test; do
    [ "$(ask "nx.$z" A)" = NXDOMAIN ] || bad "$z: NXDOMAIN expected"
    [ "$(ask "a.$z" TXT)" = NOERROR ] || bad "$z: NODATA expected"
    [ "$(ask "x.w.$z" A)" = NOERROR ] || bad "$z: wildcard answer expected"
    [ "$(ask "x.w.$z" TXT)" = NOERROR ] || bad "$z: wildcard NODATA expected"
done
sleep 0.5
if grep -q '\[DNSSEC\]' "$W/server.log"; then
    grep '\[DNSSEC\]' "$W/server.log"
    bad "a whole zone logged a missing proof"
else
    ok "whole NSEC and NSEC3 zones (NXDOMAIN, NODATA, wildcard answer, wildcard NODATA): nothing logged"
fi

# the gaps: the answers are unchanged (status), and one line per zone
for n in 1 2 3; do
    [ "$(ask bb.gap.test A)" = NXDOMAIN ] || bad "gap.test: NXDOMAIN expected"
done
[ "$(ask b.gap.test TXT)" = NOERROR ] || bad "gap.test: NODATA expected"
[ "$(ask a.gap.test TXT)" = NOERROR ] || bad "gap.test: NODATA expected"
[ "$(ask x.gap3.test A)" = NXDOMAIN ] || bad "gap3.test: NXDOMAIN expected"
[ "$(ask y.gap3.test A)" = NXDOMAIN ] || bad "gap3.test: NXDOMAIN expected"
if kari_wait_log "$W/server.log" "\[DNSSEC\] zone 'gap3.test'" 5 && kari_wait_log "$W/server.log" "\[DNSSEC\] zone 'gap.test'" 5; then
    ok "both gaps logged"
else
    bad "a gap was not logged"
fi
grep -q "\[DNSSEC\] zone 'gap.test': no NSEC that covers the name (RFC 4035 3.1.3.2) for 'bb.gap.test': the answer goes out without that proof" "$W/server.log" &&
    ok "gap.test: the proof and the name are named" || bad "gap.test: the line is not the expected one"
grep -q "\[DNSSEC\] zone 'gap3.test': no NSEC3 that matches the closest encloser (RFC 5155 7.2.2) for 'gap3.test'" "$W/server.log" &&
    ok "gap3.test: the proof and the name are named" || bad "gap3.test: the line is not the expected one"
sleep 0.5
n1=$(grep -c "\[DNSSEC\] zone 'gap.test'" "$W/server.log" || true)
n3=$(grep -c "\[DNSSEC\] zone 'gap3.test'" "$W/server.log" || true)
[ "$n1" = 1 ] && [ "$n3" = 1 ] && ok "one line per zone for five and two answers without the proof" ||
    bad "lines: gap.test $n1, gap3.test $n3 (1 each expected)"
grep -q "KariDNS [0-9]* - - \[DNSSEC\]" "$W/server.log" && ok "at the default channel (default_syslog: warning passes)" ||
    bad "the line did not reach the default channel"
grep -i "AddressSanitizer\|runtime error" "$W/server.log" && bad "sanitizer report"

echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
