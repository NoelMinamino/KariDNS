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
#   oo3.test   NSEC3 Opt-Out (dnssec-signzone -A), whole: the insecure delegations c.b.oo3.test (b.oo3.test is an empty non-terminal made
#              only by it, without an NSEC3 of its own: RFC 5155 7.1) and d.oo3.test, a CNAME to a name a wildcard makes, a wildcard CNAME.
#              Name error below b, DS at c.b and d, referrals to them, no data at b, the CNAMEs: nothing is logged, and the name error, the
#              DS answers and the referrals carry the closest provable encloser proof (RFC 5155 7.2.1: the NSEC3 of the apex, the Opt-Out NSEC3
#              that covers b.oo3.test or d.oo3.test).  With delv (BIND 9.20) the name error and the DS answer under b validate with the zone's
#              KSK as trust anchor ("fully validated").
# "Nothing is logged" is proved with a marker: after the healthy queries one answer of gap.test is made that logs; when its line is in the
# log, the lines of the earlier queries (the same Backend, the same logger) would be there as well.
#
# Needs dnssec-keygen, dnssec-signzone and nsec3hash; SKIP otherwise.  delv is optional (its checks SKIP without it).
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
# oo3.test: NSEC3 Opt-Out; b.oo3.test is an empty non-terminal made only by the insecure delegation c.b.oo3.test
cat > "$W/oo3.test.zone" <<'EOF'
$TTL 300
$ORIGIN oo3.test.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
a IN A 192.0.2.10
c.b IN NS ns.out.example.
d IN NS ns.out.example.
cn IN CNAME x.w.oo3.test.
*.w IN A 192.0.2.20
*.v IN CNAME a.oo3.test.
EOF
( cd "$W" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK oo3.test > oo3.ksk 2>/dev/null &&
             dnssec-keygen -q -a ECDSAP256SHA256 oo3.test >/dev/null 2>&1 ) || { echo "[SKIP] dnssec-keygen failed"; exit 0; }
for k in "$W"/Koo3.test.+*.key; do echo "\$INCLUDE $k" >> "$W/oo3.test.zone"; done
sign() {
    _z=$1; shift
    ( cd "$W" && dnssec-signzone -q -S -K . -O full "$@" -o "$_z" -f "$_z.signed" "$_z.zone" >/dev/null 2>&1 ) ||
        { echo "[SKIP] dnssec-signzone failed ($_z)"; exit 0; }
}
sign gap.test
sign ok.test
sign gap3.test -3 AA11 -H 0
sign ok3.test -3 AA11 -H 0
sign oo3.test -3 - -A -H 0

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
zone "oo3.test" { type master; file "$W/oo3.test.signed"; };
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

# the owner hashes of the NSEC3 RRs in the Authority section of a DO=1 answer (upper case, one per line)
n3_owners() {
    "$DAG" "$1" "$2" @127.0.0.1 -p $PORT +dnssec +norec +nohexdump +tries=1 +time=2 2>/dev/null |
        awk '$4 == "NSEC3" { h = toupper($1); sub(/\..*/, "", h); print h }' | sort -u
}
h3() { nsec3hash - 1 0 "$1" | awk '{ print toupper($1) }'; }

# the healthy zones first: nothing may be said
for z in ok.test ok3.test; do
    [ "$(ask "nx.$z" A)" = NXDOMAIN ] || bad "$z: NXDOMAIN expected"
    [ "$(ask "a.$z" TXT)" = NOERROR ] || bad "$z: NODATA expected"
    [ "$(ask "x.w.$z" A)" = NOERROR ] || bad "$z: wildcard answer expected"
    [ "$(ask "x.w.$z" TXT)" = NOERROR ] || bad "$z: wildcard NODATA expected"
done
# the Opt-Out zone: name error below the ENT, DS at and referrals to the delegations, no data at the ENT, the CNAMEs
[ "$(ask x.b.oo3.test A)" = NXDOMAIN ] || bad "oo3.test: NXDOMAIN below the ENT expected"
[ "$(ask c.b.oo3.test DS)" = NOERROR ] || bad "oo3.test: DS NODATA at c.b expected"
[ "$(ask d.oo3.test DS)" = NOERROR ] || bad "oo3.test: DS NODATA at d expected"
[ "$(ask www.c.b.oo3.test A)" = NOERROR ] || bad "oo3.test: referral to c.b expected"
[ "$(ask www.d.oo3.test A)" = NOERROR ] || bad "oo3.test: referral to d expected"
[ "$(ask b.oo3.test A)" = NOERROR ] || bad "oo3.test: NODATA at the ENT expected"
[ "$(ask cn.oo3.test A)" = NOERROR ] || bad "oo3.test: CNAME to a wildcard name expected"
[ "$(ask z.v.oo3.test A)" = NOERROR ] || bad "oo3.test: wildcard CNAME expected"
# the marker: an answer of gap.test that logs; once its line is there, a line of the queries above would be too
[ "$(ask bb.gap.test A)" = NXDOMAIN ] || bad "gap.test: NXDOMAIN expected"
if ! kari_wait_log "$W/server.log" "\[DNSSEC\] zone 'gap.test'" 10; then
    bad "the marker (a gap of gap.test) was not logged: the check below proves nothing"
elif grep '\[DNSSEC\]' "$W/server.log" | grep -v "zone 'gap.test'"; then
    bad "a whole zone logged a missing proof"
else
    ok "whole NSEC, NSEC3 and NSEC3 Opt-Out zones (NXDOMAIN, NODATA, wildcard answer and NODATA, DS, referrals, CNAMEs): nothing logged before the marker"
fi

# the closest provable encloser proof of the Opt-Out zone (RFC 5155 7.2.1): the NSEC3 of the apex, and the cover of b.oo3.test / d.oo3.test
HA=$(h3 oo3.test)
for q in "x.b.oo3.test A" "c.b.oo3.test DS" "www.c.b.oo3.test A" "d.oo3.test DS" "www.d.oo3.test A"; do
    # shellcheck disable=SC2086
    if n3_owners $q | grep -qx "$HA"; then ok "oo3.test $q: the NSEC3 of the closest provable encloser (the apex)"
    else bad "oo3.test $q: no NSEC3 of the apex: $(n3_owners $q | tr '\n' ' ')"; fi
done
if command -v delv >/dev/null 2>&1; then
    awk '$4 == "DNSKEY" && $5 == 257 { printf "trust-anchors { \"oo3.test.\" static-key %s %s %s \"", $5, $6, $7; for (i = 8; i <= NF; i++) printf "%s", $i; print "\"; };" }' \
        "$W/oo3.test.signed" > "$W/anchor.conf"
    for q in "x.b.oo3.test A" "c.b.oo3.test DS" "d.oo3.test DS" "q.oo3.test A"; do
        # shellcheck disable=SC2086
        out=$(delv @127.0.0.1 -p $PORT -a "$W/anchor.conf" +root=oo3.test. $q 2>&1) || true
        if printf '%s\n' "$out" | grep -q "negative response, fully validated"; then ok "delv: $q: fully validated"
        else bad "delv: $q: $(printf '%s\n' "$out" | grep '^;' | tr '\n' ' ' | cut -c1-200)"; fi
    done
else
    echo "[SKIP] delv is not installed: the Opt-Out proofs are not validated"
fi

# the gaps: the answers are unchanged (status), and one line per zone
for n in 1 2; do   # (the marker above was the first)
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
# and at the end, after every line of the gaps came: still nothing of the whole zones
if grep '\[DNSSEC\]' "$W/server.log" | grep -v "zone 'gap.test'\|zone 'gap3.test'"; then bad "a whole zone logged a missing proof (at the end)"
else ok "at the end: lines of gap.test and gap3.test only"; fi
grep -i "AddressSanitizer\|runtime error" "$W/server.log" && bad "sanitizer report"

echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
