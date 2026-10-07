#!/bin/sh
# ==============================================================================
# tests/run_zone_type_secondary_test.sh - secondary zone refresh, retry and expiry
# ==============================================================================
# RFC 1034 §4.3.5: a secondary loads the zone by AXFR, checks the primary's SOA
# serial every REFRESH seconds (every RETRY seconds while the check fails) and
# discards its copy when no check succeeded for EXPIRE seconds. With
# "serve-stale no" the expired zone is answered with SERVFAIL and EDE 24 "Invalid
# Data" (RFC 8914 §4.25, R-18); with the default "serve-stale yes" the stale data
# is still served, marked with EDE 3 "Stale Answer" (RFC 8914 §4.4).
#
# The primary's zone has a single NS that is also the SOA MNAME, so the primary
# sends no NOTIFY (RFC 1996 §3.2): the new serial must reach the secondary by the
# REFRESH timer alone. Also checks karicheck's acceptance of the zone types.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
. "$DIR/lib_proc.sh"

for b in karicheck karidns dag; do
    [ -x "$ROOT/$b" ] || make -C "$ROOT" "$b"
done
KARICHECK="$ROOT/karicheck"
KARIDNS="$ROOT/karidns"
DAG="$ROOT/dag"

W="$(mktemp -d /tmp/zone_secondary.XXXXXX)"
chmod 755 "$W"
PPORT=$((25000 + $$ % 5000))
SPORT=$((PPORT + 1))   # secondary, serve-stale no
STALE_PORT=$((PPORT + 2))   # secondary, serve-stale yes (default)
PRIMARY_PID=""
SECONDARY_PID=""
STALE_PID=""

cleanup() {
    [ -n "$PRIMARY_PID" ] && kari_kill_tree "$PRIMARY_PID"
    [ -n "$SECONDARY_PID" ] && kari_kill_tree "$SECONDARY_PID"
    [ -n "$STALE_PID" ] && kari_kill_tree "$STALE_PID"
    kari_kill_conf "$W/primary.conf" "$W/secondary.conf" "$W/stale.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    [ -f "$W/q.txt" ] && sed 's/^/    /' "$W/q.txt"
    exit 1
}

# --- karicheck: zone types ----------------------------------------------------
cat > "$W/type_secondary.conf" <<EOF
zone "example2.test" {
    type secondary;
    masters { 192.0.2.1; };
};
EOF
cat > "$W/type_invalid.conf" <<EOF
zone "example3.test" {
    type invalid_zone_type;
    file "$W/none.zone";
};
EOF
"$KARICHECK" conf "$W/type_secondary.conf" > "$W/kc.txt" 2>&1 || { cat "$W/kc.txt"; fail "karicheck rejected type secondary"; }
if "$KARICHECK" conf "$W/type_invalid.conf" > "$W/kc.txt" 2>&1; then
    cat "$W/kc.txt"
    fail "karicheck accepted an unknown zone type"
fi
echo "[OK] karicheck: type secondary accepted, unknown type rejected"

# --- primary and secondary ----------------------------------------------------
# REFRESH 2 s, RETRY 1 s, EXPIRE 8 s
write_zone() { # serial [extra record]
    cat > "$W/sec.zone.tmp" <<EOF
\$ORIGIN sec.test.
\$TTL 60
@    IN SOA ns1 hostmaster $1 2 1 8 60
@    IN NS  ns1
ns1  IN A   192.0.2.1
www  IN A   192.0.2.80
${2:-}
EOF
    mv "$W/sec.zone.tmp" "$W/sec.zone"
}
write_zone 1

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
cat > "$W/primary.conf" <<EOF
options { port $PPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "sec.test" { type primary; file "$W/sec.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$W/secondary.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; serve-stale no; $USER_OPT };
zone "sec.test" { type secondary; masters { 127.0.0.1 port $PPORT; }; };
EOF
cat > "$W/stale.conf" <<EOF
options { port $STALE_PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "sec.test" { type secondary; masters { 127.0.0.1 port $PPORT; }; };
EOF
for c in primary secondary stale; do
    "$KARICHECK" conf "$W/$c.conf" > "$W/kc.txt" 2>&1 || { cat "$W/kc.txt"; fail "karicheck rejected $c.conf"; }
done

q() { # port name type
    "$DAG" @127.0.0.1 -p "$1" "$2" "$3" +nohexdump +norec +timeout=1 +tries=1 > "$W/q.txt" 2>&1 || true
}
# soa_serial <port>: serial in the SOA answer, empty if none
soa_serial() {
    q "$1" sec.test SOA
    awk '$4 == "SOA" && $1 == "sec.test." { print $7 }' "$W/q.txt"
}
# wait_serial <port> <serial> <seconds>
wait_serial() {
    i=0
    while [ "$i" -lt $(($3 * 5)) ]; do
        [ "$(soa_serial "$1")" = "$2" ] && return 0
        sleep 0.2
        i=$((i + 1))
    done
    return 1
}

"$KARIDNS" -f "$W/primary.conf" > "$W/primary.log" 2>&1 &
PRIMARY_PID=$!
wait_serial "$PPORT" 1 10 || { cat "$W/primary.log"; fail "primary did not start"; }

T0=$(date +%s)
"$KARIDNS" -f "$W/secondary.conf" > "$W/secondary.log" 2>&1 &
SECONDARY_PID=$!
"$KARIDNS" -f "$W/stale.conf" > "$W/stale.log" 2>&1 &
STALE_PID=$!

# 1. initial AXFR
wait_serial "$SPORT" 1 10 || { cat "$W/secondary.log"; fail "secondary did not load the zone by AXFR"; }
wait_serial "$STALE_PORT" 1 10 || { cat "$W/stale.log"; fail "secondary (serve-stale) did not load the zone by AXFR"; }
q "$SPORT" www.sec.test A
grep -q "status: NOERROR" "$W/q.txt" && grep -q "flags: qr aa;" "$W/q.txt" &&
    grep -E -q "^www\.sec\.test\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.80$" "$W/q.txt" ||
    fail "secondary answer for www.sec.test A after the transfer"
echo "[OK] secondary loaded serial 1 by AXFR ($(( $(date +%s) - T0 )) s) and answers authoritatively"

# 2. serial bump on the primary, picked up by the REFRESH timer (no NOTIFY)
write_zone 2 "new  IN A   192.0.2.81"
kill -HUP "$PRIMARY_PID"
wait_serial "$PPORT" 2 10 || fail "primary did not reload serial 2"
T1=$(date +%s)
wait_serial "$SPORT" 2 10 || { cat "$W/secondary.log"; fail "secondary did not refresh to serial 2"; }
wait_serial "$STALE_PORT" 2 10 || { cat "$W/stale.log"; fail "secondary (serve-stale) did not refresh to serial 2"; }
q "$SPORT" new.sec.test A
grep -E -q "^new\.sec\.test\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.81$" "$W/q.txt" ||
    fail "record added with serial 2 missing on the secondary"
echo "[OK] secondary refreshed to serial 2 $(( $(date +%s) - T1 )) s after the primary reload (REFRESH 2 s)"

# 3. primary gone: answers continue until EXPIRE, then SERVFAIL + EDE 24
kari_kill_tree "$PRIMARY_PID"
PRIMARY_PID=""
T2=$(date +%s)
q "$SPORT" www.sec.test A
grep -q "status: NOERROR" "$W/q.txt" || fail "secondary stopped answering right after the primary went away (EXPIRE is 8 s)"
grep -q "^; EDE:" "$W/q.txt" && fail "EDE before the zone expired"
i=0
while :; do
    q "$SPORT" www.sec.test A
    grep -q "status: SERVFAIL" "$W/q.txt" && break
    grep -q "status: NOERROR" "$W/q.txt" || fail "unexpected answer while waiting for expiry"
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "zone did not expire within 20 s of the primary's shutdown"
    sleep 0.2
done
T3=$(date +%s)
grep -q "^; EDE: 24 (Invalid Data): (Zone expired (SOA EXPIRE exceeded))$" "$W/q.txt" || fail "expired zone: EDE 24 missing"
grep -q "flags: qr;" "$W/q.txt" || fail "expired zone: SERVFAIL must not have AA"
# the last successful check was at most REFRESH (2 s) before the shutdown
[ $((T3 - T2)) -ge 5 ] || fail "zone expired $((T3 - T2)) s after the shutdown, earlier than EXPIRE (8 s) minus REFRESH (2 s) allows"
echo "[OK] secondary answered SERVFAIL + EDE 24 $((T3 - T2)) s after the primary went away (EXPIRE 8 s)"

# serve-stale yes (default): the same expired zone is still answered, marked stale
q "$STALE_PORT" www.sec.test A
grep -q "status: NOERROR" "$W/q.txt" && grep -q "flags: qr aa;" "$W/q.txt" &&
    grep -E -q "^www\.sec\.test\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.80$" "$W/q.txt" ||
    fail "serve-stale: expired zone not answered from the stale data"
grep -q "^; EDE: 3 (Stale Answer): (Stale Answer (Zone EXPIRED))$" "$W/q.txt" || fail "serve-stale: EDE 3 missing"
echo "[OK] serve-stale (default): expired zone answered from stale data with EDE 3"

echo "[PASS] secondary zone refresh / expiry tests passed"
exit 0
