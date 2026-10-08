#!/bin/sh
set -e

# ==============================================================================
# EDNS EXPIRE option (RFC 7314)
#
#   primary (PORT1) -> secondary A (PORT2) -> secondary B (PORT3)
#
# 1. §3.1: the primary returns the SOA EXPIRE field (also for non-SOA queries and
#    from the wire cache); §3.3: no EXPIRE for a zone the server is not
#    authoritative for; no EXPIRE without the option in the query.
# 2. §3.2: a secondary returns the remaining time of its expire timer.
# 3. §4: after the primary goes away, B keeps following A's timer instead of
#    restarting SOA EXPIRE on every transfer from A, so both zones expire together.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

[ -x "$KARIDNS" ] && [ -x "$DAG" ] || make -C "$ROOT_DIR" karidns dag

PORT1=$((27000 + $$ % 3000))
PORT2=$((PORT1 + 1))
PORT3=$((PORT1 + 2))
TMP_DIR="/tmp/karidns_expire_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
FAILED=0
PID1=""; PID2=""; PID3=""

cleanup() {
    for p in $PID1 $PID2 $PID3; do kill -9 "$p" 2>/dev/null || true; done
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

pass() { echo "  [OK] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }

# SOA: refresh 2, retry 1, expire 20
cat << 'EOF' > "$TMP_DIR/exp.zone"
$TTL 300
$ORIGIN exp.example.com.
@       IN  SOA ns1.exp.example.com. hostmaster.exp.example.com. (
            2026092801 ; Serial
            2 1 20 300
)
@       IN  NS  ns1.exp.example.com.
ns1     IN  A   127.0.0.1
www     IN  A   192.0.2.10
EOF

cat << EOF > "$TMP_DIR/primary.conf"
options { port $PORT1; bind-address { 127.0.0.1; }; $USER_OPT };
zone "exp.example.com" {
    type master;
    file "$TMP_DIR/exp.zone";
    allow-transfer { 127.0.0.1; };
};
EOF

cat << EOF > "$TMP_DIR/secA.conf"
options { port $PORT2; bind-address { 127.0.0.1; }; serve-stale no; $USER_OPT };
zone "exp.example.com" {
    type slave;
    masters { 127.0.0.1 port $PORT1; };
    allow-transfer { 127.0.0.1; };
};
EOF

cat << EOF > "$TMP_DIR/secB.conf"
options { port $PORT3; bind-address { 127.0.0.1; }; serve-stale no; $USER_OPT };
zone "exp.example.com" {
    type slave;
    masters { 127.0.0.1 port $PORT2; };
};
EOF

# EXPIRE value in the OPT pseudosection ("" when absent)
expire_of() {
    "$DAG" @127.0.0.1 -p "$1" $2 +expire +nocookie +norec +timeout=2 2>/dev/null |
        sed -n 's/.*EXPIRE: \([0-9]*\) (.*/\1/p' | head -1
}
status_of() {
    "$DAG" @127.0.0.1 -p "$1" $2 +norec +timeout=2 2>/dev/null |
        sed -n 's/.*status: \([A-Z]*\),.*/\1/p' | head -1
}
start() {
    "$KARIDNS" -f "$TMP_DIR/$1.conf" > "$TMP_DIR/$1.log" 2>&1 &
    eval "$2=\$!"
    sleep 1
    eval "kill -0 \$$2" 2>/dev/null || { echo "[FAIL] $1 failed to start"; cat "$TMP_DIR/$1.log"; exit 1; }
}
wait_zone() {
    for i in $(seq 1 30); do
        [ "$("$DAG" @127.0.0.1 -p "$1" www.exp.example.com A +short +norec 2>/dev/null)" = "192.0.2.10" ] && return 0
        sleep 0.5
    done
    return 1
}

start primary PID1
start secA PID2
wait_zone "$PORT2" || { echo "[FAIL] secondary A did not transfer the zone"; cat "$TMP_DIR/secA.log"; exit 1; }
start secB PID3
wait_zone "$PORT3" || { echo "[FAIL] secondary B did not transfer the zone"; cat "$TMP_DIR/secB.log"; exit 1; }

echo "=== 1. Primary (RFC 7314 §3.1, §3.3) ==="
V=$(expire_of "$PORT1" "exp.example.com SOA")
[ "$V" = "20" ] && pass "SOA query: EXPIRE $V (SOA EXPIRE)" || fail "SOA query: EXPIRE '$V', expected 20"
V=$(expire_of "$PORT1" "www.exp.example.com A")
[ "$V" = "20" ] && pass "A query: EXPIRE $V" || fail "A query: EXPIRE '$V', expected 20"
V=$(expire_of "$PORT1" "www.exp.example.com A")
[ "$V" = "20" ] && pass "A query again (wire cache): EXPIRE $V" || fail "A query again: EXPIRE '$V', expected 20"
V=$(expire_of "$PORT1" "www.other.example A")
[ -z "$V" ] && pass "not authoritative: no EXPIRE" || fail "not authoritative: EXPIRE '$V' returned"
if "$DAG" @127.0.0.1 -p "$PORT1" exp.example.com SOA +nocookie +norec 2>/dev/null | grep -q "EXPIRE"; then
    fail "EXPIRE returned without the option in the query"
else
    pass "no EXPIRE without the option in the query"
fi
# AXFR output (like dig) has no OPT pseudosection: look for the option in the hexdump of the
# first response message: code 9, length 4, value 20.
AXFR_HEX=$("$DAG" @127.0.0.1 -p "$PORT1" exp.example.com AXFR +expire +nocookie +qr 2>/dev/null |
    awk '/^Response message 1/ {on=1; next} on && /^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]  / {print substr($0, 7, 49)} on && /^$/ {exit}' |
    tr -s ' \n' ' ')
case "$AXFR_HEX" in
    *"00 09 00 04 00 00 00 14"*) pass "AXFR: EXPIRE 20 in the first message" ;;
    *) fail "AXFR: EXPIRE option not found in the first message" ;;
esac

echo "=== 2. Secondary (§3.2) ==="
V=$(expire_of "$PORT2" "exp.example.com SOA")
if [ -n "$V" ] && [ "$V" -ge 15 ] && [ "$V" -le 20 ]; then pass "secondary A: EXPIRE $V (timer)"; else fail "secondary A: EXPIRE '$V', expected 15..20"; fi

echo "=== 3. Chained secondaries after the primary stops (§4) ==="
kill -9 "$PID1" 2>/dev/null || true; PID1=""
sleep 8
VA=$(expire_of "$PORT2" "exp.example.com SOA")
VB=$(expire_of "$PORT3" "exp.example.com SOA")
echo "  A=$VA B=$VB (SOA EXPIRE 20, primary gone for ~8s)"
if [ -n "$VA" ] && [ "$VA" -le 13 ]; then pass "A counts down"; else fail "A timer '$VA', expected <= 13"; fi
if [ -n "$VB" ] && [ -n "$VA" ] && [ "$VB" -le $((VA + 1)) ]; then
    pass "B follows A's timer instead of restarting SOA EXPIRE"
else
    fail "B timer '$VB' is not bounded by A's '$VA'"
fi

sleep $((VA + 3))
SA=$(status_of "$PORT2" "www.exp.example.com A")
SB=$(status_of "$PORT3" "www.exp.example.com A")
[ "$SA" = "SERVFAIL" ] && pass "A expired (SERVFAIL)" || fail "A status '$SA', expected SERVFAIL"
[ "$SB" = "SERVFAIL" ] && pass "B expired together with A (SERVFAIL)" || fail "B status '$SB', expected SERVFAIL"

if [ "$FAILED" -ne 0 ]; then
    echo "--- secondary A log ---"; cat "$TMP_DIR/secA.log"
    echo "--- secondary B log ---"; cat "$TMP_DIR/secB.log"
    echo "[FAIL] EDNS EXPIRE tests failed"
    exit 1
fi
echo "[PASS] EDNS EXPIRE (RFC 7314) tests passed"
exit 0
