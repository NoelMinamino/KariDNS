#!/bin/sh
# RFC 2136 §3.1.2: a secondary forwards an UPDATE toward the primary (§6). KariDNS does not
# forward, so an UPDATE sent to a secondary zone is refused (REFUSED, EDE 18 "Prohibited")
# whether or not the client matches allow-update; the zone stays unchanged on both servers.
# The same UPDATE sent to the primary is applied and reaches the secondary.
# An UPDATE whose zone section names no zone of the server gets NOTAUTH (§3.1.1).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PPORT=15471
SPORT=15472
KEY="hmac-sha256:upd-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-updsec.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
PRIMARY_PID=""
SECONDARY_PID=""

cleanup() {
    kari_kill_tree "$PRIMARY_PID" "$SECONDARY_PID"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    for f in "$W"/out.txt "$W"/primary.log "$W"/secondary.log; do
        [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }
    done
    exit 1
}

check_asan_log() {
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$W/primary.log" "$W/secondary.log"; then
        fail "sanitizer report in a server log"
    fi
}

cat > "$W/sec.test.zone" <<'EOF'
$TTL 300
$ORIGIN sec.test.
@ IN SOA ns1.sec.test. hostmaster.sec.test. ( 7 3600 600 86400 60 )
@ IN NS ns1.sec.test.
ns1 IN A 192.0.2.1
EOF

cat > "$W/primary.conf" <<EOF
options { port $PPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
key "upd-key" { algorithm hmac-sha256; secret "C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="; };
zone "sec.test" {
    type master;
    file "$W/sec.test.zone";
    allow-update { 127.0.0.1; key upd-key; };
    allow-transfer { 127.0.0.1; };
    also-notify { 127.0.0.1 port $SPORT; };
};
EOF

# allow-update on a secondary only produces a load-time warning; it must not open the zone to updates.
cat > "$W/secondary.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; send-extended-errors yes; $USER_OPT };
key "upd-key" { algorithm hmac-sha256; secret "C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="; };
zone "sec.test" {
    type slave;
    masters { 127.0.0.1 port $PPORT; };
    allow-update { 127.0.0.1; key upd-key; };
    allow-notify { 127.0.0.1; };
};
EOF

"$BIN" -f "$W/primary.conf" > "$W/primary.log" 2>&1 &
PRIMARY_PID=$!
"$BIN" -f "$W/secondary.conf" > "$W/secondary.log" 2>&1 &
SECONDARY_PID=$!

# serial PORT: SOA serial as served on PORT (empty when not answering)
serial() {
    "$DAG" sec.test SOA @127.0.0.1 -p "$1" +short +nohexdump 2>/dev/null | awk '{print $3}'
}
a_of() {
    "$DAG" "$1" A @127.0.0.1 -p "$2" +short +nohexdump 2>/dev/null
}

i=0
while [ "$(serial $SPORT)" != "7" ]; do
    i=$((i + 1))
    [ $i -le 40 ] || fail "secondary did not transfer sec.test (serial $(serial $SPORT))"
    sleep 0.5
done
echo "[OK] secondary serves sec.test serial 7"
grep -q "has 'allow-update' configured" "$W/secondary.log" || fail "no load-time warning for allow-update on a secondary"

# 1. Unsigned UPDATE from an allowed address, and TSIG-signed with an allowed key, to the secondary.
for mode in unsigned tsig; do
    if [ "$mode" = tsig ]; then set -- -y "$KEY"; else set --; fi
    "$DAG" sec.test @127.0.0.1 -p $SPORT +nohexdump +ednsopt=65001 "$@" \
        --update-add "x.sec.test 300 IN A 192.0.2.9" > "$W/out.txt" 2>&1 || true
    grep -q "opcode: UPDATE, status: REFUSED" "$W/out.txt" || fail "UPDATE ($mode) to the secondary: expected REFUSED"
    grep -q "EDE: 18 (Prohibited)" "$W/out.txt" || fail "UPDATE ($mode) to the secondary: expected EDE 18"
    echo "[OK] UPDATE ($mode) to the secondary: REFUSED, EDE 18"
done
[ -z "$(a_of x.sec.test $SPORT)" ] || fail "x.sec.test appeared on the secondary"
[ -z "$(a_of x.sec.test $PPORT)" ] || fail "x.sec.test appeared on the primary (the secondary must not forward)"
[ "$(serial $SPORT)" = "7" ] || fail "secondary serial changed"
[ "$(serial $PPORT)" = "7" ] || fail "primary serial changed"
echo "[OK] zone unchanged on both servers"

# 2. The same UPDATE to the primary: applied (serial 8) and transferred to the secondary.
"$DAG" sec.test @127.0.0.1 -p $PPORT +nohexdump -y "$KEY" \
    --update-add "x.sec.test 300 IN A 192.0.2.9" > "$W/out.txt" 2>&1 || true
grep -q "opcode: UPDATE, status: NOERROR" "$W/out.txt" || fail "UPDATE to the primary: expected NOERROR"
[ "$(a_of x.sec.test $PPORT)" = "192.0.2.9" ] || fail "x.sec.test not added on the primary"
[ "$(serial $PPORT)" = "8" ] || fail "primary serial is not 8 after the UPDATE"
i=0
while [ "$(a_of x.sec.test $SPORT)" != "192.0.2.9" ]; do
    i=$((i + 1))
    [ $i -le 40 ] || fail "the update did not reach the secondary (serial $(serial $SPORT))"
    sleep 0.5
done
echo "[OK] UPDATE to the primary: NOERROR, serial 8, transferred to the secondary"

# 3. Zone section naming no zone of the server: NOTAUTH on both (RFC 2136 §3.1.1).
for port in $PPORT $SPORT; do
    "$DAG" other.test @127.0.0.1 -p $port +nohexdump \
        --update-add "x.other.test 300 IN A 192.0.2.9" > "$W/out.txt" 2>&1 || true
    grep -q "opcode: UPDATE, status: NOTAUTH" "$W/out.txt" || fail "UPDATE for other.test on port $port: expected NOTAUTH"
done
echo "[OK] UPDATE for a zone that is not served: NOTAUTH"

check_asan_log
kill -0 "$PRIMARY_PID" 2>/dev/null || fail "primary exited"
kill -0 "$SECONDARY_PID" 2>/dev/null || fail "secondary exited"
echo "[PASS] UPDATE to a secondary zone is refused; the primary applies it"
exit 0
