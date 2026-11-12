#!/bin/sh
# ==============================================================================
# run_udp_oversize_test.sh
#
# 0.6.2 (audit M5): a UDP datagram larger than the receive buffer (BUFFER_SIZE, 4096 octets) came back from recvmmsg() cut to 4096
# octets with MSG_TRUNC, and the server answered the cut message as if the client had sent it (an UPDATE or a TSIG whose end was
# cut).  It is now dropped.
#  1. A query of 5000 octets (the question, then octets after the message)  -> no answer
#  2. The same query of 4000 octets (fits the buffer)                       -> an answer (the server still reads such datagrams)
#  3. An ordinary query is still answered, the server is still running
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT_DIR}"
[ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag
KARIDNS="$BIN_DIR/karidns"
DAG="$BIN_DIR/dag"
TQ="perl $SCRIPT_DIR/tsig_query.pl"

PORT=$(kari_port 0 $((43000 + $$ % 3000)))
TMP_DIR="$(mktemp -d /tmp/udp_oversize.XXXXXX)"
chmod 755 "$TMP_DIR"
SERVER_PID=""
FAILED=0
cleanup() { kari_kill_tree "$SERVER_PID"; rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi
cat > "$TMP_DIR/ov.zone" <<'EOF'
$TTL 300
$ORIGIN ov.test.
@ IN SOA ns1.ov.test. hostmaster.ov.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.ov.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
EOF
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "ov.test" { type master; file "$TMP_DIR/ov.zone"; };
EOF
chmod 644 "$TMP_DIR"/*

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" www.ov.test A +short +time=1 +tries=1 2>/dev/null | grep -q 192.0.2.80 && break
    sleep 0.1; i=$((i + 1))
done

HDR=123400000001000000000000           # ID 0x1234, QDCOUNT=1
Q=03777777026f760474657374000001000001  # www.ov.test A IN (17 octets)
pad() { awk -v n="$1" 'BEGIN { for (i = 0; i < n; i++) printf "00" }'; }
P5000=$(pad $((5000 - 12 - 17)))
P4000=$(pad $((4000 - 12 - 17)))

echo "=== UDP datagrams larger than the receive buffer (audit M5) ==="
OUT=$($TQ --port "$PORT" --hex "$HDR$Q$P5000")
[ "$OUT" = "timeout" ] && pass "5000 octets: no answer" || fail "5000 octets: answered ($OUT)"
OUT=$($TQ --port "$PORT" --hex "$HDR$Q$P4000")
[ "$OUT" != "timeout" ] && pass "4000 octets: answered ($OUT)" || fail "4000 octets: no answer"
OUT=$($TQ --port "$PORT" --name www.ov.test --type A)
case "$OUT" in
    "rcode=0 tc=0 aa=1 qd=1 an=1"*) pass "ordinary query answered ($OUT)" ;;
    *) fail "ordinary query: $OUT" ;;
esac

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"
if [ "$FAILED" -ne 0 ]; then
    echo "=== server log ==="; cat "$TMP_DIR/server.log"
    echo "FAILED: $FAILED check(s)"; exit 1
fi
echo "PASSED: oversized UDP datagrams are dropped (audit M5)"
exit 0
