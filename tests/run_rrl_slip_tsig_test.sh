#!/bin/sh
# ==============================================================================
# run_rrl_slip_tsig_test.sh
#
# X-20 (phase 13b): an RRL "slip" answer (TC=1, question + OPT only) to a validly
# TSIG-signed query is signed with the request's key (RFC 8945 §5.3: a response to
# a request with a valid MAC is signed). BIND 9.20 does the same (query_checkrrl()
# sets TC and the message is rendered and signed as usual). The slip answer used to
# be cut after the question and lost its TSIG.
# rate-limit { responses-per-second 1; window 1; slip 1; } so every limited UDP answer
# is a slip.
#  1. 6 signed queries for one name: some slipped (TC=1), every answer signed (MAC verified)
#  2. 6 unsigned queries: slipped answers carry no TSIG
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

PORT=$((43000 + $$ % 3000))
TMP_DIR="$(mktemp -d /tmp/rrl_slip_tsig.XXXXXX)"
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
SECRET=$(openssl rand -base64 32)
cat > "$TMP_DIR/rs.zone" <<'EOF'
$TTL 300
$ORIGIN rs.test.
@ IN SOA ns1.rs.test. hostmaster.rs.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.rs.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.81
www2 IN A 192.0.2.82
EOF
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
          rate-limit { responses-per-second 1; window 1; slip 1; }; };
key "k1" { algorithm hmac-sha256; secret "$SECRET"; };
zone "rs.test" { type master; file "$TMP_DIR/rs.zone"; };
EOF
chmod 644 "$TMP_DIR"/*

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" ns1.rs.test A +short +time=1 +tries=1 2>/dev/null | grep -q 192.0.2.1 && break
    sleep 0.1; i=$((i + 1))
done
sleep 1.2

echo "=== RRL slip answers to signed queries (X-20) ==="
$TQ --port "$PORT" --name www.rs.test --type A --edns-version 0 --key "k1:$SECRET" --count 6 > "$TMP_DIR/signed.out"
cat "$TMP_DIR/signed.out" | sed 's/^/    /'
SLIPPED=$(grep -c " tc=1 " "$TMP_DIR/signed.out")
UNSIGNED=$(grep -vc " tsig=ok$" "$TMP_DIR/signed.out")
if [ "$SLIPPED" -ge 3 ]; then pass "signed queries: $SLIPPED of 6 slipped"; else fail "signed queries: $SLIPPED of 6 slipped (expected >= 3)"; fi
if [ "$UNSIGNED" -eq 0 ]; then pass "every answer to a signed query is signed, slip answers included"; else fail "$UNSIGNED answer(s) to signed queries not signed"; fi
if grep " tc=1 " "$TMP_DIR/signed.out" | grep -q " an=0 ns=0 ar=2 opt=0 "; then
    pass "slip answer: question + OPT + TSIG only"
else
    fail "slip answer sections"
fi

sleep 1.2
$TQ --port "$PORT" --name www2.rs.test --type A --edns-version 0 --count 6 > "$TMP_DIR/unsigned.out"
SLIPPED=$(grep -c " tc=1 " "$TMP_DIR/unsigned.out")
if [ "$SLIPPED" -ge 3 ] && ! grep " tc=1 " "$TMP_DIR/unsigned.out" | grep -vq " ar=1 opt=0 tsig=none$"; then
    pass "unsigned queries: $SLIPPED slipped, no TSIG"
else
    fail "unsigned queries"; cat "$TMP_DIR/unsigned.out"
fi

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"
if [ "$FAILED" -ne 0 ]; then
    echo "=== server log ==="; cat "$TMP_DIR/server.log"
    echo "FAILED: $FAILED check(s)"; exit 1
fi
echo "PASSED: signed RRL slip answers (X-20)"
exit 0
