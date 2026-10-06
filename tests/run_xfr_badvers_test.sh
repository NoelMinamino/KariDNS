#!/bin/sh
# ==============================================================================
# run_xfr_badvers_test.sh
#
# X-28 (phase 13b): AXFR/IXFR over TCP with an OPT VERSION the server does not
# implement get RCODE=BADVERS with OPT VERSION 0 (RFC 6891 §6.1.3), like ordinary
# queries. Same order as the query path: after the TSIG check (a valid TSIG -> the
# BADVERS answer is signed), before allow-transfer.
#  1. AXFR, EDNS version 1, unsigned (allow-transfer needs a key): BADVERS, not REFUSED
#  2. IXFR, EDNS version 1, signed with the allowed key: BADVERS, signed (MAC verified)
#  3. AXFR, EDNS version 0, signed: the transfer still works (SOA ... SOA)
#  4. A query with EDNS version 1 (query path, shared helper): BADVERS
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

PORT=$((37000 + $$ % 3000))
TMP_DIR="$(mktemp -d /tmp/xfr_badvers.XXXXXX)"
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
cat > "$TMP_DIR/ax.zone" <<'EOF'
$TTL 300
$ORIGIN ax.test.
@ IN SOA ns1.ax.test. hostmaster.ax.test. ( 5 3600 600 86400 60 )
@ IN NS ns1.ax.test.
ns1 IN A 192.0.2.1
EOF
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
key "k1" { algorithm hmac-sha256; secret "$SECRET"; };
zone "ax.test" { type master; file "$TMP_DIR/ax.zone"; allow-transfer { key "k1"; }; };
EOF
chmod 644 "$TMP_DIR"/*

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" ns1.ax.test A +short +time=1 +tries=1 2>/dev/null | grep -q 192.0.2.1 && break
    sleep 0.1; i=$((i + 1))
done

echo "=== BADVERS for AXFR/IXFR (X-28) ==="
OUT=$($TQ --port "$PORT" --tcp --name ax.test --type AXFR --edns-version 1)
case "$OUT" in
    "rcode=16 "*"opt=0 tsig=none") pass "AXFR, EDNS version 1, unsigned: BADVERS, OPT version 0 ($OUT)" ;;
    *) fail "AXFR, EDNS version 1, unsigned: $OUT" ;;
esac

OUT=$($TQ --port "$PORT" --tcp --name ax.test --type IXFR --ixfr-serial 1 --edns-version 1 --key "k1:$SECRET")
case "$OUT" in
    "rcode=16 "*"opt=0 tsig=ok") pass "IXFR, EDNS version 1, signed: BADVERS, signed with the request key ($OUT)" ;;
    *) fail "IXFR, EDNS version 1, signed: $OUT" ;;
esac

OUT=$($TQ --port "$PORT" --tcp --name ax.test --type AXFR --edns-version 0 --key "k1:$SECRET")
case "$OUT" in
    "rcode=0 "*"an=4 "*"tsig=ok") pass "AXFR, EDNS version 0, signed: transfer ($OUT)" ;;
    *) fail "AXFR, EDNS version 0, signed: $OUT" ;;
esac

OUT=$($TQ --port "$PORT" --name ns1.ax.test --type A --edns-version 1)
case "$OUT" in
    "rcode=16 "*"opt=0 "*) pass "A query, EDNS version 1: BADVERS ($OUT)" ;;
    *) fail "A query, EDNS version 1: $OUT" ;;
esac

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"
if [ "$FAILED" -ne 0 ]; then
    echo "=== server log ==="; cat "$TMP_DIR/server.log"
    echo "FAILED: $FAILED check(s)"; exit 1
fi
echo "PASSED: BADVERS for zone transfers (X-28)"
exit 0
