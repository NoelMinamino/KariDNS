#!/bin/sh
# ==============================================================================
# run_compressed_qname_test.sh
#
# X-15 (phase 13b): a compression pointer in the question name is FORMERR with
# QDCOUNT=0 (RFC 1035 §4.1.4: a pointer refers to a prior occurrence of a name; the
# question name is the first name of the message, so a pointer there can only point
# into the header). The server used to stop the name at the pointer: depending on
# the target it answered for the shorter name ("www." for "www" + pointer to
# offset 2) or sent nothing (a pointer to the name itself).
#  1. UDP: "www" + pointer to offset 12           -> FORMERR, QDCOUNT=0
#  2. TCP: the same                               -> FORMERR, QDCOUNT=0
#  3. UDP: the name is only a pointer             -> FORMERR, QDCOUNT=0
#  4. UDP: "www" + pointer into the header (offset 2; used to be answered for "www.") -> FORMERR
#  5. UDP: the same query with an OPT             -> FORMERR with OPT
#  6. An ordinary query is still answered
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

PORT=$((40000 + $$ % 3000))
TMP_DIR="$(mktemp -d /tmp/compressed_qname.XXXXXX)"
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
cat > "$TMP_DIR/cq.zone" <<'EOF'
$TTL 300
$ORIGIN cq.test.
@ IN SOA ns1.cq.test. hostmaster.cq.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.cq.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
EOF
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "cq.test" { type master; file "$TMP_DIR/cq.zone"; };
EOF
chmod 644 "$TMP_DIR"/*

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" www.cq.test A +short +time=1 +tries=1 2>/dev/null | grep -q 192.0.2.80 && break
    sleep 0.1; i=$((i + 1))
done

HDR=123400000001000000000000      # ID 0x1234, QDCOUNT=1
HDR_OPT=123400000001000000000001  # ... ARCOUNT=1
OPT=0000290400000000000000         # root, OPT, 1024, version 0, RDLEN 0
WWW_PTR=03777777c00c00010001       # "www" + pointer to offset 12, A IN
PTR_ONLY=c00c00010001             # pointer only, A IN

echo "=== Compression pointer in the question name (X-15) ==="
check() { # $1 = description, $2 = expected prefix, then tsig_query.pl options
    desc="$1"; want="$2"; shift 2
    OUT=$($TQ --port "$PORT" "$@")
    case "$OUT" in
        "$want"*) pass "$desc ($OUT)" ;;
        *) fail "$desc: $OUT" ;;
    esac
}
check "UDP: www + pointer -> FORMERR, QDCOUNT=0" "rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=0" --hex "$HDR$WWW_PTR"
check "TCP: www + pointer -> FORMERR, QDCOUNT=0" "rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=0" --tcp --hex "$HDR$WWW_PTR"
check "UDP: pointer only -> FORMERR, QDCOUNT=0" "rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=0" --hex "$HDR$PTR_ONLY"
# pointer to offset 2 (the flags, 0x0000 = an empty label): the old code answered for "www." (NXDOMAIN/REFUSED)
check "UDP: www + pointer into the header -> FORMERR" "rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=0" --hex "${HDR}03777777c00200010001"
check "UDP: www + pointer with OPT -> FORMERR with OPT" "rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0" --hex "$HDR_OPT$WWW_PTR$OPT"
check "Ordinary query still answered" "rcode=0 tc=0 aa=1 qd=1 an=1" --name www.cq.test --type A

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"
if [ "$FAILED" -ne 0 ]; then
    echo "=== server log ==="; cat "$TMP_DIR/server.log"
    echo "FAILED: $FAILED check(s)"; exit 1
fi
echo "PASSED: compressed question names (X-15)"
exit 0
