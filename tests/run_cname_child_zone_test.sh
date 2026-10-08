#!/bin/sh
# ==============================================================================
# run_cname_child_zone_test.sh
#
# X-27 (phase 13b): after a CNAME/DNAME the zone is chosen again for the new name
# (RFC 1034 §4.3.2 step 3a: "change QNAME to the canonical name ... and go back to
# step 1"; step 2 picks the nearest ancestor zone). The parent par.test delegates
# ch.par.test, and the same server serves ch.par.test.
#  1. alias.par.test A -> CNAME www.ch.par.test. + the child's A, AA=1, no referral
#     (it used to stay in the parent and answer with the referral, AA=0).
#  2. www.d.par.test A through DNAME d -> ch.par.test.: DNAME + CNAME + child's A.
#  3. A CNAME inside the parent (in.par.test -> host.par.test.) still resolves.
#  4. A CNAME into a forward zone stops at the CNAME (NOERROR, not SERVFAIL).
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT_DIR}"
[ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag
KARIDNS="$BIN_DIR/karidns"
DAG="$BIN_DIR/dag"

PORT=$((34000 + $$ % 3000))
TMP_DIR="$(mktemp -d /tmp/cname_child_zone.XXXXXX)"
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

cat > "$TMP_DIR/par.zone" <<'EOF'
$TTL 300
$ORIGIN par.test.
@ IN SOA ns1.par.test. hostmaster.par.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.par.test.
ns1 IN A 192.0.2.1
alias IN CNAME www.ch.par.test.
in IN CNAME host.par.test.
host IN A 192.0.2.10
fwd IN CNAME x.fwd.test.
d IN DNAME ch.par.test.
ch IN NS ns1.ch.par.test.
ns1.ch IN A 192.0.2.2
EOF
cat > "$TMP_DIR/ch.zone" <<'EOF'
$TTL 300
$ORIGIN ch.par.test.
@ IN SOA ns1.ch.par.test. hostmaster.ch.par.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.ch.par.test.
ns1 IN A 192.0.2.2
www IN A 192.0.2.99
EOF
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "par.test" { type master; file "$TMP_DIR/par.zone"; };
zone "ch.par.test" { type master; file "$TMP_DIR/ch.zone"; };
zone "fwd.test" { type forward; forwarders { 192.0.2.53; }; forward-timeout 500; };
EOF
chmod 644 "$TMP_DIR"/*

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" www.ch.par.test A +short +time=1 +tries=1 2>/dev/null | grep -q 192.0.2.99 && break
    sleep 0.1; i=$((i + 1))
done

q() { "$DAG" @127.0.0.1 -p "$PORT" "$@" +time=2 +tries=1 +nohexdump +norec 2>&1; }

echo "=== CNAME/DNAME into a child zone on the same server (X-27) ==="
OUT=$(q alias.par.test A)
if echo "$OUT" | grep -q "status: NOERROR" &&
   echo "$OUT" | grep -Eq "^alias\.par\.test\.[[:space:]].*CNAME[[:space:]]+www\.ch\.par\.test\." &&
   echo "$OUT" | grep -Eq "^www\.ch\.par\.test\.[[:space:]].*A[[:space:]]+192\.0\.2\.99" &&
   echo "$OUT" | grep -Eq "^;; flags:.* aa"; then
    # The authority section may carry the child zone's own apex NS (positive answer from that zone);
    # the referral of the old behaviour had AA=0 and no A record.
    pass "CNAME into the child zone: child's answer, AA=1, no referral"
else
    fail "CNAME into the child zone"; echo "$OUT"
fi

OUT=$(q www.d.par.test A)
if echo "$OUT" | grep -Eq "^d\.par\.test\.[[:space:]].*DNAME[[:space:]]+ch\.par\.test\." &&
   echo "$OUT" | grep -Eq "^www\.d\.par\.test\.[[:space:]].*CNAME[[:space:]]+www\.ch\.par\.test\." &&
   echo "$OUT" | grep -Eq "^www\.ch\.par\.test\.[[:space:]].*A[[:space:]]+192\.0\.2\.99"; then
    pass "DNAME into the child zone: DNAME + CNAME + child's A"
else
    fail "DNAME into the child zone"; echo "$OUT"
fi

OUT=$(q in.par.test A)
if echo "$OUT" | grep -Eq "^host\.par\.test\.[[:space:]].*A[[:space:]]+192\.0\.2\.10" &&
   echo "$OUT" | grep -Eq "^;; flags:.* aa"; then
    pass "CNAME inside the parent zone still resolves"
else
    fail "CNAME inside the parent zone"; echo "$OUT"
fi

OUT=$(q fwd.par.test A)
if echo "$OUT" | grep -q "status: NOERROR" &&
   echo "$OUT" | grep -Eq "^fwd\.par\.test\.[[:space:]].*CNAME[[:space:]]+x\.fwd\.test\." &&
   echo "$OUT" | grep -q "ANSWER: 1"; then
    pass "CNAME into a forward zone stops at the CNAME"
else
    fail "CNAME into a forward zone"; echo "$OUT"
fi

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"
if [ "$FAILED" -ne 0 ]; then
    echo "=== server log ==="; cat "$TMP_DIR/server.log"
    echo "FAILED: $FAILED check(s)"; exit 1
fi
echo "PASSED: CNAME/DNAME zone selection (X-27)"
exit 0
