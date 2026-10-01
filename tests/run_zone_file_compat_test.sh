#!/bin/sh
# run_zone_file_compat_test.sh - BIND-compatible zone file syntax served by karidns (phase 11).
#
# R-22 a  type/class mnemonics are case-insensitive (RFC 1035 §2.3.3)
# R-22 b  CLASSnn / HS in the class field (RFC 3597 §5)
# R-22 c  omitted TTL = last explicitly stated TTL when there is no $TTL (RFC 1035 §5.1)
# R-22 d  a relative $ORIGIN is relative to the current origin (RFC 1035 §5.1)
# R-22 e / D-18  $GENERATE with any type, a quoted multi-token rhs and the BIND n modifier
# D-08    SINK, ATMA (BIND presentation) and IPSECKEY gateway type 0 are loaded and answered
# O-11    tinydns parent/child filtering with more than 256 zones in the view

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="$BASE_DIR/karidns"
DAG="$BASE_DIR/dag"
KARICHECK="$BASE_DIR/karicheck"
PORT=15451

echo "=== Zone file compatibility: R-22, D-18, D-08, O-11 ==="

[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICHECK" ] || \
    make -C "$BASE_DIR" karidns dag karicheck >/dev/null || exit 1

if sockstat -4 -l 2>/dev/null | grep -q "127.0.0.1:$PORT "; then
    echo "[SKIP] port $PORT is in use"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/karidns_zfc.XXXXXX)"
chmod 755 "$TMP_DIR"
PID=""
cleanup() {
    kari_kill_tree "$PID"
    kari_kill_conf "$TMP_DIR/k.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

# No $TTL on purpose (R-22 c).
cat > "$TMP_DIR/o.test.zone" <<'EOF'
$ORIGIN o.test.
@ 7200 IN SOA ns1.o.test. hm.o.test. ( 1 3600 600 86400 60 )
@ 7200 IN NS ns1
ns1 IN A 192.0.2.1
w1 300 IN a 192.0.2.2
w2 300 in A 192.0.2.3
w3 300 CLASS1 A 192.0.2.4
h 300 hs TXT "hesiod"
$ORIGIN sub
x A 192.0.2.5
$ORIGIN o.test.
$GENERATE 1-2 mail$ A 192.0.2.1$
$GENERATE 1-2 m$ MX "10 mail$"
$GENERATE 1-2 ${0,7,n}.r PTR h$
k IN SINK 1 2 3 AQIDBAUG
a IN ATMA +358400123456
i IN IPSECKEY 10 0 1 . AQNR
EOF

# O-11: the parent and the 301st zone share one tinydns data file.
cat > "$TMP_DIR/data" <<'EOF'
.p.test::ns.p.test:3600
+ns.p.test:192.0.2.53
+www.p.test:192.0.2.80
.c300.p.test::ns.c300.p.test:3600
+ns.c300.p.test:192.0.2.54
+www.c300.p.test:192.0.2.77
EOF
cat > "$TMP_DIR/filler.zone" <<'EOF'
@ 300 IN SOA ns.invalid. hm.invalid. 1 3600 600 86400 60
@ 300 IN NS ns.invalid.
EOF

USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'   # karidns refuses to run as root otherwise
chmod 644 "$TMP_DIR"/*
{
    echo "options { port $PORT; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    echo "zone \"o.test\" { type master; file \"$TMP_DIR/o.test.zone\"; };"
    echo "zone \"p.test\" { type master; file \"$TMP_DIR/data\"; file-format tinydns; allow-transfer { 127.0.0.1; }; };"
    i=1
    while [ $i -le 299 ]; do
        echo "zone \"f$i.test\" { type master; file \"$TMP_DIR/filler.zone\"; };"
        i=$((i + 1))
    done
    echo "zone \"c300.p.test\" { type master; file \"$TMP_DIR/data\"; file-format tinydns; };"
} > "$TMP_DIR/k.conf"

echo "[*] karicheck on the zone file"
if "$KARICHECK" zone o.test "$TMP_DIR/o.test.zone" > "$TMP_DIR/kc.out" 2>&1; then
    pass "karicheck accepts the zone file"
else
    fail "karicheck rejects the zone file: $(grep -m1 ERROR "$TMP_DIR/kc.out")"
fi

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/srv.log" 2>&1 &
PID=$!
n=0
until "$DAG" @127.0.0.1 -p $PORT f299.test SOA +short +time=1 +tries=1 2>/dev/null | grep -q ns.invalid; do
    n=$((n + 1))
    if [ $n -ge 20 ]; then
        fail "server did not answer"; cat "$TMP_DIR/srv.log"; exit 1
    fi
    sleep 0.5
done

# answer <name> <type> -> "TTL<TAB>RDATA" lines of the answer section
answer() {
    "$DAG" @127.0.0.1 -p $PORT "$1" "$2" +noall +answer +nohexdump +nottlunits 2>/dev/null |
        awk '{ ttl = $2; $1 = $2 = $3 = $4 = ""; sub(/^ +/, ""); print ttl "\t" $0 }'
}
expect() {   # expect <label> <name> <type> <expected "TTL<TAB>RDATA">
    got="$(answer "$2" "$3")"
    if printf '%s\n' "$got" | grep -qxF "$(printf '%b' "$4")"; then
        pass "$1"
    else
        fail "$1: got '$got'"
    fi
}

expect "R-22 c: omitted TTL after an explicit 7200 (no \$TTL)" ns1.o.test A '7200\t192.0.2.1'
expect "R-22 a: lower-case type" w1.o.test A '300\t192.0.2.2'
expect "R-22 a: lower-case class" w2.o.test A '300\t192.0.2.3'
expect "R-22 b: CLASS1" w3.o.test A '300\t192.0.2.4'
expect "R-22 d: relative \$ORIGIN" x.sub.o.test A '300\t192.0.2.5'
expect "R-22 e: \$GENERATE quoted MX rhs" m2.o.test MX '300\t10 mail2.o.test.'
expect "R-22 e: \$GENERATE nibble owner" 1.0.0.0.r.o.test PTR '300\th1.o.test.'
expect "D-08: SINK" k.o.test SINK '300\t1 2 3 AQIDBAUG'
expect "D-08: ATMA E.164" a.o.test ATMA '300\t+358400123456'
expect "D-08: IPSECKEY gateway type 0" i.o.test IPSECKEY '300\t10 0 1 . AQNR'

# HS-class data is kept with its class: an IN query does not see it
if [ -z "$(answer h.o.test TXT)" ]; then
    pass "R-22 b: HS record is not answered for class IN"
else
    fail "R-22 b: HS record answered for class IN"
fi

echo "[*] O-11: 301 zones in the view, tinydns data shared by p.test and c300.p.test"
expect "O-11: child zone answers its own record" www.c300.p.test A '86400\t192.0.2.77'
"$DAG" @127.0.0.1 -p $PORT p.test AXFR +nohexdump > "$TMP_DIR/axfr.out" 2>&1
if grep -q "^www\.p\.test\." "$TMP_DIR/axfr.out" && ! grep -q "c300\.p\.test.*IN[[:space:]]*A" "$TMP_DIR/axfr.out"; then
    pass "O-11: the parent's AXFR does not contain the child's records"
else
    fail "O-11: parent AXFR:"; cat "$TMP_DIR/axfr.out"
fi

if [ $FAILED -ne 0 ]; then
    echo "=== FAILED ==="
    exit 1
fi
echo "=== PASSED ==="
exit 0
