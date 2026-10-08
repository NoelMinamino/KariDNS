#!/bin/sh
# ==============================================================================
# run_rrl_bind_keys_test.sh
#
# Phase 13 (D-05): RRL counts like BIND (lib/dns/rrl.c make_key()).
# rate-limit { responses-per-second 2; nxdomains-per-second 2; window 1; slip 1; }
# slip 1 turns every limited UDP response into a truncated one (TC=1), so the
# test can count limited answers without waiting for timeouts.
#  1. Six different names from one client: none limited (the key contains the
#     name; it used to be the client only -> 4 of 6 limited).
#  2. One name six times: limited after 2.
#  3. Six random NXDOMAIN names of one zone: limited after 2 (key = zone).
#  4. Six names answered by one wildcard: limited after 2 (key = "*.<zone>").
#  5. Root only: 127.0.0.2 and 127.0.0.3 share the default /24 bucket, and are
#     counted apart with ipv4-prefix-length 32 (loopback aliases; SKIP otherwise).
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag
KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

PORT=$((26000 + $$ % 4000))
TMP_DIR="/tmp/rrl_bind_keys_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
ALIASES=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    for a in $ALIASES; do ifconfig lo0 inet "$a" -alias 2>/dev/null; done
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

{
cat <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
*.wc IN A 192.0.2.77
EOF
for i in 1 2 3 4 5 6 7 8 9; do echo "n$i IN A 192.0.2.$i"; echo "p$i IN A 192.0.2.$((i + 20))"; done
} > "$TMP_DIR/example.test.zone"

BIND_ADDRS="127.0.0.1;"
write_conf() { # $1 = extra rate-limit options
cat > "$TMP_DIR/karidns.conf" <<EOF
options {
    port $PORT; bind-address { $BIND_ADDRS }; pid-file "none"; $USER_OPT
    rate-limit { responses-per-second 2; nxdomains-per-second 2; window 1; slip 1; $1 };
};
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
chmod 644 "$TMP_DIR"/*
}

start_server() {
    "$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ $i -lt 50 ]; do
        "$DAG" @127.0.0.1 -p "$PORT" ns1.example.test A +time=1 +tries=1 +nohexdump 2>/dev/null | grep -q "status: NOERROR" && { sleep 1.2; return 0; }
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

# limited NAMES...: number of truncated (slipped) answers among the queries, sent back to back
limited() { # $1 = source address, then the names
    src="$1"; shift
    n=0
    for q in "$@"; do
        "$DAG" @127.0.0.1 -b "$src" -p "$PORT" "$q" A +time=1 +tries=1 +ignore +nohexdump > "$TMP_DIR/q.out" 2>&1
        grep -q "^;; flags:.* tc" "$TMP_DIR/q.out" && n=$((n + 1))
    done
    echo "$n"
}

echo "=== RRL keys like BIND (D-05) ==="
write_conf ""
start_server || { echo "FAIL: server did not start"; exit 1; }

n=$(limited 127.0.0.1 n1.example.test n2.example.test n3.example.test n4.example.test n5.example.test n6.example.test)
[ "$n" = 0 ] && pass "6 different names from one client: none limited" || fail "6 different names: $n limited (expected 0)"
sleep 1.2
n=$(limited 127.0.0.1 n7.example.test n7.example.test n7.example.test n7.example.test n7.example.test n7.example.test)
[ "$n" -ge 3 ] && pass "one name 6 times: $n limited" || fail "one name 6 times: $n limited (expected >= 3)"
sleep 1.2
n=$(limited 127.0.0.1 r1.example.test r2.example.test r3.example.test r4.example.test r5.example.test r6.example.test)
[ "$n" -ge 3 ] && pass "6 random NXDOMAIN names: $n limited (one bucket per zone)" || fail "random NXDOMAIN: $n limited (expected >= 3)"
sleep 1.2
n=$(limited 127.0.0.1 a.wc.example.test b.wc.example.test c.wc.example.test d.wc.example.test e.wc.example.test f.wc.example.test)
[ "$n" -ge 3 ] && pass "6 wildcard names: $n limited (one *.<zone> bucket)" || fail "wildcard names: $n limited (expected >= 3)"

if [ "$(id -u)" = "0" ] && command -v ifconfig > /dev/null 2>&1; then
    for a in 127.0.0.2 127.0.0.3; do
        ifconfig lo0 inet "$a" alias 2>/dev/null && ALIASES="$ALIASES $a"
    done
    BIND_ADDRS="127.0.0.1; 127.0.0.2; 127.0.0.3;"
    write_conf ""
    kari_kill_tree "$SERVER_PID"; SERVER_PID=""
    start_server || fail "restart with aliases"
    sleep 1.2
    a=$(limited 127.0.0.2 p1.example.test p1.example.test)
    b=$(limited 127.0.0.3 p1.example.test)
    [ "$a" = 0 ] && [ "$b" = 1 ] && pass "default /24: 127.0.0.2 and 127.0.0.3 share a bucket" \
                                  || fail "default /24: limited $a then $b (expected 0 then 1)"
    kari_kill_tree "$SERVER_PID"; SERVER_PID=""
    write_conf "ipv4-prefix-length 32;"
    start_server || fail "restart with ipv4-prefix-length 32"
    a=$(limited 127.0.0.2 p2.example.test p2.example.test)
    b=$(limited 127.0.0.3 p2.example.test)
    [ "$a" = 0 ] && [ "$b" = 0 ] && pass "ipv4-prefix-length 32: counted per address" \
                                  || fail "ipv4-prefix-length 32: limited $a then $b (expected 0 then 0)"
else
    echo "  SKIP: prefix-length check needs root (loopback aliases)"
fi

kill -0 "$SERVER_PID" 2>/dev/null && pass "server still running" || fail "server exited"

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: RRL keys follow BIND (name, zone for NXDOMAIN, wildcard, client prefix)"
exit 0
