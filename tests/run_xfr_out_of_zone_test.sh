#!/bin/sh
# run_xfr_out_of_zone_test.sh - out-of-zone records (R-27).
#
# tests/zones/example.com.zone contains "10.2.0.192.in-addr.arpa. IN PTR ...", which is not part of
# example.com (RFC 1034 §4.2). The primary must ignore it with a warning instead of loading it and
# sending it in AXFR (RFC 5936 §2.2), karicheck must warn about it (exit status unchanged), and a
# KariDNS secondary must complete the transfer and serve the same data as the primary.

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="$BASE_DIR/karidns"
DAG="$BASE_DIR/dag"
KARICHECK="$BASE_DIR/karicheck"
PPORT=15441
SPORT=15442

echo "=== Out-of-zone data: loader, karicheck, primary -> secondary transfer (R-27) ==="

[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICHECK" ] || \
    make -C "$BASE_DIR" karidns dag karicheck >/dev/null || exit 1

TMP_DIR="$(mktemp -d /tmp/karidns_ooz.XXXXXX)"
chmod 755 "$TMP_DIR"
P_PID=""
S_PID=""
cleanup() {
    kari_kill_tree "$P_PID" "$S_PID"
    kari_kill_conf "$TMP_DIR/primary.conf" "$TMP_DIR/secondary.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

cp "$SCRIPT_DIR/zones/example.com.zone" "$SCRIPT_DIR/zones/example.com.dnskey" \
   "$SCRIPT_DIR/zones/example.com.hosts" "$TMP_DIR/"
chmod 644 "$TMP_DIR"/example.com.*
grep -q "^10\.2\.0\.192\.in-addr\.arpa\." "$TMP_DIR/example.com.zone" || { echo "test zone changed: no out-of-zone record"; exit 1; }

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

# 1. karicheck: warning naming the record. (example.com.zone fails its ZONEMD check with or
#    without this change, so the exit status is checked on a small zone below.)
KC_OUT=$("$KARICHECK" zone example.com "$TMP_DIR/example.com.zone" 2>&1)
if echo "$KC_OUT" | grep -q "\[WARNING\] Zone 'example.com.': out-of-zone record '10.2.0.192.in-addr.arpa.' PTR ignored"; then
    pass "karicheck warns about the out-of-zone PTR in example.com.zone"
else
    fail "karicheck has no out-of-zone warning"; echo "$KC_OUT" | grep -i "out-of-zone\|RESULT\|ERROR"
fi
cat > "$TMP_DIR/small.zone" <<'EOF'
$TTL 60
$ORIGIN small.test.
@   IN SOA ns1.small.test. hostmaster.small.test. 1 3600 600 86400 60
@   IN NS  ns1.small.test.
@   IN NS  ns.other.test.
ns1 IN A   192.0.2.1
ns.other.test. IN A 192.0.2.2
EOF
KC_OUT=$("$KARICHECK" zone small.test "$TMP_DIR/small.zone" 2>&1); KC_RC=$?
if [ $KC_RC -eq 0 ] && echo "$KC_OUT" | grep -q "out-of-zone record 'ns.other.test.' A ignored" \
   && echo "$KC_OUT" | grep -q "0 error(s)"; then
    pass "karicheck: out-of-zone glue is a warning, exit status 0"
else
    fail "karicheck small zone (rc=$KC_RC)"; echo "$KC_OUT"
fi

cat > "$TMP_DIR/primary.conf" <<EOF
options { port $PPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "example.com" { type master; file "$TMP_DIR/example.com.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$TMP_DIR/secondary.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "example.com" { type slave; masters { 127.0.0.1 port $PPORT; }; allow-transfer { 127.0.0.1; }; };
EOF

"$KARIDNS" -f "$TMP_DIR/primary.conf" > "$TMP_DIR/primary.log" 2>&1 &
P_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" example.com SOA @127.0.0.1 -p $PPORT +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster && break
    sleep 0.2; i=$((i + 1))
done

# wait_grep PATTERN FILE: the server log is written asynchronously
wait_grep() {
    _w=0
    while [ $_w -lt 25 ]; do grep -q "$1" "$2" && return 0; sleep 0.2; _w=$((_w + 1)); done
    return 1
}

# 2. primary: warning in the log, record neither loaded nor transferred
if wait_grep "ignoring out-of-zone data '10.2.0.192.in-addr.arpa.' PTR" "$TMP_DIR/primary.log"; then
    pass "primary logs the ignored out-of-zone record"
else
    fail "primary log has no out-of-zone warning"; grep -i "zone" "$TMP_DIR/primary.log" | head
fi
"$DAG" example.com AXFR @127.0.0.1 -p $PPORT +time=5 +nohexdump > "$TMP_DIR/p.axfr" 2>&1
P_SOAS=$(grep -Ec "^example\.com\.[[:space:]].*[[:space:]]SOA[[:space:]]" "$TMP_DIR/p.axfr")
if [ "$P_SOAS" = "2" ] && ! grep -q "in-addr\.arpa\.[[:space:]].*PTR" "$TMP_DIR/p.axfr"; then
    pass "primary AXFR is complete and has no out-of-zone record"
else
    fail "primary AXFR (SOA lines: $P_SOAS)"; grep "in-addr" "$TMP_DIR/p.axfr"
fi
# The in-zone PTR next to it is still there
grep -q "^ptr-host\.example\.com\.[[:space:]].*PTR" "$TMP_DIR/p.axfr" && pass "in-zone PTR kept" || fail "in-zone PTR missing"

# 3. secondary: transfer succeeds and serves the same data
"$KARIDNS" -f "$TMP_DIR/secondary.conf" > "$TMP_DIR/secondary.log" 2>&1 &
S_PID=$!
P_SERIAL=$("$DAG" example.com SOA @127.0.0.1 -p $PPORT +short | awk '{print $3}')
S_SERIAL=""
i=0
while [ $i -lt 60 ]; do
    S_SERIAL=$("$DAG" example.com SOA @127.0.0.1 -p $SPORT +short +time=1 +tries=1 2>/dev/null | awk '{print $3}')
    [ -n "$S_SERIAL" ] && [ "$S_SERIAL" = "$P_SERIAL" ] && break
    sleep 0.5; i=$((i + 1))
done
if [ -n "$P_SERIAL" ] && [ "$S_SERIAL" = "$P_SERIAL" ]; then
    pass "secondary transferred the zone (serial $S_SERIAL)"
else
    fail "secondary did not transfer the zone (primary '$P_SERIAL', secondary '$S_SERIAL')"
    grep "AXFR" "$TMP_DIR/secondary.log" | tail -5
fi
if grep -q "Failed to transfer zone" "$TMP_DIR/secondary.log"; then
    fail "secondary logged a failed transfer"
fi
i=0
while [ $i -lt 20 ]; do
    "$DAG" example.com AXFR @127.0.0.1 -p $SPORT +time=5 +nohexdump > "$TMP_DIR/s.axfr" 2>&1
    grep -q "^www\.example\.com\." "$TMP_DIR/s.axfr" && break
    sleep 0.5; i=$((i + 1))
done
normalize() { grep -Ev "^;|^$" "$1" | awk '{ $2 = ""; print }' | sort; }
if [ -s "$TMP_DIR/s.axfr" ] && normalize "$TMP_DIR/p.axfr" > "$TMP_DIR/p.norm" && normalize "$TMP_DIR/s.axfr" > "$TMP_DIR/s.norm" \
   && [ "$(wc -l < "$TMP_DIR/p.norm")" -gt 50 ] && cmp -s "$TMP_DIR/p.norm" "$TMP_DIR/s.norm"; then
    pass "secondary AXFR matches the primary ($(wc -l < "$TMP_DIR/s.norm" | tr -d ' ') records)"
else
    fail "secondary AXFR differs from the primary"; diff "$TMP_DIR/p.norm" "$TMP_DIR/s.norm" | head -10
fi
W_P=$("$DAG" www.example.com A @127.0.0.1 -p $PPORT +short | sort)
W_S=$("$DAG" www.example.com A @127.0.0.1 -p $SPORT +short | sort)
[ -n "$W_S" ] && [ "$W_P" = "$W_S" ] && pass "secondary answers www.example.com like the primary" || fail "www.example.com: primary '$W_P' secondary '$W_S'"
R_S=$("$DAG" 10.2.0.192.in-addr.arpa PTR @127.0.0.1 -p $SPORT +time=2 +tries=1 2>&1 | grep -o "status: [A-Z]*")
[ "$R_S" = "status: REFUSED" ] && pass "secondary does not serve the out-of-zone name (REFUSED)" || fail "out-of-zone name on the secondary: '$R_S'"

for p in "$P_PID" "$S_PID"; do kill -0 "$p" 2>/dev/null || fail "a server exited during the test"; done
if [ $FAILED -ne 0 ]; then
    echo "--- primary.log (tail) ---"; tail -15 "$TMP_DIR/primary.log"
    echo "--- secondary.log (tail) ---"; tail -15 "$TMP_DIR/secondary.log"
    echo "=== FAILED ==="
    exit 1
fi
echo "=== PASSED ==="
exit 0
