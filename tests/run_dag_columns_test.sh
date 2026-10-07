#!/bin/sh
# X-40: dag lays out records and question lines like dig 9.20 (BIND masterdump.c indent(): fields start at
# fixed columns reached with tabs of width 8 and spaces, or one space when the column is already passed).
# Columns of TTL/CLASS/TYPE/RDATA: 24/32/40/48 by default, 24/24/32/40 with +nottlid or +noclass, 24/24/24/32
# with +multiline (continuation lines indented by four tabs). The expected lines are fixed below; when dig is
# installed, the same queries are also compared byte for byte with dig.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns

PORT=15856
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-dagcol.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
SERVER_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

cat > "$W/col.zone" <<'EOF'
$ORIGIN col.test.
$TTL 300
@    IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@    IN NS  ns1.col.test.
ns1  IN A   192.0.2.1
www  IN A   192.0.2.80
a-very-long-owner-name-for-columns IN A 192.0.2.81
big  2147483647 IN A 192.0.2.82
nx   IN NSEC nx2.col.test. RRSIG NSEC NXNAME
EOF

cat > "$W/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "col.test" { type master; file "$W/col.zone"; };
EOF

"$BIN" -f "$W/k.conf" > "$W/server.log" 2>&1 &
SERVER_PID=$!
i=0
until "$DAG" @127.0.0.1 -p $PORT col.test SOA +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster; do
    i=$((i + 1))
    if [ $i -ge 50 ]; then echo "[FAIL] server did not start"; cat "$W/server.log"; exit 1; fi
    sleep 0.2
done

T=$(printf '\t')
# check NAME "ARGS" EXPECTED : dag output (ARGS +nohexdump) must equal EXPECTED exactly (tabs written as <T>)
check() {
    want=$(printf '%s\n' "$3" | sed "s/<T>/$T/g")
    got=$(eval "\"$DAG\" @127.0.0.1 -p $PORT $2 +nohexdump" 2>&1 || true)
    if [ "$got" = "$want" ]; then
        echo "[OK] $1"
    else
        echo "[FAIL] $1"
        echo "--- expected"; printf '%s\n' "$want" | sed "s/$T/<T>/g"
        echo "--- got"; printf '%s\n' "$got" | sed "s/$T/<T>/g"
        FAILED=1
    fi
    if command -v dig >/dev/null 2>&1; then
        dig_out=$(eval "dig @127.0.0.1 -p $PORT $2" 2>&1 || true)
        if [ "$dig_out" != "$got" ]; then
            echo "[FAIL] $1: differs from dig"
            echo "--- dig"; printf '%s\n' "$dig_out" | sed "s/$T/<T>/g"
            FAILED=1
        fi
    fi
}

check "default columns 24/32/40/48" "www.col.test A +noall +answer" \
    "www.col.test.<T><T>300<T>IN<T>A<T>192.0.2.80"
check "owner past the TTL column: one space" "a-very-long-owner-name-for-columns.col.test A +noall +answer" \
    "a-very-long-owner-name-for-columns.col.test. 300 IN A 192.0.2.81"
check "long TTL past the class column" "big.col.test A +noall +answer" \
    "big.col.test.<T><T>2147483647 IN<T>A<T>192.0.2.82"
check "+nottlid: 24/24/32/40" "www.col.test A +nottlid +noall +answer" \
    "www.col.test.<T><T>IN<T>A<T>192.0.2.80"
check "+noclass: 24/24/32/40" "www.col.test A +noclass +noall +answer" \
    "www.col.test.<T><T>300<T>A<T>192.0.2.80"
check "+nottlid +noclass: 24/24/24/32" "www.col.test A +nottlid +noclass +noall +answer" \
    "www.col.test.<T><T>A<T>192.0.2.80"
check "question line (';' not counted)" "www.col.test A +noall +question" \
    ";www.col.test.<T><T><T>IN<T>A"
check "question line +multiline" "www.col.test A +multiline +noall +question" \
    ";www.col.test.<T><T>IN A"
check "type 128 (RFC 9824 NXNAME) printed as TYPE128 like dig 9.20" "nx.col.test NSEC +noall +answer" \
    "nx.col.test.<T><T>300<T>IN<T>NSEC<T>nx2.col.test. RRSIG NSEC TYPE128"
check "+multiline SOA (BIND soa_6.c layout)" "col.test SOA +multiline +noall +answer" \
"col.test.<T><T>300 IN SOA ns1.col.test. hostmaster.col.test. (
<T><T><T><T>1          ; serial
<T><T><T><T>7200       ; refresh (2 hours)
<T><T><T><T>3600       ; retry (1 hour)
<T><T><T><T>1209600    ; expire (2 weeks)
<T><T><T><T>300        ; minimum (5 minutes)
<T><T><T><T>)"

if [ $FAILED -ne 0 ]; then
    echo "[FAIL] dag column layout test failed"
    exit 1
fi
command -v dig >/dev/null 2>&1 || echo "[INFO] dig not installed: compared with the fixed expectations only"
echo "[PASS] dag column layout test passed"
exit 0
