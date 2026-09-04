#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
make -C "$ROOT" karidns dag

TMP_DIR="$(mktemp -d /tmp/karidns_sibling_test.XXXXXX)"

CONF_YES="$TMP_DIR/sibling_yes.conf"
CONF_INDOMAIN="$TMP_DIR/sibling_indomain.conf"
CONF_NO="$TMP_DIR/sibling_no.conf"

ZONE_JP="$TMP_DIR/example.jp.zone"
ZONE_COM="$TMP_DIR/example.com.zone"
ZONE_NET="$TMP_DIR/example.net.zone"

cat << 'EOF' > "$ZONE_JP"
$ORIGIN example.jp.
$TTL 86400
@           IN SOA   ns1.example.jp. hostmaster.example.jp. 2026090401 7200 3600 1209600 86400
@           IN NS    ns1.v6.example.com.
@           IN NS    ns1.sub.example.net.
@           IN NS    ns1.city.example.jp.
ns1.city    IN A     192.0.2.15
EOF

cat << 'EOF' > "$ZONE_COM"
$ORIGIN example.com.
$TTL 86400
@           IN SOA   ns1.example.com. hostmaster.example.com. 2026090401 7200 3600 1209600 86400
@           IN NS    ns1.example.com.
ns1         IN A     127.0.0.1
ns1.v6      IN A     192.0.2.86
ns1.v6      IN AAAA  2001:db8:1::86
EOF

cat << 'EOF' > "$ZONE_NET"
$ORIGIN example.net.
$TTL 86400
@           IN SOA   ns1.example.net. hostmaster.example.net. 2026090401 7200 3600 1209600 86400
@           IN NS    ns1.example.net.
ns1         IN A     127.0.0.1
ns1.sub     IN A     192.0.2.60
ns1.sub     IN AAAA  2001:db8:2::60
EOF

# Configuration 1: additional-from-auth yes (default)
cat << EOF > "$CONF_YES"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    additional-from-auth yes;
    user "nobody";
    group "nobody";
};
zone "example.jp" {
    type master;
    file "$ZONE_JP";
};
zone "example.com" {
    type master;
    file "$ZONE_COM";
};
zone "example.net" {
    type master;
    file "$ZONE_NET";
};
EOF

# Configuration 2: additional-from-auth in-domain
cat << EOF > "$CONF_INDOMAIN"
options {
    port 10054;
    bind-address { 127.0.0.1; };
    additional-from-auth in-domain;
    user "nobody";
    group "nobody";
};
zone "example.jp" {
    type master;
    file "$ZONE_JP";
};
zone "example.com" {
    type master;
    file "$ZONE_COM";
};
zone "example.net" {
    type master;
    file "$ZONE_NET";
};
EOF

# Configuration 3: additional-from-auth no
cat << EOF > "$CONF_NO"
options {
    port 10055;
    bind-address { 127.0.0.1; };
    additional-from-auth no;
    user "nobody";
    group "nobody";
};
zone "example.jp" {
    type master;
    file "$ZONE_JP";
};
zone "example.com" {
    type master;
    file "$ZONE_COM";
};
zone "example.net" {
    type master;
    file "$ZONE_NET";
};
EOF

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID_YES" ] && kill -9 "$SERVER_PID_YES" 2>/dev/null || true
    [ -n "$SERVER_PID_IN" ] && kill -9 "$SERVER_PID_IN" 2>/dev/null || true
    [ -n "$SERVER_PID_NO" ] && kill -9 "$SERVER_PID_NO" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
    rm -f "$DIR"/server_sibling_*.log
}
trap cleanup EXIT INT TERM

# -------------------------------------------------------------
# Test 1: additional-from-auth yes (BIND compatible)
# -------------------------------------------------------------
echo "[*] Starting KariDNS with additional-from-auth yes on port 10053..."
$BIN -f -c "$CONF_YES" > "$DIR/server_sibling_yes.log" 2>&1 &
SERVER_PID_YES=$!
sleep 2

echo "[*] Querying NS example.jp on port 10053..."
OUT_YES=$($DAG NS example.jp @127.0.0.1 -p 10053)
echo "$OUT_YES"

# Verify Answer section
if ! echo "$OUT_YES" | grep -q "ns1.v6.example.com"; then
    echo "[FAIL] NS ns1.v6.example.com missing from Answer!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.sub.example.net"; then
    echo "[FAIL] NS ns1.sub.example.net missing from Answer!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.city.example.jp"; then
    echo "[FAIL] NS ns1.city.example.jp missing from Answer!"
    exit 1
fi

# Verify Additional section contains sibling glue
if ! echo "$OUT_YES" | grep -q "ns1.v6.example.com.*192.0.2.86"; then
    echo "[FAIL] Sibling glue A record for ns1.v6.example.com missing in Additional!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.v6.example.com.*2001:db8:1::86"; then
    echo "[FAIL] Sibling glue AAAA record for ns1.v6.example.com missing in Additional!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.sub.example.net.*192.0.2.60"; then
    echo "[FAIL] Sibling glue A record for ns1.sub.example.net missing in Additional!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.sub.example.net.*2001:db8:2::60"; then
    echo "[FAIL] Sibling glue AAAA record for ns1.sub.example.net missing in Additional!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.city.example.jp.*192.0.2.15"; then
    echo "[FAIL] In-domain A record for ns1.city.example.jp missing in Additional!"
    exit 1
fi

echo "[PASS] Test 1: additional-from-auth yes returned all 5 Additional records!"

kill -9 "$SERVER_PID_YES" 2>/dev/null || true
SERVER_PID_YES=""
sleep 1

# -------------------------------------------------------------
# Test 2: additional-from-auth in-domain
# -------------------------------------------------------------
echo "[*] Starting KariDNS with additional-from-auth in-domain on port 10054..."
$BIN -f -c "$CONF_INDOMAIN" > "$DIR/server_sibling_indomain.log" 2>&1 &
SERVER_PID_IN=$!
sleep 2

echo "[*] Querying NS example.jp on port 10054..."
OUT_IN=$($DAG NS example.jp @127.0.0.1 -p 10054)
echo "$OUT_IN"

# In-domain record must be present
if ! echo "$OUT_IN" | grep -q "ns1.city.example.jp.*192.0.2.15"; then
    echo "[FAIL] In-domain A record for ns1.city.example.jp missing in Additional!"
    exit 1
fi

# Sibling domain records must NOT be present
if echo "$OUT_IN" | grep -q "192.0.2.86"; then
    echo "[FAIL] Sibling domain record 192.0.2.86 leaked in in-domain mode!"
    exit 1
fi
if echo "$OUT_IN" | grep -q "192.0.2.60"; then
    echo "[FAIL] Sibling domain record 192.0.2.60 leaked in in-domain mode!"
    exit 1
fi

echo "[PASS] Test 2: additional-from-auth in-domain returned ONLY in-domain glue!"

kill -9 "$SERVER_PID_IN" 2>/dev/null || true
SERVER_PID_IN=""
sleep 1

# -------------------------------------------------------------
# Test 3: additional-from-auth no
# -------------------------------------------------------------
echo "[*] Starting KariDNS with additional-from-auth no on port 10055..."
$BIN -f -c "$CONF_NO" > "$DIR/server_sibling_no.log" 2>&1 &
SERVER_PID_NO=$!
sleep 2

echo "[*] Querying NS example.jp on port 10055..."
OUT_NO=$($DAG NS example.jp @127.0.0.1 -p 10055)
echo "$OUT_NO"

# No address records in Additional section
if echo "$OUT_NO" | grep -E "192.0.2.15|192.0.2.86|192.0.2.60"; then
    echo "[FAIL] Address records were returned in Additional section when additional-from-auth is no!"
    exit 1
fi

echo "[PASS] Test 3: additional-from-auth no returned 0 Additional address records!"

kill -9 "$SERVER_PID_NO" 2>/dev/null || true
SERVER_PID_NO=""

echo "[ALL PASS] Sibling domain Additional glue test suite passed successfully!"
exit 0
