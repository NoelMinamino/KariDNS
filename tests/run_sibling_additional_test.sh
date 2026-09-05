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

ZONE_PARENT="$TMP_DIR/example-parent.jp.zone"
ZONE_SIBLING="$TMP_DIR/example-sibling.jp.zone"
CONF_SIBLING="$TMP_DIR/sibling_dynamic.conf"

cat << 'EOF' > "$ZONE_PARENT"
$ORIGIN example-parent.jp.
$TTL 1800
@           IN SOA   ns1.city.example-parent.jp. hostmaster.example-parent.jp. 2026090501 7200 3600 1209600 1800
@           IN NS    ns-ext.example.org.
@           IN NS    ns1.city.example-parent.jp.
@           IN NS    ns-sibling.v6.example-sibling.jp.
ns-ext.example.org. IN A 192.0.2.88
ns-ext.example.org. IN AAAA 2001:db8:1::88
ns1.city    IN A     192.0.2.61
EOF

cat << 'EOF' > "$ZONE_SIBLING"
$ORIGIN example-sibling.jp.
$TTL 1800
@           IN SOA   ns1.example-sibling.jp. hostmaster.example-sibling.jp. 2026090501 7200 3600 1209600 1800
@           IN NS    ns1.example-sibling.jp.
ns-sibling.v6    IN A     198.51.100.226
ns-sibling.v6    IN AAAA  2001:db8:2::226
EOF

cat << EOF > "$CONF_SIBLING"
options {
    port 10056;
    bind-address { 127.0.0.1; };
    additional-from-auth yes;
    user "nobody";
    group "nobody";
};
zone "example-parent.jp" {
    type master;
    file "$ZONE_PARENT";
};
zone "example-sibling.jp" {
    type master;
    file "$ZONE_SIBLING";
};
EOF

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID_YES" ] && kill -9 "$SERVER_PID_YES" 2>/dev/null || true
    [ -n "$SERVER_PID_IN" ] && kill -9 "$SERVER_PID_IN" 2>/dev/null || true
    [ -n "$SERVER_PID_NO" ] && kill -9 "$SERVER_PID_NO" 2>/dev/null || true
    [ -n "$SERVER_PID_SIBLING" ] && kill -9 "$SERVER_PID_SIBLING" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
    rm -f "$DIR"/server_sibling_*.log
}
trap cleanup EXIT INT TERM

sleep 1

# -------------------------------------------------------------
# Test 1: additional-from-auth yes (BIND compatible)
# -------------------------------------------------------------
echo "[*] Starting KariDNS with additional-from-auth yes on port 10053..."
$BIN -f -c "$CONF_YES" > "$DIR/server_sibling_yes.log" 2>&1 &
SERVER_PID_YES=$!
sleep 2

if ! kill -0 "$SERVER_PID_YES" 2>/dev/null; then
    echo "[FAIL] Server (yes) failed to start. Log output:"
    cat "$DIR/server_sibling_yes.log" 2>/dev/null || true
    exit 1
fi

echo "[*] Querying NS example.jp on port 10053..."
OUT_YES=$($DAG NS example.jp @127.0.0.1 -p 10053)
echo "$OUT_YES"

# Verify Answer section
if ! echo "$OUT_YES" | grep -q "ns1.v6.example.com"; then
    echo "[FAIL] NS record ns1.v6.example.com missing in Answer!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.sub.example.net"; then
    echo "[FAIL] NS record ns1.sub.example.net missing in Answer!"
    exit 1
fi
if ! echo "$OUT_YES" | grep -q "ns1.city.example.jp"; then
    echo "[FAIL] NS record ns1.city.example.jp missing in Answer!"
    exit 1
fi

# Verify Additional section (all 5 records must be present)
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

killall -9 karidns 2>/dev/null || true
SERVER_PID_YES=""
sleep 1

# -------------------------------------------------------------
# Test 2: additional-from-auth in-domain
# -------------------------------------------------------------
echo "[*] Starting KariDNS with additional-from-auth in-domain on port 10054..."
$BIN -f -c "$CONF_INDOMAIN" > "$DIR/server_sibling_indomain.log" 2>&1 &
SERVER_PID_IN=$!
sleep 2

if ! kill -0 "$SERVER_PID_IN" 2>/dev/null; then
    echo "[FAIL] Server (in-domain) failed to start. Log output:"
    cat "$DIR/server_sibling_indomain.log" 2>/dev/null || true
    exit 1
fi

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

killall -9 karidns 2>/dev/null || true
SERVER_PID_IN=""
sleep 1

# -------------------------------------------------------------
# Test 3: additional-from-auth no
# -------------------------------------------------------------
echo "[*] Starting KariDNS with additional-from-auth no on port 10055..."
$BIN -f -c "$CONF_NO" > "$DIR/server_sibling_no.log" 2>&1 &
SERVER_PID_NO=$!
sleep 2

if ! kill -0 "$SERVER_PID_NO" 2>/dev/null; then
    echo "[FAIL] Server (no) failed to start. Log output:"
    cat "$DIR/server_sibling_no.log" 2>/dev/null || true
    exit 1
fi

echo "[*] Querying NS example.jp on port 10055..."
OUT_NO=$($DAG NS example.jp @127.0.0.1 -p 10055)
echo "$OUT_NO"

# No address records in Additional section
if echo "$OUT_NO" | grep -E "192.0.2.15|192.0.2.86|192.0.2.60"; then
    echo "[FAIL] Address records were returned in Additional section when additional-from-auth is no!"
    exit 1
fi

echo "[PASS] Test 3: additional-from-auth no returned 0 Additional address records!"

killall -9 karidns 2>/dev/null || true
SERVER_PID_NO=""
sleep 1

# -------------------------------------------------------------
# Test 4: Sibling domain dynamic resolution with example domains
# -------------------------------------------------------------
echo "[*] Starting KariDNS for example-parent.jp & example-sibling.jp on port 10056..."
$BIN -f -c "$CONF_SIBLING" > "$DIR/server_sibling_dyn.log" 2>&1 &
SERVER_PID_SIBLING=$!
sleep 2

if ! kill -0 "$SERVER_PID_SIBLING" 2>/dev/null; then
    echo "[FAIL] Server (sibling dynamic) failed to start. Log output:"
    cat "$DIR/server_sibling_dyn.log" 2>/dev/null || true
    exit 1
fi

echo "[*] Querying NS example-parent.jp on port 10056..."
OUT_SIBLING=$($DAG NS example-parent.jp @127.0.0.1 -p 10056)
echo "$OUT_SIBLING"

# Verify all Additional records
if ! echo "$OUT_SIBLING" | grep -q "ns-ext.example.org.*192.0.2.88"; then
    echo "[FAIL] A record for ns-ext.example.org missing in Additional!"
    exit 1
fi
if ! echo "$OUT_SIBLING" | grep -q "ns-ext.example.org.*2001:db8:1::88"; then
    echo "[FAIL] AAAA record for ns-ext.example.org missing in Additional!"
    exit 1
fi
if ! echo "$OUT_SIBLING" | grep -q "ns1.city.example-parent.jp.*192.0.2.61"; then
    echo "[FAIL] A record for ns1.city.example-parent.jp missing in Additional!"
    exit 1
fi
if ! echo "$OUT_SIBLING" | grep -q "ns-sibling.v6.example-sibling.jp.*198.51.100.226"; then
    echo "[FAIL] Sibling A record for ns-sibling.v6.example-sibling.jp missing in Additional!"
    exit 1
fi
if ! echo "$OUT_SIBLING" | grep -q "ns-sibling.v6.example-sibling.jp.*2001:db8:2::226"; then
    echo "[FAIL] Sibling AAAA record for ns-sibling.v6.example-sibling.jp missing in Additional!"
    exit 1
fi

echo "[PASS] Test 4: Sibling domain (ns-sibling.v6.example-sibling.jp A/AAAA) successfully resolved in Additional!"

killall -9 karidns 2>/dev/null || true
SERVER_PID_SIBLING=""

echo "[ALL PASS] Sibling domain Additional glue test suite passed successfully!"
exit 0

