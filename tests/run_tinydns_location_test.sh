#!/bin/sh
set -e

# ==============================================================================
# KariDNS tinydns Location Directive (%) Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICHECK="${BIN_DIR}/karicheck"
DAG="${DAG:-$BIN_DIR/dag}"

killall -9 karidns karidns-asan 2>/dev/null || true

TMP_DIR="$(mktemp -d /tmp/karidns_tinydns_loc_test.XXXXXX)"
SERVER_PID=""
ALIAS_IP="127.0.0.2"
ALIAS_ADDED=0

if [ "$(id -u)" = "0" ]; then
    if ifconfig lo0 inet "$ALIAS_IP" netmask 255.0.0.0 alias 2>/dev/null; then
        ALIAS_ADDED=1
        echo "=== Added alias $ALIAS_IP to lo0 for client source IP testing ==="
    fi
fi

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    if [ "$ALIAS_ADDED" = "1" ]; then
        ifconfig lo0 inet "$ALIAS_IP" netmask 255.0.0.0 -alias 2>/dev/null || true
        echo "=== Removed alias $ALIAS_IP from lo0 ==="
    fi
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((31000 + $$ % 4000))
FAILED=0
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECTED="$3"

    echo -n "Test: $NAME ... "
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    FLAT_OUTPUT=$(echo "$OUTPUT" | tr '\n' ' ')
    if echo "$FLAT_OUTPUT" | grep -E -q "$EXPECTED"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
}

run_check_not() {
    NAME="$1"
    CMD="$2"
    UNEXPECTED="$3"

    echo -n "Test: $NAME ... "
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUTPUT" | grep -E -q "$UNEXPECTED"; then
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Unexpected pattern found: $UNEXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    else
        echo "OK"
    fi
}

echo "=== Setting up test zones for tinydns location evaluation ==="

# Zone 1: Client 127.0.0.1 matches %in, 127.0.0.2 matches %ex
cat << 'EOF' > "$TMP_DIR/zone1.data"
%in:127.0.0.1
%ex:127.0.0.2
.zone1.test:127.0.0.1:ns1.zone1.test:2560
+www.zone1.test:192.168.1.10:300::in
+www.zone1.test:10.0.0.10:300::ex
+www.zone1.test:1.2.3.4:300
+inonly.zone1.test:192.168.1.20:300::in
+exonly.zone1.test:10.0.0.20:300::ex
EOF

# Zone 2: Client 127.0.0.1 matches %ex
cat << 'EOF' > "$TMP_DIR/zone2.data"
%in:10.0.0.1
%ex:127.0.0.1
.zone2.test:127.0.0.1:ns1.zone2.test:2560
+www.zone2.test:192.168.1.10:300::in
+www.zone2.test:10.0.0.10:300::ex
+inonly.zone2.test:192.168.1.20:300::in
+exonly.zone2.test:10.0.0.20:300::ex
EOF

# Zone 3: Longest Prefix Match (LPM): %p1 (127) vs %p4 (127.0.0.1)
cat << 'EOF' > "$TMP_DIR/zone3.data"
%p1:127
%p4:127.0.0.1
.zone3.test:127.0.0.1:ns1.zone3.test:2560
+lpm.zone3.test:192.168.1.1:300::p1
+lpm.zone3.test:192.168.1.4:300::p4
EOF

# Zone 4: Default catch-all location (%df) vs unmatched specific prefix (%sp:10)
cat << 'EOF' > "$TMP_DIR/zone4.data"
%df
%sp:10
.zone4.test:127.0.0.1:ns1.zone4.test:2560
+target.zone4.test:192.168.4.1:300::df
+target.zone4.test:192.168.4.2:300::sp
EOF

# Zone 5: Standard BIND zone
cat << 'EOF' > "$TMP_DIR/bind.zone"
$TTL 300
@ IN SOA ns1.bind.test. hostmaster.bind.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.bind.test.
ns1 IN A 127.0.0.1
www IN A 192.168.1.100
EOF

cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

zone "zone1.test." {
    type master;
    file "$TMP_DIR/zone1.data";
    file-format tinydns;
};

zone "zone2.test." {
    type master;
    file "$TMP_DIR/zone2.data";
    file-format tinydns;
};

zone "zone3.test." {
    type master;
    file "$TMP_DIR/zone3.data";
    file-format tinydns;
};

zone "zone4.test." {
    type master;
    file "$TMP_DIR/zone4.data";
    file-format tinydns;
};

zone "bind.test." {
    type master;
    file "$TMP_DIR/bind.zone";
    file-format bind;
};
EOF

echo "=== Validating configuration with karicheck ==="
run_check "karicheck conf" "$KARICHECK conf $TMP_DIR/karidns.conf" "is valid"

echo "=== Starting KariDNS on port $PORT ==="
$KARIDNS -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: KariDNS failed to start. Logs:"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

echo "=== 1. Zone 1 (Client is 'in' via 127.0.0.1): in-records and unrestricted records match, ex excluded ==="
run_check "zone1 inonly matches" \
    "$DAG inonly.zone1.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.20"

run_check "zone1 exonly returns NXDOMAIN" \
    "$DAG exonly.zone1.test A @127.0.0.1 -p $PORT" \
    "status: NXDOMAIN"

run_check "zone1 www returns 'in' (192.168.1.10) and unrestricted (1.2.3.4)" \
    "$DAG www.zone1.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.10.*1.2.3.4|1.2.3.4.*192.168.1.10"

run_check_not "zone1 www does NOT contain 'ex' (10.0.0.10)" \
    "$DAG www.zone1.test A @127.0.0.1 -p $PORT +short" \
    "10\.0\.0\.10"

echo "=== 2. Zone 2 (Client is 'ex' via 127.0.0.1): ex-records match, in excluded ==="
run_check "zone2 exonly matches" \
    "$DAG exonly.zone2.test A @127.0.0.1 -p $PORT +short" \
    "10.0.0.20"

run_check "zone2 inonly returns NXDOMAIN" \
    "$DAG inonly.zone2.test A @127.0.0.1 -p $PORT" \
    "status: NXDOMAIN"

run_check "zone2 www returns 'ex' (10.0.0.10)" \
    "$DAG www.zone2.test A @127.0.0.1 -p $PORT +short" \
    "10.0.0.10"

echo "=== 3. Zone 3 (Longest Prefix Match): /32 beats /8 ==="
run_check "zone3 lpm returns /32 match (192.168.1.4)" \
    "$DAG lpm.zone3.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.4"

echo "=== 4. Zone 4 (Catch-all location): %df matches when no specific prefix matches ==="
run_check "zone4 catch-all matches 'df' (192.168.4.1)" \
    "$DAG target.zone4.test A @127.0.0.1 -p $PORT +short" \
    "192.168.4.1"

echo "=== 5. BIND zone regression check -> Unaffected ==="
run_check "BIND zone query returns A 192.168.1.100" \
    "$DAG www.bind.test A @127.0.0.1 -p $PORT +short" \
    "192.168.1.100"

echo "=== 6. Multi-Source IP Test (via 127.0.0.2 alias) ==="
if [ "$ALIAS_ADDED" = "1" ] || $DAG www.zone1.test A @127.0.0.1 -p $PORT -b "$ALIAS_IP" >/dev/null 2>&1; then
    run_check "zone1 from 127.0.0.2 returns 'ex' (10.0.0.10) and unrestricted (1.2.3.4)" \
        "$DAG www.zone1.test A @127.0.0.1 -p $PORT -b $ALIAS_IP +short" \
        "10.0.0.10.*1.2.3.4|1.2.3.4.*10.0.0.10"

    run_check_not "zone1 from 127.0.0.2 does NOT contain 'in' (192.168.1.10)" \
        "$DAG www.zone1.test A @127.0.0.1 -p $PORT -b $ALIAS_IP +short" \
        "192\.168\.1\.10"

    run_check "zone1 exonly from 127.0.0.2 returns 10.0.0.20" \
        "$DAG exonly.zone1.test A @127.0.0.1 -p $PORT -b $ALIAS_IP +short" \
        "10.0.0.20"

    run_check "zone1 inonly from 127.0.0.2 returns NXDOMAIN" \
        "$DAG inonly.zone1.test A @127.0.0.1 -p $PORT -b $ALIAS_IP" \
        "status: NXDOMAIN"
else
    echo "Skipping 127.0.0.2 alias test (not running as root or alias not available)"
fi

if [ $FAILED -gt 0 ]; then
    echo "=================================================="
    echo " $FAILED tests failed!"
    echo "=================================================="
    exit 1
else
    echo "=================================================="
    echo " All tinydns location tests passed successfully!"
    echo "=================================================="
    exit 0
fi
