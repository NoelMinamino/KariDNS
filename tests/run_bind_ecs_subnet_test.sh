#!/bin/sh
set -e

# ==============================================================================
# KariDNS BIND Zone $ECS-SUBNET Directive Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICHECK="${BIN_DIR}/karicheck"
DAG="${DAG:-$BIN_DIR/dag}"

killall -9 karidns karidns-asan 2>/dev/null || true

TMP_DIR="$(mktemp -d /tmp/karidns_bind_ecs_test.XXXXXX)"
SERVER_PID=""
SERVER_UNTRUSTED_PID=""
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
    if [ -n "$SERVER_UNTRUSTED_PID" ]; then
        kill -9 "$SERVER_UNTRUSTED_PID" 2>/dev/null || true
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

PORT=$((31500 + $$ % 3000))
PORT_UNTRUSTED=$((PORT + 1))
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
    FLAT_OUTPUT=$(echo "$OUTPUT" | tr '\n' ' ' | sed 's/[[:space:]]*$//')
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

echo "=== 0. Setting up test files for \$ECS-SUBNET directive ==="

# Zone 1: Global tag matching & defaults
cat << 'EOF' > "$TMP_DIR/example.zone"
$TTL 300
$ORIGIN example.com.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1

$ECS-SUBNET us
www     IN  A   192.0.2.1

$ECS-SUBNET eu
www     IN  A   192.0.2.2

$ECS-SUBNET jp
www     IN  A   192.0.2.10

$ECS-SUBNET default
www     IN  A   192.0.2.3

$ECS-SUBNET none
mail    IN  A   192.0.2.25
EOF

# Zone 2: Zone-level override of ecs-tags
cat << 'EOF' > "$TMP_DIR/cdn.zone"
$TTL 300
$ORIGIN cdn.example.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 900 1209600 300 )
        IN  NS  ns1.example.com.

$ECS-SUBNET us-east
edge    IN  A   192.0.2.101

$ECS-SUBNET us-west
edge    IN  A   192.0.2.102

$ECS-SUBNET eu
edge    IN  A   192.0.2.103

$ECS-SUBNET default
edge    IN  A   192.0.2.199
EOF

# Zone 3: $INCLUDE penetration test
cat << 'EOF' > "$TMP_DIR/inc_child.zone"
$ECS-SUBNET us
child-us IN A 192.0.2.50
EOF

cat << 'EOF' > "$TMP_DIR/inc_parent.zone"
$TTL 300
$ORIGIN inc.example.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 900 1209600 300 )
        IN  NS  ns1.example.com.

$INCLUDE inc_child.zone
after-include IN A 192.0.2.51
$ECS-SUBNET default
after-include IN A 192.0.2.52
EOF

# Zone 4: tinydns zone non-interference
cat << 'EOF' > "$TMP_DIR/tiny.data"
.tiny.test:127.0.0.1:ns1.tiny.test:2560
+www.tiny.test:1.2.3.4:300
EOF

# Zone 5: Invalid tag for karicheck test
cat << 'EOF' > "$TMP_DIR/invalid_tag.zone"
$TTL 300
$ORIGIN invalid.test.
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 1 3600 900 1209600 300 )
        IN  NS  ns1.example.com.

$ECS-SUBNET undefined_tag
bad     IN  A   192.0.2.99
EOF

# Valid Server Config
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 127.0.0.1; };
    ecs-tags {
        tag "us" { 8.8.8.0/24; 1.1.1.0/24; };
        tag "eu" { 5.6.7.0/24; 2001:db8:ee::/32; };
        tag "jp" { 203.0.113.0/24; };
    };
};

zone "example.com." {
    type master;
    file "$TMP_DIR/example.zone";
};

zone "cdn.example." {
    type master;
    file "$TMP_DIR/cdn.zone";
    ecs-tags {
        tag "us-east" { 8.8.8.0/24; };
        tag "us-west" { 1.2.3.0/24; };
        tag "eu" { 5.6.7.0/24; };
    };
};

zone "inc.example." {
    type master;
    file "$TMP_DIR/inc_parent.zone";
};

zone "tiny.test." {
    type master;
    file "$TMP_DIR/tiny.data";
    file-format tinydns;
};
EOF

# Invalid Config 1: Undefined tag in zone file
cat << EOF > "$TMP_DIR/conf_invalid_tag.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 127.0.0.1; };
    ecs-tags {
        tag "us" { 8.8.8.0/24; };
    };
};

zone "invalid.test." {
    type master;
    file "$TMP_DIR/invalid_tag.zone";
};
EOF

# Invalid Config 2: Invalid CIDR syntax
cat << EOF > "$TMP_DIR/conf_invalid_cidr.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 127.0.0.1; };
    ecs-tags {
        tag "us" { 8.8.8.0/35; };
    };
};

zone "example.com." {
    type master;
    file "$TMP_DIR/example.zone";
};
EOF

# Config with ecs-tags but ecs-enable no (should trigger WARNING)
cat << EOF > "$TMP_DIR/conf_ecs_disabled_warning.conf"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable no;
    ecs-tags {
        tag "us" { 8.8.8.0/24; };
    };
};

zone "example.com." {
    type master;
    file "$TMP_DIR/example.zone";
};
EOF

# Untrusted resolver config (127.0.0.1 is not in ecs-trusted-resolvers)
cat << EOF > "$TMP_DIR/conf_untrusted.conf"
options {
    port $PORT_UNTRUSTED;
    bind-address { 127.0.0.1; };
    $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 10.0.0.53; };
    ecs-tags {
        tag "us" { 8.8.8.0/24; 1.1.1.0/24; };
        tag "eu" { 5.6.7.0/24; 2001:db8:ee::/32; };
        tag "jp" { 203.0.113.0/24; };
    };
};

zone "example.com." {
    type master;
    file "$TMP_DIR/example.zone";
};
EOF

echo "=== 1. Validating configuration with karicheck ==="
run_check "karicheck conf valid" "$KARICHECK conf $TMP_DIR/karidns.conf" "\[OK\] Config file .* is valid\."
run_check "karicheck zones valid" "$KARICHECK zones $TMP_DIR/karidns.conf" "\[INFO\] Checked 4 zones\. Errors: 0"

run_check "karicheck conf detects undefined tag in zone" \
    "$KARICHECK zones $TMP_DIR/conf_invalid_tag.conf 2>&1 || true" \
    "references undefined ECS subnet tag 'undefined_tag'"

run_check "karicheck conf detects invalid CIDR (/35)" \
    "$KARICHECK conf $TMP_DIR/conf_invalid_cidr.conf 2>&1 || true" \
    "Invalid CIDR '8\.8\.8\.0/35'"

run_check "karicheck conf warning when ecs-tags defined but ecs-enable no" \
    "$KARICHECK conf $TMP_DIR/conf_ecs_disabled_warning.conf 2>&1 || true" \
    "\[WARNING\] ecs-tags defined, but ecs-enable is not set to 'yes'"

echo "=== 2. Starting KariDNS on port $PORT ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: KariDNS failed to start. Logs:"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

echo "=== 3. Testing Global Tag Matching (\$ECS-SUBNET us/eu/jp/default) ==="

# US tag: 8.8.8.0/24
run_check "US client gets 'us' (192.0.2.1) and 'default' (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=8.8.8.50" \
    "192\.0\.2\.1.*192\.0\.2\.3|192\.0\.2\.3.*192\.0\.2\.1"

run_check_not "US client does not get 'eu' or 'jp'" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=8.8.8.50" \
    "192\.0\.2\.2|192\.0\.2\.10"

# EU tag (IPv4): 5.6.7.0/24
run_check "EU client gets 'eu' (192.0.2.2) and 'default' (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=5.6.7.88" \
    "192\.0\.2\.2.*192\.0\.2\.3|192\.0\.2\.3.*192\.0\.2\.2"

run_check_not "EU client does not get 'us' or 'jp'" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=5.6.7.88" \
    "192\.0\.2\.1$|192\.0\.2\.10"

# EU tag (IPv6): 2001:db8:ee::/32
run_check "EU IPv6 client gets 'eu' (192.0.2.2) and 'default' (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=2001:db8:ee:1234::1" \
    "192\.0\.2\.2.*192\.0\.2\.3|192\.0\.2\.3.*192\.0\.2\.2"

# JP tag: 203.0.113.0/24
run_check "JP client gets 'jp' (192.0.2.10) and 'default' (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=203.0.113.5" \
    "192\.0\.2\.10.*192\.0\.2\.3|192\.0\.2\.3.*192\.0\.2\.10"

# Untagged subnet: 198.51.100.0/24 (no tag match -> default only)
run_check "Unknown subnet gets only 'default' (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=198.51.100.1" \
    "^192\.0\.2\.3$"

run_check_not "Unknown subnet does not get tagged records" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +subnet=198.51.100.1" \
    "192\.0\.2\.1|192\.0\.2\.2|192\.0\.2\.10"

# Query without ECS (+nosubnet) gets only 'default'
run_check "Query without ECS gets only 'default' (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT +short +nosubnet" \
    "^192\.0\.2\.3$"

# $ECS-SUBNET none record (mail) is unrestricted
run_check "'none' record is returned to any client" \
    "$DAG mail.example.com A @127.0.0.1 -p $PORT +short +subnet=8.8.8.1" \
    "^192\.0\.2\.25$"

echo "=== 4. Testing Zone-Level Override of ecs-tags ==="

# cdn.example has zone-level ecs-tags (us-east: 8.8.8.0/24, us-west: 1.2.3.0/24, eu: 5.6.7.0/24)
run_check "cdn.example: 8.8.8.0/24 matches 'us-east' (192.0.2.101)" \
    "$DAG edge.cdn.example A @127.0.0.1 -p $PORT +short +subnet=8.8.8.1" \
    "192\.0\.2\.101.*192\.0\.2\.199|192\.0\.2\.199.*192\.0\.2\.101"

run_check "cdn.example: 1.2.3.0/24 matches 'us-west' (192.0.2.102)" \
    "$DAG edge.cdn.example A @127.0.0.1 -p $PORT +short +subnet=1.2.3.4" \
    "192\.0\.2\.102.*192\.0\.2\.199|192\.0\.2\.199.*192\.0\.2\.102"

# In global tags, 203.0.113.0/24 is 'jp', but cdn.example overrides tags and has NO 'jp' tag.
# It MUST NOT fall back to global tags! It must get only 'default' (192.0.2.199).
run_check "cdn.example does NOT fall back to global 'jp' tag" \
    "$DAG edge.cdn.example A @127.0.0.1 -p $PORT +short +subnet=203.0.113.5" \
    "^192\.0\.2\.199$"

echo "=== 5. Testing \$INCLUDE penetration ==="

# inc_child.zone sets $ECS-SUBNET us.
# after-include in inc_parent.zone has 192.0.2.51 (under us) and 192.0.2.52 (under default).
run_check "\$INCLUDE penetrates tag to parent: US client gets 192.0.2.51 & 192.0.2.52" \
    "$DAG after-include.inc.example A @127.0.0.1 -p $PORT +short +subnet=8.8.8.1" \
    "192\.0\.2\.51.*192\.0\.2\.52|192\.0\.2\.52.*192\.0\.2\.51"

run_check "\$INCLUDE penetrates tag: EU client gets only default (192.0.2.52)" \
    "$DAG after-include.inc.example A @127.0.0.1 -p $PORT +short +subnet=5.6.7.1" \
    "^192\.0\.2\.52$"

echo "=== 6. Testing Fail-Closed Security (Untrusted Resolvers) ==="

# (a) If alias IP 127.0.0.2 is available on main server (where only 127.0.0.1 is trusted):
if [ "$ALIAS_ADDED" = "1" ]; then
    run_check "Client from untrusted alias IP 127.0.0.2 gets only default" \
        "$DAG www.example.com A @127.0.0.1 -p $PORT -b $ALIAS_IP +short +subnet=8.8.8.1" \
        "^192\.0\.2\.3$"
fi

echo "=== 7. Testing tinydns Non-Interference ==="
run_check "tinydns zone answers query regardless of ECS" \
    "$DAG www.tiny.test A @127.0.0.1 -p $PORT +short +subnet=8.8.8.1" \
    "^1\.2\.3\.4$"

echo "=== 8. Testing Fail-Closed with Untrusted Server Config (Single-Instance Restart) ==="
# Stop main server (frontend and capsicum backend) before starting untrusted instance
killall -9 karidns karidns-asan 2>/dev/null || true
sleep 1

"$KARIDNS" -f "$TMP_DIR/conf_untrusted.conf" > "$TMP_DIR/karidns_untrusted.log" 2>&1 &
SERVER_UNTRUSTED_PID=$!
sleep 1

if ! kill -0 "$SERVER_UNTRUSTED_PID" 2>/dev/null; then
    echo "ERROR: Untrusted KariDNS failed to start. Logs:"
    cat "$TMP_DIR/karidns_untrusted.log"
    exit 1
fi

run_check "Untrusted resolver query with ECS gets ONLY default (192.0.2.3)" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT_UNTRUSTED +short +subnet=8.8.8.1" \
    "^192\.0\.2\.3$"

run_check_not "Untrusted resolver query never sees tagged records" \
    "$DAG www.example.com A @127.0.0.1 -p $PORT_UNTRUSTED +short +subnet=8.8.8.1" \
    "192\.0\.2\.1"

kill -9 "$SERVER_UNTRUSTED_PID" 2>/dev/null || true
wait "$SERVER_UNTRUSTED_PID" 2>/dev/null || true
SERVER_UNTRUSTED_PID=""

echo "=== 8. Test Summary ==="
if [ "$FAILED" -eq 0 ]; then
    echo "ALL TESTS PASSED!"
    exit 0
else
    echo "SOME TESTS FAILED: $FAILED failure(s)"
    exit 1
fi
