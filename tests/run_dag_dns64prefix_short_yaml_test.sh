#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +dns64prefix in +short and +yaml Mode Validation Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag and karidns with make ==="
make -C "$ROOT_DIR" dag karidns

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"
KARIDNS="${KARIDNS:-$ROOT_DIR/karidns}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$ROOT_DIR/dag"
    fi
fi

if [ ! -x "$KARIDNS" ]; then
    KARIDNS="./karidns"
fi
if [ ! -x "$KARIDNS" ]; then
    echo "Error: karidns binary not found at $KARIDNS"
    exit 1
fi

FAILED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    echo -n "Test: $NAME ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$EXPECT"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

PORT=$((16000 + $$ % 10000))
TMP_DIR="/tmp/karidns_dns64_test_$$"
mkdir -p "$TMP_DIR"
CONF_FILE="$TMP_DIR/karidns.conf"
ZONE_ARPA="$TMP_DIR/ipv4only.arpa.zone"
ZONE_EX="$TMP_DIR/example.com.zone"

cat <<'EOF' > "$ZONE_ARPA"
$ORIGIN ipv4only.arpa.
$TTL 300
@       IN SOA  ns1.ipv4only.arpa. hostmaster.ipv4only.arpa. (
                2026071001 3600 900 1209600 86400 )
        IN NS   ns1.ipv4only.arpa.
ns1     IN AAAA 64:ff9b::1
@       IN AAAA 64:ff9b::192.0.0.170
@       IN AAAA 64:ff9b::192.0.0.171
EOF

cat <<'EOF' > "$ZONE_EX"
$ORIGIN example.com.
$TTL 300
@       IN SOA  ns1.example.com. hostmaster.example.com. (
                2026071001 3600 900 1209600 86400 )
        IN NS   ns1.example.com.
ns1     IN A    192.0.2.1
www     IN A    192.0.2.10
EOF

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

zone "ipv4only.arpa" {
    type master;
    file "$ZONE_ARPA";
};

zone "example.com" {
    type master;
    file "$ZONE_EX";
};
EOF

"$KARIDNS" -f "$CONF_FILE" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

echo "=== 1. Testing Standard +dns64prefix Output ==="
run_check "Standard query with +dns64prefix" \
    "$DAG @127.0.0.1 -p $PORT www.example.com A +dns64prefix" \
    "64:ff9b::/96"

echo "=== 2. Testing +short +dns64prefix Mode Contract ==="
run_check "Short mode with +dns64prefix returns only clean data" \
    "$DAG @127.0.0.1 -p $PORT www.example.com A +short +dns64prefix" \
    "64:ff9b::/96"

echo -n "Test: Short mode contains no comments/headers ... "
SHORT_OUT=$($DAG @127.0.0.1 -p $PORT www.example.com A +short +dns64prefix 2>&1 || true)
if echo "$SHORT_OUT" | grep -q "^;"; then
    echo "FAILED"
    echo "  Unexpected comment line found in +short output:"
    echo "$SHORT_OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

echo "=== 3. Testing +yaml +dns64prefix Mode Contract ==="
run_check "YAML mode with +dns64prefix contains prefix 64:ff9b::/96" \
    "$DAG @127.0.0.1 -p $PORT www.example.com A +yaml +dns64prefix" \
    "64:ff9b::/96"

YAML_OUT="$TMP_DIR/out.yaml"
$DAG @127.0.0.1 -p $PORT www.example.com A +yaml +dns64prefix > "$YAML_OUT" 2>&1 || true

if command -v perl >/dev/null 2>&1; then
    echo -n "Test: Perl YAML structure validation for +dns64prefix +yaml ... "
    cat <<'PL_EOF' > "$TMP_DIR/check_yaml.pl"
my $file = $ARGV[0];
open(my $fh, "<", $file) or die "Cannot open $file: $!";
my $has_prefix = 0;
my $msg_count = 0;
while (my $line = <$fh>) {
    chomp $line;
    if ($line =~ /^\s*64:ff9b::\/96/) { $has_prefix = 1; }
    if ($line =~ /^- type:\s+MESSAGE/) { $msg_count++; }
    if ($line =~ /^;/) {
        die "Unexpected comment line in YAML output: $line\n";
    }
}
close($fh);
if (!$has_prefix) { die "DNS64 prefix 64:ff9b::/96 not found in YAML output\n"; }
if ($msg_count == 0) { die "No MESSAGE document found in YAML output\n"; }
exit 0;
PL_EOF

    if ERR=$(perl "$TMP_DIR/check_yaml.pl" "$YAML_OUT" 2>&1); then
        echo "OK"
    else
        echo "FAILED"
        echo "  Error: $ERR"
        echo "  YAML Content:"
        sed 's/^/    /' "$YAML_OUT"
        FAILED=$((FAILED + 1))
    fi
else
    echo "Test: Perl YAML structure validation ... SKIP (perl not available)"
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL DNS64PREFIX SHORT/YAML TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED DNS64PREFIX SHORT/YAML TESTS FAILED!"
    exit 1
fi
