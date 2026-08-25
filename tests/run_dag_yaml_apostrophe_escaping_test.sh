#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) YAML Single-Quote / Apostrophe Escaping Regression Test Suite
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

PORT=$((15000 + $$ % 10000))
TMP_DIR="/tmp/karidns_yaml_esc_test_$$"
mkdir -p "$TMP_DIR"
CONF_FILE="$TMP_DIR/karidns.conf"
ZONE_FILE="$TMP_DIR/example.com.zone"

cat <<'EOF' > "$ZONE_FILE"
$ORIGIN example.com.
$TTL 300
@       IN SOA  ns1.example.com. hostmaster.example.com. (
                2026071001 3600 900 1209600 86400 )
        IN NS   ns1.example.com.
ns1     IN A    192.0.2.1

txt1    IN TXT  "it's a test"
txt2    IN TXT  "O'Reilly \"Special\" Edition"
txt3    IN TXT  "multiple ' single ' quotes ' here"
it's    IN A    192.0.2.123
EOF

cat <<EOF > "$CONF_FILE"
options {
    port $PORT;
    bind-address { 127.0.0.1; };
};

zone "example.com" {
    type master;
    file "$ZONE_FILE";
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

echo "=== 1. Testing YAML Escaping for Apostrophes in TXT RDATA ==="
run_check "Single apostrophe in TXT record" \
    "$DAG @127.0.0.1 -p $PORT txt1.example.com TXT +yaml" \
    "it''s a test"

run_check "Apostrophe and double-quotes in TXT record" \
    "$DAG @127.0.0.1 -p $PORT txt2.example.com TXT +yaml" \
    "O''Reilly"

run_check "Multiple apostrophes in TXT record" \
    "$DAG @127.0.0.1 -p $PORT txt3.example.com TXT +yaml" \
    "multiple '' single '' quotes '' here"

echo "=== 2. Testing YAML Escaping for Apostrophes in Domain Names ==="
run_check "Apostrophe in question section domain name" \
    "$DAG @127.0.0.1 -p $PORT it\\'s.example.com A +yaml" \
    "it''s\.example\.com"

run_check "Apostrophe in answer section domain name" \
    "$DAG @127.0.0.1 -p $PORT it\\'s.example.com A +yaml" \
    "it''s\.example\.com.*192\.0\.2\.123"

echo "=== 3. Testing Semantic YAML Parsability via Perl ==="
OUTPUT_YAML="$TMP_DIR/out.yaml"
$DAG @127.0.0.1 -p $PORT txt1.example.com TXT +yaml > "$OUTPUT_YAML" 2>&1 || true

if command -v perl >/dev/null 2>&1; then
    echo -n "Test: Perl YAML single-quote syntax validation ... "
    cat <<'PL_EOF' > "$TMP_DIR/check_yaml.pl"
my $file = $ARGV[0];
open(my $fh, "<", $file) or die "Cannot open $file: $!";
my $in_msg = 0;
my $valid_lines = 0;
while (my $line = <$fh>) {
    chomp $line;
    if ($line =~ /^- type:\s+MESSAGE/) { $in_msg = 1; }
    if ($line =~ /^\s+-\s+/) {
        if ($line =~ /^\s+-\s+'((?:[^']|'')*)'\s*$/) {
            $valid_lines++;
        } else {
            die "Invalid YAML single-quoted line: $line\n";
        }
    }
}
close($fh);
if (!$in_msg) { die "No '- type: MESSAGE' found in $file\n"; }
if ($valid_lines == 0) { die "No valid record lines found in $file\n"; }
exit 0;
PL_EOF

    if ERR=$(perl "$TMP_DIR/check_yaml.pl" "$OUTPUT_YAML" 2>&1); then
        echo "OK"
    else
        echo "FAILED"
        echo "  Error: $ERR"
        echo "  YAML Content:"
        sed 's/^/    /' "$OUTPUT_YAML"
        FAILED=$((FAILED + 1))
    fi
else
    echo "Test: Perl YAML syntax validation ... SKIP (perl not available)"
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL YAML APOSTROPHE ESCAPING TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED YAML APOSTROPHE ESCAPING TESTS FAILED!"
    exit 1
fi
