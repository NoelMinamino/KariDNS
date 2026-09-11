#!/bin/sh
# ==============================================================================
# run_dag_replay_diff_test.sh
#
# Integration test for dag DNS Replay and Differential Testing engine.
# Tests text query file replay, differential comparison across two servers,
# order-independent RRset comparison, --ignore-ttl, --stop-after, --output-diff,
# and positive detection of DIFF_GLUE_MISSING, DIFF_CNAME_CHAIN, DIFF_DNSSEC_*.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$BASE_DIR"

PORT1=${KARIDNS_REPLAY_PORT1:-$((28000 + $$ % 1000))}
PORT2=$((PORT1 + 1))

TMP_DIR="$(mktemp -d /tmp/karidns_replay_test.XXXXXX)"
CONF1="$TMP_DIR/server1.conf"
CONF2="$TMP_DIR/server2.conf"
ZONE1="$TMP_DIR/server1.zone"
ZONE2="$TMP_DIR/server2.zone"
QUERY_FILE="$TMP_DIR/queries.txt"
PID1=""
PID2=""
LOG1="$TMP_DIR/server1.log"
LOG2="$TMP_DIR/server2.log"

cleanup() {
    [ -n "$PID1" ] && kill "$PID1" 2>/dev/null || true
    [ -n "$PID2" ] && kill "$PID2" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

echo "=== Running dag DNS Replay & Differential Testing Suite ==="

# Build binaries
echo "[+] Building karidns..."
make karidns
echo "[+] Building dag..."
make dag

# 1. Prepare Zones
# Zone 1
cat << 'EOF' > "$ZONE1"
$ORIGIN example.com.
$TTL 300
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1
match1  IN  A   192.0.2.1
match2  IN  A   192.0.2.2
differ  IN  A   192.0.2.10

; Shuffled RRset test
round   IN  A   192.0.2.1
round   IN  A   192.0.2.2

; TTL difference test
ttltest 300 IN A 192.0.2.50

; Delegation and Glue
sub     IN  NS  ns.sub.example.com.
ns.sub  IN  A   192.0.2.77

; CNAME Chain test
cnamechain IN CNAME target1.example.com.
target1    IN A     192.0.2.88

; DNSSEC records
sec     300 IN A     192.0.2.90
sec     300 IN RRSIG A 13 3 300 20300101000000 20260101000000 12345 example.com. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
sec     300 IN NSEC  next.example.com. A RRSIG NSEC
EOF

# Zone 2 (differing records)
cat << 'EOF' > "$ZONE2"
$ORIGIN example.com.
$TTL 300
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1
match1  IN  A   192.0.2.1
match2  IN  A   192.0.2.2
differ  IN  A   192.0.2.99

; Shuffled RRset test (order reversed)
round   IN  A   192.0.2.2
round   IN  A   192.0.2.1

; TTL difference test (600 vs 300)
ttltest 600 IN A 192.0.2.50

; Delegation missing glue
sub     IN  NS  ns.sub.example.com.

; CNAME Chain test (different target)
cnamechain IN CNAME target2.example.com.
target2    IN A     192.0.2.89

; DNSSEC test (missing RRSIG and NSEC)
sec     300 IN A     192.0.2.90
EOF

# 2. Prepare Configs
cat << EOF > "$CONF1"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    $USER_OPT
};
zone "example.com" {
    type primary;
    file "$ZONE1";
};
EOF

cat << EOF > "$CONF2"
options {
    port $PORT2;
    bind-address { 127.0.0.1; };
    $USER_OPT
};
zone "example.com" {
    type primary;
    file "$ZONE2";
};
EOF

# 3. Prepare Query File
cat << 'EOF' > "$QUERY_FILE"
match1.example.com A
match2.example.com A
differ.example.com A
EOF

chmod 755 "$TMP_DIR"
chmod 644 "$CONF1" "$CONF2" "$ZONE1" "$ZONE2" "$QUERY_FILE"

# 4. Start Servers
echo "[+] Starting Server 1 on 127.0.0.1:$PORT1..."
./karidns -f -c "$CONF1" > "$LOG1" 2>&1 &
PID1=$!

echo "[+] Starting Server 2 on 127.0.0.1:$PORT2..."
./karidns -f -c "$CONF2" > "$LOG2" 2>&1 &
PID2=$!
sleep 1

if ! kill -0 "$PID1" 2>/dev/null; then
    echo "FAIL: Server 1 failed to start. Log:"
    cat "$LOG1"
    exit 1
fi
if ! kill -0 "$PID2" 2>/dev/null; then
    echo "FAIL: Server 2 failed to start. Log:"
    cat "$LOG2"
    exit 1
fi

# 5. Test 1: Single Server Replay
echo "[+] Test 1: Single server replay..."
OUT1=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1")
echo "$OUT1"
if echo "$OUT1" | grep -q "Server 1: 3 responses"; then
    echo "  PASS: Single server replay completed with 3 responses."
else
    echo "FAIL: Expected 3 responses from server 1."
    exit 1
fi

# 6. Test 2: Differential Replay with Text Report
echo "[+] Test 2: Differential replay (text output)..."
OUT2=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff)
echo "$OUT2"
if echo "$OUT2" | grep -q "Identical responses: 2" && echo "$OUT2" | grep -q "Mismatched responses: 1"; then
    echo "  PASS: Differential test detected 2 matching and 1 differing response."
else
    echo "FAIL: Differential test mismatch count unexpected."
    exit 1
fi

# 7. Test 3: Differential Replay with JSON Output
echo "[+] Test 3: Differential replay (JSON output)..."
OUT3=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output json)
echo "$OUT3"
if echo "$OUT3" | grep -q '"mismatched_queries": 1' && echo "$OUT3" | grep -q '"identical_queries": 2'; then
    echo "  PASS: JSON report accurately reported identical and mismatched query counts."
else
    echo "FAIL: JSON output did not contain expected fields."
    exit 1
fi

# 8. Test 4: Rate Limiting & Max Queries
echo "[+] Test 4: Rate limit and max-queries limit..."
OUT4=$(./dag --replay "$QUERY_FILE" --server1 "127.0.0.1:$PORT1" --rate 50 --workers 2 --max-queries 2)
echo "$OUT4"
if echo "$OUT4" | grep -q "Server 1: 2 responses"; then
    echo "  PASS: Max queries limit (2) correctly enforced."
else
    echo "FAIL: Max queries limit not enforced."
    exit 1
fi

# 9. Test 5: Order-Independent Set Comparison (Shuffled RRset in Answer)
echo "[+] Test 5: Order-independent set comparison..."
Q_SHUFFLE="$TMP_DIR/q_shuffle.txt"
echo "round.example.com A" > "$Q_SHUFFLE"
OUT5=$(./dag --replay "$Q_SHUFFLE" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output json)
echo "$OUT5"
if echo "$OUT5" | grep -q '"identical_queries": 1' && echo "$OUT5" | grep -q '"mismatched_queries": 0'; then
    echo "  PASS: Shuffled RRset records correctly recognized as identical set."
else
    echo "FAIL: Order-independent comparison failed to match shuffled RRset."
    exit 1
fi

# 10. Test 6: --ignore-ttl flag
echo "[+] Test 6: TTL difference with and without --ignore-ttl..."
Q_TTL="$TMP_DIR/q_ttl.txt"
echo "ttltest.example.com A" > "$Q_TTL"

OUT6_STRICT=$(./dag --replay "$Q_TTL" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output json)
echo "$OUT6_STRICT"
if echo "$OUT6_STRICT" | grep -q '"mismatched_queries": 1'; then
    echo "  PASS: Strict mode flagged TTL difference as mismatch."
else
    echo "FAIL: Strict mode missed TTL difference."
    exit 1
fi

OUT6_IGNORE=$(./dag --replay "$Q_TTL" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --ignore-ttl --output json)
echo "$OUT6_IGNORE"
if echo "$OUT6_IGNORE" | grep -q '"identical_queries": 1' && echo "$OUT6_IGNORE" | grep -q '"mismatched_queries": 0'; then
    echo "  PASS: --ignore-ttl successfully suppressed false positive on TTL difference."
else
    echo "FAIL: --ignore-ttl failed to ignore TTL difference."
    exit 1
fi

# 11. Test 7: Positive Detection of DIFF_GLUE_MISSING
echo "[+] Test 7: Positive detection of missing glue (DIFF_GLUE_MISSING)..."
Q_GLUE="$TMP_DIR/q_glue.txt"
echo "host.sub.example.com A" > "$Q_GLUE"
DIFF_GLUE_LOG="$TMP_DIR/diff_glue.log"
OUT7=$(./dag --replay "$Q_GLUE" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output-diff "$DIFF_GLUE_LOG" --output json)
echo "$OUT7"
if echo "$OUT7" | grep -q '"glue_missing_diffs": 1'; then
    echo "  PASS: DIFF_GLUE_MISSING counter incremented in JSON output."
else
    echo "FAIL: DIFF_GLUE_MISSING not detected in JSON output."
    exit 1
fi
if grep -q "GLUE_MISSING" "$DIFF_GLUE_LOG"; then
    echo "  PASS: DIFF_GLUE_MISSING present in output-diff file."
else
    echo "FAIL: DIFF_GLUE_MISSING missing from output-diff file."
    exit 1
fi

# 12. Test 8: Positive Detection of DIFF_CNAME_CHAIN
echo "[+] Test 8: Positive detection of CNAME chain differences (DIFF_CNAME_CHAIN)..."
Q_CNAME="$TMP_DIR/q_cname.txt"
echo "cnamechain.example.com A" > "$Q_CNAME"
DIFF_CNAME_LOG="$TMP_DIR/diff_cname.log"
OUT8=$(./dag --replay "$Q_CNAME" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output-diff "$DIFF_CNAME_LOG" --output json)
echo "$OUT8"
if echo "$OUT8" | grep -q '"cname_chain_diffs": 1'; then
    echo "  PASS: DIFF_CNAME_CHAIN counter incremented in JSON output."
else
    echo "FAIL: DIFF_CNAME_CHAIN not detected in JSON output."
    exit 1
fi
if grep -q "CNAME_CHAIN" "$DIFF_CNAME_LOG"; then
    echo "  PASS: DIFF_CNAME_CHAIN present in output-diff file."
else
    echo "FAIL: DIFF_CNAME_CHAIN missing from output-diff file."
    exit 1
fi

# 13. Test 9: Positive Detection of DIFF_DNSSEC_RRSIG & DIFF_DNSSEC_NSEC
echo "[+] Test 9: Positive detection of DNSSEC RRSIG & NSEC differences..."
Q_SEC="$TMP_DIR/q_sec.txt"
cat << 'EOF' > "$Q_SEC"
sec.example.com A +dnssec
sec.example.com TXT +dnssec
EOF
DIFF_SEC_LOG="$TMP_DIR/diff_sec.log"
OUT9=$(./dag --replay "$Q_SEC" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --output-diff "$DIFF_SEC_LOG" --output json)
echo "$OUT9"
if echo "$OUT9" | grep -q '"dnssec_rrsig_diffs": 1' && echo "$OUT9" | grep -q '"dnssec_nsec_diffs": 1'; then
    echo "  PASS: DIFF_DNSSEC_RRSIG and DIFF_DNSSEC_NSEC counters incremented in JSON output."
else
    echo "FAIL: DNSSEC RRSIG or NSEC difference not detected in JSON output."
    exit 1
fi
if grep -q "DNSSEC_RRSIG" "$DIFF_SEC_LOG" && grep -q "DNSSEC_NSEC" "$DIFF_SEC_LOG"; then
    echo "  PASS: DNSSEC_RRSIG and DNSSEC_NSEC present in output-diff file."
else
    echo "FAIL: DNSSEC flags missing from output-diff file."
    exit 1
fi

# 14. Test 10: --stop-after flag
echo "[+] Test 10: --stop-after early termination..."
Q_STOP="$TMP_DIR/q_stop.txt"
cat << 'EOF' > "$Q_STOP"
differ.example.com A
cnamechain.example.com A
sec.example.com A
EOF
OUT10=$(./dag --replay "$Q_STOP" --server1 "127.0.0.1:$PORT1" --server2 "127.0.0.1:$PORT2" --diff --stop-after 1 --output json)
echo "$OUT10"
if echo "$OUT10" | grep -q '"mismatched_queries": 1'; then
    echo "  PASS: --stop-after 1 terminated after recording exactly 1 mismatch."
else
    echo "FAIL: --stop-after 1 did not limit mismatches to 1."
    exit 1
fi

echo "=== All dag DNS Replay & Differential Tests Passed! ==="
