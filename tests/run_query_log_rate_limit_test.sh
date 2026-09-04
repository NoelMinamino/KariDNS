#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

echo "[*] Building targets..."
rm -f "$BIN" "$DAG"
make -C "$ROOT" karidns dag

CONF_LIMITED="$DIR/query_log_rate_limit_limited.conf"
CONF_UNLIMITED="$DIR/query_log_rate_limit_unlimited.conf"
LOG_LIMITED="/tmp/karidns_queries_limited.log"
LOG_UNLIMITED="/tmp/karidns_queries_unlimited.log"
ZONE_FILE="$DIR/zones/example_rate_limit.jp.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE_FILE"
$ORIGIN example.jp.
$TTL 86400
@           IN SOA   ns1.example.jp. hostmaster.example.jp. 2026090401 7200 3600 1209600 86400
@           IN NS    ns1.example.jp.
ns1         IN A     192.0.2.1
www         IN A     192.0.2.100
EOF

# Configuration 1: query-log-max-qps 30 (rate limited to 30 queries/sec)
cat << EOF > "$CONF_LIMITED"
options {
    port 10055;
    bind-address { 127.0.0.1; };
    query-log-max-qps 30;
    user "nobody";
    group "nobody";
};
logging {
    channel qlog {
        file "$LOG_LIMITED";
        print-time yes;
        print-category yes;
    };
    category queries { qlog; };
};
zone "example.jp" {
    type master;
    file "$ZONE_FILE";
};
EOF

# Configuration 2: max-qps 0 (unlimited logging)
cat << EOF > "$CONF_UNLIMITED"
options {
    port 10056;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
logging {
    channel qlog_unlimited {
        file "$LOG_UNLIMITED";
        max-qps 0;
        print-time yes;
        print-category yes;
    };
    category queries { qlog_unlimited; };
};
zone "example.jp" {
    type master;
    file "$ZONE_FILE";
};
EOF

cleanup() {
    echo "[*] Cleaning up test processes and temp files..."
    if [ -n "$PID_LIMITED" ] && kill -0 "$PID_LIMITED" 2>/dev/null; then
        kill -9 "$PID_LIMITED" 2>/dev/null || true
        wait "$PID_LIMITED" 2>/dev/null || true
    fi
    if [ -n "$PID_UNLIMITED" ] && kill -0 "$PID_UNLIMITED" 2>/dev/null; then
        kill -9 "$PID_UNLIMITED" 2>/dev/null || true
        wait "$PID_UNLIMITED" 2>/dev/null || true
    fi
    killall -9 karidns 2>/dev/null || true
    rm -f "$CONF_LIMITED" "$CONF_UNLIMITED" "$LOG_LIMITED" "$LOG_UNLIMITED" "$ZONE_FILE"
    rm -f "$DIR"/server_limited.log "$DIR"/server_unlimited.log
}
trap cleanup EXIT INT TERM

# -------------------------------------------------------------
# Test 1: Rate-limited query logging (max-qps 30)
# -------------------------------------------------------------
echo "[*] Starting KariDNS with query-log-max-qps = 30 on port 10055..."
rm -f "$LOG_LIMITED" "$DIR/server_limited.log"
"$BIN" -f -c "$CONF_LIMITED" > "$DIR/server_limited.log" 2>&1 &
PID_LIMITED=$!
sleep 2

echo "[*] Sending 150 queries rapidly to 127.0.0.1:10055..."
SUCCESS_COUNT=0
for i in $(seq 1 150); do
    "$DAG" www.example.jp a @127.0.0.1 -p 10055 > /dev/null 2>&1 && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
done

echo "[*] Completed $SUCCESS_COUNT / 150 queries successfully."
if [ "$SUCCESS_COUNT" -ne 150 ]; then
    echo "[FAIL] Expected 150 successful DNS queries, but got $SUCCESS_COUNT"
    if [ -f "$DIR/server_limited.log" ]; then
        echo "--- server_limited.log ---"
        cat "$DIR/server_limited.log"
    fi
    exit 1
fi

# Wait for background query logger thread to finish writing
sleep 2

if [ ! -f "$LOG_LIMITED" ]; then
    echo "[FAIL] Log file $LOG_LIMITED was not created!"
    exit 1
fi

LINE_COUNT=$(wc -l < "$LOG_LIMITED" | tr -d ' ')
echo "[*] Log lines written with rate-limiting: $LINE_COUNT (out of 150 queries)"

# With max-qps = 30 and 150 queries sent within ~1 second,
# the logged lines should be throttled (allow slight slack up to 60 if span crosses 1-second boundary).
if [ "$LINE_COUNT" -gt 60 ]; then
    echo "[FAIL] Rate limiter failed to throttle queries log! Expected <= 60 lines, got $LINE_COUNT"
    exit 1
fi

if [ "$LINE_COUNT" -eq 0 ]; then
    echo "[FAIL] No queries were logged at all!"
    exit 1
fi

echo "[OK] Rate-limiting successfully throttled query logging ($LINE_COUNT lines logged for 150 queries)."

kill -9 "$PID_LIMITED" 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
wait "$PID_LIMITED" 2>/dev/null || true
PID_LIMITED=""
sleep 2

# -------------------------------------------------------------
# Test 2: Unlimited query logging (max-qps 0)
# -------------------------------------------------------------
echo "[*] Starting KariDNS with max-qps = 0 (unlimited) on port 10056..."
rm -f "$LOG_UNLIMITED" "$DIR/server_unlimited.log"
"$BIN" -f -c "$CONF_UNLIMITED" > "$DIR/server_unlimited.log" 2>&1 &
PID_UNLIMITED=$!
sleep 2

echo "[*] Sending 60 queries to 127.0.0.1:10056..."
SUCCESS_COUNT2=0
for i in $(seq 1 60); do
    "$DAG" www.example.jp a @127.0.0.1 -p 10056 > /dev/null 2>&1 && SUCCESS_COUNT2=$((SUCCESS_COUNT2 + 1))
done

echo "[*] Completed $SUCCESS_COUNT2 / 60 queries successfully."
if [ "$SUCCESS_COUNT2" -ne 60 ]; then
    echo "[FAIL] Expected 60 successful DNS queries, but got $SUCCESS_COUNT2"
    if [ -f "$DIR/server_unlimited.log" ]; then
        echo "--- server_unlimited.log ---"
        cat "$DIR/server_unlimited.log"
    fi
    exit 1
fi

sleep 2

if [ ! -f "$LOG_UNLIMITED" ]; then
    echo "[FAIL] Log file $LOG_UNLIMITED was not created!"
    exit 1
fi

LINE_COUNT2=$(wc -l < "$LOG_UNLIMITED" | tr -d ' ')
echo "[*] Log lines written with unlimited logging: $LINE_COUNT2 (out of 60 queries)"

if [ "$LINE_COUNT2" -ne 60 ]; then
    echo "[FAIL] Expected all 60 queries to be logged with max-qps 0, got $LINE_COUNT2"
    exit 1
fi

echo "[OK] Unlimited query logging logged all $LINE_COUNT2 queries."
echo "[ALL TESTS PASSED]"
