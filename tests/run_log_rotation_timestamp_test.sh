#!/bin/sh
# ==============================================================================
# run_log_rotation_timestamp_test.sh
#
# Phase 12 (D-21): "suffix timestamp" rotation in the running server (inside the Capsicum sandbox).
#  1. size + suffix timestamp without versions: several rotations on the same day give
#     q.log.YYYYMMDD, q.log.YYYYMMDD.1, ... and no query line is lost (it used to overwrite the
#     first file)
#  2. size + suffix timestamp + versions 2: only the 2 newest dated files are kept (BIND
#     remove_old_tsversions()); unrelated files in the directory are not touched
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag

KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

PORT=$((38000 + $$ % 4000))
TMP_DIR="/tmp/log_rotation_ts_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
FAILED=0
QUERIES=60

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi
cat > "$TMP_DIR/rot.example.zone" <<'EOF'
$TTL 300
@ IN SOA ns1.rot.example. hostmaster.rot.example. ( 1 3600 600 86400 60 )
@ IN NS ns1.rot.example.
ns1 IN A 192.0.2.1
EOF
chmod 644 "$TMP_DIR/rot.example.zone"

# run_case <name> <versions clause>
run_case() {
    LOGDIR="$TMP_DIR/$1"
    mkdir -p "$LOGDIR"
    chmod 777 "$LOGDIR"
    : > "$LOGDIR/other.log.20250101"
    : > "$LOGDIR/q.log.notes"
    chmod 666 "$LOGDIR"/*
    cat > "$TMP_DIR/$1.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
logging { channel q { file "$LOGDIR/q.log" size 1K $2 suffix timestamp; }; category queries { q; }; };
zone "rot.example" { type master; file "$TMP_DIR/rot.example.zone"; };
EOF
    chmod 644 "$TMP_DIR/$1.conf"
    "$KARIDNS" -f "$TMP_DIR/$1.conf" > "$TMP_DIR/$1.log" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ $i -lt 30 ]; do
        "$DAG" @127.0.0.1 -p "$PORT" rot.example SOA +short +nohexdump 2>/dev/null | grep -q ns1 && break
        sleep 0.2; i=$((i + 1))
    done
    i=1
    while [ $i -lt "$QUERIES" ]; do
        "$DAG" @127.0.0.1 -p "$PORT" "q$i.rot.example" A +short +nohexdump > /dev/null 2>&1
        i=$((i + 1))
    done
    sleep 2
    kari_kill_tree "$SERVER_PID"
    SERVER_PID=""
    DATED=$(ls "$LOGDIR" | grep -Ec '^q\.log\.[0-9]{8}(\.[1-9][0-9]*)?$')
    LINES=$(cat "$LOGDIR"/q.log* 2>/dev/null | grep -c "query:")
    echo "    $1: $(ls "$LOGDIR" | tr '\n' ' ')"
    [ -f "$LOGDIR/other.log.20250101" ] && [ -f "$LOGDIR/q.log.notes" ] && pass "$1: unrelated files kept" || \
        fail "$1: unrelated file removed"
    grep -q "Failed to remove\|Cannot list\|Cannot rotate\|Failed to rotate" "$TMP_DIR/$1.log" && \
        fail "$1: rotation error logged: $(grep -m1 'Failed\|Cannot' "$TMP_DIR/$1.log")" || pass "$1: no rotation error"
}

echo "=== 1. suffix timestamp without versions ==="
run_case noversions ""
[ "$DATED" -ge 3 ] && pass "several dated files ($DATED)" || fail "only $DATED dated file(s)"
[ "$LINES" -eq "$QUERIES" ] && pass "all $QUERIES query lines kept" || fail "$LINES of $QUERIES query lines kept"

echo "=== 2. suffix timestamp with versions 2 ==="
run_case versions2 "versions 2"
[ "$DATED" -eq 2 ] && pass "2 dated files kept" || fail "$DATED dated files (expected 2)"
[ "$LINES" -lt "$QUERIES" ] && pass "older files were removed" || fail "nothing removed"

if [ "$FAILED" -ne 0 ]; then
    echo "RESULT: $FAILED check(s) FAILED"; exit 1
fi
echo "RESULT: all checks passed"
exit 0
