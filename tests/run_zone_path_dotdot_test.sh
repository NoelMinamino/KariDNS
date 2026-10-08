#!/bin/sh
# ==============================================================================
# run_zone_path_dotdot_test.sh
#
# Phase 12 (D-24): relative zone and log file paths that contain "../" are resolved against the
# directory karidns was started from, also with the Capsicum sandbox (the directories are opened
# before cap_enter). Before the fix the zone answered SERVFAIL (EDE 14) and only syslog said
# "Failed to read file".
#  1. zone file "../zones/x.zone" loads; the query log "../logs/q.log" is written
#  2. karictl reload <zone> after start (inside the sandbox) re-reads the same file
#  3. karicheck zone <zone> <file> no longer warns about "../" in standalone mode
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/karictl" ] && [ -x "$ROOT_DIR/dag" ] && [ -x "$ROOT_DIR/karicheck" ] || \
    make -C "$ROOT_DIR" karidns karictl dag karicheck

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
KARICHECK="$ROOT_DIR/karicheck"
DAG="$ROOT_DIR/dag"

PORT=$((30000 + $$ % 4000))
TMP_DIR="/tmp/zone_path_dotdot_test_$$"
CTRL_SOCK="$TMP_DIR/control.sock"
SECRET="ZG90ZG90LXBhdGgtdGVzdC1zZWNyZXQta2V5LTAwMDE="
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR/run" "$TMP_DIR/zones" "$TMP_DIR/logs"
chmod 755 "$TMP_DIR" "$TMP_DIR/run" "$TMP_DIR/zones"
chmod 777 "$TMP_DIR/logs"
SERVER_PID=""
FAILED=0

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

write_zone() { # $1 = address of www
cat > "$TMP_DIR/zones/dotdot.example.zone" <<EOF
\$TTL 300
@ IN SOA ns1.dotdot.example. hostmaster.dotdot.example. ( $2 3600 600 86400 60 )
@ IN NS ns1.dotdot.example.
ns1 IN A 192.0.2.1
www IN A $1
EOF
chmod 644 "$TMP_DIR/zones/dotdot.example.zone"
}
write_zone 192.0.2.10 1

cat > "$TMP_DIR/run/karidns.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "$SECRET"; };
logging { channel q { file "../logs/q.log"; }; category queries { q; }; };
zone "dotdot.example" { type master; file "../zones/dotdot.example.zone"; };
EOF
chmod 644 "$TMP_DIR/run/karidns.conf"
printf 'socket "%s";\nkey "karictl" { algorithm "hmac-sha256"; secret "%s"; };\n' "$CTRL_SOCK" "$SECRET" > "$TMP_DIR/karictl.conf"
chmod 600 "$TMP_DIR/karictl.conf"

(cd "$TMP_DIR/run" && exec "$KARIDNS" -f karidns.conf) > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ] && [ ! -S "$CTRL_SOCK" ]; do sleep 0.1; i=$((i + 1)); done
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi

echo "=== 1. zone and log file through ../ ==="
out=$("$DAG" @127.0.0.1 -p "$PORT" www.dotdot.example A +nohexdump 2>&1)
printf '%s\n' "$out" | grep -q "status: NOERROR" && pass "NOERROR" || fail "status: $(printf '%s\n' "$out" | grep status)"
printf '%s\n' "$out" | grep -q "192.0.2.10" && pass "answer from ../zones" || fail "no answer"
grep -q "Failed to read file" "$TMP_DIR/karidns.log" && fail "log says Failed to read file" || pass "no read failure logged"
sleep 1.5
grep -q "www.dotdot.example" "$TMP_DIR/logs/q.log" 2>/dev/null && pass "query log written to ../logs/q.log" || fail "query log missing"

echo "=== 2. reload after start (inside the sandbox) ==="
sleep 1
write_zone 192.0.2.20 2
out=$("$KARICTL" -f "$TMP_DIR/karictl.conf" reload dotdot.example 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "OK reloaded" ] && pass "karictl reload" || fail "karictl reload rc=$rc $out"
"$DAG" @127.0.0.1 -p "$PORT" www.dotdot.example A +short +nohexdump 2>/dev/null | grep -qx "192.0.2.20" && pass "new data" || fail "old data after reload"

echo "=== 3. karicheck standalone with ../ ==="
out=$(cd "$TMP_DIR/run" && "$KARICHECK" zone dotdot.example ../zones/dotdot.example.zone 2>&1); rc=$?
[ "$rc" -eq 0 ] && pass "karicheck exit 0" || fail "karicheck exit $rc"
case "$out" in *"contains '../'"*) fail "karicheck still warns about ../";; *) pass "no ../ warning";; esac

if [ "$FAILED" -ne 0 ]; then
    echo "--- karidns log ---"; tail -30 "$TMP_DIR/karidns.log"
    echo "RESULT: $FAILED check(s) FAILED"; exit 1
fi
echo "RESULT: all checks passed"
exit 0
