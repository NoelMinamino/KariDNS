#!/bin/sh
# ==============================================================================
# run_dnstap_lifecycle_test.sh
#
# Phase 13 (O-03): dnstap connection life cycle.
#  1. Message.query_zone (field 11) carries the zone of the query.
#  2. The collector drops the connection (restart): karidns reconnects through
#     the connect broker and keeps sending (it used to disable dnstap until
#     restart).
#  3. SIGTERM: the backend sends the frames still queued, then a Frame Streams
#     STOP, and waits for FINISH (it used to _exit() at once).
#  4. karictl stop: the same STOP / FINISH.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] && [ -x "$ROOT_DIR/karictl" ] || \
    make -C "$ROOT_DIR" karidns dag karictl
KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"
KARICTL="$ROOT_DIR/karictl"

PORT=$((26000 + $$ % 4000))
TMP_DIR="/tmp/dnstap_lifecycle_test_$$"
SOCK="$TMP_DIR/dnstap.sock"
CTRL_SOCK="$TMP_DIR/control.sock"
SECRET="ZG5zdGFwLWxpZmVjeWNsZS10ZXN0LXNlY3JldC0wMDA="
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
RECV_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

cat > "$TMP_DIR/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
EOF
cat > "$TMP_DIR/karidns.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "$SECRET"; };
dnstap { socket "$SOCK"; identity "lifecycle"; log-queries yes; log-responses yes; };
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
printf 'socket "%s";\nkey "karictl" { algorithm "hmac-sha256"; secret "%s"; };\n' "$CTRL_SOCK" "$SECRET" > "$TMP_DIR/karictl.conf"
chmod 644 "$TMP_DIR"/*.zone "$TMP_DIR/karidns.conf"
chmod 600 "$TMP_DIR/karictl.conf"

start_receiver() { # $1 = output file, then receiver options
    out="$1"; shift
    rm -f "$SOCK"
    perl "$SCRIPT_DIR/mock_dnstap_receiver.pl" --socket "$SOCK" --output "$out" --timeout 20 "$@" > "$out.stdout" 2>&1 &
    RECV_PID=$!
    i=0
    while [ $i -lt 50 ] && [ ! -S "$SOCK" ]; do sleep 0.1; i=$((i + 1)); done
}

start_server() {
    "$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ $i -lt 50 ]; do
        "$DAG" @127.0.0.1 -p "$PORT" www.example.test A +time=1 +tries=1 +nohexdump 2>/dev/null | grep -q "status: NOERROR" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

wait_for() { # $1 = file, $2 = pattern, $3 = seconds; queries meanwhile so frames keep flowing
    i=0
    while [ $i -lt $(($3 * 5)) ]; do
        grep -q "$2" "$1" 2>/dev/null && return 0
        "$DAG" @127.0.0.1 -p "$PORT" www.example.test A +time=1 +tries=1 +nohexdump > /dev/null 2>&1
        sleep 0.2; i=$((i + 1))
    done
    return 1
}

wait_exit() { # $1 = pid, $2 = seconds
    i=0
    while [ $i -lt $(($2 * 10)) ] && kill -0 "$1" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    ! kill -0 "$1" 2>/dev/null
}

echo "=== dnstap life cycle (O-03) ==="

# --- 1-3: query_zone, reconnect, SIGTERM -------------------------------------
start_receiver "$TMP_DIR/cap1.log" --connections 2 --drop-after 4
start_server || fail "server did not answer"
if wait_for "$TMP_DIR/cap1.log" "zone=example.test\." 10; then
    pass "Message.query_zone = example.test."
else
    fail "no frame with query_zone example.test."
fi
if wait_for "$TMP_DIR/cap1.log" "connection #2" 15 && wait_for "$TMP_DIR/cap1.log" "Frame #[5-9].*type=AUTH" 10; then
    pass "reconnected after the collector dropped the connection; frames keep arriving"
else
    fail "no reconnect after the collector dropped the connection"
    grep "dnstap" "$TMP_DIR/karidns.log" | sed 's/^/    /'
fi
kill -TERM "$SERVER_PID"
if wait_exit "$SERVER_PID" 10; then
    wait "$SERVER_PID"; rc=$?
    [ "$rc" = 0 ] && pass "SIGTERM: exit status 0" || fail "SIGTERM: exit status $rc"
else
    fail "SIGTERM: server still running after 10 s"
fi
SERVER_PID=""
wait_exit "$RECV_PID" 5
if grep -q "STOP received, FINISH sent" "$TMP_DIR/cap1.log"; then
    pass "SIGTERM: Frame Streams STOP sent and FINISH received"
else
    fail "SIGTERM: no STOP frame"
fi
RECV_PID=""

# --- 4: karictl stop ----------------------------------------------------------
start_receiver "$TMP_DIR/cap2.log"
start_server || fail "server did not answer (second start)"
wait_for "$TMP_DIR/cap2.log" "type=AUTH_RESPONSE" 10 || fail "no frame before karictl stop"
"$KARICTL" -f "$TMP_DIR/karictl.conf" stop > "$TMP_DIR/stop.out" 2>&1
grep -q "OK stopping" "$TMP_DIR/stop.out" && pass "karictl stop accepted" || fail "karictl stop: $(cat "$TMP_DIR/stop.out")"
wait_exit "$SERVER_PID" 10 && pass "server exited after karictl stop" || fail "server still running after karictl stop"
SERVER_PID=""
wait_exit "$RECV_PID" 5
grep -q "STOP received, FINISH sent" "$TMP_DIR/cap2.log" && pass "karictl stop: STOP / FINISH" \
                                                          || fail "karictl stop: no STOP frame"
RECV_PID=""

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: dnstap reconnects, carries query_zone and ends with STOP/FINISH"
exit 0
