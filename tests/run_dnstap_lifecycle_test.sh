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
#  5. (0.7) karictl status / stats show the messages lost when the collector
#     stops reading (queue full) and while it is away (not connected), the
#     link state and the reconnects; the queue-full log line.
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

PORT=$(kari_port 0 $((26000 + $$ % 4000)))
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
    "$KARIDNS" -f "${CONF:-$TMP_DIR/karidns.conf}" > "$TMP_DIR/karidns.log" 2>&1 &
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

# --- 5: loss and link state in karictl status / stats (0.7) --------------------
# A collector that stops reading: the sender blocks (2 s), the rings (queue-size 64) fill and drop, the link is dropped and made again.
# Then the collector goes away for good (connected no, messages lost while not connected) and comes back (connected yes).
echo "--- loss counters and link state (0.7) ---"
sed -e 's/identity "lifecycle";/identity "lifecycle"; queue-size 64;/' "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns5.conf"
chmod 644 "$TMP_DIR/karidns5.conf"
CONF="$TMP_DIR/karidns5.conf"
ctl() { "$KARICTL" -f "$TMP_DIR/karictl.conf" "$@" 2>/dev/null; }
flood() { # $1 = queries, sent without waiting for the answers, from one socket
    perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $ARGV[0], Proto => "udp") or exit 1;
        my $q = pack("n6", 0, 0x0100, 1, 0, 0, 0) . "\x03www\x07example\x04test\x00" . pack("n2", 1, 1);
        for my $i (1 .. $ARGV[1]) { substr($q, 0, 2) = pack("n", $i & 0xffff); $s->send($q); select(undef, undef, undef, 0.0002) if $i % 50 == 0 }' \
        "$PORT" "$1"
}
status_num() { ctl status | sed -n "s/^$1: \([0-9][0-9]*\)$/\1/p"; }
wait_status() { # $1 = status line, $2 = seconds; floods meanwhile so that frames keep flowing
    i=0
    while [ $i -lt $(($2 * 2)) ]; do
        ctl status | grep -qx "$1" && return 0
        flood 200; sleep 0.5; i=$((i + 1))
    done
    return 1
}
start_receiver "$TMP_DIR/cap5.log" --connections 2 --stall-after 4 --stall 2.5 --timeout 60
start_server || fail "server did not answer (loss test)"
# the Backend connects to the collector after its workers start, so an answered query does not mean connected yet: wait for the state
# (no flood meanwhile: the collector stalls after its first frames, and the loss below is counted from here)
i=0
while [ $i -lt 40 ] && ! ctl status | grep -qx "dnstap connected: yes"; do sleep 0.25; i=$((i + 1)); done
ctl status | grep -qx "dnstap connected: yes" && pass "status: dnstap connected: yes" || fail "status: $(ctl status | grep '^dnstap')"
i=0; full=0
while [ $i -lt 40 ]; do
    flood 2000
    full=$(status_num "dnstap dropped (queue full)")
    [ "${full:-0}" -gt 0 ] && break
    sleep 0.25; i=$((i + 1))
done
[ "${full:-0}" -gt 0 ] && pass "status: dnstap dropped (queue full): $full while the collector did not read" \
                       || fail "status: no queue-full loss: $(ctl status | grep '^dnstap')"
i=0
while [ $i -lt 50 ] && ! grep -q "messages dropped, the queue was full" "$TMP_DIR/karidns.log"; do sleep 0.2; i=$((i + 1)); done
grep -q "\[dnstap\] [0-9]* messages dropped, the queue was full" "$TMP_DIR/karidns.log" && pass "log: the queue-full line" \
    || fail "log: no queue-full line"
[ "$(grep -c "messages dropped, the queue was full" "$TMP_DIR/karidns.log")" -le 2 ] && pass "log: the line is rate-limited" \
    || fail "log: $(grep -c "messages dropped, the queue was full" "$TMP_DIR/karidns.log") queue-full lines"
if wait_status "dnstap connected: yes" 20 && grep -q "connection #2" "$TMP_DIR/cap5.log" && [ "$(status_num "dnstap reconnects")" -ge 1 ]; then
    pass "status: reconnected after the stall (dnstap reconnects: $(status_num "dnstap reconnects"))"
else
    fail "no reconnect after the stall: $(ctl status | grep '^dnstap'); $(tail -3 "$TMP_DIR/cap5.log")"
fi
kill "$RECV_PID" 2>/dev/null; wait "$RECV_PID" 2>/dev/null; RECV_PID=""
rm -f "$SOCK"
if wait_status "dnstap connected: no" 20; then
    pass "status: dnstap connected: no after the collector went away"
else
    fail "status after the collector went away: $(ctl status | grep '^dnstap')"
fi
flood 200; sleep 0.3
ctl stats -f json > "$TMP_DIR/s5.json"
grep -q '"dnstap_connected":false' "$TMP_DIR/s5.json" && pass "stats json: dnstap_connected false" || fail "stats json: $(grep -o '"dnstap[^}]*}' "$TMP_DIR/s5.json")"
nc=$(sed -n 's/.*"dnstap_dropped":{"queue_full":[0-9]*,"not_connected":\([0-9]*\)}.*/\1/p' "$TMP_DIR/s5.json")
[ "${nc:-0}" -gt 0 ] && pass "stats json: dnstap_dropped.not_connected = $nc" || fail "stats json: no not_connected loss ($nc)"
ctl stats | grep -qx "karidns_dnstap_connected 0" && pass "stats: karidns_dnstap_connected 0" || fail "stats: $(ctl stats | grep '^karidns_dnstap')"
ctl stats | grep -q '^karidns_dnstap_dropped_total{reason="queue_full"} [1-9]' && pass "stats: karidns_dnstap_dropped_total{reason=\"queue_full\"}" \
    || fail "stats: $(ctl stats | grep '^karidns_dnstap')"
start_receiver "$TMP_DIR/cap6.log" --timeout 60
# the retry interval doubles while the collector is away (1, 2, 4, ... s)
if wait_status "dnstap connected: yes" 40; then
    ctl stats | grep -qx "karidns_dnstap_connected 1" && pass "the collector is back: connected yes, karidns_dnstap_connected 1" \
                                                     || fail "stats after the reconnect: $(ctl stats | grep '^karidns_dnstap')"
    grep -q "reconnected to .*messages were lost while not connected" "$TMP_DIR/karidns.log" && pass "log: the reconnect line counts the loss" \
        || fail "log: no reconnect line with the loss"
else
    fail "no reconnect when the collector came back: $(ctl status | grep '^dnstap')"
fi
kill -TERM "$SERVER_PID"; wait_exit "$SERVER_PID" 10; SERVER_PID=""
kill "$RECV_PID" 2>/dev/null; RECV_PID=""

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: dnstap reconnects, carries query_zone and ends with STOP/FINISH"
exit 0
