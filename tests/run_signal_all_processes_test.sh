#!/bin/sh
set -e

# ==============================================================================
# Signals sent to every karidns process (pkill -HUP karidns)
#
# SIGHUP, SIGUSR1 and SIGUSR2 terminate a process by default. karidns forks a
# connect broker, frontend routers and a backend; when one of them died, the
# manager stopped the whole server ("Child process N killed by signal 1").
# Verifies that after SIGHUP/SIGUSR1/SIGUSR2/SIGPIPE are sent to all processes:
#   1. every process is still alive (same PIDs) and the server still answers,
#   2. SIGHUP made the server reload (and not stop), and
#   3. the same signals sent to the manager only also reload and do not kill.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag

KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

FAILED=0
PORT=$((21000 + $$ % 8000))
TMP_DIR="/tmp/signal_all_processes_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    kari_kill_tree "${SERVER_PID:-}"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat > "$TMP_DIR/sig.example.zone" << 'EOF'
$TTL 300
@ IN SOA ns1.sig.example. hostmaster.sig.example. ( 2026090101 3600 600 86400 300 )
@   IN NS ns1.sig.example.
ns1 IN A 127.0.0.1
www IN A 192.0.2.1
EOF

cat > "$TMP_DIR/karidns.conf" << EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
view "default" {
    match-clients { any; };
    zone "sig.example" {
        type master;
        file "$TMP_DIR/sig.example.zone";
    };
};
EOF

check() {
    if [ "$2" = ok ]; then echo "OK:   $1"; else echo "FAIL: $1"; FAILED=1; fi
}

answers() {
    "$DAG" +nohexdump +short +time=2 +tries=1 @127.0.0.1 -p "$PORT" www.sig.example A 2>/dev/null | grep -q '^192\.0\.2\.1$'
}

reloads() {
    grep -c "Configuration and zones reloaded successfully" "$TMP_DIR/karidns.log" || true
}

# wait_reloads N : wait (bounded) until the log has at least N reloads
wait_reloads() {
    _i=0
    while [ "$(reloads)" -lt "$1" ] && [ $_i -lt 100 ]; do sleep 0.1; _i=$((_i + 1)); done
    [ "$(reloads)" -ge "$1" ]
}

"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!

_i=0
while ! answers && [ $_i -lt 100 ]; do sleep 0.1; _i=$((_i + 1)); done
if answers; then check "server answers before signals" ok; else check "server answers before signals" ng; fi

BEFORE=$(kari_conf_pids "$TMP_DIR/karidns.conf" | sort -n | tr '\n' ' ')
NPROC=$(echo "$BEFORE" | wc -w)
if [ "$NPROC" -ge 4 ]; then
    check "supervisor, broker, backend and routers are running ($NPROC)" ok
else
    check "supervisor, broker, backend and routers are running ($NPROC)" ng
fi
R0=$(reloads)

# 1. every signal to every process
for sig in HUP USR1 USR2 PIPE; do
    for p in $BEFORE; do kill -$sig "$p" 2>/dev/null || true; done
done
if wait_reloads $((R0 + 1)); then check "SIGHUP to all processes reloads" ok; else check "SIGHUP to all processes reloads" ng; fi
sleep 1
AFTER=$(kari_conf_pids "$TMP_DIR/karidns.conf" | sort -n | tr '\n' ' ')
if [ "$BEFORE" = "$AFTER" ]; then check "no process died (same PIDs)" ok; else check "no process died (before: $BEFORE after: $AFTER)" ng; fi
if grep -q "killed by signal" "$TMP_DIR/karidns.log"; then check "no 'killed by signal' in the log" ng; else check "no 'killed by signal' in the log" ok; fi
if answers; then check "server answers after signals to all processes" ok; else check "server answers after signals to all processes" ng; fi

# 2. the same signals to the manager only
R1=$(reloads)
kill -HUP $SERVER_PID
kill -USR1 $SERVER_PID
kill -USR2 $SERVER_PID
if wait_reloads $((R1 + 1)); then check "SIGHUP to the manager reloads" ok; else check "SIGHUP to the manager reloads" ng; fi
if kill -0 $SERVER_PID 2>/dev/null && answers; then
    check "manager alive and answering after HUP/USR1/USR2" ok
else
    check "manager alive and answering after HUP/USR1/USR2" ng
fi

if [ $FAILED -ne 0 ]; then
    echo "--- karidns.log tail ---"
    tail -20 "$TMP_DIR/karidns.log"
    exit 1
fi
echo "ALL TESTS PASSED"
