#!/bin/sh
# ==============================================================================
# run_manager_signal_race_test.sh
#
# The manager (supervisor) process must end on its own when the Backend dies
# during start-up, and must not wait forever for a child.  Driven with the
# fault-injection shim (tests/fi/kari_fi_preload.c).
#  1. The Backend fails (its first pthread_create) while the Frontend routers are still
#     starting (cpuset_setaffinity() delayed 3 s in every router).  The manager's SIGTERM
#     used to reach a router that still ran the manager's flag-only handler and
#     was lost; the router then waited for a Backend that was already gone.
#     Expected: the manager ends by itself, exit status 1, no pid file left.
#  2. The Backend does not end on SIGTERM (its _exit() is held back 60 s): after SIGTERM to the
#     manager the Backend is killed after the bounded wait (10 s), the
#     manager removes its pid file and ends with a non-zero status.
#  3. The same, but a second SIGTERM to the manager kills it at once.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag
KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

PORT=$(kari_port 1 $((26000 + $$ % 4000)))
TMP_DIR="/tmp/manager_signal_race_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

echo "=== manager shutdown races and the bounded child wait ==="

SHIM="$TMP_DIR/kari_fi_preload.so"
if ! ${CC:-cc} -O1 -fPIC -shared -o "$SHIM" "$ROOT_DIR/tests/fi/kari_fi_preload.c" > "$TMP_DIR/shim.log" 2>&1; then
    echo "SKIP: cannot build the fault-injection shim"; exit 0
fi
chmod 755 "$SHIM"
env LD_PRELOAD="$SHIM" KARI_FI_SPEC="socket@1:errno=EACCES" KARI_FI_LOG="$TMP_DIR/probe.log" \
    perl -MSocket -e 'socket(my $s, PF_INET, SOCK_DGRAM, 0);' > /dev/null 2>&1
if ! grep -q "socket@1" "$TMP_DIR/probe.log" 2>/dev/null; then
    echo "SKIP: LD_PRELOAD shim not effective from $TMP_DIR (noexec mount?)"; exit 0
fi

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi
cat > "$TMP_DIR/example.test.zone" <<'ZEOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
www IN A 192.0.2.10
ZEOF
cat > "$TMP_DIR/karidns.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "$TMP_DIR/karidns.pid"; $USER_OPT };
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
chmod 644 "$TMP_DIR"/*.zone "$TMP_DIR/karidns.conf"

start_server() { # $1 = KARI_FI_SPEC
    rm -f "$TMP_DIR/fired.log" "$TMP_DIR/karidns.pid"
    env LD_PRELOAD="$SHIM" KARI_FI_SPEC="$1" KARI_FI_LOG="$TMP_DIR/fired.log" \
        "$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
    SERVER_PID=$!
}

wait_answer() { # up to 10 s
    i=0
    while [ $i -lt 100 ] && kill -0 "$SERVER_PID" 2>/dev/null; do
        "$DAG" @127.0.0.1 -p "$PORT" www.example.test A +time=1 +tries=1 +nohexdump 2>/dev/null | grep -q "status: NOERROR" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

wait_exit() { # $1 = limit in tenths of a second; sets RC and ELAPSED (tenths); returns 1 on timeout
    i=0
    while [ $i -lt "$1" ] && kill -0 "$SERVER_PID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    ELAPSED=$i
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        kari_kill_tree "$SERVER_PID"
        wait "$SERVER_PID" 2>/dev/null
        RC=-1; SERVER_PID=""
        return 1
    fi
    wait "$SERVER_PID" 2>/dev/null
    RC=$?
    SERVER_PID=""
    return 0
}

# 1. the Backend dies while the routers start
start_server "pthread_create@1:child,cpuset_setaffinity@1:delay=3000:child"
if wait_exit 300; then
    pass "start-up failure: the manager ended by itself after $((ELAPSED / 10)) s"
else
    fail "start-up failure: the manager is still running after 30 s (hang)"
fi
grep -q "pthread_create@1" "$TMP_DIR/fired.log" 2>/dev/null || fail "start-up failure: the Backend was not faulted"
grep -q "cpuset_setaffinity@1" "$TMP_DIR/fired.log" 2>/dev/null || fail "start-up failure: the router start-up was not delayed"
[ "$RC" = 1 ] && pass "start-up failure: exit status 1" || fail "start-up failure: exit status $RC (expected 1)"
[ ! -e "$TMP_DIR/karidns.pid" ] && pass "start-up failure: pid file removed" || fail "start-up failure: pid file left behind"

# 2. a Backend that does not end on SIGTERM: SIGKILL after the bounded wait
start_server "_exit@1:delay=60000:child"
if wait_answer; then
    kill -TERM "$SERVER_PID"
    if wait_exit 250; then
        pass "stuck Backend: the manager ended after about $((ELAPSED / 10)) s"
        [ "$ELAPSED" -ge 90 ] && pass "stuck Backend: not before the 10 s wait" || fail "stuck Backend: ended after $ELAPSED/10 s (< 9 s)"
    else
        fail "stuck Backend: the manager did not end within 25 s"
    fi
    [ "$RC" != 0 ] && [ "$RC" != -1 ] && pass "stuck Backend: non-zero exit status ($RC)" || fail "stuck Backend: exit status $RC"
    grep -q "did not stop; killing it" "$TMP_DIR/karidns.log" && pass "stuck Backend: the kill is logged" || fail "stuck Backend: no kill log line"
    [ ! -e "$TMP_DIR/karidns.pid" ] && pass "stuck Backend: pid file removed" || fail "stuck Backend: pid file left behind"
else
    fail "stuck Backend: the server did not answer"
    kari_kill_tree "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
fi

# 3. a second SIGTERM kills at once
start_server "_exit@1:delay=60000:child"
if wait_answer; then
    kill -TERM "$SERVER_PID"
    sleep 1
    kill -TERM "$SERVER_PID"
    if wait_exit 60; then
        pass "second SIGTERM: the manager ended within 6 s"
    else
        fail "second SIGTERM: the manager did not end within 6 s"
    fi
    [ "$RC" != 0 ] && [ "$RC" != -1 ] && pass "second SIGTERM: non-zero exit status ($RC)" || fail "second SIGTERM: exit status $RC"
else
    fail "second SIGTERM: the server did not answer"
    kari_kill_tree "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
fi

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: the manager ends by itself and kills children that do not stop"
exit 0
