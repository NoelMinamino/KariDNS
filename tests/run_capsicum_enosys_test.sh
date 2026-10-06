#!/bin/sh
# ==============================================================================
# run_capsicum_enosys_test.sh
#
# Phase 13 (O-02, O-15): backend start-up and shutdown edge cases, driven with
# the fault-injection shim (tests/fi/kari_fi_preload.c).
#  1. cap_enter() fails with ENOSYS (kernel without CAPABILITY_MODE): the
#     backend logs at LOG_CRIT that it runs without the sandbox and keeps
#     answering (it used to continue silently).
#  2. cap_enter() fails with another error: start-up is aborted cleanly (exit
#     status 1, no crash), through _exit() because threads are already running.
#  3. A worker thread cannot be created: start-up is aborted without a crash.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" karidns dag
KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"

PORT=$((26000 + $$ % 4000))
TMP_DIR="/tmp/capsicum_enosys_test_$$"
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

echo "=== backend start-up edge cases (O-02, O-15) ==="

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
cat > "$TMP_DIR/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
www IN A 192.0.2.10
EOF
cat > "$TMP_DIR/karidns.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
chmod 644 "$TMP_DIR"/*.zone "$TMP_DIR/karidns.conf"

run_with_fault() { # $1 = KARI_FI_SPEC; waits for an answer or for the exit
    rm -f "$TMP_DIR/fired.log"
    env LD_PRELOAD="$SHIM" KARI_FI_SPEC="$1" KARI_FI_LOG="$TMP_DIR/fired.log" \
        "$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
    SERVER_PID=$!
    i=0
    ANSWERED=0
    while [ $i -lt 40 ] && kill -0 "$SERVER_PID" 2>/dev/null; do
        if "$DAG" @127.0.0.1 -p "$PORT" www.example.test A +time=1 +tries=1 +nohexdump 2>/dev/null | grep -q "status: NOERROR"; then
            ANSWERED=1; break
        fi
        sleep 0.1; i=$((i + 1))
    done
}

stop_server() { # sets RC to the exit status
    kill -TERM "$SERVER_PID" 2>/dev/null
    i=0
    while [ $i -lt 100 ] && kill -0 "$SERVER_PID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kari_kill_tree "$SERVER_PID"
    wait "$SERVER_PID" 2>/dev/null
    RC=$?
    SERVER_PID=""
}

# 1. ENOSYS
run_with_fault "cap_enter@1:errno=ENOSYS:child"
grep -q "cap_enter@1" "$TMP_DIR/fired.log" 2>/dev/null || fail "ENOSYS: the fault was not injected"
grep -q "WITHOUT the capability-mode sandbox" "$TMP_DIR/karidns.log" && pass "ENOSYS: logged that the sandbox is missing" \
    || fail "ENOSYS: no log line about the missing sandbox"
[ "$ANSWERED" = 1 ] && pass "ENOSYS: the server keeps answering" || fail "ENOSYS: no answer"
stop_server; rc=$RC
[ "$rc" = 0 ] && pass "ENOSYS: SIGTERM -> exit status 0" || fail "ENOSYS: exit status $rc after SIGTERM"

# 2. other cap_enter() error: clean abort
run_with_fault "cap_enter@1:errno=EPERM:child"
stop_server; rc=$RC
grep -q "cap_enter failed" "$TMP_DIR/karidns.log" && pass "cap_enter EPERM: start-up aborted with a message" \
    || fail "cap_enter EPERM: no message"
[ "$rc" = 1 ] && pass "cap_enter EPERM: exit status 1, no crash" || fail "cap_enter EPERM: exit status $rc (expected 1)"

# 3. a worker thread cannot be created (pthread_create #2 in the backend: after the async I/O pool)
run_with_fault "pthread_create@18:child"
stop_server; rc=$RC
[ "$rc" = 1 ] && pass "pthread_create fault: exit status 1, no crash" || fail "pthread_create fault: exit status $rc (expected 1)"
grep -q "Sanitizer\|Segmentation fault" "$TMP_DIR/karidns.log" && fail "pthread_create fault: sanitizer report or segfault"

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: $FAILED check(s) failed"
    sed 's/^/    /' "$TMP_DIR/karidns.log" | tail -20
    exit 1
fi
echo "PASS: ENOSYS is logged, failing start-ups end cleanly"
exit 0
