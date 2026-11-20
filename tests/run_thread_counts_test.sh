#!/bin/sh
# ==============================================================================
# run_thread_counts_test.sh
#
# 0.7: the Frontend routers and the Backend workers follow the CPUs the server may run on (its CPU set), not the CPUs of the machine,
# and options { router-threads; worker-threads; } replace them.
#  1. `cpuset -l <first CPU>`: 1 router and 1 worker, "(1 CPUs usable of N)" in the start-up line, `karictl status` shows 1 worker thread
#     and the machine's CPUs (unchanged `CPUs found`)
#  2. no CPU set of its own: the counts of the CPUs this shell may use (B3 phase 1: 1 router up to 3 CPUs, from 4 on half the CPUs as routers, at
#     most 8, and the rest as workers), the same line; then CPU sets of 4, 8 and 16 CPUs (as far as the shell has them)
#  3. router-threads / worker-threads: the counts and "set by ..." in the line, under a CPU set; the one that is not written stays automatic
#  4. a reload that changes them: "OK (restart needed for: router-threads, worker-threads)" and the counts of the start stay
#  5. karicheck conf: a valid file passes, a value out of range is an error with file:line; the server refuses to start with it
#
# SKIP when cpuset(1) is missing (not FreeBSD).
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! command -v cpuset >/dev/null 2>&1; then echo "SKIP: cpuset(1) is not available"; exit 0; fi
[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/karictl" ] && [ -x "$ROOT_DIR/karicheck" ] || \
    make -C "$ROOT_DIR" karidns karictl karicheck

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
KARICHECK="$ROOT_DIR/karicheck"

PORT=$(kari_port 0 $((26000 + $$ % 4000)))
TMP_DIR="/tmp/thread_counts_test_$$"
CTRL_SOCK="$TMP_DIR/control.sock"
SECRET="dGhyZWFkLWNvdW50cy10ZXN0LXNlY3JldC1rZXktMDE="
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

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

NCPU=$(sysctl -n hw.ncpu)
# the CPUs this shell may use (a CI runner may be under a CPU set itself): the first one, and how many
MASK=$(cpuset -g 2>/dev/null | sed -n 's/^pid [-0-9]* mask: *//p' | head -1)   # ("pid -1 mask: ..." on FreeBSD 15: the calling process)
FIRST=$(printf '%s' "$MASK" | cut -d, -f1)
[ -n "$FIRST" ] || FIRST=0
HAVE=$(printf '%s' "$MASK" | tr ',' '\n' | grep -c .)
[ "$HAVE" -ge 1 ] || HAVE=$NCPU

cat > "$TMP_DIR/a.example.zone" <<EOT
\$TTL 300
@ IN SOA ns1.a.example. hostmaster.a.example. ( 1 3600 600 86400 60 )
@ IN NS ns1.a.example.
ns1 IN A 192.0.2.1
EOT
chmod 644 "$TMP_DIR/a.example.zone"

write_conf() { # $1 = extra options text
cat > "$TMP_DIR/karidns.conf" <<EOT
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT $1 };
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "$SECRET"; };
zone "a.example" { type primary; file "$TMP_DIR/a.example.zone"; };
EOT
chmod 644 "$TMP_DIR/karidns.conf"
}
printf 'socket "%s";\nkey "karictl" { algorithm "hmac-sha256"; secret "%s"; };\n' "$CTRL_SOCK" "$SECRET" > "$TMP_DIR/karictl.conf"
chmod 600 "$TMP_DIR/karictl.conf"
ctl() { "$KARICTL" -f "$TMP_DIR/karictl.conf" "$@" 2>&1; }

# start_server COMMAND... : runs COMMAND (e.g. `cpuset -l 0`, `env`) in front of karidns; returns when the start-up line is in the log
start_server() {
    kari_kill_tree "$SERVER_PID"; SERVER_PID=""
    rm -f "$CTRL_SOCK"
    "$@" "$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ $i -lt 100 ] && [ ! -S "$CTRL_SOCK" ]; do sleep 0.1; i=$((i + 1)); done
    if ! kill -0 "$SERVER_PID" 2>/dev/null || [ ! -S "$CTRL_SOCK" ]; then
        fail "karidns did not start"; cat "$TMP_DIR/karidns.log"; return 1
    fi
    if ! kari_wait_log "$TMP_DIR/karidns.log" '\[Startup\] [0-9]* routers' 10; then
        fail "no start-up line about the threads in the log"; cat "$TMP_DIR/karidns.log"; return 1
    fi
}
line() { grep '\[Startup\] [0-9]* routers' "$TMP_DIR/karidns.log" | head -1 | sed 's/^.*\[Startup\] //'; }
# expect_line DESC WANT : the start-up line starts with WANT
expect_line() {
    l=$(line)
    case "$l" in "$2"*) pass "$1: $l";; *) fail "$1: '$l' (want '$2...')";; esac
}
# plan_expect CPUS: R and W the default plan gives (dns_server_core.c plan_threads())
plan_expect() {
    if [ "$1" -le 3 ]; then
        R=1
        if [ "$1" -ge 3 ]; then W=2; else W=1; fi
    else
        R=$(($1 / 2)); [ "$R" -gt 8 ] && R=8
        W=$(($1 - R))
    fi
    [ "$W" -gt 128 ] && W=128
    return 0
}
# the worker threads the Backend reports (`karictl status`)
status_workers() { ctl status | sed -n 's/^worker threads: //p'; }

echo "=== 1. under a CPU set of one CPU ==="
write_conf ""
start_server cpuset -l "$FIRST" && {
    expect_line "one CPU" "1 routers, 1 workers (1 CPUs usable of $NCPU)"
    [ "$(status_workers)" = "1" ] && pass "status: 1 worker thread" || fail "status worker threads: $(status_workers)"
    ctl status | grep -q "^CPUs found: $NCPU\$" && pass "status: CPUs found is the machine's" || fail "CPUs found"
}

echo "=== 2. the CPUs this shell may use ($HAVE of $NCPU) ==="
start_server env && {
    plan_expect "$HAVE"
    expect_line "the CPUs of the shell" "$R routers, $W workers ($HAVE CPUs usable of $NCPU)"
    [ "$(status_workers)" = "$W" ] && pass "status: $W worker threads" || fail "status worker threads: $(status_workers) (want $W)"
}
# a CPU set of the first N CPUs of the shell's mask: the plan for N CPUs
for N in 4 8 16; do
    [ "$HAVE" -ge "$N" ] || { echo "  (skipped: $N CPUs, this shell has $HAVE)"; continue; }
    LIST=$(printf '%s' "$MASK" | tr -d ' ' | tr ',' '\n' | head -n "$N" | tr '\n' ',' | sed 's/,$//')
    start_server cpuset -l "$LIST" && {
        plan_expect "$N"
        expect_line "a CPU set of $N CPUs" "$R routers, $W workers ($N CPUs usable of $NCPU)"
        [ "$(status_workers)" = "$W" ] && pass "status: $W worker threads" || fail "status worker threads: $(status_workers) (want $W)"
    }
done

echo "=== 3. router-threads / worker-threads ==="
write_conf "router-threads 3; worker-threads 5;"
start_server cpuset -l "$FIRST" && {
    expect_line "both set under one CPU" "3 routers, 5 workers (1 CPUs usable of $NCPU); set by router-threads and worker-threads"
    [ "$(status_workers)" = "5" ] && pass "status: 5 worker threads" || fail "status worker threads: $(status_workers)"
}
write_conf "worker-threads 2;"
start_server cpuset -l "$FIRST" && expect_line "worker-threads only" "1 routers, 2 workers (1 CPUs usable of $NCPU); set by worker-threads"
write_conf "router-threads 4;"
start_server cpuset -l "$FIRST" && expect_line "router-threads only" "4 routers, 1 workers (1 CPUs usable of $NCPU); set by router-threads"

echo "=== 4. a reload that changes them ==="
write_conf "router-threads 2; worker-threads 3;"
out=$(ctl reconfig); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "OK (restart needed for: router-threads, worker-threads)" ] && pass "restart note: $out" || fail "reconfig rc=$rc: $out"
kari_wait_log "$TMP_DIR/karidns.log" "changed settings take effect only after a restart: router-threads, worker-threads" 10 || true
grep -q "changed settings take effect only after a restart: router-threads, worker-threads" "$TMP_DIR/karidns.log" && pass "warning logged" || fail "warning not logged"
[ "$(status_workers)" = "1" ] && pass "still 1 worker thread" || fail "worker threads after the reload: $(status_workers)"
out=$(ctl reconfig); rc=$?
[ "$rc" -eq 0 ] && case "$out" in OK|"OK reloaded") true;; *) false;; esac && pass "a reload that changes nothing more reloads silently" || fail "reconfig rc=$rc: $out"

echo "=== 5. karicheck conf ==="
write_conf "router-threads 1; worker-threads 128;"
"$KARICHECK" conf "$TMP_DIR/karidns.conf" > "$TMP_DIR/kc.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && pass "valid values pass" || { fail "karicheck rc=$rc"; cat "$TMP_DIR/kc.out"; }
write_conf "router-threads 8;"
"$KARICHECK" conf "$TMP_DIR/karidns.conf" > "$TMP_DIR/kc.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && pass "router-threads 8 (the most) passes" || { fail "karicheck rc=$rc"; cat "$TMP_DIR/kc.out"; }
for bad in "router-threads 9;" "router-threads 0;" "worker-threads 129;" "worker-threads many;"; do
    write_conf "
$bad"
    out=$("$KARICHECK" conf "$TMP_DIR/karidns.conf" 2>&1); rc=$?
    name=${bad%% *}
    if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q "karidns.conf:[0-9]*.*$name"; then pass "'$bad' is an error with file:line"
    else fail "'$bad' rc=$rc: $out"; fi
done
write_conf "router-threads 9;"
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/bad.log" 2>&1 &
BAD=$!
i=0
while [ $i -lt 50 ] && kill -0 "$BAD" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$BAD" 2>/dev/null; then kari_kill_tree "$BAD"; fail "karidns started with router-threads 9"
else wait "$BAD"; [ $? -ne 0 ] && pass "start with router-threads 9 refused" || fail "start with router-threads 9 exited 0"; fi

if [ "$FAILED" -eq 0 ]; then echo "PASS: thread counts"; exit 0; fi
echo "FAIL: $FAILED check(s)"; exit 1
