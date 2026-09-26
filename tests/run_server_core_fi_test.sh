#!/bin/sh
# =============================================================================
# KariDNS server fault-injection sweep
#
# Starts karidns repeatedly with tests/fi/kari_fi_preload.so preloaded and one
# system call made to fail on its Nth invocation (socket, bind, setsockopt,
# socketpair, fork, pthread_create, kqueue, privilege-drop calls, ...), then
# drives a small workload (UDP/TCP queries, AXFR, NOTIFY, control commands).
# For each call the sweep advances N until the call is no longer reached.
#
# The server must never crash: a fault may make startup fail cleanly or be
# absorbed, but a SIGSEGV/SIGBUS/SIGABRT is a test failure.
# Needs root (the server drops privileges to nobody); skipped otherwise.
# =============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARIDNS="$ROOT/karidns"
DAG="$ROOT/dag"
KARICTL="$ROOT/karictl"
PORT=10153
CTRL_PORT=10954
SHIM_SRC="$ROOT/tests/fi/kari_fi_preload.c"

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: run_server_core_fi_test.sh needs root (privilege drop)"
    exit 0
fi
[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICTL" ] || make -C "$ROOT" karidns dag karictl >/dev/null
# The sweep relies on the shim's KARI_FI_LOG / ":child" support; an older
# kari_fi_preload.c injects nothing this test can observe.
if ! grep -q "KARI_FI_LOG" "$SHIM_SRC" || ! grep -q "child_only" "$SHIM_SRC"; then
    echo "FAIL: $SHIM_SRC is older than this test (no KARI_FI_LOG / :child support)."
    echo "      Update it from git (git checkout HEAD -- tests/fi/kari_fi_preload.c)."
    exit 1
fi

TMP="$(mktemp -d /tmp/karidns_fi.XXXXXX)"
chmod 755 "$TMP"
# always build the shim fresh from the checked-out source (never reuse a
# possibly stale kari_fi_preload.so)
SHIM="$TMP/kari_fi_preload.so"
${CC:-cc} -O1 -g -fPIC -shared -o "$SHIM" "$SHIM_SRC" > "$TMP/shim_build.log" 2>&1 || {
    echo "FAIL: cannot build the fault-injection shim:"; sed 's/^/    /' "$TMP/shim_build.log"; exit 1; }
chmod 755 "$SHIM"

# Make sure the preload actually takes effect before sweeping. Without this
# check a shim that cannot be loaded (e.g. the checkout lives on a noexec
# mount) makes every run a no-op and the sweep "passes" without injecting
# anything. Try the checkout first, then a copy in /var/tmp and /tmp.
probe_shim() {
    rm -f "$TMP/probe.log"
    env LD_PRELOAD="$1" KARI_FI_SPEC="socket@1:errno=EACCES" KARI_FI_LOG="$TMP/probe.log" \
        perl -MSocket -e 'socket(my $s, PF_INET, SOCK_DGRAM, 0);' > "$TMP/probe.out" 2>&1
    grep -q "socket@1" "$TMP/probe.log" 2>/dev/null
}
SHIM_OK=0
for dir in "" /var/tmp /tmp; do
    if [ -n "$dir" ]; then
        cand="$dir/kari_fi_preload.$$.so"
        cp "$SHIM" "$cand" 2>/dev/null || continue
        chmod 755 "$cand"
    else
        cand="$SHIM"
    fi
    if probe_shim "$cand"; then SHIM="$cand"; SHIM_OK=1; break; fi
    echo "  note: fault-injection shim not effective from $cand"
    [ -s "$TMP/probe.out" ] && sed 's/^/    /' "$TMP/probe.out" | head -3
done
if [ $SHIM_OK -ne 1 ]; then
    echo "FAIL: LD_PRELOAD fault-injection shim could not be activated (see notes above)"
    exit 1
fi
echo "  fault-injection shim: $SHIM"
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null
    pkill -9 -f "karidns -f $TMP" 2>/dev/null
    rm -f /var/tmp/kari_fi_preload.$$.so /tmp/kari_fi_preload.$$.so
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

cat > "$TMP/fi.zone" <<'ZEOF'
$ORIGIN fi.test.
$TTL 300
@   IN SOA ns1.fi.test. hostmaster.fi.test. 2026092501 7200 3600 1209600 300
@   IN NS  ns1.fi.test.
ns1 IN A   127.0.0.1
www IN A   192.0.2.1
txt IN TXT "fault injection"
ZEOF

cat > "$TMP/karidns.conf" <<CEOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    pid-file "$TMP/run/karidns.pid";
};
logging {
    channel q { file "$TMP/run/query.log" versions 2 size 1k; print-time yes; };
    category queries { q; };
};
control-channel {
    port $CTRL_PORT;
    bind-address 127.0.0.1;
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
zone "fi.test" {
    type master;
    file "$TMP/fi.zone";
    allow-transfer { 127.0.0.1; };
    also-notify { 127.0.0.1 port 10155; };
};
CEOF

cat > "$TMP/karictl.conf" <<KEOF
server 127.0.0.1;
port $CTRL_PORT;
key "karictl" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
KEOF

CRASHES=0
RUNS=0
FIRED=0

# run_one "<KARI_FI_SPEC>" -> 0 if the injected fault fired, 1 otherwise
run_one() {
    spec="$1"
    rm -f "$TMP/fired.log"
    # karidns hands the pid/log directory over to the unprivileged user, and
    # then refuses a directory it does not trust on the next start: recreate it
    rm -rf "$TMP/run"; mkdir -m 755 "$TMP/run"
    RUNS=$((RUNS + 1))
    env LD_PRELOAD="$SHIM" KARI_FI_SPEC="$spec" KARI_FI_LOG="$TMP/fired.log" \
        "$KARIDNS" -f "$TMP/karidns.conf" > "$TMP/server.log" 2>&1 &
    SERVER_PID=$!
    # wait up to ~3s for the server to answer (or to exit)
    i=0
    while [ $i -lt 30 ]; do
        kill -0 "$SERVER_PID" 2>/dev/null || break
        # dag exits 0 even on a timeout, so look for an actual answer
        out="$("$DAG" @127.0.0.1 -p $PORT fi.test. SOA +time=1 +tries=1 +short 2>/dev/null)"
        case "$out" in *hostmaster*) break ;; esac
        sleep 0.1
        i=$((i + 1))
    done
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        "$DAG" @127.0.0.1 -p $PORT www.fi.test. A +time=1 +tries=1 >/dev/null 2>&1
        "$DAG" @127.0.0.1 -p $PORT txt.fi.test. TXT +tcp +time=1 +tries=1 >/dev/null 2>&1
        "$DAG" @127.0.0.1 -p $PORT nx.fi.test. A +keepopen +tcp www.fi.test. A +time=1 +tries=1 >/dev/null 2>&1
        "$DAG" @127.0.0.1 -p $PORT fi.test. AXFR +time=1 +tries=1 >/dev/null 2>&1
        "$KARICTL" -f "$TMP/karictl.conf" status >/dev/null 2>&1
        "$KARICTL" -f "$TMP/karictl.conf" notify fi.test >/dev/null 2>&1
        "$KARICTL" -f "$TMP/karictl.conf" reload fi.test >/dev/null 2>&1
        "$KARICTL" -f "$TMP/karictl.conf" reconfig >/dev/null 2>&1
        "$DAG" @127.0.0.1 -p $PORT www.fi.test. A +time=1 +tries=1 >/dev/null 2>&1
        if [ -n "${HEAVY:-}" ]; then
            # enough logged queries to rotate the 1k query log a few times
            j=0
            while [ $j -lt 40 ]; do
                "$DAG" @127.0.0.1 -p $PORT q$j.fi.test. A +time=1 +tries=1 >/dev/null 2>&1
                j=$((j + 1))
            done
            sleep 1
        fi
        kill -TERM "$SERVER_PID" 2>/dev/null
    fi
    i=0
    while kill -0 "$SERVER_PID" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
    kill -9 "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    rc=$?
    SERVER_PID=""
    pkill -9 -f "karidns -f $TMP" 2>/dev/null
    # 128+SIGABRT(6) / SIGBUS(10) / SIGSEGV(11), or a sanitizer report
    if [ $rc -eq 134 ] || [ $rc -eq 138 ] || [ $rc -eq 139 ] || grep -q "Sanitizer\|Segmentation fault" "$TMP/server.log"; then
        echo "  !! crash (rc=$rc) with KARI_FI_SPEC=$spec"
        tail -n 5 "$TMP/server.log" | sed 's/^/     /'
        CRASHES=$((CRASHES + 1))
    fi
    if [ -s "$TMP/fired.log" ]; then FIRED=$((FIRED + 1)); return 0; fi
    return 1
}

# sweep <call> <max-N> [errno]   (CHILD=1: only count calls in forked children)
sweep() {
    call="$1"; max="$2"; err="${3:-}"
    n=1
    while [ $n -le "$max" ]; do
        if [ -n "$err" ]; then spec="$call@$n:errno=$err"; else spec="$call@$n:"; fi
        [ -n "${CHILD:-}" ] && spec="$spec:child"
        run_one "$spec" || break
        n=$((n + 1))
    done
    echo "  $call${err:+ ($err)}${CHILD:+ [children]}: swept N=1..$((n - 1))"
}

echo "=== KariDNS server fault-injection sweep ==="
sweep socket 64
sweep bind 32 EADDRINUSE
sweep setsockopt 160 ENOBUFS
sweep listen 16
sweep socketpair 64
sweep fork 32 EAGAIN
sweep pthread_create 160
sweep kqueue 40 EMFILE
sweep setgroups 3 EPERM
sweep setgid 3 EPERM
sweep setuid 3 EPERM
sweep getpwnam 3
sweep getgrnam 3
sweep cap_enter 3 ENOSYS
sweep mkdir 16 EACCES
sweep accept 16 EMFILE
sweep accept 3 ECONNABORTED
sweep sendmsg 16 ENOBUFS
sweep sendto 16 ENOBUFS
sweep rename 3 EXDEV
sweep getsockname 32
sweep connect 6 ECONNREFUSED
# the same calls failing inside the broker / frontend / backend processes
CHILD=1
sweep setgroups 2 EPERM
sweep setgid 2 EPERM
sweep setuid 2 EPERM
sweep getpwnam 3
sweep getgrnam 3
sweep kqueue 16 EMFILE
sweep socket 24
sweep bind 16 EADDRINUSE
sweep socketpair 16
sweep pthread_create 64
sweep cap_enter 2 ENOSYS
CHILD=
# log rotation: rename and re-open of the query log fail
HEAVY=1
sweep renameat 6 EXDEV
sweep openat 48 EMFILE
HEAVY=

echo "  -> $RUNS runs, $FIRED with an injected fault, $CRASHES crash(es)"
if [ $FIRED -eq 0 ]; then
    echo "FAIL: no fault was ever injected"
    exit 1
fi
if [ $CRASHES -ne 0 ]; then
    echo "FAIL: karidns crashed under fault injection"
    exit 1
fi
echo "PASS: karidns survived every injected fault"
exit 0
