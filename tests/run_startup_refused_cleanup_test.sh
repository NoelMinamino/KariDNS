#!/bin/sh
# ==============================================================================
# tests/run_startup_refused_cleanup_test.sh - what a refused start leaves behind: the control socket, the pid file, the log files (0.7)
# ==============================================================================
# A start that is refused after it bound the control socket used to leave the socket file (root-owned when its owner could not be set); a
# fork or setsid() failure in daemonize() exited without the log hand-off (the log files it made stayed root-owned) and left the pid file; a
# log directory the start made that is also the pid file or control socket directory went to the run user, so that start worked and every
# later one was refused ("not root-owned").  The faults are injected with tests/fi/kari_fi_preload.c (LD_PRELOAD).
#   1  allow-group: the mode (fchmodat) or the owner (fchownat) of the socket cannot be set: exit 1, the reason; the socket, the pid file
#      are gone, the log file and the directory the start made are the run user's, a file that was there stays; the next start works
#   2  the fork of the Backend fails (after the bind and the log hand-off): the same
#   3  a socketpair of the IPC tables fails (after daemonize, before the bind): no pid file, the log file is the run user's
#   4  daemonize(): the first fork (exit 1, the reason on stderr), setsid() and the second fork (the first process has exited 0) fail: the
#      reason on stderr, no pid file, the log files the run user's
#   5  a second instance against a running server is refused and the first one keeps answering on its socket
#   6  a log directory the start would make that is also the pid file / control socket directory: refused before anything is bound, the
#      reason on stderr, again at the next start; a root-owned directory that was there is used as before
#   7  a log directory the start makes above the pid file / control socket directory (its parent, a grandparent, through a symlink or
#      ".."): refused before the directory is made, the reason on stderr, the log directories the run user's; with the pid file / socket
#      moved out the next start works; a root-owned log directory that was there above them is used as before
# Needs root (the run user is nobody) and a C compiler for the shim.  SKIP otherwise.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN_DIR:-$ROOT}"
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the files are handed to the run user nobody)"; exit 0; fi
for b in "$BIN/karidns" "$BIN/karictl"; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_refclean.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
FAILS=0; PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "PASS: $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL: $1"; }
cleanup() {
    set +e
    kari_kill_tree "$SRV"
    for c in "$T"/*.conf; do [ -f "$c" ] && kari_kill_conf "$c"; done
    [ "$FAILS" -ne 0 ] && ls -lR "$T" 2>/dev/null | grep -v '\.so$' | head -80
    rm -f "/var/tmp/kari_fi_preload.$$.so"
    if [ -n "${KARI_KEEP_TMP:-}" ]; then echo "kept: $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

# the shim, from the checked-out source; it must take effect (a noexec /tmp: a copy in /var/tmp)
SHIM="$T/kari_fi_preload.so"
${CC:-cc} -O1 -fPIC -shared -o "$SHIM" tests/fi/kari_fi_preload.c > "$T/shim.log" 2>&1 || { echo "SKIP: cannot build the shim: $(head -3 "$T/shim.log")"; exit 0; }
probe() { rm -f "$T/probe.log"; env LD_PRELOAD="$1" KARI_FI_SPEC="socket@1:errno=EACCES" KARI_FI_LOG="$T/probe.log" perl -MSocket -e 'socket(my $s, PF_INET, SOCK_DGRAM, 0);' >/dev/null 2>&1; grep -q "socket@1" "$T/probe.log" 2>/dev/null; }
if ! probe "$SHIM"; then
    cp "$SHIM" "/var/tmp/kari_fi_preload.$$.so" && SHIM="/var/tmp/kari_fi_preload.$$.so"
    probe "$SHIM" || { echo "SKIP: the LD_PRELOAD shim does not take effect"; exit 0; }
fi

PORT=$(kari_port 0 $((22000 + $$ % 20000)))
SECRET="cmVmdXNlZC1zdGFydC1jbGVhbnVwLXRlc3Qta2V5LTA="
mkdir "$T/dir"; chmod 755 "$T/dir"
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$T/file.zone"
owner() { stat -f %Su "$1" 2>/dev/null; }

# mkcase NAME [LOGDIR PIDDIR CTLDIR]: $T/NAME.conf; by default the log file is in a directory the start makes ($T/NAME/logs/new), the pid
# file in $T/NAME/pid and the socket in $T/NAME/ctl (both root's, 0755, each with a file "keep" from before; not made when it is LOGDIR,
# below it or in $NOMK); allow-group nobody; $LOG2: a second log file (channel b)
mkcase() {
    C="$T/$1"
    LOGDIR="${2:-$C/logs/new}"; PIDDIR="${3:-$C/pid}"; CTLDIR="${4:-$C/ctl}"
    mkdir -p "$C/logs"; chmod 755 "$C" "$C/logs"
    for d in "$PIDDIR" "$CTLDIR"; do
        case " $LOGDIR ${NOMK:-} " in *" $d "*) continue ;; esac; case "$d" in "$LOGDIR"/*) continue ;; esac
        mkdir -p "$d"; chmod 755 "$d"; : > "$d/keep"
    done
    B_CH=""; B_USE=""
    [ -n "${LOG2:-}" ] && { B_CH="channel b { file \"$LOG2\"; severity info; }; "; B_USE=" b;"; }
    cat > "$T/$1.conf" <<EOF
options { user "nobody"; group "nobody"; directory "$T/dir"; pid-file "$PIDDIR/k.pid"; listen-on { 127.0.0.1; }; port $PORT; };
control-channel { socket "$CTLDIR/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; allow-group "nobody"; };
logging { channel a { file "$LOGDIR/a.log"; severity info; }; ${B_CH}category default { a;${B_USE} }; category general { a; }; };
zone "file.test" { type primary; file "$T/file.zone"; };
EOF
    printf 'socket "%s/ctl.sock";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$CTLDIR" "$SECRET" > "$T/$1.ctl"
    chmod 600 "$T/$1.ctl"
}
ctl() { "$BIN/karictl" -f "$T/$1.ctl" status 2>&1; }
# bounded OUT CMD...: a start that is to be refused, with its output in OUT and its exit status in RC; one that goes on (a server that runs:
# the behaviour before 0.7 in case 6) is stopped after 30 s (RC 124) instead of holding the test
bounded() {
    _out="$1"; shift
    "$@" > "$_out" 2>&1 &
    _p=$!
    _i=0; while kill -0 "$_p" 2>/dev/null && [ $_i -lt 300 ]; do sleep 0.1; _i=$((_i + 1)); done
    if kill -0 "$_p" 2>/dev/null; then kari_kill_tree "$_p"; wait "$_p" 2>/dev/null; RC=124; else wait "$_p"; RC=$?; fi
}
# fi_start NAME SPEC [-f]: a start of NAME with the fault SPEC; RC and the output in $T/NAME.out
fi_start() {
    rm -f "$T/$1.fi"
    bounded "$T/$1.out" env LD_PRELOAD="$SHIM" KARI_FI_SPEC="$2" KARI_FI_LOG="$T/$1.fi" "$BIN/karidns" -c "$T/$1.conf" ${3:-}
}
# the process(es) of a daemon start that went on in the background are gone (they end at once; at most 20 s)
wait_gone() { i=0; while [ -n "$(kari_conf_pids "$T/$1.conf")" ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i + 1)); done; [ -z "$(kari_conf_pids "$T/$1.conf")" ]; }
# left NAME WHAT: nothing root-owned that the refused start made; what was there stays
left() {
    C="$T/$1"
    [ ! -e "$CTLDIR/ctl.sock" ] && pass "$1: $2: no control socket left" || fail "$1: $2: $(ls -l "$CTLDIR/ctl.sock")"
    [ ! -e "$PIDDIR/k.pid" ] && pass "$1: $2: no pid file left" || fail "$1: $2: $(ls -l "$PIDDIR/k.pid")"
    [ "$(owner "$LOGDIR/a.log")" = nobody ] && [ "$(owner "$LOGDIR")" = nobody ] &&
        pass "$1: $2: the log file and the directory the start made are the run user's" || fail "$1: $2: $(ls -ld "$LOGDIR" "$LOGDIR/a.log" 2>&1)"
    [ -f "$CTLDIR/keep" ] && [ -f "$PIDDIR/keep" ] && [ "$(owner "$CTLDIR")" = root ] && [ "$(owner "$PIDDIR")" = root ] &&
        pass "$1: $2: the files and directories that were there stay (root's)" || fail "$1: $2: $(ls -la "$CTLDIR" "$PIDDIR")"
}
# next NAME: the next start (no fault) works, and stops
next_start() {
    "$BIN/karidns" -c "$T/$1.conf" -f > "$T/$1.next" 2>&1 &
    SRV=$!
    i=0; until ctl "$1" | grep -q '^version:'; do i=$((i + 1)); kill -0 "$SRV" 2>/dev/null || break; [ $i -gt 120 ] && break; sleep 0.25; done
    ctl "$1" | grep -q '^version:' && pass "$1: the next start works" || fail "$1: the next start: $(tail -3 "$T/$1.next")"
    kill -TERM "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=""
}

# ================================================================ 1: allow-group
echo "== 1: the allow-group mode or owner of the socket cannot be set"
mkcase c1a
fi_start c1a "fchmodat@1:errno=EPERM" -f
[ $RC -eq 1 ] && grep -q "allow-group: cannot give the socket" "$T/c1a.out" && grep -q "fchmodat@1" "$T/c1a.fi" &&
    pass "c1a: refused (exit 1): allow-group, fchmodat" || fail "c1a: rc $RC: $(tail -3 "$T/c1a.out")"
left c1a "fchmodat"
next_start c1a
mkcase c1b
fi_start c1b "fchownat@1:errno=EPERM" -f
[ $RC -eq 1 ] && grep -q "allow-group: cannot give the socket" "$T/c1b.out" && grep -q "fchownat@1" "$T/c1b.fi" &&
    pass "c1b: refused (exit 1): allow-group, fchownat (the socket was root's)" || fail "c1b: rc $RC: $(tail -3 "$T/c1b.out")"
left c1b "fchownat"

# ================================================================ 2: the fork of the Backend
echo "== 2: the fork of the Backend fails"
mkcase c2
fi_start c2 "fork@2:errno=EAGAIN" -f        # (fork 1: the connect broker)
[ $RC -eq 1 ] && grep -q "fork@2" "$T/c2.fi" && kari_wait_log "$T/c2/logs/new/a.log" "fork for backend process failed" 5 &&
    pass "c2: refused (exit 1): fork of the Backend" || fail "c2: rc $RC: $(tail -3 "$T/c2.out") $(tail -3 "$T/c2/logs/new/a.log")"
left c2 "fork of the Backend"
next_start c2

# ================================================================ 3: the IPC tables
echo "== 3: a socketpair of the IPC tables fails"
mkcase c3
fi_start c3 "socketpair@2:errno=ENFILE" -f  # (socketpair 1: the connect broker)
[ $RC -eq 1 ] && grep -q "socketpair@2" "$T/c3.fi" && kari_wait_log "$T/c3/logs/new/a.log" "Failed to create socketpair for router" 5 &&
    pass "c3: refused (exit 1): IPC socketpair" || fail "c3: rc $RC: $(tail -3 "$T/c3.out") $(tail -3 "$T/c3/logs/new/a.log")"
left c3 "IPC socketpair"

# ================================================================ 4: daemonize()
echo "== 4: daemonize() fails"
mkcase c4a
fi_start c4a "fork@1:errno=EAGAIN"
[ $RC -eq 1 ] && grep -q "Refusing to start: cannot run as a daemon" "$T/c4a.out" &&
    pass "c4a: refused (exit 1): the first fork, the reason on stderr" || fail "c4a: rc $RC: $(tail -3 "$T/c4a.out")"
left c4a "first fork"
for x in "c4b setsid@1:errno=EPERM" "c4c fork@2:errno=EAGAIN"; do
    set -- $x
    mkcase "$1"
    fi_start "$1" "$2"
    wait_gone "$1" && kari_wait_log "$T/$1.out" "Refusing to start: cannot run as a daemon" 5 && grep -q "${2%%:*}" "$T/$1.fi" &&
        pass "$1: refused in the first child ($2; the first process exits $RC), the reason on stderr" || fail "$1: rc $RC: $(tail -3 "$T/$1.out")"
    left "$1" "$2"
done
next_start c4c

# ================================================================ 5: a second instance against a running one
echo "== 5: a second instance against a running server"
mkcase c5
"$BIN/karidns" -c "$T/c5.conf" -f > "$T/c5.next" 2>&1 &
SRV=$!
i=0; until ctl c5 | grep -q '^version:'; do i=$((i + 1)); kill -0 "$SRV" 2>/dev/null || break; [ $i -gt 120 ] && break; sleep 0.25; done
ctl c5 | grep -q '^version:' && pass "c5: the first server answers" || fail "c5: no first server: $(tail -3 "$T/c5.next")"
bounded "$T/c5.out" "$BIN/karidns" -c "$T/c5.conf" -f; rc=$RC
[ $rc -eq 1 ] && grep -q "Another KariDNS instance is already running" "$T/c5.out" && pass "c5: the second instance is refused" ||
    fail "c5: rc $rc: $(tail -3 "$T/c5.out")"
bounded "$T/c5.out2" "$BIN/karidns" -c "$T/c5.conf"; rc=$RC
[ $rc -eq 1 ] && pass "c5: so is a second daemon" || fail "c5: daemon rc $rc: $(tail -3 "$T/c5.out2")"
[ -S "$T/c5/ctl/ctl.sock" ] && ctl c5 | grep -q '^version:' && [ -s "$T/c5/pid/k.pid" ] &&
    pass "c5: the first server keeps its socket and pid file and answers" || fail "c5: $(ls -l "$T/c5/ctl" "$T/c5/pid")"
kill -TERM "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=""

# ================================================================ 6: a log directory shared with the pid file / control socket directory
echo "== 6: a log directory that is also the pid file or control socket directory"
mkcase c6a "$T/c6a/run" "$T/c6a/run" "$T/c6a/ctl"
bounded "$T/c6a.out" "$BIN/karidns" -c "$T/c6a.conf" -f; rc=$RC
[ $rc -eq 1 ] && grep -q "the pid file directory '$T/c6a/run' is also the directory of the log file '$T/c6a/run/a.log'" "$T/c6a.out" &&
    pass "c6a: a new log directory that is the pid file directory is refused (exit 1), the reason on stderr" || fail "c6a: rc $rc: $(tail -3 "$T/c6a.out")"
[ ! -e "$T/c6a/run/k.pid" ] && [ ! -e "$T/c6a/ctl/ctl.sock" ] && pass "c6a: no pid file, no socket" || fail "c6a: $(ls -l "$T/c6a/run" "$T/c6a/ctl")"
bounded "$T/c6a.out2" "$BIN/karidns" -c "$T/c6a.conf" -f; rc=$RC
[ $rc -eq 1 ] && grep -q "the pid file directory '$T/c6a/run' is also the directory of the log file" "$T/c6a.out2" &&
    pass "c6a: the next start is refused with the same reason (the directory is the run user's now)" || fail "c6a: next rc $rc: $(tail -3 "$T/c6a.out2")"
mkcase c6b "$T/c6b/run" "$T/c6b/pid" "$T/c6b/run"
bounded "$T/c6b.out" "$BIN/karidns" -c "$T/c6b.conf" -f; rc=$RC
[ $rc -eq 1 ] && grep -q "the control socket directory '$T/c6b/run' is also the directory of the log file" "$T/c6b.out" &&
    pass "c6b: a new log directory that is the control socket directory is refused (exit 1)" || fail "c6b: rc $rc: $(tail -3 "$T/c6b.out")"
[ ! -e "$T/c6b/run/ctl.sock" ] && [ ! -e "$T/c6b/pid/k.pid" ] && pass "c6b: no socket, no pid file" || fail "c6b: $(ls -l "$T/c6b/run" "$T/c6b/pid")"
mkdir -p "$T/c6c/pre"; chmod 755 "$T/c6c" "$T/c6c/pre"
mkcase c6c "$T/c6c/pre" "$T/c6c/pre" "$T/c6c/pre"      # a root-owned directory that was there: log file, pid file and socket in it
next_start c6c
next_start c6c
[ "$(owner "$T/c6c/pre")" = root ] && pass "c6c: a root-owned directory that was there is used as before (twice), and stays root's" ||
    fail "c6c: $(ls -ld "$T/c6c/pre")"

# ================================================================ 7: a log directory the start makes above the pid file / control socket directory
echo "== 7: a log directory the start makes that contains the pid file or control socket directory"
# refused_above NAME WHAT DIR LDIR LFILE: refused (exit 1) with the reason; DIR (the pid file / socket directory) was not made, no pid file, no
# socket; the log directory and file the start made are the run user's
refused_above() {
    bounded "$T/$1.out" "$BIN/karidns" -c "$T/$1.conf" -f; rc=$RC
    [ $rc -eq 1 ] && grep -qF "the directory '$4' of the log file '$5', made by this start, contains the $2 directory '$3'" "$T/$1.out" &&
        pass "$1: refused (exit 1), the reason on stderr" || fail "$1: rc $rc: $(tail -3 "$T/$1.out")"
    [ ! -e "$3" ] && [ ! -e "$PIDDIR/k.pid" ] && [ ! -e "$CTLDIR/ctl.sock" ] && pass "$1: the $2 directory was not made, no pid file, no socket" ||
        fail "$1: $(ls -la "$3" "$PIDDIR" "$CTLDIR" 2>&1)"
    [ "$(owner "$4")" = nobody ] && [ "$(owner "$5")" = nobody ] && [ "$(owner "$LOGDIR")" = nobody ] && [ "$(owner "$LOGDIR/a.log")" = nobody ] &&
        pass "$1: the log directory and file the start made are the run user's" || fail "$1: $(ls -ld "$4" "$5" "$LOGDIR" "$LOGDIR/a.log" 2>&1)"
}
L="$T/c7a/logs/new"
mkcase c7a "$L" "$L/run"                               # the parent of the pid file directory
refused_above c7a "pid file" "$L/run" "$L" "$L/a.log"
mkcase c7a "$L"                                        # corrected: the pid file in a directory of its own
next_start c7a
L="$T/c7b/logs/new"
mkcase c7b "$L" "" "$L/ctl"                            # the parent of the control socket directory
refused_above c7b "control socket" "$L/ctl" "$L" "$L/a.log"
mkcase c7b "$L"
next_start c7b
L="$T/c7c/logs/new"                                    # a grandparent: logs/new (b.log) and logs/new/a (a.log) are both made by the start
LOG2="$L/b.log"; mkcase c7c "$L/a" "$L/a/run"
refused_above c7c "pid file" "$L/a/run" "$L" "$L/b.log"
mkcase c7c "$L/a"; LOG2=""
next_start c7c
mkdir -p "$T/c7d/pre"; chmod 755 "$T/c7d" "$T/c7d/pre"  # a root-owned log directory that was there, above both: used as before
mkcase c7d "$T/c7d/pre" "$T/c7d/pre/run" "$T/c7d/pre/ctl"
next_start c7d
next_start c7d
[ "$(owner "$T/c7d/pre")" = root ] && [ "$(owner "$T/c7d/pre/run")" = root ] &&
    pass "c7d: a root-owned log directory that was there above the pid file directory is used as before (twice), and stays root's" ||
    fail "c7d: $(ls -ld "$T/c7d/pre" "$T/c7d/pre/run" 2>&1)"
L="$T/c7e/logs/new"                                    # through a symlink: c7e/lnk -> logs/new (made by the start)
NOMK="$T/c7e/lnk/run"; mkcase c7e "$L" "$T/c7e/lnk/run"; NOMK=""
ln -s logs/new "$T/c7e/lnk"
refused_above c7e "pid file" "$T/c7e/lnk/run" "$L" "$L/a.log"
L="$T/c7f/logs/new"                                    # through "..": c7f/logs/../logs/new/ctl
NOMK="$T/c7f/logs/../logs/new/ctl"; mkcase c7f "$L" "" "$T/c7f/logs/../logs/new/ctl"; NOMK=""
refused_above c7f "control socket" "$T/c7f/logs/../logs/new/ctl" "$L" "$L/a.log"

echo "== $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
