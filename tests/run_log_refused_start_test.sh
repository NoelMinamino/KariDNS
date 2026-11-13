#!/bin/sh
# ==============================================================================
# tests/run_log_refused_start_test.sh - a start refused after the log files were made leaves none of them root-owned (0.7 M2)
# ==============================================================================
# karidns opens (and makes) its log files before it checks the pid file and control socket directories, and hands them to the run user only
# after those checks.  A start that is refused in between used to leave the files it had just made, and a log directory it had made,
# root-owned: the next start took the files over, but the directory stayed root's and the run-user Backend could not roll the files in it.
#   1  a start refused by an unsafe pid file directory (group / other writable): exit 1, the reason on stderr; the log file it made, the
#      directory it made for it and karidns.run (default_debug) belong to the run user; a log file that was there before (root's) keeps its
#      owner; nothing was removed
#   2  the next start (the directory fixed) works: the run-user Backend appends to the files and rolls the one with a size limit in the
#      directory the refused start made
# Needs root (the run user is nobody).  SKIP otherwise.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN_DIR:-$ROOT}"
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the files are handed to the run user nobody)"; exit 0; fi
for b in "$BIN/karidns" "$BIN/karictl"; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_logrefused.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
FAILS=0; PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "PASS: $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL: $1"; }
cleanup() {
    set +e
    kari_kill_tree "$SRV"
    kari_kill_conf "$T/k.conf"
    [ "$FAILS" -ne 0 ] && { ls -lR "$T" 2>/dev/null | head -60; tail -20 "$T/k.log" "$T/k2.log" 2>/dev/null; }
    if [ -n "${KARI_KEEP_TMP:-}" ]; then echo "kept: $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PORT=$(kari_port 0 $((22000 + $$ % 20000)))
SECRET="cmVmdXNlZC1zdGFydC10ZXN0LWNvbnRyb2wta2V5LTAw"
mkdir "$T/dir" "$T/logs" "$T/old" "$T/pid" "$T/ctl"     # root's, 0755 (the pid directory is made unsafe below)
chmod 755 "$T/dir" "$T/logs" "$T/old" "$T/pid" "$T/ctl"
OLD="$T/old/b.log"
: > "$OLD"; chmod 644 "$OLD"                              # a log file from before: root's
NEWDIR="$T/logs/sub"                                     # made by the start (prepare_log_dir())
NEW="$NEWDIR/a.log"
RUN="$T/dir/karidns.run"
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$T/file.zone"
printf 'socket "%s/ctl/ctl.sock";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T" "$SECRET" > "$T/karictl.conf"
chmod 600 "$T/karictl.conf"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; group "nobody"; directory "$T/dir"; pid-file "$T/pid/k.pid"; listen-on { 127.0.0.1; }; port $PORT;
};
control-channel { socket "$T/ctl/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; };
logging {
    channel a { file "$NEW" versions 2 size 2k; severity info; print-severity yes; };
    channel b { file "$OLD"; severity info; };
    category general { a; b; default_debug; };
};
zone "file.test" { type primary; file "$T/file.zone"; };
EOF
owner() { stat -f %Su "$1" 2>/dev/null; }
ctl() { "$BIN/karictl" -s "$T/ctl/ctl.sock" -f "$T/karictl.conf" "$@" 2>&1; }

# ================================================================ 1: the refused start
echo "== 1: a start refused by the pid file directory"
chmod 777 "$T/pid"
"$BIN/karidns" -c "$T/k.conf" -f > "$T/k.log" 2>&1
rc=$?
[ $rc -eq 1 ] && grep -q "Refusing to use directory '$T/pid'" "$T/k.log" && pass "1: the start is refused (exit 1): unsafe pid file directory" ||
    fail "1: rc $rc, $(tail -3 "$T/k.log")"
[ -f "$NEW" ] && [ "$(owner "$NEW")" = nobody ] && pass "1: the log file the start made belongs to the run user" || fail "1: $(ls -l "$NEW" 2>&1)"
[ -d "$NEWDIR" ] && [ "$(owner "$NEWDIR")" = nobody ] && pass "1: so does the directory it made for it" || fail "1: $(ls -ld "$NEWDIR" 2>&1)"
[ -f "$RUN" ] && [ "$(owner "$RUN")" = nobody ] && pass "1: and karidns.run (default_debug)" || fail "1: $(ls -l "$RUN" 2>&1)"
[ -f "$OLD" ] && [ "$(owner "$OLD")" = root ] && pass "1: a log file from before keeps its owner (root)" || fail "1: $(ls -l "$OLD" 2>&1)"
[ "$(owner "$T/logs")" = root ] && [ "$(owner "$T/dir")" = root ] && pass "1: directories that were there keep their owner" || fail "1: $(ls -ld "$T/logs" "$T/dir")"
[ ! -e "$T/pid/k.pid" ] && pass "1: no pid file" || fail "1: a pid file: $(ls -l "$T/pid")"

# ================================================================ 2: the next start
echo "== 2: the next start"
chmod 755 "$T/pid"
"$BIN/karidns" -c "$T/k.conf" -f > "$T/k2.log" 2>&1 &
SRV=$!
i=0; until ctl status 2>/dev/null | grep -q '^version:'; do i=$((i + 1)); [ $i -gt 80 ] && break; sleep 0.25; done
ctl status | grep -q '^version:' && pass "2: the next start works" || fail "2: no control channel"
ctl trace 1 > /dev/null
kari_wait_log "$RUN" '\[Control\] debug level is now 1$' 10 && pass "2: the run-user Backend appends to karidns.run" || fail "2: karidns.run: $(cat "$RUN")"
i=0
while [ $i -lt 60 ] && [ ! -e "$NEW.0" ]; do ctl trace 2 > /dev/null; ctl notrace > /dev/null; i=$((i + 1)); done
[ -e "$NEW.0" ] && [ "$(owner "$NEW.0")" = nobody ] && [ "$(owner "$NEW")" = nobody ] &&
    pass "2: the Backend rolled $NEW in the directory the refused start made (a.log.0 and the new a.log are the run user's)" ||
    { fail "2: no roll: $(ls -l "$NEWDIR")"; grep -i "rotate\|roll" "$T/k2.log" | tail -3; }
grep -q 'debug level is now' "$OLD" && pass "2: the file from before is used (and handed over as on any start)" || fail "2: nothing in $OLD"
[ "$(owner "$OLD")" = nobody ] && pass "2: ... it belongs to the run user now, as before 0.7" || fail "2: owner of $OLD: $(owner "$OLD")"

echo "== $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
