#!/bin/sh
# run_daemonize_relative_paths_test.sh - relative paths of a daemonized karidns (BIND 9.20 compatibility, batch 1 follow-up).
# daemonize() used to chdir("/") (BIND's named_os_daemonize() does not): a relative pid-file, control-channel or dnstap socket path was then
# looked for there.  Now the daemon keeps the directory it was started in, or options { directory } (main() chdir()s there once, as BIND
# does when it reads the statement), so a relative name means the same before and after daemonize().  The paths that are handed to something
# that does not share the working directory (the pid file, the database loader, which is started from "/") are made absolute at start-up.
#   - a daemonized karidns (no -f) started from a deliberately deep directory (> 150 characters) with a relative pid-file, relative zone
#     file, relative -c and a relative control-channel socket (short name): the pid file and the socket are in the starting directory, the
#     zone answers, karictl status / reload work through the relative socket, a SIGHUP reload still finds the configuration and the zone
#     file, and stopping the server removes the pid file
#   - the same with a relative options { directory }, plus a relative dnstap socket (with the mock receiver): sockets are below directory
#   - a path that does not fit is a clear start-up error, not a truncated path (pid-file in the configuration, -P, socket paths)
#   - root only (the loader must be root-owned): a relative database-file and loader-path of options { database }
# Nothing here depends on how deep the checkout is: paths are made up at run time and the output is matched on file names only.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
DAG="${DAG:-$ROOT/dag}"
KARICTL="${KARICTL:-$ROOT/karictl}"
[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICTL" ] || make -C "$ROOT" karidns dag karictl >/dev/null || exit 1
case "$KARIDNS" in /*) ;; *) KARIDNS="$(cd "$(dirname "$KARIDNS")" && pwd)/$(basename "$KARIDNS")" ;; esac
case "$DAG" in /*) ;; *) DAG="$(cd "$(dirname "$DAG")" && pwd)/$(basename "$DAG")" ;; esac
case "$KARICTL" in /*) ;; *) KARICTL="$(cd "$(dirname "$KARICTL")" && pwd)/$(basename "$KARICTL")" ;; esac
SECRET="cDEwLWRtei10ZXN0LWNvbnRyb2wta2V5LXNlY3JldA=="

DEEP=""
W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-dmz.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
P1=$(kari_port 1 15731)
P2=$(kari_port 2 15732)
P3=$(kari_port 3 15733)
FAILS=0
PIDFILES=""

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    [ -n "${RECV_PID:-}" ] && kill "$RECV_PID" 2>/dev/null
    for f in $PIDFILES; do
        [ -f "$f" ] && p=$(cat "$f" 2>/dev/null) && [ -n "$p" ] && kari_kill_tree "$p"
    done
    [ -n "$DEEP" ] && kari_kill_conf "$DEEP/etc/s1.conf" "$DEEP/etc/s2.conf" "$DEEP/etc/s3.conf" "$DEEP/etc/s4.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P1 $P2 $P3; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

# a deep working directory: more than 150 characters, whatever $TMPDIR is
DEEP="$W"
for n in aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddddddddddd; do
    DEEP="$DEEP/$n"
    [ ${#DEEP} -gt 160 ] && break
done
mkdir -p "$DEEP/etc" "$DEEP/run" "$DEEP/dirrel/run"
chmod -R 755 "$W"
if [ ${#DEEP} -gt 150 ]; then pass "the working directory is ${#DEEP} characters long (> 150)"; else fail "the working directory is only ${#DEEP} characters long"; fi

zone() { # zone FILE ORIGIN [extra record] [extra record]
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.80\n' "$2" > "$1"
    [ -n "${3:-}" ] && printf '%s\n' "$3" >> "$1"
    [ -n "${4:-}" ] && printf '%s\n' "$4" >> "$1"
    return 0
}
ctl() { # ctl DIR SOCKET COMMAND : karictl run from DIR with a relative socket name and configuration
    ( cd "$1" && "$KARICTL" -s "$2" -f etc/ctl.conf "$3" 2>&1 )
}
ans() { "$DAG" "@127.0.0.1" -p "$1" "$2" "${3:-A}" +short +nohexdump +time=2 +tries=1 2>&1; }
wait_gone() { # wait_gone PID SECONDS
    _i=0
    while [ $_i -lt $(($2 * 5)) ]; do kill -0 "$1" 2>/dev/null || return 0; sleep 0.2; _i=$((_i + 1)); done
    return 1
}
wait_ans() { # wait_ans PORT NAME EXPECTED SECONDS
    _i=0
    while [ $_i -lt $(($4 * 5)) ]; do [ "$(ans "$1" "$2")" = "$3" ] && return 0; sleep 0.2; _i=$((_i + 1)); done
    return 1
}

# ---------------------------------------------------------------- 1. daemonized, relative pid-file / zone / -c, deep working directory
zone "$DEEP/z1.zone" one.test
cat > "$DEEP/etc/s1.conf" <<EOF
options { port $P1; bind-address { 127.0.0.1; }; pid-file "run/k1.pid"; $USER_OPT };
control-channel { socket "k1.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "one.test" { type primary; file "z1.zone"; };
EOF
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$DEEP/etc/ctl.conf"
chmod 600 "$DEEP/etc/ctl.conf"
( cd "$DEEP" && "$KARIDNS" -c etc/s1.conf ) > "$W/s1.out" 2>&1
RC=$?
PIDFILES="$PIDFILES $DEEP/run/k1.pid"
[ $RC -eq 0 ] && pass "karidns daemonized (the parent exited 0)" || fail "karidns -c etc/s1.conf exited $RC: $(cat "$W/s1.out")"
if kari_wait_answer "$DAG" "$P1" one.test 20; then pass "the daemon answers"; else fail "the daemon did not start"; fi
if [ -f "$DEEP/run/k1.pid" ]; then pass "the relative pid-file was written in the starting directory (k1.pid)"; else fail "no run/k1.pid below the starting directory"; fi
[ ! -e /run/k1.pid ] && [ ! -e /k1.pid ] && [ ! -e /etc/s1.conf ] && pass "nothing was created below / by the daemon" || fail "a pid file was created below /"
PID1=$(cat "$DEEP/run/k1.pid" 2>/dev/null)
if [ -n "$PID1" ] && kill -0 "$PID1" 2>/dev/null; then pass "the pid in k1.pid is a running process"; else fail "k1.pid does not name a running process ($PID1)"; fi
[ "$(ans "$P1" www.one.test)" = "192.0.2.80" ] && pass "the zone file given as a relative name is served" || fail "www.one.test: $(ans "$P1" www.one.test)"

# the control socket is bound by its relative name after daemonize(): in the starting directory (the process did not move to "/"), and
# karictl reaches it through the same relative name
[ -S "$DEEP/k1.sock" ] && pass "the relative control-channel socket was created in the starting directory (k1.sock)" || fail "no k1.sock in the starting directory"
[ ! -e /k1.sock ] && pass "no control socket below /" || fail "a control socket was created below /"
OUT=$(ctl "$DEEP" k1.sock status); RC=$?
if [ $RC -eq 0 ] && [ -n "$OUT" ]; then pass "karictl status through the relative control socket"; else fail "karictl status (rc=$RC): $(echo "$OUT" | head -3)"; fi

# a reload after daemonize(): the configuration (-c etc/s1.conf) and the zone file are read again by their relative names
zone "$DEEP/z1.zone" one.test 'new IN A 192.0.2.99'
kill -HUP "$PID1"
if wait_ans "$P1" new.one.test 192.0.2.99 15; then pass "SIGHUP reload re-reads the relative configuration and zone file"; else fail "reload did not bring in new.one.test"; fi
zone "$DEEP/z1.zone" one.test 'new IN A 192.0.2.99' 'newer IN A 192.0.2.97'
OUT=$(ctl "$DEEP" k1.sock reload); RC=$?
if [ $RC -eq 0 ] && wait_ans "$P1" newer.one.test 192.0.2.97 15; then pass "karictl reload through the relative control socket"; else fail "karictl reload (rc=$RC): $OUT"; fi

kill -TERM "$PID1"
if wait_gone "$PID1" 15; then pass "the daemon stopped on SIGTERM"; else fail "the daemon did not stop"; kill -KILL "$PID1" 2>/dev/null; fi
if [ ! -e "$DEEP/run/k1.pid" ]; then pass "the pid file was removed when the daemon stopped"; else fail "run/k1.pid is still there"; fi

# ---------------------------------------------------------------- 2. a relative options { directory }
zone "$DEEP/dirrel/z2.zone" two.test
cat > "$DEEP/etc/s2.conf" <<EOF
options { port $P2; bind-address { 127.0.0.1; }; directory "dirrel"; pid-file "run/k2.pid"; $USER_OPT };
control-channel { socket "k2.sock"; algorithm hmac-sha256; secret "$SECRET"; };
dnstap { socket "ds.sock"; identity "dmz-test"; version "1"; log-queries yes; log-responses yes; queue-size 64; };
zone "two.test" { type primary; file "z2.zone"; };
EOF
# a dnstap receiver listening on a relative name in the directory the server will be in (the server connects to "ds.sock" after daemonize())
HAVE_RECV=0
if command -v perl >/dev/null 2>&1 && [ -f "$DIR/mock_dnstap_receiver.pl" ]; then
    ( cd "$DEEP/dirrel" && exec perl "$DIR/mock_dnstap_receiver.pl" --socket ds.sock --output dnstap.out --max-frames 4 --timeout 60 ) > "$W/recv.out" 2>&1 &
    RECV_PID=$!
    i=0; while [ $i -lt 50 ] && [ ! -S "$DEEP/dirrel/ds.sock" ]; do sleep 0.1; i=$((i + 1)); done
    if [ -S "$DEEP/dirrel/ds.sock" ]; then HAVE_RECV=1; else fail "the mock dnstap receiver did not start"; fi
fi
( cd "$DEEP" && "$KARIDNS" -c etc/s2.conf ) > "$W/s2.out" 2>&1
RC=$?
PIDFILES="$PIDFILES $DEEP/dirrel/run/k2.pid"
[ $RC -eq 0 ] && pass "karidns with a relative directory daemonized" || fail "karidns -c etc/s2.conf exited $RC: $(cat "$W/s2.out")"
if kari_wait_answer "$DAG" "$P2" two.test 20; then pass "the daemon with a relative directory answers (zone file below directory)"; else fail "the second daemon did not start"; fi
[ -f "$DEEP/dirrel/run/k2.pid" ] && pass "pid-file is below the (relative) directory: run/k2.pid" || fail "no dirrel/run/k2.pid"
PID2=$(cat "$DEEP/dirrel/run/k2.pid" 2>/dev/null)
# with a directory the daemon is in it: the relative sockets are there, not in the starting directory
[ -S "$DEEP/dirrel/k2.sock" ] && pass "the relative control-channel socket is below directory (k2.sock)" || fail "no dirrel/k2.sock"
[ ! -e "$DEEP/k2.sock" ] && pass "and not in the starting directory" || fail "k2.sock is in the starting directory"
OUT=$(ctl "$DEEP" dirrel/k2.sock status); RC=$?
if [ $RC -eq 0 ] && [ -n "$OUT" ]; then pass "karictl status through the control socket below directory"; else fail "karictl status k2 (rc=$RC): $(echo "$OUT" | head -3)"; fi
if [ $HAVE_RECV -eq 1 ]; then
    ans "$P2" www.two.test > /dev/null
    i=0; while [ $i -lt 100 ] && ! grep -q "type=AUTH_RESPONSE" "$DEEP/dirrel/dnstap.out" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    if grep -q "type=AUTH_QUERY" "$DEEP/dirrel/dnstap.out" 2>/dev/null && grep -q "type=AUTH_RESPONSE" "$DEEP/dirrel/dnstap.out" 2>/dev/null; then
        pass "the daemon connected to the relative dnstap socket (query and response frames received)"
    else
        fail "no dnstap frames through the relative socket: $(head -3 "$W/recv.out")"
    fi
else
    echo "SKIP: dnstap through a relative socket (needs perl and tests/mock_dnstap_receiver.pl)"
fi
zone "$DEEP/dirrel/z2.zone" two.test 'new IN A 192.0.2.98'
[ -n "$PID2" ] && kill -HUP "$PID2"
if wait_ans "$P2" new.two.test 192.0.2.98 15; then pass "reload with a relative directory re-reads the zone file"; else fail "reload did not bring in new.two.test"; fi
[ -n "$PID2" ] && kill -TERM "$PID2"
if [ -n "$PID2" ] && wait_gone "$PID2" 15; then pass "the daemon stopped"; else fail "the second daemon did not stop"; [ -n "$PID2" ] && kill -KILL "$PID2" 2>/dev/null; fi
[ ! -e "$DEEP/dirrel/run/k2.pid" ] && pass "the pid file was removed" || fail "dirrel/run/k2.pid is still there"
[ -n "${RECV_PID:-}" ] && kill "$RECV_PID" 2>/dev/null

# ---------------------------------------------------------------- 2b. a UNIX socket path longer than sun_path is refused before daemonize(), with the reason
SOCKLONG=$(awk 'BEGIN { s = ""; for (i = 0; i < 12; i++) s = s "0123456789"; print s }')   # 120 characters
for which in control-channel dnstap; do
    if [ "$which" = control-channel ]; then stmt="control-channel { socket \"$SOCKLONG.sock\"; algorithm hmac-sha256; secret \"$SECRET\"; };"
    else stmt="dnstap { socket \"$SOCKLONG.sock\"; };"; fi
    cat > "$DEEP/etc/s3.conf" <<EOF
options { port $P3; bind-address { 127.0.0.1; }; $USER_OPT };
$stmt
zone "three.test" { type primary; file "z1.zone"; };
EOF
    OUT=$( cd "$DEEP" && "$KARIDNS" -f -c etc/s3.conf 2>&1 )
    RC=$?
    if [ $RC -ne 0 ] && echo "$OUT" | grep -q "a UNIX socket path holds at most 103 bytes"; then pass "a too long $which socket path is refused with a clear message"; else fail "long $which socket (rc=$RC): $(echo "$OUT" | head -3)"; fi
done

# ---------------------------------------------------------------- 3. a path that does not fit is an error, not a truncated path
LONGNAME=$(awk 'BEGIN { s = ""; for (i = 0; i < 110; i++) s = s "0123456789"; print s }')   # 1100 characters
cat > "$DEEP/etc/s3.conf" <<EOF
options { port $P3; bind-address { 127.0.0.1; }; pid-file "$LONGNAME.pid"; $USER_OPT };
zone "three.test" { type primary; file "z1.zone"; };
EOF
OUT=$( cd "$DEEP" && "$KARIDNS" -f -c etc/s3.conf 2>&1 )
RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "once it is made absolute against the directory karidns was started in"; then pass "a pid-file that is too long once absolute is refused with a clear message"; else fail "long pid-file (rc=$RC): $(echo "$OUT" | head -3)"; fi
sockstat -4 -l -p "$P3" 2>/dev/null | grep -q ":$P3 " && fail "a server is listening although the configuration was refused"
cat > "$DEEP/etc/s3.conf" <<EOF
options { port $P3; bind-address { 127.0.0.1; }; $USER_OPT };
zone "three.test" { type primary; file "z1.zone"; };
EOF
OUT=$( cd "$DEEP" && "$KARIDNS" -f -P "$LONGNAME.pid" -c etc/s3.conf 2>&1 )
RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "PID file.*once it is made absolute"; then pass "-P with a name that is too long once absolute is refused"; else fail "long -P (rc=$RC): $(echo "$OUT" | head -3)"; fi
OUT=$( cd "$DEEP" && "$KARIDNS" -f -P "/$LONGNAME.pid" -c etc/s3.conf 2>&1 )
RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "PID file path is .* bytes long"; then pass "an absolute -P that is too long is refused, not truncated"; else fail "long absolute -P (rc=$RC): $(echo "$OUT" | head -3)"; fi

# ---------------------------------------------------------------- 4. root only: a relative database-file and loader-path
SQL="$ROOT/tests/db/pdns_schema.sqlite3.sql"
Z2S="$ROOT/tests/db/zone2sql"
LOADER="$ROOT/karidns-dbloader"
if [ "$(id -u)" != "0" ]; then
    echo "SKIP: relative database-file / loader-path (needs root: the loader runs as another user)"
elif ! command -v sqlite3 >/dev/null 2>&1 || [ ! -x "$LOADER" ] || [ ! -x "$Z2S" ] || [ ! -f "$SQL" ] || ! "$LOADER" --drivers | grep -qx sqlite3; then
    echo "SKIP: relative database-file / loader-path (needs sqlite3, karidns-dbloader with SQLite3 and tests/db/zone2sql)"
else
    mkdir -p "$DEEP/db" "$DEEP/bin" "$DEEP/etc"
    zone "$DEEP/dbz.zone" db1.test
    sqlite3 "$DEEP/db/z.db" < "$SQL" > /dev/null
    "$Z2S" --dialect sqlite3 "$DEEP/dbz.zone" 2>/dev/null | sqlite3 "$DEEP/db/z.db"
    chown -R nobody "$DEEP/db"; chmod 600 "$DEEP/db/z.db"*
    install -o root -g wheel -m 755 "$LOADER" "$DEEP/bin/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$DEEP/bin/karidns-dbloader"; chown 0:0 "$DEEP/bin/karidns-dbloader"; chmod 755 "$DEEP/bin/karidns-dbloader"; }
    P4=$(kari_port 4 15734)
    cat > "$DEEP/etc/s4.conf" <<EOF
options {
    user "nobody"; port $P4; bind-address { 127.0.0.1; }; pid-file "run/k4.pid";
    database { driver sqlite3; database-file "db/z.db"; loader-user "nobody"; loader-path "bin/karidns-dbloader"; };
};
EOF
    ( cd "$DEEP" && "$KARIDNS" -c etc/s4.conf ) > "$W/s4.out" 2>&1
    RC=$?
    PIDFILES="$PIDFILES $DEEP/run/k4.pid"
    [ $RC -eq 0 ] && pass "karidns with a relative database-file and loader-path daemonized" || fail "karidns -c etc/s4.conf exited $RC: $(cat "$W/s4.out")"
    if wait_ans "$P4" www.db1.test 192.0.2.80 30; then pass "a zone from the SQLite3 database named by a relative database-file is served by the daemon"; else fail "no DB zone answer (the loader could not open the relative database-file?)"; fi
    PID4=$(cat "$DEEP/run/k4.pid" 2>/dev/null)
    # a restarted loader finds its binary and its database again: both are absolute now
    LP=$(pgrep -P "$PID4" -f 'karidns-dbloader -s 3' | head -1)
    if [ -n "$LP" ]; then
        kill -KILL "$LP"
        sleep 3
        LP2=$(pgrep -P "$PID4" -f 'karidns-dbloader -s 3' | head -1)
        if [ -n "$LP2" ] && [ "$LP2" != "$LP" ]; then pass "the loader was restarted from the relative loader-path"; else fail "the loader did not come back after a kill"; fi
    else
        fail "no karidns-dbloader child of the daemon"
    fi
    [ -n "$PID4" ] && kill -TERM "$PID4"
    if [ -n "$PID4" ] && wait_gone "$PID4" 20; then pass "the daemon with a loader stopped"; else fail "the daemon with a loader did not stop"; [ -n "$PID4" ] && kill -KILL "$PID4" 2>/dev/null; fi
fi

if [ "$FAILS" -eq 0 ]; then echo "ALL TESTS PASSED"; exit 0; fi
echo "$FAILS FAILURE(S)"
exit 1
