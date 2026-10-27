#!/bin/sh
# run_db_loader_sigterm_test.sh - the database loader stops promptly on SIGTERM, also in the middle of a long load (milestone B13).
#
# A restarted loader compares every zone with the Backend's inventory before it reports its first batch; for a big database that
# takes seconds, and until B13 SIGTERM was only looked at between two loads, so the manager killed the loader after 10 s.  Here
# karidns serves a SQLite3 database of ZONES zones x RRS records (default 3000 x 1000, made by tests/db/gen_sqlite3_zones.sh),
# the loader is killed (kill -9), the supervisor starts a new one, and as soon as that one has asked for the inventory (so it is
# reading the database) it gets SIGTERM.  Required: it is gone within LIMIT_MS (default 2000) and the manager did not have to kill it.
# Both with loader-threads 1 (the main thread converts) and 2 (the worker threads).  If the load finishes before the signal is
# sent, the database is too small for the machine: that is reported as a failure (raise ZONES).
#
# Needs root (the loader runs as nobody).  SKIP otherwise, and when karidns, karidns-dbloader (SQLite3 driver), the sqlite3 CLI or perl
# (Time::HiRes) is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
perl -MTime::HiRes -e 1 2>/dev/null || { echo "SKIP: perl with Time::HiRes is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

ZONES=${ZONES:-3000}
RRS=${RRS:-1000}
LIMIT_MS=${LIMIT_MS:-2000}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbsigterm.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 200 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() { stop_srv; rm -rf "$T"; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
now_ms() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time * 1000'; }
wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

mkdir "$T/db"
t0=$(now_ms)
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$ZONES" "$RRS" > /dev/null || { echo "cannot make the database"; exit 1; }
echo "database: $ZONES zones x $RRS records made in $(( $(now_ms) - t0 )) ms"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }

for LT in 1 2; do
    echo "== loader-threads $LT"
    cat > "$T/k.conf" <<EOC
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; loader-threads $LT; };
};
control-channel { socket "$T/ctl.sock"; secret "dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"; };
EOC
    : > "$T/srv$LT.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv$LT.log" 2>&1 < /dev/null &
    SRV=$!
    if wait_log "$T/srv$LT.log" "initial load complete" 300; then pass "the first load is complete"; else fail "no 'initial load complete'"; stop_srv; continue; fi
    old=$(pgrep -P "$SRV" -x karidns-dbloader | head -1)
    kill -KILL "$old" 2>/dev/null
    # the supervisor starts a new loader after 1 s; it asks for the inventory and then reads every zone to compare it
    n=0; new=""
    while [ $n -lt 100 ]; do
        new=$(pgrep -P "$SRV" -x karidns-dbloader | head -1)
        [ -n "$new" ] && [ "$new" != "$old" ] && break
        new=""; sleep 0.1; n=$((n + 1))
    done
    if [ -z "$new" ]; then fail "no new loader after kill -9"; stop_srv; continue; fi
    if ! wait_log "$T/srv$LT.log" "inventory received" 20 2; then fail "the new loader did not ask for the inventory"; stop_srv; continue; fi
    sleep 0.5
    if [ "$(grep -c '(startup) sent' "$T/srv$LT.log")" -ge 2 ]; then
        fail "the reconciliation was already finished before the signal: too small a database for this machine (raise ZONES)"
        stop_srv; continue
    fi
    t1=$(now_ms)
    kill -TERM "$new"
    n=0
    while kill -0 "$new" 2>/dev/null && [ $n -lt 1500 ]; do sleep 0.01; n=$((n + 1)); done
    el=$(( $(now_ms) - t1 ))
    if kill -0 "$new" 2>/dev/null; then
        fail "the loader was still running $el ms after SIGTERM"
    elif [ $el -le "$LIMIT_MS" ]; then
        pass "the loader ended $el ms after SIGTERM in the middle of the load (limit $LIMIT_MS ms)"
    else
        fail "the loader needed $el ms to end after SIGTERM (limit $LIMIT_MS ms)"
    fi
    sleep 0.5
    grep -q "did not stop; killing it" "$T/srv$LT.log" && fail "the manager had to kill the loader" || pass "the manager did not kill the loader"
    grep -q "stopping on a signal" "$T/srv$LT.log" && pass "the loader logged that it stops on a signal" || fail "no 'stopping on a signal' line"
    kill -0 "$SRV" 2>/dev/null && pass "karidns keeps running (the loader is restarted by the supervisor)" || fail "karidns died"
    stop_srv
done
echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_loader_sigterm_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_loader_sigterm_test: $FAILS of $((PASS + FAILS)) checks FAILED ==="
exit 1
