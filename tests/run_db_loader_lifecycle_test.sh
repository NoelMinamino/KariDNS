#!/bin/sh
# run_db_loader_lifecycle_test.sh - the database loader under the supervisor (beta design 1.2, 1.3, 1.5; milestone B4a).
#
# karidns with options { database { } } (SQLite3, WAL, made with tests/db/zone2sql and the sqlite3 CLI), the loader run
# as "nobody":
#   - the loader runs as nobody, started as "karidns-dbloader -s 3", fd 3 is its stream socket; the Backend has the
#     stream with the limited rights (read, write, event);
#   - the log shows HELLO / CONFIG / INVENTORY and the zones received and installed (B4b: they answer);
#   - kill -9 of the loader: restarted with a new pid after about 1 s, then about 2 s; file zones answer throughout;
#   - pkill -HUP karidns does not kill the loader; a configuration reload sends a new CONFIG (new generation);
#   - a loader that breaks the protocol (fake loader): the Backend logs the protocol error once, closes the stream,
#     survives and answers; the supervisor restarts the loader;
#   - SIGTERM stops every process including the loader.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned).  SKIP otherwise, and
# when karidns, dag, karidns-dbloader (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
for b in ./karidns ./dag ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbloader_lc.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    # wait for the manager (it stops its children first; a sanitizer build is slow): a KILL too early orphans them
    i=0; while [ -n "$SRV" ] && [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$((20000 + $$ % 20000))
DAG="./dag @127.0.0.1 -p $PORT"

# ---------------------------------------------------------------- fixtures
mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
for z in tests/zones/example.com.zone tests/zones/nsec.zone; do
    ./tests/db/zone2sql --dialect sqlite3 "$z" 2>/dev/null | sqlite3 "$T/db/z.db"
done
NZ=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM domains")
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n' > "$T/file.zone"

conf() {   # conf FILE LOADERPATH
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$2"; };
};
control-channel { enabled yes; socket "$T/ctl.sock"; secret "dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"; };
zone "file.test" { type primary; file "$T/file.zone"; };
EOF
}

wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
loader_pid() { pgrep -P "$SRV" -f '(karidns-dbloader|fake_dbloader) -s 3' | head -1; }
file_answers() { [ "$($DAG file.test SOA +short +nohexdump 2>/dev/null | head -1)" = "ns.file.test. host.file.test. 1 2 3 4 5" ]; }

# ================================================================ part 1: the real loader
echo "== real loader"
conf "$T/k.conf" "$T/karidns-dbloader"
./karidns -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
if wait_log "$T/srv.log" "\[DB\] batch 1 complete" 15; then pass "startup: the loader sent its startup batch"; else fail "no startup batch"; sed 's/^/         /' "$T/srv.log" | tail -20; fi

LP=$(loader_pid)
if [ -n "$LP" ]; then
    U=$(ps -o user= -p "$LP" | tr -d ' ')
    A=$(ps -o command= -p "$LP")
    [ "$U" = "nobody" ] && pass "the loader runs as nobody" || fail "the loader runs as '$U'"
    [ "$A" = "karidns-dbloader -s 3" ] && pass "started as 'karidns-dbloader -s 3'" || fail "command line is '$A'"
    if procstat -f "$LP" 2>/dev/null | awk '$3 == "3" && $4 == "s" { f = 1 } END { exit !f }'; then pass "fd 3 of the loader is a socket"; else fail "fd 3 of the loader is not a socket"; procstat -f "$LP" | head; fi
    NFD=$(procstat -f "$LP" 2>/dev/null | awk '$3 ~ /^[0-9]+$/ && $3 >= 4 && $0 !~ /run.log/' | wc -l | tr -d ' ')
    [ "$NFD" -eq 0 ] && pass "the loader has no descriptor above 3 except the syslog socket (closefrom)" || fail "the loader holds $NFD descriptor(s) above 3"
else
    fail "no loader process"
fi

grep -q "\[DB\] loader connected: pid $LP" "$T/srv.log" && pass "log: HELLO" || fail "log: no HELLO line"
grep -q "\[DB\] sent CONFIG generation 1" "$T/srv.log" && pass "log: CONFIG sent" || fail "log: no CONFIG line"
grep -q "\[DB\] loader asked for the inventory" "$T/srv.log" && pass "log: INVENTORY" || fail "log: no inventory line"
grep -q "batch 1 complete: $NZ zone(s) received ($NZ installed, 0 hidden by karidns.conf, 0 rejected)" "$T/srv.log" && pass "$NZ zones received and installed" || fail "the batch line does not say $NZ installed"
wait_log "$T/srv.log" "Backend result for batch 1: $NZ applied, 0 unchanged, 0 rejected" 5 && pass "the loader got the BATCH_RESULT" || fail "no BATCH_RESULT at the loader"
file_answers && pass "the file zone answers" || fail "the file zone does not answer"

# design 1.3: the Backend limited the rights of the control socket (pair C, a SEQPACKET socket "UDQ") to recvmsg +
# kqueue.  procstat -fC shows "rd,ev,re" for it ("re" is CAP_RECV; the stream socket shows "rd,wr,ev,re,sd").
# There is no reliable procstat flag for capability mode itself, so that is not checked here.
CTRL_CAPS=0
for p in $(pgrep -P "$SRV" -f 'karidns'); do
    procstat -fC "$p" 2>/dev/null | awk '$4 == "s" && $0 ~ / UDQ / && $0 ~ / rd,ev,re / { f = 1 } END { exit !f }' && CTRL_CAPS=1
done
[ "$CTRL_CAPS" -eq 1 ] && pass "the Backend's control socket is limited to rd,ev,re" || fail "no Backend control socket with the limited rights rd,ev,re"

# kill -9: restart after about 1 s, then about 2 s; file zones answer throughout
echo "== loader restarts"
P1=$LP
T0=$(date +%s)
kill -9 "$P1"
file_answers && pass "the file zone answers while the loader is down" || fail "the file zone does not answer after kill -9"
i=0; P2=""
while [ $i -lt 80 ]; do P2=$(loader_pid); [ -n "$P2" ] && [ "$P2" != "$P1" ] && break; P2=""; sleep 0.1; i=$((i + 1)); done
T1=$(date +%s)
if [ -n "$P2" ] && [ $((T1 - T0)) -le 3 ]; then pass "restarted as pid $P2 after $((T1 - T0)) s (about 1 s)"; else fail "no restart within 3 s (pid '$P2', $((T1 - T0)) s)"; fi
wait_log "$T/srv.log" "\[DB\] batch 1 complete" 15 2 && pass "the new loader sent a startup batch on the new stream" || fail "no batch from the restarted loader"
T0=$(date +%s)
kill -9 "$P2"
i=0; P3=""
while [ $i -lt 100 ]; do P3=$(loader_pid); [ -n "$P3" ] && [ "$P3" != "$P2" ] && break; P3=""; sleep 0.1; i=$((i + 1)); done
T1=$(date +%s)
if [ -n "$P3" ] && [ $((T1 - T0)) -ge 1 ] && [ $((T1 - T0)) -le 4 ]; then pass "second restart as pid $P3 after $((T1 - T0)) s (about 2 s)"; else fail "second restart: pid '$P3' after $((T1 - T0)) s"; fi
grep -q "Restarting the database loader in 2 s" "$T/srv.log" && pass "log: the backoff doubled to 2 s" || fail "log: no 2 s backoff line"
grep -q "\[DB\] loader disconnected" "$T/srv.log" && pass "log: the Backend noticed the end of the stream" || fail "log: no 'loader disconnected'"
file_answers && pass "the file zone answers after the restarts" || fail "the file zone does not answer"

# SIGHUP to every process: the loader survives; the reload sends a new CONFIG
echo "== SIGHUP and configuration reload"
wait_log "$T/srv.log" "\[DB\] batch 1 complete" 15 3 || true
LP=$(loader_pid)
pkill -HUP -f "karidns -c $T/k.conf"
sleep 1
if [ -n "$LP" ] && kill -0 "$LP" 2>/dev/null && [ "$(loader_pid)" = "$LP" ]; then pass "pkill -HUP karidns did not kill the loader"; else fail "the loader died on SIGHUP"; fi
wait_log "$T/srv.log" "\[DB\] sent CONFIG generation 2" 10 && pass "the reload sent a new CONFIG (generation 2)" || fail "no CONFIG with a new generation after the reload"
file_answers && pass "the file zone answers after the reload" || fail "the file zone does not answer"

# ---------------------------------------------------------------- stop
echo "== SIGTERM"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then fail "karidns did not stop within 10 s"; else pass "karidns stopped"; fi
sleep 0.5
LEFT=$(pgrep -f "karidns.*$T" | tr '\n' ' ')
[ -z "$LEFT" ] && pass "no process of this server is left (loader included)" || fail "left over: $LEFT"
SRV=""

# ================================================================ part 2: a loader that breaks the protocol
echo "== fake loaders"
cc -O1 -o "$T/fake_dbloader" tests/db/fake_dbloader.c 2>"$T/cc.log" || { echo "SKIP part 2: no C compiler"; cat "$T/cc.log"; }
if [ -x "$T/fake_dbloader" ]; then
    chown 0:0 "$T/fake_dbloader"; chmod 755 "$T/fake_dbloader"
    for mode in bad-magic bad-order bad-view silent; do
        # the fake takes its mode as an argument: a wrapper script (root-owned) execs it with the fixed -s 3
        printf '#!/bin/sh\nexec "%s/fake_dbloader" -s 3 %s\n' "$T" "$mode" > "$T/fake_$mode"
        chown 0:0 "$T/fake_$mode"; chmod 755 "$T/fake_$mode"
        conf "$T/f_$mode.conf" "$T/fake_$mode"
        ./karidns -c "$T/f_$mode.conf" -f > "$T/f_$mode.log" 2>&1 &
        SRV=$!
        if [ "$mode" = silent ]; then
            wait_log "$T/f_$mode.log" "\[DB\] sent CONFIG generation 1" 10 && pass "$mode: HELLO accepted, CONFIG sent"
            sleep 1
            ! grep -q "protocol error" "$T/f_$mode.log" && pass "$mode: no protocol error from a quiet loader" || fail "$mode: protocol error logged"
        else
            if wait_log "$T/f_$mode.log" "protocol error from the loader" 10; then pass "$mode: the Backend logged the protocol error"; else fail "$mode: no protocol error line"; sed 's/^/         /' "$T/f_$mode.log" | tail -8; fi
            sleep 0.5
            N=$(grep -c "protocol error from the loader" "$T/f_$mode.log")
            [ "$N" -eq 1 ] && pass "$mode: logged once" || fail "$mode: logged $N times"
            grep "protocol error from the loader" "$T/f_$mode.log" | head -1 | grep -q "closing the stream" && pass "$mode: it says the stream is closed" || fail "$mode: no 'closing the stream'"
            wait_log "$T/f_$mode.log" "Database loader .* started .*restart" 10 && pass "$mode: the supervisor restarted the loader" || fail "$mode: no restart"
        fi
        file_answers && pass "$mode: the Backend survived and answers" || fail "$mode: the file zone does not answer"
        kill -TERM "$SRV"; i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
        kill -0 "$SRV" 2>/dev/null && fail "$mode: karidns did not stop"
        SRV=""
        sleep 0.3
    done
fi

# ================================================================ part 3: a loader nobody may start
echo "== refusing to start"
chmod 775 "$T/karidns-dbloader"
conf "$T/bad.conf" "$T/karidns-dbloader"
OUT=$(./karidns -c "$T/bad.conf" -f 2>&1); RC=$?
if [ $RC -ne 0 ] && printf '%s\n' "$OUT" | grep -q "writable by group or others"; then pass "a group-writable loader-path stops the start"; else fail "start with a writable loader (rc $RC)"; fi
chmod 755 "$T/karidns-dbloader"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_loader_lifecycle_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_loader_lifecycle_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
