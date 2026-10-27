#!/bin/sh
# run_db_autoreload_test.sh - SQLite3 auto reload, `auto-reload yes;` (beta design 6, 8.4, 9; milestone B9; gate T-AUTORELOAD).
#
# karidns with options { database { auto-reload yes; } }, the loader run as "nobody".  The loader polls PRAGMA data_version
# on a persistent connection of its own; a change starts the coalesce window, and one batch of kind auto follows.  Checked:
#   S1  one view, the change log (db/karidns_ext.sqlite3.sql) present:
#       - auto-reload no (the default): an edit is not picked up and dbstatus says "auto reload: off";
#       - karictl reconfig with auto-reload yes: the edit made while it was off is picked up (nothing may be missed), dbstatus
#         shows the settings, the poll and the change seq per view;
#       - commit -> served within poll-interval + coalesce + build time (measured; the gate is a bound); an edit that keeps the
#         serial, a serial change, a new zone, a deleted zone (ZONE_DELETE) are applied without karictl;
#       - a burst of edits inside the coalesce window gives ONE batch; an explicit `karictl reload` next to it is answered and
#         the auto batch that follows finds nothing to send; dbstatus: kind auto, pending 0;
#       - a reconfig with other poll-interval / coalesce takes effect (dbstatus) and one with auto-reload no stops it;
#   S2  two views on the shared source with the DEFAULT settings (poll-interval 2, coalesce 1000): T-AUTORELOAD is measured
#       three times (bound 5 s), a change of karidns_domain_views moves a zone from view a to view b by itself, each view makes
#       its own auto batches;
#   S3  a database without karidns_changes: warned once, a serial bump is picked up (also a new and a deleted zone), an edit that
#       keeps the serial is not, `karictl reload <zone>` reads it;
#   S4  a change log pruned to 5 rows: a burst larger than the log gives "comparing every zone" and every zone is right; the
#       database file replaced by another file: every zone is compared again, zones that are not in the new file go away;
#       the file deleted: the zones keep answering, dbstatus names the error, the file comes back and everything recovers.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned; loopback aliases 127.0.0.2/3 are
# added and removed).  SKIP otherwise, and when karidns, dag, karictl, karidns-dbloader (SQLite3 driver), zone2sql or the
# sqlite3 CLI is missing.  KARIDNS=./karidns-tsan and LOADER=./karidns-dbloader-tsan run the sanitizer builds.
# PROFILE=1 prints the latencies only.  The latency bounds: BOUND_MS (S1, default 3500) and BOUND_DEFAULT_MS (S2, default 5000).
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
case $(date +%s%N 2>/dev/null) in ""|*N*) echo "SKIP: date has no %N (milliseconds are measured)"; exit 0 ;; esac

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_autoreload.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
ADDED=""
stop_server() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    # wait for the manager (it stops its children first; a sanitizer build is slow): a KILL too early orphans them
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    stop_server
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

for ip in 127.0.0.2 127.0.0.3; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else echo "SKIP: cannot add the loopback alias $ip"; exit 0; fi
done

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
BOUND_MS=${BOUND_MS:-3500}
BOUND_DEFAULT_MS=${BOUND_DEFAULT_MS:-5000}

# ---------------------------------------------------------------- helpers
mkdir "$T/db" "$T/z"
chown nobody "$T/db"; chmod 777 "$T/db"
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
EOF
}
newdb() {   # newdb FILE [ext|ext5|plain]: the PowerDNS schema (WAL), with the change log (retention 1000000 or 5) or without
    sqlite3 "$1" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    case "${2:-ext}" in
    ext) sqlite3 "$1" < db/karidns_ext.sqlite3.sql ;;
    ext5) sed 's/1000000/5/g' db/karidns_ext.sqlite3.sql | sqlite3 "$1" ;;
    esac
    chmod 666 "$1"
}
addz() {   # addz DB NAME SERIAL ADDRESS
    mkzone "$2" "$3" "$4"
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/$2.zone" 2>/dev/null | sqlite3 "$1"
    chmod 666 "$1"*
}
DB=""
sq() { sqlite3 "$DB" "$@"; chmod 666 "$DB"* 2>/dev/null; }          # the files stay readable and writable for the loader (user nobody)
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

# conf FILE DBFILE "DATABASE-OPTIONS" [views]
conf() {
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$2"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; $3 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
    if [ "${4:-}" = views ]; then
        cat >> "$1" <<'EOF'
view "a" { match-clients { 127.0.0.2; }; };
view "b" { match-clients { 127.0.0.3; }; };
EOF
    fi
}
LOG="$T/srv.log"
start_server() {   # start_server CONF
    : > "$LOG"
    "$KARIDNS" -c "$1" -f > "$LOG" 2>&1 &
    SRV=$!
    if wait_log "$LOG" "\[DB\] initial load complete" 30; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$LOG" | tail -20; fi
}
wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
msnow() { echo $(( $(date +%s%N) / 1000000 )); }
SRCB=""
qa() { ./dag @127.0.0.1 -p $PORT ${SRCB:+-b $SRCB} "$1" A +short +nohexdump 2>/dev/null; }
status_of() { ./dag @127.0.0.1 -p $PORT ${SRCB:+-b $SRCB} "$1" A +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
WAIT_MS=0
wait_ans() {   # wait_ans NAME EXPECTED MAXMS: poll dag every ~50 ms until it answers EXPECTED; WAIT_MS = how long it took; 0 = found
    t0=$(msnow); got=""
    while :; do
        got=$(qa "$1")
        now=$(msnow)
        [ "$got" = "$2" ] && { WAIT_MS=$((now - t0)); return 0; }
        [ $((now - t0)) -ge "$3" ] && { WAIT_MS=$((now - t0)); return 1; }
        sleep 0.05
    done
}
wait_status() {   # wait_status NAME STATUS MAXMS
    t0=$(msnow)
    while :; do
        got=$(status_of "$1"); now=$(msnow)
        [ "$got" = "$2" ] && { WAIT_MS=$((now - t0)); return 0; }
        [ $((now - t0)) -ge "$3" ] && { WAIT_MS=$((now - t0)); return 1; }
        sleep 0.05
    done
}
check_ans() {   # check_ans DESCRIPTION EXPECTED QNAME
    got=$(qa "$3")
    [ "$got" = "$2" ] && pass "$1" || fail "$1 (got '$got', want '$2')"
}
dbst() { $KCTL dbstatus "$@" 2>&1; }
n_auto() { grep -c "karidns-dbloader.* batch [0-9]* (auto) sent" "$LOG" 2>/dev/null; }
wait_dbst() {   # wait_dbst PATTERN SECONDS
    i=0
    while [ $i -lt $(($2 * 10)) ]; do
        dbst | grep -q -- "$1" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
latency() {   # latency DESCRIPTION NAME EXPECTED BOUND_MS: the edit has been made just before this call
    if wait_ans "$2" "$3" 15000; then
        [ "$WAIT_MS" -le "$4" ] && pass "$1: served after $WAIT_MS ms (bound $4 ms)" || fail "$1: served after $WAIT_MS ms, bound $4 ms"
    else
        fail "$1: not served within $WAIT_MS ms (got '$got', want '$3')"
    fi
    LAT_LAST=$WAIT_MS
}

# ================================================================ S1
echo "== S1: one view, change log; auto-reload no, then reconfig to yes"
DB="$T/db/s1.db"
newdb "$DB" ext
addz "$DB" z1.test 10 192.0.2.10
addz "$DB" z2.test 20 192.0.2.20
addz "$DB" z3.test 30 192.0.2.30
conf "$T/s1.conf" "$DB" ""
start_server "$T/s1.conf"
check_ans "www.z1.test A" "192.0.2.10" www.z1.test
dbst | grep -q "^auto reload: off$" && pass "dbstatus: auto reload: off" || { fail "dbstatus (auto-reload no)"; dbst | sed 's/^/         /' | head -8; }
sq "UPDATE records SET content = '192.0.2.11' WHERE name = 'www.z1.test'"
sleep 3.5
check_ans "auto-reload no: the edit is not picked up" "192.0.2.10" www.z1.test
[ "$(n_auto)" = "0" ] && pass "auto-reload no: no auto batch" || fail "auto-reload no: $(n_auto) auto batch(es)"

conf "$T/s1.conf" "$DB" "auto-reload yes; poll-interval 1; coalesce 500;"
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig with auto-reload yes: $OUT" || fail "reconfig: '$OUT'"
if wait_ans www.z1.test 192.0.2.11 8000; then pass "switched on: the edit made while it was off is picked up ($WAIT_MS ms)"; else fail "switched on: the edit of the off period was not picked up"; fi
wait_log "$LOG" "auto reload is on; checking for changes" 5 && pass "log: auto reload is on; checking for changes" || fail "no 'auto reload is on' line"
wait_log "$LOG" "karidns-dbloader.* batch [0-9]* (auto) sent: 1 zone(s) read, 1 sent, 0 failed in the loader, 0 deleted, 2 unchanged (view " 5 && pass "that batch is an auto batch: 1 read, 1 sent, 2 unchanged" || { fail "auto batch line"; grep "batch" "$LOG" | tail -3 | sed 's/^/         /'; }
wait_dbst "^auto reload: on (poll-interval 1 s, coalesce 500 ms), [1-9][0-9]* auto batch(es) since start$" 5 && pass "dbstatus: auto reload: on, with the settings and the auto batch count" || { fail "dbstatus (auto-reload yes)"; dbst | sed 's/^/         /' | head -8; }
wait_dbst "^  view [^:]*: last poll 20[0-9-]* [0-9:]* UTC, applied change seq [1-9][0-9]*, pending changes 0, last error: none$" 5 && pass "dbstatus: per view last poll, applied change seq, pending changes, last error" || { fail "dbstatus per-view line"; dbst | sed 's/^/         /' | head -8; }
dbst | grep -q "^last batch: id [0-9]*, kind auto, finished" && pass "dbstatus: the last batch is of kind auto" || { fail "dbstatus last batch kind"; dbst | sed 's/^/         /' | head -8; }

echo "== S1: latency, edits"
sq "UPDATE records SET content = '192.0.2.12' WHERE name = 'www.z1.test'"
latency "an edit that keeps the serial" www.z1.test 192.0.2.12 "$BOUND_MS"
sleep 0.3
sq "UPDATE records SET content = replace(content, ' 10 3600', ' 11 3600') WHERE type = 'SOA' AND name = 'z1.test'; UPDATE records SET content = '192.0.2.13' WHERE name = 'www.z1.test'"
latency "a serial change" www.z1.test 192.0.2.13 "$BOUND_MS"
sleep 0.3
$KCTL dbstatus z1.test | grep -q "serial 11, status applied" && pass "dbstatus z1.test: serial 11" || { fail "dbstatus z1.test"; $KCTL dbstatus z1.test | sed 's/^/         /'; }
addz "$DB" z4.test 40 192.0.2.40
latency "a new zone" www.z4.test 192.0.2.40 "$BOUND_MS"
sleep 0.3
sq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'z4.test'); DELETE FROM domains WHERE name = 'z4.test'"
if wait_status www.z4.test REFUSED 15000; then [ "$WAIT_MS" -le "$BOUND_MS" ] && pass "a deleted zone is gone after $WAIT_MS ms (bound $BOUND_MS ms)" || fail "a deleted zone is gone after $WAIT_MS ms, bound $BOUND_MS ms"; else fail "the deleted zone still answers"; fi
grep "karidns-dbloader.* (auto) sent" "$LOG" | grep -q "0 sent, 0 failed in the loader, 1 deleted" && pass "the delete went as ZONE_DELETE in an auto batch" || fail "no auto batch with 1 deleted"
check_ans "the other zones are untouched" "192.0.2.20" www.z2.test
sleep 1.5

echo "== S1: coalescing: a burst of edits is one batch"
B0=$(n_auto)
n=1; while [ $n -le 8 ]; do sq "UPDATE records SET content = '192.0.2.1$n' WHERE name = 'www.z2.test'"; sleep 0.03; n=$((n + 1)); done
if wait_ans www.z2.test 192.0.2.18 8000; then pass "the last value of the burst is served ($WAIT_MS ms after the burst)"; else fail "the burst: last value not served (got '$got')"; fi
sleep 2.5
B1=$(n_auto)
[ $((B1 - B0)) -eq 1 ] && pass "8 commits in 0.3 s gave one auto batch" || fail "8 commits gave $((B1 - B0)) auto batch(es)"

echo "== S1: an explicit karictl reload next to auto reload"
sleep 1
B0=$(n_auto)
sq "UPDATE records SET content = '192.0.2.77' WHERE name = 'www.z3.test'"
OUT=$($KCTL reload 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK reloaded; DB reload requested (request [0-9][0-9]*)$" && [ $RC -eq 0 ] && pass "karictl reload is answered at once: $OUT" || fail "reload: rc $RC '$OUT'"
if wait_ans www.z3.test 192.0.2.77 8000; then pass "the explicit reload applied the edit ($WAIT_MS ms)"; else fail "the explicit reload did not apply the edit"; fi
sleep 3
B1=$(n_auto)
[ "$B1" = "$B0" ] && pass "the auto batch that followed found nothing to send (no batch)" || fail "auto batches after the explicit reload: $((B1 - B0))"
dbst | grep -q "pending changes 0, last error: none$" && pass "dbstatus: pending changes 0" || { fail "dbstatus pending"; dbst | sed 's/^/         /' | head -8; }
OUT=$($KCTL reload z3.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone z3.test. (view [_a-z]*): unchanged, serial 30$" && [ $RC -eq 0 ] && pass "reload <zone> still works: $OUT" || fail "reload z3.test: rc $RC '$OUT'"

echo "== S1: reconfig changes the settings, then off"
conf "$T/s1.conf" "$DB" "auto-reload yes; poll-interval 3; coalesce 0;"
$KCTL reconfig > /dev/null 2>&1
wait_dbst "^auto reload: on (poll-interval 3 s, coalesce 0 ms)" 5 && pass "dbstatus shows poll-interval 3 s, coalesce 0 ms" || { fail "dbstatus after the reconfig"; dbst | sed 's/^/         /' | head -4; }
sleep 3.5                                       # let the new interval run once
sq "UPDATE records SET content = '192.0.2.31' WHERE name = 'www.z3.test'"
latency "poll-interval 3, coalesce 0" www.z3.test 192.0.2.31 4500
conf "$T/s1.conf" "$DB" "auto-reload no;"
$KCTL reconfig > /dev/null 2>&1
wait_log "$LOG" "auto reload is off" 5 && pass "log: auto reload is off" || fail "no 'auto reload is off' line"
wait_dbst "^auto reload: off$" 5 && pass "dbstatus: auto reload: off" || fail "dbstatus after switching off"
B0=$(n_auto)
sq "UPDATE records SET content = '192.0.2.32' WHERE name = 'www.z3.test'"
sleep 4
check_ans "switched off again: the edit is not picked up" "192.0.2.31" www.z3.test
[ "$(n_auto)" = "$B0" ] && pass "no auto batch after switching off" || fail "an auto batch after switching off"
kill -0 "$SRV" 2>/dev/null && pass "the server is up" || fail "the server died"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$LOG" && fail "sanitizer report in the server log" || true
stop_server

# ================================================================ S2
echo "== S2: two views, default settings (poll-interval 2, coalesce 1000): T-AUTORELOAD, the mapping"
DB="$T/db/s2.db"
newdb "$DB" ext
addz "$DB" all.test 10 192.0.2.10
addz "$DB" mv.test 20 192.0.2.20
sq "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'a' FROM domains WHERE name = 'mv.test'"
conf "$T/s2.conf" "$DB" "auto-reload yes;" views
start_server "$T/s2.conf"
SRCB=127.0.0.2; check_ans "all.test in view a" "192.0.2.10" www.all.test
check_ans "mv.test in view a" "192.0.2.20" www.mv.test
SRCB=127.0.0.3; check_ans "all.test in view b" "192.0.2.10" www.all.test
[ "$(status_of www.mv.test)" = REFUSED ] && pass "mv.test is not in view b" || fail "mv.test in view b: '$(status_of www.mv.test)'"
wait_dbst "^auto reload: on (poll-interval 2 s, coalesce 1000 ms)" 5 && pass "dbstatus: the default settings (2 s, 1000 ms)" || { fail "dbstatus defaults"; dbst | sed 's/^/         /' | head -6; }
wait_dbst "^  view a: last poll " 6 && wait_dbst "^  view b: last poll " 6 && pass "dbstatus lists both views" || { fail "dbstatus views"; dbst | sed 's/^/         /' | head -8; }
sleep 2.5
SUM=0; MAX=0; k=1
while [ $k -le 3 ]; do
    SRCB=127.0.0.2
    sq "UPDATE records SET content = '192.0.2.1$k' WHERE name = 'www.all.test'"
    latency "T-AUTORELOAD with the defaults, sample $k" www.all.test 192.0.2.1$k "$BOUND_DEFAULT_MS"
    SUM=$((SUM + LAT_LAST)); [ "$LAT_LAST" -gt "$MAX" ] && MAX=$LAT_LAST
    sleep 1.3
    k=$((k + 1))
done
echo "  T-AUTORELOAD (defaults): mean $((SUM / 3)) ms, max $MAX ms"
SRCB=127.0.0.3; check_ans "view b has the last value too" "192.0.2.13" www.all.test
grep "karidns-dbloader.* (auto) sent" "$LOG" | grep -q "(view 'a')" && grep "karidns-dbloader.* (auto) sent" "$LOG" | grep -q "(view 'b')" && pass "each view makes its own auto batches" || fail "auto batches of views a and b"
echo "== S2: a change of karidns_domain_views moves the zone"
sq "UPDATE karidns_domain_views SET view_name = 'b' WHERE domain_id = (SELECT id FROM domains WHERE name = 'mv.test')"
SRCB=127.0.0.3
latency "mv.test appears in view b" www.mv.test 192.0.2.20 "$BOUND_DEFAULT_MS"
SRCB=127.0.0.2
if wait_status www.mv.test REFUSED 8000; then pass "mv.test is gone from view a"; else fail "mv.test is still in view a"; fi
SRCB=""
dbst mv.test | grep -q "view b:" && ! dbst mv.test | grep -q "view a:" && pass "dbstatus mv.test: only view b" || { fail "dbstatus mv.test"; dbst mv.test | sed 's/^/         /'; }
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$LOG" && fail "sanitizer report in the server log" || true
stop_server

# ================================================================ S3
echo "== S3: a database without karidns_changes"
DB="$T/db/s3.db"
newdb "$DB" plain
addz "$DB" p1.test 10 192.0.2.10
addz "$DB" p2.test 20 192.0.2.20
conf "$T/s3.conf" "$DB" "auto-reload yes; poll-interval 1; coalesce 200;"
start_server "$T/s3.conf"
wait_log "$LOG" "auto-reload is on but the database has no karidns_changes table" 5 && pass "warned at the start: no karidns_changes" || fail "no warning about the missing change log"
sq "UPDATE records SET content = replace(content, ' 10 3600', ' 11 3600') WHERE type = 'SOA' AND name = 'p1.test'; UPDATE records SET content = '192.0.2.11' WHERE name = 'www.p1.test'"
latency "a serial bump without a change log" www.p1.test 192.0.2.11 "$BOUND_MS"
sleep 0.3
addz "$DB" p3.test 30 192.0.2.30
latency "a new zone without a change log" www.p3.test 192.0.2.30 "$BOUND_MS"
sleep 0.3
sq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'p3.test'); DELETE FROM domains WHERE name = 'p3.test'"
if wait_status www.p3.test REFUSED 10000; then pass "a deleted zone is gone after $WAIT_MS ms"; else fail "the deleted zone still answers"; fi
sq "UPDATE records SET content = '192.0.2.99' WHERE name = 'www.p2.test'"
sleep 3.5
check_ans "an edit that keeps the serial is not picked up (no change log)" "192.0.2.20" www.p2.test
OUT=$($KCTL reload p2.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK zone p2.test. (view [_a-z]*): applied, serial 20$" && pass "reload <zone> reads it: $OUT" || fail "reload p2.test: '$OUT'"
check_ans "now it is served" "192.0.2.99" www.p2.test
[ "$(grep -c "auto-reload is on but the database has no karidns_changes table" "$LOG")" = "1" ] && pass "the warning was logged once" || fail "the warning was logged $(grep -c "auto-reload is on but the database has no karidns_changes table" "$LOG") times"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$LOG" && fail "sanitizer report in the server log" || true
stop_server

# ================================================================ S4
echo "== S4: a pruned change log, a replaced file, a deleted file"
DB="$T/db/s4.db"
newdb "$DB" ext5
n=1; while [ $n -le 7 ]; do addz "$DB" "g$n.test" $((n * 10)) "192.0.2.$n"; n=$((n + 1)); done
conf "$T/s4.conf" "$DB" "auto-reload yes; poll-interval 1; coalesce 200;"
start_server "$T/s4.conf"
sleep 1.5
sq "UPDATE records SET content = '192.0.2.200' WHERE type = 'A' AND name LIKE 'www.%'"        # 7 records, 14 log rows at most; the log keeps 5
n=1; ok=0
while [ $n -le 7 ]; do wait_ans "www.g$n.test" 192.0.2.200 8000 && ok=$((ok + 1)); n=$((n + 1)); done
[ "$ok" = "7" ] && pass "a burst larger than the log: all 7 zones are right" || fail "a burst larger than the log: $ok of 7 zones are right"
wait_log "$LOG" "rows of the change log after seq [0-9]* were pruned; comparing every zone" 5 && pass "log: the gap in the change log is noticed, every zone is compared" || fail "no 'were pruned' line"

echo "== S4: the database file is replaced by another file"
newdb "$T/db/new1.db" ext5
addz "$T/db/new1.db" g1.test 10 192.0.2.101
addz "$T/db/new1.db" g8.test 80 192.0.2.108
rm -f "$DB-wal" "$DB-shm"                         # a stale WAL must not meet the new file
mv "$T/db/new1.db" "$DB"
chmod 666 "$DB"
latency "the replaced file: g1.test is the new file's" www.g1.test 192.0.2.101 "$BOUND_MS"
if wait_ans www.g8.test 192.0.2.108 8000; then pass "g8.test of the new file is served"; else fail "g8.test of the new file is not served"; fi
if wait_status www.g5.test REFUSED 8000; then pass "g5.test (not in the new file) is gone"; else fail "g5.test still answers"; fi
grep -q "the database file was replaced or removed; reopening and comparing every zone" "$LOG" && pass "log: the replaced file is noticed" || fail "no 'file was replaced' line"

echo "== S4: the database file is deleted, then comes back"
newdb "$T/db/new2.db" ext5
addz "$T/db/new2.db" g1.test 10 192.0.2.201
addz "$T/db/new2.db" g8.test 80 192.0.2.208
rm -f "$DB" "$DB-wal" "$DB-shm"
wait_dbst "last error: [a-z]" 8 && pass "dbstatus names an error while the file is missing" || { fail "dbstatus shows no error for a missing file"; dbst | sed 's/^/         /' | head -8; }
check_ans "the zones keep answering from memory" "192.0.2.101" www.g1.test
mv "$T/db/new2.db" "$DB"; chmod 666 "$DB"
latency "the file is back: g1.test is the new content" www.g1.test 192.0.2.201 6000
if wait_dbst "last error: none" 8; then pass "dbstatus: the error is gone"; else fail "dbstatus still shows an error"; dbst | sed 's/^/         /' | head -8; fi
kill -0 "$SRV" 2>/dev/null && pass "the server is up" || fail "the server died"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$LOG" && fail "sanitizer report in the server log" || true
stop_server
SRV=""
sleep 0.5
LEFT=$(pgrep -f "karidns.*$T" | tr '\n' ' ')
[ -z "$LEFT" ] && pass "no process of this server is left" || fail "left over: $LEFT"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_autoreload_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_autoreload_test: $FAILS check(s) FAILED ($PASS passed) ==="
echo "--- server log (last 60 lines) ---"
tail -60 "$LOG" 2>/dev/null
exit 1
