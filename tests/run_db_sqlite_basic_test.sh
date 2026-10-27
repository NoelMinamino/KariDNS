#!/bin/sh
# run_db_sqlite_basic_test.sh - zones served from a SQLite3 database through karidns-dbloader (beta design 1.5, 4.1-4.5,
# 5.2, 8.4; milestone B4b).
#
# karidns with options { database { } } (SQLite3, WAL, made with tests/db/zone2sql and the sqlite3 CLI), the loader run
# as "nobody":
#   - DB zones answer (SOA, A, MX, TXT, NXDOMAIN, AA) once the startup batch is done; the log says so and
#     `karictl dbstatus` shows the loader, the batch and the zones (summary and one zone);
#   - kill -9 of the loader: the zones keep answering, the restarted loader reconciles against the Backend's inventory
#     (B6a: it reads every zone, finds the digests equal and sends none): no errors, the answers stay, the totals do not move;
#   - D-PRIO: a zone {} with a file of the same name hides the DB zone (warning, dbstatus "shadowed", the file's data
#     answers); removing it from karidns.conf and `karictl reconfig` brings the DB zone back without a loader run;
#   - a bad row: the loader cannot read the zone, the Backend keeps the last good version (still answers, dbstatus says
#     "rejected" with the reason); when the row is fixed and the loader restarts the zone is applied again;
#   - karidns and karicheck refuse a configuration with more than 1024 views that take DB zones.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned).  SKIP otherwise, and when
# karidns, dag, karictl, karidns-dbloader (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karicheck ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbbasic.XXXXXX") || exit 1
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
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
DAG="./dag @127.0.0.1 -p $PORT"
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

# ---------------------------------------------------------------- fixtures
mkdir "$T/db" "$T/z"
cat > "$T/z/db1.test.zone" <<'EOF'
$ORIGIN db1.test.
$TTL 300
@ SOA ns1.db1.test. host.db1.test. 10 3600 600 86400 300
@ NS ns1
@ MX 10 mail
ns1 A 192.0.2.1
mail A 192.0.2.25
www A 192.0.2.10
txt TXT "hello db"
EOF
cat > "$T/z/db2.test.zone" <<'EOF'
$ORIGIN db2.test.
$TTL 300
@ SOA ns1.db2.test. host.db2.test. 20 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.2
www A 192.0.2.20
EOF
cat > "$T/z/shadow.test.zone" <<'EOF'
$ORIGIN shadow.test.
$TTL 300
@ SOA ns1.shadow.test. host.shadow.test. 30 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.3
www A 192.0.2.77
EOF
cat > "$T/shadow_file.zone" <<'EOF'
$ORIGIN shadow.test.
$TTL 300
@ SOA ns1.shadow.test. host.shadow.test. 99 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.3
www A 192.0.2.99
EOF
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n' > "$T/file.zone"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
for z in db1 db2 shadow; do
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/$z.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
done
NZ=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM domains")
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf FILE [extra zone statement]
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
zone "file.test" { type primary; file "$T/file.zone"; };
${2:-}
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
loader_pid() { pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1; }
ans() { $DAG "$@" +short +nohexdump 2>/dev/null; }
check_ans() {   # check_ans DESCRIPTION EXPECTED QNAME QTYPE
    got=$(ans "$3" "$4")
    [ "$got" = "$2" ] && pass "$1" || { fail "$1 (got '$got', want '$2')"; }
}
file_answers() { [ "$(ans www.file.test A)" = "192.0.2.80" ]; }
dbst() { $KCTL dbstatus "$@" 2>&1; }

# ================================================================ start
echo "== startup"
conf "$T/k.conf"
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
if wait_log "$T/srv.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$T/srv.log" | tail -20; fi
grep -q "initial load complete: $NZ zone(s) served from the database" "$T/srv.log" && pass "the log counts $NZ zones" || fail "the log does not count $NZ zones"
grep -q "\[DB\] batch 1 complete: $NZ zone(s) received ($NZ installed, 0 hidden by karidns.conf, 0 rejected)" "$T/srv.log" && pass "batch 1: $NZ installed, none rejected" || fail "the batch line is wrong"
grep -q "zone 'db1.test.' (view '[_a-z]*'): installed, serial 10" "$T/srv.log" && pass "log: db1.test installed with serial 10" || fail "no install line for db1.test"

echo "== answers"
check_ans "db1.test SOA" "ns1.db1.test. host.db1.test. 10 3600 600 86400 300" db1.test SOA
check_ans "www.db1.test A" "192.0.2.10" www.db1.test A
check_ans "db1.test MX" "10 mail.db1.test." db1.test MX
check_ans "txt.db1.test TXT" '"hello db"' txt.db1.test TXT
check_ans "www.db2.test A" "192.0.2.20" www.db2.test A
check_ans "www.shadow.test A (the DB version)" "192.0.2.77" www.shadow.test A
$DAG nope.db1.test A +nohexdump 2>/dev/null | grep -q "status: NXDOMAIN" && pass "NXDOMAIN below a DB zone" || fail "no NXDOMAIN below db1.test"
$DAG db1.test SOA +nohexdump 2>/dev/null | grep -q "flags:.* aa" && pass "DB zones answer authoritatively (aa)" || fail "no aa flag"
file_answers && pass "the file zone answers" || fail "the file zone does not answer"
$DAG db1.test AXFR +nohexdump 2>&1 | grep -q "192.0.2.10" && fail "AXFR of a DB zone was served with the default settings" || pass "AXFR of a DB zone is not allowed with the default settings"

echo "== karictl dbstatus"
OUT=$(dbst)
LP=$(loader_pid)
printf '%s\n' "$OUT" | grep -q "^loader: connected since .* (pid $LP, " && pass "dbstatus: loader connected, pid $LP" || { fail "dbstatus: loader line"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
printf '%s\n' "$OUT" | grep -q "^zones: $NZ in the registry ($NZ served, 0 shadowed by karidns.conf), 0 with a rejected version" && pass "dbstatus: $NZ zones, none shadowed or rejected" || fail "dbstatus: zones line"
printf '%s\n' "$OUT" | grep -q "^last batch: id 1, kind startup, finished .*: $NZ applied, 0 rejected, 0 shadowed, 0 deleted" && pass "dbstatus: last batch" || fail "dbstatus: last batch line"
printf '%s\n' "$OUT" | grep -q "^since start: $NZ applied, 0 rejected, 0 shadowed, 0 deleted, 0 failed in the loader" && pass "dbstatus: totals" || fail "dbstatus: totals line"
printf '%s\n' "$OUT" | grep -q "^last protocol error: none" && pass "dbstatus: no protocol error" || fail "dbstatus: protocol error line"
OUT=$(dbst db1.test)
printf '%s\n' "$OUT" | grep -q "^zone db1.test. view [_a-z]*: source id [0-9]*, serial 10, status applied$" && pass "dbstatus db1.test: serial 10, applied" || { fail "dbstatus db1.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
dbst nothere.test | grep -q "not in the database registry" && pass "dbstatus of an unknown zone" || fail "dbstatus of an unknown zone"

# ================================================================ kill -9 of the loader
echo "== loader killed"
P1=$LP
kill -9 "$P1"
[ "$(ans www.db1.test A)" = "192.0.2.10" ] && pass "DB zones keep answering while the loader is down" || fail "no answer without the loader"
dbst | grep -q "^loader: not connected since" && pass "dbstatus: loader down" || fail "dbstatus does not show the loader down"
if wait_log "$T/srv.log" "\[DB\] batch 1 complete" 20 2; then pass "the restarted loader delivered a batch"; else fail "no batch from the restarted loader"; fi
grep -q "loader asked for the inventory: sent $NZ zone(s)" "$T/srv.log" && pass "the Backend's inventory listed the $NZ zones" || { fail "inventory line"; grep "inventory" "$T/srv.log" | sed 's/^/         /'; }
P2=$(loader_pid)
[ -n "$P2" ] && [ "$P2" != "$P1" ] && pass "new loader pid $P2" || fail "no new loader process"
[ "$(grep -c 'rejected:' "$T/srv.log")" -eq 0 ] && pass "no zone was rejected at the restart" || fail "a zone was rejected on the second batch"
grep -q "batch 1 (startup) sent: $NZ zone(s) read, 0 sent, 0 failed in the loader, 0 deleted, $NZ unchanged" "$T/srv.log" && pass "the restarted loader read $NZ zones and sent none (same digests)" || { fail "the restarted loader sent zones again"; grep "batch 1 (startup)" "$T/srv.log" | sed 's/^/         /'; }
check_ans "www.db1.test A after the restart" "192.0.2.10" www.db1.test A
dbst | grep -q "^zones: $NZ in the registry ($NZ served" && pass "dbstatus: still $NZ zones" || fail "dbstatus zones line after the restart"
dbst | grep -q "^since start: $NZ applied, 0 rejected" && pass "dbstatus: still $NZ applied in total (nothing was sent again)" || fail "dbstatus totals after the restart"

# ================================================================ D-PRIO
echo "== a configured zone hides a DB zone"
conf "$T/k.conf" "zone \"shadow.test\" { type primary; file \"$T/shadow_file.zone\"; };"
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig: $OUT" || fail "reconfig: $OUT"
wait_log "$T/srv.log" "zone shadow.test. from the DB is shadowed by the zone in karidns.conf" 5 && pass "log: the DB zone is shadowed" || fail "no shadow warning"
check_ans "www.shadow.test A is the file zone's" "192.0.2.99" www.shadow.test A
dbst shadow.test | grep -q "serial 30, status shadowed" && pass "dbstatus shadow.test: shadowed" || { fail "dbstatus shadow.test"; dbst shadow.test | sed 's/^/         /'; }
dbst | grep -q "^zones: $NZ in the registry ($((NZ - 1)) served, 1 shadowed by karidns.conf)" && pass "dbstatus: 1 shadowed" || fail "dbstatus shadowed count"
check_ans "the other DB zones are not affected" "192.0.2.10" www.db1.test A
conf "$T/k.conf"
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig (zone removed): $OUT" || fail "reconfig: $OUT"
wait_log "$T/srv.log" "zone shadow.test. (view '[_a-z]*') is served from the DB again" 5 && pass "log: the DB zone is back" || fail "no 'served from the DB again' line"
check_ans "www.shadow.test A is the DB version again" "192.0.2.77" www.shadow.test A
dbst shadow.test | grep -q "serial 30, status applied" && pass "dbstatus shadow.test: applied again" || fail "dbstatus shadow.test after the zone is gone"

# ================================================================ a bad row
echo "== a zone the loader cannot read keeps its last good version"
sqlite3 "$T/db/z.db" "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES ((SELECT id FROM domains WHERE name = 'db2.test'), 'bad.db2.test', 'A', 'not.an.ip', 300, 0, 0)"
P2=$(loader_pid)
kill -9 "$P2"
if wait_log "$T/srv.log" "the loader could not read zone 'db2.test.'" 20; then pass "log: the loader reports db2.test"; else fail "no loader error for db2.test"; fi
wait_log "$T/srv.log" "\[DB\] batch 1 complete" 20 3 || true
check_ans "www.db2.test A still answers (the last good version)" "192.0.2.20" www.db2.test A
OUT=$(dbst db2.test)
printf '%s\n' "$OUT" | grep -q "status rejected (serving the last good version, serial 20), last error: " && pass "dbstatus db2.test: rejected, serving serial 20, with the reason" || { fail "dbstatus db2.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
dbst | grep -q "1 with a rejected version" && pass "dbstatus: 1 rejected" || fail "dbstatus does not count the rejected zone"
dbst | grep -q ", 1 failed in the loader" && pass "dbstatus: the loader failure is counted" || fail "dbstatus: failures"
sqlite3 "$T/db/z.db" "DELETE FROM records WHERE name = 'bad.db2.test'"
P3=$(loader_pid)
kill -9 "$P3"
i=0; while [ $i -lt 200 ]; do dbst db2.test | grep -q "status applied$" && break; sleep 0.1; i=$((i + 1)); done
dbst db2.test | grep -q "serial 20, status applied$" && pass "dbstatus db2.test: applied again after the fix" || { fail "db2.test is still not applied"; dbst db2.test | sed 's/^/         /'; }

# ================================================================ serial 0
# beta design 3.2: a zone with SOA serial 0 is loaded as it is, with a warning (once per version sent, not on every reload)
echo "== SOA serial 0: loaded with a warning, once"
printf '$ORIGIN zero.test.\n$TTL 300\n@ SOA ns1.zero.test. host.zero.test. 0 3600 600 86400 300\n@ NS ns1\nns1 A 192.0.2.4\nwww A 192.0.2.40\n' > "$T/z/zero.test.zone"
./tests/db/zone2sql --dialect sqlite3 "$T/z/zero.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
$KCTL reload > "$T/reload0.out" 2>&1
i=0; while [ $i -lt 100 ]; do [ "$(ans www.zero.test A)" = "192.0.2.40" ] && break; sleep 0.1; i=$((i + 1)); done
check_ans "www.zero.test A is served" "192.0.2.40" www.zero.test A
ans zero.test SOA | grep -q "^ns1.zero.test. host.zero.test. 0 3600 600 86400 300$" && pass "zero.test is served with SOA serial 0" || fail "zero.test SOA: $(ans zero.test SOA)"
dbst zero.test | grep -q "serial 0, status applied" && pass "dbstatus zero.test: serial 0, applied" || { fail "dbstatus zero.test"; dbst zero.test | sed 's/^/         /'; }
wait_log "$T/srv.log" "zone 'zero.test.' (domains.id [0-9]*): the SOA serial is 0" 5 && pass "log: the loader warns about serial 0" || { fail "no serial 0 warning"; tail -5 "$T/srv.log" | sed 's/^/         /'; }
$KCTL reload > "$T/reload1.out" 2>&1
P4=$(loader_pid)
kill -9 "$P4"                                   # a new loader compares every zone with the Backend's inventory: same digest, nothing sent
wait_log "$T/srv.log" "\[DB\] batch [0-9]* complete" 20 5 || true
sleep 1
[ "$(grep -c "zone 'zero.test.' (domains.id [0-9]*): the SOA serial is 0" "$T/srv.log")" -eq 1 ] && pass "the warning appears once: not on a reload of the unchanged zone, nor after a loader restart" || { fail "the serial 0 warning was logged $(grep -c "the SOA serial is 0" "$T/srv.log") times"; }
check_ans "www.zero.test A is still served" "192.0.2.40" www.zero.test A
sqlite3 "$T/db/z.db" "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'zero.test'); DELETE FROM domains WHERE name = 'zero.test'"      # the later sections count $NZ zones

# ================================================================ stop
echo "== SIGTERM"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then fail "karidns did not stop within 10 s"; else pass "karidns stopped"; fi
sleep 0.5
LEFT=$(pgrep -f "karidns.*$T" | tr '\n' ' ')
[ -z "$LEFT" ] && pass "no process of this server is left" || fail "left over: $LEFT"
SRV=""

# ================================================================ ingest-threads, and a configured zone that exists before the DB zone arrives
echo "== ingest-threads 4 (the zone shadow.test is in karidns.conf from the start)"
conf "$T/k4.conf" "zone \"shadow.test\" { type primary; file \"$T/shadow_file.zone\"; };"
sed 's/loader-path "\([^"]*\)";/loader-path "\1"; ingest-threads 4;/' "$T/k4.conf" > "$T/k4t.conf"
"$KARIDNS" -c "$T/k4t.conf" -f > "$T/srv4.log" 2>&1 &
SRV=$!
if wait_log "$T/srv4.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete with 4 builder threads"; else fail "no startup batch with ingest-threads 4"; sed 's/^/         /' "$T/srv4.log" | tail -10; fi
grep -q "4 builder thread(s) for the zones of the database" "$T/srv4.log" && pass "log: 4 builder threads" || fail "no builder thread line"
grep -q "batch 1 complete: $NZ zone(s) received ($((NZ - 1)) installed, 1 hidden by karidns.conf, 0 rejected)" "$T/srv4.log" && pass "batch 1: $((NZ - 1)) installed by the builders, 1 hidden by the configured zone" || { fail "the batch line is wrong with builders"; grep "batch 1 complete" "$T/srv4.log" | sed 's/^/         /'; }
grep -q "zone 'shadow.test.' (view '[_a-z]*'): loaded, but hidden by the zone in karidns.conf" "$T/srv4.log" && pass "log: the DB zone that arrives behind a configured zone is hidden" || fail "no 'hidden' line for shadow.test"
check_ans "www.db1.test A (builders)" "192.0.2.10" www.db1.test A
check_ans "www.shadow.test A is the configured zone's" "192.0.2.99" www.shadow.test A
dbst | grep -q "^zones: $NZ in the registry ($((NZ - 1)) served, 1 shadowed by karidns.conf)" && pass "dbstatus (builders): $NZ zones, 1 shadowed" || { fail "dbstatus with builders"; dbst | sed 's/^/         /'; }
dbst shadow.test | grep -q "serial 30, status shadowed" && pass "dbstatus shadow.test: shadowed at ingest time" || fail "dbstatus shadow.test at ingest time"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2>/dev/null && fail "karidns (4 builders) did not stop"
SRV=""
sleep 0.5

# ================================================================ view limit
echo "== more views than the loader link can list"
mkconf_views() {   # mkconf_views FILE NVIEWS NONE_FROM  (views from NONE_FROM on are "database none;")
    {
        printf 'options {\n  user "nobody";\n  database { driver sqlite3; database-file "%s/db/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; };\n};\n' "$T" "$T"
        awk -v n="$2" -v none="$3" 'BEGIN { for (i = 1; i <= n; i++) { printf "view \"v%d\" { match-clients { 192.0.2.%d; }; ", i, i % 250 + 1; if (i >= none) printf "database none; "; printf "};\n" } }'
    } > "$1"
}
mkconf_views "$T/v1025.conf" 1025 100000
OUT=$(./karicheck conf "$T/v1025.conf" 2>&1); RC=$?
[ $RC -ne 0 ] && printf '%s\n' "$OUT" | grep -q "1025 views take DB zones, at most 1024" && pass "karicheck conf refuses 1025 views with a database block" || { fail "karicheck conf accepted 1025 views (rc $RC)"; printf '%s\n' "$OUT" | head -5 | sed 's/^/         /'; }
"$KARIDNS" -c "$T/v1025.conf" -f > "$T/v1025.log" 2>&1 &
V=$!
i=0; while [ $i -lt 50 ] && kill -0 "$V" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$V" 2>/dev/null; then kill -KILL "$V"; fail "karidns started with 1025 views and a database block"; else
    grep -q "1025 views take DB zones, at most 1024" "$T/v1025.log" && pass "karidns refuses to start with 1025 views and a database block" || { fail "karidns stopped without the view limit message"; sed 's/^/         /' "$T/v1025.log" | head -5; }
fi
mkconf_views "$T/v1024.conf" 1025 1025
OUT=$(./karicheck conf "$T/v1024.conf" 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "views take DB zones" && fail "1024 views that take DB zones (and one \"database none\") were refused" || pass "1025 views of which one is \"database none;\" pass the view limit"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_sqlite_basic_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_sqlite_basic_test: $FAILS check(s) FAILED ($PASS passed) ==="
echo "--- server log (last 40 lines) ---"
tail -40 "$T/srv.log" 2>/dev/null
exit 1
