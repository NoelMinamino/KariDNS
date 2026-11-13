#!/bin/sh
# ==============================================================================
# run_reload_long_reader_test.sh
#
# 0.7: a reader that stays in its read section costs memory, never the time of a reload or of a database ingest batch.  The reader is the
# TEST ONLY `karictl rcu-hold <ms>` (a thread that holds an auxiliary read section; the server with the test hooks: ./karidns of
# `make coverage`, else ./karidns-evict of `make evict`).
#   1. 3000 small file zones: a full `karictl reload` (every zone file read again, a grace period was waited for every 1024 zones and at the end:
#      60 s each before) takes about as long during the hold as without it, and answers "OK reloaded"; a second reload during the hold waits
#      for the readers of normal operation (here 1 s: no program or forward zone), then answers "ERROR reload postponed" (the configuration is
#      double-buffered: its buffer may still be read by the reader) and the server does it by itself when the hold is over; `retired zone versions waiting` rises during the hold and goes back to 0 after it.
#   2. (root, the loader with SQLite3, sqlite3) 1500 database zones change during the hold: the ingest batch (a grace period was waited for
#      every 1024 zones) is applied while the reader holds, the zones are served with their new serial; the counts go back to 0 after it.
#      A second full reload during the hold is postponed; a row changed meanwhile is served once the tick applies it (the postponed reload asks
#      the loader as the command would have); the postponement makes at most three log lines.
#   3. A program zone whose plugin takes 1.5 s (program-timeout 3000): with such a query in flight, `reconfig` and `reload` back to back both
#      answer OK (the reload waits for the query, at most program-timeout + 0.5 s; it answered "postponed" after 0.1 s before).
# SKIP without perl or the test hooks; part 2 prints "SKIP: part 2: ..." without its prerequisites.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
for b in ./dag ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
has_hook() { [ -x "$1" ] && grep -q 'ERROR bad hold' "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_hook ./karidns; then KARIDNS=./karidns; elif has_hook ./karidns-evict; then KARIDNS=./karidns-evict; else KARIDNS=""; fi
fi
[ -n "$KARIDNS" ] && has_hook "$KARIDNS" || { echo "SKIP: no server with the test hooks (make evict, or the build of make coverage)"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/reload_long_reader.XXXXXX") || exit 1
chmod 755 "$T"
PIDS=""
cleanup() {
    for p in $PIDS; do kari_kill_tree "$p"; done
    rm -rf "$T" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
FAILED=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
now_ms() { perl -MTime::HiRes=time -e 'printf("%d\n", time * 1000)'; }
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0}"
SECRET="cmVsb2FkLWxvbmctcmVhZGVyLXRlc3Qta2V5LTAwMDA="
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$T/ctl.conf"
chmod 600 "$T/ctl.conf"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
ctl() { ./karictl -t 200 -s "$T/$1.sock" -f "$T/ctl.conf" "$2" ${3:-} 2>&1; }
status_num() { ctl "$1" status | sed -n "s/^$2: \([0-9][0-9]*\).*/\1/p" | head -1; }
serial_of() { ./dag @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump +time=2 +tries=2 2>/dev/null | awk '{print $3}' | head -1; }
# timed NAME CMD: "<ms> <first line of the reply>"
timed() { s=$1; shift; t0=$(now_ms); out=$(ctl "$s" "$@" | head -1); t1=$(now_ms); echo "$((t1 - t0)) $out"; }
sanitizer_clean() {
    if grep -q "ERROR: AddressSanitizer\|runtime error:\|ERROR: ThreadSanitizer" "$T/$1.log"; then
        fail "$1: a sanitizer report: $(grep -m1 'ERROR: AddressSanitizer\|runtime error:\|ERROR: ThreadSanitizer' "$T/$1.log")"
    else
        pass "$1: no sanitizer report"
    fi
}

echo "=== a long reader does not hold up a reload or an ingest batch ($(basename "$KARIDNS")) ==="

echo "== 1. 3000 file zones, full reloads with and without a reader that stays in its read section"
P1=$(kari_port 0 $((27000 + $$ % 4000)))
mkdir "$T/z"
perl -e '
    my $d = shift;
    for my $i (1 .. 3000) {
        open(my $f, ">", sprintf("%s/z%04d.test.zone", $d, $i)) or die;
        printf $f "\$TTL 300\n\@ IN SOA ns1.z%04d.test. h.z%04d.test. 1 3600 600 86400 60\n\@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.%d\n", $i, $i, $i % 250 + 1;
        close $f;
    }' "$T/z"
chmod -R a+rX "$T/z"
{
    echo "options { port $P1; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    echo "control-channel { socket \"$T/a.sock\"; algorithm hmac-sha256; secret \"$SECRET\"; };"
    perl -e 'my $d = shift; printf("zone \"z%04d.test\" { type primary; file \"%s/z%04d.test.zone\"; notify no; };\n", $_, $d, $_) for 1 .. 3000' "$T/z"
} > "$T/a.conf"
chmod 644 "$T/a.conf"
"$KARIDNS" -f "$T/a.conf" > "$T/a.log" 2>&1 &
PIDS="$PIDS $!"
kari_wait_answer ./dag "$P1" z3000.test 60 || { fail "the server did not start"; tail -20 "$T/a.log"; exit 1; }
set -- $(timed a reload)
BASE=$1
echo "   reload without a reader: $*"
case "$*" in *"OK reloaded"*) pass "a full reload of 3000 zones without a reader: OK in $BASE ms" ;; *) fail "the reload without a reader: $*" ;; esac
H=$(ctl a rcu-hold 60000)
[ "$H" = "OK" ] && pass "karictl rcu-hold 60000 (TEST ONLY)" || fail "rcu-hold: '$H'"
set -- $(timed a reload)
HELD=$1
echo "   reload during the hold: $*"
case "$*" in
    *"OK reloaded"*) [ "$HELD" -le $((BASE * 3 + 2000)) ] && pass "the full reload during the hold: OK in $HELD ms (without: $BASE ms)" || fail "the reload during the hold took $HELD ms (without: $BASE ms)" ;;
    *) fail "the reload during the hold: $*" ;;
esac
V=$(status_num a "retired zone versions waiting")
[ -n "$V" ] && [ "$V" -ge 1000 ] && pass "the replaced versions wait for the reader (retired zone versions waiting: $V)" || fail "retired zone versions waiting: '$V'"
set -- $(timed a reload)
echo "   a second reload during the hold: $*"
# (an explicit reload waits for the readers of normal operation first: here 1 s, as there is no program or forward zone; at most 5 s)
case "$*" in *"reload postponed"*) [ "$1" -ge 900 ] && [ "$1" -lt 5500 ] && pass "a second reload during the hold answers after the 1 s wait for normal readers ($1 ms): postponed, the configuration's buffer may still be read" || fail "the postponement took $1 ms" ;; *) fail "the second reload: $*" ;; esac
N0=$(grep -c "reloaded successfully" "$T/a.log")
ctl a status | grep -q "^retired zone snapshots waiting: [1-9]" && pass "status: a retired snapshot waits for the reader" || fail "status: $(ctl a status | grep 'retired zone')"
echo "   (waiting for the end of the hold)"
i=0; while [ "$(status_num a "retired zone versions waiting")" != "0" ] && [ $i -lt 900 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num a "retired zone versions waiting")" = "0" ] && pass "the hold over, the retired versions are freed (0)" || fail "retired zone versions waiting: $(status_num a "retired zone versions waiting")"
i=0; while [ "$(grep -c "reloaded successfully" "$T/a.log")" -le "$N0" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(grep -c "reloaded successfully" "$T/a.log")" -gt "$N0" ] && pass "the postponed reload is done by the server when the reader has left" || fail "the postponed reload was not done"
i=0; while [ "$(status_num a "retired zone snapshots waiting")" != "0" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num a "retired zone snapshots waiting")" = "0" ] && [ "$(status_num a "retired zone versions waiting")" = "0" ] && pass "everything is freed (snapshots and versions waiting: 0)" \
    || fail "after the hold: $(ctl a status | grep 'retired zone')"
[ "$(serial_of "$P1" z1234.test)" = "1" ] && pass "the zones are served" || fail "z1234.test: '$(serial_of "$P1" z1234.test)'"
sanitizer_clean a

echo "== 2. a database ingest batch of 1500 zones during the hold"
D_SKIP=""
[ "$(id -u)" = "0" ] || D_SKIP="needs root (the loader runs as another user)"
[ -z "$D_SKIP" ] && { [ -x ./karidns-dbloader ] && ./karidns-dbloader --drivers | grep -qx sqlite3 || D_SKIP="./karidns-dbloader with SQLite3 is not built"; }
[ -z "$D_SKIP" ] && { command -v sqlite3 >/dev/null 2>&1 || D_SKIP="the sqlite3 command line tool is not installed"; }
[ -z "$D_SKIP" ] && { id nobody >/dev/null 2>&1 || D_SKIP="no user nobody"; }
if [ -n "$D_SKIP" ]; then
    echo "  SKIP: part 2: $D_SKIP"
else
    P2=$(kari_port 1 $((P1 + 1)))
    mkdir "$T/db"
    chown nobody "$T/db"; chmod 777 "$T/db"
    sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    sqlite3 "$T/db/z.db" "
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1500)
INSERT INTO domains (name, type) SELECT printf('d%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.' || name || ' h.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 600, 0, 0 FROM domains;"
    chmod 666 "$T/db/z.db"*
    install -o root -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    cat > "$T/b.conf" <<EOF
options {
    user "nobody"; pid-file "none"; port $P2; bind-address { 127.0.0.1; }; rollback-window 0;   # (the replaced versions are retired, not kept as prev)
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 1; };
};
control-channel { socket "$T/b.sock"; algorithm hmac-sha256; secret "$SECRET"; };
EOF
    chmod 644 "$T/b.conf"
    "$KARIDNS" -f "$T/b.conf" > "$T/b.log" 2>&1 &
    PIDS="$PIDS $!"
    kari_wait_answer ./dag "$P2" d1500.test 60 || { fail "the database server did not start"; tail -20 "$T/b.log"; exit 1; }
    H=$(ctl b rcu-hold 60000)
    [ "$H" = "OK" ] && pass "karictl rcu-hold 60000" || fail "rcu-hold: '$H'"
    sqlite3 "$T/db/z.db" "UPDATE records SET content = REPLACE(content, ' 1 3600 600 ', ' 2 3600 600 ') WHERE type = 'SOA';"
    t0=$(now_ms)
    R=$(ctl b reload | head -1)
    echo "   reload: $R"
    i=0; while [ "$(serial_of "$P2" d0001.test)$(serial_of "$P2" d1500.test)" != "22" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
    t1=$(now_ms)
    [ "$(serial_of "$P2" d0001.test)$(serial_of "$P2" d1500.test)" = "22" ] && pass "the batch of 1500 zones is applied during the hold ($((t1 - t0)) ms)" \
        || fail "after the batch: d0001 '$(serial_of "$P2" d0001.test)', d1500 '$(serial_of "$P2" d1500.test)'"
    [ $((t1 - t0)) -lt 30000 ] && pass "well before the reader leaves (the hold is 60 s)" || fail "the batch took $((t1 - t0)) ms"
    V=$(status_num b "retired zone versions waiting")
    [ -n "$V" ] && [ "$V" -ge 1000 ] && pass "the replaced versions wait for the reader (retired zone versions waiting: $V)" || fail "retired zone versions waiting: '$V'"
    echo "   (waiting for the end of the hold)"
    # a second full reload during the hold is postponed; it is to ask the loader too: a row changed meanwhile is served once the tick applies it
    sqlite3 "$T/db/z.db" "UPDATE records SET content = REPLACE(content, ' 2 3600 600 ', ' 3 3600 600 ') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = 'd0007.test');"
    R=$(ctl b reload | head -1)
    case "$R" in *"reload postponed"*) pass "a second full reload during the hold is postponed" ;; *) fail "the second reload: '$R'" ;; esac
    i=0; while [ "$(status_num b "retired zone versions waiting")" != "0" ] && [ $i -lt 900 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(status_num b "retired zone versions waiting")" = "0" ] && pass "the hold over, the retired versions are freed (0)" || fail "retired zone versions waiting: $(status_num b "retired zone versions waiting")"
    i=0; while [ "$(serial_of "$P2" d0007.test)" != "3" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(serial_of "$P2" d0007.test)" = "3" ] && pass "the tick applied the postponed reload with its request to the loader: the changed row is served (serial 3)" \
        || fail "after the postponed reload: d0007.test serial '$(serial_of "$P2" d0007.test)' (the loader was not asked)"
    grep -q "The postponed reload was applied" "$T/b.log" && pass "the log says the postponed reload was applied" || fail "no 'The postponed reload was applied' line"
    N=$(grep -ci "postponed" "$T/b.log")
    [ "$N" -le 3 ] && pass "the postponed reload makes $N log line(s): once, a reminder at most once a minute, the outcome (it was one a second)" || fail "$N log lines about the postponed reload"
    sanitizer_clean b
fi

echo "== 3. a slow program zone query (the plugin takes 1.5 s, program-timeout 3000) in flight: reconfig and reload back to back answer OK"
P3=$(kari_port 2 $((P1 + 2)))
PROG_USER=""
[ "$(id -u)" = "0" ] && PROG_USER="program-user \"nobody\";"
cp "$ROOT_DIR/tests/plugins/dnstestscript.pl" "$T/plugin.pl" && chmod 755 "$T/plugin.pl"   # (executable, and readable by the program-user)
cat > "$T/c.conf" <<EOF
options { port $P3; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT allow-program-zones yes; };
control-channel { socket "$T/c.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "p.test" { type program; program "$T/plugin.pl"; program-args { "192.0.2.7"; }; $PROG_USER program-timeout 3000; };
EOF
chmod 644 "$T/c.conf"
"$KARIDNS" -f "$T/c.conf" > "$T/c.log" 2>&1 &
PIDS="$PIDS $!"
i=0; until ./dag @127.0.0.1 -p "$P3" normal.p.test A +short +nohexdump +time=2 +tries=1 2>/dev/null | grep -q 192.0.2.7 || [ $i -ge 75 ]; do sleep 0.2; i=$((i + 1)); done
[ $i -lt 75 ] && pass "the program zone answers" || fail "the program zone does not answer"
./dag @127.0.0.1 -p "$P3" slow.p.test A +short +nohexdump +time=6 +tries=1 > "$T/slow.out" 2>&1 &
SLOW=$!
sleep 0.3   # (the query reaches the plugin: it holds an async I/O read section for 1.5 s from then on)
set -- $(timed c reconfig)
case "$*" in *" OK"*) pass "reconfig with the slow query in flight: OK ($1 ms)" ;; *) fail "reconfig: $*" ;; esac
set -- $(timed c reload)
case "$*" in *"OK reloaded"*) pass "reload right after it: OK ($1 ms; it waited for the slow query, up to program-timeout + 0.5 s)" ;; *) fail "reload after reconfig: $*" ;; esac
wait "$SLOW"
grep -q 192.0.2.7 "$T/slow.out" && pass "the slow query is answered" || fail "the slow query: $(cat "$T/slow.out")"
sanitizer_clean c

if [ "$FAILED" -eq 0 ]; then
    echo "=== run_reload_long_reader_test: all checks passed ==="
    exit 0
fi
echo "=== run_reload_long_reader_test: $FAILED check(s) FAILED ==="
exit 1
