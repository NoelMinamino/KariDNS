#!/bin/sh
# run_db_views_test.sh - per-view database sources and karidns_domain_views (beta design 3.7, 7.1, D6; milestone B6b).
#
# karidns with options { database { } } and four views:  a and b use the global source (g.db, with the karidns_* tables of
# db/karidns_ext.sqlite3.sql), c has its own file (c.db), n says "database none;".  Checked:
#   - a domain without a mapping row is served by every view that uses the global source (D6); a domain with rows by the
#     views they name (names compare case-insensitively) and by no other; a row naming a view that does not use this
#     source is logged once per batch and ignored (the zone it maps goes nowhere);
#   - a view with its own database-file takes all zones of that file; the mapping table inside it is ignored;
#     "database none;" takes nothing;
#   - the answers differ per view (queries from 127.0.0.2.. select the view);
#   - an edit of karidns_domain_views reaches the loader through the change log: `karictl reload` moves a zone between
#     views (ZONE_DELETE in the old one), and so does `karictl reload <zone>` without a view, which asks every view that takes
#     database zones and answers with one line (applied in view b, not in the database of view a ...);
#   - `karictl reload <zone> <view>` for a view with "database none;" is refused by the Backend ("zone not found"), and for a view whose
#     database file the loader cannot open the loader answers the request with ZONE_FAILED and the reason (failed: sqlite3: cannot open ...);
#   - a database without karidns_domain_views behaves like D6 (every zone in every view of the global source);
#   - karidns-dbloader --dump --map-view gives the same bytes with --loader-threads 1 and 4.
#
# Needs root (the server starts as root and drops to nobody; loopback aliases 127.0.0.2-5 are added and removed).  SKIP
# otherwise, and when karidns, dag, karictl, karidns-dbloader (SQLite3 driver) or the sqlite3 CLI is missing.
# THREADS=n sets loader-threads of the server (default 3).
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user, loopback aliases)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karidns-dbloader; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbviews.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
ADDED=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else echo "SKIP: cannot add the loopback alias $ip"; exit 0; fi
done

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
THREADS=${THREADS:-3}

# ---------------------------------------------------------------- fixtures
mkdir "$T/db"
newdb() {   # newdb FILE [ext]
    sqlite3 "$1" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    sqlite3 "$1" "PRAGMA journal_mode=WAL" > /dev/null
    [ "${2:-}" = ext ] && sqlite3 "$1" < db/karidns_ext.sqlite3.sql
}
mkzone() {   # mkzone DB NAME SERIAL ADDRESS: SOA, NS, www A
    sqlite3 "$1" "INSERT INTO domains (name, type) VALUES ('$2', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.$2 host.$2 $3 3600 600 86400 300', 300, 0, 0 FROM domains WHERE name = '$2';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.$2', 300, 0, 0 FROM domains WHERE name = '$2';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.$2', 'A', '$4', 300, 0, 0 FROM domains WHERE name = '$2';"
}
mapz() {   # mapz DB ZONE VIEW
    sqlite3 "$1" "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, '$3' FROM domains WHERE name = '$2'"
}
G="$T/db/g.db"; C="$T/db/c.db"
newdb "$G" ext; newdb "$C" ext
mkzone "$G" all.test 10 192.0.2.10
mkzone "$G" aonly.test 20 192.0.2.20
mkzone "$G" bonly.test 30 192.0.2.30
mkzone "$G" ab.test 40 192.0.2.40
mkzone "$G" other.test 50 192.0.2.50
mkzone "$G" moved.test 60 192.0.2.60
mapz "$G" aonly.test a
mapz "$G" bonly.test b
mapz "$G" ab.test a
mapz "$G" ab.test B                  # compared case-insensitively
mapz "$G" other.test nosuchview      # a view this server does not have: logged, ignored, the zone is served by no view
mapz "$G" moved.test a
mkzone "$C" c1.test 70 192.0.2.70
mkzone "$C" c2.test 80 192.0.2.80
mapz "$C" c2.test a                  # the mapping of a view's own file is ignored
chown -R nobody "$T/db"; chmod 600 "$T/db"/*.db*
sq() { sqlite3 "$G" "$@"; }
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

conf() {   # conf FILE GLOBAL-DB
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$2"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; loader-threads $THREADS; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
view "a" { match-clients { 127.0.0.2; }; };
view "b" { match-clients { 127.0.0.3; }; };
view "c" { match-clients { 127.0.0.4; }; database-file "$C"; };
view "n" { match-clients { 127.0.0.5; }; database none; };
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
q() {   # q VIEW-ADDRESS NAME: the A answer of www
    ./dag @127.0.0.1 -p $PORT -b "$1" "$2" A +short +nohexdump 2>/dev/null
}
status_of() {   # status_of VIEW-ADDRESS NAME
    ./dag @127.0.0.1 -p $PORT -b "$1" "$2" A +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}
dbst() { $KCTL dbstatus "$@" 2>&1; }
views_of() {   # views_of ZONE: the views that have the zone, sorted, space separated
    dbst "$1" | sed -n "s/^zone [^ ]* view \([^:]*\): .*/\1/p" | sort | tr '\n' ' ' | sed 's/ $//'
}
expect_views() {   # expect_views ZONE "VIEWS"
    got=$(views_of "$1")
    [ "$got" = "$2" ] && pass "$1 is in the views: ${2:-(none)}" || fail "$1 is in the views '$got', wanted '${2}'"
}
NRES=0
reload_all() {   # reload_all DESCRIPTION: karictl reload, wait for the batch result
    NRES=$((NRES + 1))
    OUT=$($KCTL reload 2>&1)
    printf '%s\n' "$OUT" | grep -q "^OK reloaded; DB reload requested" || fail "$1: '$OUT'"
    wait_log "$T/srv.log" "Backend result for batch" 15 $NRES && pass "$1: the batch is done" || fail "$1: no batch result"
}

# ================================================================ start
echo "== startup: threads $THREADS"
conf "$T/k.conf" "$G"
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
if wait_log "$T/srv.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$T/srv.log" | tail -20; fi
NRES=1
wait_log "$T/srv.log" "Backend result for batch 1:" 10 || fail "no result for the startup batch"

echo "== which view gets which zone"
expect_views all.test "a b"
expect_views aonly.test "a"
expect_views bonly.test "b"
expect_views ab.test "a b"
expect_views other.test ""
expect_views moved.test "a"
expect_views c1.test "c"
expect_views c2.test "c"
n=$(grep -c "karidns_domain_views: .* name view(s) that do not use this database" "$T/srv.log")
[ "$n" = 1 ] && pass "the mapping row of an unknown view is logged once for the batch" || { fail "unknown view logged $n times"; grep "karidns_domain_views" "$T/srv.log" | sed 's/^/         /'; }
n=$(grep -c "karidns_domain_views: 1 zone(s) are mapped only to views that do not use this database as their source and are served by no view: other.test" "$T/srv.log")
[ "$n" = 1 ] && pass "the zone served by no view is named in a warning, once for the batch" || { fail "orphan zone warning seen $n times"; grep "karidns_domain_views" "$T/srv.log" | sed 's/^/         /'; }
grep "karidns_domain_views:" "$T/srv.log" | grep -q "nosuchview" && pass "the log names the view" || fail "the log does not name nosuchview"

echo "== the answers differ per view"
[ "$(q 127.0.0.2 www.aonly.test)" = "192.0.2.20" ] && pass "view a answers www.aonly.test" || fail "view a: www.aonly.test"
[ "$(status_of 127.0.0.3 www.aonly.test)" = "REFUSED" ] && pass "view b does not have aonly.test" || fail "view b: www.aonly.test is '$(status_of 127.0.0.3 www.aonly.test)'"
[ "$(q 127.0.0.3 www.bonly.test)" = "192.0.2.30" ] && pass "view b answers www.bonly.test" || fail "view b: www.bonly.test"
[ "$(q 127.0.0.2 www.all.test)" = "192.0.2.10" ] && [ "$(q 127.0.0.3 www.all.test)" = "192.0.2.10" ] && pass "both views answer www.all.test (no mapping row)" || fail "www.all.test"
[ "$(status_of 127.0.0.2 www.other.test)" = "REFUSED" ] && [ "$(status_of 127.0.0.3 www.other.test)" = "REFUSED" ] && pass "other.test (mapped to an unknown view) is served by no view" || fail "other.test is served"
[ "$(q 127.0.0.4 www.c1.test)" = "192.0.2.70" ] && [ "$(q 127.0.0.4 www.c2.test)" = "192.0.2.80" ] && pass "view c answers both zones of its own file" || fail "view c"
[ "$(status_of 127.0.0.2 www.c1.test)" = "REFUSED" ] && pass "view a does not have the zones of c.db" || fail "view a has c1.test"
[ "$(status_of 127.0.0.5 www.all.test)" = "REFUSED" ] && [ "$(status_of 127.0.0.5 www.c1.test)" = "REFUSED" ] && pass "view n (database none) has no database zone" || fail "view n answers"

# ================================================================ mapping edits through the change log
echo "== a mapping edit moves a zone between views (reload, all)"
sq "UPDATE karidns_domain_views SET view_name = 'b' WHERE domain_id = (SELECT id FROM domains WHERE name = 'moved.test')"
reload_all "moved.test a -> b"
expect_views moved.test "b"
[ "$(q 127.0.0.3 www.moved.test)" = "192.0.2.60" ] && [ "$(status_of 127.0.0.2 www.moved.test)" = "REFUSED" ] && pass "moved.test answers in b, not in a" || fail "moved.test answers"

echo "== removing the rows sends the zone to every view (D6)"
sq "DELETE FROM karidns_domain_views WHERE domain_id = (SELECT id FROM domains WHERE name = 'bonly.test')"
reload_all "bonly.test rows removed"
expect_views bonly.test "a b"
sq "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'a' FROM domains WHERE name = 'other.test'"
reload_all "other.test also mapped to a"
expect_views other.test "a"

# ================================================================ reload <zone> without a view
echo "== reload <zone> with several views and no view named"
mkzone "$G" newz.test 5 192.0.2.5
mapz "$G" newz.test b
OUT=$($KCTL reload newz.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone newz.test.: view a: not in the database; view b: applied, serial 5; view c: not in the database$" && [ $RC -eq 0 ] && pass "one line for all views: $OUT" || fail "reload newz.test: rc $RC '$OUT'"
expect_views newz.test "b"
sq "UPDATE karidns_domain_views SET view_name = 'a' WHERE domain_id = (SELECT id FROM domains WHERE name = 'newz.test')"
OUT=$($KCTL reload newz.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone newz.test.: view a: applied, serial 5; view b: deleted (it is no longer in the database); view c: not in the database$" && [ $RC -eq 0 ] && pass "the zone moved by the mapping: $OUT" || fail "reload newz.test (moved): rc $RC '$OUT'"
expect_views newz.test "a"
OUT=$($KCTL reload ab.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone ab.test.: view a: unchanged, serial 40; view b: unchanged, serial 40; view c: not in the database$" && [ $RC -eq 0 ] && pass "a zone in two views: $OUT" || fail "reload ab.test: rc $RC '$OUT'"
OUT=$($KCTL reload c1.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone c1.test.: view a: not in the database; view b: not in the database; view c: unchanged, serial 70$" && [ $RC -eq 0 ] && pass "a zone of the view's own file: $OUT" || fail "reload c1.test: rc $RC '$OUT'"
OUT=$($KCTL reload nothere.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone not found (it is not in the database of any view that takes database zones)$" && [ $RC -eq 3 ] && pass "a zone no view has: $OUT" || fail "reload nothere.test: rc $RC '$OUT'"
OUT=$($KCTL reload ab.test b 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone ab.test. (view b): unchanged, serial 40$" && [ $RC -eq 0 ] && pass "a named view keeps the single-view answer: $OUT" || fail "reload ab.test b: rc $RC '$OUT'"
sq "UPDATE records SET content = '192.0.2.41' WHERE name = 'www.ab.test'"
OUT=$($KCTL reload ab.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone ab.test.: view a: applied, serial 40; view b: applied, serial 40; view c: not in the database$" && [ $RC -eq 0 ] && pass "an edit reaches both views: $OUT" || fail "edit of ab.test: rc $RC '$OUT'"
[ "$(q 127.0.0.2 www.ab.test)" = "192.0.2.41" ] && [ "$(q 127.0.0.3 www.ab.test)" = "192.0.2.41" ] && pass "both views answer the new address" || fail "ab.test answers"
OUT=$($KCTL zonestatus ab.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone exists in multiple views" && [ $RC -eq 3 ] && pass "zonestatus still asks for a view: $OUT" || fail "zonestatus ab.test: rc $RC '$OUT'"

# ================================================================ reload <zone> that the loader cannot answer from the database (ZONE_FAILED)
echo "== reload <zone> of a view that takes no zones from the database, and of a database the loader cannot read"
OUT=$($KCTL reload ab.test n 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone not found (view 'n' takes no zones from the database)$" && [ $RC -eq 3 ] && pass "a view with database none: $OUT" || fail "reload ab.test n: rc $RC '$OUT'"
chmod 000 "$C" "$C"-wal "$C"-shm 2>/dev/null
OUT=$($KCTL reload c1.test c 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^ERROR zone c1.test. (view c): failed: sqlite3: cannot open the database file" && [ $RC -eq 3 ] && pass "a database the loader cannot read: the request fails with the reason: $OUT" || fail "reload c1.test c (unreadable): rc $RC '$OUT'"
chmod 600 "$C" "$C"-wal "$C"-shm 2>/dev/null
OUT=$($KCTL reload c1.test c 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone c1.test. (view c): unchanged, serial 70$" && [ $RC -eq 0 ] && pass "the same request after the file is readable again: $OUT" || fail "reload c1.test c (readable): rc $RC '$OUT'"
[ "$(q 127.0.0.4 www.c1.test)" = "192.0.2.70" ] && pass "view c kept serving its zone" || fail "view c answer after the failed request"

echo "== stop, then a database without karidns_domain_views"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2>/dev/null && fail "karidns did not stop" || pass "karidns stopped"
SRV=""
G2="$T/db/g2.db"
newdb "$G2"
mkzone "$G2" one.test 1 192.0.2.1
mkzone "$G2" two.test 2 192.0.2.2
chown nobody "$G2"*; chmod 600 "$G2"*
conf "$T/k2.conf" "$G2"
"$KARIDNS" -c "$T/k2.conf" -f > "$T/srv2.log" 2>&1 &
SRV=$!
if wait_log "$T/srv2.log" "\[DB\] initial load complete" 20; then pass "the second server's startup batch is complete"; else fail "no 'initial load complete' line (second server)"; fi
wait_log "$T/srv2.log" "Backend result for batch 1:" 10 || fail "no result for the startup batch (second server)"
expect_views one.test "a b"
expect_views two.test "a b"
[ "$(q 127.0.0.2 www.one.test)" = "192.0.2.1" ] && [ "$(q 127.0.0.3 www.two.test)" = "192.0.2.2" ] && pass "without the mapping table every view answers every zone" || fail "D6 answers"
mkzone "$G2" three.test 3 192.0.2.3
OUT=$($KCTL reload three.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone three.test.: view a: applied, serial 3; view b: applied, serial 3; view c: not in the database$" && [ $RC -eq 0 ] && pass "reload <zone>: $OUT" || fail "reload three.test: rc $RC '$OUT'"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
SRV=""

# ================================================================ dump: --map-view and --loader-threads
echo "== karidns-dbloader --dump --map-view, loader-threads 1 and 4"
for v in a b; do
    for n in 1 4; do
        ./karidns-dbloader --dump "$T/d_${v}_$n.kdb" --driver sqlite3 --database-file "$G" --map-view $v --loader-threads $n 2> "$T/d_${v}_$n.err"
        [ $? -le 1 ] || fail "dump $v with $n thread(s) failed: $(cat "$T/d_${v}_$n.err")"
    done
    cmp -s "$T/d_${v}_1.kdb" "$T/d_${v}_4.kdb" && pass "view $v: the dump is byte for byte the same with 1 and 4 threads" || fail "view $v: dumps differ"
done
grep -qa "aonly" "$T/d_a_1.kdb" && ! grep -qa "aonly" "$T/d_b_1.kdb" && pass "the dump for view a has aonly.test, the one for b has not" || fail "map-view dump contents"
grep -qa "newz" "$T/d_a_1.kdb" && ! grep -qa "newz" "$T/d_b_1.kdb" && pass "newz.test (mapped to a) is in a's dump only" || fail "newz in the dumps"
! cmp -s "$T/d_a_1.kdb" "$T/d_b_1.kdb" && pass "the two views get different streams" || fail "identical streams"
./karidns-dbloader --dump "$T/d_all.kdb" --driver sqlite3 --database-file "$G" --loader-threads 4 2>/dev/null
grep -qa "other" "$T/d_all.kdb" && pass "without --map-view every zone is dumped" || fail "plain dump lacks other.test"
./karidns-dbloader --dump - --driver sqlite3 --database-file "$G" --map-view b --zone aonly.test > /dev/null 2> "$T/z.err"
[ $? -eq 3 ] && grep -q "not mapped to this view" "$T/z.err" && pass "--zone of a zone mapped elsewhere: not found for the view" || fail "--zone with --map-view: $(cat "$T/z.err")"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_views_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_views_test: $FAILS check(s) FAILED ($PASS passed) ==="
echo "--- server log (last 60 lines) ---"
tail -60 "$T/srv.log" 2>/dev/null
exit 1
