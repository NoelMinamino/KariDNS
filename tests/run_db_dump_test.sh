#!/bin/sh
# run_db_dump_test.sh - karidns-dbloader --dump against the file zones (beta design, milestone B3 gate).
#
# For every zone file of tests/zones/ that the reader takes: zone file -> tests/db/zone2sql --dialect sqlite3 ->
# the sqlite3 CLI -> a WAL database -> karidns-dbloader --dump.  The dump must be byte for byte the KDB1 stream that
# tests/db/zone2kdb writes from the same files (zone2sql rows -> reader -> pdns_zone_encode_kdb, nothing in between).
# Also checked: two dumps of one database are identical, the per-zone path (--zone) gives the same bytes for every
# zone as the bulk path, --loader-threads does not change the output, cryptokeys without PRESIGNED fail the zone
# (and PRESIGNED=1 lets it through), the exit statuses and error messages, and that every example of --help runs.
#
# SKIP (exit 0) when the sqlite3 CLI is missing or the loader was built without the SQLite3 driver.
# A missing binary is built with make (as $SUDO_USER when run by root).

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "SKIP: the sqlite3 command line tool is not installed"
    exit 0
fi

build() {
    for t in "$@"; do
        if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
            su -m "$SUDO_USER" -c "make $t" > "/tmp/run_db_dump_build.$$.log" 2>&1
        else
            make "$t" > "/tmp/run_db_dump_build.$$.log" 2>&1
        fi
        if [ $? -ne 0 ]; then
            echo "[FAIL] make $t failed:"
            tail -20 "/tmp/run_db_dump_build.$$.log"
            rm -f "/tmp/run_db_dump_build.$$.log"
            exit 1
        fi
        rm -f "/tmp/run_db_dump_build.$$.log"
    done
}

[ -x ./karidns-dbloader ] || build karidns-dbloader
[ -x tests/db/zone2sql ] || build zone2sql
[ -x tests/db/zone2kdb ] || build zone2kdb

LOADER=$ROOT/karidns-dbloader
Z2S=$ROOT/tests/db/zone2sql
Z2K=$ROOT/tests/db/zone2kdb
SCHEMA=$ROOT/tests/db/pdns_schema.sqlite3.sql

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbdump.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT INT TERM

# the loader must have the SQLite3 driver
"$LOADER" --dump "$T/probe.kdb" --driver sqlite3 --database-file "$T/none.db" > "$T/probe.out" 2>&1
if grep -q "is not available in this build" "$T/probe.out"; then
    echo "SKIP: karidns-dbloader was built without the SQLite3 driver ($(cat "$T/probe.out"))"
    exit 0
fi

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
check() {   # check "description" command...
    d=$1
    shift
    if "$@" > "$T/check.out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/         /' "$T/check.out" | head -10; fi
}

# ---------------------------------------------------------------- reference stream and database
echo "== reference stream from the zone files"
"$Z2K" --ref "$T/ref.kdb" --list "$T/list.txt" tests/zones/*.zone > "$T/ref.log" 2>&1
RC=$?
grep -c "^  \[ OK \]" "$T/ref.log" | sed 's/^/  zones taken: /'
grep "^SKIP" "$T/ref.log" | sed 's/^/  /'
if [ $RC -ne 0 ]; then
    bad "zone2kdb --ref"
    cat "$T/ref.log"
    exit 1
fi
NZ=$(wc -l < "$T/list.txt" | tr -d ' ')
if [ "$NZ" -ge 15 ]; then ok "$NZ zone files in the reference stream"; else bad "only $NZ zone files in the reference stream"; fi

import() {     # import DBFILE: the zones of list.txt, in order, plus example.test
    rm -f "$1" "$1-wal" "$1-shm"
    sqlite3 "$1" < "$SCHEMA" > /dev/null || return 1
    while read -r f; do
        "$Z2S" --dialect sqlite3 "$f" | sqlite3 "$1" || return 1
    done < "$T/list.txt"
}

echo "== import into SQLite (WAL)"
check "import into z.db" import "$T/z.db"
MODE=$(sqlite3 "$T/z.db" "PRAGMA journal_mode")
[ "$MODE" = "wal" ] && ok "the database is in WAL mode" || bad "journal_mode is $MODE"
N_DOM=$(sqlite3 "$T/z.db" "SELECT count(*) FROM domains")
[ "$N_DOM" = "$NZ" ] && ok "$N_DOM domains imported" || bad "$N_DOM domains imported, $NZ expected"

# ---------------------------------------------------------------- the gate
echo "== dump equals the encoding of the file zones"
"$LOADER" --dump "$T/d1.kdb" --driver sqlite3 --database-file "$T/z.db" 2> "$T/d1.err"
RC=$?
[ $RC -eq 0 ] && ok "dump exits 0" || { bad "dump exit status $RC"; cat "$T/d1.err"; }
check "dump == reference stream (byte for byte)" "$Z2K" --compare "$T/ref.kdb" "$T/d1.kdb"
check "dump == reference stream (cmp)" cmp "$T/ref.kdb" "$T/d1.kdb"
"$LOADER" --dump "$T/d2.kdb" --driver sqlite3 --database-file "$T/z.db" 2> /dev/null
check "two dumps of one database are identical" cmp "$T/d1.kdb" "$T/d2.kdb"
"$LOADER" --dump "$T/d3.kdb" --driver sqlite3 --database-file "$T/z.db" --loader-threads 4 2> /dev/null
check "--loader-threads 4 gives the same bytes" cmp "$T/d1.kdb" "$T/d3.kdb"
"$LOADER" --dump - --driver sqlite3 --database-file "$T/z.db" 2> /dev/null > "$T/d4.kdb"
check "--dump - (standard output) gives the same bytes" cmp "$T/d1.kdb" "$T/d4.kdb"

echo "== per-zone path (--zone) gives the bulk path's bytes for every zone"
sqlite3 "$T/z.db" "SELECT name FROM domains ORDER BY id" > "$T/names.txt"
NPER=0
NBAD=0
while read -r zn; do
    "$LOADER" --dump "$T/one.kdb" --driver sqlite3 --database-file "$T/z.db" --zone "$zn" 2> "$T/one.err"
    r=$?
    "$Z2K" --extract "$T/d1.kdb" "$zn" > "$T/zb.bulk"
    "$Z2K" --extract "$T/one.kdb" "$zn" > "$T/zb.one"
    NPER=$((NPER + 1))
    if [ $r -ne 0 ] || ! cmp -s "$T/zb.bulk" "$T/zb.one" || [ ! -s "$T/zb.one" ]; then
        NBAD=$((NBAD + 1))
        echo "         zone $zn: exit $r"
    fi
done < "$T/names.txt"
[ "$NBAD" -eq 0 ] && ok "$NPER zones: --zone == bulk" || bad "$NBAD of $NPER zones differ between --zone and the bulk path"

# ---------------------------------------------------------------- cryptokeys, PRESIGNED, view index
echo "== cryptokeys without PRESIGNED"
ZK=$(head -1 "$T/names.txt")
sqlite3 "$T/z.db" "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ((SELECT id FROM domains WHERE name = '$ZK'), 257, 1, 'x')"
"$LOADER" --dump "$T/k1.kdb" --driver sqlite3 --database-file "$T/z.db" 2> "$T/k1.err"
RC=$?
[ $RC -eq 1 ] && ok "exit status 1 when a zone fails" || bad "exit status $RC, 1 expected"
grep -q "cryptokeys but no PRESIGNED" "$T/k1.err" && ok "the reason names cryptokeys and PRESIGNED" || { bad "reason missing"; cat "$T/k1.err"; }
if cmp -s "$T/ref.kdb" "$T/k1.kdb"; then bad "the dump did not change"; else ok "the zone is not in the stream any more"; fi
"$Z2K" --extract "$T/k1.kdb" "$ZK" > "$T/zb.k1"
[ ! -s "$T/zb.k1" ] && ok "no ZONE_BEGIN for $ZK" || bad "$ZK is still in the stream"
sqlite3 "$T/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = '$ZK'), 'PRESIGNED', '1')"
PM_ID=$(sqlite3 "$T/z.db" "SELECT max(id) FROM domainmetadata")     # the row just added; zone2sql's own PRESIGNED / NSEC3PARAM rows of signed zones stay
"$LOADER" --dump "$T/k2.kdb" --driver sqlite3 --database-file "$T/z.db" 2> "$T/k2.err"
RC=$?
[ $RC -eq 0 ] && ok "with PRESIGNED=1 the zone loads (exit 0)" || { bad "exit $RC with PRESIGNED=1"; cat "$T/k2.err"; }
"$Z2K" --extract "$T/k2.kdb" "$ZK" > "$T/zb.k2"
[ -s "$T/zb.k2" ] && ok "$ZK is in the stream again" || bad "$ZK is missing"
sqlite3 "$T/z.db" "DELETE FROM cryptokeys; DELETE FROM domainmetadata WHERE id = $PM_ID"
"$LOADER" --dump "$T/v1.kdb" --driver sqlite3 --database-file "$T/z.db" --view-index 3 --default-ttl 120 2> /dev/null
RC=$?
[ $RC -eq 0 ] && ok "--view-index 3 --default-ttl 120" || bad "exit $RC with --view-index"
if cmp -s "$T/d1.kdb" "$T/v1.kdb"; then bad "--view-index changed nothing"; else ok "--view-index changes the ZONE_BEGIN view tag"; fi

# ---------------------------------------------------------------- error handling
echo "== exit statuses"
expect() {   # expect STATUS "description" command...
    want=$1
    d=$2
    shift 2
    "$@" > "$T/e.out" 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then ok "$d (exit $got)"; else bad "$d: exit $got, $want expected"; sed 's/^/         /' "$T/e.out" | head -5; fi
}
expect 2 "no arguments" "$LOADER"
expect 2 "--dump without --driver" "$LOADER" --dump "$T/x.kdb"
expect 2 "unknown driver" "$LOADER" --dump "$T/x.kdb" --driver mysql --database-file "$T/z.db"
expect 2 "postgresql is not built yet" "$LOADER" --dump "$T/x.kdb" --driver postgresql --database-file "$T/z.db"
expect 2 "sqlite3 without --database-file" "$LOADER" --dump "$T/x.kdb" --driver sqlite3
expect 2 "-s with a descriptor that is not open" "$LOADER" -s 9 9>&-
expect 2 "-s with a file instead of a stream socket" "$LOADER" -s 9 9<"$T/z.db"
expect 2 "-s with a number that is not a descriptor number" "$LOADER" -s x
expect 2 "bad --view-index" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/z.db" --view-index 70000
expect 2 "bad --default-ttl" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/z.db" --default-ttl 0
expect 2 "bad --loader-threads" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/z.db" --loader-threads 17
expect 2 "stray argument" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/z.db" extra
expect 3 "missing database file" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/missing.db"
[ ! -e "$T/missing.db" ] && ok "the database file was not created" || bad "a database file was created"
expect 3 "a name starting with file: is refused" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "file:$T/z.db"
grep -q "file:" "$T/e.out" && ok "the message names file:" || bad "no message about file:"
expect 3 "unknown zone" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/z.db" --zone nothere.test
[ ! -e "$T/x.kdb" ] && ok "no output file after an error" || bad "x.kdb left behind"
expect 3 "output in a directory that does not exist" "$LOADER" --dump "$T/no/such/dir/x.kdb" --driver sqlite3 --database-file "$T/z.db"
# not in WAL mode
sqlite3 "$T/nowal.db" "CREATE TABLE t (a)" > /dev/null
expect 3 "a database that is not in WAL mode" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/nowal.db"
grep -q "WAL" "$T/e.out" && ok "the message says WAL" || bad "no message about WAL"
# schema errors
sqlite3 "$T/noschema.db" "PRAGMA journal_mode=WAL; CREATE TABLE domains (id INTEGER PRIMARY KEY, name TEXT)" > /dev/null
expect 3 "a database without the PowerDNS tables" "$LOADER" --dump "$T/x.kdb" --driver sqlite3 --database-file "$T/noschema.db"
grep -q "domains has no column" "$T/e.out" && ok "the message names the missing column" || bad "no column message"
# a path with % is taken literally; a UTF-8 path works
sqlite3 "$T/z.db" "PRAGMA wal_checkpoint(TRUNCATE)" > /dev/null
cp "$T/z.db" "$T/pct%65.db"
expect 0 "a database file name with %65 is taken literally" "$LOADER" --dump "$T/pct.kdb" --driver sqlite3 --database-file "$T/pct%65.db"
cp "$T/z.db" "$T/zone-日本語.db"
expect 0 "a UTF-8 database file name" "$LOADER" --dump "$T/utf8.kdb" --driver sqlite3 --database-file "$T/zone-日本語.db"
check "the dumps of both copies equal the original's" sh -c "cmp '$T/pct.kdb' '$T/d1.kdb' && cmp '$T/utf8.kdb' '$T/d1.kdb'"

# ---------------------------------------------------------------- --help
echo "== --help examples"
"$LOADER" --help > "$T/help.txt"
[ $? -eq 0 ] && ok "--help exits 0" || bad "--help exit status"
"$LOADER" --version | grep -q "^karidns-dbloader " && ok "--version" || bad "--version"
mkdir -p "$T/bin" "$T/ex"
ln -s "$LOADER" "$T/bin/karidns-dbloader"
cp "$T/z.db" "$T/ex/zones.sqlite3"
cp "$T/z.db" "$T/ex/view1.sqlite3"
sqlite3 "$T/ex/zones.sqlite3" "INSERT INTO domains (name, type) VALUES ('example.test', 'NATIVE'); INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 'example.test', 'SOA', 'ns1.example.test hostmaster.example.test 1 7200 3600 1209600 300', 3600, 0, 0, 1)" > /dev/null
mkdir -p "$T/var/db/karidns"
cp "$T/ex/zones.sqlite3" "$T/var/db/karidns/zones.sqlite3"
sed -n '/^examples:/,$p' "$T/help.txt" | grep '^  karidns-dbloader ' > "$T/examples.txt"
NEX=$(wc -l < "$T/examples.txt" | tr -d ' ')
[ "$NEX" -ge 3 ] && ok "$NEX examples in --help" || bad "$NEX examples in --help"
n=0
while read -r line; do
    n=$((n + 1))
    cmd=$(printf '%s\n' "$line" | sed -e "s#/tmp/#$T/ex/#g" -e "s#/var/db/karidns/#$T/var/db/karidns/#")
    ( cd "$T/ex" && PATH="$T/bin:$PATH" sh -c "$cmd" > "$T/ex$n.out" 2> "$T/ex$n.err" )
    r=$?
    if [ $r -eq 0 ]; then ok "example $n runs: $(printf '%s' "$line" | cut -c1-90)"; else bad "example $n exit $r: $line"; cat "$T/ex$n.err"; fi
done < "$T/examples.txt"
[ -s "$T/ex/zones.kdb" ] && ok "example 1 wrote the stream" || bad "example 1 wrote no stream"
grep -q "K   D   B   1" "$T/ex2.out" && ok "example 2 wrote KDB1 to standard output" || bad "example 2 output has no KDB1 magic"
[ -s "$T/ex/view1.kdb" ] && ok "example 3 wrote the stream" || bad "example 3 wrote no stream"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
