#!/bin/sh
# run_karidns_zone_test.sh - karidns-zone (tools/karidns_zone.c, docs/karidns-zone.md): the command line of the ZoneImporter and the ZoneExporter
# on a SQLite3 database (0.6.0 milestone M3; the PostgreSQL variant is run_karidns_zone_pg_test.sh).
#
#  1. usage: every wrong command line exits 2 (also with --json, which then gives one document with a usage.* code), -h and --version exit 0, and
#     every example of --help runs.
#  2. import: a new zone (NATIVE, MASTER), replace, merge, the types filter, a dry run (lists the RRsets, writes nothing), the serial rules
#     (grow, increment, keep), --strict, a zone with errors, the read-back verification (a merge that puts a CNAME beside an A record is refused
#     and rolled back), standard input ($INCLUDE refused), tinydns data files (--all, one zone), the format by file name, bad files.
#  3. the configuration: -c karidns.conf gives the database, a view (shared source -> karidns_domain_views row, own source, database none, an
#     undefined view), the check-* options and the size limits of the view (a zone the server would refuse is not written), the file zones of the
#     configuration (the D-PRIO warning), and the errors (no database, no such file, a syntax error, a driver that is not there).
#  4. export: standard output, a file, an existing file (refused; --force replaces it), --all --dir (file names, one zone that fails does not stop
#     the others, a symbolic link in the directory is never followed), tinydns zones, the views, zone types.
#  5. --json: import and export give one valid document of the karicheck schema with "karidns-zone": 1, only the document on standard output.
#  6. hostile input: zone names that are paths or commands, files that are not files, NUL bytes, control characters and quotes in names, a
#     database whose rows hold line feeds, comment characters and directives.
#  7. the round trip: file -> import -> export -> import -> export for the signed, tagged, tinydns, $GENERATE and $INCLUDE zones of tests/: the two
#     exports are byte for byte the same, and the records are those of the original (test_zone_text --dump).
#
# Environment: ZONE (default ./karidns-zone; ./karidns-zone-asan runs the ASan build), TZT (./test_zone_text).  SKIP (exit 0, with the reason)
# without the binary or the sqlite3 command line tool, or with a karidns-zone without the SQLite3 driver.  The json part SKIPs without perl
# JSON::PP.  Runs as any user (it never needs root).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

ZONE=${ZONE:-$ROOT/karidns-zone}
case $ZONE in /*) ;; *) ZONE=$ROOT/${ZONE#./} ;; esac      # absolute: one case runs it from another directory
TZT=${TZT:-$ROOT/test_zone_text}
JC="perl $ROOT/tests/lib/json_check.pl"
[ -x "$ZONE" ] || { echo "SKIP: $ZONE is not built"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver"; exit 0; }
HAVE_JSON=1
case $ZONE in *-asan) ASAN_OPTIONS="exitcode=99:${ASAN_OPTIONS:-}"; UBSAN_OPTIONS="halt_on_error=1:exitcode=99:${UBSAN_OPTIONS:-}"; export ASAN_OPTIONS UBSAN_OPTIONS ;; esac   # a sanitizer error is exit status 99, which no case expects
perl -MJSON::PP -e 1 >/dev/null 2>&1 || HAVE_JSON=0

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_zone.XXXXXX") || exit 1
trap 'if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"; fi' EXIT INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

OUT=$T/out.txt
ERR=$T/err.txt
DB=$T/z.db

newdb() {       # newdb FILE: an empty PowerDNS database with the karidns_* tables
    rm -f "$1" "$1-wal" "$1-shm"
    sqlite3 "$1" < "$ROOT/tests/db/pdns_schema.sqlite3.sql" > /dev/null && sqlite3 "$1" < "$ROOT/db/karidns_ext.sqlite3.sql" > /dev/null
}
q() { sqlite3 "$DB" "$1"; }          # one query on the current database
nrec() { q "SELECT count(*) FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = '$1')"; }
serial() { q "SELECT content FROM records WHERE type = 'SOA' AND name = '$1'" | awk '{print $3}'; }
chg() { q "SELECT count(*) FROM karidns_changes"; }

# kz ARGS...: karidns-zone against the current database, no configuration; stdout in $OUT, stderr in $ERR, the status in $st
kz() { "$ZONE" "$1" --no-config --sqlite3 "$DB" "${@:-}" > "$OUT" 2> "$ERR"; st=$?; }
IN=/dev/null
kz() { cmd=$1; shift; "$ZONE" "$cmd" --no-config --sqlite3 "$DB" "$@" > "$OUT" 2> "$ERR" < "$IN"; st=$?; }
# run DESC WANT ARGS...: karidns-zone exactly as given
run() { desc=$1; want=$2; shift 2; "$ZONE" "$@" > "$OUT" 2> "$ERR" < "$IN"; st=$?; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 400 "$OUT")"; fi; }
# expect DESC WANT ARGS...: kz ARGS and the status
expect() { desc=$1; want=$2; shift 2; kz "$@"; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 400 "$OUT")"; fi; }
errhas() { if grep -q -- "$2" "$ERR"; then ok "$1"; else bad "$1 (stderr lacks '$2')" "$(cat "$ERR")"; fi; }
outhas() { if grep -q -- "$2" "$OUT"; then ok "$1"; else bad "$1 (stdout lacks '$2')" "$(head -c 600 "$OUT")"; fi; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
jvalid() { if [ $HAVE_JSON = 1 ]; then if msg=$($JC "$OUT" valid 2>&1); then ok "$1: a valid document"; else bad "$1: $msg" "$(head -c 800 "$OUT")"; fi; fi; }
jhas() { [ $HAVE_JSON = 1 ] || return 0; if $JC "$OUT" has "$2"; then ok "$1"; else bad "$1 (no message $2)" "$(head -c 800 "$OUT")"; fi; }
jget() { [ $HAVE_JSON = 1 ] || return 0; got=$($JC "$OUT" get "$2" 2>&1); if [ "$got" = "$3" ]; then ok "$1"; else bad "$1 ($2: got '$got', wanted '$3')" "$(head -c 800 "$OUT")"; fi; }

HDR='$ORIGIN %s\n$TTL 300\n@ IN SOA ns1 hostmaster %s 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n'
mkzone() {      # mkzone FILE ORIGIN SERIAL [EXTRA]
    printf "$HDR" "$2" "$3" > "$1"
    [ -n "${4:-}" ] && printf '%s\n' "$4" >> "$1"
}

# ================================================================ 1. usage
echo "== usage"
newdb "$DB"
mkzone "$T/ex.zone" example.test. 10 'www IN A 192.0.2.2
mail IN MX 10 www'
run "no arguments" 2
errhas "...says what is missing" "no command given"
run "an unknown command" 2 frobnicate
errhas "...names it" "frobnicate"
run "an unknown option" 2 import --bogus x y
errhas "...names it" "unknown option"
run "an option without its value" 2 import --mode
errhas "...says so" "needs a value"
run "import without a file" 2 import --no-config --sqlite3 "$DB" example.test
run "import with three arguments" 2 import --no-config --sqlite3 "$DB" a b c
run "import --all with two arguments" 2 import --all --no-config --sqlite3 "$DB" a b
run "--mode bogus" 2 import --no-config --sqlite3 "$DB" --mode bogus example.test "$T/ex.zone"
run "--serial bogus" 2 import --no-config --sqlite3 "$DB" --serial bogus example.test "$T/ex.zone"
run "--type SLAVE" 2 import --no-config --sqlite3 "$DB" --type SLAVE example.test "$T/ex.zone"
run "--format bogus" 2 import --no-config --sqlite3 "$DB" --format bogus example.test "$T/ex.zone"
run "--format bind with --all" 2 import --all --format bind --no-config --sqlite3 "$DB" "$T/ex.zone"
run "--dir on import" 2 import --no-config --sqlite3 "$DB" --dir "$T" example.test "$T/ex.zone"
run "--force on import" 2 import --no-config --sqlite3 "$DB" --force example.test "$T/ex.zone"
types65=$(i=0; while [ $i -lt 65 ]; do printf 'A,'; i=$((i + 1)); done)A
run "more than 64 types" 2 import --no-config --sqlite3 "$DB" --types "$types65" example.test "$T/ex.zone"
run "export without a zone" 2 export --no-config --sqlite3 "$DB"
run "export with three arguments" 2 export --no-config --sqlite3 "$DB" a b c
run "export --all without --dir" 2 export --all --no-config --sqlite3 "$DB"
run "export --dir without --all" 2 export --dir "$T/d" --no-config --sqlite3 "$DB" example.test
run "export --all with a zone" 2 export --all --dir "$T/d" --no-config --sqlite3 "$DB" example.test
run "export --mode (an import option)" 2 export --mode merge --no-config --sqlite3 "$DB" example.test
run "export --dry-run (an import option)" 2 export --dry-run --no-config --sqlite3 "$DB" example.test
run "-c with --no-config" 2 import -c "$T/none.conf" --no-config --sqlite3 "$DB" example.test "$T/ex.zone"
run "--sqlite3 with --conninfo-file" 2 import --no-config --sqlite3 "$DB" --conninfo-file "$T/ci" example.test "$T/ex.zone"
run "--schema with --sqlite3" 2 import --no-config --sqlite3 "$DB" --schema s example.test "$T/ex.zone"
run "--json export to standard output" 2 --json export --no-config --sqlite3 "$DB" example.test
run "--version" 0 --version
outhas "...names the tool and the drivers" "karidns-zone .* (drivers: .*sqlite3"
run "-h" 0 -h
outhas "...prints the usage on standard output" "karidns-zone import"
run "import --help" 0 import --help
run "--json -h" 2 --json -h
# the examples of --help, as they are written there with paths of this test
mkdir "$T/ex"
run "help example: import into the database of a configuration" 1 import -c "$T/none.conf" example.test "$T/ex.zone"
errhas "...the configuration does not exist" "none.conf"
IN="$T/ex.zone"
run "help example: dry run, merge, standard input" 0 import --no-config --sqlite3 "$DB" --dry-run --mode merge example.test -
kz import --dry-run --mode merge example.test -
IN=/dev/null
same "...the dry run wrote nothing" "$(q "SELECT count(*) FROM domains")" 0
printf 'Zexample.test:ns1.example.test:hostmaster.example.test:10:7200:3600:1209600:300:300\n&example.test::ns1.example.test:300\n+ns1.example.test:192.0.2.1:300\n+www.example.test:192.0.2.2:300\n' > "$T/data"
run "help example: import --all a tinydns data file" 0 import --all --no-config --sqlite3 "$DB" "$T/data"
same "...the zone is in the database" "$(q "SELECT count(*) FROM domains")" 1
run "help example: export to standard output" 0 export --no-config --sqlite3 "$DB" example.test
outhas "...the zone text (a data file: the zone came from one)" "+ns1.example.test.:192.0.2.1"
run "help example: export --all --dir" 0 export --all --dir "$T/ex" --no-config --sqlite3 "$DB"
[ -f "$T/ex/example.test.tinydns" ] && ok "...a tinydns zone is written as a data file" || bad "...no example.test.tinydns" "$(ls "$T/ex")"

# ================================================================ 2. import
echo "== import"
newdb "$DB"
expect "a new zone" 0 import example.test "$T/ex.zone"
outhas "...reported as new, with its serial" "(new).*SOA serial 10"
same "...type NATIVE" "$(q "SELECT type FROM domains WHERE name = 'example.test'")" NATIVE
same "...the records are there" "$(nrec example.test)" 5
same "...the owners are lower case without the dot" "$(q "SELECT count(*) FROM records WHERE name = 'www.example.test'")" 1
same "...MX priority is in prio" "$(q "SELECT prio || ' ' || content FROM records WHERE type = 'MX'")" "10 www.example.test"
n1=$(chg); [ "$n1" -gt 0 ] && ok "...the change log has the change (a running server reloads)" || bad "...karidns_changes is empty"
mkzone "$T/m.zone" mzone.test. 1
expect "a new zone of type MASTER" 0 import --type MASTER mzone.test "$T/m.zone"
same "...type MASTER" "$(q "SELECT type FROM domains WHERE name = 'mzone.test'")" MASTER
mkzone "$T/m.zone" mzone.test. 2
expect "an existing zone keeps its type (--type is for new zones)" 0 import --type NATIVE mzone.test "$T/m.zone"
same "...still MASTER" "$(q "SELECT type FROM domains WHERE name = 'mzone.test'")" MASTER

echo "-- replace, merge, types"
mkzone "$T/r.zone" example.test. 11 'new IN A 192.0.2.9
mail IN MX 20 www
www IN A 192.0.2.2'
expect "replace (the default)" 0 import example.test "$T/r.zone"
outhas "...counts" "RRset(s) added"
same "...the old RRsets are gone" "$(q "SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A'")" 1
same "...the new one is there" "$(q "SELECT count(*) FROM records WHERE name = 'new.example.test'")" 1
same "...the MX changed" "$(q "SELECT prio FROM records WHERE type = 'MX'")" 20
same "...another zone is not touched" "$(nrec mzone.test)" 3
printf '$ORIGIN example.test.\n$TTL 60\nwww IN A 192.0.2.81\nwww IN A 192.0.2.82\nadded IN TXT "hi"\n' > "$T/merge.zone"
expect "merge: a part of the zone, without SOA and NS" 0 import --mode merge example.test "$T/merge.zone"
same "...the RRset www A was replaced" "$(q "SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND ttl = 60")" 2
same "...the other RRsets stayed" "$(q "SELECT count(*) FROM records WHERE name = 'new.example.test'")" 1
same "...the serial stayed" "$(serial example.test)" 11
printf '$ORIGIN example.test.\n$TTL 60\nwww IN A 192.0.2.99\nwww IN TXT "t"\n' > "$T/types.zone"
expect "--types A: only the A records are replaced" 0 import --mode merge --types a example.test "$T/types.zone"
same "...the A RRset" "$(q "SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND content = '192.0.2.99'")" 1
same "...no TXT was written" "$(q "SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'TXT'")" 0
expect "--types with a type that is not a name" 1 import --types 'A;B' example.test "$T/types.zone"
errhas "...says so" "not a record type"

echo "-- dry run"
before="$(q "SELECT count(*), sum(id) FROM records")|$(chg)"
mkzone "$T/d.zone" example.test. 12 'dry IN A 192.0.2.10'
expect "--dry-run" 0 import --dry-run example.test "$T/d.zone"
outhas "...says it was a dry run" "dry run, nothing was written"
errhas "...lists an RRset that would be added" "add dry.example.test A"
errhas "...and one that would be deleted" "delete www.example.test A"
same "...the database is unchanged" "$(q "SELECT count(*), sum(id) FROM records")|$(chg)" "$before"
expect "-n is --dry-run" 0 import -n example.test "$T/d.zone"
outhas "...dry run" "dry run"
expect "--verbose lists the changes of a real import" 0 import --verbose example.test "$T/d.zone"
errhas "...replaced or added" "dry.example.test A"
same "...and wrote them" "$(q "SELECT count(*) FROM records WHERE name = 'dry.example.test'")" 1

echo "-- serial"
mkzone "$T/s.zone" example.test. 12 'x IN A 192.0.2.50'
expect "the serial must grow: an equal serial is refused" 1 import example.test "$T/s.zone"
errhas "...with the reason" "does not grow"
same "...nothing was written" "$(q "SELECT count(*) FROM records WHERE name = 'x.example.test'")" 0
mkzone "$T/s.zone" example.test. 3 'x IN A 192.0.2.50'
expect "a smaller serial is refused" 1 import example.test "$T/s.zone"
expect "--serial increment writes the database serial + 1" 0 import --serial increment example.test "$T/s.zone"
same "...13" "$(serial example.test)" 13
expect "--serial keep takes the file's serial (a restore)" 0 import --serial keep example.test "$T/s.zone"
same "...3" "$(serial example.test)" 3
mkzone "$T/s.zone" example.test. 4 'x IN A 192.0.2.50'
expect "a serial that grows" 0 import example.test "$T/s.zone"
same "...4" "$(serial example.test)" 4
mkzone "$T/s.zone" fresh.test. 77
expect "a new zone takes the file's serial" 0 import fresh.test "$T/s.zone"
same "...77" "$(serial fresh.test)" 77

echo "-- checks, strict, verification"
cat > "$T/warn.zone" <<'EOF'
$ORIGIN warn.test.
$TTL 300
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
a IN CNAME b
b IN CNAME www
www IN A 192.0.2.2
EOF
expect "a warning is printed and the import goes on" 0 import warn.test "$T/warn.zone"
errhas "...the CNAME chain warning" "CNAME chain"
sed 's/warn.test/warn2.test/g' "$T/warn.zone" > "$T/warn2.zone"
expect "--strict: a warning fails the import" 1 import --strict warn2.test "$T/warn2.zone"
errhas "...with the reason" "strict mode"
same "...nothing was written" "$(q "SELECT count(*) FROM domains WHERE name = 'warn2.test'")" 0
mkzone "$T/bad.zone" bad.test. 1 'bad IN A 999.1.1.1'
expect "a syntax error" 1 import bad.test "$T/bad.zone"
errhas "...names the line" "bad.zone:6"
same "...nothing was written" "$(q "SELECT count(*) FROM domains WHERE name = 'bad.test'")" 0
mkzone "$T/lint.zone" lint.test. 1 'c IN CNAME www
c IN A 192.0.2.5
www IN A 192.0.2.6'
expect "an error of the zone checks (CNAME beside an A record)" 1 import lint.test "$T/lint.zone"
errhas "...with the finding" "coexists"
same "...nothing was written" "$(q "SELECT count(*) FROM domains WHERE name = 'lint.test'")" 0
expect "the zone is not in the file" 1 import other.test "$T/ex.zone"
errhas "...says so" "other.test"

# the read-back: the file is fine, the zone as written is not
expect "set up for the read-back" 0 import --serial keep example.test "$T/r.zone"
n0=$(nrec example.test); c0=$(chg)
printf '$ORIGIN example.test.\n$TTL 300\nwww IN CNAME mail\n' > "$T/cn.zone"
expect "a merge that puts a CNAME beside an A record is refused" 1 import --mode merge example.test "$T/cn.zone"
errhas "...by the checks of the zone as written" "coexists"
errhas "...and rolled back" "nothing was written"
same "...no record was added" "$(nrec example.test)" "$n0"
same "...the change log did not grow" "$(chg)" "$c0"
expect "the same with --dry-run" 1 import --dry-run --mode merge example.test "$T/cn.zone"
printf '$ORIGIN example.test.\n$TTL 300\nwww IN ALIAS lb.target.test.\n' > "$T/al.zone"
expect "an ALIAS beside an A record is refused" 1 import --mode merge example.test "$T/al.zone"
errhas "...by the loader's reader" "ALIAS"
same "...no ALIAS was written" "$(q "SELECT count(*) FROM records WHERE type = 'ALIAS'")" 0
printf '$ORIGIN example.test.\n$TTL 300\nunique IN CNAME mail\n' > "$T/cn.zone"
expect "a CNAME at a name of its own is fine" 0 import --mode merge example.test "$T/cn.zone"

echo "-- standard input, file names, tinydns"
newdb "$DB"
IN="$T/ex.zone"
expect "a zone from standard input" 0 import example.test -
IN=/dev/null
outhas "...imported" "example.test"
printf '$ORIGIN example.test.\n$INCLUDE /etc/hostname\n' > "$T/inc.zone"
IN="$T/inc.zone"
expect "\$INCLUDE in standard input is refused" 1 import example.test -
IN=/dev/null
errhas "...with the reason" "INCLUDE"
cp -r tests/include_tests "$T/inc"
expect "\$INCLUDE in a file is read from its directory" 0 import example.com "$T/inc/valid_parent.zone"
same "...with the included records" "$(q "SELECT count(*) FROM records WHERE name IN ('www.example.com', 'host.sub.example.com')")" 2
expect "a file that does not exist" 1 import example.test "$T/nonexistent.zone"
errhas "...names it" "nonexistent.zone"
expect "a directory is not a zone file" 1 import example.test "$T"
errhas "...says so" "not a regular file"
printf '$ORIGIN nul.test.\n@ IN SOA a b 1 2 3 4 5\n\000 x\n' > "$T/nul.zone"
expect "a file with a NUL byte" 1 import nul.test "$T/nul.zone"
expect "a zone name that is not a name" 1 import 'a..b' "$T/ex.zone"
errhas "...says so" "not a valid zone name"
newdb "$DB"
cat > "$T/two.data" <<'EOF'
Ztwo-a.test:ns1.two-a.test:hostmaster.two-a.test:5:7200:3600:1209600:300:300
&two-a.test::ns1.two-a.test:300
+ns1.two-a.test:192.0.2.1:300
+www.two-a.test:192.0.2.2:300
Ztwo-b.test:ns1.two-b.test:hostmaster.two-b.test:6:7200:3600:1209600:300:300
&two-b.test::ns1.two-b.test:300
+ns1.two-b.test:192.0.2.3:300
EOF
expect "import --all: every zone of a tinydns data file" 0 import --all "$T/two.data"
outhas "...the summary" "2 zone(s) imported, 0 failed"
same "...both zones" "$(q "SELECT count(*) FROM domains")" 2
same "...marked as tinydns zones" "$(q "SELECT count(*) FROM domainmetadata WHERE kind = 'X-KARIDNS-FORMAT'")" 2
expect "one zone of a tinydns data file (by the name data.tinydns)" 0 import --serial keep two-b.test "$T/two.data" --format tinydns
cp "$T/two.data" "$T/x.tinydns"
expect "the format by file name (.tinydns)" 0 import --serial keep two-a.test "$T/x.tinydns"
expect "a zone that is not in the data file" 1 import --format tinydns nothere.test "$T/two.data"
printf 'Zbad-c.test:ns1.bad-c.test:h.bad-c.test:1:7200:3600:1209600:300:300\n+www.bad-c.test:999.1.1.1:300\n' > "$T/badc.data"
expect "import --all: a bad zone fails, the others are not stopped" 1 import --all "$T/badc.data"
errhas "...the reason" "bad-c.test"

# ================================================================ 3. the configuration
echo "== configuration"
newdb "$DB"
newdb "$T/own.db"
cat > "$T/k.conf" <<EOF
options {
    directory "$T";
    check-mx fail;
    max-records 12;
    database { driver sqlite3; database-file "$DB"; default-ttl 600; };
};
view "internal" {
    match-clients { 127.0.0.1; };
    max-records 100;
    zone "filez.test" { type master; file "$T/filez.zone"; };
};
view "own" {
    match-clients { 127.0.0.2; };
    database-file "$T/own.db";
};
view "nodb" {
    match-clients { 127.0.0.3; };
    database none;
};
EOF
cat > "$T/plain.conf" <<EOF
options { directory "$T"; database { driver sqlite3; database-file "$DB"; }; };
zone "example.test" { type master; file "$T/ex.zone"; };
EOF
kzc() { conf=$1; shift; cmd=$1; shift; "$ZONE" "$cmd" -c "$conf" "$@" > "$OUT" 2> "$ERR"; st=$?; }
expectc() { desc=$1; want=$2; shift 2; kzc "$@" < /dev/null; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 400 "$OUT")"; fi; }
expectc "the database of the configuration" 0 "$T/plain.conf" import example.test "$T/ex.zone"
same "...is the one that got the zone" "$(q "SELECT count(*) FROM domains")" 1
errhas "...the zone is also a file zone of the configuration (D-PRIO)" "file zone"
expectc "a view that reads the shared source" 0 "$T/k.conf" import --view internal example.test "$T/ex.zone" --serial keep
same "...the zone is in the view (karidns_domain_views)" "$(q "SELECT view_name FROM karidns_domain_views")" internal
mkzone "$T/f.zone" filez.test. 1
expectc "a zone that is a file zone of the view" 0 "$T/k.conf" import --view internal filez.test "$T/f.zone"
errhas "...warns that the file zone is served" "file zone"
expectc "a file zone of another view is no warning here" 0 "$T/k.conf" import --view own filez.test "$T/f.zone"
if grep -q "file zone" "$ERR"; then bad "...a warning for a zone of another view"; else ok "...no warning for a zone of another view"; fi
same "...a view with a source of its own: that database got the zone" "$(sqlite3 "$T/own.db" "SELECT count(*) FROM domains")" 1
same "...no view row (the view ignores karidns_domain_views)" "$(sqlite3 "$T/own.db" "SELECT count(*) FROM karidns_domain_views")" 0
expectc "a view that takes no zones from the database" 1 "$T/k.conf" import --view nodb example.test "$T/ex.zone"
errhas "...says so" "database none"
expectc "a view that is not defined" 1 "$T/k.conf" import --view nowhere example.test "$T/ex.zone"
errhas "...names it" "nowhere"
expectc "export from a view lists its zones" 0 "$T/k.conf" export --view internal example.test
mkzone "$T/ov.zone" otherv.test. 1
kz import --view other otherv.test "$T/ov.zone"
expectc "export of a zone that is not in the view" 1 "$T/k.conf" export --view internal otherv.test
errhas "...not found" "not in the view"
# the size limits and the check-* options of the configuration: a zone the server would refuse is not written
mkzone "$T/big.zone" big.test. 1 'a IN A 192.0.2.10
b IN A 192.0.2.11
c IN A 192.0.2.12
d IN A 192.0.2.13
e IN A 192.0.2.14
f IN A 192.0.2.15
g IN A 192.0.2.16
h IN A 192.0.2.17
i IN A 192.0.2.18
j IN A 192.0.2.19
k IN A 192.0.2.20'
expectc "max-records of options: a zone over the limit is refused" 1 "$T/k.conf" import big.test "$T/big.zone"
errhas "...with the limit" "max-records"
same "...nothing was written" "$(q "SELECT count(*) FROM domains WHERE name = 'big.test'")" 0
expectc "max-records of the view (100) applies to that view" 0 "$T/k.conf" import --view internal big.test "$T/big.zone"
mkzone "$T/mx.zone" mx.test. 1 'm IN MX 10 192.0.2.25.'
expectc "check-mx fail: an MX that is an address is an error" 1 "$T/k.conf" import --view internal mx.test "$T/mx.zone"
errhas "...the finding" "check-mx"
expectc "...and only a warning without the option" 0 "$T/plain.conf" import mx.test "$T/mx.zone"
cat > "$T/ttl.conf" <<EOF
options { directory "$T"; max-zone-ttl 100; database { driver sqlite3; database-file "$DB"; }; };
EOF
mkzone "$T/ttl.zone" ttl.test. 1
expectc "max-zone-ttl: a TTL above it is refused" 1 "$T/ttl.conf" import ttl.test "$T/ttl.zone"
errhas "...with the limit" "TTL"
cat > "$T/types.conf" <<EOF
options { directory "$T"; max-types-per-name 1; max-records-per-type 1; database { driver sqlite3; database-file "$DB"; }; };
EOF
mkzone "$T/tpn.zone" tpn.test. 1
expectc "max-types-per-name: the apex has SOA and NS" 1 "$T/types.conf" import tpn.test "$T/tpn.zone"
cat > "$T/rpt.conf" <<EOF
options { directory "$T"; max-records-per-type 1; database { driver sqlite3; database-file "$DB"; }; };
EOF
mkzone "$T/rpt.zone" rpt.test. 1 'w IN A 192.0.2.1
w IN A 192.0.2.2'
expectc "max-records-per-type" 1 "$T/rpt.conf" import rpt.test "$T/rpt.zone"
printf '$ORIGIN example.test.\n$TTL 300\nm1 IN A 192.0.2.61\nm2 IN A 192.0.2.62\nm3 IN A 192.0.2.63\n' > "$T/m3.zone"
cat > "$T/lim5.conf" <<EOF
options { directory "$T"; max-records 6; database { driver sqlite3; database-file "$DB"; }; };
EOF
expectc "a merge that takes the zone over max-records is refused" 1 "$T/lim5.conf" import --mode merge example.test "$T/m3.zone"
errhas "...with the limit" "max-records"
# the errors
expectc "a configuration that does not exist" 1 "$T/none.conf" import example.test "$T/ex.zone"
printf 'options { this is not valid\n' > "$T/syntax.conf"
expectc "a configuration with a syntax error" 1 "$T/syntax.conf" import example.test "$T/ex.zone"
errhas "...says so" "Syntax error"
printf 'options { directory "%s"; };\n' "$T" > "$T/nodb.conf"
expectc "a configuration without a database block" 1 "$T/nodb.conf" import example.test "$T/ex.zone"
errhas "...says what is missing" "No database"
run "no database at all" 1 import --no-config example.test "$T/ex.zone"
errhas "...says what to give" "--sqlite3"
printf 'options { directory "%s"; database { driver postgresql; conninfo-file "%s/ci"; }; };\n' "$T" "$T" > "$T/pg.conf"
if "$ZONE" --version | grep -q postgresql; then ok "(this karidns-zone has the PostgreSQL driver: the missing-driver case is not run)"
else
    expectc "a driver this build does not have" 1 "$T/pg.conf" import example.test "$T/ex.zone"
    errhas "...names the drivers there are" "drivers: sqlite3"
fi
printf 'options { directory "%s"; database { driver sqlite3; }; };\n' "$T" > "$T/nofile.conf"
expectc "options { database { } } without a database file" 1 "$T/nofile.conf" import example.test "$T/ex.zone"
errhas "...says so" "database-file"
expectc "-c gives the same database to export" 0 "$T/plain.conf" export example.test
outhas "...the zone text" "ns1 A 192.0.2.1"

mkzone "$T/dd.zone" dd.test. 1
expect "-- ends the options" 0 import -- dd.test "$T/dd.zone"
head -c 17000000 /dev/zero > "$T/big.conf"
expectc "a configuration that is not a file" 1 "$T" import example.test "$T/ex.zone"
errhas "...says so" "not a regular file"
expectc "a configuration larger than 16 MiB" 1 "$T/big.conf" import example.test "$T/ex.zone"
errhas "...says so" "larger than"
rm -f "$T/big.conf"
if [ ! -e /usr/local/etc/karidns/karidns.conf ] && [ ! -e /usr/local/etc/karidns.conf ]; then
    mkzone "$T/dd2.zone" dd2.test. 1
    run "without -c and without a default configuration, --sqlite3 is enough" 0 import --sqlite3 "$DB" dd2.test "$T/dd2.zone"
fi
rm -f "$T/rel.zone"
( cd "$T" && "$ZONE" export --no-config --sqlite3 "$DB" example.test rel.zone > "$OUT" 2> "$ERR" < /dev/null ); st=$?
[ "$st" = 0 ] && [ -s "$T/rel.zone" ] && ok "export to a file name without a directory part (the current directory)" || bad "export to a relative name: exit status $st" "$(cat "$ERR")"
# standard output that cannot be written to: a descriptor opened for reading only (write fails with EBADF)
"$ZONE" export --no-config --sqlite3 "$DB" example.test 1< /dev/null 2> "$ERR" < /dev/null; st=$?
[ "$st" = 1 ] && grep -q "Could not write" "$ERR" && ok "export to a standard output that cannot be written: exit status 1 and the reason" || bad "export to an unwritable stdout: exit status $st" "$(cat "$ERR")"
"$ZONE" --json export --no-config --sqlite3 "$DB" example.test "$T/jfull.zone" 1< /dev/null 2> "$ERR" < /dev/null; st=$?
[ "$st" = 1 ] && grep -q "cannot write the JSON document" "$ERR" && ok "a JSON document that cannot be written: exit status 1 and the reason on standard error" || bad "--json to an unwritable stdout: exit status $st" "$(cat "$ERR")"

# ================================================================ 4. export
echo "== export"
newdb "$DB"
expect "set up" 0 import example.test "$T/ex.zone"
expect "export to standard output" 0 export example.test
head -2 "$OUT" | tr '\n' ' ' | grep -q 'ORIGIN example.test. .TTL' && ok "...BIND format: \$ORIGIN, \$TTL" || bad "...the first lines" "$(head -3 "$OUT")"
cp "$OUT" "$T/e0.out"
expect "the name is accepted in any case and with the dot" 0 export Example.TEST.
cmp -s "$OUT" "$T/e0.out" && ok "...the same text" || bad "...differs"
expect "export of a zone that is not there" 1 export nothere.test
errhas "...not found" "not in the database"
same "...and nothing on standard output" "$(wc -c < "$OUT" | tr -d ' ')" 0
rm -f "$T/o.zone"
expect "export to a file" 0 export example.test "$T/o.zone"
cmp -s "$T/o.zone" "$T/e0.out" && ok "...the same text as on standard output" || bad "...the file differs"
outhas "...reported" "exported to"
expect "the file exists: refused" 1 export example.test "$T/o.zone"
errhas "...with --force" "use --force"
echo OLD > "$T/o.zone"
expect "...and untouched" 1 export example.test "$T/o.zone"
same "...old content" "$(cat "$T/o.zone")" OLD
expect "--force replaces it" 0 export --force example.test "$T/o.zone"
cmp -s "$T/o.zone" "$T/e0.out" && ok "...new content" || bad "...not replaced"
ls -a "$T" | grep -q 'karidns-zone.*tmp' && bad "a temporary file was left behind" || ok "no temporary file is left behind"
expect "a file in a directory that does not exist" 1 export example.test "$T/nodir/o.zone"
errhas "...says so" "directory"
expect "a file name that is a directory name" 1 export example.test "$T/"
expect "- is standard output" 0 export example.test -
cmp -s "$OUT" "$T/e0.out" && ok "...the text" || bad "...differs"
expect "--format tinydns of a BIND zone" 0 export --format tinydns example.test
outhas "...a data file" "^Zexample.test"
expect "--format bind" 0 export --format bind example.test
expect "--format auto" 0 export --format auto example.test
echo VICTIM > "$T/victim"
rm -f "$T/o.zone"; ln -s "$T/victim" "$T/o.zone"
expect "an output name that is a symbolic link is not followed" 1 export example.test "$T/o.zone"
same "...the target is untouched" "$(cat "$T/victim")" VICTIM
expect "--force replaces the link itself, not its target" 0 export --force example.test "$T/o.zone"
same "...the target is untouched" "$(cat "$T/victim")" VICTIM
[ -L "$T/o.zone" ] && bad "...the link is still a link" || ok "...the name is now a regular file"

echo "-- export --all --dir"
newdb "$DB"
expect "set up the zones" 0 import example.test "$T/ex.zone"
expect "..." 0 import --all "$T/two.data"
mkzone "$T/mm.zone" mm.test. 1
expect "..." 0 import --type MASTER mm.test "$T/mm.zone"
q "INSERT INTO domains (name, type) VALUES ('slave.test', 'SLAVE')"
q "INSERT INTO domains (name, type) VALUES ('a%b.test', 'NATIVE')"
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT id, name, 'SOA', 'ns1.a%b.test hostmaster.a%b.test 1 7200 3600 1209600 300', 300, 0 FROM domains WHERE name = 'a%b.test'"
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT id, name, 'NS', 'ns1.a%b.test', 300, 0 FROM domains WHERE name = 'a%b.test'"
q "INSERT INTO domains (name, type) VALUES ('x/y.test', 'NATIVE')"
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT id, name, 'SOA', 'ns1.x/y.test hostmaster.x/y.test 1 7200 3600 1209600 300', 300, 0 FROM domains WHERE name = 'x/y.test'"
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT id, name, 'NS', 'ns1.x/y.test', 300, 0 FROM domains WHERE name = 'x/y.test'"
longname=$(printf '/%.0s' $(seq 1 100))
q "INSERT INTO domains (name, type) VALUES ('$longname.test', 'NATIVE')"
q "INSERT INTO domains (name, type) VALUES ('broken.test', 'NATIVE')"
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT id, name, 'SOA', 'not an soa', 300, 0 FROM domains WHERE name = 'broken.test'"
rm -rf "$T/bk"
expect "every primary zone into a directory (created); a zone that cannot be read is an error" 1 export --all --dir "$T/bk"
errhas "...names the broken zone" "broken.test"
outhas "...the summary" "exported to .*, 2 failed"
errhas "...a name too long for a file name is reported" "too long"
for f in example.test.zone two-a.test.tinydns two-b.test.tinydns mm.test.zone 'a%25b.test.zone' 'x%2Fy.test.zone'; do
    [ -f "$T/bk/$f" ] && ok "...$f" || bad "...no $f" "$(ls "$T/bk")"
done
[ -e "$T/bk/slave.test.zone" ] && bad "...a SLAVE zone was exported" || ok "...the SLAVE zone is not exported"
[ -e "$T/bk/broken.test.zone" ] && bad "...a file for the broken zone" || ok "...no file for the broken zone"
bad_names=$(ls -a "$T/bk" | grep -v '^\.\.\?$' | grep -v '^[A-Za-z0-9%][A-Za-z0-9%._-]*$')
[ -z "$bad_names" ] && ok "...every file name is made of safe characters, none starts with a dot" || bad "...unsafe file names" "$bad_names"
[ -d "$T/bk/x" ] && bad "...a slash in a zone name made a directory" || ok "...a slash in a zone name made no directory"
cmp -s "$T/bk/example.test.zone" "$T/e0.out" && ok "...a zone file equals the export of the zone" || bad "...differs"
head -1 "$T/bk/two-a.test.tinydns" | grep -q '^[%Z.&+]' && ok "...the tinydns zone is a data file" || bad "...not a data file" "$(head -3 "$T/bk/two-a.test.tinydns")"
expect "again into the same directory: existing files are refused, not touched" 1 export --all --dir "$T/bk"
errhas "...with --force" "use --force"
echo OLD > "$T/bk/mm.test.zone"
expect "...(a changed file stays as it is)" 1 export --all --dir "$T/bk"
same "...it is still the old one" "$(cat "$T/bk/mm.test.zone")" OLD
expect "--force replaces them" 1 export --all --force --dir "$T/bk"
cmp -s "$T/bk/example.test.zone" "$T/e0.out" && [ "$(head -1 "$T/bk/mm.test.zone")" = '$ORIGIN mm.test.' ] && ok "...replaced" || bad "...not replaced"
# links in the directory
rm -rf "$T/bl"; mkdir "$T/bl"
echo VICTIM > "$T/victim2"
ln -s "$T/victim2" "$T/bl/example.test.zone"
ln -s "$T/nowhere" "$T/bl/mm.test.zone"
expect "--all: a symbolic link in the directory is never followed" 1 export --all --dir "$T/bl"
same "...the target is untouched" "$(cat "$T/victim2")" VICTIM
[ ! -e "$T/nowhere" ] && ok "...a dangling link was not created through" || bad "...the dangling link was written through"
expect "--force replaces the link itself" 1 export --all --force --dir "$T/bl"
same "...the target is untouched" "$(cat "$T/victim2")" VICTIM
[ -f "$T/bl/example.test.zone" ] && [ ! -L "$T/bl/example.test.zone" ] && ok "...the name is a regular file" || bad "...still a link"
expect "--dir that is a file" 1 export --all --dir "$T/victim2"
errhas "...says so" "directory"
q "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'internal' FROM domains WHERE name = 'example.test'"
q "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'other' FROM domains WHERE name = 'mm.test'"
rm -rf "$T/bv"
expect "(with rows in karidns_domain_views)" 1 export --all --dir "$T/bv" --view internal
[ -f "$T/bv/example.test.zone" ] && [ ! -e "$T/bv/mm.test.zone" ] && ok "...the zone of the view is there, the zone of another view is not" || bad "...the view" "$(ls "$T/bv")"
q "UPDATE domains SET type = 'SLAVE' WHERE name = 'mm.test'"
expect "export of a SLAVE zone" 1 export mm.test
errhas "...not a primary zone" "only NATIVE and MASTER"

# ================================================================ 5. json
echo "== json"
if [ $HAVE_JSON = 0 ]; then echo "  (perl JSON::PP is not installed: the json part is skipped)"; else
newdb "$DB"
jrun() { desc=$1; want=$2; shift 2; "$ZONE" --json "$@" > "$OUT" 2> "$ERR" < /dev/null; st=$?
    if [ "$st" != "$want" ]; then bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 600 "$OUT")"; return 1; fi
    if [ -s "$ERR" ]; then bad "$desc: stderr is not empty" "$(cat "$ERR")"; return 1; fi
    jvalid "$desc"; }
jrun "import" 0 import --no-config --sqlite3 "$DB" example.test "$T/ex.zone"
jget "...the tool" karidns-zone 1
jget "...the command" command import
jget "...the result" result ok
jget "...one zone" zones.0.zone example.test
jget "...its format" zones.0.format bind
jget "...its result" zones.0.result ok
jhas "...a message with the code db.import.done" db.import.done
jrun "import (the serial does not grow)" 1 import --no-config --sqlite3 "$DB" example.test "$T/ex.zone"
jget "...the result" result fail
jhas "...the code" db.import.serial
jget "...the zone entry fails" zones.0.result fail
jrun "import --dry-run" 0 import --no-config --sqlite3 "$DB" --dry-run --mode merge example.test "$T/merge.zone"
jhas "...the dry run code" db.import.dry-run
jhas "...the changes are messages too" db.import.change
jrun "import --all" 0 import --all --no-config --sqlite3 "$DB" "$T/two.data"
jget "...two zones" counts.checked 2
jget "...a zone" zones.0.format tinydns
jrun "import --all with a failing zone" 1 import --all --no-config --sqlite3 "$DB" "$T/badc.data"
jget "...the zone entry" zones.0.result fail
jrun "export to a file" 0 export --no-config --sqlite3 "$DB" example.test "$T/je.zone"
jget "...the command" command export
jget "...the zone" zones.0.zone example.test
jget "...the file" zones.0.file "$T/je.zone"
jhas "...done" db.export.done
jrun "export --all --dir" 0 export --all --no-config --sqlite3 "$DB" --dir "$T/jd"
jget "...zones" counts.checked 3
jrun "export of a zone that is not there" 1 export --no-config --sqlite3 "$DB" nothere.test "$T/jn.zone"
jhas "...the code" db.export.not-found
jrun "no command" 2
jget "...the result" result usage
jhas "...the code" usage.command.missing
jrun "unknown command" 2 frobnicate
jhas "...the code" usage.command.unknown
jrun "unknown option" 2 import --bogus
jhas "...the code" usage.option
jrun "wrong number of arguments" 2 import --no-config --sqlite3 "$DB" a
jhas "...the code" usage.args
jrun "export to standard output" 2 export --no-config --sqlite3 "$DB" example.test
jrun "no database" 1 import --no-config example.test "$T/ex.zone"
jhas "...the code" db.zone.no-source
jrun "file exists" 1 export --no-config --sqlite3 "$DB" example.test "$T/je.zone"
jhas "...the code" db.zone.output-exists
# the same status as the text mode, for the same arguments
for args in "import --no-config --sqlite3 $DB example.test $T/ex.zone" "export --no-config --sqlite3 $DB example.test $T/je2.zone" "import --bogus" ""; do
    "$ZONE" --json $args > "$OUT" 2>/dev/null < /dev/null; sj=$?
    rm -f "$T/je2.zone"
    "$ZONE" $args > /dev/null 2>&1 < /dev/null; sx=$?
    rm -f "$T/je2.zone"
    [ "$sj" = "$sx" ] && ok "the status of '$args' is the same with --json ($sj)" || bad "'$args': text mode $sx, --json $sj"
done
# hostile names reach the document escaped
weird="$T/we\"ird\\name.zone"
cp "$T/ex.zone" "$weird"
jrun "a file name with a quote and a backslash" 1 import --no-config --sqlite3 "$DB" example.test "$weird"
fi

# ================================================================ 6. hostile input
echo "== hostile input"
newdb "$DB"
before="$(q "SELECT count(*) FROM domains")|$(q "SELECT count(*) FROM records")"
for name in '../x' 'a/b' '$(touch pwned)' '`touch pwned`' 'a;b' "a'b" 'a"b' ' ' '-' '.' "$(printf 'x%.0s' $(seq 1 300))"; do
    kz import "$name" "$T/ex.zone" < /dev/null
    if [ "$st" = "1" ]; then ok "zone name '$(printf '%s' "$name" | cut -c1-20)' is refused"; else bad "zone name '$(printf '%s' "$name" | cut -c1-20)': exit status $st" "$(cat "$ERR")"; fi
done
[ ! -e pwned ] && [ ! -e "$T/pwned" ] && ok "no name was run as a command" || bad "a file 'pwned' appeared"
same "the database is unchanged" "$(q "SELECT count(*) FROM domains")|$(q "SELECT count(*) FROM records")" "$before"
kz export '../x' < /dev/null; same "export of '../x': not found" "$st" 1
kz export 'a/b' "$T/hostile.zone" < /dev/null; same "export of 'a/b' to a file: not found" "$st" 1
[ -e "$T/hostile.zone" ] && bad "a file was created for a zone that does not exist" || ok "...no file was created"
# owner names and strings that are hard for a zone file
printf '$ORIGIN hostile.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n' > "$T/h.zone"
cat >> "$T/h.zone" <<'EOF'
a\.b IN A 192.0.2.2
sp\032ace IN A 192.0.2.3
\200x IN A 192.0.2.6
t\.x IN TXT "quote \" semi ; paren ( ) dollar $INCLUDE /etc/passwd \\ back"
nl IN TXT "line\010feed and \013 control"
long IN TXT "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "second"
EOF
expect "owners with escapes, strings with quotes, semicolons, parentheses, directives and control characters" 0 import hostile.test "$T/h.zone"
expect "...exported" 0 export hostile.test "$T/h1.zone"
grep -c '^\$INCLUDE' "$T/h1.zone" | grep -qx 0 && ok "...no directive in the file that the data did not put there" || bad "...a \$INCLUDE line in the export" "$(cat "$T/h1.zone")"
expect "...imported again" 0 import --serial keep hostile.test "$T/h1.zone"
expect "...exported again" 0 export hostile.test "$T/h2.zone"
cmp -s "$T/h1.zone" "$T/h2.zone" && ok "...the two exports are the same" || bad "...they differ" "$(diff "$T/h1.zone" "$T/h2.zone" | head -6)"
same "...the same number of records" "$(nrec hostile.test)" 9
# a database whose rows are hostile
q "INSERT INTO domains (name, type) VALUES ('rows.test', 'NATIVE')"
rid=$(q "SELECT id FROM domains WHERE name = 'rows.test'")
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) VALUES ($rid, 'rows.test', 'SOA', 'ns1.rows.test hostmaster.rows.test 1 7200 3600 1209600 300', 300, 0), ($rid, 'rows.test', 'NS', 'ns1.rows.test', 300, 0), ($rid, 'ns1.rows.test', 'A', '192.0.2.1', 300, 0)"
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) VALUES ($rid, 't1.rows.test', 'TXT', '\"x\\\" ; ( ) \$INCLUDE /etc/passwd\"', 300, 0)"
expect "TXT data with a quote, a semicolon, parentheses and a directive in the database" 0 export rows.test "$T/r1.zone"
expect "...round trip" 0 import --serial keep rows.test "$T/r1.zone"
expect "..." 0 export rows.test "$T/r2.zone"
cmp -s "$T/r1.zone" "$T/r2.zone" && ok "...the exports are the same" || bad "...they differ" "$(diff "$T/r1.zone" "$T/r2.zone" | head)"
same "...the TXT record is the same" "$(q "SELECT count(*) FROM records WHERE name = 't1.rows.test'")" 1
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) VALUES ($rid, 'nl.rows.test', 'TXT', '\"a'||char(10)||'\$INCLUDE /etc/passwd\"', 300, 0)"
rm -f "$T/r3.zone"
expect "a row with a line feed in its content: the zone is refused, not exported" 1 export rows.test "$T/r3.zone"
[ -e "$T/r3.zone" ] && bad "...a file was created" || ok "...no file was created"
expect "...(on standard output nothing is written either)" 1 export rows.test
same "...stdout is empty" "$(wc -c < "$OUT" | tr -d ' ')" 0
q "DELETE FROM records WHERE name = 'nl.rows.test'"
q "INSERT INTO domains (name, type) VALUES ('Mixed.Test', 'NATIVE')"
rid2=$(q "SELECT id FROM domains WHERE name = 'Mixed.Test'")
q "INSERT INTO records (domain_id, name, type, content, ttl, disabled) VALUES ($rid2, 'Mixed.Test', 'SOA', 'ns1.Mixed.Test hostmaster.Mixed.Test 1 7200 3600 1209600 300', 300, 0), ($rid2, 'Mixed.Test', 'NS', 'ns1.Mixed.Test', 300, 0)"
rm -rf "$T/hd"
expect "--all with a zone named in mixed case" 0 export --all --dir "$T/hd"
[ -f "$T/hd/Mixed.Test.zone" ] && ok "...the file name keeps the case" || bad "...no Mixed.Test.zone" "$(ls "$T/hd")"

# ================================================================ 7. the round trip
echo "== round trip"
# the rows of a database without their ids: what two importers must make the same
rowdump() {
    sqlite3 "$1" "SELECT 'D', name, type FROM domains ORDER BY name;
        SELECT 'R', name, type, content, ttl, prio, disabled, auth, ordername FROM records ORDER BY name, type, content, ttl, prio;
        SELECT 'M', kind, content FROM domainmetadata ORDER BY kind, content;
        SELECT 'G', kind, tag, cidr FROM karidns_zone_tagdefs ORDER BY id;
        SELECT 'T', r.name, r.type, r.content, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id ORDER BY 2, 3, 4, 5, 6;
        SELECT 'N', r.name, r.type, r.content, t.ttd, t.loc, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id ORDER BY 2, 3, 4, 5, 6"
}
Z2S=$ROOT/tests/db/zone2sql
rt() {      # rt NAME APEX FILE [bind|tinydns] [dump|nodump]: file -> import -> export -> import -> export
    name=$1; apex=$2; file=$3; fmt=${4:-bind}; dump=${5:-dump}
    DB=$T/rt_$name.db; newdb "$DB"
    ext=zone; [ "$fmt" = tinydns ] && ext=tinydns
    if ! "$ZONE" import --no-config --sqlite3 "$DB" --format "$fmt" "$apex" "$file" > "$OUT" 2> "$ERR" < /dev/null; then bad "$name: import" "$(cat "$ERR")"; return; fi
    if [ -x "$Z2S" ]; then       # the rows are those of tests/db/zone2sql (the SQL it prints, loaded with sqlite3)
        z2a="--dialect sqlite3"; [ "$fmt" = tinydns ] && z2a="$z2a --format tinydns"
        if "$Z2S" $z2a "$file" > "$T/z2s.sql" 2> /dev/null; then
            sdb=$T/z2s_$name.db; newdb "$sdb"; sqlite3 "$sdb" < "$T/z2s.sql" > /dev/null 2>&1
            rowdump "$sdb" > "$T/rows.z2s"; rowdump "$DB" > "$T/rows.kz"
            if cmp -s "$T/rows.z2s" "$T/rows.kz" && [ -s "$T/rows.kz" ]; then ok "$name: karidns-zone writes the rows zone2sql prints ($(wc -l < "$T/rows.kz" | tr -d ' ') rows)"
            else bad "$name: the rows differ from zone2sql's" "$(diff "$T/rows.z2s" "$T/rows.kz" | head -6)"; fi
        fi
    fi
    if ! "$ZONE" export --no-config --sqlite3 "$DB" "$apex" "$T/rt1.$ext" > "$OUT" 2> "$ERR" < /dev/null; then bad "$name: export" "$(cat "$ERR")"; return; fi
    if ! "$ZONE" import --no-config --sqlite3 "$DB" --serial keep "$apex" "$T/rt1.$ext" > "$OUT" 2> "$ERR" < /dev/null; then bad "$name: import of the export" "$(cat "$ERR")"; return; fi
    if ! "$ZONE" export --no-config --sqlite3 "$DB" --force "$apex" "$T/rt2.$ext" > "$OUT" 2> "$ERR" < /dev/null; then bad "$name: second export" "$(cat "$ERR")"; return; fi
    if cmp -s "$T/rt1.$ext" "$T/rt2.$ext"; then ok "$name: file -> import -> export -> import -> export: the two exports are byte for byte the same ($(wc -l < "$T/rt1.$ext" | tr -d ' ') lines)"
    else bad "$name: the two exports differ" "$(diff "$T/rt1.$ext" "$T/rt2.$ext" | head -6)"; fi
    if [ "$dump" = dump ] && [ -x "$TZT" ]; then
        "$TZT" --dump "$apex" "$file" > "$T/rt.dump" 2> "$T/rt.dumperr"
        if cmp -s "$T/rt.dump" "$T/rt1.$ext"; then ok "$name: the records are those of the original file"
        else bad "$name: the export is not the original zone (test_zone_text --dump)" "$(diff "$T/rt.dump" "$T/rt1.$ext" | head -6; head -2 "$T/rt.dumperr")"; fi
    fi
    rm -f "$T/rt1.$ext" "$T/rt2.$ext"
}
cat > "$T/gen.zone" <<'EOF'
$ORIGIN gen.test.
$TTL 600
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
$GENERATE 1-5 host-$ A 10.0.0.$
$GENERATE 1-3 wide-${0,4,d} CNAME host-1
EOF
cat > "$T/flat.zone" <<'EOF'
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
@ IN MX 10 ns1
host.sub IN A 192.0.2.3
after IN A 192.0.2.4
EOF
rt signed_nsec3 example.com tests/zones/example.com.zone bind nodump
rt signed_nsec nsec.example tests/zones/nsec.zone
rt signed_nsec_test nsec.test tests/matrix/zones/nsec_signed.zone
rt tags tagz.test tests/db/tagz.test.zone
rt tinydns tdz.test tests/db/tdz.test.data tinydns
rt generate gen.test "$T/gen.zone"
rt include example.com tests/include_tests/valid_parent.zone bind nodump
rt all_types alltypes.test tests/matrix/zones/all_types.zone
rt delegation deleg.test tests/matrix/zones/deleg.zone
rt wildcard wildcard.test tests/matrix/zones/wildcard.zone
rt dname dname.test tests/matrix/zones/dname.zone
rt cname_chain chain.test tests/matrix/zones/cname_chain.zone
rt ttl_harmonize harmonize.test tests/zones/ttl_harmonize_basic.zone
cat > "$T/al.zone" <<'EOF2'
$ORIGIN alias.test.
$TTL 300
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
@ IN ALIAS lb.target.test.
a 120 IN ALIAS T.Target.Test.
r IN alias rel
both IN ALIAS t.target.test.
both IN TXT "hello"
l IN LUA A ";return {'192.0.2.1'}"
l2 IN LUA TXT "a" "b"
*.w IN ALIAS t.target.test.
EOF2
rt alias_lua alias.test "$T/al.zone"
# a zone with an included file of more than 64 KiB, and one whose included file is missing
mkdir "$T/big"
awk 'BEGIN { for (i = 1; i <= 6000; i++) printf "host-%05d IN A 10.%d.%d.%d\n", i, int(i / 65536) % 256, int(i / 256) % 256, i % 256 }' > "$T/big/hosts.inc"
printf '$ORIGIN big.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n$INCLUDE hosts.inc\n' > "$T/big/big.zone"
rt big_include big.test "$T/big/big.zone" bind nodump
DB=$T/rt_big_include.db
same "big_include: all 6003 records are in the database" "$(nrec big.test)" 6003
printf '$ORIGIN gone.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n$INCLUDE missing.inc\n' > "$T/big/gone.zone"
kz import gone.test "$T/big/gone.zone"
[ "$st" = 1 ] && grep -q "INCLUDE" "$ERR" && ok "a missing \$INCLUDE file is an error that names it" || bad "missing include: exit status $st" "$(cat "$ERR")"

# the $INCLUDE zone is the flat zone
DB=$T/rt_flat.db; newdb "$DB"
"$ZONE" import --no-config --sqlite3 "$DB" example.com "$T/flat.zone" > /dev/null 2>&1 && "$ZONE" export --no-config --sqlite3 "$DB" example.com "$T/flat.out" > /dev/null 2>&1
DB=$T/rt_include.db
"$ZONE" export --no-config --sqlite3 "$DB" example.com "$T/inc.out" > /dev/null 2>&1
cmp -s "$T/flat.out" "$T/inc.out" && ok "include: the zone with \$INCLUDE is the zone with the files written in" || bad "include: differs from the flat zone" "$(diff "$T/flat.out" "$T/inc.out" | head -6)"
[ -x "$TZT" ] && "$TZT" --dump example.com "$T/flat.zone" > "$T/flat.dump" 2>/dev/null && { cmp -s "$T/flat.dump" "$T/flat.out" && ok "include: the records are those of the original (flat copy)" || bad "include: not the original records" "$(diff "$T/flat.dump" "$T/flat.out" | head -6)"; }
# the signed zone, once more: the same RRSIG / NSEC3 records come back
DB=$T/rt_signed_nsec3.db
sig=$(q "SELECT count(*) FROM records WHERE type = 'RRSIG'")
"$ZONE" export --no-config --sqlite3 "$DB" example.com > "$T/sig.out" 2>/dev/null
[ "$sig" -gt 0 ] && [ "$(grep -c ' RRSIG ' "$T/sig.out")" -gt 0 ] && ok "signed_nsec3: the signatures are in the database and in the export" || bad "signed_nsec3: no RRSIG ($sig in the database)"
grep -q ' NSEC3PARAM ' "$T/sig.out" && ok "signed_nsec3: NSEC3PARAM is in the export (the file alone can serve the zone)" || bad "signed_nsec3: no NSEC3PARAM in the export"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_karidns_zone_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_karidns_zone_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
