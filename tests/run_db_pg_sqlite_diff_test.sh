#!/bin/sh
# run_db_pg_sqlite_diff_test.sh - GATE of milestone B10: the PostgreSQL driver and the SQLite3 driver give the same result
# (beta design 8.4, 9: "PostgreSQL vs SQLite3 = 0").
#
# The same SQL goes into a SQLite3 database and into a PostgreSQL schema (tests/db/zone2sql --dialect sqlite3 / pgsql; the
# zone files of tests/zones/, the tags zone, a tinydns data file, signed zones, and a hand written fixture with ALIAS and LUA
# rows, NULL ttl / prio / disabled, ENT rows, a second SOA, metadata and a profile, karidns_domain_views, a SLAVE zone, a
# zone with cryptokeys, a bad row).  For every round (a round holds each zone name once):
#   1. karidns-dbloader --dump of both, HELLO removed (it names the driver): the bytes must be identical; also with
#      --loader-threads 4, with --zone for every zone (the per-zone queries), and with --map-view for the fixture;
#   2. as root: two servers (A reads the SQLite3 file, B the PostgreSQL schema) answer every query of a generated list
#      (every owner x type, ANY, NXDOMAIN, plain / EDNS0 / DO) with the same bytes (message ID masked), and the AXFR of both
#      holds the same RRs.
# Zones the SQLite3 side cannot load (the reader refuses them) are compared as ZONE_FAILED messages: identical too.
#
# SKIP (exit 0, with the reason) when PostgreSQL is not reachable (KARIDNS_TEST_PG, tests/db/pg_lib.sh), the loader lacks a
# driver, a binary or the sqlite3 CLI is missing.  Part 1 runs as any user; part 2 needs root (the loader runs as another
# user; as root psql and the PostgreSQL loader run as the user pg_lib.sh picked).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-$ROOT/karidns-dbloader}
Z2S=$ROOT/tests/db/zone2sql
Z2K=$ROOT/tests/db/zone2kdb
KARIDNS=${KARIDNS:-./karidns}
for b in "$LOADER" "$Z2S" "$Z2K"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: karidns-dbloader has no PostgreSQL driver (make karidns-dbloader DB_DRIVERS=\"sqlite3 postgresql\")"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pgdiff.XXXXXX") || exit 1
chmod 755 "$T"
SA=""; SB=""
stop_servers() {
    [ -n "$SA" ] && kill -TERM "$SA" 2>/dev/null
    [ -n "$SB" ] && kill -TERM "$SB" 2>/dev/null
    i=0
    while [ $i -lt 50 ]; do
        { [ -z "$SA" ] || ! kill -0 "$SA" 2>/dev/null; } && { [ -z "$SB" ] || ! kill -0 "$SB" 2>/dev/null; } && break
        sleep 0.1; i=$((i + 1))
    done
    [ -n "$SA" ] && kill -KILL "$SA" 2>/dev/null
    [ -n "$SB" ] && kill -KILL "$SB" 2>/dev/null
    SA=""; SB=""
}
. "$ROOT/tests/db/pg_lib.sh"
cleanup() { stop_servers; pg_cleanup; if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi; }
trap cleanup EXIT INT TERM
pg_setup pgdiff || exit 0

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
TAB=$(printf '	')
SQ_SCHEMA=tests/db/pdns_schema.sqlite3.sql
PG_SCHEMA=tests/db/pdns_schema.pgsql.sql

pg_conninfo_file "$T/ci"
[ -n "$PG_AS" ] && { chown "$PG_AS" "$T/ci"; }

# ---------------------------------------------------------------- the hand written fixture (valid in both dialects)
cat > "$T/mix.sql" <<'EOF2'
INSERT INTO domains (id, name, type) VALUES (1, 'alias.test', 'NATIVE');
INSERT INTO domains (id, name, type) VALUES (2, 'views.test', 'MASTER');
INSERT INTO domains (id, name, type, master) VALUES (3, 'sec.test', 'SLAVE', '192.0.2.53');
INSERT INTO domains (id, name, type) VALUES (4, 'nullrows.test', 'NATIVE');
INSERT INTO domains (id, name, type) VALUES (5, 'badrow.test', 'NATIVE');
INSERT INTO domains (id, name, type) VALUES (6, 'keys.test', 'NATIVE');
INSERT INTO domains (id, name, type) VALUES (7, 'keys2.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES
 (1, 'alias.test', 'SOA', 'ns1.alias.test hostmaster.alias.test 5 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (1, 'alias.test', 'NS', 'ns1.alias.test', 3600, NULL, '0', NULL),
 (1, 'ns1.alias.test', 'A', '192.0.2.1', 3600, NULL, '0', NULL),
 (1, 'www.alias.test', 'ALIAS', 'target.example.test.', 300, NULL, '0', NULL),
 (1, 'lua.alias.test', 'LUA', 'A "return ''192.0.2.9''"', 300, NULL, '0', NULL),
 (1, 'plain.alias.test', 'A', '192.0.2.10', 300, NULL, '0', NULL);
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES
 (2, 'views.test', 'SOA', 'ns1.views.test hostmaster.views.test 7 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (2, 'views.test', 'NS', 'ns1.views.test', 3600, NULL, '0', NULL),
 (2, 'ns1.views.test', 'A', '192.0.2.2', 3600, NULL, '0', NULL),
 (2, 'views.test', 'MX', 'mail.views.test', 3600, 10, '0', NULL),
 (2, 'mail.views.test', 'AAAA', '2001:db8::25', 3600, NULL, '0', NULL),
 (2, 'views.test', 'TXT', '"v=spf1 -all" "second string"', 3600, NULL, '0', NULL),
 (2, 'srv.views.test', 'SRV', '0 5060 sip.views.test', 3600, 10, '0', NULL),
 (2, 'sip.views.test', 'A', '192.0.2.5', 3600, NULL, '0', NULL);
INSERT INTO domainmetadata (domain_id, kind, content) VALUES
 (2, 'ALLOW-AXFR-FROM', '192.0.2.0/24'), (2, 'ALSO-NOTIFY', '192.0.2.8'), (2, 'X-KARIDNS-PROFILE', 'gold'), (2, 'SOA-EDIT-API', 'DEFAULT');
INSERT INTO karidns_profiles (name, settings) VALUES ('gold', 'also-notify { 192.0.2.7; };'), ('Bronze', 'also-notify { 192.0.2.6; };');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES
 (4, 'nullrows.test', 'SOA', 'ns1.nullrows.test hostmaster.nullrows.test 3 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (4, 'nullrows.test', 'SOA', 'ns2.nullrows.test hostmaster.nullrows.test 3 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (4, 'nullrows.test', 'NS', 'ns1.nullrows.test', NULL, NULL, '0', NULL),
 (4, 'ns1.nullrows.test', 'A', '192.0.2.3', NULL, NULL, '0', NULL),
 (4, 'mx5.nullrows.test', 'MX', 'mail.nullrows.test', 300, 5, '0', NULL),
 (4, 'mxc.nullrows.test', 'MX', '15 mail.nullrows.test', 300, NULL, '0', NULL),
 (4, 'mail.nullrows.test', 'A', '192.0.2.4', 300, NULL, NULL, NULL),
 (4, 'off.nullrows.test', 'A', '192.0.2.11', 300, NULL, '1', NULL),
 (4, 'ent.nullrows.test', NULL, NULL, NULL, NULL, '0', 'ent'),
 (4, 'a.ent.nullrows.test', 'A', '192.0.2.12', 300, NULL, '0', NULL),
 (4, 'q.nullrows.test', 'TXT', '"say \"hi\""', 300, NULL, '0', NULL);
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES
 (5, 'badrow.test', 'SOA', 'ns1.badrow.test hostmaster.badrow.test 1 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (5, 'badrow.test', 'NS', 'ns1.badrow.test', 3600, NULL, '0', NULL),
 (5, 'bad.badrow.test', 'A', 'not-an-address', 3600, NULL, '0', NULL);
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES
 (6, 'keys.test', 'SOA', 'ns1.keys.test hostmaster.keys.test 1 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (6, 'keys.test', 'NS', 'ns1.keys.test', 3600, NULL, '0', NULL),
 (7, 'keys2.test', 'SOA', 'ns1.keys2.test hostmaster.keys2.test 1 7200 3600 1209600 300', 3600, NULL, '0', NULL),
 (7, 'keys2.test', 'NS', 'ns1.keys2.test', 3600, NULL, '0', NULL);
INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (6, 257, '1', 'x'), (7, 257, '1', 'y');
INSERT INTO domainmetadata (domain_id, kind, content) VALUES (7, 'PRESIGNED', '1');
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'internal'), (2, 'internal'), (2, 'external'), (4, 'external');
INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (2, 'location', 'tokyo', '192.0.2.0/24'), (2, 'location', 'osaka', '192.0.2.0/25');
EOF2

# ---------------------------------------------------------------- candidate zone files
echo "== candidate zone files"
mkdir "$T/sql" "$T/cand"
: > "$T/cand.list"      # apex <TAB> file <TAB> format
: > "$T/skipped.txt"
N=0
cat > "$T/cand/mixed.test.zone" <<'EOF2'
$ORIGIN mixed.test.
$TTL 300
@ SOA ns1 host 1 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
WWW A 192.0.2.2
Mail.Sub A 192.0.2.3
@ MX 10 Mail.Sub
EOF2
for f in tests/zones/*.zone tests/db/tagz.test.zone "$T/cand/mixed.test.zone"; do
    [ -f "$f" ] || continue
    N=$((N + 1))
    sz=$(wc -c < "$f" | tr -d ' ')
    if [ "$sz" -gt 300000 ]; then echo "$f: larger than 300 kB" >> "$T/skipped.txt"; continue; fi
    if ! "$Z2S" --dialect sqlite3 "$f" > "$T/sql/$N.sq.sql" 2> "$T/z2s.err" || ! "$Z2S" --dialect pgsql "$f" > "$T/sql/$N.pg.sql" 2> "$T/z2s.err"; then
        echo "$f: zone2sql cannot take it ($(head -1 "$T/z2s.err" | cut -c1-90))" >> "$T/skipped.txt"; continue
    fi
    rm -f "$T/scratch.db"
    sqlite3 "$T/scratch.db" < "$SQ_SCHEMA" > /dev/null
    sqlite3 "$T/scratch.db" < db/karidns_ext.sqlite3.sql > /dev/null
    sqlite3 "$T/scratch.db" < "$T/sql/$N.sq.sql" > /dev/null 2>&1 || { echo "$f: the SQL does not import" >> "$T/skipped.txt"; continue; }
    ND=$(sqlite3 "$T/scratch.db" "SELECT count(*) FROM domains")
    APEX=$(sqlite3 "$T/scratch.db" "SELECT name FROM domains LIMIT 1")
    if [ "$ND" != "1" ] || [ -z "$APEX" ]; then echo "$f: $ND domains in the import" >> "$T/skipped.txt"; continue; fi
    printf '%s\t%s\t%s\n' "$APEX" "$f" "$N" >> "$T/cand.list"
done
# a tinydns data file (several zones in one file) goes into a round of its own
TDF=tests/db/tdz.test.data
TDN=""
if [ -f "$TDF" ] && "$Z2S" --dialect sqlite3 --format tinydns "$TDF" > "$T/sql/td.sq.sql" 2> "$T/z2s.err" && "$Z2S" --dialect pgsql --format tinydns "$TDF" > "$T/sql/td.pg.sql" 2> "$T/z2s.err"; then
    TDN=1
else
    echo "$TDF: zone2sql cannot take it" >> "$T/skipped.txt"
fi
NC=$(wc -l < "$T/cand.list" | tr -d ' ')
echo "  $NC of $N zone files are candidates${TDN:+, plus a tinydns data file}"

: > "$T/rounds.txt"
R=0
while IFS="$TAB" read -r apex f n; do
    k=1
    while [ $k -le $R ] && grep -qx "$apex" "$T/round.$k.apex" 2>/dev/null; do k=$((k + 1)); done
    if [ $k -gt $R ]; then R=$k; : > "$T/round.$k.apex"; : > "$T/round.$k.list"; fi
    echo "$apex" >> "$T/round.$k.apex"
    printf '%s\t%s\t%s\n' "$apex" "$f" "$n" >> "$T/round.$k.list"
done < "$T/cand.list"
# the fixture and the tinydns file are rounds of their own: "mix" and "td"
R=$((R + 1)); MIXR=$R; : > "$T/round.$R.list"; echo "mix" > "$T/round.$R.kind"
if [ -n "$TDN" ]; then R=$((R + 1)); TDR=$R; : > "$T/round.$R.list"; echo "td" > "$T/round.$R.kind"; else TDR=0; fi
echo "  $R round(s)"

gen_queries() {   # gen_queries DB APEX: the query list on stdout
    db=$1; apex=$2
    id=$(sqlite3 "$db" "SELECT id FROM domains WHERE name = '$apex'")
    sqlite3 -separator ' ' "$db" "SELECT DISTINCT name, type FROM records WHERE domain_id = $id AND type IS NOT NULL AND disabled = 0 ORDER BY name, type" |
    awk -v apex="$apex" '
        { n[$1] = 1; t0 = $2; if (t0 == "ALIAS") t0 = "TYPE65401"; if (t0 == "LUA") t0 = "TYPE65402"; if (t0 !~ /^(A|NS|CNAME|SOA|PTR|HINFO|MINFO|MX|RP|AFSDB|RT|PX|KX|LP|TXT|AAAA|LOC|SRV|NAPTR|DNAME|DS|SSHFP|RRSIG|NSEC|DNSKEY|NSEC3|NSEC3PARAM|TLSA|CDS|CDNSKEY|ZONEMD|SVCB|HTTPS|URI|CAA|TYPE[0-9]+)$/) next; for (m = 1; m <= 3; m++) print $1 ". " t0 " " substr("ped", m, 1) }
        END {
            for (nm in n) {
                for (m = 1; m <= 3; m++) print nm ". ANY " substr("ped", m, 1)
                split("A AAAA MX TXT CNAME NS SOA TYPE65401 TYPE65402", ts, " ")
                for (t = 1; t <= 9; t++) print nm ". " ts[t] " e"
                print "zzz-probe." nm ". A e"
                print "zzz-probe." nm ". A d"
                print "deeper.zzz-probe." nm ". TXT p"
            }
            split("SOA NS MX TXT AAAA A DNSKEY DS NSEC NSEC3PARAM CAA ZONEMD SRV", at, " ")
            for (t = 1; t <= 13; t++) for (m = 1; m <= 3; m++) print apex ". " at[t] " " substr("ped", m, 1)
            for (m = 1; m <= 3; m++) {
                print "nxd-probe." apex ". A " substr("ped", m, 1)
                print "a.b.c.nxd-probe." apex ". TXT " substr("ped", m, 1)
            }
            print toupper("www." apex) ". A e"
            print toupper(apex) ". SOA d"
        }' | head -20000
}

compare() {   # compare A.out B.out: prints "total identical mismatch"; the first mismatches on stderr
    awk -F'\t' '
        NR == FNR { k[FNR] = $1; s[FNR] = $2; next }
        { total++
          if ($1 != k[FNR]) { bad++; if (bad <= 5) print "         query list mismatch at " FNR > "/dev/stderr"; next }
          if ($2 == s[FNR]) ident++
          else { bad++; if (bad <= 5) print "         DIFFERENT: " $1 > "/dev/stderr" } }
        END { printf "%d %d %d\n", total, ident, bad }' "$1" "$2"
}

rcode_of() {
    h=$(head -1 "$1" 2>/dev/null | cut -f2)
    if [ -z "$h" ] || [ "$h" = "TIMEOUT" ]; then echo "-1 0"; return; fi
    printf '%d %d\n' "0x$(printf '%s' "$h" | cut -c8)" "0x$(printf '%s' "$h" | cut -c13-16)"
}

# ---------------------------------------------------------------- servers need root
SERVERS=1
if [ "$(id -u)" != "0" ]; then SERVERS=0; echo "  (not root: the dumps are compared, the servers are not started)"; fi
if [ $SERVERS -eq 1 ]; then
    [ -x "$KARIDNS" ] && [ -x ./dag ] || { SERVERS=0; echo "  (karidns or dag is not built: the servers are not started)"; }
    command -v cc >/dev/null 2>&1 || { SERVERS=0; echo "  (no C compiler for tests/db/dbquery.c: the servers are not started)"; }
    id nobody >/dev/null 2>&1 || { SERVERS=0; echo "  (no user nobody: the servers are not started)"; }
    [ -n "$PG_AS" ] || { SERVERS=0; echo "  (no unprivileged PostgreSQL user: the servers are not started)"; }
fi
if [ $SERVERS -eq 1 ]; then
    if cc -O1 -o "$T/dbquery" tests/db/dbquery.c 2> "$T/cc.log"; then
        install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    else SERVERS=0; echo "  (tests/db/dbquery.c does not compile: the servers are not started)"; fi
fi
BASE=$((20000 + $$ % 20000)); PA=$BASE; PB=$((BASE + 1))

wait_log() {   # wait_log LOG PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -Eq -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

dumpcmp() {   # dumpcmp DESCRIPTION A.kdb B.kdb
    "$Z2K" --strip-hello "$2" "$T/cmp.a" && "$Z2K" --strip-hello "$3" "$T/cmp.b" || { fail "$1: not a KDB1 stream"; return 1; }
    if cmp -s "$T/cmp.a" "$T/cmp.b"; then pass "$1 ($(wc -c < "$T/cmp.a" | tr -d ' ') bytes)"; return 0; fi
    fail "$1: the streams differ"
    "$Z2K" --compare "$2" "$3" | head -3 | sed 's/^/         /'
    return 1
}

TOTAL_Q=0; TOTAL_OK=0; COMPARED=0; NSTREAM=0
k=1
while [ $k -le $R ]; do
    D="$T/r$k"; mkdir "$D"; chmod 777 "$D"
    kind=$(cat "$T/round.$k.kind" 2>/dev/null || echo files)
    SCH="karidns_test_r$k"
    echo "== round $k ($kind)"
    # ---- SQLite3
    sqlite3 "$D/z.db" < "$SQ_SCHEMA" > /dev/null
    sqlite3 "$D/z.db" < db/karidns_ext.sqlite3.sql > /dev/null
    { printf 'CREATE SCHEMA %s;\nSET search_path TO %s;\n' "$SCH" "$SCH"; cat "$PG_SCHEMA" db/karidns_ext.pgsql.sql; } > "$D/pg.sql"
    case $kind in
    mix)  sqlite3 "$D/z.db" < "$T/mix.sql" > /dev/null 2> "$D/sq.err" || { fail "round $k: the fixture does not import into SQLite3"; head -3 "$D/sq.err"; }
          cat "$T/mix.sql" >> "$D/pg.sql" ;;
    td)   sqlite3 "$D/z.db" < "$T/sql/td.sq.sql" > /dev/null 2> "$D/sq.err" || fail "round $k: the tinydns SQL does not import into SQLite3"
          cat "$T/sql/td.pg.sql" >> "$D/pg.sql" ;;
    *)    while IFS="$TAB" read -r apex f n; do
              sqlite3 "$D/z.db" < "$T/sql/$n.sq.sql" > /dev/null 2>&1
              cat "$T/sql/$n.pg.sql" >> "$D/pg.sql"
          done < "$T/round.$k.list" ;;
    esac
    # the same ALLOW-AXFR-FROM for every zone (the AXFR comparison below), in both
    ACL="INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE id NOT IN (SELECT domain_id FROM domainmetadata WHERE kind = 'ALLOW-AXFR-FROM');"
    sqlite3 "$D/z.db" "$ACL" > /dev/null
    printf '%s\n' "$ACL" >> "$D/pg.sql"
    # ---- PostgreSQL
    if ! pf "$D/pg.sql" > "$D/pg.out" 2>&1; then fail "round $k: the SQL does not import into PostgreSQL"; head -5 "$D/pg.out" | sed 's/^/         /'; k=$((k + 1)); continue; fi
    ND=$(sqlite3 "$D/z.db" "SELECT count(*) FROM domains")
    NDP=$(pq "SELECT count(*) FROM $SCH.domains")
    [ "$ND" = "$NDP" ] && pass "$ND domains in both" || fail "round $k: $ND domains in SQLite3, $NDP in PostgreSQL"
    # ---- dumps
    "$LOADER" --dump "$D/sq.kdb" --driver sqlite3 --database-file "$D/z.db" 2> "$D/sq.dump.err"; rs=$?
    as_pg "$PGLOADER" --dump "$D/pg.kdb" --driver postgresql --conninfo-file "$T/ci" --schema "$SCH" 2> "$D/pg.dump.err"; rp=$?
    if [ "$rs" != "$rp" ]; then fail "round $k: exit status SQLite3 $rs, PostgreSQL $rp"; head -3 "$D/pg.dump.err" | sed 's/^/         /'; fi
    if [ "$rs" -ge 2 ] || [ "$rp" -ge 2 ]; then fail "round $k: a dump failed (SQLite3 $rs, PostgreSQL $rp)"; head -3 "$D/pg.dump.err" | sed 's/^/         /'; k=$((k + 1)); continue; fi
    dumpcmp "round $k: the dump of PostgreSQL equals the dump of SQLite3" "$D/sq.kdb" "$D/pg.kdb" && NSTREAM=$((NSTREAM + 1))
    diff "$D/sq.dump.err" "$D/pg.dump.err" > /dev/null 2>&1 && pass "the loader says the same about the rows (stderr identical)" || { fail "stderr of the dumps differs"; diff "$D/sq.dump.err" "$D/pg.dump.err" | head -6 | sed 's/^/         /'; }
    if [ $k -eq 1 ]; then       # the PostgreSQL example of --help runs (the test's paths and schema in it) and writes the stream just made
        ex=$("$LOADER" --help | sed -n '/^examples:/,$p' | grep '^  karidns-dbloader --dump .*--driver postgresql' | head -1)
        cmd=$(printf '%s\n' "$ex" | sed -e "s#^  karidns-dbloader#as_pg $PGLOADER#" -e "s#/tmp/zones.kdb#$D/ex.kdb#" -e "s#/usr/local/etc/karidns/database.conf#$T/ci#" -e "s#--schema pdns#--schema $SCH#")
        if [ -n "$ex" ] && eval "$cmd" 2> "$D/ex.err" && cmp -s "$D/ex.kdb" "$D/pg.kdb"; then pass "the PostgreSQL example of --help runs and writes the same stream"
        else fail "the PostgreSQL example of --help: $ex"; head -3 "$D/ex.err" | sed 's/^/         /'; fi
    fi
    as_pg "$PGLOADER" --dump "$D/pg4.kdb" --driver postgresql --conninfo-file "$T/ci" --schema "$SCH" --loader-threads 4 2> /dev/null
    dumpcmp "round $k: --loader-threads 4 gives the same bytes" "$D/sq.kdb" "$D/pg4.kdb"
    # the per-zone path: --zone NAME of both
    sqlite3 "$D/z.db" "SELECT name FROM domains ORDER BY id" > "$D/names.txt"
    NPER=0; NBAD=0
    while read -r zn; do
        "$LOADER" --dump "$D/s1.kdb" --driver sqlite3 --database-file "$D/z.db" --zone "$zn" 2> "$D/s1.err"; r1=$?
        as_pg "$PGLOADER" --dump "$D/p1.kdb" --driver postgresql --conninfo-file "$T/ci" --schema "$SCH" --zone "$zn" 2> "$D/p1.err"; r2=$?
        NPER=$((NPER + 1))
        if [ "$r1" != "$r2" ]; then NBAD=$((NBAD + 1)); echo "         zone $zn: exit SQLite3 $r1, PostgreSQL $r2"; continue; fi
        [ "$r1" -ge 2 ] && continue
        "$Z2K" --strip-hello "$D/s1.kdb" "$D/s1.x" && "$Z2K" --strip-hello "$D/p1.kdb" "$D/p1.x"
        cmp -s "$D/s1.x" "$D/p1.x" || { NBAD=$((NBAD + 1)); echo "         zone $zn: --zone streams differ"; }
    done < "$D/names.txt"
    [ "$NBAD" -eq 0 ] && pass "round $k: $NPER zones: --zone is the same in both" || fail "round $k: $NBAD of $NPER zones differ with --zone"
    if [ "$kind" = mix ]; then
        for mv in internal external nothere; do
            "$LOADER" --dump "$D/sqm.kdb" --driver sqlite3 --database-file "$D/z.db" --map-view $mv 2> /dev/null; r1=$?
            as_pg "$PGLOADER" --dump "$D/pgm.kdb" --driver postgresql --conninfo-file "$T/ci" --schema "$SCH" --map-view $mv 2> /dev/null; r2=$?
            [ "$r1" = "$r2" ] && dumpcmp "--map-view $mv: the same bytes (exit $r1)" "$D/sqm.kdb" "$D/pgm.kdb" || fail "--map-view $mv: exit SQLite3 $r1, PostgreSQL $r2"
        done
        # the fixture really exercises the interesting rows: the stream has the zones, ZONE_FAILED for the bad ones
        grep -q "zone .badrow.test" "$D/pg.dump.err" && pass "the bad row is reported (ZONE_FAILED) in the PostgreSQL dump too" || fail "no report about the bad row"
        grep -q "keys.test" "$D/pg.dump.err" && pass "cryptokeys without PRESIGNED fail the zone with PostgreSQL's column privilege path as well" || fail "no report about cryptokeys"
        [ "$("$Z2K" --extract "$D/pg.kdb" views.test | wc -c | tr -d ' ')" -gt 200 ] && pass "views.test (metadata, profile) is in the PostgreSQL stream" || fail "views.test missing from the PostgreSQL stream"
    fi
    # ---- servers (root)
    if [ $SERVERS -eq 1 ]; then
        chown -R nobody "$D"; chmod 600 "$D/z.db"*
        {
            printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n' "$PA"
            printf '    database { driver sqlite3; database-file "%s/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; acl-ceiling { 127.0.0.1; }; };\n};\n' "$D" "$T"
        } > "$D/a.conf"
        {
            printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n' "$PB"
            printf '    database { driver postgresql; conninfo-file "%s/ci"; schema "%s"; loader-user "%s"; loader-path "%s/karidns-dbloader"; acl-ceiling { 127.0.0.1; }; };\n};\n' "$T" "$SCH" "$PG_AS" "$T"
        } > "$D/b.conf"
        "$KARIDNS" -c "$D/a.conf" -f > "$D/a.log" 2>&1 &
        SA=$!
        "$KARIDNS" -c "$D/b.conf" -f > "$D/b.log" 2>&1 &
        SB=$!
        if ! wait_log "$D/a.log" "\[DB\] initial load complete" 30 || ! wait_log "$D/b.log" "\[DB\] initial load complete" 30; then
            fail "round $k: a database server did not finish its startup batch"; tail -5 "$D/b.log" | sed 's/^/         /'; stop_servers; k=$((k + 1)); continue
        fi
        sleep 0.5
        while read -r apex; do
            printf '%s. SOA p\n' "$apex" > "$D/soa.list"
            "$T/dbquery" -p "$PA" -t 3 "$D/soa.list" "$D/soa.a" > /dev/null 2>&1
            "$T/dbquery" -p "$PB" -t 3 "$D/soa.list" "$D/soa.b" > /dev/null 2>&1
            set -- $(rcode_of "$D/soa.a"); ra=${1:--1}; aa=${2:-0}
            set -- $(rcode_of "$D/soa.b"); rb=${1:--1}; ab=${2:-0}
            if [ "$ra" != "$rb" ] || [ "$aa" != "$ab" ]; then fail "$apex: SQLite3 server rcode $ra/$aa answers, PostgreSQL server rcode $rb/$ab"; continue; fi
            if [ "$ra" != "0" ] || [ "$aa" = "0" ]; then continue; fi          # served by neither (a failed zone): equal, nothing more to ask
            gen_queries "$D/z.db" "$apex" > "$D/q.list"
            NQ=$(wc -l < "$D/q.list" | tr -d ' ')
            [ "$NQ" -gt 0 ] || continue
            "$T/dbquery" -p "$PA" -t 3 "$D/q.list" "$D/q.a" > /dev/null 2>&1
            "$T/dbquery" -p "$PB" -t 3 "$D/q.list" "$D/q.b" > /dev/null 2>&1
            set -- $(compare "$D/q.a" "$D/q.b" 2> "$D/cmp.err"); tot=$1; idn=$2; bad=$3
            COMPARED=$((COMPARED + 1)); TOTAL_Q=$((TOTAL_Q + tot)); TOTAL_OK=$((TOTAL_OK + idn))
            if [ "$bad" = "0" ] && [ "$tot" = "$NQ" ]; then pass "$apex: $tot queries, all byte-identical"
            else fail "$apex: $bad of $tot queries differ (list had $NQ)"; cat "$D/cmp.err"; fi
            ./dag @127.0.0.1 -p "$PA" "$apex" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$D/axfr.a"
            ./dag @127.0.0.1 -p "$PB" "$apex" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$D/axfr.b"
            if [ "$(wc -l < "$D/axfr.a" | tr -d ' ')" -ge 2 ] && cmp -s "$D/axfr.a" "$D/axfr.b"; then pass "$apex: AXFR is the same set of $(wc -l < "$D/axfr.a" | tr -d ' ') RRs"
            else fail "$apex: AXFR differs ($(wc -l < "$D/axfr.a" | tr -d ' ') vs $(wc -l < "$D/axfr.b" | tr -d ' ') lines)"; diff "$D/axfr.a" "$D/axfr.b" | head -4 | sed 's/^/         /'; fi
        done < "$D/names.txt"
        stop_servers
    fi
    k=$((k + 1))
done

echo
echo "== skipped zone files (not compared)"
sed 's/^/  /' "$T/skipped.txt"
echo
echo "$NSTREAM round dumps identical; $COMPARED zones compared by server, $TOTAL_Q queries, $TOTAL_OK byte-identical"
[ "$NSTREAM" -ge 3 ] && pass "at least 3 rounds compared ($NSTREAM)" || fail "only $NSTREAM rounds could be compared"
if [ $SERVERS -eq 1 ]; then [ "$COMPARED" -ge 8 ] && pass "at least 8 zones compared by server ($COMPARED)" || fail "only $COMPARED zones compared by server (8 needed)"; fi
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_pg_sqlite_diff_test: all $PASS checks passed (PostgreSQL vs SQLite3 = 0 differences) ==="; exit 0; fi
echo "=== run_db_pg_sqlite_diff_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
