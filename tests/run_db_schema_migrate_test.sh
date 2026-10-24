#!/bin/sh
# run_db_schema_migrate_test.sh - the extension schema version 2 and the migration from version 1 (milestone B10).
#
# Version 2 adds karidns_zone_tagdefs.id (the order of the definitions of a zone, the first match wins) and, on PostgreSQL,
# karidns_changes.xid (xid8, the writing transaction).  db/karidns_ext_v1_to_v2.{sqlite3,pgsql}.sql convert a database;
# karidns-dbloader reads both versions.  Version 1 is made here from the version 2 file (the lines of version 2 removed).
#
# SQLite3 (sqlite3 CLI and a loader with the driver; SKIP otherwise): a version 1 database with tag definitions of two zones
# inserted interleaved; the dump of it; after the migration (applied twice) the table has ids in the old order, the version
# row is 2 (one row), the three triggers of the table are back and log, integrity_check is ok, and the dump has the same bytes;
# applying the version 2 file to the migrated database changes nothing; a version 3 database is refused by the loader.
# PostgreSQL (psql, a reachable server, a loader with the driver; SKIP otherwise, with the reason): the same on a version 1
# database (no xid: the loader serves it without a change log, the dump is the same as SQLite3's), the migration (applied
# twice) gives xid 0 to the old log rows and the transaction's xid to new ones, ids in the old order, and the same dump bytes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-$ROOT/karidns-dbloader}
Z2S=$ROOT/tests/db/zone2sql
Z2K=$ROOT/tests/db/zone2kdb
for b in "$LOADER" "$Z2S" "$Z2K"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_migrate.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
cleanup() { pg_cleanup; rm -rf "$T"; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0; SKIPS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
skip() { SKIPS=$((SKIPS + 1)); echo "  [SKIP] $1"; }

# the version 1 files: version 2 without its additions
perl -ne 'next if /schema version 2: the order of the definitions/; next if /^CREATE INDEX IF NOT EXISTS karidns_changes_xid_idx/; s/ SET search_path FROM CURRENT//; s/SELECT 2 WHERE/SELECT 1 WHERE/; s/^(  changed_at BIGINT NOT NULL),$/$1/; next if /^  xid        xid8/; print' db/karidns_ext.pgsql.sql > "$T/v1.pgsql.sql"
perl -ne 'next if /schema version 2: the order of the definitions/; s/SELECT 2 WHERE/SELECT 1 WHERE/; print' db/karidns_ext.sqlite3.sql > "$T/v1.sqlite3.sql"
grep -q "xid8 NOT NULL" "$T/v1.pgsql.sql" && fail "the version 1 PostgreSQL file still has the xid column"
[ "$(grep -c "^  id        INTEGER PRIMARY KEY AUTOINCREMENT" "$T/v1.sqlite3.sql")" = "0" ] || fail "the version 1 SQLite file still has tagdefs.id"

# the data: a zone with tags and definitions, and a second zone with definitions (inserted interleaved below)
"$Z2S" --dialect sqlite3 tests/db/tagz.test.zone > "$T/tagz.sq.sql" 2>/dev/null || { echo "SKIP: zone2sql cannot read tests/db/tagz.test.zone"; exit 0; }
"$Z2S" --dialect pgsql tests/db/tagz.test.zone > "$T/tagz.pg.sql" 2>/dev/null
cat > "$T/more.sql" <<'EOF'
INSERT INTO domains (name, type) VALUES ('two.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
 ((SELECT id FROM domains WHERE name = 'two.test'), 'two.test', 'SOA', 'ns1.two.test hostmaster.two.test 1 7200 3600 1209600 300', 3600, NULL, '0'),
 ((SELECT id FROM domains WHERE name = 'two.test'), 'two.test', 'NS', 'ns1.two.test', 3600, NULL, '0'),
 ((SELECT id FROM domains WHERE name = 'two.test'), 'ns1.two.test', 'A', '192.0.2.2', 3600, NULL, '0'),
 ((SELECT id FROM domains WHERE name = 'two.test'), 'www.two.test', 'A', '192.0.2.3', 3600, NULL, '0');
INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES
 ((SELECT id FROM domains WHERE name = 'two.test'), 'location', 'zz-first', '192.0.2.0/24'),
 ((SELECT id FROM domains WHERE name = 'two.test'), 'location', 'aa-second', '192.0.2.0/25'),
 ((SELECT id FROM domains WHERE name = 'two.test'), 'ecs', 'mm-third', '198.51.100.0/24');
EOF

dump_cmp() {   # dump_cmp DESCRIPTION A.kdb B.kdb: equal after the HELLO (it names the driver)
    "$Z2K" --strip-hello "$2" "$T/c.a" && "$Z2K" --strip-hello "$3" "$T/c.b" && cmp -s "$T/c.a" "$T/c.b" && pass "$1" || fail "$1"
}

# ================================================================ SQLite3
echo "== SQLite3"
if ! command -v sqlite3 >/dev/null 2>&1; then skip "the sqlite3 command line tool is not installed"
elif ! "$LOADER" --drivers | grep -qx sqlite3; then skip "karidns-dbloader has no SQLite3 driver"
else
    DB=$T/s.db
    sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    sqlite3 "$DB" < "$T/v1.sqlite3.sql" > /dev/null || fail "the version 1 file does not apply"
    [ "$(sqlite3 "$DB" "SELECT version FROM karidns_schema_version")" = "1" ] && pass "version 1 database" || fail "version row"
    [ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('karidns_zone_tagdefs') WHERE name = 'id'")" = "0" ] && pass "v1: karidns_zone_tagdefs has no id" || fail "v1 has an id column"
    sqlite3 "$DB" < "$T/tagz.sq.sql" > /dev/null
    sqlite3 "$DB" < "$T/more.sql" > /dev/null
    sqlite3 "$DB" "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (1, 'location', 'interleaved', '203.0.113.0/24')" > /dev/null
    "$LOADER" --dump "$T/s1.kdb" --driver sqlite3 --database-file "$DB" 2> "$T/s1.err"; r=$?
    [ "$r" -eq 0 ] && pass "the loader reads a version 1 database (exit 0)" || { fail "dump of the version 1 database: exit $r"; head -3 "$T/s1.err"; }
    sqlite3 "$DB" "SELECT domain_id || ':' || tag FROM karidns_zone_tagdefs ORDER BY rowid" > "$T/order.before"
    NDEF=$(wc -l < "$T/order.before" | tr -d ' ')
    sqlite3 "$DB" < db/karidns_ext_v1_to_v2.sqlite3.sql > /dev/null 2> "$T/m1.err" && pass "the migration applies" || { fail "the migration: $(head -2 "$T/m1.err")"; }
    sqlite3 "$DB" < db/karidns_ext_v1_to_v2.sqlite3.sql > /dev/null 2> "$T/m2.err" && pass "the migration applies a second time" || { fail "second migration: $(head -2 "$T/m2.err")"; }
    [ "$(sqlite3 "$DB" "SELECT version FROM karidns_schema_version")" = "2" ] && [ "$(sqlite3 "$DB" "SELECT count(*) FROM karidns_schema_version")" = "1" ] && pass "version 2, one row" || fail "version row after the migration"
    [ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('karidns_zone_tagdefs') WHERE name = 'id' AND pk = 1")" = "1" ] && pass "karidns_zone_tagdefs.id is the primary key" || fail "id column"
    sqlite3 "$DB" "SELECT domain_id || ':' || tag FROM karidns_zone_tagdefs ORDER BY id" > "$T/order.after"
    cmp -s "$T/order.before" "$T/order.after" && pass "the $NDEF definitions are in the same order (by id)" || { fail "the order of the definitions changed"; diff "$T/order.before" "$T/order.after" | head -4; }
    [ "$(sqlite3 "$DB" "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'karidns_zone_tagdefs'")" = "3" ] && pass "the three triggers of the table are back" || fail "triggers of karidns_zone_tagdefs"
    [ "$(sqlite3 "$DB" "PRAGMA integrity_check")" = "ok" ] && pass "integrity_check ok" || fail "integrity_check"
    sqlite3 "$DB" "DELETE FROM karidns_changes"
    sqlite3 "$DB" "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (2, 'location', 'after', '203.0.113.0/25')" > /dev/null
    [ "$(sqlite3 "$DB" "SELECT group_concat(domain_id) FROM karidns_changes")" = "2" ] && pass "an INSERT into the new table is logged by its trigger" || fail "trigger after the migration"
    sqlite3 "$DB" "DELETE FROM karidns_zone_tagdefs WHERE tag = 'after'; DELETE FROM karidns_zone_tagdefs WHERE tag = 'interleaved'" > /dev/null
    "$LOADER" --dump "$T/s2.kdb" --driver sqlite3 --database-file "$DB" 2> "$T/s2.err"; r=$?
    [ "$r" -eq 0 ] && pass "the loader reads the migrated database" || fail "dump after the migration: exit $r"
    # the interleaved definition was deleted again: the dump equals the first one without it
    sqlite3 "$DB" "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (1, 'location', 'interleaved', '203.0.113.0/24')" > /dev/null
    "$LOADER" --dump "$T/s3.kdb" --driver sqlite3 --database-file "$DB" 2> /dev/null
    cmp -s "$T/s1.kdb" "$T/s3.kdb" && pass "the dump of the migrated database equals the dump of the version 1 database (byte for byte)" || fail "the dump changed with the migration"
    sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null 2>&1 && [ "$(sqlite3 "$DB" "SELECT version FROM karidns_schema_version")" = "2" ] && pass "the version 2 file applies to a migrated database (idempotent)" || fail "version 2 file on a migrated database"
    sqlite3 "$DB" "UPDATE karidns_schema_version SET version = 3" > /dev/null
    "$LOADER" --dump "$T/s4.kdb" --driver sqlite3 --database-file "$DB" 2> "$T/s4.err"; r=$?
    [ "$r" -eq 3 ] && grep -q "versions 1 and 2" "$T/s4.err" && pass "version 3 is refused (exit 3, 'versions 1 and 2')" || { fail "version 3: exit $r"; head -2 "$T/s4.err"; }
fi

# ================================================================ PostgreSQL
echo "== PostgreSQL"
if ! "$LOADER" --drivers | grep -qx postgresql; then skip "karidns-dbloader has no PostgreSQL driver"
elif ! command -v sqlite3 >/dev/null 2>&1 || [ ! -s "$T/s1.kdb" ]; then skip "the SQLite3 dump is the reference of this part and is not available"
else
    pg_setup migrate > "$T/pgsetup.out"; rc=$?
    if [ $rc -ne 0 ]; then skip "$(sed 's/^SKIP: //' "$T/pgsetup.out")"
    else
        cat "$T/pgsetup.out"
        pg_conninfo_file "$T/ci"
        pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf "$T/v1.pgsql.sql" > "$T/pg1.out" 2>&1 && pass "the version 1 PostgreSQL file applies" || { fail "the version 1 PostgreSQL file"; head -3 "$T/pg1.out"; }
        [ "$(pq "SELECT count(*) FROM information_schema.columns WHERE table_name = 'karidns_changes' AND column_name = 'xid'")" = "0" ] && pass "v1: no xid column" || fail "v1 has xid"
        pf "$T/tagz.pg.sql" > /dev/null && pf "$T/more.sql" > /dev/null
        pq "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (1, 'location', 'interleaved', '203.0.113.0/24')" > /dev/null
        chmod 777 "$T"
        as_pg "$PGLOADER" --dump "$T/p1.kdb" --driver postgresql --conninfo-file "$T/ci" 2> "$T/p1.err"; r=$?
        [ "$r" -eq 0 ] && pass "the loader reads a version 1 PostgreSQL database (no change log)" || { fail "dump of the version 1 database: exit $r"; head -3 "$T/p1.err"; }
        dump_cmp "the version 1 PostgreSQL dump equals the SQLite3 dump" "$T/s1.kdb" "$T/p1.kdb"
        pq "SELECT domain_id || ':' || tag FROM karidns_zone_tagdefs ORDER BY ctid" > "$T/porder.before"
        pq "SELECT count(*) FROM karidns_changes" > "$T/nchg"
        [ "$(pq "SELECT count(*) FROM pg_proc WHERE proname LIKE 'karidns\_%' AND pronamespace = current_schema()::regnamespace AND proconfig IS NULL")" -gt 0 ] && pass "v1: the karidns_* functions do not pin a search_path" || fail "v1 functions already pinned"
        pf db/karidns_ext_v1_to_v2.pgsql.sql > /dev/null 2> "$T/pm1.err" && pass "the migration applies" || { fail "the migration"; head -3 "$T/pm1.err"; }
        [ "$(pq "SELECT count(*) FROM pg_proc WHERE proname LIKE 'karidns\_%' AND pronamespace = current_schema()::regnamespace AND proconfig IS NULL")" = "0" ] && pass "the migration pinned the search_path of every karidns_* function" || fail "unpinned karidns_* functions after the migration"
        pf db/karidns_ext_v1_to_v2.pgsql.sql > /dev/null 2> "$T/pm2.err" && pass "the migration applies a second time" || { fail "second migration"; head -3 "$T/pm2.err"; }
        [ "$(pq "SELECT version FROM karidns_schema_version")" = "2" ] && [ "$(pq "SELECT count(*) FROM karidns_schema_version")" = "1" ] && pass "version 2, one row" || fail "version row"
        pq "SELECT domain_id || ':' || tag FROM karidns_zone_tagdefs ORDER BY id" > "$T/porder.after"
        cmp -s "$T/porder.before" "$T/porder.after" && pass "the definitions are in the same order (by id)" || { fail "the order of the definitions changed"; diff "$T/porder.before" "$T/porder.after" | head -4; }
        [ "$(pq "SELECT count(*) FROM karidns_changes WHERE xid = '0'::xid8")" = "$(cat "$T/nchg")" ] && pass "the $(cat "$T/nchg") old log rows have xid 0" || fail "old log rows: xid 0 count"
        pq "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (2, 'location', 'after', '203.0.113.0/25')" > /dev/null
        [ "$(pq "SELECT count(*) FROM karidns_changes WHERE xid <> '0'::xid8 AND domain_id = 2")" = "1" ] && pass "a new log row carries the xid of its transaction" || fail "xid of a new log row"
        [ "$(pq "SELECT pg_get_expr(adbin, adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum WHERE a.attrelid = 'karidns_changes'::regclass AND a.attname = 'xid'")" = "pg_current_xact_id()" ] && pass "xid DEFAULT pg_current_xact_id()" || fail "the default of xid"
        pq "DELETE FROM karidns_zone_tagdefs WHERE tag = 'after'" > /dev/null
        as_pg "$PGLOADER" --dump "$T/p2.kdb" --driver postgresql --conninfo-file "$T/ci" 2> "$T/p2.err"; r=$?
        [ "$r" -eq 0 ] && pass "the loader reads the migrated database" || { fail "dump after the migration: exit $r"; head -3 "$T/p2.err"; }
        cmp -s "$T/p1.kdb" "$T/p2.kdb" && pass "the dump of the migrated database equals the dump of the version 1 database (byte for byte)" || fail "the dump changed with the migration"
        pf db/karidns_ext.pgsql.sql > /dev/null 2>&1 && [ "$(pq "SELECT version FROM karidns_schema_version")" = "2" ] && pass "the version 2 file applies to a migrated database (idempotent)" || fail "version 2 file on a migrated database"
        pq "UPDATE karidns_schema_version SET version = 3" > /dev/null
        as_pg "$PGLOADER" --dump "$T/p4.kdb" --driver postgresql --conninfo-file "$T/ci" 2> "$T/p4.err"; r=$?
        [ "$r" -eq 3 ] && grep -q "versions 1 and 2" "$T/p4.err" && pass "version 3 is refused (exit 3, 'versions 1 and 2')" || { fail "version 3: exit $r"; head -2 "$T/p4.err"; }
    fi
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_schema_migrate_test: all $PASS checks passed ($SKIPS skipped) ==="; exit 0; fi
echo "=== run_db_schema_migrate_test: $FAILS check(s) FAILED ($PASS passed, $SKIPS skipped) ==="
exit 1
