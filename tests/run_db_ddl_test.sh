#!/bin/sh
# run_db_ddl_test.sh - the extension DDL db/karidns_ext.sqlite3.sql and db/karidns_ext.pgsql.sql (beta design 3.7, 5.1, 6;
# milestone B6a): the tables of design 3.7, schema version 1, and the change-log triggers that feed karidns-dbloader.
#
# SQLite3 (the sqlite3 CLI; SKIP without it): the ext file is applied twice (idempotent, one version row), every table has
# its INSERT / UPDATE / DELETE triggers, and each kind of edit writes the right (OLD and NEW) domain ids to
# karidns_changes: domains, records (also the move of a record to another domain), domainmetadata, cryptokeys,
# karidns_domain_views, karidns_zone_tagdefs, and, through the record, karidns_record_tags / karidns_record_tinydns.
# The prune trigger is tested on a small scale by replacing the retention 1000000 by 5.
#
# PostgreSQL (psql and a reachable server; SKIP otherwise, with the reason): in a temporary database, statement-level
# triggers write ONE row per distinct domain per statement (a million-row INSERT into one zone logs one row; a statement
# touching two zones logs two), UPDATE logs OLD and NEW ids, a cascade delete is logged, pg_notify('karidns_changes')
# reaches a LISTENing session, and the prune keeps the newest rows.  KARIDNS_TEST_PG is the conninfo of a maintenance
# database the role may create databases from (default: the local socket, database "postgres").  If the real PowerDNS
# schema file is found (PDNS_SCHEMA_PGSQL or /usr/local/share/doc/pdns/schema.pgsql.sql) the ext DDL is also applied to it.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

PASS=0; FAILS=0; SKIPS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
skip() { SKIPS=$((SKIPS + 1)); echo "  [SKIP] $1"; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_ddl.XXXXXX") || exit 1
PGDB=""
cleanup() {
    if [ -n "$PGDB" ]; then psql -X -q -d "${KARIDNS_TEST_PG:-postgres}" -c "DROP DATABASE IF EXISTS $PGDB" >/dev/null 2>&1; fi
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

# ================================================================ SQLite3
echo "== SQLite3"
if ! command -v sqlite3 >/dev/null 2>&1; then
    skip "the sqlite3 command line tool is not installed"
else
    SCHEMA=tests/db/pdns_schema.sqlite3.sql
    EXT=db/karidns_ext.sqlite3.sql
    DB=$T/ddl.db
    sq() { sqlite3 "$DB" "$@"; }
    chg() { sq "SELECT coalesce(group_concat(domain_id, ','), '') FROM (SELECT domain_id FROM karidns_changes ORDER BY seq)"; }
    reset() { sq "DELETE FROM karidns_changes"; }
    expect() {   # expect DESCRIPTION WANTED-LOG-OF-DOMAIN-IDS
        got=$(chg)
        [ "$got" = "$2" ] && pass "$1: $got" || fail "$1: logged '$got', wanted '$2'"
        reset
    }

    sq < "$SCHEMA" > /dev/null
    sq < "$EXT" || fail "the ext file does not apply"
    sq < "$EXT" || fail "the ext file does not apply a second time"
    [ "$(sq 'SELECT count(*) FROM karidns_schema_version')" = "1" ] && [ "$(sq 'SELECT version FROM karidns_schema_version')" = "1" ] &&
        pass "schema version 1, one row after two applications" || fail "karidns_schema_version"
    for t in karidns_schema_version karidns_changes karidns_domain_views karidns_profiles karidns_record_tags karidns_record_tinydns karidns_zone_tagdefs; do
        [ "$(sq "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '$t'")" = "1" ] && pass "table $t" || fail "table $t is missing"
    done
    # 8 tables with INSERT / UPDATE / DELETE triggers + the prune trigger
    [ "$(sq "SELECT count(*) FROM sqlite_master WHERE type = 'trigger'")" = "25" ] && pass "25 triggers (8 tables x 3 + prune)" ||
        fail "trigger count $(sq "SELECT count(*) FROM sqlite_master WHERE type = 'trigger'"), wanted 25"
    sq "PRAGMA foreign_keys = ON" > /dev/null

    # sq with foreign keys on for the statements below (the pragma is per connection)
    sqf() { sqlite3 "$DB" "PRAGMA foreign_keys = ON; $1" > /dev/null; }

    sqf "INSERT INTO domains (id, name, type) VALUES (1, 'a.test', 'NATIVE')"
    expect "INSERT INTO domains" "1"
    sqf "INSERT INTO domains (id, name, type) VALUES (2, 'b.test', 'NATIVE')"
    reset
    sqf "INSERT INTO records (id, domain_id, name, type, content, ttl) VALUES (10, 1, 'a.test', 'SOA', 'ns h 1 2 3 4 5', 60), (11, 1, 'www.a.test', 'A', '192.0.2.1', 60)"
    expect "INSERT INTO records (two rows, one statement: one row each in SQLite)" "1,1"
    sqf "UPDATE records SET content = '192.0.2.2' WHERE id = 11"
    expect "UPDATE records (content)" "1"
    sqf "UPDATE records SET domain_id = 2 WHERE id = 11"
    expect "UPDATE records (moved to another domain: OLD and NEW id)" "1,2"
    sqf "DELETE FROM records WHERE id = 11"
    expect "DELETE FROM records" "2"
    sqf "INSERT INTO records (id, domain_id, name, type, content, ttl) VALUES (12, 2, 'x.b.test', 'A', '192.0.2.3', 60)"
    reset
    sqf "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'PRESIGNED', '1')"
    expect "INSERT INTO domainmetadata" "1"
    sqf "UPDATE domainmetadata SET content = '0' WHERE domain_id = 1"
    expect "UPDATE domainmetadata" "1"
    sqf "DELETE FROM domainmetadata WHERE domain_id = 1"
    expect "DELETE FROM domainmetadata" "1"
    sqf "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (1, 257, 1, 'k')"
    expect "INSERT INTO cryptokeys" "1"
    sqf "DELETE FROM cryptokeys WHERE domain_id = 1"
    expect "DELETE FROM cryptokeys" "1"
    sqf "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'internal')"
    expect "INSERT INTO karidns_domain_views" "1"
    sqf "UPDATE karidns_domain_views SET view_name = 'external' WHERE domain_id = 1"
    expect "UPDATE karidns_domain_views" "1"
    sqf "DELETE FROM karidns_domain_views WHERE domain_id = 1"
    expect "DELETE FROM karidns_domain_views" "1"
    sqf "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (2, 'location', 'tokyo', '192.0.2.0/24')"
    expect "INSERT INTO karidns_zone_tagdefs" "2"
    sqf "DELETE FROM karidns_zone_tagdefs WHERE domain_id = 2"
    expect "DELETE FROM karidns_zone_tagdefs" "2"
    sqf "INSERT INTO karidns_record_tags (record_id, location_tag) VALUES (12, 'tokyo')"
    expect "INSERT INTO karidns_record_tags (the domain comes through the record)" "2"
    sqf "UPDATE karidns_record_tags SET ecs_tag = 'e' WHERE record_id = 12"
    expect "UPDATE karidns_record_tags" "2"
    sqf "DELETE FROM karidns_record_tags WHERE record_id = 12"
    expect "DELETE FROM karidns_record_tags" "2"
    sqf "INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES (12, 1900000000, 'tk', 0)"
    expect "INSERT INTO karidns_record_tinydns" "2"
    sqf "DELETE FROM karidns_record_tinydns WHERE record_id = 12"
    expect "DELETE FROM karidns_record_tinydns" "2"
    sqf "UPDATE domains SET name = 'c.test' WHERE id = 1"
    expect "UPDATE domains (rename)" "1"
    sqf "UPDATE domains SET id = 3 WHERE id = 1"
    expect "UPDATE domains (new id: OLD and NEW)" "1,3"
    sqf "DELETE FROM domains WHERE id = 3"
    expect "DELETE FROM domains (the log keeps the deleted id)" "3"
    # sequence numbers only grow, and the time is a unix time
    sqf "INSERT INTO domains (id, name, type) VALUES (20, 'seq1.test', 'NATIVE'); INSERT INTO domains (id, name, type) VALUES (21, 'seq2.test', 'NATIVE')"
    [ "$(sq "SELECT count(*) FROM karidns_changes c1 JOIN karidns_changes c2 ON c2.seq > c1.seq WHERE c2.domain_id = 21 AND c1.domain_id = 20")" = "1" ] &&
        pass "seq grows with each change" || fail "seq order"
    [ "$(sq "SELECT count(*) FROM karidns_changes WHERE changed_at > 1700000000")" = "2" ] && pass "changed_at is a unix time" || fail "changed_at"

    # the prune trigger, retention 5 instead of 1000000
    sed 's/1000000/5/g' "$EXT" > "$T/ext5.sql"
    DB=$T/ddl5.db
    sq < "$SCHEMA" > /dev/null
    sq < "$T/ext5.sql"
    sq "SELECT sql FROM sqlite_master WHERE name = 'karidns_changes_prune'" | grep -q "seq <= NEW.seq - 5" && pass "the retention was replaced by 5" || fail "retention replace"
    i=1; while [ $i -le 12 ]; do sq "INSERT INTO domains (id, name, type) VALUES ($i, 'p$i.test', 'NATIVE')"; i=$((i + 1)); done
    [ "$(sq 'SELECT count(*) FROM karidns_changes')" = "5" ] && [ "$(sq 'SELECT min(seq) FROM karidns_changes')" = "8" ] &&
        [ "$(sq 'SELECT max(seq) FROM karidns_changes')" = "12" ] && [ "$(chg)" = "8,9,10,11,12" ] &&
        pass "prune: the newest 5 of 12 rows are kept (seq 8..12)" || fail "prune: $(chg)"
    # the log of a database that is pruned: the next seq goes on from the last one (AUTOINCREMENT), never reuses a number
    sq "INSERT INTO domains (id, name, type) VALUES (13, 'p13.test', 'NATIVE')"
    [ "$(sq 'SELECT max(seq) FROM karidns_changes')" = "13" ] && pass "seq 13 follows 12" || fail "seq after prune"
fi

# ================================================================ PostgreSQL
echo "== PostgreSQL"
PGMAINT=${KARIDNS_TEST_PG:-postgres}
if ! command -v psql >/dev/null 2>&1; then
    skip "psql is not installed"
elif ! pg_isready -q 2>/dev/null && [ -z "${KARIDNS_TEST_PG:-}" ]; then
    skip "no PostgreSQL server is reachable on the default socket (set KARIDNS_TEST_PG to a conninfo to test one)"
elif ! psql -X -q -At -d "$PGMAINT" -c "SELECT 1" >/dev/null 2>&1; then
    skip "cannot connect to PostgreSQL (database '$PGMAINT')"
else
    PGDB="karidns_ddl_test_$$"
    if ! psql -X -q -d "$PGMAINT" -c "CREATE DATABASE $PGDB" >/dev/null 2>&1; then
        skip "the role may not create databases"
        PGDB=""
    else
        # the maintenance conninfo may be a keyword string: reuse it with another dbname
        if [ -n "${KARIDNS_TEST_PG:-}" ]; then PGC="$KARIDNS_TEST_PG dbname=$PGDB"; else PGC="dbname=$PGDB"; fi
        pq() { psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "$1"; }
        pf() { psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -f "$1"; }
        chg() { pq "SELECT coalesce(string_agg(domain_id::text, ',' ORDER BY domain_id), '') FROM karidns_changes"; }   # order within a statement is not defined
        reset() { pq "DELETE FROM karidns_changes" >/dev/null; }
        expect() {
            got=$(chg)
            [ "$got" = "$2" ] && pass "$1: $got" || fail "$1: logged '$got', wanted '$2'"
            reset
        }
        pf tests/db/pdns_schema.pgsql.sql > "$T/pg_schema.out" 2>&1 || { fail "the PowerDNS-style schema does not load"; cat "$T/pg_schema.out"; }
        pf db/karidns_ext.pgsql.sql > "$T/pg_ext.out" 2>&1 && pass "the ext file applies" || { fail "the ext file does not apply"; cat "$T/pg_ext.out"; }
        pf db/karidns_ext.pgsql.sql > "$T/pg_ext2.out" 2>&1 && pass "the ext file applies a second time" || { fail "second application"; cat "$T/pg_ext2.out"; }
        [ "$(pq 'SELECT count(*) FROM karidns_schema_version')" = "1" ] && [ "$(pq 'SELECT version FROM karidns_schema_version')" = "1" ] &&
            pass "schema version 1, one row after two applications" || fail "karidns_schema_version"
        for t in karidns_schema_version karidns_changes karidns_domain_views karidns_profiles karidns_record_tags karidns_record_tinydns karidns_zone_tagdefs; do
            [ "$(pq "SELECT count(*) FROM pg_tables WHERE tablename = '$t' AND schemaname = current_schema()")" = "1" ] && pass "table $t" || fail "table $t is missing"
        done
        [ "$(pq "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal AND c.relname LIKE '%'")" = "25" ] &&
            pass "25 triggers (8 tables x 3 + prune)" || fail "trigger count $(pq "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal")"

        pq "INSERT INTO domains (name, type) SELECT 'd' || g || '.test', 'NATIVE' FROM generate_series(1, 3) g" >/dev/null
        expect "INSERT of 3 domains in one statement: one row per domain" "1,2,3"
        pq "INSERT INTO records (domain_id, name, type, content, ttl) SELECT 1, 'h' || g || '.d1.test', 'A', '192.0.2.1', 60 FROM generate_series(1, 1000) g" >/dev/null
        expect "INSERT of 1000 records into one zone: ONE row" "1"
        pq "INSERT INTO records (domain_id, name, type, content, ttl) SELECT 1 + (g % 2), 'x' || g || '.test', 'A', '192.0.2.2', 60 FROM generate_series(1, 100) g" >/dev/null
        expect "INSERT of 100 records into two zones: one row each" "1,2"
        pq "UPDATE records SET content = '192.0.2.9' WHERE domain_id = 1" >/dev/null
        expect "UPDATE of many records of one zone: one row" "1"
        pq "UPDATE records SET domain_id = 3 WHERE domain_id = 2" >/dev/null
        expect "UPDATE moving records from zone 2 to zone 3: OLD and NEW" "2,3"
        pq "DELETE FROM records WHERE domain_id IN (1, 3)" >/dev/null
        expect "DELETE from two zones: one row each" "1,3"
        pq "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'r.d2.test', 'A', '192.0.2.5', 60)" >/dev/null
        reset
        pq "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'PRESIGNED', '1'), (1, 'NSEC3PARAM', '1 0 0 -')" >/dev/null
        expect "INSERT INTO domainmetadata (two rows of one zone)" "1"
        pq "UPDATE domainmetadata SET content = '0' WHERE domain_id = 1 AND kind = 'PRESIGNED'" >/dev/null
        expect "UPDATE domainmetadata" "1"
        pq "DELETE FROM domainmetadata WHERE domain_id = 1" >/dev/null
        expect "DELETE FROM domainmetadata" "1"
        pq "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (1, 257, true, 'k')" >/dev/null
        expect "INSERT INTO cryptokeys" "1"
        pq "DELETE FROM cryptokeys WHERE domain_id = 1" >/dev/null
        expect "DELETE FROM cryptokeys" "1"
        pq "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'internal'), (2, 'internal')" >/dev/null
        expect "INSERT INTO karidns_domain_views (two zones)" "1,2"
        pq "DELETE FROM karidns_domain_views" >/dev/null
        expect "DELETE FROM karidns_domain_views" "1,2"
        pq "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (3, 'location', 'tokyo', '192.0.2.0/24')" >/dev/null
        expect "INSERT INTO karidns_zone_tagdefs" "3"
        RID=$(pq "SELECT id FROM records WHERE domain_id = 2 LIMIT 1")
        pq "INSERT INTO karidns_record_tags (record_id, location_tag) VALUES ($RID, 'tokyo')" >/dev/null
        expect "INSERT INTO karidns_record_tags (the domain comes through the record)" "2"
        pq "DELETE FROM karidns_record_tags" >/dev/null
        expect "DELETE FROM karidns_record_tags" "2"
        pq "INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES ($RID, 1900000000, 'tk', false)" >/dev/null
        expect "INSERT INTO karidns_record_tinydns" "2"
        pq "UPDATE karidns_record_tinydns SET loc = 'ty'" >/dev/null
        expect "UPDATE karidns_record_tinydns" "2"
        pq "DELETE FROM karidns_record_tinydns" >/dev/null
        expect "DELETE FROM karidns_record_tinydns" "2"
        pq "DELETE FROM domains WHERE name = 'd2.test'" >/dev/null
        got=$(chg)
        case ",$got," in *,2,*) pass "DELETE FROM domains (cascade included) logs the deleted zone: $got" ;; *) fail "DELETE FROM domains: logged '$got'" ;; esac
        reset
        [ "$(pq "SELECT count(*) FROM karidns_changes WHERE changed_at > 1700000000")" = "0" ] && pass "(the log is empty after reset)" || fail "reset"

        # pg_notify reaches a LISTENing session (psql prints the notification after the next command)
        printf "LISTEN karidns_changes;\nINSERT INTO domains (name, type) VALUES ('notify.test', 'NATIVE');\nSELECT 1;\n" |
            psql -X "$PGC" > "$T/pg_notify.out" 2>&1
        grep -q 'Asynchronous notification "karidns_changes" received' "$T/pg_notify.out" && pass "pg_notify('karidns_changes') reaches a listener" ||
            { fail "no notification"; sed 's/^/         /' "$T/pg_notify.out"; }

        # prune: a second copy of the DDL with the retention 5, in a second database
        sed 's/1000000/5/g' db/karidns_ext.pgsql.sql > "$T/pg_ext5.sql"
        PGDB5="karidns_ddl_test5_$$"
        psql -X -q -d "$PGMAINT" -c "CREATE DATABASE $PGDB5" >/dev/null 2>&1 &&
            { PGC5="dbname=$PGDB5"; [ -n "${KARIDNS_TEST_PG:-}" ] && PGC5="$KARIDNS_TEST_PG dbname=$PGDB5";
              psql -X -q -At -v ON_ERROR_STOP=1 "$PGC5" -f tests/db/pdns_schema.pgsql.sql >/dev/null 2>&1 &&
              psql -X -q -At -v ON_ERROR_STOP=1 "$PGC5" -f "$T/pg_ext5.sql" >/dev/null 2>&1 &&
              psql -X -q -At -v ON_ERROR_STOP=1 "$PGC5" -c "INSERT INTO domains (name, type) SELECT 'p' || g || '.test', 'NATIVE' FROM generate_series(1, 20) g" >/dev/null 2>&1;
              n=$(psql -X -q -At "$PGC5" -c "SELECT count(*) FROM karidns_changes" 2>&1);
              mx=$(psql -X -q -At "$PGC5" -c "SELECT max(seq) - min(seq) + 1 FROM karidns_changes" 2>&1);
              [ "$n" = "5" ] && [ "$mx" = "5" ] && pass "prune: the newest 5 of 20 rows are kept" || fail "prune: $n rows, span $mx";
              psql -X -q -d "$PGMAINT" -c "DROP DATABASE IF EXISTS $PGDB5" >/dev/null 2>&1; } ||
            skip "cannot create a second database for the prune test"

        # the real PowerDNS schema, if it can be found
        PDNS_PG=${PDNS_SCHEMA_PGSQL:-/usr/local/share/doc/pdns/schema.pgsql.sql}
        if [ -r "$PDNS_PG" ]; then
            PGDB6="karidns_ddl_test6_$$"
            if psql -X -q -d "$PGMAINT" -c "CREATE DATABASE $PGDB6" >/dev/null 2>&1; then
                PGC6="dbname=$PGDB6"; [ -n "${KARIDNS_TEST_PG:-}" ] && PGC6="$KARIDNS_TEST_PG dbname=$PGDB6"
                if psql -X -q -At -v ON_ERROR_STOP=1 "$PGC6" -f "$PDNS_PG" >/dev/null 2>&1 &&
                   psql -X -q -At -v ON_ERROR_STOP=1 "$PGC6" -f db/karidns_ext.pgsql.sql >/dev/null 2>&1 &&
                   psql -X -q -At -v ON_ERROR_STOP=1 "$PGC6" -c "INSERT INTO domains (name, type) VALUES ('real.test', 'NATIVE'); INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'real.test', 'SOA', 'ns h 1 2 3 4 5', 60)" >/dev/null 2>&1 &&
                   [ "$(psql -X -q -At "$PGC6" -c "SELECT string_agg(domain_id::text, ',' ORDER BY seq) FROM karidns_changes")" = "1,1" ]; then
                    pass "the real PowerDNS schema ($PDNS_PG) takes the ext DDL and its triggers log"
                else
                    fail "the real PowerDNS schema ($PDNS_PG) with the ext DDL"
                fi
                psql -X -q -d "$PGMAINT" -c "DROP DATABASE IF EXISTS $PGDB6" >/dev/null 2>&1
            fi
        else
            skip "the PowerDNS schema file is not installed ($PDNS_PG); only the reduced test schema was used"
        fi
    fi
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_ddl_test: all $PASS checks passed ($SKIPS skipped) ==="; exit 0; fi
echo "=== run_db_ddl_test: $FAILS check(s) FAILED ($PASS passed, $SKIPS skipped) ==="
exit 1
