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
# When the test runs as root (the suite does) psql runs as an unprivileged user through su -m, because FreeBSD has no sudo
# in base and PostgreSQL has no role "root": KARIDNS_TEST_PG_USER, else SUDO_USER, else the owner of the source tree (the
# first of them that can connect); the test never needs sudo.
# B7a: the triggers on karidns_profiles log every domain whose X-KARIDNS-PROFILE names the profile (both dialects).
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

# psql, as an unprivileged user when this test runs as root (PG_AS is chosen in the PostgreSQL section; empty = as
# ourselves).  The arguments travel in the environment (PSQLA1, PSQLA2, ...) so that nothing has to be quoted for su.
PG_AS=""
psql() {
    if [ -z "$PG_AS" ]; then command psql "$@"; return $?; fi
    cmd="exec psql"
    i=0
    for a in "$@"; do
        i=$((i + 1))
        export "PSQLA$i=$a"
        cmd="$cmd \"\$PSQLA$i\""
    done
    su -m "$PG_AS" -c "$cmd"
}
# who may run psql: the first candidate that can connect (as root; anybody else runs psql as themselves)
pick_pg_user() {
    [ "$(id -u)" = "0" ] || return 0
    owner=$(stat -f %Su "$ROOT" 2>/dev/null || stat -c %U "$ROOT" 2>/dev/null)
    for u in "${KARIDNS_TEST_PG_USER:-}" "${SUDO_USER:-}" "$owner" postgres pgsql; do
        [ -n "$u" ] && [ "$u" != root ] && id "$u" >/dev/null 2>&1 || continue
        PG_AS=$u
        if psql -X -q -At -d "${KARIDNS_TEST_PG:-postgres}" -c "SELECT 1" >/dev/null 2>&1; then
            PG_TRIED="$PG_TRIED $u"
            chmod 755 "$T"                     # psql -f reads files of the temporary directory
            return 0
        fi
        PG_TRIED="$PG_TRIED $u"
    done
    PG_AS=""
    return 0
}
PG_TRIED=""

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
    [ "$(sq 'SELECT count(*) FROM karidns_schema_version')" = "1" ] && [ "$(sq 'SELECT version FROM karidns_schema_version')" = "2" ] &&
        pass "schema version 2, one row after two applications" || fail "karidns_schema_version"
    for t in karidns_schema_version karidns_changes karidns_domain_views karidns_profiles karidns_record_tags karidns_record_tinydns karidns_zone_tagdefs; do
        [ "$(sq "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '$t'")" = "1" ] && pass "table $t" || fail "table $t is missing"
    done
    # 9 tables with INSERT / UPDATE / DELETE triggers (B7a: karidns_profiles) + the prune trigger
    # B10: karidns_zone_tagdefs.id (schema version 2) is the rowid alias, in the order of the inserts
    [ "$(sq "SELECT count(*) FROM pragma_table_info('karidns_zone_tagdefs') WHERE name = 'id' AND pk = 1")" = "1" ] && pass "karidns_zone_tagdefs.id is the primary key" || fail "karidns_zone_tagdefs.id"
    [ "$(sq "SELECT count(*) FROM sqlite_master WHERE type = 'trigger'")" = "28" ] && pass "28 triggers (9 tables x 3 + prune)" ||
        fail "trigger count $(sq "SELECT count(*) FROM sqlite_master WHERE type = 'trigger'"), wanted 28"
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
    # B7a: a profile edit logs every domain whose X-KARIDNS-PROFILE names the old or the new name (kind in any case, blanks
    # around the name ignored, other profiles and other kinds not)
    sqf "INSERT INTO domains (id, name, type) VALUES (31, 'pa.test', 'NATIVE'), (32, 'pb.test', 'NATIVE'), (33, 'pc.test', 'NATIVE'), (34, 'pd.test', 'NATIVE'), (35, 'pe.test', 'NATIVE')"
    sqf "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (31, 'X-KARIDNS-PROFILE', 'gold'), (32, 'X-KARIDNS-PROFILE', '  gold ' || char(9)),
         (33, 'X-KARIDNS-PROFILE', 'silver'), (34, 'x-karidns-profile', 'gold'), (35, 'ALSO-NOTIFY', 'gold')"
    reset
    sets() { sq "SELECT coalesce(group_concat(domain_id, ','), '') FROM (SELECT domain_id FROM karidns_changes ORDER BY domain_id)"; }
    expect_set() { got=$(sets); [ "$got" = "$2" ] && pass "$1: $got" || fail "$1: logged '$got', wanted '$2'"; reset; }
    sqf "INSERT INTO karidns_profiles (name, settings) VALUES ('gold', 'allow-transfer { 192.0.2.1; };')"
    expect_set "INSERT INTO karidns_profiles logs the domains that name it" "31,32,34"
    sqf "UPDATE karidns_profiles SET settings = 'allow-transfer { 192.0.2.2; };' WHERE name = 'gold'"
    expect_set "UPDATE karidns_profiles (settings)" "31,32,34"
    sqf "UPDATE karidns_profiles SET name = 'silver' WHERE name = 'gold'"
    expect_set "UPDATE karidns_profiles (rename: the old and the new name)" "31,32,33,34"
    sqf "DELETE FROM karidns_profiles WHERE name = 'silver'"
    expect_set "DELETE FROM karidns_profiles" "33"
    sqf "INSERT INTO karidns_profiles (name, settings) VALUES ('unused', '')"
    expect_set "a profile no domain names logs nothing" ""
    sqf "DELETE FROM domains WHERE id >= 31 AND id <= 35"
    reset
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
elif pick_pg_user; ! psql -X -q -At -d "$PGMAINT" -c "SELECT 1" >/dev/null 2>&1; then
    if [ "$(id -u)" = "0" ] && [ -z "$PG_AS" ]; then
        skip "running as root and no unprivileged user could connect to PostgreSQL (tried:${PG_TRIED:- none}; set KARIDNS_TEST_PG_USER)"
    else
        skip "cannot connect to PostgreSQL (database '$PGMAINT')"
    fi
else
    [ -n "$PG_AS" ] && echo "  (psql runs as user $PG_AS)"
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
        [ "$(pq 'SELECT count(*) FROM karidns_schema_version')" = "1" ] && [ "$(pq 'SELECT version FROM karidns_schema_version')" = "2" ] &&
            pass "schema version 2, one row after two applications" || fail "karidns_schema_version"
        for t in karidns_schema_version karidns_changes karidns_domain_views karidns_profiles karidns_record_tags karidns_record_tinydns karidns_zone_tagdefs karidns_reload_requests karidns_server_status; do
            [ "$(pq "SELECT count(*) FROM pg_tables WHERE tablename = '$t' AND schemaname = current_schema()")" = "1" ] && pass "table $t" || fail "table $t is missing"
        done
        [ "$(pq "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal AND c.relname LIKE '%'")" = "31" ] &&
            pass "31 triggers (9 tables x 3 + prune + the 3 of karidns_reload_requests: lock, notify, prune)" || fail "trigger count $(pq "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal")"

        # B10 (schema version 2): the log rows carry the xid8 of the writing transaction, tagdefs have an id
        [ "$(pq "SELECT format_type(atttypid, atttypmod) FROM pg_attribute WHERE attrelid = 'karidns_changes'::regclass AND attname = 'xid'")" = "xid8" ] &&
            pass "karidns_changes.xid is xid8" || fail "karidns_changes.xid"
        [ "$(pq "SELECT count(*) FROM pg_indexes WHERE tablename = 'karidns_changes' AND indexname = 'karidns_changes_xid_idx'")" = "1" ] && pass "index on karidns_changes.xid" || fail "xid index"
        [ "$(pq "SELECT count(*) FROM pg_attribute WHERE attrelid = 'karidns_zone_tagdefs'::regclass AND attname = 'id' AND NOT attisdropped")" = "1" ] && pass "karidns_zone_tagdefs.id" || fail "karidns_zone_tagdefs.id"
        XOUT=$(printf "BEGIN;\nSELECT pg_current_xact_id();\nINSERT INTO domains (id, name, type) VALUES (9001, 'xid1.test', 'NATIVE');\nSELECT xid FROM karidns_changes ORDER BY seq DESC LIMIT 1;\nCOMMIT;\nINSERT INTO domains (id, name, type) VALUES (9002, 'xid2.test', 'NATIVE');\nSELECT xid FROM karidns_changes ORDER BY seq DESC LIMIT 1;\n" | psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" | tr '\n' ' ')
        set -- $XOUT
        if [ $# -eq 3 ] && [ "$1" = "$2" ] && [ "$1" != "$3" ] && [ "$1" != "0" ]; then pass "a log row carries the xid8 of the writing transaction ($1), the next transaction has another ($3)"
        else fail "xid of log rows: '$XOUT'"; fi
        pq "DELETE FROM domains WHERE name IN ('xid1.test', 'xid2.test'); DELETE FROM karidns_changes" >/dev/null
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
        # B7a: a profile edit logs every domain whose X-KARIDNS-PROFILE names the old or the new name (kind in any case,
        # blanks around the name ignored, other profiles and other kinds not), one row per domain and statement
        pq "INSERT INTO domains (id, name, type) VALUES (41, 'pa.test', 'NATIVE'), (42, 'pb.test', 'NATIVE'), (43, 'pc.test', 'NATIVE'), (44, 'pd.test', 'NATIVE'), (45, 'pe.test', 'NATIVE')" >/dev/null
        pq "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (41, 'X-KARIDNS-PROFILE', 'gold'), (42, 'X-KARIDNS-PROFILE', E'  gold \t'),
            (43, 'X-KARIDNS-PROFILE', 'silver'), (44, 'x-karidns-profile', 'gold'), (45, 'ALSO-NOTIFY', 'gold')" >/dev/null
        reset
        pq "INSERT INTO karidns_profiles (name, settings) VALUES ('gold', 'allow-transfer { 192.0.2.1; };')" >/dev/null
        expect "INSERT INTO karidns_profiles logs the domains that name it" "41,42,44"
        pq "INSERT INTO karidns_profiles (name, settings) VALUES ('silver', ''), ('gold2', ''), ('nobody', '')" >/dev/null
        expect "INSERT of three profiles in one statement: one row per domain" "43"
        pq "UPDATE karidns_profiles SET settings = 'allow-transfer { 192.0.2.2; };' WHERE name = 'gold'" >/dev/null
        expect "UPDATE karidns_profiles (settings)" "41,42,44"
        pq "UPDATE karidns_profiles SET name = 'bronze' WHERE name = 'gold'" >/dev/null
        expect "UPDATE karidns_profiles (rename: the old name)" "41,42,44"
        pq "DELETE FROM karidns_profiles" >/dev/null
        expect "DELETE FROM karidns_profiles (silver is the only name a domain still uses)" "43"
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

        # B11 (multi-server): karidns_reload_requests numbers the requests, NOTIFYs karidns_reload with the generation, keeps the
        # newest 1000, and the INSERT takes a lock that is held until commit (generations become visible in order)
        pq "INSERT INTO karidns_reload_requests DEFAULT VALUES; INSERT INTO karidns_reload_requests (zone, force) VALUES ('z.test', true)" > /dev/null
        [ "$(pq "SELECT generation || ':' || coalesce(zone, '-') || ':' || force FROM karidns_reload_requests ORDER BY generation" | tr '\n' ' ')" = "1:-:false 2:z.test:true " ] &&
            pass "karidns_reload_requests: generations 1, 2; zone NULL = all, force defaults to false" || fail "karidns_reload_requests rows"
        printf "LISTEN karidns_reload;\nINSERT INTO karidns_reload_requests DEFAULT VALUES;\nSELECT 1;\n" | psql -X "$PGC" > "$T/pg_notify2.out" 2>&1
        grep -q 'Asynchronous notification "karidns_reload" with payload "3" received' "$T/pg_notify2.out" && pass "pg_notify('karidns_reload', generation) reaches a listener" ||
            { fail "no karidns_reload notification"; sed 's/^/         /' "$T/pg_notify2.out"; }
        pq "INSERT INTO karidns_reload_requests (zone) SELECT 'p' || g || '.test' FROM generate_series(1, 1200) g" > /dev/null
        [ "$(pq "SELECT count(*) || ':' || max(generation) - min(generation) + 1 FROM karidns_reload_requests")" = "1000:1000" ] && pass "karidns_reload_requests keeps the newest 1000 requests" ||
            fail "request prune: $(pq "SELECT count(*), min(generation), max(generation) FROM karidns_reload_requests")"
        pq "INSERT INTO karidns_server_status (server_id, generation, applied_at, ok) VALUES ('ns1', 5, now(), true)" > /dev/null
        [ "$(pq "SELECT failed_zones = '' FROM karidns_server_status WHERE server_id = 'ns1'")" = "t" ] && pass "karidns_server_status: failed_zones defaults to an empty text" || fail "karidns_server_status default"
        pq "INSERT INTO karidns_server_status (server_id, generation, applied_at, ok) VALUES ('ns1', 6, now(), true)" > /dev/null 2>&1 && fail "a second row for the same server_id was accepted" || pass "server_id is the primary key of karidns_server_status"
        # a requester that is still in its transaction keeps the next one waiting (statement-level BEFORE trigger, advisory lock)
        { printf "BEGIN;\nINSERT INTO karidns_reload_requests (zone) VALUES ('first.test');\nSELECT pg_sleep(2);\nCOMMIT;\n" | psql -X "$PGC" > /dev/null 2>&1 & } ; sleep 0.7
        pq "SET lock_timeout = '500ms'; INSERT INTO karidns_reload_requests (zone) VALUES ('second.test')" > "$T/lock.out" 2>&1 && fail "the second requester did not wait for the first" ||
            { grep -q "lock timeout" "$T/lock.out" && pass "a second requester waits while the first one has not committed (lock timeout after the advisory lock)" || { fail "lock test"; cat "$T/lock.out"; }; }
        wait
        pq "INSERT INTO karidns_reload_requests (zone) VALUES ('after.test')" > /dev/null
        [ "$(pq "SELECT (SELECT generation FROM karidns_reload_requests WHERE zone = 'after.test') > (SELECT generation FROM karidns_reload_requests WHERE zone = 'first.test')")" = "t" ] &&
            pass "after the first requester committed the next one goes on, with a higher generation" || fail "generation order after the lock"

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

        # the functions pin the search_path of the session that applied the DDL: a writer with another search_path, and a decoy
        # karidns_changes / karidns_log_domains earlier on its path, still logs into the schema the DDL was installed in
        pq "CREATE SCHEMA karidns_ddl_home; CREATE SCHEMA karidns_ddl_decoy" >/dev/null
        { echo "SET search_path TO karidns_ddl_home;"; cat tests/db/pdns_schema.pgsql.sql db/karidns_ext.pgsql.sql; } > "$T/home.sql"
        pf "$T/home.sql" > "$T/home.out" 2>&1 && pass "the DDL applies in a non-default schema" || { fail "the DDL in a non-default schema"; head -3 "$T/home.out"; }
        pq "CREATE TABLE karidns_ddl_decoy.karidns_changes (seq BIGSERIAL, domain_id INTEGER, changed_at BIGINT, xid xid8 DEFAULT pg_current_xact_id());
            CREATE FUNCTION karidns_ddl_decoy.karidns_log_domains(ids INTEGER[]) RETURNS void LANGUAGE sql AS 'INSERT INTO karidns_ddl_decoy.karidns_changes (domain_id, changed_at) SELECT 0, 0'" >/dev/null
        pq "SET search_path = karidns_ddl_decoy, karidns_ddl_home; INSERT INTO karidns_ddl_home.domains (name, type) VALUES ('home.test', 'NATIVE'); INSERT INTO karidns_ddl_home.records (domain_id, name, type, content, ttl) SELECT id, 'h.home.test', 'A', '192.0.2.1', 60 FROM karidns_ddl_home.domains WHERE name = 'home.test'" >/dev/null
        [ "$(pq "SELECT count(*) FROM karidns_ddl_home.karidns_changes")" = "2" ] && [ "$(pq "SELECT count(*) FROM karidns_ddl_decoy.karidns_changes")" = "0" ] &&
            pass "a writer with a different search_path (and a decoy log) still logs into the schema of the DDL" ||
            fail "log rows: home $(pq "SELECT count(*) FROM karidns_ddl_home.karidns_changes"), decoy $(pq "SELECT count(*) FROM karidns_ddl_decoy.karidns_changes")"
        [ "$(pq "SELECT count(*) FROM pg_proc WHERE proname LIKE 'karidns\_%' AND pronamespace = 'karidns_ddl_home'::regnamespace AND proconfig IS NULL")" = "0" ] && pass "every karidns_* function pins its search_path" || fail "unpinned functions"
        pq "DROP SCHEMA karidns_ddl_home CASCADE; DROP SCHEMA karidns_ddl_decoy CASCADE" >/dev/null

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
