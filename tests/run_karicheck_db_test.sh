#!/bin/sh
# run_karicheck_db_test.sh - karicheck db: every finding of `karidns-dbloader --check` / `karicheck db` (beta design 7.2, 8.4; milestone B12).
#
# One small database per case (SQLite3, and PostgreSQL when a server is reachable: the same SQL, the same expectations), a
# configuration that points at it, and `karicheck db` run on that.  Each finding is tested twice, once where it must appear and once
# where the same input without the fault must not produce it:
#   schema      PowerDNS tables and columns, the karidns_* tables and their version, the change log triggers (auto-reload yes),
#               PostgreSQL: the privileges of the role, a role that can read the keys
#   zones       the reader's errors with records.id (content, unsupported type, owner outside the zone, ambiguous prio, no SOA, a bad
#               secondary), NULL ttl, serial 0, ALIAS in a presigned zone, LUA, and the checks `karicheck zone` makes (the same code)
#   keys        cryptokeys without PRESIGNED, NSEC3PARAM syntax, a presigned NSEC3 chain (needs BIND's dnssec-signzone, else skipped)
#   metadata    the restricted parse of a profile, TSIG key names, ACL entries outside acl-ceiling (and no acl-ceiling)
#   D-PRIO/PROG a zone of the same name in karidns.conf (file, program, forward)
#   views       mapping rows naming an undefined view / a view that does not read the source, a zone no view serves, `db VIEW`
#   rights      root: the loader runs as loader-user (privilege drop); another user: with its own rights; unreadable files name the
#               file and the permission; no loader ("DB support is not installed"); a loader without the driver; exit codes
# Run it as root (needs a user to drop to: SUDO_USER or nobody) and as a normal user; both use the same cases.
#
# SKIP (exit 0, with the reason) when karicheck or karidns-dbloader (SQLite3 driver) or the sqlite3 CLI is missing.  The PostgreSQL
# part is skipped with its reason when no server can be used (KARIDNS_TEST_PG, tests/db/pg_lib.sh).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

KC=${KC:-$ROOT/karicheck}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
if [ ! -x "$KC" ] || [ ! -x "$LOADER" ]; then echo "SKIP: karicheck or karidns-dbloader is not built"; exit 0; fi
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karicheck_db.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
cleanup() { pg_cleanup; [ -n "${PGROLES:-}" ] && for r in $PGROLES; do psql -X -q -d "$PGMAINT" -c "DROP OWNED BY $r" -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done; if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"; fi; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -14 | sed 's/^/         /'; }

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1
ME=$(id -un)
if [ $IS_ROOT = 1 ]; then
    LUSER=${KARIDNS_TEST_LOADER_USER:-${SUDO_USER:-nobody}}
    id "$LUSER" >/dev/null 2>&1 || { echo "SKIP: no user '$LUSER' to drop to"; exit 0; }
    [ "$LUSER" = root ] && { echo "SKIP: no unprivileged user to drop to (set KARIDNS_TEST_LOADER_USER)"; exit 0; }
else
    LUSER=$ME
fi
own() { [ $IS_ROOT = 1 ] && chown "$LUSER" "$@"; return 0; }
echo "== karicheck db, run as $ME$( [ $IS_ROOT = 1 ] && echo " (root: the loader runs as $LUSER)")"

cp "$LOADER" "$T/dbl" && chmod 755 "$T/dbl"
if [ $IS_ROOT = 1 ]; then
    chown 0:0 "$T/dbl"
    chown "$LUSER" "$T"             # the directory of a WAL database must be writable by the user who reads it (the -shm file)
fi
SCHEMA_SQ=$ROOT/tests/db/pdns_schema.sqlite3.sql
SCHEMA_PG=$ROOT/tests/db/pdns_schema.pgsql.sql
EXT_SQ=$ROOT/db/karidns_ext.sqlite3.sql
EXT_PG=$ROOT/db/karidns_ext.pgsql.sql
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
DB=$T/z.db
CI=$T/ci
BACKEND=sqlite3

# ---------------------------------------------------------------- the database of a case
# sqlite: $DB is made again; postgresql: the schema "public" is made again.  Both then hold the clean zone ok.test.
sql() {                 # sql STATEMENTS: into the current database
    if [ "$BACKEND" = sqlite3 ]; then sqlite3 "$DB" "$1" > "$T/sql.out" 2>&1; else pq "$1" > "$T/sql.out" 2>&1; fi
    rc=$?
    [ $rc -ne 0 ] && { echo "  [FAIL] SQL: $(head -2 "$T/sql.out") -- $(printf '%s' "$1" | head -c 150)"; FAILS=$((FAILS + 1)); }
    return 0
}
dbfile_reset() {        # the sqlite3 file only: schema, extension tables, WAL
    rm -f "$DB" "$DB-wal" "$DB-shm"
    sqlite3 "$DB" < "$SCHEMA_SQ" > /dev/null 2>&1
    [ "${NOEXT:-0}" = 1 ] || sqlite3 "$DB" < "$EXT_SQ" > /dev/null 2>&1
    sqlite3 "$DB" "PRAGMA journal_mode=WAL" > /dev/null 2>&1
    chmod 600 "$DB"
}
db_reset() {            # db_reset: a database with the clean zone ok.test (NOEXT=1: a plain PowerDNS database)
    if [ "$BACKEND" = sqlite3 ]; then
        dbfile_reset
    else
        psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "DROP SCHEMA public CASCADE" -c "CREATE SCHEMA public" > "$T/sql.out" 2>&1 || { bad "reset the PostgreSQL schema" "$(cat "$T/sql.out")"; return; }
        pf "$SCHEMA_PG" > "$T/sql.out" 2>&1 || bad "load the PowerDNS schema" "$(cat "$T/sql.out")"
        [ "${NOEXT:-0}" = 1 ] || pf "$EXT_PG" > "$T/sql.out" 2>&1 || bad "load the karidns_* DDL" "$(cat "$T/sql.out")"
        if [ -n "${PGRL:-}" ]; then
            psql -X -q -At -v ON_ERROR_STOP=1 -v role=$PGRL -v schema=public "$PGC" -f "$ROOT/db/karidns_loader_role.pgsql.sql" > "$T/sql.out" 2>&1 || bad "grant the loader role" "$(cat "$T/sql.out")"
        fi
    fi
    sql "$(zone 1 ok.test)
$(rec 1 www.ok.test A 192.0.2.2)
$(rec 1 ok.test MX mail.ok.test 3600 10)
$(rec 1 mail.ok.test A 192.0.2.3)"
    if [ "$BACKEND" = sqlite3 ]; then
        own "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    else            # the cases name their ids; a zone made by zone2sql takes the next one from the sequences
        pq "SELECT setval(pg_get_serial_sequence('domains', 'id'), 1000); SELECT setval(pg_get_serial_sequence('records', 'id'), 100000)" > /dev/null 2>&1
    fi
}
# SQL of a clean zone: SOA (serial 2024010101), apex NS, glue
zone() {                # zone ID NAME [SERIAL]
    printf "INSERT INTO domains (id, name, type) VALUES (%s, '%s', 'NATIVE');\n" "$1" "$2"
    printf "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (%s, '%s', 'SOA', 'ns1.%s hostmaster.%s %s 3600 600 86400 300', 3600, NULL, '0'), (%s, '%s', 'NS', 'ns1.%s', 3600, NULL, '0'), (%s, 'ns1.%s', 'A', '192.0.2.1', 3600, NULL, '0');\n" \
        "$1" "$2" "$2" "$2" "${3:-2024010101}" "$1" "$2" "$2" "$1" "$2"
}
rec() {                 # rec DOMAIN_ID NAME TYPE CONTENT [TTL|NULL] [PRIO|NULL]
    printf "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (%s, '%s', '%s', '%s', %s, %s, '0');\n" "$1" "$2" "$3" "$4" "${5:-3600}" "${6:-NULL}"
}
meta() { printf "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (%s, '%s', '%s');\n" "$1" "$2" "$3"; }

# ---------------------------------------------------------------- the configuration of a case
# conf [DBBLOCK-EXTRA] [TOPLEVEL-EXTRA] [CEILING]: options { database { } } for the current backend, the key "xfr", a zone "file.test"
CEIL_DEFAULT='acl-ceiling { 192.0.2.0/24; key "xfr"; };'
conf() {
    ceil=${3-$CEIL_DEFAULT}
    if [ "$BACKEND" = sqlite3 ]; then src="driver sqlite3; database-file \"$DB\";"; else src="driver postgresql; conninfo-file \"$CI\";"; fi
    {
        printf 'options {\n  user "%s";\n  database { %s loader-user "%s"; loader-path "%s"; %s %s };\n};\n' "$ME" "$src" "${DBUSER:-$LUSER}" "${LOADERPATH:-$T/dbl}" "$ceil" "${1:-}"
        printf 'key "xfr" { algorithm hmac-sha256; secret "%s"; };\n' "$SECRET"
        [ "${NOFILEZONE:-0}" = 1 ] || printf 'zone "file.test" { type master; file "%s/file.zone"; };\n' "$T"
        printf '%s\n' "${2:-}"
    } > "$T/k.conf"
}
printf '$TTL 60\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$T/file.zone"
kc() {                  # kc [ARGS...]: karicheck db on $T/k.conf; $out, $st
    out=$("$KC" db "$@" 2>&1); st=$?
}
run() {                 # run: kc "$T/k.conf"
    out=$("$KC" db "$T/k.conf" 2>&1); st=$?
    # PostgreSQL as the owner of the tables (no role could be created): the owner can read the keys, which is a finding of its own
    if [ "${PGOWNER:-0}" = 1 ]; then out=$(printf '%s\n' "$out" | grep -v "can read cryptokeys.content"); fi
}
# assertions on the last run
lbl() { echo "$BACKEND: $1"; }
has() {                 # has DESC PATTERN
    if printf '%s\n' "$out" | grep -q -- "$2"; then ok "$(lbl "$1")"; else bad "$(lbl "$1") (pattern: $2)" "$out"; fi
}
hasnt() {               # hasnt DESC PATTERN
    if printf '%s\n' "$out" | grep -q -- "$2"; then bad "$(lbl "$1") (unexpected: $2)" "$out"; else ok "$(lbl "$1")"; fi
}
status() {              # status DESC WANT
    if [ "$st" -eq "$2" ]; then ok "$(lbl "$1")"; else bad "$(lbl "$1") (exit $st, want $2)" "$out"; fi
}
err() {                 # err DESC PATTERN: an [ERROR] line with the pattern, exit 1
    if printf '%s\n' "$out" | grep "^\[ERROR\]" | grep -q -- "$2" && [ "$st" -eq 1 ]; then ok "$(lbl "$1")"; else bad "$(lbl "$1") (exit $st; [ERROR] with: $2)" "$out"; fi
}
warn() {                # warn DESC PATTERN: a [WARNING] line with the pattern, and no [ERROR] line
    if printf '%s\n' "$out" | grep "^\[WARNING\]" | grep -q -- "$2" && ! printf '%s\n' "$out" | grep -q "^\[ERROR\]"; then ok "$(lbl "$1")"; else bad "$(lbl "$1") ([WARNING] with: $2, no [ERROR])" "$out"; fi
}
clean() {               # clean DESC: exit 0, no [ERROR], no [WARNING]
    if [ "$st" -eq 0 ] && ! printf '%s\n' "$out" | grep -q "^\[ERROR\]\|^\[WARNING\]"; then ok "$(lbl "$1")"; else bad "$(lbl "$1") (exit $st; no [ERROR] / [WARNING])" "$out"; fi
}
nowarn() {              # nowarn DESC PATTERN: no [WARNING] / [ERROR] line with the pattern
    if printf '%s\n' "$out" | grep "^\[WARNING\]\|^\[ERROR\]" | grep -q -- "$2"; then bad "$(lbl "$1") (unexpected: $2)" "$out"; else ok "$(lbl "$1")"; fi
}

# ================================================================================================================================
suite() {
BACKEND=$1
echo "== $BACKEND: a clean database"
db_reset; conf; run
clean "a clean database and configuration give no finding"
has "the run says whose rights it used" "with the rights of"
has "the result line counts the zones" "RESULT.*1 zone(s) read, 0 error(s)"
has "a clean database is valid" "\[OK\] .* is valid"
status "exit status 0" 0

echo "== $BACKEND: schema"
NOEXT=1; db_reset; NOEXT=0
conf; run
warn "a plain PowerDNS database: no karidns_* tables" "none of the karidns_\* extension tables exists"
status "a missing extension is a warning, not an error" 0
db_reset
if [ $BACKEND = sqlite3 ]; then sql "DROP TABLE karidns_profiles"; else sql "DROP TABLE karidns_profiles CASCADE"; fi
conf; run
warn "one extension table missing" "table karidns_profiles is missing or incomplete"
db_reset
sql "INSERT INTO karidns_schema_version (version) VALUES (3)"
conf; run
err "a newer schema version" "karidns_schema_version is 3"
db_reset
conf; run
has "the schema version is reported" "karidns_\* schema version"
if [ $BACKEND = sqlite3 ]; then
    db_reset
    sql "ALTER TABLE records DROP COLUMN ttl; ALTER TABLE records DROP COLUMN prio"
    conf; run
    err "a required column is missing (all missing columns named)" "table records has no column ttl, prio"
    db_reset
    sql "DROP TABLE cryptokeys"
    conf; run
    err "a required table is missing" "table cryptokeys is missing"
else
    db_reset
    sql "ALTER TABLE records DROP COLUMN prio"
    conf; run
    err "a required column is missing" "table records has no column prio"
    db_reset
    sql "DROP TABLE cryptokeys CASCADE"
    conf; run
    err "a required table is missing" "table cryptokeys is missing"
fi
echo "-- change log triggers (auto-reload yes)"
db_reset; conf "auto-reload yes;"; run
clean "auto-reload yes with all triggers"
if [ $BACKEND = sqlite3 ]; then sql "DROP TRIGGER karidns_trg_records_upd"; else sql "DROP TRIGGER karidns_trg_records_upd ON records"; fi
conf "auto-reload yes;"; run
err "auto-reload yes: a trigger is missing" "auto-reload yes needs the change log triggers, but 1 are missing: karidns_trg_records_upd"
conf "auto-reload no;"; run
hasnt "auto-reload no: missing triggers are not an error" "triggers"
conf; run
hasnt "no auto-reload (default): missing triggers are not an error" "triggers"
db_reset
if [ $BACKEND = sqlite3 ]; then sql "DROP TABLE karidns_changes"; else sql "DROP TABLE karidns_changes CASCADE"; fi
conf "auto-reload yes;"; run
err "auto-reload yes without karidns_changes" "auto-reload yes needs the change log: table karidns_changes is missing"

echo "== $BACKEND: zones (the reader's errors carry records.id)"
db_reset
sql "$(zone 10 badcontent.test)
$(rec 10 bad.badcontent.test A 999.1.1.1)"
conf; run
err "a content the zone parser rejects: records.id" "badcontent.test.' (domains.id 10): records.id [0-9]*:"
sql "$(zone 11 badtype.test)
$(rec 11 x.badtype.test FOO 'abc')"
conf; run
err "an unsupported record type: records.id" "domains.id 11): records.id [0-9]*:"
db_reset
sql "$(zone 12 outside.test)
$(rec 12 elsewhere.example A 192.0.2.9)"
conf; run
err "a name outside the zone" "outside.test.' (domains.id 12): records.id [0-9]*: .*outside the zone"
db_reset
sql "$(zone 13 ambig.test)
$(rec 13 ambig.test MX '10 mail.ambig.test' 3600 5)"
conf; run
err "prio and content both carry the preference" "ambig.test.' (domains.id 13): records.id [0-9]*: .*ambiguous"
db_reset
sql "$(zone 13 prio.test)
$(rec 13 prio.test MX mail.prio.test 3600 5)
$(rec 13 mail.prio.test A 192.0.2.4)
$(rec 13 prio.test MX '15 mail.prio.test')"
conf; run
nowarn "prio in the column and a content with the preference alone are fine" "ambiguous"
status "no ambiguity: exit 0" 0
db_reset
sql "INSERT INTO domains (id, name, type) VALUES (14, 'nosoa.test', 'NATIVE'); $(rec 14 nosoa.test NS ns1.nosoa.test)"
conf; run
err "no apex SOA" "nosoa.test.' (domains.id 14): .*no enabled SOA"
db_reset
sql "$(zone 15 nullttl.test)
$(rec 15 www.nullttl.test A 192.0.2.5 NULL)"
conf; run
warn "a NULL ttl uses default-ttl" "records.id [0-9]*: 1 record(s) have a NULL ttl"
db_reset; conf "default-ttl 7200;" ; run
nowarn "no NULL ttl, no warning" "NULL ttl"
db_reset
sql "$(zone 16 serial0.test 0)"
conf; run
warn "SOA serial 0" "serial0.test.' (domains.id 16): the SOA serial is 0"
db_reset
sql "$(zone 16 serial1.test 1)"
conf; run
nowarn "SOA serial 1 is fine" "serial is 0"
db_reset
# two rows whose names differ only in case: the SQLite3 schema has a NOCASE unique index and the PostgreSQL schema a lower-case CHECK (as PowerDNS's own does), so those are dropped first
if [ "$BACKEND" = sqlite3 ]; then sql "DROP INDEX name_index"; else sql "ALTER TABLE domains DROP CONSTRAINT c_lowercase_name; ALTER TABLE records DROP CONSTRAINT c_lowercase_name"; fi
sql "$(zone 18 CaseDup.test)
$(zone 19 casedup.test)"
conf; run
warn "names that differ only in case" "domains.id 18 ('CaseDup.test') and domains.id 19 ('casedup.test') have names that differ only in case"
status "names that differ only in case: a warning, exit 0" 0
db_reset
sql "$(zone 18 casedup.test)
$(zone 19 other.test)"
conf; run
nowarn "different names: no case warning" "differ only in case"
db_reset
sql "$(zone 17 cnamex.test)
$(rec 17 www.cnamex.test CNAME ok.test)
$(rec 17 www.cnamex.test A 192.0.2.6)"
conf; run
err "a CNAME beside other data" "cnamex.test.' (domains.id 17): CNAME record at 'www.cnamex.test.' coexists with other record type"
warn_is_err=$(printf '%s\n' "$out" | grep -c "co-exists with other records")
[ "$warn_is_err" -ge 1 ] && ok "$BACKEND: the RFC 1912 warning of karicheck zone too" || bad "$BACKEND: the RFC 1912 warning of karicheck zone" "$out"
db_reset
sql "$(zone 17 cnamey.test)
$(rec 17 www.cnamey.test CNAME ok.test)"
conf; run
nowarn "a CNAME alone is fine" "CNAME"
echo "-- the checks karicheck zone makes (one implementation)"
db_reset
sql "INSERT INTO domains (id, name, type) VALUES (20, 'nons.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (20, 'nons.test', 'SOA', 'ns1.nons.test hostmaster.nons.test 5 3600 600 86400 300', 3600, NULL, '0')"
conf; run
err "no NS at the apex" "nons.test.' (domains.id 20): No NS record found at zone apex"
db_reset
sql "$(zone 21 glue.test)
$(rec 21 sub.glue.test NS ns.sub.glue.test)"
conf; run
err "an in-bailiwick NS target without an address" "glue.test.' (domains.id 21):"
db_reset
sql "$(zone 22 ttlmix.test)
$(rec 22 www.ttlmix.test A 192.0.2.7 300)
$(rec 22 www.ttlmix.test A 192.0.2.8 600)"
conf; run
warn "inconsistent TTLs in an RRset (RFC 2181)" "ttlmix.test.' (domains.id 22): RRset 'www.ttlmix.test.' type 1 has inconsistent TTLs (300 vs 600) in the source database"
db_reset
sql "$(zone 23 dnskey.test)
$(rec 23 dnskey.test DNSKEY '257 3 1 AwEAAcw3')"
conf; run
has "a DNSSEC record with a weak algorithm (RFC 8624)" "dnskey.test.' (domains.id 23): .*DNSSEC algorithm 1"
db_reset
sql "$(zone 24 srvbad.test)
$(rec 24 _sip._udp.srvbad.test SRV '5 70000 srv.srvbad.test.' 3600)"
conf; run
has "an SRV record the zone checks refuse" "srvbad.test.' (domains.id 24):"
echo "-- ALIAS and LUA (design 3.6b)"
db_reset
sql "$(zone 25 alias.test)
$(rec 25 www.alias.test ALIAS target.example.test.)"
conf; run
has "an ALIAS record is reported" "alias.test.' (domains.id 25): .*1 ALIAS record(s)"
status "ALIAS in an unsigned zone is fine" 0
sql "$(meta 25 PRESIGNED 1)"
conf; run
err "ALIAS in a presigned zone" "alias.test.' (domains.id 25):.*PRESIGNED.*ALIAS"
db_reset
sql "$(zone 26 lua.test)
$(rec 26 www.lua.test LUA 'A \"return 1\"')"
conf; run
warn "a LUA record is kept but never answered" "lua.test.' (domains.id 26): .*1 LUA record(s)"
sql "$(meta 26 ENABLE-LUA-RECORDS 1)"
conf; run
has "ENABLE-LUA-RECORDS=1 is reported" "lua.test.' (domains.id 26)"

echo "== $BACKEND: secondaries and catalogs"
db_reset
sql "INSERT INTO domains (id, name, type, master) VALUES (30, 'sec.test', 'SLAVE', NULL)"
conf; run
err "a SLAVE zone without masters" "sec.test.' (domains.id 30):"
db_reset
sql "INSERT INTO domains (id, name, type, master) VALUES (30, 'sec.test', 'SLAVE', '192.0.2.53')"
conf; run
clean "a SLAVE zone with a master"
db_reset
sql "INSERT INTO domains (id, name, type, master) VALUES (31, 'cons.test', 'CONSUMER', NULL)"
conf; run
err "a CONSUMER zone without masters" "cons.test.' (domains.id 31):"
db_reset
sql "INSERT INTO domains (id, name, type, master) VALUES (31, 'cons.test', 'CONSUMER', '192.0.2.53')"
conf; run
clean "a CONSUMER zone with a master"
db_reset
sql "INSERT INTO domains (id, name, type) VALUES (32, 'cat.test', 'PRODUCER')"
conf; run
warn "a PRODUCER zone is a warning: the catalog zone is not served, nothing else is wrong" "cat.test.' (domains.id 32): the catalog zone cat.test. is not served (catalog producer zones are not supported yet); its 0 member zones are served; secondaries that take the catalog from KariDNS will not get it"
status "a PRODUCER zone alone: exit 0 (D9: only the catalog zone itself is missing)" 0
db_reset
sql "INSERT INTO domains (id, name, type) VALUES (32, 'cat.test', 'PRODUCER');
$(zone 34 m1.test)
$(zone 35 m2.test)
UPDATE domains SET catalog = 'cat.test' WHERE id IN (34, 35)"
conf; run
warn "a PRODUCER zone with members: they are counted as served" "cat.test.' (domains.id 32): the catalog zone cat.test. is not served .*its 2 member zones are served; secondaries"
status "a PRODUCER zone with members: exit 0" 0
nowarn "the members of a PRODUCER zone have a catalog to name" "domains.catalog names"
has "the PRODUCER zone and its members are read, no error" "RESULT.*4 zone(s) read, 0 error(s)"
db_reset
sql "$(zone 33 member.test)
UPDATE domains SET catalog = 'nocat.test' WHERE id = 33"
conf; run
warn "domains.catalog names a zone that is no PRODUCER" "member.test.' (domains.id 33): domains.catalog names 'nocat.test'"

echo "== $BACKEND: keys and presigned zones"
db_reset
sql "$(zone 40 keys.test)
INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (40, 257, '1', 'x')"
conf; run
err "cryptokeys without PRESIGNED" "keys.test.' (domains.id 40): the zone has cryptokeys but no PRESIGNED=1"
sql "$(meta 40 PRESIGNED 1)"
conf; run
nowarn "cryptokeys with PRESIGNED=1 pass this check" "cryptokeys"
db_reset
sql "$(zone 41 n3syn.test)
$(meta 41 PRESIGNED 1)
$(meta 41 NSEC3PARAM 'x y z')"
conf; run
err "NSEC3PARAM metadata with a bad syntax" "n3syn.test.' (domains.id 41):"
db_reset
sql "$(zone 42 n3.test)
$(meta 42 PRESIGNED 1)
$(meta 42 NSEC3PARAM '1 0 0 -')"
conf; run
err "a presigned NSEC3 zone without a chain" "n3.test.' (domains.id 42):.*NSEC3"
db_reset
sql "$(zone 43 n3ok.test)
$(meta 43 NSEC3PARAM '1 0 0 -')"
conf; run
nowarn "NSEC3PARAM without PRESIGNED is not a presigned zone" "NSEC3"
signed_cases

echo "== $BACKEND: settings from metadata and profiles"
db_reset
sql "$(zone 50 prof.test)
$(meta 50 X-KARIDNS-PROFILE badp)
INSERT INTO karidns_profiles (name, settings) VALUES ('badp', 'file \"/etc/passwd\";')"
conf; run
err "a profile whose settings do not parse in restricted mode" "prof.test.' (domains.id 50): the settings text of the profile 'badp' does not parse"
hasnt "the parser's own lines about the zone 'settings.' are not printed" "zone 'settings.'"
has "the reason of the parser is in the message" "profile 'badp' does not parse in restricted mode: .*file"
sql "UPDATE karidns_profiles SET settings = 'also-notify { 192.0.2.7; };'"
conf; run
nowarn "a profile that parses" "does not parse"
status "the good profile: exit 0" 0
db_reset
sql "$(zone 51 nopro.test)
$(meta 51 X-KARIDNS-PROFILE nosuch)"
conf; run
err "a profile that is not defined" "nopro.test.' (domains.id 51): the profile 'nosuch'"
echo "-- TSIG key names"
db_reset
sql "$(zone 52 key.test)
$(meta 52 TSIG-ALLOW-AXFR nokey)"
conf; run
err "a TSIG key the configuration does not define" "key.test.' (domains.id 52): .*TSIG key 'nokey'"
db_reset
sql "$(zone 52 key.test)
$(meta 52 TSIG-ALLOW-AXFR xfr)"
conf; run
nowarn "a TSIG key that is defined" "TSIG key"
status "a defined key: exit 0" 0
echo "-- acl-ceiling"
db_reset
sql "$(zone 53 acl.test)
$(meta 53 ALLOW-AXFR-FROM 198.51.100.0/24)"
conf; run
warn "an ACL entry outside acl-ceiling" "acl.test.' (domains.id 53): allow-transfer entry '198.51.100.0/24' is outside acl-ceiling"
db_reset
sql "$(zone 53 acl.test)
$(meta 53 ALLOW-AXFR-FROM 192.0.2.64/26)"
conf; run
nowarn "an ACL entry inside acl-ceiling" "outside acl-ceiling"
status "inside the ceiling: exit 0" 0
db_reset
sql "$(zone 53 acl.test)
$(meta 53 ALLOW-AXFR-FROM 192.0.2.0/23)"
conf; run
warn "an ACL entry wider than acl-ceiling" "allow-transfer entry '192.0.2.0/23' is outside acl-ceiling"
db_reset
sql "$(zone 53 acl.test)
$(meta 53 ALLOW-DNSUPDATE-FROM 203.0.113.1)"
conf; run
warn "an allow-update entry outside acl-ceiling" "allow-update entry '203.0.113.1' is outside acl-ceiling"
db_reset
sql "$(zone 54 aclkey.test)
$(meta 54 TSIG-ALLOW-AXFR upd)"
conf '' 'key "upd" { algorithm hmac-sha256; secret "'$SECRET'"; };'; run
warn "a key that acl-ceiling does not list" "aclkey.test.' (domains.id 54): allow-transfer key 'upd' is not listed in acl-ceiling"
db_reset
sql "$(zone 53 acl.test)
$(meta 53 ALLOW-AXFR-FROM 192.0.2.8)"
conf '' '' ''; run
warn "an ACL while no acl-ceiling is configured" "acl.test.' (domains.id 53): .*acl-ceiling is not configured"
db_reset
conf '' '' ''; run
nowarn "no ACL, no ceiling: nothing to say" "acl-ceiling"

echo "== $BACKEND: D-PRIO and D-PROG (zones of karidns.conf with the same name)"
db_reset
sql "$(zone 60 file.test)"
conf; run
warn "a zone with file hides the database zone" "file.test.' (domains.id 60): D-PRIO: .*file.zone"
db_reset
sql "$(zone 61 prog.test)"
conf '' 'zone "prog.test" { type program; program "/bin/true"; };' ; run
has "a type program zone hides the database zone" "prog.test.' (domains.id 61): D-PROG: .*type program"
db_reset
sql "$(zone 62 fwd.test)"
conf '' 'zone "fwd.test" { type forward; forwarders { 192.0.2.53; }; };'; run
has "a type forward zone hides the database zone" "fwd.test.' (domains.id 62): D-PROG: .*type forward"
db_reset
conf; run
nowarn "no zone of that name in karidns.conf" "D-PRIO\|D-PROG"

echo "== $BACKEND: views"
view_conf() { NOFILEZONE=1; conf '' 'view "va" { match-clients { 127.0.0.2; }; zone "file.test" { type master; file "'$T'/file.zone"; }; };
view "vb" { match-clients { 127.0.0.3; }; };
view "vnone" { match-clients { 127.0.0.4; }; database none; };'; NOFILEZONE=0; }
db_reset
sql "$(zone 70 map.test)
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (70, 'va')"
view_conf; run
clean "a mapping row naming a view that reads the source"
db_reset
sql "$(zone 70 map.test)
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (70, 'VA'), (70, 'ghost')"
view_conf; run
warn "a mapping row naming an undefined view" "map.test.' (domains.id 70): karidns_domain_views names the view 'ghost', which is not defined"
nowarn "view names compare case-insensitively" "view 'VA'"
db_reset
sql "$(zone 70 map.test)
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (70, 'vnone')"
view_conf; run
warn "a mapping row naming a view that does not read the source" "map.test.' (domains.id 70): karidns_domain_views names the view 'vnone', which does not read"
has "a zone only such rows map is served by no view" "map.test.' (domains.id 70): karidns_domain_views maps the zone only to views that do not read it"
echo "-- karicheck db VIEW"
db_reset
sql "$(zone 71 onlya.test)
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (71, 'va');
$(zone 72 onlyb.test)
INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (72, 'vb');
$(rec 71 www.onlya.test A 192.0.2.7 NULL)
$(rec 72 www.onlyb.test A 192.0.2.8 NULL)"
view_conf; "$KC" db "$T/k.conf" > /dev/null 2>&1
out=$("$KC" db va "$T/k.conf" 2>&1); st=$?
has "db VIEW shows the zone mapped to the view" "onlya.test.' (domains.id 71)"
hasnt "db VIEW does not show the zone mapped to another view" "onlyb.test"
out=$("$KC" db vb "$T/k.conf" 2>&1); st=$?
has "the other view sees its own zone" "onlyb.test.' (domains.id 72)"
out=$("$KC" db "$T/k.conf" 2>&1); st=$?
has "db without a view shows every zone" "onlya.test.' (domains.id 71)"
has "db without a view shows every zone (2)" "onlyb.test.' (domains.id 72)"
db_reset
sql "$(zone 74 file.test)"
view_conf
out=$("$KC" db va "$T/k.conf" 2>&1); st=$?
has "db VIEW: D-PRIO for the view that has the zone in karidns.conf" "file.test.' (domains.id 74): D-PRIO: the view 'va' has a zone"
out=$("$KC" db vb "$T/k.conf" 2>&1); st=$?
hasnt "db VIEW: no D-PRIO for a view that has no such zone" "D-PRIO"
out=$("$KC" db ghost "$T/k.conf" 2>&1); st=$?
err "an undefined view" "The view 'ghost' is not defined"
out=$("$KC" db vnone "$T/k.conf" 2>&1); st=$?
err "a view with database none" "takes no zones from the database"
if [ $BACKEND = sqlite3 ]; then
    echo "-- a view with a database of its own"
    db_reset
    sql "$(zone 73 shared.test)"
    cp "$DB" "$T/own.db"; sqlite3 "$T/own.db" "UPDATE domains SET name='private.test' WHERE id=73; UPDATE records SET name=replace(name,'shared.test','private.test'), content=replace(content,'shared.test','private.test') WHERE domain_id=73" 2>/dev/null; own "$T/own.db" "$T/own.db-wal" "$T/own.db-shm" 2>/dev/null
    NOFILEZONE=1; conf '' 'view "va" { match-clients { 127.0.0.2; }; };
view "vown" { match-clients { 127.0.0.4; }; database-file "'$T'/own.db"; };'; NOFILEZONE=0; run
    has "a view with its own database file: two databases are checked" "Checked 2 databases"
    out=$("$KC" db vown "$T/k.conf" 2>&1); st=$?
    has "db VIEW of a view with its own file checks that file" "own.db"
    hasnt "db VIEW of a view with its own file leaves the global one" "z.db"
fi
}

# ---------------------------------------------------------------- the presigned NSEC3 chain (needs BIND)
signed_cases() {
    if ! command -v dnssec-keygen >/dev/null 2>&1 || ! command -v dnssec-signzone >/dev/null 2>&1 || [ ! -x "$ROOT/tests/db/zone2sql" ]; then
        echo "  [SKIP] presigned NSEC3 chain: dnssec-keygen / dnssec-signzone or tests/db/zone2sql is missing"
        return
    fi
    if [ ! -f "$T/signed/sg.test.signed" ]; then
        mkdir -p "$T/signed"
        printf '$TTL 300\n@ IN SOA ns1 host 1 3600 600 86400 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.2\nmail IN A 192.0.2.3\n@ IN MX 10 mail\nx.y IN A 192.0.2.4\n' > "$T/signed/sg.test.zone"
        ( cd "$T/signed" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK sg.test > /dev/null 2>&1 && dnssec-keygen -q -a ECDSAP256SHA256 sg.test > /dev/null 2>&1 &&
          dnssec-signzone -q -S -K . -3 - -H 0 -o sg.test -f sg.test.signed sg.test.zone > /dev/null 2>&1 ) || { echo "  [SKIP] presigned NSEC3 chain: dnssec-signzone failed"; rm -f "$T/signed/sg.test.signed"; return; }
    fi
    dialect=sqlite3; [ $BACKEND = postgresql ] && dialect=pgsql
    db_reset
    "$ROOT/tests/db/zone2sql" --dialect $dialect "$T/signed/sg.test.signed" > "$T/signed/sg.sql" 2> "$T/signed/sg.err" || { bad "$BACKEND: zone2sql of the signed zone" "$(cat "$T/signed/sg.err")"; return; }
    if [ $BACKEND = sqlite3 ]; then sqlite3 "$DB" < "$T/signed/sg.sql" > "$T/sql.out" 2>&1; else pf "$T/signed/sg.sql" > "$T/sql.out" 2>&1; fi
    [ $? -eq 0 ] || bad "$BACKEND: import of the signed zone" "$(cat "$T/sql.out")"
    [ $BACKEND = sqlite3 ] && own "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    conf; run
    nowarn "a consistent presigned NSEC3 zone passes" "sg.test.*NSEC3\|sg.test.*ordername\|sg.test.*RRSIG"
    status "a consistent presigned NSEC3 zone: exit 0" 0
    sql "UPDATE records SET ordername = 'zzzz' WHERE id = (SELECT min(id) FROM records WHERE name = 'www.sg.test' AND type = 'A')"
    conf; run
    err "a presigned NSEC3 zone whose ordername is not the hash" "sg.test.' (domains.id [0-9]*): presigned zone: ordername 'zzzz' of 'www.sg.test.' is not its NSEC3 hash"
    db_reset
    "$ROOT/tests/db/zone2sql" --dialect $dialect "$T/signed/sg.test.signed" > "$T/signed/sg.sql" 2>/dev/null
    if [ $BACKEND = sqlite3 ]; then sqlite3 "$DB" < "$T/signed/sg.sql" > "$T/sql.out" 2>&1; else pf "$T/signed/sg.sql" > "$T/sql.out" 2>&1; fi
    [ $BACKEND = sqlite3 ] && own "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    sql "DELETE FROM records WHERE type = 'RRSIG' AND content LIKE 'NSEC3 %' AND id = (SELECT min(id) FROM records WHERE type = 'RRSIG' AND content LIKE 'NSEC3 %')"
    conf; run
    err "a presigned NSEC3 chain with a missing RRSIG(NSEC3)" "sg.test.' (domains.id [0-9]*):"
}

# ================================================================================================================================
suite sqlite3

echo "== sqlite3: rights, files and the loader"
BACKEND=sqlite3
db_reset; conf; run
if [ $IS_ROOT = 1 ]; then
    has "root: the loader runs as loader-user" "with the rights of loader-user '$LUSER'"
    # the file belongs to root and is private: the loader user cannot read it
    chown 0:0 "$DB" "$DB-wal" "$DB-shm" 2>/dev/null; chmod 600 "$DB"
    conf; run
    err "root: the database file is unreadable for loader-user: file and permission named" "database file '$DB' is not readable by the user $LUSER.*read permission"
    status "root: an unreadable file is exit 1" 1
    own "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    mkdir "$T/priv" && chmod 700 "$T/priv" && chown 0:0 "$T/priv"
    cp "$DB" "$T/priv/z.db"
    DB_SAVE=$DB; DB=$T/priv/z.db; conf; run; DB=$DB_SAVE
    err "root: a directory loader-user cannot search" "no search (x) permission on the directory '$T/priv'"
    conf '' '' ; sed 's/loader-user "[^"]*"; //' "$T/k.conf" > "$T/nouser.conf"
    out=$("$KC" db "$T/nouser.conf" 2>&1); st=$?
    err "root without loader-user: no check is run" "karicheck is run by root, but options { database { loader-user } } is not set"
    DBUSER=no-such-user-b12; conf; run; DBUSER=
    err "root: a loader-user that does not exist" "loader-user 'no-such-user-b12' does not exist"
else
    has "another user: its own rights" "with the rights of the user $ME"
    DBUSER=root; conf; run; DBUSER=
    has "another user, and loader-user is someone else: the run says that permission findings can differ" "loader-user is 'root', so what the files allow can differ"
    conf; run
    chmod 000 "$DB"
    conf; run
    err "the database file is unreadable: file and permission named" "database file '$DB' is not readable by the user $ME.*read permission"
    status "an unreadable file is exit 1" 1
    chmod 400 "$DB"
    conf; run
    err "a database file the user cannot write (SQLite needs it for -shm)" "database file '$DB' is not writable by the user $ME"
    chmod 600 "$DB"
    mkdir "$T/priv" && cp "$DB" "$T/priv/z.db" && chmod 000 "$T/priv"
    DB_SAVE=$DB; DB=$T/priv/z.db; conf; run; DB=$DB_SAVE
    chmod 700 "$T/priv"
    err "a directory the user cannot search" "no search (x) permission on the directory '$T/priv'"
fi
rm -f "$DB" "$DB-wal" "$DB-shm"
conf; run
err "a database file that does not exist" "database file '$DB': No such file or directory"
# the ownership and the mode of the loader, as karidns wants them (dns_db_supervisor.c): an error before the loader is run
printf '#!/bin/sh\ntouch "%s/ran"\n' "$T" > "$T/dbl_gw"; chmod 775 "$T/dbl_gw"; own "$T/dbl_gw"
rm -f "$T/ran"
LOADERPATH=$T/dbl_gw; conf; run; LOADERPATH=
err "a loader writable by group: error" "database loader '$T/dbl_gw' is writable by group or others"
status "a loader writable by group: exit 1" 1
[ -e "$T/ran" ] && bad "$BACKEND: a group-writable loader was run" || ok "$BACKEND: a group-writable loader is not run"
printf '#!/bin/sh\ntouch "%s/ran"\n' "$T" > "$T/dbl_other"; chmod 755 "$T/dbl_other"
OTHER_OK=0
if [ $IS_ROOT = 1 ]; then
    chown "$LUSER" "$T/dbl_other" && OTHER_OK=1
elif [ "$ME" != nobody ] && sudo -n chown nobody "$T/dbl_other" 2>/dev/null; then
    OTHER_OK=1
fi
if [ $OTHER_OK = 1 ]; then
    LOADERPATH=$T/dbl_other; conf; run; LOADERPATH=
    err "a loader owned by another non-root user: error" "database loader '$T/dbl_other' is not owned by root.*(uid [1-9][0-9]*); karidns refuses to run it"
    status "a loader owned by another non-root user: exit 1" 1
    [ -e "$T/ran" ] && bad "$BACKEND: a loader of another user was run" || ok "$BACKEND: a loader of another user is not run"
else
    echo "  [SKIP] a loader owned by another non-root user (needs passwordless sudo to chown)"
fi
db_reset
LOADERPATH=$T/nope; conf; run; LOADERPATH=
err "no loader: DB support is not installed" "DB support is not installed"
status "no loader: exit 1" 1
cat > "$T/fake_dbl" <<'EOF2'
#!/bin/sh
if [ "$1" = --drivers ]; then echo sqlite3; exit 0; fi
echo "karidns-dbloader: driver postgresql is not available in this build (compiled in: sqlite3)" >&2
exit 2
EOF2
chmod 755 "$T/fake_dbl"
printf 'options {\n  user "%s";\n  database { driver postgresql; conninfo-file "%s"; loader-user "%s"; loader-path "%s/fake_dbl"; };\n};\n' "$ME" "$CI" "$LUSER" "$T" > "$T/fake.conf"
out=$("$KC" db "$T/fake.conf" 2>&1); st=$?
err "a loader without the driver" "driver postgresql is not available"
printf 'options {\n  user "%s";\n  database { driver postgresql; loader-user "%s"; loader-path "%s/dbl"; };\n};\n' "$ME" "$LUSER" "$T" > "$T/noci.conf"
out=$("$KC" db "$T/noci.conf" 2>&1); st=$?
err "driver postgresql without a conninfo-file (the configuration parser says so)" "driver postgresql needs 'conninfo-file'"
printf 'options { user "%s"; };\n' "$ME" > "$T/nodb.conf"
out=$("$KC" db "$T/nodb.conf" 2>&1); st=$?
err "no database block" "no options { database { } } block"
out=$("$KC" db "$T/does-not-exist.conf" 2>&1); st=$?
err "a configuration that does not exist" "Could not open file"
printf 'options { database {
' > "$T/junk.conf"
out=$("$KC" db "$T/junk.conf" 2>&1); st=$?
err "a configuration that does not parse" "Syntax error in config file"
db_reset
# fake loaders: what karicheck does with a loader that misbehaves (--drivers answers, so the loader looks installed)
cat > "$T/noise_dbl" <<'EOF2'
#!/bin/sh
if [ "$1" = --drivers ]; then echo sqlite3; exit 0; fi
echo "this is not the protocol"
exit 3
EOF2
cat > "$T/odd_dbl" <<'EOF2'
#!/bin/sh
if [ "$1" = --drivers ]; then echo sqlite3; exit 0; fi
printf 'E\t\t0\tonly\tfour\tfields\textra\n'
printf 'Z\tbad\\9\t1\tprimary\t*\n'
printf 'R\t0\t0\t0\n'
exit 0
EOF2
cat > "$T/esc_dbl" <<'EOF2'
#!/bin/sh
if [ "$1" = --drivers ]; then echo sqlite3; exit 0; fi
printf 'E\t\t0\t\033[31mred\\001 and a \033 escape\n'
printf 'W\tx.test.\t1\tfine \\065 text\n'
printf 'R\t0\t1\t1\n'
exit 1
EOF2
chmod 755 "$T/noise_dbl" "$T/odd_dbl" "$T/esc_dbl"
LOADERPATH=$T/noise_dbl; conf; run; LOADERPATH=
err "a loader that exits with an error and says something else" "could not check the database: this is not the protocol"
LOADERPATH=$T/odd_dbl; conf; run; LOADERPATH=
has "lines that are not in the protocol are counted, not printed raw" "not part of its protocol"
has "a zone line that does not decode is an error" "zone line that does not decode"
LOADERPATH=$T/esc_dbl; conf; run; LOADERPATH=
hasnt "a loader cannot put a control character on the terminal" "$(printf '\033')"
has "its escapes are decoded and printed" "fine A text"
echo "== usage and the examples of --help"
out=$("$KC" 2>&1); st=$?
has "the usage names the db command" "karicheck[-a-z]* db \[view\] \[config_path\]"
db_reset; conf
out=$("$KC" db "$T/k.conf" 2>&1); st=$?
status "example: karicheck db CONFIG" 0
out=$("$KC" db va "$T/k.conf" 2>&1); st=$?
err "example: karicheck db VIEW CONFIG (the view must exist)" "view 'va' is not defined"
out=$("$KC" db a b c d 2>&1); st=$?
status "too many arguments" 1

# ================================================================================================================================
if "$LOADER" --drivers | grep -qx postgresql; then
    if pg_setup kcdb; then
        [ -n "$PG_AS" ] && LUSER=$PG_AS
        if [ $IS_ROOT = 1 ] && [ -n "$PG_AS" ]; then own() { chown "$PG_AS" "$@"; return 0; }; fi
        # Who the loader is in the database.  With CREATE ROLE available it is a role with the privileges of
        # db/karidns_loader_role.pgsql.sql (the session switches to it with options='-c role=...').  Without, it is the owner of the
        # tables, which can read the keys: that one warning is filtered from the output (PGOWNER) and the role script is not run
        # (its ALTER ROLE would change the settings of the user who runs the test).
        RL=karidns_kcdb_$$
        PGRL=""
        PGOWNER=0
        if pq "CREATE ROLE $RL NOLOGIN" >/dev/null 2>&1 && pq "GRANT $RL TO CURRENT_USER" >/dev/null 2>&1; then
            PGROLES="$RL"
            PGRL=$RL
            printf "%s options='-c role=%s'\n" "$PGC" "$RL" > "$CI"; chmod 600 "$CI"; own "$CI"
        else
            RL=$(pq "SELECT current_user")
            PGOWNER=1
            echo "  (no CREATE ROLE: the loader connects as $RL, the owner of the tables)"
            pg_conninfo_file "$CI"
        fi
        suite postgresql
        echo "== postgresql: the conninfo-file and the role"
        BACKEND=postgresql
        db_reset; conf; run
        clean "(again) a clean PostgreSQL database"
        if [ $IS_ROOT = 1 ]; then
            chown 0:0 "$CI"
            conf; run
            err "root: the conninfo-file is unreadable for loader-user: file named" "conninfo-file '$CI' is not readable by the user $LUSER.*read permission"
            chmod 644 "$CI"
            conf; run
            err "root: a conninfo-file that belongs to another user: file and owner named" "conninfo-file '$CI' is owned by uid 0; the loader refuses it unless it is owned by the user it runs as"
            chmod 600 "$CI"
            own "$CI"
        else
            chmod 000 "$CI"
            conf; run
            err "the conninfo-file is unreadable: file and permission named" "conninfo-file '$CI' is not readable by the user $ME.*read permission"
            chmod 600 "$CI"
        fi
        chmod 644 "$CI"
        conf; run
        err "a conninfo-file with a wrong mode: file and mode named" "conninfo-file '$CI' has mode 0644; the loader requires 0600 or 0400"
        chmod 600 "$CI"
        sed "s#$CI#$T/ci.nothere#" "$T/k.conf" > "$T/k2.conf"
        out=$("$KC" db "$T/k2.conf" 2>&1); st=$?
        err "a conninfo-file that does not exist" "conninfo-file '$T/ci.nothere': No such file or directory"
        echo "-- the privileges of the role"
        db_reset
        pq "REVOKE SELECT ON records FROM $RL" >/dev/null 2>&1
        conf; run
        err "a role that cannot SELECT from the PowerDNS tables" "the role $RL cannot SELECT from table records"
        db_reset
        pq "REVOKE SELECT ON karidns_profiles FROM $RL" >/dev/null 2>&1
        conf; run
        err "a role that cannot SELECT from a karidns_* table" "the role $RL cannot SELECT from table karidns_profiles"
        db_reset
        pq "REVOKE ALL ON cryptokeys FROM $RL" >/dev/null 2>&1
        conf; run
        err "a role without the cryptokeys.domain_id column privilege" "the role $RL cannot SELECT cryptokeys.domain_id"
        db_reset
        pq "REVOKE ALL ON cryptokeys FROM $RL; GRANT SELECT ON cryptokeys TO $RL" >/dev/null 2>&1
        SAVE_OWNER=$PGOWNER; PGOWNER=0
        conf; run
        PGOWNER=$SAVE_OWNER
        warn "a role that can read cryptokeys.content" "the role $RL can read cryptokeys.content"
        db_reset
        pq "REVOKE INSERT, UPDATE ON karidns_server_status FROM $RL" >/dev/null 2>&1
        conf; run
        warn "a role that cannot write karidns_server_status" "the role $RL cannot INSERT or UPDATE karidns_server_status"
        db_reset
        pq "REVOKE INSERT ON karidns_server_status FROM $RL" >/dev/null 2>&1
        conf; run
        warn "a role that cannot INSERT into karidns_server_status" "the role $RL cannot INSERT into karidns_server_status"
        db_reset
        pq "DROP TABLE karidns_server_status CASCADE" >/dev/null 2>&1
        conf; run
        warn "only one of the multi-server tables" "only one of karidns_reload_requests and karidns_server_status exists"
        pq "DROP TABLE karidns_reload_requests CASCADE" >/dev/null 2>&1
        conf; run
        nowarn "no server-id, no multi-server tables: nothing to say" "server-id\|multi-server\|karidns_reload"
        conf 'server-id "ns1";'; run
        warn "server-id is set but the multi-server tables are missing" "server-id is set but karidns_reload_requests and karidns_server_status do not exist"
        db_reset
        conf 'server-id "ns1";'; run
        clean "server-id with the multi-server tables"
        if [ -n "$PGRL" ]; then
            db_reset
            pq "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM $RL" >/dev/null 2>&1
            psql -X -q -At -v ON_ERROR_STOP=1 -v role=$RL -v schema=public "$PGC" -f "$ROOT/db/karidns_loader_role.pgsql.sql" > "$T/role.out" 2>&1 || bad "the role script" "$(cat "$T/role.out")"
            conf; run
            clean "a role set up by db/karidns_loader_role.pgsql.sql has no privilege finding"
        else
            echo "  [SKIP] postgresql: the role script is not run without CREATE ROLE (its ALTER ROLE would change the user of the test)"
        fi
    fi
else
    echo "== postgresql: SKIP: karidns-dbloader has no PostgreSQL driver (make karidns-dbloader DB_DRIVERS=\"sqlite3 postgresql\")"
fi

echo
echo "== $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
