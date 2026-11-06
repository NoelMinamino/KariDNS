#!/bin/sh
# auth_rls_bench.sh - what row level security (RLS) and the audit log cost (0.6.0 item B, milestone M3; docs/karidns-dbloader.md, "Measurements").
# Not part of the test suite: it builds a private database, fills it, measures, and drops it again.
#
# Usage: sh tests/perf/auth_rls_bench.sh
#   PGHOST / PGPORT / PGUSER (the usual libpq variables) name a PostgreSQL server that the user may create databases and roles on, as a superuser.
#   Run it on a private server (a test cluster), never on a production one.  Run it from the top of the source tree.
#   ZONE=./karidns-zone   the importer, built with a PostgreSQL driver (DB_DRIVERS="sqlite3 postgresql"); without it the import part is skipped
#   RECORDS=100000        records of the big zone          ZONES=100000   zones of the second round (scale)
#   GRANTS=10000          grants of the second round       RUNS=3         runs per measurement (the median is printed)
#   KEEP=1                keep the database and roles (names are printed)
#
# What it measures (times in ms, client side; rows go to /dev/null):
#   select       SELECT * FROM records of the big zone: the owner (no RLS), a role in karidns_rls_trusted (RLS on, policy true), and karidns_api with
#                karidns.principal = a user that is in a group that is domain master of the zone
#   change set   INSERT, UPDATE, DELETE of 1000 records (one multi-row statement and one transaction each), the owner and karidns_api
#   lookups      the grant lookups again, with ZONES zones and GRANTS grants (scale), and EXPLAIN of the lookups
#   import       karidns-zone import (replace) of the big zone as the writer role: audit off, --audit rows, --audit summary
# Memory: the data is made with generate_series in SQL, nothing big is held in the shell.  Set shared_buffers modestly on a shared machine.
set -eu
RECORDS=${RECORDS:-100000}; ZONES=${ZONES:-100000}; GRANTS=${GRANTS:-10000}; RUNS=${RUNS:-3}; ZONE=${ZONE:-./karidns-zone}
[ -f db/karidns_ext.pgsql.sql ] || { echo "run from the top of the source tree" >&2; exit 2; }
PGOPTIONS="-c client_min_messages=warning"; export PGOPTIONS
DB=karidns_rlsbench_$$; API=kb_api_$$; WR=kb_wr_$$
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rlsbench.XXXXXX")
P="psql -X -q -At -v ON_ERROR_STOP=1 -d $DB"
PM="psql -X -q -At -v ON_ERROR_STOP=1 -d postgres"
cleanup() {
    [ "${KEEP:-}" = 1 ] && { echo "kept: database $DB, roles $API $WR, directory $WORK"; return; }
    $PM -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" > /dev/null 2>&1
    $PM -c "DROP ROLE IF EXISTS $API" > /dev/null 2>&1
    $PM -c "DROP ROLE IF EXISTS $WR" > /dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

$PM -c "CREATE DATABASE $DB" > /dev/null
$PM -c "CREATE ROLE $WR LOGIN" > /dev/null
$P -f tests/db/pdns_schema.pgsql.sql > /dev/null
$P -f db/karidns_ext.pgsql.sql > /dev/null

# ---- data: the big zone, a small auth fixture (a user in a group in a group, the group is domain master of the big zone)
BIGSQL="$WORK/big.sql"
cat > "$BIGSQL" <<EOF
INSERT INTO domains (name, type) VALUES ('big.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio)
SELECT d.id, v.name, v.type, v.content, 3600, NULL FROM domains d, (VALUES
  ('big.test', 'SOA', 'ns1.big.test hostmaster.big.test 1 7200 3600 1209600 300'),
  ('big.test', 'NS', 'ns1.big.test'), ('big.test', 'NS', 'ns2.big.test'),
  ('ns1.big.test', 'A', '192.0.2.1'), ('ns2.big.test', 'A', '192.0.2.2')) AS v(name, type, content) WHERE d.name = 'big.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio)
SELECT d.id, 'h' || i || '.big.test', CASE i % 5 WHEN 1 THEN 'AAAA' WHEN 2 THEN 'TXT' WHEN 3 THEN 'MX' ELSE 'A' END,
       CASE i % 5 WHEN 1 THEN '2001:db8::' || to_hex(i % 65536) WHEN 2 THEN '"v=' || i || '"' WHEN 3 THEN 'ns1.big.test'
                  ELSE '192.0.2.' || (i % 250 + 1) END,
       300, CASE i % 5 WHEN 3 THEN 10 END
  FROM domains d, generate_series(1, $RECORDS - 5) AS i WHERE d.name = 'big.test';
INSERT INTO karidns_auth.rr_policies (name, allowed_types, ttl_min, ttl_max) VALUES ('std', ARRAY['A','AAAA','CNAME','MX','TXT','SRV'], 60, 86400);
INSERT INTO karidns_auth.principals (kind, name) VALUES ('user', 'bm'), ('user', 'gm'), ('group', 'team'), ('group', 'org');
INSERT INTO karidns_auth.memberships (member_id, group_id)
SELECT m.id, g.id FROM karidns_auth.principals m, karidns_auth.principals g WHERE (m.name, g.name) IN (('bm', 'team'), ('team', 'org'));
INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id)
SELECT p.id, 'domain_master', 'public', 'big.test', (SELECT id FROM karidns_auth.rr_policies WHERE name = 'std') FROM karidns_auth.principals p WHERE p.name = 'team';
INSERT INTO karidns_auth.grants (principal_id, role, rr_policy_id)
SELECT p.id, 'global_master', (SELECT id FROM karidns_auth.rr_policies WHERE name = 'std') FROM karidns_auth.principals p WHERE p.name = 'gm';
EOF
$P -f "$BIGSQL" > /dev/null
$P -f db/karidns_writer_role.pgsql.sql -v role="$WR" -v schema=public > /dev/null 2>&1
$P -f db/karidns_api_role.pgsql.sql -v role="$API" -v schema=public > /dev/null 2>&1
$P -c "ANALYZE" > /dev/null
BIG=$($P -c "SELECT id FROM domains WHERE name = 'big.test'")
BM=$($P -c "SELECT id FROM karidns_auth.principals WHERE name = 'bm'")
GM=$($P -c "SELECT id FROM karidns_auth.principals WHERE name = 'gm'")
echo "== $($P -c "SELECT count(*) FROM records") records in the big zone, $($P -c "SELECT count(*) FROM karidns_auth.grants") grants, $($P -c "SELECT count(*) FROM domains") zones, server $($P -c "SHOW server_version") shared_buffers $($P -c "SHOW shared_buffers")"

# ---- helpers
# tsql ROLE PRINCIPAL SQL: SQL as ROLE (owner = the session user) in one transaction, with karidns.principal when given; prints the ms of SQL + COMMIT
tsql() {
    {
        echo "BEGIN;"
        [ "$1" = owner ] || echo "SET LOCAL ROLE $1;"
        [ -z "$2" ] || echo "SET LOCAL karidns.principal = '$2';"
        echo '\timing on'
        echo '\o /dev/null'
        echo "$3;"
        echo '\o'
        echo "COMMIT;"
        echo '\timing off'
    } | $P | awk '/^Time:/ { s += $2 } END { printf "%.1f\n", s }'
}
median() { printf '%s\n' "$@" | sort -n | awk '{ a[NR] = $1 } END { printf "%.1f\n", a[int((NR + 1) / 2)] }'; }
# meas LABEL ROLE PRINCIPAL SQL: RUNS runs, the median
meas() {
    _l=$1; _r=$2; _p=$3; _s=$4; _v=""; _i=0
    while [ $_i -lt "$RUNS" ]; do _v="$_v $(tsql "$_r" "$_p" "$_s")"; _i=$((_i + 1)); done
    # shellcheck disable=SC2086
    printf '%-58s %10s ms   (runs:%s)\n' "$_l" "$(median $_v)" "$_v"
}
SELALL="SELECT * FROM records WHERE domain_id = $BIG"
# changeset ROUND-LABEL ROLE PRINCIPAL: INSERT, UPDATE, DELETE of 1000 records, RUNS times; the medians
changeset() {
    _ti=""; _tu=""; _td=""; _i=0
    while [ $_i -lt "$RUNS" ]; do
        _i=$((_i + 1))
        _ti="$_ti $(tsql "$2" "$3" "INSERT INTO records (domain_id, name, type, content, ttl) SELECT $BIG, 'cs$_i-' || g || '.big.test', 'A', '192.0.2.' || (g % 250 + 1), 300 FROM generate_series(1, 1000) AS g")"
        _lo=$($P -c "SELECT min(id) FROM records WHERE domain_id = $BIG AND name LIKE 'cs$_i-%.big.test'")
        _hi=$($P -c "SELECT max(id) FROM records WHERE domain_id = $BIG AND name LIKE 'cs$_i-%.big.test'")
        _tu="$_tu $(tsql "$2" "$3" "UPDATE records SET content = '192.0.2.250', ttl = 600 WHERE domain_id = $BIG AND id BETWEEN $_lo AND $_hi")"
        _td="$_td $(tsql "$2" "$3" "DELETE FROM records WHERE domain_id = $BIG AND id BETWEEN $_lo AND $_hi")"
    done
    # shellcheck disable=SC2086
    printf '%-58s %10s ms   (runs:%s)\n%-58s %10s ms   (runs:%s)\n%-58s %10s ms   (runs:%s)\n' \
        "$1 INSERT 1000" "$(median $_ti)" "$_ti" "$1 UPDATE 1000" "$(median $_tu)" "$_tu" "$1 DELETE 1000" "$(median $_td)" "$_td"
}
round() {
    echo "-- $1"
    meas "select all records of the zone, owner (no RLS)" owner "" "$SELALL"
    meas "select all records of the zone, trusted role (RLS, true)" "$WR" "" "$SELALL"
    meas "select all records of the zone, karidns_api (RLS)" "$API" "$BM" "$SELALL"
    meas "select all records of the zone, karidns_api global master" "$API" "$GM" "$SELALL"
    meas "select count(*) of the zone, karidns_api (RLS)" "$API" "$BM" "SELECT count(*) FROM records WHERE domain_id = $BIG"
    meas "select one name, karidns_api (RLS)" "$API" "$BM" "SELECT * FROM records WHERE name = 'h77.big.test'"
    changeset "change set, owner (audit on, no RLS)" owner ""
    changeset "change set, karidns_api (audit on, RLS)" "$API" "$BM"
}

round "round 1: the big zone, $($P -c "SELECT count(*) FROM karidns_auth.grants") grants"
$P -c "SELECT karidns_auth.disable_audit('public')" > /dev/null
changeset "change set, owner (audit off, no RLS)" owner ""
$P -c "SELECT karidns_auth.enable_audit('public')" > /dev/null

# ---- round 2: many zones and grants (the grant lookups must stay flat)
echo "-- adding $ZONES zones and $GRANTS grants (users u<i> are domain masters of z<i>.test)"
$P > /dev/null <<EOF
SELECT karidns_auth.disable_audit('public');
INSERT INTO domains (name, type) SELECT 'z' || i || '.test', 'NATIVE' FROM generate_series(1, $ZONES) AS i;
INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, name, 'SOA', 'ns1.' || name || ' hostmaster.' || name || ' 1 7200 3600 1209600 300', 3600 FROM domains WHERE name <> 'big.test';
INSERT INTO karidns_auth.principals (kind, name) SELECT 'user', 'u' || i FROM generate_series(1, $GRANTS) AS i;
INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, rr_policy_id)
SELECT p.id, 'domain_master', 'public', 'z' || substr(p.name, 2) || '.test', (SELECT id FROM karidns_auth.rr_policies WHERE name = 'std')
  FROM karidns_auth.principals p WHERE p.name ~ '^u[0-9]+\$';
SELECT karidns_auth.enable_audit('public');
ANALYZE;
EOF
round "round 2: the big zone, $($P -c "SELECT count(*) FROM karidns_auth.grants") grants, $($P -c "SELECT count(*) FROM domains") zones"
U5=$($P -c "SELECT id FROM karidns_auth.principals WHERE name = 'u5'")
meas "select the records of z5.test (1 record), karidns_api u5" "$API" "$U5" "SELECT * FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'z5.test')"
meas "select count(*) of all visible records, karidns_api u5" "$API" "$U5" "SELECT count(*) FROM records"
meas "select count(*) of all zones, karidns_api u5" "$API" "$U5" "SELECT count(*) FROM domains"

echo "-- EXPLAIN (ANALYZE, BUFFERS): the lookups the effective-grants function makes (each runs once per statement)"
$P <<EOF | grep -E "Scan|Execution Time|Planning Time|Buffers|Index Cond|Filter|Rows Removed" | head -40
EXPLAIN (ANALYZE, BUFFERS) SELECT 1 FROM karidns_auth.grants WHERE data_schema = 'public' AND zone_name = 'z5.test';
EXPLAIN (ANALYZE, BUFFERS) SELECT 1 FROM karidns_auth.principal_closure WHERE member_id = $U5;
EXPLAIN (ANALYZE, BUFFERS) SELECT g.role FROM karidns_auth.principal_closure c JOIN karidns_auth.principals gp ON gp.id = c.group_id AND NOT gp.disabled
  JOIN karidns_auth.grants g ON g.principal_id = c.group_id WHERE c.member_id = $U5 AND (g.role = 'global_master' OR (g.data_schema = 'public' AND g.zone_name = 'z5.test'));
EOF

# ---- import
if [ -x "$ZONE" ] && "$ZONE" --version 2>/dev/null | grep -q postgresql; then
    echo "-- karidns-zone import (replace, --serial keep) of $RECORDS records as the writer role"
    awk -v n="$RECORDS" 'BEGIN { print "$ORIGIN big.test."; print "$TTL 300"; print "@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300"; print "@ IN NS ns1"; print "@ IN NS ns2";
        print "ns1 IN A 192.0.2.1"; print "ns2 IN A 192.0.2.2";
        for (i = 1; i <= n - 5; i++) { m = i % 5;
            if (m == 1) printf "h%d IN AAAA 2001:db8::%x\n", i, i % 65536; else if (m == 2) printf "h%d IN TXT \"v=%d\"\n", i, i;
            else if (m == 3) printf "h%d IN MX 10 ns1\n", i; else printf "h%d IN A 192.0.2.%d\n", i, i % 250 + 1 } }' > "$WORK/big.zone"
    printf 'host=%s port=%s user=%s dbname=%s\n' "${PGHOST:-127.0.0.1}" "${PGPORT:-5432}" "$WR" "$DB" > "$WORK/ci"; chmod 600 "$WORK/ci"
    imp() {     # imp LABEL AUDIT-OPTION
        _v=""; _i=0
        while [ $_i -lt "$RUNS" ]; do
            _i=$((_i + 1))
            $P -c "TRUNCATE karidns_auth.audit_log" > /dev/null; $P -c "VACUUM ANALYZE records" > /dev/null; $P -c "VACUUM ANALYZE karidns_changes" > /dev/null
            /usr/bin/time -p -o "$WORK/t" "$ZONE" import --no-config --conninfo-file "$WORK/ci" --serial keep $2 big.test "$WORK/big.zone" > "$WORK/imp.out" 2>&1 \
                || { echo "import failed:"; head -5 "$WORK/imp.out"; return 1; }
            _v="$_v $(awk '/^real/ { printf "%.0f", $2 * 1000 }' "$WORK/t")"
        done
        # shellcheck disable=SC2086
        printf '%-58s %10s ms   (runs:%s)   audit_log rows: %s\n' "$1" "$(median $_v)" "$_v" "$($P -c "SELECT count(*) FROM karidns_auth.audit_log")"
    }
    $P -c "SELECT karidns_auth.disable_audit('public')" > /dev/null
    imp "import, audit off (disable_audit)" ""
    $P -c "SELECT karidns_auth.enable_audit('public')" > /dev/null
    imp "import, audit on, --audit rows" "--audit rows"
    imp "import, audit on, --audit summary" "--audit summary"
else
    echo "-- import skipped: $ZONE is not built with a PostgreSQL driver"
fi
