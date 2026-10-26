#!/bin/sh
# gen_pgsql_zones.sh - build the same deterministic PowerDNS-schema data as gen_sqlite3_zones.sh in a PostgreSQL database, for the
# DB-path measurements (docs/karidns-dbloader.md "Measurements").
# Usage: sh tests/db/gen_pgsql_zones.sh CONNINFO ZONES RRS_PER_ZONE
#   CONNINFO is the conninfo string psql gets ("dbname=karidns_bench", "host=/tmp dbname=..."); the database must exist and be empty.
#   zone names z<i>.test (RFC 6761); per zone: SOA, 2 NS, apex A, apex MX, www A and RRS-6 hosts h<k>
#   (A 40%, CNAME 20%, AAAA 15%, TXT 20%, MX 5% by k mod 20).  The data is a function of (ZONES, RRS) and identical to the SQLite3
#   generator's, so a database can always be regenerated instead of kept.  The karidns_* extension (triggers) is applied AFTER the
#   bulk load, so the change log stays empty (db/karidns_ext.pgsql.sql).
# Needs psql.  Run from the top of the source tree.  Drop the database afterwards: 1,000,000 zones x 11 records take about 2.6 GB.
set -eu
CONN=${1:?usage: gen_pgsql_zones.sh CONNINFO ZONES RRS_PER_ZONE}
ZONES=${2:?zones}
RRS=${3:?rrs per zone}
[ "$RRS" -ge 7 ] || { echo "RRS_PER_ZONE must be >= 7" >&2; exit 2; }
HOSTS=$((RRS - 6))
PGOPTIONS="-c client_min_messages=warning"; export PGOPTIONS       # no NOTICE lines from the IF NOT EXISTS / DROP IF EXISTS of the DDL
Q="psql -X -q -At -v ON_ERROR_STOP=1"
[ "$($Q "$CONN" -c "SELECT count(*) FROM pg_tables WHERE tablename = 'domains' AND schemaname = current_schema()")" = 0 ] ||
    { echo "the database already has a domains table; use an empty one" >&2; exit 2; }
$Q "$CONN" -f tests/db/pdns_schema.pgsql.sql > /dev/null
$Q "$CONN" <<SQL
SET synchronous_commit = off;
BEGIN;
INSERT INTO domains (name, type) SELECT 'z' || i || '.test', 'NATIVE' FROM generate_series(1, $ZONES) AS i;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, false FROM domains ORDER BY id;
COMMIT;
BEGIN;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'NS', 'ns1.example.test.', 300, 0, false FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'NS', 'ns2.example.test.', 300, 0, false FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'A', '192.0.2.' || (id % 250 + 1), 300, 0, false FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'MX', 'www.' || name || '.', 300, 10, false FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'www.' || name, 'A', '192.0.2.' || ((id + 7) % 250 + 1), 300, 0, false FROM domains ORDER BY id;
COMMIT;
BEGIN;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || n.k || '.' || d.name,
    CASE WHEN n.k % 20 < 8 THEN 'A' WHEN n.k % 20 < 12 THEN 'CNAME' WHEN n.k % 20 < 15 THEN 'AAAA'
         WHEN n.k % 20 < 19 THEN 'TXT' ELSE 'MX' END,
    CASE WHEN n.k % 20 < 8 THEN '192.0.2.' || ((d.id + n.k) % 250 + 1)
         WHEN n.k % 20 < 12 THEN 'www.' || d.name || '.'
         WHEN n.k % 20 < 15 THEN '2001:db8::' || to_hex(n.k)
         WHEN n.k % 20 < 19 THEN '"v=' || d.id || '-' || n.k || '"'
         ELSE 'www.' || d.name || '.' END,
    300, CASE WHEN n.k % 20 = 19 THEN 10 ELSE 0 END, false
  FROM domains d CROSS JOIN generate_series(1, $HOSTS) AS n(k);
COMMIT;
SQL
$Q "$CONN" -c "ANALYZE domains, records"
$Q "$CONN" -f db/karidns_ext.pgsql.sql > /dev/null
echo "$($Q "$CONN" -c 'SELECT count(*) FROM domains') zones, $($Q "$CONN" -c 'SELECT count(*) FROM records') records"
