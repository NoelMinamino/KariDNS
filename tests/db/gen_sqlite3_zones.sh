#!/bin/sh
# gen_sqlite3_zones.sh - build a deterministic PowerDNS-schema SQLite3 database for the DB-path measurements (bench/phase0) and
# tests that need a large database (tests/run_db_loader_sigterm_test.sh).
# Usage: sh tests/db/gen_sqlite3_zones.sh DB ZONES RRS_PER_ZONE
#   zone names z<i>.test (RFC 6761); per zone: SOA, 2 NS, apex A, apex MX, www A and RRS-6 hosts h<k>
#   (A 40%, CNAME 20%, AAAA 15%, TXT 20%, MX 5% by k mod 20).  The data is a function of (ZONES, RRS), so a
#   database can always be regenerated instead of kept.  The karidns_* extension (triggers) is applied AFTER the
#   bulk load, so the change log stays empty (db/karidns_ext.sqlite3.sql).
# Needs the sqlite3 command line tool.  Run from the top of the source tree.
set -eu
DB=${1:?usage: gen_sqlite3_zones.sh DB ZONES RRS_PER_ZONE}
ZONES=${2:?zones}
RRS=${3:?rrs per zone}
[ "$RRS" -ge 7 ] || { echo "RRS_PER_ZONE must be >= 7" >&2; exit 2; }
HOSTS=$((RRS - 6))
[ ! -e "$DB" ] || { echo "$DB exists; remove it first" >&2; exit 2; }
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$DB" <<SQL
PRAGMA synchronous = OFF;
PRAGMA cache_size = -400000;
BEGIN;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $ZONES)
INSERT INTO domains (name, type) SELECT 'z' || i || '.test', 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, 0 FROM domains ORDER BY id;
COMMIT;
BEGIN;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'NS', 'ns1.example.test.', 300, 0, 0 FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'NS', 'ns2.example.test.', 300, 0, 0 FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'A', '192.0.2.' || (id % 250 + 1), 300, 0, 0 FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'MX', 'www.' || name || '.', 300, 10, 0 FROM domains ORDER BY id;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, 'www.' || name, 'A', '192.0.2.' || ((id + 7) % 250 + 1), 300, 0, 0 FROM domains ORDER BY id;
COMMIT;
BEGIN;
WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < $HOSTS)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || n.k || '.' || d.name,
    CASE WHEN n.k % 20 < 8 THEN 'A' WHEN n.k % 20 < 12 THEN 'CNAME' WHEN n.k % 20 < 15 THEN 'AAAA'
         WHEN n.k % 20 < 19 THEN 'TXT' ELSE 'MX' END,
    CASE WHEN n.k % 20 < 8 THEN '192.0.2.' || ((d.id + n.k) % 250 + 1)
         WHEN n.k % 20 < 12 THEN 'www.' || d.name || '.'
         WHEN n.k % 20 < 15 THEN '2001:db8::' || printf('%x', n.k)
         WHEN n.k % 20 < 19 THEN '"v=' || d.id || '-' || n.k || '"'
         ELSE 'www.' || d.name || '.' END,
    300, CASE WHEN n.k % 20 = 19 THEN 10 ELSE 0 END, 0
  FROM domains d CROSS JOIN n;
COMMIT;
ANALYZE;
SQL
sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null
sqlite3 "$DB" "PRAGMA journal_mode = WAL;" > /dev/null
echo "$DB: $(sqlite3 "$DB" 'SELECT count(*) FROM domains') zones, $(sqlite3 "$DB" 'SELECT count(*) FROM records') records"
