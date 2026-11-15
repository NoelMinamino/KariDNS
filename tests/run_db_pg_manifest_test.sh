#!/bin/sh
# run_db_pg_manifest_test.sh - the loader's store protocol (0.7 WP7a) on PostgreSQL; tests/run_db_manifest_test.sh does the same with SQLite3.
#
# tests/db/fetch_backend.c (--store: the Backend's state machine checks every message, every entry is logged) starts the real karidns-dbloader on a PostgreSQL
# database (schema version 3: karidns_zone_state and karidns_changes with the xid column).  Checked:
#   - first fill: a pass whose pages cover every offered zone once, in ascending id order, with the cursor (the xmin of the snapshot) taken before it
#   - a restart with that cursor: no pass; the zones changed meanwhile (a serial change, a new zone, a rename, a delete by id, a zone that became a PRODUCER)
#     are CHANGES entries; a cursor from another database, or above the server's xmin, is a pass again
#   - views that share the source (karidns_domain_views); a zone asked for by name and id; a plain schema (no karidns_zone_state)
#   - memory: the resident size of the loader after a first fill and after a drain of every zone is the same at 100,000 zones as at 10,000
# The cursor of PostgreSQL is not the highest seq: a restart may read the transaction that made the last change again (duplicates, never losses); the checks
# allow it.  No root needed when the user can connect to PostgreSQL itself; as root the harness and the loader run as the unprivileged PostgreSQL user.
# SKIP when PostgreSQL is not reachable (tests/db/pg_lib.sh: KARIDNS_TEST_PG, KARIDNS_TEST_PG_USER), the loader has no PostgreSQL driver or a binary is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-./karidns-dbloader}
[ -x "$LOADER" ] || { echo "SKIP: $LOADER is not built"; exit 0; }
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver (make karidns-dbloader DB_DRIVERS=\"sqlite3 postgresql\")"; exit 0; }
FB=${FETCH_BACKEND:-./fetch_backend}
[ -x "$FB" ] || { echo "SKIP: $FB is not built (make fetch_backend)"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_pgmanifest.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
cleanup() { pg_cleanup; if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi; }
trap cleanup EXIT INT TERM
pg_setup pgmanifest || exit 0
mkdir "$T/o"
[ -n "$PG_AS" ] && chown "$PG_AS" "$T/o"
chmod 700 "$T/o"
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
NZ=300

pg_conninfo_file "$T/ci"
[ -n "$PG_AS" ] && { cp "$FB" "$T/fetch_backend" && chmod 755 "$T/fetch_backend" && FB="$T/fetch_backend"; }
LD=${PGLOADER:-$LOADER}
SRC="$T/ci|public"

mkzones() {   # mkzones FIRST LAST: z<i>.test with SOA, NS and an address
    pq "INSERT INTO domains (name, type) SELECT 'z' || i || '.test', 'NATIVE' FROM generate_series($1, $2) i;
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
          SELECT d.id, d.name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, false FROM domains d WHERE d.name ~ '^z[0-9]+\.test\$' AND d.id >= $1;
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
          SELECT d.id, d.name, 'NS', 'ns1.example.test.', 300, 0, false FROM domains d WHERE d.name ~ '^z[0-9]+\.test\$' AND d.id >= $1;
        INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
          SELECT d.id, 'www.' || d.name, 'A', '192.0.2.' || (d.id % 250 + 1), 300, 0, false FROM domains d WHERE d.name ~ '^z[0-9]+\.test\$' AND d.id >= $1" > /dev/null
}
fresh() {   # fresh: an empty schema of version 3 (the data is loaded before the extension when it is big: see below)
    pq "DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null
    pf tests/db/pdns_schema.pgsql.sql > /dev/null
}

# run NAME OPTION... -- ITEM...: output in $T/o/NAME.out, entries in $T/o/NAME.log, status in $RC
run() {
    n=$1; shift
    opts=""
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do opts="$opts $1"; shift; done
    [ $# -gt 0 ] && shift
    # shellcheck disable=SC2086
    as_pg "$FB" --store --postgresql="$SRC" --log="$T/o/$n.log" $opts "$LD" - "$@" > "$T/o/$n.out" 2> "$T/o/$n.err"
    RC=$?
}
has() { grep -Eq -- "$3" "$T/o/$2" && pass "$1" || { fail "$1"; head -12 "$T/o/$2" | sed 's/^/         /'; }; }
hasnt() { grep -Eq -- "$3" "$T/o/$2" && { fail "$1"; grep -E -- "$3" "$T/o/$2" | head -5 | sed 's/^/         /'; } || pass "$1"; }
cnt() { grep -Ec -- "$2" "$T/o/$1" 2>/dev/null; }
is() { [ "$2" = "$3" ] && pass "$1" || fail "$1 (got '$2', want '$3')"; }
field() { grep -E -- "$2" "$T/o/$1" | head -1 | sed -n "s/.* $3=\([^ ]*\).*/\1/p"; }

echo "== the database: $NZ zones, schema version 3"
fresh
pf db/karidns_ext.pgsql.sql > /dev/null || { fail "cannot apply db/karidns_ext.pgsql.sql"; exit 1; }
mkzones 1 $NZ || { fail "cannot fill the database"; exit 1; }
pq "INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.1');
    INSERT INTO domains (name, type) VALUES ('producer.test', 'PRODUCER')" > /dev/null
NLIST=$(pq "SELECT count(*) FROM domains WHERE type IN ('NATIVE','MASTER','SLAVE','CONSUMER')")

echo "== first fill: a pass over every zone"
run first -- sleep:500
[ $RC -eq 0 ] && pass "the harness ran to the end (every message went through the Backend's state machine)" || { fail "the harness failed (status $RC)"; head -20 "$T/o/first.out" "$T/o/first.err"; }
has "the pass starts with a count, a valid cursor, an identity" first.out "^MB view=0 count=$((NZ + 2)) cursor=[0-9]+ valid=1 ident=postgresql:public flags=0$"
has "the pass ends complete, every entry counted, the ids ascending (ok=1), the PRODUCER zone not offered" first.out "^ME view=0 n=$NLIST seen=$NLIST skipped=1 cursor=[0-9]+ valid=1 complete=1 ident=postgresql:public ok=1$"
is "every offered zone is in the log once" "$(awk '$1 == "M" && $2 == 0 { print $3 }' "$T/o/first.log" | sort -n | uniq | wc -l | tr -d ' ')" "$NLIST"
is "... and no zone twice" "$(awk '$1 == "M" && $2 == 0 { print $3 }' "$T/o/first.log" | sort -n | uniq -d | wc -l | tr -d ' ')" 0
has "a zone has its state row (stamped)" first.log '^M 0 3 z3\.test\. 0 1 '
has "the SLAVE zone is a secondary" first.log '^M 0 301 slave\.test\. 1 '
hasnt "the PRODUCER zone is not offered" first.log 'producer'
grep '^STATE ' "$T/o/first.out" > "$T/st1"
has "the cursor the Backend keeps" first.out '^STATE view=0 cursor=[0-9]+ valid=1 ident=postgresql:public$'

echo "== a restart with the cursor"
run restart --cursor=state:"$T/st1" -- sleep:500
hasnt "no pass" restart.out '^MB '
CH0=$(cnt restart.out '^CH ')
echo "  (the transaction of the last change may be read again: $CH0 CHANGES message(s))"
hasnt "no zone is changed that did not change (only the zones of the last transaction may come again)" restart.log '^C 0 up ([1-9]|[1-9][0-9]|[12][0-9][0-9]) '

echo "== the zones that changed since the cursor"
pq "UPDATE records SET content = 'ns1.example.test. host.example.test. 2 3600 600 86400 300' WHERE domain_id = 5 AND type = 'SOA';
    INSERT INTO domains (name, type) VALUES ('new1.test', 'NATIVE');
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, false FROM domains WHERE name = 'new1.test';
    DELETE FROM records WHERE domain_id = 7;
    DELETE FROM domains WHERE id = 7;
    UPDATE domains SET name = 'renamed9.test' WHERE id = 9;
    UPDATE domains SET type = 'PRODUCER' WHERE id = 11" > /dev/null
NEWID=$(pq "SELECT id FROM domains WHERE name = 'new1.test'")
run chg --cursor=state:"$T/st1" -- sleep:500
[ $RC -eq 0 ] && pass "the harness ran to the end" || { fail "the harness failed (status $RC)"; head "$T/o/chg.out"; }
hasnt "no pass" chg.out '^MB '
has "the serial change of z5 is an upsert, stamped" chg.log '^C 0 up 5 z5\.test\. 0 1 0 [1-9][0-9]* [1-9][0-9]* -1$'
has "the new zone is an upsert" chg.log "^C 0 up $NEWID new1\.test\. 0 1 "
has "the rename is an upsert with the new name" chg.log '^C 0 up 9 renamed9\.test\. 0 1 '
has "the deleted zone is a delete by id with no name" chg.log '^C 0 del 7 - '
has "a zone that became a PRODUCER is a delete with its name" chg.log '^C 0 del 11 z11\.test\. '
hasnt "a zone that did not change is not mentioned" chg.log '^C 0 up 6 '
has "the drain ends with last = 1" chg.out '^CH view=0 cursor=[0-9]+ last=1 '
grep '^STATE ' "$T/o/chg.out" > "$T/st2"
is "the cursor moved" "$([ "$(sed -n 's/.* cursor=\([0-9]*\) .*/\1/p' "$T/st2" | head -1)" -gt "$(sed -n 's/.* cursor=\([0-9]*\) .*/\1/p' "$T/st1" | head -1)" ] && echo yes || echo no)" yes

echo "== a cursor above the server's, another database: a pass again"
run above --cursor=0:99999999999:postgresql:public -- sleep:500
has "a cursor above the xmin of the server is a gap: a pass" above.out '^MB view=0 '
run ident --cursor=0:1:postgresql:other -- sleep:500
has "another database identity makes a pass" ident.out '^MB view=0 '
run force --cursor=state:"$T/st2" -- reloadforce batches:2 sleep:500
is "reload -force lists every zone again (a second pass)" "$(cnt force.out '^MB ')" 1

echo "== the fetch stream: a zone by name and id"
run byid -- "req:1:z5.test.:0:0:5" "req:2:z5.test.:0:0:6" wait:2
has "the right id is answered" byid.out '^ANS id=1 zone=z5\.test\. kind=primary summary=0 '
has "another id is refused: renamed or created again" byid.out '^FAILED id=2 zone=z5\.test\. reason=.*domain id 5 now, not 6'

echo "== views that share the source (karidns_domain_views)"
pq "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'a'), (2, 'b'), (4, 'a'), (4, 'b'), (5, 'other')" > /dev/null
run views --views=2 -- sleep:500
has "a zone mapped to a is offered to a" views.log '^M 0 1 z1\.test\. '
hasnt "... and not to b" views.log '^M 1 1 z1\.test\. '
has "a zone mapped to b is offered to b" views.log '^M 1 2 z2\.test\. '
hasnt "... and not to a" views.log '^M 0 2 z2\.test\. '
has "a zone mapped to both is in both" views.log '^M 1 4 z4\.test\. '
hasnt "a zone mapped only to a view this source does not serve is in neither" views.log '^M [01] 5 '
grep '^STATE ' "$T/o/views.out" > "$T/stv"
pq "UPDATE karidns_domain_views SET view_name = 'b' WHERE domain_id = 1 AND view_name = 'a'" > /dev/null
run views2 --views=2 --cursor=state:"$T/stv" -- sleep:500
hasnt "a changed mapping needs no pass" views2.out '^MB '
has "the view that lost the zone gets a delete, with the name" views2.log '^C 0 del 1 z1\.test\. '
has "the view that got it gets an upsert" views2.log '^C 1 up 1 z1\.test\. '

echo "== auto reload: the notification wakes the loader, a drain follows (poll-interval 20 s)"
T0=$(date +%s)
run auto --auto=20 --cursor=state:"$T/st2" -- sleep:300 "sh:psql -X -q -At '$PGC' -c \"UPDATE records SET ttl = 311 WHERE domain_id = 21 AND type = 'SOA'\"" batches:2 sleep:300
T1=$(date +%s)
has "an auto batch follows the change" auto.out '^BB kind=4 '
has "the zone that changed is an upsert" auto.log '^C 0 up 21 z21\.test\. '
[ $((T1 - T0)) -lt 15 ] && pass "... at once (the notification, not the poll interval of 20 s: $((T1 - T0)) s)" || fail "the change took $((T1 - T0)) s"

echo "== a plain PowerDNS schema: no karidns_zone_state"
fresh
pq "INSERT INTO domains (name, type) VALUES ('plain1.test', 'NATIVE'), ('plain2.test', 'NATIVE');
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 77 3600 600 86400 300', 300, 0, false FROM domains;
    INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, false FROM domains" > /dev/null
run plain -- reloadzone:0:plain1.test. reloadzone:0:nope.test. batches:3 sleep:500
has "a pass without a cursor, flagged plain" plain.out '^MB view=0 count=2 cursor=0 valid=0 ident= flags=2$'
has "... listing the zones with their serials, unstamped" plain.log '^M 0 1 plain1\.test\. 0 0 0 0 77$'
has "a one-zone reload is a CHANGES entry that forces the body" plain.log '^C 0 up 1 plain1\.test\. 0 0 1 0 0 77$'
has "a one-zone reload of a zone that is not there is a ZONE_DELETE by name" plain.out '^ZD view=0 id=0 name=nope\.test\.$'

echo "== memory: the loader keeps no table of the zones"
rss() { field "$1" '^RSS' kb; }
BIG=${MANIFEST_BIG:-100000}; SMALL=10000
fresh
mkzones 1 $SMALL || { fail "cannot fill the small database"; exit 1; }
pf db/karidns_ext.pgsql.sql > /dev/null
run m1 -- sleep:500
R1=$(rss m1.out)
grep '^STATE ' "$T/o/m1.out" > "$T/s1"
pq "UPDATE records SET ttl = 301 WHERE type = 'SOA'" > /dev/null
run d1 --cursor=state:"$T/s1" -- sleep:500
R3=$(rss d1.out)
U1=$(grep '^CH ' "$T/o/d1.out" | sed -n 's/.* up=\([0-9]*\) .*/\1/p' | awk '{ s += $1 } END { print s + 0 }')
fresh
mkzones 1 $BIG || { fail "cannot fill the big database"; exit 1; }
pf db/karidns_ext.pgsql.sql > /dev/null
run m2 -- sleep:500
R2=$(rss m2.out)
grep '^STATE ' "$T/o/m2.out" > "$T/s2"
pq "UPDATE records SET ttl = 301 WHERE type = 'SOA'" > /dev/null
run d2 --cursor=state:"$T/s2" -- sleep:500
R4=$(rss d2.out)
U2=$(grep '^CH ' "$T/o/d2.out" | sed -n 's/.* up=\([0-9]*\) .*/\1/p' | awk '{ s += $1 } END { print s + 0 }')
has "the pass over $SMALL zones lists them all" m1.out "^ME view=0 n=$SMALL seen=$SMALL skipped=0 .*ok=1$"
has "the pass over $BIG zones lists them all" m2.out "^ME view=0 n=$BIG seen=$BIG skipped=0 .*ok=1$"
echo "  (resident size of the loader: ${R1:-?} KB at $SMALL zones, ${R2:-?} KB at $BIG zones)"
[ -n "$R1" ] && [ -n "$R2" ] && [ "$R2" -le $((R1 + 8192)) ] && pass "a first fill of $BIG zones needs at most 8 MB more than $SMALL zones" || fail "the resident size grows with the zones: ${R1:-?} KB -> ${R2:-?} KB"
[ -n "$R2" ] && [ "$R2" -le 40960 ] && pass "... and the loader stays under 40 MB" || fail "the loader is above 40 MB (${R2:-?} KB)"
is "the drain of $SMALL changed zones: one upsert for each" "$U1" "$SMALL"
is "the drain of $BIG changed zones: one upsert for each" "$U2" "$BIG"
echo "  (resident size of the loader after the drain: ${R3:-?} KB at $SMALL zones, ${R4:-?} KB at $BIG zones)"
[ -n "$R3" ] && [ -n "$R4" ] && [ "$R4" -le $((R3 + 8192)) ] && pass "a drain of $BIG zones needs at most 8 MB more than $SMALL zones" || fail "the resident size of a drain grows with the zones: ${R3:-?} KB -> ${R4:-?} KB"

echo
echo "PASS=$PASS FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
