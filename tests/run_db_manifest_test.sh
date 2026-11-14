#!/bin/sh
# run_db_manifest_test.sh - the loader's store protocol (0.7 WP7a, store design 5.1 - 5.4): a loader without a table of the zones.
#
# tests/db/fetch_backend.c stands in for the Backend (--store: CONFIG store_proto, the first stream goes through the state machine of the Backend, every
# entry is logged) and starts the real karidns-dbloader on a SQLite3 database.  Checked:
#   - first fill: MANIFEST_BEGIN, pages in ascending id order that cover every zone the loader can send exactly once, MANIFEST_END with the counts (zones it
#     cannot send are counted, not listed) and the cursor taken before the pass; BATCH_END counts the entries
#   - a restart with the cursor the first run ended at (CONFIG): no pass, no entry; with changes made meanwhile: CHANGES with the zones that changed (an upsert
#     with a stamp, a rename as an upsert with the new name, a delete by id with no name) and the new cursor
#   - a gap in the change log, a cursor above its end, another database identity: a pass again; `reload -force` a pass, `reload` a drain
#   - views that share a source (karidns_domain_views): a pass lists to each view the zones it serves; a changed mapping is a delete for the view that lost
#     the zone and an upsert for the view that got it
#   - a zone asked for by name and id on the fetch stream: the right id is answered, another id is refused (renamed / created again)
#   - a plain PowerDNS schema (no karidns_zone_state): a pass with serials, no cursor; a one-zone reload is a CHANGES entry with the force flag, a missing zone a ZONE_DELETE
#   - auto reload: a change made while the loader runs is a CHANGES batch; a zone of the signer (X-KARIDNS-SIGNER=1) is held and goes out with a reload of that zone
#   - memory: the resident size of the loader after a first fill and after a drain of every zone is the same at 100,000 zones as at 10,000 (no table per zone)
# No root needed.  SKIP when the sqlite3 command line tool, a compiler or a binary is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

LOADER=${LOADER:-./karidns-dbloader}
[ -x "$LOADER" ] || { echo "SKIP: $LOADER is not built"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
FB=${FETCH_BACKEND:-./fetch_backend}
[ -x "$FB" ] || { echo "SKIP: $FB is not built (make fetch_backend)"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbmanifest.XXXXXX") || exit 1
trap 'if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
NZ=300

DB="$T/z.db"
sh tests/db/gen_sqlite3_zones.sh "$DB" $NZ 7 > /dev/null || { fail "cannot build the database"; exit 1; }
sqlite3 "$DB" "INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.1');
INSERT INTO domains (name, type) VALUES ('producer.test', 'PRODUCER');
UPDATE records SET ttl = 301 WHERE domain_id = 3 AND type = 'SOA';" > /dev/null

# run NAME OPTION... -- ITEM...: the harness output in $T/NAME.out (the entries in $T/NAME.log), its status in $RC
run() {
    n=$1; shift
    opts=""
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do opts="$opts $1"; shift; done
    [ $# -gt 0 ] && shift
    # shellcheck disable=SC2086
    "$FB" --store --log="$T/$n.log" $opts "$LOADER" "$DB" "$@" > "$T/$n.out" 2> "$T/$n.err"
    RC=$?
}
has() { grep -Eq -- "$3" "$T/$2" && pass "$1" || { fail "$1"; head -12 "$T/$2" | sed 's/^/         /'; }; }
hasnt() { grep -Eq -- "$3" "$T/$2" && { fail "$1"; grep -E -- "$3" "$T/$2" | head -5 | sed 's/^/         /'; } || pass "$1"; }
cnt() { grep -Ec -- "$2" "$T/$1" 2>/dev/null; }
is() { [ "$2" = "$3" ] && pass "$1" || fail "$1 (got '$2', want '$3')"; }
field() {   # field FILE REGEX KEY: the value of KEY= on the first line that matches REGEX
    grep -E -- "$2" "$T/$1" | head -1 | sed -n "s/.* $3=\([^ ]*\).*/\1/p"
}
sq() { sqlite3 "$DB" "$1" > /dev/null; }

echo "== first fill: a pass over every zone"
NLIST=$(sqlite3 "$DB" "SELECT count(*) FROM domains WHERE type IN ('NATIVE','MASTER','SLAVE','CONSUMER')")
run first -- sleep:300
[ $RC -eq 0 ] && pass "the harness ran to the end (every message went through the Backend's state machine)" || { fail "the harness failed (status $RC)"; cat "$T/first.out" "$T/first.err" | head -20; }
has "the loader says it has the store protocol (HELLO features 1)" first.out '^HELLO features=1$'
is "one pass" "$(cnt first.out '^MB ')" 1
has "the pass starts with a count, a valid cursor, an identity" first.out "^MB view=0 count=$((NZ + 2)) cursor=[0-9]+ valid=1 ident=sqlite3:[0-9a-f]+:[0-9a-f]+ flags=0$"
has "the pass ends complete, with every entry counted and the ids in ascending order (ok=1), one zone not offered (PRODUCER)" first.out "^ME view=0 n=$NLIST seen=$NLIST skipped=1 cursor=[0-9]+ valid=1 complete=1 ident=sqlite3:[0-9a-f]+:[0-9a-f]+ ok=1$"
is "every offered zone is in the log once" "$(awk '$1 == "M" && $2 == 0 { print $3 }' "$T/first.log" | sort -n | uniq | wc -l | tr -d ' ')" "$NLIST"
is "... and no zone twice" "$(awk '$1 == "M" && $2 == 0 { print $3 }' "$T/first.log" | sort -n | uniq -d | wc -l | tr -d ' ')" 0
has "a zone with a state row is stamped (generation, time)" first.log '^M 0 3 z3\.test\. 0 1 [1-9][0-9]* [1-9][0-9]* -1$'
has "the SLAVE zone is a secondary (kind 1)" first.log '^M 0 301 slave\.test\. 1 '
hasnt "the PRODUCER zone is not offered" first.log 'producer'
has "BATCH_END counts the entries" first.out "^BE zones=$NLIST failed=0 deleted=0$"
hasnt "no CHANGES in a first fill (the log is empty after the pass)" first.out '^CH '
hasnt "the loader keeps no zone table: no body of a zone is sent on the first stream" first.out '^ZD |^ZF '
grep '^STATE ' "$T/first.out" > "$T/st1"
has "the cursor the Backend keeps is the one of the pass" first.out '^STATE view=0 cursor=[0-9]+ valid=1 ident=sqlite3:'
has "the resident size is printed" first.out '^RSS kb=[0-9]+$'

echo "== a restart with the cursor: nothing to say"
run restart --cursor=state:"$T/st1" -- sleep:300
[ $RC -eq 0 ] && pass "the harness ran to the end" || { fail "the harness failed (status $RC)"; cat "$T/restart.out" | head; }
hasnt "no pass" restart.out '^MB |^MP |^ME '
hasnt "no entry" restart.out '^CH '
has "the startup batch is empty" restart.out '^BE zones=0 failed=0 deleted=0$'

echo "== the zones that changed since the cursor"
sq "UPDATE records SET content = 'ns1.example.test. host.example.test. 2 3600 600 86400 300' WHERE domain_id = 5 AND type = 'SOA';
INSERT INTO domains (name, type) VALUES ('new1.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.example.test. host.example.test. 1 3600 600 86400 300', 300, 0, 0 FROM domains WHERE name = 'new1.test';
DELETE FROM records WHERE domain_id = 7;
DELETE FROM domains WHERE id = 7;
UPDATE domains SET name = 'renamed9.test' WHERE id = 9;
UPDATE domains SET type = 'PRODUCER' WHERE id = 11"
NEWID=$(sqlite3 "$DB" "SELECT id FROM domains WHERE name = 'new1.test'")
run chg --cursor=state:"$T/st1" -- sleep:300
[ $RC -eq 0 ] && pass "the harness ran to the end" || { fail "the harness failed (status $RC)"; head "$T/chg.out"; }
hasnt "no pass" chg.out '^MB '
has "one CHANGES message ends the drain (last = 1) with 3 upserts and 2 deletes" chg.out '^CH view=0 cursor=[0-9]+ last=1 up=3 del=2$'
has "BATCH_END counts them" chg.out '^BE zones=3 failed=0 deleted=2$'
has "the serial change of z5 is an upsert, stamped" chg.log '^C 0 up 5 z5\.test\. 0 1 0 [1-9][0-9]* [1-9][0-9]* -1$'
has "the new zone is an upsert" chg.log "^C 0 up $NEWID new1\.test\. 0 1 "
has "the rename is an upsert with the new name" chg.log '^C 0 up 9 renamed9\.test\. 0 1 '
has "the deleted zone is a delete by id with no name" chg.log '^C 0 del 7 - '
has "a zone that became a PRODUCER is a delete (the Backend must not keep the old one), with its name" chg.log '^C 0 del 11 z11\.test\. '
hasnt "a zone that did not change is not mentioned" chg.log '^C 0 up 6 '
CUR1=$(sed -n 's/.* cursor=\([0-9]*\) .*/\1/p' "$T/st1" | head -1)
CUR2=$(field chg.out '^CH ' cursor)
[ "${CUR2:-0}" -gt "${CUR1:-0}" ] && pass "the cursor moved ($CUR1 -> $CUR2)" || fail "the cursor did not move ($CUR1 -> ${CUR2:-?})"
grep '^STATE ' "$T/chg.out" > "$T/st2"
run chg2 --cursor=state:"$T/st2" -- sleep:300
hasnt "from the new cursor there is nothing" chg2.out '^CH |^MB '

echo "== a gap, a cursor above the log's end, another database: a pass again"
sq "UPDATE domains SET type = 'NATIVE' WHERE id = 11;
UPDATE records SET ttl = 302 WHERE domain_id = 4 AND type = 'SOA';
UPDATE records SET ttl = 303 WHERE domain_id = 6 AND type = 'SOA'"
sq "DELETE FROM karidns_changes WHERE seq <= $((CUR2 + 1))"
run gap --cursor=state:"$T/st2" -- sleep:300
has "the pruned log makes a pass (the change log no longer reaches back)" gap.out '^ME view=0 n=[0-9]+ seen=[0-9]+ skipped=1 .*complete=1 .*ok=1$'
has "the pass sees the zone that came back" gap.log '^M 0 11 z11\.test\. '
grep -q "no longer reaches back" "$T/gap.err" && pass "the loader says why" || fail "the loader does not say why"
grep '^STATE ' "$T/gap.out" > "$T/st3"
run above --cursor=0:99999999:"$(sed -n 's/.* ident=//p' "$T/st3" | head -1)" -- sleep:300
has "a cursor above the end of the log makes a pass" above.out '^MB view=0 '
run ident --cursor=0:1:other-database -- sleep:300
has "another database identity makes a pass" ident.out '^MB view=0 '
grep -q "not the one the cursor belongs to" "$T/ident.err" && pass "the loader says why" || fail "the loader does not say why (identity)"
run force --cursor=state:"$T/st3" -- reload sleep:300 reloadforce batches:3 sleep:300
is "reload -force lists every zone (one pass, the startup batch and the plain reload are drains)" "$(cnt force.out '^MB ')" 1
is "three batches: startup, reload, reload -force" "$(cnt force.out '^BB ')" 3

echo "== the fetch stream: a zone by name and id"
run byid -- "req:1:z5.test.:0:0:5" "req:2:z5.test.:0:0:6" "req:3:z5.test.:0:1:5" "req:4:z5.test.:0:0" wait:4
has "the right id is answered" byid.out '^ANS id=1 zone=z5\.test\. kind=primary summary=0 '
has "another id is refused: renamed or created again" byid.out '^FAILED id=2 zone=z5\.test\. reason=.*domain id 5 now, not 6'
has "a summary by id" byid.out '^ANS id=3 zone=z5\.test\. kind=primary summary=1 '
has "no id: as before" byid.out '^ANS id=4 zone=z5\.test\. '

echo "== views that share the source (karidns_domain_views)"
sq "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'a'), (2, 'b'), (4, 'a'), (4, 'b'), (5, 'other')"
run views --views=2 -- sleep:300
has "view a has a pass" views.out '^ME view=0 '
has "view b has a pass" views.out '^ME view=1 '
has "a zone mapped to a is offered to a" views.log '^M 0 1 z1\.test\. '
hasnt "... and not to b" views.log '^M 1 1 z1\.test\. '
has "a zone mapped to b is offered to b" views.log '^M 1 2 z2\.test\. '
hasnt "... and not to a" views.log '^M 0 2 z2\.test\. '
has "a zone mapped to both is in both" views.log '^M 0 4 z4\.test\. '
has "(both)" views.log '^M 1 4 z4\.test\. '
has "a zone without rows is in both (a)" views.log '^M 0 6 z6\.test\. '
has "(b)" views.log '^M 1 6 z6\.test\. '
hasnt "a zone mapped only to a view this source does not serve is in neither" views.log '^M [01] 5 '
grep -q "mapped only to views that do not use this database" "$T/views.err" && pass "the loader says which zones no view serves" || fail "the loader does not say which zones no view serves"
grep '^STATE ' "$T/views.out" > "$T/stv"
sq "UPDATE karidns_domain_views SET view_name = 'b' WHERE domain_id = 1 AND view_name = 'a';
DELETE FROM karidns_domain_views WHERE domain_id = 4 AND view_name = 'b'"
run views2 --views=2 --cursor=state:"$T/stv" -- sleep:300
hasnt "a changed mapping needs no pass" views2.out '^MB '
has "the view that lost the zone gets a delete, with the name" views2.log '^C 0 del 1 z1\.test\. '
has "the view that got it gets an upsert" views2.log '^C 1 up 1 z1\.test\. '
has "a zone taken from b only: delete for b" views2.log '^C 1 del 4 z4\.test\. '
has "... and a, which still has it, gets an upsert (the Backend finds the stamp unchanged)" views2.log '^C 0 up 4 z4\.test\. '

echo "== a plain PowerDNS schema: no karidns_zone_state"
PDB="$T/plain.db"
sqlite3 "$PDB" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$PDB" "PRAGMA journal_mode=WAL" > /dev/null
for z in plain1 plain2; do
    sqlite3 "$PDB" "INSERT INTO domains (name, type) VALUES ('$z.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.$z.test host.$z.test 77 3600 600 86400 300', 300, 0, 0 FROM domains WHERE name = '$z.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.$z.test', 300, 0, 0 FROM domains WHERE name = '$z.test'"
done
"$FB" --store --log="$T/plain.log" "$LOADER" "$PDB" reloadzone:0:plain1.test. reloadzone:0:nope.test. sleep:500 > "$T/plain.out" 2> "$T/plain.err"
RC=$?
[ $RC -eq 0 ] && pass "the harness ran to the end" || { fail "the harness failed (status $RC)"; head "$T/plain.out"; }
has "a pass without a cursor, flagged plain" plain.out '^MB view=0 count=2 cursor=0 valid=0 ident= flags=2$'
has "... listing the zones with their serials, unstamped" plain.log '^M 0 1 plain1\.test\. 0 0 0 0 77$'
has "a one-zone reload is a CHANGES entry that forces the body, with the serial" plain.log '^C 0 up 1 plain1\.test\. 0 0 1 0 0 77$'
has "a one-zone reload of a zone that is not there is a ZONE_DELETE by name" plain.out '^ZD view=0 id=0 name=nope\.test\.$'
grep '^BE ' "$T/plain.out" | head -3 | sed 's/^/         /' > /dev/null

echo "== auto reload and signer-wait"
sq "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (20, 'X-KARIDNS-SIGNER', '1')"
run pre --cursor=state:"$T/st3" -- sleep:300
grep '^STATE ' "$T/pre.out" > "$T/st4"
run auto --auto=1 --cursor=state:"$T/st4" -- sleep:200 \
    "sh:sqlite3 $DB \"UPDATE records SET ttl = 311 WHERE domain_id = 21 AND type = 'SOA'; UPDATE records SET ttl = 312 WHERE domain_id = 20 AND type = 'SOA'\"" \
    batches:2 sleep:1500 reloadzone:0:z20.test. batches:3 sleep:300
has "an auto batch follows the change" auto.out '^BB kind=4 '
has "the zone that changed is an upsert" auto.log '^C 0 up 21 z21\.test\. '
hasnt "a zone of the signer that changed is held back" auto.log '^C 0 up 20 z20.test. 0 1 0 '
has "a reload of that zone sends it (force)" auto.log '^C 0 up 20 z20.test. 0 0 1 0 0 '

echo "== memory: the loader keeps no table of the zones"
# 100,000 zones against 10,000: the resident size of the loader after a first fill, and after a drain of every zone, must not grow with the zones
rss() { field "$1" '^RSS' kb; }
if [ -z "${MANIFEST_BIG:-}" ]; then
    BIG=100000; SMALL=10000
else
    BIG=$MANIFEST_BIG; SMALL=10000
fi
D1="$T/small.db"; D2="$T/big.db"
sh tests/db/gen_sqlite3_zones.sh "$D1" $SMALL 7 > /dev/null && sh tests/db/gen_sqlite3_zones.sh "$D2" $BIG 7 > /dev/null || { fail "cannot build the big databases"; exit 1; }
"$FB" --store "$LOADER" "$D1" sleep:300 > "$T/m1.out" 2> "$T/m1.err"
"$FB" --store "$LOADER" "$D2" sleep:300 > "$T/m2.out" 2> "$T/m2.err"
R1=$(rss m1.out); R2=$(rss m2.out)
has "the pass over $SMALL zones lists them all" m1.out "^ME view=0 n=$SMALL seen=$SMALL skipped=0 .*ok=1$"
has "the pass over $BIG zones lists them all" m2.out "^ME view=0 n=$BIG seen=$BIG skipped=0 .*ok=1$"
echo "  (resident size of the loader: ${R1:-?} KB at $SMALL zones, ${R2:-?} KB at $BIG zones)"
[ -n "$R1" ] && [ -n "$R2" ] && [ "$R2" -le $((R1 + 8192)) ] && pass "a first fill of $BIG zones needs at most 8 MB more than $SMALL zones" || fail "the resident size grows with the zones: ${R1:-?} KB -> ${R2:-?} KB"
[ -n "$R2" ] && [ "$R2" -le 40960 ] && pass "... and the loader stays under 40 MB" || fail "the loader is above 40 MB (${R2:-?} KB)"
grep '^STATE ' "$T/m1.out" > "$T/s1"; grep '^STATE ' "$T/m2.out" > "$T/s2"
sqlite3 "$D1" "UPDATE records SET ttl = 301 WHERE type = 'SOA'" > /dev/null
sqlite3 "$D2" "UPDATE records SET ttl = 301 WHERE type = 'SOA'" > /dev/null
"$FB" --store --cursor=state:"$T/s1" "$LOADER" "$D1" sleep:300 > "$T/d1.out" 2> "$T/d1.err"
"$FB" --store --cursor=state:"$T/s2" "$LOADER" "$D2" sleep:300 > "$T/d2.out" 2> "$T/d2.err"
R3=$(rss d1.out); R4=$(rss d2.out)
U1=$(grep '^CH ' "$T/d1.out" | sed -n 's/.* up=\([0-9]*\) .*/\1/p' | awk '{ s += $1 } END { print s + 0 }')
U2=$(grep '^CH ' "$T/d2.out" | sed -n 's/.* up=\([0-9]*\) .*/\1/p' | awk '{ s += $1 } END { print s + 0 }')
is "the drain of $SMALL changed zones: one upsert for each" "$U1" "$SMALL"
is "the drain of $BIG changed zones: one upsert for each" "$U2" "$BIG"
echo "  (resident size of the loader after the drain: ${R3:-?} KB at $SMALL zones, ${R4:-?} KB at $BIG zones)"
[ -n "$R3" ] && [ -n "$R4" ] && [ "$R4" -le $((R3 + 8192)) ] && pass "a drain of $BIG zones needs at most 8 MB more than $SMALL zones" || fail "the resident size of a drain grows with the zones: ${R3:-?} KB -> ${R4:-?} KB"

echo
echo "PASS=$PASS FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
