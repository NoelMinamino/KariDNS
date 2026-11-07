#!/bin/sh
# run_karidns_zone_pg_test.sh - karidns-zone (tools/karidns_zone.c) on PostgreSQL with the writer role (db/karidns_writer_role.pgsql.sql;
# 0.6.0 milestone M3).  The SQLite3 part of the tool is run_karidns_zone_test.sh; this test is about what PostgreSQL adds: a role that may write the
# zone tables but cannot read cryptokeys.content, a conninfo-file, the schema, reload requests, advisory locks and transactions that really roll back.
#
#  - a role karidns_test_zw_<pid> (LOGIN, a random password) gets the writer role script; karidns-zone with a conninfo-file of that role imports a
#    zone, replaces it, merges, runs a dry run (nothing is written), refuses a serial that does not grow, refuses a merge that puts a CNAME beside an A
#    record (rolled back: the row counts are the same), puts the zone in a view, adds a reload request with --reload, imports a tinydns data file with
#    --all, exports one zone and --all --dir, and gives the JSON document;
#  - what the tool writes equals what it writes into SQLite3: the same files imported into a SQLite3 database and into PostgreSQL give the same export,
#    byte for byte (the signed, tagged and tinydns fixtures of tests/);
#  - the role cannot read cryptokeys.content (SELECT is denied, also through a query the tool never makes), a zone with keys is imported with the
#    warning that the loader will refuse unsigned data, and the tool never needs more rights than the script gives;
#  - a conninfo-file with a wrong mode is refused before it is read; a role without the script cannot write (exit 1, the reason, nothing written).
# SKIP (exit 0, with the reason) when PostgreSQL is not reachable, the role may not create roles, karidns-zone has no PostgreSQL driver or the sqlite3
# tool is missing (for the comparison with SQLite3).  Runs as any user (as root the tool runs as the PostgreSQL user, see tests/db/pg_lib.sh).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

ZONE_BIN=${ZONE:-$ROOT/karidns-zone}
[ -x "$ZONE_BIN" ] || { echo "SKIP: $ZONE_BIN is not built"; exit 0; }
"$ZONE_BIN" --version | grep -q postgresql || { echo "SKIP: karidns-zone has no PostgreSQL driver"; exit 0; }
case $ZONE_BIN in *-asan) ASAN_OPTIONS="exitcode=99:${ASAN_OPTIONS:-}"; UBSAN_OPTIONS="halt_on_error=1:exitcode=99:${UBSAN_OPTIONS:-}"; export ASAN_OPTIONS UBSAN_OPTIONS ;; esac
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_zonepg.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
ROLE=""
cleanup() {
    pg_cleanup
    [ -n "$ROLE" ] && psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $ROLE" > /dev/null 2>&1
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
pg_setup zonetool || exit 0
HAVE_SQLITE=1
command -v sqlite3 >/dev/null 2>&1 || HAVE_SQLITE=0
"$ZONE_BIN" --version | grep -q sqlite3 || HAVE_SQLITE=0

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

ROLE="karidns_test_zw_$$"
PW="pw$$x$(date +%s)"
if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $ROLE LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
    ROLE=""
    echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"
    exit 0
fi
PORT=$(pq "SHOW port")
HOST=127.0.0.1
RC="host=$HOST port=$PORT user=$ROLE password=$PW"
if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$RC dbname=$PGDB" -c "SELECT 1" > /dev/null 2>&1; then
    echo "SKIP: the server does not accept a password login of the new role over $HOST:$PORT (pg_hba.conf)"
    exit 0
fi

# the tool and its inputs where the user it runs as can read them
Z=$T/karidns-zone
cp "$ZONE_BIN" "$Z" && chmod 755 "$Z"
mkdir "$T/in"
cp tests/db/tagz.test.zone tests/db/tdz.test.data tests/zones/example.com.zone tests/zones/example.com.dnskey tests/zones/example.com.hosts tests/zones/nsec.zone tests/matrix/zones/nsec_signed.zone tests/matrix/zones/all_types.zone "$T/in/"
chmod 755 "$T/in"; chmod 644 "$T"/in/*

# ---- the database: the PowerDNS schema, the extension; the role has nothing yet
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
printf '%s dbname=%s\n' "$RC" "$PGDB" > "$T/ci_role"
[ -n "$PG_AS" ] && chown "$PG_AS" "$T/ci_role"
chmod 600 "$T/ci_role"
CI=$T/ci_role
W=$T/w            # what the tool writes: $T belongs to root when the tool runs as PG_AS
mkdir "$W" && chmod 755 "$W"
[ -n "$PG_AS" ] && chown "$PG_AS" "$W"
OUT=$T/out.txt; ERR=$T/err.txt
# zt ARGS...: the tool as the role; the status in $st
zt() { as_pg "$Z" "$@" --no-config --conninfo-file "$CI" > "$OUT" 2> "$ERR" < /dev/null; st=$?; }
expect() { desc=$1; want=$2; shift 2; zt "$@"; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 400 "$OUT")"; fi; }
errhas() { if grep -q -- "$2" "$ERR"; then ok "$1"; else bad "$1 (stderr lacks '$2')" "$(cat "$ERR")"; fi; }
outhas() { if grep -q -- "$2" "$OUT"; then ok "$1"; else bad "$1 (stdout lacks '$2')" "$(head -c 600 "$OUT")"; fi; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
zone_serial() { pq "SELECT split_part(content, ' ', 3) FROM records WHERE type = 'SOA' AND name = '$1'"; }

mkzone() {      # mkzone FILE ORIGIN SERIAL [EXTRA]
    printf '$ORIGIN %s\n$TTL 300\n@ IN SOA ns1 hostmaster %s 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n' "$2" "$3" > "$1"
    [ -n "${4:-}" ] && printf '%s\n' "$4" >> "$1"
    chmod 644 "$1"
}

echo "== a role without the writer script"
mkzone "$T/ex.zone" example.test. 10 'www IN A 192.0.2.2
mail IN MX 10 www'
expect "an import by a role without privileges fails" 1 import example.test "$T/ex.zone"
grep -qi "permission denied\|does not exist\|read-only" "$ERR" && ok "...the message says why" || bad "...the message" "$(cat "$ERR")"
same "...nothing was written" "$(pq "SELECT count(*) FROM domains")" 0

echo "== the writer role script"
psql -X -q -At -v ON_ERROR_STOP=1 -v role=$ROLE -v schema=public -f db/karidns_writer_role.pgsql.sql "$PGC" > "$T/role.out" 2>&1 && ok "db/karidns_writer_role.pgsql.sql applies" || { bad "the role script" "$(head -5 "$T/role.out")"; exit 1; }
expect "a new zone" 0 import example.test "$T/ex.zone"
outhas "...reported as new" "(new)"
same "...type NATIVE" "$(pq "SELECT type FROM domains WHERE name = 'example.test'")" NATIVE
same "...the records" "$(pq "SELECT count(*) FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'example.test')")" 5
same "...MX priority in prio" "$(pq "SELECT prio FROM records WHERE type = 'MX'")" 10
n=$(pq "SELECT count(*) FROM karidns_changes"); [ "$n" -gt 0 ] && ok "...the change log has the change (written by the triggers with the role's rights)" || bad "...karidns_changes is empty"
mkzone "$T/m.zone" mzone.test. 1
expect "a new zone of type MASTER" 0 import --type MASTER mzone.test "$T/m.zone"
same "...type MASTER" "$(pq "SELECT type FROM domains WHERE name = 'mzone.test'")" MASTER
mkzone "$T/r.zone" example.test. 11 'new IN A 192.0.2.9
www IN A 192.0.2.2'
expect "replace" 0 import example.test "$T/r.zone"
same "...the old MX is gone" "$(pq "SELECT count(*) FROM records WHERE type = 'MX'")" 0
same "...the serial" "$(zone_serial example.test)" 11
printf '$ORIGIN example.test.\n$TTL 60\nwww IN A 192.0.2.81\nadded IN TXT "hi"\n' > "$T/merge.zone"; chmod 644 "$T/merge.zone"
before="$(pq "SELECT count(*) || ' ' || coalesce(sum(id), 0) FROM records")|$(pq "SELECT count(*) FROM karidns_changes")"
expect "dry run" 0 import --dry-run --mode merge example.test "$T/merge.zone"
errhas "...lists the changes" "add added.example.test TXT"
same "...nothing was written (rows, change log)" "$(pq "SELECT count(*) || ' ' || coalesce(sum(id), 0) FROM records")|$(pq "SELECT count(*) FROM karidns_changes")" "$before"
expect "merge" 0 import --mode merge example.test "$T/merge.zone"
same "...www A replaced" "$(pq "SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND ttl = 60")" 1
same "...new stays" "$(pq "SELECT count(*) FROM records WHERE name = 'new.example.test'")" 1
expect "the serial must grow" 1 import example.test "$T/r.zone"
errhas "...with the reason" "does not grow"
expect "--serial increment" 0 import --serial increment example.test "$T/r.zone"
same "...12" "$(zone_serial example.test)" 12
expect "--serial keep" 0 import --serial keep example.test "$T/r.zone"
same "...11" "$(zone_serial example.test)" 11

echo "== the read-back is a transaction that rolls back"
n0=$(pq "SELECT count(*) FROM records"); c0=$(pq "SELECT count(*) FROM karidns_changes")
printf '$ORIGIN example.test.\n$TTL 300\nwww IN CNAME mail\nzzz IN A 192.0.2.77\n' > "$T/cn.zone"; chmod 644 "$T/cn.zone"
expect "a merge that puts a CNAME beside an A record is refused" 1 import --mode merge example.test "$T/cn.zone"
errhas "...by the checks of the zone as written" "coexists"
same "...no record was added" "$(pq "SELECT count(*) FROM records")" "$n0"
same "...the change log did not grow" "$(pq "SELECT count(*) FROM karidns_changes")" "$c0"
printf '$ORIGIN example.test.\n$TTL 300\nwww IN ALIAS lb.target.test.\n' > "$T/al.zone"; chmod 644 "$T/al.zone"
expect "an ALIAS beside an A record is refused" 1 import --mode merge example.test "$T/al.zone"
same "...no ALIAS was written" "$(pq "SELECT count(*) FROM records WHERE type = 'ALIAS'")" 0
expect "the zone checks refuse a bad zone" 1 import --strict example.test "$T/cn.zone"

echo "== views, reload requests, schema"
mkzone "$T/v.zone" viewed.test. 1
expect "--view puts the zone in karidns_domain_views" 0 import --view internal viewed.test "$T/v.zone"
same "...the row" "$(pq "SELECT view_name FROM karidns_domain_views")" internal
expect "--reload adds a row to karidns_reload_requests" 0 import --reload --serial keep viewed.test "$T/v.zone"
same "...one request for the zone" "$(pq "SELECT count(*) FROM karidns_reload_requests WHERE zone = 'viewed.test'")" 1
expect "export --view lists the zone of the view" 0 export --view internal viewed.test
expect "export of a zone that is not in the view" 1 export --view other viewed.test
expect "a schema that does not exist" 1 import --schema nosuchschema viewed.test "$T/v.zone"

echo "== tinydns, export, backup"
expect "import --all" 0 import --all "$T/in/tdz.test.data"
outhas "...the summary" "1 zone(s) imported, 0 failed"
same "...a tinydns zone" "$(pq "SELECT count(*) FROM domainmetadata WHERE kind = 'X-KARIDNS-FORMAT'")" 1
expect "export of one zone" 0 export example.test "$W/o.zone"
head -1 "$W/o.zone" | grep -q 'ORIGIN example.test' && ok "...BIND format" || bad "...format" "$(head -2 "$W/o.zone")"
expect "export --all --dir" 0 export --all --dir "$W/bk"
for f in example.test.zone mzone.test.zone viewed.test.zone tdz.test.tinydns; do
    [ -f "$W/bk/$f" ] && ok "...$f" || bad "...no $f" "$(ls "$W/bk")"
done
expect "again: existing files are refused" 1 export --all --dir "$W/bk"
expect "--json import" 0 --json import --serial keep example.test "$T/r.zone"
ZT_JSON=$OUT
zt --json export example.test "$W/oj.zone"
grep -q '"karidns-zone": 1' "$OUT" && ok "...the JSON document of export" || bad "...no document" "$(head -c 300 "$OUT")"

echo "== the role and the keys"
rq() { PGCONNECT_TIMEOUT=5 psql -X -q -At "$RC dbname=$PGDB" -c "$1"; }
pq "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 257, true, 'PRIVATE-KEY-MATERIAL-DO-NOT-READ')"
rq "SELECT content FROM cryptokeys" > "$T/ck.out" 2>&1; grep -q "permission denied" "$T/ck.out" && ! grep -q "PRIVATE-KEY" "$T/ck.out" && ok "the writer role cannot read cryptokeys.content" || bad "cryptokeys.content" "$(head -2 "$T/ck.out")"
rq "SELECT * FROM cryptokeys" > "$T/ck2.out" 2>&1; grep -q "permission denied" "$T/ck2.out" && ok "SELECT * FROM cryptokeys is denied" || bad "SELECT * FROM cryptokeys"
rq "UPDATE cryptokeys SET active = false" > "$T/ck3.out" 2>&1; grep -q "permission denied" "$T/ck3.out" && ok "the role cannot change cryptokeys" || bad "UPDATE cryptokeys"
expect "a zone with keys gets unsigned data: imported, with the warning" 0 import --serial increment example.test "$T/r.zone"
errhas "...the loader will refuse the zone" "cryptokeys"
expect "export of a zone with keys but no PRESIGNED" 1 export example.test
errhas "...the reason" "PRESIGNED"
pq "DELETE FROM cryptokeys"

echo "== the conninfo-file"
chmod 644 "$T/ci_role"
expect "a conninfo-file with mode 0644 is refused" 1 export example.test
errhas "...before it is read" "0600 or 0400"
grep -q "$PW" "$ERR" "$OUT" && bad "...the password is in the output" || ok "...the password is not in the output"
chmod 400 "$T/ci_role"
expect "mode 0400 is accepted" 0 export example.test
chmod 600 "$T/ci_role"

echo "== PostgreSQL and SQLite3 write the same rows"
if [ $HAVE_SQLITE = 0 ]; then echo "  (no sqlite3 tool or no SQLite3 driver: skipped)"; else
    cmp_one() {     # cmp_one NAME APEX FILE [FORMAT]
        name=$1; apex=$2; file=$3; fmt=${4:-bind}
        sdb=$T/cmp_$name.db; rm -f "$sdb"
        sqlite3 "$sdb" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$sdb" < db/karidns_ext.sqlite3.sql > /dev/null
        "$Z" import --no-config --sqlite3 "$sdb" --format "$fmt" "$apex" "$file" > /dev/null 2> "$T/cmp.err" || { bad "$name: SQLite3 import" "$(head -3 "$T/cmp.err")"; return; }
        zt import --serial keep --format "$fmt" "$apex" "$file"
        [ $st = 0 ] || { bad "$name: PostgreSQL import" "$(head -3 "$ERR")"; return; }
        "$Z" export --no-config --sqlite3 "$sdb" "$apex" > "$T/cmp.sq" 2>/dev/null
        zt export "$apex"
        cp "$OUT" "$T/cmp.pg"
        if cmp -s "$T/cmp.sq" "$T/cmp.pg" && [ -s "$T/cmp.pg" ]; then ok "$name: the export of the PostgreSQL zone is the export of the SQLite3 zone ($(wc -l < "$T/cmp.pg" | tr -d ' ') lines)"
        else bad "$name: PostgreSQL and SQLite3 differ" "$(diff "$T/cmp.sq" "$T/cmp.pg" | head -6)"; fi
    }
    cmp_one tags tagz.test "$T/in/tagz.test.zone"
    cmp_one signed_nsec nsec.example "$T/in/nsec.zone"
    cmp_one signed_nsec2 nsec.test "$T/in/nsec_signed.zone"
    cmp_one signed_nsec3 example.com "$T/in/example.com.zone"
    cmp_one all_types alltypes.test "$T/in/all_types.zone"
    cmp_one tinydns tdz.test "$T/in/tdz.test.data" tinydns
fi

echo "== import --signer: a zone with 2000 hosts is written in a few statements (0.6.0 item C)"
N=2000
{
    printf '$ORIGIN big.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n'
    awk -v n=$N 'BEGIN { for (i = 1; i <= n; i++) printf "h%04d IN A 192.0.2.%d\n", i, i % 250 + 1 }'
} > "$T/big.zone"
# the signed zone: an NSEC chain in canonical order (apex, h0001 ... h2000, ns1) and a fake signature for every RRset
awk -v n=$N 'BEGIN {
    sig = "AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o"
    r3 = " 8 3 300 20350101000000 20250101000000 12345 big.test. " sig
    r2 = " 8 2 300 20350101000000 20250101000000 12345 big.test. " sig
    printf "$ORIGIN big.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 2 7200 3600 1209600 300\n@ IN NS ns1\n@ IN DNSKEY 257 3 8 %s\n", sig
    printf "@ IN NSEC h0001.big.test. NS SOA RRSIG NSEC DNSKEY\n@ IN RRSIG SOA%s\n@ IN RRSIG NS%s\n@ IN RRSIG DNSKEY%s\n@ IN RRSIG NSEC%s\n", r2, r2, r2, r2
    for (i = 1; i <= n; i++) {
        nxt = (i < n) ? sprintf("h%04d.big.test.", i + 1) : "ns1.big.test."
        printf "h%04d IN A 192.0.2.%d\nh%04d IN NSEC %s A RRSIG NSEC\nh%04d IN RRSIG A%s\nh%04d IN RRSIG NSEC%s\n", i, i % 250 + 1, i, nxt, i, r3, i, r3
    }
    printf "ns1 IN A 192.0.2.1\nns1 IN NSEC big.test. A RRSIG NSEC\nns1 IN RRSIG A%s\nns1 IN RRSIG NSEC%s\n", r3, r3
}' > "$T/big.signed"
chmod 644 "$T/big.zone" "$T/big.signed"
expect "a zone with $N hosts" 0 import big.test "$T/big.zone"
pq "SELECT karidns_auth.enable_audit('public')" > /dev/null
C0=$(pq "SELECT count(*) FROM karidns_changes"); A0=$(pq "SELECT count(*) FROM karidns_auth.audit_log")
expect "import --signer writes the signed zone" 0 import --signer big.test "$T/big.signed"
C1=$(pq "SELECT count(*) FROM karidns_changes"); A1=$(pq "SELECT count(*) FROM karidns_auth.audit_log")
same "...the serial grew by one, the signatures are in (2 per host, 2 for ns1, 4 at the apex)" "$(zone_serial big.test)|$(pq "SELECT count(*) FROM records WHERE type = 'RRSIG' AND name LIKE '%big.test'")" "2|$((2 * N + 6))"
same "...ordername of the hosts (NSEC zone: the reversed relative name)" "$(pq "SELECT ordername FROM records WHERE name = 'h0007.big.test' AND type = 'A'")" h0007
if [ $((C1 - C0)) -ge 1 ] && [ $((C1 - C0)) -le 40 ]; then ok "...the change log got $((C1 - C0)) rows for $((2 * N + 6)) DNSSEC rows and $N updated ones (statement level, not one per row)"; else bad "...the change log grew by $((C1 - C0)) rows"; fi
if [ $((A1 - A0)) -ge 1 ] && [ $((A1 - A0)) -le 40 ]; then ok "...the audit log got $((A1 - A0)) rows (summary mode is the default of --signer)"; else bad "...the audit log grew by $((A1 - A0)) rows"; fi
same "...the audit rows are summaries" "$(pq "SELECT count(*) FROM (SELECT * FROM karidns_auth.audit_log ORDER BY id DESC LIMIT $((A1 - A0))) a WHERE (after ->> 'summary') IS NULL AND table_name = 'records'")" 0
mkzone "$T/big.zone2" big.test. 3
expect "an import of unsigned data into the signed zone keeps its DNSSEC rows (the signer's zone)" 0 import big.test "$T/big.zone2"
same "...the signatures are still there" "$(pq "SELECT count(*) FROM records WHERE type = 'RRSIG' AND name LIKE '%big.test'")" "$((2 * N + 6))"
same "...and the metadata PRESIGNED and X-KARIDNS-SIGNER" "$(pq "SELECT string_agg(kind, ',' ORDER BY kind) FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = 'big.test')")" "PRESIGNED,X-KARIDNS-SIGNER"
if grep -q "signed by karidns-signer" "$OUT" "$ERR"; then ok "...and the note says so (db.import.signer-zone)"; else bad "...no note about the signer's zone" "$(cat "$ERR"; head -c 400 "$OUT")"; fi
C2=$(pq "SELECT count(*) FROM karidns_changes")
mkzone "$T/big.signed3" big.test. 5
expect "--audit rows is accepted with --signer (here a dry run of a file that is not signed: refused)" 1 import --signer --audit rows --dry-run big.test "$T/big.signed3"
same "...nothing was written" "$(pq "SELECT count(*) FROM karidns_changes")" "$C2"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_karidns_zone_pg_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_karidns_zone_pg_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
