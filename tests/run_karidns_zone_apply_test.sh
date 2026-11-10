#!/bin/sh
# run_karidns_zone_apply_test.sh - karidns-zone apply (tools/karidns_zone.c, dns_zone_changes.c; docs/karidns-zone.md "apply" and "The change file") and the
# schema it relies on (0.6.0 items D and E, milestone M1: the C and SQL foundation of the API with permission checks, templates and zone versions).
#
#  1. SQLite3: usage errors, --types-list, the change file (stdin, comments, CRLF; every hostile line is refused and nothing is written), a dry run (the JSON
#     document: generation, serial, the RRsets changed with their records before and after, the version it would write; nothing stays), --expect-generation
#     (exit status 3), the real change (principal, name and change set in the audit log and the version row, the serial raised, the RRset rows of the version),
#     delete, create, a zone that is not there, the retention of the versions (the trigger's 100 replaced by 3), --readback changed, a busy database (exit
#     status 4), the zone versions of an operator's import, the generation of the zone, the tables and triggers of the auth file (sessions, api_tokens,
#     templates, template_records: constraints, revision, redaction in the audit, delete cascades), and the migration of a version 3 file made before M1.
#  2. PostgreSQL (SKIP without a server that takes password logins over 127.0.0.1): the roles of db/karidns_api_role.pgsql.sql (row level security on),
#     db/karidns_check_role.pgsql.sql and db/karidns_writer_role.pgsql.sql.  The CHECK role (assumption 13.2 of the plan): its dry run works, and a transaction of
#     its login role that wrote a row of any table the dry run writes cannot commit (also after SET ROLE); the commit run as the API role (--readback changed,
#     the serial through karidns_auth.bump_serial): a domain master and a subdomain master change what their grants cover and RLS refuses the rest (rolled back);
#     the audit rows name the principal and the change set; the version rows and their RLS; sessions, api_tokens, templates (RLS, the lookups, redaction);
#     the generation conflict between the check run and the commit run (exit status 3) and the zone lock (exit status 4); the retention.
# Environment: ZONE (default ./karidns-zone; ./karidns-zone-asan runs the ASan build).  SKIP (exit 0, with the reason) without the binary, the sqlite3 tool or
# perl JSON::PP (each part on its own).  Runs as any user (it never needs root).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

ZONE=${ZONE:-$ROOT/karidns-zone}
case $ZONE in /*) ;; *) ZONE=$ROOT/${ZONE#./} ;; esac
JC="perl $ROOT/tests/lib/json_check.pl"
[ -x "$ZONE" ] || { echo "SKIP: $ZONE is not built"; exit 0; }
perl -MJSON::PP -e 1 >/dev/null 2>&1 || { echo "SKIP: perl JSON::PP is not installed"; exit 0; }
case $ZONE in *-asan) ASAN_OPTIONS="exitcode=99:${ASAN_OPTIONS:-}"; UBSAN_OPTIONS="halt_on_error=1:exitcode=99:${UBSAN_OPTIONS:-}"; export ASAN_OPTIONS UBSAN_OPTIONS ;; esac

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_apply.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
ROLES=""
cleanup() {
    pg_cleanup
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    jobs -p 2>/dev/null | xargs kill 2>/dev/null
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
OUT=$T/out.txt; ERR=$T/err.txt
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
errhas() { if grep -q -- "$2" "$ERR"; then ok "$1"; else bad "$1 (stderr lacks '$2')" "$(cat "$ERR")"; fi; }
outhas() { if grep -q -- "$2" "$OUT"; then ok "$1"; else bad "$1 (stdout lacks '$2')" "$(head -c 600 "$OUT")"; fi; }
jvalid() { if msg=$($JC "$OUT" valid 2>&1); then ok "$1: a valid document"; else bad "$1: $msg" "$(head -c 800 "$OUT")"; fi; }
jget() { got=$($JC "$OUT" get "$2" 2>&1); if [ "$got" = "$3" ]; then ok "$1"; else bad "$1 ($2: got '$got', wanted '$3')" "$(head -c 800 "$OUT")"; fi; }
HDR='$ORIGIN %s\n$TTL 300\n@ IN SOA ns1 hostmaster %s 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n'
mkzone() { printf "$HDR" "$2" "$3" > "$1"; [ -n "${4:-}" ] && printf '%s\n' "$4" >> "$1"; chmod 644 "$1"; }

# ================================================================ 1. SQLite3
echo "== SQLite3"
if ! command -v sqlite3 >/dev/null 2>&1; then echo "  SKIP: the sqlite3 command line tool is not installed"
elif ! "$ZONE" --version | grep -q sqlite3; then echo "  SKIP: $ZONE has no SQLite3 driver"
else
DB=$T/z.db
newdb() { rm -f "$1" "$1-wal" "$1-shm"; sqlite3 "$1" < "$ROOT/tests/db/pdns_schema.sqlite3.sql" > /dev/null && sqlite3 "$1" < "$ROOT/db/karidns_ext.sqlite3.sql" > /dev/null && sqlite3 "$1" < "$ROOT/db/karidns_audit.sqlite3.sql" > /dev/null; }
q() { sqlite3 "$DB" "$1"; }
IN=/dev/null
ka() { "$ZONE" apply --no-config --sqlite3 "$DB" "$@" > "$OUT" 2> "$ERR" < "$IN"; st=$?; }
kz() { cmd=$1; shift; "$ZONE" "$cmd" --no-config --sqlite3 "$DB" "$@" > "$OUT" 2> "$ERR" < "$IN"; st=$?; }
run() { desc=$1; want=$2; shift 2; "$ZONE" "$@" > "$OUT" 2> "$ERR" < "$IN"; st=$?; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 400 "$OUT")"; fi; }
aexp() { desc=$1; want=$2; shift 2; ka "$@"; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 600 "$OUT")"; fi; }
serial() { q "SELECT content FROM records WHERE type = 'SOA' AND name = '$1'" | awk '{print $3}'; }
gen() { q "SELECT generation FROM karidns_zone_state WHERE domain_id = (SELECT id FROM domains WHERE name = '$1')"; }
CH=$T/ch.txt

echo "-- usage"
newdb "$DB"
printf 'rr www.example.test. 300 A 192.0.2.9\n' > "$CH"
run "apply without arguments" 2 apply
run "apply without --changes" 2 apply --no-config --sqlite3 "$DB" example.test
run "apply without a zone" 2 apply --no-config --sqlite3 "$DB" --changes "$CH"
run "apply with two zones" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" a b
run "--expect-generation x" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --expect-generation x example.test
run "--expect-generation with --create" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --create --expect-generation 1 example.test
run "--principal abc" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --principal abc example.test
run "--principal with 19 digits" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --principal 1234567890123456789 example.test
run "--principal-name without --principal" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --principal-name bob example.test
run "--change-set with a blank" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --change-set 'a b' example.test
run "--readback bogus" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --readback bogus example.test
run "--version-kind bogus" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --version-kind bogus example.test
run "--version-kind rollback without --rollback-of" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --version-kind rollback example.test
run "--rollback-of without a rollback" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --rollback-of 3 example.test
run "--create with --version-kind" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --create --version-kind edit example.test
run "--type without --create" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --type MASTER example.test
run "--mode on apply" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --mode merge example.test
run "--all on apply" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --all example.test
run "--signer on apply" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --signer example.test
run "--serial bogus" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --serial bogus example.test
run "--comment over 1024 octets" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --comment "$(head -c 1100 /dev/zero | tr '\0' x)" example.test
run "--changes and --zone-file together" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --zone-file "$CH" example.test
run "--delete-others without --zone-file" 2 apply --no-config --sqlite3 "$DB" --changes "$CH" --delete-others example.test
run "--delete-others with --create" 2 apply --no-config --sqlite3 "$DB" --zone-file "$CH" --create --delete-others example.test
run "--zone-file on import" 2 import --no-config --sqlite3 "$DB" --zone-file "$CH" example.test /dev/null
run "--changes on import" 2 import --no-config --sqlite3 "$DB" --changes "$CH" example.test /dev/null
run "--principal on export" 2 export --no-config --sqlite3 "$DB" --principal 7 example.test
run "--types-list with a command" 2 --types-list apply
errhas "...says what is wrong" "takes no command"

echo "-- the examples of --help"
printf 'options { database { driver sqlite3; database-file "%s"; }; };\n' "$DB" > "$T/k.conf"
printf 'rr help.example.test. 60 A 192.0.2.99\n' > "$T/changes.txt"
mkzone "$T/h.zone" example.test. 10; kz import example.test "$T/h.zone"
"$ZONE" --help | grep '^  karidns-zone \(apply -\|--types-list$\)' > "$T/examples.txt"
[ "$(wc -l < "$T/examples.txt" | tr -d ' ')" -ge 3 ] && ok "--help has the examples of apply and --types-list" || bad "no examples in --help" "$(cat "$T/examples.txt")"
while IFS= read -r line; do
    cmd=$(printf '%s' "$line" | sed -e "s#^  karidns-zone#$ZONE#" -e "s#/var/db/karidns/pdns.sqlite3#$DB#" -e "s#/usr/local/etc/karidns/karidns.conf#$T/k.conf#" -e "s#< changes.txt#< $T/changes.txt#" -e "s# changes.txt# $T/changes.txt#" -e "s# example.test.zone# $T/h.zone#")
    sh -c "$cmd" > "$OUT" 2> "$ERR"; st=$?
    if [ "$st" = 0 ] || [ "$st" = 3 ]; then ok "the example runs ($st): $(printf '%s' "$line" | cut -c3-70)"; else bad "the example fails ($st): $line" "$(cat "$ERR")"; fi
done < "$T/examples.txt"
newdb "$DB"

echo "-- --types-list"
run "--types-list" 0 --types-list
for t in A AAAA MX TXT CAA SRV CNAME NS PTR SOA; do grep -qx "$t" "$OUT" && ok "...$t" || bad "...no $t" "$(head -5 "$OUT")"; done
for t in RRSIG NSEC NSEC3 DNSKEY ANY AXFR OPT TSIG; do grep -qx "$t" "$OUT" && bad "...$t must not be listed" || ok "...no $t"; done
run "--types-list --json" 0 --types-list --json
jvalid "--types-list --json"
jget "...the command" command types

echo "-- render (item F, the WebAdmin GUI: stored records as the text a change set takes)"
printf 'mail.example.test\tMX\t10\tmail2.example.test\nwww.example.test\tTXT\t-\t"hello" "wor ld"\nexample.test\tSOA\t0\tns1.example.test hostmaster.example.test 10 7200 3600 1209600 300\nx.example.test\tA\t-\tbad\nx.example.test\tMX\t5\t10 mail\nn.example.test\tMX\t-\t0 .\n_sip._tcp.example.test\tSRV\t3\t5 5060 sip.example.test\nfoo.other.test\tA\t-\t192.0.2.1\nt.example.test\tTXT\t-\ta;b' > "$T/render.in"
IN="$T/render.in"
run "render --json" 0 render --json example.test
jvalid "render --json"
jget "...the command" command render
jget "...an MX: the priority in front, every name absolute" render.rdata.0 "10 mail2.example.test."
jget "...a TXT" render.rdata.1 '"hello" "wor ld"'
jget "...the SOA at the apex" render.rdata.2 "ns1.example.test. hostmaster.example.test. 10 7200 3600 1209600 300"
jget "...a bad address is null" render.rdata.3 null
jget "...a priority twice is null" render.rdata.4 null
jget "...the null MX has the root name (not @, which would be the origin of the zone)" render.rdata.5 "0 ."
jget "...an SRV" render.rdata.6 "3 5 5060 sip.example.test."
jget "...a name outside the zone is null" render.rdata.7 null
jget "...a comment in a string is null" render.rdata.8 null
jget "...one entry for each line, an error for each null" render.errors.0.index 3
jget "...(the reason has neither the zone nor the row)" render.errors.0.text "invalid IPv4 address literal in A record"
jget "...a priority twice" render.errors.1.text "MX content already has a preference and prio is 5: ambiguous"
jget "...the last one" "render.errors.3.index" 8
same "...and there are four" "$($JC "$OUT" count render.errors)" 4
IN=/dev/null
printf '' > "$T/empty.in"; IN="$T/empty.in"
run "render of nothing" 0 render --json example.test
jvalid "render of nothing"
jget "...no records" render.rdata "[]"
printf 'only-an-owner\n' > "$T/render.in"; IN="$T/render.in"
run "render of a line that is not four fields" 1 render --json example.test
jvalid "...a document with the failure"
jget "...db.render.input" messages.0.code db.render.input
jget "...names the line" messages.0.text "line 1: the line has fewer than four fields (owner, type, prio, content)"
printf 'a.example.test\tA\t1x\t192.0.2.1\n' > "$T/render.in"
run "render: a prio that is not a number" 1 render --json example.test
printf 'a.example.test\tTXT\t-\t"x"\nb\n' > "$T/render.in"
run "render: the second line is the wrong one" 1 render --json example.test
jget "...names the line" messages.0.text "line 2: the line has fewer than four fields (owner, type, prio, content)"
IN=/dev/null
run "render without --json" 2 render example.test
errhas "...says why" "render needs --json"
run "render without a zone" 2 render --json
run "render with two zones" 2 render --json a.test b.test
run "render with a database option" 2 render --json --sqlite3 "$DB" example.test
run "render with --no-config" 2 render --json --no-config example.test
run "render with -c" 2 render --json -c /nonexistent example.test
run "render with --mode" 2 render --json --mode merge example.test
run "render with --changes" 2 render --json --changes "$CH" example.test
run "render of a zone that is not a name" 1 render --json 'a..b'
run "--types-list with render" 2 --types-list render
printf 'a.example.test\tA\t-\t192.0.2.1\n' > "$T/render.in"; IN="$T/render.in"
run "render: the zone with its final dot, any case" 0 render --json EXAMPLE.test.
jget "...renders" render.rdata.0 192.0.2.1
IN=/dev/null
"$ZONE" --help | grep -c 'karidns-zone render --json example.test$' | grep -q '^1$' && ok "--help has the example of render" || bad "no example of render in --help"
"$ZONE" --help | grep '^  printf .*karidns-zone render --json example.test$' | sed "s#karidns-zone render#$ZONE render#" > "$T/render_example.sh"
sh "$T/render_example.sh" > "$OUT" 2> "$ERR"; st=$?
if [ "$st" = 0 ]; then ok "the example of --help runs"; else bad "the example of --help fails ($st)" "$(cat "$ERR")"; fi
jget "...it gives the MX as a change set takes it" render.rdata.0 "10 mail2.example.test."
# the root name in a diff (apply): "0 ." and not "0 @", which a change file would read as the zone's own name
newdb "$DB"; mkzone "$T/nm.zone" example.test. 10; kz import example.test "$T/nm.zone"
printf 'rr n.example.test. 300 MX 0 .\nrr s.example.test. 300 SRV 0 0 0 .\nrr naptr.example.test. 300 NAPTR 100 10 "" "" "" .\n' > "$T/nm.changes"
ka --dry-run --json --changes "$T/nm.changes" example.test
jget "apply: the root name in the diff of a null MX is a dot" apply.diff.0.after.0 "300 MX 0 ."
jget "...of an SRV with no target" apply.diff.2.after.0 "300 SRV 0 0 0 ."
jget "...of a NAPTR replacement" apply.diff.1.after.0 '300 NAPTR 100 10 "" "" "" .'
newdb "$DB"

echo "-- the generation and the versions of an operator's import"
mkzone "$T/ex.zone" example.test. 10 'www IN A 192.0.2.2
mail IN MX 10 www
old IN TXT "old"'
kz import example.test "$T/ex.zone"; [ $st = 0 ] && ok "import" || bad "import" "$(cat "$ERR")"
g0=$(gen example.test)
[ -n "$g0" ] && [ "$g0" -gt 0 ] && ok "the zone has a generation ($g0)" || bad "no generation"
same "...version 1 is the import" "$(q "SELECT kind || ' ' || coalesce(serial_before, 'none') || ' ' || serial_after || ' ' || generation_before || ' ' || delta_complete FROM karidns_zone_versions WHERE version = 1")" "import none 10 0 1"
same "...its RRsets (every RRset of the new zone)" "$(q "SELECT count(*) FROM karidns_zone_version_rrsets")" 6
kz import --serial keep example.test "$T/ex.zone"
same "...an import writes the generation again" "$([ "$(gen example.test)" -gt "$g0" ] && echo grew)" grew
same "...a second import that changes nothing writes no version" "$(q "SELECT count(*) FROM karidns_zone_versions")" 1
q "UPDATE records SET ttl = ttl WHERE 0" >/dev/null
g1=$(gen example.test)
sqlite3 "$DB" "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 'X-T', '1')"
same "...a metadata row grows it too (every writer does)" "$([ "$(gen example.test)" -gt "$g1" ] && echo grew)" grew
q "DELETE FROM domainmetadata WHERE kind = 'X-T'"

echo "-- the change file"
printf '# comment\n\r\n  rr WWW.example.test.\t300\ta 192.0.2.20   \r\nrr www.example.test. 300 A 192.0.2.21\ndelete old.example.test. txt\nrr new.example.test. 60 TXT "a;b ( c"\n' > "$CH"
a0=$(q "SELECT count(*) FROM karidns_audit_log")
ka --dry-run --json --changes "$CH" example.test
[ $st = 0 ] && ok "a dry run" || bad "a dry run: exit status $st" "$(cat "$ERR"; head -c 400 "$OUT")"
jvalid "the dry run"
jget "...a dry run" apply.dry_run true
jget "...not committed" apply.committed false
jget "...the generation" apply.generation "$(gen example.test)"
jget "...the serial raised" apply.serial.after 11
jget "...it would write version 2" apply.version 2
jget "...three RRsets" apply.diff.*.type "TXT
TXT
A"
jget "...the lines of the RRset before" apply.diff.2.before.0 "300 A 192.0.2.2"
jget "...and after (canonical order)" apply.diff.2.after.1 "300 A 192.0.2.21"
jget "...an added RRset has no before" apply.diff.0.before null
jget "...the records of the zone before and after" apply.records_after 7
same "...nothing was written" "$(q "SELECT count(*) FROM records") $(q "SELECT count(*) FROM karidns_zone_versions") $(serial example.test)" "6 1 10"
same "...and no audit row" "$(q "SELECT count(*) FROM karidns_audit_log")" "$a0"
ka --dry-run --changes "$CH" example.test
errhas "...the report in the text mode" "replace www.example.test A"
ka --expect-generation $((g0 + 99)) --changes "$CH" example.test
same "--expect-generation: the zone is not at that generation, exit status 3" "$st" 3
errhas "...says so" "generation"
same "...nothing was written" "$(q "SELECT count(*) FROM records")" 6
ka --json --expect-generation $((g0 + 99)) --changes "$CH" example.test
jvalid "the document of a zone that changed"
jget "...changed" apply.changed true
G=$(gen example.test)
ka --json --expect-generation "$G" --principal 42 --principal-name alice --change-set cs-1 --comment "move www" --changes "$CH" example.test
[ $st = 0 ] && ok "the change, at the generation the dry run printed" || bad "the change" "$(cat "$ERR")"
jget "...committed" apply.committed true
jget "...version 2" apply.version 2
same "...the records" "$(q "SELECT group_concat(content, ',') FROM (SELECT content FROM records WHERE name = 'www.example.test' ORDER BY content)")" "192.0.2.20,192.0.2.21"
same "...the TXT is gone, the new one is there" "$(q "SELECT count(*) FROM records WHERE name = 'old.example.test'")$(q "SELECT content FROM records WHERE name = 'new.example.test'")" '0"a;b ( c"'
same "...the serial is raised" "$(serial example.test)" 11
same "...the version row" "$(q "SELECT kind || '|' || change_set || '|' || principal_id || '|' || principal_name || '|' || comment || '|' || serial_before || '|' || serial_after || '|' || generation_before FROM karidns_zone_versions WHERE version = 2")" "edit|cs-1|42|alice|move www|10|11|$G"
same "...its RRsets (the serial of the SOA is not versioned)" "$(q "SELECT count(*) FROM karidns_zone_version_rrsets WHERE version_id = (SELECT id FROM karidns_zone_versions WHERE version = 2)")" 3
same "...the audit names the principal and the change set" "$(q "SELECT count(DISTINCT principal_name || change_set || db_role) FROM karidns_audit_log")" 1
same "...the actor row is gone again" "$(q "SELECT count(*) FROM karidns_audit_actor")" 0
same "...the generation grew" "$([ "$(gen example.test)" -gt "$G" ] && echo grew)" grew
aexp "the same change again: nothing to do" 0 --json --changes "$CH" example.test
jget "...no RRset changed" apply.diff.* ""
same "...no new version, no new serial" "$(q "SELECT count(*) FROM karidns_zone_versions")$(serial example.test)" 211

echo "-- standard input, delete, SOA, --serial, --readback changed"
printf 'delete www.example.test. A\nrr example.test. 300 SOA ns1.example.test. hostmaster.example.test. 500 7200 3600 1209600 300\n' > "$CH"
IN=$CH aexp "the change file on standard input; an SOA of its own gets database serial + 1" 0 --changes - example.test
same "...the serial" "$(serial example.test)" 12
same "...the A records are gone" "$(q "SELECT count(*) FROM records WHERE name = 'www.example.test'")" 0
same "...the SOA changed only in its serial: no version" "$(q "SELECT count(*) FROM karidns_zone_versions WHERE version = 3")$(q "SELECT count(*) FROM karidns_zone_version_rrsets s JOIN karidns_zone_versions v ON v.id = s.version_id WHERE v.version = 3")" "11"
printf 'rr example.test. 3600 SOA ns1.example.test. hostmaster.example.test. 3 7200 3600 1209600 300\n' > "$CH"
aexp "--serial grow: a serial that does not grow is refused" 1 --serial grow --changes "$CH" example.test
errhas "...with the reason" "does not grow"
printf 'rr q.example.test. 60 A 192.0.2.30\nrr q.example.test. 60 A 192.0.2.31\n' > "$CH"
aexp "--readback changed" 0 --readback changed --changes "$CH" example.test
same "...the rows are there" "$(q "SELECT count(*) FROM records WHERE name = 'q.example.test'")" 2
printf 'rr r.example.test. 60 A 192.0.2.32\n' > "$CH"
aexp "--serial keep" 0 --serial keep --changes "$CH" example.test
same "...the serial stays" "$(serial example.test)" 13
printf 'rr www.example.test. 60 CNAME q.example.test.\nrr q.example.test. 60 CNAME www.example.test.\n' > "$CH"
aexp "a change the checks of the zone as written refuse (a CNAME beside an A record)" 1 --changes "$CH" example.test
errhas "...by the read-back" "coexists"
same "...rolled back" "$(q "SELECT count(*) FROM records WHERE name = 'q.example.test' AND type = 'A'")" 2

echo "-- hostile change files"
n0=$(q "SELECT count(*) FROM records"); v0=$(q "SELECT count(*) FROM karidns_zone_versions")
i=0
while IFS='|' read -r why line; do
    i=$((i + 1))
    printf "$line" > "$CH"
    aexp "refused: $why" 1 --changes "$CH" example.test
    [ "$(q "SELECT count(*) FROM records")" = "$n0" ] && [ "$(q "SELECT count(*) FROM karidns_zone_versions")" = "$v0" ] || bad "...rows were written ($why)"
done <<'EOF'
a directive after the RDATA|rr z.example.test. 60 TXT "a" ; $INCLUDE /etc/passwd\n
an open quote|rr z.example.test. 60 TXT "open\nrr y.example.test. 60 A 192.0.2.1\n
an open group|rr z.example.test. 60 TXT ( a\nrr y.example.test. 60 A 192.0.2.1\n
a directive as RDATA|rr z.example.test. 60 TXT $ORIGIN evil.\n
a record of another zone|rr z.example.org. 60 A 192.0.2.1\n
a name that only ends like the zone|rr zexample.test. 60 A 192.0.2.1\n
a relative owner|rr z 60 A 192.0.2.1\n
a signature|rr z.example.test. 60 RRSIG A 13 3 60 20300101000000 20200101000000 1 example.test. AAAA\n
a type of the signer in the generic form|rr z.example.test. 60 TYPE46 \\# 1 00\n
a TTL that is too big|rr z.example.test. 4294967296 A 192.0.2.1\n
a delete and a replacement of one RRset|delete z.example.test. A\nrr z.example.test. 60 A 192.0.2.1\n
the apex SOA deleted|delete example.test. SOA\n
EOF
same "...no version was written" "$(q "SELECT count(*) FROM karidns_zone_versions")" "$v0"
printf 'rr z.example.test. 60 MX 10\n' > "$CH"
aexp "an MX without a target" 1 --changes "$CH" example.test
errhas "...refused before anything is written" "No records found"
aexp "a change file that is not there" 1 --changes "$T/nope.txt" example.test
printf 'rr www.nozone.test. 60 A 192.0.2.1\n' > "$CH"
aexp "a zone that is not there" 1 --changes "$CH" nozone.test
errhas "...says so" "not in the database"
aexp "a name that is no zone name" 1 --changes "$CH" 'a b'
sqlite3 "$DB" "INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.99')"
printf 'rr www.slave.test. 60 A 192.0.2.1\n' > "$CH"
aexp "a SLAVE zone is not changed" 1 --changes "$CH" slave.test

echo "-- create"
printf 'rr made.test. 3600 SOA ns1.made.test. hostmaster.made.test. 7 7200 3600 1209600 300\nrr made.test. 3600 NS ns1.made.test.\nrr ns1.made.test. 3600 A 192.0.2.7\nrr www.made.test. 60 A 192.0.2.8\n' > "$CH"
aexp "--create --dry-run" 0 --create --dry-run --json --changes "$CH" made.test
jget "...a new zone" apply.created true
jget "...no generation yet" apply.generation 0
same "...nothing was written" "$(q "SELECT count(*) FROM domains WHERE name = 'made.test'")" 0
aexp "--create --type MASTER" 0 --create --type MASTER --principal 5 --change-set cs-c --changes "$CH" made.test
same "...the zone" "$(q "SELECT type FROM domains WHERE name = 'made.test'")$(serial made.test)" MASTER7
same "...version 1 is of kind create" "$(q "SELECT kind || '|' || principal_id || '|' || serial_after FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'made.test'")" "create|5|7"
aexp "--create of a zone that is there" 1 --create --changes "$CH" made.test
errhas "...says so" "exists already"
printf 'rr www.made2.test. 60 A 192.0.2.8\n' > "$CH"
aexp "--create with records and no SOA" 1 --create --changes "$CH" made2.test
errhas "...the checks of a whole zone" "SOA"
same "...the zone was not made" "$(q "SELECT count(*) FROM domains WHERE name = 'made2.test'")" 0
printf 'delete www.made.test. A\n' > "$CH"
aexp "--create with a delete line" 1 --create --changes "$CH" made3.test

echo "-- a zone text instead of a change file (--zone-file, --delete-others)"
newdb "$DB"
mkzone "$T/zt.zone" example.test. 10 'www IN A 192.0.2.2
mail IN MX 10 www
old IN TXT "old"'
kz import example.test "$T/zt.zone"
mkzone "$T/zt2.zone" example.test. 777 'www IN A 192.0.2.3
new IN TXT "new"'
aexp "--zone-file --dry-run (merge)" 0 --dry-run --json --zone-file "$T/zt2.zone" example.test
jvalid "--zone-file --dry-run"
same "...merge changes www and adds new" "$(perl -MJSON::PP -e 'my $d = decode_json(join "", <STDIN>); print join ",", map { "$_->{owner}$_->{type}$_->{change}" } @{$d->{apply}{diff}}' < "$OUT")" "new.example.test.TXTadd,www.example.test.Areplace"
jget "...the serial is raised, not the file's" apply.serial.after 11
same "...nothing was written" "$(q "SELECT count(*) FROM records WHERE name = 'new.example.test'")$(serial example.test)" 010
aexp "--zone-file (merge)" 0 --principal 7 --principal-name zed --change-set cs-z --version-kind import --comment "from a file" --zone-file "$T/zt2.zone" example.test
same "...www replaced, new added, mail and old stay, the SOA is the database's + 1" "$(q "SELECT group_concat(content, ',') FROM records WHERE name = 'www.example.test'")|$(q "SELECT count(*) FROM records WHERE type IN ('MX', 'TXT')")|$(serial example.test)" "192.0.2.3|3|11"
same "...the version row is of kind import and names who" "$(q "SELECT kind || '|' || principal_name || '|' || change_set || '|' || comment FROM karidns_zone_versions WHERE version = 2")" "import|zed|cs-z|from a file"
IN="$T/zt2.zone"; aexp "--zone-file - --delete-others (standard input)" 0 --delete-others --json --zone-file - example.test; IN=/dev/null
same "...what the text does not have is gone (mail, old); the apex SOA and NS stay" "$(q "SELECT group_concat(name || ' ' || type, ',') FROM (SELECT name, type FROM records ORDER BY name, type)")" "example.test NS,example.test SOA,new.example.test TXT,ns1.example.test A,www.example.test A"
mkzone "$T/zt3.zone" example.test. 1 'www IN A 192.0.2.3
new IN TXT "new"'
sed -i.bak 's/ 7200 3600 1209600 300/ 7200 3600 1209600 600/' "$T/zt3.zone"
aexp "--zone-file with an SOA of other values" 0 --json --zone-file "$T/zt3.zone" example.test
jget "...the SOA is written (the serial is the database's + 1)" apply.serial.after 13
printf '$ORIGIN example.test.\n$TTL 60\nx IN A 192.0.2.1\nx IN RRSIG A 8 3 60 20350101000000 20250101000000 1 example.test. AAAA\n' > "$T/zt-sig.zone"
aexp "a zone text with DNSSEC records is refused" 1 --zone-file "$T/zt-sig.zone" example.test
errhas "...and says so" "plain records only"
printf '$ORIGIN example.test.\n$TTL 60\n$INCLUDE /etc/passwd\n' > "$T/zt-inc.zone"
IN="$T/zt-inc.zone"; aexp "\$INCLUDE in a zone text is refused" 1 --zone-file - example.test; IN=/dev/null
grep -q root "$OUT" "$ERR" && bad "...a file was read" || ok "...nothing was read"
printf '$ORIGIN made.test.\n$TTL 3600\n@ IN SOA ns1 h 4 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.4\n' > "$T/made.zone"
aexp "--create --zone-file" 0 --create --type MASTER --principal 5 --zone-file "$T/made.zone" made.test
same "...the zone, its serial and its version 1 (kind create)" "$(q "SELECT type FROM domains WHERE name = 'made.test'")$(serial made.test)|$(q "SELECT kind FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'made.test'")" "MASTER4|create"
aexp "--create --zone-file of a zone that is there" 1 --create --zone-file "$T/made.zone" made.test

echo "-- the retention of the versions"
q "DROP TRIGGER karidns_zone_versions_prune; CREATE TRIGGER karidns_zone_versions_prune AFTER INSERT ON karidns_zone_versions BEGIN DELETE FROM karidns_zone_version_rrsets WHERE version_id IN (SELECT id FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 3); DELETE FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 3; END" >/dev/null
vex=$(q "SELECT count(*) FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'example.test'")
for n in 1 2 3 4 5 6; do printf 'rr t%s.made.test. 60 A 192.0.2.%s\n' $n $n > "$CH"; ka --changes "$CH" made.test; done
same "the newest 3 versions are kept" "$(q "SELECT group_concat(version) FROM (SELECT version FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'made.test' ORDER BY version)")" "5,6,7"
same "...their RRset rows are kept, the others went" "$(q "SELECT count(*) FROM karidns_zone_version_rrsets")" "$(q "SELECT count(*) FROM karidns_zone_version_rrsets s JOIN karidns_zone_versions v ON v.id = s.version_id")"
same "...the other zone keeps its versions" "$(q "SELECT count(*) FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'example.test'")" "$vex"
q "DELETE FROM domains WHERE name = 'made.test'"
same "a zone that is deleted takes its generation and its versions" "$(q "SELECT count(*) FROM karidns_zone_state WHERE domain_id NOT IN (SELECT id FROM domains)")$(q "SELECT count(*) FROM karidns_zone_versions WHERE domain_id NOT IN (SELECT id FROM domains)")" 00

echo "-- a busy database"
printf 'rr busy.example.test. 60 A 192.0.2.40\n' > "$CH"
( echo "BEGIN IMMEDIATE;"; sleep 9 ) | sqlite3 "$DB" > /dev/null 2>&1 &
holder=$!
sleep 1
ka --changes "$CH" example.test
same "the write lock is held by someone else: exit status 4" "$st" 4
errhas "...busy" "busy"
kill $holder 2>/dev/null; wait $holder 2>/dev/null
sleep 1
aexp "...and it works when the lock is free" 0 --changes "$CH" example.test

echo "-- --json of the other commands is unchanged"
kz import --json --serial keep example.test "$T/ex.zone"
jvalid "import --json"
jget "...no apply key" command import

# ---- the auth file
echo "-- the auth file (sessions, api_tokens, templates)"
AU=$T/auth.db
rm -f "$AU"
sqlite3 "$AU" < "$ROOT/db/karidns_auth.sqlite3.sql" > /dev/null && ok "db/karidns_auth.sqlite3.sql applies" || bad "the auth file does not apply"
sqlite3 "$AU" < "$ROOT/db/karidns_auth.sqlite3.sql" > /dev/null && ok "...and again"
aq() { sqlite3 -cmd "PRAGMA foreign_keys=ON" "$AU" "$1" 2>&1; }
aq "INSERT INTO principals (kind, name) VALUES ('user', 'alice'), ('group', 'ops')" >/dev/null
H32="x'$(printf '%064d' 1)'"
H32b="x'$(printf '%064d' 2)'"
aq "INSERT INTO karidns_auth_actor (id, principal_id, principal_name, change_set, db_role) VALUES (1, 1, 'alice', 'cs', 'api')" > /dev/null
aq "INSERT INTO sessions (id_hash, principal_id, csrf_hash, expires_at, client) VALUES ($H32, 1, $H32b, '2030-01-01T00:00:00Z', '192.0.2.1 test')" | grep -q . && bad "a session" || ok "a session is made"
aq "INSERT INTO sessions (id_hash, principal_id, csrf_hash, expires_at) VALUES (x'00', 1, $H32b, '2030-01-01T00:00:00Z')" | grep -q "CHECK" && ok "a session id of the wrong length is refused" || bad "a short session id"
aq "INSERT INTO sessions (id_hash, principal_id, csrf_hash, expires_at) VALUES ('textual', 1, $H32b, '2030-01-01T00:00:00Z')" | grep -q "CHECK" && ok "a session id that is text is refused" || bad "a text session id"
aq "INSERT INTO sessions (id_hash, principal_id, csrf_hash, expires_at) VALUES ($H32b, 99, $H32b, '2030-01-01T00:00:00Z')" | grep -q "FOREIGN KEY" && ok "a session of no principal is refused" || bad "a session of no principal"
aq "UPDATE sessions SET last_seen = '2029-01-01T00:00:00Z'" >/dev/null
same "an UPDATE of last_seen alone is not audited" "$(aq "SELECT count(*) FROM karidns_auth_audit WHERE table_name = 'sessions'")" 1
aq "UPDATE sessions SET totp_ok = 1" >/dev/null
same "...another change is" "$(aq "SELECT count(*) FROM karidns_auth_audit WHERE table_name = 'sessions'")" 2
same "...the hashes are written as <redacted>" "$(aq "SELECT count(*) FROM karidns_auth_audit WHERE table_name = 'sessions' AND after LIKE '%\"id_hash\":\"<redacted>\"%' AND after LIKE '%\"csrf_hash\":\"<redacted>\"%'")" 2
aq "INSERT INTO api_tokens (principal_id, name, secret_hash, expires_at) VALUES (1, 'ci', $H32, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+30 days'))" | grep -q . && bad "an api token" || ok "an api token is made"
aq "INSERT INTO api_tokens (principal_id, name, secret_hash, expires_at) VALUES (1, 'long', $H32, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+400 days'))" | grep -q "CHECK" && ok "a token that lives more than a year is refused" || bad "a long token"
same "...the secret hash is redacted in the audit" "$(aq "SELECT count(*) FROM karidns_auth_audit WHERE table_name = 'api_tokens' AND after LIKE '%\"secret_hash\":\"<redacted>\"%'")" 1
aq "INSERT INTO templates (name, soa_mname, soa_rname, soa_minimum) VALUES ('web', 'ns1', 'hostmaster', 300)" >/dev/null
same "a template starts at revision 1" "$(aq "SELECT revision FROM templates WHERE name = 'web'")" 1
aq "INSERT INTO template_records (template_id, ordinal, owner, type, ttl, content) VALUES (1, 0, '@', 'MX', 3600, '10 mail')" >/dev/null
aq "INSERT INTO template_records (template_id, ordinal, owner, type, ttl, content) VALUES (1, 1, 'www', 'A', NULL, '192.0.2.1')" >/dev/null
same "...every change of a record grows the revision" "$(aq "SELECT revision FROM templates WHERE name = 'web'")" 3
aq "UPDATE templates SET description = 'x' WHERE name = 'web'" >/dev/null
same "...and of the template" "$(aq "SELECT revision FROM templates WHERE name = 'web'")" 4
aq "DELETE FROM template_records WHERE ordinal = 1" >/dev/null
same "...and a delete" "$(aq "SELECT revision FROM templates WHERE name = 'web'")" 5
for bad_rec in "'WWW', 'A', 1, 'x'" "'www.', 'A', 1, 'x'" "'a..b', 'A', 1, 'x'" "'www', 'a', 1, 'x'" "'www', 'RRSIG', 1, 'x'" "'www', 'TYPE0046', 1, 'x'" "'www', 'A', -1, 'x'" "'www', 'A', 1, ''" "'w w', 'A', 1, 'x'"; do
    aq "INSERT INTO template_records (template_id, ordinal, owner, type, ttl, content) VALUES (1, 9, $bad_rec)" | grep -q "CHECK" && ok "template record refused: $bad_rec" || bad "template record accepted: $bad_rec"
done
aq "INSERT INTO template_records (template_id, ordinal, owner, type, ttl, content) VALUES (1, 9, 'a.b', 'A', 1, 'x')" | grep -q . && bad "a good template record" || ok "a good template record (a.b)"
same "the audit has the templates and their records" "$(aq "SELECT count(DISTINCT table_name) FROM karidns_auth_audit WHERE table_name IN ('templates', 'template_records')")" 2
aq "DELETE FROM principals WHERE name = 'alice'" >/dev/null
same "a deleted principal takes its sessions and tokens" "$(aq "SELECT count(*) FROM sessions") $(aq "SELECT count(*) FROM api_tokens")" "0 0"
aq "DELETE FROM templates" >/dev/null
same "a deleted template takes its records" "$(aq "SELECT count(*) FROM template_records")" 0
fi

# ================================================================ 2. PostgreSQL
echo "== PostgreSQL"
if ! "$ZONE" --version | grep -q postgresql; then echo "  SKIP: $ZONE has no PostgreSQL driver"; else
pg_setup zoneapply || { echo "  (PostgreSQL part skipped)"; echo; echo "=== run_karidns_zone_apply_test: $FAILS failed, $PASS passed ==="; [ "$FAILS" = 0 ]; exit; }
PORT=$(pq "SHOW port")
PW="pw$$x$(date +%s)"
RA=kz_api_$$; RK=kz_chk_$$; RW=kz_wr_$$; ROLES="$RA $RK $RW"
if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $RA LOGIN PASSWORD '$PW'" -c "CREATE ROLE $RK LOGIN PASSWORD '$PW'" -c "CREATE ROLE $RW LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
    echo "  SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"
else
rc_of() { echo "host=127.0.0.1 port=$PORT user=$1 password=$PW"; }
if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA) dbname=$PGDB" -c "SELECT 1" > /dev/null 2>&1; then
    echo "  SKIP: the server does not accept a password login over 127.0.0.1:$PORT (pg_hba.conf)"
else
Z=$T/karidns-zone
cp "$ZONE" "$Z" && chmod 755 "$Z"
W=$T/w; mkdir "$W"; chmod 755 "$W"; [ -n "$PG_AS" ] && chown "$PG_AS" "$W"
for r in $RA $RK $RW; do printf '%s dbname=%s\n' "$(rc_of $r)" "$PGDB" > "$W/ci_$r"; [ -n "$PG_AS" ] && chown "$PG_AS" "$W/ci_$r"; chmod 600 "$W/ci_$r"; done
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
rolescript() { psql -X -q -At -v ON_ERROR_STOP=1 -v role="$2" -v schema=public -f "$1" "$PGC" > "$T/role.out" 2>&1 && ok "$3" || bad "$3" "$(head -5 "$T/role.out")"; }
rolescript db/karidns_writer_role.pgsql.sql $RW "the writer role script"
rolescript db/karidns_api_role.pgsql.sql $RA "the API role script (row level security on)"
rolescript db/karidns_check_role.pgsql.sql $RK "the check role script"
rolescript db/karidns_check_role.pgsql.sql $RK "...and again"
psql -X -q -At -v ON_ERROR_STOP=1 -v role=$RA -v schema=public -f db/karidns_check_role.pgsql.sql "$PGC" > "$T/role3.out" 2>&1 && bad "the API role cannot be the check role" || ok "the check role script refuses an API role"
grep -q "API role" "$T/role3.out" && ok "...and says why" || bad "...the reason" "$(head -3 "$T/role3.out")"
SUPER=$(pq "SELECT current_user")
psql -X -q -At -v ON_ERROR_STOP=1 -v role="$SUPER" -v schema=public -f db/karidns_check_role.pgsql.sql "$PGC" > "$T/role4.out" 2>&1 && bad "a superuser or the owner cannot be the check role" || ok "the check role script refuses the owner / a superuser"
pq "SELECT count(*) FROM pg_trigger WHERE tgname = 'karidns_never_commit'" > "$T/nc.out"
[ "$(cat "$T/nc.out")" -ge 10 ] && ok "the never-commit triggers are on the tables the dry run writes ($(cat "$T/nc.out"))" || bad "never-commit triggers: $(cat "$T/nc.out")"

# principals: a global master, a domain master (policy web), a subdomain master (policy web)
pq "INSERT INTO karidns_auth.rr_policies (name, allowed_types, allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max) VALUES
      ('all', ARRAY['A','AAAA','CNAME','MX','TXT','NS','SOA','SRV','PTR'], true, true, true, true, 0, 2147483647),
      ('web', ARRAY['A','AAAA','CNAME','TXT'], false, false, false, false, 60, 86400);
    INSERT INTO karidns_auth.principals (kind, name) VALUES ('user', 'root1'), ('user', 'bob'), ('user', 'carol');
    INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id) VALUES
      (1, 'global_master', NULL, NULL, NULL, 1), (2, 'domain_master', 'public', 'example.test', NULL, 2), (3, 'subdomain_master', 'public', 'example.test', 'sub.example.test', 2)" > /dev/null
cat > "$W/ex.zone" <<'EOF'
$ORIGIN example.test.
$TTL 300
@ IN SOA ns1 hostmaster 10 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
sub IN A 192.0.2.3
a.sub IN A 192.0.2.4
evilsub IN A 192.0.2.5
EOF
chmod 644 "$W/ex.zone"
zrun() { r=$1; shift; as_pg "$Z" "$@" --no-config --conninfo-file "$W/ci_$r" > "$OUT" 2> "$ERR" < /dev/null; st=$?; }
zexp() { desc=$1; want=$2; r=$3; shift 3; zrun $r "$@"; if [ "$st" = "$want" ]; then ok "$desc"; else bad "$desc: exit status $st, wanted $want" "$(cat "$ERR"; head -c 600 "$OUT")"; fi; }
vcount() { pq "SELECT count(*) FROM karidns_zone_versions"; }
spf() { pq "SELECT split_part(content, ' ', 3) FROM records WHERE type = 'SOA' AND name = 'example.test'"; }
zexp "the operator imports the zone (writer role)" 0 $RW import example.test "$W/ex.zone"
same "...version 1 (kind import, the role of the session)" "$(pq "SELECT kind || ' ' || db_role FROM karidns_zone_versions WHERE version = 1")" "import $RW"
G=$(pq "SELECT generation FROM karidns_zone_state")
[ "$G" -ge 1 ] && ok "the zone has a generation ($G; one bump per transaction)" || bad "no generation"
printf 'rr www.example.test. 300 A 192.0.2.10\nrr x.example.test. 300 TXT "from the check run"\ndelete sub.example.test. A\n' > "$W/c1.txt"; chmod 644 "$W/c1.txt"
echo "-- the check role"
zexp "the check run (dry run, trusted)" 0 $RK apply --dry-run --json --principal 2 --principal-name bob --change-set cs-chk --changes "$W/c1.txt" example.test
jvalid "...its document"
jget "...the generation" apply.generation "$G"
jget "...the serial it would write" apply.serial.after 11
jget "...version 2" apply.version 2
same "...nothing was written: records, versions, audit" "$(pq "SELECT count(*) FROM records") $(vcount) $(spf)" "7 1 10"
same "...no audit row" "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE change_set = 'cs-chk'")" 0
zexp "the check run without a principal (no bump_serial: direct)" 0 $RK apply --dry-run --changes "$W/c1.txt" example.test
zexp "the check role cannot import for real" 1 $RK import --serial increment example.test "$W/ex.zone"
errhas "...the check role never commits" "never commits"
same "...nothing was written" "$(pq "SELECT count(*) FROM records") $(vcount) $(spf)" "7 1 10"
zexp "the check role cannot apply for real either" 1 $RK apply --principal 2 --changes "$W/c1.txt" example.test
errhas "...the same" "never commits"
CK="$(rc_of $RK) dbname=$PGDB"
ck() { PGCONNECT_TIMEOUT=5 psql -X -q -At -v ON_ERROR_STOP=1 "$CK" -c "$1" > "$T/ck.out" 2>&1; }
DID=$(pq "SELECT id FROM domains WHERE name = 'example.test'")
for stmt in "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($DID, 'k.example.test', 'A', '192.0.2.99', 60)" \
            "UPDATE records SET ttl = 61 WHERE name = 'www.example.test'" \
            "DELETE FROM records WHERE name = 'www.example.test'" \
            "INSERT INTO domains (name, type) VALUES ('k.test', 'NATIVE')" \
            "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($DID, 'X-K', '1')" \
            "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES ($DID, 'k')" \
            "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES ($DID, 'ecs', 'k', '192.0.2.0/24')" \
            "INSERT INTO karidns_reload_requests (zone) VALUES ('example.test')" \
            "INSERT INTO karidns_zone_versions (domain_id, version, kind, generation_before, generation_after) VALUES ($DID, 77, 'edit', 0, 0)" ; do
    ck "BEGIN; $stmt; COMMIT"
    if grep -q "never commits" "$T/ck.out"; then ok "a transaction of the check role that wrote cannot commit: $(echo "$stmt" | cut -c1-48)"; else bad "committed or other error: $stmt" "$(cat "$T/ck.out")"; fi
done
ck "SET ROLE $RW; BEGIN; INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($DID, 'X-K', '2'); COMMIT"
grep -q "never commits\|permission denied\|cannot set role" "$T/ck.out" && ok "SET ROLE does not get around it" || bad "SET ROLE" "$(cat "$T/ck.out")"
ck "BEGIN; SET CONSTRAINTS ALL IMMEDIATE; INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($DID, 'X-K', '3'); COMMIT"
grep -q "never commits" "$T/ck.out" && ok "SET CONSTRAINTS ALL IMMEDIATE does not either" || bad "SET CONSTRAINTS" "$(cat "$T/ck.out")"
ck "ALTER TABLE records DISABLE TRIGGER ALL"
grep -q "must be owner" "$T/ck.out" && ok "the check role cannot switch the triggers off" || bad "DISABLE TRIGGER" "$(cat "$T/ck.out")"
ck "BEGIN; SELECT count(*) FROM records; COMMIT"
[ "$(sed -n 1p "$T/ck.out")" = "7" ] && ok "a read-only transaction of the check role commits (it sees every row)" || bad "read" "$(cat "$T/ck.out")"
same "...none of it persisted" "$(pq "SELECT count(*) FROM records") $(pq "SELECT count(*) FROM domainmetadata WHERE kind LIKE 'X-K'") $(pq "SELECT count(*) FROM domains") $(vcount) $(spf)" "7 0 1 1 10"
same "...the superuser's own transactions are not blocked" "$(pq "BEGIN; INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($DID, 'X-OWNER', '1'); COMMIT; SELECT count(*) FROM domainmetadata WHERE kind = 'X-OWNER'" | tail -1)" 1
pq "DELETE FROM domainmetadata WHERE kind = 'X-OWNER'" > /dev/null

echo "-- the commit run as the API role (row level security)"
G=$(pq "SELECT generation FROM karidns_zone_state")
zexp "bob (domain master, policy web) changes what his grant covers" 0 $RA apply --readback changed --expect-generation "$G" --principal 2 --principal-name bob --change-set cs-bob --comment "bob's change" --changes "$W/c1.txt" example.test
same "...the records" "$(pq "SELECT count(*) FROM records WHERE name = 'www.example.test' AND content = '192.0.2.10'")$(pq "SELECT count(*) FROM records WHERE name = 'x.example.test'")$(pq "SELECT count(*) FROM records WHERE name = 'sub.example.test'")" "110"
same "...the serial was raised by karidns_auth.bump_serial (the API role may not write an SOA)" "$(spf)" 11
same "...the version row (RLS: the principal itself)" "$(pq "SELECT kind || '|' || principal_id || '|' || principal_name || '|' || change_set || '|' || serial_before || '|' || serial_after || '|' || db_role FROM karidns_zone_versions WHERE version = 2")" "edit|2|bob|cs-bob|10|11|$RA"
same "...the audit log names the principal and the change set" "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE principal_name = 'bob' AND change_set = 'cs-bob' AND table_name = 'records'")" 5
same "...(www replaced, x added, sub deleted: 2 + 1 + 1 rows, and the SOA)" "$(pq "SELECT string_agg(op, '' ORDER BY id) FROM karidns_auth.audit_log WHERE change_set = 'cs-bob' AND table_name = 'records'")" "DDIIU"
printf 'rr example.test. 3600 SOA ns1.example.test. hostmaster.example.test. 999 7200 3600 1209600 300\n' > "$W/c2.txt"; chmod 644 "$W/c2.txt"
zexp "bob cannot write the SOA: row level security refuses, the transaction is rolled back" 1 $RA apply --readback changed --principal 2 --changes "$W/c2.txt" example.test
errhas "...by the policy" "row-level security"
same "...nothing changed" "$(spf) $(vcount)" "11 2"
printf 'rr www.example.test. 300 MX 10 mail.example.test.\n' > "$W/c3.txt"; chmod 644 "$W/c3.txt"
zexp "bob cannot write a type his policy does not list" 1 $RA apply --readback changed --principal 2 --changes "$W/c3.txt" example.test
printf 'rr y.example.test. 5 A 192.0.2.50\n' > "$W/c4.txt"; chmod 644 "$W/c4.txt"
zexp "bob cannot write a TTL outside his policy" 1 $RA apply --readback changed --principal 2 --changes "$W/c4.txt" example.test
zexp "no principal: the API role sees nothing" 1 $RA apply --readback changed --changes "$W/c1.txt" example.test
errhas "...the zone is not there for it" "not in the database"
printf 'rr b.sub.example.test. 300 A 192.0.2.60\n' > "$W/c5.txt"; chmod 644 "$W/c5.txt"
zexp "carol changes a name below her suffix" 0 $RA apply --readback changed --principal 3 --principal-name carol --change-set cs-carol --changes "$W/c5.txt" example.test
same "...it is there" "$(pq "SELECT count(*) FROM records WHERE name = 'b.sub.example.test'")" 1
printf 'rr evilsub.example.test. 300 A 192.0.2.61\n' > "$W/c6.txt"; chmod 644 "$W/c6.txt"
zexp "carol cannot change evilsub.example.test (label boundary)" 1 $RA apply --readback changed --principal 3 --changes "$W/c6.txt" example.test
errhas "...row level security" "row-level security"
printf 'rr other.example.test. 300 A 192.0.2.62\n' > "$W/c7.txt"; chmod 644 "$W/c7.txt"
zexp "carol cannot change a name outside her suffix" 1 $RA apply --readback changed --principal 3 --changes "$W/c7.txt" example.test
same "...nothing of it persisted" "$(pq "SELECT count(*) FROM records WHERE name IN ('evilsub.example.test', 'other.example.test') AND type = 'A' AND content LIKE '192.0.2.6%'")" 0
zexp "root1 (global master) writes the SOA through apply" 0 $RA apply --readback changed --principal 1 --principal-name root1 --serial keep --changes "$W/c2.txt" example.test
same "...serial 999 (--serial keep takes the file's)" "$(spf)" 999
AQ="$(rc_of $RA) dbname=$PGDB"
aq() { PGCONNECT_TIMEOUT=5 psql -X -q -At -v ON_ERROR_STOP=1 "$AQ" -c "BEGIN; SET LOCAL karidns.principal = '$1'; $2; COMMIT" 2>&1 | grep -v '^BEGIN$\|^COMMIT$\|^SET$'; }
same "the versions as bob sees them (a grant on the zone)" "$(aq 2 "SELECT count(*) FROM karidns_zone_versions")" "$(vcount)"
same "...as carol: the versions of the zone, the RRsets of her names only" "$(aq 3 "SELECT count(*) FROM karidns_zone_version_rrsets")" "$(pq "SELECT count(*) FROM karidns_zone_version_rrsets WHERE owner = 'sub.example.test' OR owner LIKE '%.sub.example.test' OR (owner = 'example.test' AND type IN ('SOA', 'NS'))")"
same "...nobody sees anything without a principal" "$(aq 99 "SELECT count(*) FROM karidns_zone_versions")" 0
aq 2 "UPDATE karidns_zone_versions SET comment = 'x'" | grep -q "permission denied" && ok "the API role cannot update a version" || bad "UPDATE karidns_zone_versions"
aq 2 "DELETE FROM karidns_zone_versions" | grep -q "permission denied" && ok "...or delete one" || bad "DELETE karidns_zone_versions"
aq 3 "INSERT INTO karidns_zone_versions (domain_id, version, kind, principal_id, generation_before, generation_after) VALUES ($DID, 500, 'edit', 2, 0, 0)" | grep -q "row-level security" && ok "...or write a version of another principal" || bad "a version of another principal"
same "the generation: bob sees the zone's, an outsider does not" "$(aq 2 "SELECT count(*) FROM karidns_zone_state")$(aq 99 "SELECT count(*) FROM karidns_zone_state")" 10
same "karidns_server_status is readable for the API role" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT count(*) FROM karidns_server_status")" 0
PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT content FROM cryptokeys" 2>&1 | grep -q "permission denied" && ok "...and the API role still cannot read cryptokeys.content" || bad "cryptokeys.content"

echo "-- sessions, tokens, templates (row level security, the lookups)"
H1="decode('$(printf '%064d' 1)', 'hex')"; H2="decode('$(printf '%064d' 2)', 'hex')"; H3="decode('$(printf '%064d' 3)', 'hex')"
aq 2 "INSERT INTO karidns_auth.sessions (id_hash, principal_id, csrf_hash, expires_at) VALUES ($H1, 2, $H2, now() + interval '1 hour')" | grep -q . && bad "bob's session" || ok "bob makes his own session"
aq 2 "INSERT INTO karidns_auth.sessions (id_hash, principal_id, csrf_hash, expires_at) VALUES ($H3, 3, $H2, now() + interval '1 hour')" | grep -q "row-level security" && ok "...but not carol's" || bad "carol's session by bob"
same "bob sees his session, carol none of it, root1 all" "$(aq 2 "SELECT count(*) FROM karidns_auth.sessions")$(aq 3 "SELECT count(*) FROM karidns_auth.sessions")$(aq 1 "SELECT count(*) FROM karidns_auth.sessions")" 101
same "session_lookup finds the session by the hash of its cookie, with no principal set" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT principal_id FROM karidns_auth.session_lookup($H1)")" 2
same "...nothing for another hash, an expired session or a disabled principal" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT count(*) FROM karidns_auth.session_lookup($H3)")" 0
pq "UPDATE karidns_auth.principals SET disabled = true WHERE id = 2" > /dev/null
same "...a disabled principal's session is not found" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT count(*) FROM karidns_auth.session_lookup($H1)")" 0
pq "UPDATE karidns_auth.principals SET disabled = false WHERE id = 2" > /dev/null
aq 2 "UPDATE karidns_auth.sessions SET last_seen = now()" > /dev/null
same "the audit has the session without the hashes, and not a change of last_seen alone" "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'sessions'")$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'sessions' AND after::text LIKE '%<redacted>%'")" 11
pq "INSERT INTO karidns_auth.sessions (id_hash, principal_id, csrf_hash, expires_at) VALUES (decode('$(printf '%064d' 7)', 'hex'), 3, $H2, now() - interval '1 hour'), (decode('$(printf '%064d' 8)', 'hex'), 2, $H2, now() - interval '1 minute')" > /dev/null
same "sweep_expired: a principal deletes the expired sessions of every principal (the policy shows it its own)" "$(aq 2 "SELECT karidns_auth.sweep_expired()")|$(pq "SELECT count(*) FROM karidns_auth.sessions WHERE expires_at <= now()")|$(pq "SELECT count(*) FROM karidns_auth.sessions")" "2|0|1"
PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT karidns_auth.sweep_expired()" > /dev/null 2>&1 && ok "...the function needs no principal" || bad "sweep_expired without a principal"
aq 1 "INSERT INTO karidns_auth.api_tokens (principal_id, name, secret_hash, expires_at) VALUES (3, 'svc', $H3, now() + interval '30 days')" | grep -q . && bad "a service token" || ok "a global master makes a token for another principal"
aq 2 "INSERT INTO karidns_auth.api_tokens (principal_id, name, secret_hash, expires_at) VALUES (3, 'steal', $H3, now() + interval '30 days')" | grep -q "row-level security" && ok "...bob cannot" || bad "a token for another principal"
aq 2 "INSERT INTO karidns_auth.api_tokens (principal_id, name, secret_hash, expires_at) VALUES (2, 'forever', $H3, now() + interval '400 days')" | grep -q "api_tokens_max_life" && ok "a token cannot live more than a year" || bad "a long token"
TID=$(pq "SELECT id FROM karidns_auth.api_tokens WHERE name = 'svc'")
same "api_token_lookup" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT principal_id::text || read_only::text FROM karidns_auth.api_token_lookup($TID, $H3)")" "3false"
pq "UPDATE karidns_auth.api_tokens SET revoked_at = now()" > /dev/null
same "...a revoked token is not found" "$(PGCONNECT_TIMEOUT=5 psql -X -q -At "$AQ" -c "SELECT count(*) FROM karidns_auth.api_token_lookup($TID, $H3)")" 0
same "the audit of the tokens has no secret hash" "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'api_tokens' AND after::text LIKE '%<redacted>%'")" "$(pq "SELECT count(*) FROM karidns_auth.audit_log WHERE table_name = 'api_tokens'")"
aq 1 "INSERT INTO karidns_auth.templates (name, soa_mname) VALUES ('web', 'ns1')" | grep -q . && bad "a template by a global master" || ok "a global master makes a template"
aq 2 "INSERT INTO karidns_auth.templates (name) VALUES ('mine')" | grep -q "row-level security" && ok "...a domain master cannot" || bad "a template by bob"
same "every principal reads the templates" "$(aq 3 "SELECT count(*) FROM karidns_auth.templates")" 1
aq 1 "INSERT INTO karidns_auth.template_records (template_id, ordinal, owner, type, ttl, content) VALUES ((SELECT id FROM karidns_auth.templates), 0, '@', 'MX', 3600, '10 mail')" | grep -q . && bad "a template record" || ok "a template record"
aq 1 "UPDATE karidns_auth.template_records SET ttl = 60" > /dev/null
same "the revision grows with every change (insert, update)" "$(pq "SELECT revision FROM karidns_auth.templates")" 3
aq 1 "INSERT INTO karidns_auth.template_records (template_id, ordinal, owner, type, content) VALUES (1, 1, 'WWW', 'A', 'x')" | grep -q "violates check" && ok "a template record owner in upper case is refused" || bad "an upper case owner"
aq 1 "INSERT INTO karidns_auth.template_records (template_id, ordinal, owner, type, content) VALUES (1, 1, 'www', 'RRSIG', 'x')" | grep -q "violates check" && ok "...a DNSSEC type" || bad "a DNSSEC type"
same "the audit has the templates and their records" "$(pq "SELECT count(DISTINCT table_name) FROM karidns_auth.audit_log WHERE table_name IN ('templates', 'template_records')")" 2

echo "-- the generation: a writer between the check run and the commit run (exit status 3)"
pq "CREATE FUNCTION slow_k() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END \$\$;
    CREATE TRIGGER slow_k BEFORE INSERT ON records FOR EACH ROW WHEN (NEW.name = 'slow.example.test') EXECUTE FUNCTION slow_k()" > /dev/null
printf 'rr slow.example.test. 60 A 192.0.2.70\n' > "$W/c8.txt"; chmod 644 "$W/c8.txt"
G=$(pq "SELECT generation FROM karidns_zone_state")
( zrun $RW apply --principal 1 --changes "$W/c8.txt" example.test; echo $st > "$T/bg.st"; cp "$ERR" "$T/bg.err" ) &
bgp=$!
sleep 1
pq "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($DID, 'X-RACE', '1')" > /dev/null
wait $bgp
same "a row written by someone else after the snapshot: exit status 3" "$(cat "$T/bg.st")" 3
grep -q "changed while" "$T/bg.err" && ok "...says so" || bad "...the message" "$(cat "$T/bg.err")"
same "...nothing of the change persisted" "$(pq "SELECT count(*) FROM records WHERE name = 'slow.example.test'")" 0
pq "DROP TRIGGER slow_k ON records; DROP FUNCTION slow_k(); DELETE FROM domainmetadata WHERE kind = 'X-RACE'" > /dev/null
zexp "--expect-generation with the old value after that" 3 $RW apply --expect-generation "$G" --principal 1 --changes "$W/c8.txt" example.test
echo "-- the zone lock (exit status 4)"
( pq "BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('karidns-zone:example.test', 0)); SELECT pg_sleep(14); COMMIT" > /dev/null 2>&1 ) &
lk=$!
sleep 1
zexp "the zone is locked by another importer" 4 $RW apply --principal 1 --changes "$W/c8.txt" example.test
wait $lk
echo "-- the retention of the versions"
pq "CREATE OR REPLACE FUNCTION karidns_zone_versions_prune_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS \$\$ BEGIN DELETE FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 3; RETURN NULL; END \$\$" > /dev/null
for n in 1 2 3 4 5; do printf 'rr r%s.example.test. 60 A 192.0.2.8%s\n' $n $n > "$W/c9.txt"; chmod 644 "$W/c9.txt"; zrun $RA apply --readback changed --principal 2 --change-set "cs-r$n" --changes "$W/c9.txt" example.test; done
same "the newest 3 versions of the zone are kept" "$(pq "SELECT count(*) FROM karidns_zone_versions")" 3
same "...their RRset rows are kept, the others went" "$(pq "SELECT count(*) FROM karidns_zone_version_rrsets")" "$(pq "SELECT count(*) FROM karidns_zone_version_rrsets s JOIN karidns_zone_versions v ON v.id = s.version_id")"
same "the zone is deleted: the generation and the versions go" "$(pq "DELETE FROM domains WHERE name = 'example.test'; SELECT count(*) FROM karidns_zone_state") $(vcount) $(pq "SELECT count(*) FROM karidns_zone_version_rrsets")" "0 0 0"
fi
fi
fi

echo
if [ "$FAILS" = 0 ]; then echo "=== run_karidns_zone_apply_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_karidns_zone_apply_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
