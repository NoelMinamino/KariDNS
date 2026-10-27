#!/bin/sh
# run_db_file_diff_test.sh - GATE of milestone B4b: the same unsigned zone answers the same from a zone file and from a
# SQLite3 database (beta design 8.4, 9: "file vs DB = 0").
#
# For every zone file of tests/zones/ that tests/db/zone2sql takes (the zone parser accepts it, one zone, no DNSSEC
# records, no extended attributes) two servers are started on the same data: A loads the file (type primary, file), B
# gets the zone from a SQLite3 database through karidns-dbloader.  Files that define the same zone name (example.com has
# many variants) go into separate rounds.  Zones with location / ECS tags (B8) go through the karidns_* tables and are compared as the client 127.0.0.1 (the per-client comparison is run_db_tags_test.sh).  For each zone, every owner x every type present, ANY, the types NS MX TXT AAAA
# A CNAME at every owner, a name below every owner, the apex types, NXDOMAIN names and a differently-cased name are
# asked in three flavours (plain query = 512 byte limit, EDNS0 DO=0, EDNS0 DO=1) with tests/db/dbquery.c, which writes
# the exact response bytes with the message ID zeroed.  The responses of A and B must be identical.  Since B7b the zones are also transferred: A allows 127.0.0.1 in the zone
# statement, B in domainmetadata (ALLOW-AXFR-FROM, bounded by acl-ceiling); the AXFR of A and B must hold the same RRs.  A third
# server C has neither a zone file nor a database but is a secondary (type slave) of B: it must answer the same list of
# queries as B byte for byte, and its AXFR is the same set of RRs too (database primary -> file-free KariDNS secondary).
#
# Owner case: PowerDNS stores owners in lower case and zone2sql does the same, so a zone file with upper-case letters in
# an owner could differ from the database version in the case of that owner name (RFC 4343: the same name).  The
# comparison is strict first; where the strict one fails the responses are compared again with the owner names (and the
# question name) folded to lower case, and such a zone is listed as "differs only in owner case" (it passes).  Anything
# else is a failure.  Observed with this tree: none of the zones needs the second step (the zone parser itself reads
# owners in lower case; the synthetic zone mixed.test with WWW and Mail.Sub is identical byte for byte).  A zone that one of the servers does not load (a zone the server's loader rejects, tags that need B8) is
# skipped and listed with the reason; the test fails if fewer than 8 zones could be compared.
#
# Needs root (the loader must be root-owned and runs as nobody).  SKIP otherwise, and when a binary, the sqlite3 CLI or
# a C compiler is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
. "$ROOT/tests/lib_proc.sh"

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler for tests/db/dbquery.c"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbdiff.XXXXXX") || exit 1
chmod 755 "$T"
SA=""; SB=""; SC=""
stop_servers() {
    [ -n "$SA" ] && kill -TERM "$SA" 2>/dev/null
    [ -n "$SB" ] && kill -TERM "$SB" 2>/dev/null
    [ -n "$SC" ] && kill -TERM "$SC" 2>/dev/null
    i=0
    while [ $i -lt 50 ]; do
        { [ -z "$SA" ] || ! kill -0 "$SA" 2>/dev/null; } && { [ -z "$SB" ] || ! kill -0 "$SB" 2>/dev/null; } &&
            { [ -z "$SC" ] || ! kill -0 "$SC" 2>/dev/null; } && break
        sleep 0.1; i=$((i + 1))
    done
    [ -n "$SA" ] && kill -KILL "$SA" 2>/dev/null
    [ -n "$SB" ] && kill -KILL "$SB" 2>/dev/null
    [ -n "$SC" ] && kill -KILL "$SC" 2>/dev/null
    SA=""; SB=""; SC=""
}
cleanup() { stop_servers; rm -rf "$T"; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
TAB=$(printf '	')
BASE=$(kari_port 0 $((20000 + $$ % 20000)))
PA=$BASE
PB=$((BASE + 1))
PC=$((BASE + 2))
SCHEMA=tests/db/pdns_schema.sqlite3.sql

cc -O1 -o "$T/dbquery" tests/db/dbquery.c 2> "$T/cc.log" || { echo "SKIP: tests/db/dbquery.c does not compile"; cat "$T/cc.log"; exit 0; }
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }

wait_log() {   # wait_log LOG PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -Eq -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

# ---------------------------------------------------------------- which zone files can be compared
echo "== candidate zone files"
mkdir "$T/sql" "$T/cand"
: > "$T/cand.list"      # apex <TAB> file <TAB> sql
: > "$T/skipped.txt"
N=0
# one zone of our own with upper-case owners: it exercises the owner-case rule below
cat > "$T/cand/mixed.test.zone" <<'EOF2'
$ORIGIN mixed.test.
$TTL 300
@ SOA ns1 host 1 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
WWW A 192.0.2.2
Mail.Sub A 192.0.2.3
@ MX 10 Mail.Sub
EOF2
for f in tests/zones/*.zone tests/db/tagz.test.zone "$T/cand/mixed.test.zone"; do
    [ -f "$f" ] || continue
    N=$((N + 1))
    sz=$(wc -c < "$f" | tr -d ' ')
    if [ "$sz" -gt 300000 ]; then echo "$f: larger than 300 kB" >> "$T/skipped.txt"; continue; fi
    if ! ./tests/db/zone2sql --dialect sqlite3 "$f" > "$T/sql/$N.sql" 2> "$T/z2s.err"; then
        echo "$f: zone2sql cannot take it ($(head -1 "$T/z2s.err" | cut -c1-90))" >> "$T/skipped.txt"; continue
    fi
    rm -f "$T/scratch.db"
    sqlite3 "$T/scratch.db" < "$SCHEMA" > /dev/null
    sqlite3 "$T/scratch.db" < db/karidns_ext.sqlite3.sql > /dev/null          # B8: tags and tinydns attributes of a zone file go into the karidns_* tables
    sqlite3 "$T/scratch.db" < "$T/sql/$N.sql" > /dev/null 2>&1 || { echo "$f: the SQL does not import" >> "$T/skipped.txt"; continue; }
    ND=$(sqlite3 "$T/scratch.db" "SELECT count(*) FROM domains")
    APEX=$(sqlite3 "$T/scratch.db" "SELECT name FROM domains LIMIT 1")
    SIGNED=$(sqlite3 "$T/scratch.db" "SELECT count(*) FROM records WHERE type IN ('RRSIG','NSEC','NSEC3','NSEC3PARAM')")
    META=$(sqlite3 "$T/scratch.db" "SELECT count(*) FROM domainmetadata WHERE kind = 'PRESIGNED'")
    if [ "$ND" != "1" ] || [ -z "$APEX" ]; then echo "$f: $ND domains in the import" >> "$T/skipped.txt"; continue; fi
    if [ "$SIGNED" != "0" ] || [ "$META" != "0" ]; then echo "$f: a signed zone (DNSSEC records; B5)" >> "$T/skipped.txt"; continue; fi
    printf '%s\t%s\t%s\n' "$APEX" "$f" "$T/sql/$N.sql" >> "$T/cand.list"
done
NC=$(wc -l < "$T/cand.list" | tr -d ' ')
echo "  $NC of $N zone files are candidates"

# rounds: a zone name once per round
: > "$T/rounds.txt"
R=0
while read -r apex f sqlf; do
    k=1
    while [ $k -le $R ] && grep -qx "$apex" "$T/round.$k.apex" 2>/dev/null; do k=$((k + 1)); done
    if [ $k -gt $R ]; then R=$k; : > "$T/round.$k.apex"; : > "$T/round.$k.list"; fi
    echo "$apex" >> "$T/round.$k.apex"
    printf '%s\t%s\t%s\n' "$apex" "$f" "$sqlf" >> "$T/round.$k.list"
done < "$T/cand.list"
echo "  $R round(s)"

gen_queries() {   # gen_queries DB APEX: the query list on stdout
    db=$1; apex=$2
    id=$(sqlite3 "$db" "SELECT id FROM domains WHERE name = '$apex'")
    sqlite3 -separator ' ' "$db" "SELECT DISTINCT name, type FROM records WHERE domain_id = $id AND type IS NOT NULL AND disabled = 0 ORDER BY name, type" |
    awk -v apex="$apex" '
        { n[$1] = 1; for (m = 1; m <= 3; m++) print $1 ". " $2 " " substr("ped", m, 1) }
        END {
            for (nm in n) {
                for (m = 1; m <= 3; m++) print nm ". ANY " substr("ped", m, 1)
                split("A AAAA MX TXT CNAME NS SOA", ts, " ")
                for (t = 1; t <= 7; t++) print nm ". " ts[t] " e"
                print "zzz-probe." nm ". A e"
                print "zzz-probe." nm ". A d"
                print "deeper.zzz-probe." nm ". TXT p"
            }
            split("SOA NS MX TXT AAAA A DNSKEY DS NSEC NSEC3PARAM CAA ZONEMD SRV", at, " ")
            for (t = 1; t <= 13; t++) for (m = 1; m <= 3; m++) print apex ". " at[t] " " substr("ped", m, 1)
            for (m = 1; m <= 3; m++) {
                print "nxd-probe." apex ". A " substr("ped", m, 1)
                print "a.b.c.nxd-probe." apex ". TXT " substr("ped", m, 1)
            }
            print toupper("www." apex) ". A e"
            print toupper(apex) ". SOA d"
        }' | head -20000
}

compare() {   # compare A.out B.out: prints "identical folded mismatch"; mismatches (first 5) on stderr
    awk -F'\t' '
        FILENAME == ARGV[1] { k[FNR] = $1; s[FNR] = $2; f[FNR] = $3; next }
        { total++
          if ($1 != k[FNR]) { bad++; if (bad <= 5) print "         query list mismatch at " FNR > "/dev/stderr"; next }
          if ($2 == "TIMEOUT" || s[FNR] == "TIMEOUT") { bad++; if (bad <= 5) print "         timeout: " $1 > "/dev/stderr"; next }
          if ($2 == s[FNR]) ident++
          else if ($3 == f[FNR]) fold++
          else { bad++; if (bad <= 5) print "         DIFFERENT: " $1 > "/dev/stderr" } }
        END { printf "%d %d %d %d\n", total, ident, fold, bad }' "$1" "$2"
}

rcode_of() {   # the first answer line "key TAB strict TAB folded" -> "rcode ancount" (-1 0 when there is none)
    h=$(head -1 "$1" 2>/dev/null | cut -f2)
    if [ -z "$h" ] || [ "$h" = "TIMEOUT" ]; then echo "-1 0"; return; fi
    printf '%d %d\n' "0x$(printf '%s' "$h" | cut -c8)" "0x$(printf '%s' "$h" | cut -c13-16)"
}

TOTAL_C=0; OK_C=0; TOTAL_Q=0; TOTAL_OK=0; TOTAL_FOLD=0; COMPARED=0; FOLDED_ZONES=""
k=1
while [ $k -le $R ]; do
    echo "== round $k"
    D="$T/r$k"; mkdir "$D"
    sqlite3 "$D/z.db" < "$SCHEMA" > /dev/null
    sqlite3 "$D/z.db" < db/karidns_ext.sqlite3.sql > /dev/null
    {
        printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PA"
    } > "$D/a.conf"
    # odd rounds build the DB zones on the stream thread, even rounds on 4 builder threads (ingest-threads, D10)
    if [ $((k % 2)) -eq 0 ]; then TH=4; else TH=1; fi
    {
        printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n' "$PB"
        printf '    database { driver sqlite3; database-file "%s/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; ingest-threads %s; acl-ceiling { 127.0.0.1; }; };\n};\n' "$D" "$T" "$TH"
    } > "$D/b.conf"
    printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PC" > "$D/c.conf"
    while IFS="$TAB" read -r apex f sqlf; do
        sqlite3 "$D/z.db" < "$sqlf" > /dev/null 2>&1
        sqlite3 "$D/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE name = '$apex'"
        case $f in /*) zf=$f ;; *) zf="$ROOT/$f" ;; esac
        printf 'zone "%s" { type primary; file "%s"; allow-transfer { 127.0.0.1; }; };\n' "$apex" "$zf" >> "$D/a.conf"
        printf 'zone "%s" { type slave; masters { 127.0.0.1 port %s; }; allow-transfer { 127.0.0.1; }; };\n' "$apex" "$PB" >> "$D/c.conf"
    done < "$T/round.$k.list"
    chown -R nobody "$D"; chmod 600 "$D/z.db"*
    NZR=$(wc -l < "$T/round.$k.list" | tr -d ' ')
    "$KARIDNS" -c "$D/a.conf" -f > "$D/a.log" 2>&1 &
    SA=$!
    "$KARIDNS" -c "$D/b.conf" -f > "$D/b.log" 2>&1 &
    SB=$!
    "$KARIDNS" -c "$D/c.conf" -f > "$D/c.log" 2>&1 &
    SC=$!
    if ! wait_log "$D/b.log" "\[DB\] initial load complete" 30; then fail "round $k: the database server did not finish its startup batch"; sed 's/^/         /' "$D/b.log" | tail -10; stop_servers; k=$((k + 1)); continue; fi
    sleep 0.5
    while IFS="$TAB" read -r apex f sqlf; do
        printf '%s. SOA p\n' "$apex" > "$D/soa.list"
        "$T/dbquery" -p "$PA" -t 3 "$D/soa.list" "$D/soa.a" > /dev/null 2>&1
        "$T/dbquery" -p "$PB" -t 3 "$D/soa.list" "$D/soa.b" > /dev/null 2>&1
        set -- $(rcode_of "$D/soa.a"); ra=${1:--1}; aa=${2:-0}
        set -- $(rcode_of "$D/soa.b"); rb=${1:--1}; ab=${2:-0}
        if [ "$ra" != "0" ] || [ "$aa" = "0" ]; then echo "$f: the zone file is not loaded by the file server (rcode $ra)" >> "$T/skipped.txt"; continue; fi
        if [ "$rb" != "0" ] || [ "$ab" = "0" ]; then echo "$f: not served from the database (rcode $rb; $(grep -h "zone '$apex\.' " "$D/b.log" | grep -m1 -o 'rejected: .*' | cut -c1-80))" >> "$T/skipped.txt"; continue; fi
        gen_queries "$D/z.db" "$apex" > "$D/q.list"
        NQ=$(wc -l < "$D/q.list" | tr -d ' ')
        "$T/dbquery" -p "$PA" -t 3 "$D/q.list" "$D/q.a" > /dev/null 2>&1
        "$T/dbquery" -p "$PB" -t 3 "$D/q.list" "$D/q.b" > /dev/null 2>&1
        set -- $(compare "$D/q.a" "$D/q.b" 2> "$D/cmp.err"); tot=$1; idn=$2; fol=$3; bad=$4
        COMPARED=$((COMPARED + 1)); TOTAL_Q=$((TOTAL_Q + tot)); TOTAL_OK=$((TOTAL_OK + idn)); TOTAL_FOLD=$((TOTAL_FOLD + fol))
        if [ "$bad" = "0" ] && [ "$tot" = "$NQ" ] && [ "$tot" -gt 0 ]; then
            if [ "$fol" = "0" ]; then pass "$apex ($f): $tot queries, all identical"
            else pass "$apex ($f): $tot queries, $idn identical, $fol differ only in owner case"; FOLDED_ZONES="$FOLDED_ZONES $apex"; fi
        else
            fail "$apex ($f): $bad of $tot queries differ (list had $NQ)"
            cat "$D/cmp.err"
        fi
        # AXFR of A (file) and B (database) hold the same RRs; C (a secondary of B, no file, no database) answers like B
        ./dag @127.0.0.1 -p "$PA" "$apex" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$D/axfr.a"
        ./dag @127.0.0.1 -p "$PB" "$apex" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$D/axfr.b"
        NAX=$(wc -l < "$D/axfr.a" | tr -d ' ')
        if [ "$NAX" -lt 2 ]; then fail "$apex: the file server did not transfer the zone"
        elif cmp -s "$D/axfr.a" "$D/axfr.b"; then pass "$apex: AXFR from the database server is the same set of $NAX RRs as the file server's"
        else
            # PowerDNS keeps owner names in lower case (the zone file may not): the same RRs once the case is folded
            tr 'A-Z' 'a-z' < "$D/axfr.a" | sort > "$D/axfr.a.l"
            tr 'A-Z' 'a-z' < "$D/axfr.b" | sort > "$D/axfr.b.l"
            if cmp -s "$D/axfr.a.l" "$D/axfr.b.l"; then pass "$apex: AXFR is the same set of $NAX RRs once the case of names is folded (the file has upper-case names)"
            else fail "$apex: AXFR differs ($NAX vs $(wc -l < "$D/axfr.b" | tr -d ' ') lines)"; diff "$D/axfr.a" "$D/axfr.b" | head -6; fi
        fi
        j=0
        while [ $j -lt 300 ]; do
            "$T/dbquery" -p "$PC" -t 2 "$D/soa.list" "$D/soa.c" > /dev/null 2>&1
            rcode_of "$D/soa.c" | grep -q "^0 [1-9]" && break
            sleep 0.1; j=$((j + 1))
        done
        "$T/dbquery" -p "$PC" -t 3 "$D/q.list" "$D/q.c" > /dev/null 2>&1
        set -- $(compare "$D/q.b" "$D/q.c" 2> "$D/cmp.err")
        TOTAL_C=$((TOTAL_C + $1)); OK_C=$((OK_C + $2))
        if [ "$4" = "0" ] && [ "$1" = "$NQ" ] && [ "$1" -gt 0 ]; then pass "$apex: the secondary C answers all $1 queries as the database server does"
        elif [ "$1" = "$NQ" ] && [ "$4" -le 40 ]; then
            # A zone transfer compresses names (RFC 1035 4.1.4), and the target of an MX / NS / CNAME takes the case of an earlier
            # owner name: a secondary of a database zone (lower-case owners) can hold "mail.sub" where the primary has "Mail.Sub".
            # Such an answer is the same name (RFC 4343); every differing query is asked again as text and must match when folded.
            awk -F'\t' 'FILENAME == ARGV[1] { s[FNR] = $2; next } $1 != "" && $2 != s[FNR] { print $1 }' "$D/q.b" "$D/q.c" | sort -u > "$D/diff.keys"
            unres=0
            while read -r qn qt qf; do
                ./dag @127.0.0.1 -p "$PB" "$qn" "$qt" +noall +answer +authority +additional +nohexdump 2> /dev/null | tr 'A-Z' 'a-z' | sort > "$D/dq.b"
                ./dag @127.0.0.1 -p "$PC" "$qn" "$qt" +noall +answer +authority +additional +nohexdump 2> /dev/null | tr 'A-Z' 'a-z' | sort > "$D/dq.c"
                cmp -s "$D/dq.b" "$D/dq.c" || { unres=$((unres + 1)); echo "         DIFFERENT also as text: $qn $qt"; }
            done < "$D/diff.keys"
            if [ "$unres" = "0" ]; then pass "$apex: the secondary C answers like the database server ($4 queries differ only in the case of a name inside the data, which a transfer folds)"
            else fail "$apex: $unres queries differ between the database server and its secondary C"; fi
        else fail "$apex: $4 of $1 queries differ between the database server and its secondary C"; cat "$D/cmp.err"; fi
        ./dag @127.0.0.1 -p "$PC" "$apex" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$D/axfr.c"
        if cmp -s "$D/axfr.b" "$D/axfr.c"; then pass "$apex: AXFR from C is the same set of RRs"
        else fail "$apex: AXFR from C differs from B's ($(wc -l < "$D/axfr.b" | tr -d ' ') vs $(wc -l < "$D/axfr.c" | tr -d ' ') lines)"; diff "$D/axfr.b" "$D/axfr.c" | head -6; fi
    done < "$T/round.$k.list"
    stop_servers
    k=$((k + 1))
done

echo
echo "== skipped zone files (not compared)"
sed 's/^/  /' "$T/skipped.txt"
echo
echo "$COMPARED zones compared, $TOTAL_Q queries: $TOTAL_OK byte-identical, $TOTAL_FOLD identical after folding the owner case"
echo "secondary C: $TOTAL_C queries, $OK_C byte-identical to the database server's answers"
[ -n "$FOLDED_ZONES" ] && echo "zones that differ only in the case of owner names (zone file has upper-case letters):$FOLDED_ZONES"
if [ "$COMPARED" -ge 8 ]; then pass "at least 8 zones could be compared ($COMPARED)"; else fail "only $COMPARED zones could be compared (8 needed)"; fi
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_file_diff_test: all $PASS checks passed (file vs DB = 0 differences) ==="; exit 0; fi
echo "=== run_db_file_diff_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
