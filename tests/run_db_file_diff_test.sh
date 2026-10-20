#!/bin/sh
# run_db_file_diff_test.sh - GATE of milestone B4b: the same unsigned zone answers the same from a zone file and from a
# SQLite3 database (beta design 8.4, 9: "file vs DB = 0").
#
# For every zone file of tests/zones/ that tests/db/zone2sql takes (the zone parser accepts it, one zone, no DNSSEC
# records, no extended attributes) two servers are started on the same data: A loads the file (type primary, file), B
# gets the zone from a SQLite3 database through karidns-dbloader.  Files that define the same zone name (example.com has
# many variants) go into separate rounds.  Zones with location / ECS tags are left out until the database carries tags (B8).  For each zone, every owner x every type present, ANY, the types NS MX TXT AAAA
# A CNAME at every owner, a name below every owner, the apex types, NXDOMAIN names and a differently-cased name are
# asked in three flavours (plain query = 512 byte limit, EDNS0 DO=0, EDNS0 DO=1) with tests/db/dbquery.c, which writes
# the exact response bytes with the message ID zeroed.  The responses of A and B must be identical.
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
SA=""; SB=""
stop_servers() {
    [ -n "$SA" ] && kill -TERM "$SA" 2>/dev/null
    [ -n "$SB" ] && kill -TERM "$SB" 2>/dev/null
    i=0
    while [ $i -lt 50 ]; do
        { [ -z "$SA" ] || ! kill -0 "$SA" 2>/dev/null; } && { [ -z "$SB" ] || ! kill -0 "$SB" 2>/dev/null; } && break
        sleep 0.1; i=$((i + 1))
    done
    [ -n "$SA" ] && kill -KILL "$SA" 2>/dev/null
    [ -n "$SB" ] && kill -KILL "$SB" 2>/dev/null
    SA=""; SB=""
}
cleanup() { stop_servers; rm -rf "$T"; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
TAB=$(printf '	')
BASE=$((20000 + $$ % 20000))
PA=$BASE
PB=$((BASE + 1))
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
for f in tests/zones/*.zone "$T/cand/mixed.test.zone"; do
    [ -f "$f" ] || continue
    N=$((N + 1))
    sz=$(wc -c < "$f" | tr -d ' ')
    if [ "$sz" -gt 300000 ]; then echo "$f: larger than 300 kB" >> "$T/skipped.txt"; continue; fi
    if grep -Eq '^[[:space:]]*[$](LOCATION|ECS)' "$f"; then echo "$f: location / ECS tags (the database carries them from B8)" >> "$T/skipped.txt"; continue; fi
    if ! ./tests/db/zone2sql --dialect sqlite3 "$f" > "$T/sql/$N.sql" 2> "$T/z2s.err"; then
        echo "$f: zone2sql cannot take it ($(head -1 "$T/z2s.err" | cut -c1-90))" >> "$T/skipped.txt"; continue
    fi
    rm -f "$T/scratch.db"
    sqlite3 "$T/scratch.db" < "$SCHEMA" > /dev/null
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
        NR == FNR { k[FNR] = $1; s[FNR] = $2; f[FNR] = $3; next }
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

TOTAL_Q=0; TOTAL_OK=0; TOTAL_FOLD=0; COMPARED=0; FOLDED_ZONES=""
k=1
while [ $k -le $R ]; do
    echo "== round $k"
    D="$T/r$k"; mkdir "$D"
    sqlite3 "$D/z.db" < "$SCHEMA" > /dev/null
    {
        printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PA"
    } > "$D/a.conf"
    # odd rounds build the DB zones on the stream thread, even rounds on 4 builder threads (ingest-threads, D10)
    if [ $((k % 2)) -eq 0 ]; then TH=4; else TH=1; fi
    {
        printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n' "$PB"
        printf '    database { driver sqlite3; database-file "%s/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; ingest-threads %s; };\n};\n' "$D" "$T" "$TH"
    } > "$D/b.conf"
    while IFS="$TAB" read -r apex f sqlf; do
        sqlite3 "$D/z.db" < "$sqlf" > /dev/null 2>&1
        case $f in /*) zf=$f ;; *) zf="$ROOT/$f" ;; esac
        printf 'zone "%s" { type primary; file "%s"; };\n' "$apex" "$zf" >> "$D/a.conf"
    done < "$T/round.$k.list"
    chown -R nobody "$D"; chmod 600 "$D/z.db"*
    NZR=$(wc -l < "$T/round.$k.list" | tr -d ' ')
    "$KARIDNS" -c "$D/a.conf" -f > "$D/a.log" 2>&1 &
    SA=$!
    "$KARIDNS" -c "$D/b.conf" -f > "$D/b.log" 2>&1 &
    SB=$!
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
    done < "$T/round.$k.list"
    stop_servers
    k=$((k + 1))
done

echo
echo "== skipped zone files (not compared)"
sed 's/^/  /' "$T/skipped.txt"
echo
echo "$COMPARED zones compared, $TOTAL_Q queries: $TOTAL_OK byte-identical, $TOTAL_FOLD identical after folding the owner case"
[ -n "$FOLDED_ZONES" ] && echo "zones that differ only in the case of owner names (zone file has upper-case letters):$FOLDED_ZONES"
if [ "$COMPARED" -ge 8 ]; then pass "at least 8 zones could be compared ($COMPARED)"; else fail "only $COMPARED zones could be compared (8 needed)"; fi
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_file_diff_test: all $PASS checks passed (file vs DB = 0 differences) ==="; exit 0; fi
echo "=== run_db_file_diff_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
