#!/bin/sh
# run_db_signed_diff_test.sh - GATE of milestone B5: signed zones answer the same from the signed zone file and from a
# SQLite3 database holding the PowerDNS presigned layout (beta design 3.6, 8.4, 9: "file vs DB = 0 for signed zones").
#
# Four zones are signed at test time with BIND's dnssec-signzone: NSEC, NSEC3 (salt, 3 iterations), NSEC3 without salt
# (RFC 9276) and NSEC3 with Opt-Out.  Each has secure and insecure delegations with glue, a DNAME, wildcards (also a
# wildcard CNAME), CNAME chains and an empty non-terminal chain.  Server A loads the signed file.  Server B gets the
# zone from the database: tests/db/zone2sql writes the layout PowerDNS 5.1.4 stores for a zone it AXFRed with
# PRESIGNED=1 (no NSEC / NSEC3 / NSEC3PARAM rows, ordername, ENT rows, NSEC3PARAM metadata), karidns-dbloader reads it
# and the reader rebuilds the chain (dns_presigned.c).  Every owner x every type present, ANY, DS NSEC NSEC3, the ENTs,
# a name below every owner (wildcard, NXDOMAIN, below a delegation, below a DNAME), the hashed owner names of the
# NSEC3 chain and NXDOMAIN probes are asked in three flavours (plain, EDNS0 DO=0, EDNS0 DO=1) with tests/db/dbquery.c;
# the responses must be identical byte for byte (message ID masked).  Then the AXFR of both servers is compared as a
# set of RRs (B7b: the database zones may be transferred now: ALLOW-AXFR-FROM in domainmetadata, bounded by acl-ceiling), and,
# when BIND's dnssec-verify is installed, the zone transferred from the database-backed server is verified (every signature,
# every NSEC / NSEC3 link and Opt-Out rule).  A third server C has no zone file and no database: it is a plain secondary of B
# (type slave).  Everything it was asked must come back as B answers it (byte for byte), its own AXFR is the same set of RRs,
# and dnssec-verify accepts that too (database primary -> file-free KariDNS secondary, B7b).
#
# Needs root (the loader must be root-owned and runs as nobody).  SKIP otherwise and when a binary, the sqlite3 CLI, a C
# compiler or dnssec-keygen / dnssec-signzone is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./karidns-dbloader ./tests/db/zone2sql ./dag; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
for t in sqlite3 cc dnssec-keygen dnssec-signzone; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: $t is not installed"; exit 0; }
done
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbsigned.XXXXXX") || exit 1
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
cleanup() { stop_servers; if [ -n "${KARI_KEEP:-}" ]; then echo "kept $T"; else rm -rf "$T"; fi; }
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
BASE=$((20000 + $$ % 20000))
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

# ---------------------------------------------------------------- the signed zones
write_zone() {   # write_zone NAME FILE
    cat > "$2" <<EOF
\$ORIGIN $1.
\$TTL 300
@ IN SOA ns1 hostmaster 2026101301 3600 600 86400 300
@ IN NS ns1
@ IN NS ns2
@ IN MX 10 mail
@ IN TXT "v=spf1 -all"
ns1 IN A 192.0.2.53
ns1 IN AAAA 2001:db8::53
ns2 IN A 192.0.2.54
mail IN A 192.0.2.25
mail IN AAAA 2001:db8::25
www IN A 192.0.2.80
www IN AAAA 2001:db8::80
w2 IN CNAME www
c1 IN CNAME c2
c2 IN CNAME www
cext IN CNAME host.ext.example.
dn IN DNAME target
target IN A 192.0.2.99
www.target IN A 192.0.2.97
*.wild IN A 192.0.2.100
*.wild IN TXT "wild"
a.wild IN A 192.0.2.101
*.wcn IN CNAME www
x.y.z.ent IN A 192.0.2.110
sec IN NS ns1.sec
sec IN DS 12345 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
ns1.sec IN A 192.0.2.131
ins IN NS ns1.ins
ins IN NS ns.ext.example.
ns1.ins IN A 192.0.2.141
ns1.ins IN AAAA 2001:db8::141
host.ins IN A 192.0.2.142
srv IN SRV 10 20 5060 sip
sip IN A 192.0.2.160
mxfat IN MX 10 fat
fat IN A 192.0.2.201
fat IN A 192.0.2.202
fat IN AAAA 2001:db8::ee
big IN TXT "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
big IN TXT "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
big IN TXT "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
EOF
}

mkdir "$T/signed" "$T/sql" "$T/db"
ZONES="sg-nsec.test sg-n3.test sg-n30.test sg-oo.test"
sign() {   # sign NAME OPTIONS
    write_zone "$1" "$T/signed/$1.zone"
    ( cd "$T/signed" &&
      dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$1" > /dev/null 2>&1 &&
      dnssec-keygen -q -a ECDSAP256SHA256 "$1" > /dev/null 2>&1 &&
      dnssec-signzone -q -S -K . $2 -o "$1" -f "$1.signed" "$1.zone" > /dev/null 2>&1 )
}
sign sg-nsec.test "" && sign sg-n3.test "-3 AABBCCDD -H 3" && sign sg-n30.test "-3 - -H 0" && sign sg-oo.test "-3 - -H 0 -A" ||
    { echo "SKIP: dnssec-signzone could not sign the test zones"; exit 0; }

# ---------------------------------------------------------------- the database
sqlite3 "$T/db/z.db" < "$SCHEMA" > /dev/null
for z in $ZONES; do
    if ! ./tests/db/zone2sql --dialect sqlite3 "$T/signed/$z.signed" > "$T/sql/$z.sql" 2> "$T/z2s.err"; then
        fail "$z: zone2sql: $(head -1 "$T/z2s.err")"; exit 1
    fi
    sqlite3 "$T/db/z.db" < "$T/sql/$z.sql" > /dev/null 2>&1 || { fail "$z: the SQL does not import"; exit 1; }
    sqlite3 "$T/db/z.db" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains WHERE name = '$z'"
    P=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM domainmetadata m JOIN domains d ON d.id = m.domain_id WHERE d.name = '$z' AND m.kind = 'PRESIGNED' AND m.content = '1'")
    N3=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = '$z' AND r.type IN ('NSEC', 'NSEC3', 'NSEC3PARAM')")
    E=$(sqlite3 "$T/db/z.db" "SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = '$z' AND r.type IS NULL")
    if [ "$P" = "1" ] && [ "$N3" = "0" ] && [ "$E" -ge 3 ]; then pass "$z: presigned layout (PRESIGNED, no NSEC/NSEC3/NSEC3PARAM rows, $E ENT rows)"
    else fail "$z: layout presigned=$P chain rows=$N3 ENT rows=$E"; fi
done
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*

{
    printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PA"
    for z in $ZONES; do printf 'zone "%s" { type primary; file "%s/signed/%s.signed"; allow-transfer { 127.0.0.1; }; };\n' "$z" "$T" "$z"; done
} > "$T/a.conf"
{
    printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n' "$PB"
    printf '    database { driver sqlite3; database-file "%s/db/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; acl-ceiling { 127.0.0.1; }; };\n};\n' "$T" "$T"
} > "$T/b.conf"
{   # C: no zone file, no database; a secondary of B for every zone (B7b)
    printf 'options {\n    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PC"
    for z in $ZONES; do printf 'zone "%s" { type slave; masters { 127.0.0.1 port %s; }; allow-transfer { 127.0.0.1; }; };\n' "$z" "$PB"; done
} > "$T/c.conf"
"$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 &
SA=$!
"$KARIDNS" -c "$T/b.conf" -f > "$T/b.log" 2>&1 &
SB=$!
if ! wait_log "$T/b.log" "\[DB\] initial load complete" 30; then fail "the database server did not finish its startup batch"; sed 's/^/         /' "$T/b.log" | tail -15; exit 1; fi
sleep 0.5
"$KARIDNS" -c "$T/c.conf" -f > "$T/c.log" 2>&1 &
SC=$!
# C has every zone when each one answers its SOA record (the first transfer is made at the first tick of its control thread).
# Only a real SOA counts: a zone whose first transfer is still going answers SERVFAIL with EDE 14 "Zone not ready", and +short prints
# the EDE text, so "any output" is not enough (with a slow server, e.g. under TSan, the queries below would hit the empty zone).
for z in $ZONES; do
    i=0; got=""
    while [ $i -lt 300 ]; do
        if ./dag @127.0.0.1 -p "$PC" "$z" SOA +short +nohexdump +time=1 +tries=1 2>/dev/null | grep -Eq '( [0-9]+){5}$'; then got=1; break; fi
        sleep 0.1; i=$((i + 1))
    done
    if [ -n "$got" ]; then pass "$z: the file-free secondary C has transferred the zone from the database server"
    else fail "$z: C did not get the zone from B within 30 s"; grep -h "$z" "$T/c.log" | tail -3 | sed 's/^/         /'; fi
done

gen_queries() {   # gen_queries APEX: the query list on stdout
    apex=$1
    id=$(sqlite3 "$T/db/z.db" "SELECT id FROM domains WHERE name = '$apex'")
    {
        sqlite3 -separator ' ' "$T/db/z.db" "SELECT DISTINCT name, type FROM records WHERE domain_id = $id AND type IS NOT NULL AND disabled = 0 ORDER BY name, type" |
            awk '{ n[$1] = 1; for (m = 1; m <= 3; m++) print $1 ". " $2 " " substr("ped", m, 1) } END { for (nm in n) print "#NAME " nm }'
        sqlite3 "$T/db/z.db" "SELECT DISTINCT name FROM records WHERE domain_id = $id AND type IS NULL AND disabled = 0" | awk '{ print "#NAME " $1 }'
    } | awk -v apex="$apex" '
        /^#NAME / { names[$2] = 1; next }
        { print }
        END {
            for (nm in names) {
                for (m = 1; m <= 3; m++) print nm ". ANY " substr("ped", m, 1)
                split("A AAAA MX TXT CNAME NS SOA DS NSEC NSEC3 DNSKEY", ts, " ")
                for (t = 1; t <= 11; t++) { print nm ". " ts[t] " d"; print nm ". " ts[t] " e" }
                print "zzz-probe." nm ". A d"
                print "zzz-probe." nm ". A e"
                print "zzz-probe." nm ". AAAA d"
                print "zzz-probe." nm ". DS d"
                print "deeper.zzz-probe." nm ". TXT d"
                print "deeper.zzz-probe." nm ". TXT p"
            }
            split("SOA NS MX TXT AAAA A DNSKEY DS NSEC NSEC3 NSEC3PARAM CAA RRSIG ZONEMD SRV", at, " ")
            for (t = 1; t <= 15; t++) for (m = 1; m <= 3; m++) print apex ". " at[t] " " substr("ped", m, 1)
            for (m = 1; m <= 3; m++) {
                print "nxd-probe." apex ". A " substr("ped", m, 1)
                print "a.b.c.nxd-probe." apex ". TXT " substr("ped", m, 1)
                print "nxd-probe." apex ". DS " substr("ped", m, 1)
                print "aaa." apex ". A " substr("ped", m, 1)
                print "zzz." apex ". A " substr("ped", m, 1)
            }
        }' | head -40000
}

# compare A.out B.out: prints "total identical folded mismatches" (folded is always 0 now).  Since B6a the answers are
# compared byte for byte, the case of the owner names included: PowerDNS stores the hashed owner names of an NSEC3 chain
# in lower case, the loader writes the hashed first label of every NSEC3 owner and of every RRSIG(NSEC3) owner in upper
# case (RFC 4648 s7 alphabet, as BIND's dnssec-signzone writes it; open item 1, decided 2026-10-21), so the file zone and
# its database copy answer the same bytes.
compare() {
    awk -F'\t' '
        NR == FNR { k[FNR] = $1; s[FNR] = $2; next }
        { total++
          if ($1 != k[FNR]) { bad++; if (bad <= 5) print "         query list mismatch at " FNR > "/dev/stderr"; next }
          if ($2 == "TIMEOUT" || s[FNR] == "TIMEOUT") { bad++; if (bad <= 5) print "         timeout: " $1 > "/dev/stderr"; next }
          if ($2 == s[FNR]) ident++
          else { bad++; if (bad <= 5) print "         DIFFERENT: " $1 > "/dev/stderr" } }
        END { printf "%d %d 0 %d\n", total, ident, bad }' "$1" "$2"
}

TOTAL=0; IDENT=0; FOLD=0
for z in $ZONES; do
    printf '%s. SOA p\n' "$z" > "$T/soa.list"
    "$T/dbquery" -p "$PA" -t 3 "$T/soa.list" "$T/soa.a" > /dev/null 2>&1
    "$T/dbquery" -p "$PB" -t 3 "$T/soa.list" "$T/soa.b" > /dev/null 2>&1
    ha=$(head -1 "$T/soa.a" | cut -f2); hb=$(head -1 "$T/soa.b" | cut -f2)
    if [ -z "$ha" ] || [ "$ha" = "TIMEOUT" ] || [ -z "$hb" ] || [ "$hb" = "TIMEOUT" ]; then
        fail "$z: not answered (file server: ${ha:-none}, database server: ${hb:-none}; $(grep -h "$z" "$T/b.log" | grep -m1 -o 'rejected: .*' | cut -c1-100))"; continue
    fi
    gen_queries "$z" > "$T/q.list"
    NQ=$(wc -l < "$T/q.list" | tr -d ' ')
    "$T/dbquery" -p "$PA" -t 3 "$T/q.list" "$T/q.a" > /dev/null 2>&1
    "$T/dbquery" -p "$PB" -t 3 "$T/q.list" "$T/q.b" > /dev/null 2>&1
    set -- $(compare "$T/q.a" "$T/q.b" 2> "$T/cmp.err"); tot=$1; idn=$2; fol=$3; bad=$4
    TOTAL=$((TOTAL + tot)); IDENT=$((IDENT + idn)); FOLD=$((FOLD + fol))
    if [ "$bad" = "0" ] && [ "$tot" = "$NQ" ] && [ "$tot" -gt 0 ]; then
        pass "$z: $tot queries (DO=1 included), all byte-identical (the case of the owner names included)"
    else fail "$z: $bad of $tot queries differ (list had $NQ)"; cat "$T/cmp.err"; fi
    # the NSEC3 hashed owners of the zone as query names (NSEC3 owner names answer NOERROR, RFC 5155 s7.2)
    id=$(sqlite3 "$T/db/z.db" "SELECT id FROM domains WHERE name = '$z'")
    sqlite3 "$T/db/z.db" "SELECT DISTINCT name FROM records WHERE domain_id = $id AND type = 'RRSIG' AND content LIKE 'NSEC3 %'" |
        awk '{ for (m = 1; m <= 3; m++) { print $1 ". NSEC3 " substr("ped", m, 1); print $1 ". ANY " substr("ped", m, 1); print $1 ". A " substr("ped", m, 1) } }' > "$T/h.list"
    if [ -s "$T/h.list" ]; then
        "$T/dbquery" -p "$PA" -t 3 "$T/h.list" "$T/h.a" > /dev/null 2>&1
        "$T/dbquery" -p "$PB" -t 3 "$T/h.list" "$T/h.b" > /dev/null 2>&1
        set -- $(compare "$T/h.a" "$T/h.b" 2> "$T/cmp.err")
        TOTAL=$((TOTAL + $1)); IDENT=$((IDENT + $2)); FOLD=$((FOLD + $3))
        if [ "$4" = "0" ] && [ "$1" -gt 0 ]; then pass "$z: $1 queries for the NSEC3 owner names, all byte-identical"
        else fail "$z: $4 of $1 NSEC3 owner name queries differ"; cat "$T/cmp.err"; fi
    fi
    # C, the file-free secondary of B: every query B answered must come back byte for byte as B gave it (the same list)
    "$T/dbquery" -p "$PC" -t 3 "$T/q.list" "$T/q.c" > /dev/null 2>&1
    set -- $(compare "$T/q.b" "$T/q.c" 2> "$T/cmp.err")
    TOTAL=$((TOTAL + $1)); IDENT=$((IDENT + $2))
    if [ "$4" = "0" ] && [ "$1" = "$NQ" ] && [ "$1" -gt 0 ]; then pass "$z: the secondary C answers all $1 queries as the database server B does (byte-identical)"
    else fail "$z: $4 of $1 queries differ between the database server and its secondary C (list had $NQ)"; cat "$T/cmp.err"; fi
    if [ -s "$T/h.list" ]; then
        "$T/dbquery" -p "$PC" -t 3 "$T/h.list" "$T/h.c" > /dev/null 2>&1
        set -- $(compare "$T/h.b" "$T/h.c" 2> "$T/cmp.err")
        TOTAL=$((TOTAL + $1)); IDENT=$((IDENT + $2))
        if [ "$4" = "0" ] && [ "$1" -gt 0 ]; then pass "$z: C answers the $1 NSEC3 owner name queries as B does"
        else fail "$z: $4 of $1 NSEC3 owner name queries differ between B and C"; cat "$T/cmp.err"; fi
    fi
    # AXFR as a set of RRs: A (the signed file), B (the database zone; its metadata allows 127.0.0.1 and acl-ceiling lets the
    # address in) and C (a secondary of B).  They must all hold the same RRs.
    ./dag @127.0.0.1 -p "$PA" "$z" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$T/axfr.a"
    ./dag @127.0.0.1 -p "$PB" "$z" AXFR +nohexdump +noall +answer 2> /dev/null > "$T/axfr.b.raw"
    ./dag @127.0.0.1 -p "$PC" "$z" AXFR +nohexdump +noall +answer 2> /dev/null > "$T/axfr.c.raw"
    sort "$T/axfr.b.raw" > "$T/axfr.b"
    sort "$T/axfr.c.raw" > "$T/axfr.c"
    NA=$(wc -l < "$T/axfr.a" | tr -d ' ')
    if [ "$NA" -lt 10 ]; then fail "$z: the file server did not transfer the zone"
    elif [ "$(wc -l < "$T/axfr.b" | tr -d ' ')" -lt 10 ]; then fail "$z: the database server refused the AXFR (allow-transfer from the metadata and acl-ceiling)"; grep -h "$z" "$T/b.log" | tail -3 | sed 's/^/         /'
    else
        if cmp -s "$T/axfr.a" "$T/axfr.b"; then pass "$z: AXFR from the database server is the same set of $NA RRs as the signed file's"
        else fail "$z: AXFR differs ($NA vs $(wc -l < "$T/axfr.b" | tr -d ' ') lines)"; diff "$T/axfr.a" "$T/axfr.b" | head -6; fi
        if cmp -s "$T/axfr.b" "$T/axfr.c"; then pass "$z: AXFR from the secondary C is the same set of RRs"
        else fail "$z: AXFR from C differs from B's ($(wc -l < "$T/axfr.b" | tr -d ' ') vs $(wc -l < "$T/axfr.c" | tr -d ' ') lines)"; diff "$T/axfr.b" "$T/axfr.c" | head -6; fi
        if command -v dnssec-verify >/dev/null 2>&1; then
            for who in b c; do
                sed '$d' "$T/axfr.$who.raw" > "$T/verify.zone"
                if dnssec-verify -q -o "$z" "$T/verify.zone" > "$T/verify.out" 2>&1; then pass "$z: dnssec-verify of the AXFR from $(echo $who | tr bc BC)"
                else fail "$z: dnssec-verify of the AXFR from $(echo $who | tr bc BC): $(head -3 "$T/verify.out" | tr '\n' ' ')"; fi
            done
        fi
    fi
done
echo
echo "$TOTAL queries: $IDENT byte-identical"
stop_servers
if grep -q "AddressSanitizer\|runtime error:" "$T/a.log" "$T/b.log" "$T/c.log" 2>/dev/null; then fail "sanitizer report in a server log"; fi
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_signed_diff_test: all $PASS checks passed (file vs DB = 0 differences, signed zones) ==="; exit 0; fi
echo "=== run_db_signed_diff_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
