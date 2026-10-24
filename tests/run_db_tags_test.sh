#!/bin/sh
# run_db_tags_test.sh - GATE of milestone B8: location / ECS tags and tinydns zones (time stamps, countdown TTLs, % locations)
# answer the same, for every client, from a zone file, from a SQLite3 database and from a file-free KariDNS secondary of the
# database server (beta design 3.6a, 3.7, 9: "per-client answers file vs DB = 0").
#
# Two zones, both written for this test (tests/db/):
#   tagz.test  BIND zone with $LOCATION / $ECS-SUBNET tags and tag definitions (IPv4 and IPv6 CIDRs)
#   tdz.test   tinydns data with % locations, activation time stamps, countdown TTLs (ttl 0 + time stamp), a location on a countdown
# Servers (127.0.0.1, one port each):
#   A  both zones from files (type primary; tagz.test with ecs-trusted-resolvers 127.0.0.2 / 127.0.0.5)
#   B  both zones from SQLite3 through karidns-dbloader: tests/db/zone2sql writes records + karidns_record_tags /
#      karidns_record_tinydns / karidns_zone_tagdefs + X-KARIDNS-FORMAT; the trusted resolvers come from the metadata
#      X-KARIDNS-ECS-TRUSTED-RESOLVERS, bounded by acl-ceiling { 127.0.0.0/24; }
#   C  no file, no database: a secondary of B (Extended AXFR carries tags and tinydns attributes)
#   D  the database of B with a narrower acl-ceiling { 127.0.0.2; }: the resolver 127.0.0.5 is no longer trusted
# Clients are the loopback aliases 127.0.0.1 ... 127.0.0.5 (added with ifconfig and removed on exit).  Every combination of name x type x
# {plain, EDNS} x ECS option (none, two IPv4 subnets that carry tags, one that does not, one IPv6 subnet) is asked from every client and
# the responses (message ID zeroed) of A, B and C are compared byte for byte.  Time-dependent tinydns TTLs are constant here (a countdown
# whose time stamp is far in the future is capped at 3600 s).  Also: the Extended AXFR stream of the file zone and of the database zone are
# the same bytes, a plain AXFR of both hold the same RRs, an edit of a tag in the database reaches the answers with `karictl reload`,
# and the ceiling cuts the database zone's trusted resolvers.
#
# Needs root (loader owner, loopback aliases).  SKIP otherwise, and when a binary, the sqlite3 CLI or a C compiler is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user; loopback aliases)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./karidns-dbloader ./tests/db/zone2sql ./dag ./karictl; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler for tests/db/dbquery.c"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbtags.XXXXXX") || exit 1
chmod 755 "$T"
SA=""; SB=""; SC=""; SD=""
ADDED=""
stop_servers() {
    for p in "$SA" "$SB" "$SC" "$SD"; do [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; done
    i=0
    while [ $i -lt 100 ]; do                       # wait for the managers (they stop their children): no sanitizer build leaves one behind
        alive=0
        for p in "$SA" "$SB" "$SC" "$SD"; do [ -n "$p" ] && kill -0 "$p" 2>/dev/null && alive=1; done
        [ $alive -eq 0 ] && break
        sleep 0.1; i=$((i + 1))
    done
    for p in "$SA" "$SB" "$SC" "$SD"; do [ -n "$p" ] && kill -KILL "$p" 2>/dev/null; done
    for p in "$SA" "$SB" "$SC" "$SD"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
    SA=""; SB=""; SC=""; SD=""
}
cleanup() {
    stop_servers
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
BASE=$((20000 + $$ % 20000))
PA=$BASE; PB=$((BASE + 1)); PC=$((BASE + 2)); PD=$((BASE + 3))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
SRCS="127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5"

for ip in $SRCS; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || ifconfig lo 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null || ifconfig lo inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"
    else echo "SKIP: loopback alias $ip cannot be added"; exit 0; fi
done

cc -O1 -o "$T/dbquery" tests/db/dbquery.c 2> "$T/cc.log" || { echo "SKIP: tests/db/dbquery.c does not compile"; cat "$T/cc.log"; exit 0; }
cc -O1 -o "$T/xfrdump" tests/db/xfrdump.c 2>> "$T/cc.log" || { echo "SKIP: tests/db/xfrdump.c does not compile"; cat "$T/cc.log"; exit 0; }
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }

wait_log() {   # wait_log LOG PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -Eq -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

# ---------------------------------------------------------------- data
echo "== data"
mkdir "$T/z" "$T/db"
cp tests/db/tagz.test.zone tests/db/tdz.test.data "$T/z/"
chmod 644 "$T/z/"*
SCHEMA=tests/db/pdns_schema.sqlite3.sql
sqlite3 "$T/db/z.db" < "$SCHEMA" > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
./tests/db/zone2sql --dialect sqlite3 "$T/z/tagz.test.zone" | sqlite3 "$T/db/z.db" && pass "tagz.test imported" || fail "zone2sql / import of tagz.test"
./tests/db/zone2sql --dialect sqlite3 --format tinydns "$T/z/tdz.test.data" | sqlite3 "$T/db/z.db" && pass "tdz.test imported" || fail "zone2sql / import of tdz.test"
sq() { sqlite3 "$T/db/z.db" "$@"; }
NTAG=$(sq "SELECT count(*) FROM karidns_record_tags"); NTD=$(sq "SELECT count(*) FROM karidns_record_tinydns"); NDEF=$(sq "SELECT count(*) FROM karidns_zone_tagdefs")
[ "$NTAG" -ge 8 ] && [ "$NTD" -ge 8 ] && [ "$NDEF" -ge 11 ] && pass "the importer wrote $NTAG tag rows, $NTD tinydns rows, $NDEF definition rows" || fail "importer rows: $NTAG / $NTD / $NDEF"
[ "$(sq "SELECT content FROM domainmetadata WHERE kind = 'X-KARIDNS-FORMAT'")" = "tinydns" ] && pass "X-KARIDNS-FORMAT tinydns for tdz.test" || fail "X-KARIDNS-FORMAT"
sq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains"
sq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-ECS-TRUSTED-RESOLVERS', '127.0.0.2, 127.0.0.5' FROM domains WHERE name = 'tagz.test'"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*

{
    printf 'options {\n    user "nobody"; pid-file "none"; ecs-enable yes; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PA"
    printf 'zone "tagz.test" { type primary; file "%s/z/tagz.test.zone"; allow-transfer { 127.0.0.1; }; ecs-trusted-resolvers { 127.0.0.2; 127.0.0.5; }; };\n' "$T"
    printf 'zone "tdz.test" { type primary; file "%s/z/tdz.test.data"; file-format tinydns; allow-transfer { 127.0.0.1; }; };\n' "$T"
} > "$T/a.conf"
dbconf() {   # dbconf PORT CEILING CTLSOCKET
    printf 'options {\n    user "nobody"; pid-file "none"; ecs-enable yes; listen-on { 127.0.0.1; }; port %s;\n' "$1"
    printf '    database { driver sqlite3; database-file "%s/db/z.db"; loader-user "nobody"; loader-path "%s/karidns-dbloader"; acl-ceiling { %s; }; db-reload-timeout 4; };\n};\n' "$T" "$T" "$2"
    [ -n "${3:-}" ] && printf 'control-channel { socket "%s"; secret "%s"; };\n' "$3" "$SECRET"
}
dbconf "$PB" "127.0.0.0/24" "$T/ctl.sock" > "$T/b.conf"
dbconf "$PD" "127.0.0.2" > "$T/d.conf"
{
    printf 'options {\n    user "nobody"; pid-file "none"; ecs-enable yes; listen-on { 127.0.0.1; }; port %s;\n};\n' "$PC"
    printf 'zone "tagz.test" { type slave; masters { 127.0.0.1 port %s; }; allow-transfer { 127.0.0.1; }; };\n' "$PB"
    printf 'zone "tdz.test" { type slave; masters { 127.0.0.1 port %s; }; allow-transfer { 127.0.0.1; }; };\n' "$PB"
} > "$T/c.conf"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"

# ---------------------------------------------------------------- servers
echo "== servers"
"$KARIDNS" -c "$T/a.conf" -f > "$T/a.log" 2>&1 & SA=$!
"$KARIDNS" -c "$T/b.conf" -f > "$T/b.log" 2>&1 & SB=$!
"$KARIDNS" -c "$T/d.conf" -f > "$T/d.log" 2>&1 & SD=$!
if wait_log "$T/b.log" "\[DB\] initial load complete" 30; then pass "B: the startup batch is complete"; else fail "B: no initial load"; sed 's/^/         /' "$T/b.log" | tail -15; fi
"$KARIDNS" -c "$T/c.conf" -f > "$T/c.log" 2>&1 & SC=$!
sleep 1
grep -q "zone '[^']*' .*rejected" "$T/b.log" && { fail "B rejected a zone"; grep "rejected" "$T/b.log" | head -3 | sed 's/^/         /'; } || pass "B accepted both zones"
asked() { "$T/dbquery" -p "$1" -t 3 "$2" "$3" > /dev/null 2>&1; }
for z in tagz.test tdz.test; do
    printf '%s. SOA p\n' "$z" > "$T/soa.list"
    j=0
    while [ $j -lt 100 ]; do
        asked "$PC" "$T/soa.list" "$T/soa.c"
        h=$(head -1 "$T/soa.c" | cut -f2); [ -n "$h" ] && [ "$h" != TIMEOUT ] && [ "$(printf '%s' "$h" | cut -c8)" = "0" ] && [ "$(printf '%s' "$h" | cut -c13-16)" != "0000" ] && break
        sleep 0.2; j=$((j + 1))
    done
    [ $j -lt 100 ] && pass "C transferred $z from B" || fail "C did not get $z"
done

# ---------------------------------------------------------------- query lists
ECSS="- 198.51.100.0/24 203.0.113.0/24 192.0.2.0/24 2001:db8:1::/48"
gen() {   # gen ZONE NAMES TYPES MODES
    awk -v zone="$1" -v names="$2" -v types="$3" -v modes="$4" -v ecss="$ECSS" 'BEGIN {
        nn = split(names, n, " "); nt = split(types, t, " "); nm = split(modes, m, " "); ne = split(ecss, e, " ")
        for (i = 1; i <= nn; i++) for (j = 1; j <= nt; j++) for (k = 1; k <= nm; k++) {
            fq = (n[i] == "@") ? zone "." : n[i] "." zone "."
            if (m[k] == "p") { print fq " " t[j] " p"; continue }
            for (l = 1; l <= ne; l++) print fq " " t[j] " " m[k] (e[l] == "-" ? "" : " " e[l])
        } }'
}
gen tagz.test "@ www mail geo both txt srv sip mx ns1 nx-probe" "A AAAA TXT MX SRV NS SOA ANY" "p e" > "$T/q.tagz"
gen tdz.test "@ www cd cd2 act fut both mail ns1 c ip6 nx-probe" "A AAAA TXT MX NS SOA ANY CNAME" "p e" > "$T/q.tdz"
# an owner with a '.' inside a label (tinydns \056) and a location: its TINYDNS_WRAP owner must keep the escape through the
# Extended AXFR to C (the receiver used to rebuild the owner by splitting the text at every dot).  awk -v would eat the
# backslash, so these lines are written with printf (\\ is one backslash).
printf 'a\\046b.tdz.test. A p\na\\046b.tdz.test. A e\na\\046b.tdz.test. ANY e\n' >> "$T/q.tdz"
# a plain (no EDNS) query takes no ECS option: the lines "p" are asked once
compare() {   # compare X.out Y.out: prints "total identical bad"
    awk -F'\t' '
        NR == FNR { k[FNR] = $1; s[FNR] = $2; next }
        { total++
          if ($1 != k[FNR]) { bad++; if (bad <= 5) print "         query list mismatch at " FNR > "/dev/stderr"; next }
          if ($2 == "TIMEOUT" || s[FNR] == "TIMEOUT") { bad++; if (bad <= 5) print "         timeout: " $1 > "/dev/stderr"; next }
          if ($2 == s[FNR]) ident++
          else { bad++; if (bad <= 8) print "         DIFFERENT: " $1 > "/dev/stderr" } }
        END { printf "%d %d %d\n", total, ident, bad }' "$1" "$2"
}
NQ_TOTAL=0
ask_all() {   # ask_all NAME PORT LIST: every client
    for s in $SRCS; do "$T/dbquery" -p "$2" -b "$s" -t 3 "$3" "$T/$1.$s.out" > /dev/null 2>&1; done
}
echo "== per-client answers: zone file (A) vs database (B) vs file-free secondary (C)"
for zq in tagz tdz; do
    for s in $SRCS; do :; done
    ask_all "a.$zq" "$PA" "$T/q.$zq"
    ask_all "b.$zq" "$PB" "$T/q.$zq"
    ask_all "c.$zq" "$PC" "$T/q.$zq"
    NQ=$(wc -l < "$T/q.$zq" | tr -d ' ')
    for s in $SRCS; do
        set -- $(compare "$T/a.$zq.$s.out" "$T/b.$zq.$s.out" 2> "$T/cmp.err"); tot=$1; idn=$2; bad=$3
        if [ "$bad" = "0" ] && [ "$tot" = "$NQ" ]; then pass "$zq from $s: A = B ($tot queries identical)"; NQ_TOTAL=$((NQ_TOTAL + tot)); else fail "$zq from $s: A vs B: $bad of $tot differ (list $NQ)"; cat "$T/cmp.err"; fi
        set -- $(compare "$T/b.$zq.$s.out" "$T/c.$zq.$s.out" 2> "$T/cmp.err"); tot=$1; bad=$3
        if [ "$bad" = "0" ] && [ "$tot" = "$NQ" ]; then pass "$zq from $s: B = C ($tot queries identical)"; else fail "$zq from $s: B vs C: $bad of $tot differ"; cat "$T/cmp.err"; fi
    done
done
echo "  $NQ_TOTAL queries compared between the zone-file server and the database server"
# the data must actually differ per client, or the comparison proves nothing
D=0
for s in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5; do cmp -s "$T/a.tagz.127.0.0.1.out" "$T/a.tagz.$s.out" || D=$((D + 1)); done
[ $D -ge 3 ] && pass "tagz.test answers differ between clients ($D of 4 clients differ from 127.0.0.1)" || fail "tagz.test answers do not depend on the client"
D=0
for s in 127.0.0.2 127.0.0.3 127.0.0.4; do cmp -s "$T/a.tdz.127.0.0.1.out" "$T/a.tdz.$s.out" || D=$((D + 1)); done
[ $D -ge 2 ] && pass "tdz.test answers differ between clients ($D of 3)" || fail "tdz.test answers do not depend on the client"

# ---------------------------------------------------------------- spot checks with dag (the expectations are written down here)
echo "== spot checks"
DAGB() { ./dag @127.0.0.1 -p "$PB" "$@" +short +nohexdump 2>/dev/null; }
chk() {   # chk DESCRIPTION EXPECTED -b SRC NAME TYPE [+subnet=..]
    d=$1; want=$2; shift 2
    got=$(DAGB "$@" | sort | tr '\n' ' ' | sed 's/ $//')
    [ "$got" = "$want" ] && pass "$d" || fail "$d (got '$got', want '$want')"
}
chk "tagz www from the untagged client 127.0.0.1" "192.0.2.1" -b 127.0.0.1 www.tagz.test A
chk "tagz www from the lan client 127.0.0.2 (untagged and lan)" "192.0.2.1 192.0.2.10" -b 127.0.0.2 www.tagz.test A
chk "tagz www from the wan client 127.0.0.4 (untagged and wan)" "192.0.2.1 192.0.2.20" -b 127.0.0.4 www.tagz.test A
chk "tagz geo from trusted 127.0.0.2 with ECS east" "192.0.2.30 192.0.2.50" -b 127.0.0.2 geo.tagz.test A +subnet=198.51.100.0/24
chk "tagz geo from trusted 127.0.0.5 with ECS west" "192.0.2.40 192.0.2.50" -b 127.0.0.5 geo.tagz.test A +subnet=203.0.113.0/24
chk "tagz geo from untrusted 127.0.0.3 with ECS east (ignored)" "192.0.2.50" -b 127.0.0.3 geo.tagz.test A +subnet=198.51.100.0/24
chk "tdz www from 127.0.0.2 (location l2)" "192.0.2.1 192.0.2.12" -b 127.0.0.2 www.tdz.test A
chk "tdz www from 127.0.0.4 (location lw)" "192.0.2.1 192.0.2.14" -b 127.0.0.4 www.tdz.test A
chk "tdz countdown record cd" "192.0.2.20" -b 127.0.0.1 cd.tdz.test A
chk "tdz activated record act (time stamp in the past)" "192.0.2.21" -b 127.0.0.1 act.tdz.test A
chk "tdz future record fut is not served" "" -b 127.0.0.1 fut.tdz.test A
TTL=$(./dag @127.0.0.1 -p "$PB" -b 127.0.0.1 cd.tdz.test A +noall +answer +nohexdump 2>/dev/null | awk '{print $2}' | head -1)
[ "$TTL" = "3600" ] && pass "countdown TTL is capped at 3600" || fail "countdown TTL '$TTL'"

# ---------------------------------------------------------------- the ceiling bounds the trusted resolvers of a database zone
echo "== acl-ceiling and ecs-trusted-resolvers"
DAGD() { ./dag @127.0.0.1 -p "$PD" "$@" +short +nohexdump 2>/dev/null | sort | tr '\n' ' ' | sed 's/ $//'; }
wait_log "$T/d.log" "\[DB\] initial load complete" 30 || fail "D: no initial load"
got=$(DAGD -b 127.0.0.2 geo.tagz.test A +subnet=198.51.100.0/24)
[ "$got" = "192.0.2.30 192.0.2.50" ] && pass "D (ceiling 127.0.0.2): the resolver 127.0.0.2 is trusted" || fail "D 127.0.0.2: '$got'"
got=$(DAGD -b 127.0.0.5 geo.tagz.test A +subnet=198.51.100.0/24)
[ "$got" = "192.0.2.50" ] && pass "D: the resolver 127.0.0.5 is in the zone's list but outside the ceiling: not trusted" || fail "D 127.0.0.5: '$got'"
grep -q "ecs-trusted-resolvers 127.0.0.5 .*acl-ceiling\|ecs-trusted-resolvers.*acl-ceiling" "$T/d.log" && pass "D logged the entry outside the ceiling" || fail "D did not log the narrowed list"
./karictl -c "$T/karictl.conf" dbstatus tagz.test 2>&1 | grep -q "ecs-trusted-resolvers" && pass "dbstatus names the ecs-trusted-resolvers note" || echo "  [info] dbstatus has no ecs-trusted-resolvers note (not required)"

# ---------------------------------------------------------------- Extended AXFR out of the database zone = out of the file zone
echo "== Extended AXFR"
for z in tagz.test tdz.test; do
    "$T/xfrdump" -p "$PA" -x "$z." > "$T/xa.$z" 2>/dev/null; "$T/xfrdump" -p "$PB" -x "$z." > "$T/xb.$z" 2>/dev/null; "$T/xfrdump" -p "$PC" -x "$z." > "$T/xc.$z" 2>/dev/null
    na=$(wc -l < "$T/xa.$z" | tr -d ' ')
    [ "$na" -ge 1 ] && grep -q ff16 "$T/xa.$z" && pass "$z: the file server sends Extended AXFR records ($na message(s))" || fail "$z: no Extended AXFR from the file server"
    cmp -s "$T/xa.$z" "$T/xb.$z" && pass "$z: Extended AXFR of the database zone is byte-identical to the file zone's" || { fail "$z: Extended AXFR of the database zone differs from the file zone's"; cut -c1-300 "$T/xa.$z" | head -2; cut -c1-300 "$T/xb.$z" | head -2; }
    # the EXPIRE option (RFC 7314) at the end of the first message carries the primary's SOA EXPIRE, the secondary's remaining timer: masked
    for w in b c; do sed -E 's/[0-9a-f]{8}$//' "$T/x$w.$z" > "$T/x$w.$z.m"; done
    if cmp -s "$T/xb.$z.m" "$T/xc.$z.m"; then pass "$z: the secondary C re-serves the same Extended AXFR"; else
        fail "$z: Extended AXFR of C differs from B's"
        off=$(cmp "$T/xb.$z" "$T/xc.$z" 2>&1 | awk '{for (i = 1; i < NF; i++) if ($i == "char" || $i == "byte") { gsub(",", "", $(i + 1)); print $(i + 1); exit }}')
        [ -n "$off" ] && { echo "         first difference at hex digit $off; B: $(head -1 "$T/xb.$z" | cut -c$((off > 40 ? off - 40 : 1))-$((off + 60)))"; echo "                                         C: $(head -1 "$T/xc.$z" | cut -c$((off > 40 ? off - 40 : 1))-$((off + 60)))"; echo "         lengths $(wc -c < "$T/xb.$z") $(wc -c < "$T/xc.$z")"; }
    fi
    ./dag @127.0.0.1 -p "$PA" "$z" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$T/pa.$z"
    ./dag @127.0.0.1 -p "$PB" "$z" AXFR +nohexdump +noall +answer 2> /dev/null | sort > "$T/pb.$z"
    cmp -s "$T/pa.$z" "$T/pb.$z" && [ -s "$T/pa.$z" ] && pass "$z: plain AXFR of file and database hold the same RRs ($(wc -l < "$T/pa.$z" | tr -d ' '))" || fail "$z: plain AXFR differs"
done

# ---------------------------------------------------------------- a tag edited in the database reaches the answers
echo "== change log"
sq "UPDATE karidns_record_tags SET location_tag = 'wan' WHERE record_id = (SELECT id FROM records WHERE name = 'mail.tagz.test')"
ALOG=$(./karictl -c "$T/karictl.conf" reload 2>&1)
printf '%s\n' "$ALOG" | grep -q "^OK reloaded" && pass "karictl reload: $ALOG" || fail "karictl reload: $ALOG"
j=0
while [ $j -lt 60 ]; do
    [ "$(DAGB -b 127.0.0.4 mail.tagz.test A)" = "192.0.2.11" ] && break
    sleep 0.2; j=$((j + 1))
done
[ $j -lt 60 ] && pass "mail.tagz.test now goes to the wan client (tag edited without a serial bump)" || fail "the tag edit did not arrive"
[ -z "$(DAGB -b 127.0.0.2 mail.tagz.test A)" ] && pass "and no longer to the lan client" || fail "the lan client still gets mail.tagz.test"

stop_servers
echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_tags_test: all $PASS checks passed (per-client answers: file = database = secondary) ==="; exit 0; fi
echo "=== run_db_tags_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
