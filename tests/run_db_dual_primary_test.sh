#!/bin/sh
# run_db_dual_primary_test.sh - two karidns servers on ONE PostgreSQL database act as primaries and are deterministic
# (milestone B11b; release plan 4.8 "Dual (multi) primary over one DB", beta design 8.4).
#
# Requirement: the same database state gives the same SOA serial and the same RR sequence in an AXFR on every server, so a
# secondary can follow either of them.  Checked here, with two servers (server-id ns1 / ns2, ports of their own on 127.0.0.1,
# a loader each) on the lab zone set (tests/zones/, the tags zone, a tinydns data file, a zone with ALIAS and LUA records,
# signed NSEC / NSEC3 zones when BIND's dnssec-signzone is installed):
#   S0  - karidns-dbloader --dump of the same state from two separate processes is byte for byte the same (also with
#         --loader-threads 4, per schema, and per view with --map-view);
#   S1  - no auto-reload: every zone has the same SOA serial and the same AXFR RR sequence (in order, not sorted) on both servers,
#         also as seen from other client addresses (tinydns locations, $LOCATION tags); samples of query answers are the same;
#         a zone with a row the loader cannot read is served by neither; an edit + a reload request makes both converge to the
#         same serial and the same AXFR;
#         IXFR (RFC 1995 s4, D-B11-2): the (from, to) pair that both servers hold in their history gives the same answer; a
#         "from" that only one server holds is answered incrementally by that one and with the whole zone (AXFR style, RFC 1995
#         s4) by the other, which restarted and has no history; a "from" older than any history is the whole zone on both;
#   S2  - auto-reload yes (ns2 with ingest-threads 4 and loader-threads 4, ns1 with one of each): an edit without a request is
#         served by both with the same serial and AXFR; three zones changed in one commit are one reload of three zones (read by
#         the worker threads of ns2: a regression test for workers that did not know the optional tables of the source); two
#         commits in a row end in the same state whatever intermediate versions each server saw;
#   S3  - two views (karidns_domain_views, loopback aliases 127.0.0.2/3): the same serial and AXFR per view on both servers.
# Not deterministic, and so not tested (docs/karidns.md "Several servers on one PostgreSQL database"): ALIAS answers that an
# alias-resolver expands (the resolver and the time of the lookup), Dynamic UPDATE, the IXFR history across restarts and
# coalesced reloads, a tinydns time stamp or countdown at the moment it passes.  LUA records are never run, so they are the same.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned and runs as the unprivileged user that
# can connect to PostgreSQL).  SKIP otherwise, and when PostgreSQL is not reachable (tests/db/pg_lib.sh) or a binary is missing.
# The loopback aliases 127.0.0.2/3 are added when missing (and removed on exit); without them S3 and the per-address checks are SKIPped.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dual.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
mkdir "$T/dd"; chmod 777 "$T/dd"; DD=$T/dd
PIDA=""; PIDB=""; ADDED=""
stop_one() {   # stop_one PID: TERM, wait up to 15 s, then the whole tree
    [ -n "$1" ] || return 0
    kill -TERM "$1" 2>/dev/null
    i=0; while [ $i -lt 150 ] && kill -0 "$1" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kari_kill_tree "$1"
}
cleanup() {
    stop_one "$PIDA"; stop_one "$PIDB"
    kari_kill_conf "$T/a.conf" "$T/b.conf"
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
pg_setup dual || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT_A=$((20000 + $$ % 20000))
PORT_B=$((PORT_A + 1))
BOUND=${BOUND:-20}        # seconds a server may need to show a change (every wait in this test is bounded by it)

# loopback aliases for the per-address checks and the views
ALIASES=1
for ip in 127.0.0.2 127.0.0.3; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else ALIASES=0; fi
done

pfz() { psql -X -q -At -1 -v ON_ERROR_STOP=1 "$PGC" -f "$1"; }     # one file in a transaction (a duplicate zone changes nothing)
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
pg_conninfo_file "$T/ci"
DUMPER="$T/karidns-dbloader"

# ---------------------------------------------------------------- the lab zone set
mkdir "$T/z" "$T/sql"; chmod 755 "$T/z" "$T/sql"
NLOAD=0; NSKIP=0
loadz() {   # loadz FILE [zone2sql options]: zone2sql, then one transaction; 0 when the zone is in the database now
    f=$1; shift
    [ -f "$f" ] || return 1
    [ "$(wc -c < "$f" | tr -d ' ')" -le 300000 ] || { NSKIP=$((NSKIP + 1)); return 1; }
    if ./tests/db/zone2sql --dialect pgsql "$@" "$f" > "$T/sql/one.sql" 2> /dev/null && pfz "$T/sql/one.sql" > /dev/null 2>&1; then NLOAD=$((NLOAD + 1)); return 0; fi
    NSKIP=$((NSKIP + 1)); return 1
}
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
EOF
    loadz "$T/z/$1.zone"
}
newdb() { pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null; }
newdb || { fail "cannot create the schema"; exit 1; }

for f in tests/zones/*.zone tests/db/tagz.test.zone; do loadz "$f" || true; done
if [ -f tests/db/tdz.test.data ]; then loadz tests/db/tdz.test.data --format tinydns || true; fi
mkzone d1.test 10 192.0.2.10; mkzone d2.test 20 192.0.2.20; mkzone d3.test 30 192.0.2.30
cat > "$T/z/alias.test.zone" <<'EOF'
$ORIGIN alias.test.
$TTL 300
@ SOA ns1 host 5 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www ALIAS target.example.test.
lua LUA A "return '192.0.2.9'"
plain A 192.0.2.10
EOF
loadz "$T/z/alias.test.zone"

# signed zones: the PowerDNS presigned layout (PRESIGNED metadata, no NSEC / NSEC3 rows), the loader rebuilds the chain
NSIGNED=0
if command -v dnssec-keygen >/dev/null 2>&1 && command -v dnssec-signzone >/dev/null 2>&1; then
    mkdir "$T/signed"
    for spec in "sg-nsec.test:" "sg-n3.test:-3 AABBCCDD -H 3" "sg-oo.test:-3 - -H 0 -A"; do
        zn=${spec%%:*}; opt=${spec#*:}
        cat > "$T/signed/$zn.zone" <<EOF
\$ORIGIN $zn.
\$TTL 300
@ IN SOA ns1 hostmaster 2026101301 3600 600 86400 300
@ IN NS ns1
@ IN MX 10 mail
ns1 IN A 192.0.2.53
mail IN A 192.0.2.25
www IN A 192.0.2.80
w2 IN CNAME www
*.wild IN A 192.0.2.100
x.y.z.ent IN A 192.0.2.110
sec IN NS ns1.sec
sec IN DS 12345 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
ns1.sec IN A 192.0.2.131
EOF
        if ( cd "$T/signed" &&
             dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$zn" > /dev/null 2>&1 &&
             dnssec-keygen -q -a ECDSAP256SHA256 "$zn" > /dev/null 2>&1 &&
             dnssec-signzone -q -S -K . $opt -o "$zn" -f "$zn.signed" "$zn.zone" > /dev/null 2>&1 ) && loadz "$T/signed/$zn.signed"; then
            NSIGNED=$((NSIGNED + 1))
        fi
    done
fi
# a zone the loader cannot read (an A record that is no address): neither server may serve it
pq "WITH d AS (INSERT INTO domains (name, type) VALUES ('bad.test', 'NATIVE') RETURNING id)
    INSERT INTO records (domain_id, name, type, content, ttl, disabled)
    SELECT d.id, v.n, v.t, v.c, 300, false FROM d, (VALUES ('bad.test', 'SOA', 'ns1.bad.test hostmaster.bad.test 1 3600 600 86400 300'), ('bad.test', 'NS', 'ns1.bad.test'),
      ('ns1.bad.test', 'A', '192.0.2.1'), ('www.bad.test', 'A', 'not-an-address')) AS v(n, t, c)" > /dev/null
# every zone may be transferred from 127.0.0.0/24 (the servers' acl-ceiling): the AXFR / IXFR comparisons below
pq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.0/24' FROM domains WHERE id NOT IN (SELECT domain_id FROM domainmetadata WHERE kind = 'ALLOW-AXFR-FROM')" > /dev/null
NZ=$(pq "SELECT count(*) FROM domains")
echo "== lab zone set: $NZ zones in the database ($NLOAD files loaded, $NSKIP not usable, $NSIGNED signed)"
[ "$NZ" -ge 8 ] && pass "at least 8 zones in the database ($NZ)" || fail "only $NZ zones were loaded"
[ -n "$(pq "SELECT 1 FROM domains WHERE name = 'tagz.test'")" ] && pass "the tags zone is in" || fail "the tags zone is missing"
[ -n "$(pq "SELECT 1 FROM domains WHERE name = 'tdz.test'")" ] && pass "the tinydns zone is in" || fail "the tinydns zone is missing"
if command -v dnssec-signzone >/dev/null 2>&1; then
    [ "$NSIGNED" -ge 3 ] && pass "3 signed zones (NSEC, NSEC3 with salt, NSEC3 Opt-Out) are in" || fail "only $NSIGNED signed zones could be loaded"
else
    echo "  [SKIP] no dnssec-signzone: the signed zones are not part of this run"
fi
pq "SELECT name FROM domains ORDER BY id" > "$T/names.txt"

# ---------------------------------------------------------------- S0: --dump from two processes
dumpcmp() {   # dumpcmp DESCRIPTION OPTIONS...: two separate loader processes, same options, same database state
    desc=$1; shift
    as_pg "$DUMPER" --dump "$DD/dump.1" --driver postgresql --conninfo-file "$T/ci" "$@" 2> "$DD/dump.1.err"; r1=$?
    as_pg "$DUMPER" --dump "$DD/dump.2" --driver postgresql --conninfo-file "$T/ci" "$@" 2> "$DD/dump.2.err"; r2=$?
    if [ "$r1" -ge 2 ] || [ "$r2" -ge 2 ]; then fail "$desc: a dump failed (exit $r1, $r2)"; head -3 "$DD/dump.1.err" | sed 's/^/         /'; return 1; fi
    if cmp -s "$DD/dump.1" "$DD/dump.2"; then pass "$desc: byte for byte the same ($(wc -c < "$DD/dump.1" | tr -d ' ') bytes)"; return 0; fi
    fail "$desc: the two streams differ ($(cmp "$DD/dump.1" "$DD/dump.2" 2>&1 | head -1))"; return 1
}
echo "== S0: karidns-dbloader --dump of one state from two processes"
dumpcmp "all zones" || true
cp "$DD/dump.1" "$DD/dump.base"
dumpcmp "--loader-threads 4" --loader-threads 4 || true
cmp -s "$DD/dump.1" "$DD/dump.base" && pass "--loader-threads 4 is the same stream as one thread" || fail "--loader-threads 4 gives another stream than one thread"
dumpcmp "--loader-threads 16" --loader-threads 16 || true
cmp -s "$DD/dump.1" "$DD/dump.base" && pass "--loader-threads 16 is the same stream as one thread" || fail "--loader-threads 16 gives another stream than one thread"
for n in 1 2 3; do
    sed -n "$((n * 3)),$((n * 3))p" "$T/names.txt" > "$T/one.name"
    zn=$(cat "$T/one.name")
    [ -n "$zn" ] && dumpcmp "--zone $zn" --zone "$zn" || true
done
# a schema of its own (a view source) with a few zones
pq "CREATE SCHEMA karidns_test_dualv" > /dev/null
{ echo "SET search_path TO karidns_test_dualv;"; cat tests/db/pdns_schema.pgsql.sql db/karidns_ext.pgsql.sql; } > "$T/sql/vschema.sql"
pfz "$T/sql/vschema.sql" > /dev/null 2>&1 && {
    ./tests/db/zone2sql --dialect pgsql "$T/z/d1.test.zone" > "$T/sql/d1.sql" 2> /dev/null
    ./tests/db/zone2sql --dialect pgsql "$T/z/alias.test.zone" > "$T/sql/al.sql" 2> /dev/null
    { echo "SET search_path TO karidns_test_dualv;"; cat "$T/sql/d1.sql" "$T/sql/al.sql"; } > "$T/sql/vz.sql"
    pfz "$T/sql/vz.sql" > /dev/null 2>&1
    dumpcmp "--schema karidns_test_dualv" --schema karidns_test_dualv || true
    dumpcmp "--schema karidns_test_dualv --loader-threads 4" --schema karidns_test_dualv --loader-threads 4 || true
} || fail "cannot create the second schema"

# ---------------------------------------------------------------- servers
conf() {   # conf FILE PORT "DATABASE-OPTIONS" SERVER-ID [EXTRA TOP-LEVEL]
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $2;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; poll-interval 2; coalesce 300; acl-ceiling { 127.0.0.0/24; }; server-id "$4"; $3 };
};
${5:-}
EOF
}
wait_log() {   # wait_log LOG PATTERN SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        grep -Eq -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
start() {   # start a|b: runs $T/NAME.conf, log $T/NAME.log
    : > "$T/$1.log"
    "$KARIDNS" -c "$T/$1.conf" -f > "$T/$1.log" 2>&1 &
    if [ "$1" = b ]; then PIDB=$!; else PIDA=$!; fi
    if wait_log "$T/$1.log" "\[DB\] initial load complete" 30; then pass "server $1: the startup batch is complete"; else fail "server $1: no 'initial load complete' line"; sed 's/^/         /' "$T/$1.log" | tail -20; fi
}
stop_both() { stop_one "$PIDA"; PIDA=""; stop_one "$PIDB"; PIDB=""; }

SRC=""
D() { p=$1; shift; ./dag @127.0.0.1 -p "$p" ${SRC:+-b $SRC} "$@" 2>/dev/null; }      # D PORT ARGS...  (ARGS: name type, options)
soa_of() { D "$1" "$2" SOA +short +nohexdump; }
axfr_of() { D "$1" "$2" AXFR +nohexdump +noall +answer; }
ixfr_of() { D "$1" "$2" "IXFR=$3" +nohexdump +noall +answer; }
serial_of() { soa_of "$1" "$2" | awk '{ print $3 }'; }
wait_serial() {   # wait_serial PORT ZONE SERIAL: bounded by $BOUND seconds
    i=0
    while [ $i -lt $((BOUND * 10)) ]; do
        [ "$(serial_of "$1" "$2")" = "$3" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
both_serial() {   # both_serial DESCRIPTION ZONE SERIAL
    if wait_serial "$PORT_A" "$2" "$3" && wait_serial "$PORT_B" "$2" "$3"; then pass "$1: both servers serve $2 at serial $3"
    else fail "$1: $2 is at serial '$(serial_of "$PORT_A" "$2")' on ns1 and '$(serial_of "$PORT_B" "$2")' on ns2, expected $3"; fi
}
NSAME=0; NAXFRRR=0
same_zone() {   # same_zone ZONE: the same SOA and the same AXFR RR sequence (in order) on both servers; returns 1 when different
    z=$1
    soa_of "$PORT_A" "$z" > "$T/s.a"; soa_of "$PORT_B" "$z" > "$T/s.b"
    axfr_of "$PORT_A" "$z" > "$T/x.a"; axfr_of "$PORT_B" "$z" > "$T/x.b"
    if ! cmp -s "$T/s.a" "$T/s.b"; then fail "$z${SRC:+ (from $SRC)}: SOA differs: '$(cat "$T/s.a")' / '$(cat "$T/s.b")'"; return 1; fi
    if ! cmp -s "$T/x.a" "$T/x.b"; then
        fail "$z${SRC:+ (from $SRC)}: the AXFR differs ($(wc -l < "$T/x.a" | tr -d ' ') / $(wc -l < "$T/x.b" | tr -d ' ') RRs)"; diff "$T/x.a" "$T/x.b" | head -6 | sed 's/^/         /'; return 1
    fi
    NSAME=$((NSAME + 1)); NAXFRRR=$((NAXFRRR + $(wc -l < "$T/x.a" | tr -d ' ')))
    return 0
}
all_same() {   # all_same DESCRIPTION: every zone of the database
    bad=0; cnt=0; empty=0
    while read -r z; do
        [ -n "$z" ] || continue
        same_zone "$z" || bad=$((bad + 1))
        cnt=$((cnt + 1))
        [ "$(wc -l < "$T/x.a" | tr -d ' ')" -ge 2 ] || empty=$((empty + 1))
    done < "$T/names.txt"
    [ "$bad" -eq 0 ] && pass "$1: $cnt zones, the same SOA and the same AXFR RR sequence ($((cnt - empty)) zones with data, $empty refused or failed alike)" || fail "$1: $bad of $cnt zones differ"
    [ "$((cnt - empty))" -ge 8 ] && pass "$1: at least 8 zones were served ($((cnt - empty)))" || fail "$1: only $((cnt - empty)) zones were served"
}
qsame() {   # qsame DESCRIPTION NAME TYPE [OPTION]: the answer and authority sections are the same on both servers
    D "$PORT_A" "$2" "$3" ${4:-+nohexdump} +nohexdump +noall +answer +authority > "$T/q.a"
    D "$PORT_B" "$2" "$3" ${4:-+nohexdump} +nohexdump +noall +answer +authority > "$T/q.b"
    cmp -s "$T/q.a" "$T/q.b" && pass "$1 ($(wc -l < "$T/q.a" | tr -d ' ') RRs)" || { fail "$1: the answers differ"; diff "$T/q.a" "$T/q.b" | head -4 | sed 's/^/         /'; }
}
bump() {   # bump ZONE SERIAL: the serial of the SOA row
    pq "UPDATE records SET content = regexp_replace(content, '^([^ ]+ +[^ ]+ +)[0-9]+', '\1' || '$2') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = '$1')" > /dev/null
}
setaddr() { pq "UPDATE records SET content = '$2' WHERE name = 'www.$1' AND type = 'A'" > /dev/null; }
request() { pq "INSERT INTO karidns_reload_requests DEFAULT VALUES" > /dev/null; }
zsql() {   # zsql ZONE SERIAL ADDRESS: the SQL that sets www.ZONE and the serial (a heredoc: the echo of dash takes a backslash-1 for an escape)
    cat <<EOF
UPDATE records SET content = '$3' WHERE name = 'www.$1' AND type = 'A'; UPDATE records SET content = regexp_replace(content, '^([^ ]+ +[^ ]+ +)[0-9]+', '\1' || '$2') WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = '$1');
EOF
}

# ================================================================ S1
echo "== S1: two primaries, no auto-reload"
conf "$T/a.conf" "$PORT_A" '' ns1
conf "$T/b.conf" "$PORT_B" '' ns2
start a; start b
all_same "S1 start"
[ -z "$(soa_of "$PORT_A" bad.test)" ] && [ -z "$(soa_of "$PORT_B" bad.test)" ] && pass "bad.test (a row the loader cannot read) is served by neither server" || fail "bad.test is served by a server"
qsame "ALIAS name A (no alias-resolver): the same answer" www.alias.test A
qsame "ALIAS name ANY: the same answer" www.alias.test ANY
qsame "LUA name TXT: LUA records are never run, the same answer" lua.alias.test TXT
qsame "LUA name A" lua.alias.test A
qsame "plain A at the ALIAS zone" plain.alias.test A
qsame "www.example.com A" www.example.com A
qsame "tdz.test www A (tinydns)" www.tdz.test A
qsame "tdz.test countdown name" cd.tdz.test A
if [ "$NSIGNED" -ge 3 ]; then
    qsame "signed NSEC zone: DNSKEY with DO" sg-nsec.test DNSKEY +dnssec
    qsame "signed NSEC3 zone: NXDOMAIN with DO" nope.sg-n3.test A +dnssec
    qsame "signed Opt-Out zone: NXDOMAIN with DO" nope.sg-oo.test A +dnssec
fi
if [ "$ALIASES" = 1 ]; then
    for s in 127.0.0.2 127.0.0.3; do
        SRC=$s
        for z in tagz.test tdz.test; do
            same_zone "$z" && pass "$z seen from $s: the same SOA and AXFR on both servers ($(wc -l < "$T/x.a" | tr -d ' ') RRs)"
        done
        qsame "tdz.test www A from $s" www.tdz.test A
    done
    SRC=""
    SRC=127.0.0.2; axfr_of "$PORT_A" tdz.test > "$T/loc2.txt"; SRC=127.0.0.3; axfr_of "$PORT_A" tdz.test > "$T/loc3.txt"; SRC=""
    cmp -s "$T/loc2.txt" "$T/loc3.txt" && fail "the tinydns zone looks the same from two addresses (the per-address check proves nothing)" || pass "the tinydns zone differs by client address (the per-address checks are meaningful)"
else
    echo "  [SKIP] no loopback aliases 127.0.0.2/3: the per-address checks are not run"
fi

echo "== S1: dumps while the servers run"
dumpcmp "all zones (servers up)" || true
cmp -s "$DD/dump.1" "$DD/dump.base" && pass "the stream is the one of before the servers started" || fail "the stream changed although the data did not"

echo "== S1: an edit and a reload request: both converge"
setaddr d1.test 192.0.2.11; bump d1.test 11
sleep 2
[ "$(serial_of "$PORT_A" d1.test)" = 10 ] && [ "$(serial_of "$PORT_B" d1.test)" = 10 ] && pass "no request, no auto-reload: both still serve serial 10" || fail "an edit without a request was served"
request
both_serial "request 1" d1.test 11
same_zone d1.test && pass "d1.test: the same AXFR after the first request" || true
setaddr d1.test 192.0.2.12; bump d1.test 12; setaddr d2.test 192.0.2.22; bump d2.test 21
request
both_serial "request 2" d1.test 12
both_serial "request 2" d2.test 21
all_same "S1 after two requests"
qsame "the new address" www.d1.test A

echo "== S1: IXFR from a version both servers hold (history 10>11>12 on both)"
for f in 10 11; do
    ixfr_of "$PORT_A" d1.test $f > "$T/i.a"; ixfr_of "$PORT_B" d1.test $f > "$T/i.b"
    axfr_of "$PORT_A" d1.test > "$T/x.a"
    if cmp -s "$T/i.a" "$T/i.b" && [ "$(wc -l < "$T/i.a" | tr -d ' ')" -ge 4 ]; then pass "IXFR from $f: the same $(wc -l < "$T/i.a" | tr -d ' ') RRs on both servers"
    else fail "IXFR from $f differs or is empty ($(wc -l < "$T/i.a" | tr -d ' ') / $(wc -l < "$T/i.b" | tr -d ' ') RRs)"; diff "$T/i.a" "$T/i.b" | head -6 | sed 's/^/         /'; fi
    if ! cmp -s "$T/i.a" "$T/x.a" && [ "$(sed -n 2p "$T/i.a" | awk '{ print $4 }')" = SOA ] && [ "$(sed -n 2p "$T/i.a" | awk '{ print $7 }')" = "$f" ]; then
        pass "IXFR from $f is incremental (current SOA, then the SOA of $f, RFC 1995 s4)"
    else fail "IXFR from $f is not an incremental answer"; head -3 "$T/i.a" | sed 's/^/         /'; fi
done
ixfr_of "$PORT_A" d1.test 12 > "$T/i.a"; ixfr_of "$PORT_B" d1.test 12 > "$T/i.b"
cmp -s "$T/i.a" "$T/i.b" && [ "$(wc -l < "$T/i.a" | tr -d ' ')" -eq 1 ] && pass "IXFR from the current serial: the same single SOA (RFC 1995 s2)" || fail "IXFR from the current serial: '$(cat "$T/i.a")' / '$(cat "$T/i.b")'"
ixfr_of "$PORT_A" d1.test 5 > "$T/i.a"; ixfr_of "$PORT_B" d1.test 5 > "$T/i.b"; axfr_of "$PORT_A" d1.test > "$T/x.a"
cmp -s "$T/i.a" "$T/i.b" && cmp -s "$T/i.a" "$T/x.a" && pass "IXFR from a serial older than any history: the whole zone, the same as the AXFR, on both (RFC 1995 s4)" || { fail "IXFR from serial 5 is not the whole zone on both"; head -3 "$T/i.a" | sed 's/^/         /'; }
ixfr_of "$PORT_A" d2.test 20 > "$T/i.a"; ixfr_of "$PORT_B" d2.test 20 > "$T/i.b"
cmp -s "$T/i.a" "$T/i.b" && [ "$(wc -l < "$T/i.a" | tr -d ' ')" -ge 4 ] && pass "d2.test: IXFR from 20 is the same on both" || fail "d2.test: IXFR from 20 differs"

echo "== S1: ns2 is down for two versions and restarts without a history"
stop_one "$PIDB"; PIDB=""
setaddr d1.test 192.0.2.13; bump d1.test 13; request
wait_serial "$PORT_A" d1.test 13 && pass "ns1 serves serial 13" || fail "ns1 did not apply request 3"
setaddr d1.test 192.0.2.14; bump d1.test 14; request
wait_serial "$PORT_A" d1.test 14 && pass "ns1 serves serial 14" || fail "ns1 did not apply request 4"
start b
both_serial "ns2 restarted" d1.test 14
all_same "S1 after the restart of ns2"
ixfr_of "$PORT_A" d1.test 12 > "$T/i.a"; ixfr_of "$PORT_B" d1.test 12 > "$T/i.b"
axfr_of "$PORT_A" d1.test > "$T/x.a"; axfr_of "$PORT_B" d1.test > "$T/x.b"
if [ "$(sed -n 2p "$T/i.a" | awk '{ print $4 }')" = SOA ] && [ "$(sed -n 2p "$T/i.a" | awk '{ print $7 }')" = 12 ] && ! cmp -s "$T/i.a" "$T/x.a"; then
    pass "ns1 holds serial 12: its IXFR from 12 is incremental ($(wc -l < "$T/i.a" | tr -d ' ') RRs, 12>13>14)"
else fail "ns1: IXFR from 12 is not incremental"; head -3 "$T/i.a" | sed 's/^/         /'; fi
if cmp -s "$T/i.b" "$T/x.b" && [ "$(wc -l < "$T/i.b" | tr -d ' ')" -ge 5 ]; then
    pass "ns2 does not hold serial 12: its IXFR from 12 is the whole zone, AXFR style ($(wc -l < "$T/i.b" | tr -d ' ') RRs, RFC 1995 s4)"
else fail "ns2: IXFR from 12 is not the whole zone"; head -3 "$T/i.b" | sed 's/^/         /'; fi
cmp -s "$T/x.a" "$T/x.b" && pass "the whole zone ns2 sends is the AXFR of ns1 (the same serial 14 RR sequence)" || fail "the AXFR of the two servers differs at serial 14"
setaddr d1.test 192.0.2.15; bump d1.test 15; request
both_serial "request 5" d1.test 15
ixfr_of "$PORT_A" d1.test 14 > "$T/i.a"; ixfr_of "$PORT_B" d1.test 14 > "$T/i.b"
if cmp -s "$T/i.a" "$T/i.b" && [ "$(sed -n 2p "$T/i.a" | awk '{ print $7 }')" = 14 ] && [ "$(wc -l < "$T/i.a" | tr -d ' ')" -ge 4 ]; then
    pass "the pair 14>15 is in both histories: the same incremental IXFR ($(wc -l < "$T/i.a" | tr -d ' ') RRs), although ns1 keeps more versions"
else fail "IXFR from 14 differs"; diff "$T/i.a" "$T/i.b" | head -6 | sed 's/^/         /'; fi
ixfr_of "$PORT_A" d1.test 13 > "$T/i.a"; ixfr_of "$PORT_B" d1.test 13 > "$T/i.b"; axfr_of "$PORT_B" d1.test > "$T/x.b"
if [ "$(sed -n 2p "$T/i.a" | awk '{ print $4 }')" = SOA ] && [ "$(sed -n 2p "$T/i.a" | awk '{ print $7 }')" = 13 ] && cmp -s "$T/i.b" "$T/x.b"; then
    pass "from 13 (only ns1 holds it): ns1 answers 13>14>15, ns2 the whole zone"
else fail "IXFR from 13 is not as documented (ns1 incremental, ns2 whole zone)"; fi
all_same "S1 at the end"
for n in a b; do
    grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/$n.log" && fail "server $n: sanitizer report" || true
done
stop_both

# ================================================================ S2
echo "== S2: auto-reload yes on both (ns2 with ingest-threads 4 and loader-threads 4, ns1 with one of each)"
conf "$T/a.conf" "$PORT_A" 'auto-reload yes;' ns1
conf "$T/b.conf" "$PORT_B" 'auto-reload yes; ingest-threads 4; loader-threads 4;' ns2
start a; start b
all_same "S2 start"
setaddr d2.test 192.0.2.23; bump d2.test 22
both_serial "auto-reload" d2.test 22
same_zone d2.test && pass "d2.test: the same AXFR after the automatic reload" || true
ixfr_of "$PORT_A" d2.test 21 > "$T/i.a"; ixfr_of "$PORT_B" d2.test 21 > "$T/i.b"
if cmp -s "$T/i.a" "$T/i.b" && [ "$(sed -n 2p "$T/i.a" | awk '{ print $7 }')" = 21 ]; then pass "the pair 21>22 (both servers reloaded it automatically): the same incremental IXFR"
else fail "IXFR from 21 after an automatic reload"; diff "$T/i.a" "$T/i.b" | head -4 | sed 's/^/         /'; fi
# three zones in ONE commit: one reload of three zones, read one query each (below bulk-threshold); with loader-threads 4 on ns2 they are
# read by its worker threads, whose connections must know the optional tables of the source too (B11b: they did not, and ns2 never
# applied such a reload: "the ... tables do not exist in this database")
pq "$(zsql d1.test 16 192.0.2.26) $(zsql d2.test 23 192.0.2.24) $(zsql d3.test 31 192.0.2.34)" > /dev/null
both_serial "three zones in one commit" d1.test 16
both_serial "three zones in one commit" d2.test 23
both_serial "three zones in one commit" d3.test 31
grep -q "tables do not exist in this database" "$T/a.log" "$T/b.log" && fail "a loader could not read the extension tables" || pass "no loader complained about missing extension tables"
all_same "S2 after the commit of three zones"
setaddr d2.test 192.0.2.25; bump d2.test 24
setaddr d2.test 192.0.2.27; bump d2.test 25
both_serial "two commits in a row" d2.test 25
all_same "S2 after two commits in a row (the intermediate versions may differ per server, the final state does not)"
qsame "the final address" www.d2.test A
stop_both

# ================================================================ S3
if [ "$ALIASES" = 1 ]; then
    echo "== S3: two views on one database (karidns_domain_views)"
    pq "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'internal' FROM domains WHERE name IN ('d1.test', 'tagz.test')" > /dev/null
    pq "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'external' FROM domains WHERE name IN ('d2.test', 'tagz.test', 'tdz.test')" > /dev/null
    dumpcmp "--map-view internal" --map-view internal || true
    cp "$DD/dump.1" "$DD/dump.int"
    dumpcmp "--map-view external" --map-view external || true
    cmp -s "$DD/dump.int" "$DD/dump.1" && fail "the two views have the same stream (the view mapping proves nothing)" || pass "the streams of the two views differ"
    dumpcmp "--map-view external --loader-threads 4" --map-view external --loader-threads 4 || true
    VIEWS='view "internal" { match-clients { 127.0.0.2; }; };
view "external" { match-clients { 127.0.0.3; }; };'
    conf "$T/a.conf" "$PORT_A" '' ns1 "$VIEWS"
    conf "$T/b.conf" "$PORT_B" '' ns2 "$VIEWS"
    start a; start b
    for s in 127.0.0.2 127.0.0.3; do
        SRC=$s; bad=0; served=0
        while read -r z; do
            [ -n "$z" ] || continue
            same_zone "$z" || bad=$((bad + 1))
            [ "$(wc -l < "$T/x.a" | tr -d ' ')" -ge 2 ] && served=$((served + 1))
        done < "$T/names.txt"
        [ "$bad" -eq 0 ] && pass "view of $s: the same SOA and AXFR for every zone on both servers ($served zones served)" || fail "view of $s: $bad zones differ"
        [ "$served" -ge 5 ] && pass "view of $s: at least 5 zones served ($served)" || fail "view of $s: only $served zones served"
    done
    SRC=127.0.0.2; [ -n "$(soa_of "$PORT_A" d2.test)" ] && fail "d2.test is served in the internal view" || pass "d2.test is not served in the internal view (on ns1)"
    [ -n "$(soa_of "$PORT_B" d2.test)" ] && fail "d2.test is served in the internal view (ns2)" || pass "d2.test is not served in the internal view (on ns2)"
    SRC=""
    setaddr d1.test 192.0.2.27; bump d1.test 17; request
    SRC=127.0.0.2
    both_serial "request in a view setup" d1.test 17
    same_zone d1.test && pass "d1.test: the same AXFR in the internal view after the request" || true
    SRC=""
    stop_both
else
    echo "== S3: [SKIP] no loopback aliases 127.0.0.2/3"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_dual_primary_test: all $PASS checks passed ($NSAME zone comparisons, $NAXFRRR AXFR RRs compared) ==="; exit 0; fi
echo "=== run_db_dual_primary_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
