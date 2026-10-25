#!/bin/sh
# run_db_secondary_test.sh - SLAVE and CONSUMER zones of a PowerDNS database (beta design 3.2, 3.5, 4.2; milestone B7b).
#
# Two ordinary KariDNS primaries serve zone files (P1 on port PM1, P2 on PM2).  The server under test S has no zone file of
# its own: its zones come from a SQLite3 database (tests/db/pdns_schema.sqlite3.sql + db/karidns_ext.sqlite3.sql) whose
# domains.type is SLAVE (secondary zones; masters from domains.master, key from the AXFR-MASTER-TSIG metadata), CONSUMER (a
# catalog consumer) or NATIVE.  The loader sends the SLAVE / CONSUMER zones as ZONE_BEGIN without data (rr_count 0) and
# the Backend's secondary machinery transfers them from the masters.  Checked:
#   - the initial AXFR (with and without TSIG), the zones answer as the primary does, `karictl dbstatus <zone>` shows the
#     masters, the key and the transfer, an AXFR out of S (metadata ALLOW-AXFR-FROM + acl-ceiling) equals the primary's;
#   - NOTIFY from the master -> IXFR (the SOA refresh is an hour, so only the NOTIFY can be the reason), `karictl retransfer`;
#   - a key that karidns.conf does not define, a missing master, a host name as master, a PRODUCER zone: the zone is rejected
#     (dbstatus says why), the others are not affected;
#   - a master changed in the database re-points the zone (karictl reload <zone>); a SLAVE that becomes NATIVE and back;
#   - a restarted loader (kill -9) causes no transfer: the zones keep their data and counters, the new batch sends nothing;
#   - a row deleted from the database removes the zone;
#   - CONSUMER: the members of the catalog appear (and win over a database zone of the same name, D17-1), a member the catalog
#     drops disappears, and when the consumer's row is deleted its members go and the hidden database zone is served again;
#   - the data of a SLAVE lives in memory only: a restarted server transfers it again.
#
# Needs root (the loader must be root-owned and runs as nobody).  SKIP otherwise, and when karidns, dag, karictl, karidns-dbloader
# (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.  KARIDNS=./karidns-asan runs it on the ASan build.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbsec.XXXXXX") || exit 1
chmod 755 "$T"
P1=""; P2=""; SRV=""
cleanup() {
    for p in $SRV $P1 $P2; do kill -TERM "$p" 2>/dev/null; done
    # wait for each manager (it stops its children first; a sanitizer build is slow): a KILL too early orphans them
    for p in $SRV $P1 $P2; do
        i=0; while [ $i -lt 100 ] && kill -0 "$p" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
        kill -KILL "$p" 2>/dev/null
    done
    if [ -n "${KARI_KEEP:-}" ]; then echo "kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
BASE=$((20000 + $$ % 20000))
PM1=$BASE; PM2=$((BASE + 1)); PS=$((BASE + 2))
DAG="./dag @127.0.0.1 -p $PS"
DAG1="./dag @127.0.0.1 -p $PM1"
S_CTL="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
S_XFR="eGZyLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc="

# ---------------------------------------------------------------- fixtures
mkdir "$T/db" "$T/z"
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS [extra lines]   -> the zone file text on stdout (refresh one hour: only NOTIFY is fast)
    cat <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
${4:-}
EOF
}
# P1: the zones S transfers
mkzone slv.test 10 192.0.2.10 > "$T/z/slv.zone"
mkzone plain.test 10 192.0.2.11 > "$T/z/plain.zone"
mkzone recon.test 10 192.0.2.31 > "$T/z/recon.zone"
mkzone del.test 10 192.0.2.12 > "$T/z/del.zone"
mkzone flip.test 20 192.0.2.51 > "$T/z/flip.zone"
mkzone m1.test 1 192.0.2.41 > "$T/z/m1.zone"
mkzone m2.test 1 192.0.2.42 > "$T/z/m2.zone"
mkzone m3.test 1 192.0.2.43 > "$T/z/m3.zone"
mkzone m4.test 1 192.0.2.44 > "$T/z/m4.zone"
catalog() {   # catalog SERIAL MEMBER...   (uid1 -> first member, ...)
    s=$1; shift
    printf '$ORIGIN cat.test.\n$TTL 300\n@ SOA ns1.cat.test. hostmaster.cat.test. %s 3600 600 86400 60\n@ NS invalid.\nversion TXT "2"\n' "$s"
    n=1
    for m in "$@"; do printf 'uid%s.zones PTR %s.\n' "$n" "$m"; n=$((n + 1)); done
}
catalog 1 m1.test m2.test m3.test > "$T/z/cat.zone"
# P2: the same name as recon.test with another address and a newer serial
mkzone recon.test 20 192.0.2.32 > "$T/z/recon2.zone"
# the primary zone of S's database that the catalog member m3.test will hide (D17-1), and flip.test as a primary
mkzone m3.test 7 192.0.2.99 > "$T/z/m3db.zone"
mkzone flip.test 5 192.0.2.50 > "$T/z/flipdb.zone"

cat > "$T/p1.conf" <<EOF
options { user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PM1; };
key "xfr" { algorithm hmac-sha256; secret "$S_XFR"; };
control-channel { socket "$T/p1.sock"; secret "$S_CTL"; };
zone "slv.test" { type primary; file "$T/z/slv.zone"; tsig-key "xfr"; allow-transfer { key "xfr"; }; allow-update { 127.0.0.1; };
                  also-notify { 127.0.0.1 port $PS; }; notify-retry-interval 1; };
zone "plain.test" { type primary; file "$T/z/plain.zone"; allow-transfer { 127.0.0.1; }; };
zone "recon.test" { type primary; file "$T/z/recon.zone"; allow-transfer { 127.0.0.1; }; };
zone "del.test" { type primary; file "$T/z/del.zone"; allow-transfer { 127.0.0.1; }; };
zone "flip.test" { type primary; file "$T/z/flip.zone"; allow-transfer { 127.0.0.1; }; };
zone "m1.test" { type primary; file "$T/z/m1.zone"; allow-transfer { 127.0.0.1; }; };
zone "m2.test" { type primary; file "$T/z/m2.zone"; allow-transfer { 127.0.0.1; }; };
zone "m3.test" { type primary; file "$T/z/m3.zone"; allow-transfer { 127.0.0.1; }; };
zone "m4.test" { type primary; file "$T/z/m4.zone"; allow-transfer { 127.0.0.1; }; };
zone "cat.test" { type primary; file "$T/z/cat.zone"; allow-transfer { 127.0.0.1; }; also-notify { 127.0.0.1 port $PS; }; notify-retry-interval 1; };
EOF
cat > "$T/p2.conf" <<EOF
options { user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PM2; };
zone "recon.test" { type primary; file "$T/z/recon2.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$T/p1ctl.conf" <<EOF
socket "$T/p1.sock";
key "karictl" { algorithm hmac-sha256; secret "$S_CTL"; };
EOF
chmod 600 "$T/p1ctl.conf"

# the database
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
sq() { sqlite3 "$T/db/z.db" "$@"; }
meta() {   # meta ZONE KIND CONTENT
    sq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, '$2', '$3' FROM domains WHERE name = '$1'"
}
slave() {   # slave NAME MASTER
    sq "INSERT INTO domains (name, master, type) VALUES ('$1', $( [ "$2" = NULL ] && echo NULL || echo "'$2'" ), 'SLAVE')"
}
slave slv.test "127.0.0.1:$PM1";   meta slv.test AXFR-MASTER-TSIG xfr;  meta slv.test ALLOW-AXFR-FROM 127.0.0.1
slave plain.test "127.0.0.1:$PM1"; meta plain.test ALLOW-AXFR-FROM 127.0.0.1
slave recon.test "127.0.0.1:$PM1"
slave del.test "127.0.0.1:$PM1"
slave nokey.test "127.0.0.1:$PM1"; meta nokey.test AXFR-MASTER-TSIG ghost
slave nomaster.test NULL
slave dead.test "127.0.0.1:1"
slave hostm.test "ns1.example.net"
sq "INSERT INTO domains (name, master, type) VALUES ('cat.test', '127.0.0.1:$PM1', 'CONSUMER')"
sq "INSERT INTO domains (name, type) VALUES ('prod.test', 'PRODUCER')"
# zone2sql names the zone by its $ORIGIN: m3.test and flip.test (NATIVE)
for z in m3db flipdb; do ./tests/db/zone2sql --dialect sqlite3 "$T/z/$z.zone" 2>/dev/null | sq; done
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$S_CTL"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
KCTL1="./karictl -c $T/p1ctl.conf"

write_sconf() {   # write_sconf FILE: the server under test
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PS;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 4;
               acl-ceiling { 127.0.0.1; }; };
};
key "xfr" { algorithm hmac-sha256; secret "$S_XFR"; };
control-channel { socket "$T/ctl.sock"; secret "$S_CTL"; };
EOF
}

wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
ans() { $DAG "$@" +short +nohexdump 2>/dev/null; }
wait_ans() {   # wait_ans EXPECTED QNAME QTYPE [SECONDS]: S answers EXPECTED within SECONDS (default 15)
    i=0; max=$(( ${4:-15} * 10 ))
    while [ $i -lt $max ]; do
        [ "$(ans "$2" "$3")" = "$1" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
rcode() { $DAG "$1" SOA +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
wait_rcode() {   # wait_rcode WANT ZONE [SECONDS]
    i=0; max=$(( ${3:-15} * 10 ))
    while [ $i -lt $max ]; do
        [ "$(rcode "$2")" = "$1" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
dbst() { $KCTL dbstatus "$@" 2>&1; }
transfers() { $KCTL observatory "$1" 2>/dev/null | sed -n 's/.*Transfers (In): *\(AXFR=[0-9]* IXFR=[0-9]*\).*/\1/p'; }
loader_pid() { pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1; }

# ================================================================ start
echo "== start"
"$KARIDNS" -c "$T/p1.conf" -f > "$T/p1.log" 2>&1 &
P1=$!
"$KARIDNS" -c "$T/p2.conf" -f > "$T/p2.log" 2>&1 &
P2=$!
sleep 1
write_sconf "$T/s.conf"
"$KARIDNS" -c "$T/s.conf" -f > "$T/s.log" 2>&1 &
SRV=$!
if wait_log "$T/s.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$T/s.log" | tail -20; fi
./karicheck conf "$T/s.conf" > "$T/kc.out" 2>&1 && pass "karicheck conf accepts the configuration" || { fail "karicheck conf"; sed 's/^/         /' "$T/kc.out" | tail -5; }

# ================================================================ initial transfers
echo "== initial AXFR"
wait_ans 192.0.2.10 www.slv.test A && pass "slv.test (TSIG key xfr): transferred from P1, www answers" || { fail "slv.test does not answer"; grep -E "slv.test|AXFR|TSIG" "$T/s.log" | tail -5 | sed 's/^/         /'; }
wait_ans 192.0.2.11 www.plain.test A && pass "plain.test (no key): transferred" || fail "plain.test does not answer"
wait_ans 192.0.2.31 www.recon.test A && pass "recon.test: transferred from P1" || fail "recon.test does not answer"
wait_ans 192.0.2.12 www.del.test A && pass "del.test: transferred" || fail "del.test does not answer"
for z in slv plain; do
    a=$(ans "$z.test" SOA); b=$($DAG1 "$z.test" SOA +short +nohexdump 2>/dev/null)
    [ -n "$a" ] && [ "$a" = "$b" ] && pass "$z.test: S and P1 answer the same SOA" || fail "$z.test: SOA differs between S and P1 ($a / $b)"
done
OUT=$(dbst slv.test)
printf '%s\n' "$OUT" | grep -q "^zone slv.test.* serial 10, status applied" && pass "dbstatus: slv.test applied, the transferred serial 10" || { fail "dbstatus slv.test status"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
printf '%s\n' "$OUT" | grep -q "type: secondary (SLAVE), masters 127.0.0.1 port $PM1, TSIG key 'xfr'" && pass "dbstatus: type, master and key" || fail "dbstatus: no 'type: secondary (SLAVE), masters ...' line"
printf '%s\n' "$OUT" | grep -q "transfer: last successful .*serial 10 (kept in memory only" && pass "dbstatus: the last transfer" || fail "dbstatus: no transfer line"
[ "$(transfers slv.test)" = "AXFR=1 IXFR=0" ] && pass "slv.test: one AXFR so far (observatory)" || fail "slv.test transfers: '$(transfers slv.test)'"
# AXFR out of S: the metadata (ALLOW-AXFR-FROM 127.0.0.1) and acl-ceiling let this client in; the RRs are the primary's
./dag @127.0.0.1 -p $PS slv.test AXFR +nohexdump +noall +answer 2>/dev/null | sort > "$T/axfr.s"
$DAG1 slv.test AXFR +nohexdump +noall +answer -y "hmac-sha256:xfr:$S_XFR" 2>/dev/null | grep -v "TSIG" | sort > "$T/axfr.p"
[ -s "$T/axfr.s" ] && cmp -s "$T/axfr.s" "$T/axfr.p" && pass "AXFR out of the database secondary = AXFR of the primary ($(wc -l < "$T/axfr.p" | tr -d ' ') RRs)" || { fail "AXFR out of S differs from P1's"; diff "$T/axfr.s" "$T/axfr.p" | head -5; }

# B8t-2: the settings P1 sends with the zone (Extended AXFR version 3) reach a database secondary; the statements of its own row win
OUT=$($KCTL zonestatus recon.test 2>&1)
printf '%s\n' "$OUT" | grep -q 'settings=primary' && pass "recon.test: zonestatus says that the settings of the primary are in force" || { fail "recon.test: no settings=primary"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
OUT=$(dbst recon.test)
printf '%s\n' "$OUT" | grep -q 'settings from the primary: in force' && pass "recon.test: dbstatus says that settings of the primary are in force" || { fail "recon.test: dbstatus has no 'settings from the primary' line"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
if command -v perl >/dev/null 2>&1; then
    perl tests/lib_axfr_probe.pl 127.0.0.1 "$PS" 127.0.0.1 recon.test AXFR 2>&1 | grep -q 'rcode=0 aa=1' \
        && pass "recon.test: the allow-transfer P1 sent applies (inside acl-ceiling), the row of S has none" || fail "recon.test: the received allow-transfer is not applied"
fi

# ================================================================ rejected zones
echo "== rejected zones"
for case in "nokey.test:TSIG key 'ghost'" "nomaster.test:domains.master is NULL" "hostm.test:host names are not supported" "prod.test:PRODUCER"; do
    z=${case%%:*}; why=${case#*:}
    OUT=$(dbst "$z")
    if printf '%s\n' "$OUT" | grep -q "status rejected (no version loaded), last error: .*$why"; then pass "$z: rejected, dbstatus says '$why'"
    else fail "$z: dbstatus"; printf '%s\n' "$OUT" | sed 's/^/         /'; fi
    [ "$(rcode "$z")" = REFUSED ] && pass "$z: not served (REFUSED)" || fail "$z: answers"
done
[ "$(ans www.slv.test A)" = "192.0.2.10" ] && pass "the other zones are not affected" || fail "slv.test lost"
# A secondary that has not transferred yet (its master does not answer) is registered but empty: SERVFAIL with EDE 14 (RFC 8914 4.15).
# dag +short prints the EDE text for it, so a script that waits for "any output" would think the zone is there; only an SOA record is
# the proof (the signed-zone tests wait for exactly that: with a slow server their first queries used to hit the empty zone).
[ "$(rcode dead.test)" = SERVFAIL ] && pass "dead.test (master refuses connections): registered, SERVFAIL until the first transfer" || fail "dead.test: $(rcode dead.test)"
ans dead.test SOA | grep -Eq "( [0-9]+){5}$" && fail "dead.test answers an SOA record" || pass "dead.test: no SOA record (whatever +short prints)"
dbst dead.test | grep -q "transfer: no transfer has succeeded yet" && pass "dbstatus: no transfer has succeeded yet" || fail "dbstatus dead.test"

# ================================================================ NOTIFY -> IXFR
echo "== NOTIFY and IXFR"
before=$(transfers slv.test)
$DAG1 slv.test A --update-add "new.slv.test 300 IN A 192.0.2.77" +nohexdump > /dev/null 2>&1
if wait_ans 192.0.2.77 new.slv.test A 12; then pass "the UPDATE on P1 reached S within a few seconds (the SOA refresh is an hour: NOTIFY)"; else fail "new.slv.test did not arrive"; grep -E "NOTIFY|slv.test" "$T/s.log" | tail -5 | sed 's/^/         /'; fi
after=$(transfers slv.test)
if [ "$before" = "AXFR=1 IXFR=0" ] && [ "$after" = "AXFR=1 IXFR=1" ]; then pass "it came as IXFR ($before -> $after)"; else fail "transfers $before -> $after (want AXFR=1 IXFR=0 -> AXFR=1 IXFR=1)"; fi
OUT=$(dbst slv.test)
printf '%s\n' "$OUT" | grep -q "serial 1[1-9], status applied" && pass "dbstatus shows the new serial 11" || fail "dbstatus after the IXFR"

echo "== karictl retransfer"
$KCTL retransfer slv.test 2>&1 | grep -q "^OK" && pass "karictl retransfer slv.test is accepted" || fail "karictl retransfer slv.test"
i=0; while [ $i -lt 100 ] && [ "$(transfers slv.test)" != "AXFR=2 IXFR=1" ]; do sleep 0.1; i=$((i + 1)); done
[ "$(transfers slv.test)" = "AXFR=2 IXFR=1" ] && pass "slv.test was transferred again (AXFR=2)" || fail "retransfer: '$(transfers slv.test)'"
$KCTL retransfer flip.test 2>&1 | grep -q "primary zone" && pass "karictl retransfer of a database primary zone says it is one" || fail "karictl retransfer flip.test (NATIVE)"

# ================================================================ master change, type change
echo "== master change"
[ "$(ans www.recon.test A)" = "192.0.2.31" ] && pass "recon.test comes from P1" || fail "recon.test before the change"
sq "UPDATE domains SET master = '127.0.0.1:$PM2' WHERE name = 'recon.test'"
sq "UPDATE domains SET master = '127.0.0.1:$PM1, 127.0.0.1:$PM2' WHERE name = 'plain.test'"
meta plain.test AXFR-MASTER-TSIG xfr
OUT=$($KCTL reload recon.test 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "karictl reload recon.test: $OUT" || { fail "karictl reload recon.test: $OUT"; }
if wait_ans 192.0.2.32 www.recon.test A 15; then pass "recon.test is transferred from P2 now (www 192.0.2.32)"; else fail "recon.test still has the old data"; grep recon "$T/s.log" | tail -4 | sed 's/^/         /'; fi
dbst recon.test | grep -q "masters 127.0.0.1 port $PM2" && pass "dbstatus shows the new master" || fail "dbstatus after the master change"
$KCTL reload plain.test > /dev/null 2>&1
i=0; while [ $i -lt 50 ]; do dbst plain.test | grep -q "masters 127.0.0.1 port $PM1, 127.0.0.1 port $PM2, TSIG key 'xfr'" && break; sleep 0.1; i=$((i + 1)); done
dbst plain.test | grep -q "masters 127.0.0.1 port $PM1, 127.0.0.1 port $PM2, TSIG key 'xfr'" && pass "a list of masters and a new key are taken over (plain.test)" || { fail "plain.test settings after the edit"; dbst plain.test | sed 's/^/         /'; }
[ "$(ans www.plain.test A)" = "192.0.2.11" ] && pass "plain.test keeps answering" || fail "plain.test lost its data"

echo "== SLAVE <-> NATIVE"
[ "$(ans www.flip.test A)" = "192.0.2.50" ] && pass "flip.test is a database primary (www 192.0.2.50)" || fail "flip.test as a primary"
sq "UPDATE domains SET type = 'SLAVE', master = '127.0.0.1:$PM1' WHERE name = 'flip.test'"
$KCTL reload flip.test > /dev/null 2>&1
wait_ans 192.0.2.51 www.flip.test A 15 && pass "flip.test became a SLAVE: transferred from P1 (www 192.0.2.51)" || { fail "flip.test as a SLAVE"; dbst flip.test | sed 's/^/         /'; }
dbst flip.test | grep -q "type: secondary (SLAVE)" && pass "dbstatus: flip.test is a secondary" || fail "dbstatus flip.test"
sq "UPDATE domains SET type = 'NATIVE', master = NULL WHERE name = 'flip.test'"
$KCTL reload flip.test > /dev/null 2>&1
wait_ans 192.0.2.50 www.flip.test A 15 && pass "flip.test became NATIVE again: its own rows answer (www 192.0.2.50)" || { fail "flip.test back to NATIVE"; dbst flip.test | sed 's/^/         /'; }
dbst flip.test | grep -q "type: secondary" && fail "dbstatus still says secondary" || pass "dbstatus: flip.test is a primary again"

# ================================================================ CONSUMER
echo "== catalog consumer"
wait_ans 192.0.2.41 www.m1.test A 20 && pass "member m1.test of the catalog appeared and was transferred" || { fail "m1.test did not appear"; grep -E "Catalog|cat.test" "$T/s.log" | tail -6 | sed 's/^/         /'; }
wait_ans 192.0.2.42 www.m2.test A 20 && pass "member m2.test appeared" || fail "m2.test did not appear"
wait_ans 192.0.2.43 www.m3.test A 20 && pass "member m3.test answers with the catalog member's data (192.0.2.43), not the database zone's (192.0.2.99)" || fail "m3.test: the member does not win"
dbst m3.test | grep -q "hidden by a catalog member" && pass "dbstatus: the database zone m3.test is hidden by the catalog member (D17-1)" || { fail "dbstatus m3.test"; dbst m3.test | sed 's/^/         /'; }
dbst cat.test | grep -q "type: catalog consumer (CONSUMER)" && pass "dbstatus: cat.test is a catalog consumer" || fail "dbstatus cat.test"
# the catalog drops m2.test and lists m4.test
catalog 2 m1.test m3.test m4.test > "$T/z/cat.zone"
$KCTL1 reload cat.test > /dev/null 2>&1
wait_ans 192.0.2.44 www.m4.test A 20 && pass "the catalog update added m4.test (NOTIFY -> transfer of the catalog)" || { fail "m4.test did not appear"; grep -E "Catalog|cat.test" "$T/s.log" | tail -6 | sed 's/^/         /'; }
wait_rcode REFUSED m2.test 15 && pass "the member m2.test the catalog dropped is gone" || fail "m2.test is still served"
[ "$(ans www.m1.test A)" = "192.0.2.41" ] && pass "m1.test, still a member, was not disturbed" || fail "m1.test lost"
# the consumer's row is deleted: its members go with it and the database zone comes back
sq "DELETE FROM domains WHERE name = 'cat.test'"
OUT=$($KCTL reload 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "karictl reload: $(printf '%s' "$OUT" | cut -c1-60)" || fail "karictl reload: $OUT"
wait_rcode REFUSED m1.test 15 && wait_rcode REFUSED m4.test 5 && pass "the members m1.test and m4.test left with the consumer" || fail "members are still served"
wait_ans 192.0.2.99 www.m3.test A 15 && pass "m3.test is served from the database again (www 192.0.2.99)" || { fail "m3.test did not come back"; dbst m3.test | sed 's/^/         /'; }
[ "$(rcode cat.test)" = REFUSED ] && pass "cat.test itself is gone" || fail "cat.test still answers"

# ================================================================ a row is deleted
echo "== a deleted row"
sq "DELETE FROM domains WHERE name = 'del.test'"
$KCTL reload > /dev/null 2>&1
wait_rcode REFUSED del.test 15 && pass "del.test left with its row" || fail "del.test is still served"
dbst del.test | grep -q "not in the database registry" && pass "dbstatus: del.test is not in the registry" || fail "dbstatus del.test"
wait_log "$T/s.log" "zone 'del.test.' (view '[_a-z]*') deleted" 5 && pass "the deletion is logged" || fail "no deletion line in the log"

# ================================================================ loader restart
echo "== loader restart"
t_slv=$(transfers slv.test); t_rec=$(transfers recon.test); t_plain=$(transfers plain.test)
B0=$(grep -c "\[DB\] batch .* complete" "$T/s.log")
LP=$(loader_pid)
if [ -n "$LP" ]; then
    kill -9 "$LP"
    wait_log "$T/s.log" "\[DB\] batch .* complete" 15 $((B0 + 1)) && pass "the restarted loader reconciled (a new batch)" || fail "no batch after the loader was killed"
    sleep 3
    grep "\[DB\] batch .* complete" "$T/s.log" | tail -1 | grep -q "(0 installed" && pass "that batch sent nothing: 0 zones installed" || { fail "the batch after the restart"; grep "\[DB\] batch .* complete" "$T/s.log" | tail -2 | sed 's/^/         /'; }
    [ "$(transfers slv.test)" = "$t_slv" ] && [ "$(transfers recon.test)" = "$t_rec" ] && [ "$(transfers plain.test)" = "$t_plain" ] &&
        pass "no zone was transferred again (slv $t_slv, recon $t_rec, plain $t_plain)" || fail "transfer counters changed after the loader restart"
    [ "$(ans www.slv.test A)" = "192.0.2.10" ] && [ "$(ans new.slv.test A)" = "192.0.2.77" ] && [ "$(ans www.recon.test A)" = "192.0.2.32" ] &&
        pass "the zones kept their data" || fail "data lost after the loader restart"
else fail "no loader process found"; fi

# ================================================================ in memory only
echo "== memory only"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2>/dev/null && { kill -KILL "$SRV"; fail "karidns did not stop"; }
SRV=""
: > "$T/s2.log"
"$KARIDNS" -c "$T/s.conf" -f > "$T/s2.log" 2>&1 &
SRV=$!
wait_log "$T/s2.log" "\[DB\] initial load complete" 20 && pass "the server restarted" || fail "restart"
wait_ans 192.0.2.10 www.slv.test A && pass "it is transferred again" || fail "slv.test after the restart"
[ "$(ans new.slv.test A)" = "192.0.2.77" ] && pass "with the current data (the UPDATE of the primary included)" || fail "new.slv.test after the restart"

if grep -q "AddressSanitizer\|runtime error:" "$T/s.log" "$T/s2.log" "$T/p1.log" "$T/p2.log" 2>/dev/null; then fail "sanitizer report in a server log"; fi
echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_secondary_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_secondary_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
