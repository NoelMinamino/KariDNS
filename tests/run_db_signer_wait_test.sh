#!/bin/sh
# run_db_signer_wait_test.sh - the loader waits for the signer (0.6.0 item C, S-5; `database { signer-wait yes; }`), SQLite3.
#
# karidns with options { database { auto-reload yes; } }, the loader run as "nobody".  A zone with the domainmetadata X-KARIDNS-SIGNER=1 is kept
# signed by karidns-signer: a change to it (a record, a serial) must not be served before the signer has signed it, so the loader does not reload
# it because of the change log or a moved serial; it reloads it on a reload request (karictl reload, or the signer's row in karidns_reload_requests).
# Checked:
#   S1  signer-wait yes (the default):
#       - an ordinary zone follows its change at once, the signer's zone keeps the version it has (the old answer), and dbstatus names the zone that waits;
#       - a change that keeps the serial waits as well; two zones wait; the list says "and N more" beyond the first few names (cap);
#       - `karictl reload <zone>` and `karictl reload` read the zone as it is: the new answer is served and dbstatus stops naming the zone;
#       - a zone that is new to the Backend is read as it is (also with the metadata); a deleted zone leaves the list of waiting zones;
#       - a restart reads the changed zone as it is (the full comparison of the start);
#       - a waiting zone that loses the metadata X-KARIDNS-SIGNER is read as it is at the next batch and leaves the list;
#   S2  signer-wait no: the same change is served by auto reload, nothing waits; karictl reconfig switches between the two;
#   S4  a reload request that comes before the poll of the loader has read the change rows: the zone does not go on the list afterwards; a later change does;
#   S3  two views (loopback aliases 127.0.0.2 and 127.0.0.3): every view has its own set of waiting zones; a zone of view a that waits does not hold back the
#       same name in view b, an ordinary zone follows in both, and `karictl reload <zone>` clears only the view that has the zone.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned; S3 adds loopback aliases).  SKIP otherwise, and
# when karidns, dag, karictl, karidns-dbloader (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_sigwait.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_server() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
ADDED=""
cleanup() {
    stop_server
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
HAVE_ALIASES=1
for ip in 127.0.0.2 127.0.0.3; do
    if ifconfig lo0 2>/dev/null | grep -q "inet $ip " || [ "$(uname -s)" = "Linux" ]; then continue; fi
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null; then ADDED="$ADDED $ip"; else HAVE_ALIASES=0; fi
done

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db" "$T/z"
chown nobody "$T/db"; chmod 777 "$T/db"
mkzone() {   # mkzone NAME SERIAL WWW-ADDRESS
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A $3
EOF
}
DB="$T/db/s.db"
sq() { sqlite3 "$DB" "$@"; chmod 666 "$DB"* 2>/dev/null; }
newdb() { rm -f "$DB" "$DB-wal" "$DB-shm"; sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null; sqlite3 "$DB" < db/karidns_ext.sqlite3.sql; chmod 666 "$DB"; }
addz() {   # addz NAME SERIAL ADDRESS
    mkzone "$1" "$2" "$3"
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/$1.zone" 2>/dev/null | sqlite3 "$DB"
    chmod 666 "$DB"*
}
# a signed zone (an NSEC chain, fake signatures) in the presigned layout, with the signer's metadata
addsigned() {   # addsigned NAME SERIAL ADDRESS
    zn=$1
    cat > "$T/z/$zn.zone" <<EOF
\$ORIGIN $zn.
\$TTL 300
@ IN SOA ns1.$zn. host.$zn. $2 3600 600 86400 300
@ IN NS ns1.$zn.
@ IN DNSKEY 257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN NSEC ns1.$zn. NS SOA RRSIG NSEC DNSKEY
ns1 IN A 192.0.2.1
ns1 IN NSEC www.$zn. A RRSIG NSEC
www IN A $3
www IN NSEC $zn. A RRSIG NSEC
@ IN RRSIG SOA 8 2 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN RRSIG NS 8 2 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN RRSIG DNSKEY 8 2 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
@ IN RRSIG NSEC 8 2 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
ns1 IN RRSIG A 8 3 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
ns1 IN RRSIG NSEC 8 3 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
www IN RRSIG A 8 3 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
www IN RRSIG NSEC 8 3 300 20350101000000 20250101000000 12345 $zn. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o
EOF
    ./tests/db/zone2sql --dialect sqlite3 "$T/z/$zn.zone" 2>/dev/null | sqlite3 "$DB"
    sqlite3 "$DB" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = '$zn'"
    chmod 666 "$DB"*
}
bump() {   # bump NAME OLD NEW: the serial of the SOA, and the address of www, are changed
    sq "UPDATE records SET content = replace(content, ' $2 3600', ' $3 3600') WHERE type = 'SOA' AND name = '$1'"
}
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf "DATABASE-OPTIONS" [views]
    cat > "$T/s.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$DB"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; auto-reload yes; poll-interval ${POLL:-1}; coalesce 300; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
    if [ "${2:-}" = views ]; then
        cat >> "$T/s.conf" <<'EOF'
view "a" { match-clients { 127.0.0.2; }; };
view "b" { match-clients { 127.0.0.3; }; };
EOF
    fi
}
LOG="$T/srv.log"
start_server() {
    : > "$LOG"
    "$KARIDNS" -c "$T/s.conf" -f > "$LOG" 2>&1 &
    SRV=$!
    if kari_wait_log "$LOG" "\[DB\] initial load complete" 30; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$LOG" | tail -20; fi
}
SRCB=""
qa() { ./dag @127.0.0.1 -p $PORT ${SRCB:+-b $SRCB} "$1" A +short +nohexdump 2>/dev/null; }
wait_ans() {   # wait_ans NAME EXPECTED SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(qa "$1")" = "$2" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
check_ans() { got=$(qa "$3"); [ "$got" = "$2" ] && pass "$1" || fail "$1 (got '$got', want '$2')"; }
dbst() { $KCTL dbstatus "$@" 2>&1; }
wait_dbst() {   # wait_dbst PATTERN SECONDS
    i=0
    while [ $i -lt $(($2 * 10)) ]; do dbst | grep -q -- "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
nowait() { ! dbst | grep -q "waiting for the signer"; }

# ================================================================ S1
echo "== S1: signer-wait yes (the default)"
newdb
addz plain.test 10 192.0.2.10
addsigned sg.test 1 192.0.2.20
addsigned sg2.test 1 192.0.2.30
conf ""
start_server
check_ans "the signer's zone is served" "192.0.2.20" www.sg.test
nowait && pass "dbstatus: nothing waits for the signer" || { fail "dbstatus names a waiting zone at the start"; dbst | sed 's/^/         /'; }

sq "UPDATE records SET content = '192.0.2.21' WHERE name = 'www.sg.test' AND type = 'A'"
bump sg.test 1 2
sq "UPDATE records SET content = '192.0.2.11' WHERE name = 'www.plain.test'"
if wait_ans www.plain.test 192.0.2.11 8; then pass "an ordinary zone follows its change by auto reload"; else fail "the ordinary zone was not reloaded"; fi
sleep 2
check_ans "the signer's zone keeps the version it has (a changed record, a new serial)" "192.0.2.20" www.sg.test
wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 5 && pass "dbstatus: 1 zone waits for the signer, by name" || { fail "dbstatus does not name the waiting zone"; dbst | sed 's/^/         /'; }
dbst | grep -q "pending changes 0" && pass "...and the change log is read up to date (pending changes 0)" || fail "pending changes"

sq "UPDATE records SET content = '192.0.2.31' WHERE name = 'www.sg2.test' AND type = 'A'"
sleep 3
check_ans "a change that keeps the serial waits as well" "192.0.2.30" www.sg2.test
wait_dbst "^    waiting for the signer: 2 zone(s): sg.test, sg2.test$" 5 && pass "dbstatus: 2 zones wait" || { fail "dbstatus after the second zone"; dbst | sed 's/^/         /'; }
sq "UPDATE records SET content = '192.0.2.12' WHERE name = 'www.plain.test'"
wait_ans www.plain.test 192.0.2.12 8 && pass "...an ordinary zone still follows" || fail "the ordinary zone does not follow any more"
grep -q "(auto) sent" "$LOG" && pass "log: the batches are auto batches" || fail "no auto batch in the log"

OUT=$($KCTL reload sg.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK zone sg.test" && [ $RC -eq 0 ] && pass "karictl reload sg.test: $OUT" || fail "reload sg.test: rc $RC '$OUT'"
if wait_ans www.sg.test 192.0.2.21 8; then pass "the reload request reads the zone as it is: the new answer is served"; else fail "reload sg.test: the change is not served"; fi
wait_dbst "^    waiting for the signer: 1 zone(s): sg2.test$" 5 && pass "dbstatus: only sg2.test waits now" || { fail "dbstatus after the reload of sg.test"; dbst | sed 's/^/         /'; }
check_ans "...sg2.test still has the old answer" "192.0.2.30" www.sg2.test
OUT=$($KCTL reload 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "^OK" && [ $RC -eq 0 ] && pass "karictl reload (every zone): $OUT" || fail "reload: rc $RC '$OUT'"
if wait_ans www.sg2.test 192.0.2.31 8; then pass "the reload of every zone reads it as it is"; else fail "reload: sg2.test not served"; fi
wait_dbst "waiting for the signer" 1 && fail "dbstatus still names a zone" || pass "dbstatus: nothing waits any more"

echo "== S1: new zones, deleted zones, a restart"
addsigned sg3.test 1 192.0.2.40
if wait_ans www.sg3.test 192.0.2.40 8; then pass "a signer's zone that is new to the Backend is read as it is"; else fail "the new signed zone is not served"; fi
nowait && pass "...and nothing waits" || fail "a new zone waits"
sq "UPDATE records SET content = '192.0.2.41' WHERE name = 'www.sg3.test' AND type = 'A'"
wait_dbst "^    waiting for the signer: 1 zone(s): sg3.test$" 6 && pass "a change of it waits" || { fail "sg3.test does not wait"; dbst | sed 's/^/         /'; }
sq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'sg3.test'); DELETE FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = 'sg3.test'); DELETE FROM domains WHERE name = 'sg3.test'"
sq "UPDATE records SET content = '192.0.2.13' WHERE name = 'www.plain.test'"
wait_ans www.plain.test 192.0.2.13 8 && pass "a deleted zone: the next batch runs" || fail "no batch after the delete"
wait_dbst "waiting for the signer" 1 && { fail "the deleted zone still waits"; dbst | sed 's/^/         /'; } || pass "...and the deleted zone left the list of waiting zones"
sq "UPDATE records SET content = '192.0.2.22' WHERE name = 'www.sg.test' AND type = 'A'"
sleep 3
check_ans "waiting again" "192.0.2.21" www.sg.test
stop_server
start_server
check_ans "a restart reads the changed zone as it is (the full comparison of the start)" "192.0.2.22" www.sg.test
nowait && pass "...and nothing waits after the restart" || fail "waiting zones after the restart"

# ================================================================ S2
echo "== S2: signer-wait no"
conf "signer-wait no;"
$KCTL reconfig > /dev/null 2>&1
sleep 2
sq "UPDATE records SET content = '192.0.2.23' WHERE name = 'www.sg.test' AND type = 'A'"
if wait_ans www.sg.test 192.0.2.23 8; then pass "signer-wait no: the change of the signer's zone is picked up by auto reload"; else fail "signer-wait no: not picked up"; fi
nowait && pass "...and nothing waits" || fail "a zone waits with signer-wait no"
conf ""
$KCTL reconfig > /dev/null 2>&1
sleep 2
sq "UPDATE records SET content = '192.0.2.24' WHERE name = 'www.sg.test' AND type = 'A'"
sleep 3.5
check_ans "reconfig back to the default: the zone waits again" "192.0.2.23" www.sg.test
wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 5 && pass "dbstatus names it" || { fail "dbstatus after the reconfig"; dbst | sed 's/^/         /'; }

echo "== S1: a waiting zone that loses X-KARIDNS-SIGNER"
wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 5 && pass "sg.test waits (served 192.0.2.23, the database has 192.0.2.24)" || { fail "sg.test does not wait"; dbst | sed 's/^/         /'; }
sq "DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-SIGNER' AND domain_id = (SELECT id FROM domains WHERE name = 'sg.test')"
if wait_ans www.sg.test 192.0.2.24 8; then pass "without the metadata the zone is no signer's: the next batch reads it as it is"; else fail "the zone that lost the metadata is still held back"; dbst | sed 's/^/         /'; fi
wait_dbst "waiting for the signer" 1 && { fail "the zone is still on the list of waiting zones"; dbst | sed 's/^/         /'; } || pass "...and it left the list of waiting zones"
sq "UPDATE records SET content = '192.0.2.25' WHERE name = 'www.sg.test' AND type = 'A'"
if wait_ans www.sg.test 192.0.2.25 8; then pass "...and its changes are served at once"; else fail "a change of the zone without the metadata is not served"; fi
sq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'sg.test'"
sleep 3
$KCTL reload > /dev/null 2>&1
sleep 1

echo "== S1: the names are capped"
$KCTL reload > /dev/null 2>&1
wait_ans www.sg.test 192.0.2.25 8 && pass "reload of every zone" || fail "reload"
n=1; while [ $n -le 8 ]; do addsigned c$n.test 1 192.0.2.5$n; n=$((n + 1)); done
sleep 3
n=1; while [ $n -le 8 ]; do sq "UPDATE records SET content = '192.0.2.6$n' WHERE name = 'www.c$n.test' AND type = 'A'"; n=$((n + 1)); done
wait_dbst "^    waiting for the signer: 8 zone(s): c1.test, c2.test, c3.test, c4.test, c5.test, c6.test, and 2 more$" 8 && pass "dbstatus: 8 zones wait; six names and 'and 2 more'" || { fail "the capped list"; dbst | sed 's/^/         /'; }
check_ans "...none of them is served changed" "192.0.2.51" www.c1.test
$KCTL reload > /dev/null 2>&1
wait_ans www.c8.test 192.0.2.68 8 && pass "a reload of every zone serves them" || fail "reload after the cap"

stop_server

# ================================================================ S3
echo "== S3: two views, every view has its own waiting set"
if [ "$HAVE_ALIASES" != 1 ]; then
    echo "  SKIP: cannot add the loopback aliases 127.0.0.2 and 127.0.0.3"
else
    newdb
    addz plain.test 10 192.0.2.10
    addsigned va.test 1 192.0.2.20
    addsigned vb.test 1 192.0.2.30
    sq "INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'a' FROM domains WHERE name = 'va.test'; INSERT INTO karidns_domain_views (domain_id, view_name) SELECT id, 'b' FROM domains WHERE name = 'vb.test'"
    conf "" views
    start_server
    vwait() {   # vwait VIEW PATTERN SECONDS: the "waiting for the signer" line of the block of a view
        i=0
        while [ $i -lt $(($3 * 10)) ]; do
            dbst | awk -v v="$1" 'index($0, "  view " v ":") == 1 { f = 1; next } /^  view / { f = 0 } /^[^ ]/ { f = 0 } f' | grep -q -- "$2" && return 0
            sleep 0.1; i=$((i + 1))
        done
        return 1
    }
    vnone() { ! dbst | awk -v v="$1" 'index($0, "  view " v ":") == 1 { f = 1; next } /^  view / { f = 0 } /^[^ ]/ { f = 0 } f' | grep -q "waiting for the signer"; }
    # the first queries after the start may go unanswered on a slow host (the coverage build in CI): wait for the answer
    SRCB=127.0.0.2; wait_ans www.va.test 192.0.2.20 10 && pass "view a serves its signer zone" || fail "view a serves its signer zone (got '$(qa www.va.test)', want '192.0.2.20')"
    SRCB=127.0.0.3; wait_ans www.vb.test 192.0.2.30 10 && pass "view b serves its signer zone" || fail "view b serves its signer zone (got '$(qa www.vb.test)', want '192.0.2.30')"
    sq "UPDATE records SET content = '192.0.2.21' WHERE name = 'www.va.test' AND type = 'A'"
    sq "UPDATE records SET content = '192.0.2.11' WHERE name = 'www.plain.test'"
    SRCB=127.0.0.2; wait_ans www.plain.test 192.0.2.11 8 && pass "an ordinary zone follows in view a" || fail "plain.test in view a"
    SRCB=127.0.0.3; wait_ans www.plain.test 192.0.2.11 8 && pass "...and in view b" || fail "plain.test in view b"
    SRCB=127.0.0.2; sleep 1.5; check_ans "the signer's zone of view a keeps its version" "192.0.2.20" www.va.test
    vwait a "waiting for the signer: 1 zone(s): va.test$" 6 && pass "dbstatus: view a names va.test" || { fail "view a does not name va.test"; dbst | sed 's/^/         /'; }
    vnone b && pass "...view b has nothing waiting" || { fail "view b waits for something"; dbst | sed 's/^/         /'; }
    sq "UPDATE records SET content = '192.0.2.31' WHERE name = 'www.vb.test' AND type = 'A'"
    vwait b "waiting for the signer: 1 zone(s): vb.test$" 8 && pass "dbstatus: view b names vb.test (and only that)" || { fail "view b does not name vb.test"; dbst | sed 's/^/         /'; }
    vwait a "waiting for the signer: 1 zone(s): va.test$" 2 && pass "...view a still names va.test only" || { fail "view a changed its list"; dbst | sed 's/^/         /'; }
    OUT=$($KCTL reload va.test 2>&1)
    SRCB=127.0.0.2
    if wait_ans www.va.test 192.0.2.21 8; then pass "karictl reload va.test: view a serves the new answer"; else fail "reload va.test: not served ($OUT)"; fi
    vnone a && pass "...view a stops waiting" || { fail "view a still waits"; dbst | sed 's/^/         /'; }
    vwait b "waiting for the signer: 1 zone(s): vb.test$" 2 && pass "...view b still waits for vb.test" || { fail "view b lost vb.test"; dbst | sed 's/^/         /'; }
    SRCB=127.0.0.3; check_ans "...and serves the old answer of vb.test" "192.0.2.30" www.vb.test
    SRCB=""
fi

# ================================================================ S4
# The signer writes the zone and asks for the reload at once: the request comes before the poll of the loader has read the change rows.  The reload reads the zone
# as it is, so those rows are in what it read; when the poll reaches them they must not put the zone on the list again.  (A poll interval of 6 s makes it certain
# that the poll is later than the request.)  A change made after the reload is a change.
echo "== S4: a reload request that comes before the poll has read the change rows"
stop_server
POLL=6
newdb
addsigned sg4.test 1 192.0.2.20
addsigned sg4b.test 1 192.0.2.30
conf ""
start_server
sleep 7
sq "UPDATE records SET content = '192.0.2.21' WHERE name = 'www.sg4.test' AND type = 'A'"
bump sg4.test 1 2
$KCTL reload sg4.test > /dev/null 2>&1
wait_ans www.sg4.test 192.0.2.21 8 && pass "the reload request serves the change at once" || fail "the reload request did not serve the change"
sleep 9
nowait && pass "the poll of the loader has read the rows of the change: sg4.test does not wait" || { fail "sg4.test is on the list of the zones that wait for the signer"; dbst | sed 's/^/         /'; }
sq "UPDATE records SET content = '192.0.2.22' WHERE name = 'www.sg4.test' AND type = 'A'"
wait_dbst "^    waiting for the signer: 1 zone(s): sg4.test$" 12 && pass "a change after the reload is a change: sg4.test waits" || { fail "a change after the reload is not noticed"; dbst | sed 's/^/         /'; }
check_ans "...and is not served" "192.0.2.21" www.sg4.test
$KCTL reload sg4.test > /dev/null 2>&1
wait_ans www.sg4.test 192.0.2.22 8 && pass "...until the reload request" || fail "the second reload request did not serve the change"
sleep 9
nowait && pass "...and then the list is empty again" || { fail "the list is not empty after the second reload"; dbst | sed 's/^/         /'; }
# a deleted zone loses its mark: a zone of the same name that is created again waits for the signer like any other
sq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'sg4b.test'); DELETE FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = 'sg4b.test'); DELETE FROM domains WHERE name = 'sg4b.test'"
sleep 8
nowait && pass "a deleted zone is not on the list" || fail "a deleted zone is on the list"
POLL=1
stop_server


if grep -q "killed by signal\|AddressSanitizer\|ThreadSanitizer" "$LOG"; then fail "the loader crashed"; grep -E "killed by signal|Sanitizer|#[0-9] " "$LOG" | head -12 | sed 's/^/         /'; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_signer_wait_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_signer_wait_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
