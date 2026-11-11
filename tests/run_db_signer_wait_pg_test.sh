#!/bin/sh
# run_db_signer_wait_pg_test.sh - the loader waits for the signer (0.6.0 item C, S-5; `database { signer-wait yes; }`), PostgreSQL (0.6.1, P5 (c)).
#
# The PostgreSQL side of tests/run_db_signer_wait_test.sh.  karidns with options { database { driver postgresql; auto-reload yes; } }, the loader run as the user of
# the PostgreSQL role (LISTEN karidns_changes wakes it).  A zone with the domainmetadata X-KARIDNS-SIGNER=1 is kept signed by karidns-signer: a change to it must
# not be served before the signer has signed it, so the loader does not reload it because of the change log; it reloads it on a reload request (karictl reload, or the
# signer's row in karidns_reload_requests).  The cursor of the PostgreSQL change log is the xmin of a snapshot, not a seq (dns_db_driver.h changes_unsettled), and the
# "cover marks" of a one-zone reload (karidns_dbloader.c cov_covers: a row is covered when its transaction id is below the xmin of the reload's snapshot) are
# the part that only this test reaches.  Checked:
#   S1  signer-wait yes (the default):
#       - an ordinary zone follows its change at once, the signer's zone keeps the version it has, and dbstatus names the zone that waits (a change that keeps the
#         serial waits as well; two zones wait);
#       - `karictl reload <zone>` and `karictl reload` read the zone as it is, and dbstatus stops naming the zone;
#       - a zone that is new to the Backend is read as it is; a deleted zone leaves the list; a restart reads the changed zone as it is;
#       - a waiting zone that loses the metadata X-KARIDNS-SIGNER is read as it is at the next batch and leaves the list;
#   S2  signer-wait no: the same change is served by auto reload, nothing waits; karictl reconfig switches between the two;
#   S4  the cover marks: a reload request that comes inside the coalesce window, before the batch has read the change rows: the zone does not go on the list when the
#       batch reaches the rows; a change made after the reload does; a transaction that is open while the reload is made (its xid is above the xmin of the reload's
#       snapshot is not covered: PostgreSQL leaves such a zone listed until the next reload, documented) is checked as well.
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned and runs as the unprivileged user that can connect to PostgreSQL).  SKIP
# otherwise, and when PostgreSQL is not reachable (tests/db/pg_lib.sh) or a binary is missing.
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
"$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_sigwaitpg.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""
HOLD=""
stop_server() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    stop_server
    [ -n "$HOLD" ] && kill "$HOLD" 2>/dev/null
    pg_cleanup
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
pg_setup sigwait || exit 0
[ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader cannot run as root); set KARIDNS_TEST_PG_USER"; exit 0; }

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/z"; chmod 755 "$T/z"
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
loadz() {   # loadz NAME: the zone file into the database
    ./tests/db/zone2sql --dialect pgsql "$T/z/$1.zone" > "$T/z/$1.sql" 2>/dev/null && pf "$T/z/$1.sql" > /dev/null
}
newdb() { pq "DROP SCHEMA public CASCADE; CREATE SCHEMA public" > /dev/null; pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null; }
addz() {   # addz NAME SERIAL ADDRESS
    mkzone "$1" "$2" "$3"
    loadz "$1"
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
    loadz "$zn"
    pq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = '$zn'" > /dev/null
}
setwww() { pq "UPDATE records SET content = '$2' WHERE name = 'www.$1' AND type = 'A'" > /dev/null; }
bump() {   # bump NAME OLD NEW: the serial of the SOA
    pq "UPDATE records SET content = replace(content, ' $2 3600', ' $3 3600') WHERE type = 'SOA' AND name = '$1'" > /dev/null
}
dropz() {
    pq "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = '$1'); DELETE FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = '$1'); DELETE FROM domains WHERE name = '$1'" > /dev/null
}
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
pg_conninfo_file "$T/ci"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf "DATABASE-OPTIONS"
    cat > "$T/s.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; auto-reload yes; poll-interval 20; coalesce ${COALESCE:-300}; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
LOG="$T/srv.log"
start_server() {
    : > "$LOG"
    "$KARIDNS" -c "$T/s.conf" -f > "$LOG" 2>&1 &
    SRV=$!
    if kari_wait_log "$LOG" "\[DB\] initial load complete" 30; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$LOG" | tail -20; fi
}
qa() { ./dag @127.0.0.1 -p $PORT "$1" A +short +nohexdump 2>/dev/null; }
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

setwww sg.test 192.0.2.21
bump sg.test 1 2
setwww plain.test 192.0.2.11
if wait_ans www.plain.test 192.0.2.11 8; then pass "an ordinary zone follows its change by auto reload (LISTEN, not the 20 s poll)"; else fail "the ordinary zone was not reloaded"; fi
sleep 1
check_ans "the signer's zone keeps the version it has (a changed record, a new serial)" "192.0.2.20" www.sg.test
wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 5 && pass "dbstatus: 1 zone waits for the signer, by name" || { fail "dbstatus does not name the waiting zone"; dbst | sed 's/^/         /'; }
setwww sg2.test 192.0.2.31
sleep 1.5
check_ans "a change that keeps the serial waits as well" "192.0.2.30" www.sg2.test
wait_dbst "^    waiting for the signer: 2 zone(s): sg.test, sg2.test$" 5 && pass "dbstatus: 2 zones wait" || { fail "dbstatus after the second zone"; dbst | sed 's/^/         /'; }
setwww plain.test 192.0.2.12
wait_ans www.plain.test 192.0.2.12 8 && pass "...an ordinary zone still follows" || fail "the ordinary zone does not follow any more"

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
setwww sg3.test 192.0.2.41
wait_dbst "^    waiting for the signer: 1 zone(s): sg3.test$" 6 && pass "a change of it waits" || { fail "sg3.test does not wait"; dbst | sed 's/^/         /'; }
dropz sg3.test
setwww plain.test 192.0.2.13
wait_ans www.plain.test 192.0.2.13 8 && pass "a deleted zone: the next batch runs" || fail "no batch after the delete"
wait_dbst "waiting for the signer" 1 && { fail "the deleted zone still waits"; dbst | sed 's/^/         /'; } || pass "...and the deleted zone left the list of waiting zones"
setwww sg.test 192.0.2.22
sleep 2
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
setwww sg.test 192.0.2.23
if wait_ans www.sg.test 192.0.2.23 8; then pass "signer-wait no: the change of the signer's zone is picked up by auto reload"; else fail "signer-wait no: not picked up"; fi
nowait && pass "...and nothing waits" || fail "a zone waits with signer-wait no"
conf ""
$KCTL reconfig > /dev/null 2>&1
sleep 2
setwww sg.test 192.0.2.24
sleep 2.5
check_ans "reconfig back to the default: the zone waits again" "192.0.2.23" www.sg.test
wait_dbst "^    waiting for the signer: 1 zone(s): sg.test$" 5 && pass "dbstatus names it" || { fail "dbstatus after the reconfig"; dbst | sed 's/^/         /'; }

echo "== S1: a waiting zone that loses X-KARIDNS-SIGNER"
pq "DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-SIGNER' AND domain_id = (SELECT id FROM domains WHERE name = 'sg.test')" > /dev/null
if wait_ans www.sg.test 192.0.2.24 8; then pass "without the metadata the zone is no signer's: the next batch reads it as it is"; else fail "the zone that lost the metadata is still held back"; dbst | sed 's/^/         /'; fi
wait_dbst "waiting for the signer" 1 && { fail "the zone is still on the list of waiting zones"; dbst | sed 's/^/         /'; } || pass "...and it left the list of waiting zones"
setwww sg.test 192.0.2.25
if wait_ans www.sg.test 192.0.2.25 8; then pass "...and its changes are served at once"; else fail "a change of the zone without the metadata is not served"; fi
stop_server

# ================================================================ S4
# The cover marks.  The signer writes the zone and asks for the reload at once: the request comes inside the coalesce window, before the auto batch has read the change
# rows.  The reload reads the zone as it is, so those rows are in what it read (their transaction ids are below the xmin of its snapshot); when the batch reaches
# them they must not put the zone on the list again.  A change made after the reload is a change.
echo "== S4: a reload request inside the coalesce window, before the batch has read the change rows"
COALESCE=4000
newdb
addsigned sg4.test 1 192.0.2.20
addsigned sg4b.test 1 192.0.2.30
conf ""
start_server
sleep 1
setwww sg4.test 192.0.2.21
bump sg4.test 1 2
$KCTL reload sg4.test > /dev/null 2>&1
wait_ans www.sg4.test 192.0.2.21 3 && pass "the reload request serves the change at once (inside the 4 s window)" || fail "the reload request did not serve the change"
sleep 6
nowait && pass "the batch has read the rows of the change: sg4.test does not wait (covered)" || { fail "sg4.test is on the list of the zones that wait for the signer"; dbst | sed 's/^/         /'; }
setwww sg4.test 192.0.2.22
wait_dbst "^    waiting for the signer: 1 zone(s): sg4.test$" 12 && pass "a change after the reload is a change: sg4.test waits" || { fail "a change after the reload is not noticed"; dbst | sed 's/^/         /'; }
check_ans "...and is not served" "192.0.2.21" www.sg4.test
$KCTL reload sg4.test > /dev/null 2>&1
wait_ans www.sg4.test 192.0.2.22 3 && pass "...until the reload request" || fail "the second reload request did not serve the change"
sleep 6
nowait && pass "...and then the list is empty again" || { fail "the list is not empty after the second reload"; dbst | sed 's/^/         /'; }
# a second zone: the cover mark of sg4 does not hide a change of sg4b
setwww sg4b.test 192.0.2.31
wait_dbst "^    waiting for the signer: 1 zone(s): sg4b.test$" 12 && pass "the mark of one zone does not cover another: sg4b.test waits" || { fail "sg4b.test does not wait"; dbst | sed 's/^/         /'; }

# An old transaction that is still open keeps the xmin of every snapshot low: a row written after it began has a transaction id above the xmin of the reload's snapshot, so
# the reload does not cover it, and the next batch lists the zone again (the limit written in docs/karidns-signer.md).  The reload that follows the end of that
# transaction clears the list for good.
echo "== S4: an open old transaction (the documented limit)"
$KCTL reload > /dev/null 2>&1
wait_ans www.sg4b.test 192.0.2.31 5 && pass "reload of every zone" || fail "reload of every zone"
sleep 5
nowait && pass "nothing waits" || { fail "something waits"; dbst | sed 's/^/         /'; }
( printf 'BEGIN;\nSELECT txid_current();\nSELECT pg_sleep(40);\nROLLBACK;\n' | psql -X -q -At "$PGC" > /dev/null 2>&1 ) &
HOLD=$!
sleep 1.5
setwww sg4.test 192.0.2.23
$KCTL reload sg4.test > /dev/null 2>&1
wait_ans www.sg4.test 192.0.2.23 3 && pass "the reload serves the change" || fail "the reload did not serve the change"
sleep 6
if dbst | grep -q "waiting for the signer: 1 zone(s): sg4.test"; then pass "an open older transaction: the rows are above the xmin of the reload, the zone is listed again (documented)"; else pass "(the zone is not listed: the loader's cursor had passed the rows before the old transaction began)"; fi
kill "$HOLD" 2>/dev/null; wait "$HOLD" 2>/dev/null; HOLD=""
sleep 1
$KCTL reload sg4.test > /dev/null 2>&1
sleep 6
nowait && pass "...the next reload, with no old transaction, clears the list" || { fail "the list is not empty after the reload"; dbst | sed 's/^/         /'; }
stop_server

if grep -q "killed by signal\|AddressSanitizer\|ThreadSanitizer" "$LOG"; then fail "the loader crashed"; grep -E "killed by signal|Sanitizer|#[0-9] " "$LOG" | head -12 | sed 's/^/         /'; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_signer_wait_pg_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_signer_wait_pg_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
