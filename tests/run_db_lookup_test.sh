#!/bin/sh
# run_db_lookup_test.sh - 0.7, the first start of a zone store: a query for a zone that the manifest pass has not listed yet is answered by asking the loader for the zone that encloses its name.
#
# A database of LOOKUP_ZONES zones (default 20000, tests/db/gen_sqlite3_zones.sh) is read into an empty store.  The loader is started behind tests/db/slow_manifest.c, which holds the pass after its
# MANIFEST_BEGIN for as long as the test wants (the pass over 20000 zones takes 40 ms, too short for a query to meet it), while the real loader answers on its fetch stream.  The whole scenario runs twice:
#   - "body": the loader as it is (HELLO features 15 (with the zone image bit): the answer of a lookup is followed by the body of the zone, FETCH_REQ mode 3);
#   - "plain": the proxy takes the lookup-body bit (4) out of the HELLO (-DHELLO_MASK=11: the store, lookup and image bits stay), the loader of an earlier version: the Backend asks mode 2 and fetches the zone in a second request.
# Checked while the pass is held:
#   - a query for a zone near the end of the manifest order is NOERROR (not REFUSED), over UDP and over TCP, and so is a query for a name inside such a zone; with the body the zone comes with the answer
#     of the lookup (karictl dbstatus: body_inline), without it never;
#   - a name that no zone has is REFUSED;
#   - a flood of names that no zone has is all REFUSED, the lookups in flight stay within their share of the places, no place is left taken afterwards (karictl dbstatus), and the queries for zones are answered meanwhile;
#   - karictl dbstatus and karictl store count the lookups (found, none, body_inline, the time to the answer);
# and after the pass is released: the store ends up with every zone (the flood did not starve the fill), and a name that no zone has is refused at once with no lookup (the counters stay).
# Needs sqlite3, perl, a C compiler (the proxy is built in the test's directory), the binaries; as root the loader and the server run as nobody, otherwise as the user who runs the test.  SKIP without them.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
DAG=${DAG:-./dag}
for b in "$KARIDNS" ./karictl "$LOADER" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler for the proxy of the loader"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
if [ "$(id -u)" = "0" ]; then
    id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
    RUNUSER=nobody
else
    RUNUSER=$(id -un)
fi

NZ=${LOOKUP_ZONES:-20000}
FLOOD=${LOOKUP_FLOOD:-1500}
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_lookup.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    kari_kill_conf "$T/a.conf"
    kari_kill_conf "$T/b.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((22000 + $$ % 15000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

echo "== the database: $NZ zones; the loader behind the proxy that holds the first pass"
mkdir "$T/db"
sh tests/db/gen_sqlite3_zones.sh "$T/db/z.db" "$NZ" 11 > "$T/gen.log" 2>&1 || { echo "gen failed"; cat "$T/gen.log"; exit 1; }
chown -R "$RUNUSER" "$T/db" 2>/dev/null; chmod 600 "$T/db/z.db"*
if [ "$(id -u)" = "0" ]; then
    install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader.real" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader.real"; chown 0:0 "$T/karidns-dbloader.real"; chmod 755 "$T/karidns-dbloader.real"; }
else
    cp "$LOADER" "$T/karidns-dbloader.real"; chmod 755 "$T/karidns-dbloader.real"
fi
cc -O1 -o "$T/karidns-dbloader" tests/db/slow_manifest.c -DREAL_LOADER="\"$T/karidns-dbloader.real\"" -DRELEASE_FILE="\"$T/release\"" > "$T/cc.log" 2>&1 || { echo "SKIP: the proxy does not build"; cat "$T/cc.log"; exit 0; }
cc -O1 -o "$T/karidns-dbloader.plain" tests/db/slow_manifest.c -DREAL_LOADER="\"$T/karidns-dbloader.real\"" -DRELEASE_FILE="\"$T/release\"" -DHELLO_MASK=11u > "$T/cc2.log" 2>&1 || { echo "SKIP: the proxy does not build"; cat "$T/cc2.log"; exit 0; }
chmod 755 "$T/karidns-dbloader" "$T/karidns-dbloader.plain"
cat > "$T/a.ctl.conf" <<EOF
socket "$T/a.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/a.ctl.conf"
KA="./karictl -c $T/a.ctl.conf"
cat > "$T/a.conf" <<EOF
options {
    user "$RUNUSER"; pid-file "none"; listen-on { 127.0.0.1; }; port $PA; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "$RUNUSER"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; };
               park-timeout 5000; store "$T/store"; };
};
control-channel { socket "$T/a.sock"; secret "$SECRET"; };
EOF
sed "s#karidns-dbloader\"#karidns-dbloader.plain\"#" "$T/a.conf" > "$T/b.conf"
sf() { $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
lk() { $KA dbstatus 2>/dev/null | grep '^lookup of names' | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
lkall() { $KA dbstatus 2>/dev/null | grep '^lookup of names' | sed 's/.*: //'; }
fq() { $KA dbstatus 2>/dev/null | grep '^fetchq:' | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
waitfor() { w=$1; shift; i=0; while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }
lookup_ready() { [ "$(lk ready)" = yes ]; }
none_in_flight() { [ "$(lk in_flight)" = 0 ]; }
dagq() { "$DAG" @127.0.0.1 -p "$PA" "$1" "${2:-A}" +nohexdump +time=10 +tries=1 2>&1; }
status_of() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }

# scenario NAME CONF: one run of the server and the loader (a.conf: the loader as it is; b.conf: behind the proxy that takes the third bit out of the HELLO)
scenario() {
    SNAME=$1
    CONF=$2
    rm -rf "$T/store" "$T/release"
    echo
    echo "######## $SNAME"
    : > "$T/a.log"
    "$KARIDNS" -c "$CONF" -f > "$T/a.log" 2>&1 &
    SRV=$!
    kari_wait_log "$T/a.log" "a manifest pass starts" 30 && pass "[$SNAME] the first pass has started (the loader is behind the proxy: its pages are held)" || { fail "[$SNAME] no manifest pass"; tail -20 "$T/a.log"; }
    waitfor 20 lookup_ready && pass "[$SNAME] the loader answers lookups (HELLO features)" || fail "[$SNAME] the lookups are not ready: $(lkall)"
    sleep 0.5
    KN=$(sf store.zones.known); ST=$(sf store.zones.stored)
    [ "${KN:-9}" -lt 50 ] && [ "${ST:-9}" -lt 50 ] && pass "[$SNAME] the store has no list of the zones yet (known $KN, stored $ST)" || fail "[$SNAME] the pass was not held: known $KN stored $ST"

    echo "== [$SNAME] queries for zones that the pass has not listed"
    LATE=$((NZ - 9))
    OUT=$(dagq "z$LATE.test" A)
    [ "$(echo "$OUT" | status_of)" = NOERROR ] && echo "$OUT" | grep -q "^z$LATE.test.[[:space:]].*A[[:space:]]*192\.0\.2\." && pass "[$SNAME] z$LATE.test (near the end of the manifest order): NOERROR with its A record (UDP)" || { fail "[$SNAME] z$LATE.test: $(echo "$OUT" | status_of)"; echo "$OUT" | head -20; }
    OUT=$(dagq "www.z$((NZ - 8)).test" A)
    [ "$(echo "$OUT" | status_of)" = NOERROR ] && echo "$OUT" | grep -q "^www.z$((NZ - 8)).test.[[:space:]]" && pass "[$SNAME] www.z$((NZ - 8)).test (a name inside a zone that was not listed): NOERROR with its record" || { fail "[$SNAME] www.z$((NZ - 8)).test: $(echo "$OUT" | status_of)"; echo "$OUT" | head -20; }
    TOUT=$(perl tests/db/tcp_query.pl "$PA" "www.z$((NZ - 7)).test" A 2>&1)
    [ "$TOUT" = "rcode=0 answers=1" ] && pass "[$SNAME] www.z$((NZ - 7)).test over TCP: NOERROR with its record" || fail "[$SNAME] TCP: $TOUT"
    [ "$(lk found)" -ge 3 ] 2>/dev/null && pass "[$SNAME] dbstatus counts the lookups that found a zone ($(lkall))" || fail "[$SNAME] dbstatus: $(lkall)"
    if [ "$SNAME" = body ]; then
        [ "$(lk body_inline)" -ge 3 ] 2>/dev/null && [ "$(sf store.lookup.body_inline)" -ge 3 ] 2>/dev/null && pass "[$SNAME] the zones came with the answer of the lookup (body_inline=$(lk body_inline), store.lookup.body_inline=$(sf store.lookup.body_inline))" || fail "[$SNAME] body_inline: $(lkall)"
    else
        [ "$(lk body_inline)" = 0 ] && [ "$(sf store.lookup.body_inline)" = 0 ] && pass "[$SNAME] a loader without the third feature bit is asked in mode 2: no zone came with a lookup" || fail "[$SNAME] body_inline: $(lkall)"
    fi
    [ "$(sf store.lookup.found)" = "$(lk found)" ] && [ -n "$(sf store.lookup.rtt.p99_us)" ] && [ "$(sf store.lookup.take_fail)" = 0 ] && pass "[$SNAME] karictl store has the counters (store.lookup.found, .rtt.p99_us=$(sf store.lookup.rtt.p99_us), .take_fail)" || fail "[$SNAME] store.lookup: found $(sf store.lookup.found) p99 $(sf store.lookup.rtt.p99_us) take_fail $(sf store.lookup.take_fail)"
    KN=$(sf store.zones.known); ST=$(sf store.zones.stored)
    [ "$((KN + ST))" -lt 50 ] && pass "[$SNAME] the pass is still held: the store knows $((KN + ST)) zones (the three that the queries asked for)" || fail "[$SNAME] known $KN stored $ST"
    OUT=$(dagq "www.nozone.test" A)
    [ "$(echo "$OUT" | status_of)" = REFUSED ] && pass "[$SNAME] a name that no zone has: REFUSED (UDP)" || { fail "[$SNAME] www.nozone.test: $(echo "$OUT" | status_of)"; }
    TOUT=$(perl tests/db/tcp_query.pl "$PA" "www.nozone.test" A 2>&1)
    [ "$TOUT" = "rcode=5 answers=0" ] && pass "[$SNAME] a name that no zone has: REFUSED (TCP)" || fail "[$SNAME] TCP: $TOUT"
    [ "$(lk none)" -ge 2 ] 2>/dev/null && pass "[$SNAME] dbstatus counts the lookups that found nothing ($(lkall))" || fail "[$SNAME] dbstatus: $(lkall)"

    echo "== [$SNAME] a flood of names that no zone has"
    kari_udp_snap "$T/udp.flood.snap"
    FOUT=$(perl tests/db/udp_lookup_probe.pl flood "$PA" "$FLOOD" nothing.test 30)
    echo "  $FOUT"
    fv() { echo "$FOUT" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
    [ "$(fv refused)" -ge $((FLOOD - FLOOD / 100)) ] 2>/dev/null && [ "$(fv servfail)" = 0 ] && [ "$(fv noerror)" = 0 ] && pass "[$SNAME] the flood: $(fv refused) of $FLOOD names REFUSED, 0 SERVFAIL, 0 NOERROR" || { fail "[$SNAME] the flood: $FOUT"; echo "  the lookups: $(lkall)"; echo "  the kernel during the flood (netstat -s -p udp: a query lost with no lookup counted for it was dropped before the server read it):"; kari_udp_delta "$T/udp.flood.snap"; }
    waitfor 20 none_in_flight && pass "[$SNAME] no lookup is left in flight (in_flight=0)" || fail "[$SNAME] in_flight=$(lk in_flight)"
    [ "$(fq places)" = 0 ] && [ "$(lk pending)" = 0 ] && pass "[$SNAME] no place of fetch-concurrency is left taken, no lookup waits for one (places=$(fq places) pending=$(lk pending))" || fail "[$SNAME] places=$(fq places) pending=$(lk pending)"
    echo "  $(lkall)"
    [ "$(lk found)" -le 6 ] 2>/dev/null && pass "[$SNAME] the flood found no zone and made none known (found=$(lk found))" || fail "[$SNAME] found=$(lk found)"
    OUT=$(dagq "z$((NZ - 5)).test" SOA)
    [ "$(echo "$OUT" | status_of)" = NOERROR ] && pass "[$SNAME] a zone is answered after the flood (the lookups and the cold fetches were not starved)" || fail "[$SNAME] z$((NZ - 5)).test after the flood: $(echo "$OUT" | status_of)"
    grep -q "\[DB\].*fetch.*failed" "$T/a.log" && fail "[$SNAME] a fetch failed: $(grep '\[DB\].*fetch.*failed' "$T/a.log" | head -2)" || pass "[$SNAME] no fetch failed"
    kill -0 "$SRV" 2>/dev/null && pass "[$SNAME] the server is up" || fail "[$SNAME] the server died"

    echo "== [$SNAME] the pass is released"
    : > "$T/release"
    kari_wait_log "$T/a.log" "the manifest pass is over" 60 && pass "[$SNAME] the pass ended" || { fail "[$SNAME] the pass did not end"; tail -10 "$T/a.log"; }
    waitfor 90 stored_all && pass "[$SNAME] the store holds all $NZ zones (the fill was not starved by the lookups)" || fail "[$SNAME] the store holds $(sf store.zones.stored) of $NZ zones (known $(sf store.zones.known))"
    L0=$(lkall)
    OUT=$(dagq "www.nozone.test" A)
    [ "$(echo "$OUT" | status_of)" = REFUSED ] && pass "[$SNAME] after the pass: a name that no zone has is REFUSED" || fail "[$SNAME] www.nozone.test after the pass: $(echo "$OUT" | status_of)"
    FOUT=$(perl tests/db/udp_lookup_probe.pl flood "$PA" 300 later.test 20)
    echo "  $FOUT"
    [ "$(echo "$FOUT" | tr ' ' '\n' | sed -n 's/^refused=//p')" -ge 297 ] 2>/dev/null && pass "[$SNAME] after the pass: 300 unknown names, all REFUSED" || fail "[$SNAME] after the pass: $FOUT"
    L1=$(lkall)
    [ "$L0" = "$L1" ] && pass "[$SNAME] after the pass no name is looked up (the counters stay: $L1)" || fail "[$SNAME] the lookup counters moved after the pass: [$L0] -> [$L1]"
    OUT=$(dagq "z$LATE.test" A)
    [ "$(echo "$OUT" | status_of)" = NOERROR ] && pass "[$SNAME] z$LATE.test still answers" || fail "[$SNAME] z$LATE.test after the pass: $(echo "$OUT" | status_of)"
    kill -TERM "$SRV" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$SRV" 2>/dev/null
    SRV=""
}

scenario body "$T/a.conf"
scenario plain "$T/b.conf"

echo
echo "run_db_lookup_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
