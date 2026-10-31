#!/bin/sh
# run_db_notify_test.sh - NOTIFY for database zones that are not in memory (D1a step 7, design 7 "NOTIFY の送信"), with the real karidns, the real
# karidns-dbloader and SQLite3; tests/mock_notify_sink.pl plays the name servers (one per loopback address, all at the server's port: the NS hosts of a zone are
# notified at options { port }).
#
#   - nothing is sent at the start of the server (every zone is new to the directory), after a restart of the loader, or after `karictl reload` (nothing changed):
#     no NOTIFY storm (RFC 1996 4.5 and the first load of a zone in memory send none either)
#   - a zone that is out of memory and changes in the database (a summary with a new serial) is notified, RFC 1996 3.2: to the addresses of its NS hosts that the
#     loader found by name in the database -- the hosts ns1.prov.test and ns2.prov.test live in another zone (prov.test), which is out of memory as well -- and to the
#     address of a host inside the zone (the glue of the apex); another zone is not notified; the zones stay out of memory
#   - a zone in memory is notified as before (the NS host inside the zone)
#   - notify explicit: only the also-notify list (ALSO-NOTIFY of the zone) is notified, not the NS hosts; notify no: nobody
# Needs root (the loader runs as nobody, loopback aliases 127.0.0.2 .. 127.0.0.6).  SKIP without karidns, dag, karictl, karidns-dbloader (SQLite3), sqlite3 or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user, loopback aliases)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
perl -MIO::Socket::IP -MDigest::SHA -MMIME::Base64 -e 1 2>/dev/null || { echo "SKIP: perl modules IO::Socket::IP, Digest::SHA, MIME::Base64 missing"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_notify.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
PIDS=""
ALIASES=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    if [ $FAILS -ne 0 ]; then echo "--- sink logs"; for n in 2 3 4 5 6; do echo "127.0.0.$n:"; cat "$T/l$n" 2>/dev/null; cat "$T/sink$n.err" 2>/dev/null; done; echo "--- server log (Notify, DB)"; grep -E "Notify|\\[DB\\]" "$T/srv.log" 2>/dev/null | tail -30; fi
    kari_kill_tree $PIDS                      # (the sinks)
    stop_srv
    for ip in $ALIASES; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 127.0.0.6; do
    ifconfig lo0 2>/dev/null | grep -q "inet $ip " && continue
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null || ifconfig lo inet "$ip/32" alias 2>/dev/null; then
        ALIASES="$ALIASES $ip"
    else
        echo "SKIP: loopback alias $ip is not configured (ifconfig lo0 inet $ip/32 alias)"; exit 0
    fi
done

mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
# c1, c2: customers whose NS hosts are in prov.test; prov.test: the provider; inz: a host inside the zone; res: the zone that a query loads (its host inside the zone);
# res2: loaded by a query as well, its NS host is in prov.test (out of memory); also: ALSO-NOTIFY
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('c1.test', 'NATIVE'), ('c2.test', 'NATIVE'), ('prov.test', 'NATIVE'), ('inz.test', 'NATIVE'), ('res.test', 'NATIVE'), ('res2.test', 'NATIVE'), ('also.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns0.' || name || ' host.' || name || ' 1 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.prov.test', 3600, 0, 0 FROM domains WHERE name IN ('c1.test', 'c2.test', 'also.test', 'res2.test');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns2.prov.test', 3600, 0, 0 FROM domains WHERE name = 'c1.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.prov.test', 3600, 0, 0 FROM domains WHERE name = 'prov.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.prov.test', 'A', '127.0.0.2', 600, 0, 0 FROM domains WHERE name = 'prov.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns2.prov.test', 'A', '127.0.0.3', 600, 0, 0 FROM domains WHERE name = 'prov.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.inz.test', 3600, 0, 0 FROM domains WHERE name = 'inz.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.inz.test', 'A', '127.0.0.4', 600, 0, 0 FROM domains WHERE name = 'inz.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.res.test', 3600, 0, 0 FROM domains WHERE name = 'res.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.res.test', 'A', '127.0.0.5', 600, 0, 0 FROM domains WHERE name = 'res.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALSO-NOTIFY', '127.0.0.6:$PORT' FROM domains WHERE name = 'also.test';
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf NOTIFY-MODE
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify $1; notify-rate 100; minimal-responses yes;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate 5000; acl-ceiling { 127.0.0.1; }; memory-limit 64m; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
# the name servers: one sink per address, all at the server's port, each with its own log
: > "$T/l2"; : > "$T/l3"; : > "$T/l4"; : > "$T/l5"; : > "$T/l6"
for n in 2 3 4 5 6; do
    perl tests/mock_notify_sink.pl --log "$T/l$n" --bind "127.0.0.$n:$PORT" --answer 2> "$T/sink$n.err" &
    PIDS="$PIDS $!"
done
# (each sink says READY on stderr once it is bound; a slow host is waited for, a sink that died is reported)
i=0
while [ $i -lt 600 ]; do
    r=0
    for n in 2 3 4 5 6; do grep -q READY "$T/sink$n.err" 2>/dev/null && r=$((r + 1)); done
    [ $r -eq 5 ] && break
    sleep 0.1; i=$((i + 1))
done
if [ $r -ne 5 ]; then echo "  [FAIL] only $r of 5 NOTIFY sinks are bound after $((i / 10)) s"; cat "$T"/sink*.err; exit 1; fi
start_srv() {
    : > "$T/srv.log"                     # (the background job truncates it later: the line of the previous server must not be seen as this one's)
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete ($((i / 10)) s)" || { fail "no 'initial load complete' after $((i / 10)) s"; tail -20 "$T/srv.log"; }
    sleep 1
}
oom() { $KCTL dbstatus "$1" 2>/dev/null | grep -q "out of memory"; }       # oom ZONE: its data is out of memory
q() { ./dag @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=5 +tries=1 2>/dev/null | head -1; }
got() { grep -c "qname=$2 " "$T/l$1" 2>/dev/null; }                        # got N ZONE: the NOTIFY messages the sink at 127.0.0.N received for the zone
all_empty() { for n in 2 3 4 5 6; do [ -s "$T/l$n" ] && return 1; done; return 0; }
wait_got() {   # wait_got N ZONE SECONDS
    i=0; while [ $i -lt $(($3 * 10)) ] && [ "$(got "$1" "$2")" -eq 0 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(got "$1" "$2")" -gt 0 ]
}
bump() {   # bump ZONE SERIAL: the SOA serial changes in the database and the loader reads the zone (karictl reload)
    sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns0.$1 host.$1 $2 3600 600 86400 300' WHERE type = 'SOA' AND name = '$1'"
    $KCTL reload "$1" > /dev/null 2>&1
}

echo "== notify yes: the zones are out of memory, nothing is sent at the start"
conf yes
start_srv
oom c1.test && oom prov.test && oom inz.test && oom res.test && pass "the zones start out of memory (a summary each)" || fail "a zone is in memory at the start"
sleep 5
all_empty && pass "no NOTIFY at the start of the server (no storm)" || { fail "NOTIFY at the start"; cat "$T"/l[2-6]; }
LP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1)
if [ -n "$LP" ]; then
    kill -9 "$LP"
    i=0; while [ $i -lt 100 ]; do NLP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s 3' | head -1); [ -n "$NLP" ] && [ "$NLP" != "$LP" ] && break; sleep 0.1; i=$((i + 1)); done
    sleep 5
    all_empty && pass "no NOTIFY after the loader was restarted (its comparison with the Backend's inventory sends nothing for a zone that did not change)" || { fail "NOTIFY after the loader restart"; cat "$T"/l[2-6]; }
else
    fail "no loader process"
fi
$KCTL reload > /dev/null 2>&1
sleep 4
all_empty && pass "no NOTIFY after a reload that changed nothing" || { fail "NOTIFY after a full reload"; cat "$T"/l[2-6]; }

echo "== a zone that is out of memory changes: its NS hosts live in another zone that is out of memory"
bump c1.test 2
if wait_got 2 c1.test 10 && wait_got 3 c1.test 10; then
    pass "c1.test: NOTIFY to ns1.prov.test (127.0.0.2) and ns2.prov.test (127.0.0.3): the addresses come from the database (the loader), not from a zone in memory"
else fail "c1.test: 127.0.0.2 got $(got 2 c1.test), 127.0.0.3 got $(got 3 c1.test)"; fi
sleep 1
[ "$(got 4 c1.test)" -eq 0 ] && [ "$(got 5 c1.test)" -eq 0 ] && [ "$(got 2 inz.test)" -eq 0 ] && [ "$(got 2 c2.test)" -eq 0 ] && pass "only c1.test was notified, and only its two hosts" || fail "unexpected NOTIFY: $(cat "$T"/l[2-6])"
oom c1.test && oom prov.test && pass "c1.test and prov.test are still out of memory (nothing was read for the NOTIFY)" || fail "a zone was read"
grep -q "zone 'c1.test.' (data out of memory): NOTIFY to 2 address" "$T/srv.log" && pass "logged: [Notify] zone 'c1.test.' (data out of memory): NOTIFY to 2 address(es)" || fail "no log line for c1.test: $(grep Notify "$T/srv.log" | tail -3)"
$KCTL dbstatus 2>/dev/null | grep -q "^notify of zones out of memory: queued=[1-9]" && pass "karictl dbstatus counts it (queued)" || fail "dbstatus: $($KCTL dbstatus 2>/dev/null | grep '^notify')"
bump c2.test 2
wait_got 2 c2.test 10 && pass "c2.test (one NS host in prov.test): NOTIFY to ns1.prov.test" || fail "c2.test: 127.0.0.2 got $(got 2 c2.test)"
sleep 1
[ "$(got 3 c2.test)" -eq 0 ] && pass "... and not to ns2.prov.test (c2.test has no such NS host)" || fail "c2.test was sent to 127.0.0.3"

echo "== the NS host is inside the zone: the glue of the apex"
bump inz.test 2
wait_got 4 inz.test 10 && pass "inz.test: NOTIFY to ns1.inz.test (127.0.0.4)" || fail "inz.test: 127.0.0.4 got $(got 4 inz.test)"
oom inz.test && pass "inz.test is still out of memory" || fail "inz.test was read"

# (minimal-responses: an answer of res2.test would carry its NS with the glue of ns1.prov.test, and the glue of a sibling that is out of memory is asked for in the
# background since D1a step 8: prov.test must stay out of memory here to show the apex path)
echo "== a zone in memory is notified as before"
[ "$(q www.res.test)" = "192.0.2.80" ] && ! oom res.test && pass "a query loads res.test" || fail "res.test was not loaded"
bump res.test 2
wait_got 5 res.test 10 && pass "res.test (in memory): NOTIFY to ns1.res.test (127.0.0.5), from its image" || fail "res.test: 127.0.0.5 got $(got 5 res.test)"
[ "$(q www.res2.test)" = "192.0.2.80" ] && ! oom res2.test && oom prov.test && pass "a query loads res2.test, whose NS host ns1.prov.test is in prov.test, which is out of memory" || fail "res2.test was not loaded"
bump res2.test 2
wait_got 2 res2.test 10 && pass "res2.test (in memory): NOTIFY to ns1.prov.test (127.0.0.2): the address is in the glue of the apex of prov.test, which is out of memory" || fail "res2.test: 127.0.0.2 got $(got 2 res2.test)"
oom prov.test && pass "prov.test is still out of memory" || fail "prov.test was read"
stop_srv
: > "$T/l2"; : > "$T/l3"; : > "$T/l4"; : > "$T/l5"; : > "$T/l6"

echo "== notify explicit: the also-notify list only"
conf explicit
start_srv
sleep 3
all_empty && pass "no NOTIFY at the start" || { fail "NOTIFY at the start"; cat "$T"/l[2-6]; }
bump also.test 2
wait_got 6 also.test 10 && pass "also.test: NOTIFY to the address of its ALSO-NOTIFY metadata (127.0.0.6)" || fail "also.test: 127.0.0.6 got $(got 6 also.test)"
bump c1.test 3
sleep 4
[ "$(got 2 also.test)" -eq 0 ] && [ "$(got 2 c1.test)" -eq 0 ] && [ "$(got 3 c1.test)" -eq 0 ] && pass "the NS hosts (ns1.prov.test, ns2.prov.test) are not notified; a zone with no also-notify list sends nothing" || fail "NOTIFY to an NS host: $(cat "$T"/l[2-6])"
stop_srv
: > "$T/l2"; : > "$T/l3"; : > "$T/l4"; : > "$T/l5"; : > "$T/l6"

echo "== notify no"
conf no
start_srv
bump c1.test 4
bump also.test 3
bump inz.test 3
sleep 5
all_empty && pass "nothing is sent" || { fail "NOTIFY with notify no"; cat "$T"/l[2-6]; }
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
