#!/bin/sh
# run_db_inview_test.sh - zone "x" { in-view "v1"; } where x is a zone of the database of v1 (D1a step 9, design 9, in-view phase 2; BIND 9.20 bin/named/server.c
# configure_zone(): the zone of the second view is the zone object of the first), with the real karidns, the real karidns-dbloader and SQLite3.
#
#   - a query, an AXFR and a NOTIFY that come through the view that shares the zone are answered as in the owner view, for a zone that is in memory and for one that
#     is not (the Backend asks for the zone in the owner's name, the query waits for it, and the zone is the owner's: one fetch)
#   - the sibling glue comes from the view of the query: an NS host in another zone is glued in the view that names that zone too, and not in the one that does not
#   - the ACL follows `in-view-settings`: with `view` the stub's allow-query refuses a client of the sharing view that the owner view answers
#   - only the names the configuration wrote are shared: a zone that comes into the database of v1 is not served in the sharing view, one that leaves it is gone from
#     both, and comes back in both when it returns, with no change of the configuration; a name that is no zone of v1 is REFUSED
# Needs root (the loader runs as nobody, loopback aliases 127.0.0.2 and 127.0.0.3).  SKIP without karidns, dag, karictl, karidns-dbloader (SQLite3), sqlite3 or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user, loopback aliases)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl ./karicheck "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_inview.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
ALIASES=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
cleanup() {
    [ $FAILS -ne 0 ] && { echo "--- server log"; tail -30 "$T/srv.log" 2>/dev/null; }
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

for ip in 127.0.0.2 127.0.0.3; do
    ifconfig lo0 2>/dev/null | grep -q "inet $ip " && continue
    if ifconfig lo0 inet "$ip/32" alias 2>/dev/null || ifconfig lo inet "$ip/32" alias 2>/dev/null; then
        ALIASES="$ALIASES $ip"
    else
        echo "SKIP: loopback alias $ip is not configured (ifconfig lo0 inet $ip/32 alias)"; exit 0
    fi
done

mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
# a, b: shared; g: its NS host is in b (sibling glue); c: the stub of the sharing view has an allow-query; n: not named by any sharing view (added later)
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE'), ('b.test', 'NATIVE'), ('g.test', 'NATIVE'), ('c.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 5 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains WHERE name <> 'g.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.b.test', 3600, 0, 0 FROM domains WHERE name = 'g.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 600, 0, 0 FROM domains WHERE name <> 'g.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains WHERE name <> 'g.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'h' || n.i || '.' || d.name, 'A', '10.0.0.' || (n.i + 1), 300, 0, 0
  FROM domains d, (SELECT 0 AS i UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4) n WHERE d.name = 'a.test';
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains;
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.2' FROM domains;
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
conf() {   # conf: v1 takes the database, v2 and v3 share some of its zones
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate 5000; park-timeout 4000;
               acl-ceiling { 127.0.0.1; 127.0.0.2; }; memory-limit 64m; auto-reload yes; poll-interval 1; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
view "v1" { match-clients { 127.0.0.1; }; };
view "v2" {
    match-clients { 127.0.0.2; };
    database none;
    in-view-settings view;
    zone "a.test" { in-view "v1"; };
    zone "b.test" { in-view "v1"; };
    zone "g.test" { in-view "v1"; };
    zone "c.test" { in-view "v1"; allow-query { 192.0.2.99; }; };
    zone "ghost.test" { in-view "v1"; };
};
view "v3" {
    match-clients { 127.0.0.3; };
    database none;
    zone "g.test" { in-view "v1"; };
};
EOF
}
start_srv() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv.log" && pass "the startup batch is complete ($((i / 10)) s)" || { fail "no 'initial load complete' after $((i / 10)) s"; tail -20 "$T/srv.log"; }
    sleep 1
}
issued() { $KCTL dbstatus 2>/dev/null | grep '^fetch:' | sed -n 's/.* issued=\([0-9]*\).*/\1/p' | tail -1; }
oom() { $KCTL dbstatus "$1" 2>/dev/null | grep -q "out of memory"; }       # oom ZONE: its data is out of memory
# D SRC ARGS...: dag from the address SRC (127.0.0.1 = v1, 127.0.0.2 = v2, 127.0.0.3 = v3)
D() { s=$1; shift; ./dag -b "$s" @127.0.0.1 -p "$PORT" "$@" 2>/dev/null; }
ans() { s=$1; shift; D "$s" "$@" +short +nohexdump +time=5 +tries=1 | head -1; }
rcode() { s=$1; shift; D "$s" "$@" +nohexdump +time=5 +tries=1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
addl() { s=$1; shift; D "$s" "$@" +noall +additional +nohexdump +time=5 +tries=1 | awk '{ print $4 }' | tr '\n' ' '; }
axfr() { s=$1; shift; D "$s" "$@" AXFR +nohexdump +noall +answer | grep -v '^;' | sort; }
wait_oom() {   # wait_oom ZONE SECONDS: the zone's data leaves memory (the cache manager)
    i=0; while [ $i -lt $(($2 * 10)) ] && ! oom "$1"; do sleep 0.1; i=$((i + 1)); done
    oom "$1"
}
wait_ans() {   # wait_ans SRC NAME EXPECTED SECONDS
    i=0; while [ $i -lt $(($4 * 10)) ]; do [ "$(ans "$1" "$2" A)" = "$3" ] && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
notify_rcode() {   # notify_rcode SRC ZONE: the rcode of a NOTIFY (opcode 4) for ZONE sent from the address SRC
    perl tests/db/udp_notify_probe.pl "$1" 127.0.0.1 "$PORT" "$2"
}

echo "== the configuration is accepted"
conf
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1 && pass "karicheck accepts zone { in-view } of zones of the database" || { fail "karicheck: $(head -3 "$T/kc.out")"; }
start_srv

echo "== a zone that is out of memory, through the sharing view"
oom a.test && oom b.test && oom g.test && pass "the zones start out of memory (a summary each)" || fail "a zone is in memory at the start"
I0=$(issued)
R2=$(ans 127.0.0.2 www.a.test)
[ "$R2" = "192.0.2.80" ] && pass "v2: www.a.test is answered (the query waited for the zone of v1)" || fail "v2: www.a.test: '$R2'"
[ "$(issued)" = "$((I0 + 1))" ] && ! oom a.test && pass "one fetch, in the owner's name; the zone is in memory now" || fail "issued $(issued) (was $I0); a.test out of memory: $(oom a.test && echo yes || echo no)"
[ "$(ans 127.0.0.1 www.a.test)" = "192.0.2.80" ] && [ "$(issued)" = "$((I0 + 1))" ] && pass "v1 answers from the same zone (no second fetch)" || fail "v1: $(ans 127.0.0.1 www.a.test); issued $(issued)"
[ "$(ans 127.0.0.3 www.a.test)" = "" ] && [ "$(rcode 127.0.0.3 www.a.test A)" = "REFUSED" ] && pass "v3 does not name a.test: REFUSED" || fail "v3: www.a.test is served ($(rcode 127.0.0.3 www.a.test A))"
[ "$(rcode 127.0.0.2 www.ghost.test A)" = "REFUSED" ] && pass "v2: a name that is no zone of v1 (ghost.test) is REFUSED" || fail "v2: ghost.test: $(rcode 127.0.0.2 www.ghost.test A)"

echo "== AXFR and NOTIFY through the sharing view"
wait_oom a.test 15 > /dev/null
axfr 127.0.0.1 a.test > "$T/a.v1"
wait_oom a.test 15 > /dev/null
axfr 127.0.0.2 a.test > "$T/a.v2"
NA=$(wc -l < "$T/a.v1" | tr -d ' ')
[ "$NA" -ge 10 ] && cmp -s "$T/a.v1" "$T/a.v2" && pass "AXFR of a.test through v2 is the same record set as through v1 ($NA records), also when the zone was out of memory" || { fail "AXFR differs or is short ($NA records)"; diff "$T/a.v1" "$T/a.v2" | head -5; }
axfr 127.0.0.3 a.test > "$T/a.v3"
[ ! -s "$T/a.v3" ] && pass "AXFR through v3 (a.test is not shared there) gives nothing" || fail "AXFR through v3: $(head -2 "$T/a.v3")"
N1=$(notify_rcode 127.0.0.1 a.test)
N2=$(notify_rcode 127.0.0.2 a.test)
[ -n "$N1" ] && [ "$N1" = "$N2" ] && pass "NOTIFY for a.test: the same answer through v1 and v2 (rcode $N1)" || fail "NOTIFY: v1 '$N1', v2 '$N2'"
wait_oom b.test 15 > /dev/null
N1=$(notify_rcode 127.0.0.1 b.test)
N2=$(notify_rcode 127.0.0.2 b.test)
[ -n "$N1" ] && [ "$N1" = "$N2" ] && oom b.test && pass "... and for b.test (out of memory) through v1 and v2 (rcode $N1), and the zone was not read for it" || fail "NOTIFY b.test: v1 '$N1', v2 '$N2'; out of memory: $(oom b.test && echo yes || echo no)"

echo "== sibling glue comes from the view of the query"
ans 127.0.0.1 www.b.test > /dev/null          # b.test in memory
G1=$(addl 127.0.0.1 g.test NS)
G2=$(addl 127.0.0.2 g.test NS)
G3=$(addl 127.0.0.3 g.test NS)
[ "$G1" = "A " ] && [ "$G2" = "A " ] && pass "the glue of ns1.b.test (a sibling) is in the answer in v1 and in v2 (both name b.test)" || fail "glue: v1 '$G1', v2 '$G2'"
[ -z "$G3" ] && [ "$(ans 127.0.0.3 g.test NS)" != "" ] && pass "... and not in v3, which names g.test and not b.test" || fail "glue in v3: '$G3'"

echo "== the ACL follows in-view-settings"
[ "$(rcode 127.0.0.1 www.c.test A)" = "NOERROR" ] && pass "v1: c.test is answered" || fail "v1: c.test $(rcode 127.0.0.1 www.c.test A)"
[ "$(rcode 127.0.0.2 www.c.test A)" = "REFUSED" ] && pass "v2 (in-view-settings view): the stub's allow-query refuses this client" || fail "v2: c.test $(rcode 127.0.0.2 www.c.test A)"
[ "$(rcode 127.0.0.2 www.a.test A)" = "NOERROR" ] && pass "v2: a.test, whose stub has no allow-query, is answered" || fail "v2: a.test $(rcode 127.0.0.2 www.a.test A)"

echo "== only the names written are shared; the database may change"
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('n.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.n.test host.n.test 5 3600 600 86400 300', 900, 0, 0 FROM domains WHERE name = 'n.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.n.test', 'A', '192.0.2.81', 300, 0, 0 FROM domains WHERE name = 'n.test';
SQL
wait_ans 127.0.0.1 www.n.test 192.0.2.81 15 && pass "n.test, added to the database, is served in v1" || fail "v1: n.test is not served"
[ "$(rcode 127.0.0.2 www.n.test A)" = "REFUSED" ] && pass "... and not in v2, which does not name it" || fail "v2: n.test $(rcode 127.0.0.2 www.n.test A)"
sqlite3 "$T/db/z.db" "DELETE FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = 'a.test'); DELETE FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = 'a.test'); DELETE FROM domains WHERE name = 'a.test';"
i=0; while [ $i -lt 200 ] && [ "$(rcode 127.0.0.1 www.a.test A)" != "REFUSED" ]; do sleep 0.1; i=$((i + 1)); done
[ "$(rcode 127.0.0.1 www.a.test A)" = "REFUSED" ] && [ "$(rcode 127.0.0.2 www.a.test A)" = "REFUSED" ] && pass "a.test, removed from the database, is gone from v1 and from v2 (the configuration is the same)" || fail "after the removal: v1 $(rcode 127.0.0.1 www.a.test A), v2 $(rcode 127.0.0.2 www.a.test A)"
[ "$(ans 127.0.0.2 www.b.test)" = "192.0.2.80" ] && pass "v2 goes on serving b.test" || fail "v2: b.test: $(ans 127.0.0.2 www.b.test)"
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.a.test host.a.test 6 3600 600 86400 300', 900, 0, 0 FROM domains WHERE name = 'a.test';
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.a.test', 'A', '192.0.2.82', 300, 0, 0 FROM domains WHERE name = 'a.test';
SQL
wait_ans 127.0.0.2 www.a.test 192.0.2.82 15 && pass "a.test is back in the database: v2 serves it again, with no change of the configuration" || fail "v2: a.test after it returned: '$(ans 127.0.0.2 www.a.test)'"

echo "== a reload of the configuration keeps the sharing"
$KCTL reconfig > /dev/null 2>&1
sleep 2
[ "$(ans 127.0.0.2 www.b.test)" = "192.0.2.80" ] && pass "after karictl reconfig v2 still serves b.test" || fail "after reconfig: v2 b.test '$(ans 127.0.0.2 www.b.test)'"
[ "$(rcode 127.0.0.3 www.b.test A)" = "REFUSED" ] && pass "and v3 still does not" || fail "v3: b.test $(rcode 127.0.0.3 www.b.test A)"
grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report in the server log"
stop_srv

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
