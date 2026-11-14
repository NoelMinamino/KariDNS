#!/bin/sh
# run_db_memadvice_test.sh - the server says what the database needs in memory (0.7 P-F, dns_mem_advice.c): syslog lines, `karictl dbstatus`, karicheck db.
#
# Real karidns, the real loader, SQLite3.  300 zones of 63 records each (about 7 KB in memory each, about 2.2 MB in all).  Checked:
#   A  no memory-limit: after the start one INFO line with the estimate (every zone is in memory, so the size of a zone is the measured one) and nothing
#      else (no NOTICE, WARNING or ERROR); dbstatus has the `memory:` line ("no memory-limit", status=ok).  A reconfig that sets memory-limit 1m says it
#      again as a WARNING (a limit that keeps less than half of the zones) with the recommended memory-limit.
#   B  memory-limit 1800k from the start: the directory is read as summaries, so the first INFO line has to assume the size of a zone ("assumed 11
#      records") and says nothing more; after every zone has been asked for (about 230 fit) the size is the measured one and the server says it again, with a
#      NOTICE (below what every zone needs, about 80% fit); a reconfig to 8m says an INFO line only (keeps 100%); dbstatus shows each state.
#   C  at run time: memory-limit 1m, park-timeout 500, the loader stopped (SIGSTOP: no fetch is ever answered) and a burst of queries for zones that are not
#      in memory: one WARNING that names the queries that waited and were answered SERVFAIL + EDE 14 for overload (the park-timeout counter), the numbers
#      and the recommended memory-limit; not said again within a minute.
#   D  karicheck db counts the database (the loader's M line) and says the same about it: INFO with the records counted, the WARNING of a small limit, no
#      warning of a limit that holds everything, an estimate without a limit.
# Needs root (the loader runs as nobody).  SKIP without karidns, karictl, karidns-dbloader (SQLite3), sqlite3 or perl; D without karicheck.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./karictl "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=300; NH=60
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_memadv.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 150 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
trap 'stop_srv; rm -rf "$T"' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" <<SQL
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ - 1)))
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 300, 0, 0 FROM domains;
WITH RECURSIVE k(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM k WHERE j < $((NH - 1)))
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.%d.%d.%d', (CAST(substr(d.name, 2, 4) AS INTEGER) % 200) + 1, k.j / 200, k.j % 200 + 1), 300, 0, 0
  FROM domains d, k;
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

# conf EXTRA-DATABASE-OPTIONS
conf() {
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    waitlog "\[DB\] initial load complete" 30 || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
}
# waitlog PATTERN SECONDS [NTH]: until the log has at least NTH (default 1) lines matching PATTERN
waitlog() {
    i=0; n=$(($2 * 10))
    while [ $i -lt $n ] && [ "$(grep -c "$1" "$T/srv.log" 2>/dev/null)" -lt "${3:-1}" ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(grep -c "$1" "$T/srv.log" 2>/dev/null)" -ge "${3:-1}" ]
}
count() { c=$(grep -c "$1" "$T/srv.log" 2>/dev/null); echo "${c:-0}"; }
memline() { $KCTL dbstatus 2>/dev/null | grep '^memory:'; }
reconf() { conf "$1"; $KCTL reconfig > "$T/reconfig.out" 2>&1 || { fail "karictl reconfig: $(head -2 "$T/reconfig.out")"; return 1; }; }

echo "== A: no memory-limit"
conf ""
start_srv
waitlog "memory sizing:" 10 && pass "the server says what the database needs" || fail "no 'memory sizing' line"
L=$(grep "memory sizing:" "$T/srv.log" | head -1)
echo "  $L" | cut -c1-400
echo "$L" | grep -q "300 zone(s)" && pass "the zone count is the database's" || fail "zone count: $L"
echo "$L" | grep -q "from the zones in memory" && pass "every zone is in memory, so the size of a zone is the measured one" || fail "basis: $L"
echo "$L" | grep -q "no memory-limit" && pass "the line says there is no memory-limit and what limit would keep every zone" || fail "no limit text: $L"
sleep 2
[ "$(count "is below what every zone needs\|keeps only\|is too small")" = 0 ] && pass "no NOTICE, WARNING or ERROR without memory-limit" || fail "advice without a limit: $(grep "keeps only\|is too small\|below what" "$T/srv.log" | head -2)"
M=$(memline)
echo "  $M" | cut -c1-300
echo "$M" | grep -q "zones=300 " && echo "$M" | grep -q "no memory-limit" && echo "$M" | grep -q "status=ok" && echo "$M" | grep -q "recommended=" && pass "karictl dbstatus has the memory: line" || fail "dbstatus: $M"
N0=$(count "memory sizing:")
reconf "memory-limit 1m;" && {
    waitlog "keeps only" 10 && pass "a reconfig with memory-limit 1m: a WARNING (less than half of the zones fit)" || fail "no WARNING after the reconfig: $(tail -5 "$T/srv.log")"
    W=$(grep "keeps only" "$T/srv.log" | head -1)
    echo "  $W" | cut -c1-500
    echo "$W" | grep -q "memory-limit 1M keeps only" && echo "$W" | grep -q "recommended [0-9]*[MG]" && pass "it names the limit, the share and the recommended memory-limit" || fail "text: $W"
    [ "$(count "memory sizing:")" -gt "$N0" ] && pass "the estimate is said again with it (INFO)" || fail "no INFO line after the reconfig"
    M=$(memline)
    echo "$M" | grep -q "memory-limit=1M" && echo "$M" | grep -q "status=warning" && pass "dbstatus: memory-limit=1M, status=warning" || fail "dbstatus after the reconfig: $M"
}
stop_srv

echo "== B: memory-limit 1800k from the start"
conf "memory-limit 1800k; fetch-rate 5000; park-timeout 4000;"
start_srv
waitlog "memory sizing:" 10 && pass "the first line comes after the directory is read" || fail "no 'memory sizing' line"
L=$(grep "memory sizing:" "$T/srv.log" | head -1)
echo "  $L" | cut -c1-300
echo "$L" | grep -q "assumed 11 records a zone" && pass "no zone is in memory yet: the size of a zone is assumed, and it says so" || fail "basis: $L"
[ "$(count "is below what every zone needs\|keeps only")" = 0 ] && pass "no advice from an assumed size that fits" || fail "advice on the assumed size"
perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ $NH sweep > "$T/sweep.out" 2> "$T/sweep.err"
grep -q "wrong=0" "$T/sweep.out" || { fail "the sweep: $(cat "$T/sweep.out")"; head -3 "$T/sweep.err"; }
waitlog "is below what every zone needs" 30 && pass "after every zone was asked for: the NOTICE (below what every zone needs)" || fail "no NOTICE: $(grep "memory" "$T/srv.log" | tail -4)"
L=$(grep "memory sizing:" "$T/srv.log" | tail -1)
echo "  $L" | cut -c1-300
echo "$L" | grep -q "from the zones in memory" && pass "the size of a zone is the measured one now" || fail "basis: $L"
Nt=$(grep "is below what every zone needs" "$T/srv.log" | head -1)
echo "  $Nt" | cut -c1-400
echo "$Nt" | grep -q "recommended memory-limit [0-9]*[MG]" && echo "$Nt" | grep -q "keeps half of the zones" && pass "the NOTICE has the recommended memory-limit and the one that keeps half of the zones" || fail "notice: $Nt"
[ "$(count "keeps only")" = 0 ] && pass "not a WARNING: more than half of the zones fit" || fail "a WARNING at 1800k"
M=$(memline)
echo "  $M" | cut -c1-400
echo "$M" | grep -q "status=notice" && pass "dbstatus: status=notice" || fail "dbstatus: $M"
N1=$(count "memory sizing:"); NN=$(count "is below what every zone needs"); NW=$(count "keeps only")
reconf "memory-limit 8m; fetch-rate 5000; park-timeout 4000;" && {
    waitlog "memory sizing:" 10 $((N1 + 1)) && pass "a reconfig with memory-limit 8m: the estimate is said again" || fail "nothing said after the reconfig to 8m"
    L=$(grep "memory sizing:" "$T/srv.log" | tail -1)
    echo "$L" | grep -q "keeps 100% of the zones" && pass "... and every zone fits" || fail "8m: $L"
    sleep 1
    [ "$(count "is below what every zone needs")" = "$NN" ] && [ "$(count "keeps only")" = "$NW" ] && pass "... without a NOTICE or a WARNING" || fail "advice for a limit that holds every zone"
    M=$(memline)
    echo "$M" | grep -q "fit=100%" && echo "$M" | grep -q "status=ok" && pass "dbstatus: fit=100%, status=ok" || fail "dbstatus: $M"
}

echo "== C: at run time, a burst of queries for zones that are not in memory"
NW=$(count "is too small for the traffic")
reconf "memory-limit 1m; park-timeout 500;" || true
sleep 2
LP=$(pgrep -P "$SRV" -f 'karidns-dbloader -s' | head -1)
[ -n "$LP" ] && kill -STOP "$LP" || fail "no loader process"
cat > "$T/burst.pl" <<'EOPL'
use strict; use IO::Socket::INET;
my ($port, $nz, $n, $secs) = @ARGV;
my $s = IO::Socket::INET->new(Proto => 'udp', PeerAddr => "127.0.0.1:$port") or die "socket: $!";
for my $i (0 .. $n - 1) {
    my $z = sprintf('z%04d.test', ($i * 7 + 3) % $nz);
    my $q = pack('nnnnnn', $i & 0xffff, 0x0100, 1, 0, 0, 0) . join('', map { pack('C/a*', $_) } split(/\./, "h0.$z")) . pack('Cnn', 0, 1, 1);
    $s->send($q);
    select(undef, undef, undef, $secs / $n);
}
EOPL
perl "$T/burst.pl" "$PORT" $NZ 300 14 &
BP=$!
waitlog "is too small for the traffic" 40 $((NW + 1)) && pass "the burst made the server warn" || fail "no run-time warning: $(tail -5 "$T/srv.log")"
wait $BP 2>/dev/null
W=$(grep "is too small for the traffic" "$T/srv.log" | tail -1)
echo "  $W" | cut -c1-700
echo "$W" | grep -q "memory-limit 1M is too small for the traffic" && echo "$W" | grep -q "queries (" && echo "$W" | grep -q "had to wait for a zone" && pass "it names the limit and the queries that waited" || fail "text: $W"
echo "$W" | grep -q "answered SERVFAIL + EDE 14 for overload" && echo "$W" | grep -q "park-timeout" && echo "$W" | grep -q "refused" && pass "... and the queries that were answered SERVFAIL + EDE 14 for overload, with the counters" || fail "overload text: $W"
echo "$W" | grep -q "recommended [0-9]*[MG] (every zone in memory" && pass "... and the recommended memory-limit" || fail "recommendation: $W"
perl "$T/burst.pl" "$PORT" $NZ 300 14
[ -n "$LP" ] && kill -CONT "$LP"
[ "$(count "is too small for the traffic")" = $((NW + 1)) ] && pass "not said again within a minute while it lasts" || fail "said $(count "is too small for the traffic") times"
stop_srv

echo "== D: karicheck db"
if [ -x ./karicheck ]; then
    conf "memory-limit 1m;"
    ./karicheck db "$T/k.conf" > "$T/kc1.out" 2>&1; rc=$?
    grep "memory sizing" "$T/kc1.out" | head -1 | cut -c1-300
    grep -q "memory sizing: 300 zone(s) (18900 records counted in the database)" "$T/kc1.out" && pass "the database was counted: 300 zones, 18900 records" || fail "count: $(grep -i "sizing\|error" "$T/kc1.out" | head -3)"
    grep -q "memory-limit 1M keeps only" "$T/kc1.out" && pass "memory-limit 1m: the warning with the recommendation" || fail "no warning: $(tail -5 "$T/kc1.out")"
    grep -q "warnings: [1-9]" "$T/kc1.out" && [ $rc -eq 0 ] && pass "counted as a warning, the exit status is 0" || fail "summary / exit status $rc: $(tail -2 "$T/kc1.out")"
    conf "memory-limit 8m;"
    ./karicheck db "$T/k.conf" > "$T/kc2.out" 2>&1
    grep -q "memory sizing" "$T/kc2.out" && ! grep -q "keeps only\|below what every zone needs\|is too small" "$T/kc2.out" && pass "memory-limit 8m: the estimate, no warning" || fail "8m: $(grep -i "sizing\|keeps\|below" "$T/kc2.out" | head -3)"
    conf ""
    ./karicheck db "$T/k.conf" > "$T/kc3.out" 2>&1
    grep -q "no memory-limit" "$T/kc3.out" && ! grep -q "keeps only\|below what every zone needs\|is too small" "$T/kc3.out" && pass "no memory-limit: the estimate only" || fail "no limit: $(grep -i "sizing" "$T/kc3.out" | head -3)"
else
    echo "  (karicheck is not built: not checked)"
fi

if grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null; then fail "sanitizer report in the server log"; fi
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
