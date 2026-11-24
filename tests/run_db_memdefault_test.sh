#!/bin/sh
# run_db_memdefault_test.sh - the default memory-limit (0.7, small-VPS defaults; dns_mem_advice.c ma_default_limit(), dns_db_ingest.c db_ingest_memory_limit()).
#
# Real karidns, the real loader, SQLite3, the zone store in $T.  12,000 zones of 63 records (about 7 KB in memory each, about 85 MB in all: more than the
# default of a host with 300 MB of RAM, 64M).  KARIDNS_TEST_PHYSMEM=314572800 is the RAM the server derives the default from.  Checked:
#   A  store, no memory-limit: the start says the default at NOTICE (64M, "half of the 300 MB of RAM above 256 MB, at least 64M"); `karictl dbstatus`
#      has it in the cache: line (limit=67108864 ... limit_default=1) and the memory: line ("memory-limit=64M (default)"); after every zone was asked for,
#      the zones in memory stay under it (resident within 115% of the limit + 256 KB, as tests/run_db_cache_test.sh accepts), zones were taken out, every
#      answer was right, and the sizing lines name the default ("memory-limit 64M (the default from 300 MB of RAM)").
#   B  a reconfig to `memory-limit unlimited;`: no limit (cache: no memory-limit); a reconfig without memory-limit again: the default is back (limit_default=1).
#   C  `store none` and no memory-limit: no default (a limit makes a start without the store lazy): cache: no memory-limit, no NOTICE about a default.
#   D  karicheck db says the default it computes from the RAM of this host ("memory-limit is not set: ... (the RAM of this host)").
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

NZ=12000; NH=60
RAM=314572800; LIM=67108864                 # 300 MB of RAM: (300 - 256) / 2 = 22 MB, below the minimum: 64M
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_memdef.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && kill -0 "$SRV" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    SRV=""
}
trap 'stop_srv; rm -rf "$T"' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

mkdir "$T/db" "$T/store"
chown nobody "$T/store" 2>/dev/null
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
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.%d.%d.%d', (CAST(substr(d.name, 2) AS INTEGER) % 200) + 1, k.j / 200, k.j % 200 + 1), 300, 0, 0
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

# conf EXTRA-DATABASE-OPTIONS (the store in $T unless EXTRA says `store none`)
conf() {
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; store "$T/store"; $1 };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
}
start_srv() {
    : > "$T/srv.log"
    KARIDNS_TEST_PHYSMEM=$RAM "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    waitlog "\[DB\] initial load complete" 120 || { fail "no 'initial load complete'"; tail -20 "$T/srv.log"; }
}
# waitlog PATTERN SECONDS [NTH]: until the log has at least NTH (default 1) lines matching PATTERN
waitlog() {
    i=0; n=$(($2 * 10))
    while [ $i -lt $n ] && [ "$(grep -c "$1" "$T/srv.log" 2>/dev/null)" -lt "${3:-1}" ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(grep -c "$1" "$T/srv.log" 2>/dev/null)" -ge "${3:-1}" ]
}
count() { c=$(grep -c "$1" "$T/srv.log" 2>/dev/null); echo "${c:-0}"; }
cacheline() { $KCTL dbstatus 2>/dev/null | grep '^cache:'; }
memline() { $KCTL dbstatus 2>/dev/null | grep '^memory:'; }
field() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }
# waitcache PATTERN SECONDS: until the cache: line matches PATTERN (a reconfig reaches the cache manager within a second)
waitcache() {
    i=0; n=$(($2 * 10))
    while [ $i -lt $n ] && ! cacheline | grep -q "$1"; do sleep 0.1; i=$((i + 1)); done
    cacheline | grep -q "$1"
}
reconf() { conf "$1"; $KCTL reconfig > "$T/reconfig.out" 2>&1 || { fail "karictl reconfig: $(head -2 "$T/reconfig.out")"; return 1; }; }

echo "== A: the zone store, no memory-limit: the default from the RAM ($RAM bytes)"
conf ""
start_srv
waitlog "memory-limit is not set" 10 && pass "the start says the default" || fail "no line about the default: $(grep "\[DB\]" "$T/srv.log" | head -5)"
L=$(grep "memory-limit is not set" "$T/srv.log" | head -1)
echo "  $L" | cut -c1-300
echo "$L" | grep -q "64M is used (the default: half of the 300 MB of RAM above 256 MB, at least 64M)" && pass "64M, and how it was derived" || fail "text: $L"
echo "$L" | grep -q "memory-limit unlimited" && pass "... and how to keep every zone in memory" || fail "no unlimited in: $L"
waitcache "limit_default=1" 5 || true
C=$(cacheline)
echo "  $C" | cut -c1-200
[ "$(field "$C" limit)" = "$LIM" ] && [ "$(field "$C" limit_default)" = 1 ] && pass "dbstatus cache: limit=$LIM limit_default=1" || fail "cache line: $C"
M=$(memline)
echo "$M" | grep -q "memory-limit=64M (default)" && pass "dbstatus memory: memory-limit=64M (default)" || fail "memory line: $M"
CACHE_STRESS_SWEEP_WAIT_S=60 perl tests/db/cache_stress.pl 127.0.0.1 "$PORT" $NZ $NH sweep > "$T/sweep.out" 2> "$T/sweep.err"
echo "  sweep: $(cat "$T/sweep.out")"
grep -q "wrong=0 notready=0 timeout=0" "$T/sweep.out" && pass "every zone answered right" || { fail "the sweep: $(cat "$T/sweep.out")"; head -3 "$T/sweep.err"; }
# the cache manager takes zones out every 50 ms and a zone taken out is freed after the next publication: wait (bounded) for the level to settle under the line
i=0; while [ $i -lt 100 ]; do
    C=$(cacheline); R=$(field "$C" resident)
    [ -n "$R" ] && [ "$R" -le $((LIM * 115 / 100 + 262144)) ] && break
    sleep 0.1; i=$((i + 1))
done
C=$(cacheline); R=$(field "$C" resident); E=$(field "$C" evictions); P=$(field "$C" peak)
echo "  resident=$R peak=$P evictions=$E limit=$LIM"
[ -n "$R" ] && [ "$R" -le $((LIM * 115 / 100 + 262144)) ] && pass "the zones in memory stay under the default (resident $R <= 115% of $LIM + 256 KB)" || fail "resident $R over the default; $C; $($KCTL dbstatus 2>/dev/null | grep '^residency:')"
[ -n "$E" ] && [ "$E" -gt 0 ] && pass "zones were taken out of memory ($E)" || fail "no eviction: $C"
RS=$($KCTL dbstatus 2>/dev/null | grep '^residency:')
echo "  $RS"
RES=$(field "$RS" resident)
[ -n "$RES" ] && [ "$RES" -lt $NZ ] && pass "not every zone is in memory ($RES of $NZ)" || fail "residency: $RS"
waitlog "memory-limit 64M (the default from 300 MB of RAM)" 30 && pass "the sizing lines name the default" || fail "sizing: $(grep "memory sizing\|keeps only\|below what" "$T/srv.log" | tail -2 | cut -c1-300)"

echo "== B: memory-limit unlimited, then unset again"
reconf "memory-limit unlimited;" && {
    waitcache "^cache: no memory-limit" 5 && pass "memory-limit unlimited: no limit" || fail "after unlimited: $(cacheline)"
}
reconf "" && {
    waitcache "limit_default=1" 5 && [ "$(field "$(cacheline)" limit)" = "$LIM" ] && pass "unset again: the default is back" || fail "after unset: $(cacheline)"
}
stop_srv

echo "== C: store none, no memory-limit: no default"
cat > "$T/k.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; store none; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
EOF
start_srv
cacheline | grep -q "^cache: no memory-limit" && pass "without the store an unset memory-limit is no limit" || fail "store none: $(cacheline)"
[ "$(count "memory-limit is not set")" = 0 ] && pass "no line about a default" || fail "a default without the store: $(grep "memory-limit is not set" "$T/srv.log" | head -1)"
stop_srv

echo "== D: karicheck db"
if [ -x ./karicheck ]; then
    conf ""
    ./karicheck db "$T/k.conf" > "$T/kc.out" 2>&1
    grep "memory-limit is not set" "$T/kc.out" | head -1 | cut -c1-300
    grep -q "memory-limit is not set: [0-9]*[MG] is used (the default: half of the .* of RAM above 256 MB, at least 64M).*(the RAM of this host)" "$T/kc.out" && pass "karicheck db says the default of this host" || fail "karicheck: $(grep -i "memory" "$T/kc.out" | head -3 | cut -c1-300)"
    grep -q "(the default from .* of RAM) keeps" "$T/kc.out" && pass "... and its estimate names it" || fail "karicheck estimate: $(grep "memory sizing" "$T/kc.out" | head -1 | cut -c1-400)"
else
    echo "  (karicheck is not built: not checked)"
fi

if grep -q "AddressSanitizer\|runtime error:\|ThreadSanitizer" "$T/srv.log" 2>/dev/null; then fail "sanitizer report in the server log"; fi
echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
