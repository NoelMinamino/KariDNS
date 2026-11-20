[ "$(sf store.zones.nonstore)" = 0 ] && pass "nothing is counted as unstorable after the restart" || fail "store.zones.nonstore=$(sf store.zones.nonstore) after the restart"waitfor 30 ns_chg && pass "a change of the zone shows with the store on and off" || fail "the change of the long zone is not served"waitfor 30 ns_up && pass "the 250-character zone is answered with the store on" || fail "the 250-character zone is not answered"
#!/bin/sh
# run_db_store_test.sh - the zone store in the server (0.7 store S2): write-through of installed zones, ATTACH of zones that are out of memory, restart from the store,
# a damaged record, a stale record.  The real karidns, the real karidns-dbloader and SQLite3.
#
# The database holds STORE_ZONES zones (default 2000) of about 35 records each.  The server under test has memory-limit 1m and a store; a second server (the reference)
# reads the same database with every zone in memory and no store.  Checked:
#   - every query is answered; the first pass over the zones reads them from the loader (the fetch counter of dbstatus goes up) and the store holds them all afterwards
#   - after zones were taken out of memory a second pass is answered by ATTACH: the fetch counter stays where it was, the attach counter of `karictl store` goes up, zones were
#     detached, and the answers (answer, authority and additional sections of a set of queries on a subset of the zones) are those of the reference server, byte for byte
#   - kill -9 of the server, a restart on the same store, the loader stopped (SIGSTOP) once the directory is there: the zones are answered from the store alone (no fetch), the
#     answers are the reference's
#   - one byte of a record is damaged (the server stopped cleanly first): that zone is read from the database (a fetch, the damage is counted, a line is logged) and answered
#     right; the other zones still attach
#   - a zone that the database changes (new serial) is not answered from the old record: the new data is seen at once and still after the zone was taken out of memory again
#   - karicheck: a store directory whose parent does not exist is an error; `store none;` and `store-mode copy;` are accepted, `store-mode bogus;` is an error
#   - 0.7 S6, the cleaner: the zones of the database are changed again and again (segments of 1 MiB): the segments that are dead are cleaned and removed (`karictl store compact`),
#     the dead share falls, the answers are those of the reference server before and after, and after kill -9 and a restart
#   - 0.7 S6, disk full (needs ZFS and the variable STORE_ZFS_PARENT, a dataset to make children of, e.g. STORE_ZFS_PARENT=bench/store/st9; SKIP without): a dataset with a quota
#     of 100 MB (segments of 64 MB, so the reserve is 32 MB: ZFS makes every writer wait for a transaction group when a quota has less than about a fifth left, because it counts the
#     mapped tables worst case; the store stops writing images before that): updates are made room for by the cleaner; more zones than fit make the store degraded (ERROR in the log, `store.state=degraded`, every zone is still answered
#     right: from the database); when the zones are gone and the cleaner has won the room back the state is ok again.  The record size warning of a dataset with the default 128K.
# The whole test runs once in TMPDIR (UFS: map mode, ZFS: copy mode: the mode is printed; STORE_MODE=copy|map forces one).  Needs root (the loader runs as nobody).  SKIP without the binaries, sqlite3 or perl.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
LOADER=${LOADER:-./karidns-dbloader}
for b in "$KARIDNS" ./dag ./karictl ./karicheck "$LOADER"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

NZ=${STORE_ZONES:-2000}
STEP=${STORE_SUBSET_STEP:-33}                   # every STEP-th zone is in the subset that is compared with the reference
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbstore.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""; REF=""
stop_one() {
    p=$1
    [ -n "$p" ] && kill -TERM "$p" 2>/dev/null
    i=0; while [ -n "$p" ] && [ $i -lt 200 ] && kill -0 "$p" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$p" ] && kill -KILL "$p" 2>/dev/null
}
ZFS_DS=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    [ -n "$REF" ] && kari_kill_tree "$REF"
    kari_kill_conf "$T/a.conf" "$T/b.conf"
    for ds in $ZFS_DS; do zfs destroy -f "$ds" > /dev/null 2>&1; done
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PA=$(kari_port 0 $((22000 + $$ % 15000)))
PB=$(kari_port 1 $((22000 + $$ % 15000 + 1)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"

echo "== the database: $NZ zones"
mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" "PRAGMA journal_mode=WAL" > /dev/null
sqlite3 "$T/db/z.db" <<SQL
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $NZ)
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns2.' || name, 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.1', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns2.' || name, 'AAAA', '2001:db8::2', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'MX', 'mail.' || name, 300, 10, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'mail.' || name, 'A', '192.0.2.25', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'TXT', '"v=spf1 -all"', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, '*.w.' || name, 'A', '192.0.2.99', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'alias.' || name, 'CNAME', 'www.' || name, 300, 0, 0 FROM domains;
WITH RECURSIVE m(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM m WHERE j < 24)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || m.j || '.' || d.name, 'A', '192.0.2.' || (m.j % 250 + 1), 300, 0, 0 FROM domains d, m;
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
for x in a b; do
    cat > "$T/$x.ctl.conf" <<EOF
socket "$T/$x.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
    chmod 600 "$T/$x.ctl.conf"
done
KA="./karictl -c $T/a.ctl.conf"
KB="./karictl -c $T/b.ctl.conf"
conf() {   # conf a|b "extra database statements"
    if [ "$1" = a ]; then port=$PA; else port=$PB; fi
    cat > "$T/$1.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $port; notify no;
    database { driver sqlite3; database-file "${DBFILE:-$T/db/z.db}"; loader-user "nobody"; loader-path "${LPATH:-$T/karidns-dbloader}"; acl-ceiling { 127.0.0.1; };
               park-timeout 5000; $2 };
};
control-channel { socket "$T/$1.sock"; secret "$SECRET"; };
EOF
}
start_one() {   # start_one a|b : sets SRV / REF
    : > "$T/$1.log"
    "$KARIDNS" -c "$T/$1.conf" -f > "$T/$1.log" 2>&1 &
    p=$!
    if [ "$1" = a ]; then SRV=$p; else REF=$p; fi
    i=0
    while [ $i -lt 1200 ] && ! grep -q "\[DB\] initial load complete" "$T/$1.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/$1.log" && pass "server $1: the startup batch is complete" || { fail "server $1: no 'initial load complete'"; tail -20 "$T/$1.log"; }
}
sf() {   # sf KEY: a value of `karictl store -k` on the server under test
    $KA store -k 2>/dev/null | sed -n "s/^$1=//p" | head -1
}
fetches() { $KA dbstatus 2>/dev/null | grep '^fetch:' | head -1 | sed -n 's/.* issued=\([0-9]*\).*/\1/p'; }
park_drops() { echo "store.park.drop room=$(sf store.park.drop.room) timeout=$(sf store.park.drop.timeout) queue=$(sf store.park.drop.queue)"; }
zname() { printf 'z%04d.test' "$1"; }
waitfor() {   # waitfor SECONDS COMMAND...
    w=$1; shift
    i=0
    while [ $i -lt $((w * 10)) ]; do "$@" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
# pass_all FIRST LAST STEP: a www query for each zone, 8 at a time; prints the number that were not answered with 192.0.2.80
pass_all() {
    z=$1; bad=0; n=0; pids=""
    while [ "$z" -ge 1 ] && [ "$z" -le "$NZ" ]; do
        k=0
        while [ $k -lt 8 ] && [ "$z" -ge 1 ] && [ "$z" -le "$NZ" ]; do
            ./dag @127.0.0.1 -p "$PA" "www.$(zname $z)" A +short +nohexdump +time=8 +tries=3 > "$T/q.$k" 2>/dev/null &
            pids="$pids $!"
            z=$((z + $3)); k=$((k + 1))
        done
        wait $pids; pids=""
        j=0
        while [ $j -lt $k ]; do
            [ "$(head -1 "$T/q.$j")" = "192.0.2.80" ] || bad=$((bad + 1))
            j=$((j + 1))
        done
        n=$((n + k))
    done
    PASS_N=$n
    PASS_BAD=$bad
    [ "$bad" = 0 ] || echo "  $bad queries not answered right: $(park_drops)"
}
# the answers of the subset on a port, normalised, into FILE
subset_answers() {   # subset_answers PORT FILE
    sp=$1; sout=$2
    : > "$sout.tmp"
    z=1
    while [ $z -le "$NZ" ]; do
        zn=$(zname $z)
        zu=$(echo "$zn" | tr a-z A-Z)
        for q in "$zn SOA" "$zn NS" "$zn MX" "$zn TXT" "www.$zn A" "alias.$zn CNAME" "x.w.$zn A" "nx.$zn A" "$zn DNSKEY" "ns2.$zn AAAA" "WWW.$zu A"; do
            qn=${q% *}; qt=${q##* }
            echo "## $q" >> "$sout.tmp"
            ./dag @127.0.0.1 -p "$sp" "$qn" "$qt" +noall +answer +authority +additional +nohexdump 2> /dev/null | tr 'A-Z' 'a-z' | sort >> "$sout.tmp"
        done
        z=$((z + STEP))
    done
    mv "$sout.tmp" "$sout"
}

echo "== the reference server (every zone in memory, no store) and the server under test (memory-limit 1m, a store)"
conf b "store none;"
start_one b
conf a "memory-limit 1m; store \"$T/store\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
start_one a
M=$(sf store.mode)
echo "  store mode: ${M:-?}; file system of the store: $(sf store.fstype)"
[ -n "$M" ] && [ "$(sf store.state)" != "none" ] && pass "the store is on" || { fail "karictl store says no store: $($KA store 2>&1 | head -5)"; }
$KA store -j 2>/dev/null | perl -MJSON::PP -e 'local $/; my $d = decode_json(<STDIN>); exit(($d->{"store.state"} // $d->{store}{state} // "") eq "ok" ? 0 : 1)' && pass "karictl store -j is one JSON object and says the state is ok" || fail "karictl store -j: $($KA store -j 2>&1 | head -c 300)"
ls "$T/store" > "$T/store.ls" 2>&1
grep -q '^super\.' "$T/store.ls" && pass "the directory holds a store ($(wc -l < "$T/store.ls" | tr -d ' ') files)" || fail "no store files in $T/store: $(cat "$T/store.ls")"
[ "$(stat -f %Su "$T/store" 2>/dev/null || stat -c %U "$T/store")" = "nobody" ] && pass "the directory belongs to the user the server runs as" || fail "owner of the store directory: $(ls -ld "$T/store")"

echo "== the first pass: the startup batch put every zone in the store; the zones that do not fit under memory-limit are not kept in memory"
stored_all() { [ "$(sf store.zones.stored)" -ge "$NZ" ] 2>/dev/null; }
waitfor 60 stored_all && pass "the store holds all $NZ zones (written when they were installed)" || fail "the store holds $(sf store.zones.stored) of $NZ zones"
[ "$(sf store.zones.attached)" -lt "$NZ" ] 2>/dev/null && pass "not every zone is in memory (memory-limit 1m): $(sf store.zones.attached) of $NZ attached" || fail "all zones are in memory: $(sf store.zones.attached)"
pass_all 1 "$NZ" 1
P1=$PASS_N
[ "$PASS_BAD" = 0 ] && pass "all $PASS_N queries of the first pass were answered right" || fail "$PASS_BAD of $PASS_N queries of the first pass were wrong"
F1=$(fetches)
[ "${F1:-0}" = "$NZ" ] && pass "every zone was read from the loader once, by the background fetch of the store protocol, and the queries of the first pass read none (fetch issued=$F1)" || fail "fetch issued=$F1 in the first pass, want $NZ (one body per zone): $($KA dbstatus | grep -E '^(fetch|cache):')"
[ "$(sf store.attach.count)" -gt 0 ] 2>/dev/null && pass "zones were attached from the store ($(sf store.attach.count))" || fail "no attach in the first pass"

echo "== the second pass: zones that are out of memory are attached from the store"
A0=$(sf store.attach.count); A0=${A0:-0}
pass_all "$NZ" 1 -1
P2=$PASS_N
[ "$PASS_BAD" = 0 ] && pass "all $PASS_N queries of the second pass were answered right" || fail "$PASS_BAD of $PASS_N queries of the second pass were wrong"
F2=$(fetches)
A1=$(sf store.attach.count); A1=${A1:-0}
[ "$F2" = "$F1" ] && pass "no zone was read from the loader in the second pass (fetch issued stays $F2)" || fail "fetch issued went from $F1 to $F2: $($KA dbstatus | grep -E '^(fetch|cache):')"
[ "$A1" -gt "$A0" ] && pass "zones were attached from the store ($((A1 - A0)) attaches, cold attach $(sf store.cold.attach), p50 $(sf store.attach.p50_us) us, p99 $(sf store.attach.p99_us) us)" || fail "no attach in the second pass: $($KA store | head -30)"
[ "$(sf store.detach.count)" -gt 0 ] 2>/dev/null && pass "zones were taken out of memory ($(sf store.detach.count) detaches)" || fail "no detach: $($KA dbstatus | grep '^cache:')"
# 0.7 store S5 (design 6.1): the counters of a zone that leaves memory are folded into the totals, so the totals of `karictl stats` do not go back with the detaches (the alerts look at their change), and the
# busiest zones that are not in memory are listed after the zones that are (a table of 128 rows in the heap)
ST_ALL=$($KA stats 2>/dev/null)
ST_Q=$(printf '%s\n' "$ST_ALL" | sed -n 's/^karidns_queries_total{proto="udp"} \([0-9]*\)$/\1/p'); ST_T=$(printf '%s\n' "$ST_ALL" | sed -n 's/^karidns_queries_total{proto="tcp"} \([0-9]*\)$/\1/p')
ST_SUM=$(( ${ST_Q:-0} + ${ST_T:-0} ))
[ "$ST_SUM" -ge $(( P1 + P2 )) ] 2>/dev/null && pass "the totals of karictl stats kept every query of the two passes ($ST_SUM of $((P1 + P2)); only $(sf store.zones.attached) zones are in memory)" || fail "karictl stats counts $ST_SUM queries, the passes sent $((P1 + P2)): the counters of the zones that left memory are lost"
ST_ROWS=$(printf '%s\n' "$ST_ALL" | grep -c '^karidns_zone_queries_total{.*proto="udp"')
ST_ATT=$(sf store.zones.attached)
[ "$ST_ROWS" -gt "$ST_ATT" ] 2>/dev/null && [ "$ST_ROWS" -le $(( ST_ATT + 128 )) ] 2>/dev/null && pass "karictl stats lists the zones in memory ($ST_ATT) and, after them, the busiest zones that left it ($((ST_ROWS - ST_ATT)) of at most 128)" || fail "karictl stats lists $ST_ROWS zones with $ST_ATT in memory"
[ "$(sf store.attach.failed)" = 0 ] && pass "no attach failed" || fail "attach failures: $(sf store.attach.failed)"
echo "  answers on the subset: the server with the store against the reference"
subset_answers "$PB" "$T/ref.ans"
subset_answers "$PA" "$T/a1.ans"
if cmp -s "$T/ref.ans" "$T/a1.ans" && [ -s "$T/ref.ans" ]; then pass "the answers are the reference's ($(grep -c '^##' "$T/ref.ans") queries, $(wc -l < "$T/ref.ans" | tr -d ' ') lines)"; else fail "the answers differ from the reference"; diff -u "$T/ref.ans" "$T/a1.ans" | head -60; fi
waitfor 30 stored_all >/dev/null

echo "== kill -9, a restart on the same store, the loader stopped: answered from the store alone"
kari_kill_tree "$SRV"; SRV=""
sleep 0.5
conf a "memory-limit 1m; store \"$T/store\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
start_one a
grep -q "\[Store\] the zone store is on" "$T/a.log" && pass "the store was opened again ($(grep '\[Store\] the zone store is on' "$T/a.log" | sed 's/.*zone store is on: //'))" || fail "no 'zone store is on' line after the restart: $(grep Store "$T/a.log" | head -3)"
LPID=$(sed -n 's/.*Database loader .* started (pid \([0-9]*\)).*/\1/p' "$T/a.log" | tail -1)
if [ -n "$LPID" ]; then kill -STOP "$LPID"; pass "the loader (pid $LPID) is stopped"; else fail "could not find the loader process"; fi
pass_all 1 "$NZ" 1
[ "$PASS_BAD" = 0 ] && pass "all $PASS_N queries are answered with the loader stopped" || fail "$PASS_BAD of $PASS_N queries were not answered with the loader stopped"
[ "$(fetches)" = 0 ] && pass "no zone was read from the loader (fetch issued=0)" || fail "fetch issued=$(fetches) after the restart"
[ "$(sf store.attach.count)" -gt 0 ] 2>/dev/null && pass "the zones were attached from the store ($(sf store.attach.count))" || fail "no attach after the restart: $($KA store | head -20)"
subset_answers "$PA" "$T/a2.ans"
if cmp -s "$T/ref.ans" "$T/a2.ans"; then pass "the answers after the restart are the reference's"; else fail "the answers after the restart differ"; diff -u "$T/ref.ans" "$T/a2.ans" | head -60; echo "  $(park_drops)"; $KA store -k 2>/dev/null | grep -E "^store.(attach|cold|park|wa)" | head -40; fi
[ -n "$LPID" ] && kill -CONT "$LPID" 2>/dev/null

echo "== a damaged record: that zone is read from the database, the others still attach"
stop_one "$SRV"; SRV=""
DZ=$(zname $((NZ / 2 + 7)))
perl -e '
    my ($f, $name) = @ARGV;
    my $bad = 0;
    for my $seg (glob("$f/seg.*")) {
        open(my $h, "+<:raw", $seg) or next;
        local $/; my $d = <$h>;
        my $p = index($d, "www.$name");
        next if $p < 0;
        seek($h, $p + 3, 0); print $h "#"; $bad = 1; close $h; last;
    }
    exit($bad ? 0 : 1);' "$T/store" "$DZ" && pass "a byte of the record of $DZ was damaged" || fail "no record of $DZ found in the segments"
conf a "memory-limit 1m; store \"$T/store\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
start_one a
r=$(./dag @127.0.0.1 -p "$PA" "www.$DZ" A +short +nohexdump +time=10 +tries=1 2>/dev/null | head -1)
[ "$r" = "192.0.2.80" ] && pass "the zone with the damaged record is answered right (read from the database)" || fail "zone $DZ answered '$r'"
[ "$(fetches)" -ge 1 ] 2>/dev/null && pass "it was fetched (fetch issued=$(fetches))" || fail "no fetch for the damaged zone"
dmg=$(sf store.attach.fail.checksum); inv=$(sf store.attach.fail.invalid); rec=$(sf store.attach.fail.record)
[ "$(( ${dmg:-0} + ${inv:-0} + ${rec:-0} ))" -ge 1 ] && pass "the damage was counted (checksum $dmg, invalid $inv, record $rec)" || fail "no attach failure was counted: $($KA store | head -30)"
grep -q "\[Store\] the record of zone '$DZ\.' .* cannot be used" "$T/a.log" && pass "the log says so" || fail "no log line about $DZ: $(grep -i store "$T/a.log" | head -3)"
B1=$(sf store.attach.count)
pass_all 1 "$NZ" 7
[ "$PASS_BAD" = 0 ] && pass "$PASS_N other queries are answered right" || fail "$PASS_BAD of $PASS_N queries were wrong"
[ "$(sf store.attach.count)" -gt "${B1:-0}" ] && pass "the other zones were attached" || fail "no attach of the other zones"

echo "== a zone the database changes is not answered from the old record"
CZ=$(zname 3)
NF=$(fetches)
sqlite3 "$T/db/z.db" "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'new.' || name, 'A', '192.0.2.123', 300, 0, 0 FROM domains WHERE name = '$CZ';
UPDATE records SET content = 'ns1.$CZ host.$CZ 2 3600 600 86400 300' WHERE type = 'SOA' AND name = '$CZ';"
$KA reload "$CZ" > "$T/reload.out" 2>&1
waitfor 10 sh -c "[ \"\$(./dag @127.0.0.1 -p $PA new.$CZ A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)\" = 192.0.2.123 ]" && pass "the changed zone shows the new data" || fail "the changed zone does not show the new record: $(cat "$T/reload.out")"
pass_all 1 "$NZ" 3
[ "$PASS_BAD" = 0 ] || fail "$PASS_BAD queries wrong while the zones were evicted"
[ "$(./dag @127.0.0.1 -p "$PA" "new.$CZ" A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)" = "192.0.2.123" ] && pass "and still after other zones pushed it out of memory and it came back (from the store)" || fail "the changed zone lost its new record"
stop_one "$SRV"; SRV=""
stop_one "$REF"; REF=""

# ---------------------------------------------------------------- zones the store cannot name: the root zone, a name of 250 characters
echo "== a 250-character zone name (the longest the store keeps) and the root zone (the loader refuses it): with the store as without it, after a change, a kill -9 and a restart"
LONG=$(perl -e 'print join(".", ("a" x 61, "b" x 61, "c" x 61, "d" x 61, "ab"))')
mkdir "$T/db5"
sqlite3 "$T/db5/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db5/z.db" "PRAGMA journal_mode=WAL" > /dev/null
sqlite3 "$T/db5/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('.', 'NATIVE'), ('$LONG', 'NATIVE'), ('znorm.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.nsx.test. host.nsx.test. 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.nsx.test.', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'A', '192.0.2.61', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'TXT', '"apex"', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.62', 300, 0, 0 FROM domains WHERE name = 'znorm.test';
SQL
chown -R nobody "$T/db5"; chmod 600 "$T/db5/z.db"*
DBFILE="$T/db5/z.db"
nsq() {   # nsq PORT FILE: the answers (rcode, answer, authority, additional) of the apex and a missing name of the three zones, normalised
    sp=$1; sout=$2
    : > "$sout.tmp"
    for q in ". SOA" ". NS" ". A" ". TXT" "x. A" "nx.znorm.test. A" "$LONG. SOA" "$LONG. NS" "$LONG. A" "$LONG. TXT" "$LONG. MX" "x.$LONG. A" "znorm.test. A" "www.znorm.test. A"; do
        qn=${q% *}; qt=${q##* }
        echo "## $q" >> "$sout.tmp"
        ./dag @127.0.0.1 -p "$sp" "$qn" "$qt" +nohexdump +time=8 +tries=1 2> /dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1 >> "$sout.tmp"
        ./dag @127.0.0.1 -p "$sp" "$qn" "$qt" +noall +answer +authority +additional +nohexdump 2> /dev/null | tr 'A-Z' 'a-z' | sort >> "$sout.tmp"
    done
    mv "$sout.tmp" "$sout"
}
ns_up() { [ "$(./dag @127.0.0.1 -p "$PA" "$LONG." A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)" = 192.0.2.61 ]; }
conf b "store none;"
start_one b
conf a "store \"$T/store5\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
start_one a
waitfor 30 ns_up && pass "the 250-character zone is answered with the store on" || fail "the 250-character zone is not answered"
nsq "$PB" "$T/ns.ref"
nsq "$PA" "$T/ns.a1"
grep -q 'SOA' "$T/ns.ref" && [ "$(grep -c 192.0.2.61 "$T/ns.ref")" -ge 2 ] && pass "the reference serves the zone ($(grep -c '^##' "$T/ns.ref") queries)" || fail "the reference does not serve the zones: $(head -12 "$T/ns.ref")"
if cmp -s "$T/ns.ref" "$T/ns.a1"; then pass "the answers with the store are the reference's, byte for byte"; else fail "the answers with the store differ"; diff "$T/ns.ref" "$T/ns.a1" | head -10; fi
[ "$(sf store.zones.stored)" = 2 ] && [ "$(sf store.zones.nonstore)" = 0 ] && pass "the 250-character name is in the store (stored=2, nonstore=0: the store keeps names up to 255 bytes)" || fail "stored=$(sf store.zones.stored) nonstore=$(sf store.zones.nonstore)"
rootrefused() { grep -q "root zone is not supported" "$T/b.log"; }
waitfor 10 rootrefused && pass "the loader refuses the root zone (it is not served with or without the store)" || fail "no refusal of the root zone in the logs"
# a change: the new data comes by the change log
sqlite3 "$T/db5/z.db" "UPDATE records SET content = '192.0.2.99' WHERE type = 'A' AND domain_id IN (SELECT id FROM domains WHERE name = '$LONG'); UPDATE records SET content = 'ns1.nsx.test. host.nsx.test. 2 3600 600 86400 300' WHERE type = 'SOA' AND domain_id IN (SELECT id FROM domains WHERE name = '$LONG');"
$KA reload > /dev/null 2>&1; $KB reload > /dev/null 2>&1
ns_chg() { [ "$(./dag @127.0.0.1 -p "$PB" "$LONG." A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)" = 192.0.2.99 ] && [ "$(./dag @127.0.0.1 -p "$PA" "$LONG." A +short +nohexdump +time=8 +tries=1 2>/dev/null | head -1)" = 192.0.2.99 ]; }
waitfor 30 ns_chg && pass "a change of the zone shows with the store on and off" || fail "the change of the long zone is not served"
waitfor 5 sh -c 'sleep 1'
nsq "$PB" "$T/ns.ref2"
nsq "$PA" "$T/ns.a2"
cmp -s "$T/ns.ref2" "$T/ns.a2" && pass "the answers after the change are the reference's" || { fail "the answers after the change differ"; diff "$T/ns.ref2" "$T/ns.a2" | head -10; }
# kill -9, a restart on the same store
kari_kill_tree "$SRV"; SRV=""
sleep 0.5
conf a "store \"$T/store5\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
start_one a
waitfor 30 ns_chg && pass "after kill -9 and a restart the zone is served again" || fail "after the restart the long zone is not served"
nsq "$PA" "$T/ns.a3"
cmp -s "$T/ns.ref2" "$T/ns.a3" && pass "the answers after the restart are the reference's, byte for byte" || { fail "the answers after the restart differ"; diff "$T/ns.ref2" "$T/ns.a3" | head -10; }
[ "$(sf store.zones.nonstore)" = 0 ] && [ "$(sf store.zones.stored)" = 2 ] && pass "both zones are in the store after the restart" || fail "nonstore=$(sf store.zones.nonstore) stored=$(sf store.zones.stored) after the restart"
# a clean restart as well
stop_one "$SRV"; SRV=""
start_one a
waitfor 30 ns_chg && pass "after a clean stop and a start the zone is served again" || fail "after the clean restart the zone is not served"
stop_one "$SRV"; SRV=""
stop_one "$REF"; REF=""
unset DBFILE

# ---------------------------------------------------------------- 0.7 S3: the store is the directory
COLD_N=${STORE_COLD_ZONES:-20000}
HEAP_N=${STORE_HEAP_ZONES:-100000}
cc -O1 -o "$T/dbquery" tests/db/dbquery.c 2> "$T/cc.log" || { echo "SKIP: tests/db/dbquery.c does not compile"; cat "$T/cc.log"; }
printf '#!/bin/sh\nexec sleep 100000\n' > "$T/idle-loader"
chown 0:0 "$T/idle-loader"; chmod 755 "$T/idle-loader"
# the Backend's resident set (KiB): the biggest karidns process
backend_rss() {
    ps -ax -o pid= -o rss= -o comm= | awk '$3 == "karidns" { if ($2 > m) m = $2 } END { print m + 0 }'
}
# start_cold a|b: a server whose loader never says anything (an idle program in its place): up when the store is open
start_cold() {
    : > "$T/$1.log"
    "$KARIDNS" -c "$T/$1.conf" -f > "$T/$1.log" 2>&1 &
    p=$!
    if [ "$1" = a ]; then SRV=$p; else REF=$p; fi
    i=0
    while [ $i -lt 1200 ] && ! grep -q "\[Store\] the zone store is on" "$T/$1.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[Store\] the zone store is on" "$T/$1.log" || { fail "server $1: the store did not come up"; tail -10 "$T/$1.log"; return 1; }
    return 0
}
# the queries of the comparison: for every zone the apex types, a name that is not there, a wildcard, a CNAME, a delegation, DS, in the three flavours (plain, EDNS DO=0, DO=1)
gen_cold_queries() {   # gen_cold_queries N > list
    awk -v n="$1" 'BEGIN {
        for (i = 1; i <= n; i++) {
            z = "z" i ".test."
            print z " SOA p"; print z " NS e"; print z " MX d"; print z " A p"; print z " AAAA e"; print z " DS d"; print z " DNSKEY d"
            print "www." z " A p"; print "www." z " A d"; print "nx." z " A d"; print "a.b.nx." z " TXT e"
            print "x.w." z " A d"; print "h3." z " A p"; print "h5." z " CNAME e"; print "h7." z " A d"; print "h2." z " TXT p"
            print "www.sub." z " A d"; print "sub." z " NS e"; print "WWW." toupper(z) " A p"
        }
    }'
}
if [ -x "$T/dbquery" ]; then
    echo "== store-cold: $COLD_N zones; a server restarted on the store with an idle loader answers like the reference (every zone, NXDOMAIN, NODATA, wildcard, CNAME, delegation, DS, DO=1)"
    mkdir "$T/db2"
    sh tests/db/gen_sqlite3_zones.sh "$T/db2/z.db" "$COLD_N" 20 > /dev/null 2>&1 || fail "the database of $COLD_N zones was not made"
    sqlite3 "$T/db2/z.db" "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, '*.w.' || name, 'A', '192.0.2.99', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'sub.' || name, 'NS', 'ns.sub.' || name || '.', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns.sub.' || name, 'A', '192.0.2.55', 300, 0, 0 FROM domains;" > /dev/null 2>&1
    chown -R nobody "$T/db2"; chmod 600 "$T/db2/z.db"*
    gen_cold_queries "$COLD_N" > "$T/cold.list"
    DBFILE="$T/db2/z.db"
    conf b "store none;"
    start_one b
    conf a "memory-limit 4m; store \"$T/store2\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
    start_one a
    stored2() { [ "$(sf store.zones.stored)" -ge "$COLD_N" ] 2>/dev/null; }
    waitfor 120 stored2 && pass "the store holds all $COLD_N zones" || fail "the store holds $(sf store.zones.stored) of $COLD_N zones"
    stop_one "$SRV"; SRV=""
    LPATH="$T/idle-loader"
    conf a "memory-limit 4m; store \"$T/store2\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
    start_cold a && pass "the server is up on the store with an idle loader"
    "$T/dbquery" -p "$PB" -t 5 "$T/cold.list" "$T/cold.ref" > /dev/null 2>&1
    "$T/dbquery" -p "$PA" -t 5 "$T/cold.list" "$T/cold.a" > /dev/null 2>&1
    NQC=$(wc -l < "$T/cold.list" | tr -d ' ')
    if [ "$(wc -l < "$T/cold.a" | tr -d ' ')" = "$NQC" ] && cmp -s "$T/cold.ref" "$T/cold.a"; then pass "$NQC queries over $COLD_N zones: every answer is the reference's, byte for byte"; else fail "the cold answers differ from the reference ($(wc -l < "$T/cold.a" | tr -d ' ') of $NQC lines)"; diff "$T/cold.ref" "$T/cold.a" | head -6; fi
    [ "$(fetches)" = 0 ] && pass "no zone was read from the loader" || fail "fetch issued=$(fetches)"
    [ "$(sf store.attach.failed)" = 0 ] && pass "no attach failed ($(sf store.attach.count) attaches)" || fail "attach failures: $(sf store.attach.failed)"
    $KA dbstatus "z$((COLD_N / 2)).test" > "$T/zs2.out" 2>&1
    grep -q "z$((COLD_N / 2)).test" "$T/zs2.out" && pass "dbstatus <zone> finds a zone of the store: $(head -1 "$T/zs2.out" | cut -c1-110)" || fail "dbstatus <zone>: $(head -2 "$T/zs2.out")"
    stop_one "$SRV"; SRV=""
    stop_one "$REF"; REF=""
    unset DBFILE LPATH

    echo "== heap: $HEAP_N zones in the store, none attached"
    mkdir "$T/db3"
    sh tests/db/gen_sqlite3_zones.sh "$T/db3/z.db" "$HEAP_N" 7 > /dev/null 2>&1 || fail "the database of $HEAP_N zones was not made"
    chown -R nobody "$T/db3"; chmod 600 "$T/db3/z.db"*
    DBFILE="$T/db3/z.db"
    conf a "memory-limit 4m; store \"$T/store3\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
    start_one a
    stored3() { [ "$(sf store.zones.stored)" -ge "$HEAP_N" ] 2>/dev/null; }
    waitfor 300 stored3 && pass "the store holds all $HEAP_N zones" || fail "the store holds $(sf store.zones.stored) of $HEAP_N zones"
    stop_one "$SRV"; SRV=""
    # a server with an empty store is the base: the same process with one zone
    mkdir "$T/db4"; sh tests/db/gen_sqlite3_zones.sh "$T/db4/z.db" 1 7 > /dev/null 2>&1; chown -R nobody "$T/db4"; chmod 600 "$T/db4/z.db"*
    DBFILE="$T/db4/z.db"; LPATH="$T/idle-loader"
    conf a "memory-limit 4m; store \"$T/store4\"; store-threads 2; store-mode ${STORE_MODE:-auto};"
    start_cold a
    ./dag @127.0.0.1 -p "$PA" www.z1.test A +short +nohexdump +time=3 +tries=1 > /dev/null 2>&1
    R0=$(backend_rss)
    stop_one "$SRV"; SRV=""
    DBFILE="$T/db3/z.db"
    conf a "memory-limit 4m; store \"$T/store3\"; store-threads 2; store-mode ${STORE_MODE:-auto}; store-hot-list no;"      # (hot.list would attach the zones of the last stop: this is about a store with nothing attached; the segments are mapped with their cached pages, which RSS counts)
    start_cold a
    ./dag @127.0.0.1 -p "$PA" www.z77.test A +short +nohexdump +time=5 +tries=1 > /dev/null 2>&1
    R1=$(backend_rss)
    EL=$($KA dbstatus | sed -n 's/^zone directory: .*the heap holds \([0-9]*\) elements.*/\1/p' | head -1)
    [ "$(sf store.zones.stored)" -ge "$HEAP_N" ] 2>/dev/null && pass "the restarted server has all $HEAP_N zones in its store ($(sf store.zones.stored))" || fail "stored=$(sf store.zones.stored)"
    [ "${EL:-99999}" -le 2 ] && pass "the heap holds $EL registry element(s) for $HEAP_N stored zones (only the zone that was asked for)" || fail "registry elements: ${EL:-?}"
    DR=$((R1 - R0))
    echo "  Backend RSS: $R0 KiB with an empty store, $R1 KiB with $HEAP_N stored zones (the store's mapped pages are in it): $DR KiB more"
    [ "$DR" -le "${HEAP_RSS_MAX_KIB:-196608}" ] && pass "the Backend with $HEAP_N stored zones is within ${HEAP_RSS_MAX_KIB:-196608} KiB of the one with none ($DR KiB)" || fail "RSS grew by $DR KiB for $HEAP_N stored zones"
    stop_one "$SRV"; SRV=""
    unset DBFILE LPATH
fi

# ---------------------------------------------------------------- 0.7 S6: the cleaner
echo "== the cleaner (0.7 S6): the zones change again and again, the dead segments are cleaned and removed, the answers do not change"
CL_ROUNDS=${STORE_CLEAN_ROUNDS:-5}
conf b "store none;"
start_one b
conf a "memory-limit 1m; store \"$T/storeC\"; store-threads 2; store-mode ${STORE_MODE:-auto}; store-segment-size 1m; store-scrub-interval off;"
start_one a
waitfor 90 stored_all && pass "the store holds all $NZ zones" || fail "the store holds $(sf store.zones.stored) of $NZ zones"
set_serial() {   # set_serial N: the serial of every zone of the database (a change of every zone)
    sqlite3 "$T/db/z.db" "UPDATE records SET content = 'ns1.' || name || ' host.' || name || ' $1 3600 600 86400 300' WHERE type = 'SOA';"
}
serial_of() { ./dag @127.0.0.1 -p "$1" "$(zname "$2")" SOA +short +nohexdump +time=8 +tries=1 2>/dev/null | awk '{print $3}' | head -1; }
bodies_done() { [ "$(sf store.recon.bodies.fetched)" -ge "$1" ] 2>/dev/null; }
maxdead=0
r=1
while [ $r -le "$CL_ROUNDS" ]; do
    set_serial $((10 + r))
    $KA reload > /dev/null 2>&1; $KB reload > /dev/null 2>&1
    waitfor 120 bodies_done $((NZ * (r + 1))) || fail "round $r: only $(sf store.recon.bodies.fetched) bodies fetched, want $((NZ * (r + 1)))"
    dp=$(sf store.segments.dead_pct); [ "${dp:-0}" -gt "$maxdead" ] && maxdead=$dp
    r=$((r + 1))
done
last_serial() { [ "$(serial_of "$PA" "$NZ")" = "$((10 + CL_ROUNDS))" ] && [ "$(serial_of "$PB" "$NZ")" = "$((10 + CL_ROUNDS))" ]; }
waitfor 60 last_serial && pass "$CL_ROUNDS rounds of changes to all $NZ zones were made (every zone was written to the store $((CL_ROUNDS + 1)) times)" || fail "the last serial is not served (a $(serial_of "$PA" "$NZ"), b $(serial_of "$PB" "$NZ"))"
MV0=$(sf store.compact.moved_bytes); FR0=$(sf store.compact.segments_freed)
UB=$(sf store.segments.used_bytes); LB=$(sf store.segments.live_bytes)
FILES0=$(ls "$T/storeC" | grep -c '^seg\.')
echo "  after the rounds: segments used $UB live $LB bytes (dead ${maxdead}% at the most seen), $FILES0 segment files, the cleaner has copied ${MV0:-0} bytes and removed ${FR0:-0} segments by itself"
sleep 1
subset_answers "$PB" "$T/cl.ref"
subset_answers "$PA" "$T/cl.a1"
cmp -s "$T/cl.ref" "$T/cl.a1" && [ -s "$T/cl.ref" ] && pass "the answers are the reference's (before the cleaner is asked to finish)" || { fail "the answers differ from the reference before compaction"; diff "$T/cl.ref" "$T/cl.a1" | head -6; }
$KA store compact > "$T/compact.out" 2>&1
grep -q '^OK' "$T/compact.out" && pass "karictl store compact: $(head -1 "$T/compact.out" | cut -c1-100)" || fail "karictl store compact: $(cat "$T/compact.out")"
cl_idle() { [ "$(sf store.compact.candidates)" = 0 ] && [ "$(sf store.segments.draining)" = 0 ] && [ "$(sf store.segments.pinned)" = 0 ]; }
waitfor 90 cl_idle && pass "the cleaner is done: no segment is dead enough, none waits to be removed" || fail "the cleaner is not done: candidates=$(sf store.compact.candidates) draining=$(sf store.segments.draining) pinned=$(sf store.segments.pinned)"
sleep 2
UB1=$(sf store.segments.used_bytes); LB1=$(sf store.segments.live_bytes); DP1=$(sf store.segments.dead_pct)
FILES1=$(ls "$T/storeC" | grep -c '^seg\.')
echo "  after: segments used $UB1 live $LB1 bytes (dead ${DP1}%), $FILES1 segment files; copied $(sf store.compact.moved_bytes) bytes, removed $(sf store.compact.segments_freed) segments, $(sf store.segments.free_numbers) segment numbers free"
[ "${DP1:-100}" -lt 40 ] && pass "the dead share of the segments is ${DP1}%" || fail "the dead share is still ${DP1}% after the cleaner"
[ "$(sf store.compact.segments_freed)" -ge 1 ] 2>/dev/null && pass "segments were removed ($(sf store.compact.segments_freed))" || fail "no segment was removed"
[ "$UB1" -lt "$UB" ] 2>/dev/null || [ "$(sf store.compact.segments_freed)" -gt "${FR0:-0}" ] 2>/dev/null && pass "the segments hold less than before (used $UB -> $UB1, files $FILES0 -> $FILES1)" || fail "used bytes did not fall: $UB -> $UB1"
[ "$FILES1" -le $(( (LB1 + 1048575) / 1048576 + 3 )) ] && pass "the number of segment files ($FILES1) is about what the live bytes need ($LB1)" || fail "$FILES1 segment files for $LB1 live bytes"
[ "$(sf store.zones.stored)" = "$NZ" ] && [ "$LB1" -ge "$LB" ] 2>/dev/null && pass "every zone is still stored, nothing live was lost ($LB -> $LB1 bytes live)" || fail "stored=$(sf store.zones.stored) live $LB -> $LB1"
[ "$(sf store.compact.bad_records)" = 0 ] && pass "no record was found damaged by the cleaner" || fail "the cleaner found $(sf store.compact.bad_records) damaged records"
subset_answers "$PA" "$T/cl.a2"
cmp -s "$T/cl.ref" "$T/cl.a2" && pass "the answers after the cleaner are the reference's, byte for byte" || { fail "the answers after the cleaner differ"; diff "$T/cl.ref" "$T/cl.a2" | head -6; }
$KA store checkpoint | grep -q '^OK checkpoint' && pass "karictl store checkpoint" || fail "karictl store checkpoint failed"
$KA store scrub start | grep -q '^OK' && pass "karictl store scrub start" || fail "karictl store scrub start failed"
scrub_done() { [ "$(sf store.scrub.passes)" -ge 1 ] 2>/dev/null; }
waitfor 120 scrub_done && pass "the scrub pass is over: $(sf store.scrub.zones_checked) zones, $(sf store.scrub.bytes_checked) bytes read, bad images $(sf store.scrub.bad_images), bad cells $(sf store.scrub.bad_cells), bad index $(sf store.scrub.bad_index)" || fail "the scrub did not end: $($KA store | grep -A12 '^scrub:')"
[ "$(sf store.scrub.bad_images)$(sf store.scrub.bad_cells)$(sf store.scrub.bad_index)" = 000 ] && pass "the scrub found nothing wrong" || fail "the scrub found damage"
# kill -9 and a restart
kari_kill_tree "$SRV"; SRV=""
sleep 0.5
start_one a
subset_answers "$PA" "$T/cl.a3"
cmp -s "$T/cl.ref" "$T/cl.a3" && pass "after kill -9 and a restart the answers are the reference's" || { fail "after the restart the answers differ"; diff "$T/cl.ref" "$T/cl.a3" | head -6; }
[ "$(sf store.zones.stored)" = "$NZ" ] && [ "$(sf store.recovery.rebuilt)" = 0 ] && pass "the restart found every zone in the store without a rebuild" || fail "stored=$(sf store.zones.stored) rebuilt=$(sf store.recovery.rebuilt)"
stop_one "$SRV"; SRV=""
stop_one "$REF"; REF=""
set_serial 1

# ---------------------------------------------------------------- 0.7 S6: disk full, on a small ZFS dataset
if [ -n "${STORE_ZFS_PARENT:-}" ] && command -v zfs > /dev/null 2>&1 && zfs list -H -o name "$STORE_ZFS_PARENT" > /dev/null 2>&1; then
    echo "== a dataset with the default record size (128K): the server says so"
    DS128="$STORE_ZFS_PARENT/rs128.$$"
    ZFS_DS="$DS128"
    zfs create -o recordsize=128k -o compression=lz4 -o atime=off "$DS128" && MP128=$(zfs get -H -o value mountpoint "$DS128")
    if [ -n "${MP128:-}" ] && [ -d "$MP128" ]; then
        chown nobody "$MP128"; chmod 700 "$MP128"
        conf a "memory-limit 1m; store \"$MP128/store\"; store-threads 2; store-segment-size 1m; store-scrub-interval off;"
        start_one a
        [ "$(sf store.fstype)" = zfs ] && [ "$(sf store.mode)" = copy ] && pass "auto: copy mode on ZFS (store.mode=copy)" || fail "fstype=$(sf store.fstype) mode=$(sf store.mode)"
        [ "$(sf store.fs.recordsize_warning)" = 1 ] && [ "$(sf store.fs.blksize)" -gt 32768 ] 2>/dev/null && pass "a record size of $(sf store.fs.blksize): store.fs.recordsize_warning=1" || fail "recordsize_warning=$(sf store.fs.recordsize_warning) blksize=$(sf store.fs.blksize)"
        grep -q "\[Store\] store: the store is on ZFS with a record size of" "$T/a.log" && pass "the log has the WARNING with the recommended value ($(grep -o 'set recordsize=[0-9A-Za-z]*' "$T/a.log" | head -1))" || fail "no record size WARNING in the log: $(grep -i 'record size' "$T/a.log" | head -2)"
        $KA store -k 2>/dev/null | grep -q '^store.memory.arc.total_bytes=' && pass "karictl store has the sum of the Backend, the ARC, the loader and the system against RAM ($($KA store -k | grep -E '^store.memory.arc.(total_bytes|ram_bytes|level)=' | tr '\n' ' '))" || fail "no store.memory.arc.* keys: $($KA store -k | grep -c memory)"
        stop_one "$SRV"; SRV=""
        pass "ZFS: record size checked"
    else
        fail "could not make the dataset $DS128"
    fi
    zfs destroy -f "$DS128" > /dev/null 2>&1; ZFS_DS=""

    echo "== disk full on a dataset with a quota (record size 16K)"
    DSQ="$STORE_ZFS_PARENT/small.$$"
    ZFS_DS="$DSQ"
    zfs create -o quota=${STORE_SMALLFS_QUOTA:-100m} -o recordsize=16k -o compression=off -o atime=off "$DSQ" && MPQ=$(zfs get -H -o value mountpoint "$DSQ")
    if [ -n "${MPQ:-}" ] && [ -d "$MPQ" ]; then
        chown nobody "$MPQ"; chmod 700 "$MPQ"
        conf a "memory-limit 1m; store \"$MPQ/store\"; store-threads 2; store-segment-size 64m; store-scrub-interval off;"
        start_one a
        [ "$(sf store.fs.recordsize_warning)" = 0 ] && pass "a record size of $(sf store.fs.blksize): no warning" || fail "recordsize_warning=$(sf store.fs.recordsize_warning) blksize=$(sf store.fs.blksize)"
        waitfor 90 stored_all && pass "the store holds all $NZ zones ($(sf store.space.fs_free_bytes) bytes free of the quota, reserve $(sf store.space.reserve_bytes))" || fail "the store holds $(sf store.zones.stored) of $NZ zones: $($KA store | grep -E 'state|free' | head -5)"
        r=1
        while [ $r -le ${STORE_SMALLFS_ROUNDS:-12} ]; do
            set_serial $((20 + r))
            $KA reload > /dev/null 2>&1
            waitfor 120 bodies_done $((NZ * (r + 1))) || fail "round $r on the small dataset: only $(sf store.recon.bodies.fetched) bodies fetched"
            r=$((r + 1))
        done
        echo "  ${STORE_SMALLFS_ROUNDS:-12} rounds of changes on a quota of ${STORE_SMALLFS_QUOTA:-100m}: enospc events $(sf store.space.enospc_events), degraded puts $(sf store.space.degraded_puts), segments freed $(sf store.compact.segments_freed), free $(sf store.space.fs_free_bytes)"
        # (a segment of 64 MB on a quota of 100 MB leaves the cleaner little room to copy into: a zone or two may have been kept without an image at the very limit; that is fine, the state ends)
        [ "$(sf store.state)" = ok ] && [ "$(sf store.space.degraded_puts)" -le 3 ] && pass "the updates were made room for by the cleaner: the store is ok (degraded puts: $(sf store.space.degraded_puts))" || fail "state=$(sf store.state) degraded_puts=$(sf store.space.degraded_puts)"
        [ "$(sf store.compact.segments_freed)" -ge 1 ] && pass "segments were freed ($(sf store.compact.segments_freed)) to make the room" || fail "no segment was freed on a full quota"
        # more zones than fit
        EXTRA=${STORE_EXTRA_ZONES:-20000}
        sqlite3 "$T/db/z.db" <<SQL
WITH RECURSIVE n(i) AS (SELECT $((NZ + 1)) UNION ALL SELECT i + 1 FROM n WHERE i < $((NZ + EXTRA)))
INSERT INTO domains (name, type) SELECT printf('z%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns2.' || name, 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.' || name, 'A', '192.0.2.80', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.1', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns2.' || name, 'AAAA', '2001:db8::2', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'MX', 'mail.' || name, 300, 10, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'mail.' || name, 'A', '192.0.2.25', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'TXT', '"v=spf1 -all"', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, '*.w.' || name, 'A', '192.0.2.99', 300, 0, 0 FROM domains WHERE id > $NZ;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'alias.' || name, 'CNAME', 'www.' || name, 300, 0, 0 FROM domains WHERE id > $NZ;
WITH RECURSIVE m(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM m WHERE j < 24)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || m.j || '.' || d.name, 'A', '192.0.2.' || (m.j % 250 + 1), 300, 0, 0 FROM domains d, m WHERE d.id > $NZ;
SQL
        $KA reload > /dev/null 2>&1
        is_degraded() { [ "$(sf store.state)" = degraded ] && [ "$(sf store.space.level)" = degraded ]; }
        waitfor 120 is_degraded && pass "$EXTRA more zones than the quota holds: the store is degraded (store.space.degraded_puts=$(sf store.space.degraded_puts), free $(sf store.space.fs_free_bytes), reserve $(sf store.space.reserve_bytes))" || fail "the store did not become degraded: state=$(sf store.state) free=$(sf store.space.fs_free_bytes) stored=$(sf store.zones.stored) known=$(sf store.zones.known)"
        waitfor 120 sh -c "[ \$($KA store -k 2>/dev/null | sed -n 's/^store.recon.bodies.known=//p' | head -1) = 0 ] || [ \$($KA store -k 2>/dev/null | sed -n 's/^store.state=//p' | head -1) = degraded ]"
        grep -q "\[Store\] store: no room for zone images" "$T/a.log" && pass "the log has the ERROR: $(grep 'no room for zone images' "$T/a.log" | head -1 | cut -c1-200)" || fail "no 'no room for zone images' line in the log"
        [ "$(grep -c 'no room for zone images' "$T/a.log")" -le 3 ] && pass "the ERROR is said once a minute, not for every zone ($(grep -c 'no room for zone images' "$T/a.log") time(s))" || fail "the ERROR was logged $(grep -c 'no room for zone images' "$T/a.log") times"
        [ "$(sf store.space.level)" = degraded ] && [ "$(sf store.state_bits)" -ge 1 ] && pass "karictl store: state degraded, store.space.level=degraded" || fail "space.level=$(sf store.space.level) state_bits=$(sf store.state_bits)"
        # every zone is answered right: the old ones from the store or the database, the new ones (no image) from the database
        pass_all 1 $((NZ + EXTRA)) 37
        [ "$PASS_BAD" = 0 ] && pass "all $PASS_N sampled queries over old and new zones are answered right while the store is degraded" || fail "$PASS_BAD of $PASS_N queries were wrong while the store is degraded"
        [ "$(sf store.space.degraded_puts)" -ge 1 ] && pass "zones were kept without an image: $(sf store.space.degraded_puts)" || fail "no zone was kept without an image"
        # the way back: the extra zones go, the cleaner makes the room
        sqlite3 "$T/db/z.db" "DELETE FROM records WHERE domain_id > $NZ; DELETE FROM domains WHERE id > $NZ;"
        $KA reload -force > /dev/null 2>&1          # (more than a fifth of the zones go: the mass-delete guard holds a plain reload back)
        is_ok() { [ "$(sf store.state)" = ok ]; }
        waitfor 180 is_ok && pass "the extra zones are gone and room is back: the store is ok again (free $(sf store.space.fs_free_bytes), $(sf store.compact.segments_freed) segments freed)" || fail "the store stays degraded: state=$(sf store.state) free=$(sf store.space.fs_free_bytes) known=$(sf store.zones.known) stored=$(sf store.zones.stored)"
        grep -q "\[Store\] store: there is room again" "$T/a.log" && pass "the log says there is room again" || fail "no 'there is room again' line in the log"
        all_stored() { [ "$(sf store.zones.stored)" = "$NZ" ] && [ "$(sf store.zones.known)" = 0 ]; }
        waitfor 180 all_stored && pass "all $NZ zones have an image again" || fail "stored=$(sf store.zones.stored) known=$(sf store.zones.known)"
        pass_all 1 "$NZ" 13
        [ "$PASS_BAD" = 0 ] && pass "$PASS_N queries are answered right after the way back" || fail "$PASS_BAD of $PASS_N queries were wrong after the way back"
        stop_one "$SRV"; SRV=""
    else
        fail "could not make the dataset $DSQ"
    fi
    zfs destroy -f "$DSQ" > /dev/null 2>&1; ZFS_DS=""
    set_serial 1
else
    echo "SKIP: disk full on a small ZFS dataset needs STORE_ZFS_PARENT=<dataset> (and zfs, as root)"
fi

echo "== karicheck"
kc() { ./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1; }
conf a "store \"$T/none/such/dir\";"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && grep -q "store" "$T/kc.out" && pass "a store directory whose parent does not exist is an error: $(grep store "$T/kc.out" | head -1 | cut -c1-120)" || fail "karicheck accepted a store directory with no parent"
conf a "store \"$T/store\"; store-mode copy; store-threads 3;"
cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused a good store configuration: $(grep -i store "$T/kc.out")" || pass "store, store-mode and store-threads are accepted"
conf a "store none;"
cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused store none" || pass "store none is accepted"
conf a "store \"$T/store\"; store-segment-size 4m; store-scrub-interval 3600;"
cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused store-segment-size / store-scrub-interval: $(grep -i store "$T/kc.out")" || pass "store-segment-size 4m and store-scrub-interval 3600 are accepted"
conf a "store \"$T/store\"; store-scrub-interval off;"
cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused store-scrub-interval off" || pass "store-scrub-interval off is accepted"
conf a "store \"$T/store\"; store-hot-list no; store-threads 32;"
cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused store-hot-list no / store-threads 32: $(grep -i store "$T/kc.out")" || pass "store-hot-list no and store-threads 32 are accepted"
conf a "store-hot-list maybe;"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && pass "store-hot-list maybe is an error" || fail "karicheck accepted store-hot-list maybe"
conf a "store-threads 33;"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && pass "store-threads 33 (above 32) is an error" || fail "karicheck accepted store-threads 33"
conf a "store-scrub-interval 5;"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && pass "store-scrub-interval 5 (below a minute) is an error" || fail "karicheck accepted store-scrub-interval 5"
conf a "store-segment-size 4k;"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && pass "store-segment-size 4k (below 1m) is an error" || fail "karicheck accepted store-segment-size 4k"
conf a "store \"$T/store\"; store-max-zones 100000000;"
cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused store-max-zones 100000000: $(grep -i store "$T/kc.out")" || pass "store-max-zones 100000000 is accepted"
conf a "store-max-zones 100;"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && pass "store-max-zones 100 (below 1024) is an error" || fail "karicheck accepted store-max-zones 100"
if [ "$(id -u)" = 0 ]; then
    # the owner and mode rules of the start (L8): the same refusals as the server's
    mkdir -p "$T/wdir" && chmod 0777 "$T/wdir"
    conf a "store \"$T/wdir\";"
    cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && grep -q "written by group or others" "$T/kc.out" && pass "a store directory that group or others can write in is an error (as at the start)" || fail "karicheck accepted a store directory of mode 0777: $(grep -i store "$T/kc.out")"
    mkdir -p "$T/odir" && chmod 0700 "$T/odir" && chown 12345:12345 "$T/odir"
    conf a "store \"$T/odir\";"
    cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && grep -q "belongs to user 12345" "$T/kc.out" && pass "a store directory of another user is an error (as at the start)" || fail "karicheck accepted a store directory of user 12345: $(grep -i store "$T/kc.out")"
    mkdir -p "$T/rdir" && chmod 0700 "$T/rdir"
    conf a "store \"$T/rdir\";"
    cp "$T/a.conf" "$T/k.conf"; kc; grep -E "ERROR|error" "$T/kc.out" | grep -qi "store" && fail "karicheck refused a store directory of root, mode 0700: $(grep -i store "$T/kc.out")" || pass "a store directory of root, mode 0700, is accepted"
else
    skip_msg="owner and mode checks of the store directory need root"; echo "SKIP: $skip_msg"
fi
conf a "store-mode bogus;"
cp "$T/a.conf" "$T/k.conf"; kc; [ $? != 0 ] && pass "store-mode bogus is an error" || fail "karicheck accepted store-mode bogus"

echo
echo "run_db_store_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
