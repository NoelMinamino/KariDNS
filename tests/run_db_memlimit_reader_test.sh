#!/bin/sh
# ==============================================================================
# run_db_memlimit_reader_test.sh
#
# 0.7 (memory-limit, option B): the retired versions that a reader holds are not weighed against memory-limit.  3000 database zones of about
# 4.7 KB, `memory-limit 2m`, `rollback-window 0`, the loader polling the database every second; 280 zones are brought into memory by queries
# (about 1.3 MB, below the high mark of 95 %).  A reader then stays in its read section (TEST ONLY `karictl rcu-hold 60000`; the server with
# the test hooks: ./karidns of `make coverage`, else ./karidns-evict) and a database batch replaces 140 of those zones (about 0.65 MB of
# replaced versions that only the reader's leaving frees):
#   - the batch is applied (the new serial is served);
#   - `held` (karictl dbstatus, line cache:) shows the retired bytes the reader holds, and `retired` is at least that;
#   - no zone that is served is taken out of memory for them (`evictions` does not change, the 140 other zones are still answered from memory:
#     `misses` does not change), and no zone of the batch is left out of memory (`cold` does not change);
#   - after the hold `retired` and `held` are 0.
# Before option B the 0.65 MB counted against the limit (1.7 + 0.65 MB above the high mark) and the manager took the zones that were not
# replaced out of memory.  Root (the loader runs as another user), SQLite3.  SKIP without them or the test hooks.
# MLR_NOHOLD=1 runs the same batch without the reader (a comparison by hand: the checks of the hold then fail).
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
cd "$SCRIPT_DIR/.." || exit 1

[ "$(id -u)" = "0" ] || { echo "SKIP: needs root (the loader runs as another user)"; exit 0; }
has_hook() { [ -x "$1" ] && grep -q 'ERROR bad hold' "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_hook ./karidns; then KARIDNS=./karidns; elif has_hook ./karidns-evict; then KARIDNS=./karidns-evict; else KARIDNS=""; fi
fi
[ -n "$KARIDNS" ] && has_hook "$KARIDNS" || { echo "SKIP: no server with the test hooks (make evict, or the build of make coverage)"; exit 0; }
for b in ./dag ./karictl ./karidns-dbloader; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: ./karidns-dbloader has no SQLite3 driver"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/db_memlimit_reader.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() { kari_kill_tree "$SRV"; rm -rf "$T" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
FAILED=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0}"
P=$(kari_port 0 $((27000 + $$ % 4000)))
SECRET="ZGItbWVtbGltaXQtcmVhZGVyLXRlc3Qta2V5LTAwMDA="
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$T/ctl.conf"; chmod 600 "$T/ctl.conf"
ctl() { ./karictl -t 200 -s "$T/ctl.sock" -f "$T/ctl.conf" "$@" 2>&1; }
# stat NAME: a number of the cache: line of karictl dbstatus
stat() { ctl dbstatus | sed -n "s/^cache: .* $1=\([0-9]*\).*/\1/p" | head -1; }
serial_of() { ./dag @127.0.0.1 -p "$P" "$1" SOA +short +nohexdump +time=2 +tries=2 2>/dev/null | awk '{print $3}' | head -1; }

mkdir "$T/db"; chown nobody "$T/db"; chmod 777 "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
cat > "$T/init.sql" <<'EOF'
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000)
INSERT INTO domains (name, type) SELECT printf('d%04d.test', i), 'NATIVE' FROM n;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'SOA', 'ns1.' || name || ' h.' || name || ' 1 3600 600 86400 300', 300, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains;
WITH RECURSIVE k(j) AS (SELECT 1 UNION ALL SELECT j + 1 FROM k WHERE j < 20)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'h' || j || '.' || name, 'TXT', '"' || hex(randomblob(60)) || '"', 300, 0, 0 FROM domains, k;
EOF
sqlite3 "$T/db/z.db" < "$T/init.sql"
chmod 666 "$T/db/z.db"*
install -o root -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/k.conf" <<EOF
options { user "nobody"; pid-file "none"; port $P; bind-address { 127.0.0.1; }; rollback-window 0;
  database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 1;
             auto-reload yes; poll-interval 1; memory-limit 2m; }; };
control-channel { socket "$T/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 644 "$T/k.conf"
echo "=== memory-limit does not count the retired versions a reader holds ($(basename "$KARIDNS")) ==="
"$KARIDNS" -f "$T/k.conf" > "$T/k.log" 2>&1 &
SRV=$!
kari_wait_answer ./dag "$P" d3000.test 60 || { fail "the server did not start"; tail -20 "$T/k.log"; exit 1; }
q=1; while [ $q -le 280 ]; do ./dag @127.0.0.1 -p "$P" "$(printf 'www.d%04d.test' $q)" A +short +nohexdump +time=3 +tries=2 > /dev/null 2>&1; q=$((q + 1)); done
R0=$(stat resident); E0=$(stat evictions); C0=$(stat cold); M0=$(stat misses)
echo "   after the queries: $(ctl dbstatus | grep '^cache:')"
[ "${R0:-0}" -gt 1000000 ] && [ "${R0:-0}" -lt 1992294 ] && pass "280 zones in memory ($R0 bytes, below the high mark of 2m)" || fail "resident: '$R0'"
if [ -n "${MLR_NOHOLD:-}" ]; then H=OK; else H=$(ctl rcu-hold 60000); fi
[ "$H" = "OK" ] && pass "karictl rcu-hold 60000 (TEST ONLY)" || fail "rcu-hold: '$H'"
# the cache manager samples the readers every second: a reader is long once it has stayed from one sample to the next
i=0; while [ "$(stat long_reader)" != "1" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(stat long_reader)" = "1" ] && pass "dbstatus shows long_reader=1 within 5 s" || fail "long_reader: '$(stat long_reader)'"
sqlite3 "$T/db/z.db" "UPDATE records SET content = REPLACE(content, ' 1 3600 600 ', ' 2 3600 600 ') WHERE type = 'SOA' AND domain_id <= 280 AND domain_id % 2 = 1;"
i=0; while [ "$(serial_of d0279.test)" != "2" ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(serial_of d0279.test)" = "2" ] && pass "the batch replacing 140 of the zones in memory is applied during the hold" || fail "d0279.test: '$(serial_of d0279.test)'"
i=0; while [ "$(stat held)" -lt 500000 ] 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
sleep 3   # (with a limit the cache manager runs a round every 50 ms: give it 60 rounds to act on the retired bytes)
echo "   during the hold: $(ctl dbstatus | grep '^cache:')"
HE=$(stat held); RE=$(stat retired)
[ "${HE:-0}" -gt 500000 ] && [ "${RE:-0}" -ge "${HE:-0}" ] && pass "held=$HE of retired=$RE: the replaced versions the reader holds" || fail "held '$HE', retired '$RE'"
[ "$(stat evictions)" = "$E0" ] && pass "no zone that is served was taken out of memory for them (evictions $E0)" || fail "evictions: $E0 -> $(stat evictions)"
q=2; while [ $q -le 280 ]; do ./dag @127.0.0.1 -p "$P" "$(printf 'www.d%04d.test' $q)" A +short +nohexdump +time=3 +tries=2 > /dev/null 2>&1; q=$((q + 2)); done
[ "$(stat misses)" = "$M0" ] && pass "the 140 zones that were not replaced are answered from memory (misses $M0)" || fail "misses: $M0 -> $(stat misses)"
[ "$(stat cold)" = "$C0" ] && pass "no zone of the batch was left out of memory (cold $C0)" || fail "cold: $C0 -> $(stat cold)"
# what is served is still bounded during the hold: queries for 620 more zones make the manager take zones out for them (resident is still
# weighed in full), and the hard stop of fetches (resident above 110 % of the limit) is unchanged
MAXR=0; q=281
while [ $q -le 900 ]; do
    ./dag @127.0.0.1 -p "$P" "$(printf 'www.d%04d.test' $q)" A +short +nohexdump +time=3 +tries=2 > /dev/null 2>&1
    [ $((q % 20)) -eq 0 ] && { r=$(stat resident); [ "${r:-0}" -gt "$MAXR" ] && MAXR=$r; }
    q=$((q + 1))
done
echo "   after 620 more zones: $(ctl dbstatus | grep '^cache:')"
LIM=2097152
[ "$MAXR" -le $((LIM / 100 * 115 + 262144)) ] && pass "resident stays bounded during the hold (largest seen $MAXR, limit $LIM)" || fail "resident reached $MAXR (limit $LIM)"
[ "$(stat evictions)" -gt "$E0" ] && pass "zones are taken out for the zones that queries bring in ($(stat evictions) evictions)" || fail "no eviction for 620 more zones"
echo "   (waiting for the end of the hold)"
i=0; while [ "$(stat retired)" != "0" ] && [ $i -lt 900 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(stat retired)" = "0" ] && [ "$(stat held)" = "0" ] && pass "after the hold: retired 0, held 0" || fail "after the hold: $(ctl dbstatus | grep '^cache:')"
i=0; while [ "$(stat long_reader)" != "0" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(stat long_reader)" = "0" ] && pass "after the hold: long_reader=0" || fail "long_reader after the hold: '$(stat long_reader)'"
grep -q "ERROR: AddressSanitizer\|runtime error:" "$T/k.log" && fail "a sanitizer report: $(grep -m1 'ERROR: AddressSanitizer\|runtime error:' "$T/k.log")" || pass "no sanitizer report"

if [ "$FAILED" -eq 0 ]; then
    echo "=== run_db_memlimit_reader_test: all checks passed ==="
    exit 0
fi
echo "=== run_db_memlimit_reader_test: $FAILED check(s) FAILED ==="
exit 1
