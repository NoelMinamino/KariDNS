#!/bin/sh
# ==============================================================================
# run_rcu_reclaim_status_test.sh
#
# R1 (0.7, K-1): the reclaim queue of the zone snapshots in karictl status / stats.  R11: a zone transfer no longer holds it.
#  1. An AXFR client with a small receive buffer asks for a zone of about 1 MB and reads nothing (max-transfer-idle-out is 60 minutes by
#     default).  The transfer pins the one version it sends and holds no read section and no snapshot: `karictl reload` answers
#     "OK reloaded" at once (no zone failed), "retired zone snapshots waiting" goes back to 0, a second reload is not postponed, and
#     "retired zone versions waiting" is at most 1 (the version the transfer sends) until the client goes away, then 0.
#  2. A reader that does hold a read section (`karictl rcu-hold <ms>`, a TEST ONLY command of the build with the test hooks: ./karidns of
#     `make coverage`, else ./karidns-evict of `make evict`) keeps the snapshot that a reload retires (the reload itself answers at once: it does not wait for the reader, 0.7): "retired zone snapshots waiting: 1"
#     with an age that grows, the stats gauges and the JSON "reclaim" object, one warning after 60 s naming the auxiliary slot that holds
#     it, the warning counter 1; when the hold ends the counts go back to 0.  Without such a build part 2 is skipped (said in the output).
# About 90 seconds with part 2.  Needs perl.  SKIP without it.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
[ -x "$ROOT_DIR/karictl" ] || make -C "$ROOT_DIR" karictl
[ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
# the server: one with the test hook (part 2) when there is one, else ./karidns (part 1 only)
has_hook() { [ -x "$1" ] && grep -q 'ERROR bad hold' "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_hook "$ROOT_DIR/karidns"; then KARIDNS=$ROOT_DIR/karidns
    elif has_hook "$ROOT_DIR/karidns-evict"; then KARIDNS=$ROOT_DIR/karidns-evict
    else
        [ -x "$ROOT_DIR/karidns" ] || make -C "$ROOT_DIR" karidns
        KARIDNS=$ROOT_DIR/karidns
    fi
fi
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

PORT=$(kari_port 0 $((27000 + $$ % 4000)))
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rcu_reclaim_status.XXXXXX") || exit 1
chmod 755 "$TMP_DIR"
SERVER_PID=""
CLIENT_PID=""
FAILED=0

cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    kari_kill_tree "$SERVER_PID"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
now_ms() { perl -MTime::HiRes=time -e 'printf("%d\n", time * 1000)'; }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

SECRET="cmN1LXJlY2xhaW0tc3RhdHVzLXRlc3Qta2V5LTAwMDA="
{
    echo '$TTL 300'
    echo '$ORIGIN example.test.'
    echo '@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )'
    echo '@ IN NS ns1.example.test.'
    echo 'ns1 IN A 192.0.2.1'
    perl -e 'for my $i (1 .. 5000) { printf("r%05d IN TXT \"%s\"\n", $i, "x" x 200) }'
} > "$TMP_DIR/example.test.zone"
cat > "$TMP_DIR/karidns.conf" <<EOF
options {
    port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
};
control-channel { socket "$TMP_DIR/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; allow-transfer { 127.0.0.1; }; };
EOF
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$TMP_DIR/ctl.conf"
chmod 600 "$TMP_DIR/ctl.conf"
chmod 644 "$TMP_DIR/example.test.zone" "$TMP_DIR/karidns.conf"

ctl() { "$KARICTL" -s "$TMP_DIR/ctl.sock" -f "$TMP_DIR/ctl.conf" "$@" 2>&1; }
# status_num PREFIX: the number after "PREFIX: " in karictl status
status_num() { ctl status | sed -n "s/^$1: \([0-9][0-9]*\).*/\1/p" | head -1; }
oldest_ms() { ctl status | sed -n 's/^retired zone snapshots waiting: [0-9]* (oldest \([0-9]*\) ms)$/\1/p' | head -1; }
# reload_ok LABEL: a full reload answers "OK reloaded" within 3 s
reload_ok() {
    t0=$(now_ms)
    R=$(ctl reload)
    t1=$(now_ms)
    case "$R" in
        "OK reloaded"*) [ $((t1 - t0)) -lt 3000 ] && pass "$1 ($((t1 - t0)) ms: $R)" || fail "$1: it took $((t1 - t0)) ms ($R)" ;;
        *) fail "$1: '$R'" ;;
    esac
}

echo "=== the reclaim queue in karictl status; a stalled transfer holds no snapshot (R1, R11) ($(basename "$KARIDNS")) ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
if ! kari_wait_answer "$DAG" "$PORT" example.test; then
    echo "  FAIL: the server did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi
W=$(status_num "retired zone snapshots waiting")
[ "$W" = "0" ] && pass "at the start nothing waits (retired zone snapshots waiting: 0)" || fail "at the start: '$W' snapshots waiting"
ctl status | grep -q "^retired zone versions waiting: [0-9]" && pass "status has 'retired zone versions waiting'" || fail "no 'retired zone versions waiting' line"

# the client: SO_RCVBUF 2048 before connect, one AXFR query, then it sleeps without reading
cat > "$TMP_DIR/stall.pl" <<'EOF'
use strict; use warnings;
use Socket qw(:all);
my ($port, $out) = @ARGV;
socket(my $s, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 2048)) or die "rcvbuf: $!";
connect($s, pack_sockaddr_in($port, inet_aton('127.0.0.1'))) or die "connect: $!";
my $m = pack('nnnnnn', 4242, 0x0000, 1, 0, 0, 0) . "\x07example\x04test\x00" . pack('nn', 252, 1);
my $q = pack('n', length $m) . $m;
syswrite($s, $q) == length $q or die "write: $!";
open(my $f, '>', $out) or die; print $f "sent\n"; close $f;
sleep 300;
EOF
perl "$TMP_DIR/stall.pl" "$PORT" "$TMP_DIR/stall.out" 2> "$TMP_DIR/stall.err" &
CLIENT_PID=$!
i=0; while [ ! -s "$TMP_DIR/stall.out" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
[ -s "$TMP_DIR/stall.out" ] && pass "the client asked for the transfer and reads nothing" || fail "the client: $(cat "$TMP_DIR/stall.err")"
i=0; while [ "$(status_num "xfers running")" != "1" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num "xfers running")" = "1" ] && pass "the transfer runs (xfers running: 1)" || fail "no transfer is running: $(ctl status | grep xfers)"

echo "== 1. the stalled transfer and two reloads"
reload_ok "a reload during the stalled transfer answers at once, no zone failed"
i=0; while [ "$(status_num "retired zone snapshots waiting")" != "0" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
W=$(status_num "retired zone snapshots waiting")
[ "$W" = "0" ] && pass "the snapshot the reload retired is freed (retired zone snapshots waiting: 0)" || fail "after the reload: '$W' snapshots waiting"
reload_ok "a second reload is not postponed"
V=$(status_num "retired zone versions waiting")
[ -n "$V" ] && [ "$V" -le 1 ] && pass "retired zone versions waiting: $V (at most the version the transfer sends)" || fail "retired zone versions waiting: '$V'"
"$KARICTL" -s "$TMP_DIR/ctl.sock" -f "$TMP_DIR/ctl.conf" stats > "$TMP_DIR/stats.prom" 2>&1
grep -q '^karidns_reclaim_snapshots_waiting 0$' "$TMP_DIR/stats.prom" && pass "stats: karidns_reclaim_snapshots_waiting 0" || fail "stats: $(grep reclaim "$TMP_DIR/stats.prom")"
[ "$(status_num "xfers running")" = "1" ] && pass "the transfer still runs" || fail "the transfer ended: $(ctl status | grep xfers)"
BAD='failed to load\|[Rr]eload postponed\|postponed: active AXFR'
grep -q "$BAD" "$TMP_DIR/karidns.log" && fail "the log reports a failed or postponed reload: $(grep "$BAD" "$TMP_DIR/karidns.log" | head -2)" \
    || pass "no 'failed to load' or 'reload postponed' in the log"
kill "$CLIENT_PID" 2>/dev/null; wait "$CLIENT_PID" 2>/dev/null; CLIENT_PID=""
i=0; while [ "$(status_num "retired zone versions waiting")" != "0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num "retired zone versions waiting")" = "0" ] && pass "the client gone, no retired zone version waits" || fail "retired zone versions waiting: $(status_num "retired zone versions waiting")"
i=0; while [ "$(status_num "xfers running")" != "0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
[ "$(status_num "xfers running")" = "0" ] && pass "the transfer ended (xfers running: 0)" || fail "xfers running: $(status_num "xfers running")"

echo "== 2. a reader that holds a read section (the test hook)"
if ! has_hook "$KARIDNS"; then
    echo "  SKIP: part 2: $KARIDNS has no test hook (make evict, or the build of make coverage)"
else
    H=$(ctl rcu-hold 70000)
    [ "$H" = "OK" ] && pass "karictl rcu-hold 70000 (TEST ONLY)" || fail "rcu-hold: '$H'"
    ctl rcu-hold 999999 | grep -q '^ERROR' && pass "rcu-hold refuses more than 120 s" || fail "rcu-hold 999999 was accepted"
    # (a full reload: every zone file read again; it waited 60 s for this reader before 0.7)
    reload_ok "a full reload during the hold answers at once"
    t0=$(now_ms); R=$(ctl reload); t1=$(now_ms)
    case "$R" in *"reload postponed"*) [ $((t1 - t0)) -lt 5500 ] && pass "a second reload answers after the wait for the readers of normal operation ($((t1 - t0)) ms, at most 5 s): postponed while the reader may hold the configuration's other buffer" || fail "the second reload took $((t1 - t0)) ms" ;; *) fail "the second reload: '$R'" ;; esac
    i=0; while [ "$(status_num "retired zone snapshots waiting")" != "1" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    W=$(status_num "retired zone snapshots waiting")
    [ "$W" = "1" ] && pass "after the reload the old snapshot waits for the reader (retired zone snapshots waiting: 1)" || fail "after the reload: '$W' snapshots waiting"
    A1=$(oldest_ms)
    sleep 2
    A2=$(oldest_ms)
    if [ -n "$A1" ] && [ -n "$A2" ] && [ "$A2" -ge $((A1 + 1500)) ]; then pass "the age of the oldest grows ($A1 ms, then $A2 ms)"; else fail "the age: '$A1' then '$A2'"; fi
    "$KARICTL" -s "$TMP_DIR/ctl.sock" -f "$TMP_DIR/ctl.conf" stats > "$TMP_DIR/stats.prom" 2>&1
    grep -q '^karidns_reclaim_snapshots_waiting 1$' "$TMP_DIR/stats.prom" && pass "stats: karidns_reclaim_snapshots_waiting 1" || fail "stats: $(grep reclaim "$TMP_DIR/stats.prom")"
    grep -q '^karidns_reclaim_oldest_snapshot_age_seconds [1-9]' "$TMP_DIR/stats.prom" && pass "stats: the age gauge" || fail "stats: no age gauge"
    grep -q '^karidns_reclaim_zone_versions_waiting [0-9]' "$TMP_DIR/stats.prom" && grep -q '^karidns_reclaim_warnings_total 0$' "$TMP_DIR/stats.prom" \
        && pass "stats: the zone-version gauge and the warning counter (0)" || fail "stats: $(grep reclaim "$TMP_DIR/stats.prom")"
    "$KARICTL" -s "$TMP_DIR/ctl.sock" -f "$TMP_DIR/ctl.conf" stats -f json > "$TMP_DIR/stats.json" 2>&1
    grep -q '"reclaim":{"snapshots_waiting":1,"oldest_snapshot_age_ms":[0-9]*,"zone_versions_waiting":[0-9]*,"warnings":0}' "$TMP_DIR/stats.json" \
        && pass "stats JSON: the reclaim object" || fail "stats JSON: $(head -c 300 "$TMP_DIR/stats.json")"

    echo "   (waiting for the 60-second warning)"
    i=0; while ! grep -q "\[GC\] the oldest retired zone snapshot has waited" "$TMP_DIR/karidns.log" && [ $i -lt 80 ]; do sleep 1; i=$((i + 1)); done
    L=$(grep "\[GC\] the oldest retired zone snapshot has waited" "$TMP_DIR/karidns.log" | head -1)
    echo "   $L"
    case "$L" in
        *"held by "*"auxiliary"*) pass "one warning after 60 s names what holds the snapshot (an auxiliary slot)" ;;
        *) fail "no warning naming the holder: '$L'" ;;
    esac
    N=$(grep -c "\[GC\] the oldest retired zone snapshot has waited" "$TMP_DIR/karidns.log")
    [ "$N" = "1" ] && pass "the warning was written once (at most one a minute)" || fail "$N warnings"
    [ "$(status_num "reclaim warnings (snapshot held over 60 s)")" = "1" ] && pass "status: reclaim warnings 1" || fail "status: $(ctl status | grep 'reclaim warnings')"
    grep -q "wait_until_safe stalled" "$TMP_DIR/karidns.log" && N2=$(grep -c "wait_until_safe stalled" "$TMP_DIR/karidns.log") || N2=0
    [ "$N2" -le 3 ] && pass "the stall lines of the waits are not one a second ($N2)" || fail "$N2 stall lines"

    # the hold ends 70 s after it began
    i=0; while [ "$(status_num "retired zone snapshots waiting")" != "0" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
    W=$(status_num "retired zone snapshots waiting")
    [ "$W" = "0" ] && pass "the hold over, the snapshot is freed (retired zone snapshots waiting: 0)" || fail "after the hold: '$W' waiting"
    [ "$(oldest_ms)" = "0" ] && pass "and the age is 0" || fail "the age: $(oldest_ms)"
    i=0; while [ "$(status_num "retired zone versions waiting")" != "0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    [ "$(status_num "retired zone versions waiting")" = "0" ] && pass "no retired zone version waits" || fail "retired zone versions waiting: $(status_num "retired zone versions waiting")"
fi
"$DAG" @127.0.0.1 -p "$PORT" ns1.example.test A +short +nohexdump +time=2 +tries=3 | grep -q 192.0.2.1 && pass "the server answers" || fail "no answer"
kill -0 "$SERVER_PID" 2>/dev/null && pass "the server is running" || fail "the server is gone"
grep -q "ERROR: AddressSanitizer\|runtime error:" "$TMP_DIR/karidns.log" && fail "a sanitizer report: $(grep -m1 'ERROR: AddressSanitizer\|runtime error:' "$TMP_DIR/karidns.log")" || true

if [ "$FAILED" -eq 0 ]; then
    echo "=== run_rcu_reclaim_status_test: all checks passed ==="
    exit 0
fi
echo "=== run_rcu_reclaim_status_test: $FAILED check(s) FAILED ==="
exit 1
