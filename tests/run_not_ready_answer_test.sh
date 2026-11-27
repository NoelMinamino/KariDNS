#!/bin/sh
# run_not_ready_answer_test.sh - 0.7 W6: options { not-ready-answer drop | servfail; } for a secondary zone before its first transfer (the primary does not answer).
#   - drop (not written: the default): an ordinary query for the secondary is not answered (dag exit 9), counted in karidns_not_ready_dropped_total (karictl stats);
#     a primary zone of the same server is answered
#   - an AXFR of the secondary gets SERVFAIL + EDE 14 whatever the option (a transfer is not an ordinary query; the server logs "the zone has no data yet")
#   - servfail, after `karictl reload` (the option is reloadable): the query gets SERVFAIL with EDE 14 and AA=0, as BIND; nothing more is counted as dropped
#   - drop again after another reload
# The database paths of the option are in tests/run_db_firstfill_latency_test.sh and test_park_worker.  No root needed.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./karictl ./dag; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_nra.XXXXXX") || exit 1
chmod 755 "$T"
RUNAS=""
[ "$(id -u)" = 0 ] && RUNAS='user "nobody";'          # (as root the server must drop its privileges: the directory and the zone file are readable by nobody)
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
P=$(kari_port 0 $((24000 + $$ % 15000)))
DEAD=$(kari_port 1 $((40000 + $$ % 15000)))        # (nothing listens there: the primary of the secondary never answers)
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
cat > "$T/pri.test.zone" <<EOF
\$TTL 300
@ SOA ns1.pri.test. host.pri.test. 1 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.80
EOF
conf() {   # conf "not-ready-answer statement or nothing"
    cat > "$T/k.conf" <<EOF
options {
    $RUNAS pid-file "none"; directory "$T"; listen-on { 127.0.0.1; }; port $P; notify no; zone-store none; allow-transfer { 127.0.0.1; }; send-extended-errors yes;
    $1
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
logging { channel r { file "$T/r.log"; }; category responses { r; }; };
zone "pri.test" { type master; file "pri.test.zone"; };
zone "sec.test" { type slave; masters { 127.0.0.1 port $DEAD; }; primary-settings no; file "sec.test.zone"; };
EOF
}
cat > "$T/ctl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/ctl.conf"
KA="./karictl -c $T/ctl.conf"
dropped() { $KA stats 2>/dev/null | sed -n 's/^karidns_not_ready_dropped_total //p' | head -1; }

conf ""
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
kari_wait_answer ./dag "$P" pri.test 30 && pass "the server answers its primary zone" || { fail "the server does not answer"; tail -20 "$T/srv.log"; exit 1; }

echo "== not-ready-answer not written (drop)"
D0=$(dropped); D0=${D0:-0}
./dag @127.0.0.1 -p "$P" www.sec.test A +nohexdump +time=2 +tries=1 > "$T/q1.out" 2>&1; rc=$?
[ "$rc" = 9 ] && pass "a query for the secondary before its first transfer is not answered (dag exit 9)" || fail "dag exit $rc: $(grep -E 'status:|EDE' "$T/q1.out" | tr '\n' ' ')"
D1=$(dropped)
[ "${D1:-0}" -gt "$D0" ] 2>/dev/null && pass "counted: karidns_not_ready_dropped_total $D0 -> $D1" || fail "karidns_not_ready_dropped_total stays ${D1:-?}"
./dag @127.0.0.1 -p "$P" www.pri.test A +short +nohexdump +time=2 +tries=1 | grep -q 192.0.2.80 && pass "the primary zone is answered meanwhile" || fail "the primary zone is not answered"
# (review #279, 3) the responses log says why it was not answered (not "<malformed>"), and over TCP the connection stays open after the dropped message (tcp-connection-reuse no, the default)
kari_wait_log "$T/r.log" "www.sec.test.*DROP:NOT-READY" 5 && ! grep -q "<malformed>" "$T/r.log" \
    && pass "the responses log names the query and says it was not answered as not ready ($(grep -m1 'DROP:NOT-READY' "$T/r.log" | sed 's/.*response: //'))" \
    || { fail "responses log:"; sed 's/^/    /' "$T/r.log" | tail -5; }
perl -MIO::Socket::INET -e '
    my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $ARGV[0], Proto => "tcp", Timeout => 3) or exit 2;
    sub msg { my ($id, $name) = @_; my $m = pack("nnnnnn", $id, 0x0100, 1, 0, 0, 0); $m .= pack("C", length $_) . $_ for split /\./, $name; $m .= "\0" . pack("nn", 1, 1); return pack("n", length $m) . $m; }
    sub rd { my ($t) = @_; my $rin = ""; vec($rin, fileno($s), 1) = 1; return select(my $r = $rin, undef, undef, $t); }
    syswrite($s, msg(1, "www.sec.test"));
    if (rd(1.5) > 0) { my $n = sysread($s, my $b, 2); exit($n ? 3 : 4); }   # (3: answered; 4: the server closed the connection)
    syswrite($s, msg(2, "www.pri.test"));
    rd(3) > 0 or exit 5;
    my $h = ""; while (length $h < 2) { my $n = sysread($s, $h, 2 - length $h, length $h); exit 6 unless $n; }
    my $len = unpack("n", $h); my $m = ""; while (length $m < $len) { my $n = sysread($s, $m, $len - length $m, length $m); exit 6 unless $n; }
    my ($id, $fl) = unpack("nn", $m); exit(($id == 2 && ($fl & 0x0F) == 0) ? 0 : 7);
' "$P"; rc=$?
[ "$rc" = 0 ] && pass "TCP: the query for the secondary is dropped and the connection stays open: the next query on it is answered" || fail "TCP: exit $rc (3: answered, 4: closed, 5-7: no answer to the next query)"
./dag @127.0.0.1 -p "$P" sec.test AXFR +nohexdump +time=5 +tries=1 > "$T/x.out" 2>&1
grep -q 'Transfer failed' "$T/x.out" && kari_wait_log "$T/srv.log" "the zone has no data yet (SERVFAIL, Not Ready)" 5 \
    && pass "an AXFR of the secondary gets SERVFAIL + EDE 14 (a transfer is not an ordinary query)" || { fail "AXFR:"; sed 's/^/    /' "$T/x.out" | head -8; }

echo "== not-ready-answer servfail (reload)"
conf "not-ready-answer servfail;"
$KA reload > "$T/r1.out" 2>&1 || { fail "reload: $(cat "$T/r1.out")"; }
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    ./dag @127.0.0.1 -p "$P" www.sec.test A +nohexdump +time=2 +tries=1 > "$T/q2.out" 2>&1
    grep -q 'status: SERVFAIL' "$T/q2.out" && { ok=1; break; }
    sleep 0.3                                      # (the reload is published by the control thread: a bounded wait for it)
done
[ "$ok" = 1 ] && grep -q 'EDE: 14' "$T/q2.out" && ! grep -q 'flags:.* aa' "$T/q2.out" && pass "the query gets SERVFAIL with EDE 14 and AA=0" || { fail "servfail:"; grep -E 'status:|flags:|EDE' "$T/q2.out" | sed 's/^/    /'; }
D2=$(dropped)
./dag @127.0.0.1 -p "$P" www.sec.test A +nohexdump +time=2 +tries=1 > /dev/null 2>&1
[ "$(dropped)" = "$D2" ] && pass "a SERVFAIL answer is not counted as dropped" || fail "karidns_not_ready_dropped_total moved: $D2 -> $(dropped)"

echo "== back to drop (reload)"
conf "not-ready-answer drop;"
$KA reload > /dev/null 2>&1
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    ./dag @127.0.0.1 -p "$P" www.sec.test A +nohexdump +time=1 +tries=1 > /dev/null 2>&1; rc=$?
    [ "$rc" = 9 ] && { ok=1; break; }
    sleep 0.3
done
[ "$ok" = 1 ] && pass "not answered again" || fail "still answered after the reload (dag exit $rc)"

echo
echo "run_not_ready_answer_test: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
