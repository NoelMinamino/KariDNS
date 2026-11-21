#!/bin/sh
# run_forward_cookie_test.sh - DNS Cookies (RFC 7873) on the queries to the forwarders of `type forward` zones (0.7).  The forwarders are
# tests/mock_alias_upstream.pl (--cookies for one that sends cookies).  The queries of forward zones are answered by the threads of the
# async I/O pool, each with its own cookie state and one process-wide mark per forwarder.  No root.
#
#   1. a forwarder with cookies: every query carries a client cookie, later ones the server cookie it sent; the server logs once that the
#      forwarder sends cookies; the client never sees the forwarder's cookies (its own COOKIE in the reply is this server's for it).
#   2. a forged answer with another client cookie that comes first is ignored and the real one served; once cookies were seen, a forged
#      answer without a COOKIE option is ignored too (in every thread).
#   3. BADCOOKIE, then one retry with the new server cookie, answered.
#   4. a truncated answer: the same query (the same client cookie) over TCP, the TCP answer served.
#   5. a client without EDNS: the query to the forwarder carries an OPT RR with the cookie, the reply to the client has no OPT RR.
#   6. a forwarder without cookies still works and is not marked.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
KARIDNS=${KARIDNS:-./karidns}
DAG=${DAG:-./dag}
for b in "$KARIDNS" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
. "$ROOT/tests/lib_proc.sh"

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_fwd_ck.XXXXXX") || exit 1
chmod 755 "$T"
PIDS=""
cleanup() {
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done
    for p in $PIDS; do
        i=0; while [ $i -lt 100 ] && kill -0 "$p" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
        kill -KILL "$p" 2>/dev/null
    done
    for p in $PIDS; do kari_kill_tree "$p"; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
check() {   # check DESCRIPTION EXPECTED ACTUAL
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$3', want '$2')"; fi
}
count() { grep -c -- "$2" "$1" 2>/dev/null || true; }

BASE=$(kari_port 0 $((20000 + $$ % 20000)))
P_K=$BASE; P_CK=$((BASE + 1)); P_NC=$((BASE + 2))
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT='user "nobody"; group "nobody";'   # root: the server refuses to run without a user to drop to

cat > "$T/ck.data" <<'EOF'
a.fw.test A 60 192.0.2.10
w.fw.test A 60 192.0.2.11
sp.fw.test A 60 192.0.2.20
dg.fw.test A 60 192.0.2.30
bc.fw.test A 60 192.0.2.40
tc.fw.test A 60 192.0.2.50
ne.fw.test A 60 192.0.2.55
spoof sp.fw.test
downgrade dg.fw.test
badcookie bc.fw.test
trunc tc.fw.test
EOF
cat > "$T/nc.data" <<'EOF'
a.nc.test A 60 192.0.2.60
EOF
cat > "$T/k.conf" <<EOF
options { pid-file "none"; bind-address { 127.0.0.1; }; port $P_K; $USER_OPT };
zone "fw.test." { type forward; forwarders { 127.0.0.1 port $P_CK; }; forward-timeout 3000; };
zone "nc.test." { type forward; forwarders { 127.0.0.1 port $P_NC; }; forward-timeout 3000; };
EOF
chmod 644 "$T"/*

# q NAME [dag options] -> STATUS|sorted answer RRs without TTL
q() {
    _n=$1; shift
    out=$($DAG @127.0.0.1 -p "$P_K" "$_n" A +nohexdump +noall +comments +answer +nottlid +time=4 +tries=1 "$@" 2>/dev/null)
    st=$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z0-9]*\).*/\1/p' | head -1)
    an=$(printf '%s\n' "$out" | grep -v '^;' | grep -v '^$' | tr -s ' \t' ' ' | sort | tr '\n' ';')
    echo "$st|$an"
}

perl "$ROOT/tests/mock_alias_upstream.pl" --port "$P_CK" --data "$T/ck.data" --log "$T/ck.log" --cookies --cookie-log "$T/ck.cookies" > "$T/ck.out" 2>&1 &
PIDS="$PIDS $!"
perl "$ROOT/tests/mock_alias_upstream.pl" --port "$P_NC" --data "$T/nc.data" --log "$T/nc.log" > "$T/nc.out" 2>&1 &
PIDS="$PIDS $!"
"$KARIDNS" -c "$T/k.conf" -f > "$T/k.log" 2>&1 &
PID_K=$!
PIDS="$PIDS $PID_K"
i=0
while [ $i -lt 200 ]; do
    case $(q a.nc.test) in 'NOERROR|'*) break ;; esac
    kill -0 "$PID_K" 2>/dev/null || break
    sleep 0.1; i=$((i + 1))
done
case $(q a.nc.test) in 'NOERROR|'*) pass "karidns starts and forwards" ;; *) fail "karidns did not start"; tail -20 "$T/k.log"; exit 1 ;; esac

# ================================================================ 1. a forwarder with cookies
echo "== 1. DNS Cookies (RFC 7873) to a forwarder that sends them"
check "a name through the forwarder with cookies" "NOERROR|a.fw.test. IN A 192.0.2.10;" "$(q a.fw.test)"
if kari_wait_log "$T/k.log" "forwarder 127.0.0.1:$P_CK sends DNS cookies" 10; then pass "the server logs that the forwarder sends cookies"; else fail "no 'sends DNS cookies' line"; tail -5 "$T/k.log"; fi
i=0; while [ $i -lt 12 ]; do q w.fw.test > /dev/null; i=$((i + 1)); done   # more queries: more threads of the pool
check "... once for all threads" "1" "$(count "$T/k.log" "forwarder 127.0.0.1:$P_CK sends DNS cookies")"
n_q=$(count "$T/ck.cookies" ' udp ')
n_nocc=$(count "$T/ck.cookies" ' cc=- ')
[ "$n_q" -ge 13 ] && [ "$n_nocc" = 0 ] && pass "every query carries a client cookie ($n_q queries)" || { fail "queries without a client cookie: $n_nocc of $n_q"; cat "$T/ck.cookies"; }
n_sc=$(count "$T/ck.cookies" ' sc=16 ')
[ "$n_sc" -ge 1 ] && pass "the later queries carry the server cookie ($n_sc)" || { fail "no query with the server cookie"; cat "$T/ck.cookies"; }
n_cc=$(sed -n 's/.* cc=\([0-9a-f]*\) .*/\1/p' "$T/ck.cookies" | sort -u | wc -l | tr -d ' ')
[ "$n_cc" -ge 1 ] && [ "$n_cc" -le 16 ] && pass "one client cookie per thread that asked ($n_cc)" || fail "$n_cc client cookies for one forwarder (at most 16 threads)"
# the client's view: its own COOKIE comes back with this server's server cookie, never the forwarder's ("MOCKSRVR")
out=$($DAG @127.0.0.1 -p "$P_K" a.fw.test A +nohexdump +cookie=0102030405060708 +time=4 +tries=1 2>/dev/null)
ck=$(printf '%s\n' "$out" | sed -n 's/.*COOKIE: \([0-9a-fA-F]*\).*/\1/p' | head -1 | tr 'A-F' 'a-f')
case $ck in
    0102030405060708*) pass "the reply carries the client's own client cookie" ;;
    *) fail "the client cookie of the reply is '$ck'"; printf '%s\n' "$out" | grep -i cookie ;;
esac
case $ck in
    *4d4f434b53525652*) fail "the forwarder's server cookie reached the client ($ck)" ;;
    ?????????????????*) pass "the server cookie of the reply is this server's, not the forwarder's" ;;
    *) fail "no server cookie in the reply ($ck)" ;;
esac
printf '%s\n' "$out" | grep -q "192\.0\.2\.10" && pass "... and the answer" || fail "no answer with +cookie"

# ================================================================ 2. forgeries
echo "== 2. forged answers"
bad=""
i=0; while [ $i -lt 6 ]; do a=$(q sp.fw.test); case $a in *192.0.2.20*) ;; *) bad="$bad [$a]" ;; esac; i=$((i + 1)); done
[ -z "$bad" ] && pass "a forged answer with another client cookie is never served (6 queries)" || fail "sp.fw.test answers:$bad"
n_sp=$(count "$T/ck.cookies" '^sp.fw.test 1 udp .* spoof+answer')
[ "$n_sp" -ge 6 ] && pass "the forgery came first $n_sp times" || fail "only $n_sp forged answers were sent"
bad=""
i=0; while [ $i -lt 6 ]; do a=$(q dg.fw.test); case $a in *192.0.2.30*) ;; *) bad="$bad [$a]" ;; esac; i=$((i + 1)); done
[ -z "$bad" ] && pass "a forged answer without a COOKIE option is never served after cookies were seen (6 queries)" || fail "dg.fw.test answers:$bad"
n_dg=$(count "$T/ck.cookies" '^dg.fw.test 1 udp .* downgrade+answer')
[ "$n_dg" -ge 6 ] && pass "the cookie-less forgery came first $n_dg times" || fail "only $n_dg cookie-less forgeries were sent"
kari_wait_log "$T/k.log" "with a wrong or missing DNS cookie was discarded" 5 && pass "the discarded responses are logged" || fail "no 'wrong or missing DNS cookie' line"

# ================================================================ 3. BADCOOKIE
echo "== 3. BADCOOKIE"
check "a name whose first query gets BADCOOKIE is answered" "NOERROR|bc.fw.test. IN A 192.0.2.40;" "$(q bc.fw.test)"
bc_lines=$(grep '^bc.fw.test 1 ' "$T/ck.cookies")
case $(printf '%s\n' "$bc_lines" | awk '{ print $(NF - 1), $NF }' | head -2 | tr '\n' ' ') in
    'cur=no badcookie cur=yes answer ') pass "BADCOOKIE then one retry with the new server cookie" ;;
    *) fail "the BADCOOKIE exchange: $bc_lines" ;;
esac

# ================================================================ 4. TCP after a truncated answer
echo "== 4. TCP fallback"
check "a truncated answer is fetched over TCP" "NOERROR|tc.fw.test. IN A 192.0.2.50;" "$(q tc.fw.test)"
u_cc=$(sed -n 's/^tc.fw.test 1 udp cc=\([0-9a-f]*\) .*/\1/p' "$T/ck.cookies" | head -1)
t_cc=$(sed -n 's/^tc.fw.test 1 tcp cc=\([0-9a-f]*\) .*/\1/p' "$T/ck.cookies" | head -1)
[ -n "$u_cc" ] && [ "$u_cc" = "$t_cc" ] && pass "the TCP query carries the same client cookie" || { fail "udp cc '$u_cc', tcp cc '$t_cc'"; grep '^tc.fw.test' "$T/ck.cookies"; }

# ================================================================ 5. a client without EDNS
echo "== 5. a client without EDNS"
out=$($DAG @127.0.0.1 -p "$P_K" ne.fw.test A +nohexdump +noedns +time=4 +tries=1 2>/dev/null)
printf '%s\n' "$out" | grep -q "192\.0\.2\.55" && pass "a query without EDNS is answered" || { fail "ne.fw.test without EDNS"; printf '%s\n' "$out"; }
printf '%s\n' "$out" | grep -q "OPT PSEUDOSECTION" && fail "the reply to a client without EDNS has an OPT RR" || pass "the reply has no OPT RR (RFC 6891 section 7)"
grep -q '^ne.fw.test 1 udp cc=[0-9a-f]' "$T/ck.cookies" && pass "the query to the forwarder carried the cookie in an OPT RR of its own" || { fail "no cookie in the forwarded query"; grep '^ne.fw.test' "$T/ck.cookies"; }

# ================================================================ 6. a forwarder without cookies
echo "== 6. a forwarder without cookies"
check "a name through a forwarder without cookies" "NOERROR|a.nc.test. IN A 192.0.2.60;" "$(q a.nc.test)"
grep -q "forwarder 127.0.0.1:$P_NC sends DNS cookies" "$T/k.log" && fail "the forwarder without cookies was marked" || pass "the forwarder without cookies is not marked"

kill -0 "$PID_K" 2>/dev/null && pass "the server still runs" || fail "the server exited"
echo ""
echo "passed: $PASS, failed: $FAILS"
if [ "$FAILS" -ne 0 ]; then
    echo "--- karidns log (tail)"; tail -30 "$T/k.log"
    echo "--- cookie log (tail)"; tail -30 "$T/ck.cookies"
    exit 1
fi
exit 0
