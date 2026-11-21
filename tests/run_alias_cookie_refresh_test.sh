#!/bin/sh
# run_alias_cookie_refresh_test.sh - the hardening of the ALIAS resolver client (0.7): DNS Cookies (RFC 7873) on the queries to the
# alias-resolver addresses, and alias-max-refresh-time.  The upstream is tests/mock_alias_upstream.pl (--cookies for a resolver that
# sends cookies); file zones only, no root.
#
#   1. a resolver with cookies: every query carries a client cookie, the later ones the server cookie it sent; the server logs once
#      that the resolver sends cookies; a forged answer with another client cookie that comes first is ignored (the real one is
#      served); once cookies were seen, a forged answer without a COOKIE option is ignored too; BADCOOKIE then one retry with the new
#      server cookie resolves the name.
#   2. a resolver without cookies still works (its answers carry no OPT RR).
#   3. alias-max-refresh-time: a target with an upstream TTL of a day is looked up again every 5 s with `alias-max-refresh-time 5;`;
#      two zones that share a target with 6 s and the default take the smaller; a target without a cap is not looked up again in that
#      window; a configuration reload that sets a cap applies to the result already held (looked up again at once).
#   4. karicheck conf: alias-max-refresh-time outside 5 s .. 1 day is an error in options, in a zone and in the database block; 30m is fine.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
KARIDNS=${KARIDNS:-./karidns}
DAG=${DAG:-./dag}
KARICHECK=${KARICHECK:-./karicheck}
for b in "$KARIDNS" "$DAG" "$KARICHECK"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
. "$ROOT/tests/lib_proc.sh"

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_alias_ck.XXXXXX") || exit 1
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

BASE=$(kari_port 0 $((20000 + $$ % 20000)))
P_K=$BASE; P_CK=$((BASE + 1)); P_NC=$((BASE + 2))

# ---------------------------------------------------------------- fixtures
cat > "$T/ck.data" <<'EOF'
t.target.test A 60 192.0.2.10
t.target.test A 60 192.0.2.11
t.target.test AAAA 60 2001:db8::10
sp.target.test A 6 192.0.2.20
dg.target.test A 6 192.0.2.30
bc.target.test A 60 192.0.2.40
spoof sp.target.test
downgrade dg.target.test
badcookie bc.target.test
EOF
cat > "$T/nc.data" <<'EOF'
t.target.test A 60 192.0.2.50
long.target.test A 86400 192.0.2.60
sh.target.test A 86400 192.0.2.70
lo.target.test A 86400 192.0.2.80
EOF
mkzone() {   # mkzone ORIGIN "records"
    printf '$ORIGIN %s.\n$TTL 300\n@ SOA ns hostmaster 1 3600 600 86400 300\n@ NS ns\nns A 192.0.2.1\n%s\n' "$1" "$2" > "$T/$1.zone"
}
mkzone ck.test 'a ALIAS t.target.test.
sp ALIAS sp.target.test.
dg ALIAS dg.target.test.
bc ALIAS bc.target.test.'
mkzone nc.test 'a ALIAS t.target.test.'
mkzone cap.test 'r ALIAS long.target.test.'
mkzone share1.test 's ALIAS sh.target.test.'
mkzone share2.test 's ALIAS sh.target.test.'
mkzone def.test 'r ALIAS lo.target.test.'

conf_file() {   # conf_file [statements of zone def.test]
    cat > "$T/k.conf" <<EOF
options { pid-file "none"; bind-address { 127.0.0.1; }; port $P_K; alias-resolver { 127.0.0.1 port $P_NC; }; };
zone "ck.test." { type primary; file "$T/ck.test.zone"; alias-resolver { 127.0.0.1 port $P_CK; }; };
zone "nc.test." { type primary; file "$T/nc.test.zone"; };
zone "cap.test." { type primary; file "$T/cap.test.zone"; alias-max-refresh-time 5; };
zone "share1.test." { type primary; file "$T/share1.test.zone"; alias-max-refresh-time 6; };
zone "share2.test." { type primary; file "$T/share2.test.zone"; };
zone "def.test." { type primary; file "$T/def.test.zone"; ${1:-} };
EOF
}

# q NAME TYPE -> STATUS|sorted answer RRs without TTL
q() {
    out=$($DAG @127.0.0.1 -p "$P_K" "$1" "$2" +nohexdump +noall +comments +answer +nottlid +time=3 +tries=1 2>/dev/null)
    st=$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z0-9]*\).*/\1/p' | head -1)
    an=$(printf '%s\n' "$out" | grep -v '^;' | grep -v '^$' | tr -s ' \t' ' ' | sort | tr '\n' ';')
    echo "$st|$an"
}
wait_value() {   # wait_value NAME TYPE PATTERN SECONDS
    i=0
    while [ $i -lt $(($4 * 10)) ]; do
        q "$1" "$2" | grep -q -- "$3" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
count() { grep -c -- "$2" "$1" 2>/dev/null || true; }
# never_value NAME TYPE PATTERN SECONDS: the answer never matches PATTERN in the window (a check that something must not happen)
never_value() {
    i=0
    while [ $i -lt $(($4 * 5)) ]; do
        a=$(q "$1" "$2")
        case $a in *"$3"*) echo "$a"; return 1 ;; esac
        sleep 0.2; i=$((i + 1))
    done
    return 0
}

# ---------------------------------------------------------------- start
perl "$ROOT/tests/mock_alias_upstream.pl" --port "$P_CK" --data "$T/ck.data" --log "$T/ck.log" --cookies --cookie-log "$T/ck.cookies" > "$T/ck.out" 2>&1 &
PIDS="$PIDS $!"
perl "$ROOT/tests/mock_alias_upstream.pl" --port "$P_NC" --data "$T/nc.data" --log "$T/nc.log" > "$T/nc.out" 2>&1 &
PIDS="$PIDS $!"
conf_file
"$KARIDNS" -c "$T/k.conf" -f > "$T/k.log" 2>&1 &
PID_K=$!
PIDS="$PIDS $PID_K"
i=0
while [ $i -lt 200 ]; do
    case $(q ck.test SOA) in 'NOERROR|'*) break ;; esac
    kill -0 "$PID_K" 2>/dev/null || break
    sleep 0.1; i=$((i + 1))
done
case $(q ck.test SOA) in 'NOERROR|'*) pass "karidns starts" ;; *) fail "karidns did not start"; tail -20 "$T/k.log"; exit 1 ;; esac

# ================================================================ 1. a resolver with cookies
echo "== 1. DNS Cookies (RFC 7873) to a resolver that sends them"
if wait_value a.ck.test A "192.0.2.10" 20; then pass "an ALIAS through a resolver with cookies is resolved"; else fail "a.ck.test not resolved: $(q a.ck.test A)"; fi
check "the addresses of the target" "NOERROR|a.ck.test. IN A 192.0.2.10;a.ck.test. IN A 192.0.2.11;" "$(q a.ck.test A)"
if kari_wait_log "$T/k.log" "resolver 127.0.0.1:$P_CK sends DNS cookies" 10; then pass "the server logs that the resolver sends cookies"; else fail "no 'sends DNS cookies' line"; tail -5 "$T/k.log"; fi
check "... once" "1" "$(count "$T/k.log" "resolver 127.0.0.1:$P_CK sends DNS cookies")"
n_q=$(count "$T/ck.cookies" ' udp ')
n_nocc=$(count "$T/ck.cookies" ' cc=- ')
[ "$n_q" -ge 4 ] && [ "$n_nocc" = 0 ] && pass "every query carries a client cookie ($n_q queries)" || { fail "queries without a client cookie: $n_nocc of $n_q"; cat "$T/ck.cookies"; }
n_sc=$(count "$T/ck.cookies" ' sc=16 ')
[ "$n_sc" -ge 1 ] && pass "the later queries carry the server cookie ($n_sc)" || { fail "no query with the server cookie"; cat "$T/ck.cookies"; }
n_cc=$(sed -n 's/.* cc=\([0-9a-f]*\) .*/\1/p' "$T/ck.cookies" | sort -u | wc -l | tr -d ' ')
check "one client cookie for the resolver address" "1" "$n_cc"
# a forged answer with another client cookie comes first (each refresh, every 5 s): never served
if wait_value sp.ck.test A "192.0.2.20" 20; then pass "the target with forged answers is resolved"; else fail "sp.ck.test not resolved: $(q sp.ck.test A)"; fi
if bad=$(never_value sp.ck.test A "192.0.2.99" 12); then pass "a forged answer with another client cookie is never served"; else fail "the forged answer was served: $bad"; fi
n_sp=$(count "$T/ck.cookies" '^sp.target.test 1 udp .* spoof+answer')
[ "$n_sp" -ge 2 ] && pass "the forgery was sent before $n_sp answers" || fail "only $n_sp forged answers were sent"
# downgrade: once cookies were seen, a forged answer without COOKIE is ignored
if wait_value dg.ck.test A "192.0.2.30" 20; then pass "the target with cookie-less forgeries is resolved"; else fail "dg.ck.test not resolved: $(q dg.ck.test A)"; fi
if bad=$(never_value dg.ck.test A "192.0.2.98" 12); then pass "a forged answer without a COOKIE option is never served after cookies were seen"; else fail "the cookie-less answer was served: $bad"; fi
n_dg=$(count "$T/ck.cookies" '^dg.target.test 1 udp .* downgrade+answer')
[ "$n_dg" -ge 2 ] && pass "the cookie-less forgery was sent before $n_dg answers" || fail "only $n_dg cookie-less forgeries were sent"
# BADCOOKIE, then one retry with the new server cookie
if wait_value bc.ck.test A "192.0.2.40" 20; then pass "a name whose first query gets BADCOOKIE is resolved"; else fail "bc.ck.test not resolved: $(q bc.ck.test A)"; fi
bc_lines=$(grep '^bc.target.test 1 ' "$T/ck.cookies")
case $(printf '%s\n' "$bc_lines" | awk '{ print $(NF - 1), $NF }' | head -2 | tr '\n' ' ') in
    'cur=no badcookie cur=yes answer ') pass "BADCOOKIE then one retry with the new server cookie, answered" ;;
    *) fail "the BADCOOKIE exchange: $bc_lines" ;;
esac

# ================================================================ 2. a resolver without cookies
echo "== 2. a resolver without cookies"
if wait_value a.nc.test A "192.0.2.50" 20; then pass "an ALIAS through a resolver without cookies is resolved"; else fail "a.nc.test not resolved: $(q a.nc.test A)"; fi
grep -q "resolver 127.0.0.1:$P_NC sends DNS cookies" "$T/k.log" && fail "the resolver without cookies was marked" || pass "the resolver without cookies is not marked"

# ================================================================ 3. alias-max-refresh-time
echo "== 3. alias-max-refresh-time"
if kari_wait_log "$T/nc.log" '^long.target.test 1 ' 30 3; then pass "a target with TTL 86400 and alias-max-refresh-time 5 is looked up again ($(count "$T/nc.log" '^long.target.test 1 ') times)"
else fail "long.target.test looked up $(count "$T/nc.log" '^long.target.test 1 ') times"; fi
T1=$($DAG @127.0.0.1 -p "$P_K" r.cap.test A +nohexdump +noall +answer +time=3 +tries=1 2>/dev/null | awk '!/^;/ && NF { print $2; exit }')
[ -n "$T1" ] && [ "$T1" -le 300 ] && [ "$T1" -ge 250 ] && pass "the TTL served is not cut by the cap ($T1 = min(300, upstream))" || fail "TTL of r.cap.test is '$T1'"
if kari_wait_log "$T/nc.log" '^sh.target.test 1 ' 30 3; then pass "a target of two zones (6 s and the default) is looked up at the smaller value ($(count "$T/nc.log" '^sh.target.test 1 ') times)"
else fail "sh.target.test looked up $(count "$T/nc.log" '^sh.target.test 1 ') times"; fi
n_lo=$(count "$T/nc.log" '^lo.target.test 1 ')   # 1; 2 when the first try timed out on a loaded host (retried after 5 s); a refresh every few seconds gives many
[ "$n_lo" -ge 1 ] && [ "$n_lo" -le 2 ] && pass "a target without a cap is not looked up again (TTL 86400, default 3600; $n_lo lookups)" || fail "lo.target.test looked up $n_lo times without a cap"
# a reconfiguration that sets a cap applies to the result already held: it is older than 5 s, so it is looked up at once
conf_file "alias-max-refresh-time 5;"
kill -HUP "$PID_K"
if kari_wait_log "$T/nc.log" '^lo.target.test 1 ' 20 3; then pass "a reload with alias-max-refresh-time applies to the result held ($(count "$T/nc.log" '^lo.target.test 1 ') lookups)"
else fail "lo.target.test looked up $(count "$T/nc.log" '^lo.target.test 1 ') times after the reload"; tail -5 "$T/k.log"; fi
check "the answer stays the same" "NOERROR|r.def.test. IN A 192.0.2.80;" "$(q r.def.test A)"

# ================================================================ 4. karicheck conf
echo "== 4. karicheck conf"
mkzone z.test ''
kc() {   # kc DESCRIPTION want(ok|error) CONF-TEXT
    printf '%s\n' "$3" > "$T/kc.conf"
    out=$($KARICHECK conf "$T/kc.conf" 2>&1); rc=$?
    if [ "$2" = ok ]; then
        [ $rc -eq 0 ] && pass "$1" || fail "$1: rc $rc: $out"
    else
        if [ $rc -ne 0 ] && printf '%s\n' "$out" | grep -q 'alias-max-refresh-time'; then pass "$1"; else fail "$1: rc $rc: $out"; fi
    fi
}
kc "options alias-max-refresh-time 30m is accepted" ok 'options { alias-max-refresh-time 30m; };'
kc "zone alias-max-refresh-time 86400 is accepted" ok "zone \"z.test.\" { type primary; file \"$T/z.test.zone\"; alias-max-refresh-time 86400; };"
kc "options alias-max-refresh-time 4 is an error" error 'options { alias-max-refresh-time 4; };'
kc "zone alias-max-refresh-time 2d is an error" error "zone \"z.test.\" { type primary; file \"$T/z.test.zone\"; alias-max-refresh-time 2d; };"
kc "database alias-max-refresh-time 0 is an error" error "options { database { driver sqlite3; database-file \"$T/none.db\"; alias-max-refresh-time 0; }; };"
echo 'options { alias-max-refresh-time 90000; };' > "$T/kc.conf"
out=$($KARICHECK --json conf "$T/kc.conf" 2>/dev/null)
printf '%s\n' "$out" | grep -q 'conf.alias-max-refresh-time' && pass "karicheck names the code conf.alias-max-refresh-time" || fail "no code in: $out"

echo ""
echo "passed $PASS, failed $FAILS"
[ $FAILS -eq 0 ] || { echo "--- karidns log (tail)"; tail -30 "$T/k.log"; echo "--- cookie log"; cat "$T/ck.cookies"; exit 1; }
exit 0
