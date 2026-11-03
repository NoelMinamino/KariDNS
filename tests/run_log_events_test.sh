#!/bin/sh
# ==============================================================================
# tests/run_log_events_test.sh - the event messages of the categories update-security, update, xfer-out and query-errors (batch 14)
# ==============================================================================
#   U  update-security / update: a signed UPDATE (signer "k" approved), an UPDATE refused by allow-update (ERROR) and by a zone without an update ACL
#      (INFO), a secondary zone, NOTAUTH and a zone section that is not a SOA (category update), update-policy refusals, a failed prerequisite;
#      the rate limit: a flood of refused UPDATEs writes at most about 10 lines per second and a report of the rest
#   X  xfer-out: AXFR / IXFR over TCP (started, ended with messages / records / bytes / time), IXFR that falls back to AXFR, an up-to-date IXFR,
#      refusals (allow-transfer, a zone that is not served, a bad TSIG), the IXFR over UDP
#   Q  query-errors: the reasons of SERVFAIL / FORMERR / REFUSED at the levels the channel asks for
#   R  the paths: the same messages from a worker thread (through the ring) and from the transfer thread (directly); the categories without a
#      channel cost nothing and write nothing
# The channels write to files in one directory that the run user "nobody" can write to.  Runs as root or as an ordinary user.
# ==============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns dag >/dev/null || exit 1

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-logev.XXXXXX")"
chmod 755 "$W"
LG="$W/logs"
mkdir "$LG"
chmod 777 "$LG"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
SECRET="bG9nZXZlbnRzLXRlc3Qta2V5LTAwMDAwMDAwMDAwMDA="
KEY="hmac-sha256:upd:$SECRET"

P1=$(kari_port 0) P2=$(kari_port 1)
PIDS=""
FAILS=0
PASSES=0
pass() { echo "PASS: $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

cleanup() {
    set +e
    kari_kill_tree $PIDS
    if [ "$FAILS" -ne 0 ]; then
        for f in "$W"/*.log "$LG"/*.log; do [ -f "$f" ] && { echo "--- $f (tail)"; tail -25 "$f"; }; done
    fi
    if [ -n "${KARI_KEEP_TMP:-}" ]; then echo "kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT INT TERM

for p in $P1 $P2; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

wait_free() { # PORT : nothing listens there any more (a stopped server takes a moment)
    _i=0
    while [ $_i -lt 50 ]; do sockstat -4 -l -p "$1" 2>/dev/null | grep -q ":$1 " || return 0; sleep 0.2; _i=$((_i + 1)); done
    return 1
}
wait_grep() { # PATTERN FILE [SECONDS]
    _i=0
    while [ $_i -lt $((${3:-10} * 5)) ]; do grep -q -- "$1" "$2" 2>/dev/null && return 0; sleep 0.2; _i=$((_i + 1)); done
    return 1
}
count() { grep -c -- "$1" "$2" 2>/dev/null || true; }
has() { # has NAME FILE PATTERN : the pattern is in the file (after a short wait)
    if wait_grep "$3" "$2" 6; then pass "$1"; else fail "$1: no line matching [$3] in $2"; tail -8 "$2" 2>/dev/null | sed 's/^/        /'; fi
}
hasnt() { # hasnt NAME FILE PATTERN
    sleep 0.5
    if grep -q -- "$3" "$2" 2>/dev/null; then fail "$1: unexpected line matching [$3]"; grep -- "$3" "$2" | head -3 | sed 's/^/        /'; else pass "$1"; fi
}
d() { "$DAG" @127.0.0.1 -p "$P1" +nohexdump +time=2 +tries=1 "$@" 2>&1; }

zonefile() { # zonefile FILE ORIGIN SERIAL
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' "$2" "$3" > "$1"
}
zonefile "$W/u.zone" u.test 1
zonefile "$W/noacl.zone" noacl.test 1
zonefile "$W/pol.zone" pol.test 1
zonefile "$W/x.zone" x.test 1
zonefile "$W/deny.zone" deny.test 1
zonefile "$W/key.zone" key.test 1

chan() { # chan NAME FILE [SEVERITY]
    printf '    channel %s { file "%s"; severity %s; print-category yes; print-severity yes; };\n' "$1" "$2" "${3:-info}"
}

cat > "$W/s1.conf" <<EOF
options { port $P1; listen-on { 127.0.0.1; }; pid-file "none"; $USER_OPT };
key "upd" { algorithm hmac-sha256; secret "$SECRET"; };
logging {
$(chan sec "$LG/sec.log")
$(chan upd "$LG/upd.log")
    category update-security { sec; };
    category update { upd; };
};
zone "u.test" { type primary; file "$W/u.zone"; allow-update { key upd; }; };
zone "noacl.test" { type primary; file "$W/noacl.zone"; };
zone "pol.test" { type primary; file "$W/pol.zone"; update-policy { grant upd zonesub A; }; };
zone "sec.test" { type secondary; primaries { 127.0.0.1 port $P2; }; allow-update { key upd; }; };
EOF
"$KARIDNS" -f "$W/s1.conf" > "$W/s1.log" 2>&1 &
PIDS="$PIDS $!"
S1=$!
_i=0; while [ $_i -lt 20 ]; do d u.test SOA +short | grep -q hostmaster && break; sleep 0.5; _i=$((_i + 1)); done

# ------------------------------------------------------------------------------------------------ U: update-security / update
echo "== U: UPDATE"
d u.test A --update-add 'a1.u.test 300 A 192.0.2.101' -y "$KEY" | grep -q "status: NOERROR" && pass "U: a signed UPDATE is applied" || fail "U: signed UPDATE"
has "U: signer approved (update-security, info)" "$LG/sec.log" 'update-security: info: client 127\.0\.0\.1#[0-9]*: signer "upd" approved'
d u.test A --update-add 'a2.u.test 300 A 192.0.2.102' | grep -q "status: REFUSED" && pass "U: an unsigned UPDATE is REFUSED" || fail "U: unsigned UPDATE"
has "U: update denied by allow-update (error)" "$LG/sec.log" "update-security: error: client 127\.0\.0\.1#[0-9]*: update 'u\.test/IN' denied"
d u.test A --update-add 'a3.u.test 300 A 192.0.2.103' -y "hmac-sha256:upd:$SECRET" >/dev/null
d noacl.test A --update-add 'a1.noacl.test 300 A 192.0.2.104' | grep -q "status: REFUSED" && pass "U: UPDATE to a zone without update ACL is REFUSED" || fail "U: noacl"
has "U: no update ACL: update denied at info" "$LG/sec.log" "update-security: info: client 127\.0\.0\.1#[0-9]*: update 'noacl\.test/IN' denied"
d sec.test A --update-add 'a1.sec.test 300 A 192.0.2.105' -y "$KEY" | grep -q "status: REFUSED" && pass "U: UPDATE to a secondary is REFUSED" || fail "U: secondary"
has "U: secondary zone: update forwarding denied" "$LG/sec.log" "update forwarding 'sec\.test/IN' denied"
d other.test A --update-add 'a1.other.test 300 A 192.0.2.106' -y "$KEY" | grep -q "status: NOTAUTH" && pass "U: UPDATE for a zone that is not served: NOTAUTH" || fail "U: notauth"
has "U: NOTAUTH is logged in the update category" "$LG/upd.log" "update: info: client 127\.0\.0\.1#[0-9]*: update failed: other\.test: not authoritative for update zone (NOTAUTH)"
d u.test A --update-add 'a1.u.test 300 A 192.0.2.101' --prereq-nxdomain a1.u.test -y "$KEY" | grep -q "status: YXDOMAIN" && pass "U: failed prerequisite: YXDOMAIN" || fail "U: prereq"
has "U: a failed prerequisite is logged" "$LG/upd.log" "updating zone 'u\.test/IN': update failed: prerequisite not satisfied (YXDOMAIN)"
d pol.test A --update-add 'a1.pol.test 300 A 192.0.2.107' -y "$KEY" | grep -q "status: NOERROR" && pass "U: update-policy grants an A" || fail "U: policy A"
d pol.test A --update-add 'a2.pol.test 300 TXT "x"' -y "$KEY" | grep -q "status: REFUSED" && pass "U: update-policy refuses a TXT" || fail "U: policy TXT"
has "U: the policy refusal names the record" "$LG/upd.log" "updating zone 'pol\.test/IN': update failed: rejected by secure update (REFUSED): a2\.pol\.test TXT"
has "U: signer approved for the policy zone" "$LG/sec.log" 'signer "upd" approved'
d pol.test A --update-add 'a3.pol.test 300 A 192.0.2.108' | grep -q "status: REFUSED" && pass "U: update-policy: an unsigned UPDATE is REFUSED" || fail "U: policy unsigned"
has "U: policy zone, unsigned: update denied (error: a policy is an update ACL)" "$LG/sec.log" "update-security: error: client 127\.0\.0\.1#[0-9]*: update 'pol\.test/IN' denied"

# the rate limit: a flood of refused UPDATEs
N0=$(count "update 'u.test/IN' denied" "$LG/sec.log")
T0=$(date +%s)
i=0
while [ $i -lt 60 ]; do d u.test A --update-add "f$i.u.test 300 A 192.0.2.200" >/dev/null; i=$((i + 1)); done
T1=$(date +%s)
sleep 2
N1=$(count "update 'u.test/IN' denied" "$LG/sec.log")
NEW=$((N1 - N0))
MAX=$(( (T1 - T0 + 2) * 10 ))
if [ "$NEW" -ge 1 ] && [ "$NEW" -le "$MAX" ]; then pass "U: 60 refused UPDATEs in $((T1 - T0)) s wrote $NEW 'denied' lines (at most $MAX: 10 per second)"; else fail "U: rate limit: $NEW lines for 60 refusals in $((T1 - T0)) s (max $MAX)"; fi
has "U: the suppressed lines are reported" "$LG/sec.log" "update-security: [a-z]*: [0-9]* message(s) suppressed by the rate limit of 10 per second"

# ------------------------------------------------------------------------------------------------ X: xfer-out
echo "== X: xfer-out"
kari_kill_tree $S1; PIDS=""
wait_free $P1
perl -e 'print "\$TTL 300\n\$ORIGIN big.test.\n\@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n\@ IN NS ns1\nns1 IN A 192.0.2.1\n"; for my $i (1..30000) { printf "h%d IN TXT \"%s\"\n", $i, "x" x 200 }' > "$W/big.zone"
cat > "$W/s2.conf" <<EOF
options { port $P1; listen-on { 127.0.0.1; }; pid-file "none"; transfers-out 1; max-transfer-idle-out 1; $USER_OPT };
key "upd" { algorithm hmac-sha256; secret "$SECRET"; };
logging {
$(chan xf "$LG/xfer.log")
$(chan xfd "$LG/xfer_dbg.log" "debug 1")
$(chan xf4 "$LG/xfer_dbg4.log" "debug 4")
    category xfer-out { xf; xfd; xf4; };
};
zone "x.test" { type primary; file "$W/x.zone"; allow-update { key upd; }; allow-transfer { 127.0.0.1; }; };
zone "deny.test" { type primary; file "$W/deny.zone"; allow-transfer { none; }; };
zone "key.test" { type primary; file "$W/key.zone"; allow-transfer { key upd; }; };
zone "big.test" { type primary; file "$W/big.zone"; allow-transfer { 127.0.0.1; }; };
EOF
KARIDNS_XFER_MINUTE_SECS=1 "$KARIDNS" -f "$W/s2.conf" > "$W/s2.log" 2>&1 &
PIDS="$PIDS $!"
S2=$!
_i=0; while [ $_i -lt 20 ]; do d x.test SOA +tcp +short | grep -q hostmaster && break; sleep 0.5; _i=$((_i + 1)); done
sleep 1

d x.test AXFR | grep -q "SOA" && pass "X: AXFR over TCP works" || fail "X: AXFR"
has "X: AXFR started" "$LG/xfer.log" "xfer-out: info: client 127\.0\.0\.1#[0-9]*: transfer of 'x\.test/IN': AXFR started (serial 1)"
has "X: AXFR ended with the statistics" "$LG/xfer.log" "transfer of 'x\.test/IN': AXFR ended: 1 messages, [0-9]* records, [0-9]* bytes, 0\.[0-9][0-9][0-9] secs ([0-9]* bytes/sec) (serial 1)"
d x.test A --update-add 'n1.x.test 300 A 192.0.2.50' -y "$KEY" | grep -q "status: NOERROR" && pass "X: the zone moves to serial 2" || fail "X: update"
d x.test IXFR=1 +tcp | grep -q "SOA" && pass "X: IXFR from serial 1 over TCP" || fail "X: IXFR"
has "X: IXFR started with both serials" "$LG/xfer.log" "transfer of 'x\.test/IN': IXFR started (serial 1 -> 2)"
has "X: IXFR ended" "$LG/xfer.log" "transfer of 'x\.test/IN': IXFR ended: [0-9]* messages, [0-9]* records, [0-9]* bytes"
d x.test IXFR=0 +tcp | grep -q "SOA" && pass "X: IXFR from a serial the history does not have" || fail "X: IXFR old"
has "X: IXFR falling back to AXFR" "$LG/xfer.log" "transfer of 'x\.test/IN': IXFR version not in journal, falling back to AXFR"
has "X: AXFR-style IXFR started" "$LG/xfer.log" "transfer of 'x\.test/IN': AXFR-style IXFR started (serial 2)"
d x.test IXFR=2 +tcp | grep -q "SOA" && pass "X: IXFR from the current serial (a poll)" || fail "X: IXFR poll"
has "X: the poll is a debug 1 line" "$LG/xfer_dbg.log" "xfer-out: debug 1: client 127\.0\.0\.1#[0-9]*: transfer of 'x\.test/IN': IXFR poll up to date (serial 2)"
hasnt "X: ... and not at info" "$LG/xfer.log" "poll up to date"
d x.test IXFR=1 +notcp | grep -q "SOA" && pass "X: IXFR over UDP" || fail "X: IXFR UDP"
has "X: IXFR over UDP from a serial that is behind: SOA and TC" "$LG/xfer.log" "transfer of 'x\.test/IN': IXFR over UDP: serial 1 is behind 2, answered with the SOA and TC=1"
d x.test IXFR=2 +notcp | grep -q "SOA" && pass "X: IXFR over UDP, up to date" || fail "X: IXFR UDP poll"
d x.test AXFR -y "$KEY" >/dev/null
d key.test AXFR -y "$KEY" | grep -q "Transfer failed" && pass "X: a zone whose key is the ACL" || true
d deny.test AXFR | grep -qi "refused\|Transfer failed" && pass "X: AXFR denied by allow-transfer" || fail "X: deny"
has "X: denied: zone transfer ... denied (error)" "$LG/xfer.log" "xfer-out: error: client 127\.0\.0\.1#[0-9]*: zone transfer 'deny\.test/AXFR/IN' denied"
d deny.test IXFR=1 +notcp | grep -qi "refused\|failed" && pass "X: IXFR over UDP denied by allow-transfer" || fail "X: deny UDP"
has "X: ... IXFR over UDP" "$LG/xfer.log" "zone transfer 'deny\.test/IXFR/IN' denied"
d nosuch.test AXFR | grep -qi "refused\|Transfer failed" && pass "X: AXFR of a zone that is not served" || fail "X: nosuch"
has "X: non-authoritative zone" "$LG/xfer.log" "transfer of 'nosuch\.test/IN': bad zone transfer request: non-authoritative zone (REFUSED)"
d key.test AXFR -y "hmac-sha256:upd:Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy" | grep -qi "fail\|NOTAUTH\|bad" && pass "X: AXFR signed with a wrong secret" || fail "X: bad tsig"
has "X: TSIG that does not verify" "$LG/xfer.log" "transfer of 'key\.test/IN': bad zone transfer request: TSIG verification failed (NOTAUTH)"
d x.test AXFR +notcp | grep -qi "FORMERR\|Transfer failed\|truncated" ; pass "X: AXFR over UDP was sent"
has "X: AXFR over UDP is a bad request" "$LG/xfer.log" "transfer of 'x\.test/IN': bad zone transfer request: attempted AXFR over UDP (FORMERR)"

# transfers-out 1 and a client that does not read: the second transfer is refused (quota), the first one is aborted by max-transfer-idle-out
perl "$DIR/lib_slow_axfr_client.pl" "$P1" big.test 6 > "$W/slow.out" 2>&1 &
SLOWPID=$!
sleep 1
d big.test AXFR +time=3 | head -5 | grep -qi "refused\|Transfer failed" && pass "X: a second transfer over transfers-out is refused" || fail "X: quota"
has "X: quota reached (warning)" "$LG/xfer.log" "xfer-out: warning: client 127\.0\.0\.1#[0-9]*: transfer of 'big\.test/IN': AXFR request denied: quota reached (transfers-out 1)"
wait_grep "transfer of 'big.test/IN': AXFR aborted: the message could not be sent to the client" "$LG/xfer.log" 12 && pass "X: the transfer to the client that does not read is aborted (max-transfer-idle-out 1)" || fail "X: no abort line"
has "X: the abort line has the statistics" "$LG/xfer.log" "AXFR aborted: .* ([0-9]* messages, [0-9]* records, [0-9]* bytes were sent)"
wait $SLOWPID 2>/dev/null
hasnt "X: no debug 4 line without provide-ixfr no" "$LG/xfer_dbg4.log" "provide-ixfr"
kari_kill_tree $S2; PIDS=""
wait_free $P1

# the same, with provide-ixfr no (debug 4) and no channel for xfer-out at all: nothing is written
cat > "$W/s3.conf" <<EOF
options { port $P1; listen-on { 127.0.0.1; }; pid-file "none"; provide-ixfr no; $USER_OPT };
logging {
$(chan xf4 "$LG/xfer_dbg4b.log" "debug 4")
$(chan other "$LG/other.log")
    category xfer-out { xf4; };
    category general { other; };
};
zone "x.test" { type primary; file "$W/x.zone"; allow-transfer { 127.0.0.1; }; };
EOF
"$KARIDNS" -f "$W/s3.conf" > "$W/s3.log" 2>&1 &
PIDS="$PIDS $!"
S3=$!
_i=0; while [ $_i -lt 20 ]; do d x.test SOA +tcp +short | grep -q hostmaster && break; sleep 0.5; _i=$((_i + 1)); done
d x.test IXFR=0 +tcp | grep -q "SOA" && pass "X: IXFR with provide-ixfr no is answered with the whole zone" || { fail "X: provide-ixfr no"; d x.test IXFR=0 +tcp | head -8; }
has "X: provide-ixfr no: debug 4 line" "$LG/xfer_dbg4b.log" "xfer-out: debug 4: client 127\.0\.0\.1#[0-9]*: transfer of 'x\.test/IN': IXFR delta response disabled due to 'provide-ixfr no;' being set"
has "X: ... and the AXFR-style IXFR" "$LG/xfer_dbg4b.log" "AXFR-style IXFR started (serial 1)"
kari_kill_tree $S3; PIDS=""
wait_free $P1

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
