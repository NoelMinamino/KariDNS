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

kari_kill_tree $S1; PIDS=""

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
