#!/bin/sh
# ==============================================================================
# run_xfr_dispatch_fault_test.sh - the TCP zone transfer dispatch when the transfer cannot be started
#
# The dispatch (dns_server_core.c) starts a thread for each allowed AXFR / IXFR; when the thread cannot be created (XD_NO_THREAD) or its arguments
# cannot be allocated (XD_NO_MEMORY) the request is refused: REFUSED, AA=0, EDE 0 Other without a text (an internal failure tells the client nothing
# about the server's state, RFC 8914 §4.1), and the reason is logged in category xfer-out ("AXFR request denied: cannot start a thread for the
# transfer" / "... out of memory", at error).  The failures are acted out with the TEST-ONLY control command `karictl xfr-fail thread|memory|off`
# (karidns-evict and the coverage build; it does not exist in any other build).  Checked: both failures, AXFR and IXFR, with send-extended-errors
# (EDE 0, no text) and the log lines; the transfer works again after `xfr-fail off`; a bad argument is an error.
# SKIP when karidns-evict (make evict), karictl or perl is missing.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
# the server with the test hook: ./karidns when it has it (the instrumented build of `make coverage` does), else ./karidns-evict (make evict)
has_hook() { [ -x "$1" ] && grep -q 'expected thread, memory or off' "$1" 2>/dev/null; }
if [ -z "${KARIDNS:-}" ]; then
    if has_hook ./karidns; then KARIDNS=./karidns; else KARIDNS=./karidns-evict; fi
fi
for b in "$KARIDNS" ./dag ./karictl; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
has_hook "$KARIDNS" || { echo "SKIP: $KARIDNS has no test hook (make evict)"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
perl -MDigest::SHA -MMIME::Base64 -e 1 2>/dev/null || { echo "SKIP: perl lacks Digest::SHA or MIME::Base64"; exit 0; }
TQ="perl $ROOT/tests/tsig_query.pl"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"      # (as run_db_park_test.sh: karidns-evict is an ASan + UBSan build)

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_xfault.XXXXXX") || exit 1
chmod 755 "$T"
mkdir "$T/logs"; chmod 777 "$T/logs"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    SRV=""
}
trap 'stop_srv; rm -rf "$T"' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
USER_OPT=""
if [ "$(id -u)" = "0" ]; then USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"; fi

cat > "$T/ax.zone" <<'EOF'
$TTL 300
$ORIGIN ax.test.
@ IN SOA ns1.ax.test. hostmaster.ax.test. ( 5 3600 600 86400 60 )
@ IN NS ns1.ax.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
EOF
chmod 644 "$T/ax.zone"
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"
cat > "$T/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; send-extended-errors yes; $USER_OPT };
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
zone "ax.test" { type master; file "$T/ax.zone"; allow-transfer { 127.0.0.1; }; };
logging {
    channel xo { file "$T/logs/xfer.log"; severity info; print-category yes; print-severity yes; };
    category xfer-out { xo; };
};
EOF
"$KARIDNS" -f "$T/k.conf" >> "$T/server.log" 2>&1 &
SRV=$!
kari_wait_answer ./dag "$PORT" ax.test. || { echo "FAIL: the server did not start"; cat "$T/server.log"; exit 1; }

# t NAME ERE ARGS... : one TCP request, the first line of the answer must match ERE
t() {
    _n=$1; _w=$2; shift 2
    _o=$($TQ --port "$PORT" --tcp --show-ede-text "$@" | head -1)
    if echo "$_o" | grep -Eq "$_w"; then pass "$_n ($_o)"; else fail "$_n: got '$_o', expected /$_w/"; fi
}
REFUSED_E0='^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=0 ede-text=-$'
# xlog TEXT: a line of category xfer-out at error has TEXT (the logger writes it a moment after the answer)
xlog() {
    i=0; while [ $i -lt 30 ] && ! grep -q "$1" "$T/logs/xfer.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "^xfer-out: error: client 127\.0\.0\.1#[0-9]*: transfer of 'ax\.test/IN': $1\$" "$T/logs/xfer.log" \
        && pass "logged: '$1'" || fail "no xfer-out error line '$1': $(tail -3 "$T/logs/xfer.log" 2>/dev/null)"
}

echo "== the transfer works"
t "AXFR"                                            '^rcode=0 tc=0 aa=1 qd=1 an=[1-9]' --name ax.test --type AXFR

echo "== no thread for the transfer (XD_NO_THREAD)"
$KCTL xfr-fail thread | grep -q '^OK' && pass "karictl xfr-fail thread (the test hook)" || fail "xfr-fail thread: $($KCTL xfr-fail thread 2>&1)"
t "AXFR: REFUSED, EDE 0 without a text"             "$REFUSED_E0" --name ax.test --type AXFR --edns-version 0
t "IXFR: REFUSED, EDE 0 without a text"             "$REFUSED_E0" --name ax.test --type IXFR --ixfr-serial 1 --edns-version 0
t "without OPT: REFUSED, no OPT"                    '^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=0 opt=none' --name ax.test --type AXFR
xlog "AXFR request denied: cannot start a thread for the transfer"
xlog "IXFR request denied: cannot start a thread for the transfer"

echo "== no memory for the transfer (XD_NO_MEMORY)"
$KCTL xfr-fail memory | grep -q '^OK' && pass "karictl xfr-fail memory" || fail "xfr-fail memory"
t "AXFR: REFUSED, EDE 0 without a text"             "$REFUSED_E0" --name ax.test --type AXFR --edns-version 0
t "IXFR: REFUSED, EDE 0 without a text"             "$REFUSED_E0" --name ax.test --type IXFR --ixfr-serial 1 --edns-version 0
xlog "AXFR request denied: out of memory"
xlog "IXFR request denied: out of memory"

echo "== off again"
$KCTL xfr-fail off | grep -q '^OK' && pass "karictl xfr-fail off" || fail "xfr-fail off"
t "AXFR is transferred again"                       '^rcode=0 tc=0 aa=1 qd=1 an=[1-9]' --name ax.test --type AXFR
$KCTL xfr-fail sometimes | grep -q '^ERROR' && pass "xfr-fail refuses an unknown failure" || fail "xfr-fail sometimes was accepted"
[ "$($KCTL status 2>/dev/null | grep -c .)" -gt 0 ] && pass "the server still answers the control channel" || fail "karictl status"

stop_srv
grep -E 'AddressSanitizer|runtime error' "$T/server.log" > /dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report"
echo "== $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
