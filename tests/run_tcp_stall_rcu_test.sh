#!/bin/sh
# ==============================================================================
# run_tcp_stall_rcu_test.sh
#
# Review H2: a TCP client that asks for a large answer and does not read it keeps the send of the worker waiting (up to 30 s on
# EAGAIN).  That wait must be outside the read section of the worker: a reload that waits for the readers of the previous
# configuration (perform_config_reload: the grace period of retire_epoch, at most 10 s, then "postponed") is not held up by it.
#  1. A client connects with a small receive buffer, sends queries for a TXT RRset of about 50 KB over one connection
#     (tcp-connection-reuse yes) and reads nothing.
#  2. Two `karictl reload` in a row while the client hangs: both are done (not postponed) in a few seconds.
#     (The second one waits for the readers that could see the configuration the first one replaced: a send held in the read
#     section would keep it waiting 10 s and postpone it.)
#  3. Once the client is gone the server answers (the worker whose send waits serves nothing else meanwhile).
# Needs perl.  SKIP without it.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
[ -x "$ROOT_DIR/karidns" ] || make -C "$ROOT_DIR" karidns
[ -x "$ROOT_DIR/karictl" ] || make -C "$ROOT_DIR" karictl
[ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
KARIDNS=${KARIDNS:-$ROOT_DIR/karidns}
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

PORT=$(kari_port 0 $((27000 + $$ % 4000)))
TMP_DIR="/tmp/tcp_stall_rcu_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
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

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

SECRET="cDEwLXRjcC1zdGFsbC1yY3UtdGVzdC1rZXktMDAwMDA="
{
    echo '$TTL 300'
    echo '$ORIGIN example.test.'
    echo '@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )'
    echo '@ IN NS ns1.example.test.'
    echo 'ns1 IN A 192.0.2.1'
    perl -e 'for my $i (1 .. 200) { printf("big IN TXT \"%03d%s\"\n", $i, "x" x 240) }'
} > "$TMP_DIR/example.test.zone"
cat > "$TMP_DIR/karidns.conf" <<EOF
options {
    port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
    tcp-connection-reuse yes;
    tcp-idle-timeout 600;
};
control-channel { socket "$TMP_DIR/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$TMP_DIR/ctl.conf"
chmod 600 "$TMP_DIR/ctl.conf"
chmod 644 "$TMP_DIR/example.test.zone" "$TMP_DIR/karidns.conf"

echo "=== a TCP client that does not read, and the read section (review H2) ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
if ! kari_wait_answer "$DAG" "$PORT" example.test; then
    echo "  FAIL: the server did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi

# the client: SO_RCVBUF 2048 before connect, 40 queries for big.example.test TXT on one connection, then it sleeps without reading
cat > "$TMP_DIR/stall.pl" <<'EOF'
use strict; use warnings;
use Socket qw(:all);
my ($port, $out) = @ARGV;
socket(my $s, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 2048)) or die "rcvbuf: $!";
connect($s, pack_sockaddr_in($port, inet_aton('127.0.0.1'))) or die "connect: $!";
my $q = '';
for my $id (1 .. 40) {
    my $m = pack('nnnnnn', $id, 0x0000, 1, 0, 0, 0) . "\x03big\x07example\x04test\x00" . pack('nn', 16, 1);
    $q .= pack('n', length $m) . $m;
}
syswrite($s, $q) == length $q or die "write: $!";
open(my $f, '>', $out) or die; print $f "sent\n"; close $f;
sleep 60;
EOF
perl "$TMP_DIR/stall.pl" "$PORT" "$TMP_DIR/stall.out" 2> "$TMP_DIR/stall.err" &
CLIENT_PID=$!
i=0; while [ ! -s "$TMP_DIR/stall.out" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
[ -s "$TMP_DIR/stall.out" ] && pass "the client sent its queries and reads nothing" || { fail "the client: $(cat "$TMP_DIR/stall.err")"; }
sleep 1

ctl() { "$KARICTL" -s "$TMP_DIR/ctl.sock" -f "$TMP_DIR/ctl.conf" "$@" 2>&1; }
T0=$(date +%s)
R1=$(ctl reload)
R2=$(ctl reload)
T1=$(date +%s)
E=$((T1 - T0))
if echo "$R1$R2" | grep -qi "postponed"; then
    fail "a reload was postponed while the client hung ($E s): $R1 / $R2"
elif [ "$E" -le 5 ]; then
    pass "two reloads while the client hangs are done in $E s (not postponed)"
else
    fail "two reloads took $E s: $R1 / $R2"
fi
grep -q "Reload postponed" "$TMP_DIR/karidns.log" && fail "log: a reload was postponed" || pass "log: no postponed reload"
kill -0 "$CLIENT_PID" 2>/dev/null && pass "the client is still connected (the test ran while it hung)" || fail "the client went away early"

# the worker whose send waits serves nothing else meanwhile (up to 30 s; the read section is the point of this test): the client goes away,
# the send fails, and the server answers again
kill "$CLIENT_PID" 2>/dev/null; wait "$CLIENT_PID" 2>/dev/null; CLIENT_PID=""
"$DAG" @127.0.0.1 -p "$PORT" ns1.example.test A +short +nohexdump +time=2 +tries=3 | grep -q 192.0.2.1 && pass "the server answers once the client is gone" || fail "no answer after the client went away"
kill -0 "$SERVER_PID" 2>/dev/null && pass "the server is running" || fail "the server is gone"

if [ "$FAILED" -eq 0 ]; then
    echo "=== run_tcp_stall_rcu_test: all checks passed ==="
    exit 0
fi
echo "=== run_tcp_stall_rcu_test: $FAILED check(s) FAILED ==="
exit 1
