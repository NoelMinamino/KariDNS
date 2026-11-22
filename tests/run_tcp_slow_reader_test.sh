#!/bin/sh
# ==============================================================================
# run_tcp_slow_reader_test.sh
#
# Review S-1 (2026-11-22): a TCP client that asks for large answers and reads them a few bytes at a time kept the worker's send waiting
# for ever (each 30 s wait of poll() ended with some progress), and that worker serves nothing else meanwhile: not its other connections,
# not its UDP.  The send of one answer now has tcp-idle-timeout (RFC 7766 §6.2.3) to leave once the client stops taking it at once; then
# the connection is closed.
#  1. One worker (worker-threads 1), tcp-idle-timeout 20 (2 s).  A client with a 2 KB receive buffer sends 40 queries for a TXT RRset of
#     about 50 KB on one connection (tcp-connection-reuse yes) and reads 256 bytes every 0.2 s (about 1.3 KB/s: the 2 MB would take
#     half an hour).
#  2. UDP is answered meanwhile, within a few seconds (the old code: not while the client reads).
#  3. The server closes the connection within the deadline (the client sees the end of the stream; the old code: never).
#  4. The worker serves TCP again, and the server is still running.
# Needs perl.  SKIP without it.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
[ -x "$ROOT_DIR/karidns" ] || make -C "$ROOT_DIR" karidns
[ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
KARIDNS=${KARIDNS:-$ROOT_DIR/karidns}
DAG="$ROOT_DIR/dag"

PORT=$(kari_port 0 $((31000 + $$ % 4000)))
TMP_DIR="/tmp/tcp_slow_reader_test_$$"
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
    worker-threads 1;
    tcp-connection-reuse yes;
    tcp-idle-timeout 20;
};
zone "example.test" { type primary; file "$TMP_DIR/example.test.zone"; };
EOF
chmod 644 "$TMP_DIR/example.test.zone" "$TMP_DIR/karidns.conf"

echo "=== a TCP client that reads its large answers a few bytes at a time (review S-1) ==="
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
if ! kari_wait_answer "$DAG" "$PORT" example.test; then
    echo "  FAIL: the server did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi

# the client: SO_RCVBUF 2048 before connect, 40 queries for big.example.test TXT on one connection, then 256 bytes every 0.2 s until the
# server closes (or 90 s); it writes "sent" when the queries are out and "eof <ms> <bytes>" when the stream ends
cat > "$TMP_DIR/slow.pl" <<'EOF'
use strict; use warnings;
use Socket qw(:all);
use Time::HiRes qw(time sleep);
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
my $t0 = time;
{ open(my $f, '>', "$out.sent") or die; print $f "sent\n"; close $f; }
my $got = 0;
while (time - $t0 < 90) {
    my $n = sysread($s, my $buf, 256);
    last if !defined $n || $n == 0;
    $got += $n;
    sleep 0.2;
}
open(my $f, '>', $out) or die;
printf $f "eof %d %d\n", (time - $t0) * 1000, $got;
close $f;
EOF
T0=$(date +%s)
perl "$TMP_DIR/slow.pl" "$PORT" "$TMP_DIR/slow.out" 2> "$TMP_DIR/slow.err" &
CLIENT_PID=$!
i=0; while [ ! -s "$TMP_DIR/slow.out.sent" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
[ -s "$TMP_DIR/slow.out.sent" ] && pass "the client sent its queries and reads slowly" || fail "the client: $(cat "$TMP_DIR/slow.err")"

# 2. UDP while the client reads: the one worker answers within a few seconds (tcp-idle-timeout 2 s, then the send gives up); bounded wait
udp_ok=0; i=0
while [ $i -lt 15 ]; do
    if "$DAG" @127.0.0.1 -p "$PORT" ns1.example.test A +short +nohexdump +notcp +time=1 +tries=1 2>/dev/null | grep -q 192.0.2.1; then udp_ok=1; break; fi
    i=$((i + 1))
done
E=$(($(date +%s) - T0))
if [ "$udp_ok" -eq 1 ] && [ "$E" -le 12 ]; then
    pass "UDP is answered $E s after the slow client started (the worker is not held by it)"
else
    fail "UDP not answered within 12 s of the slow client's start (answered=$udp_ok after $E s; client: $(cat "$TMP_DIR/slow.out" 2>/dev/null))"
fi

# 3. the connection is closed within the deadline: the client sees the end of the stream (bounded wait)
i=0; while [ ! -s "$TMP_DIR/slow.out" ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i + 1)); done
if [ -s "$TMP_DIR/slow.out" ]; then
    read -r _w MS BYTES < "$TMP_DIR/slow.out"
    if [ "$MS" -le 15000 ] && [ "$BYTES" -lt 1000000 ]; then
        pass "the server closed the slow connection after $MS ms ($BYTES bytes read of about 2 MB)"
    else
        fail "the slow connection ended after $MS ms with $BYTES bytes (expected a close within 15 s, well before the 2 MB)"
    fi
else
    fail "the server did not close the slow connection within $(($(date +%s) - T0)) s (client still reading: $(kill -0 "$CLIENT_PID" 2>/dev/null && echo yes || echo no))"
fi
kill "$CLIENT_PID" 2>/dev/null; wait "$CLIENT_PID" 2>/dev/null; CLIENT_PID=""

# 4. the worker serves TCP again; the server runs
"$DAG" @127.0.0.1 -p "$PORT" ns1.example.test A +short +nohexdump +tcp +time=2 +tries=3 | grep -q 192.0.2.1 && pass "TCP is answered again" || fail "no TCP answer after the slow client"
kill -0 "$SERVER_PID" 2>/dev/null && pass "the server is running" || { fail "the server is gone"; tail -20 "$TMP_DIR/karidns.log"; }

if [ "$FAILED" -eq 0 ]; then
    echo "=== run_tcp_slow_reader_test: all checks passed ==="
    exit 0
fi
tail -20 "$TMP_DIR/karidns.log"
echo "=== run_tcp_slow_reader_test: $FAILED check(s) FAILED ==="
exit 1
