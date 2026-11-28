#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"
KARICTL="$ROOT/karictl"

[ -x "$ROOT/karidns" ] && [ -x "$ROOT/dag" ] && [ -x "$ROOT/karictl" ] || {
    echo "[*] Building targets..."
    make -C "$ROOT" karidns dag karictl
}

CONF="$DIR/notify_source_test.conf"
ZONE="$DIR/zones/notify_source_test.zone"
OUT_NOTIFY="$DIR/notify_received.log"
TMP_DIR="/tmp/notify_source_test_$$"   # own directory for the control socket (a socket in /tmp itself is refused)
CTL_CONF="$TMP_DIR/karictl.conf"

mkdir -p "$DIR/zones"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

# -----------------------------------------------------------------------------
# FreeBSD / OS loopback alias configuration
# FreeBSD defaults to having only 127.0.0.1 on lo0.
# Testing notify-source with 127.0.0.2 ensures we verify that packets actually
# originate from the explicit notify-source IP rather than the default 127.0.0.1.
# -----------------------------------------------------------------------------
TEST_SRC_IP="127.0.0.2"
ALIAS_ADDED=0

check_ip_available() {
    if ifconfig lo0 2>/dev/null | grep -q "inet $1 " || \
       ifconfig lo 2>/dev/null | grep -q "inet $1 "; then
        return 0
    fi
    return 1
}

if ! check_ip_available "$TEST_SRC_IP"; then
    if [ "$(id -u)" -eq 0 ]; then
        echo "[*] Adding loopback alias $TEST_SRC_IP for FreeBSD/Unix testing..."
        if ifconfig lo0 inet "$TEST_SRC_IP/32" alias 2>/dev/null; then
            ALIAS_ADDED=1
        elif ifconfig lo inet "$TEST_SRC_IP/32" alias 2>/dev/null; then
            ALIAS_ADDED=1
        fi
    else
        echo "[!] Non-root user: cannot add $TEST_SRC_IP alias via ifconfig."
        echo "[!] Falling back to 127.0.0.1 for basic smoke test (run as root or add 127.0.0.2 alias for strict source IP verification)."
        TEST_SRC_IP="127.0.0.1"
    fi
fi

cat << 'EOF' > "$ZONE"
$ORIGIN notify.test.
$TTL 3600
@   IN SOA  ns1.notify.test. hostmaster.notify.test. 2026082401 7200 3600 1209600 3600
@   IN NS   ns1.notify.test.
ns1 IN A    127.0.0.1
EOF

cat << EOF > "$CONF"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
control-channel {
    socket "$TMP_DIR/ctl.sock";
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
zone "notify.test" {
    type master;
    file "$ZONE";
    also-notify { 127.0.0.1 port 10054; };
    notify-source "$TEST_SRC_IP";
};
EOF

cat << EOF > "$CTL_CONF"
socket "$TMP_DIR/ctl.sock";
key "karictl" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF
chmod 600 "$CTL_CONF"   # karictl refuses a karictl.conf with the secret that others can read

# Start UDP Listener on 10054 using Perl to capture sender IP and packet details
rm -f "$OUT_NOTIFY"
perl -e '
use strict;
use warnings;
use Socket;

my $port = 10054;
socket(my $sock, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
bind($sock, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

open(my $rd, ">", $ARGV[1]) or die $!;   # the socket is bound: the shell waits for this file
print $rd "LISTENER_READY\n";
close($rd);

my $buf;
my $from = recv($sock, $buf, 4096, 0);
if ($from) {
    my ($src_port, $src_ip) = sockaddr_in($from);
    my $ip_str = inet_ntoa($src_ip);
    my ($id, $flags, $qd, $an, $ns, $ar) = unpack("n6", $buf);
    my $opcode = ($flags >> 11) & 0x0F;
    open(my $fh, ">", $ARGV[0]) or die $!;
    print $fh "SRC_IP=$ip_str\n";
    print $fh "SRC_PORT=$src_port\n";
    print $fh "OPCODE=$opcode\n";
    print $fh "QDCOUNT=$qd\n";
    close($fh);
}
' "$OUT_NOTIFY" "$TMP_DIR/listener.ready" > "$TMP_DIR/listener.err" 2>&1 &
PERL_PID=$!
if ! kari_wait_log "$TMP_DIR/listener.ready" LISTENER_READY 10; then
    echo "[FAIL] the NOTIFY listener on 127.0.0.1:10054 did not start:"
    cat "$TMP_DIR/listener.err"
    exit 1
fi

echo "[*] Starting KariDNS on port 10053 (notify-source: $TEST_SRC_IP)..."
$BIN -f -c "$CONF" > "$DIR/server_notify.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    echo "[*] Cleaning up test processes and aliases..."
    kari_kill_tree "${SERVER_PID:-}"
    kari_kill_tree "${PERL_PID:-}"
    if [ "$ALIAS_ADDED" = "1" ]; then
        ifconfig lo0 inet "$TEST_SRC_IP" -alias 2>/dev/null || \
        ifconfig lo inet "$TEST_SRC_IP" -alias 2>/dev/null || true
    fi
    rm -f "$CONF" "$ZONE" "$OUT_NOTIFY" "$DIR/server_notify.log"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if ! kari_wait_answer "$DAG" 10053 notify.test. 30; then
    echo "[FAIL] the server did not answer notify.test SOA within 30 s"
    cat "$DIR/server_notify.log"
    exit 1
fi

# Send notify command via karictl.  The control socket is bound before the server answers
# (dns_server_core.c binds it before the Backend fork), so it exists by now.
echo "[*] Sending NOTIFY via karictl..."
if ! $KARICTL -f "$CTL_CONF" notify notify.test > "$TMP_DIR/karictl.out" 2>&1; then
    echo "[FAIL] karictl notify failed:"
    cat "$TMP_DIR/karictl.out"
    ls -l "$TMP_DIR"
    cat "$DIR/server_notify.log"
    exit 1
fi

# Wait for notification capture (the listener exits after one datagram)
i=0
while [ ! -s "$OUT_NOTIFY" ] && [ "$i" -lt 200 ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ ! -f "$OUT_NOTIFY" ] || [ ! -s "$OUT_NOTIFY" ]; then
    echo "[FAIL] No NOTIFY packet received by listener on 127.0.0.1:10054"
    cat "$TMP_DIR/karictl.out" "$TMP_DIR/listener.err"
    cat "$DIR/server_notify.log"
    exit 1
fi

cat "$OUT_NOTIFY"

if grep -q "SRC_IP=$TEST_SRC_IP" "$OUT_NOTIFY" && grep -q "OPCODE=4" "$OUT_NOTIFY"; then
    echo "[PASS] NOTIFY packet verified: received from configured notify-source ($TEST_SRC_IP) with OPCODE=4 (NOTIFY)"
else
    echo "[FAIL] NOTIFY packet verification failed (expected SRC_IP=$TEST_SRC_IP)!"
    exit 1
fi

exit 0
