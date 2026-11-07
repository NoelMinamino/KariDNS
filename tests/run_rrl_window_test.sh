#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
PORT=$(kari_port 0 10053)
ROOT="$DIR/.."
BIN="$ROOT/karidns"

[ -x "$ROOT/karidns" ] || {
    echo "[*] Building targets..."
    [ -x "$ROOT/karidns" ] || make -C "$ROOT" karidns
}

CONF="$DIR/rrl_window_test.conf"
ZONE="$DIR/zones/rrl_window_test.zone"

mkdir -p "$DIR/zones"

cat << 'EOF' > "$ZONE"
$ORIGIN rrl.test.
$TTL 3600
@   IN SOA  ns1.rrl.test. hostmaster.rrl.test. 2026082401 7200 3600 1209600 3600
@   IN NS   ns1.rrl.test.
ns1 IN A    127.0.0.1
www IN A    192.0.2.1
EOF

cat << EOF > "$CONF"
options {
    port ${PORT};
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    rate-limit {
        responses-per-second 5;
        window 3;
        slip 0;
    };
};
zone "rrl.test" {
    type master;
    file "$ZONE";
};
EOF

echo "[*] Starting KariDNS with RRL (rps=5, window=3: start at 5, down to -15)..."
$BIN -f -c "$CONF" > "$DIR/server_rrl.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    echo "[*] Cleaning up test processes..."
    kari_kill_tree "${SERVER_PID:-}"
    rm -f "$CONF" "$ZONE" "$DIR/server_rrl.log"
}
trap cleanup EXIT INT TERM

sleep 2

# Helper function to send N queries in a single microsecond-level burst via Perl
send_instant_burst() {
    KARI_RRL_PORT=$PORT perl -e '
    use strict;
    use warnings;
    use Socket;

    my $count = $ARGV[0] || 25;
    my $qtype = $ARGV[1] || 1; # 1 = A (NOERROR), 28 = AAAA (NODATA)
    my $port = $ENV{KARI_RRL_PORT};
    my $ip = "127.0.0.1";

    socket(my $sock, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
    my $dest = sockaddr_in($port, inet_aton($ip));
    connect($sock, $dest) or die "connect: $!";

    my $qname = "\x03www\x03rrl\x04test\x00";
    my $pkt_base = $qname . pack("nn", $qtype, 1);

    # Pre-generate all packets so send loop is purely connected UDP writes (< 1ms total)
    my @pkts = map { pack("nnnnnn", $_, 0x0100, 1, 0, 0, 0) . $pkt_base } (1..$count);
    for my $p (@pkts) {
        send($sock, $p, 0);
    }

    # Collect responses with short drain timeout
    my $received = 0;
    my $rin = "";
    vec($rin, fileno($sock), 1) = 1;
    my $buf;

    while (select(my $rout = $rin, undef, undef, 0.05) > 0) {
        while (defined recv($sock, $buf, 4096, 0)) {
            $received++;
            last unless select(my $r2 = $rin, undef, undef, 0.001) > 0;
        }
    }
    print "$received\n";
    ' "$1" "${2:-1}"
}

# The balance follows BIND 9 (lib/dns/rrl.c debit_rrl_entry()): a key starts at `responses-per-second` and its balance is
# capped there (one second of responses); every response is debited, also a limited one, down to -window*rate; the
# balance is credited by the rate per second; a key unused for longer than the window starts again at the rate.

# 1. Initial burst of 25 queries (start at the rate: 5 accepted; the balance goes down to -15 = -window*rate)
echo "[*] Step 1: Sending initial instant burst of 25 queries (NOERROR)..."
BURST1_RES=$(send_instant_burst 25 1)
echo "[*] Step 1 responses received: $BURST1_RES / 25 (expected 5)"

if [ "$BURST1_RES" -lt 5 ] || [ "$BURST1_RES" -gt 6 ]; then
    echo "[FAIL] Expected 5 responses for the first burst (rps=5), but received $BURST1_RES!"
    exit 1
fi

# 2. Wait 3.5 seconds (longer than the window: the key starts again at the rate)
echo "[*] Step 2: Waiting 3.5s (longer than the window)..."
sleep 3.5

echo "[*] Step 2: Sending second instant burst of 25 queries..."
BURST2_RES=$(send_instant_burst 25 1)
echo "[*] Step 2 responses received: $BURST2_RES / 25 (expected 5)"

if [ "$BURST2_RES" -lt 5 ] || [ "$BURST2_RES" -gt 6 ]; then
    echo "[FAIL] Expected 5 responses after the window, but received $BURST2_RES!"
    exit 1
fi

# 3. Wait 1.0 second: +5 on a balance of -15 is still negative, so a client that kept sending stays limited
echo "[*] Step 3: Waiting 1.0s (the balance is -15 + 5)..."
sleep 1.0

echo "[*] Step 3: Sending instant burst of 10 queries..."
BURST3_RES=$(send_instant_burst 10 1)
echo "[*] Step 3 responses received: $BURST3_RES / 10 (expected 0)"

if [ "$BURST3_RES" -gt 1 ]; then
    echo "[FAIL] Expected no response 1.0s after a burst that took the balance to -window*rate, but received $BURST3_RES!"
    exit 1
fi

# 4. Step 4: Dedicated nodata-per-second verification
echo "[*] Step 4: Restarting server with dedicated nodata-per-second configuration..."
kill -9 "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

cat << EOF > "$CONF"
options {
    port ${PORT};
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    rate-limit {
        responses-per-second 10;
        nodata-per-second 3;
        window 2;
        slip 0;
    };
};
zone "rrl.test" {
    type master;
    file "$ZONE";
};
EOF

$BIN -f -c "$CONF" > "$DIR/server_rrl.log" 2>&1 &
SERVER_PID=$!
sleep 2

# 4a. NODATA burst test (qtype 28 AAAA on www.rrl.test -> NODATA: the rate: 3)
echo "[*] Step 4a: Sending burst of 20 NODATA queries (qtype=28 AAAA)..."
NODATA_RES=$(send_instant_burst 20 28)
echo "[*] Step 4a NODATA responses received: $NODATA_RES / 20 (expected 3)"

if [ "$NODATA_RES" -lt 3 ] || [ "$NODATA_RES" -gt 4 ]; then
    echo "[FAIL] Expected 3 responses for NODATA burst (nodata_rps=3), but received $NODATA_RES!"
    exit 1
fi

# 4b. NOERROR burst test (qtype 1 A on www.rrl.test -> NOERROR: the rate: 10)
echo "[*] Step 4b: Sending burst of 30 NOERROR queries (qtype=1 A)..."
NOERROR_RES=$(send_instant_burst 30 1)
echo "[*] Step 4b NOERROR responses received: $NOERROR_RES / 30 (expected 10)"

if [ "$NOERROR_RES" -lt 10 ] || [ "$NOERROR_RES" -gt 11 ]; then
    echo "[FAIL] Expected 10 responses for NOERROR burst (responses_rps=10), but received $NOERROR_RES!"
    exit 1
fi

echo "[PASS] RRL window burst capacity, rate throttling, refills, and dedicated nodata-per-second verified successfully!"
exit 0
