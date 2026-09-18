#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
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
    port 10053;
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

echo "[*] Starting KariDNS with RRL (rps=5, window=3 -> capacity=15)..."
$BIN -f -c "$CONF" > "$DIR/server_rrl.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    echo "[*] Cleaning up test processes..."
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    rm -f "$CONF" "$ZONE" "$DIR/server_rrl.log"
}
trap cleanup EXIT INT TERM

sleep 2

# Helper function to send N queries in a single microsecond-level burst via Perl
send_instant_burst() {
    perl -e '
    use strict;
    use warnings;
    use Socket;

    my $count = $ARGV[0] || 25;
    my $qtype = $ARGV[1] || 1; # 1 = A (NOERROR), 28 = AAAA (NODATA)
    my $port = 10053;
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

# 1. Initial burst of 25 queries (capacity is 15 -> exactly 15 accepted, 10 dropped)
echo "[*] Step 1: Sending initial instant burst of 25 queries (NOERROR)..."
BURST1_RES=$(send_instant_burst 25 1)
echo "[*] Step 1 responses received: $BURST1_RES / 25 (expected 15)"

if [ "$BURST1_RES" -ne 15 ]; then
    echo "[FAIL] Expected 15 responses for burst (rps=5, window=3), but received $BURST1_RES!"
    exit 1
fi

# 2. Wait 3.5 seconds (full window refill to max capacity 15 tokens)
echo "[*] Step 2: Waiting 3.5s for full window refill..."
sleep 3.5

echo "[*] Step 2: Sending second instant burst of 25 queries after full refill..."
BURST2_RES=$(send_instant_burst 25 1)
echo "[*] Step 2 responses received: $BURST2_RES / 25 (expected 15)"

if [ "$BURST2_RES" -ne 15 ]; then
    echo "[FAIL] Expected 15 responses after full window refill, but received $BURST2_RES!"
    exit 1
fi

# 3. Wait 1.0 second (partial refill: exactly 5 tokens at 5 rps)
echo "[*] Step 3: Waiting 1.0s for partial refill (5 tokens)..."
sleep 1.0

echo "[*] Step 3: Sending instant burst of 10 queries after 1.0s partial refill..."
BURST3_RES=$(send_instant_burst 10 1)
echo "[*] Step 3 responses received: $BURST3_RES / 10 (expected 5)"

if [ "$BURST3_RES" -ne 5 ]; then
    echo "[FAIL] Expected 5 responses after 1.0s refill (5 rps), but received $BURST3_RES!"
    exit 1
fi

# 4. Step 4: Dedicated nodata-per-second verification
echo "[*] Step 4: Restarting server with dedicated nodata-per-second configuration..."
kill -9 "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

cat << EOF > "$CONF"
options {
    port 10053;
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

# 4a. NODATA burst test (qtype 28 AAAA on www.rrl.test -> NODATA: cap = 3 rps * 2s = 6 tokens)
echo "[*] Step 4a: Sending burst of 20 NODATA queries (qtype=28 AAAA)..."
NODATA_RES=$(send_instant_burst 20 28)
echo "[*] Step 4a NODATA responses received: $NODATA_RES / 20 (expected 6)"

if [ "$NODATA_RES" -ne 6 ]; then
    echo "[FAIL] Expected 6 responses for NODATA burst (nodata_rps=3, window=2), but received $NODATA_RES!"
    exit 1
fi

# 4b. NOERROR burst test (qtype 1 A on www.rrl.test -> NOERROR: cap = 10 rps * 2s = 20 tokens)
echo "[*] Step 4b: Sending burst of 30 NOERROR queries (qtype=1 A)..."
NOERROR_RES=$(send_instant_burst 30 1)
echo "[*] Step 4b NOERROR responses received: $NOERROR_RES / 30 (expected 20)"

if [ "$NOERROR_RES" -ne 20 ]; then
    echo "[FAIL] Expected 20 responses for NOERROR burst (responses_rps=10, window=2), but received $NOERROR_RES!"
    exit 1
fi

echo "[PASS] RRL window burst capacity, rate throttling, refills, and dedicated nodata-per-second verified successfully!"
exit 0
