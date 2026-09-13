#!/bin/sh
# ==============================================================================
# run_dag_replay_compare_recorded_test.sh
#
# Integration test for dag --replay --compare-recorded feature.
# Tests single-server live response vs. recorded response differential comparison
# across PCAP (UDP & TCP stream reassembly including split and OOO segments),
# dnstap Frame Streams, missing response warning handling, and CLI mutual exclusion.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$BASE_DIR"

PORT1=${KARIDNS_COMPARE_PORT1:-$((29000 + $$ % 1000))}
TMP_DIR="$(mktemp -d /tmp/karidns_compare_test.XXXXXX)"
CONF1="$TMP_DIR/server1.conf"
ZONE1="$TMP_DIR/server1.zone"
PID1=""
LOG1="$TMP_DIR/server1.log"
DNSTAP_SOCK="$TMP_DIR/dnstap.sock"

cleanup() {
    [ -n "$PID1" ] && kill "$PID1" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi

echo "=== Running dag --replay --compare-recorded Test Suite ==="

# Build binaries
echo "[+] Building karidns..."
make karidns
echo "[+] Building dag..."
make dag

# Prepare Zone
cat << 'EOF' > "$ZONE1"
$ORIGIN example.com.
$TTL 300
@       IN  SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 900 1209600 300 )
        IN  NS  ns1.example.com.
ns1     IN  A   127.0.0.1
match1  IN  A   192.0.2.1
match2  IN  A   192.0.2.2
differ  IN  A   192.0.2.10
round   IN  A   192.0.2.1
round   IN  A   192.0.2.2
sub     IN  NS  ns.sub.example.com.
ns.sub  IN  A   192.0.2.77
EOF

# Prepare Server Config
cat << EOF > "$CONF1"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    $USER_OPT
};

zone "example.com" {
    type primary;
    file "$ZONE1";
};
EOF

chmod 755 "$TMP_DIR"
chmod 644 "$CONF1" "$ZONE1"

# Start karidns
echo "[+] Starting karidns on 127.0.0.1:$PORT1..."
./karidns -f -c "$CONF1" > "$LOG1" 2>&1 &
PID1=$!
sleep 1

if ! kill -0 "$PID1" 2>/dev/null; then
    echo "FAIL: Server 1 failed to start. Log:"
    cat "$LOG1"
    exit 1
fi

# Verify server reachability
echo "[+] Verifying server reachability..."
./dag -p $PORT1 match1.example.com @127.0.0.1 +short > /dev/null

# ------------------------------------------------------------------------------
# Test 7 & 8: CLI Option Validation & Mutual Exclusion
# ------------------------------------------------------------------------------
echo "[+] Testing CLI validation and mutual exclusion..."

# 7. --server2 and --compare-recorded mutual exclusion
set +e
./dag --replay "$ZONE1" --server1 127.0.0.1:$PORT1 --server2 127.0.0.1:$((PORT1+1)) --compare-recorded >/dev/null 2>&1
STATUS=$?
set -e
if [ $STATUS -eq 0 ]; then
    echo "[-] FAILED: Expected error when specifying both --server2 and --compare-recorded"
    exit 1
fi
echo "    [OK] --server2 and --compare-recorded are mutually exclusive."

# 8. Text queries file rejection with --compare-recorded
cat << 'EOF' > "$TMP_DIR/queries.txt"
match1.example.com A
match2.example.com A
EOF
set +e
./dag --replay "$TMP_DIR/queries.txt" --server1 127.0.0.1:$PORT1 --compare-recorded >/dev/null 2>&1
STATUS=$?
set -e
if [ $STATUS -eq 0 ]; then
    echo "[-] FAILED: Expected error when using --compare-recorded with text query file"
    exit 1
fi
echo "    [OK] text queries file correctly rejected for --compare-recorded."

# ------------------------------------------------------------------------------
# Generate Synthetic PCAP & dnstap Test Fixtures (Perl)
# ------------------------------------------------------------------------------
echo "[+] Generating synthetic capture test fixtures (PCAP & dnstap)..."

perl -e '
use strict;
use warnings;
use IO::Socket::INET;

my ($tmp, $port) = @ARGV;

sub make_pcap {
    my ($filename, @packets) = @_;
    open(my $fh, ">:raw", $filename) or die "Cannot open $filename: $!";
    # PCAP Global Header: magic (0xa1b2c3d4), v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    print $fh pack("NnnNNNN", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1);
    for my $pkt (@packets) {
        # Record Header: ts_sec=1000, ts_usec=0, incl_len, orig_len
        print $fh pack("NNNN", 1000, 0, length($pkt), length($pkt));
        print $fh $pkt;
    }
    close($fh);
}

sub build_dns_query {
    my ($txid, $qname, $qtype) = @_;
    $qtype //= 1;
    my $hdr = pack("n6", $txid, 0x0100, 1, 0, 0, 0);
    my $q = "";
    for my $part (split(/\./, $qname)) {
        next if $part eq "";
        $q .= chr(length($part)) . $part;
    }
    $q .= "\0" . pack("nn", $qtype, 1);
    return $hdr . $q;
}

sub make_ether_ip_udp {
    my ($src_ip, $dst_ip, $src_port, $dst_port, $payload) = @_;
    my $eth = ("\0" x 6) . ("\0" x 6) . pack("n", 0x0800);
    my $iplen = 20 + 8 + length($payload);
    my $ip_s = pack("C*", split(/\./, $src_ip));
    my $ip_d = pack("C*", split(/\./, $dst_ip));
    my $ip = pack("CCnnnCCn", 0x45, 0, $iplen, 1, 0x4000, 64, 17, 0) . $ip_s . $ip_d;
    my $udp = pack("nnnn", $src_port, $dst_port, 8 + length($payload), 0);
    return $eth . $ip . $udp . $payload;
}

sub make_ether_ip_tcp {
    my ($src_ip, $dst_ip, $src_port, $dst_port, $seq, $ack, $flags, $payload) = @_;
    my $eth = ("\0" x 6) . ("\0" x 6) . pack("n", 0x0800);
    my $iplen = 20 + 20 + length($payload);
    my $ip_s = pack("C*", split(/\./, $src_ip));
    my $ip_d = pack("C*", split(/\./, $dst_ip));
    my $ip = pack("CCnnnCCn", 0x45, 0, $iplen, 1, 0x4000, 64, 6, 0) . $ip_s . $ip_d;
    my $tcp = pack("nnNNCCnnn", $src_port, $dst_port, $seq, $ack, 0x50, $flags, 65535, 0, 0);
    return $eth . $ip . $tcp . $payload;
}

sub encode_varint {
    my ($val) = @_;
    my $res = "";
    while (1) {
        my $b = $val & 0x7f;
        $val >>= 7;
        if ($val > 0) {
            $res .= chr($b | 0x80);
        } else {
            $res .= chr($b);
            last;
        }
    }
    return $res;
}

sub encode_field {
    my ($field_num, $wire_type, $data) = @_;
    my $tag = encode_varint(($field_num << 3) | $wire_type);
    if ($wire_type == 0) {
        return $tag . encode_varint($data);
    } elsif ($wire_type == 2) {
        return $tag . encode_varint(length($data)) . $data;
    } else {
        return $tag . $data;
    }
}

sub build_dnstap_frame {
    my ($msg_type, $client_ip, $client_port, $dns_wire) = @_;
    my $msg = "";
    $msg .= encode_field(1, 0, $msg_type);
    $msg .= encode_field(2, 0, 1); # INET
    $msg .= encode_field(3, 0, 1); # UDP
    $msg .= encode_field(4, 2, pack("C*", split(/\./, $client_ip)));
    $msg .= encode_field(6, 0, $client_port);
    if ($msg_type == 1) {
        $msg .= encode_field(10, 2, $dns_wire);
    } else {
        $msg .= encode_field(14, 2, $dns_wire);
    }

    my $top = "";
    $top .= encode_field(15, 0, 1); # type = MESSAGE
    $top .= encode_field(14, 2, $msg);

    return pack("N", length($top)) . $top;
}

# Fetch authentic baseline responses from the running karidns server
my $sock = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1",
    PeerPort => $port,
    Proto    => "udp",
    Timeout  => 3,
) or die "Cannot connect to 127.0.0.1:$port: $!";

sub fetch_dns_pair {
    my ($txid, $qname) = @_;
    my $q = build_dns_query($txid, $qname);
    $sock->send($q);
    my $resp = "";
    $sock->recv($resp, 4096);
    die "Failed to receive response from server for $qname" if length($resp) < 12;
    return ($q, $resp);
}

my ($q1, $r1) = fetch_dns_pair(0x1234, "match1.example.com");
my ($q2, $r2) = fetch_dns_pair(0x5678, "match2.example.com");
my ($q3, $r3) = fetch_dns_pair(0x9abc, "differ.example.com");
close($sock);

# 1. UDP PCAP fixture
my $pkt_q1 = make_ether_ip_udp("192.0.2.100", "127.0.0.1", 10001, 53, $q1);
my $pkt_r1 = make_ether_ip_udp("127.0.0.1", "192.0.2.100", 53, 10001, $r1);
my $pkt_q2 = make_ether_ip_udp("192.0.2.100", "127.0.0.1", 10002, 53, $q2);
my $pkt_r2 = make_ether_ip_udp("127.0.0.1", "192.0.2.100", 53, 10002, $r2);
make_pcap("$tmp/udp_pairs.pcap", $pkt_q1, $pkt_r1, $pkt_q2, $pkt_r2);

# 2. UDP PCAP with missing response
my $pkt_q3 = make_ether_ip_udp("192.0.2.100", "127.0.0.1", 10003, 53, $q3);
make_pcap("$tmp/udp_missing.pcap", $pkt_q1, $pkt_r1, $pkt_q3);

# 3. TCP Stream PCAP (Split Segment)
my $t_q1 = pack("n", length($q1)) . $q1;
my $t_r1 = pack("n", length($r1)) . $r1;
my $pkt_t_q1 = make_ether_ip_tcp("192.0.2.100", "127.0.0.1", 20001, 53, 1000, 1, 0x18, $t_q1);

my $seg1 = substr($t_r1, 0, 10);
my $seg2 = substr($t_r1, 10, 15);
my $seg3 = substr($t_r1, 25);
my $pkt_t_r1_1 = make_ether_ip_tcp("127.0.0.1", "192.0.2.100", 53, 20001, 5000, 1000 + length($t_q1), 0x10, $seg1);
my $pkt_t_r1_2 = make_ether_ip_tcp("127.0.0.1", "192.0.2.100", 53, 20001, 5000 + length($seg1), 1000 + length($t_q1), 0x10, $seg2);
my $pkt_t_r1_3 = make_ether_ip_tcp("127.0.0.1", "192.0.2.100", 53, 20001, 5000 + length($seg1) + length($seg2), 1000 + length($t_q1), 0x18, $seg3);
make_pcap("$tmp/tcp_split.pcap", $pkt_t_q1, $pkt_t_r1_1, $pkt_t_r1_2, $pkt_t_r1_3);

# 4. TCP Stream PCAP (Out-Of-Order Segments: seg1, seg3, seg2)
make_pcap("$tmp/tcp_ooo.pcap", $pkt_t_q1, $pkt_t_r1_1, $pkt_t_r1_3, $pkt_t_r1_2);

# 4b. TCP Stream PCAP with Post-Drain Duplicate Retransmission
# Connection with 2 queries & 2 responses; between response 1 and query 2,
# a duplicate segment of response 1 (seq < base_seq) is injected.
my $t_q2 = pack("n", length($q2)) . $q2;
my $t_r2 = pack("n", length($r2)) . $r2;
my $seq_c = 1000;
my $seq_s = 5000;

my $pkt_m1_q = make_ether_ip_tcp("192.0.2.100", "127.0.0.1", 20002, 53, $seq_c, $seq_s, 0x18, $t_q1);
$seq_c += length($t_q1);
my $pkt_m1_r = make_ether_ip_tcp("127.0.0.1", "192.0.2.100", 53, 20002, $seq_s, $seq_c, 0x18, $t_r1);
$seq_s += length($t_r1);

# Stale duplicate of first segment of message 1 (seq=5000, which has already been drained)
my $pkt_m1_r_dup = make_ether_ip_tcp("127.0.0.1", "192.0.2.100", 53, 20002, 5000, $seq_c, 0x10, substr($t_r1, 0, 10));

# Message 2
my $pkt_m2_q = make_ether_ip_tcp("192.0.2.100", "127.0.0.1", 20002, 53, $seq_c, $seq_s, 0x18, $t_q2);
$seq_c += length($t_q2);
my $pkt_m2_r = make_ether_ip_tcp("127.0.0.1", "192.0.2.100", 53, 20002, $seq_s, $seq_c, 0x18, $t_r2);

make_pcap("$tmp/tcp_post_drain_dup.pcap", $pkt_m1_q, $pkt_m1_r, $pkt_m1_r_dup, $pkt_m2_q, $pkt_m2_r);

# 5. dnstap traffic fixtures
my $ct = "protobuf:dnstap.Dnstap";
my $start_p = pack("NNN", 2, 1, length($ct)) . $ct;
my $frames = pack("NN", 0, length($start_p)) . $start_p;
$frames .= build_dnstap_frame(1, "192.0.2.55", 30001, $q1);
$frames .= build_dnstap_frame(2, "192.0.2.55", 30001, $r1);
$frames .= build_dnstap_frame(1, "192.0.2.55", 30002, $q2);
$frames .= build_dnstap_frame(2, "192.0.2.55", 30002, $r2);

open(my $fh, ">:raw", "$tmp/traffic.dnstap") or die "Cannot open traffic.dnstap: $!";
print $fh $frames;
close($fh);

# 6. dnstap traffic fixture with a modified recorded response (synthetic difference)
my $r3_diff = $r3;
# Replace 192.0.2.10 (c0 00 02 0a) with 192.0.2.99 (c0 00 02 63)
$r3_diff =~ s/\xc0\x00\x02\x0a/\xc0\x00\x02\x63/;

my $frames_diff = pack("NN", 0, length($start_p)) . $start_p;
$frames_diff .= build_dnstap_frame(1, "192.0.2.55", 30001, $q1);
$frames_diff .= build_dnstap_frame(2, "192.0.2.55", 30001, $r1);
$frames_diff .= build_dnstap_frame(1, "192.0.2.55", 30002, $q3);
$frames_diff .= build_dnstap_frame(2, "192.0.2.55", 30002, $r3_diff);

open(my $fh_diff, ">:raw", "$tmp/traffic_diff.dnstap") or die "Cannot open traffic_diff.dnstap: $!";
print $fh_diff $frames_diff;
close($fh_diff);
' "$TMP_DIR" "$PORT1"

# ------------------------------------------------------------------------------
# Test 3: PCAP UDP Pairing & --compare-recorded (Identical matching)
# ------------------------------------------------------------------------------
echo "[+] Test 3: PCAP UDP Query-Response Pairing..."
RES_JSON="$TMP_DIR/res_pcap_udp.json"
./dag --replay "$TMP_DIR/udp_pairs.pcap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "2" ] || [ "$IDENTICAL" != "2" ]; then
    echo "[-] FAILED: PCAP UDP pairing expected 2 compared / 2 identical, got compared=$COMPARED identical=$IDENTICAL"
    cat "$RES_JSON"
    exit 1
fi
echo "    [OK] PCAP UDP 2/2 pairs matched perfectly."

# ------------------------------------------------------------------------------
# Test 4: PCAP TCP Stream Reassembly (Split Segment)
# ------------------------------------------------------------------------------
echo "[+] Test 4: PCAP TCP Stream Reassembly (Split Segments)..."
RES_JSON="$TMP_DIR/res_tcp_split.json"
./dag --replay "$TMP_DIR/tcp_split.pcap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "1" ] || [ "$IDENTICAL" != "1" ]; then
    echo "[-] FAILED: PCAP TCP split reassembly expected 1 compared / 1 identical, got compared=$COMPARED identical=$IDENTICAL"
    cat "$RES_JSON"
    exit 1
fi
echo "    [OK] PCAP TCP split reassembly succeeded (1/1 matched)."

# ------------------------------------------------------------------------------
# Test 5: PCAP TCP Stream Reassembly (Out-Of-Order Segments)
# ------------------------------------------------------------------------------
echo "[+] Test 5: PCAP TCP Stream Reassembly (Out-Of-Order Segments)..."
RES_JSON="$TMP_DIR/res_tcp_ooo.json"
./dag --replay "$TMP_DIR/tcp_ooo.pcap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "1" ] || [ "$IDENTICAL" != "1" ]; then
    echo "[-] FAILED: PCAP TCP OOO reassembly expected 1 compared / 1 identical, got compared=$COMPARED identical=$IDENTICAL"
    cat "$RES_JSON"
    exit 1
fi
echo "    [OK] PCAP TCP out-of-order reassembly succeeded (1/1 matched)."

# ------------------------------------------------------------------------------
# Test 5b: PCAP TCP Stream Reassembly (Post-Drain Duplicate Retransmission)
# ------------------------------------------------------------------------------
echo "[+] Test 5b: PCAP TCP Stream Reassembly (Post-Drain Duplicate Retransmission)..."
RES_JSON="$TMP_DIR/res_tcp_dup.json"
./dag --replay "$TMP_DIR/tcp_post_drain_dup.pcap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "2" ] || [ "$IDENTICAL" != "2" ]; then
    echo "[-] FAILED: PCAP TCP post-drain duplicate reassembly expected 2 compared / 2 identical, got compared=$COMPARED identical=$IDENTICAL"
    cat "$RES_JSON"
    exit 1
fi
echo "    [OK] PCAP TCP post-drain duplicate properly ignored (2/2 matched)."

# ------------------------------------------------------------------------------
# Test 6: Missing Response Handling
# ------------------------------------------------------------------------------
echo "[+] Test 6: Missing Response in capture handling..."
RES_JSON="$TMP_DIR/res_missing.json"
STDERR_OUT="$TMP_DIR/missing.err"
./dag --replay "$TMP_DIR/udp_missing.pcap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON" 2> "$STDERR_OUT"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "1" ] || [ "$IDENTICAL" != "1" ]; then
    echo "[-] FAILED: Expected 1 complete pair compared, got compared=$COMPARED identical=$IDENTICAL"
    cat "$RES_JSON"
    exit 1
fi
if ! grep -q "had no recorded response in capture" "$STDERR_OUT"; then
    echo "[-] FAILED: Expected warning about missing response in stderr"
    cat "$STDERR_OUT"
    exit 1
fi
echo "    [OK] Missing response properly warned and excluded from comparison."

# ------------------------------------------------------------------------------
# Test 1 & 2: dnstap capture, --compare-recorded and difference detection
# ------------------------------------------------------------------------------
echo "[+] Test 1 & 2: dnstap capture & difference detection..."

# Test 1: dnstap replay with recorded responses matching live responses
RES_JSON="$TMP_DIR/res_dnstap1.json"
./dag --replay "$TMP_DIR/traffic.dnstap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "2" ] || [ "$IDENTICAL" != "2" ]; then
    echo "[-] FAILED: dnstap replay expected 2 compared / 2 identical, got compared=$COMPARED identical=$IDENTICAL"
    cat "$RES_JSON"
    exit 1
fi
echo "    [OK] dnstap 2/2 pairs matched perfectly."

# Test 2: Difference detection (synthetic modified recorded response in traffic_diff.dnstap)
RES_JSON="$TMP_DIR/res_dnstap2.json"
./dag --replay "$TMP_DIR/traffic_diff.dnstap" --server1 127.0.0.1:$PORT1 --compare-recorded --ignore-ttl --output json > "$RES_JSON"

COMPARED=$(grep '"compared":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
IDENTICAL=$(grep '"identical":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')
MISMATCH=$(grep '"mismatched_queries":' "$RES_JSON" | awk -F': ' '{print $2}' | tr -d ', ')

if [ "$COMPARED" != "2" ] || [ "$IDENTICAL" != "1" ] || [ "$MISMATCH" != "1" ]; then
    echo "[-] FAILED: dnstap difference detection expected 2 compared / 1 identical / 1 mismatch, got compared=$COMPARED identical=$IDENTICAL mismatch=$MISMATCH"
    cat "$RES_JSON"
    exit 1
fi
echo "    [OK] Difference correctly detected (1 identical, 1 mismatched)."

echo "=== All dag --replay --compare-recorded tests passed! ==="
