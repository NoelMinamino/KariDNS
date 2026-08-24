#!/bin/sh
set -e

# Test: TSIG AXFR multi-message digest chaining with unsigned intermediate messages (RFC 2845 §4.4 / RFC 8945 §5.4)
# Compatible with both KariDNS dag and BIND 9 dig.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${DAG:-$BIN_DIR/dag}"
if [ ! -x "$DAG" ] && [ "$DAG" != "dig" ]; then
    DAG="./dag"
fi

if [ ! -x "$DAG" ] && [ "$DAG" != "dig" ]; then
    echo "Error: dag executable not found at $DAG"
    exit 1
fi

KEY_NAME="tsig-test-key"
KEY_SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"
KEY_ALG="hmac-sha256"

PORT_AXFR=53594

echo "Running: test_dag_axfr_tsig_unsigned_intermediate ($DAG)"

# Multi-message AXFR Mock Server with unsigned intermediate message (RFC 8945 §5.4)
perl -e '
use strict;
use warnings;
use Socket;
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(decode_base64);

my $port = $ARGV[0];
my $key_secret = decode_base64("dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl");

socket(my $server, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
setsockopt($server, SOL_SOCKET, SO_REUSEADDR, 1);
bind($server, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen($server, 5) or die "listen: $!";

my $rin = "";
vec($rin, fileno($server), 1) = 1;
if (select(my $rout = $rin, undef, undef, 5.0) > 0) {
    accept(my $client, $server) or die "accept: $!";
    
    # Read query length (2 bytes) + query packet
    my $len_buf;
    read($client, $len_buf, 2);
    my $qlen = unpack("n", $len_buf);
    my $qpkt;
    read($client, $qpkt, $qlen);
    my $qid = unpack("n", substr($qpkt, 0, 2));

    # Extract Request MAC from query TSIG RR (RFC 8945 §5.3)
    my $req_mac = "";
    if ($qpkt =~ /\x0dtsig-test-key\x00\x00\xfa\x00\xff\x00\x00\x00\x00..\x0bhmac-sha256\x00.{8}(..)/s) {
        my $mac_len = unpack("n", $1);
        my $mac_pos = $+[1];
        $req_mac = substr($qpkt, $mac_pos, $mac_len);
    }

    # 1. Message 1: Initial SOA (TSIG signed, RFC 8945 §5.3)
    my $question = "\x07example\x03com\x00" . pack("nn", 252, 1); # AXFR IN
    my $soa_rdata = "\x03ns1\x07example\x03com\x00\x04host\x07example\x03com\x00" . pack("NNNNN", 1, 7200, 3600, 1209600, 3600);
    my $soa_rr = "\x07example\x03com\x00" . pack("nnNn", 6, 1, 3600, length($soa_rdata)) . $soa_rdata;

    # Pre-MAC for Message 1: Request MAC + Header(AR=0) + Question + Answer + TSIG Variables
    my $m1_pre = pack("nnnnnn", $qid, 0x8400, 1, 1, 0, 0) . $question . $soa_rr;
    my $now = time();
    my $tsig_timers = pack("nNn", ($now >> 32) & 0xffff, $now & 0xffffffff, 300); # 48-bit time + 16-bit fudge (8 bytes)
    my $tsig_vars1 = "\x0dtsig-test-key\x00" . pack("nN", 255, 0) . "\x0bhmac-sha256\x00" . $tsig_timers . pack("nn", 0, 0); # Error=0, OtherLen=0
    
    my $mac1_input = ($req_mac ne "" ? pack("n", length($req_mac)) . $req_mac : "") . $m1_pre . $tsig_vars1;
    my $mac1 = hmac_sha256($mac1_input, $key_secret);
    my $tsig_rdata1 = "\x0bhmac-sha256\x00" . $tsig_timers . pack("n", length($mac1)) . $mac1 . pack("nnn", $qid, 0, 0);
    my $tsig_rr1 = "\x0dtsig-test-key\x00" . pack("nnNn", 250, 255, 0, length($tsig_rdata1)) . $tsig_rdata1;
    
    my $m1_wire = pack("nnnnnn", $qid, 0x8400, 1, 1, 0, 1) . $question . $soa_rr . $tsig_rr1;
    print $client pack("n", length($m1_wire)) . $m1_wire;

    # 2. Message 2: Intermediate record (UNSIGNED, AR=0)
    my $a_rdata = pack("C4", 192, 0, 2, 10);
    my $a_rr = "\x03www\x07example\x03com\x00" . pack("nnNn", 1, 1, 3600, length($a_rdata)) . $a_rdata;
    my $m2_wire = pack("nnnnnn", $qid, 0x8400, 0, 1, 0, 0) . $a_rr;
    print $client pack("n", length($m2_wire)) . $m2_wire;

    # 3. Message 3: Final SOA (TSIG signed with digest chain, RFC 8945 §5.4)
    # Subsequent message TSIG input: Prior MAC + Unsigned Messages ($m2_wire) + $m3_pre + TSIG Timers only
    my $m3_pre = pack("nnnnnn", $qid, 0x8400, 0, 1, 0, 0) . $soa_rr;
    my $mac3_input = pack("n", length($mac1)) . $mac1 . $m2_wire . $m3_pre . $tsig_timers;
    my $mac3 = hmac_sha256($mac3_input, $key_secret);
    my $tsig_rdata3 = "\x0bhmac-sha256\x00" . $tsig_timers . pack("n", length($mac3)) . $mac3 . pack("nnn", $qid, 0, 0);
    my $tsig_rr3 = "\x0dtsig-test-key\x00" . pack("nnNn", 250, 255, 0, length($tsig_rdata3)) . $tsig_rdata3;

    my $m3_wire = pack("nnnnnn", $qid, 0x8400, 0, 1, 0, 1) . $soa_rr . $tsig_rr3;
    print $client pack("n", length($m3_wire)) . $m3_wire;
    close($client);
}
' "$PORT_AXFR" &
SRV_PID=$!
trap "kill -9 $SRV_PID 2>/dev/null || true" EXIT

sleep 0.1

OUT=$($DAG @127.0.0.1 -p $PORT_AXFR example.com AXFR -y "${KEY_ALG}:${KEY_NAME}:${KEY_SECRET}" +timeout=3 2>&1 || true)

# Verify no false-positive TSIG failure was emitted
if echo "$OUT" | grep -q -i "TSIG verification FAILED"; then
    echo "FAIL: Unexpected TSIG verification FAILED warning on unsigned intermediate message"
    echo "$OUT"
    exit 1
fi

if echo "$OUT" | grep -q -i "Couldn't verify signature"; then
    echo "FAIL: Unexpected signature verification failure"
    echo "$OUT"
    exit 1
fi

# Verify zone records were transferred
echo "$OUT" | grep -q "192\.0\.2\.10" || {
    echo "FAIL: Expected 192.0.2.10 in transferred records"
    echo "$OUT"
    exit 1
}

# Verify TSIG verification indicator
if [ "$DAG" != "dig" ]; then
    echo "$OUT" | grep -q "TSIG verified" || {
        echo "FAIL: Expected 'TSIG verified' in output"
        echo "$OUT"
        exit 1
    }
else
    echo "$OUT" | grep -q -i "tsig" || {
        echo "FAIL: Expected TSIG record in dig output"
        echo "$OUT"
        exit 1
    }
fi

echo "PASS: test_dag_axfr_tsig_unsigned_intermediate"
exit 0
