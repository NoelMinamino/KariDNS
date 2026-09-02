#!/bin/sh
set -e

# ==============================================================================
# DAG EDE (0-29) and UDP TC Fallback Regression Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
DAG="${DAG:-$BIN_DIR/dag}"

TMP_DIR="$(mktemp -d /tmp/dag_ede_truncation_test.XXXXXX)"
MOCK_PID=""

cleanup() {
    if [ -n "$MOCK_PID" ]; then
        kill -9 "$MOCK_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PORT=$((34000 + $$ % 3000))
FAILED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECTED="$3"

    echo -n "Test: $NAME ... "
    OUTPUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUTPUT" | grep -E -q "$EXPECTED"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECTED"
        echo "  Output: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Building dag ==="
(cd "$BASE_DIR" && make -j4 dag)

# Create Mock Perl Server responding with EDE 0-29 and UDP TC=1
cat << 'EOF' > "$TMP_DIR/mock_ede_server.pl"
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;

my $port = $ARGV[0] || 34053;

my $udp_sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'udp'
) or die "Cannot bind UDP port $port: $!\n";

my $tcp_sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 10,
    Reuse     => 1
) or die "Cannot bind TCP port $port: $!\n";

my $select = IO::Select->new($udp_sock, $tcp_sock);

while (my @ready = $select->can_read(10)) {
    for my $fh (@ready) {
        if ($fh == $udp_sock) {
            my $buf;
            my $peer = $udp_sock->recv($buf, 4096);
            next unless defined($peer) && length($buf) >= 12;
            my ($resp, $is_tc) = handle_packet($buf, 0);
            $udp_sock->send($resp) if defined $resp;
        } elsif ($fh == $tcp_sock) {
            my $client = $tcp_sock->accept();
            next unless $client;
            my $len_buf;
            $client->sysread($len_buf, 2);
            if (length($len_buf) == 2) {
                my $len = unpack('n', $len_buf);
                my $buf;
                $client->sysread($buf, $len);
                my ($resp, $is_tc) = handle_packet($buf, 1);
                if (defined $resp) {
                    my $out = pack('n', length($resp)) . $resp;
                    $client->syswrite($out);
                }
            }
            close($client);
        }
    }
}

sub handle_packet {
    my ($pkt, $is_tcp) = @_;
    return (undef, 0) if length($pkt) < 12;

    my ($id, $flags, $qdcount) = unpack('nnn', substr($pkt, 0, 6));
    my $offset = 12;
    my $qname = '';
    while ($offset < length($pkt)) {
        my $l = ord(substr($pkt, $offset, 1));
        last if $l == 0;
        $offset++;
        $qname .= substr($pkt, $offset, $l) . '.';
        $offset += $l;
    }
    $offset++; # skip 0
    my ($qtype, $qclass) = unpack('nn', substr($pkt, $offset, 4));
    $offset += 4;

    if ($qname =~ /^ede-all\./i) {
        # Return response with 30 EDEs (codes 0 to 29)
        my $resp_flags = 0x8182; # QR=1, AA=0, SERVFAIL (rcode 2)
        my $header = pack('nnnnnn', $id, $resp_flags, 1, 0, 0, 1);
        my $qsec = substr($pkt, 12, $offset - 12);

        # Construct OPT record with EDEs 0..29
        my $opt_rdata = '';
        for my $code (0..29) {
            my $text = "EDE code $code test description";
            my $ede_payload = pack('n', $code) . $text;
            $opt_rdata .= pack('nn', 15, length($ede_payload)) . $ede_payload;
        }
        my $opt_rr = "\x00" . pack('nnNn', 41, 4096, 0, length($opt_rdata)) . $opt_rdata;
        return ($header . $qsec . $opt_rr, 0);
    } elsif ($qname =~ /^trunc-test\./i) {
        if (!$is_tcp) {
            # UDP: Return TC=1 Truncated response
            my $resp_flags = 0x8380; # QR=1, AA=0, TC=1, RD=1, RA=1, NOERROR
            my $header = pack('nnnnnn', $id, $resp_flags, 1, 0, 0, 0);
            my $qsec = substr($pkt, 12, $offset - 12);
            return ($header . $qsec, 1);
        } else {
            # TCP: Return complete A record answer
            my $resp_flags = 0x8180; # QR=1, AA=0, TC=0, NOERROR
            my $header = pack('nnnnnn', $id, $resp_flags, 1, 1, 0, 0);
            my $qsec = substr($pkt, 12, $offset - 12);
            my $ans_rr = "\xc0\x0c" . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 100);
            return ($header . $qsec . $ans_rr, 0);
        }
    }
    return (undef, 0);
}
EOF

echo "=== Starting Mock DNS Server on port $PORT ==="
perl "$TMP_DIR/mock_ede_server.pl" $PORT &
MOCK_PID=$!
sleep 1

# 1. Test full EDE 0..29 parsing (Task 1)
echo "=== 1. Testing EDE 0..29 Full Range Display (Task 1) ==="
run_check "EDE 0 is displayed" "$DAG @127.0.0.1 -p $PORT ede-all.test A" "; EDE: 0"
run_check "EDE 15 is displayed" "$DAG @127.0.0.1 -p $PORT ede-all.test A" "; EDE: 15"
run_check "EDE 16 is displayed" "$DAG @127.0.0.1 -p $PORT ede-all.test A" "; EDE: 16"
run_check "EDE 25 is displayed" "$DAG @127.0.0.1 -p $PORT ede-all.test A" "; EDE: 25"
run_check "EDE 29 is displayed" "$DAG @127.0.0.1 -p $PORT ede-all.test A" "; EDE: 29"

# 2. Test UDP Truncation (TC=1) followed by TCP Retry (Task 2)
echo "=== 2. Testing UDP Truncated Response Display and TCP Retry (Task 2) ==="
run_check "UDP TC response is displayed before retry" \
    "$DAG @127.0.0.1 -p $PORT trunc-test.test A" \
    "flags: .*tc"

run_check "Truncated notification is displayed" \
    "$DAG @127.0.0.1 -p $PORT trunc-test.test A" \
    "Truncated, retrying in TCP mode"

run_check "TCP response is retrieved after retry" \
    "$DAG @127.0.0.1 -p $PORT trunc-test.test A" \
    "192\.0\.2\.100"

# 3. Test +ignore suppresses TCP fallback
echo "=== 3. Testing +ignore with Truncated Response ==="
run_check "+ignore displays UDP TC response without TCP fallback" \
    "$DAG @127.0.0.1 -p $PORT trunc-test.test A +ignore" \
    "flags: .*tc"

echo "=== Summary ==="
if [ $FAILED -eq 0 ]; then
    echo "ALL DAG EDE & TRUNCATION TESTS PASSED!"
    exit 0
else
    echo "$FAILED TEST(S) FAILED."
    exit 1
fi
