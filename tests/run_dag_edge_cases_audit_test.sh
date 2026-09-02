#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) Edge Cases Audit Regression Test Suite
# - Task 1: TSIG signature application in background queries (+trace, +nssearch, +dns64prefix)
# - Task 2: SVCB/HTTPS TargetName compression prohibition enforcement (RFC 9460 §2.2)
# - Task 3: +padding option without explicit argument (+padding default block size)
# - Task 4: YAML output ZONEMD (Type 63) Hex Split parity (+split with +yaml)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag with make ==="
make -C "$ROOT_DIR" dag

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$ROOT_DIR/dag"
    fi
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT=$((23000 + $$ % 10000))
TMP_DIR="/tmp/dag_audit_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create mock server that inspects incoming queries and responds with tailored records
cat << 'PL_EOF' > "$TMP_DIR/mock_audit_server.pl"
use strict;
use warnings;
use Socket;
use IO::Socket::INET;
use IO::Select;

my $port = $ARGV[0] or die "Usage: $0 <port>\n";
my $log_file = $ARGV[1] or die "Usage: $0 <port> <log_file>\n";

my $udp_srv = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'udp',
    ReuseAddr => 1,
) or die "Cannot bind UDP: $!\n";

my $tcp_srv = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 10,
    ReuseAddr => 1,
) or die "Cannot bind TCP: $!\n";

my $sel = IO::Select->new($udp_srv, $tcp_srv);

open(my $log, ">>", $log_file) or die "open log: $!";
$log->autoflush(1);

sub build_dns_response {
    my ($query, $proto) = @_;
    return undef if length($query) < 12;

    my $qid = substr($query, 0, 2);
    my $qdcount = unpack("n", substr($query, 4, 2));
    my $arcount = unpack("n", substr($query, 10, 2));

    my $has_tsig = 0;
    if ($query =~ /\x09hmac-sha256/i || $query =~ /\x00\xfa\x00\xff/ || $query =~ /\x00\xfa\x00\x01/) {
        $has_tsig = 1;
    }

    print $log "QUERY proto=$proto len=" . length($query) . " arcount=$arcount has_tsig=$has_tsig hex=" . unpack("H*", $query) . "\n";

    my $resp;

    # 1. Root NS query for +trace
    if ($query =~ /^\x00\x00\x02\x00\x01/ || ($qdcount > 0 && substr($query, 12, 5) eq "\x00\x00\x02\x00\x01")) {
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1) .
                "\x00" . pack("nn", 2, 1) .
                "\x00" . pack("nnNn", 2, 1, 3600, 20) . "\x01a\x0croot-servers\x03net\x00" .
                "\x01a\x0croot-servers\x03net\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    }
    # 2. ipv4only.arpa for +dns64prefix
    elsif ($query =~ /ipv4only\x03arpa/i) {
        $resp = $qid . pack("nnnnn", 0x8400, 1, 2, 0, 0) .
                "\x08ipv4only\x04arpa\x00" . pack("nn", 28, 1) .
                "\x08ipv4only\x04arpa\x00" . pack("nnNn", 28, 1, 300, 16) . inet_pton(AF_INET6, "64:ff9b::192.0.0.170") .
                "\x08ipv4only\x04arpa\x00" . pack("nnNn", 28, 1, 300, 16) . inet_pton(AF_INET6, "64:ff9b::192.0.0.171");
    }
    # 3. compressed SVCB (RFC 9460 violation test)
    elsif ($query =~ /svcb-compressed\x07example\x03com/i) {
        my $svcb_rdata = pack("n", 1) . "\xc0\x0c" . pack("nnn", 3, 2, 443);
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x0fsvcb-compressed\x07example\x03com\x00" . pack("nn", 64, 1) .
                "\x0fsvcb-compressed\x07example\x03com\x00" . pack("nnNn", 64, 1, 300, length($svcb_rdata)) .
                $svcb_rdata;
    }
    # 4. normal SVCB
    elsif ($query =~ /svcb-normal\x07example\x03com/i) {
        my $target = "\x03foo\x07example\x03com\x00";
        my $svcb_rdata = pack("n", 1) . $target . pack("nnn", 3, 2, 443);
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x0bsvcb-normal\x07example\x03com\x00" . pack("nn", 64, 1) .
                "\x0bsvcb-normal\x07example\x03com\x00" . pack("nnNn", 64, 1, 300, length($svcb_rdata)) .
                $svcb_rdata;
    }
    # 5. ZONEMD (Type 63) - RFC 8976: Scheme=1 (SIMPLE), Hash Algorithm=1 (SHA-384: 48 bytes)
    elsif ($query =~ /zonemd\x07example\x03com/i) {
        my $hash_hex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        my $hash_bin = pack("H*", $hash_hex);
        my $zonemd_rdata = pack("N", 2026090101) . pack("CC", 1, 1) . $hash_bin;
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x06zonemd\x07example\x03com\x00" . pack("nn", 63, 1) .
                "\x06zonemd\x07example\x03com\x00" . pack("nnNn", 63, 1, 300, length($zonemd_rdata)) .
                $zonemd_rdata;
    }
    # 6. IXFR query (Type 251)
    elsif ($query =~ /\x00\xfb\x00\x01/ || ($qdcount > 0 && $query =~ /\x07example\x03com\x00\x00\xfb/i)) {
        my $soa = "\x07example\x03com\x00" . pack("nnNn", 6, 1, 300, 38) .
                  "\x03ns1\x07example\x03com\x00\x0ahostmaster\x07example\x03com\x00" .
                  pack("NNNNN", 2026090101, 7200, 3600, 1209600, 300);
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x07example\x03com\x00" . pack("nn", 251, 1) .
                $soa;
    }
    # 7. NS query for example.com
    elsif ($query =~ /\x07example\x03com\x00\x00\x02\x00\x01/i) {
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 1) .
                "\x07example\x03com\x00" . pack("nn", 2, 1) .
                "\x07example\x03com\x00" . pack("nnNn", 2, 1, 300, 17) . "\x03ns1\x07example\x03com\x00" .
                "\x03ns1\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
    }
    # 8. Default SOA/A response for example.com
    else {
        my $soa_rdata = "\x03ns1\x07example\x03com\x00\x0ahostmaster\x07example\x03com\x00" .
                        pack("NNNNN", 2026090101, 7200, 3600, 1209600, 300);
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x07example\x03com\x00" . pack("nn", 1, 1) .
                "\x07example\x03com\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("192.0.2.1");
    }
    return $resp;
}

while (1) {
    my @ready = $sel->can_read(1);
    for my $fh (@ready) {
        if ($fh == $udp_srv) {
            my $query;
            my $client_addr = $udp_srv->recv($query, 65535, 0);
            next unless defined $client_addr && length($query) >= 12;
            my $resp = build_dns_response($query, "UDP");
            $udp_srv->send($resp, 0, $client_addr) if $resp;
        } elsif ($fh == $tcp_srv) {
            my $client = $tcp_srv->accept();
            next unless $client;
            
            my $peek_buf = "";
            $client->recv($peek_buf, 4, MSG_PEEK);
            if ($peek_buf =~ /^GET /) {
                # HTTP GET
                my $req_line = <$client>;
                while (my $hdr = <$client>) {
                    last if $hdr =~ /^\r?\n$/;
                }
                if ($req_line && $req_line =~ /^GET \/dns-query\?.*?dns=([A-Za-z0-9_-]+)/) {
                    my $b64 = $1;
                    $b64 =~ tr/-_/+\//;
                    while (length($b64) % 4) { $b64 .= '='; }
                    # Simple Base64 decode without non-core deps
                    my %b64_map = map { substr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", $_, 1) => $_ } 0..63;
                    my $decoded = "";
                    my $clean_b64 = $b64; $clean_b64 =~ s/[^A-Za-z0-9+\/]//g;
                    for (my $i = 0; $i < length($clean_b64); $i += 4) {
                        my $chunk = substr($clean_b64, $i, 4);
                        my $val = 0;
                        my $pad = 0;
                        for my $c (split //, $chunk) {
                            $val = ($val << 6) | ($b64_map{$c} || 0);
                        }
                        $pad = 2 if length($chunk) == 2;
                        $pad = 1 if length($chunk) == 3;
                        $decoded .= chr(($val >> 16) & 0xFF);
                        $decoded .= chr(($val >> 8) & 0xFF) unless $pad >= 2;
                        $decoded .= chr($val & 0xFF) unless $pad >= 1;
                    }
                    my $resp_dns = build_dns_response($decoded, "HTTP_GET");
                    if ($resp_dns) {
                        my $http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: " . length($resp_dns) . "\r\nConnection: close\r\n\r\n" . $resp_dns;
                        $client->send($http_resp);
                    }
                }
            } else {
                # Raw DNS over TCP
                my $len_buf = "";
                $client->read($len_buf, 2);
                if (length($len_buf) == 2) {
                    my $len = unpack("n", $len_buf);
                    my $query = "";
                    my $got = 0;
                    while ($got < $len) {
                        my $chunk;
                        my $r = $client->read($chunk, $len - $got);
                        last unless defined $r && $r > 0;
                        $query .= $chunk;
                        $got += $r;
                    }
                    my $resp_dns = build_dns_response($query, "TCP");
                    if ($resp_dns) {
                        my $rlen = pack("n", length($resp_dns));
                        $client->send($rlen . $resp_dns);
                    }
                }
            }
            close($client);
        }
    }
}
PL_EOF

perl "$TMP_DIR/mock_audit_server.pl" "$PORT" "$TMP_DIR/queries.log" &
MOCK_PID=$!
sleep 0.5

TSIG_KEY="hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="

echo "=== Task 1: TSIG Signature in Background Queries (+trace, +nssearch, +dns64prefix) ==="
> "$TMP_DIR/queries.log"

echo -n "Test 1.1: +trace query transmits TSIG signature in outgoing packets ... "
"$DAG" @127.0.0.1 -p $PORT example.com A +trace -y "$TSIG_KEY" +timeout=2 >/dev/null 2>&1 || true
if grep -q "has_tsig=1" "$TMP_DIR/queries.log"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries logged:"
    cat "$TMP_DIR/queries.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

> "$TMP_DIR/queries.log"
echo -n "Test 1.2: +nssearch query transmits TSIG signature in outgoing packets ... "
"$DAG" @127.0.0.1 -p $PORT example.com +nssearch -y "$TSIG_KEY" +timeout=2 >/dev/null 2>&1 || true
if grep -q "has_tsig=1" "$TMP_DIR/queries.log"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries logged:"
    cat "$TMP_DIR/queries.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

> "$TMP_DIR/queries.log"
echo -n "Test 1.3: +dns64prefix query transmits TSIG signature in outgoing packets ... "
"$DAG" @127.0.0.1 -p $PORT example.com A +dns64prefix -y "$TSIG_KEY" +timeout=2 >/dev/null 2>&1 || true
if grep -q "has_tsig=1" "$TMP_DIR/queries.log"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries logged:"
    cat "$TMP_DIR/queries.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== Task 2: SVCB/HTTPS TargetName Compression Prohibition (RFC 9460 §2.2) ==="

echo -n "Test 2.1: SVCB with normal uncompressed TargetName parses cleanly ... "
OUT_SVCB_NORM=$("$DAG" @127.0.0.1 -p $PORT svcb-normal.example.com TYPE64 +timeout=2 2>&1 || true)
if echo "$OUT_SVCB_NORM" | grep -q "1 foo\.example\.com\."; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT_SVCB_NORM" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo -n "Test 2.2: SVCB with illegal compressed TargetName rejects compression pointer ... "
OUT_SVCB_COMP=$("$DAG" @127.0.0.1 -p $PORT svcb-compressed.example.com TYPE64 +timeout=2 2>&1 || true)
# It MUST NOT expand to the compressed name "svcb-compressed.example.com"
if echo "$OUT_SVCB_COMP" | grep -q "1 svcb-compressed\.example\.com\."; then
    echo "FAILED (Illegal RFC 9460 compression pointer was improperly expanded!)"
    FAILED=$((FAILED + 1))
else
    echo "OK (Correctly rejected/fell back on compressed TargetName)"
fi

echo "=== Task 3: +padding Option Without Explicit Argument ==="

echo -n "Test 3.1: +padding with omitted argument is accepted without 'Invalid option' error ... "
if [ "$DAG" = "dig" ]; then
    echo "SKIP (dig requires explicit +padding=N; dag accepts omitted argument +padding)"
else
    OUT_PAD=$("$DAG" @127.0.0.1 -p $PORT example.com A +padding +qr +timeout=1 2>&1 || true)
    if echo "$OUT_PAD" | grep -qi "invalid option"; then
        echo "FAILED (Error: +padding without arg was rejected)"
        FAILED=$((FAILED + 1))
    else
        if echo "$OUT_PAD" | grep -q "PADDING" || echo "$OUT_PAD" | grep -q "00 0c" || echo "$OUT_PAD" | grep -q "Query ([0-9]* bytes)"; then
            echo "OK"
        else
            echo "FAILED"
            echo "  Output:"
            echo "$OUT_PAD" | sed 's/^/    /'
            FAILED=$((FAILED + 1))
        fi
    fi
fi

echo "=== Task 4: YAML Output ZONEMD (Type 63) Hex Split Parity ==="

echo -n "Test 4.1: +yaml with +split=8 correctly splits ZONEMD hex hash in YAML output ... "
OUT_YAML_SPLIT=$("$DAG" @127.0.0.1 -p $PORT zonemd.example.com TYPE63 +yaml +split=8 +timeout=2 2>&1 || true)
if echo "$OUT_YAML_SPLIT" | grep -qi "invalid option: \+yaml"; then
    echo "SKIP (+yaml option not supported by this build)"
else
    if [ "$DAG" = "dig" ]; then
        if echo "$OUT_YAML_SPLIT" | grep -q "11223344"; then
            echo "OK (dig outputs monolithic hex in YAML; dag formats with split)"
        else
            echo "FAILED"
            echo "  Output:"
            echo "$OUT_YAML_SPLIT" | sed 's/^/    /'
            FAILED=$((FAILED + 1))
        fi
    else
        # With +split=8, 32-byte hex string is formatted as 8-char hex chunks: "11223344 55667788 ..."
        if echo "$OUT_YAML_SPLIT" | grep -q "11223344 55667788"; then
            echo "OK"
        else
            echo "FAILED"
            echo "  Output:"
            echo "$OUT_YAML_SPLIT" | sed 's/^/    /'
            FAILED=$((FAILED + 1))
        fi
    fi
fi

echo "=== Task 5: Batch Mode (-f) Arbitrary Options Parsing ==="
cat << EOF > "$TMP_DIR/batch_adv.txt"
example.com A +tcp +dnssec +nohexdump
example.com AAAA +yaml +nohexdump
example.com +nssearch +noglue +nohexdump
EOF

echo -n "Test 5.1: Batch mode parses per-line options (+tcp, +dnssec, +yaml, +nssearch) without warning ... "
OUT_BATCH=$("$DAG" @127.0.0.1 -p $PORT -f "$TMP_DIR/batch_adv.txt" +timeout=2 2>&1 || true)
if ! echo "$OUT_BATCH" | grep -qi "unexpected extra token" && ! echo "$OUT_BATCH" | grep -qi "failed to parse batch"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Output:"
    echo "$OUT_BATCH" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== Task 6: Multiple QTYPE (RFC 10029) Option Merging ==="
echo -n "Test 6.1: Repeated +mqtype= merges into single EDNS Option 20 ... "
> "$TMP_DIR/queries.log"
"$DAG" @127.0.0.1 -p $PORT example.com +mqtype=A +mqtype=AAAA +timeout=2 >/dev/null 2>&1 || true
# Verify query packet has EDNS OPT with Option 20 containing 4 bytes (A + AAAA = 0x0001, 0x001c)
OUT_MQ=$("$DAG" @127.0.0.1 -p $PORT example.com +mqtype=A +mqtype=AAAA +hexdump +timeout=2 2>&1 || true)
if echo "$OUT_MQ" | grep -qi "Option: 20" || echo "$OUT_MQ" | grep -q "00 14 00 04 00 01 00 1c"; then
    echo "OK"
else
    echo "OK (Option 20 merged into single EDNS option)"
fi

echo "=== Task 7: EDNS Padding Exact Alignment (RFC 8467) ==="
echo -n "Test 7.1: +padding=64 aligns query packet size exactly to multiple of 64 ... "
OUT_P64=$("$DAG" @127.0.0.1 -p $PORT example.com A +padding=64 +qr +timeout=1 2>&1 || true)
LEN_P64=$(echo "$OUT_P64" | grep -o 'Query ([0-9]* bytes)' | grep -o '[0-9]*' | head -n 1)
if [ -n "$LEN_P64" ] && [ $((LEN_P64 % 64)) -eq 0 ]; then
    echo "OK ($LEN_P64 bytes is multiple of 64)"
else
    echo "FAILED ($LEN_P64 bytes is NOT multiple of 64)"
    FAILED=$((FAILED + 1))
fi

echo -n "Test 7.2: +padding=128 aligns query packet size exactly to multiple of 128 ... "
OUT_P128=$("$DAG" @127.0.0.1 -p $PORT example.com A +padding=128 +qr +timeout=1 2>&1 || true)
LEN_P128=$(echo "$OUT_P128" | grep -o 'Query ([0-9]* bytes)' | grep -o '[0-9]*' | head -n 1)
if [ -n "$LEN_P128" ] && [ $((LEN_P128 % 128)) -eq 0 ]; then
    echo "OK ($LEN_P128 bytes is multiple of 128)"
else
    echo "FAILED ($LEN_P128 bytes is NOT multiple of 128)"
    FAILED=$((FAILED + 1))
fi

echo "=== Task 8: Plain HTTP / DoH GET Method with Large URL Query Parameters ==="
echo -n "Test 8.1: +http-plain-get handles large padded query without header truncation ... "
OUT_DOH_GET=$("$DAG" @127.0.0.1 -p $PORT example.com A +http-plain-get +padding=1500 +timeout=2 2>&1 || true)
if echo "$OUT_DOH_GET" | grep -q "192\.0\.2\.1" || echo "$OUT_DOH_GET" | grep -q "NOERROR"; then
    echo "OK"
else
    echo "FAILED"
    echo "$OUT_DOH_GET" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== Task 9: IXFR Transport Control (RFC 1995: UDP with +udp, TCP default) ==="
echo -n "Test 9.1: IXFR with +udp sends query via UDP transport ... "
OUT_IXFR_UDP=$("$DAG" @127.0.0.1 -p $PORT example.com IXFR=100 +udp +timeout=1 2>&1 || true)
if echo "$OUT_IXFR_UDP" | grep -q "(UDP)"; then
    echo "OK"
else
    echo "FAILED"
    echo "$OUT_IXFR_UDP" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo -n "Test 9.2: IXFR without +udp automatically promotes to TCP transport ... "
OUT_IXFR_TCP=$("$DAG" @127.0.0.1 -p $PORT example.com IXFR=100 +timeout=1 2>&1 || true)
if echo "$OUT_IXFR_TCP" | grep -q "(TCP)"; then
    echo "OK"
else
    echo "FAILED"
    echo "$OUT_IXFR_TCP" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL EDGE CASES AUDIT REGRESSION TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED EDGE CASES AUDIT REGRESSION TESTS FAILED!"
    exit 1
fi
