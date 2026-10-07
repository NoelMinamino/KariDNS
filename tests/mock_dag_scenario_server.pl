#!/usr/bin/perl
# ==============================================================================
# mock_dag_scenario_server.pl
#
# KariDNS & dag(1) Comprehensive Multi-Protocol Scenario Mock Server
#
# Features:
#   1. Multiplexed UDP & TCP DNS Server
#   2. Plain-HTTP DoH (HTTP/1.1 POST and GET with application/dns-message, RFC 8484
#      message format), error codes 400/404/500 and chunked transfer encoding
#   3. PROXY Protocol v2 (LOCAL and PROXY commands, IPv4 and IPv6)
#   4. Multi-message AXFR streaming (62 records in 3 TCP messages)
#   5. IXFR delta streaming (RFC 1995 delete/add sequences)
#   6. UDP Truncation (TC=1) with automatic TCP fallback
#
# Every accepted TCP connection and every PROXY v2 header is logged to stdout
# ("ACCEPT tcp", "PROXY cmd=<LOCAL|PROXY> fam=<n> src=<addr>#<port> dst=<addr>#<port>")
# so the test can check connection reuse and the PROXY header contents.
# ==============================================================================

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;
use MIME::Base64 qw(decode_base64);
use Socket qw(inet_ntop AF_INET AF_INET6);

my $port = 10555;
my $host = '127.0.0.1';
my $verbose = 0;

GetOptions(
    'port=i'    => \$port,
    'host=s'    => \$host,
    'verbose|v' => \$verbose,
    'help|h'    => sub {
        print "Usage: $0 [--port <port>] [--host <ip>] [--verbose]\n";
        exit 0;
    }
);

# Create UDP socket
my $udp_sock = IO::Socket::INET->new(
    LocalAddr => $host,
    LocalPort => $port,
    Proto     => 'udp',
    ReuseAddr => 1,
) or die "Cannot bind UDP $host:$port: $!\n";

# Create TCP socket
my $tcp_sock = IO::Socket::INET->new(
    LocalAddr => $host,
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 32,
    ReuseAddr => 1,
) or die "Cannot bind TCP $host:$port: $!\n";

print "[*] Scenario Mock Server listening on UDP/TCP $host:$port (PID: $$)\n";
$| = 1; # autoflush

my $select = IO::Select->new($udp_sock, $tcp_sock);

$SIG{INT} = sub { exit 0; };
$SIG{TERM} = sub { exit 0; };

while (my @ready = $select->can_read()) {
    for my $fh (@ready) {
        if ($fh == $udp_sock) {
            handle_udp($udp_sock);
        } elsif ($fh == $tcp_sock) {
            handle_tcp_accept($tcp_sock);
        }
    }
}

# ------------------------------------------------------------------------------
# UDP Handler
# ------------------------------------------------------------------------------
sub handle_udp {
    my ($sock) = @_;
    my $req;
    my $peer = $sock->recv($req, 65535);
    return unless defined $peer && length($req) >= 12;

    my ($resp) = process_dns_query($req, 0);
    if (defined $resp) {
        $sock->send($resp);
    }
}

# ------------------------------------------------------------------------------
# TCP Handler (Supports Raw DNS-over-TCP, PROXY v2, and HTTP/1.1 DoH)
# ------------------------------------------------------------------------------
sub handle_tcp_accept {
    my ($listener) = @_;
    my $client = $listener->accept();
    return unless $client;
    print "ACCEPT tcp\n";

    # Handle keepalive/persistent connection loop
    while (1) {
        my $peek_buf;
        my $n = $client->sysread($peek_buf, 16);
        last unless defined $n && $n > 0;

        # 1. Check for PROXY Protocol v2 prefix (12-byte signature)
        # \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
        if ($n >= 12 && substr($peek_buf, 0, 12) eq "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A") {
            while (length($peek_buf) < 16) {
                my $tmp;
                my $r = $client->sysread($tmp, 16 - length($peek_buf));
                last unless defined $r && $r > 0;
                $peek_buf .= $tmp;
            }
            if (length($peek_buf) >= 16) {
                my $proxy_len = unpack('n', substr($peek_buf, 14, 2));
                my $proxy_extra = '';
                while (length($proxy_extra) < $proxy_len) {
                    my $tmp;
                    my $r = $client->sysread($tmp, $proxy_len - length($proxy_extra));
                    last unless defined $r && $r > 0;
                    $proxy_extra .= $tmp;
                }
                log_proxy_header($peek_buf, $proxy_extra);
                # PROXY v2 header stripped, now read next message on connection
                next;
            }
        }

        # 2. Check for HTTP DoH methods: "GET " or "POST"
        if ($peek_buf =~ /^(GET|POST)\s/) {
            my $http_data = $peek_buf;
            while ($http_data !~ /\r\n\r\n/) {
                my $tmp;
                my $r = $client->sysread($tmp, 1024);
                last unless defined $r && $r > 0;
                $http_data .= $tmp;
            }

            if ($http_data =~ /^(GET|POST)\s+([^\s]+)\s+HTTP\/1\.[01]/) {
                my ($method, $uri) = ($1, $2);
                my $content_len = 0;
                if ($http_data =~ /content-length:\s*(\d+)/i) {
                    $content_len = int($1);
                }

                my ($hdr, $body) = split(/\r\n\r\n/, $http_data, 2);
                $body //= '';
                while (length($body) < $content_len) {
                    my $tmp;
                    my $r = $client->sysread($tmp, $content_len - length($body));
                    last unless defined $r && $r > 0;
                    $body .= $tmp;
                }

                my $dns_req = '';
                if ($method eq 'POST') {
                    $dns_req = $body;
                } elsif ($method eq 'GET') {
                    if ($uri =~ /[?&]dns=([A-Za-z0-9_-]+)/) {
                        my $b64 = $1;
                        $b64 =~ tr/-_/+\//;
                        my $pad = (4 - length($b64) % 4) % 4;
                        $b64 .= ('=' x $pad);
                        $dns_req = decode_base64($b64);
                    }
                }

                # Check special HTTP DoH error scenarios
                if ($uri =~ /error400/ || ($dns_req && $dns_req =~ /error400/)) {
                    my $http_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\n400 Bad Request";
                    $client->syswrite($http_resp);
                    last;
                } elsif ($uri =~ /error404/ || ($dns_req && $dns_req =~ /error404/)) {
                    my $http_resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n404 Not Found";
                    $client->syswrite($http_resp);
                    last;
                } elsif ($uri =~ /error500/ || ($dns_req && $dns_req =~ /error500/)) {
                    my $http_resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\n\r\n500 Internal Error";
                    $client->syswrite($http_resp);
                    last;
                }

                if (length($dns_req) >= 12) {
                    my ($resp) = process_dns_query($dns_req, 1);
                    if ($uri =~ /chunked/ || ($dns_req =~ /chunked/)) {
                        my $hex_len = sprintf("%x", length($resp));
                        my $http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      . "$hex_len\r\n" . $resp . "\r\n0\r\n\r\n";
                        $client->syswrite($http_resp);
                    } else {
                        my $http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: " . length($resp) . "\r\n\r\n" . $resp;
                        $client->syswrite($http_resp);
                    }
                }
                next; # Allow next DoH query if client keeps open
            }
            last;
        }

        # 3. Standard DNS over TCP: 2-byte length prefix
        my $req_len = unpack('n', substr($peek_buf, 0, 2));
        my $req = substr($peek_buf, 2);
        while (length($req) < $req_len) {
            my $tmp;
            my $r = $client->sysread($tmp, $req_len - length($req));
            last unless defined $r && $r > 0;
            $req .= $tmp;
        }

        if (length($req) >= 12) {
            my ($resp, $multi_resp) = process_dns_query($req, 1);
            if ($multi_resp && @$multi_resp) {
                for my $msg (@$multi_resp) {
                    my $out = pack('n', length($msg)) . $msg;
                    $client->syswrite($out);
                }
            } elsif (defined $resp) {
                my $out = pack('n', length($resp)) . $resp;
                $client->syswrite($out);
            }
        }
    }
    $client->close();
}

# PROXY v2 header (after the 12-byte signature): ver/cmd, family/protocol, length, addresses
sub log_proxy_header {
    my ($hdr, $addr) = @_;
    my $cmd = (ord(substr($hdr, 12, 1)) & 0x0F) == 1 ? 'PROXY' : 'LOCAL';
    my $fam = ord(substr($hdr, 13, 1)) >> 4;
    my ($src, $dst, $sp, $dp) = ('-', '-', 0, 0);
    if ($fam == 1 && length($addr) >= 12) {
        ($src, $dst) = (inet_ntop(AF_INET, substr($addr, 0, 4)), inet_ntop(AF_INET, substr($addr, 4, 4)));
        ($sp, $dp) = unpack('nn', substr($addr, 8, 4));
    } elsif ($fam == 2 && length($addr) >= 36) {
        ($src, $dst) = (inet_ntop(AF_INET6, substr($addr, 0, 16)), inet_ntop(AF_INET6, substr($addr, 16, 16)));
        ($sp, $dp) = unpack('nn', substr($addr, 32, 4));
    }
    print "PROXY cmd=$cmd fam=$fam src=$src#$sp dst=$dst#$dp\n";
}

# ------------------------------------------------------------------------------
# Name encoding/decoding helpers
# ------------------------------------------------------------------------------
sub decode_qname {
    my ($pkt, $offset) = @_;
    my $name = '';
    my $len = length($pkt);
    while ($offset < $len) {
        my $l = ord(substr($pkt, $offset, 1));
        if ($l == 0) {
            $offset++;
            last;
        } elsif (($l & 0xC0) == 0xC0) {
            $offset += 2;
            last;
        } else {
            $offset++;
            my $label = substr($pkt, $offset, $l);
            $name .= ($name eq '' ? '' : '.') . $label;
            $offset += $l;
        }
    }
    return ($name, $offset);
}

sub encode_name {
    my ($name) = @_;
    return "\x00" if $name eq '.' || $name eq '';
    my $wire = '';
    for my $label (split /\./, $name) {
        $wire .= pack('C', length($label)) . $label;
    }
    $wire .= "\x00";
    return $wire;
}

# ------------------------------------------------------------------------------
# Core DNS Query Processor & Scenarios
# ------------------------------------------------------------------------------
sub process_dns_query {
    my ($req, $is_tcp) = @_;
    my ($id, $flags, $qdcount, $ancount, $nscount, $arcount) = unpack('n6', substr($req, 0, 12));

    my $offset = 12;
    my $qname = '';
    my $qtype = 1;
    my $qclass = 1;

    if ($qdcount > 0) {
        ($qname, $offset) = decode_qname($req, $offset);
        if ($offset + 4 <= length($req)) {
            ($qtype, $qclass) = unpack('n2', substr($req, $offset, 4));
            $offset += 4;
        }
    }

    my $qname_lower = lc($qname);

    # --------------------------------------------------------------------------
    # SCENARIO 1: UDP Truncation (TC=1) with TCP Fallback
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /tc-fallback/ || $qname_lower =~ /truncate/) {
        if (!$is_tcp) {
            # Return truncated response over UDP
            my $resp_flags = 0x8700; # QR=1, AA=1, TC=1, RD=1
            my $hdr = pack('n6', $id, $resp_flags, $qdcount, 0, 0, 0);
            my $qsec = substr($req, 12, $offset - 12);
            return ($hdr . $qsec);
        } else {
            # Return full multi-record response over TCP
            my $resp_flags = 0x8400; # QR=1, AA=1, NOERROR
            my $ans = '';
            for my $i (1..10) {
                $ans .= encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, $i);
            }
            my $hdr = pack('n6', $id, $resp_flags, $qdcount, 10, 0, 0);
            my $qsec = substr($req, 12, $offset - 12);
            return ($hdr . $qsec . $ans);
        }
    }

    # --------------------------------------------------------------------------
    # SCENARIO 4: Multi-Message AXFR Transfers
    # --------------------------------------------------------------------------
    if ($qtype == 252) { # AXFR
        my $qsec = substr($req, 12, $offset - 12);
        my $soa_rdata = encode_name('ns1.example.com') . encode_name('hostmaster.example.com')
                      . pack('NNNNN', 2026092401, 7200, 3600, 1209600, 3600);
        my $soa_rr = encode_name($qname) . pack('nnNn', 6, 1, 3600, length($soa_rdata)) . $soa_rdata;

        my @messages;
        # Message 1: Initial SOA + 20 A records
        my $m1_ans = $soa_rr;
        for my $i (1..20) {
            my $rec_name = "host$i." . $qname;
            $m1_ans .= encode_name($rec_name) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 10, 0, 0, $i);
        }
        my $hdr1 = pack('n6', $id, 0x8400, $qdcount, 21, 0, 0);
        push @messages, ($hdr1 . $qsec . $m1_ans);

        # Message 2: 20 TXT records
        my $m2_ans = '';
        for my $i (1..20) {
            my $rec_name = "txt$i." . $qname;
            my $txt = "v=spf1 ip4:10.0.0.$i -all";
            my $txt_rdata = pack('C', length($txt)) . $txt;
            $m2_ans .= encode_name($rec_name) . pack('nnNn', 16, 1, 300, length($txt_rdata)) . $txt_rdata;
        }
        my $hdr2 = pack('n6', $id, 0x8400, 0, 20, 0, 0);
        push @messages, ($hdr2 . $m2_ans);

        # Message 3: 20 AAAA records + Trailing SOA
        my $m3_ans = '';
        for my $i (1..20) {
            my $rec_name = "ipv6-$i." . $qname;
            my $ip6_raw = pack('n8', 0x2001, 0xdb8, 0, 0, 0, 0, 0, $i);
            $m3_ans .= encode_name($rec_name) . pack('nnNn', 28, 1, 300, 16) . $ip6_raw;
        }
        $m3_ans .= $soa_rr; # Trailing SOA
        my $hdr3 = pack('n6', $id, 0x8400, 0, 21, 0, 0);
        push @messages, ($hdr3 . $m3_ans);

        return (undef, \@messages);
    }

    # --------------------------------------------------------------------------
    # SCENARIO 5: IXFR Delta Transfers
    # --------------------------------------------------------------------------
    if ($qtype == 251) { # IXFR
        my $qsec = substr($req, 12, $offset - 12);
        my $soa_new_rdata = encode_name('ns1.example.com') . encode_name('hostmaster.example.com')
                          . pack('NNNNN', 200, 7200, 3600, 1209600, 3600);
        my $soa_new = encode_name($qname) . pack('nnNn', 6, 1, 3600, length($soa_new_rdata)) . $soa_new_rdata;
        my $soa_old_rdata = encode_name('ns1.example.com') . encode_name('hostmaster.example.com')
                          . pack('NNNNN', 100, 7200, 3600, 1209600, 3600);
        my $soa_old = encode_name($qname) . pack('nnNn', 6, 1, 3600, length($soa_old_rdata)) . $soa_old_rdata;

        my $del_rec = encode_name("old." . $qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        my $add_rec = encode_name("new." . $qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 2);

        # IXFR Response: SOA(new) -> SOA(old) -> Del-RR -> SOA(new) -> Add-RR -> SOA(new)
        my $ixfr_ans = $soa_new . $soa_old . $del_rec . $soa_new . $add_rec . $soa_new;
        my $hdr = pack('n6', $id, 0x8400, $qdcount, 6, 0, 0);
        return ($hdr . $qsec . $ixfr_ans);
    }

    # --------------------------------------------------------------------------
    # Default NOERROR Response
    # --------------------------------------------------------------------------
    my $qsec = substr($req, 12, $offset - 12);
    my $resp_flags = 0x8400; # QR=1, AA=1, NOERROR
    my $ans = '';
    if ($qtype == 1) { # A
        $ans = encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 34);
    } elsif ($qtype == 28) { # AAAA
        $ans = encode_name($qname) . pack('nnNn', 28, 1, 300, 16) . pack('n8', 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x34);
    } elsif ($qtype == 16) { # TXT
        my $txt = "v=spf1 -all";
        my $txt_rdata = pack('C', length($txt)) . $txt;
        $ans = encode_name($qname) . pack('nnNn', 16, 1, 300, length($txt_rdata)) . $txt_rdata;
    } else {
        $ans = encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 34);
    }

    my $hdr = pack('n6', $id, $resp_flags, $qdcount, 1, 0, 0);
    return ($hdr . $qsec . $ans);
}
