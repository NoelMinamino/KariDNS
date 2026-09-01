#!/usr/bin/perl
# ==============================================================================
# mock_server.pl / mock_dns_server.pl
#
# A versatile DNS mock server in pure Perl (no non-core dependencies).
# Serves both UDP and TCP on the specified port.
#
# Simulates specific DNS scenarios for testing and capturing BIND 9 dig behavior:
#   1. ttl-test.example       -> Multiple records with various TTL values
#                                (0, 59, 60, 3600, 3661, 86400, 90061, 604800, 604861)
#   2. badcookie.example      -> Returns BADCOOKIE (RCODE 23) with Server Cookie on
#                                first query, and NOERROR once Server Cookie is sent back.
#   3. badvers.example        -> Returns BADVERS (RCODE 16) if EDNS version >= 1,
#                                returns NOERROR if EDNS version == 0.
#   4. badvers-always.example -> Always returns BADVERS (RCODE 16) regardless of EDNS version.
#   5. malformed-trunc.example-> Returns response with truncated RDATA (packet ends prematurely).
#   6. malformed-svcb.example -> Returns SVCB record where TargetName exceeds RDLENGTH.
#   7. axfr.example           -> Returns complete AXFR sequence (SOA -> A -> TXT -> SOA).
#   8. ipv4only.arpa          -> Returns AAAA 64:ff9b::c000:aa01 for DNS64 prefix testing.
#   9. crypto.example         -> Returns DNSKEY, RRSIG, DS records for crypto/nocrypto testing.
#  10. ede-0 .. ede-29        -> Returns Extended DNS Error (EDE, RFC 8914) with codes 0..29.
#  11. ede-all.example        -> Returns all 30 EDE options in a single OPT record.
# ==============================================================================

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my $port = 10553;
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
    Listen    => 10,
    ReuseAddr => 1,
) or die "Cannot bind TCP $host:$port: $!\n";

print "[*] Mock DNS Server listening on UDP and TCP $host:$port (PID: $$)\n";
$| = 1; # autoflush stdout

my $select = IO::Select->new($udp_sock, $tcp_sock);

# Signal handler for clean exit
$SIG{INT} = sub { print "\n[*] Shutting down mock DNS server...\n"; exit 0; };
$SIG{TERM} = sub { print "\n[*] Terminated mock DNS server...\n"; exit 0; };

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
# TCP Handler
# ------------------------------------------------------------------------------
sub handle_tcp_accept {
    my ($listener) = @_;
    my $client = $listener->accept();
    return unless $client;

    my $len_buf;
    my $n = $client->read($len_buf, 2);
    if (!defined $n || $n != 2) {
        $client->close();
        return;
    }
    my $req_len = unpack('n', $len_buf);
    my $req = '';
    my $got = 0;
    while ($got < $req_len) {
        my $buf;
        my $r = $client->read($buf, $req_len - $got);
        last unless defined $r && $r > 0;
        $req .= $buf;
        $got += $r;
    }

    if (length($req) >= 12) {
        my ($resp, $multi_resp) = process_dns_query($req, 1);
        if ($multi_resp && @$multi_resp) {
            for my $msg (@$multi_resp) {
                my $out = pack('n', length($msg)) . $msg;
                $client->send($out);
            }
        } elsif (defined $resp) {
            my $out = pack('n', length($resp)) . $resp;
            $client->send($out);
        }
    }
    $client->close();
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
# Core DNS Query Processor
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

    # Inspect OPT in AR section if present
    my $has_edns = 0;
    my $edns_version = 0;
    my $edns_flags = 0;
    my $edns_bufsize = 512;
    my $client_cookie = undef;
    my $server_cookie = undef;

    # Scan for OPT RR
    my $scan_off = $offset;
    # Skip answers/authority records if any
    for (my $i = 0; $i < $ancount + $nscount; $i++) {
        last if $scan_off >= length($req);
        my (undef, $nxt) = decode_qname($req, $scan_off);
        last if $nxt + 10 > length($req);
        my $rdlen = unpack('n', substr($req, $nxt + 8, 2));
        $scan_off = $nxt + 10 + $rdlen;
    }
    for (my $i = 0; $i < $arcount; $i++) {
        last if $scan_off >= length($req);
        my (undef, $nxt) = decode_qname($req, $scan_off);
        last if $nxt + 10 > length($req);
        my ($rtype, $rclass, $ttl, $rdlen) = unpack('nnNn', substr($req, $nxt, 10));
        if ($rtype == 41) { # OPT
            $has_edns = 1;
            $edns_bufsize = $rclass;
            $edns_version = ($ttl >> 16) & 0xFF;
            $edns_flags = $ttl & 0xFFFF;
            my $rdata_off = $nxt + 10;
            my $rdata_end = $rdata_off + $rdlen;
            while ($rdata_off + 4 <= $rdata_end) {
                my ($opt_code, $opt_len) = unpack('nn', substr($req, $rdata_off, 4));
                $rdata_off += 4;
                last if $rdata_off + $opt_len > $rdata_end;
                if ($opt_code == 10) { # COOKIE
                    if ($opt_len >= 8) {
                        $client_cookie = substr($req, $rdata_off, 8);
                        if ($opt_len > 8) {
                            $server_cookie = substr($req, $rdata_off + 8, $opt_len - 8);
                        }
                    }
                }
                $rdata_off += $opt_len;
            }
        }
        $scan_off = $nxt + 10 + $rdlen;
    }

    my $qname_lower = lc($qname);
    print "[*] Query: id=$id qname='$qname_lower' qtype=$qtype edns=$has_edns ver=$edns_version cookie=" .
          (defined $client_cookie ? unpack('H*', $client_cookie) : 'none') . "\n" if $verbose;

    my $question_wire = encode_name($qname) . pack('nn', $qtype, $qclass);

    # --------------------------------------------------------------------------
    # Scenario 1: TTL tests (`ttl-test.example` or `*.ttl.test`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /(ttl-test\.example|ttl\.test)$/) {
        my $answers = '';
        my @ttls = (
            ['zero',      0,       '192.0.2.1'],
            ['s59',       59,      '192.0.2.2'],
            ['m1',        60,      '192.0.2.3'],
            ['h1',        3600,    '192.0.2.4'],
            ['mixed-hms', 3661,    '192.0.2.5'],  # 1h 1m 1s
            ['d1',        86400,   '192.0.2.6'],
            ['mixed-dhms',90061,   '192.0.2.7'],  # 1d 1h 1m 1s
            ['w1',        604800,  '192.0.2.8'],
            ['mixed-whms',604861,  '192.0.2.9'],  # 1w 1m 1s
            ['w2',        1209600, '192.0.2.10'],
        );

        my $num_ans = scalar(@ttls);
        for my $item (@ttls) {
            my ($sub, $ttl_val, $ip) = @$item;
            my $rec_name = "$sub." . $qname;
            my @octets = split /\./, $ip;
            my $rdata = pack('C4', @octets);
            $answers .= encode_name($rec_name) . pack('nnNn', 1, 1, $ttl_val, 4) . $rdata;
        }

        my $resp_flags = 0x8180; # QR=1, RD=1, RA=1, RCODE=0
        my $opt_rr = '';
        my $ar_count = 0;
        if ($has_edns) {
            $opt_rr = encode_name('') . pack('nnNn', 41, 1232, 0, 0);
            $ar_count = 1;
        }
        my $hdr = pack('n6', $id, $resp_flags, 1, $num_ans, 0, $ar_count);
        return ($hdr . $question_wire . $answers . $opt_rr);
    }

    # --------------------------------------------------------------------------
    # Scenario 2: BADCOOKIE test (`badcookie.example`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /badcookie\.example$/) {
        my $expected_sc = "\xde\xad\xbe\xef\x12\x34\x56\x78"; # 8-byte server cookie
        if (defined $client_cookie && defined $server_cookie && $server_cookie eq $expected_sc) {
            # Good cookie: return NOERROR answer
            my $answers = encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 100);
            my $cookie_opt = pack('nn', 10, 16) . $client_cookie . $expected_sc;
            my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, 0, length($cookie_opt)) . $cookie_opt;
            my $hdr = pack('n6', $id, 0x8180, 1, 1, 0, 1);
            return ($hdr . $question_wire . $answers . $opt_rr);
        } else {
            # Bad cookie: return BADCOOKIE (RCODE 23 = base rcode 7, ext_rcode 1 -> (1<<4)|7 = 23)
            my $base_rcode = 7;
            my $ext_rcode = 1;
            my $resp_flags = 0x8180 | $base_rcode;
            my $opt_ttl = ($ext_rcode << 24);
            my $cc = defined $client_cookie ? $client_cookie : "\x01\x02\x03\x04\x05\x06\x07\x08";
            my $cookie_opt = pack('nn', 10, 16) . $cc . $expected_sc;
            my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, $opt_ttl, length($cookie_opt)) . $cookie_opt;
            my $hdr = pack('n6', $id, $resp_flags, 1, 0, 0, 1);
            return ($hdr . $question_wire . $opt_rr);
        }
    }

    # --------------------------------------------------------------------------
    # Scenario 3: BADVERS test (`badvers.example` and `badvers-always.example`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /badvers-always\.example$/ || ($qname_lower =~ /badvers\.example$/ && $edns_version >= 1)) {
        # Return BADVERS (RCODE 16 = base rcode 0, ext_rcode 1)
        my $ext_rcode = 1;
        my $opt_ttl = ($ext_rcode << 24) | (0 << 16); # version 0 in response
        my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, $opt_ttl, 0);
        my $hdr = pack('n6', $id, 0x8180, 1, 0, 0, 1);
        return ($hdr . $question_wire . $opt_rr);
    }
    if ($qname_lower =~ /badvers\.example$/ && $edns_version == 0) {
        # Fallback to version 0 succeeded: return NOERROR
        my $answers = encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 200);
        my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, 0, 0);
        my $hdr = pack('n6', $id, 0x8180, 1, 1, 0, 1);
        return ($hdr . $question_wire . $answers . $opt_rr);
    }

    # --------------------------------------------------------------------------
    # Scenario 4: Malformed Truncated RDATA (`malformed-trunc.example`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /malformed-trunc\.example$/) {
        # Answer 1: Normal A record
        my $ans1 = encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        # Answer 2: Broken record claiming RDLENGTH=20, but truncated after 3 bytes
        my $ans2 = encode_name("broken." . $qname) . pack('nnNn', 1, 1, 300, 20) . pack('C3', 0xDE, 0xAD, 0xBE);
        my $hdr = pack('n6', $id, 0x8180, 1, 2, 0, 0);
        return ($hdr . $question_wire . $ans1 . $ans2);
    }

    # --------------------------------------------------------------------------
    # Scenario 5: Malformed SVCB RDATA (`malformed-svcb.example`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /malformed-svcb\.example$/) {
        my $target_wire = encode_name("target.example");
        my $svcb_rdata = pack('n', 1) . $target_wire;
        # Claim RDLENGTH = 3 (too short for target name)
        my $ans = encode_name($qname) . pack('nnNn', 64, 1, 300, 3) . substr($svcb_rdata, 0, 3);
        my $hdr = pack('n6', $id, 0x8180, 1, 1, 0, 0);
        return ($hdr . $question_wire . $ans);
    }

    # --------------------------------------------------------------------------
    # Scenario 6: AXFR test (`axfr.example`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /axfr\.example$/) {
        my $soa_rdata = encode_name("ns1.axfr.example") . encode_name("hostmaster.axfr.example") .
                        pack('N5', 2026082201, 3600, 600, 604800, 300);
        my $soa_rr = encode_name($qname) . pack('nnNn', 6, 1, 3600, length($soa_rdata)) . $soa_rdata;
        my $a_rr = encode_name("host1." . $qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 50);
        my $txt_payload = "\x0chello world";
        my $txt_rr = encode_name("host1." . $qname) . pack('nnNn', 16, 1, 300, length($txt_payload)) . $txt_payload;

        # AXFR sequence: SOA -> A -> TXT -> SOA
        my $answers = $soa_rr . $a_rr . $txt_rr . $soa_rr;
        my $hdr = pack('n6', $id, 0x8400, 1, 4, 0, 0);
        return ($hdr . $question_wire . $answers);
    }

    # --------------------------------------------------------------------------
    # Scenario 7: DNS64 `ipv4only.arpa`
    # --------------------------------------------------------------------------
    if ($qname_lower eq 'ipv4only.arpa' || $qname_lower =~ /ipv4only\.arpa$/) {
        my $answers = '';
        my $num_ans = 0;
        if ($qtype == 28 || $qtype == 255) { # AAAA or ANY
            # 64:ff9b::192.0.2.1 = 0064:ff9b:0000:0000:0000:0000:c000:0201
            my $v6_bytes = pack('n4C4', 0x0064, 0xff9b, 0x0000, 0x0000, 0, 0, 192, 0, 2, 1);
            $answers .= encode_name($qname) . pack('nnNn', 28, 1, 300, 16) . $v6_bytes;
            $num_ans++;
        }
        if ($qtype == 1 || $qtype == 255) { # A or ANY
            $answers .= encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            $num_ans++;
        }
        my $hdr = pack('n6', $id, 0x8180, 1, $num_ans, 0, 0);
        return ($hdr . $question_wire . $answers);
    }

    # --------------------------------------------------------------------------
    # Scenario 8: Crypto test (DNSKEY, RRSIG, DS for `crypto.example`)
    # --------------------------------------------------------------------------
    if ($qname_lower =~ /crypto\.example$/) {
        my $answers = '';
        my $num_ans = 0;

        # DNSKEY: Flags=257 (KSK), Proto=3, Alg=8 (RSASHA256), Keytag=20326
        my $key_bin = "\x01\x00\x01" . ("\xAA" x 128);
        my $dnskey_rdata = pack('nCC', 257, 3, 8) . $key_bin;
        $answers .= encode_name($qname) . pack('nnNn', 48, 1, 3600, length($dnskey_rdata)) . $dnskey_rdata;
        $num_ans++;

        # DS: Keytag=20326, Alg=8, DigestType=2 (SHA-256), Digest=32 bytes
        my $ds_rdata = pack('nCC', 20326, 8, 2) . ("\xBB" x 32);
        $answers .= encode_name($qname) . pack('nnNn', 43, 1, 3600, length($ds_rdata)) . $ds_rdata;
        $num_ans++;

        # RRSIG: TypeCovered=48, Alg=8, Labels=2, OrigTTL=3600, Exp=1755900000, Incept=1755800000, Tag=20326, Signer=crypto.example
        my $rrsig_rdata = pack('nCCNNNn', 48, 8, 2, 3600, 1755900000, 1755800000, 20326) .
                          encode_name($qname) . ("\xCC" x 64);
        $answers .= encode_name($qname) . pack('nnNn', 46, 1, 3600, length($rrsig_rdata)) . $rrsig_rdata;
        $num_ans++;

        my $opt_rr = '';
        my $ar_count = 0;
        if ($has_edns) {
            my $resp_edns_flags = ($edns_flags & 0x8000) ? 0x8000 : 0;
            $opt_rr = encode_name('') . pack('nnNn', 41, 1232, $resp_edns_flags, 0);
            $ar_count = 1;
        }

        my $hdr = pack('n6', $id, 0x8180, 1, $num_ans, 0, $ar_count);
        return ($hdr . $question_wire . $answers . $opt_rr);
    }

    # --------------------------------------------------------------------------
    # Scenario 9: Extended DNS Errors (EDE, RFC 8914, codes 0..29 & ede-all)
    # --------------------------------------------------------------------------
    my %ede_names = (
        0  => "Other Error",
        1  => "Unsupported DNSKEY Algorithm",
        2  => "Unsupported DS Digest Type",
        3  => "Stale Answer",
        4  => "Forged Answer",
        5  => "DNSSEC Indeterminate",
        6  => "DNSSEC Bogus",
        7  => "Signature Expired",
        8  => "Signature Not Yet Valid",
        9  => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        25 => "Signature Expired Before Inception",
        26 => "Too Early",
        27 => "Unsupported NSEC3 Iterations",
        28 => "Unable to obtain DNS COOKIE",
        29 => "Unassigned",
    );

    if ($qname_lower =~ /^ede-all2(?:\.|$)/) {
        my $ede_opts = '';
        for my $code (0 .. 29) {
            my $name = $ede_names{$code} // "Code $code";
            for my $rep (1 .. 2) {
                my $ede_text = "EDE code $code ($name) duplicate #$rep";
                $ede_opts .= pack('nnn', 15, length($ede_text) + 2, $code) . $ede_text;
            }
        }
        my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, 0, length($ede_opts)) . $ede_opts;
        my $hdr = pack('n6', $id, 0x8182, 1, 0, 0, 1); # SERVFAIL with all duplicate EDE options
        return ($hdr . $question_wire . $opt_rr);
    }

    if ($qname_lower =~ /^ede-all(?:\.|$)/) {
        my $ede_opts = '';
        for my $code (0 .. 29) {
            my $name = $ede_names{$code} // "Code $code";
            my $ede_text = "EDE code $code ($name)";
            $ede_opts .= pack('nnn', 15, length($ede_text) + 2, $code) . $ede_text;
        }
        my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, 0, length($ede_opts)) . $ede_opts;
        my $hdr = pack('n6', $id, 0x8182, 1, 0, 0, 1); # SERVFAIL with all EDE options
        return ($hdr . $question_wire . $opt_rr);
    }

    if ($qname_lower =~ /^ede-(\d+)(?:\.|$)/) {
        my $code = int($1);
        my $name = $ede_names{$code} // "Code $code";
        my $ede_text = "EDE code $code ($name)";
        my $ede_opt = pack('nnn', 15, length($ede_text) + 2, $code) . $ede_text;
        my $opt_rr = encode_name('') . pack('nnNn', 41, 1232, 0, length($ede_opt)) . $ede_opt;
        my $hdr = pack('n6', $id, 0x8182, 1, 0, 0, 1); # SERVFAIL with specific EDE
        return ($hdr . $question_wire . $opt_rr);
    }

    # --------------------------------------------------------------------------
    # Default fallback: Standard A record
    # --------------------------------------------------------------------------
    my $answers = encode_name($qname) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 93, 184, 216, 34);
    my $opt_rr = '';
    my $ar_count = 0;
    if ($has_edns) {
        my $resp_edns_flags = ($edns_flags & 0x8000) ? 0x8000 : 0;
        $opt_rr = encode_name('') . pack('nnNn', 41, 1232, $resp_edns_flags, 0);
        $ar_count = 1;
    }
    my $hdr = pack('n6', $id, 0x8180, 1, 1, 0, $ar_count);
    return ($hdr . $question_wire . $answers . $opt_rr);
}
