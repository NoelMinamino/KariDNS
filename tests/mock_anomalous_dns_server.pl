#!/usr/bin/env perl
# ==============================================================================
# mock_anomalous_dns_server.pl
#
# KariDNS "type program" Plugin & Comprehensive Anomalous DNS Packet Generator.
#
# Can be run in two modes:
#   1. KariDNS Plugin Mode (default):
#      Communicates with KariDNS backend via STDIN / STDOUT protocol:
#        Input:  "QUERY <proto> <client_ip>\n" + 2-byte len + raw query packet
#        Output: 2-byte len + raw response packet (len=0 drops query)
#
#   2. Standalone Server Mode (via --standalone or --port):
#      Binds UDP and TCP sockets directly on the specified host:port.
# ==============================================================================

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;
use Socket;

my $standalone = 0;
my $port       = 0;
my $host       = '127.0.0.1';
my $verbose    = 0;

GetOptions(
    'standalone' => \$standalone,
    'port=i'     => \$port,
    'host=s'     => \$host,
    'verbose|v'  => \$verbose,
    'help|h'     => sub {
        print "Usage: $0 [--standalone] [--port <port>] [--host <ip>] [--verbose]\n";
        exit 0;
    }
);

$standalone = 1 if $port > 0;

if ($standalone) {
    $port = 10553 if $port == 0;
    run_standalone_mode($host, $port, $verbose);
} else {
    run_plugin_mode($verbose);
}

# ==============================================================================
# Mode 1: KariDNS type "program" Plugin Loop (STDIN/STDOUT)
# ==============================================================================
sub read_raw_line {
    my $line = '';
    while (1) {
        my $ch;
        my $n = sysread(STDIN, $ch, 1);
        return undef unless defined($n) && $n == 1;
        $line .= $ch;
        last if $ch eq "\n";
    }
    return $line;
}

sub read_raw_bytes {
    my ($len) = @_;
    my $buf = '';
    my $got = 0;
    while ($got < $len) {
        my $chunk;
        my $n = sysread(STDIN, $chunk, $len - $got);
        return undef unless defined($n) && $n > 0;
        $buf .= $chunk;
        $got += $n;
    }
    return $buf;
}

sub write_raw_bytes {
    my ($data) = @_;
    my $len = length($data);
    my $written = 0;
    while ($written < $len) {
        my $n = syswrite(STDOUT, substr($data, $written));
        return 0 unless defined($n) && $n > 0;
        $written += $n;
    }
    return 1;
}

sub run_plugin_mode {
    my ($v) = @_;
    binmode(STDIN,  ":raw");
    binmode(STDOUT, ":raw");

    while (defined(my $line = read_raw_line())) {
        chomp($line);
        my ($cmd, $proto, $client_ip) = split(/\s+/, $line);
        next unless $cmd && $cmd eq "QUERY";

        my $len_buf = read_raw_bytes(2);
        last unless defined $len_buf && length($len_buf) == 2;
        my $req_len = unpack("n", $len_buf);

        my $req = read_raw_bytes($req_len);
        last unless defined $req && length($req) == $req_len;

        my $is_tcp = (defined $proto && lc($proto) eq 'tcp') ? 1 : 0;
        my $resp = "";
        eval {
            $resp = process_query_packet($req, $is_tcp, $client_ip // '127.0.0.1');
        };
        if ($@) {
            print STDERR "[Plugin Exception] process_query_packet failed: $@\n";
            $resp = "";
        }

        my $resp_len = length($resp // "");
        write_raw_bytes(pack("n", $resp_len));
        if ($resp_len > 0) {
            write_raw_bytes($resp);
        }
    }
    exit 0;
}

# ==============================================================================
# Mode 2: Standalone Server Mode (UDP / TCP Listener)
# ==============================================================================
sub run_standalone_mode {
    my ($h, $p, $v) = @_;
    $| = 1;

    my $udp_sock = IO::Socket::INET->new(
        LocalAddr => $h,
        LocalPort => $p,
        Proto     => 'udp',
        ReuseAddr => 1,
    ) or die "Cannot bind UDP $h:$p: $!\n";

    my $tcp_sock = IO::Socket::INET->new(
        LocalAddr => $h,
        LocalPort => $p,
        Proto     => 'tcp',
        Listen    => 16,
        ReuseAddr => 1,
    ) or die "Cannot bind TCP $h:$p: $!\n";

    print "[*] Anomalous DNS Mock Server running in standalone mode on $h:$p (PID: $$)\n";

    my $select = IO::Select->new($udp_sock, $tcp_sock);
    $SIG{INT}  = sub { exit 0; };
    $SIG{TERM} = sub { exit 0; };

    while (my @ready = $select->can_read()) {
        for my $fh (@ready) {
            if ($fh == $udp_sock) {
                my $req;
                my $peer = $udp_sock->recv($req, 65535);
                if (defined $peer && length($req) >= 2) {
                    my $resp = process_query_packet($req, 0, 'udp-client');
                    if (defined $resp && length($resp) > 0) {
                        $udp_sock->send($resp, 0, $peer);
                    }
                }
            } elsif ($fh == $tcp_sock) {
                my $client = $tcp_sock->accept();
                if ($client) {
                    my $len_buf;
                    my $n = $client->read($len_buf, 2);
                    if (defined $n && $n == 2) {
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
                        if (length($req) >= $req_len) {
                            my $resp = process_query_packet($req, 1, 'tcp-client');
                            if (defined $resp && length($resp) > 0) {
                                my $out = pack('n', length($resp)) . $resp;
                                $client->send($out);
                            }
                        }
                    }
                    $client->close();
                }
            }
        }
    }
}

# ==============================================================================
# ==============================================================================
# Wire Format Parsing & Encoding Helpers
# ==============================================================================
sub sanitize_domain_name {
    my ($name) = @_;
    return 'anomaly.test' unless defined $name && length($name) > 0;

    my $clean = lc($name);
    # Remove leading/trailing dots and whitespace
    $clean =~ s/^\s+//;
    $clean =~ s/\s+$//;
    $clean =~ s/^\.+//;
    $clean =~ s/\.+$//;

    # Replace dangerous characters (quotes `, ", ', shell metachars, control chars, spaces) with hyphen
    $clean =~ s/[^a-z0-9_.-]/-/g;

    # Normalize consecutive dots and hyphens
    $clean =~ s/\.{2,}/\./g;
    $clean =~ s/-{2,}/-/g;
    $clean =~ s/^\.+//;
    $clean =~ s/\.+$//;

    # Enforce label length limits (RFC 1035: max 63 chars per label)
    my @labels = split(/\./, $clean);
    @labels = grep { length($_) > 0 } @labels;
    for my $l (@labels) {
        $l = substr($l, 0, 63) if length($l) > 63;
    }
    $clean = join('.', @labels);

    # Enforce total FQDN length limit (RFC 1035: max 253 chars)
    $clean = substr($clean, 0, 253) if length($clean) > 253;

    return (length($clean) > 0) ? $clean : 'anomaly.test';
}

sub decode_qname {
    my ($pkt, $offset) = @_;
    my $name = '';
    my $len = length($pkt);
    my $hops = 0;
    while ($offset < $len && $hops++ < 128) {
        my $l = ord(substr($pkt, $offset, 1));
        if ($l == 0) {
            $offset++;
            last;
        } elsif (($l & 0xC0) == 0xC0) {
            $offset += 2;
            last;
        } else {
            $offset++;
            last if $offset + $l > $len;
            my $label = substr($pkt, $offset, $l);
            $name .= ($name eq '' ? '' : '.') . $label;
            $offset += $l;
        }
    }
    return ($name, $offset);
}

sub encode_name {
    my ($name) = @_;
    return "\x00" if !defined $name || $name eq '.' || $name eq '';
    my $wire = '';
    for my $label (split /\./, $name) {
        next if length($label) == 0;
        my $l = substr($label, 0, 63); # RFC 1035 max 63 bytes
        $wire .= pack('C', length($l)) . $l;
    }
    $wire .= "\x00";
    return $wire;
}

sub encode_soa_rr {
    my ($zone_name, $ttl) = @_;
    $ttl //= 300;
    my $safe_zone = sanitize_domain_name($zone_name);
    my $name_wire = encode_name($safe_zone);
    my $mname_wire = encode_name("ns1." . $safe_zone);
    my $rname_wire = encode_name("hostmaster." . $safe_zone);
    my $soa_rdata = $mname_wire . $rname_wire . pack('NNNNN', 2026083101, 3600, 900, 604800, $ttl);
    return $name_wire . pack('nnNn', 6, 1, $ttl, length($soa_rdata)) . $soa_rdata;
}

sub encode_txt_rr {
    my ($name, $text, $ttl) = @_;
    $ttl //= 300;
    my $name_wire = encode_name($name);
    
    # Sanitize text to printable ASCII to prevent escape injection or terminal corruption
    $text =~ s/[^\x20-\x7E]/ /g;

    my $rdata = '';
    # Split text into 255-byte chunks as per RFC 1035 §3.3.14
    for (my $i = 0; $i < length($text); $i += 255) {
        my $chunk = substr($text, $i, 255);
        $rdata .= pack('C', length($chunk)) . $chunk;
    }
    return $name_wire . pack('nnNn', 16, 1, $ttl, length($rdata)) . $rdata;
}

# ==============================================================================
# Scenario Dispatcher: Generates crafted anomalous response packets
# ==============================================================================
sub process_query_packet {
    my ($req, $is_tcp, $client_ip) = @_;
    my $req_len = length($req);

    my $id = 0x1234;
    my $flags = 0;
    my $qdcount = 0;
    my $ancount = 0;
    my $nscount = 0;
    my $arcount = 0;

    if ($req_len >= 12) {
        ($id, $flags, $qdcount, $ancount, $nscount, $arcount) = unpack('n6', substr($req, 0, 12));
    }

    my $offset = 12;
    my $qname = '';
    my $qtype = 1;
    my $qclass = 1;

    if ($qdcount > 0 && $offset < $req_len) {
        ($qname, $offset) = decode_qname($req, $offset);
        if ($offset + 4 <= $req_len) {
            ($qtype, $qclass) = unpack('n2', substr($req, $offset, 4));
            $offset += 4;
        }
    }

    # Detect EDNS / Cookie in request
    my $client_cookie = undef;
    my $server_cookie = undef;
    if ($req_len > 12) {
        if ($req =~ /\x00\x0a\x00\x10(.{8})(.{8})/s) {
            $client_cookie = $1;
            $server_cookie = $2;
        } elsif ($req =~ /\x00\x0a\x00\x08(.{8})/s) {
            $client_cookie = $1;
        }
    }

    my %KNOWN_SCENARIOS = map { $_ => 1 } qw(
        normal header-only short-header trailing-garbage qdcount-mismatch
        ancount-underflow ancount-overflow compression-loop compression-forward-ptr
        unclosed-label rdata-short-a rdata-short-aaaa rdata-soa-truncated
        rdata-mx-truncated rdata-txt-len-mismatch rdata-svcb-overflow
        rdata-opt-truncated cookie-badcookie truncated-tc
        rcode-noerror rcode-formerr rcode-servfail rcode-nxdomain rcode-notimp
        rcode-refused rcode-yxdomain rcode-yxrrset rcode-nxrrset rcode-notauth
        rcode-notzone rcode-dsotypeni rcode-unassigned-12 rcode-unassigned-13
        rcode-unassigned-14 rcode-unassigned-15 rcode-badvers rcode-badsig
        rcode-badkey rcode-badtime rcode-badmode rcode-badname rcode-badalg
        rcode-badtrunc rcode-badcookie rcode-private-3841 rcode-private-4095
        ede-prohibited ede-long-text ede-all ede-all2 drop
        flag-rd flag-ra flag-ad flag-cd flag-z flag-mbz flag-no-aa flag-aa0
        flag-no-qr flag-qr0 flag-tc flag-tc-record flag-all flag-all-tc
        flag-rd-ra flag-ad-cd flag-do flag-co flag-none
    );
    for my $c (0 .. 29) {
        $KNOWN_SCENARIOS{"ede-$c"} = 1;
    }

    my $qname_clean = lc($qname);
    $qname_clean =~ s/\.+$//; # Strip trailing dots

    my ($first_label, $rest_domain) = ($qname_clean =~ /^([^.]+)(?:\.(.*))?$/);
    $first_label //= '';
    $rest_domain //= '';

    my $scenario = '';
    my $zone_apex = '';

    if (exists $KNOWN_SCENARIOS{$first_label} ||
        $first_label =~ /^ede-(\d+)$/ ||
        $first_label =~ /^ede-all2?$/ ||
        $first_label =~ /^flags?-(?:0x[0-9a-fA-F]+|\d+)$/i ||
        $first_label =~ /^flags?-[a-z0-9-]+$/ ||
        $first_label =~ /^rcodes?-(?:0x[0-9a-fA-F]+|\d+)$/i ||
        $first_label =~ /^rcodes?-[a-z0-9-]+$/) {
        $scenario = $first_label;
        $zone_apex = $rest_domain ne '' ? $rest_domain : $qname_clean;
    } else {
        $scenario = 'help';
        $zone_apex = $qname_clean ne '' ? $qname_clean : 'anomaly.test';
    }

    my $id_raw = pack('n', $id);
    my $qname_wire = encode_name($qname);
    my $question_wire = $qname_wire . pack('nn', $qtype, $qclass);

    # --------------------------------------------------------------------------
    # AXFR (QTYPE=252) or Apex Help/TXT Query: Return Dynamic Usage Guide
    # --------------------------------------------------------------------------
    if ($qtype == 252 || $scenario eq 'help' || $qtype == 16) {
        my $display_zone = sanitize_domain_name($zone_apex);
        my @help_lines = (
            "=== KariDNS Anomalous DNS Packet Test Server ===",
            "Usage: dag @<server> -p <port> <scenario>.$display_zone <type>",
            "",
            "[Normal]",
            "  normal.$display_zone                    - Standard NOERROR answer (192.0.2.1)",
            "",
            "[Header & Structure Anomalies]",
            "  header-only.$display_zone               - Header-only packet (QD=0, AN=0)",
            "  short-header.$display_zone              - Truncated header (< 12 bytes)",
            "  trailing-garbage.$display_zone          - Answer with 24 trailing garbage bytes",
            "  qdcount-mismatch.$display_zone          - Claims QDCOUNT=2, but only 1 present",
            "  ancount-underflow.$display_zone         - Claims ANCOUNT=5, but only 1 present",
            "  ancount-overflow.$display_zone          - Claims ANCOUNT=1, but 2 records present",
            "",
            "[Compression & Pointer Safety]",
            "  compression-loop.$display_zone          - Direct pointer compression loop (offset 12)",
            "  compression-forward-ptr.$display_zone   - Out-of-bounds pointer (0x3000)",
            "  unclosed-label.$display_zone            - Unterminated label without trailing 0x00",
            "",
            "[RDATA Truncation & Boundary Violations]",
            "  rdata-short-a.$display_zone             - Truncated A record (RDLENGTH=4 with 2 bytes)",
            "  rdata-short-aaaa.$display_zone          - Truncated AAAA (RDLENGTH=16 with 8 bytes)",
            "  rdata-soa-truncated.$display_zone       - Truncated SOA record",
            "  rdata-mx-truncated.$display_zone        - Truncated MX record (missing exchange)",
            "  rdata-txt-len-mismatch.$display_zone    - TXT string length exceeds RDLENGTH",
            "  rdata-svcb-overflow.$display_zone       - SVCB TargetName length exceeds RDLENGTH",
            "  rdata-opt-truncated.$display_zone       - Truncated OPT record option data",
            "",
            "[Protocol & Security Flags]",
            "  cookie-badcookie.$display_zone          - BADCOOKIE (RCODE 23) retry negotiation",
            "  truncated-tc.$display_zone              - TC=1 response triggering TCP fallback (0 records)",
            "  flag-tc.$display_zone                   - TC=1 (Truncation) with answer record attached",
            "  flag-rd.$display_zone                   - RD=1 (Recursion Desired) unsolicitedly set in response",
            "  flag-ra.$display_zone                   - RA=1 (Recursion Available) unsolicitedly set in response",
            "  flag-ad.$display_zone                   - AD=1 (Authentic Data) set in answer",
            "  flag-cd.$display_zone                   - CD=1 (Checking Disabled) set in answer",
            "  flag-z.$display_zone                    - Z=1 (Reserved MBZ bit 0x0040) set in answer",
            "  flag-no-aa.$display_zone                - AA=0 (Authoritative bit cleared) in answer",
            "  flag-no-qr.$display_zone                - QR=0 (Query bit unset, response masquerade)",
            "  flag-rd-ra.$display_zone                - Both RD=1 and RA=1 set in answer",
            "  flag-ad-cd.$display_zone                - Both AD=1 and CD=1 set in answer",
            "  flag-all.$display_zone                  - All header flags enabled (QR,AA,RD,RA,AD,CD,Z)",
            "  flag-all-tc.$display_zone               - All header flags enabled including TC",
            "  flag-do.$display_zone                   - EDNS0 DO=1 (DNSSEC OK) set in OPT RR",
            "  flag-co.$display_zone                   - EDNS0 Compact Answers OK set in OPT RR",
            "  flag-0x<HEX>.$display_zone              - Custom 16-bit header flags (e.g. flag-0x85f0)",
            "",
            "[DNS Header RCODEs (0-15)]",
            "  rcode-noerror.$display_zone             - NOERROR (RCODE 0): Success",
            "  rcode-formerr.$display_zone             - FORMERR (RCODE 1): Format Error",
            "  rcode-servfail.$display_zone            - SERVFAIL (RCODE 2): Server Failure",
            "  rcode-nxdomain.$display_zone            - NXDOMAIN (RCODE 3): Non-Existent Domain",
            "  rcode-notimp.$display_zone              - NOTIMP (RCODE 4): Not Implemented",
            "  rcode-refused.$display_zone             - REFUSED (RCODE 5): Query Refused",
            "  rcode-yxdomain.$display_zone            - YXDOMAIN (RCODE 6): Name Exists (RFC 2136)",
            "  rcode-yxrrset.$display_zone             - YXRRSET (RCODE 7): RR Set Exists (RFC 2136)",
            "  rcode-nxrrset.$display_zone             - NXRRSET (RCODE 8): RR Set Does Not Exist (RFC 2136)",
            "  rcode-notauth.$display_zone             - NOTAUTH (RCODE 9): Not Authoritative / Authorized",
            "  rcode-notzone.$display_zone             - NOTZONE (RCODE 10): Name Not In Zone (RFC 2136)",
            "  rcode-dsotypeni.$display_zone           - DSOTYPENI (RCODE 11): DSO Type Not Implemented (RFC 8490)",
            "  rcode-unassigned-12..15.$display_zone   - Unassigned standard header RCODEs 12..15",
            "",
            "[EDNS0 Extended RCODEs (16-23+)]",
            "  rcode-badvers.$display_zone             - BADVERS (RCODE 16): Bad EDNS Version (RFC 6891)",
            "  rcode-badsig.$display_zone              - BADSIG (RCODE 16): TSIG Signature Failure (RFC 2845)",
            "  rcode-badkey.$display_zone              - BADKEY (RCODE 17): Key Not Recognized (RFC 2845)",
            "  rcode-badtime.$display_zone             - BADTIME (RCODE 18): Signature Out of Time (RFC 2845)",
            "  rcode-badmode.$display_zone             - BADMODE (RCODE 19): Bad TKEY Mode (RFC 2930)",
            "  rcode-badname.$display_zone             - BADNAME (RCODE 20): Duplicate Key Name (RFC 2930)",
            "  rcode-badalg.$display_zone              - BADALG (RCODE 21): Algorithm Not Supported (RFC 2930)",
            "  rcode-badtrunc.$display_zone            - BADTRUNC (RCODE 22): Bad Truncation (RFC 4635)",
            "  rcode-badcookie.$display_zone           - BADCOOKIE (RCODE 23): Bad/Missing Cookie (RFC 7873)",
            "  rcode-private-3841..4095.$display_zone  - Private Use Extended RCODEs (RFC 6891)",
            "  rcode-<DEC>.$display_zone               - Arbitrary decimal RCODE (e.g. rcode-100)",
            "  rcode-0x<HEX>.$display_zone             - Arbitrary hex RCODE (e.g. rcode-0x0017)",
            "",
            "[Extended DNS Errors (EDE)]",
            "  ede-0 .. ede-29.$display_zone           - Individual EDE Code 0..29",
            "  ede-all.$display_zone                   - All 30 EDE options in a single response",
            "  ede-all2.$display_zone                  - All 30 EDE options duplicated (2x each)",
            "  ede-prohibited.$display_zone            - EDE Code 18 (Prohibited)",
            "  ede-long-text.$display_zone             - EDE with long description string",
            "",
            "[Drop / Discard]",
            "  drop.$display_zone                      - Silently discards query without reply",
        );

        my $soa_start = encode_soa_rr($qname, 300);
        my $soa_end   = encode_soa_rr($qname, 300);

        my $answers = '';
        my $ans_count = 0;

        if ($qtype == 252) {
            # AXFR transfer format (RFC 5936): Full 35+ scenarios list
            $answers .= $soa_start;
            $ans_count++;
            for my $line (@help_lines) {
                next if $line eq '';
                $answers .= encode_txt_rr($qname, $line, 300);
                $ans_count++;
            }
            $answers .= $soa_end;
            $ans_count++;
        } else {
            # Standard TXT / Apex Query format: Compact overview (fits safely in 512-byte UDP packet)
            my @summary_lines = (
                "=== KariDNS Anomalous DNS Packet Test Server ===",
                "Usage: dag @<server> -p <port> <scenario>.$display_zone <type>",
                "Query AXFR (Zone Transfer) to view all 30+ anomalous test scenarios."
            );
            for my $line (@summary_lines) {
                next if $line eq '';
                $answers .= encode_txt_rr($qname, $line, 300);
                $ans_count++;
            }
        }

        my $pkt = $id_raw . pack('n5', 0x8400, 1, $ans_count, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $answers;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 0. Intentional Drop / No Response
    # --------------------------------------------------------------------------
    if ($scenario eq 'drop') {
        return ""; # 0 length tells KariDNS not to send anything
    }

    # --------------------------------------------------------------------------
    # 1. Basic Header / Structure Anomalies
    # --------------------------------------------------------------------------
    if ($scenario eq 'header-only') {
        # Valid header but 0 questions, 0 answers
        return $id_raw . pack('n5', 0x8400, 0, 0, 0, 0);
    }
    if ($scenario eq 'short-header') {
        # Only 6 bytes (truncated header)
        return $id_raw . pack('n2', 0x8400, 1);
    }
    if ($scenario eq 'trailing-garbage') {
        # Normal Answer + 24 extra garbage bytes
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= "EXTRA_TRAILING_GARBAGE_BYTES";
        return $pkt;
    }
    if ($scenario eq 'qdcount-mismatch') {
        # Header says QDCOUNT=2, but only 1 question present
        my $pkt = $id_raw . pack('n5', 0x8400, 2, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario eq 'ancount-underflow') {
        # Header says ANCOUNT=5, but only 1 record present
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 5, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'ancount-overflow') {
        # Header says ANCOUNT=1, but 2 records present
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 2);
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 2. Name Compression / Pointer Anomalies
    # --------------------------------------------------------------------------
    if ($scenario eq 'compression-loop') {
        # Offset 12 starts name: 0xc0 0x0c (direct loop)
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\xc0\x0c" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'compression-forward-ptr') {
        # Pointer to offset 0x3000 (far beyond packet length)
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\xc0\xff" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'unclosed-label') {
        # Unterminated label without 0x00
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\x05hello\x0aabc";
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 3. RDATA Truncation & Boundary Violations
    # --------------------------------------------------------------------------
    if ($scenario eq 'rdata-short-a') {
        # TYPE=A, RDLENGTH=4, but only 2 bytes provided
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . "\xc0\x00";
        return $pkt;
    }
    if ($scenario eq 'rdata-short-aaaa') {
        # TYPE=AAAA, RDLENGTH=16, but only 8 bytes provided
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 28, 1, 300, 16) . pack('C8', 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1);
        return $pkt;
    }
    if ($scenario eq 'rdata-soa-truncated') {
        # SOA record ends abruptly
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 6, 1, 300, 30) . "\x02ns\x07example";
        return $pkt;
    }
    if ($scenario eq 'rdata-mx-truncated') {
        # MX with preference only
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 15, 1, 300, 2) . pack('n', 10);
        return $pkt;
    }
    if ($scenario eq 'rdata-txt-len-mismatch') {
        # TXT length declares 100, but RDLENGTH is 10
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 16, 1, 300, 10) . pack('C', 100) . "123456789";
        return $pkt;
    }
    if ($scenario eq 'rdata-svcb-overflow') {
        # SVCB TargetName length exceeds RDLENGTH
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 64, 1, 300, 8) . pack('n', 1) . "\x14target";
        return $pkt;
    }
    if ($scenario eq 'rdata-opt-truncated') {
        # OPT RR with truncated option
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 1);
        $pkt .= $question_wire;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, 8) . pack('nn', 10, 16) . "1234";
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 4. Protocol & Security Flags (Cookies, Truncation)
    # --------------------------------------------------------------------------
    if ($scenario eq 'cookie-badcookie') {
        my $srv_cookie = "\x11\x22\x33\x44\x55\x66\x77\x88";
        my $cl_c = $client_cookie // "\x01\x02\x03\x04\x05\x06\x07\x08";
        if (defined $server_cookie && $server_cookie eq $srv_cookie) {
            # Verified server cookie returned on retry: respond with NOERROR Answer
            my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 1);
            $pkt .= $question_wire;
            $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            my $copt = pack('nn', 10, 16) . $cl_c . $srv_cookie;
            $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($copt)) . $copt;
            return $pkt;
        } else {
            # First query without valid server cookie: return BADCOOKIE (RCODE 23)
            my $pkt = $id_raw . pack('n5', 0x8407, 1, 0, 0, 1);
            $pkt .= $question_wire;
            my $copt = pack('nn', 10, 16) . $cl_c . $srv_cookie;
            $pkt .= "\x00" . pack('nnNn', 41, 4096, 0x01000000, length($copt)) . $copt;
            return $pkt;
        }
    }
    if ($scenario eq 'truncated-tc') {
        # TC=1 (Truncated) response
        my $pkt = $id_raw . pack('n5', 0x8600, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario =~ /^flags?-(.*)$/) {
        my $spec = lc($1);
        my $flag_val = 0x8400; # Base: QR=1, AA=1
        my $desc = "Flag test: ";
        my $edns_do = 0;
        my $edns_co = 0;

        if ($spec =~ /^0x([0-9a-fA-F]{1,4})$/) {
            $flag_val = hex($1);
            $desc .= sprintf("Custom flags 0x%04X", $flag_val);
        } elsif ($spec =~ /^(\d+)$/) {
            $flag_val = int($1) & 0xFFFF;
            $desc .= sprintf("Custom flags %d (0x%04X)", $flag_val, $flag_val);
        } elsif ($spec eq 'rd') {
            $flag_val = 0x8500; # QR=1, AA=1, RD=1
            $desc .= "RD=1 (Recursion Desired) unsolicitedly set in response";
        } elsif ($spec eq 'ra') {
            $flag_val = 0x8480; # QR=1, AA=1, RA=1
            $desc .= "RA=1 (Recursion Available) unsolicitedly set in response";
        } elsif ($spec eq 'ad') {
            $flag_val = 0x8420; # QR=1, AA=1, AD=1
            $desc .= "AD=1 (Authentic Data) set in response";
        } elsif ($spec eq 'cd') {
            $flag_val = 0x8410; # QR=1, AA=1, CD=1
            $desc .= "CD=1 (Checking Disabled) set in response";
        } elsif ($spec eq 'z' || $spec eq 'mbz') {
            $flag_val = 0x8440; # QR=1, AA=1, Z=1 (MBZ bit 0x0040)
            $desc .= "Reserved Z-bit (MBZ 0x0040) set to 1 in response";
        } elsif ($spec eq 'no-aa' || $spec eq 'aa0') {
            $flag_val = 0x8000; # QR=1, AA=0
            $desc .= "AA=0 (Authoritative Answer bit cleared) in response";
        } elsif ($spec eq 'no-qr' || $spec eq 'qr0') {
            $flag_val = 0x0400; # QR=0, AA=1 (claims to be query)
            $desc .= "QR=0 (Query/Response bit cleared, response masquerade) in packet";
        } elsif ($spec eq 'tc' || $spec eq 'tc-record') {
            $flag_val = 0x8600; # QR=1, AA=1, TC=1
            $desc .= "TC=1 (Truncation) with answer records attached";
        } elsif ($spec eq 'rd-ra') {
            $flag_val = 0x8580; # QR=1, AA=1, RD=1, RA=1
            $desc .= "Both RD=1 and RA=1 unsolicitedly set in response";
        } elsif ($spec eq 'ad-cd') {
            $flag_val = 0x8430; # QR=1, AA=1, AD=1, CD=1
            $desc .= "Both AD=1 and CD=1 set in response";
        } elsif ($spec eq 'all') {
            $flag_val = 0x85F0; # QR=1, AA=1, RD=1, RA=1, Z=1, AD=1, CD=1
            $desc .= "ALL header flags set (QR=1, AA=1, RD=1, RA=1, AD=1, CD=1, Z=1 [0x85F0])";
        } elsif ($spec eq 'all-tc') {
            $flag_val = 0x87F0; # All flags including TC
            $desc .= "ALL header flags set including TC (QR=1, AA=1, TC=1, RD=1, RA=1, AD=1, CD=1, Z=1 [0x87F0])";
        } elsif ($spec eq 'do') {
            $flag_val = 0x8400;
            $edns_do = 1;
            $desc .= "EDNS0 DO=1 (DNSSEC OK) flag set in OPT RR";
        } elsif ($spec eq 'co') {
            $flag_val = 0x8400;
            $edns_co = 1;
            $desc .= "EDNS0 Compact Answers OK flag set in OPT RR";
        } elsif ($spec eq 'none') {
            $flag_val = 0x0000;
            $desc .= "No flags set (0x0000)";
        } else {
            # Combinations like flag-rd-ad
            $flag_val = 0x8400;
            $flag_val |= 0x0100 if $spec =~ /rd/;
            $flag_val |= 0x0080 if $spec =~ /ra/;
            $flag_val |= 0x0020 if $spec =~ /ad/;
            $flag_val |= 0x0010 if $spec =~ /cd/;
            $flag_val |= 0x0040 if $spec =~ /z/;
            $flag_val |= 0x0200 if $spec =~ /tc/;
            $flag_val &= ~0x0400 if $spec =~ /no-aa/;
            $flag_val &= ~0x8000 if $spec =~ /no-qr/;
            $desc .= sprintf("Combined flags 0x%04X (%s)", $flag_val, $spec);
        }

        my $answers = '';
        my $ancount = 0;
        my $arcount = 0;
        my $additionals = '';

        if ($qtype == 16) {
            # QTYPE=TXT: Return explanation in ANSWER section
            $answers .= encode_txt_rr($qname, $desc, 300);
            $ancount++;
        } elsif ($qtype == 255) {
            # QTYPE=ANY: Return both A and TXT in ANSWER section
            $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            $answers .= encode_txt_rr($qname, $desc, 300);
            $ancount += 2;
        } else {
            # Default (A or others): Return A record in ANSWER, TXT in ADDITIONAL
            $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            $ancount++;
            $additionals .= encode_txt_rr($qname, $desc, 300);
            $arcount++;
        }

        if ($edns_do || $edns_co) {
            my $ext_flags = 0;
            $ext_flags |= 0x8000 if $edns_do; # DO bit
            $ext_flags |= 0x4000 if $edns_co; # CO bit
            # OPT pseudo-RR: Name=\x00, TYPE=41, CLASS=4096 (UDP size), TTL=ext_flags (32-bit: rcode/version/flags), RDLEN=0
            $additionals .= "\x00" . pack('nnNn', 41, 4096, ($ext_flags << 16), 0);
            $arcount++;
        }

        my $pkt = $id_raw . pack('n5', $flag_val, 1, $ancount, 0, $arcount);
        $pkt .= $question_wire;
        $pkt .= $answers;
        $pkt .= $additionals;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 5. RFC Standard & Extended RCODEs
    # --------------------------------------------------------------------------
    my %RCODE_INFO = (
        0  => { name => 'NOERROR',       rfc => 'RFC 1035', desc => 'No Error condition' },
        1  => { name => 'FORMERR',       rfc => 'RFC 1035', desc => 'Format Error' },
        2  => { name => 'SERVFAIL',      rfc => 'RFC 1035', desc => 'Server Failure' },
        3  => { name => 'NXDOMAIN',      rfc => 'RFC 1035', desc => 'Non-Existent Domain' },
        4  => { name => 'NOTIMP',        rfc => 'RFC 1035', desc => 'Not Implemented' },
        5  => { name => 'REFUSED',       rfc => 'RFC 1035', desc => 'Query Refused' },
        6  => { name => 'YXDOMAIN',      rfc => 'RFC 2136', desc => 'Name Exists when it should not' },
        7  => { name => 'YXRRSET',       rfc => 'RFC 2136', desc => 'RR Set Exists when it should not' },
        8  => { name => 'NXRRSET',       rfc => 'RFC 2136', desc => 'RR Set that should exist does not' },
        9  => { name => 'NOTAUTH',       rfc => 'RFC 2136 / RFC 8945', desc => 'Server Not Authoritative for zone / Not Authorized' },
        10 => { name => 'NOTZONE',       rfc => 'RFC 2136', desc => 'Name not contained in zone' },
        11 => { name => 'DSOTYPENI',     rfc => 'RFC 8490', desc => 'DSO-TYPE Not Implemented' },
        12 => { name => 'UNASSIGNED-12', rfc => 'RFC 6891', desc => 'Unassigned standard header RCODE 12' },
        13 => { name => 'UNASSIGNED-13', rfc => 'RFC 6891', desc => 'Unassigned standard header RCODE 13' },
        14 => { name => 'UNASSIGNED-14', rfc => 'RFC 6891', desc => 'Unassigned standard header RCODE 14' },
        15 => { name => 'UNASSIGNED-15', rfc => 'RFC 6891', desc => 'Unassigned standard header RCODE 15' },
        16 => { name => 'BADVERS/BADSIG', rfc => 'RFC 6891 / RFC 2845', desc => 'Bad OPT Version (BADVERS) / TSIG Signature Failure (BADSIG)' },
        17 => { name => 'BADKEY',        rfc => 'RFC 2845', desc => 'Key not recognized (TSIG)' },
        18 => { name => 'BADTIME',       rfc => 'RFC 2845', desc => 'Signature out of time window (TSIG)' },
        19 => { name => 'BADMODE',       rfc => 'RFC 2930', desc => 'Bad TKEY Mode' },
        20 => { name => 'BADNAME',       rfc => 'RFC 2930', desc => 'Duplicate key name (TKEY)' },
        21 => { name => 'BADALG',        rfc => 'RFC 2930', desc => 'Algorithm not supported (TKEY)' },
        22 => { name => 'BADTRUNC',      rfc => 'RFC 4635', desc => 'Bad Truncation (TSIG)' },
        23 => { name => 'BADCOOKIE',     rfc => 'RFC 7873', desc => 'Bad / missing Server Cookie' },
    );

    my %RCODE_ALIASES = (
        'noerror'       => 0,
        'formerr'       => 1,
        'servfail'      => 2,
        'nxdomain'      => 3,
        'notimp'        => 4,
        'refused'       => 5,
        'yxdomain'      => 6,
        'yxrrset'       => 7,
        'nxrrset'       => 8,
        'notauth'       => 9,
        'notzone'       => 10,
        'dsotypeni'     => 11,
        'unassigned-12' => 12,
        'unassigned-13' => 13,
        'unassigned-14' => 14,
        'unassigned-15' => 15,
        'badvers'       => 16,
        'badsig'        => 16,
        'badkey'        => 17,
        'badtime'       => 18,
        'badmode'       => 19,
        'badname'       => 20,
        'badalg'        => 21,
        'badtrunc'      => 22,
        'badcookie'     => 23,
        'private-3841'  => 3841,
        'private-4095'  => 4095,
    );

    if ($scenario =~ /^rcodes?-(.*)$/) {
        my $spec = lc($1);
        my $rcode_val = undef;

        if ($spec =~ /^0x([0-9a-fA-F]+)$/) {
            $rcode_val = hex($1);
        } elsif ($spec =~ /^(\d+)$/) {
            $rcode_val = int($1);
        } elsif (exists $RCODE_ALIASES{$spec}) {
            $rcode_val = $RCODE_ALIASES{$spec};
        }

        if (defined $rcode_val) {
            $rcode_val &= 0xFFFF;
            my $header_rc = $rcode_val & 0x0F;
            my $ext_rc    = ($rcode_val >> 4) & 0xFF;
            my $flags_val = 0x8400 | $header_rc;

            my $info = $RCODE_INFO{$rcode_val};
            my $name_str = $info ? $info->{name} : sprintf("RCODE_%d", $rcode_val);
            my $rfc_str  = $info ? $info->{rfc} : "RFC 6891";
            my $desc_str = $info ? $info->{desc} : sprintf("Unassigned / Private RCODE %d (0x%04X)", $rcode_val, $rcode_val);

            my $desc = sprintf(
                "RCODE %d (0x%04X) [%s] %s: %s (header_rc=%d, edns_ext=%d)",
                $rcode_val, $rcode_val, $name_str, $rfc_str, $desc_str, $header_rc, $ext_rc
            );

            my $answers = '';
            my $ancount = 0;
            my $arcount = 0;
            my $additionals = '';

            if ($qtype == 16) {
                # QTYPE=TXT: Return explanation in ANSWER section
                $answers .= encode_txt_rr($qname, $desc, 300);
                $ancount++;
            } elsif ($qtype == 255) {
                # QTYPE=ANY: Return both A and TXT in ANSWER section
                $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
                $answers .= encode_txt_rr($qname, $desc, 300);
                $ancount += 2;
            } else {
                # Default (A or others):
                if ($rcode_val == 0) {
                    # NOERROR: Return A record in ANSWER
                    $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
                    $ancount++;
                }
                # Attach explanation TXT in ADDITIONAL section for diagnostic experience
                $additionals .= encode_txt_rr($qname, $desc, 300);
                $arcount++;
            }

            # If RCODE > 15 (EDNS Extended RCODE) or client had EDNS, append OPT pseudo-RR
            my $client_has_edns = (defined($client_cookie) || $req =~ /\x00\x00\x29/s);
            if ($ext_rc > 0 || $client_has_edns) {
                my $ttl_ext = ($ext_rc << 24);
                my $opt_rdata = '';
                if ($rcode_val == 23) {
                    # BADCOOKIE (RFC 7873): return Server Cookie in OPT RR
                    my $srv_c = "\x11\x22\x33\x44\x55\x66\x77\x88";
                    my $cl_c  = $client_cookie // "\x01\x02\x03\x04\x05\x06\x07\x08";
                    $opt_rdata = pack('nn', 10, 16) . $cl_c . $srv_c;
                }
                $additionals .= "\x00" . pack('nnNn', 41, 4096, $ttl_ext, length($opt_rdata)) . $opt_rdata;
                $arcount++;
            }

            my $pkt = $id_raw . pack('n5', $flags_val, 1, $ancount, 0, $arcount);
            $pkt .= $question_wire;
            $pkt .= $answers;
            $pkt .= $additionals;
            return $pkt;
        }
    }

    # --------------------------------------------------------------------------
    # 6. Extended DNS Errors (EDE, RFC 8914)
    # --------------------------------------------------------------------------
    if ($scenario eq 'ede-all') {
        my $pkt = $id_raw . pack('n5', 0x8402, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_opts = '';
        for my $code (0 .. 29) {
            my $ede_text = "EDE code $code test description";
            $ede_opts .= pack('nnn', 15, length($ede_text) + 2, $code) . $ede_text;
        }
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opts)) . $ede_opts;
        return $pkt;
    }
    if ($scenario eq 'ede-all2') {
        my $pkt = $id_raw . pack('n5', 0x8402, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_opts = '';
        for my $code (0 .. 29) {
            for my $rep (1 .. 2) {
                my $ede_text = "EDE code $code duplicate #$rep test description";
                $ede_opts .= pack('nnn', 15, length($ede_text) + 2, $code) . $ede_text;
            }
        }
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opts)) . $ede_opts;
        return $pkt;
    }
    if ($scenario =~ /^ede-(\d+)$/) {
        my $code = int($1);
        my $pkt = $id_raw . pack('n5', 0x8402, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_text = "EDE code $code test description";
        my $ede_opt = pack('nnn', 15, length($ede_text) + 2, $code) . $ede_text;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opt)) . $ede_opt;
        return $pkt;
    }
    if ($scenario eq 'ede-prohibited') {
        my $pkt = $id_raw . pack('n5', 0x8405, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_text = "Query blocked by test policy";
        my $ede_opt = pack('nnn', 15, length($ede_text) + 2, 18) . $ede_text;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opt)) . $ede_opt;
        return $pkt;
    }
    if ($scenario eq 'ede-long-text') {
        my $pkt = $id_raw . pack('n5', 0x8402, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_text = "ExtendedErrorDescription:" . ("A" x 280);
        my $ede_opt = pack('nnn', 15, length($ede_text) + 2, 0) . $ede_text;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opt)) . $ede_opt;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # Default: Normal NOERROR Answer
    # --------------------------------------------------------------------------
    my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
    $pkt .= $question_wire;
    $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
    return $pkt;
}
