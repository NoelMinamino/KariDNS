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
# Wire Format Parsing & Encoding Helpers
# ==============================================================================
sub sanitize_domain_name {
    my ($name) = @_;
    return 'anomaly.test' unless defined $name && length($name) > 0;

    my $clean = lc($name);
    $clean =~ s/^\s+//;
    $clean =~ s/\s+$//;
    $clean =~ s/^\.+//;
    $clean =~ s/\.+$//;

    $clean =~ s/[^a-z0-9_.-]/-/g;
    $clean =~ s/\.{2,}/\./g;
    $clean =~ s/-{2,}/-/g;
    $clean =~ s/^\.+//;
    $clean =~ s/\.+$//;

    my @labels = split(/\./, $clean);
    @labels = grep { length($_) > 0 } @labels;
    for my $l (@labels) {
        $l = substr($l, 0, 63) if length($l) > 63;
    }
    $clean = join('.', @labels);
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
        my $l = substr($label, 0, 63);
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
    my $soa_rdata = $mname_wire . $rname_wire . pack('NNNNN', 2026091301, 3600, 900, 604800, $ttl);
    return $name_wire . pack('nnNn', 6, 1, $ttl, length($soa_rdata)) . $soa_rdata;
}

sub encode_txt_rr {
    my ($name, $text, $ttl) = @_;
    $ttl //= 300;
    my $name_wire = encode_name($name);
    $text =~ s/[^\x20-\x7E]/ /g;

    my $rdata = '';
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

    # Detect EDNS / Cookie / Buffer size in request
    my $client_cookie = undef;
    my $server_cookie = undef;
    my $client_bufsize = 512;
    if ($req_len > 12) {
        if ($req =~ /\x00\x0a\x00\x10(.{8})(.{8})/s) {
            $client_cookie = $1;
            $server_cookie = $2;
        } elsif ($req =~ /\x00\x0a\x00\x08(.{8})/s) {
            $client_cookie = $1;
        }
        if ($req =~ /\x00\x00\x29(..)/s) {
            $client_bufsize = unpack('n', $1);
        }
    }

    my %KNOWN_SCENARIOS = map { $_ => 1 } qw(
        normal header-only short-header trailing-garbage qdcount-mismatch
        ancount-underflow ancount-overflow compression-loop compression-indirect-loop
        compression-forward-ptr compression-bad-bits compression-deep-chain ptr-chain
        compression-misaligned ptr-chain-name-overflow label-overflow label-64
        null-byte-in-label case-0x20-mismatch class-mismatch meta-type-in-answer
        dname-loop dname-overflow edns-bufsize-exceeded tcp-max-65535 huge-tcp-65535
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
        flag-rd-ra flag-ad-cd flag-do flag-co flag-do-co flag-all-do-co
        flag-all-do flag-all-co flag-all-tc-do-co flag-none what-is-my-ip
        id-mismatch no-question query-mismatch multi-question
        opcode-unassigned opcode-status opcode-notify
        nscount-underflow nscount-overflow arcount-underflow arcount-overflow
        zero-ttl huge-ttl cname-loop cname-with-data
        multi-opt opt-in-answer opt-badvers opt-unknown-option opt-option-len-overflow
    );
    for my $c (0 .. 29) {
        $KNOWN_SCENARIOS{"ede-$c"} = 1;
    }

    my $qname_clean = lc($qname);
    $qname_clean =~ s/\.+$//;

    my ($first_label, $rest_domain) = ($qname_clean =~ /^([^.]+)(?:\.(.*))?$/);
    $first_label //= '';
    $rest_domain //= '';

    # QNAME の中に dname-loop / dname-a / dname-b が含まれているか判定
    my $is_dname_scenario = 0;
    my $dname_sublabel = '1';
    if ($qname_clean =~ /^(?:(.*)\.)?(dname-(?:loop|[ab]))\.(.*)$/) {
        $dname_sublabel = $1 if defined $1 && length($1) > 0;
        $first_label    = $2;
        $rest_domain    = $3;
        $is_dname_scenario = 1;
    }

    
    my $scenario = '';
    my $zone_apex = '';

    if (exists $KNOWN_SCENARIOS{$first_label} ||
	$first_label =~ /^dname-[ab]$/ ||
        $first_label =~ /^ede-(\d+)$/ ||
        $first_label =~ /^ede-all2?$/ ||
        $first_label =~ /^(?:ptr-chain|compression-chain|ptr-hops)(?:-(\d+))?$/ ||
	$first_label =~ /^(?:tcp-size|packet-size)-(\d+)$/ ||
        $first_label =~ /^flags?-(?:0x[0-9a-fA-F]+|\d+)$/i ||
        $first_label =~ /^flags?-[a-z0-9+_-]+$/i ||
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
            "  what-is-my-ip.$display_zone             - Show your resolver IP address",
            "",
            "[Header & Structure Anomalies]",
            "  header-only.$display_zone               - Header-only packet (QD=0, AN=0)",
            "  short-header.$display_zone              - Truncated header (< 12 bytes)",
            "  trailing-garbage.$display_zone          - Answer with 24 trailing garbage bytes",
            "  qdcount-mismatch.$display_zone          - Claims QDCOUNT=2, but only 1 present",
            "  ancount-underflow.$display_zone         - Claims ANCOUNT=5, but only 1 present",
            "  ancount-overflow.$display_zone          - Claims ANCOUNT=1, but 2 records present",
            "  id-mismatch.$display_zone               - Response Transaction ID mismatch (spoofing detection)",
            "  no-question.$display_zone               - QDCOUNT=0 with Answer RR present",
            "  query-mismatch.$display_zone            - Question section QNAME mismatch",
            "  multi-question.$display_zone            - QDCOUNT=2 with 2 Question sections present (RFC 9619)",
            "  opcode-unassigned.$display_zone         - Unassigned DNS Opcode 3 in header",
            "  opcode-status.$display_zone             - Opcode 2 (STATUS) in header",
            "  opcode-notify.$display_zone             - Opcode 4 (NOTIFY) in header",
            "",
            "[Compression & Pointer Safety]",
            "  compression-loop.$display_zone          - Direct pointer compression loop (offset 12)",
            "  compression-indirect-loop.$display_zone - Mutual indirect compression loop (offset 12 <-> 22)",
            "  compression-forward-ptr.$display_zone   - Out-of-bounds pointer (0x3000)",
            "  compression-bad-bits.$display_zone      - Reserved/unsupported label type bits (0x40/0x80)",
            "  compression-deep-chain.$display_zone    - Deep chain of 60 consecutive compression pointers",
            "  ptr-chain-<hops>.$display_zone          - Arbitrary N-hop compression pointer chain (e.g. ptr-chain-10)",
            "  compression-misaligned.$display_zone    - Pointer points into the middle of a string (non-aligned)",
            "  ptr-chain-name-overflow.$display_zone   - Pointer chain expanding domain name beyond 255 bytes limit",
            "  unclosed-label.$display_zone            - Unterminated label without trailing 0x00",
            "",
            "[Label & Name Boundary Violations]",
            "  label-overflow.$display_zone            - Label length octet is 64 (> 63 bytes RFC 1035 limit)",
            "  null-byte-in-label.$display_zone        - Label contains embedded 0x00 byte (C-string poison test)",
            "  case-0x20-mismatch.$display_zone        - Reflected Question section with inverted ASCII casing",
            "",
            "[Section Count & Record Semantics]",
            "  class-mismatch.$display_zone            - QCLASS=IN query answered with CLASS=CH (Chaosnet) RR",
            "  meta-type-in-answer.$display_zone       - Meta-type (QTYPE=ANY) injected into Answer section",
            "  dname-loop.$display_zone                - Mutual DNAME loop (A -> B -> A)",
            "  dname-overflow.$display_zone            - DNAME synthesis exceeds 255-byte limit (returns YXDOMAIN)",
            "  nscount-underflow.$display_zone         - Claims NSCOUNT=3, but only 1 record present",
            "  nscount-overflow.$display_zone          - Claims NSCOUNT=1, but 2 records present",
            "  arcount-underflow.$display_zone         - Claims ARCOUNT=3, but only 1 record present",
            "  arcount-overflow.$display_zone          - Claims ARCOUNT=1, but 2 records present",
            "  zero-ttl.$display_zone                  - Answer record with TTL = 0",
            "  huge-ttl.$display_zone                  - Answer record with TTL = 0xFFFFFFFF (RFC 2181 §8)",
            "  cname-loop.$display_zone                - Mutually referencing CNAME loop (A -> B -> A)",
            "  cname-with-data.$display_zone           - CNAME and A record coexistence (RFC 1034 §3.6.2)",
            "",
            "[Transport & Buffer Oversize]",
            "  edns-bufsize-exceeded.$display_zone     - UDP answer exceeding advertised EDNS buffer size (TC=0)",
            "  tcp-max-65535.$display_zone             - Maximum legal DNS message size of 65,535 bytes (TCP)",
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
            "[EDNS0 (RFC 6891) Boundary & Violations]",
            "  multi-opt.$display_zone                 - Multiple (2) OPT pseudo-RRs in Additional section",
            "  opt-in-answer.$display_zone             - OPT pseudo-RR placed in Answer section",
            "  opt-badvers.$display_zone               - OPT pseudo-RR with EDNS Version=1 (BADVERS=16)",
            "  opt-unknown-option.$display_zone        - OPT RR with unknown option code 65001 (0xFDE9)",
            "  opt-option-len-overflow.$display_zone   - OPT Option length exceeds OPT RR RDLENGTH",
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
            "  flag-do-co.$display_zone                - Both EDNS0 DO=1 and CO=1 set in OPT RR",
            "  flag-all-do-co.$display_zone            - All header flags (0x85F0) + EDNS0 DO=1 and CO=1",
            "  flag-all+do+co.$display_zone            - All header flags + DO=1 + CO=1 ('+' syntax)",
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
            "  rcode-unassigned-<12-15>.$display_zone  - Unassigned standard header RCODEs 12..15 (e.g. rcode-unassigned-12)",
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
            "  rcode-private-<3841-4095>.$display_zone - Private Use Extended RCODEs (RFC 6891, e.g. rcode-private-3841)",
            "  rcode-<DEC>.$display_zone               - Arbitrary decimal RCODE (e.g. rcode-100)",
            "  rcode-0x<HEX>.$display_zone             - Arbitrary hex RCODE (e.g. rcode-0x0017)",
            "",
            "[Extended DNS Errors (EDE)]",
            "  ede-<0-29>.$display_zone                - Individual EDE Code 0..29 (e.g. ede-18)",
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
                "Query AXFR (Zone Transfer) to view all 40+ anomalous test scenarios."
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
        if ($is_tcp) {
            sleep(2);
        }
        return "";
    }

    # --------------------------------------------------------------------------
    # 1. Basic Header / Structure Anomalies
    # --------------------------------------------------------------------------
    if ($scenario eq 'header-only') {
        return $id_raw . pack('n5', 0x8400, 0, 0, 0, 0);
    }
    if ($scenario eq 'short-header') {
        return $id_raw . pack('n2', 0x8400, 1);
    }
    if ($scenario eq 'trailing-garbage') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= "EXTRA_TRAILING_GARBAGE_BYTES";
        return $pkt;
    }
    if ($scenario eq 'qdcount-mismatch') {
        my $pkt = $id_raw . pack('n5', 0x8400, 2, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario eq 'ancount-underflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 5, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'ancount-overflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 2);
        return $pkt;
    }
    if ($scenario eq 'id-mismatch') {
        my $bad_id = pack('n', $id ^ 0x55aa);
        my $pkt = $bad_id . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'no-question') {
        my $pkt = $id_raw . pack('n5', 0x8400, 0, 1, 0, 0);
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'query-mismatch') {
        my $spoofed_name = "mismatch-spoofed." . ($zone_apex ne '' ? $zone_apex : "anomaly.test");
        my $spoofed_qwire = encode_name($spoofed_name) . pack('nn', $qtype, $qclass);
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $spoofed_qwire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'multi-question') {
        my $sub_qwire = encode_name("sub." . $qname) . pack('nn', 28, 1);
        my $pkt = $id_raw . pack('n5', 0x8400, 2, 1, 0, 0);
        $pkt .= $question_wire . $sub_qwire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'opcode-unassigned') {
        my $pkt = $id_raw . pack('n5', 0x9c00, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario eq 'opcode-status') {
        my $pkt = $id_raw . pack('n5', 0x9400, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario eq 'opcode-notify') {
        my $pkt = $id_raw . pack('n5', 0xa400, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    
    # --------------------------------------------------------------------------
    # 2. Name Compression & Pointer Safety
    # --------------------------------------------------------------------------
    if ($scenario eq 'compression-loop') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\xc0\x0c" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'compression-indirect-loop') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\x03foo\xc0\x16" . pack('nn', 1, 1) . "\x03bar\xc0\x0c";
        return $pkt;
    }
    if ($scenario eq 'compression-forward-ptr') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\xc0\xff" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'compression-bad-bits') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\x45badlabel\x00" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'compression-misaligned') {
        # Pointer to offset 13 (inside the first label string 'compression-misaligned')
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= "\xc0\x0d" . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'ptr-chain-name-overflow') {
        # Pointer chain expanding domain name beyond 255-byte limit
        # 5 labels of 60 bytes chained together = 305 bytes expanded FQDN
        my $flags_val = 0x8400;
        my $rr1_prefix = pack('n', 0xc00c) . pack('nnN', 10, 1, 300); # NULL RR
        my $root_offset = 12 + length($question_wire) + length($rr1_prefix) + 2;

        my $rdata = '';
        my @label_offsets;
        for my $idx (1 .. 5) {
            my $curr_off = $root_offset + length($rdata);
            push @label_offsets, $curr_off;
            my $lstr = ("a" x 59) . $idx;
            $rdata .= pack('C', 60) . $lstr;
            if ($idx == 1) {
                $rdata .= "\x00"; # Label 1 ends with root
            } else {
                my $prev_off = $label_offsets[$idx - 2];
                $rdata .= pack('n', 0xC000 | $prev_off);
            }
        }
        my $rr1 = $rr1_prefix . pack('n', length($rdata)) . $rdata;

        # Answer 2: NAME points to Label 5, expanding to > 300 bytes
        my $last_label_off = $label_offsets[-1];
        my $rr2 = pack('n', 0xC000 | $last_label_off) . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);

        my $pkt = $id_raw . pack('n5', $flags_val, 1, 2, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $rr1;
        $pkt .= $rr2;
        return $pkt;
    }
    if ($scenario =~ /^(?:ptr-chain|compression-chain|ptr-hops)(?:-(\d+))?$/ || $scenario eq 'compression-deep-chain') {
        my $hops = 10;
        if ($scenario eq 'compression-deep-chain') {
            $hops = 60;
        } elsif (defined $1) {
            $hops = int($1);
        }
        $hops = 1 if $hops < 1;

        my $flags_val = 0x8400;
        my $rr1_prefix = pack('n', 0xc00c) . pack('nnN', 10, 1, 300);
        my $root_offset = 12 + length($question_wire) + length($rr1_prefix) + 2;

        my $max_hops = int((0x3FFF - $root_offset - 1) / 2) + 1;
        $hops = $max_hops if $hops > $max_hops;

        my $rdata = "\x00";
        my $last_target_offset = $root_offset;

        if ($hops > 1) {
            my $curr_ptr_offset = $root_offset + 1;
            for (my $i = 0; $i < $hops - 1; $i++) {
                my $target = ($i == 0) ? $root_offset : ($curr_ptr_offset - 2);
                $rdata .= pack('n', 0xC000 | $target);
                $last_target_offset = $curr_ptr_offset;
                $curr_ptr_offset += 2;
            }
        }

        my $rr1 = $rr1_prefix . pack('n', length($rdata)) . $rdata;
        my $rr2_name = pack('n', 0xC000 | $last_target_offset);
        my $rr2 = $rr2_name . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);

        my $desc = "Pointer chain: $hops hops successfully traversed to root (.)";
        my $add_rr = encode_txt_rr($qname, $desc, 300);

        my $pkt = $id_raw . pack('n5', $flags_val, 1, 2, 0, 1);
        $pkt .= $question_wire;
        $pkt .= $rr1;
        $pkt .= $rr2;
        $pkt .= $add_rr;
        return $pkt;
    }
    if ($scenario eq 'unclosed-label') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
        $pkt .= "\x05hello\x0aabc";
        return $pkt;
    }
    
    # --------------------------------------------------------------------------
    # Arbitrary Packet Size Generator: tcp-size-<bytes> / packet-size-<bytes>
    # Generates exact N bytes packet (from 1 byte to 65535+ bytes)
    # --------------------------------------------------------------------------
# --------------------------------------------------------------------------
    # Arbitrary Packet Size Generator: tcp-size-<bytes> / packet-size-<bytes>
    # --------------------------------------------------------------------------
    if ($scenario =~ /^(?:tcp-size|packet-size)-(\d+)$/) {
        my $target_size = int($1);
        $target_size = 1 if $target_size < 1;

        # 16-bit 境界ガード (TypeProgram IPC および DNS over TCP の絶対上限)
        $target_size = 65535 if $target_size > 65535;

        # 1. ヘッダー未満 (1 〜 11 バイト)
        if ($target_size < 12) {
            my $raw_hdr = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0);
            return substr($raw_hdr, 0, $target_size);
        }

        # 2. ヘッダー以上だが Question を含めると溢れる場合
        my $base_min = 12 + length($question_wire);
        if ($target_size < $base_min) {
            my $full = $id_raw . pack('n5', 0x8400, 1, 0, 0, 0) . $question_wire;
            return substr($full, 0, $target_size);
        }

        # 3. Question のみで Answer なし (QDCOUNT=1, ANCOUNT=0)
        if ($target_size == $base_min) {
            return $id_raw . pack('n5', 0x8400, 1, 0, 0, 0) . $question_wire;
        }

        # 4. Answer (NULL RR) で target_size ぴったりにパディング
        my $rr_prefix = pack('n', 0xc00c) . pack('nnN', 10, 1, 300);
        my $min_with_rr = $base_min + length($rr_prefix) + 2;

        if ($target_size < $min_with_rr) {
            my $partial_rr = $rr_prefix . pack('n', 0);
            my $full = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0) . $question_wire . $partial_rr;
            return substr($full, 0, $target_size);
        }

        my $rdlen = $target_size - $min_with_rr;
        my $rdata = "X" x $rdlen;

        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $rr_prefix . pack('n', $rdlen) . $rdata;

        return $pkt;
    }
    
    # --------------------------------------------------------------------------
    # 3. Label & Name Boundary Violations
    # --------------------------------------------------------------------------
    if ($scenario eq 'label-overflow' || $scenario eq 'label-64') {
        # Label length declared as 64 (0x40), exceeding RFC 1035 max of 63
        my $bad_name = pack('C', 64) . ("a" x 64) . "\x00";
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $bad_name . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'null-byte-in-label') {
        # Embedded 0x00 byte inside label (poison test for C-string functions)
        my $poison_label = "\x0bnull\x00byte\x00x" . encode_name($zone_apex);
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $poison_label . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'case-0x20-mismatch') {
        # Inverts ASCII casing in reflected Question section to test 0x20 verification
        my $raw_qname_wire = substr($req, 12, length($qname_wire));
        my $inverted_wire = $raw_qname_wire;
        my $pos = 0;
        my $wlen = length($inverted_wire);
        while ($pos < $wlen) {
            my $llen = ord(substr($inverted_wire, $pos, 1));
            last if $llen == 0 || ($llen & 0xC0) == 0xC0;
            $pos++;
            for (my $i = 0; $i < $llen && $pos < $wlen; $i++, $pos++) {
                my $c = substr($inverted_wire, $pos, 1);
                $c =~ tr/a-zA-Z/A-Za-z/;
                substr($inverted_wire, $pos, 1, $c);
            }
        }
        my $bad_question = $inverted_wire . pack('nn', $qtype, $qclass);
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $bad_question;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 4. Section Count & Record Semantics
    # --------------------------------------------------------------------------
    if ($scenario eq 'class-mismatch') {
        # QCLASS=IN (1), but Answer CLASS=3 (CH / Chaosnet)
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 3, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'meta-type-in-answer') {
        # Answer section contains Meta-QTYPE 255 (ANY)
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 255, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    # --------------------------------------------------------------------------
    # Genuine DNAME Loop (RFC 6672)
    # Returns 4 records (2x DNAME + 2x CNAME) with NOERROR to test client-side loop detection
    # --------------------------------------------------------------------------
    if ($scenario eq 'dname-loop' || $scenario =~ /^dname-[ab]$/) {
        # サーバー側はループを気にせず、何食わぬ顔で NOERROR (RCODE=0) を返す
        my $flags_val = 0x8400; # QR=1, AA=1, RCODE=0 (NOERROR)
        $flags_val |= 0x0100 if ($flags & 0x0100); # クエリの RD ビットを反映

        # 相互参照する2つの親ドメイン
        my $base1 = "dname1." . ($zone_apex ne '' ? $zone_apex : "anomaly.test");
        my $base2 = "dname2." . ($zone_apex ne '' ? $zone_apex : "anomaly.test");

        # サブドメイン名（1.dname-loop... で引かれたら '1'、単体なら 'loop'）
        my $sub = $dname_sublabel // 'loop';

        my $name1 = "$sub.$base1";
        my $name2 = "$sub.$base2";

        # 起点の決定
        my ($curr_base, $target_base, $curr_name, $target_name);
        if ($scenario eq 'dname-b' || $qname_clean =~ /\Q$base2\E$/i) {
            $curr_base   = $base2;
            $target_base = $base1;
            $curr_name   = $name2;
            $target_name = $name1;
        } else {
            $curr_base   = $base1;
            $target_base = $base2;
            $curr_name   = $name1;
            $target_name = $name2;
        }

        my $curr_base_wire   = encode_name($curr_base);
        my $target_base_wire = encode_name($target_base);
        # QNAME のワイヤフォーマットをそのまま第1 CNAME の所有名として利用
        my $curr_name_wire   = ($qname_clean eq $curr_name) ? $qname_wire : encode_name($curr_name);
        my $target_name_wire = encode_name($target_name);

        # ----------------------------------------------------------------------
        # BIND と同じ 4つの ANSWER レコード (DNAME 2つ + 合成 CNAME 2つ)
        # 1. curr_base   DNAME target_base
        # 2. curr_name   CNAME target_name (合成)
        # 3. target_base DNAME curr_base
        # 4. target_name CNAME curr_name   (合成 -> 2へループバック)
        # ----------------------------------------------------------------------
        my $answers = '';
        $answers .= $curr_base_wire   . pack('nnNn', 39, 1, 1800, length($target_base_wire)) . $target_base_wire;
        $answers .= $curr_name_wire   . pack('nnNn',  5, 1, 1800, length($target_name_wire)) . $target_name_wire;
        $answers .= $target_base_wire . pack('nnNn', 39, 1, 1800, length($curr_base_wire))   . $curr_base_wire;
        $answers .= $target_name_wire . pack('nnNn',  5, 1, 1800, length($curr_name_wire))   . $curr_name_wire;

        # QDCOUNT=1, ANCOUNT=4, NSCOUNT=0, ARCOUNT=0
        my $pkt = $id_raw . pack('n5', $flags_val, 1, 4, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $answers;
        return $pkt;
    }
    if ($scenario eq 'dname-overflow') {
        # Synthesized domain name exceeds 255 bytes limit -> returns YXDOMAIN (RFC 6672 §2.4)
        my $long_target = ("x" x 60) . "." . ("y" x 60) . "." . ("z" x 60) . "." . ("w" x 60) . ".test.";
        my $target_wire = encode_name($long_target);
        my $pkt = $id_raw . pack('n5', 0x8406, 1, 1, 0, 0); # RCODE=6 (YXDOMAIN)
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 39, 1, 300, length($target_wire)) . $target_wire;
        return $pkt;
    }
    if ($scenario eq 'nscount-underflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 3, 0);
        $pkt .= $question_wire;
        my $ns_target = encode_name("ns1." . ($zone_apex ne '' ? $zone_apex : "anomaly.test"));
        $pkt .= $qname_wire . pack('nnNn', 2, 1, 300, length($ns_target)) . $ns_target;
        return $pkt;
    }
    if ($scenario eq 'nscount-overflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 1, 0);
        $pkt .= $question_wire;
        my $ns1 = encode_name("ns1." . ($zone_apex ne '' ? $zone_apex : "anomaly.test"));
        my $ns2 = encode_name("ns2." . ($zone_apex ne '' ? $zone_apex : "anomaly.test"));
        $pkt .= $qname_wire . pack('nnNn', 2, 1, 300, length($ns1)) . $ns1;
        $pkt .= $qname_wire . pack('nnNn', 2, 1, 300, length($ns2)) . $ns2;
        return $pkt;
    }
    if ($scenario eq 'arcount-underflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 3);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= encode_txt_rr($qname, "arcount-underflow-additional", 300);
        return $pkt;
    }
    if ($scenario eq 'arcount-overflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 1);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= encode_txt_rr($qname, "additional-1", 300);
        $pkt .= encode_txt_rr($qname, "additional-2", 300);
        return $pkt;
    }
    if ($scenario eq 'zero-ttl') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 0, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'huge-ttl') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 0xFFFFFFFF, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'cname-loop') {
        my $target_name = "cname-loop-target." . ($zone_apex ne '' ? $zone_apex : "anomaly.test");
        my $target_wire = encode_name($target_name);
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 2, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 5, 1, 300, length($target_wire)) . $target_wire;
        $pkt .= $target_wire . pack('nnNn', 5, 1, 300, length($qname_wire)) . $qname_wire;
        return $pkt;
    }
    if ($scenario eq 'cname-with-data') {
        my $target_name = "cname-target." . ($zone_apex ne '' ? $zone_apex : "anomaly.test");
        my $target_wire = encode_name($target_name);
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 2, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 5, 1, 300, length($target_wire)) . $target_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 5. Transport & Buffer Oversize
    # --------------------------------------------------------------------------
    if ($scenario eq 'edns-bufsize-exceeded') {
        # Intentionally exceeds advertised buffer size by ~300 bytes without setting TC=1
        my $target_size = $client_bufsize + 300;
        $target_size = 1420 if $target_size < 1420;
        my $flags_val = 0x8400; # TC=0 intentionally
        my $rr_prefix = pack('n', 0xc00c) . pack('nnN', 10, 1, 300); # NULL RR
        my $base_len = 12 + length($question_wire) + length($rr_prefix) + 2;
        my $pad_len = $target_size - $base_len;
        $pad_len = 500 if $pad_len < 500;
        my $rdata = "X" x $pad_len;

        my $pkt = $id_raw . pack('n5', $flags_val, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $rr_prefix . pack('n', length($rdata)) . $rdata;
        return $pkt;
    }
    if ($scenario eq 'tcp-max-65535' || $scenario eq 'huge-tcp-65535') {
        # Generates exact maximum possible DNS message size: 65,535 bytes
        # When queried via UDP, KariDNS will automatically truncate (TC=1) and client falls back to TCP
        my $flags_val = 0x8400;
        my $rr_prefix = pack('n', 0xc00c) . pack('nnN', 10, 1, 300);
        my $base_len = 12 + length($question_wire) + length($rr_prefix) + 2;
        my $rdlen = 65535 - $base_len;
        $rdlen = 0 if $rdlen < 0;
        my $rdata = "\x00" x $rdlen;

        my $pkt = $id_raw . pack('n5', $flags_val, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $rr_prefix . pack('n', $rdlen) . $rdata;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 6. RDATA Truncation & Boundary Violations   
    # --------------------------------------------------------------------------
    if ($scenario eq 'rdata-short-a') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . "\xc0\x00";
        return $pkt;
    }
    if ($scenario eq 'rdata-short-aaaa') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 28, 1, 300, 16) . pack('C8', 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1);
        return $pkt;
    }
    if ($scenario eq 'rdata-soa-truncated') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 6, 1, 300, 30) . "\x02ns\x07example";
        return $pkt;
    }
    if ($scenario eq 'rdata-mx-truncated') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 15, 1, 300, 2) . pack('n', 10);
        return $pkt;
    }
    if ($scenario eq 'rdata-txt-len-mismatch') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 16, 1, 300, 10) . pack('C', 100) . "123456789";
        return $pkt;
    }
    if ($scenario eq 'rdata-svcb-overflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 64, 1, 300, 8) . pack('n', 1) . "\x14target";
        return $pkt;
    }
    if ($scenario eq 'rdata-opt-truncated') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 1);
        $pkt .= $question_wire;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, 8) . pack('nn', 10, 16) . "1234";
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 7. EDNS0 (RFC 6891) Boundary & Violations
    # --------------------------------------------------------------------------
    if ($scenario eq 'multi-opt') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 2);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, 0);
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, 0);
        return $pkt;
    }
    if ($scenario eq 'opt-in-answer') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 2, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, 0);
        return $pkt;
    }
    if ($scenario eq 'opt-badvers') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 1);
        $pkt .= $question_wire;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0x00010000, 0);
        return $pkt;
    }
    if ($scenario eq 'opt-unknown-option') {
        my $unknown_opt = pack('nn', 65001, 4) . "\xde\xad\xbe\xef";
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 1);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($unknown_opt)) . $unknown_opt;
        return $pkt;
    }
    if ($scenario eq 'opt-option-len-overflow') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 0, 0, 1);
        $pkt .= $question_wire;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, 6) . pack('nn', 15, 20) . "12";
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 8. Protocol & Security Flags (Cookies, Truncation)
    # --------------------------------------------------------------------------
    if ($scenario eq 'cookie-badcookie') {
        my $srv_cookie = "\x11\x22\x33\x44\x55\x66\x77\x88";
        my $cl_c = $client_cookie // "\x01\x02\x03\x04\x05\x06\x07\x08";
        if (defined $server_cookie && $server_cookie eq $srv_cookie) {
            my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 1);
            $pkt .= $question_wire;
            $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            my $copt = pack('nn', 10, 16) . $cl_c . $srv_cookie;
            $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($copt)) . $copt;
            return $pkt;
        } else {
            my $pkt = $id_raw . pack('n5', 0x8407, 1, 0, 0, 1);
            $pkt .= $question_wire;
            my $copt = pack('nn', 10, 16) . $cl_c . $srv_cookie;
            $pkt .= "\x00" . pack('nnNn', 41, 4096, 0x01000000, length($copt)) . $copt;
            return $pkt;
        }
    }
    if ($scenario eq 'truncated-tc') {
        my $pkt = $id_raw . pack('n5', 0x8600, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario =~ /^flags?-(.*)$/) {
        my $spec = lc($1);
        my $flag_val = 0x8400;
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
            $flag_val = 0x8500;
            $desc .= "RD=1 (Recursion Desired) unsolicitedly set in response";
        } elsif ($spec eq 'ra') {
            $flag_val = 0x8480;
            $desc .= "RA=1 (Recursion Available) unsolicitedly set in response";
        } elsif ($spec eq 'ad') {
            $flag_val = 0x8420;
            $desc .= "AD=1 (Authentic Data) set in response";
        } elsif ($spec eq 'cd') {
            $flag_val = 0x8410;
            $desc .= "CD=1 (Checking Disabled) set in response";
        } elsif ($spec eq 'z' || $spec eq 'mbz') {
            $flag_val = 0x8440;
            $desc .= "Reserved Z-bit (MBZ 0x0040) set to 1 in response";
        } elsif ($spec eq 'no-aa' || $spec eq 'aa0') {
            $flag_val = 0x8000;
            $desc .= "AA=0 (Authoritative Answer bit cleared) in response";
        } elsif ($spec eq 'no-qr' || $spec eq 'qr0') {
            $flag_val = 0x0400;
            $desc .= "QR=0 (Query/Response bit cleared, response masquerade) in packet";
        } elsif ($spec eq 'tc' || $spec eq 'tc-record') {
            $flag_val = 0x8600;
            $desc .= "TC=1 (Truncation) with answer records attached";
        } elsif ($spec eq 'rd-ra') {
            $flag_val = 0x8580;
            $desc .= "Both RD=1 and RA=1 unsolicitedly set in response";
        } elsif ($spec eq 'ad-cd') {
            $flag_val = 0x8430;
            $desc .= "Both AD=1 and CD=1 set in response";
        } elsif ($spec eq 'all') {
            $flag_val = 0x85F0;
            $desc .= "ALL header flags set (QR=1, AA=1, RD=1, RA=1, AD=1, CD=1, Z=1 [0x85F0])";
        } elsif ($spec eq 'all-tc') {
            $flag_val = 0x87F0;
            $desc .= "ALL header flags set including TC (QR=1, AA=1, TC=1, RD=1, RA=1, AD=1, CD=1, Z=1 [0x87F0])";
        } elsif ($spec eq 'do') {
            $flag_val = 0x8400;
            $edns_do = 1;
            $desc .= "EDNS0 DO=1 (DNSSEC OK) flag set in OPT RR";
        } elsif ($spec eq 'co') {
            $flag_val = 0x8400;
            $edns_co = 1;
            $desc .= "EDNS0 Compact Answers OK flag set in OPT RR";
        } elsif ($spec eq 'do-co' || $spec eq 'do+co') {
            $flag_val = 0x8400;
            $edns_do = 1;
            $edns_co = 1;
            $desc .= "Both EDNS0 DO=1 and CO=1 flags set in OPT RR";
        } elsif ($spec eq 'all-do-co' || $spec eq 'all+do+co') {
            $flag_val = 0x85F0;
            $edns_do = 1;
            $edns_co = 1;
            $desc .= "ALL header flags (0x85F0) and both EDNS0 DO=1 and CO=1 flags set in OPT RR";
        } elsif ($spec eq 'all-do' || $spec eq 'all+do') {
            $flag_val = 0x85F0;
            $edns_do = 1;
            $desc .= "ALL header flags (0x85F0) and EDNS0 DO=1 flag set in OPT RR";
        } elsif ($spec eq 'all-co' || $spec eq 'all+co') {
            $flag_val = 0x85F0;
            $edns_co = 1;
            $desc .= "ALL header flags (0x85F0) and EDNS0 CO=1 flag set in OPT RR";
        } elsif ($spec eq 'all-tc-do-co' || $spec eq 'all-tc+do+co') {
            $flag_val = 0x87F0;
            $edns_do = 1;
            $edns_co = 1;
            $desc .= "ALL header flags including TC (0x87F0) and both EDNS0 DO=1 and CO=1 set in OPT RR";
        } elsif ($spec eq 'none') {
            $flag_val = 0x0000;
            $desc .= "No flags set (0x0000)";
        } else {
            my $norm = $spec;
            $norm =~ s/[+_]/-/g;

            $flag_val = 0x8400;
            if ($norm =~ /\ball-tc\b/) {
                $flag_val = 0x87F0;
            } elsif ($norm =~ /\ball\b/) {
                $flag_val = 0x85F0;
            } else {
                $flag_val |= 0x0100 if $norm =~ /\brd\b/;
                $flag_val |= 0x0080 if $norm =~ /\bra\b/;
                $flag_val |= 0x0020 if $norm =~ /\bad\b/;
                $flag_val |= 0x0010 if $norm =~ /\bcd\b/;
                $flag_val |= 0x0040 if $norm =~ /\b(?:z|mbz)\b/;
                $flag_val |= 0x0200 if $norm =~ /\btc(?:-record)?\b/;
                $flag_val &= ~0x0400 if $norm =~ /\b(?:no-aa|aa0)\b/;
                $flag_val &= ~0x8000 if $norm =~ /\b(?:no-qr|qr0)\b/;
            }

            $edns_do = 1 if $norm =~ /\bdo\b/;
            $edns_co = 1 if $norm =~ /\bco\b/;

            my @parts;
            push @parts, sprintf("header 0x%04X", $flag_val);
            push @parts, "EDNS0 DO=1" if $edns_do;
            push @parts, "EDNS0 CO=1" if $edns_co;
            $desc .= sprintf("Combined flags (%s) [%s]", join(", ", @parts), $spec);
        }

        my $answers = '';
        my $ancount = 0;
        my $arcount = 0;
        my $additionals = '';

        if ($qtype == 16) {
            $answers .= encode_txt_rr($qname, $desc, 300);
            $ancount++;
        } elsif ($qtype == 255) {
            $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            $answers .= encode_txt_rr($qname, $desc, 300);
            $ancount += 2;
        } else {
            $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            $ancount++;
            $additionals .= encode_txt_rr($qname, $desc, 300);
            $arcount++;
        }

        if ($edns_do || $edns_co) {
            my $ext_flags = 0;
            $ext_flags |= 0x8000 if $edns_do;
            $ext_flags |= 0x4000 if $edns_co;
            $additionals .= "\x00" . pack('nnNn', 41, 4096, $ext_flags, 0);
            $arcount++;
        }

        my $pkt = $id_raw . pack('n5', $flag_val, 1, $ancount, 0, $arcount);
        $pkt .= $question_wire;
        $pkt .= $answers;
        $pkt .= $additionals;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 9. RFC Standard & Extended RCODEs
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
                $answers .= encode_txt_rr($qname, $desc, 300);
                $ancount++;
            } elsif ($qtype == 255) {
                $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
                $answers .= encode_txt_rr($qname, $desc, 300);
                $ancount += 2;
            } else {
                if ($rcode_val == 0) {
                    $answers .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
                    $ancount++;
                }
                $additionals .= encode_txt_rr($qname, $desc, 300);
                $arcount++;
            }

            my $client_has_edns = (defined($client_cookie) || $req =~ /\x00\x00\x29/s);
            if ($ext_rc > 0 || $client_has_edns) {
                my $ttl_ext = ($ext_rc << 24);
                my $opt_rdata = '';
                if ($rcode_val == 23) {
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
    # 10. Extended DNS Errors (EDE, RFC 8914)
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
    if ($scenario eq 'what-is-my-ip') {
        my $pkt = $id_raw . pack('n5', 0x8400, 1, 1, 0, 0);
        my @ip_adr = split(/\./, $client_ip);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', $ip_adr[0], $ip_adr[1], $ip_adr[2], $ip_adr[3]);
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
