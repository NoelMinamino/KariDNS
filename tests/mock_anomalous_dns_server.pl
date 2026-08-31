#!/usr/bin/perl
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
sub run_plugin_mode {
    my ($v) = @_;
    $| = 1; # Autoflush stdout
    binmode(STDIN,  ":raw");
    binmode(STDOUT, ":raw");

    while (my $line = <STDIN>) {
        chomp($line);
        my ($cmd, $proto, $client_ip) = split(/\s+/, $line);
        next unless $cmd && $cmd eq "QUERY";

        my $len_buf;
        my $n = read(STDIN, $len_buf, 2);
        last unless defined($n) && $n == 2;
        my $req_len = unpack("n", $len_buf);

        my $req = "";
        my $got = 0;
        while ($got < $req_len) {
            my $buf;
            my $r = read(STDIN, $buf, $req_len - $got);
            last unless defined($r) && $r > 0;
            $req .= $buf;
            $got += $r;
        }
        last if length($req) < $req_len;

        my $is_tcp = (defined $proto && lc($proto) eq 'tcp') ? 1 : 0;
        my $resp = process_query_packet($req, $is_tcp, $client_ip // '127.0.0.1');

        my $resp_len = length($resp // "");
        print STDOUT pack("n", $resp_len);
        if ($resp_len > 0) {
            print STDOUT $resp;
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
    return "\x00" if !defined $name || $name eq '.' || $name eq '';
    my $wire = '';
    for my $label (split /\./, $name) {
        $wire .= pack('C', length($label)) . $label;
    }
    $wire .= "\x00";
    return $wire;
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

    my $qname_lc = lc($qname);
    my ($scenario) = ($qname_lc =~ /^([^.]+)/);
    $scenario //= 'normal';

    my $id_raw = pack('n', $id);
    my $qname_wire = encode_name($qname);
    my $question_wire = $qname_wire . pack('nn', $qtype, $qclass);

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
        return $id_raw . pack('n5', 0x8180, 0, 0, 0, 0);
    }
    if ($scenario eq 'short-header') {
        # Only 6 bytes (truncated header)
        return $id_raw . pack('n2', 0x8180, 1);
    }
    if ($scenario eq 'trailing-garbage') {
        # Normal Answer + 24 extra garbage bytes
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        $pkt .= "EXTRA_TRAILING_GARBAGE_BYTES";
        return $pkt;
    }
    if ($scenario eq 'qdcount-mismatch') {
        # Header says QDCOUNT=2, but only 1 question present
        my $pkt = $id_raw . pack('n5', 0x8180, 2, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }
    if ($scenario eq 'ancount-underflow') {
        # Header says ANCOUNT=5, but only 1 record present
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 5, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
        return $pkt;
    }
    if ($scenario eq 'ancount-overflow') {
        # Header says ANCOUNT=1, but 2 records present
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
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
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 0, 0, 0);
        $pkt .= "\xc0\x0c" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'compression-forward-ptr') {
        # Pointer to offset 0x3000 (far beyond packet length)
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 0, 0, 0);
        $pkt .= "\xc0\xff" . pack('nn', 1, 1);
        return $pkt;
    }
    if ($scenario eq 'unclosed-label') {
        # Unterminated label without 0x00
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 0, 0, 0);
        $pkt .= "\x05hello\x0aabc";
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 3. RDATA Truncation & Boundary Violations
    # --------------------------------------------------------------------------
    if ($scenario eq 'rdata-short-a') {
        # TYPE=A, RDLENGTH=4, but only 2 bytes provided
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . "\xc0\x00";
        return $pkt;
    }
    if ($scenario eq 'rdata-short-aaaa') {
        # TYPE=AAAA, RDLENGTH=16, but only 8 bytes provided
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 28, 1, 300, 16) . pack('C8', 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1);
        return $pkt;
    }
    if ($scenario eq 'rdata-soa-truncated') {
        # SOA record ends abruptly
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 6, 1, 300, 30) . "\x02ns\x07example";
        return $pkt;
    }
    if ($scenario eq 'rdata-mx-truncated') {
        # MX with preference only
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 15, 1, 300, 2) . pack('n', 10);
        return $pkt;
    }
    if ($scenario eq 'rdata-txt-len-mismatch') {
        # TXT length declares 100, but RDLENGTH is 10
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 16, 1, 300, 10) . pack('C', 100) . "123456789";
        return $pkt;
    }
    if ($scenario eq 'rdata-svcb-overflow') {
        # SVCB TargetName length exceeds RDLENGTH
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
        $pkt .= $question_wire;
        $pkt .= $qname_wire . pack('nnNn', 64, 1, 300, 8) . pack('n', 1) . "\x14target";
        return $pkt;
    }
    if ($scenario eq 'rdata-opt-truncated') {
        # OPT RR with truncated option
        my $pkt = $id_raw . pack('n5', 0x8180, 1, 0, 0, 1);
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
            my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 1);
            $pkt .= $question_wire;
            $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
            my $copt = pack('nn', 10, 16) . $cl_c . $srv_cookie;
            $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($copt)) . $copt;
            return $pkt;
        } else {
            # First query without valid server cookie: return BADCOOKIE (RCODE 23)
            my $pkt = $id_raw . pack('n5', 0x8187, 1, 0, 0, 1);
            $pkt .= $question_wire;
            my $copt = pack('nn', 10, 16) . $cl_c . $srv_cookie;
            $pkt .= "\x00" . pack('nnNn', 41, 4096, 0x01000000, length($copt)) . $copt;
            return $pkt;
        }
    }
    if ($scenario eq 'truncated-tc') {
        # TC=1 (Truncated) response
        my $pkt = $id_raw . pack('n5', 0x8380, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 5. RFC Standard & Extended RCODEs
    # --------------------------------------------------------------------------
    my %RCODES = (
        'rcode-formerr'   => 1,
        'rcode-servfail'  => 2,
        'rcode-nxdomain'  => 3,
        'rcode-notimp'    => 4,
        'rcode-refused'   => 5,
        'rcode-yxdomain'  => 6,
        'rcode-yxrrset'   => 7,
        'rcode-nxrrset'   => 8,
        'rcode-notauth'   => 9,
        'rcode-notzone'   => 10,
    );
    if (exists $RCODES{$scenario}) {
        my $rc = $RCODES{$scenario};
        my $flags_val = 0x8180 | ($rc & 0x0F);
        my $pkt = $id_raw . pack('n5', $flags_val, 1, 0, 0, 0);
        $pkt .= $question_wire;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # 6. Extended DNS Errors (EDE, RFC 8914)
    # --------------------------------------------------------------------------
    if ($scenario eq 'ede-prohibited') {
        my $pkt = $id_raw . pack('n5', 0x8185, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_text = "Query blocked by test policy";
        my $ede_opt = pack('nnn', 15, length($ede_text) + 2, 18) . $ede_text;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opt)) . $ede_opt;
        return $pkt;
    }
    if ($scenario eq 'ede-long-text') {
        my $pkt = $id_raw . pack('n5', 0x8182, 1, 0, 0, 1);
        $pkt .= $question_wire;
        my $ede_text = "ExtendedErrorDescription:" . ("A" x 280);
        my $ede_opt = pack('nnn', 15, length($ede_text) + 2, 0) . $ede_text;
        $pkt .= "\x00" . pack('nnNn', 41, 4096, 0, length($ede_opt)) . $ede_opt;
        return $pkt;
    }

    # --------------------------------------------------------------------------
    # Default: Normal NOERROR Answer
    # --------------------------------------------------------------------------
    my $pkt = $id_raw . pack('n5', 0x8180, 1, 1, 0, 0);
    $pkt .= $question_wire;
    $pkt .= $qname_wire . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
    return $pkt;
}
