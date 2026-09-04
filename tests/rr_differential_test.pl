#!/usr/bin/perl
# ==============================================================================
# rr_differential_test.pl
#
# Structured RR Differential & Semantic Oracle Test Suite for KariDNS dag(1)
#
# Validates that multi-field Resource Records (NAPTR, SRV, SOA, CAA, MX)
# have their wire fields correctly parsed, mapped, and printed in the exact
# specification order in both standard output and +yaml structured output.
#
# Specifically guards against silent transposition bugs (e.g. NAPTR order vs pref
# where both are uint16_t, so swapping offsets produces valid formatting but
# completely erroneous values without any crashes).
# ==============================================================================

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my $dag = "./dag";
my $port = 0; # Auto-bind to ephemeral port
my $iterations = 20;
my $verbose = 0;

GetOptions(
    'dag=s'        => \$dag,
    'port=i'       => \$port,
    'iterations=i' => \$iterations,
    'verbose|v'    => \$verbose,
    'help|h'       => sub {
        print "Usage: $0 [--dag <path>] [--port <port>] [--iterations <num>] [-v]\n";
        exit 0;
    }
);

die "Error: dag binary '$dag' not found or not executable\n" unless -x $dag;

# 1. Setup mock authoritative DNS server on UDP
my $sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'udp',
) or die "Cannot bind UDP socket: $!\n";

my $server_port = $sock->sockport();
print "[*] RR Differential Mock Server listening on 127.0.0.1:$server_port\n" if $verbose;

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

sub decode_qname {
    my ($pkt, $offset) = @_;
    my $name = '';
    while ($offset < length($pkt)) {
        my $len = ord(substr($pkt, $offset, 1));
        if ($len == 0) { $offset++; last; }
        if (($len & 0xC0) == 0xC0) {
            my $ptr = unpack('n', substr($pkt, $offset, 2)) & 0x3FFF;
            $offset += 2;
            my ($sub_name) = decode_qname($pkt, $ptr);
            $name .= ($name eq '' ? '' : '.') . $sub_name;
            return ($name, $offset);
        } else {
            $offset++;
            my $label = substr($pkt, $offset, $len);
            $name .= ($name eq '' ? '' : '.') . $label;
            $offset += $len;
        }
    }
    return ($name, $offset);
}

# Active scenario state for incoming queries
my $current_rr_type = 0;
my %expected_fields = ();
my $current_ans_rdata = "";
my $current_ans_qname = "";

sub handle_one_query {
    my ($buf) = @_;
    return unless length($buf) >= 12;
    my ($id, $flags, $qdcount) = unpack('n3', substr($buf, 0, 6));
    my $offset = 12;
    my ($qname, $nxt) = decode_qname($buf, $offset);
    return unless $nxt + 4 <= length($buf);
    my ($qtype, $qclass) = unpack('nn', substr($buf, $nxt, 4));

    my $hdr = pack('n6', $id, 0x8180, 1, 1, 0, 0); # NOERROR, QR=1, AA=1, ANCOUNT=1
    my $question = encode_name($qname) . pack('nn', $qtype, $qclass);
    my $answer = encode_name($qname) . pack('nnNn', $current_rr_type, 1, 300, length($current_ans_rdata)) . $current_ans_rdata;

    return $hdr . $question . $answer;
}

# Run query in background and serve mock response
sub query_and_capture {
    my ($qname, $qtype_str, $yaml_mode) = @_;
    my @cmd = ($dag, $qname, $qtype_str, "\@127.0.0.1", "-p", $server_port, "+tries=1", "+timeout=2");
    push @cmd, "+yaml" if $yaml_mode;

    # Fork child to run dag command
    my $pid = open(my $dag_out, "-|", @cmd) or die "Cannot fork dag: $!\n";

    # Serve the DNS query in parent
    my $select = IO::Select->new($sock);
    if ($select->can_read(3)) {
        my $buf;
        my $peer = $sock->recv($buf, 4096);
        if ($peer) {
            my $resp = handle_one_query($buf);
            $sock->send($resp, 0, $peer) if $resp;
        }
    }

    my $output = do { local $/; <$dag_out> };
    close $dag_out;
    waitpid($pid, 0);

    return $output // "";
}

my $total_checks = 0;
my $passed_checks = 0;

print "========================================================\n";
print "Starting Structured RR Differential & Semantic Oracle Test\n";
print "Iterations: $iterations | dag: $dag | port: $server_port\n";
print "========================================================\n";

for my $iter (1 .. $iterations) {
    print "Iteration $iter/$iterations...\n" if $verbose;

    # --------------------------------------------------------------------------
    # 1. NAPTR (TYPE 35): Order vs Preference distinction
    # --------------------------------------------------------------------------
    {
        my $order = int(rand(65535));
        my $pref  = int(rand(65535));
        while ($pref == $order) { $pref = int(rand(65535)); } # Ensure distinct values
        my $flags = "S";
        my $services = "SIP+D2U";
        my $regexp = "";
        my $repl = "sip" . int(rand(1000)) . ".example.com";

        $current_rr_type = 35;
        $current_ans_qname = "naptr$iter.example.com";
        $current_ans_rdata = pack('nn', $order, $pref) .
                             pack('C', length($flags)) . $flags .
                             pack('C', length($services)) . $services .
                             pack('C', length($regexp)) . $regexp .
                             encode_name($repl);

        # Standard display test
        $total_checks++;
        my $std_out = query_and_capture($current_ans_qname, "NAPTR", 0);
        if ($std_out =~ /NAPTR\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+([^\s\n;]+)/) {
            my ($got_order, $got_pref, $got_flags, $got_svc, $got_reg, $got_repl) =
                (int($1), int($2), $3, $4, $5, $6);
            $got_repl =~ s/\.$//;
            if ($got_order == $order && $got_pref == $pref &&
                $got_flags eq $flags && $got_svc eq $services && $got_repl eq $repl) {
                $passed_checks++;
            } else {
                die "[-] FAIL: NAPTR standard mismatch: expected order=$order pref=$pref, got order=$got_order pref=$got_pref\nOutput:\n$std_out\n";
            }
        } else {
            die "[-] FAIL: NAPTR pattern match failed in standard output:\n$std_out\n";
        }

        # YAML display test
        $total_checks++;
        my $yaml_out = query_and_capture($current_ans_qname, "NAPTR", 1);
        if ($yaml_out =~ /NAPTR\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+([^\s\n';]+)/) {
            my ($got_order, $got_pref) = (int($1), int($2));
            if ($got_order == $order && $got_pref == $pref) {
                $passed_checks++;
            } else {
                die "[-] FAIL: NAPTR YAML mismatch: expected order=$order pref=$pref, got order=$got_order pref=$got_pref\nOutput:\n$yaml_out\n";
            }
        } else {
            die "[-] FAIL: NAPTR pattern match failed in YAML output:\n$yaml_out\n";
        }
    }

    # --------------------------------------------------------------------------
    # 2. SRV (TYPE 33): Priority / Weight / Port distinction
    # --------------------------------------------------------------------------
    {
        my $prio   = int(rand(65535));
        my $weight = int(rand(65535));
        my $port_v = int(rand(65535));
        while ($weight == $prio) { $weight = int(rand(65535)); }
        while ($port_v == $prio || $port_v == $weight) { $port_v = int(rand(65535)); }
        my $target = "srv" . int(rand(1000)) . ".example.org";

        $current_rr_type = 33;
        $current_ans_qname = "srv$iter.example.com";
        $current_ans_rdata = pack('nnn', $prio, $weight, $port_v) . encode_name($target);

        $total_checks++;
        my $std_out = query_and_capture($current_ans_qname, "SRV", 0);
        if ($std_out =~ /SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+([^\s\n;]+)/) {
            my ($got_prio, $got_weight, $got_port, $got_tgt) =
                (int($1), int($2), int($3), $4);
            $got_tgt =~ s/\.$//;
            if ($got_prio == $prio && $got_weight == $weight && $got_port == $port_v && $got_tgt eq $target) {
                $passed_checks++;
            } else {
                die "[-] FAIL: SRV standard mismatch: expected ($prio, $weight, $port_v), got ($got_prio, $got_weight, $got_port)\n";
            }
        } else {
            die "[-] FAIL: SRV pattern match failed in standard output:\n$std_out\n";
        }

        $total_checks++;
        my $yaml_out = query_and_capture($current_ans_qname, "SRV", 1);
        if ($yaml_out =~ /SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+([^\s\n';]+)/) {
            my ($got_prio, $got_weight, $got_port) = (int($1), int($2), int($3));
            if ($got_prio == $prio && $got_weight == $weight && $got_port == $port_v) {
                $passed_checks++;
            } else {
                die "[-] FAIL: SRV YAML mismatch: expected ($prio, $weight, $port_v), got ($got_prio, $got_weight, $got_port)\n";
            }
        } else {
            die "[-] FAIL: SRV pattern match failed in YAML output:\n$yaml_out\n";
        }
    }

    # --------------------------------------------------------------------------
    # 3. SOA (TYPE 6): 5-numeric field sequence check
    # --------------------------------------------------------------------------
    {
        my $serial  = 2026000000 + int(rand(99999));
        my $refresh = 1000 + int(rand(5000));
        my $retry   = 500 + int(rand(500));
        my $expire  = 50000 + int(rand(50000));
        my $minimum = 100 + int(rand(400));

        my $mname = "ns" . int(rand(100)) . ".example.net";
        my $rname = "admin" . int(rand(100)) . ".example.net";

        $current_rr_type = 6;
        $current_ans_qname = "soa$iter.example.com";
        $current_ans_rdata = encode_name($mname) . encode_name($rname) .
                             pack('NNNNN', $serial, $refresh, $retry, $expire, $minimum);

        $total_checks++;
        my $std_out = query_and_capture($current_ans_qname, "SOA", 0);
        # dag standard SOA outputs multi-line: serial, refresh, retry, expire, minimum with comments
        if ($std_out =~ /(\d+)\s*;\s*serial[\s\S]*?(\d+)\s*;\s*refresh[\s\S]*?(\d+)\s*;\s*retry[\s\S]*?(\d+)\s*;\s*expire[\s\S]*?(\d+)\s*;\s*minimum/) {
            my ($g_s, $g_ref, $g_ret, $g_exp, $g_min) = (int($1), int($2), int($3), int($4), int($5));
            if ($g_s == $serial && $g_ref == $refresh && $g_ret == $retry && $g_exp == $expire && $g_min == $minimum) {
                $passed_checks++;
            } else {
                die "[-] FAIL: SOA standard mismatch:\nExpected: ($serial, $refresh, $retry, $expire, $minimum)\nGot: ($g_s, $g_ref, $g_ret, $g_exp, $g_min)\n";
            }
        } elsif ($std_out =~ /SOA\s+\S+\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/) {
            my ($g_s, $g_ref, $g_ret, $g_exp, $g_min) = (int($1), int($2), int($3), int($4), int($5));
            if ($g_s == $serial && $g_ref == $refresh && $g_ret == $retry && $g_exp == $expire && $g_min == $minimum) {
                $passed_checks++;
            } else {
                die "[-] FAIL: SOA standard single-line mismatch: ($g_s, $g_ref, $g_ret, $g_exp, $g_min)\n";
            }
        } else {
            die "[-] FAIL: SOA pattern match failed in standard output:\n$std_out\n";
        }

        # YAML SOA format
        $total_checks++;
        my $yaml_out = query_and_capture($current_ans_qname, "SOA", 1);
        if ($yaml_out =~ /SOA\s+\S+\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/) {
            my ($g_s, $g_ref, $g_ret, $g_exp, $g_min) = (int($1), int($2), int($3), int($4), int($5));
            if ($g_s == $serial && $g_ref == $refresh && $g_ret == $retry && $g_exp == $expire && $g_min == $minimum) {
                $passed_checks++;
            } else {
                die "[-] FAIL: SOA YAML mismatch: ($g_s, $g_ref, $g_ret, $g_exp, $g_min)\n";
            }
        } else {
            die "[-] FAIL: SOA pattern match failed in YAML output:\n$yaml_out\n";
        }
    }

    # --------------------------------------------------------------------------
    # 4. CAA (TYPE 257): Flags / Tag / Value
    # --------------------------------------------------------------------------
    {
        my $flags = (int(rand(2)) == 0) ? 0 : 128; # Critical bit
        my @tags = ("issue", "issuewild", "iodef");
        my $tag = $tags[int(rand(scalar @tags))];
        my $val = "ca" . int(rand(1000)) . ".example.org";

        $current_rr_type = 257;
        $current_ans_qname = "caa$iter.example.com";
        $current_ans_rdata = pack('CC', $flags, length($tag)) . $tag . $val;

        $total_checks++;
        my $std_out = query_and_capture($current_ans_qname, "CAA", 0);
        if ($std_out =~ /CAA\s+(\d+)\s+([a-z]+)\s+"([^"]*)"/) {
            my ($g_flags, $g_tag, $g_val) = (int($1), $2, $3);
            if ($g_flags == $flags && $g_tag eq $tag && $g_val eq $val) {
                $passed_checks++;
            } else {
                die "[-] FAIL: CAA standard mismatch: expected ($flags, $tag, $val), got ($g_flags, $g_tag, $g_val)\n";
            }
        } else {
            die "[-] FAIL: CAA pattern match failed in standard output:\n$std_out\n";
        }

        $total_checks++;
        my $yaml_out = query_and_capture($current_ans_qname, "CAA", 1);
        if ($yaml_out =~ /CAA\s+(\d+)\s+([a-z]+)\s+"([^"]*)"/) {
            my ($g_flags, $g_tag, $g_val) = (int($1), $2, $3);
            if ($g_flags == $flags && $g_tag eq $tag && $g_val eq $val) {
                $passed_checks++;
            } else {
                die "[-] FAIL: CAA YAML mismatch: expected ($flags, $tag, $val), got ($g_flags, $g_tag, $g_val)\n";
            }
        } else {
            die "[-] FAIL: CAA pattern match failed in YAML output:\n$yaml_out\n";
        }
    }

    # --------------------------------------------------------------------------
    # 5. MX (TYPE 15): Preference / Exchange
    # --------------------------------------------------------------------------
    {
        my $pref = 1 + int(rand(65534));
        my $mx = "mail" . int(rand(1000)) . ".example.net";

        $current_rr_type = 15;
        $current_ans_qname = "mx$iter.example.com";
        $current_ans_rdata = pack('n', $pref) . encode_name($mx);

        $total_checks++;
        my $std_out = query_and_capture($current_ans_qname, "MX", 0);
        if ($std_out =~ /MX\s+(\d+)\s+([^\s\n;]+)/) {
            my ($g_pref, $g_mx) = (int($1), $2);
            $g_mx =~ s/\.$//;
            if ($g_pref == $pref && $g_mx eq $mx) {
                $passed_checks++;
            } else {
                die "[-] FAIL: MX standard mismatch: expected ($pref, $mx), got ($g_pref, $g_mx)\n";
            }
        } else {
            die "[-] FAIL: MX pattern match failed in standard output:\n$std_out\n";
        }

        $total_checks++;
        my $yaml_out = query_and_capture($current_ans_qname, "MX", 1);
        if ($yaml_out =~ /MX\s+(\d+)\s+([^\s\n';]+)/) {
            my ($g_pref, $g_mx) = (int($1), $2);
            $g_mx =~ s/\.$//;
            if ($g_pref == $pref && $g_mx eq $mx) {
                $passed_checks++;
            } else {
                die "[-] FAIL: MX YAML mismatch: expected ($pref, $mx), got ($g_pref, $g_mx)\n";
            }
        } else {
            die "[-] FAIL: MX pattern match failed in YAML output:\n$yaml_out\n";
        }
    }
}

close $sock;

print "[+] Total assertions executed: $total_checks\n";
print "[+] All assertions passed:     $passed_checks\n";
print "ALL RR DIFFERENTIAL TESTS PASSED\n";
exit 0;
