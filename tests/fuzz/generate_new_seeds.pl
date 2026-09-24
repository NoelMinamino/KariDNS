#!/usr/bin/perl
use strict;
use warnings;
use File::Path qw(make_path);

my $base = "tests/fuzz";

# ------------------------------------------------------------------------------
# 1. corpus_fuzz_dag_chunked_http
# ------------------------------------------------------------------------------
my $dir_chunked = "$base/corpus_fuzz_dag_chunked_http";
make_path($dir_chunked);

{
    open my $fh, '>:raw', "$dir_chunked/seed_chunked_basic.raw" or die $!;
    my $crlf = "\r\n";
    print $fh "HTTP/1.1 200 OK${crlf}" .
              "Content-Type: application/dns-message${crlf}" .
              "Transfer-Encoding: chunked${crlf}${crlf}" .
              "10${crlf}0123456789abcdef${crlf}" .
              "0${crlf}${crlf}";
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_chunked/seed_chunked_extensions.raw" or die $!;
    my $crlf = "\r\n";
    print $fh "HTTP/1.1 200 OK${crlf}" .
              "Transfer-Encoding: chunked${crlf}${crlf}" .
              "05;foo=bar${crlf}12345${crlf}" .
              "0${crlf}${crlf}";
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_chunked/seed_content_length.raw" or die $!;
    my $crlf = "\r\n";
    my $dns_hdr = pack('n6', 0x1234, 0x8180, 1, 0, 0, 0);
    print $fh "HTTP/1.1 200 OK${crlf}" .
              "Content-Type: application/dns-message${crlf}" .
              "Content-Length: " . length($dns_hdr) . "${crlf}${crlf}" .
              $dns_hdr;
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_chunked/seed_chunked_trailer.raw" or die $!;
    my $crlf = "\r\n";
    print $fh "HTTP/1.1 200 OK${crlf}" .
              "Transfer-Encoding: chunked${crlf}${crlf}" .
              "04${crlf}test${crlf}" .
              "0${crlf}" .
              "X-Trailer: test${crlf}${crlf}";
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_chunked/seed_chunked_overflow_regression.raw" or die $!;
    # ASan heap-buffer-overflow regression seed (integer overflow in chunk-size line)
    my $crlf = "\r\n";
    print $fh "HTTP/1.1 200CHTTP/ 200\n" .
              "Transfer-Encoding:chunkedontffffffffffffffffffffffffffffffffff${crlf}${crlf}" .
              "fffffffffffffffe: apls-mes]ag0${crlf}" .
              "Transfer-Encoding: chunked${crlf}${crlf}" .
              "01${crlf}c${crlf}0A\r'${crlf}\n";
    close $fh;
}

# ------------------------------------------------------------------------------
# 2. corpus_fuzz_dag_rdata_yaml
# ------------------------------------------------------------------------------
my $dir_rdata = "$base/corpus_fuzz_dag_rdata_yaml";
make_path($dir_rdata);

# Helper to pack wire domain name
sub wire_name {
    my ($d) = @_;
    my $out = '';
    for my $l (split /\./, $d) {
        $out .= pack('C', length($l)) . $l;
    }
    $out .= "\x00";
    return $out;
}

# APL (Type 42)
{
    open my $fh, '>:raw', "$dir_rdata/seed_apl.bin" or die $!;
    # type 42, AFI=1 (IPv4), prefix=24, afdlength=3, addr=192.0.2
    my $apl = pack('nCC', 1, 24, 3) . pack('C3', 192, 0, 2);
    print $fh pack('n', 42) . $apl;
    close $fh;
}

# NAPTR (Type 35)
{
    open my $fh, '>:raw', "$dir_rdata/seed_naptr.bin" or die $!;
    # order=100, pref=10, flags="S", service="SIP+D2U", regex="", replacement="_sip._udp.example.com."
    my $naptr = pack('nn', 100, 10) .
                "\x01S" . "\x07SIP+D2U" . "\x00" .
                wire_name("_sip._udp.example.com");
    print $fh pack('n', 35) . $naptr;
    close $fh;
}

# SRV (Type 33)
{
    open my $fh, '>:raw', "$dir_rdata/seed_srv.bin" or die $!;
    # prio=10, weight=20, port=5060, target=sip.example.com.
    my $srv = pack('nnn', 10, 20, 5060) . wire_name("sip.example.com");
    print $fh pack('n', 33) . $srv;
    close $fh;
}

# SOA (Type 6)
{
    open my $fh, '>:raw', "$dir_rdata/seed_soa.bin" or die $!;
    # mname, rname, serial=2026090401, refresh=3600, retry=600, expire=604800, min=300
    my $soa = wire_name("ns1.example.com") . wire_name("hostmaster.example.com") .
              pack('NNNNN', 2026090401, 3600, 600, 604800, 300);
    print $fh pack('n', 6) . $soa;
    close $fh;
}

# CAA (Type 257)
{
    open my $fh, '>:raw', "$dir_rdata/seed_caa.bin" or die $!;
    # flags=0, tag="issue", value="letsencrypt.org"
    my $tag = "issue";
    my $val = "letsencrypt.org";
    my $caa = pack('CC', 0, length($tag)) . $tag . $val;
    print $fh pack('n', 257) . $caa;
    close $fh;
}

# HTTPS (Type 65)
{
    open my $fh, '>:raw', "$dir_rdata/seed_https.bin" or die $!;
    # prio=1, target=target.example.com., key1=alpn, len=3, "h2"
    my $https = pack('n', 1) . wire_name("target.example.com") .
                pack('nn', 1, 3) . "\x02h2";
    print $fh pack('n', 65) . $https;
    close $fh;
}

# ------------------------------------------------------------------------------
# 3. corpus_fuzz_dag_axfr_stream
# ------------------------------------------------------------------------------
my $dir_axfr = "$base/corpus_fuzz_dag_axfr_stream";
make_path($dir_axfr);

{
    open my $fh, '>:raw', "$dir_axfr/seed_axfr_2msg.bin" or die $!;
    # 1 byte: 2 messages
    # msg 1: SOA
    my $soa_rdata = wire_name("ns1.example.com") . wire_name("hostmaster.example.com") .
                    pack('NNNNN', 2026090401, 3600, 600, 604800, 300);
    my $q = wire_name("example.com") . pack('nn', 252, 1);
    my $ans_soa = wire_name("example.com") . pack('nnNn', 6, 1, 3600, length($soa_rdata)) . $soa_rdata;
    my $msg1 = pack('n6', 0x1111, 0x8400, 1, 1, 0, 0) . $q . $ans_soa;

    # msg 2: A record
    my $ans_a = wire_name("host.example.com") . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
    my $msg2 = pack('n6', 0x1111, 0x8400, 0, 1, 0, 0) . $ans_a;

    print $fh pack('C', 2) . $msg1 . $msg2;
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_axfr/seed_axfr_3msg.bin" or die $!;
    my $soa_rdata = wire_name("ns1.example.com") . wire_name("hostmaster.example.com") .
                    pack('NNNNN', 2026090401, 3600, 600, 604800, 300);
    my $q = wire_name("example.com") . pack('nn', 252, 1);
    my $ans_soa = wire_name("example.com") . pack('nnNn', 6, 1, 3600, length($soa_rdata)) . $soa_rdata;
    my $msg1 = pack('n6', 0x2222, 0x8400, 1, 1, 0, 0) . $q . $ans_soa;

    my $ans_txt = wire_name("host.example.com") . pack('nnNn', 16, 1, 300, 5) . "\x04test";
    my $msg2 = pack('n6', 0x2222, 0x8400, 0, 1, 0, 0) . $ans_txt;

    my $msg3 = pack('n6', 0x2222, 0x8400, 0, 1, 0, 0) . $ans_soa;

    print $fh pack('C', 3) . $msg1 . $msg2 . $msg3;
    close $fh;
}

# ------------------------------------------------------------------------------
# 4. corpus_fuzz_dag_replay_pcap_reader
# ------------------------------------------------------------------------------
my $dir_pcap = "$base/corpus_fuzz_dag_replay_pcap_reader";
make_path($dir_pcap);

{
    # Ethernet + IPv4 + UDP + DNS Query
    open my $fh, '>:raw', "$dir_pcap/seed_eth_udp_dns.raw" or die $!;
    my $dns_msg = pack('n6', 0x1234, 0x0100, 1, 0, 0, 0) . wire_name("example.com") . pack('nn', 1, 1);
    my $udp_hdr = pack('nnnn', 5353, 53, 8 + length($dns_msg), 0);
    my $ip_len = 20 + length($udp_hdr) + length($dns_msg);
    my $ip_hdr = pack('CCnnnCCnC4C4', 0x45, 0, $ip_len, 0x1234, 0x4000, 64, 17, 0, 192, 0, 2, 1, 192, 0, 2, 53);
    my $eth_hdr = pack('C6C6n', (0x00, 0x11, 0x22, 0x33, 0x44, 0x55), (0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff), 0x0800);
    print $fh $eth_hdr . $ip_hdr . $udp_hdr . $dns_msg;
    close $fh;
}

{
    # Raw IP + UDP + DNS Query
    open my $fh, '>:raw', "$dir_pcap/seed_raw_udp_dns.raw" or die $!;
    my $dns_msg = pack('n6', 0x9abc, 0x0100, 1, 0, 0, 0) . wire_name("test.net") . pack('nn', 15, 1);
    my $udp_hdr = pack('nnnn', 5353, 53, 8 + length($dns_msg), 0);
    my $ip_len = 20 + length($udp_hdr) + length($dns_msg);
    my $ip_hdr = pack('CCnnnCCnC4C4', 0x45, 0, $ip_len, 0x9abc, 0x4000, 64, 17, 0, 192, 0, 2, 3, 192, 0, 2, 53);
    print $fh $ip_hdr . $udp_hdr . $dns_msg;
    close $fh;
}

# ------------------------------------------------------------------------------
# 5. corpus_fuzz_dag_replay_diff
# ------------------------------------------------------------------------------
my $dir_diff = "$base/corpus_fuzz_dag_replay_diff";
make_path($dir_diff);

{
    open my $fh, '>:raw', "$dir_diff/seed_diff_basic.raw" or die $!;
    my $q = wire_name("example.com") . pack('nn', 1, 1);
    my $ans1 = wire_name("example.com") . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
    my $ans2 = wire_name("example.com") . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 2);
    my $msg1 = pack('n6', 0x1234, 0x8180, 1, 1, 0, 0) . $q . $ans1;
    my $msg2 = pack('n6', 0x1234, 0x8180, 1, 1, 0, 0) . $q . $ans2;
    print $fh pack('C', length($msg1)) . $msg1 . $msg2;
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_diff/seed_diff_identical.raw" or die $!;
    my $q = wire_name("example.com") . pack('nn', 28, 1);
    my $ans = wire_name("example.com") . pack('nnNn', 28, 1, 3600, 16) . pack('H32', "20010db8000000000000000000000001");
    my $msg = pack('n6', 0xabcd, 0x8180, 1, 1, 0, 0) . $q . $ans;
    print $fh pack('C', length($msg)) . $msg . $msg;
    close $fh;
}

# ------------------------------------------------------------------------------
# 6. corpus_fuzz_dag_tcp_reassembly
# ------------------------------------------------------------------------------
my $dir_reasm = "$base/corpus_fuzz_dag_tcp_reassembly";
make_path($dir_reasm);

{
    open my $fh, '>:raw', "$dir_reasm/seed_tcp_reasm_inorder.raw" or die $!;
    my $dns_msg = pack('n6', 0x1234, 0x0100, 1, 0, 0, 0) . wire_name("example.com") . pack('nn', 1, 1);
    my $tcp_payload = pack('n', length($dns_msg)) . $dns_msg;
    my $seg = pack('CNn', 0, 1000, length($tcp_payload)) . $tcp_payload;
    print $fh $seg;
    close $fh;
}

{
    open my $fh, '>:raw', "$dir_reasm/seed_tcp_reasm_multi_seg.raw" or die $!;
    my $dns_msg = pack('n6', 0x5678, 0x8180, 1, 1, 0, 0) . wire_name("example.com") . pack('nn', 1, 1) .
                  wire_name("example.com") . pack('nnNn', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 1);
    my $tcp_payload = pack('n', length($dns_msg)) . $dns_msg;
    my $half = int(length($tcp_payload) / 2);
    my $p1 = substr($tcp_payload, 0, $half);
    my $p2 = substr($tcp_payload, $half);
    my $seg1 = pack('CNn', 1, 2000, length($p1)) . $p1;
    my $seg2 = pack('CNn', 1, 2000 + $half, length($p2)) . $p2;
    print $fh $seg1 . $seg2;
    close $fh;
}

print "[+] Seed corpus generation complete.\n";
