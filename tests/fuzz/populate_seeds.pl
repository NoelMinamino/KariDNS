#!/usr/bin/perl
# ==============================================================================
# tests/fuzz/populate_seeds.pl - Populate seed corpuses for libFuzzer targets
# ==============================================================================
use strict;
use warnings;
use File::Path qw(make_path);
use File::Copy qw(copy);
use File::Basename;

my $root = ".";
my $fuzz_dir = "$root/tests/fuzz";

# Ensure base directories exist
for my $c (qw(
    corpus_fuzz_zone_parser
    corpus_fuzz_conf_parser
    corpus_fuzz_dns_wire
    corpus_fuzz_tsig_sign
    corpus_fuzz_tsig_verify
    corpus_fuzz_dns_server_core
    corpus_fuzz_query_engine
    corpus_fuzz_xfr_packet
    corpus_fuzz_dynamic_update
    corpus_fuzz_dag_response
    corpus_fuzz_dag_hash
    corpus_fuzz_dag_chunked_http
    corpus_fuzz_dag_rdata_yaml
    corpus_fuzz_dag_axfr_stream
    corpus_fuzz_dag_cli_args
    corpus_fuzz_dag_batch_file
    corpus_fuzz_dag_replay_pcap_reader
    corpus_fuzz_tapstat
    corpus_fuzz_dag_replay_diff
    corpus_fuzz_dag_tcp_reassembly
)) {
    make_path("$fuzz_dir/$c");
}

# 1. Populate Zone Parser Corpus
my $zone_corpus = "$fuzz_dir/corpus_fuzz_zone_parser";
my @zone_files = glob("$root/tests/zones/*.zone");
push @zone_files, glob("$root/*.zone.sample");
push @zone_files, glob("$root/tests/include_tests/*");
push @zone_files, glob("$root/*.zone");

for my $zf (@zone_files) {
    next unless -f $zf;
    my $bname = basename($zf);
    copy($zf, "$zone_corpus/seed_$bname");
}

# 2. Populate Conf Parser Corpus
my $conf_corpus = "$fuzz_dir/corpus_fuzz_conf_parser";
my @conf_files = (
    glob("$root/*.conf.sample"),
    glob("$root/tests/*.conf"),
    glob("$root/tests/*_test.conf"),
    glob("$root/*.conf"),
);

for my $cf (@conf_files) {
    next unless -f $cf;
    my $bname = basename($cf);
    copy($cf, "$conf_corpus/seed_$bname");
}

# 3. Generate structured wire & dag seeds
if (-f "$fuzz_dir/generate_new_seeds.pl") {
    system("perl $fuzz_dir/generate_new_seeds.pl");
}

# 4. Generate basic wire seeds if corpus is empty
my $wire_corpus = "$fuzz_dir/corpus_fuzz_dns_wire";
{
    # Basic Query: example.com IN A
    open my $fh, '>:raw', "$wire_corpus/seed_query_a.bin" or die $!;
    my $hdr = pack('n6', 0x1234, 0x0100, 1, 0, 0, 0); # RD=1, QD=1
    my $qname = "\x07example\x03com\x00";
    my $qtail = pack('nn', 1, 1); # TYPE=A, CLASS=IN
    print $fh $hdr . $qname . $qtail;
    close $fh;
}

{
    # Basic Query with EDNS(0) DO=1
    open my $fh, '>:raw', "$wire_corpus/seed_query_edns_do.bin" or die $!;
    my $hdr = pack('n6', 0x5678, 0x0100, 1, 0, 0, 1); # AR=1
    my $qname = "\x07example\x03com\x00";
    my $qtail = pack('nn', 28, 1); # TYPE=AAAA, CLASS=IN
    my $opt_rr = "\x00" . pack('n', 41) . pack('n', 4096) . pack('N', 0x00008000) . pack('n', 0); # DO=1
    print $fh $hdr . $qname . $qtail . $opt_rr;
    close $fh;
}

# 5. Populate dag cli args seeds
my $cli_corpus = "$fuzz_dir/corpus_fuzz_dag_cli_args";
my @cli_seeds = (
    "example.com A",
    "example.com AAAA +dnssec +yaml",
    "@127.0.0.1 -p 5353 example.com ANY +tcp",
    "example.com HTTPS +yaml +edns=0 +bufsize=1232",
    "example.com MX +trace +nodnssec",
    "-x 192.0.2.1 +short",
    "-x 2001:db8::1 +yaml",
    "example.com TXT +subnet=192.0.2.0/24 +cookie",
    "example.com SOA +multiline +comments",
    "-k tests/fixtures/tsig.key example.com AXFR +yaml",
);

my $idx = 1;
for my $cs (@cli_seeds) {
    open my $fh, '>:raw', "$cli_corpus/seed_arg_$idx.txt" or die $!;
    print $fh $cs;
    close $fh;
    $idx++;
}

# 6. Populate dag batch file seeds
my $batch_corpus = "$fuzz_dir/corpus_fuzz_dag_batch_file";
{
    open my $fh, '>:raw', "$batch_corpus/seed_batch_1.txt" or die $!;
    print $fh "example.com A\n";
    print $fh "example.com AAAA +dnssec\n";
    print $fh "example.org MX\n";
    print $fh "sub.example.net TXT +yaml\n";
    close $fh;
}

# 7. karidns-tapstat: Frame Streams sessions (the first byte is the chunk size of the harness) with dnstap frames
{
    my $dir = "$fuzz_dir/corpus_fuzz_tapstat";
    my $varint = sub { my $v = shift; my $o = ''; while ($v >= 0x80) { $o .= chr(($v & 0x7f) | 0x80); $v >>= 7; } return $o . chr($v); };
    my $fvar   = sub { my ($f, $v) = @_; return $varint->(($f << 3) | 0) . $varint->($v); };
    my $fbytes = sub { my ($f, $b) = @_; return $varint->(($f << 3) | 2) . $varint->(length $b) . $b; };
    my $dns = sub {
        my ($resp, $rcode, $name, $qtype) = @_;
        my $w = join('', map { chr(length $_) . $_ } split(/\./, $name)) . "\0";
        return pack('nnnnnn', 0x1234, ($resp ? 0x8400 : 0) | $rcode, 1, 0, 0, 0) . $w . pack('nn', $qtype, 1);
    };
    my $frame = sub {
        my ($type, $addr, $wire, $zone) = @_;
        my $m = $fvar->(1, $type) . $fvar->(2, length($addr) == 16 ? 2 : 1) . $fvar->(3, 1) . $fbytes->(4, $addr) . $fvar->(6, 5353)
              . $fbytes->($type == 1 ? 10 : 14, $wire) . (defined $zone ? $fbytes->(11, $zone) : '');
        return $fbytes->(1, 'id') . $fvar->(15, 1) . $fbytes->(14, $m);
    };
    my $ct = 'protobuf:dnstap.Dnstap';
    my $ctl = sub { my ($type, $withct) = @_; my $p = pack('N', $type) . ($withct ? pack('NN', 1, length $ct) . $ct : ''); return pack('NN', 0, length $p) . $p; };
    my $data = sub { my $f = shift; return pack('N', length $f) . $f; };
    my $a4 = pack('C4', 192, 0, 2, 77);
    my $a6 = pack('C16', 0x20, 0x01, 0x0d, 0xb8, 0, 0x12, 0x34, 0x56, 1 .. 8);
    my @frames = (
        $frame->(2, $a4, $dns->(1, 0, 'www.example.test', 1), "\7example\4test\0"),
        $frame->(1, $a4, $dns->(0, 0, 'www.example.test', 1)),
        $frame->(2, $a6, $dns->(1, 3, 'nx.sub.example.test', 28)),
        $frame->(2, $a4, $dns->(1, 5, 'example.org', 255)),
    );
    my %seeds = (
        seed_session => chr(7) . $ctl->(4, 1) . $ctl->(2, 1) . join('', map { $data->($_) } @frames) . $ctl->(3, 0),
        seed_file    => chr(255) . $ctl->(2, 1) . join('', map { $data->($_) } @frames),
        seed_frame   => chr(0) . $frames[2],
        seed_nocontenttype => chr(1) . $ctl->(4, 0) . $ctl->(2, 0) . $data->($frames[0]),
        seed_oversize => chr(3) . $ctl->(2, 1) . pack('N', 0x7fffffff),
    );
    for my $n (sort keys %seeds) {
        open my $fh, '>:raw', "$dir/$n" or die $!;
        print $fh $seeds{$n};
        close $fh;
    }
}

print "[+] Seed corpuses populated successfully.\n";
