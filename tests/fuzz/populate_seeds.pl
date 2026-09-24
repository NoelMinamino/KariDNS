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

print "[+] Seed corpuses populated successfully.\n";
