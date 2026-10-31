#!/usr/bin/perl
# cache_stress.pl - the client of tests/run_db_cache_test.sh: queries for hosts of many zones, the zones chosen with a Zipf distribution
# (s = 1: the zone of rank r is asked for 1/r as often as the first), each answer checked against what the database holds.
#
#   cache_stress.pl HOST PORT NZONES NHOSTS COUNT SEED       random queries
#   cache_stress.pl HOST PORT NZONES NHOSTS sweep            one query for every zone, in order
#
# Zone z (0-based) is "zNNNN.test." (4 digits); its host hK (K 0-based) has the address 10.(z % 200 + 1).(K / 200).(K % 200 + 1), the same
# arithmetic as in the SQL that fills the database.  The answer is: ok (NOERROR, one A record with that address), wrong (anything else
# that is an answer: this is a failure of the test), notready (SERVFAIL, which is what a query gets when its zone could not be had in time),
# timeout (no answer in 5 s).  Prints one line: "ok=N wrong=N notready=N timeout=N".
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time usleep);
my $delay_us = ($ENV{CACHE_STRESS_DELAY_MS} || 0) * 1000;           # a pause between two queries of this client

my ($host, $port, $nz, $nh, $count_or_sweep, $seed) = @ARGV;
die "usage\n" unless defined $nh;
my $sweep = $count_or_sweep eq 'sweep';
my $count = $sweep ? $nz : $count_or_sweep;
srand(defined $seed ? $seed : 1);

my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "udp: $!\n";
my $sel = IO::Select->new($sock);

my @cum;
if (!$sweep) {
    my $acc = 0;
    for my $r (1 .. $nz) { $acc += 1.0 / $r; push @cum, $acc; }
}
sub pick_zone {
    my $x = rand($cum[-1]);
    my ($lo, $hi) = (0, $#cum);
    while ($lo < $hi) {
        my $mid = int(($lo + $hi) / 2);
        if ($cum[$mid] < $x) { $lo = $mid + 1 } else { $hi = $mid }
    }
    return $lo;
}

sub query {
    my ($id, $name) = @_;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
    $q .= pack('C', length $_) . $_ for split /\./, $name;
    return $q . pack('Cnn', 0, 1, 1);
}

my %n = (ok => 0, wrong => 0, notready => 0, timeout => 0);
for my $i (0 .. $count - 1) {
    my $z = $sweep ? $i : pick_zone();
    my $k = $sweep ? 0 : int(rand($nh));
    my $name = sprintf('h%d.z%04d.test', $k, $z);
    my $want = sprintf('10.%d.%d.%d', $z % 200 + 1, int($k / 200), $k % 200 + 1);
    usleep($delay_us) if $delay_us;
    my $id = int(rand(65536));
    my $q = query($id, $name);
    my $got;
    for my $try (1 .. 2) {
        send($sock, $q, 0);
        my $deadline = time() + 5;
        while (time() < $deadline) {
            next unless $sel->can_read($deadline - time());
            my $r;
            next unless defined recv($sock, $r, 4096, 0);
            next unless length($r) >= 12 && unpack('n', $r) == $id;
            $got = $r;
            last;
        }
        last if defined $got;
    }
    if (!defined $got) { $n{timeout}++; next; }
    my ($fl, $qd, $an) = unpack('x2nnn', $got);
    my $rcode = $fl & 0xF;
    if ($rcode == 2) { $n{notready}++; next; }
    my $ip = '';
    if ($rcode == 0 && $an == 1) {
        my $o = 12;
        $o += 1 + ord(substr($got, $o, 1)) while ord(substr($got, $o, 1)) != 0;
        $o += 1 + 4;                                   # the root label, QTYPE, QCLASS
        $o += 2;                                       # the name of the answer (a pointer)
        my ($type, $cls, $ttl, $rdlen) = unpack('nnNn', substr($got, $o, 10));
        $o += 10;
        $ip = join('.', unpack('C4', substr($got, $o, 4))) if $type == 1 && $rdlen == 4;
    }
    if ($ip eq $want) { $n{ok}++ } else { $n{wrong}++; print STDERR "wrong answer for $name: rcode $rcode an $an ip '$ip' want $want\n"; }
}
printf("ok=%d wrong=%d notready=%d timeout=%d\n", @n{qw(ok wrong notready timeout)});
