#!/usr/bin/perl
# udp_lookup_probe.pl - the UDP side of tests/run_db_lookup_test.sh (0.7: a query for a name that no zone of the store covers while the first pass has not listed every zone).
# Usage: perl udp_lookup_probe.pl one PORT NAME [TYPE]               one query to 127.0.0.1:PORT; prints "rcode=R answers=N" (exit status 0: an answer came back)
#        perl udp_lookup_probe.pl flood PORT COUNT SUFFIX [WAIT]     COUNT queries for r<i>.SUFFIX (A), a name each, sent in bursts of 100; waits up to WAIT seconds (default 20) for the answers;
#                                                                    prints "sent=N refused=R noerror=E servfail=S other=O lost=L"
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time sleep);

my ($mode, $port, @rest) = @ARGV;
die "usage: udp_lookup_probe.pl one|flood PORT ...\n" unless $mode && $port;
my %types = (A => 1, NS => 2, SOA => 6, MX => 15, DS => 43);

sub packet {
    my ($id, $name, $qt) = @_;
    $name =~ s/\.$//;
    my $q = join('', map { chr(length($_)) . $_ } split(/\./, $name)) . "\0";
    return pack("nnnnnn", $id, 0x0100, 1, 0, 0, 0) . $q . pack("nn", $qt, 1);
}

my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port, Proto => "udp") or die "socket: $!\n";
my $sel = IO::Select->new($s);

if ($mode eq "one") {
    my ($name, $type) = @rest;
    die "usage: udp_lookup_probe.pl one PORT NAME [TYPE]\n" unless $name;
    my $qt = $types{uc($type || "A")} or die "unknown type\n";
    $s->send(packet(0x4243, $name, $qt));
    die "no answer\n" unless $sel->can_read(10);
    my $buf;
    $s->recv($buf, 4096);
    my ($id, $fl, $qd, $an) = unpack("nnnn", $buf);
    printf("rcode=%d answers=%d\n", $fl & 15, $an);
    exit 0;
}

die "unknown mode\n" unless $mode eq "flood";
my ($count, $suffix, $wait) = @rest;
die "usage: udp_lookup_probe.pl flood PORT COUNT SUFFIX [WAIT]\n" unless $count && $suffix;
$wait ||= 20;
my %rc;
my $got = 0;
my $drain = sub {
    while ($sel->can_read(0)) {
        my $buf;
        last unless defined $s->recv($buf, 4096) && length($buf) >= 12;
        my ($id, $fl) = unpack("nn", $buf);
        $rc{$fl & 15}++;
        $got++;
    }
};
for my $i (1 .. $count) {
    $s->send(packet(($i % 65535) + 1, "r$i.$suffix", 1));
    if ($i % 100 == 0) {
        sleep(0.01);
        $drain->();
    }
}
my $end = time() + $wait;
while ($got < $count && time() < $end) {
    $sel->can_read(0.2);
    $drain->();
}
printf("sent=%d refused=%d noerror=%d servfail=%d other=%d lost=%d\n", $count, $rc{5} || 0, $rc{0} || 0, $rc{2} || 0,
       $got - ($rc{5} || 0) - ($rc{0} || 0) - ($rc{2} || 0), $count - $got);
exit 0;
