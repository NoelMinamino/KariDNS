#!/usr/bin/perl
# dns_soa_probe.pl HOST PORT udp|tcp NAME QTYPE EDNS-SIZE(0 = none) DO(0|1) - one query, the response as one line of hex (the id is fixed, so two
# answers to the same question can be compared byte for byte).  Prints "no answer" when there is none.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
my ($host, $port, $proto, $name, $qtype, $edns, $do) = @ARGV;
my %T = (A => 1, NS => 2, SOA => 6, AAAA => 28);
my $q = pack('nnnnnn', 0x1234, 0x0100, 1, 0, 0, $edns ? 1 : 0);
$q .= pack('C', length $_) . $_ for split /\./, $name;
$q .= pack('Cnn', 0, $T{$qtype}, 1);
$q .= pack('CnnCCnn', 0, 41, $edns, 0, 0, $do ? 0x8000 : 0, 0) if $edns;
my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => $proto eq 'tcp' ? 'tcp' : 'udp') or die "connect: $!\n";
my $m;
if ($proto eq 'tcp') {
    syswrite($s, pack('n', length $q) . $q);
    my $sel = IO::Select->new($s);
    my $buf = '';
    while (length($buf) < 2 || length($buf) < 2 + unpack('n', $buf)) {
        last unless $sel->can_read(10) && sysread($s, my $chunk, 65535);
        $buf .= $chunk;
    }
    $m = length($buf) >= 2 ? substr($buf, 2) : undef;
} else {
    syswrite($s, $q);
    my $r;
    $m = IO::Select->new($s)->can_read(10) && sysread($s, $r, 65535) ? $r : undef;
}
print defined $m && length $m ? unpack('H*', $m) : 'no answer', "\n";
