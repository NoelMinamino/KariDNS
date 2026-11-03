#!/usr/bin/perl
# udp_a_sweep.pl HOST PORT FILE - one A question over UDP for every name in FILE (one name per line), one after the other (each waits for its answer, at most
# 10 s).  Prints one line: "sent=N answered=N noerror=N".  A zone that is not in memory is read for the first question, so the answers take a few milliseconds.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
my ($host, $port, $file) = @ARGV;
die "usage: udp_a_sweep.pl HOST PORT FILE\n" unless defined $file;
open(my $fh, '<', $file) or die "$file: $!\n";
my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "udp: $!\n";
my $sel = IO::Select->new($s);
my ($sent, $answered, $noerror) = (0, 0, 0);
my $id = 1;
while (my $name = <$fh>) {
    chomp $name;
    next unless length $name;
    $id = ($id % 65535) + 1;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0) . join('', map { pack('C', length $_) . $_ } split /\./, $name) . "\0" . pack('nn', 1, 1);
    syswrite($s, $q);
    $sent++;
    my $r;
    while ($sel->can_read(10) && sysread($s, $r, 4096)) {
        next if unpack('n', $r) != $id;                  # (an answer to an earlier question that came late)
        $answered++;
        $noerror++ if (unpack('n', substr($r, 2, 2)) & 15) == 0;
        last;
    }
}
print "sent=$sent answered=$answered noerror=$noerror\n";
