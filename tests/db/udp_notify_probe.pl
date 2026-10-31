#!/usr/bin/perl
# udp_notify_probe.pl SRC HOST PORT ZONE - a NOTIFY (RFC 1996) for ZONE over UDP from the local address SRC (so that the view that matches SRC answers).
# Prints the rcode of the answer ("NOERROR" / "REFUSED" / "NOTAUTH" ... as a number), or "timeout".
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
my ($src, $host, $port, $zone) = @ARGV;
die "usage: udp_notify_probe.pl SRC HOST PORT ZONE\n" unless defined $zone;
my $name = join('', map { pack('C', length $_) . $_ } split /\./, $zone) . "\0";
my $q = pack('nnnnnn', 0x4e54, 0x2400, 1, 0, 0, 0) . $name . pack('nn', 6, 1);     # opcode 4 (NOTIFY), AA
my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp', LocalAddr => $src) or die "udp: $!\n";
syswrite($s, $q);
my $r;
unless (IO::Select->new($s)->can_read(5) && sysread($s, $r, 4096)) { print "timeout\n"; exit 1; }
my ($id, $fl) = unpack('nn', $r);
print $fl & 0x0F, "\n";
