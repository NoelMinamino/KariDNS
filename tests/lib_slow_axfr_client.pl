#!/usr/bin/perl
# lib_slow_axfr_client.pl - an AXFR client that does not read (tests/run_xfr_failover_test.sh: transfers-out, max-transfer-idle-out).
#
#   lib_slow_axfr_client.pl PORT ZONE HOLD-SECONDS
#
# Connects to 127.0.0.1:PORT with a small receive buffer, sends an AXFR request for ZONE, reads nothing for HOLD-SECONDS (so the server's
# send blocks once the socket buffers are full), then reads until the server closes the connection or 3 seconds pass without data.
# Prints "BYTES=<n> CLOSED=<0|1>": CLOSED=1 when the server closed the connection (EOF) before the zone was complete is only
# knowable by the size, so the caller compares BYTES with the size of the zone.
use strict;
use warnings;
use IO::Socket::INET;
use Socket;

my ($port, $zone, $hold) = @ARGV;
die "usage: $0 PORT ZONE HOLD-SECONDS\n" unless defined $hold;
socket(my $s, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 4096));
connect($s, sockaddr_in($port, inet_aton('127.0.0.1'))) or die "connect: $!";
my $q = pack('n6', 0x4242, 0, 1, 0, 0, 0) . join('', map { chr(length $_) . $_ } split(/\./, $zone)) . "\0" . pack('nn', 252, 1);
syswrite($s, pack('n', length $q) . $q);
$| = 1;
print "HELD\n";
sleep $hold;
my ($bytes, $closed) = (0, 0);
while (1) {
    my $rin = '';
    vec($rin, fileno($s), 1) = 1;
    last unless select($rin, undef, undef, 3);
    my $n = sysread($s, my $buf, 65536);
    if (!defined $n || $n == 0) { $closed = 1; last; }
    $bytes += $n;
}
print "BYTES=$bytes CLOSED=$closed\n";
