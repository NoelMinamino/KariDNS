#!/usr/bin/perl
# hold_axfr.pl HOST PORT ZONE SECONDS - load a database zone with a query (www.ZONE A), then start a zone transfer of it over TCP and stop reading after the first message
# (the receive buffer is 4 KB: the transfer thread of a large zone blocks in send() and the zone stays "being transferred", so the cache manager cannot take it out of
# memory).  Prints "held" once the first message of the transfer (NOERROR, with records) has been read, then keeps the connection open for SECONDS (or until it is
# killed).  When the transfer is refused (the zone was taken out of memory between the query and the transfer) the query and the transfer are tried again.
use strict;
use warnings;
use Socket;
use IO::Select;
use IO::Socket::INET;
$| = 1;
my ($host, $port, $zone, $secs) = @ARGV;
sub query {
    my ($name, $qt, $id) = @_;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
    $q .= pack('C', length $_) . $_ for split /\./, $name;
    return $q . pack('Cnn', 0, $qt, 1);
}
for my $try (1 .. 10) {
    my $u = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "udp: $!\n";
    syswrite($u, query("www.$zone", 1, 0x4242));
    my $got = IO::Select->new($u)->can_read(15) && sysread($u, my $r, 4096);
    close $u;
    next unless $got;
    socket(my $s, PF_INET, SOCK_STREAM, 0) or die "socket: $!\n";
    setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 4096));
    connect($s, sockaddr_in($port, inet_aton($host))) or die "connect: $!\n";
    my $q = query($zone, 252, 0x4343);
    syswrite($s, pack('n', length $q) . $q);
    my ($hdr, $msg) = ('', '');
    while (length $hdr < 2) { my $n = sysread($s, my $c, 2 - length $hdr); last unless $n; $hdr .= $c; }
    if (length $hdr == 2) {
        my $len = unpack('n', $hdr);
        while (length $msg < $len) { my $n = sysread($s, my $c, $len - length $msg); last unless $n; $msg .= $c; }
    }
    if (length $msg >= 12 && (unpack('n', substr($msg, 2, 2)) & 0xF) == 0 && unpack('n', substr($msg, 6, 2)) > 0) {
        print "held\n";
        sleep($secs);
        exit 0;
    }
    close $s;
    select(undef, undef, undef, 0.3);
}
print "refused\n";
exit 1;
