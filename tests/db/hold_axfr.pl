#!/usr/bin/perl
# hold_axfr.pl HOST PORT ZONE SECONDS [BUDGET] - load a database zone with a query (www.ZONE A), then start a zone transfer of it over TCP and stop reading after the first message
# (the receive buffer is 4 KB: the transfer thread of a large zone blocks in send() and the zone stays "being transferred", so the cache manager cannot take it out of
# memory).  Prints "held" once the first message of the transfer (NOERROR, with records) has been read, then keeps the connection open for SECONDS (or until it is
# killed).  When the transfer is refused (the zone was taken out of memory between the query and the transfer) the query and the transfer are tried again.
# BUDGET (default 30) is the total of seconds that all the tries and every wait for the server together may take; the tests that start this script wait for "held" for the same
# time, so that a failing run does not leave this process behind.  Prints "refused" and exits 1 when the budget is spent.
use strict;
use warnings;
use Socket;
use IO::Select;
use IO::Socket::INET;
use Time::HiRes qw(time);
$| = 1;
my ($host, $port, $zone, $secs, $budget) = @ARGV;
my $end = time() + (defined $budget ? $budget : 30);
sub query {
    my ($name, $qt, $id) = @_;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
    $q .= pack('C', length $_) . $_ for split /\./, $name;
    return $q . pack('Cnn', 0, $qt, 1);
}
# read exactly $want bytes from the TCP socket before the end of the budget (a shorter string when the peer closes or the time is up)
sub read_n {
    my ($s, $want) = @_;
    my $buf = '';
    my $sel = IO::Select->new($s);
    while (length $buf < $want) {
        my $left = $end - time();
        last if $left <= 0 || !$sel->can_read($left);
        my $n = sysread($s, my $c, $want - length $buf);
        last unless $n;
        $buf .= $c;
    }
    return $buf;
}
while (time() < $end) {
    my $u = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "udp: $!\n";
    syswrite($u, query("www.$zone", 1, 0x4242));
    my $wait = $end - time();
    $wait = 3 if $wait > 3;
    my $got = $wait > 0 && IO::Select->new($u)->can_read($wait) && sysread($u, my $r, 4096);
    close $u;
    unless ($got) { select(undef, undef, undef, 0.3); next; }
    socket(my $s, PF_INET, SOCK_STREAM, 0) or die "socket: $!\n";
    setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 4096));
    connect($s, sockaddr_in($port, inet_aton($host))) or die "connect: $!\n";
    my $q = query($zone, 252, 0x4343);
    syswrite($s, pack('n', length $q) . $q);
    my $hdr = read_n($s, 2);
    my $msg = length $hdr == 2 ? read_n($s, unpack('n', $hdr)) : '';
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
