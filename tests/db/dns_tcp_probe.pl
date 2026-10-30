#!/usr/bin/perl
# dns_tcp_probe.pl - a small DNS-over-TCP client for tests/run_db_park_test.sh: what dag cannot do (pipelined queries in one write, an
# EOF while the server holds the request, the time the server takes to close an idle connection).
#
#   dns_tcp_probe.pl HOST PORT pipeline NAME...   all the queries (A, IN, RD) in ONE write; reads one answer per query
#                                                 prints "id=N rcode=R an=A" per answer, in the order they arrive
#   dns_tcp_probe.pl HOST PORT eof NAME           sends the query and closes at once; prints "closed"
#   dns_tcp_probe.pl HOST PORT idle NAME          sends the query, reads the answer, then waits for the server to close; prints
#                                                 "id=N rcode=R an=A" and "closed after S seconds" (at most 30)
#   dns_tcp_probe.pl HOST PORT udp-op OPCODE NAME  one message with that opcode (4 NOTIFY, 5 UPDATE) and a SOA question for NAME (the zone
#   dns_tcp_probe.pl HOST PORT tcp-op OPCODE NAME  section of an UPDATE), over UDP or TCP; prints "id=N rcode=R" or "no answer"
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time);

my ($host, $port, $mode, @names) = @ARGV;
die "usage\n" unless defined $mode && @names;

sub query {
    my ($id, $name) = @_;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
    for my $l (split /\./, $name) { $q .= pack('C', length $l) . $l; }
    $q .= pack('Cnn', 0, 1, 1);
    return pack('n', length $q) . $q;
}

sub read_exact {
    my ($s, $n, $deadline) = @_;
    my $buf = '';
    my $sel = IO::Select->new($s);
    while (length $buf < $n) {
        my $left = $deadline - time();
        return undef if $left <= 0;
        next unless $sel->can_read($left);
        my $got = sysread($s, my $chunk, $n - length $buf);
        return undef unless $got;
        $buf .= $chunk;
    }
    return $buf;
}

sub read_answer {
    my ($s, $deadline) = @_;
    my $lb = read_exact($s, 2, $deadline);
    return undef unless defined $lb;
    my $len = unpack('n', $lb);
    my $m = read_exact($s, $len, $deadline);
    return undef unless defined $m;
    my ($id, $fl, $qd, $an) = unpack('nnnn', $m);
    return sprintf("id=%d rcode=%d an=%d", $id, $fl & 0xF, $an);
}

if ($mode eq 'udp-op') {
    my ($opcode, $name) = @names;
    my $q = pack('nnnnnn', 401, ($opcode << 11), 1, 0, 0, 0);
    for my $l (split /\./, $name) { $q .= pack('C', length $l) . $l; }
    $q .= pack('Cnn', 0, 6, 1);                      # SOA IN
    my $u = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "udp: $!\n";
    syswrite($u, $q);
    my $sel = IO::Select->new($u);
    if ($sel->can_read(10) && sysread($u, my $m, 4096)) {
        my ($id, $fl) = unpack('nn', $m);
        printf("id=%d rcode=%d\n", $id, $fl & 0xF);
    } else {
        print "no answer\n";
    }
    exit 0;
}

my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Timeout => 5) or die "connect: $!\n";
$s->autoflush(1);

if ($mode eq 'tcp-op') {
    my ($opcode, $name) = @names;
    my $q = pack('nnnnnn', 402, ($opcode << 11), 1, 0, 0, 0);
    for my $l (split /\./, $name) { $q .= pack('C', length $l) . $l; }
    $q .= pack('Cnn', 0, 6, 1);
    syswrite($s, pack('n', length $q) . $q);
    my $lb = read_exact($s, 2, time() + 10);
    my $m = defined $lb ? read_exact($s, unpack('n', $lb), time() + 10) : undef;
    if (defined $m) {
        my ($id, $fl) = unpack('nn', $m);
        printf("id=%d rcode=%d\n", $id, $fl & 0xF);
    } else {
        print "no answer\n";
    }
} elsif ($mode eq 'pipeline') {
    my $id = 100;
    my $all = '';
    $all .= query(++$id, $_) for @names;
    syswrite($s, $all);
    for (@names) {
        my $a = read_answer($s, time() + 10);
        last unless defined $a;
        print "$a\n";
    }
} elsif ($mode eq 'eof') {
    syswrite($s, query(201, $names[0]));
    close($s);
    print "closed\n";
} elsif ($mode eq 'idle') {
    syswrite($s, query(301, $names[0]));
    my $a = read_answer($s, time() + 10);
    print(defined $a ? "$a\n" : "no answer\n");
    my $t0 = time();
    my $sel = IO::Select->new($s);
    my $closed = 0;
    while (time() - $t0 < 30) {
        next unless $sel->can_read(0.2);
        my $n = sysread($s, my $junk, 4096);
        if (!$n) { $closed = 1; last; }
    }
    printf("%s after %.1f seconds\n", $closed ? 'closed' : 'still open', time() - $t0);
} else {
    die "unknown mode\n";
}
