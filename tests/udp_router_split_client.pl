#!/usr/bin/perl
# udp_router_split_client.pl - the load of tests/run_udp_router_split_test.sh: N UDP queries (q<i>.example.test. A, DNS id = i & 0xffff, so N <= 65536) from
# NSOCK sockets of their own (NSOCK source ports: the router that gets a query is chosen by the kernel from the 4-tuple, so every router needs several), the
# query i going from socket i % NSOCK to the server address IPS[i % @IPS], at most WINDOW unanswered at a time, BATCH queries and then a pause of PAUSE_MS
# milliseconds.  No query is sent again: an answer that does not come is a loss, and it is counted as one.  A query unanswered for LOST_S (3) seconds
# is given up (it stays a loss) and frees its place in the window: with WINDOW 1 one datagram the kernel drops must not stop the rest of the load.
# Every answer is checked: QR set, the id of a query of that socket, NOERROR, one A record 192.0.2.1, and the datagram comes from the address and port that
# the query went to (a wildcard socket of the server has to answer from the address the query came to, a socket bound to an address from that address).
# Usage: perl udp_router_split_client.pl PORT N NSOCK WINDOW WAIT_S IP[,IP...] [BATCH [PAUSE_MS]]
# Output (one line): "sent=S received=R answered=A unanswered=U bad=B socks=K secs=T senderr=E"
#   bad = answers that failed a check above; socks = the sockets that were answered at least once.
#   senderr = sends the kernel refused at first (tried again, every 5 ms, up to 200 times).  The client waits WAIT_S seconds after the last send for the answers (a bound).
use strict;
use warnings;
use Socket;
use Fcntl;
use Time::HiRes qw(time sleep);

my ($port, $n, $nsock, $window, $wait_s, $ips, $batch, $pause_ms) = @ARGV;
die "usage: udp_router_split_client.pl PORT N NSOCK WINDOW WAIT_S IP[,IP...] [BATCH [PAUSE_MS]]\n" unless $port && $n && $nsock && $window && $ips;
die "N is at most 65536 (the DNS id is the number of the query)\n" if $n > 65536;
$wait_s //= 5;
$batch ||= 16;
$pause_ms //= 0;
my @ips = split(/,/, $ips);
my @dest = map { inet_aton($_) or die "bad address $_\n" } @ips;

my @sock;
for my $k (0 .. $nsock - 1) {
    socket(my $s, PF_INET, SOCK_DGRAM, 0) or die "socket: $!";
    setsockopt($s, SOL_SOCKET, SO_RCVBUF, 1024 * 1024);
    fcntl($s, F_SETFL, fcntl($s, F_GETFL, 0) | O_NONBLOCK);
    bind($s, sockaddr_in(0, INADDR_ANY)) or die "bind: $!";
    push @sock, $s;
}
my $rin = '';
vec($rin, fileno($_), 1) = 1 for @sock;
my %by_fd = map { fileno($sock[$_]) => $_ } 0 .. $#sock;

sub pkt {
    my ($i) = @_;
    my $q = join('', map { chr(length($_)) . $_ } ("q$i", "example", "test")) . "\0";
    return pack("nnnnnn", $i & 0xffff, 0x0100, 1, 0, 0, 0) . $q . pack("nn", 1, 1);
}

my %pending;                                   # id => the number of the socket it went from
my %want_ip;                                   # id => the index in @dest of the address it went to
my %sent_at;                                   # id => the time it was sent (a query unanswered for $lost_s seconds is given up)
my $lost_s = 3;
my %given_up;                                  # id => the socket of a query given up
my ($sent, $received, $answered, $bad, $senderr) = (0, 0, 0, 0, 0);
my (%seen, %socks_ok);
my $buf;
sub drain {
    my $got = 0;
    my $rout = $rin;
    select($rout, undef, undef, 0);
    for my $k (0 .. $#sock) {
        next unless vec($rout, fileno($sock[$k]), 1);
        while (defined(my $from = recv($sock[$k], $buf, 4096, 0))) {
            $got++;
            $received++;
            if (length($buf) < 12) { $bad++; next; }
            my ($id, $fl, $qd, $an) = unpack("nnnn", $buf);
            my ($fport, $faddr) = sockaddr_in($from);
            my $want = $pending{$id} // $given_up{$id};       # (a late answer to a query given up is still checked and counted)
            # (the A record 192.0.2.1 is in the answer: RDLENGTH 4 and the address; the datagram comes from the address the query went to, at the server's port)
            my $ok = ($fl & 0x8000) && ($fl & 0xf) == 0 && $an == 1 && $fport == $port && defined $want && $want == $k
                && index($buf, pack("nC4", 4, 192, 0, 2, 1)) > 12 && $faddr eq $dest[$want_ip{$id}];
            $bad++ unless $ok;
            if (!$seen{$id}++) { $answered++; $socks_ok{$k} = 1; }
            delete $pending{$id};
            delete $sent_at{$id};
        }
    }
    return $got;
}

my $t0 = time;
my $next = 1;
my $end_sent;
while (1) {
    my $moved = 0;
    for (my $b = 0; $b < $batch && $next <= $n && keys(%pending) < $window; $b++) {
        my $i = $next++;
        my $k = $i % $nsock;
        my $d = $i % @dest;
        $pending{$i & 0xffff} = $k;
        $want_ip{$i & 0xffff} = $d;
        $sent_at{$i & 0xffff} = time;
        # (a send the kernel refuses for a moment, ENOBUFS on a loaded host, is tried again: a loss of the client is not one of the server)
        my $tries = 0;
        until (defined send($sock[$k], pkt($i), 0, sockaddr_in($port, $dest[$d]))) { $senderr++; last if ++$tries >= 200; sleep(0.005); }
        $sent++;
        $moved++;
    }
    $moved += drain();
    for my $id (keys %pending) { next if time - $sent_at{$id} < $lost_s; $given_up{$id} = delete $pending{$id}; delete $sent_at{$id}; $moved++; }   # (given up: counted as unanswered)
    $end_sent = time if $next > $n && !defined $end_sent;
    last if time - $t0 > 120;                    # (a server that does not answer at all: do not run for ever)
    last if $next > $n && !%pending;
    last if defined $end_sent && time - $end_sent > $wait_s;   # (a bound only: a host that stalls for seconds is given the time, the answers are still checked)
    if ($pause_ms > 0) { sleep($pause_ms / 1000); } elsif (!$moved) { sleep(0.0005); }
}
for (my $q0 = time; time - $q0 < 1; ) { $q0 = time if drain(); sleep(0.01); }
my $secs = time - $t0;
printf("sent=%d received=%d answered=%d unanswered=%d bad=%d socks=%d secs=%.2f\n", $sent, $received, $answered, $n - $answered, $bad, scalar(keys %socks_ok), $secs);
exit(0);
