#!/usr/bin/perl
# udp_cold_burst.pl - first-touch burst against a database server: one A query for www.z<i>.test. for every i in 1..N, in a random order (a permutation),
# sent as fast as one socket goes (WINDOW queries in flight), then the answers are counted.
# Usage: perl udp_cold_burst.pl PORT N [SEED] [WINDOW] [WAIT_S] [START]   (the server is 127.0.0.1; names z<i>.test as tests/db/gen_sqlite3_zones.sh makes them)
# Output (one line): "sent=S resent=R answered=A noerror=X servfail=Y other=Z lost=L secs=T rate=R"
# `noerror` = rcode 0 with at least one answer record.  A query is matched to its answer by name; its DNS id is the number of the query in the burst, so that the ones in flight (WINDOW, fewer than 65536) all differ: two queries from one port with one id are the same query to a server that suppresses duplicates, and one of them is not answered.
use strict;
use warnings;
use Socket;
use Time::HiRes qw(time sleep);

my ($port, $n, $seed, $window, $wait_s, $start) = @ARGV;
die "usage: udp_cold_burst.pl PORT N [SEED] [WINDOW] [WAIT_S] [START]\n" unless $port && $n;
$seed = 1 unless defined $seed;
$window ||= 4000;
$wait_s = 8 unless defined $wait_s;
$start ||= 1;
srand($seed);
my @order = ($start .. $start + $n - 1);
for (my $i = $#order; $i > 0; $i--) {
    my $j = int(rand($i + 1));
    @order[$i, $j] = @order[$j, $i];
}
socket(my $s, PF_INET, SOCK_DGRAM, 0) or die "socket: $!";
# The receive buffer: 8 MiB is more than kern.ipc.maxsockbuf allows (8388608: the kernel takes 8/9 of it, ENOBUFS above that) and the refusal left the 42080 bytes of net.inet.udp.recvspace, which holds a few hundred answers: the
# answers of a wave of resends that this client sends without reading were dropped by the kernel of the client, and no counter of the server saw it.  So the sizes are tried from the top down, and the one that was taken is printed (rcvbuf=).
my $rcvbuf = 0;
for my $sz (8 * 1024 * 1024, 7 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024, 256 * 1024) {
    if (setsockopt($s, SOL_SOCKET, SO_RCVBUF, $sz)) { $rcvbuf = unpack("i", getsockopt($s, SOL_SOCKET, SO_RCVBUF)); last; }
}
$rcvbuf ||= unpack("i", getsockopt($s, SOL_SOCKET, SO_RCVBUF));
setsockopt($s, SOL_SOCKET, SO_SNDBUF, 4 * 1024 * 1024);
my $dest = sockaddr_in($port, inet_aton("127.0.0.1"));
my $flags = fcntl($s, 3, 0);                       # F_GETFL
fcntl($s, 4, $flags | 4);                          # F_SETFL, O_NONBLOCK (4 on FreeBSD)

sub pkt {
    my ($i, $id) = @_;
    my $name = "www.z$i.test";
    my $q = join('', map { chr(length($_)) . $_ } split(/\./, $name)) . "\0";
    return pack("nnnnnn", $id, 0x0100, 1, 0, 0, 0) . $q . pack("nn", 1, 1);
}
my %pending;                                       # "zN" => [N, the time it was sent]
my ($sent, $ans, $ok, $sf, $oth, $resent, $late) = (0, 0, 0, 0, 0, 0, 0);
my %nsent;                                         # "zN" => how many times the query was sent (the lost ones are printed with it)
my $t0 = time;
my $deadline;
my $buf;
sub drain {
    my $got = 0;
    while (defined(recv($s, $buf, 4096, 0))) {
        next if length($buf) < 17;
        my ($id, $fl, $qd, $an) = unpack("nnnn", $buf);
        my $off = 12;
        my @labels;
        while ($off < length($buf)) {
            my $l = ord(substr($buf, $off, 1));
            last if $l == 0;
            push @labels, substr($buf, $off + 1, $l);
            $off += 1 + $l;
        }
        my $key = $labels[1] // next;              # www.zN.test: the second label
        if (!delete $pending{$key}) { $late++; next; }        # (an answer to a query that was answered already: a resend's second answer)
        $ans++;
        my $rc = $fl & 15;
        if ($rc == 0 && $an > 0) { $ok++ } elsif ($rc == 2) { $sf++ } else { $oth++ }
        $got++;
    }
    return $got;
}
my $idx = 0;
my $lastmove = time;
my $lastresend = time;
while ($idx < @order || %pending) {
    my $moved = 0;
    while ($idx < @order && keys(%pending) < $window) {
        my $i = $order[$idx++];
        $pending{"z$i"} = [$i, time];
        $nsent{"z$i"} = 1;
        send($s, pkt($i, $sent & 0xffff), 0, $dest) or do { delete $pending{"z$i"}; };
        $sent++;
        $moved++;
        drain() if ($sent & 63) == 0;
    }
    $moved += drain();
    # a query that nobody answered within two seconds is sent again, as a resolver does (a datagram can be lost on the way, in either direction, when the host is busy).  The server's own counters
    # (karictl stats) say whether it answered every query it was given: a wake-up that was lost leaves a query unanswered there, whatever is sent again.
    if (time - $lastresend > 0.5) {
        $lastresend = time;
        for my $k (keys %pending) {
            my $p = $pending{$k};
            next unless defined $p;                          # (answered by a drain() of this very wave)
            next if time - $p->[1] < 2;
            $p->[1] = time;
            send($s, pkt($p->[0], $sent & 0xffff), 0, $dest);
            $sent++;
            $resent++;
            $nsent{$k}++;
            drain() if ($resent & 31) == 0;                 # (the answers are read while a wave goes out, not after it)
            $moved++;
        }
    }
    if ($idx >= @order) {
        $deadline //= time + $wait_s;
        last if time > $deadline;
        last unless %pending;
    }
    if ($moved) { $lastmove = time; } else { last if time - $lastmove > $wait_s; sleep(0.0005); }     # (nothing is sent and nothing comes back: the server is not there, or it is stuck)
}
drain();
my $secs = time - $t0;
my $lost = keys %pending;
if ($lost) {                                       # the first 10 names and how often each was sent: the test asks the server about them
    my @l = sort { $a cmp $b } keys %pending;
    print STDERR "LOST: ", join(" ", map { "$_(x$nsent{$_})" } @l[0 .. ($#l < 9 ? $#l : 9)]), (@l > 10 ? " ... (" . @l . " in all)" : ""), "\n";
}
printf("sent=%d resent=%d answered=%d noerror=%d servfail=%d other=%d lost=%d secs=%.2f rate=%d late=%d rcvbuf=%d\n", $sent, $resent, $ans, $ok, $sf, $oth, $lost, $secs, $secs > 0 ? $sent / $secs : 0, $late, $rcvbuf);
exit($ok == $n ? 0 : 1);
