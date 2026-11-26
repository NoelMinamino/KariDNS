#!/usr/bin/perl
# ipc_drops_client.pl - the load of tests/run_ipc_drops_test.sh: N UDP queries (q<i>.example.test. A, DNS id = i & 0xffff, so N <= 65536), at most
# WINDOW unanswered at a time, BATCH queries and then a pause of PAUSE_MS milliseconds, and an exact count of every datagram sent and received.
# A query that is not answered within RESEND_S seconds is sent again with the same id (RESEND_S 0: never), as a resolver does.
# Usage: perl ipc_drops_client.pl PORT N WINDOW RESEND_S WAIT_S [BATCH [PAUSE_MS [CONT_PID]]]   (the server is 127.0.0.1)
#   CONT_PID: a process that gets SIGCONT when the last query is sent (the test stops the Backend, and lets it go once everything is queued)
# Output (one line): "sent=S received=R answered=A unanswered=U resent=X sendfail=F secs=T"
#   sent = every datagram the kernel took (the resends included; sendfail = the ones it refused); received = every datagram that came back (a late answer of a resent query too);
#   answered = the queries that got at least one answer; unanswered = N - answered.  sent - received is what the server and the kernel lost.
use strict;
use warnings;
use Socket;
use Fcntl;
use Time::HiRes qw(time sleep);

my ($port, $n, $window, $resend_s, $wait_s, $batch, $pause_ms, $cont_pid) = @ARGV;
die "usage: ipc_drops_client.pl PORT N WINDOW RESEND_S WAIT_S [BATCH [PAUSE_MS [CONT_PID]]]\n" unless $port && $n && $window;
die "N is at most 65536 (the DNS id is the number of the query)\n" if $n > 65536;
$resend_s //= 0;
$wait_s //= 5;
$batch ||= 16;
$pause_ms //= 0;

socket(my $s, PF_INET, SOCK_DGRAM, 0) or die "socket: $!";
setsockopt($s, SOL_SOCKET, SO_RCVBUF, 4 * 1024 * 1024);      # (the client must not be the one that loses the answers)
setsockopt($s, SOL_SOCKET, SO_SNDBUF, 1024 * 1024);
my $dest = sockaddr_in($port, inet_aton("127.0.0.1"));
fcntl($s, F_SETFL, fcntl($s, F_GETFL, 0) | O_NONBLOCK);

sub pkt {
    my ($i) = @_;
    my $q = join('', map { chr(length($_)) . $_ } ("q$i", "example", "test")) . "\0";
    return pack("nnnnnn", $i & 0xffff, 0x0100, 1, 0, 0, 0) . $q . pack("nn", 1, 1);
}

my %pending;                                   # id => time of the last send
my ($sent, $received, $answered, $resent, $sendfail) = (0, 0, 0, 0, 0);
# xsend: a datagram counts as sent only when the kernel took it (a refused one, ENOBUFS, is counted apart: it was never on the wire)
sub xsend { my ($p) = @_; if (defined(send($s, $p, 0, $dest))) { $sent++; return 1; } $sendfail++; return 0; }
my %seen;
my $buf;
sub drain {
    my $got = 0;
    while (defined(recv($s, $buf, 4096, 0))) {
        next if length($buf) < 12;
        my ($id, $fl) = unpack("nn", $buf);
        next unless $fl & 0x8000;
        $received++;
        $got++;
        if (!$seen{$id}++) { $answered++; }
        delete $pending{$id};
    }
    return $got;
}

my $t0 = time;
my $next = 1;
my $end_sent;
my $last_resend = time;
my $last_move = time;
while (1) {
    my $moved = 0;
    for (my $b = 0; $b < $batch && $next <= $n && keys(%pending) < $window; $b++) {
        my $i = $next++;
        $pending{$i & 0xffff} = time;
        xsend(pkt($i));
        $moved++;
    }
    $moved += drain();
    if ($next > $n && !defined $end_sent) {
        $end_sent = time;
        kill('CONT', $cont_pid) if $cont_pid;
    }
    if ($resend_s > 0 && time - $last_resend > 0.2) {
        $last_resend = time;
        for my $id (keys %pending) {
            next if time - $pending{$id} < $resend_s;
            $pending{$id} = time;
            xsend(pkt($id));
            $resent++;
            $moved++;
        }
    }
    last if time - $t0 > 120;                    # (a server that does not answer at all: do not run for ever)
    last if $next > $n && !%pending;
    last if defined $end_sent && (time - $end_sent > $wait_s || ($resend_s == 0 && time - $last_move > 1.5));   # (without resends: nothing came for 1.5 s)
    if ($moved) { $last_move = time; }
    if ($pause_ms > 0) { sleep($pause_ms / 1000); } elsif (!$moved) { sleep(0.0005); }
}
# the answers that are still on their way (a resent query is answered twice, the second one may be late) are counted too: the test adds up every datagram
for (my $q0 = time; time - $q0 < 2; ) { $q0 = time if drain(); sleep(0.01); }
my $secs = time - $t0;
printf("sent=%d received=%d answered=%d unanswered=%d resent=%d sendfail=%d secs=%.2f\n", $sent, $received, $answered, $n - $answered, $resent, $sendfail, $secs);
exit(0);
