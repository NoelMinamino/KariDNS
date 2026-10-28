#!/usr/bin/perl
# mock_notify_sink.pl - NOTIFY receiver that records where each NOTIFY came from (tests/run_xfr_sources_test.sh).
#
#   mock_notify_sink.pl --log FILE --ports P1,P2,... [--ports6 P3,...] [--answer]
#
# Listens on 127.0.0.1 UDP ports P1.. (and on ::1 for --ports6) and appends one line per NOTIFY (opcode 4) to FILE:
#   NOTIFY port=P src=SOURCE-ADDRESS qname=Q t=SECONDS-SINCE-THE-EPOCH
# SOURCE-ADDRESS is the address the datagram came from, i.e. the notify-source the sender bound.  With --answer the NOTIFY is answered
# (QR set, same ID and question) so the sender stops retransmitting; without it nothing is answered.
use strict;
use warnings;
use IO::Socket::IP;
use IO::Select;
use Time::HiRes qw(time);
use Getopt::Long;

my ($logfile, $ports, $ports6, $answer);
GetOptions('log=s' => \$logfile, 'ports=s' => \$ports, 'ports6=s' => \$ports6, 'answer' => \$answer) or die "usage\n";
open(my $log, '>>', $logfile) or die "log: $!";
select((select($log), $| = 1)[0]);

sub dec_name {   # (packet, offset) -> lowercase text without the trailing dot
    my ($p, $off) = @_;
    my @l;
    my $hops = 0;
    while ($off < length $p) {
        my $len = ord substr($p, $off, 1);
        if (($len & 0xC0) == 0xC0) {
            $off = (($len & 0x3F) << 8) | ord substr($p, $off + 1, 1);
            return undef if ++$hops > 20;
            next;
        }
        last if $len == 0;
        push @l, lc substr($p, $off + 1, $len);
        $off += 1 + $len;
    }
    return join('.', @l);
}

my $sel = IO::Select->new;
my %port_of;
for my $spec ([$ports, '127.0.0.1'], [$ports6, '::1']) {
    my ($list, $addr) = @$spec;
    next unless defined $list;
    for my $port (split /,/, $list) {
        my $s = IO::Socket::IP->new(LocalHost => $addr, LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die "bind $addr $port: $!";
        $sel->add($s);
        $port_of{fileno $s} = $port;
    }
}
print STDERR "READY\n";
while (my @ready = $sel->can_read) {
    for my $s (@ready) {
        my $buf;
        my $peer = $s->recv($buf, 4096) // next;
        next if length($buf) < 12;
        my ($id, $flags, $qd) = unpack('n3', $buf);
        next unless (($flags >> 11) & 0x0F) == 4;
        my $ip = $s->peerhost;
        $ip =~ s/^::ffff://i;
        my $q = dec_name($buf, 12);
        printf $log "NOTIFY port=%d src=%s qname=%s t=%.3f\n", $port_of{fileno $s}, $ip, defined $q ? $q : '?', time;
        if ($answer) {
            # header: ID, flags (QR, AA, opcode NOTIFY), QDCOUNT 1; the question is copied
            my $qend = 12;
            while ($qend < length $buf && ord substr($buf, $qend, 1) != 0) { $qend += 1 + ord substr($buf, $qend, 1); }
            $qend += 5;
            my $reply = pack('n6', $id, 0x8000 | 0x0400 | (4 << 11), 1, 0, 0, 0) . substr($buf, 12, $qend - 12);
            $s->send($reply, 0, $peer);
        }
    }
}
