#!/usr/bin/perl
# ==============================================================================
# mock_tapstat_sender.pl - helper of tests/run_tapstat_test.sh
#
#   gen-file OUT              write a Frame Streams file (START, dnstap frames, STOP) with known traffic
#   send SOCK MODE            act as a dnstap sender on tapstat's socket and check the answers
#                             MODE: good badct garbage oversize idle earlydata nofields
#   sum FILE                  add up the JSON lines of karidns-tapstat; prints name=value lines
#
# The known traffic of gen-file (what the test expects, with -z example.test,sub.example.test):
#   3 x response NOERROR  www.example.test A      from 192.0.2.10
#   2 x response NXDOMAIN nx.sub.example.test AAAA from 192.0.2.99
#   1 x response REFUSED  www.example.org A       from 2001:db8:1:2::5
#   1 x query             www.example.test A      from 192.0.2.10
# ==============================================================================
use strict;
use warnings;
use IO::Socket::UNIX;
use IO::Select;
use JSON::PP;

sub varint { my $v = shift; my $o = ''; while ($v >= 0x80) { $o .= chr(($v & 0x7f) | 0x80); $v >>= 7; } return $o . chr($v); }
sub fvar   { my ($f, $v) = @_; return varint(($f << 3) | 0) . varint($v); }
sub fbytes { my ($f, $b) = @_; return varint(($f << 3) | 2) . varint(length $b) . $b; }

sub dns {
    my ($resp, $rcode, $name, $qtype) = @_;
    my $w = join('', map { chr(length $_) . $_ } split(/\./, $name)) . "\0";
    return pack('nnnnnn', 0x1234, ($resp ? 0x8400 : 0) | $rcode, 1, 0, 0, 0) . $w . pack('nn', $qtype, 1);
}

sub frame {
    my ($type, $addr, $wire) = @_;
    my $m = fvar(1, $type) . fvar(2, length($addr) == 16 ? 2 : 1) . fvar(3, 1) . fbytes(4, $addr) . fvar(6, 5353)
          . fbytes($type == 1 ? 10 : 14, $wire);
    return fbytes(1, 'mock') . fvar(15, 1) . fbytes(14, $m);
}

my $CT = 'protobuf:dnstap.Dnstap';
sub ctl { my ($type, $withct) = @_; my $p = pack('N', $type) . ($withct ? pack('NN', 1, length $CT) . $CT : ''); return pack('NN', 0, length $p) . $p; }
sub data { my $f = shift; return pack('N', length $f) . $f; }

sub traffic {
    my @f;
    my $a1 = pack('C4', 192, 0, 2, 10);
    my $a2 = pack('C4', 192, 0, 2, 99);
    my $a6 = pack('n8', 0x2001, 0x0db8, 1, 2, 0, 0, 0, 5);
    push @f, frame(2, $a1, dns(1, 0, 'www.example.test', 1)) for 1 .. 3;
    push @f, frame(2, $a2, dns(1, 3, 'nx.sub.example.test', 28)) for 1 .. 2;
    push @f, frame(2, $a6, dns(1, 5, 'www.example.org', 1));
    push @f, frame(1, $a1, dns(0, 0, 'www.example.test', 1));
    return @f;
}

sub read_exact {
    my ($s, $n, $timeout) = @_;
    my $buf = '';
    my $sel = IO::Select->new($s);
    while (length($buf) < $n) {
        return undef unless $sel->can_read($timeout);
        my $r = sysread($s, my $chunk, $n - length($buf));
        return undef unless $r;
        $buf .= $chunk;
    }
    return $buf;
}

# 1 when the peer closes the connection within $timeout seconds
sub closed_within {
    my ($s, $timeout) = @_;
    my $sel = IO::Select->new($s);
    my $deadline = time + $timeout;
    while (time <= $deadline) {
        next unless $sel->can_read(0.2);
        my $r = sysread($s, my $c, 4096);
        return 1 if !defined($r) || $r == 0;
    }
    return 0;
}

my $cmd = shift // '';
if ($cmd eq 'gen-file') {
    my $out = shift or die "gen-file OUT\n";
    open my $fh, '>:raw', $out or die "$out: $!\n";
    print $fh ctl(2, 1), (map { data($_) } traffic()), ctl(3, 0);
    close $fh;
    exit 0;
}
if ($cmd eq 'send') {
    my ($path, $mode) = @ARGV;
    die "send SOCK MODE\n" unless $path && $mode;
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $path) or die "connect $path: $!\n";
    $s->autoflush(1);
    binmode($s);
    if ($mode eq 'good') {
        print $s ctl(4, 1);
        my $acc = read_exact($s, 42, 3);
        die "no ACCEPT\n" unless defined $acc && $acc eq ctl(1, 1);
        print $s ctl(2, 1);
        # one frame split over two writes, the rest in one
        my @f = map { data($_) } traffic();
        my $first = shift @f;
        syswrite($s, substr($first, 0, 5));
        select(undef, undef, undef, 0.2);
        syswrite($s, substr($first, 5));
        print $s join('', @f), ctl(3, 0);
        my $fin = read_exact($s, 12, 3);
        die "no FINISH\n" unless defined $fin && $fin eq ctl(5, 0);
        die "connection not closed after FINISH\n" unless closed_within($s, 3);
    } elsif ($mode eq 'badct') {
        my $p = pack('N', 4) . pack('NN', 1, 3) . 'abc';
        print $s pack('NN', 0, length $p) . $p;
        die "not closed\n" unless closed_within($s, 3);
    } elsif ($mode eq 'garbage') {
        print $s join('', map { chr(int(rand(256))) } 1 .. 4000);
        die "not closed\n" unless closed_within($s, 3);
    } elsif ($mode eq 'oversize') {
        print $s ctl(4, 1);
        read_exact($s, 42, 3);
        print $s ctl(2, 1), pack('N', 0x7fffffff);
        die "not closed\n" unless closed_within($s, 3);
    } elsif ($mode eq 'earlydata') {
        print $s data((traffic())[0]);
        die "not closed\n" unless closed_within($s, 3);
    } elsif ($mode eq 'idle') {
        die "an idle sender was not dropped\n" unless closed_within($s, 8);
    } elsif ($mode eq 'nofields') {
        # READY without a content type is accepted (ACCEPT without one), then a session
        print $s ctl(4, 0);
        my $acc = read_exact($s, 12, 3);
        die "no ACCEPT\n" unless defined $acc && $acc eq ctl(1, 0);
        print $s ctl(2, 0), data((traffic())[0]), ctl(3, 0);
        my $fin = read_exact($s, 12, 3);
        die "no FINISH\n" unless defined $fin && $fin eq ctl(5, 0);
    } else {
        die "unknown mode $mode\n";
    }
    print "OK $mode\n";
    exit 0;
}
if ($cmd eq 'sum') {
    my $file = shift or die "sum FILE\n";
    open my $fh, '<', $file or die "$file: $!\n";
    my %t;
    my $lines = 0;
    while (my $l = <$fh>) {
        my $d = decode_json($l);
        $lines++;
        $t{$_} += $d->{$_} for qw(frames bad_frames queries responses other_messages no_question malformed);
        for my $dim (keys %{ $d->{dimensions} }) {
            my $x = $d->{dimensions}{$dim};
            $t{"$dim.events"} += $x->{events};
            $t{"$dim.evictions"} += $x->{evictions};
            $t{"$dim=$_->{key}"} += $_->{count} for @{ $x->{top} };
        }
    }
    print "lines=$lines\n";
    print "$_=$t{$_}\n" for sort keys %t;
    exit 0;
}
die "usage: $0 gen-file OUT | send SOCK MODE | sum FILE\n";
