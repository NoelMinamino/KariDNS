#!/usr/bin/perl
# ==============================================================================
# mock_dag_review_server.pl - answers that KariDNS does not send, for run_dag_review_test.sh (tools review 2026-11-23)
#
#   --mode referral  every query: an unsigned referral (no TSIG) to test. NS ns1.test., glue ns1.test. A 127.0.0.1;
#                    ". NS": the answer NS ns1.test. with the same glue (RA=0).  A client with -y must not follow it (T1-M1)
#   --mode owner     ". NS": answer NS ns1.test. without glue, RA=1; "ns1.test. A": the answer evil.test. A 127.0.0.9 then
#                    ns1.test. A 127.0.0.1; other A/AAAA of ns1.test.: empty; anything else: an authoritative NXDOMAIN (T1-L2)
#   --mode badid     UDP: first a REFUSED with another ID, then the right answer (A 192.0.2.1); TCP: the answer, and for a name
#                    starting with "big" one of about 5000 bytes (T2-L2)
#   --mode good      UDP and TCP: the answer A 192.0.2.1 (and "big": the same 5000 bytes)
# Every query is logged on stdout as "Q <qname> <qtype> <udp|tcp>"; "ready" once it listens.  No real names: .test only.
# ==============================================================================
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my ($port, $mode, $host) = (15353, 'good', '127.0.0.1');
GetOptions('port=i' => \$port, 'mode=s' => \$mode, 'host=s' => \$host) or die "usage: $0 --port N --mode M\n";
my $udp = IO::Socket::INET->new(LocalAddr => $host, LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die "udp $port: $!\n";
my $tcp = IO::Socket::INET->new(LocalAddr => $host, LocalPort => $port, Proto => 'tcp', Listen => 8, ReuseAddr => 1) or die "tcp $port: $!\n";
$| = 1;
$SIG{INT} = $SIG{TERM} = sub { exit 0 };
print "ready\n";

sub name { my $b = ''; for my $l (split /\./, $_[0]) { $b .= chr(length $l) . $l if length $l } return $b . "\0" }
sub rr { my ($n, $t, $rd) = @_; return name($n) . pack('nnNn', $t, 1, 300, length $rd) . $rd }

sub parse {
    my ($m) = @_;
    return () if length($m) < 17;
    my ($off, @l) = (12);
    while ($off < length $m) {
        my $len = ord(substr($m, $off, 1));
        $off++;
        last if $len == 0;
        push @l, substr($m, $off, $len);
        $off += $len;
    }
    return () if $off + 4 > length $m;
    my $qn = join('.', @l) . '.';
    $qn = '.' if !@l;
    return (substr($m, 0, 2), $qn, unpack('n', substr($m, $off, 2)), substr($m, 12, $off + 4 - 12));
}

# header: id, flags, counts; then the question and the records
sub msg {
    my ($id, $flags, $q, $an, $ns, $ar) = @_;
    return $id . pack('nnnnn', $flags, 1, scalar @$an, scalar @$ns, scalar @$ar) . $q . join('', @$an, @$ns, @$ar);
}

sub answers {
    my ($m, $proto) = @_;
    my ($id, $qn, $qt, $q) = parse($m);
    return () unless defined $id;
    print "Q $qn $qt $proto\n";
    my $a127 = pack('C4', 127, 0, 0, 1);
    if ($mode eq 'referral') {
        my @glue = (rr('ns1.test', 1, $a127));
        return (msg($id, 0x8000, $q, [rr('.', 2, name('ns1.test'))], [], \@glue)) if $qn eq '.';
        return (msg($id, 0x8000, $q, [], [rr('test', 2, name('ns1.test'))], \@glue));
    }
    if ($mode eq 'owner') {
        return (msg($id, 0x8080, $q, [rr('.', 2, name('ns1.test'))], [], [])) if $qn eq '.';
        if (lc $qn eq 'ns1.test.') {
            return (msg($id, 0x8080, $q, [rr('evil.test', 1, pack('C4', 127, 0, 0, 9)), rr('ns1.test', 1, $a127)], [], [])) if $qt == 1;
            return (msg($id, 0x8080, $q, [], [], []));
        }
        return (msg($id, 0x8403, $q, [], [], []));
    }
    my @ans = (rr($qn, 1, pack('C4', 192, 0, 2, 1)));
    if ($qn =~ /^big/i) {
        @ans = ();
        push @ans, rr($qn, 16, chr(200) . ('x' x 200)) for 1 .. 24;   # about 5000 bytes: TCP only
    }
    my $good = msg($id, 0x8400, $q, \@ans, [], []);
    if ($mode eq 'badid' && $proto eq 'udp') {
        my $other = pack('n', unpack('n', $id) ^ 0x5a5a);
        return (msg($other, 0x8405, $q, [], [], []), $good);
    }
    return ($good);
}

sub read_n {
    my ($s, $n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $r = sysread($s, my $c, $n - length $buf);
        return undef unless $r;
        $buf .= $c;
    }
    return $buf;
}

my $sel = IO::Select->new($udp, $tcp);
while (1) {
    for my $fh ($sel->can_read()) {
        if ($fh == $udp) {
            my $peer = $udp->recv(my $buf, 65535) or next;
            for my $r (answers($buf, 'udp')) {
                next if length($r) > 1232;   # (the big answer does not go over UDP: the client asks again over TCP or not at all)
                $udp->send($r, 0, $peer);
            }
        } else {
            my $c = $tcp->accept() or next;
            my $sc = IO::Select->new($c);
            while ($sc->can_read(2)) {
                my $lb = read_n($c, 2);
                last unless defined $lb;
                my $m = read_n($c, unpack('n', $lb));
                last unless defined $m;
                my @r = answers($m, 'tcp');
                last unless @r;
                syswrite($c, pack('n', length $r[-1]) . $r[-1]);
            }
            close $c;
        }
    }
}
