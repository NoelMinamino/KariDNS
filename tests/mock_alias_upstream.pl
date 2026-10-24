#!/usr/bin/perl
# ==============================================================================
# mock_alias_upstream.pl - a small recursive-resolver stand-in for the ALIAS tests (milestone B9a).
#
#   perl tests/mock_alias_upstream.pl --port N --data FILE [--down FILE] [--log FILE]
#
# UDP and TCP on 127.0.0.1:N.  FILE is read again for every query:
#   <name> A|AAAA|CNAME <ttl> <value>      a record (value: address, or a target name for CNAME)
#   nxdomain <name>                        RCODE 3
#   servfail <name>                        RCODE 2
#   refused <name>                         RCODE 5
#   trunc <name>                           UDP: TC=1 and nothing else; TCP: the answer in full
# A query for a name with a CNAME is answered with the CNAME chain (at most 10 links) and the records of the final name, like
# a recursive resolver; a name with nothing is NOERROR without data.  While the file given by --down exists no UDP query is
# answered and a TCP connection is closed at once.  Every query is appended to --log as "<name> <type> udp|tcp".
# ==============================================================================
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my ($port, $data, $down, $logf) = (0, '', '', '');
GetOptions('port=i' => \$port, 'data=s' => \$data, 'down=s' => \$down, 'log=s' => \$logf) or die "usage\n";
die "--port and --data are required\n" unless $port && $data;

my $udp = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die "udp: $!\n";
my $tcp = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'tcp', Listen => 10, ReuseAddr => 1) or die "tcp: $!\n";
my $sel = IO::Select->new($udp, $tcp);
$| = 1;

sub is_down { return $down ne '' && -e $down; }

sub logq {
    my ($name, $type, $how) = @_;
    return unless $logf ne '';
    if (open(my $fh, '>>', $logf)) { print $fh "$name $type $how\n"; close $fh; }
}

sub enc_name {
    my ($n) = @_;
    $n =~ s/\.$//;
    return "\0" if $n eq '';
    return join('', map { pack('C a*', length($_), $_) } split /\./, $n) . "\0";
}

sub dec_name {   # decode a query name (no compression in a question)
    my ($pkt, $off) = @_;
    my @l;
    while (1) {
        my $len = ord(substr($pkt, $off, 1));
        $off++;
        last if $len == 0;
        push @l, substr($pkt, $off, $len);
        $off += $len;
    }
    return (lc(join('.', @l)), $off);
}

sub load_data {
    my (%rr, %special);
    if (open(my $fh, '<', $data)) {
        while (my $line = <$fh>) {
            chomp $line;
            $line =~ s/^\s+//;
            next if $line eq '' || $line =~ /^#/;
            my @f = split /\s+/, $line;
            if ($f[0] =~ /^(nxdomain|servfail|refused|trunc)$/) { $special{lc $f[1]} = $f[0]; next; }
            my ($n, $t, $ttl, $v) = @f;
            push @{ $rr{lc $n}{uc $t} }, [$ttl, $v];
        }
        close $fh;
    }
    return (\%rr, \%special);
}

sub rr_bytes {
    my ($owner, $type, $ttl, $v) = @_;
    my ($tc, $rd);
    if ($type eq 'A') { $tc = 1; $rd = pack('C4', split /\./, $v); }
    elsif ($type eq 'AAAA') {
        $tc = 28;
        my ($l, $r) = split /::/, $v, 2;
        my @l = (defined $l && $l ne '') ? split(/:/, $l) : ();
        my @r = (defined $r && $r ne '') ? split(/:/, $r) : ();
        my @g = (@l, ($v =~ /::/ ? (('0') x (8 - @l - @r)) : ()), @r);
        $rd = pack('n8', map { hex($_) } @g);
    }
    else { $tc = 5; $rd = enc_name($v); }
    return enc_name($owner) . pack('n n N n', $tc, 1, $ttl, length($rd)) . $rd;
}

sub answer {
    my ($req, $over_tcp) = @_;
    return undef if length($req) < 12;
    my ($id, $flags, $qd) = unpack('n n n', $req);
    return undef unless $qd == 1;
    my ($qname, $off) = dec_name($req, 12);
    my ($qtype) = unpack('n', substr($req, $off, 2));
    my $question = substr($req, 12, $off + 4 - 12);
    logq($qname, $qtype, $over_tcp ? 'tcp' : 'udp');
    my ($rr, $special) = load_data();
    my $rcode = 0;
    my $tc = 0;
    my $body = '';
    my $an = 0;
    my $sp = $special->{$qname} // '';
    if ($sp eq 'nxdomain') { $rcode = 3; }
    elsif ($sp eq 'servfail') { $rcode = 2; }
    elsif ($sp eq 'refused') { $rcode = 5; }
    elsif ($sp eq 'trunc' && !$over_tcp) { $tc = 1; }
    else {
        my $cur = $qname;
        for (my $hop = 0; $hop < 10; $hop++) {
            my $cn = $rr->{$cur}{CNAME};
            last unless $cn;
            $body .= rr_bytes($cur, 'CNAME', $cn->[0][0], $cn->[0][1]);
            $an++;
            $cur = lc $cn->[0][1];
            $cur =~ s/\.$//;
        }
        my %tn = (1 => 'A', 28 => 'AAAA');
        my $t = $tn{$qtype};
        if ($t) {
            for my $e (@{ $rr->{$cur}{$t} // [] }) {
                $body .= rr_bytes($cur, $t, $e->[0], $e->[1]);
                $an++;
            }
        }
    }
    my $rd = $flags & 0x0100;
    my $hdr = pack('n', $id) . pack('C C', 0x80 | 0x04 | ($tc ? 0x02 : 0) | ($rd ? 0x01 : 0), 0x80 | $rcode) . pack('n n n n', 1, $an, 0, 0);
    return $hdr . $question . $body;
}

my %tcpbuf;
while (1) {
    for my $s ($sel->can_read(0.5)) {
        if ($s == $udp) {
            my $req;
            my $peer = $udp->recv($req, 4096);
            next unless defined $peer && length($req);
            next if is_down();
            my $res = answer($req, 0);
            $udp->send($res, 0, $peer) if defined $res;
        } elsif ($s == $tcp) {
            my $c = $tcp->accept or next;
            if (is_down()) { close $c; next; }
            $sel->add($c);
            $tcpbuf{$c} = '';
        } else {
            my $buf = '';
            my $n = sysread($s, $buf, 65535);
            if (!$n) { $sel->remove($s); delete $tcpbuf{$s}; close $s; next; }
            $tcpbuf{$s} .= $buf;
            while (length($tcpbuf{$s}) >= 2) {
                my $len = unpack('n', $tcpbuf{$s});
                last if length($tcpbuf{$s}) < 2 + $len;
                my $req = substr($tcpbuf{$s}, 2, $len);
                $tcpbuf{$s} = substr($tcpbuf{$s}, 2 + $len);
                my $res = answer($req, 1);
                syswrite($s, pack('n', length($res)) . $res) if defined $res;
            }
        }
    }
}
