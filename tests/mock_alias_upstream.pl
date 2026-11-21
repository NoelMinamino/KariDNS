#!/usr/bin/perl
# ==============================================================================
# mock_alias_upstream.pl - a small recursive-resolver stand-in for the ALIAS tests (milestone B9a; DNS Cookies 0.7).
#
#   perl tests/mock_alias_upstream.pl --port N --data FILE [--down FILE] [--log FILE] [--cookies] [--cookie-log FILE]
#
# UDP and TCP on 127.0.0.1:N.  FILE is read again for every query:
#   <name> A|AAAA|CNAME <ttl> <value>      a record (value: address, or a target name for CNAME)
#   nxdomain <name>                        RCODE 3
#   servfail <name>                        RCODE 2
#   refused <name>                         RCODE 5
#   trunc <name>                           UDP: TC=1 and nothing else; TCP: the answer in full
# With --cookies (RFC 7873) every response to a query with a COOKIE option carries the client cookie of the query and a 16-octet server
# cookie ("MOCKSRVR" + 4 zero octets + a 32-bit epoch, RFC 9018's size), and these lines apply too:
#   spoof <name>                           UDP: before the answer, a forged one (first A 192.0.2.99) with another client cookie
#   downgrade <name>                       UDP: once this server has sent a cookie, a forged answer (first A 192.0.2.98) without any
#                                          COOKIE option comes before the real one
#   badcookie <name>                       the first query for each type of the name gets BADCOOKIE (RCODE 23) with a new server
#                                          cookie (the epoch goes up); a query that carries that server cookie is answered
# Without --cookies no OPT RR is sent (a resolver without cookies).
# A query for a name with a CNAME is answered with the CNAME chain (at most 10 links) and the records of the final name, like
# a recursive resolver; a name with nothing is NOERROR without data.  While the file given by --down exists no UDP query is
# answered and a TCP connection is closed at once.  Every query is appended to --log as "<name> <type> udp|tcp"; with --cookie-log
# also there as "<name> <type> udp|tcp cc=<16 hex digits or -> sc=<length of the server cookie of the query> cur=yes|no <what was sent>"
# (cur: the query carried the server cookie in force, after a BADCOOKIE the new one), what being answer, badcookie, spoof+answer or
# downgrade+answer.
# ==============================================================================
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my ($port, $data, $down, $logf, $cookies, $cklog) = (0, '', '', '', 0, '');
GetOptions('port=i' => \$port, 'data=s' => \$data, 'down=s' => \$down, 'log=s' => \$logf, 'cookies' => \$cookies, 'cookie-log=s' => \$cklog)
    or die "usage\n";
die "--port and --data are required\n" unless $port && $data;

my $udp = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die "udp: $!\n";
my $tcp = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'tcp', Listen => 10, ReuseAddr => 1) or die "tcp: $!\n";
my $sel = IO::Select->new($udp, $tcp);
$| = 1;

my $epoch = 1;           # the server cookie changes when it goes up (badcookie)
my $cookie_sent = 0;     # responses with a cookie sent so far (downgrade waits for one)
my %bc_done;             # "<name> <type>" that got their BADCOOKIE

sub is_down { return $down ne '' && -e $down; }

sub logline {
    my ($f, $line) = @_;
    return unless $f ne '';
    if (open(my $fh, '>>', $f)) { print $fh "$line\n"; close $fh; }
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
    my (%rr, %special, %mod);
    if (open(my $fh, '<', $data)) {
        while (my $line = <$fh>) {
            chomp $line;
            $line =~ s/^\s+//;
            next if $line eq '' || $line =~ /^#/;
            my @f = split /\s+/, $line;
            if ($f[0] =~ /^(nxdomain|servfail|refused|trunc)$/) { $special{lc $f[1]} = $f[0]; next; }
            if ($f[0] =~ /^(spoof|downgrade|badcookie)$/) { $mod{lc $f[1]} = $f[0]; next; }
            my ($n, $t, $ttl, $v) = @f;
            push @{ $rr{lc $n}{uc $t} }, [$ttl, $v];
        }
        close $fh;
    }
    return (\%rr, \%special, \%mod);
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

sub server_cookie { return pack('a8 N N', 'MOCKSRVR', 0, $epoch); }

# the client and server cookie of the COOKIE option of a query (RFC 7873 section 4): () when there is none
sub query_cookie {
    my ($req, $off) = @_;   # $off: the end of the question
    return () unless length($req) >= $off + 11 && unpack('n', substr($req, 10, 2)) >= 1;
    return () unless ord(substr($req, $off, 1)) == 0 && unpack('n', substr($req, $off + 1, 2)) == 41;
    my $p = $off + 11;
    my $end = $p + unpack('n', substr($req, $off + 9, 2));
    $end = length($req) if $end > length($req);
    while ($p + 4 <= $end) {
        my ($code, $len) = unpack('n n', substr($req, $p, 4));
        $p += 4;
        last if $p + $len > $end;
        return (substr($req, $p, 8), substr($req, $p + 8, $len - 8)) if $code == 10 && $len >= 8 && $len <= 40;
        $p += $len;
    }
    return ();
}

# the OPT RR with a COOKIE option; $ext = the upper 8 bits of the RCODE (RFC 6891 section 6.1.3)
sub opt_rr {
    my ($cc, $sc, $ext) = @_;
    my $o = pack('n n', 10, length($cc . $sc)) . $cc . $sc;
    return "\0" . pack('n n C C n n', 41, 1232, $ext, 0, 0, length($o)) . $o;
}

# (header fields, question, body, ancount) of the answer; $fake replaces the first A address
sub build {
    my ($qname, $qtype, $over_tcp, $rr, $special, $fake) = @_;
    my ($rcode, $tc, $body, $an) = (0, 0, '', 0);
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
                my $v = $e->[1];
                if (defined $fake && $t eq 'A') { $v = $fake; undef $fake; }
                $body .= rr_bytes($cur, $t, $e->[0], $v);
                $an++;
            }
        }
    }
    return ($rcode, $tc, $body, $an);
}

sub packet {
    my ($id, $flags, $question, $rcode, $tc, $an, $body, $opt) = @_;
    my $rd = $flags & 0x0100;
    return pack('n', $id) . pack('C C', 0x80 | 0x04 | ($tc ? 0x02 : 0) | ($rd ? 0x01 : 0), 0x80 | ($rcode & 15))
         . pack('n n n n', 1, $an, 0, $opt ne '' ? 1 : 0) . $question . $body . $opt;
}

# the responses to one query, in the order they are sent (the last one is the real answer)
sub answer {
    my ($req, $over_tcp) = @_;
    return () if length($req) < 12;
    my ($id, $flags, $qd) = unpack('n n n', $req);
    return () unless $qd == 1;
    my ($qname, $off) = dec_name($req, 12);
    my ($qtype) = unpack('n', substr($req, $off, 2));
    my $question = substr($req, 12, $off + 4 - 12);
    my $how = $over_tcp ? 'tcp' : 'udp';
    logline($logf, "$qname $qtype $how");
    my ($rr, $special, $mod) = load_data();
    my ($rcode, $tc, $body, $an) = build($qname, $qtype, $over_tcp, $rr, $special, undef);
    my ($cc, $sc) = $cookies ? query_cookie($req, $off + 4) : ();
    if (!defined $cc) {
        logline($cklog, "$qname $qtype $how cc=- sc=0 cur=no answer") if $cookies;
        return (packet($id, $flags, $question, $rcode, $tc, $an, $body, ''));
    }
    my $m = $mod->{$qname} // '';
    my $what = 'answer';
    my @out;
    if ($m eq 'badcookie' && !$bc_done{"$qname $qtype"}) {
        $bc_done{"$qname $qtype"} = 1;
        $epoch++;
        logline($cklog, "$qname $qtype $how cc=" . unpack('H*', $cc) . " sc=" . length($sc) . " cur=" . ($sc eq server_cookie() ? "yes" : "no") . " badcookie");
        return (packet($id, $flags, $question, 23, 0, 0, '', opt_rr($cc, server_cookie(), 1)));   # RFC 7873 section 8: 23 = 16 * 1 + 7
    }
    if (!$over_tcp && $m eq 'spoof') {
        my (undef, undef, $fb, $fa) = build($qname, $qtype, 0, $rr, $special, '192.0.2.99');
        push @out, packet($id, $flags, $question, $rcode, $tc, $fa, $fb, opt_rr($cc ^ ("\xFF" x 8), server_cookie(), 0));
        $what = 'spoof+answer';
    } elsif (!$over_tcp && $m eq 'downgrade' && $cookie_sent > 0) {
        my (undef, undef, $fb, $fa) = build($qname, $qtype, 0, $rr, $special, '192.0.2.98');
        push @out, packet($id, $flags, $question, $rcode, $tc, $fa, $fb, '');
        $what = 'downgrade+answer';
    }
    logline($cklog, "$qname $qtype $how cc=" . unpack('H*', $cc) . " sc=" . length($sc) . " cur=" . ($sc eq server_cookie() ? "yes" : "no") . " $what");
    push @out, packet($id, $flags, $question, $rcode, $tc, $an, $body, opt_rr($cc, server_cookie(), 0));
    $cookie_sent++;
    return @out;
}

my %tcpbuf;
while (1) {
    for my $s ($sel->can_read(0.5)) {
        if ($s == $udp) {
            my $req;
            my $peer = $udp->recv($req, 4096);
            next unless defined $peer && length($req);
            next if is_down();
            $udp->send($_, 0, $peer) for answer($req, 0);
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
                my @res = answer($req, 1);
                syswrite($s, pack('n', length($res[-1])) . $res[-1]) if @res;
            }
        }
    }
}
