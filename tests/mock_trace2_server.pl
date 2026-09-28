#!/usr/bin/perl
# ==============================================================================
# mock_trace2_server.pl - dag +trace2 用の異常系権威サーバ
#
# KariDNS では作りにくい応答を返す。run_dag_trace2_test.sh が 127.0.0.5 で起動する。
#
#   *.tc.test.        UDP: TC=1 の空応答 / TCP: A 192.0.2.10 (AA)
#   *.noedns.test.    OPT 付きクエリ: FORMERR / OPT なし: A 192.0.2.11 (AA)
#   *.deadonly.test.  応答しない (タイムアウト)
#   ". NS"            glue なしの NS a.root-servers. (最小応答のプライベートルート)
#   unrelated.alt.    SOA (起動確認用)
#   それ以外           REFUSED (lame サーバ役)
# ==============================================================================
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my $port = 15353;
my $host = '127.0.0.5';
GetOptions('port=i' => \$port, 'host=s' => \$host) or die "usage: $0 [--port N] [--host IP]\n";

my $udp = IO::Socket::INET->new(LocalAddr => $host, LocalPort => $port, Proto => 'udp', ReuseAddr => 1)
    or die "Cannot bind UDP $host:$port: $!\n";
my $tcp = IO::Socket::INET->new(LocalAddr => $host, LocalPort => $port, Proto => 'tcp', Listen => 16, ReuseAddr => 1)
    or die "Cannot bind TCP $host:$port: $!\n";
$| = 1;
$SIG{INT} = $SIG{TERM} = sub { exit 0; };

my $sel = IO::Select->new($udp, $tcp);
while (1) {
    for my $fh ($sel->can_read()) {
        if ($fh == $udp) {
            my $buf;
            my $peer = $udp->recv($buf, 65535) or next;
            my $resp = answer($buf, 0);
            $udp->send($resp, 0, $peer) if defined $resp;
        } else {
            my $c = $tcp->accept() or next;
            $c->autoflush(1);
            my $sc = IO::Select->new($c);
            while ($sc->can_read(2)) {
                my $lenb = read_n($c, 2);
                last unless defined $lenb;
                my $msg = read_n($c, unpack('n', $lenb));
                last unless defined $msg;
                my $resp = answer($msg, 1);
                last unless defined $resp;
                print $c pack('n', length $resp) . $resp;
            }
            close $c;
        }
    }
}

sub read_n {
    my ($s, $n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $r = sysread($s, my $chunk, $n - length($buf));
        return undef unless $r;
        $buf .= $chunk;
    }
    return $buf;
}

# 質問を解析して応答を作る
sub answer {
    my ($q, $is_tcp) = @_;
    return undef if length($q) < 12;
    my ($id, $flags, $qd, $an, $ns, $ar) = unpack('n6', $q);
    return undef if ($flags & 0x8000) || $qd != 1;
    my $off = 12;
    my @labels;
    while ($off < length $q) {
        my $l = ord(substr($q, $off, 1));
        $off++;
        last if $l == 0;
        return undef if $l > 63 || $off + $l > length $q;
        push @labels, lc substr($q, $off, $l);
        $off += $l;
    }
    return undef if $off + 4 > length $q;
    my ($qtype) = unpack('n', substr($q, $off, 2));
    my $question = substr($q, 12, $off + 4 - 12);
    my $name = join('.', @labels) . '.';
    my $has_opt = $ar > 0;
    my $rd = $flags & 0x0100;

    my $hdr = sub {
        my ($fl, $ancount) = @_;
        return pack('n6', $id, 0x8000 | $rd | $fl, 1, $ancount, 0, 0) . $question;
    };
    my $rr_a = sub {
        my ($ip) = @_;
        return pack('n n n N n', 0xC00C, 1, 1, 300, 4) . pack('C4', split /\./, $ip);
    };

    return undef if $name =~ /(^|\.)deadonly\.test\.$/;
    if ($name eq '.' && $qtype == 2) {
        my $rdata = "\x01a\x0Croot-servers\x00";
        return $hdr->(0x0400, 1) . pack('n n n N n', 0xC00C, 2, 1, 3600, length $rdata) . $rdata;
    }
    if ($name =~ /(^|\.)tc\.test\.$/) {
        return $hdr->(0x0200 | 0x0400, 0) unless $is_tcp;                 # TC=1 AA=1, 回答なし
        return $qtype == 1 ? $hdr->(0x0400, 1) . $rr_a->('192.0.2.10') : $hdr->(0x0400, 0);
    }
    if ($name =~ /(^|\.)noedns\.test\.$/) {
        return pack('n6', $id, 0x8000 | $rd | 1, 1, 0, 0, 0) . $question if $has_opt;   # FORMERR
        return $qtype == 1 ? $hdr->(0x0400, 1) . $rr_a->('192.0.2.11') : $hdr->(0x0400, 0);
    }
    if ($name eq 'unrelated.alt.' && $qtype == 6) {
        my $rdata = "\x02ns\xC0\x0C" . "\x0Ahostmaster\xC0\x0C" . pack('N5', 1, 3600, 900, 604800, 300);
        return $hdr->(0x0400, 1) . pack('n n n N n', 0xC00C, 6, 1, 300, length $rdata) . $rdata;
    }
    return pack('n6', $id, 0x8000 | $rd | 5, 1, 0, 0, 0) . $question;                  # REFUSED
}
