#!/usr/bin/perl
# mock_also_notify.pl - NOTIFY receivers for tests/run_also_notify_test.sh.
#
#   mock_also_notify.pl --log FILE --ports P1,P2,... [--key NAME:BASE64SECRET]...
#
# Listens on 127.0.0.1 UDP ports P1.. and logs one line per NOTIFY (opcode 4) it receives:
#   NOTIFY port=P qname=Q tsig=none|KEYNAME mac=ok|bad|nokey
# The TSIG MAC of a request is checked with the secret given for its key name: RFC 8945 section 4.3 (the digest covers the message
# without the TSIG RR, ARCOUNT decremented, the original ID, and the TSIG variables: key name, class, TTL, algorithm name, time
# signed, fudge, error, other data), HMAC-SHA256 only.  Nothing is answered (the sender retransmits on its own schedule).
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(decode_base64);
use Getopt::Long;

my ($logfile, $ports, @keys);
GetOptions('log=s' => \$logfile, 'ports=s' => \$ports, 'key=s' => \@keys) or die "usage\n";
my %secret;
for my $k (@keys) {
    my ($n, $s) = split /:/, $k, 2;
    $secret{lc $n} = decode_base64($s);
}
open(my $log, '>>', $logfile) or die "log: $!";
select((select($log), $| = 1)[0]);

sub dec_name {   # (packet, offset) -> (lowercase text without trailing dot, offset after the name in place)
    my ($p, $off) = @_;
    my @l;
    my $end;
    my $hops = 0;
    while (1) {
        return unless $off < length $p;
        my $len = ord substr($p, $off, 1);
        if (($len & 0xC0) == 0xC0) {
            $end = $off + 2 unless defined $end;
            $off = (($len & 0x3F) << 8) | ord substr($p, $off + 1, 1);
            return if ++$hops > 20;
            next;
        }
        if ($len == 0) { $end = $off + 1 unless defined $end; last; }
        push @l, lc substr($p, $off + 1, $len);
        $off += 1 + $len;
    }
    return (join('.', @l), $end);
}

sub enc_name { my $n = shift; return join('', map { chr(length $_) . $_ } split(/\./, lc $n)) . "\0"; }

my $sel = IO::Select->new;
my %port_of;
for my $port (split /,/, $ports) {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die "bind $port: $!";
    $sel->add($s);
    $port_of{fileno $s} = $port;
}
print STDERR "READY\n";
while (my @ready = $sel->can_read) {
    for my $s (@ready) {
        $s->recv(my $p, 65535, 0);
        next unless defined $p && length $p >= 12;
        my ($id, $fl, $qd, $an, $ns, $ar) = unpack 'n6', $p;
        next if $fl & 0x8000;
        next unless (($fl >> 11) & 15) == 4 && $qd == 1;
        my ($qn, $qe) = dec_name($p, 12);
        next unless defined $qn;
        my $off = $qe + 4;
        my ($tsig, $mac) = ('none', 'nokey');
        for my $i (1 .. $an + $ns + $ar) {
            my $rr_start = $off;
            my ($rn, $re) = dec_name($p, $off);
            last unless defined $rn && $re + 10 <= length $p;
            my ($t, $c, $ttl, $rl) = unpack 'nnNn', substr($p, $re, 10);
            my $rd = $re + 10;
            if ($t == 250) {
                $tsig = $rn;
                my ($alg, $ae) = dec_name($p, $rd);
                my ($thi, $tlo, $fudge, $maclen) = unpack 'nNnn', substr($p, $ae, 10);
                my $time6 = substr($p, $ae, 6);
                my $got = substr($p, $ae + 10, $maclen);
                my ($oid, $err, $olen) = unpack 'nnn', substr($p, $ae + 10 + $maclen, 6);
                my $other = substr($p, $ae + 16 + $maclen, $olen);
                my $key = $secret{lc $rn};
                if (defined $key && defined $alg && $alg eq 'hmac-sha256') {
                    my $msg = substr($p, 0, $rr_start);
                    substr($msg, 0, 2) = pack('n', $oid);
                    substr($msg, 10, 2) = pack('n', $ar - 1);
                    my $data = $msg . enc_name($rn) . pack('nN', 255, 0) . enc_name($alg) . $time6 . pack('nnn', $fudge, $err, $olen) . $other;
                    $mac = hmac_sha256($data, $key) eq $got ? 'ok' : 'bad';
                } else {
                    $mac = 'nokey';
                }
            }
            $off = $rd + $rl;
        }
        printf $log "NOTIFY port=%d qname=%s tsig=%s mac=%s\n", $port_of{fileno $s}, $qn, $tsig, $mac;
    }
}
