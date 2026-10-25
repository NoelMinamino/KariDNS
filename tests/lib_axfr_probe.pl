#!/usr/bin/perl
# lib_axfr_probe.pl - send one zone transfer request over TCP from a chosen source address and print the shape of the
# FIRST response message: "rcode=<n> aa=<0|1> an=<count> ede=<code|none> soa=<number of SOA RRs in the whole transfer>"
#
#   perl tests/lib_axfr_probe.pl SERVER PORT SOURCE ZONE [AXFR|IXFR] [SERIAL]
#
# It reads messages until the closing SOA (or an error response) and counts the SOA RRs, so a test can tell "refused"
# from "transferred" and see that exactly two SOAs (opening and closing) were sent. No dependencies beyond core Perl.
use strict;
use warnings;
use IO::Socket::INET;

my ($server, $port, $src, $zone, $kind, $serial) = @ARGV;
$kind ||= 'AXFR';
die "usage: $0 SERVER PORT SOURCE ZONE [AXFR|IXFR] [SERIAL]\n" unless defined $zone;

my $sock = IO::Socket::INET->new(PeerAddr => $server, PeerPort => $port, LocalAddr => $src, Proto => 'tcp', Timeout => 5)
    or die "connect: $!\n";

sub qname { my $n = shift; $n =~ s/\.$//; return join('', map { pack('C a*', length($_), $_) } split(/\./, $n)) . "\0"; }

my $qt = $kind eq 'IXFR' ? 251 : 252;
my $msg = pack('n n n n n n', 0x4242, 0x0000, 1, 0, ($kind eq 'IXFR' ? 1 : 0), 1) . qname($zone) . pack('n n', $qt, 1);
if ($kind eq 'IXFR') {
    $msg .= qname($zone) . pack('n n N n', 6, 1, 0, 22) . "\0\0" . pack('N5', $serial // 1, 0, 0, 0, 0);
}
$msg .= "\0" . pack('n n N n', 41, 4096, 0, 0);    # OPT, so that a refusal can carry an EDE
$sock->print(pack('n', length($msg)) . $msg);

sub read_exact {
    my $want = shift;
    my $buf = '';
    while (length($buf) < $want) {
        my $got = $sock->read(my $chunk, $want - length($buf));
        return undef unless $got;
        $buf .= $chunk;
    }
    return $buf;
}

# skip a (possibly compressed) name at $off, return the offset after it
sub skip_name {
    my ($d, $off) = @_;
    while (1) {
        my $l = ord(substr($d, $off, 1));
        if ($l == 0) { return $off + 1; }
        if (($l & 0xC0) == 0xC0) { return $off + 2; }
        $off += 1 + $l;
    }
}

my ($first_rcode, $first_aa, $first_an, $ede, $soas, $msgs) = (undef, undef, undef, 'none', 0, 0);
READ: while (1) {
    my $lenb = read_exact(2);
    last unless defined $lenb;
    my $d = read_exact(unpack('n', $lenb));
    last unless defined $d;
    $msgs++;
    my ($id, $flags, $qd, $an, $ns, $ar) = unpack('n n n n n n', $d);
    my $rcode = $flags & 0xF;
    if ($msgs == 1) { ($first_rcode, $first_aa, $first_an) = ($rcode, ($flags >> 10) & 1, $an); }
    my $off = 12;
    for (1 .. $qd) { $off = skip_name($d, $off) + 4; }
    for my $i (1 .. $an + $ns + $ar) {
        $off = skip_name($d, $off);
        my ($type, $class, $ttl, $rdlen) = unpack('n n N n', substr($d, $off, 10));
        $off += 10;
        if ($type == 6 && $i <= $an) { $soas++; }
        if ($type == 41) {
            my $o = $off;
            while ($o + 4 <= $off + $rdlen) {
                my ($code, $len) = unpack('n n', substr($d, $o, 4));
                $ede = unpack('n', substr($d, $o + 4, 2)) if $code == 15 && $len >= 2;
                $o += 4 + $len;
            }
        }
        $off += $rdlen;
    }
    last READ if $rcode != 0;
    # the transfer ends with a message whose last answer is a SOA; an AXFR with one SOA RR in total is the only exception
    last READ if $soas >= 2 || ($kind eq 'IXFR' && $soas >= 1 && $an == 1);
}
printf("rcode=%s aa=%s an=%s ede=%s soa=%d msgs=%d\n", $first_rcode // 'none', $first_aa // 'none', $first_an // 'none', $ede,
       $soas, $msgs);
