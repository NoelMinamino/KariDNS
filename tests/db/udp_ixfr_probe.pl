#!/usr/bin/perl
# udp_ixfr_probe.pl HOST PORT ZONE SERIAL - an IXFR question over UDP (RFC 1995 4.2) with the client's SOA (serial SERIAL) in Authority and an OPT record.
# Prints one line: "rcode=N tc=0|1 aa=0|1 an=N ns=N ar=N ede=N|-" (ede: the Extended DNS Error info code of the OPT record, - when none), or "timeout".
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
my ($host, $port, $zone, $serial) = @ARGV;
die "usage: udp_ixfr_probe.pl HOST PORT ZONE SERIAL\n" unless defined $serial;
my $name = join('', map { pack('C', length $_) . $_ } split /\./, $zone) . "\0";
my $q = pack('nnnnnn', 0x4a51, 0, 1, 0, 1, 1) . $name . pack('nn', 251, 1);
my $rd = "\2ns\xC0\x0C\1h\xC0\x0C" . pack('NNNNN', $serial, 0, 0, 0, 0);
$q .= "\xC0\x0C" . pack('nnNn', 6, 1, 0, length $rd) . $rd;
$q .= "\0" . pack('nnNn', 41, 1232, 0, 0);
my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "udp: $!\n";
syswrite($s, $q);
my $r;
unless (IO::Select->new($s)->can_read(5) && sysread($s, $r, 4096)) { print "timeout\n"; exit 1; }
my ($id, $fl, $qd, $an, $ns, $ar) = unpack('n6', $r);
my $ede = '-';
# walk to the OPT record (the last of the additional section) and look for option 15
my $p = 12;
for (1 .. $qd) { $p++ while ord(substr($r, $p, 1)) != 0; $p += 5; }
for my $i (1 .. $an + $ns + $ar) {
    my $l = ord(substr($r, $p, 1));
    if (($l & 0xC0) == 0xC0) { $p += 2 } else { while ($l != 0) { $p += 1 + $l; $l = ord(substr($r, $p, 1)); } $p += 1; }
    my ($type, $class, $ttl, $rdlen) = unpack('nnNn', substr($r, $p, 10));
    $p += 10;
    if ($type == 41) {
        for (my $k = $p; $k + 4 <= $p + $rdlen;) {
            my ($code, $len) = unpack('nn', substr($r, $k, 4));
            $ede = unpack('n', substr($r, $k + 4, 2)) if $code == 15 && $len >= 2;
            $k += 4 + $len;
        }
    }
    $p += $rdlen;
}
printf "rcode=%d tc=%d aa=%d an=%d ns=%d ar=%d ede=%s\n", $fl & 15, ($fl >> 9) & 1, ($fl >> 10) & 1, $an, $ns, $ar, $ede;
