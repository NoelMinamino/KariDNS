#!/usr/bin/perl
# lib_xfr_ext_probe.pl - send one zone transfer request over TCP that carries the KariDNS extension option (EDNS option 65153) of a
# chosen version, from a chosen source address, and print what came back:
#
#   perl tests/lib_xfr_ext_probe.pl SERVER PORT SOURCE ZONE VERSION [AXFR|IXFR] [SERIAL]
#
# VERSION is the Extended AXFR version the requester claims (2 = a version 2 secondary, 3 = this version, 0 = no option at all).
# Output, one line:
#   rcode=<n> ext=<version of the option in the first response|none> soa=<SOA RRs outside CLASS 65302 in the transfer> \
#   seq=<record sequence> settings=<text of the SETTINGS record, | for a newline|none> soaset=<flags/count|none>
# seq: S = a SOA, <type> = a CLASS 65302 record of that TYPE (65401-65409), r = other RRs (consecutive ones count once).
# TYPE 65406 wrappers are listed as "65406(<orig type>)".  No dependencies beyond core Perl.
use strict;
use warnings;
use IO::Socket::INET;

my ($server, $port, $src, $zone, $ver, $kind, $serial) = @ARGV;
$kind ||= 'AXFR';
die "usage: $0 SERVER PORT SOURCE ZONE VERSION [AXFR|IXFR] [SERIAL]\n" unless defined $ver;

my $sock = IO::Socket::INET->new(PeerAddr => $server, PeerPort => $port, LocalAddr => $src, Proto => 'tcp', Timeout => 5)
    or die "connect: $!\n";

sub qname { my $n = shift; $n =~ s/\.$//; return join('', map { pack('C a*', length($_), $_) } split(/\./, $n)) . "\0"; }

# FNV-1a of the lower-cased zone name with its final dot, as calc_fnv1a_str() computes it
sub fnv { my $s = lc(shift); my $h = 2166136261; for my $c (unpack('C*', $s)) { $h ^= $c; $h = ($h * 16777619) & 0xFFFFFFFF; } return $h; }

my $qt = $kind eq 'IXFR' ? 251 : 252;
my $z = $zone; $z .= '.' unless $z =~ /\.$/;
my $msg = pack('n n n n n n', 0x4243, 0x0000, 1, 0, ($kind eq 'IXFR' ? 1 : 0), 1) . qname($zone) . pack('n n', $qt, 1);
if ($kind eq 'IXFR') {
    $msg .= qname($zone) . pack('n n N n', 6, 1, 0, 22) . "\0\0" . pack('N5', $serial // 1, 0, 0, 0, 0);
}
my $opts = pack('n n', 9, 0);                                              # EXPIRE query (RFC 7314)
$opts .= pack('n n C N', 65153, 5, $ver, fnv($z)) if $ver;
$msg .= "\0" . pack('n n N n', 41, 4096, 0, length($opts)) . $opts;
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

sub skip_name {
    my ($d, $off) = @_;
    while (1) {
        my $l = ord(substr($d, $off, 1));
        if ($l == 0) { return $off + 1; }
        if (($l & 0xC0) == 0xC0) { return $off + 2; }
        $off += 1 + $l;
    }
}

my ($first_rcode, $ext, $settings, $soaset) = (undef, 'none', 'none', 'none');
my ($soas, $msgs) = (0, 0);
my @seq;
READ: while (1) {
    my $lenb = read_exact(2);
    last unless defined $lenb;
    my $d = read_exact(unpack('n', $lenb));
    last unless defined $d;
    $msgs++;
    my ($id, $flags, $qd, $an, $ns, $ar) = unpack('n n n n n n', $d);
    my $rcode = $flags & 0xF;
    $first_rcode = $rcode if $msgs == 1;
    my $off = 12;
    for (1 .. $qd) { $off = skip_name($d, $off) + 4; }
    for my $i (1 .. $an + $ns + $ar) {
        $off = skip_name($d, $off);
        my ($type, $class, $ttl, $rdlen) = unpack('n n N n', substr($d, $off, 10));
        $off += 10;
        my $rd = substr($d, $off, $rdlen);
        if ($i <= $an) {
            if ($class == 65302) {
                my $tag = $type;
                if ($type == 65406 && $rdlen >= 2) { $tag = sprintf('65406(%d)', unpack('n', $rd)); }
                if ($type == 65408) { ($settings = $rd) =~ s/\n/|/g; }
                if ($type == 65409 && $rdlen == 3) { $soaset = sprintf('%d/%d', ord($rd), unpack('n', substr($rd, 1, 2))); }
                push @seq, $tag;
            } elsif ($type == 6) {
                $soas++;
                push @seq, 'S';
            } elsif (!@seq || $seq[-1] ne 'r') {
                push @seq, 'r';
            }
        }
        if ($type == 41 && $msgs == 1) {
            my $o = 0;
            while ($o + 4 <= $rdlen) {
                my ($code, $len) = unpack('n n', substr($rd, $o, 4));
                $ext = ord(substr($rd, $o + 4, 1)) if $code == 65153 && $len >= 1;
                $o += 4 + $len;
            }
        }
        $off += $rdlen;
    }
    last READ if $rcode != 0;
    last READ if $soas >= 2 || ($kind eq 'IXFR' && $soas >= 1 && $an == 1);
}
printf("rcode=%s ext=%s soa=%d seq=%s settings=%s soaset=%s\n", $first_rcode // 'none', $ext, $soas, join(',', @seq), $settings,
       $soaset);
