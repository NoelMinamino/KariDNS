#!/usr/bin/perl
# xfer_stress.pl - the zone transfer client of tests/run_db_xfer_test.sh: AXFR (and IXFR from an old serial) of zones chosen at random, for a number of
# seconds, each transfer checked: the first and the last RR are the SOA, and the number of RRs is what the database holds.
#
#   xfer_stress.pl HOST PORT NZONES NHOSTS SECONDS SEED
#
# Zone z (0-based) is "zNNNN.test." (4 digits), a zone of NHOSTS host records plus SOA, NS and the address of the name server (NHOSTS + 3 RRs without
# the second SOA).  Prints one line: "ok=N bad=N servfail=N refused=N other=N".  ok: a complete transfer; bad: a transfer that ended with the wrong number
# of RRs or without the closing SOA (a failure of the test); servfail: the one error message of RFC 5936 2.2 with SERVFAIL (the zone could not be had
# in time); refused / other: the rest.
use strict;
use warnings;
use Socket;
use IO::Select;
use Time::HiRes qw(time);
$| = 1;
my ($host, $port, $nz, $nh, $secs, $seed) = @ARGV;
die "usage\n" unless defined $secs;
srand($seed // 1);

sub qname {
    my ($name, $qt, $id, $soa_serial) = @_;
    my $q = pack('nnnnnn', $id, 0x0100, 1, 0, defined $soa_serial ? 1 : 0, 0);
    my $n = '';
    $n .= pack('C', length $_) . $_ for split /\./, $name;
    $n .= "\0";
    $q .= $n . pack('nn', $qt, 1);
    if (defined $soa_serial) {
        my $rd = "\3ns1\0\4host\0" . pack('NNNNN', $soa_serial, 3600, 600, 86400, 300);
        $q .= "\xC0\x0C" . pack('nnNn', 6, 1, 0, length $rd) . $rd;
    }
    return $q;
}
sub skip_name {
    my ($m, $p) = @_;
    while (1) {
        return undef if $p >= length $m;
        my $l = ord(substr($m, $p, 1));
        if (($l & 0xC0) == 0xC0) { return $p + 2; }
        return $p + 1 if $l == 0;
        $p += 1 + $l;
    }
}

# one transfer; returns (status, rrs).  status: ok / bad / servfail / refused / other
sub transfer {
    my ($zone, $qt, $serial) = @_;
    socket(my $s, PF_INET, SOCK_STREAM, 0) or return ('other', 0);
    connect($s, sockaddr_in($port, inet_aton($host))) or return ('other', 0);
    my $q = qname($zone, $qt, 0x1234, $serial);
    syswrite($s, pack('n', length $q) . $q);
    my $sel = IO::Select->new($s);
    my $deadline = time() + 20;
    my ($rrs, $soas, $first_soa, $last_type) = (0, 0, 0, 0);
    my $status = 'other';
    while (time() < $deadline) {
        my $hdr = '';
        while (length $hdr < 2) {
            $sel->can_read(1) or last;
            my $n = sysread($s, my $c, 2 - length $hdr);
            last unless $n;
            $hdr .= $c;
        }
        last if length $hdr < 2;
        my $len = unpack('n', $hdr);
        my $msg = '';
        while (length $msg < $len) {
            $sel->can_read(1) or last;
            my $n = sysread($s, my $c, $len - length $msg);
            last unless $n;
            $msg .= $c;
        }
        last if length $msg < $len;
        my $rcode = unpack('n', substr($msg, 2, 2)) & 0xF;
        if ($rcode != 0) {
            $status = $rcode == 2 ? 'servfail' : $rcode == 5 ? 'refused' : 'other';
            close $s;
            return ($status, 0);
        }
        my ($qd, $an) = unpack('nn', substr($msg, 4, 4));
        my $p = 12;
        for (1 .. $qd) { $p = skip_name($msg, $p); last unless defined $p; $p += 4; }
        for my $i (1 .. $an) {
            $p = skip_name($msg, $p);
            last unless defined $p;
            my ($type, $class, $ttl, $rdlen) = unpack('nnNn', substr($msg, $p, 10));
            $p += 10 + $rdlen;
            $rrs++;
            $last_type = $type;
            if ($type == 6) { $soas++; $first_soa = 1 if $rrs == 1; }
        }
        if ($soas >= 2) {                                   # the closing SOA: a full transfer
            close $s;
            return ($first_soa && $last_type == 6 && $rrs == $nh + 3 + 1 ? 'ok' : 'bad', $rrs);
        }
        if ($qt == 251 && $rrs == 1 && $soas == 1) {        # the first message holds one SOA only: the answer to a client that is up to date (RFC 1995 2)
            close $s;
            return ('ok1', 1);
        }
    }
    close $s;
    return ($status, $rrs);

}

my %c = (ok => 0, ok1 => 0, bad => 0, servfail => 0, refused => 0, other => 0);
my $end = time() + $secs;
while (time() < $end) {
    my $z = int(rand($nz));
    my $name = sprintf('z%04d.test.', $z);
    my $kind = int(rand(4));
    my ($st, $n);
    if ($kind == 0) { ($st, $n) = transfer($name, 251, 1) }                 # IXFR from a version the zone never had: the whole zone
    elsif ($kind == 1) { ($st, $n) = transfer($name, 251, 7) }              # IXFR from the current version (serial 7): one SOA
    else { ($st, $n) = transfer($name, 252, undef) }
    $c{$st}++;
    print STDERR "bad transfer of $name (kind $kind): $n RRs\n" if $st eq 'bad';
}
printf "ok=%d ok1=%d bad=%d servfail=%d refused=%d other=%d\n", $c{ok}, $c{ok1}, $c{bad}, $c{servfail}, $c{refused}, $c{other};
