#!/usr/bin/perl
# mock_notify_sink.pl - NOTIFY receiver that records where each NOTIFY came from (tests/run_xfr_sources_test.sh).
#
#   mock_notify_sink.pl --log FILE --ports P1,P2,... [--ports6 P3,...] [--bind ADDR:P4,...] [--key NAME:BASE64 ...] [--answer]
#
# Listens on 127.0.0.1 UDP ports P1.. (on ::1 for --ports6, and on the given addresses for --bind) and appends one line per NOTIFY (opcode 4) to FILE:
#   NOTIFY port=P src=SOURCE-ADDRESS qname=Q tsig=T t=SECONDS-SINCE-THE-EPOCH
# T is none (no TSIG), or NAME:ok / NAME:badsig / NAME:unknown -- the key name of the TSIG record and whether its HMAC-SHA256 (RFC 8945 §4.3.3, a request) is
# right for the secret given with --key NAME:BASE64 (unknown: no such --key).
# SOURCE-ADDRESS is the address the datagram came from, i.e. the notify-source the sender bound.  With --answer the NOTIFY is answered
# (QR set, same ID and question) so the sender stops retransmitting; without it nothing is answered.
use strict;
use warnings;
use IO::Socket::IP;
use IO::Select;
use Time::HiRes qw(time);
use Getopt::Long;
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(decode_base64);

my ($logfile, $ports, $ports6, $answer, $bind, @keyspecs);
GetOptions('log=s' => \$logfile, 'ports=s' => \$ports, 'ports6=s' => \$ports6, 'bind=s' => \$bind, 'key=s' => \@keyspecs,
           'answer' => \$answer) or die "usage\n";
my %secret = map { my ($n, $b) = split /:/, $_, 2; (lc $n => decode_base64($b)) } @keyspecs;
open(my $log, '>>', $logfile) or die "log: $!";
select((select($log), $| = 1)[0]);

sub dec_name {   # (packet, offset) -> lowercase text without the trailing dot
    my ($p, $off) = @_;
    my @l;
    my $hops = 0;
    while ($off < length $p) {
        my $len = ord substr($p, $off, 1);
        if (($len & 0xC0) == 0xC0) {
            $off = (($len & 0x3F) << 8) | ord substr($p, $off + 1, 1);
            return undef if ++$hops > 20;
            next;
        }
        last if $len == 0;
        push @l, lc substr($p, $off + 1, $len);
        $off += 1 + $len;
    }
    return join('.', @l);
}

sub skip_name {   # (packet, offset) -> the offset after the name field
    my ($p, $off) = @_;
    while ($off < length $p) {
        my $len = ord substr($p, $off, 1);
        return $off + 2 if ($len & 0xC0) == 0xC0;
        return $off + 1 if $len == 0;
        $off += 1 + $len;
    }
    return undef;
}

sub wire_name {   # canonical (lower case) wire format, RFC 4034 section 6.2
    my $n = lc shift;
    $n =~ s/\.$//;
    return join('', map { chr(length $_) . $_ } split /\./, $n) . "\0";
}

# The TSIG record of a request (RFC 8945 section 4.3.3, no prior MAC): "none", or "NAME:ok" / "NAME:badsig" / "NAME:unknown"
sub tsig_state {
    my ($p) = @_;
    return 'none' if length($p) < 12;
    my ($id, $fl, $qd, $an, $ns, $ar) = unpack('n6', $p);
    return 'none' if $ar == 0;
    my $off = 12;
    for (1 .. $qd) { $off = skip_name($p, $off); return 'none' unless defined $off; $off += 4; }
    my ($tstart, $rdoff, $rdlen);
    for (1 .. $an + $ns + $ar) {
        my $start = $off;
        $off = skip_name($p, $off);
        return 'none' if !defined $off || $off + 10 > length $p;
        my ($type, $class, $ttl, $len) = unpack('nnNn', substr($p, $off, 10));
        ($tstart, $rdoff, $rdlen) = ($start, $off + 10, $len) if $type == 250;
        $off += 10 + $len;
    }
    return 'none' unless defined $tstart;
    my $keyname = dec_name($p, $tstart);
    my $alg = dec_name($p, $rdoff);
    my $aend = skip_name($p, $rdoff);
    my $time6 = substr($p, $aend, 6);
    my ($fudge, $maclen) = unpack('nn', substr($p, $aend + 6, 4));
    my $mac = substr($p, $aend + 10, $maclen);
    my ($origid, $err, $olen) = unpack('nnn', substr($p, $aend + 10 + $maclen, 6));
    my $other = substr($p, $aend + 16 + $maclen, $olen);
    return "$keyname:unknown" unless defined $secret{$keyname};
    my $msg = pack('n6', $origid, $fl, $qd, $an, $ns, $ar - 1) . substr($p, 12, $tstart - 12);
    my $vars = wire_name($keyname) . pack('nN', 255, 0) . wire_name($alg) . $time6 . pack('nnn', $fudge, $err, $olen) . $other;
    my $want = hmac_sha256($msg . $vars, $secret{$keyname});
    my $ok = $alg eq 'hmac-sha256' && $maclen > 0 && substr($want, 0, $maclen) eq $mac;
    return "$keyname:" . ($ok ? 'ok' : 'badsig');
}

my $sel = IO::Select->new;
my %port_of;
my @specs = ([$ports, '127.0.0.1'], [$ports6, '::1']);
push @specs, map { /^(.*):(\d+)$/ ? [$2, $1] : die "bad --bind $_\n" } split /,/, $bind if defined $bind;
for my $spec (@specs) {
    my ($list, $addr) = @$spec;
    next unless defined $list;
    for my $port (split /,/, $list) {
        my $s = IO::Socket::IP->new(LocalHost => $addr, LocalPort => $port, Proto => 'udp', ReuseAddr => 1) or die "bind $addr $port: $!";
        $sel->add($s);
        $port_of{fileno $s} = $port;
    }
}
print STDERR "READY\n";
while (my @ready = $sel->can_read) {
    for my $s (@ready) {
        my $buf;
        my $peer = $s->recv($buf, 4096) // next;
        next if length($buf) < 12;
        my ($id, $flags, $qd) = unpack('n3', $buf);
        next unless (($flags >> 11) & 0x0F) == 4;
        my $ip = $s->peerhost;
        $ip =~ s/^::ffff://i;
        my $q = dec_name($buf, 12);
        printf $log "NOTIFY port=%d src=%s qname=%s tsig=%s t=%.3f\n", $port_of{fileno $s}, $ip, defined $q ? $q : '?', tsig_state($buf), time;
        if ($answer) {
            # header: ID, flags (QR, AA, opcode NOTIFY), QDCOUNT 1; the question is copied
            my $qend = 12;
            while ($qend < length $buf && ord substr($buf, $qend, 1) != 0) { $qend += 1 + ord substr($buf, $qend, 1); }
            $qend += 5;
            my $reply = pack('n6', $id, 0x8000 | 0x0400 | (4 << 11), 1, 0, 0, 0) . substr($buf, 12, $qend - 12);
            $s->send($reply, 0, $peer);
        }
    }
}
