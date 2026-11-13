#!/usr/bin/perl
# lib_stall_xfr_client.pl - a zone transfer client that stops reading until it is told to go on (tests/run_axfr_stall_reload_test.sh, R11).
#
#   lib_stall_xfr_client.pl --port N --zone ZONE [--type AXFR|IXFR] [--ixfr-serial N] [--key NAME:BASE64] [--go FILE] [--body FILE]
#                           [--rcvbuf N] [--count N] [--ready FILE]
#
# Connects to 127.0.0.1:PORT with a small receive buffer (--rcvbuf, default 2048), sends one AXFR (or IXFR with the client's SOA, RFC 1995 3)
# request, TSIG-signed with hmac-sha256 when --key is given (RFC 8945 4.3), writes "sent" to --ready, and reads nothing until the file --go
# exists (it looks every 50 ms; no --go: it reads at once).  Then it reads the stream until the server closes the connection (or 10 s pass
# without data), and checks every message:
#   - the TSIG of every signed message (RFC 8945 5.3.1: the first one over the request MAC, the message and all TSIG variables; each later one
#     over the previous MAC, the messages since the previous signed one and the timers only).  A stream with a key must end with a signed message.
#   - the SOA serials of the answer (the first and the last SOA RR of the stream).
# --body FILE gets the messages without their TSIG RR (ARCOUNT less one, the original ID), each with its two-octet length: two transfers of the same
# version compare equal there although their TSIG time stamps differ.
# --count N opens N such connections and holds them all (no checks, prints "HELD n" once all requests are sent), for the test of many transfers.
# Prints one line: "MSGS=<n> BYTES=<n> FIRST=<serial|-> LAST=<serial|-> TSIG=<none|ok|bad|unsigned-end> RCODE=<rcode of the first message>".
use strict;
use warnings;
use Socket;
use Getopt::Long;
use Time::HiRes qw(sleep time);
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(decode_base64);

my ($port, $zone, $type, $ixfr_serial, $key, $go, $body, $rcvbuf, $count, $ready) = (53, undef, 'AXFR', undef, undef, undef, undef, 2048, 1, undef);
GetOptions('port=i' => \$port, 'zone=s' => \$zone, 'type=s' => \$type, 'ixfr-serial=i' => \$ixfr_serial, 'key=s' => \$key,
           'go=s' => \$go, 'body=s' => \$body, 'rcvbuf=i' => \$rcvbuf, 'count=i' => \$count, 'ready=s' => \$ready) or die "bad options\n";
die "--zone is required\n" unless defined $zone;
my $qtype = uc($type) eq 'IXFR' ? 251 : 252;

sub wire_name {
    my $n = lc shift;
    $n =~ s/\.$//;
    return "\0" if $n eq '';
    return join('', map { chr(length $_) . $_ } split /\./, $n) . "\0";
}
my ($key_name, $secret);
if (defined $key) {
    my ($kn, $b64) = split(/:/, $key, 2);
    ($key_name, $secret) = ($kn, decode_base64($b64));
}
my $alg = wire_name('hmac-sha256');

sub request {
    my $id = 0x5151;
    my $q = wire_name($zone) . pack('nn', $qtype, 1);
    my ($ns, $nscount) = ('', 0);
    if ($qtype == 251) {
        my $rd = wire_name("ns.$zone") . wire_name("h.$zone") . pack('NNNNN', $ixfr_serial // 0, 0, 0, 0, 0);
        $ns = wire_name($zone) . pack('nnNn', 6, 1, 0, length $rd) . $rd;
        $nscount = 1;
    }
    my $msg = pack('nnnnnn', $id, 0, 1, 0, $nscount, 0) . $q . $ns;
    return ($msg, '') unless defined $key_name;
    my $now = int(time());
    my $time48 = pack('nN', 0, $now);
    my $vars = wire_name($key_name) . pack('nN', 255, 0) . $alg . $time48 . pack('nnn', 300, 0, 0);
    my $mac = hmac_sha256($msg . $vars, $secret);
    my $rd = $alg . $time48 . pack('nn', 300, length $mac) . $mac . pack('nnn', $id, 0, 0);
    substr($msg, 10, 2) = pack('n', 1);
    return ($msg . wire_name($key_name) . pack('nnNn', 250, 255, 0, length $rd) . $rd, $mac);
}

sub connect_one {
    socket(my $s, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
    setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', $rcvbuf)) or die "rcvbuf: $!";
    connect($s, sockaddr_in($port, inet_aton('127.0.0.1'))) or die "connect: $!";
    my ($m, $mac) = request();
    my $w = pack('n', length $m) . $m;
    syswrite($s, $w) == length $w or die "write: $!";
    return ($s, $mac);
}

if ($count > 1) {
    my @socks;
    for (1 .. $count) { my ($s) = connect_one(); push @socks, $s; }
    $| = 1;
    print "HELD $count\n";
    if (defined $ready) { open(my $f, '>', $ready) or die; print $f "sent\n"; close $f; }
    sleep 0.05 while defined $go && !-e $go;
    exit 0;
}

my ($s, $req_mac) = connect_one();
if (defined $ready) { open(my $f, '>', $ready) or die; print $f "sent\n"; close $f; }
sleep 0.05 while defined $go && !-e $go;

my $buf = '';
while (1) {
    my $rin = '';
    vec($rin, fileno($s), 1) = 1;
    last unless select($rin, undef, undef, 10);
    my $n = sysread($s, $buf, 65536, length $buf);
    last if !defined $n || $n == 0;
}

sub skip_name {
    my ($m, $o) = @_;
    while ($o < length $m) {
        my $l = ord substr($m, $o, 1);
        return $o + 1 if $l == 0;
        return $o + 2 if ($l & 0xC0) == 0xC0;
        $o += 1 + $l;
    }
    return length $m;
}

my ($msgs, $first, $last, $tsig, $rcode0) = (0, '-', '-', defined $key_name ? 'ok' : 'none', '-');
my ($prev_mac, $pending, $signed_last) = ($req_mac, '', 0);
my $bodies = '';
my $o = 0;
while ($o + 2 <= length $buf) {
    my $len = unpack('n', substr($buf, $o, 2));
    last if $o + 2 + $len > length $buf;
    my $m = substr($buf, $o + 2, $len);
    $o += 2 + $len;
    $msgs++;
    my ($id, $flags, $qd, $an, $ns, $ar) = unpack('nnnnnn', $m);
    $rcode0 = $flags & 0x0F if $msgs == 1;
    my $p = 12;
    for (1 .. $qd) { $p = skip_name($m, $p) + 4; }
    for (1 .. $an + $ns) {
        my $nend = skip_name($m, $p);
        my ($t, $c, $ttl, $rdlen) = unpack('nnNn', substr($m, $nend, 10));
        if ($t == 6) {
            my $rd = $nend + 10;
            my $x = skip_name($m, skip_name($m, $rd));
            my $serial = unpack('N', substr($m, $x, 4));
            $first = $serial if $first eq '-';
            $last = $serial;
        }
        $p = $nend + 10 + $rdlen;
    }
    my ($tsig_start, $orig_id) = (undef, $id);
    my ($time48, $fudge, $mac, $err, $other_len, $other, $alg_wire) = ('', 0, '', 0, 0, '', '');
    for my $i (1 .. $ar) {
        my $rr = $p;
        my $nend = skip_name($m, $p);
        my ($t, $c, $ttl, $rdlen) = unpack('nnNn', substr($m, $nend, 10));
        my $rd = $nend + 10;
        if ($t == 250 && $i == $ar) {
            $tsig_start = $rr;
            my $a = skip_name($m, $rd);
            $alg_wire = lc substr($m, $rd, $a - $rd);
            $time48 = substr($m, $a, 6);
            my $mac_len;
            ($fudge, $mac_len) = unpack('nn', substr($m, $a + 6, 4));
            $mac = substr($m, $a + 10, $mac_len);
            ($orig_id, $err, $other_len) = unpack('nnn', substr($m, $a + 10 + $mac_len, 6));
            $other = substr($m, $a + 16 + $mac_len, $other_len);
        }
        $p = $rd + $rdlen;
    }
    my $plain = $m;
    if (defined $tsig_start) {
        $plain = substr($m, 0, $tsig_start);
        substr($plain, 0, 2) = pack('n', $orig_id);
        substr($plain, 10, 2) = pack('n', $ar - 1);
    }
    $bodies .= pack('n', length $plain) . $plain;
    next unless defined $key_name;
    if (!defined $tsig_start) {        # RFC 8945 5.3.1: an unsigned message in between; the next signed one covers it
        $pending .= $plain;
        $signed_last = 0;
        next;
    }
    my $vars = $msgs == 1 ? wire_name($key_name) . pack('nN', 255, 0) . $alg_wire . $time48 . pack('nnn', $fudge, $err, $other_len) . $other
                          : $time48 . pack('n', $fudge);
    my $want = hmac_sha256(pack('n', length $prev_mac) . $prev_mac . $pending . $plain . $vars, $secret);
    $tsig = 'bad' if $want ne $mac;
    ($prev_mac, $pending, $signed_last) = ($mac, '', 1);
}
$tsig = 'unsigned-end' if defined $key_name && $tsig eq 'ok' && !$signed_last;
if (defined $body) { open(my $f, '>:raw', $body) or die "$body: $!"; print $f $bodies; close $f; }
printf("MSGS=%d BYTES=%d FIRST=%s LAST=%s TSIG=%s RCODE=%s\n", $msgs, length $buf, $first, $last, $tsig, $rcode0);
