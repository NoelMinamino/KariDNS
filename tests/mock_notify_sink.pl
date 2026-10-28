#!/usr/bin/perl
# mock_notify_sink.pl - NOTIFY receiver that records where each NOTIFY came from (tests/run_xfr_sources_test.sh).
#
#   mock_notify_sink.pl --log FILE --ports P1,P2,... [--ports6 P3,...] [--bind ADDR:P4,...] [--key NAME:BASE64 ...] [--answer]
#                       [--tcp-ports P5[:MODE],...] [--tcp-bind ADDR:P6[:MODE],...]
#
# Listens on 127.0.0.1 UDP ports P1.. (on ::1 for --ports6, and on the given addresses for --bind) and appends one line per NOTIFY (opcode 4) to FILE:
#   NOTIFY port=P src=SOURCE-ADDRESS qname=Q tsig=T via=udp t=SECONDS-SINCE-THE-EPOCH
# --tcp-ports / --tcp-bind listen on TCP too (NOTIFY over TCP, RFC 1035 section 4.2.2: a two-octet length before each message; a connection
# is served by a child process); the line then says via=tcp.  MODE is what the sink does with the NOTIFY it read (default answer; --answer is
# for UDP only):
#   answer    reply (QR, same ID and question); signed with the key of the request when the sink knows it (--key), RFC 8945 section 4.3.2
#   unsigned  reply without a TSIG       badsig  reply signed with a wrong secret      badid  reply with another ID
#   close     close the connection without a reply          garble  a reply of 20 random octets with a valid length prefix
#   short     a reply of 5 octets (less than a header)      bigprefix  a length prefix of 65535 and nothing more
#   stall     read the message and never answer             partial  3 octets of a reply of 100, then nothing
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

my ($logfile, $ports, $ports6, $answer, $bind, $tcp_ports, $tcp_bind, @keyspecs);
GetOptions('log=s' => \$logfile, 'ports=s' => \$ports, 'ports6=s' => \$ports6, 'bind=s' => \$bind, 'key=s' => \@keyspecs,
           'answer' => \$answer, 'tcp-ports=s' => \$tcp_ports, 'tcp-bind=s' => \$tcp_bind) or die "usage\n";
$SIG{CHLD} = 'IGNORE';
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

# The TSIG record of a request (RFC 8945 section 4.3.3, no prior MAC) as a hash (keyname, alg, mac, state), or undef when there is none
sub tsig_parse {
    my ($p) = @_;
    return undef if length($p) < 12;
    my ($id, $fl, $qd, $an, $ns, $ar) = unpack('n6', $p);
    return undef if $ar == 0;
    my $off = 12;
    for (1 .. $qd) { $off = skip_name($p, $off); return undef unless defined $off; $off += 4; }
    my ($tstart, $rdoff, $rdlen);
    for (1 .. $an + $ns + $ar) {
        my $start = $off;
        $off = skip_name($p, $off);
        return undef if !defined $off || $off + 10 > length $p;
        my ($type, $class, $ttl, $len) = unpack('nnNn', substr($p, $off, 10));
        ($tstart, $rdoff, $rdlen) = ($start, $off + 10, $len) if $type == 250;
        $off += 10 + $len;
    }
    return undef unless defined $tstart;
    my $keyname = dec_name($p, $tstart);
    my $alg = dec_name($p, $rdoff);
    my $aend = skip_name($p, $rdoff);
    my $time6 = substr($p, $aend, 6);
    my ($fudge, $maclen) = unpack('nn', substr($p, $aend + 6, 4));
    my $mac = substr($p, $aend + 10, $maclen);
    my ($origid, $err, $olen) = unpack('nnn', substr($p, $aend + 10 + $maclen, 6));
    my $other = substr($p, $aend + 16 + $maclen, $olen);
    my %r = (keyname => $keyname, alg => $alg, mac => $mac, state => "$keyname:unknown");
    return \%r unless defined $secret{$keyname};
    my $msg = pack('n6', $origid, $fl, $qd, $an, $ns, $ar - 1) . substr($p, 12, $tstart - 12);
    my $vars = wire_name($keyname) . pack('nN', 255, 0) . wire_name($alg) . $time6 . pack('nnn', $fudge, $err, $olen) . $other;
    my $want = hmac_sha256($msg . $vars, $secret{$keyname});
    my $ok = $alg eq 'hmac-sha256' && $maclen > 0 && substr($want, 0, $maclen) eq $mac;
    $r{state} = "$keyname:" . ($ok ? 'ok' : 'badsig');
    return \%r;
}

# "none", or "NAME:ok" / "NAME:badsig" / "NAME:unknown"
sub tsig_state {
    my $t = tsig_parse($_[0]);
    return $t ? $t->{state} : 'none';
}

# The reply to the NOTIFY $req (without a TSIG): QR, AA, opcode NOTIFY, the question copied.  $id overrides the ID.
sub plain_reply {
    my ($req, $id) = @_;
    my $qend = 12;
    while ($qend < length $req && ord substr($req, $qend, 1) != 0) { $qend += 1 + ord substr($req, $qend, 1); }
    $qend += 5;
    my $oid = unpack('n', $req);
    return pack('n6', defined $id ? $id : $oid, 0x8000 | 0x0400 | (4 << 11), 1, 0, 0, 0) . substr($req, 12, $qend - 12);
}

# The reply signed like a response (RFC 8945 section 4.3.2): the MAC covers the request MAC, the reply without the TSIG and the variables
sub signed_reply {
    my ($req, $t, $secret) = @_;
    my $reply = plain_reply($req);
    my $time6 = substr(pack('Q>', time), 2, 6);
    my $fudge = 300;
    my $vars = wire_name($t->{keyname}) . pack('nN', 255, 0) . wire_name($t->{alg}) . $time6 . pack('nnn', $fudge, 0, 0);
    my $mac = hmac_sha256(pack('n', length $t->{mac}) . $t->{mac} . $reply . $vars, $secret);
    my $rdata = wire_name($t->{alg}) . $time6 . pack('nn', $fudge, length $mac) . $mac . pack('nnn', unpack('n', $req), 0, 0);
    my $rr = wire_name($t->{keyname}) . pack('nnNn', 250, 255, 0, length $rdata) . $rdata;
    substr($reply, 10, 2) = pack('n', 1);
    return $reply . $rr;
}

# What a TCP connection does with the NOTIFY it read, by MODE (see the header)
sub tcp_respond {
    my ($c, $mode, $req) = @_;
    my $t = tsig_parse($req);
    my $send = sub { my $m = shift; print $c pack('n', length $m) . $m; $c->flush; };
    if ($mode eq 'answer') {
        $send->($t && defined $secret{$t->{keyname}} ? signed_reply($req, $t, $secret{$t->{keyname}}) : plain_reply($req));
    } elsif ($mode eq 'unsigned') {
        $send->(plain_reply($req));
    } elsif ($mode eq 'badsig') {
        $send->($t ? signed_reply($req, $t, 'not-the-secret-0123456789abcdef') : plain_reply($req));
    } elsif ($mode eq 'badid') {
        $send->(plain_reply($req, (unpack('n', $req) + 1) & 0xFFFF));
    } elsif ($mode eq 'garble') {
        $send->(join('', map { chr(int rand 256) } 1 .. 20));
    } elsif ($mode eq 'short') {
        $send->('abcde');
    } elsif ($mode eq 'bigprefix') {
        print $c pack('n', 65535); $c->flush;
    } elsif ($mode eq 'partial') {
        print $c pack('n', 100) . 'abc'; $c->flush; sleep 40;
    } elsif ($mode eq 'stall') {
        sleep 40;
    }   # close: nothing
}

# One TCP connection (in a child process): read the framed message, log it, respond
sub tcp_serve {
    my ($c, $port, $mode) = @_;
    $c->autoflush(1);
    local $SIG{ALRM} = sub { exit 0 };
    alarm 60;
    my ($lp, $req) = ('', '');
    read($c, $lp, 2) == 2 or exit 0;
    my $n = unpack('n', $lp);
    read($c, $req, $n) == $n or exit 0;
    return if $n < 12;
    my ($id, $flags) = unpack('n2', $req);
    if ((($flags >> 11) & 0x0F) == 4) {
        my $ip = $c->peerhost; $ip =~ s/^::ffff://i;
        my $q = dec_name($req, 12);
        printf $log "NOTIFY port=%d src=%s qname=%s tsig=%s via=tcp t=%.3f\n", $port, $ip, defined $q ? $q : '?', tsig_state($req), time;
        tcp_respond($c, $mode, $req);
    }
    close $c;
    exit 0;
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
my %tcp_mode;   # fileno of a TCP listener -> [port, mode]
my @tspecs = (['127.0.0.1', $tcp_ports]);
push @tspecs, ['', $tcp_bind] if defined $tcp_bind;
for my $spec (@tspecs) {
    my ($addr, $list) = @$spec;
    next unless defined $list;
    for my $item (split /,/, $list) {
        my ($a, $port, $mode) = $addr eq '' ? $item =~ /^(.*?):(\d+)(?::(\w+))?$/ : ($addr, split(/:/, $item, 2));
        $mode = 'answer' unless defined $mode && length $mode;
        my $s = IO::Socket::IP->new(LocalHost => $a, LocalPort => $port, Proto => 'tcp', Listen => 16, ReuseAddr => 1) or die "tcp bind $a $port: $!";
        $sel->add($s);
        $tcp_mode{fileno $s} = [$port, $mode];
    }
}
print STDERR "READY\n";
while (my @ready = $sel->can_read) {
    for my $s (@ready) {
        if (my $tm = $tcp_mode{fileno $s}) {
            my $c = $s->accept or next;
            my $pid = fork;
            if (defined $pid && $pid == 0) { close($_) for $sel->handles; tcp_serve($c, @$tm); exit 0; }
            close $c;
            next;
        }
        my $buf;
        my $peer = $s->recv($buf, 4096) // next;
        next if length($buf) < 12;
        my ($id, $flags, $qd) = unpack('n3', $buf);
        next unless (($flags >> 11) & 0x0F) == 4;
        my $ip = $s->peerhost;
        $ip =~ s/^::ffff://i;
        my $q = dec_name($buf, 12);
        printf $log "NOTIFY port=%d src=%s qname=%s tsig=%s via=udp t=%.3f\n", $port_of{fileno $s}, $ip, defined $q ? $q : '?', tsig_state($buf), time;
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
