#!/usr/bin/env perl
# Zone transfer / NOTIFY helper for the phase 10 tests (core Perl modules only).
#
#   notify-sink  --port P --log FILE [--answer-after N]
#       UDP listener on 127.0.0.1:P. Logs one line per NOTIFY:
#       "NOTIFY n=<count> id=<id> qname=<name> tsig=<0|1> from=<addr>:<port>".
#       Answers (QR AA, NOERROR, question copied) only from the (N+1)-th packet on;
#       N = -1 (default) never answers.
#   xfr-primary  --port P --zone Z --mode M [--serial S] [--log FILE]
#       TCP primary for Z on 127.0.0.1:P. Modes:
#         ok           AXFR/IXFR answered with a full zone (SOA, www A, SOA)
#         refused      every request answered REFUSED
#         notimp-ixfr  IXFR answered NOTIMP, AXFR answered with the zone
#         formerr-ixfr IXFR answered FORMERR, AXFR answered with the zone
#         badid        zone sent with a different message ID
#         badqr        zone sent with QR=0
#         badq         zone sent with another QNAME in the question
#       Logs "REQ qtype=<n>" per request.
#   probe  --port P --name N --qtype T [--serial S] [--edns] [--udp] [--nosoa]
#       Sends one query (TCP unless --udp) and prints one line per message:
#       "MSG id=.. qr=.. opcode=.. aa=.. tc=.. rcode=.. qd=.. an=.. ns=.. ar=.. opt=0|1 soa=<serials>"
use strict;
use warnings;
use IO::Socket::INET;
use Getopt::Long;

my $cmd = shift @ARGV // '';
my %o = (port => 0, log => '', 'answer-after' => -1, zone => 'xfr.test', mode => 'ok',
         serial => 0, name => '', qtype => 'SOA', edns => 0, udp => 0, nosoa => 0, timeout => 5);
GetOptions(\%o, 'port=i', 'log=s', 'answer-after=i', 'zone=s', 'mode=s', 'serial=i',
           'name=s', 'qtype=s', 'edns', 'udp', 'nosoa', 'timeout=i') or die "bad options\n";
$| = 1;

my %TYPES = (A => 1, NS => 2, SOA => 6, AXFR => 252, IXFR => 251, OPT => 41, TSIG => 250);

sub enc_name {
    my ($n) = @_;
    $n =~ s/\.$//;
    my $w = '';
    $w .= chr(length $_) . $_ for grep { length } split /\./, $n;
    return $w . "\0";
}

# Returns (name, offset after the name); follows compression pointers.
sub dec_name {
    my ($p, $off) = @_;
    my @l; my $end; my $jumps = 0;
    while (1) {
        return (undef, undef) if $off >= length $p;
        my $c = ord substr($p, $off, 1);
        if (($c & 0xC0) == 0xC0) {
            return (undef, undef) if $off + 1 >= length $p || ++$jumps > 32;
            $end //= $off + 2;
            $off = (($c & 0x3F) << 8) | ord substr($p, $off + 1, 1);
            next;
        }
        if ($c == 0) { $end //= $off + 1; last; }
        push @l, substr($p, $off + 1, $c);
        $off += 1 + $c;
    }
    return ((@l ? join('.', @l) : '') . '.', $end);
}

sub logline {
    my ($s) = @_;
    return unless $o{log};
    open my $fh, '>>', $o{log} or die "$o{log}: $!";
    print $fh "$s\n";
    close $fh;
}

sub soa_rr {
    my ($zone, $serial) = @_;
    my $rd = enc_name("ns1.$zone") . enc_name("hostmaster.$zone") . pack('N5', $serial, 3600, 600, 86400, 60);
    return enc_name($zone) . pack('nnNn', 6, 1, 300, length $rd) . $rd;
}

sub a_rr {
    my ($name, $ip) = @_;
    return enc_name($name) . pack('nnNn', 1, 1, 300, 4) . pack('C4', split /\./, $ip);
}

sub read_tcp_msg {
    my ($s) = @_;
    my $len = '';
    while (length $len < 2) { my $r = sysread($s, $len, 2 - length $len, length $len); return undef unless $r; }
    my $n = unpack 'n', $len; my $buf = '';
    while (length $buf < $n) { my $r = sysread($s, $buf, $n - length $buf, length $buf); return undef unless $r; }
    return $buf;
}

sub send_tcp_msg { my ($s, $m) = @_; syswrite($s, pack('n', length $m) . $m); }

if ($cmd eq 'notify-sink') {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $o{port}, Proto => 'udp', ReuseAddr => 1)
        or die "bind: $!";
    my $count = 0;
    while (1) {
        my $from = $s->recv(my $p, 65535, 0);
        next unless defined $from && length $p >= 12;
        my ($id, $fl, $qd, $an, $ns, $ar) = unpack 'n6', $p;
        next if $fl & 0x8000;
        my ($qn, $qe) = dec_name($p, 12);
        next unless defined $qn;
        my $tsig = 0;
        # Walk to the additional section and look for TSIG (type 250).
        my $off = $qe + 4;
        for my $i (1 .. $an + $ns + $ar) {
            my ($rn, $re) = dec_name($p, $off); last unless defined $rn && $re + 10 <= length $p;
            my ($t, $c, $ttl, $rl) = unpack 'nnNn', substr($p, $re, 10);
            $tsig = 1 if $t == 250;
            $off = $re + 10 + $rl;
        }
        $count++;
        my ($port, $addr) = sockaddr_in($from);
        logline("NOTIFY n=$count id=$id qname=$qn tsig=$tsig from=" . inet_ntoa($addr) . ":$port");
        if ($o{'answer-after'} >= 0 && $count > $o{'answer-after'}) {
            my $resp = pack('n6', $id, 0x8000 | ($fl & 0x7800) | 0x0400, 1, 0, 0, 0) . substr($p, 12, $qe + 4 - 12);
            $s->send($resp, 0, $from);
        }
    }
} elsif ($cmd eq 'xfr-primary') {
    my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $o{port}, Proto => 'tcp',
                                  Listen => 8, ReuseAddr => 1) or die "listen: $!";
    my $serial = $o{serial} || 10;
    while (my $c = $l->accept) {
        while (defined(my $q = read_tcp_msg($c))) {
            next if length $q < 12;
            my ($id) = unpack 'n', $q;
            my ($qn, $qe) = dec_name($q, 12);
            last unless defined $qn;
            my $qtype = unpack 'n', substr($q, $qe, 2);
            my $question = substr($q, 12, $qe + 4 - 12);
            logline("REQ qtype=$qtype");
            my $m = $o{mode};
            my $rcode = 0;
            $rcode = 5 if $m eq 'refused';
            $rcode = 4 if $m eq 'notimp-ixfr' && $qtype == 251;
            $rcode = 1 if $m eq 'formerr-ixfr' && $qtype == 251;
            if ($rcode) {
                send_tcp_msg($c, pack('n6', $id, 0x8000 | $rcode, 1, 0, 0, 0) . $question);
                next;
            }
            my $rid = $m eq 'badid' ? ($id ^ 0x5a5a) : $id;
            my $flags = $m eq 'badqr' ? 0x0400 : 0x8400;
            my $qsec = $m eq 'badq' ? enc_name("other.$o{zone}") . pack('nn', $qtype, 1) : $question;
            my $body = soa_rr($o{zone}, $serial) . a_rr("www.$o{zone}", '192.0.2.80') . soa_rr($o{zone}, $serial);
            send_tcp_msg($c, pack('n6', $rid, $flags, 1, 3, 0, 0) . $qsec . $body);
        }
        close $c;
    }
} elsif ($cmd eq 'probe') {
    my $qtype = $TYPES{uc $o{qtype}} // $o{qtype};
    my $id = int(rand(65535));
    my $ns = ($qtype == 251 && !$o{nosoa}) ? 1 : 0;
    my $ar = $o{edns} ? 1 : 0;
    my $m = pack('n6', $id, 0, 1, 0, $ns, $ar) . enc_name($o{name}) . pack('nn', $qtype, 1);
    $m .= soa_rr($o{name}, $o{serial}) if $ns;
    $m .= "\0" . pack('nnNn', 41, 1232, 0, 0) if $ar;
    my @msgs;
    if ($o{udp}) {
        my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $o{port}, Proto => 'udp') or die "udp: $!";
        $s->send($m);
        my $rin = ''; vec($rin, fileno($s), 1) = 1;
        if (select($rin, undef, undef, $o{timeout})) { $s->recv(my $p, 65535); push @msgs, $p; }
    } else {
        my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $o{port}, Proto => 'tcp',
                                      Timeout => $o{timeout}) or die "tcp: $!";
        send_tcp_msg($s, $m);
        # Read until an error RCODE, the server closes, or 1 s without a further message.
        while (1) {
            my $rin = ''; vec($rin, fileno($s), 1) = 1;
            last unless select($rin, undef, undef, @msgs ? 1 : $o{timeout});
            my $p = read_tcp_msg($s); last unless defined $p;
            push @msgs, $p;
            my ($rid, $fl) = unpack 'nn', $p;
            last if ($fl & 0x000F) || ($qtype != 252 && $qtype != 251);
        }
    }
    for my $p (@msgs) {
        my ($rid, $fl, $qd, $an, $nsc, $arc) = unpack 'n6', $p;
        my $opt = 0;
        my @s = soa_serials($p, \$opt);
        printf "MSG id=%s qr=%d opcode=%d aa=%d tc=%d rcode=%d qd=%d an=%d ns=%d ar=%d opt=%d soa=%s\n",
            ($rid == $id ? 'match' : 'other'), ($fl >> 15) & 1, ($fl >> 11) & 15, ($fl >> 10) & 1, ($fl >> 9) & 1,
            $fl & 15, $qd, $an, $nsc, $arc, $opt, join(',', @s);
    }
    print "NOMSG\n" unless @msgs;
} else {
    die "usage: $0 notify-sink|xfr-primary|probe [options]\n";
}

# SOA serials in the answer section; sets $$optref when an OPT is in the additional section.
sub soa_serials {
    my ($p, $optref) = @_;
    my ($id, $fl, $qd, $an, $ns, $ar) = unpack 'n6', $p;
    my $off = 12;
    for (1 .. $qd) { my ($n, $e) = dec_name($p, $off); return () unless defined $n; $off = $e + 4; }
    my @s;
    for my $i (1 .. $an + $ns + $ar) {
        my ($rn, $re) = dec_name($p, $off); last unless defined $rn && $re + 10 <= length $p;
        my ($t, $c, $ttl, $rl) = unpack 'nnNn', substr($p, $re, 10);
        if ($t == 6 && $i <= $an) {
            my ($m1, $e1) = dec_name($p, $re + 10); my ($m2, $e2) = dec_name($p, $e1);
            push @s, unpack('N', substr($p, $e2, 4)) if defined $e2;
        }
        $$optref = 1 if $optref && $t == 41 && $i > $an + $ns;
        $off = $re + 10 + $rl;
    }
    return @s;
}
