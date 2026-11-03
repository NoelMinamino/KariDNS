#!/usr/bin/env perl
# ==============================================================================
# tsig_query.pl - send one DNS query (optionally TSIG-signed) and report the answer
#
# Used by the phase 13b tests (X-28 BADVERS for AXFR/IXFR, X-15 compressed QNAME,
# X-20 signed RRL slip responses), where dag cannot be used: dag retries BADVERS and
# re-signs, and it cannot send a hand-made packet.
#
# Options:
#   --server ADDR --port N [--tcp]
#   --name NAME --type TYPE(number or A/SOA/AXFR/IXFR/TXT) [--ixfr-serial N]
#   --edns-version V        (OPT with this version; default: no OPT)
#   --key NAME:BASE64       (sign with hmac-sha256, RFC 8945 §4.3; verify the answer)
#   --hex HEX               (send this packet as is, instead of building one)
#   --count N               (UDP: send N queries back to back, one line each)
#   A malformed request (tests/run_xfr_request_shape_test.sh): each option changes one thing of the request; the TSIG, if any, signs the result
#   --opcode N / --req-rcode N                the OPCODE / RCODE of the request header (default 0)
#   --hdr-qd N / --hdr-an N / --hdr-ns N      this value in QDCOUNT / ANCOUNT / NSCOUNT instead of the number of records that are there
#   --second-question                         a second question, the same as the first
#   --q2-name NAME / --q2-type T / --q2-class N a second question that differs from the first in this (implies --second-question)
#   --opt-data HEX                            these octets (options, RFC 6891 6.1.2) in the RDATA of the OPT (with --edns-version)
#   --auth-type N                             the TYPE of the IXFR Authority record instead of SOA (6)
#   --second-opt                              two OPT records (with --edns-version)
#   --trailing N                              N octets after the last record (after the TSIG)
#   --class N                                 the QCLASS of the question (default 1, IN); the IXFR SOA keeps class IN
#   --show-ede                                add " ede=<INFO-CODE of the first EDE option (RFC 8914 2)|->" to the line
#   --show-ede-text                           and " ede-text=<EXTRA-TEXT of that option|->" after it
# Output, one line per answer:
#   rcode=<12-bit extended rcode> tc=<0|1> aa=<0|1> qd=<n> an=<n> ns=<n> ar=<n> opt=<version|none> tsig=<none|ok|bad|error-N> [ede=<n|->]
# A timeout prints "timeout".
# ==============================================================================
use strict;
use warnings;
use Socket;
use IO::Socket::INET;
use IO::Select;
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(decode_base64);
use Getopt::Long;

my ($server, $port, $tcp, $name, $type, $ixfr_serial, $edns_version, $key, $hex, $count) =
    ('127.0.0.1', 53, 0, '.', 'A', undef, undef, undef, undef, 1);
my ($opcode, $req_rcode, $hdr_qd, $hdr_an, $hdr_ns, $second_question, $auth_type, $second_opt, $trailing, $qclass) =
    (0, 0, undef, undef, undef, 0, 6, 0, 0, 1);
my $show_ede = 0;
my ($show_ede_text, $q2_name, $q2_type, $q2_class, $opt_data) = (0, undef, undef, undef, q{});
GetOptions('server=s' => \$server, 'port=i' => \$port, 'tcp' => \$tcp, 'name=s' => \$name,
           'type=s' => \$type, 'ixfr-serial=i' => \$ixfr_serial, 'edns-version=i' => \$edns_version,
           'key=s' => \$key, 'hex=s' => \$hex, 'count=i' => \$count,
           'opcode=i' => \$opcode, 'req-rcode=i' => \$req_rcode, 'hdr-qd=i' => \$hdr_qd, 'hdr-an=i' => \$hdr_an,
           'hdr-ns=i' => \$hdr_ns, 'second-question' => \$second_question, 'auth-type=i' => \$auth_type,
           'second-opt' => \$second_opt, 'trailing=i' => \$trailing, 'class=i' => \$qclass,
           'show-ede' => \$show_ede, 'show-ede-text' => \$show_ede_text, 'q2-name=s' => \$q2_name, 'q2-type=s' => \$q2_type,
           'q2-class=i' => \$q2_class, 'opt-data=s' => \$opt_data) or die "bad options\n";
$show_ede = 1 if $show_ede_text;

my %types = (A => 1, NS => 2, SOA => 6, TXT => 16, AAAA => 28, IXFR => 251, AXFR => 252, ANY => 255);
my $qtype = $type =~ /^\d+$/ ? $type : ($types{uc $type} // die "unknown type $type\n");

sub wire_name {    # canonical (lower case) wire format, RFC 4034 §6.2
    my $n = lc shift;
    $n =~ s/\.$//;
    return "\0" if $n eq '';
    return join('', map { chr(length $_) . $_ } split /\./, $n) . "\0";
}

my ($key_name, $secret);
if (defined $key) {
    my ($kn, $b64) = split /:/, $key, 2;
    ($key_name, $secret) = ($kn, decode_base64($b64));
}
my $alg = wire_name('hmac-sha256');

# Build the query; returns (packet, request MAC)
sub build_query {
    return (pack('H*', $hex), '') if defined $hex;
    my $id = int(rand(65536));
    my $q = wire_name($name) . pack('nn', $qtype, $qclass);
    my $qdcount = 1;
    if (defined $q2_name || defined $q2_type || defined $q2_class) {
        my $t2 = !defined $q2_type ? $qtype : $q2_type =~ /^\d+$/ ? $q2_type : ($types{uc $q2_type} // die "unknown type $q2_type\n");
        $q .= wire_name($q2_name // $name) . pack('nn', $t2, $q2_class // $qclass);
        $qdcount = 2;
    } elsif ($second_question) { $q .= $q; $qdcount = 2; }
    my $ns = '';
    my $nscount = 0;
    if (defined $ixfr_serial) {    # RFC 1995 §3: the client's SOA in the authority section
        my $rd = wire_name("ns.$name") . wire_name("h.$name") . pack('NNNNN', $ixfr_serial, 0, 0, 0, 0);
        $ns = wire_name($name) . pack('nnNn', $auth_type, 1, 0, length $rd) . $rd;
        $nscount = 1;
    }
    my $ar = '';
    my $arcount = 0;
    if (defined $edns_version) {   # RFC 6891 §6.1.3: VERSION is the second octet of the TTL
        my $od = pack('H*', $opt_data);
        $ar .= "\0" . pack('nnNn', 41, 1232, $edns_version << 16, length $od) . $od;
        $arcount++;
        if ($second_opt) { $ar .= "\0" . pack('nnNn', 41, 1232, $edns_version << 16, 0); $arcount++; }
    }
    my $flags = ($opcode << 11) | $req_rcode;
    my $msg = pack('nnnnnn', $id, $flags, $hdr_qd // $qdcount, $hdr_an // 0, $hdr_ns // $nscount, $arcount) . $q . $ns . $ar;
    return ($msg . ("\xAA" x $trailing), '') unless defined $key_name;
    # RFC 8945 §4.3.2-§4.3.3: digest = message (before TSIG) + TSIG variables
    my $now = time();
    my $time48 = pack('nN', $now >> 32, $now & 0xFFFFFFFF);
    my $vars = wire_name($key_name) . pack('nN', 255, 0) . $alg . $time48 . pack('nnn', 300, 0, 0);
    my $mac = hmac_sha256($msg . $vars, $secret);
    my $rd = $alg . $time48 . pack('nn', 300, length $mac) . $mac . pack('nnn', $id, 0, 0);
    my $tsig = wire_name($key_name) . pack('nnNn', 250, 255, 0, length $rd) . $rd;
    substr($msg, 10, 2) = pack('n', $arcount + 1);
    return ($msg . $tsig . ("\xAA" x $trailing), $mac);
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

sub report {
    my ($m, $req_mac) = @_;
    return "short" if length $m < 12;
    my ($id, $flags, $qd, $an, $ns, $ar) = unpack('nnnnnn', $m);
    my $rcode = $flags & 0x0F;
    my $o = 12;
    for (1 .. $qd) { $o = skip_name($m, $o) + 4; }
    for (1 .. $an + $ns) {
        $o = skip_name($m, $o);
        my $rdlen = unpack('n', substr($m, $o + 8, 2));
        $o += 10 + $rdlen;
    }
    my ($opt, $tsig, $ede, $ede_text) = ('none', 'none', '-', '-');
    for my $i (1 .. $ar) {
        my $rr_start = $o;
        $o = skip_name($m, $o);
        my ($t, $c, $ttl, $rdlen) = unpack('nnNn', substr($m, $o, 10));
        my $rd_off = $o + 10;
        $o = $rd_off + $rdlen;
        if ($t == 41) {
            $opt = ($ttl >> 16) & 0xFF;
            $rcode |= (($ttl >> 24) & 0xFF) << 4;
            for (my $p = $rd_off; $p + 4 <= $rd_off + $rdlen; ) {    # the options (RFC 6891 6.1.2); EDE is code 15 (RFC 8914 2)
                my ($code, $len) = unpack('nn', substr($m, $p, 4));
                if ($code == 15 && $len >= 2 && $ede eq '-') {
                    $ede = unpack('n', substr($m, $p + 4, 2));
                    $ede_text = $len > 2 ? '"' . substr($m, $p + 6, $len - 2) . '"' : '-';
                }
                $p += 4 + $len;
            }
        } elsif ($t == 250 && $i == $ar) {
            if (!defined $key_name) { $tsig = 'present'; next; }
            my $p = skip_name($m, $rd_off);    # algorithm name
            my $alg_wire = lc substr($m, $rd_off, $p - $rd_off);
            my $time48 = substr($m, $p, 6);
            my ($fudge, $mac_len) = unpack('nn', substr($m, $p + 6, 4));
            my $mac = substr($m, $p + 10, $mac_len);
            my ($orig_id, $err, $other_len) = unpack('nnn', substr($m, $p + 10 + $mac_len, 6));
            my $other = substr($m, $p + 16 + $mac_len, $other_len);
            # RFC 8945 §4.3.2: without the TSIG RR, ARCOUNT - 1, the original ID
            my $body = substr($m, 0, $rr_start);
            substr($body, 0, 2) = pack('n', $orig_id);
            substr($body, 10, 2) = pack('n', $ar - 1);
            my $vars = wire_name($key_name) . pack('nN', 255, 0) . $alg_wire . $time48 .
                       pack('nnn', $fudge, $err, $other_len) . $other;
            my $prefix = length $req_mac ? pack('n', length $req_mac) . $req_mac : '';
            if ($mac_len == 0) {
                $tsig = "error-$err";
            } elsif (hmac_sha256($prefix . $body . $vars, $secret) eq $mac) {
                $tsig = $err ? "ok-error-$err" : 'ok';
            } else {
                $tsig = 'bad';
            }
        }
    }
    return sprintf("rcode=%d tc=%d aa=%d qd=%d an=%d ns=%d ar=%d opt=%s tsig=%s%s%s",
                   $rcode, ($flags >> 9) & 1, ($flags >> 10) & 1, $qd, $an, $ns, $ar, $opt, $tsig, $show_ede ? " ede=$ede" : '',
                   $show_ede_text ? " ede-text=$ede_text" : '');
}

if ($tcp) {
    my ($msg, $mac) = build_query();
    my $s = IO::Socket::INET->new(PeerAddr => $server, PeerPort => $port, Proto => 'tcp', Timeout => 3)
        or do { print "timeout\n"; exit 0 };
    print $s pack('n', length $msg) . $msg;
    my $sel = IO::Select->new($s);
    my $buf = '';
    while ($sel->can_read(3)) {
        my $r = sysread($s, $buf, 65537, length $buf);
        last unless $r;
        if (length $buf >= 2) {
            my $l = unpack('n', $buf);
            last if length $buf >= 2 + $l;
        }
    }
    if (length $buf < 2) { print "timeout\n"; exit 0; }
    my $l = unpack('n', $buf);
    print report(substr($buf, 2, $l), $mac), "\n";
} else {
    my $s = IO::Socket::INET->new(PeerAddr => $server, PeerPort => $port, Proto => 'udp') or die "socket: $!\n";
    my $sel = IO::Select->new($s);
    for (1 .. $count) {
        my ($msg, $mac) = build_query();
        $s->send($msg);
        if ($sel->can_read(2)) {
            my $buf;
            $s->recv($buf, 65535);
            print report($buf, $mac), "\n";
        } else {
            print "timeout\n";
        }
    }
}
exit 0;
