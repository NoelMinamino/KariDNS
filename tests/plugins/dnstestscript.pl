#!/usr/bin/env perl
# dnstestscript.pl - KariDNS type "program" plugin test script
use strict;
use warnings;
use Socket;

$| = 1; # Autoflush stdout

sub extract_qname {
    my ($pkt) = @_;
    return "" if length($pkt) < 12;
    my $offset = 12;
    my @labels;
    while ($offset < length($pkt)) {
        my $len = ord(substr($pkt, $offset, 1));
        last if $len == 0;
        if (($len & 0xC0) == 0xC0) {
            $offset += 2;
            last;
        }
        $offset++;
        last if $offset + $len > length($pkt);
        push @labels, substr($pkt, $offset, $len);
        $offset += $len;
    }
    return join(".", @labels) . ".";
}

sub build_normal_a_response {
    my ($req, $qname, $txid) = @_;
    # Header: QR=1, AA=1, RD=1, RA=0, RCODE=0, QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    my $header = pack("n", $txid) . pack("n", 0x8400) . pack("nnnn", 1, 1, 0, 0);

    # Question section: copy from request (offset 12 up to question end)
    my $q_offset = 12;
    while ($q_offset < length($req)) {
        my $l = ord(substr($req, $q_offset, 1));
        last if $l == 0;
        $q_offset += ($l + 1);
    }
    $q_offset += 5; # 0x00 + QTYPE(2) + QCLASS(2)
    my $question = substr($req, 12, $q_offset - 12);

    # Answer section: pointer to question (0xc00c), TYPE=1 (A), CLASS=1 (IN), TTL=300, RDLENGTH=4, RDATA=192.0.2.1
    my $answer = pack("n", 0xc00c) . pack("nnNn", 1, 1, 300, 4) . inet_aton("192.0.2.1");

    return $header . $question . $answer;
}

sub build_truncated_rdata_response {
    my ($req, $qname, $txid) = @_;
    my $header = pack("n", $txid) . pack("n", 0x8400) . pack("nnnn", 1, 1, 0, 0);
    my $q_offset = 12;
    while ($q_offset < length($req)) {
        my $l = ord(substr($req, $q_offset, 1));
        last if $l == 0;
        $q_offset += ($l + 1);
    }
    $q_offset += 5;
    my $question = substr($req, 12, $q_offset - 12);
    # Intentionally claimed RDLENGTH=4 but only provided 2 bytes
    my $answer = pack("n", 0xc00c) . pack("nnNn", 1, 1, 300, 4) . "\x01\x02";
    return $header . $question . $answer;
}

sub build_nodata_response {
    my ($req, $qname, $txid) = @_;
    return ""; # 0 length = drop/no response
}

my %HANDLERS = (
    'normal'       => \&build_normal_a_response,
    'trunc-rdata'  => \&build_truncated_rdata_response,
    'drop'         => \&build_nodata_response,
);

sub read_raw_line {
    my $line = '';
    while (1) {
        my $ch;
        my $n = sysread(STDIN, $ch, 1);
        return undef unless defined($n) && $n == 1;
        $line .= $ch;
        last if $ch eq "\n";
    }
    return $line;
}

sub read_raw_bytes {
    my ($len) = @_;
    my $buf = '';
    my $got = 0;
    while ($got < $len) {
        my $chunk;
        my $n = sysread(STDIN, $chunk, $len - $got);
        return undef unless defined($n) && $n > 0;
        $buf .= $chunk;
        $got += $n;
    }
    return $buf;
}

sub write_raw_bytes {
    my ($data) = @_;
    my $len = length($data);
    my $written = 0;
    while ($written < $len) {
        my $n = syswrite(STDOUT, substr($data, $written));
        return 0 unless defined($n) && $n > 0;
        $written += $n;
    }
    return 1;
}

binmode(STDIN,  ":raw");
binmode(STDOUT, ":raw");

while (my $line = read_raw_line()) {
    chomp($line);
    # Expect: QUERY <proto> <client_ip>
    my ($cmd, $proto, $client_ip) = split(/\s+/, $line);
    next unless $cmd && $cmd eq "QUERY";

    # Read 2-byte length prefix
    my $len_buf = read_raw_bytes(2);
    last unless defined $len_buf && length($len_buf) == 2;
    my $req_len = unpack("n", $len_buf);

    # Read DNS request packet
    my $req = read_raw_bytes($req_len);
    last unless defined $req && length($req) == $req_len;

    my $txid = unpack("n", substr($req, 0, 2));
    my $qname = extract_qname($req);

    my ($first_label) = ($qname =~ /^([^.]+)\./);
    $first_label //= 'normal';

    my $handler = $HANDLERS{$first_label} // \&build_normal_a_response;
    my $resp = $handler->($req, $qname, $txid);

    my $resp_len = length($resp);
    write_raw_bytes(pack("n", $resp_len));
    if ($resp_len > 0) {
        write_raw_bytes($resp);
    }
}
