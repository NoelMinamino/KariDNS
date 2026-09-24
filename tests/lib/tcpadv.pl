#!/usr/bin/perl
# ==============================================================================
# tests/lib/tcpadv.pl - TCP Adversary Client Helper for KariDNS Testing
# ==============================================================================
use strict;
use warnings;
use IO::Socket::INET;
use Time::HiRes qw(sleep);

my ($mode, $host, $port) = @ARGV;
$host ||= "127.0.0.1";
$port ||= 5353;

if (!$mode) {
    die "Usage: $0 <mode> [host] [port]\nModes: slowloris, zero_len, giant_len, partial_msg, pipeline, byte_by_byte, qr1_packet, flood\n";
}

sub connect_sock {
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 2
    );
    return $sock;
}

if ($mode eq "slowloris") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    # Send only 1 byte of the 2-byte length prefix
    syswrite($sock, "\x00");
    # Hold connection open until closed by server idle timeout
    my $buf;
    sysread($sock, $buf, 1024);
    close($sock);
}
elsif ($mode eq "zero_len") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    # Send 2-byte length of 0
    syswrite($sock, "\x00\x00");
    close($sock);
}
elsif ($mode eq "giant_len") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    # Send 2-byte length of 65535 followed by only 10 bytes
    syswrite($sock, "\xFF\xFF" . "0123456789");
    close($sock);
}
elsif ($mode eq "partial_msg") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    # Length prefix of 20 bytes, send 5 bytes and send FIN
    syswrite($sock, "\x00\x14" . "12345");
    shutdown($sock, 1); # send FIN
    close($sock);
}
elsif ($mode eq "pipeline") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    # Send two queries in one segment
    my $q1 = pack('n6', 0x1111, 0x0100, 1, 0, 0, 0) . "\x07example\x03com\x00\x00\x01\x00\x01";
    my $q2 = pack('n6', 0x2222, 0x0100, 1, 0, 0, 0) . "\x07example\x03com\x00\x00\x1C\x00\x01";
    my $payload = pack('n', length($q1)) . $q1 . pack('n', length($q2)) . $q2;
    syswrite($sock, $payload);
    my $buf;
    sysread($sock, $buf, 4096);
    close($sock);
}
elsif ($mode eq "byte_by_byte") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    my $q = pack('n6', 0x3333, 0x0100, 1, 0, 0, 0) . "\x07example\x03com\x00\x00\x01\x00\x01";
    my $payload = pack('n', length($q)) . $q;
    for my $i (0 .. length($payload) - 1) {
        syswrite($sock, substr($payload, $i, 1));
        sleep(0.005);
    }
    my $buf;
    sysread($sock, $buf, 4096);
    close($sock);
}
elsif ($mode eq "qr1_packet") {
    my $sock = connect_sock();
    exit 0 unless $sock;
    # Send a response packet (QR=1: 0x8180) to query port
    my $resp = pack('n6', 0x4444, 0x8180, 1, 1, 0, 0) . "\x07example\x03com\x00\x00\x01\x00\x01";
    my $payload = pack('n', length($resp)) . $resp;
    syswrite($sock, $payload);
    close($sock);
}
elsif ($mode eq "flood") {
    my @socks;
    for (1 .. 20) {
        my $s = connect_sock();
        push @socks, $s if $s;
    }
    sleep(0.1);
    for my $s (@socks) {
        close($s) if $s;
    }
}
