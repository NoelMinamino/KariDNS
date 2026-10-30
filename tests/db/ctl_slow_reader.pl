#!/usr/bin/perl
# ctl_slow_reader.pl SOCKET SECRET-BASE64 COMMAND TRICKLE-SECONDS - a control client that reads the reply of COMMAND one byte at a time for
# TRICKLE-SECONDS (0 = at once), then reads what is left as fast as it can.  Prints "bytes=N", the bytes it received in all.  A server that gives a
# client that reads a byte at a time all the time it wants sends the whole reply; one with a deadline for the reply cuts it (the connection is closed
# once the deadline has passed; only what the socket buffers hold is left to read).
use strict;
use warnings;
use IO::Socket::UNIX;
use MIME::Base64;
use Digest::SHA qw(hmac_sha256_hex);
use Time::HiRes qw(time sleep);
my ($path, $secret, $cmd, $trickle) = @ARGV;
my $s = IO::Socket::UNIX->new(Peer => $path, Type => SOCK_STREAM) or die "connect: $!\n";
sub line {
    my $l = '';
    while (1) {
        my $n = sysread($s, my $c, 1);
        return undef unless $n;
        last if $c eq "\n";
        $l .= $c;
    }
    return $l;
}
my $ch = line();
die "no challenge\n" unless defined $ch && $ch =~ /^CHALLENGE (\S{64})$/;
syswrite($s, 'AUTH ' . hmac_sha256_hex($1, decode_base64($secret)) . "\n");
my $ok = line();
die "auth: " . ($ok // 'eof') . "\n" unless defined $ok && $ok eq 'OK';
syswrite($s, "$cmd\n");
my ($bytes, $t0) = (0, time);
while (time - $t0 < $trickle) {
    my $n = sysread($s, my $c, 1);
    last unless $n;
    $bytes += $n;
    sleep(0.05);
}
while (1) {
    my $n = sysread($s, my $buf, 65536);
    last unless $n;
    $bytes += $n;
}
print "bytes=$bytes\n";
