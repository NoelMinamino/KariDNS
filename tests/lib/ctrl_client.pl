#!/usr/bin/perl
# ==============================================================================
# tests/lib/ctrl_client.pl - Control Socket Adversary Client for KariDNS
# ==============================================================================
use strict;
use warnings;
use IO::Socket::UNIX;

my ($sock_path, $cmd_mode) = @ARGV;
$sock_path ||= "/tmp/karidns_ctrl.sock";
$cmd_mode ||= "silent";

my $sock = IO::Socket::UNIX->new(
    Peer => $sock_path,
    Type => SOCK_STREAM,
    Timeout => 2
);

if (!$sock) {
    print "SKIP: Cannot connect to control socket $sock_path\n";
    exit 0;
}

if ($cmd_mode eq "silent") {
    # Connect and do nothing, let 5-second server timeout trigger
    sleep(1);
} elsif ($cmd_mode eq "bad_hmac") {
    # Send bogus HMAC header
    syswrite($sock, "AUTH BAD_HMAC_SIGNATURE_DATA\n");
    my $buf;
    sysread($sock, $buf, 1024);
} elsif ($cmd_mode eq "giant_cmd") {
    my $giant = "UNKNOWN_COMMAND_" . ("A" x 8192) . "\n";
    syswrite($sock, $giant);
} elsif ($cmd_mode eq "unknown_cmd") {
    syswrite($sock, "NON_EXISTENT_COMMAND\n");
    my $buf;
    sysread($sock, $buf, 1024);
}

close($sock);
exit 0;
