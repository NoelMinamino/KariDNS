#!/usr/bin/perl
# ==============================================================================
# tests/lib/ctrl_client.pl - Control Socket Adversary Client for KariDNS
# ==============================================================================
# Usage: ctrl_client.pl <socket> <mode>
# Connects, reads the server's "CHALLENGE <hex>" line, sends the attack and prints
# the server's reply as "REPLY: <line>" (or "REPLY: <closed>" when the server closed
# the connection without a reply). Exit status: 0 when a reply or a close was seen,
# 1 when the socket could not be used (the caller treats that as a failure).
use strict;
use warnings;
use IO::Socket::UNIX;
use IO::Select;

my ($sock_path, $cmd_mode) = @ARGV;
die "usage: $0 <socket> <bad_hmac|giant_cmd|unknown_cmd|silent>\n" unless $sock_path && $cmd_mode;

my $sock = IO::Socket::UNIX->new(Peer => $sock_path, Type => SOCK_STREAM, Timeout => 2);
if (!$sock) {
    print "ERROR: cannot connect to control socket $sock_path: $!\n";
    exit 1;
}
my $sel = IO::Select->new($sock);

# Reads one line (or EOF) within $timeout seconds. Returns the line, "<closed>" or undef (timeout).
sub read_line {
    my ($timeout) = @_;
    my $buf = '';
    my $deadline = time() + $timeout;
    while (time() <= $deadline) {
        my @ready = $sel->can_read(0.2);
        next unless @ready;
        my $chunk;
        my $n = sysread($sock, $chunk, 4096);
        return "<error: $!>" if !defined $n && $buf eq '';
        return ($buf eq '' ? '<closed>' : $buf) if !$n;
        $buf .= $chunk;
        if ($buf =~ /^([^\n]*)\n/) { return $1; }
    }
    return undef;
}

my $challenge = read_line(3);
if (!defined $challenge || $challenge !~ /^CHALLENGE [0-9a-f]{64}$/) {
    print "ERROR: no CHALLENGE line (got: " . (defined $challenge ? $challenge : '<timeout>') . ")\n";
    exit 1;
}

my $reply;
if ($cmd_mode eq "bad_hmac") {
    # AUTH with a value that is not the HMAC of the challenge
    syswrite($sock, "AUTH " . ("0" x 64) . "\n");
    $reply = read_line(3);
} elsif ($cmd_mode eq "giant_cmd") {
    # more than the server's 1024-byte line buffer, before authentication
    syswrite($sock, "UNKNOWN_COMMAND_" . ("A" x 8192) . "\n");
    $reply = read_line(3);
} elsif ($cmd_mode eq "unknown_cmd") {
    # a command instead of AUTH: commands are refused before authentication
    syswrite($sock, "status\n");
    $reply = read_line(3);
} elsif ($cmd_mode eq "silent") {
    # say nothing: the server drops unauthenticated clients after 5 s
    $reply = read_line(9);
} else {
    die "unknown mode $cmd_mode\n";
}
close($sock);
print "REPLY: " . (defined $reply ? $reply : '<timeout>') . "\n";
exit 0;
