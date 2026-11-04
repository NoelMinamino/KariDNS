#!/usr/bin/perl
# ==============================================================================
# tests/lib/ctrl_multi_client.pl - control socket client that sends several commands on ONE connection
# ==============================================================================
# Usage: ctrl_multi_client.pl <socket> <secret-base64> <sha256|sha512> <command>...
# Connects, answers the CHALLENGE with HMAC(secret, challenge) and prints "AUTH: <reply>".  Then sends each
# command in turn on the same connection and prints "REPLY: <first line of the answer>" (or "REPLY: <closed>"
# when the server closed the connection instead).  A refused command (restricted control key) leaves the
# connection open; an accepted command ends it, so the commands after one should print "<closed>".
# Use text commands only (zonestatus, reload, ...): the answer of `status` is binary.
use strict;
use warnings;
use IO::Socket::UNIX;
use IO::Select;
use MIME::Base64;
use Digest::SHA qw(hmac_sha256_hex hmac_sha512_hex);

$| = 1;
$SIG{PIPE} = "IGNORE";   # a command after the one that ended the connection must print <closed>, not kill the client

my ($sock_path, $secret_b64, $alg, @cmds) = @ARGV;
die "usage: $0 <socket> <secret-base64> <sha256|sha512> <command>...\n" unless $sock_path && $secret_b64 && $alg && @cmds;

my $sock = IO::Socket::UNIX->new(Peer => $sock_path, Type => SOCK_STREAM, Timeout => 2) or do {
    print "ERROR: cannot connect to $sock_path: $!\n";
    exit 1;
};
my $sel = IO::Select->new($sock);
my $buf = '';

# one line, or "<closed>" at EOF, or "<timeout>"
sub read_line {
    my ($timeout) = @_;
    my $deadline = time() + $timeout;
    while (time() <= $deadline) {
        return $1 if $buf =~ s/^([^\n]*)\n//;
        next unless $sel->can_read(0.2);
        my $chunk;
        my $n = sysread($sock, $chunk, 4096);
        return '<closed>' if !defined $n || $n == 0;
        $buf .= $chunk;
    }
    return '<timeout>';
}

my $challenge = read_line(3);
my ($chal) = $challenge =~ /^CHALLENGE ([0-9a-f]{64})$/;
if (!defined $chal) {
    print "ERROR: no CHALLENGE line (got: $challenge)\n";
    exit 1;
}
my $key = decode_base64($secret_b64);
my $hex = $alg eq 'sha512' ? hmac_sha512_hex($chal, $key) : hmac_sha256_hex($chal, $key);
syswrite($sock, "AUTH $hex\n");
my $auth = read_line(3);
print "AUTH: $auth\n";
exit 0 if $auth ne 'OK';

for my $c (@cmds) {
    syswrite($sock, "$c\n");
    print 'REPLY: ' . read_line(5) . "\n";
}
close($sock);
exit 0;
