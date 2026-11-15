#!/usr/bin/perl
# tcp_query.pl - one query over TCP to 127.0.0.1 (the first-touch of a stored zone on the TCP path of a worker).
# Usage: perl tcp_query.pl PORT NAME [TYPE]    (TYPE: A (default), SOA, NS, MX)
# Output (one line): "rcode=R answers=N"; exit status 0 when an answer came back.
use strict;
use warnings;
use Socket;
use IO::Socket::INET;

my ($port, $name, $type) = @ARGV;
die "usage: tcp_query.pl PORT NAME [TYPE]\n" unless $port && $name;
my %types = (A => 1, NS => 2, SOA => 6, MX => 15);
my $qt = $types{uc($type || "A")} or die "unknown type\n";
$name =~ s/\.$//;
my $q = join('', map { chr(length($_)) . $_ } split(/\./, $name)) . "\0";
my $msg = pack("nnnnnn", 0x4242, 0x0100, 1, 0, 0, 0) . $q . pack("nn", $qt, 1);
my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port, Proto => "tcp", Timeout => 10) or die "connect: $!\n";
print $s pack("n", length($msg)) . $msg;
$s->flush;
my $buf = "";
my $got = read($s, $buf, 2);
die "no answer\n" unless defined $got && $got == 2;
my $len = unpack("n", $buf);
$got = read($s, $buf, $len);
die "short answer\n" unless defined $got && $got == $len && $len >= 12;
my ($id, $fl, $qd, $an) = unpack("nnnn", $buf);
printf("rcode=%d answers=%d\n", $fl & 15, $an);
exit(($fl & 15) == 0 && $an > 0 ? 0 : 1);
