#!/usr/bin/env perl
# supervised_plugin.pl - a type "program" plugin for tests/run_program_zone_supervisor_test.sh.
#
# Arguments (program-args): ADDR EVENTS [EXIT_AFTER]
#   ADDR        the address of every A answer (and the name of the plugin in EVENTS)
#   EVENTS      a file the plugin appends its events to: "START <pid> <ADDR>", "RELOAD <pid> <ADDR>", "EXIT <pid> <ADDR>",
#               "UNKNOWN <pid> <ADDR> <line>"
#   EXIT_AFTER  when > 0, the plugin exits after answering that many queries
# A line that is neither QUERY nor RELOAD ends the plugin (exit 2), as a plugin written to the protocol before 0.6.2 may do: the test
# checks that a zone without program-reload-line never gets the RELOAD line.
use strict;
use warnings;
use Socket;

$| = 1;
my ($ADDR, $EVENTS, $EXIT_AFTER) = @ARGV;
die "usage: supervised_plugin.pl ADDR EVENTS [EXIT_AFTER]\n" unless defined $ADDR && defined $EVENTS;
$EXIT_AFTER //= 0;

sub event {
    my ($what) = @_;
    open(my $fh, '>>', $EVENTS) or return;
    print $fh "$what $$ $ADDR\n";
    close($fh);
}

sub read_line {
    my $line = "";
    while (1) {
        my $ch;
        my $n = sysread(STDIN, $ch, 1);
        return undef unless $n;
        return $line if $ch eq "\n";
        $line .= $ch;
        return $line if length($line) > 512;
    }
}

sub read_bytes {
    my ($len) = @_;
    my $buf = "";
    while (length($buf) < $len) {
        my $chunk;
        my $n = sysread(STDIN, $chunk, $len - length($buf));
        return undef unless $n;
        $buf .= $chunk;
    }
    return $buf;
}

sub answer {
    my ($req) = @_;
    my $txid = unpack("n", substr($req, 0, 2));
    my $q = 12;
    while ($q < length($req)) {
        my $l = ord(substr($req, $q, 1));
        last if $l == 0;
        $q += $l + 1;
    }
    $q += 5;
    my $question = substr($req, 12, $q - 12);
    return pack("n", $txid) . pack("n", 0x8400) . pack("nnnn", 1, 1, 0, 0) . $question .
           pack("n", 0xc00c) . pack("nnNn", 1, 1, 60, 4) . inet_aton($ADDR);
}

event("START");
my $answered = 0;
while (defined(my $line = read_line())) {
    if ($line eq "RELOAD") {
        event("RELOAD");
        next;
    }
    my ($cmd) = split(/\s+/, $line);
    unless (defined $cmd && $cmd eq "QUERY") {
        event("UNKNOWN");
        exit 2;
    }
    my $lb = read_bytes(2);
    last unless defined $lb;
    my $req = read_bytes(unpack("n", $lb));
    last unless defined $req;
    my $resp = answer($req);
    syswrite(STDOUT, pack("n", length($resp)) . $resp);
    $answered++;
    if ($EXIT_AFTER > 0 && $answered >= $EXIT_AFTER) {
        event("EXIT");
        exit 0;
    }
}
event("EXIT");
exit 0;
