#!/usr/bin/perl
# tests/check_log_twins.pl - the syslog() lines of the parsers that karicheck runs, and their dns_diag() twins (0.7).
#
# karicheck drops every syslog line of the shared code (tools/karicheck.c karicheck_klog_drop()): its messages are the dns_diag() ones only,
# so nothing is printed twice whatever the texts are.  What a syslog line tells the user must therefore reach dns_diag() at the same place:
# every syslog() call of these files is either followed by its twin (the next statement is a cfg_diag() / dns_diag() / dns_diag_at() /
# dns_vdiag_at() call) or marked as the server's log only with a comment "log only: <why>" on its first line or the line above it.
# A new syslog() call without either fails this check (tests/run_logging_test.sh, L2).
#
# usage: perl tests/check_log_twins.pl FILE...     exit 0 = every call is paired or marked; 1 = the calls that are neither are listed
use strict;
use warnings;

my $diag = qr/\b(?:cfg_diag|dns_diag|dns_diag_at|dns_vdiag_at)\s*\(/;
my ($bad, $calls, $paired, $marked) = (0, 0, 0, 0);
for my $f (@ARGV) {
    open(my $fh, '<', $f) or die "$f: $!\n";
    my @l = map { s/\r?\n\z//r } <$fh>;
    close($fh);
    my $in_comment = 0;
    for (my $i = 0; $i < @l; $i++) {
        my $line = $l[$i];
        # skip the text of comments (a block comment may span lines); strings are left alone (no syslog( inside the strings of these files)
        my $code = '';
        my $rest = $line;
        while (length $rest) {
            if ($in_comment) {
                if ($rest =~ s{^.*?\*/}{}) { $in_comment = 0; } else { $rest = ''; }
            } elsif ($rest =~ s{^(.*?)(/\*|//)}{}) {
                $code .= $1;
                if ($2 eq '//') { $rest = ''; } else { $in_comment = 1; }
            } else {
                $code .= $rest;
                $rest = '';
            }
        }
        next unless $code =~ /\bsyslog\s*\(/;
        next if $code =~ /^\s*#\s*(?:define|undef)\b/;
        $calls++;
        if ($line =~ /log only:/ || ($i > 0 && $l[$i - 1] =~ /log only:/)) {
            $marked++;
            next;
        }
        # the end of the call: the ';' after its parentheses close
        my $depth = 0;
        my $j = $i;
        my $pos = index($l[$i], 'syslog');
        my $done = 0;
        while (!$done && $j < @l) {
            my $s = $j == $i ? substr($l[$j], $pos) : $l[$j];
            my $q = 0;
            for my $c (split //, $s) {
                if ($q) { $q = 0 if $c eq '"'; next; }
                if ($c eq '"') { $q = 1; next; }
                $depth++ if $c eq '(';
                $depth-- if $c eq ')';
                if ($c eq ';' && $depth == 0) { $done = 1; last; }
            }
            $j++ unless $done;
        }
        # the next statement, past blank lines and comment lines
        my $k = $j + 1;
        $k++ while $k < @l && ($l[$k] =~ /^\s*$/ || $l[$k] =~ m{^\s*(?://|/\*|\*)});
        if ($k < @l && $l[$k] =~ /^\s*$diag/) {
            $paired++;
            next;
        }
        $bad++;
        printf "%s:%d: a syslog() line without a dns_diag() twin and without a \"log only:\" comment: %s\n", $f, $i + 1, $line =~ s/^\s+//r;
    }
}
printf "%d syslog() call(s): %d with a dns_diag() twin, %d marked log only, %d neither\n", $calls, $paired, $marked, $bad;
exit($bad ? 1 : 0);
