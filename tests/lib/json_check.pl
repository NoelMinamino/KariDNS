#!/usr/bin/perl
# json_check.pl - read the JSON document of `karicheck --json` or `karidns-zone --json` (first key "karidns-zone") strictly, check its shape, and answer questions about it for the shell tests.
#
#   json_check.pl FILE valid         exit 0 when FILE is one valid JSON document (UTF-8, nothing after it) of the karicheck schema
#                                    (docs/karicheck.md, JSON OUTPUT); otherwise the reason on stderr and exit 1
#   json_check.pl FILE get PATH      print the value at PATH: keys and array indexes joined by '.', '*' for every element of an array
#                                    (one value per line); null / true / false as words; exit 1 when PATH is not there
#   json_check.pl FILE codes         the code of every message, one per line
#   json_check.pl FILE has CODE      exit 0 when a message has CODE
#   json_check.pl FILE count PATH    the number of elements of the array (or keys of the object) at PATH
#
# The codes are checked against dns_diag_codes.h (next to the repository root, or KC_CODES_H).
# Exit status 2: the arguments are wrong, or JSON::PP is not installed (the test then SKIPs).
use strict;
use warnings;

BEGIN {
    eval { require JSON::PP; 1 } or do { print STDERR "JSON::PP is not installed\n"; exit 2; };
}

my ($file, $cmd, @args) = @ARGV;
if (!defined $file || !defined $cmd) { print STDERR "usage: json_check.pl FILE valid|get PATH|codes|has CODE|count PATH\n"; exit 2; }

open my $fh, '<:raw', $file or do { print STDERR "cannot read $file: $!\n"; exit 1; };
my $raw = do { local $/; <$fh> };
close $fh;
my $doc = eval { JSON::PP->new->utf8->decode($raw) };
if ($@) { my $e = $@; $e =~ s/\s+$//; print STDERR "not valid JSON: $e\n"; exit 1; }
if (ref $doc ne 'HASH') { print STDERR "the document is not an object\n"; exit 1; }

sub fail { print STDERR "schema: @_\n"; exit 1; }
sub is_int { my $v = shift; return defined $v && !ref $v && $v =~ /^(0|[1-9][0-9]*)$/; }
sub is_str { my $v = shift; return defined $v && !ref $v; }

sub known_codes {
    my $h = $ENV{KC_CODES_H};
    if (!$h) {
        my $dir = $0; $dir =~ s{/[^/]*$}{} or $dir = '.';
        $h = "$dir/../../dns_diag_codes.h";
    }
    open my $in, '<', $h or fail("cannot read $h: $!");
    my %c;
    while (<$in>) { $c{$1} = 1 if /^\s*XR?\s*\(\s*\w+\s*,\s*"([^"]+)"/; }
    close $in;
    return \%c;
}

sub check_schema {
    my $tool = exists $doc->{"karidns-zone"} ? "karidns-zone" : "karicheck";    # the first key names the tool
    my @top = ($tool, qw(version command result counts truncated messages zones));
    for my $k (@top) { fail("missing key $k") unless exists $doc->{$k}; }
    fail("unexpected keys: " . join(',', grep { my $x = $_; !grep { $_ eq $x } @top } sort keys %$doc)) if keys %$doc != @top;
    fail("$tool is not 1") unless is_int($doc->{$tool}) && $doc->{$tool} == 1;
    fail("version is not a string") unless is_str($doc->{version}) && length $doc->{version};
    my $cmds = $tool eq "karidns-zone" ? "import|export" : "conf|zones|zone|db";
    fail("command is not $cmds or null") unless !defined $doc->{command} || $doc->{command} =~ /^($cmds)$/;
    fail("result is not ok/fail/usage") unless is_str($doc->{result}) && $doc->{result} =~ /^(ok|fail|usage)$/;
    fail("truncated is not a boolean") unless ref $doc->{truncated} eq 'JSON::PP::Boolean';
    my $c = $doc->{counts};
    fail("counts is not an object") unless ref $c eq 'HASH';
    for my $k (qw(error warning checked skipped dropped)) { fail("counts.$k is not a non-negative integer") unless is_int($c->{$k}); }
    fail("counts has unexpected keys") if keys %$c != 5;
    fail("messages is not an array") unless ref $doc->{messages} eq 'ARRAY';
    fail("zones is not an array") unless ref $doc->{zones} eq 'ARRAY';
    my $codes = known_codes();
    my ($ne, $nw) = (0, 0);
    my $i = 0;
    for my $m (@{ $doc->{messages} }) {
        fail("messages[$i] is not an object") unless ref $m eq 'HASH';
        for my $k (qw(severity code text file line zone view)) { fail("messages[$i] has no $k") unless exists $m->{$k}; }
        fail("messages[$i] has unexpected keys") if keys %$m != 7;
        fail("messages[$i].severity") unless is_str($m->{severity}) && $m->{severity} =~ /^(error|warning|note|info)$/;
        fail("messages[$i].code is not a string") unless is_str($m->{code});
        fail("messages[$i].code '$m->{code}' is not in dns_diag_codes.h") unless $codes->{ $m->{code} };
        fail("messages[$i].code '$m->{code}' is not lowercase dotted") unless $m->{code} =~ /^[a-z]+(\.[a-z0-9]+(-[a-z0-9]+)*)+$/;
        fail("messages[$i].text is not a string") unless is_str($m->{text});
        for my $k (qw(file zone view)) { fail("messages[$i].$k is neither a string nor null") unless !defined $m->{$k} || is_str($m->{$k}); }
        fail("messages[$i].line is neither a positive integer nor null") unless !defined $m->{line} || (is_int($m->{line}) && $m->{line} > 0);
        $ne++ if $m->{severity} eq 'error';
        $nw++ if $m->{severity} eq 'warning';
        $i++;
    }
    if (!$doc->{truncated}) {
        fail("counts.error is $c->{error}, the document has $ne errors") unless $c->{error} == $ne;
        fail("counts.warning is $c->{warning}, the document has $nw warnings") unless $c->{warning} == $nw;
        fail("counts.dropped is not 0") unless $c->{dropped} == 0;
    } else {
        fail("truncated without dropped messages or zones") unless $c->{dropped} > 0 || @{ $doc->{zones} } >= 100000;
    }
    fail("result ok with errors") if $doc->{result} eq 'ok' && $c->{error} > 0;
    $i = 0;
    for my $z (@{ $doc->{zones} }) {
        fail("zones[$i] is not an object") unless ref $z eq 'HASH';
        for my $k (qw(zone view file format result errors warnings)) { fail("zones[$i] has no $k") unless exists $z->{$k}; }
        fail("zones[$i] has unexpected keys") if keys %$z != 7;
        fail("zones[$i].zone is not a string") unless is_str($z->{zone});
        for my $k (qw(view file)) { fail("zones[$i].$k is neither a string nor null") unless !defined $z->{$k} || is_str($z->{$k}); }
        fail("zones[$i].format") unless is_str($z->{format}) && $z->{format} =~ /^(bind|tinydns|database)$/;
        fail("zones[$i].result") unless is_str($z->{result}) && $z->{result} =~ /^(ok|fail)$/;
        fail("zones[$i].errors / warnings") unless is_int($z->{errors}) && is_int($z->{warnings});
        fail("zones[$i] result does not follow its errors") unless ($z->{result} eq 'fail') == ($z->{errors} > 0);
        $i++;
    }
}

sub lookup {                    # list of values at PATH
    my ($path) = @_;
    my @cur = ($doc);
    for my $k (split /\./, $path) {
        my @next;
        for my $v (@cur) {
            if ($k eq '*') { push @next, @$v if ref $v eq 'ARRAY'; }
            elsif (ref $v eq 'HASH' && exists $v->{$k}) { push @next, $v->{$k}; }
            elsif (ref $v eq 'ARRAY' && $k =~ /^[0-9]+$/ && $k < @$v) { push @next, $v->[$k]; }
        }
        @cur = @next;
        return () unless @cur;
    }
    return @cur;
}

sub show {
    my ($v) = @_;
    return 'null' unless defined $v;
    return $v ? 'true' : 'false' if ref $v eq 'JSON::PP::Boolean';
    return JSON::PP->new->canonical->encode($v) if ref $v;
    return $v;
}

binmode STDOUT, ':utf8';
if ($cmd eq 'valid') {
    check_schema();
    exit 0;
} elsif ($cmd eq 'get') {
    my @v = lookup($args[0] // '');
    exit 1 unless @v;
    print show($_), "\n" for @v;
    exit 0;
} elsif ($cmd eq 'codes') {
    print "$_\n" for map { $_->{code} } @{ $doc->{messages} };
    exit 0;
} elsif ($cmd eq 'has') {
    exit((grep { $_->{code} eq $args[0] } @{ $doc->{messages} }) ? 0 : 1);
} elsif ($cmd eq 'count') {
    my @v = lookup($args[0] // '');
    exit 1 unless @v;
    my $v = $v[0];
    print ref $v eq 'ARRAY' ? scalar(@$v) : ref $v eq 'HASH' ? scalar(keys %$v) : 0, "\n";
    exit 0;
}
print STDERR "unknown command $cmd\n";
exit 2;
