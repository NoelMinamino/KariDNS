#!/usr/bin/perl
# ==============================================================================
# tests/coverage_gate.pl - Multi-tier coverage gating for KariDNS
# ==============================================================================
# Reads JSON summary from `llvm-cov export -format=text -summary-only`
# and evaluates Line, Region, and Branch coverage against Tier A/B/C targets.
# Function coverage must be 100% in every measured file (a MUST): it is shown per tier and for the total, and one function that never ran
# fails the gate.
#
# Usage:
#   llvm-cov export ... -format=text -summary-only | perl tests/coverage_gate.pl [options]
#   perl tests/coverage_gate.pl --profdata=coverage.profdata [options]
#
# The text report goes to stdout.  --markdown=FILE and --html=FILE write the same table as well (measured value, threshold of the phase,
# counts, pass/fail per tier), for the Job Summary of the CI job "Coverage gate" and for coverage_html/gate.html.
#
# The binaries the summary is made from are COV_BIN_OBJS of the Makefile, the list make coverage-report gives llvm-cov: --objects="$(COV_BIN_OBJS)",
# or, without --objects, what `make -s print-cov-bin-objs` prints.  The gate kept a list of its own before, which lost six unit tests and
# karidns-tapstat: one list, so that the gate and the report count the same binaries.
# ==============================================================================

use strict;
use warnings;
use Getopt::Long;
use JSON::PP;

my $profdata = "coverage.profdata";
my $target = "./karidns";
my $llvm_cov = $ENV{LLVM_COV} || "llvm-cov";
my $phase = 1;
my $strict = 0;
my $help = 0;
my $json_file = "";
my $objects = "";
my $markdown_file = "";    # --markdown=FILE: the table as Markdown (the CI job writes it to the Job Summary)
my $html_file = "";        # --html=FILE: the table as a page (CI: coverage_html/gate.html, published with the report on GitHub Pages)
my $gen_note = "";         # --note=TEXT: a line under the table of --html (CI: the commit and the run)

GetOptions(
    "markdown=s" => \$markdown_file,
    "html=s"     => \$html_file,
    "note=s"     => \$gen_note,
    "profdata=s" => \$profdata,
    "target=s"   => \$target,
    "objects=s"  => \$objects,
    "llvm-cov=s" => \$llvm_cov,
    "phase=i"    => \$phase,
    "strict"     => \$strict,
    "json=s"     => \$json_file,
    "help|h"     => \$help,
) or die "Error in command line arguments\n";

if ($help) {
    print "Usage: $0 [--profdata=FILE] [--json=FILE] [--objects=\"\$(COV_BIN_OBJS)\"] [--phase=1|2] [--strict] [--markdown=FILE] [--html=FILE] [--note=TEXT]\n";
    exit 0;
}

# Define Tier membership
my %tier_a_files = map { $_ => 1 } (
    "dns_wire.c", "dns_zone_parser.c", "dns_config_parser.c", "dns_tinydns_parser.c",
    "dns_utils.c", "dns_cidr.c", "dns_tsig_acl.c", "dns_query_engine.c",
    "dns_axfr_ixfr.c", "dns_dynamic_update.c", "dns_catalog_zone.c",
    "dns_rrl.c", "dns_edns_ecs.c"
);

my %tier_b_files = map { $_ => 1 } (
    "dns_server_core.c", "dns_snapshot_rcu.c", "dns_dnstap.c",
    "dns_priv_sandbox.c", "dns_epoch_rcu.c", "dns_log.c"
);

my %tier_c_files = map { $_ => 1 } (
    "tools/dag.c", "tools/dag_output_yaml.c", "tools/dag_batch.c",
    "tools/dag_axfr_client.c", "tools/dag_trace.c", "tools/dag_trace_common.c",
    "tools/dag_iter.c", "tools/dag_roothints.c", "tools/dag_idn.c", "tools/dag_tsig_client.c",
    "tools/dag_edns_client.c", "tools/dag_transport.c", "tools/dag_replay.c",
    "tools/dag_pcap_l4.c", "tools/dag_tcp_reassembly.c", "tools/dag_http.c", "tools/dag_tls.c",
    "tools/dnstap_decode.c", "tools/tapstat_core.c",   # 0.6.1 M3: the dnstap decoder shared by dag --replay and karidns-tapstat; the Frame Streams reader and the aggregator
    "tools/karicheck.c", "tools/karictl.c", "tools/karidns_zone.c",
    "dns_zone_lint.c",   # the zone checks of karicheck (moved out of tools/karicheck.c in B12; karidns-dbloader --check runs them too)
    "dns_diag.c",        # the diagnostic sink: the text path of the parser and the checks, the JSON document of karicheck --json
    # 0.6.0 ZoneImporter / ZoneExporter: zone file <-> PowerDNS rows <-> zone file text; the database drivers they use are in Tier D
    "dns_zone_rows.c", "dns_zone_text.c", "dns_zone_import.c", "dns_zone_export.c", "dns_zone_msg.c"
);

# Tier D (B10, design 8.6; B11c, D-B11-4): the database layer: the PostgreSQL driver, and since B11 the SQLite3 driver and the loader
# itself (karidns-dbloader and test_db_sqlite3, which includes karidns_dbloader.c, are counted).  Only gated when the database tests
# ran (test_db_pgsql found a server, or the loader / SQLite3 unit test produced data): without data for the tier it is reported as
# skipped, so a build or a CI run without them is not failed for it.
my %tier_d_files = map { $_ => 1 } (
    "dns_db_pgsql.c", "dns_db_sqlite3.c", "karidns_dbloader.c",
    "dns_db_checkproto.c"      # B12: the line protocol of karidns-dbloader --check / karicheck db
);

# Threshold definitions (Phase 1 vs Phase 2)
# Tier thresholds
my %thresholds = (
    'A' => { line => 93.0, region => 89.0, branch => 80.0 },
    'B' => { line => 87.0, region => 80.0, branch => 68.0 },
    'C' => { line => 90.0, region => 84.0, branch => 72.0 },
    'D' => { line => 85.0, region => 78.0, branch => 60.0 },     # measured 88.6 / 84.9 / 67.2 with test_db_pgsql alone (B10)
    'Overall' => ($phase == 2)
        ? { line => 92.0, region => 85.0, branch => 75.0 }
        : { line => 90.0, region => 84.0, branch => 72.0 }
);

# Read JSON data
my $json_text = "";
my $export_cmd = "";       # the llvm-cov export command when the summary is generated here (reused to name never-executed functions)
if ($json_file && -f $json_file) {
    open my $fh, '<', $json_file or die "Cannot open $json_file: $!";
    $json_text = do { local $/; <$fh> };
    close $fh;
} elsif ($json_file eq '-' || -p STDIN || -f STDIN) {
    # JSON piped in (llvm-cov export ... | coverage_gate.pl). Only a real pipe or
    # redirected file counts: under make/cron/CI stdin is often just a non-tty
    # (e.g. /dev/null), which must not turn into an empty "summary".
    $json_text = do { local $/; <STDIN> };
}
if ($json_text eq "") {
    # Generate on the fly using llvm-cov, from the binaries of COV_BIN_OBJS (see the head of this file)
    if ($objects eq "") {
        $objects = `make -s print-cov-bin-objs 2>/dev/null`;
        die "Error: no list of binaries: give --objects=\"\$(COV_BIN_OBJS)\" (make -s print-cov-bin-objs printed nothing)\n" if $? != 0;
    }
    my (@objs, @missing, %seen);
    for my $tok (split ' ', $objects) {
        $tok =~ /^-object=(.+)$/ or die "Error: --objects: '$tok' is not -object=FILE (COV_BIN_OBJS of the Makefile)\n";
        my $obj = $1;
        next if $seen{$obj}++;
        if (-x $obj) { push @objs, "-object=$obj"; } else { push @missing, $obj; }
    }
    die "Error: none of the binaries of COV_BIN_OBJS is built (" . scalar(@missing) . " listed)\n" unless @objs;
    # a binary that is not built (a build without the fuzzers, without libpq) adds nothing; it is named, not silently left out
    print "  [gate] " . scalar(@objs) . " binaries; not built, left out: " . join(" ", @missing) . "\n" if @missing;
    my $obj_str = join(" ", @objs);
    my $cmd = "$llvm_cov export $target $obj_str -instr-profile=$profdata -summary-only -ignore-filename-regex=\"tests/|scratch/|old_patches/|third_party/\"";
    $export_cmd = $cmd;
    $json_text = `$cmd`;
    if ($? != 0 || !$json_text) {
        die "Error running llvm-cov export command: $cmd\n";
    }
}

my $data = eval { decode_json($json_text) };
if (!$data || !$data->{data} || !$data->{data}[0]) {
    die "Failed to parse JSON coverage summary\n";
}

my $export = $data->{data}[0];
my $files = $export->{files} || [];

my %tier_stats = map {
    $_ => { lines_cov => 0, lines_cnt => 0, regions_cov => 0, regions_cnt => 0, branches_cov => 0, branches_cnt => 0,
            functions_cov => 0, functions_cnt => 0 }
} qw(A B C D Overall);

my @file_records = ();
my $pg_driver_skipped = 0;
my @missed_functions = ();

for my $f (@$files) {
    my $filename = $f->{filename} || "";
    # Normalize filename relative to repo root
    my $relname = $filename;
    $relname =~ s{^.*?/(tools/[^/]+)$}{$1} or $relname =~ s{^.*?/([^/]+)$}{$1};
    
    my $tier = "Other";
    if ($tier_a_files{$relname} || $tier_a_files{basename($relname)}) {
        $tier = "A";
    } elsif ($tier_b_files{$relname} || $tier_b_files{basename($relname)}) {
        $tier = "B";
    } elsif ($tier_c_files{$relname} || $tier_c_files{basename($relname)}) {
        $tier = "C";
    } elsif ($tier_d_files{$relname} || $tier_d_files{basename($relname)}) {
        $tier = "D";
    }
    
    my $summary = $f->{summary} || {};
    my $lines = $summary->{lines} || {};
    my $regions = $summary->{regions} || {};
    my $branches = $summary->{branches} || {};
    my $functions = $summary->{functions} || {};

    my $l_cov = $lines->{covered} || 0;
    my $l_cnt = $lines->{count} || 0;
    my $r_cov = $regions->{covered} || 0;
    my $r_cnt = $regions->{count} || 0;
    my $b_cov = $branches->{covered} || 0;
    my $b_cnt = $branches->{count} || 0;
    my $f_cov = $functions->{covered} || 0;
    my $f_cnt = $functions->{count} || 0;

    # dns_db_pgsql.c is compiled into karidns-dbloader whenever libpq is installed, but only test_db_pgsql and the PostgreSQL integration
    # tests execute it, and those SKIP without a server.  A pgsql driver that is almost never executed (under 10% of its lines; a real
    # run reaches about 85%) means "the PostgreSQL tests did not run": the file is left out of Tier D and of the totals (design 8.6), so
    # a build or CI run without a PostgreSQL server is not failed for it.  The rest of Tier D (loader, SQLite3 driver, check protocol) is
    # always exercised and stays gated.
    my $pg_skipped = (basename($relname) eq "dns_db_pgsql.c" && $l_cnt && $l_cov * 10 < $l_cnt) ? 1 : 0;
    $pg_driver_skipped = 1 if $pg_skipped;
    $tier = "D (skipped)" if $pg_skipped;
    
    push @file_records, {
        file => $relname,
        tier => $tier,
        l_cov => $l_cov, l_cnt => $l_cnt, l_pct => ($l_cnt ? 100.0 * $l_cov / $l_cnt : 100.0),
        r_cov => $r_cov, r_cnt => $r_cnt, r_pct => ($r_cnt ? 100.0 * $r_cov / $r_cnt : 100.0),
        b_cov => $b_cov, b_cnt => $b_cnt, b_pct => ($b_cnt ? 100.0 * $b_cov / $b_cnt : 100.0),
    };
    
    next if $pg_skipped;                       # counted in neither the tier nor the totals

    # Function coverage is gated per file, not per tier: every function of every measured file must have run at least once (a function
    # no test reaches is either missing a test or dead code, and dead code is deleted)
    push @missed_functions, sprintf("%-40s %d of %d functions never executed", $relname, $f_cnt - $f_cov, $f_cnt) if $f_cov < $f_cnt;

    if (exists $tier_stats{$tier}) {
        $tier_stats{$tier}{lines_cov} += $l_cov;
        $tier_stats{$tier}{lines_cnt} += $l_cnt;
        $tier_stats{$tier}{regions_cov} += $r_cov;
        $tier_stats{$tier}{regions_cnt} += $r_cnt;
        $tier_stats{$tier}{branches_cov} += $b_cov;
        $tier_stats{$tier}{branches_cnt} += $b_cnt;
        $tier_stats{$tier}{functions_cov} += $f_cov;
        $tier_stats{$tier}{functions_cnt} += $f_cnt;
    }

    $tier_stats{'Overall'}{lines_cov} += $l_cov;
    $tier_stats{'Overall'}{lines_cnt} += $l_cnt;
    $tier_stats{'Overall'}{regions_cov} += $r_cov;
    $tier_stats{'Overall'}{regions_cnt} += $r_cnt;
    $tier_stats{'Overall'}{branches_cov} += $b_cov;
    $tier_stats{'Overall'}{branches_cnt} += $b_cnt;
    $tier_stats{'Overall'}{functions_cov} += $f_cov;
    $tier_stats{'Overall'}{functions_cnt} += $f_cnt;
}

# "file:line name" of every function no instance of which ran, from an lcov export of the same binaries.  A static inline function of a
# header is one function per translation unit in lcov; llvm-cov's summary counts it once, as covered when any instance ran, and so does
# this (grouped by file and line).
sub never_executed_functions {
    return ("(names: run llvm-cov export -format=lcov on the same binaries)") unless $export_cmd;
    (my $cmd = $export_cmd) =~ s/ -summary-only/ -format=lcov/;
    my (%hit, %name, %line_of);
    my $file = "";
    open my $fh, '-|', $cmd or return ("(llvm-cov export -format=lcov failed: $!)");
    while (my $l = <$fh>) {
        if ($l =~ /^SF:(.*)/) {
            ($file = $1) =~ s{^.*?/(tools/[^/]+)$}{$1} or $file =~ s{^.*/}{};
            %line_of = ();
        } elsif ($l =~ /^FN:(\d+),(.*)/) {
            $line_of{$2} = $1;
            $hit{"$file:$1"} //= 0;
            ($name{"$file:$1"} //= $2) =~ s/^[^:]+\.c://;   # "file.c:name" for a static function of a header
        } elsif ($l =~ /^FNDA:(\d+),(.*)/ && defined $line_of{$2}) {
            $hit{"$file:$line_of{$2}"} += $1;
        }
    }
    close $fh;
    return map { "$_ $name{$_}" } grep { !$hit{$_} && !($pg_driver_skipped && /^dns_db_pgsql\.c:/) } sort keys %hit;
}

sub basename {
    my $p = shift;
    $p =~ s{^.*/}{};
    return $p;
}

# The rows of the report, once: the text below, --markdown and --html print the same rows
my $all_passed = 1;
my @rows;
for my $t (qw(A B C D Overall)) {
    my $st = $tier_stats{$t};
    my $th = $thresholds{$t};
    my $label = ($t eq 'Overall' ? "TOTAL" : "Tier $t");
    if ($t eq 'D' && !$st->{lines_cnt}) {      # no data for any file of the tier (no loader built): not gated
        push @rows, { label => $label, skipped => 1, th => $th };
        next;
    }

    my $l_pct = $st->{lines_cnt} ? (100.0 * $st->{lines_cov} / $st->{lines_cnt}) : 100.0;
    my $r_pct = $st->{regions_cnt} ? (100.0 * $st->{regions_cov} / $st->{regions_cnt}) : 100.0;
    my $b_pct = $st->{branches_cnt} ? (100.0 * $st->{branches_cov} / $st->{branches_cnt}) : 100.0;
    my $f_pct = $st->{functions_cnt} ? (100.0 * $st->{functions_cov} / $st->{functions_cnt}) : 100.0;

    my $l_pass = ($l_pct >= $th->{line});
    my $r_pass = ($r_pct >= $th->{region});
    my $b_pass = ($b_pct >= $th->{branch});
    # Functions: 100% is a MUST for every tier and the total.  Compared as counts, not as a percentage: 99.999% prints as 100.00%.
    my $f_pass = ($st->{functions_cov} >= $st->{functions_cnt});

    my $tier_pass = ($l_pass && $r_pass && $b_pass && $f_pass);
    $all_passed = 0 unless $tier_pass;

    # a missed function never shows as 100.00% (rounding), so the column and the status agree
    push @rows, { label => $label, th => $th, st => $st, pass => $tier_pass,
                  l_pct => $l_pct, r_pct => $r_pct, b_pct => $b_pct, l_pass => $l_pass, r_pass => $r_pass, b_pass => $b_pass,
                  f_pass => $f_pass, f_pct => ($f_pass ? $f_pct : ($f_pct > 99.99 ? 99.99 : $f_pct)) };
}
my @never_executed = @missed_functions ? never_executed_functions() : ();
$all_passed = 0 if @missed_functions;
my $pg_note = "dns_db_pgsql.c was left out of Tier D and the totals: the PostgreSQL tests did not run (under 10% of its lines executed)";

# Print report
print "\n";
print "=" x 109 . "\n";
printf "                KariDNS Multi-Tier Coverage Quality Gate (Phase %d)\n", $phase;
print "=" x 109 . "\n";
printf "%-10s | %-16s | %-16s | %-16s | %-16s | %-8s\n",
    "Tier", "Line Cov (%)", "Region Cov (%)", "Branch Cov (%)", "Func Cov (%)", "Status";
print "-" x 109 . "\n";

for my $r (@rows) {
    if ($r->{skipped}) {
        printf "%-10s | %-16s | %-16s | %-16s | %-16s | %-8s\n", $r->{label}, "-", "-", "-", "-", "SKIPPED (no database test data)";
        next;
    }
    printf "%-10s | %6.2f%% (%4.1f%%) | %6.2f%% (%4.1f%%) | %6.2f%% (%4.1f%%) | %6.2f%% (100%%) | %-8s\n",
        $r->{label},
        $r->{l_pct}, $r->{th}{line},
        $r->{r_pct}, $r->{th}{region},
        $r->{b_pct}, $r->{th}{branch},
        $r->{f_pct},
        $r->{pass} ? "PASS" : "FAIL";
}

print "=" x 109 . "\n\n";
if ($pg_driver_skipped) {
    print "[i] $pg_note\n\n";
}

if (@missed_functions) {
    print "[-] Function coverage below 100%:\n";
    print "    $_\n" for @missed_functions;
    print "\n";
    print "    $_\n" for @never_executed;
    print "\n";
}

my $verdict = $all_passed
    ? "PASSED (All tiers met target thresholds, every function executed)"
    : "FAILED (One or more tiers below target, or a function never executed)";
if (!$all_passed) {
    print "[-] Coverage Gate Status: $verdict\n";
} else {
    print "[+] Coverage Gate Status: $verdict\n";
}

# --markdown=FILE (the Job Summary of the CI job "Coverage gate") and --html=FILE (gate.html beside the llvm-cov report): the same table, with
# the measured value and its threshold in each cell, the counts behind it, and the cells under their threshold marked
sub cell_counts {
    my ($r, $k) = @_;
    my %n = (l => 'lines', r => 'regions', b => 'branches', f => 'functions');
    return sprintf("%d / %d", $r->{st}{"$n{$k}_cov"}, $r->{st}{"$n{$k}_cnt"});
}
sub esc_html { my $s = shift; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s; }
sub write_file {
    my ($file, $text) = @_;
    open my $fh, '>', $file or die "Cannot write $file: $!\n";
    print $fh $text;
    close $fh or die "Cannot write $file: $!\n";
}
my $title = sprintf("KariDNS coverage gate (phase %d%s)", $phase, $strict ? ", strict" : "");

if ($markdown_file ne "") {
    my $md = "## $title: " . ($all_passed ? "PASSED" : "FAILED") . "\n\n";
    $md .= "Each cell: measured (threshold). Functions must be 100% in every file (a MUST).\n\n";
    $md .= "| Tier | Lines | Regions | Branches | Functions | Status |\n|---|---|---|---|---|---|\n";
    for my $r (@rows) {
        if ($r->{skipped}) { $md .= "| $r->{label} | - | - | - | - | SKIPPED (no database test data) |\n"; next; }
        my $c = sub {
            my ($k, $pct, $th, $ok) = @_;
            my $s = sprintf("%.2f%% (%s) <sub>%s</sub>", $pct, $th, cell_counts($r, $k));
            return $ok ? $s : "**$s** :x:";
        };
        $md .= sprintf("| %s | %s | %s | %s | %s | %s |\n", $r->{label},
            $c->('l', $r->{l_pct}, sprintf("%.1f%%", $r->{th}{line}), $r->{l_pass}),
            $c->('r', $r->{r_pct}, sprintf("%.1f%%", $r->{th}{region}), $r->{r_pass}),
            $c->('b', $r->{b_pct}, sprintf("%.1f%%", $r->{th}{branch}), $r->{b_pass}),
            $c->('f', $r->{f_pct}, "100%", $r->{f_pass}),
            $r->{pass} ? "PASS" : "**FAIL**");
    }
    $md .= "\n";
    $md .= "> [!NOTE]\n> $pg_note\n\n" if $pg_driver_skipped;
    if (@missed_functions) {
        $md .= "### Function coverage below 100%\n\n";
        $md .= "- `$_`\n" for @missed_functions;
        $md .= "\nNever executed:\n\n";
        $md .= "- `$_`\n" for @never_executed;
        $md .= "\n";
    }
    $md .= "**Coverage gate: $verdict**\n";
    write_file($markdown_file, $md);
}

if ($html_file ne "") {
    my $h = "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
          . "<title>" . esc_html($title) . "</title>\n<style>\n"
          . "body{font-family:sans-serif;margin:1em;color:#222;background:#fff}table{border-collapse:collapse}"
          . "th,td{border:1px solid #bbb;padding:.3em .6em;text-align:right}th:first-child,td:first-child{text-align:left}"
          . "small{color:#666}.fail{background:#fdd;font-weight:bold}.pass{background:#dfd}.skip{color:#666}\n</style></head><body>\n"
          . "<h1>" . esc_html($title) . ": " . ($all_passed ? "PASSED" : "FAILED") . "</h1>\n"
          . "<p>Each cell: measured (threshold). Functions must be 100% in every file (a MUST). "
          . "<a href=\"index.html\">The line-by-line report</a>.</p>\n"
          . "<table>\n<tr><th>Tier</th><th>Lines</th><th>Regions</th><th>Branches</th><th>Functions</th><th>Status</th></tr>\n";
    for my $r (@rows) {
        if ($r->{skipped}) {
            $h .= "<tr class=\"skip\"><td>$r->{label}</td><td>-</td><td>-</td><td>-</td><td>-</td><td>SKIPPED (no database test data)</td></tr>\n";
            next;
        }
        my $c = sub {
            my ($k, $pct, $th, $ok) = @_;
            return sprintf("<td%s>%.2f%% (%s)<br><small>%s</small></td>", $ok ? "" : " class=\"fail\"", $pct, $th, cell_counts($r, $k));
        };
        $h .= "<tr><td>$r->{label}</td>"
            . $c->('l', $r->{l_pct}, sprintf("%.1f%%", $r->{th}{line}), $r->{l_pass})
            . $c->('r', $r->{r_pct}, sprintf("%.1f%%", $r->{th}{region}), $r->{r_pass})
            . $c->('b', $r->{b_pct}, sprintf("%.1f%%", $r->{th}{branch}), $r->{b_pass})
            . $c->('f', $r->{f_pct}, "100%", $r->{f_pass})
            . sprintf("<td class=\"%s\">%s</td></tr>\n", $r->{pass} ? "pass" : "fail", $r->{pass} ? "PASS" : "FAIL");
    }
    $h .= "</table>\n";
    $h .= "<p>" . esc_html($pg_note) . "</p>\n" if $pg_driver_skipped;
    if (@missed_functions) {
        $h .= "<h2>Function coverage below 100%</h2>\n<ul>\n";
        $h .= "<li><code>" . esc_html($_) . "</code></li>\n" for @missed_functions;
        $h .= "</ul>\n<p>Never executed:</p>\n<ul>\n";
        $h .= "<li><code>" . esc_html($_) . "</code></li>\n" for @never_executed;
        $h .= "</ul>\n";
    }
    $h .= "<p><strong>Coverage gate: " . esc_html($verdict) . "</strong></p>\n";
    $h .= "<p><small>" . esc_html($gen_note) . "</small></p>\n" if $gen_note ne "";
    $h .= "</body></html>\n";
    write_file($html_file, $h);
}

exit($all_passed ? 0 : ($strict ? 1 : 0));
