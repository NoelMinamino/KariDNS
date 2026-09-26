#!/usr/bin/perl
# ==============================================================================
# tests/coverage_gate.pl - Multi-tier coverage gating for KariDNS
# ==============================================================================
# Reads JSON summary from `llvm-cov export -format=text -summary-only`
# and evaluates Line, Region, and Branch coverage against Tier A/B/C targets.
#
# Usage:
#   llvm-cov export ... -format=text -summary-only | perl tests/coverage_gate.pl [options]
#   perl tests/coverage_gate.pl --profdata=coverage.profdata [options]
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

GetOptions(
    "profdata=s" => \$profdata,
    "target=s"   => \$target,
    "llvm-cov=s" => \$llvm_cov,
    "phase=i"    => \$phase,
    "strict"     => \$strict,
    "json=s"     => \$json_file,
    "help|h"     => \$help,
) or die "Error in command line arguments\n";

if ($help) {
    print "Usage: $0 [--profdata=FILE] [--json=FILE] [--phase=1|2] [--strict]\n";
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
    "dns_priv_sandbox.c", "dns_epoch_rcu.c"
);

my %tier_c_files = map { $_ => 1 } (
    "tools/dag.c", "tools/dag_output_yaml.c", "tools/dag_batch.c",
    "tools/dag_axfr_client.c", "tools/dag_trace.c", "tools/dag_tsig_client.c",
    "tools/dag_edns_client.c", "tools/dag_transport.c", "tools/dag_replay.c",
    "tools/dag_pcap_l4.c", "tools/dag_tcp_reassembly.c",
    "tools/karicheck.c", "tools/karictl.c"
);

# Threshold definitions (Phase 1 vs Phase 2)
# Tier thresholds
my %thresholds = (
    'A' => { line => 93.0, region => 89.0, branch => 80.0 },
    'B' => { line => 87.0, region => 80.0, branch => 68.0 },
    'C' => { line => 90.0, region => 84.0, branch => 72.0 },
    'Overall' => ($phase == 2)
        ? { line => 92.0, region => 85.0, branch => 75.0 }
        : { line => 90.0, region => 84.0, branch => 72.0 }
);

# Read JSON data
my $json_text = "";
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
    # Generate on the fly using llvm-cov
    my @objs = ();
    for my $obj (qw(dag karictl karicheck test_cidr test_tinydns_parser test_asan_overflow test_conf_include test_config_directives test_wire_helpers test_zone_parser_paths test_tinydns_paths test_sig0_sign test_snapshot_rebuild test_dnssec_proofs test_dag_format test_dag_reassembly test_query_engine_protocol test_hash_table test_dnstap_engine test_edns_ecs_engine test_rfc_vectors test_dynamic_update_engine test_axfr_ixfr_engine test_rrl_engine test_query_engine_expanded test_response_cache test_vulnerability_fixes test_catalog_zone_engine test_snapshot_sandbox_engine test_dag_tools test_server_core test_fi_parsers test_fi_wire test_fi_snapshot test_fi_xfr test_fi_misc test_fi_dag test_coverage_sweep test_coverage_sweep_dag test_coverage_sweep_net test_coverage_sweep_tools)) {
        push @objs, "-object=./$obj" if -x "./$obj";
    }
    if (-d "coverage_fuzz") {
        for my $fobj (glob "coverage_fuzz/fuzz_*") {
            push @objs, "-object=$fobj" if -x $fobj;
        }
    }
    my $obj_str = join(" ", @objs);
    my $cmd = "$llvm_cov export $target $obj_str -instr-profile=$profdata -summary-only -ignore-filename-regex=\"tests/|scratch/|old_patches/|third_party/\"";
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

my %tier_stats = (
    'A' => { lines_cov => 0, lines_cnt => 0, regions_cov => 0, regions_cnt => 0, branches_cov => 0, branches_cnt => 0 },
    'B' => { lines_cov => 0, lines_cnt => 0, regions_cov => 0, regions_cnt => 0, branches_cov => 0, branches_cnt => 0 },
    'C' => { lines_cov => 0, lines_cnt => 0, regions_cov => 0, regions_cnt => 0, branches_cov => 0, branches_cnt => 0 },
    'Overall' => { lines_cov => 0, lines_cnt => 0, regions_cov => 0, regions_cnt => 0, branches_cov => 0, branches_cnt => 0 },
);

my @file_records = ();

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
    }
    
    my $summary = $f->{summary} || {};
    my $lines = $summary->{lines} || {};
    my $regions = $summary->{regions} || {};
    my $branches = $summary->{branches} || {};
    
    my $l_cov = $lines->{covered} || 0;
    my $l_cnt = $lines->{count} || 0;
    my $r_cov = $regions->{covered} || 0;
    my $r_cnt = $regions->{count} || 0;
    my $b_cov = $branches->{covered} || 0;
    my $b_cnt = $branches->{count} || 0;
    
    push @file_records, {
        file => $relname,
        tier => $tier,
        l_cov => $l_cov, l_cnt => $l_cnt, l_pct => ($l_cnt ? 100.0 * $l_cov / $l_cnt : 100.0),
        r_cov => $r_cov, r_cnt => $r_cnt, r_pct => ($r_cnt ? 100.0 * $r_cov / $r_cnt : 100.0),
        b_cov => $b_cov, b_cnt => $b_cnt, b_pct => ($b_cnt ? 100.0 * $b_cov / $b_cnt : 100.0),
    };
    
    if (exists $tier_stats{$tier}) {
        $tier_stats{$tier}{lines_cov} += $l_cov;
        $tier_stats{$tier}{lines_cnt} += $l_cnt;
        $tier_stats{$tier}{regions_cov} += $r_cov;
        $tier_stats{$tier}{regions_cnt} += $r_cnt;
        $tier_stats{$tier}{branches_cov} += $b_cov;
        $tier_stats{$tier}{branches_cnt} += $b_cnt;
    }
    
    $tier_stats{'Overall'}{lines_cov} += $l_cov;
    $tier_stats{'Overall'}{lines_cnt} += $l_cnt;
    $tier_stats{'Overall'}{regions_cov} += $r_cov;
    $tier_stats{'Overall'}{regions_cnt} += $r_cnt;
    $tier_stats{'Overall'}{branches_cov} += $b_cov;
    $tier_stats{'Overall'}{branches_cnt} += $b_cnt;
}

sub basename {
    my $p = shift;
    $p =~ s{^.*/}{};
    return $p;
}

# Print report
print "\n";
print "=" x 90 . "\n";
printf "                KariDNS Multi-Tier Coverage Quality Gate (Phase %d)\n", $phase;
print "=" x 90 . "\n";
printf "%-10s | %-16s | %-16s | %-16s | %-8s\n",
    "Tier", "Line Cov (%)", "Region Cov (%)", "Branch Cov (%)", "Status";
print "-" x 90 . "\n";

my $all_passed = 1;

for my $t (qw(A B C Overall)) {
    my $st = $tier_stats{$t};
    my $th = $thresholds{$t};
    
    my $l_pct = $st->{lines_cnt} ? (100.0 * $st->{lines_cov} / $st->{lines_cnt}) : 100.0;
    my $r_pct = $st->{regions_cnt} ? (100.0 * $st->{regions_cov} / $st->{regions_cnt}) : 100.0;
    my $b_pct = $st->{branches_cnt} ? (100.0 * $st->{branches_cov} / $st->{branches_cnt}) : 100.0;
    
    my $l_pass = ($l_pct >= $th->{line});
    my $r_pass = ($r_pct >= $th->{region});
    my $b_pass = ($b_pct >= $th->{branch});
    
    my $tier_pass = ($l_pass && $r_pass && $b_pass);
    $all_passed = 0 unless $tier_pass;
    
    my $status_str = $tier_pass ? "PASS" : "FAIL";
    
    printf "%-10s | %6.2f%% (%4.1f%%) | %6.2f%% (%4.1f%%) | %6.2f%% (%4.1f%%) | %-8s\n",
        ($t eq 'Overall' ? "TOTAL" : "Tier $t"),
        $l_pct, $th->{line},
        $r_pct, $th->{region},
        $b_pct, $th->{branch},
        $status_str;
}

print "=" x 90 . "\n\n";

if (!$all_passed) {
    print "[-] Coverage Gate Status: FAILED (One or more tiers below target)\n";
    if ($strict) {
        exit 1;
    }
} else {
    print "[+] Coverage Gate Status: PASSED (All tiers met target thresholds)\n";
}

exit($all_passed ? 0 : ($strict ? 1 : 0));
