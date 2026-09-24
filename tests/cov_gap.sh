#!/bin/sh
# ==============================================================================
# tests/cov_gap.sh - Show top uncovered functions by line / branch gap
# ==============================================================================
set -eu

TOP_N="${1:-25}"
DATA_FILE="${2:-coverage.profdata}"
TARGET_BIN="${3:-./karidns}"

LLVM_COV="${LLVM_COV:-llvm-cov}"

if [ ! -f "${DATA_FILE}" ]; then
    echo "Error: profile data ${DATA_FILE} not found." >&2
    exit 1
fi

OBJS=""
for obj in ./dag ./karictl ./karicheck test_cidr test_tinydns_parser test_asan_overflow test_conf_include test_config_directives test_wire_helpers test_zone_parser_paths test_tinydns_paths test_sig0_sign test_snapshot_rebuild test_dnssec_proofs test_dag_format test_dag_reassembly test_query_engine_protocol test_hash_table test_dnstap_engine test_edns_ecs_engine test_rfc_vectors test_dynamic_update_engine test_axfr_ixfr_engine test_rrl_engine test_query_engine_expanded test_response_cache test_vulnerability_fixes test_catalog_zone_engine test_snapshot_sandbox_engine test_dag_tools test_server_core; do
    if [ -x "${obj}" ]; then
        OBJS="${OBJS} -object=${obj}"
    fi
done

if [ -d "coverage_fuzz" ]; then
    for fobj in coverage_fuzz/fuzz_*; do
        if [ -x "${fobj}" ]; then
            OBJS="${OBJS} -object=${fobj}"
        fi
    done
fi

${LLVM_COV} export ${TARGET_BIN} ${OBJS} -instr-profile="${DATA_FILE}" -ignore-filename-regex="tests/|scratch/|old_patches/|third_party/" | perl -MJSON::PP -e '
use strict;
use warnings;

my $json_text = do { local $/; <STDIN> };
my $data = eval { decode_json($json_text) };
if (!$data || !$data->{data} || !$data->{data}[0]) {
    die "Failed to parse llvm-cov export JSON\n";
}

my @funcs;
for my $export (@{$data->{data}}) {
    for my $fn (@{$export->{functions} || []}) {
        my $name = $fn->{name} || "unknown";
        my @files = @{$fn->{filenames} || []};
        my $file = $files[0] || "unknown";
        
        my $lines = $fn->{lines} || {};
        my $line_cnt = $lines->{count} || 0;
        my $line_cov = $lines->{covered} || 0;
        my $line_gap = $line_cnt - $line_cov;
        
        my $branches = $fn->{branches} || {};
        my $br_cnt = $branches->{count} || 0;
        my $br_cov = $branches->{covered} || 0;
        my $br_gap = $br_cnt - $br_cov;
        
        my $regions = $fn->{regions} || [];
        my ($start_ln, $end_ln) = (0, 0);
        if (@$regions) {
            $start_ln = $regions->[0][0] || 0;
            $end_ln   = $regions->[-1][2] || $start_ln;
        }
        
        my $fn_len = ($end_ln >= $start_ln && $start_ln > 0) ? ($end_ln - $start_ln + 1) : $line_cnt;
        
        next if ($line_gap == 0 && $br_gap == 0);
        
        push @funcs, {
            name => $name,
            file => $file,
            line_gap => $line_gap,
            br_gap => $br_gap,
            fn_len => $fn_len,
            start_ln => $start_ln,
            end_ln => $end_ln,
        };
    }
}

@funcs = sort { $b->{line_gap} <=> $a->{line_gap} || $b->{br_gap} <=> $a->{br_gap} } @funcs;

my $top = $ARGV[0] || 25;
printf "%-10s %-10s %-10s %-28s %-32s %-15s\n", "UNC_LINES", "UNC_BRS", "FN_LEN", "FILE", "FUNCTION", "LINE_RANGE";
print "-" x 110 . "\n";

my $count = 0;
for my $f (@funcs) {
    last if ++$count > $top;
    my $range = ($f->{start_ln} > 0) ? "L$f->{start_ln}-L$f->{end_ln}" : "-";
    my $short_file = $f->{file};
    $short_file =~ s{^.*?([^/]+/[^/]+)$}{$1} or $short_file =~ s{^.*?([^/]+)$}{$1};
    printf "%-10d %-10d %-10d %-28s %-32s %-15s\n",
        $f->{line_gap}, $f->{br_gap}, $f->{fn_len}, $short_file, $f->{name}, $range;
}
' "$TOP_N"
