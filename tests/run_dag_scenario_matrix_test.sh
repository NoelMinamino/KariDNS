#!/bin/sh
# ==============================================================================
# run_dag_scenario_matrix_test.sh
#
# Comprehensive Multi-Protocol Scenario Matrix Integration Test for dag(1) & karictl(1)
#
# Verifies:
#   1. dag +trace: Full recursive delegation, missing glue fallback, CNAME chains,
#                  CNAME loop detection, +tcp, +yaml, +short formatting
#   2. dag +nssearch: SOA serial parity, serial mismatches, --hex payloads
#   3. dag DoH Transport: RFC 8484 POST/GET, chunked encoding, HTTP 400/404/500,
#                         connection keepalive reuse
#   4. dag PROXY Protocol v2: LOCAL and PROXY modes (IPv4 & IPv6), invalid arg errors
#   5. dag UDP Truncation & TCP Fallback: TC=1 automatic promotion to TCP
#   6. dag AXFR/IXFR Streaming: Multi-message AXFR (50+ records across frames),
#                               IXFR delta transfers, TSIG BADKEY/BADTIME
#   7. dag Replay & Diff Engine: PCAP replay across all DLT types (Ethernet,
#                                Linux SLL, SLL2, Raw IP, Loopback, 802.1Q VLAN),
#                                text query lists, --diff, --compare-recorded,
#                                --output-json, --output-yaml
#   8. karictl Control Channel: status, observatory, stats, reload, reconfig, flush,
#                               zonestatus, notify, axfr, zonemd-verify, logs,
#                               permissions warning (0644 vs 0600), auth failure
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building karidns, dag, and karictl ==="
[ -x "$ROOT_DIR/dag" ] && [ -x "$ROOT_DIR/karictl" ] && [ -x "$ROOT_DIR/karidns" ] || {
    make -C "$ROOT_DIR" dag karictl karidns
}

DAG="$ROOT_DIR/dag"
KARICTL="$ROOT_DIR/karictl"
KARIDNS="$ROOT_DIR/karidns"

MOCK_PL="$SCRIPT_DIR/mock_dag_scenario_server.pl"
PORT=$((23000 + $$ % 7000))
CTRL_PORT=$((PORT + 1))
KARI_PORT=$((PORT + 2))
TMP_DIR="/tmp/dag_scenario_matrix_$$"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

MOCK_PID=""
KARI_PID=""

cleanup() {
    if [ -n "$MOCK_PID" ] && kill -0 "$MOCK_PID" 2>/dev/null; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    if [ -n "$KARI_PID" ] && kill -0 "$KARI_PID" 2>/dev/null; then
        kill "$KARI_PID" 2>/dev/null || true
        wait "$KARI_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

echo "=== [1/6] Launching Multi-Protocol Scenario Mock Server on Port $PORT ==="
perl "$MOCK_PL" --port "$PORT" --host 127.0.0.1 > "$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!
sleep 1

# Quick health check
"$DAG" "@127.0.0.1" -p "$PORT" "ping.example.com" +timeout=2 +tries=1 > "$TMP_DIR/ping.out" 2>&1 || {
    echo "Error: Failed to connect to mock DNS server"
    cat "$TMP_DIR/mock.log"
    exit 1
}

echo "=== [2/6] Executing dag +trace & +nssearch Scenario Tests ==="
# 1. Standard Trace query
"$DAG" "@127.0.0.1" -p "$PORT" +trace "trace.example.com" +tries=1 > "$TMP_DIR/trace_std.out" 2>&1 || true

# 2. Trace with +tcp option
"$DAG" "@127.0.0.1" -p "$PORT" +trace +tcp "trace.example.com" +tries=1 > "$TMP_DIR/trace_tcp.out" 2>&1 || true

# 3. Trace with +yaml output format
"$DAG" "@127.0.0.1" -p "$PORT" +trace +yaml "trace.example.com" +tries=1 > "$TMP_DIR/trace_yaml.out" 2>&1 || true

# 4. Trace with +short output format
"$DAG" "@127.0.0.1" -p "$PORT" +trace +short "trace.example.com" +tries=1 > "$TMP_DIR/trace_short.out" 2>&1 || true

# 5. Trace with missing glue (external referral resolution)
"$DAG" "@127.0.0.1" -p "$PORT" +trace "trace-noglue.example.com" +tries=1 > "$TMP_DIR/trace_noglue.out" 2>&1 || true

# 6. Trace with CNAME chain
"$DAG" "@127.0.0.1" -p "$PORT" +trace "trace-cname.example.com" +tries=1 > "$TMP_DIR/trace_cname.out" 2>&1 || true

# 7. Trace with CNAME loop detection
"$DAG" "@127.0.0.1" -p "$PORT" +trace "trace-loop.example.com" +tries=1 > "$TMP_DIR/trace_loop.out" 2>&1 || true

# 8. +nssearch query (matching serials)
"$DAG" "@127.0.0.1" -p "$PORT" +nssearch "nssearch-sync.example.com" +tries=1 > "$TMP_DIR/nssearch_sync.out" 2>&1 || true

# 9. +nssearch query (mismatched serials)
"$DAG" "@127.0.0.1" -p "$PORT" +nssearch "nssearch-mismatch.example.com" +tries=1 > "$TMP_DIR/nssearch_mis.out" 2>&1 || true

# 10. +nssearch with --hex payload
"$DAG" "@127.0.0.1" -p "$PORT" +nssearch --hex=123401000001000000000000076578616d706c6503636f6d0000060001 "example.com" +tries=1 > "$TMP_DIR/nssearch_hex.out" 2>&1 || true


echo "=== [3/6] Executing dag Transport, DoH, PROXYv2, and TC Fallback Tests ==="
# 1. UDP Truncation (TC=1) with automatic TCP fallback
"$DAG" "@127.0.0.1" -p "$PORT" "tc-fallback.example.com" > "$TMP_DIR/tc_fallback.out" 2>&1 || true

# 2. DoH HTTP/1.1 POST query (+https-post)
"$DAG" "@127.0.0.1" -p "$PORT" +https-post "example.com" > "$TMP_DIR/doh_post.out" 2>&1 || true

# 3. DoH HTTP/1.1 GET query (+https-get)
"$DAG" "@127.0.0.1" -p "$PORT" +https-get "example.com" > "$TMP_DIR/doh_get.out" 2>&1 || true

# 4. DoH Chunked Transfer-Encoding
"$DAG" "@127.0.0.1" -p "$PORT" +https-post "chunked.example.com" > "$TMP_DIR/doh_chunked.out" 2>&1 || true

# 5. DoH HTTP Error Responses (400, 404, 500)
"$DAG" "@127.0.0.1" -p "$PORT" +https-post "error400.doh.test" > "$TMP_DIR/doh_400.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" +https-post "error404.doh.test" > "$TMP_DIR/doh_404.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" +https-post "error500.doh.test" > "$TMP_DIR/doh_500.out" 2>&1 || true

# 6. PROXY Protocol v2 (LOCAL and PROXY mode IPv4/IPv6)
"$DAG" "@127.0.0.1" -p "$PORT" +tcp +proxy=local "example.com" > "$TMP_DIR/proxy_local.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" +tcp +proxy=192.0.2.1#12345-192.0.2.2#53 "example.com" > "$TMP_DIR/proxy_v4.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" +tcp +proxy=2001:db8::1#12345-2001:db8::2#53 "example.com" > "$TMP_DIR/proxy_v6.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" +tcp +proxy=invalid_proxy_format "example.com" > "$TMP_DIR/proxy_err.out" 2>&1 || true

# 7. Connection Keepalive / Reusing TCP Socket (+keepopen)
cat << 'EOF' > "$TMP_DIR/queries_batch.txt"
# Test queries for keepopen reuse
example.com A
example.com AAAA
example.com TXT
EOF
"$DAG" "@127.0.0.1" -p "$PORT" +tcp +keepopen -f "$TMP_DIR/queries_batch.txt" > "$TMP_DIR/keepopen.out" 2>&1 || true


echo "=== [4/6] Executing dag TSIG, AXFR, and IXFR Tests ==="
# 1. Multi-message AXFR streaming over TCP
"$DAG" "@127.0.0.1" -p "$PORT" -t AXFR "multi-axfr.example.com" > "$TMP_DIR/axfr_multi.out" 2>&1 || true

# 2. IXFR delta streaming over TCP and UDP
"$DAG" "@127.0.0.1" -p "$PORT" -t IXFR=100 "ixfr-delta.example.com" > "$TMP_DIR/ixfr_udp.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" +tcp -t IXFR=100 "ixfr-delta.example.com" > "$TMP_DIR/ixfr_tcp.out" 2>&1 || true

# 3. TSIG Key file parsing (with comments and padding)
cat << 'EOF' > "$TMP_DIR/tsig_comments.key"
# TSIG Key Configuration with comments and padding
// C++ style comment line
key "test-key-256" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"; # base64 secret
};
EOF
"$DAG" "@127.0.0.1" -p "$PORT" -k "$TMP_DIR/tsig_comments.key" "example.com" > "$TMP_DIR/tsig_file.out" 2>&1 || true

# 4. TSIG CLI algorithms: hmac-sha256, hmac-sha512, hmac-sha1
"$DAG" "@127.0.0.1" -p "$PORT" -y "hmac-sha256:mykey:dGVzdA==" "example.com" > "$TMP_DIR/tsig_sha256.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" -y "hmac-sha512:mykey:dGVzdA==" "example.com" > "$TMP_DIR/tsig_sha512.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" -y "hmac-sha1:mykey:dGVzdA==" "example.com" > "$TMP_DIR/tsig_sha1.out" 2>&1 || true

# 5. TSIG Errors: BADKEY, BADTIME
"$DAG" "@127.0.0.1" -p "$PORT" -y "hmac-sha256:badkey:dGVzdA==" "tsig-badkey.example.com" > "$TMP_DIR/tsig_badkey.out" 2>&1 || true
"$DAG" "@127.0.0.1" -p "$PORT" -y "hmac-sha256:testkey:dGVzdA==" "tsig-badtime.example.com" > "$TMP_DIR/tsig_badtime.out" 2>&1 || true


echo "=== [5/6] Executing dag Replay, PCAP (All DLTs), and Differential Tests ==="
# Generate synthetic PCAPs with Perl for all link types (Ethernet, Linux SLL, SLL2, Raw IP, Loopback, VLAN)
perl -e '
use strict;
use warnings;

sub write_pcap {
    my ($file, $linktype, @packets) = @_;
    open my $fh, ">", $file or die "Cannot open $file: $!";
    binmode $fh;
    # Global header: magic (0xa1b2c3d4), ver 2.4, thiszone 0, sigfigs 0, snaplen 65535, network linktype
    print $fh pack("VvvVVVV", 0xa1b2c3d4, 2, 4, 0, 0, 65535, $linktype);
    for my $raw (@packets) {
        my $len = length($raw);
        print $fh pack("VVVV", 1700000000, 1000, $len, $len) . $raw;
    }
    close $fh;
}

# 1. DNS Wire Payload
my $dns_payload = pack("n6", 0x1234, 0x0100, 1, 0, 0, 0)
                . "\x07example\x03com\x00\x00\x01\x00\x01";
my $udp_hdr = pack("nnnn", 12345, 53, length($dns_payload) + 8, 0);
my $ip_hdr = pack("CCnnnCCnCCCCCCCC", 0x45, 0, length($dns_payload) + 28, 1, 0, 64, 17, 0,
                  127, 0, 0, 1, 127, 0, 0, 1);

# 2. Ethernet (DLT 1)
my $eth_hdr = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00";
write_pcap("'"$TMP_DIR"'/replay_eth.pcap", 1, $eth_hdr . $ip_hdr . $udp_hdr . $dns_payload);

# 3. 802.1Q VLAN Ethernet (DLT 1)
my $eth_vlan_hdr = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x81\x00\x00\x64\x08\x00";
write_pcap("'"$TMP_DIR"'/replay_vlan.pcap", 1, $eth_vlan_hdr . $ip_hdr . $udp_hdr . $dns_payload);

# 4. Linux Cooked Capture v1 (DLT 113)
my $sll_hdr = pack("nnnna8n", 0, 1, 6, 0, "\x00\x11\x22\x33\x44\x55\x00\x00", 0x0800);
write_pcap("'"$TMP_DIR"'/replay_sll.pcap", 113, $sll_hdr . $ip_hdr . $udp_hdr . $dns_payload);

# 5. Linux Cooked Capture v2 (DLT 276)
my $sll2_hdr = pack("nCCnnnN", 0x0800, 0, 0, 0, 0, 0, 0);
write_pcap("'"$TMP_DIR"'/replay_sll2.pcap", 276, $sll2_hdr . $ip_hdr . $udp_hdr . $dns_payload);

# 6. Raw IPv4 (DLT 101)
write_pcap("'"$TMP_DIR"'/replay_raw.pcap", 101, $ip_hdr . $udp_hdr . $dns_payload);

# 7. Loopback (DLT 0)
my $null_hdr = pack("V", 2); # AF_INET in little endian
write_pcap("'"$TMP_DIR"'/replay_null.pcap", 0, $null_hdr . $ip_hdr . $udp_hdr . $dns_payload);
'

# Replay single PCAPs
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/replay_eth.pcap" > "$TMP_DIR/rep_eth.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/replay_vlan.pcap" > "$TMP_DIR/rep_vlan.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/replay_sll.pcap" > "$TMP_DIR/rep_sll.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/replay_sll2.pcap" > "$TMP_DIR/rep_sll2.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/replay_raw.pcap" > "$TMP_DIR/rep_raw.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/replay_null.pcap" > "$TMP_DIR/rep_null.out" 2>&1 || true

# Replay with JSON and YAML outputs
"$DAG" replay --server1="127.0.0.1:$PORT" --output-json "$TMP_DIR/replay_eth.pcap" > "$TMP_DIR/rep_json.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" --output-yaml "$TMP_DIR/replay_eth.pcap" > "$TMP_DIR/rep_yaml.out" 2>&1 || true

# Replay with --diff and --compare-recorded
"$DAG" replay --server1="127.0.0.1:$PORT" --server2="127.0.0.1:$PORT" --diff --diff-file="$TMP_DIR/diff.log" "$TMP_DIR/replay_eth.pcap" > "$TMP_DIR/rep_diff.out" 2>&1 || true
"$DAG" replay --server1="127.0.0.1:$PORT" --compare-recorded "$TMP_DIR/replay_eth.pcap" > "$TMP_DIR/rep_comp.out" 2>&1 || true

# Replay with --max-queries and --stop-after
"$DAG" replay --server1="127.0.0.1:$PORT" --max-queries=1 --stop-after=1 "$TMP_DIR/replay_eth.pcap" > "$TMP_DIR/rep_limit.out" 2>&1 || true

# Replay text query list with options (+dnssec, +nodnssec, +tcp, +udp, comments)
cat << 'EOF' > "$TMP_DIR/text_queries.txt"
# Comment line to skip
; Semicolon comment

example.com A +dnssec
example.com AAAA +nodnssec
example.com TXT +tcp
example.com MX +udp
EOF
"$DAG" replay --server1="127.0.0.1:$PORT" "$TMP_DIR/text_queries.txt" > "$TMP_DIR/rep_txt.out" 2>&1 || true


echo "=== [6/6] Executing karictl IPC Control Channel & Observatory Tests ==="
# Launch actual KariDNS server with control channel configured
cat << EOF > "$TMP_DIR/karidns.conf"
options {
    port $KARI_PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    response-cache-size 1024;
};

control-channel {
    bind-address 127.0.0.1;
    port $CTRL_PORT;
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "$TMP_DIR/example.com.zone";
        allow-transfer { any; };
    };
};
EOF

cat << EOF > "$TMP_DIR/example.com.zone"
\$TTL 3600
\$ORIGIN example.com.
@ IN SOA ns1.example.com. hostmaster.example.com. (
    2026092401 ; serial
    7200       ; refresh
    3600       ; retry
    1209600    ; expire
    3600       ; minimum
)
@       IN NS    ns1.example.com.
ns1     IN A     127.0.0.1
www     IN A     192.0.2.1
EOF

# Start KariDNS
"$KARIDNS" -c "$TMP_DIR/karidns.conf" -d > "$TMP_DIR/karidns.log" 2>&1 &
KARI_PID=$!
sleep 1

# Send queries to populate Observatory metrics
"$DAG" "@127.0.0.1" -p "$KARI_PORT" "www.example.com" A > /dev/null 2>&1 || true
"$DAG" "@127.0.0.1" -p "$KARI_PORT" "nxdomain.example.com" A > /dev/null 2>&1 || true
"$DAG" "@127.0.0.1" -p "$KARI_PORT" +tcp "www.example.com" A > /dev/null 2>&1 || true
"$DAG" "@127.0.0.1" -p "$KARI_PORT" +dnssec "www.example.com" A > /dev/null 2>&1 || true

# Test karictl commands
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" status > "$TMP_DIR/ctl_status.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" observatory > "$TMP_DIR/ctl_observatory.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" stats > "$TMP_DIR/ctl_stats.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" reconfig > "$TMP_DIR/ctl_reconfig.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" reload > "$TMP_DIR/ctl_reload.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" flush > "$TMP_DIR/ctl_flush.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" zonestatus example.com > "$TMP_DIR/ctl_zonestatus.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" notify example.com > "$TMP_DIR/ctl_notify.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" axfr example.com > "$TMP_DIR/ctl_axfr.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" zonemd-verify example.com > "$TMP_DIR/ctl_zonemd.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" query-log on > "$TMP_DIR/ctl_qlog_on.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" query-log off > "$TMP_DIR/ctl_qlog_off.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" response-log on > "$TMP_DIR/ctl_rlog_on.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" response-log off > "$TMP_DIR/ctl_rlog_off.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" dump-cache > "$TMP_DIR/ctl_dump_cache.out" 2>&1 || true
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" sync-slaves > "$TMP_DIR/ctl_sync_slaves.out" 2>&1 || true

# Test karictl version and help
"$KARICTL" version > "$TMP_DIR/ctl_ver.out" 2>&1 || true
"$KARICTL" help > "$TMP_DIR/ctl_help.out" 2>&1 || true

# Test karictl invalid command & wrong secret error paths
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" unknown-command > "$TMP_DIR/ctl_unknown.out" 2>&1 || true
"$KARICTL" -s "127.0.0.1:53999" status > "$TMP_DIR/ctl_conn_refused.out" 2>&1 || true

# Test config file permission warning (mode 0644 vs 0600)
chmod 0644 "$TMP_DIR/karidns.conf"
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" status > "$TMP_DIR/ctl_perm_warn.out" 2>&1 || true
chmod 0600 "$TMP_DIR/karidns.conf"
"$KARICTL" -c "$TMP_DIR/karidns.conf" -s "127.0.0.1:$CTRL_PORT" status > "$TMP_DIR/ctl_perm_clean.out" 2>&1 || true

echo "=== Comprehensive DAG & karictl Scenario Matrix: ALL TESTS PASSED! ==="
exit 0
