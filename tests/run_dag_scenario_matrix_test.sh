#!/bin/sh
# ==============================================================================
# run_dag_scenario_matrix_test.sh
#
# Multi-protocol scenario matrix for dag(1) against tests/mock_dag_scenario_server.pl
# and a local karidns. Every command's output is checked.
#
# Verifies:
#   1. UDP truncation (TC=1) and the automatic retry over TCP
#   2. PROXY protocol v2: LOCAL and PROXY (IPv4 / IPv6) headers as received by the
#      server, invalid specification rejected
#   3. +keepopen: several queries over one TCP connection (RFC 7766 §6.2.1)
#   4. Plain-HTTP DoH (RFC 8484 message format): POST, GET, chunked transfer
#      encoding, HTTP 400/404/500 reported as errors
#   5. Multi-message AXFR and IXFR (RFC 1995) output
#   6. Replay: PCAP link types Ethernet, 802.1Q, Linux SLL, raw IP, NULL, LOOP;
#      text query lists; --output json; --diff; --compare-recorded; --max-queries
#   7. TSIG (RFC 8945) against karidns: every HMAC algorithm signs the query and
#      verifies the signed response; keyfile with comments; BADSIG and BADKEY
#
# Not covered here (dedicated tests): +trace / +trace2 (run_dag_trace_*_test.sh),
# +nssearch (run_dag_trace_nssearch_*_test.sh), karictl (run_control_adversary_test.sh,
# run_karictl_*_test.sh), DoH/DoT over TLS (run_dag_doh_dot_axfr_test.sh).
# ==============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"

[ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
[ -x "$ROOT_DIR/karidns" ] || make -C "$ROOT_DIR" karidns

DAG="$ROOT_DIR/dag"
KARIDNS="$ROOT_DIR/karidns"
MOCK_PL="$SCRIPT_DIR/mock_dag_scenario_server.pl"
PORT=$((23000 + $$ % 7000))
KARI_PORT=$((PORT + 2))
TMP_DIR="$(mktemp -d /tmp/dag_scenario_matrix.XXXXXX)"
chmod 755 "$TMP_DIR"

MOCK_PID=""
KARI_PID=""
FAILED=0
PASSED=0

cleanup() {
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    [ -n "$KARI_PID" ] && kari_kill_tree "$KARI_PID"
    kari_kill_conf "$TMP_DIR/karidns.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

ok() { PASSED=$((PASSED + 1)); echo "  [OK] $1"; }
ng() { FAILED=$((FAILED + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && sed 's/^/      /' "$2" | head -40; return 0; }

# expect <label> <file> <extended regex>...: every regex must match a line of the file
expect() {
    label="$1"; file="$2"; shift 2
    for re in "$@"; do
        if ! grep -E -q -e "$re" "$file"; then
            ng "$label (missing: $re)" "$file"
            return 0
        fi
    done
    ok "$label"
}

# expect_not <label> <file> <extended regex>: the regex must not match (paired with an expect on the same file)
expect_not() {
    if grep -E -q -e "$3" "$2"; then ng "$1 (unexpected: $3)" "$2"; else ok "$1"; fi
}

# count_is <label> <file> <regex> <n>
count_is() {
    n=$(grep -E -c -e "$3" "$2" || true)
    if [ "$n" -eq "$4" ]; then ok "$1"; else ng "$1 ($n lines match '$3', expected $4)" "$2"; fi
}

# dag against the mock; output in $TMP_DIR/<name>.out, exit status in $TMP_DIR/<name>.rc
qm() {
    name="$1"; shift
    set +e
    "$DAG" @127.0.0.1 -p "$PORT" +nohexdump +timeout=3 +tries=1 "$@" > "$TMP_DIR/$name.out" 2>&1
    echo $? > "$TMP_DIR/$name.rc"
    set -e
}
rc_is() { # label name expected
    rc=$(cat "$TMP_DIR/$2.rc")
    if [ "$rc" -eq "$3" ]; then ok "$1"; else ng "$1 (exit status $rc, expected $3)" "$TMP_DIR/$2.out"; fi
}

echo "=== [1/7] Mock server on port $PORT ==="
perl "$MOCK_PL" --port "$PORT" --host 127.0.0.1 > "$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 30); do
    grep -q "listening" "$TMP_DIR/mock.log" 2>/dev/null && break
    sleep 0.1
done
qm ping ping.example.com
if ! grep -q "status: NOERROR" "$TMP_DIR/ping.out"; then
    echo "Error: the mock DNS server does not answer"
    cat "$TMP_DIR/mock.log" "$TMP_DIR/ping.out"
    exit 1
fi
expect "UDP query answered" "$TMP_DIR/ping.out" "^ping\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.34$" "\(UDP\)$"

echo "=== [2/7] Transport: TC fallback, PROXY v2, keepopen ==="
qm tc tc-fallback.example.com
expect "TC=1 over UDP -> retried over TCP" "$TMP_DIR/tc.out" "^;; Truncated, retrying in TCP mode\.$" \
    "ANSWER: 10," "^tc-fallback\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.10$" "\(TCP\)$"

proxy_check() { # label name expected-log-line dag-args...
    plabel="$1"; pname="$2"; pwant="$3"; shift 3
    before=$(grep -c "^PROXY " "$TMP_DIR/mock.log" || true)
    qm "$pname" +tcp "$@" example.com
    expect "$plabel: answered" "$TMP_DIR/$pname.out" "status: NOERROR" "192\.0\.2\.34$"
    grep "^PROXY " "$TMP_DIR/mock.log" | tail -n +$((before + 1)) > "$TMP_DIR/$pname.proxy"
    expect "$plabel: header as received by the server" "$TMP_DIR/$pname.proxy" "^$pwant\$"
}
proxy_check "+proxy (LOCAL)" proxy_local "PROXY cmd=LOCAL fam=0 src=-#0 dst=-#0" +proxy
proxy_check "+proxy IPv4" proxy_v4 "PROXY cmd=PROXY fam=1 src=192\.0\.2\.1#12345 dst=192\.0\.2\.2#53" "+proxy=192.0.2.1#12345-192.0.2.2#53"
proxy_check "+proxy IPv6" proxy_v6 "PROXY cmd=PROXY fam=2 src=2001:db8::1#12345 dst=2001:db8::2#53" "+proxy=2001:db8::1#12345-2001:db8::2#53"
qm proxy_err +tcp +proxy=invalid_proxy_format example.com
expect "invalid +proxy specification rejected" "$TMP_DIR/proxy_err.out" "^dag: invalid proxy specification 'invalid_proxy_format'$"
rc_is "invalid +proxy specification: exit status 1" proxy_err 1

accepts_before=$(grep -c "^ACCEPT tcp" "$TMP_DIR/mock.log" || true)
qm keepopen +tcp +keepopen example.com A example.com AAAA example.com TXT
accepts=$(( $(grep -c "^ACCEPT tcp" "$TMP_DIR/mock.log" || true) - accepts_before ))
expect "+keepopen: three answers" "$TMP_DIR/keepopen.out" "IN[[:space:]]+A[[:space:]]+192\.0\.2\.34$" \
    "IN[[:space:]]+AAAA[[:space:]]+2001:db8::34$" "IN[[:space:]]+TXT[[:space:]]+\"v=spf1 -all\"$"
count_is "+keepopen: all over TCP" "$TMP_DIR/keepopen.out" "^;; SERVER: .*\(TCP\)$" 3
if [ "$accepts" -eq 1 ]; then ok "+keepopen: one TCP connection for three queries"; else ng "+keepopen: $accepts TCP connections for three queries (expected 1)"; fi

echo "=== [3/7] Plain-HTTP DoH ==="
qm doh_post +http-plain-post example.com
expect "DoH POST" "$TMP_DIR/doh_post.out" "status: NOERROR" "192\.0\.2\.34$" "\(HTTP\)$"
qm doh_get +http-plain-get example.com
expect "DoH GET" "$TMP_DIR/doh_get.out" "status: NOERROR" "192\.0\.2\.34$" "\(HTTP-GET\)$"
qm doh_chunked +http-plain-post chunked.example.com
expect "DoH chunked transfer encoding" "$TMP_DIR/doh_chunked.out" "status: NOERROR" "^chunked\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.34$"
for code in 400 404 500; do
    qm "doh_$code" +http-plain-post "error$code.doh.test"
    expect "DoH HTTP $code reported" "$TMP_DIR/doh_$code.out" "^;; DoH server returned HTTP status $code \(expected 200 OK\)$" "^;; no servers could be reached$"
    rc_is "DoH HTTP $code: exit status 9" "doh_$code" 9
done

echo "=== [4/7] AXFR / IXFR ==="
qm axfr -t AXFR multi-axfr.example.com
expect "multi-message AXFR" "$TMP_DIR/axfr.out" "^host20\.multi-axfr\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+10\.0\.0\.20$" \
    "^txt20\.multi-axfr\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+TXT" "^ipv6-20\.multi-axfr\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+AAAA[[:space:]]+2001:db8::14$" \
    "^;; XFR size: 62 records \(messages 3, bytes [0-9]+\)$"
count_is "AXFR: SOA at start and end" "$TMP_DIR/axfr.out" "IN[[:space:]]+SOA[[:space:]]" 2
qm ixfr -t IXFR=100 ixfr-delta.example.com
expect "IXFR delta" "$TMP_DIR/ixfr.out" "^old\.ixfr-delta\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.1$" \
    "^new\.ixfr-delta\.example\.com\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.2$" "^;; XFR size: 6 records \(messages 1, bytes [0-9]+\)$"
count_is "IXFR: SOA 200 / 100 / 200 / 200" "$TMP_DIR/ixfr.out" "IN[[:space:]]+SOA[[:space:]].* 200 7200 " 3

echo "=== [5/7] Replay ==="
# One query (example.com A, from 127.0.0.1:12345 to 127.0.0.1:53) per capture.
perl - "$TMP_DIR" <<'PERL'
use strict;
use warnings;
my $dir = shift;
sub write_pcap {
    my ($file, $linktype, @packets) = @_;
    open my $fh, ">", $file or die "Cannot open $file: $!";
    binmode $fh;
    print $fh pack("VvvVVVV", 0xa1b2c3d4, 2, 4, 0, 0, 65535, $linktype);
    for my $raw (@packets) {
        my $len = length($raw);
        print $fh pack("VVVV", 1700000000, 1000, $len, $len) . $raw;
    }
    close $fh;
}
my $dns = pack("n6", 0x1234, 0x0100, 1, 0, 0, 0) . "\x07example\x03com\x00\x00\x01\x00\x01";
my $udp = pack("nnnn", 12345, 53, length($dns) + 8, 0);
my $ip = pack("CCnnnCCnCCCCCCCC", 0x45, 0, length($dns) + 28, 1, 0, 64, 17, 0, 127, 0, 0, 1, 127, 0, 0, 1);
my $l3 = $ip . $udp . $dns;
my $mac = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb";
write_pcap("$dir/eth.pcap", 1, $mac . "\x08\x00" . $l3);                        # LINKTYPE_ETHERNET
write_pcap("$dir/vlan.pcap", 1, $mac . "\x81\x00\x00\x64\x08\x00" . $l3);        # 802.1Q tag
# LINKTYPE_LINUX_SLL (113): packet type, ARPHRD type, address length, 8-byte address, protocol (16 bytes)
write_pcap("$dir/sll.pcap", 113, pack("nnna8n", 0, 1, 6, "\x00\x11\x22\x33\x44\x55", 0x0800) . $l3);
write_pcap("$dir/raw.pcap", 101, $l3);                                           # LINKTYPE_RAW
write_pcap("$dir/null.pcap", 0, pack("V", 2) . $l3);                             # LINKTYPE_NULL, host order
write_pcap("$dir/loop.pcap", 108, pack("N", 2) . $l3);                           # LINKTYPE_LOOP, network order
PERL

replay() { # name args...
    name="$1"; shift
    set +e
    "$DAG" --replay "$@" --server1 "127.0.0.1:$PORT" > "$TMP_DIR/$name.out" 2>&1
    echo $? > "$TMP_DIR/$name.rc"
    set -e
}
for f in eth vlan sll raw null loop; do
    replay "rep_$f" "$TMP_DIR/$f.pcap"
    expect "replay $f.pcap" "$TMP_DIR/rep_$f.out" "^Total Queries Replayed: 1$" "^  Received: 1$" "^  RCODEs:   NOERROR=1 "
    rc_is "replay $f.pcap: exit status 0" "rep_$f" 0
done
replay rep_json "$TMP_DIR/eth.pcap" --output json
expect "replay --output json" "$TMP_DIR/rep_json.out" "^  \"total_queries\": 1,$" "\"received\": 1,$" "\"noerror\": 1,$"
replay rep_diff "$TMP_DIR/eth.pcap" --server2 "127.0.0.1:$PORT" --diff
expect "replay --diff (same server twice)" "$TMP_DIR/rep_diff.out" "^  Compared: +1$" "^  Identical responses: 1 \(100\.0%\)$" "^  Mismatched responses: 0$"
replay rep_comp "$TMP_DIR/eth.pcap" --compare-recorded
expect "replay --compare-recorded" "$TMP_DIR/rep_comp.out" "^  RCODE Mismatches: +0$" "^  RRset Mismatches: +0$"
cat > "$TMP_DIR/text_queries.txt" <<'EOF'
# Comment line to skip
; Semicolon comment

example.com A +dnssec
example.com AAAA +nodnssec
example.com TXT +tcp
example.com MX +udp
EOF
replay rep_txt "$TMP_DIR/text_queries.txt"
expect "replay of a text query list (comments skipped)" "$TMP_DIR/rep_txt.out" "^Total Queries Replayed: 4$" "^  Received: 4$" "NOERROR=4 "
replay rep_limit "$TMP_DIR/text_queries.txt" --max-queries 1
expect "replay --max-queries 1" "$TMP_DIR/rep_limit.out" "^  Sent: +1$" "^  Received: 1$"

echo "=== [6/7] karidns for TSIG on port $KARI_PORT ==="
SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
cat > "$TMP_DIR/tsig.zone" <<'EOF'
$ORIGIN tsig.test.
$TTL 300
@   IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@   IN NS  ns1
ns1 IN A   192.0.2.1
www IN A   192.0.2.80
EOF
{
    echo "options { port $KARI_PORT; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    for a in md5 sha1 sha224 sha256 sha384 sha512; do
        echo "key \"k-$a\" { algorithm hmac-$a; secret \"$SECRET\"; };"
    done
    echo "zone \"tsig.test\" { type master; file \"$TMP_DIR/tsig.zone\"; };"
} > "$TMP_DIR/karidns.conf"
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
KARI_PID=$!
for _ in $(seq 1 50); do
    "$DAG" @127.0.0.1 -p "$KARI_PORT" tsig.test SOA +short +timeout=1 +tries=1 2>/dev/null | grep -q hostmaster && break
    sleep 0.2
done

qk() { # name args...
    name="$1"; shift
    "$DAG" @127.0.0.1 -p "$KARI_PORT" +nohexdump +timeout=3 +tries=1 www.tsig.test A "$@" > "$TMP_DIR/$name.out" 2>&1 || true
}

echo "=== [7/7] TSIG (RFC 8945) ==="
for spec in md5:16 sha1:20 sha224:28 sha256:32 sha384:48 sha512:64; do
    a=${spec%%:*}; maclen=${spec#*:}
    qk "tsig_$a" -y "hmac-$a:k-$a:$SECRET"
    expect "TSIG hmac-$a: signed query, verified signed response" "$TMP_DIR/tsig_$a.out" "status: NOERROR" \
        "^www\.tsig\.test\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.80$" \
        "^k-$a\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+TSIG[[:space:]]+hmac-$a\.[[:space:]]+[0-9]+[[:space:]]+300[[:space:]]+$maclen[[:space:]].*[[:space:]]NOERROR[[:space:]]+0[[:space:]]*$"
    expect_not "TSIG hmac-$a: no verification warning" "$TMP_DIR/tsig_$a.out" "Couldn't verify|could not be validated"
done
cat > "$TMP_DIR/tsig_comments.key" <<EOF
# TSIG Key Configuration with comments and padding
// C++ style comment line
key "k-sha384" {
    algorithm hmac-sha384;
    secret "$SECRET"; # base64 secret
};
EOF
qk tsig_file -k "$TMP_DIR/tsig_comments.key"
expect "TSIG keyfile with comments (-k)" "$TMP_DIR/tsig_file.out" "status: NOERROR" "^k-sha384\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+TSIG[[:space:]]+hmac-sha384\..*[[:space:]]NOERROR[[:space:]]+0"
expect_not "TSIG keyfile: no verification warning" "$TMP_DIR/tsig_file.out" "Couldn't verify|could not be validated"
# RFC 8945 §5.2.2 / §5.2.1: wrong secret -> BADSIG, unknown key -> BADKEY (NOTAUTH, unsigned)
qk tsig_badsig -y "hmac-sha256:k-sha256:d3Jvbmc="
expect "TSIG wrong secret -> BADSIG" "$TMP_DIR/tsig_badsig.out" "status: NOTAUTH" "TSIG[[:space:]]+hmac-sha256\..*[[:space:]]BADSIG[[:space:]]" "^;; Couldn't verify signature: tsig indicates error$"
qk tsig_badkey -y "hmac-sha256:nokey:$SECRET"
expect "TSIG unknown key -> BADKEY" "$TMP_DIR/tsig_badkey.out" "status: NOTAUTH" "^nokey\.[[:space:]].*TSIG[[:space:]]+hmac-sha256\..*[[:space:]]BADKEY[[:space:]]"

echo "=== Results: $PASSED passed, $FAILED failed ==="
if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
exit 0
