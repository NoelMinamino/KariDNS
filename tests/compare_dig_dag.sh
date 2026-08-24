#!/bin/sh
# ==============================================================================
# tests/compare_dig_dag.sh
#
# Compares the query responses of BIND 9 dig and KariDNS dag against a local
# KariDNS authoritative server to verify exact protocol/formatting compatibility.
#
# Usage:
#   sh tests/compare_dig_dag.sh             (Runs full test comparison suite)
#   sh tests/compare_dig_dag.sh <query...>  (Runs custom single query comparison)
# ==============================================================================

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
PORT=53556
TEST_DIR=".compare_tmp_$$"

# Check dependencies
if ! command -v dig >/dev/null 2>&1; then
    echo "Error: BIND 9 'dig' is not installed on this system." >&2
    exit 1
fi

DAG="$REPO_DIR/dag"
KARIDNS="$REPO_DIR/karidns"

make -C "$REPO_DIR" dag
make -C "$REPO_DIR" karidns

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

# Configure local KariDNS authoritative server
cat << EOF > karidns.conf
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    rfc10029-mqtype yes;
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "${SCRIPT_DIR}/zones/example.com.zone";
        allow-transfer { any; };
    };
};
EOF

# Start local server in background
"$KARIDNS" -f karidns.conf > karidns.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Output normalizer to mask only non-deterministic fields, tool banner, and dag-specific comparison summary
normalize_output() {
    sed -E \
        -e '/^; <<>>/d' \
        -e '/^;; global options: \+cmd/d' \
        -e '/^; \([0-9]+ servers? found\)/d' \
        -e 's/^(dig|dag):/dig:/' \
        -e 's/id: [0-9]+/id: <ID>/g' \
        -e 's/; COOKIE: [0-9a-fA-F]+/;; COOKIE: <COOKIE>/g' \
        -e 's/[0-9]+[[:space:]]+IN[[:space:]]+/<TTL> IN /g' \
        -e 's/;; Query time: [0-9]+ (msec|usec)/;; Query time: <TIME>/g' \
        -e 's/ in [0-9]+ ms/ in <TIME> ms/g' \
        -e 's/;; WHEN: .*/;; WHEN: <DATE>/g' \
        -e '/;; (no usable response received|connection failed|no servers could be reached)/d' \
        -e '/^;; === MULTI-SERVER COMPARISON SUMMARY ===/,$d' \
        -e 's/[[:space:]]+/ /g' \
        -e 's/[[:space:]]*$//' | \
    awk 'NF { print }'
}

TOTAL=0
MATCH=0
MISMATCH=0

compare_query() {
    NAME="$1"
    ARGS="$2"
    TOTAL=$((TOTAL + 1))

    # Run dig and dag (passing +nohexdump in global options to dag by default)
    dig @127.0.0.1 -p $PORT $ARGS 2>&1 | normalize_output > dig.out || true
    "$DAG" @127.0.0.1 -p $PORT +nohexdump $ARGS 2>&1 | normalize_output > dag.out || true

    if diff -u dig.out dag.out > diff.out 2>&1; then
        echo "  [MATCH] $NAME"
        MATCH=$((MATCH + 1))
    else
        echo "  [DIFF]  $NAME"
        echo "    Args: $ARGS"
        echo "    --- Diff (dig vs dag) ---"
        sed 's/^/      /' diff.out | head -n 25
        echo "    -------------------------"
        MISMATCH=$((MISMATCH + 1))
    fi
}

compare_raw() {
    NAME="$1"
    DIG_CMD="$2"
    DAG_CMD="$3"
    TOTAL=$((TOTAL + 1))

    eval "$DIG_CMD" 2>&1 | normalize_output > dig.out || true
    eval "$DAG_CMD" 2>&1 | normalize_output > dag.out || true

    if diff -u dig.out dag.out > diff.out 2>&1; then
        echo "  [MATCH] $NAME"
        MATCH=$((MATCH + 1))
    else
        echo "  [DIFF]  $NAME"
        echo "    Cmd: $DIG_CMD vs $DAG_CMD"
        echo "    --- Diff (dig vs dag) ---"
        sed 's/^/      /' diff.out | head -n 25
        echo "    -------------------------"
        MISMATCH=$((MISMATCH + 1))
    fi
}

echo "========================================================"
echo "Comparing BIND 9 dig vs KariDNS dag"
echo "Target: KariDNS Authoritative Server (127.0.0.1:$PORT)"
echo "========================================================"

if [ $# -gt 0 ]; then
    echo "Running custom query comparison: $@"
    compare_query "Custom Query" "$*"
else
    echo "--------------------------------------------------------"
    echo "1. Record Types & Resolution"
    echo "--------------------------------------------------------"
    compare_query "Standard A query" "www.example.com A +noedns"
    compare_query "Standard AAAA query" "www.example.com AAAA +noedns"
    compare_query "SOA query" "example.com SOA +noedns"
    compare_query "NS query" "example.com NS +noedns"
    compare_query "MX query" "example.com MX +noedns"
    compare_query "TXT query" "example.com TXT +noedns"
    compare_query "SRV query" "_sip._tcp.example.com SRV +noedns"
    compare_query "NAPTR query" "_ldap._tcp.example.com NAPTR +noedns"
    compare_query "HTTPS query" "www.example.com HTTPS +noedns"
    compare_query "SVCB query" "_8443._tcp.svc.example.com SVCB +noedns"
    compare_query "TLSA query" "_443._tcp.www.example.com TLSA +noedns"
    compare_query "SSHFP query" "ns1.example.com SSHFP +noedns"
    compare_query "CAA query" "example.com CAA +noedns"
    compare_query "LOC query" "office.example.com LOC +noedns"
    compare_query "CNAME resolution" "ftp.example.com A +noedns"
    compare_query "Wildcard query" "foo.wild.example.com A +noedns"
    compare_query "NXDOMAIN response" "nonexistent.example.com A +noedns"
    compare_query "NODATA response" "www.example.com TXT +noedns"

    echo "--------------------------------------------------------"
    echo "2. Format & Layout Options"
    echo "--------------------------------------------------------"
    compare_query "Short mode (+short)" "www.example.com A +short"
    compare_query "No class (+noclass)" "www.example.com A +noclass +noedns"
    compare_query "TTL units (+ttlunits)" "www.example.com A +ttlunits +noedns"
    compare_query "Unknown format (+unknownformat)" "www.example.com A +noall +answer +unknownformat +noedns"
    compare_query "Omit TTL ID (+nottlid)" "www.example.com A +nottlid +noedns"
    compare_query "Multiline mode (+multiline)" "example.com SOA +multiline +noedns"
    compare_query "No comments (+nocomments)" "www.example.com A +nocomments +noedns"
    compare_query "No command header (+nocmd)" "www.example.com A +nocmd +noedns"
    compare_query "No answer section (+noanswer)" "www.example.com A +noanswer +noedns"
    compare_query "No question section (+noquestion)" "www.example.com A +noquestion +noedns"
    compare_query "Combined +noall +answer" "www.example.com A +noall +answer"
    compare_query "No stats section (+nostats)" "www.example.com A +nostats +noedns"

    echo "--------------------------------------------------------"
    echo "3. DNSSEC & Crypto Formatting"
    echo "--------------------------------------------------------"
    compare_query "DNSSEC OK (+dnssec)" "example.com DNSKEY +dnssec +nocookie"
    compare_query "RR Comments on DNSKEY (+rrcomments)" "example.com DNSKEY +rrcomments +noedns"
    compare_query "Omit Crypto on DNSKEY (+nocrypto)" "example.com DNSKEY +nocrypto +noedns"
    compare_query "Split width (+split=16)" "example.com DNSKEY +split=16 +noedns"

    echo "--------------------------------------------------------"
    echo "4. EDNS0 & Transport Options"
    echo "--------------------------------------------------------"
    compare_query "EDNS Buffer Size (+bufsize=4096)" "www.example.com A +bufsize=4096 +nocookie"
    compare_query "EDNS NSID Option (+nsid)" "www.example.com A +nsid +nocookie"
    compare_query "EDNS Subnet (+subnet)" "www.example.com A +subnet=192.0.2.0/24 +nocookie"
    compare_query "EDNS Padding (+padding)" "www.example.com A +padding=64 +nocookie"
    compare_query "EDNS Cookie (+cookie)" "www.example.com A +cookie=0102030405060708"
    compare_query "Standard TCP Query (+tcp)" "www.example.com A +tcp +noedns"

    echo "--------------------------------------------------------"
    echo "5. Zone Transfers (AXFR)"
    echo "--------------------------------------------------------"
    compare_query "Standard AXFR Transfer" "example.com AXFR"
    compare_query "AXFR Short Mode (+short)" "example.com AXFR +short"
    compare_query "AXFR No Comments (+nocomments)" "example.com AXFR +nocomments"

    echo "--------------------------------------------------------"
    echo "6. Default Query (No domain/type specified)"
    echo "--------------------------------------------------------"
    compare_query "Default Query against @server (defaults to . NS)" "+noedns"

    echo "--------------------------------------------------------"
    echo "7. TLS / DoT Verification (RFC 7858)"
    echo "--------------------------------------------------------"
    if "$DAG" @9.9.9.9 dns.quad9.net A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net +adflag +timeout=4 +noedns" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net +adflag +timeout=4 +noedns +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    elif "$DAG" @8.8.8.8 dns.google A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google +adflag +timeout=4 +noedns" "$DAG @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google +adflag +timeout=4 +noedns +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    else
        echo "  [SKIP] Outbound DoT not reachable"
    fi

    echo "--------------------------------------------------------"
    echo "8. Multiple Queries & Argument Flexibility"
    echo "--------------------------------------------------------"
    compare_query "Multiple Queries (A and TXT)" "www.example.com A +noedns example.com TXT +noedns"
    compare_query "Multiple Queries Short Mode" "www.example.com A +short example.com TXT +short"
    compare_query "Positional Order: Name Class Type" "www.example.com IN A +noedns"
    compare_query "Positional Order: Name Type Class" "www.example.com A IN +noedns"
    compare_query "Positional Order: Type Name Class" "A www.example.com IN +noedns"
    compare_query "Multiple Reverse (-x) and Forward" "-x 192.0.2.10 +noedns www.example.com A +noedns"
    compare_query "Per-query flag override (+noanswer on second)" "www.example.com A +noedns example.com TXT +noanswer +noedns"

    echo "--------------------------------------------------------"
    echo "9. IDN (Internationalized Domain Names)"
    echo "--------------------------------------------------------"
    compare_query "IDN Japanese domain (+idn)" "日本語ドメイン.jp +idn +noedns"
    compare_query "IDN Japanese domain with noidnout (+idn +noidnout)" "日本語ドメイン.jp +idn +noidnout +noedns"
    compare_query "IDN Japanese domain with explicit A (+idn +noidnout A)" "日本語ドメイン.jp A +idn +noidnout +noedns"
    compare_query "IDN ASCII domain enabled (+idn)" "www.example.com A +idn +noedns"
    compare_query "IDN disabled (+noidn)" "www.example.com A +noidn +noedns"
    compare_query "IDN in/out flags (+idnin +idnout)" "www.example.com A +idnin +idnout +noedns"
    compare_query "IDN disabled in/out (+noidnin +noidnout)" "www.example.com A +noidnin +noidnout +noedns"

    echo "--------------------------------------------------------"
    echo "10. Zone Nameserver Search (+nssearch)"
    echo "--------------------------------------------------------"
    compare_query "NS Search for zone (+nssearch)" "example.com +nssearch +timeout=2"
    compare_query "NS Search with TCP (+nssearch +tcp)" "example.com +nssearch +tcp +timeout=2"
fi

echo "========================================================"
echo "Comparison Summary: $MATCH / $TOTAL matched"
if [ "$MISMATCH" -eq 0 ]; then
    echo "🎉 ALL COMPARISON TESTS MATCHED EXACTLY!"
    exit 0
else
    echo "⚠️  $MISMATCH / $TOTAL queries had differences."
    exit 1
fi
