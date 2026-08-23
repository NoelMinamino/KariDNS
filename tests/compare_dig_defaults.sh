#!/bin/sh
# ==============================================================================
# tests/compare_dig_defaults.sh
#
# Compares BIND 9 dig (running with its native default options: EDNS0, bufsize 1232,
# Cookie, AD flag) against KariDNS dag (passing those same options).
#
# Usage:
#   sh tests/compare_dig_defaults.sh             (Runs full comparison suite)
#   sh tests/compare_dig_defaults.sh <query...>  (Runs custom single query comparison)
# ==============================================================================

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
PORT=53557
TEST_DIR=".compare_dig_defaults_tmp_$$"

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

# Output normalizer to mask non-deterministic fields, tool banner, and dag-specific comparison summary
normalize_output() {
    sed -E \
        -e '/^; <<>>/d' \
        -e '/^;; global options: \+cmd/d' \
        -e '/^; \([0-9]+ servers? found\)/d' \
        -e 's/id: [0-9]+/id: <ID>/g' \
        -e 's/; COOKIE: [0-9a-fA-F]+/;; COOKIE: <COOKIE>/g' \
        -e 's/[0-9]+[[:space:]]+IN[[:space:]]+/<TTL> IN /g' \
        -e 's/;; Query time: [0-9]+ (msec|usec)/;; Query time: <TIME>/g' \
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

# Default options that match BIND 9 dig's native defaults
DIG_DEFAULTS="+edns=0 +bufsize=1232 +cookie +adflag"

compare_query() {
    NAME="$1"
    ARGS="$2"
    TOTAL=$((TOTAL + 1))

    # dig runs with its native defaults + any ARGS
    dig @127.0.0.1 -p $PORT $ARGS 2>&1 | normalize_output > dig.out || true
    # dag runs with dig-equivalent defaults + nohexdump in global options + any ARGS
    "$DAG" @127.0.0.1 -p $PORT $DIG_DEFAULTS +nohexdump $ARGS 2>&1 | normalize_output > dag.out || true

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
echo "Comparing BIND 9 dig (native defaults) vs KariDNS dag"
echo "Target: KariDNS Authoritative Server (127.0.0.1:$PORT)"
echo "Default Flags applied to dag: $DIG_DEFAULTS"
echo "========================================================"

if [ $# -gt 0 ]; then
    echo "Running custom query comparison: $@"
    compare_query "Custom Query" "$*"
else
    echo "--------------------------------------------------------"
    echo "1. Record Types & Resolution (with EDNS0 + Cookie defaults)"
    echo "--------------------------------------------------------"
    compare_query "Standard A query" "www.example.com A"
    compare_query "Standard AAAA query" "www.example.com AAAA"
    compare_query "SOA query" "example.com SOA"
    compare_query "NS query" "example.com NS"
    compare_query "MX query" "example.com MX"
    compare_query "TXT query" "example.com TXT"
    compare_query "SRV query" "_sip._tcp.example.com SRV"
    compare_query "NAPTR query" "_ldap._tcp.example.com NAPTR"
    compare_query "HTTPS query" "www.example.com HTTPS"
    compare_query "SVCB query" "_8443._tcp.svc.example.com SVCB"
    compare_query "TLSA query" "_443._tcp.www.example.com TLSA"
    compare_query "SSHFP query" "ns1.example.com SSHFP"
    compare_query "CAA query" "example.com CAA"
    compare_query "LOC query" "office.example.com LOC"
    compare_query "CNAME resolution" "ftp.example.com A"
    compare_query "Wildcard query" "foo.wild.example.com A"
    compare_query "NXDOMAIN response" "nonexistent.example.com A"
    compare_query "NODATA response" "mail.example.com TXT"

    echo "--------------------------------------------------------"
    echo "2. Format & Layout Options"
    echo "--------------------------------------------------------"
    compare_query "Short mode (+short)" "www.example.com A +short"
    compare_query "No class (+noclass)" "www.example.com A +noclass"
    compare_query "TTL units (+ttlunits)" "www.example.com A +ttlunits"
    compare_query "Unknown format (+unknownformat)" "www.example.com A +noall +answer +unknownformat"
    compare_query "Omit TTL ID (+nottlid)" "www.example.com A +nottlid"
    compare_query "Multiline mode (+multiline)" "example.com SOA +multiline"
    compare_query "No comments (+nocomments)" "www.example.com A +nocomments"
    compare_query "No command header (+nocmd)" "www.example.com A +nocmd"
    compare_query "No answer section (+noanswer)" "www.example.com A +noanswer"
    compare_query "No question section (+noquestion)" "www.example.com A +noquestion"
    compare_query "Combined +noall +answer" "www.example.com A +noall +answer"
    compare_query "No stats section (+nostats)" "www.example.com A +nostats"

    echo "--------------------------------------------------------"
    echo "3. DNSSEC & Crypto Formatting"
    echo "--------------------------------------------------------"
    compare_query "DNSSEC OK (+dnssec)" "example.com DNSKEY +dnssec"
    compare_query "RR Comments on DNSKEY (+rrcomments)" "example.com DNSKEY +rrcomments"
    compare_query "Omit Crypto on DNSKEY (+nocrypto)" "example.com DNSKEY +nocrypto"
    compare_query "Split width (+split=16)" "example.com DNSKEY +split=16"

    echo "--------------------------------------------------------"
    echo "4. EDNS0 & Transport Overrides"
    echo "--------------------------------------------------------"
    compare_query "EDNS Buffer Size override (+bufsize=4096)" "www.example.com A +bufsize=4096"
    compare_query "EDNS NSID Option (+nsid)" "www.example.com A +nsid"
    compare_query "EDNS Subnet (+subnet)" "www.example.com A +subnet=192.0.2.0/24"
    compare_query "EDNS Padding (+padding)" "www.example.com A +padding=64"
    compare_query "Explicit EDNS Cookie (+cookie)" "www.example.com A +cookie=0102030405060708"
    compare_query "Standard TCP Query (+tcp)" "www.example.com A +tcp"

    echo "--------------------------------------------------------"
    echo "5. Zone Transfers (AXFR)"
    echo "--------------------------------------------------------"
    compare_query "Standard AXFR Transfer" "example.com AXFR"
    compare_query "AXFR Short Mode (+short)" "example.com AXFR +short"
    compare_query "AXFR No Comments (+nocomments)" "example.com AXFR +nocomments"

    echo "--------------------------------------------------------"
    echo "6. Default Query (No domain/type specified)"
    echo "--------------------------------------------------------"
    compare_query "Default Query against @server (defaults to . NS)" ""

    echo "--------------------------------------------------------"
    echo "7. TLS / DoT Verification (RFC 7858)"
    echo "--------------------------------------------------------"
    if "$DAG" @9.9.9.9 dns.quad9.net A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net +timeout=4" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net $DIG_DEFAULTS +timeout=4 +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    elif "$DAG" @8.8.8.8 dns.google A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google +timeout=4" "$DAG @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google $DIG_DEFAULTS +timeout=4 +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    else
        echo "  [SKIP] Outbound DoT not reachable"
    fi

    echo "--------------------------------------------------------"
    echo "8. Multiple Queries & Argument Flexibility"
    echo "--------------------------------------------------------"
    compare_query "Multiple Queries (A and TXT)" "www.example.com A example.com TXT"
    compare_query "Multiple Queries Short Mode" "www.example.com A +short example.com TXT +short"
    compare_query "Positional Order: Name Class Type" "www.example.com IN A"
    compare_query "Positional Order: Name Type Class" "www.example.com A IN"
    compare_query "Positional Order: Type Name Class" "A www.example.com IN"
    compare_query "Multiple Reverse (-x) and Forward" "-x 192.0.2.10 www.example.com A"
    compare_query "Per-query flag override (+noanswer on second)" "www.example.com A example.com TXT +noanswer"
fi

echo "========================================================"
echo "Comparison Summary: $MATCH / $TOTAL matched"
if [ "$MISMATCH" -eq 0 ]; then
    echo "🎉 ALL COMPARISON TESTS MATCHED EXACTLY (DIG DEFAULTS MODE)!"
    exit 0
else
    echo "⚠️  $MISMATCH / $TOTAL queries had differences."
    exit 1
fi
