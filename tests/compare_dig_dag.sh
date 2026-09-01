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
        -e 's/;* COOKIE: .*/;; COOKIE: <COOKIE>/g' \
        -e 's/CLIENT: [0-9a-fA-F]+/CLIENT: <COOKIE>/g' \
        -e 's/SERVER: [0-9a-fA-F]{16,}/SERVER: <COOKIE>/g' \
        -e 's/(query|response)_time: !!timestamp .*/\1_time: <TIME>/g' \
        -e "s/'([^']+) [0-9]+ IN /'\1 <TTL> IN /g" \
        -e 's/[0-9]+[[:space:]]+IN[[:space:]]+/<TTL> IN /g' \
        -e 's/;; Query time: [0-9]+ (msec|usec)/;; Query time: <TIME>/g' \
        -e 's/ in [0-9]+ ms/ in <TIME> ms/g' \
        -e 's/;; WHEN: .*/;; WHEN: <DATE>/g' \
        -e 's/;; communications error to [0-9a-fA-F.:#]+: end of file/;; communications error to <SERVER>: end of file/g' \
        -e 's/;; communications error to [0-9a-fA-F.:#]+: connection refused/;; communications error to <SERVER>: connection refused/g' \
        -e 's/;; UDP setup with [0-9a-fA-F.:#()]+( for [^ ]+)? failed: .*/;; UDP setup with <SERVER> failed: <ERR>/g' \
        -e '/;; (no usable response received|connection failed|no servers could be reached)/d' \
        -e '/^;; === MULTI-SERVER COMPARISON SUMMARY ===/,$d' \
        -e 's/\x1b\[[0-9;]*m//g' \
        -e 's/[[:space:]]+/ /g' \
        -e 's/[[:space:]]*$//' | \
    awk '
    BEGIN { in_sec = 0; count = 0; }
    NF == 0 { next }
    /^;; (ANSWER|AUTHORITY|ADDITIONAL) SECTION:/ {
        if (in_sec && count > 0) {
            for (i = 1; i <= count; i++) {
                for (j = i + 1; j <= count; j++) {
                    if (lines[i] > lines[j]) { t = lines[i]; lines[i] = lines[j]; lines[j] = t; }
                }
                print lines[i];
            }
            count = 0;
        }
        in_sec = 1;
        print;
        next;
    }
    /^;;/ || /^; / {
        if (in_sec && count > 0) {
            for (i = 1; i <= count; i++) {
                for (j = i + 1; j <= count; j++) {
                    if (lines[i] > lines[j]) { t = lines[i]; lines[i] = lines[j]; lines[j] = t; }
                }
                print lines[i];
            }
            count = 0;
        }
        in_sec = 0;
        print;
        next;
    }
    {
        if (in_sec) {
            count++;
            lines[count] = $0;
        } else {
            print;
        }
    }
    END {
        if (in_sec && count > 0) {
            for (i = 1; i <= count; i++) {
                for (j = i + 1; j <= count; j++) {
                    if (lines[i] > lines[j]) { t = lines[i]; lines[i] = lines[j]; lines[j] = t; }
                }
                print lines[i];
            }
        }
    }'
}

TOTAL=0
MATCH=0
MISMATCH=0

compare_query() {
    NAME="$1"
    ARGS="$2"
    TOTAL=$((TOTAL + 1))

    # Run native dig
    eval "dig @127.0.0.1 -p $PORT $ARGS" > dig.raw 2>&1 || true
    # Run KariDNS dag
    eval "$DAG @127.0.0.1 -p $PORT +nohexdump $ARGS" > dag.raw 2>&1 || true

    normalize_output < dig.raw > dig.out
    normalize_output < dag.raw > dag.out

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

    eval "$DIG_CMD" > dig.raw 2>&1 || true
    eval "$DAG_CMD" > dag.raw 2>&1 || true

    normalize_output < dig.raw > dig.out
    normalize_output < dag.raw > dag.out

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
    compare_query "Explicit query name (-q)" "-q www.example.com A +noedns"
    compare_query "Explicit query type (-t)" "example.com -t MX +noedns"
    compare_query "Standard AAAA query" "www.example.com AAAA +noedns"
    compare_query "SOA query" "example.com SOA +noedns"
    compare_query "NS query" "example.com NS +noedns"
    compare_query "MX query" "example.com MX +noedns"
    compare_query "TXT query" "example.com TXT +noedns"
    compare_query "SRV query" "_sip._tcp.example.com SRV +noedns"
    compare_query "NAPTR query" "_ldap._tcp.example.com NAPTR +noedns"
    compare_query "HTTPS query" "www.example.com HTTPS +noedns"
    compare_query "SVCB query" "_8443._tcp.svc.example.com SVCB +noedns"
    compare_query "SVCB key7 query" "_dns.resolver.example.com SVCB +noedns"
    compare_query "TLSA query" "_443._tcp.www.example.com TLSA +noedns"
    compare_query "SSHFP query" "ns1.example.com SSHFP +noedns"
    compare_query "CAA query" "example.com CAA +noedns"
    compare_query "LOC query" "office.example.com LOC +noedns"
    compare_query "CNAME resolution" "ftp.example.com A +noedns"
    compare_query "DNAME resolution" "sub.legacy.example.com A +noedns"
    compare_query "URI query" "_https._tcp.example.com URI +noedns"
    compare_query "SPF query" "example.com SPF +noedns"
    compare_query "Wildcard query" "foo.wild.example.com A +noedns"
    compare_query "Reverse IPv4 lookup (-x)" "-x 192.0.2.10 +noedns"
    compare_query "Reverse IPv6 lookup (-x)" "-x 2001:db8::1 +noedns"
    compare_query "NXDOMAIN response" "nonexistent.example.com A +noedns"
    compare_query "NODATA response" "www.example.com TXT +noedns"
    compare_query "ANY query" "example.com ANY +noedns"

    echo "--------------------------------------------------------"
    echo "2. Format & Layout Options"
    echo "--------------------------------------------------------"
    compare_query "Short mode (+short)" "www.example.com A +short"
    compare_query "No class (+noclass)" "www.example.com A +noclass +noedns"
    compare_query "TTL units (+ttlunits)" "www.example.com A +ttlunits +noedns"
    compare_query "Unknown format (+unknownformat)" "www.example.com A +noall +answer +unknownformat +noedns"
    compare_query "Omit TTL ID (+nottlid)" "www.example.com A +nottlid +noedns"
    compare_query "Multiline mode (+multiline)" "example.com SOA +multiline +noedns"
    compare_query "Expand AAAA (+expandaaaa)" "www.example.com AAAA +expandaaaa +noedns"
    compare_query "No comments (+nocomments)" "www.example.com A +nocomments +noedns"
    compare_query "No command header (+nocmd)" "www.example.com A +nocmd +noedns"
    compare_query "No answer section (+noanswer)" "www.example.com A +noanswer +noedns"
    compare_query "No authority section (+noauthority)" "nonexistent.example.com A +noauthority +noedns"
    compare_query "No additional section (+noadditional)" "example.com NS +noadditional +noedns"
    compare_query "No question section (+noquestion)" "www.example.com A +noquestion +noedns"
    compare_query "Combined +noall +answer" "www.example.com A +noall +answer"
    compare_query "No stats section (+nostats)" "www.example.com A +nostats +noedns"
    compare_query "Query header dump (+qr)" "www.example.com A +qr +noedns"
    compare_query "Identification (+short +identify)" "www.example.com A +short +identify +noedns"
    compare_query "YAML formatted output (+yaml)" "www.example.com A +yaml +noedns"

    echo "--------------------------------------------------------"
    echo "3. DNSSEC & Crypto Formatting"
    echo "--------------------------------------------------------"
    compare_query "DNSSEC OK (+dnssec)" "example.com DNSKEY +dnssec +nocookie"
    compare_query "DNSSEC DS query" "example.com DS +dnssec +nocookie"
    compare_query "RR Comments on DNSKEY (+rrcomments)" "example.com DNSKEY +rrcomments +noedns"
    compare_query "Omit Crypto on DNSKEY (+nocrypto)" "example.com DNSKEY +nocrypto +noedns"
    compare_query "Split width (+split=16)" "example.com DNSKEY +split=16 +noedns"

    echo "--------------------------------------------------------"
    echo "4. EDNS0 & Transport Options"
    echo "--------------------------------------------------------"
    compare_query "EDNS0 query (+edns +nocookie)" "www.example.com A +edns +nocookie"
    compare_query "EDNS Buffer Size (+bufsize=4096)" "www.example.com A +bufsize=4096 +nocookie"
    compare_query "EDNS NSID Option (+nsid)" "www.example.com A +nsid +nocookie"
    compare_query "EDNS Subnet (+subnet)" "www.example.com A +subnet=192.0.2.0/24 +nocookie"
    compare_query "EDNS Padding (+padding)" "www.example.com A +padding=64 +nocookie"
    compare_query "EDNS Cookie (+cookie)" "www.example.com A +cookie=0102030405060708"
    compare_query "EDNS Keepalive (+keepalive)" "www.example.com A +keepalive +nocookie"
    compare_query "EDNS Expire (+expire)" "example.com SOA +expire +nocookie"
    compare_query "EDNS CO flag (+coflag)" "www.example.com A +coflag +nocookie"
    compare_query "EDNS Flags raw Z-bits (+ednsflags)" "www.example.com A +ednsflags=0x0040 +nocookie"
    compare_query "Generic EDNS option (+ednsopt)" "www.example.com A +ednsopt=65001:01020304 +nocookie"
    compare_query "Generic EDNS option cleared (+ednsopt +noednsopt)" "www.example.com A +ednsopt=65001:01020304 +noednsopt +nocookie"
    compare_query "EDNS Subnet + NSID + Padding" "www.example.com A +subnet=192.0.2.0/24 +nsid +padding=64 +nocookie"
    compare_query "Standard TCP Query (+tcp)" "www.example.com A +tcp +noedns"
    compare_query "Keep TCP open (+tcp +keepopen)" "www.example.com A +tcp +keepopen +noedns"
    compare_query "Flags override (+raflag +tcflag +zflag)" "www.example.com A +raflag +tcflag +zflag +noedns"
    compare_query "Header flags (+adflag +cdflag +aaflag)" "www.example.com A +adflag +cdflag +aaflag +noedns"
    compare_query "No RD flag (+nordflag)" "www.example.com A +nordflag +noedns"
    compare_query "No AD flag (+noadflag)" "www.example.com A +noadflag +noedns"
    compare_query "Explicit CD flag only (+cdflag)" "www.example.com A +cdflag +noedns"
    compare_query "Explicit AA flag query (+aaflag)" "www.example.com A +aaflag +noedns"
    compare_query "Opcode override (+opcode=NOTIFY)" "www.example.com A +opcode=NOTIFY +noadflag +noedns"
    compare_query "QID override (+qid=4660)" "www.example.com A +qid=4660 +noedns"
    compare_query "Ignore TC flag (+ignore)" "www.example.com A +ignore +noedns"
    compare_query "Best effort parsing (+besteffort)" "www.example.com A +besteffort +noedns"
    compare_query "DNS64 prefix check (+dns64prefix)" "ipv4only.arpa AAAA +dns64prefix +cookie"
    compare_query "Search domain option (+domain= +search)" "www +domain=example.com +search +noedns"
    compare_query "Search ndots expansion (+domain= +ndots=2 +search)" "www.example +domain=com +ndots=2 +search +noedns"
    compare_query "Search ndots not expanded (+domain= +ndots=1 +search)" "www.example +domain=com +ndots=1 +search +noedns"
    compare_query "Showsearch diagnostic (+showsearch)" "www +domain=example.com +showsearch +noedns"

    echo "--------------------------------------------------------"
    echo "5. Zone Transfers (AXFR)"
    echo "--------------------------------------------------------"
    compare_query "Standard AXFR Transfer" "example.com AXFR"
    compare_query "AXFR Short Mode (+short)" "example.com AXFR +short"
    compare_query "AXFR No Comments (+nocomments)" "example.com AXFR +nocomments"
    compare_query "AXFR Single SOA (+onesoa)" "example.com AXFR +onesoa"

    echo "--------------------------------------------------------"
    echo "6. Default Query (No domain/type specified)"
    echo "--------------------------------------------------------"
    compare_query "Default Query against @server (defaults to . NS)" "+noedns"

    echo "--------------------------------------------------------"
    echo "7. TLS / DoT Verification (RFC 7858)"
    echo "--------------------------------------------------------"
    if "$DAG" @8.8.8.8 dns.google A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google +adflag +timeout=4 +noedns" "$DAG @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google +adflag +timeout=4 +noedns +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    elif "$DAG" @9.9.9.9 dns.quad9.net A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net +adflag +timeout=4 +noedns" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net +adflag +timeout=4 +noedns +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    else
        echo "  [SKIP] Outbound DoT not reachable"
    fi

    if dig @dns.google example.com A +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "FQDN Server Name (@dns.google)" "dig @dns.google example.com A +timeout=4 +noedns" "$DAG @dns.google example.com A +timeout=4 +noedns +nohexdump"
    fi

    echo "--------------------------------------------------------"
    echo "8. Multiple Queries & Argument Flexibility"
    echo "--------------------------------------------------------"
    compare_query "Multiple Queries (A and TXT)" "www.example.com A +noedns example.com TXT +noedns"
    compare_query "Multiple Queries Short Mode" "www.example.com A +short example.com TXT +short"
    compare_query "Positional Order: Name Class Type" "www.example.com IN A +noedns"
    compare_query "Positional Order: Name Type Class" "www.example.com A IN +noedns"
    compare_query "Positional Order: Type Name Class" "A www.example.com IN +noedns"
    compare_query "Multiple Queries with different classes" "www.example.com IN A +noedns example.com IN MX +noedns"
    compare_query "Multiple Queries with mixed options" "www.example.com A +noedns +nocmd example.com SOA +noedns +noquestion"
    compare_query "Three positional queries" "ns1.example.com A +noedns ns2.example.com AAAA +noedns mail.example.com MX +noedns"
    compare_query "Multiple Reverse (-x) and Forward" "-x 192.0.2.10 +noedns www.example.com A +noedns"
    compare_query "Per-query flag override (+noanswer on second)" "www.example.com A +noedns example.com TXT +noanswer +noedns"
    cat << 'EOF' > tsig_key.conf
key "testkey" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF
    compare_query "TSIG key inline (-y)" "www.example.com A -y hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +noedns"
    compare_query "TSIG keyfile flag (-k)" "www.example.com A -k tsig_key.conf +noedns"
    compare_query "TSIG signing time override (+fuzztime)" "www.example.com A -y hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +fuzztime=1646972129 +noedns"

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

    echo "--------------------------------------------------------"
    echo "11. Comprehensive YAML Output Comparison (+yaml)"
    echo "--------------------------------------------------------"
    compare_query "YAML: Standard A query" "www.example.com A +yaml +noedns"
    compare_query "YAML: TXT with special characters & quotes" "example.com TXT +yaml +noedns"
    compare_query "YAML: Authority & Additional sections (NS)" "example.com NS +yaml +noedns"
    compare_query "YAML: NXDOMAIN response with SOA" "nonexistent.example.com A +yaml +noedns"
    compare_query "YAML: EDNS0 Opts (Cookie, Subnet, NSID)" "www.example.com A +yaml +cookie +subnet=192.0.2.0/24 +nsid"
    compare_query "YAML: Multiple Queries" "www.example.com A example.com TXT +yaml +noedns"
    compare_query "YAML: DNS64 prefix" "ipv4only.arpa AAAA +dns64prefix +yaml +noedns"
    compare_query "YAML: AAAA with expandaaaa (+yaml +expandaaaa)" "www.example.com AAAA +yaml +expandaaaa +noedns"
    compare_query "YAML: DNSKEY with nocrypto (+yaml +nocrypto)" "example.com DNSKEY +yaml +nocrypto +noedns"
    compare_query "YAML: DS with nocrypto (+yaml +nocrypto)" "example.com DS +yaml +nocrypto +noedns"
    compare_query "YAML: RRSIG structured output (+yaml)" "example.com RRSIG +yaml +noedns"
    compare_query "YAML: SOA with multiline (+yaml +multiline)" "example.com SOA +yaml +multiline +noedns"
    compare_query "YAML: SOA with multi alias (+yaml +multi)" "example.com SOA +yaml +multi +noedns"
    compare_query "YAML: LOC record (+yaml)" "office.example.com LOC +yaml +noedns"
    compare_query "YAML: LOC record (where-is-the-iss.dedyn.io)" "where-is-the-iss.dedyn.io LOC +yaml +timeout=3 +noedns"
    compare_query "YAML: Trace query (+trace +yaml)" "example.com +trace +yaml +timeout=3"

    echo "--------------------------------------------------------"
    echo "12. DNS64 Prefix Discovery (+dns64prefix)"
    echo "--------------------------------------------------------"
    compare_query "DNS64 prefix: Standard mode" "ipv4only.arpa AAAA +dns64prefix +noedns"
    compare_query "DNS64 prefix: Short mode (+short)" "ipv4only.arpa AAAA +short +dns64prefix +noedns"
    compare_query "DNS64 prefix: With regular query" "www.example.com A +dns64prefix +noedns"

    echo "--------------------------------------------------------"
    echo "13. Class Argument Flexibility (-c)"
    echo "--------------------------------------------------------"
    compare_query "Class argument: Valid class (-c IN)" "www.example.com A -c IN +noedns"
    compare_query "Class argument: Fallback on unknown class (-c INVALIDCLASS)" "www.example.com A -c INVALIDCLASS +noedns"

    echo "--------------------------------------------------------"
    echo "14. TCP Keepopen & Session Transport (+keepopen)"
    echo "--------------------------------------------------------"
    compare_query "TCP Keepopen: Multiple queries on single TCP connection" "www.example.com A +tcp +keepopen example.com TXT +tcp +keepopen +noedns"

    echo "--------------------------------------------------------"
    echo "15. Multiline Formatting (+multiline)"
    echo "--------------------------------------------------------"
    compare_query "Multiline: SOA record formatting" "example.com SOA +multiline +noedns"
    compare_query "Multiline: DNSKEY record formatting" "example.com DNSKEY +multiline +noedns"
    compare_query "Multiline: DS record single-line formatting" "example.com DS +multiline +noedns"

    echo "--------------------------------------------------------"
    echo "16. Source Address Binding (-b)"
    echo "--------------------------------------------------------"
    compare_query "Source address binding: IPv4 localhost" "www.example.com A -b 127.0.0.1 +noedns"

    echo "--------------------------------------------------------"
    echo "17. Error Handling & Negative Test Cases"
    echo "--------------------------------------------------------"
    compare_query "Negative: Unassignable bind address (-b)" "www.example.com A -b 192.0.2.1 +noedns +tries=1 +timeout=1"
    compare_query "Negative: Unreachable port" "www.example.com A -p 19999 +noedns +tries=1 +timeout=1"
    compare_query "Negative: Unknown record type" "www.example.com UNKNOWNTYPE +noedns"
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
