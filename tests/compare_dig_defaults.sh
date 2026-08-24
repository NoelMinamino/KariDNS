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
    echo "1. Record Types & Resolution"
    echo "--------------------------------------------------------"
    compare_query "Standard A query" "www.example.com A"
    compare_query "Explicit query name (-q)" "-q www.example.com A"
    compare_query "Explicit query type (-t)" "example.com -t MX"
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
    compare_query "DNAME resolution" "sub.legacy.example.com A"
    compare_query "URI query" "_https._tcp.example.com URI"
    compare_query "SPF query" "example.com SPF"
    compare_query "Wildcard query" "foo.wild.example.com A"
    compare_query "Reverse IPv4 lookup (-x)" "-x 192.0.2.10"
    compare_query "Reverse IPv6 lookup (-x)" "-x 2001:db8::1"
    compare_query "NXDOMAIN response" "nonexistent.example.com A"
    compare_query "NODATA response" "mail.example.com TXT"
    compare_query "ANY query" "example.com ANY"

    echo "--------------------------------------------------------"
    echo "2. Format & Layout Options"
    echo "--------------------------------------------------------"
    compare_query "Short mode (+short)" "www.example.com A +short"
    compare_query "No class (+noclass)" "www.example.com A +noclass"
    compare_query "TTL units (+ttlunits)" "www.example.com A +ttlunits"
    compare_query "Unknown format (+unknownformat)" "www.example.com A +noall +answer +unknownformat"
    compare_query "Omit TTL ID (+nottlid)" "www.example.com A +nottlid"
    compare_query "Multiline mode (+multiline)" "example.com SOA +multiline"
    compare_query "Expand AAAA (+expandaaaa)" "www.example.com AAAA +expandaaaa"
    compare_query "No comments (+nocomments)" "www.example.com A +nocomments"
    compare_query "No command header (+nocmd)" "www.example.com A +nocmd"
    compare_query "No answer section (+noanswer)" "www.example.com A +noanswer"
    compare_query "No authority section (+noauthority)" "nonexistent.example.com A +noauthority"
    compare_query "No additional section (+noadditional)" "example.com NS +noadditional"
    compare_query "No question section (+noquestion)" "www.example.com A +noquestion"
    compare_query "Combined +noall +answer" "www.example.com A +noall +answer"
    compare_query "No stats section (+nostats)" "www.example.com A +nostats"
    compare_query "Query header dump (+qr)" "www.example.com A +qr"
    compare_query "Identification (+short +identify)" "www.example.com A +short +identify"
    compare_query "YAML formatted output (+yaml)" "www.example.com A +yaml"

    echo "--------------------------------------------------------"
    echo "3. DNSSEC & Crypto Formatting"
    echo "--------------------------------------------------------"
    compare_query "DNSSEC OK (+dnssec)" "example.com DNSKEY +dnssec"
    compare_query "DNSSEC DS query" "example.com DS +dnssec"
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
    compare_query "Standard EDNS Cookie (+cookie)" "www.example.com A +cookie"
    compare_query "Explicit EDNS Cookie (+cookie=hex)" "www.example.com A +cookie=0102030405060708"
    compare_query "EDNS Keepalive (+keepalive)" "www.example.com A +keepalive"
    compare_query "EDNS Expire (+expire)" "example.com SOA +expire"
    compare_query "EDNS CO flag (+coflag)" "www.example.com A +coflag"
    compare_query "EDNS Flags raw Z-bits (+ednsflags)" "www.example.com A +ednsflags=0x0040"
    compare_query "Generic EDNS option (+ednsopt)" "www.example.com A +ednsopt=65001:01020304"
    compare_query "Generic EDNS option cleared (+ednsopt +noednsopt)" "www.example.com A +ednsopt=65001:01020304 +noednsopt"
    compare_query "EDNS Subnet + NSID + Padding" "www.example.com A +subnet=192.0.2.0/24 +nsid +padding=64"
    compare_query "Standard TCP Query (+tcp)" "www.example.com A +tcp"
    compare_query "TCP Query with explicit timeout (+tcp +timeout=2)" "www.example.com A +tcp +timeout=2"
    compare_query "TCP Query with +time alias (+tcp +time=2)" "www.example.com A +tcp +time=2"
    compare_query "TCP Query with tries override (+tcp +timeout=2 +tries=1)" "www.example.com A +tcp +timeout=2 +tries=1"
    compare_query "TCP Query with retry override (+tcp +timeout=2 +retry=1)" "www.example.com A +tcp +timeout=2 +retry=1"
    compare_query "Combined TCP and Cookie (+tcp +cookie)" "www.example.com A +tcp +cookie +timeout=2"
    compare_query "Keep TCP open (+tcp +keepopen)" "www.example.com A +tcp +keepopen"
    compare_query "Flags override (+raflag +tcflag +zflag)" "www.example.com A +raflag +tcflag +zflag"
    compare_query "Header flags (+adflag +cdflag +aaflag)" "www.example.com A +adflag +cdflag +aaflag"
    compare_query "No RD flag (+nordflag)" "www.example.com A +nordflag"
    compare_query "No AD flag (+noadflag)" "www.example.com A +noadflag"
    compare_query "Explicit CD flag only (+cdflag)" "www.example.com A +cdflag"
    compare_query "Explicit AA flag query (+aaflag)" "www.example.com A +aaflag"
    compare_query "Opcode override (+opcode=NOTIFY)" "www.example.com A +opcode=NOTIFY +noadflag"
    compare_query "QID override (+qid=4660)" "www.example.com A +qid=4660"
    compare_query "Ignore TC flag (+ignore)" "www.example.com A +ignore"
    compare_query "Best effort parsing (+besteffort)" "www.example.com A +besteffort"
    compare_query "DNS64 prefix check (+dns64prefix)" "ipv4only.arpa AAAA +dns64prefix"
    compare_query "Search domain option (+domain= +search)" "www +domain=example.com +search"
    compare_query "Search ndots expansion (+domain= +ndots=2 +search)" "www.example +domain=com +ndots=2 +search"
    compare_query "Search ndots not expanded (+domain= +ndots=1 +search)" "www.example +domain=com +ndots=1 +search"
    compare_query "Showsearch diagnostic (+showsearch)" "www +domain=example.com +showsearch"

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
    compare_query "Default Query against @server (defaults to . NS)" ""

    echo "--------------------------------------------------------"
    echo "7. TLS / DoT Verification (RFC 7858)"
    echo "--------------------------------------------------------"
    if "$DAG" @8.8.8.8 dns.google A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google +timeout=4" "$DAG @8.8.8.8 dns.google A +tls +tls-ca +tls-hostname=dns.google $DIG_DEFAULTS +timeout=4 +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
    elif "$DAG" @9.9.9.9 dns.quad9.net A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
        compare_raw "Live DoT with default CA & SNI verification" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net +timeout=4" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=dns.quad9.net $DIG_DEFAULTS +timeout=4 +nohexdump"
        compare_raw "Live DoT with mismatched hostname rejected" "dig @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "$DAG @9.9.9.9 dns.quad9.net A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4 +nohexdump"
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
    compare_query "Multiple Queries with different classes" "www.example.com IN A example.com IN MX"
    compare_query "Multiple Queries with mixed options" "www.example.com A +nocmd example.com SOA +noquestion"
    compare_query "Three positional queries" "ns1.example.com A ns2.example.com AAAA mail.example.com MX"
    compare_query "Multiple Reverse (-x) and Forward" "-x 192.0.2.10 www.example.com A"
    compare_query "Per-query flag override (+noanswer on second)" "www.example.com A example.com TXT +noanswer"
    cat << 'EOF' > tsig_key.conf
key "testkey" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF
    compare_query "TSIG key inline (-y)" "www.example.com A -y hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"
    compare_query "TSIG keyfile flag (-k)" "www.example.com A -k tsig_key.conf"
    compare_query "TSIG signing time override (+fuzztime)" "www.example.com A -y hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +fuzztime=1646972129"

    echo "--------------------------------------------------------"
    echo "9. IDN (Internationalized Domain Names)"
    echo "--------------------------------------------------------"
    compare_query "IDN Japanese domain (+idn)" "日本語ドメイン.jp +idn"
    compare_query "IDN Japanese domain with noidnout (+idn +noidnout)" "日本語ドメイン.jp +idn +noidnout"
    compare_query "IDN Japanese domain with explicit A (+idn +noidnout A)" "日本語ドメイン.jp A +idn +noidnout"
    compare_query "IDN ASCII domain enabled (+idn)" "www.example.com A +idn"
    compare_query "IDN disabled (+noidn)" "www.example.com A +noidn"
    compare_query "IDN in/out flags (+idnin +idnout)" "www.example.com A +idnin +idnout"
    compare_query "IDN disabled in/out (+noidnin +noidnout)" "www.example.com A +noidnin +noidnout"

    echo "--------------------------------------------------------"
    echo "10. Zone Nameserver Search (+nssearch)"
    echo "--------------------------------------------------------"
    compare_query "NS Search for zone (+nssearch)" "example.com +nssearch +timeout=2"
    compare_query "NS Search with TCP (+nssearch +tcp)" "example.com +nssearch +tcp +timeout=2"
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
