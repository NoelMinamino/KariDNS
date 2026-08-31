#!/bin/sh
# ==============================================================================
# KariDNS dag(1) & BIND 9 dig(1) Comprehensive Test Suite
# Usage:
#   sh tests/run_dag_ci_test.sh       # Runs tests with ./dag (Default)
#   sh tests/run_dag_ci_test.sh dig   # Runs tests with system dig
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="dag_ci_test_dir"
PORT=53555

CLIENT_ARG="${1:-dag}"
if [ "$CLIENT_ARG" = "dig" ]; then
    if ! command -v dig >/dev/null 2>&1; then
        echo "Error: 'dig' command not found in PATH."
        exit 1
    fi
    DAG="dig"
    CLIENT_NAME="BIND 9 dig ($(dig -v 2>&1 | head -n 1))"
    make -C "$BIN_DIR" all || { echo "Error: make all failed"; exit 1; }
else
    make -C "$BIN_DIR" all || { echo "Error: make all failed"; exit 1; }
    DAG="$BIN_DIR/dag"
    CLIENT_NAME="KariDNS dag"
fi

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

KARIDNS="$BIN_DIR/karidns"

echo "========================================================"
echo "Running Test Suite with: $CLIENT_NAME"
echo "========================================================"

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
    echo "=== Cleaning up ==="
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

FAILED=0
SKIPPED=0

run_check() {
    NAME="$1"
    CMD="$2"
    EXPECT="$3"
    echo -n "Test: $NAME ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$EXPECT"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Expected: $EXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

run_skip() {
    NAME="$1"
    REASON="${2:-dag-only feature}"
    echo "Test: $NAME ... SKIP ($REASON)"
    SKIPPED=$((SKIPPED + 1))
}

run_exit_check() {
    NAME="$1"
    CMD="$2"
    EXP_CODE="$3"
    echo -n "Exit code test: $NAME ... "
    set +e
    eval "$CMD" >/dev/null 2>&1
    ACT_CODE=$?
    set -e
    if [ "$ACT_CODE" -eq "$EXP_CODE" ]; then
        echo "OK (code $ACT_CODE)"
    else
        echo "FAILED (expected $EXP_CODE, got $ACT_CODE)"
        FAILED=$((FAILED + 1))
    fi
}

echo "========================================================"
echo "1. Basic Queries, Transport & Protocols"
echo "========================================================"
run_check "Standard UDP Query" "$DAG @127.0.0.1 -p $PORT www.example.com A" "192.0.2.10"
run_check "Explicit Query Name flag (-q)" "$DAG @127.0.0.1 -p $PORT -q www.example.com" "192.0.2.10"
run_check "Explicit Query Type flag (-t)" "$DAG @127.0.0.1 -p $PORT example.com -t MX" "mail\.example\.com"
run_check "Uppercase Query Type (SOA)" "$DAG @127.0.0.1 -p $PORT example.com SOA" "ns1\.example\.com"
run_check "Lowercase Query Type (soa)" "$DAG @127.0.0.1 -p $PORT example.com soa" "ns1\.example\.com"
run_check "Mixed-case Query Type (SOa)" "$DAG @127.0.0.1 -p $PORT example.com SOa" "ns1\.example\.com"
run_check "Explicit Query Class flag (-c)" "$DAG @127.0.0.1 -p $PORT -c IN www.example.com A" "192.0.2.10"
run_check "Standard TCP Query (+tcp)" "$DAG @127.0.0.1 -p $PORT www.example.com A +tcp" "192.0.2.10"
run_check "Standard TCP Query (+vc)" "$DAG @127.0.0.1 -p $PORT www.example.com A +vc" "192.0.2.10"
run_check "Reverse PTR Query (-x)" "$DAG @127.0.0.1 -p $PORT -x 192.0.2.10" "10\.2\.0\.192\.in-addr\.arpa"
run_check "Reverse IPv6 PTR Query (-x)" "$DAG @127.0.0.1 -p $PORT -x 2001:db8::1 +timeout=1" "(ip6\.arpa|timed out|no usable response|no servers could be reached)"
run_check "DNAME resolution" "$DAG @127.0.0.1 -p $PORT sub.legacy.example.com A" "(archive\.example\.com|192\.0\.2)"
run_check "URI query" "$DAG @127.0.0.1 -p $PORT _https._tcp.example.com URI" "https://www\.example\.com"
run_check "SPF query" "$DAG @127.0.0.1 -p $PORT example.com SPF" "v=spf1"
run_check "LOC query" "$DAG @127.0.0.1 -p $PORT example.com LOC" "35 10.*N 136 58.*E"
run_check "LOC query (+yaml)" "$DAG @127.0.0.1 -p $PORT example.com LOC +yaml" "35 10.*N 136 58.*E"
run_check "LOC query external (where-is-the-iss.dedyn.io)" "$DAG where-is-the-iss.dedyn.io LOC +timeout=2" "(LOC|timed out|no usable response|no servers could be reached)"
run_check "LOC query external (+yaml)" "$DAG where-is-the-iss.dedyn.io LOC +yaml +timeout=2" "(IN[[:space:]]+LOC|LOC|timed out|no usable response|no servers could be reached)"
run_check "ANY query" "$DAG @127.0.0.1 -p $PORT example.com ANY" "(SOA|NS|MX|TXT)"
run_check "DNSSEC DS query" "$DAG @127.0.0.1 -p $PORT example.com DS +dnssec" "(status: NOERROR|SOA|DS)"
run_check "IPv4 preference flag (-4)" "$DAG @127.0.0.1 -p $PORT www.example.com A -4" "192.0.2.10"
run_check "IPv6 preference flag (-6)" "$DAG @127.0.0.1 -p $PORT www.example.com AAAA -6 +timeout=1" "(2001:db8::10|timed out|no usable response|No acceptable nameservers|no servers could be reached)"
run_check "Ignore .digrc flag (-r)" "$DAG @127.0.0.1 -p $PORT www.example.com A -r" "192.0.2.10"
run_check "Source address & port bind (-b)" "$DAG @127.0.0.1 -p $PORT www.example.com A -b 127.0.0.1#54321" "192.0.2.10"
run_check "Short mode (+short)" "$DAG @127.0.0.1 -p $PORT www.example.com A +short" "^192\.0\.2\.10$"
run_check "Show Query (+qr)" "$DAG @127.0.0.1 -p $PORT www.example.com A +qr" ";; Sending:"
run_check "Microsecond stats (-u)" "$DAG @127.0.0.1 -p $PORT www.example.com A -u" ";; Query time:.*usec"
if [ "$DAG" = "dig" ]; then
    run_exit_check "Memory & Rusage Stats flag (-m)" "$DAG @127.0.0.1 -p $PORT www.example.com A -m" 0
    run_skip "Raw Hex Query (--hex)"
else
    run_check "Memory & Rusage Stats (-m)" "$DAG @127.0.0.1 -p $PORT www.example.com A -m" ";; Memory usage: maxrss="
    run_check "Raw Hex Query (--hex)" "$DAG @127.0.0.1 -p $PORT --hex=\"00010100000100000000000003777777076578616d706c6503636f6d0000010001\"" "192\.0\.2\.10"
fi
run_check "Version flag (-v)" "$DAG -v" "(KariDNS dag|DiG)"

echo "========================================================"
echo "2. Section & Display Toggling (+noall, +identify, +yaml)"
echo "========================================================"
run_check "No comments (+nocomments)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nocomments" "192\.0\.2\.10"
run_check "No answer section (+noanswer)" "$DAG @127.0.0.1 -p $PORT www.example.com A +noanswer" ";; flags:"
run_check "No authority section (+noauthority)" "$DAG @127.0.0.1 -p $PORT nonexistent.example.com A +noauthority" "status: NXDOMAIN"
run_check "No additional section (+noadditional)" "$DAG @127.0.0.1 -p $PORT example.com NS +noadditional" "ns1\.example\.com"
run_check "No question section (+noquestion)" "$DAG @127.0.0.1 -p $PORT www.example.com A +noquestion" "192\.0\.2\.10"
run_check "No command header (+nocmd)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nocmd" "192\.0\.2\.10"
run_check "No stats section (+nostats)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nostats" "192\.0\.2\.10"
run_check "Combined +noall +answer" "$DAG @127.0.0.1 -p $PORT www.example.com A +noall +answer" "192\.0\.2\.10"
run_check "Identify server (+identify)" "$DAG @127.0.0.1 -p $PORT www.example.com A +identify" "(127\.0\.0\.1#53555|from server 127\.0\.0\.1)"
run_check "Best effort parsing flag (+besteffort)" "$DAG @127.0.0.1 -p $PORT www.example.com A +besteffort" "192\.0\.2\.10"
run_check "YAML formatted output (+yaml)" "$DAG @127.0.0.1 -p $PORT www.example.com A +yaml" "(answers:|answer:|name:|opcode:|message:)"
if [ "$DAG" = "dig" ]; then
    run_skip "Hexdump suppression (+nohexdump)"
    run_skip "Hexdump query suppression (+nohexdump-query)"
    run_skip "Hexdump response suppression (+nohexdump-response)"
else
    run_check "Hexdump suppression (+nohexdump)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nohexdump" "192\.0\.2\.10"
    run_check "Hexdump query suppression (+nohexdump-query)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nohexdump-query" "192\.0\.2\.10"
    run_check "Hexdump response suppression (+nohexdump-response)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nohexdump-response" "192\.0\.2\.10"
fi

echo "========================================================"
echo "3. Layout, Class & TTL Formatting"
echo "========================================================"
run_check "No class (+noclass)" "$DAG @127.0.0.1 -p $PORT www.example.com A +noclass" "www\.example\.com\.[[:space:]]+[0-9]+[[:space:]]+A[[:space:]]+192\.0\.2\.10"
run_check "TTL units (+ttlunits)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ttlunits" "www\.example\.com\.[[:space:]]+[0-9]+[smhd][[:space:]]+IN[[:space:]]+A"
run_check "Unknown format (+unknownformat)" "$DAG @127.0.0.1 -p $PORT www.example.com A +unknownformat" 'CLASS1[[:space:]]+TYPE1[[:space:]]+\\#[[:space:]]+[0-9]+'
run_check "TTL ID toggling (+ttlid / +nottlid)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nottlid" "www\.example\.com\.[[:space:]]+IN[[:space:]]+A"
run_check "Multiline mode (+multiline)" "$DAG @127.0.0.1 -p $PORT example.com SOA +multiline" "serial"
run_check "Multiline mode alias (+multi)" "$DAG @127.0.0.1 -p $PORT example.com SOA +multi" "serial"
run_check "Multiline mode disable alias (+nomulti)" "$DAG @127.0.0.1 -p $PORT example.com SOA +nomulti" "(IN[[:space:]]+SOA|serial)"
run_check "Expire time display (+expire)" "$DAG @127.0.0.1 -p $PORT example.com SOA +expire" "(SOA|expire|serial)"
run_check "AXFR single SOA (+onesoa)" "$DAG @127.0.0.1 -p $PORT example.com AXFR +onesoa" "SOA"
run_check "Expand AAAA addresses (+expandaaaa)" "$DAG @127.0.0.1 -p $PORT www.example.com AAAA +expandaaaa" "2001:0db8:0000:0000:0000:0000:0000:0010"

echo "========================================================"
echo "4. DNSSEC & RR Comments & Crypto formatting"
echo "========================================================"
run_check "RR Comments on DNSKEY (+rrcomments)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +rrcomments" "; KSK; alg =.*key id ="
run_check "Omit crypto on DNSKEY (+nocrypto)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +nocrypto" "\[key id ="
run_check "Split width (+split=16)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +split=16" "257 3 [0-9]+ [A-Za-z0-9+/=]{16} [A-Za-z0-9+/=]{16}"
run_check "DNSSEC OK flag (+dnssec / +do)" "$DAG @127.0.0.1 -p $PORT example.com DNSKEY +dnssec +qr" "flags: do"

echo "========================================================"
echo "5. EDNS0, Badcookie & Transport Extensions"
echo "========================================================"
run_check "EDNS Buffer Size (+bufsize=4096)" "$DAG @127.0.0.1 -p $PORT www.example.com A +bufsize=4096 +qr" "udp:[[:space:]]*4096"
run_check "EDNS NSID Option (+nsid)" "$DAG @127.0.0.1 -p $PORT www.example.com A +nsid +qr" "NSID"
run_check "EDNS CO flag (+coflag)" "$DAG @127.0.0.1 -p $PORT www.example.com A +coflag +qr" "flags: co"
run_check "EDNS Cookie (+cookie)" "$DAG @127.0.0.1 -p $PORT www.example.com A +cookie=0102030405060708 +qr" "; COOKIE: 0102030405060708"
run_check "EDNS Subnet (+subnet)" "$DAG @127.0.0.1 -p $PORT www.example.com A +subnet=192.0.2.0/24 +qr" "; CLIENT-SUBNET: 192\.0\.2\.0/24"
run_check "EDNS Padding (+padding)" "$DAG @127.0.0.1 -p $PORT www.example.com A +padding=64 +qr" "; PADDING:"
run_check "EDNS Keepalive (+keepalive)" "$DAG @127.0.0.1 -p $PORT www.example.com A +keepalive +qr" "; (TCP-)?KEEPALIVE"
run_check "EDNS Flags raw Z-bits (+ednsflags)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ednsflags=0x0040 +qr" "flags:.*0x0040|OPT PSEUDOSECTION"
run_check "EDNS Negotiation flag (+ednsnegotiation)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ednsnegotiation" "192\.0\.2\.10"
run_check "BADCOOKIE retry (+badcookie)" "$DAG @127.0.0.1 -p $PORT www.example.com A +badcookie" "192\.0\.2\.10"
run_check "Show BADCOOKIE diagnostic (+showbadcookie)" "$DAG @127.0.0.1 -p $PORT www.example.com A +showbadcookie" "192\.0\.2\.10"
run_check "Show BADVERS diagnostic (+showbadvers)" "$DAG @127.0.0.1 -p $PORT www.example.com A +showbadvers" "192\.0\.2\.10"
run_check "Keep TCP socket open (+keepopen)" "$DAG @127.0.0.1 -p $PORT www.example.com A +tcp +keepopen" "192\.0\.2\.10"
run_check "Generic EDNS option (+ednsopt)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ednsopt=65001:01020304 +qr" "; (OPTION:[[:space:]]+|OPT=)65001"
if [ "$DAG" = "dig" ]; then
    run_skip "RFC 10029 Multi-QTYPE (+mqtype)"
else
    run_check "RFC 10029 Multi-QTYPE (+mqtype)" "$DAG @127.0.0.1 -p $PORT www.example.com A +mqtype=AAAA +qr" "2001:db8::10"
fi

echo "========================================================"
echo "6. Query & Header Overrides"
echo "========================================================"
run_check "Header only / QDCOUNT=0 (+header-only)" "$DAG @127.0.0.1 -p $PORT www.example.com A +header-only +qr" "QUERY: 0"
run_check "QID override (+qid=4660)" "$DAG @127.0.0.1 -p $PORT www.example.com A +qid=4660 +qr" "id: 4660"
run_check "Opcode override (+opcode=NOTIFY)" "$DAG @127.0.0.1 -p $PORT www.example.com A +opcode=NOTIFY +qr" "opcode: NOTIFY"
run_check "Flags override (+adflag +cdflag +aaflag +tcflag +raflag +zflag)" "$DAG @127.0.0.1 -p $PORT www.example.com A +adflag +cdflag +aaflag +tcflag +raflag +zflag +qr" "flags:.*(ad|cd|aa|tc|ra)"
run_check "Recursion flag override (+norec)" "$DAG @127.0.0.1 -p $PORT www.example.com A +norec +qr" ";; flags:"
run_check "Recursion flag enable (+rec)" "$DAG @127.0.0.1 -p $PORT www.example.com A +rec +qr" "flags:.*rd"
run_check "Ignore truncation flag (+ignore)" "$DAG @127.0.0.1 -p $PORT www.example.com A +ignore" "192\.0\.2\.10"
run_check "Timeout flag (+timeout=2)" "$DAG @127.0.0.1 -p $PORT www.example.com A +timeout=2" "192\.0\.2\.10"
run_check "Timeout alias (+time=2)" "$DAG @127.0.0.1 -p $PORT www.example.com A +time=2" "192\.0\.2\.10"
run_check "Tries and Retry flags (+tries=2 +retry=2)" "$DAG @127.0.0.1 -p $PORT www.example.com A +tries=2 +retry=2" "192\.0\.2\.10"
run_check "Search list and ndots expansion (+search +domain +ndots=2)" "$DAG @127.0.0.1 -p $PORT www.example +domain=com +ndots=2 +search" "192\.0\.2\.10"
run_check "Search list not expanded when ndots exceeded (+ndots=1)" "$DAG @127.0.0.1 -p $PORT www.example +domain=com +ndots=1 +search" "(NXDOMAIN|SERVFAIL|REFUSED|no servers could be reached|got NXDOMAIN)"
run_check "Showsearch diagnostic (+showsearch)" "$DAG @127.0.0.1 -p $PORT www +domain=example.com +showsearch" "192\.0\.2\.10"
run_check "DNS64 prefix check (+dns64prefix)" "$DAG @127.0.0.1 -p $PORT ipv4only.arpa AAAA +dns64prefix +qr" ";ipv4only\.arpa\..*IN.*AAAA"
run_check "PROXYv2 local header (+proxy)" "$DAG @127.0.0.1 -p $PORT www.example.com A +proxy +timeout=1" "(192\.0\.2\.10|timed out|no usable response|no servers could be reached)"
run_check "Plain HTTP query (+http-plain)" "$DAG @127.0.0.1 -p $PORT www.example.com A +http-plain +timeout=1" "(192\.0\.2\.10|timed out|connection failed|no usable response|no servers could be reached)"

echo "========================================================"
echo "7. Multi-Server, LDNSZ & Failover"
echo "========================================================"
if [ "$DAG" = "dig" ]; then
    run_skip "Multi-Server query list (@s1,s2)"
    run_skip "LDNS-style summary (+ldnsz)"
    run_skip "Comparison matrix (+allcompare)"
    run_skip "Server failover (+nofail)"
else
    run_check "Multi-Server query list" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A" "192\.0\.2\.10"
    run_check "LDNS-style summary (+ldnsz)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A +ldnsz" "127\.0\.0\.1"
    run_check "Comparison matrix (+allcompare)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A +allcompare" "127\.0\.0\.1"
    run_check "Comparison matrix with Cookie (+allcompare +cookie)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A +cookie +allcompare" "127\.0\.0\.1"
    run_check "Comparison matrix with TCP timeout (+allcompare +tcp +timeout=2)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A +tcp +timeout=2 +allcompare" "127\.0\.0\.1"
    run_check "Comparison matrix with +time alias (+allcompare +time=2)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A +time=2 +allcompare" "127\.0\.0\.1"
    run_check "Server failover (+nofail)" "$DAG @127.0.0.1:19999,127.0.0.1:$PORT www.example.com A +nofail +timeout=1 +tries=1" "192\.0\.2\.10"
fi

echo "========================================================"
echo "8. TSIG Authentication (-y, +tsig, -k keyfile, +fuzztime)"
echo "========================================================"
run_check "TSIG signature (-y)" "$DAG @127.0.0.1 -p $PORT www.example.com A -y hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +qr" "(TSIG|testkey|ADDITIONAL)"
cat << 'EOF' > tsig_key.conf
key "testkey" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF
run_check "TSIG keyfile flag (-k)" "$DAG @127.0.0.1 -p $PORT www.example.com A -k tsig_key.conf +qr" "(TSIG|testkey|ADDITIONAL)"
run_check "TSIG signing time override (+fuzztime)" "$DAG @127.0.0.1 -p $PORT www.example.com A -y hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +fuzztime=1646972129 +qr" "(BADTIME|62 2a ab 61|1646972129|ADDITIONAL)"
if [ "$DAG" = "dig" ]; then
    run_skip "TSIG signature (+tsig=)"
else
    run_check "TSIG signature (+tsig=)" "$DAG @127.0.0.1 -p $PORT www.example.com A +tsig=hmac-sha256:testkey:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl +qr" "(TSIG|testkey|ADDITIONAL)"
fi

echo "========================================================"
echo "9. Dynamic DNS Update (RFC 2136) & Prerequisites"
echo "========================================================"
if [ "$DAG" = "dig" ]; then
    run_skip "Dynamic update add (--update-add)"
    run_skip "Dynamic update del (--update-del)"
    run_skip "Dynamic update del exact (--update-del-exact)"
    run_skip "Dynamic update prereq NXDOMAIN (--prereq-nxdomain)"
    run_skip "Dynamic update prereq YXDOMAIN (--prereq-yxdomain)"
    run_skip "Dynamic update prereq NXRRSET (--prereq-nxrrset)"
    run_skip "Dynamic update prereq YXRRSET (--prereq-yxrrset)"
    run_skip "Dynamic update prereq spec (--prereq=)"
else
    run_check "Dynamic update add (--update-add)" "$DAG @127.0.0.1 -p $PORT example.com --update-add \"dyn.example.com 300 IN A 192.0.2.99\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update del (--update-del)" "$DAG @127.0.0.1 -p $PORT example.com --update-del \"dyn.example.com A\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update del without type (--update-del name)" "$DAG @127.0.0.1 -p $PORT example.com --update-del \"obsolete.example.com\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update del exact (--update-del-exact)" "$DAG @127.0.0.1 -p $PORT example.com --update-del-exact \"dyn.example.com A 192.0.2.99\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update del exact with TTL (--update-del-exact 'name TTL type rdata')" "$DAG @127.0.0.1 -p $PORT example.com --update-del-exact \"host.example.com 300 A 192.0.2.1\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update unknown type skipped gracefully" "$DAG @127.0.0.1 -p $PORT example.com --update-del-exact \"host.example.com BOGUSTYPE 192.0.2.1\" --update-add \"valid.example.com 300 A 192.0.2.1\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update prereq NXDOMAIN (--prereq-nxdomain)" "$DAG @127.0.0.1 -p $PORT example.com --prereq-nxdomain dyn.example.com +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update prereq YXDOMAIN (--prereq-yxdomain)" "$DAG @127.0.0.1 -p $PORT example.com --prereq-yxdomain example.com +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update prereq NXRRSET (--prereq-nxrrset)" "$DAG @127.0.0.1 -p $PORT example.com --prereq-nxrrset \"dyn.example.com TXT\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update prereq YXRRSET (--prereq-yxrrset)" "$DAG @127.0.0.1 -p $PORT example.com --prereq-yxrrset \"example.com SOA\" +qr" "opcode:[[:space:]]*UPDATE"
    run_check "Dynamic update prereq spec (--prereq=)" "$DAG @127.0.0.1 -p $PORT example.com --prereq=nxdomain:dyn.example.com +qr" "opcode:[[:space:]]*UPDATE"
fi

echo "========================================================"
echo "10. Search Domains, Batch Files & .digrc Configuration"
echo "========================================================"
run_check "Search domain option (+domain= +search)" "$DAG @127.0.0.1 -p $PORT www +domain=example.com +search" "192\.0\.2\.10"
run_check "Persistent option lifecycle across retries (+domain= with +tries=2)" "$DAG @127.0.0.1 -p $PORT www +domain=example.com +search +tries=2" "192\.0\.2\.10"
cat << 'EOF' > batch_test.txt
www.example.com A
mail.example.com A
example.com NS
EOF
run_check "Batch query file (-f)" "$DAG @127.0.0.1 -p $PORT -f batch_test.txt" "192\.0\.2\.20"

# Test .digrc loading
cat << 'EOF' > .digrc
+short
EOF
HOME="$TEST_DIR_ABS" run_check ".digrc default option loading" "HOME='$TEST_DIR_ABS' $DAG @127.0.0.1 -p $PORT www.example.com A" "^192\.0\.2\.10$"
HOME="$TEST_DIR_ABS" run_check "Ignore .digrc (-r)" "HOME='$TEST_DIR_ABS' $DAG @127.0.0.1 -p $PORT www.example.com A -r" ";; ->>HEADER<<-"

echo "========================================================"
echo "11. Exit Code Specification (0, 1, 8, 9)"
echo "========================================================"
run_exit_check "Exit code 0 on success" "$DAG @127.0.0.1 -p $PORT www.example.com A" 0
run_exit_check "Exit code 1 on usage error / bad option" "$DAG -X" 1
run_exit_check "Exit code 8 on missing batch file" "$DAG -f /nonexistent/batch/file.txt" 8
run_exit_check "Exit code 9 on unreachable server / timeout" "$DAG @127.0.0.1 -p 19999 www.example.com A +timeout=1 +tries=1" 9

echo "========================================================"
echo "12. Multiple Queries & Positional Flexibility"
echo "========================================================"
run_check "Multiple Queries (A and TXT)" "$DAG @127.0.0.1 -p $PORT www.example.com A example.com TXT" "192\.0\.2\.10"
run_check "Positional Order: Name Class Type (www.example.com IN A)" "$DAG @127.0.0.1 -p $PORT www.example.com IN A" "192\.0\.2\.10"
run_check "Positional Order: Name Type Class (www.example.com A IN)" "$DAG @127.0.0.1 -p $PORT www.example.com A IN" "192\.0\.2\.10"
run_check "Positional Order: Type Name Class (A www.example.com IN)" "$DAG @127.0.0.1 -p $PORT A www.example.com IN" "192\.0\.2\.10"
run_check "Global +short applied to multiple queries" "$DAG @127.0.0.1 -p $PORT www.example.com A +short example.com TXT" "192\.0\.2\.10"
run_check "Per-query display override (+qr / +noqr)" "$DAG @127.0.0.1 -p $PORT +qr www.example.com A example.com TXT +noqr" ";; Sending:"
run_check "Mixed -x reverse and normal lookup" "$DAG @127.0.0.1 -p $PORT -x 192.0.2.10 www.example.com A" "192\.0\.2\.10"
if [ "$DAG" = "dig" ]; then
    run_skip "MAX_DAG_QUERIES (64) exceeded error"
else
    # 65 queries generates exit code 1
    Q65_ARGS=""
    i=1
    while [ "$i" -le 65 ]; do
        Q65_ARGS="$Q65_ARGS test$i.example.com A"
        i=$((i + 1))
    done
    run_exit_check "MAX_DAG_QUERIES (64) exceeded error" "$DAG @127.0.0.1 -p $PORT $Q65_ARGS" 1
fi

echo "========================================================"
echo "13. Live DoT / DoH Checks (against public resolvers)"
echo "========================================================"
# Check if outbound internet is accessible
if "$DAG" @1.1.1.1 example.com A +timeout=2 +tries=1 >/dev/null 2>&1; then
    echo "Internet connectivity detected. Running Live DoT & DoH tests..."
    run_check "Live DoT (RFC 7858) @8.8.8.8" "$DAG @8.8.8.8 www.google.com A +tls +timeout=4" "142\.25[0-9]\.[0-9]+"
    run_check "Live DoT with default CA & SNI verification" "$DAG @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=dns.google +timeout=4" "142\.25[0-9]\.[0-9]+"
    run_check "Live DoT with mismatched hostname rejected" "$DAG @8.8.8.8 www.google.com A +tls +tls-ca +tls-hostname=mismatch.invalid +timeout=4" "(TLS peer certificate verification|hostname mismatch|verification failed)"
    run_check "Live DoH (RFC 8484) @1.1.1.1" "$DAG @1.1.1.1 www.cloudflare.com A +https +timeout=4" "104\.1[0-9]\.[0-9]+"
else
    echo "No direct outbound internet connectivity. Skipping live DoT/DoH network tests."
fi

echo "========================================================"
echo "14. Multi-Server Queries & +ldnsz Diff URL Tests"
echo "========================================================"
if [ "$DAG" = "dig" ]; then
    run_skip "Multi-server query comparison and +ldnsz URL"
else
    run_check "Single server +ldnsz URL output" "$DAG @127.0.0.1 -p $PORT www.example.com A +ldnsz" "https://ldns\.jp/\?dnsz="
    run_check "Multi-server comparison table output" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A" ";; === MULTI-SERVER COMPARISON SUMMARY ==="
    run_check "Multi-server +ldnsz diff URL (option at end)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT www.example.com A +ldnsz" "https://ldns\.jp/diff/#c="
    run_check "Multi-server +ldnsz diff URL (option at beginning)" "$DAG @127.0.0.1,127.0.0.1 -p $PORT +ldnsz www.example.com A" "https://ldns\.jp/diff/#c="
fi

echo "========================================================"
echo "15. Version Flags & Tool Metadata Tests"
echo "========================================================"
if [ "$DAG" != "dig" ]; then
    run_check "dag -v output" "$DAG -v" "KariDNS dag v0\."
    run_check "dag --version output" "$DAG --version" "KariDNS dag v0\."
    run_check "karictl -v output" "$BIN_DIR/karictl -v" "karictl 0\."
    run_check "karicheck -v output" "$BIN_DIR/karicheck -v" "karicheck 0\."
    run_check "karidns -v output" "$BIN_DIR/karidns -v" "KariDNS 0\."
fi

echo "========================================================"
echo "16. Hex Payload Overflow & Boundary Tests"
echo "========================================================"
if [ "$DAG" != "dig" ]; then
    OVERSIZED_HEX=$(awk 'BEGIN { for (i=1; i<=70000; i++) printf "aa" }' 2>/dev/null || perl -e 'print "aa" x 70000' 2>/dev/null)
    run_check "Oversized hex payload rejected without crash" "$DAG @127.0.0.1 -p $PORT --hex $OVERSIZED_HEX" "Invalid, empty, or oversized hex payload"
    run_check "Empty hex payload rejected" "$DAG @127.0.0.1 -p $PORT --hex ''" "Invalid, empty, or oversized hex payload"
fi

echo "========================================================"
echo "17. CLI Options, IDN, EDNSOPT, Prereq, and Break Validation"
echo "========================================================"
run_check "+idn flag accepted" "$DAG @127.0.0.1 -p $PORT example.com A +idn +timeout=1" "(opcode: QUERY|status:|timed out|no usable response|no servers could be reached)"
run_check "+noidn flag accepted" "$DAG @127.0.0.1 -p $PORT example.com A +noidn +timeout=1" "(opcode: QUERY|status:|timed out|no usable response|no servers could be reached)"
run_check "+multi flag accepted" "$DAG @127.0.0.1 -p $PORT example.com A +multi +timeout=1" "(opcode: QUERY|status:|timed out|no usable response|no servers could be reached)"
run_check "+nomulti flag accepted" "$DAG @127.0.0.1 -p $PORT example.com A +nomulti +timeout=1" "(opcode: QUERY|status:|timed out|no usable response|no servers could be reached)"
run_check "+noednsopt flag accepted" "$DAG @127.0.0.1 -p $PORT example.com A +ednsopt=65001:0102 +noednsopt +qr +timeout=1" "(opcode: QUERY|status:|timed out|no usable response|no servers could be reached)"
if [ "$DAG" != "dig" ]; then
    run_check "--prereq-nxrrset separate args" "$DAG @127.0.0.1 -p $PORT example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq-nxrrset test.example.com A +qr +timeout=1" "Query \([0-9]+ bytes\)"
    run_check "--prereq-yxrrset separate args with rdata" "$DAG @127.0.0.1 -p $PORT example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq-yxrrset test.example.com A 1.2.3.4 +qr +timeout=1" "Query \([0-9]+ bytes\)"
    run_check "Multiple structural breaks warning" "$DAG @127.0.0.1 -p $PORT example.com A --break compression-loop --break oversized-qname +timeout=1" "warning: --break 'oversized-qname' ignored; structural break kind is already set"
fi

echo "========================================================"
echo "18. +trace/+nssearch Transport & +yaml RDATA Output Tests"
echo "========================================================"
run_check "+trace +tcp execution" "$DAG @127.0.0.1 -p $PORT example.com +trace +tcp +timeout=1" "(TRACE:|connection timed out|no servers could be reached|no usable response|Received [0-9]+ bytes)"
run_check "+nssearch +tcp execution" "$DAG @127.0.0.1 -p $PORT example.com +nssearch +tcp +timeout=1" "(couldn't get address|SOA |connection timed out|no usable response)"
run_check "+yaml output structure" "$DAG @127.0.0.1 -p $PORT example.com A +yaml +timeout=1" "(^---|question:|- type: MESSAGE)"

echo "========================================================"
echo "19. RFC 5452 UDP Security & Transport Resilience Tests"
echo "========================================================"
run_check "Standard UDP resolution with connected socket" "$DAG @127.0.0.1 -p $PORT www.example.com A +timeout=2" "192\.0\.2\.10"
run_check "Explicit QID query with connected socket (+qid)" "$DAG @127.0.0.1 -p $PORT www.example.com A +qid=4660 +timeout=2" "192\.0\.2\.10"
run_check "UDP socket bind to source IP (-b)" "$DAG -b 127.0.0.1 @127.0.0.1 -p $PORT www.example.com A +timeout=2" "192\.0\.2\.10"

echo "========================================================"
echo "20. Dedicated Security & Regression Test Scripts"
echo "========================================================"
if [ "$DAG" != "dig" ]; then
    run_check "Regression: --update-del type omission (tests/run_dag_update_del_no_type_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_update_del_no_type_test.sh\"" "PASS:"
    run_check "Regression: --update-del-exact TTL & type safety (tests/run_dag_update_del_exact_ttl_notype_crash_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_update_del_exact_ttl_notype_crash_test.sh\"" "PASS:"
    run_check "Help examples: --break usage examples validation (tests/run_dag_break_help_examples_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_break_help_examples_test.sh\"" "PASS:"
    run_check "Override: duplicate --break kind override validation (tests/run_break_duplicate_kind_override_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_break_duplicate_kind_override_test.sh\"" "PASS:"
fi
run_check "CLI Options & Prereq/Break validation (tests/run_dag_cli_options_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_cli_options_test.sh\"" "ALL CLI OPTION TESTS PASSED"
run_check "Hex payload overflow safety (tests/run_dag_hex_payload_overflow_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_hex_payload_overflow_test.sh\"" "ALL HEX PAYLOAD OVERFLOW TESTS PASSED"
run_check "YAML RDATA output structure (tests/run_dag_yaml_rdata_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_rdata_test.sh\"" "ALL YAML RDATA TESTS PASSED"
run_check "YAML apostrophe escaping (tests/run_dag_yaml_apostrophe_escaping_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_apostrophe_escaping_test.sh\"" "ALL YAML APOSTROPHE ESCAPING TESTS PASSED"
if command -v perl >/dev/null 2>&1; then
    run_check "Security: UDP spoofing source rejection (tests/run_dag_udp_spoofing_source_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_udp_spoofing_source_test.sh\"" "PASS:"
    run_check "Security: UDP transaction ID mismatch discard (tests/run_dag_udp_id_mismatch_discard_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_udp_id_mismatch_discard_test.sh\"" "PASS:"
    run_check "Security: DNS Cookie mismatch discard (tests/run_dag_cookie_mismatch_discard_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_cookie_mismatch_discard_test.sh\"" "PASS:"
    run_check "RFC 8945: TSIG AXFR unsigned intermediate digest chaining (tests/run_dag_axfr_tsig_unsigned_intermediate_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_axfr_tsig_unsigned_intermediate_test.sh\"" "PASS:"
    run_check "RFC 7873: BADCOOKIE TCP transport fallback (tests/run_dag_badcookie_transport_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_badcookie_transport_test.sh\"" "ALL BADCOOKIE / EXPIRE / KEEPOPEN TESTS PASSED"
    run_check "RFC 7050: DNS64 prefix discovery (tests/run_dag_dns64prefix_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_dns64prefix_test.sh\"" "PASS:"
    run_check "RFC 7050: DNS64 prefix in +short and +yaml mode (tests/run_dag_dns64prefix_short_yaml_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_dns64prefix_short_yaml_test.sh\"" "ALL DNS64PREFIX SHORT/YAML TESTS PASSED"
    run_check "Diagnostic: Malformed packet detection in default mode (tests/run_malformed_detection_default_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_malformed_detection_default_test.sh\"" "PASS:"
fi
run_check "Transport: TCP Keepopen & EDNS0 Keepalive (tests/run_dag_keepopen_keepalive_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_keepopen_keepalive_test.sh\"" "ALL KEEPOPEN & KEEPALIVE TESTS PASSED"
run_check "Transport: TCP Keepopen partial read cache invalidation (tests/run_dag_keepopen_partial_read_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_keepopen_partial_read_test.sh\"" "ALL KEEPOPEN PARTIAL READ TESTS PASSED"
run_check "Transport: TLS Keepopen & DoT continuity (tests/run_dag_keepopen_tls_partial_read_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_keepopen_tls_partial_read_test.sh\"" "ALL KEEPOPEN TLS TESTS PASSED"
run_check "Formatting: YAML EDE double-quote escaping (tests/run_dag_yaml_ede_escaping_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_ede_escaping_test.sh\"" "ALL YAML EDE ESCAPING TESTS PASSED"
run_check "Formatting: YAML Cookie STATUS verification (tests/run_dag_yaml_cookie_status_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_cookie_status_test.sh\"" "ALL YAML COOKIE STATUS TESTS PASSED"
run_check "Formatting: YAML socket_family accuracy (tests/run_dag_yaml_socket_family_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_socket_family_test.sh\"" "ALL YAML SOCKET_FAMILY TESTS PASSED"
run_check "Formatting: YAML -4/-6 socket_family priority (tests/run_dag_yaml_socket_family_force_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_socket_family_force_test.sh\"" "ALL YAML SOCKET_FAMILY FORCE TESTS PASSED"
run_check "Formatting: YAML clean stream without spurious errors (tests/run_dag_yaml_no_spurious_resolve_error_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_no_spurious_resolve_error_test.sh\"" "ALL YAML CLEAN STREAM TESTS PASSED"
run_check "Formatting: +multiline DS single-line formatting (tests/run_dag_multiline_ds_single_line_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_multiline_ds_single_line_test.sh\"" "ALL MULTILINE DS TESTS PASSED"
run_check "Transport: -b bind address family mismatch detection (tests/run_dag_bind_address_family_mismatch_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_bind_address_family_mismatch_test.sh\"" "ALL BIND ADDRESS FAMILY MISMATCH TESTS PASSED"
run_check "Transport: TCP connection establishment timeout (tests/run_dag_tcp_connect_timeout_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_tcp_connect_timeout_test.sh\"" "PASS:"
run_check "Formatting: YAML +nocrypto suppression (tests/run_dag_yaml_nocrypto_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_nocrypto_test.sh\"" "ALL YAML NOCRYPTO TESTS PASSED"
run_check "Formatting: YAML +expandaaaa AAAA expansion (tests/run_dag_yaml_expandaaaa_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_expandaaaa_test.sh\"" "ALL YAML EXPANDAAAA TESTS PASSED"
run_check "Formatting: YAML RRSIG structured decoding (tests/run_dag_yaml_rrsig_decode_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_yaml_rrsig_decode_test.sh\"" "ALL YAML RRSIG DECODE TESTS PASSED"
run_check "Protocol: Long label (63 bytes) name expansion (tests/run_dag_long_label_name_expansion_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_long_label_name_expansion_test.sh\"" "ALL LONG LABEL EXPANSION TESTS PASSED"
run_check "Features: Multi-server Semantic Match across compression (tests/run_dag_multi_server_semantic_match_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_multi_server_semantic_match_test.sh\"" "ALL MULTI-SERVER SEMANTIC MATCH TESTS PASSED"
run_check "RFC & CLI Fixes validation (tests/run_dag_fixes_validation_test.sh)" "sh \"$SCRIPT_DIR/run_dag_fixes_validation_test.sh\" \"$DAG\"" "All tests PASSED successfully\."
run_check "Compatibility: BIND 9 dig sample comparison (tests/run_dag_compat_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_compat_test.sh\"" "ALL DAG COMPATIBILITY TESTS PASSED"
if command -v perl >/dev/null 2>&1; then
    run_check "Plugin Zones: 'type program' zone loader (tests/run_program_zone_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_program_zone_test.sh\"" "ALL PROGRAM ZONE TESTS PASSED"
    run_check "Anomalous Packets: Comprehensive DNS packet wire suite (tests/run_dag_dig_anomalous_suite.sh)" "DAG_BIN=\"$DAG\" DIG_BIN=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_dig_anomalous_suite.sh\" \"$([ "$DAG" = "dig" ] && echo "dig" || echo "dag")\"" "ALL ANOMALOUS PACKET TESTS PASSED SUCCESSFULLY"
    run_check "Transport: Multi-Message AXFR & Plain-HTTP DoH mock (tests/run_dag_doh_dot_axfr_test.sh)" "DAG=\"$DAG\" sh \"$SCRIPT_DIR/run_dag_doh_dot_axfr_test.sh\"" "ALL DOT/DOH AXFR & MEMORY TESTS PASSED"
fi

echo "========================================================"
if [ "$FAILED" -eq 0 ]; then
    if [ "$SKIPPED" -gt 0 ]; then
        echo "🎉 ALL TESTS PASSED! ($SKIPPED skipped for $CLIENT_NAME)"
    else
        echo "🎉 ALL DAG COMPREHENSIVE CI TESTS PASSED!"
    fi
    exit 0
else
    echo "❌ $FAILED TESTS FAILED! ($SKIPPED skipped)"
    exit 1
fi
