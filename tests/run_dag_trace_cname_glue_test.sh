#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +trace Glue Fallback and CNAME Chain Tracing Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -x "$ROOT_DIR/dag" ]; then
    echo "=== Building dag with make ==="
    [ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag
fi

DAG="${1:-${DAG:-$ROOT_DIR/dag}}"

if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$ROOT_DIR/dag"
    fi
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[-] perl is not installed; skipping mock server test."
    exit 0
fi

FAILED=0
PORT=$((19000 + $$ % 10000))
TMP_DIR="/tmp/dag_trace_cname_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create a mock DNS server handling trace steps:
# 1. Root query (". NS") -> returns NS "a.root-servers.net" with glue "127.0.0.1"
#    (default +noglue ignores that glue and asks "a.root-servers.net A" -> "127.0.0.1")
# 2. Query "example.com A" -> returns referral to "ns1.external.org" WITHOUT glue
# 3. Query "ns1.external.org A" (glue resolution fallback) -> returns "127.0.0.1"
# 4. Query "example.com A" to authoritative -> returns "example.com CNAME cdn.example.net"
# 5. Query "cdn.example.net A" (CNAME re-trace) -> returns "192.0.2.100"
cat << 'PL_EOF' > "$TMP_DIR/mock_trace_server.pl"
use strict;
use warnings;
use Socket;

my $port = $ARGV[0] or die "Usage: $0 <port> [query_log] [authonly]\n";
my $query_log = $ARGV[1];
# authonly: behave like an authoritative-only root server (RA=0) whose NS name
# can only be resolved through the system resolver (e.g. dig +trace @198.41.0.4)
my $authonly = (defined $ARGV[2] && $ARGV[2] eq "authonly");
socket(my $srv, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!";
bind($srv, sockaddr_in($port, inet_aton("127.0.0.1"))) or die "bind: $!";

my $example_count = 0;
my %deleg_count;

sub enc_name {
    my ($n) = @_;
    my $w = "";
    for my $l (split /\./, $n) { $w .= chr(length($l)) . $l; }
    return $w . "\x00";
}

while (1) {
    my $query;
    my $client_addr = recv($srv, $query, 4096, 0);
    next unless defined $client_addr && length($query) >= 12;

    my $qid = substr($query, 0, 2);

    # Parse Question name
    my $off = 12;
    my $qname = "";
    while ($off < length($query)) {
        my $len = ord(substr($query, $off, 1));
        $off++;
        last if $len == 0;
        $qname .= substr($query, $off, $len) . ".";
        $off += $len;
    }

    my $qtype = unpack("n", substr($query, $off, 2));
    if ($query_log && open(my $lfh, ">>", $query_log)) {
        print $lfh "$qname $qtype\n";
        close($lfh);
    }
    # X-45: DO bit of the query (OPT right after the question: root name, TYPE 41, CLASS, TTL with the flags)
    my $do = 0;
    if (unpack("n", substr($query, 10, 2)) >= 1 && length($query) >= $off + 15 &&
        substr($query, $off + 4, 1) eq "\x00" && unpack("n", substr($query, $off + 5, 2)) == 41) {
        $do = (unpack("n", substr($query, $off + 11, 2)) & 0x8000) ? 1 : 0;
    }
    if ($query_log && open(my $dfh, ">>", "$query_log.do")) {
        print $dfh "$qname $qtype do=$do\n";
        close($dfh);
    }

    my $resp = "";
    if ($authonly && ($qname eq "" || $qname eq ".")) {
        # Root NS query (AA=1, RA=0): NS ns.root.invalid with glue 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 1) .
                "\x00" . pack("nn", 2, 1) .
                "\x00" . pack("nnNn", 2, 1, 3600, 17) . "\x02ns\x04root\x07invalid\x00" .
                "\x02ns\x04root\x07invalid\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    } elsif ($authonly) {
        # Authoritative-only server refuses recursion
        $resp = $qid . pack("nnnnn", 0x8405, 1, 0, 0, 0) . substr($query, 12, $off + 4 - 12);
    } elsif ($qname eq "" || $qname eq ".") {
        $example_count = 0;
        %deleg_count = ();
        # Root NS query: return a.root-servers.net with glue 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 1) .
                "\x00" . pack("nn", 2, 1) .
                "\x00" . pack("nnNn", 2, 1, 3600, 20) . "\x01a\x0croot-servers\x03net\x00" .
                "\x01a\x0croot-servers\x03net\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^a\.root-servers\.net\./i && $qtype == 1) {
        # Root server address resolution (+noglue): return 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0) .
                "\x01a\x0croot-servers\x03net\x00" . pack("nn", 1, 1) .
                "\x01a\x0croot-servers\x03net\x00" . pack("nnNn", 1, 1, 3600, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^(indomain|sibling)\.test\.$/i && $qtype == 1) {
        # +glue=indomain scenarios:
        #   indomain.test NS ns1.indomain.test (in-domain glue -> trusted)
        #   sibling.test  NS ns1.other.test    (out-of-domain glue -> ignored by +glue=indomain)
        my $zone = lc($1) . ".test";
        my $ns = ($zone eq "indomain.test") ? "ns1.indomain.test" : "ns1.other.test";
        my $zw = enc_name($zone);
        my $nw = enc_name($ns);
        if (++$deleg_count{$zone} == 1) {
            $resp = $qid . pack("nnnnn", 0x8000, 1, 0, 1, 1) .
                    $zw . pack("nn", 1, 1) .
                    $zw . pack("nnNn", 2, 1, 300, length($nw)) . $nw .
                    $nw . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
        } else {
            $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                    $zw . pack("nn", 1, 1) .
                    $zw . pack("nnNn", 1, 1, 300, 4) . inet_aton("192.0.2.200");
        }
    } elsif ($qname =~ /^ns1\.(indomain|other)\.test\.$/i && $qtype == 1) {
        # NS address resolution for the scenarios above
        my $nw = enc_name(lc($qname));
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0) .
                $nw . pack("nn", 1, 1) .
                $nw . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^ns1\.external\.org\./i) {
        # Glue resolution query: return 127.0.0.1
        $resp = $qid . pack("nnnnn", 0x8180, 1, 1, 0, 0) .
                "\x03ns1\x08external\x03org\x00" . pack("nn", 1, 1) .
                "\x03ns1\x08external\x03org\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("127.0.0.1");
    } elsif ($qname =~ /^example\.com\./i) {
        $example_count++;
        if ($example_count == 1) {
            # Referral without glue (Authority section only)
            $resp = $qid . pack("nnnnn", 0x8000, 1, 0, 1, 0) .
                    "\x07example\x03com\x00" . pack("nn", 1, 1) .
                    "\x07example\x03com\x00" . pack("nnNn", 2, 1, 300, 18) . "\x03ns1\x08external\x03org\x00";
        } else {
            # Authoritative response: CNAME cdn.example.net
            $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                    "\x07example\x03com\x00" . pack("nn", 1, 1) .
                    "\x07example\x03com\x00" . pack("nnNn", 5, 1, 300, 17) . "\x03cdn\x07example\x03net\x00";
        }
    } elsif ($qname =~ /^nodata\.test\./i) {
        # X-45: authoritative NODATA with only an SOA in Authority (no NS): not a referral, the trace ends
        my $nw = enc_name("nodata.test");
        my $soa = enc_name("ns1.nodata.test") . enc_name("hostmaster.nodata.test") . pack("NNNNN", 1, 3600, 600, 86400, 60);
        $resp = $qid . pack("nnnnn", 0x8400, 1, 0, 1, 0) . $nw . pack("nn", $qtype, 1) .
                $nw . pack("nnNn", 6, 1, 60, length($soa)) . $soa;
    } elsif ($qname =~ /^cdn\.example\.net\./i) {
        # Re-traced target: return final A record 192.0.2.100
        $resp = $qid . pack("nnnnn", 0x8400, 1, 1, 0, 0) .
                "\x03cdn\x07example\x03net\x00" . pack("nn", 1, 1) .
                "\x03cdn\x07example\x03net\x00" . pack("nnNn", 1, 1, 300, 4) . inet_aton("192.0.2.100");
    } else {
        $resp = $qid . pack("nnnnn", 0x8183, 1, 0, 0, 0) . substr($query, 12, $off + 4 - 12);
    }

    send($srv, $resp, 0, $client_addr);
}
PL_EOF

QUERY_LOG="$TMP_DIR/queries.log"
perl "$TMP_DIR/mock_trace_server.pl" "$PORT" "$QUERY_LOG" &
MOCK_PID=$!
sleep 0.5

echo "=== 1. Testing +trace with Out-of-Bailiwick Delegation (No Glue Fallback) ==="
echo -n "Test: Trace succeeds through glue resolution and stops at the CNAME like dig ... "
: > "$QUERY_LOG"
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 2>&1 || true)
# BIND dig +trace (9.20) ends at the authoritative CNAME answer and does not restart for the target (T-14)
if echo "$OUT" | grep -q "ns1\.external\.org" && echo "$OUT" | grep -qE "^example\.com\.[[:space:]].*CNAME[[:space:]]+cdn\.example\.net\." \
   && ! echo "$OUT" | grep -q "192\.0\.2\.100" && ! grep -qi "^cdn\.example\.net\." "$QUERY_LOG"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$QUERY_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo -n "Test: Received lines name the server like dig (T-05) ... "
# first hop: the @server text; later hops: the NS name the address belongs to
if echo "$OUT" | grep -qE "^;; Received [0-9]+ bytes from 127\.0\.0\.1#$PORT\(127\.0\.0\.1\) in [0-9]+ ms" \
   && echo "$OUT" | grep -qE "^;; Received [0-9]+ bytes from 127\.0\.0\.1#$PORT\(a\.root-servers\.net\) in [0-9]+ ms" \
   && echo "$OUT" | grep -qE "^;; Received [0-9]+ bytes from 127\.0\.0\.1#$PORT\(ns1\.external\.org\) in [0-9]+ ms"; then
    echo "OK"
else
    echo "FAILED"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo -n "Test: no multi-server comparison table after a trace (T-06) ... "
if ! echo "$OUT" | grep -q "MULTI-SERVER COMPARISON"; then
    echo "OK"
else
    echo "FAILED"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 2. Testing +trace default (+noglue) ignores ADDITIONAL section glue ==="
echo -n "Test: Root server address is resolved via resolver instead of glue ... "
: > "$QUERY_LOG"
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 2>&1 || true)
if grep -q "^a\.root-servers\.net\. 1$" "$QUERY_LOG" && echo "$OUT" | grep -q "cdn\.example\.net"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$QUERY_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 3. Testing +trace +glue uses ADDITIONAL section glue (legacy behavior) ==="
echo -n "Test: Root server glue is used without resolver lookup ... "
: > "$QUERY_LOG"
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +glue +timeout=2 2>&1 || true)
if ! grep -q "^a\.root-servers\.net\." "$QUERY_LOG" && echo "$OUT" | grep -q "ns1\.external\.org" && echo "$OUT" | grep -q "cdn\.example\.net"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$QUERY_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 3a. Testing +trace +glue=indomain (BIND named 9.18.41/9.20.15+ strict glue) ==="
if [ "$DAG" = "dig" ]; then
    echo "Test: +glue=indomain ... SKIP (dag-only option)"
else
    echo -n "Test: +glue=indomain trusts in-domain glue without resolver lookup ... "
    : > "$QUERY_LOG"
    OUT=$("$DAG" @127.0.0.1 -p $PORT indomain.test A +trace +glue=indomain +timeout=2 +nohexdump 2>&1 || true)
    if echo "$OUT" | grep -q "192\.0\.2\.200" && ! grep -q "^ns1\.indomain\.test\." "$QUERY_LOG" && ! echo "$OUT" | grep -q "ignoring out-of-domain glue"; then
        echo "OK"
    else
        echo "FAILED"; sed 's/^/    /' "$QUERY_LOG"; echo "$OUT" | sed 's/^/    /'; FAILED=$((FAILED + 1))
    fi

    echo -n "Test: +glue=indomain ignores sibling glue and resolves the NS name ... "
    : > "$QUERY_LOG"
    OUT=$("$DAG" @127.0.0.1 -p $PORT sibling.test A +trace +glue=indomain +timeout=2 +nohexdump 2>&1 || true)
    if echo "$OUT" | grep -q "192\.0\.2\.200" && grep -q "^ns1\.other\.test\. 1$" "$QUERY_LOG" && echo "$OUT" | grep -q "ignoring out-of-domain glue for 'ns1\.other\.test\.'"; then
        echo "OK"
    else
        echo "FAILED"; sed 's/^/    /' "$QUERY_LOG"; echo "$OUT" | sed 's/^/    /'; FAILED=$((FAILED + 1))
    fi

    echo -n "Test: +glue (all) still uses sibling glue ... "
    : > "$QUERY_LOG"
    OUT=$("$DAG" @127.0.0.1 -p $PORT sibling.test A +trace +glue +timeout=2 +nohexdump 2>&1 || true)
    if echo "$OUT" | grep -q "192\.0\.2\.200" && ! grep -q "^ns1\.other\.test\." "$QUERY_LOG"; then
        echo "OK"
    else
        echo "FAILED"; sed 's/^/    /' "$QUERY_LOG"; echo "$OUT" | sed 's/^/    /'; FAILED=$((FAILED + 1))
    fi

    echo -n "Test: invalid +glue mode is rejected ... "
    OUT=$("$DAG" @127.0.0.1 -p $PORT sibling.test A +trace +glue=bogus 2>&1 || true)
    if echo "$OUT" | grep -q "invalid +glue mode"; then
        echo "OK"
    else
        echo "FAILED"; echo "$OUT" | sed 's/^/    /'; FAILED=$((FAILED + 1))
    fi
fi

echo "=== 3b. Testing +trace hides ADDITIONAL section like dig (+additional re-enables) ==="
echo -n "Test: Root glue A record is not displayed by default ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 +nohexdump 2>&1 || true)
if [ "$DAG" = "dig" ]; then OUT=$(dig @127.0.0.1 -p $PORT example.com A +trace +timeout=2 2>&1 || true); fi
if ! echo "$OUT" | grep -qE "^a\.root-servers\.net\.[[:space:]].*[[:space:]]A[[:space:]]"; then
    echo "OK"
else
    echo "FAILED"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi
if [ "$DAG" != "dig" ]; then
    echo -n "Test: +trace +additional displays root glue A record ... "
    OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +additional +timeout=2 +nohexdump 2>&1 || true)
    if echo "$OUT" | grep -qE "^a\.root-servers\.net\.[[:space:]].*[[:space:]]A[[:space:]]"; then
        echo "OK"
    else
        echo "FAILED"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
fi

echo "=== 3c. Testing +trace like dig 9.20: banner, implied +dnssec and +authority, NODATA end (X-45) ==="
# compared with dig 9.20.29 +trace on the Internet (FIX_REPORTS phase 15b); here against the mock
echo -n "Test: banner and global options line before the first records ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 +nohexdump 2>&1 || true)
if [ "$(printf '%s\n' "$OUT" | sed -n 2p)" = "; <<>> dag <<>> example.com A @127.0.0.1" ] \
   && printf '%s\n' "$OUT" | grep -q "^; (1 server found)$" && printf '%s\n' "$OUT" | grep -q "^;; global options: +cmd$"; then
    echo "OK"
else
    echo "FAILED"; echo "$OUT" | sed 's/^/    /'; FAILED=$((FAILED + 1))
fi
echo -n "Test: +trace sets DO on every hop, a later +nodnssec clears it ... "
: > "$QUERY_LOG.do"
"$DAG" @127.0.0.1 -p $PORT example.com A +trace +timeout=2 > /dev/null 2>&1 || true
DO_ON=$(grep -c "do=1" "$QUERY_LOG.do" || true); DO_OFF=$(grep -c "do=0" "$QUERY_LOG.do" || true)
: > "$QUERY_LOG.do"
"$DAG" @127.0.0.1 -p $PORT example.com A +trace +nodnssec +timeout=2 > /dev/null 2>&1 || true
NO_DO=$(grep -c "do=1" "$QUERY_LOG.do" || true); NO_DO_TOTAL=$(wc -l < "$QUERY_LOG.do" | tr -d ' ')
if [ "$DO_ON" -ge 3 ] && [ "$DO_OFF" -eq 0 ] && [ "$NO_DO" -eq 0 ] && [ "$NO_DO_TOTAL" -ge 3 ]; then
    echo "OK"
else
    echo "FAILED (do=1: $DO_ON, do=0: $DO_OFF; with +nodnssec do=1: $NO_DO of $NO_DO_TOTAL)"; FAILED=$((FAILED + 1))
fi
echo -n "Test: +noall +answer +trace still shows the referral (dig: +trace sets +authority) ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +noall +answer +trace +timeout=2 +nohexdump 2>&1 || true)
OUT2=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +noall +answer +timeout=2 +nohexdump 2>&1 || true)
if printf '%s\n' "$OUT" | grep -qE "^example\.com\.[[:space:]].*NS[[:space:]]+ns1\.external\.org\." \
   && ! printf '%s\n' "$OUT2" | grep -qE "^example\.com\.[[:space:]].*NS[[:space:]]"; then
    echo "OK"
else
    echo "FAILED"; echo "$OUT" | sed 's/^/    /'; echo "    ---"; echo "$OUT2" | sed 's/^/    /'; FAILED=$((FAILED + 1))
fi
echo -n "Test: NODATA without NS in Authority ends the trace without a message ... "
OUT=$("$DAG" @127.0.0.1 -p $PORT nodata.test A +trace +timeout=2 +nohexdump 2>&1 || true)
if printf '%s\n' "$OUT" | grep -qE "^nodata\.test\.[[:space:]].*SOA[[:space:]]" && ! printf '%s\n' "$OUT" | grep -q "stopping trace"; then
    echo "OK"
else
    echo "FAILED"; echo "$OUT" | sed 's/^/    /'; FAILED=$((FAILED + 1))
fi

echo "=== 4. Testing +trace against authoritative-only @server (RA=0) ==="
echo -n "Test: NS names are resolved via system resolver, not the non-recursive @server ... "
AUTH_PORT=$((PORT + 1))
AUTH_LOG="$TMP_DIR/auth_queries.log"
: > "$AUTH_LOG"
perl "$TMP_DIR/mock_trace_server.pl" "$AUTH_PORT" "$AUTH_LOG" authonly &
AUTH_PID=$!
sleep 0.5
OUT=$("$DAG" @127.0.0.1 -p $AUTH_PORT example.com A +trace +timeout=1 +tries=1 2>&1 || true)
kill -9 "$AUTH_PID" 2>/dev/null || true
if echo "$OUT" | grep -q "couldn't get address for 'ns\.root\.invalid'" && ! grep -q "^ns\.root\.invalid\." "$AUTH_LOG" && ! echo "$OUT" | grep -q "from 127\.0\.0\.1#$AUTH_PORT\$"; then
    echo "OK"
else
    echo "FAILED"
    echo "  Queries:"
    sed 's/^/    /' "$AUTH_LOG"
    echo "  Output:"
    echo "$OUT" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo "=== 5. Testing +trace +ldnsz emits ldns.jp trace viewer URL ==="
if [ "$DAG" = "dig" ]; then
    echo "Test: +trace +ldnsz emits https://ldns.jp/trace/#c= URL ... SKIP (dag-only +ldnsz option)"
else
    echo -n "Test: +trace +ldnsz emits https://ldns.jp/trace/#c= URL ... "
    OUT=$("$DAG" @127.0.0.1 -p $PORT example.com A +trace +ldnsz +timeout=2 2>&1 || true)
    if echo "$OUT" | grep -q "https://ldns\.jp/trace/#c=" && ! echo "$OUT" | grep -q "https://ldns\.jp/diff/"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL TRACE GLUE & CNAME TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED TRACE GLUE & CNAME TESTS FAILED!"
    exit 1
fi
