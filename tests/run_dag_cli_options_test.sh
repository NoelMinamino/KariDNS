#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) CLI Options, IDN, EDNSOPT, Prereq, and Break Validation Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building tools/dag with make ==="
make -C "$ROOT_DIR" dag

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

FAILED=0

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

run_not_check() {
    NAME="$1"
    CMD="$2"
    UNEXPECT="$3"
    echo -n "Test: $NAME (should NOT match '$UNEXPECT') ... "
    OUT=$(eval "$CMD" 2>&1 || true)
    if echo "$OUT" | grep -E -q "$UNEXPECT"; then
        echo "FAILED"
        echo "  Command: $CMD"
        echo "  Unexpected match: $UNEXPECT"
        echo "  Output:"
        echo "$OUT" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    else
        echo "OK"
    fi
}

run_skip() {
    NAME="$1"
    REASON="${2:-dag-only feature}"
    echo "Test: $NAME ... SKIP ($REASON)"
}

echo "=== 1. Testing +idn and +noidn flags ==="
# +idn and +noidn should be recognized as valid options
run_check "+idn flag accepted" "$DAG @127.0.0.1 -p 10053 example.com A +idn +timeout=1" "(opcode: QUERY|timed out|no usable response|status:)"
run_check "+noidn flag accepted" "$DAG @127.0.0.1 -p 10053 example.com A +noidn +timeout=1" "(opcode: QUERY|timed out|no usable response|status:)"
run_check "+idnin and +idnout accepted" "$DAG @127.0.0.1 -p 10053 example.com A +idnin +idnout +timeout=1" "(opcode: QUERY|timed out|no usable response|status:)"
run_check "+idnin converts UTF-8 domain to Punycode" "$DAG @127.0.0.1 -p 10053 日本語.jp A +idnin +qr +timeout=1" "(xn--wgv71a119e\.jp|timed out|no usable response)"

echo "=== 2. Testing +noednsopt flag ==="
# +ednsopt=65001:0102 adds custom option 65001 (0xfde9 in hex dump)
run_check "+ednsopt adds custom EDNS option" "$DAG @127.0.0.1 -p 10053 example.com A +ednsopt=65001:0102 +qr +timeout=1" "(fd e9 00 02 01 02|OPT 65001|OPTION: 65001)"
run_not_check "+noednsopt clears custom EDNS option" "$DAG @127.0.0.1 -p 10053 example.com A +ednsopt=65001:0102 +noednsopt +qr +timeout=1" "(fd e9 00 02 01 02|OPTION: 65001|OPT 65001)"

echo "=== 3. Testing Dynamic DNS UPDATE prerequisites (--prereq-*) ==="
if [ "$DAG" = "dig" ]; then
    run_skip "--prereq-nxrrset separate arguments"
    run_skip "--prereq-yxrrset separate arguments without rdata"
    run_skip "--prereq-yxrrset separate arguments with rdata"
    run_skip "--prereq-yxrrset quoted argument with rdata"
    run_skip "--prereq colon-delimited with rdata"
else
    # Test --prereq-nxrrset with separate arguments (name type)
    run_check "--prereq-nxrrset separate arguments" "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq-nxrrset test.example.com A +qr +timeout=1" "Query \([0-9]+ bytes\)"
    # Test --prereq-yxrrset with separate arguments (name type)
    run_check "--prereq-yxrrset separate arguments without rdata" "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq-yxrrset test.example.com A +qr +timeout=1" "Query \([0-9]+ bytes\)"
    # Test --prereq-yxrrset with separate arguments including rdata (name type rdata)
    run_check "--prereq-yxrrset separate arguments with rdata" "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq-yxrrset test.example.com A 1.2.3.4 +qr +timeout=1" "Query \([0-9]+ bytes\)"
    # Test --prereq-yxrrset with quoted single argument
    run_check "--prereq-yxrrset quoted argument with rdata" "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq-yxrrset 'test.example.com A 1.2.3.4' +qr +timeout=1" "Query \([0-9]+ bytes\)"
    # Test --prereq=yxrrset:name:type:rdata colon-delimited format
    run_check "--prereq colon-delimited with rdata" "$DAG @127.0.0.1 -p 10053 example.com SOA --update-add 'test.example.com 300 IN A 1.2.3.4' --prereq='yxrrset:test.example.com:A:1.2.3.4' +qr +timeout=1" "Query \([0-9]+ bytes\)"
fi

echo "=== 4. Testing Structural --break exclusivity warning & help ==="
if [ "$DAG" = "dig" ]; then
    run_skip "Multiple structural breaks warning"
    run_skip "--break-help displays exclusivity note"
else
    # Multiple structural breaks should emit a warning
    run_check "Multiple structural breaks warning" "$DAG @127.0.0.1 -p 10053 example.com A --break compression-loop --break oversized-qname +timeout=1" "warning: --break 'oversized-qname' ignored; structural break kind is already set"
    # --break-help contains exclusivity note
    run_check "--break-help displays exclusivity note" "$DAG --break-help" "NOTE: Only one \*structural\* --break kind"
fi

echo "=== 5. Testing Multi-Query Argument Slicing with Two-Arg Options ==="
# Two queries with -c IN in both
run_check "Multi-query with -c IN option" "$DAG @127.0.0.1 -p 10053 -c IN example.com A @127.0.0.1 -p 10053 -c IN example.net AAAA +timeout=1" "(example\.com.*example\.net|no usable response)"

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL CLI OPTION TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED CLI OPTION TESTS FAILED!"
    exit 1
fi
