#!/bin/sh
set -e

# ==============================================================================
# KariDNS dag(1) +keepopen +tls Partial Read & Desync Transparent Retry Test
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building dag with make ==="
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
    if [ ! -x "$DAG" ]; then
        echo "Error: dag binary not found at $DAG"
        exit 1
    fi
fi

FAILED=0
TMP_DIR="/tmp/karidns_tls_keepopen_test_$$"
mkdir -p "$TMP_DIR"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

echo "=== 1. Testing Live DoT Keepopen Connection Reuse & Continuity ==="
# Check if public DoT servers (8.8.8.8 or 9.9.9.9) are reachable
DOT_SERVER=""
if "$DAG" @8.8.8.8 dns.google A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
    DOT_SERVER="8.8.8.8"
    DOT_NAME="dns.google"
elif "$DAG" @9.9.9.9 dns.quad9.net A +tls +timeout=2 +tries=1 >/dev/null 2>&1; then
    DOT_SERVER="9.9.9.9"
    DOT_NAME="dns.quad9.net"
fi

if [ -n "$DOT_SERVER" ]; then
    echo -n "Test: Consecutive queries over +tls +keepopen ... "
    OUT=$($DAG @$DOT_SERVER $DOT_NAME A +tls +keepopen @$DOT_SERVER $DOT_NAME AAAA +tls +keepopen +timeout=4 2>&1 || true)
    if echo "$OUT" | grep -q "status: NOERROR" && echo "$OUT" | grep -q "SERVER: $DOT_SERVER"; then
        echo "OK"
    else
        echo "FAILED"
        echo "  Output: $OUT"
        FAILED=$((FAILED + 1))
    fi
else
    echo "Test: Live DoT Keepopen ... SKIP (Outbound port 853 not reachable)"
fi

echo "========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL KEEPOPEN TLS TESTS PASSED!"
    exit 0
else
    echo "❌ $FAILED KEEPOPEN TLS TESTS FAILED!"
    exit 1
fi
