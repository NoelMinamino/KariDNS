#!/bin/sh
set -e

# Test: Regression test for --update-del type omission (RFC 2136 §2.5.2)
# Ensures `dag --update-del <name>` without type generates TYPE=ANY, CLASS=ANY, TTL=0, RDLEN=0

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DAG="${1:-${DAG:-$BIN_DIR/dag}}"
if [ "$DAG" = "dig" ] || [ "$(basename "$DAG")" = "dig" ]; then
    DAG="dig"
    if ! command -v "$DAG" >/dev/null 2>&1; then
        echo "Error: dig executable not found"
        exit 1
    fi
else
    if [ ! -x "$DAG" ]; then
        DAG="$BIN_DIR/dag"
    fi
    if [ ! -x "$DAG" ]; then
        DAG="./dag"
    fi
    if [ ! -x "$DAG" ]; then
        echo "Error: dag executable not found at $DAG"
        exit 1
    fi
fi

echo "Running: test_dag_update_del_no_type"

# 1. Wire format verification: TYPE=255 (00 ff), CLASS=255 (00 ff), TTL=0 (00 00 00 00), RDLENGTH=0 (00 00)
OUT=$($DAG @127.0.0.1 example.com SOA --update-del 'host.example.com' +qr +timeout=1 2>&1 || true)
echo "$OUT" | grep -q -i "ff 00 ff 00 00 00 00 00  00" || {
    echo "FAIL: Expected wire format 00 ff 00 ff 00 00 00 00 00 00 for --update-del without type"
    echo "$OUT"
    exit 1
}

# 2. Separate argument syntax verification
OUT_SEP=$($DAG @127.0.0.1 example.com SOA --update-del host.example.com +qr +timeout=1 2>&1 || true)
echo "$OUT_SEP" | grep -q -i "ff 00 ff 00 00 00 00 00  00" || {
    echo "FAIL: Expected wire format for separate argument --update-del host.example.com"
    echo "$OUT_SEP"
    exit 1
}

# 3. Explicit type syntax verification: TYPE=1 (00 01), CLASS=255 (00 ff), TTL=0 (00 00 00 00), RDLENGTH=0 (00 00)
OUT_TYPE=$($DAG @127.0.0.1 example.com SOA --update-del 'host.example.com A' +qr +timeout=1 2>&1 || true)
echo "$OUT_TYPE" | grep -q -i "01 00 ff 00 00 00 00 00  00" || {
    echo "FAIL: Expected wire format 00 01 00 ff 00 00 00 00 00 00 for --update-del with explicit type A"
    echo "$OUT_TYPE"
    exit 1
}

echo "PASS: test_dag_update_del_no_type"
exit 0
