#!/bin/sh
# CI smoke test of dag on every platform (FreeBSD, Linux, macOS, Windows MinGW).
# X-09: queries tests/mock_dns_server.pl on the loopback address only; no real domain names and no public
# resolvers (CLAUDE.md section 6), so the CI does not depend on the Internet.
#
# Usage: sh tests/run_ci_dag_smoke.sh          (DAG=./dag.exe on Windows, PORT=10553 by default)
set -u
cd "$(dirname "$0")/.."

DAG="${DAG:-./dag}"
PORT="${PORT:-10553}"
LOG="mock_ci_smoke.log"

perl tests/mock_dns_server.pl --port "$PORT" > "$LOG" 2>&1 &
MOCK_PID=$!
trap 'kill "$MOCK_PID" 2>/dev/null' EXIT INT TERM

i=0
until "$DAG" ttl-test.example A @127.0.0.1 -p "$PORT" +short +time=1 +tries=1 >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 20 ]; then
        echo "FAIL: mock_dns_server.pl did not answer"
        cat "$LOG"
        exit 1
    fi
    sleep 1
done

FAILED=0
check() { # description pattern dag-arguments...
    desc="$1"; pattern="$2"; shift 2
    echo "Testing $desc..."
    out=$("$DAG" "$@" +nohexdump 2>&1)
    rc=$?
    printf '%s\n' "$out"
    if [ "$rc" -ne 0 ] || ! printf '%s\n' "$out" | grep -q -- "$pattern"; then
        echo "FAIL: $desc (exit code $rc, expected '$pattern')"
        FAILED=1
    fi
}

check "UDP query" "status: NOERROR" ttl-test.example A @127.0.0.1 -p "$PORT"
check "TCP query" "(TCP)" ttl-test.example A @127.0.0.1 -p "$PORT" +tcp
check "multiple UDP queries" "MULTI-SERVER COMPARISON" ttl-test.example A @127.0.0.1,127.0.0.1 -p "$PORT"
check "multiple TCP queries" "MULTI-SERVER COMPARISON" ttl-test.example A @127.0.0.1,127.0.0.1 -p "$PORT" +tcp
check "zone transfer" "XFR size" axfr.example AXFR @127.0.0.1 -p "$PORT"

if [ "$FAILED" -ne 0 ]; then
    echo "FAIL: dag CI smoke test"
    exit 1
fi
echo "PASS: dag CI smoke test"
exit 0
