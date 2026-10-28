#!/bin/sh
# ==============================================================================
# run_dag_discarded_hexdump_test.sh
#
# dag prints a hexdump of every response by default. A response that dag receives and then discards (short
# message, ID / question / opcode mismatch; RFC 5452 §9.1) is also dumped, right after its warning line:
#   ;; Discarded response (N bytes, UDP from 127.0.0.1#PORT):
# The dump follows the conditions of the normal response hexdump: not with +short, +yaml, +nohexdump,
# +nocomments. The discarded message is still discarded (exit code and retry behaviour are unchanged).
# Server: tests/mock_anomalous_dns_server.pl as a "type program" zone of karidns.
# ==============================================================================

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="${KARIDNS:-$BASE_DIR/karidns}"
DAG="${DAG:-$BASE_DIR/dag}"

[ -x "$KARIDNS" ] || make -C "$BASE_DIR" karidns >/dev/null 2>&1
[ -x "$DAG" ] || make -C "$BASE_DIR" dag >/dev/null 2>&1
if ! command -v perl >/dev/null 2>&1; then
    echo "SKIP: perl is not installed"
    exit 0
fi

TMP_DIR="$(mktemp -d /tmp/dag_discarded_hexdump.XXXXXX)"
PORT=$(kari_port 0 $((38000 + $$ % 5000)))
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cp "$SCRIPT_DIR/mock_anomalous_dns_server.pl" "$TMP_DIR/mock.pl"
chmod 755 "$TMP_DIR/mock.pl" "$TMP_DIR"
USER_OPT=""
PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi
cat > "$TMP_DIR/k.conf" <<CONF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT allow-program-zones yes; };
zone "anomaly.test" { type program; program "$TMP_DIR/mock.pl"; $PROG_USER_OPT
    program-max-failures 500; disable-auto-tc-flag yes; };
CONF
"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns did not start"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

FAILED=0
PASSED=0
OUT="$TMP_DIR/out.txt"
OPTS="+tries=1 +time=2 +nocookie +noedns"

run() { # scenario [extra options]
    sc="$1"; shift
    "$DAG" @127.0.0.1 -p "$PORT" "$sc.anomaly.test" A $OPTS "$@" > "$OUT" 2>&1
    CUR="$sc $*"
}
has() {
    if grep -qF -- "$1" "$OUT"; then return 0; fi
    echo "FAIL [$CUR]: expected '$1'"; sed 's/^/    | /' "$OUT"; FAILED=$((FAILED + 1)); return 1
}
hasnt() {
    if ! grep -qF -- "$1" "$OUT"; then return 0; fi
    echo "FAIL [$CUR]: unexpected '$1'"; sed 's/^/    | /' "$OUT"; FAILED=$((FAILED + 1)); return 1
}
# The first dump line after the heading holds the expected header octets ("0000  " + "xx " per octet).
dump_has() { # proto octets
    if grep -E -A1 -- "^;; Discarded response \([0-9]+ bytes, $1 from 127\.0\.0\.1#$PORT\):\$" "$OUT" | tail -n 1 | grep -qF -- "$2"; then
        return 0
    fi
    echo "FAIL [$CUR]: expected '$2' in the first dump line after the $1 heading"; sed 's/^/    | /' "$OUT"
    FAILED=$((FAILED + 1)); return 1
}
nodump() { hasnt ";; Discarded response"; }
ok() { PASSED=$((PASSED + 1)); echo "PASS [$CUR]"; }

REACH=";; no servers could be reached"

echo "=== dag discarded-response hexdump ==="

# UDP: the warning, then the dump of the discarded datagram; dag keeps waiting until the timeout
run id-mismatch;     has ";; Warning: ID mismatch: expected ID" && dump_has UDP " 84 00 00 01 00 01 " && has "$REACH" && ok
run query-mismatch;  has ";; ;; Question section mismatch: got mismatch-spoofed.anomaly.test/A/IN" && dump_has UDP " 84 00 00 01 00 01 " && has "$REACH" && ok
run opcode-status;   has ";; Warning: Opcode mismatch: expected QUERY, got STATUS" && dump_has UDP " 94 00 00 01 00 00 " && ok
run short-header;    has ";; Warning: short (< header size) message received" && has "(6 bytes, UDP from" && dump_has UDP " 84 00 00 01" && ok

# the dump directly follows the warning line
run id-mismatch
w=$(grep -nF ";; Warning: ID mismatch" "$OUT" | head -n 1 | cut -d: -f1)
d=$(grep -nF ";; Discarded response (" "$OUT" | head -n 1 | cut -d: -f1)
if [ -n "$w" ] && [ -n "$d" ] && [ "$d" -eq $((w + 1)) ]; then ok; else
    echo "FAIL [$CUR]: the dump does not directly follow the warning ($w, $d)"; FAILED=$((FAILED + 1)); fi

# the exit code is unchanged (dig: 9 when no server could be reached)
rc=0
"$DAG" @127.0.0.1 -p "$PORT" id-mismatch.anomaly.test A $OPTS > /dev/null 2>&1 || rc=$?
CUR="id-mismatch exit code"
if [ "$rc" -eq 9 ]; then ok; else echo "FAIL [$CUR]: exit code $rc, expected 9"; FAILED=$((FAILED + 1)); fi

# TCP: the lookup is dropped (ID, question, short message) or waits for the next message (opcode)
run id-mismatch +tcp;    has ";; ERROR: ID mismatch: expected ID" && dump_has TCP " 84 00 00 01 00 01 " && ok
run query-mismatch +tcp; has ";; ;; Question section mismatch: got mismatch-spoofed.anomaly.test/A/IN" && dump_has TCP " 84 00 00 01 00 01 " && ok
run short-header +tcp;   has ";; ERROR: short (< header size) message" && has "(6 bytes, TCP from" && dump_has TCP " 84 00 00 01" && ok
run opcode-status +tcp;  has ";; Warning: Opcode mismatch: expected QUERY, got STATUS" && dump_has TCP " 94 00 00 01 00 00 " && ok

# the conditions of the normal response hexdump
for opt in +short +yaml +nohexdump +nocomments; do
    run id-mismatch $opt;       nodump && ok
    run id-mismatch +tcp $opt;  nodump && ok
done

# an answer that is used is not a discarded response
run normal;                     has "Got answer" && nodump && ok

echo "dag discarded hexdump: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: test_dag_discarded_hexdump"
exit 0
