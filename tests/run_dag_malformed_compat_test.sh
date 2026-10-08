#!/bin/sh
# ==============================================================================
# run_dag_malformed_compat_test.sh
#
# T-12: dag reports malformed responses like dig 9.20 (BIND dns_message_parse()).
# KariDNS serves tests/mock_anomalous_dns_server.pl as a "type program" zone; every
# check below was written from the output of dig 9.20.29 for the same scenario
# (options +tries=1 +time=2 +nocookie +noedns, display +noall +answer +comments).
# When dig 9.20 is installed, every scenario is also compared with dig directly.
# ==============================================================================

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

TMP_DIR="$(mktemp -d /tmp/dag_malformed_compat.XXXXXX)"
PORT=$((33000 + $$ % 5000))
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# the program zone runs the mock directly, so it must be executable
cp "$SCRIPT_DIR/mock_anomalous_dns_server.pl" "$TMP_DIR/mock.pl"
chmod 755 "$TMP_DIR/mock.pl" "$TMP_DIR"
USER_OPT=""
PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT allow-program-zones yes; };
zone "anomaly.test" { type program; program "$TMP_DIR/mock.pl"; $PROG_USER_OPT
    program-max-failures 500; disable-auto-tc-flag yes; };
EOF
"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns did not start"
    cat "$TMP_DIR/karidns.log"
    exit 1
fi

OPTS="+tries=1 +time=2 +nocookie +noedns +noall +answer +comments"
FAILED=0
PASSED=0
OUT="$TMP_DIR/out.txt"

run() { # scenario [extra options]
    sc="$1"; shift
    "$DAG" @127.0.0.1 -p "$PORT" "$sc.anomaly.test" A $OPTS "$@" +nohexdump 2>&1 | sed -E 's/[[:space:]]+/ /g; s/ $//' > "$OUT"
    CUR="$sc $*"
}
has() { # fixed string expected in the output
    if grep -qF -- "$1" "$OUT"; then return 0; fi
    echo "FAIL [$CUR]: expected '$1'"; sed 's/^/    | /' "$OUT"; FAILED=$((FAILED + 1)); return 1
}
hasnt() {
    if ! grep -qF -- "$1" "$OUT"; then return 0; fi
    echo "FAIL [$CUR]: unexpected '$1'"; sed 's/^/    | /' "$OUT"; FAILED=$((FAILED + 1)); return 1
}
ok() { PASSED=$((PASSED + 1)); echo "PASS [$CUR]"; }

MAL="Message parser reports malformed message packet."
REACH=";; no servers could be reached"
TIMEOUT=";; communications error to 127.0.0.1#$PORT: timed out"

echo "=== dag malformed-response diagnostics (dig 9.20 compatible) ==="

# trailing data and count overflows: only "extra bytes", not malformed
run trailing-garbage;   has ";; WARNING: Message has 28 extra bytes at end" && hasnt "$MAL" && ok
run ancount-overflow;   has ";; WARNING: Message has 45 extra bytes at end" && hasnt "$MAL" && ok
run nscount-overflow;   has ";; WARNING: Message has 59 extra bytes at end" && hasnt "$MAL" && ok
# counts larger than the records present: malformed, the parsed records are shown
run ancount-underflow;  has "$MAL" && has "ancount-underflow.anomaly.test. 300 IN A 192.0.2.1" && hasnt "Got bad packet" && hasnt "extra bytes" && ok
# no question
run no-question;        has ";; missing question section" && has "no-question.anomaly.test. 300 IN A 192.0.2.1" && ok
run header-only;        has ";; missing question section" && has "QUERY: 0, ANSWER: 0" && ok
# answers that are ignored: dag keeps waiting until the timeout (RFC 5452 §9.1)
run id-mismatch;        has ";; Warning: ID mismatch: expected ID" && has "$TIMEOUT" && has "$REACH" && ok
run query-mismatch;     has ";; ;; Question section mismatch: got mismatch-spoofed.anomaly.test/A/IN" && has "$REACH" && hasnt "Got answer" && ok
run multi-question;     has "$MAL" && has ";; ;; Question section mismatch: got sub.multi-question.anomaly.test/AAAA/IN" && has "$REACH" && ok
run opcode-status;      has ";; Warning: Opcode mismatch: expected QUERY, got STATUS" && has "$REACH" && ok
run opcode-unassigned;  has ";; Warning: Opcode mismatch: expected QUERY, got RESERVED3" && ok
run short-header;       has ";; Warning: short (< header size) message received" && has "$REACH" && ok
run flag-no-qr;         has ";; Warning: query response not set" && has "Got answer" && ok
# names that make the message unusable
for sc in compression-loop compression-indirect-loop compression-forward-ptr; do
    run $sc;            has ";; Got bad packet: bad compression pointer" && has " bytes" && hasnt "Got answer" && ok
done
for sc in compression-bad-bits compression-misaligned label-overflow; do
    run $sc;            has ";; Got bad packet: bad label type" && hasnt "Got answer" && ok
done
run ptr-chain-name-overflow; has ";; Got bad packet: name too long" && hasnt "Got answer" && ok
# RDATA that does not fit its type: malformed, extra bytes from the start of the RDATA, record not shown
for spec in rdata-short-a:2 rdata-short-aaaa:8 rdata-soa-truncated:11 rdata-mx-truncated:2 rdata-txt-len-mismatch:10 rdata-svcb-overflow:9; do
    run "${spec%%:*}";  has "$MAL" && has ";; WARNING: Message has ${spec##*:} extra bytes at end" && hasnt "ANSWER SECTION" && ok
done
for spec in rdata-opt-truncated:8 opt-option-len-overflow:6; do
    run "${spec%%:*}";  has "$MAL" && has ";; WARNING: Message has ${spec##*:} extra bytes at end" && hasnt "OPT PSEUDOSECTION" && ok
done
# OPT records that are not the pseudo-RR
run multi-opt +additional; has "$MAL" && has "OPT PSEUDOSECTION" && has ";; ADDITIONAL SECTION:" && has ". 0 CLASS4096 OPT" && ok
run opt-in-answer;      has "$MAL" && has ". 0 CLASS4096 OPT" && hasnt "OPT PSEUDOSECTION" && ok
run opt-unknown-option; has '; OPT=65001: de ad be ef ("....")' && ok
# class differs from the question (Chaosnet A); query ID 0x0765 makes the RDATA pointer land on a valid name
run class-mismatch +qid=1893; has "$MAL" && has 'class-mismatch.anomaly.test. 300 CH A e\132\000\000\001\000\001. 1001' && ok
# RCODE and EDE names
run rcode-dsotypeni;    has "status: RESERVED11" && ok
run rcode-badkey;       has "status: ?17" && ok
run rcode-badcookie;    has "status: BADCOOKIE" && hasnt "retrying" && ok
run ede-all;            has "; EDE: 0 (Other): (EDE code 0 test description)" && has "; EDE: 19 (Stale NXDOMAIN Answer):" && has "; EDE: 25: (EDE code 25 test description)" && ok
# truncation: the UDP answer is not shown, the TCP answer is
run flag-tc;            has ";; Truncated, retrying in TCP mode." && hasnt "MULTI-SERVER COMPARISON" && ok
if [ "$(grep -c "Got answer" "$OUT")" -ne 1 ]; then
    echo "FAIL [flag-tc]: expected exactly one printed answer (the TCP one)"; FAILED=$((FAILED + 1))
fi

# X-43: over TCP dig 9.20 does not wait for another answer: an ID mismatch or a question mismatch ends the lookup
# (nothing else is printed, exit code 0); an opcode mismatch waits for the next message on the same connection
run_tcp() { # scenario [extra options]; sets RC
    sc="$1"; shift
    "$DAG" @127.0.0.1 -p "$PORT" "$sc.anomaly.test" A $OPTS +tcp "$@" +nohexdump > "$OUT.raw" 2>&1
    RC=$?
    sed -E 's/[[:space:]]+/ /g; s/ $//' "$OUT.raw" > "$OUT"
    CUR="$sc +tcp $*"
}
rc_is() {
    if [ "$RC" = "$1" ]; then return 0; fi
    echo "FAIL [$CUR]: exit code $RC, expected $1"; FAILED=$((FAILED + 1)); return 1
}
run_tcp id-mismatch;    has ";; ERROR: ID mismatch: expected ID" && hasnt "Got answer" && hasnt "<<>> dag" && rc_is 0 && ok
run_tcp query-mismatch; has ";; ;; Question section mismatch: got mismatch-spoofed.anomaly.test/A/IN" && hasnt "Got answer" && hasnt "$REACH" && rc_is 0 && ok
run_tcp multi-question; has "$MAL" && has ";; ;; Question section mismatch: got sub.multi-question.anomaly.test/AAAA/IN" && hasnt "Got answer" && rc_is 0 && ok
run_tcp opcode-status;  has ";; Warning: Opcode mismatch: expected QUERY, got STATUS" && has "$REACH" && hasnt "Got answer" && rc_is 9 && ok
run_tcp no-question;    has ";; missing question section" && has "Got answer" && rc_is 0 && ok
run_tcp short-header;   has ";; ERROR: short (< header size) message" && hasnt "Got bad packet" && hasnt "$REACH" && rc_is 0 && ok

# X-44: +short prints the parse diagnostics like dig and only the records that parsed; +yaml prints no ";;" lines,
# nothing for a message that cannot be parsed, and a DIG_ERROR document when no answer is accepted
run rdata-short-a +short;    has "$MAL" && hasnt "truncated" && hasnt "192.0.2" && ok
run compression-loop +short; has ";; Got bad packet: bad compression pointer" && has "18 bytes" && ok
run ancount-underflow +short; has "$MAL" && has "192.0.2.1" && ok
run compression-loop +yaml;  hasnt "type: MESSAGE" && hasnt ";;" && ok
[ -s "$OUT" ] && { echo "FAIL [$CUR]: expected no output"; sed 's/^/    | /' "$OUT"; FAILED=$((FAILED + 1)); }
run id-mismatch +yaml;       has "- type: DIG_ERROR" && has "no servers could be reached" && hasnt ";;" && ok
run rdata-opt-truncated +yaml; hasnt "OPT_PSEUDOSECTION" && hasnt "ADDITIONAL_SECTION" && has "ADDITIONAL: 1" && ok
run multi-opt +yaml +additional;      has "OPT_PSEUDOSECTION:" && has "ADDITIONAL_SECTION:" && has "- '. 0 CLASS4096 OPT '" && ok
run unclosed-label +yaml +question; has "QUESTION: 1" && hasnt "QUESTION_SECTION" && ok
run flag-z +yaml;            has "flags: qr aa" && has "MBZ: 0x4" && hasnt "flags: qr aa z" && ok
run flag-rd-ra +yaml;        has "type: RECURSIVE_RESPONSE" && ok
run flag-rd +yaml;           has "type: AUTH_RESPONSE" && ok
run rcode-badkey +yaml;      has "status: 17" && hasnt "status: ?17" && ok

# direct comparison with dig 9.20 (optional)
if command -v dig >/dev/null 2>&1 && dig -v 2>&1 | grep -q "DiG 9\.20\."; then
    echo "=== comparison with $(dig -v 2>&1) ==="
    norm() {
        sed -E -e 's/^; <<>> .*/; <<>> BANNER/' -e '/^;; global options/d' -e '/^; \([0-9] server found\)/d' \
            -e 's/(query_time|response_time): !!timestamp .*/\1: T/' \
            -e 's/id: [0-9]+/id: X/' -e 's/expected ID [0-9]+, got [0-9]+/expected ID X, got Y/' \
            -e 's/^(.. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..) .*/\1/' -e 's/^[0-9a-f]{2} [0-9a-f]{2} (8[0-9a-f] )/XX XX \1/' \
            -e 's/[[:space:]]+/ /g' -e 's/ $//' | grep -v '^$'
    }
    # Every scenario in the default format, +short, +yaml (X-44) and over TCP (X-43), exit codes included.
    # class-mismatch depends on the random query ID (its RDATA points into the header) and is checked above
    for mode in "" "+short" "+yaml" "+tcp"; do
        for sc in $(perl -ne 'print "$1\n" if /^\s+"  ([a-z0-9-]+)\.\$display_zone/' "$SCRIPT_DIR/mock_anomalous_dns_server.pl" |
                    grep -v '^drop$\|^what-is-my-ip$\|^tcp-max-65535$\|^class-mismatch$'); do
            dig @127.0.0.1 -p "$PORT" "$sc.anomaly.test" A $OPTS $mode > "$TMP_DIR/dig.raw" 2>&1
            drc=$?
            "$DAG" @127.0.0.1 -p "$PORT" "$sc.anomaly.test" A $OPTS $mode +nohexdump > "$TMP_DIR/dag.raw" 2>&1
            grc=$?
            norm < "$TMP_DIR/dig.raw" > "$TMP_DIR/dig.txt"
            norm < "$TMP_DIR/dag.raw" > "$TMP_DIR/dag.txt"
            CUR="$sc $mode (vs dig)"
            if cmp -s "$TMP_DIR/dig.txt" "$TMP_DIR/dag.txt" && [ "$drc" = "$grc" ]; then
                PASSED=$((PASSED + 1))
            else
                echo "FAIL [$CUR]: exit code dig=$drc dag=$grc"
                diff "$TMP_DIR/dig.txt" "$TMP_DIR/dag.txt" | head -20 | sed 's/^/    /'
                FAILED=$((FAILED + 1))
            fi
        done
    done
else
    echo "SKIP: dig 9.20 not installed; direct comparison not run"
fi

echo "========================================================="
echo "passed=$PASSED failed=$FAILED"
[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: dag malformed-response diagnostics match dig 9.20"
