#!/bin/sh
# X-13: `karictl reload <zone>` (and a full `karictl reload` of a changed file) of a tinydns zone
# runs inside the Capsicum sandbox.
# The tinydns parser used to stat() the data file by path for the SOA serial (file mtime);
# in capability mode that is ECAPMODE, PROC_TRAPCAP turned it into SIGTRAP and the server stopped.
# Checks: the reload succeeds, the new record is answered, the SOA serial is the file mtime,
# the server is still running, and (when ktrace is available) no ECAPMODE/TRAP_CAP in the trace.
set -u
. "$(dirname "$0")/lib_proc.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="$BIN_DIR/karidns"
KARICTL="$BIN_DIR/karictl"
DAG="$BIN_DIR/dag"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$DAG" ] || (cd "$BASE_DIR" && make karidns karictl dag) || exit 1

TMP_DIR="$(mktemp -d /tmp/karidns_tinyreload.XXXXXX)"
chmod 755 "$TMP_DIR"
PORT=$((31000 + $$ % 3000))
SERVER_PID=""
FAILED=0

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        sleep 0.5 2>/dev/null || true
        kari_kill_tree "$SERVER_PID"
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

ok()   { echo "[OK] $1"; }
fail() { echo "[FAIL] $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
fi
SECRET=$(openssl rand -base64 32)
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$TMP_DIR/c.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "tiny.test" { type master; file "$TMP_DIR/tiny.data"; file-format tinydns; };
EOF
cp "$TMP_DIR/k.conf" "$TMP_DIR/c.conf"
chmod 600 "$TMP_DIR/c.conf"
chmod 644 "$TMP_DIR/k.conf"
printf '.tiny.test:192.0.2.1:a:300\n+www.tiny.test:192.0.2.3:300\n' > "$TMP_DIR/tiny.data"
chmod 644 "$TMP_DIR/tiny.data"

TRACE=""
if command -v ktrace >/dev/null 2>&1 && command -v kdump >/dev/null 2>&1; then
    TRACE="$TMP_DIR/kt.out"
    ktrace -i -f "$TRACE" "$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
else
    "$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
fi
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" www.tiny.test A @127.0.0.1 -p "$PORT" +short +time=1 +tries=1 2>/dev/null | grep -q '^192\.0\.2\.3$' && break
    sleep 0.1; i=$((i + 1))
done
if "$DAG" www.tiny.test A @127.0.0.1 -p "$PORT" +short +time=2 +tries=1 | grep -q '^192\.0\.2\.3$'; then
    ok "tinydns zone loaded"
else
    fail "tinydns zone not answered at startup"; cat "$TMP_DIR/server.log"; exit 1
fi

# Change the data (and its mtime) and reload only this zone
sleep 1
printf '+www2.tiny.test:192.0.2.4:300\n' >> "$TMP_DIR/tiny.data"
MTIME=$(stat -f %m "$TMP_DIR/tiny.data" 2>/dev/null || stat -c %Y "$TMP_DIR/tiny.data")
OUT=$("$KARICTL" -f "$TMP_DIR/c.conf" reload tiny.test 2>&1); RC=$?
if [ "$RC" -eq 0 ]; then ok "karictl reload tiny.test succeeded"; else fail "karictl reload tiny.test rc=$RC: $OUT"; fi
sleep 0.5

if "$DAG" www2.tiny.test A @127.0.0.1 -p "$PORT" +short +time=2 +tries=1 | grep -q '^192\.0\.2\.4$'; then
    ok "record added before the reload is answered"
else
    fail "www2.tiny.test not answered after the targeted reload"
fi
SERIAL=$("$DAG" tiny.test SOA @127.0.0.1 -p "$PORT" +short +time=2 +tries=1 | awk '{print $3}')
if [ "$SERIAL" = "$MTIME" ]; then
    ok "SOA serial is the data file mtime ($MTIME)"
else
    fail "SOA serial '$SERIAL' is not the data file mtime '$MTIME'"
fi
if kill -0 "$SERVER_PID" 2>/dev/null && ! grep -q 'Terminating all children' "$TMP_DIR/server.log"; then
    ok "server still running"
else
    fail "server stopped after the targeted reload"
fi

# A full reload of a changed tinydns file goes through the same loader (it stopped the server too)
sleep 1
printf '+www3.tiny.test:192.0.2.5:300\n' >> "$TMP_DIR/tiny.data"
OUT=$("$KARICTL" -f "$TMP_DIR/c.conf" reload 2>&1); RC=$?
if [ "$RC" -eq 0 ]; then ok "karictl reload (full) succeeded"; else fail "karictl reload (full) rc=$RC: $OUT"; fi
sleep 0.5
if "$DAG" www3.tiny.test A @127.0.0.1 -p "$PORT" +short +time=2 +tries=1 | grep -q '^192\.0\.2\.5$' &&
   kill -0 "$SERVER_PID" 2>/dev/null && ! grep -q 'Terminating all children' "$TMP_DIR/server.log"; then
    ok "record added before the full reload is answered, server still running"
else
    fail "full reload of the changed tinydns zone"
fi

if [ -n "$TRACE" ]; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    sleep 1
    kari_kill_tree "$SERVER_PID"
    SERVER_PID=""
    if kdump -f "$TRACE" | grep -E 'ECAPMODE|TRAP_CAP|Not permitted in capability mode'; then
        fail "Capsicum violation in the trace"
    else
        ok "no ECAPMODE/TRAP_CAP in the trace"
    fi
else
    echo "SKIP: ktrace not available (trace check)"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "=== server log ==="; cat "$TMP_DIR/server.log"
    echo "FAILED: $FAILED check(s)"
    exit 1
fi
echo "PASSED: tinydns targeted reload (X-13)"
exit 0
