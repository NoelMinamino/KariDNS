#!/bin/sh
# ==============================================================================
# run_karictl_reload_failure_test.sh
#
# Phase 12 (D-13, O-05, O-09, D-12, T-11, D-23): karictl reports what a reload did.
#  1. status: server values (version/host/CPUs), times without the broken ".%03d" (T-11)
#  2. reconfig / reload with a configuration error -> "ERROR configuration not applied", exit 3,
#     the running configuration keeps answering
#  3. reload with a zone file that cannot be read -> "ERROR configuration applied, but 1 zone(s)
#     failed to load: <zone>", exit 3, and the same line in the log
#  4. reconfig that changes port -> "OK (restart needed for: port)", exit 0, warning in the log
#  5. karictl reload <zone> for a zone written "type Master;" (D-23)
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/karictl" ] && [ -x "$ROOT_DIR/dag" ] || \
    make -C "$ROOT_DIR" karidns karictl dag

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

PORT=$((26000 + $$ % 4000))
TMP_DIR="/tmp/karictl_reload_failure_test_$$"
CTRL_SOCK="$TMP_DIR/control.sock"
SECRET="cmVsb2FkLWZhaWx1cmUtdGVzdC1zZWNyZXQta2V5LTA="
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi

for z in a.example b.example; do
cat > "$TMP_DIR/$z.zone" <<EOF
\$TTL 300
@ IN SOA ns1.$z. hostmaster.$z. ( 1 3600 600 86400 60 )
@ IN NS ns1.$z.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
EOF
done
chmod 644 "$TMP_DIR"/*.zone

write_conf() { # $1 = port, $2 = file of b.example, $3 = extra text
cat > "$TMP_DIR/karidns.conf" <<EOF
options { port $1; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "$SECRET"; };
zone "a.example" { type Master; file "$TMP_DIR/a.example.zone"; };
zone "b.example" { type primary; file "$2"; };
$3
EOF
chmod 644 "$TMP_DIR/karidns.conf"
}
write_conf "$PORT" "$TMP_DIR/b.example.zone" ""
printf 'socket "%s";\nkey "karictl" { algorithm "hmac-sha256"; secret "%s"; };\n' "$CTRL_SOCK" "$SECRET" > "$TMP_DIR/karictl.conf"
chmod 600 "$TMP_DIR/karictl.conf"

"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ] && [ ! -S "$CTRL_SOCK" ]; do sleep 0.1; i=$((i + 1)); done
if ! kill -0 "$SERVER_PID" 2>/dev/null || [ ! -S "$CTRL_SOCK" ]; then
    echo "FAIL: karidns did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi
ctl() { "$KARICTL" -f "$TMP_DIR/karictl.conf" "$@" 2>&1; }
answer() { "$DAG" @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump 2>/dev/null; }

echo "=== 1. status (D-12, T-11) ==="
out=$(ctl status); rc=$?
printf '%s\n' "$out" | head -6 | sed 's/^/    /'
want_ver=$("$KARIDNS" -v 2>/dev/null | awk '{print $2; exit}')
[ "$rc" -eq 0 ] && pass "status exit 0" || fail "status exit $rc"
printf '%s\n' "$out" | grep -q "^version: KariDNS $want_ver (Authoritative)$" && pass "server version" || fail "version line"
printf '%s\n' "$out" | grep -q "^running on $(uname -n): $(uname -s) $(uname -m) $(uname -r)$" && pass "host line" || fail "host line"
printf '%s\n' "$out" | grep -Eq '^boot time: [0-9]{2}-[A-Z][a-z]{2}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}$' && pass "boot time format" || fail "boot time format (T-11)"
printf '%s\n' "$out" | grep -Eq '^last configured: [0-9]{2}-[A-Z][a-z]{2}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}$' && pass "last configured format" || fail "last configured format (T-11)"
printf '%s\n' "$out" | grep -q "^CPUs found: $(sysctl -n hw.ncpu)$" && pass "CPU count" || fail "CPU count"

echo "=== 2. configuration error (D-13) ==="
cp "$TMP_DIR/karidns.conf" "$TMP_DIR/karidns.good"
echo 'options { serve-stale maybe; };' >> "$TMP_DIR/karidns.conf"
for cmd in reconfig reload; do
    out=$(ctl $cmd); rc=$?
    echo "    $cmd -> rc=$rc $out"
    [ "$rc" -eq 3 ] && pass "$cmd exit 3" || fail "$cmd exit $rc (expected 3)"
    case "$out" in "ERROR configuration not applied: "*) pass "$cmd reply";; *) fail "$cmd reply: $out";; esac
done
[ "$(answer www.a.example)" = "192.0.2.10" ] && pass "old configuration still answers" || fail "no answer after failed reload"

echo "=== 3. zone file that cannot be read (D-13) ==="
write_conf "$PORT" "$TMP_DIR/missing.zone" ""
out=$(ctl reload); rc=$?
echo "    reload -> rc=$rc $out"
[ "$rc" -eq 3 ] && pass "reload exit 3" || fail "reload exit $rc (expected 3)"
case "$out" in "ERROR configuration applied, but 1 zone(s) failed to load: b.example."*) pass "reply names the zone";; *) fail "reply: $out";; esac
sleep 0.3
grep -q "Configuration reloaded, but 1 zone(s) failed to load: b.example." "$TMP_DIR/karidns.log" && pass "logged" || fail "not logged"
[ "$(answer www.a.example)" = "192.0.2.10" ] && pass "other zone answers" || fail "other zone does not answer"
write_conf "$PORT" "$TMP_DIR/b.example.zone" ""
out=$(ctl reload); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "OK reloaded" ] && pass "fixed reload: OK reloaded" || fail "fixed reload rc=$rc $out"

echo "=== 4. restart-only setting (O-09) ==="
write_conf "$((PORT + 1))" "$TMP_DIR/b.example.zone" ""
out=$(ctl reconfig); rc=$?
echo "    reconfig -> rc=$rc $out"
[ "$rc" -eq 0 ] && [ "$out" = "OK (restart needed for: port)" ] && pass "restart note" || fail "reply: $out"
sleep 0.3
grep -q "changed settings take effect only after a restart: port" "$TMP_DIR/karidns.log" && pass "warning logged" || fail "warning not logged"
[ "$(answer www.a.example)" = "192.0.2.10" ] && pass "still listening on the old port" || fail "old port"

echo "=== 5. reload of a 'type Master;' zone (D-23) ==="
out=$(ctl reload a.example); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "OK reloaded" ] && pass "reload a.example" || fail "reload a.example rc=$rc $out"

if [ "$FAILED" -ne 0 ]; then
    echo "--- karidns log ---"; tail -30 "$TMP_DIR/karidns.log"
    echo "RESULT: $FAILED check(s) FAILED"; exit 1
fi
echo "RESULT: all checks passed"
exit 0
