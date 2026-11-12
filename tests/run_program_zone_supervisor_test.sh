#!/bin/sh
# ==============================================================================
# KariDNS type "program" zones: the RELOAD line (program-reload-line, 0.6.2)
#
#   - karictl reload and SIGHUP write "RELOAD" to a plugin whose zone has program-reload-line yes;
#   - a zone without it never gets the line (its plugin would exit on an unknown line, tests/plugins/supervised_plugin.pl).
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICTL="${BIN_DIR}/karictl"
DAG="${DAG:-$BIN_DIR/dag}"
PLUGIN="${BASE_DIR}/tests/plugins/supervised_plugin.pl"

for b in "$KARIDNS" "$KARICTL" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }

TMP_DIR="$(mktemp -d /tmp/karidns_program_sup.XXXXXX)"
SERVER_PID=""
cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$TMP_DIR/karidns.conf"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# the plugins run as nobody when the test runs as root: they must reach the plugin and write their event files
chmod 755 "$TMP_DIR"
mkdir "$TMP_DIR/ev"
chmod 777 "$TMP_DIR/ev"
chmod +x "$PLUGIN" 2>/dev/null || true

PORT=$(kari_port 0 $((29000 + $$ % 5000)))
FAILED=0
USER_OPT=""
PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi
SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"

pass() { echo "Test: $1 ... OK"; }
fail() {
    echo "Test: $1 ... FAILED"
    [ -n "${2:-}" ] && echo "  $2"
    FAILED=$((FAILED + 1))
}
# events NAME WHAT: how many WHAT lines the plugin of address NAME wrote
events() { grep -c "^$2 [0-9]* $1\$" "$TMP_DIR/ev/$1" 2>/dev/null || true; }
# wait_events NAME WHAT N [SECONDS]: wait until there are at least N
wait_events() {
    _we_i=0
    while [ "$_we_i" -lt $(( ${4:-10} * 5 )) ]; do
        [ "$(events "$1" "$2")" -ge "$3" ] && return 0
        sleep 0.2
        _we_i=$((_we_i + 1))
    done
    return 1
}
# answer NAME: the A answer for NAME (empty when there is none)
answer() { "$DAG" @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=2 +tries=1 2>/dev/null | head -1; }

# zone NAME ADDR [extra statements]: a program zone whose plugin answers ADDR and logs to ev/ADDR
zone() {
    cat << EOF
zone "$1" {
    type program;
    program "$PLUGIN";
    program-args { "$2"; "$TMP_DIR/ev/$2"; };
    $PROG_USER_OPT
    program-timeout 1000;
    program-max-failures 2;
    $3
};
EOF
}

write_conf() {
    {
        cat << EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    allow-program-zones yes;
};
control-channel {
    socket "$TMP_DIR/ctl.sock";
    algorithm hmac-sha256;
    secret "$SECRET";
};
EOF
        cat "$TMP_DIR/zones"
    } > "$TMP_DIR/karidns.conf"
}

cat << EOF > "$TMP_DIR/karictl.conf"
socket "$TMP_DIR/ctl.sock";
key "karictl" {
    algorithm hmac-sha256;
    secret "$SECRET";
};
EOF

{
    zone rl.example. 192.0.2.10 "program-reload-line yes;"
    zone norl.example. 192.0.2.11 "program-reload-line no;"
    zone plain.example. 192.0.2.12
} > "$TMP_DIR/zones"
write_conf

"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
for z in rl norl plain; do
    i=0
    while [ "$i" -lt 50 ] && [ -z "$(answer x.$z.example.)" ]; do sleep 0.2; i=$((i + 1)); done
done

echo "=== 1. The plugins answer ==="
[ "$(answer x.rl.example.)" = "192.0.2.10" ] && pass "rl.example answers" || fail "rl.example answers" "got '$(answer x.rl.example.)'"
[ "$(answer x.norl.example.)" = "192.0.2.11" ] && pass "norl.example answers" || fail "norl.example answers"
[ "$(answer x.plain.example.)" = "192.0.2.12" ] && pass "plain.example answers" || fail "plain.example answers"

echo "=== 2. karictl reload writes RELOAD only with program-reload-line yes ==="
"$KARICTL" -f "$TMP_DIR/karictl.conf" reload > "$TMP_DIR/ctl.out" 2>&1 || true
if wait_events 192.0.2.10 RELOAD 1; then pass "karictl reload: RELOAD reached rl.example"; else fail "karictl reload: RELOAD reached rl.example" "$(cat "$TMP_DIR/ctl.out")"; fi
echo "=== 3. SIGHUP to the manager does the same ==="
kill -HUP "$SERVER_PID"
if wait_events 192.0.2.10 RELOAD 2; then pass "SIGHUP: RELOAD reached rl.example"; else fail "SIGHUP: RELOAD reached rl.example"; fi
sleep 0.5
[ "$(events 192.0.2.10 START)" = "1" ] && pass "rl.example's plugin was not restarted" || fail "rl.example's plugin was not restarted"
for a in 192.0.2.11 192.0.2.12; do
    if [ "$(events $a RELOAD)" = "0" ] && [ "$(events $a UNKNOWN)" = "0" ] && [ "$(events $a START)" = "1" ]; then
        pass "no RELOAD line without program-reload-line ($a)"
    else
        fail "no RELOAD line without program-reload-line ($a)" "$(cat "$TMP_DIR/ev/$a" 2>/dev/null)"
    fi
done
[ "$(answer y.rl.example.)" = "192.0.2.10" ] && pass "rl.example answers after the RELOAD lines" || fail "rl.example answers after the RELOAD lines"
[ "$(answer y.norl.example.)" = "192.0.2.11" ] && pass "norl.example answers after the reloads" || fail "norl.example answers after the reloads"

if [ "$FAILED" -gt 0 ]; then
    echo "=== Server log ==="
    cat "$TMP_DIR/karidns.log"
    for f in "$TMP_DIR"/ev/*; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done
fi
kari_kill_tree "$SERVER_PID"
SERVER_PID=""

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "ALL PROGRAM ZONE SUPERVISOR TESTS PASSED"
    exit 0
fi
echo "$FAILED PROGRAM ZONE SUPERVISOR TEST(S) FAILED"
exit 1
