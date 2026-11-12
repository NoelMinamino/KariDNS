#!/bin/sh
# ==============================================================================
# KariDNS type "program" zones 0.6.2: karictl reload <zone> with the zone in two views
#
#   - without a view name the command is refused ("zone exists in multiple views"), as for every other zone type;
#   - with a view name it writes the RELOAD line to the plugin of that view only (program-reload-line yes);
#   - a view that does not exist is an error.
# The plugins are the ones of tests/run_program_zone_supervisor_test.sh (tests/plugins/supervised_plugin.pl); only their event files are read.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="${BIN_DIR}/karidns"
KARICTL="${BIN_DIR}/karictl"
PLUGIN="${BASE_DIR}/tests/plugins/supervised_plugin.pl"

for b in "$KARIDNS" "$KARICTL"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }

TMP_DIR="$(mktemp -d /tmp/karidns_program_views.XXXXXX)"
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
events() { _ev_n=$(grep -c "^$2 [0-9]* $1\$" "$TMP_DIR/ev/$1" 2>/dev/null || true); echo "${_ev_n:-0}"; }
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
# ctl_out ARGS...: run karictl; the reply is in ctl.out, the exit status in $rc
ctl_out() { rc=0; "$KARICTL" -f "$TMP_DIR/karictl.conf" "$@" > "$TMP_DIR/ctl.out" 2>&1 || rc=$?; }

cat << EOF > "$TMP_DIR/karictl.conf"
socket "$TMP_DIR/ctl.sock";
key "karictl" {
    algorithm hmac-sha256;
    secret "$SECRET";
};
EOF

# view NAME CLIENTS ADDR: a view with the program zone z.example., whose plugin answers ADDR
view() {
    cat << EOF
view "$1" {
    match-clients { $2 };
    zone "z.example." {
        type program;
        program "$PLUGIN";
        program-args { "$3"; "$TMP_DIR/ev/$3"; };
        $PROG_USER_OPT
        program-timeout 1000;
        program-reload-line yes;
    };
};
EOF
}
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
    view a "127.0.0.1;" 192.0.2.10
    view b "any;" 192.0.2.11
} > "$TMP_DIR/karidns.conf"

"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!

echo "=== karictl reload <zone> with the zone in two views ==="
if wait_events 192.0.2.10 START 1 && wait_events 192.0.2.11 START 1; then pass "both plugins started"; else fail "both plugins started" "$(cat "$TMP_DIR/karidns.log")"; fi

ctl_out reload z.example.
if [ "$rc" = "3" ] && grep -q "zone exists in multiple views" "$TMP_DIR/ctl.out"; then pass "no view named: zone exists in multiple views, exit 3"; else fail "no view named: zone exists in multiple views, exit 3" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
sleep 0.5
if [ "$(events 192.0.2.10 RELOAD)" = "0" ] && [ "$(events 192.0.2.11 RELOAD)" = "0" ]; then pass "no plugin got a line"; else fail "no plugin got a line"; fi

ctl_out reload z.example. b
if [ "$rc" = "0" ] && grep -q "^OK reloaded (program zone: RELOAD line sent" "$TMP_DIR/ctl.out"; then pass "reload z.example. b: RELOAD line sent"; else fail "reload z.example. b: RELOAD line sent" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
if wait_events 192.0.2.11 RELOAD 1; then pass "the plugin of view b got the line"; else fail "the plugin of view b got the line"; fi
sleep 0.5
[ "$(events 192.0.2.10 RELOAD)" = "0" ] && pass "the plugin of view a got none" || fail "the plugin of view a got none"

ctl_out reload z.example. a
if [ "$rc" = "0" ] && wait_events 192.0.2.10 RELOAD 1; then pass "reload z.example. a: the plugin of view a got the line"; else fail "reload z.example. a: the plugin of view a got the line" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
sleep 0.5
if [ "$(events 192.0.2.11 RELOAD)" = "1" ] && [ "$(events 192.0.2.10 START)" = "1" ] && [ "$(events 192.0.2.11 START)" = "1" ]; then pass "one line each, no plugin restarted"; else fail "one line each, no plugin restarted"; fi

ctl_out reload z.example. c
if [ "$rc" = "3" ] && grep -q "^ERROR" "$TMP_DIR/ctl.out"; then pass "reload in a view that does not exist: ERROR, exit 3"; else fail "reload in a view that does not exist: ERROR, exit 3" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi

if [ "$FAILED" -gt 0 ]; then
    echo "=== Server log ==="
    cat "$TMP_DIR/karidns.log"
fi
kari_kill_tree "$SERVER_PID"
SERVER_PID=""

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "ALL PROGRAM ZONE RELOAD VIEWS TESTS PASSED"
    exit 0
fi
echo "$FAILED PROGRAM ZONE RELOAD VIEWS TEST(S) FAILED"
exit 1
