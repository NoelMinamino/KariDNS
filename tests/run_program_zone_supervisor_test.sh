#!/bin/sh
# ==============================================================================
# KariDNS type "program" zones 0.6.2: the RELOAD line and the plugin supervisor of the manager
#
#   - karictl reload and SIGHUP write "RELOAD" to a plugin whose zone has program-reload-line yes, and do not restart it;
#   - a zone without it never gets the line (its plugin would exit on an unknown line, tests/plugins/supervised_plugin.pl);
#   - a plugin that exits after N queries is started again and answers;
#   - a plugin that exits at once is started again after 1, 2, 4 s (the backoff), not in a loop;
#   - a plugin that reaches program-max-failures is killed and started again;
#   - a reload: a changed program-args gets a new plugin (the old one ends), a new zone answers, a removed zone's plugin ends;
#   - karictl reload <zone> on one program zone: settings changed -> a new plugin (a replacement the manager refused is asked for again);
#     the same settings with program-reload-line yes -> the RELOAD line; the same settings without it -> a new plugin with them (the old
#     one answers until it is up); an unknown zone is an error; a zone that is not a program zone and the other plugins are not touched;
#   - the plugins end with the server.
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
    [ -n "$SERVER_PID" ] && kill -CONT "$SERVER_PID" 2>/dev/null   # (step 8 stops the manager for a while)
    kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$TMP_DIR/karidns.conf"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# the plugins run as nobody when the test runs as root: they must reach the plugin and write their event files
chmod 755 "$TMP_DIR"
mkdir "$TMP_DIR/ev"
chmod 777 "$TMP_DIR/ev"
cat << EOF > "$TMP_DIR/file.zone"
\$TTL 60
@ IN SOA ns.file.example. h.file.example. 1 3600 600 86400 60
@ IN NS ns.file.example.
ns IN A 192.0.2.1
EOF
chmod 644 "$TMP_DIR/file.zone"
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
answer() { "$DAG" @127.0.0.1 -p "$PORT" "$1" A +short +nohexdump +time=2 +tries=1 2>/dev/null | grep -E '^[0-9.]+$' | head -1; }

# zone NAME ADDR [extra statements] [EXIT_AFTER]: a program zone whose plugin answers ADDR and logs to ev/ADDR
zone() {
    _z_more=""
    [ -n "${4:-}" ] && _z_more=" \"$4\";"
    cat << EOF
zone "$1" {
    type program;
    program "$PLUGIN";
    program-args { "$2"; "$TMP_DIR/ev/$2";$_z_more };
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

base_zones() {
    zone rl.example. 192.0.2.10 "program-reload-line yes;"
    zone norl.example. 192.0.2.11 "program-reload-line no;"
    zone plain.example. 192.0.2.12
    zone exit.example. 192.0.2.20 "" 2
    zone hang.example. 192.0.2.21 "" hang
    cat << EOF
zone "quick.example." {
    type program;
    program "/usr/bin/true";
    $PROG_USER_OPT
};
zone "file.example." {
    type master;
    file "$TMP_DIR/file.zone";
};
EOF
}
{
    base_zones
    zone chg.example. 192.0.2.30
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

# pid NAME: the pid of the newest start of the plugin of address NAME
pid() { grep "^START [0-9]* $1\$" "$TMP_DIR/ev/$1" 2>/dev/null | tail -1 | awk '{print $2}'; }
# gone PID [SECONDS]: wait until the process has ended
gone() {
    _g_i=0
    while [ "$_g_i" -lt $(( ${2:-10} * 5 )) ]; do
        kill -0 "$1" 2>/dev/null || return 0
        sleep 0.2
        _g_i=$((_g_i + 1))
    done
    return 1
}
# answer_is NAME ADDR [SECONDS]: wait until NAME answers ADDR
answer_is() {
    _a_i=0
    while [ "$_a_i" -lt $(( ${3:-10} * 2 )) ]; do
        [ "$(answer "$1")" = "$2" ] && return 0
        sleep 0.5
        _a_i=$((_a_i + 1))
    done
    return 1
}

echo "=== 4. A plugin that exits after two queries is started again ==="
answer a.exit.example. >/dev/null
answer b.exit.example. >/dev/null
if wait_events 192.0.2.20 EXIT 1 && wait_events 192.0.2.20 START 2 5; then pass "exit.example's plugin was started again"; else fail "exit.example's plugin was started again" "$(cat "$TMP_DIR/ev/192.0.2.20" 2>/dev/null)"; fi
if answer_is c.exit.example. 192.0.2.20 5; then pass "exit.example answers after the restart"; else fail "exit.example answers after the restart"; fi

echo "=== 5. A plugin that exits at once: the backoff ==="
# quick.example's plugin (/usr/bin/true) has been exiting since the start: the waits 1, 2, 4 s, never a loop
sleep 4
q_starts=$(grep -c "Spawned program zone 'quick.example.'" "$TMP_DIR/karidns.log" || true)
waits=$(grep "zone 'quick.example.' in view '[^']*': starting the plugin again in" "$TMP_DIR/karidns.log" | sed 's/.* in \([0-9]*\) s$/\1/' | tr '\n' ' ')
case "$waits" in
    "1 2 4 "*) pass "the waits are 1, 2, 4 ... s ($waits)" ;;
    *) fail "the waits are 1, 2, 4 ... s" "got '$waits'" ;;
esac
if [ "$q_starts" -ge 3 ] && [ "$q_starts" -le 6 ]; then pass "a few starts, no loop ($q_starts)"; else fail "a few starts, no loop" "$q_starts starts"; fi
st=$("$DAG" @127.0.0.1 -p "$PORT" x.quick.example. A +nohexdump +time=2 +tries=1 2>/dev/null | grep -o "status: [A-Z]*")
[ "$st" = "status: SERVFAIL" ] && pass "quick.example answers SERVFAIL meanwhile" || fail "quick.example answers SERVFAIL meanwhile" "$st"

echo "=== 6. program-max-failures: the plugin is killed and started again ==="
hang_pid=$(pid 192.0.2.21)
answer a.hang.example. >/dev/null
answer b.hang.example. >/dev/null
if grep -q "zone 'hang.example.' exceeded max failures" "$TMP_DIR/karidns.log" && gone "$hang_pid" 5; then
    pass "hang.example's plugin was killed at program-max-failures"
else
    fail "hang.example's plugin was killed at program-max-failures" "pid $hang_pid"
fi
if wait_events 192.0.2.21 START 2 5; then pass "hang.example's plugin was started again"; else fail "hang.example's plugin was started again"; fi

echo "=== 7. Reload: a changed program-args, a new zone, a removed zone ==="
rl_pid=$(pid 192.0.2.10)
chg_pid=$(pid 192.0.2.30)
plain_pid=$(pid 192.0.2.12)
{
    base_zones | awk '/^zone "plain.example."/{skip=1} skip&&/^};/{skip=0; next} !skip'
    zone chg.example. 192.0.2.31
    zone add.example. 192.0.2.40
} > "$TMP_DIR/zones"
write_conf
"$KARICTL" -f "$TMP_DIR/karictl.conf" reload > "$TMP_DIR/ctl.out" 2>&1 || true
grep -q "restart needed" "$TMP_DIR/ctl.out" && fail "the reload asks for no restart" "$(cat "$TMP_DIR/ctl.out")" || pass "the reload asks for no restart"
if answer_is x.chg.example. 192.0.2.31; then pass "chg.example answers with the new program-args"; else fail "chg.example answers with the new program-args" "got '$(answer x.chg.example.)'"; fi
if [ -n "$chg_pid" ] && gone "$chg_pid"; then pass "chg.example's old plugin ended"; else fail "chg.example's old plugin ended" "pid $chg_pid"; fi
if answer_is x.add.example. 192.0.2.40; then pass "add.example (added by the reload) answers"; else fail "add.example (added by the reload) answers"; fi
if [ -n "$plain_pid" ] && gone "$plain_pid"; then pass "plain.example's plugin ended with its zone"; else fail "plain.example's plugin ended with its zone" "pid $plain_pid"; fi
[ "$(answer x.plain.example.)" = "" ] && pass "plain.example is gone" || fail "plain.example is gone"
if [ "$(pid 192.0.2.10)" = "$rl_pid" ] && kill -0 "$rl_pid" 2>/dev/null; then pass "rl.example's unchanged plugin kept running"; else fail "rl.example's unchanged plugin kept running"; fi
[ "$(events 192.0.2.10 RELOAD)" -ge 3 ] && pass "rl.example got the RELOAD line of this reload too" || fail "rl.example got the RELOAD line of this reload too"

echo "=== 8. karictl reload <zone> on a program zone ==="
# ctl_out ARGS...: run karictl; the reply is in ctl.out, the exit status in $rc
ctl_out() { rc=0; "$KARICTL" -f "$TMP_DIR/karictl.conf" "$@" > "$TMP_DIR/ctl.out" 2>&1 || rc=$?; }
# zones_with_chg ADDR: the configuration of step 7 with chg.example's plugin answering ADDR
zones_with_chg() {
    {
        base_zones | awk '/^zone "plain.example."/{skip=1} skip&&/^};/{skip=0; next} !skip'
        zone chg.example. "$1"
        zone add.example. 192.0.2.40
    } > "$TMP_DIR/zones"
    write_conf
}
rl_pid=$(pid 192.0.2.10)
rl_n=$(events 192.0.2.10 RELOAD)
ctl_out reload rl.example.
if [ "$rc" = "0" ] && grep -q "^OK reloaded (program zone: RELOAD line sent" "$TMP_DIR/ctl.out"; then pass "reload rl.example.: the reply says the RELOAD line was sent"; else fail "reload rl.example.: the reply says the RELOAD line was sent" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
if wait_events 192.0.2.10 RELOAD $((rl_n + 1)); then pass "reload rl.example.: the plugin got the RELOAD line"; else fail "reload rl.example.: the plugin got the RELOAD line"; fi
sleep 0.5
if [ "$(events 192.0.2.10 RELOAD)" = "$((rl_n + 1))" ] && [ "$(pid 192.0.2.10)" = "$rl_pid" ] && kill -0 "$rl_pid" 2>/dev/null; then pass "reload rl.example.: one line, the plugin was not restarted"; else fail "reload rl.example.: one line, the plugin was not restarted"; fi
[ "$(answer y.rl.example.)" = "192.0.2.10" ] && pass "rl.example answers after the targeted reload" || fail "rl.example answers after the targeted reload"

# no program-reload-line, the same settings: a new plugin replaces the old one, which answers until the new one is up
norl_pid=$(pid 192.0.2.11)
ctl_out reload norl.example.
if [ "$rc" = "0" ] && grep -q "^OK reloaded (program zone: no program-reload-line; a new plugin with the same settings was asked for" "$TMP_DIR/ctl.out"; then pass "reload norl.example.: the reply says a new plugin with the same settings was asked for"; else fail "reload norl.example.: the reply says a new plugin with the same settings was asked for" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
lost=0
k=0
while [ "$k" -lt 20 ]; do
    [ "$(answer q$k.norl.example.)" = "192.0.2.11" ] || lost=$((lost + 1))
    k=$((k + 1))
done
[ "$lost" = "0" ] && pass "reload norl.example.: every query was answered during the switch" || fail "reload norl.example.: every query was answered during the switch" "$lost of 20 lost"
if wait_events 192.0.2.11 START 2 && [ -n "$norl_pid" ] && gone "$norl_pid" 5; then pass "reload norl.example.: a new plugin started and the old one ended"; else fail "reload norl.example.: a new plugin started and the old one ended" "$(cat "$TMP_DIR/ev/192.0.2.11" 2>/dev/null)"; fi
if [ "$(events 192.0.2.11 RELOAD)" = "0" ] && [ "$(events 192.0.2.11 UNKNOWN)" = "0" ] && [ "$(events 192.0.2.11 START)" = "2" ]; then pass "reload norl.example.: no RELOAD line, one new plugin"; else fail "reload norl.example.: no RELOAD line, one new plugin" "$(cat "$TMP_DIR/ev/192.0.2.11" 2>/dev/null)"; fi
[ "$(answer z.norl.example.)" = "192.0.2.11" ] && pass "norl.example answers from the new plugin" || fail "norl.example answers from the new plugin"
[ "$(events 192.0.2.10 RELOAD)" = "$((rl_n + 1))" ] && pass "reload norl.example.: the plugin of the other zone got no line" || fail "reload norl.example.: the plugin of the other zone got no line"

ctl_out reload nosuch.example.
if [ "$rc" = "3" ] && grep -q "ERROR zone not found" "$TMP_DIR/ctl.out"; then pass "reload of an unknown zone: ERROR zone not found, exit 3"; else fail "reload of an unknown zone: ERROR zone not found, exit 3" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
# a zone that is not a program zone: as before, and no plugin is touched
rl_n=$(events 192.0.2.10 RELOAD)
ctl_out reload file.example.
if [ "$rc" = "0" ] && [ "$(tail -n 1 "$TMP_DIR/ctl.out")" = "OK reloaded" ]; then pass "reload file.example. (master zone): OK reloaded, as before"; else fail "reload file.example. (master zone): OK reloaded, as before" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
sleep 0.5
if [ "$(events 192.0.2.10 RELOAD)" = "$rl_n" ] && [ "$(events 192.0.2.11 START)" = "2" ]; then pass "reload of a master zone touched no plugin"; else fail "reload of a master zone touched no plugin"; fi

# an edited program-args: reconfig (the configuration only) already replaces the plugin; a reload of the zone after it (no program-reload-line,
# the same settings) starts one more
chg_pid=$(pid 192.0.2.31)
zones_with_chg 192.0.2.32
ctl_out reconfig
if answer_is x.chg.example. 192.0.2.32 && [ -n "$chg_pid" ] && gone "$chg_pid"; then pass "reconfig replaced chg.example's plugin (program-args edited)"; else fail "reconfig replaced chg.example's plugin (program-args edited)" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
chg_pid=$(pid 192.0.2.32)
ctl_out reload chg.example.
if [ "$rc" = "0" ] && grep -q "^OK reloaded (program zone: no program-reload-line; a new plugin with the same settings" "$TMP_DIR/ctl.out"; then pass "reload chg.example. after the reconfig: restarted with the same settings"; else fail "reload chg.example. after the reconfig: restarted with the same settings" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
if wait_events 192.0.2.32 START 2 && gone "$chg_pid" 5 && answer_is y.chg.example. 192.0.2.32; then pass "reload chg.example.: the plugin was replaced by one with the same settings"; else fail "reload chg.example.: the plugin was replaced by one with the same settings" "$(cat "$TMP_DIR/ev/192.0.2.32" 2>/dev/null)"; fi
sleep 0.5
chg_pid=$(pid 192.0.2.32)

# a replacement the manager refused: the manager is stopped while the configuration changes twice, so that it reads the second edit
# for the START of the first ("not the ones the server loaded"); the zone keeps its running plugin; restoring the first edit and
# reloading the zone asks for the plugin again at once
sleep 1.2
refused0=$(grep -c "are not the ones the server loaded" "$TMP_DIR/karidns.log" || true)
kill -STOP "$SERVER_PID"
zones_with_chg 192.0.2.33
ctl_out reconfig
[ "$rc" = "0" ] || fail "reconfig while the manager is stopped" "rc $rc: $(cat "$TMP_DIR/ctl.out")"
zones_with_chg 192.0.2.34
kill -CONT "$SERVER_PID"
i=0
while [ "$i" -lt 50 ] && [ "$(grep -c "are not the ones the server loaded" "$TMP_DIR/karidns.log" || true)" -le "$refused0" ]; do sleep 0.2; i=$((i + 1)); done
if [ "$(grep -c "are not the ones the server loaded" "$TMP_DIR/karidns.log" || true)" -gt "$refused0" ]; then pass "the manager refused the replacement (the file changed again)"; else fail "the manager refused the replacement (the file changed again)"; fi
zones_with_chg 192.0.2.33
ctl_out reload chg.example.
if [ "$rc" = "0" ] && grep -q "^OK reloaded (program zone: a plugin was asked for" "$TMP_DIR/ctl.out"; then pass "reload chg.example.: the reply says the plugin was asked for again"; else fail "reload chg.example.: the reply says the plugin was asked for again" "rc $rc: $(cat "$TMP_DIR/ctl.out")"; fi
if answer_is x.chg.example. 192.0.2.33 15 && gone "$chg_pid" 5; then pass "reload chg.example.: the new plugin answers and the old one ended"; else fail "reload chg.example.: the new plugin answers and the old one ended" "got '$(answer x.chg.example.)'"; fi
[ ! -e "$TMP_DIR/ev/192.0.2.34" ] && pass "the plugin of the edit the file no longer has was never started" || fail "the plugin of the edit the file no longer has was never started"

echo "=== 9. The plugins end with the server ==="
all_pids=""
for a in 192.0.2.10 192.0.2.11 192.0.2.20 192.0.2.21 192.0.2.33 192.0.2.40; do all_pids="$all_pids $(pid $a)"; done
kill -TERM "$SERVER_PID" 2>/dev/null
i=0
while [ "$i" -lt 50 ] && kill -0 "$SERVER_PID" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
left=""
for p in $all_pids; do gone "$p" 5 || left="$left $p"; done
[ -z "$left" ] && pass "no plugin is left after the server stopped" || fail "no plugin is left after the server stopped" "still running:$left"
grep -q "Terminating all children" "$TMP_DIR/karidns.log" && fail "no child of the server died on its own" || pass "no child of the server died on its own"

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
