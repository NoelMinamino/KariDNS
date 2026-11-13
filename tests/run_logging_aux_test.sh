#!/bin/sh
# ==============================================================================
# tests/run_logging_aux_test.sh - the debug level and `logging { }` in every process of the server (0.7 M2)
# ==============================================================================
# The Backend owns karictl trace / notrace / reload; the manager (with the plugin supervisor and the loader's supervisor), the Frontend
# routers and the connect broker get the level and the channels from it (dns_log_state.h), karidns-dbloader gets the level (--debug at its
# start, KDB1 DEBUG later).  One server with a `severity dynamic` channel for `general` and `database`, a program zone and a SQLite3 zone:
#   T  trace 1: a debug 1 line of the manager, of a Frontend router, of the broker, of the plugin supervisor (a plugin started again) and of
#      the loader (its new level, a batch of karictl reload) reaches the channel
#   S  trace 2, the loader is killed: the new one comes up at level 2 (its first line, written before it talks to the Backend, says so; the
#      manager's line says --debug 2)
#   N  notrace: the same events (a plugin and the loader started again, a reload) leave no debug line, while their notice / info lines arrive
#   R  a reload that replaces the channel: the manager's, a router's and the broker's lines go to the new file (before 0.7 M2 they kept the
#      channels of the start-up); only their warnings and errors also reach the old one, the channel of the start (the floor)
#   F  a log file removed by hand is not made again by the manager (root): the lines of the manager are lost until a reload makes the file
#      again, as the run user, and then they arrive
# Needs root (the server drops to nobody, the loader runs as nobody and must be root-owned).  SKIP otherwise, and without the binaries,
# the SQLite3 driver, zone2sql, the sqlite3 tool or perl.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN_DIR:-$ROOT}"
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the server drops to nobody, the loader runs as nobody)"; exit 0; fi
for b in "$BIN/karidns" "$BIN/karictl" "$BIN/dag" "$BIN/karidns-dbloader" ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$BIN/karidns-dbloader" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_logaux.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
FAILS=0; PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "PASS: $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL: $1"; }
cleanup() {
    set +e
    kari_kill_tree "$SRV"
    kari_kill_conf "$T/k.conf"
    if [ "$FAILS" -ne 0 ]; then
        for f in "$T/k.log" "$LOGD/dyn.log" "$LOGD/dyn2.log"; do echo "--- $f (tail)"; tail -40 "$f" 2>/dev/null; done
    fi
    if [ -n "${KARI_KEEP_TMP:-}" ]; then echo "kept: $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PORT=$(kari_port 0 $((21000 + $$ % 20000)))
LOGD="$T/logs"; mkdir "$LOGD"; chmod 777 "$LOGD"
DYN="$LOGD/dyn.log"; DYN2="$LOGD/dyn2.log"
SECRET="bG9nZ2luZy1hdXgtdGVzdC1jb250cm9sLWtleS0wMA=="
PLUGIN="$ROOT/tests/plugins/supervised_plugin.pl"
chmod +x "$PLUGIN" 2>/dev/null || true
mkdir "$T/ev"; chmod 777 "$T/ev"

# ---------------------------------------------------------------- fixtures
mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
./tests/db/zone2sql --dialect sqlite3 tests/zones/example.com.zone 2>/dev/null | sqlite3 "$T/db/z.db"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$BIN/karidns-dbloader" "$T/karidns-dbloader"
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n' > "$T/file.zone"
printf 'socket "%s/ctl.sock";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T" "$SECRET" > "$T/karictl.conf"
chmod 600 "$T/karictl.conf"

conf() {   # conf CHANNEL-FILE
    cat > "$T/k.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    allow-program-zones yes;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; };
};
control-channel { socket "$T/ctl.sock"; algorithm hmac-sha256; secret "$SECRET"; };
logging {
    channel dyn { file "$1"; severity dynamic; print-category yes; print-severity yes; };
    category general { dyn; };
    category database { dyn; };
};
zone "file.test" { type primary; file "$T/file.zone"; };
zone "prog.example." { type program; program "$PLUGIN"; program-args { "192.0.2.50"; "$T/ev/192.0.2.50"; }; program-user "nobody"; };
EOF
}
ctl() { "$BIN/karictl" -s "$T/ctl.sock" -f "$T/karictl.conf" "$@" 2>&1; }
wl() { kari_wait_log "$1" "$2" "${3:-15}" "${4:-1}"; }          # wl FILE PATTERN [SECONDS] [COUNT]
cnt() { grep -c -- "$2" "$1" 2>/dev/null || true; }
debug_lines() { cnt "$1" ': debug [0-9]*: '; }
starts() { grep -c "^START " "$T/ev/192.0.2.50" 2>/dev/null || true; }
wait_starts() { _i=0; while [ $_i -lt 100 ]; do [ "$(starts)" -ge "$1" ] && return 0; sleep 0.2; _i=$((_i + 1)); done; return 1; }
kill_plugin() { pkill -f "supervised_plugin.pl 192.0.2.50" 2>/dev/null; }
kill_loader() { _lp=$(pgrep -P "$SRV" -f "karidns-dbloader -s 3" | head -1); [ -n "$_lp" ] && kill -KILL "$_lp"; }

# ================================================================ start
conf "$DYN"
"$BIN/karidns" -c "$T/k.conf" -f > "$T/k.log" 2>&1 &
SRV=$!
i=0; until ctl status 2>/dev/null | grep -q '^version:'; do i=$((i + 1)); [ $i -gt 60 ] && break; sleep 0.25; done
wl "$DYN" "database: info: \[DB\] loader connected" 20 && pass "start: the server and the loader are up" || fail "start: no loader"
wait_starts 1 && pass "start: the plugin of the program zone runs" || fail "start: no plugin"
[ "$(debug_lines "$DYN")" = 0 ] && pass "level 0: no debug line from any process" || fail "level 0: $(debug_lines "$DYN") debug line(s)"

# ================================================================ T: trace 1 reaches every process
echo "== T: trace 1"
ctl trace 1 | grep -q '^OK debug level is now 1$' || fail "T: trace 1"
wl "$DYN" 'general: debug 1: \[Logging\] Manager: debug level 1' && pass "T: the manager follows (its own debug 1 line)" || fail "T: no manager line"
wl "$DYN" 'general: debug 1: \[Logging\] Frontend 0: debug level 1' && pass "T: Frontend router 0 follows" || fail "T: no router 0 line"
NR=$(grep -c 'general: debug 1: \[Logging\] Frontend [0-9]*: debug level 1' "$DYN")
[ "$NR" -ge 1 ] && pass "T: $NR router(s) said so" || fail "T: routers"
wl "$DYN" 'general: debug 1: \[Logging\] Broker: debug level 1' && pass "T: the connect broker follows" || fail "T: no broker line"
wl "$DYN" 'database: debug 1: \[DB\] debug level 1 (was 0)' && pass "T: the loader follows (KDB1 DEBUG): database, debug 1" || fail "T: no loader line"
kill_plugin
wl "$DYN" "general: debug 1: \[Plugin\] zone '[^']*prog.example[^']*' in view '[^']*': start 2 " 20 &&
    pass "T: the plugin supervisor of the manager: a debug 1 line for the plugin started again" || fail "T: no plugin supervisor line"
ctl reload > /dev/null
wl "$DYN" 'database: debug 1: \[DB\] batch [0-9]* ([a-z]*): reading every view' && pass "T: a batch of the loader at debug 1 (karictl reload)" || fail "T: no batch line"
grep -q 'conninfo\|secret' "$DYN" && fail "T: a credential word in the log" || pass "T: nothing about credentials in the debug lines"

# ================================================================ S: a loader started while the level is 2 comes up at 2
echo "== S: a restarted loader"
ctl trace 2 > /dev/null
wl "$DYN" 'database: debug 1: \[DB\] debug level 2 (was 1)' || fail "S: the loader did not take level 2"
kill_loader
wl "$DYN" 'general: debug 1: \[Manager\] Database loader (pid [0-9]*, start 2): debug level 2' 30 && pass "S: the manager starts the new loader with the level in force" || fail "S: no manager start line"
wl "$DYN" 'database: debug 1: \[DB\] stream mode: .*debug level 2$' 30 && pass "S: the new loader is at level 2 from its first line (--debug 2)" || fail "S: the new loader's first line"
wl "$DYN" 'database: info: \[DB\] loader connected' 30 2 || fail "S: the new loader did not connect"

# ================================================================ N: notrace
echo "== N: notrace"
ctl notrace | grep -q '^OK debug level is now 0$' || fail "N: notrace"
wl "$DYN" 'general: notice: \[Control\] debug level is now 0' || fail "N: no notice of notrace"
D0=$(debug_lines "$DYN")
S0=$(starts)
kill_plugin
wait_starts $((S0 + 1)) || fail "N: the plugin was not started again"
wl "$DYN" "general: notice: \[Plugin\] zone '[^']*prog.example[^']*' in view '[^']*': starting the plugin again" 20 2 || fail "N: no notice of the plugin restart"
kill_loader
wl "$DYN" 'database: info: \[DB\] loader connected' 30 3 && pass "N: a loader started again at level 0 connects" || fail "N: the loader did not come back"
NB=$(cnt "$DYN" 'database: info: \[DB\] batch [0-9]* ([a-z]*) sent')
ctl reload > /dev/null
wl "$DYN" 'database: info: \[DB\] batch [0-9]* ([a-z]*) sent' 20 $((NB + 1)) || fail "N: no batch of the loader after the reload"
[ "$(debug_lines "$DYN")" = "$D0" ] && pass "N: after notrace no process wrote a debug line (plugin, loader and reload done)" ||
    { fail "N: debug lines after notrace"; grep ': debug [0-9]*: ' "$DYN" | tail -n +$((D0 + 1)); }

# ================================================================ R: a reload that replaces the channel
echo "== R: reload of logging"
conf "$DYN2"
out=$(ctl reload); echo "$out" | grep -q '^OK' || fail "R: reload: $out"
wl "$DYN2" 'general' 15 && pass "R: the new file has lines" || fail "R: nothing in the new file"
B0=$(wc -l < "$DYN")
ctl trace 1 > /dev/null
wl "$DYN2" 'general: debug 1: \[Logging\] Manager: debug level 1, logging configuration of the Backend taken' 15 && pass "R: the manager writes to the new channel" || fail "R: manager not in the new file"
wl "$DYN2" 'general: debug 1: \[Logging\] Frontend 0: debug level 1' && pass "R: router 0 writes to the new channel" || fail "R: router not in the new file"
wl "$DYN2" 'general: debug 1: \[Logging\] Broker: debug level 1' && pass "R: the broker writes to the new channel" || fail "R: broker not in the new file"
S0=$(starts)
kill_plugin
wait_starts $((S0 + 1)) || fail "R: the plugin was not started again"
wl "$DYN2" "general: notice: \[Plugin\] zone '[^']*prog.example[^']*' in view '[^']*': starting the plugin again" 20 && pass "R: a notice of the manager goes to the new channel" || fail "R: manager notice"
wl "$DYN2" 'database: debug 1: \[DB\] debug level 1 (was 0)' && pass "R: the loader's lines (logged by the manager) go to the new channel" || fail "R: loader not in the new file"
# 0.7: the floor (dns_log.c klog_record()): the warnings and errors of the manager, a router or the broker still reach the start's channel of
# their category, whatever the Backend hands over; nothing below warning does
OLD_NEW=$(tail -n +$((B0 + 1)) "$DYN")
if echo "$OLD_NEW" | grep -v -E '^(general|database): (warning|error|critical): ' | grep -q .; then
    fail "R: lines below warning in the old file after the reload"; echo "$OLD_NEW"
else pass "R: the old file got no line below warning after the reload"; fi
echo "$OLD_NEW" | grep -q "^general: warning: \[Plugin\] zone '[^']*prog.example[^']*' in view '[^']*': the plugin (pid [0-9]*) was killed by signal" &&
    pass "R: the manager's warning (the plugin was killed) still reaches the start's channel as well" || { fail "R: no warning of the manager in the start's file"; echo "$OLD_NEW"; }

# ================================================================ F: a removed file is not made again by the manager
echo "== F: a removed log file"
rm -f "$DYN2"
S0=$(starts)
kill_plugin
wait_starts $((S0 + 1)) || fail "F: the plugin was not started again"
[ ! -e "$DYN2" ] && pass "F: the manager (root) did not make the removed file again" || fail "F: $(ls -l "$DYN2")"
out=$(ctl reload); echo "$out" | grep -q '^OK' || fail "F: reload: $out"
wl "$DYN2" 'general' 15 || true
[ -f "$DYN2" ] && [ "$(stat -f %Su "$DYN2")" = nobody ] && pass "F: a reload makes it again, as the run user" || fail "F: after the reload: $(ls -l "$DYN2" 2>&1)"
S0=$(starts)
kill_plugin
wait_starts $((S0 + 1)) || fail "F: the plugin was not started again"
wl "$DYN2" "\[Plugin\] zone '[^']*prog.example[^']*' in view '[^']*': starting the plugin again" 20 && pass "F: and the manager's lines arrive in it again" || fail "F: no manager line after the reload"

echo "== $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
