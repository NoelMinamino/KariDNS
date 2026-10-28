#!/bin/sh
# ==============================================================================
# tests/run_logging_test.sh - logging { } and controls { } of BIND 9.20 (batch 6)
# ==============================================================================
#   L  lint: every "[Prefix]" a syslog() site of the server uses is in the category table of dns_log.c
#   K  karicheck conf: logging / controls / statistics-channels: warnings and errors with file:line; a stock BIND logging + controls passes
#   C  categories to channels in a running server: per-category files, severity filtering (info / warning / critical), print-time local /
#      iso8601-utc, print-category / print-severity, the category `default`, a stderr channel, a syslog channel (the server's stderr copy of
#      syslog() shows it), the null channel
#   R  reload: a change inside the directories opened at start-up applies at once; a file in a new directory is "restart needed" and the
#      logging in use stays; a configuration error keeps everything
#   Q  querylog yes / no, the queries category, queries to syslog when no channel is named, karictl status; rolling inside the sandbox
#      (size 3k versions 2), size without versions (the file stops), versions unlimited
#   X  controls { inet ...; } and statistics-channels in a running server: accepted with a warning, karictl works, a controls error rejects a reload
# Runs as root or as an ordinary user (the log directory is world-writable for the run user "nobody").
# ==============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$DAG" ] && [ -x "$KARICHECK" ] || make -C "$ROOT" karidns karictl dag karicheck >/dev/null || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-logging.XXXXXX")"
chmod 755 "$W"
LG="$W/logs"          # the log files: the one directory the run user "nobody" writes to (the control sockets are in $W: a privileged socket directory must not be writable)
mkdir "$LG"
chmod 777 "$LG"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
SECRET="bG9nZ2luZy10ZXN0LWNvbnRyb2wta2V5LTAwMDAwMA=="
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"

P1=$(kari_port 0) P2=$(kari_port 1) P3=$(kari_port 2)
SINK=$(kari_port 3)      # a NOTIFY receiver that never answers
CLOSED=$(kari_port 4)    # nothing listens here: connections are refused

PIDS=""
FAILS=0
PASSES=0
pass() { echo "PASS: $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

cleanup() {
    set +e
    kari_kill_tree $PIDS
    for n in c1 q1 q2 q3 q4 x1; do kari_kill_conf "$W/$n.conf"; done
    if [ "$FAILS" -ne 0 ]; then
        for f in c1 q1 q2 q3 q4 x1; do echo "--- $f.log (tail)"; tail -25 "$W/$f.log" 2>/dev/null; done
    fi
    if [ -n "${KARI_KEEP_TMP:-}" ]; then echo "kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT INT TERM

for p in $P1 $P2 $P3 $SINK $CLOSED; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

wait_grep() { # PATTERN FILE [SECONDS]
    _i=0
    while [ $_i -lt "${3:-10}" ]; do grep -q -- "$1" "$2" 2>/dev/null && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
wait_more() { # FILE LINES [SECONDS] : the file has more than LINES lines
    _i=0
    while [ $_i -lt "${3:-10}" ]; do [ "$(lines_of "$1")" -gt "$2" ] && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
wait_up() { # PORT [SECONDS] : the server answers
    _i=0
    while [ $_i -lt "${2:-15}" ]; do
        "$DAG" @127.0.0.1 -p "$1" pri.test SOA +short +nohexdump +time=1 +tries=1 2>/dev/null | grep -q . && return 0
        sleep 1; _i=$((_i + 1))
    done
    return 1
}
start() { # start NAME : karidns in the foreground on $W/NAME.conf, its stdout / stderr in $W/NAME.log
    "$KARIDNS" -f "$W/$1.conf" > "$W/$1.log" 2>&1 &
    PIDS="$PIDS $!"
    LAST_PID=$!
}
stop() { kari_kill_tree "$1"; PIDS=$(echo "$PIDS" | sed "s/ $1\$//; s/ $1 / /"); sleep 1; }
ctl() { n=$1; shift; "$KARICTL" -s "$W/$n.sock" -f "$W/ctl.conf" "$@" 2>&1; }
ctl_wait() { # NAME : the control channel answers (it is opened after the privileges are dropped)
    _i=0
    while [ $_i -lt 15 ]; do ctl "$1" status | grep -q "^version:" && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
ctlblock() { printf 'control-channel { socket "%s/%s.sock"; algorithm hmac-sha256; secret "%s"; };\n' "$W" "$1" "$SECRET"; }
zone() { # zone FILE ORIGIN SERIAL
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s 2 1 3600 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' "$2" "$3" > "$1"
}
size_of() { if [ -f "$1" ]; then wc -c < "$1" | tr -d ' '; else echo 0; fi; }
lines_of() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
query() { # query PORT NAME [dag args]
    _p=$1; _n=$2; shift 2
    "$DAG" @127.0.0.1 -p "$_p" "$_n" A +short +nohexdump +time=1 +tries=1 "$@" >/dev/null 2>&1
}

zone "$W/pri.zone" pri.test 1
printf '$TTL 300\n@ IN SOA ns1 hostmaster 1 2 1 3600 60\nthis is not a zone file line\n' > "$W/bad.zone"

# ------------------------------------------------------------------------------------------------ L: lint
bad=""
for p in $(grep -h -o '"\[[A-Za-z0-9]*[] ]' "$ROOT"/dns_*.c | grep -v '/dns_log.c' | tr -d '"[] ' | sort -u); do
    case "$p" in ERROR|WARNING|FATAL|INFO|CRITICAL|Prefix) continue ;; esac
    grep -q "{ \"$p\", LOGC_" "$ROOT/dns_log.c" || bad="$bad $p"
done
# dns_log.c itself shows "[Prefix]" in a comment and is read by the loop above; its own strings are table entries
[ -z "$bad" ] && pass "L: every [Prefix] of the sources is in the category table" || fail "L: prefixes missing from the table of dns_log.c:$bad"

# ------------------------------------------------------------------------------------------------ K: karicheck conf
kc_check() { # kc_check NAME CONF EXPECT PATTERN... : error = rc != 0, warn = rc 0; every PATTERN in the output
    n=$1; c=$2; e=$3; shift 3
    printf '%s\n' "$c" > "$W/$n.conf"
    out=$("$KARICHECK" conf "$W/$n.conf" 2>&1); rc=$?
    okrc=1
    [ "$e" = error ] && [ $rc -eq 0 ] && okrc=0
    [ "$e" = warn ] && [ $rc -ne 0 ] && okrc=0
    [ "$e" = ok ] && { [ $rc -ne 0 ] || printf '%s\n' "$out" | grep -q "WARNING\|ERROR"; } && okrc=0
    miss=""
    for pat in "$@"; do printf '%s\n' "$out" | grep -q -- "$pat" || miss="$miss [$pat]"; done
    if [ $okrc -eq 1 ] && [ -z "$miss" ]; then pass "K $n ($e)${1:+: $1}"; else fail "K $n ($e): rc $rc, missing:$miss"; printf '%s\n' "$out" | head -8; fi
}
NL=$(printf '\n_'); NL=${NL%_}
KEYDEF="key \"rndc-key\" { algorithm hmac-sha256; secret \"$SECRET\"; };"
kc_check k1 "options { directory \"$W\"; listen-on { 127.0.0.1; }; };
logging {
    channel default_log { file \"$W/named.log\" versions 3 size 5m; severity info; print-time yes; print-severity yes; print-category yes; };
    channel query_log { file \"$W/query.log\" versions unlimited size 100m suffix timestamp; print-time iso8601; };
    channel auth_log { syslog authpriv; severity notice; };
    category default { default_log; };
    category queries { query_log; };
    category security { auth_log; default_log; };
    category lame-servers { null; };
    category unmatched { null; };
    category dnssec { default_stderr; };
};
$KEYDEF
controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { \"rndc-key\"; }; };
zone \"pri.test\" { type primary; file \"$W/pri.zone\"; };" warn "controls: inet 127.0.0.1 port 953: rndc is not supported" "k1.conf:[0-9]*: controls"
kc_check k2 "logging {${NL} channel c {${NL}  file \"$W/c.log\" size 1m;${NL}  buffered yes;${NL} };${NL}};" warn "k2.conf:4: logging channel 'c': buffered is accepted but has no effect" "k2.conf:3: logging channel 'c': size without versions"
kc_check k3 "statistics-channels {${NL} inet 127.0.0.1 port 8053 allow { 127.0.0.1; };${NL}};" warn "k3.conf:1: statistics-channels"
kc_check k4 "logging { frobnicate yes; };" error "k4.conf:1: logging: unknown statement 'frobnicate'"
kc_check k5 "logging {${NL} channel c {${NL}  severity info;${NL} };${NL}};" error "k5.conf:4: logging channel 'c': exactly one of file, syslog, null, and stderr must be present"
kc_check k6 "logging {${NL} channel c { null; };${NL} category queries { nosuch; };${NL}};" error "k6.conf:3: logging: undefined channel: 'nosuch'"
kc_check k7 "logging { category nonsense { null; }; };" error "k7.conf:1: logging: undefined category: 'nonsense'"
kc_check k8 "logging { channel c { file \"$W/c.log\" size 10x; }; };" error "k8.conf:1: logging channel 'c': file: invalid size value '10x'"
kc_check k9 "logging { channel c { null; severity chatty; }; };" error "severity: invalid severity 'chatty'"
kc_check k10 "logging { channel c { null; print-time sometimes; }; };" error "print-time: invalid value 'sometimes'"
kc_check k11 "controls {${NL} unix \"/var/run/named.sock\" perm 0600 owner 0 group 0;${NL}};" error "k11.conf:2: controls: unix control '/var/run/named.sock': not supported"
kc_check k12 "controls { inet 127.0.0.1 allow { any; } keys { missing; }; };" error "controls: unknown key 'missing'"
kc_check k13 "controls {${NL} inet 127.0.0.1 allow { any; };${NL} inet 127.0.0.1 port 953 allow { none; };${NL}};" error "k13.conf:3: controls: inet control socket '127.0.0.1#953': already defined, previous definition: $W/k13.conf:2"
kc_check k14 "controls { inet 127.0.0.1 allow { nosuchacl; }; };" error "nosuchacl"
kc_check k15 "options { querylog maybe; };" error "querylog"
kc_check k16 "options { querylog yes; };" ok
kc_check k17 "controls { };" ok
kc_check k18 "logging { channel c { file \"$W/c.log\"; syslog; }; };" error "exactly one of file, syslog, null, and stderr"
kc_check k19 "logging { channel c { syslog nosuchfacility; }; };" warn "unknown facility 'nosuchfacility'"

# ------------------------------------------------------------------------------------------------ C / R: categories and a reload
cat > "$W/c1.conf" <<EOF
options { port $P1; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT notify-retries 1; notify-retry-interval 1; };
$(ctlblock c1)
logging {
    channel cfglog   { file "$LG/config.log"; print-time iso8601-utc; print-category yes; print-severity yes; };
    channel xferlog  { file "$LG/xfer.log"; print-category yes; };
    channel xferhi   { file "$LG/xfer_crit.log"; severity critical; };
    channel notifylog { file "$LG/notify.log"; severity warning; print-time local; print-category yes; print-severity yes; };
    channel notifyall { file "$LG/notify_all.log"; print-severity yes; };
    channel seclog   { file "$LG/sec.log"; print-severity yes; };
    channel stderrch { stderr; print-category yes; };
    channel sy       { syslog local3; print-category yes; print-severity yes; };
    channel nul      { null; };
    category config   { cfglog; };
    category xfer-in  { xferlog; xferhi; };
    category notify   { notifylog; notifyall; };
    category security { seclog; };
    category general  { sy; };
    category network  { nul; };
    category default  { stderrch; };
};
zone "pri.test" { type primary; file "$W/pri.zone"; also-notify { 127.0.0.1 port $SINK; }; };
zone "sec.test" { type secondary; primaries { 127.0.0.1 port $CLOSED; }; file "$W/sec.zone"; };
zone "bad.test" { type primary; file "$W/bad.zone"; };
EOF
if ! "$KARICHECK" conf "$W/c1.conf" > "$W/c1.check" 2>&1; then
    # bad.zone is on purpose; karicheck conf may check zones too: only the logging part matters here
    grep -q "bad.zone\|bad.test" "$W/c1.check" || { fail "C: karicheck conf refused the test configuration"; cat "$W/c1.check"; }
fi
start c1
C1PID=$LAST_PID
if wait_up $P1 20; then pass "C: the server with BIND logging started"; else fail "C: the server did not start"; fi
ctl_wait c1
ctl c1 notify pri.test > /dev/null
# the NOTIFY gets no answer: UDP, one retransmission, then TCP (refused): a notice and a warning, a few seconds apart
wait_grep "failed" "$LG/notify.log" 20 || true
ctl c1 reload > "$W/reload1.out"
wait_grep "Configuration and zones reloaded" "$W/c1.log" 10 || true
# an error of the configuration: [Config] lines (category config), "Failed to reload" (no prefix: general)
cp "$W/c1.conf" "$W/c1.conf.good"
printf 'options { nonsense-option yes; };\n' >> "$W/c1.conf"
ctl c1 reload > "$W/reload_bad.out"
grep -q "ERROR" "$W/reload_bad.out" && pass "R: a configuration error is reported by karictl reload" || { fail "R: reload of a bad configuration did not fail"; cat "$W/reload_bad.out"; }
cp "$W/c1.conf.good" "$W/c1.conf"
# a TSIG request with a key the server does not know (category security, info)
"$DAG" @127.0.0.1 -p $P1 www.pri.test A -y hmac-sha256:nokey:c2VjcmV0c2VjcmV0 +time=1 +tries=1 +nohexdump >/dev/null 2>&1
# wait for the secondary's failed transfer and the NOTIFY failure over TCP
wait_grep "AXFR" "$LG/xfer.log" 15 || true
wait_grep "TSIG" "$LG/sec.log" 5 || true

# config.log: iso8601-utc, category and severity
if grep -E -q '^20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]Z config: (error|warning|notice): \[Config\]' "$LG/config.log" 2>/dev/null; then
    pass "C: config.log has [Config] lines with iso8601-utc time, category and severity"
else fail "C: config.log"; cat "$LG/config.log" 2>/dev/null | head -5; fi
grep -q 'nonsense-option' "$LG/config.log" && pass "C: the configuration error reached the config category (file:line text)" || fail "C: the reload error is not in config.log"
# xfer-in: the failed connection of the secondary; severity critical channel stays empty
if grep -q 'xfer-in: \[AXFR\] Failed to connect to 127.0.0.1 for zone' "$LG/xfer.log" 2>/dev/null; then pass "C: xfer.log has the [AXFR] error with its category"; else fail "C: xfer.log"; cat "$LG/xfer.log" 2>/dev/null | head -3; fi
[ "$(size_of "$LG/xfer_crit.log")" = 0 ] && pass "C: a channel with severity critical receives no error" || fail "C: xfer_crit.log is not empty"
# notify: the warning-only channel has no notice line, the info channel has both
if grep -q 'warning' "$LG/notify.log" 2>/dev/null && ! grep -q 'notice:' "$LG/notify.log" 2>/dev/null &&
   grep -E -q '^[0-9][0-9]-[A-Z][a-z][a-z]-20[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9] notify: warning: \[Notify\]' "$LG/notify.log"; then
    pass "C: notify.log (severity warning): local time format, no notice lines"
else fail "C: notify.log"; cat "$LG/notify.log" 2>/dev/null | head -5; fi
grep -q 'notice: \[Notify\]' "$LG/notify_all.log" 2>/dev/null && grep -q 'warning: \[Notify\]' "$LG/notify_all.log" 2>/dev/null &&
    pass "C: notify_all.log (info) has the notice and the warning of the same NOTIFY" || { fail "C: notify_all.log"; cat "$LG/notify_all.log" 2>/dev/null | head -5; }
grep -q 'info: \[TSIG\] request from 127.0.0.1' "$LG/sec.log" 2>/dev/null && pass "C: sec.log has the [TSIG] error as category security (print-severity, no time)" || { fail "C: sec.log"; cat "$LG/sec.log" 2>/dev/null | head -3; }
# the stderr channel (category default): the zone file error of bad.test is a zoneload message
if grep -q 'zoneload: ' "$W/c1.log"; then pass "C: a category with no channel (zoneload) follows category default (stderr channel)"; else fail "C: no zoneload line on stderr"; grep -c . "$W/c1.log"; fi
# the syslog channel: syslog() of the server also prints on stderr (LOG_PERROR), so the line is in the server log
if grep -q 'general: notice: \[Control\] Received full reload command' "$W/c1.log"; then pass "C: the syslog channel (category general) wrote category and severity"; else fail "C: no general line"; fi
# network is the null channel: nothing from [Network] anywhere
grep -q '\[Network\]' "$W/c1.log" "$LG"/*.log 2>/dev/null && fail "C: a [Network] message escaped the null channel" || pass "C: the null channel swallowed the [Network] messages"

# R: a reload inside a directory that was opened at start-up applies at once
sed "s|category notify   { notifylog; notifyall; };|category notify   { notifyall; seclog; };|" "$W/c1.conf" > "$W/c1.conf.new"
cp "$W/c1.conf.new" "$W/c1.conf"
sec_before=$(lines_of "$LG/sec.log")
ctl c1 reload > "$W/reload2.out"
cat "$W/reload2.out" | grep -q "restart needed" && fail "R: a change inside the opened directories needs no restart: $(cat "$W/reload2.out")" || pass "R: the change of a category is applied by the reload (no restart note)"
nw_before=$(lines_of "$LG/notify.log")
ctl c1 notify pri.test > /dev/null
wait_more "$LG/sec.log" $sec_before 20
if [ "$(lines_of "$LG/sec.log")" -gt "$sec_before" ] && [ "$(lines_of "$LG/notify.log")" = "$nw_before" ]; then pass "R: the NOTIFY lines now go to the new channel (sec.log), no longer to notify.log"
else fail "R: routing after the reload (sec $sec_before -> $(lines_of "$LG/sec.log"), notify $nw_before -> $(lines_of "$LG/notify.log"))"; fi
# a file in a directory that was not opened at start-up: restart needed, the logging in use stays
mkdir "$LG/newdir"
chmod 777 "$LG/newdir"
printf 'logging { channel newch { file "%s/newdir/new.log"; }; category notify { newch; }; };\n' "$LG" >> "$W/c1.conf"
ctl c1 reload > "$W/reload3.out"
if grep -q "restart needed for: .*logging" "$W/reload3.out"; then pass "R: a log file in a new directory is reported as restart needed: $(head -1 "$W/reload3.out")"; else fail "R: no restart note"; cat "$W/reload3.out"; fi
[ ! -e "$LG/newdir/new.log" ] && pass "R: the new file was not created" || fail "R: new.log exists"
wait_grep "restart" "$LG/config.log" 5 || true
grep -q 'config: warning: \[Config\] Reload: changed settings take effect only after a restart: logging' "$LG/config.log" && pass "R: the restart note is a [Config] message in the config category" || fail "R: no restart message in config.log"
sec_before=$(lines_of "$LG/sec.log")
ctl c1 notify pri.test > /dev/null
wait_more "$LG/sec.log" $sec_before 20
[ "$(lines_of "$LG/sec.log")" -gt "$sec_before" ] && pass "R: the logging in use (sec.log for notify) stays until the restart" || fail "R: the old routing was lost"
query $P1 www.pri.test && pass "R: the server still answers after the reloads" || fail "R: the server does not answer"
stop $C1PID

# ------------------------------------------------------------------------------------------------ Q: query log
mkq() { # mkq NAME PORT OPTIONS LOGGING
    cat > "$W/$1.conf" <<EOF
options { port $2; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT $3 };
$(ctlblock "$1")
$4
zone "pri.test" { type primary; file "$W/pri.zone"; };
EOF
}
# q1: querylog yes, a rolled file (3k, 2 versions) in the sandbox
mkq q1 $P2 "querylog yes; query-log-max-qps 0;" "logging { channel q { file \"$LG/q.log\" versions 2 size 3k; print-category yes; print-severity yes; }; category queries { q; }; };"
start q1
Q1PID=$LAST_PID
wait_up $P2 20 || fail "Q: q1 did not start"
ctl_wait q1
ctl q1 status | grep -q "query logging is ON" && pass "Q: querylog yes: karictl status says query logging is ON" || fail "Q: status of q1"
i=0; while [ $i -lt 120 ]; do query $P2 www.pri.test; i=$((i + 1)); done
sleep 3
if grep -q '^queries: info: client 127.0.0.1#[0-9]* (www.pri.test.): query: www.pri.test. IN A' "$LG/q.log"; then pass "Q: query lines carry category and severity"; else fail "Q: q.log"; head -3 "$LG/q.log"; fi
if [ -f "$LG/q.log.0" ] && [ -f "$LG/q.log.1" ] && [ ! -f "$LG/q.log.2" ]; then pass "Q: size 3k versions 2: q.log.0 and q.log.1 exist, no q.log.2 (rolled inside the sandbox)"; else fail "Q: roll files: $(ls "$LG" | grep '^q.log' | tr '\n' ' ')"; fi
[ "$(size_of "$LG/q.log")" -le 3072 ] && [ "$(size_of "$LG/q.log.0")" -le 3072 ] && pass "Q: no file is over the size" || fail "Q: a file is over 3k"
stop $Q1PID

# q2: querylog no with a queries category: nothing logged; status says OFF
rm -f "$LG/q.log" "$LG/q.log.0" "$LG/q.log.1"
mkq q2 $P2 "querylog no;" "logging { channel q { file \"$LG/q2chan.log\"; }; category queries { q; }; };"
start q2
Q2PID=$LAST_PID
wait_up $P2 20 || fail "Q: q2 did not start"
i=0; while [ $i -lt 10 ]; do query $P2 www.pri.test; i=$((i + 1)); done
sleep 2
[ "$(size_of "$LG/q2chan.log")" = 0 ] && pass "Q: querylog no: the queries category stays silent" || fail "Q: q2chan.log has lines"
ctl_wait q2
ctl q2 status | grep -q "query logging is OFF" && pass "Q: querylog no: karictl status says OFF" || fail "Q: status of q2"
stop $Q2PID

# q3: querylog yes and no queries category: the default category (syslog, which the foreground server also prints on stderr)
mkq q3 $P2 "querylog yes;" ""
start q3
Q3PID=$LAST_PID
wait_up $P2 20 || fail "Q: q3 did not start"
i=0; while [ $i -lt 5 ]; do query $P2 www.pri.test; i=$((i + 1)); done
wait_grep 'client 127.0.0.1#[0-9]* (www.pri.test.): query: www.pri.test. IN A' "$W/q3.log" 10
grep -q 'client 127.0.0.1#[0-9]* (www.pri.test.): query: www.pri.test. IN A' "$W/q3.log" && pass "Q: querylog yes with no queries category logs to the default channel (syslog)" || { fail "Q: no query line in q3.log"; tail -3 "$W/q3.log"; }
stop $Q3PID

# q4: size without versions: the file stops at the size; versions unlimited keeps everything
mkq q4 $P3 "querylog yes; query-log-max-qps 0;" "logging { channel full { file \"$LG/full.log\" size 1k; }; channel unl { file \"$LG/unl.log\" versions unlimited size 1k; };
  category queries { full; unl; }; };"
start q4
Q4PID=$LAST_PID
wait_up $P3 20 || fail "Q: q4 did not start"
i=0; while [ $i -lt 60 ]; do query $P3 www.pri.test; i=$((i + 1)); done
sleep 3
s1=$(size_of "$LG/full.log")
[ "$s1" -gt 0 ] && [ "$s1" -le 1024 ] && pass "Q: size 1k without versions: full.log stopped at $s1 bytes" || fail "Q: full.log size $s1"
i=0; while [ $i -lt 10 ]; do query $P3 www.pri.test; i=$((i + 1)); done
sleep 1
[ "$(size_of "$LG/full.log")" = "$s1" ] && pass "Q: the full file does not grow" || fail "Q: full.log grew"
[ ! -e "$LG/full.log.0" ] && pass "Q: ... and is not rolled" || fail "Q: full.log.0 exists"
wait_grep "reached its size limit" "$W/q4.log" 5 && pass "Q: the server says the file is full" || fail "Q: no size limit message"
n=$(ls "$LG" | grep -c '^unl\.log\.[0-9]*$')
[ "$n" -ge 3 ] && [ -f "$LG/unl.log.0" ] && [ -f "$LG/unl.log.2" ] && pass "Q: versions unlimited kept $n old files" || fail "Q: unl.log.N files: $n"
stop $Q4PID

# ------------------------------------------------------------------------------------------------ X: controls
cat > "$W/x1.conf" <<EOF
options { port $P3; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
$(ctlblock x1)
key "rndc-key" { algorithm hmac-sha256; secret "$SECRET"; };
controls { inet 127.0.0.1 port 9953 allow { localhost; } keys { "rndc-key"; }; };
statistics-channels { inet 127.0.0.1 port 8053 allow { 127.0.0.1; }; };
zone "pri.test" { type primary; file "$W/pri.zone"; };
EOF
start x1
X1PID=$LAST_PID
if wait_up $P3 20; then pass "X: a server with controls and statistics-channels starts"; else fail "X: x1 did not start"; fi
wait_grep 'rndc is not supported' "$W/x1.log" 10 && wait_grep 'no statistics channel' "$W/x1.log" 10 && pass "X: both statements were accepted with a warning" || fail "X: warnings missing in x1.log"
ctl_wait x1
ctl x1 status | grep -q "query logging" && pass "X: karictl works through control-channel" || fail "X: karictl status"
cp "$W/x1.conf" "$W/x1.conf.good"
sed 's|keys { "rndc-key"; }|keys { "other-key"; }|' "$W/x1.conf.good" > "$W/x1.conf"
ctl x1 reload > "$W/xreload.out"
if grep -q "ERROR" "$W/xreload.out"; then pass "X: a controls statement with an unknown key rejects the reload"; else fail "X: reload accepted an unknown controls key"; cat "$W/xreload.out"; fi
query $P3 www.pri.test && pass "X: the server keeps answering with the old configuration" || fail "X: the server is not answering"
stop $X1PID

echo "== $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
