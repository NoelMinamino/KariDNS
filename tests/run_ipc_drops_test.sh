#!/bin/sh
# ==============================================================================
# run_ipc_drops_test.sh - queries and replies between the Frontend routers and the Backend workers are never lost without a trace (0.7)
#
#   A  a server with small IPC / UDP buffers (udp-recvbuf-size 16K, udp-sndbuf-size 16K), one router and two workers: `karictl ipcstats` lists
#      every counter (all 0 at the start), `karictl stats` has them as karidns_ipc_events_total (and "ipc" in JSON), `karictl status` the total
#   B  the same server under load (a CPU burner on every CPU, 400 queries in flight, a query that is not answered in 1 s is sent again): every one
#      of 20000 queries is answered within the resend window, and the accounting holds: the datagrams that were sent and did not come back are
#      the drops that the server counted (karictl ipcstats), plus the datagrams the kernel dropped at a full UDP socket (netstat -s)
#   C  the Backend is stopped (SIGSTOP) while 2000 queries come, paced so that the router can read them all: the queues to the workers fill up
#      and every query that did not fit is counted (router.worker.dropped_full > 0), none is lost without a count; the Backend goes on (SIGCONT)
#      and the ones that were queued are answered
#   D  an IPC / UDP buffer above kern.ipc.maxsockbuf: the kernel refuses it, every buffer gets the most the kernel takes, the warning says "asked N, got M (limited by kern.ipc.maxsockbuf=X; set it to Y)"
#   E  (0.7 IPC backpressure) the router stopped while 400 queries come, with a small reply queue (test switches KARIDNS_TEST_IPC_REPLY_QUEUE, _BUDGET_US):
#      with no wait (the worker before 0.7) the replies that do not fit are dropped and counted; with the wait every query is answered, none dropped.
#      The switches exist only in the test build (./karidns of make coverage, or ./karidns-evict): E is skipped without one; a release ./karidns has none (E0)
#
# SKIP (exit 0, with the reason) without karidns, karictl, perl.  About 30 s.  See docs/karictl.md (ipcstats), docs/karidns.md (udp-recvbuf-size).
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS=${KARIDNS:-$ROOT_DIR/karidns}
KARICTL=${KARICTL:-$ROOT_DIR/karictl}
for b in "$KARIDNS" "$KARICTL"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

T=$(mktemp -d "${TMPDIR:-/tmp}/ipc_drops.XXXXXX") || exit 1
chmod 755 "$T"
SERVER_PID=""
BURNERS=""
BACKEND=""
stop_burners() { [ -n "$BURNERS" ] && kill $BURNERS 2>/dev/null; BURNERS=""; }
stop_server() {
    [ -n "$BACKEND" ] && kill -CONT "$BACKEND" 2>/dev/null     # (a stopped process does not die from SIGTERM)
    [ -n "$SERVER_PID" ] && kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$T/karidns.conf"
    SERVER_PID=""; BACKEND=""
}
cleanup() {
    set +e
    stop_burners
    stop_server
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PORT=$(kari_port 0 $((26000 + $$ % 4000)))
CTRL_SOCK="$T/control.sock"
LOG="$T/karidns.log"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
CLIENT="$SCRIPT_DIR/ipc_drops_client.pl"

cat > "$T/example.zone" <<'EOF'
$TTL 300
@ IN SOA ns1 hostmaster 2026112001 3600 600 86400 300
@ IN NS ns1
ns1 IN A 127.0.0.1
* IN A 192.0.2.1
EOF
chmod 644 "$T/example.zone"
cat > "$T/karictl.conf" <<EOF
socket "$CTRL_SOCK";
key "karictl" { algorithm hmac-sha256; secret "c3RhdHMtdGVzdC1zZWNyZXQta2V5LTAwMQ=="; };
EOF
chmod 600 "$T/karictl.conf"
ctl() { "$KARICTL" -s "$CTRL_SOCK" -f "$T/karictl.conf" "$@"; }

# write_conf BUFFER: the configuration with udp-recvbuf-size / udp-sndbuf-size BUFFER
write_conf() {
    cat > "$T/karidns.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    router-threads 1;
    worker-threads 2;
    udp-receive frontend;      # (B3 phase 2 made backend the default; this test fills the queues between the routers and the workers)
    udp-recvbuf-size $1;
    udp-sndbuf-size $1;
    $USER_OPT
};
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "c3RhdHMtdGVzdC1zZWNyZXQta2V5LTAwMQ=="; };
zone "example.test" { type primary; file "$T/example.zone"; };
EOF
    chmod 644 "$T/karidns.conf"
}

start_server() {
    : > "$LOG"
    "$KARIDNS" -f "$T/karidns.conf" > "$LOG" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ $i -lt 100 ]; do
        ctl ipcstats >/dev/null 2>&1 && break
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.2
        i=$((i + 1))
    done
    # the Backend is the child with the threads
    BACKEND=$(ps -ax -o pid= -o ppid= -o nlwp= -o command= | awk -v p="$SERVER_PID" '$2 == p && $3 > 1 { print $1; exit }')
    ctl ipcstats >/dev/null 2>&1
}

ipcv() { ctl ipcstats 2>/dev/null | sed -n "s/^ipc\\.$1=//p" | head -1; }   # ipcv router.worker.dropped_full
udp_full_drops() { netstat -s -p udp 2>/dev/null | awk '/dropped due to full socket buffers/ { print $1; exit }'; }
kv() { echo "$1" | tr ' ' '\012' | sed -n "s/^$2=//p" | head -1; }   # kv "sent=3 received=2" received

# account LABEL CLIENT-OUTPUT DROPPED-BEFORE UDPFULL-BEFORE: sent - received is what was lost; the server's counted drops (and the kernel's at a
# full UDP socket, when netstat says) must account for all of it, and none of them may be a loss that did not happen
account() {
    s=$(kv "$2" sent); r=$(kv "$2" received)
    d1=$(ipcv dropped.total); u1=$(udp_full_drops)
    lost=$((s - r)); counted=$((d1 - $3))
    if [ -n "$u1" ] && [ -n "$4" ]; then udp=$((u1 - $4)); else udp=""; fi
    if [ "$counted" -gt "$lost" ]; then
        bad "$1: the server counted $counted drops but only $lost datagrams were lost (sent $s, received $r)"
    elif [ -n "$udp" ] && [ "$lost" -gt $((counted + udp)) ]; then
        bad "$1: $lost datagrams were lost (sent $s, received $r), the server counted $counted and the kernel $udp at full UDP sockets: $((lost - counted - udp)) are not counted anywhere"
    elif [ -z "$udp" ] && [ "$lost" -gt "$counted" ]; then
        bad "$1: $lost datagrams were lost (sent $s, received $r), the server counted only $counted"
    else
        ok "$1: sent $s - received $r = $lost lost; counted by the server $counted${udp:+, by the kernel at a full UDP socket $udp}"
    fi
}

# ---------------------------------------------------------------- A. the counters are there
echo "== A. karictl ipcstats / stats / status, buffers of 16K"
write_conf 16K
start_server
if [ -z "$BACKEND" ] || ! ctl ipcstats >/dev/null 2>&1; then
    bad "the server does not answer karictl ipcstats" "$(tail -8 "$LOG")"
    echo "run_ipc_drops_test: $PASS ok, $FAILS failed"; exit 1
fi
OUT=$(perl "$CLIENT" "$PORT" 1 1 1 5)
[ "$(kv "$OUT" answered)" = 1 ] && ok "the server answers a query (the load generator works)" || bad "no answer to the first query" "$OUT"
ctl ipcstats > "$T/ipc0.txt" 2>&1
want="router.worker.spilled router.worker.dropped_full router.worker.dropped_error router.rx.truncated router.rx.short router.reply.short router.reply.bad_length router.reply.bad_socket router.client.dropped_full router.client.dropped_error worker.rx.short worker.rx.bad_length worker.reply.dropped_full worker.reply.dropped_error worker.async.dropped_full worker.udp.truncated worker.udp.short router.reply.cut router.client.retried worker.reply.retried dropped.total"
missing=""
for k in $want; do grep -q "^ipc\\.$k=[0-9]*\$" "$T/ipc0.txt" || missing="$missing $k"; done
[ -z "$missing" ] && ok "karictl ipcstats lists all 21 counters" || bad "karictl ipcstats lacks:$missing" "$(cat "$T/ipc0.txt")"
[ "$(ipcv dropped.total)" = 0 ] && ok "nothing was dropped yet (ipc.dropped.total=0)" || bad "ipc.dropped.total=$(ipcv dropped.total) before any load"
ctl stats > "$T/stats.prom" 2>&1
grep -q '^karidns_ipc_events_total{event="router.worker.dropped_full"} 0$' "$T/stats.prom" && ok "karictl stats: karidns_ipc_events_total{event=...}" || bad "karictl stats has no karidns_ipc_events_total" "$(grep ipc "$T/stats.prom" | head -3)"
ctl stats -f json > "$T/stats.json" 2>&1
grep -q '"ipc":{"router.worker.spilled":0' "$T/stats.json" && ok "karictl stats -f json: the \"ipc\" object" || bad "karictl stats -f json has no \"ipc\" object" "$(head -c 300 "$T/stats.json")"
ctl status 2>&1 | grep -q '^IPC dropped .*: 0$' && ok "karictl status: IPC dropped: 0" || bad "karictl status has no IPC dropped line" "$(ctl status 2>&1 | tail -4)"

# ---------------------------------------------------------------- B. under load
echo "== B. a CPU burner on every CPU, 400 queries in flight, 20000 queries, a query that waits 1 s is sent again"
NCPU=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
i=0
while [ "$i" -lt "$NCPU" ]; do
    sh -c 'while :; do :; done' &
    BURNERS="$BURNERS $!"
    i=$((i + 1))
done
D0=$(ipcv dropped.total); U0=$(udp_full_drops)
OUT=$(perl "$CLIENT" "$PORT" 20000 400 1 30 16 0)
echo "  $OUT"
stop_burners
[ "$(kv "$OUT" unanswered)" = 0 ] && ok "every one of 20000 queries was answered within the resend window" || bad "unanswered: $(kv "$OUT" unanswered)" "$OUT"
account "under load" "$OUT" "$D0" "$U0"
echo "  counted so far: $(ctl ipcstats | grep -v '=0$' | tr '\n' ' ')"

# ---------------------------------------------------------------- C. the Backend is stopped
echo "== C. the Backend is stopped while 2000 queries come (8 at a time, 2 ms apart): the queues to the workers fill up"
D0=$(ipcv dropped.total); F0=$(ipcv router.worker.dropped_full); U0=$(udp_full_drops)
kill -STOP "$BACKEND"
OUT=$(perl "$CLIENT" "$PORT" 2000 2000 0 20 8 2 "$BACKEND")
kill -CONT "$BACKEND" 2>/dev/null
echo "  $OUT"
F1=$(ipcv router.worker.dropped_full)
[ "${F1:-0}" -gt "${F0:-0}" ] && ok "queries that did not fit the queues are counted: router.worker.dropped_full +$((F1 - F0))" || bad "router.worker.dropped_full did not move ($F0 -> $F1)" "$OUT"
[ "$(kv "$OUT" answered)" -gt 0 ] && ok "the queries that were queued were answered after SIGCONT ($(kv "$OUT" answered))" || bad "no query was answered after SIGCONT" "$OUT"
account "the stopped Backend" "$OUT" "$D0" "$U0"
ctl ipcstats > "$T/ipc1.txt"
[ "$(sed -n 's/^ipc\.router\.rx\.short=//p' "$T/ipc1.txt")" = 0 ] && [ "$(sed -n 's/^ipc\.worker\.rx\.bad_length=//p' "$T/ipc1.txt")" = 0 ] && ok "no message was dropped as malformed (rx.short, bad_length 0)" || bad "malformed-message counters moved" "$(cat "$T/ipc1.txt")"
# what the DB tests print when a query is lost (tests/lib_proc.sh kari_ipc_diag)
DIAG=$(kari_ipc_diag "$KARICTL -s $CTRL_SOCK -f $T/karictl.conf" "$LOG")
printf '%s\n' "$DIAG" | grep -q 'ipc\.router\.worker\.dropped_full=[1-9]' && printf '%s\n' "$DIAG" | grep -q 'kern.ipc.maxsockbuf=' && ok "kari_ipc_diag prints the counters that are not 0 and the sysctls" || bad "kari_ipc_diag output" "$DIAG"
# the server still works
OUT=$(perl "$CLIENT" "$PORT" 500 100 1 10 16 0)
[ "$(kv "$OUT" unanswered)" = 0 ] && ok "after SIGCONT the server answers everything again" || bad "after SIGCONT: $OUT"
stop_server

# ---------------------------------------------------------------- D. the warning
echo "== D. a buffer above kern.ipc.maxsockbuf (the stock 2 MB and the 4M default): the kernel refuses it, the sockets get the most it takes, and the warning says what to set"
MAXB=$(sysctl -n kern.ipc.maxsockbuf 2>/dev/null || echo 0)
if [ "$MAXB" -gt 65536 ] && [ "$MAXB" -lt 1073741824 ] 2>/dev/null; then
    ASK=$((MAXB * 2))                                   # (a stock host: 4 MB against 2 MB, the default size of the server)
    LIMIT=$((MAXB * 2048 / 2304))                       # what the kernel takes: kern.ipc.maxsockbuf * MCLBYTES / (MSIZE + MCLBYTES)
    NEED=$(((ASK * 2304 + 2047) / 2048))                # the kern.ipc.maxsockbuf that gives ASK
    write_conf "$ASK"
    start_server
    kari_wait_log "$LOG" '\[IPC\] WARNING' 15 && ok "the server logs \"[IPC] WARNING\"" || bad "no [IPC] WARNING line in the log" "$(head -12 "$LOG")"
    W=$(grep '\[IPC\] WARNING' "$LOG" | head -1)
    case "$W" in
    *"asked $ASK, got "*"limited by kern.ipc.maxsockbuf=$MAXB; set it to $NEED to get $ASK"*) ok "the warning says: asked $ASK, got M (limited by kern.ipc.maxsockbuf=$MAXB; set it to $NEED to get $ASK)" ;;
    *) bad "the warning does not say asked / got / the sysctl and the value to set" "$W" ;;
    esac
    gotv() { ctl ipcstats 2>/dev/null | sed -n "s/^ipcbuf\.$1=//p" | head -1; }
    i=0; while [ $i -lt 150 ] && [ "$(gotv udp.rcv.got)" -le 0 ] 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    QR=$(gotv queue.rcv.got); QS=$(gotv queue.snd.got); UR=$(gotv udp.rcv.got); US=$(gotv udp.snd.got)
    echo "  sizes in force: queues rcv $QR snd $QS, UDP sockets rcv $UR snd $US (asked $ASK, the kernel takes $LIMIT)"
    [ "$(gotv queue.rcv.asked)" = "$ASK" ] && [ "$(gotv udp.snd.asked)" = "$ASK" ] && ok "karictl ipcstats shows what was asked for ($ASK)" || bad "ipcbuf asked lines" "$(ctl ipcstats | grep ipcbuf)"
    allok=1
    for v in "$QR" "$QS" "$UR" "$US"; do
        [ "${v:-0}" -le "$LIMIT" ] 2>/dev/null && [ "${v:-0}" -ge $((LIMIT / 2)) ] 2>/dev/null || allok=0
    done
    [ "$allok" = 1 ] && ok "every buffer got the most the kernel takes (between $((LIMIT / 2)) and $LIMIT), not the small default" || bad "a buffer is not near the limit $LIMIT" "$(ctl ipcstats | grep ipcbuf)"
    grep -q "\[Network\] WARNING: UDP SO_RCVBUF: asked $ASK, got .*kern.ipc.maxsockbuf=$MAXB; set it to $NEED" "$LOG" && ok "the UDP socket warning has the same words" || bad "no UDP socket warning with the sysctl and the value to set" "$(grep -i 'network' "$LOG" | head -3)"
    OUT=$(perl "$CLIENT" "$PORT" 2000 100 1 10 16 0)
    [ "$(kv "$OUT" unanswered)" = 0 ] && ok "the server with the clamped buffers answers 2000 queries" || bad "clamped buffers: $OUT"
    stop_server
    # D2 (0.7, user 2026-11-24): the default size (not written; `0` keeps the default) that the kernel does not give is a NOTICE, not a WARNING
    if [ "$MAXB" -lt 4718592 ]; then
        write_conf 0
        start_server
        kari_wait_log "$LOG" '\[IPC\] NOTICE' 15 && ok "the default size the kernel does not give: [IPC] NOTICE" || bad "no [IPC] NOTICE line" "$(grep -i 'ipc\]\|network\]' "$LOG" | head -4)"
        grep -q "\[IPC\] NOTICE: .*asked 4194304 (the default), got .*kern.ipc.maxsockbuf=$MAXB" "$LOG" && ok "... it says the default and the sysctl" || bad "notice text" "$(grep '\[IPC\] NOTICE' "$LOG" | head -1)"
        grep -q "\[Network\] NOTICE: UDP SO_RCVBUF: asked 4194304 (the default), got" "$LOG" && ok "the UDP sockets: [Network] NOTICE" || bad "no UDP NOTICE" "$(grep -i 'network\]' "$LOG" | head -3)"
        ! grep -q "\[IPC\] WARNING\|\[Network\] WARNING: UDP" "$LOG" && ok "no WARNING for the default size" || bad "a WARNING for the default" "$(grep 'WARNING' "$LOG" | head -3)"
        stop_server
    else
        echo "  (kern.ipc.maxsockbuf $MAXB gives the 4M default: part D2 skipped)"
    fi
else
    echo "  (kern.ipc.maxsockbuf is $MAXB: part D skipped)"
fi

# ---------------------------------------------------------------- E. a router that does not read for a moment (0.7 IPC backpressure)
# udp-receive backend, 1 router, 1 worker, the router's end of the reply queue made small (KARIDNS_TEST_IPC_REPLY_QUEUE 4096: a few datagrams) and the
# router stopped (SIGSTOP) while 400 queries come (8 at a time, 2 ms apart; the client sends SIGCONT to the router after the last one, nothing is sent twice).
#   E1 KARIDNS_TEST_IPC_REPLY_BUDGET_US=0, the worker as before 0.7: the replies that do not fit the queue are dropped (worker.reply.dropped_full > 0), and counted
#   E2 the wait in force (KARIDNS_TEST_IPC_REPLY_BUDGET_US=10000000, so that the time the router is stopped is inside it): the worker waits for the queue,
#      the queries wait in its UDP socket, and every one of the 400 is answered: nothing dropped, worker.reply.retried > 0
echo "== E. the router stopped while 400 queries come, a small reply queue: dropped at once (the pre-0.7 worker) / waited for (0.7)"
write_conf_e() {
    cat > "$T/karidns.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    router-threads 1;
    worker-threads 1;
    udp-receive backend;
    $USER_OPT
};
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "c3RhdHMtdGVzdC1zZWNyZXQta2V5LTAwMQ=="; };
zone "example.test" { type primary; file "$T/example.zone"; };
EOF
    chmod 644 "$T/karidns.conf"
}
# the router: the last single-threaded child of the manager (forked after the Backend; the first one is the broker)
router_pid() { ps -ax -o pid= -o ppid= -o nlwp= | awk -v p="$SERVER_PID" -v b="$BACKEND" '$2 == p && $3 == 1 && $1 != b { r = $1 } END { print r }'; }
# The test switches exist only in the test build (review 2026-11-23 F-B3, -DKARIDNS_TEST_EVICT): ./karidns of `make coverage`, else ./karidns-evict (make evict;
# tests/run_all_suite.sh builds it).  A release ./karidns has none of them: it is checked that it does not, and E runs on the test build or is skipped.
has_ipc_knobs() { [ -x "$1" ] && grep -q 'KARIDNS_TEST_IPC_REPLY_QUEUE' "$1" 2>/dev/null; }
KARIDNS_E=""
if has_ipc_knobs "$KARIDNS"; then KARIDNS_E=$KARIDNS
else
    ok "E0: $KARIDNS (no test build) does not read the IPC test switches from its environment"
    has_ipc_knobs "$ROOT_DIR/karidns-evict" && KARIDNS_E=$ROOT_DIR/karidns-evict
fi
run_e() {   # run_e LABEL BUDGET_US
    write_conf_e
    export KARIDNS_TEST_IPC_REPLY_QUEUE=4096 KARIDNS_TEST_IPC_REPLY_BUDGET_US=$2
    KARIDNS_REL=$KARIDNS; KARIDNS=$KARIDNS_E
    start_server
    KARIDNS=$KARIDNS_REL
    unset KARIDNS_TEST_IPC_REPLY_QUEUE KARIDNS_TEST_IPC_REPLY_BUDGET_US
    ROUTER=$(router_pid)
    if [ -z "$BACKEND" ] || [ -z "$ROUTER" ]; then
        bad "$1: no Backend / router process (Backend '$BACKEND', router '$ROUTER')" "$(ps -ax -o pid= -o ppid= -o nlwp= -o command= | awk -v p="$SERVER_PID" '$2 == p')"
        stop_server; return 1
    fi
    OUT=$(perl "$CLIENT" "$PORT" 1 1 1 5)
    [ "$(kv "$OUT" answered)" = 1 ] || { bad "$1: no answer before the test" "$OUT"; stop_server; return 1; }
    D0=$(ipcv dropped.total); F0=$(ipcv worker.reply.dropped_full); R0=$(ipcv worker.reply.retried); U0=$(udp_full_drops)
    kill -STOP "$ROUTER"
    OUT=$(perl "$CLIENT" "$PORT" 400 400 0 5 8 2 "$ROUTER")
    kill -CONT "$ROUTER" 2>/dev/null
    echo "  $1: $OUT"
    # (the counters are read through a bounded wait: the worker may still be sending the last replies when the client gives up)
    i=0; while [ $i -lt 50 ] && [ "$(ipcv dropped.total)" = "$D0" ] && [ "$(ipcv worker.reply.retried)" = "$R0" ]; do sleep 0.1; i=$((i + 1)); done
    F1=$(ipcv worker.reply.dropped_full); R1=$(ipcv worker.reply.retried)
    echo "  $1: worker.reply.dropped_full +$((F1 - F0)), worker.reply.retried +$((R1 - R0)); not 0: $(ctl ipcstats | grep '^ipc\.' | grep -v '=0$' | tr '\n' ' ')"
}
if [ -z "$KARIDNS_E" ]; then
    echo "  SKIP: E needs the test build with the IPC test switches (./karidns of make coverage, or make evict)"
else
[ "$KARIDNS_E" != "$KARIDNS" ] && export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}"      # (karidns-evict is a sanitizer build)
run_e "E1 (no wait)" 0 && {
    [ "$((F1 - F0))" -gt 0 ] && ok "E1: without the wait the replies that do not fit the queue are dropped: worker.reply.dropped_full +$((F1 - F0))" || bad "E1: worker.reply.dropped_full did not move ($F0 -> $F1): the reply queue did not fill" "$OUT"
    account "E1" "$OUT" "$D0" "$U0"
    stop_server
}
run_e "E2 (wait)" 10000000 && {
    [ "$(kv "$OUT" answered)" = 400 ] && [ "$(kv "$OUT" sent)" = "$(kv "$OUT" received)" ] && ok "E2: every one of the 400 queries was answered, none sent twice" || bad "E2: not every query was answered" "$OUT"
    [ "$F1" = "$F0" ] && [ "$(ipcv dropped.total)" = "$D0" ] && ok "E2: nothing dropped (worker.reply.dropped_full and ipc.dropped.total unchanged)" || bad "E2: dropped: worker.reply.dropped_full $F0 -> $F1, ipc.dropped.total $D0 -> $(ipcv dropped.total)" "$OUT"
    [ "$((R1 - R0))" -gt 0 ] && ok "E2: the worker waited for the queue: worker.reply.retried +$((R1 - R0))" || bad "E2: worker.reply.retried did not move: the queue did not fill" "$OUT"
    stop_server
}
fi

echo
echo "run_ipc_drops_test: $PASS ok, $FAILS failed"
[ "$FAILS" = 0 ]
