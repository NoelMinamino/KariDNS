#!/bin/sh
# ==============================================================================
# run_udp_router_split_test.sh - 4 Frontend routers and 4 Backend workers (B3 phase 1 and 2): the UDP path with several routers, run once with
#   udp-receive frontend (the routers read the queries, B3 phase 1) and once with udp-receive backend (the default since B3 phase 2: every worker reads
#   its own UDP socket of each address and the routers only send the replies)
#
#   A  a server on the wildcard addresses (the default), router-threads 4 / worker-threads 4:
#        - the start-up line "4 routers, 4 workers ... set by router-threads and worker-threads"
#        - 20000 queries from 64 sockets (64 source ports, the kernel's SO_REUSEPORT_LB hash gives each router some of them), nothing sent twice:
#          every one answered (zero loss), every answer checked (NOERROR, the A record, the source address and port of the datagram = the
#          address the query went to, from the socket that asked), `karictl ipcstats`: no drop counted, and every router passed on queries
#          (ipcrouter.<r>.queries > 0 for all four, and their sum is exactly the number of queries sent)
#        - the same through a second local address (loopback alias, root only): a wildcard socket answers from the address the query came to
#        - paced single queries (a short batch every time: the read loop ends on a short recvmmsg batch and relies on the EV_CLEAR event of the next
#          datagram) and bursts of 33 (two full batches and a short one) are all answered
#   B  a server bound to specific addresses (127.0.0.1, and the alias when root): the same load and checks; allow-query-on takes the address
#        the socket is bound to (the router does not ask the kernel for the destination of these sockets): a zone with allow-query-on { 127.0.0.1; }
#        answers a query to 127.0.0.1, one with allow-query-on { 192.0.2.77; } refuses it, and the alias is refused by the first
#   With udp-receive backend A and B are the same, but the counters are the workers': the start-up line "udp-receive backend: N UDP receive socket(s)
#   (4 worker(s) x M listen address(es))", ipcworker.<w>.queries above 0 for all four workers and their sum exactly the queries sent, and the routers
#   read none of them (ipcrouter.<r>.queries do not move); the answers still come from the address and port the query went to (the router sends on
#   its descriptor of the worker's socket).  With udp-receive frontend there are no ipcworker lines.
#
# SKIP (exit 0, with the reason) without karidns, karictl, dag, perl.  The alias checks are skipped without root (ifconfig lo0 alias).  About 80 s (both modes).
# See docs/karidns.md (thread layout, router-threads), docs/karictl.md (ipcstats).
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS=${KARIDNS:-$ROOT_DIR/karidns}
KARICTL=${KARICTL:-$ROOT_DIR/karictl}
DAG=${DAG:-$ROOT_DIR/dag}
for b in "$KARIDNS" "$KARICTL" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

T=$(mktemp -d "${TMPDIR:-/tmp}/router_split.XXXXXX") || exit 1
chmod 755 "$T"
SERVER_PID=""
ALIAS_IP="127.0.0.2"
ALIAS_ADDED=0
stop_server() {
    [ -n "$SERVER_PID" ] && kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$T/karidns.conf"
    SERVER_PID=""
}
cleanup() {
    set +e
    stop_server
    [ "$ALIAS_ADDED" = "1" ] && ifconfig lo0 inet "$ALIAS_IP" netmask 255.0.0.0 -alias 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" = "0" ] && ifconfig lo0 inet "$ALIAS_IP" netmask 255.0.0.0 alias 2>/dev/null; then ALIAS_ADDED=1; fi
[ "$ALIAS_ADDED" = "1" ] || echo "  (no loopback alias $ALIAS_IP: the checks through a second local address are skipped; run as root to have them)"
IPS="127.0.0.1"
[ "$ALIAS_ADDED" = "1" ] && IPS="127.0.0.1,$ALIAS_IP"

PORT=$(kari_port 0 $((26000 + $$ % 4000)))
CTRL_SOCK="$T/control.sock"
LOG="$T/karidns.log"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
CLIENT="$SCRIPT_DIR/udp_router_split_client.pl"
SECRET="cm91dGVyLXNwbGl0LXRlc3Qtc2VjcmV0LWtleS0wMDE="

cat > "$T/example.zone" <<'EOF'
$TTL 300
@ IN SOA ns1 hostmaster 2026112001 3600 600 86400 300
@ IN NS ns1
ns1 IN A 127.0.0.1
* IN A 192.0.2.1
EOF
for z in on.test off.test; do
    printf '$TTL 300\n@ IN SOA ns1 hostmaster 1 3600 600 86400 300\n@ IN NS ns1\nns1 IN A 127.0.0.1\nwww IN A 192.0.2.80\n' > "$T/$z.zone"
done
chmod 644 "$T"/*.zone
cat > "$T/karictl.conf" <<EOF
socket "$CTRL_SOCK";
key "karictl" { algorithm "hmac-sha256"; secret "$SECRET"; };
EOF
chmod 600 "$T/karictl.conf"
ctl() { "$KARICTL" -s "$CTRL_SOCK" -f "$T/karictl.conf" "$@"; }

# write_conf BIND: BIND is the bind-address statement ("" = the wildcard addresses)
write_conf() {
    cat > "$T/karidns.conf" <<EOF
options {
    port $PORT;
    $1
    router-threads 4;
    worker-threads 4;
    udp-receive $MODE;
    pid-file "none";
    $USER_OPT
};
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "$SECRET"; };
zone "example.test" { type primary; file "$T/example.zone"; };
zone "on.test" { type primary; file "$T/on.test.zone"; allow-query-on { 127.0.0.1; }; };
zone "off.test" { type primary; file "$T/off.test.zone"; allow-query-on { 192.0.2.77; }; };
EOF
    chmod 644 "$T/karidns.conf"
}

start_server() {
    : > "$LOG"
    rm -f "$CTRL_SOCK"
    "$KARIDNS" -f "$T/karidns.conf" > "$LOG" 2>&1 &
    SERVER_PID=$!
    i=0
    while [ $i -lt 100 ]; do
        ctl ipcstats >/dev/null 2>&1 && break
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.2
        i=$((i + 1))
    done
    kari_wait_answer "$DAG" "$PORT" example.test 20
}

ipcv() { ctl ipcstats 2>/dev/null | sed -n "s/^$1=//p" | head -1; }   # ipcv ipc.dropped.total / ipcv ipcrouter.2.queries
routed_sum() { s=0; for r in 0 1 2 3; do s=$((s + $(ipcv ipcrouter.$r.queries))); done; echo "$s"; }
wrecv_sum() { s=0; for w in 0 1 2 3; do v=$(ipcv ipcworker.$w.queries); s=$((s + ${v:-0})); done; echo "$s"; }   # (udp-receive backend: the workers' own sockets)
kv() { echo "$1" | tr ' ' '\012' | sed -n "s/^$2=//p" | head -1; }   # kv "sent=3 received=2" received

# load LABEL N NSOCK WINDOW BATCH PAUSE_MS: the client against the server; every query answered, every answer right
load() {
    kari_udp_snap "$T/udp.snap"; qd0=$(sysctl -n net.inet.ip.intr_queue_drops 2>/dev/null || echo 0)
    out=$(perl "$CLIENT" "$PORT" "$2" "$3" "$4" 15 "$IPS" "$5" "$6" 2>&1)
    s=$(kv "$out" sent); r=$(kv "$out" received); u=$(kv "$out" unanswered); b=$(kv "$out" bad); k=$(kv "$out" socks)
    qd=$(($(sysctl -n net.inet.ip.intr_queue_drops 2>/dev/null || echo 0) - qd0))
    if [ "$s" = "$2" ] && [ "$r" = "$2" ] && [ "$u" = "0" ] && [ "$b" = "0" ]; then
        ok "$1: $2 queries from $3 sockets (to $IPS), all answered, all right ($out)"
        # loopback output goes through the one netisr IP input queue (256 deep): a burst of answers that overflows it is dropped by the kernel before
        # UDP, counted in net.inet.ip.intr_queue_drops (seen on CI, 5 of 20000).  Such a loss is not the server's, when the queue dropped at least as many
        # datagrams during this load (the checks that follow still demand that the routers and workers passed every query on and dropped none).
    elif [ "$s" = "$2" ] && [ "$b" = "0" ] && [ "$((r + u))" = "$2" ] && [ "$u" -le "$qd" ]; then
        ok "$1: $2 queries from $3 sockets (to $IPS), all right; $u answer(s) lost in the kernel's loopback IP input queue (net.inet.ip.intr_queue_drops +$qd) ($out)"
    else
        bad "$1: $out" "$out
    netstat -s -p udp since the start of this load (the client and the server share the host):
$(kari_udp_delta "$T/udp.snap")
    net.inet.ip.intr_queue_drops +$qd during this load
$(ctl ipcstats | grep -v '=0$')"
    fi
    LAST_SOCKS=${k:-0}
    LOST_Q=${u:-0}   # (the unanswered queries load() accepted as lost in the kernel's queue: the query itself may be what was dropped)
}

# in_lost N: N queries reached the server: 20000, or fewer by at most the LOST_Q that the kernel's queue explains
in_lost() { [ "$1" -le 20000 ] && [ "$1" -ge $((20000 - LOST_Q)) ]; }

# one_server LABEL: the checks A (wildcard) and B (specific addresses) share
one_server() {
    lbl=$1
    if grep -q '\[Startup\] 4 routers, 4 workers .*set by router-threads and worker-threads' "$LOG"; then
        ok "$lbl: 4 routers, 4 workers"
    else
        bad "$lbl: start-up line" "$(grep Startup "$LOG")"
    fi
    if [ "$MODE" = "backend" ]; then
        if grep -q '\[Startup\] udp-receive backend: [0-9]* UDP receive socket(s) (4 worker(s) x [0-9]* listen address(es))' "$LOG"; then
            ok "$lbl: $(grep -o 'udp-receive backend: [0-9]* UDP receive socket(s) (.* listen address(es))' "$LOG" | head -1)"
        else
            bad "$lbl: no udp-receive backend start-up line" "$(grep Startup "$LOG")"
        fi
    elif grep -q 'udp-receive backend' "$LOG"; then
        bad "$lbl: udp-receive frontend, but the log speaks of backend receive sockets" "$(grep 'udp-receive' "$LOG")"
    fi
    sum0=$(routed_sum); wsum0=$(wrecv_sum); drop0=$(ipcv ipc.dropped.total)
    load "$lbl: 64 source ports" 20000 64 256 16 0
    # (the counters are read until they reach the 20000 or 10 s are up: a router or a worker that is late on a loaded host is waited for)
    if [ "$MODE" = "backend" ]; then
        i=0; while [ $i -lt 50 ] && [ "$(($(wrecv_sum) - wsum0))" -lt $((20000 - LOST_Q)) ]; do sleep 0.2; i=$((i + 1)); done
    else
        i=0; while [ $i -lt 50 ] && [ "$(($(routed_sum) - sum0))" -lt $((20000 - LOST_Q)) ]; do sleep 0.2; i=$((i + 1)); done
    fi
    sum1=$(routed_sum); wsum1=$(wrecv_sum); drop1=$(ipcv ipc.dropped.total)
    if [ "$LAST_SOCKS" = "64" ]; then ok "$lbl: every socket was answered"; else bad "$lbl: $LAST_SOCKS of 64 sockets were answered"; fi
    if [ "$((drop1 - drop0))" = "0" ]; then ok "$lbl: karictl ipcstats counted no drop"; else bad "$lbl: ipc.dropped.total grew by $((drop1 - drop0))" "$(ctl ipcstats | grep -v '=0$')"; fi
    if [ "$MODE" = "backend" ]; then
        if in_lost $((wsum1 - wsum0)); then ok "$lbl: the workers read $((wsum1 - wsum0)) of 20000 queries from their own sockets (ipcworker.<w>.queries; $LOST_Q lost in the kernel's queue allowed)"; else bad "$lbl: the workers' counters grew by $((wsum1 - wsum0)), want 20000" "$(ctl ipcstats | grep -E 'ipcworker|ipcrouter')"; fi
        if [ "$((sum1 - sum0))" = "0" ]; then ok "$lbl: the routers read none of them (ipcrouter.<r>.queries did not move)"; else bad "$lbl: the routers' counters grew by $((sum1 - sum0)), want 0" "$(ctl ipcstats | grep -E 'ipcworker|ipcrouter')"; fi
        idle=""
        for w in 0 1 2 3; do
            [ "$(ipcv ipcworker.$w.queries)" -gt 0 ] 2>/dev/null || idle="$idle $w"
        done
        if [ -z "$idle" ]; then ok "$lbl: every worker read queries ($(ctl ipcstats | grep ipcworker | tr '\n' ' '))"; else bad "$lbl: workers that read nothing:$idle" "$(ctl ipcstats | grep -E 'ipcworker|ipcrouter')"; fi
    else
        if in_lost $((sum1 - sum0)); then ok "$lbl: the routers passed on $((sum1 - sum0)) of 20000 queries (ipcrouter.<r>.queries; $LOST_Q lost in the kernel's queue allowed)"; else bad "$lbl: the routers' counters grew by $((sum1 - sum0)), want 20000" "$(ctl ipcstats | grep ipcrouter)"; fi
        idle=""
        for r in 0 1 2 3; do
            [ "$(ipcv ipcrouter.$r.queries)" -gt 0 ] || idle="$idle $r"
        done
        if [ -z "$idle" ]; then ok "$lbl: every router passed on queries ($(ctl ipcstats | grep ipcrouter | tr '\n' ' '))"; else bad "$lbl: routers that served nothing:$idle" "$(ctl ipcstats | grep ipcrouter)"; fi
        if ctl ipcstats | grep -q '^ipcworker\.'; then bad "$lbl: ipcworker lines with udp-receive frontend" "$(ctl ipcstats | grep ipcworker)"; fi
    fi
    load "$lbl: paced single queries (a short batch each)" 300 8 1 1 3
    load "$lbl: bursts of 33" 3300 33 33 33 0
}

q() { _ip=$1; _n=$2; "$DAG" "@$_ip" -p "$PORT" "$_n" A +nohexdump +time=2 +tries=1 2>&1; }
answered() { if echo "$2" | grep -q "status: NOERROR" && echo "$2" | grep -Eq "$3"; then ok "$1"; else bad "$1: want NOERROR and /$3/" "$2"; fi; }
refused() { if echo "$2" | grep -q "status: REFUSED"; then ok "$1"; else bad "$1: want REFUSED" "$2"; fi; }

for MODE in backend frontend; do
echo "== A ($MODE). the wildcard addresses, 4 routers + 4 workers, udp-receive $MODE"
write_conf ""
if ! start_server; then bad "A: the server did not start" "$(tail -20 "$LOG")"; exit 1; fi
one_server "A $MODE"
if [ "$ALIAS_ADDED" = "1" ]; then
    answered "A: a query to the alias ($ALIAS_IP) is answered by the wildcard socket, from the alias (dag takes no answer from another address)" "$(q $ALIAS_IP www.example.test)" "192\.0\.2\.1"
else
    echo "  SKIP: the checks through a second local address (needs root for the loopback alias $ALIAS_IP)"
fi
answered "A: allow-query-on { 127.0.0.1; } lets a query to 127.0.0.1 in (the destination of the query is taken from the packet)" "$(q 127.0.0.1 www.on.test)" "192\.0\.2\.80"
refused "A: allow-query-on { 192.0.2.77; } refuses a query to 127.0.0.1" "$(q 127.0.0.1 www.off.test)"
[ "$ALIAS_ADDED" = "1" ] && refused "A: allow-query-on { 127.0.0.1; } refuses a query to $ALIAS_IP" "$(q $ALIAS_IP www.on.test)"
stop_server

echo "== B ($MODE). sockets bound to specific addresses, 4 routers + 4 workers, udp-receive $MODE"
if [ "$ALIAS_ADDED" = "1" ]; then write_conf "bind-address { 127.0.0.1; $ALIAS_IP; };"; else write_conf "bind-address { 127.0.0.1; };"; fi
if ! start_server; then bad "B: the server did not start" "$(tail -20 "$LOG")"; exit 1; fi
one_server "B $MODE"
answered "B: allow-query-on { 127.0.0.1; } lets a query to 127.0.0.1 in (the address the socket is bound to)" "$(q 127.0.0.1 www.on.test)" "192\.0\.2\.80"
refused "B: allow-query-on { 192.0.2.77; } refuses a query to 127.0.0.1" "$(q 127.0.0.1 www.off.test)"
if [ "$ALIAS_ADDED" = "1" ]; then
    refused "B: allow-query-on { 127.0.0.1; } refuses a query to the second address $ALIAS_IP (its socket knows its own address)" "$(q $ALIAS_IP www.on.test)"
    answered "B: the second address answers the queries it gets" "$(q $ALIAS_IP www.example.test)" "192\.0\.2\.1"
fi
stop_server
done

echo "== passed $PASS, failed $FAILS"
[ "$FAILS" -eq 0 ]
