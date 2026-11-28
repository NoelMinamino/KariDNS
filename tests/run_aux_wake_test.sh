#!/bin/sh
# run_aux_wake_test.sh - the UDP routers, the connect broker and the manager of an idle karidns wake at least once a second (0.7, CI flake rows 9 and 90).
#
# FreeBSD 14 swaps out a whole process all of whose threads have slept longer than vm.swap_idle_threshold1 (2 s by default) when memory is short.
# A router that slept until the next reply was swapped out on the loaded 14.4 CI runners, and the replies of its workers waited seconds for the
# swap-in.  The routers' kevent(), the broker's poll() and the manager's sigtimedwait() now end at least every KARIDNS_AUX_WAKE_MS (1 s) with nothing to do, so they are never
# asleep that long.  This test starts a server with a zone file, leaves it idle and checks that each of them made voluntary context
# switches (ps nvcsw) during a quiet window of 4 s: a process that sleeps until an event makes none.  It then checks that the server still answers.
# Root or not (the server runs as the caller, or as nobody when root).  About 8 seconds.  KARI_SWAP_HOG_MB=<MB> adds the swap-out itself under a memory hog
# (FreeBSD 14 and root only; SKIP otherwise), see below.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
. "$DIR/lib_proc.sh"
[ "$(uname -s)" = FreeBSD ] || { echo "SKIP: the server runs on FreeBSD only"; exit 0; }
KARIDNS=${KARIDNS:-$ROOT/karidns}
[ -x "$KARIDNS" ] && [ -x "$ROOT/dag" ] || { echo "SKIP: $KARIDNS or dag is not built"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_auxwake.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SRV" ] && { kill -TERM "$SRV" 2>/dev/null; i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done; kari_kill_tree "$SRV" 2>/dev/null; }
    rm -rf "$T"
}
trap cleanup EXIT
trap "exit 130" INT TERM
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

PORT=$(kari_port 0)
printf '$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' > "$T/ex.zone"
U=""; [ "$(id -u)" = 0 ] && U='user "nobody"; group "nobody";'
cat > "$T/k.conf" <<EOF
options { $U pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; };
zone "example.test" { type primary; file "$T/ex.zone"; };
EOF
chmod 644 "$T/k.conf" "$T/ex.zone"
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
NR=""
kari_wait_log "$T/srv.log" "\[Startup\] [0-9]* routers" 20 1 && NR=$(sed -n 's/^KariDNS [0-9]* - - \[Startup\] \([0-9][0-9]*\) routers.*/\1/p' "$T/srv.log" | head -n 1)
if [ -n "$NR" ] && kari_wait_log "$T/srv.log" "UDP Router process started" 20 "$NR" && [ "$("$ROOT/dag" @127.0.0.1 -p "$PORT" www.example.test A +short +time=2 +tries=3 2>/dev/null)" = 192.0.2.10 ]; then
    ok "the server answers ($NR router(s) started)"
else
    bad "the server did not start, did not start its ${NR:-?} router(s), or does not answer" "$(tail -n 20 "$T/srv.log")"; exit 1
fi

# the processes: the manager is the server's pid (-f); the routers say their pid in their start line (all NR of them are there now); the broker is the
# one other single-threaded child (the Backend has many threads)
ROUTERS=$(sed -n 's/^KariDNS \([0-9][0-9]*\) - - \[Frontend [0-9]*\] UDP Router process started.*/\1/p' "$T/srv.log" | tr '\n' ' ')
BROKER=""
for p in $(pgrep -f -- "$T/k.conf"); do
    [ "$p" = "$SRV" ] && continue
    case " $ROUTERS " in *" $p "*) continue ;; esac
    [ "$(ps -o nlwp= -p "$p" 2>/dev/null | tr -d ' ')" = 1 ] && BROKER="$BROKER $p"
done
BROKER=$(echo $BROKER)
[ "$(echo $ROUTERS | wc -w | tr -d ' ')" = "$NR" ] && ok "the routers: $ROUTERS" || bad "router start lines for '$ROUTERS', $NR routers" "$(tail -n 20 "$T/srv.log")"
[ "$(echo $BROKER | wc -w | tr -d ' ')" = 1 ] && ok "the connect broker: $BROKER" || bad "not exactly one single-threaded child besides the routers (the broker): '$BROKER'" "$(ps -H -o pid,ppid,nlwp,stat,wchan,command -p "$(pgrep -f -- "$T/k.conf" | tr '\n' ',' | sed 's/,$//')")"

# a quiet window: nothing is asked during it, so what a router, the broker or the manager does is its own wake-up
csw() { ps -o nvcsw= -p "$1" 2>/dev/null | tr -d ' '; }
sleep 1
for p in $ROUTERS $BROKER $SRV; do eval "c0_$p=\$(csw $p)"; done
sleep 4
for p in $ROUTERS $BROKER $SRV; do
    eval "c0=\$c0_$p"; c1=$(csw "$p")
    what=router; [ "$p" = "$BROKER" ] && what=broker; [ "$p" = "$SRV" ] && what=manager
    if [ -n "$c0" ] && [ -n "$c1" ] && [ $((c1 - c0)) -ge 2 ]; then ok "the $what $p woke $((c1 - c0)) times in 4 s idle"
    else bad "the $what $p did not wake by itself in 4 s idle (voluntary context switches $c0 -> $c1): FreeBSD 14 would swap it out" "$(ps -H -o pid,lwp,stat,wchan,nvcsw -p "$p")"; fi
done
[ "$("$ROOT/dag" @127.0.0.1 -p "$PORT" www.example.test A +short +time=2 +tries=3 2>/dev/null)" = 192.0.2.10 ] && ok "the server answers after the idle time" || bad "no answer after the idle time"

# The swap-out itself (opt-in: KARI_SWAP_HOG_MB=<MB>, FreeBSD 14, root; about the RAM of the host minus 200 MB, e.g. 5900 on a 6 GB VM).  A memory hog
# holds that much for up to 45 s.  Once the pager has written 50 MB or more to swap (the memory is short now: on a 6 GB 14.4 VM this came after
# 20-25 s) the check goes on for 5 s more; through all of it the routers, the broker and the manager must not be swapped out (ps STAT W), and a
# query must then be answered within 1 s.  A hog that never drives swap use up fails, as the check would prove nothing.  Not in the suite's default
# run: it takes the host's memory from every other test.  Before the fix the routers, the broker and the manager went to IW.  (Where swap is fast,
# a swapped-out router is read back in under a millisecond: then only the W check fails without the fix, not the 1 s answer.)
# ps takes one -o per column: in "-o pid=,stat=" FreeBSD reads ",stat=" as the header of pid and prints no STAT at all.
if [ -n "${KARI_SWAP_HOG_MB:-}" ]; then
    if [ "$(id -u)" != 0 ] || [ "$(uname -r | cut -d. -f1)" != 14 ]; then
        echo "  SKIP: the swap-out part needs root and FreeBSD 14 (FreeBSD 15 does not swap processes out); this is $(uname -r)"
    else
        swap_mb() { swapinfo -m | tail -n 1 | awk '{ print $3 }'; }
        sw0=$(swap_mb)
        perl -e 'my @a; for (1 .. $ARGV[0]) { my $s = "\0" x (1 << 20); push @a, $s } for my $t (1 .. 45) { sleep 1; substr($_, ($t * 4096) % (1 << 20), 1) = "x" for @a }' "$KARI_SWAP_HOG_MB" &
        HOG=$!
        i=0; left=""; st=""; swapped=""
        while [ $i -lt 45 ] && kari_alive "$HOG" && [ "${left:-1}" -gt 0 ]; do
            sleep 1; i=$((i + 1))
            st=$(ps -o pid= -o stat= -p "$(echo $ROUTERS $BROKER $SRV | tr ' ' ',')" 2>/dev/null)
            case "$st" in *W*) swapped="after $i s: $st"; break ;; esac
            sw=$(swap_mb)
            [ -z "$left" ] && [ $((sw - sw0)) -ge 50 ] && left=5
            [ -n "$left" ] && left=$((left - 1))
        done
        sw=$(swap_mb)
        echo "    under the hog for $i s: $(echo "$st" | tr '\n' ' ') swap used $sw0 -> $sw MB"
        if [ -n "$swapped" ]; then
            bad "a router, the broker or the manager was swapped out under memory pressure" "$swapped"
        elif [ "$left" != 0 ]; then
            bad "the hog of $KARI_SWAP_HOG_MB MB did not make memory short (swap used $sw0 -> $sw MB): raise KARI_SWAP_HOG_MB"
        else
            ok "no router, broker or manager swapped out under memory pressure ($i s, swap used $sw0 -> $sw MB)"
        fi
        t0=$(perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000')
        a=$("$ROOT/dag" @127.0.0.1 -p "$PORT" www.example.test A +short +time=5 +tries=1 2>/dev/null)
        t1=$(perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000')
        [ "$a" = 192.0.2.10 ] && [ $((t1 - t0)) -lt 1000 ] && ok "answered within 1 s under memory pressure ($((t1 - t0)) ms)" || bad "under memory pressure: answer \"$a\" after $((t1 - t0)) ms"
        kill "$HOG" 2>/dev/null; wait "$HOG" 2>/dev/null
    fi
fi
grep -q "ERROR\|ssertion" "$T/srv.log" && bad "the server logged an error" "$(grep 'ERROR\|ssertion' "$T/srv.log" | head -3)" || ok "the server logged no error"

echo
echo "=== run_aux_wake_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]
