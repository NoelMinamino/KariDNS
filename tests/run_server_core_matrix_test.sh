#!/bin/sh
# =============================================================================
# KariDNS server runtime matrix
#
# Exercises server paths that the feature tests leave alone:
#   A. dual-stack wildcard listeners (0.0.0.0 + ::), IPv6 clients, IPv6 NOTIFY
#      targets and notify-source, TC on oversized UDP answers, TCP edge cases
#      (idle hold, zero length, a DNS *response* sent to the query port,
#      pipelining, bursts), dnstap receiver going away, query-log rotation,
#      control-channel error handling (unknown zones, bad arguments, over-long
#      lines, idle unauthenticated clients, reload failures, broken config on
#      reconfig), SIGHUP to the supervisor and the "stop" command.
#   B. command line: usage, version, missing config, daemon mode with -p/-P,
#      an existing pid-file lock, pid-file symlink refusal, unix control
#      sockets (relative / over-long paths), dnstap require-connect.
#   C. primary + secondary instances with TSIG: transfer, retransfer, notify.
#
# The checks are about robustness: every instance must keep answering (or
# refuse cleanly) and nothing may crash. Needs root; skipped otherwise.
# =============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
KARIDNS="$ROOT/karidns"
DAG="$ROOT/dag"
KARICTL="$ROOT/karictl"
SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"
PA=10253; CA=10255; N4=10256; N6=10257
PB=10263; CB=10265
PM=10273; CM=10275; PS=10283; CS=10285

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: run_server_core_matrix_test.sh needs root (privilege drop)"
    exit 0
fi
[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICTL" ] || make -C "$ROOT" karidns dag karictl >/dev/null

TMP="$(mktemp -d /tmp/karidns_matrix.XXXXXX)"
chmod 755 "$TMP"
PIDS=""
cleanup() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    pkill -9 -f "karidns.*$TMP" 2>/dev/null
    [ -n "${KEEP_TMP:-}" ] && echo "(kept $TMP)" || rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

FAILED=0
CRASHES=0
fail() { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
ok()   { echo "  ok: $*"; }

# karidns hands its pid/log directories to the unprivileged user and then
# distrusts them on the next start, so every instance gets a fresh one.
fresh_dir() { rm -rf "$1"; mkdir -m 755 "$1"; }

# answer <server> <port> <name> <type> [dag options] -> prints +short answer
answer() {
    s="$1"; p="$2"; n="$3"; t="$4"; shift 4
    "$DAG" @"$s" -p "$p" "$n" "$t" +time=1 +tries=1 +short "$@" 2>/dev/null
}

# wait_up <server> <port> <zone> : wait up to ~4s for an SOA answer
wait_up() {
    i=0
    while [ $i -lt 40 ]; do
        case "$(answer "$1" "$2" "$3" SOA)" in *hostmaster*) return 0 ;; esac
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

# check_exit <pid> <label>: reap a server and flag crash signals
check_exit() {
    wait "$1" 2>/dev/null
    rc=$?
    case $rc in
        134|138|139) echo "  !! $2 crashed (rc=$rc)"; CRASHES=$((CRASHES + 1)) ;;
    esac
}

ctl() { f="$1"; shift; "$KARICTL" -f "$f" "$@" 2>&1; }

make_zone() { # <file> <origin>
    cat > "$1" <<ZEOF
\$ORIGIN $2.
\$TTL 300
@   IN SOA ns1.$2. hostmaster.$2. 2026092501 7200 3600 1209600 300
@   IN NS  ns1.$2.
ns1 IN A   127.0.0.1
ns1 IN AAAA ::1
www IN A   192.0.2.1
www IN AAAA 2001:db8::1
ZEOF
    i=1
    while [ $i -le 12 ]; do
        echo "big IN TXT \"record-$i-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"" >> "$1"
        i=$((i + 1))
    done
}

make_ctl_conf() { # <file> <port>
    cat > "$1" <<KEOF
server 127.0.0.1;
port $2;
key "karictl" {
    algorithm hmac-sha256;
    secret "$SECRET";
};
KEOF
}

# NOTIFY sink: answers every NOTIFY so the server sees an acknowledgement
start_notify_sink() { # <family 4|6> <port>
    perl -MSocket -e '
        my ($fam, $port) = @ARGV;
        my ($pf, $addr) = $fam == 6
            ? (PF_INET6, pack_sockaddr_in6($port, inet_pton(AF_INET6, "::1")))
            : (PF_INET,  pack_sockaddr_in($port, inet_aton("127.0.0.1")));
        socket(my $s, $pf, SOCK_DGRAM, 0) or exit 1;
        bind($s, $addr) or exit 1;
        my $end = time + 60;
        while (time < $end) {
            my $rin = ""; vec($rin, fileno($s), 1) = 1;
            next unless select($rin, undef, undef, 1);
            my $from = recv($s, my $buf, 4096, 0) or next;
            next if length($buf) < 12;
            substr($buf, 2, 1) = chr(ord(substr($buf, 2, 1)) | 0x80);
            send($s, $buf, 0, $from);
        }' "$1" "$2" >/dev/null 2>&1 &
    PIDS="$PIDS $!"
}

# raw control-channel client: send <bytes> then keep the socket open <sec>
ctl_raw() { # <port> <payload-length> <hold-seconds>
    perl -MIO::Socket::INET -e '
        my ($port, $len, $hold) = @ARGV;
        my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port, Proto => "tcp") or exit 0;
        # in three writes, so that data arrives again after the buffer is full
        if ($len > 0) { for (1 .. 3) { print $s ("x" x int($len / 3)); select(undef, undef, undef, 0.3); } }
        sleep $hold;' "$1" "$2" "$3" >/dev/null 2>&1
}

# udp_flood <addr> <port> <count> <qname>: fire queries without waiting
udp_flood() {
    perl -MSocket -e '
        my ($addr, $port, $count, $name) = @ARGV;
        my $v6 = $addr =~ /:/;
        socket(my $s, $v6 ? PF_INET6 : PF_INET, SOCK_DGRAM, 0) or exit 0;
        my $to = $v6 ? pack_sockaddr_in6($port, inet_pton(AF_INET6, $addr))
                     : pack_sockaddr_in($port, inet_aton($addr));
        my $q = join("", map { chr(length $_) . $_ } split /\./, $name) . "\0";
        for my $i (1 .. $count) {
            send($s, pack("nnnnnn", $i & 0xffff, 0x0100, 1, 0, 0, 0) . $q . pack("nn", 1, 1), 0, $to);
        }' "$@" >/dev/null 2>&1
}

# tcp_session <port> <mode>: one query, then misbehave on the same connection
#   qr: send a DNS response   short: a 4-byte message   eof: half-close
#   burst: 40 pipelined queries   partial: half a message, then stall
tcp_session() {
    perl -MIO::Socket::INET -e '
        my ($port, $mode) = @ARGV;
        my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $port, Proto => "tcp", Timeout => 2) or exit 0;
        my $q = sub { my ($id, $fl) = @_; my $m = pack("nnnnnn", $id, $fl, 1, 0, 0, 0) . "\3www\1m\4test\0" . pack("nn", 1, 1); pack("n", length $m) . $m };
        print $s $q->(1, 0x0100);
        my $buf; sysread($s, $buf, 4096);
        select(undef, undef, undef, 0.2);   # let the server go back to waiting
        if ($mode eq "qr")      { print $s $q->(2, 0x8100); }
        elsif ($mode eq "short") { print $s pack("n", 4) . "abcd"; }
        elsif ($mode eq "eof")   { shutdown($s, 1); }
        elsif ($mode eq "burst") { print $s join("", map { $q->($_, 0x0100) } 3 .. 42); }
        elsif ($mode eq "partial") { my $m = $q->(9, 0x0100); print $s substr($m, 0, 10); sleep 3; }
        my $t = time; while (time - $t < 2) { last unless sysread($s, $buf, 65535); }' "$@" >/dev/null 2>&1
}

echo "=== KariDNS server runtime matrix ==="

# -----------------------------------------------------------------------------
echo "[A] dual-stack wildcard instance"
fresh_dir "$TMP/a"
make_zone "$TMP/m.zone" m.test
make_zone "$TMP/m6.zone" m6.test
make_zone "$TMP/rl.zone" rl.test
make_zone "$TMP/n4.zone" n4.test
make_zone "$TMP/n6.zone" n6.test
cp "$TMP/m.zone" "$TMP/m.zone.orig"
cat > "$TMP/a.conf" <<CEOF
options {
    port $PA;
    bind-address { 0.0.0.0; ::; };
    user "nobody";
    group "nobody";
    pid-file "$TMP/a/a.pid";
    tcp-idle-timeout 2;
    tcp-connection-reuse yes;
    allow-program-zones yes;
    query-log-buffer-size 1024;
    query-log-max-qps 100000;
};
logging {
    channel q { file "$TMP/a/q.log" versions 2 size 1k; print-time yes; print-category yes; print-severity yes; };
    channel r { file "$TMP/a/r.log" versions 1 size 2k; };
    category queries { q; };
    category responses { r; };
};
control-channel {
    port $CA;
    bind-address 127.0.0.1;
    algorithm hmac-sha256;
    secret "$SECRET";
};
dnstap {
    socket "$TMP/dt.sock";
    identity "matrix";
    version "1";
    log-queries yes;
    log-responses yes;
    queue-size 1000;
};
zone "m.test" {
    type master;
    file "$TMP/m.zone";
    allow-transfer { any; };
    also-notify { 127.0.0.1 port $N4; ::1 port $N6; };
    notify-source "127.0.0.1";
};
zone "m6.test" {
    type master;
    file "$TMP/m6.zone";
    allow-transfer { any; };
    also-notify { ::1 port $N6; };
    notify-source "::1";
};
# notify-source addresses that are not configured locally: the frontend has
# to fall back to the wildcard sockets
zone "n4.test" {
    type master;
    file "$TMP/n4.zone";
    also-notify { 127.0.0.1 port $N4; };
    notify-source "127.0.0.3";
};
zone "n6.test" {
    type master;
    file "$TMP/n6.zone";
    also-notify { ::1 port $N6; };
    notify-source "2001:db8::53";
};
# program (plugin) zone: answered through the async I/O pool, rate limited
zone "prog.test" {
    type program;
    program "$DIR/plugins/dnstestscript.pl";
    program-user "nobody";
    program-timeout 2000;
    program-max-failures 5;
    rate-limit { responses-per-second 2; window 1; slip 2; };
};
zone "rl.test" {
    type master;
    file "$TMP/rl.zone";
    rate-limit { responses-per-second 1; errors-per-second 1; nxdomains-per-second 1; window 1; slip 2; };
};
zone "fwd.test" {
    type forward;
    forwarders { 127.0.0.1 port 1; };
};
# the NOTIFY sink echoes every packet back with QR set, which is enough of an
# upstream answer to drive the forwarding (async I/O) path end to end
zone "fwd2.test" {
    type forward;
    forwarders { 127.0.0.1 port $N4; };
};
CEOF
cp "$TMP/a.conf" "$TMP/a.conf.orig"
make_ctl_conf "$TMP/a.ctl" $CA
start_notify_sink 4 $N4
start_notify_sink 6 $N6
# the receiver takes a handful of frames and leaves: the server must cope
perl "$DIR/mock_dnstap_receiver.pl" --socket "$TMP/dt.sock" --max-frames 4 --timeout 30 >/dev/null 2>&1 &
PIDS="$PIDS $!"
sleep 0.5

chmod +x "$DIR/plugins/dnstestscript.pl" 2>/dev/null
"$KARIDNS" -f "$TMP/a.conf" > "$TMP/a.log" 2>&1 &
APID=$!
PIDS="$PIDS $APID"
if wait_up 127.0.0.1 $PA m.test; then
    ok "IPv4 wildcard answers"
    case "$(answer ::1 $PA www.m.test AAAA)" in *2001:db8::1*) ok "IPv6 wildcard answers" ;; *) fail "no answer over ::1" ;; esac
    answer ::1 $PA www.m.test A +tcp >/dev/null
    answer ::1 $PA m.test AXFR >/dev/null
    "$DAG" @::1 -p $PA m6.test AXFR +time=2 +tries=1 >/dev/null 2>&1
    # oversized answer over UDP without EDNS -> TC; then over TCP
    "$DAG" @127.0.0.1 -p $PA big.m.test TXT +noedns +ignore +time=1 +tries=1 > "$TMP/tc.out" 2>&1
    grep -q "flags:.* tc" "$TMP/tc.out" && ok "oversized UDP answer truncated" || fail "no TC bit on oversized UDP answer"
    "$DAG" @::1 -p $PA big.m.test TXT +noedns +ignore +time=1 +tries=1 >/dev/null 2>&1
    answer 127.0.0.1 $PA big.m.test TXT +tcp >/dev/null
    # TCP edge cases
    "$DAG" @127.0.0.1 -p $PA www.m.test A +tcp --break=qr-bit +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @::1 -p $PA www.m.test A +tcp --break=qr-bit +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A +tcp --break=tcp-zero-length +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A +tcp --break=tcp-length-overclaim=20 +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A +tcp --break=truncated-length +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A +tcp --break=tcp-idle-hold=4 +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A +keepopen +tcp www.m.test AAAA big.m.test TXT m.test SOA +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A --break=qr-bit +time=1 +tries=1 >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PA www.m.test A --break=short-header +time=1 +tries=1 >/dev/null 2>&1
    j=0
    while [ $j -lt 24 ]; do
        "$DAG" @127.0.0.1 -p $PA www.m.test A +tcp +time=2 +tries=1 >/dev/null 2>&1 &
        "$DAG" @::1 -p $PA r$j.m.test A +time=2 +tries=1 >/dev/null 2>&1 &
        j=$((j + 1))
    done
    sleep 2
    # enough queries to rotate the 1k query log several times
    j=0
    while [ $j -lt 30 ]; do answer 127.0.0.1 $PA q$j.m.test A >/dev/null; j=$((j + 1)); done
    ls "$TMP/a/" | grep -q "q.log.0\|q.log.1" && ok "query log rotated" || echo "  note: query log not rotated"
    # program zone over UDP/TCP, then enough to trip its rate limit (drop + slip)
    answer 127.0.0.1 $PA normal.prog.test A >/dev/null
    answer 127.0.0.1 $PA normal.prog.test A +tcp >/dev/null
    answer ::1 $PA oversized.prog.test TXT >/dev/null
    udp_flood 127.0.0.1 $PA 200 normal.prog.test
    sleep 1
    # forward zones: answered upstream and failing upstream, over UDP and TCP
    for n in a b c; do
        answer 127.0.0.1 $PA $n.fwd2.test A >/dev/null
        answer 127.0.0.1 $PA $n.fwd2.test A +tcp >/dev/null
        answer ::1 $PA $n.fwd2.test AAAA >/dev/null
    done
    answer 127.0.0.1 $PA x.fwd.test A >/dev/null
    answer 127.0.0.1 $PA x.fwd.test A +tcp >/dev/null
    # rate limiting (drop + slip/TC), query-log ring overflow, TCP misbehaviour
    udp_flood 127.0.0.1 $PA 300 www.rl.test
    udp_flood ::1 $PA 300 nx.rl.test
    udp_flood 127.0.0.1 $PA 4000 www.m.test
    udp_flood ::1 $PA 2000 www.m.test
    for round in 1 2 3; do
        for mode in qr short eof burst partial; do tcp_session $PA $mode; done
    done
    tcp_session $PA burst & T1=$!
    tcp_session $PA burst & T2=$!
    tcp_session $PA qr & T3=$!
    wait $T1 $T2 $T3
    sleep 5   # the query logger reports ring-buffer drops every 5s
    udp_flood 127.0.0.1 $PA 50 www.m.test
    sleep 1

    # control channel: every error path
    ctl "$TMP/a.ctl" status >/dev/null
    ctl "$TMP/a.ctl" notify m.test >/dev/null
    ctl "$TMP/a.ctl" notify m6.test >/dev/null
    ctl "$TMP/a.ctl" notify n4.test >/dev/null
    ctl "$TMP/a.ctl" notify n6.test >/dev/null
    ctl "$TMP/a.ctl" notify nosuch.test >/dev/null
    ctl "$TMP/a.ctl" zonestatus m.test >/dev/null
    ctl "$TMP/a.ctl" zonestatus nosuch.test >/dev/null
    ctl "$TMP/a.ctl" retransfer m.test >/dev/null
    ctl "$TMP/a.ctl" retransfer nosuch.test >/dev/null
    ctl "$TMP/a.ctl" reload nosuch.test >/dev/null
    ctl "$TMP/a.ctl" reload fwd.test >/dev/null
    ctl "$TMP/a.ctl" reload "m.test default" >/dev/null
    ctl "$TMP/a.ctl" reload m.test default >/dev/null
    grep -v "IN SOA" "$TMP/m.zone.orig" > "$TMP/m.zone"
    ctl "$TMP/a.ctl" reload m.test >/dev/null
    mv "$TMP/m.zone" "$TMP/m.zone.away"
    ctl "$TMP/a.ctl" reload m.test >/dev/null
    printf 'garbage (((\n' > "$TMP/m.zone"
    ctl "$TMP/a.ctl" reload m.test >/dev/null
    cp "$TMP/m.zone.orig" "$TMP/m.zone"
    ctl "$TMP/a.ctl" reload m.test >/dev/null
    # reconfig: changed settings of the running plugin, a plugin zone that
    # cannot be started any more, and a config without "user" (rejected as root)
    sed 's/program-timeout 2000;/program-timeout 3000;/' "$TMP/a.conf.orig" > "$TMP/a.conf"
    printf 'zone "prog2.test" { type program; program "%s"; program-user "nobody"; };\n' "$DIR/plugins/dnstestscript.pl" >> "$TMP/a.conf"
    ctl "$TMP/a.ctl" reconfig >/dev/null
    grep -v 'user "nobody";' "$TMP/a.conf.orig" > "$TMP/a.conf"
    ctl "$TMP/a.ctl" reconfig >/dev/null
    printf 'options { this is not valid\n' > "$TMP/a.conf"
    ctl "$TMP/a.ctl" reconfig >/dev/null
    cp "$TMP/a.conf.orig" "$TMP/a.conf"
    ctl "$TMP/a.ctl" reconfig >/dev/null
    ctl "$TMP/a.ctl" observatory >/dev/null
    ctl "$TMP/a.ctl" bogus-command >/dev/null
    ctl_raw $CA 2000 1          # over-long line without a newline
    ctl_raw $CA 0 7 &           # idle, never authenticates -> timer disconnects it
    RAWPID=$!
    kill -HUP $APID 2>/dev/null # supervisor reload
    sleep 1
    kill -HUP $APID 2>/dev/null
    ctl "$TMP/a.ctl" reconfig >/dev/null &
    ctl "$TMP/a.ctl" reconfig >/dev/null
    wait $RAWPID 2>/dev/null
    # answers must still flow over both families after all of the above
    wait_up 127.0.0.1 $PA m.test && ok "still answering after control/reload storm" || fail "IPv4 answers stopped"
    case "$(answer ::1 $PA m6.test SOA)" in *hostmaster*) ok "IPv6 still answering" ;; *) fail "IPv6 answers stopped" ;; esac
    ctl "$TMP/a.ctl" stop >/dev/null
    i=0; while kill -0 $APID 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    kill -0 $APID 2>/dev/null && { echo "  note: stop did not end the supervisor; sending SIGTERM"; kill -TERM $APID; }
else
    fail "instance A did not come up"
    tail -n 20 "$TMP/a.log" | sed 's/^/    /'
    kill -TERM $APID 2>/dev/null
fi
sleep 0.5
kill -9 $APID 2>/dev/null
check_exit $APID "instance A"

# -----------------------------------------------------------------------------
echo "[B] command line and startup variants"
"$KARIDNS" >/dev/null 2>&1; [ $? -ne 0 ] && ok "usage without a config" || fail "no-arg start succeeded"
"$KARIDNS" -v >/dev/null 2>&1 && ok "-v" || fail "-v failed"
"$KARIDNS" -f "$TMP/nonexistent.conf" >/dev/null 2>&1; [ $? -ne 0 ] && ok "missing config refused" || fail "missing config accepted"

fresh_dir "$TMP/b"
make_zone "$TMP/b.zone" b.test
cat > "$TMP/b.conf" <<CEOF
options {
    port 1;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};
control-channel {
    socket "$TMP/b/ctl.sock";
    algorithm hmac-sha256;
    secret "$SECRET";
};
zone "b.test" { type master; file "$TMP/b.zone"; };
CEOF
# daemon mode, port override (-p <port>) and pid file (-P)
"$KARIDNS" -p $PB -P "$TMP/b/b.pid" "$TMP/b.conf" > "$TMP/b.log" 2>&1
if wait_up 127.0.0.1 $PB b.test; then
    ok "daemon mode with -p/-P"
    # a second instance must refuse the locked pid file
    "$KARIDNS" -f -p $((PB + 1)) -P "$TMP/b/b.pid" "$TMP/b.conf" >/dev/null 2>&1
    [ $? -ne 0 ] && ok "locked pid file refused" || fail "second instance ignored the pid lock"
    BPID="$(cat "$TMP/b/b.pid" 2>/dev/null)"
    [ -n "$BPID" ] && kill -TERM "$BPID" 2>/dev/null
    i=0; while [ -n "$BPID" ] && kill -0 "$BPID" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
else
    fail "daemon-mode instance did not come up"
    tail -n 10 "$TMP/b.log" | sed 's/^/    /'
fi
pkill -9 -f "karidns.*$TMP/b.conf" 2>/dev/null

# pid file that is a symlink -> refused (ELOOP)
fresh_dir "$TMP/b2"
ln -s /nonexistent-target "$TMP/b2/b.pid"
"$KARIDNS" -f -p $PB -P "$TMP/b2/b.pid" "$TMP/b.conf" >/dev/null 2>&1
[ $? -ne 0 ] && ok "symlinked pid file refused" || fail "symlinked pid file accepted"
pkill -9 -f "karidns.*$TMP/b.conf" 2>/dev/null

# pid file in a group/world-writable directory, and under a missing directory
mkdir -m 777 "$TMP/ww"
"$KARIDNS" -f -p $PB -P "$TMP/ww/x.pid" "$TMP/b.conf" >/dev/null 2>&1
[ $? -ne 0 ] && ok "pid file in a world-writable directory refused" || fail "world-writable pid directory accepted"
pkill -9 -f "karidns.*$TMP/b.conf" 2>/dev/null
"$KARIDNS" -f -p $PB -P "$TMP/missing/deeper/x.pid" "$TMP/b.conf" >/dev/null 2>&1
[ $? -ne 0 ] && ok "pid file under a missing directory refused" || fail "pid file under a missing directory accepted"
pkill -9 -f "karidns.*$TMP/b.conf" 2>/dev/null

# control socket variants: over-long path, relative path, path under /
LONG="$TMP/$(printf 'x%.0s' $(seq 1 120))/ctl.sock"
sed "s#socket \".*\";#socket \"$LONG\";#" "$TMP/b.conf" > "$TMP/b_long.conf"
"$KARIDNS" -f -p $PB "$TMP/b_long.conf" >/dev/null 2>&1
[ $? -ne 0 ] && ok "over-long control socket path refused" || fail "over-long control socket path accepted"
for sp in "ctl-rel.sock" "/karidns-matrix-$$.sock"; do
    fresh_dir "$TMP/b3"
    sed "s#socket \".*\";#socket \"$sp\";#" "$TMP/b.conf" > "$TMP/b_sock.conf"
    ( cd "$TMP/b3" && exec "$KARIDNS" -f -p $PB "$TMP/b_sock.conf" > "$TMP/b3.log" 2>&1 ) &
    SPID=$!
    PIDS="$PIDS $SPID"
    wait_up 127.0.0.1 $PB b.test && ok "control socket '$sp'" || echo "  note: instance with control socket '$sp' did not answer"
    kill -TERM $SPID 2>/dev/null; sleep 0.5; kill -9 $SPID 2>/dev/null
    check_exit $SPID "instance with control socket $sp"
    rm -f "/karidns-matrix-$$.sock" "$TMP/b3/ctl-rel.sock"
done

# dnstap require-connect with nobody listening -> startup aborts
cat > "$TMP/b_dt.conf" <<CEOF
options { port $PB; bind-address { 127.0.0.1; }; user "nobody"; group "nobody"; };
dnstap { socket "$TMP/no-such-dnstap.sock"; require-connect yes; queue-size 100; };
zone "b.test" { type master; file "$TMP/b.zone"; };
CEOF
"$KARIDNS" -f "$TMP/b_dt.conf" > "$TMP/b_dt.log" 2>&1 &
DPID=$!
i=0; while kill -0 $DPID 2>/dev/null && [ $i -lt 40 ]; do sleep 0.1; i=$((i + 1)); done
if kill -0 $DPID 2>/dev/null; then
    echo "  note: require-connect instance kept running"; kill -TERM $DPID
else
    ok "dnstap require-connect aborts startup"
fi
sleep 0.3; kill -9 $DPID 2>/dev/null
check_exit $DPID "dnstap require-connect instance"

# privilege variants: group only (no user) and neither -- as root, karidns
# must refuse to start without a "user" to drop privileges to
for priv in 'group "nobody";' ''; do
    fresh_dir "$TMP/p"
    cat > "$TMP/priv.conf" <<CEOF
options { port $PB; bind-address { 127.0.0.1; }; $priv };
zone "b.test" { type master; file "$TMP/b.zone"; };
CEOF
    "$KARIDNS" -f "$TMP/priv.conf" > "$TMP/priv.log" 2>&1 &
    PPID_=$!
    PIDS="$PIDS $PPID_"
    i=0; while kill -0 $PPID_ 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 $PPID_ 2>/dev/null; then
        fail "root instance without 'user' kept running (${priv:-no user/group})"
    else
        ok "root without 'user' refused (${priv:-no user/group})"
    fi
    kill -TERM $PPID_ 2>/dev/null; sleep 0.5; kill -9 $PPID_ 2>/dev/null
    check_exit $PPID_ "privilege variant '$priv'"
done

# explicit (non-wildcard) listener with notify-source addresses that are not
# local: the frontend opens a one-off socket for each NOTIFY
fresh_dir "$TMP/n"
make_ctl_conf "$TMP/n.ctl" $CB
cat > "$TMP/n.conf" <<CEOF
options { port $PB; bind-address { 127.0.0.1; ::1; }; user "nobody"; group "nobody"; };
control-channel { port $CB; bind-address 127.0.0.1; algorithm hmac-sha256; secret "$SECRET"; };
zone "n4.test" { type master; file "$TMP/n4.zone"; also-notify { 127.0.0.1 port $N4; }; notify-source "127.0.0.3"; };
zone "n6.test" { type master; file "$TMP/n6.zone"; also-notify { ::1 port $N6; }; notify-source "2001:db8::53"; };
zone "b.test" { type master; file "$TMP/b.zone"; also-notify { 127.0.0.1 port $N4; ::1 port $N6; }; };
CEOF
"$KARIDNS" -f "$TMP/n.conf" > "$TMP/n.log" 2>&1 &
NPID=$!
PIDS="$PIDS $NPID"
if wait_up 127.0.0.1 $PB b.test; then
    for z in n4.test n6.test b.test; do ctl "$TMP/n.ctl" notify $z >/dev/null; done
    sleep 1
    wait_up 127.0.0.1 $PB n4.test && ok "NOTIFY from non-local notify-source addresses" || fail "instance stopped answering after NOTIFY"
else
    fail "notify instance did not come up"
fi
kill -TERM $NPID 2>/dev/null; sleep 0.5; kill -9 $NPID 2>/dev/null
check_exit $NPID "notify instance"

# -----------------------------------------------------------------------------
echo "[C] primary + secondary with TSIG"
fresh_dir "$TMP/m"; fresh_dir "$TMP/s"
make_zone "$TMP/p.zone" p.test
cat > "$TMP/prim.conf" <<CEOF
options { port $PM; bind-address { 127.0.0.1; ::1; }; user "nobody"; group "nobody"; pid-file "$TMP/m/m.pid"; };
key "xfr" { algorithm hmac-sha256; secret "$SECRET"; };
control-channel { port $CM; bind-address 127.0.0.1; algorithm hmac-sha256; secret "$SECRET"; };
zone "p.test" {
    type master;
    file "$TMP/p.zone";
    allow-transfer { 127.0.0.1; ::1; };
    tsig-key "xfr";
    also-notify { 127.0.0.1 port $PS; };
};
CEOF
cat > "$TMP/sec.conf" <<CEOF
options { port $PS; bind-address { 127.0.0.1; }; user "nobody"; group "nobody"; pid-file "$TMP/s/s.pid"; serve-stale yes; };
key "xfr" { algorithm hmac-sha256; secret "$SECRET"; };
control-channel { port $CS; bind-address 127.0.0.1; algorithm hmac-sha256; secret "$SECRET"; };
zone "p.test" {
    type slave;
    file "$TMP/s/p.zone";
    masters { 127.0.0.1 port $PM; };
    tsig-key "xfr";
};
CEOF
make_ctl_conf "$TMP/m.ctl" $CM
make_ctl_conf "$TMP/s.ctl" $CS
"$KARIDNS" -f "$TMP/prim.conf" > "$TMP/prim.log" 2>&1 &
MPID=$!
"$KARIDNS" -f "$TMP/sec.conf" > "$TMP/sec.log" 2>&1 &
SPID=$!
PIDS="$PIDS $MPID $SPID"
if wait_up 127.0.0.1 $PM p.test; then
    ctl "$TMP/s.ctl" retransfer p.test >/dev/null
    i=0
    while [ $i -lt 40 ]; do
        case "$(answer 127.0.0.1 $PS p.test SOA)" in *hostmaster*) break ;; esac
        sleep 0.1; i=$((i + 1))
    done
    case "$(answer 127.0.0.1 $PS www.p.test A)" in *192.0.2.1*) ok "secondary transferred the zone" ;; *) echo "  note: secondary has no data yet" ;; esac
    sed 's/2026092501/2026092502/' "$TMP/p.zone" > "$TMP/p.zone.new" && mv "$TMP/p.zone.new" "$TMP/p.zone"
    ctl "$TMP/m.ctl" reload p.test >/dev/null
    ctl "$TMP/m.ctl" notify p.test >/dev/null
    sleep 1
    ctl "$TMP/s.ctl" zonestatus p.test >/dev/null
    ctl "$TMP/s.ctl" retransfer p.test >/dev/null
    ctl "$TMP/s.ctl" reload p.test >/dev/null
    # primary goes away: the secondary keeps serving (serve-stale)
    kill -TERM $MPID; sleep 0.5
    ctl "$TMP/s.ctl" retransfer p.test >/dev/null
    sleep 1
    answer 127.0.0.1 $PS www.p.test A >/dev/null
    ctl "$TMP/s.ctl" status >/dev/null
else
    fail "primary did not come up"
fi
kill -TERM $MPID $SPID 2>/dev/null
sleep 0.5
kill -9 $MPID $SPID 2>/dev/null
check_exit $MPID "primary"
check_exit $SPID "secondary"

echo "=== matrix done: $FAILED failure(s), $CRASHES crash(es) ==="
[ $FAILED -eq 0 ] && [ $CRASHES -eq 0 ] || exit 1
exit 0
