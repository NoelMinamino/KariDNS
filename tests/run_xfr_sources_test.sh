#!/bin/sh
# ==============================================================================
# tests/run_xfr_sources_test.sh - the source addresses of NOTIFY and zone transfers (BIND 9.20, batch 4)
# ==============================================================================
# notify-source / notify-source-v6 and transfer-source / transfer-source-v6 in options, view and zone (zone > view > options, option by
# option), `*`, the `source` / `source-v6` of primaries and also-notify lists, and notify-delay / notify-rate / notify-to-soa.
#
#   N  NOTIFY leaves from the configured address: a mock receiver (tests/mock_notify_sink.pl) logs the address each NOTIFY came from
#      (options, view, zone, `*` = the system's choice, the source of the also-notify list, notify-source-v6)
#   T  zone transfers and refresh checks leave from the configured address: the primary answers 127.0.0.2 only (allow-transfer), so a
#      secondary that does not use 127.0.0.2 stays empty -- an AXFR, and the later IXFR check, prove the address
#   R  a reload that names a source address the server did not start with is "restart needed for: source-address"
#   E  start-up refuses a source address it cannot bind, with file:line (also karicheck conf accepts the file: it cannot know the host)
#   D  notify-delay (a second set of NOTIFY waits), notify-rate (N a second), notify-to-soa (the SOA MNAME host is notified)
#
# The loopback aliases 127.0.0.2 .. 127.0.0.5 (and 2001:db8:f::2) are added when run as root and removed on exit; without them the
# parts that need them are SKIPped (the start-up refusals and the notify-delay / rate / notify-to-soa parts need none).
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

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-xfrsrc.XXXXXX")"
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
SECRET="cDEwLXhmci1zb3VyY2VzLXRlc3QtY29udHJvbC1rZXk="
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"

PP=$(kari_port 0)         # primary (allow-transfer 127.0.0.2 only)
PS=$(kari_port 1)         # secondary, options transfer-source
PV=$(kari_port 2)         # secondary, view transfer-source
PN=$(kari_port 3)         # NOTIFY sender
PD=$(kari_port 4)         # notify-delay / notify-rate / notify-to-soa
SB=$(kari_port 10) SC=$(kari_port 11) SD=$(kari_port 12) SE=$(kari_port 13) SF=$(kari_port 14) SG=$(kari_port 15)
D1=$(kari_port 20) D2=$(kari_port 21) D3=$(kari_port 22) D4=$(kari_port 23) D5=$(kari_port 24)
PE=$(kari_port 30)        # start-up refusals

PIDS=""
ALIASES=""
ALIASES6=""
FAILS=0
PASSES=0
SKIPS=0
pass() { echo "PASS: $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
skip() { echo "SKIP: $*"; SKIPS=$((SKIPS + 1)); }

cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/p.conf" "$W/s.conf" "$W/v.conf" "$W/n.conf" "$W/d.conf"
    for a in $ALIASES; do ifconfig lo0 inet "$a" -alias 2>/dev/null; done
    for a in $ALIASES6; do ifconfig lo0 inet6 "$a" -alias 2>/dev/null; done
    if [ "$FAILS" -ne 0 ]; then
        for f in p s v n d; do echo "--- $f.log (tail)"; tail -25 "$W/$f.log" 2>/dev/null; done
        echo "--- sink.log"; cat "$W/sink.log" 2>/dev/null
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

has_ip() { ifconfig lo0 2>/dev/null | grep -q "inet $1 "; }
add_alias() { # add_alias 127.0.0.N : 0 when the address is there afterwards
    has_ip "$1" && return 0
    [ "$(id -u)" -eq 0 ] || return 1
    ifconfig lo0 inet "$1/32" alias 2>/dev/null || return 1
    ALIASES="$ALIASES $1"
    return 0
}
HAVE_ALIAS=1
for i in 2 3 4 5; do add_alias 127.0.0.$i || HAVE_ALIAS=0; done
HAVE_V6=0
if [ "$HAVE_ALIAS" -eq 1 ] && ifconfig lo0 inet6 2001:db8:f::2 prefixlen 128 alias 2>/dev/null; then
    ALIASES6="2001:db8:f::2"
    HAVE_V6=1
fi

for p in $PP $PS $PV $PN $PD $SB $SC $SD $SE $SF $SG $D1 $D2 $D3 $D4 $D5 $PE; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

wait_grep() { # PATTERN FILE [SECONDS]
    _i=0
    while [ $_i -lt "${3:-10}" ]; do grep -q -- "$1" "$2" 2>/dev/null && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
# dag_soa PORT ZONE : the SOA text the server on 127.0.0.1:PORT answers (empty when it has no data for the zone)
dag_soa() { "$DAG" @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump +time=1 +tries=1 2>/dev/null; }
wait_soa() { # PORT ZONE SERIAL [SECONDS] : the SOA with that serial is served
    _i=0
    while [ $_i -lt "${4:-15}" ]; do [ "$(dag_soa "$1" "$2" | awk '{print $3}')" = "$3" ] && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
zone() { # zone FILE ORIGIN SERIAL [extra lines]   (refresh 2 s, retry 1 s)
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s 2 1 3600 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n%s' \
        "$2" "$3" "${4:-}" > "$1"
}
start() { # start NAME : karidns on $W/NAME.conf
    "$KARIDNS" -f "$W/$1.conf" > "$W/$1.log" 2>&1 &
    PIDS="$PIDS $!"
}

# ------------------------------------------------------------------------------------------------ E: start-up refusals
printf 'options { port %s; bind-address { 127.0.0.1; }; pid-file "none"; %s\n  transfer-source 192.0.2.77;\n};\n' "$PE" "$USER_OPT" > "$W/e1.conf"
printf 'options { port %s; bind-address { 127.0.0.1; }; pid-file "none"; %s };\nzone "a.test" { type master; file "%s/a.zone";\n  notify-source 192.0.2.77; };\n' "$PE" "$USER_OPT" "$W" > "$W/e2.conf"
printf 'options { port %s; bind-address { 127.0.0.1; }; pid-file "none"; %s };\nzone "a.test" { type slave;\n  primaries source 192.0.2.77 { 127.0.0.1 port 1; }; };\n' "$PE" "$USER_OPT" > "$W/e3.conf"
printf 'options { port %s; bind-address { 127.0.0.1; }; pid-file "none"; %s };\nzone "a.test" { type master; file "%s/a.zone"; also-notify\n  source 192.0.2.77 { 127.0.0.1 port 1; }; };\n' "$PE" "$USER_OPT" "$W" > "$W/e4.conf"
zone "$W/a.zone" a.test 1
e=1
for want in "e1.conf:2:transfer-source" "e2.conf:3:notify-source" "e3.conf:3:primaries source" "e4.conf:3:also-notify source"; do
    f=${want%%:*}; rest=${want#*:}; line=${rest%%:*}; what=${rest#*:}
    "$KARIDNS" -f "$W/$f" > "$W/e.log" 2>&1 &
    epid=$!
    i=0
    while [ $i -lt 20 ] && kill -0 "$epid" 2>/dev/null; do sleep 0.5; i=$((i + 1)); done
    if kill -0 "$epid" 2>/dev/null; then
        kari_kill_tree "$epid"
        fail "E$e: karidns started with an unbindable source address ($f)"
    elif grep -q "$W/$f:$line: .*$what 192.0.2.77: cannot use it as a source address" "$W/e.log"; then
        pass "E$e: karidns refuses to start; the message names $f:$line and '$what 192.0.2.77'"
    else
        fail "E$e: karidns stopped but not with the expected message ($f:$line $what)"; cat "$W/e.log"
    fi
    if "$KARICHECK" conf "$W/$f" > "$W/kc.log" 2>&1 && grep -q "Source addresses" "$W/kc.log"; then
        pass "E$e: karicheck conf accepts the file and lists the source address"
    else
        fail "E$e: karicheck conf on $f"; cat "$W/kc.log"
    fi
    e=$((e + 1))
done

# ------------------------------------------------------------------------------------------------ K: karicheck conf notes
cat > "$W/k.conf" <<EOF
options { startup-notify-rate 5; transfers-in 0; transfers-out 0; transfers-per-ns 0; try-tcp-refresh no;
  min-refresh-time 900; max-refresh-time 600; min-retry-time 900; max-retry-time 600; };
zone "pri.test" { type master; file "$W/a.zone"; min-refresh-time 5; transfer-source 127.0.0.1; };
zone "sec.test" { type slave; primaries { 127.0.0.1 port 1; }; multi-master yes; };
EOF
"$KARICHECK" conf "$W/k.conf" > "$W/kc.out" 2>&1
rc=$?
for want in "startup-notify-rate 5 is accepted but has no effect" "transfers-in 0: no zone is transferred in" "transfers-out 0: every zone transfer request is refused" \
            "transfers-per-ns 0" "try-tcp-refresh" "have no effect in a primary zone" "multi-master has no effect with fewer than two primaries" \
            "min-refresh-time 900 is larger than max-refresh-time 600" "min-retry-time 900 is larger than max-retry-time 600" "Source addresses"; do
    if grep -q "$want" "$W/kc.out"; then pass "K: karicheck conf says '$want'"
    else fail "K: karicheck conf has no '$want'"; cat "$W/kc.out"; fi
done
[ "$rc" -eq 0 ] && pass "K: the notes do not make karicheck conf fail" || fail "K: karicheck conf exit status $rc"

# ------------------------------------------------------------------------------------------------ D: notify-delay, notify-rate, notify-to-soa
perl "$DIR/mock_notify_sink.pl" --log "$W/dsink.log" --ports "$D1,$D2,$D3,$D4,$D5" --answer 2>/dev/null &
PIDS="$PIDS $!"
for n in 1 2 3 4; do zone "$W/dn$n.zone" "dn$n.test" 1; done
zone "$W/dm.zone" "dm.test" 1
cat > "$W/d.conf" <<EOF
options { port $PD; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
  notify explicit; notify-rate 1; notify-delay 3; };
control-channel { socket "$W/d.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "dn1.test" { type master; file "$W/dn1.zone"; also-notify { 127.0.0.1 port $D1; }; };
zone "dn2.test" { type master; file "$W/dn2.zone"; also-notify { 127.0.0.1 port $D2; }; };
zone "dn3.test" { type master; file "$W/dn3.zone"; also-notify { 127.0.0.1 port $D3; }; };
zone "dn4.test" { type master; file "$W/dn4.zone"; also-notify { 127.0.0.1 port $D4; }; };
zone "dm.test" { type master; file "$W/dm.zone"; notify yes; notify-to-soa yes; };
EOF
CD="$KARICTL -s $W/d.sock -f $W/ctl.conf"
start d
kari_wait_answer "$DAG" "$PD" dn1.test. || true
: > "$W/dsink.log"
$CD notify dn1.test >/dev/null; $CD notify dn2.test >/dev/null; $CD notify dn3.test >/dev/null; $CD notify dn4.test >/dev/null
sleep 6
n=$(grep -c NOTIFY "$W/dsink.log")
t_first=$(sed -n 's/.* t=\([0-9.]*\)$/\1/p' "$W/dsink.log" | sort -n | head -1)
t_last=$(sed -n 's/.* t=\([0-9.]*\)$/\1/p' "$W/dsink.log" | sort -n | tail -1)
spread=$(perl -e "printf '%d', (${t_last:-0} - ${t_first:-0}) * 10")
if [ "$n" -eq 4 ] && [ "$spread" -ge 25 ]; then
    pass "D1: notify-rate 1 sends four NOTIFY messages one a second (spread $spread/10 s)"
else
    fail "D1: notify-rate 1: $n NOTIFYs (expected 4) spread $spread/10 s (expected >= 2.5 s)"; cat "$W/dsink.log"
fi
: > "$W/dsink.log"
sleep 3
$CD notify dn1.test >/dev/null
sleep 1
$CD notify dn1.test >/dev/null     # inside notify-delay 3: waits for the end of the delay
sleep 7
n=$(grep -c "port=$D1 " "$W/dsink.log")
t1=$(sed -n 's/.* t=\([0-9.]*\)$/\1/p' "$W/dsink.log" | sort -n | head -1)
t2=$(sed -n 's/.* t=\([0-9.]*\)$/\1/p' "$W/dsink.log" | sort -n | tail -1)
gap=$(perl -e "printf '%d', (${t2:-0} - ${t1:-0}) * 10")
if [ "$n" -eq 2 ] && [ "$gap" -ge 15 ]; then
    pass "D2: notify-delay 3: the second set of NOTIFY for the zone waits (gap $gap/10 s after a request 1 s later)"
else
    fail "D2: notify-delay: $n NOTIFYs to the sink (expected 2), gap $gap/10 s (expected >= 1.5 s)"; cat "$W/dsink.log"
fi
sent=$($CD observatory dm.test 2>/dev/null | sed -n 's/.*Sent=\([0-9]*\).*/\1/p')
$CD notify dm.test >/dev/null
sleep 2
sent2=$($CD observatory dm.test 2>/dev/null | sed -n 's/.*Sent=\([0-9]*\).*/\1/p')
if [ "${sent2:-0}" -ge 1 ]; then
    pass "D3: notify-to-soa yes: the NS host that is the SOA MNAME gets a NOTIFY (Sent=$sent2)"
else
    fail "D3: notify-to-soa yes: no NOTIFY was sent to the MNAME host (Sent before=${sent:-?} after=${sent2:-?})"
fi

# ------------------------------------------------------------------------------------------------ N: NOTIFY sources
if [ "$HAVE_ALIAS" -ne 1 ]; then
    skip "N: NOTIFY sources need the loopback aliases 127.0.0.2 - 127.0.0.5 (run as root)"
else
    SINK_PORTS6=""
    [ "$HAVE_V6" -eq 1 ] && SINK_PORTS6="--ports6 $SG"
    perl "$DIR/mock_notify_sink.pl" --log "$W/sink.log" --ports "$SB,$SC,$SD,$SE,$SF" $SINK_PORTS6 --answer 2>/dev/null &
    PIDS="$PIDS $!"
    for z in zb zc zd ze zf zg; do zone "$W/$z.zone" "$z.test" 1; done
    V6OPT=""; V6ZONE=""
    if [ "$HAVE_V6" -eq 1 ]; then
        V6OPT="notify-source-v6 2001:db8:f::2;"
        V6ZONE="zone \"zg.test\" { type master; file \"$W/zg.zone\"; also-notify { ::1 port $SG; }; };"
    fi
    cat > "$W/n.conf" <<EOF
options { port $PN; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
  notify explicit; notify-source 127.0.0.2; $V6OPT };
control-channel { socket "$W/n.sock"; algorithm hmac-sha256; secret "$SECRET"; };
view "v1" { match-clients { any; }; notify-source 127.0.0.3;
  zone "zb.test" { type master; file "$W/zb.zone"; also-notify { 127.0.0.1 port $SB; }; };
  zone "zc.test" { type master; file "$W/zc.zone"; also-notify { 127.0.0.1 port $SC; }; notify-source 127.0.0.4; };
  zone "zd.test" { type master; file "$W/zd.zone"; also-notify { 127.0.0.1 port $SD; }; notify-source *; };
  zone "zf.test" { type master; file "$W/zf.zone"; notify-source 127.0.0.4;
                   also-notify source 127.0.0.5 { 127.0.0.1 port $SF; }; };
  $V6ZONE
};
view "v2" { match-clients { none; };
  zone "ze.test" { type master; file "$W/ze.zone"; also-notify { 127.0.0.1 port $SE; }; };
};
EOF
    CN="$KARICTL -s $W/n.sock -f $W/ctl.conf"
    start n
    kari_wait_answer "$DAG" "$PN" zb.test. || true
    : > "$W/sink.log"
    for z in zb zc zd ze zf; do $CN notify $z.test >/dev/null; done
    [ "$HAVE_V6" -eq 1 ] && $CN notify zg.test >/dev/null
    sleep 3
    chk() { # NAME PORT EXPECTED-SOURCE DESCRIPTION
        if grep -q "NOTIFY port=$2 src=$3 " "$W/sink.log"; then pass "N$1: $4 ($3)"
        else fail "N$1: $4: expected a NOTIFY from $3 at port $2"; grep "port=$2 " "$W/sink.log"; fi
    }
    chk 1 "$SB" 127.0.0.3 "the view's notify-source beats options'"
    chk 2 "$SC" 127.0.0.4 "the zone's notify-source beats the view's"
    chk 3 "$SD" 127.0.0.1 "notify-source * in the zone: the system chooses the address"
    chk 4 "$SE" 127.0.0.2 "options' notify-source for a zone with no statement of its own and a view with none"
    chk 5 "$SF" 127.0.0.5 "the source of the also-notify list beats the zone's notify-source"
    if [ "$HAVE_V6" -eq 1 ]; then
        chk 6 "$SG" 2001:db8:f::2 "notify-source-v6 for an IPv6 target"
    else
        skip "N6: notify-source-v6 needs the loopback alias 2001:db8:f::2"
    fi
    # the sockets that send the NOTIFY are not listening ports of the server (the old pre-bind opened the source address at the server port)
    if sockstat -4 -l 2>/dev/null | grep -q "127.0.0.[2345]:$PN "; then
        fail "N7: a NOTIFY source address is a listening address of the server (port $PN)"
    else
        pass "N7: the NOTIFY source addresses are not listening addresses of the server"
    fi
fi

# ------------------------------------------------------------------------------------------------ T: transfer sources
if [ "$HAVE_ALIAS" -ne 1 ]; then
    skip "T: transfer sources need the loopback aliases 127.0.0.2 and 127.0.0.3 (run as root)"
else
    for z in za zc zd ze zv1 zv2; do zone "$W/t$z.zone" "$z.test" 1; done
    {
        echo "options { port $PP; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify no; };"
        echo "control-channel { socket \"$W/p.sock\"; algorithm hmac-sha256; secret \"$SECRET\"; };"
        for z in za zc zd ze zv1 zv2; do echo "zone \"$z.test\" { type master; file \"$W/t$z.zone\"; allow-transfer { 127.0.0.2; }; };"; done
    } > "$W/p.conf"
    cat > "$W/s.conf" <<EOF
options { port $PS; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
  min-refresh-time 1; min-retry-time 1; transfer-source 127.0.0.2; };
control-channel { socket "$W/s.sock"; algorithm hmac-sha256; secret "$SECRET"; };
primaries pl source 127.0.0.2 { 127.0.0.1 port $PP; };
zone "za.test" { type slave; primaries { 127.0.0.1 port $PP; }; };
zone "zc.test" { type slave; primaries { pl; }; transfer-source 127.0.0.3; };
zone "zd.test" { type slave; primaries { 127.0.0.1 port $PP; }; transfer-source *; };
zone "ze.test" { type slave; primaries { 127.0.0.1 port $PP; }; transfer-source 127.0.0.3; };
EOF
    cat > "$W/v.conf" <<EOF
options { port $PV; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
  min-refresh-time 1; min-retry-time 1; transfer-source 127.0.0.3; };
view "v1" { match-clients { any; }; transfer-source 127.0.0.2;
  zone "zv1.test" { type slave; primaries { 127.0.0.1 port $PP; }; };
  zone "zv2.test" { type slave; primaries { 127.0.0.1 port $PP; }; transfer-source 127.0.0.3; };
};
EOF
    CP="$KARICTL -s $W/p.sock -f $W/ctl.conf"
    CS="$KARICTL -s $W/s.sock -f $W/ctl.conf"
    start p
    kari_wait_answer "$DAG" "$PP" za.test. || true
    start s
    start v
    if wait_soa "$PS" za.test 1 15; then pass "T1: transfer-source in options: the secondary transferred za.test from the primary that answers 127.0.0.2 only"
    else fail "T1: za.test (options transfer-source 127.0.0.2) was not transferred"; fi
    if wait_soa "$PS" zc.test 1 5; then pass "T2: the source of the primaries list (127.0.0.2) beats the zone's transfer-source (127.0.0.3)"
    else fail "T2: zc.test (primaries source 127.0.0.2, zone transfer-source 127.0.0.3) was not transferred"; fi
    if wait_soa "$PV" zv1.test 1 5; then pass "T3: the view's transfer-source (127.0.0.2) beats options' (127.0.0.3)"
    else fail "T3: zv1.test (view transfer-source 127.0.0.2) was not transferred"; fi
    sleep 4   # the refused ones have had their first attempts and retries by now
    if [ -z "$(dag_soa "$PS" zd.test)" ]; then pass "T4: transfer-source * in the zone: the system chooses (127.0.0.1), the primary refuses, the zone stays empty"
    else fail "T4: zd.test (transfer-source *) was transferred"; fi
    if [ -z "$(dag_soa "$PS" ze.test)" ]; then pass "T5: the zone's transfer-source (127.0.0.3) beats options' (127.0.0.2): refused by the primary"
    else fail "T5: ze.test (zone transfer-source 127.0.0.3) was transferred"; fi
    if [ -z "$(dag_soa "$PV" zv2.test)" ]; then pass "T6: the zone's transfer-source (127.0.0.3) beats the view's (127.0.0.2): refused by the primary"
    else fail "T6: zv2.test (zone transfer-source 127.0.0.3 in a view with 127.0.0.2) was transferred"; fi
    # the refresh check (IXFR / SOA) leaves from the transfer source too: the new serial only arrives from 127.0.0.2
    zone "$W/tza.zone" za.test 2
    $CP reload >/dev/null 2>&1
    if wait_soa "$PS" za.test 2 15; then pass "T7: the refresh check after a change leaves from transfer-source (the primary answers 127.0.0.2 only): serial 2 arrived"
    else fail "T7: za.test did not follow the primary to serial 2"; fi
    st=$($CS zonestatus za.test 2>&1)
    case "$st" in
        *"refresh=2 "*) pass "T8: min-refresh-time 1 leaves the SOA refresh of 2 s as it is ($st)" ;;
        *) fail "T8: zonestatus of za.test: $st" ;;
    esac

    # R: a source address that was not there at start-up needs a restart
    sed 's/transfer-source 127.0.0.3; };$/transfer-source 127.0.0.4; };/' "$W/s.conf" > "$W/s.conf.new"
    cp "$W/s.conf" "$W/s.conf.orig"
    cp "$W/s.conf.new" "$W/s.conf"
    out=$($CS reload 2>&1)
    case "$out" in
        *"restart needed for"*source-address*) pass "R1: a reload that names a new transfer-source answers '$out'" ;;
        *) fail "R1: reload with a new transfer-source answered '$out'" ;;
    esac
    if wait_grep "transfer-source 127.0.0.4 was not in the configuration" "$W/s.log" 8; then
        pass "R2: the log says which address waits for a restart"
    else
        fail "R2: no log line for the transfer-source added by the reload"
    fi
    cp "$W/s.conf.orig" "$W/s.conf"
    out=$($CS reload 2>&1)
    case "$out" in
        *"restart needed"*) fail "R3: the reload back to the start-up addresses still says '$out'" ;;
        *) pass "R3: a reload with the start-up addresses needs no restart ($out)" ;;
    esac
fi

echo "== $PASSES passed, $FAILS failed, $SKIPS skipped"
[ "$FAILS" -eq 0 ]
