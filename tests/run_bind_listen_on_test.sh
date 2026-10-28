#!/bin/sh
# run_bind_listen_on_test.sh - listen-on, listen-on-v6 and blackhole of the BIND 9.20 configuration compatibility (BIND 9.20 ARM
# "Interfaces", "blackhole"; tests/test_listen_on.c checks the parsing and the computation of the address set against a fixed table):
#   - a port per statement, listen-on (IPv4) apart from listen-on-v6, `listen-on-v6 { none; }`, no wildcard socket when addresses are listed
#   - listen-on together with bind-address (union, a duplicate is one socket), an address list matched against the interfaces
#     (`!127.0.0.2; 127.0.0.0/8;`)
#   - -p replaces the port of the statements
#   - the start-up refusals with file:line (one address with two ports, tls, nothing to listen on) and karicheck conf
#   - blackhole: requests from a matching source are dropped over UDP and TCP, a reload adds and removes it
#   - a reload that changes listen-on is reported as "restart needed" and does not move the sockets
# Run by root, the loopback aliases 127.0.0.2 and 127.0.0.3 are added (and removed on exit) and the checks that need a second or third
# address run too; they are skipped otherwise.  Everything else runs as a normal user on 127.0.0.1 / ::1.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$KARICHECK" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl karicheck dag >/dev/null || exit 1

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-listen.XXXXXX")"
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
P1=$(kari_port 1 15801)   # per-statement ports (v4 at P1, v6 at P1B)
P1B=$(kari_port 2 15802)
P2=$(kari_port 3 15803)   # union with bind-address
P3=$(kari_port 4 15804)   # interface matching with a negation
P4=$(kari_port 5 15805)   # -p
P4S=$(kari_port 6 15806)  # the port written in the statement (must stay unused)
P5=$(kari_port 7 15807)   # blackhole, reload
P6=$(kari_port 8 15808)   # restart needed
P6B=$(kari_port 9 15809)  # the port a reload adds (must stay unused)
SECRET="cDEwLWFjbC10ZXN0LWNvbnRyb2wta2V5LXNlY3JldA=="
PIDS=""
FAILS=0
A2="127.0.0.2"
A3="127.0.0.3"
ALIASES=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/s1.conf" "$W/s2.conf" "$W/s3.conf" "$W/s4.conf" "$W/s5.conf" "$W/s6.conf"
    if [ "$ALIASES" = "1" ]; then
        ifconfig lo0 inet "$A2" netmask 255.0.0.0 -alias 2>/dev/null
        ifconfig lo0 inet "$A3" netmask 255.0.0.0 -alias 2>/dev/null
    fi
    if [ "$FAILS" -ne 0 ]; then
        for l in s1 s2 s3 s4 s5 s6; do echo "--- $l.log (tail)"; tail -12 "$W/$l.log" 2>/dev/null; done
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P1 $P1B $P2 $P3 $P4 $P4S $P5 $P6 $P6B; do
    if sockstat -46 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done
if [ "$(id -u)" -eq 0 ] && ifconfig lo0 inet "$A2" netmask 255.0.0.0 alias 2>/dev/null && ifconfig lo0 inet "$A3" netmask 255.0.0.0 alias 2>/dev/null; then ALIASES=1; fi
HAVE_V6=0
ifconfig lo0 2>/dev/null | grep -q "inet6 ::1 " && HAVE_V6=1

printf '$TTL 300\n$ORIGIN ex.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.80\n' > "$W/ex.test.zone"
ZONE="zone \"ex.test\" { type master; file \"$W/ex.test.zone\"; };"
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"

# start NAME [karidns options]: runs $W/NAME.conf in the foreground
start() {
    _n=$1; shift
    "$KARIDNS" -f -c "$W/$_n.conf" "$@" > "$W/$_n.log" 2>&1 &
    PIDS="$PIDS $!"
}
# wait_up ADDR PORT: the server answers (at most 20 s)
wait_up() {
    _i=0
    while [ $_i -lt 100 ]; do
        "$DAG" "@$1" -p "$2" www.ex.test A +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1 && return 0
        sleep 0.2
        _i=$((_i + 1))
    done
    return 1
}
# answer ADDR PORT [dag options]: the A record of www.ex.test, empty when there is no answer
answer() {
    _a=$1; _p=$2; shift 2
    "$DAG" "@$_a" -p "$_p" www.ex.test A +short +nohexdump +time=1 +tries=1 "$@" 2>/dev/null
}
expect_answer() { # expect_answer LABEL ADDR PORT [dag options]
    _l=$1; shift
    if [ "$(answer "$@")" = "192.0.2.80" ]; then pass "$_l"; else fail "$_l: no answer from $1:$2"; fi
}
expect_silent() { # expect_silent LABEL ADDR PORT [dag options]: nothing answers (no socket, or the request is dropped)
    _l=$1; shift
    if [ "$(answer "$@")" != "192.0.2.80" ]; then pass "$_l"; else fail "$_l: $1:$2 answered"; fi
}
no_wildcard() { # no_wildcard LABEL PORT: no socket on the wildcard address at PORT
    if sockstat -46 -l -p "$2" 2>/dev/null | awk '$6 ~ /^\*:/ { f = 1 } END { exit !f }'; then fail "$1: a wildcard socket is bound on port $2: $(sockstat -46 -l -p "$2")"; else pass "$1"; fi
}

# ---------------------------------------------------------------- server 1: a port per statement, IPv4 apart from IPv6
{
    echo "options { port $P1; pid-file \"none\"; $USER_OPT"
    echo "  listen-on { 127.0.0.1; };"
    [ "$HAVE_V6" = "1" ] && echo "  listen-on-v6 port $P1B { ::1; };" || echo "  listen-on-v6 { none; };"
    echo "};"
    echo "$ZONE"
} > "$W/s1.conf"
"$KARICHECK" conf "$W/s1.conf" > "$W/s1.check" 2>&1 && grep -q "Listening (UDP and TCP) on: 127.0.0.1:$P1" "$W/s1.check" \
    && pass "karicheck conf: listen-on / listen-on-v6 with a port accepted, the addresses are shown" || fail "karicheck conf s1: $(cat "$W/s1.check")"
start s1
if ! wait_up 127.0.0.1 $P1; then fail "server 1 did not start"; tail -20 "$W/s1.log"; exit 1; fi
expect_answer "listen-on { 127.0.0.1; } at options port (udp)" 127.0.0.1 $P1
expect_answer "listen-on { 127.0.0.1; } at options port (tcp)" 127.0.0.1 $P1 +tcp
no_wildcard "listen-on lists an address: no wildcard socket (udp and tcp)" $P1
if [ "$HAVE_V6" = "1" ]; then
    expect_answer "listen-on-v6 port $P1B { ::1; } (udp)" ::1 $P1B
    expect_answer "listen-on-v6 port $P1B { ::1; } (tcp)" ::1 $P1B +tcp
    expect_silent "IPv6 is not listened on at the IPv4 statement's port" ::1 $P1
    expect_silent "IPv4 is not listened on at the IPv6 statement's port" 127.0.0.1 $P1B
    no_wildcard "listen-on-v6 lists an address: no wildcard socket" $P1B
else
    echo "SKIP: listen-on-v6 { ::1; } (lo0 has no ::1)"
fi

# ---------------------------------------------------------------- server 2: listen-on together with bind-address; listen-on-v6 { none; }
EXTRA2=""
[ "$ALIASES" = "1" ] && EXTRA2="$A2;"
cat > "$W/s2.conf" <<EOF
options { port $P2; pid-file "none"; $USER_OPT
  bind-address { 127.0.0.1; };
  listen-on { 127.0.0.1; $EXTRA2 };
  listen-on-v6 { none; };
};
$ZONE
EOF
start s2
if ! wait_up 127.0.0.1 $P2; then fail "server 2 did not start"; tail -20 "$W/s2.log"; exit 1; fi
expect_answer "bind-address and listen-on name 127.0.0.1: one socket answers (udp)" 127.0.0.1 $P2
expect_answer "bind-address and listen-on name 127.0.0.1: one socket answers (tcp)" 127.0.0.1 $P2 +tcp
if [ "$HAVE_V6" = "1" ]; then expect_silent "listen-on-v6 { none; } opens no IPv6 socket" ::1 $P2; fi
if [ -z "$(sockstat -6 -l -p $P2 2>/dev/null | grep ":$P2 ")" ]; then pass "sockstat: nothing listens on IPv6 at port $P2"; else fail "an IPv6 socket at $P2: $(sockstat -6 -l -p $P2)"; fi
if [ "$ALIASES" = "1" ]; then
    expect_answer "listen-on { $A2; } is added to bind-address' 127.0.0.1 (udp)" $A2 $P2
    expect_answer "(tcp)" $A2 $P2 +tcp
else
    echo "SKIP: the union with a second address (needs root for the loopback alias $A2)"
fi

# ---------------------------------------------------------------- server 3: a list matched against the interface addresses (root)
if [ "$ALIASES" = "1" ]; then
    cat > "$W/s3.conf" <<EOF
options { port $P3; pid-file "none"; $USER_OPT
  listen-on { !$A2; 127.0.0.0/8; };
  listen-on-v6 { none; };
};
$ZONE
EOF
    "$KARICHECK" conf "$W/s3.conf" > "$W/s3.check" 2>&1 && grep -q "Listening (UDP and TCP) on: .*127.0.0.1:$P3" "$W/s3.check" && grep -q "127.0.0.3:$P3" "$W/s3.check" \
        && ! grep -q "127.0.0.2:$P3" "$W/s3.check" && pass "karicheck conf: !$A2; 127.0.0.0/8 selects the other loopback addresses" || fail "karicheck conf s3: $(cat "$W/s3.check")"
    start s3
    if ! wait_up 127.0.0.1 $P3; then fail "server 3 did not start"; tail -20 "$W/s3.log"; exit 1; fi
    expect_answer "127.0.0.0/8 matches the interface address 127.0.0.1" 127.0.0.1 $P3
    expect_answer "127.0.0.0/8 matches the interface address $A3 (alias)" $A3 $P3
    expect_answer "(tcp)" $A3 $P3 +tcp
    expect_silent "!$A2 first: no socket for $A2 (udp)" $A2 $P3
    expect_silent "!$A2 first: no socket for $A2 (tcp)" $A2 $P3 +tcp
    no_wildcard "an address list that is not plain any binds no wildcard socket" $P3
else
    echo "SKIP: a list matched against the interface addresses (needs root for the loopback aliases)"
fi

# ---------------------------------------------------------------- server 4: -p replaces the port of the statement
cat > "$W/s4.conf" <<EOF
options { pid-file "none"; $USER_OPT
  listen-on port $P4S { 127.0.0.1; };
  listen-on-v6 { none; };
};
$ZONE
EOF
start s4 -p "$P4"
if ! wait_up 127.0.0.1 $P4; then fail "server 4 did not start with -p"; tail -20 "$W/s4.log"; exit 1; fi
expect_answer "-p $P4 replaces the port written in listen-on" 127.0.0.1 $P4
expect_silent "the port of the statement ($P4S) is not bound" 127.0.0.1 $P4S

# ---------------------------------------------------------------- start-up refusals, karicheck conf
conf_case() { # conf_case LABEL EXPECTED-TEXT CONFIG-BODY: karicheck conf and karidns -f both fail with the text
    _l=$1; _t=$2
    printf 'options { pid-file "none"; %s\n%s\n};\n' "$USER_OPT" "$3" > "$W/bad.conf"
    _o=$("$KARICHECK" conf "$W/bad.conf" 2>&1); _rc=$?
    if [ $_rc -ne 0 ] && echo "$_o" | grep -q "$_t"; then pass "karicheck conf: $_l"; else fail "karicheck conf: $_l (rc=$_rc): $_o"; fi
    _o=$(timeout 10 "$KARIDNS" -f -c "$W/bad.conf" 2>&1); _rc=$?
    if [ $_rc -ne 0 ] && echo "$_o" | grep -q "$_t"; then pass "karidns refuses to start: $_l"; else fail "karidns: $_l (rc=$_rc): $_o"; fi
}
conf_case "one address with two ports" "bad.conf:3: options listen-on: address 127.0.0.1 is listened on at port 53 (.*bad.conf:2) and at port 5353" \
" listen-on { 127.0.0.1; };
 listen-on port 5353 { 127.0.0.1; };"
conf_case "bind-address and listen-on with two ports" "listened on at port 5353 (.*bad.conf:3) and at port 53" \
" bind-address { 127.0.0.1; };
 listen-on port 5353 { 127.0.0.1; };"
conf_case "tls in listen-on" "bad.conf:2: options listen-on: 'tls' is not supported" \
" listen-on port 853 tls ephemeral { 127.0.0.1; };"
conf_case "http in listen-on-v6" "bad.conf:2: options listen-on-v6: 'http' is not supported" \
" listen-on-v6 http default { ::1; };"
conf_case "proxy in listen-on" "bad.conf:2: options listen-on: 'proxy' is not supported" \
" listen-on proxy plain { 127.0.0.1; };"
conf_case "an unknown name in a listen-on list" "bad.conf:3: options listen-on: entry 'nosuch' is not an address" \
" listen-on {
  nosuch;
 };"
conf_case "an invalid port" "bad.conf:2: options listen-on: port: invalid port '70000'" \
" listen-on port 70000 { 127.0.0.1; };"
conf_case "a bind-address that is no address" "bad.conf:2: options: bind-address: 'localhost' is not an IPv4 or IPv6 address" \
" bind-address { localhost; };"
printf 'options { pid-file "none"; %s\n listen-on { none; };\n listen-on-v6 { none; };\n};\n' "$USER_OPT" > "$W/bad.conf"
_o=$("$KARICHECK" conf "$W/bad.conf" 2>&1); _rc=$?
if [ $_rc -eq 0 ] && echo "$_o" | grep -q "select no address"; then pass "karicheck conf: nothing to listen on is a warning"; else fail "karicheck conf nothing to listen on (rc=$_rc): $_o"; fi
_o=$(timeout 10 "$KARIDNS" -f -c "$W/bad.conf" 2>&1); _rc=$?
if [ $_rc -ne 0 ] && echo "$_o" | grep -q "select no address to listen on"; then pass "karidns refuses to start when nothing is selected"; else fail "karidns nothing to listen on (rc=$_rc): $_o"; fi
printf 'options { pid-file "none"; %s\n listen-on {\n  203.0.113.9;\n  127.0.0.1;\n };\n listen-on-v6 { none; };\n};\n' "$USER_OPT" > "$W/warn.conf"
_o=$("$KARICHECK" conf "$W/warn.conf" 2>&1); _rc=$?
if [ $_rc -eq 0 ] && echo "$_o" | grep -q "\[WARNING\] .*warn.conf:2: options listen-on: '203.0.113.9' matches no address of an interface of this host"; then pass "karicheck conf: an address on no interface is a warning with file:line"
else fail "karicheck conf warning (rc=$_rc): $_o"; fi

# ---------------------------------------------------------------- server 5: blackhole, UDP and TCP, added and removed by a reload
write_s5() { # write_s5 BLACKHOLE-LIST
    cat > "$W/s5.conf" <<EOF
options { port $P5; pid-file "none"; $USER_OPT
  listen-on { 127.0.0.1; };
  listen-on-v6 { none; };
  $1
};
control-channel { socket "$W/ctl5.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$ZONE
EOF
}
reload5() {
    "$KARICTL" -s "$W/ctl5.sock" -f "$W/ctl.conf" reload > "$W/reload5.out" 2>&1
    sleep 1
}
write_s5 "blackhole { 198.51.100.0/24; };"
start s5
if ! wait_up 127.0.0.1 $P5; then fail "server 5 did not start"; tail -20 "$W/s5.log"; exit 1; fi
expect_answer "blackhole { 198.51.100.0/24; }: 127.0.0.1 is not dropped (udp)" 127.0.0.1 $P5
expect_answer "(tcp)" 127.0.0.1 $P5 +tcp
if [ "$ALIASES" = "1" ]; then
    write_s5 "blackhole { $A2; };"
    reload5
    expect_silent "blackhole { $A2; }: a request from $A2 gets no response (udp)" 127.0.0.1 $P5 -b $A2
    expect_silent "blackhole { $A2; }: a connection from $A2 is dropped (tcp)" 127.0.0.1 $P5 +tcp -b $A2
    expect_answer "blackhole { $A2; }: 127.0.0.1 is answered (udp)" 127.0.0.1 $P5
    expect_answer "blackhole { $A2; }: $A3 is answered (udp)" 127.0.0.1 $P5 -b $A3
    expect_answer "blackhole { $A2; }: $A3 is answered (tcp)" 127.0.0.1 $P5 +tcp -b $A3
    # first match decides (ARM): "!address;" exempts that address, the prefix after it drops the rest
    write_s5 "blackhole { !$A3; 127.0.0.0/8; };"
    reload5
    expect_silent "blackhole { !$A3; 127.0.0.0/8; }: $A2 is dropped" 127.0.0.1 $P5 -b $A2
    expect_silent "blackhole { !$A3; 127.0.0.0/8; }: 127.0.0.1 is dropped" 127.0.0.1 $P5
    expect_answer "blackhole { !$A3; 127.0.0.0/8; }: $A3 is exempt (udp)" 127.0.0.1 $P5 -b $A3
    expect_answer "blackhole { !$A3; 127.0.0.0/8; }: $A3 is exempt (tcp)" 127.0.0.1 $P5 +tcp -b $A3
else
    echo "SKIP: blackhole of a second source address (needs root for the loopback aliases)"
fi
write_s5 "blackhole { 127.0.0.1; };"
reload5
expect_silent "reload adds blackhole { 127.0.0.1; }: the request is dropped (udp)" 127.0.0.1 $P5
expect_silent "(tcp)" 127.0.0.1 $P5 +tcp
if grep -q "restart needed" "$W/reload5.out"; then fail "a blackhole change must not need a restart: $(cat "$W/reload5.out")"; else pass "a reload that changes blackhole needs no restart"; fi
write_s5 "blackhole { none; };"
reload5
expect_answer "reload with blackhole { none; }: answered again (udp)" 127.0.0.1 $P5
expect_answer "(tcp)" 127.0.0.1 $P5 +tcp
write_s5 ""
reload5
expect_answer "reload without blackhole: answered (udp)" 127.0.0.1 $P5
# the first match decides: "!address;" alone drops nothing, "!address; any;" drops everything else (ARM)
write_s5 "blackhole { !127.0.0.1; };"
reload5
expect_answer "blackhole { !127.0.0.1; } alone drops nothing (udp)" 127.0.0.1 $P5
write_s5 "blackhole { !127.0.0.1; any; };"
reload5
expect_answer "blackhole { !127.0.0.1; any; }: 127.0.0.1 is exempt (udp)" 127.0.0.1 $P5
if [ "$ALIASES" = "1" ]; then expect_silent "blackhole { !127.0.0.1; any; }: $A2 is dropped" 127.0.0.1 $P5 -b $A2; fi

# ---------------------------------------------------------------- server 6: a reload that changes listen-on is "restart needed"
cat > "$W/s6.conf" <<EOF
options { port $P6; pid-file "none"; $USER_OPT
  listen-on { 127.0.0.1; };
  listen-on-v6 { none; };
};
control-channel { socket "$W/ctl6.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$ZONE
EOF
start s6
if ! wait_up 127.0.0.1 $P6; then fail "server 6 did not start"; tail -20 "$W/s6.log"; exit 1; fi
cat > "$W/s6.conf" <<EOF
options { port $P6; pid-file "none"; $USER_OPT
  listen-on port $P6B { 127.0.0.1; };
  listen-on-v6 { none; };
};
control-channel { socket "$W/ctl6.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$ZONE
EOF
OUT=$("$KARICTL" -s "$W/ctl6.sock" -f "$W/ctl.conf" reload 2>&1)
sleep 1
echo "$OUT" | grep -q "restart needed for: .*listen-on" && pass "a reload that changes listen-on says: $OUT" || fail "reload reply: $OUT"
expect_answer "after the reload the old socket still answers" 127.0.0.1 $P6
expect_silent "after the reload no new socket was opened (a restart is needed)" 127.0.0.1 $P6B

if [ "$FAILS" -eq 0 ]; then echo "ALL TESTS PASSED"; exit 0; fi
echo "$FAILS FAILURE(S)"
exit 1
