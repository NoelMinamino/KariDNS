#!/bin/sh
# ==============================================================================
# tests/run_server_stmt_test.sh - server <prefix> { } and key { } in view { } (BIND 9.20, batch 5)
# ==============================================================================
#   K  karicheck conf: the warnings of the server options that have no effect, the errors with file:line, the note about a view's own list
#   A  zone transfers, refresh checks and IXFR signed only through `server ... keys` (the primary refuses unsigned queries and transfers); the
#      key of the primaries element beats the server's, the server's beats the zone's tsig-key; no `server` statement: nothing is transferred;
#      bogus / request-nsid / edns-udp-size / edns no do not stop a transfer (and `request-ixfr no` of the server statement = SOA check first)
#   N  signed NOTIFY: the key comes from the server statement (a mock receiver verifies the HMAC), the also-notify element's key and the zone's
#      tsig-key are the other two places, in that precedence
#   S  the source addresses of the server statement beat the `source` of the list and the zone's / options' (loopback aliases, root)
#   T  `transfers` of a server statement replaces transfers-per-ns for that primary (stalling mock primaries)
#   V  keys in views: the same name in two views with different secrets; a transfer and an UPDATE are accepted in the view whose key signed them
#      and refused in the other; a secondary's view key (loopback aliases, root)
#   P  the port of the enclosing primaries list reaches the elements of a nested list
#   F  transfer-format one-answer (one RR a message), provide-ixfr no (an IXFR is answered with the whole zone), max-udp-size (a UDP answer is
#      cut at the peer's limit)
#   E  start-up refuses a server transfer-source it cannot bind, with file:line
#   C  NOTIFY over TCP: tcp-only yes sends it over TCP (signed, the answer verified), the retry over TCP after the UDP attempts or an unusable UDP
#      answer, peers that close / garble / stall do not hang the server, the local address is the one of the UDP NOTIFY (aliases, root)
# The loopback aliases 127.0.0.2 .. 127.0.0.5 are added when run as root and removed on exit; without them S, V and C11-C13 are SKIPped.
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

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-srvstmt.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
SECRET="cDEwLXNlcnZlci1zdG10LWNvbnRyb2wta2V5LTAwMDA="
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
M="perl $DIR/mock_xfr_notify.pl"
b64() { perl -MMIME::Base64 -e 'print encode_base64($ARGV[0], "")' "$1"; }
XK=$(b64 "srvstmt-xk-secret-0123456789ab")      # the key the server statements name
GK=$(b64 "srvstmt-good-secret-0123456789a")      # a key written on a primaries element
BK=$(b64 "srvstmt-bad--secret-0123456789a")      # a key the primary does not know
EK=$(b64 "srvstmt-ek-secret-0123456789ab")      # a key written on an also-notify element
ZK=$(b64 "srvstmt-zk-secret-0123456789ab")      # a zone's tsig-key
VKA=$(b64 "srvstmt-view-a-secret-0123456")      # the key `vk` of view va
VKB=$(b64 "srvstmt-view-b-secret-0123456")      # another key of the same name, in view vb

PP=$(kari_port 0)                      # primary of the signed zones
S1=$(kari_port 1) S2=$(kari_port 2) S3=$(kari_port 3)     # secondaries: IXFR, SOA first, no server statement
PV=$(kari_port 4) SV=$(kari_port 5)    # primary / secondary with views
PN1=$(kari_port 6) PN2=$(kari_port 7) PN3=$(kari_port 8)  # NOTIFY senders: with a server statement, without, with notify-source
SK1=$(kari_port 10) SK2=$(kari_port 11) SK3=$(kari_port 12) SK4=$(kari_port 13) SK5=$(kari_port 14) SK6=$(kari_port 15) SK7=$(kari_port 16) SK8=$(kari_port 17)
MG3=$(kari_port 20) MG4=$(kari_port 21) MG5=$(kari_port 22) MG6=$(kari_port 23)
ST1=$(kari_port 24) ST2=$(kari_port 25)
PF1=$(kari_port 30) PF2=$(kari_port 31)
PO=$(kari_port 32) SO=$(kari_port 33)
SNP=$(kari_port 34) PE=$(kari_port 35)

PIDS=""
ALIASES=""
FAILS=0
PASSES=0
SKIPS=0
pass() { echo "PASS: $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
skip() { echo "SKIP: $*"; SKIPS=$((SKIPS + 1)); }

cleanup() {
    set +e
    kari_kill_tree $PIDS
    for n in pp s1 s2 s3 pv sv pn1 pn2 pn3 st1 st2 pf1 pf2 po so snp pc1 pc2 pc3 pcm pcsec; do kari_kill_conf "$W/$n.conf"; done
    for a in $ALIASES; do ifconfig lo0 inet "$a" -alias 2>/dev/null; done
    if [ "$FAILS" -ne 0 ]; then
        for f in pp s1 s2 s3 pv sv pn1 pn2 pn3 st1 st2 pf1 pf2 po so snp pc1 pc2 pc3 pcm pcsec; do echo "--- $f.log (tail)"; tail -15 "$W/$f.log" 2>/dev/null; done
        for f in sink1 sink3 sink4 sinkc sinkd sinke; do echo "--- $f.log"; cat "$W/$f.log" 2>/dev/null; done
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

for p in $PP $S1 $S2 $S3 $PV $SV $PN1 $PN2 $PN3 $SK1 $SK2 $SK3 $SK4 $SK5 $SK6 $SK7 $SK8 $MG3 $MG4 $MG5 $MG6 $ST1 $ST2 $PF1 $PF2 $PO $SO $SNP $PE; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

wait_grep() { # PATTERN FILE [SECONDS]
    _i=0
    while [ $_i -lt "${3:-10}" ]; do grep -q -- "$1" "$2" 2>/dev/null && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
dag_soa() { "$DAG" @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump +time=1 +tries=1 2>/dev/null; }
serial_of() { dag_soa "$1" "$2" | awk '{print $3}'; }
wait_serial() { # PORT ZONE SERIAL [SECONDS]
    _i=0
    while [ $_i -lt "${4:-20}" ]; do [ "$(serial_of "$1" "$2")" = "$3" ] && return 0; sleep 1; _i=$((_i + 1)); done
    return 1
}
zone() { # zone FILE ORIGIN SERIAL [REFRESH RETRY EXPIRE]
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s %s %s %s 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' \
        "$2" "$3" "${4:-2}" "${5:-1}" "${6:-3600}" > "$1"
}
start() { # start NAME [VAR=value ...] : karidns on $W/NAME.conf
    n=$1; shift
    env X=1 "$@" "$KARIDNS" -f "$W/$n.conf" > "$W/$n.log" 2>&1 &
    PIDS="$PIDS $!"
}
ctl() { n=$1; shift; "$KARICTL" -s "$W/$n.sock" -f "$W/ctl.conf" "$@" 2>&1; }
ctlblock() { printf 'control-channel { socket "%s/%s.sock"; algorithm hmac-sha256; secret "%s"; };\n' "$W" "$1" "$SECRET"; }
keydef() { printf 'key "%s" { algorithm hmac-sha256; secret "%s"; };\n' "$1" "$2"; }

# ------------------------------------------------------------------------------------------------ K: karicheck conf
cat > "$W/k1.conf" <<EOF
options { directory "$W"; };
$(keydef k1 "$XK")
server 192.0.2.0/24 { keys k1; bogus yes; tcp-only yes; tcp-keepalive yes; padding 600; send-cookie no; require-cookie no;
  query-source 192.0.2.9; transfers 3; request-nsid yes; edns-udp-size 1400; max-udp-size 1200; transfer-format one-answer; };
view v1 { match-clients { 127.0.0.1; }; server 192.0.2.7 { }; zone "a.test" { type master; file "k1.zone"; }; };
view v2 { match-clients { any; }; zone "b.test" { type master; file "k1.zone"; }; };
EOF
zone "$W/k1.zone" a.test 1
"$KARICHECK" conf "$W/k1.conf" > "$W/kc.out" 2>&1
rc=$?
for want in "bogus is accepted, no effect in KariDNS" "tcp-keepalive is accepted, no effect in KariDNS" \
            "padding cannot exceed 512" "padding is accepted, no effect in KariDNS" "send-cookie is accepted, no effect in KariDNS" \
            "require-cookie is accepted, no effect in KariDNS" "query-source is accepted, no effect in KariDNS" \
            "View 'v1': it has server statements of its own, so the top-level server statements do not apply in this view"; do
    if grep -q "$want" "$W/kc.out"; then pass "K: karicheck conf says '$want'"
    else fail "K: karicheck conf has no '$want'"; cat "$W/kc.out"; fi
done
grep -q "tcp-only" "$W/kc.out" && { fail "K: tcp-only has an effect now (NOTIFY over TCP) and must not be warned about"; cat "$W/kc.out"; } || pass "K: tcp-only is not warned about"
grep -q "k1.conf:[0-9]*: server '192.0.2.0/24': bogus" "$W/kc.out" && pass "K: the warnings name file:line and the statement" || { fail "K: no file:line in the warnings"; cat "$W/kc.out"; }
grep -q "View 'v2'" "$W/kc.out" && fail "K: v2 has no server statements of its own and must not be mentioned" || pass "K: a view without statements of its own is not mentioned"
[ "$rc" -eq 0 ] && pass "K: the warnings do not make karicheck conf fail" || fail "K: karicheck conf exit status $rc"
kc_err() { # kc_err NAME TEXT EXPECTED : the file is refused and the message has EXPECTED
    printf '%s\n' "$2" > "$W/$1.conf"
    if "$KARICHECK" conf "$W/$1.conf" > "$W/kc.out" 2>&1; then fail "K $1: karicheck conf accepted: $2"; return; fi
    if grep -q -- "$3" "$W/kc.out"; then pass "K $1: refused; the message has '$3'"
    else fail "K $1: refused but without '$3'"; cat "$W/kc.out"; fi
}
kc_err e1 "options { };
server 192.0.2.1 { frobnicate yes; };" "e1.conf:2: server '192.0.2.1': unknown option 'frobnicate'"
kc_err e2 "$(keydef k1 "$XK")
view v1 { match-clients { 127.0.0.1; }; key k1 { algorithm hmac-sha256; secret \"$VKA\"; }; };" "view 'v1': key 'k1' already exists as a top-level key"
kc_err e3 "view v1 { match-clients { 127.0.0.1; }; key k { algorithm hmac-sha256; secret \"$XK\"; }; zone \"a.test\" { type master; file \"$W/k1.zone\"; }; };
view v2 { match-clients { any; }; zone \"b.test\" { type master; file \"$W/k1.zone\"; tsig-key k; }; };
server 192.0.2.1 { };" "Zone 'b.test.': tsig-key 'k' is not defined"
kc_err e4 "view v1 { match-clients { 127.0.0.1; }; key k { algorithm hmac-sha256; secret \"$XK\"; }; zone \"a.test\" { type master; file \"$W/k1.zone\"; }; };
view v2 { match-clients { any; }; zone \"b.test\" { type master; file \"$W/k1.zone\"; }; };
server 192.0.2.1 { keys k; };" "e4.conf:3: server '192.0.2.1': unknown key 'k' (in view 'v2')"
kc_err e5 "server 192.0.2.1/24 { };" "e5.conf:1: server '192.0.2.1/24': '192.0.2.1/24' is an invalid prefix (extra bits specified)"
kc_err e6 "server 192.0.2.1 { transfer-source-v6 2001:db8::1; };" "e6.conf:1: server '192.0.2.1': transfer-source-v6 is not legal for an IPv4 server"
kc_err e7 "server 192.0.2.1 { };
server 192.0.2.1 { };" "e7.conf:2: server '192.0.2.1': already exists, previous definition: $W/e7.conf:1"
kc_err e8 "view v1 { key k { algorithm hmac-sha256; secret \"$XK\"; }; key k { algorithm hmac-sha256; secret \"$VKA\"; }; };" "view 'v1': duplicate TSIG key 'k' defined"

# ------------------------------------------------------------------------------------------------ E: start-up refusal
printf 'options { port %s; bind-address { 127.0.0.1; }; pid-file "none"; %s };\nserver 127.0.0.1 {\n  transfer-source 192.0.2.77;\n};\n' "$PE" "$USER_OPT" > "$W/e1.conf"
"$KARIDNS" -f "$W/e1.conf" > "$W/e.log" 2>&1 &
epid=$!
i=0
while [ $i -lt 20 ] && kill -0 "$epid" 2>/dev/null; do sleep 0.5; i=$((i + 1)); done
if kill -0 "$epid" 2>/dev/null; then
    kari_kill_tree "$epid"
    fail "E1: karidns started with an unbindable server transfer-source"
elif grep -q "$W/e1.conf:3: .*transfer-source 192.0.2.77: cannot use it as a source address" "$W/e.log"; then
    pass "E1: karidns refuses to start; the message names e1.conf:3 and 'transfer-source 192.0.2.77'"
else
    fail "E1: karidns stopped but not with the expected message"; cat "$W/e.log"
fi
"$KARICHECK" conf "$W/e1.conf" > "$W/kc.out" 2>&1 && grep -q "Source addresses" "$W/kc.out" && pass "E1: karicheck conf accepts the file and lists the source address" \
    || { fail "E1: karicheck conf on e1.conf"; cat "$W/kc.out"; }

# ------------------------------------------------------------------------------------------------ A: keys of the server statement
zone "$W/ready.zone" ready.test 1
zone "$W/sk1.zone" sk1.test 5 2 1 3600
zone "$W/sk3.zone" sk3.test 5 2 1 3600
zone "$W/sk4.zone" sk4.test 5 2 1 3600
zone "$W/np.zone" np.test 5 2 1 3600
{
    echo "options { port $PP; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify no; };"
    ctlblock pp
    keydef xk "$XK"; keydef goodk "$GK"
    echo "zone \"ready.test\" { type master; file \"$W/ready.zone\"; };"
    echo "zone \"sk1.test\" { type master; file \"$W/sk1.zone\"; allow-query { key xk; }; allow-transfer { key xk; }; };"
    echo "zone \"sk3.test\" { type master; file \"$W/sk3.zone\"; allow-query { key goodk; }; allow-transfer { key goodk; }; };"
    echo "zone \"sk4.test\" { type master; file \"$W/sk4.zone\"; allow-query { key xk; }; allow-transfer { key xk; }; };"
    echo "zone \"np.test\" { type master; file \"$W/np.zone\"; allow-transfer { 127.0.0.1; }; };"
} > "$W/pp.conf"
start pp
kari_wait_answer "$DAG" "$PP" ready.test. || true
out=$("$DAG" @127.0.0.1 -p "$PP" sk1.test SOA +nohexdump +time=1 +tries=1 2>&1)
case "$out" in *REFUSED*) pass "A0: the primary refuses an unsigned query for sk1.test (so a signed refresh check proves the key)" ;; *) fail "A0: an unsigned SOA query was not refused"; echo "$out" ;; esac

{
    echo "options { port $S1; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; };"
    keydef xk "$XK"; keydef goodk "$GK"; keydef badk "$BK"
    echo "server 127.0.0.1 { keys xk; bogus yes; request-nsid yes; edns-udp-size 1400; transfer-format many-answers; };"
    echo "zone \"sk1.test\" { type slave; primaries { 127.0.0.1 port $PP; }; };"
    echo "zone \"sk3.test\" { type slave; primaries { 127.0.0.1 port $PP key goodk; }; };"
    echo "zone \"sk4.test\" { type slave; tsig-key badk; primaries { 127.0.0.1 port $PP; }; };"
} > "$W/s1.conf"
{
    echo "options { port $S2; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; };"
    keydef xk "$XK"
    echo "server 127.0.0.1 { keys xk; request-ixfr no; edns no; };"
    echo "zone \"sk1.test\" { type slave; primaries { 127.0.0.1 port $PP; }; };"
} > "$W/s2.conf"
{
    echo "options { port $S3; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; };"
    echo "zone \"sk1.test\" { type slave; primaries { 127.0.0.1 port $PP; }; };"
} > "$W/s3.conf"
start s1; start s2; start s3
if wait_serial "$S1" sk1.test 5 25; then pass "A1: sk1.test came from a primary that wants a signature: the key is the server statement's (AXFR)"
else fail "A1: sk1.test was not transferred with the key of the server statement"; fi
if wait_serial "$S1" sk3.test 5 25; then pass "A2: sk3.test: the key of the primaries element (goodk) beats the key of the server statement (xk)"
else fail "A2: sk3.test was not transferred with the key of the primaries element"; fi
if wait_serial "$S1" sk4.test 5 25; then pass "A3: sk4.test: the key of the server statement beats the zone's tsig-key (badk, which the primary does not know)"
else fail "A3: sk4.test was not transferred: the zone's tsig-key was used instead of the server statement's"; fi
if wait_serial "$S2" sk1.test 5 25; then pass "A4: request-ixfr no in the server statement: the signed SOA check came first, then the AXFR (and 'edns no' left the OPT out)"
else fail "A4: sk1.test was not transferred by the secondary with request-ixfr no / edns no"; fi
sleep 3
if [ -z "$(dag_soa "$S3" sk1.test)" ]; then pass "A5: no server statement, no key: nothing is transferred from the primary that wants a signature"
else fail "A5: the secondary without a key got the zone"; fi
zone "$W/sk1.zone" sk1.test 6 2 1 3600
zone "$W/sk3.zone" sk3.test 6 2 1 3600
ctl pp reload > /dev/null
if wait_serial "$S1" sk1.test 6 25 && wait_serial "$S1" sk3.test 6 25; then pass "A6: the next version came by a signed refresh (IXFR) too: serial 6"
else fail "A6: the refresh check / IXFR with the server statement's key failed"; fi
wait_serial "$S2" sk1.test 6 25 && pass "A7: the same for the secondary that checks the SOA first" || fail "A7: the SOA-first secondary did not get serial 6"
grep -q "TSIG" "$W/pp.log" && grep -E "\[TSIG\].*(BADSIG|BADKEY)" "$W/pp.log" | grep -q . && fail "A8: the primary logged a TSIG error" || pass "A8: the primary logged no TSIG error"

# ------------------------------------------------------------------------------------------------ N: signed NOTIFY
perl "$DIR/mock_notify_sink.pl" --log "$W/sink1.log" --ports "$SK1,$SK2,$SK3" --key "xk:$XK" --key "ek:$EK" --key "zk:$ZK" --answer 2>/dev/null &
PIDS="$PIDS $!"
perl "$DIR/mock_notify_sink.pl" --log "$W/sink4.log" --ports "$SK4,$SK5" --key "xk:$XK" --key "ek:$EK" --key "zk:$ZK" --answer 2>/dev/null &
PIDS="$PIDS $!"
for z in za zb zc zd ze; do zone "$W/$z.zone" "$z.test" 1; done
{
    echo "options { port $PN1; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; };"
    ctlblock pn1
    keydef xk "$XK"; keydef ek "$EK"; keydef zk "$ZK"
    echo "server 127.0.0.1 { keys xk; };"
    echo "zone \"za.test\" { type master; file \"$W/za.zone\"; also-notify { 127.0.0.1 port $SK1; }; };"
    echo "zone \"zb.test\" { type master; file \"$W/zb.zone\"; also-notify { 127.0.0.1 port $SK2 key ek; }; };"
    echo "zone \"zc.test\" { type master; file \"$W/zc.zone\"; tsig-key zk; also-notify { 127.0.0.1 port $SK3; }; };"
} > "$W/pn1.conf"
{
    echo "options { port $PN2; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; };"
    ctlblock pn2
    keydef zk "$ZK"
    echo "zone \"zd.test\" { type master; file \"$W/zd.zone\"; tsig-key zk; also-notify { 127.0.0.1 port $SK4; }; };"
    echo "zone \"ze.test\" { type master; file \"$W/ze.zone\"; also-notify { 127.0.0.1 port $SK5; }; };"
} > "$W/pn2.conf"
start pn1; start pn2
kari_wait_answer "$DAG" "$PN1" za.test. || true
kari_wait_answer "$DAG" "$PN2" zd.test. || true
for z in za zb zc; do ctl pn1 notify $z.test > /dev/null; done
for z in zd ze; do ctl pn2 notify $z.test > /dev/null; done
sleep 3
nchk() { # NAME LOGFILE PORT EXPECTED-TSIG DESCRIPTION
    if grep -q "NOTIFY port=$3 .* tsig=$4 " "$2"; then pass "N$1: $5 (tsig=$4)"
    else fail "N$1: $5: expected tsig=$4 at port $3"; grep "port=$3 " "$2"; fi
}
nchk 1 "$W/sink1.log" "$SK1" "xk:ok" "the NOTIFY is signed with the key of the server statement"
nchk 2 "$W/sink1.log" "$SK2" "ek:ok" "the key of the also-notify element beats the server statement's"
nchk 3 "$W/sink1.log" "$SK3" "xk:ok" "the server statement's key beats the zone's tsig-key"
nchk 4 "$W/sink4.log" "$SK4" "zk:ok" "no server statement: the zone's tsig-key signs"
nchk 5 "$W/sink4.log" "$SK5" "none" "no key anywhere: the NOTIFY is not signed"

# ------------------------------------------------------------------------------------------------ S: sources
if [ "$HAVE_ALIAS" -ne 1 ]; then
    skip "S: the sources of the server statement need the loopback aliases 127.0.0.2 - 127.0.0.5 (run as root)"
else
    perl "$DIR/mock_notify_sink.pl" --log "$W/sink3.log" --ports "$SK6,$SK7" --bind "127.0.0.5:$SK8" --answer 2>/dev/null &
    PIDS="$PIDS $!"
    for z in zs1 zs2 zs3; do zone "$W/$z.zone" "$z.test" 1; done
    {
        echo "options { port $PN3; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; notify-source 127.0.0.3; };"
        ctlblock pn3
        echo "server 127.0.0.1 { notify-source 127.0.0.2; };"
        echo "server 127.0.0.5 { notify-source *; };"
        echo "zone \"zs1.test\" { type master; file \"$W/zs1.zone\"; also-notify source 127.0.0.4 { 127.0.0.1 port $SK6; }; };"
        echo "zone \"zs2.test\" { type master; file \"$W/zs2.zone\"; notify-source 127.0.0.4; also-notify { 127.0.0.1 port $SK7; }; };"
        echo "zone \"zs3.test\" { type master; file \"$W/zs3.zone\"; also-notify source 127.0.0.4 { 127.0.0.5 port $SK8; }; };"
    } > "$W/pn3.conf"
    start pn3
    kari_wait_answer "$DAG" "$PN3" zs1.test. || true
    for z in zs1 zs2 zs3; do ctl pn3 notify $z.test > /dev/null; done
    sleep 3
    if grep -q "NOTIFY port=$SK6 src=127.0.0.2 " "$W/sink3.log"; then pass "S1: the server statement's notify-source (127.0.0.2) beats the source of the also-notify list (127.0.0.4)"
    else fail "S1: expected a NOTIFY from 127.0.0.2"; cat "$W/sink3.log"; fi
    if grep -q "NOTIFY port=$SK7 src=127.0.0.2 " "$W/sink3.log"; then pass "S2: the server statement's notify-source beats the zone's notify-source (127.0.0.4)"
    else fail "S2: expected a NOTIFY from 127.0.0.2"; cat "$W/sink3.log"; fi
    if grep "NOTIFY port=$SK8 " "$W/sink3.log" | grep -vq "src=127.0.0.[34] "; then pass "S3: notify-source * in the server statement: the system chooses (not the list's 127.0.0.4, not options' 127.0.0.3)"
    else fail "S3: the NOTIFY to 127.0.0.5 left from the list's / options' source"; cat "$W/sink3.log"; fi

    # R: a source address of a server statement that was not there at start-up needs a restart (as every source address)
    cp "$W/pn3.conf" "$W/pn3.conf.orig"
    sed 's/server 127.0.0.1 { notify-source 127.0.0.2; };/server 127.0.0.1 { notify-source 127.0.0.5; };/' "$W/pn3.conf.orig" > "$W/pn3.conf"
    out=$(ctl pn3 reload)
    case "$out" in
        *"restart needed for"*source-address*) pass "R1: a reload that gives a server statement a new notify-source answers '$out'" ;;
        *) fail "R1: reload with a new server notify-source answered '$out'" ;;
    esac
    cp "$W/pn3.conf.orig" "$W/pn3.conf"
    ctl pn3 reload > /dev/null

    # transfers: the primary answers 127.0.0.2 only
    zone "$W/o1.zone" o1.test 3
    zone "$W/o2.zone" o2.test 3
    {
        echo "options { port $PO; bind-address { 127.0.0.1; 127.0.0.5; }; pid-file \"none\"; $USER_OPT notify no; };"
        echo "zone \"ready.test\" { type master; file \"$W/ready.zone\"; };"
        echo "zone \"o1.test\" { type master; file \"$W/o1.zone\"; allow-transfer { 127.0.0.2; }; };"
        echo "zone \"o2.test\" { type master; file \"$W/o2.zone\"; allow-transfer { 127.0.0.2; }; };"
    } > "$W/po.conf"
    {
        echo "options { port $SO; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; transfer-source 127.0.0.4; };"
        echo "server 127.0.0.1 { transfer-source 127.0.0.2; };"
        echo "server 127.0.0.5 { transfer-source *; };"
        echo "zone \"o1.test\" { type slave; primaries source 127.0.0.3 { 127.0.0.1 port $PO; }; };"
        echo "zone \"o2.test\" { type slave; primaries source 127.0.0.2 { 127.0.0.5 port $PO; }; };"
    } > "$W/so.conf"
    start po
    kari_wait_answer "$DAG" "$PO" ready.test. || true
    start so
    if wait_serial "$SO" o1.test 3 25; then pass "S4: the server statement's transfer-source (127.0.0.2) beats the primaries list's source (127.0.0.3) and options' (127.0.0.4): the primary only answers 127.0.0.2"
    else fail "S4: o1.test was not transferred from 127.0.0.2"; fi
    sleep 3
    if [ -z "$(dag_soa "$SO" o2.test)" ]; then pass "S5: transfer-source * in the server statement: the system chooses, not the list's 127.0.0.2 (the zone stays empty)"
    else fail "S5: o2.test was transferred: the list's source was used although the server statement says *"; fi
fi

# ------------------------------------------------------------------------------------------------ T: transfers
$M xfr-primary --port "$MG3" --zone g1.test --mode stall --log "$W/mg3.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MG4" --zone g2.test --mode stall --log "$W/mg4.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MG5" --zone g3.test --mode stall --log "$W/mg5.log" & PIDS="$PIDS $!"
$M xfr-primary --port "$MG6" --zone g4.test --mode stall --log "$W/mg6.log" & PIDS="$PIDS $!"
sleep 1
{
    echo "options { port $ST1; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT max-transfer-idle-in 1; };"
    echo "server 127.0.0.1 { transfers 1; };"
    echo "zone \"g1.test\" { type slave; primaries { 127.0.0.1 port $MG3; }; };"
    echo "zone \"g2.test\" { type slave; primaries { 127.0.0.1 port $MG4; }; };"
} > "$W/st1.conf"
{
    echo "options { port $ST2; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT max-transfer-idle-in 1; transfers-per-ns 1; };"
    echo "server 127.0.0.1 { transfers 5; };"
    echo "zone \"g3.test\" { type slave; primaries { 127.0.0.1 port $MG5; }; };"
    echo "zone \"g4.test\" { type slave; primaries { 127.0.0.1 port $MG6; }; };"
} > "$W/st2.conf"
start st1 KARIDNS_XFER_MINUTE_SECS=4
start st2 KARIDNS_XFER_MINUTE_SECS=4
wait_grep "STALL" "$W/mg3.log" 12; wait_grep "STALL" "$W/mg4.log" 20
t1=$(sed -n 's/.* t=\([0-9]*\)$/\1/p' "$W/mg3.log" | head -1)
t2=$(sed -n 's/.* t=\([0-9]*\)$/\1/p' "$W/mg4.log" | head -1)
if [ -n "$t1" ] && [ -n "$t2" ]; then
    d=$((t1 > t2 ? t1 - t2 : t2 - t1))
    if [ "$d" -ge 3 ]; then pass "T1: transfers 1 in the server statement (options: 2 per primary): the second transfer started $d s after the first"
    else fail "T1: the two transfers started $d s apart (expected >= 3)"; fi
else fail "T1: both mock primaries should have been asked ($t1 / $t2)"; fi
wait_grep "STALL" "$W/mg5.log" 12; wait_grep "STALL" "$W/mg6.log" 12
t1=$(sed -n 's/.* t=\([0-9]*\)$/\1/p' "$W/mg5.log" | head -1)
t2=$(sed -n 's/.* t=\([0-9]*\)$/\1/p' "$W/mg6.log" | head -1)
if [ -n "$t1" ] && [ -n "$t2" ]; then
    d=$((t1 > t2 ? t1 - t2 : t2 - t1))
    if [ "$d" -le 2 ]; then pass "T2: transfers 5 in the server statement beats transfers-per-ns 1: both started within $d s"
    else fail "T2: the two transfers started $d s apart (expected <= 2)"; fi
else fail "T2: both mock primaries should have been asked ($t1 / $t2)"; fi

# ------------------------------------------------------------------------------------------------ V: keys in views
if [ "$HAVE_ALIAS" -ne 1 ]; then
    skip "V: view keys need the loopback aliases 127.0.0.2 - 127.0.0.5 (run as root)"
else
    zone "$W/va.zone" vz.test 7 2 1 3600
    zone "$W/vb.zone" vz.test 8 2 1 3600
    {
        echo "options { port $PV; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify no; };"
        echo "view va { match-clients { 127.0.0.2; }; $(keydef vk "$VKA")"
        echo "  zone \"vz.test\" { type master; file \"$W/va.zone\"; allow-transfer { key vk; }; allow-update { key vk; }; }; };"
        echo "view vb { match-clients { 127.0.0.3; }; $(keydef vk "$VKB")"
        echo "  zone \"vz.test\" { type master; file \"$W/vb.zone\"; allow-transfer { key vk; }; allow-update { key vk; }; }; };"
        echo "view vc { match-clients { any; }; zone \"ready.test\" { type master; file \"$W/ready.zone\"; }; };"
    } > "$W/pv.conf"
    start pv
    kari_wait_answer "$DAG" "$PV" ready.test. || true
    axfr() { # axfr SOURCE SECRET : the output of a signed AXFR of vz.test from SOURCE
        "$DAG" vz.test AXFR @127.0.0.1 -p "$PV" -b "$1" -y "hmac-sha256:vk:$2" +tcp +nohexdump 2>&1
    }
    out=$(axfr 127.0.0.2 "$VKA")
    case "$out" in *www.vz.test*) pass "V1: view va accepts an AXFR signed with its key vk" ;; *) fail "V1: AXFR from view va's address with va's key"; echo "$out" ;; esac
    out=$(axfr 127.0.0.2 "$VKB")
    case "$out" in *www.vz.test*) fail "V2: view va accepted an AXFR signed with vb's key of the same name" ;; *) pass "V2: view va refuses an AXFR signed with the other view's key of the same name" ;; esac
    out=$(axfr 127.0.0.3 "$VKB")
    case "$out" in *www.vz.test*) pass "V3: view vb accepts an AXFR signed with its key vk (a different secret)" ;; *) fail "V3: AXFR from view vb's address with vb's key"; echo "$out" ;; esac
    out=$(axfr 127.0.0.3 "$VKA")
    case "$out" in *www.vz.test*) fail "V4: view vb accepted an AXFR signed with va's key" ;; *) pass "V4: view vb refuses an AXFR signed with va's key" ;; esac
    upd() { # upd SOURCE SECRET NAME : a signed UPDATE adding NAME.vz.test A 192.0.2.99
        "$DAG" vz.test a @127.0.0.1 -p "$PV" -b "$1" --update-add "$3.vz.test 300 A 192.0.2.99" +nohexdump -y "hmac-sha256:vk:$2" 2>&1
    }
    out=$(upd 127.0.0.2 "$VKA" new1)
    case "$out" in *"status: NOERROR"*) pass "V5: an UPDATE signed with va's key is accepted in view va" ;; *) fail "V5: UPDATE in view va with va's key"; echo "$out" ;; esac
    out=$(upd 127.0.0.2 "$VKB" new2)
    case "$out" in *"status: NOERROR"*) fail "V6: view va accepted an UPDATE signed with vb's key" ;; *) pass "V6: view va refuses an UPDATE signed with vb's key of the same name" ;; esac
    out=$(upd 127.0.0.3 "$VKA" new3)
    case "$out" in *"status: NOERROR"*) fail "V7: view vb accepted an UPDATE signed with va's key" ;; *) pass "V7: view vb refuses an UPDATE signed with va's key" ;; esac
    qa=$("$DAG" @127.0.0.1 -p "$PV" -b 127.0.0.2 new1.vz.test A +short +nohexdump +time=1 +tries=1 2>&1)
    qb=$("$DAG" @127.0.0.1 -p "$PV" -b 127.0.0.3 new1.vz.test A +short +nohexdump +time=1 +tries=1 2>&1)
    q2=$("$DAG" @127.0.0.1 -p "$PV" -b 127.0.0.2 new2.vz.test A +short +nohexdump +time=1 +tries=1 2>&1)
    if [ "$qa" = "192.0.2.99" ] && [ -z "$qb" ] && [ -z "$q2" ]; then pass "V8: the accepted UPDATE is in view va only; the refused one changed nothing"
    else fail "V8: new1 in va='$qa' (expected 192.0.2.99), in vb='$qb' (expected empty), refused new2='$q2' (expected empty)"; fi

    {
        echo "options { port $SV; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; };"
        echo "view sv1 { match-clients { 127.0.0.2; }; transfer-source 127.0.0.2; $(keydef vk "$VKA")"
        echo "  zone \"vz.test\" { type slave; primaries { 127.0.0.1 port $PV key vk; }; }; };"
        echo "view sv2 { match-clients { 127.0.0.3; }; transfer-source 127.0.0.3; $(keydef vk "$VKA")"
        echo "  zone \"vz.test\" { type slave; primaries { 127.0.0.1 port $PV key vk; }; }; };"
    } > "$W/sv.conf"
    start sv
    i=0
    sv_soa() { "$DAG" @127.0.0.1 -p "$SV" -b "$1" vz.test SOA +short +nohexdump +time=1 +tries=1 2>/dev/null | awk '{print $3}'; }
    want=$("$DAG" @127.0.0.1 -p "$PV" -b 127.0.0.2 vz.test SOA +short +nohexdump +time=1 +tries=1 2>/dev/null | awk '{print $3}')   # 8: the UPDATE of V5 raised 7
    while [ $i -lt 25 ] && [ "$(sv_soa 127.0.0.2)" != "$want" ]; do sleep 1; i=$((i + 1)); done
    if [ -n "$want" ] && [ "$(sv_soa 127.0.0.2)" = "$want" ]; then pass "V9: a secondary's view key signs its transfer: view sv1 (key vk = va's secret, source 127.0.0.2) has vz.test serial $want"
    else fail "V9: view sv1 did not transfer vz.test"; fi
    sleep 3
    if [ -z "$(sv_soa 127.0.0.3)" ]; then pass "V10: view sv2 has a key vk with the same secret but reaches view vb of the primary (another secret): it gets nothing"
    else fail "V10: view sv2 transferred vz.test with a key the primary's view vb does not know"; fi
fi

# ------------------------------------------------------------------------------------------------ P: nested primaries ports
{
    echo "options { port $SNP; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT min-refresh-time 1; min-retry-time 1; };"
    echo "primaries inner { 127.0.0.1; };"
    echo "primaries outer port $PP { inner; };"
    echo "zone \"np.test\" { type slave; primaries { outer; }; };"
} > "$W/snp.conf"
start snp
if wait_serial "$SNP" np.test 5 25; then pass "P1: the nested list 'inner' has no port; it took the port $PP of 'outer' (BIND named_config_getipandkeylist())"
else fail "P1: np.test was not transferred: the nested list did not take the enclosing list's port"; fi

# ------------------------------------------------------------------------------------------------ F: transfer-format, provide-ixfr, max-udp-size
perl -e 'print "\$TTL 300\n\$ORIGIN big.test.\n\@ IN SOA ns1 hostmaster 2 3600 600 86400 60\n\@ IN NS ns1\nns1 IN A 192.0.2.1\n"; for my $i (1..40) { printf "h%d IN A 192.0.2.%d\n", $i, $i } for my $i (1..8) { printf "t IN TXT \"%s\"\n", "x" x 100 }' > "$W/big.zone"
for n in pf1 pf2; do
    p=$PF1; [ $n = pf2 ] && p=$PF2
    {
        echo "options { port $p; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify no; };"
        ctlblock $n
        [ $n = pf1 ] && echo "server 127.0.0.1 { transfer-format one-answer; provide-ixfr no; max-udp-size 512; };"
        echo "zone \"big.test\" { type master; file \"$W/big.zone\"; allow-transfer { 127.0.0.1; }; };"
    } > "$W/$n.conf"
    start $n
done
kari_wait_answer "$DAG" "$PF1" big.test. || true
kari_wait_answer "$DAG" "$PF2" big.test. || true
perl -pi -e 's/ 2 3600 600/ 3 3600 600/; ' "$W/big.zone"
printf 'extra IN A 192.0.2.200\n' >> "$W/big.zone"
ctl pf1 reload > /dev/null; ctl pf2 reload > /dev/null
wait_serial "$PF1" big.test 3 15 >/dev/null; wait_serial "$PF2" big.test 3 15 >/dev/null
n1=$($M probe --port "$PF1" --name big.test --qtype AXFR | grep -c '^MSG')
n2=$($M probe --port "$PF2" --name big.test --qtype AXFR | grep -c '^MSG')
mx=$($M probe --port "$PF1" --name big.test --qtype AXFR | sed -n 's/.* an=\([0-9]*\) .*/\1/p' | sort -n | tail -1)
if [ "$n1" -gt 40 ] && [ "${mx:-0}" -eq 1 ] && [ "$n2" -le 2 ]; then pass "F1: transfer-format one-answer: $n1 messages with one RR each; without it the zone comes in $n2 message(s)"
else fail "F1: one-answer: $n1 messages (max an=$mx); default: $n2 messages"; fi
s1=$($M probe --port "$PF1" --name big.test --qtype IXFR --serial 2 | sed -n 's/.* soa=\(.*\)$/\1/p' | tr ',' '\n' | grep -c .)
s2=$($M probe --port "$PF2" --name big.test --qtype IXFR --serial 2 | sed -n 's/.* soa=\(.*\)$/\1/p' | tr ',' '\n' | grep -c .)
if [ "$s2" -gt 2 ] && [ "$s1" -le 2 ]; then pass "F2: provide-ixfr no in the server statement: the IXFR is answered with the whole zone ($s1 SOA RRs), otherwise with differences ($s2 SOA RRs)"
else fail "F2: IXFR answers: provide-ixfr no gave $s1 SOA RRs, default gave $s2"; "$M" probe --port "$PF2" --name big.test --qtype IXFR --serial 2 | head -3; fi
tc() { "$DAG" @127.0.0.1 -p "$1" t.big.test TXT +bufsize=4096 +ignore +nohexdump +time=2 +tries=1 2>&1 | grep -c ";; flags:.* tc"; }
c1=$(tc "$PF1"); c2=$(tc "$PF2")
if [ "$c1" -ge 1 ] && [ "$c2" -eq 0 ]; then pass "F3: max-udp-size 512 in the server statement: the UDP answer to a client that offers 4096 is cut (TC); otherwise it fits"
else fail "F3: max-udp-size: truncated with the statement=$c1 (expected 1), without=$c2 (expected 0)"; fi

# ------------------------------------------------------------------------------------------------ C: NOTIFY over TCP
# `tcp-only yes` in a server statement sends the NOTIFY over TCP; otherwise it is UDP, and a NOTIFY that got no usable answer is made once
# over TCP (BIND 9.20 zone.c notify_send_toaddr() / notify_done()).  A mock receiver (tests/mock_notify_sink.pl) listens on UDP and TCP of the
# same port and logs how each NOTIFY came (via=udp / via=tcp) and whether its TSIG is right; its TCP side answers by mode.
for z in c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 d1 d2 d3; do zone "$W/$z.zone" "$z.test" 1; done
CPORT=$(kari_port 40)       # 40 .. 59: one port per target, UDP and TCP on it
cp_of() { echo $((CPORT + $1)); }
# sink A (UDP answers; TCP by mode): c1 answer | c2 close | c3 garble | c4 short | c5 bigprefix | c6 badid | c7 unsigned | c8 badsig | c9 stall | c10 partial
# d1: UDP answered, d3: UDP answered without a TSIG although the NOTIFY is signed; both TCP answer
perl "$DIR/mock_notify_sink.pl" --log "$W/sinkc.log" --key "xk:$XK" --answer \
    --ports "$(cp_of 1),$(cp_of 2),$(cp_of 3),$(cp_of 4),$(cp_of 5),$(cp_of 6),$(cp_of 7),$(cp_of 8),$(cp_of 9),$(cp_of 10),$(cp_of 11),$(cp_of 13)" \
    --tcp-ports "$(cp_of 1):answer,$(cp_of 2):close,$(cp_of 3):garble,$(cp_of 4):short,$(cp_of 5):bigprefix,$(cp_of 6):badid,$(cp_of 7):unsigned,$(cp_of 8):badsig,$(cp_of 9):stall,$(cp_of 10):partial,$(cp_of 11):answer,$(cp_of 13):answer" \
    2>/dev/null &
PIDS="$PIDS $!"
# sink B: UDP is silent (no --answer), TCP answers: d2
perl "$DIR/mock_notify_sink.pl" --log "$W/sinkd.log" --ports "$(cp_of 12)" --tcp-ports "$(cp_of 12):answer" 2>/dev/null &
PIDS="$PIDS $!"
{
    echo "options { port $(cp_of 30); bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; };"
    ctlblock pc1
    keydef xk "$XK"
    echo "server 127.0.0.1 { tcp-only yes; keys xk; };"
    n=1
    for z in c1 c2 c3 c4 c5 c6 c7 c8 c9 c10; do
        echo "zone \"$z.test\" { type master; file \"$W/$z.zone\"; also-notify { 127.0.0.1 port $(cp_of $n); }; };"
        n=$((n + 1))
    done
} > "$W/pc1.conf"
{
    echo "options { port $(cp_of 31); bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; notify-retries 1; notify-retry-interval 1; };"
    ctlblock pc2
    keydef xk "$XK"
    echo "zone \"d1.test\" { type master; file \"$W/d1.zone\"; also-notify { 127.0.0.1 port $(cp_of 11); }; };"
    echo "zone \"d2.test\" { type master; file \"$W/d2.zone\"; also-notify { 127.0.0.1 port $(cp_of 12); }; };"
    echo "zone \"d3.test\" { type master; file \"$W/d3.zone\"; tsig-key xk; notify-retries 5; notify-retry-interval 60; also-notify { 127.0.0.1 port $(cp_of 13); }; };"
} > "$W/pc2.conf"
sleep 1
start pc1; start pc2
kari_wait_answer "$DAG" "$(cp_of 30)" c1.test. || true
kari_wait_answer "$DAG" "$(cp_of 31)" d1.test. || true
: > "$W/sinkc.log"; : > "$W/sinkd.log"
for z in c1 c2 c3 c4 c5 c6 c7 c8 c9 c10; do ctl pc1 notify $z.test > /dev/null; done
for z in d1 d2 d3; do ctl pc2 notify $z.test > /dev/null; done
sleep 5
cnt() { grep -c "NOTIFY port=$2 .* via=$3 " "$1"; }
# C1: tcp-only: over TCP only, signed with the server statement's key, from a TCP answer that carries a good TSIG
if [ "$(cnt "$W/sinkc.log" "$(cp_of 1)" tcp)" -eq 1 ] && [ "$(cnt "$W/sinkc.log" "$(cp_of 1)" udp)" -eq 0 ] && grep -q "NOTIFY port=$(cp_of 1) .* qname=c1.test tsig=xk:ok via=tcp" "$W/sinkc.log"; then
    pass "C1: tcp-only yes: the NOTIFY came once over TCP, none over UDP, signed with the server statement's key (tsig=xk:ok)"
else fail "C1: expected one signed TCP NOTIFY and no UDP datagram for c1.test"; cat "$W/sinkc.log"; fi
if ! grep -q "zone 'c1.test.'.*over TCP failed" "$W/pc1.log"; then pass "C2: the signed TCP answer (TSIG verified against the request MAC) is accepted: no failure logged"
else fail "C2: a failure was logged for c1.test"; grep "c1.test" "$W/pc1.log"; fi
# C3: d1 has no tcp-only: UDP, answered, nothing over TCP
if [ "$(cnt "$W/sinkc.log" "$(cp_of 11)" udp)" -eq 1 ] && [ "$(cnt "$W/sinkc.log" "$(cp_of 11)" tcp)" -eq 0 ]; then pass "C3: no tcp-only: the NOTIFY goes over UDP and its answer ends it (nothing over TCP)"
else fail "C3: d1.test: udp=$(cnt "$W/sinkc.log" "$(cp_of 11)" udp) tcp=$(cnt "$W/sinkc.log" "$(cp_of 11)" tcp)"; cat "$W/sinkc.log"; fi
# C4: UDP silent, notify-retries 1 / interval 1: two datagrams, then one TCP NOTIFY that is answered
if [ "$(cnt "$W/sinkd.log" "$(cp_of 12)" udp)" -eq 2 ] && [ "$(cnt "$W/sinkd.log" "$(cp_of 12)" tcp)" -eq 1 ]; then
    pass "C4: no answer over UDP (1 + notify-retries 1 datagrams): the NOTIFY is made once over TCP and answered"
else fail "C4: d2.test: udp=$(cnt "$W/sinkd.log" "$(cp_of 12)" udp) (expected 2) tcp=$(cnt "$W/sinkd.log" "$(cp_of 12)" tcp) (expected 1)"; cat "$W/sinkd.log"; fi
grep -q "zone 'd2.test.': no answer from 127.0.0.1 port $(cp_of 12) after 2 NOTIFY message(s); retrying over TCP" "$W/pc2.log" \
    && pass "C5: the log says 'no answer ... after 2 NOTIFY message(s); retrying over TCP'" || { fail "C5: no 'retrying over TCP' line for d2.test"; grep d2.test "$W/pc2.log"; }
# C6: a signed NOTIFY whose UDP answer is unsigned: not accepted, and made over TCP at once (the retry interval of the zone is 60 s)
if [ "$(cnt "$W/sinkc.log" "$(cp_of 13)" udp)" -eq 1 ] && [ "$(cnt "$W/sinkc.log" "$(cp_of 13)" tcp)" -eq 1 ] && grep -q "NOTIFY port=$(cp_of 13) .* tsig=xk:ok via=tcp" "$W/sinkc.log"; then
    pass "C6: an answer over UDP that fails TSIG verification: ignored, and the NOTIFY follows over TCP at once, signed (not after 5 x 60 s)"
else fail "C6: d3.test: udp=$(cnt "$W/sinkc.log" "$(cp_of 13)" udp) tcp=$(cnt "$W/sinkc.log" "$(cp_of 13)" tcp)"; cat "$W/sinkc.log"; fi
grep -q "zone 'd3.test.': ignoring NOTIFY answer from 127.0.0.1 port $(cp_of 13) that fails TSIG verification" "$W/pc2.log" \
    && grep -q "zone 'd3.test.': the answer from 127.0.0.1 port $(cp_of 13) was no good; retrying over TCP" "$W/pc2.log" \
    && pass "C7: the UDP answer is logged as failing TSIG verification, then 'retrying over TCP'" || { fail "C7: log lines of d3.test"; grep d3.test "$W/pc2.log"; }
# C8: a peer that closes, garbles, sends a short reply, a huge length, another ID, no TSIG or a wrong one: tcp-only makes two attempts, then the failure is logged
chk_tcp_fail() { # chk_tcp_fail ZONE N MODE REASON
    _p=$(cp_of "$2")
    _n=$(cnt "$W/sinkc.log" "$_p" tcp)
    if [ "$_n" -eq 2 ] && grep -q "zone '$1.test.': NOTIFY to 127.0.0.1 port $_p over TCP failed: $4: retrying over TCP" "$W/pc1.log" \
        && grep -q "zone '$1.test.': NOTIFY to 127.0.0.1 port $_p over TCP failed: $4\$" "$W/pc1.log"; then
        pass "C8 $3: two TCP attempts (the second is BIND's 'retrying over TCP'), then 'over TCP failed: $4'"
    else fail "C8 $3: $1.test: $_n TCP NOTIFYs (expected 2) or no '$4' failure in the log"; grep "$1.test" "$W/pc1.log"; fi
}
chk_tcp_fail c2 2 close "the connection was closed before the answer"
chk_tcp_fail c3 3 garble "the reply is not an answer to this NOTIFY"
chk_tcp_fail c4 4 short "the answer has an impossible length"
chk_tcp_fail c5 5 bigprefix "the answer has an impossible length"
chk_tcp_fail c6 6 badid "the reply is not an answer to this NOTIFY"
chk_tcp_fail c7 7 unsigned "the answer fails TSIG verification with key 'xk' (unsigned, rcode 0)"
chk_tcp_fail c8 8 badsig "the answer fails TSIG verification with key 'xk' (BADSIG, rcode 0)"
# C9: stalling peers hold one thread each, not the server: it still answers and sends other NOTIFYs; they give up after 15 s (two attempts)
if [ "$(cnt "$W/sinkc.log" "$(cp_of 9)" tcp)" -ge 1 ] && [ "$(cnt "$W/sinkc.log" "$(cp_of 10)" tcp)" -ge 1 ]; then
    : > "$W/sinkc.log"
    ctl pc1 notify c1.test > /dev/null
    sleep 2
    out=$("$DAG" @127.0.0.1 -p "$(cp_of 30)" c1.test SOA +short +nohexdump +time=2 +tries=1 2>&1)
    if [ "$(cnt "$W/sinkc.log" "$(cp_of 1)" tcp)" -eq 1 ] && [ -n "$out" ]; then
        pass "C9: while the stalled and the half-answering peer are waited for, the server answers queries and sends the next NOTIFY over TCP"
    else fail "C9: during the stalls: c1 NOTIFYs=$(cnt "$W/sinkc.log" "$(cp_of 1)" tcp), query answer='$out'"; fi
else fail "C9: the stalling receivers were not asked"; cat "$W/sinkc.log"; fi
i=0
while [ $i -lt 45 ] && ! { grep -q "zone 'c9.test.': NOTIFY to 127.0.0.1 port $(cp_of 9) over TCP failed: timed out\$" "$W/pc1.log" &&
                            grep -q "zone 'c10.test.': NOTIFY to 127.0.0.1 port $(cp_of 10) over TCP failed: timed out\$" "$W/pc1.log"; }; do sleep 1; i=$((i + 1)); done
if [ "$i" -lt 45 ] && [ "$i" -ge 5 ]; then pass "C10: a peer that never answers, and one that sends 3 octets of its answer, are given up after the 15 s of BIND's TCP timeout (both attempts, ~$i s more)"
else fail "C10: the stalled exchanges ended after $i more seconds (expected 5..44) or not at all"; grep -E "c9.test|c10.test" "$W/pc1.log"; fi

# C11: the source address of a NOTIFY over TCP is the one of the UDP NOTIFY: the server statement's, else the list's, else options' (root: loopback aliases)
if [ "$HAVE_ALIAS" -ne 1 ]; then
    skip "C11: the source address of a NOTIFY over TCP needs the loopback aliases 127.0.0.2 - 127.0.0.5 (run as root)"
else
    for z in e1 e2 e3; do zone "$W/$z.zone" "$z.test" 1; done
    perl "$DIR/mock_notify_sink.pl" --log "$W/sinke.log" --key "xk:$XK" --tcp-ports "$(cp_of 41):answer" \
        --tcp-bind "127.0.0.5:$(cp_of 42):answer,127.0.0.4:$(cp_of 43):answer" 2>/dev/null &
    PIDS="$PIDS $!"
    {
        echo "options { port $(cp_of 32); bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; notify-source 127.0.0.3; };"
        ctlblock pc3
        keydef xk "$XK"
        echo "server 127.0.0.1 { tcp-only yes; keys xk; notify-source 127.0.0.2; };"
        echo "server 127.0.0.5 { tcp-only yes; keys xk; };"
        echo "server 127.0.0.4 { tcp-only yes; keys xk; };"
        echo "zone \"e1.test\" { type master; file \"$W/e1.zone\"; also-notify source 127.0.0.4 { 127.0.0.1 port $(cp_of 41); }; };"
        echo "zone \"e2.test\" { type master; file \"$W/e2.zone\"; also-notify source 127.0.0.4 { 127.0.0.5 port $(cp_of 42); }; };"
        echo "zone \"e3.test\" { type master; file \"$W/e3.zone\"; also-notify { 127.0.0.4 port $(cp_of 43); }; };"
    } > "$W/pc3.conf"
    sleep 1
    start pc3
    kari_wait_answer "$DAG" "$(cp_of 32)" e1.test. || true
    for z in e1 e2 e3; do ctl pc3 notify $z.test > /dev/null; done
    sleep 3
    grep -q "NOTIFY port=$(cp_of 41) src=127.0.0.2 .* tsig=xk:ok via=tcp" "$W/sinke.log" \
        && pass "C11: the server statement's notify-source (127.0.0.2) is the local address of the TCP connection (above the list's 127.0.0.4)" \
        || { fail "C11: e1.test: expected a TCP NOTIFY from 127.0.0.2"; cat "$W/sinke.log"; }
    grep -q "NOTIFY port=$(cp_of 42) src=127.0.0.4 .* via=tcp" "$W/sinke.log" \
        && pass "C12: no server notify-source: the source of the also-notify list (127.0.0.4) is the local address (above options' 127.0.0.3)" \
        || { fail "C12: e2.test: expected a TCP NOTIFY from 127.0.0.4"; cat "$W/sinke.log"; }
    grep -q "NOTIFY port=$(cp_of 43) src=127.0.0.3 .* via=tcp" "$W/sinke.log" \
        && pass "C13: neither: options' notify-source (127.0.0.3) is the local address" \
        || { fail "C13: e3.test: expected a TCP NOTIFY from 127.0.0.3"; cat "$W/sinke.log"; }
fi

# C14: KariDNS to KariDNS: a primary with tcp-only yes notifies a secondary over TCP (signed); the secondary's refresh timer is an hour, so
# the new serial arrives through the NOTIFY (the primary never sends a datagram)
zone "$W/m.zone" m.test 1 3600 3600 86400
{
    echo "options { port $(cp_of 50); bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT notify explicit; };"
    ctlblock pcm
    keydef xk "$XK"
    echo "server 127.0.0.1 { tcp-only yes; keys xk; };"
    echo "zone \"m.test\" { type master; file \"$W/m.zone\"; allow-transfer { key xk; }; also-notify { 127.0.0.1 port $(cp_of 51); }; };"
} > "$W/pcm.conf"
{
    echo "options { port $(cp_of 51); bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    keydef xk "$XK"
    echo "zone \"m.test\" { type slave; tsig-key xk; primaries { 127.0.0.1 port $(cp_of 50) key xk; }; };"
} > "$W/pcsec.conf"
start pcm
kari_wait_answer "$DAG" "$(cp_of 50)" m.test. || true
start pcsec
if wait_serial "$(cp_of 51)" m.test 1 25; then
    zone "$W/m.zone" m.test 2 3600 3600 86400
    ctl pcm reload > /dev/null
    if wait_serial "$(cp_of 51)" m.test 2 15; then pass "C14: a KariDNS primary with tcp-only yes notified a KariDNS secondary over TCP (signed): serial 2 arrived long before its refresh time"
    else fail "C14: the secondary did not refresh after the NOTIFY over TCP"; grep -i notify "$W/pcm.log" | tail -5; fi
    grep -q "over TCP failed" "$W/pcm.log" && fail "C14: the primary logged a failed NOTIFY over TCP" || pass "C14: the primary logged no failure"
else fail "C14: the secondary did not load m.test"; fi

echo ""
echo "server statement test: $PASSES passed, $FAILS failed, $SKIPS skipped"
[ "$FAILS" -eq 0 ]
