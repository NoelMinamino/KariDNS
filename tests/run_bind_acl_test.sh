#!/bin/sh
# run_bind_acl_test.sh - the ACL batch of the BIND 9.20 configuration compatibility (BIND 9.20 ARM "Address Match Lists", "acl Block",
# allow-query, allow-query-on, allow-transfer, allow-update, allow-notify):
#   - allow-query in options / view / zone (zone overrides view overrides options), REFUSED + EDE 18 over UDP and TCP, with the shared
#     response cache warm (an answer cached for a client that may ask is never given to one that may not), a CNAME that leads into a zone
#     the client may not ask, reload that closes a zone
#   - allow-query-on (the address the query came to; a wildcard socket takes it from the packet)
#   - allow-transfer inherited from options and view; first-match evaluation of key / address / ! elements (transfer-acl-match not
#     written) and the old "address AND key" through transfer-acl-match all
#   - localhost and localnets
#   - karicheck conf: errors with file:line, the warning for a list that became more permissive
# karidns runs as a normal user on 127.0.0.1.  Run by root the loopback alias 127.0.0.2 is added as a second client / local address and the
# checks that need it run too (they are skipped otherwise); nothing else needs root.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$KARICHECK" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl karicheck dag >/dev/null || exit 1

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-acl.XXXXXX")"
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
P1=$(kari_port 1 15701)   # server 1: options-level ACLs, zones, keys
P2=$(kari_port 2 15702)   # server 2: views, wildcard socket (allow-query-on)
P3=$(kari_port 3 15703)   # server 3: transfers
SECRET="cDEwLWFjbC10ZXN0LWNvbnRyb2wta2V5LXNlY3JldA=="
QK="cWstc2VjcmV0LWZvci1hY2wtdGVzdC1rZXk="
TK="dGstc2VjcmV0LWZvci1hY2wtdGVzdC1rZXkh"
PIDS=""
FAILS=0
ALIAS_IP="127.0.0.2"
ALIAS_ADDED=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/s1.conf" "$W/s2.conf" "$W/s3.conf"
    if [ "$ALIAS_ADDED" = "1" ]; then ifconfig lo0 inet "$ALIAS_IP" netmask 255.0.0.0 -alias 2>/dev/null; fi
    if [ "$FAILS" -ne 0 ]; then
        for l in s1 s2 s3; do echo "--- $l.log (tail)"; tail -15 "$W/$l.log" 2>/dev/null; done
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P1 $P2 $P3; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done
if [ "$(id -u)" -eq 0 ] && ifconfig lo0 inet "$ALIAS_IP" netmask 255.0.0.0 alias 2>/dev/null; then ALIAS_ADDED=1; fi
NEG_ALIAS=""
[ "$ALIAS_ADDED" = "1" ] && NEG_ALIAS="!$ALIAS_IP;"

zone() { # zone NAME [extra record line]
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.80\n' "$1" > "$W/$1.zone"
    [ -n "${2:-}" ] && printf '%s\n' "$2" >> "$W/$1.zone"
    return 0
}
for z in open.test closed.test none.test local.test neg.test keyed.test zown.test inh.test tx.test; do zone "$z"; done
zone cn.test 'x IN CNAME www.keyed.test.'
zone cnc.test 'y IN CNAME www.closed.test.'
for z in v1.test v2.test; do zone "$z"; done
for z in xa.test xb.test xc.test xd.test xe.test xf.test xg.test on.test; do zone "$z"; done

KEYS="key \"qk\" { algorithm hmac-sha256; secret \"$QK\"; };
key \"tk\" { algorithm hmac-sha256; secret \"$TK\"; };"

# ---------------------------------------------------------------- server 1
cat > "$W/s1.conf" <<EOF
options { port $P1; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
          allow-query { 127.0.0.1; $NEG_ALIAS }; };
control-channel { socket "$W/ctl1.sock"; algorithm hmac-sha256; secret "$SECRET"; };
$KEYS
acl "mynets" { 192.0.2.0/24; { !127.0.0.1; 127.0.0.0/8; }; };
zone "inh.test" { type master; file "$W/inh.test.zone"; };
zone "open.test" { type master; file "$W/open.test.zone"; allow-query { any; }; };
zone "closed.test" { type master; file "$W/closed.test.zone"; allow-query { 192.0.2.0/24; }; };
zone "none.test" { type master; file "$W/none.test.zone"; allow-query { none; }; };
zone "local.test" { type master; file "$W/local.test.zone"; allow-query { localhost; }; };
zone "neg.test" { type master; file "$W/neg.test.zone"; allow-query { !127.0.0.1; any; }; };
zone "keyed.test" { type master; file "$W/keyed.test.zone"; allow-query { key qk; }; };
zone "zown.test" { type master; file "$W/zown.test.zone"; allow-query { mynets; }; };
zone "cn.test" { type master; file "$W/cn.test.zone"; allow-query { any; }; };
zone "cnc.test" { type master; file "$W/cnc.test.zone"; allow-query { any; }; };
EOF
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"

"$KARICHECK" conf "$W/s1.conf" > "$W/s1.check" 2>&1
if [ $? -eq 0 ]; then pass "karicheck conf accepts the ACL statements (options, zone, acl block, nested list, localhost, key)"; else fail "karicheck conf s1: $(cat "$W/s1.check")"; fi

"$KARIDNS" -f -c "$W/s1.conf" > "$W/s1.log" 2>&1 &
PIDS="$PIDS $!"
if ! kari_wait_answer "$DAG" "$P1" open.test 20; then fail "server 1 did not start"; tail -20 "$W/s1.log"; exit 1; fi

# q SERVER_IP PORT NAME TYPE [dag options]: the dag output
q() { _ip=$1; _p=$2; _n=$3; _t=$4; shift 4; "$DAG" "@$_ip" -p "$_p" "$_n" "$_t" +nohexdump +time=2 +tries=1 "$@" 2>&1; }
# expect_refused LABEL OUTPUT / expect_answer LABEL OUTPUT PATTERN
refused() { # refused LABEL OUTPUT
    if echo "$2" | grep -q "status: REFUSED" && echo "$2" | grep -q "EDE: 18"; then pass "$1: REFUSED with EDE 18"; else fail "$1: expected REFUSED + EDE 18: $2"; fi
}
answered() { # answered LABEL OUTPUT PATTERN
    if echo "$2" | grep -q "status: NOERROR" && echo "$2" | grep -Eq "$3"; then pass "$1"; else fail "$1: expected NOERROR and /$3/: $2"; fi
}

for proto in "" "+tcp"; do
    L="${proto:-udp}"
    answered "options allow-query inherited, client allowed ($L)" "$(q 127.0.0.1 $P1 www.inh.test A $proto)" "192\.0\.2\.80"
    answered "zone allow-query { any; } overrides options ($L)" "$(q 127.0.0.1 $P1 www.open.test A $proto)" "192\.0\.2\.80"
    refused "zone allow-query { 192.0.2.0/24; } ($L)" "$(q 127.0.0.1 $P1 www.closed.test A $proto)"
    refused "zone allow-query { none; } ($L)" "$(q 127.0.0.1 $P1 www.none.test A $proto)"
    answered "zone allow-query { localhost; } from 127.0.0.1 ($L)" "$(q 127.0.0.1 $P1 www.local.test A $proto)" "192\.0\.2\.80"
    refused "zone allow-query { !127.0.0.1; any; } ($L)" "$(q 127.0.0.1 $P1 www.neg.test A $proto)"
    refused "zone allow-query { key qk; } unsigned ($L)" "$(q 127.0.0.1 $P1 www.keyed.test A $proto)"
    refused "zone allow-query { mynets; } with !127.0.0.1 in a nested list ($L)" "$(q 127.0.0.1 $P1 www.zown.test A $proto)"
    refused "REFUSED also for a name below the zone that does not exist ($L)" "$(q 127.0.0.1 $P1 nx.closed.test A $proto)"
    refused "REFUSED also for the SOA ($L)" "$(q 127.0.0.1 $P1 closed.test SOA $proto)"
done

# the shared response cache: a signed query warms it, the unsigned one is still refused (UDP and TCP), then the signed one is answered again
for i in 1 2 3; do q 127.0.0.1 $P1 www.keyed.test A -y hmac-sha256:qk:$QK >/dev/null; done
answered "signed query answered (cache warm)" "$(q 127.0.0.1 $P1 www.keyed.test A -y hmac-sha256:qk:$QK)" "192\.0\.2\.80"
refused "unsigned query refused after the cache is warm (udp)" "$(q 127.0.0.1 $P1 www.keyed.test A)"
refused "unsigned query refused after the cache is warm (tcp)" "$(q 127.0.0.1 $P1 www.keyed.test A +tcp)"
answered "signed query answered after the refusals" "$(q 127.0.0.1 $P1 www.keyed.test A -y hmac-sha256:qk:$QK +tcp)" "192\.0\.2\.80"
refused "a request signed with another (valid) key is refused" "$(q 127.0.0.1 $P1 www.keyed.test A -y hmac-sha256:tk:$TK)"

# a CNAME into a zone the client may not ask: the chain stops at the CNAME, and nothing is cached for the next client
OUT=$(q 127.0.0.1 $P1 y.cnc.test A)
if echo "$OUT" | grep -q "status: NOERROR" && echo "$OUT" | grep -q "CNAME" && ! echo "$OUT" | grep -q "192\.0\.2\.80"; then pass "CNAME into a closed zone: the CNAME only, no data of the closed zone"; else fail "CNAME into closed zone: $OUT"; fi
OUT=$(q 127.0.0.1 $P1 x.cn.test A)
if echo "$OUT" | grep -q "CNAME" && ! echo "$OUT" | grep -q "192\.0\.2\.80"; then pass "CNAME into a keyed zone, unsigned: the CNAME only"; else fail "CNAME into keyed zone unsigned: $OUT"; fi
OUT=$(q 127.0.0.1 $P1 x.cn.test A -y hmac-sha256:qk:$QK)
if echo "$OUT" | grep -q "CNAME" && echo "$OUT" | grep -q "192\.0\.2\.80"; then pass "CNAME into a keyed zone, signed: the whole chain"; else fail "CNAME into keyed zone signed: $OUT"; fi
OUT=$(q 127.0.0.1 $P1 x.cn.test A)
if echo "$OUT" | grep -q "CNAME" && ! echo "$OUT" | grep -q "192\.0\.2\.80"; then pass "CNAME into a keyed zone, unsigned again after the signed one: still the CNAME only"; else fail "CNAME again: $OUT"; fi

# a second source address (root only): the allowed address warms the cache, the other is refused
if [ "$ALIAS_ADDED" = "1" ]; then
    answered "127.0.0.1 may ask the zone that inherits options' allow-query" "$(q 127.0.0.1 $P1 www.inh.test A -b 127.0.0.1)" "192\.0\.2\.80"
    answered "(again, cache warm)" "$(q 127.0.0.1 $P1 www.inh.test A -b 127.0.0.1)" "192\.0\.2\.80"
    refused "$ALIAS_IP is refused by options' allow-query { 127.0.0.1; !$ALIAS_IP; } after the cache is warm (udp)" "$(q 127.0.0.1 $P1 www.inh.test A -b $ALIAS_IP)"
    refused "$ALIAS_IP is refused after the cache is warm (tcp)" "$(q 127.0.0.1 $P1 www.inh.test A -b $ALIAS_IP +tcp)"
    answered "a zone with allow-query { any; } answers $ALIAS_IP" "$(q 127.0.0.1 $P1 www.open.test A -b $ALIAS_IP)" "192\.0\.2\.80"
    answered "$ALIAS_IP is let in by the positive nested list of acl mynets (the nested negation only names 127.0.0.1)" "$(q 127.0.0.1 $P1 www.zown.test A -b $ALIAS_IP)" "192\.0\.2\.80"
    answered "allow-query { localhost; } lets $ALIAS_IP in (it is an address of lo0)" "$(q 127.0.0.1 $P1 www.local.test A -b $ALIAS_IP)" "192\.0\.2\.80"
else
    echo "SKIP: second source address (needs root for the loopback alias $ALIAS_IP)"
fi

# reload: the zone is closed at once (the response cache is keyed by the configuration generation, and the check comes first anyway)
answered "before the reload: open.test answers" "$(q 127.0.0.1 $P1 www.open.test A)" "192\.0\.2\.80"
sed "s|zone \"open.test\" { type master; file \"\([^\"]*\)\"; allow-query { any; }; };|zone \"open.test\" { type master; file \"\1\"; allow-query { 192.0.2.99; }; };|" "$W/s1.conf" > "$W/s1.new" && cp "$W/s1.new" "$W/s1.conf"
grep -q "192.0.2.99" "$W/s1.conf" || fail "the test could not edit s1.conf"
"$KARICTL" -s "$W/ctl1.sock" -f "$W/ctl.conf" reload > "$W/reload.out" 2>&1
sleep 1
refused "after the reload open.test is closed" "$(q 127.0.0.1 $P1 www.open.test A)"
answered "after the reload a zone that was not changed still answers" "$(q 127.0.0.1 $P1 www.inh.test A)" "192\.0\.2\.80"

# ---------------------------------------------------------------- server 2: views, wildcard socket, allow-query-on, view-level transfer
cat > "$W/s2.conf" <<EOF
options { port $P2; pid-file "none"; $USER_OPT
          allow-query-on { 127.0.0.1; }; allow-transfer { 192.0.2.1; }; };
$KEYS
view "v" { match-clients { any; };
  allow-query { none; };
  allow-transfer { 127.0.0.1; };
  zone "v1.test" { type master; file "$W/v1.test.zone"; };
  zone "v2.test" { type master; file "$W/v2.test.zone"; allow-query { 127.0.0.1; }; allow-query-on { 127.0.0.1; $NEG_ALIAS }; };
  zone "open.test" { type master; file "$W/open.test.zone"; allow-transfer { none; }; };
  zone "on.test" { type master; file "$W/on.test.zone"; allow-query { any; }; allow-query-on { 192.0.2.77; }; };
};
EOF
"$KARICHECK" conf "$W/s2.conf" > "$W/s2.check" 2>&1 || fail "karicheck conf s2: $(cat "$W/s2.check")"
"$KARIDNS" -f -c "$W/s2.conf" > "$W/s2.log" 2>&1 &
PIDS="$PIDS $!"
i=0; while [ $i -lt 100 ]; do "$DAG" @127.0.0.1 -p $P2 v2.test SOA +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1 && break; sleep 0.2; i=$((i + 1)); done
for proto in "" "+tcp"; do
    L="${proto:-udp}"
    refused "view allow-query { none; } is the default of the zones of the view ($L)" "$(q 127.0.0.1 $P2 www.v1.test A $proto)"
    answered "zone allow-query overrides the view's ($L)" "$(q 127.0.0.1 $P2 www.v2.test A $proto)" "192\.0\.2\.80"
    refused "zone without a statement inherits the view's allow-query, not allow-query-on of options ($L)" "$(q 127.0.0.1 $P2 www.open.test A $proto)"
    refused "allow-query-on { 192.0.2.77; }: the query came to 127.0.0.1 ($L)" "$(q 127.0.0.1 $P2 www.on.test A $proto)"
done
if [ "$ALIAS_ADDED" = "1" ]; then
    answered "wildcard socket: allow-query-on { 127.0.0.1; } lets a query to 127.0.0.1 in (udp)" "$(q 127.0.0.1 $P2 www.v2.test A)" "192\.0\.2\.80"
    refused "wildcard socket: a query to $ALIAS_IP is refused by allow-query-on (udp)" "$(q $ALIAS_IP $P2 www.v2.test A)"
    refused "wildcard socket: a query to $ALIAS_IP is refused by allow-query-on (tcp)" "$(q $ALIAS_IP $P2 www.v2.test A +tcp)"
    answered "wildcard socket: a query to 127.0.0.1 is let in (tcp)" "$(q 127.0.0.1 $P2 www.v2.test A +tcp)" "192\.0\.2\.80"
else
    echo "SKIP: allow-query-on on a wildcard socket with a second local address (needs root for the loopback alias $ALIAS_IP)"
fi
# allow-transfer of the view (overrides options'), of the zone (overrides the view's); allow-query does not apply to a transfer (BIND: allow-transfer decides)
xfr() { # xfr PORT ZONE [dag options]: succeeds when the transfer brought the zone's records
    _port=$1; _z=$2; shift 2
    "$DAG" @127.0.0.1 -p "$_port" "$_z" AXFR +nohexdump +time=2 +tries=1 "$@" 2>&1 | grep -q "192\.0\.2\.80"
}
xfr_ok_t() { _l=$1; shift; if xfr "$@"; then pass "$_l: transferred"; else fail "$_l: the transfer failed"; fi; }
xfr_no_t() { _l=$1; shift; if xfr "$@"; then fail "$_l: the transfer worked but must be refused"; else pass "$_l: refused"; fi; }
xfr_ok_t "view allow-transfer { 127.0.0.1; } overrides options' { 192.0.2.1; }" $P2 v1.test
xfr_no_t "zone allow-transfer { none; } overrides the view's" $P2 open.test

# ---------------------------------------------------------------- server 3: transfers
cat > "$W/s3.conf" <<EOF
options { port $P3; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
          allow-transfer { 127.0.0.1; }; };
$KEYS
zone "xa.test" { type master; file "$W/xa.test.zone"; };
zone "xb.test" { type master; file "$W/xb.test.zone"; allow-transfer { none; }; };
zone "xc.test" { type master; file "$W/xc.test.zone"; allow-transfer { key tk; 192.0.2.1; }; };
zone "xd.test" { type master; file "$W/xd.test.zone"; allow-transfer { 127.0.0.1; key tk; }; };
zone "xe.test" { type master; file "$W/xe.test.zone"; allow-transfer { 127.0.0.1; key tk; }; transfer-acl-match all; };
zone "xf.test" { type master; file "$W/xf.test.zone"; allow-transfer { !{ !127.0.0.1; any; }; key tk; }; };
zone "xg.test" { type master; file "$W/xg.test.zone"; allow-transfer { 127.0.0.1; }; tsig-key tk; };
EOF
"$KARICHECK" conf "$W/s3.conf" > "$W/s3.check" 2>&1 || fail "karicheck conf s3: $(cat "$W/s3.check")"
"$KARIDNS" -f -c "$W/s3.conf" > "$W/s3.log" 2>&1 &
PIDS="$PIDS $!"
i=0; while [ $i -lt 100 ]; do "$DAG" @127.0.0.1 -p $P3 xa.test SOA +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1 && break; sleep 0.2; i=$((i + 1)); done
xfr_ok_t "allow-transfer from options is inherited by a zone without one" $P3 xa.test
xfr_no_t "a zone's allow-transfer { none; } overrides options'" $P3 xb.test
xfr_no_t "{ key tk; 192.0.2.1; } unsigned from 127.0.0.1" $P3 xc.test
xfr_ok_t "{ key tk; 192.0.2.1; } signed with tk (a key element matches on its own)" $P3 xc.test -y hmac-sha256:tk:$TK
xfr_ok_t "{ 127.0.0.1; key tk; } unsigned from 127.0.0.1 (first match: the address; it used to need both)" $P3 xd.test
xfr_no_t "{ 127.0.0.1; key tk; } with transfer-acl-match all, unsigned" $P3 xe.test
xfr_ok_t "{ 127.0.0.1; key tk; } with transfer-acl-match all, signed" $P3 xe.test -y hmac-sha256:tk:$TK
xfr_no_t "{ !{ !127.0.0.1; any; }; key tk; } (BIND's address AND key) unsigned from the address" $P3 xf.test
xfr_ok_t "{ !{ !127.0.0.1; any; }; key tk; } signed with tk from the address" $P3 xf.test -y hmac-sha256:tk:$TK
xfr_no_t "{ 127.0.0.1; } with the zone's tsig-key, unsigned (the key stays required: address AND tsig-key)" $P3 xg.test
xfr_ok_t "{ 127.0.0.1; } with the zone's tsig-key, signed with it" $P3 xg.test -y hmac-sha256:tk:$TK
if [ "$ALIAS_ADDED" = "1" ]; then
    xfr_no_t "{ !{ !127.0.0.1; any; }; key tk; } signed with tk from $ALIAS_IP (the address part fails)" $P3 xf.test -b $ALIAS_IP -y hmac-sha256:tk:$TK
fi

# ---------------------------------------------------------------- karicheck
cat > "$W/bad1.conf" <<EOF
options { port 5353; };
zone "a.test" { type master; file "$W/open.test.zone";
  allow-query { nosuchacl; }; };
EOF
OUT=$("$KARICHECK" conf "$W/bad1.conf" 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "bad1.conf:3: zone 'a.test.' allow-query: entry 'nosuchacl' is not an address"; then pass "karicheck conf: an undefined acl name is an error with file:line"; else fail "karicheck bad1 (rc=$RC): $OUT"; fi
cat > "$W/bad2.conf" <<EOF
options { port 5353;
  allow-update { key nokey; }; };
EOF
OUT=$("$KARICHECK" conf "$W/bad2.conf" 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "bad2.conf:2: options allow-update: key 'nokey' is not defined"; then pass "karicheck conf: an undefined key is an error with file:line"; else fail "karicheck bad2 (rc=$RC): $OUT"; fi
cat > "$W/bad3.conf" <<EOF
options { port 5353; allow-query { 192.0.2.1 }; };
EOF
OUT=$("$KARICHECK" conf "$W/bad3.conf" 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "bad3.conf:[12]: options allow-query: expected ';' after the element"; then pass "karicheck conf: a missing ';' is an error with file:line"; else fail "karicheck bad3 (rc=$RC): $OUT"; fi
cat > "$W/bad4.conf" <<EOF
acl a1 { a2; };
acl a2 { a1; };
options { port 5353; allow-query { a1; }; };
EOF
OUT=$("$KARICHECK" conf "$W/bad4.conf" 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "refers to itself"; then pass "karicheck conf: acl blocks that contain each other are an error"; else fail "karicheck bad4 (rc=$RC): $OUT"; fi
cat > "$W/bad5.conf" <<EOF
options { port 5353; allow-transfer port 53 { any; }; };
EOF
OUT=$("$KARICHECK" conf "$W/bad5.conf" 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "bad5.conf:1: options allow-transfer: 'port' in front of the address list is not supported"; then pass "karicheck conf: allow-transfer port/transport qualifiers are refused"; else fail "karicheck bad5 (rc=$RC): $OUT"; fi
cat > "$W/warn1.conf" <<EOF
key "k1" { algorithm hmac-sha256; secret "$TK"; };
zone "a.test" { type master; file "$W/open.test.zone"; allow-transfer { 192.0.2.1; key k1; }; };
zone "b.test" { type master; file "$W/open.test.zone"; allow-transfer { 192.0.2.1; key k1; }; transfer-acl-match all; };
zone "c.test" { type master; file "$W/open.test.zone"; allow-transfer { 192.0.2.1; }; tsig-key k1; };
zone "d.test" { type master; file "$W/open.test.zone"; allow-update { !192.0.2.9; 192.0.2.0/24; key k1; }; };
zone "e.test" { type master; file "$W/open.test.zone"; allow-transfer { 192.0.2.1; }; };
EOF
OUT=$("$KARICHECK" conf "$W/warn1.conf" 2>&1); RC=$?
[ $RC -eq 0 ] || fail "karicheck warn1 (rc=$RC): $OUT"
echo "$OUT" | grep -q "Zone 'a.test.': allow-transfer lists addresses and keys: it now lets in" && pass "karicheck conf: warns that { address; key; } became address OR key" || fail "warning for a.test: $OUT"
echo "$OUT" | grep -q "Zone 'b.test.': allow-transfer lists" && fail "no warning expected for transfer-acl-match all: $OUT" || pass "karicheck conf: no warning with transfer-acl-match all"
echo "$OUT" | grep -q "Zone 'c.test.'" && fail "no warning expected for addresses plus the zone's tsig-key (unchanged): $OUT" || pass "karicheck conf: no warning for addresses plus the zone's tsig-key (that stays address AND key)"
echo "$OUT" | grep -q "Zone 'd.test.': allow-update has keys and negated entries" && pass "karicheck conf: warns for allow-update with keys and negated entries" || fail "warning for d.test: $OUT"
echo "$OUT" | grep -q "Zone 'e.test.'" && fail "no warning expected for addresses only: $OUT" || pass "karicheck conf: no warning for a list of addresses only"

if [ "$FAILS" -eq 0 ]; then echo "ALL TESTS PASSED"; exit 0; fi
echo "$FAILS FAILURE(S)"
exit 1
