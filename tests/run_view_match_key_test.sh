#!/bin/sh
# run_view_match_key_test.sh - match-clients { key <name>; } (BIND 9.20 bin/named/server.c get_matching_view_sync()): the view of a request is
# chosen by the TSIG key it is signed with, verified in that view's key ring.
#
#   K1-K3  queries over UDP and TCP: signed with key A -> view a, key B -> view b, unsigned -> the view of its address
#   K4-K6  a MAC that does not verify, a key nobody knows, a key of the wrong view: not the view of that key (the address view answers NOTAUTH)
#   K7     AXFR (TCP) is taken from the view of the key
#   K8     UPDATE signed with key A changes view a only; unsigned UPDATE is refused
#   K9     NOTIFY (OPCODE 4) of a secondary zone that exists in the key views only
#   K10    key views of one name with different secrets (each checked in its own ring)
#   K11    the same after karictl reload
#   K12    karicheck: an undefined key is an error with file:line; a defined one is accepted
#
# karidns runs on 127.0.0.1 as a normal user; every client is 127.0.0.1, so only the TSIG key tells the views apart.  KARIDNS=./karidns-tsan
# runs the server under ThreadSanitizer (the view is chosen on the query path of every worker).
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

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-viewkey.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
b64() { perl -MMIME::Base64 -e 'print encode_base64($ARGV[0], "")' "$1"; }
KA=$(b64 "viewkey-a-secret-0123456789abcd")
KB=$(b64 "viewkey-b-secret-0123456789abcd")
KX=$(b64 "viewkey-x-secret-0123456789abcd")      # a wrong secret for the name ka
V1=$(b64 "viewkey-ring-one-0123456789abcdef")    # key "k" in view r1
V2=$(b64 "viewkey-ring-two-0123456789abcdef")    # key "k" in view r2
CS=$(b64 "viewkey-control-0123456789abcdefg")
P=$(kari_port 0 15701)
P2=$(kari_port 1 15702)

PIDS=""
FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/p.conf" "$W/r.conf"
    if [ "$FAILS" -ne 0 ]; then
        echo "--- p.log (tail)"; tail -25 "$W/p.log" 2>/dev/null
        echo "--- r.log (tail)"; tail -25 "$W/r.log" 2>/dev/null
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P $P2; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

zone() { # zone FILE ORIGIN WHO
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwho IN TXT "%s"\n' "$1" "$3" > "$W/$2"
}
zone x.test xa.zone view-a
zone x.test xb.zone view-b
zone x.test xc.zone view-c
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$CS\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
CT="$KARICTL -s $W/ctl.sock -f $W/ctl.conf"

cat > "$W/p.conf" <<EOF
options { port $P; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT notify no; };
control-channel { socket "$W/ctl.sock"; algorithm hmac-sha256; secret "$CS"; };
key "ka" { algorithm hmac-sha256; secret "$KA"; };
key "kb" { algorithm hmac-sha256; secret "$KB"; };
view "va" { match-clients { key ka; };
  zone "x.test" { type master; file "$W/xa.zone"; allow-transfer { key ka; }; allow-update { key ka; }; };
  zone "n.test" { type slave; primaries { 127.0.0.1 port $P2 key ka; }; }; };
view "vb" { match-clients { key kb; };
  zone "x.test" { type master; file "$W/xb.zone"; allow-transfer { key kb; }; allow-update { key kb; }; };
  zone "n.test" { type slave; primaries { 127.0.0.1 port $P2 key kb; }; }; };
view "vc" { match-clients { any; };
  zone "x.test" { type master; file "$W/xc.zone"; allow-transfer { 127.0.0.1; }; allow-update { none; }; }; };
EOF
"$KARIDNS" -f "$W/p.conf" > "$W/p.log" 2>&1 &
PIDS="$PIDS $!"
kari_wait_answer "$DAG" "$P" x.test. || true

# who TRANSPORT KEYSPEC : the TXT of who.x.test as the server answers it ("" for a failure)
who() { # who [+tcp] [-y spec]
    "$DAG" @127.0.0.1 -p "$P" who.x.test TXT +short +nohexdump +time=2 +tries=1 "$@" 2>/dev/null | tr -d '"'
}
status_of() { "$DAG" @127.0.0.1 -p "$P" who.x.test TXT +nohexdump +time=2 +tries=1 "$@" 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
SIGA="hmac-sha256:ka:$KA"; SIGB="hmac-sha256:kb:$KB"

check_who() { # check_who LABEL EXPECT [dag args]
    _l=$1; _e=$2; shift 2
    _g=$(who "$@")
    if [ "$_g" = "$_e" ]; then pass "$_l"; else fail "$_l: got '$_g', expected '$_e'"; fi
}

check_views() { # check_views PREFIX
    check_who "$1 UDP signed with ka: view va" view-a -y "$SIGA"
    check_who "$1 UDP signed with kb: view vb" view-b -y "$SIGB"
    check_who "$1 UDP unsigned: the view of the address" view-c
    check_who "$1 TCP signed with ka: view va" view-a +tcp -y "$SIGA"
    check_who "$1 TCP signed with kb: view vb" view-b +tcp -y "$SIGB"
    check_who "$1 TCP unsigned: the view of the address" view-c +tcp
}
check_views "K1-K3"

# K4-K6: the signature has to verify in the ring of the view, else the key identifies nobody (BIND: dns_message_checksig() fails, the identity is NULL)
st=$(status_of -y "hmac-sha256:ka:$KX")
[ "$st" = NOTAUTH ] && pass "K4: a MAC that does not verify (key ka, wrong secret) does not select view va: view vc answers NOTAUTH" || fail "K4: status '$st' (expected NOTAUTH)"
g=$(who -y "hmac-sha256:ka:$KX")
case "$g" in *view-a*|*view-b*) fail "K4b: got the data of a key view: '$g'" ;; *) pass "K4b: ... and the answer has no data of a key view" ;; esac
st=$(status_of -y "hmac-sha256:nokey:$KA")
[ "$st" = NOTAUTH ] && pass "K5: a key that no ring has: NOTAUTH from the view of the address" || fail "K5: status '$st' (expected NOTAUTH)"
st=$(status_of +tcp -y "hmac-sha256:ka:$KX")
[ "$st" = NOTAUTH ] && pass "K6: the same over TCP" || fail "K6: status '$st' (expected NOTAUTH)"

# K7: AXFR (TCP): the zone of the view of the key
axfr() { "$DAG" x.test AXFR @127.0.0.1 -p "$P" +tcp +nohexdump "$@" 2>&1; }
out=$(axfr -y "$SIGA"); case "$out" in *view-a*) pass "K7a: an AXFR signed with ka is the zone of view va" ;; *) fail "K7a: $out" ;; esac
out=$(axfr -y "$SIGB"); case "$out" in *view-b*) pass "K7b: an AXFR signed with kb is the zone of view vb" ;; *) fail "K7b: $out" ;; esac
out=$(axfr); case "$out" in *view-c*) pass "K7c: an unsigned AXFR is the zone of view vc (the address)" ;; *) fail "K7c: $out" ;; esac
out=$(axfr -y "hmac-sha256:ka:$KX"); case "$out" in *view-a*) fail "K7d: an AXFR with a wrong MAC got view va" ;; *) pass "K7d: an AXFR with a wrong MAC does not get view va" ;; esac

# K8: UPDATE
upd() { # upd NAME [dag args]
    _n=$1; shift
    "$DAG" x.test a @127.0.0.1 -p "$P" --update-add "$_n.x.test 300 A 192.0.2.99" +nohexdump "$@" 2>&1
}
q() { "$DAG" @127.0.0.1 -p "$P" "$1.x.test" A +short +nohexdump +time=2 +tries=1 "${2:-+notcp}" ${3:+-y "$3"} 2>/dev/null; }
out=$(upd newa -y "$SIGA"); case "$out" in *"status: NOERROR"*) pass "K8a: an UPDATE signed with ka is accepted (view va)" ;; *) fail "K8a: $out" ;; esac
out=$(upd newc); case "$out" in *"status: REFUSED"*) pass "K8b: an unsigned UPDATE goes to view vc and is refused" ;; *) fail "K8b: $out" ;; esac
if [ "$(q newa +notcp "$SIGA")" = 192.0.2.99 ] && [ -z "$(q newa +notcp "$SIGB")" ] && [ -z "$(q newa +notcp)" ] && [ -z "$(q newc +notcp "$SIGA")" ]; then
    pass "K8d: the UPDATE is in view va only (not in vb and vc), the refused one changed nothing"
else fail "K8d: newa va='$(q newa +notcp "$SIGA")' vb='$(q newa +notcp "$SIGB")' vc='$(q newa +notcp)'"; fi
out=$(upd newk -y "$SIGB"); case "$out" in *"status: NOERROR"*) pass "K8e: an UPDATE signed with kb is accepted (view vb)" ;; *) fail "K8e: $out" ;; esac
if [ "$(q newk +notcp "$SIGB")" = 192.0.2.99 ] && [ -z "$(q newk +notcp "$SIGA")" ]; then pass "K8f: ... and it is in view vb only"
else fail "K8f: newk vb='$(q newk +notcp "$SIGB")' va='$(q newk +notcp "$SIGA")'"; fi

# K9: NOTIFY for a secondary zone that only the key views have (RFC 1996): accepted from the primary signed with the primary's key
notify() { "$DAG" n.test SOA @127.0.0.1 -p "$P" +opcode=NOTIFY +aaflag +norec +nohexdump +time=2 +tries=1 "$@" 2>&1; }
out=$(notify -y "$SIGA"); case "$out" in *"status: NOERROR"*) pass "K9a: a NOTIFY signed with ka is taken in view va (the zone is there, ka is its primary's key)" ;; *) fail "K9a: $out" ;; esac
out=$(notify -y "$SIGB"); case "$out" in *"status: NOERROR"*) pass "K9b: a NOTIFY signed with kb is taken in view vb" ;; *) fail "K9b: $out" ;; esac
out=$(notify); case "$out" in *"status: NOERROR"*) fail "K9c: an unsigned NOTIFY was accepted (view vc has no such zone)" ;; *) pass "K9c: an unsigned NOTIFY goes to view vc, which has no such zone: not accepted" ;; esac

# K11: a reload rebuilds the snapshot; the views are the same afterwards
$CT reload > /dev/null 2>&1
sleep 2
check_views "K11"

# K12: karicheck
cat > "$W/ok.conf" <<EOF
key "ka" { algorithm hmac-sha256; secret "$KA"; };
acl "signers" { key ka; };
view "va" { match-clients { signers; 192.0.2.0/24; }; zone "x.test" { type master; file "$W/xa.zone"; }; };
view "vb" { match-clients { !key ka; any; }; zone "x.test" { type master; file "$W/xb.zone"; }; };
EOF
out=$("$KARICHECK" conf "$W/ok.conf" 2>&1); rc=$?
[ "$rc" -eq 0 ] && pass "K12a: karicheck accepts key elements in match-clients (also through an acl, negated)" || { fail "K12a: karicheck rc=$rc"; echo "$out"; }
cat > "$W/bad.conf" <<EOF
view "va" { match-clients { key nokey; }; zone "x.test" { type master; file "$W/xa.zone"; }; };
EOF
out=$("$KARICHECK" conf "$W/bad.conf" 2>&1); rc=$?
case "$out" in *"bad.conf:1"*"match-clients"*"key 'nokey' is not defined"*) [ "$rc" -ne 0 ] && pass "K12b: an undefined key in match-clients is an error with file:line" || fail "K12b: rc=0" ;; *) fail "K12b: $out" ;; esac

# K13: karicheck warns (KariDNS warning, not an error) about a keyed view that an earlier view hides; only when that view surely matches everything
kc_shadow() { # kc_shadow LABEL EXPECTED_WARNINGS FIRST_VIEW_MATCH : a view "va" with the match list, then a keyed view "vk"
    printf 'key "ka" { algorithm hmac-sha256; secret "%s"; };\nview "va" { %s zone "x.test" { type master; file "%s/xa.zone"; }; };\nview "vk" {\n  match-clients { key ka; };\n  zone "x.test" { type master; file "%s/xb.zone"; };\n};\n' \
        "$KA" "$3" "$W" "$W" > "$W/sh.conf"
    out=$("$KARICHECK" conf "$W/sh.conf" 2>&1); rc=$?
    n=$(printf '%s\n' "$out" | grep -c "can never be chosen")
    if [ "$rc" -eq 0 ] && [ "$n" -eq "$2" ]; then pass "$1"; else fail "$1: rc=$rc warnings=$n (expected $2)"; printf '%s\n' "$out"; fi
}
kc_shadow "K13a: an earlier view with match-clients { any; } hides the keyed view: one warning, exit 0" 1 'match-clients { any; };'
kc_shadow "K13b: 0.0.0.0/0 and ::/0 together do the same" 1 'match-clients { 0.0.0.0/0; ::/0; };'
kc_shadow "K13c: a view without match-clients matches everything" 1 ''
kc_shadow "K13d: IPv4 only (0.0.0.0/0): not sure, no warning" 0 'match-clients { 0.0.0.0/0; };'
kc_shadow "K13e: a negated element before any: not sure, no warning" 0 'match-clients { !192.0.2.0/24; any; };'
kc_shadow "K13f: an earlier view for one network: no warning" 0 'match-clients { 192.0.2.0/24; };'
kc_shadow "K13g: a nested list: the same warning" 1 'match-clients { { any; }; };'
case "$out" in *"sh.conf:4: view 'vk' match-clients: KariDNS warning"*) pass "K13h: the warning says it is a KariDNS warning and names sh.conf:4 (the keyed view's match-clients)" ;; *) fail "K13h: $out" ;; esac

# K10: key views of one name with different secrets, each checked in its own ring (a second server)
cat > "$W/r.conf" <<EOF
options { port $P2; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT notify no; };
view "r1" { key "k" { algorithm hmac-sha256; secret "$V1"; }; match-clients { key k; };
  zone "x.test" { type master; file "$W/xa.zone"; }; };
view "r2" { key "k" { algorithm hmac-sha256; secret "$V2"; }; match-clients { key k; };
  zone "x.test" { type master; file "$W/xb.zone"; }; };
view "r3" { match-clients { any; }; zone "x.test" { type master; file "$W/xc.zone"; }; };
EOF
"$KARIDNS" -f "$W/r.conf" > "$W/r.log" 2>&1 &
PIDS="$PIDS $!"
kari_wait_answer "$DAG" "$P2" x.test. || true
rw() { "$DAG" @127.0.0.1 -p "$P2" who.x.test TXT +short +nohexdump +time=2 +tries=1 "$@" 2>/dev/null | tr -d '"'; }
[ "$(rw -y "hmac-sha256:k:$V1")" = view-a ] && pass "K10a: key k with r1's secret: view r1" || fail "K10a: got '$(rw -y "hmac-sha256:k:$V1")'"
[ "$(rw -y "hmac-sha256:k:$V2")" = view-b ] && pass "K10b: key k with r2's secret: it fails in r1's ring, verifies in r2's: view r2" || fail "K10b: got '$(rw -y "hmac-sha256:k:$V2")'"
[ "$(rw)" = view-c ] && pass "K10c: unsigned: view r3" || fail "K10c: got '$(rw)'"

# a sanitizer build of the server (KARIDNS=./karidns-tsan or ./karidns-asan) reports into its log
if grep -q "ThreadSanitizer\|AddressSanitizer\|UndefinedBehaviorSanitizer\|runtime error:" "$W/p.log" "$W/r.log" 2>/dev/null; then
    fail "a sanitizer reported an error in the server log"
else pass "no sanitizer report in the server logs"; fi

echo "---"
if [ "$FAILS" -eq 0 ]; then echo "ALL PASSED"; exit 0; fi
echo "$FAILS FAILED"
exit 1
