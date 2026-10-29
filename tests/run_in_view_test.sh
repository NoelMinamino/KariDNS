#!/bin/sh
# ==============================================================================
# tests/run_in_view_test.sh - zone { in-view "view"; } and in-view-settings (BIND 9.20, batch 8 phase 1)
# ==============================================================================
# BIND lib/isccfg/check.c check_zoneconf(), bin/named/server.c configure_zone(): a zone of an earlier view is the zone of this view too (one zone
# object: one set of data, one NOTIFY, one IXFR history); lib/ns/query.c: the answer is made with the options of the view the client came through.
#   K  karicheck conf: the errors of check.c with file:line (no such view / zone, view defined later, incompatible options), the ACL statements
#      of an in-view zone only with `in-view-settings view`, and the value errors
#   O  in-view-settings owner (BIND): queries from both views are answered the same; AXFR is allowed by the owner zone / owner view lists (the
#      referencing view's own list does not count); an UPDATE through the referencing view reaches both; one NOTIFY per change; a reload keeps
#      the share; karictl notify / observatory name the zone once with `shared to views`; view-level minimal-responses differs per view (and
#      the shared response cache does not mix them up); removing the in-view stops the answers in that view and putting it back starts them
#   V  in-view-settings view (KariDNS): the in-view zone's own allow-transfer / allow-update / allow-query decide first, then the owner zone's, then
#      the referencing view's (not the owner view's), then options'; a refused client is not served from the response cache
#   G  the glue of a shared zone's NS in a sibling zone comes from the client's view (BIND query_getzonedb(): client->view), never from the
#      owner view's siblings, also through the response cache (queries in both orders)
# The loopback aliases 127.0.0.2 .. 127.0.0.5 are added when run as root and removed on exit; without them O, V and G are SKIPped.
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

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-inview.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
SECRET="aW4tdmlldy10ZXN0LWNvbnRyb2wta2V5LTAwMDAwMDA="
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"

PO=$(kari_port 0)      # owner mode server
PV=$(kari_port 1)      # view mode server
SK=$(kari_port 2)      # the NOTIFY sink

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
    for n in po pv pg; do kari_kill_conf "$W/$n.conf"; done
    for a in $ALIASES; do ifconfig lo0 inet "$a" -alias 2>/dev/null; done
    if [ "$FAILS" -ne 0 ]; then
        for f in po pv pg; do echo "--- $f.log (tail)"; tail -15 "$W/$f.log" 2>/dev/null; done
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

for p in $PO $PV $SK $(kari_port 3); do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

zone() { # zone FILE ORIGIN SERIAL
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s 3600 900 604800 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' "$2" "$3" > "$1"
}
start() { # start NAME : karidns on $W/NAME.conf
    env X=1 "$KARIDNS" -f "$W/$1.conf" > "$W/$1.log" 2>&1 &
    PIDS="$PIDS $!"
}
ctl() { n=$1; shift; "$KARICTL" -s "$W/$n.sock" -f "$W/ctl.conf" "$@" 2>&1; }
ctlblock() { printf 'control-channel { socket "%s/%s.sock"; algorithm hmac-sha256; secret "%s"; };\n' "$W" "$1" "$SECRET"; }
# q PORT SOURCE NAME [TYPE] : the short answer to a query from the address SOURCE (which view's match-clients it falls in)
q() { "$DAG" @127.0.0.1 -p "$1" -b "$2" "$3" "${4:-A}" +short +nohexdump +time=1 +tries=1 2>&1; }
# status PORT SOURCE NAME : the rcode of a query
status() { "$DAG" @127.0.0.1 -p "$1" -b "$2" "$3" A +nohexdump +noedns +time=1 +tries=1 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
# axfr PORT SOURCE ZONE : 0 when the transfer worked
axfr_ok() { "$DAG" "$3" AXFR @127.0.0.1 -p "$1" -b "$2" +tcp +nohexdump 2>&1 | grep -q "www.$3"; }
# upd PORT SOURCE ZONE NAME : an UPDATE adding NAME.ZONE A 192.0.2.99; the output
upd() { "$DAG" "$3" a @127.0.0.1 -p "$1" -b "$2" --update-add "$4.$3 300 A 192.0.2.99" +nohexdump 2>&1; }
upd_ok() { upd "$@" | grep -q "status: NOERROR"; }

# ------------------------------------------------------------------------------------------------ K: karicheck conf
zone "$W/x.zone" x.test 1
kc_err() { # kc_err NAME TEXT EXPECTED : the file is refused and the message has EXPECTED
    printf '%s\n' "$2" > "$W/$1.conf"
    if "$KARICHECK" conf "$W/$1.conf" > "$W/kc.out" 2>&1; then fail "K $1: karicheck conf accepted: $2"; return; fi
    if grep -q -- "$3" "$W/kc.out"; then pass "K $1: refused; the message has '$3'"
    else fail "K $1: refused but without '$3'"; cat "$W/kc.out"; fi
}
kc_ok() { # kc_ok NAME TEXT
    printf '%s\n' "$2" > "$W/$1.conf"
    if "$KARICHECK" conf "$W/$1.conf" > "$W/kc.out" 2>&1; then pass "K $1: accepted"; else fail "K $1: karicheck conf refused it"; cat "$W/kc.out"; fi
}
VA="view va { match-clients { 127.0.0.2; }; zone \"x.test\" { type master; file \"$W/x.zone\"; }; };"
kc_ok i1 "$VA
view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; }; };"
kc_err i2 "view vb { match-clients { any; }; zone \"x.test\" { in-view \"nope\"; }; };" \
    "i2.conf:1: zone 'x.test.': 'in-view' zone 'x.test.' does not exist in view 'nope', or view 'nope' is not yet defined"
kc_err i3 "$VA
view vb { match-clients { any; }; zone \"y.test\" { in-view \"va\"; }; };" \
    "'in-view' zone 'y.test.' does not exist in view 'va', or view 'va' is not yet defined"
kc_err i4 "view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; }; };
$VA" "'in-view' zone 'x.test.' does not exist in view 'va', or view 'va' is not yet defined"
kc_err i5 "$VA
view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; file \"$W/x.zone\"; }; };" \
    "i5.conf:2: zone 'x.test.': 'in-view' used with incompatible zone options"
kc_err i6 "$VA
view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; allow-query { any; }; }; };" \
    "zone 'x.test.': 'in-view' used with incompatible zone options"
kc_ok i7 "$VA
view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; in-view-settings view; allow-query { any; }; allow-transfer { none; }; }; };"
kc_ok i8 "options { in-view-settings view; };
$VA
view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; allow-update { none; }; }; };"
kc_err i9 "options { in-view-settings both; };" "i9.conf:1: options: in-view-settings: invalid value 'both' (expected owner or view)"
kc_err i10 "$VA
view vb { match-clients { any; }; in-view-settings sideways; };" "view 'vb': in-view-settings: invalid value 'sideways'"
kc_err i11 "$VA
view vb { match-clients { any; }; zone \"x.test\" { in-view \"va\"; in-view-settings x; }; };" "invalid in-view-settings value 'x' (expected owner or view)"
kc_err i12 "zone \"x.test\" { type master; file \"$W/x.zone\"; in-view-settings view; };" "'in-view-settings' is only valid in a zone with 'in-view'"
kc_ok i13 "view va { match-clients { 127.0.0.2; }; minimal-responses yes; };
view vb { match-clients { any; }; minimal-responses no-auth-recursive; };"
printf 'options { max-records-per-type 500; };\n' > "$W/i14.conf"
"$KARICHECK" conf "$W/i14.conf" > "$W/kc.out" 2>&1 && grep -q "i14.conf:1: options: max-records-per-type 500 is above BIND's default of 100" "$W/kc.out" \
    && pass "K i14: max-records-per-type above 100 is a warning with file:line" || { fail "K i14: no warning"; cat "$W/kc.out"; }
# karicheck zones checks a shared zone once, in its owner view
printf '%s\nview vb { match-clients { any; }; zone "x.test" { in-view "va"; }; };\n' "$VA" > "$W/i15.conf"
n=$("$KARICHECK" zones "$W/i15.conf" 2>&1 | grep -c "Checked 1 zones")
[ "$n" = 1 ] && pass "K i15: karicheck zones checks the shared zone once" || fail "K i15: karicheck zones: $("$KARICHECK" zones "$W/i15.conf" 2>&1)"

if [ "$HAVE_ALIAS" -ne 1 ]; then
    skip "O, V: they need the loopback aliases 127.0.0.2 - 127.0.0.5 (run as root)"
    echo "[*] $PASSES passed, $FAILS failed, $SKIPS skipped"
    [ "$FAILS" -eq 0 ]
    exit $?
fi

# ------------------------------------------------------------------------------------------------ O: in-view-settings owner
zone "$W/shr.zone" shr.test 7
zone "$W/ready.zone" ready.test 1
zone "$W/own.zone" own.test 1
perl "$DIR/mock_notify_sink.pl" --log "$W/sink.log" --ports "$SK" --answer 2>/dev/null &
PIDS="$PIDS $!"
cat > "$W/po.in" <<EOF
options { port $PO; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT minimal-responses no; };
$(ctlblock po)
view va { match-clients { 127.0.0.2; }; allow-transfer { 127.0.0.2; 127.0.0.4; };
  zone "shr.test" { type master; file "$W/shr.zone"; allow-update { 127.0.0.2; 127.0.0.3; }; also-notify { 127.0.0.1 port $SK; }; }; };
view vb { match-clients { 127.0.0.3; 127.0.0.4; }; minimal-responses yes; allow-transfer { 127.0.0.3; };
@INVIEW@
};
view vc { match-clients { any; }; zone "ready.test" { type master; file "$W/ready.zone"; }; };
EOF
mkconf_o() { # mkconf_o INVIEWTEXT : $W/po.conf
    awk -v t="$1" '{ if ($0 == "@INVIEW@") print t; else print }' "$W/po.in" > "$W/po.conf"
}
mkconf_o '  zone "shr.test" { in-view "va"; };'
"$KARICHECK" conf "$W/po.conf" > "$W/kc.out" 2>&1 || { fail "O: karicheck conf refused po.conf"; cat "$W/kc.out"; }
start po
kari_wait_answer "$DAG" "$PO" ready.test. || true
sleep 1
notify_count() { grep -c "qname=shr.test" "$W/sink.log" 2>/dev/null; }

a2=$(q $PO 127.0.0.2 www.shr.test); a3=$(q $PO 127.0.0.3 www.shr.test); a4=$(q $PO 127.0.0.4 www.shr.test)
[ "$a2" = 192.0.2.10 ] && [ "$a3" = "$a2" ] && [ "$a4" = "$a2" ] && pass "O1: both views answer www.shr.test the same" || fail "O1: va='$a2' vb='$a3' vb2='$a4'"
s=$(q $PO 127.0.0.3 shr.test SOA); [ "$(q $PO 127.0.0.2 shr.test SOA)" = "$s" ] && [ -n "$s" ] && pass "O2: the SOA is the same in both views" || fail "O2: SOA differs: '$s'"

axfr_ok $PO 127.0.0.2 shr.test && pass "O3: AXFR from the owner view is allowed (owner view's allow-transfer)" || fail "O3: AXFR from 127.0.0.2"
axfr_ok $PO 127.0.0.4 shr.test && pass "O4: AXFR through the referencing view is allowed by the owner view's allow-transfer (127.0.0.4)" || fail "O4: AXFR from 127.0.0.4 through vb"
axfr_ok $PO 127.0.0.3 shr.test && fail "O5: AXFR through vb was allowed by vb's own allow-transfer (in-view-settings owner ignores it)" \
    || pass "O5: AXFR through vb is refused although vb's own allow-transfer lists the client (owner mode)"

before=$(notify_count)
upd_ok $PO 127.0.0.3 shr.test n1 && pass "O6: an UPDATE through the referencing view is allowed (allow-update of the owner zone)" || fail "O6: UPDATE through vb refused"
upd_ok $PO 127.0.0.4 shr.test n2 && fail "O7: an UPDATE from 127.0.0.4 (not in allow-update) was accepted" || pass "O7: an UPDATE from a client the owner zone does not list is refused"
sleep 3
[ "$(q $PO 127.0.0.2 n1.shr.test)" = 192.0.2.99 ] && [ "$(q $PO 127.0.0.3 n1.shr.test)" = 192.0.2.99 ] && [ -z "$(q $PO 127.0.0.4 n2.shr.test)" ] \
    && pass "O8: the UPDATE of vb is in both views; the refused one changed nothing" || fail "O8: n1 va='$(q $PO 127.0.0.2 n1.shr.test)' vb='$(q $PO 127.0.0.3 n1.shr.test)' n2='$(q $PO 127.0.0.4 n2.shr.test)'"
after=$(notify_count)
[ $((after - before)) -eq 1 ] && pass "O9: one NOTIFY for the change (not one per view)" || fail "O9: NOTIFY messages for the change: $((after - before)) (before $before, after $after)"
upd_ok $PO 127.0.0.2 shr.test n3 && sleep 3 && [ "$(q $PO 127.0.0.3 n3.shr.test)" = 192.0.2.99 ] && pass "O10: an UPDATE through the owner view is in the referencing view" || fail "O10: n3 in vb"
[ $(($(notify_count) - after)) -eq 1 ] && pass "O11: ... again one NOTIFY" || fail "O11: NOTIFY messages: $(($(notify_count) - after))"

# minimal-responses of the client's view; alternate the views so that the cached answers are used
ok=1
for round in 1 2 3; do
    for src in 127.0.0.2 127.0.0.3 127.0.0.4; do
        out=$("$DAG" @127.0.0.1 -p $PO -b $src www.shr.test A +nohexdump +noedns +time=1 +tries=1 2>&1)
        case $src in
            127.0.0.2) echo "$out" | grep -q "AUTHORITY: 1" && echo "$out" | grep -q "ADDITIONAL: 1" || ok=0 ;;
            *) echo "$out" | grep -q "AUTHORITY: 0" && echo "$out" | grep -q "ADDITIONAL: 0" || ok=0 ;;
        esac
        [ "$ok" = 1 ] || { echo "$out"; break 2; }
    done
done
[ "$ok" = 1 ] && pass "O12: va (minimal-responses no) answers with authority and additional, vb (yes) without, also from the response cache" \
    || fail "O12: the view-level minimal-responses was mixed up"

hits=$(ctl po observatory shr.test | sed -n 's/.*WireCache: *Hits=\([0-9]*\).*/\1/p' | head -1)
[ -n "$hits" ] && [ "$hits" -gt 0 ] && pass "O12b: the answers above came partly from the shared response cache ($hits hits)" || fail "O12b: no response cache hit (Hits=$hits): the cache path was not tested"

out=$(ctl po observatory shr.test)
n=$(echo "$out" | grep -c "^Zone: shr.test")
echo "$out" | grep -q "^Zone: shr.test. (view: va, shared to views: vb)$" && [ "$n" = 1 ] && pass "O13: karictl observatory lists the zone once, in its owner view, with 'shared to views: vb'" \
    || fail "O13: observatory: $out"
out=$(ctl po observatory)
[ "$(echo "$out" | grep -c "^Zone: shr.test")" = 1 ] && [ "$(echo "$out" | grep -c "^Zone: ready.test")" = 1 ] && pass "O14: the listing of all zones has the shared zone once" || fail "O14: $out"
out=$(ctl po notify shr.test)
[ "$out" = "OK" ] && pass "O15: karictl notify names the zone without a view (it is one zone)" || fail "O15: karictl notify shr.test: $out"
out=$(ctl po notify shr.test vb)
[ "$out" = "OK" ] && pass "O16: karictl notify <zone> <referencing view> reaches the owner's zone" || fail "O16: $out"
sleep 3
out=$(ctl po status)
echo "$out" | grep -qi "zones.*: *2$\|zones: *2" && pass "O17: the status counts the shared zone once" || { echo "$out" | grep -i zone; fail "O17: status zone count"; }

out=$(ctl po reload)
sleep 2
[ -z "$(q $PO 127.0.0.2 n1.shr.test)" ] && [ -z "$(q $PO 127.0.0.3 n1.shr.test)" ] && [ "$(q $PO 127.0.0.3 www.shr.test)" = 192.0.2.10 ] && [ "$(q $PO 127.0.0.2 www.shr.test)" = 192.0.2.10 ] && pass "O18: after a reload (nothing changed) both views answer from the reloaded zone (the UPDATEs are gone from both)" || fail "O18: reload: $out"
ctl po observatory shr.test | grep -q "shared to views: vb" && pass "O19: ... and the zone is still shared" || fail "O19: observatory after the reload"

mkconf_o '  zone "own.test" { type master; file "'$W'/own.zone"; };'
out=$(ctl po reload)
sleep 2
st=$(status $PO 127.0.0.3 www.shr.test)
[ "$st" = REFUSED ] && [ "$(q $PO 127.0.0.2 www.shr.test)" = 192.0.2.10 ] && pass "O20: with the in-view removed, view vb no longer answers the zone (REFUSED) and va does" || fail "O20: vb status '$st' ($out)"
ctl po observatory shr.test | grep -q "shared to views" && fail "O21: the zone is still listed as shared" || pass "O21: ... and the listing no longer says shared"
mkconf_o '  zone "shr.test" { in-view "va"; };'
out=$(ctl po reload)
sleep 2
[ "$(q $PO 127.0.0.3 www.shr.test)" = 192.0.2.10 ] && upd_ok $PO 127.0.0.3 shr.test n4 && sleep 2 && [ "$(q $PO 127.0.0.2 n4.shr.test)" = 192.0.2.99 ] && pass "O22: putting the in-view back shares the zone again (an UPDATE through vb is in va)" || fail "O22: vb after the in-view came back ($out)"
ctl po observatory shr.test | grep -q "shared to views: vb" && pass "O23: ... and the listing says shared again" || fail "O23: observatory"

# ------------------------------------------------------------------------------------------------ V: in-view-settings view
zone "$W/inh.zone" inh.test 3
zone "$W/inh2.zone" inh2.test 3
cat > "$W/pv.conf" <<EOF
options { port $PV; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT in-view-settings view; minimal-responses no; };
$(ctlblock pv)
view va { match-clients { 127.0.0.2; }; allow-transfer { 127.0.0.2; 127.0.0.4; };
  zone "shr.test" { type master; file "$W/shr.zone"; allow-update { 127.0.0.2; 127.0.0.3; }; allow-transfer { 127.0.0.2; 127.0.0.5; }; };
  zone "inh.test" { type master; file "$W/inh.zone"; allow-transfer { 127.0.0.4; }; };
  zone "inh2.test" { type master; file "$W/inh2.zone"; }; };
view vb { match-clients { 127.0.0.3; 127.0.0.4; }; allow-transfer { 127.0.0.3; 127.0.0.4; };
  zone "shr.test" { in-view "va"; allow-transfer { 127.0.0.3; }; allow-update { 127.0.0.4; }; allow-query { 127.0.0.3; }; };
  zone "inh.test" { in-view "va"; };
  zone "inh2.test" { in-view "va"; }; };
view vc { match-clients { any; }; zone "ready.test" { type master; file "$W/ready.zone"; }; };
EOF
"$KARICHECK" conf "$W/pv.conf" > "$W/kc.out" 2>&1 || { fail "V: karicheck conf refused pv.conf"; cat "$W/kc.out"; }
start pv
kari_wait_answer "$DAG" "$PV" ready.test. || true
sleep 1

# allow-query of the in-view zone: the client that may ask primes the response cache, the other is refused
r3=$(q $PV 127.0.0.3 www.shr.test); r3b=$(q $PV 127.0.0.3 www.shr.test)
[ "$r3" = 192.0.2.10 ] && [ "$r3b" = 192.0.2.10 ] && pass "V1: the in-view zone's allow-query lets 127.0.0.3 in" || fail "V1: '$r3' '$r3b'"
st=$(status $PV 127.0.0.4 www.shr.test); r4=$(q $PV 127.0.0.4 www.shr.test)
[ "$st" = REFUSED ] && ! echo "$r4" | grep -q 192.0.2.10 && pass "V2: 127.0.0.4 is refused although the answer is in the cache (the ACL comes before the cache)" || fail "V2: status '$st' answer '$r4'"
[ "$(q $PV 127.0.0.2 www.shr.test)" = 192.0.2.10 ] && pass "V3: the owner view has no query ACL and answers" || fail "V3: va"

axfr_ok $PV 127.0.0.3 shr.test && pass "V4: AXFR through vb: the in-view zone's allow-transfer lists 127.0.0.3" || fail "V4: AXFR from 127.0.0.3"
axfr_ok $PV 127.0.0.4 shr.test && fail "V5: AXFR from 127.0.0.4 was allowed (the in-view zone's list overrides vb's, which lists it)" \
    || pass "V5: AXFR from 127.0.0.4 is refused: the in-view zone's own list overrides vb's, which lists it"
axfr_ok $PV 127.0.0.2 shr.test && pass "V6: AXFR through the owner view is decided by the owner zone's list" || fail "V6: AXFR from 127.0.0.2"
axfr_ok $PV 127.0.0.4 inh.test && pass "V7: no in-view list: the owner zone's allow-transfer decides (127.0.0.4)" || fail "V7: AXFR of inh.test from 127.0.0.4"
axfr_ok $PV 127.0.0.3 inh.test && fail "V8: AXFR of inh.test from 127.0.0.3 was allowed by vb's list (the owner zone's list comes first)" \
    || pass "V8: ... and vb's view-level list does not override the owner zone's"
axfr_ok $PV 127.0.0.3 inh2.test && pass "V9: neither the in-view zone nor the owner zone has a list: the referencing view's allow-transfer decides (127.0.0.3)" || fail "V9: AXFR of inh2.test from 127.0.0.3"
axfr_ok $PV 127.0.0.2 inh2.test && pass "V10: ... and the owner view's applies to its own clients (127.0.0.2)" || fail "V10: AXFR of inh2.test from 127.0.0.2"

upd_ok $PV 127.0.0.4 shr.test v1 && pass "V11: an UPDATE through vb: the in-view zone's allow-update lists 127.0.0.4" || fail "V11: UPDATE from 127.0.0.4"
upd_ok $PV 127.0.0.3 shr.test v2 && fail "V12: an UPDATE from 127.0.0.3 was accepted (the owner zone lists it, the in-view zone's own list overrides)" \
    || pass "V12: an UPDATE from 127.0.0.3 is refused: the in-view zone's own allow-update overrides the owner zone's"
upd_ok $PV 127.0.0.2 shr.test v3 && pass "V13: through the owner view the owner zone's allow-update applies" || fail "V13: UPDATE from 127.0.0.2"
sleep 2
[ "$(q $PV 127.0.0.3 v1.shr.test)" = 192.0.2.99 ] && [ "$(q $PV 127.0.0.2 v1.shr.test)" = 192.0.2.99 ] && [ "$(q $PV 127.0.0.2 v3.shr.test)" = 192.0.2.99 ] && [ -z "$(q $PV 127.0.0.3 v2.shr.test)" ] \
    && pass "V14: the accepted UPDATEs are in both views, the refused one nowhere" || fail "V14: data after the UPDATEs"

out=$(ctl pv observatory shr.test)
echo "$out" | grep -q "^Zone: shr.test. (view: va, shared to views: vb)$" && pass "V15: karictl observatory in view mode: the zone once, shared to vb" || fail "V15: $out"

# ------------------------------------------------------------------------------------------------ G: sibling-zone glue of a shared zone
# The NS of the shared zone shr2.test is ns.sib.test., a zone of a sibling.  BIND finds additional data in the zones of the CLIENT's view
# (lib/ns/query.c query_getzonedb(): dns_view_findzone(client->view, ...)).  ga has sib.test with 192.0.2.1, gb has its own sib.test with
# 192.0.2.2, gc has none: ga's address must never reach the clients of gb or gc, in either order of the queries (the response cache).
printf '$TTL 300\n$ORIGIN shr2.test.\n@ IN SOA ns.sib.test. hostmaster 1 3600 900 604800 60\n@ IN NS ns.sib.test.\nwww IN A 192.0.2.10\n' > "$W/shr2.zone"
printf '$TTL 300\n$ORIGIN sib.test.\n@ IN SOA ns hostmaster 1 3600 900 604800 60\n@ IN NS ns\nns IN A 192.0.2.1\n' > "$W/siba.zone"
printf '$TTL 300\n$ORIGIN sib.test.\n@ IN SOA ns hostmaster 1 3600 900 604800 60\n@ IN NS ns\nns IN A 192.0.2.2\n' > "$W/sibb.zone"
PG=$(kari_port 3)
cat > "$W/pg.conf" <<EOF
options { port $PG; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
view ga { match-clients { 127.0.0.2; };
  zone "shr2.test" { type master; file "$W/shr2.zone"; };
  zone "sib.test" { type master; file "$W/siba.zone"; }; };
view gb { match-clients { 127.0.0.3; };
  zone "shr2.test" { in-view "ga"; };
  zone "sib.test" { type master; file "$W/sibb.zone"; }; };
view gc { match-clients { 127.0.0.4; }; zone "shr2.test" { in-view "ga"; }; };
view gd { match-clients { any; }; zone "ready.test" { type master; file "$W/ready.zone"; }; };
EOF
"$KARICHECK" conf "$W/pg.conf" > "$W/kc.out" 2>&1 || { fail "G: karicheck conf refused pg.conf"; cat "$W/kc.out"; }
start pg
kari_wait_answer "$DAG" "$PG" ready.test. || true
# glue_of SOURCE : the addresses of ns.sib.test. in the Additional section of "shr2.test NS", space separated
glue_of() { "$DAG" @127.0.0.1 -p $PG -b "$1" shr2.test NS +nohexdump +noedns +time=1 +tries=1 2>&1 | awk '$1 == "ns.sib.test." && $4 == "A" { printf "%s ", $5 }'; }
g_ok=1
g_seq="127.0.0.4:none 127.0.0.2:192.0.2.1 127.0.0.3:192.0.2.2 127.0.0.4:none 127.0.0.2:192.0.2.1 127.0.0.3:192.0.2.2 127.0.0.2:192.0.2.1 127.0.0.4:none"
for step in $g_seq; do
    src=${step%%:*}; want=${step#*:}
    got=$(glue_of "$src" | sed 's/ $//')
    [ "$want" = none ] && want=""
    if [ "$got" != "$want" ]; then
        g_ok=0
        echo "  G: from $src the glue of ns.sib.test. is '$got', expected '$want'"
        "$DAG" @127.0.0.1 -p $PG -b "$src" shr2.test NS +nohexdump +noedns +time=1 +tries=1 2>&1 | sed 's/^/     /'
    fi
done
[ "$g_ok" = 1 ] && pass "G1: the glue of the shared zone's NS comes from the client's view (ga 192.0.2.1, gb 192.0.2.2, gc none), in any order, queried repeatedly" \
    || fail "G1: sibling glue of a shared zone differs from the client's view"
leak=$("$DAG" @127.0.0.1 -p $PG -b 127.0.0.3 shr2.test NS +nohexdump +noedns +time=1 +tries=1 2>&1 | grep -c "192.0.2.1$")
[ "$leak" = 0 ] && pass "G2: the address of the owner view's sibling never appears for gb" || fail "G2: 192.0.2.1 leaked to gb"
# a name below the shared zone that needs no sibling is still served from the cache for every view
for src in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.2 127.0.0.3; do
    [ "$(q $PG $src www.shr2.test)" = 192.0.2.10 ] || g_ok=0
done
[ "$g_ok" = 1 ] && pass "G3: www.shr2.test is the same in all three views" || fail "G3: www.shr2.test"

echo "[*] $PASSES passed, $FAILS failed, $SKIPS skipped"
[ "$FAILS" -eq 0 ]
