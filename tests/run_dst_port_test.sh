#!/bin/sh
# run_dst_port_test.sh - options { port } is the default port of the servers a configuration names without a port (BIND 9.20
# bin/named/config.c named_config_getipandkeylist(): named_config_getport(config, "port"); lib/dns/zone.c notify_find_address(): the NS hosts of a zone are
# sent to at view->dstport, which bin/named/server.c sets from the same option):
#
#   D1  also-notify { 127.0.0.1; } with no port: the NOTIFY goes to options { port }        D2  an element's own port wins
#   D3  a remote-servers list name: its elements without a port take options { port }       D4  the NS host of the zone (glue 127.0.0.1) is sent to options { port }
#   D5  -p replaces the ports the server listens on, not this default (BIND: -p is the listen port only)
#   D6  primaries { 127.0.0.1; } with no port: the secondary transfers from options { port } (a primary on that port)
#   D7  a primaries element with its own port wins over options { port }
#   D8  karicheck conf accepts the configuration (the same parser)
#   D9  forwarders { 127.0.0.1; } of a forward zone with no port: the query goes to options { port } (bin/named/server.c configure_forward())
#   D10 forwarders port N { ... }: the port of the list is the default of its elements        D11 an element's own port wins
#   D12 karicheck conf accepts the forward zones
#
# The server under test listens somewhere else than options { port } (-p, or listen-on port), so that options { port } can be the port of the mock
# NOTIFY receivers (tests/mock_also_notify.pl, 127.0.0.1) and of a second KariDNS (the primary).  Normal user, 127.0.0.1 only.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$KARICHECK" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl karicheck dag >/dev/null || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }
perl -MDigest::SHA -MMIME::Base64 -MIO::Select -e 1 2>/dev/null || { echo "SKIP: perl modules Digest::SHA, MIME::Base64, IO::Select missing"; exit 0; }

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-dstport.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
PD=$(kari_port 0 15801)      # options { port } of the notifier: the mock NOTIFY receivers listen here
PE=$(kari_port 1 15802)      # a port written in an also-notify element
PL=$(kari_port 2 15803)      # where the notifier listens (-p)
PP=$(kari_port 3 15804)      # options { port } of the secondary and port of the primary
PS=$(kari_port 4 15805)      # where the secondary listens (listen-on port)
PQ=$(kari_port 5 15806)      # where a primary listens whose port is written in an element
PF=$(kari_port 6 15807)      # options { port } of the forwarding server: the upstream of the zone with no port
PF2=$(kari_port 7 15808)     # the port of a forwarders list
PF3=$(kari_port 8 15809)     # the port of a forwarders element
PG=$(kari_port 9 15810)      # where the forwarding server listens
CS="Y29udHJvbC1zZWNyZXQtZm9yLWRzdC1wb3J0LXRlc3Q="

PIDS=""
FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/n.conf" "$W/p.conf" "$W/s.conf" "$W/q.conf" "$W/f.conf"
    if [ "$FAILS" -ne 0 ]; then
        for f in n p s q f; do echo "--- $f.log (tail)"; tail -15 "$W/$f.log" 2>/dev/null; done
        echo "--- recv.log"; cat "$W/recv.log" 2>/dev/null
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $PD $PE $PL $PP $PS $PQ $PF $PF2 $PF3 $PG; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

zone() { # zone FILE ORIGIN SERIAL
    printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns0 hostmaster %s 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 127.0.0.1\nwww IN A 192.0.2.10\n' "$2" "$3" > "$1"
}
for z in zj zk zl zn; do zone "$W/$z.zone" "$z.test" 1; done
zone "$W/s.zone" s.test 7
zone "$W/t.zone" t.test 9
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$CS\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
CT="$KARICTL -s $W/ctl.sock -f $W/ctl.conf"

# ---- the notifier: options { port PD } is written AFTER the zones; the server listens on PL (-p).  The zone zn has an NS host 127.0.0.1 (glue);
# the other zones are notified through also-notify only (notify explicit leaves the NS hosts out).
cat > "$W/n.conf" <<EOF
remote-servers grp { 127.0.0.1; };
control-channel { socket "$W/ctl.sock"; algorithm hmac-sha256; secret "$CS"; };
zone "zj.test" { type master; file "$W/zj.zone"; notify explicit; also-notify { 127.0.0.1; }; };
zone "zk.test" { type master; file "$W/zk.zone"; notify explicit; also-notify { 127.0.0.1 port $PE; }; };
zone "zl.test" { type master; file "$W/zl.zone"; notify explicit; also-notify { grp; }; };
zone "zn.test" { type master; file "$W/zn.zone"; };
options { bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT port $PD; };
EOF
: > "$W/recv.log"
perl "$DIR/mock_also_notify.pl" --log "$W/recv.log" --ports "$PD,$PE" 2> "$W/mock.err" &
PIDS="$PIDS $!"
i=0; while ! grep -q READY "$W/mock.err" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
grep -q READY "$W/mock.err" || { fail "the NOTIFY receivers did not start"; cat "$W/mock.err"; exit 1; }

out=$("$KARICHECK" conf "$W/n.conf" 2>&1); rc=$?
[ "$rc" -eq 0 ] && pass "D8: karicheck conf accepts the configuration" || { fail "D8: karicheck conf rc=$rc"; echo "$out"; }

"$KARIDNS" -p "$PL" -f "$W/n.conf" > "$W/n.log" 2>&1 &
PIDS="$PIDS $!"
i=0; while ! [ -S "$W/ctl.sock" ] && [ $i -lt 100 ]; do sleep 0.2; i=$((i + 1)); done
[ -S "$W/ctl.sock" ] || { fail "karidns did not start"; exit 1; }
sleep 1
: > "$W/recv.log"
for z in zj zk zl zn; do $CT notify "$z.test" >/dev/null 2>&1; done
sleep 3

ports() { sed -n "s/^NOTIFY port=\([0-9]*\) qname=$1\.test .*/\1/p" "$W/recv.log" | sort -n | uniq | tr '\n' ' '; }
expect() { # expect ZONE LABEL PORT
    _g=$(ports "$1")
    if [ "$_g" = "$3 " ]; then pass "$2"; else fail "$2: $1.test got NOTIFY on [$_g], expected [$3]"; fi
}
expect zj "D1: also-notify { 127.0.0.1; } is sent to options { port } ($PD), not to 53 (options is written after the zone)" "$PD"
expect zk "D2: an element's own port ($PE) wins over options { port }" "$PE"
expect zl "D3: a remote-servers list name: its element without a port is sent to options { port } ($PD)" "$PD"
expect zn "D4: the NS host of the zone (glue 127.0.0.1) is sent to options { port } ($PD)" "$PD"
# D5: the server answers on the -p port and not on options { port }
a=$("$DAG" @127.0.0.1 -p "$PL" www.zj.test A +short +nohexdump +time=2 +tries=1 2>/dev/null)
[ "$a" = 192.0.2.10 ] && pass "D5: -p $PL is where the server listens; the default port of the lists stayed options { port }" || fail "D5: no answer on the -p port ($a)"

# ---- the primary (options { port PP }, listens there) and the secondary (options { port PP }, listens on PS)
cat > "$W/p.conf" <<EOF
options { port $PP; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT notify no; };
zone "s.test" { type master; file "$W/s.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$W/q.conf" <<EOF
options { port $PQ; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT notify no; };
zone "t.test" { type master; file "$W/t.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$W/s.conf" <<EOF
options { port $PP; listen-on port $PS { 127.0.0.1; }; listen-on-v6 { none; }; pid-file "none"; $USER_OPT min-refresh-time 1; min-retry-time 1; notify no; };
zone "s.test" { type slave; primaries { 127.0.0.1; }; };
zone "t.test" { type slave; primaries { 127.0.0.1 port $PQ; }; };
EOF
"$KARIDNS" -f "$W/p.conf" > "$W/p.log" 2>&1 & PIDS="$PIDS $!"
"$KARIDNS" -f "$W/q.conf" > "$W/q.log" 2>&1 & PIDS="$PIDS $!"
kari_wait_answer "$DAG" "$PP" s.test. || true
kari_wait_answer "$DAG" "$PQ" t.test. || true
"$KARIDNS" -f "$W/s.conf" > "$W/s.log" 2>&1 & PIDS="$PIDS $!"
soa() { "$DAG" @127.0.0.1 -p "$PS" "$1" SOA +short +nohexdump +time=1 +tries=1 2>/dev/null | awk '{print $3}'; }
i=0; while [ $i -lt 25 ] && { [ "$(soa s.test)" != 7 ] || [ "$(soa t.test)" != 9 ]; }; do sleep 1; i=$((i + 1)); done
[ "$(soa s.test)" = 7 ] && pass "D6: primaries { 127.0.0.1; } with no port: s.test was transferred from options { port } ($PP)" || fail "D6: s.test serial '$(soa s.test)' (expected 7)"
[ "$(soa t.test)" = 9 ] && pass "D7: primaries { 127.0.0.1 port $PQ; }: the element's own port wins; t.test was transferred from $PQ" || fail "D7: t.test serial '$(soa t.test)' (expected 9)"

# ---- forward zones (D9-D11): the upstreams are mock servers (tests/mock_dns_server.pl answers every name under ttl.test) on PF, PF2 and PF3.  They are
# started one after the other: a zone whose forwarder port is wrong has nothing to talk to (or talks to the wrong mock) and answers SERVFAIL.
cat > "$W/f.conf" <<EOF
zone "a.ttl.test" { type forward; forwarders { 127.0.0.1; }; forward-timeout 1500; };
zone "b.ttl.test" { type forward; forwarders port $PF2 { 127.0.0.1; }; forward-timeout 1500; };
zone "c.ttl.test" { type forward; forwarders { 127.0.0.1 port $PF3; }; forward-timeout 1500; };
options { port $PF; listen-on port $PG { 127.0.0.1; }; listen-on-v6 { none; }; pid-file "none"; $USER_OPT };
EOF
out=$("$KARICHECK" conf "$W/f.conf" 2>&1); rc=$?
[ "$rc" -eq 0 ] && pass "D12: karicheck conf accepts the forward zones (forwarders port N { ... })" || { fail "D12: karicheck conf rc=$rc"; echo "$out"; }

perl "$DIR/mock_dns_server.pl" --port "$PF" --host 127.0.0.1 > "$W/mockf1.log" 2>&1 & PIDS="$PIDS $!"
"$KARIDNS" -f "$W/f.conf" > "$W/f.log" 2>&1 & PIDS="$PIDS $!"
i=0; while [ $i -lt 30 ] && ! "$DAG" @127.0.0.1 -p "$PG" x.a.ttl.test A +nohexdump +time=1 +tries=1 2>/dev/null | grep -q "status: NOERROR"; do sleep 1; i=$((i + 1)); done
fq() { "$DAG" @127.0.0.1 -p "$PG" "$1" A +nohexdump +time=3 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }
[ "$(fq x.a.ttl.test)" = NOERROR ] && pass "D9: forwarders { 127.0.0.1; } with no port: the query went to options { port } ($PF), not to 53" || fail "D9: x.a.ttl.test got '$(fq x.a.ttl.test)'"
[ "$(fq x.b.ttl.test)" = SERVFAIL ] && [ "$(fq x.c.ttl.test)" = SERVFAIL ] && pass "D10/D11: the other two zones do not use options { port } (nothing listens on $PF2 and $PF3 yet)" || fail "D10/D11: b='$(fq x.b.ttl.test)' c='$(fq x.c.ttl.test)' before their upstreams are up (expected SERVFAIL)"
perl "$DIR/mock_dns_server.pl" --port "$PF2" --host 127.0.0.1 > "$W/mockf2.log" 2>&1 & PIDS="$PIDS $!"
sleep 1
[ "$(fq x.b.ttl.test)" = NOERROR ] && [ "$(fq x.c.ttl.test)" = SERVFAIL ] && pass "D10: forwarders port $PF2 { 127.0.0.1; }: the port of the list is the default of its elements" || fail "D10: b='$(fq x.b.ttl.test)' c='$(fq x.c.ttl.test)'"
perl "$DIR/mock_dns_server.pl" --port "$PF3" --host 127.0.0.1 > "$W/mockf3.log" 2>&1 & PIDS="$PIDS $!"
sleep 1
[ "$(fq x.c.ttl.test)" = NOERROR ] && pass "D11: forwarders { 127.0.0.1 port $PF3; }: the element's own port wins over options { port }" || fail "D11: c='$(fq x.c.ttl.test)'"

echo "---"
if [ "$FAILS" -eq 0 ]; then echo "ALL PASSED"; exit 0; fi
echo "$FAILS FAILED"
exit 1
