#!/bin/sh
# run_db_alias_lua_test.sh - PowerDNS ALIAS and LUA records (beta design 3.6b, D12, D13; milestone B9a).
#
# What it checks (the "oracle" is PowerDNS 5.1.4 with gsqlite3 when pdns_server and the sqlite3 CLI are installed; the upstream
# resolver of the ALIAS tests is tests/mock_alias_upstream.pl, so no named is needed):
#   1. default mode (no alias-resolver): the answers for A / AAAA / TXT / ANY / TYPE65401 / TYPE65402 at ALIAS names, LUA names,
#      wildcards, empty non-terminals and missing names, from a zone file, are what PowerDNS gives with expand-alias=no and
#      enable-lua-records=no; a few of them are also pinned as literals so that the test means something without PowerDNS.
#      The AXFR of the zone carries ALIAS / LUA as TYPE65401 / TYPE65402 with PowerDNS's RDATA.
#   2. expansion (alias-resolver): the same names against PowerDNS with expand-alias=yes (the TTL is not compared: KariDNS gives
#      min(ALIAS TTL, what is left of the upstream TTL) and counts down, PowerDNS the upstream TTL); the TTL rule, SERVFAIL with
#      EDE 22, NODATA, a CNAME chain, a truncated upstream answer (TCP), the bound on upstream queries, serve-stale after a success
#      and the recovery, a configuration reload that turns expansion on, a zone reload that adds a target.
#   3. zone errors (karicheck zone, and the server refuses the zone): ALIAS beside A / AAAA, ALIAS beside DNSSEC records;
#      karicheck conf: alias-resolver entries.
#   4. a secondary KariDNS gets the zone (Extended AXFR from KariDNS, a standard AXFR from PowerDNS) with ALIAS and LUA intact.
#   5. as root (the loader runs as nobody): the same zone in a SQLite3 database answers like the file zone, in both modes, and the
#      database zones that break the rules (ALIAS + A, ENABLE-LUA-RECORDS=1) are rejected.
# Parts that need a tool that is not there are SKIPped (reported).  Needs no root except part 5.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
KARIDNS=${KARIDNS:-./karidns}
DAG=${DAG:-./dag}
KARICHECK=${KARICHECK:-./karicheck}
for b in "$KARIDNS" "$DAG" "$KARICHECK"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
. "$ROOT/tests/lib_proc.sh"

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_alias.XXXXXX") || exit 1
chmod 755 "$T"
PIDS=""
cleanup() {
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done
    for p in $PIDS; do
        i=0; while [ $i -lt 100 ] && kill -0 "$p" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
        kill -KILL "$p" 2>/dev/null
    done
    for p in $PIDS; do kari_kill_tree "$p"; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0; SKIPS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
skip() { SKIPS=$((SKIPS + 1)); echo "  [SKIP] $1"; }
check() {   # check DESCRIPTION EXPECTED ACTUAL
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$3', want '$2')"; fi
}

BASE=$(kari_port 0 $((20000 + $$ % 20000)))
P_DEF=$BASE; P_EXP=$((BASE + 1)); P_UP=$((BASE + 2)); P_PDEF=$((BASE + 3)); P_PEXP=$((BASE + 4)); P_SEC=$((BASE + 5)); P_SEC2=$((BASE + 6)); P_DB=$((BASE + 7))
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT='user "nobody"; group "nobody";'

# ---------------------------------------------------------------- fixtures
# name|type|ttl|content (PowerDNS record rows); type "-" is an empty non-terminal row
cat > "$T/records.txt" <<'EOF'
alias.test|SOA|3600|ns.alias.test hostmaster.alias.test 1 3600 600 86400 300
alias.test|NS|3600|ns.alias.test
ns.alias.test|A|3600|192.0.2.53
alias.test|ALIAS|120|t.target.test.
a.alias.test|ALIAS|120|t.target.test.
both.alias.test|ALIAS|120|t.target.test.
both.alias.test|TXT|120|"hello"
v4.alias.test|ALIAS|120|v4.target.test.
v6.alias.test|ALIAS|120|v6.target.test.
cn.alias.test|ALIAS|1000|cn2.target.test.
loop.alias.test|ALIAS|120|loop1.target.test.
txtonly.alias.test|ALIAS|120|txtonly.target.test.
nx.alias.test|ALIAS|120|nosuch.target.test.
out.alias.test|ALIAS|120|out.target.test.
ttl0.alias.test|ALIAS|120|ttl0.target.test.
short.alias.test|ALIAS|20|t.target.test.
wild.alias.test|ALIAS|120|x.wild.target.test.
nozone.alias.test|ALIAS|120|t.nozone.test.
fast.alias.test|ALIAS|120|fast.target.test.
tcp.alias.test|ALIAS|120|tcp.target.test.
*.w.alias.test|ALIAS|120|t.target.test.
w.alias.test|-
l.alias.test|LUA|120|A ";return {'192.0.2.1'}"
lm.alias.test|LUA|120|A ";return {'192.0.2.1'}"
lm.alias.test|TXT|120|"x"
*.wl.alias.test|LUA|120|A ";return {'192.0.2.2'}"
wl.alias.test|-
x.y.z.alias.test|A|120|192.0.2.9
y.z.alias.test|-
z.alias.test|-
EOF
cat > "$T/upstream.data" <<'EOF'
t.target.test A 60 192.0.2.10
t.target.test A 60 192.0.2.11
t.target.test AAAA 90 2001:db8::10
v4.target.test A 200 192.0.2.20
v6.target.test AAAA 200 2001:db8::20
cn.target.test CNAME 30 t.target.test
cn2.target.test CNAME 500 cn.target.test
out.target.test CNAME 60 elsewhere.other.test
ttl0.target.test A 0 192.0.2.30
x.wild.target.test A 300 192.0.2.40
fast.target.test A 5 192.0.2.50
tcp.target.test A 60 192.0.2.61
tcp.target.test A 60 192.0.2.62
tcp.target.test A 60 192.0.2.63
trunc tcp.target.test
servfail loop1.target.test
nxdomain nosuch.target.test
refused t.nozone.test
EOF
# the zone file: PowerDNS content read relative to the root, as the database reader does
{ printf '$ORIGIN .\n'; awk -F'|' '$2 != "-" { printf "%s %s IN %s %s\n", $1, $3, $2, $4 }' "$T/records.txt"; } > "$T/alias.test.zone"
cat > "$T/tagged.zone" <<'EOF'
$ORIGIN tagged.test.
$TTL 300
@ SOA ns hostmaster 1 3600 600 86400 300
@ NS ns
ns A 192.0.2.1
$LOCATION-TAG lan 192.0.2.0/24
$LOCATION lan
a ALIAS t.target.test.
l LUA A "x"
$LOCATION none
b ALIAS u.target.test.
EOF
cat > "$T/plain.zone" <<'EOF'
$ORIGIN plain.test.
$TTL 300
@ SOA ns hostmaster 1 3600 600 86400 300
@ NS ns
ns A 192.0.2.54
EOF

conf_file() {   # conf_file FILE PORT [options statements] [zone statements]
    cat > "$1" <<EOF
options { pid-file "none"; bind-address { 127.0.0.1; }; port $2; $USER_OPT ${3:-} };
zone "alias.test." { type primary; file "$T/alias.test.zone"; allow-transfer { 127.0.0.1; }; ${4:-} };
zone "tagged.test." { type primary; file "$T/tagged.zone"; allow-transfer { 127.0.0.1; }; };
EOF
}

start_karidns() {   # start_karidns NAME CONF PORT   (sets PID_<NAME> in LAST_PID)
    "$KARIDNS" -c "$2" -f > "$T/$1.log" 2>&1 &
    LAST_PID=$!
    PIDS="$PIDS $LAST_PID"
    i=0
    while [ $i -lt 200 ]; do
        case $(q "$3" alias.test SOA) in 'NOERROR|'*) return 0 ;; esac
        kill -0 "$LAST_PID" 2>/dev/null || break
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
stop_pid() {
    kill -TERM "$1" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$1" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$1" 2>/dev/null
}

# q PORT NAME TYPE -> STATUS|sorted answer RRs without TTL, NS and SOA|1 when an SOA is in the message
q() {
    out=$($DAG @127.0.0.1 -p "$1" "$2" "$3" +nohexdump +noall +comments +answer +authority +nottlid +time=3 +tries=1 2>/dev/null)
    st=$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z0-9]*\).*/\1/p' | head -1)
    an=$(printf '%s\n' "$out" | grep -v '^;' | grep -v '^$' | grep -v 'IN[[:space:]]*NS[[:space:]]' | grep -v 'IN[[:space:]]*SOA[[:space:]]' | tr -s ' \t' ' ' | sort | tr '\n' ';')
    soa=0
    printf '%s\n' "$out" | grep -q 'IN[[:space:]]*SOA[[:space:]]' && soa=1
    echo "$st|$an|$soa"
}
# ttl PORT NAME TYPE -> the TTL of the first answer RR
ttl() {
    $DAG @127.0.0.1 -p "$1" "$2" "$3" +nohexdump +noall +answer +time=3 +tries=1 2>/dev/null | awk '!/^;/ && NF { print $2; exit }'
}
wait_not_servfail() {   # wait_not_servfail PORT NAME SECONDS
    i=0
    while [ $i -lt $(($3 * 10)) ]; do
        case $(q "$1" "$2" A) in SERVFAIL*) ;; *) return 0 ;; esac
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
wait_value() {   # wait_value PORT NAME TYPE PATTERN SECONDS
    i=0
    while [ $i -lt $(($5 * 10)) ]; do
        q "$1" "$2" "$3" | grep -q -- "$4" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

NAMES="alias.test a.alias.test both.alias.test v4.alias.test v6.alias.test cn.alias.test loop.alias.test txtonly.alias.test nx.alias.test out.alias.test ttl0.alias.test short.alias.test wild.alias.test nozone.alias.test fast.alias.test tcp.alias.test x.w.alias.test w.alias.test l.alias.test lm.alias.test x.wl.alias.test wl.alias.test x.y.z.alias.test y.z.alias.test z.alias.test nothere.alias.test"
compare_ports() {   # compare_ports LABEL PORT_KARI PORT_PDNS "TYPES" ["NAMES" [expansion]]
    bad=0; n=0
    for name in ${5:-$NAMES}; do
        for t in $4; do
            a=$(q "$2" "$name" "$t"); b=$(q "$3" "$name" "$t"); n=$((n + 1))
            if [ "${6:-}" = expansion ]; then   # RFC 2308 2.2: KariDNS puts the SOA into every NODATA, PowerDNS 5.1.4 leaves it out of the one from an expansion
                case $a in 'NOERROR||'[01]) a="NOERROR||0" ;; esac
                case $b in 'NOERROR||'[01]) b="NOERROR||0" ;; esac
            fi
            if [ "$a" != "$b" ]; then bad=$((bad + 1)); echo "         $name $t: KariDNS '$a' PowerDNS '$b'"; fi
        done
    done
    [ $bad -eq 0 ] && pass "$1: $n answers equal PowerDNS" || fail "$1: $bad of $n answers differ from PowerDNS"
}

# ---------------------------------------------------------------- PowerDNS oracle (optional)
HAVE_PDNS=0
if command -v pdns_server >/dev/null 2>&1 && command -v sqlite3 >/dev/null 2>&1; then
    SCHEMA=tests/db/pdns_schema.sqlite3.sql
    [ -f "$SCHEMA" ] || SCHEMA=/usr/local/share/doc/pdns/schema.sqlite3.sql
    if [ -f "$SCHEMA" ]; then
        mkdir "$T/pdnsdb"
        sqlite3 "$T/pdnsdb/pdns.sqlite3" < "$SCHEMA" >/dev/null 2>&1 || true
        sqlite3 "$T/pdnsdb/pdns.sqlite3" "INSERT INTO domains (name, type) VALUES ('alias.test', 'NATIVE');" 2>/dev/null
        awk -F'|' '{ c = $4; gsub(/\047/, "\047\047", c);
                     if ($2 == "-") printf "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES (1, \047%s\047, NULL, NULL, NULL, NULL, 0, 1);\n", $1;
                     else printf "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES (1, \047%s\047, \047%s\047, \047%s\047, %s, 0, 0, 1);\n", $1, $2, c, $3 }' "$T/records.txt" | sqlite3 "$T/pdnsdb/pdns.sqlite3"
        PD_OPT="setuid=$(id -u)
setgid=$(id -g)"
        if [ "$(id -u)" = "0" ]; then   # PowerDNS drops its rights: give it a user that can read the database
            PD_OPT="setuid=nobody
setgid=nobody"
            chown -R nobody "$T/pdnsdb"
        fi
        for m in def exp; do
            mkdir -p "$T/pdns-$m"
            [ "$(id -u)" = "0" ] && chown nobody "$T/pdns-$m"
            port=$P_PDEF; [ $m = exp ] && port=$P_PEXP
            cat > "$T/pdns-$m/pdns.conf" <<EOF
launch=gsqlite3
gsqlite3-database=$T/pdnsdb/pdns.sqlite3
local-address=127.0.0.1
local-port=$port
socket-dir=$T/pdns-$m
daemon=no
guardian=no
cache-ttl=0
negquery-cache-ttl=0
query-cache-ttl=0
log-dns-queries=no
disable-syslog=yes
allow-axfr-ips=127.0.0.0/8
$PD_OPT
EOF
            [ $m = exp ] && printf 'expand-alias=yes\nresolver=127.0.0.1:%s\n' "$P_UP" >> "$T/pdns-$m/pdns.conf"
            pdns_server --config-dir="$T/pdns-$m" > "$T/pdns-$m.log" 2>&1 &
            PIDS="$PIDS $!"
        done
        HAVE_PDNS=1
    fi
fi

# ================================================================ 1. default mode
echo "== 1. default mode (no alias-resolver)"
conf_file "$T/def.conf" "$P_DEF"
if start_karidns def "$T/def.conf" "$P_DEF"; then pass "karidns starts with ALIAS and LUA records in the zone"; else fail "karidns did not start"; sed 's/^/         /' "$T/def.log" | tail -5; fi
PID_DEF=$LAST_PID
H1=$(printf '%s' '017406746172676574047465737400')
check "A at an ALIAS name is NODATA" "NOERROR||1" "$(q $P_DEF a.alias.test A)"
check "AAAA at an ALIAS name is NODATA" "NOERROR||1" "$(q $P_DEF a.alias.test AAAA)"
check "TYPE65401 returns the ALIAS RR (RDATA = the target name)" "NOERROR|a.alias.test. IN TYPE65401 \\# 15 $H1;|0" "$(q $P_DEF a.alias.test TYPE65401)"
check "ANY lists the ALIAS RR" "NOERROR|a.alias.test. IN TYPE65401 \\# 15 $H1;|0" "$(q $P_DEF a.alias.test ANY)"
check "a name with LUA only: NXDOMAIN for A" "NXDOMAIN||1" "$(q $P_DEF l.alias.test A)"
check "a name with LUA only: NXDOMAIN for TYPE65402" "NXDOMAIN||1" "$(q $P_DEF l.alias.test TYPE65402)"
check "a name with LUA only: NXDOMAIN for ANY" "NXDOMAIN||1" "$(q $P_DEF l.alias.test ANY)"
check "ANY leaves the LUA RR out" 'NOERROR|lm.alias.test. IN TXT "x";|0' "$(q $P_DEF lm.alias.test ANY)"
check "TYPE65402 at a name with other records is NODATA" "NOERROR||1" "$(q $P_DEF lm.alias.test TYPE65402)"
check "a wildcard of LUA records is not there" "NXDOMAIN||1" "$(q $P_DEF x.wl.alias.test A)"
check "a wildcard ALIAS is a plain RR (TYPE65401)" "NOERROR|x.w.alias.test. IN TYPE65401 \\# 15 $H1;|0" "$(q $P_DEF x.w.alias.test TYPE65401)"
check "A below a wildcard ALIAS is NODATA" "NOERROR||1" "$(q $P_DEF x.w.alias.test A)"
check "an empty non-terminal above a LUA-only wildcard is NODATA" "NOERROR||1" "$(q $P_DEF wl.alias.test A)"
check "the ALIAS target of a transferred zone keeps its case and name" "NOERROR|both.alias.test. IN TXT \"hello\";both.alias.test. IN TYPE65401 \\# 15 $H1;|0" "$(q $P_DEF both.alias.test ANY)"

# AXFR: ALIAS / LUA as TYPE65401 / TYPE65402 with PowerDNS's RDATA
axfr() { $DAG @127.0.0.1 -p "$1" ${2:-alias.test} AXFR +nohexdump +noall +answer +nottlid +time=5 +tries=1 2>/dev/null | grep -E 'TYPE6540[12]' | tr -s ' \t' ' ' | sort; }
AX=$(axfr $P_DEF)
echo "$AX" | grep -q 'a.alias.test. IN TYPE65401 \\# 15 017406746172676574047465737400' && pass "AXFR: the ALIAS RR is TYPE65401 with the target name uncompressed" || fail "AXFR: no ALIAS RR in PowerDNS form"
echo "$AX" | grep -q 'l.alias.test. IN TYPE65402 \\# 24 0001153B72657475726E207B273139322E302E322E31277D' && pass "AXFR: the LUA RR is TYPE65402 (16-bit type + <character-string>)" || fail "AXFR: no LUA RR in PowerDNS form"
[ "$(echo "$AX" | wc -l | tr -d ' ')" = "$(grep -c -E '\|(ALIAS|LUA)\|' "$T/records.txt")" ] && pass "AXFR: every ALIAS and LUA RR is sent" || fail "AXFR: the number of ALIAS / LUA RRs is wrong"

if [ $HAVE_PDNS = 1 ]; then
    i=0; while [ $i -lt 100 ]; do q $P_PDEF alias.test SOA | grep -q '^NOERROR' && break; sleep 0.1; i=$((i + 1)); done
    if q $P_PDEF alias.test SOA | grep -q '^NOERROR'; then
        compare_ports "default mode" $P_DEF $P_PDEF "A AAAA TXT ANY TYPE65401 TYPE65402"
        APD=$(axfr $P_PDEF)
        [ -n "$APD" ] && check "AXFR of the ALIAS / LUA RRs equals PowerDNS's" "$APD" "$AX" || skip "PowerDNS did not give an AXFR"
    else
        HAVE_PDNS=0; skip "PowerDNS did not start (see $T/pdns-def.log)"; sed 's/^/         /' "$T/pdns-def.log" | tail -5
    fi
else
    skip "default mode against PowerDNS: pdns_server or the sqlite3 CLI is not installed"
fi

# ================================================================ 2. expansion
echo "== 2. expansion (alias-resolver)"
perl "$ROOT/tests/mock_alias_upstream.pl" --port "$P_UP" --data "$T/upstream.data" --down "$T/upstream.down" --log "$T/upstream.log" > "$T/upstream.out" 2>&1 &
PIDS="$PIDS $!"
sleep 0.5
conf_file "$T/exp.conf" "$P_EXP" "alias-resolver { 127.0.0.1 port $P_UP; };"
if start_karidns exp "$T/exp.conf" "$P_EXP"; then pass "karidns starts with alias-resolver"; else fail "karidns (expansion) did not start"; sed 's/^/         /' "$T/exp.log" | tail -5; fi
PID_EXP=$LAST_PID
if wait_not_servfail $P_EXP a.alias.test 15; then pass "the target of an ALIAS is resolved in the background"; else fail "a.alias.test still SERVFAIL after 15 s"; fi
sleep 1
check "A at an ALIAS name: the addresses of the target" "NOERROR|a.alias.test. IN A 192.0.2.10;a.alias.test. IN A 192.0.2.11;|0" "$(q $P_EXP a.alias.test A)"
check "AAAA" "NOERROR|a.alias.test. IN AAAA 2001:db8::10;|0" "$(q $P_EXP a.alias.test AAAA)"
check "ANY: the expanded A and AAAA only" "NOERROR|a.alias.test. IN A 192.0.2.10;a.alias.test. IN A 192.0.2.11;a.alias.test. IN AAAA 2001:db8::10;|0" "$(q $P_EXP a.alias.test ANY)"
check "TYPE65401 is NODATA now" "NOERROR||1" "$(q $P_EXP a.alias.test TYPE65401)"
check "TXT at an ALIAS name that has TXT still works" 'NOERROR|both.alias.test. IN TXT "hello";|0' "$(q $P_EXP both.alias.test TXT)"
check "a CNAME chain of the resolver is followed" "NOERROR|cn.alias.test. IN A 192.0.2.10;cn.alias.test. IN A 192.0.2.11;|0" "$(q $P_EXP cn.alias.test A)"
check "the apex can be an ALIAS" "NOERROR|alias.test. IN A 192.0.2.10;alias.test. IN A 192.0.2.11;|0" "$(q $P_EXP alias.test A)"
check "an upstream NODATA is NODATA" "NOERROR||1" "$(q $P_EXP txtonly.alias.test A)"
check "an upstream CNAME that leads nowhere is NODATA" "NOERROR||1" "$(q $P_EXP out.alias.test A)"
check "upstream NXDOMAIN: SERVFAIL" "SERVFAIL||0" "$(q $P_EXP nx.alias.test A)"
check "upstream SERVFAIL (a CNAME loop): SERVFAIL" "SERVFAIL||0" "$(q $P_EXP loop.alias.test A)"
check "upstream REFUSED: SERVFAIL" "SERVFAIL||0" "$(q $P_EXP nozone.alias.test AAAA)"
$DAG @127.0.0.1 -p $P_EXP nx.alias.test A +nohexdump 2>/dev/null | grep -q 'EDE: 22' && pass "SERVFAIL carries EDE 22 (No Reachable Authority)" || fail "no EDE 22 on the SERVFAIL"
check "a wildcard ALIAS is not expanded (as in PowerDNS)" "NOERROR||1" "$(q $P_EXP x.w.alias.test A)"
check "the LUA-only name is still NXDOMAIN" "NXDOMAIN||1" "$(q $P_EXP l.alias.test A)"
# TTL: min(ALIAS TTL, upstream TTL), counting down
T1=$(ttl $P_EXP v4.alias.test A);   [ "$T1" -le 120 ] && [ "$T1" -ge 100 ] && pass "TTL = min(ALIAS 120, upstream 200) = 120 ($T1)" || fail "TTL of v4 is '$T1'"
T2=$(ttl $P_EXP short.alias.test A); [ "$T2" -le 20 ] && [ "$T2" -ge 5 ] && pass "TTL = min(ALIAS 20, upstream 60) = 20 ($T2)" || fail "TTL of short is '$T2'"
T3=$(ttl $P_EXP a.alias.test A);    [ "$T3" -le 60 ] && [ "$T3" -ge 30 ] && pass "TTL = min(ALIAS 120, upstream 60) <= 60 ($T3)" || fail "TTL of a is '$T3'"
T4=$(ttl $P_EXP ttl0.alias.test A); [ "$T4" = "0" ] && pass "an upstream TTL of 0 gives TTL 0" || fail "TTL of ttl0 is '$T4'"
sleep 3
T5=$(ttl $P_EXP a.alias.test A); [ -n "$T5" ] && [ "$T5" -lt "$T3" ] && pass "the TTL counts down ($T3 -> $T5)" || fail "the TTL did not count down ($T3 -> '$T5')"
# truncated upstream answer: TCP
if wait_value $P_EXP tcp.alias.test A "192.0.2.61" 10; then
    check "a truncated upstream answer is read over TCP" "NOERROR|tcp.alias.test. IN A 192.0.2.61;tcp.alias.test. IN A 192.0.2.62;tcp.alias.test. IN A 192.0.2.63;|0" "$(q $P_EXP tcp.alias.test A)"
    grep -q '^tcp.target.test 1 udp' "$T/upstream.log" && grep -q '^tcp.target.test 1 tcp' "$T/upstream.log" && pass "the upstream saw the UDP query and the TCP retry" || fail "no UDP + TCP pair for tcp.target.test in the upstream log"
else
    fail "tcp.alias.test was not resolved over TCP"
fi
# the number of upstream queries does not follow the number of client queries
BEFORE=$(grep -c '^t.target.test 1 ' "$T/upstream.log")
i=0; while [ $i -lt 100 ]; do q $P_EXP a.alias.test A > /dev/null; i=$((i + 1)); done
AFTER=$(grep -c '^t.target.test 1 ' "$T/upstream.log")
[ $((AFTER - BEFORE)) -le 2 ] && pass "100 client queries caused $((AFTER - BEFORE)) upstream queries" || fail "100 client queries caused $((AFTER - BEFORE)) upstream queries"

if [ $HAVE_PDNS = 1 ]; then
    i=0; while [ $i -lt 100 ]; do q $P_PEXP alias.test SOA | grep -q '^NOERROR' && break; sleep 0.1; i=$((i + 1)); done
    compare_ports "expansion" $P_EXP $P_PEXP "A AAAA TXT ANY TYPE65401" "$(echo $NAMES | sed 's/tcp.alias.test //')" expansion
else
    skip "expansion against PowerDNS: not available"
fi

# serve-stale after a success, and the recovery
echo "== 2b. failure handling"
wait_value $P_EXP fast.alias.test A "192.0.2.50" 10 && pass "fast.alias.test resolved (upstream TTL 5)" || fail "fast.alias.test not resolved"
: > "$T/upstream.down"
sleep 8
TS=$(ttl $P_EXP fast.alias.test A)
[ "$TS" = "30" ] && pass "after the TTL ran out and the refreshes failed: the last result with TTL 30" || fail "stale TTL is '$TS' (want 30)"
check "the stale result is the last one" "NOERROR|fast.alias.test. IN A 192.0.2.50;|0" "$(q $P_EXP fast.alias.test A)"
grep -v '^fast.target.test A ' "$T/upstream.data" > "$T/ud.new"; echo 'fast.target.test A 5 192.0.2.51' >> "$T/ud.new"; mv "$T/ud.new" "$T/upstream.data"
rm -f "$T/upstream.down"
if wait_value $P_EXP fast.alias.test A "192.0.2.51" 25; then pass "the upstream is back: the refreshed data is served"; else fail "the new address did not appear within 25 s"; fi
TF=$(ttl $P_EXP fast.alias.test A); [ -n "$TF" ] && [ "$TF" -le 5 ] && pass "fresh again (TTL $TF)" || fail "TTL after recovery '$TF'"
# a result that was never obtained: a new target with the upstream down
: > "$T/upstream.down"
cp "$T/alias.test.zone" "$T/alias.test.zone.keep"
printf 'late.alias.test 120 IN ALIAS fast.target.test.\nlate2.alias.test 120 IN ALIAS never.target.test.\n' >> "$T/alias.test.zone"
kill -HUP "$PID_EXP"
sleep 2
check "a target never resolved while the upstream is down: SERVFAIL" "SERVFAIL||0" "$(q $P_EXP late2.alias.test A)"
check "a target another name resolved before is served (same target, same upstream)" "NOERROR|late.alias.test. IN A 192.0.2.51;|0" "$(q $P_EXP late.alias.test A)"
rm -f "$T/upstream.down"
printf 'never.target.test A 60 192.0.2.99\n' >> "$T/upstream.data"
wait_value $P_EXP late2.alias.test A "192.0.2.99" 20 && pass "a new ALIAS target added by a zone reload is resolved" || fail "late2.alias.test not resolved after the reload"
cp "$T/alias.test.zone.keep" "$T/alias.test.zone"
kill -HUP "$PID_EXP"

# a configuration reload turns expansion on
conf_file "$T/def.conf" "$P_DEF" "alias-resolver { 127.0.0.1 port $P_UP; };"
kill -HUP "$PID_DEF"
if wait_value $P_DEF a.alias.test A "192.0.2.10" 20; then pass "a configuration reload with alias-resolver turns expansion on"; else fail "no expansion after the reload"; fi
conf_file "$T/def.conf" "$P_DEF"
kill -HUP "$PID_DEF"
i=0; while [ $i -lt 100 ]; do [ "$(q $P_DEF a.alias.test A)" = "NOERROR||1" ] && break; sleep 0.1; i=$((i + 1)); done
check "removing alias-resolver goes back to PowerDNS's default" "NOERROR||1" "$(q $P_DEF a.alias.test A)"

# ================================================================ 3. zone errors
echo "== 3. zone errors"
mk() { printf '$ORIGIN bad.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n%s\n' "$2" > "$T/$1.zone"; }
mk both 'a ALIAS t.example.
a A 192.0.2.5'
mk aaaa 'a ALIAS t.example.
A AAAA 2001:db8::1'
mk signed 'a ALIAS t.example.
@ DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=='
mk badrdata 'a TYPE65401 \# 3 010161'
mk fine 'a ALIAS t.example.
a TXT "x"
l LUA A "code"'
for z in both aaaa signed badrdata; do
    out=$($KARICHECK zone bad.test "$T/$z.zone" 2>&1); rc=$?
    if [ $rc -ne 0 ]; then pass "karicheck zone refuses $z"; else fail "karicheck zone accepts $z"; fi
done
$KARICHECK zone bad.test "$T/both.zone" 2>&1 | grep -q 'an A or AAAA record' && pass "karicheck names the reason (ALIAS beside A)" || fail "karicheck: no reason for ALIAS beside A"
$KARICHECK zone bad.test "$T/signed.zone" 2>&1 | grep -q 'DNSSEC' && pass "karicheck names the reason (ALIAS in a signed zone)" || fail "karicheck: no reason for ALIAS + DNSSEC"
out=$($KARICHECK zone bad.test "$T/fine.zone" 2>&1); rc=$?
[ $rc -eq 0 ] && pass "karicheck zone accepts ALIAS + TXT and LUA" || fail "karicheck zone refuses a fine zone: $out"
echo "$out" | grep -q 'LUA record(s) are kept for zone transfers and never answered' && pass "karicheck warns that LUA records are not run" || fail "karicheck: no LUA warning"
echo "$out" | grep -q '1 ALIAS record(s)' && pass "karicheck reports the ALIAS records" || fail "karicheck: no ALIAS info line"
printf 'options { alias-resolver { ns.example.test; }; };\n' > "$T/badres.conf"
$KARICHECK conf "$T/badres.conf" > "$T/badres.out" 2>&1 && fail "karicheck conf accepts a host name in alias-resolver" || pass "karicheck conf refuses a host name in alias-resolver"
printf 'options { alias-resolver { 192.0.2.53; 2001:db8::53 port 5353; }; };\nzone "z.test." { type primary; file "%s"; alias-resolver { 192.0.2.54; }; };\n' "$T/plain.zone" > "$T/goodres.conf"
$KARICHECK conf "$T/goodres.conf" > "$T/goodres.out" 2>&1 && pass "karicheck conf accepts alias-resolver in options and in a zone" || { fail "karicheck conf refuses a good alias-resolver"; sed 's/^/         /' "$T/goodres.out" | tail -3; }
if [ -x ./tests/db/zone2sql ]; then
    n=$(./tests/db/zone2sql --dialect sqlite3 "$T/alias.test.zone" 2>/dev/null | grep -c "'ALIAS'\|'LUA'")
    check "zone2sql writes the ALIAS and LUA RRs as PowerDNS rows (type ALIAS / LUA)" "$(grep -c -E '\|(ALIAS|LUA)\|' "$T/records.txt")" "$n"
fi
# the server does not load such a zone
printf 'options { pid-file "none"; bind-address { 127.0.0.1; }; port %s; %s };\nzone "plain.test." { type primary; file "%s"; };\nzone "bad.test." { type primary; file "%s"; };\n' "$P_SEC2" "$USER_OPT" "$T/plain.zone" "$T/both.zone" > "$T/bad.conf"
"$KARIDNS" -c "$T/bad.conf" -f > "$T/bad.log" 2>&1 &
BADPID=$!; PIDS="$PIDS $BADPID"
i=0; while [ $i -lt 100 ]; do case $(q "$P_SEC2" plain.test SOA) in 'NOERROR|'*) break ;; esac; sleep 0.1; i=$((i + 1)); done
S=$($DAG @127.0.0.1 -p "$P_SEC2" ns.plain.test A +noall +comments +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
check "the server serves the good zone ..." "NOERROR" "$S"
S=$($DAG @127.0.0.1 -p "$P_SEC2" a.bad.test A +noall +comments +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
[ "$S" = "REFUSED" ] || [ "$S" = "SERVFAIL" ] && pass "... and not the zone with an ALIAS beside an A record ($S)" || fail "bad.test is served ($S)"
stop_pid "$BADPID"

# ================================================================ 4. secondary
echo "== 4. a secondary gets the zone"
cat > "$T/sec.conf" <<EOF
options { pid-file "none"; bind-address { 127.0.0.1; }; port $P_SEC; $USER_OPT };
zone "alias.test." { type secondary; masters { 127.0.0.1 port $P_DEF; }; allow-transfer { 127.0.0.1; }; };
zone "tagged.test." { type secondary; masters { 127.0.0.1 port $P_DEF; }; allow-transfer { 127.0.0.1; }; };
EOF
"$KARIDNS" -c "$T/sec.conf" -f > "$T/sec.log" 2>&1 &
SECPID=$!; PIDS="$PIDS $SECPID"
if wait_value $P_SEC a.alias.test TYPE65401 "TYPE65401" 30; then
    pass "the secondary has the zone (Extended AXFR from KariDNS)"
    check "ALIAS and LUA RRs equal the primary's" "$AX" "$(axfr $P_SEC)"
    i=0; while [ $i -lt 200 ] && [ -z "$(axfr $P_SEC tagged.test)" ]; do sleep 0.1; i=$((i + 1)); done
    TAX=$(axfr $P_DEF tagged.test)
    if [ -z "$TAX" ]; then
        fail "no AXFR of tagged.test from the primary"
    else
        check "tagged zone: the secondary equals the primary (state records of CLASS 65302 beside ALIAS / LUA RRs of CLASS IN with the same type numbers)" "$TAX" "$(axfr $P_SEC tagged.test)"
    fi
    check "LUA only: NXDOMAIN on the secondary" "NXDOMAIN||1" "$(q $P_SEC l.alias.test A)"
    check "A at an ALIAS name: NODATA on the secondary" "NOERROR||1" "$(q $P_SEC a.alias.test A)"
else
    fail "the secondary did not get the zone"; sed 's/^/         /' "$T/sec.log" | tail -5
fi
stop_pid "$SECPID"
if [ $HAVE_PDNS = 1 ]; then
    cat > "$T/sec2.conf" <<EOF
options { pid-file "none"; bind-address { 127.0.0.1; }; port $P_SEC2; $USER_OPT };
zone "alias.test." { type secondary; masters { 127.0.0.1 port $P_PDEF; }; allow-transfer { 127.0.0.1; }; };
EOF
    "$KARIDNS" -c "$T/sec2.conf" -f > "$T/sec2.log" 2>&1 &
    SEC2PID=$!; PIDS="$PIDS $SEC2PID"
    if wait_value $P_SEC2 a.alias.test TYPE65401 "TYPE65401" 30; then
        pass "the secondary has the zone (standard AXFR from PowerDNS)"
        check "ALIAS and LUA RRs equal PowerDNS's" "$(axfr $P_PDEF)" "$(axfr $P_SEC2)"
    else
        fail "the secondary did not get the zone from PowerDNS"; sed 's/^/         /' "$T/sec2.log" | tail -5
    fi
    stop_pid "$SEC2PID"
else
    skip "standard AXFR from PowerDNS: not available"
fi

# ================================================================ 5. database zones
echo "== 5. database zones (root)"
if [ "$(id -u)" != "0" ]; then
    skip "needs root (the loader runs as nobody)"
elif [ ! -x ./karidns-dbloader ] || ! command -v sqlite3 >/dev/null 2>&1 || ! ./karidns-dbloader --drivers | grep -qx sqlite3 || ! id nobody >/dev/null 2>&1; then
    skip "karidns-dbloader with the SQLite3 driver, the sqlite3 CLI or the user nobody is missing"
else
    mkdir "$T/db"
    sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    sqlite3 "$T/db/z.db" "INSERT INTO domains (name, type) VALUES ('alias.test', 'NATIVE');"
    awk -F'|' '{ c = $4; gsub(/\047/, "\047\047", c);
                 if ($2 == "-") printf "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES (1, \047%s\047, NULL, NULL, NULL, NULL, 0, 1);\n", $1;
                 else printf "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES (1, \047%s\047, \047%s\047, \047%s\047, %s, 0, 0, 1);\n", $1, $2, c, $3 }' "$T/records.txt" | sqlite3 "$T/db/z.db"
    # zones that break the rules
    sqlite3 "$T/db/z.db" "INSERT INTO domains (name, type) VALUES ('conflict.test', 'NATIVE'); INSERT INTO domains (name, type) VALUES ('lua.test', 'NATIVE'); INSERT INTO domains (name, type) VALUES ('presigned.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth) VALUES
 (2, 'conflict.test', 'SOA', 'ns.conflict.test hm.conflict.test 1 3600 600 86400 300', 300, 0, 0, 1), (2, 'conflict.test', 'NS', 'ns.conflict.test', 300, 0, 0, 1), (2, 'ns.conflict.test', 'A', '192.0.2.1', 300, 0, 0, 1),
 (2, 'a.conflict.test', 'ALIAS', 't.target.test.', 300, 0, 0, 1), (2, 'a.conflict.test', 'A', '192.0.2.5', 300, 0, 0, 1),
 (3, 'lua.test', 'SOA', 'ns.lua.test hm.lua.test 1 3600 600 86400 300', 300, 0, 0, 1), (3, 'lua.test', 'NS', 'ns.lua.test', 300, 0, 0, 1), (3, 'ns.lua.test', 'A', '192.0.2.1', 300, 0, 0, 1),
 (3, 'x.lua.test', 'LUA', 'A \";return {''192.0.2.1''}\"', 300, 0, 0, 1),
 (4, 'presigned.test', 'SOA', 'ns.presigned.test hm.presigned.test 1 3600 600 86400 300', 300, 0, 0, 1), (4, 'presigned.test', 'NS', 'ns.presigned.test', 300, 0, 0, 1), (4, 'ns.presigned.test', 'A', '192.0.2.1', 300, 0, 0, 1),
 (4, 'a.presigned.test', 'ALIAS', 't.target.test.', 300, 0, 0, 1);
INSERT INTO domainmetadata (domain_id, kind, content) VALUES (3, 'ENABLE-LUA-RECORDS', '1'), (4, 'PRESIGNED', '1'), (1, 'ALLOW-AXFR-FROM', '127.0.0.1');"
    chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
    install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    dbconf() {   # dbconf [alias-resolver statement]
        cat > "$T/db.conf" <<EOF
options { user "nobody"; pid-file "none"; bind-address { 127.0.0.1; }; port $P_DB; ${1:-}
  database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; acl-ceiling { 127.0.0.1; }; };
};
EOF
    }
    dbconf
    "$KARIDNS" -c "$T/db.conf" -f > "$T/db.log" 2>&1 &
    DBPID=$!; PIDS="$PIDS $DBPID"
    i=0; while [ $i -lt 300 ]; do grep -q "initial load complete" "$T/db.log" 2>/dev/null && break; sleep 0.1; i=$((i + 1)); done
    grep -q "initial load complete" "$T/db.log" && pass "the database zones are loaded" || { fail "no initial load"; sed 's/^/         /' "$T/db.log" | tail -8; }
    grep -q "ENABLE-LUA-RECORDS" "$T/db.log" && pass "ENABLE-LUA-RECORDS=1 rejects the zone (reason logged)" || fail "no ENABLE-LUA-RECORDS rejection in the log"
    grep -q "an A or AAAA record" "$T/db.log" && pass "ALIAS beside A rejects the zone (reason logged)" || fail "no ALIAS + A rejection in the log"
    grep -q "PRESIGNED and has an ALIAS" "$T/db.log" && pass "ALIAS in a PRESIGNED zone rejects the zone (reason logged)" || fail "no PRESIGNED + ALIAS rejection in the log"
    check "a.conflict.test is not served" "REFUSED" "$($DAG @127.0.0.1 -p $P_DB a.conflict.test A +noall +comments +nohexdump 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
    # default mode: the database zone answers like the file zone
    bad=0; n=0
    for name in $NAMES; do for t in A AAAA TXT ANY TYPE65401 TYPE65402; do
        a=$(q $P_DEF "$name" "$t"); b=$(q $P_DB "$name" "$t"); n=$((n + 1))
        [ "$a" = "$b" ] || { bad=$((bad + 1)); echo "         $name $t: file '$a' database '$b'"; }
    done; done
    [ $bad -eq 0 ] && pass "database zone = file zone in default mode ($n answers)" || fail "database zone differs from the file zone in default mode ($bad of $n)"
    DBAX=$(axfr $P_DB)
    check "AXFR of the database zone = the file zone" "$AX" "$DBAX"
    # expansion on: reload with options { alias-resolver }
    dbconf "alias-resolver { 127.0.0.1 port $P_UP; };"
    kill -HUP "$DBPID"
    if wait_value $P_DB a.alias.test A "192.0.2.10" 30; then
        pass "a configuration reload turns expansion on for database zones"
        sleep 1
        bad=0; n=0
        for name in $NAMES; do for t in A AAAA ANY TYPE65401; do
            a=$(q $P_EXP "$name" "$t"); b=$(q $P_DB "$name" "$t"); n=$((n + 1))
            [ "$a" = "$b" ] || { bad=$((bad + 1)); echo "         $name $t: file '$a' database '$b'"; }
        done; done
        [ $bad -eq 0 ] && pass "database zone = file zone with expansion ($n answers)" || fail "database zone differs from the file zone with expansion ($bad of $n)"
    else
        fail "no expansion of database zones after the reload"
    fi
    stop_pid "$DBPID"
fi

# a sanitizer build (KARIDNS=./karidns-tsan or -asan) reports in the log of the server
for f in "$T"/*.log; do
    [ -f "$f" ] || continue
    if grep -q "WARNING: ThreadSanitizer\|ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|runtime error:" "$f" 2>/dev/null; then
        fail "a sanitizer reported in $(basename "$f")"
        grep -m1 -A12 "WARNING: ThreadSanitizer\|ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|runtime error:" "$f" | sed 's/^/         /'
    fi
done

echo
echo "PASS=$PASS FAIL=$FAILS SKIP=$SKIPS"
[ "$FAILS" -eq 0 ]
