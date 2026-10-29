#!/bin/sh
# run_bind_option_values_test.sh - option values of the BIND 9.20 configuration compatibility, batch 7 (BIND 9.20.4 bin/named/server.c,
# builtin.c, zoneconf.c, lib/isccfg/namedconf.c, lib/ns/query.c, lib/ns/update.c; tests/test_config_directives.c checks the parsing,
# tests/test_query_engine_expanded.c and tests/test_dynamic_update_engine.c the engine):
#   karicheck conf (no server):
#     - tcp-idle-timeout / tcp-initial-timeout: a bare number is in units of 100 ms, `10000ms` keeps the old meaning, a bare number above
#       1200 is an error with file:line that names the suffix
#     - masterfile-format raw is an error; max-records / max-records-per-type / max-types-per-name / max-zone-ttl refuse a zone
#     - check-mx-cname, check-srv-cname, check-wildcard, check-dup-records, check-mx, check-names, check-integrity set the severity of a
#       finding (fail = error, warn = warning, ignore = nothing); a zone-level value beats options
#   a running server (normal user, 127.0.0.1):
#     - version.bind, hostname.bind, id.server over UDP and TCP (CH TXT), none, name below the zone, SOA / NS
#     - minimal-responses no-auth and no-auth-recursive (the RD bit of the query decides)
#     - dynamic update: max-zone-ttl lowers the TTL, serial-update-method unixtime, max-records refuses the update with SERVFAIL
#     - a zone that breaks max-records is not loaded
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICHECK" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karicheck dag >/dev/null || exit 1

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-optval.XXXXXX")"
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
P1=$(kari_port 1 15901)
P2=$(kari_port 2 15902)
P3=$(kari_port 3 15903)
P4=$(kari_port 4 15904)
KEYSECRET="C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="
PIDS=""
FAILS=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    if [ "$FAILS" -ne 0 ]; then
        for l in s1 s2 s3 s4 s5; do echo "--- $l.log (tail)"; tail -12 "$W/$l.log" 2>/dev/null; done
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P1 $P2 $P3 $P4; do
    if sockstat -46 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

# ------------------------------------------------------------------------------------------------ karicheck conf
# expect_check LABEL EXPECTED_EXIT CONF PATTERN...: karicheck conf CONF exits EXPECTED_EXIT and every PATTERN (grep -E) is in its output
expect_check() {
    _l=$1; _x=$2; _c=$3; shift 3
    "$KARICHECK" ${KC_CMD:-conf} "$_c" > "$W/check.out" 2>&1
    _rc=$?
    if [ "$_rc" -ne "$_x" ]; then fail "$_l: exit $_rc, expected $_x: $(head -5 "$W/check.out")"; return; fi
    for _p in "$@"; do
        if ! grep -Eq -- "$_p" "$W/check.out"; then fail "$_l: no line matches '$_p': $(head -8 "$W/check.out")"; return; fi
    done
    pass "$_l"
}
# expect_absent LABEL PATTERN: the last karicheck output has no line that matches
expect_zones() { KC_CMD=zones expect_check "$@"; }
expect_absent() {
    if grep -Eq -- "$2" "$W/check.out"; then fail "$1: unexpected '$2': $(head -8 "$W/check.out")"; else pass "$1"; fi
}

printf '$TTL 300\n$ORIGIN ex.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.80\n' > "$W/ex.test.zone"
cat > "$W/e.conf" <<EOF
options { directory "$W"; tcp-idle-timeout 10000; };
zone "ex.test" { type master; file "$W/ex.test.zone"; };
EOF
expect_check "tcp-idle-timeout 10000 is an error that names the suffix" 1 "$W/e.conf" "\[ERROR\] .*e\.conf:1: options tcp-idle-timeout: 10000 is more than the maximum of 1200 .*write 10000ms"
sed 's/tcp-idle-timeout 10000;/tcp-idle-timeout 10000ms; tcp-initial-timeout 100;/' "$W/e.conf" > "$W/e2.conf"
expect_check "tcp-idle-timeout 10000ms and tcp-initial-timeout 100 (10 s) are accepted" 0 "$W/e2.conf" "\[OK\] Config file"
sed 's/tcp-idle-timeout 10000;/tcp-initial-timeout 10;/' "$W/e.conf" > "$W/e3.conf"
expect_check "tcp-initial-timeout 10 is raised to 25 (2.5 s) with a warning, as BIND does" 0 "$W/e3.conf" "\[WARNING\] .*options tcp-initial-timeout: value is out of range: raising to 25"
sed 's/tcp-idle-timeout 10000;/masterfile-format raw;/' "$W/e.conf" > "$W/e4.conf"
expect_check "masterfile-format raw is an error" 1 "$W/e4.conf" "\[ERROR\] .*options: masterfile-format raw is not supported"
sed 's/tcp-idle-timeout 10000;/masterfile-format text; serial-update-method unixtime; tcp-advertised-timeout 300; tcp-keepalive-timeout 300;/' "$W/e.conf" > "$W/e5.conf"
expect_check "masterfile-format text, serial-update-method, tcp-advertised-timeout and tcp-keepalive-timeout are read" 0 "$W/e5.conf" "tcp-keepalive-timeout: accepted, no effect"
# size limits: the zone has 4 records, www has 1 A
sed 's/tcp-idle-timeout 10000;/max-records 3;/' "$W/e.conf" > "$W/l1.conf"
expect_zones "max-records 3: a zone of 4 records is refused" 1 "$W/l1.conf" "\[ERROR\] Zone 'ex\.test\.': the zone has 4 records, more than max-records 3"
sed 's/tcp-idle-timeout 10000;/max-records 4; max-records-per-type 1; max-types-per-name 2; max-zone-ttl 300;/' "$W/e.conf" > "$W/l2.conf"
expect_zones "the limits as large as the zone: accepted" 0 "$W/l2.conf" "\[OK\] Zone .* is valid\."
sed 's/tcp-idle-timeout 10000;/max-zone-ttl 299;/' "$W/e.conf" > "$W/l3.conf"
expect_zones "max-zone-ttl 299: TTL 300 is refused" 1 "$W/l3.conf" "TTL 300, which exceeds the configured max-zone-ttl 299"
sed 's/tcp-idle-timeout 10000;/max-zone-ttl 299;/; s/type master;/type master; max-zone-ttl 1h;/' "$W/e.conf" > "$W/l4.conf"
expect_zones "a zone's max-zone-ttl replaces options'" 0 "$W/l4.conf" "\[OK\] Zone .* is valid\."
printf '$TTL 300\n$ORIGIN ex.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nm IN A 192.0.2.80\nm IN A 192.0.2.81\nm IN TXT "x"\n' > "$W/many.zone"
sed 's/tcp-idle-timeout 10000;/max-records-per-type 1;/; s#ex.test.zone#many.zone#' "$W/e.conf" > "$W/l5.conf"
expect_zones "max-records-per-type 1: two A records at one name are refused" 1 "$W/l5.conf" "'m.ex.test.' has 2 records of type 1, more than max-records-per-type 1"
sed 's/tcp-idle-timeout 10000;/max-types-per-name 1;/; s#ex.test.zone#many.zone#' "$W/e.conf" > "$W/l6.conf"
expect_zones "max-types-per-name 1: a name with two types is refused" 1 "$W/l6.conf" "'ex.test.' has 2 record types, more than max-types-per-name 1"

# check-*: one zone with an MX and an SRV whose targets are aliases, an MX to an address, a duplicate RR, a wildcard that is not the leftmost
# label and a name that is not a host name
cat > "$W/chk.zone" <<'EOF'
$TTL 300
$ORIGIN ck.test.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
alias IN CNAME ns1
@ IN MX 10 alias
@ IN MX 20 192.0.2.9.
_sip._tcp IN SRV 0 0 5060 alias
dup IN A 192.0.2.50
dup IN A 192.0.2.50
a.*.wild IN A 192.0.2.60
bad_name IN A 192.0.2.70
EOF
mkconf() { # mkconf FILE OPTIONS [ZONE_STATEMENTS]
    _zs=${3:-}
    cat > "$1" <<EOF
options { directory "$W"; $2 };
zone "ck.test" { type master; file "$W/chk.zone"; $_zs };
EOF
}
result_line() { grep -E "^\[RESULT\] Zone 'ck\.test\.'" "$W/check.out" | head -1; }
mkconf "$W/c0.conf" ""
expect_zones "no check-*: the findings KariDNS always reported (MX alias is an error, SRV alias a warning)" 1 "$W/c0.conf" \
    "\[ERROR\] MX record 'ck\.test\.' points to CNAME target 'alias\.ck\.test\.'" "\[WARNING\] SRV record '_sip\._tcp\.ck\.test\.' points to CNAME target"
expect_absent "no check-*: no wildcard, duplicate, MX address or host name finding" "check-wildcard|check-dup-records|check-mx\)|check-names"
mkconf "$W/c1.conf" "check-mx-cname warn; check-srv-cname ignore; check-dup-records warn; check-wildcard yes; check-mx warn; check-names primary warn;"
expect_zones "check-* warn: every finding is a warning" 0 "$W/c1.conf" \
    "\[WARNING\] MX record 'ck\.test\.' points to CNAME target" "\[WARNING\] ownername 'a\.\*\.wild\.ck\.test\.' contains a non-terminal wildcard \(check-wildcard\)" \
    "\[WARNING\] 'dup\.ck\.test\.' A has duplicate rdata \(check-dup-records\)" "\[WARNING\] MX record 'ck\.test\.' has the IP address '192\.0\.2\.9' as its target \(check-mx\)" \
    "\[WARNING\] A record owner 'bad_name\.ck\.test\.' is not a valid host name \(check-names\)"
expect_absent "check-srv-cname ignore: the SRV finding is gone" "SRV record"
mkconf "$W/c2.conf" "check-mx-cname ignore; check-srv-cname fail; check-names primary ignore; check-dup-records fail;"
expect_zones "check-srv-cname fail and check-dup-records fail are errors, check-mx-cname ignore is silent" 1 "$W/c2.conf" \
    "\[ERROR\] SRV record '_sip\._tcp\.ck\.test\.' points to CNAME target" "\[ERROR\] 'dup\.ck\.test\.' A has duplicate rdata"
expect_absent "check-mx-cname ignore and check-names ignore" "MX record 'ck\.test\.' points to CNAME|not a valid host name"
mkconf "$W/c3.conf" "check-mx-cname fail; check-names primary fail;" "check-names ignore; check-mx-cname warn;"
expect_zones "the zone's values beat options" 0 "$W/c3.conf" "\[WARNING\] MX record 'ck\.test\.' points to CNAME target"
expect_absent "zone check-names ignore" "not a valid host name"
cat > "$W/c4.conf" <<EOF
options { directory "$W"; check-names primary fail; };
view v { match-clients { any; }; check-names primary ignore;
  zone "ck.test" { type master; file "$W/chk.zone"; }; };
EOF
expect_zones "a view's check-names replaces options'" 1 "$W/c4.conf" "points to CNAME target"
expect_absent "view check-names ignore" "not a valid host name"
printf '$TTL 300\n$ORIGIN ig.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1.ig.test.\n@ IN MX 10 mail.ig.test.\n@ IN MX 20 mail2\n' > "$W/ig.zone"
cat > "$W/c5.conf" <<EOF
options { directory "$W"; };
zone "ig.test" { type master; file "$W/ig.zone"; };
EOF
expect_zones "an NS with no glue is an error by default" 1 "$W/c5.conf" "In-bailiwick NS target 'ns1\.ig\.test\.' lacks A/AAAA glue"
sed 's/options { directory "\(.*\)"; };/options { directory "\1"; check-integrity no; };/' "$W/c5.conf" > "$W/c6.conf"
expect_zones "check-integrity no: the missing glue and MX addresses are not looked for" 0 "$W/c6.conf" "\[OK\] Zone .* is valid\."
mkconf "$W/c7.conf" "check-sibling no; check-svcb no; check-spf ignore;"
expect_check "check-sibling, check-svcb and check-spf: read, with a note that they have no effect" 0 "$W/c7.conf" \
    "check-sibling is accepted, no effect in KariDNS" "check-svcb is accepted" "check-spf is accepted"
mkconf "$W/c8.conf" "check-mx maybe;"
expect_check "an unknown check mode is an error with file:line" 1 "$W/c8.conf" "\[ERROR\] .*c8\.conf:1: options: check-mx: invalid value 'maybe'"

# ------------------------------------------------------------------------------------------------ the server
printf '$TTL 300\n$ORIGIN ex.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\n@ IN MX 10 mail\nns1 IN A 192.0.2.1\nmail IN A 192.0.2.25\nwww IN A 192.0.2.80\n' > "$W/s.zone"
sed 's/^[$]TTL 300/$TTL 100/' "$W/s.zone" > "$W/s1.zone"

start() { # start NAME: runs $W/NAME.conf
    "$KARIDNS" -f -c "$W/$1.conf" > "$W/$1.log" 2>&1 &
    PIDS="$PIDS $!"
}
wait_up() { # wait_up PORT
    _i=0
    while [ $_i -lt 100 ]; do
        "$DAG" @127.0.0.1 -p "$1" ex.test SOA +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1 && return 0
        sleep 0.2
        _i=$((_i + 1))
    done
    return 1
}
d() { # d PORT args...: dag against the server
    _p=$1; shift
    "$DAG" @127.0.0.1 -p "$_p" "$@" +nohexdump +time=2 +tries=1 2>&1
}

# server 1: CHAOS texts, the zone limits and serial-update-method, dynamic update with a key
cat > "$W/s1.conf" <<EOF
options { port $P1; pid-file "none"; bind-address { 127.0.0.1; }; $USER_OPT
  version "9.99-test"; hostname "ns1.example.test"; server-id "node-7";
  max-zone-ttl 200; max-records 8; serial-update-method unixtime; };
key "upd" { algorithm hmac-sha256; secret "$KEYSECRET"; };
zone "ex.test" { type master; file "$W/s1.zone"; allow-update { key upd; }; };
EOF
start s1
if ! wait_up $P1; then fail "server 1 did not start"; tail -20 "$W/s1.log"; exit 1; fi
for tr in "" "+tcp"; do
    [ -n "$tr" ] && via="tcp" || via="udp"
    [ "$(d $P1 version.bind TXT -c CH +short $tr)" = '"9.99-test"' ] && pass "version.bind CH TXT ($via)" || fail "version.bind ($via): $(d $P1 version.bind TXT -c CH +short $tr)"
    [ "$(d $P1 hostname.bind TXT -c CH +short $tr)" = '"ns1.example.test"' ] && pass "hostname.bind CH TXT ($via)" || fail "hostname.bind ($via)"
    [ "$(d $P1 id.server TXT -c CH +short $tr)" = '"node-7"' ] && pass "id.server CH TXT ($via)" || fail "id.server ($via)"
done
d $P1 version.bind TXT -c CH > "$W/ch.out"
grep -q "flags: qr aa" "$W/ch.out" && grep -q "status: NOERROR" "$W/ch.out" && grep -Eq "^version\.bind\.[[:space:]]+0[[:space:]]+CH[[:space:]]+TXT" "$W/ch.out" \
    && pass "the TXT is class CH, TTL 0, authoritative" || fail "version.bind full answer: $(cat "$W/ch.out")"
d $P1 version.bind SOA -c CH +noall +answer > "$W/ch.out"
grep -Eq "^version\.bind\.[[:space:]]+86400[[:space:]]+CH[[:space:]]+SOA[[:space:]]+version\.bind\. hostmaster\.version\.bind\. 0 28800 7200 604800 86400" "$W/ch.out" \
    && pass "version.bind SOA as BIND builds it" || fail "version.bind SOA: $(cat "$W/ch.out")"
d $P1 id.server NS -c CH +noall +answer | grep -Eq "^id\.server\.[[:space:]]+0[[:space:]]+CH[[:space:]]+NS[[:space:]]+id\.server\." && pass "id.server NS" || fail "id.server NS"
d $P1 x.version.bind TXT -c CH | grep -q "status: NXDOMAIN" && pass "a name below version.bind is NXDOMAIN" || fail "x.version.bind"
out=$(d $P1 version.bind A -c CH); echo "$out" | grep -q "status: NOERROR" && echo "$out" | grep -q "ANSWER: 0, AUTHORITY: 1" && pass "version.bind A is NODATA with the SOA" || fail "version.bind A: $out"
d $P1 authors.bind TXT -c CH | grep -q "status: REFUSED" && pass "authors.bind is not served (REFUSED)" || fail "authors.bind"
d $P1 version.bind TXT +short | grep -q . && fail "version.bind in class IN answered" || pass "version.bind in class IN is not served"

# dynamic update: max-zone-ttl lowers the TTL, serial-update-method unixtime, max-records refuses
YKEY="hmac-sha256:upd:$KEYSECRET"
before=$(date +%s)
d $P1 ex.test A --update-add 'n1.ex.test 300 A 192.0.2.101' -y "$YKEY" | grep -q "status: NOERROR" && pass "update accepted (7 records)" || fail "update 1"
ttl=$(d $P1 n1.ex.test A +noall +answer | awk '$4 == "A" { print $2 }')
[ "$ttl" = "200" ] && pass "max-zone-ttl 200: the TTL 300 of the update was lowered" || fail "TTL after update: '$ttl'"
serial=$(d $P1 ex.test SOA +short | awk '{ print $3 }')
[ -n "$serial" ] && [ "$serial" -ge "$before" ] && pass "serial-update-method unixtime: the serial is the time ($serial)" || fail "serial after update: '$serial' (before=$before)"
d $P1 ex.test A --update-add 'n2.ex.test 300 A 192.0.2.102' -y "$YKEY" | grep -q "status: NOERROR" && pass "update accepted (8 records, max-records 8)" || fail "update 2"
d $P1 ex.test A --update-add 'n3.ex.test 300 A 192.0.2.103' -y "$YKEY" | grep -q "status: SERVFAIL" && pass "max-records 8: the update that makes 9 is SERVFAIL" || fail "update 3"
[ -z "$(d $P1 n3.ex.test A +short)" ] && pass "the refused update changed nothing" || fail "n3 exists"
grep -q "exceeds max-records\|more than max-records" "$W/s1.log" && pass "the refusal is logged" || fail "no log line about max-records"

# server 2: minimal-responses no-auth, then a server with no-auth-recursive and one with none
cat > "$W/s2.conf" <<EOF
options { port $P2; pid-file "none"; bind-address { 127.0.0.1; }; $USER_OPT minimal-responses no-auth; };
zone "ex.test" { type master; file "$W/s.zone"; };
EOF
start s2
if ! wait_up $P2; then fail "server 2 did not start"; tail -20 "$W/s2.log"; exit 1; fi
counts() { # counts PORT args...: "ANSWER AUTHORITY ADDITIONAL" of the response
    d "$@" +noedns | sed -n 's/.*ANSWER: \([0-9]*\), AUTHORITY: \([0-9]*\), ADDITIONAL: \([0-9]*\).*/\1 \2 \3/p' | head -1
}
[ "$(counts $P2 www.ex.test A)" = "1 0 0" ] && pass "no-auth: no authority NS for an A answer" || fail "no-auth www A: $(counts $P2 www.ex.test A)"
[ "$(counts $P2 ex.test MX)" = "1 0 1" ] && pass "no-auth: the additional section stays (the MX target)" || fail "no-auth MX: $(counts $P2 ex.test MX)"
kari_kill_tree $PIDS; PIDS=""
sed 's/minimal-responses no-auth;/minimal-responses no-auth-recursive;/; s/'"$P2"'/'"$P3"'/' "$W/s2.conf" > "$W/s3.conf"
start s3
if ! wait_up $P3; then fail "server 3 did not start"; tail -20 "$W/s3.log"; exit 1; fi
[ "$(counts $P3 www.ex.test A +recurse)" = "1 0 0" ] && pass "no-auth-recursive: RD set, no authority NS" || fail "no-auth-recursive +rd: $(counts $P3 www.ex.test A +recurse)"
[ "$(counts $P3 www.ex.test A +norecurse)" = "1 1 1" ] && pass "no-auth-recursive: RD clear, authority NS and its glue as usual" || fail "no-auth-recursive +nord: $(counts $P3 www.ex.test A +norecurse)"
[ "$(counts $P3 www.ex.test A +recurse)" = "1 0 0" ] && pass "no-auth-recursive: RD set again after a RD-clear query (the response cache is keyed by RD)" || fail "no-auth-recursive again"
kari_kill_tree $PIDS; PIDS=""

# server 4: version none, hostname none, server-id not written; a zone that breaks max-records is not loaded
cat > "$W/s4.conf" <<EOF
options { port $P4; pid-file "none"; bind-address { 127.0.0.1; }; $USER_OPT version none; hostname none; };
zone "ex.test" { type master; file "$W/s.zone"; };
zone "big.test" { type master; file "$W/many.zone"; max-records 5; };
EOF
printf '$TTL 300\n$ORIGIN big.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\na IN A 192.0.2.2\nb IN A 192.0.2.3\nc IN A 192.0.2.4\n' > "$W/many.zone"
start s4
if ! wait_up $P4; then fail "server 4 did not start"; tail -20 "$W/s4.log"; exit 1; fi
for n in version.bind hostname.bind id.server; do
    out=$(d $P4 $n TXT -c CH)
    echo "$out" | grep -q "ANSWER: 0, AUTHORITY: 1" && echo "$out" | grep -q "status: NOERROR" && pass "$n with none / not written: NODATA with the SOA" || fail "$n none: $out"
done
d $P4 big.test SOA | grep -q "status: SERVFAIL\|status: REFUSED" && pass "a zone with more than max-records records is not served" || fail "big.test is served: $(d $P4 big.test SOA)"
grep -q "more than max-records 5" "$W/s4.log" && pass "the load failure is logged" || fail "no log line for big.test"
d $P4 ex.test SOA +short | grep -q . && pass "the other zone is served" || fail "ex.test not served"

kari_kill_tree $PIDS; PIDS=""

# server 5: require-server-cookie, update-policy, the BIND dnstap grammar, catalog-zones, buffer aliases (all read without a warning)
P5=$(kari_port 5 15905)
cat > "$W/s5.conf" <<EOF
options { port $P5; pid-file "none"; bind-address { 127.0.0.1; }; $USER_OPT require-server-cookie yes;
  udp-receive-buffer 262144; udp-send-buffer 262144; tcp-receive-buffer 65536; tcp-send-buffer 65536; max-udp-size 1400;
  dnstap { auth; }; dnstap-output unix "$W/dnstap.sock"; dnstap-identity "optval"; fstrm-set-buffer-hint 8192;
  catalog-zones { zone "ex.test" in-memory yes; }; };
key "upd" { algorithm hmac-sha256; secret "$KEYSECRET"; };
zone "ex.test" { type master; file "$W/s.zone"; update-policy { grant upd zonesub A; }; };
EOF
"$KARICHECK" conf "$W/s5.conf" > "$W/s5.check" 2>&1 && pass "karicheck conf: the BIND dnstap grammar, catalog-zones, the buffer names and require-server-cookie are read" || fail "karicheck conf s5: $(cat "$W/s5.check")"
grep -q "fstrm-set-buffer-hint: accepted, no effect" "$W/s5.check" && pass "karicheck says that fstrm-set-* has no effect" || fail "no fstrm note: $(cat "$W/s5.check")"
sed 's#dnstap-output unix "[^"]*"#dnstap-output file "/var/log/dnstap.log"#' "$W/s5.conf" > "$W/s5b.conf"
"$KARICHECK" conf "$W/s5b.conf" > "$W/s5b.check" 2>&1 && fail "dnstap-output file was accepted" || { grep -q "mode file is not supported" "$W/s5b.check" && pass "dnstap-output file is an error (a file would be opened by the Backend)" || fail "dnstap-output file message: $(cat "$W/s5b.check")"; }
start s5
if ! wait_up $P5; then fail "server 5 did not start"; tail -20 "$W/s5.log"; else
    d $P5 www.ex.test A +cookie | grep -q "BADCOOKIE, retrying" && pass "require-server-cookie: a client cookie without a server cookie is BADCOOKIE (dag repeats the query with the server cookie it got)" || fail "BADCOOKIE: $(d $P5 www.ex.test A +cookie | head -12)"
    d $P5 www.ex.test A +nocookie | grep -q "status: NOERROR" && pass "require-server-cookie: a query without a cookie is answered" || fail "no cookie: $(d $P5 www.ex.test A +nocookie | head -12)"
    d $P5 www.ex.test A +tcp +cookie | grep -q "status: NOERROR" && pass "require-server-cookie: over TCP the client cookie is enough" || fail "tcp cookie"
    d $P5 ex.test A --update-add 'u1.ex.test 300 A 192.0.2.201' -y "$YKEY" | grep -q "status: NOERROR" && pass "update-policy: grant upd zonesub A allows an A" || fail "policy A: $(d $P5 ex.test A --update-add 'u1.ex.test 300 A 192.0.2.201' -y "$YKEY" | head -10)"
    d $P5 ex.test A --update-add 'u2.ex.test 300 TXT "x"' -y "$YKEY" | grep -q "status: REFUSED" && pass "update-policy: a TXT is REFUSED" || fail "policy TXT"
    [ -z "$(d $P5 u2.ex.test TXT +nocookie +short)" ] && pass "update-policy: the refused TXT is not in the zone" || fail "u2 exists"
    d $P5 ex.test A --update-add 'u3.ex.test 300 A 192.0.2.203' | grep -q "status: REFUSED" && pass "update-policy: an unsigned UPDATE is REFUSED" || fail "unsigned"
    [ "$(d $P5 u1.ex.test A +nocookie +short)" = "192.0.2.201" ] && pass "the granted A is served" || fail "u1 not served"
fi

kari_kill_tree $PIDS; PIDS=""

# servers 6 and 7: a secondary refuses a transfer that breaks max-records / max-records-per-type, and takes it when the limit is wide enough
P6=$(kari_port 6 15906)
P7=$(kari_port 7 15907)
cat > "$W/s6.conf" <<EOF
options { port $P6; pid-file "none"; bind-address { 127.0.0.1; }; $USER_OPT };
zone "ex.test" { type master; file "$W/s.zone"; allow-transfer { 127.0.0.1; }; };
EOF
start s6
if ! wait_up $P6; then fail "server 6 did not start"; tail -20 "$W/s6.log"; else
    # the zone has 6 records and 3 types at the apex (SOA, NS, MX)
    for lim in "max-records 5;" "max-types-per-name 2;" "max-records 6; max-records-per-type 1; max-types-per-name 3;"; do
        cat > "$W/s7.conf" <<EOF
options { port $P7; pid-file "none"; bind-address { 127.0.0.1; }; $USER_OPT };
zone "ex.test" { type secondary; primaries { 127.0.0.1 port $P6; }; $lim };
EOF
        "$KARIDNS" -f -c "$W/s7.conf" > "$W/s7.log" 2>&1 &
        S7=$!
        PIDS="$PIDS $S7"
        _i=0
        while [ $_i -lt 40 ] && ! grep -q "not installed after XFR\|Transfer.*complete\|AXFR.*success" "$W/s7.log" && [ -z "$(d $P7 www.ex.test A +nocookie +short 2>/dev/null | grep 192)" ]; do sleep 0.5; _i=$((_i + 1)); done
        case "$lim" in
        "max-records 6;"*)
            [ "$(d $P7 www.ex.test A +nocookie +short)" = "192.0.2.80" ] && pass "a limit that the zone fits ('$lim'): the transfer is installed" || fail "secondary with room: www not served: $(tail -5 "$W/s7.log")" ;;
        *)
            d $P7 ex.test SOA | grep -q "status: SERVFAIL\|status: REFUSED" && pass "secondary with '$lim': the transfer is refused, the zone is not served" || fail "secondary '$lim' serves the zone"
            grep -q "not installed after XFR" "$W/s7.log" && pass "the refusal is logged (zone not installed after XFR)" || fail "secondary '$lim': no log line: $(tail -5 "$W/s7.log")" ;;
        esac
        kari_kill_tree $S7
    done
fi

# karidns-dbloader --check --zone-checks: the policy text is read before the database is opened (karicheck db passes the check-* options this way)
LOADER="${LOADER:-$ROOT/karidns-dbloader}"
if [ -x "$LOADER" ] && "$LOADER" --drivers 2>/dev/null | grep -qx sqlite3; then
    out=$("$LOADER" --check --driver sqlite3 --database-file "$W/none.db" --zone-checks "mx-cname=sometimes" 2>&1); rc=$?
    [ "$rc" -eq 2 ] && echo "$out" | grep -q "zone-checks: invalid check policy 'mx-cname=sometimes'" && pass "dbloader --zone-checks: an invalid severity is a usage error" || fail "dbloader --zone-checks bad value: rc=$rc $out"
    out=$("$LOADER" --check --driver sqlite3 --database-file "$W/none.db" --zone-checks "nonsense=warn" 2>&1); rc=$?
    [ "$rc" -eq 2 ] && echo "$out" | grep -q "invalid check policy 'nonsense=warn'" && pass "dbloader --zone-checks: an unknown check is a usage error" || fail "dbloader --zone-checks unknown name: rc=$rc $out"
    out=$("$LOADER" --check --driver sqlite3 --database-file "$W/none.db" --zone-checks "names=fail,mx-cname=warn,integrity=ignore,wildcard=warn" 2>&1); rc=$?
    echo "$out" | grep -q "invalid check policy" && fail "dbloader --zone-checks: a valid policy was refused: $out" || pass "dbloader --zone-checks: a valid policy is read (the missing database is then the only complaint)"
    out=$("$LOADER" --zone-checks "mx=warn" --driver sqlite3 --database-file "$W/none.db" 2>&1); rc=$?
    [ "$rc" -eq 2 ] && echo "$out" | grep -q "are for --check" && pass "dbloader --zone-checks without --check is a usage error" || fail "dbloader --zone-checks without --check: rc=$rc $out"
else
    echo "SKIP: karidns-dbloader (SQLite3 driver) is not built: --zone-checks not tested"
fi

if [ "$FAILS" -eq 0 ]; then echo "PASS: BIND option values (batch 7)"; exit 0; fi
echo "FAILED: $FAILS check(s)"
exit 1
