#!/bin/sh
# run_any_rrsig_query_test.sh - ANY and RRSIG questions (0.7, BIND's changes of 2026-11-24).
#
# ANY over UDP: an empty response with TC=1 (RFC 8482 section 4.4; NOERROR, AA=0), unless the query carries a valid
# server cookie of this server (RFC 7873 section 5.2.4, RFC 9018): a client cookie alone gets TC=1 with a server
# cookie, and the query repeated with that cookie is answered over UDP.  ANY over TCP is answered as before, with
# minimal-any no (all RRsets) and the default, yes since 0.7 (HINFO "RFC8482", RFC 8482 section 4.2).
# RRSIG: FORMERR with EDE 30 Invalid Query Type, the question echoed, over UDP and TCP, DO=0 and DO=1, at a CNAME
# owner, for a tinydns zone and for a name in no zone (BIND 9.20.31 lib/ns/query.c ns_query_start()).
# NXNAME (RFC 9824 3.5): FORMERR with EDE 30 for this server's own data; a forward zone relays it as it comes.
# answer-rrsig-queries yes keeps the 0.6 answer: the name's RRSIG RRset (at a CNAME owner its own, RFC 4035 2.5).
# The RRSIG records of the zone are not checked by anyone here (no validation), so the zone needs no real signing.

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="${KARIDNS:-$BASE_DIR/karidns-asan}"
DAG="$BASE_DIR/dag"
KARICHECK="$BASE_DIR/karicheck"
PORT=$(kari_port 0 15490)      # minimal-any no (every RRset), else the defaults
OPORT=$(kari_port 100 15491)   # answer-rrsig-queries yes; minimal-any not written (the default, yes)
FPORT=$(kari_port 200 15492)   # tests/mock_alias_upstream.pl: the forwarder of the forward zone fw.test

echo "=== ANY over UDP (RFC 8482 4.4) and RRSIG questions ==="

[ -x "$DAG" ] || kari_make dag >/dev/null || exit 1
[ -x "$KARIDNS" ] || kari_make karidns-asan >/dev/null || exit 1
[ -x "$KARICHECK" ] || kari_make karicheck >/dev/null || exit 1

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/karidns_anyrrsig.XXXXXX")"
chmod 755 "$TMP_DIR"
PID=""
OPID=""
MPID=""
cleanup() {
    kari_kill_tree "$PID" "$OPID" "$MPID"
    kari_kill_conf "$TMP_DIR/k.conf" "$TMP_DIR/o.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

SIG="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
cat > "$TMP_DIR/ar.zone" <<EOF
\$TTL 300
\$ORIGIN ar.test.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
host IN A 192.0.2.10
host IN TXT "t"
host IN RRSIG A 13 3 300 20300101000000 20260101000000 12345 ar.test. $SIG
host IN RRSIG TXT 13 3 300 20300101000000 20260101000000 12345 ar.test. $SIG
alias IN CNAME host
alias IN RRSIG CNAME 13 3 300 20300101000000 20260101000000 12345 ar.test. $SIG
big IN TXT "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
big IN TXT "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
big IN TXT "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
big IN TXT "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
EOF
cat > "$TMP_DIR/td.data" <<EOF
Ztd.test:ns1.td.test.:hostmaster.td.test.:1:3600:900:604800:300:300
&td.test::ns1.td.test.:300
+ns1.td.test:192.0.2.1:300
+www.td.test:192.0.2.20:300
EOF
{ echo "a.fw.test A 300 192.0.2.5"; i=1; while [ $i -le 24 ]; do echo "big.fw.test A 300 192.0.2.$i"; i=$((i + 1)); done; } > "$TMP_DIR/fw.data"
chmod 644 "$TMP_DIR/ar.zone" "$TMP_DIR/td.data"

write_conf() {
    cat > "$1" <<EOF
options { port $2; bind-address { 127.0.0.1; }; pid-file "none"; send-extended-errors yes; $3 $USER_OPT };
zone "ar.test" { type master; file "$TMP_DIR/ar.zone"; };
zone "td.test" { type master; file "$TMP_DIR/td.data"; file-format tinydns; };
zone "fw.test" { type forward; forwarders { 127.0.0.1 port $FPORT; }; forward-timeout 3000; };
EOF
}
write_conf "$TMP_DIR/k.conf" $PORT "minimal-any no;"
write_conf "$TMP_DIR/o.conf" $OPORT "answer-rrsig-queries yes; nocookie-udp-size 256;"

for c in k o; do
    if "$KARICHECK" conf "$TMP_DIR/$c.conf" > "$TMP_DIR/$c.check" 2>&1; then
        pass "karicheck conf accepts $c.conf"
    else
        fail "karicheck conf $c.conf: $(cat "$TMP_DIR/$c.check")"
    fi
done
printf 'options { answer-rrsig-queries maybe; };\n' > "$TMP_DIR/bad.conf"
if "$KARICHECK" conf "$TMP_DIR/bad.conf" > "$TMP_DIR/bad.check" 2>&1; then
    fail "karicheck conf accepts answer-rrsig-queries maybe"
else
    pass "karicheck conf refuses answer-rrsig-queries maybe"
fi
# minimal-any yes|no|hinfo|rrset (0.7): another word is an error with the file and line
for v in hinfo rrset yes no; do
    printf 'options { minimal-any %s; };\n' "$v" > "$TMP_DIR/ma.conf"
    if "$KARICHECK" conf "$TMP_DIR/ma.conf" > "$TMP_DIR/ma.check" 2>&1; then pass "karicheck conf accepts minimal-any $v"; else fail "karicheck conf minimal-any $v: $(cat "$TMP_DIR/ma.check")"; fi
done
printf 'options {\n    minimal-any single;\n};\n' > "$TMP_DIR/ma.conf"
if ! "$KARICHECK" conf "$TMP_DIR/ma.conf" > "$TMP_DIR/ma.check" 2>&1 && grep -q "ma.conf:2" "$TMP_DIR/ma.check"; then
    pass "karicheck conf refuses minimal-any single, with the file and line"
else
    fail "karicheck conf minimal-any single: $(cat "$TMP_DIR/ma.check")"
fi
# nocookie-udp-size: an integer (BIND: uint32; here 0..2147483647), below 128 raised to 128 with a warning, in options and view
for v in maybe -1 2147483648; do
    printf 'options { nocookie-udp-size %s; };\n' "$v" > "$TMP_DIR/nc.conf"
    if "$KARICHECK" conf "$TMP_DIR/nc.conf" > "$TMP_DIR/nc.check" 2>&1; then fail "karicheck conf accepts nocookie-udp-size $v"; else pass "karicheck conf refuses nocookie-udp-size $v"; fi
done
printf 'options { nocookie-udp-size 100; };\nview "v" { nocookie-udp-size 512; };\n' > "$TMP_DIR/nc.conf"
if "$KARICHECK" conf "$TMP_DIR/nc.conf" > "$TMP_DIR/nc.check" 2>&1 && grep -q "raising to 128" "$TMP_DIR/nc.check"; then
    pass "karicheck conf: nocookie-udp-size 100 is raised to 128 with a warning (as BIND), the view's accepted"
else
    fail "karicheck conf nocookie-udp-size 100 / view: $(cat "$TMP_DIR/nc.check")"
fi

perl "$BASE_DIR/tests/mock_alias_upstream.pl" --port "$FPORT" --data "$TMP_DIR/fw.data" --log "$TMP_DIR/fw.log" > "$TMP_DIR/fw.out" 2>&1 &
MPID=$!
"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/k.log" 2>&1 &
PID=$!
"$KARIDNS" -f "$TMP_DIR/o.conf" > "$TMP_DIR/o.log" 2>&1 &
OPID=$!
kari_wait_answer "$DAG" $PORT ar.test || { fail "server on $PORT did not answer"; kari_log_tail "$TMP_DIR/k.log"; exit 1; }
kari_wait_answer "$DAG" $OPORT ar.test || { fail "server on $OPORT did not answer"; kari_log_tail "$TMP_DIR/o.log"; exit 1; }

# ask PORT ARGS...: the dag output (no hex dumps; +ignore keeps a TC=1 UDP answer)
ask() { _p=$1; shift; "$DAG" @127.0.0.1 -p "$_p" +nohexdump +time=3 +tries=1 "$@" 2>&1; }
# expect LABEL OUT NOT-PATTERN PATTERN...: OUT matches every PATTERN (grep -E, each on some line) and no line matches NOT-PATTERN ("" = none)
expect() {
    _l=$1; _o=$2; _n=$3; shift 3
    _ok=1
    for _pat in "$@"; do echo "$_o" | grep -E -q -e "$_pat" || { _ok=0; echo "      missing /$_pat/"; }; done
    if [ -n "$_n" ] && echo "$_o" | grep -E -q -e "$_n"; then _ok=0; echo "      unexpected /$_n/"; fi
    if [ $_ok -eq 1 ]; then pass "$_l"; else fail "$_l"; echo "$_o" | sed 's/^/      /'; fi
}

# --- ANY ---
OUT=$(ask $PORT host.ar.test ANY +notcp +ignore +nocookie +noedns)
expect "ANY over UDP without EDNS: NOERROR, TC=1, AA=0, empty" "$OUT" " aa[ ;]" "status: NOERROR" ";; flags: qr tc; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0"
OUT=$(ask $PORT host.ar.test ANY +notcp +ignore +dnssec)
expect "ANY over UDP, DO=1, client cookie: TC=1, empty, OPT kept" "$OUT" " aa[ ;]" "status: NOERROR" ";; flags: qr tc; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1" "EDNS: version: 0, flags: do;"
CK=$(echo "$OUT" | awk '$1 == ";" && $2 == "COOKIE:" { print $3; exit }')
if [ "${#CK}" -eq 48 ]; then pass "the TC=1 answer carries a server cookie"; else fail "server cookie in the TC=1 answer: '$CK'"; fi
OUT=$(ask $PORT host.ar.test ANY +notcp +ignore +dnssec +cookie="$CK")
expect "ANY over UDP with the valid server cookie: answered" "$OUT" " tc[ ;]" "status: NOERROR" "flags: qr aa; QUERY: 1, ANSWER: 4," "RRSIG[[:space:]]+TXT"
FORGED=0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8
OUT=$(ask $PORT host.ar.test ANY +notcp +ignore +nobadcookie +cookie=$FORGED)
expect "ANY over UDP with a forged server cookie: BADCOOKIE (RFC 7873 5.2.3), not TC" "$OUT" " tc[ ;]" "status: BADCOOKIE" "ANSWER: 0,"
# dag (as dig) repeats the query with the server cookie of the BADCOOKIE answer (RFC 7873 5.3): that one is answered over UDP
OUT=$(ask $PORT host.ar.test ANY +notcp +ignore +cookie=$FORGED)
expect "... the BADCOOKIE retry with the new server cookie: answered over UDP" "$OUT" " tc[ ;]" ";; BADCOOKIE, retrying\." "flags: qr aa; QUERY: 1, ANSWER: 4," "SERVER: 127\.0\.0\.1#$PORT.*\(UDP\)"
OUT=$(ask $PORT nosuch.example ANY +notcp +ignore +nocookie)
expect "ANY over UDP for a name in no zone: TC=1" "$OUT" "" "status: NOERROR" ";; flags: qr tc; QUERY: 1, ANSWER: 0"
OUT=$(ask $PORT host.ar.test ANY +tcp)
expect "ANY over TCP: every RRset (minimal-any no)" "$OUT" " tc[ ;]" "flags: qr aa; QUERY: 1, ANSWER: 4,"
OUT=$(ask $PORT host.ar.test ANY)
expect "dag ANY (TCP by default, RD=0): answered" "$OUT" "" "flags: qr aa; QUERY: 1, ANSWER: 4,"
OUT=$(ask $OPORT host.ar.test ANY +notcp +ignore +nocookie)
expect "minimal-any yes (default), ANY over UDP: still TC=1" "$OUT" "" ";; flags: qr tc; QUERY: 1, ANSWER: 0"
OUT=$(ask $OPORT host.ar.test ANY +tcp +nodnssec)
expect "minimal-any yes (default), ANY over TCP: HINFO RFC8482" "$OUT" "" "ANSWER: 1," 'HINFO[[:space:]]+"RFC8482"'

# --- RRSIG ---
for a in "host.ar.test RRSIG +notcp" "host.ar.test RRSIG +tcp +dnssec" "alias.ar.test RRSIG +dnssec" "www.td.test RRSIG" \
         "nosuch.example RRSIG +notcp" "-c ANY host.ar.test RRSIG +tcp"; do
    # shellcheck disable=SC2086
    OUT=$(ask $PORT $a)
    expect "RRSIG ($a): FORMERR, EDE 30, question echoed, AA=0, no answer" "$OUT" " aa[ ;]" "status: FORMERR" "EDE: 30" "QUERY: 1, ANSWER: 0" "IN[[:space:]]+RRSIG$"
done
# --- NXNAME (RFC 9824 3.5): FORMERR (MUST), EDE 30 (MAY), for zone files, tinydns zones and no zone, with answer-rrsig-queries yes too ---
for a in "$PORT host.ar.test NXNAME +notcp" "$PORT host.ar.test NXNAME +tcp +dnssec" "$PORT www.td.test NXNAME" \
         "$PORT nosuch.example NXNAME +notcp" "$OPORT host.ar.test NXNAME +notcp"; do
    # shellcheck disable=SC2086
    OUT=$(ask $a)
    expect "NXNAME ($a): FORMERR, EDE 30, question echoed, AA=0" "$OUT" " aa[ ;]" "status: FORMERR" "EDE: 30" "QUERY: 1, ANSWER: 0" "IN[[:space:]]+NXNAME$"
done

OUT=$(ask $OPORT host.ar.test RRSIG +notcp)
expect "answer-rrsig-queries yes: the RRSIG RRset" "$OUT" "" "status: NOERROR" "flags: qr aa rd; QUERY: 1, ANSWER: 2,"
OUT=$(ask $OPORT alias.ar.test RRSIG +tcp)
expect "answer-rrsig-queries yes, CNAME owner: its own RRSIG, the CNAME not followed" "$OUT" "IN[[:space:]]+CNAME[[:space:]]" "status: NOERROR" "ANSWER: 1," "RRSIG[[:space:]]+CNAME"

# --- a forward zone relays ANY and RRSIG as before (the forwarder's answer, no TC=1 / FORMERR of this server) ---
for p in $PORT $OPORT; do
    : > "$TMP_DIR/fw.log"
    OUT=$(ask $p a.fw.test ANY +notcp +ignore +nocookie)
    expect "forward zone ($p): ANY over UDP without a cookie is relayed, no TC=1" "$OUT" " tc[ ;]" "status: NOERROR" "SERVER: .*\(UDP\)"
    OUT=$(ask $p a.fw.test RRSIG +notcp)
    expect "forward zone ($p): RRSIG is relayed, not FORMERR" "$OUT" "status: FORMERR" "status: NOERROR"
    OUT=$(ask $p a.fw.test NXNAME +notcp)
    expect "forward zone ($p): NXNAME is relayed, not FORMERR" "$OUT" "status: FORMERR" "status: NOERROR"
    if grep -q "^a\.fw\.test\.\{0,1\} 128 udp" "$TMP_DIR/fw.log"; then pass "forward zone ($p): the forwarder got the NXNAME question"; else fail "forward zone ($p): NXNAME not relayed: $(tr '\n' '|' < "$TMP_DIR/fw.log")"; fi
    if grep -q "^a\.fw\.test\.\{0,1\} 255 udp" "$TMP_DIR/fw.log" && grep -q "^a\.fw\.test\.\{0,1\} 46 udp" "$TMP_DIR/fw.log"; then   # (the mock logs the type as a number)
        pass "forward zone ($p): the forwarder got the ANY and the RRSIG questions"
    else
        fail "forward zone ($p): forwarder log: $(tr '\n' '|' < "$TMP_DIR/fw.log")"
    fi
done

# --- nocookie-udp-size (BIND 9.20; RFC 7873 5.2): a UDP answer without a valid server cookie is no larger than it ---
OUT=$(ask $PORT big.ar.test TXT +notcp +ignore +nocookie)
expect "default nocookie-udp-size (4096): the 400-octet TXT answer is not truncated" "$OUT" " tc[ ;]" "flags: qr aa rd; QUERY: 1, ANSWER: 4,"
OUT=$(ask $OPORT big.ar.test TXT +notcp +ignore +nocookie)
expect "nocookie-udp-size 256, no cookie: TC=1" "$OUT" "" "flags: qr aa tc rd;" "MSG SIZE  rcvd: ([0-9]|[0-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-6])$"
OUT=$(ask $OPORT host.ar.test A +notcp +ignore)
CK=$(echo "$OUT" | awk '$1 == ";" && $2 == "COOKIE:" { print $3; exit }')
OUT=$(ask $OPORT big.ar.test TXT +notcp +ignore +cookie="$CK")
expect "nocookie-udp-size 256, a valid server cookie: the full answer over UDP" "$OUT" " tc[ ;]" "flags: qr aa rd; QUERY: 1, ANSWER: 4," "COOKIE: .* \(good\)"
OUT=$(ask $OPORT big.ar.test TXT +notcp +ignore +cookie=$FORGED +nobadcookie)
expect "nocookie-udp-size 256, a forged server cookie: BADCOOKIE" "$OUT" "" "status: BADCOOKIE"
OUT=$(ask $OPORT big.ar.test TXT +tcp +nocookie)
expect "nocookie-udp-size 256: TCP is not limited" "$OUT" " tc[ ;]" "ANSWER: 4,"
OUT=$(ask $OPORT big.fw.test A +notcp +ignore +nocookie)
expect "nocookie-udp-size 256: a forward zone's answer is relayed whole" "$OUT" " tc[ ;]" "ANSWER: 24,"

kill -0 "$PID" 2>/dev/null || fail "the default server exited during the test"
kill -0 "$OPID" 2>/dev/null || fail "the second server exited during the test"
if grep -q "ERROR: AddressSanitizer\|runtime error:" "$TMP_DIR/k.log" "$TMP_DIR/o.log"; then
    fail "sanitizer report in the server logs"
    grep -h -A5 "AddressSanitizer\|runtime error:" "$TMP_DIR/k.log" "$TMP_DIR/o.log" | head -20
fi

if [ "$FAILED" -eq 0 ]; then
    echo "=== PASSED ==="
    exit 0
fi
echo "=== FAILED ==="
exit 1
