#!/bin/sh
# run_nsec3_owner_query_test.sh - a query for an NSEC3 owner name is a Name Error (RFC 5155 §7.2.8).
#
# RFC 5155 §7.2.8: the owner names of NSEC3 RRs are not in the NSEC3 chain like other names. When QNAME equals
# the owner name of an NSEC3 RR and no RR types exist at QNAME or below it, the response MUST be the Name Error
# response of §7.2.2 (closest encloser proof plus the NSEC3 covering the wildcard), as if the NSEC3 owner name
# did not exist. NSEC3 RRs are still returned by AXFR and IXFR. Before the fix KariDNS answered NOERROR with the
# NSEC3 RR and its RRSIG in the Answer section (found by the Phase 0 differential run against BIND 9.20).
#
# A small zone is signed with dnssec-signzone -3 - -H 0. For an NSEC3 owner name, queries for A, NSEC3, RRSIG
# and ANY (UDP and TCP, DO=1 and DO=0, MQTYPE, minimal-any on and off) must answer NXDOMAIN with an empty Answer
# section and, with DO=1, 2 or 3 NSEC3 RRs in Authority, among them the NSEC3 matching the apex (the closest
# encloser), with their RRSIGs. A name below an NSEC3 owner name is NXDOMAIN too. When an NSEC3 owner name also
# has an A RR, the name exists but its NSEC3 RR and RRSIG(NSEC3) are still never answered (QTYPE NSEC3/RRSIG
# NODATA, MQTYPE). In a second zone with a wildcard at the apex the NSEC3 owner name, not existing, is answered
# from the wildcard as BIND 9.20 does (TXT: wildcard answer with the NSEC3 covering the next closer name; other
# types: wildcard NODATA with the wildcard's NSEC3). Controls: an existing name still answers, its NSEC3 query is
# NODATA, and AXFR returns every NSEC3 RR of the signed file. When BIND named is installed, RCODE and Answer of
# A/TXT/NSEC3/RRSIG/ANY for every NSEC3 owner name of both zones must equal named's.
#
# Needs dnssec-keygen and dnssec-signzone; SKIP otherwise (nsec3hash and named are optional).

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="$BASE_DIR/karidns-asan"
DAG="$BASE_DIR/dag"
PORT=15480      # default options
MPORT=15479     # minimal-any yes
BPORT=15478     # BIND named (differential check, when installed)
Z=n3owner.test

echo "=== NSEC3 owner name queries (RFC 5155 §7.2.8) ==="

for t in dnssec-keygen dnssec-signzone; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "  [SKIP] $t is not installed"
        echo "=== SKIPPED ==="
        exit 0
    fi
done

[ -x "$DAG" ] || make -C "$BASE_DIR" dag >/dev/null || exit 1
[ -x "$KARIDNS" ] || make -C "$BASE_DIR" karidns-asan >/dev/null || exit 1

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/karidns_n3owner.XXXXXX")"
chmod 755 "$TMP_DIR"
PID=""
MPID=""
NPID=""
cleanup() {
    kari_kill_tree "$PID" "$MPID" "$NPID"
    kari_kill_conf "$TMP_DIR/k.conf" "$TMP_DIR/m.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

# sign ZONE [extra line]: $TMP_DIR/ZONE.signed, NSEC3 without salt and with 0 iterations, one RR per line
sign() {
    cat > "$TMP_DIR/$1.zone" <<EOF
\$TTL 300
\$ORIGIN $1.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
mail IN MX 10 www
$2
EOF
    (cd "$TMP_DIR" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$1" >/dev/null 2>&1 \
        && dnssec-keygen -q -a ECDSAP256SHA256 "$1" >/dev/null 2>&1 \
        && dnssec-signzone -q -S -K . -O full -3 - -H 0 -o "$1" -f "$1.signed" "$1.zone" >/dev/null 2>&1) &&
        chmod 644 "$TMP_DIR/$1.signed"
}
# WZ has a wildcard at the apex: an NSEC3 owner name there does not exist, so the wildcard answers it (as BIND 9.20)
WZ=n3wild.test
if ! sign "$Z" || ! sign "$WZ" '* IN TXT "w"'; then
    echo "  [SKIP] dnssec-signzone failed"
    echo "=== SKIPPED ==="
    exit 0
fi

# -O full: one RR per line, fully qualified owner names
OWNERS=$(awk '$4 == "NSEC3" { print tolower($1) }' "$TMP_DIR/$Z.signed")
N_NSEC3=$(echo "$OWNERS" | grep -c .)
OWNER=$(echo "$OWNERS" | head -1)
if [ "$N_NSEC3" -lt 2 ] || [ -z "$OWNER" ]; then
    fail "the signed zone has $N_NSEC3 NSEC3 RRs"
    echo "=== FAILED ==="
    exit 1
fi
# The minimal-any server also has an (unsigned) A RR at the last NSEC3 owner name: that name exists, and its
# NSEC3 RR and RRSIG(NSEC3) still must not be answered
LAST=$(echo "$OWNERS" | tail -1)
{ cat "$TMP_DIR/$Z.signed"; echo "$LAST 300 IN A 192.0.2.77"; } > "$TMP_DIR/$Z.mixed"
chmod 644 "$TMP_DIR/$Z.mixed"

write_conf() {
    cat > "$1" <<EOF
options { port $2; bind-address { 127.0.0.1; }; pid-file "none"; rfc10029-mqtype yes; $4 $USER_OPT };
zone "$Z" { type master; file "$TMP_DIR/$3"; allow-transfer { 127.0.0.1; }; };
EOF
}
write_conf "$TMP_DIR/k.conf" $PORT "$Z.signed" ""
echo "zone \"$WZ\" { type master; file \"$TMP_DIR/$WZ.signed\"; };" >> "$TMP_DIR/k.conf"
write_conf "$TMP_DIR/m.conf" $MPORT "$Z.mixed" "minimal-any yes;"

"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/k.log" 2>&1 &
PID=$!
"$KARIDNS" -f "$TMP_DIR/m.conf" > "$TMP_DIR/m.log" 2>&1 &
MPID=$!
for p in $PORT $MPORT; do
    i=0
    while [ $i -lt 100 ]; do
        "$DAG" $Z SOA @127.0.0.1 -p $p +short +time=1 +tries=1 +nohexdump 2>/dev/null | grep -q hostmaster && break
        sleep 0.2; i=$((i + 1))
    done
done

# section NAME: the RRs of one section of the dag output on stdin
section() { awk -v s=";; $1 SECTION:" '$0 == s { on = 1; next } on && /^$/ { exit } on && !/^;/ { print }'; }

# The NSEC3 owner name matching the apex (the closest encloser of every name tested below): nsec3hash (SHA-1,
# 0 iterations, no salt) when installed, otherwise the NSEC3 of the apex NODATA proof
if command -v nsec3hash >/dev/null 2>&1; then
    APEX_N3=$(nsec3hash - 1 0 "$Z" 2>/dev/null | awk '{ print tolower($1) }')
    [ -n "$APEX_N3" ] && APEX_N3="$APEX_N3.$Z."
else
    APEX_N3=$("$DAG" $Z TYPE65280 @127.0.0.1 -p $PORT +dnssec +time=2 +tries=1 +nohexdump 2>/dev/null |
        section AUTHORITY | awk '$4 == "NSEC3" { print tolower($1); exit }')
fi
echo "$OWNERS" | grep -qx "$APEX_N3" || fail "the NSEC3 owner name of the apex ($APEX_N3) is not in the zone"
[ -n "$APEX_N3" ] || fail "no NSEC3 in the NODATA answer for the apex"

# check_nx LABEL QNAME PORT DAG-ARGS...: NXDOMAIN, empty Answer, SOA in Authority; with +dnssec 2-3 NSEC3 RRs
# including the apex's, each with an RRSIG
check_nx() {
    _l=$1; _q=$2; _p=$3; shift 3
    _out=$("$DAG" "$_q" "$@" @127.0.0.1 -p "$_p" +time=2 +tries=1 +nohexdump 2>&1)
    _ans=$(echo "$_out" | section ANSWER | grep -c .)
    _auth=$(echo "$_out" | section AUTHORITY)
    _soa=$(echo "$_auth" | awk '$4 == "SOA"' | grep -c .)
    _n3=$(echo "$_auth" | awk '$4 == "NSEC3"' | grep -c .)
    _sig=$(echo "$_auth" | awk '$4 == "RRSIG" && $5 == "NSEC3"' | grep -c .)
    _ok=1
    echo "$_out" | grep -q "status: NXDOMAIN" || _ok=0
    [ "$_ans" -eq 0 ] && [ "$_soa" -eq 1 ] || _ok=0
    case " $* " in
        *" +dnssec "*)
            [ "$_n3" -ge 2 ] && [ "$_n3" -le 3 ] && [ "$_sig" -ge "$_n3" ] || _ok=0
            echo "$_auth" | awk '$4 == "NSEC3" { print tolower($1) }' | grep -qx "$APEX_N3" || _ok=0 ;;
        *) [ "$_n3" -eq 0 ] || _ok=0 ;;
    esac
    if [ $_ok -eq 1 ]; then
        pass "$_l: NXDOMAIN (answer $_ans, NSEC3 $_n3, RRSIG(NSEC3) $_sig)"
    else
        fail "$_l: expected NXDOMAIN with the NSEC3 proof"
        echo "$_out" | sed -n '/->>HEADER<<-/p;/^;; [A-Z]* SECTION:/,/^$/p' | sed 's/^/      /'
    fi
}

for qt in A NSEC3 RRSIG ANY; do
    check_nx "$qt at the NSEC3 owner, UDP, DO=1" "$OWNER" $PORT $qt +dnssec
done
check_nx "NSEC3 at the NSEC3 owner, TCP, DO=1" "$OWNER" $PORT NSEC3 +dnssec +tcp
check_nx "RRSIG at the NSEC3 owner, TCP, DO=1" "$OWNER" $PORT RRSIG +dnssec +tcp
check_nx "NSEC3 at the NSEC3 owner, DO=0 (wire cache path)" "$OWNER" $PORT NSEC3
check_nx "A at the NSEC3 owner, DO=0, TCP" "$OWNER" $PORT A +tcp
check_nx "NSEC3 + MQTYPE A,RRSIG at the NSEC3 owner, DO=1" "$OWNER" $PORT NSEC3 +dnssec +mqtype=A,RRSIG
check_nx "ANY at the NSEC3 owner, minimal-any, DO=1" "$OWNER" $MPORT ANY +dnssec
check_nx "ANY at the NSEC3 owner, minimal-any, DO=0" "$OWNER" $MPORT ANY
check_nx "A below the NSEC3 owner, DO=1" "x.$OWNER" $PORT A +dnssec
check_nx "NSEC3 at the last NSEC3 owner, DO=1" "$LAST" $PORT NSEC3 +dnssec

# check_mixed LABEL QTYPE WANT-ANSWER DAG-ARGS...: the last NSEC3 owner name with an A RR (minimal-any server):
# NOERROR, and the Answer section is exactly WANT-ANSWER RRs, all of type A
check_mixed() {
    _l=$1; _t=$2; _want=$3; shift 3
    _out=$("$DAG" "$LAST" "$_t" "$@" @127.0.0.1 -p $MPORT +time=2 +tries=1 +nohexdump 2>&1)
    _ans=$(echo "$_out" | section ANSWER | grep -c .)
    _a=$(echo "$_out" | section ANSWER | awk '$4 == "A" && $5 == "192.0.2.77"' | grep -c .)
    if echo "$_out" | grep -q "status: NOERROR" && [ "$_ans" -eq "$_want" ] && [ "$_a" -eq "$_want" ]; then
        pass "$_l: NOERROR with $_ans answer RRs"
    else
        fail "$_l: expected NOERROR with $_want A RRs in Answer"
        echo "$_out" | sed -n '/->>HEADER<<-/p;/^;; [A-Z]* SECTION:/,/^$/p' | sed 's/^/      /'
    fi
}
check_mixed "A at an NSEC3 owner name that has an A RR" A 1 +dnssec
check_mixed "NSEC3 at an NSEC3 owner name that has an A RR (NODATA)" NSEC3 0 +dnssec
check_mixed "RRSIG at an NSEC3 owner name that has an A RR (NODATA)" RRSIG 0 +dnssec
check_mixed "A + MQTYPE NSEC3,RRSIG at an NSEC3 owner name that has an A RR" A 1 +dnssec +mqtype=NSEC3,RRSIG

# Controls: an existing name keeps its answer; NSEC3 at it is NODATA (the NSEC3 matching www is the proof)
out=$("$DAG" www.$Z A @127.0.0.1 -p $PORT +dnssec +time=2 +tries=1 +nohexdump 2>&1)
if echo "$out" | grep -q "status: NOERROR" && echo "$out" | section ANSWER | awk '$4 == "A"' | grep -q 192.0.2.10; then
    pass "www A: NOERROR with the A RR"
else
    fail "www A: expected NOERROR with 192.0.2.10"
fi
out=$("$DAG" www.$Z NSEC3 @127.0.0.1 -p $PORT +dnssec +time=2 +tries=1 +nohexdump 2>&1)
if echo "$out" | grep -q "status: NOERROR" && [ "$(echo "$out" | section ANSWER | grep -c .)" -eq 0 ] &&
   [ "$(echo "$out" | section AUTHORITY | awk '$4 == "NSEC3"' | grep -c .)" -eq 1 ]; then
    pass "www NSEC3: NODATA with the matching NSEC3"
else
    fail "www NSEC3: expected NODATA with one NSEC3"
    echo "$out" | sed -n '/->>HEADER<<-/p;/^;; [A-Z]* SECTION:/,/^$/p' | sed 's/^/      /'
fi

# Apex wildcard (WZ): the NSEC3 owner name does not exist, so the wildcard is synthesized for it, as BIND 9.20
# does: TXT is a wildcard answer (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6: the NSEC3 covering the next closer name,
# here QNAME itself), any other type a wildcard NODATA (§7.2.5: also the NSEC3 matching the wildcard).
# The wildcard's NSEC3 is the only one whose type bitmap is "TXT RRSIG".
WC_N3=$(awk '$4 == "NSEC3" && $10 == "TXT" && $11 == "RRSIG" && $12 == "" { print tolower($1) }' "$TMP_DIR/$WZ.signed")
[ -n "$WC_N3" ] || fail "$WZ: no NSEC3 RR for the wildcard"
# covered_by HASH: the NSEC3 RRs on stdin (owner, next) that cover HASH (RFC 5155 §1.3, last one wraps around)
covered_by() {
    awk -v t="$1" '$4 == "NSEC3" { o = toupper($1); sub(/\..*/, "", o); n = toupper($9)
        if ((o < n && o < t && t < n) || (o >= n && (t > o || t < n))) print o }'
}
for o in $(awk '$4 == "NSEC3" { print tolower($1) }' "$TMP_DIR/$WZ.signed"); do
    out=$("$DAG" "$o" TXT @127.0.0.1 -p $PORT +dnssec +time=2 +tries=1 +nohexdump 2>&1)
    ans=$(echo "$out" | section ANSWER)
    auth=$(echo "$out" | section AUTHORITY)
    ok=1
    echo "$out" | grep -q "status: NOERROR" || ok=0
    echo "$ans" | awk -v q="$o" 'tolower($1) == q && $4 == "TXT" && $5 == "\"w\""' | grep -q . || ok=0
    echo "$ans" | awk '$4 == "RRSIG" && $5 == "TXT"' | grep -q . || ok=0
    if command -v nsec3hash >/dev/null 2>&1; then
        h=$(nsec3hash - 1 0 "$o" 2>/dev/null | awk '{ print toupper($1) }')
        [ -n "$(echo "$auth" | covered_by "$h")" ] || ok=0
    else
        echo "$auth" | awk '$4 == "NSEC3"' | grep -q . || ok=0
    fi
    if [ $ok -eq 1 ]; then
        pass "apex wildcard, TXT at NSEC3 owner $o: wildcard answer with the next closer proof"
    else
        fail "apex wildcard, TXT at NSEC3 owner $o: expected NOERROR with TXT \"w\" and the next closer proof"
        echo "$out" | sed -n '/->>HEADER<<-/p;/^;; [A-Z]* SECTION:/,/^$/p' | sed 's/^/      /'
    fi
    for qt in NSEC3 A; do
        out=$("$DAG" "$o" $qt @127.0.0.1 -p $PORT +dnssec +time=2 +tries=1 +nohexdump 2>&1)
        auth=$(echo "$out" | section AUTHORITY)
        if echo "$out" | grep -q "status: NOERROR" && [ "$(echo "$out" | section ANSWER | grep -c .)" -eq 0 ] &&
           echo "$auth" | awk '$4 == "SOA"' | grep -q . &&
           echo "$auth" | awk '$4 == "NSEC3" { print tolower($1) }' | grep -qx "$WC_N3"; then
            pass "apex wildcard, $qt at NSEC3 owner $o: wildcard NODATA with the wildcard's NSEC3"
        else
            fail "apex wildcard, $qt at NSEC3 owner $o: expected wildcard NODATA"
            echo "$out" | sed -n '/->>HEADER<<-/p;/^;; [A-Z]* SECTION:/,/^$/p' | sed 's/^/      /'
        fi
    done
done

# Differential check against BIND named (when installed): same RCODE and Answer section for every NSEC3 owner
# name of both zones. Authority is not compared: KariDNS also puts the closest encloser's NSEC3 into wildcard
# answers, which BIND leaves out (both are valid proofs).
if command -v named >/dev/null 2>&1; then
    cat > "$TMP_DIR/named.conf" <<EOF
options { directory "$TMP_DIR"; listen-on port $BPORT { 127.0.0.1; }; listen-on-v6 { none; };
          pid-file "$TMP_DIR/named.pid"; recursion no; };
zone "$Z" { type primary; file "$TMP_DIR/$Z.signed"; };
zone "$WZ" { type primary; file "$TMP_DIR/$WZ.signed"; };
EOF
    named -c "$TMP_DIR/named.conf" -g > "$TMP_DIR/named.log" 2>&1 &
    NPID=$!
    i=0
    while [ $i -lt 50 ]; do
        "$DAG" $WZ SOA @127.0.0.1 -p $BPORT +short +time=1 +tries=1 +nohexdump 2>/dev/null | grep -q hostmaster && break
        sleep 0.2; i=$((i + 1))
    done
    # answer PORT QNAME QTYPE: status and the Answer RRs (RRSIG reduced to owner and type covered), sorted
    answer() {
        _o=$("$DAG" "$2" "$3" @127.0.0.1 -p "$1" +dnssec +time=2 +tries=1 +nohexdump 2>&1)
        echo "$_o" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'
        echo "$_o" | section ANSWER | awk '{ $1 = tolower($1); $2 = ""; if ($4 == "RRSIG") print $1, $4, $5; else print }' | sort
    }
    nd=0; nq=0
    for f in "$Z" "$WZ"; do
        for o in $(awk '$4 == "NSEC3" { print tolower($1) }' "$TMP_DIR/$f.signed"); do
            for qt in A TXT NSEC3 RRSIG ANY; do
                nq=$((nq + 1))
                if [ "$(answer $PORT "$o" $qt)" != "$(answer $BPORT "$o" $qt)" ]; then
                    nd=$((nd + 1))
                    fail "differs from BIND: $o $qt"
                    echo "      KariDNS: $(answer $PORT "$o" $qt | tr '\n' '|')"
                    echo "      BIND:    $(answer $BPORT "$o" $qt | tr '\n' '|')"
                fi
            done
        done
    done
    [ $nd -eq 0 ] && pass "RCODE and Answer equal to BIND named for $nq queries to NSEC3 owner names"
else
    echo "  [SKIP] named is not installed: no differential check against BIND"
fi

# RFC 5155 §7.2.8: AXFR still carries every NSEC3 RR and its RRSIG
out=$("$DAG" $Z AXFR @127.0.0.1 -p $PORT +time=2 +tries=1 +nohexdump 2>&1)
x_n3=$(echo "$out" | awk '$4 == "NSEC3" { print tolower($1) }' | sort)
x_sig=$(echo "$out" | awk '$4 == "RRSIG" && $5 == "NSEC3"' | grep -c .)
x_soa=$(echo "$out" | awk '$4 == "SOA"' | grep -c .)
if [ "$x_n3" = "$(echo "$OWNERS" | sort)" ] && [ "$x_sig" -ge "$N_NSEC3" ] && [ "$x_soa" -eq 2 ]; then
    pass "AXFR: all $N_NSEC3 NSEC3 RRs with $x_sig RRSIG(NSEC3)"
else
    fail "AXFR: expected $N_NSEC3 NSEC3 RRs, got $(echo "$x_n3" | grep -c .) (RRSIG $x_sig, SOA $x_soa)"
fi

kill -0 "$PID" 2>/dev/null || fail "the server exited during the test"
kill -0 "$MPID" 2>/dev/null || fail "the minimal-any server exited during the test"
if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$TMP_DIR/k.log" "$TMP_DIR/m.log"; then
    fail "sanitizer report in a server log"
fi
if [ $FAILED -ne 0 ]; then
    echo "--- k.log (tail) ---"; tail -15 "$TMP_DIR/k.log"
    echo "=== FAILED ==="
    exit 1
fi
echo "=== PASSED ==="
exit 0
