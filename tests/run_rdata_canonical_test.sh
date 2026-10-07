#!/bin/sh
# RDATA handling at the server (FIX_REPORTS phase 15b):
# - X-37: names in the RDATA of types outside the RFC 4034 §6.2 item 3 list (IPSECKEY, TALINK) keep their case.
# - X-38: WKS port mnemonics (RFC 1035 §3.4.2) are encoded.
# - X-32: a record whose RDATA cannot be encoded is left out with a warning; AXFR still sends the whole zone.
# - X-16: UPDATE compares names in RDATA case-insensitively (RFC 2136 §1.1.1, §1.1.2): delete, prerequisite,
#   duplicate add.
# - X-25: UPDATE can delete a DNSSEC record loaded from the zone file (text vs wire form).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PORT=15853
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-rdcanon.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
SERVER_PID=""

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    [ -f "$W/out.txt" ] && { echo "=== last output ==="; cat "$W/out.txt"; }
    echo "=== server log ==="; cat "$W/server.log"
    exit 1
}

cat > "$W/case.zone" <<'EOF'
$ORIGIN case.test.
$TTL 300
@    IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@    IN NS  ns1.case.test.
@    IN NS  ns2.case.test.
ns1  IN A   192.0.2.1
ns2  IN A   192.0.2.2
mx   IN MX  10 mail.case.test.
mail IN A   192.0.2.3
ip   IN IPSECKEY 10 3 2 Gw.Case.Test. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==
ta   IN TALINK Prev.Case.Test. Next.Case.Test.
w    IN WKS 192.0.2.20 TCP smtp http 443
bad  IN WKS 192.0.2.21 TCP nosuchservice 25
www  IN A   192.0.2.80
www  IN RRSIG A 13 3 300 20300101000000 20200101000000 12345 case.test. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==
zz   IN A   192.0.2.99
EOF

cat > "$W/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "case.test" { type master; file "$W/case.zone"; allow-update { 127.0.0.1; }; allow-transfer { 127.0.0.1; }; };
EOF

"$BIN" -f "$W/k.conf" > "$W/server.log" 2>&1 &
SERVER_PID=$!
i=0
until "$DAG" @127.0.0.1 -p $PORT case.test SOA +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster; do
    i=$((i + 1)); [ $i -lt 50 ] || fail "server did not start"; sleep 0.2
done

D="$DAG @127.0.0.1 -p $PORT +nohexdump +time=2 +tries=1"
short() { $D "$@" +short > "$W/out.txt" 2>&1 || true; tr '\n' ' ' < "$W/out.txt" | sed 's/ *$//'; }
status() { $D "$@" > "$W/out.txt" 2>&1 || true; sed -n 's/.*status: \([A-Z]*\).*/\1/p' "$W/out.txt" | head -1; }

# X-37
got=$(short ip.case.test IPSECKEY)
[ "$got" = "10 3 2 Gw.Case.Test. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==" ] || fail "X-37 IPSECKEY: '$got'"
got=$(short ta.case.test TALINK)
[ "$got" = "Prev.Case.Test. Next.Case.Test." ] || fail "X-37 TALINK: '$got'"
echo "[OK] X-37: IPSECKEY and TALINK names keep their case"

# X-38
got=$(short w.case.test WKS)
[ "$got" = "192.0.2.20 6 25 80 443" ] || fail "X-38 WKS: '$got'"
echo "[OK] X-38: WKS port names encoded"

# X-32
[ "$(status bad.case.test WKS)" = "NXDOMAIN" ] || fail "X-32: bad.case.test (only the unencodable record) is not NXDOMAIN"
grep -q "ignoring record 'bad.case.test.' WKS: its RDATA cannot be encoded" "$W/server.log" || fail "X-32: no warning in the log"
$D case.test AXFR > "$W/out.txt" 2>&1 || true
[ "$(grep -c '^case.test\..*SOA' "$W/out.txt")" = "2" ] || fail "X-32: AXFR does not end with the SOA"
grep -q '^zz.case.test\.' "$W/out.txt" || fail "X-32: AXFR lacks the record after the bad one"
grep -q '^w.case.test\..*WKS' "$W/out.txt" || fail "X-32: AXFR lacks the WKS record"
echo "[OK] X-32: unencodable record left out with a warning, AXFR complete"

# X-16: delete with different case
[ "$(status case.test --update-del-exact 'case.test 0 IN NS NS2.CASE.TEST.')" = "NOERROR" ] || fail "X-16 delete status"
got=$(short case.test NS)
[ "$got" = "ns1.case.test." ] || fail "X-16: NS after delete: '$got'"
# X-16: value-dependent prerequisite with different case
[ "$(status case.test --prereq=yxrrset:mx.case.test:MX:'10 MAIL.case.test.' --update-add 'p.case.test 300 A 192.0.2.7')" = "NOERROR" ] \
    || fail "X-16: prerequisite with upper-case name"
[ "$(short p.case.test A)" = "192.0.2.7" ] || fail "X-16: update after the prerequisite not applied"
# X-16: adding the same RR in other case is a duplicate (RFC 2136 §3.4.2.2)
[ "$(status case.test --update-add 'mx.case.test 300 MX 10 MAIL.CASE.TEST.')" = "NOERROR" ] || fail "X-16 add status"
got=$(short mx.case.test MX)
[ "$got" = "10 mail.case.test." ] || fail "X-16: duplicate MX added: '$got'"
echo "[OK] X-16: RDATA names compared case-insensitively"

# X-25: delete the RRSIG loaded from the zone file, using the served RDATA
SIG=$($D www.case.test RRSIG +short 2>/dev/null | head -1)
[ -n "$SIG" ] || fail "X-25: no RRSIG served"
[ "$(status case.test --update-del-exact "www.case.test 0 IN RRSIG $SIG")" = "NOERROR" ] || fail "X-25 delete status"
got=$(short www.case.test RRSIG)
[ -z "$got" ] || fail "X-25: RRSIG still present: '$got'"
[ "$(short www.case.test A)" = "192.0.2.80" ] || fail "X-25: the A record changed"
echo "[OK] X-25: file-loaded RRSIG deleted by UPDATE"

if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$W/server.log"; then
    fail "sanitizer report in the server log"
fi
echo "[PASS] RDATA canonical form / case / WKS / unencodable records test passed"
exit 0
