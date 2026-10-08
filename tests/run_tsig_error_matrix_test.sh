#!/bin/sh
# TSIG verification, error responses and authorization (AUDIT_FINDINGS R-07, R-08, R-09, R-10, R-20, R-30, D-03, T-02).
# - RFC 8945 §5.2: the request TSIG is checked first; the key is the one the request names (owner + algorithm).
#   Unknown key -> NOTAUTH + BADKEY (17), bad MAC -> NOTAUTH + BADSIG (16): unsigned (MAC size 0), with the
#   request's key name (§5.3.2). Stale time -> NOTAUTH + BADTIME (18), signed with the request key, Time Signed =
#   the client's time, Other Data = server time (§5.2.3).
# - A policy denial after a valid or absent TSIG is REFUSED (RFC 2136 §3.3, RFC 1035 §4.1.1), signed with the
#   request key when the TSIG was valid (§5.3). Every response to a validly signed request is signed, also for a
#   plain QUERY (§5.2 "the server is REQUIRED to return a TSIG RR").
# - D-03: key names are DNS names (key "K2" in the config matches allow-transfer { key "k2"; }).
# - A KariDNS secondary with tsig-key transfers from a KariDNS primary that requires the key.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PPORT=15493
SPORT=15494
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-tsig.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
PRIMARY_PID=""
SECONDARY_PID=""

cleanup() {
    kari_kill_tree "$PRIMARY_PID" "$SECONDARY_PID"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    for f in "$W"/out.txt "$W"/primary.log "$W"/secondary.log; do
        [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }
    done
    exit 1
}

check_asan_log() {
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$W"/primary.log "$W"/secondary.log 2>/dev/null; then
        fail "sanitizer report in a server log"
    fi
}

S1=c2VjcmV0LWtleS1vbmUtMDEyMzQ1Njc4OWFiY2RlZg==
S2=c2VjcmV0LWtleS10d28tMDEyMzQ1Njc4OWFiY2RlZg==
BAD=YmFkLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMw==

for z in m n p ax ay az sec; do
    cat > "$W/$z.zone" <<EOF
\$TTL 300
\$ORIGIN $z.test.
@ IN SOA ns1.$z.test. hostmaster.$z.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.$z.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
EOF
done

cat > "$W/primary.conf" <<EOF
options { port $PPORT; bind-address { 127.0.0.1; }; pid-file "none"; send-extended-errors yes; $USER_OPT };
key "k1" { algorithm hmac-sha256; secret "$S1"; };
key "K2" { algorithm hmac-sha256; secret "$S2"; };
zone "m.test" { type master; file "$W/m.zone"; allow-update { key "k1"; }; };
zone "n.test" { type master; file "$W/n.zone"; };
zone "p.test" { type master; file "$W/p.zone"; allow-update { 127.0.0.1; }; };
zone "ax.test" { type master; file "$W/ax.zone"; allow-transfer { key "k1"; }; };
zone "ay.test" { type master; file "$W/ay.zone"; allow-transfer { 192.0.2.99; key "k1"; }; };
zone "az.test" { type master; file "$W/az.zone"; allow-transfer { key "k2"; }; };
zone "sec.test" { type slave; masters { 127.0.0.1 port 9; }; file "$W/sec.bak"; tsig-key "k1"; };
EOF

cat > "$W/secondary.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
key "k1" { algorithm hmac-sha256; secret "$S1"; };
zone "ax.test" { type slave; masters { 127.0.0.1 port $PPORT; }; file "$W/ax.bak"; tsig-key "k1"; };
EOF

"$BIN" -f "$W/primary.conf" > "$W/primary.log" 2>&1 &
PRIMARY_PID=$!
sleep 2
kill -0 "$PRIMARY_PID" 2>/dev/null || fail "primary did not start"

# q <args...>: run dag against the primary, output in out.txt
q() {
    "$DAG" @127.0.0.1 -p $PPORT +nohexdump "$@" > "$W/out.txt" 2>&1 || true
}
# q_xfr: like q for a zone transfer. dag prints a refused transfer like dig ("; Transfer failed." after the
# records, no header), so the RCODE is taken from a second run with +yaml, appended to out.txt
q_xfr() {
    q "$@"
    "$DAG" @127.0.0.1 -p $PPORT +nohexdump +yaml "$@" >> "$W/out.txt" 2>&1 || true
}
upd() { # <zone> <key spec or ""> ; adds x.<zone> A
    z=$1; k=$2
    q "$z" ${k:+-y hmac-sha256:$k} --update-add "x.$z 300 IN A 192.0.2.9"
}
expect_status() {
    grep -qE "status: $1(,|$)" "$W/out.txt" || fail "$2: expected status $1"
}
# expect_tsig <owner> <error> <macsize> <what>: the response's TSIG RR (owner is compared case-insensitively)
expect_tsig() {
    got=$(awk '$3 == "ANY" && $4 == "TSIG" {
                 n = 9; if ($8 > 0) n = 10;
                 printf "%s %s %s\n", tolower($1), $(n + 1), $8 }' "$W/out.txt")
    [ "$got" = "$1 $2 $3" ] || fail "$4: expected TSIG '$1 $2 $3', got '$got'"
}
expect_no_tsig() {
    grep -q "ANY[[:space:]]*TSIG" "$W/out.txt" && fail "$1: unexpected TSIG RR"
    return 0
}
expect_verified() {
    grep -q "Couldn't verify" "$W/out.txt" && fail "$1: dag could not verify the response TSIG"
    return 0
}

# ---- UPDATE (R-30 table)
upd m.test "k1:$S1"
expect_status NOERROR "UPDATE m.test k1"; expect_tsig k1. NOERROR 32 "UPDATE m.test k1"; expect_verified "UPDATE m.test k1"
upd m.test "K2:$S2"
expect_status REFUSED "UPDATE m.test K2"; expect_tsig k2. NOERROR 32 "UPDATE m.test K2"; expect_verified "UPDATE m.test K2"
upd m.test "k3:$S2"
expect_status NOTAUTH "UPDATE m.test unknown key"; expect_tsig k3. BADKEY 0 "UPDATE m.test unknown key"
upd m.test "k1:$BAD"
expect_status NOTAUTH "UPDATE m.test bad secret"; expect_tsig k1. BADSIG 0 "UPDATE m.test bad secret"
upd n.test "k1:$S1"
expect_status REFUSED "UPDATE n.test"; expect_tsig k1. NOERROR 32 "UPDATE n.test"; expect_verified "UPDATE n.test"
upd p.test "K2:$S2"
expect_status NOERROR "UPDATE p.test K2"; expect_tsig k2. NOERROR 32 "UPDATE p.test K2"; expect_verified "UPDATE p.test K2"
upd p.test ""
expect_status NOERROR "UPDATE p.test unsigned"; expect_no_tsig "UPDATE p.test unsigned"
echo "[OK] UPDATE: TSIG errors NOTAUTH (unsigned), denials REFUSED (signed with the request key)"

# ---- AXFR (R-07, R-10)
q ax.test AXFR -y "hmac-sha256:k1:$S1"
grep -q "^www\.ax\.test\." "$W/out.txt" || fail "AXFR ax.test k1: no zone data"
expect_verified "AXFR ax.test k1"
q_xfr ax.test AXFR -y "hmac-sha256:k1:$BAD"
expect_status NOTAUTH "AXFR bad secret"; expect_tsig k1. BADSIG 0 "AXFR bad secret"
q_xfr ax.test AXFR -y "hmac-sha256:k3:$S1"
expect_status NOTAUTH "AXFR unknown key"; expect_tsig k3. BADKEY 0 "AXFR unknown key"
q_xfr ax.test AXFR -y "hmac-sha256:k1:$S1" +fuzztime=1646972129
expect_status NOTAUTH "AXFR stale time"; expect_tsig k1. BADTIME 32 "AXFR stale time"
# R-08: Time Signed is the client's time, Other Len 6 (server time)
grep -qE "ANY[[:space:]]+TSIG[[:space:]]+hmac-sha256\.[[:space:]]+1646972129[[:space:]]+300[[:space:]]+32[[:space:]].*BADTIME[[:space:]]+6[[:space:]]" "$W/out.txt" \
    || fail "AXFR stale time: BADTIME response must carry the client's Time Signed and Other Len 6"
q_xfr ay.test AXFR -y "hmac-sha256:k1:$S1"
expect_status REFUSED "AXFR ay.test (address not allowed)"; expect_tsig k1. NOERROR 32 "AXFR ay.test"
expect_verified "AXFR ay.test"
q_xfr ax.test AXFR
expect_status REFUSED "AXFR unsigned"; expect_no_tsig "AXFR unsigned"
# D-03: allow-transfer { key "k2"; } names the key defined as "K2"
q az.test AXFR -y "hmac-sha256:k2:$S2"
grep -q "^www\.az\.test\." "$W/out.txt" || fail "AXFR az.test k2 (D-03): no zone data"
expect_verified "AXFR az.test k2"
echo "[OK] AXFR: BADSIG/BADKEY unsigned, BADTIME signed, REFUSED signed, key names case-insensitive"

# ---- NOTIFY (sec.test: masters 127.0.0.1, tsig-key k1)
q sec.test SOA +opcode=NOTIFY -y "hmac-sha256:k1:$S1"
expect_status NOERROR "NOTIFY k1"; expect_tsig k1. NOERROR 32 "NOTIFY k1"; expect_verified "NOTIFY k1"
q sec.test SOA +opcode=NOTIFY -y "hmac-sha256:K2:$S2"
expect_status REFUSED "NOTIFY K2"; expect_tsig k2. NOERROR 32 "NOTIFY K2"; expect_verified "NOTIFY K2"
q sec.test SOA +opcode=NOTIFY -y "hmac-sha256:k3:$S1"
expect_status NOTAUTH "NOTIFY unknown key"; expect_tsig k3. BADKEY 0 "NOTIFY unknown key"
q sec.test SOA +opcode=NOTIFY
expect_status REFUSED "NOTIFY unsigned"; expect_no_tsig "NOTIFY unsigned"
echo "[OK] NOTIFY"

# ---- plain QUERY (RFC 8945 §5.2, §5.3)
q www.m.test A -y "hmac-sha256:k1:$S1"
expect_status NOERROR "signed QUERY"; expect_tsig k1. NOERROR 32 "signed QUERY"; expect_verified "signed QUERY"
grep -q "^www\.m\.test\..*192\.0\.2\.10" "$W/out.txt" || fail "signed QUERY: no answer"
q www.m.test A -y "hmac-sha256:k1:$S1" +tcp
expect_status NOERROR "signed QUERY over TCP"; expect_tsig k1. NOERROR 32 "signed QUERY over TCP"
expect_verified "signed QUERY over TCP"
q www.m.test A -y "hmac-sha256:k1:$BAD"
expect_status NOTAUTH "signed QUERY bad secret"; expect_tsig k1. BADSIG 0 "signed QUERY bad secret"
grep -q "^www\.m\.test\..*192\.0\.2\.10" "$W/out.txt" && fail "signed QUERY bad secret: answer returned"
echo "[OK] QUERY"

# ---- KariDNS secondary with tsig-key transfers from the primary
"$BIN" -f "$W/secondary.conf" > "$W/secondary.log" 2>&1 &
SECONDARY_PID=$!
i=0
while :; do
    "$DAG" @127.0.0.1 -p $SPORT +nohexdump www.ax.test A > "$W/out.txt" 2>&1 || true
    grep -q "status: NOERROR," "$W/out.txt" && grep -q "192\.0\.2\.10" "$W/out.txt" && break
    i=$((i + 1))
    [ $i -le 20 ] || fail "secondary did not transfer ax.test with TSIG"
    sleep 1
done
echo "[OK] secondary transfer with tsig-key"

check_asan_log
kill -0 "$PRIMARY_PID" 2>/dev/null || fail "primary exited"
echo "[PASS] TSIG error matrix"
exit 0
