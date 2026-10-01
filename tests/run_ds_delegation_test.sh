#!/bin/sh
# run_ds_delegation_test.sh - DS at a delegation point (RFC 4035 §3.1.4.1, R-32).
#
# The DS RRset exists only on the parent side of a zone cut (RFC 4035 §3.1.4.1, §3.1.5).
#   1. Parent only: DS queries at the delegation point are authoritative answers from the parent (DS, or NODATA
#      with the parent's SOA and, with DO=1, the parent's NSEC for the name); NS queries and names below the cut
#      are referrals (AA=0).
#   2. Parent and children on the same server: DS for the child apex still comes from the parent (not NODATA from
#      the child's apex), also after a CNAME and for repeated DO=0 queries (wire cache); other types at the child
#      apex come from the child.
#   3. Child only: the child answers authoritatively with NODATA from its apex (§3.1.4.1, server not authoritative
#      for the parent).
# The parent carries NSEC records and placeholder RRSIGs (the server serves pre-signed data and never validates),
# so no DNSSEC tools are needed.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG="$ROOT/dag"

[ -x "$ROOT/karidns" ] && [ -x "$ROOT/dag" ] || {
    echo "[*] Building targets..."
    [ -x "$ROOT/karidns" ] && [ -x "$ROOT/dag" ] || make -C "$ROOT" karidns dag
}

W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-dsdeleg.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
PID1=""
PID2=""
PID3=""

cleanup() {
    echo "[*] Cleaning up test processes..."
    kari_kill_tree "$PID1" "$PID2" "$PID3"
    kari_kill_conf "$W/parent.conf" "$W/both.conf" "$W/child.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    for f in "$W"/*.log; do [ -s "$f" ] && { echo "=== $f ==="; tail -n 20 "$f"; }; done
    exit 1
}

SIG="20300101000000 20200101000000 12345 example.com. AAAAAAAA"
cat > "$W/example.com.zone" << EOF
\$ORIGIN example.com.
\$TTL 3600
@           IN SOA   ns1.example.com. hostmaster.example.com. 2026082401 7200 3600 1209600 3600
@           IN RRSIG SOA 13 2 3600 $SIG
@           IN NS    ns1.example.com.
@           IN RRSIG NS 13 2 3600 $SIG
@           IN NSEC  insecure.example.com. NS SOA RRSIG NSEC
@           IN RRSIG NSEC 13 2 3600 $SIG
ns1         IN A     127.0.0.1
ns1         IN RRSIG A 13 3 3600 $SIG
ns1         IN NSEC  secure.example.com. A RRSIG NSEC
ns1         IN RRSIG NSEC 13 3 3600 $SIG

; 1. Secure delegation point (NS + DS)
secure      IN NS    ns1.secure.example.com.
secure      IN DS    12345 13 2 2BB1834370273412E81E3272C18B868FD63804EB61A086C38D04FF2DEDFE2516
secure      IN RRSIG DS 13 3 3600 $SIG
secure      IN NSEC  example.com. NS DS RRSIG NSEC
secure      IN RRSIG NSEC 13 3 3600 $SIG
ns1.secure  IN A     192.0.2.53

; 2. Insecure delegation point (NS only, no DS)
insecure    IN NS    ns1.insecure.example.com.
insecure    IN NSEC  ns1.example.com. NS RRSIG NSEC
insecure    IN RRSIG NSEC 13 3 3600 $SIG
ns1.insecure IN A    192.0.2.54
EOF
for c in secure insecure; do
    cat > "$W/$c.example.com.zone" << EOF
\$ORIGIN $c.example.com.
\$TTL 3600
@           IN SOA   ns1.$c.example.com. child-hostmaster.$c.example.com. 7 7200 3600 1209600 300
@           IN NS    ns1.$c.example.com.
ns1         IN A     192.0.2.53
EOF
done
cat > "$W/other.example.zone" << EOF
\$ORIGIN other.example.
\$TTL 3600
@           IN SOA   ns1.other.example. hostmaster.other.example. 1 7200 3600 1209600 300
@           IN NS    ns1.other.example.
ns1         IN A     192.0.2.9
alias       IN CNAME secure.example.com.
EOF
chmod 644 "$W"/*.zone

# conf NAME PORT ZONE...: one master zone per argument
conf() {
    _name=$1; _port=$2; shift 2
    {
        echo "options { port $_port; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
        for _z in "$@"; do echo "zone \"$_z\" { type master; file \"$W/$_z.zone\"; };"; done
    } > "$W/$_name.conf"
}
conf parent 10053 example.com
conf both 10058 example.com secure.example.com insecure.example.com other.example
conf child 10059 secure.example.com

echo "[*] Starting KariDNS on ports 10053 (parent), 10058 (parent + children), 10059 (child only)..."
$BIN -f -c "$W/parent.conf" > "$W/parent.log" 2>&1 &
PID1=$!
$BIN -f -c "$W/both.conf" > "$W/both.log" 2>&1 &
PID2=$!
$BIN -f -c "$W/child.conf" > "$W/child.log" 2>&1 &
PID3=$!

for p in 10053 10058 10059; do
    i=0
    until $DAG SOA example.com @127.0.0.1 -p $p +short +nohexdump +tries=1 +time=1 2>/dev/null | grep -q hostmaster ||
          $DAG SOA secure.example.com @127.0.0.1 -p $p +short +nohexdump +tries=1 +time=1 2>/dev/null | grep -q hostmaster; do
        i=$((i + 1)); [ $i -le 40 ] || fail "karidns on port $p did not start"; sleep 0.25
    done
done

# q PORT NAME TYPE [options]
q() {
    _p=$1; shift
    $DAG "$@" @127.0.0.1 -p "$_p" +nohexdump +norec
}
# section NAME: the RR lines of one section of the output on stdin
section() {
    awk -v s=";; $1 SECTION:" '$0 == s { on = 1; next } /^;; / || /^$/ { on = 0 } on && !/^;/'
}

# ---------------------------------------------------------------------------------------------------------------
# 1. Parent only
echo "[*] Querying DS secure.example.com (RFC 4035 §3.1.4.1 authoritative response)..."
DS_OUT=$(q 10053 DS secure.example.com +dnssec)
echo "$DS_OUT"
echo "$DS_OUT" | grep -q "flags:.*aa" || fail "AA flag was NOT set for delegation point DS query"
echo "$DS_OUT" | section ANSWER | grep -Eq "^secure\.example\.com\.[[:space:]].*IN[[:space:]]+DS[[:space:]]+12345 " ||
    fail "Answer section did not contain the DS record"
echo "$DS_OUT" | section ANSWER | grep -Eq "IN[[:space:]]+RRSIG[[:space:]]+DS " || fail "DS answer without RRSIG(DS)"

echo "[*] Querying NS secure.example.com (referral response)..."
NS_OUT=$(q 10053 NS secure.example.com)
echo "$NS_OUT"
echo "$NS_OUT" | grep -q "flags:.*aa" && fail "AA flag was incorrectly set for NS referral query"
echo "$NS_OUT" | section AUTHORITY | grep -Eq "^secure\.example\.com\..*IN[[:space:]]+NS[[:space:]]+ns1\.secure\.example\.com" ||
    fail "Authority section did not contain delegation NS record"

echo "[*] Querying A host.secure.example.com (referral response)..."
SUB_OUT=$(q 10053 A host.secure.example.com)
echo "$SUB_OUT"
echo "$SUB_OUT" | grep -q "status: NOERROR" || fail "referral is not NOERROR"
echo "$SUB_OUT" | grep -q "flags:.*aa" && fail "AA flag was incorrectly set for sub-zone referral"

echo "[*] Querying DS insecure.example.com (NODATA authoritative response)..."
INSEC_OUT=$(q 10053 DS insecure.example.com +dnssec)
echo "$INSEC_OUT"
echo "$INSEC_OUT" | grep -q "flags:.*aa" || fail "AA flag was NOT set for insecure delegation DS NODATA query"
echo "$INSEC_OUT" | grep -q "status: NOERROR" || fail "DS NODATA is not NOERROR"
# §3b: the SOA must be the parent's (owner example.com.), and the parent's NSEC for the name proves "no DS"
echo "$INSEC_OUT" | section AUTHORITY | grep -Eq "^example\.com\.[[:space:]].*IN[[:space:]]+SOA[[:space:]]+ns1\.example\.com\. " ||
    fail "DS NODATA without the parent's SOA"
echo "$INSEC_OUT" | section AUTHORITY | grep -Eq "^insecure\.example\.com\.[[:space:]].*IN[[:space:]]+NSEC[[:space:]]" ||
    fail "DS NODATA without the parent's NSEC for insecure.example.com"
[ -z "$(echo "$INSEC_OUT" | section ANSWER)" ] || fail "DS NODATA has an Answer"

# ---------------------------------------------------------------------------------------------------------------
# 2. Parent and children on one server (R-32)
echo "[*] Parent and children on one server: DS secure.example.com..."
for do_bit in +dnssec +nodnssec +nodnssec; do   # DO=0 twice: the second answer may come from the wire cache
    OUT=$(q 10058 DS secure.example.com $do_bit)
    echo "$OUT" | grep -q "flags:.*aa" || { echo "$OUT"; fail "($do_bit) DS for the child apex: AA not set"; }
    echo "$OUT" | section ANSWER | grep -Eq "^secure\.example\.com\.[[:space:]].*IN[[:space:]]+DS[[:space:]]+12345 " ||
        { echo "$OUT"; fail "($do_bit) DS for the child apex not answered from the parent"; }
    echo "$OUT" | grep -q "child-hostmaster" && { echo "$OUT"; fail "($do_bit) DS answered from the child zone"; }
done
OUT=$(q 10058 DS secure.example.com +dnssec)
echo "$OUT" | section ANSWER | grep -Eq "IN[[:space:]]+RRSIG[[:space:]]+DS " || { echo "$OUT"; fail "DS from the parent without RRSIG(DS)"; }

echo "[*] Parent and children on one server: DS insecure.example.com..."
OUT=$(q 10058 DS insecure.example.com +dnssec)
echo "$OUT"
echo "$OUT" | grep -q "status: NOERROR" || fail "DS insecure: not NOERROR"
echo "$OUT" | section AUTHORITY | grep -Eq "^example\.com\.[[:space:]].*IN[[:space:]]+SOA[[:space:]]+ns1\.example\.com\. " ||
    fail "DS insecure: NODATA without the parent's SOA (answered from the child?)"
echo "$OUT" | section AUTHORITY | grep -Eq "^insecure\.example\.com\.[[:space:]].*IN[[:space:]]+NSEC[[:space:]]" ||
    fail "DS insecure: NODATA without the parent's NSEC"
echo "$OUT" | grep -q "child-hostmaster" && fail "DS insecure answered from the child zone"

echo "[*] Parent and children on one server: other types and CNAME..."
OUT=$(q 10058 SOA secure.example.com)
echo "$OUT" | section ANSWER | grep -q "child-hostmaster" || { echo "$OUT"; fail "SOA at the child apex must come from the child"; }
OUT=$(q 10058 NS secure.example.com)
echo "$OUT" | grep -q "flags:.*aa" || { echo "$OUT"; fail "NS at the child apex must be the child's authoritative answer"; }
OUT=$(q 10058 DS alias.other.example +dnssec)
echo "$OUT" | section ANSWER | grep -Eq "^alias\.other\.example\..*IN[[:space:]]+CNAME[[:space:]]+secure\.example\.com\." ||
    { echo "$OUT"; fail "DS via CNAME: CNAME missing"; }
echo "$OUT" | section ANSWER | grep -Eq "^secure\.example\.com\.[[:space:]].*IN[[:space:]]+DS[[:space:]]+12345 " ||
    { echo "$OUT"; fail "DS via CNAME not answered from the parent"; }

# ---------------------------------------------------------------------------------------------------------------
# 3. Child only: authoritative NODATA from the child apex
echo "[*] Child only: DS secure.example.com..."
OUT=$(q 10059 DS secure.example.com +dnssec)
echo "$OUT"
echo "$OUT" | grep -q "flags:.*aa" || fail "child only: AA not set"
echo "$OUT" | grep -q "status: NOERROR" || fail "child only: not NOERROR"
echo "$OUT" | section AUTHORITY | grep -Eq "^secure\.example\.com\.[[:space:]].*IN[[:space:]]+SOA[[:space:]].*child-hostmaster" ||
    fail "child only: NODATA without the child's SOA"
[ -z "$(echo "$OUT" | section ANSWER)" ] || fail "child only: DS NODATA has an Answer"

echo "[PASS] Delegation point DS queries and NS referrals correctly handled according to RFC 4035 §3.1.4.1!"
exit 0
