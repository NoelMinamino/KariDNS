#!/bin/sh
# run_dnssec_answer_sections_test.sh - DNSSEC answer assembly on zones signed with dnssec-signzone (phase 9:
# R-03, R-04, O-16, O-17, R-31, R-32).
#
# RFC 4035 §3.1.1: a signed RRset in the Answer, Authority or Additional section is followed by its RRSIGs (glue
# below a zone cut is not signed, §2.2). RFC 2181 §5: an RRset holds no duplicate RR; each RRset is returned
# as one unit (the answer lists all RRs of an RRset, then its RRSIGs). RFC 4035 §3.1.4.1: a DS query for the apex
# of a hosted child is answered from the hosted parent. RFC 5155: salts of up to 255 octets (§3.1.5); NSEC3PARAM
# with Flags != 0 are ignored (§4.1.2); with several NSEC3PARAMs one chain is chosen (§7.3) and every NSEC3 RR
# of an answer belongs to it (§7.2).
#
# Zones:
#   an.test    NSEC; wildcard, DNAME, MX/NS targets inside the zone, a secure (sec) and an insecure (ins)
#              delegation whose child zones sec.an.test / ins.an.test are served by the same server,
#              and a delegation (far) whose child is not served (referral with DS and glue).
#   s255.test  NSEC3 with a 255-octet salt.
#   two.test   two complete NSEC3 chains (salts AA11 and BB22, as during a salt change) plus an NSEC3PARAM with
#              Flags 1 listed first; the BB22 NSEC3PARAM comes before the AA11 one, so BB22 must be used.
# Checks: the RRs of each section (RRSIGs present, grouping, no duplicates), NSEC3 owners and salts against
# nsec3hash, and, when delv is installed, that every answer validates with the zone's KSK as trust anchor.
#
# Needs dnssec-keygen, dnssec-signzone and nsec3hash; SKIP otherwise. delv is optional (reported when missing).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"

echo "=== DNSSEC answer sections, NSEC3 parameters, DS from the parent (R-03, R-04, O-16, O-17, R-31, R-32) ==="
for t in dnssec-keygen dnssec-signzone nsec3hash; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] $t is not installed"
        exit 0
    fi
done
HAVE_DELV=0
command -v delv >/dev/null 2>&1 && HAVE_DELV=1

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PORT=15521
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-dnssecans.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
SERVER_PID=""

cleanup() {
    kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$W/k.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    [ -s "$W/server.log" ] && { echo "=== server.log ==="; tail -n 40 "$W/server.log"; }
    exit 1
}

SALT255=$(awk 'BEGIN { for (i = 0; i < 255; i++) printf "CD" }')

# keys ZONE: KSK + ZSK in $W (ECDSAP256SHA256)
keys() {
    ( cd "$W" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$1" >/dev/null 2>&1 &&
                 dnssec-keygen -q -a ECDSAP256SHA256 "$1" >/dev/null 2>&1 )
}
# sign ZONE OUT [dnssec-signzone options]: one RR per line (-O full)
sign() {
    _z=$1; _o=$2; shift 2
    ( cd "$W" && dnssec-signzone -q -S -K . -O full "$@" -o "$_z" -f "$_o" "$_z.zone" >/dev/null 2>&1 &&
      chmod 644 "$_o" )
}

cat > "$W/an.test.zone" <<'EOF'
$TTL 300
$ORIGIN an.test.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
ns1 IN AAAA 2001:db8::1
www IN A 192.0.2.10
www IN AAAA 2001:db8::10
www IN TXT "www"
mail IN MX 10 www
*.wild IN A 192.0.2.20
*.wild IN TXT "wild"
dn IN DNAME www.an.test.
sec IN NS ns.sec
sec IN DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.sec IN A 192.0.2.50
ins IN NS ns.ins
ns.ins IN A 192.0.2.60
far IN NS ns.far
far IN DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.far IN A 192.0.2.70
EOF
for c in sec ins; do
    cat > "$W/$c.an.test.zone" <<EOF
\$TTL 300
\$ORIGIN $c.an.test.
@ IN SOA ns $c-hostmaster 7 3600 600 86400 60
@ IN NS ns
ns IN A 192.0.2.50
EOF
    chmod 644 "$W/$c.an.test.zone"
done
for z in s255.test two.test; do
    cat > "$W/$z.zone" <<EOF
\$TTL 300
\$ORIGIN $z.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
*.wild IN A 192.0.2.20
EOF
done

for z in an.test s255.test two.test; do
    for k in $(keys "$z" && ls "$W"/K"$z".+*.key); do
        echo "\$INCLUDE $k" >> "$W/$z.zone"
    done
done
sign an.test an.test.signed || { echo "[SKIP] dnssec-signzone failed (NSEC)"; exit 0; }
sign s255.test s255.test.signed -3 "$SALT255" -H 0 || { echo "[SKIP] dnssec-signzone refused a 255-octet salt"; exit 0; }
sign two.test two.aa -3 AA11 -H 0 || { echo "[SKIP] dnssec-signzone failed (two.test)"; exit 0; }
sign two.test two.bb -3 BB22 -H 0 || { echo "[SKIP] dnssec-signzone failed (two.test)"; exit 0; }
# two complete chains (the AA11 zone plus the BB22 chain and its NSEC3PARAM), an NSEC3PARAM with Flags 1 first
{
    echo "two.test. 300 IN NSEC3PARAM 1 1 0 CC33"
    awk '$4 == "NSEC3PARAM"' "$W/two.bb"
    cat "$W/two.aa"
    awk '$4 == "NSEC3" || ($4 == "RRSIG" && $5 == "NSEC3")' "$W/two.bb"
} > "$W/two.test.signed"
chmod 644 "$W/two.test.signed"

# trust anchors for delv: the KSK of each zone
for z in an.test s255.test two.test; do
    awk -v z="$z." '/^;/ { next } { for (d = 1; d <= NF && $d != "DNSKEY"; d++); }
                     d < NF && $(d + 1) == 257 { k = ""; for (i = d + 4; i <= NF; i++) k = k $i;
                     printf "trust-anchors { \"%s\" static-key 257 %s %s \"%s\"; };\n", z, $(d + 2), $(d + 3), k }' \
        "$W"/K"$z".+*.key
done > "$W/anchors.conf"

cat > "$W/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "an.test" { type master; file "$W/an.test.signed"; };
zone "sec.an.test" { type master; file "$W/sec.an.test.zone"; };
zone "ins.an.test" { type master; file "$W/ins.an.test.zone"; };
zone "s255.test" { type master; file "$W/s255.test.signed"; };
zone "two.test" { type master; file "$W/two.test.signed"; };
EOF

if "$DAG" an.test SOA @127.0.0.1 -p $PORT +short +nohexdump +tries=1 +time=1 >/dev/null 2>&1; then
    fail "something already answers on 127.0.0.1 port $PORT"
fi
"$BIN" -f "$W/k.conf" > "$W/server.log" 2>&1 &
SERVER_PID=$!
i=0
until "$DAG" two.test SOA @127.0.0.1 -p $PORT +short +nohexdump +tries=1 +time=1 2>/dev/null | grep -q hostmaster; do
    i=$((i + 1)); [ $i -le 40 ] || fail "karidns did not start"; sleep 0.25
done

# ask NAME TYPE [dag options]: DO=1 answer; "SECTION owner ttl class type rdata" per RR, in message order, and
# the header and flags lines. The proofs of s255.test (255-octet salts) do not fit in 1232 octets: TCP there.
ask() {
    _n=$1; _t=$2; shift 2
    case "$_n" in *s255.test) set -- +tcp "$@" ;; esac
    "$DAG" "$_n" "$_t" @127.0.0.1 -p $PORT +dnssec +norec +nohexdump "$@" 2>&1 | awk '
        /->>HEADER<<-/ { print "HEADER " $0; next }
        /^;; flags:/ { print "FLAGS " $0; next }
        /^;; [A-Z]+ SECTION:/ { sec = $2; next }
        /^;/ || /^$/ { next }
        sec != "" { $1 = $1; print sec " " $0 }'
}

# grouped NAME TYPE: in every section each RRset is contiguous, its RRSIGs follow it, no RR appears twice
grouped() {
    ask "$1" "$2" > "$W/g.txt"
    awk '$1 == "ANSWER" || $1 == "AUTHORITY" || $1 == "ADDITIONAL" {
            if (seen[$0]++) { print "duplicate: " $0; bad = 1 }
            if ($5 == "RRSIG") {
                if (cur[$1] != $2 "|" $6) { print "RRSIG not after its RRset: " $0; bad = 1 }
            } else {
                k = $2 "|" $5
                if (cur[$1] != k || last[$1] == "RRSIG") {
                    if (done[$1 "|" k]++) { print "split RRset: " $0; bad = 1 }
                    cur[$1] = k
                }
            }
            last[$1] = $5
         } END { exit bad }' "$W/g.txt" > "$W/g.err" || { cat "$W/g.txt" "$W/g.err"; fail "$1 $2: RRsets not grouped"; }
}

# has NAME TYPE PATTERN WHAT / hasnot NAME TYPE PATTERN WHAT (extended regex on the ask() lines)
has() {
    ask "$1" "$2" > "$W/h.txt"
    grep -q "^FLAGS" "$W/h.txt" || fail "$4: no answer"
    grep -Eq "$3" "$W/h.txt" || { cat "$W/h.txt"; fail "$4"; }
}
hasnot() {
    ask "$1" "$2" > "$W/h.txt"
    grep -q "^FLAGS" "$W/h.txt" || fail "$4: no answer"
    ! grep -Eq "$3" "$W/h.txt" || { cat "$W/h.txt"; fail "$4"; }
}
count() {
    ask "$1" "$2" | grep -Ec "$3" || true
}

# --- R-03: RRSIGs in the Authority and Additional sections ---
has www.an.test A '^AUTHORITY an\.test\. [0-9]+ IN RRSIG NS ' "www A: Authority NS without RRSIG(NS)"
has mail.an.test MX '^ADDITIONAL www\.an\.test\. [0-9]+ IN RRSIG A ' "mail MX: Additional www A without RRSIG(A)"
has mail.an.test MX '^ADDITIONAL www\.an\.test\. [0-9]+ IN RRSIG AAAA ' "mail MX: Additional www AAAA without RRSIG(AAAA)"
has www.an.test A '^ADDITIONAL ns1\.an\.test\. [0-9]+ IN RRSIG A ' "www A: Additional ns1 A without RRSIG(A)"
has www.far.an.test A '^AUTHORITY far\.an\.test\. [0-9]+ IN RRSIG DS ' "referral: no RRSIG(DS)"
has www.far.an.test A '^ADDITIONAL ns\.far\.an\.test\. [0-9]+ IN A ' "referral: glue missing"
hasnot www.far.an.test A '^ADDITIONAL .* RRSIG ' "referral: glue below the cut must not be signed"
hasnot www.an.test A '^FLAGS .* tc' "www A: TC set"
echo "[OK] R-03: RRSIGs in Authority and Additional; glue unsigned"

# --- R-04 / O-16 / O-17: grouping, no duplicates ---
for q in "www.an.test ANY" "ns1.an.test ANY" "an.test DNSKEY" "an.test ANY" "a.wild.an.test ANY" \
         "a.wild.an.test MX" "nx.an.test A" "www.an.test A" "mail.an.test MX" "x.dn.an.test A" "www.far.an.test A" \
         "nx.s255.test A" "a.wild.s255.test MX" "nx.two.test A"; do
    grouped $q
done
n=$(count www.an.test ANY '^ANSWER [^ ]+ [0-9]+ IN RRSIG ')
[ "$n" = 4 ] || { ask www.an.test ANY; fail "www ANY: $n RRSIGs in the Answer, expected 4 (A, AAAA, TXT, NSEC)"; }
n=$(count a.wild.an.test MX '^AUTHORITY \*\.wild\.an\.test\. [0-9]+ IN NSEC ')
[ "$n" = 1 ] || { ask a.wild.an.test MX; fail "wildcard NODATA: $n copies of the *.wild NSEC, expected 1"; }
echo "[OK] R-04, O-16, O-17: RRsets contiguous, RRSIGs after their RRset, no duplicates"

# --- R-32: DS at a child apex from the hosted parent ---
has sec.an.test DS '^ANSWER sec\.an\.test\. [0-9]+ IN DS 12345 ' "sec DS: no DS from the parent"
has sec.an.test DS '^ANSWER sec\.an\.test\. [0-9]+ IN RRSIG DS ' "sec DS: no RRSIG(DS)"
has ins.an.test DS '^AUTHORITY an\.test\. [0-9]+ IN SOA ' "ins DS: NODATA without the parent's SOA"
has ins.an.test DS '^AUTHORITY ins\.an\.test\. [0-9]+ IN NSEC ' "ins DS: NODATA without the parent's NSEC"
hasnot ins.an.test DS 'ins-hostmaster' "ins DS: answered from the child"
has sec.an.test SOA '^ANSWER sec\.an\.test\. [0-9]+ IN SOA ns\.sec\.an\.test\. ' "sec SOA: must still come from the child"
echo "[OK] R-32: DS from the parent (DS + RRSIG, or NODATA with the parent's SOA and NSEC)"

# --- R-31: NSEC3 parameters ---
# n3check NAME TYPE ZONE SALT CE: every NSEC3 in the Authority has SALT, and the NSEC3 matching the closest
# encloser CE (hash from nsec3hash) is there
n3check() {
    ask "$1" "$2" > "$W/n.txt"
    grep -q "^AUTHORITY .* NSEC3 " "$W/n.txt" || { cat "$W/n.txt"; fail "$1 $2: no NSEC3 proof"; }
    awk -v s="$4" '$1 == "AUTHORITY" && $5 == "NSEC3" && toupper($9) != s { print; bad = 1 } END { exit bad }' \
        "$W/n.txt" || fail "$1 $2: NSEC3 from another chain (salt must be $4)"
    h=$(nsec3hash "$4" 1 0 "$5" | awk '{ print $1 }')
    grep -Eiq "^AUTHORITY $h\.$3\. [0-9]+ IN NSEC3 " "$W/n.txt" || { cat "$W/n.txt"; fail "$1 $2: closest-encloser NSEC3 $h missing"; }
}
n3check nx.s255.test A s255.test "$SALT255" s255.test
n3check a.wild.s255.test MX s255.test "$SALT255" wild.s255.test
n3check nx.two.test A two.test BB22 two.test
n3check a.wild.two.test MX two.test BB22 wild.two.test
# over UDP the proof does not fit: it is left out and TC is set (RFC 4035 §3.1.1, not an unsigned-looking NXDOMAIN)
ask nx.s255.test A +notcp +ignore > "$W/u.txt"
grep -Eq '^FLAGS .* tc' "$W/u.txt" && ! grep -q ' NSEC3 ' "$W/u.txt" || { cat "$W/u.txt"; fail "nx.s255.test over UDP: expected TC=1 without a partial proof"; }
grep -q "using NSEC3PARAM 1 0 0 BB22 (2 usable of 3; chain complete)" "$W/server.log" ||
    fail "two.test: the NSEC3PARAM choice was not logged as expected"
echo "[OK] R-31: 255-octet salt; Flags 1 ignored; one chain (BB22) per answer"

# --- validation with delv (the zone KSKs as trust anchors) ---
if [ "$HAVE_DELV" = 1 ]; then
    nval=0
    while read -r zone name type; do
        [ -n "$zone" ] || continue
        out=$(delv @127.0.0.1 -p $PORT -a "$W/anchors.conf" +root="$zone" "$name" "$type" 2>&1 || true)
        echo "$out" | grep -q "fully validated" || { echo "$out"; fail "delv: $name $type does not validate"; }
        nval=$((nval + 1))
    done <<EOF
an.test www.an.test A
an.test mail.an.test MX
an.test an.test DNSKEY
an.test nx.an.test A
an.test a.wild.an.test A
an.test a.wild.an.test MX
an.test x.dn.an.test A
an.test sec.an.test DS
an.test ins.an.test DS
s255.test www.s255.test A
s255.test nx.s255.test A
s255.test a.wild.s255.test A
s255.test a.wild.s255.test MX
s255.test www.s255.test MX
two.test nx.two.test A
two.test a.wild.two.test A
two.test www.two.test MX
EOF
    echo "[OK] delv: $nval answers fully validated"
else
    echo "[NOTE] delv is not installed: validation of the answers not run"
fi

if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$W/server.log"; then
    fail "sanitizer report in the server log"
fi
echo "[PASS] run_dnssec_answer_sections_test.sh"
