#!/bin/sh
# ==============================================================================
# B8t-1: several / restricted apex SOA records (tinydns locations and time stamps, BIND $LOCATION tags)
#
# A zone may hold one SOA per client group (a tinydns "Z" line per location, a $LOCATION-tagged SOA). The SOA a client gets is
# the first one it can see (tdlookup.c); a client that sees none gets REFUSED, AA=0, EDE 18 (Prohibited), like BIND 9.20 for a
# client the zone is not served to (RFC 8914 s4.19); a standard AXFR is the zone as the requester sees it (axfrdns.c). All SOA
# records of a zone have one serial or the zone is not loaded (RFC 2181 s6.1).
#
# Clients are the loopback addresses 127.0.0.1 (location "in"), 127.0.0.2 ("ex") and 127.0.0.3 ("no"); 127.0.0.2/3 are added as
# aliases when run as root (the multi-source checks are SKIPped otherwise).
# Optional: DJBDNS_DIR=<dir with the built tinydns, tinydns-data, axfrdns> (root only) compares with djbdns 1.05.
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="$BIN_DIR/karidns"
KARICHECK="$BIN_DIR/karicheck"
KARICTL="$BIN_DIR/karictl"
DAG="${DAG:-$BIN_DIR/dag}"
PROBE="$SCRIPT_DIR/lib_axfr_probe.pl"
DJB="${DJBDNS_DIR:-}"

[ -x "$KARIDNS" ] && [ -x "$KARICHECK" ] && [ -x "$KARICTL" ] && [ -x "$DAG" ] || (cd "$BASE_DIR" && make karidns karicheck karictl dag) || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }

TMP_DIR="$(mktemp -d /tmp/karidns_soaloc.XXXXXX)"
chmod 755 "$TMP_DIR"
PORT=$(kari_port 0 $((31000 + $$ % 3000)))
SERVER_PID=""
DJB_PID=""
AXFRDNS_PID=""
ADDED=""
PASS=0
FAIL=0
SKIP=0
SRC_IN=127.0.0.1
SRC_EX=127.0.0.2
SRC_NO=127.0.0.3
DJB_IP=127.0.0.9

cleanup() {
    kari_kill_tree "${SERVER_PID:-}" "${DJB_PID:-}" "${AXFRDNS_PID:-}"
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; shift; for l in "$@"; do echo "       $l"; done; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP $1"; }

# expect NAME OUTPUT REGEX... : every REGEX must match the output (newlines folded to blanks)
expect() {
    _n="$1"; _o="$2"; shift 2
    _flat=$(printf '%s' "$_o" | tr '\n' ' ')
    for _re in "$@"; do
        if ! printf '%s' "$_flat" | grep -E -q -- "$_re"; then
            bad "$_n" "missing: $_re" "output: $(printf '%s' "$_o" | head -40)"
            return
        fi
    done
    ok "$_n"
}
# reject NAME OUTPUT REGEX : REGEX must not match (call expect on the same output first, an empty output would pass)
reject() {
    _flat=$(printf '%s' "$2" | tr '\n' ' ')
    if printf '%s' "$_flat" | grep -E -q -- "$3"; then
        bad "$1" "unexpected: $3" "output: $(printf '%s' "$2" | head -40)"
    else
        ok "$1"
    fi
}

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
    for ip in $SRC_EX $SRC_NO; do
        if ifconfig lo0 inet "$ip" netmask 255.0.0.0 alias 2>/dev/null; then ADDED="$ADDED $ip"; fi
    done
    [ -n "$DJB" ] && ifconfig lo0 inet "$DJB_IP" netmask 255.0.0.0 alias 2>/dev/null && ADDED="$ADDED $DJB_IP"
fi
MULTI=0
case "$ADDED" in *"$SRC_EX"*"$SRC_NO"*) MULTI=1 ;; esac
if [ "$MULTI" = 0 ]; then
    # not root: usable only if the addresses already exist
    if ifconfig lo0 2>/dev/null | grep -q "inet $SRC_EX " && ifconfig lo0 2>/dev/null | grep -q "inet $SRC_NO "; then MULTI=1; fi
fi

NOW=$(date +%s)
HEX_CD=$(printf '40000000%08x' $((NOW + 1800)))     # countdown (TTL 0): runs out in 30 minutes
HEX_PAST=400000003b9aca00                           # 2001
HEX_FUTURE=40000000b2d05e00                         # 2065: not yet active

# ------------------------------------------------------------------------------ data
cat > "$TMP_DIR/loc.data" <<EOF
%in:127.0.0.1
%ex:127.0.0.2
%no:127.0.0.3
Zloc.test:ns1.in.loc.test.:hostmaster.loc.test.:7:3600:900:604800:300:300::in
Zloc.test:ns1.ex.loc.test.:hostmaster.loc.test.:7:3600:900:604800:600:300::ex
&loc.test::ns1.loc.test:300
+ns1.loc.test:192.0.2.1:300
+www.loc.test:192.0.2.10:300
+inonly.loc.test:192.0.2.20:300::in
+exonly.loc.test:192.0.2.21:300::ex
EOF

# a countdown SOA (first, visible now), an expired one, and the SOA for everybody (the reference)
cat > "$TMP_DIR/tm.data" <<EOF
%in:127.0.0.1
%ex:127.0.0.2
Ztm.test:ns1.cd.tm.test.:hostmaster.tm.test.:9:3600:900:604800:300:0:${HEX_CD}:
Ztm.test:ns1.old.tm.test.:hostmaster.tm.test.:9:3600:900:604800:300:0:${HEX_PAST}:
Ztm.test:ns1.plain.tm.test.:hostmaster.tm.test.:9:3600:900:604800:300:300::
&tm.test::ns1.tm.test:300
+ns1.tm.test:192.0.2.1:300
+www.tm.test:192.0.2.30:300
+cd.tm.test:192.0.2.31:0:${HEX_CD}
EOF

# the only SOA is not active yet: nobody sees one
cat > "$TMP_DIR/late.data" <<EOF
Zlate.test:ns1.late.test.:hostmaster.late.test.:11:3600:900:604800:300:300:${HEX_FUTURE}:
&late.test::ns1.late.test:300
+www.late.test:192.0.2.60:300
EOF

# serial mismatch: the zone must not be loaded
cat > "$TMP_DIR/bad.data" <<EOF
%in:127.0.0.1
Zbad.test:ns1.a.bad.test.:hostmaster.bad.test.:1:3600:900:604800:300:300::in
Zbad.test:ns1.b.bad.test.:hostmaster.bad.test.:2:3600:900:604800:300:300:
&bad.test::ns1.bad.test:300
EOF

# BIND format: $LOCATION on the SOA (tags from options)
cat > "$TMP_DIR/bt.zone" <<'EOF'
$TTL 300
$ORIGIN bt.test.
$LOCATION lt-in
@ IN SOA ns1.in.bt.test. hostmaster.bt.test. ( 4 3600 900 604800 300 )
$LOCATION lt-ex
@ IN SOA ns1.ex.bt.test. hostmaster.bt.test. ( 4 3600 900 604800 600 )
$LOCATION none
@ IN NS ns1.bt.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.40
$LOCATION lt-in
inonly IN A 192.0.2.41
EOF

# parent / child: the child's SOA is visible to "in" only; "ex" must get REFUSED, not the parent's referral
cat > "$TMP_DIR/par.zone" <<'EOF'
$TTL 300
$ORIGIN par.test.
@ IN SOA ns1.par.test. hostmaster.par.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.par.test.
ns1 IN A 192.0.2.1
sub IN NS ns1.sub.par.test.
ns1.sub IN A 192.0.2.2
EOF
cat > "$TMP_DIR/sub.data" <<EOF
%in:127.0.0.1
Zsub.par.test:ns1.sub.par.test.:hostmaster.par.test.:1:3600:900:604800:300:300::in
&sub.par.test::ns1.sub.par.test:300
+www.sub.par.test:192.0.2.50:300
EOF

# a signed zone (plain SOA): reloaded with a tagged SOA it must be refused
cat > "$TMP_DIR/sg.zone" <<'EOF'
$TTL 300
$ORIGIN sg.test.
@ IN SOA ns1.sg.test. hostmaster.sg.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.sg.test.
@ IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
ns1 IN A 192.0.2.1
EOF

# a zone for the serial check at reload time
cat > "$TMP_DIR/mm.data" <<EOF
%in:127.0.0.1
%ex:127.0.0.2
Zmm.test:ns1.a.mm.test.:hostmaster.mm.test.:5:3600:900:604800:300:300::in
Zmm.test:ns1.b.mm.test.:hostmaster.mm.test.:5:3600:900:604800:300:300::ex
&mm.test::ns1.mm.test:300
EOF

SECRET=$(openssl rand -base64 32)
cat > "$TMP_DIR/k.conf" <<EOF
options {
    port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
    location-tags { tag "lt-in" { 127.0.0.1/32; }; tag "lt-ex" { 127.0.0.2/32; }; };
};
control-channel { socket "$TMP_DIR/c.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "loc.test" { type master; file "$TMP_DIR/loc.data"; file-format tinydns; allow-transfer { any; }; };
zone "tm.test" { type master; file "$TMP_DIR/tm.data"; file-format tinydns; allow-transfer { any; }; };
zone "late.test" { type master; file "$TMP_DIR/late.data"; file-format tinydns; allow-transfer { any; }; };
zone "bad.test" { type master; file "$TMP_DIR/bad.data"; file-format tinydns; };
zone "bt.test" { type master; file "$TMP_DIR/bt.zone"; allow-transfer { any; }; };
zone "par.test" { type master; file "$TMP_DIR/par.zone"; };
zone "sub.par.test" { type master; file "$TMP_DIR/sub.data"; file-format tinydns; };
zone "sg.test" { type master; file "$TMP_DIR/sg.zone"; };
zone "mm.test" { type master; file "$TMP_DIR/mm.data"; file-format tinydns; };
EOF
cp "$TMP_DIR/k.conf" "$TMP_DIR/c.conf"
chmod 600 "$TMP_DIR/c.conf"
chmod 644 "$TMP_DIR/k.conf" "$TMP_DIR"/*.data "$TMP_DIR"/*.zone

Q()  { "$DAG" "$2" "$3" @127.0.0.1 -p "$PORT" -b "$1" +nohexdump +time=2 +tries=1 2>&1; }
AX() { "$DAG" "$2" AXFR @127.0.0.1 -p "$PORT" -b "$1" +nohexdump +time=3 +tries=1 2>&1; }
# the RRs of an AXFR listing, without the TTL column, sorted (axfrdns and KariDNS differ in order)
rrset() { printf '%s\n' "$1" | grep -E '[[:space:]]IN[[:space:]]' | awk '{ $2 = ""; print }' | sort; }

# ------------------------------------------------------------------------------ 1. karicheck
echo "=== 1. karicheck ==="
printf 'zone "loc.test" { type master; file "%s/loc.data"; file-format tinydns; };\n' "$TMP_DIR" > "$TMP_DIR/kc1.conf"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc1.conf" 2>&1); RC=$?
[ "$RC" = 0 ] && ok "karicheck: per-location SOA records with one serial are valid" || bad "karicheck per-location SOA" "rc=$RC" "$OUT"
expect "karicheck: no warning for defined locations" "$OUT" "0 warning"
printf 'zone "bad.test" { type master; file "%s/bad.data"; file-format tinydns; };\n' "$TMP_DIR" > "$TMP_DIR/kc2.conf"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc2.conf" 2>&1); RC=$?
[ "$RC" = 1 ] && ok "karicheck: serial mismatch between SOA records is an error" || bad "karicheck serial mismatch rc" "rc=$RC" "$OUT"
expect "karicheck: serial mismatch message" "$OUT" "different serials \\(1 and 2\\)"
# the location tags come from the configuration (options), so these checks go through a configuration
kc_tag_conf() {   # kc_tag_conf CONF ZONE FILE
    printf 'options { location-tags { tag "lt-in" { 127.0.0.1/32; }; tag "lt-ex" { 127.0.0.2/32; }; }; };\nzone "%s" { type master; file "%s"; };\n' "$2" "$3" > "$1"
}
kc_tag_conf "$TMP_DIR/kc4.conf" bt.test "$TMP_DIR/bt.zone"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc4.conf" 2>&1); RC=$?
[ "$RC" = 0 ] && ok "karicheck: BIND zone with \$LOCATION-tagged SOA records is valid" || bad "karicheck tagged SOA" "rc=$RC" "$OUT"
sed 's/( 4 3600 900 604800 600 )/( 5 3600 900 604800 600 )/' "$TMP_DIR/bt.zone" > "$TMP_DIR/bt_ser.zone"
kc_tag_conf "$TMP_DIR/kc5.conf" bt.test "$TMP_DIR/bt_ser.zone"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc5.conf" 2>&1); RC=$?
[ "$RC" = 1 ] && ok "karicheck: serial mismatch between tagged SOA records is an error" || bad "karicheck tagged serial rc" "rc=$RC" "$OUT"
cat > "$TMP_DIR/dup.zone" <<'EOF'
$TTL 300
$ORIGIN dup.test.
@ IN SOA ns1.dup.test. hostmaster.dup.test. ( 1 3600 900 604800 300 )
@ IN SOA ns2.dup.test. hostmaster.dup.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.dup.test.
ns1 IN A 192.0.2.1
EOF
OUT=$("$KARICHECK" zone dup.test. "$TMP_DIR/dup.zone" 2>&1); RC=$?
[ "$RC" = 1 ] && ok "karicheck: several SOA records without tags are an error" || bad "karicheck duplicate SOA rc" "rc=$RC" "$OUT"
expect "karicheck: duplicate SOA message" "$OUT" "has 2 SOA records at the apex"
{ cat "$TMP_DIR/sg.zone"; echo '$LOCATION lt-in'; echo '@ IN SOA ns9.sg.test. hostmaster.sg.test. ( 1 3600 900 604800 300 )'; } > "$TMP_DIR/sg_bad.zone"
kc_tag_conf "$TMP_DIR/kc6.conf" sg.test "$TMP_DIR/sg_bad.zone"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc6.conf" 2>&1); RC=$?
[ "$RC" = 1 ] && ok "karicheck: a restricted SOA in a zone with DNSSEC records is an error" || bad "karicheck signed zone rc" "rc=$RC" "$OUT"
expect "karicheck: signed zone message" "$OUT" "holds DNSSEC records and several or restricted SOA"
cat > "$TMP_DIR/nob.data" <<EOF
%in:127.0.0.1
Znob.test:ns1.nob.test.:hostmaster.nob.test.:1:3600:900:604800:300:300::zz
Znob.test:ns1.nob.test.:hostmaster.nob.test.:1:3600:900:604800:300:300::in
&nob.test::ns1.nob.test:300
+ns1.nob.test:192.0.2.1:300
EOF
printf 'zone "nob.test" { type master; file "%s/nob.data"; file-format tinydns; };\n' "$TMP_DIR" > "$TMP_DIR/kc3.conf"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc3.conf" 2>&1); RC=$?
[ "$RC" = 0 ] && ok "karicheck: a SOA that nobody sees is a warning, not an error" || bad "karicheck invisible SOA rc" "rc=$RC" "$OUT"
expect "karicheck: invisible SOA warning" "$OUT" "restricted to location 'zz', which the zone does not define"

# ------------------------------------------------------------------------------ server
echo "=== 2. start the server (serial mismatch zone bad.test is in the configuration) ==="
"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    Q $SRC_IN www.loc.test A | grep -q '192.0.2.10' && break
    sleep 0.1; i=$((i + 1))
done
if ! kill -0 "$SERVER_PID" 2>/dev/null; then echo "ERROR: server did not start"; cat "$TMP_DIR/server.log"; exit 1; fi

expect "bad.test (serial mismatch) was not loaded: logged" "$(cat "$TMP_DIR/server.log")" "zone 'bad.test.?' not loaded.*different serials"
OUT=$(Q $SRC_IN bad.test SOA)
reject "bad.test is not answered" "$OUT" "flags:.* aa"
expect "bad.test: some error status, no answer" "$OUT" "status: (REFUSED|SERVFAIL)"

echo "=== 3. tinydns zone with one SOA per location (loc.test) ==="
OUT=$(Q $SRC_IN loc.test SOA)
expect "in: SOA query = NOERROR, AA, exactly the one SOA of location in" "$OUT" "status: NOERROR" "flags: qr aa" "ANSWER: 1," "SOA[[:space:]]+ns1\\.in\\.loc\\.test\\."
reject "in: the SOA of location ex is not sent" "$OUT" "ns1\\.ex\\.loc\\.test"
OUT=$(Q $SRC_IN nx.loc.test A)
expect "in: NXDOMAIN carries its SOA in the authority section (RFC 2308 s3)" "$OUT" "status: NXDOMAIN" "flags: qr aa" "AUTHORITY: 1," "SOA[[:space:]]+ns1\\.in\\.loc\\.test\\."
OUT=$(Q $SRC_IN www.loc.test AAAA)
expect "in: NODATA carries its SOA in the authority section (RFC 2308 s3)" "$OUT" "status: NOERROR" "ANSWER: 0," "SOA[[:space:]]+ns1\\.in\\.loc\\.test\\."
OUT=$(Q $SRC_IN inonly.loc.test A)
expect "in: positive answer for a record of its location" "$OUT" "status: NOERROR" "flags: qr aa" "192\\.0\\.2\\.20"
OUT=$(Q $SRC_IN loc.test ANY)
expect "in: ANY at the apex has one SOA" "$OUT" "SOA[[:space:]]+ns1\\.in\\.loc\\.test\\."
reject "in: ANY at the apex does not carry the other SOA" "$OUT" "ns1\\.ex\\."

if [ "$MULTI" = 1 ]; then
    OUT=$(Q $SRC_EX loc.test SOA)
    expect "ex: SOA query = the SOA of location ex" "$OUT" "status: NOERROR" "flags: qr aa" "ANSWER: 1," "SOA[[:space:]]+ns1\\.ex\\.loc\\.test\\. .* 600"
    reject "ex: the SOA of location in is not sent" "$OUT" "ns1\\.in\\.loc\\.test"
    OUT=$(Q $SRC_EX inonly.loc.test A)
    expect "ex: NXDOMAIN for a name of another location, with its own SOA" "$OUT" "status: NXDOMAIN" "SOA[[:space:]]+ns1\\.ex\\.loc\\.test\\."
    OUT=$(Q $SRC_EX exonly.loc.test A)
    expect "ex: positive answer for a record of its location" "$OUT" "status: NOERROR" "192\\.0\\.2\\.21"

    echo "--- a client that sees no SOA of the zone: REFUSED, AA=0, EDE 18 (BIND 9.20 shape) ---"
    OUT=$(Q $SRC_NO loc.test SOA)
    expect "no: SOA query = REFUSED, no AA, EDE 18 Prohibited" "$OUT" "status: REFUSED" "ANSWER: 0, AUTHORITY: 0" "EDE: 18 \\(Prohibited\\)"
    reject "no: REFUSED has no AA flag" "$OUT" "flags: qr aa"
    OUT=$(Q $SRC_NO www.loc.test A)
    expect "no: a name the client could see is REFUSED too" "$OUT" "status: REFUSED" "EDE: 18 \\(Prohibited\\)"
    reject "no: no answer data leaks" "$OUT" "192\\.0\\.2\\.10"
    OUT=$(Q $SRC_NO nx.loc.test A)
    expect "no: NXDOMAIN case is REFUSED" "$OUT" "status: REFUSED" "EDE: 18 \\(Prohibited\\)"
    OUT=$(Q $SRC_NO loc.test NS)
    expect "no: even the NS (visible) is not served: REFUSED" "$OUT" "status: REFUSED" "EDE: 18 \\(Prohibited\\)"
else
    skip "ex / no clients of loc.test (needs the loopback aliases $SRC_EX and $SRC_NO: run as root)"
fi

echo "=== 4. standard AXFR of loc.test = the zone as the requester sees it ==="
OUT=$(AX $SRC_IN loc.test)
expect "in: AXFR has the SOA of location in" "$OUT" "SOA[[:space:]]+ns1\\.in\\.loc\\.test\\." "inonly\\.loc\\.test\\..*192\\.0\\.2\\.20" "www\\.loc\\.test\\..*192\\.0\\.2\\.10"
reject "in: AXFR has no record of location ex" "$OUT" "exonly|ns1\\.ex\\."
N=$(printf '%s\n' "$OUT" | grep -c '[[:space:]]SOA[[:space:]]')
[ "$N" = 2 ] && ok "in: exactly two SOA records (opening and closing, RFC 5936 s2.2)" || bad "in: AXFR SOA count" "count=$N" "$OUT"
OUT=$(perl "$PROBE" 127.0.0.1 "$PORT" $SRC_IN loc.test AXFR)
expect "in: AXFR shape" "$OUT" "rcode=0 aa=1" "soa=2"
if [ "$MULTI" = 1 ]; then
    OUT=$(AX $SRC_EX loc.test)
    expect "ex: AXFR has the SOA of location ex and its records" "$OUT" "SOA[[:space:]]+ns1\\.ex\\.loc\\.test\\." "exonly\\.loc\\.test\\..*192\\.0\\.2\\.21"
    reject "ex: AXFR has no record of location in" "$OUT" "inonly|ns1\\.in\\."
    N=$(printf '%s\n' "$OUT" | grep -c '[[:space:]]SOA[[:space:]]')
    [ "$N" = 2 ] && ok "ex: exactly two SOA records" || bad "ex: AXFR SOA count" "count=$N" "$OUT"
    OUT=$(perl "$PROBE" 127.0.0.1 "$PORT" $SRC_NO loc.test AXFR)
    expect "no: AXFR refused: REFUSED, AA=0, EDE 18" "$OUT" "rcode=5 aa=0" "ede=18" "soa=0"
    OUT=$(perl "$PROBE" 127.0.0.1 "$PORT" $SRC_NO loc.test IXFR 1)
    expect "no: IXFR refused the same way" "$OUT" "rcode=5 aa=0" "ede=18"
    OUT=$(perl "$PROBE" 127.0.0.1 "$PORT" $SRC_EX loc.test IXFR 1)
    expect "ex: IXFR of an older serial is answered with the whole zone (RFC 1995 s4)" "$OUT" "rcode=0" "soa=2"
else
    skip "AXFR per requester for ex / no"
fi

echo "=== 5. time stamps (tm.test): a countdown SOA, an expired one, the SOA for everybody ==="
OUT=$(Q $SRC_IN tm.test SOA)
expect "SOA query = the first visible SOA (the countdown one), TTL 1700-1800" "$OUT" "ANSWER: 1," "tm\\.test\\.[[:space:]]+1[78][0-9][0-9][[:space:]]+IN[[:space:]]+SOA[[:space:]]+ns1\\.cd\\.tm\\.test\\."
reject "the expired countdown SOA is gone" "$OUT" "ns1\\.old\\."
OUT=$(Q $SRC_IN nx.tm.test A)
expect "NXDOMAIN carries the visible SOA" "$OUT" "status: NXDOMAIN" "SOA[[:space:]]+ns1\\.cd\\.tm\\.test\\."
OUT=$(AX $SRC_IN tm.test)
expect "AXFR: the countdown SOA opens and closes the transfer with TTL 2 (axfrdns.c)" "$OUT" "tm\\.test\\.[[:space:]]+2[[:space:]]+IN[[:space:]]+SOA[[:space:]]+ns1\\.cd\\.tm\\.test\\."
N=$(printf '%s\n' "$OUT" | grep -c '[[:space:]]SOA[[:space:]]')
[ "$N" = 2 ] && ok "AXFR: two SOA records, the other SOAs are not in the body" || bad "tm AXFR SOA count" "count=$N" "$OUT"
expect "AXFR: a countdown record is sent with TTL 2" "$OUT" "cd\\.tm\\.test\\.[[:space:]]+2[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.31"
OUT=$(Q $SRC_IN late.test SOA)
expect "late.test: the only SOA is not active yet: REFUSED, EDE 18" "$OUT" "status: REFUSED" "EDE: 18 \\(Prohibited\\)"
OUT=$(perl "$PROBE" 127.0.0.1 "$PORT" $SRC_IN late.test AXFR)
expect "late.test: AXFR refused" "$OUT" "rcode=5 aa=0" "ede=18"

echo "=== 6. BIND format: \$LOCATION-tagged SOA records (bt.test) ==="
OUT=$(Q $SRC_IN bt.test SOA)
expect "in: SOA of tag lt-in" "$OUT" "ANSWER: 1," "SOA[[:space:]]+ns1\\.in\\.bt\\.test\\."
OUT=$(Q $SRC_IN nx.bt.test A)
expect "in: NXDOMAIN with the SOA of its tag" "$OUT" "status: NXDOMAIN" "SOA[[:space:]]+ns1\\.in\\.bt\\.test\\."
OUT=$(AX $SRC_IN bt.test)
expect "in: standard AXFR is the requester's view (tag lt-in)" "$OUT" "SOA[[:space:]]+ns1\\.in\\.bt\\.test\\." "inonly\\.bt\\.test\\..*192\\.0\\.2\\.41" "www\\.bt\\.test\\..*192\\.0\\.2\\.40"
N=$(printf '%s\n' "$OUT" | grep -c '[[:space:]]SOA[[:space:]]')
[ "$N" = 2 ] && ok "in: AXFR has two SOA records" || bad "bt AXFR SOA count" "count=$N" "$OUT"
if [ "$MULTI" = 1 ]; then
    OUT=$(Q $SRC_EX bt.test SOA)
    expect "ex: SOA of tag lt-ex" "$OUT" "ANSWER: 1," "SOA[[:space:]]+ns1\\.ex\\.bt\\.test\\."
    OUT=$(AX $SRC_EX bt.test)
    reject "ex: AXFR has nothing of tag lt-in" "$OUT" "inonly|ns1\\.in\\."
    expect "ex: AXFR has the SOA of its tag" "$OUT" "SOA[[:space:]]+ns1\\.ex\\.bt\\.test\\." "www\\.bt\\.test\\."
    OUT=$(Q $SRC_NO bt.test SOA)
    expect "no: no tag, no SOA: REFUSED, EDE 18" "$OUT" "status: REFUSED" "EDE: 18 \\(Prohibited\\)"
    OUT=$(perl "$PROBE" 127.0.0.1 "$PORT" $SRC_NO bt.test AXFR)
    expect "no: AXFR refused" "$OUT" "rcode=5 aa=0" "ede=18"
else
    skip "ex / no clients of bt.test"
fi

echo "=== 7. the closest zone decides: no fall back to the parent's answer ==="
OUT=$(Q $SRC_IN www.sub.par.test A)
expect "in: answered by the child zone" "$OUT" "status: NOERROR" "flags: qr aa" "192\\.0\\.2\\.50"
if [ "$MULTI" = 1 ]; then
    OUT=$(Q $SRC_EX www.sub.par.test A)
    expect "ex: REFUSED, not the parent's referral" "$OUT" "status: REFUSED" "EDE: 18 \\(Prohibited\\)"
    reject "ex: no referral" "$OUT" "ns1\\.sub\\.par\\.test"
    OUT=$(Q $SRC_EX par.test SOA)
    expect "ex: the parent zone itself is served" "$OUT" "status: NOERROR" "SOA[[:space:]]+ns1\\.par\\.test\\."
else
    skip "ex client of sub.par.test"
fi

echo "=== 8. reload: a serial mismatch keeps the last good version ==="
OUT=$(Q $SRC_IN mm.test SOA)
expect "mm.test loaded" "$OUT" "SOA[[:space:]]+ns1\\.a\\.mm\\.test\\. .* 5 "
sleep 1
sed 's/:5:3600:900:604800:300:300::ex/:6:3600:900:604800:300:300::ex/' "$TMP_DIR/mm.data" > "$TMP_DIR/mm.data.new" && mv "$TMP_DIR/mm.data.new" "$TMP_DIR/mm.data"
chmod 644 "$TMP_DIR/mm.data"
"$KARICTL" -f "$TMP_DIR/c.conf" reload mm.test > "$TMP_DIR/reload.out" 2>&1
sleep 0.5
OUT=$(Q $SRC_IN mm.test SOA)
expect "after the failed reload the old version is still served" "$OUT" "status: NOERROR" "SOA[[:space:]]+ns1\\.a\\.mm\\.test\\. .* 5 "
expect "the failed reload is logged" "$(cat "$TMP_DIR/server.log")" "zone 'mm.test.?' not loaded.*different serials"
sed 's/:6:3600:900:604800:300:300::ex/:5:3600:900:604800:300:300::ex/; s/ns1.b.mm.test./ns1.c.mm.test./' "$TMP_DIR/mm.data" > "$TMP_DIR/mm.data.new" && mv "$TMP_DIR/mm.data.new" "$TMP_DIR/mm.data"
chmod 644 "$TMP_DIR/mm.data"
sleep 1; touch "$TMP_DIR/mm.data"
"$KARICTL" -f "$TMP_DIR/c.conf" reload mm.test > "$TMP_DIR/reload2.out" 2>&1
sleep 0.5
if [ "$MULTI" = 1 ]; then
    OUT=$(Q $SRC_EX mm.test SOA)
    expect "a reload with equal serials is accepted" "$OUT" "SOA[[:space:]]+ns1\\.c\\.mm\\.test\\."
else
    OUT=$(Q $SRC_IN mm.test SOA)
    expect "a reload with equal serials is accepted" "$OUT" "SOA[[:space:]]+ns1\\.a\\.mm\\.test\\."
fi
# a signed zone gets a restricted SOA
sleep 1
cp "$TMP_DIR/sg_bad.zone" "$TMP_DIR/sg.zone"; chmod 644 "$TMP_DIR/sg.zone"
"$KARICTL" -f "$TMP_DIR/c.conf" reload sg.test > "$TMP_DIR/reload3.out" 2>&1
sleep 0.5
expect "a signed zone with a restricted SOA is not loaded (logged)" "$(cat "$TMP_DIR/server.log")" "zone 'sg.test.?' not loaded.*DNSSEC"
OUT=$(Q $SRC_IN sg.test SOA)
expect "the signed zone still serves its last good SOA" "$OUT" "status: NOERROR" "SOA[[:space:]]+ns1\\.sg\\.test\\."

# ------------------------------------------------------------------------------ djbdns reference
echo "=== 9. djbdns 1.05 reference (tinydns, axfrdns) ==="
if [ -z "$DJB" ] || [ ! -x "$DJB/tinydns" ] || [ ! -x "$DJB/tinydns-data" ] || [ ! -x "$DJB/axfrdns" ]; then
    skip "djbdns reference (set DJBDNS_DIR to a directory with the built tinydns, tinydns-data and axfrdns)"
elif [ "$(id -u)" != 0 ] || [ "$MULTI" != 1 ] || ! ifconfig lo0 2>/dev/null | grep -q "inet $DJB_IP "; then
    skip "djbdns reference (needs root and the loopback aliases)"
else
    ROOTD="$TMP_DIR/djbroot"
    mkdir -p "$ROOTD"; chmod 755 "$ROOTD"
    cat "$TMP_DIR/loc.data" "$TMP_DIR/tm.data" > "$ROOTD/data"
    # the two files declare the same locations: tinydns-data wants each % line once
    awk '!(/^%/ && seen[$0]++)' "$ROOTD/data" > "$ROOTD/data.u" && mv "$ROOTD/data.u" "$ROOTD/data"
    (cd "$ROOTD" && "$DJB/tinydns-data") || { bad "tinydns-data failed"; }
    chmod 644 "$ROOTD"/data*
    NOBODY_UID=$(id -u nobody 2>/dev/null || echo 65534); NOBODY_GID=$(id -g nobody 2>/dev/null || echo 65534)
    env ROOT="$ROOTD" IP="$DJB_IP" UID="$NOBODY_UID" GID="$NOBODY_GID" "$DJB/tinydns" > "$TMP_DIR/djb.log" 2>&1 &
    DJB_PID=$!
    # axfrdns reads one TCP connection on its stdin / stdout: a tiny listener plays tcpserver (TCPREMOTEIP from the peer)
    cat > "$TMP_DIR/tcpserver.pl" <<'EOF'
use strict; use warnings; use IO::Socket::INET;
my ($ip, $axfrdns) = @ARGV;
my $l = IO::Socket::INET->new(LocalAddr => $ip, LocalPort => 53, Listen => 5, ReuseAddr => 1, Proto => 'tcp') or die "listen: $!";
$SIG{CHLD} = 'IGNORE';
while (my $c = $l->accept) {
    my $pid = fork();
    if (!$pid) {
        $ENV{TCPREMOTEIP} = $c->peerhost; $ENV{TCPREMOTEPORT} = $c->peerport;
        open(STDIN, "<&=" . fileno($c)) or die; open(STDOUT, ">&=" . fileno($c)) or die;
        exec($axfrdns) or die;
    }
    close $c;
}
EOF
    env ROOT="$ROOTD" UID="$NOBODY_UID" GID="$NOBODY_GID" perl "$TMP_DIR/tcpserver.pl" "$DJB_IP" "$DJB/axfrdns" > "$TMP_DIR/axfrdns.log" 2>&1 &
    AXFRDNS_PID=$!
    sleep 1
    DQ()  { "$DAG" "$2" "$3" @"$DJB_IP" -p 53 -b "$1" +nohexdump +time=2 +tries=1 2>&1; }
    DAX() { "$DAG" "$2" AXFR @"$DJB_IP" -p 53 -b "$1" +nohexdump +time=3 +tries=1 2>&1; }
    OUT=$(DQ $SRC_IN loc.test SOA)
    if ! printf '%s' "$OUT" | grep -q 'ns1.in.loc.test'; then
        bad "djbdns reference server did not answer" "$OUT" "$(cat "$TMP_DIR/djb.log")"
    else
        for pair in "$SRC_IN:in" "$SRC_EX:ex"; do
            src=${pair%%:*}; loc=${pair##*:}
            D=$(DQ $src loc.test SOA); K=$(Q $src loc.test SOA)
            expect "djbdns $loc: SOA is the SOA of its location" "$D" "SOA[[:space:]]+ns1\\.$loc\\.loc\\.test\\."
            expect "KariDNS $loc: same SOA" "$K" "SOA[[:space:]]+ns1\\.$loc\\.loc\\.test\\."
            D=$(DQ $src nx.loc.test A); K=$(Q $src nx.loc.test A)
            expect "djbdns $loc: NXDOMAIN with the SOA of its location" "$D" "status: NXDOMAIN" "SOA[[:space:]]+ns1\\.$loc\\.loc\\.test\\."
            expect "KariDNS $loc: same" "$K" "status: NXDOMAIN" "SOA[[:space:]]+ns1\\.$loc\\.loc\\.test\\."
            D=$(rrset "$(DAX $src loc.test)"); K=$(rrset "$(AX $src loc.test)")
            if [ -n "$D" ] && [ "$D" = "$K" ]; then ok "AXFR of loc.test as seen by $loc: same records in djbdns and KariDNS"
            else bad "AXFR of loc.test as seen by $loc differs" "djbdns:" "$D" "KariDNS:" "$K"; fi
        done
        # time stamps: the countdown SOA opens the transfer; TTL 2 in both
        D=$(rrset "$(DAX $SRC_IN tm.test)"); K=$(rrset "$(AX $SRC_IN tm.test)")
        if [ -n "$D" ] && [ "$D" = "$K" ]; then ok "AXFR of tm.test: same records in djbdns and KariDNS"
        else bad "AXFR of tm.test differs" "djbdns:" "$D" "KariDNS:" "$K"; fi
        # EXPECTED DIFFERENCES: a client that sees no SOA
        D=$(DQ $SRC_NO loc.test SOA); K=$(Q $SRC_NO loc.test SOA)
        expect "djbdns no: NOERROR without AA (a referral to the visible NS)" "$D" "status: NOERROR" "ANSWER: 0,"
        reject "djbdns no: AA is not set" "$D" "flags: qr aa"
        expect "KariDNS no: REFUSED, no AA, EDE 18 (expected difference: BIND 9.20 shape)" "$K" "status: REFUSED" "EDE: 18"
        D=$(DAX $SRC_NO loc.test)
        reject "djbdns no: no AXFR data (axfrdns dies outside)" "$D" "[[:space:]]SOA[[:space:]]"
    fi
fi

echo
echo "=== tinydns SOA/location (B8t-1): $PASS passed, $FAIL failed, $SKIP skipped ==="
[ "$FAIL" = 0 ] || exit 1
exit 0
