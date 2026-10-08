#!/bin/sh
# run_name_escape_test.sh - names with master-file escapes (R-29, R-23, O-08).
#
# RFC 1035 §5.1: "\X" and "\DDD" in master files denote the literal octet; RFC 4343 §2: names are compared
# as octet strings (ASCII case-insensitive). KariDNS keeps one text form for every name (dns_wire.h), so a
# name written with escapes in a zone file (BIND or tinydns format) or in named.conf must be found by the
# query that carries the same octets on the wire. Checked here:
#   1. BIND zone: \DDD, \X, escaped dot, \065 (= 'A'), DNS-SD instance name, CNAME to an escaped target;
#      "a.b" (two labels) must not match the owner "a\.b" (one label).
#   2. tinydns zone (octal escapes, zone name with an escape in named.conf): owners, the '.' line's
#      NS/SOA (hostmaster rname) built from the escaped zone name.
#   2b. BIND zone "k\032z.test": "karictl reload" with another spelling of the name (k\032\122.test,
#      \122 = 'z') finds the zone. (A tinydns zone is not used here: a targeted reload of any tinydns zone
#      stops the backend, also without escapes - reported separately as X-13.)
#   3. Primary -> secondary AXFR of the escaped names; the secondary answers them like the primary.
#   4. NSEC3 (RFC 5155 §5): the NSEC3 owner hashes in NODATA / NXDOMAIN proofs for escaped names equal
#      BIND's nsec3hash (needs dnssec-keygen, dnssec-signzone, nsec3hash; SKIP otherwise).

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="$BASE_DIR/karidns"
DAG="$BASE_DIR/dag"
KARICTL="$BASE_DIR/karictl"
PPORT=15461
SPORT=15462

echo "=== Escaped owner names: BIND/tinydns zones, AXFR, NSEC3 (R-29, R-23, O-08) ==="

[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICTL" ] || make -C "$BASE_DIR" karidns dag karictl >/dev/null || exit 1

TMP_DIR="$(mktemp -d /tmp/karidns_esc.XXXXXX)"
chmod 755 "$TMP_DIR"
P_PID=""
S_PID=""
cleanup() {
    kari_kill_tree "$P_PID" "$S_PID"
    kari_kill_conf "$TMP_DIR/primary.conf" "$TMP_DIR/secondary.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

cat > "$TMP_DIR/esc.zone" <<'EOF'
$TTL 300
$ORIGIN esc.test.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
a\.b IN A 192.0.2.2
b IN A 192.0.2.8
sp\032ace IN A 192.0.2.3
c\(p IN A 192.0.2.4
\065bc IN A 192.0.2.5
\200x IN A 192.0.2.6
My\032Printer._ipp._tcp IN SRV 0 0 631 ns1.esc.test.
alias IN CNAME sp\032ace
EOF

# tinydns-data: \ooo is octal. \040 = space, \056 = '.'.
cat > "$TMP_DIR/tiny.data" <<'EOF'
.e\040s.test:192.0.2.1:a:300
+sp\040ace.e\040s.test:192.0.2.3:300
+d\056t.e\040s.test:192.0.2.9:300
EOF
cat > "$TMP_DIR/kz.zone" <<'EOF'
$TTL 300
@ IN SOA ns1.esc.test. hostmaster.esc.test. 1 3600 600 86400 60
@ IN NS ns1.esc.test.
www IN A 192.0.2.20
EOF
chmod 644 "$TMP_DIR"/*

cat > "$TMP_DIR/primary.conf" <<EOF
options { port $PPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
control-channel {
    socket "$TMP_DIR/control.sock";
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
zone "esc.test" { type master; file "$TMP_DIR/esc.zone"; allow-transfer { 127.0.0.1; }; };
zone "e\\032s.test" { type master; file "$TMP_DIR/tiny.data"; file-format tinydns; };
zone "k\\032z.test" { type master; file "$TMP_DIR/kz.zone"; };
EOF
cat > "$TMP_DIR/karictl.conf" <<EOF
socket "$TMP_DIR/control.sock";
algorithm hmac-sha256;
secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
EOF
chmod 600 "$TMP_DIR/karictl.conf"
cat > "$TMP_DIR/secondary.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "esc.test" { type slave; masters { 127.0.0.1 port $PPORT; }; allow-transfer { 127.0.0.1; }; };
EOF

"$KARIDNS" -f "$TMP_DIR/primary.conf" > "$TMP_DIR/primary.log" 2>&1 &
P_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" esc.test SOA @127.0.0.1 -p $PPORT +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster && break
    sleep 0.2; i=$((i + 1))
done

# q PORT NAME TYPE: "<status> <sorted short answers>"
q() {
    _o=$("$DAG" "$2" "$3" @127.0.0.1 -p "$1" +time=2 +tries=1 +nohexdump 2>&1)
    _s=$(echo "$_o" | grep -o "status: [A-Z]*" | head -1 | sed 's/status: //')
    _a=$("$DAG" "$2" "$3" @127.0.0.1 -p "$1" +short +time=2 +tries=1 2>/dev/null | sort | tr '\n' ' ' | sed 's/ $//')
    echo "$_s $_a"
}
expect() { # PORT NAME TYPE EXPECTED LABEL
    _r=$(q "$1" "$2" "$3")
    if [ "$_r" = "$4" ]; then pass "$5: $2 $3 -> $_r"; else fail "$5: $2 $3 -> '$_r' (expected '$4')"; fi
}

# 1. BIND zone
expect $PPORT 'sp\032ace.esc.test' A "NOERROR 192.0.2.3" "BIND \\DDD owner"
expect $PPORT 'c\(p.esc.test' A "NOERROR 192.0.2.4" "BIND \\X owner"
expect $PPORT 'c(p.esc.test' A "NOERROR 192.0.2.4" "BIND \\X owner (unescaped query spelling)"
expect $PPORT 'a\.b.esc.test' A "NOERROR 192.0.2.2" "escaped dot"
expect $PPORT 'a.b.esc.test' A "NXDOMAIN " "escaped dot is not a label boundary"
expect $PPORT 'ABC.esc.test' A "NOERROR 192.0.2.5" "\\065bc owner, case-insensitive"
expect $PPORT '\200x.esc.test' A "NOERROR 192.0.2.6" "non-ASCII octet"
expect $PPORT 'My\032Printer._ipp._tcp.esc.test' SRV "NOERROR 0 0 631 ns1.esc.test." "DNS-SD instance name"
expect $PPORT 'alias.esc.test' A "NOERROR 192.0.2.3 sp\\032ace.esc.test." "CNAME to an escaped target"

# 2. tinydns zone, zone name with an escape in named.conf
expect $PPORT 'sp\032ace.e\032s.test' A "NOERROR 192.0.2.3" "tinydns octal \\040 owner"
expect $PPORT 'd\.t.e\032s.test' A "NOERROR 192.0.2.9" "tinydns octal \\056 (dot inside a label)"
expect $PPORT 'e\032s.test' NS "NOERROR a.ns.e\\032s.test." "tinydns '.' line NS (x expansion)"
SOA_R=$("$DAG" 'e\032s.test' SOA @127.0.0.1 -p $PPORT +short +time=2 +tries=1 2>/dev/null | awk '{print $2}')
[ "$SOA_R" = 'hostmaster.e\032s.test.' ] && pass "tinydns SOA rname $SOA_R" || fail "tinydns SOA rname '$SOA_R'"

# 2b. karictl: the zone argument is normalised like the configured name (find_configured_domain())
expect $PPORT 'www.k\032z.test' A "NOERROR 192.0.2.20" "zone name with an escape in named.conf"
sed 's/^\$TTL 300$/$TTL 300\
new IN A 192.0.2.21/; s/ 1 3600 / 2 3600 /' "$TMP_DIR/kz.zone" > "$TMP_DIR/kz.new" && mv "$TMP_DIR/kz.new" "$TMP_DIR/kz.zone"
chmod 644 "$TMP_DIR/kz.zone"
KC_OUT=$("$KARICTL" -f "$TMP_DIR/karictl.conf" reload 'k\032\122.test' 2>&1); KC_RC=$?
if [ $KC_RC -eq 0 ] && echo "$KC_OUT" | grep -q "reloaded"; then
    pass "karictl reload 'k\\032\\122.test' found zone k\\032z.test"
else
    fail "karictl reload 'k\\032\\122.test' (rc=$KC_RC): $KC_OUT"
fi
expect $PPORT 'new.k\032z.test' A "NOERROR 192.0.2.21" "record added before the targeted reload"

# 3. Primary -> secondary AXFR
"$KARIDNS" -f "$TMP_DIR/secondary.conf" > "$TMP_DIR/secondary.log" 2>&1 &
S_PID=$!
i=0
S_SERIAL=""
while [ $i -lt 60 ]; do
    S_SERIAL=$("$DAG" esc.test SOA @127.0.0.1 -p $SPORT +short +time=1 +tries=1 2>/dev/null | awk '{print $3}')
    [ "$S_SERIAL" = "1" ] && break
    sleep 0.5; i=$((i + 1))
done
[ "$S_SERIAL" = "1" ] && pass "secondary transferred esc.test" || fail "secondary did not transfer esc.test ('$S_SERIAL')"
"$DAG" esc.test AXFR @127.0.0.1 -p $PPORT +time=5 +nohexdump > "$TMP_DIR/p.axfr" 2>&1
"$DAG" esc.test AXFR @127.0.0.1 -p $SPORT +time=5 +nohexdump > "$TMP_DIR/s.axfr" 2>&1
normalize() { grep -Ev "^;|^$" "$1" | awk '{ $2 = ""; print }' | sort; }
normalize "$TMP_DIR/p.axfr" > "$TMP_DIR/p.norm"
normalize "$TMP_DIR/s.axfr" > "$TMP_DIR/s.norm"
if grep -q '^sp\\032ace\.esc\.test\.' "$TMP_DIR/p.norm" && cmp -s "$TMP_DIR/p.norm" "$TMP_DIR/s.norm"; then
    pass "secondary AXFR matches the primary ($(wc -l < "$TMP_DIR/s.norm" | tr -d ' ') records)"
else
    fail "secondary AXFR differs from the primary"; diff "$TMP_DIR/p.norm" "$TMP_DIR/s.norm" | head -10
fi
expect $SPORT 'sp\032ace.esc.test' A "NOERROR 192.0.2.3" "secondary: \\DDD owner"
expect $SPORT 'a\.b.esc.test' A "NOERROR 192.0.2.2" "secondary: escaped dot"
expect $SPORT 'a.b.esc.test' A "NXDOMAIN " "secondary: escaped dot is not a label boundary"
expect $SPORT 'c(p.esc.test' A "NOERROR 192.0.2.4" "secondary: \\X owner"

# 4. NSEC3 hashes of escaped names (RFC 5155 §5 via the canonical wire form of RFC 4034 §6.2)
if command -v dnssec-keygen >/dev/null 2>&1 && command -v dnssec-signzone >/dev/null 2>&1 \
   && command -v nsec3hash >/dev/null 2>&1; then
    sed 's/esc\.test\./n3.test./' "$TMP_DIR/esc.zone" > "$TMP_DIR/n3.zone"
    (cd "$TMP_DIR" && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK n3.test >/dev/null 2>&1 \
        && dnssec-keygen -q -a ECDSAP256SHA256 n3.test >/dev/null 2>&1 \
        && dnssec-signzone -q -S -K . -3 AABBCCDD -H 0 -o n3.test -f n3.signed n3.zone >/dev/null 2>&1)
    if [ -s "$TMP_DIR/n3.signed" ]; then
        chmod 644 "$TMP_DIR/n3.signed"
        cat > "$TMP_DIR/n3.conf" <<EOF
options { port $SPORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "n3.test" { type master; file "$TMP_DIR/n3.signed"; };
EOF
        kari_kill_tree "$S_PID"; S_PID=""
        "$KARIDNS" -f "$TMP_DIR/n3.conf" > "$TMP_DIR/n3.log" 2>&1 &
        S_PID=$!
        i=0
        while [ $i -lt 50 ]; do
            "$DAG" n3.test SOA @127.0.0.1 -p $SPORT +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster && break
            sleep 0.2; i=$((i + 1))
        done
        # nsec3_owners NAME TYPE: first labels of the NSEC3 owners in the response, lower case
        nsec3_owners() {
            "$DAG" "$1" "$2" @127.0.0.1 -p $SPORT +dnssec +time=2 +tries=1 +nohexdump 2>/dev/null \
                | awk '$4 == "NSEC3" { split($1, l, "."); print tolower(l[1]) }' | sort -u | tr '\n' ' '
        }
        h() { nsec3hash AABBCCDD 1 0 "$1" | awk '{ print tolower($1) }'; }
        # NODATA at an escaped owner: the NSEC3 matching that owner (RFC 5155 §7.2.3)
        for n in 'sp\032ace.n3.test.' 'a\.b.n3.test.' 'Abc.n3.test.'; do
            want=$(h "$n")
            got=$(nsec3_owners "$n" TXT)
            case " $got" in
                *" $want "*) pass "NODATA $n TXT: NSEC3 owner $want (nsec3hash)" ;;
                *) fail "NODATA $n TXT: expected NSEC3 owner $want, got '$got'" ;;
            esac
        done
        # NXDOMAIN below an escaped owner: closest encloser a\.b.n3.test. (RFC 5155 §7.2.2)
        want=$(h 'a\.b.n3.test.')
        got=$(nsec3_owners 'x.a\.b.n3.test.' A)
        case " $got" in
            *" $want "*) pass "NXDOMAIN x.a\\.b.n3.test: closest-encloser NSEC3 $want" ;;
            *) fail "NXDOMAIN x.a\\.b.n3.test: expected closest-encloser NSEC3 $want, got '$got'" ;;
        esac
    else
        echo "  [SKIP] NSEC3 part: dnssec-signzone failed"
    fi
else
    echo "  [SKIP] NSEC3 part: dnssec-keygen / dnssec-signzone / nsec3hash not installed"
fi

for p in "$P_PID" "$S_PID"; do kill -0 "$p" 2>/dev/null || fail "a server exited during the test"; done
if [ $FAILED -ne 0 ]; then
    echo "--- primary.log (tail) ---"; tail -15 "$TMP_DIR/primary.log"
    echo "--- secondary.log (tail) ---"; tail -15 "$TMP_DIR/secondary.log"
    echo "=== FAILED ==="
    exit 1
fi
echo "=== PASSED ==="
exit 0
