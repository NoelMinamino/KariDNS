#!/bin/sh
# karicheck ZONEMD digests against an independent implementation (ldns-signzone, ldns >= 1.8).
#
# A zone with upper- and mixed-case owner names and RDATA names in every RFC 4034 section 6.2 item 3 type that
# karicheck serializes (NS CNAME SOA PTR MX RP AFSDB RT KX PX MINFO SRV NAPTR DNAME; SIG/RRSIG/NXT/A6/MD/MF/MB/MG/MR
# are covered by RRSIG below or not accepted by ldns), plus types whose RDATA names are not lower-cased (SVCB, NSEC
# per RFC 6840 section 5.1), duplicate RRs, a wildcard, occluded data and a non-apex ZONEMD. ldns-signzone adds the
# SHA-384 and SHA-512 ZONEMD RRs (RFC 8976 section 3); karicheck must report both VALID (K-01).
# The same zone is also signed with an ECDSA key, once with NSEC and once with NSEC3 (RRSIG signer names, NSEC
# next names and the apex RRSIG(ZONEMD) that RFC 8976 section 3.3.1.1 excludes).
#
# Not in the zone: WKS (ldns prints port mnemonics, which the server drops, see FIX_REPORTS X-38) and types whose
# RDATA names the serializer lower-cases although RFC 4034 section 6.2 does not list them (IPSECKEY, HIP, LP,
# TALINK, NSAP-PTR; X-37).
#
# SKIP (exit 0) when ldns-signzone is not installed.

KARICHECK="./karicheck"
[ -x "$KARICHECK" ] || { echo "[-] FAIL: ./karicheck not built"; exit 1; }
if ! command -v ldns-signzone >/dev/null 2>&1; then
    echo "SKIP: ldns-signzone not installed"
    exit 0
fi

TMP_DIR=$(mktemp -d /tmp/kc_zonemd_ldns.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT
FAILED=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=1; }

cat > "$TMP_DIR/case.zone" <<'EOF'
$TTL 300
$ORIGIN Case.Example.
@         IN SOA   NS1.Case.Example. HostMaster.Case.Example. 2026100601 3600 600 86400 60
@         IN NS    NS1.Case.Example.
@         IN NS    ns2.CASE.example.
NS1       IN A     192.0.2.1
NS2       IN AAAA  2001:db8::2
Mail      IN MX    10 NS1.Case.Example.
Alias     IN CNAME Www.Case.Example.
Www       IN A     192.0.2.10
_sip._TCP IN SRV   10 60 5060 NS1.Case.Example.
Ptr       IN PTR   Target.Example.Net.
Dn        IN DNAME Other.Example.Org.
Rp        IN RP    Admin.Case.Example. Txt.Case.Example.
Txt       IN TXT   "Mixed Case Text"
Afs       IN AFSDB 1 NS1.Case.Example.
Rt        IN RT    10 NS1.Case.Example.
Kx        IN KX    10 NS1.Case.Example.
Px        IN PX    10 Map822.Case.Example. MapX400.Case.Example.
Mi        IN MINFO Rmail.Case.Example. Email.Case.Example.
Np        IN NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:Info@Case.Example!" .
Np2       IN NAPTR 100 10 "S" "SIP+D2U" "" _sip._udp.Case.Example.
Svc       IN SVCB  1 Target.Case.Example. alpn=h2
Hi        IN HINFO "Intel" "FreeBSD"
Dup       IN TXT   "same"
DUP       IN TXT   "same"
Sub       IN NS    NS.Sub.Case.Example.
NS.Sub    IN A     192.0.2.53
Hidden.Sub IN TXT  "occluded"
*         IN TXT   "wild"
Other     IN ZONEMD 2026100601 1 1 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
EOF

# check <label> <signed zone file>
check() {
    out=$("$KARICHECK" zone case.example. "$2" 2>&1)
    rc=$?
    n=$(echo "$out" | grep -c "^\[OK\] ZONEMD (Scheme 1, Hash [12]) for 'case.example.' is VALID\.$")
    if [ "$rc" -eq 0 ] && [ "$n" -eq 2 ]; then
        pass "$1: SHA-384 and SHA-512 ZONEMD from ldns-signzone are VALID"
    else
        fail "$1: rc=$rc, $n VALID lines"; echo "$out" | grep -v "^\[OK\] Zone"
    fi
}

if ldns-signzone -Z -z 1 -z 2 -f "$TMP_DIR/unsigned.out" "$TMP_DIR/case.zone" Case.Example. >"$TMP_DIR/ldns.log" 2>&1 &&
   grep -q "ZONEMD" "$TMP_DIR/unsigned.out"; then
    check "unsigned" "$TMP_DIR/unsigned.out"
else
    fail "ldns-signzone -Z did not produce a ZONEMD"; cat "$TMP_DIR/ldns.log"
fi

if command -v ldns-keygen >/dev/null 2>&1; then
    KEY=$(cd "$TMP_DIR" && ldns-keygen -a ECDSAP256SHA256 -k Case.Example. 2>/dev/null)
    if [ -n "$KEY" ] && [ -f "$TMP_DIR/$KEY.private" ]; then
        cat "$TMP_DIR/$KEY.key" >> "$TMP_DIR/case.zone"
        if ldns-signzone -z 1 -z 2 -f "$TMP_DIR/nsec.out" "$TMP_DIR/case.zone" "$TMP_DIR/$KEY" >"$TMP_DIR/ldns.log" 2>&1; then
            check "NSEC-signed" "$TMP_DIR/nsec.out"
        else
            fail "ldns-signzone (NSEC) failed"; cat "$TMP_DIR/ldns.log"
        fi
        if ldns-signzone -n -t 0 -z 1 -z 2 -f "$TMP_DIR/nsec3.out" "$TMP_DIR/case.zone" "$TMP_DIR/$KEY" \
             >"$TMP_DIR/ldns.log" 2>&1; then
            check "NSEC3-signed" "$TMP_DIR/nsec3.out"
        else
            fail "ldns-signzone (NSEC3) failed"; cat "$TMP_DIR/ldns.log"
        fi
    else
        echo "  SKIP: ldns-keygen could not create a key; signed variants not checked"
    fi
else
    echo "  SKIP: ldns-keygen not installed; signed variants not checked"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "karicheck ZONEMD vs ldns: FAILED"
    exit 1
fi
echo "karicheck ZONEMD vs ldns: all checks passed"
exit 0
