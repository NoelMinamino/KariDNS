#!/bin/sh
# ==============================================================================
# run_karicheck_low_l4_test.sh
#
# karicheck on the zone-file and zone-lint fixes of review batch "low L4":
#   * DS / CDS digest length and SSHFP fingerprint length against the digest type (RFC 4034 5.1.4, RFC 4509 2, RFC 6605 5,
#     RFC 4255 3.1.2, RFC 6594 5; BIND refuses the other lengths), in a zone file and in a tinydns '_' line
#   * SSHFP algorithm 6 (Ed448, RFC 8709) is assigned
#   * DNSSEC algorithm numbers 17, 23 and the private 252-254 are known (IANA registry)
#   * CAA issuemail (RFC 9495) and issuevmc are known tags
#   * the glue of a sibling delegation (RFC 9471) is not "occluded"
#   * two different CNAMEs / DNAMEs at one name, NSEC3 iterations above 150 (RFC 9276 3.2): the zone is refused
#   * zone file syntax: unknown $ directive, $ORIGIN without a name, a line that starts with a blank before any record,
#     \DDD above 255, \000 outside TXT, a bad entry in a tag definition
#   * tinydns: a TTL that is not decimal digits, more than 4096 location lines; 0.6.2: the numeric RDATA fields (MX, SRV, NAPTR, SSHFP,
#     the type of a generic line) are digits within the size of the field
#   * 0.6.2: an $INCLUDE that is a symbolic link or a FIFO is refused (as the server refuses it), without waiting on the FIFO
# Exit status contract as in run_karicheck_matrix_test.sh: 1 when at least one [ERROR] is reported, 0 otherwise.
# The binary can be overridden with KARICHECK=/path/to/karicheck.
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

KC="${KARICHECK:-./karicheck}"
if [ ! -x "$KC" ]; then
    echo "[+] Building karicheck..."
    make karicheck >/dev/null 2>&1 || { echo "FAIL: cannot build karicheck"; exit 1; }
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/karicheck_low_l4.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM
PASS=0
FAIL=0

# check <label> <expected-exit> <fixed-string-pattern> <output> <actual-exit>; a pattern starting with "!" must NOT be in the output
check() {
    label="$1"; want_exit="$2"; pat="$3"; out="$4"; got_exit="$5"
    if [ "$got_exit" -ne "$want_exit" ]; then
        echo "  FAIL [$label]: exit $got_exit, expected $want_exit"; echo "$out" | head -8 | sed 's/^/      /'
        FAIL=$((FAIL + 1)); return
    fi
    case "$pat" in
        '!'*)
            if printf '%s\n' "$out" | grep -qF -- "${pat#!}"; then
                echo "  FAIL [$label]: unexpected message: ${pat#!}"; echo "$out" | head -8 | sed 's/^/      /'
                FAIL=$((FAIL + 1)); return
            fi ;;
        '')  ;;
        *)
            if ! printf '%s\n' "$out" | grep -qF -- "$pat"; then
                echo "  FAIL [$label]: message not found: $pat"; echo "$out" | head -8 | sed 's/^/      /'
                FAIL=$((FAIL + 1)); return
            fi ;;
    esac
    PASS=$((PASS + 1))
}

ZHEAD='$ORIGIN z.example.
$TTL 300
@ SOA ns.z.example. h.z.example. 1 7200 3600 1209600 300
@ NS ns.z.example.
ns A 192.0.2.1'

# zone_case <label> <expected-exit> <pattern> <extra zone lines>
zone_case() {
    f="$TMP/$1.zone"
    printf '%s\n%s\n' "$ZHEAD" "$4" > "$f"
    out=$("$KC" zone z.example. "$f" 2>&1); rc=$?
    check "zone:$1" "$2" "$3" "$out" "$rc"
}
# raw_zone <label> <expected-exit> <pattern> <complete zone text>
raw_zone() {
    f="$TMP/$1.zone"
    printf '%s\n' "$4" > "$f"
    out=$("$KC" zone z.example. "$f" 2>&1); rc=$?
    check "raw:$1" "$2" "$3" "$out" "$rc"
}
# td_case <label> <expected-exit> <pattern> <tinydns lines after the SOA/NS line>
td_case() {
    d="$TMP/td_$1.data"
    printf '.example.com:192.0.2.1:a.ns.example.com:300\n%s\n' "$4" > "$d"
    printf 'zone "example.com" { type master; file "%s"; file-format tinydns; };\n' "$d" > "$TMP/td_$1.conf"
    out=$("$KC" zones "$TMP/td_$1.conf" 2>&1); rc=$?
    check "tinydns:$1" "$2" "$3" "$out" "$rc"
}

echo "=== Running karicheck low batch L4 ==="

H20=0123456789abcdef0123456789abcdef01234567                       # 20 octets
H32=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef   # 32 octets
H48=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef   # 48 octets

# ---- DS / CDS digest length (BIND ds_43.c) ----------------------------------------------------------------
zone_case ds_sha1_ok    0 "!digest is" "k DS 1 8 1 $H20"
zone_case ds_sha256_ok  0 "!digest is" "k DS 1 8 2 $H32"
zone_case ds_sha384_ok  0 "!digest is" "k DS 1 8 4 $H48"
zone_case ds_sha1_len   1 "a SHA-1 digest is 20 octets, found 4" "k DS 1 8 1 AABBCCDD"
zone_case ds_sha256_len 1 "a SHA-256 digest is 32 octets, found 20" "k DS 1 8 2 $H20"
zone_case ds_sha384_len 1 "a SHA-384 digest is 48 octets, found 32" "k DS 1 8 4 $H32"
zone_case cds_len       1 "CDS 'k.z.example.': a SHA-256 digest is 32 octets, found 20" "k CDS 1 8 2 $H20"
zone_case cds_delete    0 "!digest is" "k CDS 0 0 0 00"
zone_case ds_split_ok   0 "!digest is" "k DS 1 8 2 0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef"

# ---- SSHFP -----------------------------------------------------------------------------------------------
zone_case sshfp_sha1_ok   0 "!fingerprint for" "s SSHFP 1 1 $H20"
zone_case sshfp_sha256_ok 0 "!fingerprint for" "s SSHFP 4 2 $H32"
zone_case sshfp_sha1_len  1 "SSHFP fingerprint for 's.z.example.' is 4 octets, a SHA-1 fingerprint is 20" "s SSHFP 1 1 AABBCCDD"
zone_case sshfp_256_len   1 "is 20 octets, a SHA-256 fingerprint is 32" "s SSHFP 4 2 $H20"
zone_case sshfp_alg6      0 "!outside standard RFC assignments" "s SSHFP 6 2 $H32"
zone_case sshfp_alg5      0 "SSHFP record for 's.z.example.' uses algorithm '5'" "s SSHFP 5 2 $H32"
td_case   td_sshfp_alg6   0 "!outside standard RFC assignments" "_s.example.com:6:2:$H32:300"
td_case   td_sshfp_alg9   0 "SSHFP algorithm '9' is outside standard RFC assignments (1-4, 6)" "_s.example.com:9:2:$H32:300"
td_case   td_sshfp_len    1 "SSHFP fingerprint is 20 octets, a SHA-256 fingerprint is 32" "_s.example.com:4:2:$H20:300"
td_case   td_sshfp_ok     0 "!fingerprint is" "_s.example.com:4:1:$H20:300"

# ---- DNSSEC algorithm numbers ------------------------------------------------------------------------------
K='AwEAAQ=='
zone_case alg17     0 "!unknown DNSSEC algorithm" "k DNSKEY 257 3 17 $K"
zone_case alg23     0 "!unknown DNSSEC algorithm" "k DNSKEY 257 3 23 $K"
zone_case alg252    0 "!unknown DNSSEC algorithm" "k DNSKEY 257 3 252 $K"
zone_case alg253    0 "!unknown DNSSEC algorithm" "k DNSKEY 257 3 253 $K"
zone_case alg254    0 "!unknown DNSSEC algorithm" "k DNSKEY 257 3 254 $K"
zone_case alg17_ok  0 "!is NOT RECOMMENDED" "k DNSKEY 257 3 17 $K"
zone_case alg99     0 "unknown DNSSEC algorithm number 99" "k DNSKEY 257 3 99 $K"
zone_case alg5      0 "DNSSEC algorithm 5 (RSASHA1) is NOT RECOMMENDED" "k DNSKEY 257 3 5 $K"
zone_case alg3      0 "DNSSEC algorithm 3 (DSA) is MUST NOT" "k DNSKEY 257 3 3 $K"
zone_case alg8      0 "!(RFC 8624)" "k DNSKEY 257 3 8 $K"

# ---- CAA ------------------------------------------------------------------------------------------------
zone_case caa_issuemail  0 "!critical flag" "c CAA 128 issuemail \"ca.example\""
zone_case caa_issuevmc   0 "!critical flag" "c CAA 128 issuevmc \"ca.example\""
zone_case caa_issuemail2 0 "!unrecognized tag" "c CAA 0 issuemail \"ca.example\""
zone_case caa_unknown    1 "unknown tag 'foo' with the critical flag set" "c CAA 128 foo \"x\""

# ---- the glue of a sibling delegation (RFC 9471) ------------------------------------------------------------
zone_case sibling_glue 0 "!occluded" "c1 NS ns.c2.z.example.
c2 NS ns.other.example.net.
ns.c2 A 192.0.2.9"
zone_case sibling_glue6 0 "!occluded" "c1 NS ns.c2.z.example.
c2 NS ns.other.example.net.
ns.c2 AAAA 2001:db8::9"
# ... but an address that no delegation uses as a target, and any other type below the cut, still is occluded
zone_case sibling_other 1 "Record 'x.c2.z.example. A' is occluded by delegation at 'c2.z.example.'" "c1 NS ns.c2.z.example.
c2 NS ns.other.example.net.
x.c2 A 192.0.2.9"
zone_case sibling_txt   1 "Record 'ns.c2.z.example. TXT' is occluded by delegation at 'c2.z.example.'" "c1 NS ns.c2.z.example.
c2 NS ns.other.example.net.
ns.c2 TXT \"x\""
zone_case own_glue      0 "!occluded" "c2 NS ns.c2.z.example.
ns.c2 A 192.0.2.9"

# ---- singleton types (BIND: multiple RRs of singleton type) ---------------------------------------------------
zone_case cname_two     1 "more than one CNAME record (RFC 1034 section 3.6.2)" "a CNAME b.z.example.
a CNAME c.z.example."
zone_case cname_same    0 "!singleton" "a CNAME b.z.example.
a CNAME b.z.example."
zone_case dname_two     1 "more than one DNAME record (RFC 6672 section 2.4)" "d DNAME b.z.example.
d DNAME c.z.example."

# ---- NSEC3 iterations: above 150 the server does not load the zone (RFC 9276 3.2) ---------------------------------
zone_case n3p_151       1 "has 151 NSEC3 iterations; more than 150 is refused" '@ NSEC3PARAM 1 0 151 -'
zone_case n3p_5000      1 "has 5000 NSEC3 iterations; more than 150 is refused" '@ NSEC3PARAM 1 0 5000 -'
zone_case n3_151        1 "NSEC3 at '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.z.example.' has 151 NSEC3 iterations" '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom NSEC3 1 0 151 - 2vptu5timamqttgl4luu9kg21e0aor3s A'
zone_case n3p_150       1 "iterations value is excessively high" '@ NSEC3PARAM 1 0 150 -'
zone_case n3p_150_load  1 "!more than 150 is refused" '@ NSEC3PARAM 1 0 150 -'

# ---- zone file syntax ---------------------------------------------------------------------------------------
raw_zone dir_unknown 1 "unknown directive '\$foo'" '$ORIGIN z.example.
$TTL 300
@ SOA ns.z.example. h.z.example. 1 7200 3600 1209600 300
$foo bar'
raw_zone dir_origin  1 "\$ORIGIN requires a domain name" '$ORIGIN
$TTL 300
@ SOA ns.z.example. h.z.example. 1 7200 3600 1209600 300'
raw_zone no_owner    1 "no current owner name" '$ORIGIN z.example.
$TTL 300
  IN SOA ns.z.example. h.z.example. 1 7200 3600 1209600 300'
raw_zone esc_300     1 "bad escape: \\DDD is a decimal number from 000 to 255" "$ZHEAD
t HINFO \"a\\300\" \"b\""
raw_zone esc_nul     1 "\\000 (a NUL octet) cannot be held in this field" "$ZHEAD
t HINFO \"a\\000\" \"b\""
raw_zone txt_nul     0 "0 error(s)" "$ZHEAD
t TXT \"a\\000b\" \"c\""
raw_zone txt_hash    0 "0 error(s)" "$ZHEAD
t TXT \"#\" \"1\" \"ab\""
raw_zone tag_bad     1 "\$LOCATION-TAG: 'notacidr' is not an address or CIDR" "$ZHEAD
\$LOCATION-TAG lo 127.0.0.0/8 notacidr"
raw_zone tag_ok      0 "0 error(s)" "$ZHEAD
\$LOCATION-TAG lo 127.0.0.0/8 any"

# ---- tinydns -------------------------------------------------------------------------------------------
td_case ttl_alpha   1 "Invalid TTL in tinydns record" '+www.example.com:192.0.2.10:abc'
td_case ttl_signed  1 "Invalid TTL in tinydns record" '+www.example.com:192.0.2.10:-1'
td_case ttl_ok      0 "0 error(s)" '+www.example.com:192.0.2.10:300'
# 0.6.2 (audit: numeric RDATA fields): digits only and within the size of the field; strtoul read "10x" as 10 and "abc" as 0
td_case mx_alpha    1 "Invalid MX distance in tinydns record" '@example.com:192.0.2.11:mx:10x'
td_case mx_big      1 "Invalid MX distance in tinydns record" '@example.com:192.0.2.11:mx:65536'
td_case mx_ok       0 "0 error(s)" '@example.com:192.0.2.11:mx:65535'
td_case srv_port    1 "Invalid SRV port in tinydns record" 'S_sip._udp.example.com:192.0.2.12:sip.example.com:70000:1:2'
td_case srv_weight  1 "Invalid SRV weight in tinydns record" 'S_sip._udp.example.com:192.0.2.12:sip.example.com:5060:w:2'
td_case srv_prio    1 "Invalid SRV priority in tinydns record" 'S_sip._udp.example.com:192.0.2.12:sip.example.com:5060:1:-2'
td_case srv_ok      0 "0 error(s)" 'S_sip._udp.example.com:192.0.2.12:sip.example.com:5060:1:2'
td_case naptr_order 1 "Invalid NAPTR order in tinydns record" 'Nexample.com:1a:10:u:E2U+sip:!^.*$!sip\072info@example.com!:.'
td_case naptr_pref  1 "Invalid NAPTR preference in tinydns record" 'Nexample.com:100:99999:u:E2U+sip:!^.*$!sip\072info@example.com!:.'
td_case sshfp_alg   1 "Invalid SSHFP algorithm in tinydns record" "_host.example.com:256:1:$H20"
td_case sshfp_type  1 "Invalid SSHFP fingerprint type in tinydns record" "_host.example.com:4:x:$H20"
td_case gen_type    1 "Invalid type number in tinydns generic record" ':gen.example.com:16x:\003abc'
td_case gen_big     1 "Invalid type number in tinydns generic record" ':gen.example.com:99999999999:\003abc'
td_case gen_ok      0 "0 error(s)" ':gen.example.com:16:\003abc'
i=0
: > "$TMP/loc4097.txt"
while [ $i -lt 4097 ]; do printf '%%l%d:10.%d.%d.0/24\n' "$i" $((i / 256)) $((i % 256)) >> "$TMP/loc4097.txt"; i=$((i + 1)); done
td_case loc_4097    1 "Too many location lines" "$(cat "$TMP/loc4097.txt")"
head -4096 "$TMP/loc4097.txt" > "$TMP/loc4096.txt"
td_case loc_4096    0 "!Too many location lines" "$(cat "$TMP/loc4096.txt")"

# ---- $INCLUDE (0.6.2, audit M11): read as the server reads it ----------------------------------------------------------
printf 'inc A 192.0.2.44\n' > "$TMP/real.inc"
ln -s "$TMP/real.inc" "$TMP/link.inc"
mkfifo "$TMP/fifo.inc"
zone_case inc_ok      0 "0 error(s)" "\$INCLUDE real.inc"
zone_case inc_symlink 1 "\$INCLUDE file could not be read" "\$INCLUDE link.inc"
# a FIFO must not block the open (no writer comes): bounded with timeout(1) where there is one
TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 20"
f="$TMP/inc_fifo.zone"; printf '%s\n%s\n' "$ZHEAD" '$INCLUDE fifo.inc' > "$f"
out=$($TO "$KC" zone z.example. "$f" 2>&1); rc=$?
check "zone:inc_fifo" 1 "\$INCLUDE file could not be read" "$out" "$rc"

echo "=== karicheck low batch L4: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
