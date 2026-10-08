#!/bin/sh
# ==============================================================================
# run_karicheck_matrix_test.sh
#
# Fixture matrix for karicheck: every diagnostic below is provoked by a minimal input and the exit status
# plus the message are asserted. Covers
#   * RDATA field validation (SRV, NAPTR, CAA, SSHFP, HIP, WKS, EUI48/64, DSYNC, CSYNC, ZONEMD)
#   * DNSSEC parameter lint (NSEC3PARAM flags / iterations / salt / algorithm, NSEC3 chains, RFC 5155, RFC 9276)
#   * glue: NS targets without addresses are errors, MX/SRV targets only warnings (K-02)
#   * zone structure (missing/duplicate SOA, missing NS, empty zone, unreadable file, CNAME coexistence)
#   * tinydns-data zones (generic/SRV/NAPTR/IPv6 record checks, duplicate location codes)
#   * catalog zones (RFC 9432 version property, orphaned group properties)
#   * config lint (program/forward zones, allow-program-zones, ecs/location CIDRs, syntax errors)
#   * command-line handling (usage, --version, unknown zone)
# Exit status contract: 1 when at least one [ERROR] is reported, 0 for clean zones and for warnings only.
# For every single-zone check the [RESULT] counts must equal the [ERROR]/[WARNING] lines printed (K-04).
# The binary can be overridden with KARICHECK=/path/to/karicheck (used for instrumented builds).
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

TMP="$(mktemp -d "${TMPDIR:-/tmp}/karicheck_matrix.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM
PASS=0
FAIL=0

# check <label> <expected-exit> <fixed-string-pattern> <output> <actual-exit>
check() {
    label="$1"; want_exit="$2"; pat="$3"; out="$4"; got_exit="$5"
    if [ "$got_exit" -ne "$want_exit" ]; then
        echo "  FAIL [$label]: exit $got_exit, expected $want_exit"; echo "$out" | head -8 | sed 's/^/      /'
        FAIL=$((FAIL + 1)); return
    fi
    if [ -n "$pat" ] && ! printf '%s\n' "$out" | grep -qF -- "$pat"; then
        echo "  FAIL [$label]: message not found: $pat"; echo "$out" | head -8 | sed 's/^/      /'
        FAIL=$((FAIL + 1)); return
    fi
    PASS=$((PASS + 1))
}

# K-04: with exactly one [RESULT] line, its counts must equal the [ERROR] / [WARNING] lines printed
# check_counts <label> <output>
check_counts() {
    [ "$(printf '%s\n' "$2" | grep -c '^\[RESULT\]')" -eq 1 ] || return 0
    e=$(printf '%s\n' "$2" | grep -c '^\[ERROR\]')
    w=$(printf '%s\n' "$2" | grep -c '^\[WARNING\]')
    if printf '%s\n' "$2" | grep -q "^\[RESULT\] Zone '.*': $e error(s), $w warning(s)\$"; then
        PASS=$((PASS + 1))
    else
        echo "  FAIL [$1:counts]: $e [ERROR] and $w [WARNING] lines printed, but:"
        printf '%s\n' "$2" | grep '^\[RESULT\]' | sed 's/^/      /'
        FAIL=$((FAIL + 1))
    fi
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
    check_counts "zone:$1" "$out"
}
# raw_zone <label> <expected-exit> <pattern> <complete zone text>
raw_zone() {
    f="$TMP/$1.zone"
    printf '%s\n' "$4" > "$f"
    out=$("$KC" zone z.example. "$f" 2>&1); rc=$?
    check "raw:$1" "$2" "$3" "$out" "$rc"
    check_counts "raw:$1" "$out"
}
# conf_case <label> <subcommand> <expected-exit> <pattern> <config text>
conf_case() {
    f="$TMP/$1.conf"
    printf '%s\n' "$5" > "$f"
    out=$("$KC" "$2" "$f" 2>&1); rc=$?
    check "conf:$1" "$3" "$4" "$out" "$rc"
}
# td_case <label> <expected-exit> <pattern> <tinydns lines after the SOA/NS line>
td_case() {
    d="$TMP/td_$1.data"
    printf '.example.com:192.0.2.1:a.ns.example.com:300\n%s\n' "$4" > "$d"
    printf 'zone "example.com" { type master; file "%s"; file-format tinydns; };\n' "$d" > "$TMP/td_$1.conf"
    out=$("$KC" zones "$TMP/td_$1.conf" 2>&1); rc=$?
    check "tinydns:$1" "$2" "$3" "$out" "$rc"
    check_counts "tinydns:$1" "$out"
}

echo "=== Running karicheck Diagnostic Matrix ==="

# ---- clean zone: no false positives -----------------------------------------------------------------
zone_case clean 0 "0 error(s)" '_sip._tcp SRV 10 60 5060 ns.z.example.
n NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .
c CAA 0 issue "letsencrypt.org"
s SSHFP 1 1 AABBCCDDEEFF00112233445566778899AABBCCDD
@ NSEC3PARAM 1 0 0 -
w WKS 192.0.2.1 6 25
e EUI48 00-00-5e-00-53-2a'

# ---- RDATA field validation (ERROR) -------------------------------------------------------------------
zone_case srv_short   1 "SRV record requires 4 fields" '_s._tcp SRV 1 2 3'
zone_case srv_prio    1 "SRV priority '70000' out of range (0-65535)" '_s._tcp SRV 70000 2 3 ns.z.example.'
zone_case srv_weight  1 "SRV weight '70000' out of range (0-65535)" '_s._tcp SRV 1 70000 3 ns.z.example.'
zone_case srv_port    1 "SRV port '70000' out of range (0-65535)" '_s._tcp SRV 1 2 70000 ns.z.example.'
zone_case naptr_short 1 "NAPTR record requires 6 fields" 'n NAPTR 1 2 "u" "E2U+sip"'
zone_case naptr_order 1 "NAPTR order '70000' out of range (0-65535)" 'n NAPTR 70000 1 "u" "E2U+sip" "!^.*$!sip:a@b!" .'
zone_case naptr_pref  1 "NAPTR preference '70000' out of range (0-65535)" 'n NAPTR 1 70000 "u" "E2U+sip" "!^.*$!sip:a@b!" .'
zone_case naptr_flags 1 "must contain only [A-Za-z0-9] characters" 'n NAPTR 1 1 "X!" "E2U+sip" "!^.*$!sip:a@b!" .'
zone_case naptr_both  1 "sets both a regexp and a non-root replacement" 'n NAPTR 1 1 "u" "E2U+sip" "!^.*$!sip:a@b!" x.z.example.'
zone_case caa_short   1 "CAA record requires 3 fields" 'c CAA 0 issue'
zone_case caa_flags   1 "CAA flags '300' out of range (0-255)" 'c CAA 300 issue "x"'
zone_case caa_tag     1 "does not match RFC 8659 syntax" 'c CAA 0 "bad tag!" "x"'
zone_case caa_crit    1 "unknown tag 'foo' with the critical flag set" 'c CAA 128 foo "x"'
zone_case sshfp_short 1 "SSHFP record requires 3 fields" 's SSHFP 1 1'
zone_case sshfp_alg   1 "SSHFP algorithm '300' out of range (0-255)" 's SSHFP 300 1 AABB'
zone_case sshfp_fp    1 "SSHFP fp_type '300' out of range (0-255)" 's SSHFP 1 300 AABB'
zone_case sshfp_hex   1 "SSHFP invalid fingerprint hex string 'XYZ'" 's SSHFP 1 1 XYZ'
zone_case hip_b64     1 "is not valid base64" 'h HIP 2 200100107B1A74DF365639CC39F1D578 AwE rvs.z.example.'
zone_case wks_proto   1 "WKS record protocol '999' is neither a number (0-255) nor TCP/UDP" 'w WKS 192.0.2.1 999 25'
zone_case eui48       1 "EUI48 requires 6 octets" 'e EUI48 00-00-5e-00-53'
zone_case eui64       1 "EUI64 requires 8 octets" 'e EUI64 00-00-5e-ef-10-00-00'
zone_case dsync       1 "DSYNC record has unknown RRtype mnemonic 'FOO'" 'd DSYNC FOO NOTIFY 5300 s.z.example.'
zone_case a_bad       1 "Syntax error in" 'x A 300.1.1.1'
zone_case aaaa_bad    1 "Syntax error in" 'x AAAA gggg::1'
zone_case gpos_bad    1 "Syntax error in" 'g GPOS 1 2'
zone_case cname_soa   1 "coexists with other record type 'SOA'" '@ CNAME x.z.example.'
# an RDATA problem that is also unserializable must say so (the server would drop the record)
zone_case unserial    1 "cannot be serialized to wire format" '_s._tcp SRV 1 2 70000 ns.z.example.'

# ---- lint warnings: reported, exit status stays 0 ----------------------------------------------------
zone_case caa_bits    0 "sets undefined flag bits (0x01)" 'c CAA 1 issue "x"'
zone_case caa_unknown 0 "has unrecognized tag 'foo'" 'c CAA 0 foo "x"'
zone_case n3p_iter    0 "iterations 10; the iteration count MUST be 0 (RFC 9276 section 3.1)" '@ NSEC3PARAM 1 0 10 -'
zone_case n3p_alg     0 "only 1 (SHA-1) is defined (RFC 5155 section 4.1.1)" '@ NSEC3PARAM 2 0 0 -'
zone_case n3p_salt    0 "uses salt AABB; operators SHOULD NOT use a salt (RFC 9276 section 3.1)" '@ NSEC3PARAM 1 0 0 AABB'
zone_case n3p_nochain 0 "has no NSEC3 RRs with the parameters of the NSEC3PARAM the server uses" '@ NSEC3PARAM 1 0 0 -'
zone_case zonemd_apex 0 "is not at the zone apex" 'zm ZONEMD 1 1 1 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899'
zone_case csync_type  0 "CSYNC record contains unknown type 'BOGUS'" '@ CSYNC 66 3 A BOGUS'

# ---- DNSSEC parameter errors -------------------------------------------------------------------------
zone_case n3p_optout  1 "MUST be ignored (RFC 5155 section 4.1.2), so the server ignores it" '@ NSEC3PARAM 1 1 0 -'
zone_case n3p_flags   1 "has Flags 2; the Flags field must be 0" '@ NSEC3PARAM 1 2 0 -'
zone_case n3p_unusable 1 "None of the 1 NSEC3PARAM RRs of zone 'z.example.' is usable" '@ NSEC3PARAM 1 1 0 -'
zone_case n3p_high    1 "iterations value is excessively high" '@ NSEC3PARAM 1 0 5000 -'

# ---- NSEC3 chains (K-05): checked once per chain, against the NSEC3PARAM the server uses ------------------
N3A='0p9mhaveqvm6t7vbl5lop2u3t2rp3tom'
N3B='2vptu5timamqttgl4luu9kg21e0aor3s'
zone_case n3_match    0 "0 error(s), 0 warning(s)" "@ NSEC3PARAM 1 0 0 -
$N3A NSEC3 1 0 0 - $N3B A RRSIG
$N3B NSEC3 1 0 0 - $N3A NS SOA RRSIG DNSKEY NSEC3PARAM"
zone_case n3p_nonapex 0 "NSEC3PARAM 'x.z.example.' is not at the zone apex 'z.example.'" 'x NSEC3PARAM 1 0 0 -'
zone_case n3_noparam  0 "matches no NSEC3PARAM with Flags 0 at the apex; the server does not use it" "$N3A NSEC3 1 0 0 - $N3B A
$N3B NSEC3 1 0 0 - $N3A NS SOA"
zone_case n3_otherparam 0 "NSEC3 chain (hash algorithm 1, iterations 0, salt -; 2 RRs) in zone 'z.example.' matches no NSEC3PARAM" "@ NSEC3PARAM 1 0 0 AABB
$N3A NSEC3 1 0 0 - $N3B A
$N3B NSEC3 1 0 0 - $N3A NS SOA"
# a chain with iterations 5 and a salt: one warning each for the whole chain, not one per NSEC3 RR
printf '%s\n@ NSEC3PARAM 1 0 5 CCDD\n%s NSEC3 1 1 5 CCDD %s A\n%s NSEC3 1 1 5 CCDD %s NS SOA\n' \
    "$ZHEAD" "$N3A" "$N3B" "$N3B" "$N3A" > "$TMP/n3_once.zone"
out=$("$KC" zone z.example. "$TMP/n3_once.zone" 2>&1); rc=$?
check "zone:n3_once" 0 "NSEC3 chain (iterations 5, salt CCDD; 2 RRs) in zone 'z.example.': the iteration count MUST be 0" "$out" "$rc"
check_counts "zone:n3_once" "$out"
for pat in "the iteration count MUST be 0" "uses a salt; operators SHOULD NOT use a salt" "NSEC3 opt-out is set on 2 RR(s)"; do
    n=$(printf '%s\n' "$out" | grep "^\[WARNING\] NSEC3 " | grep -cF "$pat")
    if [ "$n" -eq 1 ]; then PASS=$((PASS + 1)); else echo "  FAIL [zone:n3_once]: '$pat' printed $n times for the chain"; FAIL=$((FAIL + 1)); fi
done

# ---- glue (K-02): NS targets need an address, MX/SRV targets only get a warning ---------------------------
zone_case ns_noaddr   1 "In-bailiwick NS target 'ns2.z.example.' lacks A/AAAA glue record" '@ NS ns2.z.example.'
zone_case mx_noaddr   0 "In-bailiwick MX target 'mail.z.example.' has no A/AAAA record in zone 'z.example.'" '@ MX 10 mail.z.example.'
zone_case srv_noaddr  0 "In-bailiwick SRV target 'sip.z.example.' has no A/AAAA record" '_sip._tcp SRV 10 60 5060 sip.z.example.'
# the same name as MX target first and NS target later: the NS error is still reported
zone_case mx_then_ns  1 "In-bailiwick NS target 'x.z.example.' lacks A/AAAA glue record" '@ MX 10 x.z.example.
sub NS x.z.example.'
zone_case ns_once     1 "0 warning(s)" '@ NS ns2.z.example.'

# ---- WKS (K-03): protocol names like the server; port names from the server's table (X-38) ----------------
zone_case wks_names   0 "0 error(s), 0 warning(s)" 'w WKS 192.0.2.1 TCP 25 80
u WKS 192.0.2.1 udp 53
s WKS 192.0.2.1 TCP smtp HTTP 443
d WKS 192.0.2.1 UDP domain biff'
# a port the server cannot encode: warning for the port and error for the record (the server leaves it out)
zone_case wks_port    1 "1 error(s), 1 warning(s)" 'w WKS 192.0.2.1 TCP smtp 70000'
zone_case wks_badname 1 "1 error(s), 1 warning(s)" 'w WKS 192.0.2.1 UDP exec'

# ---- counting (K-04): warnings that were printed but not counted before ----------------------------------
zone_case count_ds    0 "0 error(s), 1 warning(s)" 'k DS 1 8 1 0123456789abcdef0123456789abcdef01234567'
zone_case count_mixed 1 "1 error(s), 1 warning(s)" 'k DS 1 8 1 0123456789abcdef0123456789abcdef01234567
@ NS ns2.z.example.'

# ---- zone structure ----------------------------------------------------------------------------------
raw_zone nosoa   1 "No SOA record found in zone 'z.example.'" '$ORIGIN z.example.
$TTL 300
@ NS ns.z.example.
ns A 192.0.2.1'
raw_zone twosoa  1 "has 2 SOA records at the apex" '$ORIGIN z.example.
$TTL 300
@ SOA ns h 1 2 3 4 5
@ SOA ns h 2 2 3 4 5
@ NS ns.z.example.
ns A 192.0.2.1'
raw_zone nons    1 "No NS record found at zone apex" '$ORIGIN z.example.
$TTL 300
@ SOA ns h 1 2 3 4 5
ns A 192.0.2.1'
# An empty file is an error; the wording depends on how the path was given (relative: "Syntax error",
# absolute: "No records found"), so only the [ERROR] class is asserted.
raw_zone empty   1 "[ERROR]" ''
out=$("$KC" zone z.example. /nonexistent/x.zone 2>&1); rc=$?
check "missing-file" 1 "Could not open file" "$out" "$rc"
# D-24: the server opens absolute and "../" zone paths, so karicheck no longer warns about them
case "$out" in
    *"absolute or contains '../'"*) echo "  FAIL [no-absolute-path-warning]: warning still printed"; FAIL=$((FAIL + 1)) ;;
    *) PASS=$((PASS + 1)) ;;
esac

# ---- tinydns-data zones ------------------------------------------------------------------------------
td_case hex3       1 "type '3' requires a 32-character hexadecimal IPv6 address" '3www.example.com:20010db8:300'
td_case hex6_info  0 "type '6' generates deprecated PTR" '6www.example.com:20010db8000000000000000000000001:300'
td_case srv_range  1 "out of range (0-65535)" 'Sexample.com:5.srv.example.com:5060:70000:20:300'
td_case naptr_pref 1 "NAPTR preference '70000' out of range" 'Nexample.com:1:70000:u:E2U+sip:!^.*$!sip:a@b!:.:300'
td_case sshfp_gen  1 "SSHFP record requires 3 fields" ':sshfp.example.com:44:\001\001\252\273:300'
td_case loc_dup    0 "Duplicate location code 'lo'" '%lo:10.0
%lo:10.1'
td_case clean      0 "0 error(s), 0 warning(s)" '=www.example.com:192.0.2.10:300
+alias.example.com:192.0.2.11:300'

# ---- catalog zones (RFC 9432) --------------------------------------------------------------------------
printf '$ORIGIN cat.example.\n$TTL 300\n@ SOA ns h 1 2 3 4 5\n@ NS ns.cat.example.\nns A 192.0.2.1\nx.zones PTR m.example.\n' > "$TMP/catbad.zone"
printf 'zone "cat.example" { type master; file "%s/catbad.zone"; catalog-zone yes; };\n' "$TMP" > "$TMP/catbad.conf"
out=$("$KC" zones "$TMP/catbad.conf" 2>&1); rc=$?
check "catalog:missing-version" 1 "is missing 'version.cat.example." "$out" "$rc"
printf '$ORIGIN cat.example.\n$TTL 300\n@ SOA ns h 1 2 3 4 5\n@ NS ns.cat.example.\nns A 192.0.2.1\nversion TXT "2"\nx.zones PTR m.example.\ngrp.x.zones TXT "g"\norph.zones TXT "g"\n' > "$TMP/catok.zone"
printf 'zone "cat.example" { type master; file "%s/catok.zone"; catalog-zone yes; };\n' "$TMP" > "$TMP/catok.conf"
out=$("$KC" zones "$TMP/catok.conf" 2>&1); rc=$?
check "catalog:valid-version" 0 "" "$out" "$rc"

# ---- config lint ---------------------------------------------------------------------------------------
conf_case prog_nopath   conf 1 "has type 'program' but no 'program' path specified" 'options { allow-program-zones yes; };
zone "p.example" { type program; };'
conf_case fwd_nofwd     conf 1 "has type 'forward' but no 'forwarders' specified" 'zone "f.example" { type forward; };'
conf_case prog_denied   conf 1 "'allow-program-zones' is not enabled" 'zone "p.example" { type program; program "/bin/true"; };'
conf_case prog_notexec  conf 0 "is not executable (access X_OK failed" 'options { allow-program-zones yes; };
zone "p.example" { type program; program "/nonexistent/prog"; };'
conf_case prog_skipped  zones 0 "Checked 0 zones (1 skipped)" 'options { allow-program-zones yes; };
zone "p.example" { type program; program "/bin/true"; };'
conf_case ecs_badcidr   conf 1 "Invalid CIDR '999.0.0.0/8' in options.ecs-tags" 'options { ecs-enable yes; ecs-tags { tag "a" { 999.0.0.0/8; }; }; };'
conf_case loc_badcidr   conf 1 "Invalid CIDR '10.0.0.0/99' in options.location-tags" 'options { location-tags { tag "a" { 10.0.0.0/99; }; }; };'
conf_case zone_ecs_bad  conf 1 "Invalid CIDR '10.0.0.0/99' in ecs-tags tag 'a'" 'options { ecs-enable yes; };
zone "z.example" { type master; file "x"; ecs-tags { tag "a" { 10.0.0.0/99; }; }; };'
conf_case zone_loc_bad  conf 1 "Invalid CIDR '10.0.0.0/99' in location-tags tag 'a'" 'zone "z.example" { type master; file "x"; location-tags { tag "a" { 10.0.0.0/99; }; }; };'
conf_case ecs_disabled  conf 0 "ecs-tags defined, but ecs-enable is not set" 'options { ecs-tags { tag "a" { 10.0.0.0/8; }; }; };'
conf_case syntax        conf 1 "Syntax error in config file" 'options { port ; ; zone'
conf_case ok            conf 0 "" 'options { };'
conf_case zones_nofile  zones 1 "Could not open file" 'zone "m.example" { type master; file "/nonexistent/m.zone"; };
zone "s.example" { type slave; file "s"; masters { 192.0.2.1; }; };'
out=$("$KC" conf /nonexistent/x.conf 2>&1); rc=$?
check "conf:missing" 1 "Could not open file" "$out" "$rc"
# the shipped sample must stay loadable; its placeholder secrets are flagged but are not errors
out=$("$KC" conf karidns.conf.sample 2>&1); rc=$?
check "conf:sample" 0 "is valid" "$out" "$rc"
check "conf:sample-placeholder" 0 "secret is still the sample placeholder" "$out" "$rc"
conf_case tcp_opts      conf 0 "is valid" 'options { tcp-mss 1220; tcp-window 256K; udp-bufsize 1232; };
zone "t.example" { type master; file "t.zone"; zone-tcp-mss 1200; zone-tcp-window 128K; zone-tcp-sndbuf 2M; zone-udp-bufsize 1400; };'
conf_case tcp_opts_bad  conf 1 "invalid zone-tcp-sndbuf value" 'zone "t.example" { type master; file "t.zone"; zone-tcp-sndbuf 2MB; };'
conf_case bad_b64       conf 1 "secret is not valid base64" 'key "k" { algorithm "hmac-sha256"; secret "NOT_BASE64="; };'
conf_case bad_b64_ctl   conf 1 "control-channel: secret is not valid base64" 'control-channel { algorithm "hmac-sha256"; secret "NOT_BASE64="; };'
printf '$ORIGIN m.example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$TMP/m.zone"
printf 'zone "m.example" { type master; file "%s/m.zone"; };\nzone "p.example" { type program; program "/bin/true"; };\noptions { allow-program-zones yes; };\n' "$TMP" > "$TMP/zm.conf"
out=$("$KC" zone m.example. "$TMP/zm.conf" 2>&1); rc=$?
check "zone-from-conf" 0 "0 error(s), 0 warning(s)" "$out" "$rc"
out=$("$KC" zone p.example. "$TMP/zm.conf" 2>&1); rc=$?
check "zone-from-conf:program" 0 "is type 'program'; skipping file validation" "$out" "$rc"
out=$("$KC" zone nozone.example. "$TMP/zm.conf" 2>&1); rc=$?
check "zone-from-conf:unknown" 1 "not found in config" "$out" "$rc"

# ---- command line --------------------------------------------------------------------------------------
out=$("$KC" 2>&1); rc=$?;            check "cli:no-args" 1 "Usage:" "$out" "$rc"
out=$("$KC" zone 2>&1); rc=$?;       check "cli:zone-without-domain" 1 "Usage:" "$out" "$rc"
out=$("$KC" bogus 2>&1); rc=$?;      check "cli:unknown-command" 1 "Usage:" "$out" "$rc"
out=$("$KC" --version 2>&1); rc=$?;  check "cli:version" 0 "karicheck " "$out" "$rc"
out=$("$KC" -v 2>&1); rc=$?;         check "cli:version-short" 0 "karicheck " "$out" "$rc"

echo "=== karicheck matrix: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
