#!/bin/sh
# karicheck zone: the NSEC chain (RFC 4034 sections 4.1.1, 4.1.2, 6.1; RFC 4035 section 2.3) and the SOA timers (RFC 1912 section 2.2,
# RFC 2308 section 5), the checks of dns_zone_lint.c that karidns-dbloader --check runs as well (0.7 review).  A zone with a correct chain
# and sane timers gets none of these warnings; a zone with one fault of each kind gets each warning, and the exit status stays 0 (warnings).
# No real names (.test).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.." || exit 1
KC=${KC:-./karicheck}
[ -x "$KC" ] || { echo "SKIP: no $KC"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/kc_nsec.XXXXXX")
trap 'rm -rf "$W"' EXIT INT TERM
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }

cat > "$W/good.zone" <<'EOF'
$ORIGIN good.test.
$TTL 3600
@ IN SOA ns1 hostmaster ( 1 7200 1800 1209600 3600 )
@ IN NS ns1
@ IN NSEC host.good.test. NS SOA NSEC
host IN A 192.0.2.10
host IN NSEC ns1.good.test. A NSEC
ns1 IN A 192.0.2.1
ns1 IN NSEC sub.good.test. A NSEC
sub IN NS ns.example.
sub IN NSEC good.test. NS NSEC
EOF

cat > "$W/bad.zone" <<'EOF'
$ORIGIN bad.test.
$TTL 3600
@ IN SOA ns1 hostmaster ( 1 600 900 1000 172800 )
@ IN NS ns1
@ IN NSEC host.bad.test. SOA NSEC
host IN A 192.0.2.10
host IN NSEC zzz.bad.test. A NSEC
host IN NSEC yyy.bad.test. A NSEC
mail IN A 192.0.2.11
ns1 IN A 192.0.2.1
ns1 IN NSEC sub.bad.test. A MX NSEC
sub IN NS ns.example.
sub IN NSEC other.bad.test. NS NSEC
x.sub IN NSEC bad.test. A NSEC
EOF

# 1. the good zone: none of the new findings, exit 0
"$KC" --json zone good.test "$W/good.zone" > "$W/good.json" 2> "$W/good.err"; rc=$?
[ "$rc" -eq 0 ] || fail "good zone: exit $rc: $(cat "$W/good.err") $(head -c 600 "$W/good.json")"
if grep -Eq '"zone\.(nsec|soa)\.(duplicate|not-authoritative|next|not-closed|missing|bitmap|retry|expire|minimum)"' "$W/good.json"; then
    fail "good zone has a finding of the chain or the timers: $(cat "$W/good.json")"
fi

# 2. the bad zone: each finding once at least, warnings only (exit 0)
"$KC" --json zone bad.test "$W/bad.zone" > "$W/bad.json" 2> "$W/bad.err"; rc=$?
[ "$rc" -eq 0 ] || fail "bad zone: exit $rc (warnings only, want 0): $(head -c 800 "$W/bad.json")"
for code in zone.nsec.duplicate zone.nsec.not-authoritative zone.nsec.next zone.nsec.not-closed zone.nsec.missing zone.nsec.bitmap \
            zone.soa.retry zone.soa.expire zone.soa.minimum; do
    grep -q "\"$code\"" "$W/bad.json" || fail "bad zone: no $code: $(cat "$W/bad.json")"
done

# 3. the text form names what is wrong (the warnings go to stderr)
"$KC" zone bad.test "$W/bad.zone" > "$W/bad.out" 2>&1
grep -q "NSEC record at 'ns1.bad.test.' .*not listed: NS\|bitmap of the NSEC record at 'bad.test.' .*not listed: NS" "$W/bad.out" || fail "the apex bitmap without NS is not named: $(grep -i bitmap "$W/bad.out")"
grep -q "at 'ns1.bad.test.' .*listed but not there: MX" "$W/bad.out" || fail "the MX listed at ns1 is not named: $(grep -i bitmap "$W/bad.out")"
grep -q "Name 'mail.bad.test.' .*no NSEC record" "$W/bad.out" || fail "the gap at mail is not named: $(grep -i "no NSEC" "$W/bad.out")"
grep -q "names 'other.bad.test.', not the apex" "$W/bad.out" || fail "the open chain is not named: $(grep -i "closed" "$W/bad.out")"
grep -q "retry interval 900 is longer than the refresh interval 600" "$W/bad.out" || fail "retry > refresh: $(grep -i retry "$W/bad.out")"
grep -q "expire time 1000 is shorter than refresh + retry (600 + 900)" "$W/bad.out" || fail "expire < refresh + retry: $(grep -i expire "$W/bad.out")"
grep -q "minimum 172800" "$W/bad.out" || fail "minimum over a day: $(grep -i minimum "$W/bad.out")"

# 4. expire not greater than the minimum (expire >= refresh + retry)
sed -e 's/( 1 7200 1800 1209600 3600 )/( 1 7200 1800 9000 9000 )/' "$W/good.zone" > "$W/exp.zone"
"$KC" zone good.test "$W/exp.zone" > "$W/exp.out" 2>&1
grep -q "expire time 9000 is not greater than the minimum 9000" "$W/exp.out" || fail "expire <= minimum: $(cat "$W/exp.out")"

# 5. a zone without NSEC records: no chain findings
grep -v NSEC "$W/bad.zone" > "$W/nonsec.zone"
"$KC" --json zone bad.test "$W/nonsec.zone" > "$W/nonsec.json" 2>/dev/null
grep -q '"zone\.nsec\.' "$W/nonsec.json" && fail "a zone without NSEC got a chain finding: $(cat "$W/nonsec.json")"

[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: karicheck NSEC chain and SOA timer checks"
exit 0
