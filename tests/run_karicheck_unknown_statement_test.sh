#!/bin/sh
# run_karicheck_unknown_statement_test.sh - unknown statements inside zone { } and view { } (beta B6a, open item 2,
# decided 2026-10-21).
#
# Until now the parser skipped an unknown statement in a zone or a view without a word, so a typo ("alow-transfer") silently
# left a zone open or closed.  Now: a statement BIND 9 documents for a zone / view statement but KariDNS does not implement
# is skipped with a warning; anything else is a configuration error that names the zone or view and the statement, in
# `karicheck conf` and in `karidns` (startup and reload).  Unknown statements in options / key / logging / unknown
# top-level blocks are still skipped (out of scope, reported only).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
KARIDNS=${KARIDNS:-./karidns}
for b in ./karicheck "$KARIDNS"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_unkstmt.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }

printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$T/a.zone"

# check NAME CONF-BODY EXPECT(ok|error|warn) PATTERN
check() {
    printf '%s\n' "$2" > "$T/c.conf"
    OUT=$(./karicheck conf "$T/c.conf" 2>&1); RC=$?
    case "$3" in
    ok)
        [ $RC -eq 0 ] && ! printf '%s\n' "$OUT" | grep -q "unknown option\|does not implement" && pass "$1" || { fail "$1 (rc $RC)"; printf '%s\n' "$OUT" | head -5 | sed 's/^/         /'; } ;;
    warn)
        [ $RC -eq 0 ] && printf '%s\n' "$OUT" | grep -q "$4" && pass "$1: $(printf '%s\n' "$OUT" | grep -m1 "$4" | cut -c1-110)" || { fail "$1 (rc $RC)"; printf '%s\n' "$OUT" | head -5 | sed 's/^/         /'; } ;;
    error)
        [ $RC -ne 0 ] && printf '%s\n' "$OUT" | grep -q "$4" && pass "$1: $(printf '%s\n' "$OUT" | grep -m1 "$4" | cut -c1-110)" || { fail "$1 (rc $RC)"; printf '%s\n' "$OUT" | head -5 | sed 's/^/         /'; } ;;
    esac
}

echo "== zone { }"
check "a plain zone" "zone \"a.test\" { type primary; file \"$T/a.zone\"; allow-transfer { 192.0.2.1; }; };" ok
check "a typo in a zone" "zone \"a.test\" { type primary; file \"$T/a.zone\"; alow-transfer { 192.0.2.1; }; };" error "zone 'a.test.': unknown option 'alow-transfer'"
check "an unknown option with a value" "zone \"a.test\" { type primary; file \"$T/a.zone\"; frobnicate 3; };" error "unknown option 'frobnicate'"
check "an unknown option with a block" "zone \"a.test\" { type primary; file \"$T/a.zone\"; frobnicate { a; b; }; };" error "unknown option 'frobnicate'"
check "notify-retr... that is not an option" "zone \"a.test\" { type primary; file \"$T/a.zone\"; notify-retry-foo 3; };" error "unknown option 'notify-retry-foo'"
for o in zone-statistics inline-signing key-directory dnssec-policy auto-dnssec max-journal-size allow-query notify check-names masterfile-format; do
    check "BIND option $o" "zone \"a.test\" { type primary; file \"$T/a.zone\"; $o yes; };" warn "option '$o' is a BIND option that KariDNS does not implement"
done
check "BIND option with a block" "zone \"a.test\" { type primary; file \"$T/a.zone\"; update-policy { grant a.test zonesub any; }; };" warn "option 'update-policy' is a BIND option"
check "BIND option and a known one together" "zone \"a.test\" { type primary; file \"$T/a.zone\"; also-notify { 192.0.2.9; }; notify explicit; };" warn "option 'notify' is a BIND option"

echo "== view { }"
check "a plain view" "view \"v\" { match-clients { any; }; zone \"a.test\" { type primary; file \"$T/a.zone\"; }; };" ok
check "a typo in a view" "view \"v\" { match-clients { any; }; mach-clients { any; }; zone \"a.test\" { type primary; file \"$T/a.zone\"; }; };" error "view 'v': unknown option 'mach-clients'"
check "an unknown option in a zone of a view" "view \"v\" { zone \"a.test\" { type primary; file \"$T/a.zone\"; nonsense yes; }; };" error "zone 'a.test.': unknown option 'nonsense'"
for o in recursion allow-query dnssec-validation max-cache-size zone-statistics minimal-responses; do
    check "BIND option $o in a view" "view \"v\" { match-clients { any; }; $o yes; zone \"a.test\" { type primary; file \"$T/a.zone\"; }; };" warn "view 'v': option '$o' is a BIND option that KariDNS does not implement"
done

echo "== elsewhere nothing changes"
check "an unknown option in options { }" "options { nonsense-option yes; }; zone \"a.test\" { type primary; file \"$T/a.zone\"; };" ok
check "an unknown top-level block" "frobnicate-block { a; }; zone \"a.test\" { type primary; file \"$T/a.zone\"; };" ok

echo "== karidns refuses the same configuration"
printf 'options { user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port 1; };\nzone "a.test" { type primary; file "%s/a.zone"; alow-transfer { any; }; };\n' "$T" > "$T/bad.conf"
OUT=$(timeout 10 "$KARIDNS" -c "$T/bad.conf" -f 2>&1); RC=$?
[ $RC -ne 0 ] && [ $RC -ne 124 ] && printf '%s\n' "$OUT" | grep -q "unknown option 'alow-transfer'" && pass "karidns -c refuses to start: $(printf '%s\n' "$OUT" | grep -m1 "unknown option" | cut -c1-110)" || { fail "karidns with a typo: rc $RC"; printf '%s\n' "$OUT" | head -5 | sed 's/^/         /'; }

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_karicheck_unknown_statement_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_karicheck_unknown_statement_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
