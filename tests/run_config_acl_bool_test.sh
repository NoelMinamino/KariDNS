#!/bin/sh
# ==============================================================================
# run_config_acl_bool_test.sh
#
# Phase 12 (D-01, D-02, D-22, D-23): configuration parser behaviour seen through karicheck and a
# running server.
#  karicheck conf: invalid boolean values and invalid ACL entries are errors; a category with
#  several channels is accepted with a warning; karicheck zones checks "type Master;" zones and
#  reports skipped ones.
#  karidns: a named acl in allow-transfer allows AXFR from 127.0.0.1, "!acl" refuses it, and
#  "print-time true;" puts the time in the query log.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/karicheck" ] && [ -x "$ROOT_DIR/dag" ] || \
    make -C "$ROOT_DIR" karidns karicheck dag

KARIDNS="$ROOT_DIR/karidns"
KARICHECK="$ROOT_DIR/karicheck"
DAG="$ROOT_DIR/dag"

PORT=$((34000 + $$ % 4000))
TMP_DIR="/tmp/config_acl_bool_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR/logs"
chmod 755 "$TMP_DIR"
chmod 777 "$TMP_DIR/logs"
SERVER_PID=""
FAILED=0

cleanup() {
    kari_kill_tree "$SERVER_PID"
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

for z in acl.example deny.example prog.example; do
cat > "$TMP_DIR/$z.zone" <<EOF
\$TTL 300
@ IN SOA ns1.$z. hostmaster.$z. ( 1 3600 600 86400 60 )
@ IN NS ns1.$z.
ns1 IN A 192.0.2.1
EOF
done
chmod 644 "$TMP_DIR"/*.zone
Z="zone \"acl.example\" { type master; file \"$TMP_DIR/acl.example.zone\"; };"

# karicheck_case <label> <command> <expected exit> <expected text> <config>
karicheck_case() {
    printf '%s\n' "$5" > "$TMP_DIR/case.conf"
    out=$("$KARICHECK" "$2" "$TMP_DIR/case.conf" 2>&1); rc=$?
    if [ "$rc" -ne "$3" ]; then
        fail "$1: exit $rc, expected $3"; printf '%s\n' "$out" | head -5 | sed 's/^/      /'; return
    fi
    if ! printf '%s\n' "$out" | grep -qF -- "$4"; then
        fail "$1: missing '$4'"; printf '%s\n' "$out" | head -5 | sed 's/^/      /'; return
    fi
    pass "$1"
}

echo "=== karicheck ==="
karicheck_case "D-02 serve-stale maybe" conf 1 "invalid serve-stale value 'maybe'" "options { serve-stale maybe; }; $Z"
karicheck_case "D-02 catalog-zone maybe" conf 1 "invalid catalog-zone value 'maybe'" \
    "zone \"acl.example\" { type master; file \"$TMP_DIR/acl.example.zone\"; catalog-zone maybe; };"
karicheck_case "D-02 additional-from-auth bogus" conf 1 "invalid additional-from-auth value 'bogus'" \
    "options { additional-from-auth bogus; }; $Z"
karicheck_case "D-02 TRUE and 0 accepted" conf 0 "is valid" "options { serve-stale TRUE; minimal-any 0; }; $Z"
karicheck_case "D-01 category list" conf 0 "only the first channel ('a') is used, ignoring 'b'" \
    "logging { channel a { file \"$TMP_DIR/logs/a.log\"; }; channel b { file \"$TMP_DIR/logs/b.log\"; }; category queries { a; b; }; }; $Z"
karicheck_case "D-22 bad address" conf 1 "entry '192.0.2.300' is not an address" \
    "zone \"acl.example\" { type master; file \"$TMP_DIR/acl.example.zone\"; allow-transfer { 192.0.2.300; }; };"
karicheck_case "D-22 undefined acl" conf 1 "entry 'secondaries' is not an address" \
    "zone \"acl.example\" { type master; file \"$TMP_DIR/acl.example.zone\"; allow-transfer { secondaries; }; };"
karicheck_case "D-22 localhost" conf 1 "entry 'localhost' is not supported" \
    "zone \"acl.example\" { type master; file \"$TMP_DIR/acl.example.zone\"; allow-transfer { localhost; }; };"
karicheck_case "D-22 acl accepted" conf 0 "is valid" \
    "acl \"xfr\" { 192.0.2.0/24; none; }; zone \"acl.example\" { type master; file \"$TMP_DIR/acl.example.zone\"; allow-transfer { xfr; }; };"
karicheck_case "D-23 type Master checked" zones 0 "Checked 1 zones (1 skipped)" \
    "options { allow-program-zones yes; };
zone \"acl.example\" { type Master; file \"$TMP_DIR/acl.example.zone\"; };
zone \"prog.example\" { type Program; program \"/bin/cat\"; };"

echo "=== karidns ==="
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi
cat > "$TMP_DIR/karidns.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
logging { channel q { file "$TMP_DIR/logs/q.log"; print-time true; }; category queries { q; }; };
zone "acl.example" { type master; file "$TMP_DIR/acl.example.zone"; allow-transfer { xfr; }; };
zone "deny.example" { type master; file "$TMP_DIR/deny.example.zone"; allow-transfer { !lo; any; }; };
acl "lo" { 127.0.0.1; ::1; };
acl "xfr" { 198.51.100.0/24; lo; };
EOF
chmod 644 "$TMP_DIR/karidns.conf"
"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 30 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" acl.example SOA +short +nohexdump 2>/dev/null | grep -q ns1 && break
    sleep 0.2; i=$((i + 1))
done
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi
out=$("$DAG" @127.0.0.1 -p "$PORT" acl.example AXFR +nohexdump 2>&1)
[ "$(printf '%s\n' "$out" | grep -c 'IN[[:space:]]*SOA')" -eq 2 ] && pass "AXFR allowed through acl xfr -> lo" || \
    fail "AXFR through named acl: $(printf '%s\n' "$out" | grep -E 'status|failed' | head -1)"
out=$("$DAG" @127.0.0.1 -p "$PORT" deny.example AXFR +nohexdump 2>&1)
printf '%s\n' "$out" | grep -q "IN[[:space:]]*SOA" && fail "AXFR allowed although !lo comes first" || pass "AXFR refused by !lo"
sleep 1.5
first=$(head -1 "$TMP_DIR/logs/q.log" 2>/dev/null)
case "$first" in
    [0-9][0-9]-[A-Z][a-z][a-z]-[0-9][0-9][0-9][0-9]\ *) pass "print-time true adds the time" ;;
    *) fail "query log line without time: $first" ;;
esac

if [ "$FAILED" -ne 0 ]; then
    echo "--- karidns log ---"; tail -20 "$TMP_DIR/karidns.log"
    echo "RESULT: $FAILED check(s) FAILED"; exit 1
fi
echo "RESULT: all checks passed"
exit 0
