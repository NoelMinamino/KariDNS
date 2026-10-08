#!/bin/sh
# run_view_same_zone_test.sh - the same zone name in two views serves each view's own data (R-26),
# also after SIGHUP and karictl reload, including glue from sibling zones of the same view and a
# type "program" zone whose plugin differs per view (O-12).
#
# The views are selected by the client address: 127.0.0.1 (internal) and ::1 (external), so no
# loopback alias and no root are needed. SKIP when ::1 is not configured.

. "$(dirname "$0")/lib_proc.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="$BASE_DIR/karidns"
DAG="$BASE_DIR/dag"
KARICTL="$BASE_DIR/karictl"
KARICHECK="$BASE_DIR/karicheck"
PORT=15431

echo "=== View / zone identity test (R-26, O-12) ==="

if ! ifconfig lo0 2>/dev/null | grep -q "inet6 ::1 "; then
    echo "SKIP: ::1 is not configured on lo0"
    exit 0
fi

[ -x "$KARIDNS" ] && [ -x "$DAG" ] && [ -x "$KARICTL" ] && [ -x "$KARICHECK" ] || \
    make -C "$BASE_DIR" karidns dag karictl karicheck >/dev/null || exit 1

TMP_DIR="$(mktemp -d /tmp/karidns_view.XXXXXX)"
chmod 755 "$TMP_DIR"
# the plugin is stored without the execute bit in git; use an executable copy
PLUGIN_SCRIPT="$TMP_DIR/dnstestscript.pl"
cp "$BASE_DIR/tests/plugins/dnstestscript.pl" "$PLUGIN_SCRIPT"
chmod 755 "$PLUGIN_SCRIPT"
SERVER_PID=""
cleanup() {
    kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$TMP_DIR/karidns.conf"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

FAILED=0
fail() { echo "  [FAIL] $1"; FAILED=1; }
pass() { echo "  [PASS] $1"; }

USER_OPT=""
PROG_USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"nobody\";"
    PROG_USER_OPT="program-user \"nobody\";"
fi

PROGRAM_ZONES_INTERNAL=""
PROGRAM_ZONES_EXTERNAL=""
PROGRAM_OPT=""
HAVE_PERL=0
if command -v perl >/dev/null 2>&1; then
    HAVE_PERL=1
    PROGRAM_OPT="allow-program-zones yes;"
    PROGRAM_ZONES_INTERNAL="zone \"prog.test\" { type program; program \"$PLUGIN_SCRIPT\"; program-args { \"192.0.2.77\"; }; $PROG_USER_OPT };"
    PROGRAM_ZONES_EXTERNAL="zone \"prog.test\" { type program; program \"$PLUGIN_SCRIPT\"; program-args { \"198.51.100.77\"; }; $PROG_USER_OPT };"
fi

write_zone() { # file www-address ns-address
    cat > "$1" <<EOF
\$TTL 60
\$ORIGIN v.test.
@   IN SOA ns1.v.test. hostmaster.v.test. 1 3600 600 86400 60
@   IN NS  ns1.v.test.
@   IN NS  ns.sib.test.
ns1 IN A   $3
www IN A   $2
EOF
}
write_zone "$TMP_DIR/in.zone" 192.0.2.11 192.0.2.1
write_zone "$TMP_DIR/out.zone" 198.51.100.22 198.51.100.1
cat > "$TMP_DIR/sib-in.zone" <<EOF
\$TTL 60
\$ORIGIN sib.test.
@  IN SOA ns.sib.test. hostmaster.sib.test. 1 3600 600 86400 60
@  IN NS  ns.sib.test.
ns IN A   192.0.2.53
EOF
sed 's/192.0.2.53/198.51.100.53/' "$TMP_DIR/sib-in.zone" > "$TMP_DIR/sib-out.zone"

cat > "$TMP_DIR/karidns.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; ::1; };
    pid-file "none";
    $USER_OPT
    $PROGRAM_OPT
};
control-channel {
    socket "$TMP_DIR/control.sock";
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
view "internal" {
    match-clients { 127.0.0.1; };
    zone "v.test" { type master; file "$TMP_DIR/in.zone"; };
    zone "sib.test" { type master; file "$TMP_DIR/sib-in.zone"; };
    $PROGRAM_ZONES_INTERNAL
};
view "external" {
    match-clients { any; };
    zone "v.test" { type master; file "$TMP_DIR/out.zone"; };
    zone "sib.test" { type master; file "$TMP_DIR/sib-out.zone"; };
    $PROGRAM_ZONES_EXTERNAL
};
EOF
cat > "$TMP_DIR/karictl.conf" <<EOF
socket "$TMP_DIR/control.sock";
algorithm hmac-sha256;
secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
EOF
chmod 600 "$TMP_DIR/karictl.conf"

# karicheck checks the zone in both views
KC_OUT=$("$KARICHECK" zone v.test "$TMP_DIR/karidns.conf" 2>&1)
if [ "$(echo "$KC_OUT" | grep -c "Zone 'v.test.' parsed successfully")" = "2" ]; then
    pass "karicheck zone checks v.test in both views"
else
    fail "karicheck zone did not check v.test in both views"; echo "$KC_OUT"
fi

"$KARIDNS" -f "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 50 ]; do
    "$DAG" v.test SOA @127.0.0.1 -p $PORT +short +time=1 +tries=1 2>/dev/null | grep -q hostmaster && break
    sleep 0.2; i=$((i + 1))
done

answer() { # server name type
    "$DAG" "$2" "$3" @"$1" -p $PORT +short +time=2 +tries=1 2>/dev/null | head -1
}

check_views() { # stage internal-www external-www
    a=$(answer 127.0.0.1 www.v.test A)
    b=$(answer ::1 www.v.test A)
    [ "$a" = "$2" ] && pass "$1: internal view www.v.test = $a" || fail "$1: internal view www.v.test = '$a' (expected $2)"
    [ "$b" = "$3" ] && pass "$1: external view www.v.test = $b" || fail "$1: external view www.v.test = '$b' (expected $3)"
    # glue for ns.sib.test comes from the sibling zone of the same view
    ga=$("$DAG" v.test NS @127.0.0.1 -p $PORT +norecurse +time=2 +tries=1 2>/dev/null)
    gb=$("$DAG" v.test NS @::1 -p $PORT +norecurse +time=2 +tries=1 2>/dev/null)
    if echo "$ga" | grep -q "status: NOERROR" && echo "$ga" | grep -Eq "^ns\.sib\.test\.[[:space:]].*A[[:space:]]+192\.0\.2\.53$" \
       && ! echo "$ga" | grep -q "198.51.100.53"; then
        pass "$1: internal glue ns.sib.test from the internal view"
    else
        fail "$1: internal glue"; echo "$ga"
    fi
    if echo "$gb" | grep -q "status: NOERROR" && echo "$gb" | grep -Eq "^ns\.sib\.test\.[[:space:]].*A[[:space:]]+198\.51\.100\.53$" \
       && ! echo "$gb" | grep -q "192.0.2.53"; then
        pass "$1: external glue ns.sib.test from the external view"
    else
        fail "$1: external glue"; echo "$gb"
    fi
    if [ $HAVE_PERL -eq 1 ]; then
        pa=$(answer 127.0.0.1 x.prog.test A)
        pb=$(answer ::1 x.prog.test A)
        [ "$pa" = "192.0.2.77" ] && pass "$1: internal program zone plugin" || fail "$1: internal program zone answered '$pa'"
        [ "$pb" = "198.51.100.77" ] && pass "$1: external program zone plugin" || fail "$1: external program zone answered '$pb'"
    fi
}

check_views "start-up" 192.0.2.11 198.51.100.22

# SIGHUP (reconfig): unchanged files are skipped, changed files reloaded into their own view
write_zone "$TMP_DIR/out.zone" 198.51.100.23 198.51.100.1
sed -i '' 's/ 1 3600 600/ 2 3600 600/' "$TMP_DIR/out.zone" 2>/dev/null || sed -i 's/ 1 3600 600/ 2 3600 600/' "$TMP_DIR/out.zone"
touch -t 203001010000 "$TMP_DIR/out.zone"
kill -HUP "$SERVER_PID"
sleep 2
check_views "after SIGHUP" 192.0.2.11 198.51.100.23

# karictl reload (all zones)
"$KARICTL" -f "$TMP_DIR/karictl.conf" reload >/dev/null 2>&1 || fail "karictl reload failed"
sleep 2
check_views "after karictl reload" 192.0.2.11 198.51.100.23

# karictl reload <zone> <view>: only that view's entry is reloaded
write_zone "$TMP_DIR/in.zone" 192.0.2.12 192.0.2.1
sed -i '' 's/ 1 3600 600/ 3 3600 600/' "$TMP_DIR/in.zone" 2>/dev/null || sed -i 's/ 1 3600 600/ 3 3600 600/' "$TMP_DIR/in.zone"
"$KARICTL" -f "$TMP_DIR/karictl.conf" reload v.test internal >/dev/null 2>&1 || fail "karictl reload v.test internal failed"
sleep 1
check_views "after karictl reload v.test internal" 192.0.2.12 198.51.100.23

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "karidns is no longer running"
fi
if [ $FAILED -ne 0 ]; then
    echo "--- karidns.log (tail) ---"
    tail -30 "$TMP_DIR/karidns.log"
    echo "=== FAILED ==="
    exit 1
fi
echo "=== PASSED ==="
exit 0
