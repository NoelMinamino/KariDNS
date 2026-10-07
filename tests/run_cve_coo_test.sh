#!/bin/sh
# ==============================================================================
# tests/run_cve_coo_test.sh - catalog zone CoO tracking under allocation failure
# ==============================================================================
# A catalog zone with 20 members, each with a coo property (RFC 9432 §5.3.1) whose
# target is a 253-octet name, is loaded while tests/oom_coo_wrapper.c makes the
# first allocation of the pending-CoO table (16 entries) fail. The server must log
# the failure, skip CoO tracking for that member, keep the long names within their
# buffers and go on serving the catalog and its members. The CoO ownership rules
# themselves are checked in run_catalog_zone_test.sh (claim without coo ignored,
# migration with coo).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"

echo "[+] Starting CVE CoO allocation failure test..."
[ -x "$ROOT_DIR/karidns" ] || make -C "$ROOT_DIR" karidns
[ -x "$ROOT_DIR/dag" ] || make -C "$ROOT_DIR" dag

TEST_DIR="$(mktemp -d /tmp/coo_cve_test.XXXXXX)"
chmod 755 "$TEST_DIR"
PORT=$((31000 + $$ % 4000))
KARIDNS_PID=""
cleanup() {
    [ -n "$KARIDNS_PID" ] && kari_kill_tree "$KARIDNS_PID"
    kari_kill_conf "$TEST_DIR/karidns.conf"
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[-] $*"
    cat "$TEST_DIR/karidns.log"
    exit 1
}

# coo target of 254 octets in wire form (4 labels of 61 octets + "test"), near the 255 limit
L59=$(printf "a%.0s" $(seq 1 59))
L61="aa${L59}"
cat > "$TEST_DIR/catalog.zone" <<'EOF'
$ORIGIN catalog.example.test.
$TTL 3600
@ IN SOA ns1.example.test. admin.example.test. 1 3600 1800 604800 86400
@ IN NS invalid.
version IN TXT "2"
EOF
for i in $(seq 1 20); do
    echo "m${i}.zones IN PTR member${i}.example.test." >> "$TEST_DIR/catalog.zone"
    echo "coo.m${i}.zones IN PTR $(printf %02d "$i")${L59}.${L61}.${L61}.${L61}.test." >> "$TEST_DIR/catalog.zone"
done

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
cat > "$TEST_DIR/karidns.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    pid-file "none";
    $USER_OPT
};
zone "catalog.example.test" {
    type master;
    file "$TEST_DIR/catalog.zone";
    catalog-zone yes;
};
EOF

cc -shared -fPIC -o "$TEST_DIR/oom_coo_wrapper.so" "$SCRIPT_DIR/oom_coo_wrapper.c" -ldl 2>/dev/null ||
    cc -shared -fPIC -o "$TEST_DIR/oom_coo_wrapper.so" "$SCRIPT_DIR/oom_coo_wrapper.c"

echo "[+] Starting KariDNS with the OOM wrapper (port $PORT)..."
OOM_FAIL_AFTER_NTH_MATCHING_CALL=0 LD_PRELOAD="$TEST_DIR/oom_coo_wrapper.so" \
    "$ROOT_DIR/karidns" -f "$TEST_DIR/karidns.conf" > "$TEST_DIR/karidns.log" 2>&1 &
KARIDNS_PID=$!

q() { # name type -> status line
    "$ROOT_DIR/dag" @127.0.0.1 -p "$PORT" "$1" "$2" +nohexdump +timeout=1 +tries=1 2>&1 | sed -n 's/.*status: \([A-Z]*\),.*/\1/p'
}
for _ in $(seq 1 50); do
    [ "$(q catalog.example.test SOA)" = "NOERROR" ] && break
    kill -0 "$KARIDNS_PID" 2>/dev/null || fail "KariDNS exited during startup"
    sleep 0.2
done

[ "$(q catalog.example.test SOA)" = "NOERROR" ] || fail "catalog zone is not served"
grep -q "Intercepted realloc for size=12288, match=0! Simulating OOM." "$TEST_DIR/karidns.log" ||
    fail "the allocation of the pending-CoO table was not intercepted (sizeof(pending_coo_t) changed? update tests/oom_coo_wrapper.c)"
grep -q "\[Catalog\] Failed to allocate memory for g_pending_coo (domain=member[0-9]*.example.test.); skipping CoO tracking for this member" "$TEST_DIR/karidns.log" ||
    fail "allocation failure not reported"
# members are zones without data (SERVFAIL); a name outside the catalog is refused
for m in 1 17 20; do
    st=$(q "member$m.example.test" SOA)
    [ "$st" = "SERVFAIL" ] || fail "catalog member member$m.example.test: status '$st', expected SERVFAIL (member zone loaded)"
done
st=$(q other.example.test SOA)
[ "$st" = "REFUSED" ] || fail "name outside the catalog: status '$st', expected REFUSED"
kill -0 "$KARIDNS_PID" 2>/dev/null || fail "KariDNS is no longer running"

echo "[+] KariDNS survived the CoO allocation failure, logged it and serves the catalog and its 20 members"
exit 0
