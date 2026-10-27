#!/bin/sh
# RFC 2181 §5.2 RRset TTL harmonization + RFC 4035 §2.2 RRSIG TTL alignment test
#
# 確認すること:
#   1. karicheck は build_zone_index() による TTL の揃え込み前のゾーンファイルを検査し、
#      RRset 内で TTL が異なる A レコードに [WARNING] を出す。TTL が揃っている RRset には出さない。
#   2. karicheck は被覆タイプの異なる RRSIG 同士 (type 46 全体) を一つの RRset として比べない。
#   3. サーバーは同じ名前・タイプの A レコードの TTL を RRset の最小値に揃えて返す (300 vs 900 -> 300)。
#   4. RRSIG(A) の TTL は被覆する RRset の揃えた後の TTL (300) に合わせる (RFC 4035 §2.2)。
#   5. 同じ名前の RRSIG(MX) は RRSIG(A) とまとめず、MX の RRset の TTL (600) のままにする。
#   6. 最初から TTL が揃っている RRset (stable) は変えない。
#   7. 被覆する RRset が存在しない RRSIG (orphan) は TTL を変えずに返し、サーバーは落ちない。
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
PORT=$(kari_port 0 53731)
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"
TEST_DIR="ttl_harmonization_test_dir"
ZONE_FILE="$ZONES_DIR/ttl_harmonize_basic.zone"

[ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] && [ -x "$BIN_DIR/karicheck" ] || {
    echo "[*] Building required binaries (karidns, dag, karicheck)..."
    [ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] && [ -x "$BIN_DIR/karicheck" ] || make -C "$BIN_DIR" karidns dag karicheck
}

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"

echo "[+] Step 1: karicheck must warn about the raw (pre-harmonization) TTL mismatches..."
"$BIN_DIR/karicheck" zone harmonize.test "$ZONE_FILE" > karicheck_out.txt 2>&1 || true
cat karicheck_out.txt

grep -q "\[WARNING\].*RRset 'mixed\.harmonize\.test\.' type 1 has inconsistent TTLs" karicheck_out.txt || {
    echo "FAIL: karicheck did not warn about inconsistent A-record TTLs at 'mixed.harmonize.test.'"
    exit 1
}
if grep -qi "RRset 'stable\.harmonize\.test\.'.*inconsistent" karicheck_out.txt; then
    echo "FAIL: karicheck raised a false-positive TTL-inconsistency warning for the control RRset 'stable'"
    exit 1
fi
if grep -qi "RRset 'mixed\.harmonize\.test\.' type 46" karicheck_out.txt; then
    echo "FAIL: karicheck incorrectly compared TTLs across RRSIGs of different covered types (type 46 grouping should not be checked by the generic RRset check)"
    exit 1
fi
echo "[PASS] karicheck correctly flags the source zone file issue and produces no false positives."

echo "[+] Step 2: starting karidns with the same zone..."
cat << EOF > karidns.conf
options {
    port ${PORT};
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    socket "$(pwd)/ctl.sock";
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "harmonize.test" {
        type master;
        file "${ZONE_FILE}";
    };
};
EOF

"$BIN_DIR/karidns" -f karidns.conf > karidns.log 2>&1 &
SERVER_PID=$!
kari_wait_answer "$BIN_DIR/dag" "$PORT" harmonize.test. || true   # the queries below report a server that did not start

cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    kari_kill_tree "${SERVER_PID:-}"
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

check_no_crash() {
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: karidns process died unexpectedly. Log:"
        cat karidns.log
        exit 1
    fi
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation)" karidns.log; then
        echo "FAIL: crash/sanitizer error detected in karidns.log:"
        cat karidns.log
        exit 1
    fi
}

echo "[+] Step 3: querying 'mixed.harmonize.test.' A -- both records must show TTL 300 (the minimum)..."
"$BIN_DIR/dag" mixed.harmonize.test. A @127.0.0.1 -p ${PORT} > out_mixed_a.txt 2>&1
cat out_mixed_a.txt
check_no_crash
A_COUNT=$(grep -c "^mixed\.harmonize\.test\..*IN.*A" out_mixed_a.txt || true)
[ "$A_COUNT" -eq 2 ] || { echo "FAIL: expected 2 A records for mixed.harmonize.test."; exit 1; }
if grep "^mixed\.harmonize\.test\..*IN.*A" out_mixed_a.txt | awk '{print $2}' | grep -qv "^300$"; then
    echo "FAIL: not all A records at mixed.harmonize.test. show the normalized TTL 300"
    cat out_mixed_a.txt
    exit 1
fi
echo "[PASS] A RRset TTLs normalized to the minimum (300)."

echo "[+] Step 4: querying 'mixed.harmonize.test.' RRSIG -- RRSIG(A) must show TTL 300, RRSIG(MX) must show TTL 600..."
"$BIN_DIR/dag" mixed.harmonize.test. RRSIG @127.0.0.1 -p ${PORT} > out_mixed_rrsig.txt 2>&1
cat out_mixed_rrsig.txt
check_no_crash

grep "RRSIG" out_mixed_rrsig.txt | grep -E "RRSIG[[:space:]]+A " | awk '{print $2}' | grep -q "^300$" || {
    echo "FAIL: RRSIG covering type A does not show the harmonized covered-RRset TTL (300)"
    exit 1
}
grep "RRSIG" out_mixed_rrsig.txt | grep -E "RRSIG[[:space:]]+MX " | awk '{print $2}' | grep -q "^600$" || {
    echo "FAIL: RRSIG covering type MX does not show its own RRset TTL (600); it may have been incorrectly merged with RRSIG(A)"
    exit 1
}
echo "[PASS] Each RRSIG's TTL correctly tracks its own covered RRset, not a sibling RRSIG's TTL."

echo "[+] Step 5: control group 'stable.harmonize.test.' A -- TTL must remain 1800 unchanged..."
"$BIN_DIR/dag" stable.harmonize.test. A @127.0.0.1 -p ${PORT} > out_stable.txt 2>&1
cat out_stable.txt
check_no_crash
if grep "^stable\.harmonize\.test\..*IN.*A" out_stable.txt | awk '{print $2}' | grep -qv "^1800$"; then
    echo "FAIL: control RRset 'stable' TTL was altered even though it was already consistent"
    exit 1
fi
echo "[PASS] Consistent RRsets are left unchanged (no unwanted side effects)."

echo "[+] Step 6: orphaned RRSIG (covers NSEC, which does not exist at this name) must be served unchanged and must not crash the server..."
"$BIN_DIR/dag" orphan.harmonize.test. RRSIG @127.0.0.1 -p ${PORT} > out_orphan.txt 2>&1
cat out_orphan.txt
check_no_crash
grep "^orphan\.harmonize\.test\..*IN.*RRSIG" out_orphan.txt | awk '{print $2}' | grep -q "^3600$" || {
    echo "FAIL: orphaned RRSIG TTL was altered even though no covered RRset exists to harmonize against"
    exit 1
}
echo "[PASS] Orphaned RRSIG handled safely without crashing and without incorrect TTL modification."

echo "[+] All RRset TTL harmonization tests passed successfully!"
exit 0
