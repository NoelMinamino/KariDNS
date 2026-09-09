#!/bin/sh
# RFC 2181 繝ｻ繧托ｽｽ・ｧ5.2 RRset TTL harmonization + RFC 4035 繝ｻ繧托ｽｽ・ｧ2.2 RRSIG TTL alignment test
#
# 髫ｶﾂ隲帙・・ｽ・ｨ繝ｻ・ｼ鬯ｯ繝ｻ繝ｻ陝ｯ・ｼ:
#   1. karicheck 驍ｵ・ｺ陟募仰繝ｻ蠢吠ld_zone_index() 驍ｵ・ｺ繝ｻ・ｫ驛｢・ｧ陋ｹ・ｻ繝ｻ邇厄ｽｱ繝ｻ・ｽ・｣鬮ｫ遨ゑｽｸ讒ｫ蟇・し・ｺ霑ｹ螟ｲ・ｽ・｡陟暮ｯ会ｽｽ蜀暦ｽｹ・ｧ陟暮ｯ会ｽｽ迢暦ｽｸ・ｲ隰疲ｺｽ竏夐し・ｲ鬮ｦ・ｪ郢晢ｽｻ
#      鬨ｾ蠅難ｽｺ蛟･ﾎ咎Δ譎｢・ｽ・ｼ驛｢・ｧ繝ｻ・ｿ驛｢・ｧ陞ｳ螟ｲ・ｽ・ｦ闕ｵ譏ｶﾂ・ｻ驍ｵ・ｲ郢晢ｽｽRset髯ｷﾂ郢晢ｽｻ郢晢ｽｻTTL髣包ｽｳ髢ｧ・ｴ驍丞ｹ・・陋ｹ・ｻ繝ｻ繝ｻ[WARNING] 驍ｵ・ｺ繝ｻ・ｨ驍ｵ・ｺ陷会ｽｱ遯ｶ・ｻ髫ｶﾂ隲幢ｽｷ郢晢ｽｻ驍ｵ・ｺ陷ｷ・ｶ繝ｻ迢暦ｽｸ・ｺ髦ｮ蜷ｮ繝ｻ驍ｵ・ｲ郢晢ｽｻ#   2. karicheck 驍ｵ・ｺ繝ｻ・ｮ髣皮判縺倡ｹ晢ｽｻ驛｢譏ｶ繝ｻ邵ｺ閾･・ｹ譏ｴ繝ｻ邵ｺ繝ｻalgorithm鬮ｫ・ｴ繝ｻ・ｦ髯ｷ・ｻ鬯倩ｲｻ・ｽ・ｭ郢晢ｽｻ驛｢・ｧ陷ｻ闌ｨ・ｽ・ｱ陞｢・ｽ雎仙､・ｸ・ｺ陷会ｽｱ遶企・・ｸ・ｺ郢晢ｽｻ繝ｻ繝ｻ・ｸ・ｺ繝ｻ・ｨ驍ｵ・ｲ郢晢ｽｻ#   3. 驛｢・ｧ繝ｻ・ｵ驛｢譎｢・ｽ・ｼ驛｢譎√・郢晢ｽｻ驍ｵ・ｺ隰疲ｻゑｽｽ・ｮ雋翫・諤咎し・ｺ繝ｻ・ｫ髯滂ｽ｢隲帙・・ｽ・ｭ隴∫ｵｶ繝ｻ驛｢・ｧ郢晢ｽｻA 驛｢譎｢・ｽ・ｬ驛｢・ｧ繝ｻ・ｳ驛｢譎｢・ｽ・ｼ驛｢譎擾ｽｳ・ｨ郢晢ｽｻTTL驍ｵ・ｺ陟募仰郢晢ｽｽRset髯ｷﾂ郢晢ｽｻ郢晢ｽｻ髫ｴ蟠｢ﾂ髯昴・・ｸ讌ｪﾂ繝ｻ・､驍ｵ・ｺ繝ｻ・ｫ
#      髮弱・・ｽ・｣鬮ｫ遨ゑｽｸ讒ｫ蟇・し・ｺ髴郁ｲｻ・ｽ讙趣ｽｸ・ｺ繝ｻ・ｦ驍ｵ・ｺ郢晢ｽｻ繝ｻ迢暦ｽｸ・ｺ髦ｮ蜷ｮ繝ｻ(300 vs 900 -> 300)驍ｵ・ｲ郢晢ｽｻ#   4. 髯ｷ・ｷ陟募具ｽｧ owner name 驍ｵ・ｺ繝ｻ・ｫ髯昴・・ｽ・ｾ驍ｵ・ｺ陷ｷ・ｶ繝ｻ繝ｻRRSIG(A) 驍ｵ・ｺ繝ｻ・ｮTTL驍ｵ・ｺ陟募仰郢晢ｽｽRSIG髯ｷ・ｷ隰疲ｻゑｽｽ・｣繝ｻ・ｫ驍ｵ・ｺ繝ｻ・ｧ髫ｰ・ｰ郢晢ｽｻ遶擾ｽｴ驛｢・ｧ陝ｲ・ｨ繝ｻ讙趣ｽｹ・ｧ郢晢ｽｻ#      驍ｵ・ｺ繝ｻ・ｮ驍ｵ・ｺ繝ｻ・ｧ驍ｵ・ｺ繝ｻ・ｯ驍ｵ・ｺ繝ｻ・ｪ驍ｵ・ｺ闕ｳ迺ｰﾂ遶乗劼・ｽ・ｯ繝ｻ・ｾ鬮ｮ雜｣・ｽ・｡(covered)RRset驍ｵ・ｺ繝ｻ・ｮ髮弱・・ｽ・｣鬮ｫ遨ゑｽｸ讒ｫ蟇・辧蜍滓→TL(300)驍ｵ・ｺ繝ｻ・ｫ髣包ｽｳ・つ鬮｢・ｾ繝ｻ・ｴ驍ｵ・ｺ陷ｷ・ｶ繝ｻ迢暦ｽｸ・ｺ髦ｮ蜷ｮ繝ｻ驍ｵ・ｲ郢晢ｽｻ#   5. 髯ｷ・ｷ隰疲ｻ・ｹ驍ｵ・ｺ繝ｻ・ｫ髮趣ｽｺ繝ｻ・ｷ髯懶ｽｨ繝ｻ・ｨ驍ｵ・ｺ陷ｷ・ｶ繝ｻ繝ｻRRSIG(MX) 驍ｵ・ｺ陟募仰郢晢ｽｽRSIG(A) 驍ｵ・ｺ繝ｻ・ｮ髮弱・・ｽ・｣鬮ｫ遨ゑｽｸ讒ｫ蟇・し・ｺ繝ｻ・ｫ髯晢ｽｾ繝ｻ・ｻ驍ｵ・ｺ陝雜｣・ｽ・ｾ繝ｻ・ｼ驍ｵ・ｺ繝ｻ・ｾ驛｢・ｧ陟募ｨｯ繝ｻ驍ｵ・ｲ郢晢ｽｻ#      MX驛｢譎｢・ｽ・ｬ驛｢・ｧ繝ｻ・ｳ驛｢譎｢・ｽ・ｼ驛｢譎∵ｭ鍋ｹ晢ｽｻ鬮ｴ繝ｻ・ｽ・ｫ驍ｵ・ｺ繝ｻ・ｮTTL(600)驍ｵ・ｺ繝ｻ・ｫ髣包ｽｳ・つ鬮｢・ｾ繝ｻ・ｴ驍ｵ・ｺ陷ｷ・ｶ繝ｻ迢暦ｽｸ・ｺ髦ｮ蜷ｮ繝ｻ(鬮ｯ・ｲ繝ｻ・ｫ鬮ｫ霈斐・邵ｺ・｡驛｢・ｧ繝ｻ・､驛｢譎丞ｹｲ郢晢ｽｻ髯ｷ・ｿ隰費ｽｶ繝ｻ莨・ｽｩ謌奇ｽｼ謚ｫ譁｡髫ｶﾂ隲幢ｽｷ郢晢ｽｻ)驍ｵ・ｲ郢晢ｽｻ#   6. 髫ｴ蟠｢ﾂ髯具ｽｻ隴擾ｽｴ・ゑｽｰ驛｢・ｧ隹ｺ謚豊驍ｵ・ｺ隴ｴ・ｧ驍冗坩・ｸ・ｺ繝ｻ・｣驍ｵ・ｺ繝ｻ・ｦ驍ｵ・ｺ郢晢ｽｻ繝ｻ鬨山set(髯昴・・ｽ・ｾ髴趣ｽ｣繝ｻ・ｧ鬩玲慣・ｽ・､)驍ｵ・ｺ隰疲ｻゑｽｽ・､霑壼雀蟇・し・ｺ陷会ｽｱ遶企・・ｸ・ｺ郢晢ｽｻ繝ｻ繝ｻ・ｸ・ｺ繝ｻ・ｨ驍ｵ・ｲ郢晢ｽｻ#   7. 鬮ｯ・ｲ繝ｻ・ｫ鬮ｫ霈斐・繝ｻ・ｯ繝ｻ・ｾ鬮ｮ雜｣・ｽ・｡驍ｵ・ｺ繝ｻ・ｮRRset驍ｵ・ｺ隰疲ｻゑｽｽ・ｭ闔ｨ諛夷帝し・ｺ陷会ｽｱ遶企・・ｸ・ｺ郢晢ｽｻ繝ｻ・ｭ繝ｻ・､鬩包ｽｶ鬯ｨ螻ｱSIG驍ｵ・ｺ陟募仰遶丞｣ｹ・驛｢譎｢・ｽ・ｩ驛｢譏ｴ繝ｻ邵ｺ蜥擾ｽｹ譎｢・ｽ・･驍ｵ・ｺ陝ｶ蜷ｮ繝ｻ驍ｵ・ｲ遶丞具ｽｰ驍ｵ・ｺ繝ｻ・､
#      TTL驛｢・ｧ髮区ｩｸ・ｽ・､騾包ｽｻ陝ｲ・ｩ驍ｵ・ｺ髴郁ｲｻ・ｽ讙趣ｽｸ・ｺ陞｢・ｹ遶企豪・ｸ・ｺ隴擾ｽｴ郢晢ｽｻ驍ｵ・ｺ繝ｻ・ｾ驍ｵ・ｺ繝ｻ・ｾ髯滂ｽ｢隲帙・・ｽ・ｭ隴∵腸・ｼ繝ｻ・ｹ・ｧ陟暮ｯ会ｽｽ迢暦ｽｸ・ｺ髦ｮ蜷ｮ繝ｻ驍ｵ・ｲ郢晢ｽｻset -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"
TEST_DIR="ttl_harmonization_test_dir"
ZONE_FILE="$ZONES_DIR/ttl_harmonize_basic.zone"

echo "[*] Building required binaries (karidns, dag, karicheck)..."
make -C "$BIN_DIR" karidns dag karicheck

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
    port 53731;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
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
sleep 1

cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
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
"$BIN_DIR/dag" mixed.harmonize.test. A @127.0.0.1 -p 53731 > out_mixed_a.txt 2>&1
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
"$BIN_DIR/dag" mixed.harmonize.test. RRSIG @127.0.0.1 -p 53731 > out_mixed_rrsig.txt 2>&1
cat out_mixed_rrsig.txt
check_no_crash

grep "RRSIG" out_mixed_rrsig.txt | grep " A " | awk '{print $2}' | grep -q "^300$" || {
    echo "FAIL: RRSIG covering type A does not show the harmonized covered-RRset TTL (300)"
    exit 1
}
grep "RRSIG" out_mixed_rrsig.txt | grep " MX " | awk '{print $2}' | grep -q "^600$" || {
    echo "FAIL: RRSIG covering type MX does not show its own RRset TTL (600); it may have been incorrectly merged with RRSIG(A)"
    exit 1
}
echo "[PASS] Each RRSIG's TTL correctly tracks its own covered RRset, not a sibling RRSIG's TTL."

echo "[+] Step 5: control group 'stable.harmonize.test.' A -- TTL must remain 1800 unchanged..."
"$BIN_DIR/dag" stable.harmonize.test. A @127.0.0.1 -p 53731 > out_stable.txt 2>&1
cat out_stable.txt
check_no_crash
if grep "^stable\.harmonize\.test\..*IN.*A" out_stable.txt | awk '{print $2}' | grep -qv "^1800$"; then
    echo "FAIL: control RRset 'stable' TTL was altered even though it was already consistent"
    exit 1
fi
echo "[PASS] Consistent RRsets are left unchanged (no unwanted side effects)."

echo "[+] Step 6: orphaned RRSIG (covers NSEC, which does not exist at this name) must be served unchanged and must not crash the server..."
"$BIN_DIR/dag" orphan.harmonize.test. RRSIG @127.0.0.1 -p 53731 > out_orphan.txt 2>&1
cat out_orphan.txt
check_no_crash
grep "^orphan\.harmonize\.test\..*IN.*RRSIG" out_orphan.txt | awk '{print $2}' | grep -q "^3600$" || {
    echo "FAIL: orphaned RRSIG TTL was altered even though no covered RRset exists to harmonize against"
    exit 1
}
echo "[PASS] Orphaned RRSIG handled safely without crashing and without incorrect TTL modification."

echo "[+] All RRset TTL harmonization tests passed successfully!"
exit 0
