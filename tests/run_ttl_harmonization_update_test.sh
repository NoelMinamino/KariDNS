#!/bin/sh
# RFC 2136 UPDATE 鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢繝ｻ・ｧ髯具ｽｹ繝ｻ・ｻ髫ｨ繝ｻ・ｽ・ｲ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｦRRset鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｬ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｳ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢隴取得・ｽ・ｳ繝ｻ・ｨ驕ｯ・ｶ繝ｻ・ｲ鬯ｮ・ｴ隰・∞・ｽ・ｽ繝ｻ・ｽ鬮ｯ・ｷ闔ｨ螟ｲ・ｽ・｣繝ｻ・ｰ鬩搾ｽｵ繝ｻ・ｺ鬮ｴ驛・ｽｲ・ｻ繝ｻ・ｽ隶呵ｶ｣・ｽ・ｸ繝ｻ・ｺ髮狗ｿｫ繝ｻ隲､蜥弱＠繝ｻ・ｲ驛｢譎｢・ｽ・ｻ# build_zone_index() 鬩搾ｽｵ繝ｻ・ｺ髫ｰ逍ｲ・ｺ蛟･繝ｻ鬮ｯ讖ｸ・ｽ・ｳ髮九・・ｽ・ｯ郢晢ｽｻ繝ｻ・｡髯滓坩・ｯ莨夲ｽｽ・ｼ郢晢ｽｻ繝ｻ・ｹ繝ｻ・ｧ髯溷供ﾂ莉ｰﾂ驛｢・ｧ隰夊ｱ企ｩ搾ｽｵ繝ｻ・ｺ髫ｰ逍ｲ・ｺ蛟･繝ｻ鬮ｯ貅ｯ・ｶ・｣繝ｻ・ｽ繝ｻ・ｦ鬮ｮ蠑ｱ繝ｻ繝ｻ・ｽ繝ｻ・｣鬯ｮ・ｫ驕ｨ繧托ｽｽ・ｸ隶抵ｽｫ陝・・縺励・・ｺ鬮ｴ驛・ｽｲ・ｻ繝ｻ・ｽ隶呵ｶ｣・ｽ・ｹ繝ｻ・ｧ驛｢譎｢・ｽ・ｻharmonize_ttls=true鬮ｯ蜿･・ｹ・｢繝ｻ・ｽ繝ｻ・ｴ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｮ鬯ｩ謳ｾ・ｽ・ｨ髴托ｽｹ陞滂ｽｲ繝ｻ・ｽ繝ｻ・ｷ郢晢ｽｻ繝ｻ・ｯ)
# 鬩搾ｽｵ繝ｻ・ｺ鬮ｦ・ｮ陷ｷ・ｮ郢晢ｽｻ鬩幢ｽ｢繝ｻ・ｧ髯ｷ・ｻ髣鯉ｽｨ繝ｻ・ｽ繝ｻ・､髫ｲ蟶吶・繝ｻ・ｽ繝ｻ・ｨ郢晢ｽｻ繝ｻ・ｼ鬩搾ｽｵ繝ｻ・ｺ髯ｷ・ｷ繝ｻ・ｶ郢晢ｽｻ霑｢證ｦ・ｽ・ｹ隴擾ｽｴ郢晢ｽｻ驍ｵ・ｺ陝ｶ・ｷ繝ｻ・ｹ隴主・讓溘・縺､ﾂ驛｢譎｢・ｽ・ｻset -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"
TEST_DIR="ttl_harmonization_update_test_dir"
ORIG_ZONE="$ZONES_DIR/ttl_harmonize_update.zone"

echo "[*] Building required binaries (karidns, dag)..."
make -C "$BIN_DIR" karidns dag

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"

# UPDATE鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｧ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｾ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｼ鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｳ鬩幢ｽ｢隴弱・・ｽ・ｼ隴∵腸・ｼ諞ｺﾎ斐・・ｧ郢晢ｽｻ繝ｻ・､鬩幢ｽ｢隴趣ｽ｢繝ｻ・ｽ繝ｻ・ｫ鬩搾ｽｵ繝ｻ・ｺ髫ｴ・ｴ繝ｻ・ｧ髯溯ざ・ｪ雜｣・ｽ・ｸ繝ｻ・ｺ鬮｢・ｧ繝ｻ・ｴ鬯ｩ・ｪ繝ｻ・､鬩幢ｽ｢繝ｻ・ｧ髣包ｽｳ陞ゅ・・ｽ・ｽ霑｢證ｦ・ｽ・ｸ繝ｻ・ｺ髮九・竏槭・・ｽ遶擾ｽｫ繝ｻ・ｸ繝ｻ・ｲ驕ｶ謫ｾ・ｽ・ｽ郢晢ｽｻ繝ｻ・ｽ髫ｲ蟷・か繝ｻ・ｽ繝ｻ・･郢晢ｽｻ繝ｻ・ｭ鬯ｨ・ｾ陋ｹ繝ｻ・ｽ・ｽ繝ｻ・ｨ鬩搾ｽｵ繝ｻ・ｺ郢晢ｽｻ繝ｻ・ｫ鬩幢ｽ｢繝ｻ・ｧ郢晢ｽｻ繝ｻ・ｳ鬩幢ｽ｢隴弱・・ｱ蝣､・ｹ譎｢・ｽ・ｻ鬩搾ｽｵ繝ｻ・ｺ髯ｷ・ｷ繝ｻ・ｶ郢晢ｽｻ郢晢ｽｻ
cp "$ORIG_ZONE" ./dynttl.test.zone
ZONE_FILE="$(pwd)/dynttl.test.zone"

cat << EOF > karidns.conf
options {
    port 53732;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

key "update-key" {
    algorithm hmac-sha256;
    secret "C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=";
};

view "default" {
    match-clients { any; };
    zone "dynttl.test" {
        type master;
        file "${ZONE_FILE}";
        allow-update { key update-key; };
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

echo "[+] Step 1: baseline query before UPDATE -- dynhost.dynttl.test. A must show TTL 300..."
"$BIN_DIR/dag" dynhost.dynttl.test. A @127.0.0.1 -p 53732 > out_before.txt 2>&1
cat out_before.txt
check_no_crash
if grep "^dynhost\.dynttl\.test\..*IN.*A" out_after.txt | awk '{print $2}' | grep -qv "^300$"; then
    echo "FAIL: baseline TTL is not 300 before UPDATE"
    exit 1
fi

echo "[+] Step 2: sending authorized UPDATE adding a second A record with TTL 900 to the same RRset..."
"$BIN_DIR/dag" dynttl.test a @127.0.0.1 -p 53732 \
    --update-add 'dynhost.dynttl.test 900 A 192.0.2.101' \
    +nohexdump-response \
    -y hmac-sha256:update-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= \
    > out_update.txt 2>&1
cat out_update.txt
check_no_crash
grep -qi "NOERROR" out_update.txt || {
    echo "FAIL: authorized UPDATE was not accepted (expected NOERROR)"
    exit 1
}

echo "[+] Step 3: post-UPDATE query -- both A records must now show the re-normalized minimum TTL (300)..."
"$BIN_DIR/dag" dynhost.dynttl.test. A @127.0.0.1 -p 53732 > out_after.txt 2>&1
cat out_after.txt
check_no_crash

A_COUNT=$(grep -c "^dynhost\.dynttl\.test\..*IN.*A" out_after.txt || true)
[ "$A_COUNT" -eq 2 ] || { echo "FAIL: expected 2 A records for dynhost.dynttl.test. after UPDATE"; exit 1; }

if grep "^dynhost\.dynttl\.test\..*IN.*A" out_after.txt | awk '{print $2}' | grep -qv "^300$"; then
    echo "FAIL: after UPDATE, the RRset was not re-harmonized to the minimum TTL (300); build_zone_index() may not be re-running harmonization on the UPDATE path"
    cat out_after.txt
    exit 1
fi

echo "[PASS] Dynamic UPDATE correctly triggers RRset TTL re-harmonization on the live standby arena."
echo "[+] All dynamic-update TTL harmonization tests passed successfully!"
exit 0
