#!/bin/sh
# RFC 2136 UPDATE で既存の RRset に TTL の異なるレコードを追加したとき、build_zone_index() が
# UPDATE の経路でも TTL を RRset の最小値に揃え直すこと (harmonize_ttls=true) を確認する。
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"
TEST_DIR="ttl_harmonization_update_test_dir"
ORIG_ZONE="$ZONES_DIR/ttl_harmonize_update.zone"

[ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] || {
    echo "[*] Building required binaries (karidns, dag)..."
    [ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] || make -C "$BIN_DIR" karidns dag
}

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"

# UPDATE はゾーンをメモリ上で変えるだけだが、元のゾーンファイルを汚さないように作業ディレクトリへ写す
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

echo "[+] Step 1: baseline query before UPDATE -- dynhost.dynttl.test. A must show TTL 300..."
"$BIN_DIR/dag" dynhost.dynttl.test. A @127.0.0.1 -p 53732 > out_before.txt 2>&1
cat out_before.txt
check_no_crash
if grep "^dynhost\.dynttl\.test\..*IN.*A" out_before.txt | awk '{print $2}' | grep -qv "^300$"; then
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
