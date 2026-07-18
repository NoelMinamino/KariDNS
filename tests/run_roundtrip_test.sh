#!/bin/sh
set -e

# 1. ASanビルドでサーバーとdagを構築(メモリ破壊系のバグを最大限検出するため)
make karidns-asan dag-asan

# 2. tests/karidns-test.conf (example.com.zoneを読み込む既存の設定) でサーバーを起動
./karidns-asan -f tests/karidns-test.conf > server_asan.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 1 # 起動待ち

# 3. ゾーンファイルに実際に書かれているレコードタイプの一覧を抽出
#    (コメント行・$INCLUDE等のディレクティブ行を除外し、フィールド2番目のRRタイプだけを集計)
expected_types=$(grep -E '^[^[:space:]]*[[:space:]]+(IN[[:space:]]+)?[A-Z0-9]+[[:space:]]' tests/zones/example.com.zone \
    tests/zones/example.com.hosts tests/zones/example.com.dnskey \
    | grep -v '^[[:space:]]*;' \
    | awk '{for(i=1;i<=NF;i++) if ($i=="IN") {print $(i+1); break}}' \
    | sort -u)

# 4. dagでAXFRを実行し、応答中に出現したレコードタイプを集計
axfr_output=$(./dag-asan example.com AXFR @127.0.0.1 -p 10053 -y transfer-key:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl)
actual_types=$(echo "$axfr_output" | grep -oE '[[:space:]]IN[[:space:]]+[A-Z0-9]+[[:space:]]' | awk '{print $2}' | sort -u)

# 5. サーバープロセスがまだ生きているか確認(クラッシュ検出)
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "[FAIL] Server crashed during AXFR. ASan output:"
    cat server_asan.log
    exit 1
fi

# 6. 期待される型がすべてAXFR応答に含まれているか突き合わせる
echo "$expected_types" > expected.txt
echo "$actual_types" > actual.txt
missing=$(comm -23 expected.txt actual.txt)
rm expected.txt actual.txt

if [ -n "$missing" ]; then
    echo "[FAIL] The following record types were in the zone file but missing from the AXFR response:"
    echo "$missing"
    exit 1
fi

echo "[OK] Round-trip test passed: all record types present, server did not crash."
