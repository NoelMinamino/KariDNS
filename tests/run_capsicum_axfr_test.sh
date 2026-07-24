#!/bin/sh
set -e

# 1. 本番ビルドでサーバーとdagを構築 (Capsicumを有効にするため)
make clean
make karidns dag

# 2. ktrace を用いてシステムコールをトレースしながらサーバーを起動
ktrace -f karidns.trace ./karidns -f tests/karidns-test.conf > server_capsicum.log 2>&1 &
SERVER_PID=$!
trap '[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; true' EXIT
sleep 1 # 起動待ち

# 3. サーバープロセスが正常に起動したか確認
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "[FAIL] Server failed to start. Log output:"
    cat server_capsicum.log
    exit 1
fi

# 4. dagでAXFRを実行し、応答中に出現したレコードタイプを集計
# ゾーン設定にてTSIGが必須(tsig-key "transfer-key";)となっているため、
# まずはTSIG無しでREFUSEDされることを確認し、次にTSIGありで正常応答を得る。
echo "Running AXFR transfer without TSIG (expect REFUSED)..."
noauth_output=$(./dag example.com AXFR @127.0.0.1 -p 10053 2>&1 || true)
if ! echo "$noauth_output" | grep -qE "REFUSED|NOTAUTH"; then
    echo "[FAIL] AXFR without TSIG was not refused! TSIG-required ACL may be broken."
    echo "$noauth_output"
    exit 1
fi
echo "[OK] AXFR without TSIG correctly refused."

echo "Running AXFR transfer with TSIG..."
axfr_output=$(./dag example.com AXFR @127.0.0.1 -p 10053 -y transfer-key:dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl)
actual_types=$(echo "$axfr_output" | grep -oE '[[:space:]]IN[[:space:]]+[A-Z0-9]+[[:space:]]' | awk '{print $2}' | sort -u)

# 5. サーバープロセスがまだ生きているか確認(クラッシュ検出)
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "[FAIL] Server crashed during AXFR. Log output:"
    cat server_capsicum.log
    
    echo "Checking kdump for ECAPMODE/TRAP_CAP..."
    kdump -f karidns.trace | grep -E 'ECAPMODE|TRAP_CAP' || true
    exit 1
fi

# 6. ktraceログから Capsicum 違反 (ECAPMODE) を機械的にチェック
echo "Checking for hidden ECAPMODE violations in ktrace..."
if kdump -f karidns.trace | grep -E 'ECAPMODE|TRAP_CAP'; then
    echo "[FAIL] ECAPMODE or TRAP_CAP detected in system call trace! Sandbox violation occurred."
    exit 1
fi

# 期待される型がすべてAXFR応答に含まれているか突き合わせる (再利用)
expected_types=$(grep -E '^[^[:space:]]*[[:space:]]+(IN[[:space:]]+)?[A-Z0-9]+[[:space:]]' tests/zones/example.com.zone \
    tests/zones/example.com.hosts tests/zones/example.com.dnskey \
    | grep -v '^[[:space:]]*;' \
    | awk '{for(i=1;i<=NF;i++) if ($i=="IN") {print $(i+1); break}}' \
    | sort -u)

echo "$expected_types" > expected.txt
echo "$actual_types" > actual.txt
missing=$(comm -23 expected.txt actual.txt)
rm expected.txt actual.txt

if [ -n "$missing" ]; then
    echo "[FAIL] The following record types were in the zone file but missing from the AXFR response:"
    echo "$missing"
    exit 1
fi

echo "[OK] Capsicum round-trip test passed: no ECAPMODE/TRAP_CAP violations, all record types present, server did not crash."

if killall -0 karidns 2>/dev/null; then
    killall -9 karidns >/dev/null
fi
