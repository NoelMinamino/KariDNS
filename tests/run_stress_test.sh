#!/bin/sh
# FreeBSD Native Stress Test Script for KariDNS (dag version, using pgrep)

set -u

export ASAN_OPTIONS=abort_on_error=1
export UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1
export TSAN_OPTIONS=halt_on_error=1

# スクリプトのディレクトリを基準にプロジェクトルートへ移動
cd "$(dirname "$0")/.."

CONF_FILE="tests/karidns-test.conf"
CTL_CONF="tests/karictl-test.conf"
ZONE_FILE="tests/zones/example.com.zone"
ZONE_NAME="example.com"

if [ ! -f "$CONF_FILE" ]; then
    echo "Error: Configuration file $CONF_FILE not found."
    exit 1
fi
if [ ! -f "$ZONE_FILE" ]; then
    echo "Error: Zone file $ZONE_FILE not found."
    echo "       Please create a dummy zone file for the stress test."
    exit 1
fi

# 終了時のクリーンアップ処理（確実なプロセスの一掃）
cleanup() {
    ./karictl -f "$CTL_CONF" stop >/dev/null 2>&1
    sleep 1
    pkill -9 -f karidns-tsan 2>/dev/null
    pkill -9 -f karidns-asan 2>/dev/null
    pkill -9 -f dnsperf 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "=========================================="
echo "Phase 1: TSan Data Race Test (reload + IXFR concurrency)"
echo "=========================================="

if [ ! -f "./karidns-tsan" ]; then
    echo "Error: karidns-tsan not found. Please run 'make tsan' first."
    exit 1
fi

# ゾーンファイルのバックアップを作成
cp "$ZONE_FILE" "${ZONE_FILE}.orig"

./karidns-tsan -f "$CONF_FILE" 2> tsan_error.log &
TSAN_PID=$!
sleep 2

# バックグラウンドで猛烈なクエリ負荷をかける
dnsperf -s 127.0.0.1 -p 10053 -d tests/test_queries.txt -l 60 > dnsperf_tsan.log 2>&1
DNSPERF_PID=$!

# 並行してIXFR/AXFRを要求するクライアント（dig）を回す
(
  i=0
  while kill -0 $DNSPERF_PID 2>/dev/null; do
    OLD_SERIAL=$((2024010100 + (i % 40)))
    # NOTE: 意図的に外部の `dig` を使い、自作 `dag` との相互検証を行っている
    dig +tcp "@127.0.0.1" -p 10053 "$ZONE_NAME" "ixfr=$OLD_SERIAL" >/dev/null 2>&1
    i=$((i + 1))
  done
) &
IXFR_CLIENT_PID=$!

echo "Sending reload commands for 60 seconds (Modifying zone file continuously)..."
n=1
while kill -0 $DNSPERF_PID 2>/dev/null; do
    NEW_SERIAL=$((2024010100 + n))
    OLD_HOST="stress-$((n - 1))"
    NEW_HOST="stress-$n"

    # FreeBSDネイティブの sed (-i '' と拡張正規表現 -E) を使用してインプレース置換
    #sed -i '' -E -e "s/^[0-9]{10} ; serial/${NEW_SERIAL} ; serial/" "$ZONE_FILE"
    sed -i '' -E -e "s/^([[:space:]]*)[0-9]{10}([[:space:]]*;.*serial.*)/\1${NEW_SERIAL}\2/" "$ZONE_FILE"
    sed -i '' -E -e "/^${OLD_HOST} /d" "$ZONE_FILE"
    echo "${NEW_HOST} IN A 10.0.0.$((n % 255))" >> "$ZONE_FILE"

    ./karictl -f "$CTL_CONF" reload > /dev/null 2>&1
    n=$((n + 1))
    sleep 1
done

wait $DNSPERF_PID 2>/dev/null
kill $IXFR_CLIENT_PID 2>/dev/null

# dnsperfの完了率をチェック (()のエスケープをFreeBSD grepに最適化)
if ! grep -E -q "Queries completed:.*\([9][0-9]\." dnsperf_tsan.log; then
    echo "TSan Test WARNING: dnsperf completion rate looks low; the server may have hung."
    grep "Queries completed" dnsperf_tsan.log
fi

echo "Stopping karidns cleanly via karictl stop..."
./karictl -f "$CTL_CONF" stop > /dev/null 2>&1
sleep 2

if kill -0 $TSAN_PID 2>/dev/null; then
    echo "TSan Test WARNING: frontend did not exit after 'karictl stop'; forcing kill."
    kill -9 $TSAN_PID 2>/dev/null
fi

# pgrep -l -f を使用してFreeBSDでのプロセス残骸検知を確実にする
if pgrep -l -f karidns-tsan >/dev/null 2>&1; then
    echo "TSan Test FAILED: a karidns-tsan process is still running after shutdown."
    pgrep -l -f karidns-tsan
    mv "${ZONE_FILE}.orig" "$ZONE_FILE"
    exit 1
fi

mv "${ZONE_FILE}.orig" "$ZONE_FILE"

if grep -q "WARNING: ThreadSanitizer: data race" tsan_error.log; then
    echo "TSan Test FAILED: Data race detected."
    cat tsan_error.log
    exit 1
else
    echo "TSan Test PASSED."
fi

echo ""
echo "=========================================="
echo "Phase 2: ASan/UBSan Memory & UB Test"
echo "=========================================="

if [ ! -f "./karidns-asan" ]; then
    echo "Error: karidns-asan not found. Please run 'make asan' first."
    exit 1
fi

./karidns-asan -f "$CONF_FILE" 2> asan_error.log &
ASAN_PID=$!
sleep 2

# Fuzzingツールの呼び出しを `dag` に修正済み
for BREAK_CASE in compression-loop label-too-long tcp-length-overclaim \
                  oversized-qname truncated-question opt-rdlen=100; do
    EXTRA_FLAGS=""
    case "$BREAK_CASE" in
        tcp-length-overclaim) EXTRA_FLAGS="--tcp" ;;
    esac
    echo "Running dag --break $BREAK_CASE"
    ./dag example.com A @127.0.0.1 -p 10053 $EXTRA_FLAGS --break "$BREAK_CASE" >/dev/null 2>&1
done

sleep 2

if ! kill -0 $ASAN_PID 2>/dev/null; then
    echo "ASan Test FAILED: Process crashed."
    cat asan_error.log
    exit 1
fi

./karictl -f "$CTL_CONF" stop > /dev/null 2>&1
sleep 2

if kill -0 $ASAN_PID 2>/dev/null; then
    kill -9 $ASAN_PID 2>/dev/null
fi

if pgrep -l -f karidns-asan >/dev/null 2>&1; then
    echo "ASan Test FAILED: a karidns-asan process is still running after shutdown."
    pgrep -l -f karidns-asan
    exit 1
fi

if grep -E -q "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" asan_error.log; then
    echo "ASan/UBSan Test FAILED: issue detected."
    cat asan_error.log
    exit 1
else
    echo "ASan/UBSan Test PASSED."
fi

echo "All stress tests passed successfully."
