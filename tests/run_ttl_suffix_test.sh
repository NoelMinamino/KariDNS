#!/bin/sh
# Test BIND-compatible TTL unit suffix parsing (w/d/h/m/s)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
BIN_DIR="$SCRIPT_DIR/.."
ZONES_DIR="$SCRIPT_DIR/zones"
TEST_DIR="ttl_suffix_test_dir"

[ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] && [ -x "$BIN_DIR/karicheck" ] || {
    echo "[*] Building required binaries (karidns, dag, karicheck)..."
    [ -x "$BIN_DIR/karidns" ] && [ -x "$BIN_DIR/dag" ] && [ -x "$BIN_DIR/karicheck" ] || make -C "$BIN_DIR" karidns dag karicheck
}

rm -rf "$SCRIPT_DIR/$TEST_DIR"
mkdir -p "$SCRIPT_DIR/$TEST_DIR"
cd "$SCRIPT_DIR/$TEST_DIR"
TEST_DIR_ABS=$(pwd)

echo "[+] Checking zone syntax with karicheck..."
"$BIN_DIR/karicheck" zone example.com "$ZONES_DIR/ttl_suffix_test.zone" || {
    echo "FAIL: karicheck rejected ttl_suffix_test.zone"
    exit 1
}

USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
cat << EOF > karidns.conf
options {
    port 53532;
    bind-address { 127.0.0.1; };
    ${USER_OPT}
};

view "default" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "${ZONES_DIR}/ttl_suffix_test.zone";
    };
};
EOF

"$BIN_DIR/karidns" -f karidns.conf > karidns.log 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    "$BIN_DIR/dag" example.com. SOA @127.0.0.1 -p 53532 +short +timeout=1 +tries=1 2>/dev/null | grep -q admin && break
    sleep 0.2
done

cleanup() {
    kari_kill_tree "${SERVER_PID:-}"
    rm -rf "$SCRIPT_DIR/$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# check <label> <file> <regex>: the regex must match one answer line (+nohexdump output, anchored)
check() {
    grep -E -q "$3" "$2" || { echo "FAIL: $1"; cat "$2"; cat karidns.log; exit 1; }
    echo "[OK] $1"
}
q() { # name type file
    "$BIN_DIR/dag" "$1" "$2" @127.0.0.1 -p 53532 +nohexdump +norec > "$3" 2>&1
}

echo "[+] SOA: owner TTL from \$TTL 1D, RDATA timers 1h 15m 1w 1h..."
q example.com. SOA out_soa.txt
check "SOA TTL 1D -> 86400, refresh 1h -> 3600, retry 15m -> 900, expire 1w -> 604800, minimum 1h -> 3600" out_soa.txt \
    "^example\.com\.[[:space:]]+86400[[:space:]]+IN[[:space:]]+SOA[[:space:]]+ns1\.example\.com\.[[:space:]]+admin\.example\.com\.[[:space:]]+1[[:space:]]+3600[[:space:]]+900[[:space:]]+604800[[:space:]]+3600$"

q example.com. NS out_ns.txt
check "NS TTL 3h -> 10800" out_ns.txt "^example\.com\.[[:space:]]+10800[[:space:]]+IN[[:space:]]+NS[[:space:]]+ns1\.example\.com\.$"

q ns1.example.com. A out_ns1.txt
check "A TTL 1D -> 86400" out_ns1.txt "^ns1\.example\.com\.[[:space:]]+86400[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.53$"

q www.example.com. A out_www.txt
check "A TTL 90 (no unit) -> 90" out_www.txt "^www\.example\.com\.[[:space:]]+90[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.1$"

q mixed.example.com. A out_mixed.txt
check "A TTL 1h30m -> 5400" out_mixed.txt "^mixed\.example\.com\.[[:space:]]+5400[[:space:]]+IN[[:space:]]+A[[:space:]]+192\.0\.2\.2$"

echo "[+] All TTL unit suffix parsing tests passed successfully!"
exit 0
