#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/../karidns-asan"
KARICTL="$DIR/../karictl-asan"

if [ ! -x "$BIN" ]; then
    echo "karidns-asan not found. Run 'make asan' first."
    exit 1
fi

CONF="$DIR/dynamic_update_test.conf"
CTL_CONF="$DIR/karictl-test.conf"

cat <<EOF > "$CONF"
options {
    port 10053;
    bind-address { 127.0.0.1; };
};
control-channel {
        algorithm hmac-sha256;
        secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
key "test-key" {
    algorithm hmac-sha256;
    secret "C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=";
};
key "wrong-key" {
    algorithm hmac-sha256;
    secret "D+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=";
};
zone "dynupdate.com" {
    type master;
    file "$DIR/zones/dynupdate.com.zone";
    allow-update { test-key; };
};
EOF

echo "[*] Starting KariDNS on port 10053..."
$BIN -f -c "$CONF" > server.log 2>&1 &
SERVER_PID=$!
sleep 2

cleanup() {
    echo "[*] Stopping KariDNS (PID $SERVER_PID)..."
    kill -9 $SERVER_PID 2>/dev/null || true
    echo "=== server.log ==="
    cat server.log || true
}
trap cleanup EXIT

echo "[*] Initial query check..."
dig @127.0.0.1 -p 10053 test.dynupdate.com. TXT +short > out.txt || true
if ! grep -q "initial" out.txt; then
    echo "[FAIL] Initial test.dynupdate.com TXT not found."
    cat out.txt
    cat "$DIR/dynamic_update_test.conf" || true
    cat server.log || true
    exit 1
fi

echo "[*] 1. Unauthorized UPDATE (No TSIG)..."
cat <<EOF > update.txt
server 127.0.0.1 10053
zone dynupdate.com.
update add new1.dynupdate.com. 300 A 1.2.3.4
show
send
EOF
nsupdate update.txt > out.txt 2>&1 || true
if ! grep -q "REFUSED" out.txt && ! grep -q "NOTAUTH" out.txt && ! grep -q "connection refused" out.txt; then
    dig @127.0.0.1 -p 10053 new1.dynupdate.com. A +short > res.txt
    if [ -s res.txt ]; then
        echo "[FAIL] Unauthorized UPDATE succeeded!"
        exit 1
    fi
fi

echo "[*] 2. Unauthorized UPDATE (Wrong TSIG)..."
cat <<EOF > update.txt
server 127.0.0.1 10053
zone dynupdate.com.
update add new1.dynupdate.com. 300 A 1.2.3.4
send
EOF
nsupdate -y "hmac-sha256:wrong-key:D+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=" update.txt > out.txt 2>&1 || true
dig @127.0.0.1 -p 10053 new1.dynupdate.com. A +short > res.txt
if [ -s res.txt ]; then
    echo "[FAIL] Wrong TSIG UPDATE succeeded!"
    exit 1
fi

echo "[*] 3. Authorized UPDATE (Add Record)..."
cat <<EOF > update.txt
server 127.0.0.1 10053
zone dynupdate.com.
update add new1.dynupdate.com. 300 A 1.2.3.4
send
EOF
nsupdate -y "hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=" update.txt
dig @127.0.0.1 -p 10053 new1.dynupdate.com. A +short > res.txt
if ! grep -q "1.2.3.4" res.txt; then
    echo "[FAIL] Authorized UPDATE failed to add record."
    exit 1
fi

echo "[*] 4. Prerequisite Failure (NXDOMAIN)..."
cat <<EOF > update.txt
server 127.0.0.1 10053
zone dynupdate.com.
prereq nxdomain test.dynupdate.com.
update add new2.dynupdate.com. 300 A 2.3.4.5
send
EOF
nsupdate -y "hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=" update.txt > out.txt 2>&1 || true
if ! grep -q "YXDOMAIN" out.txt; then
    echo "[!] Note: nsupdate output: $(cat out.txt)"
fi
dig @127.0.0.1 -p 10053 new2.dynupdate.com. A +short > res.txt
if [ -s res.txt ]; then
    echo "[FAIL] Prerequisite was ignored!"
    exit 1
fi

echo "[*] 5. Reload Server to check ephemeral behavior..."
$KARICTL -f "$CTL_CONF" reload
sleep 1

echo "[*] Checking if added record is gone..."
dig @127.0.0.1 -p 10053 new1.dynupdate.com. A +short > res.txt
if grep -q "1.2.3.4" res.txt; then
    echo "[FAIL] Record persisted after reload! It should be ephemeral."
    exit 1
fi

echo "[OK] Dynamic Update tests passed!"
rm -f update.txt out.txt res.txt
echo "=== server.log ==="
cat server.log || true
exit 0
