#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/../karidns-asan"
KARICTL="$DIR/../karictl-asan"
DAG="$DIR/../dag"

if [ ! -x "$DAG" ]; then
    make dag
fi


if [ ! -x "$BIN" ]; then
    make asan
fi
if [ ! -x "$BIN" ]; then
    echo "failed: karidns-asan not found. "
    exit 1
fi


CONF="$DIR/dynamic_update_test.conf"
CTL_CONF="$DIR/karictl-test.conf"

cat <<EOF > "$CONF"
options {
    port 10053;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
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
    file "tests/zones/dynupdate.com.zone";
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
$DAG test.dynupdate.com. TXT @127.0.0.1 -p 10053 +short > out.txt || true
if ! grep -q "initial" out.txt; then
    echo "[FAIL] Initial test.dynupdate.com TXT not found."
    cat out.txt
    cat "$DIR/dynamic_update_test.conf" || true
    cat server.log || true
    exit 1
fi

echo "[*] 1. Unauthorized UPDATE (No TSIG)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.4' +nohexdump-response > out.txt 2>&1 || true
if ! grep -q "REFUSED" out.txt && ! grep -q "NOTAUTH" out.txt && ! grep -q "connection refused" out.txt; then
    $DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
    if grep -q "1.2.3.4" res.txt; then
        echo "[FAIL] Unauthorized UPDATE succeeded!"
        exit 1
    fi
fi

echo "[*] 2. Unauthorized UPDATE (Wrong TSIG)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.5' +nohexdump-response -y hmac-sha256:wrong-key:D+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
$DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.5" res.txt; then
    echo "[FAIL] Wrong TSIG UPDATE succeeded!"
    exit 1
fi

echo "[*] 3. Authorized UPDATE (Add Record with prereq)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "new-host.example.com" --update-add 'new.dynupdate.com 300 A 1.2.3.7' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
$DAG new.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if ! grep -q "1.2.3.7" res.txt; then
    echo "[FAIL] Authorized UPDATE failed to add record."
    exit 1
fi

echo "[*] 4. Prerequisite Failure (NXDOMAIN)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "test.dynupdate.com" --update-add 'new2.dynupdate.com 300 A 2.3.4.5' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "YXDOMAIN" out.txt; then
    echo "[!] Note: dag output: $(cat out.txt)"
fi
$DAG new2.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "2.3.4.5" res.txt; then
    echo "[FAIL] Prerequisite was ignored!"
    exit 1
fi

echo "[*] 5. Authorized UPDATE (Delete Record)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "new-host.example.com" --update-del 'new.dynupdate.com A' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
$DAG new.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.7" res.txt; then
    echo "[FAIL] Authorized UPDATE failed to delete record."
    exit 1
fi

echo "[*] 6. Authorized UPDATE (Add Record for ephemeral test)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.4' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true

echo "[*] 7. Reload Server to check ephemeral behavior..."
$KARICTL -f "$CTL_CONF" reload
sleep 1

echo "[*] Checking if added record is gone..."
$DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.4" res.txt; then
    echo "[FAIL] Record persisted after reload! It should be ephemeral."
    exit 1
fi

if killall -0 karidns-asan 2>/dev/null; then
    killall -9 karidns-asan 2>/dev/null
fi

echo "[OK] Dynamic Update tests passed!"
rm -f update.txt out.txt res.txt
echo "=== server.log ==="
cat server.log || true
exit 0
