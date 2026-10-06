#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
BIN="$DIR/../karidns-asan"
KARICTL="$DIR/../karictl-asan"
DAG="$DIR/../dag"

[ -x dag ] || make dag
[ -x karidns-asan ] || make asan
[ -x karictl-asan ] || make karictl-asan
if [ ! -x "$BIN" ]; then
    echo "failed: karidns-asan not found."
    exit 1
fi


CONF="$DIR/dynamic_update_test.conf"
CTL_CONF="$DIR/karictl-test.conf"
chmod 0600 "$CTL_CONF" 2>/dev/null || true

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
    kari_kill_tree "${SERVER_PID:-}"
    rm -f "$CONF" update.txt out.txt res.txt
}
trap cleanup EXIT INT TERM

check_asan_log() {
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" server.log; then
        echo "[FAIL] AddressSanitizer/UndefinedBehaviorSanitizer error detected in server.log:"
        cat server.log
        exit 1
    fi
}


echo "[*] Initial query check..."
$DAG test.dynupdate.com. TXT @127.0.0.1 -p 10053 +short > out.txt || true
if ! grep -q "initial" out.txt; then
    echo "[FAIL] Initial test.dynupdate.com TXT not found."
    cat out.txt
    cat "$DIR/dynamic_update_test.conf" || true
    cat server.log || true
    exit 1
fi

echo "[*] 1. Unauthorized UPDATE (No TSIG): REFUSED, no TSIG (RFC 2136 §3.3)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.4' +nohexdump > out.txt 2>&1 || true
if ! grep -q "status: REFUSED" out.txt || grep -q "ANY[[:space:]]*TSIG" out.txt; then
    echo "[FAIL] Unsigned UPDATE: expected REFUSED without TSIG."
    cat out.txt
    exit 1
fi
$DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.4" res.txt; then
    echo "[FAIL] Unauthorized UPDATE succeeded!"
    exit 1
fi

# tsig_line <owner> <error>: the response's TSIG RR (dag prints "owner 0 ANY TSIG alg time fudge macsize [mac] id error otherlen")
tsig_line() {
    grep -E "^$1\.[[:space:]]+0[[:space:]]+ANY[[:space:]]+TSIG[[:space:]]+hmac-sha256\..*[[:space:]]$2[[:space:]]+[0-9]+" out.txt
}

echo "[*] 2. UPDATE signed with a defined key that allow-update does not list: REFUSED, signed with that key (RFC 8945 §5.3)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.5' +nohexdump -y hmac-sha256:wrong-key:D+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "status: REFUSED" out.txt || ! tsig_line wrong-key NOERROR > /dev/null || grep -q "Couldn't verify" out.txt; then
    echo "[FAIL] Valid but not allowed key: expected REFUSED signed with wrong-key."
    cat out.txt
    exit 1
fi
$DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.5" res.txt; then
    echo "[FAIL] Wrong TSIG UPDATE succeeded!"
    exit 1
fi

echo "[*] 2b. UPDATE signed with an unknown key: NOTAUTH, BADKEY, unsigned, key name echoed (RFC 8945 §5.2.1)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.5' +nohexdump -y hmac-sha256:no-such-key:D+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "status: NOTAUTH" out.txt || ! tsig_line no-such-key BADKEY | grep -qE "[[:space:]]0[[:space:]]+[0-9]+[[:space:]]+BADKEY"; then
    echo "[FAIL] Unknown key: expected NOTAUTH with TSIG error BADKEY and MAC size 0."
    cat out.txt
    exit 1
fi

echo "[*] 2c. UPDATE signed with the allowed key name but a wrong secret: NOTAUTH, BADSIG, unsigned (RFC 8945 §5.2.2)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.5' +nohexdump -y hmac-sha256:test-key:D+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "status: NOTAUTH" out.txt || ! tsig_line test-key "BADSIG" | grep -qE "[[:space:]]0[[:space:]]+[0-9]+[[:space:]]+BADSIG"; then
    echo "[FAIL] Wrong secret: expected NOTAUTH with TSIG error BADSIG and MAC size 0."
    cat out.txt
    exit 1
fi
$DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.5" res.txt; then
    echo "[FAIL] Wrong TSIG UPDATE succeeded!"
    exit 1
fi

echo "[*] 3. Authorized UPDATE (Add Record with prereq)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "new-host.dynupdate.com" --update-add 'new.dynupdate.com 300 A 1.2.3.7' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
$DAG new.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if ! grep -q "1.2.3.7" res.txt; then
    echo "[FAIL] Authorized UPDATE failed to add record."
    exit 1
fi
check_asan_log

echo "[*] 3.5. Authorized UPDATE Double (Slot Reuse Cache Validation)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new.dynupdate.com 300 A 1.2.3.8' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
$DAG new.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if ! grep -q "1.2.3.8" res.txt; then
    echo "[FAIL] Authorized UPDATE (Double) failed to update record or cache corrupted."
    exit 1
fi
$DAG dynupdate.com. SOA @127.0.0.1 -p 10053 +short > res.txt
if ! grep -q "ns1.dynupdate.com." res.txt; then
    echo "[FAIL] SOA record corrupted after double update!"
    exit 1
fi
check_asan_log

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
check_asan_log

echo "[*] 4.5. Prerequisite Failure (RFC 2136 NOTZONE - Out of Zone Prerequisite)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "out-of-zone.example.com" --update-add 'new-invalid.dynupdate.com 300 A 2.3.4.6' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "NOTZONE" out.txt; then
    echo "[FAIL] Expected NOTZONE for out-of-zone prerequisite, output:"
    cat out.txt
    exit 1
fi
$DAG new-invalid.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "2.3.4.6" res.txt; then
    echo "[FAIL] Out-of-zone prerequisite UPDATE added record!"
    exit 1
fi
echo "[+] RFC 2136 §3.2.5 Out-of-zone prerequisite correctly rejected with NOTZONE."
check_asan_log

echo "[*] 5. Authorized UPDATE (Delete Record)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "new-host.dynupdate.com" --update-del 'new.dynupdate.com A' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
$DAG new.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.7" res.txt; then
    echo "[FAIL] Authorized UPDATE failed to delete record."
    exit 1
fi
check_asan_log

echo "[*] 6. Authorized UPDATE (Add Record for ephemeral test)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-add 'new1.dynupdate.com 300 A 1.2.3.4' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true

echo "[*] 6.5. In-flight ADD and Tombstone Logic test (3RR)..."
# 3RR test: Delete ALL -> Add -> Delete EXACT
$DAG dynupdate.com a @127.0.0.1 -p 10053 --update-del 'inflight.dynupdate.com ANY' --update-add 'inflight.dynupdate.com 300 A 10.0.0.1' --update-del-exact 'inflight.dynupdate.com 0 A 10.0.0.1' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true

# Verify it was successfully deleted (or never became visible)
$DAG inflight.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "10.0.0.1" res.txt; then
    echo "[FAIL] In-flight ADD or Tombstone logic failed. Record persisted."
    exit 1
fi
check_asan_log

echo "[*] 6.8. RFC 2136 Reject Meta-type TYPE=255 (ANY) in UPDATE ADD (FORMERR validation)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --break update-meta-type=255 +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "status: FORMERR" out.txt && ! grep -q "FORMERR" out.txt; then
    echo "[FAIL] Expected FORMERR for TYPE=255 in UPDATE ADD, output:"
    cat out.txt
    exit 1
fi
echo "[+] TYPE=255 ANY in UPDATE ADD successfully rejected with FORMERR."
check_asan_log

echo "[*] 6.9. RFC 2136 Reject Meta-type TYPE=41 (OPT) in UPDATE ADD (FORMERR validation)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --break update-meta-type=41 +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
if ! grep -q "status: FORMERR" out.txt && ! grep -q "FORMERR" out.txt; then
    echo "[FAIL] Expected FORMERR for TYPE=41 in UPDATE ADD, output:"
    cat out.txt
    exit 1
fi
echo "[+] TYPE=41 OPT in UPDATE ADD successfully rejected with FORMERR."
check_asan_log

echo "[*] 8. RFC 2136 §3 semantics (R-01, R-11): RCODE and zone content..."
TK="hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="
# upd EXPECTED_STATUS ZONE ARGS... : send an UPDATE signed with test-key and check the RCODE
upd() {
    _want=$1; _zone=$2; shift 2
    $DAG "$_zone" @127.0.0.1 -p 10053 +nohexdump -y "$TK" "$@" > out.txt 2>&1 || true
    if ! grep -q "opcode: UPDATE, status: $_want" out.txt; then
        echo "[FAIL] expected $_want for UPDATE $*"
        cat out.txt
        exit 1
    fi
}
soa_serials() {
    $DAG dynupdate.com. SOA @127.0.0.1 -p 10053 +short +nohexdump | awk '{print $3}' | tr '\n' ' '
}
# R-01: an SOA with a newer serial replaces the SOA (one SOA, that serial, not incremented again)
upd NOERROR dynupdate.com --update-add 'dynupdate.com 3600 IN SOA ns1.dynupdate.com. admin.dynupdate.com. 2026071900 3600 1800 604800 86400'
[ "$(soa_serials)" = "2026071900 " ] || { echo "[FAIL] R-01: SOA after update: $(soa_serials)"; exit 1; }
# an older serial is ignored
upd NOERROR dynupdate.com --update-add 'dynupdate.com 3600 IN SOA ns1.dynupdate.com. admin.dynupdate.com. 2026071800 3600 1800 604800 86400'
[ "$(soa_serials)" = "2026071900 " ] || { echo "[FAIL] older SOA serial was applied: $(soa_serials)"; exit 1; }
# prerequisites only: NOERROR, serial unchanged (RFC 2136 §3.6)
upd NOERROR dynupdate.com --prereq-yxdomain test.dynupdate.com
[ "$(soa_serials)" = "2026071900 " ] || { echo "[FAIL] prerequisite-only UPDATE changed the serial: $(soa_serials)"; exit 1; }
# R-11 a: owner outside the zone -> NOTZONE
upd NOTZONE dynupdate.com --update-add 'x.other.test 300 IN A 192.0.2.9'
# R-11 b: CNAME next to other data is ignored, the rest of the update is applied
upd NOERROR dynupdate.com --update-add 'test.dynupdate.com 300 IN CNAME ns1.dynupdate.com' --update-add 'r11b.dynupdate.com 300 IN A 192.0.2.21'
$DAG test.dynupdate.com. CNAME @127.0.0.1 -p 10053 +short +nohexdump > res.txt
[ ! -s res.txt ] || { echo "[FAIL] R-11 b: CNAME added next to TXT"; cat res.txt; exit 1; }
$DAG r11b.dynupdate.com. A @127.0.0.1 -p 10053 +short +nohexdump > res.txt
grep -qx "192.0.2.21" res.txt || { echo "[FAIL] R-11 b: the update RR after the ignored CNAME was not applied"; exit 1; }
# R-11 c: deleting the apex NS RRset is ignored
upd NOERROR dynupdate.com --update-del 'dynupdate.com NS'
$DAG dynupdate.com. NS @127.0.0.1 -p 10053 +short +nohexdump > res.txt
grep -qx "ns1.dynupdate.com." res.txt || { echo "[FAIL] R-11 c: apex NS deleted"; exit 1; }
# R-11 d: value-dependent prerequisite must match the whole RRset
upd NOERROR dynupdate.com --update-add 'r11d.dynupdate.com 300 IN A 192.0.2.31' --update-add 'r11d.dynupdate.com 300 IN A 192.0.2.32'
upd NXRRSET dynupdate.com --prereq=yxrrset:r11d.dynupdate.com:A:192.0.2.31 --update-add 'r11d-sub.dynupdate.com 300 IN A 192.0.2.33'
$DAG r11d-sub.dynupdate.com. A @127.0.0.1 -p 10053 +short +nohexdump > res.txt
[ ! -s res.txt ] || { echo "[FAIL] R-11 d: update applied after a subset prerequisite"; exit 1; }
# R-11 f: zone section naming a name below the zone apex -> NOTAUTH
upd NOTAUTH sub.dynupdate.com --update-add 'x.sub.dynupdate.com 300 IN A 192.0.2.9'
echo "[+] RFC 2136 §3 semantics checked."
check_asan_log

echo "[*] 7. Reload Server to check ephemeral behavior..."
$KARICTL -f "$CTL_CONF" reload
sleep 1

echo "[*] Checking if added record is gone..."
$DAG new1.dynupdate.com. A @127.0.0.1 -p 10053 +short > res.txt
if grep -q "1.2.3.4" res.txt; then
    echo "[FAIL] Record persisted after reload! It should be ephemeral."
    exit 1
fi
check_asan_log

echo "[OK] Dynamic Update tests passed!"
rm -f update.txt out.txt res.txt
echo "=== server.log ==="
cat server.log || true
exit 0
