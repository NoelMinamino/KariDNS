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
    [ -n "$SERVER_PID" ] && kill -9 $SERVER_PID 2>/dev/null || true
    killall -9 karidns-asan 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
    rm -f "$CONF" update.txt out.txt res.txt
}
trap cleanup EXIT INT TERM

check_asan_log() {
    if grep -qE "ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)" server.log; then
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

echo "[*] 5. Authorized UPDATE (Delete Record)..."
$DAG dynupdate.com a @127.0.0.1 -p 10053 --prereq-nxdomain "new-host.example.com" --update-del 'new.dynupdate.com A' +nohexdump-response -y hmac-sha256:test-key:C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y= > out.txt 2>&1 || true
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

echo "[*] 6.8. RFC 2136 Invalid CLASS in Prerequisite (FORMERR validation)..."
if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import socket, struct, time, hmac, hashlib, base64

# --- Test with TSIG signed packet to pass authentication and reach process_update_sections ---
req_id = 0xbeef
flags = 0x2800 # Opcode=5 (UPDATE)
zocount = 1
prcount = 1
upcount = 0
arcount = 0

hdr = struct.pack("!HHHHHH", req_id, flags, zocount, prcount, upcount, arcount)
zone = b"\x0a\x64\x79\x6e\x75\x70\x64\x61\x74\x65\x03\x63\x6f\x6d\x00\x00\x06\x00\x01"
prereq = b"\x04\x74\x65\x73\x74\x0a\x64\x79\x6e\x75\x70\x64\x61\x74\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x03\x00\x00\x00\x00\x00\x00"

raw_msg = hdr + zone + prereq

# TSIG signing (test-key)
key_name = b"\x08test-key\x00"
algo_name = b"\x0bhmac-sha256\x00"
secret_b64 = "C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y="
secret_key = base64.b64decode(secret_b64)

now = int(time.time())
time_signed_high = (now >> 32) & 0xFFFF
time_signed_low = now & 0xFFFFFFFF
fudge = 300

tsig_var = (key_name +
            struct.pack("!HI", 255, 0) +
            algo_name +
            struct.pack("!HIHHH", time_signed_high, time_signed_low, fudge, 0, 0))

mac = hmac.new(secret_key, raw_msg + tsig_var, hashlib.sha256).digest()

tsig_rdata = (algo_name +
              struct.pack("!HIH", time_signed_high, time_signed_low, fudge) +
              struct.pack("!H", len(mac)) + mac +
              struct.pack("!HHH", req_id, 0, 0))

tsig_rr = key_name + struct.pack("!HHIH", 250, 255, 0, len(tsig_rdata)) + tsig_rdata
assert len(tsig_rr) == len(key_name) + 10 + len(tsig_rdata)

final_hdr = struct.pack("!HHHHHH", req_id, flags, zocount, prcount, upcount, 1)
pkt = final_hdr + zone + prereq + tsig_rr

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(pkt, ("127.0.0.1", 10053))
resp, _ = s.recvfrom(512)

print("=== Response Hex Dump ===")
print(" ".join(f"{b:02x}" for b in resp))
resp_id, resp_flags, resp_qd, resp_an, resp_ns, resp_ar = struct.unpack("!HHHHHH", resp[:12])
rcode = resp_flags & 0x0F
print(f"Parsed: ID={resp_id:#06x}, Flags={resp_flags:#06x}, QD={resp_qd}, AN={resp_an}, NS={resp_ns}, AR={resp_ar}, RCODE={rcode}")

if rcode != 1:
    print(f"FAIL: Expected FORMERR (rcode=1), got rcode={rcode}")
    exit(1)
print("PASS: Got FORMERR for invalid CLASS with valid TSIG auth")
' > out.txt 2>&1 || {
        echo "[FAIL] RFC 2136 Invalid CLASS test failed:"
        cat out.txt
        exit 1
    }
fi
check_asan_log

echo "[*] 6.9. RFC 2136 Reject Meta-type TYPE=41 (OPT) in UPDATE ADD (FORMERR validation)..."
if which python3 >/dev/null 2>&1; then
    python3 -c '
import socket
import struct
import time
import hmac
import hashlib
import base64

req_id = 0x8899
flags = 0x2800 # Opcode=5 (UPDATE), RD=0
zocount = 1
prcount = 0
upcount = 1
arcount = 0

hdr = struct.pack("!HHHHHH", req_id, flags, zocount, prcount, upcount, arcount)
zone = b"\x09dynupdate\x03com\x00" + struct.pack("!HH", 6, 1) # SOA, IN

# UPDATE ADD with TYPE=41 (OPT), CLASS=IN (1), TTL=0, RDLEN=0
update_rr = b"\x03opt\x09dynupdate\x03com\x00" + struct.pack("!HHIH", 41, 1, 0, 0)

raw_msg = hdr + zone + update_rr

secret_key = base64.b64decode("C+Cxy/p+lR2oHn+o8K2ZlJ2C/lH1X4Q+N/k/mN9mN2Y=")
key_name = b"\x08test-key\x00"
algo_name = b"\x0bhmac-sha256\x00"
now = int(time.time())
time_signed_high = (now >> 32) & 0xFFFF
time_signed_low = now & 0xFFFFFFFF
fudge = 300

tsig_var = (key_name +
            struct.pack("!HI", 255, 0) +
            algo_name +
            struct.pack("!HIHHH", time_signed_high, time_signed_low, fudge, 0, 0))

mac = hmac.new(secret_key, raw_msg + tsig_var, hashlib.sha256).digest()

tsig_rdata = (algo_name +
              struct.pack("!HIH", time_signed_high, time_signed_low, fudge) +
              struct.pack("!H", len(mac)) + mac +
              struct.pack("!HHH", req_id, 0, 0))

tsig_rr = key_name + struct.pack("!HHIH", 250, 255, 0, len(tsig_rdata)) + tsig_rdata

final_hdr = struct.pack("!HHHHHH", req_id, flags, zocount, prcount, upcount, 1)
pkt = final_hdr + zone + update_rr + tsig_rr

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(pkt, ("127.0.0.1", 10053))
resp, _ = s.recvfrom(512)

resp_id, resp_flags, resp_qd, resp_an, resp_ns, resp_ar = struct.unpack("!HHHHHH", resp[:12])
rcode = resp_flags & 0x0F
print(f"Parsed: ID={resp_id:#06x}, Flags={resp_flags:#06x}, RCODE={rcode}")

if rcode != 1:
    print(f"FAIL: Expected FORMERR (rcode=1) for TYPE=41 in UPDATE ADD, got rcode={rcode}")
    exit(1)
print("PASS: Got FORMERR for TYPE=41 (OPT) in UPDATE ADD with valid TSIG auth")
' > out.txt 2>&1 || {
        echo "[FAIL] RFC 2136 TYPE=41 (OPT) in UPDATE ADD test failed:"
        cat out.txt
        exit 1
    }
fi
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

check_asan_log
if killall -0 karidns-asan 2>/dev/null; then
    killall -9 karidns-asan 2>/dev/null
fi

echo "[OK] Dynamic Update tests passed!"
rm -f update.txt out.txt res.txt
echo "=== server.log ==="
cat server.log || true
exit 0
