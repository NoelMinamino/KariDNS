#!/bin/sh
set -e

# ==============================================================================
# KariDNS Multi-Instance, PID Lock Isolation & AXFR Zone Transfer Test Suite
#
# Verifies:
# 1. Multi-instance execution: Multiple KariDNS instances run simultaneously
#    in foreground mode (-f) with separate ports and control sockets without
#    PID file lock collisions.
# 2. Control channel isolation: karictl connects to the respective instance via
#    -s <socket_path> or karictl.conf socket directive.
# 3. AXFR zone transfer between instances: Instance 1 acts as Master and
#    Instance 2 acts as Slave. Verifies Slave performs AXFR from Master over TCP,
#    installs the zone, and correctly serves queries on its port.
# 4. Dynamic zone update & retransfer: Updates Master zone, reloads via karictl,
#    triggers retransfer on Slave via karictl, and confirms Slave serves the new data.
# 5. PID file mutual exclusion: When pid-file is explicitly configured (-p or
#    options { pid-file "..."; }), a second instance attempting to use the same
#    pidfile is cleanly rejected.
# 6. pid-file "none" directive: Explicitly disabling the PID file allows running
#    without creating any lock file.
# 7. Lock release on termination: Killing the frontend router immediately
#    releases the PID file lock (backend child process never inherits/holds pid_fd).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building karidns, karictl, and dag with make ==="
make -C "$ROOT_DIR" karidns karictl dag

KARIDNS="$ROOT_DIR/karidns"
KARICTL="$ROOT_DIR/karictl"
DAG="$ROOT_DIR/dag"

FAILED=0
PORT1=$((23000 + $$ % 4000))
PORT2=$((PORT1 + 2))
TMP_DIR="/tmp/karidns_multi_instance_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
    killall -9 karidns 2>/dev/null || true
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Prepare sample static zone
cat << 'EOF' > "$TMP_DIR/test.example.com.zone"
$TTL 300
@ IN SOA ns1.test.example.com. hostmaster.test.example.com. (
    2026090101 ; Serial
    3600 600 86400 300
)
@       IN NS   ns1.test.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.10
EOF

# Prepare initial transfer master zone
cat << 'EOF' > "$TMP_DIR/transfer_master.zone"
$TTL 300
@ IN SOA ns1.transfer.example.com. hostmaster.transfer.example.com. (
    2026090101 ; Serial
    3600 600 86400 300
)
@       IN NS   ns1.transfer.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.10
mail    IN A    192.0.2.20
EOF

# Shared karictl secret
SECRET="dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"

# Server 1 configuration (Master on PORT1)
cat << EOF > "$TMP_DIR/server1.conf"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    socket "$TMP_DIR/ctl1.sock";
    algorithm hmac-sha256;
    secret "$SECRET";
};

zone "test.example.com" {
    type master;
    file "$TMP_DIR/test.example.com.zone";
};

zone "transfer.example.com" {
    type master;
    file "$TMP_DIR/transfer_master.zone";
    allow-transfer { 127.0.0.1; };
};
EOF

# Server 2 configuration (Slave on PORT2)
cat << EOF > "$TMP_DIR/server2.conf"
options {
    port $PORT2;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    socket "$TMP_DIR/ctl2.sock";
    algorithm hmac-sha256;
    secret "$SECRET";
};

zone "test.example.com" {
    type master;
    file "$TMP_DIR/test.example.com.zone";
};

zone "transfer.example.com" {
    type slave;
    masters { 127.0.0.1 port $PORT1; };
};
EOF

# karictl config template
cat << EOF > "$TMP_DIR/karictl.conf"
key "karictl" {
    algorithm hmac-sha256;
    secret "$SECRET";
};
EOF

echo ""
echo "=== Test 1: Parallel Multi-Instance Foreground Mode (-f) ==="
echo -n "Starting Master Instance 1 (port $PORT1) and Slave Instance 2 (port $PORT2) ... "

"$KARIDNS" -f "$TMP_DIR/server1.conf" > "$TMP_DIR/server1.log" 2>&1 &
PID1=$!

# Ensure Master is fully initialized before starting Slave
sleep 1

"$KARIDNS" -f "$TMP_DIR/server2.conf" > "$TMP_DIR/server2.log" 2>&1 &
PID2=$!

sleep 1

# Check both processes are still alive
if ! kill -0 "$PID1" 2>/dev/null; then
    echo "FAILED (Instance 1 died at startup)"
    cat "$TMP_DIR/server1.log"
    FAILED=$((FAILED + 1))
elif ! kill -0 "$PID2" 2>/dev/null; then
    echo "FAILED (Instance 2 died at startup - possible PID lock collision)"
    cat "$TMP_DIR/server2.log"
    FAILED=$((FAILED + 1))
else
    # Verify static DNS queries to both instances
    ANS1=$("$DAG" @127.0.0.1 -p "$PORT1" www.test.example.com A +short 2>&1 || true)
    ANS2=$("$DAG" @127.0.0.1 -p "$PORT2" www.test.example.com A +short 2>&1 || true)

    if [ "$ANS1" = "192.0.2.10" ] && [ "$ANS2" = "192.0.2.10" ]; then
        echo "OK (Both instances serving DNS queries concurrently)"
    else
        echo "FAILED (Query failed: ANS1='$ANS1', ANS2='$ANS2')"
        FAILED=$((FAILED + 1))
    fi
fi

echo -n "Verifying isolated control-channel communication via karictl -s ... "
STATUS1=$("$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl1.sock" status 2>&1 || true)
STATUS2=$("$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl2.sock" status 2>&1 || true)

if echo "$STATUS1" | grep -q "server is up and running" && echo "$STATUS2" | grep -q "server is up and running"; then
    echo "OK (Both control sockets responding independently)"
else
    echo "FAILED"
    echo "Status 1: $STATUS1"
    echo "Status 2: $STATUS2"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Test 2: AXFR Zone Transfer from Master to Slave ==="
echo -n "Triggering AXFR transfer on Slave (Port $PORT2 from Port $PORT1) ... "
"$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl2.sock" retransfer transfer.example.com >/dev/null 2>&1 || true

# Poll Slave until AXFR is received and served
TRANSFER_OK=0
for i in $(seq 1 20); do
    SLAVE_WWW=$("$DAG" @127.0.0.1 -p "$PORT2" www.transfer.example.com A +short 2>&1 || true)
    if [ "$SLAVE_WWW" = "192.0.2.10" ]; then
        TRANSFER_OK=1
        break
    fi
    sleep 0.5
done

if [ "$TRANSFER_OK" -eq 1 ]; then
    echo "OK"
else
    echo "FAILED (Slave did not answer with transferred record within timeout)"
    echo "  Slave query output: '$SLAVE_WWW'"
    echo "  Slave log:"
    tail -n 20 "$TMP_DIR/server2.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

echo -n "Verifying Slave's transferred SOA serial and mail record ... "
SLAVE_MAIL=$("$DAG" @127.0.0.1 -p "$PORT2" mail.transfer.example.com A +short 2>&1 || true)
SLAVE_SOA=$("$DAG" @127.0.0.1 -p "$PORT2" transfer.example.com SOA +short 2>&1 || true)

if [ "$SLAVE_MAIL" = "192.0.2.20" ] && echo "$SLAVE_SOA" | grep -q "2026090101"; then
    echo "OK (All transferred records and SOA verified on Slave)"
else
    echo "FAILED (mail='$SLAVE_MAIL', soa='$SLAVE_SOA')"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Test 3: Dynamic Zone Update & Retransfer to Slave ==="
sleep 1
echo -n "Updating Master zone file with bumped serial 2026090102 and new record ... "
cat << 'EOF' > "$TMP_DIR/transfer_master.zone"
$TTL 300
@ IN SOA ns1.transfer.example.com. hostmaster.transfer.example.com. (
    2026090102 ; Serial (updated)
    3600 600 86400 300
)
@       IN NS   ns1.transfer.example.com.
ns1     IN A    127.0.0.1
www     IN A    192.0.2.99
mail    IN A    192.0.2.20
newrec  IN TXT  "transferred-via-axfr"
EOF

# Reload Master
"$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl1.sock" reload transfer.example.com >/dev/null 2>&1
sleep 0.5

# Verify Master updated
MASTER_WWW=$("$DAG" @127.0.0.1 -p "$PORT1" www.transfer.example.com A +short 2>&1 || true)
if [ "$MASTER_WWW" = "192.0.2.99" ]; then
    echo "OK"
else
    echo "FAILED (Master did not reload new record: got '$MASTER_WWW')"
    FAILED=$((FAILED + 1))
fi

echo -n "Triggering retransfer on Slave and verifying updated zone response ... "
"$KARICTL" -f "$TMP_DIR/karictl.conf" -s "$TMP_DIR/ctl2.sock" retransfer transfer.example.com >/dev/null 2>&1

UPDATE_OK=0
for i in $(seq 1 20); do
    SLAVE_UPDATED_WWW=$("$DAG" @127.0.0.1 -p "$PORT2" www.transfer.example.com A +short 2>&1 || true)
    if [ "$SLAVE_UPDATED_WWW" = "192.0.2.99" ]; then
        UPDATE_OK=1
        break
    fi
    sleep 0.5
done

SLAVE_TXT=$("$DAG" @127.0.0.1 -p "$PORT2" newrec.transfer.example.com TXT +short 2>&1 || true)
SLAVE_UPDATED_SOA=$("$DAG" @127.0.0.1 -p "$PORT2" transfer.example.com SOA +short 2>&1 || true)

if [ "$UPDATE_OK" -eq 1 ] && echo "$SLAVE_TXT" | grep -q "transferred-via-axfr" && echo "$SLAVE_UPDATED_SOA" | grep -q "2026090102"; then
    echo "OK (Slave accurately updated and serving new zone data)"
else
    echo "FAILED (www='$SLAVE_UPDATED_WWW', txt='$SLAVE_TXT', soa='$SLAVE_UPDATED_SOA')"
    echo "  Slave log:"
    tail -n 25 "$TMP_DIR/server2.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
fi

# Clean up running test instances
kill -9 "$PID1" "$PID2" 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
sleep 0.5

echo ""
echo "=== Test 4: PID File Mutual Exclusion (-p flag) ==="
SHARED_PID_FILE="$TMP_DIR/shared.pid"

echo -n "Starting primary instance holding $SHARED_PID_FILE ... "
"$KARIDNS" -f -p "$SHARED_PID_FILE" "$TMP_DIR/server1.conf" > "$TMP_DIR/prim.log" 2>&1 &
PRIM_PID=$!
sleep 1

if ! kill -0 "$PRIM_PID" 2>/dev/null; then
    echo "FAILED (Primary instance failed to start)"
    cat "$TMP_DIR/prim.log"
    FAILED=$((FAILED + 1))
else
    echo "OK"
fi

echo -n "Attempting duplicate instance with same PID file (must be rejected) ... "
if "$KARIDNS" -f -p "$SHARED_PID_FILE" "$TMP_DIR/server2.conf" > "$TMP_DIR/dup.log" 2>&1; then
    echo "FAILED (Duplicate instance unexpectedly succeeded)"
    FAILED=$((FAILED + 1))
else
    if grep -q -i "already running" "$TMP_DIR/dup.log"; then
        echo "OK (Rejected with 'already running' as expected)"
    else
        echo "FAILED (Exited non-zero but missing error message)"
        cat "$TMP_DIR/dup.log"
        FAILED=$((FAILED + 1))
    fi
fi

# Stop primary instance
kill -9 "$PRIM_PID" 2>/dev/null || true
killall -9 karidns 2>/dev/null || true
sleep 0.5

echo -n "Starting secondary instance with released PID file ... "
"$KARIDNS" -f -p "$SHARED_PID_FILE" "$TMP_DIR/server2.conf" > "$TMP_DIR/sec.log" 2>&1 &
SEC_PID=$!
sleep 1

if kill -0 "$SEC_PID" 2>/dev/null; then
    echo "OK (Secondary successfully acquired released PID file)"
    kill -9 "$SEC_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
else
    echo "FAILED (Could not acquire released PID file)"
    cat "$TMP_DIR/sec.log"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Test 5: options { pid-file \"none\"; } Directive ==="
cat << EOF > "$TMP_DIR/server_nopid.conf"
options {
    port $PORT1;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
    pid-file "none";
};
zone "test.example.com" {
    type master;
    file "$TMP_DIR/test.example.com.zone";
};
EOF

echo -n "Starting instance configured with pid-file \"none\" ... "
"$KARIDNS" -f "$TMP_DIR/server_nopid.conf" > "$TMP_DIR/nopid.log" 2>&1 &
NOPID_PID=$!
sleep 1

if kill -0 "$NOPID_PID" 2>/dev/null; then
    echo "OK (Started cleanly without PID file)"
    kill -9 "$NOPID_PID" 2>/dev/null || true
    killall -9 karidns 2>/dev/null || true
else
    echo "FAILED"
    cat "$TMP_DIR/nopid.log"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Test 6: Immediate PID File Release on Frontend SIGKILL ==="
FLOCK_PID_FILE="$TMP_DIR/kill_release.pid"
echo -n "Starting instance with PID lock ... "
"$KARIDNS" -f -p "$FLOCK_PID_FILE" "$TMP_DIR/server1.conf" > "$TMP_DIR/kill1.log" 2>&1 &
K1_PID=$!
sleep 1

if ! kill -0 "$K1_PID" 2>/dev/null; then
    echo "FAILED (Instance failed to start)"
    FAILED=$((FAILED + 1))
else
    echo "OK (PID=$K1_PID)"
fi

echo -n "Sending SIGKILL to frontend process and immediately launching new instance ... "
# Kill only frontend router (parent) with SIGKILL
kill -9 "$K1_PID" 2>/dev/null || true

# Launch immediately: If backend held pid_fd, this would fail with flock collision
if "$KARIDNS" -f -p "$FLOCK_PID_FILE" "$TMP_DIR/server2.conf" > "$TMP_DIR/kill2.log" 2>&1 & then
    K2_PID=$!
    sleep 1
    if kill -0 "$K2_PID" 2>/dev/null; then
        echo "OK (Lock was freed immediately; new instance acquired lock)"
        kill -9 "$K2_PID" 2>/dev/null || true
        killall -9 karidns 2>/dev/null || true
    else
        echo "FAILED (New instance could not acquire lock)"
        cat "$TMP_DIR/kill2.log"
        FAILED=$((FAILED + 1))
    fi
else
    echo "FAILED (Could not launch new instance)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "========================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "ALL MULTI-INSTANCE, AXFR & PID FILE TESTS PASSED"
    exit 0
else
    echo "TOTAL FAILURES: $FAILED"
    exit 1
fi
========================================================
