#!/bin/sh
set -e

echo "[+] Starting Catalog Zone tests..."

# Setup workspace
TEST_DIR="catalog_test_dir"
rm -rf $TEST_DIR
mkdir -p $TEST_DIR
cd $TEST_DIR
TEST_DIR_ABS=$(pwd)

# Trap for cleanup and automatic kdump on failure
cleanup() {
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo "[-] Test failed with exit code $EXIT_CODE"
        if [ -n "$SERVER_PID" ]; then
            kill -9 $SERVER_PID 2>/dev/null || true
        fi
        if [ -f ktrace.out ] && which kdump >/dev/null 2>&1; then
            echo "=== [KDUMP TRACE (Last 100 lines)] ==="
            kdump -f ktrace.out 2>/dev/null | tail -n 100 || true
            echo "======================================"
        fi
        if [ -f karidns.log ]; then
            echo "=== [KARIDNS LOG (Last 50 lines)] ==="
            tail -n 50 karidns.log || true
            echo "====================================="
        fi
    fi
}
trap cleanup EXIT INT TERM

# Create a master catalog zone file
cat << 'EOF' > catalog.zone
$ORIGIN catalog.example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
zone1.zones IN PTR example.net.
zone2.zones IN PTR example.org.
EOF

# Create the config file
cat << EOF > karidns.conf
options {
    port 53530;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "catalog.example.com" {
        type master;
        file "${TEST_DIR_ABS}/catalog.zone";
        catalog-zone yes;
    };
};
EOF

cat << 'EOF' > karictl.conf
key "karictl" {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};
EOF

# Build & Run with ktrace if available
if which ktrace >/dev/null 2>&1; then
    echo "[+] Running karidns under ktrace (-di)..."
    ktrace -di -f ktrace.out ../karidns -f karidns.conf > karidns.log 2>&1 &
else
    ../karidns -f karidns.conf > karidns.log 2>&1 &
fi
SERVER_PID=$!
sleep 1

# Check if member zones are mapped and resolve
echo "[+] Checking if initial catalog members are resolvable..."
# we expect the slave zones to attempt an AXFR (but since there's no real master they might fail)
# Wait, the catalog slave zones need a master to transfer from! The config parser uses the catalog's masters.
# In our karidns.conf, the catalog zone is master, it has no masters to copy.
# Wait, if catalog zone is master and has no masters, the slaves will have no masters. They will be empty.
# But they should at least reply with REFUSED or SERVFAIL or SOA?
# Wait, let's look at `create_new_zone_entry`. It just creates the zone entry. If it has no records, it replies REFUSED or SERVFAIL.
echo "Checking logs to see if membership was processed..."
grep "Processed membership for 'catalog.example.com.', desired members: 2" karidns.log || { echo "Failed to process membership"; kill $SERVER_PID; exit 1; }

echo "[+] Checking dag resolution for example.net (should be SERVFAIL because empty member)"
../dag -p 53530 @127.0.0.1 example.net. SOA > dag_output.txt 2>&1
cat dag_output.txt
grep "status: SERVFAIL" dag_output.txt || { echo "Failed: example.net did not return SERVFAIL"; kill $SERVER_PID; exit 1; }

echo "[+] Checking dag resolution for example.org (should be SERVFAIL)"
../dag -p 53530 @127.0.0.1 example.org. SOA | grep "status: SERVFAIL" || { echo "Failed: example.org did not return SERVFAIL"; kill $SERVER_PID; exit 1; }

echo "[+] Checking dag resolution for example.edu (should be REFUSED because it's not a member yet)"
../dag -p 53530 @127.0.0.1 example.edu. SOA | grep "status: REFUSED" || { echo "Failed: example.edu did not return REFUSED"; kill $SERVER_PID; exit 1; }

# Now let's update the catalog zone (add zone3, remove zone1)
cat << 'EOF' > catalog.zone
$ORIGIN catalog.example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 2 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
zone2.zones IN PTR example.org.
zone3.zones IN PTR example.edu.
EOF

../karictl -f karictl.conf reload
sleep 1
grep "Processed membership for 'catalog.example.com.', desired members: 2" karidns.log || { echo "Failed to process membership after reload"; kill $SERVER_PID; exit 1; }

echo "[+] Checking dag resolution after update"
OUT=$(../dag -p 53530 @127.0.0.1 example.net. SOA)
echo "$OUT" | grep "status: REFUSED" || { echo "Failed: example.net should be REFUSED now"; echo "$OUT"; cat karidns.log; kill $SERVER_PID; exit 1; }
OUT=$(../dag -p 53530 @127.0.0.1 example.org. SOA)
echo "$OUT" | grep "status: SERVFAIL" || { echo "Failed: example.org should still be SERVFAIL"; echo "$OUT"; kill $SERVER_PID; exit 1; }
OUT=$(../dag -p 53530 @127.0.0.1 example.edu. SOA)
echo "$OUT" | grep "status: SERVFAIL" || { echo "Failed: example.edu should be SERVFAIL now"; echo "$OUT"; kill $SERVER_PID; exit 1; }

# Run concurrent reload + something else to test race conditions
echo "[+] Testing race condition (concurrent full reload vs catalog delta update)"
PIDS=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    ../karictl -f karictl.conf reload &
    PIDS="$PIDS $!"
done
wait $PIDS
sleep 1

# Check resolution still intact after race condition test
../dag -p 53530 @127.0.0.1 example.edu. SOA | grep "status: SERVFAIL" || { echo "Failed: example.edu broken after race test"; kill $SERVER_PID; exit 1; }


echo "[+] Phase 0 Unique-ID Test: Changing unique-id of example.org..."
perl -pi -e 's/zone2\.zones/zone2_new\.zones/' catalog.zone
../karictl -f karictl.conf reload
sleep 1
grep "Added new member 'example.org.' (unique-id: zone2_new)" karidns.log || {
    echo "Failed: example.org was not added correctly as a new member after unique-id change"; cat karidns.log; kill $SERVER_PID; exit 1; 
}
../dag -p 53530 @127.0.0.1 example.org. SOA > dag_out.txt || true
grep "status: SERVFAIL" dag_out.txt || { echo "Failed: example.org broke after unique-id change"; cat dag_out.txt; kill $SERVER_PID; exit 1; }

echo "[+] Phase 1 Group Test: Adding an orphaned group to catalog.zone and testing karicheck..."
echo 'group.orphan.zones IN TXT "testgroup"' >> catalog.zone
../karicheck zones karidns.conf > karicheck_out.txt 2>&1
grep "Orphaned group TXT record" karicheck_out.txt || { echo "Failed: karicheck did not detect orphaned group TXT record"; cat karicheck_out.txt; kill $SERVER_PID; exit 1; }
echo "[+] karicheck properly detected orphaned group."

echo "[+] Phase 2 CoO Test: Setting up two catalog zones for transfer..."
cat << EOF > karidns.conf
options {
    port 53530;
    bind-address { 127.0.0.1; };
    user "nobody";
    group "nobody";
};

control-channel {
    algorithm hmac-sha256;
    secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl";
};

view "default" {
    match-clients { any; };
    zone "catalog1.example.com" {
        type master;
        file "${TEST_DIR_ABS}/catalog1.zone";
        catalog-zone yes;
    };
    zone "catalog2.example.com" {
        type master;
        file "${TEST_DIR_ABS}/catalog2.zone";
        catalog-zone yes;
    };
};
EOF

cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
abc.zones IN PTR coo-test.com.
EOF

cat << EOF > catalog2.zone
\$ORIGIN catalog2.example.com.
@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF

../karictl -f karictl.conf reconfig
sleep 1

# Verify coo-test.com is loaded (returns SERVFAIL instead of REFUSED because it has no records)
../dag -p 53530 @127.0.0.1 coo-test.com. SOA > dag_out.txt || true
grep "status: SERVFAIL" dag_out.txt || { echo "Failed: coo-test.com not loaded by catalog1"; cat dag_out.txt; kill $SERVER_PID; exit 1; }

echo "[+] CoO Test: catalog2 tries to steal coo-test.com (collision expected)..."
cat << EOF > catalog2.zone
\$ORIGIN catalog2.example.com.
@ IN SOA ns1.example.com. admin.example.com. 2 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
xyz.zones IN PTR coo-test.com.
EOF

../karictl -f karictl.conf reload catalog2.example.com
sleep 1

echo "[+] CoO Test: Initiating valid transfer (adding coo PTR to catalog1)..."
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 2 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
abc.zones IN PTR coo-test.com.
coo.abc.zones IN PTR catalog2.example.com.
EOF

../karictl -f karictl.conf reload catalog1.example.com
sleep 1

echo "[+] CoO Test: Triggering evaluation on catalog2 (transfer should succeed)..."
cat << EOF > catalog2.zone
\$ORIGIN catalog2.example.com.
@ IN SOA ns1.example.com. admin.example.com. 3 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
xyz.zones IN PTR coo-test.com.
EOF

../karictl -f karictl.conf reload catalog2.example.com
sleep 1

echo "[+] CoO Test: Verifying transfer... Removing from catalog1 should NOT delete the zone."
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 3 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF

../karictl -f karictl.conf reload catalog1.example.com
sleep 1

# If the zone was correctly transferred to catalog2, removing it from catalog1 shouldn't kill it.
../dag -p 53530 @127.0.0.1 coo-test.com. SOA > dag_out.txt || true
grep "status: SERVFAIL" dag_out.txt || { echo "Failed: coo-test.com was deleted even though catalog2 should own it"; cat dag_out.txt; kill $SERVER_PID; exit 1; }

# Verify that State Reset was properly executed (unique-ids changed)
grep "evicted old state for 'coo-test.com.' (old unique-id: abc, new unique-id: xyz)" karidns.log || { echo "Failed: State reset eviction log missing"; cat karidns.log; kill $SERVER_PID; exit 1; }
echo "[+] CoO transfer (State Reset) successfully verified!"

echo "[+] Phase 3 CoO State Retention Test: Transferring with identical unique-id..."
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 4 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
retain.zones IN PTR state-retain.com.
coo.retain.zones IN PTR catalog2.example.com.
EOF

../karictl -f karictl.conf reload catalog1.example.com
sleep 1

# Trigger transfer on catalog2 with SAME unique-id 'retain'
cat << EOF > catalog2.zone
\$ORIGIN catalog2.example.com.
@ IN SOA ns1.example.com. admin.example.com. 4 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
xyz.zones IN PTR coo-test.com.
retain.zones IN PTR state-retain.com.
EOF

../karictl -f karictl.conf reload catalog2.example.com
sleep 1

# Verify retention log
grep "retained state for 'state-retain.com.' (unique-id: retain), owner catalog1.example.com. -> catalog2.example.com." karidns.log || { echo "Failed: State retention log missing"; cat karidns.log; kill $SERVER_PID; exit 1; }

# Remove from catalog1 to confirm it doesn't drop
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 5 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF

../karictl -f karictl.conf reload catalog1.example.com
sleep 1

../dag -p 53530 @127.0.0.1 state-retain.com. SOA > dag_out.txt || true
grep "status: SERVFAIL" dag_out.txt || { echo "Failed: state-retain.com dropped after retention transfer"; cat dag_out.txt; kill $SERVER_PID; exit 1; }

echo "[+] CoO transfer (State Retention) successfully verified!"

echo "[+] Phase 4: Large Catalog Zone Benchmark (5,000 members)..."
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 10 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF

perl -e 'for ($i = 1; $i <= 5000; $i++) { print "m$i.zones IN PTR member$i.example.net.\n"; }' >> catalog1.zone

START_MS=$(perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)' 2>/dev/null || date +%s000)
../karictl -f karictl.conf reload catalog1.example.com
END_MS=$(perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)' 2>/dev/null || date +%s000)
echo "[Benchmark] Initial load (5,000 members): $((END_MS - START_MS)) ms"
sleep 1

../dag -p 53530 @127.0.0.1 member1.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: member1 not loaded"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 member2500.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: member2500 not loaded"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 member5000.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: member5000 not loaded"; kill $SERVER_PID; exit 1; }
echo "[+] Initial 5,000 members loaded successfully."

# Delta update benchmark: replace 1,000 members
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 11 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF

perl -e 'for ($i = 1; $i <= 1000; $i++) { print "new_m$i.zones IN PTR new-member$i.example.net.\n"; } for ($i = 1001; $i <= 5000; $i++) { print "m$i.zones IN PTR member$i.example.net.\n"; }' >> catalog1.zone

DELTA_START_MS=$(perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)' 2>/dev/null || date +%s000)
../karictl -f karictl.conf reload catalog1.example.com
DELTA_END_MS=$(perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)' 2>/dev/null || date +%s000)
echo "[Benchmark] Delta update (1,000 member swap out of 5,000): $((DELTA_END_MS - DELTA_START_MS)) ms"
sleep 1

../dag -p 53530 @127.0.0.1 member1.example.net. SOA | grep "status: REFUSED" || { echo "Failed: member1 was not removed"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 new-member1.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: new-member1 not loaded"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 member5000.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: member5000 broken"; kill $SERVER_PID; exit 1; }
echo "[+] Large catalog zone delta update (5,000 members) verified successfully!"

echo "[+] Phase 5: RFC 9432 §5.1 Broken Catalog Zone Detection Tests..."
# Test 5.1: Duplicate PTR records for the same unique-N
cp ../zones/catalog_duplicate_ptr.zone catalog1.zone
../karictl -f karictl.conf reload catalog1.example.com
sleep 1
grep "has 2 PTR records (RFC 9432 requires exactly 1); catalog zone is broken" karidns.log || {
    echo "Failed: duplicate PTR on same unique-N was not detected as broken catalog zone"; cat karidns.log; kill $SERVER_PID; exit 1;
}
../dag -p 53530 @127.0.0.1 member1.example.net. SOA | grep "status: REFUSED" || { echo "Failed: member1 should be REFUSED on broken catalog"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 member2.example.net. SOA | grep "status: REFUSED" || { echo "Failed: member2 should be REFUSED on broken catalog"; kill $SERVER_PID; exit 1; }
echo "[+] Test 5.1 (Duplicate PTR on same unique-N) successfully rejected."

# Test 5.2: Different unique-N pointing to the same target domain
cp ../zones/catalog_duplicate_target.zone catalog1.zone
../karictl -f karictl.conf reload catalog1.example.com
sleep 1
grep "is referenced by both 'node1' and 'node2' labels; catalog zone is broken" karidns.log || {
    echo "Failed: duplicate target domain across labels was not detected as broken catalog zone"; cat karidns.log; kill $SERVER_PID; exit 1;
}
../dag -p 53530 @127.0.0.1 member1.example.net. SOA | grep "status: REFUSED" || { echo "Failed: member1 should be REFUSED on duplicate target catalog"; kill $SERVER_PID; exit 1; }
echo "[+] Test 5.2 (Duplicate target domain across unique-N) successfully rejected."

# Test 5.3: Valid catalog zone regression test
cp ../zones/catalog_valid.zone catalog1.zone
../karictl -f karictl.conf reload catalog1.example.com
sleep 1
../dag -p 53530 @127.0.0.1 member1.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: member1 should be loaded in valid catalog"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 member2.example.net. SOA | grep "status: SERVFAIL" || { echo "Failed: member2 should be loaded in valid catalog"; kill $SERVER_PID; exit 1; }
echo "[+] Test 5.3 (Valid catalog zone) successfully loaded."

# Clean up catalog1 before final checks
cat << EOF > catalog1.zone
\$ORIGIN catalog1.example.com.
@ IN SOA ns1.example.com. admin.example.com. 20 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF
../karictl -f karictl.conf reload catalog1.example.com
sleep 1

# Clean up
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "[+] Server is still running, cascading removal didn't crash."
else
    echo "[-] Server crashed during cascading removal!"
    exit 1
fi

echo "[+] Verifying dag resolution (all former members should be REFUSED)"
../dag -p 53530 @127.0.0.1 member1.example.net. SOA | grep "status: REFUSED" || { echo "Failed: member1 should be REFUSED"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 member2.example.net. SOA | grep "status: REFUSED" || { echo "Failed: member2 should be REFUSED"; kill $SERVER_PID; exit 1; }

kill $SERVER_PID
wait $SERVER_PID || true

echo "[+] Catalog Zone tests passed!"
exit 0
