#!/bin/sh
set -e

echo "[+] Starting Catalog Zone tests..."

# Setup workspace
TEST_DIR="catalog_test_dir"
rm -rf $TEST_DIR
mkdir -p $TEST_DIR
cd $TEST_DIR
TEST_DIR_ABS=$(pwd)

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

# Build (assume it's already built, we just run it)
../karidns -f karidns.conf > karidns.log 2>&1 &
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
echo "[+] CoO transfer successfully verified!"

# Clean up
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "[+] Server is still running, cascading removal didn't crash."
else
    echo "[-] Server crashed during cascading removal!"
    exit 1
fi

echo "[+] Verifying dag resolution (all former members should be REFUSED)"
../dag -p 53530 @127.0.0.1 example.org. SOA | grep "status: REFUSED" || { echo "Failed: example.org should be REFUSED"; kill $SERVER_PID; exit 1; }
../dag -p 53530 @127.0.0.1 example.edu. SOA | grep "status: REFUSED" || { echo "Failed: example.edu should be REFUSED"; kill $SERVER_PID; exit 1; }

kill $SERVER_PID
wait $SERVER_PID || true

echo "[+] Catalog Zone tests passed!"
exit 0
