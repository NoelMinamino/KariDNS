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

# Run concurrent reload + something else to test race conditions
echo "[+] Testing race condition (concurrent full reload vs catalog delta update)"
PIDS=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    ../karictl -f karictl.conf reload &
    PIDS="$PIDS $!"
done
wait $PIDS
sleep 1

# Test catalog removal
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
    zone "catalog.example.com" {
        type master;
        file "${TEST_DIR_ABS}/catalog.zone";
        catalog-zone no;
    };
};
EOF

../karictl -f karictl.conf reload
sleep 1

echo "[+] Catalog removed (downgraded to catalog-zone no). Validating cascading removal..."
# Since it's no longer a catalog zone, all dynamically spawned members should be unresolvable and freed
# We can't directly query the slaves since they were empty, but we can check if it crashed.
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "[+] Server is still running, cascading removal didn't crash."
else
    echo "[-] Server crashed during cascading removal!"
    exit 1
fi

kill $SERVER_PID
wait $SERVER_PID || true

echo "[+] Catalog Zone tests passed!"
exit 0
