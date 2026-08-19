#!/bin/sh
set -e

echo "[+] Starting CVE CoO buffer overflow tests..."

TEST_DIR="coo_cve_test_dir"
rm -rf $TEST_DIR
mkdir -p $TEST_DIR
cd $TEST_DIR
TEST_DIR_ABS=$(pwd)

# Create a master catalog zone file with 20 items to trigger realloc
# Capacity starts at 16, so 20 items will trigger exactly one realloc.
cat << 'EOF' > catalog.zone
$ORIGIN catalog.example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400
@ IN NS ns1.example.com.
version IN TXT "2"
EOF

for i in $(seq 1 20); do
    echo "zone${i}.zones IN PTR example${i}.net." >> catalog.zone
    # Adding a very long coo target
    echo "zone${i}.zones IN PTR longcoo${i}.this-is-a-very-long-target-that-is-meant-to-test-strncpy-overflow-this-is-a-very-long-target-that-is-meant-to-test-strncpy-overflow-this-is-a-very-long-target-that-is-meant-to-test-strncpy-overflow-this-is-a-very-long-target-that-is-meant-to-test-overflow.com." >> catalog.zone
done

cat << EOF > karidns.conf
options {
    port 53531;
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

# Build the OOM wrapper
cc -shared -fPIC -o oom_coo_wrapper.so ../tests/oom_coo_wrapper.c -ldl -lexecinfo

echo "[+] Starting KariDNS with OOM wrapper..."
OOM_FAIL_AFTER_NTH_MATCHING_CALL=1 LD_PRELOAD=./oom_coo_wrapper.so ../karidns -f karidns.conf  > karidns.log 2>&1 &
KARIDNS_PID=$!

sleep 2

if kill -0 $KARIDNS_PID 2>/dev/null; then
    echo "[+] KariDNS survived the simulated OOM and long names! (CVE fixed)"
    kill $KARIDNS_PID
    exit 0
else
    echo "[-] KariDNS crashed! (CVE exists)"
    cat karidns.log
    exit 1
fi
