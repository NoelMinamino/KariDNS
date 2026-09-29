#!/bin/sh
# R-25 regression: epoch-RCU publish ordering under ThreadSanitizer.
#
# Part 1: test_epoch_rcu-tsan (publish order, grace period, reuse stress).
# Part 2: karidns-tsan as a primary. Concurrently:
#   - UDP and TCP (tcp-connection-reuse) queries from several clients,
#   - SIGHUP reloads with a touched zone file (config swap + reload_master_zone
#     + zone DB snapshot rebuild + Pass 2 glue prelink),
#   - dynamic UPDATEs and AXFRs.
# Part 3: karidns-tsan as a secondary of a normal karidns primary, with a
#   catalog zone. Concurrently: queries to the secondary, UPDATEs on the
#   primary (NOTIFY -> IXFR on the secondary's transfer threads), catalog
#   membership changes (catalog rebuild from a transfer thread) and SIGHUP
#   reloads of the secondary (Pass 2 while transfers run).
# Any ThreadSanitizer report fails the test.

set -u

cd "$(dirname "$0")/.." || exit 1

# Load parameters can be raised from the environment for longer runs.
PORT=15361
P_PORT=15362
S_PORT=15363
CLIENTS=${CLIENTS:-4}
ROUNDS=${ROUNDS:-60}
HUPS=${HUPS:-8}
UPDATES=${UPDATES:-15}

echo "=== R-25 RCU TSan test ==="

# Build as the invoking user (running make as root leaves root-owned objects).
if ! make karidns karidns-tsan dag test_epoch_rcu-tsan >/dev/null 2>&1; then
    echo "FAIL: could not build karidns / karidns-tsan / dag / test_epoch_rcu-tsan"
    exit 1
fi

# Set KEEP=1 to keep the work directory (server logs) for debugging.
WORK="$(mktemp -d /tmp/karidns-rcu-tsan.XXXXXX)" || exit 1

kill_ours() {
    # Match only this test's config paths (the backend is a forked child).
    pkill -9 -f "karidns-tsan -f $WORK/" 2>/dev/null
    pkill -9 -f "karidns -f $WORK/" 2>/dev/null
}

cleanup() {
    kill_ours
    [ -n "${KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

rc=0

# wait_answer <port> <qname> <expected A> <seconds>
wait_answer() {
    _i=0
    while [ $_i -lt "$4" ]; do
        if ./dag "$2" A @127.0.0.1 -p "$1" +short +time=1 +tries=1 2>/dev/null | grep -qx "$3"; then
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

# check_tsan <log> <label>
check_tsan() {
    if grep -q "WARNING: ThreadSanitizer" "$1"; then
        echo "FAIL: ThreadSanitizer reports ($2):"
        grep "SUMMARY: ThreadSanitizer" "$1" | sort | uniq -c
        cat "$1"
        rc=1
    fi
}

# SIGKILL, not SIGTERM, to stop servers: the shutdown path has a separate,
# known TSan report (g_backend_should_exit written by backend_sig_handler() in
# several threads) that is outside the scope of this test. Reports are written
# as they occur, so nothing from the load phase is lost.
stop_servers() {
    kill_ours
    sleep 1
}

echo "--- part 1: test_epoch_rcu-tsan"
if ! TSAN_OPTIONS="halt_on_error=0" ./test_epoch_rcu-tsan >"$WORK/unit.log" 2>&1; then
    echo "FAIL: test_epoch_rcu-tsan exited with an error"
    cat "$WORK/unit.log"
    exit 1
fi
if grep -q "WARNING: ThreadSanitizer" "$WORK/unit.log"; then
    echo "FAIL: ThreadSanitizer reports in test_epoch_rcu-tsan"
    cat "$WORK/unit.log"
    exit 1
fi
grep "reads=" "$WORK/unit.log"

cp tests/zones/example.com.zone tests/zones/example.com.dnskey tests/zones/example.com.hosts "$WORK/"

cat > "$WORK/m1.test.zone" <<'EOF'
$TTL 300
@ IN SOA ns1.m1.test. hostmaster.m1.test. ( 1 1 1 86400 60 )
@ IN NS ns1.m1.test.
ns1 IN A 192.0.2.53
www IN A 192.0.2.101
EOF
sed -e 's/m1\.test/m2.test/g' -e 's/192\.0\.2\.101/192.0.2.102/' "$WORK/m1.test.zone" > "$WORK/m2.test.zone"
sed -e 's/m1\.test/m3.test/g' -e 's/192\.0\.2\.101/192.0.2.103/' "$WORK/m1.test.zone" > "$WORK/m3.test.zone"
# Part 3 uses its own zone: tests/zones/example.com.zone contains an out-of-zone
# record, which makes a KariDNS secondary reject the whole transfer (R-27).
sed -e 's/m1\.test/sec.test/g' -e 's/192\.0\.2\.101/192.0.2.110/' "$WORK/m1.test.zone" > "$WORK/sec.test.zone"

# write_catalog <serial> <with m3: 0|1>
write_catalog() {
    {
        echo '$TTL 300'
        echo "@ IN SOA ns1.cat.test. hostmaster.cat.test. ( $1 1 1 86400 60 )"
        echo '@ IN NS ns1.cat.test.'
        echo 'ns1 IN A 192.0.2.53'
        echo 'version IN TXT "2"'
        echo 'm1.zones IN PTR m1.test.'
        echo 'm2.zones IN PTR m2.test.'
        [ "$2" -eq 1 ] && echo 'm3.zones IN PTR m3.test.'
    } > "$WORK/cat.test.zone.tmp"
    mv "$WORK/cat.test.zone.tmp" "$WORK/cat.test.zone"
}
write_catalog 1 0

chmod 755 "$WORK"
chmod 644 "$WORK"/*

USER_LINE=""
if [ "$(id -u)" -eq 0 ]; then
    USER_LINE='user "nobody"; group "nobody";'
fi

cat > "$WORK/ts.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    pid-file "none";
    tcp-connection-reuse yes;
    $USER_LINE
};
zone "example.com" {
    type master;
    file "$WORK/example.com.zone";
    allow-update { 127.0.0.1; };
    allow-transfer { any; };
};
EOF

echo "--- part 2: karidns-tsan primary: queries + SIGHUP + UPDATE + AXFR"
TSAN_OPTIONS="halt_on_error=0" \
    ./karidns-tsan -f "$WORK/ts.conf" >"$WORK/server.log" 2>&1 </dev/null &
SERVER_PID=$!

if ! wait_answer $PORT www.example.com 192.0.2.10 60; then
    echo "FAIL: karidns-tsan did not start"
    cat "$WORK/server.log"
    exit 1
fi

pids=""
w=0
while [ $w -lt "$CLIENTS" ]; do
    (
        i=0
        while [ $i -lt "$ROUNDS" ]; do
            ./dag www.example.com A @127.0.0.1 -p $PORT +short +time=5 >/dev/null 2>&1
            ./dag u$i.example.com A @127.0.0.1 -p $PORT +tcp +short +time=5 >/dev/null 2>&1
            i=$((i + 1))
        done
    ) &
    pids="$pids $!"
    w=$((w + 1))
done

(
    i=0
    while [ $i -lt "$HUPS" ]; do
        kill -HUP "$SERVER_PID" 2>/dev/null
        touch "$WORK/example.com.zone"
        sleep 1
        i=$((i + 1))
    done
) &
pids="$pids $!"

(
    i=1
    while [ $i -le "$UPDATES" ]; do
        ./dag example.com @127.0.0.1 -p $PORT --update-add "u$i.example.com 300 IN A 192.0.2.$i" >/dev/null 2>&1
        ./dag example.com AXFR @127.0.0.1 -p $PORT >/dev/null 2>&1
        i=$((i + 1))
    done
) &
pids="$pids $!"

for p in $pids; do
    wait "$p"
done

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns-tsan exited during the load"
    rc=1
elif ! wait_answer $PORT www.example.com 192.0.2.10 5; then
    echo "FAIL: karidns-tsan no longer answers after the load"
    rc=1
fi
stop_servers

reloads=$(grep -c "reloaded successfully" "$WORK/server.log")
updates=$(grep -c "\[Update\] client=" "$WORK/server.log")
echo "reloads logged: $reloads, updates logged: $updates"
check_tsan "$WORK/server.log" "primary"

echo "--- part 3: karidns-tsan secondary: queries + NOTIFY/IXFR + catalog changes + SIGHUP"
cat > "$WORK/p.conf" <<EOF
options {
    port $P_PORT;
    bind-address { 127.0.0.1; };
    pid-file "none";
    $USER_LINE
};
zone "sec.test" {
    type master;
    file "$WORK/sec.test.zone";
    allow-update { 127.0.0.1; };
    allow-transfer { any; };
    also-notify { 127.0.0.1 port $S_PORT; };
};
zone "cat.test" { type master; file "$WORK/cat.test.zone"; allow-transfer { any; }; };
zone "m1.test" { type master; file "$WORK/m1.test.zone"; allow-transfer { any; }; };
zone "m2.test" { type master; file "$WORK/m2.test.zone"; allow-transfer { any; }; };
zone "m3.test" { type master; file "$WORK/m3.test.zone"; allow-transfer { any; }; };
EOF

cat > "$WORK/s.conf" <<EOF
options {
    port $S_PORT;
    bind-address { 127.0.0.1; };
    pid-file "none";
    tcp-connection-reuse yes;
    $USER_LINE
};
zone "sec.test" { type slave; masters { 127.0.0.1 port $P_PORT; }; };
zone "cat.test" { type slave; masters { 127.0.0.1 port $P_PORT; }; catalog-zone yes; };
EOF

./karidns -f "$WORK/p.conf" >"$WORK/primary.log" 2>&1 </dev/null &
if ! wait_answer $P_PORT www.sec.test 192.0.2.110 30; then
    echo "FAIL: primary karidns did not start"
    cat "$WORK/primary.log"
    exit 1
fi
PRIMARY_PID=$(pgrep -o -f "karidns -f $WORK/p.conf")

TSAN_OPTIONS="halt_on_error=0" \
    ./karidns-tsan -f "$WORK/s.conf" >"$WORK/secondary.log" 2>&1 </dev/null &
SECONDARY_PID=$!

if ! wait_answer $S_PORT www.sec.test 192.0.2.110 90 || ! wait_answer $S_PORT www.m1.test 192.0.2.101 60; then
    echo "FAIL: secondary did not load sec.test / catalog member m1.test"
    cat "$WORK/secondary.log"
    exit 1
fi

pids=""
w=0
while [ $w -lt "$CLIENTS" ]; do
    (
        i=0
        while [ $i -lt "$ROUNDS" ]; do
            ./dag www.sec.test A @127.0.0.1 -p $S_PORT +short +time=5 >/dev/null 2>&1
            ./dag www.m1.test A @127.0.0.1 -p $S_PORT +tcp +short +time=5 >/dev/null 2>&1
            i=$((i + 1))
        done
    ) &
    pids="$pids $!"
    w=$((w + 1))
done

(
    i=0
    while [ $i -lt "$HUPS" ]; do
        kill -HUP "$SECONDARY_PID" 2>/dev/null
        sleep 1
        i=$((i + 1))
    done
) &
pids="$pids $!"

(
    i=1
    while [ $i -le "$UPDATES" ]; do
        ./dag sec.test @127.0.0.1 -p $P_PORT --update-add "s$i.sec.test 300 IN A 192.0.2.$i" >/dev/null 2>&1
        i=$((i + 1))
    done
) &
pids="$pids $!"

(
    i=0
    while [ $i -lt "$HUPS" ]; do
        write_catalog $((i + 2)) $(( (i + 1) % 2 ))
        chmod 644 "$WORK/cat.test.zone"
        kill -HUP "$PRIMARY_PID" 2>/dev/null
        sleep 2
        i=$((i + 1))
    done
) &
pids="$pids $!"

for p in $pids; do
    wait "$p"
done

if ! kill -0 "$SECONDARY_PID" 2>/dev/null; then
    echo "FAIL: secondary karidns-tsan exited during the load"
    rc=1
elif ! wait_answer $S_PORT s$UPDATES.sec.test 192.0.2.$UPDATES 30; then
    echo "FAIL: the last UPDATE did not reach the secondary"
    rc=1
elif ! wait_answer $S_PORT www.m2.test 192.0.2.102 10; then
    echo "FAIL: secondary no longer answers for catalog member m2.test"
    rc=1
fi
stop_servers

xfrs=$(grep -c "Successfully transferred" "$WORK/secondary.log")
members=$(grep -c "Processed membership" "$WORK/secondary.log")
reloads=$(grep -c "reloaded successfully" "$WORK/secondary.log")
echo "secondary: transfers logged: $xfrs, catalog passes: $members, reloads: $reloads"
check_tsan "$WORK/secondary.log" "secondary"

if [ $rc -eq 0 ]; then
    echo "PASS: no ThreadSanitizer report"
fi
exit $rc
