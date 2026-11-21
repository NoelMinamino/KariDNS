#!/bin/sh
# dnsqps --io=xdp (AF_XDP, Linux) end to end on a veth pair in generic XDP mode: dnsqps in this namespace, its reflector in a namespace of its own, so that
# every query and every answer crosses the XDP socket (Ethernet, ARP and neighbor discovery, IPv4 and IPv6 UDP, the checksums are built by dnsqps itself).
# Correctness only: a veth in generic mode says nothing about the rate (docs/dnsqps.md "AF_XDP").  Needs root, iproute2 (ip netns, veth), the kernel's
# XDP and a dnsqps built with libxdp (make dnsqps, libxdp-dev and libbpf-dev installed).  SKIP otherwise; DNSQPS_TEST_REQUIRE=1 turns a SKIP into a failure
# (the CI job sets it).
. "$(dirname "$0")/lib_proc.sh"
set -u
cd "$(dirname "$0")/.."
DQ="${DNSQPS:-./dnsqps}"
skip() {
    echo "SKIP: $*"
    [ "${DNSQPS_TEST_REQUIRE:-0}" = "1" ] && exit 1
    exit 0
}
[ "$(uname -s)" = "Linux" ] || skip "not Linux"
[ "$(id -u)" = "0" ] || skip "needs root"
command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$DQ" ] || skip "no $DQ"
"$DQ" -V | grep -q ' xdp' || skip "dnsqps is built without libxdp ($("$DQ" -V | tail -1))"

NS="dqx$$"
V0="dqv0$$"; V1="dqv1$$"
T=$(mktemp -d "${TMPDIR:-/tmp}/dnsqps_xdp.XXXXXX")
REFL=""
FAILED=0
cleanup() {
    set +e
    [ -n "$REFL" ] && kill "$REFL" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$V0" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
fail() { echo "FAIL: $*"; FAILED=1; }
jnum() { sed -n "s/.*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }

ip netns add "$NS" || skip "cannot create a network namespace"
ip link add "$V0" type veth peer name "$V1" || skip "no veth"
ip link set "$V1" netns "$NS"
ip addr add 10.99.0.1/24 dev "$V0"
ip -6 addr add fd99::1/64 dev "$V0" nodad
ip link set "$V0" up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$V1"
ip netns exec "$NS" ip -6 addr add fd99::2/64 dev "$V1" nodad
ip netns exec "$NS" ip link set "$V1" up
ip netns exec "$NS" ip link set lo up
# the answers of the peer carry partial checksums in the veth; dnsqps does not verify them, but keep the frames honest where ethtool allows
if command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$V0" tx off rx off >/dev/null 2>&1
    ip netns exec "$NS" ethtool -K "$V1" tx off rx off >/dev/null 2>&1
fi
MAC1=$(ip netns exec "$NS" cat "/sys/class/net/$V1/address")

ip netns exec "$NS" "$DQ" -r --reflect "[10.99.0.2]:5300" > "$T/refl4.log" 2>&1 &
REFL=$!
ip netns exec "$NS" "$DQ" -r --reflect "[fd99::2]:5300" > "$T/refl6.log" 2>&1 &
REFL6=$!
i=0
until grep -q reflecting "$T/refl4.log" 2>/dev/null && grep -q reflecting "$T/refl6.log" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -le 50 ] || { cat "$T/refl4.log" "$T/refl6.log"; fail "the reflectors did not start"; exit 1; }
    sleep 0.1
done
trap 'kill $REFL6 2>/dev/null; cleanup' EXIT INT TERM

cat > "$T/q.txt" <<EOF
www.example.test A
mail.example.test MX +dnssec
ipv6.example.test AAAA +bufsize=4096 +nsid +cookie
ns.example.test NS +padding=128 +subnet=192.0.2.0/24
EOF

run() { # label expected-min args... : a run that must complete most of its queries
    label=$1; min=$2; shift 2
    "$DQ" -r "$@" --json > "$T/out.json" 2> "$T/out.err"
    rc=$?
    d=$(jnum completed < "$T/out.json"); s=$(jnum sent < "$T/out.json")
    if [ "$rc" -ne 0 ] || [ "${d:-0}" -lt "$min" ]; then
        fail "$label: exit $rc, sent ${s:-?}, completed ${d:-?}, expected at least $min"
        cat "$T/out.err" | head -20
        return 1
    fi
    echo "ok: $label: sent $s, completed $d"
}

# the same path with ordinary sockets: the veth and the reflector work
run "control (sendto)" 990 -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io sendto -d "$T/q.txt" -N 1000 -T 1
# AF_XDP, IPv4, the next hop resolved by ARP
run "xdp IPv4, ARP" 19000 -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io xdp --iface "$V0" --xdp-mode skb -d "$T/q.txt" -N 20000 -T 1 -c 2
grep -qx '\[Status\] xdp skb, copy' "$T/out.err" || { fail "xdp skb on veth: no status line 'xdp skb, copy'"; grep Status "$T/out.err"; }
# the next-hop MAC given
run "xdp IPv4, --next-hop-mac" 4900 -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io xdp --iface "$V0" --xdp-mode skb --next-hop-mac "$MAC1" -d "$T/q.txt" -N 5000 -T 1
# the interface found from the source address
run "xdp IPv4, interface from -b" 4900 -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io xdp --xdp-mode skb -d "$T/q.txt" -N 5000 -T 1
# IPv6: neighbor discovery and the IPv6 UDP checksum
run "xdp IPv6, neighbor discovery" 4900 -s fd99::2 -p 5300 -b fd99::1 --io xdp --iface "$V0" --xdp-mode skb -d "$T/q.txt" -N 5000 -T 1
# generated queries over XDP, an open loop
run "xdp generated, open loop" 1900 -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io xdp --iface "$V0" --xdp-mode skb -z "$T/q.txt" --miss 0.2 -Q 2000 -l 1.5 -T 1
# auto with --iface picks it
"$DQ" -r -s 10.99.0.2 -p 5300 -b 10.99.0.1 --iface "$V0" --xdp-mode skb -d "$T/q.txt" -N 500 -T 1 > "$T/auto.out" 2>&1
grep -q 'I/O path xdp (auto)' "$T/auto.out" && grep -q 'Queries completed:    [45][0-9][0-9]' "$T/auto.out" || { fail "--io=auto with --iface does not use xdp"; head -12 "$T/auto.out"; }
# refusals
out=$("$DQ" -r -s 10.99.0.2 -p 5300 --io xdp --iface "$V0" -d "$T/q.txt" -N 5 2>&1 >/dev/null); [ $? -eq 2 ] && echo "$out" | grep -q -- '-b' || fail "xdp without -b: ($out)"
out=$("$DQ" -r -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io xdp --iface "$V0" --queue 63 -d "$T/q.txt" -N 5 2>&1 >/dev/null); [ $? -eq 2 ] && [ -n "$out" ] || fail "xdp on a queue that does not exist: exit/message ($out)"
out=$("$DQ" -r -s 10.99.0.2 -p 5300 -b 10.99.0.1 --io xdp --iface nosuchif0 --src-mac 02:00:00:00:00:01 -d "$T/q.txt" -N 5 2>&1 >/dev/null); [ $? -eq 2 ] && [ -n "$out" ] || fail "xdp on an interface that does not exist ($out)"
# auto falls back when the path cannot be opened
"$DQ" -r -s 10.99.0.2 -p 5300 -b 10.99.0.1 --iface nosuchif0 --src-mac 02:00:00:00:00:01 -d "$T/q.txt" -N 300 -T 1 -t 1 > "$T/fb.out" 2>&1
grep -q 'unavailable' "$T/fb.out" || fail "auto does not say why it fell back: $(head -3 "$T/fb.out")"

[ "$FAILED" -eq 0 ] || { echo "FAIL: dnsqps xdp test"; exit 1; }
echo "PASS: dnsqps xdp test"
exit 0
