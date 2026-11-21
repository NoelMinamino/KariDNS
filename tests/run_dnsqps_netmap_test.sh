#!/bin/sh
# dnsqps --io=netmap (FreeBSD) end to end on a VALE switch, netmap's software switch: no NIC is taken over.  dnsqps sends on the port vale0:c, a raw reflector
# (dnsqps --reflect with --io=netmap) sits on vale0:r, so every query and every answer is an Ethernet frame built and read by dnsqps itself (IPv4 and IPv6 UDP with
# checksums, ARP, neighbor discovery is checked by the unit tests only: a VALE port has no host stack to answer it).  Correctness only: VALE says nothing about the
# rate of a NIC.  Needs root, FreeBSD with netmap (kldload netmap; it is in GENERIC) and a dnsqps built on FreeBSD.  SKIP otherwise; DNSQPS_TEST_REQUIRE=1
# turns a SKIP into a failure (the CI job sets it).
. "$(dirname "$0")/lib_proc.sh"
set -u
cd "$(dirname "$0")/.."
DQ="${DNSQPS:-./dnsqps}"
skip() {
    echo "SKIP: $*"
    [ "${DNSQPS_TEST_REQUIRE:-0}" = "1" ] && exit 1
    exit 0
}
[ "$(uname -s)" = "FreeBSD" ] || skip "not FreeBSD"
[ "$(id -u)" = "0" ] || skip "needs root"
[ -x "$DQ" ] || skip "no $DQ"
[ -c /dev/netmap ] || kldload netmap >/dev/null 2>&1
[ -c /dev/netmap ] || skip "no /dev/netmap (kldload netmap failed)"

T=$(mktemp -d "${TMPDIR:-/tmp}/dnsqps_nm.XXXXXX")
REFL=""
FAILED=0
cleanup() {
    set +e
    [ -n "$REFL" ] && kill "$REFL" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
fail() { echo "FAIL: $*"; FAILED=1; }
jnum() { sed -n "s/.*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }

CMAC=02:00:00:00:00:01
RMAC=02:00:00:00:00:02
"$DQ" -r --reflect 10.88.0.2:5300 --io netmap --iface vale0:r --src-mac "$RMAC" > "$T/refl.log" 2>&1 &
REFL=$!
i=0
until grep -q reflecting "$T/refl.log" 2>/dev/null; do
    i=$((i + 1))
    kill -0 "$REFL" 2>/dev/null || { cat "$T/refl.log"; skip "the netmap reflector cannot start on vale0:r"; }
    [ "$i" -le 50 ] || { cat "$T/refl.log"; fail "the reflector did not start"; exit 1; }
    sleep 0.1
done

cat > "$T/q.txt" <<EOF
www.example.test A
mail.example.test MX +dnssec
ipv6.example.test AAAA +bufsize=4096 +nsid +cookie
ns.example.test NS +padding=128 +subnet=192.0.2.0/24
EOF

run() { # label expected-min args...
    label=$1; min=$2; shift 2
    "$DQ" -r "$@" --json > "$T/out.json" 2> "$T/out.err"
    rc=$?
    d=$(jnum completed < "$T/out.json"); s=$(jnum sent < "$T/out.json")
    if [ "$rc" -ne 0 ] || [ "${d:-0}" -lt "$min" ]; then
        fail "$label: exit $rc, sent ${s:-?}, completed ${d:-?}, expected at least $min"
        head -20 "$T/out.err"
        return 1
    fi
    echo "ok: $label: sent $s, completed $d"
}

COMMON="-s 10.88.0.2 -p 5300 -b 10.88.0.1 --io netmap --iface vale0:c --src-mac $CMAC"
# the next-hop MAC given
run "netmap, --next-hop-mac" 4900 $COMMON --next-hop-mac "$RMAC" -d "$T/q.txt" -N 5000 -T 1
# the next hop resolved by an ARP request that the reflector answers
run "netmap, ARP" 19000 $COMMON -d "$T/q.txt" -N 20000 -T 1 -c 2
# generated queries, an open loop
run "netmap generated, open loop" 1900 $COMMON --next-hop-mac "$RMAC" -z "$T/q.txt" --miss 0.2 -Q 2000 -l 1.5 -T 1
# pre-built frames with a source prefix and a cookie per query: the raw reflector drops a frame whose IPv4 or UDP checksum is wrong, so every answer proves
# the incremental update (RFC 1624) of the source address, the port, the ID and the cookie; the answers go to addresses of the prefix and are still counted
run "netmap, source prefix, cookie=random" 4900 -s 10.88.0.2 -p 5300 -b 198.18.0.0/24 --io netmap --iface vale0:c --src-mac $CMAC --next-hop-mac "$RMAC" -d "$T/q.txt" -N 5000 -T 1 -c 3 +edns +cookie=random
run "netmap, prefix, generated, small --frame-mem 0 (a frame per query)" 1900 -s 10.88.0.2 -p 5300 -b 198.19.0.0/16 --io netmap --iface vale0:c --src-mac $CMAC --next-hop-mac "$RMAC" -z "$T/q.txt" --miss 0.2 -Q 2000 -l 1.5 -T 1 --frame-mem 0 +edns +cookie=random
run "netmap, prefix, ARP resolved from the prefix" 4900 -s 10.88.0.2 -p 5300 -b 198.18.0.0/24 --io netmap --iface vale0:c --src-mac $CMAC -d "$T/q.txt" -N 5000 -T 1
out=$("$DQ" -r -s 10.88.0.2 -p 5300 -b 192.0.2.0/24 --io netmap --iface vale0:c --src-mac "$CMAC" --next-hop-mac "$RMAC" -d "$T/q.txt" -N 5 2>&1 >/dev/null); rc=$?
[ "$rc" -eq 2 ] && echo "$out" | grep -q 'backscatter' || fail "a prefix outside the reserved ranges: exit $rc ($out)"
# an ARP request nobody answers: a clear error, exit 2
out=$("$DQ" -r -s 10.88.0.9 -p 5300 -b 10.88.0.1 --io netmap --iface vale0:c --src-mac "$CMAC" -d "$T/q.txt" -N 5 2>&1 >/dev/null); rc=$?
# (the switch floods the request, the reflector ignores it: the resolution runs out)
[ "$rc" -eq 2 ] && echo "$out" | grep -q 'next-hop-mac' || fail "no ARP answer: exit $rc ($out)"
# no MAC for a port that is not an interface
out=$("$DQ" -r -s 10.88.0.2 -p 5300 -b 10.88.0.1 --io netmap --iface vale0:c -d "$T/q.txt" -N 5 2>&1 >/dev/null); rc=$?
[ "$rc" -eq 2 ] && echo "$out" | grep -q 'src-mac' || fail "no --src-mac for a switch port: exit $rc ($out)"

[ "$FAILED" -eq 0 ] || { echo "FAIL: dnsqps netmap test"; exit 1; }
echo "PASS: dnsqps netmap test"
exit 0
