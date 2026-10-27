#!/bin/sh
# ==============================================================================
# B8t-2: Extended AXFR version 3 - the SOA set, the settings of the primary, the refresh of a secondary outside every SOA location
#
# A KariDNS primary P and a KariDNS secondary S (both on 127.0.0.1, one port each):
#   loc.test  tinydns data, one SOA per location (in / ex), record TTL cases     S gets the SOA set, answers per client like P
#   bt.test   BIND zone, $LOCATION-tagged SOA records, tags defined in P's options  (the tag definitions travel with the zone)
#   out.test  tinydns data whose only SOA is for location ex; S (127.0.0.1 = in) is outside it: the extension still lets it refresh
#   set.test  BIND zone with ECS tags; P's zone has allow-transfer and ecs-trusted-resolvers: S applies them (settings transfer)
#   ovr.test  the same, but S's own zone {} writes allow-transfer and ecs-trusted-resolvers: the secondary's statement wins
#   nops.test the same, S's zone has primary-settings no: the received settings are ignored
#   key.test  P's allow-transfer names a TSIG key S does not have: that ACL fails closed on S
#   ix.test   a plain zone: a changed ACL reaches S with an IXFR
#   legacy.test  a stand-in primary that answers a standard AXFR (it does not know version 3): S still transfers the zone
#   old.test, oldt.test  served by an OLD (version 2) karidns binary, when OLD_KARIDNS names one: S, upgraded first, asks version 3, gets a
#             standard transfer, asks again with version 2 and ends with the tags and tinydns attributes (no degradation)
# Wire format and interop are checked with tests/lib_xfr_ext_probe.pl (a version 2 requester gets a version 2 stream, or is refused
# for a zone with several SOA records; a request without the option gets a standard transfer).
# Clients 127.0.0.2 (location ex) and 127.0.0.3 are loopback aliases, added when run as root (those checks SKIP otherwise).
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="${BIN_DIR:-$BASE_DIR}"
KARIDNS="$BIN_DIR/karidns"
KARICHECK="$BIN_DIR/karicheck"
KARICTL="$BIN_DIR/karictl"
DAG="${DAG:-$BIN_DIR/dag}"
PROBE="$SCRIPT_DIR/lib_xfr_ext_probe.pl"
AXPROBE="$SCRIPT_DIR/lib_axfr_probe.pl"

[ -x "$KARIDNS" ] && [ -x "$KARICHECK" ] && [ -x "$KARICTL" ] && [ -x "$DAG" ] || (cd "$BASE_DIR" && make karidns karicheck karictl dag) || exit 1
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not found"; exit 0; }

TMP_DIR="$(mktemp -d /tmp/karidns_extv3.XXXXXX)"
chmod 755 "$TMP_DIR"
PORT1=$(kari_port 0 $((31000 + $$ % 2500)))
PORT2=$((PORT1 + 1))
PORT3=$((PORT1 + 2))
PID1=""; PID2=""; PID3=""
ADDED=""
PASS=0; FAIL=0; SKIP=0
SRC_IN=127.0.0.1; SRC_EX=127.0.0.2; SRC_NO=127.0.0.3

cleanup() {
    kari_kill_tree "${PID1:-}" "${PID2:-}" "${PID3:-}" "${PID4:-}"
    for ip in $ADDED; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || true; done
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; shift; for l in "$@"; do echo "       $l"; done; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP $1"; }
expect() {
    _n="$1"; _o="$2"; shift 2
    _flat=$(printf '%s' "$_o" | tr '\n' ' ')
    for _re in "$@"; do
        if ! printf '%s' "$_flat" | grep -E -q -- "$_re"; then
            bad "$_n" "missing: $_re" "output: $(printf '%s' "$_o" | head -30)"
            return
        fi
    done
    ok "$_n"
}
reject() {
    _flat=$(printf '%s' "$2" | tr '\n' ' ')
    if printf '%s' "$_flat" | grep -E -q -- "$3"; then
        bad "$1" "unexpected: $3" "output: $(printf '%s' "$2" | head -30)"
    else
        ok "$1"
    fi
}

USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
    for ip in $SRC_EX $SRC_NO; do
        if ifconfig lo0 inet "$ip" netmask 255.0.0.0 alias 2>/dev/null; then ADDED="$ADDED $ip"; fi
    done
fi
MULTI=0
if ifconfig lo0 2>/dev/null | grep -q "inet $SRC_EX " && ifconfig lo0 2>/dev/null | grep -q "inet $SRC_NO "; then MULTI=1; fi

PORT4=$((PORT1 + 3))
PID4=""
OLD="${OLD_KARIDNS:-}"
[ -n "$OLD" ] && [ ! -x "$OLD" ] && OLD=""

SECRET=$(openssl rand -base64 32)

# ------------------------------------------------------------------------------ zone data
cat > "$TMP_DIR/loc.data" <<EOF
%in:127.0.0.1
%ex:127.0.0.2
%no:127.0.0.3
Zloc.test:ns1.in.loc.test.:hostmaster.loc.test.:7:3600:900:604800:300:300::in
Zloc.test:ns1.ex.loc.test.:hostmaster.loc.test.:7:3600:900:604800:300:600::ex
&loc.test::ns1.loc.test:300
+ns1.loc.test:192.0.2.1:300
+www.loc.test:192.0.2.10:300
+inonly.loc.test:192.0.2.20:300::in
+exonly.loc.test:192.0.2.21:300::ex
+multi.loc.test:192.0.2.51:60::in
+multi.loc.test:192.0.2.52:120::ex
+h.loc.test:192.0.2.60:300
+h.loc.test:192.0.2.61:100
+co.loc.test:192.0.2.70:300
+co.loc.test:192.0.2.71:60::in
EOF

cat > "$TMP_DIR/bt.zone" <<'EOF'
$TTL 300
$ORIGIN bt.test.
$LOCATION lt-in
@ IN SOA ns1.in.bt.test. hostmaster.bt.test. ( 4 3600 900 604800 300 )
$LOCATION lt-ex
@ IN SOA ns1.ex.bt.test. hostmaster.bt.test. ( 4 3600 900 604800 600 )
$LOCATION ""
@ IN NS ns1.bt.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.40
$LOCATION lt-in
inonly IN A 192.0.2.41
$LOCATION ""
EOF

mk_out() {   # mk_out SERIAL
    cat > "$TMP_DIR/out.data" <<EOF
%in:127.0.0.1
%ex:127.0.0.2
Zout.test:ns1.ex.out.test.:hostmaster.out.test.:$1:3600:900:604800:300:300::ex
&out.test::ns1.out.test:300
+www.out.test:192.0.2.80:300
EOF
}
mk_out 3

mk_set() {   # mk_set NAME SERIAL
    cat > "$TMP_DIR/$1.zone" <<EOF
\$TTL 300
\$ORIGIN $1.
@ IN SOA ns1.$1. hostmaster.$1. ( $2 3600 900 604800 300 )
@ IN NS ns1.$1.
ns1 IN A 192.0.2.1
\$ECS-SUBNET-TAG eu 198.51.100.0/24
\$ECS-SUBNET eu
ecs IN A 172.16.1.1
\$ECS-SUBNET ""
ecs IN A 172.16.0.1
EOF
}
for z in set.test ovr.test nops.test key.test; do mk_set $z 5; done

mk_ix() {   # mk_ix SERIAL
    cat > "$TMP_DIR/ix.zone" <<EOF
\$TTL 300
\$ORIGIN ix.test.
@ IN SOA ns1.ix.test. hostmaster.ix.test. ( $1 3600 900 604800 300 )
@ IN NS ns1.ix.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.$1
EOF
}
mk_ix 10

if [ -n "$OLD" ]; then
cat > "$TMP_DIR/old.test.zone" <<'EOZ'
$TTL 300
$ORIGIN old.test.
@ IN SOA ns1.old.test. hostmaster.old.test. ( 5 3600 900 604800 300 )
@ IN NS ns1.old.test.
ns1 IN A 192.0.2.1
$LOCATION-TAG local 127.0.0.1/32
$ECS-SUBNET-TAG eu 198.51.100.0/24
$LOCATION local
loc IN A 10.1.1.1
$LOCATION ""
loc IN A 10.0.0.1
$ECS-SUBNET eu
ecs IN A 172.16.1.1
$ECS-SUBNET ""
ecs IN A 172.16.0.1
EOZ
cat > "$TMP_DIR/oldt.data" <<EOZ
.oldt.test:192.0.2.1:ns1.oldt.test:300
%lo:127.0.0.1/32
+srv.oldt.test:10.10.1.1:300::lo
+srv.oldt.test:10.10.0.1:300
EOZ
cat > "$TMP_DIR/old.conf" <<EOZ
options { port $PORT4; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT ecs-enable yes; };
control-channel { socket "$TMP_DIR/old.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "old.test" { type master; file "$TMP_DIR/old.test.zone"; allow-transfer { 127.0.0.1; }; ecs-trusted-resolvers { 127.0.0.1; }; };
zone "oldt.test" { type master; file "$TMP_DIR/oldt.data"; file-format tinydns; allow-transfer { 127.0.0.1; }; };
EOZ
chmod 644 "$TMP_DIR/old.test.zone" "$TMP_DIR/oldt.data" "$TMP_DIR/old.conf"
fi

# P's configuration (kept in a function: the test rewrites it)
mk_pconf() {   # mk_pconf SET_TRUSTED IX_ACL
    cat > "$TMP_DIR/p.conf" <<EOF
options {
    port $PORT1; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
    ecs-enable yes;
    location-tags { tag "lt-in" { 127.0.0.1/32; }; tag "lt-ex" { 127.0.0.2/32; }; };
};
control-channel { socket "$TMP_DIR/p.sock"; algorithm hmac-sha256; secret "$SECRET"; };
key "kx" { algorithm hmac-sha256; secret "$SECRET"; };
zone "loc.test" { type master; file "$TMP_DIR/loc.data"; file-format tinydns; allow-transfer { 127.0.0.0/24; }; };
zone "bt.test" { type master; file "$TMP_DIR/bt.zone"; allow-transfer { 127.0.0.0/24; }; };
zone "out.test" { type master; file "$TMP_DIR/out.data"; file-format tinydns; allow-transfer { 127.0.0.0/24; }; also-notify { 127.0.0.1 port $PORT2; }; };
zone "set.test" { type master; file "$TMP_DIR/set.test.zone"; allow-transfer { 127.0.0.1; 127.0.0.2; }; ecs-trusted-resolvers { $1; }; also-notify { 127.0.0.1 port $PORT2; }; };
zone "ovr.test" { type master; file "$TMP_DIR/ovr.test.zone"; allow-transfer { 127.0.0.1; 127.0.0.2; }; ecs-trusted-resolvers { 127.0.0.1; }; };
zone "nops.test" { type master; file "$TMP_DIR/nops.test.zone"; allow-transfer { 127.0.0.1; 127.0.0.2; }; ecs-trusted-resolvers { 127.0.0.1; }; };
zone "key.test" { type master; file "$TMP_DIR/key.test.zone"; allow-transfer { 127.0.0.1; key "kx"; }; transfer-acl-match any; };
zone "ix.test" { type master; file "$TMP_DIR/ix.zone"; allow-transfer { $2; }; also-notify { 127.0.0.1 port $PORT2; }; };
EOF
    cp "$TMP_DIR/p.conf" "$TMP_DIR/pc.conf"
    chmod 600 "$TMP_DIR/pc.conf"; chmod 644 "$TMP_DIR/p.conf"
}
mk_pconf "127.0.0.1" "127.0.0.1; 127.0.0.2"

cat > "$TMP_DIR/s.conf" <<EOF
options {
    port $PORT2; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
    ecs-enable yes;
    ecs-trusted-resolvers { 192.0.2.200; };
};
control-channel { socket "$TMP_DIR/s.sock"; algorithm hmac-sha256; secret "$SECRET"; };
zone "loc.test" { type slave; masters { 127.0.0.1 port $PORT1; }; };
zone "bt.test" { type slave; masters { 127.0.0.1 port $PORT1; }; };
zone "out.test" { type slave; masters { 127.0.0.1 port $PORT1; }; };
zone "set.test" { type slave; masters { 127.0.0.1 port $PORT1; }; };
zone "ovr.test" { type slave; masters { 127.0.0.1 port $PORT1; }; allow-transfer { 192.0.2.9; }; ecs-trusted-resolvers { 192.0.2.77; }; };
zone "nops.test" { type slave; masters { 127.0.0.1 port $PORT1; }; primary-settings no; };
zone "key.test" { type slave; masters { 127.0.0.1 port $PORT1; }; };
zone "ix.test" { type slave; masters { 127.0.0.1 port $PORT1; }; };
zone "legacy.test" { type slave; masters { 127.0.0.1 port $PORT3; }; };
EOF
if [ -n "$OLD" ]; then
    printf 'zone "old.test" { type slave; masters { 127.0.0.1 port %s; }; };
zone "oldt.test" { type slave; masters { 127.0.0.1 port %s; }; };
' "$PORT4" "$PORT4" >> "$TMP_DIR/s.conf"
fi
cp "$TMP_DIR/s.conf" "$TMP_DIR/sc.conf"
chmod 600 "$TMP_DIR/sc.conf"; chmod 644 "$TMP_DIR/s.conf" "$TMP_DIR"/*.zone "$TMP_DIR"/*.data

# a primary that does not know version 3: it answers every AXFR request with a standard transfer of legacy.test
cat > "$TMP_DIR/legacy.pl" <<'EOF'
use strict; use warnings; use IO::Socket::INET;
my $port = shift;
my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Listen => 5, ReuseAddr => 1, Proto => 'tcp') or die "listen: $!";
$SIG{CHLD} = 'IGNORE';
sub nm { my $n = shift; $n =~ s/\.$//; return join('', map { pack('C a*', length($_), $_) } split(/\./, $n)) . "\0"; }
while (my $c = $l->accept) {
    my $pid = fork();
    if (!$pid) {
        my $len; $c->read($len, 2) or exit 0; $len = unpack('n', $len);
        my $q; $c->read($q, $len) or exit 0;
        my ($id) = unpack('n', $q);
        my $qs = substr($q, 12);
        $qs = substr($qs, 0, index($qs, "\0") + 5);       # the question only (the request has an OPT)
        my $soa = nm('ns1.legacy.test') . nm('hostmaster.legacy.test') . pack('N5', 3, 3600, 900, 604800, 300);
        my $rr_soa = "\xC0\x0C" . pack('n n N n', 6, 1, 300, length($soa)) . $soa;
        my $rr_a = nm('host.legacy.test') . pack('n n N n', 1, 1, 300, 4) . pack('C4', 192, 0, 2, 99);
        my $m = pack('n n n n n n', $id, 0x8400, 1, 3, 0, 0) . $qs . $rr_soa . $rr_a . $rr_soa;
        $c->print(pack('n', length($m)) . $m);
        $c->flush; sleep 1; exit 0;
    }
    close $c;
}
EOF

SC() { "$KARICTL" -f "$TMP_DIR/sc.conf" "$@" 2>&1; }
PC() { "$KARICTL" -f "$TMP_DIR/pc.conf" "$@" 2>&1; }
# Q PORT SRC NAME TYPE [dag options]: the status line, flags and the RRs (message ID left out)
Q() {
    _p=$1; _s=$2; _n=$3; _t=$4; shift 4
    "$DAG" "$_n" "$_t" @127.0.0.1 -p "$_p" -b "$_s" +nohexdump +time=2 +tries=1 "$@" 2>&1 | sed 's/, id: [0-9]*//' | grep -E 'status:|flags:|[[:space:]]IN[[:space:]]+[A-Z]|EDE:'
}
# same answer from P and from S?
same() {   # same NAME SRC QNAME QTYPE
    _a=$(Q $PORT1 "$2" "$3" "$4"); _b=$(Q $PORT2 "$2" "$3" "$4")
    if [ -n "$_a" ] && [ "$_a" = "$_b" ]; then ok "$1"; else bad "$1" "primary:" "$_a" "secondary:" "$_b"; fi
}
wait_zone() {   # wait_zone ZONE [SERIAL]: S has the zone
    _i=0
    while [ $_i -lt 150 ]; do
        SC zonestatus "$1" | grep -Eq "serial=${2:-[1-9][0-9]*}( |\$)" && return 0
        sleep 0.2; _i=$((_i + 1))
    done
    return 1
}
HASH_OUT=$(perl -e 'my $h = 2166136261; for my $c (unpack("C*", lc("out.test."))) { $h ^= $c; $h = ($h * 16777619) & 0xFFFFFFFF; } printf("%08x", $h);')

echo "=== 1. start P and S ==="
perl "$TMP_DIR/legacy.pl" $PORT3 > "$TMP_DIR/legacy.log" 2>&1 &
PID3=$!
if [ -n "$OLD" ]; then "$OLD" -f "$TMP_DIR/old.conf" > "$TMP_DIR/old.log" 2>&1 & PID4=$!; fi
"$KARIDNS" -f "$TMP_DIR/p.conf" > "$TMP_DIR/p.log" 2>&1 &
PID1=$!
i=0
while [ $i -lt 50 ]; do Q $PORT1 $SRC_IN www.loc.test A | grep -q '192.0.2.10' && break; sleep 0.1; i=$((i + 1)); done
kill -0 "$PID1" 2>/dev/null || { echo "ERROR: P did not start"; cat "$TMP_DIR/p.log"; exit 1; }
"$KARIDNS" -f "$TMP_DIR/s.conf" > "$TMP_DIR/s.log" 2>&1 &
PID2=$!
for z in loc.test bt.test out.test set.test ovr.test nops.test key.test ix.test legacy.test; do
    if wait_zone $z; then ok "S transferred $z"; else bad "S did not transfer $z" "$(SC zonestatus $z)" "$(tail -5 "$TMP_DIR/s.log")"; fi
done

echo "=== 2. the wire format: version 3 request, version 2 request, no option ==="
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN loc.test 3)
expect "v3 loc.test: the SOA set travels: frame, SOA_SET (1/2), settings, location definitions, the SOAs as wrappers, frame" "$OUT" \
    "rcode=0 ext=3 soa=2 seq=S,65409,65408,65405,65405,65405,65406\\(6\\),65406\\(6\\)," "soaset=1/2" "seq=.*,S settings=allow-transfer"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN loc.test 2)
expect "v2 loc.test: a version 2 requester is refused (the stream could not carry the SOA set)" "$OUT" "rcode=5"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN loc.test 0)
expect "no option loc.test: a standard AXFR without CLASS 65302 records (the requester's view)" "$OUT" "rcode=0 ext=none soa=2 seq=S,r,S settings=none"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN bt.test 3)
expect "v3 bt.test: SOA_SET, the options' tag definitions as zone data (65403), tag states, wrapped SOAs" "$OUT" "ext=3 soa=2 seq=S,65409,65408,65403,65403," "65401,65406\\(6\\)," "soaset=1/2"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN set.test 3)
expect "v3 set.test: the settings (allow-transfer, ecs-trusted-resolvers) and the zone's tag; no SOA_SET, no 65407" "$OUT" "ext=3 soa=2 seq=S,65408,65404," \
    "settings=allow-transfer \\{ 127.0.0.1; 127.0.0.2; \\};\\|ecs-trusted-resolvers \\{ 127.0.0.1; \\};\\|"
reject "v3 set.test: no SOA_SET and no ECS_TRUSTED record (the trusted resolvers are in the settings)" "$OUT" "65409|65407"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN set.test 2)
expect "v2 set.test: a version 2 stream: the trusted resolvers as 65407, no settings" "$OUT" "ext=2 soa=2 seq=S,65404,65407," "settings=none"
reject "v2 set.test: no SETTINGS record" "$OUT" "65408"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN key.test 3)
expect "v3 key.test: the key name is sent, never the secret" "$OUT" "settings=allow-transfer \\{ 127.0.0.1; key \"kx\"; \\};\\|transfer-acl-match any;"
reject "v3 key.test: no secret in the settings" "$OUT" "$SECRET"

echo "=== 3. S answers per client as P does (SOA set, authority, TTLs) ==="
CLIENTS="$SRC_IN"
[ "$MULTI" = 1 ] && CLIENTS="$SRC_IN $SRC_EX $SRC_NO"
for c in $CLIENTS; do
    same "loc.test SOA from $c" $c loc.test SOA
    same "loc.test NXDOMAIN (SOA in the authority section) from $c" $c nx.loc.test A
    same "loc.test NODATA from $c" $c www.loc.test AAAA
    same "loc.test positive answers from $c" $c inonly.loc.test A
    same "loc.test per-location record from $c" $c exonly.loc.test A
    same "loc.test TTLs of locations from $c" $c multi.loc.test A
    same "loc.test harmonized RRset from $c" $c h.loc.test A
    same "loc.test co-visible TTLs from $c" $c co.loc.test A
    same "bt.test SOA from $c" $c bt.test SOA
    same "bt.test NXDOMAIN from $c" $c nx.bt.test A
    same "bt.test tagged record from $c" $c inonly.bt.test A
done
[ "$MULTI" = 1 ] || skip "clients 127.0.0.2 and 127.0.0.3 of loc.test / bt.test (needs the loopback aliases: run as root)"
OUT=$(Q $PORT2 $SRC_IN loc.test SOA)
expect "S: the client of location in gets the SOA of in" "$OUT" "status: NOERROR" "SOA[[:space:]]+ns1\\.in\\.loc\\.test\\."
if [ "$MULTI" = 1 ]; then
    OUT=$(Q $PORT2 $SRC_EX loc.test SOA)
    expect "S: the client of location ex gets the SOA of ex" "$OUT" "status: NOERROR" "SOA[[:space:]]+ns1\\.ex\\.loc\\.test\\."
    OUT=$(Q $PORT2 $SRC_NO loc.test SOA)
    expect "S: a client outside every SOA location: REFUSED, EDE 18" "$OUT" "status: REFUSED" "EDE: 18"
fi

echo "=== 4. TTL rule: only RRs of the same visibility are harmonized ==="
OUT=$(Q $PORT2 $SRC_IN multi.loc.test A)
expect "S in: the RR of its location keeps TTL 60" "$OUT" "multi\\.loc\\.test\\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.51"
OUT=$(Q $PORT2 $SRC_IN h.loc.test A)
expect "S: an RRset every client sees is harmonized to the lowest TTL (100)" "$OUT" "h\\.loc\\.test\\.[[:space:]]+100[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.60" "h\\.loc\\.test\\.[[:space:]]+100[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.61"
OUT=$(Q $PORT2 $SRC_IN co.loc.test A)
expect "S in: an unrestricted RR (300) and a restricted RR (60) keep their TTLs" "$OUT" "co\\.loc\\.test\\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.70" "co\\.loc\\.test\\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.71"
OUT=$(Q $PORT1 $SRC_IN co.loc.test A)
expect "P (the file) gives the same TTLs" "$OUT" "co\\.loc\\.test\\.[[:space:]]+300[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.70" "co\\.loc\\.test\\.[[:space:]]+60[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.71"
if [ "$MULTI" = 1 ]; then
    OUT=$(Q $PORT2 $SRC_EX multi.loc.test A)
    expect "S ex: the RR of its location keeps TTL 120" "$OUT" "multi\\.loc\\.test\\.[[:space:]]+120[[:space:]]+IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.52"
fi
printf 'zone "loc.test" { type master; file "%s/loc.data"; file-format tinydns; };\n' "$TMP_DIR" > "$TMP_DIR/kc.conf"
OUT=$("$KARICHECK" zones "$TMP_DIR/kc.conf" 2>&1)
expect "karicheck: the co-visible TTL mismatch is a warning" "$OUT" "RRset 'co\\.loc\\.test\\.' type 1: an RR that every client sees and an RR with a location, time stamp or tag have different TTLs \\(300 vs 60\\)"
expect "karicheck: the plain inconsistent RRset is still reported (it is normalized)" "$OUT" "RRset 'h\\.loc\\.test\\.' type 1 has inconsistent TTLs"
reject "karicheck: two location-specific RRs with different TTLs are not reported" "$OUT" "RRset 'multi\\.loc\\.test"

echo "=== 5. a secondary outside every SOA location refreshes (out.test: the only SOA is for ex) ==="
OUT=$(SC zonestatus out.test)
expect "S transferred out.test although 127.0.0.1 sees no SOA of it" "$OUT" "serial=3 "
OUT=$(Q $PORT2 $SRC_IN out.test SOA)
expect "S: the client in is refused, as on P" "$OUT" "status: REFUSED" "EDE: 18"
OUT=$("$DAG" out.test SOA @127.0.0.1 -p $PORT2 -b $SRC_IN +nohexdump +time=2 +tries=1 +ednsopt=65153:03$HASH_OUT 2>&1)
expect "a SOA question with the extension option is answered with the reference SOA (rule 6), whatever the client" "$OUT" "status: NOERROR" "ns1\\.ex\\.out\\.test\\."
OUT=$("$DAG" out.test SOA @127.0.0.1 -p $PORT2 -b $SRC_IN +nohexdump +time=2 +tries=1 +ednsopt=65153:03deadbeef 2>&1)
expect "an option for another zone does not unlock it" "$OUT" "status: REFUSED"
mk_out 4; chmod 644 "$TMP_DIR/out.data"
sleep 1; touch "$TMP_DIR/out.data"
PC reload out.test > /dev/null
sleep 0.5
PC notify out.test > /dev/null
if wait_zone out.test 4; then ok "after a new serial and a NOTIFY S refreshed (outside the SOA's location)"; else bad "S did not refresh out.test" "$(SC zonestatus out.test)" "$(tail -8 "$TMP_DIR/s.log")"; fi

echo "=== 6. settings transfer ==="
OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_IN set.test AXFR)
expect "set.test: S allows the AXFR the primary's allow-transfer allows (it has no allow-transfer of its own)" "$OUT" "rcode=0 aa=1" "soa=2"
OUT=$("$DAG" ecs.set.test A @127.0.0.1 -p $PORT2 +short +subnet=198.51.100.10 2>&1)
expect "set.test: the ecs-trusted-resolvers of the primary make 127.0.0.1 trusted on S (the ECS option is believed)" "$OUT" "172\\.16\\.1\\.1"
OUT=$(SC zonestatus set.test)
expect "set.test: zonestatus shows that received settings are in force" "$OUT" "settings=primary"
OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_IN ovr.test AXFR)
expect "ovr.test: S's own allow-transfer wins over the received one" "$OUT" "rcode=5"
OUT=$("$DAG" ecs.ovr.test A @127.0.0.1 -p $PORT2 +short +subnet=198.51.100.10 2>&1)
expect "ovr.test: S's own ecs-trusted-resolvers win: 127.0.0.1 is not trusted" "$OUT" "172\\.16\\.0\\.1"
reject "ovr.test: the tagged record is not given to an untrusted resolver" "$OUT" "172\\.16\\.1\\.1"
OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_IN nops.test AXFR)
expect "nops.test: primary-settings no; ignores the received allow-transfer" "$OUT" "rcode=5"
OUT=$("$DAG" ecs.nops.test A @127.0.0.1 -p $PORT2 +short +subnet=198.51.100.10 2>&1)
expect "nops.test: primary-settings no; ignores the received ecs-trusted-resolvers" "$OUT" "172\\.16\\.0\\.1"
reject "nops.test: nothing of the primary's trust" "$OUT" "172\\.16\\.1\\.1"
OUT=$(SC zonestatus nops.test)
reject "nops.test: zonestatus shows no received settings" "$OUT" "settings=primary"
OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_IN key.test AXFR)
expect "key.test: the received allow-transfer names a key S does not have: fails closed" "$OUT" "rcode=5"
expect "key.test: logged" "$(cat "$TMP_DIR/s.log")" "TSIG key 'kx'.*not defined here"
OUT=$(perl "$PROBE" 127.0.0.1 $PORT2 $SRC_IN set.test 3)
expect "S as a primary for others: the settings it sends are the ones in force" "$OUT" "ext=3 soa=2" "settings=allow-transfer \\{ 127.0.0.1; 127.0.0.2; \\};\\|ecs-trusted-resolvers \\{ 127.0.0.1; \\};\\|"
if [ "$MULTI" = 1 ]; then
    OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_EX set.test AXFR)
    expect "set.test: 127.0.0.2 is in the received allow-transfer" "$OUT" "rcode=0"
    OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_NO set.test AXFR)
    expect "set.test: 127.0.0.3 is not" "$OUT" "rcode=5"
else
    skip "set.test AXFR from 127.0.0.2 / 127.0.0.3 (needs the loopback aliases)"
fi

echo "=== 7. the settings are replaced by the next transfer, also an IXFR; they survive a refresh failure ==="
OUT=$(perl "$PROBE" 127.0.0.1 $PORT2 $SRC_IN ix.test 3)
expect "ix.test on S: the received allow-transfer" "$OUT" "settings=allow-transfer \\{ 127.0.0.1; 127.0.0.2; \\};"
mk_ix 11; chmod 644 "$TMP_DIR/ix.zone"
mk_pconf "127.0.0.1" "127.0.0.1; 127.0.0.2; 127.0.0.3"
sleep 1; touch "$TMP_DIR/ix.zone"
PC reload > /dev/null
sleep 1
PC reload ix.test > /dev/null
sleep 0.5
OUT=$(perl "$PROBE" 127.0.0.1 $PORT1 $SRC_IN ix.test 3 IXFR 10)
expect "P: an IXFR of a plain zone carries the settings right after the opening SOA" "$OUT" "ext=3" "seq=S,65408,S"
PC notify ix.test > /dev/null
if wait_zone ix.test 11; then ok "S refreshed ix.test"; else bad "S did not refresh ix.test" "$(SC zonestatus ix.test)" "$(tail -8 "$TMP_DIR/s.log")"; fi
OUT=$(perl "$PROBE" 127.0.0.1 $PORT2 $SRC_IN ix.test 3)
expect "ix.test on S: the settings were replaced" "$OUT" "settings=allow-transfer \\{ 127.0.0.1; 127.0.0.2; 127.0.0.3; \\};"

echo "=== 8. a primary that does not know version 3 (standard AXFR): the zone is transferred, no settings ==="
OUT=$("$DAG" host.legacy.test A @127.0.0.1 -p $PORT2 +short 2>&1)
expect "legacy.test: transferred as a standard AXFR" "$OUT" "192\\.0\\.2\\.99"
OUT=$(SC zonestatus legacy.test)
reject "legacy.test: no settings in force" "$OUT" "settings=primary"

echo "=== 8b. a primary of version 2 (an old binary): S asks version 3, then version 2, and keeps the tags and attributes ==="
if [ -n "$OLD" ]; then
    wait_zone old.test && ok "S transferred old.test from the old primary" || bad "S did not transfer old.test" "$(tail -5 "$TMP_DIR/s.log")"
    wait_zone oldt.test && ok "S transferred oldt.test from the old primary" || bad "S did not transfer oldt.test"
    OUT=$("$DAG" ecs.old.test A @127.0.0.1 -p $PORT2 +short +subnet=198.51.100.10 2>&1)
    expect "old.test: the ECS tag and the trusted resolver arrived (version 2 stream)" "$OUT" "172\.16\.1\.1"
    OUT=$("$DAG" loc.old.test A @127.0.0.1 -p $PORT2 +short 2>&1)
    expect "old.test: the \$LOCATION tag arrived" "$OUT" "10\.1\.1\.1"
    OUT=$("$DAG" srv.oldt.test A @127.0.0.1 -p $PORT2 +short 2>&1)
    expect "oldt.test: the tinydns location arrived" "$OUT" "10\.10\.1\.1"
    expect "S logged that the old primary speaks version 2 only" "$(cat "$TMP_DIR/s.log")" "primary 127\.0\.0\.1 speaks Extended AXFR version 2 only"
    OUT=$(SC zonestatus old.test)
    reject "old.test: no settings from a version 2 primary" "$OUT" "settings=primary"
    mk_old_serial() { sed 's/( 5 3600/( 6 3600/' "$TMP_DIR/old.test.zone" > "$TMP_DIR/old.new" && mv "$TMP_DIR/old.new" "$TMP_DIR/old.test.zone"; chmod 644 "$TMP_DIR/old.test.zone"; }
    mk_old_serial; sleep 1; touch "$TMP_DIR/old.test.zone"
    "$KARICTL" -f "$TMP_DIR/old.conf" reload old.test > /dev/null 2>&1; sleep 0.5
    SC retransfer old.test > /dev/null
    wait_zone old.test 6 && ok "a later transfer (version 2 asked for directly) works" || bad "old.test did not follow serial 6"
    [ "$(grep -c "zone old.test.: .*answered a version 3 request with a standard transfer" "$TMP_DIR/s.log")" -le 1 ] && ok "version 3 is not tried again at every transfer" || bad "version 3 probe repeated"
else
    skip "old primary (set OLD_KARIDNS to a karidns of version 2, e.g. built from b000e2d / 31d1eaf)"
fi

echo "=== 9. settings survive a refresh failure ==="
kari_kill_tree "$PID4"; PID4=""
kari_kill_tree "$PID1"; PID1=""
sleep 2
OUT=$(perl "$AXPROBE" 127.0.0.1 $PORT2 $SRC_IN set.test AXFR)
expect "set.test: with the primary gone S still applies the received allow-transfer" "$OUT" "rcode=0"
OUT=$("$DAG" ecs.set.test A @127.0.0.1 -p $PORT2 +short +subnet=198.51.100.10 2>&1)
expect "set.test: and the received trust" "$OUT" "172\\.16\\.1\\.1"

echo
echo "=== Extended AXFR v3 (B8t-2): $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" != 0 ]; then
    echo "--- log of S"; tail -40 "$TMP_DIR/s.log"
    echo "--- log of P"; tail -20 "$TMP_DIR/p.log"
    exit 1
fi
exit 0
