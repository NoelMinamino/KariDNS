#!/bin/sh
# run_dnssec_secondary_test.sh - a secondary serves transferred DNSSEC data like the primary (R-33).
#
# RFC 4035 §3.1.1-§3.1.3: with DO=1 an authoritative server includes the RRSIGs of the returned RRsets and the
# NSEC/NSEC3 denial proofs. RFC 5936 §3 / RFC 4035 §3.1.5: these records are zone data and are transferred like
# any other, so a secondary must answer exactly like its primary.
# The secondary keeps the RDATA of RRSIG/NSEC/NSEC3/NSEC3PARAM/DNSKEY/DS as received and also decodes the fields
# the DNSSEC answer code reads (dns_wire.c decode_dnssec_rdata()); before that it served the records only for
# explicit queries and never attached RRSIGs or proofs.
#
# Three zones are signed with dnssec-signzone: NSEC, NSEC3 (salt) and NSEC3 opt-out. A KariDNS primary serves
# the files and two KariDNS secondaries transfer them:
#   - "ext" asks the primary directly. Between two KariDNS servers the transfer uses the Extended AXFR option
#     (65153), and the primary answers an IXFR request with a full Extended AXFR.
#   - "ixfr" asks through a TCP relay that renames that option, so the primary sends a plain AXFR (RFC 5936) and,
#     after the zone changes, an incremental IXFR (RFC 1995) that the secondary applies as deletions and additions.
# The same DO=1 queries (positive answers, CNAME, DNAME, wildcards, NODATA, NXDOMAIN, empty non-terminals, secure
# and insecure referrals, DS) are sent to the primary and both secondaries and the answers must be equal (ID,
# cookie, timing and message size removed; RRs compared per section, order ignored). Then every zone is re-signed
# with a new serial and a new name (all RRSIGs and the NSEC/NSEC3 chains change), the primary reloads, the
# secondaries refresh and the answers are compared again; "ixfr" must count the refresh as an IXFR.
#
# Needs dnssec-keygen, dnssec-signzone and perl; SKIP otherwise.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$(dirname "$0")/lib_proc.sh"
ROOT="$DIR/.."
BIN="$ROOT/karidns-asan"
DAG="$ROOT/dag"
KARICTL="$ROOT/karictl"

echo "=== DNSSEC data on a secondary (R-33) ==="
for t in dnssec-keygen dnssec-signzone perl; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] $t is not installed"
        exit 0
    fi
done

[ -x "$DAG" ] || make -C "$ROOT" dag
[ -x "$KARICTL" ] || make -C "$ROOT" karictl
[ -x "$BIN" ] || make -C "$ROOT" karidns-asan

PPORT=15511    # primary
EPORT=15512    # secondary "ext"
IPORT=15513    # secondary "ixfr"
RPORT=15514    # relay to the primary
ZONES="wn.test n3.test wo.test"
W=$(mktemp -d "${TMPDIR:-/tmp}/karidns-dnssec2nd.XXXXXX")
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT='user "nobody"; group "nobody";'
fi
PRIMARY_PID=""
EXT_PID=""
IXFR_PID=""
RELAY_PID=""

cleanup() {
    kari_kill_tree "$PRIMARY_PID" "$EXT_PID" "$IXFR_PID" "$RELAY_PID"
    kari_kill_conf "$W/primary.conf" "$W/ext.conf" "$W/ixfr.conf"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[FAIL] $*"
    for f in "$W"/diff.txt "$W"/primary.log "$W"/ext.log "$W"/ixfr.log "$W"/relay.log; do
        [ -s "$f" ] && { echo "=== $f ==="; tail -n 60 "$f"; }
    done
    exit 1
}

check_asan_log() {
    if grep -qE "(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:)" "$W/primary.log" "$W/ext.log" "$W/ixfr.log"; then
        fail "sanitizer report in a server log"
    fi
}

# write_zone ZONE SERIAL [extra line]: unsigned zone text. SOA refresh/retry 2 s so the secondaries poll quickly.
write_zone() {
    cat > "$W/$1.zone" <<EOF
\$TTL 300
\$ORIGIN $1.
@ IN SOA ns1 hostmaster $2 2 2 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
www IN AAAA 2001:db8::10
mail IN MX 10 www
alias IN CNAME www
*.wild IN A 192.0.2.20
*.wild IN TXT "wild"
dn IN DNAME tgt.$1.
x.tgt IN A 192.0.2.30
a.b.ent IN A 192.0.2.40
sec IN NS ns.sec
sec IN DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.sec IN A 192.0.2.50
ins IN NS ns.ins
ns.ins IN A 192.0.2.60
$3
EOF
}

# sign ZONE: sign $W/ZONE.zone into $W/ZONE.signed with the zone's keys (created on first use)
sign() {
    case "$1" in
        wn.test) set -- "$1" ;;
        n3.test) set -- "$1" -3 AABBCCDD -H 0 ;;
        wo.test) set -- "$1" -3 - -H 0 -A ;;
    esac
    _z=$1; shift
    (
        cd "$W"
        ls "K$_z."+*.key >/dev/null 2>&1 || {
            dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$_z" >/dev/null 2>&1 &&
            dnssec-keygen -q -a ECDSAP256SHA256 "$_z" >/dev/null 2>&1
        }
        dnssec-signzone -q -S -K . "$@" -o "$_z" -f "$_z.signed.tmp" "$_z.zone" >/dev/null 2>&1 &&
        chmod 644 "$_z.signed.tmp" && mv "$_z.signed.tmp" "$_z.signed"
    )
}

for z in $ZONES; do
    write_zone "$z" 1
    if ! sign "$z"; then
        echo "[SKIP] dnssec-signzone failed for $z"
        exit 0
    fi
done

# Another server on these ports would answer instead of ours (karidns binds with SO_REUSEPORT).
for p in $PPORT $EPORT $IPORT; do
    if "$DAG" wn.test SOA @127.0.0.1 -p $p +short +nohexdump +tries=1 +time=1 >/dev/null 2>&1; then
        fail "something already answers on 127.0.0.1 port $p"
    fi
done

# TCP relay RPORT -> PPORT. In the first message of each connection (the transfer request) the EDNS option code
# 65153 (KariDNS Extended AXFR, 0xFE81, length 5) becomes 65001 (local use, ignored by the primary).
cat > "$W/relay.pl" <<'EOF'
use strict; use warnings; use IO::Socket::INET; use IO::Select;
my ($lport, $dport) = @ARGV;
my $srv = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $lport, Listen => 8, ReuseAddr => 1)
    or die "relay listen: $!";
$SIG{CHLD} = 'IGNORE';
$| = 1;
print "listening\n";
while (1) {
    my $c = $srv->accept or next;
    if (fork() == 0) {
        my $u = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $dport) or exit 0;
        my ($l, $m) = ('', '');
        exit 0 unless read($c, $l, 2) == 2;
        my $n = unpack('n', $l);
        exit 0 unless read($c, $m, $n) == $n;
        my $renamed = ($m =~ s/\xFE\x81\x00\x05/\xFD\xE9\x00\x05/g) || 0;
        print "request renamed=$renamed\n";
        syswrite($u, $l . $m);
        my $sel = IO::Select->new($c, $u);
        while (my @r = $sel->can_read(30)) {
            for my $h (@r) {
                my $k = sysread($h, my $d, 65536);
                exit 0 unless $k;
                syswrite($h == $c ? $u : $c, $d);
            }
        }
        exit 0;
    }
    close $c;
}
EOF

{
    echo "options { port $PPORT; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    for z in $ZONES; do
        echo "zone \"$z\" { type master; file \"$W/$z.signed\"; allow-transfer { 127.0.0.1; }; };"
    done
} > "$W/primary.conf"
{
    echo "options { port $EPORT; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    for z in $ZONES; do
        echo "zone \"$z\" { type slave; masters { 127.0.0.1 port $PPORT; }; };"
    done
} > "$W/ext.conf"
{
    echo "options { port $IPORT; bind-address { 127.0.0.1; }; pid-file \"none\"; $USER_OPT };"
    echo "control-channel { socket \"$W/ixfr.sock\"; algorithm hmac-sha256; secret \"ZG5zc2VjLXNlY29uZGFyeS10ZXN0LWtleS0wMDE=\"; };"
    for z in $ZONES; do
        echo "zone \"$z\" { type slave; masters { 127.0.0.1 port $RPORT; }; };"
    done
} > "$W/ixfr.conf"
cat > "$W/karictl.conf" <<EOF
socket "$W/ixfr.sock";
key "karictl" { algorithm hmac-sha256; secret "ZG5zc2VjLXNlY29uZGFyeS10ZXN0LWtleS0wMDE="; };
EOF

perl "$W/relay.pl" $RPORT $PPORT > "$W/relay.log" 2>&1 &
RELAY_PID=$!
"$BIN" -f "$W/primary.conf" > "$W/primary.log" 2>&1 &
PRIMARY_PID=$!
"$BIN" -f "$W/ext.conf" > "$W/ext.log" 2>&1 &
EXT_PID=$!
"$BIN" -f "$W/ixfr.conf" > "$W/ixfr.log" 2>&1 &
IXFR_PID=$!

# serial ZONE PORT: SOA serial as served on PORT (empty when not answering)
serial() {
    "$DAG" "$1" SOA @127.0.0.1 -p "$2" +short +nohexdump 2>/dev/null | awk '{print $3}'
}

# wait_serial PORT SERIAL WHAT
wait_serial() {
    for z in $ZONES; do
        i=0
        while [ "$(serial "$z" "$1")" != "$2" ]; do
            i=$((i + 1))
            [ $i -le 60 ] || fail "$3: $z serial is '$(serial "$z" "$1")', expected $2"
            sleep 0.5
        done
    done
}

# ask NAME TYPE PORT: DO=1 answer without ID, cookie, timing and message size; RRs sorted within each section
ask() {
    "$DAG" "$1" "$2" @127.0.0.1 -p "$3" +dnssec +nohexdump 2>&1 | awk '
        /^; <<>>/ || /^;; global options/ || /COOKIE/ || /^;; Query time/ || /^;; SERVER/ ||
        /^;; WHEN/ || /^;; MSG SIZE/ || /^$/ { next }
        /->>HEADER<<-/ { sub(/, id: [0-9]+/, ""); print; next }
        /^;; [A-Z]+ SECTION:/ { sec = $2; next }
        /^;/ { print; next }
        { print sec " " $0 | "sort" }'
}

QUERIES="@ SOA
@ NS
@ DNSKEY
@ NSEC3PARAM
www A
www TXT
nx A
nx.www A
alias A
mail MX
a.wild A
a.b.wild A
a.wild MX
x.dn A
nx.dn A
dn DNAME
ent A
b.ent A
a.b.ent A
www.sec A
sec DS
www.ins A
ins DS
sec NS"

# compare WHAT PORT [extra queries]: every query against the primary and the secondary on PORT
compare() {
    : > "$W/diff.txt"
    for z in $ZONES; do
        printf '%s\n%s\n' "$QUERIES" "$3" | while read -r name type; do
            [ -n "$name" ] || continue
            if [ "$name" = "@" ]; then q=$z; else q=$name.$z; fi
            ask "$q" "$type" $PPORT > "$W/p.txt"
            ask "$q" "$type" "$2" > "$W/s.txt"
            if ! diff "$W/p.txt" "$W/s.txt" > "$W/d.txt"; then
                { echo "--- $q $type (< primary, > secondary port $2)"; cat "$W/d.txt"; } >> "$W/diff.txt"
            fi
        done
    done
    [ ! -s "$W/diff.txt" ] || { cat "$W/diff.txt"; fail "$1: primary and secondary (port $2) answers differ"; }
}

# has NAME TYPE PORT PATTERN WHAT: the DO=1 answer contains an RR line matching PATTERN (extended regex)
has() {
    ask "$1" "$2" "$3" | grep -Eq "$4" || { ask "$1" "$2" "$3"; fail "$5"; }
}

# Positive checks on a secondary, so that equality is not reached by both servers omitting the records.
positive_checks() {
    has www.wn.test A "$2" '^ANSWER .*RRSIG[[:space:]]+A ' "$1: www.wn.test A has no RRSIG"
    has nx.wn.test A "$2" '^AUTHORITY .*[[:space:]]NSEC[[:space:]]' "$1: nx.wn.test NXDOMAIN has no NSEC"
    has nx.wn.test A "$2" '^AUTHORITY .*RRSIG[[:space:]]+SOA ' "$1: nx.wn.test NXDOMAIN has no RRSIG(SOA)"
    has www.ins.wn.test A "$2" '^AUTHORITY .*[[:space:]]NSEC[[:space:]]' "$1: insecure referral has no NSEC"
    has nx.n3.test A "$2" '^AUTHORITY .*[[:space:]]NSEC3[[:space:]]' "$1: nx.n3.test NXDOMAIN has no NSEC3"
    has a.wild.n3.test A "$2" '^AUTHORITY .*[[:space:]]NSEC3[[:space:]]' "$1: wildcard answer has no NSEC3"
    has www.ins.wo.test A "$2" '^AUTHORITY .*[[:space:]]NSEC3[[:space:]]' "$1: opt-out referral has no NSEC3"
    has www.sec.wo.test A "$2" '^AUTHORITY .*RRSIG[[:space:]]+DS ' "$1: secure referral has no RRSIG(DS)"
}

# transfers ZONE: "AXFR=n IXFR=m" counted by the "ixfr" secondary (karictl observatory)
transfers() {
    "$KARICTL" -s "$W/ixfr.sock" -f "$W/karictl.conf" observatory "$1" 2>/dev/null |
        sed -n 's/.*Transfers (In): *\(AXFR=[0-9]* IXFR=[0-9]*\).*/\1/p'
}

wait_serial $PPORT 1 "primary start"
wait_serial $EPORT 1 "initial transfer (ext)"
wait_serial $IPORT 1 "initial transfer (ixfr)"
grep -q "renamed=1" "$W/relay.log" || fail "the relay did not see an Extended AXFR request"
echo "[OK] both secondaries transferred $ZONES"
if grep -q "malformed RDATA" "$W/ext.log" "$W/ixfr.log"; then fail "a secondary logged malformed RDATA"; fi

NQ=$(printf '%s\n' "$QUERIES" | wc -l | tr -d ' ')
compare "Extended AXFR" $EPORT
positive_checks "Extended AXFR" $EPORT
compare "AXFR" $IPORT
positive_checks "AXFR" $IPORT
echo "[OK] AXFR and Extended AXFR: DO=1 answers of the primary and both secondaries are equal (3 zones x $NQ queries)"

# Re-sign with serial 2 and a new name: every RRSIG and the NSEC/NSEC3 chains change.
for z in $ZONES; do
    write_zone "$z" 2 "new IN A 192.0.2.70"
    sign "$z" || fail "re-signing $z failed"
done
kill -HUP "$PRIMARY_PID"
wait_serial $PPORT 2 "primary reload"

# The primary answers IXFR=1 incrementally (RFC 1995 §4: new SOA, old SOA, deletions, new SOA, additions).
"$DAG" wn.test IXFR=1 @127.0.0.1 -p $PPORT +nohexdump +noall +answer 2>/dev/null |
    awk '$4 == "SOA" { print $7 }' | head -n 2 | tr '\n' ' ' > "$W/ixfr.txt"
[ "$(cat "$W/ixfr.txt")" = "2 1 " ] || fail "primary IXFR=1 is not incremental (SOA serials: $(cat "$W/ixfr.txt"))"
echo "[OK] primary serves an incremental IXFR from serial 1"

wait_serial $EPORT 2 "refresh (ext)"
wait_serial $IPORT 2 "refresh (ixfr)"
for z in $ZONES; do
    [ "$(transfers $z)" = "AXFR=1 IXFR=1" ] || fail "$z on the ixfr secondary: transfers '$(transfers $z)', expected AXFR=1 IXFR=1"
done
echo "[OK] secondaries refreshed to serial 2 (the ixfr secondary by IXFR)"
compare "Extended AXFR refresh" $EPORT "new A"
positive_checks "Extended AXFR refresh" $EPORT
compare "IXFR" $IPORT "new A"
positive_checks "IXFR" $IPORT
has new.n3.test A $IPORT '^ANSWER .*RRSIG[[:space:]]+A ' "IXFR: new.n3.test A has no RRSIG"
echo "[OK] after the re-signing: DO=1 answers of the primary and both secondaries are equal"

check_asan_log
for p in "$PRIMARY_PID" "$EXT_PID" "$IXFR_PID"; do
    kill -0 "$p" 2>/dev/null || fail "a server exited"
done
echo "[PASS] secondaries serve transferred DNSSEC data like the primary (Extended AXFR, AXFR and IXFR)"
exit 0
