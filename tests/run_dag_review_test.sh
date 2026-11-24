#!/bin/sh
# ==============================================================================
# run_dag_review_test.sh - dag findings of the tools review of 2026-11-23, against tests/mock_dag_review_server.pl on 127.0.0.1
#
#   T1-M1  +trace / +nssearch / +trace2 with -y: a response that fails TSIG verification is shown but not followed
#   T1-L2  +trace: the NS addresses looked up through @server are those of the NS name only (not every A record of the answer)
#   T2-L1  --replay with tls: a warning without +tls-ca; +tls-ca verifies the certificate and its name (openssl s_server; SKIP without openssl)
#   T2-L2  --replay over UDP takes the answer with the query's ID only; a TCP answer over the buffer is a failure, not compared cut
#   T2-L3  --replay text lines with an empty label or one of 64 octets are skipped with a warning, not sent
#   T2-L4  --replay: a nanosecond pcap is read; a pcapng file is refused before anything is sent
# Bounded waits only.  No real names (.test).  SKIP without perl.
# ==============================================================================
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
cd "$DIR/.." || exit 1
DAG="${DAG:-./dag}"
[ -x "$DAG" ] || { echo "SKIP: no $DAG"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: no perl"; exit 0; }
MOCK="$DIR/mock_dag_review_server.pl"
P1=$(kari_port 0 25731); P2=$(kari_port 1 25732); P3=$(kari_port 2 25733); P4=$(kari_port 3 25734); P5=$(kari_port 4 25735); P6=$(kari_port 5 25736)
W=$(mktemp -d "${TMPDIR:-/tmp}/dag_review.XXXXXX")
PIDS=""
cleanup() {
    set +e
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
pass() { echo "ok: $*"; }
start_mock() { # name port mode
    perl "$MOCK" --port "$2" --mode "$3" > "$W/$1.log" 2>&1 &
    PIDS="$PIDS $!"
    kari_wait_log "$W/$1.log" '^ready' 10 || { cat "$W/$1.log"; fail "mock $1 did not start"; }
}
KEY="hmac-sha256:k1.test:c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
Q="+nohexdump +time=1 +tries=1"

# ---------------------------------------------------------------- T1-M1
start_mock ref "$P1" referral
# shellcheck disable=SC2086
"$DAG" +trace +glue -y "$KEY" @127.0.0.1 -p "$P1" www.example.test A $Q > "$W/t1.out" 2>&1
grep -q "Couldn't verify signature: expected a TSIG or SIG(0)" "$W/t1.out" || fail "+trace -y: no verification error: $(head -20 "$W/t1.out")"
grep -q "TSIG verification failed, not following the referral; stopping trace" "$W/t1.out" || fail "+trace -y: the trace did not stop: $(tail -5 "$W/t1.out")"
grep -q "^Q www.example.test" "$W/ref.log" && fail "+trace -y followed the unverified referral (hop queries sent: $(grep -c '^Q www' "$W/ref.log"))"
pass "+trace -y: an unsigned referral is shown and not followed"
# shellcheck disable=SC2086
"$DAG" +nssearch -y "$KEY" @127.0.0.1 -p "$P1" example.test $Q > "$W/t2.out" 2>&1; rc=$?
grep -q "TSIG verification failed, not using the NS records of example.test" "$W/t2.out" && [ "$rc" -eq 1 ] || fail "+nssearch -y: exit $rc: $(tail -5 "$W/t2.out")"
grep -q "^Q example.test. 6 " "$W/ref.log" && fail "+nssearch -y asked the servers of an unverified NS answer"
pass "+nssearch -y: the NS records of an unverified answer are not used (exit $rc)"
# shellcheck disable=SC2086
"$DAG" +trace2 -y "$KEY" @127.0.0.1 -p "$P1" www.example.test A $Q > "$W/t3.out" 2>&1
grep -q "priming query to 127.0.0.1 failed: TSIG verification failed" "$W/t3.out" || fail "+trace2 -y: $(tail -8 "$W/t3.out")"
grep -q "^Q www.example.test" "$W/ref.log" && fail "+trace2 -y followed the unverified priming answer"
pass "+trace2 -y: the unverified priming answer is refused"
# without a key nothing changes: the trace follows the referral (each hop is the same mock: it ends at the hop limit or a loop)
# shellcheck disable=SC2086
"$DAG" +trace +glue @127.0.0.1 -p "$P1" www.example.test A $Q > "$W/t4.out" 2>&1
grep -q "TSIG verification failed\|Couldn't verify" "$W/t4.out" && fail "+trace without a key reports TSIG"
grep -q "^Q www.example.test" "$W/ref.log" || fail "+trace without a key did not follow the referral"
pass "+trace without a key follows the referral as before"

# ---------------------------------------------------------------- T1-L2
start_mock own "$P2" owner
# shellcheck disable=SC2086
"$DAG" +trace -4 @127.0.0.1 -p "$P2" www.example.test A $Q > "$W/t5.out" 2>&1
grep -q "127.0.0.9" "$W/t5.out" && fail "+trace took the address of another owner (evil.test.) for ns1.test.: $(grep 127.0.0.9 "$W/t5.out" | head -2)"
grep -q "Received [0-9]* bytes from 127.0.0.1#$P2(ns1.test)" "$W/t5.out" || fail "+trace did not reach ns1.test. at 127.0.0.1: $(tail -6 "$W/t5.out")"
pass "+trace: only the NS name's own address is used"

# ---------------------------------------------------------------- T2-L2, T2-L3: text replay against a server that sends a wrong-ID answer first
start_mock bad "$P3" badid
start_mock good "$P4" good
L64=$(printf '%064d' 0 | tr 0 a)
printf 'www.example.test A\nbig.example.test TXT +tcp\na..b.example.test A\n%s.example.test A\n' "$L64" > "$W/q.txt"
"$DAG" --replay "$W/q.txt" --server1 "127.0.0.1:$P3" --server2 "127.0.0.1:$P4" --output json --timeout-ms 1500 > "$W/r1.json" 2> "$W/r1.err"
mm=$(sed -n 's/.*"mismatched_queries": \([0-9]*\).*/\1/p' "$W/r1.json")
[ "${mm:-x}" = "0" ] || fail "replay took the wrong-ID datagram for the answer (mismatched ${mm:-?}): $(cat "$W/r1.err" | head -5)"
grep -q "larger than the 4096-byte replay buffer" "$W/r1.err" || fail "no warning for the TCP answer over the buffer: $(cat "$W/r1.err")"
[ "$(grep -c "is not a query name" "$W/r1.err")" -eq 2 ] || fail "the two bad names were not both reported: $(cat "$W/r1.err")"
grep -q "^Q a\. \|^Q a.example\|^Q aaaaaaaa" "$W/bad.log" && fail "a bad name was sent: $(grep '^Q a' "$W/bad.log")"
pass "replay: ID-checked UDP answers, no cut TCP comparison, bad names skipped"

# ---------------------------------------------------------------- T2-L4
printf '\012\015\015\012\034\000\000\000\115\074\053\032' > "$W/x.pcapng"
n0=$(grep -c '^Q' "$W/good.log")
"$DAG" --replay "$W/x.pcapng" --server1 "127.0.0.1:$P4" --timeout-ms 500 > "$W/r2.out" 2> "$W/r2.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q "is a pcapng file" "$W/r2.err" || fail "pcapng: exit $rc: $(cat "$W/r2.err")"
[ "$(grep -c '^Q' "$W/good.log")" -eq "$n0" ] || fail "pcapng: queries were sent"
# a nanosecond pcap (magic a1b23c4d, little endian), LINKTYPE_RAW: one IPv4/UDP query for ns-pcap.example.test A
perl -e '
    my $q = pack("nnnnnn", 0x1234, 0x0100, 1, 0, 0, 0) . "\x07ns-pcap\x07example\x04test\x00" . pack("nn", 1, 1);
    my $udp = pack("nnnn", 40000, 53, 8 + length $q, 0) . $q;
    my $ip = pack("CCnnnCCnNN", 0x45, 0, 20 + length $udp, 1, 0, 64, 17, 0, 0xc0000201, 0xc0000202);
    my ($s, @w) = (0, unpack("n10", $ip)); $s += $_ for @w; $s = ($s & 0xffff) + ($s >> 16) while $s >> 16;
    substr($ip, 10, 2) = pack("n", ~$s & 0xffff);
    my $p = $ip . $udp;
    print pack("VvvVVVV", 0xa1b23c4d, 2, 4, 0, 0, 65535, 101), pack("VVVV", 1, 500000000, length $p, length $p), $p;' > "$W/ns.pcap"
"$DAG" --replay "$W/ns.pcap" --server1 "127.0.0.1:$P4" --timeout-ms 1000 > "$W/r3.out" 2> "$W/r3.err"
kari_wait_log "$W/good.log" '^Q ns-pcap.example.test. 1 udp' 5 || fail "nanosecond pcap: the query was not replayed: $(cat "$W/r3.err" | head -3)"
pass "replay: pcapng refused before sending, nanosecond pcap read"

# ---------------------------------------------------------------- T2-L1
printf 'www.example.test A\n' > "$W/q1.txt"
"$DAG" --replay "$W/q1.txt" --server1 "127.0.0.1:$P5" --transport tls --timeout-ms 300 > "$W/r4.out" 2> "$W/r4.err"
grep -q "TLS certificate verification is disabled" "$W/r4.err" || fail "tls replay without +tls-ca: no warning: $(cat "$W/r4.err")"
"$DAG" --replay "$W/q1.txt" --server1 "127.0.0.1:$P5" --transport tls +tls-ca="$W/none.pem" --timeout-ms 300 > "$W/r5.out" 2> "$W/r5.err"; rc=$?
[ "$rc" -eq 1 ] && grep -q "could not load TLS CA file" "$W/r5.err" || fail "+tls-ca with a missing file: exit $rc: $(cat "$W/r5.err")"
if command -v openssl >/dev/null 2>&1 &&
   openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/k.pem" -out "$W/c.pem" -days 2 -subj "/CN=dot.example.test" >/dev/null 2>&1 &&
   openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/k2.pem" -out "$W/other.pem" -days 2 -subj "/CN=other.example.test" >/dev/null 2>&1; then
    sleep 60 | openssl s_server -accept "$P6" -cert "$W/c.pem" -key "$W/k.pem" -quiet > "$W/s_server.log" 2>&1 &   # (stdin kept open: at EOF it stops)
    PIDS="$PIDS $!"
    i=0; until perl -MIO::Socket::INET -e 'exit(IO::Socket::INET->new("127.0.0.1:$ARGV[0]") ? 0 : 1)' "$P6" 2>/dev/null; do
        i=$((i + 1)); [ "$i" -le 50 ] || { fail "openssl s_server did not start: $(cat "$W/s_server.log")"; break; }; sleep 0.1; done
    "$DAG" --replay "$W/q1.txt" --server1 "127.0.0.1:$P6" --transport tls +tls-ca="$W/other.pem" +tls-hostname=dot.example.test \
        --timeout-ms 1000 > "$W/r6.out" 2> "$W/r6.err"
    grep -q "TLS peer certificate verification for 127.0.0.1:$P6 failed" "$W/r6.err" || fail "+tls-ca with another CA: no verification failure: $(cat "$W/r6.err")"
    "$DAG" --replay "$W/q1.txt" --server1 "127.0.0.1:$P6" --transport tls +tls-ca="$W/c.pem" +tls-hostname=wrong.example.test \
        --timeout-ms 1000 > "$W/r7.out" 2> "$W/r7.err"
    grep -q "TLS peer certificate verification for 127.0.0.1:$P6 failed" "$W/r7.err" || fail "+tls-ca with a wrong name: no failure: $(cat "$W/r7.err")"
    "$DAG" --replay "$W/q1.txt" --server1 "127.0.0.1:$P6" --transport tls +tls-ca="$W/c.pem" +tls-hostname=dot.example.test \
        --timeout-ms 1000 > "$W/r8.out" 2> "$W/r8.err"
    grep -q "verification" "$W/r8.err" && fail "+tls-ca with the right CA and name: $(cat "$W/r8.err")"
    pass "replay tls: +tls-ca verifies the CA and the name (openssl s_server)"
else
    echo "SKIP: the +tls-ca part with a TLS server (no openssl)"
fi

grep -qE "AddressSanitizer|runtime error:" "$W"/*.out "$W"/*.err 2>/dev/null && fail "sanitizer report"
[ "$FAILED" -eq 0 ] || { echo "FAIL: dag review test"; exit 1; }
echo "PASS: dag review test"
exit 0
