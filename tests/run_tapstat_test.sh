#!/bin/sh
# ==============================================================================
# run_tapstat_test.sh
#
# karidns-tapstat (dnstap aggregation, 0.6.1 M3):
#  1. file mode: known traffic from a generated Frame Streams file, zone list with the longest match, text / json / prom,
#     -o replaces the file atomically, -n / -k limits
#  2. bad input: garbage, a cut file, bad options
#  3. socket mode with hostile and odd senders (protocol errors, idle handshake, no content type) and a stale socket
#  4. socket mode against a real karidns (dnstap to the tool's socket, dag queries, the summary adds up, STOP / FINISH)
#  5. the examples of --help
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib_proc.sh"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ -x "$ROOT_DIR/karidns" ] && [ -x "$ROOT_DIR/dag" ] && [ -x "$ROOT_DIR/karidns-tapstat" ] || \
    make -C "$ROOT_DIR" karidns dag karidns-tapstat
KARIDNS="$ROOT_DIR/karidns"
DAG="$ROOT_DIR/dag"
TAPSTAT="${TAPSTAT:-$ROOT_DIR/karidns-tapstat}"
MOCK="$SCRIPT_DIR/mock_tapstat_sender.pl"

PORT=${KARIDNS_TEST_PORT:-$(kari_port 0 $((27000 + $$ % 3000)))}
TMP_DIR="/tmp/karidns_tapstat_test_$$"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
chmod 755 "$TMP_DIR"
SERVER_PID=""
TAP_PID=""
FAILED=0

cleanup() {
    set +e
    kari_kill_tree "$SERVER_PID"
    [ -n "$TAP_PID" ] && kill "$TAP_PID" 2>/dev/null
    rm -rf "$TMP_DIR" 2>/dev/null
}
trap cleanup EXIT INT TERM

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
# has FILE LINE: the sum of the JSON lines has exactly this line
has() { grep -Fxq -- "$2" "$1" && pass "$3" || { fail "$3 (no line '$2')"; }; }

echo "=== karidns-tapstat test ==="

# ---- 1. file mode ----
echo "[1] file mode"
STREAM="$TMP_DIR/traffic.fstrm"
perl "$MOCK" gen-file "$STREAM" || { echo "FAIL: cannot generate the stream"; exit 1; }

"$TAPSTAT" -r "$STREAM" -z example.test,sub.example.test -f json > "$TMP_DIR/f1.json" 2> "$TMP_DIR/f1.err"
RC=$?
[ $RC -eq 0 ] && pass "exit 0" || fail "exit status $RC"
perl "$MOCK" sum "$TMP_DIR/f1.json" > "$TMP_DIR/f1.sum"
has "$TMP_DIR/f1.sum" "frames=7" "7 frames"
has "$TMP_DIR/f1.sum" "queries=1" "1 query"
has "$TMP_DIR/f1.sum" "responses=6" "6 responses"
has "$TMP_DIR/f1.sum" "bad_frames=0" "no bad frames"
has "$TMP_DIR/f1.sum" "zone=example.test.=3" "zone example.test (response counted, the query is not)"
has "$TMP_DIR/f1.sum" "zone=sub.example.test.=2" "zone sub.example.test: the longest suffix"
has "$TMP_DIR/f1.sum" "zone=other=1" "zone other"
has "$TMP_DIR/f1.sum" "qname=www.example.test.=3" "qname"
has "$TMP_DIR/f1.sum" "qname=nx.sub.example.test.=2" "qname below sub"
has "$TMP_DIR/f1.sum" "qtype=A=4" "qtype A"
has "$TMP_DIR/f1.sum" "qtype=AAAA=2" "qtype AAAA"
has "$TMP_DIR/f1.sum" "rcode=NOERROR=3" "rcode NOERROR"
has "$TMP_DIR/f1.sum" "rcode=NXDOMAIN=2" "rcode NXDOMAIN"
has "$TMP_DIR/f1.sum" "rcode=REFUSED=1" "rcode REFUSED"
has "$TMP_DIR/f1.sum" "client=192.0.2.0/24=5" "client /24"
has "$TMP_DIR/f1.sum" "client=2001:db8:1::/56=1" "client /56"

# -t query: the query is counted for the name tables, the responses for rcode
"$TAPSTAT" -r "$STREAM" -t query -f json > "$TMP_DIR/f2.json" 2>/dev/null
perl "$MOCK" sum "$TMP_DIR/f2.json" > "$TMP_DIR/f2.sum"
has "$TMP_DIR/f2.sum" "qname=www.example.test.=1" "-t query counts the one query"
has "$TMP_DIR/f2.sum" "rcode=NXDOMAIN=2" "-t query: rcode still from the responses"
has "$TMP_DIR/f2.sum" "zone=other=1" "no -z and no query_zone: other"

# text, prom, limits, prefixes
"$TAPSTAT" -r "$STREAM" -z example.test -n 1 > "$TMP_DIR/f3.txt" 2>&1
grep -q "^frames 7  bad 0  queries 1  responses 6" "$TMP_DIR/f3.txt" && pass "text summary line" || fail "text summary line"
grep -q "^qname: events 6  keys 3  evictions 0" "$TMP_DIR/f3.txt" && pass "text qname header" || fail "text qname header"
[ "$(grep -c 'www.example.test.$' "$TMP_DIR/f3.txt")" = "1" ] && ! grep -q 'nx.sub' "$TMP_DIR/f3.txt" && pass "-n 1 shows only the top entry" || fail "-n 1"
"$TAPSTAT" -r "$STREAM" -k 1 -f json > "$TMP_DIR/f4.json" 2>/dev/null
perl "$MOCK" sum "$TMP_DIR/f4.json" > "$TMP_DIR/f4.sum"
has "$TMP_DIR/f4.sum" "qname.events=6" "-k 1: all events counted"
has "$TMP_DIR/f4.sum" "qname.evictions=2" "-k 1: two evictions (Space-Saving replaces the single kept key)"
"$TAPSTAT" -r "$STREAM" -4 16 -6 32 -f json > "$TMP_DIR/f5.json" 2>/dev/null
perl "$MOCK" sum "$TMP_DIR/f5.json" > "$TMP_DIR/f5.sum"
has "$TMP_DIR/f5.sum" "client=192.0.0.0/16=5" "-4 16"
has "$TMP_DIR/f5.sum" "client=2001:db8::/32=1" "-6 32"

PROM="$TMP_DIR/out.prom"
"$TAPSTAT" -r "$STREAM" -z example.test -f prom -o "$PROM" 2>&1
grep -q '^karidns_tapstat_count{dimension="qname",key="www.example.test."} 3$' "$PROM" && pass "prom: count line" || fail "prom: count line"
grep -q '^# TYPE karidns_tapstat_count gauge$' "$PROM" && pass "prom: TYPE line" || fail "prom: TYPE line"
grep -q '^karidns_tapstat_messages{kind="response"} 6$' "$PROM" && pass "prom: messages" || fail "prom: messages"
"$TAPSTAT" -r "$STREAM" -f prom -o "$PROM" 2>&1
[ -z "$(ls "$TMP_DIR" | grep '\.tmp\.')" ] && pass "-o leaves no temporary file" || fail "temporary file left over"
[ "$(grep -c '^karidns_tapstat_messages{kind="frames"}' "$PROM")" = "1" ] && pass "-o replaced the file" || fail "-o did not replace the file"
printf 'example.test\n# comment\n\nsub.example.test  # trailing\n' > "$TMP_DIR/zones.txt"
"$TAPSTAT" -r "$STREAM" -Z "$TMP_DIR/zones.txt" -f json > "$TMP_DIR/f6.json" 2>/dev/null
perl "$MOCK" sum "$TMP_DIR/f6.json" > "$TMP_DIR/f6.sum"
has "$TMP_DIR/f6.sum" "zone=sub.example.test.=2" "-Z zone file"
"$TAPSTAT" -r - -z example.test -f json < "$STREAM" > "$TMP_DIR/f7.json" 2>/dev/null
perl "$MOCK" sum "$TMP_DIR/f7.json" > "$TMP_DIR/f7.sum"
has "$TMP_DIR/f7.sum" "frames=7" "-r - reads standard input"

# ---- 2. bad input and options ----
echo "[2] bad input"
head -c 3000 /dev/urandom > "$TMP_DIR/garbage.bin"
"$TAPSTAT" -r "$TMP_DIR/garbage.bin" > "$TMP_DIR/g.out" 2> "$TMP_DIR/g.err"
RC=$?
[ $RC -eq 1 ] && grep -q "not a valid Frame Streams" "$TMP_DIR/g.err" && pass "garbage file: exit 1 with a message" || fail "garbage file: exit $RC"
SIZE=$(wc -c < "$STREAM" | tr -d ' ')
head -c $((SIZE - 17)) "$STREAM" > "$TMP_DIR/cut.fstrm"
"$TAPSTAT" -r "$TMP_DIR/cut.fstrm" -f json > "$TMP_DIR/c.json" 2>/dev/null
RC=$?
perl "$MOCK" sum "$TMP_DIR/c.json" > "$TMP_DIR/c.sum"
[ $RC -eq 0 ] && pass "cut file: exit 0" || fail "cut file: exit $RC"
has "$TMP_DIR/c.sum" "frames=6" "cut file: the complete frames count"
"$TAPSTAT" -r "$TMP_DIR/none.fstrm" >/dev/null 2>&1; [ $? -eq 1 ] && pass "missing file: exit 1" || fail "missing file"
"$TAPSTAT" >/dev/null 2>&1; [ $? -eq 2 ] && pass "no input: exit 2" || fail "no input"
"$TAPSTAT" -r x -s y >/dev/null 2>&1; [ $? -eq 2 ] && pass "-r and -s: exit 2" || fail "-r and -s"
"$TAPSTAT" -r "$STREAM" -i 0 >/dev/null 2>&1; [ $? -eq 2 ] && pass "-i 0: exit 2" || fail "-i 0"
"$TAPSTAT" -r "$STREAM" -f xml >/dev/null 2>&1; [ $? -eq 2 ] && pass "-f xml: exit 2" || fail "-f xml"
"$TAPSTAT" -r "$STREAM" -z "a..b" >/dev/null 2>&1; [ $? -eq 2 ] && pass "bad zone name: exit 2" || fail "bad zone name"
"$TAPSTAT" -r "$STREAM" -k 0 >/dev/null 2>&1; [ $? -eq 2 ] && pass "-k 0: exit 2" || fail "-k 0"
"$TAPSTAT" -r "$STREAM" -4 33 >/dev/null 2>&1; [ $? -eq 2 ] && pass "-4 33: exit 2" || fail "-4 33"
"$TAPSTAT" -r "$STREAM" -m 999 >/dev/null 2>&1; [ $? -eq 2 ] && pass "-m 999: exit 2" || fail "-m 999"
"$TAPSTAT" --version | grep -q '^karidns-tapstat ' && pass "--version" || fail "--version"
"$TAPSTAT" --help | grep -q '^Usage: karidns-tapstat' && pass "--help" || fail "--help"

# ---- 3. socket mode, odd senders ----
echo "[3] socket mode, hostile senders"
SOCK="$TMP_DIR/t.sock"
# a stale socket file of an earlier run is replaced; a file that is no socket is refused
perl -MIO::Socket::UNIX -e 'my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $ARGV[0], Listen => 1) or die; close $s;' "$SOCK"
[ -S "$SOCK" ] && pass "stale socket file present" || fail "no stale socket file"
echo x > "$TMP_DIR/notasocket"
"$TAPSTAT" -s "$TMP_DIR/notasocket" >/dev/null 2>"$TMP_DIR/ns.err"; [ $? -eq 1 ] && grep -q "is not a socket" "$TMP_DIR/ns.err" && pass "a regular file is refused" || fail "regular file as socket path"

"$TAPSTAT" -s "$SOCK" -i 1 -f json -m 600 > "$TMP_DIR/s1.json" 2> "$TMP_DIR/s1.err" &
TAP_PID=$!
# the stale socket file is still there until the listener replaces it: wait for a connection that works
for i in $(seq 1 50); do perl -MIO::Socket::UNIX -e 'exit(IO::Socket::UNIX->new(Peer => $ARGV[0]) ? 0 : 1)' "$SOCK" 2>/dev/null && break; sleep 0.2; done
[ -S "$SOCK" ] && pass "listening on the socket" || fail "no socket"
"$TAPSTAT" -s "$SOCK" >/dev/null 2>"$TMP_DIR/inuse.err"; [ $? -eq 1 ] && grep -q "in use" "$TMP_DIR/inuse.err" && pass "a socket in use is refused" || fail "second listener"
[ "$(ls -l "$SOCK" | cut -c1-10)" = "srw-------" ] && pass "-m 600 sets the socket mode" || fail "socket mode $(ls -l "$SOCK" | cut -c1-10)"

for mode in garbage badct earlydata oversize; do
    perl "$MOCK" send "$SOCK" $mode > "$TMP_DIR/m.out" 2>&1 && pass "sender '$mode' is dropped" || { fail "sender '$mode': $(cat "$TMP_DIR/m.out")"; }
done
kill -0 "$TAP_PID" 2>/dev/null && pass "still running after the hostile senders" || fail "karidns-tapstat died"
perl "$MOCK" send "$SOCK" good > "$TMP_DIR/m.out" 2>&1 && pass "a correct session: ACCEPT, frames, FINISH" || fail "good session: $(cat "$TMP_DIR/m.out")"
perl "$MOCK" send "$SOCK" nofields > "$TMP_DIR/m.out" 2>&1 && pass "READY without content type" || fail "nofields: $(cat "$TMP_DIR/m.out")"
perl "$MOCK" send "$SOCK" idle > "$TMP_DIR/m.out" 2>&1 && pass "a sender that does not finish the handshake is dropped" || fail "idle: $(cat "$TMP_DIR/m.out")"
# many senders at once: 16 are served, more are refused, all of them are dropped again
PIDS=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
    perl "$MOCK" send "$SOCK" garbage > /dev/null 2>&1 &
    PIDS="$PIDS $!"
done
for p in $PIDS; do wait "$p"; done
kill -0 "$TAP_PID" 2>/dev/null && pass "still running after 18 senders at once" || fail "died with many senders"
sleep 1.2
kill -TERM "$TAP_PID"
wait "$TAP_PID"
RC=$?
TAP_PID=""
[ $RC -eq 0 ] && pass "SIGTERM: exit 0" || fail "SIGTERM: exit $RC"
[ ! -e "$SOCK" ] && pass "socket file removed" || fail "socket file left"
grep -q "protocol error" "$TMP_DIR/s1.err" && pass "protocol errors are reported on stderr" || fail "no protocol error message"
perl "$MOCK" sum "$TMP_DIR/s1.json" > "$TMP_DIR/s1.sum"
# good: 7 frames, nofields: 1 frame
has "$TMP_DIR/s1.sum" "frames=8" "frames of the two correct sessions add up over the intervals"
has "$TMP_DIR/s1.sum" "responses=7" "responses"

# ---- 4. a real karidns ----
echo "[4] karidns -> karidns-tapstat"
USER_OPT=""
if [ "$(id -u)" = "0" ]; then
    USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
fi
cat > "$TMP_DIR/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
EOF
chmod 644 "$TMP_DIR/example.test.zone"
DSOCK="$TMP_DIR/live.sock"
cat > "$TMP_DIR/karidns.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};
dnstap {
    socket "$DSOCK";
    log-queries yes;
    log-responses yes;
};
zone "example.test" {
    type primary;
    file "$TMP_DIR/example.test.zone";
};
EOF
chmod 644 "$TMP_DIR/karidns.conf"

"$TAPSTAT" -s "$DSOCK" -i 1 -f json -m 666 > "$TMP_DIR/live.json" 2> "$TMP_DIR/live.err" &
TAP_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "$DSOCK" ] && break; sleep 0.2; done
"$KARIDNS" -f -c "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "karidns did not start"; cat "$TMP_DIR/karidns.log"
else
    "$DAG" @127.0.0.1 -p $PORT +nohexdump www.example.test A >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PORT +nohexdump +tcp www.example.test A >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PORT +nohexdump nx.example.test A >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PORT +nohexdump ns1.example.test AAAA >/dev/null 2>&1
    "$DAG" @127.0.0.1 -p $PORT +nohexdump www.example.org A >/dev/null 2>&1
    sleep 2.5
    # karidns stops first: STOP, and it waits for FINISH from the tool
    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
    sleep 0.5
fi
kill -0 "$TAP_PID" 2>/dev/null && pass "karidns-tapstat still running after karidns stopped" || fail "karidns-tapstat died"
kill -TERM "$TAP_PID"
wait "$TAP_PID"
TAP_PID=""
perl "$MOCK" sum "$TMP_DIR/live.json" > "$TMP_DIR/live.sum"
has "$TMP_DIR/live.sum" "queries=5" "5 AUTH_QUERY messages"
has "$TMP_DIR/live.sum" "responses=5" "5 AUTH_RESPONSE messages"
has "$TMP_DIR/live.sum" "bad_frames=0" "no frame that could not be read"
has "$TMP_DIR/live.sum" "malformed=0" "no malformed question"
has "$TMP_DIR/live.sum" "qname=www.example.test.=2" "qname seen twice (UDP and TCP)"
has "$TMP_DIR/live.sum" "qname=nx.example.test.=1" "qname of the NXDOMAIN"
has "$TMP_DIR/live.sum" "qtype=A=4" "four A queries"
has "$TMP_DIR/live.sum" "qtype=AAAA=1" "one AAAA query"
has "$TMP_DIR/live.sum" "rcode=NOERROR=3" "rcode NOERROR (two A, one NODATA)"
has "$TMP_DIR/live.sum" "rcode=NXDOMAIN=1" "rcode NXDOMAIN"
has "$TMP_DIR/live.sum" "rcode=REFUSED=1" "rcode REFUSED"
has "$TMP_DIR/live.sum" "zone=example.test.=4" "zone from query_zone"
has "$TMP_DIR/live.sum" "zone=other=1" "REFUSED has no zone"
has "$TMP_DIR/live.sum" "client=127.0.0.0/24=5" "client prefix"
grep -q "protocol error" "$TMP_DIR/live.err" && fail "protocol error from karidns: $(cat "$TMP_DIR/live.err")" || pass "no protocol error from karidns"
grep -q "no FINISH" "$TMP_DIR/karidns.log" && fail "karidns got no FINISH after STOP" || pass "karidns logged no missing FINISH after STOP"

# ---- 4b. log-queries no: only AUTH_RESPONSE frames (docs/karidns.md "Counting": one frame per query) ----
echo "[4b] karidns (log-queries no) -> karidns-tapstat"
sed -e 's/log-queries yes;/log-queries no;/' "$TMP_DIR/karidns.conf" > "$TMP_DIR/karidns_r.conf"
chmod 644 "$TMP_DIR/karidns_r.conf"
"$TAPSTAT" -s "$DSOCK" -i 1 -t response -f json -m 666 > "$TMP_DIR/live_r.json" 2> "$TMP_DIR/live_r.err" &
TAP_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "$DSOCK" ] && break; sleep 0.2; done
"$KARIDNS" -f -c "$TMP_DIR/karidns_r.conf" > "$TMP_DIR/karidns_r.log" 2>&1 &
SERVER_PID=$!
sleep 1.5   # (as in 4: connected to the tool before the first query)
"$DAG" @127.0.0.1 -p $PORT +nohexdump www.example.test A >/dev/null 2>&1
"$DAG" @127.0.0.1 -p $PORT +nohexdump +tcp www.example.test A >/dev/null 2>&1
"$DAG" @127.0.0.1 -p $PORT +nohexdump nx.example.test A >/dev/null 2>&1
kill -TERM "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""
sleep 1.5   # one more summary interval of the tool
kill -TERM "$TAP_PID"
wait "$TAP_PID"
TAP_PID=""
perl "$MOCK" sum "$TMP_DIR/live_r.json" > "$TMP_DIR/live_r.sum"
has "$TMP_DIR/live_r.sum" "frames=3" "log-queries no: three frames for three queries"
has "$TMP_DIR/live_r.sum" "queries=0" "log-queries no: no AUTH_QUERY frame"
has "$TMP_DIR/live_r.sum" "responses=3" "log-queries no: one AUTH_RESPONSE per query (3)"
has "$TMP_DIR/live_r.sum" "qname=www.example.test.=2" "log-queries no: -t response counts each query once"

# ---- 5. the examples of --help ----
echo "[5] --help examples"
cd "$TMP_DIR" || exit 1
cp "$STREAM" queries.fstrm
"$TAPSTAT" -r queries.fstrm -f json -n 50 > ex2.json 2>&1 && [ -s ex2.json ] && pass "example 2" || fail "example 2"
"$TAPSTAT" -s "$TMP_DIR/tapstat.sock" -z example.test,example.org -i 60 -f prom -o "$TMP_DIR/karidns_tapstat.prom" &
TAP_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "$TMP_DIR/tapstat.sock" ] && break; sleep 0.2; done
perl "$MOCK" send "$TMP_DIR/tapstat.sock" good >/dev/null 2>&1
kill -TERM "$TAP_PID"
wait "$TAP_PID"
TAP_PID=""
grep -q '^karidns_tapstat_count{dimension="zone",key="example.test."} 5$' "$TMP_DIR/karidns_tapstat.prom" && pass "example 1" || fail "example 1"

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "=== karidns-tapstat test passed ==="
    exit 0
fi
echo "=== karidns-tapstat test FAILED ($FAILED) ==="
exit 1
