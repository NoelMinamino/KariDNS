#!/bin/sh
# dnsqps against a real karidns on the loopback address: every answer of a query file (existing and missing names), the generated mode with a share of
# misses, and every option set of dnsqps (+dnssec, +nsid, +cookie, +padding, +subnet, +bufsize, header flags): the server must answer all of them with
# NOERROR or NXDOMAIN (a malformed query would show as FORMERR), and the counts of dnsqps must be what was sent.  SKIP without ./karidns.
# No real domain names: example.test.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
cd "$ROOT" || exit 1
BIN="./karidns"
DQ="./dnsqps"
DAG="./dag"
[ -x "$BIN" ] || { echo "SKIP: no $BIN"; exit 0; }
[ -x "$DQ" ] || make dnsqps >/dev/null 2>&1 || { echo "FAIL: no dnsqps"; exit 1; }

PORT=$(kari_port 0 15611)
W=$(mktemp -d "${TMPDIR:-/tmp}/dnsqps_kari.XXXXXX")
chmod 755 "$W"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT='user "nobody"; group "nobody";'
PID=""
cleanup() {
    set +e
    kari_kill_tree "$PID"
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
jnum() { sed -n "s/.*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }

cat > "$W/example.test.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.10
mail IN A 192.0.2.11
@ IN MX 10 mail.example.test.
www IN AAAA 2001:db8::10
txt IN TXT "hello"
EOF
cat > "$W/server.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
zone "example.test" { type master; file "$W/example.test.zone"; };
EOF
"$BIN" -f "$W/server.conf" > "$W/server.log" 2>&1 &
PID=$!
if [ -x "$DAG" ]; then
    i=0
    until "$DAG" example.test SOA @127.0.0.1 -p "$PORT" +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1; do
        i=$((i + 1)); [ "$i" -le 50 ] || { cat "$W/server.log"; fail "karidns did not start"; exit 1; }
        sleep 0.3
    done
else
    sleep 3
fi

# 3 existing names and 1 missing one per pass
cat > "$W/q.txt" <<'EOF'
www.example.test A
mail.example.test MX
www.example.test AAAA
nothere.example.test A
EOF
"$DQ" -r -s 127.0.0.1 -p "$PORT" -d "$W/q.txt" -N 20000 -T 2 --json > "$W/r1.json" 2> "$W/r1.err" || { cat "$W/r1.err"; fail "query file run: exit $?"; }
sent=$(jnum sent < "$W/r1.json"); done_=$(jnum completed < "$W/r1.json")
[ "$sent" = "20000" ] || fail "query file: sent $sent"
[ "${done_:-0}" -ge 19000 ] || fail "query file: completed ${done_:-?} of 20000"
nx=$(sed -n 's/.*"NXDOMAIN":\([0-9]*\).*/\1/p' "$W/r1.json"); no=$(sed -n 's/.*"NOERROR":\([0-9]*\).*/\1/p' "$W/r1.json")
tot=$(( ${nx:-0} + ${no:-0} ))
[ "$tot" -eq "$done_" ] || fail "query file: rcodes other than NOERROR and NXDOMAIN ($(sed -n 's/.*"rcodes":\({[^}]*}\).*/\1/p' "$W/r1.json"))"
# a quarter of the queries are for the missing name
[ "${nx:-0}" -ge $((done_ * 20 / 100)) ] && [ "${nx:-0}" -le $((done_ * 30 / 100)) ] || fail "query file: $nx NXDOMAIN of $done_, expected about a quarter"
echo "ok: query file, $done_ answers, $nx NXDOMAIN"

# generated: names of the zone, half of the queries for names that do not exist
printf 'www.example.test.\nmail.example.test.\nns1.example.test.\ntxt.example.test.\nexample.test.\n' > "$W/names.txt"
"$DQ" -r -s 127.0.0.1 -p "$PORT" -z "$W/names.txt" --miss 0.5 --qtypes A:1 --zipf 1 --seed 3 -N 20000 -T 2 --json > "$W/r2.json" 2> "$W/r2.err" || { cat "$W/r2.err"; fail "generated run: exit $?"; }
done_=$(jnum completed < "$W/r2.json"); nx=$(sed -n 's/.*"NXDOMAIN":\([0-9]*\).*/\1/p' "$W/r2.json")
[ "${done_:-0}" -ge 19000 ] || fail "generated: completed ${done_:-?}"
[ "${nx:-0}" -ge $((done_ * 40 / 100)) ] && [ "${nx:-0}" -le $((done_ * 60 / 100)) ] || fail "generated: $nx NXDOMAIN of $done_, expected about half"
echo "ok: generated mode, $nx NXDOMAIN of $done_"

# every option set must be a well-formed query
for opts in "+dnssec" "+bufsize=4096" "+nsid" "+cookie" "+padding=128" "+subnet=192.0.2.0/24" "+subnet=2001:db8::/32" "+edns +dnssec +nsid +cookie +padding=64 +subnet=192.0.2.0/24" \
            "+nord" "+cd" "+ad" "+aa" "+noedns" "+class=IN"; do
    # shellcheck disable=SC2086
    "$DQ" -r -s 127.0.0.1 -p "$PORT" -d "$W/q.txt" -N 400 -T 1 --json $opts > "$W/o.json" 2>/dev/null || fail "options '$opts': exit $?"
    d=$(jnum completed < "$W/o.json"); nx=$(sed -n 's/.*"NXDOMAIN":\([0-9]*\).*/\1/p' "$W/o.json"); no=$(sed -n 's/.*"NOERROR":\([0-9]*\).*/\1/p' "$W/o.json")
    [ "${d:-0}" -ge 380 ] && [ $(( ${nx:-0} + ${no:-0} )) -eq "$d" ] || fail "options '$opts': completed ${d:-?}, NOERROR ${no:-0}, NXDOMAIN ${nx:-0}: $(sed -n 's/.*"rcodes":\({[^}]*}\).*/\1/p' "$W/o.json")"
done
echo "ok: option sets"

# per-line options of the query file
printf 'www.example.test A +dnssec +nsid\nmail.example.test MX +padding=128 +cookie\nwww.example.test AAAA +subnet=192.0.2.0/24 +bufsize=1232\ntxt.example.test TXT +nord\n' > "$W/q2.txt"
"$DQ" -r -s 127.0.0.1 -p "$PORT" -d "$W/q2.txt" -N 400 -T 1 --json > "$W/p.json" 2>/dev/null || fail "per-line options: exit $?"
d=$(jnum completed < "$W/p.json"); no=$(sed -n 's/.*"NOERROR":\([0-9]*\).*/\1/p' "$W/p.json")
[ "${d:-0}" -ge 380 ] && [ "${no:-0}" -eq "$d" ] || fail "per-line options: completed ${d:-?}, NOERROR ${no:-0}"
echo "ok: per-line options"

grep -qE "AddressSanitizer|runtime error:" "$W/server.log" && fail "sanitizer report in the server log"
[ "$FAILED" -eq 0 ] || { echo "FAIL: dnsqps against karidns"; exit 1; }
echo "PASS: dnsqps against karidns"
exit 0
