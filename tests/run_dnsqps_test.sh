#!/bin/sh
# dnsqps CLI and engine test, on every platform (FreeBSD, Linux, macOS, Windows MinGW): the options and their errors, ~/.dnsqpsrc and -r, every example of
# --help, the engine against dnsqps's own loopback reflector (closed loop, open loop, the I/O paths of the platform, generated queries, interval lines, the
# JSON report, the null target, a target that does not answer), and the paths that are not built or not on this OS.
# A real server is used by tests/run_dnsqps_karidns_test.sh; the kernel-bypass paths by run_dnsqps_xdp_test.sh and run_dnsqps_netmap_test.sh.
# No real domain names (CLAUDE.md section 6): example.test, 127.0.0.1.
#
# Usage: sh tests/run_dnsqps_test.sh          (DNSQPS=./dnsqps.exe on Windows)
. "$(dirname "$0")/lib_proc.sh"
set -u
cd "$(dirname "$0")/.."

DQ="${DNSQPS:-./dnsqps}"
[ -x "$DQ" ] || make dnsqps >/dev/null 2>&1 || { echo "FAIL: no $DQ"; exit 1; }
DQ="$(cd "$(dirname "$DQ")" && pwd)/$(basename "$DQ")"   # absolute: the examples run in the test directory
PORT="${PORT:-$(kari_port 0 17653)}"
T=$(mktemp -d "${TMPDIR:-/tmp}/dnsqps_test.XXXXXX") || exit 1
REFL_PID=""
FAILED=0
cleanup() {
    [ -n "$REFL_PID" ] && kill "$REFL_PID" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL: $*"; FAILED=1; }
ok() { echo "ok: $*"; }
# the number after "key": in a JSON line
jnum() { sed -n "s/.*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }

cat > "$T/queries.txt" <<EOF
www.example.test A
mail.example.test MX +dnssec
# a comment
ipv6.example.test AAAA +bufsize=4096 +nsid
txt.example.test TXT +nord +cookie
ns.example.test NS +padding=128 +subnet=192.0.2.0/24
EOF
cat > "$T/names.txt" <<EOF
www.example.test.
mail.example.test.  3600 IN A 192.0.2.5
ftp.example.test.
; a comment
ns1.example.test.
EOF
mkdir -p "$T/home" "$T/home2"
printf '# defaults for the test\n-p %s -T 2\n' "$PORT" > "$T/home/.dnsqpsrc"
printf -- '--no-such-option\n' > "$T/home2/.dnsqpsrc"

# ---------------------------------------------------------------- 1. help, version, usage errors
"$DQ" --help > "$T/help.out" 2>&1 || fail "--help exits non-zero"
grep -q '^Usage: dnsqps' "$T/help.out" || fail "--help has no Usage line"
"$DQ" -V | grep -q '^dnsqps ' || fail "--version"
for args in "-Z" "--rate" "-Q 0" "+bogus" "--io rio" "-p 70000" "-d" "--null-target=x"; do
    # shellcheck disable=SC2086
    out=$(HOME="$T/home2" "$DQ" -r $args 2>&1 >/dev/null); rc=$?
    [ "$rc" -eq 2 ] || fail "dnsqps -r $args: exit $rc, expected 2"
    [ -n "$out" ] || fail "dnsqps -r $args: no message"
done
out=$("$DQ" -r 2>&1 >/dev/null); [ $? -eq 2 ] && echo "$out" | grep -q 'no queries' || fail "no query file: expected the message 'no queries' and exit 2"
out=$("$DQ" -r -d "$T/queries.txt" -z "$T/names.txt" 2>&1 >/dev/null); [ $? -eq 2 ] || fail "-d with -z"
out=$("$DQ" -r -d "$T/no-such-file" 2>&1 >/dev/null); [ $? -eq 2 ] && echo "$out" | grep -q 'cannot open' || fail "a query file that does not exist"
printf 'bad..name A\n' > "$T/bad.txt"
out=$("$DQ" -r -d "$T/bad.txt" 2>&1 >/dev/null); [ $? -eq 2 ] && echo "$out" | grep -q 'line 1' || fail "a bad line of the query file is named"
ok "help, version, usage errors"

# ---------------------------------------------------------------- 2. the rc file and -r
out=$(HOME="$T/home2" "$DQ" -d "$T/queries.txt" 2>&1 >/dev/null); rc=$?
[ "$rc" -eq 2 ] && echo "$out" | grep -q 'dnsqpsrc' && echo "$out" | grep -q -- '-r' || fail "a bad ~/.dnsqpsrc is named with the hint -r (exit $rc: $out)"
out=$(HOME="$T/home2" "$DQ" -r -d "$T/queries.txt" -N 1 -t 0.2 -p 9 2>&1 >/dev/null); rc=$?
[ "$rc" -ne 2 ] || fail "-r does not skip the rc file (exit $rc: $out)"
ok "rc file and -r"

# ---------------------------------------------------------------- 3. the examples of --help
"$DQ" --reflect "127.0.0.1:$PORT" > "$T/refl.log" 2>&1 &
REFL_PID=$!
i=0
until grep -q 'reflecting' "$T/refl.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -le 50 ] || { cat "$T/refl.log"; fail "the reflector did not start"; exit 1; }
    sleep 0.1
done
sed -n '/^Examples:/,/^$/p' "$T/help.out" | grep '^  dnsqps ' | sed 's/^  dnsqps //' > "$T/examples.txt"
nex=$(wc -l < "$T/examples.txt" | tr -d ' ')
[ "$nex" -ge 5 ] || fail "--help lists $nex examples, expected at least 5"
while IFS= read -r line; do
    # the examples name queries.txt and names.txt: the files of the test directory; the port comes from ~/.dnsqpsrc
    # shellcheck disable=SC2086
    (cd "$T" && HOME="$T/home" "$DQ" $line > "$T/ex.out" 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || { fail "example 'dnsqps $line' exits $rc"; cat "$T/ex.out"; }
done < "$T/examples.txt"
ok "every example of --help ($nex)"

# ---------------------------------------------------------------- 4. closed loop against the reflector
HOME="$T/home" "$DQ" -d "$T/queries.txt" -N 20000 --json -T 2 -c 2 > "$T/r1.json" 2> "$T/r1.err"; rc=$?
[ "$rc" -eq 0 ] || fail "closed loop: exit $rc"
sent=$(jnum sent < "$T/r1.json"); done_=$(jnum completed < "$T/r1.json")
[ "$sent" = "20000" ] || fail "closed loop: sent $sent, expected 20000"
[ "${done_:-0}" -ge 19000 ] 2>/dev/null || fail "closed loop: completed ${done_:-?} of 20000"
grep -q '"NOERROR":' "$T/r1.json" || fail "closed loop: no NOERROR in the report"
grep -q '"p99":' "$T/r1.json" || fail "closed loop: no latency percentiles"
ok "closed loop: sent $sent, completed $done_"

# ---------------------------------------------------------------- 5. open loop: the rate is kept
HOME="$T/home" "$DQ" -d "$T/queries.txt" -Q 2000 -l 2 --json > "$T/r2.json" 2>/dev/null
sent=$(jnum sent < "$T/r2.json")
{ [ "${sent:-0}" -ge 3000 ] && [ "${sent:-0}" -le 4400 ]; } 2>/dev/null || fail "open loop 2000 qps for 2 s: sent ${sent:-?}, expected about 4000"
ok "open loop: sent $sent at 2000 qps for 2 s"

# ---------------------------------------------------------------- 6. text report and interval lines
HOME="$T/home" "$DQ" -d "$T/queries.txt" -Q 1000 -l 2.5 -S 1 > "$T/r3.out" 2>&1
grep -q '^Statistics:' "$T/r3.out" && grep -q 'Queries sent:' "$T/r3.out" && grep -q 'Average Latency' "$T/r3.out" || fail "text report"
n=$(grep -c '^\[Interval\]' "$T/r3.out")
[ "$n" -ge 2 ] || fail "interval lines: $n, expected at least 2"
ok "text report, $n interval lines"

# ---------------------------------------------------------------- 7. the I/O paths of this OS
case "$(uname -s)" in
    Linux|FreeBSD) paths="sendto mmsg auto" ;;
    *) paths="sendto auto" ;;
esac
for p in $paths; do
    HOME="$T/home" "$DQ" -d "$T/queries.txt" -N 3000 --io "$p" --json -T 1 > "$T/io.json" 2>"$T/io.err" || fail "--io=$p: exit $?"
    d=$(jnum completed < "$T/io.json")
    [ "${d:-0}" -ge 2900 ] 2>/dev/null || fail "--io=$p: completed ${d:-?} of 3000"
done
case "$(uname -s)" in
    Linux|FreeBSD) ;;
    *) out=$("$DQ" -r -d "$T/queries.txt" --io mmsg 2>&1 >/dev/null); [ $? -eq 2 ] || fail "--io=mmsg should not exist here" ;;
esac
out=$(HOME="$T/home" "$DQ" -d "$T/queries.txt" -N 10 --io xdp 2>&1 >/dev/null); rc=$?
[ "$rc" -eq 2 ] && [ -n "$out" ] || fail "--io=xdp without its prerequisites: exit $rc, expected 2 with a message ($out)"
case "$(uname -s)" in
    FreeBSD) ;;
    *) out=$(HOME="$T/home" "$DQ" -d "$T/queries.txt" -N 10 --io netmap 2>&1 >/dev/null); [ $? -eq 2 ] && echo "$out" | grep -q 'FreeBSD' || fail "--io=netmap off FreeBSD: message and exit 2 ($out)" ;;
esac
ok "I/O paths: $paths; xdp / netmap refuse without their prerequisites"

# ---------------------------------------------------------------- 8. generated queries
HOME="$T/home" "$DQ" -z "$T/names.txt" --miss 0.3 --qtypes A:3,AAAA:1 --zipf 1 --seed 5 -N 6000 --json > "$T/g.json" 2>/dev/null || fail "generated mode: exit $?"
[ "$(jnum sent < "$T/g.json")" = "6000" ] || fail "generated mode: sent"
HOME="$T/home" "$DQ" -z "$T/names.txt" -d "$T/queries.txt" 2>/dev/null; [ $? -eq 2 ] || fail "-z with -d"
HOME="$T/home" "$DQ" -d "$T/queries.txt" --miss 0.3 2>/dev/null; [ $? -eq 2 ] || fail "--miss without -z"
ok "generated mode"

# ---------------------------------------------------------------- 9. the null target
"$DQ" -r -z "$T/names.txt" --null-target -N 5000 -T 2 --json > "$T/n1.json" 2>/dev/null || fail "null target: exit $?"
d=$(jnum completed < "$T/n1.json"); [ "${d:-0}" -ge 4500 ] 2>/dev/null || fail "null target reflector: completed ${d:-?} of 5000"
"$DQ" -r -z "$T/names.txt" --null-target=sink -N 5000 -T 1 > "$T/n2.out" 2>&1 || fail "null target sink: exit $?"
grep -q 'Queries sent:         5000' "$T/n2.out" && grep -q 'n/a' "$T/n2.out" || fail "null target sink: report"
ok "null target: reflector and sink"

# ---------------------------------------------------------------- 10. a target that does not answer
HOME="$T/home" "$DQ" -d "$T/queries.txt" -N 5 -t 0.3 -p $((PORT + 1)) > "$T/dead.out" 2>&1; rc=$?
[ "$rc" -eq 1 ] || fail "no answer: exit $rc, expected 1"
grep -q 'no answer at all' "$T/dead.out" || fail "no answer: message"
ok "no answer: exit 1"

[ "$FAILED" -eq 0 ] || { echo "FAIL: dnsqps test"; exit 1; }
echo "PASS: dnsqps test"
exit 0
