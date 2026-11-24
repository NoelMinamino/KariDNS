#!/bin/sh
# karicheck zone <domain> <file> run as root (tools review 2026-11-23, T4-L4): a note on a terminal's stderr that the file is parsed with
# root's rights; nothing when stderr is not a terminal (a program that runs karicheck), and the verdict is the same.  SKIP unless root
# and script(1) are there (script gives the run a terminal).  No real names (.test).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.." || exit 1
[ -x ./karicheck ] || { echo "SKIP: no ./karicheck"; exit 0; }
[ "$(id -u)" = "0" ] || { echo "SKIP: not root"; exit 0; }
command -v script >/dev/null 2>&1 || { echo "SKIP: no script(1)"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/kc_root.XXXXXX")
trap 'rm -rf "$W"' EXIT INT TERM
cat > "$W/z.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
EOF
FAILED=0
./karicheck zone example.test "$W/z.zone" > "$W/plain.out" 2> "$W/plain.err"; rc1=$?
[ "$rc1" -eq 0 ] || { echo "FAIL: karicheck zone: exit $rc1: $(cat "$W/plain.err")"; FAILED=1; }
grep -q "as root" "$W/plain.err" && { echo "FAIL: the note went to a stderr that is not a terminal"; FAILED=1; }
if [ "$(uname -s)" = "FreeBSD" ]; then
    script -q "$W/tty.out" ./karicheck zone example.test "$W/z.zone" > /dev/null 2>&1
else
    script -q -c "./karicheck zone example.test $W/z.zone" "$W/tty.out" > /dev/null 2>&1
fi
grep -q "karicheck: note: checking $W/z.zone as root" "$W/tty.out" || { echo "FAIL: no note on a terminal: $(cat "$W/tty.out")"; FAILED=1; }
[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: karicheck root note"
exit 0
