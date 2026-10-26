#!/bin/sh
# run_trap_cleanup_status_test.sh - a failing cleanup must not change the exit status of a test.
#
# FreeBSD sh applies errexit inside the EXIT trap: in a script with "set -e", a command of the trap handler that fails (an
# "rm -rf" of a directory that a dying server still writes to, a "kill" of a process that is gone) makes the script exit with 1
# AFTER it printed [PASS] (run_dnssec_secondary_test.sh did, sometimes).  A handler therefore starts with "set +e" (after it
# saved $? when it needs it).
#   1. The shell: a script with set -e and a handler "set +e; false" keeps the status of its "exit 0", and the same handler
#      without "set +e" is the failure this test guards against (documented, not asserted: other shells differ).
#   2. Every tests/run_*.sh and tests/compare_*.sh that has "set -e" and "trap cleanup ... EXIT" has "set +e" in cleanup(); a trap that is a command
#      string ("trap '...' EXIT") must end every command in "|| true".
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
FAILS=0
bad() { echo "  [FAIL] $1"; FAILS=$((FAILS + 1)); }

echo "=== exit status of a script with a failing EXIT trap ==="
sh -c 'set -e; cleanup() { set +e; false; echo after >/dev/null; }; trap cleanup EXIT; exit 0'
[ $? -eq 0 ] && echo "  [ OK ] set +e in the handler: exit 0 stays 0" || bad "a handler with set +e changed the exit status"
sh -c 'set -e; cleanup() { set +e; false; }; trap cleanup EXIT; false'
[ $? -eq 1 ] && echo "  [ OK ] set +e in the handler: a failing test still exits 1" || bad "a failing test exited 0"

echo "=== tests/run_*.sh: the handlers ==="
n=0
for f in tests/run_*.sh tests/compare_*.sh; do
    grep -q '^set -e\|^set -eu\|^set -ue' "$f" || continue
    t=$(grep -h '^trap .* EXIT' "$f" | head -1 | tr -d '\r')
    [ -n "$t" ] || continue
    n=$((n + 1))
    case "$t" in
    "trap cleanup "*)
        # the body of cleanup(): from its first line to the closing brace at column 0
        body=$(awk '/^cleanup\(\) *\{/ { on = 1; next } on && /^\}/ { exit } on { print }' "$f" | tr -d '\r')
        if [ -z "$body" ]; then bad "$f: trap cleanup, but no cleanup() { ... } found"; continue; fi
        printf '%s\n' "$body" | grep -q '^ *set +e' || bad "$f: cleanup() has no 'set +e': a failing command in it would become the exit status (FreeBSD sh)"
        ;;
    *)
        # a command string: every command must be guarded (|| true), checked on the quoted text
        case "$t" in *"|| true"*|*"|| :"*) ;; *) bad "$f: $t -- the trap command can fail (add '|| true')" ;; esac
        ;;
    esac
done
[ "$n" -gt 0 ] || bad "no script with set -e and an EXIT trap was found (the pattern in this test is out of date)"
echo "  $n scripts with set -e and an EXIT trap checked"

if [ "$FAILS" -eq 0 ]; then echo "=== trap cleanup status: all passed ==="; exit 0; fi
echo "=== trap cleanup status: $FAILS failed ==="
exit 1
