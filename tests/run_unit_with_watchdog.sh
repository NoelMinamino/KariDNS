#!/bin/sh
# run_unit_with_watchdog.sh - run one unit test binary with a time limit
#
#   sh tests/run_unit_with_watchdog.sh SECONDS BINARY [ARGS...]
#
# The test's output is unbuffered (stdbuf -o0 -e0 when available), so a log shows how far it got even when it never
# finishes. When the binary is still running after SECONDS, the thread backtraces are printed (procstat -kk and lldb
# on FreeBSD, gdb on Linux, whatever is installed) and the process is killed: the exit status is then 124, as timeout(1)
# reports it. A hung unit test thus fails in minutes with a trace instead of blocking a CI job until its own timeout.
limit=$1
shift
[ -n "$limit" ] && [ "$#" -gt 0 ] || { echo "usage: $0 SECONDS BINARY [ARGS...]" >&2; exit 2; }

if command -v stdbuf >/dev/null 2>&1; then
    stdbuf -o0 -e0 "$@" &
else
    "$@" &
fi
pid=$!

waited=0
while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
        echo "*** TIMEOUT: $1 (pid $pid) still running after ${limit} s; thread backtraces follow"
        if command -v procstat >/dev/null 2>&1; then
            procstat -kk "$pid" 2>&1
        fi
        if command -v lldb >/dev/null 2>&1; then
            lldb -p "$pid" --batch -o "thread backtrace all" -o "detach" 2>&1 | head -400
        elif command -v gdb >/dev/null 2>&1; then
            gdb -p "$pid" -batch -ex "thread apply all bt" 2>&1 | head -400
        fi
        kill -KILL "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        exit 124
    fi
    sleep 1
    waited=$((waited + 1))
done
wait "$pid"
