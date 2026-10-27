#!/bin/sh
# ==============================================================================
# tests/run_server_lifecycle_test.sh - Server Lifecycle & Crash-Resistance Matrix
#
# Needs root: the server refuses to start as root without a "user" directive and
# a non-root server has nothing to drop, so the cases below only mean something
# when the server starts as root and drops to nobody.  SKIP otherwise.
# (Before this guard a non-root run hung forever: the second instance of Case 2
# is not refused (SO_REUSEPORT, same uid) and ran in the foreground.)
# Every wait on a server is bounded; a server that does not stop is SIGKILLed.
# ==============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/lib_proc.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -x "./karidns" ]; then
    echo "SKIP: karidns binary not found"
    exit 0
fi

if [ "$(id -u)" != "0" ]; then
    echo "SKIP: needs root (the server starts as root and drops to nobody)"
    exit 0
fi
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
NOBODY_GROUP="$(id -gn nobody 2>/dev/null || echo nobody)"

TMP_DIR="$(mktemp -d /tmp/karidns_lifecycle.XXXXXX 2>/dev/null || mktemp -d)"
chmod 755 "${TMP_DIR}"
PIDS=""

cleanup() {
    set +e  # trap handler: with set -e a failing command here would become the exit status of the test (FreeBSD sh)
    # shellcheck disable=SC2086
    kari_kill_tree ${PIDS}
    kari_kill_conf "${TMP_DIR}/valid.conf" "${TMP_DIR}/conflict.conf"
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

# wait_exit PID SECONDS : wait (bounded) until PID is gone; 0 if it exited.
wait_exit() {
    _n=$(( $2 * 10 ))
    while kill -0 "$1" 2>/dev/null && [ "${_n}" -gt 0 ]; do
        sleep 0.1
        _n=$((_n - 1))
    done
    ! kill -0 "$1" 2>/dev/null
}

# stop_server PID : SIGTERM, then SIGKILL the whole tree if it does not stop in 10 s.
stop_server() {
    kill -TERM "$1" 2>/dev/null || true
    if ! wait_exit "$1" 10; then
        echo "FAIL: pid $1 did not stop on SIGTERM within 10 s"
        kari_kill_tree "$1"
        exit 1
    fi
    wait "$1" 2>/dev/null || true
}

# Case 1: Bad Config Rejection
cat > "${TMP_DIR}/bad_syntax.conf" <<EOF
options {
    directory "/invalid/syntax
EOF

./karidns -c "${TMP_DIR}/bad_syntax.conf" -f > "${TMP_DIR}/bad.log" 2>&1 &
BAD_PID=$!
PIDS="${PIDS} ${BAD_PID}"
if ! wait_exit "${BAD_PID}" 10; then
    echo "FAIL: karidns did not exit on bad config syntax"
    exit 1
fi
if wait "${BAD_PID}" 2>/dev/null; then
    echo "FAIL: karidns should have exited with error on bad config syntax"
    exit 1
fi
echo "[+] Case 1: Bad syntax cleanly rejected"

# Case 2: Port Conflict (EADDRINUSE)
PORT=$(kari_port 0 $((30000 + ( $$ % 10000 ))))
cat > "${TMP_DIR}/valid.conf" <<EOF
options {
    directory "${TMP_DIR}";
    pid-file "none";
    listen-on { 127.0.0.1; };
    port ${PORT};
    user "nobody";
    group "${NOBODY_GROUP}";
};
EOF

# Start instance 1
./karidns -c "${TMP_DIR}/valid.conf" -f > "${TMP_DIR}/srv1.log" 2>&1 &
P1=$!
PIDS="${PIDS} ${P1}"
sleep 0.5
if ! kill -0 "${P1}" 2>/dev/null; then
    echo "FAIL: instance 1 did not start"
    cat "${TMP_DIR}/srv1.log"
    exit 1
fi

# Start instance 2 on the same port.  The server either refuses (bind error) or
# runs next to instance 1 (SO_REUSEPORT); both are acceptable, a crash or a
# hang of instance 1 is not.  Instance 2 is bounded: it is stopped below if it
# is still running.
cp "${TMP_DIR}/valid.conf" "${TMP_DIR}/conflict.conf"
./karidns -c "${TMP_DIR}/conflict.conf" -f > "${TMP_DIR}/conflict.log" 2>&1 &
P2=$!
PIDS="${PIDS} ${P2}"
sleep 1
if kill -0 "${P2}" 2>/dev/null; then
    stop_server "${P2}"
fi
if ! kill -0 "${P1}" 2>/dev/null; then
    echo "FAIL: instance 1 died when instance 2 was started on the same port"
    cat "${TMP_DIR}/srv1.log"
    exit 1
fi

# Cleanly terminate instance 1
stop_server "${P1}"

echo "[+] Case 2: Port conflict handled"

# Case 3: SIGHUP / SIGUSR1 Signal handling
./karidns -c "${TMP_DIR}/valid.conf" -f > "${TMP_DIR}/sig.log" 2>&1 &
SIG_PID=$!
PIDS="${PIDS} ${SIG_PID}"
sleep 0.5

kill -HUP "${SIG_PID}" 2>/dev/null || true
sleep 0.1
kill -USR1 "${SIG_PID}" 2>/dev/null || true
sleep 0.1
if ! kill -0 "${SIG_PID}" 2>/dev/null; then
    echo "FAIL: server died on SIGHUP/SIGUSR1"
    cat "${TMP_DIR}/sig.log"
    exit 1
fi
stop_server "${SIG_PID}"

echo "[+] Case 3: Signals (SIGHUP, SIGUSR1, SIGTERM) handled cleanly"

echo "[+] All Server Lifecycle tests passed successfully."
exit 0
