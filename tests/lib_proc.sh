# tests/lib_proc.sh - process control scoped to the servers a test started.
#
# Source it before any cd:   . "$(dirname "$0")/lib_proc.sh"
#
# Never use killall or an unscoped pkill/pgrep in tests: other karidns
# instances on the host (another working copy, a long-running server) must
# survive a test run.

# kari_kill_tree PID... : SIGKILL each PID and all of its descendants.
# karidns runs as supervisor + backend + frontend routers + broker, so killing
# only $! would leave the children behind. Each process is stopped before its
# children are listed, so it cannot fork new ones while the tree is walked.
kari_kill_tree() {
    local _kt_pid
    for _kt_pid in "$@"; do
        case "$_kt_pid" in ''|*[!0-9]*) continue ;; esac
        kill -STOP "$_kt_pid" 2>/dev/null || continue
        kari_kill_tree $(pgrep -P "$_kt_pid" 2>/dev/null)
        kill -9 "$_kt_pid" 2>/dev/null
    done
    return 0
}

# kari_conf_pids CONF... : print the PIDs of karidns/karidns-asan/karidns-tsan
# processes whose argument list contains one of the CONF paths as a separate
# word. CONF must be specific to the test (an absolute path, or a path under
# its own temporary directory), exactly as it was passed on the command line.
kari_conf_pids() {
    local _kc_pid _kc_cmd _kc_conf
    for _kc_pid in $(pgrep -x 'karidns(-asan|-tsan)?' 2>/dev/null); do
        _kc_cmd=$(ps -ww -o command= -p "$_kc_pid" 2>/dev/null) || continue
        for _kc_conf in "$@"; do
            [ -n "$_kc_conf" ] || continue
            case "$_kc_cmd" in
                *" $_kc_conf"|*" $_kc_conf "*) echo "$_kc_pid"; break ;;
            esac
        done
    done
    return 0
}

# kari_kill_conf CONF... : SIGKILL the processes kari_conf_pids finds. Use it
# for servers started without $! and as a fallback for children whose
# supervisor already died.
kari_kill_conf() {
    kari_kill_tree $(kari_conf_pids "$@")
}

# kari_port N [FALLBACK] : a TCP/UDP port for the test.
# Under tests/run_all_suite.sh (KARI_PORT_BASE set) every test slot has a window
# of 1000 ports: the result is KARI_PORT_BASE + N, N < 1000.  A test that needs
# several ports (a neighbour, a secondary) takes them as offsets of its window,
# and offsets used by one script must differ.  Run on its own the script keeps
# what it used before: FALLBACK (its old fixed port or PID formula, evaluated by
# the caller) or, without one, 20000 + PID % 20000 + N.
kari_port() {
    if [ -n "${KARI_PORT_BASE:-}" ]; then
        echo $((KARI_PORT_BASE + $1))
    else
        echo "${2:-$((20000 + $$ % 20000 + $1))}"
    fi
}

# kari_wait_log LOG PATTERN SECONDS [COUNT] : wait until LOG has COUNT (default 1) lines matching PATTERN (grep basic regex), at
# most SECONDS.  A LOG that does not exist yet has no line: grep -c prints nothing for it, so the count is taken as 0 (an empty
# operand of [ -ge ] is "[: : bad number").
kari_wait_log() {
    _kwl_i=0
    while [ "$_kwl_i" -lt $(($3 * 10)) ]; do
        _kwl_n=$(grep -c -- "$2" "$1" 2>/dev/null)
        [ "${_kwl_n:-0}" -ge "${4:-1}" ] && return 0
        sleep 0.1; _kwl_i=$((_kwl_i + 1))
    done
    return 1
}

# kari_test_conf SRC DST PORT SOCKET : copy the server configuration SRC (tests/karidns-test.conf) to DST with the port of
# its options { } replaced by PORT and a `socket "SOCKET";` added to its control-channel { }.  A control-channel without a
# socket binds /var/run/karidns/control.sock, and the server unlinks and re-binds that path: tests that run side by side
# (tests/run_all_suite.sh -j) would steal it from each other and reach each other's server with karictl.
# SOCKET must be in a directory of the test that is owned by root (or by the caller) and not writable by others.
kari_test_conf() {
    awk -v port="$3" -v sock="$4" '
        !done_port && /^[ \t]*port[ \t]+[0-9]+[ \t]*;/ { sub(/[0-9]+/, port); done_port = 1 }
        { print }
        /^control-channel[ \t]*\{/ { print "    socket \"" sock "\";" }' "$1" > "$2"
}

# kari_ctl_conf SRC DST SOCKET : the karictl.conf SRC (tests/karictl-test.conf) with the `socket` of the test's server
# (mode 0600, as karictl wants it).
kari_ctl_conf() {
    { printf 'socket "%s";\n' "$3"; cat "$1"; } > "$2"
    chmod 0600 "$2"
}

# kari_wait_answer DAG PORT NAME [SECONDS]: wait until the server on 127.0.0.1:PORT
# answers NAME SOA, at most SECONDS (default 15).  For a test that starts karidns
# and queries it at once: a fixed sleep is too short when the host is busy (tests
# run in parallel under tests/run_all_suite.sh).
kari_wait_answer() {
    _kw_i=0
    while [ "${_kw_i}" -lt $(( ${4:-15} * 5 )) ]; do
        # the exit status, not the output: dag prints "no servers could be reached" too (exit 9, as dig)
        "$1" @127.0.0.1 -p "$2" "$3" SOA +short +nohexdump +time=1 +tries=1 >/dev/null 2>&1 && return 0
        sleep 0.2
        _kw_i=$((_kw_i + 1))
    done
    return 1
}

# kari_make TARGET... : make as the user who ran sudo.  A test run as root (sudo sh tests/run_all_suite.sh) that runs a plain make leaves
# root-owned objects and binaries in the tree, which the next build as the normal user cannot replace.  Without sudo it is a plain make.
kari_make() {
    if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
        _km_args=""
        for _km_a in "$@"; do _km_args="$_km_args '$_km_a'"; done
        su -m "${SUDO_USER}" -c "make $_km_args"
    else
        make "$@"
    fi
}

# kari_default_db_drivers : the DB_DRIVERS a test build of karidns-dbloader gets when there is no loader to copy them from: "sqlite3 postgresql" when
# libpq is installed (pkg-config or pg_config, like the Makefile's DBPG_HAVE; CI builds both), else "sqlite3".  KARIDNS_DB_DRIVERS overrides it.
# A plain `make karidns-dbloader` builds sqlite3 only, which made every PostgreSQL test SKIP on a host that has libpq and a server.
kari_default_db_drivers() {
    if [ -n "${KARIDNS_DB_DRIVERS:-}" ]; then echo "$KARIDNS_DB_DRIVERS"; return 0; fi
    if { pkg-config --exists libpq || pg_config --version; } >/dev/null 2>&1; then echo "sqlite3 postgresql"; else echo "sqlite3"; fi
}

# kari_make_dbloader : (re)build karictl and karidns-dbloader and KEEP the drivers of the loader that is there.  A plain make of karidns-dbloader
# builds the default DB_DRIVERS (sqlite3 only) when a source is newer than the binary, which silently turned the PostgreSQL tests of the same run
# into SKIPs.  Without a loader yet kari_default_db_drivers applies.
kari_make_dbloader() {
    _kd=""
    [ -x ./karidns-dbloader ] && _kd=$(./karidns-dbloader --drivers 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')
    if [ -n "$_kd" ]; then
        kari_make karictl karidns-dbloader "DB_DRIVERS=$_kd"
    else
        kari_make karictl karidns-dbloader "DB_DRIVERS=$(kari_default_db_drivers)"
    fi
}

# kari_make_dbloader_tsan : karidns-dbloader-tsan with the drivers of ./karidns-dbloader (the default drivers when there is none)
kari_make_dbloader_tsan() {
    _kd=""
    [ -x ./karidns-dbloader ] && _kd=$(./karidns-dbloader --drivers 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')
    if [ -n "$_kd" ]; then
        kari_make karidns-dbloader-tsan "DB_DRIVERS=$_kd"
    else
        kari_make karidns-dbloader-tsan "DB_DRIVERS=$(kari_default_db_drivers)"
    fi
}
