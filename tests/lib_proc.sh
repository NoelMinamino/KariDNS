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
