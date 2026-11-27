# tests/lib_proc.sh - process control scoped to the servers a test started.
#
# Source it before any cd:   . "$(dirname "$0")/lib_proc.sh"
#
# Never use killall or an unscoped pkill/pgrep in tests: other karidns
# instances on the host (another working copy, a long-running server) must
# survive a test run.

# The servers a test starts write nothing to the host's system log (0.7 M4): with KARIDNS_NOSYSLOG=1 karidns prints what it would give
# syslog(3) on its stderr only, in the form of the LOG_PERROR copy it prints anyway ("KariDNS <pid> - - <text>"), so a test that reads the
# stderr of a foreground server sees the same lines.  A test that reads the system log on purpose sets KARIDNS_NOSYSLOG=0 after sourcing
# this file (tests/run_log_secrets_test.sh); a value already in the environment is kept.
KARIDNS_NOSYSLOG=${KARIDNS_NOSYSLOG:-1}
export KARIDNS_NOSYSLOG
# A database { } block without `store` would use the default zone store /var/db/karidns/store whenever the host has /var/db/karidns: with
# KARIDNS_NO_DEFAULT_STORE=1 the server runs without a store then, so the result of a test never depends on that directory (docs/karidns.md
# ENVIRONMENT).  A test of the store names its directory (store_stmt below, the *_store_test.sh scripts); a value already in the environment is kept.
KARIDNS_NO_DEFAULT_STORE=${KARIDNS_NO_DEFAULT_STORE:-1}
export KARIDNS_NO_DEFAULT_STORE

# kari_wait_no_proc PATTERN SECONDS : wait until no process command line matches PATTERN (pgrep -f), at most SECONDS.  A server that was stopped
# leaves its loader / children for a moment: one look after a fixed sleep reports them as left over on a busy host.
kari_wait_no_proc() {
    _kwn_i=0
    while [ "$_kwn_i" -lt $(($2 * 10)) ]; do
        [ -z "$(pgrep -f "$1")" ] && return 0
        sleep 0.1; _kwn_i=$((_kwn_i + 1))
    done
    return 1
}

# kari_log_tail LOG : the last lines of LOG (at most 12 lines in all: bad() of the webadmin tests prints the first 12 lines of its second argument), for a check that fails
# with nothing else to show (a daemon that did not stop after SIGTERM).
kari_log_tail() {
    echo "tail of $1:"
    tail -n 11 "$1" 2>&1
}

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

# kari_conf_pids CONF... : print the PIDs of karidns/karidns-asan/karidns-tsan/karidns-evict
# processes whose argument list contains one of the CONF paths as a separate
# word. CONF must be specific to the test (an absolute path, or a path under
# its own temporary directory), exactly as it was passed on the command line.
# (karidns-evict, the build with the test knobs, was missing: a wait for the processes of a
# conf saw none, and the next start met the old Backend's control socket, which still answered.)
kari_conf_pids() {
    local _kc_pid _kc_cmd _kc_conf
    for _kc_pid in $(pgrep -x 'karidns(-asan|-tsan|-evict)?' 2>/dev/null); do
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

# kari_ask_retry DAG PORT NAME EXPECT [TRIES]: ask 127.0.0.1:PORT for NAME (A) until the answer contains EXPECT, at most TRIES times (default 25), 0.2 s apart.
# A query for a database zone that is out of memory is refused at once (SERVFAIL with EDE 14, Not Ready) while the zones in memory are above 110% of memory-limit:
# the cache manager takes zones out every 50 ms (not the ones that came in less than 100 ms ago), and the client asks again, as a resolver does.  How many zones
# the limit holds depends on the allocator's size classes (0.7 counts the blocks the allocator holds), so a test that asks for zones that are out of memory
# one after the other must not count on every one of them being read at the first try.  KARI_ASK_REFUSED is how many of the tries were such refusals, KARI_ASK_ODD
# how many were something else (a time-out, another rcode): a refusal is the server's answer, anything else is a defect.
kari_ask_retry() {
    KARI_ASK_REFUSED=0
    KARI_ASK_ODD=0
    _ka_i=0
    while [ "$_ka_i" -lt "${5:-25}" ]; do
        _ka_out=$("$1" @127.0.0.1 -p "$2" "$3" A +nohexdump +time=5 +tries=1 2>/dev/null)
        case "$_ka_out" in
            *"$4"*) return 0 ;;
            *"status: SERVFAIL"*"EDE: 14"*) KARI_ASK_REFUSED=$((KARI_ASK_REFUSED + 1)) ;;
            *) KARI_ASK_ODD=$((KARI_ASK_ODD + 1)) ;;
        esac
        sleep 0.2
        _ka_i=$((_ka_i + 1))
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

# 0.7 store S3, DB_DIFF_STORE=cold (run_db_file_diff_test.sh, run_db_signed_diff_test.sh): the database server B (pid in SB) was started with a `store` (STORE_STMT in its conf) and has read
# every zone; it is stopped (a clean stop) and started again on the same store with an idle program in the place of the loader, so every answer of B is made from the store alone
# ("store-cold": a zone is attached on the first query for it).  store_cold_restart DIR CONFNAME LOG: the conf file is DIR/CONFNAME, LOG the log of the first run; the caller defines
# wait_log, pass, fail and KARIDNS.  Without DB_DIFF_STORE=cold it does nothing.
# store_stmt DIR: the `store` statement of the database server: a zone store in DIR/store with DB_DIFF_STORE=cold or DB_STORE=on (the store-on variants of the database tests,
# 0.7 WP7b: tests/run_db_<name>_store_test.sh), else `store none;` (the old behaviour whatever /var/db/karidns says on the host)
store_stmt() { if [ "${DB_DIFF_STORE:-}" = cold ] || [ "${DB_STORE:-}" = on ]; then printf 'store "%s/store"; store-hot-list no;' "$1"; else printf 'store none;'; fi; return 0; }
# KARI_STOP_WAIT_TENTHS: how long (tenths of a second) a test waits for a karidns it sent SIGTERM before it kills it.  The Manager gives a Backend in the
# clean checkpoint of its zone store up to 120 s (SHUTDOWN_STORE_KILL_MS, 0.7); a test that kills the Manager sooner leaves that Backend holding the
# store, and its next start finds the store "in use by another server" or the old control socket (suite 2026-11-26: run_db_memdefault_test after a
# 12.4 s stop).  A server that stops at once is not waited for longer.
KARI_STOP_WAIT_TENTHS=${KARI_STOP_WAIT_TENTHS:-1300}
store_cold_restart() {
    [ "${DB_DIFF_STORE:-}" = cold ] || return 0
    kill -TERM "$SB" 2>/dev/null
    # (the Manager gives a Backend in the clean checkpoint of its store up to 120 s, SHUTDOWN_STORE_KILL_MS: a new server started before the old one ended finds the store
    # "in use by another server"; suite 2026-11-26)
    i=0; while [ $i -lt "$KARI_STOP_WAIT_TENTHS" ] && kill -0 "$SB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    printf '#!/bin/sh\nexec sleep 100000\n' > "$1/idle-loader"; chown 0:0 "$1/idle-loader"; chmod 755 "$1/idle-loader"
    sed "s|loader-path \"[^\"]*\"|loader-path \"$1/idle-loader\"|" "$1/$2" > "$1/cold-$2"
    "$KARIDNS" -c "$1/cold-$2" -f > "$3.cold" 2>&1 &
    SB=$!
    if ! wait_log "$3.cold" "\[Store\] the zone store is on" 30; then fail "store-cold: the database server did not open its store again"; sed 's/^/         /' "$3.cold" | tail -10; return 1; fi
    pass "store-cold: the database server runs on its store with an idle loader (every zone is attached on its first query)"
}

# store_prefill (DB_STORE=on, 0.7 WP7b): the zones of a server that has a store are in memory after its first start (the store protocol brings every body in); the tests of the old behaviour
# start from zones that are out of memory.  A server that is started again on its store has exactly that: the zones are stored and not in memory (they are attached on their first query).  So
# after the first start of a test, once the background fetch has put every body in the store, the server is stopped and started again.  Once per test ($T/store.filled).  The caller
# defines SRV, T, KARIDNS, KCTL (the karictl command line), stop_srv; the configuration is $T/k.conf and the log $T/srv.log.
store_prefill() {
    [ "${DB_STORE:-}" = on ] || return 0
    [ -e "$T/store.filled" ] && return 0
    : > "$T/store.filled"
    _sp_i=0
    while [ $_sp_i -lt 1800 ]; do
        _sp_kv=$($KCTL store -k 2>/dev/null)
        _sp_k=$(echo "$_sp_kv" | sed -n 's/^store\.zones\.known=//p')
        _sp_s=$(echo "$_sp_kv" | sed -n 's/^store\.zones\.stored=//p')
        _sp_f=$(echo "$_sp_kv" | sed -n 's/^store\.recon\.bodies\.in_flight=//p')
        _sp_r=$(echo "$_sp_kv" | sed -n 's/^store\.zones\.rejected=//p')          # (a zone the loader cannot read, or the Backend refuses, stays known and is flagged: it is not waited for)
        [ $((${_sp_k:-1} - ${_sp_r:-0})) -le 0 ] && [ "${_sp_s:-0}" -gt 0 ] && [ "${_sp_f:-1}" = 0 ] && break
        sleep 0.1
        _sp_i=$((_sp_i + 1))
    done
    $KCTL dbstatus 2>/dev/null | grep '^fetchq:' | tr ' ' '\n' | sed -n 's/^peak=//p' | head -1 > "$T/fill.peak"        # (the most fetches the fill had in flight: tests of fetch-concurrency look at it)
    stop_srv
    : > "$T/srv.log"
    "$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
    SRV=$!
    _sp_i=0
    while [ $_sp_i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/srv.log" 2>/dev/null; do sleep 0.1; _sp_i=$((_sp_i + 1)); done
    return 0
}

# kari_lab_zones : the zone files of tests/zones/ that are part of the repository (tests/zones/LAB_ZONES), one path relative to the source root per line.  Tests that run
# side by side (tests/run_all_suite.sh -j) write temporary zone files of their own into tests/zones/ while they run (ttl_clamp_test.zone, ...), so a glob of
# tests/zones/*.zone sees files come and go: a test that takes "every lab zone" (run_db_dump_test.sh: reference stream and database must hold the same zones) lists them here.
kari_lab_zones() {
    sed 's#^#tests/zones/#' "${ROOT:-.}/tests/zones/LAB_ZONES"
}

# kari_udp_snap FILE / kari_udp_delta FILE: the counters of `netstat -s -p udp` now, and what changed since the snapshot (the client and the server of a test are on one host, so a datagram that a socket buffer
# could not take, "dropped due to full socket buffers", is counted here whichever side lost it; the server's own counters do not see it).  The lines are "+N label", the drops and errors among them.
kari_udp_snap() { netstat -s -p udp 2>/dev/null | sed -n 's/^[[:space:]]*\([0-9][0-9]*\) \(.*[a-z].*\)$/\2=\1/p' > "$1"; }
kari_udp_delta() {
    netstat -s -p udp 2>/dev/null | sed -n 's/^[[:space:]]*\([0-9][0-9]*\) \(.*[a-z].*\)$/\2=\1/p' | awk -F= 'NR == FNR { a[$1] = $2; next } { d = $2 - a[$1]; if (d != 0) printf "    %+d %s\n", d, $1 }' "$1" -
}

# kari_lost_diag KARICTL PORT ZONE... : zones whose query got no right answer (the first 10 are looked at).  For each: what the server says about the zone (karictl store zone: the record, whether it is in memory,
# where it is on its way there, the claims of the attach and of the fetch) and what a query for www.ZONE gets now (a query that is answered now was lost on the way, or waited for a wake-up that did not come).
kari_lost_diag() {
    _kld_ctl=$1
    _kld_port=$2
    shift 2
    _kld_n=0
    for _kld_z in "$@"; do
        [ "$_kld_n" -ge 10 ] && break
        _kld_n=$((_kld_n + 1))
        echo "  [lost diag] $_kld_z"
        printf '    server: %s\n' "$($_kld_ctl store -k zone "$_kld_z" 2>&1 | grep -E '^store\.zone\.(state|attached|elem|resident|staged|elem_state|att_claim|att_claim_req|att_claim_workers|fetch_claim)=|ERROR' | tr '\n' ' ')"
        printf '    dbstatus: %s\n' "$($_kld_ctl dbstatus "$_kld_z" 2>&1 | head -3 | tr '\n' ' ')"
        printf '    a query now: %s\n' "$(./dag @127.0.0.1 -p "$_kld_port" "www.$_kld_z" A +noall +comments +answer +nohexdump +time=3 +tries=1 2>&1 | grep -E 'status:|timed out|no servers|^www' | head -3 | tr '\n' ' ')"
    done
}

# kari_ipc_diag KARICTL LOG : for a test that lost a query (or got a wrong answer under load) on a server it started.  KARICTL is the command that
# reaches that server ("./karictl -c conf"), LOG its log.  Prints the drop counters between the routers and the workers that are not 0
# (karictl ipcstats, 0.7: a query dropped there was never counted anywhere before) and the lines of the log about the IPC and UDP socket buffers
# and the drops ("[IPC] WARNING ..." says a buffer did not get the size asked for).  So the next failure shows whether the loss was there.
kari_ipc_diag() {
    _kid_ctl=$1
    _kid_log=$2
    echo "  [ipc diag] karictl ipcstats (counters that are not 0):"
    _kid_out=$($_kid_ctl ipcstats 2>&1)
    _kid_nz=$(printf '%s\n' "$_kid_out" | grep -v '=0$')
    if [ -n "$_kid_nz" ]; then printf '%s\n' "$_kid_nz" | sed 's/^/    /'; else printf '%s\n' "$_kid_out" | head -3 | sed 's/^/    all 0, or no answer: /'; fi
    echo "  [ipc diag] buffer and drop lines of $_kid_log:"
    grep -h '\[IPC\]\|\[Network\] .*\(SO_RCVBUF\|SO_SNDBUF\)\|dropped [0-9]* UDP message' "$_kid_log" 2>/dev/null | head -6 | cut -c1-500 | sed 's/^/    /'
    echo "  [ipc diag] kern.ipc.maxsockbuf=$(sysctl -n kern.ipc.maxsockbuf 2>/dev/null) net.local.dgram.recvspace=$(sysctl -n net.local.dgram.recvspace 2>/dev/null)"
}

# kari_share_sqlite FILE... : a SQLite3 file the signer uses holds the private keys, and karidns-signer refuses one that other users can read (0.7 review W1-L3).
# A test that shares it with the server's loader (the user nobody) makes nobody the owner of the file and of its -wal / -shm, mode 0660 (the signer of the
# tests runs as root); not root: 0660, ours.  The signer's lock file (*.signer.lock) is left alone: it must stay the signer's.
kari_share_sqlite() {
    for _f in "$@"; do
        case $_f in *.signer.lock) continue ;; esac
        [ -e "$_f" ] || continue
        chmod 660 "$_f"
        if [ "$(id -u)" = 0 ] && id nobody >/dev/null 2>&1; then chown nobody "$_f"; fi
    done
    return 0
}

# kari_now : the time of day (UTC) with milliseconds, for the diagnostics (FreeBSD's date(1) has no %N)
kari_now() { perl -MTime::HiRes=time -MPOSIX=strftime -e '$t = time; print strftime("%H:%M:%S", gmtime($t)), sprintf(".%03d\n", ($t - int($t)) * 1000)' 2>/dev/null || date -u '+%H:%M:%S'; }

# kari_try_snap DIR [KARICTL] / kari_noanswer_diag DIR KARICTL LOG PORT NAME TYPE [PROC] : a query to a server of the test that got no answer (CI flakes rows 9, 10, 34 and
# the gap.test case: one try, or all of them, lost to 127.0.0.1 on a quiet runner).  kari_try_snap, before the try: its time, `netstat -s -p udp`,
# net.inet.ip.intr_queue_drops and (with KARICTL) karictl ipcstats into DIR.  kari_noanswer_diag, when the try got no answer, prints to stdout what tells the
# places apart: the drops of the loopback netisr IP queue and the UDP counters of the host since the try; the server's ipcstats since the try
# (ipcworker.N.queries grew: a worker read the query and udp_one() ran it; ipc.*dropped*: lost between a worker and a router); the store counters of
# queries dropped without an answer (store.park.drop.*, store.lookup.drop.*: parked and dropped at park-timeout, the queue, the room) and the fetchq line;
# the last lines of the server's log; then a query now, and the UDP counters during it: "dropped due to no socket" growing is a reply that came after
# the client had given up (a late reply, not a lost one).  KARICTL empty: only the host's counters.  At most 3 blocks per DIR, so a loop that waits does
# not fill the log.  A diagnostic only: the callers' checks and tries are as before.
# CI flake rows 9, 90 (2026-11-28): on the 14.4 runners the workers read the lost queries (ipcworker.N.queries grew) and the replies left seconds later
# ("dropped due to no socket" after the query), from two workers at once, with the zones in memory (the tests run without a store): something held the
# replies after the workers.  So the diag also says, at the moment it runs: the thread states of the server's processes (PROC, a pgrep -f pattern: the
# configuration file the server was started with) with their wait channels and, as root, their kernel stacks; the page-ins from swap and from files and
# the free memory since the try; the server's log without the diag's own control lines; and how long the server then stays silent.
kari_vm_snap() { sysctl -n vm.stats.vm.v_swappgsin vm.stats.vm.v_swappgsout vm.stats.vm.v_vnodepgsin 2>/dev/null | tr '\n' ' '; echo; }
kari_try_snap() {
    mkdir -p "$1" 2>/dev/null
    kari_now > "$1/t0"
    kari_udp_snap "$1/udp.snap"
    sysctl -n net.inet.ip.intr_queue_drops > "$1/iqd" 2>/dev/null || echo 0 > "$1/iqd"
    kari_vm_snap > "$1/vm.snap"
    if [ -n "${2:-}" ]; then $2 ipcstats 2>/dev/null | grep '^[a-z][a-z0-9._]*=[0-9][0-9]*$' > "$1/ipc.snap"; else : > "$1/ipc.snap"; fi
}
# kari_proc_state PATTERN : the threads of the processes whose command line matches PATTERN (pgrep -f), but those that wait as an idle server's do (a thread of
# a pool in uwait, a nap in nanslp, the manager in sigwait, a pipe read in sbwait, a kevent() in kqread: those only counted), and as root the kernel stacks of
# the ones shown
kari_proc_state() {
    _kps_p=$(pgrep -f -- "$1" 2>/dev/null | tr '\n' ' ')
    [ -n "$_kps_p" ] || { echo "      (no process matches $1)"; return 0; }
    ps -H -o pid,lwp,stat,wchan,time,nvcsw,nivcsw,comm -p "$(echo $_kps_p | tr ' ' ',')" > "${TMPDIR:-/tmp}/kari_ps.$$" 2>&1
    awk 'NR == 1 { print; next } $3 !~ /[TDL]/ && $4 ~ /^(uwait|nanslp|sigwait|sbwait|kqread)$/ { idle[$4]++; next } { print; busy[$2] = 1 }
         END { s = ""; for (w in idle) s = s " " idle[w] " " w; print "(and" s ")" }' "${TMPDIR:-/tmp}/kari_ps.$$" | head -24 | sed 's/^/      /'
    if [ "$(id -u)" = 0 ]; then
        _kps_l=$(awk 'NR > 1 && !($3 !~ /[TDL]/ && $4 ~ /^(uwait|nanslp|sigwait|sbwait|kqread)$/) { print $2 }' "${TMPDIR:-/tmp}/kari_ps.$$" | head -12)
        for _kps_t in $_kps_l; do procstat -kk $_kps_p 2>/dev/null | awk -v t="$_kps_t" '$2 == t' | cut -c1-300 | sed 's/^/      /'; done
    fi
    rm -f "${TMPDIR:-/tmp}/kari_ps.$$"
}
kari_noanswer_diag() {
    _kn_d=$1; _kn_ctl=$2; _kn_log=$3; _kn_port=$4; _kn_name=$5; _kn_type=$6; _kn_proc=${7:-}
    _kn_end=$(kari_now)
    kari_udp_snap "$_kn_d/udp.late"
    _kn_vm1=$(kari_vm_snap)
    _kn_q1=$(sysctl -n net.inet.ip.intr_queue_drops 2>/dev/null || echo 0)
    _kn_n=$(cat "$_kn_d/count" 2>/dev/null || echo 0)
    _kn_n=$((_kn_n + 1)); echo "$_kn_n" > "$_kn_d/count"
    if [ "$_kn_n" -gt 3 ]; then
        [ "$_kn_n" = 4 ] && echo "  [no answer diag] $_kn_name $_kn_type at $_kn_end: one more query without an answer (not described again)"
        return 0
    fi
    echo "  [no answer diag] $_kn_name $_kn_type to 127.0.0.1#$_kn_port: asked at $(cat "$_kn_d/t0" 2>/dev/null) UTC, no answer by $_kn_end UTC"
    echo "    net.inet.ip.intr_queue_drops: $(cat "$_kn_d/iqd" 2>/dev/null) -> $_kn_q1 (intr_queue_maxlen=$(sysctl -n net.inet.ip.intr_queue_maxlen 2>/dev/null) net.isr.dispatch=$(sysctl -n net.isr.dispatch 2>/dev/null) hw.ncpu=$(sysctl -n hw.ncpu 2>/dev/null) load: $(sysctl -n vm.loadavg 2>/dev/null))"
    echo "    netstat -s -p udp since the query (the whole host: other tests count too):"
    kari_udp_delta "$_kn_d/udp.snap" | head -12
    echo "$(cat "$_kn_d/vm.snap" 2>/dev/null) $_kn_vm1" | awk '{ printf "    pages since the query: %+d in from swap, %+d out to swap, %+d in from files", $4 - $1, $5 - $2, $6 - $3 }'
    printf '; free memory %s MB; swap: %s\n' "$(( $(sysctl -n vm.stats.vm.v_free_count 2>/dev/null || echo 0) * $(sysctl -n hw.pagesize 2>/dev/null || echo 4096) / 1048576 ))" "$(swapinfo -m 2>/dev/null | tail -n 1 | awk '{ print $3 " MB used of " $2 }')"
    if [ -n "$_kn_proc" ]; then
        echo "    the server's threads at $(kari_now) (a router waits in kqread, a worker in kqread or for its queries; anything else holds the replies):"
        kari_proc_state "$_kn_proc"
    fi
    if [ -n "$_kn_log" ] && [ -f "$_kn_log" ]; then
        echo "    the last lines of $_kn_log (without the [Control] lines of this diag):"
        grep -v '\[Control\] key "(main)": \(ipcstats\|store -k\|dbstatus\)$' "$_kn_log" | tail -n 10 | cut -c1-300 | sed 's/^/      /'
    fi
    if [ -n "$_kn_ctl" ]; then
        echo "    karictl ipcstats since the query (ipcworker.N.queries: read and run by worker N; ipc.*dropped*: lost between a worker and a router):"
        $_kn_ctl ipcstats 2>&1 | awk -F= 'NR == FNR { a[$1] = $2; next } NF == 2 && $2 ~ /^[0-9]+$/ { d = $2 - a[$1]; if (d != 0) printf "      %+d %s (now %s)\n", d, $1, $2; next } { print "      " $0 }' "$_kn_d/ipc.snap" - | head -20
        echo "    karictl store -k, queries dropped without an answer (not 0; counted since the start):"
        $_kn_ctl store -k 2>&1 | grep -E '^store\.(park\.drop\.|lookup\.(drop\.|shed=|expired=|reask_suppressed=|servfail=))|ERROR' | grep -v '=0$' | head -12 | sed 's/^/      /'
        printf '    dbstatus: %s\n' "$($_kn_ctl dbstatus 2>&1 | grep -E 'fetchq:|ERROR' | head -1 | sed 's/^ *//')"
    fi
    _kn_now=$("${ROOT:-.}/dag" @127.0.0.1 -p "$_kn_port" "$_kn_name" "$_kn_type" +nohexdump +time=3 +tries=1 2>&1 | grep -E 'status:|timed out|no servers' | head -2 | tr '\n' ' ')
    printf '    a query now (%s UTC): %s\n' "$(kari_now)" "$_kn_now"
    echo "    netstat -s -p udp from the end of the query to now ('dropped due to no socket': a reply that came late):"
    kari_udp_delta "$_kn_d/udp.late" | head -8
    case $_kn_now in
        *status:*) ;;
        *)  # still silent: how long it stays so (one try of 1 s at a time, at most 20), and the threads once more when it is over or the time is up
            _kn_i=0
            while [ "$_kn_i" -lt 20 ] && ! "${ROOT:-.}/dag" @127.0.0.1 -p "$_kn_port" "$_kn_name" "$_kn_type" +nohexdump +time=1 +tries=1 2>&1 | grep -q 'status:'; do _kn_i=$((_kn_i + 1)); done
            [ "$_kn_i" -lt 20 ] && echo "    answered again at $(kari_now) UTC, after $_kn_i more tries of 1 s" || echo "    still no answer at $(kari_now) UTC (20 more tries of 1 s)"
            if [ -n "$_kn_proc" ]; then
                echo "    the server's threads at $(kari_now):"
                kari_proc_state "$_kn_proc"
            fi ;;
    esac
}

# kari_noanswer_script FILE DIR KARICTL LOG PORT [PROC] : writes a sh script FILE for a test program that is not sh (webadmin/test/it_versions.mjs, IT_LOST_DIAG):
# `sh FILE snap` before a query, `sh FILE diag NAME TYPE` when it got no answer (kari_try_snap, kari_noanswer_diag above, with these arguments)
kari_noanswer_script() {
    cat > "$1" <<EOF
#!/bin/sh
cd "${ROOT:-.}" || exit 0
. "${ROOT:-.}/tests/lib_proc.sh"
case "\$1" in
    snap) kari_try_snap "$2" "$3" ;;
    diag) kari_noanswer_diag "$2" "$3" "$4" "$5" "\$2" "\$3" "${6:-}" ;;
esac
exit 0
EOF
}
