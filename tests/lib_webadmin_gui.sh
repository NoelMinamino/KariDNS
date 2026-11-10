#!/bin/sh
# lib_webadmin_gui.sh - what the browser tests of the web interface share (tests/run_webadmin_gui_test.sh, tests/run_webadmin_gui_pg_test.sh): the checks for Firefox and
# geckodriver, the patched geckodriver of a 15.0 userland, and the run of a driver (webadmin/test/e2e/*.mjs) under a memory watchdog.  The host is a jail on a shared
# machine (an earlier benchmark made it kill other jails), and a limit on the address space (ulimit -v) stops Firefox from starting, so the resident size of everything
# below the driver (geckodriver, Firefox, its helpers) is read every two seconds, written down (the measurement of plan section 14, assumption 2) and the whole tree is
# killed when it passes GUI_MAX_RSS_MIB (default 4096).  Sourced after ROOT, T, ok(), bad() exist.

# sets FIREFOX and GECKODRIVER (or prints SKIP and returns 1)
gui_browser_check() {
    FIREFOX=${FIREFOX:-$(command -v firefox 2>/dev/null)}
    GECKODRIVER=${GECKODRIVER:-$(command -v geckodriver 2>/dev/null)}
    [ -n "$FIREFOX" ] && [ -x "$FIREFOX" ] || { echo "SKIP: Firefox is not installed (pkg install firefox)"; return 1; }
    [ -n "$GECKODRIVER" ] && [ -x "$GECKODRIVER" ] || { echo "SKIP: geckodriver is not installed (pkg install geckodriver)"; return 1; }
    "$FIREFOX" --version > /dev/null 2>&1 || { echo "SKIP: $FIREFOX does not run"; return 1; }
    # (Firefox crashes at the start when the system has no font at all)
    if command -v fc-list > /dev/null 2>&1 && [ -z "$(fc-list 2>/dev/null | head -1)" ]; then echo "SKIP: the system has no fonts (pkg install dejavu)"; return 1; fi
    # a geckodriver of a 15.1 build does not start on a 15.0 userland (FBSD_1.9): use a patched copy
    if ! "$GECKODRIVER" --version > /dev/null 2>&1; then
        if "$NODE" "$ROOT/webadmin/test/e2e/patch_geckodriver.mjs" "$GECKODRIVER" "$T/geckodriver" > /dev/null 2>&1 && "$T/geckodriver" --version > /dev/null 2>&1; then
            GECKODRIVER=$T/geckodriver
            ok "geckodriver needed a patched copy (libc of this userland is older than the package's)"
        else
            echo "SKIP: $GECKODRIVER does not run here"; return 1
        fi
    fi
    return 0
}

# the resident size in KiB of a process and everything below it, then the pids below it
gui_tree() {
    ps -axo pid,ppid,rss 2>/dev/null | awk -v root="$1" '
        NR > 1 { pp[$1] = $2; rs[$1] = $3; all[NR] = $1 }
        END {
            mine[root] = 1
            do { n = 0; for (i in all) { p = all[i]; if (!(p in mine) && (pp[p] in mine)) { mine[p] = 1; n++ } } } while (n)
            sum = 0; list = ""
            for (p in mine) { sum += rs[p]; if (p != root) list = list " " p }
            print sum list
        }'
}

# gui_run_driver NAME WORKDIR DRIVER.mjs [VAR=value ...]: runs the driver as the only browser, with the memory watchdog; sets GUI_RC (3 = no browser could start)
gui_run_driver() {
    _name=$1; _dir=$2; _driver=$3; shift 3
    mkdir -p "$_dir"
    env "$@" GUI_DIR="$_dir" GUI_GECKODRIVER="$GECKODRIVER" GUI_FIREFOX="$FIREFOX" GUI_DRIVER_PORT="$GUI_DPORT" MOZ_HEADLESS=1 "$NODE" "$_driver" > "$_dir/driver.out" 2>&1 &
    _gpid=$!
    (
        while kill -0 "$_gpid" 2>/dev/null; do
            set -- $(gui_tree "$_gpid")
            _sum=$1; shift
            echo "$_sum" >> "$_dir/mem.log"
            if [ "$_sum" -gt $((${GUI_MAX_RSS_MIB:-4096} * 1024)) ]; then
                echo "the browser passed ${GUI_MAX_RSS_MIB:-4096} MiB resident ($((_sum / 1024)) MiB) and was killed" >> "$_dir/mem.cap"
                kill -KILL "$@" 2>/dev/null
            fi
            sleep 2
        done
    ) &
    GUI_MEM=$!
    wait "$_gpid"
    GUI_RC=$?
    cat "$_dir/driver.out"
    kill "$GUI_MEM" 2>/dev/null; GUI_MEM=""
    [ -f "$_dir/mem.cap" ] && bad "$(cat "$_dir/mem.cap")"
    [ -d "$_dir/shots" ] && [ -n "$(ls "$_dir/shots" 2>/dev/null)" ] && echo "  (pictures of the failures: $_dir/shots; run with KEEP=1 to keep them)"
    _peak=$(sort -n "$_dir/mem.log" 2>/dev/null | tail -1)
    [ -n "$_peak" ] && echo "  [MEM ] $_name: peak resident size of the driver, Firefox and geckodriver together: $((_peak / 1024)) MiB"
    if [ "$GUI_RC" = 3 ]; then echo "SKIP: the browser did not start (see above)"; return 3; fi
    if [ "$GUI_RC" = 0 ]; then ok "the browser scenarios ($_name)"; else bad "the browser scenarios failed ($_name)"; fi
    return 0
}
