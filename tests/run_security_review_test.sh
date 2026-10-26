#!/bin/sh
# run_security_review_test.sh - the fixes of the independent security review (2026-10).
#
#   P4  root by another name (user "root" / "toor", group "wheel") is refused as user, group, loader-user, loader-group
#       and program-user: by karicheck conf and by karidns itself (start).
#   P1  karicheck conf, run by root, never runs a loader that failed the owner / mode checks, and never runs one as root:
#       the loader is run as loader-user, with an empty environment and no descriptor above 2 (S-5, closefrom).   [root]
#   P2  an existing log directory keeps its owner; a directory karidns creates is handed to the run user.         [root]
#   P3  a log file that is a hard link (or belongs to a third user) is refused; the file it links to is not touched. [root]
#   S-1 a program zone's plugin starts with an empty environment.                                                 [root]
#   I5  a TXT with 60 character-strings is served, transferred (AXFR) and kept by a secondary as it is.
#   I2  a secondary with max-zone-records below the size of the zone does not take the transfer; with room it does.
#
# [root] sections SKIP when the test is not run by root.  Needs karidns, karicheck, dag; the P1 section also needs
# karidns-dbloader (as the file to copy).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
for b in ./karidns ./karicheck ./dag; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_secrev.XXXXXX") || exit 1
chmod 755 "$T"
PIDS=""
cleanup() {
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done
    sleep 0.3
    for p in $PIDS; do kill -KILL "$p" 2>/dev/null; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
BASEPORT=$((20000 + $$ % 20000))
RUN_USER=""
[ $IS_ROOT = 1 ] && RUN_USER='user "nobody"; group "nobody";'
[ $IS_ROOT = 1 ] && ! id nobody >/dev/null 2>&1 && { echo "SKIP: no user nobody"; exit 0; }

has_user() { id "$1" >/dev/null 2>&1; }
# a name that is root: "root", and "toor" where it exists (FreeBSD)
ROOTNAMES="root"
has_user toor && ROOTNAMES="root toor"
ROOTGROUP=$(id -gn root 2>/dev/null || echo wheel)

kc() {   # kc CONF -> output in $OUT, status in $ST
    OUT=$(./karicheck conf "$1" 2>&1); ST=$?
}
expect_kc() {   # expect_kc DESC CONF PATTERN
    kc "$2"
    if [ $ST -ne 0 ] && printf '%s\n' "$OUT" | grep -q -- "$3"; then ok "$1"
    else bad "$1 (exit $ST; pattern: $3)" "$OUT"; fi
}

echo "== P4: root by another name is refused (karicheck conf, karidns start)"
printf '$TTL 60\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$T/z.zone"
for n in $ROOTNAMES; do
    printf 'options { user "%s"; };\nzone "z.test" { type primary; file "%s/z.zone"; };\n' "$n" "$T" > "$T/c.conf"
    expect_kc "karicheck: options user \"$n\"" "$T/c.conf" "uid 0"
    OUT=$(timeout 10 ./karidns -f "$T/c.conf" 2>&1); ST=$?
    if [ $ST -ne 0 ] && printf '%s\n' "$OUT" | grep -q "uid 0"; then ok "karidns refuses to start with user \"$n\""
    else bad "karidns started (or said nothing useful) with user \"$n\" (exit $ST)" "$OUT"; fi
done
printf 'options { user "nobody"; group "%s"; };\nzone "z.test" { type primary; file "%s/z.zone"; };\n' "$ROOTGROUP" "$T" > "$T/c.conf"
if has_user nobody; then
    expect_kc "karicheck: options group \"$ROOTGROUP\"" "$T/c.conf" "gid 0"
    OUT=$(timeout 10 ./karidns -f "$T/c.conf" 2>&1); ST=$?
    if [ $ST -ne 0 ] && printf '%s\n' "$OUT" | grep -q "gid 0"; then ok "karidns refuses to start with group \"$ROOTGROUP\""
    else bad "karidns started with group \"$ROOTGROUP\" (exit $ST)" "$OUT"; fi
fi
for n in $ROOTNAMES; do
    printf 'options { allow-program-zones yes; database { driver sqlite3; database-file "%s/x.db"; loader-user "%s"; }; };\n' "$T" "$n" > "$T/c.conf"
    expect_kc "karicheck: database loader-user \"$n\"" "$T/c.conf" "loader-user / loader-group: .*uid 0"
    printf 'options { allow-program-zones yes; };\nzone "p.test" { type program; program "/bin/true"; program-user "%s"; };\n' "$n" > "$T/c.conf"
    expect_kc "karicheck: program-user \"$n\"" "$T/c.conf" "program-user: .*uid 0"
done
printf 'options { database { driver sqlite3; database-file "%s/x.db"; loader-user "nobody"; loader-group "%s"; }; };\n' "$T" "$ROOTGROUP" > "$T/c.conf"
has_user nobody && expect_kc "karicheck: database loader-group \"$ROOTGROUP\"" "$T/c.conf" "gid 0"

echo "== P1 / S-5: karicheck conf run by root and a loader that is not trustworthy"
if [ $IS_ROOT = 1 ] && [ -x ./karidns-dbloader ] && command -v perl >/dev/null 2>&1; then
    mkdir "$T/out"; chown nobody "$T/out"; chmod 755 "$T/out"
    # a loader that answers --drivers and records who and how it was run
    cat > "$T/ldr_src" <<EOF
#!/bin/sh
echo "ran" >> "$T/out/ran"
id -u >> "$T/out/uid"
env > "$T/out/env"
fstat -p \$\$ > "$T/out/fds" 2>&1
[ "\$1" = "--drivers" ] && echo sqlite3
exit 0
EOF
    ldrconf() {   # ldrconf LOADER [extra database statements]
        printf 'options {\n  user "nobody";\n  database { driver sqlite3; database-file "%s/x.db"; loader-path "%s"; %s };\n};\nzone "z.test" { type primary; file "%s/z.zone"; };\n' \
            "$T" "$1" "${2:-}" "$T" > "$T/l.conf"
    }
    # (a) owned by somebody else than root: refused, and not run
    cp "$T/ldr_src" "$T/ldr_other"; chmod 755 "$T/ldr_other"; chown nobody "$T/ldr_other"
    rm -f "$T/out/ran"
    ldrconf "$T/ldr_other" 'loader-user "nobody";'
    expect_kc "P1: a loader owned by another user is an error" "$T/l.conf" "is owned by uid"
    [ -e "$T/out/ran" ] && bad "P1: the loader owned by another user was run" || ok "P1: the loader owned by another user was not run"
    # (b) writable by group: refused, not run
    cp "$T/ldr_src" "$T/ldr_gw"; chmod 775 "$T/ldr_gw"; chown 0:0 "$T/ldr_gw"
    ldrconf "$T/ldr_gw" 'loader-user "nobody";'
    expect_kc "P1: a group-writable loader is an error" "$T/l.conf" "writable by group or others"
    [ -e "$T/out/ran" ] && bad "P1: the group-writable loader was run" || ok "P1: the group-writable loader was not run"
    # (c) root-owned, but no loader-user: not run as root
    cp "$T/ldr_src" "$T/ldr"; chmod 755 "$T/ldr"; chown 0:0 "$T/ldr"
    ldrconf "$T/ldr" ''
    kc "$T/l.conf"
    [ -e "$T/out/ran" ] && bad "P1: the loader was run by root without a loader-user" || ok "P1: no loader-user: the loader was not run as root"
    # (d) loader-user root by name: not run
    for n in $ROOTNAMES; do
        ldrconf "$T/ldr" "loader-user \"$n\";"
        kc "$T/l.conf"
        [ -e "$T/out/ran" ] && bad "P1: the loader was run for loader-user \"$n\"" || ok "P1: loader-user \"$n\": the loader was not run"
    done
    # (e) the good case: run as nobody, empty environment, no inherited descriptor (S-5: 300 is above the old 3..255 loop)
    ldrconf "$T/ldr" 'loader-user "nobody";'
    NOBODY_UID=$(id -u nobody)
    OUT=$(KC_CANARY=leaked perl -MPOSIX -e 'open(F, "<", "/dev/null") or die; POSIX::dup2(fileno(F), 300) or die; exec(@ARGV)' ./karicheck conf "$T/l.conf" 2>&1); ST=$?
    if [ -e "$T/out/ran" ]; then ok "P1: with a root-owned loader and a loader-user the loader is run"; else bad "P1: the loader was not run (exit $ST)" "$OUT"; fi
    if [ "$(sort -u "$T/out/uid" 2>/dev/null)" = "$NOBODY_UID" ]; then ok "P1: the loader ran as loader-user (uid $NOBODY_UID), not as root"
    else bad "P1: the loader ran as uid $(sort -u "$T/out/uid" 2>/dev/null | tr '\n' ' ')" "$OUT"; fi
    if [ -f "$T/out/env" ] && ! grep -q KC_CANARY "$T/out/env"; then ok "P1: the loader's environment does not carry the caller's variables"
    else bad "P1: the loader inherited the environment" "$(cat "$T/out/env" 2>/dev/null)"; fi
    if [ -f "$T/out/fds" ] && ! awk '$0 ~ /(^|[ \t])300([ \t]|$)/ { f = 1 } END { exit f ? 0 : 1 }' "$T/out/fds"; then ok "S-5: descriptor 300 of the caller is not open in the loader"
    else bad "S-5: descriptor 300 reached the loader" "$(cat "$T/out/fds" 2>/dev/null)"; fi
else
    echo "  [SKIP] needs root, karidns-dbloader and perl"
fi

# ----------------------------------------------------------------------------------------------------------------
# karidns instances
start_karidns() {   # start_karidns CONF LOG PORT -> pid in $KPID; waits for the SOA of z.test (or the given zone)
    ./karidns -f "$1" > "$2" 2>&1 &
    KPID=$!
    PIDS="$PIDS $KPID"
}
wait_answer() {   # wait_answer PORT ZONE [SECONDS]
    i=0
    while [ $i -lt $((${3:-10} * 10)) ]; do
        ./dag @127.0.0.1 -p "$1" "$2" SOA +short +nohexdump 2>/dev/null | grep -q host && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
stop_karidns() {
    kill -TERM "$1" 2>/dev/null
    i=0; while kill -0 "$1" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    kill -KILL "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}
logconf() {   # logconf PORT LOGFILE
    cat > "$T/log.conf" <<EOF
options { port $1; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER };
logging { channel q { file "$2"; }; category queries { q; }; };
zone "z.test" { type primary; file "$T/z.zone"; };
EOF
}

echo "== P2 / P3: log directories and log files"
if [ $IS_ROOT = 1 ]; then
    PORT=$((BASEPORT + 1))
    NOBODY_UID=$(id -u nobody)
    # P2: an existing directory keeps its owner, a new one is handed to the run user, the file is the run user's
    mkdir "$T/existing" "$T/vlog"; chmod 755 "$T/existing"
    logconf $PORT "$T/existing/q.log"
    start_karidns "$T/log.conf" "$T/p2.out" $PORT
    if wait_answer $PORT z.test; then
        [ "$(stat -f %u "$T/existing")" = "0" ] && ok "P2: an existing log directory keeps its owner (root)" || bad "P2: the existing log directory was chowned to uid $(stat -f %u "$T/existing")" "$(cat "$T/p2.out")"
    else bad "P2: karidns did not start" "$(cat "$T/p2.out")"; fi
    stop_karidns $KPID
    logconf $PORT "$T/newdir/q.log"
    start_karidns "$T/log.conf" "$T/p2b.out" $PORT
    if wait_answer $PORT z.test; then
        [ "$(stat -f %u "$T/newdir" 2>/dev/null)" = "$NOBODY_UID" ] && ok "P2: a directory karidns created is the run user's" || bad "P2: the new directory is owned by uid $(stat -f %u "$T/newdir" 2>/dev/null)" "$(cat "$T/p2b.out")"
    else bad "P2: karidns did not start (new directory)" "$(cat "$T/p2b.out")"; fi
    stop_karidns $KPID

    # P3: a hard link to another file is refused and the file is left alone
    echo "secret" > "$T/victim"; chmod 600 "$T/victim"
    ln "$T/victim" "$T/existing/h.log"
    logconf $PORT "$T/existing/h.log"
    start_karidns "$T/log.conf" "$T/p3.out" $PORT
    sleep 2
    if kill -0 $KPID 2>/dev/null; then bad "P3: karidns runs with a log file that is a hard link" "$(cat "$T/p3.out")"; stop_karidns $KPID
    else ok "P3: karidns refuses to start with a hard-linked log file"; fi
    grep -q "Refusing to use log file" "$T/p3.out" && ok "P3: the refusal names the log file" || bad "P3: no 'Refusing to use log file' message" "$(cat "$T/p3.out")"
    [ "$(stat -f %u "$T/victim")" = "0" ] && [ "$(cat "$T/victim")" = "secret" ] && ok "P3: the linked file keeps its owner and content" || bad "P3: the linked file was touched (owner $(stat -f %u "$T/victim"))"
    # P3: a log file of a third user
    has_user daemon && {
        : > "$T/existing/d.log"; chown daemon "$T/existing/d.log"
        logconf $PORT "$T/existing/d.log"
        start_karidns "$T/log.conf" "$T/p3b.out" $PORT
        sleep 2
        if kill -0 $KPID 2>/dev/null; then bad "P3: karidns runs with a log file of a third user" "$(cat "$T/p3b.out")"; stop_karidns $KPID
        else ok "P3: karidns refuses a log file owned by a third user"; fi
        [ "$(stat -f %u "$T/existing/d.log")" = "$(id -u daemon)" ] && ok "P3: that file keeps its owner" || bad "P3: the third user's file was chowned"
    }
    # a plain file with one link, root-owned, from an earlier start: fine
    : > "$T/existing/ok.log"
    logconf $PORT "$T/existing/ok.log"
    start_karidns "$T/log.conf" "$T/p3c.out" $PORT
    wait_answer $PORT z.test && ok "P3: a plain root-owned log file with one link is accepted" || bad "P3: a plain log file was refused" "$(cat "$T/p3c.out")"
    stop_karidns $KPID
else
    echo "  [SKIP] needs root"
fi

echo "== P4 at reload: names are not resolved in the sandbox; a reload that names root neither crashes the server nor changes its identity"
if [ $IS_ROOT = 1 ]; then
    PORT=$((BASEPORT + 3))
    cat > "$T/rl.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER };
zone "z.test" { type primary; file "$T/z.zone"; };
EOF
    start_karidns "$T/rl.conf" "$T/rl.out" $PORT
    if wait_answer $PORT z.test; then
        RN=$(printf '%s\n' $ROOTNAMES | tail -1)
        cat > "$T/rl.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; user "$RN"; };
zone "z.test" { type primary; file "$T/z.zone"; };
EOF
        kill -HUP $KPID
        sleep 2
        wait_answer $PORT z.test 3 && ok "P4: after a reload with user \"$RN\" the server still answers (the Backend, in capability mode, does not look names up)" || bad "P4: the server stopped answering after the reload" "$(tail -5 "$T/rl.out")"
        kill -0 $KPID 2>/dev/null && ok "P4: the manager is still running after the reload" || bad "P4: the manager exited"
    else bad "P4: karidns did not start (reload test)" "$(tail -5 "$T/rl.out")"; fi
    stop_karidns $KPID
else
    echo "  [SKIP] needs root"
fi

echo "== S-1: a program zone's plugin gets an empty environment"
if [ $IS_ROOT = 1 ]; then
    PORT=$((BASEPORT + 2))
    mkdir "$T/pout"; chown nobody "$T/pout"
    cat > "$T/plug.sh" <<EOF
#!/bin/sh
env > "$T/pout/env"
exec sleep 30
EOF
    chmod 755 "$T/plug.sh"
    cat > "$T/prog.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER allow-program-zones yes; };
zone "prog.test" { type program; program "$T/plug.sh"; program-user "nobody"; program-args { }; };
zone "z.test" { type primary; file "$T/z.zone"; };
EOF
    export KC_CANARY=leaked
    start_karidns "$T/prog.conf" "$T/s1.out" $PORT
    unset KC_CANARY
    i=0; while [ ! -s "$T/pout/env" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    if [ -f "$T/pout/env" ]; then
        if grep -q KC_CANARY "$T/pout/env"; then bad "S-1: the plugin inherited the server's environment" "$(cat "$T/pout/env")"
        else ok "S-1: the plugin's environment is empty of the server's variables"; fi
    else bad "S-1: the plugin did not start" "$(cat "$T/s1.out")"; fi
    stop_karidns $KPID
    pkill -u nobody -f "sleep 30" 2>/dev/null
else
    echo "  [SKIP] needs root"
fi

echo "== I5 / I2: a TXT with 60 strings, and the size limit of a secondary"
PP=$((BASEPORT + 10)); SP=$((BASEPORT + 11)); LP=$((BASEPORT + 12))
{
    printf '$ORIGIN txt.test.\n$TTL 300\n@ SOA ns1 host 5 3600 600 86400 300\n@ NS ns1\nns1 A 192.0.2.1\nlong TXT'
    i=0; while [ $i -lt 60 ]; do printf ' "str%02d"' $i; i=$((i + 1)); done
    printf '\n'
    i=0; while [ $i -lt 30 ]; do printf 'h%02d A 192.0.2.%d\n' $i $((i + 10)); i=$((i + 1)); done
} > "$T/txt.zone"
./karicheck zone txt.test "$T/txt.zone" > "$T/kz.out" 2>&1 && ok "karicheck zone: the 60-string TXT is accepted" || bad "karicheck zone refused the zone" "$(cat "$T/kz.out")"
cat > "$T/pri.conf" <<EOF
options { port $PP; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER };
zone "txt.test" { type primary; file "$T/txt.zone"; allow-transfer { 127.0.0.1; }; };
EOF
cat > "$T/sec.conf" <<EOF
options { port $SP; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER };
zone "txt.test" { type secondary; masters { 127.0.0.1 port $PP; }; };
EOF
cat > "$T/lim.conf" <<EOF
options { port $LP; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER };
zone "txt.test" { type secondary; masters { 127.0.0.1 port $PP; }; max-zone-records 10; };
EOF
start_karidns "$T/pri.conf" "$T/pri.out" $PP
if wait_answer $PP txt.test; then
    count_strings() {   # count_strings PORT -> number of character-strings of long.txt.test TXT
        ./dag @127.0.0.1 -p "$1" long.txt.test TXT +short +nohexdump 2>/dev/null | tr -cd '"' | wc -c | awk '{ print $1 / 2 }'
    }
    N=$(count_strings $PP)
    [ "$N" = "60" ] && ok "I5: the primary serves all 60 strings" || bad "I5: the primary serves $N strings" "$(./dag @127.0.0.1 -p $PP long.txt.test TXT +short +nohexdump 2>&1)"
    start_karidns "$T/sec.conf" "$T/sec.out" $SP
    start_karidns "$T/lim.conf" "$T/lim.out" $LP
    if wait_answer $SP txt.test 30; then
        N=$(count_strings $SP)
        [ "$N" = "60" ] && ok "I5: a secondary took the zone by AXFR and serves all 60 strings" || bad "I5: the secondary serves $N strings" "$(cat "$T/sec.out" | tail -5)"
    else bad "I5: the secondary did not take the zone (a TXT with more than 48 strings used to refuse the transfer)" "$(tail -8 "$T/sec.out")"; fi
    sleep 1
    if ./dag @127.0.0.1 -p $LP txt.test SOA +short +nohexdump 2>/dev/null | grep -q .; then bad "I2: a secondary with max-zone-records 10 took a zone of 36 records"
    else ok "I2: a secondary with max-zone-records 10 did not take a zone of 36 records"; fi
else
    bad "the primary did not start" "$(tail -8 "$T/pri.out")"
fi

echo "== I5 through the database path (karidns-dbloader, SQLite3)"
if [ $IS_ROOT = 1 ] && [ -x ./karidns-dbloader ] && [ -x ./tests/db/zone2sql ] && command -v sqlite3 >/dev/null 2>&1 &&
   ./karidns-dbloader --drivers | grep -qx sqlite3; then
    DP=$((BASEPORT + 20))
    mkdir "$T/db"
    {
        printf '$ORIGIN db.test.\n$TTL 300\n@ SOA ns1 host 5 3600 600 86400 300\n@ NS ns1\nns1 A 192.0.2.1\nlong TXT'
        i=0; while [ $i -lt 60 ]; do printf ' "str%02d"' $i; i=$((i + 1)); done
        printf '\n'
    } > "$T/db.zone"
    sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    ./tests/db/zone2sql --dialect sqlite3 "$T/db.zone" 2>/dev/null | sqlite3 "$T/db/z.db"
    chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
    cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"
    cat > "$T/dbs.conf" <<EOF
options {
    port $DP; bind-address { 127.0.0.1; }; pid-file "none"; $RUN_USER
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; };
};
EOF
    start_karidns "$T/dbs.conf" "$T/dbs.out" $DP
    if wait_answer $DP db.test 30; then
        N=$(./dag @127.0.0.1 -p $DP long.db.test TXT +short +nohexdump 2>/dev/null | tr -cd '"' | wc -c | awk '{ print $1 / 2 }')
        [ "$N" = "60" ] && ok "I5: a zone from the database serves its 60-string TXT" || bad "I5: the database zone serves $N strings" "$(tail -8 "$T/dbs.out")"
    else bad "I5: the database zone is not served (a TXT with more than 48 strings used to refuse the zone)" "$(tail -8 "$T/dbs.out")"; fi
    stop_karidns $KPID
else
    echo "  [SKIP] needs root, karidns-dbloader (SQLite3), zone2sql and sqlite3"
fi

echo
echo "== run_security_review_test: $PASS passed, $FAILS failed"
[ $FAILS -eq 0 ]
