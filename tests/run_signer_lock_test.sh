#!/bin/sh
# run_signer_lock_test.sh - the single-instance lock of karidns-signer on SQLite3 (0.7, K-2; signer/lib/db_sqlite.js acquireFileLock).
#
# The lock is <db>.signer.lock, a SQLite file held in SQLite's exclusive locking mode; what holds it is the kernel (fcntl(2) byte-range locks), not a pid.
#   L1  the holder's lock is a POSIX lock in the kernel (F_GETLK from another process names the holder's pid on SQLite's lock bytes), a second process is
#       refused with the holder's pid in the message, and after kill -9 of the holder the kernel shows no lock and the next process takes it;
#   L2  50 rounds of 4 processes started at the same instant: in every round exactly one takes the lock (it holds it 2 s, longer than the 1 s a loser
#       waits), and the times that winners hold it never overlap;
#   L3  a 0.6.x lock file (a pid as text) naming a live process that is not a signer (pid 1) does not block the start: it becomes the lock file;
#   L4  a read-only directory: the lock file cannot be made, and the message says so (as root this part runs as the user nobody, or is SKIPped).
# Runs as any user.  SKIP (exit 0) without node 22.13 or newer, or perl's Fcntl F_GETLK.  About three minutes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

NODE=${NODE:-node}
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
perl -MFcntl=F_GETLK,F_WRLCK -e 1 2>/dev/null || { echo "SKIP: perl with Fcntl F_GETLK is needed"; exit 0; }
NODE=$(command -v "$NODE")

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_signer_lock.XXXXXX") || exit 1
chmod 755 "$T"
PIDS=""
cleanup() { for p in $PIDS; do kill -9 "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }
pass() { echo "PASS: $*"; }

# The program of one process: node lock.mjs FILE hold          -> "locked" and holds until killed, or "refused <message>" and exit 3
#                                           FILE race T0 MS     -> waits for the time T0 (ms), tries; "won <pid> <t0> <t1>" after holding MS ms, or "lost <message>"
# (copies of the two modules, which import only node: built-ins, so that the user nobody of L4 can read them whatever the modes of the tree)
mkdir -p "$T/lib"
cp signer/lib/db_sqlite.js node/lib/sqlite.js "$T/lib/"
chmod 755 "$T/lib"; chmod 644 "$T/lib/"*.js
cat > "$T/lock.mjs" <<EOF
import { acquireFileLock } from '$T/lib/db_sqlite.js';
import { loadSqlite } from '$T/lib/sqlite.js';
const sqlite = await loadSqlite();
const [file, mode, t0, ms] = process.argv.slice(2);
if (mode === 'race') { while (Date.now() < Number(t0)) { /* the same instant for all */ } }
let release;
try { release = acquireFileLock(file, { sqlite }); } catch (e) { console.log((mode === 'race' ? 'lost ' : 'refused ') + e.message); process.exit(3); }
if (mode === 'race') {
  const a = Date.now();
  setTimeout(() => { const b = Date.now(); release(); console.log('won ' + process.pid + ' ' + a + ' ' + b); }, Number(ms));
} else {
  console.log('locked');
  setInterval(() => {}, 1000);
}
EOF
# F_GETLK for a write lock over SQLite's lock bytes (PENDING_BYTE 0x40000000 and the 512 octets after it, sqlite3 os_unix.c): the pid of the
# process holding a lock that conflicts, or 0.  struct flock on FreeBSD: l_start, l_len (off_t), l_pid (pid_t), l_type, l_whence (short), l_sysid (int).
getlk() {
    perl -MFcntl=F_GETLK,F_WRLCK,F_UNLCK,SEEK_SET -e '
        open(my $fh, "+<", $ARGV[0]) or die "open: $!";
        my $fl = pack("q q l s s l", 0x40000000, 512, 0, F_WRLCK, SEEK_SET, 0);
        fcntl($fh, F_GETLK, $fl) or die "F_GETLK: $!";
        my ($s, $l, $pid, $type) = unpack("q q l s", $fl);
        print $type == F_UNLCK ? 0 : $pid, "\n";' "$1"
}
wait_line() {   # FILE: wait up to 10 s for a line
    _i=0
    while [ ! -s "$1" ] && [ $_i -lt 100 ]; do sleep 0.1; _i=$((_i + 1)); done
    head -1 "$1"
}

echo "-- L1: a kernel lock, refused while held, gone after kill -9"
F="$T/l1.sqlite3.signer.lock"
"$NODE" "$T/lock.mjs" "$F" hold > "$T/h1.out" 2>/dev/null &
H1=$!
PIDS="$PIDS $H1"
[ "$(wait_line "$T/h1.out")" = "locked" ] || fail "L1: the first process did not take the lock: $(cat "$T/h1.out")"
G=$(getlk "$F")
if [ "$G" = "$H1" ]; then pass "L1: F_GETLK names the holder (pid $H1) on SQLite's lock bytes after its commit"; else fail "L1: F_GETLK says '$G', expected the holder $H1"; fi
head -c 16 "$F" | grep -q "SQLite format 3" && pass "L1: the lock file is a SQLite file" || fail "L1: the lock file is not a SQLite file"
MSG=$("$NODE" "$T/lock.mjs" "$F" hold 2>/dev/null)
RC=$?
echo "   second: $MSG"
case "$MSG" in
    "refused another karidns-signer (pid $H1) works on this database: $F is locked") [ $RC = 3 ] && pass "L1: a second process is refused, the message names the holder" || fail "L1: exit status $RC" ;;
    *) fail "L1: the second process: $MSG" ;;
esac
kill -9 "$H1"
wait "$H1" 2>/dev/null
G=$(getlk "$F")
[ "$G" = "0" ] && pass "L1: after kill -9 of the holder the kernel shows no lock" || fail "L1: after kill -9 F_GETLK says '$G'"
"$NODE" "$T/lock.mjs" "$F" hold > "$T/h2.out" 2>/dev/null &
H2=$!
PIDS="$PIDS $H2"
[ "$(wait_line "$T/h2.out")" = "locked" ] && pass "L1: the next process takes the lock (no stale state)" || fail "L1: after kill -9: $(cat "$T/h2.out")"
kill -9 "$H2"; wait "$H2" 2>/dev/null

echo "-- L2: 50 rounds of 4 processes started at the same instant"
F="$T/l2.sqlite3.signer.lock"
ROUNDS=50
BAD=0
: > "$T/won.all"
r=1
while [ $r -le $ROUNDS ]; do
    T0=$(( $("$NODE" -e 'console.log(Date.now())') + 700 ))
    RP=""
    for k in 1 2 3 4; do
        "$NODE" "$T/lock.mjs" "$F" race "$T0" 2000 > "$T/r$k.out" 2>/dev/null &
        RP="$RP $!"
    done
    for p in $RP; do wait "$p"; done
    W=$(cat "$T"/r[1-4].out | grep -c '^won ')
    cat "$T"/r[1-4].out | grep '^won ' >> "$T/won.all"
    if [ "$W" != 1 ]; then BAD=$((BAD + 1)); echo "   round $r: $W winners"; cat "$T"/r[1-4].out | sed 's/^/     /'; fi
    r=$((r + 1))
done
# no two winners ever held it at the same time (sorted by start, each starts after the previous one ended)
OVER=$(sort -k3,3n "$T/won.all" | awk 'NR > 1 && $3 < end { n++ } { end = $4 } END { print n + 0 }')
N=$(wc -l < "$T/won.all" | tr -d ' ')
[ "$BAD" = 0 ] && pass "L2: $ROUNDS rounds, exactly one winner in each ($N winners)" || fail "L2: $BAD of $ROUNDS rounds did not have exactly one winner"
[ "$OVER" = 0 ] && pass "L2: no two winners held the lock at the same time" || fail "L2: $OVER overlapping holds"

echo "-- L3: a 0.6.x lock file with a live foreign pid"
F="$T/l3.sqlite3.signer.lock"
printf '1\n' > "$F"
"$NODE" "$T/lock.mjs" "$F" hold > "$T/h3.out" 2>/dev/null &
H3=$!
PIDS="$PIDS $H3"
[ "$(wait_line "$T/h3.out")" = "locked" ] && pass "L3: the start is not blocked by a 0.6.x file naming pid 1" || fail "L3: $(cat "$T/h3.out")"
head -c 16 "$F" | grep -q "SQLite format 3" && pass "L3: the old file became the lock file" || fail "L3: the old file is not a SQLite file now"
[ "$(getlk "$F")" = "$H3" ] && pass "L3: and it is locked by the holder" || fail "L3: F_GETLK does not name the holder"
kill -9 "$H3"; wait "$H3" 2>/dev/null

echo "-- L4: a read-only directory"
RO="$T/ro"
mkdir "$RO"
chmod 555 "$RO"
if [ "$(id -u)" = 0 ]; then
    if id nobody > /dev/null 2>&1 && su -m nobody -c "test -r '$T/lock.mjs' && test -x '$NODE'" 2>/dev/null; then
        MSG=$(su -m nobody -c "'$NODE' '$T/lock.mjs' '$RO/x.sqlite3.signer.lock' hold" 2>/dev/null)
    else
        MSG="SKIP"
    fi
else
    MSG=$("$NODE" "$T/lock.mjs" "$RO/x.sqlite3.signer.lock" hold 2>/dev/null)
fi
echo "   $MSG"
case "$MSG" in
    SKIP) echo "SKIP: L4 (root, and there is no user nobody that can run $NODE and read $T)" ;;
    "refused cannot take the lock file $RO/x.sqlite3.signer.lock: "*"write access to the directory of the database)") pass "L4: refused with a message that names the file and what is needed" ;;
    *) fail "L4: $MSG" ;;
esac
chmod 755 "$RO"

if [ $FAIL = 0 ]; then echo "=== run_signer_lock_test: all checks passed ==="; exit 0; fi
echo "=== run_signer_lock_test: FAILED ==="
exit 1
