#!/bin/sh
# run_db_loader_log_test.sh - the messages of karidns-dbloader reach the `database` log category (batch 14).
#
# The supervisor gives the loader a pipe as stderr (karidns-dbloader -s 3 --fetch-fd 4 --log-stderr), reads it line by line and logs
# every line with kdns_logc(LOGC_DATABASE, ...).  Checked here with `logging { category database { file channel; }; }`:
#   A  the real loader: a message of the loader (a zone with SOA serial 0) is in the file, as "database: warning: [DB] zone ...", exactly
#      once (not also on the server's stderr / syslog copy), and the loader keeps no copy in syslog
#   B  a loader that writes garbage (a flood, a 100 KB line, NUL and escape bytes, a line without newline at the end): the file has at most
#      about DB_LOG_RATE_LINES lines per second plus a report of the dropped ones, no line longer than the limit, no raw control byte, the
#      escaped forms of the bytes, the unterminated line after the loader was stopped; the server answers meanwhile and stops on SIGTERM
#   C  a restart makes a new pipe: no descriptor of the manager is left behind after several restarts; the messages of the restarted loader arrive
#   D  --log-stderr without -s is a usage error; --dump keeps writing to stderr without the "[DB]" prefix
#
# Needs root (the server starts as root and drops to nobody, the loader must be root-owned).  SKIP otherwise, and when karidns, dag,
# karidns-dbloader (SQLite3 driver), zone2sql or the sqlite3 CLI is missing.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
for b in ./karidns ./dag ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbloader_log.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    i=0; while [ -n "$SRV" ] && [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
DAG="./dag @127.0.0.1 -p $PORT"
LOGD="$T/logs"; mkdir "$LOGD"; chmod 777 "$LOGD"
DBLOG="$LOGD/database.log"

# ---------------------------------------------------------------- fixtures
mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
./tests/db/zone2sql --dialect sqlite3 tests/zones/example.com.zone 2>/dev/null | sqlite3 "$T/db/z.db"
sqlite3 "$T/db/z.db" "INSERT INTO domains(name, type) VALUES('zero.test', 'NATIVE');
 INSERT INTO records(domain_id, name, type, content, ttl, disabled) SELECT id, 'zero.test', 'SOA', 'ns.zero.test. host.zero.test. 0 3600 600 86400 300', 3600, 0 FROM domains WHERE name = 'zero.test';
 INSERT INTO records(domain_id, name, type, content, ttl, disabled) SELECT id, 'zero.test', 'NS', 'ns.zero.test.', 3600, 0 FROM domains WHERE name = 'zero.test';
 INSERT INTO records(domain_id, name, type, content, ttl, disabled) SELECT id, 'ns.zero.test', 'A', '192.0.2.1', 3600, 0 FROM domains WHERE name = 'zero.test';"
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
printf '$TTL 300\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n' > "$T/file.zone"

conf() {   # conf FILE LOADERPATH
    cat > "$1" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$2"; };
};
logging {
    channel dbfile { file "$DBLOG" versions unlimited size 50m; severity info; print-category yes; print-severity yes; };
    category database { dbfile; };
};
zone "file.test" { type primary; file "$T/file.zone"; };
EOF
}
file_answers() { [ "$($DAG file.test SOA +short +nohexdump 2>/dev/null | head -1)" = "ns.file.test. host.file.test. 1 2 3 4 5" ]; }
stop_srv() {
    kill -TERM "$SRV"
    i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$SRV" 2>/dev/null; then fail "karidns did not stop within 10 s"; kill -KILL "$SRV"; fi
    SRV=""
    sleep 0.3
}

# ================================================================ A: the real loader
echo "== A: a message of the real loader"
conf "$T/a.conf" "$T/karidns-dbloader"
./karidns -c "$T/a.conf" -f > "$T/a.log" 2>&1 &
SRV=$!
if kari_wait_log "$DBLOG" "the SOA serial is 0" 15; then pass "the loader's warning is in the database log file"; else fail "no loader message in $DBLOG"; sed 's/^/         /' "$DBLOG" "$T/a.log" 2>/dev/null | tail -20; fi
grep -q "database: warning: \[DB\] zone 'zero.test.'" "$DBLOG" && pass "the line is 'database: warning: [DB] zone ...' (category, severity from the <N> priority, [DB] prefix)" || { fail "format of the loader line"; grep "SOA serial" "$DBLOG"; }
N=$(grep -c "the SOA serial is 0" "$DBLOG")
[ "$N" -eq 1 ] && pass "logged once" || fail "logged $N times"
grep -q "the SOA serial is 0" "$T/a.log" && fail "the message is also on the server's own stderr / syslog copy" || pass "no second copy through syslog"
grep -q "karidns-dbloader\[" "$T/a.log" && fail "the loader wrote to syslog itself" || pass "the loader did not use syslog"
grep -q "database: info: \[DB\] loader connected" "$DBLOG" && pass "the Backend's own [DB] messages go to the same category" || fail "no Backend [DB] line in the file"
file_answers && pass "the file zone answers" || fail "the file zone does not answer"
stop_srv

# ================================================================ B: a loader that writes garbage
echo "== B: hostile output of the loader"
cat > "$T/garbage.sh" <<'EOF'
#!/bin/sh
printf '<3>[DB] before the flood\n' >&2
i=0
while [ $i -lt 3000 ]; do echo "<6>[DB] flood line $i" >&2; i=$((i + 1)); done
sleep 2.5
head -c 100000 /dev/zero | tr '\0' 'Z' >&2
echo >&2
printf '<4>[DB] bytes: a\000b\033[31mred\r\ttab\200\n' >&2
printf '<4>[DB] CRLF line\r\n' >&2
printf '<4>[DB] unterminated' >&2
exec sleep 60
EOF
chown 0:0 "$T/garbage.sh"; chmod 755 "$T/garbage.sh"
: > "$DBLOG"; chmod 666 "$DBLOG"
conf "$T/b.conf" "$T/garbage.sh"
T0=$(date +%s)
./karidns -c "$T/b.conf" -f > "$T/b.log" 2>&1 &
SRV=$!
kari_wait_log "$DBLOG" "before the flood" 15 && pass "the first line arrived" || fail "no first line"
sleep 4
file_answers && pass "the server answers while the loader floods" || fail "the file zone does not answer"
T1=$(date +%s)
FL=$(grep -c "flood line" "$DBLOG")
MAXFL=$(( (T1 - T0 + 1) * 50 + 50 ))
[ "$FL" -ge 1 ] && [ "$FL" -le "$MAXFL" ] && pass "$FL of 3000 flood lines logged in $((T1 - T0)) s (at most $MAXFL)" || fail "flood lines logged: $FL (limit $MAXFL)"
grep -q "line(s) of the loader's output were not logged (more than 50 per second)" "$DBLOG" && pass "the dropped lines were reported" || fail "no report of dropped lines"
LONGEST=$(awk '{ if (length($0) > m) m = length($0) } END { print m + 0 }' "$DBLOG")
[ "$LONGEST" -le 700 ] && pass "the longest line of the file is $LONGEST bytes (the 100 KB line was cut)" || fail "a line of $LONGEST bytes"
grep -q "ZZZZZZZZ\.\.\.\$" "$DBLOG" && pass "the cut line is marked with ..." || fail "no cut Z line"
ESC=$(printf '\033')
grep -q "$ESC" "$DBLOG" && fail "a raw ESC byte reached the file" || pass "no raw escape byte in the file"
grep -q 'bytes: a\\x00b\\x1b\[31mred\\x0d tab\\x80' "$DBLOG" && pass "NUL, ESC, CR, high byte are written as \\xNN, a tab as a space" || { fail "escaped form"; grep "bytes:" "$DBLOG" | cat -v | head -3; }
grep -q "warning: \[DB\] CRLF line\$" "$DBLOG" && pass "CRLF ends a line without a stray CR" || fail "CRLF line"
grep -q "unterminated" "$DBLOG" && fail "the unterminated line came before the end of the stream" || pass "a line without newline waits for the end of the stream"
stop_srv
kari_wait_log "$DBLOG" "warning: \[DB\] unterminated\$" 5 && pass "the line without newline is logged when the loader is gone" || { fail "the unterminated line was lost"; tail -3 "$DBLOG"; }

# ================================================================ C: restarts, no descriptor left
echo "== C: restarts"
cat > "$T/short.sh" <<'EOF'
#!/bin/sh
echo "<5>[DB] short-lived loader $$ says hello" >&2
sleep 0.2
exit 1
EOF
chown 0:0 "$T/short.sh"; chmod 755 "$T/short.sh"
: > "$DBLOG"
conf "$T/c.conf" "$T/short.sh"
./karidns -c "$T/c.conf" -f > "$T/c.log" 2>&1 &
SRV=$!
kari_wait_log "$DBLOG" "short-lived loader" 30 4 && pass "the messages of four starts arrived (restart backoff 1, 2, 4 s)" || { fail "fewer than four starts logged"; grep -c "short-lived" "$DBLOG"; }
MGR_FDS=$(procstat -f "$SRV" 2>/dev/null | awk '$3 ~ /^[0-9]+$/' | wc -l | tr -d ' ')
[ "$MGR_FDS" -le 12 ] && pass "the manager holds $MGR_FDS descriptors after four restarts" || { fail "the manager holds $MGR_FDS descriptors"; procstat -f "$SRV" | head -30; }
PIPES=$(procstat -f "$SRV" 2>/dev/null | awk '$4 == "p"' | wc -l | tr -d ' ')
[ "$PIPES" -le 1 ] && pass "at most one pipe (the one of the running loader) is open in the manager" || fail "$PIPES pipes open in the manager"
file_answers && pass "the file zone answers between restarts" || fail "the file zone does not answer"
stop_srv

# ================================================================ D: the loader on its own
echo "== D: standalone"
OUT=$(./karidns-dbloader --log-stderr --driver sqlite3 --database-file "$T/db/z.db" --dump - 2>&1 >/dev/null); RC=$?
[ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q -- "--log-stderr is for -s" && pass "--log-stderr without -s is a usage error" || fail "--log-stderr without -s: rc $RC: $OUT"
OUT=$(./karidns-dbloader --dump - --driver sqlite3 --database-file "$T/nonexistent.db" 2>&1 >/dev/null); RC=$?
[ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q "^karidns-dbloader: " && ! printf '%s' "$OUT" | grep -q '\[DB\]' && pass "--dump writes to stderr as before, without [DB]" || fail "dump messages: rc $RC: $OUT"

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_db_loader_log_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_db_loader_log_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
