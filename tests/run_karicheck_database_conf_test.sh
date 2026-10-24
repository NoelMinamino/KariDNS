#!/bin/sh
# run_karicheck_database_conf_test.sh - karicheck conf: the checks of options { database { } } that need no database
# connection (beta design 7.2, milestone B4a): driver compiled into the loader (karidns-dbloader --drivers), loader-user /
# loader-group exist, loader-path root-owned and not group/world writable, SQLite file exists / WAL / not world-readable,
# conninfo-file mode and owner, PostgreSQL-only options with sqlite3, UTF-8 paths.
#
# The "everything is fine" case needs a root-owned loader, so it runs only as root; the error cases run for everybody.
# SKIP when karicheck, karidns-dbloader (with the SQLite3 driver) or the sqlite3 CLI is missing.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
KC=./karicheck
LOADER=./karidns-dbloader
if [ ! -x "$KC" ] || [ ! -x "$LOADER" ]; then echo "SKIP: karicheck or karidns-dbloader is not built"; exit 0; fi
if ! command -v sqlite3 >/dev/null 2>&1; then echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; fi
if ! "$LOADER" --drivers | grep -qx sqlite3; then echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; fi

T=$(mktemp -d "${TMPDIR:-/tmp}/karicheck_dbconf.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT INT TERM
FAILS=0
ok() { echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

# the loader the way karidns wants it: a root-owned copy, not group/world writable (root can make one)
cp "$LOADER" "$T/dbl" && chmod 755 "$T/dbl"
if [ "$(id -u)" = "0" ]; then chown 0:0 "$T/dbl"; fi
sqlite3 "$T/wal.db" "PRAGMA journal_mode=WAL; CREATE TABLE t (a INT);" > /dev/null
sqlite3 "$T/del.db" "PRAGMA journal_mode=DELETE; CREATE TABLE t (a INT);" > /dev/null
chmod 600 "$T/wal.db" "$T/del.db"
printf 'not a database, just text, at least a few bytes long....................................\n' > "$T/junk.db"
USER_OK=$(id -un)

conf() {   # conf FILE DBBLOCKBODY
    printf 'options {\n  user "%s";\n  database { %s };\n};\nzone "z.test" { type primary; file "%s/z.zone"; };\n' "$USER_OK" "$2" "$T" > "$1"
}
printf '$TTL 60\n@ SOA ns host 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n' > "$T/z.zone"
run() { "$KC" conf "$1" 2>&1; }   # output; the exit status is in $?
expect() {   # expect DESC CONF PATTERN [STATUS]
    out=$(run "$2"); st=$?
    want=${4:-1}
    if printf '%s\n' "$out" | grep -q -- "$3" && [ "$st" -eq "$want" ]; then ok "$1"
    else bad "$1 (exit $st, want $want; pattern: $3)" "$out"; fi
}

echo "== valid configuration"
conf "$T/ok.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\"; poll-interval 2;"
if [ "$(id -u)" = "0" ]; then
    out=$(run "$T/ok.conf"); st=$?
    if [ $st -eq 0 ] && ! printf '%s\n' "$out" | grep -q "ERROR"; then ok "a correct database block passes (root-owned loader, WAL file)"
    else bad "a correct database block was refused (exit $st)" "$out"; fi
else
    echo "  [SKIP] the passing case needs a root-owned loader (run as root)"
fi

echo "== loader"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-path \"$T/nope\";"
expect "missing loader-path" "$T/c.conf" "database loader '$T/nope': No such file"
cp "$T/dbl" "$T/dbl_gw" && chmod 775 "$T/dbl_gw"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl_gw\";"
expect "group-writable loader" "$T/c.conf" "writable by group or others"
printf '#!/bin/sh\necho nothing\n' > "$T/notdbl"; chmod 755 "$T/notdbl"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-path \"$T/notdbl\";"
expect "a program that is not the loader" "$T/c.conf" "driver sqlite3 is not available in this installation\|did not answer --drivers"
printf 'x' > "$T/ci"; chmod 600 "$T/ci"
# a loader that has only the SQLite3 driver (the real one may have both since B10)
printf '#!/bin/sh\necho sqlite3\n' > "$T/dbl_sq"; chmod 755 "$T/dbl_sq"
if [ "$(id -u)" = "0" ]; then chown 0:0 "$T/dbl_sq"; fi
conf "$T/c.conf" "driver postgresql; conninfo-file \"$T/ci\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl_sq\";"
expect "driver the loader does not have" "$T/c.conf" "driver postgresql is not available in this installation"

echo "== users and groups"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"no-such-user-b4a\"; loader-path \"$T/dbl\";"
expect "unknown loader-user" "$T/c.conf" "loader-user 'no-such-user-b4a' does not exist"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-group \"no-such-group-b4a\"; loader-path \"$T/dbl\";"
expect "unknown loader-group" "$T/c.conf" "loader-group 'no-such-group-b4a' does not exist"

echo "== SQLite file"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/missing.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\";"
expect "missing database file" "$T/c.conf" "missing.db': No such file"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/del.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\";"
expect "journal mode DELETE is refused" "$T/c.conf" "not in WAL mode"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/junk.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\";"
expect "not an SQLite database" "$T/c.conf" "is not an SQLite3 database"
cp "$T/wal.db" "$T/open.db" && chmod 644 "$T/open.db"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/open.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\";"
out=$(run "$T/c.conf")
if printf '%s\n' "$out" | grep -q "readable by everyone"; then ok "a world-readable database file is warned about"; else bad "no warning for a world-readable file" "$out"; fi
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\"; server-id \"ns1\";"
out=$(run "$T/c.conf")
if printf '%s\n' "$out" | grep -q "server-id is for driver postgresql"; then ok "server-id with sqlite3 is warned about"; else bad "no warning for server-id with sqlite3" "$out"; fi
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\";"
printf 'view "v" { match-clients { 10.0.0.0/8; }; database-file "%s/del.db"; zone "v.test" { type primary; file "%s/z.zone"; }; };\n' "$T" "$T" > "$T/v.part"
sed -e '/^zone /d' "$T/c.conf" > "$T/cv.conf"; cat "$T/v.part" >> "$T/cv.conf"
expect "the database file of a view is checked as well" "$T/cv.conf" "view 'v': database file .*not in WAL mode"

echo "== conninfo-file (postgresql options; the loader lacks the driver, which is reported too)"
chmod 644 "$T/ci"
conf "$T/c.conf" "driver postgresql; conninfo-file \"$T/ci\"; loader-user \"$USER_OK\"; loader-path \"$T/dbl\";"
expect "conninfo-file mode 0644" "$T/c.conf" "has mode 0644; it must be 0600 or 0400"
chmod 600 "$T/ci"
printf 'host=db.example.test dbname=pdns\n' > "$T/ci"
out=$(run "$T/c.conf")
if printf '%s\n' "$out" | grep -q "neither a UNIX socket host nor sslmode=verify-full"; then ok "a conninfo without a UNIX socket or verify-full is warned about"; else bad "no conninfo warning" "$out"; fi
# B10: which connection strings reach the server over a UNIX socket (no warning) or over TCP without verify-full (warning)
ci_warns() {   # ci_warns DESCRIPTION CONNINFO WANT(yes|no)
    printf '%s\n' "$2" > "$T/ci"; chmod 600 "$T/ci"
    out=$(run "$T/c.conf")
    if printf '%s\n' "$out" | grep -q "neither a UNIX socket host nor sslmode=verify-full"; then got=yes; else got=no; fi
    if [ "$got" = "$3" ]; then ok "conninfo $1: warning $got"; else bad "conninfo $1: warning $got, wanted $3" "$out"; fi
}
ci_warns "host=/var/run/postgresql (UNIX socket)" "host=/var/run/postgresql dbname=pdns" no
ci_warns "no host at all (libpq's default is the UNIX socket)" "dbname=pdns user=karidns_loader" no
ci_warns "host='/tmp' in quotes" "host='/tmp' dbname=pdns" no
ci_warns "a host name with sslmode=verify-full" "host=db.example.test dbname=pdns sslmode=verify-full" no
ci_warns "a host name with sslmode=require" "host=db.example.test dbname=pdns sslmode=require" yes
ci_warns "hostaddr only (TCP)" "hostaddr=192.0.2.5 dbname=pdns" yes
ci_warns "host= inside the value of another option is not a host (no host: the UNIX socket)" "dbname=pdns options=-chost=db.example.test" no
ci_warns "a comment line, then a socket host" "$(printf '# host=db.example.test\nhost=/tmp dbname=pdns')" no
ci_warns "URI with a host name" "postgresql://karidns@db.example.test/pdns" yes
ci_warns "URI without a host (socket)" "postgresql:///pdns" no
ci_warns "URI with host=/tmp in the query" "postgresql:///pdns?host=/tmp" no
ci_warns "URI with %2F host" "postgresql://%2Fvar%2Frun%2Fpostgresql/pdns" no

echo "== syntax"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/wal.db\"; poll-interval 99;"
expect "poll-interval out of range" "$T/c.conf" "Syntax error"
conf "$T/c.conf" "driver sqlite3; database-file \"$T/w$(printf '\200')al.db\";"
expect "invalid UTF-8 in a path" "$T/c.conf" "Syntax error"

echo "== the views that take DB zones (the CONFIG message of the loader link lists at most 1024)"
views_conf() {   # views_conf FILE NVIEWS NONE_FROM: views from NONE_FROM on are "database none;"
    printf 'options {\n  user "%s";\n  database { driver sqlite3; database-file "%s"; loader-user "%s"; loader-path "%s"; };\n};\n' "$USER_OK" "$T/wal.db" "$USER_OK" "$T/dbl" > "$1"
    awk -v n="$2" -v none="$3" 'BEGIN { for (i = 1; i <= n; i++) { printf "view \"v%d\" { match-clients { 192.0.2.%d; }; ", i, i % 250 + 1; if (i >= none) printf "database none; "; printf "};\n" } }' >> "$1"
}
views_conf "$T/v1025.conf" 1025 100000
expect "1025 views with a database block" "$T/v1025.conf" "1025 views take DB zones, at most 1024"
views_conf "$T/v1024.conf" 1024 100000
out=$(run "$T/v1024.conf")
if printf '%s\n' "$out" | grep -q "views take DB zones"; then bad "1024 views that take DB zones were refused" "$out"; else ok "1024 views that take DB zones pass the view limit"; fi
views_conf "$T/vnone.conf" 1100 1025
out=$(run "$T/vnone.conf")
if printf '%s\n' "$out" | grep -q "views take DB zones"; then bad "1100 views of which 76 are \"database none;\" were refused" "$out"; else ok "views marked \"database none;\" are not counted"; fi

if [ "$FAILS" -eq 0 ]; then echo "=== run_karicheck_database_conf_test: all checks passed ==="; exit 0; fi
echo "=== run_karicheck_database_conf_test: $FAILS check(s) FAILED ==="
exit 1
