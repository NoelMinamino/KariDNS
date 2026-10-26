#!/bin/sh
# run_karicheck_db_loader_output_test.sh - what `karicheck db` makes of the way karidns-dbloader --check ends and of what it prints.
#
# tests/run_karicheck_db_test.sh runs the real loader on real databases.  Here the loader is a shell script that answers
# --drivers and, for --check, writes exactly what a case needs, so that every way a loader can misbehave is seen by karicheck:
# a line longer than CHK_LINE_MAX (skipped, reported), a line that is not part of the protocol (text, a NUL byte, a bad
# escape: one warning that names the first), a last line without its line feed, no final "R" line, the exit statuses 4 (busy),
# 127 (cannot be executed) and others, death by a signal, and a clean run.  Each case checks the findings karicheck prints
# and its exit status (0: no error, 1: errors).
#
# Run as root (the loader then runs as the user in SUDO_USER, or nobody) and as a normal user.  SKIP (exit 0, with the reason)
# when karicheck is not built.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

KC=${KC:-$ROOT/karicheck}
[ -x "$KC" ] || { echo "SKIP: karicheck is not built"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karicheck_dbout.XXXXXX") || exit 1
chmod 755 "$T"
trap 'rm -rf "$T"' EXIT INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -14 | sed 's/^/         /'; }

ME=$(id -un)
if [ "$(id -u)" = "0" ]; then
    LUSER=${KARIDNS_TEST_LOADER_USER:-${SUDO_USER:-nobody}}
    id "$LUSER" >/dev/null 2>&1 || { echo "SKIP: no user '$LUSER' to drop to"; exit 0; }
    [ "$LUSER" = root ] && { echo "SKIP: no unprivileged user to drop to (set KARIDNS_TEST_LOADER_USER)"; exit 0; }
    chown "$LUSER" "$T"
else
    LUSER=$ME
fi
echo "== karicheck db with a loader that misbehaves, run as $ME"

printf 'options {\n  user "%s";\n  database { driver sqlite3; database-file "%s/none.db"; loader-user "%s"; loader-path "%s/fake"; };\n};\n' \
    "$ME" "$T" "$LUSER" "$T" > "$T/k.conf"

# case NAME EXPECTED-STATUS "loader commands for --check" PATTERN...: the patterns must all be in the output
case_run() {
    name=$1; want=$2; body=$3; shift 3
    {
        printf '#!/bin/sh\ncase "$1" in --drivers) echo sqlite3; exit 0;; esac\n%s\n' "$body"
    } > "$T/fake"
    chmod 755 "$T/fake"
    [ "$(id -u)" = "0" ] && chown 0:0 "$T/fake"
    out=$("$KC" db "$T/k.conf" 2>&1); st=$?
    if [ "$st" != "$want" ]; then bad "$name: exit status $st, wanted $want" "$out"; return; fi
    for pat in "$@"; do
        if ! printf '%s\n' "$out" | grep -q -- "$pat"; then bad "$name: no \"$pat\" in the output" "$out"; return; fi
    done
    ok "$name"
}

case_run "clean run" 0 \
    "printf 'Z\tok.test.\t1\tprimary\t*\n'; printf 'R\t1\t0\t0\n'" \
    "1 zone(s) read, 0 error(s), 0 warning(s)" "is valid"

case_run "findings are printed with their zone and records.id" 1 \
    "printf 'E\tok.test.\t1\trecords.id 5: broken\n'; printf 'W\t\t0\twatch out\n'; printf 'R\t1\t1\t1\n'; exit 1" \
    "records.id 5: broken" "watch out" "1 error(s)" "has errors"

case_run "a last line without its line feed is still read" 0 \
    "printf 'R\t0\t0\t0'" \
    "0 zone(s) read, 0 error(s), 0 warning(s)"

case_run "a line longer than the protocol allows is skipped and reported" 1 \
    "printf 'E\t\t0\t'; head -c 300000 /dev/zero | tr '\\000' x; printf '\n'; printf 'R\t0\t0\t0\n'" \
    "wrote a line longer than 262144 bytes; it was skipped"

case_run "text that is not part of the protocol is one warning naming the first line" 0 \
    "echo 'hello from the loader'; echo 'second'; printf 'R\t0\t0\t0\n'" \
    "2 line(s) that are not part of its protocol (first: hello from the loader)"

case_run "a NUL byte inside a line is not a protocol line" 0 \
    "printf 'E\t\t0\ta\000b\n'; printf 'R\t0\t0\t0\n'" \
    "line(s) that are not part of its protocol"

case_run "a bad escape inside a field is not a protocol line" 0 \
    "printf 'E\t\t0\tabc\\\\q\n'; printf 'R\t0\t0\t0\n'" \
    "line(s) that are not part of its protocol"

case_run "no final line, status 0" 1 \
    "printf 'Z\tok.test.\t1\tprimary\t*\n'; exit 0" \
    "the loader ended without its final line"

case_run "status 4: busy or unreachable" 1 \
    "echo 'database is locked'; exit 4" \
    "found the database busy or unreachable (try again): database is locked"

case_run "status 3 with the reason it printed" 1 \
    "echo 'boom: cannot open the database'; exit 3" \
    "the loader could not check the database: boom: cannot open the database"

case_run "status 127: cannot be executed" 1 \
    "exit 127" \
    "the loader could not be executed"

case_run "killed by a signal" 1 \
    "kill -9 \$\$" \
    "the loader was killed by a signal"

echo
echo "== $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
