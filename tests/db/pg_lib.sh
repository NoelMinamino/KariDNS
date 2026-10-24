# tests/db/pg_lib.sh - shared by the PostgreSQL tests of the DB loader (milestone B10): sourced, not run.
#
#   . "$ROOT/tests/db/pg_lib.sh"; pg_setup NAME     # returns 1 and prints "SKIP: reason" when no PostgreSQL can be used
#
# pg_setup creates the database karidns_test_NAME_<pid> (dropped by pg_cleanup, which the test calls from its trap) and sets
#   PGC       the conninfo of that database for psql ("dbname=..."), plus KARIDNS_TEST_PG if set
#   PG_AS     the unprivileged user psql runs as when the test runs as root (empty otherwise)
#   PGDB      the database name
#   pq SQL    one statement through psql (-At, ON_ERROR_STOP); pf FILE  a SQL file
#   pg_conninfo_file PATH   a conninfo file for karidns-dbloader (owner PG_AS or us, mode 0600) for the database
# KARIDNS_TEST_PG is the conninfo of a maintenance database the role may create databases from (default: the local UNIX socket,
# database "postgres").  KARIDNS_TEST_PG_USER names the user that runs psql when the test runs as root (else SUDO_USER, the
# owner of the source tree, postgres, pgsql: the first that can connect over the UNIX socket).  No test needs sudo.

PGOPTIONS="-c client_min_messages=warning"      # no NOTICE lines from IF NOT EXISTS / DROP IF EXISTS in the DDL
export PGOPTIONS
PG_AS=""
PG_TRIED=""
PGDB=""
PGMAINT=${KARIDNS_TEST_PG:-postgres}

# psql, as PG_AS when set: the arguments travel in the environment so that nothing has to be quoted for su
psql() {
    if [ -z "$PG_AS" ]; then command psql "$@"; return $?; fi
    cmd="exec psql"
    i=0
    for a in "$@"; do
        i=$((i + 1))
        export "PSQLA$i=$a"
        cmd="$cmd \"\$PSQLA$i\""
    done
    su -m "$PG_AS" -c "$cmd"
}

pg_pick_user() {
    [ "$(id -u)" = "0" ] || return 0
    owner=$(stat -f %Su "$ROOT" 2>/dev/null || stat -c %U "$ROOT" 2>/dev/null)
    for u in "${KARIDNS_TEST_PG_USER:-}" "${SUDO_USER:-}" "$owner" postgres pgsql; do
        [ -n "$u" ] && [ "$u" != root ] && id "$u" >/dev/null 2>&1 || continue
        PG_AS=$u
        PG_TRIED="$PG_TRIED $u"
        if psql -X -q -At -d "$PGMAINT" -c "SELECT 1" >/dev/null 2>&1; then
            [ -n "${T:-}" ] && chmod 755 "$T"            # psql -f reads files of the temporary directory
            return 0
        fi
    done
    PG_AS=""
    return 0
}

pg_setup() {
    PGNAME=$1
    if ! command -v psql >/dev/null 2>&1; then echo "SKIP: psql is not installed"; return 1; fi
    if ! pg_isready -q 2>/dev/null && [ -z "${KARIDNS_TEST_PG:-}" ]; then
        echo "SKIP: no PostgreSQL server is reachable on the default socket (set KARIDNS_TEST_PG to a conninfo to test one)"
        return 1
    fi
    pg_pick_user
    if ! psql -X -q -At -d "$PGMAINT" -c "SELECT 1" >/dev/null 2>&1; then
        if [ "$(id -u)" = "0" ] && [ -z "$PG_AS" ]; then
            echo "SKIP: running as root and no unprivileged user could connect to PostgreSQL (tried:${PG_TRIED:- none}; set KARIDNS_TEST_PG_USER)"
        else
            echo "SKIP: cannot connect to PostgreSQL (database '$PGMAINT')"
        fi
        return 1
    fi
    v=$(psql -X -q -At -d "$PGMAINT" -c "SHOW server_version_num" 2>/dev/null)
    if [ -z "$v" ] || [ "$v" -lt 130000 ]; then echo "SKIP: PostgreSQL 13 or newer is needed (server_version_num=${v:-?})"; return 1; fi
    PGDB="karidns_test_${PGNAME}_$$"
    if ! psql -X -q -d "$PGMAINT" -c "CREATE DATABASE $PGDB" >/dev/null 2>&1; then
        echo "SKIP: the PostgreSQL role may not create databases"
        PGDB=""
        return 1
    fi
    if [ -n "${KARIDNS_TEST_PG:-}" ]; then PGC="$KARIDNS_TEST_PG dbname=$PGDB"; else PGC="dbname=$PGDB"; fi
    [ -n "$PG_AS" ] && echo "  (psql and the loader run as user $PG_AS)"
    # PGLOADER: the loader as PG_AS runs it (the user may not be able to reach the source tree, and as root a copy is not ours)
    PGLOADER=${LOADER:-}
    if [ -n "$PG_AS" ] && [ -n "${LOADER:-}" ] && [ -n "${T:-}" ]; then
        cp "$LOADER" "$T/karidns-dbloader.pg" && chmod 755 "$T/karidns-dbloader.pg" && PGLOADER=$T/karidns-dbloader.pg
    fi
    return 0
}

# run a command as PG_AS when the test runs as root: the loader refuses a conninfo-file it does not own, and the PostgreSQL role
# belongs to that user (UNIX socket peer authentication)
as_pg() {
    if [ -z "$PG_AS" ]; then "$@"; return $?; fi
    cmd="exec"
    i=0
    for a in "$@"; do
        i=$((i + 1))
        export "PSQLA$i=$a"
        cmd="$cmd \"\$PSQLA$i\""
    done
    su -m "$PG_AS" -c "$cmd"
}

pq() { psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -c "$1"; }
pf() { psql -X -q -At -v ON_ERROR_STOP=1 "$PGC" -f "$1"; }

# a conninfo file for the loader: the same connection as psql uses; owned by PG_AS (the user the loader runs as) or by us
pg_conninfo_file() {
    printf '%s\n' "$PGC" > "$1"
    [ -n "$PG_AS" ] && chown "$PG_AS" "$1"
    chmod 600 "$1"
}

pg_cleanup() {
    if [ -n "$PGDB" ]; then
        psql -X -q -d "$PGMAINT" -c "DROP DATABASE IF EXISTS $PGDB WITH (FORCE)" >/dev/null 2>&1
        PGDB=""
    fi
}
