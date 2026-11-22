/*
 * dns_db_pgsql.c - PostgreSQL driver of karidns-dbloader (beta design 2.2, 3.1, 6; milestone B10).  Compiled only when
 * "postgresql" is listed in DB_DRIVERS (-DKARIDNS_DB_POSTGRESQL); karidns itself never links libpq.  The interface and its
 * contract are dns_db_driver.h; the queries are the ones of dns_db_sqlite3.c (the reader above the driver is shared, so
 * two drivers give the same stream for the same rows).
 *
 * Opening (design 2.2, 7.2):
 *   - the libpq connection string is the content of `conninfo-file`.  The file must be a regular file owned by the user
 *     the loader runs as, mode 0600 or 0400; anything else is refused before it is read (the string may hold a password).
 *     Its content is never logged or put in an error message.  Parse errors are reported without libpq's text, which
 *     can echo a fragment of the string.
 *   - session settings are set right after the connection: read only (default_transaction_read_only), the client
 *     encoding SQL_ASCII (bytes are passed through unchanged, exactly like the SQLite3 driver), application_name
 *     karidns-dbloader, statement / lock / idle-in-transaction timeouts, cursor_tuple_fraction 1 (a bulk scan is read to
 *     the end), and search_path = the schema of the view (database-schema) when there is one.
 *
 * Reading:
 *   - a snapshot is BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; every scan is a cursor (DECLARE ... FETCH FORWARD n),
 *     so a result set is never buffered whole (n rows at a time) and a scan that the callback stops is closed cleanly
 *     without reading the rest.  Every PQresultStatus is checked.
 *   - names are never compared with SQL collations by the callers (the only SQL comparison is the apex SOA join; the
 *     reader checks the owner in C again).  ORDER BY on a text column uses COLLATE "C" so the order is the one of SQLite3.
 *   - strings are zero copy from PQgetvalue(); a NULL pointer is SQL NULL.  PostgreSQL cannot store a NUL in text; the
 *     length is still compared with strlen().
 *
 * Errors: a lost connection and the transient SQLSTATEs (class 08 connection exception, 40 transaction rollback, 53
 * insufficient resources, 55P03 lock not available, 57 operator intervention incl. statement timeout and administrator
 * shutdown) are DB_ERR_RETRY; the loader backs off and tries again with a new connection.
 *
 * Change log (the one place where PostgreSQL differs from SQLite3; design 3.7, 6, advance decision of B10):
 *   karidns_changes.seq is taken when the statement ends, but rows become visible when their transaction commits, in
 *   another order: a transaction that took seq 5 may commit after one that took seq 6.  A reader that remembered "seq 6"
 *   would never see seq 5.  So every row carries the xid8 of its transaction (karidns_changes.xid, schema version 2),
 *   and the cursor this driver hands to the loader is NOT a seq but the xmin of the reading snapshot
 *   (pg_snapshot_xmin(pg_current_snapshot())): every transaction below it has finished and its rows are visible in the
 *   snapshot, so they are final.  changes_max() returns that cursor; changes_since(after) lists the rows with xid >= after
 *   (those of finished transactions that were not read before, and those of transactions that were still running when the
 *   cursor was taken, which are read again: the diff that follows is idempotent) and returns the new cursor in *last_seq.
 *   Rows of a transaction that is still open are never skipped, whatever the order of the seq values.  A cursor is only
 *   compared by the loader (<, >, ==), never added to; the dbstatus "seq" of a PostgreSQL view is this cursor.
 *   A database whose karidns_changes has no xid column (schema version 1) is served without a change log (has_changes
 *   false: the zones are compared by serial; apply db/karidns_ext_v1_to_v2.pgsql.sql).
 *   Pruning (design 3.7): the log keeps the newest 1,000,000 rows.  A gap is reported when the log has rows but none below
 *   the cursor (the rows the loader has already seen are gone) and the first seq is not 1.
 *
 * Auto reload (design 6): `LISTEN karidns_changes` on the persistent connection; wait_fd() is its socket, poll_version()
 * drains the notifications and returns a counter that changes when one arrived (it also pings the server now and then,
 * so a dead connection is noticed).
 *
 * Multi-server operation (B11, release plan 4.8; db/karidns_ext.pgsql.sql): a connection that called watch_requests() LISTENs
 * `karidns_reload` instead, requests_max() / reload_requests() read karidns_reload_requests (generation > the last applied,
 * each call its own statement, never inside a snapshot), and report_status() upserts the row of this server in
 * karidns_server_status in its own BEGIN READ WRITE ... COMMIT.  The session stays default_transaction_read_only = on; only that
 * explicit transaction writes, and the role needs INSERT and UPDATE on that one table (db/karidns_loader_role.pgsql.sql).
 * Generations are made visible in order by the advisory lock of the INSERT trigger, so a position kept as a generation number
 * never skips a request (unlike karidns_changes.seq, which needs the xmin cursor above).
 *
 * Writing (M2, the 0.6.0 ZoneImporter; the loader never does this): open_write() is the same open with a session that may write
 * (default_transaction_read_only = off, application_name karidns-zone, lock_timeout = busy_timeout_ms).  w_begin() is BEGIN READ WRITE
 * followed by a transaction-level advisory lock on the zone name, so two importers of one zone (also of one that does not exist yet) run
 * one after the other and the second gives up with DB_ERR_RETRY after lock_timeout; the reads of the zone (find_zone, scan_*) work inside
 * the transaction and see its own writes.  Every write statement is prepared once per session and takes its values as parameters.
 */

#ifdef KARIDNS_DB_POSTGRESQL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libpq-fe.h>

#include "dns_db_driver.h"

#define PG_FETCH_ROWS 1000          /* rows per FETCH: the most a scan holds at a time */
#define PG_CONNINFO_MAX 8192
#define PG_PING_SECONDS 15

struct db_conn {
    PGconn *pg;
    char err[DB_ERRLEN];
    bool in_snapshot;
    bool listening;
    uint64_t nver;                  /* poll_version(): number of notifications seen */
    time_t last_ping;
    bool has_changes, has_domain_views, has_profiles, has_ext, has_tagdef_id;
    bool has_reload_requests, has_server_status;    /* B11 */
    bool chan_reload;               /* B11: LISTEN karidns_reload (watch_requests) instead of karidns_changes */
    bool listen_failed;             /* LISTEN was refused (a standby): wait_fd() stays -1, the caller polls by timer */
    int soa_cover_idx;              /* records (domain_id) INCLUDE (name, content) WHERE type = 'SOA' ...: 0 unknown, 1 yes, -1 no */
    bool writable;                  /* M2: opened with open_write() (the session is not default_transaction_read_only) */
    bool in_wtxn;                   /* M2: w_begin() is open (in_snapshot is set too, so the reads of the zone work inside it) */
    uint32_t w_prepared;            /* M2: bit i = the statement W_STMT[i] is prepared on this session */
    bool audit_summary;             /* open_write(): every write transaction starts with SET LOCAL karidns.audit = 'summary' (w_set_audit) */
    bool repeatable;                /* open_write(): every write transaction is REPEATABLE READ (w_set_snapshot: the signer) */
    bool has_zone_state, has_versions;      /* items D and E (open_write() connections only): karidns_zone_state; karidns_zone_versions and karidns_zone_version_rrsets */
    uint32_t r_prepared;            /* 0.7 WP3: bit i = the read statement RS_* is prepared on this session */
    db_mgroup_t mg;                 /* manifest_page: the row being assembled */
    bool have_actor;                /* w_set_actor(): every write transaction starts with SET LOCAL karidns.principal / karidns.change_set */
    char actor_pid[24], actor_cs[80];
};
static bool pg_has_soa_cover_index(db_conn_t *c);

/* ------------------------------------------------------------------------------------------------------------- */
/* errors                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

static void set_err(db_conn_t *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_err(db_conn_t *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, sizeof(c->err), fmt, ap);
    va_end(ap);
}

/* the first line of a libpq message, without the trailing newline */
static void first_line(const char *m, char *out, size_t cap) {
    if (!m) m = "";
    size_t n = strcspn(m, "\r\n");
    if (n >= cap) n = cap - 1;
    memcpy(out, m, n);
    out[n] = '\0';
}

static bool sqlstate_transient(const char *s) {
    if (!s) return false;
    return strncmp(s, "08", 2) == 0 || strncmp(s, "40", 2) == 0 || strncmp(s, "53", 2) == 0 || strcmp(s, "55P03") == 0 ||
           strncmp(s, "57", 2) == 0;
}

/* error of a failed libpq call: DB_ERR_RETRY for a lost connection and the transient SQLSTATEs, else -1 */
static int pq_fail(db_conn_t *c, PGresult *r, const char *what) {
    char line[260];
    first_line(r ? PQresultErrorMessage(r) : PQerrorMessage(c->pg), line, sizeof(line));
    if (!line[0]) first_line(PQerrorMessage(c->pg), line, sizeof(line));
    const char *state = r ? PQresultErrorField(r, PG_DIAG_SQLSTATE) : NULL;
    if (state && strcmp(state, "40001") == 0 && PQstatus(c->pg) == CONNECTION_OK) {         /* a concurrent change under a REPEATABLE READ snapshot */
        set_err(c, "postgresql %s: %s (changed concurrently)", what, line);
        return DB_ERR_CONFLICT;
    }
    bool retry = PQstatus(c->pg) != CONNECTION_OK || sqlstate_transient(state);
    set_err(c, "postgresql %s: %s%s", what, line, retry ? " (retry later)" : "");
    return retry ? DB_ERR_RETRY : -1;
}

/* run one statement that returns no rows */
static int exec_cmd(db_conn_t *c, const char *sql, const char *what) {
    PGresult *r = PQexec(c->pg, sql);
    if (!r || PQresultStatus(r) != PGRES_COMMAND_OK) {
        int ret = pq_fail(c, r, what);
        PQclear(r);
        return ret;
    }
    PQclear(r);
    return 0;
}

/* run one statement that returns rows; *out is the result (caller clears) */
static int exec_rows(db_conn_t *c, const char *sql, int np, const char *const *pv, PGresult **out, const char *what) {
    PGresult *r = np ? PQexecParams(c->pg, sql, np, NULL, pv, NULL, NULL, 0) : PQexec(c->pg, sql);
    if (!r || PQresultStatus(r) != PGRES_TUPLES_OK) {
        int ret = pq_fail(c, r, what);
        PQclear(r);
        return ret;
    }
    *out = r;
    return 0;
}

static void ignore_notice(void *arg, const PGresult *res) {
    (void)arg;
    (void)res;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* cells                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

/* A text cell as a C string (NULL for SQL NULL).  *bad is set when it has an embedded NUL; c->err then names the
 * table, the row id and the column. */
static const char *cell_text(db_conn_t *c, PGresult *r, int row, int col, const char *table, int64_t id, const char *name,
                             bool *bad) {
    if (PQgetisnull(r, row, col)) return NULL;
    const char *t = PQgetvalue(r, row, col);
    if ((size_t)PQgetlength(r, row, col) != strlen(t)) {
        set_err(c, "table %s id %lld: column %s contains a NUL byte", table, (long long)id, name);
        *bad = true;
        return NULL;
    }
    return t;
}

/* An integer cell (0 for SQL NULL).  Review (the PostgreSQL sibling of D-7): the cell was read as far as it looked like a number (strtoll() without an end check), so a
 * column of another type than the PowerDNS schema's (a TEXT '2abc', a NUMERIC '1.5') gave 2 or 1, and a value out of range the limit.  The whole cell must be a decimal
 * integer now (PostgreSQL writes an integer column so: an optional '-', digits), in range; else *bad is set and c->err names the column of the result.  The text itself is
 * not quoted: it is data of the database.  cell_u64(): the same for a value that cannot be negative (an xid8, a counter, a seq). */
static void cell_int_text(db_conn_t *c, PGresult *r, int row, int col, bool sign, bool *bad, int64_t *s, uint64_t *u) {
    *s = 0;
    *u = 0;
    if (PQgetisnull(r, row, col)) return;
    const char *t = PQgetvalue(r, row, col);
    const char *d = sign && t[0] == '-' ? t + 1 : t;
    char *end = NULL;
    errno = 0;
    if (*d >= '0' && *d <= '9') {
        if (sign) *s = strtoll(t, &end, 10);
        else *u = strtoull(t, &end, 10);
    }
    if (!end || *end != '\0' || errno == ERANGE || (size_t)PQgetlength(r, row, col) != (size_t)(end - t)) {
        const char *n = PQfname(r, col);
        set_err(c, "column %s of the result: the value is not %s integer in range", n ? n : "?", sign ? "an" : "a non-negative");
        *bad = true;
        *s = 0;
        *u = 0;
    }
}
static int64_t cell_i64(db_conn_t *c, PGresult *r, int row, int col, bool *bad) {
    int64_t s;
    uint64_t u;
    cell_int_text(c, r, row, col, true, bad, &s, &u);
    return s;
}
static uint64_t cell_u64(db_conn_t *c, PGresult *r, int row, int col, bool *bad) {
    int64_t s;
    uint64_t u;
    cell_int_text(c, r, row, col, false, bad, &s, &u);
    return u;
}
static bool cell_true(PGresult *r, int row, int col) { return !PQgetisnull(r, row, col) && PQgetvalue(r, row, col)[0] == 't'; }

/* ------------------------------------------------------------------------------------------------------------- */
/* open / close                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

/* the content of conninfo-file into buf (NUL terminated, comment lines and line ends turned into blanks); 0 or -1 with err */
static int read_conninfo(const char *path, char *buf, size_t cap, char *err, size_t errlen) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errlen, "postgresql: cannot open conninfo-file: %s", strerror(errno));
        return -1;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        snprintf(err, errlen, "postgresql: conninfo-file is not a regular file");
        close(fd);
        return -1;
    }
    if (sb.st_uid != geteuid()) {
        snprintf(err, errlen, "postgresql: conninfo-file is not owned by the user the loader runs as (uid %lu)", (unsigned long)geteuid());
        close(fd);
        return -1;
    }
    if ((sb.st_mode & 07777) != 0600 && (sb.st_mode & 07777) != 0400) {
        snprintf(err, errlen, "postgresql: conninfo-file must have mode 0600 or 0400 (it may hold a password); it has %04o",
                 (unsigned)(sb.st_mode & 07777));
        close(fd);
        return -1;
    }
    if (sb.st_size <= 0 || sb.st_size >= (off_t)cap) {
        snprintf(err, errlen, "postgresql: conninfo-file is empty or larger than %zu bytes", cap - 1);
        close(fd);
        return -1;
    }
    size_t n = 0;
    while (n < (size_t)sb.st_size) {
        ssize_t k = read(fd, buf + n, (size_t)sb.st_size - n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        n += (size_t)k;
    }
    close(fd);
    if (n < (size_t)sb.st_size) {            /* a read error or a file that got shorter: half a connection string is not used */
        snprintf(err, errlen, "postgresql: cannot read conninfo-file completely");
        return -1;
    }
    buf[n] = '\0';
    if (strlen(buf) != n) {
        snprintf(err, errlen, "postgresql: conninfo-file contains a NUL byte");
        return -1;
    }
    /* '#' starts a comment line; line ends separate keyword=value pairs like blanks */
    size_t o = 0;
    bool bol = true, skip = false;
    for (size_t i = 0; i < n; i++) {
        char ch = buf[i];
        if (ch == '\n' || ch == '\r') {
            bol = true;
            skip = false;
            buf[o++] = ' ';
            continue;
        }
        if (bol && ch == '#') skip = true;
        if (ch != ' ' && ch != '\t') bol = false;
        if (!skip) buf[o++] = ch;
    }
    while (o > 0 && (buf[o - 1] == ' ' || buf[o - 1] == '\t')) o--;
    buf[o] = '\0';
    if (o == 0) {
        snprintf(err, errlen, "postgresql: conninfo-file holds no connection string");
        return -1;
    }
    return 0;
}

static void wipe(void *p, size_t n) {
    volatile char *v = p;
    while (n--) *v++ = 0;
}

/* write: the ZoneImporter's connection (open_write()): the session may write, and waits lock_timeout = busy_timeout_ms (0: 10 s) for the zone
 * lock.  The loader's open() is write == false: read only, exactly the session settings it always had. */
static int pg_open_mode(db_conn_t **out, const db_source_t *src, char *err, size_t errlen, bool write) {
    *out = NULL;
    if (!src || !src->conninfo_file || !*src->conninfo_file) {
        snprintf(err, errlen, "postgresql: no conninfo-file given");
        return -1;
    }
    char conninfo[PG_CONNINFO_MAX];
    if (read_conninfo(src->conninfo_file, conninfo, sizeof(conninfo), err, errlen) != 0) {
        wipe(conninfo, sizeof(conninfo));       /* (a NUL byte or a file of comments only: the buffer may hold the rest of a password) */
        return -1;
    }
    char *perr = NULL;
    PQconninfoOption *opts = PQconninfoParse(conninfo, &perr);
    if (!opts) {
        /* libpq's text can echo a part of the string; the string may hold a password */
        snprintf(err, errlen, "postgresql: the connection string in conninfo-file is not valid");
        if (perr) PQfreemem(perr);
        wipe(conninfo, sizeof(conninfo));
        return -1;
    }
    PQconninfoFree(opts);
    db_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        snprintf(err, errlen, "postgresql: out of memory");
        wipe(conninfo, sizeof(conninfo));
        return -1;
    }
    /* our defaults first: a keyword in the user's string (the dbname value is expanded as a connection string and its
     * keywords win) replaces them */
    const char *kw[] = { "application_name", "connect_timeout", "keepalives_idle", "keepalives_interval", "keepalives_count", "dbname", NULL };
    const char *vl[] = { write ? "karidns-zone" : "karidns-dbloader", "10", "60", "10", "3", conninfo, NULL };
    c->pg = PQconnectdbParams(kw, vl, 1);
    wipe(conninfo, sizeof(conninfo));
    if (!c->pg) {
        snprintf(err, errlen, "postgresql: out of memory");
        free(c);
        return -1;
    }
    if (PQstatus(c->pg) != CONNECTION_OK) {
        char line[260];
        first_line(PQerrorMessage(c->pg), line, sizeof(line));
        snprintf(err, errlen, "postgresql: cannot connect: %s (retry later)", line);
        PQfinish(c->pg);
        free(c);
        return DB_ERR_RETRY;
    }
    PQsetNoticeReceiver(c->pg, ignore_notice, NULL);
    PGresult *pr = PQexec(c->pg, "SET client_encoding TO 'SQL_ASCII'");     /* bytes unchanged, like SQLite3 */
    bool ok = pr && PQresultStatus(pr) == PGRES_COMMAND_OK;
    PQclear(pr);
    if (ok) {
        char setup[400];
        snprintf(setup, sizeof(setup),
                 "SET default_transaction_read_only = %s; SET application_name = '%s'; SET statement_timeout = '900s'; SET lock_timeout = '%ums'; "
                 "SET idle_in_transaction_session_timeout = '1h'; SET cursor_tuple_fraction = 1; SET standard_conforming_strings = on",
                 write ? "off" : "on", write ? "karidns-zone" : "karidns-dbloader",
                 write && src->busy_timeout_ms ? src->busy_timeout_ms : 10000u);
        pr = PQexec(c->pg, setup);
        ok = pr && PQresultStatus(pr) == PGRES_COMMAND_OK;
        PQclear(pr);
    }
    c->writable = write;
    int ret = ok ? 0 : pq_fail(c, NULL, "session setup");
    if (ret == 0 && src->schema && *src->schema) {
        char *q = PQescapeIdentifier(c->pg, src->schema, strlen(src->schema));
        if (!q) {
            set_err(c, "postgresql: cannot quote the schema name");
            ret = -1;
        } else {
            char sql[400];
            int n = snprintf(sql, sizeof(sql), "SET search_path TO %s", q);
            PQfreemem(q);
            if (n < 0 || (size_t)n >= sizeof(sql)) {
                set_err(c, "postgresql: the schema name is too long");
                ret = -1;
            } else {
                ret = exec_cmd(c, sql, "SET search_path");
            }
        }
    }
    if (ret != 0) {
        snprintf(err, errlen, "%s", c->err);
        PQfinish(c->pg);
        free(c);
        return ret;
    }
    c->last_ping = time(NULL);
    *out = c;
    return 0;
}

static int pg_open(db_conn_t **out, const db_source_t *src, char *err, size_t errlen) {
    return pg_open_mode(out, src, err, errlen, false);
}

static int pg_open_write(db_conn_t **out, const db_source_t *src, char *err, size_t errlen) {
    return pg_open_mode(out, src, err, errlen, true);
}

static void pg_close(db_conn_t *c) {
    if (!c) return;
    PQfinish(c->pg);
    free(c);
}

static const char *pg_errmsg(db_conn_t *c) { return c->err; }

/* ------------------------------------------------------------------------------------------------------------- */
/* schema                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

#define SCHEMA_MAX_COLS 12
static const struct { const char *table; const char *cols[SCHEMA_MAX_COLS]; int required; } k_tables[] = {
    /* PowerDNS 5.1 columns the loader reads (design 3.1) */
    { "domains", { "id", "name", "type", "master", "catalog", NULL }, 5 },
    { "records", { "domain_id", "id", "name", "type", "content", "ttl", "prio", "disabled", "ordername", NULL }, 9 },
    { "domainmetadata", { "domain_id", "id", "kind", "content", NULL }, 4 },
    { "cryptokeys", { "domain_id", NULL }, 1 },
    /* karidns_* (design 3.7); the last column of the zone tagdefs (id, schema version 2) is optional */
    { "karidns_changes", { "seq", "domain_id", "xid", NULL }, 3 },
    { "karidns_domain_views", { "domain_id", "view_name", NULL }, 2 },
    { "karidns_profiles", { "name", "settings", NULL }, 2 },
    { "karidns_record_tags", { "record_id", "location_tag", "ecs_tag", NULL }, 3 },
    { "karidns_record_tinydns", { "record_id", "ttd", "loc", "countdown", NULL }, 4 },
    { "karidns_zone_tagdefs", { "domain_id", "kind", "tag", "cidr", "id", NULL }, 4 },
    { "karidns_schema_version", { "version", NULL }, 1 },
    /* B11, optional (the multi-server tables) */
    { "karidns_reload_requests", { "generation", "zone", "force", NULL }, 3 },
    { "karidns_server_status", { "server_id", "generation", "applied_at", "ok", "failed_zones", NULL }, 5 },
};
#define N_TABLES (sizeof(k_tables) / sizeof(k_tables[0]))
enum { T_DOMAINS, T_RECORDS, T_META, T_KEYS, T_CHANGES, T_DV, T_PROF, T_TAGS, T_TDNS, T_TAGDEFS, T_VERSION, T_REQ, T_STATUS };
/* the columns of the PowerDNS tables (the schema the user brings) that the loader reads as integers (cell_i64()), bit k = cols[k]: domains.id; records.domain_id, id, ttl, prio;
 * domainmetadata.domain_id, id; cryptokeys.domain_id.  The karidns_* tables are made by db/karidns_ext.pgsql.sql. */
static const unsigned k_int_cols[T_KEYS + 1] = { 0x1u, 0x63u, 0x3u, 0x1u };

/* Which of k_tables exist in the search_path (exists[]) and which of their columns (found[], bit k = cols[k]); *schema_ok = the search_path
 * names at least one existing schema (a SET search_path to a missing schema is not an error in PostgreSQL).  One catalog query (to_regclass
 * follows search_path; no privilege on the tables is needed).  notint (NULL: not asked): the columns of k_int_cols whose type is not smallint, integer or bigint. */
static int schema_scan(db_conn_t *c, bool exists[N_TABLES], unsigned found[N_TABLES], bool *schema_ok, unsigned *notint) {
    PGresult *r = NULL;
    memset(found, 0, sizeof(unsigned) * N_TABLES);
    memset(exists, 0, sizeof(bool) * N_TABLES);
    if (notint) memset(notint, 0, sizeof(unsigned) * N_TABLES);
    int ret = exec_rows(c, "SELECT current_schemas(false)::text", 0, NULL, &r, "schema lookup");
    if (ret != 0) return ret;
    const char *path = PQgetvalue(r, 0, 0);
    *schema_ok = path && strcmp(path, "{}") != 0;
    PQclear(r);
    if (!*schema_ok) return 0;
    char sql[1400];
    size_t o = (size_t)snprintf(sql, sizeof(sql), "SELECT c.relname, a.attname, a.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype) "
                                                  "FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid "
                                                  "AND a.attnum > 0 AND NOT a.attisdropped WHERE c.oid = ANY (ARRAY[");
    for (size_t t = 0; t < N_TABLES && o < sizeof(sql); t++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sto_regclass('%s')::oid", t ? "," : "", k_tables[t].table);
    if (o < sizeof(sql)) o += (size_t)snprintf(sql + o, sizeof(sql) - o, "])");
    if (o >= sizeof(sql)) {                  /* (the table list is static and fits; this is the guard for the day it grows) */
        set_err(c, "postgresql: the schema query is too long");
        return -1;
    }
    ret = exec_rows(c, sql, 0, NULL, &r, "schema");
    if (ret != 0) return ret;
    for (int i = 0; i < PQntuples(r); i++) {
        const char *rel = PQgetvalue(r, i, 0), *att = PQgetvalue(r, i, 1);
        for (size_t t = 0; t < N_TABLES; t++) {
            if (strcmp(rel, k_tables[t].table) != 0) continue;
            exists[t] = true;
            for (int k = 0; k_tables[t].cols[k]; k++)
                if (strcmp(att, k_tables[t].cols[k]) == 0) {
                    found[t] |= 1u << k;
                    if (notint && t <= T_KEYS && (k_int_cols[t] & (1u << k)) && !cell_true(r, i, 2)) notint[t] |= 1u << k;
                }
        }
    }
    PQclear(r);
    return 0;
}

static int pg_check_schema(db_conn_t *c, db_schema_info_t *out) {
    PGresult *r = NULL;
    unsigned found[N_TABLES];
    bool exists[N_TABLES];
    bool schema_ok = false;
    int ret = schema_scan(c, exists, found, &schema_ok, NULL);
    if (ret != 0) return ret;
    if (!schema_ok) {
        set_err(c, "schema: the database-schema does not exist (or the role has no USAGE on it)");
        return -1;
    }
    for (size_t t = T_DOMAINS; t <= T_KEYS; t++) {
        if (!exists[t]) {
            set_err(c, "schema: table %s is missing (PowerDNS 5.1 schema expected)", k_tables[t].table);
            return -1;
        }
        for (int k = 0; k_tables[t].cols[k]; k++)
            if (!(found[t] & (1u << k))) {
                set_err(c, "schema: table %s has no column %s (PowerDNS 5.1 schema expected)", k_tables[t].table, k_tables[t].cols[k]);
                return -1;
            }
    }
#define HAVE(t) (exists[t] && (found[t] & ((1u << k_tables[t].required) - 1u)) == ((1u << k_tables[t].required) - 1u))
    /* a log without the xid column is the one of schema version 1: no change log (see the top of this file) */
    c->has_changes = HAVE(T_CHANGES);
    c->has_domain_views = HAVE(T_DV);
    c->has_profiles = HAVE(T_PROF);
    c->has_ext = HAVE(T_TAGS) && HAVE(T_TDNS) && HAVE(T_TAGDEFS);
    c->has_tagdef_id = exists[T_TAGDEFS] && (found[T_TAGDEFS] & (1u << 4)) != 0;
    c->has_reload_requests = HAVE(T_REQ);
    c->has_server_status = HAVE(T_STATUS);
    c->soa_cover_idx = pg_has_soa_cover_index(c) ? 1 : -1;
    bool has_version = HAVE(T_VERSION);
#undef HAVE
    if (has_version) {
        /* versions 1 to 3 are read (version 3 adds the schema karidns_auth and the audit log, which the loader never uses); a newer one was
         * written for a later loader */
        ret = exec_rows(c, "SELECT max(version) FROM karidns_schema_version", 0, NULL, &r, "karidns_schema_version");
        if (ret != 0) return ret;
        bool bad = false;
        long long v = cell_i64(c, r, 0, 0, &bad);
        PQclear(r);
        if (bad) return -1;
        if (v > 3) {
            set_err(c, "schema: karidns_schema_version is %lld; this loader reads versions 1 to 3", v);
            return -1;
        }
    }
    /* items D and E: the zone generation and the zone versions.  A connection that writes (karidns-zone) cares, and (0.7 WP3) manifest_page needs karidns_zone_state on a read connection too; they are no tables the loader reads, so they
     * are no entries of k_tables (the loader's privilege check of `karicheck db` would ask for them) */
    c->has_zone_state = c->has_versions = false;
    {
        ret = exec_rows(c, "SELECT to_regclass('karidns_zone_state') IS NOT NULL, to_regclass('karidns_zone_versions') IS NOT NULL AND to_regclass('karidns_zone_version_rrsets') IS NOT NULL",
                        0, NULL, &r, "schema");
        if (ret != 0) return ret;
        c->has_zone_state = cell_true(r, 0, 0);
        c->has_versions = cell_true(r, 0, 1);
        PQclear(r);
    }
    if (out) {
        out->has_changes = c->has_changes;
        out->has_domain_views = c->has_domain_views;
        out->has_profiles = c->has_profiles;
        out->has_ext = c->has_ext;
        out->has_reload_requests = c->has_reload_requests;
        out->has_server_status = c->has_server_status;
        out->has_zone_state = c->has_zone_state;
        out->has_versions = c->has_versions;
    }
    return 0;
}

/* B12: the schema check of `karicheck db` (design 7.2): catalog reads only, nothing is written. */
static void fnd(db_finding_cb cb, void *ud, char level, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void fnd(db_finding_cb cb, void *ud, char level, const char *fmt, ...) {
    char t[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t, sizeof(t), fmt, ap);
    va_end(ap);
    cb(ud, level, t);
}

/* a query that returns one boolean: *out = 1 / 0, or -1 for NULL (the object is not there) */
static int one_bool(db_conn_t *c, const char *sql, int np, const char *const *pv, int *out) {
    PGresult *r = NULL;
    int ret = exec_rows(c, sql, np, pv, &r, "privileges");
    if (ret != 0) return ret;
    *out = PQgetisnull(r, 0, 0) ? -1 : PQgetvalue(r, 0, 0)[0] == 't';
    PQclear(r);
    return 0;
}

static int priv_table(db_conn_t *c, const char *table, const char *priv, int *out) {
    const char *pv[2] = { table, priv };
    return one_bool(c, "SELECT has_table_privilege(to_regclass($1::text)::oid, $2::text)", 2, pv, out);
}

static int priv_column(db_conn_t *c, const char *table, const char *col, int *out) {
    const char *pv[2] = { table, col };
    return one_bool(c, "SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = to_regclass($1::text)::oid AND a.attname::text = $2::text "
                       "AND NOT a.attisdropped) THEN has_column_privilege(to_regclass($1::text)::oid, $2::text, 'SELECT') END", 2, pv, out);
}

static int pg_schema_findings(db_conn_t *c, const db_check_opts_t *o, db_finding_cb cb, void *ud) {
    PGresult *r = NULL;
    unsigned found[N_TABLES], notint[N_TABLES];
    bool exists[N_TABLES], schema_ok = false;
    int ret = schema_scan(c, exists, found, &schema_ok, notint);
    if (ret != 0) return ret;
    if (!schema_ok) {
        fnd(cb, ud, 'E', "the database-schema does not exist (or the role has no USAGE on it)");
        return 0;
    }
    char role[130] = "?";
    if ((ret = exec_rows(c, "SELECT current_user::text", 0, NULL, &r, "current_user")) != 0) return ret;
    snprintf(role, sizeof(role), "%s", PQgetvalue(r, 0, 0));
    PQclear(r);
#define FULL(t) (exists[t] && (found[t] & ((1u << k_tables[t].required) - 1u)) == ((1u << k_tables[t].required) - 1u))
    for (size_t t = T_DOMAINS; t <= T_KEYS; t++) {
        if (!exists[t]) {
            fnd(cb, ud, 'E', "table %s is missing (PowerDNS 5.1 schema expected)", k_tables[t].table);
            continue;
        }
        char miss[200] = "";
        unsigned nm = 0;
        for (int k = 0; k_tables[t].cols[k]; k++)
            if (!(found[t] & (1u << k))) db_list_add(miss, sizeof(miss), &nm, k_tables[t].cols[k]);
        if (nm) fnd(cb, ud, 'E', "table %s has no column %s%s (PowerDNS 5.1 schema expected)", k_tables[t].table, miss, nm > 6 ? ", ..." : "");
        /* (a warning: such a column is read while every value is an integer; a value that is not fails the read, cell_i64(), as a TEXT value does in the SQLite3 driver) */
        miss[0] = '\0';
        nm = 0;
        for (int k = 0; k_tables[t].cols[k]; k++)
            if (notint[t] & (1u << k)) db_list_add(miss, sizeof(miss), &nm, k_tables[t].cols[k]);
        if (nm) fnd(cb, ud, 'W', "table %s: column %s is not of an integer type (PowerDNS 5.1 schema expected); a value that is not an integer is an error", k_tables[t].table, miss);
    }
    /* the karidns_* tables (design 3.7); what a missing one costs */
    static const struct { int t; const char *effect; } k_eff[] = {
        { T_VERSION, "the version of the extension tables is not known" },
        { T_CHANGES, "there is no change log, so an edit that keeps the SOA serial is not noticed by a reload" },
        { T_DV, "the zone to view mapping is not available: every zone goes to every view that uses this schema" },
        { T_PROF, "a zone that names a profile (X-KARIDNS-PROFILE) fails to load" },
        { T_TAGS, "location and ECS tags are ignored (the three tag tables are used together)" },
        { T_TDNS, "tinydns time stamps and locations are ignored (the three tag tables are used together)" },
        { T_TAGDEFS, "tag definitions are ignored (the three tag tables are used together)" },
    };
    unsigned present = 0;
    for (size_t i = 0; i < sizeof(k_eff) / sizeof(k_eff[0]); i++)
        if (exists[k_eff[i].t]) present++;
    if (present == 0) {
        fnd(cb, ud, 'W', "none of the karidns_* extension tables exists (db/karidns_ext.pgsql.sql was not applied): no change log, no zone to view "
                         "mapping, no profiles, no tags; a reload compares the SOA serials");
    } else {
        for (size_t i = 0; i < sizeof(k_eff) / sizeof(k_eff[0]); i++) {
            int t = k_eff[i].t;
            if (FULL(t)) continue;
            if (t == T_CHANGES && exists[t] && (found[t] & 3u) == 3u)
                fnd(cb, ud, 'W', "table karidns_changes has no xid column (schema version 1): there is no change log; apply db/karidns_ext_v1_to_v2.pgsql.sql");
            else
                fnd(cb, ud, 'W', "table %s is missing or incomplete: %s", k_tables[t].table, k_eff[i].effect);
        }
    }
    /* privileges of the role the loader connects as (db/karidns_loader_role.pgsql.sql): SELECT on what it reads, nothing on the keys */
    bool can_sel[N_TABLES];
    memset(can_sel, 0, sizeof(can_sel));
    for (size_t t = 0; t < N_TABLES; t++) {
        if (t == T_KEYS || !FULL(t)) continue;
        int ok = 0;
        if ((ret = priv_table(c, k_tables[t].table, "SELECT", &ok)) != 0) return ret;
        can_sel[t] = ok > 0;
        if (ok == 0)
            fnd(cb, ud, 'E', "the role %s cannot SELECT from table %s (db/karidns_loader_role.pgsql.sql grants what the loader reads)", role, k_tables[t].table);
    }
    if (FULL(T_KEYS)) {
        int ok = 0, content = 0;
        if ((ret = priv_column(c, "cryptokeys", "domain_id", &ok)) != 0) return ret;
        if (ok == 0)
            fnd(cb, ud, 'E', "the role %s cannot SELECT cryptokeys.domain_id: the loader asks which zones have keys (db/karidns_loader_role.pgsql.sql)", role);
        /* cryptokeys.content is not among the columns the loader needs */
        if ((ret = priv_column(c, "cryptokeys", "content", &content)) != 0) return ret;
        if (content > 0)
            fnd(cb, ud, 'W', "the role %s can read cryptokeys.content (the private keys); the loader needs only domain_id (db/karidns_loader_role.pgsql.sql "
                                 "grants just that)", role);
    }
    if (can_sel[T_VERSION]) {
        if ((ret = exec_rows(c, "SELECT max(version) FROM karidns_schema_version", 0, NULL, &r, "karidns_schema_version")) != 0) return ret;
        bool none = PQgetisnull(r, 0, 0), bad = false;
        long long v = cell_i64(c, r, 0, 0, &bad);
        PQclear(r);
        if (bad) fnd(cb, ud, 'E', "karidns_schema_version: %s", c->err);
        else if (none) fnd(cb, ud, 'W', "karidns_schema_version has no row");
        else if (v > 3) fnd(cb, ud, 'E', "karidns_schema_version is %lld; this loader reads versions 1 to 3", v);
        else fnd(cb, ud, 'I', "karidns_* schema version %lld", v);
    }
    /* B11: the multi-server tables (db/karidns_ext.pgsql.sql, release plan 4.8) */
    bool have_req = FULL(T_REQ), have_st = FULL(T_STATUS);
    if (have_req != have_st)
        fnd(cb, ud, 'W', "only one of karidns_reload_requests and karidns_server_status exists: reload requests and the status of the servers need both "
                         "(db/karidns_ext.pgsql.sql)");
    else if (!have_req && o && o->server_id)
        fnd(cb, ud, 'W', "server-id is set but karidns_reload_requests and karidns_server_status do not exist: this server cannot receive reload requests "
                         "or report its status (db/karidns_ext.pgsql.sql)");
    if (have_st) {
        int ins = 0, upd = 0;
        if ((ret = priv_table(c, "karidns_server_status", "INSERT", &ins)) != 0 || (ret = priv_table(c, "karidns_server_status", "UPDATE", &upd)) != 0) return ret;
        if (ins <= 0 || upd <= 0)
            fnd(cb, ud, 'W', "the role %s cannot %s karidns_server_status: the outcome of the reloads is not reported there "
                             "(db/karidns_loader_role.pgsql.sql grants INSERT and UPDATE)", role, ins <= 0 && upd <= 0 ? "INSERT or UPDATE" : (ins <= 0 ? "INSERT into" : "UPDATE"));
    }
    if (o && o->auto_reload) {
        if (!FULL(T_CHANGES)) {
            fnd(cb, ud, 'E', "auto-reload yes needs the change log: table karidns_changes is missing or incomplete (apply db/karidns_ext.pgsql.sql)");
        } else {
            static const struct { const char *infix, *table; } k_trg[] = {
#define X(i, t) { #i, t },
                DB_CHANGE_TRIGGERS(X)
#undef X
            };
            /* the triggers of the tables that are here, by name */
            char sql[1400];
            size_t n = (size_t)snprintf(sql, sizeof(sql), "SELECT t.tgname FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid = ANY (ARRAY[");
            for (size_t i = 0; i < sizeof(k_trg) / sizeof(k_trg[0]) + 1; i++) {
                const char *tbl = i == 0 ? "karidns_changes" : k_trg[i - 1].table;
                n += (size_t)snprintf(sql + n, sizeof(sql) - n, "%sto_regclass('%s')::oid", i ? "," : "", tbl);
            }
            snprintf(sql + n, sizeof(sql) - n, "])");
            if ((ret = exec_rows(c, sql, 0, NULL, &r, "pg_trigger")) != 0) return ret;
            char miss[300] = "";
            unsigned nm = 0;
            for (size_t i = 0; i < sizeof(k_trg) / sizeof(k_trg[0]) * 3 + 1; i++) {
                char name[96];
                if (i == 0) {
                    snprintf(name, sizeof(name), "karidns_changes_prune");
                } else {
                    size_t k = (i - 1) / 3;
                    static const char *const sfx[3] = { "ins", "upd", "del" };
                    bool table_here = true;
                    if (strncmp(k_trg[k].table, "karidns_", 8) == 0)
                        for (size_t t = 0; t < N_TABLES; t++)
                            if (strcmp(k_tables[t].table, k_trg[k].table) == 0) table_here = FULL(t);
                    if (!table_here) continue;                 /* its table is reported above */
                    snprintf(name, sizeof(name), "karidns_trg_%s_%s", k_trg[k].infix, sfx[(i - 1) % 3]);
                }
                bool seen = false;
                for (int j = 0; j < PQntuples(r) && !seen; j++)
                    if (strcmp(PQgetvalue(r, j, 0), name) == 0) seen = true;
                if (!seen) db_list_add(miss, sizeof(miss), &nm, name);
            }
            PQclear(r);
            if (nm)
                fnd(cb, ud, 'E', "auto-reload yes needs the change log triggers, but %u are missing: %s%s (apply db/karidns_ext.pgsql.sql)", nm, miss,
                    nm > 6 ? ", ..." : "");
        }
    }
#undef FULL
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* snapshot                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static int pg_begin_snapshot(db_conn_t *c) {
    if (c->in_snapshot) {
        set_err(c, "begin_snapshot: a snapshot is already open");
        return -1;
    }
    int rc = exec_cmd(c, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", "begin snapshot");
    if (rc != 0) return rc;
    c->in_snapshot = true;
    /* the snapshot of a REPEATABLE READ transaction is taken by its first statement, which must not wait */
    PGresult *r = NULL;
    rc = exec_rows(c, "SELECT 1", 0, NULL, &r, "begin snapshot");
    if (rc != 0) {
        PQclear(PQexec(c->pg, "ROLLBACK"));
        c->in_snapshot = false;
        return rc;
    }
    PQclear(r);
    return 0;
}

static int pg_end_snapshot(db_conn_t *c) {
    if (!c->in_snapshot) return 0;
    c->in_snapshot = false;
    return exec_cmd(c, "COMMIT", "end snapshot");      /* also ends an aborted transaction (the server answers ROLLBACK, which is OK) */
}

/* ------------------------------------------------------------------------------------------------------------- */
/* cursor scans                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

/* called for each row of a FETCH result: 0 = go on, non-zero = stop (DB_STOPPED) or an error (-1, c->err set) */
typedef int (*row_fn)(db_conn_t *c, PGresult *r, int row, void *ud);

/* One cursor over `query`, rows to fn in batches.  Callbacks must not use this connection.  0, DB_STOPPED, -1, DB_ERR_RETRY. */
static int pg_scan(db_conn_t *c, const char *what, const char *query, int np, const char *const *pv, row_fn fn, void *ud) {
    if (!c->in_snapshot) {
        set_err(c, "%s: no snapshot is open", what);
        return -1;
    }
    char sql[1500];
    int n = snprintf(sql, sizeof(sql), "DECLARE karidns_cur NO SCROLL CURSOR FOR %s", query);
    if (n < 0 || (size_t)n >= sizeof(sql)) {
        set_err(c, "%s: query too long", what);
        return -1;
    }
    PGresult *r = PQexecParams(c->pg, sql, np, NULL, pv, NULL, NULL, 0);
    if (!r || PQresultStatus(r) != PGRES_COMMAND_OK) {
        int ret = pq_fail(c, r, what);
        PQclear(r);
        return ret;
    }
    PQclear(r);
    int ret = 0;
    char fetch[64];
    snprintf(fetch, sizeof(fetch), "FETCH FORWARD %d FROM karidns_cur", PG_FETCH_ROWS);
    for (;;) {
        r = PQexec(c->pg, fetch);
        if (!r || PQresultStatus(r) != PGRES_TUPLES_OK) {
            ret = pq_fail(c, r, what);
            PQclear(r);
            break;
        }
        int rows = PQntuples(r);
        for (int i = 0; i < rows && ret == 0; i++) {
            int rc = fn(c, r, i, ud);
            if (rc == DB_STOPPED || rc > 0) ret = DB_STOPPED;
            else if (rc != 0) ret = rc;
        }
        PQclear(r);
        if (ret != 0 || rows < PG_FETCH_ROWS) break;
    }
    if (PQstatus(c->pg) == CONNECTION_OK) {
        /* normally the cursor is exhausted or the callback stopped it; after a server error the transaction is aborted
         * and the CLOSE fails, which is harmless (the caller ends the snapshot) */
        r = PQexec(c->pg, "CLOSE karidns_cur");
        PQclear(r);
    }
    return ret;
}

/* ---- zones ---- */
typedef struct { db_zone_cb cb; void *ud; bool have_prev; int64_t prev; bool any; } zl_t;

static int zl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    zl_t *z = ud;
    bool bad = false;
    int64_t id = cell_i64(c, r, i, 0, &bad);
    if (bad) return -1;
    if (z->have_prev && id == z->prev) return 0;      /* more than one enabled apex SOA: the first is enough here */
    z->have_prev = true;
    z->prev = id;
    z->any = true;
    db_zone_row_t row;
    row.id = id;
    row.name = cell_text(c, r, i, 1, "domains", id, "name", &bad);
    row.type = cell_text(c, r, i, 2, "domains", id, "type", &bad);
    row.master = cell_text(c, r, i, 3, "domains", id, "master", &bad);
    row.catalog = cell_text(c, r, i, 4, "domains", id, "catalog", &bad);
    row.soa_content = cell_text(c, r, i, 5, "records", id, "content", &bad);
    if (bad) return -1;
    return z->cb(z->ud, &row) != 0 ? DB_STOPPED : 0;
}

/* The zone list: every domain with the content of its apex SOA.  The join is on the plain name (r.name = d.name), which the standard
 * PowerDNS indexes serve (records(name, type) / records(name), records(domain_id)): a plan that probes them costs about 0.2 s for
 * 10,000 zones of 1,000 records, where the former join on lower(r.name) = lower(d.name) could only be answered by reading every
 * record (0.8 s there; 2.0 s for 1,000,000 zones x 11, now 1.8 s, measured in the loader).  A zone with no enabled SOA of exactly its own spelling falls back, per zone,
 * to the case-insensitive comparison of before (the subquery runs only for such zones, through the domain_id index), so a zone whose
 * SOA owner differs from domains.name in case (the schema's c_lowercase_name CHECK forbids both) still gets its SOA (the SQLite3
 * driver compares records.name exactly and gives such a zone none: a data error either way).  The row chosen is the lowest enabled records.id of the exact spelling, else of the other spellings;
 * before it was the lowest of all spellings, which differs only for a zone that has SOA rows of two spellings.  The SQLite3 driver's
 * list_zones (r.name = d.name, ORDER BY d.id, r.id) selects the same row for every ordinary zone. */
#define PG_ZONE_SELECT                                                                                                           \
    "SELECT d.id, d.name, d.type, d.master, d.catalog, "                                                                         \
    "CASE WHEN r.id IS NULL THEN (SELECT s.content FROM records s WHERE s.domain_id = d.id AND s.type = 'SOA' "                  \
    "AND s.disabled = false AND lower(s.name) = lower(d.name) ORDER BY s.id LIMIT 1) ELSE r.content END "                        \
    "FROM domains d LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = false "

/* The optional covering index on the SOA rows of records (docs/karidns-dbloader.md "Optional indexes"): a btree on (domain_id)
 * that INCLUDEs name and content and is partial on type = 'SOA' and disabled = false.  Looked up in pg_indexes of the schema in
 * use, outside a snapshot (an error inside one would abort it).  false when the catalog cannot be read. */
static bool pg_has_soa_cover_index(db_conn_t *c) {
    PGresult *pr = PQexec(c->pg, "SELECT 1 FROM pg_catalog.pg_indexes WHERE schemaname = current_schema() AND tablename = 'records' "
                                 "AND indexdef ~* 'USING btree \\(domain_id\\) INCLUDE \\(name, content\\) WHERE' "
                                 "AND indexdef ~* 'type[^,]*= *''SOA''' AND indexdef ~* 'disabled' LIMIT 1");
    bool yes = pr && PQresultStatus(pr) == PGRES_TUPLES_OK && PQntuples(pr) == 1;
    PQclear(pr);
    return yes;
}

static int pg_list_zones(db_conn_t *c, db_zone_cb cb, void *ud) {
    zl_t z = { cb, ud, false, 0, false };
    if (!c->in_snapshot) {
        set_err(c, "list_zones: no snapshot is open");
        return -1;
    }
    /* A cursor is planned for its first 10% of rows (cursor_tuple_fraction 0.1), which here means a merge join that walks the whole
     * records table through its domain_id index (2.9 s in psql at 1,000,000 zones).  The whole list is read, so plan for all of it; the
     * planner then chooses between probing the name index per zone and one pass over the SOA rows by its cost (1.7 s in psql at 1,000,000
     * zones x 11 records, 0.2 s at 10,000 x 1,000).  The setting ends with the snapshot and is reset after the scan.
     * With the optional covering index on the SOA rows (docs/karidns-dbloader.md: records (domain_id) INCLUDE (name, content) WHERE
     * type = 'SOA' AND disabled = false) the planner's default (0.1, the first rows first) is used instead: the index gives it an
     * index-only merge join, and the session default of 1 (set for the bulk scans) is what made it read every SOA row.  Whether the
     * index exists was looked up once, when the connection checked the schema (pg_has_soa_cover_index()). */
    int ret = exec_cmd(c, c->soa_cover_idx > 0 ? "SET LOCAL cursor_tuple_fraction = 0.1" : "SET LOCAL cursor_tuple_fraction = 1",
                       "list_zones");
    if (ret != 0) return ret;
    ret = pg_scan(c, "list_zones", PG_ZONE_SELECT "ORDER BY d.id, r.id", 0, NULL, zl_row, &z);
    if (ret == 0 || ret == DB_STOPPED) {
        /* back to the session's value (1, set at connect) for the rest of the snapshot: RESET would give the server's
         * default (0.1) to the bulk scans that follow in this transaction (review db_pgsql [1.1]) */
        int rc = exec_cmd(c, "SET LOCAL cursor_tuple_fraction = 1", "list_zones");
        if (ret == 0) ret = rc;
    }
    return ret;
}

/* B13: one zone by name for a one-zone reload.  Names are compared like names_equal() of the loader: ASCII case-insensitive, with or
 * without one trailing dot.  The PowerDNS schema has only an index on domains.name (case-sensitive), so the first query asks for the
 * two spellings exactly (index scan, the usual case: names are stored in lower case); only when it finds nothing is lower() used,
 * which scans the table once (a zone stored with capitals, or a zone that is not there, i.e. a deletion).  Unlike the list, which
 * stops at the lowest id, an exact spelling wins over another capitalisation of the same name (two such rows are a data error). */
static int pg_find_zone(db_conn_t *c, const char *name, db_zone_cb cb, void *ud) {
    size_t n = strlen(name);
    if (n > 1 && name[n - 1] == '.') n--;
    char a[1100], b[1100];        /* the two spellings (PQexecParams takes C strings) */
    if (n > sizeof(a) - 2) return 0;       /* longer than any domain name (255 bytes, escapes included): no zone of that name */
    memcpy(a, name, n);
    a[n] = '\0';
    memcpy(b, a, n);
    b[n] = '.';
    b[n + 1] = '\0';
    const char *pv[2] = { a, b };
    static const char *const sel = PG_ZONE_SELECT;
    char q[1100];
    zl_t z = { cb, ud, false, 0, false };
    snprintf(q, sizeof(q), "%sWHERE d.name IN ($1, $2) ORDER BY d.id, r.id", sel);
    int ret = pg_scan(c, "find_zone", q, 2, pv, zl_row, &z);
    if (ret == 0 && !z.any) {
        snprintf(q, sizeof(q), "%sWHERE lower(d.name) IN (lower($1), lower($2)) ORDER BY d.id, r.id", sel);
        ret = pg_scan(c, "find_zone", q, 2, pv, zl_row, &z);
    }
    return ret;
}

/* 0.7: the zones that have one of the names, closest (longest name) first (dns_db_driver.h find_zones_in()).  The names go in as one text array parameter, each element quoted (a backslash and a double quote are
 * escaped, as the array literal of PostgreSQL wants), in both spellings; `d.name = ANY(...)` is a search of the index on domains.name for every element. */
static int pg_find_zones_in(db_conn_t *c, const char *const *names, size_t n, db_zone_cb cb, void *ud) {
    if (n == 0 || n > DB_LOOKUP_MAX) {
        set_err(c, "find_zones_in: %zu names (1 to %d)", n, DB_LOOKUP_MAX);
        return -1;
    }
    char *arr = malloc(2 * n * (2 * 1100 + 4) + 8);       /* (every character may be escaped; two spellings of at most 1100 bytes) */
    if (!arr) {
        set_err(c, "find_zones_in: out of memory");
        return -1;
    }
    size_t o = 0;
    arr[o++] = '{';
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(names[i]);
        if (l > 1 && names[i][l - 1] == '.') l--;
        if (l == 0 || l > 1100 - 2) continue;                  /* longer than any domain name: it matches nothing */
        for (int dot = 0; dot < 2; dot++) {
            if (!first) arr[o++] = ',';
            first = false;
            arr[o++] = '"';
            for (size_t k = 0; k < l; k++) {
                if (names[i][k] == '"' || names[i][k] == '\\') arr[o++] = '\\';
                arr[o++] = names[i][k];
            }
            if (dot) arr[o++] = '.';
            arr[o++] = '"';
        }
    }
    arr[o++] = '}';
    arr[o] = '\0';
    const char *pv[1] = { arr };
    char q[1100];
    zl_t z = { cb, ud, false, 0, false };
    snprintf(q, sizeof(q), "%sWHERE d.name = ANY($1::text[]) ORDER BY length(d.name) DESC, d.id, r.id", PG_ZONE_SELECT);
    int ret = pg_scan(c, "find_zones_in", q, 1, pv, zl_row, &z);
    free(arr);
    return ret;
}

/* ---- records ---- */
typedef struct { db_record_cb cb; void *ud; } rl_t;

static int rl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    rl_t *l = ud;
    bool bad = false;
    int64_t did = cell_i64(c, r, i, 0, &bad);
    db_record_row_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.id = cell_i64(c, r, i, 1, &bad);
    rec.name = cell_text(c, r, i, 2, "records", rec.id, "name", &bad);
    rec.type = cell_text(c, r, i, 3, "records", rec.id, "type", &bad);
    rec.content = cell_text(c, r, i, 4, "records", rec.id, "content", &bad);
    rec.ttl_null = PQgetisnull(r, i, 5);
    rec.ttl = cell_i64(c, r, i, 5, &bad);
    rec.prio_null = PQgetisnull(r, i, 6);
    rec.prio = cell_i64(c, r, i, 6, &bad);
    rec.disabled = PQgetisnull(r, i, 7) || cell_true(r, i, 7) ? true : false;      /* NULL = disabled, like SQLite3 */
    rec.ordername = cell_text(c, r, i, 8, "records", rec.id, "ordername", &bad);
    if (bad) return -1;
    return l->cb(l->ud, did, &rec) != 0 ? DB_STOPPED : 0;
}

#define REC_COLS "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername FROM records "

static int pg_scan_records(db_conn_t *c, const int64_t *domain_id, db_record_cb cb, void *ud) {
    rl_t l = { cb, ud };
    if (domain_id) {
        char p[32];
        snprintf(p, sizeof(p), "%lld", (long long)*domain_id);
        const char *pv[1] = { p };
        return pg_scan(c, "scan_records", REC_COLS "WHERE domain_id = $1::bigint ORDER BY id", 1, pv, rl_row, &l);
    }
    return pg_scan(c, "scan_records", REC_COLS "ORDER BY domain_id, id", 0, NULL, rl_row, &l);
}

/* D1a step 6: the enabled SOA and NS records at the apex (the record's name is the domain's name), one zone or all */
typedef struct { db_apex_cb cb; void *ud; } al_t;

static int al_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    al_t *l = ud;
    bool bad = false;
    int64_t rid = cell_i64(c, r, i, 4, &bad);
    db_apex_row_t a;
    a.domain_id = cell_i64(c, r, i, 0, &bad);
    const char *type = cell_text(c, r, i, 1, "records", rid, "type", &bad);
    a.is_soa = type && strcasecmp(type, "SOA") == 0;
    a.addr_type = type && strcasecmp(type, "A") == 0 ? 1 : type && strcasecmp(type, "AAAA") == 0 ? 28 : 0;
    a.name = cell_text(c, r, i, 5, "records", rid, "name", &bad);
    a.content = cell_text(c, r, i, 2, "records", rid, "content", &bad);
    a.ttl_null = PQgetisnull(r, i, 3);
    a.ttl = cell_i64(c, r, i, 3, &bad);
    if (bad) return -1;
    return l->cb(l->ud, &a) != 0 ? DB_STOPPED : 0;
}

/* the SOA and NS rows of the apex, and the address rows of the zone whose owner is an NS target inside the zone (g: the NS row n gives the target) */
#define APEX_COLS "SELECT r.domain_id, r.type, r.content, r.ttl, r.id, r.name FROM records r JOIN domains d ON d.id = r.domain_id AND lower(r.name) = lower(d.name) " \
                  "WHERE r.type IN ('SOA', 'NS') AND r.disabled = false "
#define APEX_GLUE "SELECT g.domain_id, g.type, g.content, g.ttl, g.id, g.name FROM records n JOIN domains d ON d.id = n.domain_id AND lower(n.name) = lower(d.name) " \
                  "JOIN records g ON g.domain_id = n.domain_id AND g.type IN ('A', 'AAAA') AND g.disabled = false AND lower(g.name) = lower(rtrim(n.content, '.')) " \
                  "WHERE n.type = 'NS' AND n.disabled = false "
#define APEX_IN_ZONE "AND (lower(rtrim(n.content, '.')) = lower(d.name) OR right(lower(rtrim(n.content, '.')), length(d.name) + 1) = '.' || lower(d.name)) "
/* D1a step 7: the address rows of the NS targets that are NOT inside the zone, from any zone of the source, for the NOTIFY the Backend sends while the zone is out of memory:
 * the row is the zone's (n.domain_id), the name the target's.  g.name = lower(...) uses the index on records(name) (PowerDNS stores names in lower case). */
#define APEX_XADDR "SELECT n.domain_id, g.type, g.content, g.ttl, g.id, g.name FROM records n JOIN domains d ON d.id = n.domain_id AND lower(n.name) = lower(d.name) " \
                   "JOIN records g ON g.name = lower(rtrim(n.content, '.')) AND g.type IN ('A', 'AAAA') AND g.disabled = false " \
                   "WHERE n.type = 'NS' AND n.disabled = false AND NOT (lower(rtrim(n.content, '.')) = lower(d.name) OR right(lower(rtrim(n.content, '.')), length(d.name) + 1) = '.' || lower(d.name)) "

static int pg_scan_apex(db_conn_t *c, const int64_t *domain_id, db_apex_cb cb, void *ud) {
    al_t l = { cb, ud };
    if (domain_id) {
        char p[32];
        snprintf(p, sizeof(p), "%lld", (long long)*domain_id);
        const char *pv[1] = { p };
        return pg_scan(c, "scan_apex", APEX_COLS "AND r.domain_id = $1::bigint UNION ALL " APEX_GLUE "AND n.domain_id = $1::bigint " APEX_IN_ZONE "UNION ALL " APEX_XADDR "AND n.domain_id = $1::bigint " "ORDER BY 1, 5", 1, pv, al_row, &l);
    }
    return pg_scan(c, "scan_apex", APEX_COLS "UNION ALL " APEX_GLUE APEX_IN_ZONE "UNION ALL " APEX_XADDR "ORDER BY 1, 5", 0, NULL, al_row, &l);
}

static int pg_scan_records_range(db_conn_t *c, int64_t lo, int64_t hi, db_record_cb cb, void *ud) {
    rl_t l = { cb, ud };
    char p1[32], p2[32];
    snprintf(p1, sizeof(p1), "%lld", (long long)lo);
    snprintf(p2, sizeof(p2), "%lld", (long long)hi);
    const char *pv[2] = { p1, p2 };
    return pg_scan(c, "scan_records", REC_COLS "WHERE domain_id >= $1::bigint AND domain_id <= $2::bigint ORDER BY domain_id, id", 2, pv,
                   rl_row, &l);
}

/* ---- metadata ---- */
typedef struct { db_meta_cb cb; void *ud; } ml_t;

static int ml_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    ml_t *l = ud;
    bool bad = false;
    int64_t id = cell_i64(c, r, i, 3, &bad);
    db_meta_row_t m;
    m.domain_id = cell_i64(c, r, i, 0, &bad);
    m.kind = cell_text(c, r, i, 1, "domainmetadata", id, "kind", &bad);
    m.content = cell_text(c, r, i, 2, "domainmetadata", id, "content", &bad);
    if (bad) return -1;
    return l->cb(l->ud, &m) != 0 ? DB_STOPPED : 0;
}

static int pg_scan_metadata(db_conn_t *c, const int64_t *domain_id, db_meta_cb cb, void *ud) {
    ml_t l = { cb, ud };
    if (domain_id) {
        char p[32];
        snprintf(p, sizeof(p), "%lld", (long long)*domain_id);
        const char *pv[1] = { p };
        return pg_scan(c, "scan_metadata", "SELECT domain_id, kind, content, id FROM domainmetadata WHERE domain_id = $1::bigint ORDER BY id", 1, pv,
                       ml_row, &l);
    }
    return pg_scan(c, "scan_metadata", "SELECT domain_id, kind, content, id FROM domainmetadata ORDER BY domain_id, id", 0, NULL, ml_row, &l);
}

/* ---- cryptokeys (existence only: the loader role has the column privilege SELECT (domain_id, active, published), D11) ---- */
typedef struct { db_key_cb cb; void *ud; } kl_t;

static int kl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    kl_t *l = ud;
    if (PQgetisnull(r, i, 0)) return 0;
    bool bad = false;
    const int64_t did = cell_i64(c, r, i, 0, &bad);
    if (bad) return -1;
    return l->cb(l->ud, did) != 0 ? DB_STOPPED : 0;
}

/* 0.7 signer-wait (dns_db_driver.h signer_waiting): the rules of the signer's catch-up scan (signer/lib/db_pg.js catchUp()); once at a start of the loader */
static int pg_signer_waiting(db_conn_t *c, db_key_cb cb, void *ud) {
    PGresult *r = NULL;
    int ret = exec_rows(c, "SELECT to_regclass('karidns_signer_state') IS NOT NULL", 0, NULL, &r, "signer_waiting");
    if (ret != 0) return ret;
    const bool have = cell_true(r, 0, 0);
    PQclear(r);
    if (!have || !c->has_zone_state) {
        set_err(c, "karidns_signer_state or karidns_zone_state does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    kl_t l = { cb, ud };
    return pg_scan(c, "signer_waiting",
                   "SELECT s.domain_id FROM karidns_signer_state s "
                   "WHERE EXISTS (SELECT 1 FROM domainmetadata m WHERE m.domain_id = s.domain_id AND upper(m.kind) = 'X-KARIDNS-SIGNER') "
                   "AND (s.signed_serial IS NULL "
                   "OR EXISTS (SELECT 1 FROM karidns_zone_state z WHERE z.domain_id = s.domain_id AND z.changed_at > extract(epoch FROM s.signed_at)) "
                   "OR EXISTS (SELECT 1 FROM records r WHERE r.domain_id = s.domain_id AND r.type = 'SOA' "
                   "AND CASE WHEN split_part(r.content, ' ', 3) ~ '^[0-9]+$' THEN split_part(r.content, ' ', 3)::bigint END <> s.signed_serial)) "
                   "ORDER BY s.domain_id",
                   0, NULL, kl_row, &l);
}

static int pg_zones_with_keys(db_conn_t *c, db_key_cb cb, void *ud) {
    kl_t l = { cb, ud };
    return pg_scan(c, "zones_with_keys", "SELECT DISTINCT domain_id FROM cryptokeys ORDER BY domain_id", 0, NULL, kl_row, &l);
}

/* ---- karidns_domain_views ---- */
typedef struct { db_domain_view_cb cb; void *ud; } dl_t;

static int dl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    dl_t *l = ud;
    bool bad = false;
    int64_t did = cell_i64(c, r, i, 0, &bad);
    const char *vn = cell_text(c, r, i, 1, "karidns_domain_views", did, "view_name", &bad);
    if (bad) return -1;
    if (!vn) return 0;                                  /* the column is NOT NULL; a NULL name maps to no view */
    return l->cb(l->ud, did, vn) != 0 ? DB_STOPPED : 0;
}

static int pg_scan_domain_views(db_conn_t *c, const int64_t *domain_id, db_domain_view_cb cb, void *ud) {
    if (!c->has_domain_views) {
        set_err(c, "karidns_domain_views does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    dl_t l = { cb, ud };
    if (domain_id) {
        char p[32];
        snprintf(p, sizeof(p), "%lld", (long long)*domain_id);
        const char *pv[1] = { p };
        return pg_scan(c, "scan_domain_views", "SELECT domain_id, view_name FROM karidns_domain_views WHERE domain_id = $1::bigint ORDER BY view_name", 1, pv, dl_row, &l);
    }
    return pg_scan(c, "scan_domain_views", "SELECT domain_id, view_name FROM karidns_domain_views ORDER BY domain_id", 0, NULL, dl_row, &l);
}

/* ---- karidns_profiles ---- */
typedef struct { db_profile_cb cb; void *ud; } pl_t;

static int pl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    pl_t *l = ud;
    bool bad = false;
    db_profile_row_t p;
    p.name = cell_text(c, r, i, 0, "karidns_profiles", 0, "name", &bad);
    p.settings = cell_text(c, r, i, 1, "karidns_profiles", 0, "settings", &bad);
    if (bad) return -1;
    if (!p.name) return 0;
    return l->cb(l->ud, &p) != 0 ? DB_STOPPED : 0;
}

static int pg_scan_profiles(db_conn_t *c, db_profile_cb cb, void *ud) {
    if (!c->has_profiles) {
        set_err(c, "karidns_profiles does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    pl_t l = { cb, ud };
    return pg_scan(c, "scan_profiles", "SELECT name, settings FROM karidns_profiles ORDER BY name COLLATE \"C\"", 0, NULL, pl_row, &l);
}

/* ---- the extension tables (B8) ---- */
static int xt_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    const db_ext_sink_t *s = ud;
    bool bad = false;
    int64_t did = cell_i64(c, r, i, 0, &bad);
    db_tag_row_t row;
    row.record_id = cell_i64(c, r, i, 1, &bad);
    row.location_tag = cell_text(c, r, i, 2, "karidns_record_tags", row.record_id, "location_tag", &bad);
    row.ecs_tag = cell_text(c, r, i, 3, "karidns_record_tags", row.record_id, "ecs_tag", &bad);
    if (bad) return -1;
    return s->record_tags(s->ud, did, &row) != 0 ? DB_STOPPED : 0;
}

static int xd_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    const db_ext_sink_t *s = ud;
    bool bad = false;
    int64_t did = cell_i64(c, r, i, 0, &bad);
    db_tinydns_row_t row;
    row.record_id = cell_i64(c, r, i, 1, &bad);
    row.ttd_null = PQgetisnull(r, i, 2);
    row.ttd = cell_i64(c, r, i, 2, &bad);
    row.loc = cell_text(c, r, i, 3, "karidns_record_tinydns", row.record_id, "loc", &bad);
    row.countdown = cell_true(r, i, 4);
    if (bad) return -1;
    return s->record_tinydns(s->ud, did, &row) != 0 ? DB_STOPPED : 0;
}

static int xg_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    const db_ext_sink_t *s = ud;
    bool bad = false;
    int64_t did = cell_i64(c, r, i, 0, &bad);
    db_tagdef_row_t row;
    row.kind = cell_text(c, r, i, 1, "karidns_zone_tagdefs", did, "kind", &bad);
    row.tag = cell_text(c, r, i, 2, "karidns_zone_tagdefs", did, "tag", &bad);
    row.cidr = cell_text(c, r, i, 3, "karidns_zone_tagdefs", did, "cidr", &bad);
    if (bad) return -1;
    return s->tagdef(s->ud, did, &row) != 0 ? DB_STOPPED : 0;
}

/* Each table in its own pass, rows ordered by (domain_id, record_id); the tag definitions by (domain_id, id) with the id
 * of schema version 2, or (domain_id, ctid) of version 1: the order the rows were inserted in is the order of the
 * definitions in a zone file, and the first definition that matches a client wins. */
static int pg_scan_ext(db_conn_t *c, const int64_t *domain_id, const db_ext_sink_t *sink) {
    if (!c->has_ext) {
        set_err(c, "the karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs tables do not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    char p[32];
    const char *pv[1] = { p };
    int np = 0;
    if (domain_id) {
        snprintf(p, sizeof(p), "%lld", (long long)*domain_id);
        np = 1;
    }
    int ret = pg_scan(c, "scan_ext (karidns_record_tags)",
                      domain_id ? "SELECT r.domain_id, t.record_id, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id "
                                  "WHERE r.domain_id = $1::bigint ORDER BY t.record_id"
                                : "SELECT r.domain_id, t.record_id, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id "
                                  "ORDER BY r.domain_id, t.record_id",
                      np, pv, xt_row, (void *)sink);
    if (ret != 0) return ret;
    ret = pg_scan(c, "scan_ext (karidns_record_tinydns)",
                  domain_id ? "SELECT r.domain_id, t.record_id, t.ttd, t.loc::text, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                              "WHERE r.domain_id = $1::bigint ORDER BY t.record_id"
                            : "SELECT r.domain_id, t.record_id, t.ttd, t.loc::text, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                              "ORDER BY r.domain_id, t.record_id",
                  np, pv, xd_row, (void *)sink);
    if (ret != 0) return ret;
    const char *ord = c->has_tagdef_id ? "id" : "ctid";
    char q[300];
    if (domain_id)
        snprintf(q, sizeof(q), "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs WHERE domain_id = $1::bigint ORDER BY %s", ord);
    else
        snprintf(q, sizeof(q), "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs ORDER BY domain_id, %s", ord);
    return pg_scan(c, "scan_ext (karidns_zone_tagdefs)", q, np, pv, xg_row, (void *)sink);
}

/* ---- several zones in one statement per table (scan_records_in, scan_metadata_in, scan_ext_in) ----
 * A zone read on its own costs a statement per table and three round trips per statement (DECLARE, FETCH, CLOSE), about fifteen with the
 * extension tables: 0.6 ms for each of the 100,000 zones of a 10% reload at 1,000,000 zones, where the conversion of the zone is a tenth of
 * that.  The loader asks for up to DB_IN_MAX zones at a time; the cursor still hands the rows over in batches of PG_FETCH_ROWS, so the
 * memory held is the same as for one zone. */
static int ids_literal(db_conn_t *c, const int64_t *ids, size_t n, char *out, size_t cap) {
    if (n == 0 || n > DB_IN_MAX || cap < n * 21 + 3) {
        set_err(c, "scan_*_in: %zu zones (1..%u allowed)", n, DB_IN_MAX);
        return -1;
    }
    size_t o = 0;
    out[o++] = '{';
    for (size_t i = 0; i < n; i++) o += (size_t)snprintf(out + o, cap - o, "%s%lld", i ? "," : "", (long long)ids[i]);
    out[o++] = '}';
    out[o] = '\0';
    return 0;
}
#define IDS_BUF (DB_IN_MAX * 21 + 3)

static int pg_scan_records_in(db_conn_t *c, const int64_t *ids, size_t n, db_record_cb cb, void *ud) {
    char arr[IDS_BUF];
    if (ids_literal(c, ids, n, arr, sizeof(arr)) != 0) return -1;
    rl_t l = { cb, ud };
    const char *pv[1] = { arr };
    return pg_scan(c, "scan_records", REC_COLS "WHERE domain_id = ANY ($1::bigint[]) ORDER BY domain_id, id", 1, pv, rl_row, &l);
}

static int pg_scan_metadata_in(db_conn_t *c, const int64_t *ids, size_t n, db_meta_cb cb, void *ud) {
    char arr[IDS_BUF];
    if (ids_literal(c, ids, n, arr, sizeof(arr)) != 0) return -1;
    ml_t l = { cb, ud };
    const char *pv[1] = { arr };
    return pg_scan(c, "scan_metadata", "SELECT domain_id, kind, content, id FROM domainmetadata WHERE domain_id = ANY ($1::bigint[]) ORDER BY domain_id, id", 1,
                   pv, ml_row, &l);
}

static int pg_zones_with_keys_in(db_conn_t *c, const int64_t *ids, size_t n, db_key_cb cb, void *ud) {
    char arr[IDS_BUF];
    if (ids_literal(c, ids, n, arr, sizeof(arr)) != 0) return -1;
    kl_t l = { cb, ud };
    const char *pv[1] = { arr };
    return pg_scan(c, "zones_with_keys", "SELECT DISTINCT domain_id FROM cryptokeys WHERE domain_id = ANY ($1::bigint[]) ORDER BY domain_id", 1, pv, kl_row, &l);
}

static int pg_scan_ext_in(db_conn_t *c, const int64_t *ids, size_t n, const db_ext_sink_t *sink) {
    if (!c->has_ext) {
        set_err(c, "the karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs tables do not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    char arr[IDS_BUF];
    if (ids_literal(c, ids, n, arr, sizeof(arr)) != 0) return -1;
    const char *pv[1] = { arr };
    int ret = pg_scan(c, "scan_ext (karidns_record_tags)",
                      "SELECT r.domain_id, t.record_id, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id "
                      "WHERE r.domain_id = ANY ($1::bigint[]) ORDER BY r.domain_id, t.record_id",
                      1, pv, xt_row, (void *)sink);
    if (ret != 0) return ret;
    ret = pg_scan(c, "scan_ext (karidns_record_tinydns)",
                  "SELECT r.domain_id, t.record_id, t.ttd, t.loc::text, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                  "WHERE r.domain_id = ANY ($1::bigint[]) ORDER BY r.domain_id, t.record_id",
                  1, pv, xd_row, (void *)sink);
    if (ret != 0) return ret;
    char q[300];
    snprintf(q, sizeof(q), "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs WHERE domain_id = ANY ($1::bigint[]) ORDER BY domain_id, %s",
             c->has_tagdef_id ? "id" : "ctid");
    return pg_scan(c, "scan_ext (karidns_zone_tagdefs)", q, 1, pv, xg_row, (void *)sink);
}


/* ------------------------------------------------------------------------------------------------------------- */
/* change log                                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

/* the xmin of the current snapshot (the cursor), as an unsigned number */
static int snapshot_xmin(db_conn_t *c, uint64_t *xmin) {
    PGresult *r = NULL;
    int ret = exec_rows(c, "SELECT pg_snapshot_xmin(pg_current_snapshot())::text", 0, NULL, &r, "changes cursor");
    if (ret != 0) return ret;
    bool bad = false;
    *xmin = cell_u64(c, r, 0, 0, &bad);
    PQclear(r);
    return bad ? -1 : 0;
}

static int pg_changes_max(db_conn_t *c, uint64_t *seq) {
    if (!c->has_changes) {
        set_err(c, "karidns_changes (schema version 2: with the xid column) does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    return snapshot_xmin(c, seq);
}

/* What the open snapshot sees of one zone's change log (dns_db_driver.h changes_cover): the xmin, and the transactions at or above it whose rows of the
 * zone are visible.  A transaction that committed before the snapshot is above its xmin when an older one was still running (the second worker of the
 * signer, any long transaction): the xmin alone left such a zone on the list of the zones that wait for the signer until its next reload (CI flake row 19).
 * The rows the snapshot does not see (a transaction still open) are not listed: their zone is a change.  karidns_changes_xid_idx keeps it to the rows
 * since the xmin. */
static int pg_changes_cover(db_conn_t *c, int64_t domain_id, uint64_t *cursor, uint64_t *xids, unsigned max, unsigned *n) {
    *n = 0;
    int ret = pg_changes_max(c, cursor);
    if (ret != 0) return ret;
    char p1[32], p2[32], p3[16];
    snprintf(p1, sizeof(p1), "%lld", (long long)domain_id);
    snprintf(p2, sizeof(p2), "%llu", (unsigned long long)*cursor);
    snprintf(p3, sizeof(p3), "%u", max + 1);
    const char *pv[3] = { p1, p2, p3 };
    PGresult *r = NULL;
    ret = exec_rows(c, "SELECT DISTINCT xid::text::bigint AS x FROM karidns_changes WHERE xid >= $2::xid8 AND domain_id = $1::bigint ORDER BY x DESC LIMIT $3::bigint",
                    3, pv, &r, "changes_cover");
    if (ret != 0) return ret;
    const int nt = PQntuples(r);
    bool bad = false;
    for (int i = 0; i < nt && !bad; i++) {
        if ((unsigned)i < max) xids[i] = cell_u64(c, r, i, 0, &bad);
        (*n)++;
    }
    PQclear(r);
    return bad ? -1 : 0;
}

typedef struct { db_change_cb cb; void *ud; } cl_t;

static int cl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    cl_t *l = ud;
    bool bad = false;
    db_change_row_t row;
    row.seq = (uint64_t)cell_i64(c, r, i, 0, &bad);
    row.domain_id = cell_i64(c, r, i, 1, &bad);
    row.pos = cell_u64(c, r, i, 2, &bad);
    if (bad) return -1;
    return l->cb(l->ud, &row) != 0 ? DB_STOPPED : 0;
}

static int pg_changes_since(db_conn_t *c, uint64_t after, db_change_cb cb, void *ud, uint64_t *last_seq, bool *gap) {
    if (!c->has_changes) {
        set_err(c, "karidns_changes (schema version 2: with the xid column) does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    uint64_t xmin = 0;
    int ret = snapshot_xmin(c, &xmin);
    if (ret != 0) return ret;
    char p[32];
    snprintf(p, sizeof(p), "%llu", (unsigned long long)after);
    const char *pv[1] = { p };
    bool g = false;
    if (after > 0) {
        /* pruned rows: the log has rows, the first seq is not 1, and nothing is left below the cursor (the rows the
         * loader has seen are gone, so some of the ones after them may be too).  This is a heuristic: it can say "gap" when there is
         * none (a needless full reload), and it can miss a gap behind a very long transaction (rows of a transaction that commits late
         * are older than the cursor and the check looks at min(seq) only); a full reload (karictl reload) repairs that. */
        PGresult *r = NULL;
        ret = exec_rows(c, "SELECT (SELECT min(seq) FROM karidns_changes), EXISTS (SELECT 1 FROM karidns_changes WHERE xid < $1::xid8)", 1, pv, &r,
                        "changes_since");
        if (ret != 0) return ret;
        bool bad = false;
        if (cell_i64(c, r, 0, 0, &bad) > 1 && !cell_true(r, 0, 1)) g = true;      /* (NULL: 0) */
        PQclear(r);
        if (bad) return -1;
    }
    cl_t l = { cb, ud };
    ret = pg_scan(c, "changes_since", "SELECT seq, domain_id, xid::text FROM karidns_changes WHERE xid >= $1::xid8 ORDER BY seq", 1, pv, cl_row, &l);
    if (last_seq) *last_seq = xmin;
    if (gap) *gap = g;
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* notifications                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------------------------------------------- */
/* 0.7 store, WP3: the paged calls (dns_db_driver.h).  Each is one statement (one snapshot), prepared once per    */
/* session; no BEGIN / COMMIT round trips, nothing is held between pages.                                        */
/* ------------------------------------------------------------------------------------------------------------- */

enum { RS_COUNT, RS_COUNT_VIEW, RS_MANIFEST, RS_CHANGES, RS_GAP };

static int rs_exec(db_conn_t *c, int idx, const char *sql, int np, const char *const *pv, PGresult **out, const char *what) {
    char name[16];
    snprintf(name, sizeof(name), "kzr%d", idx);
    if (!(c->r_prepared & (1u << idx))) {
        PGresult *p = PQprepare(c->pg, name, sql, np, NULL);
        if (!p || PQresultStatus(p) != PGRES_COMMAND_OK) {
            int ret = pq_fail(c, p, what);
            PQclear(p);
            return ret;
        }
        PQclear(p);
        c->r_prepared |= 1u << idx;
    }
    PGresult *r = PQexecPrepared(c->pg, name, np, pv, NULL, NULL, 0);
    if (!r || PQresultStatus(r) != PGRES_TUPLES_OK) {
        int ret = pq_fail(c, r, what);
        PQclear(r);
        return ret;
    }
    *out = r;
    return 0;
}

static int need_schema3(db_conn_t *c, const char *what, const char *table) {
    set_err(c, "%s: %s does not exist in this database (a plain PowerDNS schema: the 0.7 store needs karidns_zone_state and karidns_changes, "
               "schema version 3, db/karidns_ext.pgsql.sql)", what, table);
    return DB_ERR_NEED_SCHEMA3;
}

static int pg_count_domains(db_conn_t *c, const char *view, uint64_t *n) {
    *n = 0;
    bool by_view = view && c->has_domain_views;
    PGresult *r = NULL;
    const char *pv[1] = { view };
    int ret = by_view ? rs_exec(c, RS_COUNT_VIEW,
                                "SELECT (SELECT count(*) FROM domains) - (SELECT count(DISTINCT domain_id) FROM karidns_domain_views)"
                                " + (SELECT count(DISTINCT domain_id) FROM karidns_domain_views WHERE lower(view_name) = lower($1::text))",
                                1, pv, &r, "count_domains")
                      : rs_exec(c, RS_COUNT, "SELECT count(*) FROM domains", 0, NULL, &r, "count_domains");
    if (ret != 0) return ret;
    bool bad = false;
    long long v = cell_i64(c, r, 0, 0, &bad);
    *n = v < 0 ? 0 : (uint64_t)v;
    PQclear(r);
    return bad ? -1 : 0;
}

#ifdef KARIDNS_UNIT_TEST
static unsigned pg_test_manifest_rows;                  /* the rows of the last manifest_page result (tests: the view rows are bounded) */
#endif
static int pg_manifest_page(db_conn_t *c, int64_t after_id, unsigned limit, db_manifest_cb cb, void *ud, int64_t *last_id, unsigned *nrows) {
    *last_id = after_id;
    *nrows = 0;
    if (limit == 0 || limit > DB_PAGE_MAX) {
        set_err(c, "manifest_page: the limit must be 1 to %u", DB_PAGE_MAX);
        return -1;
    }
    if (!c->has_zone_state) return need_schema3(c, "manifest_page", "karidns_zone_state");
    /* the page of domains is cut first (an index scan on the primary key, LIMIT), then joined; the rows of one domain stay together.  Every joined
     * table carries the page's lower bound as well (S0, 10M rows): with the equality alone PostgreSQL merge-joins karidns_zone_state from its first row on
     * every page (1.9 s for a page at id 5M); with the bound a page is ~10 ms.
     * The views of a domain are bounded in the statement as well (review D-3): PQexecPrepared() holds every row of the result in the loader's memory before the first is looked at, and a
     * page of 100,000 domains with hundreds of karidns_domain_views rows each was unbounded.  The view rows are those of the page's id range (the lower bound as above, the upper bound the
     * page's last id), numbered per domain, and only the first DB_MANIFEST_MAX_VIEWS + 1 of each are joined: one more than a row carries, so that db_mgroup_view() still names the domain. */
    char sql[1200];
    if (c->has_domain_views)
        snprintf(sql, sizeof(sql),
                 "WITH d AS (SELECT id, name, type FROM domains WHERE id > $1::bigint ORDER BY id LIMIT $2::bigint) "
                 "SELECT d.id, d.name, d.type, s.generation, s.changed_at, v.view_name FROM d "
                 "LEFT JOIN karidns_zone_state s ON s.domain_id = d.id AND s.domain_id > $1::bigint "
                 "LEFT JOIN (SELECT domain_id, view_name, row_number() OVER (PARTITION BY domain_id ORDER BY view_name COLLATE \"C\") AS rn FROM karidns_domain_views "
                 "WHERE domain_id > $1::bigint AND domain_id <= (SELECT max(id) FROM d)) v ON v.domain_id = d.id AND v.rn <= %d "
                 "ORDER BY d.id, v.view_name COLLATE \"C\"",
                 DB_MANIFEST_MAX_VIEWS + 1);
    else
        snprintf(sql, sizeof(sql),
                 "SELECT d.id, d.name, d.type, s.generation, s.changed_at, NULL::text FROM (SELECT id, name, type FROM domains WHERE id > $1::bigint ORDER BY id LIMIT $2::bigint) d "
                 "LEFT JOIN karidns_zone_state s ON s.domain_id = d.id AND s.domain_id > $1::bigint ORDER BY d.id");
    char p1[32], p2[32];
    snprintf(p1, sizeof(p1), "%lld", (long long)after_id);
    snprintf(p2, sizeof(p2), "%u", limit);
    const char *pv[2] = { p1, p2 };
    PGresult *r = NULL;
    int ret = rs_exec(c, RS_MANIFEST, sql, 2, pv, &r, "manifest_page");
    if (ret != 0) return ret;
#ifdef KARIDNS_UNIT_TEST
    pg_test_manifest_rows = (unsigned)PQntuples(r);
#endif
    db_mgroup_t *g = &c->mg;
    g->open = false;
    for (int i = 0; i < PQntuples(r) && ret == 0; i++) {
        bool bad = false;
        int64_t id = cell_i64(c, r, i, 0, &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (g->open && id != g->row.id) {
            g->open = false;
            (*nrows)++;
            *last_id = g->row.id;
            if (cb(ud, &g->row) != 0) {
                ret = DB_STOPPED;
                break;
            }
        }
        if (!g->open) {
            const char *name = cell_text(c, r, i, 1, "domains", id, "name", &bad);
            const char *type = cell_text(c, r, i, 2, "domains", id, "type", &bad);
            bool has_state = !PQgetisnull(r, i, 3);
            const int64_t gen = cell_i64(c, r, i, 3, &bad), stime = cell_i64(c, r, i, 4, &bad);
            const char *why = bad ? NULL : db_mgroup_start(g, id, name, type, has_state, gen, stime);
            if (why) {
                set_err(c, "table domains id %lld: %s", (long long)id, why);
                bad = true;
            }
            if (bad) {
                ret = -1;
                break;
            }
        }
        const char *vn = cell_text(c, r, i, 5, "karidns_domain_views", id, "view_name", &bad);
        const char *why = !bad && vn ? db_mgroup_view(g, vn) : NULL;
        if (why) {
            set_err(c, "table karidns_domain_views domain %lld: %s", (long long)id, why);
            bad = true;
        }
        if (bad) ret = -1;
    }
    if (ret == 0 && g->open) {
        g->open = false;
        (*nrows)++;
        *last_id = g->row.id;
        if (cb(ud, &g->row) != 0) ret = DB_STOPPED;
    }
    g->open = false;
    PQclear(r);
    return ret;
}

static int pg_current_cursor(db_conn_t *c, uint64_t *cursor) {
    *cursor = 0;
    if (!c->has_changes) return need_schema3(c, "current_cursor", "karidns_changes");
    return snapshot_xmin(c, cursor);
}

static int pg_changes_page(db_conn_t *c, db_change_pos_t *pos, unsigned limit, db_change_entry_cb cb, void *ud, bool *more, bool *gap) {
    *more = false;
    *gap = false;
    if (limit == 0 || limit > DB_PAGE_MAX) {
        set_err(c, "changes_page: the limit must be 1 to %u", DB_PAGE_MAX);
        return -1;
    }
    if (!c->has_changes) return need_schema3(c, "changes_page", "karidns_changes");
    /* The window: `limit` log rows of the transactions at or above the drain's floor (xid >= cursor) with seq above the drain's progress, one entry per
     * domain (its highest seq), the domain's existence and the snapshot's xmin from the same statement (x is always one row, so the xmin comes even
     * when the window is empty); mn, mx and cnt describe the whole window; xl and xh are the lowest and highest xid of the domain's rows in the window (the loader's cover marks, cov_range()). */
    static const char sql[] =
        "WITH w AS (SELECT seq, domain_id, xid::text::bigint AS xi FROM karidns_changes WHERE xid >= $1::xid8 AND seq > $2::bigint ORDER BY seq LIMIT $3::bigint), "
        "a AS (SELECT domain_id, seq, min(seq) OVER () AS mn, max(seq) OVER () AS mx, count(*) OVER () AS cnt, "
        "max(seq) OVER (PARTITION BY domain_id) AS dm, min(xi) OVER (PARTITION BY domain_id) AS xl, max(xi) OVER (PARTITION BY domain_id) AS xh FROM w), "
        "x AS (SELECT pg_snapshot_xmin(pg_current_snapshot())::text AS xm) "
        "SELECT a.domain_id, a.seq, EXISTS (SELECT 1 FROM domains d WHERE d.id = a.domain_id), a.mn, a.mx, a.cnt, x.xm, a.xl, a.xh "
        "FROM x LEFT JOIN a ON a.seq = a.dm ORDER BY a.seq";
    char p1[32], p2[32], p3[32];
    snprintf(p1, sizeof(p1), "%llu", (unsigned long long)pos->cursor);
    snprintf(p2, sizeof(p2), "%llu", (unsigned long long)pos->seq);
    snprintf(p3, sizeof(p3), "%u", limit);
    const char *pv[3] = { p1, p2, p3 };
    PGresult *r = NULL;
    int ret = rs_exec(c, RS_CHANGES, sql, 3, pv, &r, "changes_page");
    if (ret != 0) return ret;
    bool first = pos->seq == 0, bad = false;
    uint64_t xmin = cell_u64(c, r, 0, 6, &bad);
    uint64_t settle = first ? xmin : pos->settle;
    uint64_t mx = pos->seq;
    int64_t cnt = 0;
    for (int i = 0; i < PQntuples(r) && !bad; i++) {
        if (PQgetisnull(r, i, 0)) continue;                        /* the empty window: x alone */
        mx = cell_u64(c, r, i, 4, &bad);
        cnt = cell_i64(c, r, i, 5, &bad);
        db_change_entry_t e;
        e.seq = cell_u64(c, r, i, 1, &bad);
        e.domain_id = cell_i64(c, r, i, 0, &bad);
        e.op = cell_true(r, i, 2) ? DB_CHANGE_UPSERT : DB_CHANGE_DELETE;
        e.pos_lo = cell_u64(c, r, i, 7, &bad);
        e.pos_hi = cell_u64(c, r, i, 8, &bad);
        if (bad) break;
        if (cb(ud, &e) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    PQclear(r);
    if (ret != 0) return ret;
    if (bad) return -1;
    if (first && pos->cursor > 0) {
        if (pos->cursor > xmin) {
            *gap = true;                                           /* a cursor from the future: not this cluster's counter */
        } else {
            /* pruned rows (the heuristic of changes_since): the log has rows, its first seq is not 1 and nothing is left below the cursor */
            const char *gv[1] = { p1 };
            ret = rs_exec(c, RS_GAP, "SELECT (SELECT min(seq) FROM karidns_changes), EXISTS (SELECT 1 FROM karidns_changes WHERE xid < $1::xid8)",
                          1, gv, &r, "changes_page");
            if (ret != 0) return ret;
            if (cell_i64(c, r, 0, 0, &bad) > 1 && !cell_true(r, 0, 1)) *gap = true;      /* (NULL: 0) */
            PQclear(r);
            if (bad) return -1;
        }
    }
    *more = cnt >= (int64_t)limit;
    if (*more) {
        pos->seq = mx;
        pos->settle = settle;
    } else {
        pos->cursor = settle > pos->cursor ? settle : pos->cursor;
        pos->seq = pos->settle = 0;
    }
    return 0;
}

static int ensure_listen(db_conn_t *c) {
    if (c->listening) return 0;
    if (c->listen_failed) return -1;                    /* refused for good (a standby cannot LISTEN): do not ask at every loop */
    if (c->in_snapshot) {
        set_err(c, "LISTEN: a snapshot is open");
        return -1;
    }
    int rc = exec_cmd(c, c->chan_reload ? "LISTEN karidns_reload" : "LISTEN karidns_changes", "LISTEN");
    if (rc == 0) c->listening = true;
    else if (rc == -1) c->listen_failed = true;         /* not a transient condition */
    return rc;
}

static int pg_wait_fd(db_conn_t *c) {
    if (ensure_listen(c) != 0) return -1;
    return PQsocket(c->pg);
}

static int pg_drain_notifications(db_conn_t *c, bool *changed) {
    if (changed) *changed = false;
    if (!PQconsumeInput(c->pg) || PQstatus(c->pg) != CONNECTION_OK) {
        char line[260];
        first_line(PQerrorMessage(c->pg), line, sizeof(line));
        set_err(c, "postgresql: the connection was lost: %s (retry later)", line);
        return DB_ERR_RETRY;
    }
    PGnotify *n;
    while ((n = PQnotifies(c->pg)) != NULL) {
        if (changed) *changed = true;
        c->nver++;
        PQfreemem(n);
    }
    return 0;
}

/* LISTEN is refused (a hot standby: "cannot execute LISTEN during recovery"), so nothing announces a commit.  The standby does
 * replay the change log, so poll_version() looks at it instead: the counter is a fingerprint of karidns_changes, the number of rows
 * and the highest seq (one index-only count per poll interval, over at most the 1,000,000 rows the log keeps).  A row that a
 * transaction adds when it commits late changes the number of rows even when its seq is below the highest one; pruning changes the
 * highest seq.  The query also notices a connection that died.  A database without the change log has nothing to look at: the
 * counter stays 0, as a primary without the triggers never notifies either. */
static int pg_poll_log(db_conn_t *c, uint64_t *version) {
    if (!c->has_changes) {
        c->nver = 0;
        *version = 0;
        return 0;
    }
    PGresult *r = NULL;
    int ret = exec_rows(c, "SELECT count(*)::text, coalesce(max(seq), 0)::text FROM karidns_changes", 0, NULL, &r, "poll the change log");
    if (ret != 0) return ret;
    bool bad = false;
    uint64_t n = cell_u64(c, r, 0, 0, &bad), mx = cell_u64(c, r, 0, 1, &bad);
    PQclear(r);
    if (bad) return -1;
    c->nver = mx * 2654435761u + n;
    *version = c->nver;
    return 0;
}

/* The change detector of the auto reload loop (dns_db_driver.h poll_version): LISTEN is started by the first call, so
 * the baseline is taken after it; the counter changes when a notification arrived.  A ping now and then notices a
 * connection that died silently (the server went away, a firewall dropped it).  When LISTEN is refused for good (a standby),
 * the counter is the fingerprint of the change log instead (pg_poll_log). */
static int pg_poll_version(db_conn_t *c, uint64_t *version, bool *replaced) {
    *replaced = false;
    int ret = ensure_listen(c);
    if (ret != 0) return c->listen_failed ? pg_poll_log(c, version) : ret;
    ret = pg_drain_notifications(c, NULL);
    if (ret != 0) return ret;
    time_t now = time(NULL);
    if (now - c->last_ping >= PG_PING_SECONDS || now < c->last_ping) {
        c->last_ping = now;
        PGresult *r = NULL;
        ret = exec_rows(c, "SELECT 1", 0, NULL, &r, "ping");
        if (ret != 0) return ret;
        PQclear(r);
        ret = pg_drain_notifications(c, NULL);
        if (ret != 0) return ret;
    }
    *version = c->nver;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* reload requests and the status row (B11)                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

#define REQ_CHUNK 500                       /* requests per query (the table keeps 1000, but nothing here depends on a trigger) */
#define REQ_STR2(x) #x
#define REQ_STR(x) REQ_STR2(x)

static int pg_watch_requests(db_conn_t *c) {
    if (c->listening && !c->chan_reload) {
        set_err(c, "watch_requests: the connection already listens to karidns_changes");
        return -1;
    }
    c->chan_reload = true;
    return ensure_listen(c);
}

static int pg_requests_max(db_conn_t *c, uint64_t *generation) {
    if (!c->has_reload_requests) {
        set_err(c, "karidns_reload_requests does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    if (c->in_snapshot) {
        set_err(c, "requests_max: a snapshot is open");
        return -1;
    }
    PGresult *r = NULL;
    int ret = exec_rows(c, "SELECT coalesce(max(generation), 0)::text FROM karidns_reload_requests", 0, NULL, &r, "requests_max");
    if (ret != 0) return ret;
    bool bad = false;
    const int64_t g = cell_i64(c, r, 0, 0, &bad);
    *generation = g < 0 ? 0 : (uint64_t)g;              /* (a negative one: 0, as the zone generation, review D-5; strtoull() made it a huge one) */
    PQclear(r);
    return bad ? -1 : 0;
}

static int pg_reload_requests(db_conn_t *c, uint64_t after, db_reload_cb cb, void *ud, uint64_t *max_gen, bool *gap) {
    if (!c->has_reload_requests) {
        set_err(c, "karidns_reload_requests does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    if (c->in_snapshot) {
        set_err(c, "reload_requests: a snapshot is open");
        return -1;
    }
    uint64_t cur = after;
    bool first = true, g = false;
    int ret = 0;
    while (ret == 0) {
        char p[32];
        snprintf(p, sizeof(p), "%llu", (unsigned long long)cur);
        const char *pv[1] = { p };
        PGresult *r = NULL;
        ret = exec_rows(c, "SELECT generation, zone, force FROM karidns_reload_requests WHERE generation > $1::bigint ORDER BY generation LIMIT " REQ_STR(REQ_CHUNK),
                        1, pv, &r, "reload_requests");
        if (ret != 0) break;
        int n = PQntuples(r);
        for (int i = 0; i < n && ret == 0; i++) {
            bool bad = false;
            db_reload_row_t row;
            row.generation = (uint64_t)cell_i64(c, r, i, 0, &bad);
            row.zone = cell_text(c, r, i, 1, "karidns_reload_requests", (int64_t)row.generation, "zone", &bad);
            row.force = cell_true(r, i, 2);
            if (bad) {
                ret = -1;
                break;
            }
            if (first) {
                g = row.generation != after + 1;      /* pruned or rolled back requests lie between */
                first = false;
            }
            if (row.generation <= cur) continue;      /* cannot happen (ORDER BY, > cur); never go backwards */
            cur = row.generation;
            if (cb(ud, &row) != 0) ret = DB_STOPPED;
        }
        PQclear(r);
        if (n < REQ_CHUNK) break;
    }
    if (max_gen) *max_gen = cur;
    if (gap) *gap = g;
    return ret;
}

static int pg_report_status(db_conn_t *c, const db_status_t *st) {
    if (!c->has_server_status) {
        set_err(c, "karidns_server_status does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    if (c->in_snapshot) {
        set_err(c, "report_status: a snapshot is open");     /* the write must not share the read snapshot */
        return -1;
    }
    if (!st || !st->server_id || !*st->server_id || strlen(st->server_id) > 64) {
        set_err(c, "report_status: the server id must be 1 to 64 bytes");
        return -1;
    }
    char gen[32];
    snprintf(gen, sizeof(gen), "%llu", (unsigned long long)st->generation);
    const char *pv[4] = { st->server_id, gen, st->ok ? "t" : "f", st->failed_zones ? st->failed_zones : "" };
    int rc = exec_cmd(c, "BEGIN READ WRITE", "report status");     /* the session is read only by default: this one writes */
    if (rc != 0) return rc;
    PGresult *r = PQexecParams(c->pg,
                               "INSERT INTO karidns_server_status (server_id, generation, applied_at, ok, failed_zones) "
                               "VALUES ($1, $2::bigint, now(), $3::boolean, $4) "
                               "ON CONFLICT (server_id) DO UPDATE SET generation = EXCLUDED.generation, applied_at = EXCLUDED.applied_at, "
                               "ok = EXCLUDED.ok, failed_zones = EXCLUDED.failed_zones",
                               4, NULL, pv, NULL, NULL, 0);
    if (!r || PQresultStatus(r) != PGRES_COMMAND_OK) {
        rc = pq_fail(c, r, "report status");
        PQclear(r);
        PQclear(PQexec(c->pg, "ROLLBACK"));                     /* ends the aborted transaction (harmless when the connection is gone) */
        return rc;
    }
    PQclear(r);
    return exec_cmd(c, "COMMIT", "report status");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* M2: write access for the ZoneImporter (dns_db_driver.h).  Only open_write() connections get here.                 */
/* ------------------------------------------------------------------------------------------------------------- */

/* The statements of the write functions.  Every one is prepared once per session (PQprepare) and run with PQexecPrepared: the values are
 * parameters, never part of the SQL text.  A prepared statement outlives a rolled back transaction. */
enum {
    W_LOCK, W_CREATE, W_DEL_ALL_TAGS, W_DEL_ALL_TD, W_DEL_ALL_REC, W_DEL_IDS_TAGS, W_DEL_IDS_TD, W_DEL_IDS_REC, W_INS_REC, W_INS_TAGS,
    W_INS_TD, W_DEL_TAGDEFS, W_INS_TAGDEF, W_DEL_META, W_INS_META, W_SET_VIEW, W_REQ, W_HAS_KEYS, W_UPD_REC, W_UPD_ORD, W_INS_DNSSEC,
    W_ACTOR, W_ZGEN, W_BUMP_API, W_SET_SOA, W_INS_VER, W_INS_VERR, W_N
};
static const struct { const char *sql; int np; } W_STMT[W_N] = {
    [W_LOCK] = { "SELECT pg_advisory_xact_lock(hashtextextended('karidns-zone:' || $1::text, 0))", 1 },
    [W_CREATE] = { "INSERT INTO domains (name, type) VALUES ($1, $2) RETURNING id", 2 },
    [W_DEL_ALL_TAGS] = { "DELETE FROM karidns_record_tags WHERE record_id IN (SELECT id FROM records WHERE domain_id = $1::bigint)", 1 },
    [W_DEL_ALL_TD] = { "DELETE FROM karidns_record_tinydns WHERE record_id IN (SELECT id FROM records WHERE domain_id = $1::bigint)", 1 },
    [W_DEL_ALL_REC] = { "DELETE FROM records WHERE domain_id = $1::bigint", 1 },
    [W_DEL_IDS_TAGS] = { "DELETE FROM karidns_record_tags WHERE record_id = ANY ($1::bigint[]) AND record_id IN (SELECT id FROM records WHERE domain_id = $2::bigint)", 2 },
    [W_DEL_IDS_TD] = { "DELETE FROM karidns_record_tinydns WHERE record_id = ANY ($1::bigint[]) AND record_id IN (SELECT id FROM records WHERE domain_id = $2::bigint)", 2 },
    [W_DEL_IDS_REC] = { "DELETE FROM records WHERE id = ANY ($1::bigint[]) AND domain_id = $2::bigint", 2 },
    [W_INS_REC] = { "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth, ordername) "
                    "VALUES ($1::bigint, $2, $3, $4, $5::bigint, $6::bigint, $7::boolean, $8::boolean, $9) RETURNING id", 9 },
    [W_INS_TAGS] = { "INSERT INTO karidns_record_tags (record_id, location_tag, ecs_tag) VALUES ($1::bigint, $2, $3)", 3 },
    [W_INS_TD] = { "INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES ($1::bigint, $2::bigint, $3, $4::boolean)", 4 },
    [W_DEL_TAGDEFS] = { "DELETE FROM karidns_zone_tagdefs WHERE domain_id = $1::bigint AND ($2::text IS NULL OR kind = $2::text) "
                        "AND ($3::text IS NULL OR lower(tag) = lower($3::text))", 3 },
    [W_INS_TAGDEF] = { "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES ($1::bigint, $2, $3, $4)", 4 },
    [W_DEL_META] = { "DELETE FROM domainmetadata WHERE domain_id = $1::bigint AND upper(kind) = upper($2::text)", 2 },
    [W_INS_META] = { "INSERT INTO domainmetadata (domain_id, kind, content) VALUES ($1::bigint, $2, $3)", 3 },
    [W_SET_VIEW] = { "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES ($1::bigint, $2) ON CONFLICT DO NOTHING", 2 },
    [W_REQ] = { "INSERT INTO karidns_reload_requests (zone, force) VALUES ($1, $2::boolean)", 2 },
    [W_HAS_KEYS] = { "SELECT EXISTS (SELECT 1 FROM cryptokeys WHERE domain_id = $1::bigint)", 1 },
    [W_UPD_REC] = { "UPDATE records SET content = coalesce($3::text, content), ordername = $4::text, auth = $5::boolean WHERE id = $1::bigint AND domain_id = $2::bigint", 5 },
    [W_UPD_ORD] = { "UPDATE records r SET ordername = u.o, auth = u.a FROM unnest($1::bigint[], $2::text[], $3::boolean[]) AS u(id, o, a) "
                    "WHERE r.id = u.id AND r.domain_id = $4::bigint", 4 },
    [W_INS_DNSSEC] = { "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth, ordername) "
                       "SELECT $1::bigint, u.n, u.t, u.c, u.ttl, u.prio, false, u.a, u.o "
                       "FROM unnest($2::text[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::boolean[], $8::text[]) AS u(n, t, c, ttl, prio, a, o)", 8 },
    /* items D and E */
    [W_ACTOR] = { "SELECT set_config('karidns.principal', $1, true), set_config('karidns.change_set', $2, true)", 2 },
    [W_ZGEN] = { "SELECT coalesce((SELECT generation FROM karidns_zone_state WHERE domain_id = $1::bigint), 0)", 1 },
    [W_BUMP_API] = { "SELECT karidns_auth.bump_serial(current_schema()::text, $1::integer)", 1 },
    [W_SET_SOA] = { "UPDATE records SET content = $3::text WHERE id = $1::bigint AND domain_id = $2::bigint", 3 },
    [W_INS_VER] = { "INSERT INTO karidns_zone_versions (domain_id, version, kind, change_set, principal_id, principal_name, db_role, comment, serial_before, serial_after, "
                    "generation_before, generation_after, rollback_of, delta_complete) "
                    "SELECT $1::integer, coalesce(max(version), 0) + 1, $2, $3, $4::bigint, $5, coalesce($6::text, session_user::text), $7, $8::bigint, $9::bigint, $10::bigint, $11::bigint, "
                    "$12::integer, $13::boolean FROM karidns_zone_versions WHERE domain_id = $1::integer RETURNING id, version", 13 },
    [W_INS_VERR] = { "INSERT INTO karidns_zone_version_rrsets (version_id, owner, type, before, after) VALUES ($1::bigint, $2, $3, $4, $5)", 5 },
};

/* run statement `idx` with the parameters pv (text, NULL = SQL NULL); the result (when out is set) is for the caller to clear */
static int wq(db_conn_t *c, int idx, const char *const *pv, PGresult **out, ExecStatusType want, const char *what) {
    char name[16];
    snprintf(name, sizeof(name), "kzw%d", idx);
    if (!(c->w_prepared & (1u << idx))) {
        PGresult *p = PQprepare(c->pg, name, W_STMT[idx].sql, W_STMT[idx].np, NULL);
        if (!p || PQresultStatus(p) != PGRES_COMMAND_OK) {
            int ret = pq_fail(c, p, what);
            PQclear(p);
            return ret;
        }
        PQclear(p);
        c->w_prepared |= 1u << idx;
    }
    PGresult *r = PQexecPrepared(c->pg, name, W_STMT[idx].np, pv, NULL, NULL, 0);
    if (!r || PQresultStatus(r) != want) {
        int ret = pq_fail(c, r, what);
        PQclear(r);
        return ret;
    }
    if (out) *out = r;
    else PQclear(r);
    return 0;
}

static int wcheck(db_conn_t *c, const char *fn) {
    if (!c->writable) {
        set_err(c, "%s: the connection is read only (open_write() makes a writable one)", fn);
        return -1;
    }
    if (!c->in_wtxn) {
        set_err(c, "%s: no write transaction is open (w_begin)", fn);
        return -1;
    }
    return 0;
}

static void i64_text(char *buf, size_t cap, int64_t v) { snprintf(buf, cap, "%lld", (long long)v); }

static int pg_w_begin(db_conn_t *c, const char *zone) {
    if (!c->writable) {
        set_err(c, "w_begin: the connection is read only (open_write() makes a writable one)");
        return -1;
    }
    if (c->in_snapshot || c->in_wtxn) {
        set_err(c, "w_begin: a transaction is already open");
        return -1;
    }
    int rc = exec_cmd(c, c->repeatable ? "BEGIN ISOLATION LEVEL REPEATABLE READ READ WRITE" : "BEGIN READ WRITE", "w_begin");
    if (rc != 0) return rc;
    /* the lock against a concurrent importer of the same zone (also one that creates it): a transaction-level advisory lock on the name,
     * which waits lock_timeout (open_write) and ends with the transaction */
    const char *pv[1] = { zone };
    rc = wq(c, W_LOCK, pv, NULL, PGRES_TUPLES_OK, "w_begin (zone lock)");
    /* karidns-zone --audit summary: the audit triggers (db/karidns_ext.pgsql.sql, karidns_auth.enable_audit) log one row per statement and
     * table for this transaction; SET LOCAL ends with it */
    if (rc == 0 && c->audit_summary) rc = exec_cmd(c, "SET LOCAL karidns.audit = 'summary'", "w_begin (audit)");
    /* items D and E: for whom the transaction is: the audit triggers log it, the row level security of the API role reads it */
    if (rc == 0 && c->have_actor) {
        const char *pa[2] = { c->actor_pid, c->actor_cs };
        rc = wq(c, W_ACTOR, pa, NULL, PGRES_TUPLES_OK, "w_begin (actor)");
    }
    if (rc != 0) {
        PQclear(PQexec(c->pg, "ROLLBACK"));            /* a failed w_begin leaves no transaction open */
        return rc;
    }
    c->in_wtxn = c->in_snapshot = true;
    return 0;
}

/* karidns-zone --audit (dns_db_driver.h): a flag the next w_begin() acts on */
static int pg_w_set_audit(db_conn_t *c, bool summary, const char *actor) {
    (void)actor;                                    /* the database role is the PostgreSQL session's own */
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_set_audit: needs a writable connection outside a transaction");
        return -1;
    }
    c->audit_summary = summary;
    return 0;
}

static int pg_w_commit(db_conn_t *c) {
    int ret = wcheck(c, "w_commit");
    if (ret != 0) return ret;
    c->in_wtxn = c->in_snapshot = false;
    return exec_cmd(c, "COMMIT", "w_commit");
}

static int pg_w_rollback(db_conn_t *c) {
    if (!c->in_wtxn) return 0;
    c->in_wtxn = c->in_snapshot = false;
    return exec_cmd(c, "ROLLBACK", "w_rollback");
}

static int pg_w_create_zone(db_conn_t *c, const char *name, const char *type, int64_t *id) {
    int ret = wcheck(c, "w_create_zone");
    if (ret != 0) return ret;
    const char *pv[2] = { name, type ? type : "NATIVE" };
    PGresult *r = NULL;
    if ((ret = wq(c, W_CREATE, pv, &r, PGRES_TUPLES_OK, "w_create_zone")) != 0) return ret;
    bool bad = false;
    *id = cell_i64(c, r, 0, 0, &bad);
    PQclear(r);
    return bad ? -1 : 0;
}

#define W_DEL_CHUNK 1000
#define W_DEL_DNSSEC_CHUNK 200000        /* ids of a DNSSEC delete: 4 MB of text, a statement for a hundred thousand signatures */

static int pg_w_delete_records(db_conn_t *c, int64_t domain_id, const int64_t *ids, size_t n) {
    int ret = wcheck(c, "w_delete_records");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    if (!ids) {
        const char *pv[1] = { did };
        /* the extension rows first: their delete triggers find the zone through the record */
        if (c->has_ext && (ret = wq(c, W_DEL_ALL_TAGS, pv, NULL, PGRES_COMMAND_OK, "w_delete_records")) != 0) return ret;
        if (c->has_ext && (ret = wq(c, W_DEL_ALL_TD, pv, NULL, PGRES_COMMAND_OK, "w_delete_records")) != 0) return ret;
        return wq(c, W_DEL_ALL_REC, pv, NULL, PGRES_COMMAND_OK, "w_delete_records");
    }
    char *arr = malloc(W_DEL_CHUNK * 21 + 4);
    if (!arr) {
        set_err(c, "out of memory");
        return -1;
    }
    for (size_t i = 0; i < n && ret == 0; i += W_DEL_CHUNK) {
        size_t k = n - i < W_DEL_CHUNK ? n - i : W_DEL_CHUNK, o = 0;
        arr[o++] = '{';
        for (size_t j = 0; j < k; j++) o += (size_t)snprintf(arr + o, 24, "%s%lld", j ? "," : "", (long long)ids[i + j]);
        arr[o++] = '}';
        arr[o] = '\0';
        const char *pv[2] = { arr, did };
        if (c->has_ext && (ret = wq(c, W_DEL_IDS_TAGS, pv, NULL, PGRES_COMMAND_OK, "w_delete_records")) == 0)
            ret = wq(c, W_DEL_IDS_TD, pv, NULL, PGRES_COMMAND_OK, "w_delete_records");
        if (ret == 0) ret = wq(c, W_DEL_IDS_REC, pv, NULL, PGRES_COMMAND_OK, "w_delete_records");
    }
    free(arr);
    return ret;
}

static int pg_w_insert_record(db_conn_t *c, int64_t domain_id, const db_record_row_t *row, bool auth, int64_t *id) {
    int ret = wcheck(c, "w_insert_record");
    if (ret != 0) return ret;
    char did[32], ttl[32], prio[32];
    i64_text(did, sizeof(did), domain_id);
    i64_text(ttl, sizeof(ttl), row->ttl);
    i64_text(prio, sizeof(prio), row->prio);
    const char *pv[9] = { did, row->name, row->type, row->content, row->ttl_null ? NULL : ttl, row->prio_null ? NULL : prio,
                          row->disabled ? "t" : "f", auth ? "t" : "f", row->ordername };
    PGresult *r = NULL;
    if ((ret = wq(c, W_INS_REC, pv, &r, PGRES_TUPLES_OK, "w_insert_record")) != 0) return ret;
    bool bad = false;
    *id = cell_i64(c, r, 0, 0, &bad);
    PQclear(r);
    return bad ? -1 : 0;
}

static int ext_missing(db_conn_t *c) {
    set_err(c, "the karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs tables do not exist in this database");
    return DB_ERR_UNAVAILABLE;
}

static int pg_w_insert_tags(db_conn_t *c, int64_t record_id, const char *loc, const char *ecs) {
    int ret = wcheck(c, "w_insert_tags");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    char rid[32];
    i64_text(rid, sizeof(rid), record_id);
    const char *pv[3] = { rid, loc, ecs };
    return wq(c, W_INS_TAGS, pv, NULL, PGRES_COMMAND_OK, "w_insert_tags");
}

static int pg_w_insert_tinydns(db_conn_t *c, int64_t record_id, int64_t ttd, const char *loc, bool countdown) {
    int ret = wcheck(c, "w_insert_tinydns");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    char rid[32], td[32];
    i64_text(rid, sizeof(rid), record_id);
    i64_text(td, sizeof(td), ttd);
    const char *pv[4] = { rid, td, loc, countdown ? "t" : "f" };
    return wq(c, W_INS_TD, pv, NULL, PGRES_COMMAND_OK, "w_insert_tinydns");
}

static int pg_w_delete_tagdefs(db_conn_t *c, int64_t domain_id, const char *kind, const char *tag) {
    int ret = wcheck(c, "w_delete_tagdefs");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[3] = { did, kind, tag };
    return wq(c, W_DEL_TAGDEFS, pv, NULL, PGRES_COMMAND_OK, "w_delete_tagdefs");
}

static int pg_w_insert_tagdef(db_conn_t *c, int64_t domain_id, const char *kind, const char *tag, const char *cidr) {
    int ret = wcheck(c, "w_insert_tagdef");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[4] = { did, kind, tag, cidr };
    return wq(c, W_INS_TAGDEF, pv, NULL, PGRES_COMMAND_OK, "w_insert_tagdef");
}

static int pg_w_delete_meta(db_conn_t *c, int64_t domain_id, const char *kind) {
    int ret = wcheck(c, "w_delete_meta");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[2] = { did, kind };
    return wq(c, W_DEL_META, pv, NULL, PGRES_COMMAND_OK, "w_delete_meta");
}

static int pg_w_insert_meta(db_conn_t *c, int64_t domain_id, const char *kind, const char *content) {
    int ret = wcheck(c, "w_insert_meta");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[3] = { did, kind, content };
    return wq(c, W_INS_META, pv, NULL, PGRES_COMMAND_OK, "w_insert_meta");
}

static int pg_w_set_view(db_conn_t *c, int64_t domain_id, const char *view_name) {
    int ret = wcheck(c, "w_set_view");
    if (ret != 0) return ret;
    if (!c->has_domain_views) {
        set_err(c, "karidns_domain_views does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[2] = { did, view_name };
    return wq(c, W_SET_VIEW, pv, NULL, PGRES_COMMAND_OK, "w_set_view");
}

static int pg_w_request_reload(db_conn_t *c, const char *zone, bool force) {
    int ret = wcheck(c, "w_request_reload");
    if (ret != 0) return ret;
    if (!c->has_reload_requests) {
        set_err(c, "karidns_reload_requests does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    const char *pv[2] = { zone, force ? "t" : "f" };
    return wq(c, W_REQ, pv, NULL, PGRES_COMMAND_OK, "w_request_reload");
}

static int pg_w_zone_has_keys(db_conn_t *c, int64_t domain_id, bool *has) {
    int ret = wcheck(c, "w_zone_has_keys");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[1] = { did };
    PGresult *r = NULL;
    if ((ret = wq(c, W_HAS_KEYS, pv, &r, PGRES_TUPLES_OK, "w_zone_has_keys")) != 0) return ret;
    *has = cell_true(r, 0, 0);
    PQclear(r);
    return 0;
}

/* ---- item C, the signer (dns_db_driver.h): the authoritative flags, one record's ordername / auth / content, the id of the write ---- */
typedef struct { db_auth_cb cb; void *ud; } au_t;

static int au_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    au_t *a = ud;
    bool bad = false;
    const int64_t id = cell_i64(c, r, i, 0, &bad);
    if (bad) return -1;
    return a->cb(a->ud, id, PQgetisnull(r, i, 1) || cell_true(r, i, 1)) != 0 ? DB_STOPPED : 0;
}

static int pg_w_scan_auth(db_conn_t *c, int64_t domain_id, db_auth_cb cb, void *ud) {
    int ret = wcheck(c, "w_scan_auth");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[1] = { did };
    au_t a = { cb, ud };
    return pg_scan(c, "w_scan_auth", "SELECT id, auth FROM records WHERE domain_id = $1::bigint ORDER BY id", 1, pv, au_row, &a);
}

static int pg_w_update_record(db_conn_t *c, int64_t domain_id, int64_t id, const char *content, const char *ordername, bool auth) {
    int ret = wcheck(c, "w_update_record");
    if (ret != 0) return ret;
    char rid[32], did[32];
    i64_text(rid, sizeof(rid), id);
    i64_text(did, sizeof(did), domain_id);
    const char *pv[5] = { rid, did, content, ordername, auth ? "t" : "f" };
    PGresult *r = NULL;
    if ((ret = wq(c, W_UPD_REC, pv, &r, PGRES_COMMAND_OK, "w_update_record")) != 0) return ret;
    bool one = strcmp(PQcmdTuples(r), "1") == 0;
    PQclear(r);
    if (!one) {
        set_err(c, "w_update_record: record %lld is not in zone %lld, was deleted meanwhile, or the role may not change it", (long long)id, (long long)domain_id);
        return DB_ERR_CONFLICT;
    }
    return 0;
}

/* ---- text in a PostgreSQL array literal: {"a","b",NULL} ---- */
typedef struct { char *p; size_t n, cap; bool oom; } abuf_t;

static void ab_put(abuf_t *b, const char *s, size_t len) {
    if (b->oom) return;
    if (b->n + len + 1 > b->cap) {
        size_t nc = (b->cap ? b->cap : 4096) * 2;
        while (nc < b->n + len + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->n, s, len);
    b->n += len;
    b->p[b->n] = '\0';
}

/* one element (NULL = NULL); a comma first when it is not the first */
static void ab_elem(abuf_t *b, bool first, const char *s) {
    if (!first) ab_put(b, ",", 1);
    if (!s) {
        ab_put(b, "NULL", 4);
        return;
    }
    ab_put(b, "\"", 1);
    for (const char *q = s; *q;) {
        size_t run = strcspn(q, "\"\\");
        ab_put(b, q, run);
        q += run;
        if (*q) {
            ab_put(b, "\\", 1);
            ab_put(b, q, 1);
            q++;
        }
    }
    ab_put(b, "\"", 1);
}

static void ab_begin(abuf_t *b) {
    b->n = 0;
    ab_put(b, "{", 1);
}
static void ab_end(abuf_t *b) { ab_put(b, "}", 1); }

#define W_ROWS_CHUNK 20000              /* rows of text per statement (the statement is as big as the text) */

static int pg_w_update_orders(db_conn_t *c, int64_t domain_id, const db_order_t *v, size_t n) {
    int ret = wcheck(c, "w_update_orders");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    abuf_t ids = {0}, ons = {0}, aus = {0};
    for (size_t i = 0; i < n && ret == 0; i += W_ROWS_CHUNK) {
        size_t k = n - i < W_ROWS_CHUNK ? n - i : W_ROWS_CHUNK;
        ab_begin(&ids);
        ab_begin(&ons);
        ab_begin(&aus);
        for (size_t j = 0; j < k; j++) {
            char idt[32];
            i64_text(idt, sizeof(idt), v[i + j].id);
            ab_elem(&ids, j == 0, idt);
            ab_elem(&ons, j == 0, v[i + j].ordername);
            ab_elem(&aus, j == 0, v[i + j].auth ? "t" : "f");
        }
        ab_end(&ids);
        ab_end(&ons);
        ab_end(&aus);
        if (ids.oom || ons.oom || aus.oom) {
            set_err(c, "out of memory");
            ret = -1;
            break;
        }
        const char *pv[4] = { ids.p, ons.p, aus.p, did };
        PGresult *r = NULL;
        if ((ret = wq(c, W_UPD_ORD, pv, &r, PGRES_COMMAND_OK, "w_update_orders")) != 0) break;
        bool all = strtoull(PQcmdTuples(r), NULL, 10) == k;
        PQclear(r);
        if (!all) {
            set_err(c, "w_update_orders: a record of zone %lld is gone, or the role may not change it", (long long)domain_id);
            ret = DB_ERR_CONFLICT;
        }
    }
    free(ids.p);
    free(ons.p);
    free(aus.p);
    return ret;
}

static int pg_w_insert_dnssec(db_conn_t *c, int64_t domain_id, const db_ins_t *v, size_t n) {
    int ret = wcheck(c, "w_insert_dnssec");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    abuf_t nm = {0}, ty = {0}, ct = {0}, tt = {0}, pr = {0}, au = {0}, on = {0};
    for (size_t i = 0; i < n && ret == 0; i += W_ROWS_CHUNK) {
        size_t k = n - i < W_ROWS_CHUNK ? n - i : W_ROWS_CHUNK;
        ab_begin(&nm);
        ab_begin(&ty);
        ab_begin(&ct);
        ab_begin(&tt);
        ab_begin(&pr);
        ab_begin(&au);
        ab_begin(&on);
        for (size_t j = 0; j < k; j++) {
            const db_record_row_t *r = v[i + j].row;
            char t[32], p[32];
            i64_text(t, sizeof(t), r->ttl);
            i64_text(p, sizeof(p), r->prio);
            ab_elem(&nm, j == 0, r->name);
            ab_elem(&ty, j == 0, r->type);
            ab_elem(&ct, j == 0, r->content);
            ab_elem(&tt, j == 0, r->ttl_null ? NULL : t);
            ab_elem(&pr, j == 0, r->prio_null ? NULL : p);
            ab_elem(&au, j == 0, v[i + j].auth ? "t" : "f");
            ab_elem(&on, j == 0, r->ordername);
        }
        ab_end(&nm);
        ab_end(&ty);
        ab_end(&ct);
        ab_end(&tt);
        ab_end(&pr);
        ab_end(&au);
        ab_end(&on);
        if (nm.oom || ty.oom || ct.oom || tt.oom || pr.oom || au.oom || on.oom) {
            set_err(c, "out of memory");
            ret = -1;
            break;
        }
        const char *pv[8] = { did, nm.p, ty.p, ct.p, tt.p, pr.p, au.p, on.p };
        PGresult *r = NULL;
        if ((ret = wq(c, W_INS_DNSSEC, pv, &r, PGRES_COMMAND_OK, "w_insert_dnssec")) != 0) break;
        bool all = strtoull(PQcmdTuples(r), NULL, 10) == k;
        PQclear(r);
        if (!all) {
            set_err(c, "w_insert_dnssec: fewer rows were inserted than given");
            ret = -1;
        }
    }
    free(nm.p);
    free(ty.p);
    free(ct.p);
    free(tt.p);
    free(pr.p);
    free(au.p);
    free(on.p);
    return ret;
}

static int pg_w_set_snapshot(db_conn_t *c, bool on) {
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_set_snapshot: needs a writable connection outside a transaction");
        return -1;
    }
    c->repeatable = on;
    return 0;
}

static int pg_w_delete_dnssec(db_conn_t *c, int64_t domain_id, const int64_t *ids, size_t n) {
    int ret = wcheck(c, "w_delete_dnssec");
    if (ret != 0) return ret;
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    char *arr = malloc((size_t)W_DEL_DNSSEC_CHUNK * 21 + 4);
    if (!arr) {
        set_err(c, "out of memory");
        return -1;
    }
    for (size_t i = 0; i < n && ret == 0; i += W_DEL_DNSSEC_CHUNK) {
        size_t k = n - i < W_DEL_DNSSEC_CHUNK ? n - i : W_DEL_DNSSEC_CHUNK, o = 0;
        arr[o++] = '{';
        for (size_t j = 0; j < k; j++) o += (size_t)snprintf(arr + o, 24, "%s%lld", j ? "," : "", (long long)ids[i + j]);
        arr[o++] = '}';
        arr[o] = '\0';
        const char *pv[2] = { arr, did };
        ret = wq(c, W_DEL_IDS_REC, pv, NULL, PGRES_COMMAND_OK, "w_delete_dnssec");
    }
    free(arr);
    return ret;
}

static int pg_w_mark(db_conn_t *c, uint64_t *mark) {
    *mark = 0;                                      /* the transaction id is the mark */
    return wcheck(c, "w_mark");
}

static int pg_w_write_id(db_conn_t *c, uint64_t mark, db_write_id_t *id) {
    (void)mark;
    memset(id, 0, sizeof(*id));
    int ret = wcheck(c, "w_write_id");
    if (ret != 0) return ret;
    PGresult *r = NULL;
    if ((ret = exec_rows(c, "SELECT pg_current_xact_id()::text", 0, NULL, &r, "w_write_id")) != 0) return ret;
    snprintf(id->xid, sizeof(id->xid), "%s", PQgetvalue(r, 0, 0));
    PQclear(r);
    return 0;
}

/* ---- items D and E: karidns-zone apply (dns_db_driver.h) ---- */
static int pg_w_set_actor(db_conn_t *c, const db_actor_t *a) {
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_set_actor: needs a writable connection outside a transaction");
        return -1;
    }
    c->have_actor = false;
    c->actor_pid[0] = c->actor_cs[0] = '\0';
    if (!a) return 0;
    if (a->has_principal) snprintf(c->actor_pid, sizeof(c->actor_pid), "%lld", (long long)a->principal_id);
    if (a->change_set) snprintf(c->actor_cs, sizeof(c->actor_cs), "%s", a->change_set);
    c->have_actor = a->has_principal || a->change_set;          /* the name is looked up by the audit trigger: karidns_auth.principals */
    return 0;
}

static int pg_w_zone_generation(db_conn_t *c, int64_t domain_id, uint64_t *generation) {
    int ret = wcheck(c, "w_zone_generation");
    if (ret != 0) return ret;
    *generation = 0;
    if (!c->has_zone_state) {
        set_err(c, "karidns_zone_state does not exist in this database (apply db/karidns_ext.pgsql.sql)");
        return DB_ERR_UNAVAILABLE;
    }
    char did[32];
    i64_text(did, sizeof(did), domain_id);
    const char *pv[1] = { did };
    PGresult *r = NULL;
    if ((ret = wq(c, W_ZGEN, pv, &r, PGRES_TUPLES_OK, "w_zone_generation")) != 0) return ret;
    bool bad = false;
    const int64_t g = cell_i64(c, r, 0, 0, &bad);
    *generation = g < 0 ? 0 : (uint64_t)g;                  /* (a negative one, which the schema's CHECK forbids, is 0: as SQLite3 and the manifest, review D-5) */
    PQclear(r);
    return bad ? -1 : 0;
}

static int pg_w_bump_serial(db_conn_t *c, int64_t domain_id, int64_t soa_id, const char *new_content, bool via_api, uint32_t *serial) {
    int ret = wcheck(c, "w_bump_serial");
    if (ret != 0) return ret;
    char did[32], sid[32];
    i64_text(did, sizeof(did), domain_id);
    i64_text(sid, sizeof(sid), soa_id);
    if (via_api) {
        const char *pv[1] = { did };
        PGresult *r = NULL;
        if ((ret = wq(c, W_BUMP_API, pv, &r, PGRES_TUPLES_OK, "w_bump_serial")) != 0) return ret;
        bool bad = false;
        *serial = (uint32_t)cell_i64(c, r, 0, 0, &bad);
        PQclear(r);
        return bad ? -1 : 0;
    }
    const char *pv[3] = { sid, did, new_content };
    PGresult *r = NULL;
    if ((ret = wq(c, W_SET_SOA, pv, &r, PGRES_COMMAND_OK, "w_bump_serial")) != 0) return ret;
    bool one = strcmp(PQcmdTuples(r), "1") == 0;
    PQclear(r);
    if (!one) {
        set_err(c, "w_bump_serial: the SOA record %lld is not in zone %lld, or the role may not change it", (long long)soa_id, (long long)domain_id);
        return DB_ERR_CONFLICT;
    }
    return 0;
}

static int pg_w_insert_version(db_conn_t *c, int64_t domain_id, const db_version_t *v, uint32_t *number, int64_t *id) {
    int ret = wcheck(c, "w_insert_version");
    if (ret != 0) return ret;
    if (!c->has_versions) {
        set_err(c, "karidns_zone_versions does not exist in this database (apply db/karidns_ext.pgsql.sql)");
        return DB_ERR_UNAVAILABLE;
    }
    char did[32], pid[32], sb[32], sa[32], gb[32], ga[32], rb[16];
    i64_text(did, sizeof(did), domain_id);
    i64_text(pid, sizeof(pid), v->principal_id);
    i64_text(sb, sizeof(sb), v->serial_before);
    i64_text(sa, sizeof(sa), v->serial_after);
    i64_text(gb, sizeof(gb), (int64_t)v->generation_before);
    i64_text(ga, sizeof(ga), (int64_t)v->generation_after);
    snprintf(rb, sizeof(rb), "%u", (unsigned)v->rollback_of);
    const char *pv[13] = { did, v->kind, v->change_set, v->has_principal ? pid : NULL, v->principal_name, v->db_role, v->comment, v->has_serial_before ? sb : NULL,
                           v->has_serial_after ? sa : NULL, gb, ga, v->rollback_of ? rb : NULL, v->delta_complete ? "t" : "f" };
    PGresult *r = NULL;
    if ((ret = wq(c, W_INS_VER, pv, &r, PGRES_TUPLES_OK, "w_insert_version")) != 0) return ret;
    bool bad = false;
    *id = cell_i64(c, r, 0, 0, &bad);
    *number = (uint32_t)cell_i64(c, r, 0, 1, &bad);
    PQclear(r);
    return bad ? -1 : 0;
}

static int pg_w_insert_version_rrset(db_conn_t *c, int64_t version_id, const char *owner, const char *type, const char *before, const char *after) {
    int ret = wcheck(c, "w_insert_version_rrset");
    if (ret != 0) return ret;
    char vid[32];
    i64_text(vid, sizeof(vid), version_id);
    const char *pv[5] = { vid, owner, type, before, after };
    return wq(c, W_INS_VERR, pv, NULL, PGRES_COMMAND_OK, "w_insert_version_rrset");
}

/* notice receiver of ANALYZE (SKIP_LOCKED): the WARNING "skipping analyze of ... --- lock not available" has SQLSTATE 55P03 (the text is
 * translated, the code is not) */
static void analyze_notice(void *arg, const PGresult *res) {
    const char *s = PQresultErrorField(res, PG_DIAG_SQLSTATE);
    if (s && strcmp(s, "55P03") == 0) *(bool *)arg = true;
}

/* 0.7: ANALYZE records after a bulk import (dns_db_driver.h).  One query first:
 *  - may the role?  A role that may not analyze the table only gets a WARNING from ANALYZE, so ask: the owner (or a member of the owning
 *    role) may, and on PostgreSQL 17 and later a role with MAINTAIN on the table (has_table_privilege() knows no MAINTAIN before 17 and raises
 *    an error, so the text is chosen here).  `records` is resolved through the search_path (the dataset's schema), as ANALYZE resolves it; a
 *    missing table is "may not".
 *  - is it needed?  Never analyzed (by anyone: last_analyze and last_autoanalyze NULL), or at least autovacuum's default trigger of rows
 *    changed since (autovacuum_analyze_threshold 50 + autovacuum_analyze_scale_factor 0.1 * reltuples): autovacuum would analyze soon anyway,
 *    this closes the window.  A huge table is not analyzed again after every re-sign of one zone.  A backend flushes its counters at most
 *    once a second, so n_mod_since_analyze may not have the caller's last commits yet: on PostgreSQL 15 and later they are flushed first
 *    (pg_stat_force_next_flush() takes effect when that statement ends; without it, counts flushed after the ANALYZE would also be counted
 *    against the new statistics), and the caller's own count is taken when larger (older servers; a failure of the flush is ignored).
 * Then ANALYZE (SKIP_LOCKED) (PostgreSQL 12 and later; the schema needs 13): it does not wait for SHARE UPDATE EXCLUSIVE, so it never queues
 * behind, nor (after deadlock_timeout) cancels, a running autovacuum; a skip is DB_ANALYZE_SKIPPED, seen by its notice. */
static int pg_w_analyze(db_conn_t *c, uint64_t changed, db_analyze_t *res) {
    *res = DB_ANALYZE_DENIED;
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_analyze: needs a writable connection outside a transaction");
        return -1;
    }
    char nb[24];
    snprintf(nb, sizeof(nb), "%llu", (unsigned long long)changed);
    const char *pv[1] = { nb };
    const char *sql = PQserverVersion(c->pg) >= 170000
        ? "SELECT pg_has_role(k.relowner, 'USAGE') OR has_table_privilege(k.oid, 'MAINTAIN'), "
          "(s.last_analyze IS NULL AND s.last_autoanalyze IS NULL) OR GREATEST(COALESCE(s.n_mod_since_analyze, 0), $1::bigint) >= 50 + 0.1 * GREATEST(k.reltuples, 0) "
          "FROM pg_class k LEFT JOIN pg_stat_all_tables s ON s.relid = k.oid WHERE k.oid = to_regclass('records')"
        : "SELECT pg_has_role(k.relowner, 'USAGE'), "
          "(s.last_analyze IS NULL AND s.last_autoanalyze IS NULL) OR GREATEST(COALESCE(s.n_mod_since_analyze, 0), $1::bigint) >= 50 + 0.1 * GREATEST(k.reltuples, 0) "
          "FROM pg_class k LEFT JOIN pg_stat_all_tables s ON s.relid = k.oid WHERE k.oid = to_regclass('records')";
    PGresult *r = NULL;
    if (PQserverVersion(c->pg) >= 150000) PQclear(PQexec(c->pg, "SELECT pg_stat_force_next_flush()"));
    int ret = exec_rows(c, sql, 1, pv, &r, "w_analyze (statistics)");
    if (ret != 0) return ret;
    bool may = PQntuples(r) == 1 && !PQgetisnull(r, 0, 0) && PQgetvalue(r, 0, 0)[0] == 't';
    bool stale = may && !PQgetisnull(r, 0, 1) && PQgetvalue(r, 0, 1)[0] == 't';
    PQclear(r);
    if (!may) return 0;
    if (!stale) {
        *res = DB_ANALYZE_NOT_NEEDED;
        return 0;
    }
    bool skipped = false;
    PQsetNoticeReceiver(c->pg, analyze_notice, &skipped);
    ret = exec_cmd(c, "ANALYZE (SKIP_LOCKED) records", "w_analyze");
    PQsetNoticeReceiver(c->pg, ignore_notice, NULL);
    if (ret != 0) return ret;
    *res = skipped ? DB_ANALYZE_SKIPPED : DB_ANALYZE_DONE;
    return 0;
}

const db_driver_t db_driver_postgresql = {
    .name = "postgresql",
    .open = pg_open, .close = pg_close, .errmsg = pg_errmsg, .check_schema = pg_check_schema,
    .begin_snapshot = pg_begin_snapshot, .end_snapshot = pg_end_snapshot, .list_zones = pg_list_zones,
    .scan_records = pg_scan_records, .scan_metadata = pg_scan_metadata, .zones_with_keys = pg_zones_with_keys,
    .changes_since = pg_changes_since, .wait_fd = pg_wait_fd, .drain_notifications = pg_drain_notifications,
    .report_status = pg_report_status, .changes_max = pg_changes_max, .changes_cover = pg_changes_cover, .scan_records_range = pg_scan_records_range,
    .scan_domain_views = pg_scan_domain_views, .scan_profiles = pg_scan_profiles, .scan_ext = pg_scan_ext,
    .poll_version = pg_poll_version,
    .changes_unsettled = true,
    .watch_requests = pg_watch_requests, .requests_max = pg_requests_max, .reload_requests = pg_reload_requests,
    .schema_findings = pg_schema_findings,      /* B12 */
    .find_zone = pg_find_zone,                  /* B13 */
    .find_zones_in = pg_find_zones_in,          /* 0.7: the lookup of a name */
    .scan_records_in = pg_scan_records_in, .scan_metadata_in = pg_scan_metadata_in, .scan_ext_in = pg_scan_ext_in, .zones_with_keys_in = pg_zones_with_keys_in,      /* B13b */
    .scan_apex = pg_scan_apex,                  /* D1a step 6 */
    .signer_waiting = pg_signer_waiting,        /* 0.7 signer-wait: the zones that wait for the signer at a start */
    .count_domains = pg_count_domains, .manifest_page = pg_manifest_page, .current_cursor = pg_current_cursor, .changes_page = pg_changes_page,      /* 0.7 store, WP3 */
    /* M2, the ZoneImporter: write access (open_write connections only) */
    .open_write = pg_open_write, .w_begin = pg_w_begin, .w_commit = pg_w_commit, .w_rollback = pg_w_rollback,
    .w_create_zone = pg_w_create_zone, .w_delete_records = pg_w_delete_records, .w_insert_record = pg_w_insert_record,
    .w_insert_tags = pg_w_insert_tags, .w_insert_tinydns = pg_w_insert_tinydns, .w_delete_tagdefs = pg_w_delete_tagdefs,
    .w_insert_tagdef = pg_w_insert_tagdef, .w_delete_meta = pg_w_delete_meta, .w_insert_meta = pg_w_insert_meta,
    .w_set_view = pg_w_set_view, .w_request_reload = pg_w_request_reload, .w_zone_has_keys = pg_w_zone_has_keys,
    .w_set_audit = pg_w_set_audit,              /* schema version 3 */
    /* item C, the signer */
    .w_scan_auth = pg_w_scan_auth, .w_update_record = pg_w_update_record, .w_mark = pg_w_mark, .w_write_id = pg_w_write_id,
    .w_delete_dnssec = pg_w_delete_dnssec, .w_update_orders = pg_w_update_orders, .w_insert_dnssec = pg_w_insert_dnssec,
    .w_set_snapshot = pg_w_set_snapshot,
    /* items D and E */
    .w_set_actor = pg_w_set_actor, .w_zone_generation = pg_w_zone_generation, .w_bump_serial = pg_w_bump_serial,
    .w_insert_version = pg_w_insert_version, .w_insert_version_rrset = pg_w_insert_version_rrset,
    .w_analyze = pg_w_analyze,                  /* 0.7: statistics after a bulk import */
};

#endif /* KARIDNS_DB_POSTGRESQL */
