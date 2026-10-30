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

static int64_t cell_i64(PGresult *r, int row, int col) { return PQgetisnull(r, row, col) ? 0 : strtoll(PQgetvalue(r, row, col), NULL, 10); }
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

static int pg_open(db_conn_t **out, const db_source_t *src, char *err, size_t errlen) {
    *out = NULL;
    if (!src || !src->conninfo_file || !*src->conninfo_file) {
        snprintf(err, errlen, "postgresql: no conninfo-file given");
        return -1;
    }
    char conninfo[PG_CONNINFO_MAX];
    if (read_conninfo(src->conninfo_file, conninfo, sizeof(conninfo), err, errlen) != 0) return -1;
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
    const char *vl[] = { "karidns-dbloader", "10", "60", "10", "3", conninfo, NULL };
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
        pr = PQexec(c->pg, "SET default_transaction_read_only = on; SET application_name = 'karidns-dbloader'; "
                           "SET statement_timeout = '900s'; SET lock_timeout = '10s'; "
                           "SET idle_in_transaction_session_timeout = '1h'; SET cursor_tuple_fraction = 1; "
                           "SET standard_conforming_strings = on");
        ok = pr && PQresultStatus(pr) == PGRES_COMMAND_OK;
        PQclear(pr);
    }
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

/* Which of k_tables exist in the search_path (exists[]) and which of their columns (found[], bit k = cols[k]); *schema_ok = the search_path
 * names at least one existing schema (a SET search_path to a missing schema is not an error in PostgreSQL).  One catalog query (to_regclass
 * follows search_path; no privilege on the tables is needed). */
static int schema_scan(db_conn_t *c, bool exists[N_TABLES], unsigned found[N_TABLES], bool *schema_ok) {
    PGresult *r = NULL;
    memset(found, 0, sizeof(unsigned) * N_TABLES);
    memset(exists, 0, sizeof(bool) * N_TABLES);
    int ret = exec_rows(c, "SELECT current_schemas(false)::text", 0, NULL, &r, "schema lookup");
    if (ret != 0) return ret;
    const char *path = PQgetvalue(r, 0, 0);
    *schema_ok = path && strcmp(path, "{}") != 0;
    PQclear(r);
    if (!*schema_ok) return 0;
    char sql[1400];
    size_t o = (size_t)snprintf(sql, sizeof(sql), "SELECT c.relname, a.attname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid "
                                                  "AND a.attnum > 0 AND NOT a.attisdropped WHERE c.oid = ANY (ARRAY[");
    for (size_t t = 0; t < N_TABLES; t++)
        o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%sto_regclass('%s')::oid", t ? "," : "", k_tables[t].table);
    snprintf(sql + o, sizeof(sql) - o, "])");
    ret = exec_rows(c, sql, 0, NULL, &r, "schema");
    if (ret != 0) return ret;
    for (int i = 0; i < PQntuples(r); i++) {
        const char *rel = PQgetvalue(r, i, 0), *att = PQgetvalue(r, i, 1);
        for (size_t t = 0; t < N_TABLES; t++) {
            if (strcmp(rel, k_tables[t].table) != 0) continue;
            exists[t] = true;
            for (int k = 0; k_tables[t].cols[k]; k++)
                if (strcmp(att, k_tables[t].cols[k]) == 0) found[t] |= 1u << k;
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
    int ret = schema_scan(c, exists, found, &schema_ok);
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
        /* version 1 and 2 are read; a newer one was written for a later loader */
        ret = exec_rows(c, "SELECT max(version) FROM karidns_schema_version", 0, NULL, &r, "karidns_schema_version");
        if (ret != 0) return ret;
        long long v = PQgetisnull(r, 0, 0) ? 0 : strtoll(PQgetvalue(r, 0, 0), NULL, 10);
        PQclear(r);
        if (v > 2) {
            set_err(c, "schema: karidns_schema_version is %lld; this loader reads versions 1 and 2", v);
            return -1;
        }
    }
    if (out) {
        out->has_changes = c->has_changes;
        out->has_domain_views = c->has_domain_views;
        out->has_profiles = c->has_profiles;
        out->has_ext = c->has_ext;
        out->has_reload_requests = c->has_reload_requests;
        out->has_server_status = c->has_server_status;
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
    unsigned found[N_TABLES];
    bool exists[N_TABLES], schema_ok = false;
    int ret = schema_scan(c, exists, found, &schema_ok);
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
        bool none = PQgetisnull(r, 0, 0);
        long long v = none ? 0 : strtoll(PQgetvalue(r, 0, 0), NULL, 10);
        PQclear(r);
        if (none) fnd(cb, ud, 'W', "karidns_schema_version has no row");
        else if (v > 2) fnd(cb, ud, 'E', "karidns_schema_version is %lld; this loader reads versions 1 and 2", v);
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
    int64_t id = cell_i64(r, i, 0);
    if (z->have_prev && id == z->prev) return 0;      /* more than one enabled apex SOA: the first is enough here */
    z->have_prev = true;
    z->prev = id;
    z->any = true;
    bool bad = false;
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
        int rc = exec_cmd(c, "RESET cursor_tuple_fraction", "list_zones");
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
    char *a = malloc(n + 1), *b = malloc(n + 2);
    if (!a || !b) {
        free(a);
        free(b);
        set_err(c, "out of memory");
        return -1;
    }
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
    free(a);
    free(b);
    return ret;
}

/* ---- records ---- */
typedef struct { db_record_cb cb; void *ud; } rl_t;

static int rl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    rl_t *l = ud;
    bool bad = false;
    int64_t did = cell_i64(r, i, 0);
    db_record_row_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.id = cell_i64(r, i, 1);
    rec.name = cell_text(c, r, i, 2, "records", rec.id, "name", &bad);
    rec.type = cell_text(c, r, i, 3, "records", rec.id, "type", &bad);
    rec.content = cell_text(c, r, i, 4, "records", rec.id, "content", &bad);
    rec.ttl_null = PQgetisnull(r, i, 5);
    rec.ttl = cell_i64(r, i, 5);
    rec.prio_null = PQgetisnull(r, i, 6);
    rec.prio = cell_i64(r, i, 6);
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
    int64_t rid = cell_i64(r, i, 4);
    db_apex_row_t a;
    a.domain_id = cell_i64(r, i, 0);
    const char *type = cell_text(c, r, i, 1, "records", rid, "type", &bad);
    a.is_soa = type && strcasecmp(type, "SOA") == 0;
    a.addr_type = type && strcasecmp(type, "A") == 0 ? 1 : type && strcasecmp(type, "AAAA") == 0 ? 28 : 0;
    a.name = cell_text(c, r, i, 5, "records", rid, "name", &bad);
    a.content = cell_text(c, r, i, 2, "records", rid, "content", &bad);
    a.ttl_null = PQgetisnull(r, i, 3);
    a.ttl = cell_i64(r, i, 3);
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

static int pg_scan_apex(db_conn_t *c, const int64_t *domain_id, db_apex_cb cb, void *ud) {
    al_t l = { cb, ud };
    if (domain_id) {
        char p[32];
        snprintf(p, sizeof(p), "%lld", (long long)*domain_id);
        const char *pv[1] = { p };
        return pg_scan(c, "scan_apex", APEX_COLS "AND r.domain_id = $1::bigint UNION ALL " APEX_GLUE "AND n.domain_id = $1::bigint " APEX_IN_ZONE "ORDER BY 1, 5", 1, pv, al_row, &l);
    }
    return pg_scan(c, "scan_apex", APEX_COLS "UNION ALL " APEX_GLUE APEX_IN_ZONE "ORDER BY 1, 5", 0, NULL, al_row, &l);
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
    int64_t id = cell_i64(r, i, 3);
    db_meta_row_t m;
    m.domain_id = cell_i64(r, i, 0);
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
    (void)c;
    kl_t *l = ud;
    if (PQgetisnull(r, i, 0)) return 0;
    return l->cb(l->ud, cell_i64(r, i, 0)) != 0 ? DB_STOPPED : 0;
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
    int64_t did = cell_i64(r, i, 0);
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
        return pg_scan(c, "scan_domain_views", "SELECT domain_id, view_name FROM karidns_domain_views WHERE domain_id = $1::bigint", 1, pv, dl_row, &l);
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
    int64_t did = cell_i64(r, i, 0);
    db_tag_row_t row;
    row.record_id = cell_i64(r, i, 1);
    row.location_tag = cell_text(c, r, i, 2, "karidns_record_tags", row.record_id, "location_tag", &bad);
    row.ecs_tag = cell_text(c, r, i, 3, "karidns_record_tags", row.record_id, "ecs_tag", &bad);
    if (bad) return -1;
    return s->record_tags(s->ud, did, &row) != 0 ? DB_STOPPED : 0;
}

static int xd_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    const db_ext_sink_t *s = ud;
    bool bad = false;
    int64_t did = cell_i64(r, i, 0);
    db_tinydns_row_t row;
    row.record_id = cell_i64(r, i, 1);
    row.ttd_null = PQgetisnull(r, i, 2);
    row.ttd = cell_i64(r, i, 2);
    row.loc = cell_text(c, r, i, 3, "karidns_record_tinydns", row.record_id, "loc", &bad);
    row.countdown = cell_true(r, i, 4);
    if (bad) return -1;
    return s->record_tinydns(s->ud, did, &row) != 0 ? DB_STOPPED : 0;
}

static int xg_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    const db_ext_sink_t *s = ud;
    bool bad = false;
    int64_t did = cell_i64(r, i, 0);
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
    *xmin = PQgetisnull(r, 0, 0) ? 0 : strtoull(PQgetvalue(r, 0, 0), NULL, 10);
    PQclear(r);
    return 0;
}

static int pg_changes_max(db_conn_t *c, uint64_t *seq) {
    if (!c->has_changes) {
        set_err(c, "karidns_changes (schema version 2: with the xid column) does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    return snapshot_xmin(c, seq);
}

typedef struct { db_change_cb cb; void *ud; } cl_t;

static int cl_row(db_conn_t *c, PGresult *r, int i, void *ud) {
    (void)c;
    cl_t *l = ud;
    db_change_row_t row;
    row.seq = (uint64_t)cell_i64(r, i, 0);
    row.domain_id = cell_i64(r, i, 1);
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
         * loader has seen are gone, so some of the ones after them may be too) */
        PGresult *r = NULL;
        ret = exec_rows(c, "SELECT (SELECT min(seq) FROM karidns_changes), EXISTS (SELECT 1 FROM karidns_changes WHERE xid < $1::xid8)", 1, pv, &r,
                        "changes_since");
        if (ret != 0) return ret;
        if (!PQgetisnull(r, 0, 0) && strtoll(PQgetvalue(r, 0, 0), NULL, 10) > 1 && !cell_true(r, 0, 1)) g = true;
        PQclear(r);
    }
    cl_t l = { cb, ud };
    ret = pg_scan(c, "changes_since", "SELECT seq, domain_id FROM karidns_changes WHERE xid >= $1::xid8 ORDER BY seq", 1, pv, cl_row, &l);
    if (last_seq) *last_seq = xmin;
    if (gap) *gap = g;
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* notifications                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

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
    uint64_t n = strtoull(PQgetvalue(r, 0, 0), NULL, 10), mx = strtoull(PQgetvalue(r, 0, 1), NULL, 10);
    PQclear(r);
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
    *generation = PQgetisnull(r, 0, 0) ? 0 : strtoull(PQgetvalue(r, 0, 0), NULL, 10);
    PQclear(r);
    return 0;
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
            row.generation = (uint64_t)cell_i64(r, i, 0);
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

const db_driver_t db_driver_postgresql = {
    "postgresql",    pg_open,         pg_close,           pg_errmsg,           pg_check_schema,
    pg_begin_snapshot, pg_end_snapshot, pg_list_zones,    pg_scan_records,     pg_scan_metadata,
    pg_zones_with_keys, pg_changes_since, pg_wait_fd,     pg_drain_notifications, pg_report_status,
    pg_changes_max,  pg_scan_records_range, pg_scan_domain_views, pg_scan_profiles, pg_scan_ext, pg_poll_version,
    true,
    pg_watch_requests, pg_requests_max, pg_reload_requests,
    pg_schema_findings, /* B12 */
    pg_find_zone,       /* B13 */
    pg_scan_records_in, pg_scan_metadata_in, pg_scan_ext_in,      /* B13b */
    pg_scan_apex,       /* D1a step 6 */
};

#endif /* KARIDNS_DB_POSTGRESQL */
