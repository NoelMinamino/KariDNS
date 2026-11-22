/*
 * dns_db_sqlite3.c - SQLite3 driver of karidns-dbloader (beta design 2.2, 3.1; milestone B3).  Compiled only when
 * "sqlite3" is listed in DB_DRIVERS (-DKARIDNS_DB_SQLITE3).  The interface and its contract are dns_db_driver.h.
 *
 * Opening (design 2.2, 4.17):
 *   - sqlite3_open_v2(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX): never SQLITE_OPEN_URI, so a path is a file
 *     name byte for byte and '%XX' in it is literal.  A library built with SQLITE_USE_URI=1 would read a name that
 *     starts with "file:" as a URI, so such a name is refused.  READWRITE because a WAL reader must be able to write
 *     the -shm file; PRAGMA query_only=1 makes every statement of this connection read only.
 *   - busy_timeout 5 s (db_source_t.busy_timeout_ms); SQLITE_BUSY after it is DB_ERR_RETRY.
 *   - journal_mode must already be wal: only WAL lets a reader and the writers (PowerDNS, the operator) run at the same
 *     time, and a snapshot is then a WAL read transaction.  The loader does not change the mode.
 *
 * Reading: names are never compared with SQL collations here.  PowerDNS declares `name` COLLATE NOCASE; the only
 * place where SQL compares names is the join that finds the apex SOA, and the reader checks the owner in C again.
 * A NULL `disabled` is a disabled row (PowerDNS reads rows with "disabled=0", which a NULL does not satisfy).
 * Every text column is checked for an embedded NUL (sqlite3_column_bytes() != strlen()): such a row is an error that
 * names the table and the row id.
 *
 * Writing (M2, the 0.6.0 ZoneImporter): open_write() is the same open without PRAGMA query_only; the loader never calls it.  w_begin() is
 * BEGIN IMMEDIATE (SQLite has one write lock for the whole database, which is the lock against a concurrent importer), everything
 * after it is parameterised (sqlite3_bind_*), and the triggers of db/karidns_ext.sqlite3.sql write the change log.  Foreign keys are
 * not relied on (PRAGMA foreign_keys is off by default): the extension rows of a record are deleted with it.
 */

#ifdef KARIDNS_DB_SQLITE3

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <pthread.h>

#include "dns_db_driver.h"

#ifdef KARIDNS_UNIT_TEST
/* the unit tests count the statements the driver parses: a fetch on a kept connection must parse none (B2, 0.7) */
unsigned long g_sq_prepares;
static int sq_prepare_counted(sqlite3 *db, const char *sql, int n, sqlite3_stmt **st, const char **tail) {
    g_sq_prepares++;
    return sqlite3_prepare_v2(db, sql, n, st, tail);
}
#define sqlite3_prepare_v2 sq_prepare_counted
#endif

/* The loader reads and does not look at SQLite memory statistics (sqlite3_memory_used() and friends are not called anywhere).  With them on, every
 * allocation of the library takes one global mutex, which was 15 % of the CPU of a fetch worker (dtrace, 4 loader threads); it can only be
 * turned off before the library is initialised, so the first open does it (SQLITE_MISUSE afterwards: ignored, the setting is an optimisation). */
static pthread_once_t g_sq_once = PTHREAD_ONCE_INIT;
static void sq_global_init(void) { (void)sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0); }

struct db_conn {
    sqlite3 *db;
    char *path;                 /* B9: the file that was opened, and which file it was (poll_version) */
    dev_t dev;
    ino_t ino;
    bool have_id;
    sqlite3_stmt *st_pv;
    sqlite3_stmt *st_begin, *st_snap, *st_commit;       /* B2 (0.7): BEGIN, the first read of a snapshot, COMMIT: prepared once per connection, not parsed for every fetch */
    char err[DB_ERRLEN];
    bool in_snapshot;
    bool has_changes;
    sqlite3_stmt *st_apex_all, *st_apex_one, *st_zones, *st_zone_one, *st_rec_all, *st_rec_one, *st_rec_rng, *st_meta_all, *st_meta_one, *st_keys, *st_changes, *st_cmax;
    sqlite3_stmt *st_dv_all, *st_dv_one;
    sqlite3_stmt *st_zlk[6];    /* 0.7: find_zones_in(), one statement per size class (SQ_ZLK_MIN << i names), kept: the lookup of a name must not parse SQL */
    sqlite3_stmt *st_in[6][7];  /* 0.7: scan_records_in, scan_metadata_in, scan_ext_in (records, metadata, tags, tinydns, tagdefs), zones_with_keys_in (cryptokeys) x size class (2 << i ids), kept */
    sqlite3_stmt *st_mpage, *st_cpage, *st_cnt, *st_cntv;      /* 0.7 WP3: manifest_page, changes_page, count_domains (all, one view) */
    db_mgroup_t mg;             /* the manifest row being assembled */
    bool has_domain_views;
    sqlite3_stmt *st_prof;
    bool has_profiles;
    sqlite3_stmt *st_xt[2], *st_xd[2], *st_xg[2];      /* B8: karidns_record_tags, karidns_record_tinydns, karidns_zone_tagdefs; [0] all, [1] one domain */
    bool has_ext;
    bool writable;              /* M2: opened with open_write() (no PRAGMA query_only) */
    bool in_wtxn;               /* M2: w_begin() is open (in_snapshot is set too, so the reads of the zone work inside it) */
    sqlite3_stmt *st_w[9];      /* M2: the statements of the write functions that run once per row (W_* below) */
    const char *audit_actor;    /* w_set_audit(): the db_role of the actor row (borrowed: it outlives the connection); NULL = no actor row */
    bool actor_set;             /* the row of karidns_audit_actor was written in the open write transaction (w_commit deletes it) */
    bool has_zone_state, has_versions;      /* items D and E: karidns_zone_state; karidns_zone_versions and karidns_zone_version_rrsets */
    bool have_actor, actor_has_pid, actor_has_pname, actor_has_cs;      /* w_set_actor(): the principal and the change set of the actor row */
    int64_t actor_pid;
    char actor_pname[260], actor_cs[80];
    int bind_rc;                /* the first bind of a parameter that failed since the last step (bnote()); bind_failed: the step that reported it, for sql_fail() */
    bool bind_failed;
};

/* M2: the statements kept for the per-row write functions */
enum { W_INS_REC, W_INS_TAGS, W_INS_TD, W_DEL_TAGS_ID, W_DEL_TD_ID, W_DEL_REC_ID, W_INS_TAGDEF, W_INS_META, W_UPD_REC };

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

static bool rc_is_busy(int rc) {
    int p = rc & 0xFF;
    return p == SQLITE_BUSY || p == SQLITE_LOCKED;
}

/* error of a failed sqlite3 call: DB_ERR_RETRY for BUSY / LOCKED, else -1 */
static int sql_fail(db_conn_t *c, int rc, const char *what) {
    if (c->bind_failed) {
        c->bind_failed = false;
        set_err(c, "sqlite3 %s: a parameter cannot be bound: %s", what, sqlite3_errstr(rc));
        return -1;
    }
    set_err(c, "sqlite3 %s: %s%s", what, sqlite3_errmsg(c->db), rc_is_busy(rc) ? " (retry later)" : "");
    return rc_is_busy(rc) ? DB_ERR_RETRY : -1;
}

/* The parameters of a statement.  A bind that fails (SQLITE_TOOBIG, a text over the length limit of the connection; SQLITE_NOMEM; SQLITE_RANGE) leaves the parameter NULL, or as the
 * last call bound it (review D-6: a read could then return the rows of another zone or view, a write store the text of the previous row).  The first failure is kept on the connection
 * and the next step, bstep(), returns it instead of running the statement; the caller's error path (sql_fail()) says that a parameter could not be bound.  Every bind is followed by
 * a step of its statement in the same call. */
static void bnote(db_conn_t *c, int rc) {
    if (rc != SQLITE_OK && c->bind_rc == SQLITE_OK) c->bind_rc = rc;
}
static void bi64(db_conn_t *c, sqlite3_stmt *st, int i, sqlite3_int64 v) { bnote(c, sqlite3_bind_int64(st, i, v)); }
static void bnull(db_conn_t *c, sqlite3_stmt *st, int i) { bnote(c, sqlite3_bind_null(st, i)); }
static void btext(db_conn_t *c, sqlite3_stmt *st, int i, const char *s, int n, sqlite3_destructor_type d) { bnote(c, sqlite3_bind_text(st, i, s, n, d)); }
static int bstep(db_conn_t *c, sqlite3_stmt *st) {
    if (c->bind_rc == SQLITE_OK) return sqlite3_step(st);
    const int rc = c->bind_rc;
    c->bind_rc = SQLITE_OK;
    c->bind_failed = true;
    return rc;
}

static int exec(db_conn_t *c, const char *sql) {
    int rc = sqlite3_exec(c->db, sql, NULL, NULL, NULL);
    return rc == SQLITE_OK ? 0 : sql_fail(c, rc, sql);
}

static int prep(db_conn_t *c, sqlite3_stmt **st, const char *sql) {
    if (*st) return 0;
    int rc = sqlite3_prepare_v2(c->db, sql, -1, st, NULL);
    if (rc != SQLITE_OK) {
        *st = NULL;
        return sql_fail(c, rc, "prepare");
    }
    return 0;
}

/* a statement without rows (BEGIN, COMMIT), prepared on first use and run again for every snapshot; errors as exec() reports them */
static int step_once(db_conn_t *c, sqlite3_stmt **st, const char *sql) {
    int ret = prep(c, st, sql);
    if (ret != 0) return ret;
    int rc = bstep(c, *st);
    ret = rc == SQLITE_DONE || rc == SQLITE_ROW ? 0 : sql_fail(c, rc, sql);
    sqlite3_reset(*st);
    return ret;
}

/* A read statement back to the start.  sqlite3_clear_bindings() is NOT called: for a statement whose plan looked at a bound value (the ORDER BY ones
 * here) it marks the statement expired, and the next sqlite3_step() then parses it again (sqlite3Reprepare; six times for every zone of a fetch, a
 * third of the CPU of the loader, dtrace on 300,000 and 10,000,000 zones).  Every user of a read statement binds every one of its parameters before
 * the first step (a NULL explicitly where a value is absent), so a binding left from the last call is never read; the text a statement keeps is a
 * copy (SQLITE_TRANSIENT).  The write statements bind SQLITE_STATIC text of the caller: they use wrearm() below, which clears. */
static void rearm(sqlite3_stmt *st) {
    sqlite3_reset(st);
}

/* the write statements of the importer: back to the start and unbound, so that no pointer of a caller (SQLITE_STATIC) outlives its call */
static void wrearm(sqlite3_stmt *st) {
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
}

/* A text column as a C string (NULL for SQL NULL).  *bad is set when the value has an embedded NUL or cannot be read;
 * c->err then names the table, the row id and the column. */
static const char *col_text(db_conn_t *c, sqlite3_stmt *st, int i, const char *table, int64_t id, const char *name,
                            bool *bad) {
    if (sqlite3_column_type(st, i) == SQLITE_NULL) return NULL;
    const unsigned char *t = sqlite3_column_text(st, i);
    int n = sqlite3_column_bytes(st, i);
    if (!t) {
        set_err(c, "table %s id %lld: column %s cannot be read (out of memory)", table, (long long)id, name);
        *bad = true;
        return NULL;
    }
    if ((size_t)n != strlen((const char *)t)) {
        set_err(c, "table %s id %lld: column %s contains a NUL byte", table, (long long)id, name);
        *bad = true;
        return NULL;
    }
    return (const char *)t;
}

/* An integer column.  SQLite is dynamically typed: a TEXT or REAL cell in an INTEGER column reads as 0 or as a cut number through
 * sqlite3_column_int64(), which would turn a damaged row into a valid-looking one (a TEXT 'false' in disabled is 0 = enabled here, but the
 * joins' `disabled = 0` do not match it).  A cell that is not SQLITE_INTEGER sets *bad; c->err names the table, the row id and the column. */
static int64_t col_int(db_conn_t *c, sqlite3_stmt *st, int i, const char *table, int64_t id, const char *name, bool *bad) {
    if (sqlite3_column_type(st, i) != SQLITE_INTEGER) {
        set_err(c, "table %s id %lld: column %s is not an integer", table, (long long)id, name);
        *bad = true;
        return 0;
    }
    return sqlite3_column_int64(st, i);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* open / close                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

/* write: the ZoneImporter's connection (open_write()).  The loader's open() is write == false: PRAGMA query_only=1, as before. */
static int sq_open_mode(db_conn_t **out, const db_source_t *src, char *err, size_t errlen, bool write) {
    *out = NULL;
    const char *path = src ? src->database_file : NULL;
    pthread_once(&g_sq_once, sq_global_init);
    if (!path || !*path) {
        snprintf(err, errlen, "sqlite3: no database file given");
        return -1;
    }
    if (strncmp(path, "file:", 5) == 0) {
        snprintf(err, errlen, "sqlite3: a database file name that starts with \"file:\" is refused "
                              "(SQLite would read it as a URI; use ./file: for a file of that name)");
        return -1;
    }
    if (strcmp(path, ":memory:") == 0) {
        snprintf(err, errlen, "sqlite3: \":memory:\" is not a database file");
        return -1;
    }
    db_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        snprintf(err, errlen, "sqlite3: out of memory");
        return -1;
    }
    int rc = sqlite3_open_v2(path, &c->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK) {
        snprintf(err, errlen, "sqlite3: cannot open the database file: %s%s", c->db ? sqlite3_errmsg(c->db) : "out of memory",
                 rc_is_busy(rc) ? " (retry later)" : "");
        int ret = rc_is_busy(rc) ? DB_ERR_RETRY : -1;
        if (c->db) sqlite3_close(c->db);
        free(c);
        return ret;
    }
    unsigned ms = src->busy_timeout_ms ? src->busy_timeout_ms : 5000;
    sqlite3_busy_timeout(c->db, ms > (unsigned)INT_MAX ? INT_MAX : (int)ms);
#ifdef SQLITE_DBCONFIG_DEFENSIVE
    sqlite3_db_config(c->db, SQLITE_DBCONFIG_DEFENSIVE, 1, (int *)NULL);
#endif
#ifdef SQLITE_DBCONFIG_TRUSTED_SCHEMA
    /* The loader reads a file other users may write: a view or trigger planted in its schema must not run functions of ours or of
     * SQLite that are not marked innocuous (the SQLite advice for a database that an untrusted party can change).  The importer's
     * connection (write) owns the file and its audit triggers, and keeps the default. */
    if (!write) {
        rc = sqlite3_db_config(c->db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, (int *)NULL);
        if (rc != SQLITE_OK) {
            snprintf(err, errlen, "sqlite3: cannot turn off trusted_schema: %s", sqlite3_errmsg(c->db));
            sqlite3_close(c->db);
            free(c);
            return -1;
        }
    }
#endif
#ifdef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
    /* The loader only reads: the last connection of a WAL database must not try to checkpoint (and remove the WAL) when it closes, as
     * the user of the loader may not be allowed to write the file. */
    if (!write) sqlite3_db_config(c->db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, (int *)NULL);
#endif
    c->writable = write;
    int ret = write ? 0 : exec(c, "PRAGMA query_only=1");
    if (ret == 0) {
        sqlite3_stmt *st = NULL;
        rc = sqlite3_prepare_v2(c->db, "PRAGMA journal_mode", -1, &st, NULL);
        if (rc == SQLITE_OK) rc = bstep(c, st);
        if (rc == SQLITE_ROW) {
            const char *m = (const char *)sqlite3_column_text(st, 0);
            if (!m || strcasecmp(m, "wal") != 0) {
                set_err(c, "sqlite3: the database is not in WAL mode (journal_mode=%.20s); WAL is required so that the loader "
                           "and the writers can work at the same time (the owner runs PRAGMA journal_mode=WAL once)",
                        m ? m : "?");
                ret = -1;
            }
        } else if (rc == SQLITE_DONE) {      /* (sql_fail() would say "not an error": the step succeeded but gave no row) */
            set_err(c, "sqlite3: PRAGMA journal_mode returned no row");
            ret = -1;
        } else {
            ret = sql_fail(c, rc, "PRAGMA journal_mode");
        }
        sqlite3_finalize(st);
    }
    if (ret != 0) {
        snprintf(err, errlen, "%s", c->err);
        sqlite3_close(c->db);
        free(c);
        return ret;
    }
    c->path = strdup(path);
    if (!c->path) {                      /* (without it poll_version would report "replaced" at every poll) */
        snprintf(err, errlen, "sqlite3: out of memory");
        sqlite3_close(c->db);
        free(c);
        return -1;
    }
    struct stat sb;
    if (stat(path, &sb) == 0) {
        c->dev = sb.st_dev;
        c->ino = sb.st_ino;
        c->have_id = true;
    }
    *out = c;
    return 0;
}

static int sq_open(db_conn_t **out, const db_source_t *src, char *err, size_t errlen) {
    return sq_open_mode(out, src, err, errlen, false);
}

static int sq_open_write(db_conn_t **out, const db_source_t *src, char *err, size_t errlen) {
    return sq_open_mode(out, src, err, errlen, true);
}

static void sq_close(db_conn_t *c) {
    if (!c) return;
    if (c->in_wtxn) sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);       /* an importer that gives up: nothing is committed */
    for (size_t i = 0; i < sizeof(c->st_w) / sizeof(c->st_w[0]); i++) sqlite3_finalize(c->st_w[i]);
    sqlite3_finalize(c->st_pv);
    sqlite3_finalize(c->st_begin);
    sqlite3_finalize(c->st_snap);
    sqlite3_finalize(c->st_commit);
    free(c->path);
    sqlite3_finalize(c->st_apex_all);
    sqlite3_finalize(c->st_apex_one);
    sqlite3_finalize(c->st_zones);
    sqlite3_finalize(c->st_zone_one);
    sqlite3_finalize(c->st_rec_all);
    sqlite3_finalize(c->st_rec_one);
    sqlite3_finalize(c->st_rec_rng);
    sqlite3_finalize(c->st_dv_all);
    sqlite3_finalize(c->st_dv_one);
    for (size_t i = 0; i < sizeof(c->st_zlk) / sizeof(c->st_zlk[0]); i++) sqlite3_finalize(c->st_zlk[i]);
    for (size_t k = 0; k < sizeof(c->st_in) / sizeof(c->st_in[0]); k++)
        for (size_t i = 0; i < 7; i++) sqlite3_finalize(c->st_in[k][i]);
    sqlite3_finalize(c->st_prof);
    for (int i = 0; i < 2; i++) {
        sqlite3_finalize(c->st_xt[i]);
        sqlite3_finalize(c->st_xd[i]);
        sqlite3_finalize(c->st_xg[i]);
    }
    sqlite3_finalize(c->st_meta_all);
    sqlite3_finalize(c->st_meta_one);
    sqlite3_finalize(c->st_keys);
    sqlite3_finalize(c->st_changes);
    sqlite3_finalize(c->st_cmax);
    sqlite3_finalize(c->st_mpage);
    sqlite3_finalize(c->st_cpage);
    sqlite3_finalize(c->st_cnt);
    sqlite3_finalize(c->st_cntv);
    sqlite3_close(c->db);
    free(c);
}

static const char *sq_errmsg(db_conn_t *c) { return c->err; }

/* ------------------------------------------------------------------------------------------------------------- */
/* schema                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

/* PowerDNS 5.1 columns the loader reads (design 3.1).  The runtime check is by column name; extra columns are
 * ignored, a missing one is a schema error. */
static const struct { const char *table; const char *cols[10]; } k_required[] = {
    { "domains", { "id", "name", "type", "master", "catalog", NULL } },
    { "records", { "domain_id", "id", "name", "type", "content", "ttl", "prio", "disabled", "ordername", NULL } },
    { "domainmetadata", { "domain_id", "id", "kind", "content", NULL } },
    { "cryptokeys", { "domain_id", NULL } },
};

/* which of cols[] (at most 31) the table has; *rows = number of columns of the table (0 = no such table) */
static int table_columns(db_conn_t *c, const char *table, const char *const *cols, unsigned *found, int *rows) {
    char sql[96];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c->db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK) return sql_fail(c, rc, "PRAGMA table_info");
    *found = 0;
    *rows = 0;
    while ((rc = bstep(c, st)) == SQLITE_ROW) {
        (*rows)++;
        const char *name = (const char *)sqlite3_column_text(st, 1);
        for (int i = 0; name && cols[i]; i++)
            if (strcasecmp(name, cols[i]) == 0) *found |= 1u << i;
    }
    int ret = 0;
    if (rc != SQLITE_DONE) ret = sql_fail(c, rc, "PRAGMA table_info");
    sqlite3_finalize(st);
    return ret;
}

static int sq_check_schema(db_conn_t *c, db_schema_info_t *out) {
    for (size_t t = 0; t < sizeof(k_required) / sizeof(k_required[0]); t++) {
        unsigned found;
        int rows;
        int rc = table_columns(c, k_required[t].table, k_required[t].cols, &found, &rows);
        if (rc != 0) return rc;
        if (rows == 0) {
            set_err(c, "schema: table %s is missing (PowerDNS 5.1 schema expected)", k_required[t].table);
            return -1;
        }
        for (int i = 0; k_required[t].cols[i]; i++)
            if (!(found & (1u << i))) {
                set_err(c, "schema: table %s has no column %s (PowerDNS 5.1 schema expected)", k_required[t].table,
                        k_required[t].cols[i]);
                return -1;
            }
    }
    static const char *const ch_cols[] = { "seq", "domain_id", NULL };
    unsigned found;
    int rows;
    int rc = table_columns(c, "karidns_changes", ch_cols, &found, &rows);
    if (rc != 0) return rc;
    c->has_changes = rows > 0 && found == 3u;
    if (out) out->has_changes = c->has_changes;
    static const char *const dv_cols[] = { "domain_id", "view_name", NULL };
    rc = table_columns(c, "karidns_domain_views", dv_cols, &found, &rows);
    if (rc != 0) return rc;
    c->has_domain_views = rows > 0 && found == 3u;
    if (out) out->has_domain_views = c->has_domain_views;
    static const char *const pr_cols[] = { "name", "settings", NULL };
    rc = table_columns(c, "karidns_profiles", pr_cols, &found, &rows);
    if (rc != 0) return rc;
    c->has_profiles = rows > 0 && found == 3u;
    if (out) out->has_profiles = c->has_profiles;
    /* B8: the three extension tables of the tags and tinydns attributes (design 3.7); all three or none */
    static const char *const xt_cols[] = { "record_id", "location_tag", "ecs_tag", NULL };
    static const char *const xd_cols[] = { "record_id", "ttd", "loc", "countdown", NULL };
    static const char *const xg_cols[] = { "domain_id", "kind", "tag", "cidr", NULL };
    unsigned f1, f2, f3;
    int r1, r2, r3;
    if ((rc = table_columns(c, "karidns_record_tags", xt_cols, &f1, &r1)) != 0 || (rc = table_columns(c, "karidns_record_tinydns", xd_cols, &f2, &r2)) != 0 ||
        (rc = table_columns(c, "karidns_zone_tagdefs", xg_cols, &f3, &r3)) != 0)
        return rc;
    c->has_ext = r1 > 0 && f1 == 7u && r2 > 0 && f2 == 15u && r3 > 0 && f3 == 15u;
    /* items D and E: the zone generation and the zone versions (db/karidns_ext.sqlite3.sql); the versions need both tables */
    static const char *const zs_cols[] = { "domain_id", "generation", "changed_at", NULL };
    static const char *const zv_cols[] = { "id", "domain_id", "version", "kind", "change_set", "principal_id", "principal_name", "db_role", "comment", "serial_before",
                                           "serial_after", "generation_before", "generation_after", "rollback_of", "delta_complete", NULL };
    static const char *const zr_cols[] = { "version_id", "owner", "type", "before", "after", NULL };
    unsigned f4, f5;
    int r4, r5;
    if ((rc = table_columns(c, "karidns_zone_state", zs_cols, &found, &rows)) != 0 || (rc = table_columns(c, "karidns_zone_versions", zv_cols, &f4, &r4)) != 0 ||
        (rc = table_columns(c, "karidns_zone_version_rrsets", zr_cols, &f5, &r5)) != 0)
        return rc;
    c->has_zone_state = rows > 0 && found == 7u;
    c->has_versions = r4 > 0 && f4 == 0x7FFFu && r5 > 0 && f5 == 31u;
    if (out) {
        out->has_ext = c->has_ext;
        out->has_reload_requests = out->has_server_status = false;     /* B11: the multi-server tables are PostgreSQL only */
        out->has_zone_state = c->has_zone_state;
        out->has_versions = c->has_versions;
    }

    /* B10: schema versions 1 to 3 (v2 adds karidns_zone_tagdefs.id; the order of the definitions is the rowid either way; v3 adds the
     * audit tables, which the loader never uses); a newer version was written for a later loader */
    static const char *const sv_cols[] = { "version", NULL };
    if ((rc = table_columns(c, "karidns_schema_version", sv_cols, &found, &rows)) != 0) return rc;
    if (rows > 0 && found == 1u) {
        sqlite3_stmt *st = NULL;
        rc = sqlite3_prepare_v2(c->db, "SELECT max(version) FROM karidns_schema_version", -1, &st, NULL);
        if (rc == SQLITE_OK) rc = bstep(c, st);
        if (rc == SQLITE_ROW) {
            sqlite3_int64 v = sqlite3_column_type(st, 0) == SQLITE_NULL ? 0 : sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            if (v > 3) {
                set_err(c, "schema: karidns_schema_version is %lld; this loader reads versions 1 to 3", (long long)v);
                return -1;
            }
            return 0;
        }
        sqlite3_finalize(st);
        return sql_fail(c, rc, "karidns_schema_version");
    }
    return 0;
}

/* B12: the schema check of `karicheck db` (design 7.2).  Everything is a catalog read; nothing is written. */
static void fnd(db_finding_cb cb, void *ud, char level, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void fnd(db_finding_cb cb, void *ud, char level, const char *fmt, ...) {
    char t[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t, sizeof(t), fmt, ap);
    va_end(ap);
    cb(ud, level, t);
}

/* the karidns_* tables of db/karidns_ext.sqlite3.sql (design 3.7) with the columns the loader reads and what a missing one costs */
static const struct { const char *table; const char *cols[6]; unsigned all; const char *effect; } k_ext[] = {
    { "karidns_schema_version", { "version", NULL }, 1u, "the version of the extension tables is not known" },
    { "karidns_changes", { "seq", "domain_id", NULL }, 3u, "there is no change log, so an edit that keeps the SOA serial is not noticed by a reload" },
    { "karidns_domain_views", { "domain_id", "view_name", NULL }, 3u, "the zone to view mapping is not available: every zone goes to every view that uses this source" },
    { "karidns_profiles", { "name", "settings", NULL }, 3u, "a zone that names a profile (X-KARIDNS-PROFILE) fails to load" },
    { "karidns_record_tags", { "record_id", "location_tag", "ecs_tag", NULL }, 7u, "location and ECS tags are ignored (the three tag tables are used together)" },
    { "karidns_record_tinydns", { "record_id", "ttd", "loc", "countdown", NULL }, 15u, "tinydns time stamps and locations are ignored (the three tag tables are used together)" },
    { "karidns_zone_tagdefs", { "domain_id", "kind", "tag", "cidr", NULL }, 15u, "tag definitions are ignored (the three tag tables are used together)" },
};
#define N_EXT (sizeof(k_ext) / sizeof(k_ext[0]))

static int sq_schema_findings(db_conn_t *c, const db_check_opts_t *o, db_finding_cb cb, void *ud) {
    for (size_t t = 0; t < sizeof(k_required) / sizeof(k_required[0]); t++) {
        unsigned found;
        int rows;
        int rc = table_columns(c, k_required[t].table, k_required[t].cols, &found, &rows);
        if (rc != 0) return rc;
        if (rows == 0) {
            fnd(cb, ud, 'E', "table %s is missing (PowerDNS 5.1 schema expected)", k_required[t].table);
            continue;
        }
        char miss[200] = "";
        unsigned nm = 0;
        for (int i = 0; k_required[t].cols[i]; i++)
            if (!(found & (1u << i))) db_list_add(miss, sizeof(miss), &nm, k_required[t].cols[i]);
        if (nm) fnd(cb, ud, 'E', "table %s has no column %s%s (PowerDNS 5.1 schema expected)", k_required[t].table, miss, nm > 6 ? ", ..." : "");
    }
    bool have[N_EXT];
    unsigned present = 0;
    for (size_t t = 0; t < N_EXT; t++) {
        unsigned found;
        int rows;
        int rc = table_columns(c, k_ext[t].table, k_ext[t].cols, &found, &rows);
        if (rc != 0) return rc;
        have[t] = rows > 0 && found == k_ext[t].all;
        if (rows > 0) present++;
    }
    if (present == 0) {
        fnd(cb, ud, 'W', "none of the karidns_* extension tables exists (db/karidns_ext.sqlite3.sql was not applied): no change log, no zone to view "
                         "mapping, no profiles, no tags; a reload compares the SOA serials");
    } else {
        for (size_t t = 0; t < N_EXT; t++)
            if (!have[t]) fnd(cb, ud, 'W', "table %s is missing or incomplete: %s", k_ext[t].table, k_ext[t].effect);
    }
    if (have[0]) {
        sqlite3_stmt *st = NULL;
        int rc = sqlite3_prepare_v2(c->db, "SELECT max(version), count(*) FROM karidns_schema_version", -1, &st, NULL);
        if (rc == SQLITE_OK) rc = bstep(c, st);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(st);
            return sql_fail(c, rc, "karidns_schema_version");
        }
        long long v = sqlite3_column_type(st, 0) == SQLITE_NULL ? 0 : sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (v == 0) fnd(cb, ud, 'W', "karidns_schema_version has no row");
        else if (v > 3) fnd(cb, ud, 'E', "karidns_schema_version is %lld; this loader reads versions 1 to 3", v);
        else fnd(cb, ud, 'I', "karidns_* schema version %lld", v);
    }
    if (o && o->auto_reload) {
        if (!have[1]) {
            fnd(cb, ud, 'E', "auto-reload yes needs the change log: table karidns_changes is missing or incomplete (apply db/karidns_ext.sqlite3.sql)");
        } else {
            static const struct { const char *infix, *table; } k_trg[] = {
#define X(i, t) { #i, t },
                DB_CHANGE_TRIGGERS(X)
#undef X
            };
            sqlite3_stmt *st = NULL;
            int rc = sqlite3_prepare_v2(c->db, "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1", -1, &st, NULL);
            if (rc != SQLITE_OK) return sql_fail(c, rc, "prepare");
            char miss[300] = "";
            unsigned nm = 0;
            for (size_t i = 0; i < sizeof(k_trg) / sizeof(k_trg[0]) * 3 + 1; i++) {
                char name[96];
                if (i == 0) {
                    snprintf(name, sizeof(name), "karidns_changes_prune");
                } else {
                    size_t k = (i - 1) / 3;
                    static const char *const sfx[3] = { "ins", "upd", "del" };
                    bool ext = strncmp(k_trg[k].table, "karidns_", 8) == 0;
                    bool table_here = true;
                    if (ext)
                        for (size_t t = 0; t < N_EXT; t++)
                            if (strcmp(k_ext[t].table, k_trg[k].table) == 0) table_here = have[t];
                    if (!table_here) continue;                 /* its table is reported above */
                    snprintf(name, sizeof(name), "karidns_trg_%s_%s", k_trg[k].infix, sfx[(i - 1) % 3]);
                }
                sqlite3_reset(st);
                btext(c, st, 1, name, -1, SQLITE_STATIC);
                rc = bstep(c, st);
                if (rc == SQLITE_DONE) db_list_add(miss, sizeof(miss), &nm, name);
                else if (rc != SQLITE_ROW) {
                    sqlite3_finalize(st);
                    return sql_fail(c, rc, "sqlite_master");
                }
            }
            sqlite3_finalize(st);
            if (nm)
                fnd(cb, ud, 'E', "auto-reload yes needs the change log triggers, but %u are missing: %s%s (apply db/karidns_ext.sqlite3.sql)", nm, miss,
                    nm > 6 ? ", ..." : "");
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* snapshot                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static int sq_begin_snapshot(db_conn_t *c) {
    if (c->in_snapshot) {
        set_err(c, "begin_snapshot: a snapshot is already open");
        return -1;
    }
    int rc = step_once(c, &c->st_begin, "BEGIN");
    if (rc != 0) return rc;
    c->in_snapshot = true;
    /* BEGIN is deferred: the WAL read transaction (the snapshot) starts with the first statement that reads */
    rc = prep(c, &c->st_snap, "SELECT 1 FROM sqlite_master LIMIT 1");
    if (rc == 0) {
        int sr = bstep(c, c->st_snap);
        if (sr != SQLITE_ROW && sr != SQLITE_DONE) rc = sql_fail(c, sr, "begin snapshot");
        sqlite3_reset(c->st_snap);
    }
    if (rc != 0) {
        sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);
        c->in_snapshot = false;
        return rc;
    }
    return 0;
}

/* every kept read statement of the connection, one call of fn each */
static void each_read_stmt(db_conn_t *c, void (*fn)(sqlite3_stmt *, void *), void *arg) {
    sqlite3_stmt *all[] = { c->st_apex_all, c->st_apex_one, c->st_zones, c->st_zone_one, c->st_rec_all, c->st_rec_one, c->st_rec_rng, c->st_meta_all, c->st_meta_one,
                            c->st_keys, c->st_changes, c->st_cmax, c->st_dv_all, c->st_dv_one, c->st_prof, c->st_mpage, c->st_cpage, c->st_cnt, c->st_cntv };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (all[i]) fn(all[i], arg);
    for (size_t i = 0; i < sizeof(c->st_zlk) / sizeof(c->st_zlk[0]); i++)
        if (c->st_zlk[i]) fn(c->st_zlk[i], arg);
    for (size_t k = 0; k < sizeof(c->st_in) / sizeof(c->st_in[0]); k++)
        for (size_t i = 0; i < sizeof(c->st_in[0]) / sizeof(c->st_in[0][0]); i++)
            if (c->st_in[k][i]) fn(c->st_in[k][i], arg);
    for (int i = 0; i < 2; i++) {
        if (c->st_xt[i]) fn(c->st_xt[i], arg);
        if (c->st_xd[i]) fn(c->st_xd[i], arg);
        if (c->st_xg[i]) fn(c->st_xg[i], arg);
    }
}

static void rearm_cb(sqlite3_stmt *st, void *arg) {
    (void)arg;
    rearm(st);
}

/* every read statement back to the start, so that no cursor keeps the transaction (or the WAL read mark) busy */
static void rearm_all(db_conn_t *c) {
    each_read_stmt(c, rearm_cb, NULL);
}

#ifdef KARIDNS_UNIT_TEST
/* how often SQLite parsed a kept read statement of the connection again because it had expired (sqlite3_stmt_status): a fetch on a kept connection must have none */
static void reprepare_cb(sqlite3_stmt *st, void *arg) {
    *(unsigned long *)arg += (unsigned long)sqlite3_stmt_status(st, SQLITE_STMTSTATUS_REPREPARE, 0);
}
unsigned long sq_reprepares(db_conn_t *c) {
    unsigned long n = 0;
    each_read_stmt(c, reprepare_cb, &n);
    return n;
}
/* the handle of the connection (tests: sqlite3_limit() makes a bind fail, review D-6) */
sqlite3 *sq_test_handle(db_conn_t *c) { return c->db; }
#endif

static int sq_end_snapshot(db_conn_t *c) {
    if (!c->in_snapshot) return 0;
    rearm_all(c);
    c->in_snapshot = false;
    int rc = step_once(c, &c->st_commit, "COMMIT");
    if (rc != 0) sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);    /* (a failed COMMIT may leave the transaction open: the snapshot must not live on) */
    return rc;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* scans                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

static int sq_zone_loop(db_conn_t *c, sqlite3_stmt *st, db_zone_cb cb, void *ud) {
    int ret = 0;
    bool have_prev = false;
    int64_t prev = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "list_zones");
            break;
        }
        bool bad = false;
        int64_t id = col_int(c, st, 0, "domains", prev, "id", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (have_prev && id == prev) continue;      /* more than one enabled apex SOA: the first is enough here */
        have_prev = true;
        prev = id;
        db_zone_row_t z;
        z.id = id;
        z.name = col_text(c, st, 1, "domains", id, "name", &bad);
        z.type = col_text(c, st, 2, "domains", id, "type", &bad);
        z.master = col_text(c, st, 3, "domains", id, "master", &bad);
        z.catalog = col_text(c, st, 4, "domains", id, "catalog", &bad);
        /* (column 6: the id of the SOA row, which is the row the error is about; NULL when the zone has no enabled apex SOA) */
        z.soa_content = col_text(c, st, 5, "records", sqlite3_column_int64(st, 6), "content", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, &z) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int sq_list_zones(db_conn_t *c, db_zone_cb cb, void *ud) {
    int ret = prep(c, &c->st_zones,
                   "SELECT d.id, d.name, d.type, d.master, d.catalog, r.content, r.id FROM domains d "
                   "LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = 0 "
                   "ORDER BY d.id, r.id");
    if (ret != 0) return ret;
    rearm(c->st_zones);
    return sq_zone_loop(c, c->st_zones, cb, ud);
}

/* B13: one zone by name, through the index on domains.name (a one-zone reload must not read the list of all zones).  The name
 * matches like names_equal() of the loader: ASCII case-insensitive, with or without one trailing dot.  COLLATE NOCASE is explicit so
 * that the answer does not depend on the collation the schema gave the column (the PowerDNS schema has NOCASE, which lets the
 * index serve both comparisons).  The two spellings are an IN list, not "a OR b": with the explicit COLLATE on the left the planner
 * does not use the index for an OR and scans all of domains (EXPLAIN QUERY PLAN: SCAN d; 8,400 pages and about 60 ms at 1,000,000
 * zones), while IN is a SEARCH on name_index. */
static int sq_find_zone(db_conn_t *c, const char *name, db_zone_cb cb, void *ud) {
    size_t n = strlen(name);
    if (n > 1 && name[n - 1] == '.') n--;
    char a[1100];                 /* the name without the dot, then the dot for the second spelling (SQLite copies the text: SQLITE_TRANSIENT) */
    if (n > sizeof(a) - 2) return 0;       /* longer than any domain name (255 bytes, escapes included): no zone of that name */
    memcpy(a, name, n);
    a[n] = '.';
    int ret = prep(c, &c->st_zone_one,
                   "SELECT d.id, d.name, d.type, d.master, d.catalog, r.content, r.id FROM domains d "
                   "LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = 0 "
                   "WHERE d.name COLLATE NOCASE IN (?1, ?2) ORDER BY d.id, r.id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_zone_one;
    rearm(st);
    btext(c, st, 1, a, (int)n, SQLITE_TRANSIENT);
    btext(c, st, 2, a, (int)n + 1, SQLITE_TRANSIENT);
    return sq_zone_loop(c, st, cb, ud);
}

/* 0.7: the zones that have one of the names, closest (longest name) first (dns_db_driver.h find_zones_in()).  The statement has two placeholders for each name (the spellings with and without the dot: an IN list is a
 * SEARCH on the name index even with the explicit collation, as for find_zone()), so its text depends on how many names there are.  There is one kept statement for each size class (4, 8, ... 128 names; it
 * is parsed at the first call of its class, not for every lookup: 3 ms of a lookup was the parse); the placeholders a call does not need are bound NULL, which is equal to no name. */
#define SQ_ZLK_MIN 4
static int sq_find_zones_in(db_conn_t *c, const char *const *names, size_t n, db_zone_cb cb, void *ud) {
    if (n == 0 || n > DB_LOOKUP_MAX) {
        set_err(c, "find_zones_in: %zu names (1 to %d)", n, DB_LOOKUP_MAX);
        return -1;
    }
    size_t cls = 0, cap = SQ_ZLK_MIN;
    while (cap < n) {
        cap <<= 1;
        cls++;
    }
    if (!c->st_zlk[cls]) {
        char sql[2560];
        size_t o = (size_t)snprintf(sql, sizeof(sql),
                                    "SELECT d.id, d.name, d.type, d.master, d.catalog, r.content, r.id FROM domains d "
                                    "LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = 0 "
                                    "WHERE d.name COLLATE NOCASE IN (");
        for (size_t i = 0; i < 2 * cap; i++) o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%s?%zu", i ? "," : "", i + 1);
        snprintf(sql + o, sizeof(sql) - o, ") ORDER BY length(d.name) DESC, d.id, r.id");
        int ret = prep(c, &c->st_zlk[cls], sql);
        if (ret != 0) return ret;
    }
    sqlite3_stmt *st = c->st_zlk[cls];
    rearm(st);
    char a[1100];                  /* the name without the dot, then the dot for the second spelling (SQLite copies the text: SQLITE_TRANSIENT) */
    for (size_t i = 0; i < cap; i++) {
        size_t l = i < n ? strlen(names[i]) : 0;
        if (l > 1 && names[i][l - 1] == '.') l--;
        if (i >= n || l > sizeof(a) - 2) {                  /* an unused slot, or a name longer than any domain name: it matches nothing (NULL is never equal to a name; an empty text would match the root zone) */
            bnull(c, st, (int)(2 * i + 1));
            bnull(c, st, (int)(2 * i + 2));
            continue;
        }
        memcpy(a, names[i], l);
        a[l] = '.';
        btext(c, st, (int)(2 * i + 1), a, (int)l, SQLITE_TRANSIENT);
        btext(c, st, (int)(2 * i + 2), a, (int)l + 1, SQLITE_TRANSIENT);
    }
    return sq_zone_loop(c, st, cb, ud);
}

/* the rows of a prepared records statement (already bound) to the callback */
static int rec_loop(db_conn_t *c, sqlite3_stmt *st, db_record_cb cb, void *ud) {
    int ret = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_records");
            break;
        }
        bool bad = false;
        db_record_row_t r;
        memset(&r, 0, sizeof(r));
        r.id = col_int(c, st, 1, "records", 0, "id", &bad);
        int64_t did = col_int(c, st, 0, "records", r.id, "domain_id", &bad);
        r.name = col_text(c, st, 2, "records", r.id, "name", &bad);
        r.type = col_text(c, st, 3, "records", r.id, "type", &bad);
        r.content = col_text(c, st, 4, "records", r.id, "content", &bad);
        r.ttl_null = sqlite3_column_type(st, 5) == SQLITE_NULL;
        r.ttl = r.ttl_null ? 0 : col_int(c, st, 5, "records", r.id, "ttl", &bad);
        r.prio_null = sqlite3_column_type(st, 6) == SQLITE_NULL;
        r.prio = r.prio_null ? 0 : col_int(c, st, 6, "records", r.id, "prio", &bad);
        /* NULL is disabled (the SQL joins' `disabled = 0` does not match it); anything but an integer is a bad cell, not "enabled" */
        r.disabled = sqlite3_column_type(st, 7) == SQLITE_NULL || col_int(c, st, 7, "records", r.id, "disabled", &bad) != 0;
        r.ordername = col_text(c, st, 8, "records", r.id, "ordername", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, did, &r) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int sq_scan_records(db_conn_t *c, const int64_t *domain_id, db_record_cb cb, void *ud) {
    sqlite3_stmt **slot = domain_id ? &c->st_rec_one : &c->st_rec_all;
    int ret = prep(c, slot, domain_id ? "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername "
                                        "FROM records WHERE domain_id = ?1 ORDER BY id"
                                      : "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername "
                                        "FROM records ORDER BY domain_id, id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) bi64(c, st, 1, *domain_id);
    return rec_loop(c, st, cb, ud);
}

/* D1a step 6: the enabled SOA and NS records at the apex (the record's name is the domain's name), one zone or all */
static int sq_scan_apex(db_conn_t *c, const int64_t *domain_id, db_apex_cb cb, void *ud) {
    sqlite3_stmt **slot = domain_id ? &c->st_apex_one : &c->st_apex_all;
    /* the SOA and NS rows of the apex, and the address rows of the zone whose owner is an NS target inside the zone (g: the NS row n gives the target).  CROSS JOIN keeps
     * the order n, d, g: left to itself the planner scans g and looks the NS rows of its zone up for every row (quadratic in the size of a big zone: 10 s for 10,000
     * records); the NS rows are few, and g is looked up by domain_id for each of them. */
#define AX_SOA_NS "SELECT r.domain_id, r.type, r.content, r.ttl, r.id, r.name FROM records r JOIN domains d ON d.id = r.domain_id AND r.name = d.name COLLATE NOCASE " \
                  "WHERE r.type IN ('SOA', 'NS') AND r.disabled = 0 "
#define AX_GLUE_1 "SELECT g.domain_id, g.type, g.content, g.ttl, g.id, g.name FROM records n CROSS JOIN domains d ON d.id = n.domain_id AND n.name = d.name COLLATE NOCASE " \
                  "CROSS JOIN records g ON g.domain_id = n.domain_id AND g.type IN ('A', 'AAAA') AND g.disabled = 0 AND g.name = rtrim(n.content, '.') COLLATE NOCASE " \
                  "WHERE n.type = 'NS' AND n.disabled = 0 "
#define AX_IN_ZONE "AND (lower(rtrim(n.content, '.')) = lower(d.name) OR substr(lower(rtrim(n.content, '.')), -(length(d.name) + 1)) = '.' || lower(d.name)) "
    /* D1a step 7: the address rows of the NS targets that are NOT inside the zone, from any zone of the source (the NOTIFY the Backend sends while the zone is out of memory
     * needs them): the row is the zone's (n.domain_id) and the name is the target's.  g.name = lower(...) is an equality on records(name, type) (PowerDNS stores names in lower
     * case; a name stored with upper case letters is not found), one lookup per NS row. */
#define AX_XADDR "SELECT n.domain_id, g.type, g.content, g.ttl, g.id, g.name FROM records n CROSS JOIN domains d ON d.id = n.domain_id AND n.name = d.name COLLATE NOCASE " \
                 "CROSS JOIN records g ON g.name = lower(rtrim(n.content, '.')) AND g.type IN ('A', 'AAAA') AND g.disabled = 0 " \
                 "WHERE n.type = 'NS' AND n.disabled = 0 AND NOT (lower(rtrim(n.content, '.')) = lower(d.name) OR substr(lower(rtrim(n.content, '.')), -(length(d.name) + 1)) = '.' || lower(d.name)) "
    int ret = prep(c, slot, domain_id ? AX_SOA_NS "AND r.domain_id = ?1 UNION ALL " AX_GLUE_1 "AND n.domain_id = ?1 " AX_IN_ZONE "UNION ALL " AX_XADDR "AND n.domain_id = ?1 " "ORDER BY 1, 5"
                                      : AX_SOA_NS "UNION ALL " AX_GLUE_1 AX_IN_ZONE "UNION ALL " AX_XADDR "ORDER BY 1, 5");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) bi64(c, st, 1, *domain_id);
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_apex");
            break;
        }
        bool bad = false;
        db_apex_row_t r;
        r.domain_id = col_int(c, st, 0, "records", sqlite3_column_int64(st, 4), "domain_id", &bad);
        const char *type = col_text(c, st, 1, "records", sqlite3_column_int64(st, 4), "type", &bad);
        r.is_soa = type && strcasecmp(type, "SOA") == 0;
        r.addr_type = type && strcasecmp(type, "A") == 0 ? 1 : type && strcasecmp(type, "AAAA") == 0 ? 28 : 0;
        r.name = col_text(c, st, 5, "records", sqlite3_column_int64(st, 4), "name", &bad);
        r.content = col_text(c, st, 2, "records", sqlite3_column_int64(st, 4), "content", &bad);
        r.ttl_null = sqlite3_column_type(st, 3) == SQLITE_NULL;
        r.ttl = r.ttl_null ? 0 : col_int(c, st, 3, "records", sqlite3_column_int64(st, 4), "ttl", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, &r) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int sq_scan_records_range(db_conn_t *c, int64_t lo, int64_t hi, db_record_cb cb, void *ud) {
    int ret = prep(c, &c->st_rec_rng, "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername "
                                      "FROM records WHERE domain_id >= ?1 AND domain_id <= ?2 ORDER BY domain_id, id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_rec_rng;
    rearm(st);
    bi64(c, st, 1, lo);
    bi64(c, st, 2, hi);
    return rec_loop(c, st, cb, ud);
}

static int sq_scan_domain_views(db_conn_t *c, const int64_t *domain_id, db_domain_view_cb cb, void *ud) {
    if (!c->has_domain_views) {
        set_err(c, "karidns_domain_views does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt **slot = domain_id ? &c->st_dv_one : &c->st_dv_all;
    int ret = prep(c, slot, domain_id ? "SELECT domain_id, view_name FROM karidns_domain_views WHERE domain_id = ?1 ORDER BY view_name"
                                      : "SELECT domain_id, view_name FROM karidns_domain_views ORDER BY domain_id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) bi64(c, st, 1, *domain_id);
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_domain_views");
            break;
        }
        bool bad = false;
        int64_t did = col_int(c, st, 0, "karidns_domain_views", 0, "domain_id", &bad);
        const char *vn = col_text(c, st, 1, "karidns_domain_views", did, "view_name", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (!vn) continue;                  /* the column is NOT NULL; a NULL name maps to no view */
        if (cb(ud, did, vn) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int sq_scan_profiles(db_conn_t *c, db_profile_cb cb, void *ud) {
    if (!c->has_profiles) {
        set_err(c, "karidns_profiles does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    int ret = prep(c, &c->st_prof, "SELECT name, settings FROM karidns_profiles ORDER BY name");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_prof;
    rearm(st);
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_profiles");
            break;
        }
        bool bad = false;
        db_profile_row_t p;
        p.name = col_text(c, st, 0, "karidns_profiles", 0, "name", &bad);
        p.settings = col_text(c, st, 1, "karidns_profiles", 0, "settings", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (!p.name) continue;                  /* the primary key is NOT NULL in practice; a NULL name names no profile */
        if (cb(ud, &p) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

/* the rows of a prepared domainmetadata statement (already bound) to the callback */
static int meta_loop(db_conn_t *c, sqlite3_stmt *st, db_meta_cb cb, void *ud) {
    int ret = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_metadata");
            break;
        }
        bool bad = false;
        int64_t id = col_int(c, st, 3, "domainmetadata", 0, "id", &bad);
        db_meta_row_t m;
        m.domain_id = col_int(c, st, 0, "domainmetadata", id, "domain_id", &bad);
        m.kind = col_text(c, st, 1, "domainmetadata", id, "kind", &bad);
        m.content = col_text(c, st, 2, "domainmetadata", id, "content", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, &m) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int sq_scan_metadata(db_conn_t *c, const int64_t *domain_id, db_meta_cb cb, void *ud) {
    sqlite3_stmt **slot = domain_id ? &c->st_meta_one : &c->st_meta_all;
    int ret = prep(c, slot, domain_id ? "SELECT domain_id, kind, content, id FROM domainmetadata WHERE domain_id = ?1 ORDER BY id"
                                      : "SELECT domain_id, kind, content, id FROM domainmetadata ORDER BY domain_id, id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) bi64(c, st, 1, *domain_id);
    return meta_loop(c, st, cb, ud);
}

static int keys_loop(db_conn_t *c, sqlite3_stmt *st, db_key_cb cb, void *ud) {
    int ret = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "zones_with_keys");
            break;
        }
        if (sqlite3_column_type(st, 0) == SQLITE_NULL) continue;
        bool bad = false;
        const int64_t did = col_int(c, st, 0, "cryptokeys", 0, "domain_id", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, did) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

/* 0.7 signer-wait (dns_db_driver.h signer_waiting): once at a start of the loader, so the statement is not kept.  The serial is the third word of the SOA content, as
 * the signer reads it (signer/lib/db_sqlite.js catchUp()); SQLite3 has no correlated subquery in FROM, so the words are cut in the expression. */
#define SQ_SOA_T1 "substr(r.content, instr(r.content, ' ') + 1)"
#define SQ_SOA_T2 "substr(" SQ_SOA_T1 ", instr(" SQ_SOA_T1 ", ' ') + 1)"
static int sq_signer_waiting(db_conn_t *c, db_key_cb cb, void *ud) {
    unsigned found;
    int rows, rc = table_columns(c, "karidns_signer_state", (const char *const[]){ "domain_id", "signed_at", "signed_serial", NULL }, &found, &rows);
    if (rc != 0) return rc;
    if (rows == 0 || found != 7u || !c->has_zone_state) {
        set_err(c, "karidns_signer_state or karidns_zone_state does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt *st = NULL;
    rc = sqlite3_prepare_v2(c->db,
                            "SELECT s.domain_id FROM karidns_signer_state s "
                            "WHERE EXISTS (SELECT 1 FROM domainmetadata m WHERE m.domain_id = s.domain_id AND upper(m.kind) = 'X-KARIDNS-SIGNER') "
                            "AND (s.signed_serial IS NULL "
                            "OR EXISTS (SELECT 1 FROM karidns_zone_state z WHERE z.domain_id = s.domain_id AND z.changed_at > s.signed_at) "
                            "OR EXISTS (SELECT 1 FROM records r WHERE r.domain_id = s.domain_id AND r.type = 'SOA' AND CAST(substr(" SQ_SOA_T2 ", 1, instr(" SQ_SOA_T2
                            " || ' ', ' ') - 1) AS INTEGER) <> s.signed_serial)) "
                            "ORDER BY s.domain_id",
                            -1, &st, NULL);
    if (rc != SQLITE_OK) return sql_fail(c, rc, "signer_waiting");
    int ret = 0;
    for (;;) {
        rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "signer_waiting");
            break;
        }
        bool bad = false;
        const int64_t did = col_int(c, st, 0, "karidns_signer_state", 0, "domain_id", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, did) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int sq_zones_with_keys(db_conn_t *c, db_key_cb cb, void *ud) {
    int ret = prep(c, &c->st_keys, "SELECT DISTINCT domain_id FROM cryptokeys ORDER BY domain_id");
    if (ret != 0) return ret;
    rearm(c->st_keys);
    return keys_loop(c, c->st_keys, cb, ud);
}

static int sq_changes_since(db_conn_t *c, uint64_t after, db_change_cb cb, void *ud, uint64_t *last_seq, bool *gap) {
    if (!c->has_changes) {
        set_err(c, "karidns_changes does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    int ret = prep(c, &c->st_changes, "SELECT seq, domain_id FROM karidns_changes WHERE seq > ?1 ORDER BY seq");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_changes;
    rearm(st);
    bi64(c, st, 1, (sqlite3_int64)after);
    uint64_t last = after;
    bool g = false, first = true;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "changes_since");
            break;
        }
        db_change_row_t row;
        row.seq = (uint64_t)sqlite3_column_int64(st, 0);       /* (INTEGER PRIMARY KEY: the rowid, always an integer) */
        row.pos = row.seq;
        bool bad = false;
        row.domain_id = col_int(c, st, 1, "karidns_changes", (int64_t)row.seq, "domain_id", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (first && after > 0 && row.seq > after + 1) g = true;      /* rows after `after` were pruned */
        first = false;
        last = row.seq;
        if (cb(ud, &row) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    if (last_seq) *last_seq = last;
    if (gap) *gap = g;
    return ret;
}

static int sq_changes_max(db_conn_t *c, uint64_t *seq) {
    if (!c->has_changes) {
        set_err(c, "karidns_changes does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    int ret = prep(c, &c->st_cmax, "SELECT max(seq) FROM karidns_changes");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_cmax;
    rearm(st);
    int rc = bstep(c, st);
    if (rc == SQLITE_ROW) {
        *seq = sqlite3_column_type(st, 0) == SQLITE_NULL ? 0 : (uint64_t)sqlite3_column_int64(st, 0);
    } else {
        ret = sql_fail(c, rc, "changes_max");
    }
    rearm(st);                       /* (the statement is kept: no cursor may hold the read transaction) */
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* 0.7 store, WP3: the paged calls (dns_db_driver.h)                                                              */
/* ------------------------------------------------------------------------------------------------------------- */

static int need_schema3(db_conn_t *c, const char *what, const char *table) {
    set_err(c, "%s: %s does not exist in this database (a plain PowerDNS schema: the 0.7 store needs karidns_zone_state and karidns_changes, "
               "schema version 3, db/karidns_ext.sqlite3.sql)", what, table);
    return DB_ERR_NEED_SCHEMA3;
}

static int sq_count_domains(db_conn_t *c, const char *view, uint64_t *n) {
    *n = 0;
    bool by_view = view && c->has_domain_views;
    sqlite3_stmt **slot = by_view ? &c->st_cntv : &c->st_cnt;
    int ret = prep(c, slot, by_view ? "SELECT (SELECT count(*) FROM domains) - (SELECT count(DISTINCT domain_id) FROM karidns_domain_views)"
                                      " + (SELECT count(DISTINCT domain_id) FROM karidns_domain_views WHERE view_name = ?1 COLLATE NOCASE)"
                                    : "SELECT count(*) FROM domains");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (by_view) btext(c, st, 1, view, -1, SQLITE_TRANSIENT);
    int rc = bstep(c, st);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        *n = v < 0 ? 0 : (uint64_t)v;
    } else {
        ret = sql_fail(c, rc, "count_domains");
    }
    rearm(st);
    return ret;
}

/* hand the finished group to the callback; DB_STOPPED when it stops the page */
static int mg_flush(db_manifest_cb cb, void *ud, db_mgroup_t *g, int64_t *last_id, unsigned *nrows) {
    g->open = false;
    (*nrows)++;
    *last_id = g->row.id;
    return cb(ud, &g->row) != 0 ? DB_STOPPED : 0;
}

static int sq_manifest_page(db_conn_t *c, int64_t after_id, unsigned limit, db_manifest_cb cb, void *ud, int64_t *last_id, unsigned *nrows) {
    *last_id = after_id;
    *nrows = 0;
    if (limit == 0 || limit > DB_PAGE_MAX) {
        set_err(c, "manifest_page: the limit must be 1 to %u", DB_PAGE_MAX);
        return -1;
    }
    if (!c->has_zone_state) return need_schema3(c, "manifest_page", "karidns_zone_state");
    /* the page of domains is cut first (an index seek on the rowid, LIMIT), then joined: the rows of one domain stay together, ORDER BY d.id,
     * view_name; the statement is built once per connection (the schema does not change under it) */
    char sql[800];
    snprintf(sql, sizeof(sql),
             "SELECT d.id, d.name, d.type, s.generation, s.changed_at, %s FROM (SELECT id, name, type FROM domains WHERE id > ?1 ORDER BY id LIMIT ?2) d "
             "LEFT JOIN karidns_zone_state s ON s.domain_id = d.id %s ORDER BY d.id%s",
             c->has_domain_views ? "v.view_name" : "NULL", c->has_domain_views ? "LEFT JOIN karidns_domain_views v ON v.domain_id = d.id" : "",
             c->has_domain_views ? ", v.view_name" : "");
    int ret = prep(c, &c->st_mpage, sql);
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_mpage;
    rearm(st);
    bi64(c, st, 1, after_id);
    bi64(c, st, 2, limit);
    db_mgroup_t *g = &c->mg;
    g->open = false;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "manifest_page");
            break;
        }
        bool bad = false;
        int64_t id = col_int(c, st, 0, "domains", after_id, "id", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (g->open && id != g->row.id && (ret = mg_flush(cb, ud, g, last_id, nrows)) != 0) break;
        if (!g->open) {
            const char *name = col_text(c, st, 1, "domains", id, "name", &bad);
            const char *type = col_text(c, st, 2, "domains", id, "type", &bad);
            bool has_state = sqlite3_column_type(st, 3) != SQLITE_NULL;
            int64_t gen = has_state ? col_int(c, st, 3, "karidns_zone_state", id, "generation", &bad) : 0;
            int64_t at = has_state ? col_int(c, st, 4, "karidns_zone_state", id, "changed_at", &bad) : 0;
            const char *why = bad ? NULL : db_mgroup_start(g, id, name, type, has_state, gen, at);
            if (why) {
                set_err(c, "table domains id %lld: %s", (long long)id, why);
                bad = true;
            }
            if (bad) {
                ret = -1;
                break;
            }
        }
        const char *vn = col_text(c, st, 5, "karidns_domain_views", id, "view_name", &bad);
        const char *why = !bad && vn ? db_mgroup_view(g, vn) : NULL;
        if (why) {
            set_err(c, "table karidns_domain_views domain %lld: %s", (long long)id, why);
            bad = true;
        }
        if (bad) {
            ret = -1;
            break;
        }
    }
    if (ret == 0 && g->open) ret = mg_flush(cb, ud, g, last_id, nrows);
    g->open = false;
    rearm(st);
    return ret;
}

static int sq_current_cursor(db_conn_t *c, uint64_t *cursor) {
    *cursor = 0;
    if (!c->has_changes) return need_schema3(c, "current_cursor", "karidns_changes");
    return sq_changes_max(c, cursor);
}

static int sq_changes_page(db_conn_t *c, db_change_pos_t *pos, unsigned limit, db_change_entry_cb cb, void *ud, bool *more, bool *gap) {
    *more = false;
    *gap = false;
    if (limit == 0 || limit > DB_PAGE_MAX) {
        set_err(c, "changes_page: the limit must be 1 to %u", DB_PAGE_MAX);
        return -1;
    }
    if (!c->has_changes) return need_schema3(c, "changes_page", "karidns_changes");
    /* the window of `limit` log rows after the cursor, one entry per domain (its highest seq), with the domain's existence in the same snapshot;
     * mn, mx and cnt describe the whole window (the same on every row) */
    int ret = prep(c, &c->st_cpage,
                   "WITH w AS (SELECT seq, domain_id FROM karidns_changes WHERE seq > ?1 ORDER BY seq LIMIT ?2), "
                   "a AS (SELECT domain_id, seq, min(seq) OVER () AS mn, max(seq) OVER () AS mx, count(*) OVER () AS cnt, "
                   "max(seq) OVER (PARTITION BY domain_id) AS dm FROM w) "
                   "SELECT domain_id, seq, EXISTS (SELECT 1 FROM domains d WHERE d.id = a.domain_id), mn, mx, cnt FROM a WHERE seq = dm ORDER BY seq");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_cpage;
    rearm(st);
    uint64_t after = pos->cursor, mx = after;
    bi64(c, st, 1, (sqlite3_int64)after);
    bi64(c, st, 2, limit);
    int64_t cnt = 0;
    bool any = false;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "changes_page");
            break;
        }
        if (!any) {
            any = true;
            if (after > 0 && (uint64_t)sqlite3_column_int64(st, 3) > after + 1) *gap = true;      /* rows after the cursor were pruned */
        }
        mx = (uint64_t)sqlite3_column_int64(st, 4);
        cnt = sqlite3_column_int64(st, 5);
        db_change_entry_t e;
        e.seq = (uint64_t)sqlite3_column_int64(st, 1);              /* (the rowid and aggregates of it, and EXISTS: always integers) */
        bool bad = false;
        e.domain_id = col_int(c, st, 0, "karidns_changes", (int64_t)e.seq, "domain_id", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        e.op = sqlite3_column_int64(st, 2) ? DB_CHANGE_UPSERT : DB_CHANGE_DELETE;
        e.pos_lo = e.pos_hi = e.seq;                                 /* (one writer: the highest seq of the domain stands for its rows) */
        if (cb(ud, &e) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    if (ret != 0) return ret;
    if (!any && after > 0) {
        /* nothing after the cursor: either the log is at it, or the log is below it (emptied, or a database that is not the one the cursor came from) */
        uint64_t top = 0;
        if ((ret = sq_changes_max(c, &top)) != 0) return ret;
        if (top < after) *gap = true;
    }
    pos->cursor = mx;
    pos->seq = pos->settle = 0;
    *more = cnt >= (int64_t)limit;
    return 0;
}

static int sq_wait_fd(db_conn_t *c) {
    (void)c;
    return -1;      /* SQLite3 has no notifications: the loader polls PRAGMA data_version by timer (B9) */
}

static int sq_drain_notifications(db_conn_t *c, bool *changed) {
    (void)c;
    if (changed) *changed = false;
    return 0;
}

static int sq_report_status(db_conn_t *c, const db_status_t *st) {
    (void)c;
    (void)st;
    return 0;       /* multi-server status is PostgreSQL only (design 2.2) */
}

/* B8: karidns_record_tags / karidns_record_tinydns (through records, for the domain id) / karidns_zone_tagdefs.  Each table in its own
 * pass, rows ordered by (domain_id, record_id); the tag definitions by (domain_id, rowid): the order the rows were inserted in is the
 * order of the definitions in a zone file, and the first definition that matches a client wins. */
/* the three loops of the extension tables over a prepared statement (already bound): the rows to the sink */
static int xt_loop(db_conn_t *c, sqlite3_stmt *st, const db_ext_sink_t *sink) {
    int ret = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_ext (karidns_record_tags)");
            break;
        }
        bool bad = false;
        db_tag_row_t row;
        row.record_id = sqlite3_column_int64(st, 1);             /* (INTEGER PRIMARY KEY: always an integer) */
        int64_t did = col_int(c, st, 0, "records", 0, "domain_id", &bad);
        row.location_tag = col_text(c, st, 2, "karidns_record_tags", row.record_id, "location_tag", &bad);
        row.ecs_tag = col_text(c, st, 3, "karidns_record_tags", row.record_id, "ecs_tag", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (sink->record_tags(sink->ud, did, &row) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int xd_loop(db_conn_t *c, sqlite3_stmt *st, const db_ext_sink_t *sink) {
    int ret = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_ext (karidns_record_tinydns)");
            break;
        }
        bool bad = false;
        db_tinydns_row_t row;
        row.record_id = sqlite3_column_int64(st, 1);             /* (INTEGER PRIMARY KEY: always an integer) */
        int64_t did = col_int(c, st, 0, "records", 0, "domain_id", &bad);
        row.ttd_null = sqlite3_column_type(st, 2) == SQLITE_NULL;
        row.ttd = row.ttd_null ? 0 : col_int(c, st, 2, "karidns_record_tinydns", row.record_id, "ttd", &bad);
        row.loc = col_text(c, st, 3, "karidns_record_tinydns", row.record_id, "loc", &bad);
        row.countdown = sqlite3_column_type(st, 4) != SQLITE_NULL && col_int(c, st, 4, "karidns_record_tinydns", row.record_id, "countdown", &bad) != 0;
        if (bad) {
            ret = -1;
            break;
        }
        if (sink->record_tinydns(sink->ud, did, &row) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int xg_loop(db_conn_t *c, sqlite3_stmt *st, const db_ext_sink_t *sink) {
    int ret = 0;
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_ext (karidns_zone_tagdefs)");
            break;
        }
        bool bad = false;
        int64_t did = col_int(c, st, 0, "karidns_zone_tagdefs", 0, "domain_id", &bad);
        db_tagdef_row_t row;
        row.kind = col_text(c, st, 1, "karidns_zone_tagdefs", did, "kind", &bad);
        row.tag = col_text(c, st, 2, "karidns_zone_tagdefs", did, "tag", &bad);
        row.cidr = col_text(c, st, 3, "karidns_zone_tagdefs", did, "cidr", &bad);
        if (bad) {
            ret = -1;
            break;
        }
        if (sink->tagdef(sink->ud, did, &row) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
}

static int sq_scan_ext(db_conn_t *c, const int64_t *domain_id, const db_ext_sink_t *sink) {
    if (!c->has_ext) {
        set_err(c, "the karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs tables do not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    const int one = domain_id ? 1 : 0;
    int ret = prep(c, &c->st_xt[one],
                   one ? "SELECT r.domain_id, t.record_id, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id "
                         "WHERE r.domain_id = ?1 ORDER BY t.record_id"
                       : "SELECT r.domain_id, t.record_id, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id "
                         "ORDER BY r.domain_id, t.record_id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_xt[one];
    rearm(st);
    if (one) bi64(c, st, 1, *domain_id);
    if ((ret = xt_loop(c, st, sink)) != 0) return ret;

    ret = prep(c, &c->st_xd[one],
               one ? "SELECT r.domain_id, t.record_id, t.ttd, t.loc, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                     "WHERE r.domain_id = ?1 ORDER BY t.record_id"
                   : "SELECT r.domain_id, t.record_id, t.ttd, t.loc, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                     "ORDER BY r.domain_id, t.record_id");
    if (ret != 0) return ret;
    st = c->st_xd[one];
    rearm(st);
    if (one) bi64(c, st, 1, *domain_id);
    if ((ret = xd_loop(c, st, sink)) != 0) return ret;

    ret = prep(c, &c->st_xg[one],
               one ? "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs WHERE domain_id = ?1 ORDER BY rowid"
                   : "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs ORDER BY domain_id, rowid");
    if (ret != 0) return ret;
    st = c->st_xg[one];
    rearm(st);
    if (one) bi64(c, st, 1, *domain_id);
    return xg_loop(c, st, sink);
}

/* ---- several zones in one statement per table (scan_records_in, scan_metadata_in, scan_ext_in) ----
 * The same rows in the same order as the single-zone calls one after the other (ORDER BY domain_id, then the order of the one-zone statement).  The statement
 * has an IN list; its text depends on how many ids there are, so there is one kept statement for each table and size class (2, 4, ... 128 = DB_IN_MAX ids; parsed at
 * the first use of the class); the placeholders a call does not need are bound NULL, which is equal to no id.  Where a one-zone statement is a few microseconds,
 * a fetch of 64 zones asks the database seven times instead of about 450. */
enum { IN_REC, IN_META, IN_XT, IN_XD, IN_XG, IN_KEY, IN_KINDS };

static sqlite3_stmt *in_stmt(db_conn_t *c, int kind, const int64_t *ids, size_t n, int *err) {
    *err = 0;
    if (n == 0 || n > DB_IN_MAX) {
        set_err(c, "scan_*_in: %zu zones (1..%u allowed)", n, DB_IN_MAX);
        *err = -1;
        return NULL;
    }
    size_t cls = 0, cap = 2;
    while (cap < n) {
        cap <<= 1;
        cls++;
    }
    sqlite3_stmt **slot = &c->st_in[kind][cls];
    if (!*slot) {
        static const struct { const char *head, *col, *tail; } k_in[IN_KINDS] = {
            [IN_REC] = { "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername FROM records WHERE domain_id IN (", "", ") ORDER BY domain_id, id" },
            [IN_META] = { "SELECT domain_id, kind, content, id FROM domainmetadata WHERE domain_id IN (", "", ") ORDER BY domain_id, id" },
            [IN_XT] = { "SELECT r.domain_id, t.record_id, t.location_tag, t.ecs_tag FROM karidns_record_tags t JOIN records r ON r.id = t.record_id "
                        "WHERE r.domain_id IN (", "", ") ORDER BY r.domain_id, t.record_id" },
            [IN_XD] = { "SELECT r.domain_id, t.record_id, t.ttd, t.loc, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                        "WHERE r.domain_id IN (", "", ") ORDER BY r.domain_id, t.record_id" },
            [IN_XG] = { "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs WHERE domain_id IN (", "", ") ORDER BY domain_id, rowid" },
            [IN_KEY] = { "SELECT DISTINCT domain_id FROM cryptokeys WHERE domain_id IN (", "", ") ORDER BY domain_id" },
        };
        char sql[1600];
        size_t o = (size_t)snprintf(sql, sizeof(sql), "%s", k_in[kind].head);
        for (size_t i = 0; i < cap; i++) o += (size_t)snprintf(sql + o, sizeof(sql) - o, "%s?%zu", i ? "," : "", i + 1);
        snprintf(sql + o, sizeof(sql) - o, "%s", k_in[kind].tail);
        if ((*err = prep(c, slot, sql)) != 0) return NULL;
    }
    sqlite3_stmt *st = *slot;
    rearm(st);
    for (size_t i = 0; i < cap; i++) {
        if (i < n) bi64(c, st, (int)i + 1, ids[i]);
        else bnull(c, st, (int)i + 1);
    }
    return st;
}

static int sq_scan_records_in(db_conn_t *c, const int64_t *ids, size_t n, db_record_cb cb, void *ud) {
    int err;
    sqlite3_stmt *st = in_stmt(c, IN_REC, ids, n, &err);
    return st ? rec_loop(c, st, cb, ud) : err;
}

static int sq_scan_metadata_in(db_conn_t *c, const int64_t *ids, size_t n, db_meta_cb cb, void *ud) {
    int err;
    sqlite3_stmt *st = in_stmt(c, IN_META, ids, n, &err);
    return st ? meta_loop(c, st, cb, ud) : err;
}

static int sq_zones_with_keys_in(db_conn_t *c, const int64_t *ids, size_t n, db_key_cb cb, void *ud) {
    int err;
    sqlite3_stmt *st = in_stmt(c, IN_KEY, ids, n, &err);
    return st ? keys_loop(c, st, cb, ud) : err;
}

static int sq_scan_ext_in(db_conn_t *c, const int64_t *ids, size_t n, const db_ext_sink_t *sink) {
    if (!c->has_ext) {
        set_err(c, "the karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs tables do not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    int err;
    sqlite3_stmt *st = in_stmt(c, IN_XT, ids, n, &err);
    if (!st || (err = xt_loop(c, st, sink)) != 0) return err;
    st = in_stmt(c, IN_XD, ids, n, &err);
    if (!st || (err = xd_loop(c, st, sink)) != 0) return err;
    st = in_stmt(c, IN_XG, ids, n, &err);
    return st ? xg_loop(c, st, sink) : err;
}

/* B9: PRAGMA data_version on the persistent connection (it reports commits of other connections only; the loader never
 * writes, so every change it sees is somebody else's).  The statement is reset after each step so that no read
 * transaction stays open.  The file is looked up by name each time: a replaced or deleted file keeps being read through the
 * old descriptor, so only the name can tell. */
static int sq_poll_version(db_conn_t *c, uint64_t *version, bool *replaced) {
    struct stat sb;
    *replaced = !c->path || stat(c->path, &sb) != 0 || (c->have_id && (sb.st_dev != c->dev || sb.st_ino != c->ino));
    int ret = prep(c, &c->st_pv, "PRAGMA data_version");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_pv;
    rearm(st);
    int rc = bstep(c, st);
    if (rc == SQLITE_ROW) *version = (uint64_t)sqlite3_column_int64(st, 0);
    else ret = sql_fail(c, rc, "PRAGMA data_version");
    rearm(st);
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* M2: write access for the ZoneImporter (dns_db_driver.h).  Only open_write() connections get here.                 */
/* ------------------------------------------------------------------------------------------------------------- */

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

static void bind_txt(db_conn_t *c, sqlite3_stmt *st, int i, const char *s) {
    if (s) btext(c, st, i, s, -1, SQLITE_STATIC);
    else bnull(c, st, i);
}

/* run a statement whose parameters are bound, once, and put it back to the start */
static int wstep(db_conn_t *c, sqlite3_stmt *st, const char *what) {
    int rc = bstep(c, st);
    int ret = rc == SQLITE_DONE ? 0 : sql_fail(c, rc, what);
    wrearm(st);
    return ret;
}

/* a statement that runs once: prepare, run (parameters bound by the caller before wstep1), finalize */
static int wstep1(db_conn_t *c, sqlite3_stmt *st, const char *what) {
    int rc = bstep(c, st);
    int ret = rc == SQLITE_DONE ? 0 : sql_fail(c, rc, what);
    sqlite3_finalize(st);
    return ret;
}

/* Who is writing, for the audit triggers of db/karidns_audit.sqlite3.sql: the one row (id 1) of karidns_audit_actor, written first in the
 * transaction and deleted by w_commit().  A database without the table (schema version 2, or an older file) gets no row.  Inside
 * BEGIN IMMEDIATE, so no other writer can see the row. */
static int put_actor(db_conn_t *c) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c->db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'karidns_audit_actor'", -1, &st, NULL);
    if (rc == SQLITE_OK) rc = bstep(c, st);
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return 0;
    if (rc != SQLITE_ROW) return sql_fail(c, rc, "karidns_audit_actor");
    st = NULL;
    rc = sqlite3_prepare_v2(c->db, "INSERT OR REPLACE INTO karidns_audit_actor (id, principal_id, principal_name, change_set, db_role) "
                                   "VALUES (1, ?2, ?3, ?4, ?1)", -1, &st, NULL);
    if (rc != SQLITE_OK) return sql_fail(c, rc, "karidns_audit_actor");
    bind_txt(c, st, 1, c->audit_actor);
    if (c->actor_has_pid) bi64(c, st, 2, c->actor_pid);
    else bnull(c, st, 2);
    bind_txt(c, st, 3, c->actor_has_pname ? c->actor_pname : NULL);
    bind_txt(c, st, 4, c->actor_has_cs ? c->actor_cs : NULL);
    int ret = wstep1(c, st, "karidns_audit_actor");
    c->actor_set = ret == 0;
    return ret;
}

/* karidns-zone --audit (dns_db_driver.h): the actor the next w_begin() writes; summary does not exist on SQLite3 */
static int sq_w_set_audit(db_conn_t *c, bool summary, const char *actor) {
    (void)summary;
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_set_audit: needs a writable connection outside a transaction");
        return -1;
    }
    c->audit_actor = actor;
    return 0;
}

static int sq_w_begin(db_conn_t *c, const char *zone) {
    (void)zone;                         /* the lock is the whole database: BEGIN IMMEDIATE takes SQLite's one write lock */
    if (!c->writable) {
        set_err(c, "w_begin: the connection is read only (open_write() makes a writable one)");
        return -1;
    }
    if (c->in_snapshot || c->in_wtxn) {
        set_err(c, "w_begin: a transaction is already open");
        return -1;
    }
    int rc = exec(c, "BEGIN IMMEDIATE");
    if (rc != 0) return rc;
    if ((c->audit_actor || c->have_actor) && (rc = put_actor(c)) != 0) {
        sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);          /* a failed w_begin leaves no transaction open */
        return rc;
    }
    c->in_wtxn = c->in_snapshot = true;
    return 0;
}

static int sq_w_commit(db_conn_t *c) {
    int ret = wcheck(c, "w_commit");
    if (ret != 0) return ret;
    rearm_all(c);
    if (c->actor_set) {
        c->actor_set = false;
        if ((ret = exec(c, "DELETE FROM karidns_audit_actor WHERE id = 1")) != 0) {
            c->in_wtxn = c->in_snapshot = false;
            sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);
            return ret;
        }
    }
    c->in_wtxn = c->in_snapshot = false;
    ret = exec(c, "COMMIT");
    if (ret != 0) sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);       /* a failed COMMIT can leave the transaction open */
    return ret;
}

static int sq_w_rollback(db_conn_t *c) {
    if (!c->in_wtxn) return 0;
    rearm_all(c);
    for (size_t i = 0; i < sizeof(c->st_w) / sizeof(c->st_w[0]); i++)
        if (c->st_w[i]) wrearm(c->st_w[i]);
    c->in_wtxn = c->in_snapshot = false;
    c->actor_set = false;                       /* the ROLLBACK takes the actor row with the rest */
    return exec(c, "ROLLBACK");
}

static int sq_w_create_zone(db_conn_t *c, const char *name, const char *type, int64_t *id) {
    int ret = wcheck(c, "w_create_zone");
    if (ret != 0) return ret;
    sqlite3_stmt *st = NULL;
    ret = prep(c, &st, "INSERT INTO domains (name, type) VALUES (?1, ?2)");
    if (ret != 0) return ret;
    btext(c, st, 1, name, -1, SQLITE_STATIC);
    btext(c, st, 2, type ? type : "NATIVE", -1, SQLITE_STATIC);
    ret = wstep1(c, st, "w_create_zone");
    if (ret == 0) *id = (int64_t)sqlite3_last_insert_rowid(c->db);
    return ret;
}

static int sq_w_delete_records(db_conn_t *c, int64_t domain_id, const int64_t *ids, size_t n) {
    int ret = wcheck(c, "w_delete_records");
    if (ret != 0) return ret;
    if (!ids) {
        /* the extension rows first: their delete triggers find the zone through the record */
        static const char *const sql[] = {
            "DELETE FROM karidns_record_tags WHERE record_id IN (SELECT id FROM records WHERE domain_id = ?1)",
            "DELETE FROM karidns_record_tinydns WHERE record_id IN (SELECT id FROM records WHERE domain_id = ?1)",
            "DELETE FROM records WHERE domain_id = ?1",
        };
        for (size_t i = c->has_ext ? 0 : 2; i < 3 && ret == 0; i++) {
            sqlite3_stmt *st = NULL;
            if ((ret = prep(c, &st, sql[i])) != 0) return ret;
            bi64(c, st, 1, domain_id);
            ret = wstep1(c, st, "w_delete_records");
        }
        return ret;
    }
    /* the ids belong to the zone: every statement says so, so an id of another zone deletes nothing */
    if (c->has_ext) {
        ret = prep(c, &c->st_w[W_DEL_TAGS_ID], "DELETE FROM karidns_record_tags WHERE record_id = ?1 AND EXISTS (SELECT 1 FROM records WHERE id = ?1 AND domain_id = ?2)");
        if (ret == 0)
            ret = prep(c, &c->st_w[W_DEL_TD_ID], "DELETE FROM karidns_record_tinydns WHERE record_id = ?1 AND EXISTS (SELECT 1 FROM records WHERE id = ?1 AND domain_id = ?2)");
    }
    if (ret == 0) ret = prep(c, &c->st_w[W_DEL_REC_ID], "DELETE FROM records WHERE id = ?1 AND domain_id = ?2");
    for (size_t i = 0; i < n && ret == 0; i++) {
        for (int k = c->has_ext ? W_DEL_TAGS_ID : W_DEL_REC_ID; k <= W_DEL_REC_ID && ret == 0; k++) {
            sqlite3_stmt *st = c->st_w[k];
            bi64(c, st, 1, ids[i]);
            bi64(c, st, 2, domain_id);
            ret = wstep(c, st, "w_delete_records");
        }
    }
    return ret;
}

static int sq_w_insert_record(db_conn_t *c, int64_t domain_id, const db_record_row_t *row, bool auth, int64_t *id) {
    int ret = wcheck(c, "w_insert_record");
    if (ret != 0) return ret;
    ret = prep(c, &c->st_w[W_INS_REC],
               "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, auth, ordername) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_w[W_INS_REC];
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, row->name);
    bind_txt(c, st, 3, row->type);
    bind_txt(c, st, 4, row->content);
    if (row->ttl_null) bnull(c, st, 5);
    else bi64(c, st, 5, row->ttl);
    if (row->prio_null) bnull(c, st, 6);
    else bi64(c, st, 6, row->prio);
    bi64(c, st, 7, row->disabled ? 1 : 0);
    bi64(c, st, 8, auth ? 1 : 0);
    bind_txt(c, st, 9, row->ordername);
    ret = wstep(c, st, "w_insert_record");
    if (ret == 0) *id = (int64_t)sqlite3_last_insert_rowid(c->db);
    return ret;
}

static int ext_missing(db_conn_t *c) {
    set_err(c, "the karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs tables do not exist in this database");
    return DB_ERR_UNAVAILABLE;
}

static int sq_w_insert_tags(db_conn_t *c, int64_t record_id, const char *loc, const char *ecs) {
    int ret = wcheck(c, "w_insert_tags");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    if ((ret = prep(c, &c->st_w[W_INS_TAGS], "INSERT INTO karidns_record_tags (record_id, location_tag, ecs_tag) VALUES (?1, ?2, ?3)")) != 0) return ret;
    sqlite3_stmt *st = c->st_w[W_INS_TAGS];
    bi64(c, st, 1, record_id);
    bind_txt(c, st, 2, loc);
    bind_txt(c, st, 3, ecs);
    return wstep(c, st, "w_insert_tags");
}

static int sq_w_insert_tinydns(db_conn_t *c, int64_t record_id, int64_t ttd, const char *loc, bool countdown) {
    int ret = wcheck(c, "w_insert_tinydns");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    if ((ret = prep(c, &c->st_w[W_INS_TD], "INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES (?1, ?2, ?3, ?4)")) != 0) return ret;
    sqlite3_stmt *st = c->st_w[W_INS_TD];
    bi64(c, st, 1, record_id);
    bi64(c, st, 2, ttd);
    bind_txt(c, st, 3, loc);
    bi64(c, st, 4, countdown ? 1 : 0);
    return wstep(c, st, "w_insert_tinydns");
}

static int sq_w_delete_tagdefs(db_conn_t *c, int64_t domain_id, const char *kind, const char *tag) {
    int ret = wcheck(c, "w_delete_tagdefs");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "DELETE FROM karidns_zone_tagdefs WHERE domain_id = ?1 AND (?2 IS NULL OR kind = ?2) AND (?3 IS NULL OR lower(tag) = lower(?3))")) != 0)
        return ret;
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, kind);
    bind_txt(c, st, 3, tag);
    return wstep1(c, st, "w_delete_tagdefs");
}

static int sq_w_insert_tagdef(db_conn_t *c, int64_t domain_id, const char *kind, const char *tag, const char *cidr) {
    int ret = wcheck(c, "w_insert_tagdef");
    if (ret != 0) return ret;
    if (!c->has_ext) return ext_missing(c);
    if ((ret = prep(c, &c->st_w[W_INS_TAGDEF], "INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (?1, ?2, ?3, ?4)")) != 0) return ret;
    sqlite3_stmt *st = c->st_w[W_INS_TAGDEF];
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, kind);
    bind_txt(c, st, 3, tag);
    bind_txt(c, st, 4, cidr);
    return wstep(c, st, "w_insert_tagdef");
}

static int sq_w_delete_meta(db_conn_t *c, int64_t domain_id, const char *kind) {
    int ret = wcheck(c, "w_delete_meta");
    if (ret != 0) return ret;
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "DELETE FROM domainmetadata WHERE domain_id = ?1 AND upper(kind) = upper(?2)")) != 0) return ret;
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, kind);
    return wstep1(c, st, "w_delete_meta");
}

static int sq_w_insert_meta(db_conn_t *c, int64_t domain_id, const char *kind, const char *content) {
    int ret = wcheck(c, "w_insert_meta");
    if (ret != 0) return ret;
    if ((ret = prep(c, &c->st_w[W_INS_META], "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?1, ?2, ?3)")) != 0) return ret;
    sqlite3_stmt *st = c->st_w[W_INS_META];
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, kind);
    bind_txt(c, st, 3, content);
    return wstep(c, st, "w_insert_meta");
}

static int sq_w_set_view(db_conn_t *c, int64_t domain_id, const char *view_name) {
    int ret = wcheck(c, "w_set_view");
    if (ret != 0) return ret;
    if (!c->has_domain_views) {
        set_err(c, "karidns_domain_views does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (?1, ?2) ON CONFLICT (domain_id, view_name) DO NOTHING")) != 0)
        return ret;
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, view_name);
    return wstep1(c, st, "w_set_view");
}

static int sq_w_request_reload(db_conn_t *c, const char *zone, bool force) {
    (void)zone;
    (void)force;
    set_err(c, "karidns_reload_requests exists on PostgreSQL only (multi-server operation); the change log triggers tell a running server");
    return DB_ERR_UNAVAILABLE;
}

static int sq_w_zone_has_keys(db_conn_t *c, int64_t domain_id, bool *has) {
    int ret = wcheck(c, "w_zone_has_keys");
    if (ret != 0) return ret;
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "SELECT 1 FROM cryptokeys WHERE domain_id = ?1 LIMIT 1")) != 0) return ret;
    bi64(c, st, 1, domain_id);
    int rc = bstep(c, st);
    if (rc == SQLITE_ROW || rc == SQLITE_DONE) *has = rc == SQLITE_ROW;
    else ret = sql_fail(c, rc, "w_zone_has_keys");
    sqlite3_finalize(st);
    return ret;
}

/* ---- item C, the signer (dns_db_driver.h): the authoritative flags, one record's ordername / auth / content, the id of the write ---- */
static int sq_w_scan_auth(db_conn_t *c, int64_t domain_id, db_auth_cb cb, void *ud) {
    int ret = wcheck(c, "w_scan_auth");
    if (ret != 0) return ret;
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "SELECT id, auth FROM records WHERE domain_id = ?1 ORDER BY id")) != 0) return ret;
    bi64(c, st, 1, domain_id);
    for (;;) {
        int rc = bstep(c, st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "w_scan_auth");
            break;
        }
        bool bad = false;
        const int64_t rid = col_int(c, st, 0, "records", 0, "id", &bad);
        const bool auth = sqlite3_column_type(st, 1) == SQLITE_NULL || col_int(c, st, 1, "records", rid, "auth", &bad) != 0;
        if (bad) {
            ret = -1;
            break;
        }
        if (cb(ud, rid, auth) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int sq_w_update_record(db_conn_t *c, int64_t domain_id, int64_t id, const char *content, const char *ordername, bool auth) {
    int ret = wcheck(c, "w_update_record");
    if (ret != 0) return ret;
    if ((ret = prep(c, &c->st_w[W_UPD_REC], "UPDATE records SET content = coalesce(?3, content), ordername = ?4, auth = ?5 WHERE id = ?1 AND domain_id = ?2")) != 0) return ret;
    sqlite3_stmt *st = c->st_w[W_UPD_REC];
    bi64(c, st, 1, id);
    bi64(c, st, 2, domain_id);
    bind_txt(c, st, 3, content);
    bind_txt(c, st, 4, ordername);
    bi64(c, st, 5, auth ? 1 : 0);
    ret = wstep(c, st, "w_update_record");
    if (ret == 0 && sqlite3_changes(c->db) != 1) {
        set_err(c, "w_update_record: record %lld is not in zone %lld", (long long)id, (long long)domain_id);
        ret = DB_ERR_CONFLICT;
    }
    return ret;
}

static int sq_w_update_orders(db_conn_t *c, int64_t domain_id, const db_order_t *v, size_t n) {
    int ret = wcheck(c, "w_update_orders");
    for (size_t i = 0; i < n && ret == 0; i++) ret = sq_w_update_record(c, domain_id, v[i].id, NULL, v[i].ordername, v[i].auth);
    return ret;
}

static int sq_w_insert_dnssec(db_conn_t *c, int64_t domain_id, const db_ins_t *v, size_t n) {
    int ret = wcheck(c, "w_insert_dnssec");
    for (size_t i = 0; i < n && ret == 0; i++) {
        int64_t id;
        ret = sq_w_insert_record(c, domain_id, v[i].row, v[i].auth, &id);
    }
    return ret;
}

static int sq_w_set_snapshot(db_conn_t *c, bool on) {
    (void)on;                           /* BEGIN IMMEDIATE: one writer, nothing changes under it */
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_set_snapshot: needs a writable connection outside a transaction");
        return -1;
    }
    return 0;
}

static int sq_w_delete_dnssec(db_conn_t *c, int64_t domain_id, const int64_t *ids, size_t n) {
    int ret = wcheck(c, "w_delete_dnssec");
    if (ret != 0) return ret;
    if ((ret = prep(c, &c->st_w[W_DEL_REC_ID], "DELETE FROM records WHERE id = ?1 AND domain_id = ?2")) != 0) return ret;
    for (size_t i = 0; i < n && ret == 0; i++) {
        sqlite3_stmt *st = c->st_w[W_DEL_REC_ID];
        bi64(c, st, 1, ids[i]);
        bi64(c, st, 2, domain_id);
        ret = wstep(c, st, "w_delete_dnssec");
    }
    return ret;
}

/* the highest seq of karidns_changes (0: none, or no such table) */
static int change_max(db_conn_t *c, uint64_t *seq) {
    *seq = 0;
    if (!c->has_changes) return 0;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c->db, "SELECT coalesce(max(seq), 0) FROM karidns_changes", -1, &st, NULL);
    if (rc != SQLITE_OK) return sql_fail(c, rc, "prepare");
    int ret = 0;
    rc = bstep(c, st);
    if (rc == SQLITE_ROW) *seq = (uint64_t)sqlite3_column_int64(st, 0);
    else ret = sql_fail(c, rc, "w_mark");
    sqlite3_finalize(st);
    return ret;
}

static int sq_w_mark(db_conn_t *c, uint64_t *mark) {
    int ret = wcheck(c, "w_mark");
    return ret != 0 ? ret : change_max(c, mark);
}

static int sq_w_write_id(db_conn_t *c, uint64_t mark, db_write_id_t *id) {
    memset(id, 0, sizeof(*id));
    int ret = wcheck(c, "w_write_id");
    if (ret != 0 || !c->has_changes) return ret;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c->db, "SELECT coalesce(min(seq), 0), coalesce(max(seq), 0) FROM karidns_changes WHERE seq > ?1", -1, &st, NULL);
    if (rc != SQLITE_OK) return sql_fail(c, rc, "prepare");
    bi64(c, st, 1, (sqlite3_int64)mark);
    rc = bstep(c, st);
    if (rc == SQLITE_ROW) {
        id->seq_first = (uint64_t)sqlite3_column_int64(st, 0);
        id->seq_last = (uint64_t)sqlite3_column_int64(st, 1);
    } else {
        ret = sql_fail(c, rc, "w_write_id");
    }
    sqlite3_finalize(st);
    return ret;
}

/* ---- items D and E: karidns-zone apply (dns_db_driver.h) ---- */
static int sq_w_set_actor(db_conn_t *c, const db_actor_t *a) {
    if (!c->writable || c->in_wtxn) {
        set_err(c, "w_set_actor: needs a writable connection outside a transaction");
        return -1;
    }
    c->have_actor = c->actor_has_pid = c->actor_has_pname = c->actor_has_cs = false;
    if (!a) return 0;
    c->have_actor = a->has_principal || a->principal_name || a->change_set;
    c->actor_has_pid = a->has_principal;
    c->actor_pid = a->principal_id;
    if ((c->actor_has_pname = a->principal_name != NULL)) snprintf(c->actor_pname, sizeof(c->actor_pname), "%s", a->principal_name);
    if ((c->actor_has_cs = a->change_set != NULL)) snprintf(c->actor_cs, sizeof(c->actor_cs), "%s", a->change_set);
    return 0;
}

static int sq_w_zone_generation(db_conn_t *c, int64_t domain_id, uint64_t *generation) {
    int ret = wcheck(c, "w_zone_generation");
    if (ret != 0) return ret;
    *generation = 0;
    if (!c->has_zone_state) {
        set_err(c, "karidns_zone_state does not exist in this database (apply db/karidns_ext.sqlite3.sql)");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "SELECT generation FROM karidns_zone_state WHERE domain_id = ?1")) != 0) return ret;
    bi64(c, st, 1, domain_id);
    int rc = bstep(c, st);
    if (rc == SQLITE_ROW) {
        bool bad = false;
        const int64_t g = col_int(c, st, 0, "karidns_zone_state", domain_id, "generation", &bad);
        if (bad) ret = -1;
        else *generation = g < 0 ? 0 : (uint64_t)g;         /* (a negative one, which the schema's CHECK forbids, is 0: as PostgreSQL and the manifest, review D-5) */
    } else if (rc != SQLITE_DONE) {
        ret = sql_fail(c, rc, "w_zone_generation");
    }
    sqlite3_finalize(st);
    return ret;
}

static int sq_w_bump_serial(db_conn_t *c, int64_t domain_id, int64_t soa_id, const char *new_content, bool via_api, uint32_t *serial) {
    (void)via_api;                      /* SQLite3 has no roles: the API checks, and writes the row itself */
    (void)serial;                       /* the row has the serial the caller wrote */
    int ret = wcheck(c, "w_bump_serial");
    if (ret != 0) return ret;
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "UPDATE records SET content = ?3 WHERE id = ?1 AND domain_id = ?2")) != 0) return ret;
    bi64(c, st, 1, soa_id);
    bi64(c, st, 2, domain_id);
    bind_txt(c, st, 3, new_content);
    int rc = bstep(c, st);
    if (rc != SQLITE_DONE) {
        ret = sql_fail(c, rc, "w_bump_serial");
    } else if (sqlite3_changes(c->db) != 1) {
        set_err(c, "w_bump_serial: the SOA record %lld is not in zone %lld", (long long)soa_id, (long long)domain_id);
        ret = DB_ERR_CONFLICT;
    }
    sqlite3_finalize(st);
    return ret;
}

static int sq_w_insert_version(db_conn_t *c, int64_t domain_id, const db_version_t *v, uint32_t *number, int64_t *id) {
    int ret = wcheck(c, "w_insert_version");
    if (ret != 0) return ret;
    if (!c->has_versions) {
        set_err(c, "karidns_zone_versions does not exist in this database (apply db/karidns_ext.sqlite3.sql)");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt *st = NULL;
    ret = prep(c, &st, "INSERT INTO karidns_zone_versions (domain_id, version, kind, change_set, principal_id, principal_name, db_role, comment, serial_before, serial_after, "
                       "generation_before, generation_after, rollback_of, delta_complete) "
                       "SELECT ?1, coalesce(max(version), 0) + 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13 FROM karidns_zone_versions WHERE domain_id = ?1");
    if (ret != 0) return ret;
    bi64(c, st, 1, domain_id);
    bind_txt(c, st, 2, v->kind);
    bind_txt(c, st, 3, v->change_set);
    if (v->has_principal) bi64(c, st, 4, v->principal_id);
    else bnull(c, st, 4);
    bind_txt(c, st, 5, v->principal_name);
    bind_txt(c, st, 6, v->db_role);
    bind_txt(c, st, 7, v->comment);
    if (v->has_serial_before) bi64(c, st, 8, (sqlite3_int64)v->serial_before);
    else bnull(c, st, 8);
    if (v->has_serial_after) bi64(c, st, 9, (sqlite3_int64)v->serial_after);
    else bnull(c, st, 9);
    bi64(c, st, 10, (sqlite3_int64)v->generation_before);
    bi64(c, st, 11, (sqlite3_int64)v->generation_after);
    if (v->rollback_of) bi64(c, st, 12, (sqlite3_int64)v->rollback_of);
    else bnull(c, st, 12);
    bi64(c, st, 13, v->delta_complete ? 1 : 0);
    ret = wstep1(c, st, "w_insert_version");
    if (ret != 0) return ret;
    *id = (int64_t)sqlite3_last_insert_rowid(c->db);
    st = NULL;
    if ((ret = prep(c, &st, "SELECT version FROM karidns_zone_versions WHERE id = ?1")) != 0) return ret;
    bi64(c, st, 1, *id);
    int rc = bstep(c, st);
    if (rc == SQLITE_ROW) {
        bool bad = false;
        *number = (uint32_t)col_int(c, st, 0, "karidns_zone_versions", *id, "version", &bad);
        if (bad) ret = -1;
    } else {
        ret = sql_fail(c, rc, "w_insert_version");
    }
    sqlite3_finalize(st);
    return ret;
}

static int sq_w_insert_version_rrset(db_conn_t *c, int64_t version_id, const char *owner, const char *type, const char *before, const char *after) {
    int ret = wcheck(c, "w_insert_version_rrset");
    if (ret != 0) return ret;
    sqlite3_stmt *st = NULL;
    if ((ret = prep(c, &st, "INSERT INTO karidns_zone_version_rrsets (version_id, owner, type, before, after) VALUES (?1, ?2, ?3, ?4, ?5)")) != 0) return ret;
    bi64(c, st, 1, version_id);
    bind_txt(c, st, 2, owner);
    bind_txt(c, st, 3, type);
    bind_txt(c, st, 4, before);
    bind_txt(c, st, 5, after);
    return wstep1(c, st, "w_insert_version_rrset");
}

const db_driver_t db_driver_sqlite3 = {
    .name = "sqlite3",
    .open = sq_open, .close = sq_close, .errmsg = sq_errmsg, .check_schema = sq_check_schema,
    .begin_snapshot = sq_begin_snapshot, .end_snapshot = sq_end_snapshot, .list_zones = sq_list_zones,
    .scan_records = sq_scan_records, .scan_metadata = sq_scan_metadata, .zones_with_keys = sq_zones_with_keys,
    .changes_since = sq_changes_since, .wait_fd = sq_wait_fd, .drain_notifications = sq_drain_notifications,
    .report_status = sq_report_status, .changes_max = sq_changes_max, .scan_records_range = sq_scan_records_range,
    .scan_domain_views = sq_scan_domain_views, .scan_profiles = sq_scan_profiles, .scan_ext = sq_scan_ext,
    .poll_version = sq_poll_version,
    .changes_unsettled = false,          /* the cursor is the highest seq */
    /* B11 reload requests: PostgreSQL only (watch_requests, requests_max, reload_requests are NULL) */
    .schema_findings = sq_schema_findings,      /* B12 */
    .find_zone = sq_find_zone,                  /* B13 */
    .find_zones_in = sq_find_zones_in,          /* 0.7: the lookup of a name */
    .scan_records_in = sq_scan_records_in, .scan_metadata_in = sq_scan_metadata_in, .scan_ext_in = sq_scan_ext_in, .zones_with_keys_in = sq_zones_with_keys_in,      /* B13b; SQLite3 since 0.7: the statements of a fetch of many zones */
    .scan_apex = sq_scan_apex,                  /* D1a step 6 */
    .signer_waiting = sq_signer_waiting,        /* 0.7 signer-wait: the zones that wait for the signer at a start */
    .count_domains = sq_count_domains, .manifest_page = sq_manifest_page, .current_cursor = sq_current_cursor, .changes_page = sq_changes_page,      /* 0.7 store, WP3 */
    /* M2, the ZoneImporter: write access (open_write connections only) */
    .open_write = sq_open_write, .w_begin = sq_w_begin, .w_commit = sq_w_commit, .w_rollback = sq_w_rollback,
    .w_create_zone = sq_w_create_zone, .w_delete_records = sq_w_delete_records, .w_insert_record = sq_w_insert_record,
    .w_insert_tags = sq_w_insert_tags, .w_insert_tinydns = sq_w_insert_tinydns, .w_delete_tagdefs = sq_w_delete_tagdefs,
    .w_insert_tagdef = sq_w_insert_tagdef, .w_delete_meta = sq_w_delete_meta, .w_insert_meta = sq_w_insert_meta,
    .w_set_view = sq_w_set_view, .w_request_reload = sq_w_request_reload, .w_zone_has_keys = sq_w_zone_has_keys,
    .w_set_audit = sq_w_set_audit,              /* schema version 3 */
    /* item C, the signer */
    .w_scan_auth = sq_w_scan_auth, .w_update_record = sq_w_update_record, .w_mark = sq_w_mark, .w_write_id = sq_w_write_id,
    .w_delete_dnssec = sq_w_delete_dnssec, .w_update_orders = sq_w_update_orders, .w_insert_dnssec = sq_w_insert_dnssec,
    .w_set_snapshot = sq_w_set_snapshot,
    /* items D and E */
    .w_set_actor = sq_w_set_actor, .w_zone_generation = sq_w_zone_generation, .w_bump_serial = sq_w_bump_serial,
    .w_insert_version = sq_w_insert_version, .w_insert_version_rrset = sq_w_insert_version_rrset,
    /* 0.7 w_analyze: NULL (only the PostgreSQL statistics are refreshed after an import) */
};

#endif /* KARIDNS_DB_SQLITE3 */
