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
 */

#ifdef KARIDNS_DB_SQLITE3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sqlite3.h>

#include "dns_db_driver.h"

struct db_conn {
    sqlite3 *db;
    char err[DB_ERRLEN];
    bool in_snapshot;
    bool has_changes;
    sqlite3_stmt *st_zones, *st_rec_all, *st_rec_one, *st_meta_all, *st_meta_one, *st_keys, *st_changes;
};

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
    set_err(c, "sqlite3 %s: %s%s", what, sqlite3_errmsg(c->db), rc_is_busy(rc) ? " (retry later)" : "");
    return rc_is_busy(rc) ? DB_ERR_RETRY : -1;
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

static void rearm(sqlite3_stmt *st) {
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

/* ------------------------------------------------------------------------------------------------------------- */
/* open / close                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static int sq_open(db_conn_t **out, const db_source_t *src, char *err, size_t errlen) {
    *out = NULL;
    const char *path = src ? src->database_file : NULL;
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
    sqlite3_busy_timeout(c->db, (int)ms);
#ifdef SQLITE_DBCONFIG_DEFENSIVE
    sqlite3_db_config(c->db, SQLITE_DBCONFIG_DEFENSIVE, 1, (int *)NULL);
#endif
    int ret = exec(c, "PRAGMA query_only=1");
    if (ret == 0) {
        sqlite3_stmt *st = NULL;
        rc = sqlite3_prepare_v2(c->db, "PRAGMA journal_mode", -1, &st, NULL);
        if (rc == SQLITE_OK) rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            const char *m = (const char *)sqlite3_column_text(st, 0);
            if (!m || strcasecmp(m, "wal") != 0) {
                set_err(c, "sqlite3: the database is not in WAL mode (journal_mode=%.20s); WAL is required so that the loader "
                           "and the writers can work at the same time (the owner runs PRAGMA journal_mode=WAL once)",
                        m ? m : "?");
                ret = -1;
            }
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
    *out = c;
    return 0;
}

static void sq_close(db_conn_t *c) {
    if (!c) return;
    sqlite3_finalize(c->st_zones);
    sqlite3_finalize(c->st_rec_all);
    sqlite3_finalize(c->st_rec_one);
    sqlite3_finalize(c->st_meta_all);
    sqlite3_finalize(c->st_meta_one);
    sqlite3_finalize(c->st_keys);
    sqlite3_finalize(c->st_changes);
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
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
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
    int rc = exec(c, "BEGIN");
    if (rc != 0) return rc;
    c->in_snapshot = true;
    /* BEGIN is deferred: the WAL read transaction (the snapshot) starts with the first statement that reads */
    sqlite3_stmt *st = NULL;
    int sr = sqlite3_prepare_v2(c->db, "SELECT 1 FROM sqlite_master LIMIT 1", -1, &st, NULL);
    if (sr == SQLITE_OK) {
        sr = sqlite3_step(st);
        if (sr == SQLITE_ROW || sr == SQLITE_DONE) sr = SQLITE_OK;
    }
    sqlite3_finalize(st);
    if (sr != SQLITE_OK) {
        rc = sql_fail(c, sr, "begin snapshot");
        sqlite3_exec(c->db, "ROLLBACK", NULL, NULL, NULL);
        c->in_snapshot = false;
        return rc;
    }
    return 0;
}

static int sq_end_snapshot(db_conn_t *c) {
    if (!c->in_snapshot) return 0;
    sqlite3_stmt *all[] = { c->st_zones, c->st_rec_all, c->st_rec_one, c->st_meta_all, c->st_meta_one, c->st_keys,
                            c->st_changes };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (all[i]) rearm(all[i]);
    c->in_snapshot = false;
    return exec(c, "COMMIT");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* scans                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

static int sq_list_zones(db_conn_t *c, db_zone_cb cb, void *ud) {
    int ret = prep(c, &c->st_zones,
                   "SELECT d.id, d.name, d.type, d.master, d.catalog, r.content FROM domains d "
                   "LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = 0 "
                   "ORDER BY d.id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_zones;
    rearm(st);
    bool have_prev = false;
    int64_t prev = 0;
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "list_zones");
            break;
        }
        int64_t id = sqlite3_column_int64(st, 0);
        if (have_prev && id == prev) continue;      /* more than one enabled apex SOA: the first is enough here */
        have_prev = true;
        prev = id;
        bool bad = false;
        db_zone_row_t z;
        z.id = id;
        z.name = col_text(c, st, 1, "domains", id, "name", &bad);
        z.type = col_text(c, st, 2, "domains", id, "type", &bad);
        z.master = col_text(c, st, 3, "domains", id, "master", &bad);
        z.catalog = col_text(c, st, 4, "domains", id, "catalog", &bad);
        z.soa_content = col_text(c, st, 5, "records", id, "content", &bad);
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

static int sq_scan_records(db_conn_t *c, const int64_t *domain_id, db_record_cb cb, void *ud) {
    sqlite3_stmt **slot = domain_id ? &c->st_rec_one : &c->st_rec_all;
    int ret = prep(c, slot, domain_id ? "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername "
                                        "FROM records WHERE domain_id = ?1 ORDER BY id"
                                      : "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername "
                                        "FROM records ORDER BY domain_id, id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) sqlite3_bind_int64(st, 1, *domain_id);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_records");
            break;
        }
        bool bad = false;
        int64_t did = sqlite3_column_int64(st, 0);
        db_record_row_t r;
        memset(&r, 0, sizeof(r));
        r.id = sqlite3_column_int64(st, 1);
        r.name = col_text(c, st, 2, "records", r.id, "name", &bad);
        r.type = col_text(c, st, 3, "records", r.id, "type", &bad);
        r.content = col_text(c, st, 4, "records", r.id, "content", &bad);
        r.ttl_null = sqlite3_column_type(st, 5) == SQLITE_NULL;
        r.ttl = r.ttl_null ? 0 : sqlite3_column_int64(st, 5);
        r.prio_null = sqlite3_column_type(st, 6) == SQLITE_NULL;
        r.prio = r.prio_null ? 0 : sqlite3_column_int64(st, 6);
        r.disabled = sqlite3_column_type(st, 7) == SQLITE_NULL || sqlite3_column_int64(st, 7) != 0;
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

static int sq_scan_metadata(db_conn_t *c, const int64_t *domain_id, db_meta_cb cb, void *ud) {
    sqlite3_stmt **slot = domain_id ? &c->st_meta_one : &c->st_meta_all;
    int ret = prep(c, slot, domain_id ? "SELECT domain_id, kind, content, id FROM domainmetadata WHERE domain_id = ?1 ORDER BY id"
                                      : "SELECT domain_id, kind, content, id FROM domainmetadata ORDER BY domain_id, id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) sqlite3_bind_int64(st, 1, *domain_id);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_metadata");
            break;
        }
        bool bad = false;
        int64_t id = sqlite3_column_int64(st, 3);
        db_meta_row_t m;
        m.domain_id = sqlite3_column_int64(st, 0);
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

static int sq_zones_with_keys(db_conn_t *c, db_key_cb cb, void *ud) {
    int ret = prep(c, &c->st_keys, "SELECT DISTINCT domain_id FROM cryptokeys ORDER BY domain_id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_keys;
    rearm(st);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "zones_with_keys");
            break;
        }
        if (sqlite3_column_type(st, 0) == SQLITE_NULL) continue;
        if (cb(ud, sqlite3_column_int64(st, 0)) != 0) {
            ret = DB_STOPPED;
            break;
        }
    }
    rearm(st);
    return ret;
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
    sqlite3_bind_int64(st, 1, (sqlite3_int64)after);
    uint64_t last = after;
    bool g = false, first = true;
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "changes_since");
            break;
        }
        db_change_row_t row;
        row.seq = (uint64_t)sqlite3_column_int64(st, 0);
        row.domain_id = sqlite3_column_int64(st, 1);
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

const db_driver_t db_driver_sqlite3 = {
    "sqlite3",       sq_open,         sq_close,           sq_errmsg,           sq_check_schema,
    sq_begin_snapshot, sq_end_snapshot, sq_list_zones,    sq_scan_records,     sq_scan_metadata,
    sq_zones_with_keys, sq_changes_since, sq_wait_fd,     sq_drain_notifications, sq_report_status,
};

#endif /* KARIDNS_DB_SQLITE3 */
