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
#include <sys/types.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "dns_db_driver.h"

struct db_conn {
    sqlite3 *db;
    char *path;                 /* B9: the file that was opened, and which file it was (poll_version) */
    dev_t dev;
    ino_t ino;
    bool have_id;
    sqlite3_stmt *st_pv;
    char err[DB_ERRLEN];
    bool in_snapshot;
    bool has_changes;
    sqlite3_stmt *st_zones, *st_zone_one, *st_rec_all, *st_rec_one, *st_rec_rng, *st_meta_all, *st_meta_one, *st_keys, *st_changes;
    sqlite3_stmt *st_dv_all, *st_dv_one;
    bool has_domain_views;
    sqlite3_stmt *st_prof;
    bool has_profiles;
    sqlite3_stmt *st_xt[2], *st_xd[2], *st_xg[2];      /* B8: karidns_record_tags, karidns_record_tinydns, karidns_zone_tagdefs; [0] all, [1] one domain */
    bool has_ext;
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
    c->path = strdup(path);
    struct stat sb;
    if (c->path && stat(path, &sb) == 0) {
        c->dev = sb.st_dev;
        c->ino = sb.st_ino;
        c->have_id = true;
    }
    *out = c;
    return 0;
}

static void sq_close(db_conn_t *c) {
    if (!c) return;
    sqlite3_finalize(c->st_pv);
    free(c->path);
    sqlite3_finalize(c->st_zones);
    sqlite3_finalize(c->st_zone_one);
    sqlite3_finalize(c->st_rec_all);
    sqlite3_finalize(c->st_rec_one);
    sqlite3_finalize(c->st_rec_rng);
    sqlite3_finalize(c->st_dv_all);
    sqlite3_finalize(c->st_dv_one);
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
    if (out) {
        out->has_ext = c->has_ext;
        out->has_reload_requests = out->has_server_status = false;     /* B11: the multi-server tables are PostgreSQL only */
    }
    /* B10: schema version 1 and 2 (v2 adds karidns_zone_tagdefs.id; the order of the definitions is the rowid either way);
     * a newer version was written for a later loader */
    static const char *const sv_cols[] = { "version", NULL };
    if ((rc = table_columns(c, "karidns_schema_version", sv_cols, &found, &rows)) != 0) return rc;
    if (rows > 0 && found == 1u) {
        sqlite3_stmt *st = NULL;
        rc = sqlite3_prepare_v2(c->db, "SELECT max(version) FROM karidns_schema_version", -1, &st, NULL);
        if (rc == SQLITE_OK) rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            sqlite3_int64 v = sqlite3_column_type(st, 0) == SQLITE_NULL ? 0 : sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            if (v > 2) {
                set_err(c, "schema: karidns_schema_version is %lld; this loader reads versions 1 and 2", (long long)v);
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
        if (rc == SQLITE_OK) rc = sqlite3_step(st);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(st);
            return sql_fail(c, rc, "karidns_schema_version");
        }
        long long v = sqlite3_column_type(st, 0) == SQLITE_NULL ? 0 : sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (v == 0) fnd(cb, ud, 'W', "karidns_schema_version has no row");
        else if (v > 2) fnd(cb, ud, 'E', "karidns_schema_version is %lld; this loader reads versions 1 and 2", v);
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
                sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
                rc = sqlite3_step(st);
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
    sqlite3_stmt *all[] = { c->st_zones, c->st_zone_one, c->st_rec_all, c->st_rec_one, c->st_rec_rng, c->st_meta_all, c->st_meta_one,
                            c->st_keys, c->st_changes, c->st_dv_all, c->st_dv_one, c->st_prof };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (all[i]) rearm(all[i]);
    for (int i = 0; i < 2; i++) {
        if (c->st_xt[i]) rearm(c->st_xt[i]);
        if (c->st_xd[i]) rearm(c->st_xd[i]);
        if (c->st_xg[i]) rearm(c->st_xg[i]);
    }
    c->in_snapshot = false;
    return exec(c, "COMMIT");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* scans                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

static int sq_zone_loop(db_conn_t *c, sqlite3_stmt *st, db_zone_cb cb, void *ud) {
    int ret = 0;
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

static int sq_list_zones(db_conn_t *c, db_zone_cb cb, void *ud) {
    int ret = prep(c, &c->st_zones,
                   "SELECT d.id, d.name, d.type, d.master, d.catalog, r.content FROM domains d "
                   "LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = 0 "
                   "ORDER BY d.id");
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
    char *a = malloc(n + 2);
    if (!a) {
        set_err(c, "out of memory");
        return -1;
    }
    memcpy(a, name, n);
    a[n] = '\0';
    a[n + 1] = '\0';
    int ret = prep(c, &c->st_zone_one,
                   "SELECT d.id, d.name, d.type, d.master, d.catalog, r.content FROM domains d "
                   "LEFT JOIN records r ON r.domain_id = d.id AND r.type = 'SOA' AND r.name = d.name AND r.disabled = 0 "
                   "WHERE d.name COLLATE NOCASE IN (?1, ?2) ORDER BY d.id");
    if (ret != 0) {
        free(a);
        return ret;
    }
    sqlite3_stmt *st = c->st_zone_one;
    rearm(st);
    sqlite3_bind_text(st, 1, a, (int)n, SQLITE_TRANSIENT);
    char *b = malloc(n + 2);
    if (!b) {
        free(a);
        set_err(c, "out of memory");
        return -1;
    }
    memcpy(b, a, n);
    b[n] = '.';
    sqlite3_bind_text(st, 2, b, (int)n + 1, SQLITE_TRANSIENT);
    ret = sq_zone_loop(c, st, cb, ud);
    free(a);
    free(b);
    return ret;
}

/* the rows of a prepared records statement (already bound) to the callback */
static int rec_loop(db_conn_t *c, sqlite3_stmt *st, db_record_cb cb, void *ud) {
    int ret = 0;
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
    return rec_loop(c, st, cb, ud);
}

static int sq_scan_records_range(db_conn_t *c, int64_t lo, int64_t hi, db_record_cb cb, void *ud) {
    int ret = prep(c, &c->st_rec_rng, "SELECT domain_id, id, name, type, content, ttl, prio, disabled, ordername "
                                      "FROM records WHERE domain_id >= ?1 AND domain_id <= ?2 ORDER BY domain_id, id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = c->st_rec_rng;
    rearm(st);
    sqlite3_bind_int64(st, 1, lo);
    sqlite3_bind_int64(st, 2, hi);
    return rec_loop(c, st, cb, ud);
}

static int sq_scan_domain_views(db_conn_t *c, const int64_t *domain_id, db_domain_view_cb cb, void *ud) {
    if (!c->has_domain_views) {
        set_err(c, "karidns_domain_views does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt **slot = domain_id ? &c->st_dv_one : &c->st_dv_all;
    int ret = prep(c, slot, domain_id ? "SELECT domain_id, view_name FROM karidns_domain_views WHERE domain_id = ?1"
                                      : "SELECT domain_id, view_name FROM karidns_domain_views ORDER BY domain_id");
    if (ret != 0) return ret;
    sqlite3_stmt *st = *slot;
    rearm(st);
    if (domain_id) sqlite3_bind_int64(st, 1, *domain_id);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_domain_views");
            break;
        }
        bool bad = false;
        int64_t did = sqlite3_column_int64(st, 0);
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
        int rc = sqlite3_step(st);
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

static int sq_changes_max(db_conn_t *c, uint64_t *seq) {
    if (!c->has_changes) {
        set_err(c, "karidns_changes does not exist in this database");
        return DB_ERR_UNAVAILABLE;
    }
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c->db, "SELECT max(seq) FROM karidns_changes", -1, &st, NULL);
    if (rc != SQLITE_OK) return sql_fail(c, rc, "prepare");
    int ret = 0;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *seq = sqlite3_column_type(st, 0) == SQLITE_NULL ? 0 : (uint64_t)sqlite3_column_int64(st, 0);
    } else {
        ret = sql_fail(c, rc, "changes_max");
    }
    sqlite3_finalize(st);
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

/* B8: karidns_record_tags / karidns_record_tinydns (through records, for the domain id) / karidns_zone_tagdefs.  Each table in its own
 * pass, rows ordered by (domain_id, record_id); the tag definitions by (domain_id, rowid): the order the rows were inserted in is the
 * order of the definitions in a zone file, and the first definition that matches a client wins. */
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
    if (one) sqlite3_bind_int64(st, 1, *domain_id);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_ext (karidns_record_tags)");
            break;
        }
        bool bad = false;
        int64_t did = sqlite3_column_int64(st, 0);
        db_tag_row_t row;
        row.record_id = sqlite3_column_int64(st, 1);
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
    if (ret != 0) return ret;

    ret = prep(c, &c->st_xd[one],
               one ? "SELECT r.domain_id, t.record_id, t.ttd, t.loc, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                     "WHERE r.domain_id = ?1 ORDER BY t.record_id"
                   : "SELECT r.domain_id, t.record_id, t.ttd, t.loc, t.countdown FROM karidns_record_tinydns t JOIN records r ON r.id = t.record_id "
                     "ORDER BY r.domain_id, t.record_id");
    if (ret != 0) return ret;
    st = c->st_xd[one];
    rearm(st);
    if (one) sqlite3_bind_int64(st, 1, *domain_id);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_ext (karidns_record_tinydns)");
            break;
        }
        bool bad = false;
        int64_t did = sqlite3_column_int64(st, 0);
        db_tinydns_row_t row;
        row.record_id = sqlite3_column_int64(st, 1);
        row.ttd_null = sqlite3_column_type(st, 2) == SQLITE_NULL;
        row.ttd = row.ttd_null ? 0 : sqlite3_column_int64(st, 2);
        row.loc = col_text(c, st, 3, "karidns_record_tinydns", row.record_id, "loc", &bad);
        row.countdown = sqlite3_column_type(st, 4) != SQLITE_NULL && sqlite3_column_int64(st, 4) != 0;
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
    if (ret != 0) return ret;

    ret = prep(c, &c->st_xg[one],
               one ? "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs WHERE domain_id = ?1 ORDER BY rowid"
                   : "SELECT domain_id, kind, tag, cidr FROM karidns_zone_tagdefs ORDER BY domain_id, rowid");
    if (ret != 0) return ret;
    st = c->st_xg[one];
    rearm(st);
    if (one) sqlite3_bind_int64(st, 1, *domain_id);
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            ret = sql_fail(c, rc, "scan_ext (karidns_zone_tagdefs)");
            break;
        }
        bool bad = false;
        int64_t did = sqlite3_column_int64(st, 0);
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
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *version = (uint64_t)sqlite3_column_int64(st, 0);
    else ret = sql_fail(c, rc, "PRAGMA data_version");
    rearm(st);
    return ret;
}

const db_driver_t db_driver_sqlite3 = {
    "sqlite3",       sq_open,         sq_close,           sq_errmsg,           sq_check_schema,
    sq_begin_snapshot, sq_end_snapshot, sq_list_zones,    sq_scan_records,     sq_scan_metadata,
    sq_zones_with_keys, sq_changes_since, sq_wait_fd,     sq_drain_notifications, sq_report_status,
    sq_changes_max,   sq_scan_records_range, sq_scan_domain_views, sq_scan_profiles, sq_scan_ext, sq_poll_version,
    false,          /* changes_unsettled: the cursor is the highest seq */
    NULL, NULL, NULL,   /* B11 reload requests: PostgreSQL only (watch_requests, requests_max, reload_requests) */
    sq_schema_findings, /* B12 */
    sq_find_zone,       /* B13 */
};

#endif /* KARIDNS_DB_SQLITE3 */
