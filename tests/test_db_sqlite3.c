/*
 * test_db_sqlite3.c - the SQLite3 driver (dns_db_sqlite3.c, dns_db_driver.h) and the dump of karidns-dbloader
 * (karidns_dbloader.c, included below with its main() renamed).
 *
 * The databases are made with the sqlite3 library in a private temporary directory, with the PowerDNS 5.1 column list
 * of tests/db/pdns_schema.sqlite3.sql (our own DDL).  Cases: WAL required, "file:" refused, '%65' taken literally,
 * UTF-8 path, missing column / table, extra column ignored, NULL ttl / prio / ordername / type, disabled rows, an
 * embedded NUL (with the row id in the message), bulk scan == per-zone scans, snapshot isolation against a concurrent
 * writer, busy handling, changes_since, and the dump: a zone with cryptokeys but without PRESIGNED fails, SLAVE zones
 * and bad names are reported, the whole stream passes the Backend state machine.
 *
 * Usage: test_db_sqlite3 [tests/db]   (the directory of pdns_schema.sqlite3.sql)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <syslog.h>

#ifdef KARIDNS_DB_SQLITE3

#include <sqlite3.h>

#define main dbloader_main
#include "../karidns_dbloader.c"
#undef main

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

static char g_dir[400];             /* private temporary directory */
static char g_schema[600];          /* path of the schema fixture */
static char *g_schema_sql;

/* ------------------------------------------------------------------ helpers */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        b = NULL;
    }
    if (b) b[n] = '\0';
    fclose(f);
    return b;
}

static void rm_tree(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(dir);
}

static sqlite3 *raw_open(const char *path, int flags) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        printf("  [FAIL] cannot open %s: %s\n", path, db ? sqlite3_errmsg(db) : "?");
        g_failed++;
    }
    return db;
}

static bool raw_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("  [FAIL] sql error: %s\n    %.200s\n", err ? err : "?", sql);
        g_failed++;
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* sqlite3_vmprintf() format (%Q): not a printf format */
static void sqlf(sqlite3 *db, const char *fmt, ...) {
    char *q;
    va_list ap;
    va_start(ap, fmt);
    q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    raw_exec(db, q);
    sqlite3_free(q);
}

/* a new database file in WAL mode with the schema; returns an open read-write handle */
static sqlite3 *make_db(const char *name, char *path_out, size_t cap) {
    snprintf(path_out, cap, "%s/%s", g_dir, name);
    sqlite3 *db = raw_open(path_out, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    if (db) raw_exec(db, g_schema_sql);
    return db;
}

static void add_zone(sqlite3 *db, int64_t id, const char *name, const char *type) {
    sqlf(db, "INSERT INTO domains (id, name, type) VALUES (%lld, %Q, %Q)", (long long)id, name, type);
}

/* ttl / prio < 0: NULL */
static void add_rec(sqlite3 *db, int64_t id, int64_t dom, const char *name, const char *type, const char *content,
                    int64_t ttl, int64_t prio, int disabled, const char *ordername) {
    char t[32], p[32];
    if (ttl < 0) strcpy(t, "NULL"); else snprintf(t, sizeof(t), "%lld", (long long)ttl);
    if (prio < 0) strcpy(p, "NULL"); else snprintf(p, sizeof(p), "%lld", (long long)prio);
    sqlf(db, "INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled, ordername) "
             "VALUES (%lld, %lld, %Q, %Q, %Q, %s, %s, %d, %Q)",
         (long long)id, (long long)dom, name, type, content, t, p, disabled, ordername);
}

static const char *SOA_K = "ns1.k.test hostmaster.k.test 7 7200 3600 1209600 300";

/* a small valid zone: SOA, NS, A */
static void add_simple_zone(sqlite3 *db, int64_t zid, int64_t first_rec, const char *name) {
    char n[300], c[400];
    add_zone(db, zid, name, "NATIVE");
    snprintf(c, sizeof(c), "ns1.%s hostmaster.%s 7 7200 3600 1209600 300", name, name);
    add_rec(db, first_rec, zid, name, "SOA", c, 3600, -1, 0, NULL);
    snprintf(c, sizeof(c), "ns1.%s", name);
    add_rec(db, first_rec + 1, zid, name, "NS", c, 3600, -1, 0, NULL);
    snprintf(n, sizeof(n), "ns1.%s", name);
    add_rec(db, first_rec + 2, zid, n, "A", "192.0.2.1", 300, -1, 0, NULL);
}

static db_conn_t *open_driver(const char *path, unsigned busy_ms, char *err, size_t errlen, int *rc_out) {
    db_conn_t *c = NULL;
    db_source_t src = { "sqlite3", path, NULL, NULL, busy_ms };
    int rc = db_driver_sqlite3.open(&c, &src, err, errlen);
    if (rc_out) *rc_out = rc;
    return c;
}

/* ---- collectors */
typedef struct { int64_t did, id, ttl, prio; bool ttl_null, prio_null, disabled; char *name, *type, *content, *ordername; } rec_t;
typedef struct { rec_t *v; size_t n, cap; } recs_t;

static char *dupn(const char *s) { return s ? strdup(s) : NULL; }

static int rec_collect(void *ud, int64_t did, const db_record_row_t *r) {
    recs_t *a = ud;
    if (a->n >= a->cap) {
        a->cap = a->cap ? a->cap * 2 : 16;
        a->v = realloc(a->v, a->cap * sizeof(rec_t));
    }
    rec_t *x = &a->v[a->n++];
    x->did = did; x->id = r->id; x->ttl = r->ttl; x->prio = r->prio;
    x->ttl_null = r->ttl_null; x->prio_null = r->prio_null; x->disabled = r->disabled;
    x->name = dupn(r->name); x->type = dupn(r->type); x->content = dupn(r->content); x->ordername = dupn(r->ordername);
    return 0;
}

static void recs_free(recs_t *a) {
    for (size_t i = 0; i < a->n; i++) {
        free(a->v[i].name); free(a->v[i].type); free(a->v[i].content); free(a->v[i].ordername);
    }
    free(a->v);
    memset(a, 0, sizeof(*a));
}

static bool str_eq(const char *a, const char *b) { return (a == NULL && b == NULL) || (a && b && strcmp(a, b) == 0); }

typedef struct { int64_t id[64]; char *name[64]; char *type[64]; char *soa[64]; size_t n; } zl_t;

static int zl_collect(void *ud, const db_zone_row_t *z) {
    zl_t *l = ud;
    if (l->n >= 64) return 1;
    l->id[l->n] = z->id;
    l->name[l->n] = dupn(z->name);
    l->type[l->n] = dupn(z->type);
    l->soa[l->n] = dupn(z->soa_content);
    l->n++;
    return 0;
}

static void zl_free(zl_t *l) {
    for (size_t i = 0; i < l->n; i++) { free(l->name[i]); free(l->type[i]); free(l->soa[i]); }
    l->n = 0;
}

typedef struct { size_t n; int64_t first_dom; } cnt_t;
static int count_meta(void *ud, const db_meta_row_t *m) { cnt_t *c = ud; if (!c->n) c->first_dom = m->domain_id; c->n++; return 0; }
static int stop_rec(void *ud, int64_t did, const db_record_row_t *r) { (void)did; (void)r; (*(size_t *)ud)++; return 1; }
typedef struct { int64_t v[16]; size_t n; } keys_t;
static int collect_key(void *ud, int64_t id) { keys_t *k = ud; if (k->n < 16) k->v[k->n++] = id; return 0; }
typedef struct { uint64_t seq[16]; int64_t dom[16]; size_t n; } chg_t;
static int collect_chg(void *ud, const db_change_row_t *r) { chg_t *c = ud; if (c->n < 16) { c->seq[c->n] = r->seq; c->dom[c->n] = r->domain_id; c->n++; } return 0; }

/* ------------------------------------------------------------------ 1. opening */
static void test_open(void) {
    printf("open\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("plain.db", path, sizeof(path));
    int rc;
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK_MSG(rc == 0 && c, "open: %s", err);
    if (c) {
        db_schema_info_t si;
        CHECK(db_driver_sqlite3.check_schema(c, &si) == 0);
        CHECK(!si.has_changes);
        CHECK(db_driver_sqlite3.wait_fd(c) == -1);
        bool changed = true;
        CHECK(db_driver_sqlite3.drain_notifications(c, &changed) == 0 && !changed);
        db_status_t st = { 1, true, NULL };
        CHECK(db_driver_sqlite3.report_status(c, &st) == 0);
        db_driver_sqlite3.close(c);
    }
    /* the journal mode must already be WAL */
    raw_exec(db, "PRAGMA journal_mode=DELETE");
    sqlite3_close(db);
    c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    CHECK_HAS(err, "WAL");
    CHECK_HAS(err, "journal_mode=delete");

    /* paths that are refused */
    c = open_driver("file:/tmp/x.db", 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    CHECK_HAS(err, "file:");
    c = open_driver("file:x.db?mode=ro", 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    c = open_driver("", 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    c = open_driver(":memory:", 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    c = open_driver(NULL, 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    /* a file that is not there is not created */
    snprintf(path, sizeof(path), "%s/absent.db", g_dir);
    c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
    CHECK(access(path, F_OK) != 0);
    /* a file that is not a database */
    snprintf(path, sizeof(path), "%s/garbage.db", g_dir);
    FILE *f = fopen(path, "wb");
    if (f) { fputs("this is not a database file, only text that is long enough to have a header....................\n", f); fclose(f); }
    c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK(rc == -1 && !c);
}

/* the file name is used byte for byte: '%65' is not 'e', a UTF-8 name works, "./file:" is an ordinary name */
static void test_paths(void) {
    printf("paths\n");
    char path[600], decoy[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("a%65b.db", path, sizeof(path));
    add_simple_zone(db, 1, 1, "literal.test");
    sqlite3_close(db);
    db = make_db("aeb.db", decoy, sizeof(decoy));
    add_simple_zone(db, 1, 1, "decoy.test");
    sqlite3_close(db);
    int rc;
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK_MSG(rc == 0 && c, "%s", err);
    if (c) {
        zl_t l = {0};
        CHECK(db_driver_sqlite3.check_schema(c, NULL) == 0);
        CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0);
        CHECK(l.n == 1 && l.name[0] && strcmp(l.name[0], "literal.test") == 0);
        zl_free(&l);
        db_driver_sqlite3.close(c);
    }
    db = make_db("zone-\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E.db", path, sizeof(path));
    add_simple_zone(db, 1, 1, "utf8.test");
    sqlite3_close(db);
    c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK_MSG(rc == 0 && c, "%s", err);
    if (c) {
        zl_t l = {0};
        CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0 && l.n == 1 && strcmp(l.name[0], "utf8.test") == 0);
        zl_free(&l);
        db_driver_sqlite3.close(c);
    }
    /* a name that merely contains "file:" later is a plain path */
    db = make_db("file:plain.db", path, sizeof(path));
    add_simple_zone(db, 1, 1, "colon.test");
    sqlite3_close(db);
    c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK_MSG(rc == 0 && c, "%s", err);
    if (c) db_driver_sqlite3.close(c);
}

/* ------------------------------------------------------------------ 2. schema */
static void test_schema(void) {
    printf("schema\n");
    char path[600], err[DB_ERRLEN];
    int rc;
    /* a missing column */
    sqlite3 *db = raw_open((snprintf(path, sizeof(path), "%s/nocol.db", g_dir), path), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    raw_exec(db, "PRAGMA journal_mode=WAL;"
                 "CREATE TABLE domains (id INTEGER PRIMARY KEY, name TEXT, type TEXT, master TEXT, catalog TEXT);"
                 "CREATE TABLE records (id INTEGER PRIMARY KEY, domain_id INT, name TEXT, type TEXT, content TEXT, ttl INT,"
                 " disabled INT, ordername TEXT);"           /* no prio */
                 "CREATE TABLE domainmetadata (id INTEGER PRIMARY KEY, domain_id INT, kind TEXT, content TEXT);"
                 "CREATE TABLE cryptokeys (id INTEGER PRIMARY KEY, domain_id INT);");
    sqlite3_close(db);
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), &rc);
    CHECK(rc == 0 && c);
    if (c) {
        CHECK(db_driver_sqlite3.check_schema(c, NULL) == -1);
        CHECK_HAS(db_driver_sqlite3.errmsg(c), "records");
        CHECK_HAS(db_driver_sqlite3.errmsg(c), "prio");
        db_driver_sqlite3.close(c);
    }
    /* a missing table */
    db = raw_open((snprintf(path, sizeof(path), "%s/notable.db", g_dir), path), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    raw_exec(db, "PRAGMA journal_mode=WAL; CREATE TABLE domains (id INTEGER PRIMARY KEY, name TEXT, type TEXT, master TEXT, catalog TEXT);");
    sqlite3_close(db);
    c = open_driver(path, 0, err, sizeof(err), &rc);
    if (c) {
        CHECK(db_driver_sqlite3.check_schema(c, NULL) == -1);
        CHECK_HAS(db_driver_sqlite3.errmsg(c), "records");
        CHECK_HAS(db_driver_sqlite3.errmsg(c), "missing");
        db_driver_sqlite3.close(c);
    }
    /* PowerDNS' own column names are matched case-insensitively and extra columns are ignored */
    db = make_db("extra.db", path, sizeof(path));
    raw_exec(db, "ALTER TABLE records ADD COLUMN extra_col TEXT DEFAULT 'x'");
    raw_exec(db, "ALTER TABLE domains ADD COLUMN another INT");
    raw_exec(db, "CREATE TABLE unrelated (a INT)");
    add_simple_zone(db, 1, 1, "extra.test");
    sqlite3_close(db);
    c = open_driver(path, 0, err, sizeof(err), &rc);
    if (c) {
        CHECK(db_driver_sqlite3.check_schema(c, NULL) == 0);
        recs_t a = {0};
        CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
        CHECK(db_driver_sqlite3.scan_records(c, NULL, rec_collect, &a) == 0 && a.n == 3);
        CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
        recs_free(&a);
        db_driver_sqlite3.close(c);
    }
}

/* ------------------------------------------------------------------ 3. rows */
static void test_rows(void) {
    printf("rows\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("rows.db", path, sizeof(path));
    add_zone(db, 1, "r.test", "NATIVE");
    add_rec(db, 1, 1, "r.test", "SOA", SOA_K, 3600, -1, 0, NULL);
    add_rec(db, 2, 1, "mx.r.test", "MX", "mail.r.test", -1, 10, 0, "ABCD");        /* NULL ttl, prio 10 */
    add_rec(db, 3, 1, "off.r.test", "A", "192.0.2.9", 60, -1, 1, NULL);            /* disabled */
    raw_exec(db, "INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled, ordername)"
                 " VALUES (4, 1, 'ent.r.test', NULL, NULL, NULL, NULL, 0, 'HASH')");                /* ENT row */
    raw_exec(db, "INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled, ordername)"
                 " VALUES (5, 1, 'nd.r.test', 'A', '192.0.2.5', 30, 0, NULL, NULL)");               /* disabled NULL */
    raw_exec(db, "INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled, ordername)"
                 " VALUES (6, 1, 'str.r.test', 'TXT', '', 5, 0, 0, '')");                           /* empty strings stay empty */
    sqlite3_close(db);
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) return;
    recs_t a = {0};
    CHECK(db_driver_sqlite3.check_schema(c, NULL) == 0);
    CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
    CHECK(db_driver_sqlite3.scan_records(c, NULL, rec_collect, &a) == 0);
    CHECK_MSG(a.n == 6, "%zu rows", a.n);
    if (a.n == 6) {
        CHECK(a.v[0].did == 1 && a.v[0].id == 1 && str_eq(a.v[0].type, "SOA") && !a.v[0].ttl_null && a.v[0].ttl == 3600);
        CHECK(a.v[0].prio_null && a.v[0].ordername == NULL && !a.v[0].disabled);
        CHECK(a.v[1].ttl_null && !a.v[1].prio_null && a.v[1].prio == 10 && str_eq(a.v[1].ordername, "ABCD"));
        CHECK(a.v[2].disabled);
        CHECK(a.v[3].type == NULL && a.v[3].content == NULL && a.v[3].ttl_null && a.v[3].prio_null && str_eq(a.v[3].ordername, "HASH"));
        CHECK(a.v[4].disabled);        /* NULL disabled: PowerDNS reads "disabled=0" only */
        CHECK(str_eq(a.v[5].content, "") && str_eq(a.v[5].ordername, "") && a.v[5].prio == 0 && !a.v[5].prio_null);
    }
    recs_free(&a);
    /* a callback that stops the scan */
    size_t seen = 0;
    CHECK(db_driver_sqlite3.scan_records(c, NULL, stop_rec, &seen) == DB_STOPPED && seen == 1);
    /* the statement is reusable after a stop */
    CHECK(db_driver_sqlite3.scan_records(c, NULL, rec_collect, &a) == 0 && a.n == 6);
    recs_free(&a);
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
    db_driver_sqlite3.close(c);
}

/* an embedded NUL is an error that names the table and the row id */
static void test_nul(void) {
    printf("embedded NUL\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("nul.db", path, sizeof(path));
    add_zone(db, 1, "n.test", "NATIVE");
    add_rec(db, 1, 1, "n.test", "SOA", SOA_K, 3600, -1, 0, NULL);
    raw_exec(db, "INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled)"
                 " VALUES (42, 1, 'n.test', 'TXT', 'a' || char(0) || 'b', 5, 0, 0)");
    raw_exec(db, "INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled)"
                 " VALUES (43, 1, 'n' || char(0) || 'x.test', 'A', '192.0.2.1', 5, 0, 0)");
    raw_exec(db, "INSERT INTO domainmetadata (id, domain_id, kind, content) VALUES (77, 1, 'ALSO-NOTIFY', '192.0.2.1' || char(0))");
    sqlite3_close(db);
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) return;
    recs_t a = {0};
    CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
    int rc = db_driver_sqlite3.scan_records(c, NULL, rec_collect, &a);
    CHECK(rc == -1);
    CHECK_HAS(db_driver_sqlite3.errmsg(c), "records");
    CHECK_HAS(db_driver_sqlite3.errmsg(c), "id 42");
    CHECK_HAS(db_driver_sqlite3.errmsg(c), "content");
    CHECK_HAS(db_driver_sqlite3.errmsg(c), "NUL");
    CHECK_MSG(a.n == 1, "the rows before the bad one were delivered, the bad one was not (%zu)", a.n);
    recs_free(&a);
    /* per-zone scan: the same */
    int64_t one = 1;
    CHECK(db_driver_sqlite3.scan_records(c, &one, rec_collect, &a) == -1);
    recs_free(&a);
    cnt_t cn = {0};
    CHECK(db_driver_sqlite3.scan_metadata(c, NULL, count_meta, &cn) == -1);
    CHECK_HAS(db_driver_sqlite3.errmsg(c), "domainmetadata");
    CHECK_HAS(db_driver_sqlite3.errmsg(c), "id 77");
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
    db_driver_sqlite3.close(c);

    /* a NUL in a name of the zone list */
    db = raw_open(path, SQLITE_OPEN_READWRITE);
    raw_exec(db, "DELETE FROM records; DELETE FROM domainmetadata;");
    raw_exec(db, "INSERT INTO domains (id, name, type) VALUES (9, 'z' || char(0) || '.test', 'NATIVE')");
    sqlite3_close(db);
    c = open_driver(path, 0, err, sizeof(err), NULL);
    if (c) {
        zl_t l = {0};
        CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == -1);
        CHECK_HAS(db_driver_sqlite3.errmsg(c), "domains");
        CHECK_HAS(db_driver_sqlite3.errmsg(c), "id 9");
        zl_free(&l);
        db_driver_sqlite3.close(c);
    }
}

/* ------------------------------------------------------------------ 4. zone list, bulk == per zone, keys */
static void test_scans(void) {
    printf("zone list, bulk and per-zone scans, metadata, keys\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("scans.db", path, sizeof(path));
    add_simple_zone(db, 1, 1, "one.test");
    add_simple_zone(db, 2, 4, "two.test");
    add_zone(db, 3, "three.test", "SLAVE");                      /* no records at all */
    add_simple_zone(db, 4, 7, "four.test");
    raw_exec(db, "UPDATE records SET disabled = 1 WHERE id = 7");   /* four.test: the SOA is disabled */
    add_rec(db, 10, 2, "two.test", "SOA", "ns9.two.test hm.two.test 8 1 1 1 1", 1, -1, 0, NULL);   /* second enabled SOA */
    add_rec(db, 11, 99, "orphan.test", "A", "192.0.2.77", 5, -1, 0, NULL);                          /* no such domain */
    /* rows of the zones interleaved by id: a later INSERT for the first zone has the highest id */
    add_rec(db, 12, 1, "late.one.test", "A", "192.0.2.12", 5, -1, 0, NULL);
    raw_exec(db, "UPDATE domains SET master = '192.0.2.53', catalog = 'cat.test' WHERE id = 3");
    sqlf(db, "INSERT INTO domainmetadata (id, domain_id, kind, content) VALUES (1, 2, 'PRESIGNED', '1')");
    sqlf(db, "INSERT INTO domainmetadata (id, domain_id, kind, content) VALUES (2, 1, 'ALSO-NOTIFY', '192.0.2.1')");
    sqlf(db, "INSERT INTO domainmetadata (id, domain_id, kind, content) VALUES (3, 1, 'ALSO-NOTIFY', '192.0.2.2')");
    sqlf(db, "INSERT INTO cryptokeys (id, domain_id, flags, active, content) VALUES (1, 4, 257, 1, 'x')");
    sqlf(db, "INSERT INTO cryptokeys (id, domain_id, flags, active, content) VALUES (2, 2, 256, 1, 'x')");
    sqlf(db, "INSERT INTO cryptokeys (id, domain_id, flags, active, content) VALUES (3, 4, 256, 1, 'x')");
    sqlite3_close(db);
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) return;
    CHECK(db_driver_sqlite3.check_schema(c, NULL) == 0);
    CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);

    zl_t l = {0};
    CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0);
    CHECK_MSG(l.n == 4, "%zu zones (one row per domain)", l.n);
    if (l.n == 4) {
        CHECK(l.id[0] == 1 && l.id[1] == 2 && l.id[2] == 3 && l.id[3] == 4);
        CHECK(strcmp(l.name[0], "one.test") == 0 && strcmp(l.type[0], "NATIVE") == 0);
        CHECK(l.soa[0] && strncmp(l.soa[0], "ns1.one.test hostmaster.one.test 7", 34) == 0);
        CHECK(l.soa[2] == NULL);                       /* no records */
        CHECK(l.soa[3] == NULL);                       /* the SOA is disabled */
        CHECK(l.soa[1] != NULL);
    }
    zl_free(&l);

    /* bulk == the per-zone scans one after the other (orphans only in the bulk scan) */
    recs_t bulk = {0}, per = {0};
    CHECK(db_driver_sqlite3.scan_records(c, NULL, rec_collect, &bulk) == 0);
    for (int64_t id = 1; id <= 4; id++) CHECK(db_driver_sqlite3.scan_records(c, &id, rec_collect, &per) == 0);
    size_t nb = 0;
    for (size_t i = 0; i < bulk.n; i++) if (bulk.v[i].did != 99) nb++;
    CHECK_MSG(nb == per.n, "bulk %zu (without the orphan), per zone %zu", nb, per.n);
    size_t j = 0;
    bool same = true;
    for (size_t i = 0; i < bulk.n && same; i++) {
        if (bulk.v[i].did == 99) continue;
        if (j >= per.n) { same = false; break; }
        rec_t *p = &per.v[j++], *b = &bulk.v[i];
        same = b->did == p->did && b->id == p->id && str_eq(b->name, p->name) && str_eq(b->type, p->type) &&
               str_eq(b->content, p->content) && b->ttl == p->ttl && b->prio == p->prio && b->ttl_null == p->ttl_null &&
               b->prio_null == p->prio_null && b->disabled == p->disabled && str_eq(b->ordername, p->ordername);
    }
    CHECK(same);
    /* ORDER BY domain_id, id */
    bool sorted = true;
    for (size_t i = 1; i < bulk.n; i++)
        if (bulk.v[i].did < bulk.v[i - 1].did || (bulk.v[i].did == bulk.v[i - 1].did && bulk.v[i].id <= bulk.v[i - 1].id)) sorted = false;
    CHECK(sorted);
    recs_free(&bulk);
    recs_free(&per);
    /* the prepared statement is reused many times */
    for (int i = 0; i < 50; i++) {
        int64_t id = 1 + i % 4;
        recs_t t = {0};
        CHECK(db_driver_sqlite3.scan_records(c, &id, rec_collect, &t) == 0);
        recs_free(&t);
    }

    cnt_t cn = {0};
    CHECK(db_driver_sqlite3.scan_metadata(c, NULL, count_meta, &cn) == 0 && cn.n == 3 && cn.first_dom == 1);
    memset(&cn, 0, sizeof(cn));
    int64_t two = 2;
    CHECK(db_driver_sqlite3.scan_metadata(c, &two, count_meta, &cn) == 0 && cn.n == 1 && cn.first_dom == 2);
    keys_t k = {0};
    CHECK(db_driver_sqlite3.zones_with_keys(c, collect_key, &k) == 0);
    CHECK_MSG(k.n == 2 && k.v[0] == 2 && k.v[1] == 4, "distinct, ordered: %zu", k.n);
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
    db_driver_sqlite3.close(c);
}

/* ------------------------------------------------------------------ 5. snapshot and a concurrent writer */
static void test_snapshot(void) {
    printf("snapshot isolation and concurrent writer\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *w = make_db("snap.db", path, sizeof(path));
    add_simple_zone(w, 1, 1, "s1.test");
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) { sqlite3_close(w); return; }
    CHECK(db_driver_sqlite3.check_schema(c, NULL) == 0);
    CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
    CHECK(db_driver_sqlite3.begin_snapshot(c) == -1);           /* already open */
    zl_t l = {0};
    CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0 && l.n == 1);
    zl_free(&l);
    /* the writer is not blocked by the open snapshot (WAL) and commits a new zone and a new record */
    add_simple_zone(w, 2, 4, "s2.test");
    add_rec(w, 20, 1, "x.s1.test", "A", "192.0.2.20", 5, -1, 0, NULL);
    raw_exec(w, "UPDATE records SET content = '192.0.2.99' WHERE id = 3");
    recs_t a = {0};
    CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0);
    CHECK_MSG(l.n == 1, "the snapshot does not see the new zone (%zu zones)", l.n);
    zl_free(&l);
    CHECK(db_driver_sqlite3.scan_records(c, NULL, rec_collect, &a) == 0);
    CHECK_MSG(a.n == 3, "the snapshot does not see the new rows (%zu)", a.n);
    bool old_content = false;
    for (size_t i = 0; i < a.n; i++) if (a.v[i].id == 3) old_content = str_eq(a.v[i].content, "192.0.2.1");
    CHECK(old_content);
    recs_free(&a);
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);              /* no snapshot: nothing to do */
    /* the next snapshot sees the writer's state */
    CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
    CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0 && l.n == 2);
    zl_free(&l);
    CHECK(db_driver_sqlite3.scan_records(c, NULL, rec_collect, &a) == 0 && a.n == 7);
    recs_free(&a);
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
    db_driver_sqlite3.close(c);
    sqlite3_close(w);
}

/* ------------------------------------------------------------------ 6. busy */
static void test_busy(void) {
    printf("busy handling\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *w = make_db("busy.db", path, sizeof(path));
    add_simple_zone(w, 1, 1, "b.test");
    sqlite3_close(w);
    /* a connection in exclusive locking mode keeps the database to itself after its first write: other connections
     * get SQLITE_BUSY (here from the first read, journal_mode) once their busy timeout (150 ms) has run out */
    w = raw_open(path, SQLITE_OPEN_READWRITE);
    CHECK(raw_exec(w, "PRAGMA locking_mode=EXCLUSIVE"));
    raw_exec(w, "INSERT INTO domainmetadata (id, domain_id, kind, content) VALUES (1, 1, 'X', 'y')");
    int rc = 0;
    db_conn_t *c = open_driver(path, 150, err, sizeof(err), &rc);
    CHECK_MSG(rc == DB_ERR_RETRY && !c, "open while the database is locked: %d (%s)", rc, err);
    CHECK_HAS(err, "retry later");
    /* the lock goes away: the same call works */
    sqlite3_close(w);
    c = open_driver(path, 150, err, sizeof(err), &rc);
    CHECK_MSG(rc == 0 && c, "after the writer is gone: %d (%s)", rc, err);
    if (c) {
        CHECK(db_driver_sqlite3.check_schema(c, NULL) == 0);
        CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
        zl_t l = {0};
        CHECK(db_driver_sqlite3.list_zones(c, zl_collect, &l) == 0 && l.n == 1);
        zl_free(&l);
        CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
        db_driver_sqlite3.close(c);
    }
}

/* ------------------------------------------------------------------ 7. changes_since */
static void test_changes(void) {
    printf("changes_since\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("chg.db", path, sizeof(path));
    add_simple_zone(db, 1, 1, "c.test");
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) { sqlite3_close(db); return; }
    db_schema_info_t si;
    CHECK(db_driver_sqlite3.check_schema(c, &si) == 0 && !si.has_changes);
    chg_t ch = {0};
    uint64_t last = 99;
    bool gap = true;
    CHECK(db_driver_sqlite3.changes_since(c, 0, collect_chg, &ch, &last, &gap) == DB_ERR_UNAVAILABLE);
    CHECK(ch.n == 0);
    db_driver_sqlite3.close(c);

    /* the change log of B6 (provisional shape: seq, domain_id, changed_at) */
    raw_exec(db, "CREATE TABLE karidns_changes (seq INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL,"
                 " changed_at INTEGER NOT NULL)");
    for (int i = 1; i <= 5; i++)
        sqlf(db, "INSERT INTO karidns_changes (domain_id, changed_at) VALUES (%d, 1)", i % 2 + 1);
    c = open_driver(path, 0, err, sizeof(err), NULL);
    if (c) {
        CHECK(db_driver_sqlite3.check_schema(c, &si) == 0 && si.has_changes);
        CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
        memset(&ch, 0, sizeof(ch));
        CHECK(db_driver_sqlite3.changes_since(c, 0, collect_chg, &ch, &last, &gap) == 0);
        CHECK(ch.n == 5 && ch.seq[0] == 1 && ch.seq[4] == 5 && last == 5 && !gap);
        memset(&ch, 0, sizeof(ch));
        CHECK(db_driver_sqlite3.changes_since(c, 3, collect_chg, &ch, &last, &gap) == 0);
        CHECK(ch.n == 2 && ch.seq[0] == 4 && last == 5 && !gap);
        memset(&ch, 0, sizeof(ch));
        CHECK(db_driver_sqlite3.changes_since(c, 5, collect_chg, &ch, &last, &gap) == 0 && ch.n == 0 && last == 5 && !gap);
        CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
        db_driver_sqlite3.close(c);
    }
    /* pruned rows: the log starts after `after` + 1 */
    raw_exec(db, "DELETE FROM karidns_changes WHERE seq <= 3");
    c = open_driver(path, 0, err, sizeof(err), NULL);
    if (c) {
        CHECK(db_driver_sqlite3.check_schema(c, &si) == 0);
        memset(&ch, 0, sizeof(ch));
        CHECK(db_driver_sqlite3.changes_since(c, 1, collect_chg, &ch, &last, &gap) == 0);
        CHECK(gap && ch.n == 2 && ch.seq[0] == 4);
        db_driver_sqlite3.close(c);
    }
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ 8. the dump */
typedef struct {
    int status;
    bool stream_ok;              /* every frame passed the Backend state machine */
    char sm_reason[KDB_REASON_LEN];
    size_t n_begin, n_end, n_failed, n_data;
    char begin_name[16][80];
    char failed_name[16][80];
    char failed_reason[16][300];
    uint32_t be_zones, be_failed, be_deleted;
    bool saw_hello, saw_batch_begin, saw_batch_end;
    uint8_t *bytes;
    size_t len;
    size_t first_begin_off, first_end_off;      /* ZONE_BEGIN of the first zone .. end of its ZONE_END */
    bool have_first;
} dump_t;

static void dump_free(dump_t *d) { free(d->bytes); memset(d, 0, sizeof(*d)); }

/* byte range of the first zone's ZONE_BEGIN .. ZONE_END in the stream */
static bool first_zone_range(const dump_t *d, size_t *off, size_t *len) {
    if (!d->have_first || d->first_end_off <= d->first_begin_off) return false;
    *off = d->first_begin_off;
    *len = d->first_end_off - d->first_begin_off;
    return true;
}

/* message boundaries (12-byte header, big-endian type and body length) */
static void find_first_zone(dump_t *d) {
    size_t p = 0;
    while (p + KDB_HEADER_LEN <= d->len) {
        uint16_t type = (uint16_t)((d->bytes[p + 4] << 8) | d->bytes[p + 5]);
        uint32_t bl = ((uint32_t)d->bytes[p + 8] << 24) | ((uint32_t)d->bytes[p + 9] << 16) | ((uint32_t)d->bytes[p + 10] << 8) | d->bytes[p + 11];
        if (p + KDB_HEADER_LEN + bl > d->len) return;
        if (type == KDB_T_ZONE_BEGIN && !d->have_first) { d->first_begin_off = p; d->have_first = true; }
        p += KDB_HEADER_LEN + bl;
        if (type == KDB_T_ZONE_END && d->have_first && !d->first_end_off) { d->first_end_off = p; return; }
    }
}

static void analyze_stream(dump_t *d) {
    static uint8_t body[KDB_MAX_BODY];
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_LOADER, body, sizeof(body));
    kdb_sm_t sm;
    kdb_sm_init(&sm, NULL);
    d->stream_ok = true;
    if (kdb_framer_feed(&f, d->bytes, d->len) != KDB_OK) { d->stream_ok = false; return; }
    for (;;) {
        kdb_frame_t fr;
        kdb_rc_t rc = kdb_framer_next(&f, &fr);
        if (rc == KDB_MORE) break;
        if (rc != KDB_OK) { d->stream_ok = false; snprintf(d->sm_reason, sizeof(d->sm_reason), "%s", f.reason); return; }
        kdb_msg_t m;
        rc = kdb_sm_accept(&sm, &fr, &m);
        if (kdb_rc_is_error(rc)) { d->stream_ok = false; snprintf(d->sm_reason, sizeof(d->sm_reason), "%s", sm.reason); return; }
        switch (m.type) {
        case KDB_T_HELLO: d->saw_hello = true; break;
        case KDB_T_BATCH_BEGIN: d->saw_batch_begin = true; break;
        case KDB_T_ZONE_BEGIN:
            if (d->n_begin < 16) snprintf(d->begin_name[d->n_begin], 80, "%s", m.u.zone_begin.name);
            d->n_begin++;
            break;
        case KDB_T_ZONE_DATA: d->n_data++; break;
        case KDB_T_ZONE_END: d->n_end++; break;
        case KDB_T_ZONE_FAILED:
            if (d->n_failed < 16) {
                snprintf(d->failed_name[d->n_failed], 80, "%s", m.u.zone_failed.name);
                snprintf(d->failed_reason[d->n_failed], 300, "%.*s", (int)m.u.zone_failed.reason.len, m.u.zone_failed.reason.p);
            }
            d->n_failed++;
            break;
        case KDB_T_BATCH_END:
            d->saw_batch_end = true;
            d->be_zones = m.u.batch_end.n_zones;
            d->be_failed = m.u.batch_end.n_failed;
            d->be_deleted = m.u.batch_end.n_deleted;
            break;
        default: break;
        }
    }
}

static uint32_t g_threads = 1;      /* loader-threads of run_dump_mem() */

/* run the dump of `path` into memory (only_zone may be NULL) */
static void run_dump_mem(const char *path, const char *only_zone, dump_t *d) {
    memset(d, 0, sizeof(*d));
    char outp[700];
    snprintf(outp, sizeof(outp), "%s/dump.out", g_dir);
    ctx_t x;
    memset(&x, 0, sizeof(x));
    x.drv = &db_driver_sqlite3;
    x.nthreads = g_threads;
    kdb_enc_init(&x.enc);
    x.out = fopen(outp, "wb");
    db_source_t src = { "sqlite3", path, NULL, NULL, 0 };
    d->status = run_dump(&x, &src, only_zone);
    fclose(x.out);
    d->bytes = (uint8_t *)slurp(outp);
    FILE *f = fopen(outp, "rb");
    if (f) { fseek(f, 0, SEEK_END); d->len = (size_t)ftell(f); fclose(f); }
    analyze_stream(d);
    if (d->bytes) find_first_zone(d);
    ctx_view_reset(&x);
    kdb_enc_free(&x.enc);
    unlink(outp);
}

typedef struct { int64_t did[32]; char vn[32][24]; size_t n; } dv_t;
static int collect_dv(void *ud, int64_t did, const char *vn) {
    dv_t *d = ud;
    if (d->n < 32) { d->did[d->n] = did; snprintf(d->vn[d->n], sizeof(d->vn[0]), "%s", vn); d->n++; }
    return 0;
}
typedef struct { int64_t lo, hi; size_t n; bool ordered; int64_t prev_d, prev_id; } rng_t;
static int collect_rng(void *ud, int64_t did, const db_record_row_t *r) {
    rng_t *g = ud;
    if (did < g->lo || did > g->hi) g->ordered = false;
    if (did < g->prev_d || (did == g->prev_d && r->id <= g->prev_id)) g->ordered = false;
    g->prev_d = did;
    g->prev_id = r->id;
    g->n++;
    return 0;
}

/* B6b: scan_records_range (the rows of a domain_id range, in order) and scan_domain_views (karidns_domain_views) */
static void test_range_views(void) {
    printf("scan_records_range, scan_domain_views\n");
    char path[600], err[DB_ERRLEN];
    sqlite3 *db = make_db("rng.db", path, sizeof(path));
    for (int i = 1; i <= 6; i++) {
        char nm[40];
        snprintf(nm, sizeof(nm), "r%d.test", i);
        add_simple_zone(db, i, i * 10, nm);                      /* 3 records each */
    }
    db_conn_t *c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) { sqlite3_close(db); return; }
    db_schema_info_t si;
    CHECK(db_driver_sqlite3.check_schema(c, &si) == 0 && !si.has_domain_views);
    dv_t dv = {0};
    CHECK(db_driver_sqlite3.scan_domain_views(c, NULL, collect_dv, &dv) == DB_ERR_UNAVAILABLE && dv.n == 0);
    db_driver_sqlite3.close(c);

    raw_exec(db, "CREATE TABLE karidns_domain_views (domain_id INTEGER NOT NULL, view_name VARCHAR(64) NOT NULL,"
                 " PRIMARY KEY (domain_id, view_name))");
    raw_exec(db, "INSERT INTO karidns_domain_views VALUES (4, 'b'), (2, 'a'), (2, 'B'), (5, 'a')");
    c = open_driver(path, 0, err, sizeof(err), NULL);
    CHECK(c != NULL);
    if (!c) { sqlite3_close(db); return; }
    CHECK(db_driver_sqlite3.check_schema(c, &si) == 0 && si.has_domain_views);
    CHECK(db_driver_sqlite3.begin_snapshot(c) == 0);
    CHECK(db_driver_sqlite3.scan_domain_views(c, NULL, collect_dv, &dv) == 0);
    CHECK(dv.n == 4 && dv.did[0] == 2 && dv.did[1] == 2 && dv.did[2] == 4 && dv.did[3] == 5);
    CHECK(strcmp(dv.vn[2], "b") == 0 && strcmp(dv.vn[3], "a") == 0);        /* names are returned as stored */
    dv_t one = {0};
    int64_t id2 = 2, id3 = 3;
    CHECK(db_driver_sqlite3.scan_domain_views(c, &id2, collect_dv, &one) == 0 && one.n == 2);
    dv_t none = {0};
    CHECK(db_driver_sqlite3.scan_domain_views(c, &id3, collect_dv, &none) == 0 && none.n == 0);

    rng_t g = { 2, 4, 0, true, 0, 0 };
    CHECK(db_driver_sqlite3.scan_records_range(c, 2, 4, collect_rng, &g) == 0);
    CHECK(g.n == 9 && g.ordered);
    rng_t g2 = { 5, 5, 0, true, 0, 0 };
    CHECK(db_driver_sqlite3.scan_records_range(c, 5, 5, collect_rng, &g2) == 0 && g2.n == 3 && g2.ordered);
    rng_t g3 = { 7, 9, 0, true, 0, 0 };
    CHECK(db_driver_sqlite3.scan_records_range(c, 7, 9, collect_rng, &g3) == 0 && g3.n == 0);
    rng_t g4 = { 1, 6, 0, true, 0, 0 };
    size_t stopped = 0;
    CHECK(db_driver_sqlite3.scan_records_range(c, 1, 6, stop_rec, &stopped) == DB_STOPPED && stopped == 1);
    CHECK(db_driver_sqlite3.scan_records_range(c, 1, 6, collect_rng, &g4) == 0 && g4.n == 18);     /* the statement is usable again */
    CHECK(db_driver_sqlite3.end_snapshot(c) == 0);
    db_driver_sqlite3.close(c);
    sqlite3_close(db);
}

static void test_dump(void) {
    printf("dump\n");
    char path[600];
    sqlite3 *db = make_db("dump.db", path, sizeof(path));
    add_simple_zone(db, 1, 1, "ok.test");
    add_simple_zone(db, 2, 4, "keys.test");                    /* cryptokeys, no PRESIGNED: fails */
    add_simple_zone(db, 3, 7, "signed.test");                  /* cryptokeys + PRESIGNED=1: loaded */
    add_zone(db, 4, "slave.test", "SLAVE");                    /* B7 */
    add_zone(db, 5, "bad name.test", "NATIVE");                /* not a name: only on stderr */
    add_simple_zone(db, 6, 10, "ttl.test");
    add_zone(db, 7, "nosoa.test", "NATIVE");
    add_rec(db, 20, 7, "nosoa.test", "NS", "ns1.nosoa.test", 3600, -1, 0, NULL);
    add_zone(db, 8, "weird.test", "WEIRD");
    add_simple_zone(db, 9, 30, "outside.test");
    add_rec(db, 40, 9, "elsewhere.example", "A", "192.0.2.1", 60, -1, 0, NULL);   /* outside the zone */
    sqlf(db, "INSERT INTO cryptokeys (id, domain_id, flags, active, content) VALUES (1, 2, 257, 1, 'x')");
    sqlf(db, "INSERT INTO cryptokeys (id, domain_id, flags, active, content) VALUES (2, 3, 257, 1, 'x')");
    sqlf(db, "INSERT INTO domainmetadata (id, domain_id, kind, content) VALUES (1, 3, 'PRESIGNED', '1')");
    raw_exec(db, "UPDATE records SET ttl = NULL WHERE domain_id = 6 AND type = 'A'");
    sqlite3_close(db);

    dump_t d;
    run_dump_mem(path, NULL, &d);
    CHECK_MSG(d.status == 1, "exit status %d: some zones failed", d.status);
    CHECK_MSG(d.stream_ok, "the whole stream passes the Backend state machine: %s", d.sm_reason);
    CHECK(d.saw_hello && d.saw_batch_begin && d.saw_batch_end);
    {   /* B6b: the stream does not depend on loader-threads (valid and failed zones, in domains.id order) */
        dump_t d4;
        g_threads = 4;
        run_dump_mem(path, NULL, &d4);
        g_threads = 1;
        CHECK_MSG(d4.status == d.status && d4.len == d.len && d.len > 0 && memcmp(d4.bytes, d.bytes, d.len) == 0,
                  "4 threads: exit %d, %zu bytes (1 thread: exit %d, %zu bytes)", d4.status, d4.len, d.status, d.len);
        dump_free(&d4);
    }
    CHECK_MSG(d.n_begin == 3 && d.n_end == 3, "zones written: %zu begin, %zu end", d.n_begin, d.n_end);
    if (d.n_begin == 3) {
        CHECK(strcmp(d.begin_name[0], "ok.test.") == 0);
        CHECK(strcmp(d.begin_name[1], "signed.test.") == 0);
        CHECK(strcmp(d.begin_name[2], "ttl.test.") == 0);
    }
    /* keys.test, slave.test, nosoa.test, weird.test, outside.test (the outside record is dropped, the zone stays) */
    CHECK_MSG(d.n_failed >= 4, "ZONE_FAILED messages: %zu", d.n_failed);
    bool f_keys = false, f_slave = false, f_nosoa = false, f_weird = false;
    for (size_t i = 0; i < d.n_failed && i < 16; i++) {
        if (!strcmp(d.failed_name[i], "keys.test.")) f_keys = strstr(d.failed_reason[i], "cryptokeys") && strstr(d.failed_reason[i], "PRESIGNED");
        if (!strcmp(d.failed_name[i], "slave.test.")) f_slave = strstr(d.failed_reason[i], "B7") != NULL;
        if (!strcmp(d.failed_name[i], "nosoa.test.")) f_nosoa = strstr(d.failed_reason[i], "SOA") != NULL;
        if (!strcmp(d.failed_name[i], "weird.test.")) f_weird = strstr(d.failed_reason[i], "domains.type") != NULL;
    }
    CHECK(f_keys);
    CHECK(f_slave);
    CHECK(f_nosoa);
    CHECK(f_weird);
    CHECK_MSG(d.be_zones == 3 && d.be_failed == d.n_failed && d.be_deleted == 0, "BATCH_END %u %u %u", d.be_zones, d.be_failed, d.be_deleted);
    /* the invalid name is not in the stream */
    for (size_t i = 0; i < d.n_failed && i < 16; i++) CHECK(strstr(d.failed_name[i], "bad") == NULL);
    dump_free(&d);

    /* the same dump twice: identical bytes */
    dump_t d1, d2;
    run_dump_mem(path, NULL, &d1);
    run_dump_mem(path, NULL, &d2);
    CHECK(d1.len > 100 && d1.len == d2.len && d1.bytes && d2.bytes && memcmp(d1.bytes, d2.bytes, d1.len) == 0);
    /* one zone: the per-zone path gives the same ZONE_BEGIN..ZONE_END bytes as the bulk path has for it */
    dump_t one;
    run_dump_mem(path, "OK.test.", &one);
    CHECK_MSG(one.status == 0 && one.stream_ok && one.n_begin == 1 && one.n_end == 1 && one.n_failed == 0, "status %d", one.status);
    CHECK(one.be_zones == 1);
    {
        size_t o1, l1, o2, l2;
        bool g1 = first_zone_range(&one, &o1, &l1), g2 = first_zone_range(&d1, &o2, &l2);
        CHECK(g1 && g2 && l1 == l2 && l1 > 100 && memcmp(one.bytes + o1, d1.bytes + o2, l1) == 0);
    }
    dump_free(&one);
    run_dump_mem(path, "nothere.test", &one);
    CHECK_MSG(one.status == 3, "unknown zone: %d", one.status);
    dump_free(&one);
    dump_free(&d1);
    dump_free(&d2);

    /* a database that is not in WAL mode: error, no stream */
    sqlite3 *w = raw_open(path, SQLITE_OPEN_READWRITE);
    raw_exec(w, "PRAGMA journal_mode=DELETE");
    sqlite3_close(w);
    run_dump_mem(path, NULL, &d);
    CHECK_MSG(d.status == 3, "not WAL: exit %d", d.status);
    dump_free(&d);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/db";
    snprintf(g_schema, sizeof(g_schema), "%s/pdns_schema.sqlite3.sql", dir);
    g_schema_sql = slurp(g_schema);
    if (!g_schema_sql) {
        printf("  [FAIL] cannot read %s\n", g_schema);
        return 1;
    }
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/karidns_dbsq_XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(g_dir)) {
        printf("  [FAIL] cannot create a temporary directory\n");
        return 1;
    }
    printf("sqlite3 %s, driver tests in %s\n", sqlite3_libversion(), g_dir);
    test_open();
    test_paths();
    test_schema();
    test_rows();
    test_nul();
    test_scans();
    test_snapshot();
    test_busy();
    test_changes();
    test_range_views();
    test_dump();
    free(g_schema_sql);
    rm_tree(g_dir);
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

#else /* !KARIDNS_DB_SQLITE3 */

int main(void) {
    printf("SKIP: built without the SQLite3 driver (DB_DRIVERS lacks sqlite3)\n");
    return 0;
}

#endif
