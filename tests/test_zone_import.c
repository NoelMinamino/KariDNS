/*
 * test_zone_import.c - the ZoneImporter and the ZoneExporter of 0.6.0 (dns_zone_import.c, dns_zone_export.c, dns_zone_msg.c; the write functions of
 * dns_db_sqlite3.c and dns_db_pgsql.c; the text loaders of dns_zone_rows.c).
 *
 * Every scenario runs on SQLite3 (a private database file per scenario, tests/db/pdns_schema.sqlite3.sql + db/karidns_ext.sqlite3.sql) and, when
 * the build has the PostgreSQL driver and KARIDNS_TEST_PG names a server (default "dbname=postgres"; the role must be allowed to create
 * databases), on PostgreSQL (a database karidns_test_zi_<pid>, dropped at the end).  Without a server the PostgreSQL part says SKIP.
 *
 * Cases: a new zone (type NATIVE), replace (the zone row and its type are kept), merge (RRset merge), the types filter, dry run and its report, the
 * serial rules (grow, equal, 2^31 apart, increment, keep, wrap-around, a new zone), the metadata the importer owns against the metadata it keeps,
 * tags / tag definitions / tinydns attributes in the karidns_* tables, views, reload requests, the change log (the triggers fire), a bad record
 * that leaves the database unchanged, a failure of every write step (a driver that fails on demand), a second importer that waits for the zone,
 * tinydns data files with several zones, the round trip file -> import -> export -> the same zone (BIND, tags, tinydns, a signed zone), standard
 * input, $INCLUDE, the options, the strict mode, the warnings (file zone, keys, no reload table), a database without the extension tables, the
 * read-back verification (CNAME / ALIAS beside other data, a limit, a check-* option), the exporter (views, zone types, keys without PRESIGNED), and on PostgreSQL the writer role (db/karidns_writer_role.pgsql.sql).
 *
 * Usage: test_zone_import [tests/db]   (the directory of pdns_schema.*.sql)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../dns_zone_import.h"
#include "../dns_zone_export.h"
#include "../dns_zone_rows.h"
#include "../dns_zone_text.h"

#ifdef KARIDNS_DB_SQLITE3
#include <sqlite3.h>
#endif
#ifdef KARIDNS_DB_POSTGRESQL
#include <libpq-fe.h>
#endif

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%.300s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

/* ------------------------------------------------------------------------------------------------------------- */
/* the backend under test                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

typedef enum { BE_SQLITE, BE_PG } be_kind_t;
static be_kind_t g_be;
static const db_driver_t *g_drv;
static db_source_t g_src;
static char g_dir[400];                 /* private temporary directory */
static char g_root[300];                /* tests/db */
static int g_dbn;                       /* SQLite3: number of the database file */
static bool g_have_ext = true;          /* the current database has the karidns_* extension tables */
#ifdef KARIDNS_DB_SQLITE3
static sqlite3 *g_sq;
#endif
#ifdef KARIDNS_DB_POSTGRESQL
static PGconn *g_pg;
static char g_maint[1024], g_pgdb[96], g_ci[460];
#endif

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

static void write_file(const char *path, const char *content, mode_t mode) {
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd >= 0) {
        if (write(fd, content, strlen(content)) < 0) g_failed++;
        close(fd);
        chmod(path, mode);
    }
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

/* run SQL on the test's own connection (several statements are fine); a failure is a FAIL */
static bool be_exec(const char *sql) {
#ifdef KARIDNS_DB_SQLITE3
    if (g_be == BE_SQLITE) {
        char *err = NULL;
        if (sqlite3_exec(g_sq, sql, NULL, NULL, &err) != SQLITE_OK) {
            printf("  [FAIL] sql error: %s\n    %.200s\n", err ? err : "?", sql);
            g_failed++;
            sqlite3_free(err);
            return false;
        }
        return true;
    }
#endif
#ifdef KARIDNS_DB_POSTGRESQL
    if (g_be == BE_PG) {
        PGresult *r = PQexec(g_pg, sql);
        ExecStatusType st = r ? PQresultStatus(r) : PGRES_FATAL_ERROR;
        bool ok = st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK;
        if (!ok) {
            printf("  [FAIL] sql error: %s    %.200s\n", PQerrorMessage(g_pg), sql);
            g_failed++;
        }
        PQclear(r);
        return ok;
    }
#endif
    (void)sql;
    return false;
}

/* the first column of the first row as text ("" for NULL or no row) */
static void be_str(const char *sql, char *out, size_t cap) {
    out[0] = '\0';
#ifdef KARIDNS_DB_SQLITE3
    if (g_be == BE_SQLITE) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(g_sq, sql, -1, &st, NULL) != SQLITE_OK) {
            printf("  [FAIL] sql error: %s\n    %.200s\n", sqlite3_errmsg(g_sq), sql);
            g_failed++;
            return;
        }
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) snprintf(out, cap, "%s", (const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
        return;
    }
#endif
#ifdef KARIDNS_DB_POSTGRESQL
    if (g_be == BE_PG) {
        PGresult *r = PQexec(g_pg, sql);
        if (r && PQresultStatus(r) == PGRES_TUPLES_OK) {
            if (PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) snprintf(out, cap, "%s", PQgetvalue(r, 0, 0));
        } else {
            printf("  [FAIL] query error: %s    %.200s\n", PQerrorMessage(g_pg), sql);
            g_failed++;
        }
        PQclear(r);
    }
#endif
}

static long be_int(const char *sql) {
    char b[64];
    be_str(sql, b, sizeof(b));
    return b[0] ? strtol(b, NULL, 10) : -1;
}

/* a printf-style count / string query */
static long qn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static long qn(const char *fmt, ...) {
    char sql[1500];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(sql, sizeof(sql), fmt, ap);
    va_end(ap);
    return be_int(sql);
}

static void qs(char *out, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void qs(char *out, size_t cap, const char *fmt, ...) {
    char sql[1500];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(sql, sizeof(sql), fmt, ap);
    va_end(ap);
    be_str(sql, out, cap);
}

static void sql_file(const char *rel) {
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", g_root, rel);
    char *sql = slurp(path);
    CHECK_MSG(sql != NULL, "cannot read %s", path);
    if (sql) be_exec(sql);
    free(sql);
}

/* an empty database with the PowerDNS tables (and the karidns_* extension tables when ext) */
static void be_fresh(bool ext) {
#ifdef KARIDNS_DB_SQLITE3
    if (g_be == BE_SQLITE) {
        static char path[600];
        if (g_sq) sqlite3_close(g_sq);
        snprintf(path, sizeof(path), "%s/zi%d.db", g_dir, ++g_dbn);
        g_sq = NULL;
        if (sqlite3_open_v2(path, &g_sq, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
            printf("  [FAIL] cannot open %s\n", path);
            g_failed++;
            return;
        }
        sql_file("pdns_schema.sqlite3.sql");
        if (ext) sql_file("../../db/karidns_ext.sqlite3.sql");
        g_src = (db_source_t){ "sqlite3", path, NULL, NULL, 400 };
        g_have_ext = ext;
        return;
    }
#endif
#ifdef KARIDNS_DB_POSTGRESQL
    if (g_be == BE_PG) {
        if (ext && g_have_ext && qn("SELECT count(*) FROM pg_class WHERE relname = 'karidns_changes'") == 1) {
            be_exec("TRUNCATE domains, records, domainmetadata, cryptokeys, karidns_changes, karidns_domain_views, karidns_record_tags, "
                    "karidns_record_tinydns, karidns_zone_tagdefs, karidns_reload_requests RESTART IDENTITY CASCADE");
            return;
        }
        be_exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
        sql_file("pdns_schema.pgsql.sql");
        if (ext) sql_file("../../db/karidns_ext.pgsql.sql");
        g_have_ext = ext;
    }
#endif
}

/* ------------------------------------------------------------------------------------------------------------- */
/* messages, options, input                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static char g_log[32768];
static size_t g_nlog;
static bool g_code_seen[DC__COUNT];            /* every code the messages carried, over all scenarios */

static void msg_cb(void *ud, int sev, dns_diag_code_t code, const char *file, const char *text) {
    (void)ud;
    (void)file;
    if (code > 0 && code < DC__COUNT) g_code_seen[code] = true;
    g_nlog += (size_t)snprintf(g_log + g_nlog, sizeof(g_log) - g_nlog, "[%d %s] %s\n", sev, dns_diag_code_name(code), text);
    if (g_nlog >= sizeof(g_log)) g_nlog = sizeof(g_log) - 1;
}
static void log_reset(void) {
    g_log[0] = '\0';
    g_nlog = 0;
}
#define LOG_HAS(code) CHECK_MSG(strstr(g_log, " " code "]") != NULL, "no message " code " in:\n%s", g_log)
#define LOG_HAS_NOT(code) CHECK_MSG(strstr(g_log, " " code "]") == NULL, "unexpected message " code " in:\n%s", g_log)

static zi_opts_t base_opts(void) {
    zi_opts_t o;
    memset(&o, 0, sizeof(o));
    o.drv = g_drv;
    o.src = g_src;
    o.mode = ZI_REPLACE;
    o.serial = ZI_SERIAL_GROW;
    o.msg.fn = msg_cb;
    return o;
}

static char g_rep[2048];
static void rep_cb(void *ud, char what, const char *owner, const char *type) {
    (void)ud;
    size_t n = strlen(g_rep);
    snprintf(g_rep + n, sizeof(g_rep) - n, "%c%s/%s ", what, owner, type);
}

/* one import with a connection of its own: ZI_OK / ZI_FAIL / ZI_BUSY, or -1 when the options were refused */
static int imp(const zi_opts_t *o, const char *text, const char *zone, zi_result_t *r) {
    zi_result_t local;
    zi_t *z = zi_open(o);
    if (!z) return -1;
    zi_input_t in = { NULL, text, strlen(text), 0 };
    int st = zi_import_zone(z, &in, zone, r ? r : &local);
    zi_close(z);
    return st;
}

/* a small valid zone: SOA with the serial, NS, glue, and body */
static char *zone_text(const char *origin, unsigned long serial, const char *body) {
    char *t = malloc(4096 + strlen(body));
    snprintf(t, 4096 + strlen(body),
             "$ORIGIN %s.\n$TTL 3600\n@ IN SOA ns1.%s. hostmaster.%s. %lu 7200 3600 1209600 300\n@ IN NS ns1.%s.\nns1 IN A 192.0.2.1\n%s", origin, origin,
             origin, serial, origin, body);
    return t;
}

static const char *K_BODY = "www IN A 192.0.2.80\nmail IN MX 10 mx\nmx IN A 192.0.2.25\n";

static int imp_zone(const zi_opts_t *o, const char *origin, unsigned long serial, const char *body, zi_result_t *r) {
    char *t = zone_text(origin, serial, body);
    int st = imp(o, t, NULL, r);
    free(t);
    return st;
}

typedef struct { char *p; size_t n, cap; } sbuf_t;
static int sb_sink(void *ud, const char *d, size_t n) {
    sbuf_t *b = ud;
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = realloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, d, n);
    b->n += n;
    b->p[b->n] = '\0';
    return 0;
}

/* the zone as text through the exporter; NULL with a message in the log */
static char *do_export(const char *zone, const char *view, const dzt_opts_t *fmt) {
    zmsg_t m = { msg_cb, NULL };
    zx_t *x = zx_open(g_drv, &g_src, &m);
    if (!x) return NULL;
    sbuf_t b = {0};
    int rc = zx_export_zone(x, zone, view, fmt, sb_sink, &b);
    zx_close(x);
    if (rc != 0) {
        free(b.p);
        return NULL;
    }
    if (!b.p) b.p = strdup("");
    return b.p;
}

static long serial_of(const char *zone) {
    char c[300];
    qs(c, sizeof(c), "SELECT content FROM records WHERE type = 'SOA' AND domain_id = (SELECT id FROM domains WHERE name = '%s')", zone);
    unsigned long s = 0;
    return sscanf(c, "%*s %*s %lu", &s) == 1 ? (long)s : -1;
}

static long nrec(const char *zone) { return qn("SELECT count(*) FROM records WHERE domain_id = (SELECT id FROM domains WHERE name = '%s')", zone); }
static long nchg(void) { return qn("SELECT count(*) FROM karidns_changes"); }

/* ------------------------------------------------------------------------------------------------------------- */
/* scenarios                                                                                                      */
/* ------------------------------------------------------------------------------------------------------------- */

static void t_new_zone(void) {
    printf("  new zone\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    log_reset();
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    CHECK(r.created && r.committed && !r.dry_run && r.rrsets_added == 6 && r.records_inserted == 6 && r.records_deleted == 0);
    CHECK(r.wrote_soa && r.new_serial == 10 && !r.has_old_serial);
    CHECK(strcmp(r.zone, "example.test") == 0);
    char b[200];
    qs(b, sizeof(b), "SELECT type FROM domains WHERE name = 'example.test'");
    CHECK_MSG(strcmp(b, "NATIVE") == 0, "type %s", b);
    CHECK(nrec("example.test") == 6);
    CHECK(r.domain_id == qn("SELECT id FROM domains WHERE name = 'example.test'"));
    qs(b, sizeof(b), "SELECT content FROM records WHERE type = 'MX'");
    CHECK_MSG(strcmp(b, "mx.example.test") == 0, "MX content '%s'", b);           /* the target without the dot, the priority in prio */
    CHECK(qn("SELECT prio FROM records WHERE type = 'MX'") == 10);
    CHECK(qn("SELECT count(*) FROM records WHERE name <> lower(name) OR name LIKE '%%.'") == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE ttl = 3600 AND CAST(disabled AS integer) = 0 AND CAST(auth AS integer) = 1") == 6);
    CHECK_MSG(nchg() > 0, "the change log triggers did not fire (%ld rows)", nchg());          /* a running server picks the change up */
    CHECK(qn("SELECT count(*) FROM karidns_changes WHERE domain_id = %ld", (long)r.domain_id) > 0);
    LOG_HAS("db.import.done");
    CHECK_HAS(g_log, "6 RRset(s) added");
    CHECK_HAS(g_log, "SOA serial 10");

    /* the zone type of a new zone */
    be_fresh(true);
    o.zone_type = "master";
    CHECK(imp_zone(&o, "m.test", 1, "", &r) == ZI_OK);
    qs(b, sizeof(b), "SELECT type FROM domains WHERE name = 'm.test'");
    CHECK_MSG(strcmp(b, "MASTER") == 0, "type %s", b);
    /* and an existing zone keeps its type (PowerDNS 5.1.4: pdnsutil load-zone does not change it) */
    o.zone_type = "slave";
    CHECK(imp_zone(&o, "m.test", 2, "", &r) == ZI_OK && !r.created);
    qs(b, sizeof(b), "SELECT type FROM domains WHERE name = 'm.test'");
    CHECK_MSG(strcmp(b, "MASTER") == 0, "type %s", b);
    /* a name with capitals and a final dot is the same zone */
    o.zone_type = NULL;
    char *t = zone_text("M.Test", 3, "");
    CHECK(imp(&o, t, "M.TEST.", &r) == ZI_OK && !r.created && strcmp(r.zone, "m.test") == 0);
    free(t);
    CHECK(qn("SELECT count(*) FROM domains") == 1);
}

static void t_replace_merge(void) {
    printf("  replace and merge\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    int64_t id = r.domain_id;
    CHECK(imp_zone(&o, "other.test", 1, "x IN A 192.0.2.7\n", &r) == ZI_OK);
    long other = nrec("other.test");

    /* replace: www goes, new comes, mail changes */
    log_reset();
    g_rep[0] = '\0';
    o.report = rep_cb;
    CHECK(imp_zone(&o, "example.test", 11, "new IN A 192.0.2.9\nmail IN MX 20 mx\nmx IN A 192.0.2.25\n", &r) == ZI_OK);
    CHECK(!r.created && r.domain_id == id && r.has_old_serial && r.old_serial == 10 && r.new_serial == 11);
    CHECK(r.records_deleted == 6 && r.records_inserted == 6);
    CHECK_MSG(r.rrsets_added == 1 && r.rrsets_replaced == 2 && r.rrsets_deleted == 1, "+%zu ~%zu -%zu", r.rrsets_added, r.rrsets_replaced, r.rrsets_deleted);
    CHECK_HAS(g_rep, "-www.example.test/A ");
    CHECK_HAS(g_rep, "+new.example.test/A ");
    CHECK_HAS(g_rep, "~mail.example.test/MX ");
    CHECK_HAS(g_rep, "~example.test/SOA ");
    CHECK(strstr(g_rep, "example.test/NS") == NULL);          /* unchanged: not reported */
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test'") == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'new.example.test'") == 1);
    CHECK(serial_of("example.test") == 11);
    CHECK(nrec("other.test") == other);                          /* another zone is not touched */
    o.report = NULL;

    /* merge: the RRsets of the file replace those of the database, the others stay */
    CHECK(imp_zone(&o, "example.test", 12, K_BODY, &r) == ZI_OK);         /* back to the first content */
    o.mode = ZI_MERGE;
    char *t = strdup("$ORIGIN example.test.\n$TTL 600\nwww IN A 192.0.2.81\nwww IN A 192.0.2.82\nadded IN TXT \"hi\"\n");
    log_reset();
    g_rep[0] = '\0';
    o.report = rep_cb;
    CHECK(imp(&o, t, "example.test", &r) == ZI_OK);
    free(t);
    LOG_HAS_NOT("zone.soa.missing");                             /* a partial file: not an error in merge mode */
    CHECK_MSG(r.rrsets_added == 1 && r.rrsets_replaced == 1 && r.rrsets_deleted == 0, "+%zu ~%zu -%zu", r.rrsets_added, r.rrsets_replaced, r.rrsets_deleted);
    CHECK(r.records_deleted == 1 && r.records_inserted == 3 && !r.wrote_soa);
    CHECK_HAS(g_rep, "+added.example.test/TXT ");
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND ttl = 600") == 2);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'mail.example.test'") == 1);        /* kept */
    CHECK(nrec("example.test") == 6 - 1 + 3);
    CHECK(serial_of("example.test") == 12);
    o.report = NULL;

    /* merge into a zone that does not exist yet is an import */
    CHECK(imp_zone(&o, "fresh.test", 5, "a IN A 192.0.2.3\n", &r) == ZI_OK && r.created && nrec("fresh.test") == 4);
    /* merge with an SOA: the serial rule applies */
    CHECK(imp_zone(&o, "example.test", 12, "", &r) == ZI_FAIL);
    CHECK(imp_zone(&o, "example.test", 13, "", &r) == ZI_OK && r.wrote_soa && serial_of("example.test") == 13);
}

static void t_types(void) {
    printf("  types filter\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 10, "www IN A 192.0.2.80\nwww IN TXT \"old\"\nmail IN MX 10 mx\nmx IN A 192.0.2.25\n", &r) == ZI_OK);
    be_exec("INSERT INTO domainmetadata (domain_id, kind, content) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 'ALLOW-AXFR-FROM', 'AUTO-NS')");
    static const char *const ty[] = { "a", "TXT" };
    o.types = ty;
    o.ntypes = 2;
    /* replace + types: only A and TXT of the file replace A and TXT of the zone; the SOA, NS and MX stay (and so does the serial) */
    char *t = zone_text("example.test", 3, "www IN A 192.0.2.99\nmail IN MX 10 other\nnewtxt IN TXT \"n\"\n");
    log_reset();
    CHECK(imp(&o, t, NULL, &r) == ZI_OK);
    free(t);
    CHECK_MSG(r.records_deleted == 4 && r.records_inserted == 3, "-%zu +%zu", r.records_deleted, r.records_inserted);        /* A ns1, A www, A mx, TXT www */
    CHECK(!r.wrote_soa);
    CHECK(serial_of("example.test") == 10);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'MX' AND content = 'mx.example.test'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'TXT'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'A' AND content = '192.0.2.99'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'A'") == 2);                  /* ns1 from the file and www */
    CHECK(qn("SELECT count(*) FROM domainmetadata WHERE kind = 'ALLOW-AXFR-FROM'") == 1);
    /* merge + types */
    o.mode = ZI_MERGE;
    t = strdup("$ORIGIN example.test.\n$TTL 60\nwww IN A 192.0.2.100\nmail IN MX 5 mx\n");
    CHECK(imp(&o, t, "example.test", &r) == ZI_OK);
    free(t);
    CHECK(r.records_deleted == 1 && r.records_inserted == 1);                         /* the MX is not an A: neither deleted nor inserted */
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'A' AND content = '192.0.2.100'") == 1);
    CHECK(qn("SELECT prio FROM records WHERE type = 'MX'") == 10);
    /* a type that is not a token */
    static const char *const bad[] = { "A;DROP" };
    o.types = bad;
    o.ntypes = 1;
    log_reset();
    CHECK(zi_open(&o) == NULL);
    LOG_HAS("db.import.option");
}

static void t_dry_run(void) {
    printf("  dry run\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    o.dry_run = true;
    o.report = rep_cb;
    zi_result_t r;
    g_rep[0] = '\0';
    log_reset();
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);          /* a new zone: created and rolled back */
    CHECK(r.dry_run && !r.committed && r.created && r.rrsets_added == 6);
    CHECK_HAS(g_rep, "+www.example.test/A ");
    CHECK(qn("SELECT count(*) FROM domains") == 0 && qn("SELECT count(*) FROM records") == 0 && nchg() == 0);
    LOG_HAS("db.import.dry-run");
    o.dry_run = false;
    o.report = NULL;
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    long chg = nchg();
    o.dry_run = true;
    o.report = rep_cb;
    g_rep[0] = '\0';
    CHECK(imp_zone(&o, "example.test", 11, "new IN A 192.0.2.9\n", &r) == ZI_OK);
    CHECK_MSG(r.rrsets_added == 1 && r.rrsets_deleted == 3 && r.rrsets_replaced == 1, "+%zu ~%zu -%zu", r.rrsets_added, r.rrsets_replaced, r.rrsets_deleted);
    CHECK_HAS(g_rep, "-mail.example.test/MX ");
    CHECK(nrec("example.test") == 6 && serial_of("example.test") == 10 && nchg() == chg);
}

static void t_serial(void) {
    printf("  serial rules\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    /* the serial must grow */
    log_reset();
    CHECK(imp_zone(&o, "example.test", 10, "other IN A 192.0.2.5\n", &r) == ZI_FAIL);          /* equal */
    LOG_HAS("db.import.serial");
    CHECK_HAS(g_log, "does not grow past the serial 10");
    CHECK(imp_zone(&o, "example.test", 9, "other IN A 192.0.2.5\n", &r) == ZI_FAIL);
    CHECK(nrec("example.test") == 6 && serial_of("example.test") == 10);                         /* nothing written */
    CHECK(imp_zone(&o, "example.test", 11, "other IN A 192.0.2.5\n", &r) == ZI_OK);
    /* increment: the database serial + 1 whatever the file says */
    o.serial = ZI_SERIAL_INCREMENT;
    CHECK(imp_zone(&o, "example.test", 5, "other IN A 192.0.2.6\n", &r) == ZI_OK);
    CHECK(serial_of("example.test") == 12 && r.new_serial == 12 && r.old_serial == 11);
    CHECK(imp_zone(&o, "example.test", 99999, "other IN A 192.0.2.7\n", &r) == ZI_OK);
    CHECK(serial_of("example.test") == 13);
    /* keep: the file's serial as it is (a restore), also a lower one */
    o.serial = ZI_SERIAL_KEEP;
    CHECK(imp_zone(&o, "example.test", 2, "other IN A 192.0.2.8\n", &r) == ZI_OK);
    CHECK(serial_of("example.test") == 2);
    o.serial = ZI_SERIAL_GROW;
    /* RFC 1982: wrap-around, and two numbers 2^31 apart have no order */
    CHECK(imp_zone(&o, "wrap.test", 4294967295UL, "", &r) == ZI_OK);                              /* a new zone takes the file's serial */
    CHECK(serial_of("wrap.test") == 4294967295L);
    CHECK(imp_zone(&o, "wrap.test", 0, "", &r) == ZI_OK && serial_of("wrap.test") == 0);          /* 0 comes after 2^32 - 1 */
    CHECK(imp_zone(&o, "wrap.test", 2147483648UL, "", &r) == ZI_FAIL);                            /* exactly 2^31 apart: undefined, refused */
    CHECK(imp_zone(&o, "wrap.test", 2147483647UL, "", &r) == ZI_OK);                              /* 2^31 - 1 ahead: grows */
    o.serial = ZI_SERIAL_INCREMENT;
    CHECK(imp_zone(&o, "wrap.test", 1, "", &r) == ZI_OK && serial_of("wrap.test") == 2147483648L);
    o.serial = ZI_SERIAL_KEEP;
    CHECK(imp_zone(&o, "wrap.test", 4294967295UL, "", &r) == ZI_OK);
    o.serial = ZI_SERIAL_INCREMENT;
    CHECK(imp_zone(&o, "wrap.test", 7, "", &r) == ZI_OK && serial_of("wrap.test") == 0);         /* 2^32 - 1 + 1 wraps */
    /* a new zone under increment takes the file's serial */
    CHECK(imp_zone(&o, "newinc.test", 77, "", &r) == ZI_OK && serial_of("newinc.test") == 77);
}

static void t_metadata_ext(void) {
    printf("  owned metadata, tags, tag definitions\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "tagz.test", 1, "", &r) == ZI_OK);
    be_exec("INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, k, c FROM domains, "
            "(SELECT 'ALLOW-AXFR-FROM' AS k, 'AUTO-NS' AS c UNION ALL SELECT 'PRESIGNED', '1' UNION ALL SELECT 'NSEC3PARAM', '1 0 1 ab' "
            "UNION ALL SELECT 'X-KARIDNS-FORMAT', 'tinydns' UNION ALL SELECT 'SOA-EDIT-API', 'DEFAULT') m WHERE name = 'tagz.test'");
    CHECK(qn("SELECT count(*) FROM domainmetadata") == 5);
    /* replace with a zone file that has tags and tag definitions: the owned metadata goes, the rest stays */
    char path[600];
    snprintf(path, sizeof(path), "%s/tagz.test.zone", g_root);
    zi_t *z = zi_open(&o);
    CHECK(z != NULL);
    zi_input_t in = { path, NULL, 0, 0 };
    log_reset();
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM domainmetadata WHERE kind IN ('PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-FORMAT')") == 0);
    CHECK(qn("SELECT count(*) FROM domainmetadata WHERE kind IN ('ALLOW-AXFR-FROM', 'SOA-EDIT-API')") == 2);
    long ntags = qn("SELECT count(*) FROM karidns_record_tags");
    CHECK_MSG(ntags > 6, "%ld tag rows", ntags);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags t JOIN records r ON r.id = t.record_id WHERE r.name = 'both.tagz.test' AND t.location_tag = 'lan' AND t.ecs_tag = 'east'") == 1);
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs WHERE kind = 'location'") == 5);        /* one row per CIDR, in definition order */
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs WHERE kind = 'ecs'") == 3);
    char b[100];
    qs(b, sizeof(b), "SELECT tag FROM karidns_zone_tagdefs ORDER BY id LIMIT 1");
    CHECK_MSG(strcmp(b, "lan") == 0, "first definition %s", b);
    CHECK(qn("SELECT count(*) FROM karidns_record_tinydns") == 0);
    long chg = nchg();
    /* a second replace does not double the rows; the tags of deleted records go with them */
    in.path = path;
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_FAIL);                 /* the serial did not grow */
    zi_close(z);
    o.serial = ZI_SERIAL_INCREMENT;
    z = zi_open(&o);
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags") == ntags && qn("SELECT count(*) FROM karidns_zone_tagdefs") == 8);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags WHERE record_id NOT IN (SELECT id FROM records)") == 0);
    CHECK(nchg() > chg);
    /* merge: the definitions the file makes replace those of the same tag; records of other RRsets keep their tags */
    o.mode = ZI_MERGE;
    zi_close(z);
    z = zi_open(&o);
    char *t = strdup("$ORIGIN tagz.test.\n$TTL 300\n$LOCATION-TAG lan 127.0.0.9/32\n$LOCATION lan\nnewhost IN A 192.0.2.77\n");
    zi_input_t mi = { NULL, t, strlen(t), 0 };
    CHECK(z && zi_import_zone(z, &mi, "tagz.test", &r) == ZI_OK);
    free(t);
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs WHERE tag = 'lan'") == 1);
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs WHERE tag = 'wan'") == 2);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags") == ntags + 1);
    zi_close(z);
    /* an import without tags removes the tag rows and the definitions of a replaced zone */
    o.mode = ZI_REPLACE;
    CHECK(imp_zone(&o, "tagz.test", 1, "", &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags") == 0 && qn("SELECT count(*) FROM karidns_zone_tagdefs") == 0);

    /* tinydns attributes and the format metadata */
    be_fresh(true);
    snprintf(path, sizeof(path), "%s/tdz.test.data", g_root);
    in.path = path;
    z = zi_open(&o);
    CHECK(z && zi_import_tinydns(z, &in, NULL, NULL, NULL) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM karidns_record_tinydns WHERE loc IS NOT NULL") >= 5 && qn("SELECT count(*) FROM karidns_record_tinydns WHERE CAST(countdown AS integer) = 1") == 2);
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs WHERE kind = 'tinydns'") == 3);
    qs(b, sizeof(b), "SELECT content FROM domainmetadata WHERE kind = 'X-KARIDNS-FORMAT'");
    CHECK_MSG(strcmp(b, "tinydns") == 0, "format %s", b);
    zi_close(z);
}

static int names_cb(void *ud, const char *n) {
    sbuf_t *b = ud;
    sb_sink(b, n, strlen(n));
    sb_sink(b, " ", 1);
    return 0;
}

static void t_views_reload(void) {

    printf("  views, reload request\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    o.view = "v1";
    o.reload = true;
    log_reset();
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM karidns_domain_views WHERE view_name = 'v1' AND domain_id = %ld", (long)r.domain_id) == 1);
    if (g_be == BE_PG) {
        CHECK(qn("SELECT count(*) FROM karidns_reload_requests WHERE zone = 'example.test' AND NOT force") == 1);
        LOG_HAS_NOT("db.import.no-reload");
    } else {
        LOG_HAS("db.import.no-reload");                                  /* SQLite3 has no reload requests: a warning, the import went on */
    }
    CHECK(imp_zone(&o, "example.test", 11, K_BODY, &r) == ZI_OK);        /* again: the row stays, one */
    CHECK(qn("SELECT count(*) FROM karidns_domain_views") == 1);
    o.view = "v2";
    CHECK(imp_zone(&o, "example.test", 12, K_BODY, &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM karidns_domain_views") == 2);
    /* the exporter: a zone with rows is in the views they name; one without any row is in every view */
    char *a = do_export("example.test", "V1", NULL);
    CHECK(a != NULL);
    free(a);
    a = do_export("example.test", "v3", NULL);
    CHECK(a == NULL);
    LOG_HAS("db.export.not-found");
    CHECK_HAS(g_log, "not in the view");
    CHECK(imp_zone(&(zi_opts_t){ .drv = g_drv, .src = g_src, .msg = { msg_cb, NULL } }, "free.test", 1, "", &r) == ZI_OK);
    a = do_export("free.test", "anything", NULL);
    CHECK(a != NULL);
    free(a);
    zmsg_t m = { msg_cb, NULL };
    zx_t *x = zx_open(g_drv, &g_src, &m);
    CHECK(x != NULL);
    if (x) {
        sbuf_t names = {0};
        CHECK(zx_list_zones(x, NULL, names_cb, &names) == 0);
        CHECK_MSG(names.p && strcmp(names.p, "example.test free.test ") == 0, "zones: %s", names.p ? names.p : "(none)");
        free(names.p);
        names.p = NULL;
        names.n = names.cap = 0;
        CHECK(zx_list_zones(x, "v2", names_cb, &names) == 0);
        CHECK_MSG(names.p && strcmp(names.p, "example.test free.test ") == 0, "v2 zones: %s", names.p ? names.p : "(none)");
        free(names.p);
        names.p = NULL;
        names.n = names.cap = 0;
        CHECK(zx_list_zones(x, "v3", names_cb, &names) == 0);
        CHECK_MSG(names.p && strcmp(names.p, "free.test ") == 0, "v3 zones: %s", names.p ? names.p : "(none)");
        free(names.p);
        zx_close(x);
    }
}

static void t_bad_input(void) {
    printf("  a bad record leaves the database unchanged\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    long chg = nchg();
    /* an error of the zone checks */
    log_reset();
    CHECK(imp_zone(&o, "example.test", 11, "www IN CNAME mx\nwww IN A 192.0.2.5\n", &r) == ZI_FAIL);
    LOG_HAS("zone.cname.coexists");
    LOG_HAS("db.import.checks");
    CHECK(nrec("example.test") == 6 && serial_of("example.test") == 10 && nchg() == chg);
    /* a syntax error, with the line */
    log_reset();
    CHECK(imp(&o, "$ORIGIN x.test.\n@ SOA a b 1 2 3 4 5\nthis is not a record at all\n", NULL, &r) == ZI_FAIL);
    LOG_HAS("zone.syntax");
    CHECK_HAS(g_log, ":3:");
    /* no records, no SOA, a name that is not a zone */
    log_reset();
    CHECK(imp(&o, "; nothing\n", "x.test", &r) == ZI_FAIL);
    LOG_HAS("zone.empty");
    log_reset();
    CHECK(imp(&o, "$ORIGIN x.test.\nwww A 192.0.2.1\n", NULL, &r) == ZI_FAIL);
    CHECK_HAS(g_log, "no SOA record");
    log_reset();
    CHECK(imp(&o, "$ORIGIN x.test.\nwww A 192.0.2.1\n", "bad..name", &r) == ZI_FAIL);
    LOG_HAS("db.import.zone-name");
    /* a write that fails half way: the whole import is rolled back (a new zone is not created, an old one is not changed) */
    if (g_be == BE_SQLITE) be_exec("CREATE TRIGGER boom BEFORE INSERT ON records WHEN NEW.content = '192.0.2.99' BEGIN SELECT RAISE(ABORT, 'boom'); END");
    else be_exec("ALTER TABLE records ADD CONSTRAINT c_boom CHECK (content <> '192.0.2.99')");
    log_reset();
    CHECK(imp_zone(&o, "example.test", 12, "last IN A 192.0.2.99\n", &r) == ZI_FAIL);
    LOG_HAS("db.import.write");
    CHECK_HAS(g_log, "nothing was written");
    CHECK(nrec("example.test") == 6 && serial_of("example.test") == 10 && nchg() == chg);
    CHECK(imp_zone(&o, "brandnew.test", 1, "last IN A 192.0.2.99\n", &r) == ZI_FAIL);
    CHECK(qn("SELECT count(*) FROM domains WHERE name = 'brandnew.test'") == 0 && nchg() == chg);
    if (g_be == BE_SQLITE) be_exec("DROP TRIGGER boom");
    else be_exec("ALTER TABLE records DROP CONSTRAINT c_boom");
    CHECK(imp_zone(&o, "brandnew.test", 1, "last IN A 192.0.2.99\n", &r) == ZI_OK);

    /* strict: a warning of the zone checks fails the import, nothing is written */
    o.strict = true;
    log_reset();
    CHECK(imp_zone(&o, "example.test", 11, "c1 IN CNAME c2\nc2 IN CNAME ns1\n", &r) == ZI_FAIL);
    LOG_HAS("zone.cname.chain");
    LOG_HAS("db.import.strict");
    CHECK(nrec("example.test") == 6);
    o.strict = false;
    log_reset();
    CHECK(imp_zone(&o, "example.test", 11, "c1 IN CNAME c2\nc2 IN CNAME ns1\n", &r) == ZI_OK);          /* a warning: printed, the import goes on */
    LOG_HAS("zone.cname.chain");
    CHECK(r.warnings >= 1);
    /* a record outside the zone is dropped with a warning */
    log_reset();
    CHECK(imp_zone(&o, "example.test", 12, "a IN A 192.0.2.5\nelsewhere.example. 300 IN A 192.0.2.6\n", &r) == ZI_OK);
    LOG_HAS("zone.out-of-zone");
    CHECK(qn("SELECT count(*) FROM records WHERE name LIKE '%%elsewhere%%'") == 0);
}

/* ---- a driver that fails on demand ---- */
enum { OP_NONE = -1, OP_BEGIN, OP_BUSY, OP_COMMIT, OP_CREATE, OP_DELREC, OP_INSREC, OP_TAGS, OP_TD, OP_DELDEFS, OP_INSDEF, OP_DELMETA, OP_INSMETA, OP_VIEW,
       OP_RELOAD, OP_KEYS, OP_FIND, OP_SCAN, OP_N };
static int g_failop = OP_NONE;
static const db_driver_t *g_real;
#define FAIL_IF(op, val) do { if (g_failop == (op)) return (val); } while (0)
static int f_begin(db_conn_t *c, const char *zone) { FAIL_IF(OP_BEGIN, -1); FAIL_IF(OP_BUSY, DB_ERR_RETRY); return g_real->w_begin(c, zone); }
static int f_commit(db_conn_t *c) { FAIL_IF(OP_COMMIT, -1); return g_real->w_commit(c); }
static int f_create(db_conn_t *c, const char *n, const char *t, int64_t *id) { FAIL_IF(OP_CREATE, -1); return g_real->w_create_zone(c, n, t, id); }
static int f_delrec(db_conn_t *c, int64_t d, const int64_t *ids, size_t n) { FAIL_IF(OP_DELREC, -1); return g_real->w_delete_records(c, d, ids, n); }
static int f_insrec(db_conn_t *c, int64_t d, const db_record_row_t *r, bool a, int64_t *id) { FAIL_IF(OP_INSREC, -1); return g_real->w_insert_record(c, d, r, a, id); }
static int f_tags(db_conn_t *c, int64_t r, const char *l, const char *e) { FAIL_IF(OP_TAGS, -1); return g_real->w_insert_tags(c, r, l, e); }
static int f_td(db_conn_t *c, int64_t r, int64_t t, const char *l, bool cd) { FAIL_IF(OP_TD, -1); return g_real->w_insert_tinydns(c, r, t, l, cd); }
static int f_deldefs(db_conn_t *c, int64_t d, const char *k, const char *t) { FAIL_IF(OP_DELDEFS, -1); return g_real->w_delete_tagdefs(c, d, k, t); }
static int f_insdef(db_conn_t *c, int64_t d, const char *k, const char *t, const char *ci) { FAIL_IF(OP_INSDEF, -1); return g_real->w_insert_tagdef(c, d, k, t, ci); }
static int f_delmeta(db_conn_t *c, int64_t d, const char *k) { FAIL_IF(OP_DELMETA, -1); return g_real->w_delete_meta(c, d, k); }
static int f_insmeta(db_conn_t *c, int64_t d, const char *k, const char *v) { FAIL_IF(OP_INSMETA, -1); return g_real->w_insert_meta(c, d, k, v); }
static int f_view(db_conn_t *c, int64_t d, const char *v) { FAIL_IF(OP_VIEW, -1); return g_real->w_set_view(c, d, v); }
static int f_reload(db_conn_t *c, const char *z, bool f) { FAIL_IF(OP_RELOAD, -1); return g_real->w_request_reload(c, z, f); }
static int f_keys(db_conn_t *c, int64_t d, bool *h) { FAIL_IF(OP_KEYS, -1); return g_real->w_zone_has_keys(c, d, h); }
static int f_find(db_conn_t *c, const char *n, db_zone_cb cb, void *ud) { FAIL_IF(OP_FIND, -1); return g_real->find_zone(c, n, cb, ud); }
static int f_scan(db_conn_t *c, const int64_t *d, db_record_cb cb, void *ud) { FAIL_IF(OP_SCAN, -1); return g_real->scan_records(c, d, cb, ud); }

static db_driver_t g_fdrv;

/* what the database holds of the zones, to see that a failed import changed nothing */
static void state_of(char *out, size_t cap) {
    snprintf(out, cap, "%ld/%ld/%ld/%ld/%ld/%ld/%ld", qn("SELECT count(*) FROM domains"), qn("SELECT count(*) FROM records"), qn("SELECT count(*) FROM domainmetadata"),
             qn("SELECT count(*) FROM karidns_record_tags"), qn("SELECT count(*) FROM karidns_zone_tagdefs"), qn("SELECT count(*) FROM karidns_record_tinydns"),
             nchg());
}

static const char *K_TAGGED = "$LOCATION-TAG lan 10.0.0.0/8\n$ECS-SUBNET-TAG east 198.51.100.0/24\n$LOCATION lan\nlanhost IN A 192.0.2.50\n$LOCATION none\n";
/* a signed zone (an NSEC chain over the apex and ns1): the import writes PRESIGNED metadata */
static const char *K_SIGNED =
    "@ NSEC ns1.example.test. NS SOA RRSIG NSEC\nns1 NSEC example.test. A RRSIG NSEC\n"
    "@ RRSIG SOA 8 2 3600 20300101000000 20200101000000 12345 example.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
    "@ RRSIG NS 8 2 3600 20300101000000 20200101000000 12345 example.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
    "@ RRSIG NSEC 8 2 3600 20300101000000 20200101000000 12345 example.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
    "ns1 RRSIG A 8 3 3600 20300101000000 20200101000000 12345 example.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
    "ns1 RRSIG NSEC 8 3 3600 20300101000000 20200101000000 12345 example.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n";

static void t_write_failures(void) {
    printf("  every write step can fail: nothing is written\n");
    g_real = g_drv;
    g_fdrv = *g_drv;
    g_fdrv.w_begin = f_begin;
    g_fdrv.w_commit = f_commit;
    g_fdrv.w_create_zone = f_create;
    g_fdrv.w_delete_records = f_delrec;
    g_fdrv.w_insert_record = f_insrec;
    g_fdrv.w_insert_tags = f_tags;
    g_fdrv.w_insert_tinydns = f_td;
    g_fdrv.w_delete_tagdefs = f_deldefs;
    g_fdrv.w_insert_tagdef = f_insdef;
    g_fdrv.w_delete_meta = f_delmeta;
    g_fdrv.w_insert_meta = f_insmeta;
    g_fdrv.w_set_view = f_view;
    g_fdrv.w_request_reload = f_reload;
    g_fdrv.w_zone_has_keys = f_keys;
    g_fdrv.find_zone = f_find;
    g_fdrv.scan_records = f_scan;
    char tdpath[600];
    snprintf(tdpath, sizeof(tdpath), "%s/tdz.test.data", g_root);
    for (int op = 0; op < OP_N; op++) {
        be_fresh(true);
        zi_opts_t o = base_opts();
        zi_result_t r;
        CHECK(imp_zone(&o, "example.test", 1, K_BODY, &r) == ZI_OK);
        be_exec("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 257, true, 'key')");
        char before[200], after[200];
        state_of(before, sizeof(before));
        o.drv = &g_fdrv;
        o.serial = ZI_SERIAL_INCREMENT;
        o.view = op == OP_VIEW ? "v1" : NULL;
        o.reload = op == OP_RELOAD;
        g_failop = op;
        log_reset();
        int st;
        if (op == OP_TD) {
            zi_t *z = zi_open(&o);
            zi_input_t in = { tdpath, NULL, 0, 0 };
            st = z ? zi_import_tinydns(z, &in, "tdz.test", NULL, NULL) : -1;
            zi_close(z);
        } else if (op == OP_CREATE) {
            st = imp_zone(&o, "new.test", 1, K_BODY, &r);
        } else {
            char *t = zone_text("example.test", 5, op == OP_TAGS || op == OP_INSDEF || op == OP_DELDEFS ? K_TAGGED : op == OP_INSMETA ? K_SIGNED : "x IN A 192.0.2.9\n");
            st = imp(&o, t, NULL, &r);
            free(t);
        }
        g_failop = OP_NONE;
        state_of(after, sizeof(after));
        if (op == OP_RELOAD && g_be != BE_PG) {                      /* SQLite3: no reload request is made, the import goes on */
            CHECK_MSG(st == ZI_OK, "op %d: status %d", op, st);
            continue;
        }
        CHECK_MSG(st == (op == OP_BUSY ? ZI_BUSY : ZI_FAIL), "op %d: status %d\n%s", op, st, g_log);
        if (op == OP_BUSY) LOG_HAS("db.import.busy");
        else LOG_HAS("db.import.write");
        CHECK_MSG(strcmp(before, after) == 0, "op %d changed the database: %s -> %s", op, before, after);
    }
}

static void t_lock(void) {
    printf("  a second importer waits for the zone and gives up cleanly\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 1, K_BODY, &r) == ZI_OK);
    db_conn_t *c = NULL;
    char err[DB_ERRLEN];
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0);
    if (!c) return;
    CHECK(g_drv->w_begin(c, "example.test") == 0);          /* the first importer holds the zone */
    log_reset();
    CHECK(imp_zone(&o, "example.test", 2, K_BODY, &r) == ZI_BUSY);
    LOG_HAS("db.import.busy");
    CHECK(serial_of("example.test") == 1);
    if (g_be == BE_PG) {
        CHECK(imp_zone(&o, "other.test", 1, "", &r) == ZI_OK);          /* PostgreSQL locks the zone, not the database */
    } else {
        CHECK(imp_zone(&o, "other.test", 1, "", &r) == ZI_BUSY);        /* SQLite3 has one write lock */
    }
    CHECK(g_drv->w_rollback(c) == 0);
    CHECK(imp_zone(&o, "example.test", 2, K_BODY, &r) == ZI_OK && serial_of("example.test") == 2);
    /* the holder that commits first wins; a writer that begins afterwards sees its rows (serial 3 grows from there) */
    CHECK(g_drv->w_begin(c, "example.test") == 0);
    int64_t id;
    CHECK(g_drv->w_create_zone(c, "held.test", NULL, &id) == 0);
    CHECK(g_drv->w_commit(c) == 0);
    CHECK(imp_zone(&o, "held.test", 1, "", &r) == ZI_OK && !r.created && r.domain_id == id);
    g_drv->close(c);
    /* a connection that is closed with a transaction open writes nothing */
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0);
    CHECK(g_drv->w_begin(c, "gone.test") == 0 && g_drv->w_create_zone(c, "gone.test", NULL, &id) == 0);
    g_drv->close(c);
    CHECK(qn("SELECT count(*) FROM domains WHERE name = 'gone.test'") == 0);
}

static int g_seen, g_ok;
static void td_fn(void *ud, const zi_result_t *res, int status) {
    (void)ud;
    g_seen++;
    if (status == ZI_OK && res->committed) g_ok++;
}

static void t_tinydns_all(void) {

    printf("  tinydns data file with several zones\n");
    be_fresh(true);
    char path[600];
    snprintf(path, sizeof(path), "%s/multi.data", g_dir);
    write_file(path,
               "Za.test:ns1.a.test:hostmaster.a.test:100:3600:600:86400:300:300\n&a.test::ns1.a.test:300\n+ns1.a.test:192.0.2.1:300\n+www.a.test:192.0.2.2:300\n"
               "Zb.test:ns1.b.test:hostmaster.b.test:100:3600:600:86400:300:300\n&b.test::ns1.b.test:300\n+ns1.b.test:192.0.2.3:300\n"
               "Zsub.a.test:ns1.sub.a.test:hostmaster.a.test:100:3600:600:86400:300:300\n&sub.a.test::ns1.sub.a.test:300\n+ns1.sub.a.test:192.0.2.4:300\n+h.sub.a.test:192.0.2.5:300\n",
               0644);
    zi_opts_t o = base_opts();
    zi_t *z = zi_open(&o);
    CHECK(z != NULL);
    zi_input_t in = { path, NULL, 0, 0 };
    g_seen = g_ok = 0;
    log_reset();
    CHECK(z && zi_import_tinydns(z, &in, NULL, td_fn, NULL) == ZI_OK);
    CHECK_MSG(g_seen == 3 && g_ok == 3, "%d zones, %d committed", g_seen, g_ok);
    CHECK(qn("SELECT count(*) FROM domains") == 3);
    CHECK(qn("SELECT count(*) FROM domainmetadata WHERE kind = 'X-KARIDNS-FORMAT'") == 3);
    CHECK(nrec("a.test") == 4 && nrec("b.test") == 3 && nrec("sub.a.test") == 4);        /* the records of the child zone are not in the parent */
    /* the same file again: every zone fails the serial rule, one by one, and the others are still tried */
    g_seen = g_ok = 0;
    log_reset();
    CHECK(z && zi_import_tinydns(z, &in, NULL, td_fn, NULL) == ZI_FAIL);
    CHECK_MSG(g_seen == 3 && g_ok == 0, "%d zones, %d committed", g_seen, g_ok);
    LOG_HAS("db.import.serial");
    /* one zone of the file */
    zi_close(z);
    o.serial = ZI_SERIAL_INCREMENT;
    z = zi_open(&o);
    g_seen = g_ok = 0;
    CHECK(z && zi_import_tinydns(z, &in, "B.TEST.", td_fn, NULL) == ZI_OK && g_seen == 1 && g_ok == 1);
    CHECK(serial_of("b.test") == 101 && serial_of("a.test") == 100);
    log_reset();
    CHECK(z && zi_import_tinydns(z, &in, "c.test", td_fn, NULL) == ZI_FAIL);
    LOG_HAS("db.import.zone-name");
    CHECK(z && zi_import_tinydns(z, &in, "bad..name", td_fn, NULL) == ZI_FAIL);
    /* a data file with an error, and one that cannot be read */
    write_file(path, "Za.test:ns1.a.test:hostmaster.a.test:100:3600:600:86400:300:300\n+x.a.test:not-an-address:300\n", 0644);
    log_reset();
    CHECK(z && zi_import_tinydns(z, &in, NULL, td_fn, NULL) == ZI_FAIL);
    CHECK(z && zi_import_tinydns(z, &(zi_input_t){ "/nonexistent/x.data", NULL, 0, 0 }, NULL, td_fn, NULL) == ZI_FAIL);
    LOG_HAS("io.open");
    write_file(path, "# no SOA\n+x.a.test:192.0.2.1:300\n", 0644);
    log_reset();
    CHECK(z && zi_import_tinydns(z, &in, NULL, td_fn, NULL) == ZI_FAIL);
    zi_close(z);
}

static bool same_zone_text(const char *a, const char *b, bool tinydns, char *why, size_t whylen) {
    zone_arena_t x, y;
    char ax[DNS_NAME_TEXT_SIZE], ay[DNS_NAME_TEXT_SIZE], err[400];
    zrows_info_t info;
    bool ok1, ok2;
    if (tinydns) {
        ok1 = zrows_load_tinydns_text(a, strlen(a), NULL, 1000, NULL, NULL, 0, &x, ax, sizeof(ax), &info, err, sizeof(err));
        ok2 = zrows_load_tinydns_text(b, strlen(b), NULL, 1000, NULL, NULL, 0, &y, ay, sizeof(ay), &info, err, sizeof(err));
    } else {
        ok1 = zrows_load_zone_text(a, strlen(a), NULL, NULL, &x, ax, sizeof(ax), &info, err, sizeof(err));
        ok2 = zrows_load_zone_text(b, strlen(b), NULL, NULL, &y, ay, sizeof(ay), &info, err, sizeof(err));
    }
    bool same = false;
    if (ok1 && ok2) same = dns_zone_text_same_zone(&x, &y, why, whylen);
    else snprintf(why, whylen, "cannot parse (%s): %s", ok1 ? "export" : "original", err);
    if (ok1) zone_arena_destroy(&x);
    if (ok2) zone_arena_destroy(&y);
    return same;
}

static void t_round_trip(void) {
    printf("  round trip: file -> import -> export -> the same zone\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    char why[300];
    char *orig = zone_text("example.test", 10, "www IN A 192.0.2.80\nwww IN AAAA 2001:db8::80\nmail IN MX 10 mx\nmx IN A 192.0.2.25\nt IN TXT \"a b\" \"c\\\"d\"\n"
                           "_sip._tcp IN SRV 1 2 5060 sip\nsip IN A 192.0.2.60\nc IN CNAME www\nd IN DNAME www\nsub IN NS ns.sub\nns.sub IN A 192.0.2.70\n"
                           "*.wild IN A 192.0.2.71\n\\032sp IN A 192.0.2.72\nl IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m\n");
    CHECK(imp(&o, orig, NULL, &r) == ZI_OK);
    char *out = do_export("example.test", NULL, NULL);
    CHECK(out != NULL);
    if (out) {
        CHECK_MSG(same_zone_text(orig, out, false, why, sizeof(why)), "%s\n%s", why, out);
        CHECK_HAS(out, "$ORIGIN example.test.");
        /* the second round gives the same file */
        o.serial = ZI_SERIAL_KEEP;
        CHECK(imp(&o, out, NULL, &r) == ZI_OK);
        char *out2 = do_export("example.test", NULL, NULL);
        CHECK(out2 && strcmp(out, out2) == 0);
        free(out2);
    }
    free(out);
    free(orig);
    /* the zone with tags */
    char path[600];
    snprintf(path, sizeof(path), "%s/tagz.test.zone", g_root);
    char *tz = slurp(path);
    CHECK(tz != NULL);
    if (tz) {
        o.serial = ZI_SERIAL_GROW;
        CHECK(imp(&o, tz, NULL, &r) == ZI_OK);
        out = do_export("tagz.test.", NULL, NULL);
        CHECK(out != NULL);
        if (out) CHECK_MSG(same_zone_text(tz, out, false, why, sizeof(why)), "%s", why);
        free(out);
        free(tz);
    }
    /* tinydns */
    snprintf(path, sizeof(path), "%s/tdz.test.data", g_root);
    char *td = slurp(path);
    CHECK(td != NULL);
    if (td) {
        zi_t *z = zi_open(&o);
        zi_input_t in = { NULL, td, strlen(td), 1000 };
        CHECK(z && zi_import_tinydns(z, &in, "tdz.test", NULL, NULL) == ZI_OK);
        zi_close(z);
        out = do_export("tdz.test", NULL, NULL);
        CHECK(out != NULL);
        if (out) {
            CHECK_MSG(same_zone_text(td, out, true, why, sizeof(why)), "%s\n%s", why, out);
            CHECK(strstr(out, "$ORIGIN") == NULL);
        }
        free(out);
        dzt_opts_t bind = { DZT_BIND, false };
        out = do_export("tdz.test", NULL, &bind);                  /* BIND cannot hold the time stamps and locations */
        CHECK(out == NULL);
        LOG_HAS("db.export.write");
        free(td);
    }
    /* a signed zone: the NSEC chain is not stored, the reader rebuilds it, the file is the same zone */
    be_fresh(true);
    static const char sig[] =
        "$ORIGIN sig.test.\n$TTL 300\n"
        "@ SOA ns1 hostmaster 100 3600 600 86400 300\n@ NS ns1\nns1 A 192.0.2.53\nwww A 192.0.2.80\n"
        "@ NSEC ns1.sig.test. NS SOA RRSIG NSEC\nns1 NSEC www.sig.test. A RRSIG NSEC\nwww NSEC sig.test. A RRSIG NSEC\n"
        "@ RRSIG SOA 8 2 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "@ RRSIG NS 8 2 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "@ RRSIG NSEC 8 2 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "ns1 RRSIG A 8 3 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "ns1 RRSIG NSEC 8 3 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "www RRSIG A 8 3 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "www RRSIG NSEC 8 3 300 20300101000000 20200101000000 12345 sig.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n";
    o.serial = ZI_SERIAL_GROW;
    log_reset();
    CHECK_MSG(imp(&o, sig, NULL, &r) == ZI_OK, "%s", g_log);
    CHECK(qn("SELECT count(*) FROM domainmetadata WHERE kind = 'PRESIGNED' AND content = '1'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'NSEC'") == 0);              /* the PowerDNS layout: no NSEC rows */
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") == 7);
    out = do_export("sig.test", NULL, NULL);
    CHECK(out != NULL);
    if (out) {
        CHECK_MSG(same_zone_text(sig, out, false, why, sizeof(why)), "%s\n%s", why, out);
        CHECK_HAS(out, " NSEC ");
    }
    free(out);
    /* unsigned data replaces a signed zone: PRESIGNED goes (and with cryptokeys, the loader would refuse it: a warning) */
    be_exec("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ((SELECT id FROM domains WHERE name = 'sig.test'), 257, true, 'secret')");
    log_reset();
    CHECK(imp_zone(&o, "sig.test", 101, "www IN A 192.0.2.1\n", &r) == ZI_OK);
    LOG_HAS("db.import.keys");
    CHECK(qn("SELECT count(*) FROM domainmetadata WHERE kind = 'PRESIGNED'") == 0);
    /* a zone with keys and no PRESIGNED is not served: the exporter says so */
    log_reset();
    CHECK(do_export("sig.test", NULL, NULL) == NULL);
    LOG_HAS("db.export.zone");
    CHECK_HAS(g_log, "cryptokeys");
}

static void t_inputs(void) {
    printf("  input: files, $INCLUDE, standard input, errors\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    char path[600], inc[600];
    snprintf(path, sizeof(path), "%s/main.zone", g_dir);
    snprintf(inc, sizeof(inc), "%s/more.inc", g_dir);
    write_file(inc, "inc IN A 192.0.2.44\n", 0644);
    write_file(path, "$ORIGIN inc.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n$INCLUDE more.inc\n", 0644);
    zi_t *z = zi_open(&o);
    CHECK(z != NULL);
    zi_input_t in = { path, NULL, 0, 0 };
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'inc.inc.test'") == 1);
    /* standard input: the text of a file on file descriptor 0; $INCLUDE is refused */
    write_file(path, "$ORIGIN stdin.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n", 0644);
    int saved = dup(0), fd = open(path, O_RDONLY);
    dup2(fd, 0);
    close(fd);
    in.path = "-";
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_OK && strcmp(r.zone, "stdin.test") == 0);
    write_file(path, "$ORIGIN stdin2.test.\n$INCLUDE more.inc\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n", 0644);
    fd = open(path, O_RDONLY);
    dup2(fd, 0);
    close(fd);
    log_reset();
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_FAIL);
    LOG_HAS("zone.include-stdin");
    fd = open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    close(fd);
    log_reset();
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_FAIL);          /* empty standard input: no SOA */
    LOG_HAS("zone.syntax");
    close(0);
    log_reset();
    CHECK(z && zi_import_zone(z, &in, NULL, &r) == ZI_FAIL);          /* a closed standard input cannot be read */
    LOG_HAS("io.stdin.read");
    dup2(saved, 0);
    close(saved);
    /* a memory text with a name in the messages; a text with a NUL byte; nothing to read; a directory; a missing file */
    zi_input_t mem = { "mem.zone", "x", 1, 0 };
    log_reset();
    CHECK(z && zi_import_zone(z, &mem, NULL, &r) == ZI_FAIL);
    mem = (zi_input_t){ NULL, "ab\0cd", 5, 0 };
    log_reset();
    CHECK(z && zi_import_zone(z, &mem, NULL, &r) == ZI_FAIL);
    CHECK_HAS(g_log, "NUL byte");
    log_reset();
    CHECK(z && zi_import_zone(z, &(zi_input_t){ NULL, NULL, 0, 0 }, NULL, &r) == ZI_FAIL);
    LOG_HAS("usage.args");
    log_reset();
    CHECK(z && zi_import_zone(z, &(zi_input_t){ g_dir, NULL, 0, 0 }, NULL, &r) == ZI_FAIL);
    LOG_HAS("io.not-regular");
    log_reset();
    CHECK(z && zi_import_zone(z, &(zi_input_t){ "/nonexistent/x.zone", NULL, 0, 0 }, NULL, NULL) == ZI_FAIL);
    LOG_HAS("io.open");
    zi_close(z);
}

static void t_options(void) {
    printf("  options, the file zone warning, keys\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    log_reset();
    o.zone_type = "bogus";
    CHECK(zi_open(&o) == NULL);
    LOG_HAS("db.import.option");
    o.zone_type = NULL;
    o.view = "has a blank";
    CHECK(zi_open(&o) == NULL);
    o.view = "";
    CHECK(zi_open(&o) == NULL);
    o.view = NULL;
    db_driver_t nodrv = *g_drv;
    nodrv.open_write = NULL;
    o.drv = &nodrv;
    log_reset();
    CHECK(zi_open(&o) == NULL);
    LOG_HAS("db.import.open");
    o.drv = g_drv;
    /* a database that cannot be opened / has no PowerDNS tables */
    zi_opts_t bad = o;
    if (g_be == BE_SQLITE) bad.src.database_file = "/nonexistent/dir/x.db";
    else bad.src.conninfo_file = "/nonexistent/conninfo";
    log_reset();
    CHECK(zi_open(&bad) == NULL);
    LOG_HAS("db.import.open");
    if (g_be == BE_SQLITE) {
        char p[600];
        snprintf(p, sizeof(p), "%s/empty.db", g_dir);
        sqlite3 *db = NULL;
        CHECK(sqlite3_open_v2(p, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK);
        sqlite3_exec(db, "PRAGMA journal_mode=WAL; CREATE TABLE t (x)", NULL, NULL, NULL);
        sqlite3_close(db);
        bad.src.database_file = p;
        log_reset();
        CHECK(zi_open(&bad) == NULL);
        LOG_HAS("db.import.schema");
    }
    /* the file zone warning (D-PRIO), the import goes on */
    static const char *const fz[] = { "other.test.", "EXAMPLE.test" };
    o.file_zones = fz;
    o.nfile_zones = 2;
    log_reset();
    CHECK(imp_zone(&o, "example.test", 1, K_BODY, &r) == ZI_OK);
    LOG_HAS("db.import.file-zone");
    CHECK_HAS(g_log, "serves the file zone");
    o.nfile_zones = 0;
    /* an existing zone with cryptokeys, replaced with unsigned data: a warning; a merge does not warn */
    be_exec("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 257, true, 'k')");
    log_reset();
    CHECK(imp_zone(&o, "example.test", 2, K_BODY, &r) == ZI_OK);
    LOG_HAS("db.import.keys");
    o.mode = ZI_MERGE;
    log_reset();
    CHECK(imp_zone(&o, "example.test", 3, "", &r) == ZI_OK);
    LOG_HAS_NOT("db.import.keys");
    /* more than one zone row of one name (a data error): refused */
    if (g_be == BE_SQLITE) {
        be_exec("INSERT INTO domains (name, type) VALUES ('dup.test', 'NATIVE')");
        sqlite3_exec(g_sq, "DROP INDEX name_index", NULL, NULL, NULL);
        be_exec("INSERT INTO domains (name, type) VALUES ('DUP.test', 'NATIVE')");
        o.mode = ZI_REPLACE;
        log_reset();
        CHECK(imp_zone(&o, "dup.test", 1, "", &r) == ZI_FAIL);
        CHECK_HAS(g_log, "More than one domains row");
        CHECK(do_export("dup.test", NULL, NULL) == NULL);
        CHECK_HAS(g_log, "More than one domains row");
    }
    /* without the extension tables: a plain zone imports, one with tags or a view does not */
    be_fresh(false);
    o.src = g_src;
    o.mode = ZI_REPLACE;
    o.reload = false;
    log_reset();
    CHECK(imp_zone(&o, "plain.test", 1, K_BODY, &r) == ZI_OK);
    CHECK(imp_zone(&o, "plain.test", 2, K_BODY, &r) == ZI_OK);
    CHECK(imp_zone(&o, "plain.test", 3, K_TAGGED, &r) == ZI_FAIL);
    LOG_HAS("db.import.schema");
    CHECK(nrec("plain.test") == 6);
    o.view = "v1";
    log_reset();
    CHECK(zi_open(&o) == NULL);
    LOG_HAS("db.import.schema");
    CHECK(do_export("plain.test", "v1", NULL) != NULL);              /* no views in the database: every zone is in every view */
}

static int g_stops;
static int stop_cb(void *ud, const char *name) {
    (void)ud;
    (void)name;
    return ++g_stops >= 1;                                      /* stops after the first */
}

static void t_export(void) {
    printf("  exporter: zone types, errors\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 1, K_BODY, &r) == ZI_OK);
    log_reset();
    CHECK(do_export("nothere.test", NULL, NULL) == NULL);
    LOG_HAS("db.export.not-found");
    be_exec("UPDATE domains SET type = 'SLAVE', master = '192.0.2.1' WHERE name = 'example.test'");
    log_reset();
    CHECK(do_export("example.test", NULL, NULL) == NULL);
    LOG_HAS("db.export.zone-type");
    be_exec("UPDATE domains SET type = 'MASTER' WHERE name = 'example.test'");
    char *a = do_export("EXAMPLE.test.", NULL, NULL);
    CHECK(a != NULL);
    free(a);
    /* a row the reader refuses */
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 'bad.example.test', 'A', 'not-an-address', 60)");
    log_reset();
    CHECK(do_export("example.test", NULL, NULL) == NULL);
    LOG_HAS("db.export.zone");
    /* a NULL ttl: the reader's warning is passed on */
    be_exec("DELETE FROM records WHERE name = 'bad.example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 'nottl.example.test', 'A', '192.0.2.77', NULL)");
    log_reset();
    a = do_export("example.test", NULL, NULL);
    CHECK(a != NULL);
    free(a);
    LOG_HAS("db.export.warning");
    /* the list of zones leaves out the zones that are not primary */
    be_exec("INSERT INTO domains (name, type, master) VALUES ('sl.test', 'SLAVE', '192.0.2.1')");
    zx_t *x = zx_open(g_drv, &g_src, &(zmsg_t){ msg_cb, NULL });
    CHECK(x != NULL);
    g_stops = 0;
    CHECK(x && zx_list_zones(x, NULL, stop_cb, NULL) == 0 && g_stops == 1);
    zx_close(x);
    /* an open that fails */
    log_reset();
    if (g_be == BE_SQLITE) {
        char p[600];
        db_source_t src = { "sqlite3", "/nonexistent/dir/x.db", NULL, NULL, 100 };
        CHECK(zx_open(g_drv, &src, &(zmsg_t){ msg_cb, NULL }) == NULL);
        snprintf(p, sizeof(p), "%s/empty.db", g_dir);
        src.database_file = p;
        CHECK(zx_open(g_drv, &src, &(zmsg_t){ msg_cb, NULL }) == NULL);
    } else {
        db_source_t src = { "postgresql", NULL, "/nonexistent/conninfo", NULL, 0 };
        CHECK(zx_open(g_drv, &src, &(zmsg_t){ msg_cb, NULL }) == NULL);
    }
    LOG_HAS("db.export.open");
    /* dns_diag: the messages with no zmsg_t go to dns_diag (JSON mode keeps them) */
    dns_diag_json_start("zone", "test");
    zi_opts_t d = base_opts();
    d.msg.fn = NULL;
    CHECK(imp(&d, "$ORIGIN x.test.\nwww A 192.0.2.1\n", "x.test", &r) == ZI_FAIL);          /* no SOA: the checks fail, through dns_diag */
    zx_t *x2 = zx_open(g_drv, &g_src, NULL);
    CHECK(x2 != NULL);
    if (x2) {
        CHECK(zx_export_zone(x2, "nothere.test", NULL, NULL, sb_sink, &(sbuf_t){0}) != 0);
        zx_close(x2);
    }
    zi_t *dz = zi_open(&d);
    CHECK(dz != NULL);
    if (dz) {
        zi_input_t m = { NULL, "$ORIGIN x.test.\n@ SOA a b 1 2 3 4 5\n", 36, 0 };
        CHECK(zi_import_zone(dz, &m, NULL, &r) == ZI_FAIL);
        zi_close(dz);
    }
    zmsg_emit(NULL, ZMSG_DETAIL, DC_NONE, NULL, "a continuation line of the message before");        /* dns_diag_detail() */
    char *jbuf = NULL;
    size_t jlen = 0;
    FILE *jf = open_memstream(&jbuf, &jlen);
    CHECK(jf != NULL);
    if (jf) {
        dns_diag_json_finish(jf, 1);
        fclose(jf);
        CHECK_HAS(jbuf, "db.export.not-found");
        CHECK_HAS(jbuf, "zone.");
        free(jbuf);
    }
    dns_diag_json_reset();
}

static int count_rec_cb(void *ud, int64_t did, const db_record_row_t *r) {
    (void)did;
    (void)r;
    (*(int *)ud)++;
    return 0;
}

/* the driver's write functions, called directly */
static void t_driver(void) {
    printf("  driver write functions\n");
    be_fresh(true);
    db_conn_t *c = NULL, *ro = NULL;
    char err[DB_ERRLEN];
    db_schema_info_t si;
    CHECK(g_drv->open(&ro, &g_src, err, sizeof(err)) == 0);
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0);
    if (!c || !ro) return;
    CHECK(g_drv->check_schema(c, &si) == 0 && si.has_ext && si.has_domain_views);
    CHECK(g_drv->check_schema(ro, &si) == 0);
    /* a read only connection refuses every write function */
    int64_t id = 0;
    CHECK(g_drv->w_begin(ro, "x.test") == -1);
    CHECK_HAS(g_drv->errmsg(ro), "read only");
    CHECK(g_drv->w_commit(ro) == -1 && g_drv->w_rollback(ro) == 0);
    CHECK(g_drv->w_create_zone(ro, "x.test", NULL, &id) == -1);
    /* and so does a writable one outside a transaction */
    db_record_row_t row = { 0, 300, 10, false, false, false, "a.x.test", "MX", "mx.x.test", NULL };
    bool has = false;
    CHECK(g_drv->w_create_zone(c, "x.test", NULL, &id) == -1);
    CHECK_HAS(g_drv->errmsg(c), "no write transaction");
    CHECK(g_drv->w_delete_records(c, 1, NULL, 0) == -1 && g_drv->w_insert_record(c, 1, &row, true, &id) == -1 && g_drv->w_insert_tags(c, 1, "a", NULL) == -1);
    CHECK(g_drv->w_insert_tinydns(c, 1, 1, NULL, false) == -1 && g_drv->w_delete_tagdefs(c, 1, NULL, NULL) == -1 && g_drv->w_insert_tagdef(c, 1, "ecs", "t", "10.0.0.0/8") == -1);
    CHECK(g_drv->w_delete_meta(c, 1, "K") == -1 && g_drv->w_insert_meta(c, 1, "K", "v") == -1 && g_drv->w_set_view(c, 1, "v") == -1);
    int rr = g_drv->w_request_reload(c, NULL, false);
    CHECK(rr == -1 || rr == DB_ERR_UNAVAILABLE);
    CHECK(g_drv->w_zone_has_keys(c, 1, &has) == -1 && g_drv->w_commit(c) == -1 && g_drv->w_rollback(c) == 0);
    /* a transaction: create, insert, tags, definitions, metadata, view, keys */
    CHECK(g_drv->w_begin(c, "x.test") == 0);
    CHECK(g_drv->w_begin(c, "x.test") == -1);                         /* already open */
    CHECK_HAS(g_drv->errmsg(c), "already open");
    int64_t did = 0, rid = 0, rid2 = 0;
    CHECK(g_drv->w_create_zone(c, "x.test", "MASTER", &did) == 0 && did > 0);
    CHECK(g_drv->w_insert_record(c, did, &row, false, &rid) == 0 && rid > 0);
    db_record_row_t ent = { 0, 0, 0, true, true, false, "e.x.test", NULL, NULL, "ordername1" };
    CHECK(g_drv->w_insert_record(c, did, &ent, true, &rid2) == 0 && rid2 != rid);
    CHECK(g_drv->w_insert_tags(c, rid, "lan", "east") == 0 && g_drv->w_insert_tags(c, rid2, NULL, "west") == 0);
    CHECK(g_drv->w_insert_tinydns(c, rid, 1000, "l2", true) == 0);
    CHECK(g_drv->w_insert_tagdef(c, did, "location", "lan", "10.0.0.0/8") == 0 && g_drv->w_insert_tagdef(c, did, "ecs", "east", "198.51.100.0/24") == 0);
    CHECK(g_drv->w_insert_meta(c, did, "PRESIGNED", "1") == 0 && g_drv->w_insert_meta(c, did, "Other", "x") == 0);
    CHECK(g_drv->w_set_view(c, did, "v1") == 0 && g_drv->w_set_view(c, did, "v1") == 0);
    CHECK(g_drv->w_zone_has_keys(c, did, &has) == 0 && !has);
    /* the reads of the zone inside the transaction see the writes */
    int cnt = 0;
    CHECK(g_drv->scan_records(c, &did, count_rec_cb, &cnt) == 0 && cnt == 2);
    CHECK(g_drv->w_commit(c) == 0);
    CHECK(qn("SELECT count(*) FROM records") == 2 && qn("SELECT prio FROM records WHERE type = 'MX'") == 10);
    CHECK(qn("SELECT count(*) FROM records WHERE type IS NULL AND ordername = 'ordername1' AND ttl IS NULL AND prio IS NULL AND CAST(auth AS integer) = 1") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'MX' AND CAST(auth AS integer) = 0") == 1);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags") == 2 && qn("SELECT count(*) FROM karidns_record_tinydns WHERE CAST(countdown AS integer) = 1") == 1);
    CHECK(qn("SELECT count(*) FROM karidns_domain_views") == 1 && qn("SELECT count(*) FROM karidns_changes") > 0);
    /* deletes: by id (an id of another zone deletes nothing), the tag rows go with the records; definitions by kind and tag; metadata by kind.
     * Each step is committed: the test's own connection reads committed rows only. */
    CHECK(g_drv->w_begin(c, "y.test") == 0);
    int64_t did2 = 0, rid3 = 0;
    CHECK(g_drv->w_create_zone(c, "y.test", NULL, &did2) == 0 && g_drv->w_insert_record(c, did2, &row, true, &rid3) == 0 && g_drv->w_commit(c) == 0);
    CHECK(g_drv->w_begin(c, "x.test") == 0);
    int64_t both[2] = { rid, rid3 };
    CHECK(g_drv->w_delete_records(c, did, both, 2) == 0 && g_drv->w_commit(c) == 0);
    CHECK_MSG(qn("SELECT count(*) FROM records") == 2, "%ld records", qn("SELECT count(*) FROM records"));       /* rid of x.test is gone, rid3 of y.test stays: ent and y */
    CHECK(qn("SELECT count(*) FROM records WHERE id = %ld", (long)rid3) == 1);
    CHECK(qn("SELECT count(*) FROM karidns_record_tags") == 1 && qn("SELECT count(*) FROM karidns_record_tinydns") == 0);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_delete_records(c, did, NULL, 0) == 0 && g_drv->w_commit(c) == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE domain_id = %ld", (long)did) == 0 && qn("SELECT count(*) FROM records") == 1 && qn("SELECT count(*) FROM karidns_record_tags") == 0);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_delete_tagdefs(c, did, "location", "LAN") == 0 && g_drv->w_commit(c) == 0);
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs") == 1);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_delete_tagdefs(c, did, NULL, NULL) == 0 && g_drv->w_commit(c) == 0);
    CHECK(qn("SELECT count(*) FROM karidns_zone_tagdefs") == 0);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_delete_meta(c, did, "presigned") == 0 && g_drv->w_zone_has_keys(c, did, &has) == 0 && !has && g_drv->w_commit(c) == 0);
    CHECK(qn("SELECT count(*) FROM domainmetadata") == 1);
    /* a rolled back transaction leaves nothing */
    CHECK(g_drv->w_begin(c, "z.test") == 0);
    CHECK(g_drv->w_create_zone(c, "z.test", NULL, &did2) == 0 && g_drv->w_insert_meta(c, did2, "K", "v") == 0 && g_drv->w_delete_meta(c, did, "Other") == 0);
    CHECK(g_drv->w_rollback(c) == 0 && g_drv->w_rollback(c) == 0);
    CHECK(qn("SELECT count(*) FROM domains") == 2 && qn("SELECT count(*) FROM domainmetadata") == 1);
    /* a statement that fails; the transaction is rolled back; the connection is usable again */
    CHECK(g_drv->w_begin(c, "x.test") == 0);
    CHECK(g_drv->w_create_zone(c, "x.test", NULL, &did) != 0);          /* the name exists */
    CHECK(g_drv->errmsg(c)[0] != '\0');
    CHECK(g_drv->w_rollback(c) == 0);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_commit(c) == 0);
    /* the extension tables are missing */
    g_drv->close(c);
    g_drv->close(ro);
    c = NULL;
    be_fresh(false);
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0 && g_drv->check_schema(c, &si) == 0 && !si.has_ext && !si.has_domain_views);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_create_zone(c, "x.test", NULL, &did) == 0 && g_drv->w_insert_record(c, did, &row, true, &rid) == 0);
    CHECK(g_drv->w_insert_tags(c, rid, "a", NULL) == DB_ERR_UNAVAILABLE && g_drv->w_insert_tinydns(c, rid, 1, NULL, false) == DB_ERR_UNAVAILABLE);
    CHECK(g_drv->w_delete_tagdefs(c, did, NULL, NULL) == DB_ERR_UNAVAILABLE && g_drv->w_insert_tagdef(c, did, "ecs", "t", "10.0.0.0/8") == DB_ERR_UNAVAILABLE);
    CHECK(g_drv->w_set_view(c, did, "v") == DB_ERR_UNAVAILABLE && g_drv->w_request_reload(c, "x.test", false) == DB_ERR_UNAVAILABLE);
    CHECK(g_drv->w_delete_records(c, did, NULL, 0) == 0);                   /* without extension rows to delete */
    int64_t one = rid;
    CHECK(g_drv->w_delete_records(c, did, &one, 1) == 0);
    CHECK(g_drv->w_commit(c) == 0);
    g_drv->close(c);
}

#ifdef KARIDNS_DB_POSTGRESQL
/* PostgreSQL only: the role file, the lock of a zone only, reload requests with the table */
static void t_pg_role(void) {
    printf("  PostgreSQL: the writer role (db/karidns_writer_role.pgsql.sql)\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 1, K_BODY, &r) == ZI_OK);
    be_exec("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES ((SELECT id FROM domains WHERE name = 'example.test'), 257, true, 'secret')");
    be_exec("DROP ROLE IF EXISTS karidns_writer_t");
    PGresult *cr = PQexec(g_pg, "CREATE ROLE karidns_writer_t LOGIN");
    bool made = cr && PQresultStatus(cr) == PGRES_COMMAND_OK;
    PQclear(cr);
    if (!made) {
        printf("  [note] SKIP: the PostgreSQL role may not create roles\n");
        return;
    }
    char cmd[2400];
    snprintf(cmd, sizeof(cmd), "psql -X -q -v ON_ERROR_STOP=1 -v role=karidns_writer_t -v schema=public -f %s/../../db/karidns_writer_role.pgsql.sql "
                               "\"%s dbname=%s\" >%s/role.out 2>&1", g_root, g_maint, g_pgdb, g_dir);
    if (system(cmd) != 0) {
        printf("  [note] SKIP: psql is not available or cannot run the role script (see %s/role.out)\n", g_dir);
        be_exec("DROP ROLE karidns_writer_t");
        return;
    }
    int again = system(cmd);                                          /* the script can be run again */
    CHECK(again == 0);
    /* the importer as the writer role */
    char ci[1500];
    snprintf(ci, sizeof(ci), "%s user=karidns_writer_t dbname=%s\n", g_maint, g_pgdb);
    char wci[500];
    snprintf(wci, sizeof(wci), "%s/writer.ci", g_dir);
    write_file(wci, ci, 0600);
    zi_opts_t w = base_opts();
    w.src.conninfo_file = wci;
    w.view = "vw";
    w.reload = true;
    log_reset();
    zi_t *z = zi_open(&w);
    if (!z) {
        printf("  [note] SKIP: the role cannot log in (%s)\n", g_log);
        be_exec("DROP OWNED BY karidns_writer_t");
        be_exec("DROP ROLE karidns_writer_t");
        return;
    }
    zi_close(z);
    char *tz;
    char path[600];
    snprintf(path, sizeof(path), "%s/tagz.test.zone", g_root);
    tz = slurp(path);
    w.serial = ZI_SERIAL_INCREMENT;
    CHECK_MSG(imp(&w, tz, NULL, &r) == ZI_OK && r.created, "%s", g_log);             /* records, tags, definitions, the view, a reload request */
    free(tz);
    CHECK_MSG(imp_zone(&w, "example.test", 1, "new IN A 192.0.2.9\n", &r) == ZI_OK, "%s", g_log);          /* replace a zone that has cryptokeys */
    LOG_HAS("db.import.keys");
    CHECK(qn("SELECT count(*) FROM karidns_reload_requests") == 2 && qn("SELECT count(*) FROM karidns_domain_views") == 2);
    CHECK(qn("SELECT count(*) FROM karidns_changes") > 10);
    /* and it cannot read the private keys */
    PGconn *wc = PQconnectdb(ci);
    CHECK(PQstatus(wc) == CONNECTION_OK);
    PGresult *q = PQexec(wc, "SELECT content FROM cryptokeys");
    CHECK(q && PQresultStatus(q) == PGRES_FATAL_ERROR);
    CHECK_HAS(PQresultErrorMessage(q), "permission denied");
    PQclear(q);
    q = PQexec(wc, "SELECT domain_id FROM cryptokeys");
    CHECK(q && PQresultStatus(q) == PGRES_TUPLES_OK);
    PQclear(q);
    q = PQexec(wc, "SELECT * FROM cryptokeys");
    CHECK(q && PQresultStatus(q) == PGRES_FATAL_ERROR);
    PQclear(q);
    q = PQexec(wc, "UPDATE cryptokeys SET active = false");
    CHECK(q && PQresultStatus(q) == PGRES_FATAL_ERROR);
    PQclear(q);
    q = PQexec(wc, "CREATE TABLE t_nope (x int)");
    CHECK(q && PQresultStatus(q) == PGRES_FATAL_ERROR);
    PQclear(q);
    PQfinish(wc);
    be_exec("DROP OWNED BY karidns_writer_t");
    be_exec("DROP ROLE karidns_writer_t");
}

static void t_pg_session(void) {
    printf("  PostgreSQL: the write session\n");
    be_fresh(true);
    db_conn_t *c = NULL, *r = NULL;
    char err[DB_ERRLEN];
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0 && g_drv->open(&r, &g_src, err, sizeof(err)) == 0);
    if (!c || !r) return;
    CHECK(qn("SELECT count(*) FROM pg_stat_activity WHERE application_name = 'karidns-zone' AND datname = current_database()") == 1);
    CHECK(qn("SELECT count(*) FROM pg_stat_activity WHERE application_name = 'karidns-dbloader' AND datname = current_database()") == 1);
    int64_t id;
    CHECK(g_drv->w_begin(r, "x.test") == -1);           /* the loader's connection stays read only: it never writes */
    /* a statement error inside the transaction: w_rollback ends it */
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_create_zone(c, "y.test", NULL, &id) == 0 && g_drv->w_create_zone(c, "y.test", NULL, &id) != 0);
    CHECK(g_drv->w_rollback(c) == 0);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_commit(c) == 0);
    /* more than one chunk of ids */
    int64_t did;
    db_record_row_t row = { 0, 300, 0, false, true, false, "a.x.test", "A", "192.0.2.1", NULL };
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_create_zone(c, "x.test", NULL, &did) == 0);
    int64_t *ids = malloc(2500 * sizeof(*ids));
    for (int i = 0; i < 2500; i++) CHECK(g_drv->w_insert_record(c, did, &row, true, &ids[i]) == 0);
    CHECK(g_drv->w_delete_records(c, did, ids, 2500) == 0);
    CHECK(qn("SELECT count(*) FROM records") == 0);
    free(ids);
    CHECK(g_drv->w_commit(c) == 0);
    g_drv->close(c);
    g_drv->close(r);
}
#endif

/* Post-write verification and the rules of the server (limits, check-* options): what the loader would refuse is not written. */
static void t_verify(void) {
    printf("  read-back verification, limits, check-* options\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, &r) == ZI_OK);
    long n0 = nrec("example.test"), c0 = nchg();

    /* a merge that puts a CNAME beside an A record: the file alone is fine, the zone as written is not */
    o.mode = ZI_MERGE;
    log_reset();
    CHECK(imp(&o, "$ORIGIN example.test.\n$TTL 300\nwww IN CNAME mx\n", "example.test", &r) == ZI_FAIL);
    LOG_HAS("zone.cname.coexists");
    LOG_HAS("db.import.verify");
    CHECK_HAS(g_log, "nothing was written");
    CHECK(nrec("example.test") == n0 && nchg() == c0 && qn("SELECT count(*) FROM records WHERE type = 'CNAME'") == 0);
    CHECK(!r.committed);
    /* a dry run reads back too */
    o.dry_run = true;
    log_reset();
    CHECK(imp(&o, "$ORIGIN example.test.\n$TTL 300\nwww IN CNAME mx\n", "example.test", &r) == ZI_FAIL);
    LOG_HAS("db.import.verify");
    o.dry_run = false;
    /* ... and the same merge of a name that has no other data goes through */
    CHECK(imp(&o, "$ORIGIN example.test.\n$TTL 300\nfresh IN CNAME mx\n", "example.test", &r) == ZI_OK && r.committed);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'CNAME'") == 1);

    /* an ALIAS beside an A record (PowerDNS ALIAS, TYPE65401): the loader's reader refuses the zone */
    n0 = nrec("example.test");
    log_reset();
    CHECK(imp(&o, "$ORIGIN example.test.\n$TTL 300\nwww IN ALIAS target.example.net.\n", "example.test", &r) == ZI_FAIL);
    LOG_HAS("db.import.verify");
    CHECK_HAS(g_log, "ALIAS");
    CHECK(nrec("example.test") == n0 && qn("SELECT count(*) FROM records WHERE type = 'ALIAS'") == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A'") == 1);

    /* the reader's own limits (max-zone-records of the database block) */
    zi_opts_t lo = base_opts();
    lo.reader.max_records = 3;
    log_reset();
    CHECK(imp_zone(&lo, "tiny.test", 1, K_BODY, &r) == ZI_FAIL);
    LOG_HAS("db.import.verify");
    CHECK(qn("SELECT count(*) FROM domains WHERE name = 'tiny.test'") == 0);

    /* the size limits of the configuration: max-records, max-records-per-type, max-types-per-name, max-zone-ttl */
    zi_opts_t li = base_opts();
    li.limits.max_records = 4;
    log_reset();
    CHECK(imp_zone(&li, "lim.test", 1, K_BODY, &r) == ZI_FAIL);
    LOG_HAS("zone.limits");
    CHECK(qn("SELECT count(*) FROM domains WHERE name = 'lim.test'") == 0);
    li.limits.max_records = 0;
    li.limits.max_per_type = 1;
    log_reset();
    CHECK(imp_zone(&li, "lim.test", 1, "www IN A 192.0.2.80\nwww IN A 192.0.2.81\n", &r) == ZI_FAIL);
    LOG_HAS("zone.limits");
    li.limits.max_per_type = 0;
    li.limits.max_types_per_name = 1;
    log_reset();
    CHECK(imp_zone(&li, "lim.test", 1, K_BODY, &r) == ZI_FAIL);            /* the apex has SOA and NS */
    LOG_HAS("zone.limits");
    li.limits.max_types_per_name = 0;
    li.limits.max_zone_ttl = 100;
    log_reset();
    CHECK(imp_zone(&li, "lim.test", 1, K_BODY, &r) == ZI_FAIL);            /* $TTL 3600 */
    LOG_HAS("zone.limits");
    li.limits.max_zone_ttl = 3600;
    li.limits.max_records = 100;
    li.limits.max_per_type = 5;
    li.limits.max_types_per_name = 5;
    CHECK(imp_zone(&li, "lim.test", 1, K_BODY, &r) == ZI_OK && r.created);
    /* a merge that takes an existing zone over a limit is refused too */
    li.mode = ZI_MERGE;
    li.limits.max_records = 6;
    log_reset();
    CHECK(imp(&li, "$ORIGIN lim.test.\n$TTL 300\nb IN A 192.0.2.3\nc IN A 192.0.2.4\n", "lim.test", &r) == ZI_FAIL);
    LOG_HAS("zone.limits");
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'b.lim.test'") == 0);

    /* the check-* options: check-mx fail is an error where it is only a warning by default */
    uint8_t chk[ZC_N];
    for (int i = 0; i < ZC_N; i++) chk[i] = CHK_DEFAULT;
    zi_opts_t po = base_opts();
    log_reset();
    CHECK(imp_zone(&po, "mx.test", 1, "m IN MX 10 192.0.2.25.\n", &r) == ZI_OK);        /* default severity: nothing */
    chk[ZC_MX] = CHK_FAIL;
    po.chk = chk;
    log_reset();
    CHECK(imp_zone(&po, "mx2.test", 1, "m IN MX 10 192.0.2.25.\n", &r) == ZI_FAIL);
    LOG_HAS("zone.mx.address");
    LOG_HAS("db.import.checks");
    CHECK(qn("SELECT count(*) FROM domains WHERE name = 'mx2.test'") == 0);
    /* the zone as written is judged by the same options: the stored MX address fails a merge of something else */
    po.mode = ZI_MERGE;
    log_reset();
    CHECK(imp(&po, "$ORIGIN mx.test.\n$TTL 300\nx IN A 192.0.2.3\n", "mx.test", &r) == ZI_FAIL);
    LOG_HAS("zone.mx.address");
    LOG_HAS("db.import.verify");
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'x.mx.test'") == 0);
    /* as a warning: shown for a merge (the file did not contain it), counted, and fatal in strict mode */
    chk[ZC_MX] = CHK_WARN;
    log_reset();
    CHECK(imp(&po, "$ORIGIN mx.test.\n$TTL 300\nx IN A 192.0.2.3\n", "mx.test", &r) == ZI_OK && r.warnings >= 1);
    LOG_HAS("zone.mx.address");
    po.strict = true;
    log_reset();
    CHECK(imp(&po, "$ORIGIN mx.test.\n$TTL 300\ny IN A 192.0.2.4\n", "mx.test", &r) == ZI_FAIL);
    LOG_HAS("db.import.strict");
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'y.mx.test'") == 0);
    /* the tag definitions of the configuration reach the checks */
    ecs_tag_def_t etag;
    memset(&etag, 0, sizeof(etag));
    po.strict = false;
    po.ecs_tags = &etag;
    po.n_ecs_tags = 0;
    po.loc_tags = &etag;
    po.n_loc_tags = 0;
    CHECK(imp(&po, "$ORIGIN mx.test.\n$TTL 300\nz IN A 192.0.2.5\n", "mx.test", &r) == ZI_OK);

    /* a zone that is not a primary zone: the server does not serve its records, so they are not checked */
    be_exec("UPDATE domains SET type = 'SLAVE' WHERE name = 'example.test'");
    log_reset();
    CHECK(imp(&o, "$ORIGIN example.test.\n$TTL 300\nwww IN CNAME mx\n", "example.test", &r) == ZI_OK);
    LOG_HAS("db.import.not-primary");
    CHECK_HAS(g_log, "SLAVE");
}

static void run_scenarios(void) {
    t_new_zone();
    t_replace_merge();
    t_types();
    t_dry_run();
    t_serial();
    t_metadata_ext();
    t_views_reload();
    t_bad_input();
    t_write_failures();
    t_lock();
    t_tinydns_all();
    t_round_trip();
    t_inputs();
    t_options();
    t_verify();
    t_export();
    t_driver();
#ifdef KARIDNS_DB_POSTGRESQL
    if (g_be == BE_PG) {
        t_pg_session();
        t_pg_role();
    }
#endif
}

#ifdef KARIDNS_DB_POSTGRESQL
static void pg_cleanup(void) {
    if (g_pg) {
        PQfinish(g_pg);
        g_pg = NULL;
    }
    PGconn *m = PQconnectdb(g_maint);
    if (PQstatus(m) == CONNECTION_OK && g_pgdb[0]) {
        char sql[200];
        snprintf(sql, sizeof(sql), "DROP DATABASE IF EXISTS %s", g_pgdb);
        PQclear(PQexec(m, sql));
    }
    PQfinish(m);
}

/* a PostgreSQL server for the second run; false (with a SKIP note) when there is none */
static bool pg_setup(void) {
    const char *pg = getenv("KARIDNS_TEST_PG");
    snprintf(g_maint, sizeof(g_maint), "%s", pg && *pg ? pg : "dbname=postgres");
    char ci[1200];
    snprintf(ci, sizeof(ci), "%s connect_timeout=5", g_maint);
    PGconn *m = PQconnectdb(ci);
    if (PQstatus(m) != CONNECTION_OK) {
        printf("SKIP: no PostgreSQL server for the importer tests (%.100s); set KARIDNS_TEST_PG to a conninfo\n", PQerrorMessage(m));
        PQfinish(m);
        return false;
    }
    snprintf(g_pgdb, sizeof(g_pgdb), "karidns_test_zi_%d", (int)getpid());
    char sql[200];
    snprintf(sql, sizeof(sql), "CREATE DATABASE %s", g_pgdb);
    PGresult *r = PQexec(m, sql);
    bool made = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    bool ok = made && PQserverVersion(m) >= 130000;
    PQfinish(m);
    if (!made) {
        printf("SKIP: the PostgreSQL role may not create databases\n");
        g_pgdb[0] = '\0';
        return false;
    }
    if (!ok) {
        printf("SKIP: PostgreSQL 13 or newer is needed\n");
        return false;
    }
    snprintf(ci, sizeof(ci), "%s dbname=%s", g_maint, g_pgdb);
    g_pg = PQconnectdb(ci);
    if (PQstatus(g_pg) != CONNECTION_OK) {
        printf("  [FAIL] cannot connect to %s\n", g_pgdb);
        g_failed++;
        return false;
    }
    PQclear(PQexec(g_pg, "SET client_min_messages = warning"));
    snprintf(g_ci, sizeof(g_ci), "%s/conninfo", g_dir);
    char content[1300];
    snprintf(content, sizeof(content), "# test\n%s\ndbname=%s\n", g_maint, g_pgdb);
    write_file(g_ci, content, 0600);
    return true;
}
#endif

int main(int argc, char **argv) {
    snprintf(g_root, sizeof(g_root), "%s", argc > 1 ? argv[1] : "tests/db");
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/karidns_zi_XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(g_dir)) {
        printf("  [FAIL] cannot create a temporary directory\n");
        return 1;
    }
    int ran = 0;
    bool ran_sqlite = false;
#ifdef KARIDNS_DB_SQLITE3
    printf("SQLite3\n");
    g_be = BE_SQLITE;
    g_drv = &db_driver_sqlite3;
    run_scenarios();
    ran++;
    ran_sqlite = true;
    if (g_sq) sqlite3_close(g_sq);
    g_sq = NULL;
#else
    printf("SKIP: built without the SQLite3 driver\n");
#endif
#ifdef KARIDNS_DB_POSTGRESQL
    if (pg_setup()) {
        printf("PostgreSQL (%s)\n", g_pgdb);
        g_be = BE_PG;
        g_drv = &db_driver_postgresql;
        g_src = (db_source_t){ "postgresql", NULL, g_ci, NULL, 400 };
        g_have_ext = false;
        run_scenarios();
        ran++;
    }
    pg_cleanup();
#else
    printf("SKIP: built without the PostgreSQL driver\n");
#endif
    /* every code of the importer and the exporter was printed by some scenario (run_karicheck_codes_test.sh lists them as printed here, not by
     *karicheck).  db.import.rows is the one no input reaches: the rows of a parsed zone are always writable; db.import.summary, db.import.change and
     * db.export.done are printed by tools/karidns_zone.c (tests/run_karidns_zone_test.sh), not by the library. */
    if (ran_sqlite)
        for (int c = 1; c < DC__COUNT; c++) {
            const char *n = dns_diag_code_name((dns_diag_code_t)c);
            if ((strncmp(n, "db.import.", 10) == 0 || strncmp(n, "db.export.", 10) == 0) && strcmp(n, "db.import.rows") != 0 &&
                strcmp(n, "db.import.summary") != 0 && strcmp(n, "db.import.change") != 0 && strcmp(n, "db.export.done") != 0)
                CHECK_MSG(g_code_seen[c], "no scenario printed the code %s", n);
        }
    rm_tree(g_dir);
    printf("\n%d checks, %d failed%s\n", g_checks, g_failed, ran ? "" : " (no database driver was run)");
    return g_failed ? 1 : 0;
}
