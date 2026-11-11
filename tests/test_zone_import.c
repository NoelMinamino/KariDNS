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
 * apply (items D and E): the change file parser (dns_zone_changes.c: every field it refuses, the zone text it makes), karidns-zone apply (the generation, the diff with the records
 * before and after, the serial, the version rows and their retention, create, the narrow read-back, the zone that is locked or not there) and the driver functions behind it.
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

#include "../dns_zone_changes.h"
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

/* an FNV-1a hash of the text of what a query returns (one value) */
static unsigned long long text_sum(const char *sql) {
    static char buf[131072];
    be_str(sql, buf, sizeof(buf));
    unsigned long long h = 1469598103934665603ull;
    for (const char *p = buf; *p; p++) h = (h ^ (unsigned char)*p) * 1099511628211ull;
    return h;
}

/* what the database holds of the zones, to see that a failed import changed nothing: the counts, and a hash of every column of the records an importer
 * or the signer writes (content, TTL, priority, disabled, ordername, auth) and of the metadata */
static void state_of(char *out, size_t cap) {
    const bool pg = g_be == BE_PG;
    unsigned long long rs = text_sum(pg ? "SELECT string_agg(domain_id || '|' || name || '|' || coalesce(type, '-') || '|' || coalesce(content, '-') || '|' || coalesce(ttl::text, '-') || '|' || "
                                          "coalesce(prio::text, '-') || '|' || disabled::int || '|' || coalesce(ordername, '-') || '|' || auth::int, ';' ORDER BY id) FROM records"
                                    : "SELECT group_concat(domain_id || '|' || name || '|' || coalesce(type, '-') || '|' || coalesce(content, '-') || '|' || coalesce(ttl, '-') || '|' || "
                                          "coalesce(prio, '-') || '|' || disabled || '|' || coalesce(ordername, '-') || '|' || CAST(auth AS integer), ';') FROM (SELECT * FROM records ORDER BY id)");
    unsigned long long ms = text_sum(pg ? "SELECT string_agg(domain_id || '|' || kind || '|' || coalesce(content, '-'), ';' ORDER BY id) FROM domainmetadata"
                                    : "SELECT group_concat(domain_id || '|' || kind || '|' || coalesce(content, '-'), ';') FROM (SELECT * FROM domainmetadata ORDER BY id)");
    snprintf(out, cap, "%ld/%ld/%ld/%ld/%ld/%ld/%ld/%016llx/%016llx", qn("SELECT count(*) FROM domains"), qn("SELECT count(*) FROM records"), qn("SELECT count(*) FROM domainmetadata"),
             qn("SELECT count(*) FROM karidns_record_tags"), qn("SELECT count(*) FROM karidns_zone_tagdefs"), qn("SELECT count(*) FROM karidns_record_tinydns"),
             nchg(), rs, ms);
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

/* a w_set_audit that fails (item B) */
static int audit_fails(db_conn_t *c, bool summary, const char *actor) {
    (void)c;
    (void)summary;
    (void)actor;
    return -1;
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
    /* the audit options (item B): w_set_audit is called when one is asked for; a driver without it is fine, one that fails is an open error */
    {
        db_driver_t fd = *g_drv;
        o.audit_summary = true;
        o.audit_actor = "karidns-zone:test";
        zi_t *az = zi_open(&o);                                 /* the real driver */
        CHECK(az != NULL);
        zi_close(az);
        fd.w_set_audit = NULL;
        o.drv = &fd;
        az = zi_open(&o);
        CHECK(az != NULL);
        zi_close(az);
        fd.w_set_audit = audit_fails;
        o.drv = &fd;
        log_reset();
        CHECK(zi_open(&o) == NULL);
        LOG_HAS("db.import.open");
        o.audit_summary = false;
        o.audit_actor = NULL;
        az = zi_open(&o);                                       /* nothing asked for: not called */
        CHECK(az != NULL);
        zi_close(az);
        o.drv = g_drv;
    }
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

/* ------------------------------------------------------------------------------------------------------------- */
/* import --signer (0.6.0 item C)                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

/* the zone as the signer's tool signs it (an NSEC chain, fake signatures): example.test with the names a.b (below the empty non-terminal b), mail, mx, ns1, sub (a
 * delegation) and www.  exp_a: the expiration of the RRSIG of the SOA, exp_b: of every other RRSIG. */
static char *signed_text(unsigned long serial, const char *exp_a, const char *exp_b, const char *soa_tail) {
    static const char sig[] = "AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o";
    char *t = malloc(9000);
    int n = snprintf(t, 9000,
        "$ORIGIN example.test.\n$TTL 3600\n"
        "@ IN SOA ns1.example.test. hostmaster.example.test. %lu %s\n"
        "@ IN NS ns1.example.test.\n"
        "@ IN DNSKEY 257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n"
        "@ IN NSEC a.b.example.test. NS SOA RRSIG NSEC DNSKEY\n"
        "a.b IN A 192.0.2.81\n"
        "a.b IN NSEC mail.example.test. A RRSIG NSEC\n"
        "mail IN MX 10 mx.example.test.\n"
        "mail IN NSEC mx.example.test. MX RRSIG NSEC\n"
        "mx IN A 192.0.2.25\n"
        "mx IN NSEC ns1.example.test. A RRSIG NSEC\n"
        "ns1 IN A 192.0.2.1\n"
        "ns1 IN NSEC sub.example.test. A RRSIG NSEC\n"
        "sub IN NS ns.sub.example.net.\n"
        "sub IN NSEC www.example.test. NS RRSIG NSEC\n"
        "www IN A 192.0.2.80\n"
        "www IN NSEC example.test. A RRSIG NSEC\n",
        serial, soa_tail);
    static const struct { const char *owner, *covered; int labels; } rr[] = {
        { "@", "SOA", 2 }, { "@", "NS", 2 }, { "@", "DNSKEY", 2 }, { "@", "NSEC", 2 }, { "a.b", "A", 4 }, { "a.b", "NSEC", 4 }, { "mail", "MX", 3 }, { "mail", "NSEC", 3 },
        { "mx", "A", 3 }, { "mx", "NSEC", 3 }, { "ns1", "A", 3 }, { "ns1", "NSEC", 3 }, { "sub", "NSEC", 3 }, { "www", "A", 3 }, { "www", "NSEC", 3 } };
    for (size_t i = 0; i < sizeof(rr) / sizeof(rr[0]); i++)
        n += snprintf(t + n, 9000 - (size_t)n, "%s IN RRSIG %s 8 %d 3600 %s 20200101000000 12345 example.test. %s\n", rr[i].owner, rr[i].covered, rr[i].labels,
                      i == 0 ? exp_a : exp_b, sig);
    return t;
}

static const char *K_SOA_TAIL = "7200 3600 1209600 300";
static const char *K_SIGNER_BODY = "www IN A 192.0.2.80\nmail IN MX 10 mx\nmx IN A 192.0.2.25\na.b IN A 192.0.2.81\nsub IN NS ns.sub.example.net.\n";

static zi_opts_t signer_opts(void) {
    zi_opts_t o = base_opts();
    o.signer = true;
    return o;
}

static int imp_signed(const zi_opts_t *o, const char *text, zi_result_t *r) { return imp(o, text, "example.test", r); }

/* the signer's calls of the driver that can fail */
enum { SF_NONE = -1, SF_AUTH, SF_UPD, SF_MARK, SF_WID, SF_DELREC, SF_INSDN, SF_UPDORD, SF_DELMETA, SF_INSMETA, SF_N,
       SF_CONFLICT_UPD = SF_N, SF_CONFLICT_DEL, SF_CONFLICT_INS, SF_CONFLICT_ORD, SF_SNAP };         /* from SF_CONFLICT_UPD: the driver reports a concurrent change (DB_ERR_CONFLICT) */
static int g_sfail = SF_NONE;
static const db_driver_t *g_sreal;
static int sf_auth(db_conn_t *c, int64_t d, db_auth_cb cb, void *ud) { if (g_sfail == SF_AUTH) return -1; return g_sreal->w_scan_auth(c, d, cb, ud); }
static int sf_upd(db_conn_t *c, int64_t d, int64_t id, const char *ct, const char *on, bool a) {
    if (g_sfail == SF_UPD) return -1;
    if (g_sfail == SF_CONFLICT_UPD) return DB_ERR_CONFLICT;
    return g_sreal->w_update_record(c, d, id, ct, on, a);
}
static int sf_mark(db_conn_t *c, uint64_t *m) { if (g_sfail == SF_MARK) return -1; return g_sreal->w_mark(c, m); }
static int sf_wid(db_conn_t *c, uint64_t m, db_write_id_t *w) { if (g_sfail == SF_WID) return -1; return g_sreal->w_write_id(c, m, w); }
static int sf_delrec(db_conn_t *c, int64_t d, const int64_t *ids, size_t n) {
    if (g_sfail == SF_DELREC) return -1;
    if (g_sfail == SF_CONFLICT_DEL) return DB_ERR_CONFLICT;
    return g_sreal->w_delete_dnssec(c, d, ids, n);
}
static int sf_insdn(db_conn_t *c, int64_t d, const db_ins_t *v, size_t n) {
    if (g_sfail == SF_INSDN) return -1;
    if (g_sfail == SF_CONFLICT_INS) return DB_ERR_CONFLICT;
    return g_sreal->w_insert_dnssec(c, d, v, n);
}
static int sf_updord(db_conn_t *c, int64_t d, const db_order_t *v, size_t n) {
    if (g_sfail == SF_UPDORD) return -1;
    if (g_sfail == SF_CONFLICT_ORD) return DB_ERR_CONFLICT;
    return g_sreal->w_update_orders(c, d, v, n);
}
static int sf_snap(db_conn_t *c, bool on) { if (g_sfail == SF_SNAP) return -1; return g_sreal->w_set_snapshot(c, on); }
static int sf_delmeta(db_conn_t *c, int64_t d, const char *k) { if (g_sfail == SF_DELMETA) return -1; return g_sreal->w_delete_meta(c, d, k); }
static int sf_insmeta(db_conn_t *c, int64_t d, const char *k, const char *v) { if (g_sfail == SF_INSMETA) return -1; return g_sreal->w_insert_meta(c, d, k, v); }
static db_driver_t g_sdrv;

/* a change another session commits while the signer works (PostgreSQL): right after the signer has read the zone, the SOA row gets a new version */
#define SF_CONCURRENT 99
static int sf_scan(db_conn_t *c, const int64_t *d, db_record_cb cb, void *ud) {
    int rc = g_sreal->scan_records(c, d, cb, ud);
    if (g_sfail == SF_CONCURRENT && rc == 0) {
        g_sfail = SF_NONE;
        be_exec("UPDATE records SET ttl = ttl WHERE type = 'SOA'");
    }
    return rc;
}

static long meta_n(const char *zone, const char *kind) {
    return qn("SELECT count(*) FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = '%s') AND kind = '%s'", zone, kind);
}

/* the unsigned zone of the scenarios: the signed text must equal it but for the DNSSEC records */
static bool signer_base(void) {
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    log_reset();
    bool ok = imp_zone(&o, "example.test", 10, K_SIGNER_BODY, &r) == ZI_OK;
    CHECK(ok);
    return ok;
}

/* the zone as text through the exporter with ZX_PLAIN_* flags (karidns-zone export --signer) */
static char *do_export_ex(const char *zone, unsigned plain) {
    zmsg_t m = { msg_cb, NULL };
    zx_t *x = zx_open(g_drv, &g_src, &m);
    if (!x) return NULL;
    sbuf_t b = {0};
    int rc = zx_export_zone_ex(x, zone, NULL, NULL, sb_sink, &b, plain);
    zx_close(x);
    if (rc != 0) {
        free(b.p);
        return NULL;
    }
    if (!b.p) b.p = strdup("");
    return b.p;
}

/* export --signer (ZX_PLAIN_CHAIN, 0.6.0 item C): the input of dnssec-signzone.  A signed zone that someone changed has no complete chain (the new name has no RRSIG(NSEC)),
 * so the reader and the plain export refuse it; without the chain the zone can be read, and the other signatures stay. */
/* the NSEC, NSEC3 and NSEC3PARAM records of an export (a token of that name that does not follow the word RRSIG: the RRSIG over them are meant to stay) */
static int chain_rrs(const char *t) {
    int n = 0;
    for (const char *p = t; (p = strstr(p, "NSEC")) != NULL; p += 4) {
        if (p > t && p[-1] != ' ' && p[-1] != '\t') continue;
        if (p - t >= 6 && (p[-1] == ' ' || p[-1] == '\t') && strncmp(p - 6, "RRSIG", 5) == 0) continue;
        n++;
    }
    return n;
}

static void t_export_signer(void) {
    printf("  export --signer (ZX_PLAIN_CHAIN)\n");
    if (!signer_base()) return;
    char *s11 = signed_text(11, "20300101000000", "20300601000000", K_SOA_TAIL);
    zi_opts_t o = signer_opts();
    zi_result_t r;
    CHECK(imp_signed(&o, s11, &r) == ZI_OK);
    free(s11);
    char *plain = do_export("example.test", NULL, NULL);
    CHECK(plain != NULL && strstr(plain, " NSEC ") != NULL);
    char *chainless = do_export_ex("example.test", ZX_PLAIN_CHAIN);
    CHECK(chainless != NULL);
    if (chainless) {
        CHECK(chain_rrs(chainless) == 0);              /* no chain, ... */
        CHECK(strstr(chainless, "RRSIG NSEC") != NULL || strstr(chainless, "RRSIG\tNSEC") != NULL);   /* ... but the signature over it stays (0.6.1: dnssec-signzone -u keeps what verifies) ... */
        CHECK_HAS(chainless, "192.0.2.80");
        CHECK(strstr(chainless, "RRSIG") != NULL && strstr(chainless, "DNSKEY") != NULL);              /* ... the other signatures and the key stay */
        free(chainless);
    }
    free(plain);
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'new.example.test', 'A', '192.0.2.99', 3600 FROM domains WHERE name = 'example.test'");
    log_reset();
    CHECK(do_export("example.test", NULL, NULL) == NULL);                    /* the chain is out of date: the zone is not one the server would serve */
    LOG_HAS("db.export.zone");
    chainless = do_export_ex("example.test", ZX_PLAIN_CHAIN);
    CHECK(chainless != NULL);
    if (chainless) {
        CHECK_HAS(chainless, "192.0.2.99");
        CHECK(chain_rrs(chainless) == 0 && strstr(chainless, "RRSIG") != NULL);
        free(chainless);
    }
    /* the signature over the chain record of a name that is gone does not go to the signer (the reader would refuse the zone after the signing): NSEC, and NSEC3 whose
     * hash is no row's ordername; the signature of a name that is there stays */
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'gone.example.test', 'RRSIG', 'NSEC 8 3 3600 20300601000000 20200101000000 1 example.test. AAAA', 3600 FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'fphivg4u4kqm6nlhk25bhvuatq4bngu1.example.test', 'RRSIG', 'NSEC3 8 3 3600 20300601000000 20200101000000 1 example.test. AAAA', 3600 FROM domains WHERE name = 'example.test'");
    chainless = do_export_ex("example.test", ZX_PLAIN_CHAIN);
    CHECK(chainless != NULL);
    if (chainless) {
        CHECK(strstr(chainless, "gone") == NULL && strstr(chainless, "fphivg4u4kqm6nlhk25bhvuatq4bngu1") == NULL && strstr(chainless, "FPHIVG4U4KQM6NLHK25BHVUATQ4BNGU1") == NULL);
        CHECK(chain_rrs(chainless) == 0 && strstr(chainless, "RRSIG") != NULL);
        free(chainless);
    }
    be_exec("DELETE FROM records WHERE name IN ('gone.example.test', 'fphivg4u4kqm6nlhk25bhvuatq4bngu1.example.test')");
    /* a zone with keys and no PRESIGNED is refused by the plain export, not by the signer's */
    be_exec("DELETE FROM domainmetadata WHERE kind IN ('PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER')");
    be_exec("INSERT INTO cryptokeys (domain_id, flags, active, content) SELECT id, 257, true, 'k' FROM domains WHERE name = 'example.test'");
    log_reset();
    CHECK(do_export("example.test", NULL, NULL) == NULL);
    chainless = do_export_ex("example.test", ZX_PLAIN_CHAIN);
    CHECK(chainless != NULL);
    free(chainless);
    /* the type an RRSIG covers: TYPE50 spelling, and an RRSIG with no content */
    be_exec("DELETE FROM cryptokeys");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'x.example.test', 'RRSIG', 'TYPE50 8 3 3600 20300601000000 20200101000000 1 example.test. AAAA', 3600 FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'y.example.test', 'RRSIG', NULL, 3600 FROM domains WHERE name = 'example.test'");
    chainless = do_export_ex("example.test", ZX_PLAIN_CHAIN);
    CHECK(chainless == NULL || strstr(chainless, "x.example.test") != NULL);      /* (0.6.1: an RRSIG over the chain stays; this odd one may be refused by the reader) */
    free(chainless);
}

/* import --signer writes only the DNSSEC rows that differ (0.6.1): a second signing whose rows are the same leaves them, with their ids, and the change log lists only
 * what changed (the SOA row); a changed signature is one DELETE and one INSERT */
static void t_signer_diff(void) {
    printf("  import --signer: only the rows that differ are written\n");
    if (!signer_base()) return;
    zi_opts_t o = signer_opts();
    zi_result_t r;
    char *s = signed_text(11, "20300101000000", "20300601000000", K_SOA_TAIL);
    CHECK(imp_signed(&o, s, &r) == ZI_OK);
    free(s);
    CHECK_MSG(r.records_inserted == 16 && r.records_deleted == 0, "%zu inserted, %zu deleted", r.records_inserted, r.records_deleted);
    long ids = qn("SELECT sum(id) FROM records WHERE type IN ('RRSIG', 'DNSKEY')");
    long seq0 = qn("SELECT coalesce(max(seq), 0) FROM karidns_changes");
    s = signed_text(12, "20300101000000", "20300601000000", K_SOA_TAIL);       /* a serial that grew, every signature the same */
    log_reset();
    CHECK(imp_signed(&o, s, &r) == ZI_OK);
    free(s);
    CHECK_MSG(r.committed && r.records_inserted == 0 && r.records_deleted == 0, "%zu inserted, %zu deleted", r.records_inserted, r.records_deleted);
    CHECK(serial_of("example.test") == 12);
    CHECK(qn("SELECT sum(id) FROM records WHERE type IN ('RRSIG', 'DNSKEY')") == ids && qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") == 15);
    CHECK(meta_n("example.test", "PRESIGNED") == 1 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1);
    CHECK(r.has_write_id);
    if (g_be == BE_SQLITE) {
        /* the change log of the write is the SOA row: not one row per DNSSEC row */
        long n = qn("SELECT count(*) FROM karidns_changes WHERE seq > %ld", seq0);
        CHECK_MSG(n >= 1 && n <= 2, "%ld log rows", n);
        CHECK(r.write_id.seq_first > (unsigned long long)seq0 && r.write_id.seq_last >= r.write_id.seq_first);
    }
    s = signed_text(13, "20300101000000", "20310101000000", K_SOA_TAIL);       /* the signatures but the SOA's are new */
    CHECK(imp_signed(&o, s, &r) == ZI_OK);
    free(s);
    CHECK_MSG(r.records_inserted == 14 && r.records_deleted == 14, "%zu inserted, %zu deleted", r.records_inserted, r.records_deleted);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") == 15 && qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%20310101000000%%'") == 14);
    s = signed_text(14, "20300201000000", "20310101000000", K_SOA_TAIL);       /* only the SOA's signature */
    CHECK(imp_signed(&o, s, &r) == ZI_OK);
    free(s);
    CHECK_MSG(r.records_inserted == 1 && r.records_deleted == 1, "%zu inserted, %zu deleted", r.records_inserted, r.records_deleted);
    CHECK(r.has_expire && r.min_expire > 0);
    /* a disabled DNSSEC row in the database is never the same as a row of the file: it goes, and the file's row is inserted */
    be_exec("UPDATE records SET disabled = true WHERE type = 'DNSKEY'");
    s = signed_text(15, "20300201000000", "20310101000000", K_SOA_TAIL);
    CHECK(imp_signed(&o, s, &r) == ZI_OK);
    free(s);
    CHECK_MSG(r.records_inserted == 1 && r.records_deleted == 1, "%zu inserted, %zu deleted", r.records_inserted, r.records_deleted);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'DNSKEY' AND NOT disabled") == 1 && qn("SELECT count(*) FROM records WHERE type = 'DNSKEY'") == 1);
    char *x = do_export("example.test", NULL, NULL);                          /* the zone the reader serves is the file's */
    CHECK(x != NULL);
    free(x);
}

static void t_signer(void) {
    printf("  import --signer\n");
    if (!signer_base()) return;
    char *s11 = signed_text(11, "20300101000000", "20300601000000", K_SOA_TAIL);
    zi_opts_t o = signer_opts();
    zi_result_t r;
    char before[200], after[200];

    /* the first signing needs nothing in the database: no cryptokeys, no PRESIGNED; the zone exports as the unsigned zone (karidns-zone export, then the
     * signer signs the text) and import --signer puts PRESIGNED and X-KARIDNS-SIGNER there */
    CHECK(meta_n("example.test", "PRESIGNED") == 0 && qn("SELECT count(*) FROM cryptokeys") == 0);
    {
        char *u = do_export("example.test", NULL, NULL);
        CHECK(u != NULL);
        if (u) {
            CHECK_HAS(u, "192.0.2.80");
            CHECK(strstr(u, " DNSKEY ") == NULL && strstr(u, " RRSIG ") == NULL);
            free(u);
        }
    }

    /* a real run: the unsigned zone becomes the signed one */
    log_reset();
    CHECK(imp_signed(&o, s11, &r) == ZI_OK);
    LOG_HAS("db.import.done");
    CHECK(r.committed && !r.dry_run && !r.created && r.wrote_soa && r.has_old_serial && r.old_serial == 10 && r.new_serial == 11);
    CHECK(serial_of("example.test") == 11);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") == 15 && qn("SELECT count(*) FROM records WHERE type = 'DNSKEY'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE type IN ('NSEC', 'NSEC3', 'NSEC3PARAM')") == 0);             /* the presigned layout stores none of them */
    CHECK_MSG(r.records_inserted == 16 && r.records_deleted == 0, "%zu inserted, %zu deleted", r.records_inserted, r.records_deleted);
    CHECK(r.rrsets_added > 0 && r.rrsets_deleted == 0);
    CHECK_MSG(r.rows_updated == 8, "%zu rows updated", r.rows_updated);                                       /* the SOA, NS, ns1, www, mail, mx, a.b and sub: each gets an ordername or auth */
    CHECK(meta_n("example.test", "PRESIGNED") == 1 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1 && meta_n("example.test", "NSEC3PARAM") == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND ordername = 'www'") == 1);                 /* NSEC: the reversed relative name */
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'a.b.example.test' AND type = 'A' AND ordername = 'b a'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'example.test' AND type = 'SOA' AND ordername = ''") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'sub.example.test' AND type = 'NS' AND CAST(auth AS integer) = 0") == 1);        /* a delegation is not authoritative */
    CHECK_MSG(r.has_expire && r.min_expire == 1893456000, "expire %lld", (long long)r.min_expire);        /* 2030-01-01T00:00:00Z: the SOA's RRSIG, the earliest */
    CHECK(r.has_write_id);
    if (g_be == BE_PG) {
        CHECK(r.write_id.xid[0] != '\0' && r.write_id.seq_last == 0);
        CHECK(qn("SELECT count(*) FROM karidns_changes WHERE xid = '%s'::xid8 AND domain_id = %lld", r.write_id.xid, (long long)r.domain_id) >= 1);
    } else {
        CHECK(r.write_id.xid[0] == '\0' && r.write_id.seq_first > 0 && r.write_id.seq_last >= r.write_id.seq_first);
        CHECK(qn("SELECT count(*) FROM karidns_changes WHERE seq >= %llu AND seq <= %llu", (unsigned long long)r.write_id.seq_first, (unsigned long long)r.write_id.seq_last) ==
              (long)(r.write_id.seq_last - r.write_id.seq_first + 1));
        CHECK(qn("SELECT max(seq) FROM karidns_changes") == (long)r.write_id.seq_last);
    }
    char *x = do_export("example.test", NULL, NULL);                                                          /* the loader's reader accepts the rows: the chain is rebuilt */
    CHECK(x != NULL);
    if (x) {
        CHECK_HAS(x, " NSEC ");
        CHECK_HAS(x, " DNSKEY ");
        free(x);
    }

    /* another writer holds the zone: the signer gives up with "busy" (the tool's exit status 4), nothing is written */
    {
        db_conn_t *hc = NULL;
        char herr[DB_ERRLEN];
        CHECK(g_drv->open_write(&hc, &g_src, herr, sizeof(herr)) == 0);
        if (hc) {
            char *sb = signed_text(12, "20300301000000", "20300601000000", K_SOA_TAIL);
            CHECK(g_drv->w_begin(hc, "example.test") == 0);
            state_of(before, sizeof(before));
            log_reset();
            CHECK(imp_signed(&o, sb, &r) == ZI_BUSY);
            LOG_HAS("db.import.busy");
            CHECK(!r.committed);
            CHECK(g_drv->w_rollback(hc) == 0);
            state_of(after, sizeof(after));
            CHECK(strcmp(before, after) == 0);
            g_drv->close(hc);
            free(sb);
        }
    }

    /* a second run: signatures replaced, nothing else changes (the NULL TTL of a row is the default TTL, a disabled row is not compared, an empty
     * non-terminal the database holds gets the ordername of a presigned zone) */
    be_exec("UPDATE records SET ttl = NULL WHERE name = 'www.example.test' AND type = 'A'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'off.example.test', 'A', '192.0.2.200', 300, true, true FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth, ordername) SELECT id, 'b.example.test', NULL, NULL, NULL, false, true, 'junk' FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth, ordername) SELECT id, 'old.example.test', 'RRSIG', 'A 8 3 3600 20300101000000 20200101000000 1 example.test. x', 300, true, true, NULL FROM domains WHERE name = 'example.test'");
    char *s12 = signed_text(12, "20300301000000", "20300601000000", K_SOA_TAIL);
    log_reset();
    g_rep[0] = '\0';
    o.report = rep_cb;
    CHECK(imp_signed(&o, s12, &r) == ZI_OK);
    o.report = NULL;
    CHECK(r.committed && r.old_serial == 11 && r.new_serial == 12 && serial_of("example.test") == 12);
    CHECK_MSG(r.records_deleted == 2 && r.records_inserted == 1, "%zu deleted, %zu inserted", r.records_deleted, r.records_inserted);      /* the SOA's changed signature and the disabled RRSIG; the other rows stay */
    CHECK_MSG(r.rows_updated == 2, "%zu rows updated", r.rows_updated);                                       /* the SOA, and the empty non-terminal (ordername NULL for NSEC) */
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'b.example.test' AND type IS NULL AND ordername IS NULL") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'off.example.test'") == 1);                          /* a disabled row stays */
    CHECK_MSG(r.min_expire == 1898553600, "expire %lld", (long long)r.min_expire);                          /* 2030-03-01T00:00:00Z */
    CHECK_HAS(g_rep, "~example.test/RRSIG");

    /* the same file again: the serial does not grow, so the zone changed since: nothing is written */
    state_of(before, sizeof(before));
    log_reset();
    CHECK(imp_signed(&o, s12, &r) == ZI_CHANGED);
    LOG_HAS("db.import.changed");
    CHECK(!r.committed);
    state_of(after, sizeof(after));
    CHECK_MSG(strcmp(before, after) == 0, "%s -> %s", before, after);

    /* a record that changed since the file was made, an RRset that is new, a TTL, the SOA timers: all ZI_CHANGED and all leave the database as it is */
    static const char *const mut[][2] = {
        { "UPDATE records SET content = '192.0.2.99' WHERE name = 'www.example.test' AND type = 'A'", "UPDATE records SET content = '192.0.2.80' WHERE name = 'www.example.test' AND type = 'A'" },
        { "INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'new.example.test', 'A', '192.0.2.7', 3600, false, true FROM domains WHERE name = 'example.test'",
          "DELETE FROM records WHERE name = 'new.example.test'" },
        { "UPDATE records SET type = 'TXT' WHERE name = 'mx.example.test' AND type = 'A'", "UPDATE records SET type = 'A' WHERE name = 'mx.example.test' AND type = 'TXT'" },
        { "UPDATE records SET ttl = 60 WHERE name = 'mail.example.test' AND type = 'MX'", "UPDATE records SET ttl = 3600 WHERE name = 'mail.example.test' AND type = 'MX'" },
        { "UPDATE records SET content = 'ns1.example.test hostmaster.example.test 12 7201 3600 1209600 300' WHERE type = 'SOA'",
          "UPDATE records SET content = 'ns1.example.test hostmaster.example.test 12 7200 3600 1209600 300' WHERE type = 'SOA'" },
        { "UPDATE records SET content = 'ns1.example.test hostmaster.example.test 40 7200 3600 1209600 300' WHERE type = 'SOA'",
          "UPDATE records SET content = 'ns1.example.test hostmaster.example.test 12 7200 3600 1209600 300' WHERE type = 'SOA'" },
        { "UPDATE records SET ttl = 90 WHERE type = 'SOA'", "UPDATE records SET ttl = 3600 WHERE type = 'SOA'" },
    };
    char *s13 = signed_text(13, "20300301000000", "20300601000000", K_SOA_TAIL);
    for (size_t i = 0; i < sizeof(mut) / sizeof(mut[0]); i++) {
        be_exec(mut[i][0]);
        state_of(before, sizeof(before));
        log_reset();
        int st = imp_signed(&o, s13, &r);
        state_of(after, sizeof(after));
        CHECK_MSG(st == ZI_CHANGED, "mutation %zu: status %d\n%s", i, st, g_log);
        CHECK_MSG(strcmp(before, after) == 0, "mutation %zu: %s -> %s", i, before, after);
        be_exec(mut[i][1]);
    }
    CHECK(serial_of("example.test") == 12);

    /* a dry run lists the work and writes nothing */
    o.dry_run = true;
    state_of(before, sizeof(before));
    log_reset();
    CHECK(imp_signed(&o, s13, &r) == ZI_OK);
    LOG_HAS("db.import.dry-run");
    CHECK(!r.committed && r.dry_run && r.new_serial == 13 && r.has_write_id);
    state_of(after, sizeof(after));
    CHECK(strcmp(before, after) == 0 && serial_of("example.test") == 12);
    o.dry_run = false;

    /* the NSEC3PARAM metadata of an earlier run goes away with an NSEC zone; the reload request goes with the data (PostgreSQL) */
    be_exec("INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'NSEC3PARAM', '1 0 0 -' FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '0' FROM domains WHERE name = 'example.test'");
    o.reload = true;
    log_reset();
    long rq = g_be == BE_PG ? qn("SELECT count(*) FROM karidns_reload_requests") : 0;
    CHECK(imp_signed(&o, s13, &r) == ZI_OK && serial_of("example.test") == 13);
    CHECK(meta_n("example.test", "NSEC3PARAM") == 0 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1);
    if (g_be == BE_PG) {
        LOG_HAS_NOT("db.import.no-reload");
        CHECK(qn("SELECT count(*) FROM karidns_reload_requests") == rq + 1);
    } else {
        LOG_HAS("db.import.no-reload");
    }
    o.reload = false;
    free(s12);
    free(s13);

    /* the expiration near a given time (RFC 4034 3.1.5): decimal values at the wrap of the 32 bit number; the earlier one in serial number arithmetic wins */
    if (signer_base()) {
        char *w = signed_text(11, "100", "4294967290", K_SOA_TAIL);
        o.now = 4294963400ll;                                               /* about a minute... of the year 2106 */
        log_reset();
        CHECK(imp_signed(&o, w, &r) == ZI_OK);
        CHECK_MSG(r.has_expire && r.min_expire == 4294967290ll, "expire %lld", (long long)r.min_expire);
        o.now = 0;
        free(w);
    }

    /* what the signer is not given */
    if (!signer_base()) {
        free(s11);
        return;
    }
    char *plain = zone_text("example.test", 11, K_SIGNER_BODY);                                             /* not signed */
    log_reset();
    CHECK(imp_signed(&o, plain, &r) == ZI_FAIL);
    LOG_HAS("db.import.signer");
    free(plain);
    log_reset();
    CHECK(imp(&o, s11, "other.test", &r) == ZI_FAIL);                                                       /* the file is not the zone asked for */
    log_reset();
    {
        char *ot = malloc(strlen(s11) + 1);
        char *p = ot;
        for (const char *q = s11; *q; q++) {
            if (strncmp(q, "example.test", 12) == 0) {
                memcpy(p, "nozone.test", 11);
                p += 11;
                q += 11;
            } else {
                *p++ = *q;
            }
        }
        *p = '\0';
        CHECK(imp(&o, ot, "nozone.test", &r) == ZI_FAIL);                                                   /* the zone is not in the database */
        LOG_HAS("db.import.signer");
        free(ot);
    }
    be_exec("UPDATE domains SET type = 'SLAVE' WHERE name = 'example.test'");
    log_reset();
    CHECK(imp_signed(&o, s11, &r) == ZI_FAIL);
    LOG_HAS("db.import.signer");
    be_exec("UPDATE domains SET type = 'NATIVE' WHERE name = 'example.test'");
    {                                                                       /* a zone with the metadata of a signer the loader does not know (an NSEC3 zone signed by BIND's tools, tests/db) is taken like any */
        char npath[700];
        snprintf(npath, sizeof(npath), "%s/signer_nsec3.example.test.zone", g_root);
        char *nz = slurp(npath);
        CHECK_MSG(nz != NULL, "cannot read %s", npath);
        if (nz) {
            log_reset();
            CHECK_MSG(imp_signed(&o, nz, &r) == ZI_OK, "%s", g_log);
            CHECK(r.committed && r.old_serial == 10 && r.new_serial == 11);
            CHECK(meta_n("example.test", "NSEC3PARAM") == 1 && meta_n("example.test", "PRESIGNED") == 1 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1);
            CHECK(qn("SELECT count(*) FROM records WHERE type IN ('NSEC', 'NSEC3', 'NSEC3PARAM')") == 0);
            CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") > 8 && qn("SELECT count(*) FROM records WHERE type = 'DNSKEY'") == 2);
            CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND length(ordername) = 32") == 1);        /* the NSEC3 hash, base32hex */
            CHECK(qn("SELECT count(*) FROM records WHERE name = 'sub.example.test' AND type = 'NS' AND CAST(auth AS integer) = 0") == 1);
            char *x = do_export("example.test", NULL, NULL);
            CHECK(x != NULL);
            if (x) {
                CHECK_HAS(x, " NSEC3PARAM ");
                free(x);
            }
            free(nz);
        }
        if (!signer_base()) {
            free(s11);
            return;
        }
    }
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'example.test', 'SOA', 'ns1.example.test hostmaster.example.test 3 1 2 3 4', 3600, false, true FROM domains WHERE name = 'example.test'");
    log_reset();
    CHECK(imp_signed(&o, s11, &r) == ZI_FAIL);                                                              /* two SOA records at the apex in the database */
    LOG_HAS("db.import.signer");
    be_exec("DELETE FROM records WHERE type = 'SOA'");
    log_reset();
    CHECK(imp_signed(&o, s11, &r) == ZI_FAIL);                                                              /* none */
    LOG_HAS("db.import.signer");

    /* the options that make no sense with a signed zone */
    zi_opts_t bad = signer_opts();
    log_reset();
    bad.mode = ZI_MERGE;
    CHECK(zi_open(&bad) == NULL);
    LOG_HAS("db.import.option");
    bad = signer_opts();
    const char *ty[1] = { "A" };
    bad.types = ty;
    bad.ntypes = 1;
    CHECK(zi_open(&bad) == NULL);
    bad = signer_opts();
    bad.serial = ZI_SERIAL_INCREMENT;
    CHECK(zi_open(&bad) == NULL);
    bad = signer_opts();
    bad.view = "v";
    CHECK(zi_open(&bad) == NULL);
    bad = signer_opts();
    bad.zone_type = "MASTER";
    CHECK(zi_open(&bad) == NULL);
    {
        zi_t *z = zi_open(&o);
        char tdpath[600];
        snprintf(tdpath, sizeof(tdpath), "%s/tdz.test.data", g_root);
        zi_input_t in = { tdpath, NULL, 0, 0 };
        log_reset();
        CHECK(z && zi_import_tinydns(z, &in, "tdz.test", NULL, NULL) == ZI_FAIL);
        LOG_HAS("db.import.option");
        zi_close(z);
    }

    /* every driver call of the signer can fail: nothing is written */
    g_sreal = g_drv;
    g_sdrv = *g_drv;
    g_sdrv.w_scan_auth = sf_auth;
    g_sdrv.w_update_record = sf_upd;
    g_sdrv.w_mark = sf_mark;
    g_sdrv.w_write_id = sf_wid;
    g_sdrv.w_delete_dnssec = sf_delrec;
    g_sdrv.w_insert_dnssec = sf_insdn;
    g_sdrv.scan_records = sf_scan;
    g_sdrv.w_update_orders = sf_updord;
    g_sdrv.w_set_snapshot = sf_snap;
    g_sdrv.w_delete_meta = sf_delmeta;
    g_sdrv.w_insert_meta = sf_insmeta;
    for (int op = 0; op < SF_SNAP; op++) {
        if (!signer_base()) break;
        zi_opts_t f = signer_opts();
        f.drv = &g_sdrv;
        if (op == SF_DELREC || op == SF_CONFLICT_DEL) be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'old.example.test', 'RRSIG', 'A 8 3 3600 20300101000000 20200101000000 1 example.test. x', 300, false, true FROM domains WHERE name = 'example.test'");
        if (op == SF_DELMETA) be_exec("INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'PRESIGNED', '0' FROM domains WHERE name = 'example.test'");      /* (a value to replace: metadata that is right is not written again) */
        state_of(before, sizeof(before));
        g_sfail = op;
        log_reset();
        int st = imp_signed(&f, s11, &r);
        g_sfail = SF_NONE;
        state_of(after, sizeof(after));
        if (op >= SF_CONFLICT_UPD) {                                        /* a concurrent change: the zone changed, the signer signs again (status 3) */
            CHECK_MSG(st == ZI_CHANGED, "concurrent change %d: status %d\n%s", op, st, g_log);
            LOG_HAS("db.import.changed");
            CHECK(!r.committed);
        } else {
            CHECK_MSG(st == ZI_FAIL, "driver call %d: status %d\n%s", op, st, g_log);
            LOG_HAS("db.import.write");
        }
        CHECK_MSG(strcmp(before, after) == 0, "driver call %d changed the database: %s -> %s", op, before, after);
    }
    if (g_be == BE_PG && signer_base()) {                                   /* another session changes the zone after the signer read it: REPEATABLE READ, 40001, "changed" (status 3) */
        zi_opts_t f = signer_opts();
        f.drv = &g_sdrv;
        state_of(before, sizeof(before));
        g_sfail = SF_CONCURRENT;
        log_reset();
        int st = imp_signed(&f, s11, &r);
        g_sfail = SF_NONE;
        state_of(after, sizeof(after));
        CHECK_MSG(st == ZI_CHANGED, "concurrent change: status %d\n%s", st, g_log);
        LOG_HAS("db.import.changed");
        CHECK_HAS(g_log, "could not serialize");
        CHECK(!r.committed && qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") == 0 && serial_of("example.test") == 10);       /* (the change log has the other session's row) */
        (void)before;
        (void)after;
        CHECK(imp_signed(&o, s11, &r) == ZI_OK && r.committed);             /* and the next run is fine */
    }
    {                                                                       /* the snapshot setting of the connection fails: the signer is not opened */
        zi_opts_t f = signer_opts();
        f.drv = &g_sdrv;
        g_sfail = SF_SNAP;
        log_reset();
        CHECK(zi_open(&f) == NULL);
        g_sfail = SF_NONE;
        LOG_HAS("db.import.open");
    }
    free(s11);
}

/* ---- the rows are compared as RRsets in canonical form ---- */
static const char K_DSHEX[] = "E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766";

/* the zone of t_signer_canonical as the signer's tool signs it: the canonical spelling of every record (a fake NSEC chain and signatures) */
static char *signed_canon(unsigned long serial) {
    static const char sig[] = "AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o";
    char *t = malloc(12000);
    int n = snprintf(t, 12000,
        "$ORIGIN example.test.\n$TTL 3600\n"
        "@ IN SOA ns1.example.test. hostmaster.example.test. %lu 7200 3600 1209600 300\n"
        "@ IN NS ns1.example.test.\n"
        "@ IN DNSKEY 257 3 8 %s\n"
        "@ IN NSEC alias.example.test. NS SOA RRSIG NSEC DNSKEY\n"
        "alias IN CNAME www.example.test.\n"
        "alias IN NSEC dup.example.test. CNAME RRSIG NSEC\n"
        "dup IN A 192.0.2.5\n"
        "dup IN NSEC mail.example.test. A RRSIG NSEC\n"
        "mail IN MX 10 mx.example.test.\n"
        "mail IN NSEC multi.example.test. MX RRSIG NSEC\n"
        "multi 300 IN A 192.0.2.6\n"
        "multi 300 IN A 192.0.2.7\n"
        "multi 300 IN NSEC mx.example.test. A RRSIG NSEC\n"
        "mx IN A 192.0.2.25\n"
        "mx IN NSEC ns1.example.test. A RRSIG NSEC\n"
        "ns1 IN A 192.0.2.1\n"
        "ns1 IN NSEC sub.example.test. A RRSIG NSEC\n"
        "sub IN NS ns.sub.example.net.\n"
        "sub IN DS 12345 8 2 %s\n"
        "sub IN NSEC tlsa.example.test. NS DS RRSIG NSEC\n"
        "tlsa IN TLSA 3 1 1 %s\n"
        "tlsa IN NSEC txt.example.test. TLSA RRSIG NSEC\n"
        "txt IN TXT \"hello world\"\n"
        "txt IN TXT \"abc\"\n"
        "txt IN NSEC v6.example.test. TXT RRSIG NSEC\n"
        "v6 IN AAAA 2001:db8::1\n"
        "v6 IN NSEC www.example.test. AAAA RRSIG NSEC\n"
        "www IN A 192.0.2.80\n"
        "www IN NSEC example.test. A RRSIG NSEC\n",
        serial, sig, K_DSHEX, K_DSHEX);
    static const struct { const char *owner, *covered; int labels; } rr[] = {
        { "@", "SOA", 2 }, { "@", "NS", 2 }, { "@", "DNSKEY", 2 }, { "@", "NSEC", 2 }, { "alias", "CNAME", 3 }, { "alias", "NSEC", 3 }, { "dup", "A", 3 }, { "dup", "NSEC", 3 },
        { "mail", "MX", 3 }, { "mail", "NSEC", 3 }, { "multi", "A", 3 }, { "multi", "NSEC", 3 }, { "mx", "A", 3 }, { "mx", "NSEC", 3 }, { "ns1", "A", 3 }, { "ns1", "NSEC", 3 },
        { "sub", "DS", 3 }, { "sub", "NSEC", 3 }, { "tlsa", "TLSA", 3 }, { "tlsa", "NSEC", 3 }, { "txt", "TXT", 3 }, { "txt", "NSEC", 3 }, { "v6", "AAAA", 3 }, { "v6", "NSEC", 3 },
        { "www", "A", 3 }, { "www", "NSEC", 3 } };
    for (size_t i = 0; i < sizeof(rr) / sizeof(rr[0]); i++)
        n += snprintf(t + n, 12000 - (size_t)n, "%s IN RRSIG %s 8 %d 3600 20300601000000 20200101000000 12345 example.test. %s\n", rr[i].owner, rr[i].covered, rr[i].labels, sig);
    return t;
}

static void t_signer_canonical(void) {
    printf("  import --signer: the rows are compared as RRsets in canonical form\n");
    be_fresh(true);
    zi_opts_t bo = base_opts();
    zi_result_t r;
    char *body = malloc(2000);
    snprintf(body, 2000,
             "alias IN CNAME www\ndup IN A 192.0.2.5\nmail IN MX 10 mx\nmulti 300 IN A 192.0.2.6\nmx IN A 192.0.2.25\nsub IN NS ns.sub.example.net.\nsub IN DS 12345 8 2 %s\n"
             "tlsa IN TLSA 3 1 1 %s\ntxt IN TXT \"hello world\"\ntxt IN TXT \"abc\"\nv6 IN AAAA 2001:db8::1\nwww IN A 192.0.2.80\n", K_DSHEX, K_DSHEX);
    log_reset();
    CHECK(imp_zone(&bo, "example.test", 10, body, &r) == ZI_OK);
    free(body);
    /* the rows as another tool wrote them: the text of a row is not the canonical text */
    be_exec("UPDATE records SET content = '2001:0DB8:0000:0000:0000:0000:0000:0001' WHERE name = 'v6.example.test'");              /* upper case, not compressed */
    be_exec("UPDATE records SET content = '12345 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766' WHERE type = 'DS'");         /* hex in lower case */
    be_exec("UPDATE records SET content = '3 1 1 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766' WHERE type = 'TLSA'");
    be_exec("UPDATE records SET content = 'abc' WHERE type = 'TXT' AND content = '\"abc\"'");                                       /* no quotes */
    be_exec("UPDATE records SET content = '\"hello\\032world\"' WHERE type = 'TXT' AND content LIKE '%%hello%%'");                   /* escaped, not split in the same places */
    be_exec("UPDATE records SET content = 'WWW.Example.TEST.' WHERE type = 'CNAME'");                                              /* names in upper case */
    be_exec("UPDATE records SET content = 'MX.EXAMPLE.TEST' WHERE type = 'MX'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'multi.example.test', 'A', '192.0.2.7', 600, false, true FROM domains WHERE name = 'example.test'");       /* one RRset, two TTLs */
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'dup.example.test', 'A', '192.0.2.5', 3600, false, true FROM domains WHERE name = 'example.test'");           /* the same row twice */
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'off.example.test', 'A', '192.0.2.200', 300, true, true FROM domains WHERE name = 'example.test'");           /* a disabled row */
    char *x = do_export("example.test", NULL, NULL);                                                                                    /* what an exporter gives the signer's tool: canonical */
    CHECK_MSG(x != NULL, "%s", g_log);
    free(x);

    zi_opts_t o = signer_opts();
    char before[200], after[200];
    char *s11 = signed_canon(11);
    log_reset();
    CHECK_MSG(imp_signed(&o, s11, &r) == ZI_OK, "%s", g_log);
    CHECK(r.committed && r.old_serial == 10 && r.new_serial == 11);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'v6.example.test' AND content = '2001:0DB8:0000:0000:0000:0000:0000:0001'") == 1);        /* the signer does not rewrite them */
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG'") == 26 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1);
    free(s11);
    char *s12 = signed_canon(12);
    log_reset();
    CHECK_MSG(imp_signed(&o, s12, &r) == ZI_OK, "%s", g_log);                                                                           /* and again, with the zone presigned */
    CHECK(r.old_serial == 11 && r.new_serial == 12);
    free(s12);

    /* a real change is still a change, whatever the spelling */
    static const struct { const char *sql, *undo, *what; } mut[] = {
        { "UPDATE records SET content = '2001:0DB8:0000:0000:0000:0000:0000:0002' WHERE name = 'v6.example.test'", "UPDATE records SET content = '2001:0DB8:0000:0000:0000:0000:0000:0001' WHERE name = 'v6.example.test'", "v6.example.test" },
        { "UPDATE records SET content = '12345 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5767' WHERE type = 'DS'",
          "UPDATE records SET content = '12345 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766' WHERE type = 'DS'", "sub.example.test" },
        { "UPDATE records SET content = 'abd' WHERE type = 'TXT' AND content = 'abc'", "UPDATE records SET content = 'abc' WHERE type = 'TXT' AND content = 'abd'", "txt.example.test" },
        { "UPDATE records SET content = 'MX2.EXAMPLE.TEST' WHERE type = 'MX'", "UPDATE records SET content = 'MX.EXAMPLE.TEST' WHERE type = 'MX'", "mail.example.test" },
        { "UPDATE records SET ttl = 100 WHERE name = 'multi.example.test' AND content = '192.0.2.7'", "UPDATE records SET ttl = 600 WHERE name = 'multi.example.test' AND content = '192.0.2.7'", "multi.example.test" },
        { "DELETE FROM records WHERE name = 'dup.example.test'", "INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'dup.example.test', 'A', '192.0.2.5', 3600, false, true FROM domains WHERE name = 'example.test'", "dup.example.test" },
    };
    char *s13 = signed_canon(13);
    for (size_t i = 0; i < sizeof(mut) / sizeof(mut[0]); i++) {
        be_exec(mut[i].sql);
        state_of(before, sizeof(before));
        log_reset();
        int st = imp_signed(&o, s13, &r);
        state_of(after, sizeof(after));
        CHECK_MSG(st == ZI_CHANGED, "mutation %zu: status %d\n%s", i, st, g_log);
        CHECK_MSG(strstr(g_log, mut[i].what) != NULL, "mutation %zu: the message does not name %s\n%s", i, mut[i].what, g_log);
        CHECK_MSG(strcmp(before, after) == 0, "mutation %zu: %s -> %s", i, before, after);
        be_exec(mut[i].undo);
    }
    log_reset();
    CHECK_MSG(imp_signed(&o, s13, &r) == ZI_OK, "%s", g_log);                                                                           /* all undone: the file is taken */
    free(s13);
}

/* ---- a normal import into a zone the signer signs ---- */
static void t_signer_zone_import(void) {
    printf("  a normal import into a zone the signer signs keeps its DNSSEC records\n");
    if (!signer_base()) return;
    char *s11 = signed_text(11, "20300101000000", "20300601000000", K_SOA_TAIL);
    zi_opts_t so = signer_opts();
    zi_result_t r;
    log_reset();
    CHECK(imp_signed(&so, s11, &r) == ZI_OK);
    free(s11);
    be_exec("INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'NSEC3PARAM', '1 0 0 -' FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl, disabled, auth) SELECT id, 'example.test', 'CDS', '12345 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766', 300, false, true FROM domains WHERE name = 'example.test'");
    char dnssec_before[300], dnssec_after[300];
    const char *const q_dnssec = "SELECT count(*) FROM records WHERE type IN ('RRSIG', 'DNSKEY', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY')";
    snprintf(dnssec_before, sizeof(dnssec_before), "%ld/%ld", qn("%s", q_dnssec), qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%20300601000000%%'"));

    /* replace: the data of the file replaces the other records; the DNSSEC records and the metadata the signer owns stay */
    zi_opts_t o = base_opts();
    char *plain = zone_text("example.test", 12, "www IN A 192.0.2.99\nnew IN A 192.0.2.7\n");
    log_reset();
    CHECK_MSG(imp(&o, plain, NULL, &r) == ZI_OK, "%s", g_log);
    LOG_HAS("db.import.signer-zone");
    LOG_HAS_NOT("db.import.keys");
    CHECK(r.committed && r.new_serial == 12 && serial_of("example.test") == 12);
    snprintf(dnssec_after, sizeof(dnssec_after), "%ld/%ld", qn("%s", q_dnssec), qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%20300601000000%%'"));
    CHECK_MSG(strcmp(dnssec_before, dnssec_after) == 0, "%s -> %s", dnssec_before, dnssec_after);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'CDS'") == 1 && qn("SELECT count(*) FROM records WHERE type = 'DNSKEY'") == 1);
    CHECK(meta_n("example.test", "PRESIGNED") == 1 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1 && meta_n("example.test", "NSEC3PARAM") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND content = '192.0.2.99'") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'new.example.test' AND type = 'A'") == 1 && qn("SELECT count(*) FROM records WHERE name = 'mail.example.test' AND type <> 'RRSIG'") == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'MX' OR (type = 'NS' AND name = 'sub.example.test')") == 0);
    free(plain);

    /* merge, and a file that has DNSSEC records of its own: they are ignored, with a note saying how many */
    zi_opts_t m = base_opts();
    m.mode = ZI_MERGE;
    char *s20 = signed_text(20, "20301001000000", "20301001000000", K_SOA_TAIL);
    log_reset();
    CHECK_MSG(imp(&m, s20, "example.test", &r) == ZI_OK, "%s", g_log);
    LOG_HAS("db.import.signer-zone");
    CHECK_HAS(g_log, "DNSSEC record(s) of the input were ignored");
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%20301001000000%%'") == 0);                     /* the signatures of the file did not go in */
    snprintf(dnssec_after, sizeof(dnssec_after), "%ld/%ld", qn("%s", q_dnssec), qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%20300601000000%%'"));
    CHECK_MSG(strcmp(dnssec_before, dnssec_after) == 0, "%s -> %s", dnssec_before, dnssec_after);
    CHECK(meta_n("example.test", "PRESIGNED") == 1 && meta_n("example.test", "X-KARIDNS-SIGNER") == 1 && meta_n("example.test", "NSEC3PARAM") == 1);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'mail.example.test' AND type = 'MX'") == 1);                                  /* the file's records are in */
    /* replace with a signed file: the same */
    char *s21 = signed_text(21, "20301001000000", "20301001000000", K_SOA_TAIL);
    log_reset();
    CHECK_MSG(imp(&o, s21, "example.test", &r) == ZI_OK, "%s", g_log);
    free(s21);
    snprintf(dnssec_after, sizeof(dnssec_after), "%ld/%ld", qn("%s", q_dnssec), qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%20300601000000%%'"));
    CHECK_MSG(strcmp(dnssec_before, dnssec_after) == 0, "%s -> %s", dnssec_before, dnssec_after);
    free(s20);

    /* a zone that is only presigned (no X-KARIDNS-SIGNER) is replaced as before: its DNSSEC records go with the rest */
    be_exec("DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-SIGNER'");
    plain = zone_text("example.test", 40, "www IN A 192.0.2.98\n");
    log_reset();
    CHECK_MSG(imp(&o, plain, NULL, &r) == ZI_OK, "%s", g_log);
    LOG_HAS_NOT("db.import.signer-zone");
    CHECK(qn("%s", q_dnssec) == 0 && meta_n("example.test", "PRESIGNED") == 0);
    free(plain);
}

static int count_auth_cb(void *ud, int64_t id, bool auth) {
    (void)id;
    (void)auth;
    (*(int *)ud)++;
    return 0;
}
static int stop_auth_cb(void *ud, int64_t id, bool auth) {
    (void)id;
    (void)auth;
    (*(int *)ud)++;
    return 1;
}

/* the driver calls of the signer, directly */
static void t_signer_driver(void) {
    printf("  driver: the signer's calls\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    zi_result_t r;
    CHECK(imp_zone(&o, "example.test", 1, K_BODY, &r) == ZI_OK);
    db_conn_t *c = NULL;
    char err[DB_ERRLEN];
    db_schema_info_t si;
    int64_t id1 = qn("SELECT min(id) FROM records WHERE domain_id = %lld", (long long)r.domain_id);
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0 && g_drv->check_schema(c, &si) == 0);
    if (!c) return;
    int64_t did = r.domain_id;
    uint64_t mark = 7;
    db_write_id_t wid;
    CHECK(g_drv->w_scan_auth(c, did, NULL, NULL) == -1 && g_drv->w_update_record(c, did, 1, NULL, NULL, true) == -1);                /* outside a transaction */
    CHECK(g_drv->w_mark(c, &mark) == -1 && g_drv->w_write_id(c, 0, &wid) == -1 && g_drv->w_delete_dnssec(c, did, &id1, 1) == -1);
    {
        const db_order_t ov = { id1, "o", true };
        db_record_row_t rv = { 0, 3600, 0, false, true, false, "example.test", "RRSIG", "x", NULL };
        const db_ins_t iv = { &rv, true };
        CHECK(g_drv->w_update_orders(c, did, &ov, 1) == -1 && g_drv->w_insert_dnssec(c, did, &iv, 1) == -1);                      /* outside a transaction */
    }
    CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_mark(c, &mark) == 0);
    int seen = 0;
    CHECK(g_drv->w_scan_auth(c, did, count_auth_cb, &seen) == 0 && seen == 6);
    seen = 0;
    CHECK(g_drv->w_scan_auth(c, did, stop_auth_cb, &seen) == DB_STOPPED && seen == 1);
    CHECK(g_drv->w_update_record(c, did, id1, NULL, "oname", false) == 0);                                                     /* ordername and auth only */
    CHECK(g_drv->w_update_record(c, did, id1 + 1000000, NULL, NULL, true) == DB_ERR_CONFLICT);                                  /* not a record: the row is gone */
    CHECK(g_drv->w_delete_dnssec(c, did, &id1, 1) == 0 && g_drv->w_delete_dnssec(c, did, &id1, 0) == 0);                       /* an id: the record goes; none: nothing */
    CHECK_HAS(g_drv->errmsg(c), "not in zone");
    CHECK(g_drv->w_rollback(c) == 0);
    /* the batched writes: ordername and auth of several records, DNSSEC records with their ordername, in few statements */
    {
        CHECK(g_drv->w_begin(c, "example.test") == 0);
        db_order_t ov[3] = { { id1, "o1", false }, { id1 + 1, NULL, true }, { id1 + 2, "o3", true } };
        CHECK(g_drv->w_update_orders(c, did, ov, 0) == 0 && g_drv->w_update_orders(c, did, ov, 3) == 0);
        db_order_t bad[2] = { { id1, "x", true }, { id1 + 1000000, "y", true } };
        CHECK(g_drv->w_update_orders(c, did, bad, 2) == DB_ERR_CONFLICT);                                                           /* one of them is not there */
        CHECK_HAS(g_drv->errmsg(c), "zone");
        CHECK(g_drv->w_rollback(c) == 0);
        CHECK(g_drv->w_begin(c, "example.test") == 0);
        CHECK(g_drv->w_update_orders(c, did, ov, 3) == 0);
        db_record_row_t rv[3];
        memset(rv, 0, sizeof(rv));
        rv[0] = (db_record_row_t){ 0, 3600, 0, false, true, false, "example.test", "RRSIG", "A 8 3 3600 20300101000000 20200101000000 1 example.test. x\"y\\z", "-" };
        rv[1] = (db_record_row_t){ 0, 0, 0, true, true, false, "www.example.test", "RRSIG", "A 8 3 3600 20300101000000 20200101000000 1 example.test. w", NULL };
        rv[2] = (db_record_row_t){ 0, 60, 5, false, false, false, "example.test", "DNSKEY", "257 3 8 AwEAAcvPyrbeMXE2", "k" };
        db_ins_t iv[3] = { { &rv[0], true }, { &rv[1], false }, { &rv[2], true } };
        CHECK(g_drv->w_insert_dnssec(c, did, iv, 0) == 0 && g_drv->w_insert_dnssec(c, did, iv, 3) == 0);
        CHECK(g_drv->w_commit(c) == 0);
        CHECK(qn("SELECT count(*) FROM records WHERE id = %lld AND ordername = 'o1' AND CAST(auth AS integer) = 0", (long long)id1) == 1);
        CHECK(qn("SELECT count(*) FROM records WHERE id = %lld AND ordername IS NULL AND CAST(auth AS integer) = 1", (long long)(id1 + 1)) == 1);
        CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND content LIKE '%%x\"y%%z' AND ttl = 3600 AND prio IS NULL AND ordername = '-'") == 1);
        CHECK(qn("SELECT count(*) FROM records WHERE type = 'RRSIG' AND name = 'www.example.test' AND ttl IS NULL AND CAST(auth AS integer) = 0 AND ordername IS NULL") == 1);
        CHECK(qn("SELECT count(*) FROM records WHERE type = 'DNSKEY' AND ttl = 60 AND prio = 5 AND ordername = 'k'") == 1);
        CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_set_snapshot(c, true) == -1);                                     /* not in a transaction */
        CHECK(g_drv->w_rollback(c) == 0);
        CHECK(g_drv->w_set_snapshot(c, true) == 0);                                                                                 /* the next transaction is one snapshot */
        CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_update_record(c, did, id1, NULL, "snap", true) == 0 && g_drv->w_commit(c) == 0);
        CHECK(qn("SELECT count(*) FROM records WHERE id = %lld AND ordername = 'snap'", (long long)id1) == 1);
#ifdef KARIDNS_DB_POSTGRESQL
        if (g_be == BE_PG) {
            /* a row changed by another session after the snapshot is a serialization failure (40001): DB_ERR_CONFLICT, not a failure */
            CHECK(g_drv->w_begin(c, "example.test") == 0);
            be_exec("UPDATE records SET ttl = ttl WHERE type = 'SOA'");                                                         /* another session commits a new version */
            CHECK(g_drv->w_update_record(c, did, id1, NULL, "snap2", true) == DB_ERR_CONFLICT);
            CHECK(g_drv->w_rollback(c) == 0);
            CHECK(g_drv->w_set_snapshot(c, false) == 0);
            CHECK(g_drv->w_begin(c, "example.test") == 0);                                                                      /* read committed: the update goes through */
            be_exec("UPDATE records SET ttl = ttl WHERE type = 'SOA'");
            CHECK(g_drv->w_update_record(c, did, id1, NULL, "snap2", true) == 0 && g_drv->w_commit(c) == 0);
        }
#endif
    }
    CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_mark(c, &mark) == 0);
    CHECK(g_drv->w_update_record(c, did, id1, "ns1.example.test hostmaster.example.test 2 7200 3600 1209600 300", "o2", true) == 0);
    CHECK(g_drv->w_insert_meta(c, did, "K", "v") == 0 && g_drv->w_write_id(c, mark, &wid) == 0);
    if (g_be == BE_PG) CHECK(wid.xid[0] != '\0' && wid.seq_first == 0 && wid.seq_last == 0);
    else CHECK(wid.xid[0] == '\0' && wid.seq_first > 0 && wid.seq_last >= wid.seq_first);
    CHECK(g_drv->w_commit(c) == 0);
    CHECK(qn("SELECT count(*) FROM records WHERE id = %lld AND ordername = 'o2' AND content LIKE '%% 2 7200 %%'", (long long)id1) == 1);
    g_drv->close(c);
    /* a database without karidns_changes: no range */
    be_fresh(false);
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0 && g_drv->check_schema(c, &si) == 0 && !si.has_changes);
    CHECK(g_drv->w_begin(c, "x.test") == 0 && g_drv->w_mark(c, &mark) == 0 && mark == 0 && g_drv->w_write_id(c, mark, &wid) == 0);
    CHECK(wid.seq_first == 0 && wid.seq_last == 0);
    CHECK(g_drv->w_rollback(c) == 0);
    g_drv->close(c);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* karidns-zone apply (items D and E): the change file, the generation, the diff, the versions                    */
/* ------------------------------------------------------------------------------------------------------------- */

static void t_changes_parser(void) {
    printf("  change file parser\n");
    zc_changes_t c;
    char err[300];
    const char *Z = "example.test.";
    const char *good = "# a comment\n\n  rr www.example.test. 300 A 192.0.2.1\r\nrr WWW.Example.TEST.\t300\ta  192.0.2.2   \ndelete old.example.test. txt\nrr example.test. 0 TXT \"v=spf1 -all\"\n"
                       "rr _x.example.test. 2147483647 TYPE65400 \\# 3 010203\nrr *.example.test. 1 MX 10 mail\nrr a-b/c.example.test. 5 TXT \"a;b ( c\"";
    CHECK(zc_parse(good, strlen(good), Z, &c, err, sizeof(err)));
    CHECK(c.n == 7 && c.n_rr == 6 && c.n_delete == 1);
    CHECK(strcmp(c.ops[1].owner, "www.example.test.") == 0 && strcmp(c.ops[1].type, "A") == 0 && strcmp(c.ops[1].rdata, "192.0.2.2") == 0);
    CHECK(strcmp(c.ops[2].type, "TXT") == 0 && c.ops[2].kind == ZC_DELETE && c.ops[2].line == 5);
    size_t tl = 0;
    char *text = zc_zone_text(&c, Z, &tl);
    CHECK(text && strncmp(text, "$ORIGIN example.test.\nwww.example.test. 300 IN A 192.0.2.1\n", 58) == 0 && strstr(text, "\n_x.example.test. 2147483647 IN TYPE65400 \\# 3 010203\n"));
    free(text);
    zc_free(&c);
    CHECK(c.ops == NULL && c.n == 0);
    static const struct { const char *text, *why; } bad[] = {
        { "frob x\n", "unknown operation" },
        { "rr www 300 A 192.0.2.1\n", "absolute" },
        { "rr www.example.org. 300 A 192.0.2.1\n", "not in the zone" },
        { "rr wwwexample.test. 300 A 192.0.2.1\n", "not in the zone" },
        { "rr exampxe.test. 300 A 192.0.2.1\n", "not in the zone" },                /* as long as the zone's name, but not its name */
        { "rr www.example.test.. 300 A 192.0.2.1\n", "empty label" },
        { "rr w$w.example.test. 300 A 192.0.2.1\n", "character" },
        { "rr www.example.test. 3x A 192.0.2.1\n", "TTL" },
        { "rr www.example.test. 2147483648 A 192.0.2.1\n", "2147483647" },
        { "rr www.example.test. 300\n", "type is missing" },
        { "rr www.example.test. 300 RRSIG A\n", "DNSSEC types" },
        { "rr www.example.test. 300 TYPE0047 \\# 0\n", "DNSSEC types" },
        { "rr www.example.test. 300 any 1.2.3.4\n", "meta types" },
        { "rr www.example.test. 300 1A x\n", "record type name" },
        { "rr www.example.test. 300 A\n", "RDATA is missing" },
        { "rr www.example.test. 300 TXT \"a\" ; $INCLUDE /etc/passwd\n", "not safe" },
        { "rr www.example.test. 300 TXT \"open\n", "not safe" },
        { "rr www.example.test. 300 TXT ( a\n", "not safe" },
        { "rr www.example.test. 300 TXT a\\\n", "not safe" },
        { "rr www.example.test. 300 TXT $ORIGIN\n", "not safe" },
        { "rr www.example.test. 300 TXT a\rb\n", "not safe" },
        { "delete www.example.test. A 300\n", "nothing more" },
        { "delete www.example.test.\n", "type is missing" },
        { "delete\n", "owner is missing" },
        { "delete www.example.test. A\nrr www.example.test. 300 A 192.0.2.1\n", "deleted here" },
        { "rr www.example.test. 300 A 192.0.2.1\ndelete www.example.test. a\n", "deleted here" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bool ok = zc_parse(bad[i].text, strlen(bad[i].text), Z, &c, err, sizeof(err));
        CHECK_MSG(!ok && strstr(err, bad[i].why) != NULL, "'%.60s': %s", bad[i].text, ok ? "accepted" : err);
        CHECK(c.n == 0 && c.ops == NULL);
    }
    CHECK(!zc_parse("rr www.example.test. 300 A 1\0 2\n", 33, Z, &c, err, sizeof(err)) && strstr(err, "NUL"));
    char *big = malloc(ZC_MAX_LINE + 200);
    memset(big, 'a', ZC_MAX_LINE + 100);
    memcpy(big, "rr www.example.test. 300 TXT ", 29);
    big[ZC_MAX_LINE + 100] = '\0';
    CHECK(!zc_parse(big, strlen(big), Z, &c, err, sizeof(err)) && strstr(err, "longer than"));
    free(big);
    CHECK(zc_type_refused("NSEC3PARAM") && zc_type_refused("TYPE250") && !zc_type_refused("TYPE65400") && !zc_type_refused("TYPE12x") && !zc_type_refused("A"));
}

/* apply with a connection of its own: ZI_OK / ZI_FAIL / ZI_BUSY / ZI_CHANGED, -2 when the change file is refused, -1 when the options were */
static int app(const zi_opts_t *o, const char *zone, const char *changes, const zi_apply_in_t *tmpl, zi_result_t *r) {
    zc_changes_t ch;
    char err[300];
    if (!zc_parse(changes, strlen(changes), zone, &ch, err, sizeof(err))) {
        printf("  [FAIL] change file: %s\n", err);
        g_failed++;
        return -2;
    }
    zi_t *z = zi_open(o);
    if (!z) {
        zc_free(&ch);
        return -1;
    }
    zi_apply_in_t in;
    memset(&in, 0, sizeof(in));
    if (tmpl) in = *tmpl;
    in.zone = zone;
    in.changes = &ch;
    in.shown = "changes";
    int st = zi_apply_changes(z, &in, r);
    zi_close(z);
    zc_free(&ch);
    return st;
}

static const zi_change_t *item_of(const zi_result_t *r, const char *owner, const char *type) {
    for (size_t i = 0; i < r->n_items; i++)
        if (strcmp(r->items[i].owner, owner) == 0 && strcmp(r->items[i].type, type) == 0) return &r->items[i];
    return NULL;
}

static void t_apply(void) {
    printf("  apply\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, NULL) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions") == 1);
    CHECK(qn("SELECT count(*) FROM karidns_zone_version_rrsets WHERE version_id = (SELECT id FROM karidns_zone_versions)") == 6);        /* the import is version 1: every RRset, SOA included */
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions WHERE version = 1 AND kind = 'import' AND serial_before IS NULL AND serial_after = 10 AND generation_before = 0 "
             "AND generation_after > 0 AND delta_complete") == 1);
    o.serial = ZI_SERIAL_INCREMENT;
    o.snapshot = true;
    const char *Z = "example.test.";
    const char *chg = "rr www.example.test. 300 A 192.0.2.10\nrr www.example.test. 300 A 192.0.2.11\ndelete mail.example.test. MX\nrr new.example.test. 60 TXT \"hello world\"\n";
    zi_result_t r;
    long recs = nrec("example.test"), vers = qn("SELECT count(*) FROM karidns_zone_versions"), chgs = nchg();

    /* a dry run: the diff and the version it would write, nothing stays */
    zi_opts_t od = o;
    od.dry_run = true;
    CHECK(app(&od, Z, chg, NULL, &r) == ZI_OK);
    CHECK(r.has_generation && r.generation > 0 && r.generation_after > r.generation && r.has_version && r.version == 2 && r.serial_bumped && r.old_serial == 10 && r.new_serial == 11);
    CHECK(r.n_items == 3 && r.rrsets_added == 1 && r.rrsets_replaced == 1 && r.rrsets_deleted == 1 && !r.committed && r.delta_complete);
    const zi_change_t *w = item_of(&r, "www.example.test", "A");
    CHECK(w && w->what == '~' && w->before && strcmp(w->before, "3600 A 192.0.2.80") == 0 && w->after && strcmp(w->after, "300 A 192.0.2.10\n300 A 192.0.2.11") == 0);
    const zi_change_t *m = item_of(&r, "mail.example.test", "MX");
    CHECK(m && m->what == '-' && strcmp(m->before, "3600 MX 10 mx.example.test.") == 0 && m->after == NULL);
    const zi_change_t *n = item_of(&r, "new.example.test", "TXT");
    CHECK(n && n->what == '+' && n->before == NULL && strcmp(n->after, "60 TXT \"hello world\"") == 0);
    CHECK(r.records_before == 6 && r.records_after == 6 + 1 - 1 + 1);
    uint64_t gen0 = r.generation;
    zi_result_free(&r);
    CHECK(nrec("example.test") == recs && qn("SELECT count(*) FROM karidns_zone_versions") == vers && nchg() == chgs && serial_of("example.test") == 10);

    /* the generation the caller expects */
    zi_apply_in_t in;
    memset(&in, 0, sizeof(in));
    in.have_expect = true;
    in.expect_generation = gen0 + 1;
    log_reset();
    CHECK(app(&o, Z, chg, &in, &r) == ZI_CHANGED);
    LOG_HAS("db.import.changed");
    zi_result_free(&r);
    CHECK(nrec("example.test") == recs && serial_of("example.test") == 10);

    /* the real change: the principal, the change set, the comment */
    in.expect_generation = gen0;
    in.actor.has_principal = true;
    in.actor.principal_id = 42;
    in.actor.principal_name = "alice";
    in.actor.change_set = "cs-1";
    in.comment = "move www";
    log_reset();
    CHECK(app(&o, Z, chg, &in, &r) == ZI_OK);
    CHECK(r.committed && r.has_version && r.version == 2 && r.generation == gen0 && r.generation_after > gen0 && r.serial_bumped && serial_of("example.test") == 11);
    CHECK(qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A' AND ttl = 300") == 2 && qn("SELECT count(*) FROM records WHERE type = 'MX'") == 0);
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions WHERE version = 2 AND kind = 'edit' AND change_set = 'cs-1' AND principal_id = 42 AND comment = 'move www' "
             "AND serial_before = 10 AND serial_after = 11 AND generation_before = %lld AND generation_after = %lld AND rollback_of IS NULL", (long long)gen0, (long long)r.generation_after) == 1);
    CHECK(qn("SELECT count(*) FROM karidns_zone_version_rrsets WHERE version_id = (SELECT id FROM karidns_zone_versions WHERE version = 2)") == 3);       /* the serial of the SOA is not versioned */
    CHECK(qn("SELECT count(*) FROM karidns_zone_version_rrsets s JOIN karidns_zone_versions v ON v.id = s.version_id WHERE v.version = 2 AND s.owner = 'mail.example.test' "
             "AND s.type = 'MX' AND s.before = '3600 MX 10 mx.example.test.' AND s.after IS NULL") == 1);
    zi_result_free(&r);
    CHECK(app(&o, Z, chg, NULL, &r) == ZI_OK && r.n_items == 0);                  /* the same change again changes nothing */
    zi_result_free(&r);

    /* nothing changes: no items, no version, no new serial */
    memset(&in, 0, sizeof(in));
    CHECK(app(&o, Z, "rr new.example.test. 60 TXT \"hello world\"\ndelete nothing.example.test. A\n", &in, &r) == ZI_OK);
    CHECK(r.n_items == 0 && !r.has_version && !r.serial_bumped && r.committed && serial_of("example.test") == 11 && qn("SELECT count(*) FROM karidns_zone_versions") == 2);
    zi_result_free(&r);

    /* an SOA in the change set: the serial rule of the import; the SOA RRset is in the diff, its serial alone is not versioned */
    CHECK(app(&o, Z, "rr example.test. 3600 SOA ns1.example.test. hostmaster.example.test. 500 7200 3600 1209600 300\n", NULL, &r) == ZI_OK);
    CHECK(!r.serial_bumped && r.wrote_soa && r.new_serial == 12 && serial_of("example.test") == 12 && r.n_items == 1 && !r.has_version);          /* increment: database serial + 1 */
    zi_result_free(&r);
    zi_opts_t og = o;
    og.serial = ZI_SERIAL_GROW;
    CHECK(app(&og, Z, "rr example.test. 3600 SOA ns1.example.test. hostmaster.example.test. 3 7200 3600 1209600 300\n", NULL, &r) == ZI_FAIL);
    zi_result_free(&r);
    CHECK(app(&og, Z, "rr example.test. 3600 SOA ns1.example.test. hostmaster.example.test. 20 7200 3600 1209600 301\n", NULL, &r) == ZI_OK);
    CHECK(r.has_version && serial_of("example.test") == 20 && item_of(&r, "example.test", "SOA") != NULL);                                           /* a real change of the SOA is a version */
    zi_result_free(&r);

    /* the zone must be there / must not be there / must be primary; the SOA stays */
    log_reset();
    CHECK(app(&o, "nozone.test.", "rr www.nozone.test. 60 A 192.0.2.1\n", NULL, &r) == ZI_FAIL);
    LOG_HAS("db.apply.zone");
    zi_result_free(&r);
    zi_apply_in_t cr;
    memset(&cr, 0, sizeof(cr));
    cr.create = true;
    log_reset();
    CHECK(app(&o, Z, "rr example.test. 3600 SOA ns1.example.test. h.example.test. 1 1 1 1 1\nrr example.test. 3600 NS ns1.example.test.\nrr ns1.example.test. 3600 A 192.0.2.1\n", &cr, &r) == ZI_FAIL);
    LOG_HAS("db.apply.zone");
    zi_result_free(&r);
    log_reset();
    CHECK(app(&o, Z, "delete example.test. SOA\n", NULL, &r) == ZI_FAIL);
    LOG_HAS("db.apply.zone");
    zi_result_free(&r);
    be_exec("INSERT INTO domains (name, type, master) VALUES ('slave.test', 'SLAVE', '192.0.2.99')");
    log_reset();
    CHECK(app(&o, "slave.test.", "rr www.slave.test. 60 A 192.0.2.1\n", NULL, &r) == ZI_FAIL);
    LOG_HAS("db.apply.zone");
    zi_result_free(&r);

    /* create: a new zone is the whole change file, checked as a whole zone, with version 1 of kind create */
    log_reset();
    CHECK(app(&o, "made.test.", "rr made.test. 3600 SOA ns1.made.test. hostmaster.made.test. 7 7200 3600 1209600 300\nrr made.test. 3600 NS ns1.made.test.\nrr ns1.made.test. 3600 A 192.0.2.7\n"
              "rr www.made.test. 60 A 192.0.2.8\n", &cr, &r) == ZI_OK);
    CHECK(r.created && r.committed && r.generation == 0 && r.generation_after > 0 && r.has_version && r.version == 1 && r.n_items == 4 && serial_of("made.test") == 7);
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'made.test' AND v.kind = 'create' AND v.version = 1") == 1);
    zi_result_free(&r);
    log_reset();
    CHECK(app(&o, "made2.test.", "rr www.made2.test. 60 A 192.0.2.8\n", &cr, &r) == ZI_FAIL);                  /* a whole zone needs SOA and NS: the zone checks */
    LOG_HAS("zone.soa.missing");
    zi_result_free(&r);
    CHECK(qn("SELECT count(*) FROM domains WHERE name = 'made2.test'") == 0);

    /* the narrow read-back of the commit run: the rows written are read back and checked */
    zi_apply_in_t nr;
    memset(&nr, 0, sizeof(nr));
    nr.readback_changed = true;
    CHECK(app(&o, Z, "rr more.example.test. 60 MX 5 mail.example.test.\n", &nr, &r) == ZI_OK);
    CHECK(r.committed && r.has_version && qn("SELECT count(*) FROM records WHERE name = 'more.example.test' AND type = 'MX' AND prio = 5") == 1);
    zi_result_free(&r);
    /* ... and the whole-zone read-back refuses a CNAME beside other data, rolled back with its version row */
    long v_before = qn("SELECT count(*) FROM karidns_zone_versions");
    log_reset();
    CHECK(app(&o, Z, "rr www.example.test. 60 CNAME other.example.test.\n", NULL, &r) == ZI_FAIL);
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions") == v_before && qn("SELECT count(*) FROM records WHERE name = 'www.example.test' AND type = 'A'") == 2);
    zi_result_free(&r);
    /* a TTL 0 / a record the zone checks refuse */
    log_reset();
    CHECK(app(&o, Z, "rr bad.example.test. 60 MX 10\n", NULL, &r) == ZI_FAIL);
    zi_result_free(&r);

    /* a database without the version tables or the generation: the change is made, there is no version */
    be_fresh(false);
    CHECK(imp_zone(&o, "plain.test", 5, K_BODY, NULL) == ZI_OK);
    CHECK(app(&o, "plain.test.", "rr x.plain.test. 60 A 192.0.2.5\n", NULL, &r) == ZI_OK);
    CHECK(!r.has_generation && !r.has_version && r.serial_bumped && serial_of("plain.test") == 6);
    zi_result_free(&r);
    in.have_expect = true;
    in.expect_generation = 1;
    log_reset();
    CHECK(app(&o, "plain.test.", "rr y.plain.test. 60 A 192.0.2.5\n", &in, &r) == ZI_FAIL);
    LOG_HAS("db.import.schema");
    zi_result_free(&r);

    /* the zone is locked by another writer */
    be_fresh(true);
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, NULL) == ZI_OK);
    {
        char err[DB_ERRLEN];
        db_conn_t *c = NULL;
        CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0 && g_drv->w_begin(c, "example.test") == 0);
        log_reset();
        CHECK(app(&o, Z, "rr y.example.test. 60 A 192.0.2.5\n", NULL, &r) == ZI_BUSY);
        LOG_HAS("db.import.busy");
        zi_result_free(&r);
        CHECK(g_drv->w_rollback(c) == 0);
        g_drv->close(c);
    }
}

/* apply with a zone text (karidns-zone apply --zone-file): the text instead of a change file */
static int apptext(const zi_opts_t *o, const char *zone, const char *text, const zi_apply_in_t *tmpl, zi_result_t *r) {
    zi_t *z = zi_open(o);
    if (!z) return -1;
    zi_apply_in_t in;
    memset(&in, 0, sizeof(in));
    if (tmpl) in = *tmpl;
    in.zone = zone;
    in.zone_text = text;
    in.zone_text_len = strlen(text);
    in.shown = "zone text";
    int st = zi_apply_changes(z, &in, r);
    zi_close(z);
    return st;
}

static void t_apply_text(void) {
    printf("  apply with a zone text\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    o.serial = ZI_SERIAL_INCREMENT;
    o.snapshot = true;
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, NULL) == ZI_OK);
    const char *Z = "example.test.";
    zi_result_t r;

    /* merge: the RRsets of the text replace those of the zone, the rest stays; an apex SOA that differs in the serial only is not written, the serial is raised as for any change */
    char *t = zone_text("example.test", 777, "www IN A 192.0.2.81\nnew IN TXT \"x\"\n");
    long ns_id = qn("SELECT id FROM records WHERE name = 'ns1.example.test' AND type = 'A'"), apex_id = qn("SELECT id FROM records WHERE name = 'example.test' AND type = 'NS'");
    long www_id = qn("SELECT min(id) FROM records WHERE name = 'www.example.test'");
    CHECK(apptext(&o, Z, t, NULL, &r) == ZI_OK);
    /* the RRsets of the text that equal the zone's are not written again (a write that changes nothing is still a write: the audit log, row level security) */
    CHECK(qn("SELECT id FROM records WHERE name = 'ns1.example.test' AND type = 'A'") == ns_id && qn("SELECT id FROM records WHERE name = 'example.test' AND type = 'NS'") == apex_id);
    CHECK(qn("SELECT min(id) FROM records WHERE name = 'www.example.test'") != www_id && r.records_inserted == 2 && r.records_deleted == 1);
    CHECK(r.n_items == 2 && item_of(&r, "www.example.test", "A") && item_of(&r, "new.example.test", "TXT") && !r.wrote_soa && r.serial_bumped && serial_of("example.test") == 11);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'MX'") == 1 && qn("SELECT count(*) FROM records WHERE type = 'SOA'") == 1);
    zi_result_free(&r);
    free(t);

    /* replace (delete_others): what the text does not have goes, except the apex SOA; the text's www is the zone's already */
    t = zone_text("example.test", 11, "www IN A 192.0.2.81\n");
    zi_apply_in_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.delete_others = true;
    rep.kind = "import";
    CHECK(apptext(&o, Z, t, &rep, &r) == ZI_OK);
    CHECK(r.n_items == 3 && item_of(&r, "new.example.test", "TXT") && item_of(&r, "mail.example.test", "MX") && item_of(&r, "mx.example.test", "A") && r.rrsets_deleted == 3);
    CHECK(serial_of("example.test") == 12 && qn("SELECT count(*) FROM records WHERE type IN ('SOA', 'NS')") == 2 && qn("SELECT count(*) FROM karidns_zone_versions WHERE kind = 'import' AND version = 3") == 1);
    zi_result_free(&r);
    /* ... a text without an SOA keeps the SOA (the text is not a zone then: the checks of a part) */
    CHECK(apptext(&o, Z, "$ORIGIN example.test.\n$TTL 3600\n@ IN NS ns1.example.test.\nns1 IN A 192.0.2.1\nonly IN A 192.0.2.9\n", &rep, &r) == ZI_OK);
    CHECK(r.n_items == 2 && item_of(&r, "only.example.test", "A") && item_of(&r, "www.example.test", "A") && !r.wrote_soa);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'SOA'") == 1 && serial_of("example.test") == 13);
    zi_result_free(&r);
    free(t);

    /* an SOA that differs in more than the serial is written (and the serial is the database's + 1); names with and without the final dot are the same name */
    CHECK(apptext(&o, Z, "$ORIGIN example.test.\n$TTL 60\n@ IN SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 600\n", NULL, &r) == ZI_OK);
    CHECK(r.wrote_soa && !r.serial_bumped && serial_of("example.test") == 14 && item_of(&r, "example.test", "SOA"));
    zi_result_free(&r);
    be_exec("UPDATE records SET content = 'NS1.example.test. hostmaster.example.test. 14 7200 3600 1209600 600' WHERE type = 'SOA'");
    CHECK(apptext(&o, Z, "$ORIGIN example.test.\n$TTL 60\n@ IN SOA ns1.example.test. hostmaster.example.test. 99 7200 3600 1209600 600\n", NULL, &r) == ZI_OK);
    CHECK(r.n_items == 0 && !r.wrote_soa && serial_of("example.test") == 14);
    zi_result_free(&r);
    be_exec("UPDATE records SET content = 'ns1.example.test hostmaster.example.test 14 7200 3600 1209600 600' WHERE type = 'SOA'");

    /* what a zone text may not carry: the signer's data, tags, attributes; and what is not a zone text */
    const char *refused[] = {
        "$ORIGIN example.test.\n$TTL 60\nx IN A 192.0.2.1\nx IN RRSIG A 8 3 60 20350101000000 20250101000000 1 example.test. AAAA\n",
        "$ORIGIN example.test.\n$TTL 60\n@ IN DNSKEY 257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o\n",
        "$ORIGIN example.test.\n$TTL 60\n$LOCATION-TAG office 10.0.0.0/8\nx IN A 192.0.2.1\n",
        "$ORIGIN example.test.\n$TTL 60\n@ IN CDS 1 8 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD\n",
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        log_reset();
        CHECK(apptext(&o, Z, refused[i], NULL, &r) == ZI_FAIL);
        zi_result_free(&r);
    }
    LOG_HAS("db.apply.changes");
    log_reset();
    CHECK(apptext(&o, Z, "$ORIGIN example.test.\nthis is not a zone\n", NULL, &r) == ZI_FAIL);
    LOG_HAS("db.apply.changes");
    zi_result_free(&r);
    CHECK(apptext(&o, Z, "", NULL, &r) == ZI_FAIL);
    zi_result_free(&r);
    CHECK(serial_of("example.test") == 14 && qn("SELECT count(*) FROM records WHERE type IN ('RRSIG', 'DNSKEY', 'CDS')") == 0);

    /* a signer zone: its DNSSEC records stay when the text replaces the rest */
    be_exec("INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'example.test'");
    be_exec("INSERT INTO records (domain_id, name, type, content, ttl) SELECT id, 'example.test', 'DNSKEY', '257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o', 60 FROM domains WHERE name = 'example.test'");
    CHECK(apptext(&o, Z, "$ORIGIN example.test.\n$TTL 60\n@ IN NS ns1.example.test.\nns1 IN A 192.0.2.1\n", &rep, &r) == ZI_OK);
    CHECK(qn("SELECT count(*) FROM records WHERE type = 'DNSKEY'") == 1 && qn("SELECT count(*) FROM records WHERE type = 'SOA'") == 1);
    zi_result_free(&r);

    /* a new zone from a text: the text is the whole zone, version 1 has the kind create; a zone that is there is refused */
    zi_apply_in_t cr;
    memset(&cr, 0, sizeof(cr));
    cr.create = true;
    t = zone_text("textzone.test", 5, "www IN A 192.0.2.7\n");
    CHECK(apptext(&o, "textzone.test.", t, &cr, &r) == ZI_OK);
    CHECK(r.created && r.committed && r.version == 1 && serial_of("textzone.test") == 5 && qn("SELECT count(*) FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id "
                                                                                          "WHERE d.name = 'textzone.test' AND v.kind = 'create'") == 1);
    zi_result_free(&r);
    log_reset();
    CHECK(apptext(&o, "textzone.test.", t, &cr, &r) == ZI_FAIL);
    LOG_HAS("db.apply.zone");
    zi_result_free(&r);
    free(t);
    log_reset();
    CHECK(apptext(&o, "empty.test.", "$ORIGIN empty.test.\n", &cr, &r) == ZI_FAIL);
    zi_result_free(&r);
}

/* the driver functions of items D and E: the generation, the version rows and their numbers, the retention, the actor, the SOA serial */
static void t_apply_driver(void) {
    printf("  generation, versions, retention\n");
    be_fresh(true);
    zi_opts_t o = base_opts();
    CHECK(imp_zone(&o, "example.test", 10, K_BODY, NULL) == ZI_OK);
    char err[DB_ERRLEN];
    db_conn_t *c = NULL;
    db_schema_info_t si;
    CHECK(g_drv->open_write(&c, &g_src, err, sizeof(err)) == 0 && g_drv->check_schema(c, &si) == 0 && si.has_zone_state && si.has_versions);
    long did = qn("SELECT id FROM domains WHERE name = 'example.test'");
    uint64_t g0 = 0, g1 = 0, g2 = 0;
    uint32_t num = 0;
    int64_t vid = 0;
    CHECK(g_drv->w_zone_generation(c, did, &g0) == -1);                                               /* not in a transaction */
    CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_zone_generation(c, did, &g0) == 0 && g0 > 0);
    CHECK(g_drv->w_zone_generation(c, 9999, &g1) == 0 && g1 == 0);                                    /* a zone with no row has generation 0 */
    CHECK(g_drv->w_set_actor(c, NULL) == -1);                                                         /* inside a transaction */
    CHECK(g_drv->w_set_snapshot(c, false) == -1);
    CHECK(g_drv->w_rollback(c) == 0);
    /* a write grows the generation (once per transaction on PostgreSQL, per row on SQLite3: only the change counts) */
    db_actor_t a = { true, 42, "alice", "cs-9" };
    CHECK(g_drv->w_set_actor(c, &a) == 0);
    CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_insert_meta(c, did, "X-TEST", "1") == 0 && g_drv->w_zone_generation(c, did, &g1) == 0 && g1 > g0);
    CHECK(g_drv->w_insert_meta(c, did, "X-TEST", "2") == 0 && g_drv->w_zone_generation(c, did, &g2) == 0 && g2 >= g1);
    if (g_be == BE_PG) CHECK(g2 == g1);                                                               /* the first change of the transaction bumped it */
    /* a version row: the number is the zone's highest + 1; its RRset rows */
    db_version_t v;
    memset(&v, 0, sizeof(v));
    v.kind = "edit";
    v.change_set = "cs-9";
    v.has_principal = true;
    v.principal_id = 42;
    v.principal_name = "alice";
    v.db_role = g_be == BE_SQLITE ? "tester" : NULL;
    v.comment = "driver test";
    v.has_serial_before = v.has_serial_after = true;
    v.serial_before = 10;
    v.serial_after = 11;
    v.generation_before = g0;
    v.generation_after = g2;
    v.delta_complete = true;
    CHECK(g_drv->w_insert_version(c, did, &v, &num, &vid) == 0 && num == 2);                          /* the import made version 1 */
    CHECK(g_drv->w_insert_version_rrset(c, vid, "a.example.test", "A", NULL, "300 A 192.0.2.1") == 0);
    CHECK(g_drv->w_insert_version_rrset(c, vid, "a.example.test", "A", "x", "y") != 0);               /* the key is (version, owner, type) */
    CHECK(g_drv->w_rollback(c) == 0);
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions") == 1 && qn("SELECT count(*) FROM domainmetadata WHERE kind = 'X-TEST'") == 0);
    /* the retention: the newest N versions of a zone (the number in the trigger; here 3) */
    if (g_be == BE_SQLITE) {
        be_exec("DROP TRIGGER karidns_zone_versions_prune; CREATE TRIGGER karidns_zone_versions_prune AFTER INSERT ON karidns_zone_versions BEGIN "
                "DELETE FROM karidns_zone_version_rrsets WHERE version_id IN (SELECT id FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 3); "
                "DELETE FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 3; END");
    } else {
        be_exec("CREATE OR REPLACE FUNCTION karidns_zone_versions_prune_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$ BEGIN "
                "DELETE FROM karidns_zone_versions WHERE domain_id = NEW.domain_id AND version <= NEW.version - 3; RETURN NULL; END $$");
    }
    for (int i = 0; i < 6; i++) {
        CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_insert_version(c, did, &v, &num, &vid) == 0 && num == (uint32_t)(i + 2));
        CHECK(g_drv->w_insert_version_rrset(c, vid, "a.example.test", "A", NULL, "300 A 192.0.2.1") == 0 && g_drv->w_commit(c) == 0);
    }
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions") == 3 && qn("SELECT min(version) FROM karidns_zone_versions") == 5);
    CHECK(qn("SELECT count(*) FROM karidns_zone_version_rrsets") == 3);                               /* the rows of the pruned versions went with them */
    CHECK(qn("SELECT count(*) FROM karidns_zone_versions WHERE principal_id = 42 AND principal_name = 'alice' AND change_set = 'cs-9'") == 3);
    /* the serial of the SOA */
    long sid = qn("SELECT id FROM records WHERE type = 'SOA'");
    uint32_t ser = 11;
    CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_bump_serial(c, did, sid, "ns1.example.test hostmaster.example.test 11 7200 3600 1209600 300", false, &ser) == 0 && g_drv->w_commit(c) == 0);
    CHECK(serial_of("example.test") == 11);
    CHECK(g_drv->w_begin(c, "example.test") == 0 && g_drv->w_bump_serial(c, did, 987654, "x", false, &ser) == DB_ERR_CONFLICT && g_drv->w_rollback(c) == 0);
    /* a zone that is deleted takes its state and its versions with it */
    be_exec("DELETE FROM domains WHERE name = 'example.test'");
    CHECK(qn("SELECT count(*) FROM karidns_zone_state") == 0 && qn("SELECT count(*) FROM karidns_zone_versions") == 0 && qn("SELECT count(*) FROM karidns_zone_version_rrsets") == 0);
    g_drv->close(c);
    /* the SQLite3 actor row: the principal, the name and the change set go to the audit log */
    if (g_be == BE_SQLITE) {
        be_fresh(true);
        sql_file("../../db/karidns_audit.sqlite3.sql");
        zi_opts_t oa = base_opts();
        oa.audit_actor = "karidns-zone:tester";
        zi_opts_t ob = oa;
        CHECK(imp_zone(&ob, "example.test", 10, K_BODY, NULL) == ZI_OK);
        oa.serial = ZI_SERIAL_INCREMENT;
        zi_result_t r;
        zi_apply_in_t in;
        memset(&in, 0, sizeof(in));
        in.actor = (db_actor_t){ true, 7, "bob", "cs-7" };
        CHECK(app(&oa, "example.test.", "rr q.example.test. 60 A 192.0.2.3\n", &in, &r) == ZI_OK);
        zi_result_free(&r);
        CHECK(qn("SELECT count(*) FROM karidns_audit_log WHERE principal_id = 7 AND principal_name = 'bob' AND change_set = 'cs-7' AND db_role = 'karidns-zone:tester' AND table_name = 'records'") == 2);
        CHECK(qn("SELECT count(*) FROM karidns_audit_actor") == 0);
        CHECK(qn("SELECT count(*) FROM karidns_zone_versions WHERE db_role = 'karidns-zone:tester' AND principal_name = 'bob'") == 1);
    }
}

static void run_scenarios(void) {
    if (g_be == BE_SQLITE) t_changes_parser();
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
    t_signer();
    t_signer_diff();
    t_export_signer();
    t_signer_canonical();
    t_signer_zone_import();
    t_signer_driver();
    t_apply();
    t_apply_text();
    t_apply_driver();
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
