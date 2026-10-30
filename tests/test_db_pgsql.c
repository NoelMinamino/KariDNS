/*
 * test_db_pgsql.c - the PostgreSQL driver (dns_db_pgsql.c, dns_db_driver.h; milestone B10).  The driver source is included, so the
 * static helpers are tested too.
 *
 * Needs a reachable PostgreSQL server (SKIP with the reason otherwise).  KARIDNS_TEST_PG is the conninfo of the maintenance
 * connection (default "dbname=postgres"); the role must be allowed to create databases.  Each run creates the database
 * karidns_test_unit_<pid> from tests/db/pdns_schema.pgsql.sql and db/karidns_ext.pgsql.sql and drops it at the end.
 *
 * Cases: conninfo-file checks (mode, bad string, no content in messages), schema check (missing table / column, version 3,
 * version 1 without xid / tagdefs.id, the v1 to v2 migration), rows (NULLs, second SOA, ENT, disabled NULL), more rows than one
 * FETCH, a scan the callback stops followed by another query in the same snapshot, snapshot isolation, per-schema search_path,
 * the order of the profiles (C collation) and of the tag definitions, the change log cursor with interleaved transactions
 * (a transaction that took a lower seq commits later: nothing is skipped; an idle transaction in front does not hide later
 * commits), the gap rule, notifications (LISTEN, wait_fd, poll_version), a terminated backend maps to DB_ERR_RETRY.
 * B11: karidns_reload_requests (reading order, NULL / named zone, force, generations pruned or rolled back are a gap, more rows than
 * one query, a callback that stops, the INSERT lock that makes generations visible in order, LISTEN karidns_reload) and
 * karidns_server_status (the upsert in its own READ WRITE transaction on a read only session, not inside a snapshot, a role
 * without INSERT, the connection usable afterwards, a source without the tables, a terminated backend).
 *
 * Usage: test_db_pgsql [tests/db]   (the directory of pdns_schema.pgsql.sql)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <poll.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef KARIDNS_DB_POSTGRESQL

#include "../dns_db_pgsql.c"

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

static const db_driver_t *D = &db_driver_postgresql;
static char g_maint[1024];          /* the maintenance conninfo */
static char g_db[96];               /* the test database */
static char g_dir[400];             /* temporary directory */
static char g_ci[460];              /* conninfo-file of the test database */
static char g_root[300];            /* tests/db */
static PGconn *g_admin;             /* connection of the test (writer / second session) */
static PGconn *g_maintc;            /* connection to the maintenance database */

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
        if (unlink(p) != 0) rmdir(p);                  /* the empty directory of test_conninfo */
    }
    closedir(d);
    rmdir(dir);
}

/* run SQL on a connection; a failure is a FAIL with the message */
static bool qx(PGconn *c, const char *sql) {
    PGresult *r = PQexec(c, sql);
    ExecStatusType st = r ? PQresultStatus(r) : PGRES_FATAL_ERROR;
    bool ok = st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK;
    if (!ok) {
        printf("  [FAIL] sql error: %s    %.200s\n", PQerrorMessage(c), sql);
        g_failed++;
    }
    PQclear(r);
    return ok;
}
#define Q(sql) qx(g_admin, (sql))

/* one value (first column of the first row) as text; "" for NULL / error */
static void qv(PGconn *c, const char *sql, char *out, size_t cap) {
    PGresult *r = PQexec(c, sql);
    out[0] = '\0';
    if (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) snprintf(out, cap, "%s", PQgetvalue(r, 0, 0));
    else if (!r || PQresultStatus(r) != PGRES_TUPLES_OK) {
        printf("  [FAIL] query error: %s    %.200s\n", PQerrorMessage(c), sql);
        g_failed++;
    }
    PQclear(r);
}

static PGconn *connect_db(const char *dbname) {
    char ci[1200];
    snprintf(ci, sizeof(ci), "%s dbname=%s", g_maint, dbname);
    PGconn *c = PQconnectdb(ci);
    if (PQstatus(c) != CONNECTION_OK) {
        printf("  [FAIL] cannot connect: %s", PQerrorMessage(c));
        g_failed++;
        PQfinish(c);
        return NULL;
    }
    PQsetNoticeReceiver(c, ignore_notice, NULL);
    return c;
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

static void write_ci(const char *dbname) {
    char content[1300];
    snprintf(content, sizeof(content), "# test\n%s\ndbname=%s\n", g_maint, dbname);
    write_file(g_ci, content, 0600);
}

static db_conn_t *open_drv(const char *schema) {
    db_source_t src = { "postgresql", NULL, g_ci, schema, 0 };
    char err[DB_ERRLEN];
    db_conn_t *c = NULL;
    int rc = D->open(&c, &src, err, sizeof(err));
    CHECK_MSG(rc == 0 && c, "open: %s", err);
    return rc == 0 ? c : NULL;
}

/* ---- callbacks that collect ---- */
typedef struct { int n; int64_t id[4000]; char name[8][64]; char type[8][16]; char master[8][32]; char soa[8][80]; bool soa_null[8]; bool master_null[8]; int stop_after; } zacc_t;
/* D1a step 6: scan_apex rows */
typedef struct { size_t n, nsoa, stop_after; int64_t first_dom; bool first_is_soa; char first_content[40]; } apx_t;
static int cb_apex(void *ud, const db_apex_row_t *r) {
    apx_t *a = ud;
    if (a->n == 0) {
        a->first_dom = r->domain_id;
        a->first_is_soa = r->is_soa;
        snprintf(a->first_content, sizeof(a->first_content), "%s", r->content ? r->content : "");
    }
    a->n++;
    a->nsoa += r->is_soa ? 1 : 0;
    return a->stop_after && a->n >= a->stop_after;
}

static int cb_zone(void *ud, const db_zone_row_t *z) {
    zacc_t *a = ud;
    if (a->n < 8) {
        snprintf(a->name[a->n], sizeof(a->name[0]), "%s", z->name ? z->name : "");
        snprintf(a->type[a->n], sizeof(a->type[0]), "%s", z->type ? z->type : "");
        a->master_null[a->n] = z->master == NULL;
        snprintf(a->master[a->n], sizeof(a->master[0]), "%s", z->master ? z->master : "");
        a->soa_null[a->n] = z->soa_content == NULL;
        snprintf(a->soa[a->n], sizeof(a->soa[0]), "%.70s", z->soa_content ? z->soa_content : "");
    }
    if (a->n < 4000) a->id[a->n] = z->id;
    a->n++;
    return a->stop_after && a->n >= a->stop_after;
}

typedef struct { int n; int64_t did[4000], id[4000]; db_record_row_t r[16]; char s[16][3][80]; } racc_t;
static int cb_rec(void *ud, int64_t did, const db_record_row_t *r) {
    racc_t *a = ud;
    if (a->n < 4000) {
        a->did[a->n] = did;
        a->id[a->n] = r->id;
    }
    if (a->n < 16) {
        a->r[a->n] = *r;
        snprintf(a->s[a->n][0], 80, "%s", r->name ? r->name : "<NULL>");
        snprintf(a->s[a->n][1], 80, "%s", r->type ? r->type : "<NULL>");
        snprintf(a->s[a->n][2], 80, "%s", r->ordername ? r->ordername : "<NULL>");
    }
    a->n++;
    return 0;
}

typedef struct { int n; int64_t v[64]; uint64_t seq[64]; } cacc_t;
static int cb_chg(void *ud, const db_change_row_t *r) {
    cacc_t *a = ud;
    if (a->n < 64) {
        a->v[a->n] = r->domain_id;
        a->seq[a->n] = r->seq;
    }
    a->n++;
    return 0;
}
static bool has_dom(const cacc_t *a, int64_t d) {
    for (int i = 0; i < a->n && i < 64; i++) if (a->v[i] == d) return true;
    return false;
}

static int cb_key(void *ud, int64_t id) {
    int *n = ud;
    *n = *n * 10 + (int)id;
    return 0;
}

typedef struct { int n; char kind[4][32]; int64_t d[4]; } macc_t;
static int cb_meta(void *ud, const db_meta_row_t *x) {
    macc_t *a = ud;
    if (a->n < 4) {
        a->d[a->n] = x->domain_id;
        snprintf(a->kind[a->n], 32, "%s", x->kind);
    }
    a->n++;
    return 0;
}

typedef struct { int n; char name[8][32]; } pacc_t;
static int cb_prof(void *ud, const db_profile_row_t *x) {
    pacc_t *a = ud;
    if (a->n < 8) snprintf(a->name[a->n], 32, "%s", x->name);
    a->n++;
    return 0;
}

typedef struct { int n; int64_t d[8]; char v[8][16]; } vacc_t;
static int cb_view(void *ud, int64_t d, const char *name) {
    vacc_t *a = ud;
    if (a->n < 8) {
        a->d[a->n] = d;
        snprintf(a->v[a->n], 16, "%s", name);
    }
    a->n++;
    return 0;
}

typedef struct { int tags, tdns, defs; int64_t def_dom[8]; char def_tag[8][16]; } xacc_t;
static int cb_xtag(void *ud, int64_t d, const db_tag_row_t *r) { xacc_t *a = ud; (void)d; a->tags++; return !r->location_tag; }
static int cb_xtdns(void *ud, int64_t d, const db_tinydns_row_t *r) {
    xacc_t *a = ud;
    (void)d;
    a->tdns++;
    return !(r->ttd_null && r->countdown && !strcmp(r->loc, "k"));
}
static int cb_xdef(void *ud, int64_t d, const db_tagdef_row_t *r) {
    xacc_t *a = ud;
    if (a->defs < 8) {
        a->def_dom[a->defs] = d;
        snprintf(a->def_tag[a->defs], 16, "%s", r->tag);
    }
    a->defs++;
    return 0;
}
static int cb_xcount(void *ud, int64_t d, const db_tagdef_row_t *r) { (void)d; (void)r; (*(int *)ud)++; return 0; }
static int cb_xnop_tag(void *ud, int64_t d, const db_tag_row_t *r) { (void)ud; (void)d; (void)r; return 0; }
static int cb_xnop_tdns(void *ud, int64_t d, const db_tinydns_row_t *r) { (void)ud; (void)d; (void)r; return 0; }

/* ------------------------------------------------------------------ the cases */
static void test_conninfo(void) {
    printf("conninfo-file\n");
    char err[DB_ERRLEN], path[460];
    db_conn_t *c = NULL;
    db_source_t src = { "postgresql", NULL, NULL, NULL, 0 };
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "no conninfo-file");
    snprintf(path, sizeof(path), "%s/ci_bad", g_dir);
    write_file(path, "host=localhost password=SECRETWORD123\n", 0644);
    src.conninfo_file = path;
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "mode 0600 or 0400");
    CHECK(strstr(err, "SECRETWORD123") == NULL);
    write_file(path, "host=localhost password=SECRETWORD123 =\n", 0600);
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "not valid");
    CHECK_MSG(strstr(err, "SECRETWORD123") == NULL, "the message must not echo the string: %s", err);
    write_file(path, "# only a comment\n   \n", 0600);
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "no connection string");
    write_file(path, "host=/nonexistent-dir-karidns port=1 dbname=x connect_timeout=2\n", 0400);
    int rc = D->open(&c, &src, err, sizeof(err));
    CHECK_MSG(rc == DB_ERR_RETRY, "an unreachable server is a retry: %d %s", rc, err);
    CHECK_HAS(err, "cannot connect");
    snprintf(path, sizeof(path), "%s/ci_missing", g_dir);
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "cannot open conninfo-file");
    char dirp[460];
    snprintf(dirp, sizeof(dirp), "%s/ci_dir", g_dir);
    mkdir(dirp, 0700);
    src.conninfo_file = dirp;
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "not a regular file");
    /* an empty file, a file with a NUL byte, a file that is too large: refused before libpq sees anything */
    snprintf(path, sizeof(path), "%s/ci_empty", g_dir);
    write_file(path, "", 0600);
    src.conninfo_file = path;
    CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
    CHECK_HAS(err, "empty or larger than");
    {
        int fd = open(path, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            CHECK(write(fd, "host=a\0b\n", 9) == 9);
            close(fd);
        }
        CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
        CHECK_HAS(err, "contains a NUL byte");
        char *big = malloc(PG_CONNINFO_MAX + 10);
        if (big) {
            memset(big, 'x', PG_CONNINFO_MAX + 8);
            big[PG_CONNINFO_MAX + 8] = '\0';
            write_file(path, big, 0600);
            CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
            CHECK_HAS(err, "empty or larger than");
            free(big);
        }
    }
    if (geteuid() == 0) {                       /* a file that another user owns (root only: nobody else can give a file away) */
        write_file(path, "host=localhost\n", 0600);
        CHECK(chown(path, 12345, 12345) == 0);
        CHECK(D->open(&c, &src, err, sizeof(err)) == -1);
        CHECK_HAS(err, "not owned by the user the loader runs as");
    }
    /* a schema name too long for the SET search_path statement */
    {
        char longname[600];
        memset(longname, 's', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        write_ci(g_db);
        db_source_t ls = { "postgresql", NULL, g_ci, longname, 0 };
        CHECK(D->open(&c, &ls, err, sizeof(err)) == -1);
        CHECK_HAS(err, "schema name is too long");
    }
    /* a comment line, line ends as blanks, an option of our own that the user may override */
    write_ci(g_db);
    db_conn_t *ok = open_drv(NULL);
    CHECK(ok != NULL);
    if (ok) {
        PGresult *r = PQexec(ok->pg, "SHOW application_name");
        CHECK(r && PQresultStatus(r) == PGRES_TUPLES_OK && strcmp(PQgetvalue(r, 0, 0), "karidns-dbloader") == 0);
        PQclear(r);
        r = PQexec(ok->pg, "SHOW default_transaction_read_only");
        CHECK(r && strcmp(PQgetvalue(r, 0, 0), "on") == 0);
        PQclear(r);
        D->close(ok);
    }
}

static void test_schema(void) {
    printf("schema\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    CHECK(si.has_changes && si.has_domain_views && si.has_profiles && si.has_ext);
    CHECK(c->has_tagdef_id);
    CHECK(D->changes_unsettled);

    /* a missing PowerDNS table, a missing column (the error says which) */
    Q("ALTER TABLE domainmetadata RENAME TO domainmetadata_x");
    CHECK(D->check_schema(c, &si) == -1);
    CHECK_HAS(D->errmsg(c), "table domainmetadata is missing");
    Q("ALTER TABLE domainmetadata_x RENAME TO domainmetadata");
    Q("ALTER TABLE records RENAME COLUMN ordername TO ordername_x");
    CHECK(D->check_schema(c, &si) == -1);
    CHECK_HAS(D->errmsg(c), "table records has no column ordername");
    Q("ALTER TABLE records RENAME COLUMN ordername_x TO ordername");
    CHECK(D->check_schema(c, &si) == 0);

    /* a newer schema version */
    Q("UPDATE karidns_schema_version SET version = 3");
    CHECK(D->check_schema(c, &si) == -1);
    CHECK_HAS(D->errmsg(c), "versions 1 and 2");
    Q("UPDATE karidns_schema_version SET version = 2");
    CHECK(D->check_schema(c, &si) == 0);

    /* a table of the optional set missing: no change log, no mapping */
    Q("ALTER TABLE karidns_domain_views RENAME TO karidns_domain_views_x");
    CHECK(D->check_schema(c, &si) == 0 && !si.has_domain_views && si.has_changes);
    CHECK(D->scan_domain_views(c, NULL, NULL, NULL) == DB_ERR_UNAVAILABLE);
    Q("ALTER TABLE karidns_domain_views_x RENAME TO karidns_domain_views");

    /* a schema that does not exist */
    D->close(c);
    c = open_drv("karidns_test_no_such_schema");
    if (c) {
        CHECK(D->check_schema(c, &si) == -1);
        CHECK_HAS(D->errmsg(c), "does not exist");
        D->close(c);
    }
}

/* B12: schema_findings() (`karicheck db`): all faults at once, the triggers by name, the multi-server tables, the privileges */
typedef struct { char text[4096]; } fnd_t;
static void fnd_sink(void *ud, char level, const char *text) {
    fnd_t *f = ud;
    size_t l = strlen(f->text);
    snprintf(f->text + l, sizeof(f->text) - l, "%c:%s\n", level, text);
}

static void test_schema_findings(void) {
    printf("schema findings (B12)\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    fnd_t f;
    db_check_opts_t o = { true, "ns1" };
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK(strstr(f.text, "E:") == NULL);                                         /* everything is there, triggers too */
    CHECK_HAS(f.text, "I:karidns_* schema version 2");

    /* several faults at once: all named */
    Q("ALTER TABLE records RENAME COLUMN ordername TO ordername_x; ALTER TABLE records RENAME COLUMN prio TO prio_x");
    Q("ALTER TABLE domainmetadata RENAME TO domainmetadata_x");
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK_HAS(f.text, "E:table records has no column prio, ordername (PowerDNS 5.1 schema expected)");
    CHECK_HAS(f.text, "E:table domainmetadata is missing (PowerDNS 5.1 schema expected)");
    Q("ALTER TABLE records RENAME COLUMN ordername_x TO ordername; ALTER TABLE records RENAME COLUMN prio_x TO prio");
    Q("ALTER TABLE domainmetadata_x RENAME TO domainmetadata");

    /* a trigger missing: an error only with auto-reload */
    Q("ALTER TRIGGER karidns_trg_records_upd ON records RENAME TO karidns_trg_records_upd_x");
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK_HAS(f.text, "E:auto-reload yes needs the change log triggers, but 1 are missing: karidns_trg_records_upd");
    o.auto_reload = false;
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK(strstr(f.text, "trigger") == NULL);
    Q("ALTER TRIGGER karidns_trg_records_upd_x ON records RENAME TO karidns_trg_records_upd");

    /* the multi-server tables: one of two; none with a server-id */
    Q("ALTER TABLE karidns_server_status RENAME TO karidns_server_status_x");
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK_HAS(f.text, "W:only one of karidns_reload_requests and karidns_server_status exists");
    Q("ALTER TABLE karidns_reload_requests RENAME TO karidns_reload_requests_x");
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK_HAS(f.text, "W:server-id is set but karidns_reload_requests and karidns_server_status do not exist");
    o.server_id = NULL;
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK(strstr(f.text, "server-id") == NULL && strstr(f.text, "only one of") == NULL);
    Q("ALTER TABLE karidns_reload_requests_x RENAME TO karidns_reload_requests; ALTER TABLE karidns_server_status_x RENAME TO karidns_server_status");

    /* no extension table at all, and the version-1 change log */
    Q("ALTER TABLE karidns_changes RENAME COLUMN xid TO xid_x");
    memset(&f, 0, sizeof(f));
    CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
    CHECK_HAS(f.text, "W:table karidns_changes has no xid column (schema version 1)");
    Q("ALTER TABLE karidns_changes RENAME COLUMN xid_x TO xid");

    /* a schema that does not exist */
    D->close(c);
    c = open_drv("karidns_test_no_such_schema");
    if (c) {
        memset(&f, 0, sizeof(f));
        CHECK(D->schema_findings(c, &o, fnd_sink, &f) == 0);
        CHECK_HAS(f.text, "E:the database-schema does not exist");
        D->close(c);
    }
}

static void test_rows(void) {
    printf("rows\n");
    Q("INSERT INTO domains (id, name, type, master, catalog) VALUES (1, 'a.test', 'NATIVE', NULL, NULL), (2, 'b.test', 'SLAVE', '192.0.2.1', 'cat.test'), (3, 'c.test', 'MASTER', NULL, NULL)");
    Q("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES "
      "(1, 'a.test', 'SOA', 'ns.a.test h.a.test 1 3600 600 86400 300', 3600, NULL, false, NULL),"
      "(1, 'a.test', 'SOA', 'ns2.a.test h.a.test 9 3600 600 86400 300', 3600, NULL, false, NULL),"
      "(1, 'www.a.test', 'A', '192.0.2.1', NULL, NULL, false, 'wwwx'),"
      "(1, 'mx.a.test', 'MX', 'mail.a.test', 60, 10, NULL, NULL),"
      "(1, 'a.test', 'TXT', 'off', 60, NULL, true, NULL),"
      "(1, 'ent.a.test', NULL, NULL, NULL, NULL, false, 'e'),"
      "(3, 'c.test', 'SOA', 'ns.c.test h.c.test 1 3600 600 86400 300', 60, NULL, true, NULL)");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    CHECK(D->scan_records(c, NULL, cb_rec, &(racc_t){0}) == -1);       /* no snapshot */
    CHECK_HAS(D->errmsg(c), "no snapshot");
    CHECK(D->begin_snapshot(c) == 0);
    CHECK(D->begin_snapshot(c) == -1);                                 /* already open */
    zacc_t *z = calloc(1, sizeof(*z));
    CHECK(D->list_zones(c, cb_zone, z) == 0);
    CHECK(z->n == 3);
    CHECK(z->id[0] == 1 && z->id[1] == 2 && z->id[2] == 3);
    CHECK(!strcmp(z->name[0], "a.test") && !strcmp(z->type[0], "NATIVE") && z->master_null[0]);
    CHECK_MSG(!z->soa_null[0] && !strncmp(z->soa[0], "ns.a.test ", 10), "first enabled apex SOA: %s", z->soa[0]);
    CHECK(!strcmp(z->type[1], "SLAVE") && !z->master_null[1] && !strcmp(z->master[1], "192.0.2.1") && z->soa_null[1]);
    CHECK(z->soa_null[2]);                                             /* the only SOA is disabled */
    memset(z, 0, sizeof(*z));
    z->stop_after = 2;
    CHECK(D->list_zones(c, cb_zone, z) == DB_STOPPED && z->n == 2);    /* stopped scan, then another query works */

    /* D1a step 6 scan_apex: the enabled SOA and NS rows at the apex, in domain id order (a.test has two enabled SOA rows, the one with the smaller id first) */
    {
        apx_t ap;
        memset(&ap, 0, sizeof(ap));
        CHECK(D->scan_apex != NULL && D->scan_apex(c, NULL, cb_apex, &ap) == 0 && ap.n >= 1);
        CHECK(ap.first_dom == 1 && ap.first_is_soa && !strncmp(ap.first_content, "ns.a.test ", 10));
        memset(&ap, 0, sizeof(ap));
        int64_t one = 3;
        CHECK(D->scan_apex(c, &one, cb_apex, &ap) == 0 && ap.nsoa == 0);        /* (the only SOA of zone 3 is disabled) */
        memset(&ap, 0, sizeof(ap));
        ap.stop_after = 1;
        CHECK(D->scan_apex(c, NULL, cb_apex, &ap) == DB_STOPPED && ap.n == 1);
    }

    /* B13 find_zone: the same row as the list, by name: exact spelling by index, other capitals / trailing dot by the lower() fallback */
    memset(z, 0, sizeof(*z));
    CHECK(D->find_zone(c, "b.test", cb_zone, z) == 0 && z->n == 1 && z->id[0] == 2 && !strcmp(z->type[0], "SLAVE") && z->soa_null[0]);
    memset(z, 0, sizeof(*z));
    CHECK(D->find_zone(c, "A.TEST.", cb_zone, z) == 0 && z->n == 1 && z->id[0] == 1 && !strncmp(z->soa[0], "ns.a.test ", 10));   /* two SOAs: the first */
    memset(z, 0, sizeof(*z));
    CHECK(D->find_zone(c, "c.test.", cb_zone, z) == 0 && z->n == 1 && z->id[0] == 3 && z->soa_null[0]);
    memset(z, 0, sizeof(*z));
    CHECK(D->find_zone(c, "nope.test", cb_zone, z) == 0 && z->n == 0);
    CHECK(D->find_zone(c, "a.test..", cb_zone, z) == 0 && z->n == 0);
    CHECK(D->find_zone(c, "a.tes", cb_zone, z) == 0 && z->n == 0);
    z->stop_after = 1;
    CHECK(D->find_zone(c, "a.test", cb_zone, z) == DB_STOPPED && z->n == 1);
    memset(z, 0, sizeof(*z));
    CHECK(D->list_zones(c, cb_zone, z) == 0 && z->n == 3);              /* the cursor was closed: the next query works */

    racc_t *r = calloc(1, sizeof(*r));
    CHECK(D->scan_records(c, NULL, cb_rec, r) == 0);
    CHECK(r->n == 7);
    CHECK(r->did[0] == 1 && r->did[6] == 3);
    int www = -1, mx = -1, txt = -1, ent = -1;
    for (int i = 0; i < r->n && i < 16; i++) {
        if (!strcmp(r->s[i][0], "www.a.test")) www = i;
        if (!strcmp(r->s[i][0], "mx.a.test")) mx = i;
        if (!strcmp(r->s[i][1], "TXT")) txt = i;
        if (!strcmp(r->s[i][0], "ent.a.test")) ent = i;
    }
    CHECK(www >= 0 && r->r[www].ttl_null && r->r[www].prio_null && !r->r[www].disabled && !strcmp(r->s[www][2], "wwwx"));
    CHECK(mx >= 0 && !r->r[mx].ttl_null && r->r[mx].ttl == 60 && !r->r[mx].prio_null && r->r[mx].prio == 10);
    CHECK_MSG(mx >= 0 && r->r[mx].disabled, "a NULL disabled is a disabled row");
    CHECK(txt >= 0 && r->r[txt].disabled);
    CHECK(ent >= 0 && r->r[ent].type == NULL && r->r[ent].content == NULL && !strcmp(r->s[ent][1], "<NULL>"));
    racc_t *r1 = calloc(1, sizeof(*r1));
    int64_t one = 1;
    CHECK(D->scan_records(c, &one, cb_rec, r1) == 0 && r1->n == 6);
    for (int i = 1; i < r1->n; i++) CHECK(r1->id[i - 1] < r1->id[i]);
    racc_t *rr = calloc(1, sizeof(*rr));
    CHECK(D->scan_records_range(c, 1, 2, cb_rec, rr) == 0 && rr->n == 6);
    memset(rr, 0, sizeof(*rr));
    CHECK(D->scan_records_range(c, 3, 3, cb_rec, rr) == 0 && rr->n == 1);

    /* snapshot isolation: a commit by another session is not seen inside the open snapshot */
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'late.b.test', 'A', '192.0.2.9', 60)");
    memset(r, 0, sizeof(*r));
    CHECK(D->scan_records(c, NULL, cb_rec, r) == 0 && r->n == 7);
    CHECK(D->end_snapshot(c) == 0);
    CHECK(D->begin_snapshot(c) == 0);
    memset(r, 0, sizeof(*r));
    CHECK(D->scan_records(c, NULL, cb_rec, r) == 0 && r->n == 8);

    /* more rows than one FETCH, in order, and a bulk scan equals per-zone scans */
    Q("INSERT INTO records (domain_id, name, type, content, ttl) SELECT 3, 'h' || g || '.c.test', 'A', '192.0.2.' || (g % 250 + 1), 60 FROM generate_series(1, 2600) g");
    CHECK(D->end_snapshot(c) == 0);
    CHECK(D->begin_snapshot(c) == 0);
    memset(r, 0, sizeof(*r));
    CHECK(D->scan_records(c, NULL, cb_rec, r) == 0);
    CHECK_MSG(r->n == 2608, "%d rows", r->n);
    bool ordered = true;
    for (int i = 1; i < r->n && i < 4000; i++) if (r->did[i - 1] > r->did[i] || (r->did[i - 1] == r->did[i] && r->id[i - 1] >= r->id[i])) ordered = false;
    CHECK(ordered);
    int64_t three = 3;
    memset(r1, 0, sizeof(*r1));
    CHECK(D->scan_records(c, &three, cb_rec, r1) == 0 && r1->n == 2601);
    memset(rr, 0, sizeof(*rr));
    CHECK(D->scan_records_range(c, 2, 3, cb_rec, rr) == 0 && rr->n == 2602);

    /* metadata, keys */
    D->end_snapshot(c);
    Q("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'PRESIGNED', '1'), (1, 'ALLOW-AXFR-FROM', '192.0.2.1'), (3, 'SOA-EDIT', 'INCEPTION-EPOCH')");
    Q("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (3, 257, true, 'SECRET-KEY-CONTENT'), (1, 256, true, 'x'), (3, 256, true, 'y')");
    D->begin_snapshot(c);
    int keys = 0;
    CHECK(D->zones_with_keys(c, cb_key, &keys) == 0 && keys == 13);
    macc_t m = {0};
    CHECK(D->scan_metadata(c, NULL, cb_meta, &m) == 0 && m.n == 3 && m.d[0] == 1 && !strcmp(m.kind[0], "PRESIGNED") && m.d[2] == 3);
    memset(&m, 0, sizeof(m));
    CHECK(D->scan_metadata(c, &three, cb_meta, &m) == 0 && m.n == 1);
    D->end_snapshot(c);
    D->close(c);
    free(z);
    free(r);
    free(r1);
    free(rr);
}

/* list_zones / find_zone: which SOA row a zone gets (the join on records is by the plain name, with a per-zone fallback to the
 * case-insensitive comparison) */
typedef struct { int n; int64_t id[4000]; char type[4000][12]; char soa[4000][24]; bool soa_null[4000]; bool master_null[4000]; bool cat_null[4000]; } szacc_t;
static int cb_szone(void *ud, const db_zone_row_t *z) {
    szacc_t *a = ud;
    if (a->n < 4000) {
        a->id[a->n] = z->id;
        snprintf(a->type[a->n], sizeof(a->type[0]), "%s", z->type ? z->type : "");
        a->soa_null[a->n] = z->soa_content == NULL;
        snprintf(a->soa[a->n], sizeof(a->soa[0]), "%.23s", z->soa_content ? z->soa_content : "");
        a->master_null[a->n] = z->master == NULL;
        a->cat_null[a->n] = z->catalog == NULL;
    }
    a->n++;
    return 0;
}

static void test_zone_soa(void) {
    printf("zone list: the apex SOA\n");
    Q("CREATE SCHEMA karidns_test_s2");
    char path[500];
    snprintf(path, sizeof(path), "%s/pdns_schema.pgsql.sql", g_root);
    char *sql = slurp(path);
    snprintf(path, sizeof(path), "%s/../../db/karidns_ext.pgsql.sql", g_root);
    char *ext = slurp(path);
    CHECK(sql != NULL && ext != NULL);
    if (!sql || !ext) {
        free(sql);
        free(ext);
        return;
    }
    Q("SET search_path TO karidns_test_s2");
    Q(sql);
    Q(ext);
    free(sql);
    free(ext);
    /* names in capitals can only exist when the schema's CHECK constraints are gone */
    Q("ALTER TABLE records DROP CONSTRAINT c_lowercase_name");
    Q("ALTER TABLE domains DROP CONSTRAINT c_lowercase_name");
    Q("INSERT INTO domains (id, name, type, master, catalog) VALUES (1, 'e1.test', 'NATIVE', NULL, NULL), (2, 'e2.test', 'SLAVE', '192.0.2.1', 'cat.test'),"
      "(3, 'e3.test', 'MASTER', NULL, NULL), (4, 'e4.test', 'CONSUMER', NULL, NULL), (5, 'e5.test', 'NATIVE', NULL, NULL), (6, 'e6.test', 'NATIVE', NULL, NULL),"
      "(7, 'e7.test', 'NATIVE', NULL, NULL), (8, 'e8.test', 'NATIVE', NULL, NULL), (9, 'e9.test', 'NATIVE', NULL, NULL), (10, 'E10.test', 'NATIVE', NULL, NULL),"
      "(11, 'e11.test', 'NATIVE', NULL, NULL)");
    Q("INSERT INTO records (domain_id, name, type, content, ttl, disabled) VALUES "
      "(1, 'e1.test', 'SOA', 'soa-e1-off', 60, true), (1, 'e1.test', 'SOA', 'soa-e1-b', 60, false), (1, 'e1.test', 'SOA', 'soa-e1-c', 60, false),"
      "(1, 'e1.test', 'NS', 'ns.e1.test', 60, false), (1, 'sub.e1.test', 'SOA', 'soa-e1-sub', 60, false),"       /* a child zone's SOA is not the apex */
      "(3, 'e3.test', 'SOA', 'soa-e3-off', 60, true),"                                                            /* the only SOA is disabled */
      "(4, 'e4.test', 'SOA', 'soa-e4-null', 60, NULL),"                                                           /* disabled NULL = disabled */
      "(5, 'sub.e5.test', 'SOA', 'soa-e5-sub', 60, false),"                                                       /* not at the apex */
      "(6, 'E6.TEST', 'SOA', 'soa-e6', 60, false),"                                                               /* the owner differs in case: the fallback */
      "(6, 'e7.test', 'SOA', 'soa-e7-other', 60, false),"                                                         /* a SOA of this name that belongs to another zone */
      "(8, 'E8.test', 'SOA', 'soa-e8-ci', 60, false), (8, 'e8.test', 'SOA', 'soa-e8-exact', 60, false),"          /* two spellings: the exact one wins */
      "(9, 'e9.test', 'SOA', 'soa-e9-off', 60, true), (9, 'E9.TEST', 'SOA', 'soa-e9-ci', 60, false),"             /* exact disabled: the other spelling */
      "(10, 'e10.test', 'SOA', 'soa-e10', 60, false),"                                                            /* the domain is in capitals */
      "(11, 'e11.test', 'SOA', NULL, 60, false)");                                                                /* an enabled SOA without content */
    db_conn_t *c = open_drv("karidns_test_s2");
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    szacc_t *z = calloc(1, sizeof(*z));
    CHECK(D->begin_snapshot(c) == 0);
    CHECK(D->list_zones(c, cb_szone, z) == 0);
    CHECK_MSG(z->n == 11, "%d zones", z->n);
    static const char *const want[11] = { "soa-e1-b", NULL, NULL, NULL, NULL, "soa-e6", NULL, "soa-e8-exact", "soa-e9-ci", "soa-e10", NULL };
    for (int i = 0; i < 11 && i < z->n; i++) {
        CHECK_MSG(z->id[i] == i + 1, "zone %d is at position %d", (int)z->id[i], i);
        if (want[i]) CHECK_MSG(!z->soa_null[i] && !strcmp(z->soa[i], want[i]), "zone %d: SOA '%s' (null %d), expected '%s'", i + 1, z->soa[i], z->soa_null[i], want[i]);
        else CHECK_MSG(z->soa_null[i], "zone %d: SOA '%s', expected none", i + 1, z->soa[i]);
    }
    CHECK(z->n >= 4 && !strcmp(z->type[1], "SLAVE") && !z->master_null[1] && !z->cat_null[1] && !strcmp(z->type[3], "CONSUMER") && z->master_null[3] && z->cat_null[3]);
    /* find_zone: the same row for the same zone, whatever the spelling of the name asked for */
    static const struct { const char *ask; int id; } fz[] = { { "e1.test", 1 }, { "E1.TEST.", 1 }, { "e2.test", 2 }, { "e3.test.", 3 }, { "e6.test", 6 },
                                                              { "E6.test", 6 }, { "e8.test", 8 }, { "e9.test.", 9 }, { "e10.test", 10 }, { "e7.test", 7 },
                                                              { "e11.test", 11 } };
    for (size_t k = 0; k < sizeof(fz) / sizeof(fz[0]); k++) {
        memset(z, 0, sizeof(*z));
        CHECK_MSG(D->find_zone(c, fz[k].ask, cb_szone, z) == 0 && z->n == 1 && z->id[0] == fz[k].id, "find_zone %s: %d rows", fz[k].ask, z->n);
        if (z->n == 1 && fz[k].id >= 1 && fz[k].id <= 11) {
            const char *w = want[fz[k].id - 1];
            CHECK_MSG(w ? (!z->soa_null[0] && !strcmp(z->soa[0], w)) : z->soa_null[0], "find_zone %s: SOA '%s' (null %d)", fz[k].ask, z->soa[0], z->soa_null[0]);
        }
    }
    CHECK(D->end_snapshot(c) == 0);

    /* more zones than one FETCH, with and without statistics (the planner may choose either plan): every zone gets its own SOA,
     * once, in id order; zones 1000..1099 have none */
    Q("INSERT INTO domains (id, name, type) SELECT g, 'b' || g || '.test', 'NATIVE' FROM generate_series(1000, 3499) g");
    Q("INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT g, 'b' || g || '.test', 'SOA', 'soa-b' || g, 60, false FROM generate_series(1100, 3499) g");
    Q("INSERT INTO records (domain_id, name, type, content, ttl, disabled) SELECT g, h || '.b' || g || '.test', 'A', '192.0.2.1', 60, false FROM generate_series(1000, 3499) g, generate_series(1, 4) h");
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) Q("ANALYZE domains; ANALYZE records");
        CHECK(D->begin_snapshot(c) == 0);
        memset(z, 0, sizeof(*z));
        CHECK(D->list_zones(c, cb_szone, z) == 0);
        CHECK_MSG(z->n == 11 + 2500, "pass %d: %d zones", pass, z->n);
        bool ok = z->n == 11 + 2500;
        for (int i = 11; ok && i < z->n && i < 4000; i++) {
            int64_t id = 989 + i;                                       /* 1000 at position 11 */
            char exp[24];
            snprintf(exp, sizeof(exp), "soa-b%lld", (long long)id);
            if (z->id[i] != id || (id < 1100 ? !z->soa_null[i] : (z->soa_null[i] || strcmp(z->soa[i], exp)))) {
                printf("  [FAIL] pass %d position %d: zone %lld SOA '%s' (null %d)\n", pass, i, (long long)z->id[i], z->soa[i], z->soa_null[i]);
                g_failed++;
                ok = false;
            }
        }
        g_checks++;
        memset(z, 0, sizeof(*z));
        CHECK(D->find_zone(c, "b2000.test", cb_szone, z) == 0 && z->n == 1 && z->id[0] == 2000 && !strcmp(z->soa[0], "soa-b2000"));
        memset(z, 0, sizeof(*z));
        CHECK(D->find_zone(c, "b1050.test", cb_szone, z) == 0 && z->n == 1 && z->id[0] == 1050 && z->soa_null[0]);
        CHECK(D->end_snapshot(c) == 0);
    }
    D->close(c);
    free(z);
    Q("RESET search_path");
    Q("DROP SCHEMA karidns_test_s2 CASCADE");
}

static void test_ext_and_profiles(void) {
    printf("profiles, domain views, tags\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    Q("INSERT INTO karidns_profiles (name, settings) VALUES ('b-lower', 's2'), ('Z-Upper', 's1'), ('a-lower', 's3'), ('B-Upper', 's4')");
    Q("INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (3, 'internal'), (1, 'external'), (1, 'internal')");
    Q("INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (1, 'location', 'tokyo', '192.0.2.0/24'), (3, 'ecs', 'e1', '198.51.100.0/24'), (1, 'location', 'osaka', '192.0.2.0/25'), (1, 'location', 'tokyo2', '192.0.2.0/24')");
    char rid[32];
    qv(g_admin, "SELECT id FROM records WHERE name = 'www.a.test'", rid, sizeof(rid));
    char sql[300];
    snprintf(sql, sizeof(sql), "INSERT INTO karidns_record_tags (record_id, location_tag, ecs_tag) VALUES (%s, 'tokyo', NULL)", rid);
    Q(sql);
    snprintf(sql, sizeof(sql), "INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES (%s, NULL, 'k', true)", rid);
    Q(sql);
    CHECK(D->begin_snapshot(c) == 0);
    pacc_t p = {0};
    CHECK(D->scan_profiles(c, cb_prof, &p) == 0 && p.n == 4);
    CHECK_MSG(!strcmp(p.name[0], "B-Upper") && !strcmp(p.name[1], "Z-Upper") && !strcmp(p.name[2], "a-lower") && !strcmp(p.name[3], "b-lower"),
              "binary (C) order: %s %s %s %s", p.name[0], p.name[1], p.name[2], p.name[3]);
    vacc_t v = {0};
    CHECK(D->scan_domain_views(c, NULL, cb_view, &v) == 0 && v.n == 3 && v.d[0] == 1 && v.d[2] == 3);
    memset(&v, 0, sizeof(v));
    int64_t one = 1;
    CHECK(D->scan_domain_views(c, &one, cb_view, &v) == 0 && v.n == 2);

    xacc_t x = {0};
    db_ext_sink_t sink = { cb_xtag, cb_xtdns, cb_xdef, &x };
    CHECK(D->scan_ext(c, NULL, &sink) == 0);
    CHECK(x.tags == 1 && x.tdns == 1 && x.defs == 4);
    CHECK_MSG(x.def_dom[0] == 1 && !strcmp(x.def_tag[0], "tokyo") && !strcmp(x.def_tag[1], "osaka") && !strcmp(x.def_tag[2], "tokyo2") && x.def_dom[3] == 3,
              "definitions in id order: %s %s %s", x.def_tag[0], x.def_tag[1], x.def_tag[2]);
    memset(&x, 0, sizeof(x));
    CHECK(D->scan_ext(c, &one, &sink) == 0 && x.tags == 1 && x.defs == 3);
    D->end_snapshot(c);
    D->close(c);
}

/* scan_records_in / scan_metadata_in / scan_ext_in give the same rows, in the same order, as the single-zone calls one after the other
 * (the loader converts a group of zones from them and must produce the same stream as zone by zone) */
typedef struct { char *s; size_t n, cap; } sbuf_t;
static void sb_add(sbuf_t *b, const char *fmt, ...) {
    char line[1200];
    va_list ap;
    va_start(ap, fmt);
    int l = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (l < 0) return;
    if ((size_t)l >= sizeof(line)) l = (int)sizeof(line) - 1;
    if (b->n + (size_t)l + 1 > b->cap) {
        b->cap = (b->n + (size_t)l + 1) * 2;
        b->s = realloc(b->s, b->cap);
    }
    memcpy(b->s + b->n, line, (size_t)l);
    b->n += (size_t)l;
    b->s[b->n] = '\0';
}
#define NN(x) ((x) ? (x) : "<NULL>")
static int sb_rec(void *ud, int64_t did, const db_record_row_t *r) {
    sb_add(ud, "R %lld %lld %s %s %s %d/%lld %d/%lld %d %s\n", (long long)did, (long long)r->id, NN(r->name), NN(r->type), NN(r->content), r->ttl_null,
           (long long)r->ttl, r->prio_null, (long long)r->prio, r->disabled, NN(r->ordername));
    return 0;
}
static int sb_meta(void *ud, const db_meta_row_t *m) {
    sb_add(ud, "M %lld %s %s\n", (long long)m->domain_id, NN(m->kind), NN(m->content));
    return 0;
}
static int sb_tag(void *ud, int64_t d, const db_tag_row_t *r) {
    sb_add(ud, "T %lld %lld %s %s\n", (long long)d, (long long)r->record_id, NN(r->location_tag), NN(r->ecs_tag));
    return 0;
}
static int sb_td(void *ud, int64_t d, const db_tinydns_row_t *r) {
    sb_add(ud, "D %lld %lld %d/%lld %s %d\n", (long long)d, (long long)r->record_id, r->ttd_null, (long long)r->ttd, NN(r->loc), r->countdown);
    return 0;
}
static int sb_def(void *ud, int64_t d, const db_tagdef_row_t *r) {
    sb_add(ud, "G %lld %s %s %s\n", (long long)d, NN(r->kind), NN(r->tag), NN(r->cidr));
    return 0;
}

static void test_scan_in(void) {
    printf("several zones in one statement (scan_*_in)\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    CHECK(D->scan_records_in != NULL && D->scan_metadata_in != NULL && D->scan_ext_in != NULL);
    CHECK(D->begin_snapshot(c) == 0);
    static const int64_t sets[][3] = { { 1, 2, 3 }, { 1, 3, 0 }, { 2, 0, 0 }, { 3, 0, 0 }, { 2, 3, 0 } };
    static const size_t counts[] = { 3, 2, 1, 1, 2 };
    db_ext_sink_t sink = { sb_tag, sb_td, sb_def, NULL };
    for (size_t k = 0; k < sizeof(counts) / sizeof(counts[0]); k++) {
        sbuf_t one[3] = { {0}, {0}, {0} }, many[3] = { {0}, {0}, {0} };
        for (size_t i = 0; i < counts[k]; i++) {
            int64_t id = sets[k][i];
            CHECK(D->scan_records(c, &id, sb_rec, &one[0]) == 0);
            CHECK(D->scan_metadata(c, &id, sb_meta, &one[1]) == 0);
            db_ext_sink_t s1 = sink;
            s1.ud = &one[2];
            CHECK(D->scan_ext(c, &id, &s1) == 0);
        }
        sink.ud = &many[2];
        CHECK(D->scan_records_in(c, sets[k], counts[k], sb_rec, &many[0]) == 0);
        CHECK(D->scan_metadata_in(c, sets[k], counts[k], sb_meta, &many[1]) == 0);
        CHECK(D->scan_ext_in(c, sets[k], counts[k], &sink) == 0);
        for (int t = 0; t < 3; t++) {
            const char *a = one[t].s ? one[t].s : "", *b = many[t].s ? many[t].s : "";
            CHECK_MSG(strcmp(a, b) == 0, "set %zu, table %d: %zu bytes one by one, %zu bytes at once", k, t, strlen(a), strlen(b));
            free(one[t].s);
            free(many[t].s);
        }
    }
    /* the sets are not empty: records (more than one FETCH for zone 3), metadata and extension rows were compared */
    sbuf_t chk[3] = { {0}, {0}, {0} };
    sink.ud = &chk[2];
    CHECK(D->scan_records_in(c, sets[0], 3, sb_rec, &chk[0]) == 0 && chk[0].n > 100000);
    CHECK(D->scan_metadata_in(c, sets[0], 3, sb_meta, &chk[1]) == 0 && chk[1].n > 0);
    CHECK(D->scan_ext_in(c, sets[0], 3, &sink) == 0 && chk[2].n > 0);
    free(chk[0].s);
    free(chk[1].s);
    free(chk[2].s);
    /* a zone that is not there gives no rows; the limits */
    sbuf_t none = {0};
    int64_t gone = 99999;
    CHECK(D->scan_records_in(c, &gone, 1, sb_rec, &none) == 0 && none.n == 0);
    CHECK(D->scan_records_in(c, &gone, 0, sb_rec, &none) == -1);
    int64_t many_ids[DB_IN_MAX + 1];
    for (size_t i = 0; i < DB_IN_MAX + 1; i++) many_ids[i] = (int64_t)i + 1;
    CHECK(D->scan_records_in(c, many_ids, DB_IN_MAX + 1, sb_rec, &none) == -1);
    CHECK(D->scan_records_in(c, many_ids, DB_IN_MAX, sb_rec, &none) == 0);          /* the most allowed */
    free(none.s);
    D->end_snapshot(c);
    D->close(c);
}

static void test_search_path(void) {
    printf("schema (search_path)\n");
    Q("CREATE SCHEMA karidns_test_s1");
    char path[500];
    snprintf(path, sizeof(path), "%s/pdns_schema.pgsql.sql", g_root);
    char *sql = slurp(path);
    CHECK(sql != NULL);
    if (!sql) return;
    Q("SET search_path TO karidns_test_s1");
    Q(sql);
    snprintf(path, sizeof(path), "%s/../../db/karidns_ext.pgsql.sql", g_root);
    char *ext = slurp(path);
    if (ext) Q(ext);
    free(ext);
    free(sql);
    Q("INSERT INTO domains (id, name, type) VALUES (77, 'only-in-s1.test', 'NATIVE')");
    Q("RESET search_path");
    db_conn_t *c = open_drv("karidns_test_s1");
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0 && si.has_changes);
    CHECK(D->begin_snapshot(c) == 0);
    zacc_t *z = calloc(1, sizeof(*z));
    CHECK(D->list_zones(c, cb_zone, z) == 0 && z->n == 1 && z->id[0] == 77);
    free(z);
    D->end_snapshot(c);
    D->close(c);
    c = open_drv("odd \"schema\"; DROP TABLE domains; --");
    if (c) {
        CHECK(D->check_schema(c, &si) == -1);                      /* quoted as an identifier: no such schema, and nothing dropped */
        D->close(c);
    }
    char v[32];
    qv(g_admin, "SELECT count(*) FROM domains", v, sizeof(v));
    CHECK(!strcmp(v, "3"));
    Q("DROP SCHEMA karidns_test_s1 CASCADE");
}

/* the cursor protocol the loader uses: changes_max() inside a snapshot, changes_since(cursor) */
static uint64_t snap_max(db_conn_t *c) {
    uint64_t m = 0;
    CHECK(D->begin_snapshot(c) == 0);
    CHECK(D->changes_max(c, &m) == 0);
    CHECK(D->end_snapshot(c) == 0);
    return m;
}

static uint64_t snap_since(db_conn_t *c, uint64_t after, cacc_t *a, bool *gap) {
    uint64_t last = 0;
    memset(a, 0, sizeof(*a));
    CHECK(D->begin_snapshot(c) == 0);
    int rc = D->changes_since(c, after, cb_chg, a, &last, gap);
    CHECK_MSG(rc == 0, "changes_since: %s", D->errmsg(c));
    CHECK(D->end_snapshot(c) == 0);
    return last;
}

static void test_changes(void) {
    printf("change log\n");
    PGconn *t1 = connect_db(g_db), *t2 = connect_db(g_db), *t3 = connect_db(g_db);
    db_conn_t *c = open_drv(NULL);
    if (!c || !t1 || !t2 || !t3) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0 && si.has_changes);
    cacc_t a;
    bool gap = false;

    /* a plain edit: seen once, the cursor moves on, nothing is listed again below it */
    uint64_t cur0 = snap_max(c);
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'plain.a.test', 'A', '192.0.2.77', 60)");
    uint64_t cur1 = snap_since(c, cur0, &a, &gap);
    CHECK_MSG(a.n == 1 && a.v[0] == 1 && !gap, "plain edit: %d rows", a.n);
    CHECK(cur1 > cur0);
    uint64_t cur1b = snap_since(c, cur1, &a, &gap);
    CHECK_MSG(a.n == 0 && cur1b == cur1, "nothing new: %d rows", a.n);

    /* A: T1 takes the lower seq and stays open, T2 takes the higher seq and commits */
    CHECK(qx(t1, "BEGIN"));
    CHECK(qx(t1, "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'slow.a.test', 'A', '192.0.2.1', 60)"));
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'fast.b.test', 'A', '192.0.2.2', 60)");
    uint64_t cur2 = snap_since(c, cur1, &a, &gap);
    CHECK_MSG(a.n == 1 && a.v[0] == 2, "only the committed edit is visible: %d rows", a.n);
    char xs[40];
    {
        PGresult *xr = PQexec(t1, "SELECT pg_current_xact_id()::text");
        snprintf(xs, sizeof(xs), "%s", xr && PQntuples(xr) ? PQgetvalue(xr, 0, 0) : "0");
        PQclear(xr);
    }
    CHECK_MSG(cur2 >= cur1 && cur2 <= strtoull(xs, NULL, 10), "the cursor does not pass the open transaction (%llu, xid %s)", (unsigned long long)cur2, xs);
    CHECK(qx(t1, "COMMIT"));
    uint64_t cur3 = snap_since(c, cur2, &a, &gap);
    CHECK_MSG(has_dom(&a, 1), "the transaction that committed late is listed (%d rows)", a.n);
    CHECK(cur3 > cur2);

    /* B: the transaction that takes the HIGHER seq has the LOWER xid and commits first (a seq based position would skip the other) */
    CHECK(qx(t2, "BEGIN"));
    CHECK(qx(t2, "SELECT pg_current_xact_id()"));                      /* t2 gets its xid first ... */
    CHECK(qx(t1, "BEGIN"));
    CHECK(qx(t1, "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'low-seq.a.test', 'A', '192.0.2.3', 60)"));   /* ... t1 takes seq N */
    CHECK(qx(t2, "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'high-seq.b.test', 'A', '192.0.2.4', 60)")); /* ... t2 takes seq N+1 */
    CHECK(qx(t2, "COMMIT"));
    char v1[32];
    uint64_t cur4 = snap_since(c, cur3, &a, &gap);
    CHECK_MSG(a.n >= 1 && has_dom(&a, 2) && !has_dom(&a, 1), "B: the committed edit of zone 2 only (%d rows)", a.n);
    CHECK(qx(t1, "COMMIT"));
    uint64_t cur5 = snap_since(c, cur4, &a, &gap);
    CHECK_MSG(has_dom(&a, 1), "B: the edit of zone 1 (lower seq, committed last) is listed");
    CHECK(cur5 >= cur4);
    qv(g_admin, "SELECT (SELECT seq FROM karidns_changes WHERE domain_id = 1 ORDER BY seq DESC LIMIT 1) < (SELECT seq FROM karidns_changes WHERE domain_id = 2 ORDER BY seq DESC LIMIT 1)", v1, sizeof(v1));
    CHECK_MSG(!strcmp(v1, "t"), "the interleaving really happened (zone 1 has the lower seq)");
    /* C: an idle transaction with an xid in front does not hide later commits (the cursor stays, the rows are still listed) */
    CHECK(qx(t3, "BEGIN"));
    CHECK(qx(t3, "SELECT pg_current_xact_id()"));
    uint64_t cur6 = snap_max(c);
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (3, 'behind-idle.c.test', 'A', '192.0.2.5', 60)");
    uint64_t cur7 = snap_max(c);
    CHECK_MSG(cur7 == cur6 || cur7 > cur6, "the cursor does not go back (%llu %llu)", (unsigned long long)cur6, (unsigned long long)cur7);
    snap_since(c, cur6, &a, &gap);
    CHECK_MSG(has_dom(&a, 3), "the commit behind the idle transaction is listed although the cursor did not grow");
    CHECK(qx(t3, "COMMIT"));
    uint64_t cur8 = snap_max(c);
    CHECK(cur8 > cur7);

    /* an aborted transaction leaves a hole in seq and nothing else; it is not a gap */
    CHECK(qx(t1, "BEGIN"));
    CHECK(qx(t1, "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'rolled.a.test', 'A', '192.0.2.6', 60)"));
    CHECK(qx(t1, "ROLLBACK"));
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'after-hole.a.test', 'A', '192.0.2.7', 60)");
    snap_since(c, cur8, &a, &gap);
    CHECK_MSG(a.n == 1 && !gap, "a rolled back transaction is no gap (%d rows, gap %d)", a.n, gap);

    /* pruning: rows below the cursor are gone, the first seq is not 1 -> gap; with rows left below the cursor -> no gap */
    uint64_t cur9 = snap_max(c);
    char sqlb[160];
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'p1.a.test', 'A', '192.0.2.8', 60)");
    snap_since(c, cur9, &a, &gap);
    CHECK_MSG(!gap && a.n == 1, "rows below the cursor exist: no gap");
    snprintf(sqlb, sizeof(sqlb), "DELETE FROM karidns_changes WHERE xid < '%llu'::xid8", (unsigned long long)cur9);
    Q(sqlb);
    snap_since(c, cur9, &a, &gap);
    CHECK_MSG(gap, "the rows the loader has seen are gone and the first seq is not 1: gap");
    Q("DELETE FROM karidns_changes");
    snap_since(c, cur9, &a, &gap);
    CHECK_MSG(!gap && a.n == 0, "an empty log is no gap");
    CHECK(D->changes_since(c, 0, cb_chg, &a, NULL, NULL) != 0);        /* needs a snapshot: the cursor query is a cursor scan */

    /* a database without karidns_changes.xid (schema version 1) has no change log */
    D->close(c);
    PQfinish(t1);
    PQfinish(t2);
    PQfinish(t3);
}

static void test_v1_and_migration(void) {
    printf("schema version 1 and the migration to 2\n");
    Q("INSERT INTO karidns_changes (domain_id, changed_at) VALUES (1, 1)");
    Q("DROP INDEX karidns_changes_xid_idx");
    Q("ALTER TABLE karidns_changes DROP COLUMN xid");
    Q("ALTER TABLE karidns_zone_tagdefs DROP COLUMN id");
    Q("UPDATE karidns_schema_version SET version = 1");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    CHECK_MSG(!si.has_changes && si.has_ext && si.has_domain_views && si.has_profiles, "v1: no change log, the rest works");
    CHECK(!c->has_tagdef_id);
    uint64_t m = 0;
    CHECK(D->begin_snapshot(c) == 0);
    CHECK(D->changes_max(c, &m) == DB_ERR_UNAVAILABLE);
    CHECK(D->changes_since(c, 0, cb_chg, &(cacc_t){0}, NULL, NULL) == DB_ERR_UNAVAILABLE);
    int defs = 0;
    db_ext_sink_t sink = { cb_xnop_tag, cb_xnop_tdns, cb_xcount, &defs };
    CHECK(D->scan_ext(c, NULL, &sink) == 0 && defs == 4);              /* ctid order */
    D->end_snapshot(c);
    D->close(c);

    /* the migration script (twice: it is idempotent) */
    char path[500];
    snprintf(path, sizeof(path), "%s/../../db/karidns_ext_v1_to_v2.pgsql.sql", g_root);
    char *mig = slurp(path);
    CHECK(mig != NULL);
    if (!mig) return;
    CHECK(qx(g_admin, mig));
    CHECK(qx(g_admin, mig));
    free(mig);
    char v[64];
    qv(g_admin, "SELECT version FROM karidns_schema_version", v, sizeof(v));
    CHECK_MSG(!strcmp(v, "2"), "version %s", v);
    qv(g_admin, "SELECT count(*) FROM karidns_schema_version", v, sizeof(v));
    CHECK(!strcmp(v, "1"));
    qv(g_admin, "SELECT string_agg(tag, ',' ORDER BY id) FROM karidns_zone_tagdefs WHERE domain_id = 1", v, sizeof(v));
    CHECK_MSG(!strcmp(v, "tokyo,osaka,tokyo2"), "the order of the definitions survives the migration: %s", v);
    qv(g_admin, "SELECT count(*) FROM karidns_changes WHERE xid = '0'::xid8", v, sizeof(v));
    CHECK_MSG(strcmp(v, "0") != 0, "old log rows have xid 0");
    c = open_drv(NULL);
    if (!c) return;
    CHECK(D->check_schema(c, &si) == 0 && si.has_changes && c->has_tagdef_id);
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'v2.b.test', 'A', '192.0.2.10', 60)");
    qv(g_admin, "SELECT count(*) FROM karidns_changes WHERE xid <> '0'::xid8", v, sizeof(v));
    CHECK_MSG(!strcmp(v, "1"), "a new row gets the xid of its transaction (%s)", v);
    D->close(c);
}

static void test_notify(void) {
    printf("notifications\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    uint64_t v0 = 0, v1 = 0;
    bool repl = true;
    CHECK(D->poll_version(c, &v0, &repl) == 0 && !repl);
    int fd = D->wait_fd(c);
    CHECK(fd >= 0);
    bool changed = true;
    CHECK(D->drain_notifications(c, &changed) == 0 && !changed);
    CHECK(D->poll_version(c, &v1, &repl) == 0 && v1 == v0);
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'n1.b.test', 'A', '192.0.2.11', 60)");
    struct pollfd pf = { fd, POLLIN, 0 };
    CHECK_MSG(poll(&pf, 1, 5000) == 1, "the socket becomes readable");
    CHECK(D->poll_version(c, &v1, &repl) == 0 && v1 > v0);
    /* a notification that arrived while the connection ran a query (changes_max) is seen by the next poll_version */
    uint64_t m;
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'n2.b.test', 'A', '192.0.2.12', 60)");
    usleep(200000);
    CHECK(D->begin_snapshot(c) == -1 || true);
    if (c->in_snapshot) D->end_snapshot(c);
    CHECK(D->changes_max(c, &m) == 0);
    uint64_t v2 = 0;
    CHECK(D->poll_version(c, &v2, &repl) == 0 && v2 > v1);
    CHECK(D->drain_notifications(c, &changed) == 0 && !changed);

    /* LISTEN cannot start inside a snapshot */
    db_conn_t *c2 = open_drv(NULL);
    if (c2) {
        CHECK(D->check_schema(c2, &si) == 0 && D->begin_snapshot(c2) == 0);
        CHECK(D->wait_fd(c2) == -1);
        D->end_snapshot(c2);
        CHECK(D->wait_fd(c2) >= 0);
        D->close(c2);
    }

    /* LISTEN refused for good (a hot standby cannot LISTEN): wait_fd() is -1 and poll_version() reads a fingerprint of the change
     * log instead, which changes when a row is added, also one that a transaction adds at its commit with a seq below the highest */
    db_conn_t *c3 = open_drv(NULL);
    PGconn *w2 = connect_db(g_db);
    if (c3 && w2) {
        CHECK(D->check_schema(c3, &si) == 0 && si.has_changes);
        c3->listen_failed = true;                      /* what ensure_listen() records when the server answers "cannot execute LISTEN during recovery" */
        CHECK(D->wait_fd(c3) == -1);
        uint64_t p0 = 0, p1 = 0, p2 = 0, p3 = 0;
        bool r3 = true;
        CHECK(D->poll_version(c3, &p0, &r3) == 0 && !r3);
        CHECK(D->poll_version(c3, &p1, &r3) == 0 && p1 == p0);              /* nothing happened */
        Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'n3.b.test', 'A', '192.0.2.13', 60)");
        CHECK(D->poll_version(c3, &p2, &r3) == 0 && p2 != p0);              /* a commit */
        CHECK(D->poll_version(c3, &p1, &r3) == 0 && p1 == p2);
        CHECK(qx(w2, "BEGIN") && qx(w2, "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'n4.b.test', 'A', '192.0.2.14', 60)"));
        Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'n5.b.test', 'A', '192.0.2.15', 60)");   /* higher seq, commits first */
        CHECK(D->poll_version(c3, &p3, &r3) == 0 && p3 != p2);
        CHECK(qx(w2, "COMMIT"));                                            /* the lower seq becomes visible last */
        CHECK(D->poll_version(c3, &p2, &r3) == 0 && p2 != p3);
        /* the connection is gone: a transient error, like the notification path */
        char pidv[32], q2[300];
        snprintf(q2, sizeof(q2), "SELECT pid FROM pg_stat_activity WHERE application_name = 'karidns-dbloader' AND datname = '%s' ORDER BY backend_start DESC LIMIT 1", g_db);
        qv(g_admin, q2, pidv, sizeof(pidv));
        snprintf(q2, sizeof(q2), "SELECT pg_terminate_backend(%s)", pidv);
        if (pidv[0]) Q(q2);
        usleep(300000);
        CHECK(D->poll_version(c3, &p1, &r3) == DB_ERR_RETRY);
    }
    if (c3) D->close(c3);
    if (w2) PQfinish(w2);

    /* the backend is terminated from outside: the driver reports a transient error */
    char sql[300], pid[32];
    snprintf(sql, sizeof(sql), "SELECT pid FROM pg_stat_activity WHERE application_name = 'karidns-dbloader' AND datname = '%s' ORDER BY backend_start LIMIT 1", g_db);
    qv(g_admin, sql, pid, sizeof(pid));
    CHECK(pid[0] != '\0');
    snprintf(sql, sizeof(sql), "SELECT pg_terminate_backend(%s)", pid);
    Q(sql);
    usleep(300000);
    int rc = D->poll_version(c, &v2, &repl);
    int rc2 = D->drain_notifications(c, &changed);
    CHECK_MSG(rc == DB_ERR_RETRY || rc2 == DB_ERR_RETRY, "terminated connection: %d %d (%s)", rc, rc2, D->errmsg(c));
    CHECK(D->begin_snapshot(c) == DB_ERR_RETRY);
    CHECK_HAS(D->errmsg(c), "retry later");
    D->close(c);
}

static void test_errors(void) {
    printf("errors in a snapshot\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    CHECK(D->begin_snapshot(c) == 0);
    /* the session is read only */
    PGresult *r = PQexec(c->pg, "INSERT INTO domains (name, type) VALUES ('rw.test', 'NATIVE')");
    CHECK(r && PQresultStatus(r) == PGRES_FATAL_ERROR);
    PQclear(r);
    /* after a server error the transaction is aborted; end_snapshot still returns and the connection can start a new one */
    D->end_snapshot(c);
    CHECK(D->begin_snapshot(c) == 0);
    D->end_snapshot(c);
    /* a NUL cannot be stored; a text cell is checked anyway */
    D->close(c);
}

/* ---- a table that disappears after the schema check, callbacks that stop a scan, a source without the optional tables ---- */
static int pgc_zone(void *ud, const db_zone_row_t *z) { (void)ud; (void)z; return 0; }
static int pgc_rec(void *ud, int64_t d, const db_record_row_t *r) { (void)ud; (void)d; (void)r; return 0; }
static int pgc_meta(void *ud, const db_meta_row_t *m) { (void)ud; (void)m; return 0; }
static int pgc_key(void *ud, int64_t id) { (void)ud; (void)id; return 0; }
static int pgc_dv(void *ud, int64_t d, const char *v) { (void)ud; (void)d; (void)v; return 0; }
static int pgc_prof(void *ud, const db_profile_row_t *p) { (void)ud; (void)p; return 0; }
static int pgc_chg(void *ud, const db_change_row_t *r) { (void)ud; (void)r; return 0; }
static int pgc_tags(void *ud, int64_t d, const db_tag_row_t *r) { (void)ud; (void)d; (void)r; return 0; }
static int pgc_td(void *ud, int64_t d, const db_tinydns_row_t *r) { (void)ud; (void)d; (void)r; return 0; }
static int pgc_def(void *ud, int64_t d, const db_tagdef_row_t *r) { (void)ud; (void)d; (void)r; return 0; }
static int pgc_stop_dv(void *ud, int64_t d, const char *v) { (void)ud; (void)d; (void)v; return 1; }
static int pgc_stop_prof(void *ud, const db_profile_row_t *p) { (void)ud; (void)p; return 1; }
static int pgc_stop_meta(void *ud, const db_meta_row_t *m) { (void)ud; (void)m; return 1; }
static int pgc_stop_key(void *ud, int64_t id) { (void)ud; (void)id; return 1; }
static int pgc_stop_chg(void *ud, const db_change_row_t *r) { (void)ud; (void)r; return 1; }
static int pgc_stop_tags(void *ud, int64_t d, const db_tag_row_t *r) { (void)ud; (void)d; (void)r; return 1; }
static int pgc_stop_td(void *ud, int64_t d, const db_tinydns_row_t *r) { (void)ud; (void)d; (void)r; return 1; }
static int pgc_stop_def(void *ud, int64_t d, const db_tagdef_row_t *r) { (void)ud; (void)d; (void)r; return 1; }

static int pgr_zones(db_conn_t *c) { return D->list_zones(c, pgc_zone, NULL); }
static int pgr_rec_all(db_conn_t *c) { return D->scan_records(c, NULL, pgc_rec, NULL); }
static int pgr_rec_one(db_conn_t *c) { int64_t d = 1; return D->scan_records(c, &d, pgc_rec, NULL); }
static int pgr_rec_rng(db_conn_t *c) { return D->scan_records_range(c, 1, 9, pgc_rec, NULL); }
static int pgr_meta(db_conn_t *c) { return D->scan_metadata(c, NULL, pgc_meta, NULL); }
static int pgr_keys(db_conn_t *c) { return D->zones_with_keys(c, pgc_key, NULL); }
static int pgr_dv(db_conn_t *c) { return D->scan_domain_views(c, NULL, pgc_dv, NULL); }
static int pgr_prof(db_conn_t *c) { return D->scan_profiles(c, pgc_prof, NULL); }
static int pgr_chg(db_conn_t *c) { uint64_t last; bool gap; return D->changes_since(c, 0, pgc_chg, NULL, &last, &gap); }
static int pgr_ext(db_conn_t *c) { db_ext_sink_t s = { pgc_tags, pgc_td, pgc_def, NULL }; return D->scan_ext(c, NULL, &s); }

/* a schema of its own (the tables of g_db belong to the other cases) with a row in every table the driver reads */
static void pg_scratch(const char *schema, bool with_ext) {
    char path[500], sql[300];
    snprintf(sql, sizeof(sql), "CREATE SCHEMA %s", schema);
    Q(sql);
    snprintf(sql, sizeof(sql), "SET search_path TO %s", schema);
    Q(sql);
    snprintf(path, sizeof(path), "%s/pdns_schema.pgsql.sql", g_root);
    char *base = slurp(path);
    CHECK(base != NULL);
    if (base) Q(base);
    free(base);
    if (with_ext) {
        snprintf(path, sizeof(path), "%s/../../db/karidns_ext.pgsql.sql", g_root);
        char *ext = slurp(path);
        CHECK(ext != NULL);
        if (ext) Q(ext);
        free(ext);
    }
    Q("INSERT INTO domains (id, name, type) VALUES (1, 's1.test', 'NATIVE'), (2, 's2.test', 'NATIVE')");
    Q("INSERT INTO records (id, domain_id, name, type, content, ttl, prio, disabled, ordername) VALUES "
      "(10, 1, 's1.test', 'SOA', 'ns1.s1.test h.s1.test 1 3600 600 86400 300', 3600, NULL, false, NULL),"
      "(11, 1, 's1.test', 'NS', 'ns1.s1.test', 3600, NULL, false, NULL),"
      "(12, 1, 'ns1.s1.test', 'A', '192.0.2.1', 300, NULL, false, NULL)");
    Q("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'ALSO-NOTIFY', '192.0.2.1')");
    Q("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (1, 257, true, 'x')");
    if (with_ext) {
        Q("INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'va'), (2, 'vb')");
        Q("INSERT INTO karidns_profiles (name, settings) VALUES ('p1', 'x'), ('p2', 'y')");
        Q("INSERT INTO karidns_record_tags (record_id, location_tag, ecs_tag) VALUES (11, 'lan', 'east')");
        Q("INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES (12, 100, 'l2', false)");
        Q("INSERT INTO karidns_zone_tagdefs (domain_id, kind, tag, cidr) VALUES (1, 'location', 'a', '192.0.2.0/24')");
    }
    Q("RESET search_path");
}

static void test_scan_failures(void) {
    printf("scans: a table that disappears after the schema check, callbacks that stop a scan, a source without the optional tables\n");
    static const struct { const char *table; int (*run)(db_conn_t *); const char *what; } cases[] = {
        { "domains",                pgr_zones,   "list_zones" },
        { "records",                pgr_rec_all, "scan_records" },
        { "records",                pgr_rec_one, "scan_records" },
        { "records",                pgr_rec_rng, "scan_records" },
        { "domainmetadata",         pgr_meta,    "scan_metadata" },
        { "cryptokeys",             pgr_keys,    "zones_with_keys" },
        { "karidns_domain_views",   pgr_dv,      "scan_domain_views" },
        { "karidns_profiles",       pgr_prof,    "scan_profiles" },
        { "karidns_changes",        pgr_chg,     "changes_since" },
        { "karidns_record_tags",    pgr_ext,     "karidns_record_tags" },
        { "karidns_record_tinydns", pgr_ext,     "karidns_record_tinydns" },
        { "karidns_zone_tagdefs",   pgr_ext,     "karidns_zone_tagdefs" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pg_scratch("karidns_test_sf", true);
        db_conn_t *c = open_drv("karidns_test_sf");
        if (c) {
            db_schema_info_t si;
            CHECK(D->check_schema(c, &si) == 0 && si.has_ext && si.has_profiles && si.has_domain_views && si.has_changes);
            CHECK(D->begin_snapshot(c) == 0);
            CHECK_MSG(cases[i].run(c) == 0, "%s: the scan works before the table goes: %s", cases[i].what, D->errmsg(c));
            CHECK(D->end_snapshot(c) == 0);
            char sql[200];
            snprintf(sql, sizeof(sql), "ALTER TABLE karidns_test_sf.%s RENAME TO %s_gone", cases[i].table, cases[i].table);
            Q(sql);
            CHECK(D->begin_snapshot(c) == 0);
            int rc = cases[i].run(c);
            CHECK_MSG(rc == -1, "%s: a statement that fails is an error, not DB_STOPPED / retry: %d", cases[i].what, rc);
            CHECK_HAS(D->errmsg(c), cases[i].what);
            D->end_snapshot(c);                   /* ends the aborted transaction too */
            D->close(c);
        }
        Q("DROP SCHEMA karidns_test_sf CASCADE");
    }

    /* the callback of every scan can stop it: DB_STOPPED, and the next query on the connection works */
    pg_scratch("karidns_test_sf", true);
    db_conn_t *c = open_drv("karidns_test_sf");
    if (c) {
        db_schema_info_t si;
        CHECK(D->check_schema(c, &si) == 0);
        CHECK(D->begin_snapshot(c) == 0);
        CHECK(D->scan_domain_views(c, NULL, pgc_stop_dv, NULL) == DB_STOPPED);
        CHECK(D->scan_profiles(c, pgc_stop_prof, NULL) == DB_STOPPED);
        CHECK(D->scan_metadata(c, NULL, pgc_stop_meta, NULL) == DB_STOPPED);
        CHECK(D->zones_with_keys(c, pgc_stop_key, NULL) == DB_STOPPED);
        {
            uint64_t last = 0;
            bool gap = false;
            CHECK(D->changes_since(c, 0, pgc_stop_chg, NULL, &last, &gap) == DB_STOPPED);
        }
        {
            db_ext_sink_t s1 = { pgc_stop_tags, pgc_td, pgc_def, NULL };
            db_ext_sink_t s2 = { pgc_tags, pgc_stop_td, pgc_def, NULL };
            db_ext_sink_t s3 = { pgc_tags, pgc_td, pgc_stop_def, NULL };
            CHECK(D->scan_ext(c, NULL, &s1) == DB_STOPPED);
            CHECK(D->scan_ext(c, NULL, &s2) == DB_STOPPED);
            CHECK(D->scan_ext(c, NULL, &s3) == DB_STOPPED);
        }
        CHECK(pgr_dv(c) == 0 && pgr_prof(c) == 0 && pgr_meta(c) == 0 && pgr_keys(c) == 0 && pgr_ext(c) == 0);
        D->end_snapshot(c);
        D->close(c);
    }
    Q("DROP SCHEMA karidns_test_sf CASCADE");

    /* a source without the optional tables: the scans of them say "unavailable" with the reason */
    pg_scratch("karidns_test_sf", false);
    c = open_drv("karidns_test_sf");
    if (c) {
        db_schema_info_t si;
        CHECK(D->check_schema(c, &si) == 0 && !si.has_ext && !si.has_profiles && !si.has_domain_views && !si.has_changes);
        CHECK(D->begin_snapshot(c) == 0);
        CHECK(pgr_prof(c) == DB_ERR_UNAVAILABLE);
        CHECK_HAS(D->errmsg(c), "karidns_profiles does not exist");
        CHECK(pgr_dv(c) == DB_ERR_UNAVAILABLE);
        CHECK_HAS(D->errmsg(c), "karidns_domain_views does not exist");
        CHECK(pgr_chg(c) == DB_ERR_UNAVAILABLE);
        CHECK_HAS(D->errmsg(c), "karidns_changes");
        uint64_t seq = 0;
        CHECK(D->changes_max(c, &seq) == DB_ERR_UNAVAILABLE);
        CHECK(pgr_ext(c) == DB_ERR_UNAVAILABLE);
        D->end_snapshot(c);
        D->close(c);
    }
    Q("DROP SCHEMA karidns_test_sf CASCADE");

    /* a schema that does not exist: the schema check says so (and the findings of karicheck db) */
    c = open_drv("karidns_test_nosuchschema");
    if (c) {
        db_schema_info_t si;
        CHECK(D->check_schema(c, &si) == -1);
        CHECK_HAS(D->errmsg(c), "database-schema does not exist");
        D->close(c);
    }
}

/* ---- B11: reload requests and the status row ---- */
typedef struct {
    int n;
    uint64_t gen[1200];
    bool all[1200], force[1200];
    char zone[12][32];
    int stop_after;
} qacc_t;
static int cb_req(void *ud, const db_reload_row_t *r) {
    qacc_t *a = ud;
    if (a->n < 1200) {
        a->gen[a->n] = r->generation;
        a->all[a->n] = r->zone == NULL;
        a->force[a->n] = r->force;
    }
    if (a->n < 12) snprintf(a->zone[a->n], sizeof(a->zone[0]), "%s", r->zone ? r->zone : "<NULL>");
    a->n++;
    return a->stop_after && a->n >= a->stop_after;
}

static void test_requests(void) {
    printf("reload requests (B11)\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    memset(&si, 0xff, sizeof(si));
    CHECK(D->check_schema(c, &si) == 0);
    CHECK(si.has_reload_requests && si.has_server_status);
    uint64_t mx = 99;
    CHECK(D->requests_max(c, &mx) == 0 && mx == 0);

    /* the order, a NULL zone (all), a named zone, force */
    Q("INSERT INTO karidns_reload_requests DEFAULT VALUES");
    Q("INSERT INTO karidns_reload_requests (zone) VALUES ('a.test')");
    Q("INSERT INTO karidns_reload_requests (zone, force) VALUES ('b.test', true)");
    qacc_t *a = calloc(1, sizeof(*a));
    uint64_t last = 0;
    bool gap = true;
    CHECK(D->requests_max(c, &mx) == 0 && mx == 3);
    CHECK(D->reload_requests(c, 0, cb_req, a, &last, &gap) == 0);
    CHECK_MSG(a->n == 3 && last == 3 && !gap, "n=%d last=%llu gap=%d", a->n, (unsigned long long)last, gap);
    CHECK(a->gen[0] == 1 && a->gen[1] == 2 && a->gen[2] == 3);
    CHECK(a->all[0] && !a->all[1] && !a->all[2]);
    CHECK(!strcmp(a->zone[1], "a.test") && !strcmp(a->zone[2], "b.test"));
    CHECK(!a->force[0] && !a->force[1] && a->force[2]);
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 1, cb_req, a, &last, &gap) == 0 && a->n == 2 && last == 3 && !gap && a->gen[0] == 2);
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 3, cb_req, a, &last, &gap) == 0 && a->n == 0 && last == 3 && !gap);
    memset(a, 0, sizeof(*a));
    a->stop_after = 1;
    CHECK(D->reload_requests(c, 0, cb_req, a, &last, &gap) == DB_STOPPED && a->n == 1 && last == 1);

    /* a request rolled back leaves a hole: the first row after it is not after + 1 */
    Q("BEGIN");
    Q("INSERT INTO karidns_reload_requests (zone) VALUES ('lost.test')");
    Q("ROLLBACK");
    Q("INSERT INTO karidns_reload_requests (zone) VALUES ('c.test')");
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 3, cb_req, a, &last, &gap) == 0 && a->n == 1 && a->gen[0] == 5 && last == 5 && gap);
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 4, cb_req, a, &last, &gap) == 0 && a->n == 1 && !gap);

    /* the INSERT trigger keeps the newest 1000; more rows than one query (500) are all delivered */
    Q("INSERT INTO karidns_reload_requests (zone) SELECT 'bulk' || g || '.test' FROM generate_series(1, 1100) g");
    char v[64];
    qv(g_admin, "SELECT count(*) FROM karidns_reload_requests", v, sizeof(v));
    CHECK_MSG(!strcmp(v, "1000"), "pruned to %s rows", v);
    CHECK(D->requests_max(c, &mx) == 0 && mx == 1105);
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 5, cb_req, a, &last, &gap) == 0);
    CHECK_MSG(a->n == 1000 && last == 1105 && gap && a->gen[0] == 106 && a->gen[999] == 1105, "n=%d first=%llu last=%llu gap=%d", a->n,
              (unsigned long long)a->gen[0], (unsigned long long)last, gap);
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 1104, cb_req, a, &last, &gap) == 0 && a->n == 1 && last == 1105 && !gap);
    /* a zone name with a byte the callback must see as it is (untrusted text; the loader checks it) */
    Q("INSERT INTO karidns_reload_requests (zone) VALUES (E'x\\ny.test')");
    memset(a, 0, sizeof(*a));
    CHECK(D->reload_requests(c, 1105, cb_req, a, &last, &gap) == 0 && a->n == 1 && !strcmp(a->zone[0], "x\ny.test"));

    /* not inside a snapshot (the read snapshot must not be mixed with anything) */
    CHECK(D->begin_snapshot(c) == 0);
    CHECK(D->reload_requests(c, 0, cb_req, a, &last, &gap) == -1);
    CHECK_HAS(D->errmsg(c), "snapshot");
    CHECK(D->requests_max(c, &mx) == -1);
    db_status_t st0 = { 1, true, "", "ns1" };
    CHECK(D->report_status(c, &st0) == -1);
    CHECK_HAS(D->errmsg(c), "snapshot");
    D->end_snapshot(c);
    free(a);

    /* LISTEN karidns_reload: the notification of an INSERT wakes the socket; karidns_changes notifications do not */
    CHECK(D->watch_requests(c) == 0);
    int fd = D->wait_fd(c);
    CHECK(fd >= 0);
    bool changed = true;
    CHECK(D->drain_notifications(c, &changed) == 0 && !changed);
    Q("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (2, 'rq1.b.test', 'A', '192.0.2.31', 60)");
    usleep(200000);
    CHECK(D->drain_notifications(c, &changed) == 0 && !changed);
    Q("INSERT INTO karidns_reload_requests DEFAULT VALUES");
    struct pollfd pf = { fd, POLLIN, 0 };
    CHECK_MSG(poll(&pf, 1, 5000) == 1, "the socket becomes readable");
    CHECK(D->drain_notifications(c, &changed) == 0 && changed);
    D->close(c);

    /* a connection that listens to karidns_changes cannot be switched */
    c = open_drv(NULL);
    if (c) {
        CHECK(D->check_schema(c, &si) == 0);
        uint64_t ver = 0;
        bool repl = false;
        CHECK(D->poll_version(c, &ver, &repl) == 0);
        CHECK(D->watch_requests(c) == -1);
        D->close(c);
    }

    /* requesters take the lock in the trigger and keep it until they commit: generations become visible in order */
    PGconn *w1 = connect_db(g_db), *w2 = connect_db(g_db);
    if (w1 && w2) {
        qx(w1, "BEGIN");
        qx(w1, "INSERT INTO karidns_reload_requests (zone) VALUES ('w1.test')");
        qx(w2, "SET lock_timeout = '300ms'");
        PGresult *r = PQexec(w2, "INSERT INTO karidns_reload_requests (zone) VALUES ('w2.test')");
        CHECK_MSG(r && PQresultStatus(r) == PGRES_FATAL_ERROR && PQresultErrorField(r, PG_DIAG_SQLSTATE) &&
                      !strcmp(PQresultErrorField(r, PG_DIAG_SQLSTATE), "55P03"),
                  "the second requester waits for the first to commit");
        PQclear(r);
        qx(w1, "COMMIT");
        CHECK(qx(w2, "INSERT INTO karidns_reload_requests (zone) VALUES ('w2.test')"));
        qv(g_admin, "SELECT (SELECT generation FROM karidns_reload_requests WHERE zone = 'w2.test') > (SELECT generation FROM karidns_reload_requests WHERE zone = 'w1.test')", v, sizeof(v));
        CHECK_MSG(!strcmp(v, "t"), "the generation order is the commit order");
    }
    if (w1) PQfinish(w1);
    if (w2) PQfinish(w2);
}

static void status_row(const char *sid, char *out, size_t cap) {
    char sql[300];
    snprintf(sql, sizeof(sql), "SELECT generation || '|' || ok || '|' || failed_zones || '|' || (applied_at > now() - interval '1 minute') FROM karidns_server_status WHERE server_id = '%s'", sid);
    qv(g_admin, sql, out, cap);
}

static void test_status(void) {
    printf("server status (B11)\n");
    db_conn_t *c = open_drv(NULL);
    if (!c) return;
    db_schema_info_t si;
    CHECK(D->check_schema(c, &si) == 0);
    /* the session is read only by default; the status write is a READ WRITE transaction of its own */
    PGresult *r = PQexec(c->pg, "SHOW default_transaction_read_only");
    CHECK(r && PQresultStatus(r) == PGRES_TUPLES_OK && !strcmp(PQgetvalue(r, 0, 0), "on"));
    PQclear(r);
    db_status_t s1 = { 7, true, "", "ns1" };
    CHECK_MSG(D->report_status(c, &s1) == 0, "%s", D->errmsg(c));
    char row[600];
    status_row("ns1", row, sizeof(row));
    CHECK_MSG(!strcmp(row, "7|true||true"), "row: %s", row);
    /* upsert: the same server id, another outcome, with the lines of failed zones; another server id is another row */
    db_status_t s2 = { 9, false, "z.test.: reason one\nw.test.: reason \\010 two", "ns1" };
    CHECK(D->report_status(c, &s2) == 0);
    status_row("ns1", row, sizeof(row));
    CHECK_MSG(!strcmp(row, "9|false|z.test.: reason one\nw.test.: reason \\010 two|true"), "row: %s", row);
    db_status_t s3 = { 4, true, NULL, "ns2" };
    CHECK(D->report_status(c, &s3) == 0);
    status_row("ns2", row, sizeof(row));
    CHECK_MSG(!strcmp(row, "4|true||true"), "row: %s", row);
    qv(g_admin, "SELECT count(*) FROM karidns_server_status", row, sizeof(row));
    CHECK(!strcmp(row, "2"));
    /* a value that is not text (an invalid UTF-8 byte): the server refuses it, the transaction is rolled back, the connection works on */
    char enc[32];
    qv(g_admin, "SHOW server_encoding", enc, sizeof(enc));
    db_status_t sbad = { 10, false, "\xff\xfe: bad", "ns1" };
    int rc = D->report_status(c, &sbad);
    if (strcmp(enc, "SQL_ASCII") != 0) {                  /* a SQL_ASCII database takes any byte */
        CHECK_MSG(rc == -1, "invalid UTF-8: %d", rc);
        status_row("ns1", row, sizeof(row));
        CHECK_MSG(!strncmp(row, "9|false|", 8), "the failed write changed nothing: %s", row);
    }
    CHECK(D->report_status(c, &s1) == 0);
    /* the server id: 1..64 bytes */
    db_status_t se = { 1, true, "", "" };
    CHECK(D->report_status(c, &se) == -1);
    char longid[80];
    memset(longid, 'a', 65);
    longid[65] = '\0';
    db_status_t sl = { 1, true, "", longid };
    CHECK(D->report_status(c, &sl) == -1);
    longid[64] = '\0';
    CHECK(D->report_status(c, &sl) == 0);
    Q("DELETE FROM karidns_server_status WHERE server_id <> 'ns1'");

    /* a role that may read but not write (the loader role before the script's grant): permission denied, not retryable, and the
     * connection is usable afterwards; then with INSERT, UPDATE the same session writes although it is read only by default */
    char role[64], sql[300];
    snprintf(role, sizeof(role), "karidns_test_st_%d", (int)getpid());
    snprintf(sql, sizeof(sql), "CREATE ROLE %s", role);
    PGresult *cr = PQexec(g_maintc, sql);
    bool have_role = PQresultStatus(cr) == PGRES_COMMAND_OK;
    PQclear(cr);
    if (!have_role) {
        printf("  [SKIP] the PostgreSQL role may not create roles: the privilege cases are not tested\n");
    } else {
        snprintf(sql, sizeof(sql), "GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s", role);
        Q(sql);
        snprintf(sql, sizeof(sql), "SET ROLE %s", role);
        CHECK(qx(c->pg, sql));
        int rc2 = D->report_status(c, &s2);
        CHECK_MSG(rc2 == -1, "no INSERT privilege: %d", rc2);
        CHECK_HAS(D->errmsg(c), "permission denied");
        CHECK(strstr(D->errmsg(c), "retry later") == NULL);
        uint64_t mx = 0;
        CHECK(D->requests_max(c, &mx) == 0);                       /* the aborted transaction was rolled back */
        status_row("ns1", row, sizeof(row));
        CHECK_MSG(!strncmp(row, "7|true|", 7), "nothing written: %s", row);
        CHECK(qx(c->pg, "RESET ROLE"));
        snprintf(sql, sizeof(sql), "GRANT INSERT, UPDATE ON karidns_server_status TO %s", role);
        Q(sql);
        snprintf(sql, sizeof(sql), "SET ROLE %s", role);
        CHECK(qx(c->pg, sql));
        CHECK_MSG(D->report_status(c, &s2) == 0, "%s", D->errmsg(c));
        status_row("ns1", row, sizeof(row));
        CHECK_MSG(!strncmp(row, "9|false|", 8), "written with INSERT, UPDATE: %s", row);
        CHECK(qx(c->pg, "RESET ROLE"));
        snprintf(sql, sizeof(sql), "DROP OWNED BY %s", role);
        Q(sql);
        snprintf(sql, sizeof(sql), "DROP ROLE %s", role);
        PQclear(PQexec(g_maintc, sql));
    }

    /* a source without the tables */
    Q("CREATE SCHEMA karidns_test_noreq");
    Q("CREATE TABLE karidns_test_noreq.domains (id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, master VARCHAR(128), last_check INT, type TEXT NOT NULL, notified_serial BIGINT, account VARCHAR(40), options TEXT, catalog VARCHAR(255))");
    Q("CREATE TABLE karidns_test_noreq.records (id BIGSERIAL PRIMARY KEY, domain_id INT, name VARCHAR(255), type VARCHAR(10), content VARCHAR(65535), ttl INT, prio INT, disabled BOOL, ordername VARCHAR(255), auth BOOL)");
    Q("CREATE TABLE karidns_test_noreq.domainmetadata (id SERIAL PRIMARY KEY, domain_id INT, kind VARCHAR(32), content TEXT)");
    Q("CREATE TABLE karidns_test_noreq.cryptokeys (id SERIAL PRIMARY KEY, domain_id INT, flags INT, active BOOL, published BOOL, content TEXT)");
    db_conn_t *c2 = open_drv("karidns_test_noreq");
    if (c2) {
        CHECK(D->check_schema(c2, &si) == 0);
        CHECK_MSG(!si.has_reload_requests && !si.has_server_status, "no tables, no flags");
        uint64_t mx = 0, lg_ = 0;
        bool g_ = false;
        CHECK(D->requests_max(c2, &mx) == DB_ERR_UNAVAILABLE);
        CHECK(D->reload_requests(c2, 0, cb_req, NULL, &lg_, &g_) == DB_ERR_UNAVAILABLE);
        CHECK(D->report_status(c2, &s1) == DB_ERR_UNAVAILABLE);
        CHECK_HAS(D->errmsg(c2), "does not exist");
        D->close(c2);
    }
    Q("DROP SCHEMA karidns_test_noreq CASCADE");

    /* the backend is terminated from outside: a transient error */
    char pid[32];
    qv(c->pg, "SELECT pg_backend_pid()", pid, sizeof(pid));
    snprintf(sql, sizeof(sql), "SELECT pg_terminate_backend(%s)", pid);
    Q(sql);
    usleep(300000);
    CHECK(D->report_status(c, &s1) == DB_ERR_RETRY);
    CHECK_HAS(D->errmsg(c), "retry later");
    D->close(c);
}

/* ------------------------------------------------------------------ main */
static void cleanup(void) {
    if (g_admin) PQfinish(g_admin);
    g_admin = NULL;
    if (g_maintc && g_db[0]) {
        char sql[200];
        snprintf(sql, sizeof(sql), "DROP DATABASE IF EXISTS %s", g_db);
        PGresult *r = PQexec(g_maintc, sql);
        PQclear(r);
    }
    if (g_maintc) PQfinish(g_maintc);
    g_maintc = NULL;
    if (g_dir[0]) rm_tree(g_dir);
}

int main(int argc, char **argv) {
    snprintf(g_root, sizeof(g_root), "%s", argc > 1 ? argv[1] : "tests/db");
    const char *pg = getenv("KARIDNS_TEST_PG");
    snprintf(g_maint, sizeof(g_maint), "%s", pg && *pg ? pg : "dbname=postgres");
    char ci[1200];
    snprintf(ci, sizeof(ci), "%s connect_timeout=5", g_maint);
    g_maintc = PQconnectdb(ci);
    if (PQstatus(g_maintc) != CONNECTION_OK) {
        char line[200];
        first_line(PQerrorMessage(g_maintc), line, sizeof(line));
        printf("SKIP: no PostgreSQL server for the driver tests (%s); set KARIDNS_TEST_PG to a conninfo\n", line);
        PQfinish(g_maintc);
        g_maintc = NULL;
        return 0;
    }
    snprintf(g_db, sizeof(g_db), "karidns_test_unit_%d", (int)getpid());
    char sql[200];
    snprintf(sql, sizeof(sql), "CREATE DATABASE %s", g_db);
    PGresult *r = PQexec(g_maintc, sql);
    bool made = PQresultStatus(r) == PGRES_COMMAND_OK;
    if (!made) {
        char line[200];
        first_line(PQerrorMessage(g_maintc), line, sizeof(line));
        printf("SKIP: the PostgreSQL role may not create databases (%s)\n", line);
    }
    PQclear(r);
    if (!made) {
        PQfinish(g_maintc);
        return 0;
    }
    atexit(cleanup);
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/karidns_dbpg_XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(g_dir)) {
        printf("  [FAIL] cannot create a temporary directory\n");
        return 1;
    }
    snprintf(g_ci, sizeof(g_ci), "%s/conninfo", g_dir);
    write_ci(g_db);
    printf("libpq %d, server %d, test database %s\n", PQlibVersion(), PQserverVersion(g_maintc), g_db);
    if (PQserverVersion(g_maintc) < 130000) {
        printf("SKIP: PostgreSQL 13 or newer is needed (xid8)\n");
        return 0;
    }
    g_admin = connect_db(g_db);
    if (!g_admin) return 1;
    char path[500];
    snprintf(path, sizeof(path), "%s/pdns_schema.pgsql.sql", g_root);
    char *schema = slurp(path);
    snprintf(path, sizeof(path), "%s/../../db/karidns_ext.pgsql.sql", g_root);
    char *ext = slurp(path);
    if (!schema || !ext) {
        printf("  [FAIL] cannot read the schema files below %s\n", g_root);
        return 1;
    }
    CHECK(qx(g_admin, schema));
    CHECK(qx(g_admin, ext));
    free(schema);
    free(ext);
    test_conninfo();
    test_schema();
    test_schema_findings();
    test_rows();
    test_zone_soa();
    test_ext_and_profiles();
    test_scan_in();
    test_search_path();
    test_changes();
    test_notify();
    test_errors();
    test_scan_failures();
    test_requests();
    test_status();
    test_v1_and_migration();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

#else /* !KARIDNS_DB_POSTGRESQL */

int main(void) {
    printf("SKIP: built without the PostgreSQL driver\n");
    return 0;
}

#endif
