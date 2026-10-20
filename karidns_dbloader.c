/*
 * karidns_dbloader.c - karidns-dbloader (beta design 1; milestone B3: the offline dump mode).
 *
 * Reads the PowerDNS 5.1 tables of one database through a driver (dns_db_driver.h), converts every zone with the
 * shared reader (dns_pdns_reader.h) and writes the KDB1 stream (dns_db_stream.h) the loader sends to the Backend:
 * HELLO, BATCH_BEGIN (startup), per zone ZONE_BEGIN / ZONE_DATA... / ZONE_END or ZONE_FAILED, BATCH_END.
 *
 *   karidns-dbloader --dump OUT --driver sqlite3 --database-file PATH [options]     (B3, this file)
 *   karidns-dbloader -s FD                                                          (B4a: stream mode)
 *
 * Ordinary process code like the tools (malloc and file I/O are fine, no Capsicum in beta); what it reads from the
 * database is untrusted and is validated by the reader.  What it writes is untrusted for the Backend.
 *
 * Bulk path (design 5.1): one snapshot; list_zones; scan_records over all zones in domain_id order feeding
 * pdns_zone_add_record() zone by zone; metadata and the cryptokeys existence list are read once before.  With --zone
 * only that zone is read (scan_records(domain_id)).  Zones are written in domains.id order, so two runs on the same
 * database give the same bytes (the HELLO of a dump carries pid 0 for that reason).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include "dns_db_driver.h"
#include "dns_db_stream.h"
#include "dns_pdns_reader.h"

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

enum { EXIT_OK = 0, EXIT_ZONES_FAILED = 1, EXIT_USAGE = 2, EXIT_ERROR = 3, EXIT_RETRY = 4 };

/* ------------------------------------------------------------------------------------------------------------- */
/* drivers compiled in                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

static const db_driver_t *const k_drivers[] = {
#ifdef KARIDNS_DB_SQLITE3
    &db_driver_sqlite3,
#endif
#ifdef KARIDNS_DB_POSTGRESQL
    &db_driver_postgresql,
#endif
    NULL
};

static const db_driver_t *driver_find(const char *name) {
    for (size_t i = 0; k_drivers[i]; i++)
        if (strcmp(k_drivers[i]->name, name) == 0) return k_drivers[i];
    return NULL;
}

static void drivers_list(char *out, size_t cap) {
    out[0] = '\0';
    for (size_t i = 0; k_drivers[i]; i++) {
        size_t l = strlen(out);
        snprintf(out + l, cap - l, "%s%s", i ? ", " : "", k_drivers[i]->name);
    }
    if (!out[0]) snprintf(out, cap, "none");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* loader state                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { int64_t id; char *name; char *type; } zinfo_t;
typedef struct { int64_t domain_id; char *kind; char *content; } meta_t;

typedef struct {
    const db_driver_t *drv;
    db_conn_t *conn;
    FILE *out;
    bool io_error;
    uint16_t view;
    pdns_opts_t opts;
    /* zone list */
    zinfo_t *zones;
    size_t nz, zcap;
    /* metadata (sorted by domain_id) and zones with cryptokeys */
    meta_t *meta;
    size_t nm, mcap, mi;
    int64_t *keys;
    size_t nk, kcap;
    /* the zone being collected */
    size_t zi;
    pdns_zone_t *cur;
    bool cur_open;
    /* results */
    uint32_t n_zones, n_failed;       /* ZONE_END / ZONE_FAILED messages written */
    uint32_t n_unwritten;             /* failed zones whose name cannot be written to the stream */
    bool oom;
    kdb_enc_t enc;
} ctx_t;

static int emit_file(void *ud, const uint8_t *msg, size_t len) {
    ctx_t *x = ud;
    if (x->io_error) return -1;
    if (fwrite(msg, 1, len, x->out) != len) {
        x->io_error = true;
        return -1;
    }
    return 0;
}

static int send_enc(ctx_t *x) {
    if (x->enc.err) return -1;
    int rc = emit_file(x, x->enc.buf, x->enc.len);
    kdb_enc_reset(&x->enc);
    return rc;
}

/* reasons go into a TLV `str`: printable ASCII, at most 255 bytes */
static void clean_reason(const char *in, char *out, size_t cap) {
    size_t k = 0;
    for (; in && *in && k < cap - 1 && k < 255; in++) out[k++] = (*in >= 0x20 && *in < 0x7F) ? *in : '?';
    out[k] = '\0';
}

/* ------------------------------------------------------------------------------------------------------------- */
/* collecting the lists                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

static int zone_cb(void *ud, const db_zone_row_t *r) {
    ctx_t *x = ud;
    if (x->nz >= x->zcap) {
        size_t nc = x->zcap ? x->zcap * 2 : 256;
        zinfo_t *nzs = realloc(x->zones, nc * sizeof(*nzs));
        if (!nzs) return x->oom = true;
        x->zones = nzs;
        x->zcap = nc;
    }
    zinfo_t *z = &x->zones[x->nz];
    z->id = r->id;
    z->name = r->name ? strdup(r->name) : NULL;
    z->type = r->type ? strdup(r->type) : NULL;
    if ((r->name && !z->name) || (r->type && !z->type)) {
        free(z->name);
        free(z->type);
        return x->oom = true;
    }
    x->nz++;
    return 0;
}

static int meta_cb(void *ud, const db_meta_row_t *r) {
    ctx_t *x = ud;
    if (x->nm >= x->mcap) {
        size_t nc = x->mcap ? x->mcap * 2 : 256;
        meta_t *nms = realloc(x->meta, nc * sizeof(*nms));
        if (!nms) return x->oom = true;
        x->meta = nms;
        x->mcap = nc;
    }
    meta_t *m = &x->meta[x->nm];
    m->domain_id = r->domain_id;
    m->kind = r->kind ? strdup(r->kind) : NULL;
    m->content = r->content ? strdup(r->content) : NULL;
    if ((r->kind && !m->kind) || (r->content && !m->content)) {
        free(m->kind);
        free(m->content);
        return x->oom = true;
    }
    x->nm++;
    return 0;
}

static int key_cb(void *ud, int64_t id) {
    ctx_t *x = ud;
    if (x->nk >= x->kcap) {
        size_t nc = x->kcap ? x->kcap * 2 : 64;
        int64_t *nk = realloc(x->keys, nc * sizeof(*nk));
        if (!nk) return x->oom = true;
        x->keys = nk;
        x->kcap = nc;
    }
    x->keys[x->nk++] = id;
    return 0;
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y;
}

static bool zone_has_keys(const ctx_t *x, int64_t id) {
    return x->nk && bsearch(&id, x->keys, x->nk, sizeof(int64_t), cmp_i64) != NULL;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* one zone                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

/* The canonical absolute name for a ZONE_FAILED message (the Backend refuses anything else).  false: the name
 * cannot be written as a zone name; the failure is then only reported on stderr. */
static bool canonical_name(const char *dbname, char out[DNS_NAME_TEXT_SIZE]) {
    if (!dbname) return false;
    pdns_zone_t *z = pdns_zone_new(dbname, NULL);
    if (!z) return false;
    bool ok = !z->failed;
    if (ok) snprintf(out, DNS_NAME_TEXT_SIZE, "%s", z->name);
    pdns_zone_free(z);
    return ok;
}

static int send_failed(ctx_t *x, const zinfo_t *zi, const char *reason) {
    char name[DNS_NAME_TEXT_SIZE], why[260], shown[210];
    clean_reason(zi->name ? zi->name : "(NULL)", shown, sizeof(shown));
    fprintf(stderr, "karidns-dbloader: zone '%s' (domains.id %lld): %s\n", shown, (long long)zi->id, reason);
    if (!canonical_name(zi->name, name)) {
        fprintf(stderr, "karidns-dbloader: the zone name is not a valid domain name; not written to the stream\n");
        x->n_unwritten++;
        return 0;
    }
    x->n_failed++;
    clean_reason(reason, why, sizeof(why));
    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_FAILED) != 0 || kdb_enc_u16(&x->enc, 1, x->view) != 0 ||
        kdb_enc_name(&x->enc, 2, name) != 0 || kdb_enc_i64(&x->enc, 3, zi->id) != 0 || kdb_enc_str(&x->enc, 4, why) != 0 ||
        kdb_enc_end(&x->enc) != 0)
        return -1;
    return send_enc(x);
}

typedef struct { ctx_t *x; bool started; } zemit_t;

static int zone_emit(void *ud, const uint8_t *msg, size_t len) {
    zemit_t *e = ud;
    e->started = true;
    return emit_file(e->x, msg, len);
}

static const char *zone_type_reason(const char *type) {
    if (!type) return "domains.type is NULL";
    if (strcasecmp(type, "NATIVE") == 0 || strcasecmp(type, "MASTER") == 0) return NULL;
    if (strcasecmp(type, "SLAVE") == 0 || strcasecmp(type, "CONSUMER") == 0)
        return "secondary zones (type SLAVE / CONSUMER) are not loaded yet (milestone B7)";
    if (strcasecmp(type, "PRODUCER") == 0) return "catalog producer zones (type PRODUCER) are not loaded yet (later 0.6.x)";
    return "unsupported domains.type";
}

static void open_current(ctx_t *x) {
    if (x->cur_open) return;
    x->cur_open = true;
    x->cur = NULL;
    const zinfo_t *zi = &x->zones[x->zi];
    if (zi->name && !zone_type_reason(zi->type)) x->cur = pdns_zone_new(zi->name, &x->opts);
    if (zi->name && !zone_type_reason(zi->type) && !x->cur) x->oom = true;
}

/* convert and write the zone x->zi; 0, or -1 on a fatal error (output, memory) */
static int finish_current(ctx_t *x) {
    open_current(x);
    const zinfo_t *zi = &x->zones[x->zi];
    pdns_zone_t *z = x->cur;
    int ret = 0;
    const char *tr = zone_type_reason(zi->type);
    char msg[PDNS_ERR_LEN + 100];

    if (x->oom) return -1;
    if (!zi->name) {
        ret = send_failed(x, zi, "domains.name is NULL");
    } else if (tr) {
        ret = send_failed(x, zi, tr);
    } else {
        /* metadata of this zone (sorted by domain_id) */
        while (x->mi < x->nm && x->meta[x->mi].domain_id < zi->id) x->mi++;
        for (; !z->failed && x->mi < x->nm && x->meta[x->mi].domain_id == zi->id; x->mi++) {
            db_meta_row_t m = { zi->id, x->meta[x->mi].kind, x->meta[x->mi].content };
            pdns_zone_add_meta(z, &m);
        }
        const char *why = NULL;
        if (pdns_zone_finish(z) != 0) {
            why = z->error;
        } else if (zone_has_keys(x, zi->id) && !(z->flags & PDNS_F_PRESIGNED)) {
            /* design 3.5: PowerDNS would sign the zone online, KariDNS serves pre-signed data only */
            why = "the zone has cryptokeys but no PRESIGNED=1 metadata (online signing is not supported)";
        }
        for (size_t i = 0; i < z->n_warnings; i++)
            fprintf(stderr, "karidns-dbloader: warning: %s\n", z->warnings[i]);
        if (why) {
            ret = send_failed(x, zi, why);
        } else {
            pdns_kdb_params_t p = { x->view, zi->id, KDB_ZK_PRIMARY, NULL };
            zemit_t e = { x, false };
            if (pdns_zone_encode_kdb(z, &p, zone_emit, &e, msg, sizeof(msg)) == 0) {
                x->n_zones++;
            } else if (x->io_error) {
                ret = -1;
            } else {
                if (e.started) {        /* cannot happen today (the refusals come before ZONE_BEGIN); be safe */
                    if (kdb_enc_begin(&x->enc, KDB_T_ZONE_ABORT) != 0 || kdb_enc_str(&x->enc, 1, "encoding failed") != 0 ||
                        kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
                        ret = -1;
                }
                if (ret == 0) ret = send_failed(x, zi, msg);
            }
        }
    }
    pdns_zone_free(z);
    x->cur = NULL;
    x->cur_open = false;
    return ret;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the scan                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static int rec_cb(void *ud, int64_t did, const db_record_row_t *row) {
    ctx_t *x = ud;
    while (x->zi < x->nz && x->zones[x->zi].id < did) {
        if (finish_current(x) != 0) return 1;
        x->zi++;
    }
    if (x->zi >= x->nz || x->zones[x->zi].id != did) return 0;      /* a row of a domain that is not listed: ignored */
    open_current(x);
    if (x->oom) return 1;
    if (x->cur && !x->cur->failed) pdns_zone_add_record(x->cur, row);
    return 0;
}

static int send_simple_header(ctx_t *x) {
    if (kdb_enc_begin(&x->enc, KDB_T_HELLO) != 0 || kdb_enc_u16(&x->enc, 1, KDB_VERSION) != 0 ||
        kdb_enc_str(&x->enc, 2, KARIDNS_VERSION) != 0 || kdb_enc_str(&x->enc, 3, x->drv->name) != 0 ||
        kdb_enc_u32(&x->enc, 4, 0) != 0 || kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
        return -1;
    if (kdb_enc_begin(&x->enc, KDB_T_BATCH_BEGIN) != 0 || kdb_enc_u64(&x->enc, 1, 1) != 0 ||
        kdb_enc_u8(&x->enc, 2, KDB_BATCH_STARTUP) != 0 || kdb_enc_u64(&x->enc, 3, 0) != 0 || kdb_enc_end(&x->enc) != 0 ||
        send_enc(x) != 0)
        return -1;
    return 0;
}

static int send_batch_end(ctx_t *x) {
    if (kdb_enc_begin(&x->enc, KDB_T_BATCH_END) != 0 || kdb_enc_u64(&x->enc, 1, 1) != 0 ||
        kdb_enc_u32(&x->enc, 2, x->n_zones) != 0 || kdb_enc_u32(&x->enc, 3, x->n_failed) != 0 ||
        kdb_enc_u32(&x->enc, 4, 0) != 0 || kdb_enc_end(&x->enc) != 0 || send_enc(x) != 0)
        return -1;
    return 0;
}

static int names_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 1 && a[la - 1] == '.') la--;
    if (lb > 1 && b[lb - 1] == '.') lb--;
    return la == lb && strncasecmp(a, b, la) == 0;
}

static int db_err(ctx_t *x, int rc, const char *what) {
    fprintf(stderr, "karidns-dbloader: %s: %s\n", what, x->conn ? x->drv->errmsg(x->conn) : "?");
    return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
}

/* The whole dump.  Returns an exit status. */
static int run_dump(ctx_t *x, const db_source_t *src, const char *only_zone) {
    char err[DB_ERRLEN];
    int rc = x->drv->open(&x->conn, src, err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "karidns-dbloader: %s\n", err);
        return rc == DB_ERR_RETRY ? EXIT_RETRY : EXIT_ERROR;
    }
    int status = EXIT_OK;
    db_schema_info_t si;
    if ((rc = x->drv->check_schema(x->conn, &si)) != 0) {
        status = db_err(x, rc, "schema");
        goto out;
    }
    if ((rc = x->drv->begin_snapshot(x->conn)) != 0) {
        status = db_err(x, rc, "snapshot");
        goto out;
    }
    if ((rc = x->drv->list_zones(x->conn, zone_cb, x)) != 0) {
        status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading the zone list");
        if (x->oom) fprintf(stderr, "karidns-dbloader: out of memory\n");
        goto out_snap;
    }
    if (only_zone) {        /* keep only that zone */
        size_t keep = 0;
        for (size_t i = 0; i < x->nz; i++) {
            if (x->zones[i].name && names_equal(x->zones[i].name, only_zone)) {
                if (keep != i) x->zones[keep] = x->zones[i];
                keep++;
            } else {
                free(x->zones[i].name);
                free(x->zones[i].type);
            }
        }
        x->nz = keep;
        if (!keep) {
            fprintf(stderr, "karidns-dbloader: zone '%.200s' is not in the database\n", only_zone);
            status = EXIT_ERROR;
            goto out_snap;
        }
    }
    {
        const int64_t *sel = only_zone ? &x->zones[0].id : NULL;
        int64_t id0 = sel ? *sel : 0;
        if ((rc = x->drv->scan_metadata(x->conn, sel ? &id0 : NULL, meta_cb, x)) != 0 ||
            (rc = x->drv->zones_with_keys(x->conn, key_cb, x)) != 0) {
            status = x->oom ? EXIT_ERROR : db_err(x, rc, "reading metadata");
            if (x->oom) fprintf(stderr, "karidns-dbloader: out of memory\n");
            goto out_snap;
        }
        qsort(x->keys, x->nk, sizeof(int64_t), cmp_i64);

        if (send_simple_header(x) != 0) {
            fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
            status = EXIT_ERROR;
            goto out_snap;
        }
        rc = x->drv->scan_records(x->conn, sel ? &id0 : NULL, rec_cb, x);
        if (rc != 0 && rc != DB_STOPPED) {
            status = db_err(x, rc, "reading records");
            goto out_snap;
        }
        if (rc == DB_STOPPED && !x->io_error && !x->oom) {
            fprintf(stderr, "karidns-dbloader: internal error: the scan was stopped\n");
            status = EXIT_ERROR;
            goto out_snap;
        }
        int fatal = rc == DB_STOPPED;
        while (!fatal && x->zi < x->nz) {
            if (finish_current(x) != 0) fatal = 1;
            x->zi++;
        }
        if (fatal || x->io_error || x->oom) {
            if (x->oom) fprintf(stderr, "karidns-dbloader: out of memory\n");
            else fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
            status = EXIT_ERROR;
            goto out_snap;
        }
        if (send_batch_end(x) != 0) {
            fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
            status = EXIT_ERROR;
            goto out_snap;
        }
        if (x->n_failed || x->n_unwritten) status = EXIT_ZONES_FAILED;
    }
out_snap:
    x->drv->end_snapshot(x->conn);
out:
    x->drv->close(x->conn);
    x->conn = NULL;
    return status;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* command line                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static void usage(FILE *fp) {
    char drv[128];
    drivers_list(drv, sizeof(drv));
    fprintf(fp,
        "karidns-dbloader %s - reads PowerDNS 5.1 tables and writes the KDB1 zone stream of the KariDNS Backend\n"
        "\n"
        "usage:\n"
        "  karidns-dbloader --dump OUT --driver DRIVER --database-file PATH [options]\n"
        "  karidns-dbloader -s FD                    (stream mode; started by karidns, not by hand)\n"
        "\n"
        "Dump mode writes the stream exactly as the loader sends it to the Backend: HELLO, BATCH_BEGIN (startup), per\n"
        "zone ZONE_BEGIN / ZONE_DATA... / ZONE_END (or ZONE_FAILED with the reason), BATCH_END.  Zones come in\n"
        "domains.id order, so two runs on the same database write the same bytes (the HELLO carries pid 0).\n"
        "\n"
        "options:\n"
        "  --dump OUT          write the stream to the file OUT (\"-\" = standard output)\n"
        "  --driver DRIVER     database driver; compiled in: %s\n"
        "  --database-file F   sqlite3: the database file; it must be in WAL mode.  The name is used byte for byte\n"
        "                      ('%%XX' is not decoded); a name starting with \"file:\" is refused (write ./file:...)\n"
        "  --view-index N      view index in ZONE_BEGIN / ZONE_FAILED (0..65535, default 0)\n"
        "  --zone NAME         dump only this zone (read with one query per zone instead of the bulk scan)\n"
        "  --default-ttl N     TTL for a records.ttl that is NULL (1..2147483647, default 3600)\n"
        "  --loader-threads N  1..16, default 1.  Accepted; the dump runs on one thread (parallel workers: milestone B6)\n"
        "  --version           print the version\n"
        "  -h, --help          this text\n"
        "\n"
        "exit status:\n"
        "  0  every zone was written\n"
        "  1  the stream is complete but some zones went out as ZONE_FAILED (reason on stderr)\n"
        "  2  usage error (nothing was read)\n"
        "  3  error: database, schema, output or memory; the output file is removed\n"
        "  4  transient database error (busy); try again\n"
        "\n"
        "examples:\n"
        "  karidns-dbloader --dump /tmp/zones.kdb --driver sqlite3 --database-file /var/db/karidns/zones.sqlite3\n"
        "  karidns-dbloader --dump - --driver sqlite3 --database-file zones.sqlite3 --zone example.test | od -c | head\n"
        "  karidns-dbloader --dump /tmp/view1.kdb --driver sqlite3 --database-file view1.sqlite3 --view-index 1 --default-ttl 300\n",
        KARIDNS_VERSION, drv);
}

static bool parse_uint(const char *s, unsigned long min, unsigned long max, unsigned long *out) {
    char *end;
    if (!*s || *s == '-' || *s == '+') return false;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end || v < min || v > max) return false;
    *out = v;
    return true;
}

int main(int argc, char **argv) {
    static const struct option longopts[] = {
        { "dump", required_argument, NULL, 'd' },          { "driver", required_argument, NULL, 'D' },
        { "database-file", required_argument, NULL, 'f' }, { "conninfo-file", required_argument, NULL, 'c' },
        { "schema", required_argument, NULL, 'S' },        { "view-index", required_argument, NULL, 'v' },
        { "zone", required_argument, NULL, 'z' },          { "default-ttl", required_argument, NULL, 't' },
        { "loader-threads", required_argument, NULL, 'j' }, { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },                { NULL, 0, NULL, 0 }
    };
    const char *dump = NULL, *driver = NULL, *dbfile = NULL, *conninfo = NULL, *schema = NULL, *zone = NULL;
    const char *stream_fd = NULL;
    unsigned long view = 0, ttl = 0, threads = 1, v;
    int ch;
    while ((ch = getopt_long(argc, argv, "hs:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'd': dump = optarg; break;
        case 'D': driver = optarg; break;
        case 'f': dbfile = optarg; break;
        case 'c': conninfo = optarg; break;
        case 'S': schema = optarg; break;
        case 's': stream_fd = optarg; break;
        case 'z': zone = optarg; break;
        case 'v':
            if (!parse_uint(optarg, 0, 65535, &view)) {
                fprintf(stderr, "karidns-dbloader: --view-index must be 0..65535\n");
                return EXIT_USAGE;
            }
            break;
        case 't':
            if (!parse_uint(optarg, 1, PDNS_MAX_TTL, &ttl)) {
                fprintf(stderr, "karidns-dbloader: --default-ttl must be 1..%u\n", PDNS_MAX_TTL);
                return EXIT_USAGE;
            }
            break;
        case 'j':
            if (!parse_uint(optarg, 1, 16, &threads)) {
                fprintf(stderr, "karidns-dbloader: --loader-threads must be 1..16\n");
                return EXIT_USAGE;
            }
            break;
        case 'V': printf("karidns-dbloader %s\n", KARIDNS_VERSION); return EXIT_OK;
        case 'h': usage(stdout); return EXIT_OK;
        default: usage(stderr); return EXIT_USAGE;
        }
    }
    (void)threads;
    if (optind != argc) {
        fprintf(stderr, "karidns-dbloader: unexpected argument '%s'\n", argv[optind]);
        usage(stderr);
        return EXIT_USAGE;
    }
    if (stream_fd) {
        if (!parse_uint(stream_fd, 0, 1u << 20, &v)) {
            fprintf(stderr, "karidns-dbloader: -s needs a file descriptor number\n");
            return EXIT_USAGE;
        }
        fprintf(stderr, "karidns-dbloader: stream mode (-s FD) is not implemented in this build (milestone B4a); "
                        "use --dump OUT\n");
        return EXIT_USAGE;
    }
    if (!dump || !driver) {
        fprintf(stderr, "karidns-dbloader: --dump and --driver are required\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    const db_driver_t *drv = driver_find(driver);
    if (!drv) {
        char list[128];
        drivers_list(list, sizeof(list));
        if (strcmp(driver, "postgresql") == 0 || strcmp(driver, "sqlite3") == 0)
            fprintf(stderr, "karidns-dbloader: driver %s is not available in this build (%s; compiled in: %s)\n", driver,
                    strcmp(driver, "postgresql") == 0 ? "the PostgreSQL driver comes with milestone B10" : "built without DB_DRIVERS=sqlite3",
                    list);
        else
            fprintf(stderr, "karidns-dbloader: unknown driver '%s' (compiled in: %s)\n", driver, list);
        return EXIT_USAGE;
    }
    if (strcmp(drv->name, "sqlite3") == 0 && !dbfile) {
        fprintf(stderr, "karidns-dbloader: driver sqlite3 needs --database-file\n");
        return EXIT_USAGE;
    }
    if (strcmp(drv->name, "sqlite3") == 0 && (conninfo || schema)) {
        fprintf(stderr, "karidns-dbloader: --conninfo-file and --schema are for the postgresql driver\n");
        return EXIT_USAGE;
    }

    ctx_t x;
    memset(&x, 0, sizeof(x));
    x.drv = drv;
    x.view = (uint16_t)view;
    x.opts.default_ttl = (uint32_t)ttl;
    kdb_enc_init(&x.enc);
    bool to_stdout = strcmp(dump, "-") == 0;
    x.out = to_stdout ? stdout : fopen(dump, "wb");
    if (!x.out) {
        fprintf(stderr, "karidns-dbloader: cannot create %s: %s\n", dump, strerror(errno));
        return EXIT_ERROR;
    }
    db_source_t src = { drv->name, dbfile, conninfo, schema, 0 };
    int status = run_dump(&x, &src, zone);
    if (x.out && (fflush(x.out) != 0 || ferror(x.out)) && status < EXIT_ERROR) {
        fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
        status = EXIT_ERROR;
    }
    if (!to_stdout && fclose(x.out) != 0 && status < EXIT_ERROR) {
        fprintf(stderr, "karidns-dbloader: cannot write the output: %s\n", strerror(errno));
        status = EXIT_ERROR;
    }
    if (status >= EXIT_ERROR && !to_stdout) unlink(dump);
    for (size_t i = 0; i < x.nz; i++) {
        free(x.zones[i].name);
        free(x.zones[i].type);
    }
    free(x.zones);
    for (size_t i = 0; i < x.nm; i++) {
        free(x.meta[i].kind);
        free(x.meta[i].content);
    }
    free(x.meta);
    free(x.keys);
    kdb_enc_free(&x.enc);
    return status;
}
