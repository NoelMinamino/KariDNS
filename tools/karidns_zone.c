/*
 * karidns_zone.c - karidns-zone: the command line of the 0.6.0 ZoneImporter and ZoneExporter (docs/karidns-zone.md).
 *
 *   karidns-zone import [options] <zone> <file|->
 *   karidns-zone import --all [options] <tinydns-data-file>
 *   karidns-zone import --signer [options] <zone> <signed-zone-file|->
 *   karidns-zone export [options] <zone> [<file>]
 *   karidns-zone export --all --dir <dir> [options]
 *
 * A thin shell over dns_zone_import.c (zone file -> PowerDNS rows, one transaction per zone, the checks of karicheck, the read-back through the
 * loader's reader) and dns_zone_export.c (rows -> zone file text, canonical order, verified).  This file reads the database settings the way
 * karicheck db does (options { database { } } and the views of karidns.conf, or --sqlite3 / --conninfo-file), applies the check-* options and the
 * size limits of the configuration, writes output files safely and reports through dns_diag (text, or one JSON document with --json).
 *
 * Ordinary process code (malloc allowed); it runs as an ordinary user and never needs root.  Exit status 0 ok, 1 failed, 2 usage error, 3 (import
 * --signer) the zone changed since the signed file was made, 4 (import --signer) the zone is locked by another import or the database is busy: try again.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dns_config_parser.h"
#include "dns_db_driver.h"
#include "dns_diag.h"
#include "dns_zone_export.h"
#include "dns_zone_import.h"
#include "dns_zone_text.h"

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

/* Stub for open_via_dir_cache used by dns_config_parser.c (as in tools/karicheck.c: an ordinary process opens files the plain way) */
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

#define KZ_CONF_MAX ((size_t)16 << 20)
#define KZ_MAX_TYPES 64
#define KZ_NAME_MAX 255                                 /* a file name */

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

static const db_driver_t *kz_driver_find(const char *name) {
    for (size_t i = 0; k_drivers[i]; i++)
        if (strcmp(k_drivers[i]->name, name) == 0) return k_drivers[i];
    return NULL;
}

static void kz_drivers_list(char *out, size_t cap) {
    out[0] = '\0';
    for (size_t i = 0; k_drivers[i]; i++) {
        size_t l = strlen(out);
        snprintf(out + l, cap - l, "%s%s", i ? ", " : "", k_drivers[i]->name);
    }
    if (!out[0]) snprintf(out, cap, "none");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* usage                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

static void kz_usage(FILE *fp) {
    fprintf(fp,
        "Usage:\n"
        "  karidns-zone import [options] <zone> <file|->\n"
        "  karidns-zone import --all [options] <tinydns-data-file>\n"
        "  karidns-zone import --signer [options] <zone> <signed-zone-file|->\n"
        "  karidns-zone export [options] <zone> [<file>]\n"
        "  karidns-zone export --all --dir <dir> [options]\n"
        "  karidns-zone --version | -h | --help\n"
        "\n"
        "import reads a zone file (BIND format, or a tinydns data file) and writes the zone to the PowerDNS database in one transaction; export\n"
        "writes a zone of the database as a zone file (canonical order, so two exports of the same zone are the same file).  Both use the\n"
        "rules of the server: the checks of `karicheck zone`, the check-* options and the size limits of the configuration, and the loader's\n"
        "reader (an import is read back before it is committed; it is refused when karidns-dbloader would refuse the zone).\n"
        "\n"
        "Database (the settings of options { database { } } in the configuration, or on the command line):\n"
        "  -c, --config FILE       karidns.conf (default: /usr/local/etc/karidns/karidns.conf when it exists); gives the database, the\n"
        "                          limits and the check-* options of the view, and the file zones of the server\n"
        "      --no-config         do not read a configuration\n"
        "      --view NAME         the view: its database, its limits; import puts the zone in this view (karidns_domain_views), export\n"
        "                          lists only the zones of this view\n"
        "      --sqlite3 FILE      the SQLite3 database file (instead of the configuration's)\n"
        "      --conninfo-file F   the file holding the libpq connection string (PostgreSQL; owned by you, mode 0600 or 0400)\n"
        "      --schema NAME       PostgreSQL: the schema\n"
        "\n"
        "import options:\n"
        "      --all               every zone (. or Z line) of a tinydns data file, each in a transaction of its own\n"
        "      --mode replace|merge  replace: the zone's records become the file's (default); merge: each RRset of the file replaces\n"
        "                          that RRset of the database, the others stay\n"
        "      --types T1,T2       only records of these types are deleted and written (the signer's use); metadata is not touched\n"
        "  -n, --dry-run           do everything but the commit, and list the RRsets that would change\n"
        "      --serial grow|increment|keep  an existing zone's SOA serial must grow (RFC 1982; default); increment writes the\n"
        "                          database serial + 1; keep writes the file's as it is (a restore)\n"
        "      --strict            a warning of the zone checks fails the import\n"
        "      --signer            write a zone the signer signed (karidns-signer): the DNSSEC records (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY) are\n"
        "                          replaced, the SOA serial grows, ordername and auth are set, PRESIGNED and X-KARIDNS-SIGNER are put in the\n"
        "                          metadata; every other record of the file must equal the database's (else exit status 3, nothing written).\n"
        "                          Works with the rights of the signer role.  Not with --mode, --types, --serial, --view, --type, --all\n"
        "      --reload            also add a row to karidns_reload_requests (PostgreSQL)\n"
        "      --type NATIVE|MASTER  domains.type of a NEW zone (default NATIVE; an existing zone keeps its type)\n"
        "      --format bind|tinydns|auto  the input format (auto: tinydns for a name ending in .tinydns or .data or called data, else bind)\n"
        "      --verbose           list the changed RRsets of a real import too\n"
        "      --audit rows|summary  the audit log (docs/karidns-zone.md, AUDIT): rows (default) logs every changed row; summary logs one\n"
        "                          row per transaction, table and operation (PostgreSQL; on SQLite3 the log always has rows).  --signer: summary\n"
        "                          unless --audit rows is given\n"
        "\n"
        "export options:\n"
        "      --format bind|tinydns|auto  the output format (auto: tinydns for a zone with X-KARIDNS-FORMAT tinydns, else bind)\n"
        "      --all --dir DIR     every primary zone, one file per zone in DIR (created when it does not exist): <name>.zone, or\n"
        "                          <name>.tinydns for a tinydns zone; unusual characters of a name are written as %%XX\n"
        "      --force             replace output files that exist (otherwise an existing file is an error and is never touched)\n"
        "\n"
        "Output:\n"
        "      --json              one JSON document on standard output (docs/karicheck.md, JSON OUTPUT; first key \"karidns-zone\");\n"
        "                          export of a single zone then needs a <file>\n"
        "\n"
        "Exit status: 0 ok, 1 failed (an error in a zone, the database or an output file), 2 usage error, 3 import --signer: the zone changed\n"
        "since the signed file was made (nothing was written; sign the zone again), 4 import --signer: the zone is locked by another import or the\n"
        "database is busy (nothing was written; try again).\n"
        "Examples:\n"
        "  karidns-zone import -c /usr/local/etc/karidns/karidns.conf example.test /var/zones/example.test.zone\n"
        "  karidns-zone import --sqlite3 /var/db/karidns/pdns.sqlite3 --dry-run --mode merge example.test -\n"
        "  karidns-zone import --all --sqlite3 /var/db/karidns/pdns.sqlite3 /var/tinydns/root/data\n"
        "  karidns-zone import --signer --json -c /usr/local/etc/karidns/karidns.conf example.test /tmp/example.test.signed\n"
        "  karidns-zone export -c /usr/local/etc/karidns/karidns.conf example.test > example.test.zone\n"
        "  karidns-zone export --all --dir /var/backups/zones --sqlite3 /var/db/karidns/pdns.sqlite3\n");
}

/* A usage error: one message and the usage text on stderr; with --json only the message goes into the document.  Exit status 2. */
static int kz_usage_error(bool json, dns_diag_code_t code, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static int kz_usage_error(bool json, dns_diag_code_t code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char msg[600];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    dns_diag(DIAG_ERROR, code, NULL, 0, "karidns-zone: %s\n", msg);
    if (!json) kz_usage(stderr);
    return 2;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* arguments                                                                                                      */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    bool json, verbose, dry_run, strict, reload, all, force, no_config, help, version, signer;
    const char *conf, *view, *sqlite, *conninfo, *schema, *mode, *types, *serial, *type, *format, *dir, *audit;
    int nargs;
    char **args;
    char perr[100];                         /* why the options could not be read */
} kz_args_t;

enum { KO_NOCONFIG = 256, KO_VIEW, KO_SQLITE, KO_CONNINFO, KO_SCHEMA, KO_ALL, KO_MODE, KO_TYPES, KO_SERIAL, KO_STRICT, KO_RELOAD, KO_TYPE, KO_FORMAT, KO_VERBOSE, KO_DIR,
       KO_FORCE, KO_AUDIT, KO_SIGNER };

static const struct option k_long[] = {
    { "config", required_argument, NULL, 'c' }, { "no-config", no_argument, NULL, KO_NOCONFIG }, { "view", required_argument, NULL, KO_VIEW },
    { "sqlite3", required_argument, NULL, KO_SQLITE }, { "conninfo-file", required_argument, NULL, KO_CONNINFO }, { "schema", required_argument, NULL, KO_SCHEMA },
    { "all", no_argument, NULL, KO_ALL }, { "mode", required_argument, NULL, KO_MODE }, { "types", required_argument, NULL, KO_TYPES },
    { "dry-run", no_argument, NULL, 'n' }, { "serial", required_argument, NULL, KO_SERIAL }, { "strict", no_argument, NULL, KO_STRICT },
    { "reload", no_argument, NULL, KO_RELOAD }, { "type", required_argument, NULL, KO_TYPE }, { "format", required_argument, NULL, KO_FORMAT },
    { "verbose", no_argument, NULL, KO_VERBOSE }, { "dir", required_argument, NULL, KO_DIR }, { "force", no_argument, NULL, KO_FORCE }, { "audit", required_argument, NULL, KO_AUDIT },
    { "signer", no_argument, NULL, KO_SIGNER },
    { "help", no_argument, NULL, 'h' }, { "version", no_argument, NULL, 'v' }, { NULL, 0, NULL, 0 }
};

/* --json is taken off first, wherever it stands (before "--"); the rest goes to getopt_long.  0, or 2 (usage error) */
static int kz_parse(int argc, char **argv, const char **cmd, kz_args_t *a) {
    memset(a, 0, sizeof(*a));
    int w = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            while (i < argc) argv[w++] = argv[i++];
            break;
        }
        if (strcmp(argv[i], "--json") == 0) a->json = true;
        else argv[w++] = argv[i];
    }
    argc = w;
    *cmd = NULL;
    if (argc >= 2 && argv[1][0] != '-') {                   /* the command word comes first */
        *cmd = argv[1];
        argv[1] = argv[0];
        argv++;
        argc--;
    }
    optind = 1;
    opterr = 0;                                             /* the message is ours: with --json nothing may reach stderr */
    int c;
    while ((c = getopt_long(argc, argv, ":c:nhv", k_long, NULL)) != -1) {
        switch (c) {
        case 'c': a->conf = optarg; break;
        case 'n': a->dry_run = true; break;
        case 'h': a->help = true; break;
        case 'v': a->version = true; break;
        case KO_NOCONFIG: a->no_config = true; break;
        case KO_VIEW: a->view = optarg; break;
        case KO_SQLITE: a->sqlite = optarg; break;
        case KO_CONNINFO: a->conninfo = optarg; break;
        case KO_SCHEMA: a->schema = optarg; break;
        case KO_ALL: a->all = true; break;
        case KO_MODE: a->mode = optarg; break;
        case KO_TYPES: a->types = optarg; break;
        case KO_SERIAL: a->serial = optarg; break;
        case KO_STRICT: a->strict = true; break;
        case KO_RELOAD: a->reload = true; break;
        case KO_TYPE: a->type = optarg; break;
        case KO_FORMAT: a->format = optarg; break;
        case KO_VERBOSE: a->verbose = true; break;
        case KO_DIR: a->dir = optarg; break;
        case KO_FORCE: a->force = true; break;
        case KO_AUDIT: a->audit = optarg; break;
        case KO_SIGNER: a->signer = true; break;
        case ':': snprintf(a->perr, sizeof(a->perr), "the option %.60s needs a value", argv[optind - 1]); return 2;
        default: snprintf(a->perr, sizeof(a->perr), "unknown option %.60s", argv[optind - 1]); return 2;
        }
    }
    a->nargs = argc - optind;
    a->args = argv + optind;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* configuration and database                                                                                     */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    server_config_t cfg;
    bool have_cfg;
    const char *conf_path;
    const view_config_t *view;              /* --view with a configuration */
    const db_driver_t *drv;
    db_source_t src;
    const char *zone_view;                  /* the view name import puts a zone in / export lists (NULL: none) */
    zone_veff_t veff;
    zone_limits_t limits;
    char actor[96];                         /* the db_role of the SQLite3 audit actor row: karidns-zone:<OS user> */
    pdns_opts_t reader;
    const char **file_zones;                /* the master zones of the configuration (the view's, or all) */
    size_t nfile_zones;
} kz_ctx_t;

static char *kz_read_conf(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        dns_diag(DIAG_ERROR, DC_IO_OPEN, path, 0, "Could not open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        dns_diag(DIAG_ERROR, DC_IO_STAT, path, 0, "Could not examine %s: %s\n", path, strerror(errno));
        close(fd);
        return NULL;
    }
    if (!S_ISREG(sb.st_mode) || (size_t)sb.st_size > KZ_CONF_MAX) {
        dns_diag(DIAG_ERROR, S_ISREG(sb.st_mode) ? DC_IO_READ : DC_IO_NOT_REGULAR, path, 0,
                 S_ISREG(sb.st_mode) ? "%s is larger than the limit for a configuration file\n" : "%s is not a regular file\n", path);
        close(fd);
        return NULL;
    }
    char *buf = malloc((size_t)sb.st_size + 1);
    if (!buf) {
        dns_diag(DIAG_ERROR, DC_INTERNAL_OOM, path, 0, "out of memory\n");
        close(fd);
        return NULL;
    }
    size_t len = 0;
    while (len < (size_t)sb.st_size) {
        ssize_t got = read(fd, buf + len, (size_t)sb.st_size - len);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        len += (size_t)got;
    }
    close(fd);
    buf[len] = '\0';
    return buf;
}

static const view_config_t *kz_find_view(const server_config_t *cfg, const char *name) {
    for (const view_config_t *v = cfg->views; v; v = v->next)
        if (v->name && strcasecmp(v->name, name) == 0) return v;
    return NULL;
}

/* The configuration: -c FILE, else the default one when it exists (--no-config: none).  0, or 1 (a message was given). */
static int kz_load_config(const kz_args_t *a, kz_ctx_t *x) {
    const char *path = a->conf;
    if (a->no_config) return 0;
    if (!path) {
        path = "/usr/local/etc/karidns/karidns.conf";
        if (access(path, F_OK) != 0 && access("/usr/local/etc/karidns.conf", F_OK) == 0) path = "/usr/local/etc/karidns.conf";
        if (access(path, F_OK) != 0) return 0;              /* no configuration, and none asked for */
    }
    char *buf = kz_read_conf(path);
    if (!buf) return 1;
    memset(&x->cfg, 0, sizeof(x->cfg));
    dns_diag_set_file(path);
    int rc = parse_named_conf_ext(buf, path, &x->cfg);
    free(buf);
    dns_diag_set_file(NULL);
    x->have_cfg = true;                                     /* parse_named_conf_ext() may have allocated part of it */
    if (rc != 0) {
        dns_diag(DIAG_ERROR, DC_CONF_PARSE_FAILED, path, 0, "Syntax error in config file: %s\n", path);
        return 1;
    }
    x->conf_path = path;
    return 0;
}

/* Where the data is, and the rules of the server for it.  0, or 1 (a message was given). */
static int kz_resolve(const kz_args_t *a, kz_ctx_t *x) {
    const database_config_t *db = x->have_cfg ? &x->cfg.database : NULL;
    bool shared = true;                                     /* the view reads the shared source: karidns_domain_views decides its zones */
    x->zone_view = a->view;
    if (a->view && x->have_cfg) {
        x->view = kz_find_view(&x->cfg, a->view);
        if (!x->view) {
            dns_diag(DIAG_ERROR, DC_DB_VIEW_NOT_FOUND, NULL, 0, "The view '%s' is not defined in %s\n", a->view, x->conf_path);
            return 1;
        }
    }
    const char *driver = NULL;
    if (a->sqlite || a->conninfo) {
        driver = a->sqlite ? "sqlite3" : "postgresql";
        x->src.database_file = a->sqlite;
        x->src.conninfo_file = a->conninfo;
        x->src.schema = a->schema;
    } else if (db && db->enabled) {
        if (x->view && x->view->database_none) {
            dns_diag(DIAG_ERROR, DC_DB_VIEW_NONE, NULL, 0, "The view '%s' takes no zones from the database (database none)\n", a->view);
            return 1;
        }
        driver = db->driver;
        bool sqlite = driver && strcmp(driver, "sqlite3") == 0;
        const char *own = x->view ? (sqlite ? x->view->database_file : x->view->database_schema) : NULL;
        shared = own == NULL;
        x->src.database_file = sqlite ? (own ? own : db->database_file) : NULL;
        x->src.conninfo_file = sqlite ? NULL : db->conninfo_file;
        x->src.schema = sqlite ? NULL : (a->schema ? a->schema : (own ? own : db->schema));
        if (sqlite && !x->src.database_file) {
            dns_diag(DIAG_ERROR, DC_DB_ZONE_NO_SOURCE, x->conf_path, 0, "The configuration has no database-file for %s\n", a->view ? "this view" : "options { database { } }");
            return 1;
        }
    } else {
        dns_diag(DIAG_ERROR, DC_DB_ZONE_NO_SOURCE, NULL, 0,
                 "No database: give --sqlite3 or --conninfo-file, or a configuration (-c) with options { database { } }%s\n",
                 x->have_cfg ? " (the configuration has none)" : "");
        return 1;
    }
    if (!driver) {
        dns_diag(DIAG_ERROR, DC_CONF_DATABASE_NO_DRIVER, x->conf_path, 0, "options { database { } } has no driver\n");
        return 1;
    }
    x->drv = kz_driver_find(driver);
    if (!x->drv) {
        char have[80];
        kz_drivers_list(have, sizeof(have));
        dns_diag(DIAG_ERROR, DC_DB_ZONE_DRIVER, NULL, 0, "The database driver '%.40s' is not in this karidns-zone (drivers: %s)\n", driver, have);
        return 1;
    }
    if (!shared) x->zone_view = NULL;                       /* a view with a source of its own ignores karidns_domain_views */
    x->src.driver = x->drv->name;
    const struct passwd *pw = getpwuid(geteuid());
    if (pw && pw->pw_name) snprintf(x->actor, sizeof(x->actor), "karidns-zone:%.60s", pw->pw_name);
    else snprintf(x->actor, sizeof(x->actor), "karidns-zone:uid%lu", (unsigned long)geteuid());
    if (x->have_cfg) {
        const char *vn = x->view ? x->view->name : NULL;
        zone_vopts_effective(&x->cfg, NULL, vn, &x->veff);
        zone_limits_effective(&x->cfg, NULL, vn, &x->limits);
        x->reader.default_ttl = db->default_ttl;
        x->reader.max_records = db->max_zone_records;
        x->reader.max_zone_bytes = db->max_zone_bytes;
        size_t cap = 0;
        for (const view_config_t *v = x->cfg.views; v; v = v->next)
            for (const zone_config_t *z = v->zones; z; z = z->next) cap++;
        x->file_zones = calloc(cap ? cap : 1, sizeof(*x->file_zones));
        if (!x->file_zones) {
            dns_diag(DIAG_ERROR, DC_INTERNAL_OOM, NULL, 0, "out of memory\n");
            return 1;
        }
        for (const view_config_t *v = x->cfg.views; v; v = v->next) {
            if (x->view && v != x->view) continue;
            for (const zone_config_t *z = v->zones; z; z = z->next)
                if (z->domain && (!z->type || strcasecmp(z->type, "master") == 0)) x->file_zones[x->nfile_zones++] = z->domain;
        }
    } else {
        for (int i = 0; i < ZC_N; i++) x->veff.chk[i] = CHK_DEFAULT;
    }
    return 0;
}

static void kz_ctx_free(kz_ctx_t *x) {
    free(x->file_zones);
    if (x->have_cfg) free_server_config_fields(&x->cfg);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* import                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

static bool kz_ieq(const char *a, const char *b) { return strcasecmp(a, b) == 0; }

/* the import format of a file: tinydns for the names a tinydns data file has (data, *.data, *.tinydns), else BIND; standard input is BIND */
static bool kz_file_is_tinydns(const char *path) {
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    size_t n = strlen(base);
    if (strcmp(path, "-") == 0) return false;
    if (strcmp(base, "data") == 0) return true;
    return (n > 5 && strcmp(base + n - 5, ".data") == 0) || (n > 8 && strcmp(base + n - 8, ".tinydns") == 0);
}

/* "T1,T2" -> a list of at most KZ_MAX_TYPES names in a malloc'd copy (the names point into it).  0, or 2 (usage error) */
static int kz_split_types(const char *list, char **copy, const char **names, size_t *n) {
    *copy = strdup(list);
    *n = 0;
    if (!*copy) {
        dns_diag(DIAG_ERROR, DC_INTERNAL_OOM, NULL, 0, "out of memory\n");
        return 1;
    }
    for (char *p = *copy; p;) {
        char *e = strchr(p, ',');
        if (e) *e++ = '\0';
        if (*n == KZ_MAX_TYPES) return 2;
        names[(*n)++] = p;
        p = e;
    }
    return 0;
}

typedef struct {
    const kz_args_t *a;
    const char *view;
    const char *file;
    const char *format;
    dns_diag_mark_t mark;
    unsigned done, failed, checked;
} kz_imp_t;

static void kz_report(void *ud, char what, const char *owner, const char *type) {
    (void)ud;
    dns_diag(DIAG_NOTE, DC_DB_IMPORT_CHANGE, NULL, 0, "%s %s %s\n", what == '+' ? "add" : what == '-' ? "delete" : "replace", owner[0] ? owner : "(apex)", type);
}

static void kz_imp_result(kz_imp_t *s, const char *zone, int status) {
    s->checked++;
    if (status == ZI_OK) s->done++;
    else s->failed++;
    dns_diag_zone_result(zone, s->view, s->file, s->format, s->mark);
    s->mark = dns_diag_mark();
}

static void kz_tinydns_result(void *ud, const zi_result_t *res, int status) {
    kz_imp_t *s = ud;
    kz_imp_result(s, res->zone[0] ? res->zone : "?", status);
}

/* import --signer --json: the result of the write as the key "signer" of the document (docs/karidns-zone.md): the new serial, the counts, the earliest
 * RRSIG expiration of the zone after the write (UTC and unix time) and the id of the write (PostgreSQL: the transaction id; SQLite3: the first and last
 * karidns_changes.seq) */
static void kz_signer_json(const zi_result_t *res, int status, bool dry_run) {
    if (!dns_diag_json_enabled()) return;
    char zone[2 * DNS_NAME_TEXT_SIZE], body[1600];
    int n = 0;                                          /* snprintf: what was written, or what would have been (a document cut short is not JSON) */
    dns_diag_json_escape(zone, sizeof(zone), res->zone, strlen(res->zone));
    if (status == ZI_CHANGED) {
        n = snprintf(body, sizeof(body), "{ \"zone\": \"%s\", \"changed\": true, \"committed\": false }", zone);
    } else if (status == ZI_BUSY) {
        n = snprintf(body, sizeof(body), "{ \"zone\": \"%s\", \"changed\": false, \"committed\": false, \"busy\": true }", zone);
    } else if (status == ZI_OK) {
        char ex[40] = "", wid[160];
        int nw;
        struct tm tmv;
        time_t et = res->min_expire;
        if (res->has_expire && gmtime_r(&et, &tmv)) strftime(ex, sizeof(ex), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        if (res->has_write_id && res->write_id.xid[0])
            nw = snprintf(wid, sizeof(wid), "{ \"xid\": \"%s\", \"seq_first\": null, \"seq_last\": null }", res->write_id.xid);
        else if (res->has_write_id && res->write_id.seq_last)
            nw = snprintf(wid, sizeof(wid), "{ \"xid\": null, \"seq_first\": %llu, \"seq_last\": %llu }", (unsigned long long)res->write_id.seq_first,
                     (unsigned long long)res->write_id.seq_last);
        else
            nw = snprintf(wid, sizeof(wid), "{ \"xid\": null, \"seq_first\": null, \"seq_last\": null }");
        if (nw < 0 || (size_t)nw >= sizeof(wid)) return;
        n = snprintf(body, sizeof(body),
                 "{ \"zone\": \"%s\", \"changed\": false, \"committed\": %s, \"serial\": %u, \"old_serial\": %u, \"dnssec_records_written\": %zu, "
                 "\"dnssec_records_removed\": %zu, \"records_updated\": %zu, \"rrsets_added\": %zu, \"rrsets_replaced\": %zu, \"rrsets_deleted\": %zu, "
                 "\"earliest_expire\": \"%s\", \"earliest_expire_epoch\": %lld, \"write_id\": %s }",
                 zone, res->committed && !dry_run ? "true" : "false", (unsigned)res->new_serial, (unsigned)res->old_serial, res->records_inserted, res->records_deleted,
                 res->rows_updated, res->rrsets_added, res->rrsets_replaced, res->rrsets_deleted, ex, (long long)res->min_expire, wid);
    } else {
        return;
    }
    if (n < 0 || (size_t)n >= sizeof(body)) return;
    dns_diag_json_extra("signer", body);
}

static int kz_cmd_import(const kz_args_t *a, kz_ctx_t *x) {
    const char *zone = a->all ? NULL : a->args[0];
    const char *file = a->args[a->nargs - 1];
    zi_opts_t o;
    memset(&o, 0, sizeof(o));
    o.drv = x->drv;
    o.src = x->src;
    o.audit_summary = a->audit ? kz_ieq(a->audit, "summary") : a->signer;      /* the signer re-signs a whole zone: one audit row per table and operation, not one per signature */
    o.audit_actor = x->actor;
    o.mode = a->mode && kz_ieq(a->mode, "merge") ? ZI_MERGE : ZI_REPLACE;
    o.serial = a->serial && kz_ieq(a->serial, "increment") ? ZI_SERIAL_INCREMENT : a->serial && kz_ieq(a->serial, "keep") ? ZI_SERIAL_KEEP : ZI_SERIAL_GROW;
    o.dry_run = a->dry_run;
    o.signer = a->signer;
    o.strict = a->strict;
    o.reload = a->reload;
    o.view = x->zone_view;
    o.zone_type = a->type;
    o.file_zones = (const char *const *)x->file_zones;
    o.nfile_zones = x->nfile_zones;
    if (a->dry_run || a->verbose) o.report = kz_report;
    o.chk = x->veff.chk;
    o.chk_names = x->veff.chk[ZC_NAMES_PRIMARY];
    if (x->have_cfg) {
        o.ecs_tags = x->cfg.ecs_tags;
        o.n_ecs_tags = x->cfg.ecs_tag_count;
        o.loc_tags = x->cfg.location_tags;
        o.n_loc_tags = x->cfg.location_tag_count;
    }
    o.limits = x->limits;
    o.reader = x->reader;
    const char *tnames[KZ_MAX_TYPES];
    char *tcopy = NULL;
    if (a->types) {
        int rc = kz_split_types(a->types, &tcopy, tnames, &o.ntypes);
        if (rc == 2) {
            free(tcopy);
            return kz_usage_error(a->json, DC_USAGE_OPTION, "--types names more than %d types", KZ_MAX_TYPES);
        }
        if (rc != 0) return 1;
        o.types = tnames;
    }
    zi_t *z = zi_open(&o);
    free(tcopy);
    if (!z) return 1;
    bool tinydns = a->all || (a->format ? kz_ieq(a->format, "tinydns") : kz_file_is_tinydns(file));
    zi_input_t in;
    memset(&in, 0, sizeof(in));
    in.path = file;
    kz_imp_t s = { a, x->zone_view, strcmp(file, "-") == 0 ? "standard input" : file, tinydns ? "tinydns" : "bind", dns_diag_mark(), 0, 0, 0 };
    dns_diag_set_file(s.file);
    int rc;
    if (tinydns) {
        rc = zi_import_tinydns(z, &in, zone, kz_tinydns_result, &s);
    } else {
        zi_result_t res;
        dns_diag_set_zone(zone, x->zone_view);
        rc = zi_import_zone(z, &in, zone, &res);
        kz_imp_result(&s, res.zone[0] ? res.zone : zone, rc);
        if (a->signer) kz_signer_json(&res, rc, a->dry_run);
        dns_diag_set_zone(NULL, NULL);
    }
    dns_diag_set_file(NULL);
    zi_close(z);
    dns_diag_counts(s.checked, 0);
    if (a->all)
        dns_diag(DIAG_INFO, DC_DB_IMPORT_SUMMARY, NULL, 0, "%u zone(s) imported, %u failed\n", s.done, s.failed);
    return rc == ZI_OK ? 0 : rc == ZI_CHANGED ? 3 : rc == ZI_BUSY && a->signer ? 4 : 1;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* export                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

/* The output of one zone: standard input of the text goes to stdout (dir_fd < 0), or into a temporary file of a directory that is renamed
 * to its name when the zone is complete.  The file is created at the first piece of text, so a zone that cannot be read leaves nothing. */
typedef struct {
    int dir_fd;                             /* -1: standard output */
    char tmp[64];
    int fd;                                 /* the temporary file, or -1 */
    int err;                                /* errno of the first failed write, or 0 */
    bool tinydns;                           /* the text is a tinydns data file (the BIND writer starts with $ORIGIN) */
    size_t bytes;
} kz_out_t;

static void kz_out_init(kz_out_t *o, int dir_fd) {
    memset(o, 0, sizeof(*o));
    o->dir_fd = dir_fd;
    o->fd = -1;
}

static int kz_sink(void *ud, const char *data, size_t len) {
    kz_out_t *o = ud;
    if (o->err) return 1;
    if (o->bytes == 0 && len > 0) o->tinydns = len < 7 || strncmp(data, "$ORIGIN", 7) != 0;
    if (o->dir_fd >= 0 && o->fd < 0) {
        static unsigned seq;
        snprintf(o->tmp, sizeof(o->tmp), ".karidns-zone.%ld.%u.tmp", (long)getpid(), seq++);
        o->fd = openat(o->dir_fd, o->tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0666);
        if (o->fd < 0) {
            o->err = errno;
            return 1;
        }
    }
    int fd = o->dir_fd >= 0 ? o->fd : 1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) {
            o->err = w < 0 ? errno : EIO;
            return 1;
        }
        off += (size_t)w;
    }
    o->bytes += len;
    return 0;
}

/* drop a temporary file that was not finished */
static void kz_out_abort(kz_out_t *o) {
    if (o->fd >= 0) {
        close(o->fd);
        unlinkat(o->dir_fd, o->tmp, 0);
        o->fd = -1;
    }
}

/* Make the temporary file the file `name` of the directory.  Without force an existing name (also a symbolic link) is never touched: link() fails
 * with EEXIST.  false: a message was given (the temporary file is gone). */
static bool kz_out_commit(kz_out_t *o, const char *shown, const char *name, bool force) {
    int e = 0;
    if (o->fd < 0 || fsync(o->fd) != 0) e = errno ? errno : EIO;
    if (o->fd >= 0 && close(o->fd) != 0 && !e) e = errno;
    int fd = o->fd;
    o->fd = -1;
    if (fd < 0 || e) {
        unlinkat(o->dir_fd, o->tmp, 0);
        dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, shown, 0, "Could not write %s: %s\n", shown, strerror(e ? e : EIO));
        return false;
    }
    int rc;
    if (force) {
        rc = renameat(o->dir_fd, o->tmp, o->dir_fd, name);
    } else {
        rc = linkat(o->dir_fd, o->tmp, o->dir_fd, name, 0);
        int le = errno;
        unlinkat(o->dir_fd, o->tmp, 0);
        errno = le;
    }
    if (rc != 0) {
        int le = errno;
        if (force) unlinkat(o->dir_fd, o->tmp, 0);
        if (le == EEXIST) dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT_EXISTS, shown, 0, "%s exists; use --force to replace it\n", shown);
        else dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, shown, 0, "Could not create %s: %s\n", shown, strerror(le));
        return false;
    }
    return true;
}

/* A zone name as a file name: letters, digits, '-', '_' and '.' (not as the first character) stay, every other byte is %XX, so that no name has
 * a path separator, a leading dot or a control character and two names never give the same file.  false: too long for a file name. */
static bool kz_safe_name(const char *zone, char *out, size_t cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t w = 0;
    for (size_t i = 0; zone[i]; i++) {
        unsigned char c = (unsigned char)zone[i];
        bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || (c == '.' && i > 0);
        if (w + 4 >= cap) return false;
        if (plain) {
            out[w++] = (char)c;
        } else {
            out[w++] = '%';
            out[w++] = hex[c >> 4];
            out[w++] = hex[c & 15];
        }
    }
    out[w] = '\0';
    return w > 0;
}

typedef struct {
    const kz_args_t *a;
    zx_t *x;
    const char *view;
    const dzt_opts_t *fmt;
    int dir_fd;
    const char *dir;
    unsigned done, failed;
} kz_exp_t;

static bool kz_exists(int dir_fd, const char *name) {
    struct stat sb;
    return fstatat(dir_fd, name, &sb, AT_SYMLINK_NOFOLLOW) == 0;
}

/* one zone of --all into the directory */
static int kz_export_one(void *ud, const char *zone) {
    kz_exp_t *e = ud;
    char safe[KZ_NAME_MAX + 1], bind_name[KZ_NAME_MAX + 16], td_name[KZ_NAME_MAX + 16], shown[1100] = "";
    dns_diag_mark_t mark = dns_diag_mark();
    dns_diag_set_zone(zone, e->view);
    bool ok = false;
    const char *fmtname = "database";                       /* the format written, once it is written */
    if (!kz_safe_name(zone, safe, sizeof(safe) - 16)) {
        dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, NULL, 0, "The name of zone '%.100s' is too long to be a file name\n", zone);
    } else {
        snprintf(bind_name, sizeof(bind_name), "%s.zone", safe);
        snprintf(td_name, sizeof(td_name), "%s.tinydns", safe);
        snprintf(shown, sizeof(shown), "%s/%s", e->dir, bind_name);
        const char *taken = NULL;
        if (!e->a->force) taken = kz_exists(e->dir_fd, bind_name) ? bind_name : kz_exists(e->dir_fd, td_name) ? td_name : NULL;
        if (taken) {
            dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT_EXISTS, taken, 0, "%s/%s exists; use --force to replace it (zone '%.100s')\n", e->dir, taken, zone);
        } else {
            kz_out_t out;
            kz_out_init(&out, e->dir_fd);
            int rc = zx_export_zone(e->x, zone, e->view, e->fmt, kz_sink, &out);
            if (rc != 0) {
                if (out.err) dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, bind_name, 0, "Could not write the file of zone '%.100s': %s\n", zone, strerror(out.err));
                kz_out_abort(&out);
            } else {
                const char *name = out.tinydns ? td_name : bind_name;
                snprintf(shown, sizeof(shown), "%s/%s", e->dir, name);
                ok = kz_out_commit(&out, shown, name, e->a->force);
                if (ok) {
                    fmtname = out.tinydns ? "tinydns" : "bind";
                    dns_diag(DIAG_INFO, DC_DB_EXPORT_DONE, shown, 0, "Zone '%s' exported to %s\n", zone, shown);
                }
            }
        }
    }
    dns_diag_zone_result(zone, e->view, shown[0] ? shown : NULL, fmtname, mark);
    dns_diag_set_zone(NULL, NULL);
    if (ok) e->done++;
    else e->failed++;
    return 0;
}

/* the directory of --dir: made when it does not exist (one level); a descriptor, or -1 with a message */
static int kz_open_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && mkdir(dir, 0777) == 0) fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, dir, 0, "Could not use the directory %s: %s\n", dir, strerror(errno));
    return fd;
}

/* the directory part of a file path and its last component (copies in dirbuf / basebuf); false: no file name */
static bool kz_split_path(const char *path, char *dirbuf, size_t dcap, const char **base) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(dirbuf, dcap, ".");
        *base = path;
    } else {
        size_t n = (size_t)(slash - path);
        snprintf(dirbuf, dcap, "%.*s", n ? (int)n : 1, n ? path : "/");
        *base = slash + 1;
    }
    return **base != '\0' && strcmp(*base, ".") != 0 && strcmp(*base, "..") != 0;
}

static int kz_cmd_export(const kz_args_t *a, kz_ctx_t *x) {
    dzt_opts_t fmt;
    memset(&fmt, 0, sizeof(fmt));
    if (a->format && kz_ieq(a->format, "bind")) fmt.format = DZT_BIND;
    else if (a->format && kz_ieq(a->format, "tinydns")) fmt.format = DZT_TINYDNS;
    zx_t *zx = zx_open(x->drv, &x->src, NULL);
    if (!zx) return 1;
    zx_set_reader_opts(zx, &x->reader);
    int rc = 1;
    if (a->all) {
        int dir_fd = kz_open_dir(a->dir);
        if (dir_fd >= 0) {
            kz_exp_t e = { a, zx, x->zone_view, &fmt, dir_fd, a->dir, 0, 0 };
            int lr = zx_list_zones(zx, x->zone_view, kz_export_one, &e);
            close(dir_fd);
            dns_diag_counts(e.done + e.failed, 0);
            if (lr == 0) dns_diag(DIAG_INFO, DC_DB_EXPORT_DONE, a->dir, 0, "%u zone(s) exported to %s, %u failed\n", e.done, a->dir, e.failed);
            rc = lr == 0 && e.failed == 0 ? 0 : 1;
        }
    } else {
        const char *zone = a->args[0];
        const char *file = a->nargs > 1 ? a->args[1] : NULL;
        dns_diag_mark_t mark = dns_diag_mark();
        dns_diag_set_zone(zone, x->zone_view);
        kz_out_t out;
        bool to_stdout = !file || strcmp(file, "-") == 0;
        char dirbuf[1100];
        const char *base = NULL;
        int dir_fd = -1;
        bool ok = true;
        if (!to_stdout) {
            if (!kz_split_path(file, dirbuf, sizeof(dirbuf), &base)) {
                dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, file, 0, "'%.200s' is not a file name\n", file);
                ok = false;
            } else if ((dir_fd = open(dirbuf, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
                dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, file, 0, "Could not use the directory of %s: %s\n", file, strerror(errno));
                ok = false;
            } else if (!a->force && kz_exists(dir_fd, base)) {
                dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT_EXISTS, file, 0, "%s exists; use --force to replace it\n", file);
                ok = false;
            }
        }
        if (ok) {
            kz_out_init(&out, dir_fd);
            ok = zx_export_zone(zx, zone, x->zone_view, &fmt, kz_sink, &out) == 0;
            if (!ok) {
                if (out.err) dns_diag(DIAG_ERROR, DC_DB_ZONE_OUTPUT, to_stdout ? "standard output" : file, 0, "Could not write the zone: %s\n", strerror(out.err));
                kz_out_abort(&out);
            } else if (!to_stdout) {
                ok = kz_out_commit(&out, file, base, a->force);
                if (ok) dns_diag(DIAG_INFO, DC_DB_EXPORT_DONE, file, 0, "Zone '%s' exported to %s\n", zone, file);
            }
            if (ok) {
                dns_diag_zone_result(zone, x->zone_view, to_stdout ? "standard output" : file, out.tinydns ? "tinydns" : "bind", mark);
            }
        }
        if (!ok) dns_diag_zone_result(zone, x->zone_view, to_stdout ? "standard output" : file, "database", mark);
        dns_diag_counts(1, 0);
        dns_diag_set_zone(NULL, NULL);
        if (dir_fd >= 0) close(dir_fd);
        rc = ok ? 0 : 1;
    }
    zx_close(zx);
    return rc;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* main                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

/* the values of the options, before anything is opened: 0, or 2 (usage error) */
static int kz_check_args(const kz_args_t *a, bool import) {
    const bool j = a->json;
    if (a->format && !kz_ieq(a->format, "bind") && !kz_ieq(a->format, "tinydns") && !kz_ieq(a->format, "auto"))
        return kz_usage_error(j, DC_USAGE_OPTION, "--format must be bind, tinydns or auto");
    if (a->sqlite && a->conninfo) return kz_usage_error(j, DC_USAGE_OPTION, "--sqlite3 and --conninfo-file name different drivers: give one");
    if (a->schema && a->sqlite) return kz_usage_error(j, DC_USAGE_OPTION, "--schema is for PostgreSQL, not for --sqlite3");
    if (a->conf && a->no_config) return kz_usage_error(j, DC_USAGE_OPTION, "-c and --no-config exclude each other");
    if (import) {
        if (a->dir || a->force) return kz_usage_error(j, DC_USAGE_OPTION, "--dir and --force are options of export");
        if (a->mode && !kz_ieq(a->mode, "replace") && !kz_ieq(a->mode, "merge")) return kz_usage_error(j, DC_USAGE_OPTION, "--mode must be replace or merge");
        if (a->serial && !kz_ieq(a->serial, "grow") && !kz_ieq(a->serial, "increment") && !kz_ieq(a->serial, "keep"))
            return kz_usage_error(j, DC_USAGE_OPTION, "--serial must be grow, increment or keep");
        if (a->type && !kz_ieq(a->type, "NATIVE") && !kz_ieq(a->type, "MASTER")) return kz_usage_error(j, DC_USAGE_OPTION, "--type must be NATIVE or MASTER");
        if (a->audit && !kz_ieq(a->audit, "rows") && !kz_ieq(a->audit, "summary")) return kz_usage_error(j, DC_USAGE_OPTION, "--audit must be rows or summary");
        if (a->all && a->format && kz_ieq(a->format, "bind")) return kz_usage_error(j, DC_USAGE_OPTION, "--all reads a tinydns data file: --format bind cannot be used with it");
        if (a->signer) {
            if (a->mode || a->types || a->serial || a->view || a->type || a->all)
                return kz_usage_error(j, DC_USAGE_OPTION, "--signer cannot be used with --mode, --types, --serial, --view, --type or --all (a signed zone replaces the DNSSEC records of a zone that exists)");
            if (a->format && kz_ieq(a->format, "tinydns")) return kz_usage_error(j, DC_USAGE_OPTION, "--signer takes a zone file in BIND format, not a tinydns data file");
            if (a->nargs == 2 && kz_file_is_tinydns(a->args[1]) && !(a->format && kz_ieq(a->format, "bind")))
                return kz_usage_error(j, DC_USAGE_OPTION, "--signer takes a zone file in BIND format (this file name is a tinydns data file's: use --format bind)");
        }
        if (a->all ? a->nargs != 1 : a->nargs != 2) return kz_usage_error(j, DC_USAGE_ARGS, a->all ? "import --all takes one argument: the tinydns data file" : "import takes a zone name and a file (or -)");
    } else {
        if (a->mode || a->types || a->dry_run || a->serial || a->strict || a->reload || a->type || a->verbose || a->audit || a->signer)
            return kz_usage_error(j, DC_USAGE_OPTION, "--mode, --types, --dry-run, --serial, --strict, --reload, --type, --verbose, --audit and --signer are options of import");
        if (a->dir && !a->all) return kz_usage_error(j, DC_USAGE_OPTION, "--dir is for export --all");
        if (a->all && (!a->dir || a->nargs != 0)) return kz_usage_error(j, DC_USAGE_ARGS, "export --all takes no argument and needs --dir DIR");
        if (!a->all && (a->nargs < 1 || a->nargs > 2)) return kz_usage_error(j, DC_USAGE_ARGS, "export takes a zone name and an optional file");
        if (!a->all && j && (a->nargs < 2 || strcmp(a->args[1], "-") == 0))
            return kz_usage_error(j, DC_USAGE_ARGS, "with --json the zone text cannot go to standard output: give a file");
    }
    return 0;
}

static int kz_run(int argc, char **argv, bool *json_out) {
    kz_args_t a;
    const char *cmd;
    int perr = kz_parse(argc, argv, &cmd, &a);
    *json_out = a.json;
    const char *known = cmd && (strcmp(cmd, "import") == 0 || strcmp(cmd, "export") == 0) ? cmd : NULL;
    if (a.json) {
        dns_diag_json_start(known, KARIDNS_VERSION);
        dns_diag_json_tool("karidns-zone");
    }
    if (perr) return kz_usage_error(a.json, DC_USAGE_OPTION, "%s", a.perr);
    if (a.help && !a.json) {
        kz_usage(stdout);
        return 0;
    }
    if (a.version && !a.json) {
        char have[80];
        kz_drivers_list(have, sizeof(have));
        printf("karidns-zone %s (drivers: %s)\n", KARIDNS_VERSION, have);
        return 0;
    }
    if (a.help || a.version) return kz_usage_error(true, DC_USAGE_OPTION, "-h and --version are not available with --json");
    if (!cmd) return kz_usage_error(a.json, DC_USAGE_COMMAND_MISSING, "no command given (import or export)");
    if (!known) return kz_usage_error(a.json, DC_USAGE_COMMAND_UNKNOWN, "unknown command '%.64s' (import or export)", cmd);
    const bool import = strcmp(cmd, "import") == 0;
    int rc = kz_check_args(&a, import);
    if (rc != 0) return rc;
    kz_ctx_t x;
    memset(&x, 0, sizeof(x));
    rc = kz_load_config(&a, &x) || kz_resolve(&a, &x) ? 1 : 0;
    if (rc == 0) rc = import ? kz_cmd_import(&a, &x) : kz_cmd_export(&a, &x);
    kz_ctx_free(&x);
    return rc;
}

int main(int argc, char **argv) {
    bool json = false;
    int rc = kz_run(argc, argv, &json);
    if (json && dns_diag_json_enabled() && dns_diag_json_finish(stdout, rc) != 0) {
        fprintf(stderr, "karidns-zone: cannot write the JSON document: %s\n", strerror(errno));
        if (rc == 0) rc = 1;
    }
    return rc;
}
