#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_utils.h"
#include "../dns_wire.h"
#include "../dns_zone_lint.h"
#include "../dns_db_checkproto.h"
#include "../dns_cidr.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "karidns_tool_linkage.h"

// Stub for open_via_dir_cache used by dns_config_parser.c
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

// Helper to read entire file
KARIDNS_TOOL_FN char *read_file_or_die(const char *path, bool *out_failed) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not open file: %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    /* A directory (or FIFO/device) opens fine on some systems, but its ftell()
     * result is meaningless (e.g. LONG_MAX for a directory on Linux), which
     * would overflow the "len + 1" allocation below. Require a regular file. */
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Not a regular file: %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not read file: %s\n", path);
        return NULL;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Out of memory reading file: %s\n", path);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, len, f);
    buf[read_bytes] = '\0';
    fclose(f);
    if (out_failed) *out_failed = false;
    return buf;
}

KARIDNS_TOOL_FN char *karicheck_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    
    if (out_dev || out_ino) {
        struct stat st;
        if (stat(rel_path, &st) == 0) {
            if (out_dev) *out_dev = st.st_dev;
            if (out_ino) *out_ino = st.st_ino;
        } else {
            return NULL; // fstat failed, fail-closed
        }
    }
    
    return read_file_or_die(rel_path, NULL);
}


// Print error context with caret
KARIDNS_TOOL_FN void print_error_context(const char *root_file_path, const char *root_buf, const parse_error_t *err, zone_arena_t *arena) {
    const char *file_path = root_file_path;
    const char *buf = root_buf;

    if (err->file_path) {
        bool found = false;
        for (int i = 0; i < arena->file_buf_count; i++) {
            if (arena->file_paths[i] && strcmp(arena->file_paths[i], err->file_path) == 0) {
                file_path = err->file_path;
                buf = arena->display_bufs[i];
                found = true;
                break;
            }
        }
        if (!found) {
            file_path = root_file_path;
            buf = root_buf;
        }
    }
    if (!buf) return;
    size_t offset = err->error_offset;
    size_t buf_len = strlen(buf);
    if (offset > buf_len) offset = buf_len;

    int line = 1;
    const char *line_start = buf;
    for (size_t i = 0; i < offset; i++) {
        if (buf[i] == '\n') {
            line++;
            line_start = buf + i + 1;
        }
    }

    const char *line_end = line_start;
    while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;

    fprintf(stderr, "[ERROR] Syntax error in %s at line %d\n", file_path, line);
    fprintf(stderr, "Reason: %s\n\n", err->error_message);

    // Limit line length to 80 chars
    size_t len = line_end - line_start;
    const char *print_start = line_start;
    int caret_pos = offset - (line_start - buf);
    bool clipped_start = false;
    bool clipped_end = false;

    if (len > 80) {
        if (caret_pos > 40) {
            print_start = line_start + caret_pos - 35;
            clipped_start = true;
        }
        if (line_end - print_start > 80) {
            len = 80;
            clipped_end = true;
        } else {
            len = line_end - print_start;
        }
        caret_pos = offset - (print_start - buf);
    }

    fprintf(stderr, "%4d | ", line);
    if (clipped_start) fprintf(stderr, "... ");
    for (size_t i = 0; i < len; i++) {
        char c = print_start[i];
        if (c == '\r' || c == '\n' || c == '\0') break;
        fputc(c, stderr);
    }
    if (clipped_end) fprintf(stderr, " ...");
    fprintf(stderr, "\n");

    fprintf(stderr, "       ");
    if (clipped_start) fprintf(stderr, "    ");
    for (int i = 0; i < caret_pos; i++) fputc(' ', stderr);
    fprintf(stderr, "\033[1;31m^");
    for (size_t i = 1; i < err->token_length && i < 20; i++) fputc('~', stderr);
    fprintf(stderr, "\033[0m\n\n");
}

KARIDNS_TOOL_FN void normalize_domain_fqdn(const char *in, char *out, size_t out_cap) {
    size_t len = strlen(in);
    if (len > 0 && dns_name_len_no_root(in, len) == len && len + 1 < out_cap) {
        memcpy(out, in, len);
        out[len] = '.';
        out[len + 1] = '\0';
    } else {
        snprintf(out, out_cap, "%s", in);
    }
}

KARIDNS_TOOL_FN bool validate_cidr_syntax(const char *cidr) {
    if (!cidr) return false;
    char buf[128];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash = '\0';
    const char *ip_part = buf;
    const char *prefix_part = slash + 1;
    if (*prefix_part == '\0') return false;
    char *endptr = NULL;
    long prefix = strtol(prefix_part, &endptr, 10);
    if (*endptr != '\0' || prefix < 0) return false;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip_part, &a4) == 1) {
        return prefix <= 32;
    } else if (inet_pton(AF_INET6, ip_part, &a6) == 1) {
        return prefix <= 128;
    }
    return false;
}

typedef struct { const char *zone; kc_tally_t *tally; } kc_out_of_zone_ud_t;

static void karicheck_report_out_of_zone(const dns_record_t *rec, void *ud) {
    const kc_out_of_zone_ud_t *u = ud;
    kc_warning(u->tally, "Zone '%s': out-of-zone record '%s' %s ignored (not at or below the zone apex; "
                         "the server does not load it)\n",
               u->zone, rec->name ? rec->name : "", rec->type ? rec->type : "");
}

/* parse_context_t.zone_exists: name が view (ud) のゾーンの頂点か */
static bool kc_view_has_zone(const void *ud, const char *name) {
    return view_find_zone_config((const view_config_t *)ud, name) != NULL;
}

KARIDNS_TOOL_FN int check_zone(const char *domain_raw, const char *file_path, bool is_standalone, bool is_catalog, const char *file_format, const zone_config_t *zcfg, const server_config_t *cfg, const view_config_t *view) {
    // Normalize domain to FQDN: append trailing dot if missing.
    // Without this, "example.com" wouldn't match records expanded to "example.com."
    char domain_buf[256];
    normalize_domain_fqdn(domain_raw, domain_buf, sizeof(domain_buf));
    const char *domain = domain_buf;
    kc_tally_t tally = {0};

    /* D-24: karidns は相対パス ("../" を含むものも) を起動時のディレクトリから、絶対パスはそのまま
     * 開くので、standalone モードでも絶対パスや "../" を警告しない */

    bool failed = false;
    char *buf = read_file_or_die(file_path, &failed);
    if (failed || !buf) return 1;

    char *mutable_buf = strdup(buf);
    if (!mutable_buf) {
        free(buf);
        kc_error(&tally, "Out of memory\n");
        return 1;
    }

    zone_arena_t arena;
    zone_arena_init(&arena);

    char *root_path_copy = strdup(file_path);
    if (!root_path_copy || zone_arena_add_file(&arena, mutable_buf, (char*)buf, root_path_copy) != 0) {
        free(root_path_copy);
        free(mutable_buf);
        free(buf);
        kc_error(&tally, "Out of memory\n");
        return 1;
    }

    parse_error_t err = {0};
    char *root_ttl = NULL;
    char *root_ecs_tag = NULL;
    char *root_loc_tag = NULL;
    char *visited_paths[16];
    dev_t visited_devs[16];
    ino_t visited_inos[16];
    char *root_path = realpath(file_path, NULL);
    if (!root_path) root_path = strdup(file_path);

    char *base_dir = get_base_dir(file_path);
    if (!base_dir) {
        kc_error(&tally, "Out of memory allocating base_dir\n");
        free(root_path);
        return 1;
    }
    
    dev_t root_dev = 0;
    ino_t root_ino = 0;
    struct stat root_st;
    if (stat(file_path, &root_st) == 0) {
        root_dev = root_st.st_dev;
        root_ino = root_st.st_ino;
    } else {
        fprintf(stderr, "Failed to stat root zone file: %s\n", file_path);
        free((void*)base_dir);
        free(root_path);
        return 1;
    }

    parse_context_t ctx = {
        .base_dir = base_dir,
        .default_origin = domain,
        .is_standalone_mode = is_standalone,
        .err_out = &err,
        .current_depth = 0,
        .visited_paths = visited_paths,
        .visited_devs = visited_devs,
        .visited_inos = visited_inos,
        .visited_count = 1,
        .visited_cap = 16,
        .load_file_cb = karicheck_load_file_cb,
        .shared_ttl_io = &root_ttl,
        .shared_ecs_tag_io = &root_ecs_tag,
        .shared_loc_tag_io = &root_loc_tag
    };
    ctx.visited_paths[0] = root_path;
    ctx.visited_devs[0] = root_dev;
    ctx.visited_inos[0] = root_ino;
    ctx.source_mtime = root_st.st_mtime; /* tinydns の SOA serial (サーバーと同じくファイルの mtime) */

    /* サーバー (reload_master_zone) と同じく、tinydns の親子ゾーンの振り分けには
     * このゾーンと同じ view のゾーン (O-11: view の全ゾーン) を、view の索引で引く */
    if (view) {
        ctx.zone_exists = kc_view_has_zone;
        ctx.zone_exists_ud = view;
    }

    int res;
    if (file_format && strcasecmp(file_format, "tinydns") == 0) {
        res = parse_tinydns_data(mutable_buf, strlen(mutable_buf), &arena, &ctx);
    } else {
        res = parse_zone_fast(mutable_buf, strlen(mutable_buf), &arena, &ctx);
    }
    ctx.zone_exists = NULL;
    if (res < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    /* R-27: サーバーと同じく、ゾーン外のデータは警告して読み込まない (RFC 1034 §4.2) */
    kc_out_of_zone_ud_t ooz = {domain, &tally};
    zone_arena_drop_out_of_zone(&arena, domain, karicheck_report_out_of_zone, &ooz);
    if (ctx.out_of_zone_count > 0) {
        kc_warning(&tally, "Zone '%s': %zu tinydns record(s) belong to no zone configured in the same "
                        "view and are ignored (first: '%s')\n",
                domain, ctx.out_of_zone_count, ctx.first_out_of_zone ? ctx.first_out_of_zone : "");
    }

    if (arena.count == 0) {
        kc_error(&tally, "No records found in zone '%s' (%s)\n", domain, file_path);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    zone_lint_ttl(&arena, "zone file", &tally);

    if (build_zone_index(&arena, true) != 0) {
        kc_error(&tally, "Memory allocation failed during index build for '%s'\n", domain);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }
    if (validate_zone_dname(&arena, &err) < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }
    if (validate_zone_name_lengths(&arena, &err) < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }
    {   /* B9a (design 3.6b): PowerDNS ALIAS / LUA records.  The same rules the server applies when it publishes the zone. */
        char pdns_why[400];
        if (validate_zone_pdns_types(&arena, &err, pdns_why, sizeof(pdns_why)) < 0) {
            kc_error(&tally, "Zone '%s': %s (the server does not load this zone)\n", domain, pdns_why);
            free((void*)ctx.base_dir);
            zone_arena_destroy(&arena);
            free(root_path);
            return 1;
        }
    }

    fprintf(stdout, "[OK] Zone '%s' parsed successfully (%zu records)\n", domain, arena.count);
    zone_lint_pdns_types(&arena, domain, &tally);
    {
        /* the library of zone checks (dns_zone_lint.c) is shared with karidns-dbloader --check, which runs it on database zones */
        zone_lint_in_t lin = {0};
        lin.domain = domain;
        lin.src = file_path;
        lin.raw_text = buf;
        lin.is_catalog = is_catalog;
        lin.ecs_tags = (zcfg && zext(zcfg)->ecs_tags) ? zext(zcfg)->ecs_tags : (cfg ? cfg->ecs_tags : NULL);
        lin.ecs_tag_count = (zcfg && zext(zcfg)->ecs_tags) ? zext(zcfg)->ecs_tag_count : (cfg ? cfg->ecs_tag_count : 0);
        lin.loc_tags = (zcfg && zext(zcfg)->location_tags) ? zext(zcfg)->location_tags : (cfg ? cfg->location_tags : NULL);
        lin.loc_tag_count = (zcfg && zext(zcfg)->location_tags) ? zext(zcfg)->location_tag_count : (cfg ? cfg->location_tag_count : 0);
        zone_lint_records(&arena, &lin, &tally);
    }

    printf("[RESULT] Zone '%s': %d error(s), %d warning(s)\n", domain, tally.errors, tally.warnings);
    free((void*)ctx.base_dir);
    zone_arena_destroy(&arena); // frees mutable_buf via arena.file_bufs[0]; do not free() it again here
    free(root_path);
    if (tally.errors > 0) {
        fprintf(stderr, "[FAIL] Zone '%s' contains invalid records.\n", domain);
        return 1;
    }
    printf("[OK] Zone '%s' is valid.\n", domain);
    return 0;
}

/* The drivers the loader at `path` was built with (`karidns-dbloader --drivers`, one name per line), run without a
 * shell.  false: it could not be run or did not succeed. */
KARIDNS_TOOL_FN bool kc_loader_drivers(const char *path, char *out, size_t cap) {
    int fds[2];
    out[0] = '\0';
    if (pipe(fds) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, 0);
            dup2(dn, 2);
        }
        dup2(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
        execl(path, "karidns-dbloader", "--drivers", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    ssize_t r;
    while ((r = read(fds[0], out + n, cap - 1 - n)) > 0 && (n += (size_t)r) < cap - 1) {}
    out[n] = '\0';
    close(fds[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* is `name` one of the lines of `list`? */
KARIDNS_TOOL_FN bool kc_line_listed(const char *list, const char *name) {
    size_t nl = strlen(name);
    for (const char *p = list; *p;) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == nl && strncmp(p, name, nl) == 0) return true;
        p += l + (e ? 1 : 0);
    }
    return false;
}

/* The loader file the way db_sup_init() (dns_db_supervisor.c, check_loader_path) wants it: a regular file that the user running karidns may
 * execute, owned by root or by that user, not writable by group or others.  Here the user who runs karicheck stands in for the one who
 * runs karidns (as root the file must be root's).  Reports errors (karicheck conf and karicheck db); true when the file can be executed. */
KARIDNS_TOOL_FN bool kc_check_loader_file(kc_tally_t *t, const char *lp) {
    struct stat st;
    if (stat(lp, &st) != 0) {
        kc_error(t, "database loader '%s': %s\n", lp, strerror(errno));
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        kc_error(t, "database loader '%s' is not a regular file\n", lp);
        return false;
    }
    if (st.st_uid != 0 && st.st_uid != geteuid())
        kc_error(t, "database loader '%s' is not owned by root%s (uid %u); karidns refuses to run it\n", lp,
                 geteuid() == 0 ? "" : " or by the user running karidns", (unsigned)st.st_uid);
    if (st.st_mode & (S_IWGRP | S_IWOTH))
        kc_error(t, "database loader '%s' is writable by group or others (mode %04o); karidns refuses to run it\n", lp,
                 (unsigned)(st.st_mode & 07777));
    if (access(lp, X_OK) != 0) {
        kc_error(t, "database loader '%s' is not executable by this user\n", lp);
        return false;
    }
    return true;
}

/* has the loader at `lp` been built with the driver `driver`?  (karicheck conf and karicheck db) */
KARIDNS_TOOL_FN void kc_check_loader_driver(kc_tally_t *t, const char *lp, const char *driver) {
    char drivers[256];
    if (!kc_loader_drivers(lp, drivers, sizeof(drivers)))
        kc_error(t, "database loader '%s' did not answer --drivers; is it karidns-dbloader?\n", lp);
    else if (!kc_line_listed(drivers, driver)) {
        for (char *c = drivers; *c; c++)
            if (*c == '\n') *c = (c[1] ? ',' : '\0');
        kc_error(t, "driver %s is not available in this installation (the loader '%s' has: %s)\n", driver, lp,
                 drivers[0] ? drivers : "no driver");
    }
}

/* B10: does a libpq connection string reach the server over a UNIX socket?  A host that starts with '/' (%2F in a URI) does, and so
 * does a string without any host (libpq's default); a host name or address (keyword form or URI authority) does not.  hostaddr
 * without host is a TCP connection. */
KARIDNS_TOOL_FN bool kc_conninfo_unix_socket(const char *s) {
    const char *hv = NULL;
    bool hostaddr = false;
    if (strncmp(s, "postgresql://", 13) == 0 || strncmp(s, "postgres://", 11) == 0) {
        const char *a = strstr(s, "//") + 2;
        const char *e = a + strcspn(a, "/? ");
        const char *at = memchr(a, '@', (size_t)(e - a));
        if (at) a = at + 1;
        if (a < e) hv = a;                                          /* the host of the authority */
        const char *q = strchr(s, '?');
        while (q) {
            q++;
            if (strncmp(q, "host=", 5) == 0) hv = q + 5;
            else if (strncmp(q, "hostaddr=", 9) == 0) hostaddr = true;
            q = strchr(q, '&');
        }
    } else {
        for (const char *p = s; (p = strstr(p, "host")) != NULL; p++) {
            if (p != s && p[-1] != ' ' && p[-1] != '\t') continue;      /* a keyword starts a word (not "dbhost=", "hostaddr" is below) */
            if (strncmp(p, "host=", 5) == 0) hv = p + 5;
            else if (strncmp(p, "hostaddr=", 9) == 0) hostaddr = true;
        }
    }
    if (hv) {
        if (*hv == '\'' || *hv == '"') hv++;
        return *hv == '/' || strncasecmp(hv, "%2f", 3) == 0;
    }
    return !hostaddr;
}

/* An SQLite3 database file: it must exist, be in WAL mode (bytes 18 and 19 of the header are 2: file format
 * write / read version, https://www.sqlite.org/fileformat2.html), not be readable by others, and not sit in a
 * directory others can write to. */
KARIDNS_TOOL_FN void kc_check_sqlite_file(kc_tally_t *t, const char *what, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        kc_error(t, "%s: database file '%s': %s\n", what, path, strerror(errno));
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        kc_error(t, "%s: database file '%s' is not a regular file\n", what, path);
        return;
    }
    if (st.st_mode & S_IROTH)
        kc_warning(t, "%s: database file '%s' is readable by everyone (mode %04o); the zone data should be private\n",
                   what, path, (unsigned)(st.st_mode & 07777));
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *(slash == dir ? slash + 1 : slash) = '\0';
    else snprintf(dir, sizeof(dir), ".");
    struct stat ds;
    if (stat(dir, &ds) == 0 && (ds.st_mode & S_IWOTH) && !(ds.st_mode & S_ISVTX))
        kc_warning(t, "%s: the directory '%s' of the database file is writable by everyone\n", what, dir);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        kc_warning(t, "%s: cannot read '%s' to check its journal mode: %s (run karicheck as the loader user to check it)\n",
                   what, path, strerror(errno));
        return;
    }
    unsigned char h[100];
    ssize_t n = read(fd, h, sizeof(h));
    close(fd);
    if (n < 20 || memcmp(h, "SQLite format 3\0", 16) != 0) {
        if (n == 0)
            kc_error(t, "%s: database file '%s' is empty; create the PowerDNS schema first\n", what, path);
        else
            kc_error(t, "%s: '%s' is not an SQLite3 database\n", what, path);
        return;
    }
    if (h[18] != 2 || h[19] != 2)
        kc_error(t, "%s: database file '%s' is not in WAL mode (run: sqlite3 '%s' 'PRAGMA journal_mode=WAL;')\n", what,
                 path, path);
}

/* beta design 7.2: the checks of options { database { } } that need no connection.  `karicheck db` (B12) reads the
 * data.  Returns the number of errors. */
KARIDNS_TOOL_FN int kc_check_database(const server_config_t *cfg) {
    const database_config_t *db = &cfg->database;
    if (!db->enabled) return 0;
    kc_tally_t t = {0};
    bool sqlite = db->driver && strcmp(db->driver, "sqlite3") == 0;

    /* loader-user / loader-group */
    uid_t loader_uid = (uid_t)-1;
    bool have_uid = false;
    if (db->loader_user) {
        struct passwd *pw = getpwnam(db->loader_user);
        if (!pw) kc_error(&t, "database loader-user '%s' does not exist\n", db->loader_user);
        else { loader_uid = pw->pw_uid; have_uid = true; }
    } else {
        kc_warning(&t, "database: no loader-user; karidns refuses to start as root without one\n");
    }
    if (db->loader_group && !getgrnam(db->loader_group))
        kc_error(&t, "database loader-group '%s' does not exist\n", db->loader_group);

    /* loader-path: owned by root (or by the user running karidns), not group / world writable, executable; and it has the driver */
    const char *lp = db_loader_path(cfg);
    bool loader_ok = kc_check_loader_file(&t, lp);
    if (loader_ok && db->driver) kc_check_loader_driver(&t, lp, db->driver);

    /* B7a: without acl-ceiling the ACLs a database zone carries (allow-transfer, allow-update from the metadata or a profile)
     * refuse every client; the zones still answer queries */
    if (db->acl_ceiling_count == 0 && db->acl_ceiling_keys_count == 0)
        kc_warning(&t, "database: no acl-ceiling; the ACLs of database zones (zone transfers, dynamic updates) refuse every "
                       "client until one is set (acl-ceiling { 192.0.2.0/24; key \"name\"; };)\n");
    /* B7b: acl-ceiling-match all needs both kinds of entry to say anything; with one kind that kind decides, as with any */
    else if (db->acl_ceiling_match == ACL_MATCH_ALL && (db->acl_ceiling_count == 0 || db->acl_ceiling_keys_count == 0))
        kc_warning(&t, "database: acl-ceiling-match all has no effect: acl-ceiling lists only %s, and that kind alone decides\n",
                   db->acl_ceiling_count == 0 ? "keys" : "addresses");

    /* sources */
    if (sqlite) {
        if (db->database_file) kc_check_sqlite_file(&t, "database", db->database_file);
        for (const view_config_t *v = cfg->views; v; v = v->next)
            if (v->database_file) {
                char what[KARIDNS_VIEW_NAME_MAX + 16];
                snprintf(what, sizeof(what), "view '%s'", v->name);
                kc_check_sqlite_file(&t, what, v->database_file);
            }
        if (db->server_id)
            kc_warning(&t, "database: server-id is for driver postgresql (ignored with sqlite3)\n");
    } else if (db->conninfo_file) {
        struct stat cs;
        if (stat(db->conninfo_file, &cs) != 0) {
            kc_error(&t, "database conninfo-file '%s': %s\n", db->conninfo_file, strerror(errno));
        } else {
            mode_t m = cs.st_mode & 0777;
            if (m != 0600 && m != 0400)
                kc_error(&t, "database conninfo-file '%s' has mode %04o; it must be 0600 or 0400\n", db->conninfo_file,
                         (unsigned)m);
            if (have_uid && cs.st_uid != loader_uid)
                kc_error(&t, "database conninfo-file '%s' is owned by uid %u; it must belong to the loader user '%s'\n",
                         db->conninfo_file, (unsigned)cs.st_uid, db->loader_user);
            FILE *cf = fopen(db->conninfo_file, "r");
            if (cf) {
                char line[2048], all[4096];
                size_t used = 0;
                all[0] = '\0';
                while (fgets(line, sizeof(line), cf)) {                   /* '#' starts a comment line, like the loader reads the file */
                    const char *l = line;
                    while (*l == ' ' || *l == '\t') l++;
                    if (*l == '#') continue;
                    size_t n = strcspn(line, "\r\n");
                    if (used + n + 2 > sizeof(all)) break;
                    memcpy(all + used, line, n);
                    used += n;
                    all[used++] = ' ';
                    all[used] = '\0';
                }
                fclose(cf);
                bool verify = strstr(all, "sslmode=verify-full") || strstr(all, "sslmode='verify-full'") || strstr(all, "sslmode=\"verify-full\"");
                if (!kc_conninfo_unix_socket(all) && !verify)
                    kc_warning(&t, "database conninfo-file '%s' has neither a UNIX socket host nor sslmode=verify-full\n",
                               db->conninfo_file);
            }
        }
    }
    /* B11: the id under which this server writes its row of karidns_server_status (release plan 4.8): server-id, else the host name.
     * The column holds 1..64 bytes (the parser limits server-id to that).  (sqlite3: warned about above.) */
    if (db->driver && !sqlite) {
        if (db->server_id) {
            size_t n = strlen(db->server_id);
            bool odd = false;
            for (size_t i = 0; i < n; i++) {
                unsigned char ch = (unsigned char)db->server_id[i];
                if (!isalnum(ch) && ch != '.' && ch != '-' && ch != '_' && ch != ':') odd = true;
            }
            if (odd)       /* the length (1..64 bytes) is checked by the parser */
                kc_warning(&t, "database: server-id '%s' has characters other than ASCII letters, digits and . - _ : ; use only those, "
                               "so that it reads the same in every tool and tables of other character sets take it\n", db->server_id);
        } else {
            char h[256];
            if (gethostname(h, sizeof(h)) == 0) {
                h[sizeof(h) - 1] = '\0';
                size_t n = strlen(h);
                if (n == 0 || n > 64)
                    kc_warning(&t, "database: server-id is not set and the host name has %zu bytes (karidns_server_status takes 1 to 64): "
                                   "a server with reload requests (karidns_reload_requests) cannot report its status; set server-id\n", n);
            }
        }
        /* B11b (D-B11-3): server-id is the signal that several servers may read this database.  An alias-resolver expands ALIAS
         * records at query time, so what each server answers for an ALIAS name depends on its resolver and the moment of the lookup;
         * the SOA serials and the zone transfers (which carry the ALIAS RR itself) stay the same.  (A resolver that a zone's profile
         * text names is not visible here.  LUA records are never run, so they are the same everywhere.) */
        if (db->server_id && (db->alias_resolver_count > 0 || cfg->alias_resolvers_count > 0))
            kc_warning(&t, "database: server-id is set and alias-resolver expands ALIAS records: the A and AAAA answers at an ALIAS name depend on "
                           "the resolver and the moment of the lookup, so two servers that share this database can answer differently "
                           "(SOA serials and zone transfers are the same); see karidns(8) \"Several servers on one PostgreSQL database\"\n");
    }
    return t.errors;
}

KARIDNS_TOOL_FN int check_config(const char *config_path, server_config_t *cfg) {
    printf("[INFO] Loading config %s...\n", config_path);
    bool failed = false;
    char *buf = read_file_or_die(config_path, &failed);
    if (failed || !buf) return 1;

    if (parse_named_conf_ext(buf, config_path, cfg) != 0) {
        fprintf(stderr, "[ERROR] Syntax error in config file: %s\n", config_path);
        free(buf);
        return 1;
    }

    int program_zone_count = 0;
    const view_config_t *zv;
    zone_config_t *z;
    CONFIG_FOR_EACH_ZONE(cfg, zv, z) {
        const zone_ext_t *zx = zext(z);
        /* D14 (B7a): transfer-acl-match / update-acl-match only choose between the entries of an ACL */
        if (zx->transfer_acl_match != ACL_MATCH_DEFAULT) {
            if (zx->allow_transfer_count == 0 && zx->tsig_keys_count == 0)
                fprintf(stderr, "[WARNING] Zone '%s': transfer-acl-match has no effect without allow-transfer\n", z->domain);
            else if (zx->allow_transfer_count == 0 || zx->tsig_keys_count == 0)
                fprintf(stderr, "[WARNING] Zone '%s': transfer-acl-match has no effect: allow-transfer lists only %s "
                                "(the option chooses between addresses and keys)\n",
                        z->domain, zx->allow_transfer_count ? "addresses" : "keys");
        }
        if (zx->update_acl_match != ACL_MATCH_DEFAULT) {
            bool addr = false, key = false;
            for (int i = 0; i < zx->allow_update_count; i++) {
                const char *e = zx->allow_update[i];
                cidr_entry_t ce;
                if (!e || e[0] == '!' || strcmp(e, "none") == 0 || cidr_entry_parse(&ce, e)) addr = true;
                else key = true;
            }
            if (zx->allow_update_count == 0)
                fprintf(stderr, "[WARNING] Zone '%s': update-acl-match has no effect without allow-update\n", z->domain);
            else if (!addr || !key)
                fprintf(stderr, "[WARNING] Zone '%s': update-acl-match has no effect: allow-update lists only %s "
                                "(the option chooses between addresses and keys)\n", z->domain, addr ? "addresses" : "keys");
        }
        if (z->type && strcasecmp(z->type, "program") == 0) {
            program_zone_count++;
            if (zx->program_path) {
                if (cfg->user && !zx->program_user) {
                    zone_ext_mut(z)->program_user = strdup(cfg->user);
                    zx = zext(z);
                }
                if (zx->program_path[0] != '/') {
                    fprintf(stderr,
                        "[ERROR] Zone '%s': 'program' must be an absolute path (got '%s'). "
                        "A relative name would be resolved via $PATH at runtime, which is "
                        "not deterministic for a network-facing daemon.\n",
                        z->domain, zx->program_path);
                    free(buf);
                    return 1;
                }
                if (access(zx->program_path, X_OK) != 0) {
                    fprintf(stderr, "[WARNING] Zone '%s' program '%s' is not executable (access X_OK failed: %s)\n",
                            z->domain, zx->program_path, strerror(errno));
                }
                if (zx->program_user && cfg->user &&
                    strcasecmp(zx->program_user, cfg->user) != 0) {
                    fprintf(stderr,
                        "[WARNING] Zone '%s': program-user '%s' differs from options.user '%s'. "
                        "This only works if karidns itself starts as root (no prior privilege drop); "
                        "if karidns is started as a non-root user, it refuses to start "
                        "(setuid to a different non-root user is not permitted by the OS).\n",
                        z->domain, zx->program_user, cfg->user);
                }
                if (zx->program_args_count > 62) {
                    fprintf(stderr,
                        "[ERROR] Zone '%s': program-args has %d entries, but only 62 are "
                        "supported (argv[] is fixed-size in spawn_one_program_plugin()). "
                        "Reduce the argument count.\n",
                        z->domain, zx->program_args_count);
                    free(buf);
                    return 1;
                }
            } else {
                fprintf(stderr, "[ERROR] Zone '%s' has type 'program' but no 'program' path specified\n", z->domain);
                free(buf);
                return 1;
            }
        } else if (z->type && strcasecmp(z->type, "forward") == 0) {
            if (zx->forwarders_count == 0) {
                fprintf(stderr, "[ERROR] Zone '%s' has type 'forward' but no 'forwarders' specified\n",
                        z->domain);
                free(buf);
                return 1;
            }
            // 自己ループ検知: forwarders のいずれかが自分自身の
            // bind-address:port と一致していないか確認する
            for (int fi = 0; fi < zx->forwarders_count; fi++) {
                if (cfg->bind_addresses) {
                    for (int bi = 0; bi < cfg->bind_address_count; bi++) {
                        if (strcmp(zx->forwarders[fi].ip, cfg->bind_addresses[bi]) == 0 &&
                            (zx->forwarders[fi].port == cfg->port || zx->forwarders[fi].port == 0)) {
                            fprintf(stderr,
                                "[WARNING] Zone '%s': forwarder '%s:%d' appears to point back "
                                "at this server itself (self-loop risk).\n",
                                z->domain, zx->forwarders[fi].ip, zx->forwarders[fi].port);
                        }
                    }
                }
            }
        }
    }

    if (program_zone_count > 0 && !cfg->allow_program_zones) {
        fprintf(stderr, "[ERROR] Config contains %d type 'program' zone(s), but 'allow-program-zones' is not enabled in options{}\n",
                program_zone_count);
        free(buf);
        return 1;
    }

    bool ecs_error = false;
    bool has_ecs_tags = (cfg->ecs_tag_count > 0);
    for (int ti = 0; ti < cfg->ecs_tag_count; ti++) {
        for (int ci = 0; ci < cfg->ecs_tags[ti].cidr_count; ci++) {
            if (!validate_cidr_syntax(cfg->ecs_tags[ti].cidrs[ci].cidr)) {
                fprintf(stderr, "[ERROR] Invalid CIDR '%s' in options.ecs-tags tag '%s'\n",
                        cfg->ecs_tags[ti].cidrs[ci].cidr, cfg->ecs_tags[ti].tag);
                ecs_error = true;
            }
        }
    }
    for (int ti = 0; ti < cfg->location_tag_count; ti++) {
        for (int ci = 0; ci < cfg->location_tags[ti].cidr_count; ci++) {
            if (!validate_cidr_syntax(cfg->location_tags[ti].cidrs[ci].cidr)) {
                fprintf(stderr, "[ERROR] Invalid CIDR '%s' in options.location-tags tag '%s'\n",
                        cfg->location_tags[ti].cidrs[ci].cidr, cfg->location_tags[ti].tag);
                ecs_error = true;
            }
        }
    }
    {
    const view_config_t *zcv;
    zone_config_t *zc;
    CONFIG_FOR_EACH_ZONE(cfg, zcv, zc) {
        const zone_ext_t *zx = zext(zc);
        if (zx->ecs_tag_count > 0) has_ecs_tags = true;
        for (int ti = 0; ti < zx->ecs_tag_count; ti++) {
            for (int ci = 0; ci < zx->ecs_tags[ti].cidr_count; ci++) {
                if (!validate_cidr_syntax(zx->ecs_tags[ti].cidrs[ci].cidr)) {
                    fprintf(stderr, "[ERROR] Zone '%s': Invalid CIDR '%s' in ecs-tags tag '%s'\n",
                            zc->domain, zx->ecs_tags[ti].cidrs[ci].cidr, zx->ecs_tags[ti].tag);
                    ecs_error = true;
                }
            }
        }
        for (int ti = 0; ti < zx->location_tag_count; ti++) {
            for (int ci = 0; ci < zx->location_tags[ti].cidr_count; ci++) {
                if (!validate_cidr_syntax(zx->location_tags[ti].cidrs[ci].cidr)) {
                    fprintf(stderr, "[ERROR] Zone '%s': Invalid CIDR '%s' in location-tags tag '%s'\n",
                            zc->domain, zx->location_tags[ti].cidrs[ci].cidr, zx->location_tags[ti].tag);
                    ecs_error = true;
                }
            }
        }
    }
    }
    if (has_ecs_tags && !cfg->ecs_enable) {
        fprintf(stderr, "[WARNING] ecs-tags defined, but ecs-enable is not set to 'yes' in options{}\n");
    }
    if (ecs_error) {
        free(buf);
        return 1;
    }

    if (kc_check_database(cfg) > 0) {
        free(buf);
        return 1;
    }

    printf("[OK] Config file %s is valid.\n", config_path);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* karicheck db [view]  (B12, beta design 7.2)                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

/* `karicheck db` links no database library.  It runs `karidns-dbloader --check` once per database the views read, as the user the
 * loader of karidns runs as (when karicheck is run by root it drops to loader-user / loader-group first, D-B12-1; otherwise it runs
 * with its own rights), reads the lines of the check protocol (dns_db_checkproto.h) from a pipe and prints them in the style of
 * `karicheck zone`.  What needs the configuration is done here, on the lines the loader sends: the restricted parse of the settings
 * texts with the key names and acl-ceiling, the views a zone is mapped to, and the zones of karidns.conf that shadow a database zone
 * (D-PRIO / D-PROG).  Everything the loader sends is untrusted (it runs with fewer rights than we may have): fields are bounded,
 * unescaped strictly, and printed through kc_pr(). */

/* printable copy of s for a message (one of four rotating buffers) */
KARIDNS_TOOL_FN const char *kc_pr(const char *s) {
    static char buf[4][600];
    static unsigned k;
    char *b = buf[k++ % 4];
    size_t i = 0;
    for (; s && s[i] && i < sizeof(buf[0]) - 4; i++) b[i] = ((unsigned char)s[i] >= 0x20 && (unsigned char)s[i] < 0x7F) ? s[i] : '?';
    if (s && s[i]) {
        b[i++] = '.';
        b[i++] = '.';
        b[i++] = '.';
    }
    b[i] = '\0';
    return b;
}

typedef struct { const view_config_t *v; bool shared; } kc_member_t;
typedef struct {
    const char *source;             /* sqlite3: the database file; postgresql: the schema (NULL: the search_path of the role) */
    kc_member_t *mem;               /* the views that read it, and whether through the shared source (karidns_domain_views decides) */
    size_t nmem, cmem;
} kc_dbsrc_t;

typedef struct {
    const server_config_t *cfg;
    const kc_dbsrc_t *src;
    const view_config_t *only;      /* karicheck db VIEW: only the zones that view gets are shown */
    const char *label;
    kc_tally_t t;
    unsigned zones;                 /* Z lines */
    bool vis;                       /* the zone of the last Z line is shown */
    char zone[DNS_NAME_TEXT_SIZE + 4];
    long long zid;
    bool have_r;
    unsigned r_errors;
    char raw[3][160];               /* lines that are not protocol lines */
    unsigned nraw, nraw_all;
    bool overlong;
} kc_dbrun_t;

/* "the view 'x'", or "the default view" for the view karidns makes when the configuration has no view {} */
KARIDNS_TOOL_FN const char *kc_vdesc(const char *name) {
    static char buf[2][320];
    static unsigned k;
    char *b = buf[k++ % 2];
    if (!name || strcmp(name, "__default__") == 0) snprintf(b, sizeof(buf[0]), "the default view");
    else snprintf(b, sizeof(buf[0]), "the view '%s'", kc_pr(name));
    return b;
}

/* the message of a finding, with the database and, for a zone, the zone */
KARIDNS_TOOL_FN void kc_db_say(kc_dbrun_t *r, char level, const char *zone, long long id, const char *text) {
    char head[DNS_NAME_TEXT_SIZE + 128];
    if (zone && zone[0]) snprintf(head, sizeof(head), "%s: zone '%s' (domains.id %lld): ", r->label, kc_pr(zone), id);
    else snprintf(head, sizeof(head), "%s: ", r->label);
    switch (level) {
    case 'E': kc_error(&r->t, "%s%s\n", head, kc_pr(text)); break;
    case 'W': kc_warning(&r->t, "%s%s\n", head, kc_pr(text)); break;
    case 'I': kc_info(&r->t, "%s%s\n", head, kc_pr(text)); break;
    case 'O': kc_ok(&r->t, "%s%s\n", head, kc_pr(text)); break;
    default: kc_detail(&r->t, "%s\n", kc_pr(text)); break;
    }
}

KARIDNS_TOOL_FN void kc_db_sayf(kc_dbrun_t *r, char level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
KARIDNS_TOOL_FN void kc_db_sayf(kc_dbrun_t *r, char level, const char *fmt, ...) {
    char msg[1200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    kc_db_say(r, level, r->zone, r->zid, msg);
}

KARIDNS_TOOL_FN const view_config_t *kc_find_view(const server_config_t *cfg, const char *name) {
    for (const view_config_t *v = cfg->views; v; v = v->next)
        if (v->name && strcasecmp(v->name, name) == 0) return v;
    return NULL;
}

/* is the view listed for the zone: through the shared source of the database, or because the view has its own source */
KARIDNS_TOOL_FN bool kc_db_view_gets(const kc_member_t *m, char **maps, int nmaps) {
    if (!m->shared) return true;                   /* a view's own database ignores karidns_domain_views */
    if (nmaps == 1 && strcmp(maps[0], "*") == 0) return true;
    for (int i = 0; i < nmaps; i++)
        if (m->v->name && strcasecmp(m->v->name, maps[i]) == 0) return true;
    return false;
}

/* A Z line: Z <zone> <id> <kind> <view>... */
KARIDNS_TOOL_FN void kc_db_zone(kc_dbrun_t *r, char **f, int n) {
    char name[DNS_NAME_TEXT_SIZE + 4], *maps[CHK_MAX_FIELDS];
    char mapbuf[CHK_MAX_FIELDS][270];
    int nmaps = 0;
    r->zones++;
    if (chk_unescape(f[1], strlen(f[1]), name, sizeof(name)) == (size_t)-1) {
        r->zone[0] = '\0';
        r->zid = 0;
        r->vis = !r->only;
        kc_db_say(r, 'E', "", 0, "the loader sent a zone line that does not decode");
        return;
    }
    snprintf(r->zone, sizeof(r->zone), "%s", name);
    r->zid = strtoll(f[2], NULL, 10);
    for (int i = 4; i < n && nmaps < CHK_MAX_FIELDS; i++) {
        if (chk_unescape(f[i], strlen(f[i]), mapbuf[nmaps], sizeof(mapbuf[nmaps])) == (size_t)-1) continue;
        maps[nmaps] = mapbuf[nmaps];
        nmaps++;
    }
    if (nmaps == 0) {
        snprintf(mapbuf[0], sizeof(mapbuf[0]), "*");
        maps[0] = mapbuf[0];
        nmaps = 1;
    }
    bool any_shared = false, served_shared = false;
    bool in_only = false;
    const kc_member_t *served[64];
    size_t nserved = 0;
    for (size_t i = 0; i < r->src->nmem; i++) {
        const kc_member_t *m = &r->src->mem[i];
        if (m->shared) any_shared = true;
        if (!kc_db_view_gets(m, maps, nmaps)) continue;
        if (m->shared) served_shared = true;
        if (m->v == r->only) in_only = true;
        if (nserved < sizeof(served) / sizeof(served[0])) served[nserved++] = m;
    }
    r->vis = !r->only || in_only;
    bool valid = strcmp(f[3], "invalid") != 0;
    if (!r->vis || !valid) return;
    /* karidns_domain_views: rows that name a view this server does not have, or one that does not read this database through the shared
     * source, are ignored by the server (it logs them); a zone that only such rows map is served by no view (design 7.1) */
    if (any_shared && !(nmaps == 1 && strcmp(maps[0], "*") == 0)) {
        for (int i = 0; i < nmaps; i++) {
            const view_config_t *v = kc_find_view(r->cfg, maps[i]);
            bool shared_member = false;
            for (size_t k = 0; k < r->src->nmem; k++)
                if (r->src->mem[k].shared && r->src->mem[k].v == v) shared_member = true;
            if (!v)
                kc_db_sayf(r, 'W', "karidns_domain_views names the view '%s', which is not defined in the configuration; the row is ignored", kc_pr(maps[i]));
            else if (!shared_member)
                kc_db_sayf(r, 'W', "karidns_domain_views names the view '%s', which does not read this database through the shared source "
                                   "(database none, or a database-file / database-schema of its own); the row is ignored", kc_pr(maps[i]));
        }
        if (!served_shared)
            kc_db_sayf(r, 'W', "karidns_domain_views maps the zone only to views that do not read it, so no view serves the zone");
    }
    /* D-PRIO / D-PROG: a zone of karidns.conf with the same name hides the database zone in that view (design 4.5) */
    for (size_t i = 0; i < nserved; i++) {
        if (r->only && served[i]->v != r->only) continue;                    /* karicheck db VIEW: the views of the other zones are not asked about */
        const zone_config_t *zc = view_find_zone_config(served[i]->v, name);
        if (!zc) continue;
        const char *vn = served[i]->v->name ? served[i]->v->name : "";
        if (zc->type && (strcasecmp(zc->type, "program") == 0 || strcasecmp(zc->type, "forward") == 0))
            kc_db_sayf(r, 'W', "D-PROG: %s has a zone of type %s with this name in the configuration; it hides the database zone", kc_vdesc(vn),
                       zc->type);
        else
            kc_db_sayf(r, 'W', "D-PRIO: %s has a zone with this name in the configuration%s%s%s; it hides the database zone", kc_vdesc(vn),
                       zc->file ? " (file '" : "", zc->file ? kc_pr(zc->file) : "", zc->file ? "')" : "");
    }
}

/* is the address / prefix entry e (not negated) inside the address entries of acl-ceiling?  First match decides, as at run time. */
KARIDNS_TOOL_FN bool kc_ceiling_covers(const database_config_t *db, const cidr_entry_t *e) {
    for (int i = 0; i < db->acl_ceiling_count; i++) {
        const cidr_entry_t *c = &db->acl_ceiling_parsed[i].cidr;
        if (!c->valid) continue;
        bool covers;
        if (c->is_any) {
            covers = true;
        } else if (e->is_any || c->family != e->family || c->prefix > e->prefix) {
            covers = false;
        } else {
            covers = true;
            for (int b = 0; b < 16 && covers; b++)
                if ((e->addr[b] & c->mask[b]) != c->addr[b]) covers = false;
        }
        if (covers) return !db->acl_ceiling_parsed[i].is_deny;
    }
    return false;
}

KARIDNS_TOOL_FN void kc_db_acl_list(kc_dbrun_t *r, const char *what, char *const *entries, int count, bool keys_too) {
    const database_config_t *db = &r->cfg->database;
    for (int i = 0; i < count; i++) {
        const char *e = entries[i];
        if (!e || !*e || e[0] == '!' || strcmp(e, "none") == 0) continue;
        cidr_entry_t ce;
        if (cidr_entry_parse(&ce, e)) {
            if (!kc_ceiling_covers(db, &ce))
                kc_db_sayf(r, 'W', "%s entry '%s' is outside acl-ceiling; a client there is refused", what, kc_pr(e));
        } else if (keys_too) {
            bool listed = false;
            for (int k = 0; k < db->acl_ceiling_keys_count; k++)
                if (db->acl_ceiling_keys[k] && strcasecmp(db->acl_ceiling_keys[k], e) == 0) listed = true;
            if (!listed)
                kc_db_sayf(r, 'W', "%s key '%s' is not listed in acl-ceiling; a client that uses it is refused unless its address is inside the ceiling", what, kc_pr(e));
        }
    }
}

KARIDNS_TOOL_FN void kc_db_ceiling(kc_dbrun_t *r, const zone_ext_t *x) {
    const database_config_t *db = &r->cfg->database;
    if (db->acl_ceiling_count == 0 && db->acl_ceiling_keys_count == 0) {
        if (x->allow_transfer_count > 0 || x->tsig_keys_count > 0 || x->allow_update_count > 0 || x->ecs_trusted_resolvers_count > 0)
            kc_db_sayf(r, 'W', "the settings have allow-transfer / allow-update / ecs-trusted-resolvers entries, but acl-ceiling is not configured; "
                               "the ACLs of a database zone refuse every client without it");
        return;
    }
    kc_db_acl_list(r, "allow-transfer", x->allow_transfer, x->allow_transfer_count, false);
    for (int i = 0; i < x->tsig_keys_count; i++) {
        bool listed = false;
        for (int k = 0; k < db->acl_ceiling_keys_count; k++)
            if (x->tsig_keys[i] && db->acl_ceiling_keys[k] && strcasecmp(db->acl_ceiling_keys[k], x->tsig_keys[i]) == 0) listed = true;
        if (!listed)
            kc_db_sayf(r, 'W', "allow-transfer key '%s' is not listed in acl-ceiling; a client that uses it is refused unless its address is inside the ceiling",
                       kc_pr(x->tsig_keys[i] ? x->tsig_keys[i] : ""));
    }
    kc_db_acl_list(r, "allow-update", x->allow_update, x->allow_update_count, true);
    kc_db_acl_list(r, "ecs-trusted-resolvers", x->ecs_trusted_resolvers, x->ecs_trusted_resolvers_count, false);
}

/* db_settings_parse() prints the parser's own "[ERROR] zone 'settings.': ..." lines on stderr.  Here they would be lines about no zone, so the
 * parse runs with stderr on /dev/null; when it fails, it is repeated once with stderr on a temporary file to learn the parser's reason
 * (the `err` text is often only "syntax error or invalid value"), which then goes into our message.  false: no second run. */
static bool kc_settings_capture = true;

KARIDNS_TOOL_FN zone_ext_shared_t *kc_parse_settings(const char *text, size_t len, char *err, size_t errlen) {
    static int devnull = -2;
    if (devnull == -2) devnull = open("/dev/null", O_WRONLY);
    fflush(stderr);
    int saved = dup(2);
    if (devnull >= 0 && saved >= 0) dup2(devnull, 2);
    zone_ext_shared_t *sh = db_settings_parse(text, len, err, errlen);
    fflush(stderr);
    if (saved >= 0) {
        dup2(saved, 2);
        close(saved);
    }
    if (!sh && kc_settings_capture) {
        FILE *tf = tmpfile();
        saved = dup(2);
        if (tf && saved >= 0) {
            char e2[200], line[300];
            dup2(fileno(tf), 2);
            zone_ext_shared_t *x2 = db_settings_parse(text, len, e2, sizeof(e2));
            fflush(stderr);
            dup2(saved, 2);
            if (x2) zone_ext_shared_unref(x2);
            rewind(tf);
            if (fgets(line, sizeof(line), tf)) {
                size_t n = strcspn(line, "\r\n");
                line[n] = '\0';
                const char *p = strncmp(line, "[ERROR] ", 8) == 0 ? line + 8 : line;
                if (*p) snprintf(err, errlen, "%s", p);
            }
        }
        if (saved >= 0) close(saved);
        if (tf) fclose(tf);
    }
    return sh;
}

/* An S line: S <zone> <id> <settings text> <profile> <profile text>.  The Backend parses the profile text alone, the zone text alone, and the
 * profile text followed by a line feed and the zone text, in restricted mode (design 7.3). */
KARIDNS_TOOL_FN void kc_db_settings(kc_dbrun_t *r, char **f) {
    if (!r->vis) return;
    size_t zl = strlen(f[3]), pl = strlen(f[5]);
    char *zt = malloc(zl + 1), *pt = malloc(pl + 1), *both = malloc(zl + pl + 2);
    if (!zt || !pt || !both) {
        kc_db_say(r, 'E', r->zone, r->zid, "out of memory");
        goto out;
    }
    size_t zn = chk_unescape(f[3], zl, zt, zl + 1), pn = chk_unescape(f[5], pl, pt, pl + 1);
    if (zn == (size_t)-1 || pn == (size_t)-1) {
        kc_db_say(r, 'E', r->zone, r->zid, "the loader sent a settings line that does not decode");
        goto out;
    }
    char pname[300];
    if (chk_unescape(f[4], strlen(f[4]), pname, sizeof(pname)) == (size_t)-1) pname[0] = '\0';
    char err[200];
    zone_ext_shared_t *sh;
    if (pn > 0) {
        sh = kc_parse_settings(pt, pn, err, sizeof(err));
        if (!sh) {
            kc_db_sayf(r, 'E', "the settings text of the profile '%s' does not parse in restricted mode: %s", kc_pr(pname), kc_pr(err));
            goto out;
        }
        zone_ext_shared_unref(sh);
    }
    if (zn > 0) {
        sh = kc_parse_settings(zt, zn, err, sizeof(err));
        if (!sh) {
            kc_db_sayf(r, 'E', "the settings from domainmetadata do not parse in restricted mode: %s", kc_pr(err));
            goto out;
        }
        zone_ext_shared_unref(sh);
    }
    size_t bn = 0;
    if (pn > 0) {
        memcpy(both, pt, pn);
        bn = pn;
    }
    if (pn > 0 && zn > 0) both[bn++] = '\n';
    if (zn > 0) {
        memcpy(both + bn, zt, zn);
        bn += zn;
    }
    sh = kc_parse_settings(both, bn, err, sizeof(err));
    if (!sh) {
        kc_db_sayf(r, 'E', "the settings of the profile '%s' and of the zone together do not parse in restricted mode: %s", kc_pr(pname), kc_pr(err));
        goto out;
    }
    const char *missing = db_settings_missing_key(&sh->ext, r->cfg);
    if (missing)
        kc_db_sayf(r, 'E', "the settings name the TSIG key '%s', which is not defined in the configuration (key \"%s\" { ... };); the server refuses the zone",
                   kc_pr(missing), kc_pr(missing));
    kc_db_ceiling(r, &sh->ext);
    zone_ext_shared_unref(sh);
out:
    free(zt);
    free(pt);
    free(both);
}

/* One line of the loader */
KARIDNS_TOOL_FN void kc_db_line(kc_dbrun_t *r, char *line) {
    char *f[CHK_MAX_FIELDS], shown[160];
    size_t sk = 0;
    for (; line[sk] && sk < sizeof(shown) - 1; sk++)                 // what to print if this is not a line of the protocol
        shown[sk] = line[sk] == '\t' ? ' ' : ((unsigned char)line[sk] >= 0x20 && (unsigned char)line[sk] < 0x7F) ? line[sk] : '?';
    shown[sk] = '\0';
    int n = chk_split(line, f, CHK_MAX_FIELDS);
    char tag = n > 0 && f[0][0] && !f[0][1] ? f[0][0] : 0;
    bool proto = (tag && strchr("EWIOD", tag) && n == 4) || (tag == 'Z' && n >= 5) || (tag == 'S' && n == 6) || (tag == 'R' && n == 4);
    if (!proto) {
        r->nraw_all++;
        if (r->nraw < 3) {
            snprintf(r->raw[r->nraw++], sizeof(r->raw[0]), "%s", shown);
        }
        return;
    }
    if (tag == 'Z') {
        kc_db_zone(r, f, n);
        return;
    }
    if (tag == 'S') {
        kc_db_settings(r, f);
        return;
    }
    if (tag == 'R') {
        r->have_r = true;
        r->r_errors = (unsigned)strtoul(f[2], NULL, 10);
        return;
    }
    char zone[DNS_NAME_TEXT_SIZE + 4], text[4 * CHK_TEXT_MAX + 16];
    if (chk_unescape(f[1], strlen(f[1]), zone, sizeof(zone)) == (size_t)-1 || chk_unescape(f[3], strlen(f[3]), text, sizeof(text)) == (size_t)-1) {
        r->nraw_all++;
        return;
    }
    long long id = strtoll(f[2], NULL, 10);
    if (zone[0] && r->only && !(r->vis && strcmp(zone, r->zone) == 0)) return;          /* a zone of another view */
    kc_db_say(r, tag, zone, id, text);
}

/* The user the loader of karidns runs as (design 1.2): when root runs karicheck, loader-user / loader-group; else the caller. */
KARIDNS_TOOL_FN bool kc_db_identity(const database_config_t *db, uid_t *uid, gid_t *gid, bool *drop, char *who, size_t whocap) {
    *drop = false;
    if (geteuid() != 0) {
        struct passwd *pw = getpwuid(geteuid());
        snprintf(who, whocap, "the rights of the user %s (uid %u)", pw ? pw->pw_name : "?", (unsigned)geteuid());
        struct passwd *lu = db->loader_user ? getpwnam(db->loader_user) : NULL;
        if (lu && lu->pw_uid != geteuid()) {
            size_t l = strlen(who);
            snprintf(who + l, whocap - l, "; loader-user is '%s', so what the files allow can differ (run karicheck as root or as that user)", kc_pr(db->loader_user));
        }
        return true;
    }
    if (!db->loader_user) {
        fprintf(stderr, "[ERROR] karicheck is run by root, but options { database { loader-user } } is not set: karidns does not run the loader as root, "
                        "so there are no rights to check with; run karicheck as the user of the loader, or set loader-user\n");
        return false;
    }
    struct passwd *pw = getpwnam(db->loader_user);
    if (!pw) {
        fprintf(stderr, "[ERROR] database loader-user '%s' does not exist\n", kc_pr(db->loader_user));
        return false;
    }
    *uid = pw->pw_uid;
    *gid = pw->pw_gid;
    if (db->loader_group) {
        struct group *gr = getgrnam(db->loader_group);
        if (!gr) {
            fprintf(stderr, "[ERROR] database loader-group '%s' does not exist\n", kc_pr(db->loader_group));
            return false;
        }
        *gid = gr->gr_gid;
    }
    *drop = true;
    snprintf(who, whocap, "the rights of loader-user '%s'%s%s (karicheck was run by root and drops to it, as karidns does for the loader)",
             kc_pr(db->loader_user), db->loader_group ? " / loader-group " : "", db->loader_group ? kc_pr(db->loader_group) : "");
    return true;
}

extern char **environ;

/* Run the loader for one source.  Returns 0, or 1 when something was wrong (also: it could not be run). */
KARIDNS_TOOL_FN int kc_db_run_source(const server_config_t *cfg, const kc_dbsrc_t *src, const view_config_t *only, bool sqlite, unsigned *zones_out,
                                     int *errors_out, int *warnings_out) {
    const database_config_t *db = &cfg->database;
    char label[1200], who[400];
    if (sqlite) snprintf(label, sizeof(label), "Database file '%s'", kc_pr(src->source));
    else if (src->source) snprintf(label, sizeof(label), "Database schema '%s'", kc_pr(src->source));
    else snprintf(label, sizeof(label), "Database (default schema)");
    uid_t uid = 0;
    gid_t gid = 0;
    bool drop = false;
    if (!kc_db_identity(db, &uid, &gid, &drop, who, sizeof(who))) return 1;
    char names[600] = "";
    for (size_t i = 0; i < src->nmem; i++) {
        size_t l = strlen(names);
        snprintf(names + l, sizeof(names) - l, "%s%s", i ? ", " : "", kc_pr(src->mem[i].v->name ? src->mem[i].v->name : ""));
    }
    if (src->nmem == 1 && src->mem[0].v->name && strcmp(src->mem[0].v->name, "__default__") == 0)
        printf("[INFO] Checking %s (the default view) with %s\n", label, who);
    else
        printf("[INFO] Checking %s (view%s %s) with %s\n", label, src->nmem > 1 ? "s" : "", names, who);
    fflush(stdout);

    /* the arguments: the source, and what the configuration says about the load */
    const char *argv[1100];
    char num[4][40];
    int a = 0;
    const char *lp = db_loader_path(cfg);
    argv[a++] = "karidns-dbloader";
    argv[a++] = "--check";
    argv[a++] = "--driver";
    argv[a++] = db->driver;
    if (sqlite) {
        argv[a++] = "--database-file";
        argv[a++] = src->source;
    } else {
        argv[a++] = "--conninfo-file";
        argv[a++] = db->conninfo_file;
        if (src->source) {
            argv[a++] = "--schema";
            argv[a++] = src->source;
        }
    }
    if (db->default_ttl) {
        snprintf(num[0], sizeof(num[0]), "%u", (unsigned)db->default_ttl);
        argv[a++] = "--default-ttl";
        argv[a++] = num[0];
    }
    if (db->max_zone_records) {
        snprintf(num[1], sizeof(num[1]), "%llu", (unsigned long long)db->max_zone_records);
        argv[a++] = "--max-zone-records";
        argv[a++] = num[1];
    }
    if (db->max_zone_bytes) {
        snprintf(num[2], sizeof(num[2]), "%llu", (unsigned long long)db->max_zone_bytes);
        argv[a++] = "--max-zone-bytes";
        argv[a++] = num[2];
    }
    if (db->auto_reload) argv[a++] = "--auto-reload";
    if (db->server_id) {
        argv[a++] = "--server-id";
        argv[a++] = db->server_id;
    }
    for (int i = 0; i < cfg->ecs_tag_count && i < 256; i++) {
        argv[a++] = "--ecs-tag";
        argv[a++] = cfg->ecs_tags[i].tag;
    }
    for (int i = 0; i < cfg->location_tag_count && i < 256; i++) {
        argv[a++] = "--location-tag";
        argv[a++] = cfg->location_tags[i].tag;
    }
    argv[a] = NULL;

    int fds[2];
    if (pipe(fds) != 0) {
        fprintf(stderr, "[ERROR] %s: pipe: %s\n", label, strerror(errno));
        return 1;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[ERROR] %s: fork: %s\n", label, strerror(errno));
        close(fds[0]);
        close(fds[1]);
        return 1;
    }
    if (pid == 0) {                                                     /* the child: the loader's rights, nothing else */
        char msg[400];
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) dup2(dn, 0);
        dup2(fds[1], 1);
        dup2(fds[1], 2);
        for (int fd = 3; fd < 256; fd++) close(fd);
        signal(SIGPIPE, SIG_DFL);
        if (drop) {
            if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0 || getuid() != uid || geteuid() != uid) {
                int n = snprintf(msg, sizeof(msg), "cannot drop to the loader user: %s\n", strerror(errno));
                if (n > 0) (void)!write(2, msg, (size_t)n);
                _exit(126);
            }
        }
        static char *empty_env[] = { NULL };
        environ = empty_env;
        if (chdir("/") != 0) _exit(126);
        execv(lp, (char *const *)argv);
        int n = snprintf(msg, sizeof(msg), "cannot execute '%s': %s\n", lp, strerror(errno));
        if (n > 0) (void)!write(2, msg, (size_t)n);
        _exit(127);
    }
    close(fds[1]);

    kc_dbrun_t r;
    memset(&r, 0, sizeof(r));
    r.cfg = cfg;
    r.src = src;
    r.only = only;
    r.label = label;
    r.vis = !only;
    char *buf = malloc(CHK_LINE_MAX + 2);
    size_t len = 0;
    bool skipping = false;
    if (!buf) {
        fprintf(stderr, "[ERROR] %s: out of memory\n", label);
        close(fds[0]);
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        return 1;
    }
    char chunk[16384];
    for (;;) {
        ssize_t got = read(fds[0], chunk, sizeof(chunk));
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        for (ssize_t i = 0; i < got; i++) {
            char ch = chunk[i];
            if (ch == '\n') {
                if (!skipping) {
                    buf[len] = '\0';
                    if (strlen(buf) == len) kc_db_line(&r, buf);
                    else r.nraw_all++;                              /* a NUL inside a line */
                }
                len = 0;
                skipping = false;
            } else if (!skipping) {
                if (len >= CHK_LINE_MAX) {
                    skipping = true;
                    r.overlong = true;
                    len = 0;
                } else {
                    buf[len++] = ch;
                }
            }
        }
    }
    close(fds[0]);
    if (len > 0 && !skipping) {                                         /* a last line without its line feed */
        buf[len] = '\0';
        kc_db_line(&r, buf);
    }
    free(buf);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    if (r.overlong) kc_error(&r.t, "%s: the loader wrote a line longer than %d bytes; it was skipped\n", label, CHK_LINE_MAX);
    if (rc >= 2 || !r.have_r) {
        /* it did not finish its job (usage, cannot run, database error, killed): whatever it said that was not a finding is the reason */
        if (r.t.errors == 0 || r.nraw > 0) {
            char why[500] = "";
            for (unsigned i = 0; i < r.nraw; i++) {
                size_t l = strlen(why);
                snprintf(why + l, sizeof(why) - l, "%s%s", i ? " / " : "", r.raw[i]);
            }
            kc_error(&r.t, "%s: the loader %s%s%s\n", label,
                     WIFSIGNALED(st) ? "was killed by a signal" : (rc == 127 ? "could not be executed" : rc == 4 ? "found the database busy or unreachable (try again)" :
                                                                          rc < 2 ? "ended without its final line" : "could not check the database"),
                     why[0] ? ": " : "", why);
        }
    } else if (r.nraw_all > 0) {
        kc_warning(&r.t, "%s: the loader printed %u line(s) that are not part of its protocol (first: %s)\n", label, r.nraw_all, r.nraw ? r.raw[0] : "?");
    }
    printf("[RESULT] %s: %u zone(s) read, %d error(s), %d warning(s)\n", label, r.zones, r.t.errors, r.t.warnings);
    if (r.t.errors > 0) fprintf(stderr, "[FAIL] %s has errors.\n", label);
    else printf("[OK] %s is valid.\n", label);
    *zones_out += r.zones;
    *errors_out += r.t.errors;
    *warnings_out += r.t.warnings;
    return r.t.errors > 0 ? 1 : 0;
}

/* karicheck db [view] [config_path] */
KARIDNS_TOOL_FN int kc_db_main(const char *config_path, const char *view_arg) {
    setvbuf(stdout, NULL, _IOLBF, 0);                   // the lines of stdout and stderr come out in the order they were written even in a pipe
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    printf("[INFO] Loading config %s...\n", config_path);
    bool failed = false;
    char *buf = read_file_or_die(config_path, &failed);
    if (failed || !buf) return 1;
    if (parse_named_conf_ext(buf, config_path, &cfg) != 0) {
        fprintf(stderr, "[ERROR] Syntax error in config file: %s\n", config_path);
        free(buf);
        return 1;
    }
    free(buf);
    const database_config_t *db = &cfg.database;
    if (!db->enabled) {
        fprintf(stderr, "[ERROR] The configuration has no options { database { } } block; there is no database to check\n");
        return 1;
    }
    const char *lp = db_loader_path(&cfg);
    struct stat lst;
    if (stat(lp, &lst) != 0 && errno == ENOENT) {
        fprintf(stderr, "[ERROR] DB support is not installed: the database loader '%s' does not exist (this installation has no karidns-dbloader; "
                        "install the karidns-sqlite3, karidns-postgresql or karidns-db package, or set loader-path)\n", kc_pr(lp));
        return 1;
    }
    const view_config_t *only = NULL;
    if (view_arg) {
        only = kc_find_view(&cfg, view_arg);
        if (!only) {
            fprintf(stderr, "[ERROR] The view '%s' is not defined in %s\n", kc_pr(view_arg), config_path);
            return 1;
        }
        if (only->database_none) {
            fprintf(stderr, "[ERROR] The view '%s' takes no zones from the database (database none)\n", kc_pr(view_arg));
            return 1;
        }
    }
    /* The rest of the database block (loader-user, the ownership of the loader, the mode of the files) is for `karicheck conf`: the loader
     * says what it cannot read, with the rights it runs with.  What this command needs: a loader that can be executed and has the driver. */
    {
        kc_tally_t ct = {0};
        if (!db->driver) kc_error(&ct, "options { database { } } has no driver\n");
        else if (!kc_check_loader_file(&ct, lp) || ct.errors > 0) {}                     /* ownership, mode and X_OK as karidns wants them: before the loader is run */
        else if (geteuid() != 0) kc_check_loader_driver(&ct, lp, db->driver);      /* root does not run the loader, not even --drivers: the loader after the privilege drop says it */
        if (ct.errors > 0) return 1;
    }

    /* the databases the views read: the global source for the views without one of their own, and the own source of each other view */
    bool sqlite = db->driver && strcmp(db->driver, "sqlite3") == 0;
    kc_dbsrc_t *srcs = NULL;
    size_t nsrc = 0, csrc = 0;
    for (const view_config_t *v = cfg.views; v; v = v->next) {
        if (v->database_none) continue;
        const char *own = sqlite ? v->database_file : v->database_schema;
        const char *source = own ? own : (sqlite ? db->database_file : db->schema);
        if (sqlite && !source) continue;                                /* reported by karicheck conf */
        size_t k = 0;
        for (; k < nsrc; k++)
            if ((srcs[k].source == NULL) == (source == NULL) && (!source || strcmp(srcs[k].source, source) == 0)) break;
        if (k == nsrc) {
            if (nsrc == csrc) {
                csrc = csrc ? csrc * 2 : 8;
                kc_dbsrc_t *ns = realloc(srcs, csrc * sizeof(*ns));
                if (!ns) {
                    fprintf(stderr, "[ERROR] Out of memory\n");
                    free(srcs);
                    return 1;
                }
                srcs = ns;
            }
            memset(&srcs[nsrc], 0, sizeof(srcs[0]));
            srcs[nsrc++].source = source;
        }
        kc_dbsrc_t *s = &srcs[k];
        if (s->nmem == s->cmem) {
            s->cmem = s->cmem ? s->cmem * 2 : 4;
            kc_member_t *nm = realloc(s->mem, s->cmem * sizeof(*nm));
            if (!nm) {
                fprintf(stderr, "[ERROR] Out of memory\n");
                return 1;
            }
            s->mem = nm;
        }
        s->mem[s->nmem].v = v;
        s->mem[s->nmem].shared = own == NULL;
        s->nmem++;
    }
    int bad = 0, total_err = 0, total_warn = 0;
    unsigned total_zones = 0;
    size_t ran = 0;
    for (size_t i = 0; i < nsrc; i++) {
        bool has_only = !only;
        for (size_t k = 0; k < srcs[i].nmem; k++)
            if (srcs[i].mem[k].v == only) has_only = true;
        if (!has_only) continue;
        ran++;
        if (kc_db_run_source(&cfg, &srcs[i], only, sqlite, &total_zones, &total_err, &total_warn) != 0) bad++;
    }
    if (ran == 0) {
        fprintf(stderr, "[ERROR] No view reads a database: nothing to check\n");
        bad++;
    }
    printf("[INFO] Checked %zu database%s (%u zone%s). Errors: %d, warnings: %d\n", ran, ran == 1 ? "" : "s", total_zones, total_zones == 1 ? "" : "s", total_err,
           total_warn);
    for (size_t i = 0; i < nsrc; i++) free(srcs[i].mem);
    free(srcs);
    return bad > 0 ? 1 : 0;
}

KARIDNS_TOOL_FN void print_usage(FILE *fp, const char *prog) {
    fprintf(fp, "Usage:\n");
    fprintf(fp, "  %s [-v | --version]\n", prog);
    fprintf(fp, "  %s conf [config_path]\n", prog);
    fprintf(fp, "  %s zones [config_path]\n", prog);
    fprintf(fp, "  %s zone <domain> [config_path]\n", prog);
    fprintf(fp, "  %s zone <domain> <zone_file_path>\n", prog);
    fprintf(fp, "  %s db [view] [config_path]\n", prog);
    fprintf(fp, "\n");
    fprintf(fp, "db reads the PowerDNS tables of options { database { } } (read only, through karidns-dbloader --check) and checks the schema,\n");
    fprintf(fp, "every zone (as zone does), the settings texts, the views and the zones that karidns.conf defines with the same name.  Run by\n");
    fprintf(fp, "root it drops to loader-user / loader-group first; run by another user it checks with that user's rights.  Exit status 0: no\n");
    fprintf(fp, "error, 1: errors (or the check could not be run).  A single argument is a view unless it contains a '/' or ends in .conf.\n");
    fprintf(fp, "Examples:\n");
    fprintf(fp, "  %s db\n", prog);
    fprintf(fp, "  %s db internal /usr/local/etc/karidns/karidns.conf\n", prog);
}

#if defined(KARIDNS_COVERAGE_LINKAGE) && !defined(main)
/* Coverage builds: the tests #include this file with "#define main karicheck_main",
 * so the body below is named karicheck_main here as well; llvm-cov then merges the
 * counters of every binary that runs it (see karidns_tool_linkage.h). */
int karicheck_main(int argc, char **argv);
int main(int argc, char **argv) { return karicheck_main(argc, argv); }
#define main karicheck_main
#endif
int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(stderr, argv[0]);
        return 2;
    }

    /* -h / --help: the text goes to stdout and the exit status is 0 (as karictl and karidns-dbloader do); a usage error goes to stderr with 2 (1 is "problems found") */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(stdout, argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("karicheck %s\n", KARIDNS_VERSION);
        return 0;
    }

    const char *cmd = argv[1];
    const char *default_config = "/usr/local/etc/karidns/karidns.conf";
    if (access(default_config, F_OK) != 0 && access("/usr/local/etc/karidns.conf", F_OK) == 0) {
        default_config = "/usr/local/etc/karidns.conf";
    }

    if (strcmp(cmd, "conf") == 0) {
        const char *cfg_path = (argc >= 3) ? argv[2] : default_config;
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        return check_config(cfg_path, &cfg);
    } else if (strcmp(cmd, "zones") == 0) {
        const char *cfg_path = (argc >= 3) ? argv[2] : default_config;
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        if (check_config(cfg_path, &cfg) != 0) return 1;

        int error_count = 0;
        int checked = 0;
        int skipped = 0;
        for (view_config_t *v = cfg.views; v; v = v->next) {
            for (zone_config_t *z = v->zones; z; z = z->next) {
                /* 型名はパーサが小文字の master/slave/forward/program に正規化している (D-23) */
                if (!z->type || strcmp(z->type, "master") == 0) {
                    if (check_zone(z->domain, z->file, false, z->is_catalog, zext(z)->file_format, z, &cfg, v) != 0) {
                        error_count++;
                    }
                    checked++;
                } else {
                    printf("[INFO] Skipping zone '%s' (type %s): no zone file to check\n", z->domain, z->type);
                    skipped++;
                }
            }
        }
        printf("[INFO] Checked %d zones (%d skipped). Errors: %d\n", checked, skipped, error_count);
        return (error_count > 0) ? 1 : 0;
    } else if (strcmp(cmd, "zone") == 0) {
        if (argc < 3) {
            print_usage(stderr, argv[0]);
            return 2;
        }
        const char *domain = argv[2];
        if (argc >= 4 && strstr(argv[3], ".conf") == NULL) {
            // Standalone mode: karicheck zone <domain> <zone_file_path>
            return check_zone(domain, argv[3], true, false, NULL, NULL, NULL, NULL);
        } else {
            // From config: karicheck zone <domain> [config_path]
            const char *cfg_path = (argc >= 4) ? argv[3] : default_config;
            server_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            if (check_config(cfg_path, &cfg) != 0) return 1;

            // Normalize domain for comparison (config parser adds trailing dot)
            char norm_domain[256];
            normalize_domain_fqdn(domain, norm_domain, sizeof(norm_domain));

            /* 同じゾーン名が複数の view にあれば、それぞれの view の定義を検査する (R-26) */
            int found = 0;
            int failed = 0;
            for (view_config_t *v = cfg.views; v; v = v->next) {
                for (zone_config_t *z = v->zones; z; z = z->next) {
                    if (strcasecmp(z->domain, norm_domain) != 0) continue;
                    found++;
                    if (z->type && strcasecmp(z->type, "program") == 0) {
                        printf("[INFO] Zone '%s' is type 'program'; skipping file validation.\n", z->domain);
                    } else if (check_zone(z->domain, z->file, false, z->is_catalog, zext(z)->file_format, z, &cfg, v) != 0) {
                        failed++;
                    }
                    break;
                }
            }
            if (found == 0) {
                fprintf(stderr, "[ERROR] Zone '%s' not found in config %s\n", domain, cfg_path);
                return 1;
            }
            return failed > 0 ? 1 : 0;
        }
    } else if (strcmp(cmd, "db") == 0) {
        /* db [view] [config_path]: one argument is the configuration when it looks like a path, else a view */
        const char *view = NULL, *cfg_path = default_config;
        if (argc > 4) {
            print_usage(stderr, argv[0]);
            return 2;
        }
        if (argc == 4) {
            view = argv[2];
            cfg_path = argv[3];
        } else if (argc == 3) {
            if (strchr(argv[2], '/') || (strlen(argv[2]) > 5 && strcmp(argv[2] + strlen(argv[2]) - 5, ".conf") == 0)) cfg_path = argv[2];
            else view = argv[2];
        }
        return kc_db_main(cfg_path, view);
    } else {
        print_usage(stderr, argv[0]);
        return 2;
    }
    return 0;
}
