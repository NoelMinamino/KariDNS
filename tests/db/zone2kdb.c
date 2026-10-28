/*
 * zone2kdb.c - test tool for tests/run_db_dump_test.sh (beta design 8.2, milestone B3).
 *
 *   zone2kdb --ref OUT --list LIST [--default-ttl N] zonefile...
 *       Reads the zone files, converts every one the way the reader does it for rows held in memory (zone2sql rows ->
 *       pdns_zone_add_record() ... pdns_zone_finish() -> pdns_zone_encode_kdb()) and writes the stream "karidns-dbloader --dump" must write for
 *       a SQLite database made from the same files by zone2sql: HELLO (driver sqlite3, pid 0), BATCH_BEGIN, one zone
 *       per file in the order given (source id = 1, 2, ... = the domains.id the import gives), BATCH_END.  A file the
 *       zone parser, zone2sql or the reader cannot take, a tinydns file, a non-IN zone or a zone name seen before is
 *       skipped with a "SKIP" line; LIST gets the names of the files that went into the stream, one per line.
 *   zone2kdb --compare A B
 *       Compares two streams message by message and names the zone and the message of the first difference.
 *       Exit status 0 = identical.
 *   zone2kdb --extract STREAM NAME
 *       Writes the messages ZONE_BEGIN .. ZONE_END of zone NAME (with or without the trailing dot, any case) of a stream
 *       to standard output; exit status 1 if the stream has no such zone.
 *   zone2kdb --strip-hello STREAM OUT
 *       Writes the stream without its first message (HELLO, which names the driver) to OUT: the dumps of two drivers for the
 *       same data are then identical bytes (tests/run_db_pg_sqlite_diff_test.sh).
 *
 * Not installed.  Built by `make zone2kdb`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>

#include "zone2sql.h"
#include "../../dns_pdns_reader.h"
#include "../../dns_db_stream.h"

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

typedef struct { uint8_t *p; size_t len, cap; } buf_t;

static int buf_add(void *ud, const uint8_t *msg, size_t n) {
    buf_t *b = ud;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 65536;
        while (nc < b->len + n) nc *= 2;
        uint8_t *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, msg, n);
    b->len += n;
    return 0;
}

static int enc_flush(kdb_enc_t *e, buf_t *b) {
    if (e->err) return -1;
    int rc = buf_add(b, e->buf, e->len);
    kdb_enc_reset(e);
    return rc;
}

static uint8_t *read_all(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        b = NULL;
    }
    fclose(f);
    if (b) *len = (size_t)n;
    return b;
}

static int cmd_ref(const char *out_path, const char *list_path, uint32_t default_ttl, int nfiles, char **files) {
    buf_t stream = {0}, hdr = {0};
    kdb_enc_t e;
    kdb_enc_init(&e);
    if (kdb_enc_begin(&e, KDB_T_HELLO) != 0 || kdb_enc_u16(&e, 1, KDB_VERSION) != 0 ||
        kdb_enc_str(&e, 2, KARIDNS_VERSION) != 0 || kdb_enc_str(&e, 3, "sqlite3") != 0 || kdb_enc_u32(&e, 4, 0) != 0 ||
        kdb_enc_end(&e) != 0 || enc_flush(&e, &hdr) != 0 ||
        kdb_enc_begin(&e, KDB_T_BATCH_BEGIN) != 0 || kdb_enc_u64(&e, 1, 1) != 0 ||
        kdb_enc_u8(&e, 2, KDB_BATCH_STARTUP) != 0 || kdb_enc_u64(&e, 3, 0) != 0 || kdb_enc_end(&e) != 0 ||
        enc_flush(&e, &hdr) != 0) {
        fprintf(stderr, "zone2kdb: cannot encode the header\n");
        return 2;
    }
    FILE *list = fopen(list_path, "w");
    if (!list) {
        fprintf(stderr, "zone2kdb: cannot create %s\n", list_path);
        return 2;
    }
    char **seen = calloc((size_t)nfiles + 1, sizeof(char *));
    size_t n_seen = 0;
    pdns_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.default_ttl = default_ttl;
    for (int i = 0; i < nfiles; i++) {
        char apex[DNS_NAME_TEXT_SIZE], err[500];
        zone_arena_t fa;
        if (!z2s_load_zone_file(files[i], NULL, &fa, apex, sizeof(apex), err, sizeof(err))) {
            printf("SKIP %s: the zone parser rejects it (%s)\n", files[i], err);
            continue;
        }
        bool non_in = false;
        for (size_t k = 0; k < fa.count; k++)
            if (fa.records[k].class_val > 1) non_in = true;
        if (fa.is_tinydns_format || non_in) {
            printf("SKIP %s: %s\n", files[i], fa.is_tinydns_format ? "tinydns data" : "non-IN class records");
            zone_arena_destroy(&fa);
            continue;
        }
        z2s_rows_t rows;
        if (!z2s_rows_from_arena(&fa, apex, &rows, err, sizeof(err))) {
            printf("SKIP %s: zone2sql cannot represent it (%s)\n", files[i], err);
            zone_arena_destroy(&fa);
            continue;
        }
        bool dup = false;
        for (size_t k = 0; k < n_seen; k++)
            if (strcasecmp(seen[k], rows.zone) == 0) dup = true;
        if (dup) {
            printf("SKIP %s: zone %s was already taken from another file\n", files[i], rows.zone);
            z2s_rows_free(&rows);
            zone_arena_destroy(&fa);
            continue;
        }
        pdns_zone_t *z = pdns_zone_new(rows.zone, &opts);
        /* the metadata zone2sql writes for a presigned zone (PRESIGNED, NSEC3PARAM), so the reader rebuilds the chain */
        db_meta_row_t meta[2];
        size_t nmeta = 0;
        if (rows.presigned) meta[nmeta++] = (db_meta_row_t){ 1, "PRESIGNED", "1" };
        if (rows.nsec3param) meta[nmeta++] = (db_meta_row_t){ 1, "NSEC3PARAM", rows.nsec3param };
        int rc = z ? 0 : -1;
        for (size_t k = 0; rc == 0 && k < rows.n; k++)
            if (pdns_zone_add_record(z, &rows.rows[k]) != 0) rc = -1;
        for (size_t k = 0; rc == 0 && k < nmeta; k++)
            if (pdns_zone_add_meta(z, &meta[k]) != 0) rc = -1;
        if (rc == 0 && z2s_feed_ext(&rows, z) != 0) rc = -1;        // B8: tags, tinydns attributes, tag definitions
        if (rc == 0) rc = pdns_zone_finish(z);
        buf_t zb = {0};
        char why[400] = "";
        if (rc == 0) {
            pdns_kdb_params_t p = { 0, (int64_t)n_seen + 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL };
            rc = pdns_zone_encode_kdb(z, &p, buf_add, &zb, why, sizeof(why));
        } else if (z) {
            snprintf(why, sizeof(why), "%s", z->error);
        }
        if (rc != 0) {
            printf("SKIP %s: the reader refuses it (%s)\n", files[i], why);
            free(zb.p);
        } else {
            if (buf_add(&stream, zb.p, zb.len) != 0) {
                fprintf(stderr, "zone2kdb: out of memory\n");
                return 2;
            }
            free(zb.p);
            seen[n_seen] = strdup(rows.zone);
            n_seen++;
            fprintf(list, "%s\n", files[i]);
            printf("  [ OK ] %s: zone %s\n", files[i], rows.zone);
        }
        pdns_zone_free(z);
        z2s_rows_free(&rows);
        zone_arena_destroy(&fa);
    }
    fclose(list);
    if (kdb_enc_begin(&e, KDB_T_BATCH_END) != 0 || kdb_enc_u64(&e, 1, 1) != 0 || kdb_enc_u32(&e, 2, (uint32_t)n_seen) != 0 ||
        kdb_enc_u32(&e, 3, 0) != 0 || kdb_enc_u32(&e, 4, 0) != 0 || kdb_enc_end(&e) != 0 || enc_flush(&e, &stream) != 0) {
        fprintf(stderr, "zone2kdb: cannot encode BATCH_END\n");
        return 2;
    }
    FILE *out = fopen(out_path, "wb");
    if (!out || fwrite(hdr.p, 1, hdr.len, out) != hdr.len || fwrite(stream.p, 1, stream.len, out) != stream.len ||
        fclose(out) != 0) {
        fprintf(stderr, "zone2kdb: cannot write %s\n", out_path);
        return 2;
    }
    printf("%zu zones in the reference stream\n", n_seen);
    for (size_t k = 0; k < n_seen; k++) free(seen[k]);
    free(seen);
    free(hdr.p);
    free(stream.p);
    kdb_enc_free(&e);
    return n_seen ? 0 : 2;
}

/* ---- compare */
typedef struct { size_t off, len; uint16_t type; } msg_t;

static size_t split(const uint8_t *p, size_t n, msg_t *out, size_t cap) {
    size_t k = 0, o = 0;
    while (o + KDB_HEADER_LEN <= n && k < cap) {
        uint32_t bl = ((uint32_t)p[o + 8] << 24) | ((uint32_t)p[o + 9] << 16) | ((uint32_t)p[o + 10] << 8) | p[o + 11];
        if (o + KDB_HEADER_LEN + bl > n) break;
        out[k].off = o;
        out[k].len = KDB_HEADER_LEN + bl;
        out[k].type = (uint16_t)((p[o + 4] << 8) | p[o + 5]);
        k++;
        o += KDB_HEADER_LEN + bl;
    }
    return o == n ? k : (size_t)-1;
}

static int cmd_compare(const char *pa, const char *pb) {
    size_t la = 0, lb = 0;
    uint8_t *a = read_all(pa, &la), *b = read_all(pb, &lb);
    if (!a || !b) {
        fprintf(stderr, "zone2kdb: cannot read %s\n", a ? pb : pa);
        return 2;
    }
    if (la == lb && memcmp(a, b, la) == 0) {
        printf("identical (%zu bytes)\n", la);
        return 0;
    }
    enum { MAXM = 1 << 20 };
    msg_t *ma = malloc(MAXM * sizeof(msg_t)), *mb = malloc(MAXM * sizeof(msg_t));
    size_t na = split(a, la, ma, MAXM), nb = split(b, lb, mb, MAXM);
    if (na == (size_t)-1 || nb == (size_t)-1) {
        printf("DIFFERENT: %s is not a well framed stream\n", na == (size_t)-1 ? pa : pb);
        return 1;
    }
    char zone[DNS_NAME_TEXT_SIZE] = "(before the first zone)";
    size_t i;
    for (i = 0; i < na && i < nb; i++) {
        if (ma[i].type == KDB_T_ZONE_BEGIN) {       /* the zone name of the message about to be compared */
            static uint8_t body[KDB_MAX_BODY];
            kdb_framer_t f;
            kdb_framer_init(&f, KDB_FROM_LOADER, body, sizeof(body));
            kdb_frame_t fr;
            kdb_msg_t m;
            char why[KDB_REASON_LEN];
            if (kdb_framer_feed(&f, a + ma[i].off, ma[i].len) == KDB_OK && kdb_framer_next(&f, &fr) == KDB_OK &&
                kdb_decode(&fr, KDB_VIEWS_ANY, &m, why, sizeof(why)) == KDB_OK)
                snprintf(zone, sizeof(zone), "%s", m.u.zone_begin.name);
        }
        if (ma[i].len != mb[i].len || memcmp(a + ma[i].off, b + mb[i].off, ma[i].len) != 0) {
            printf("DIFFERENT: message %zu (type %u, zone %s) differs: %zu vs %zu bytes\n", i, ma[i].type, zone, ma[i].len,
                   mb[i].len);
            return 1;
        }
    }
    printf("DIFFERENT: %s has %zu messages, %s has %zu (after zone %s)\n", pa, na, pb, nb, zone);
    return 1;
}

/* B10: the stream without its first message (HELLO names the driver, which is the one difference between the dumps of two
 * drivers), written to OUT */
static int cmd_strip_hello(const char *path, const char *outp) {
    size_t n = 0;
    uint8_t *a = read_all(path, &n);
    if (!a) {
        fprintf(stderr, "zone2kdb: cannot read %s\n", path);
        return 2;
    }
    enum { MAXM = 1 << 20 };
    msg_t *m = malloc(MAXM * sizeof(msg_t));
    size_t nm = split(a, n, m, MAXM);
    if (nm == (size_t)-1 || nm < 1 || m[0].type != KDB_T_HELLO) {
        fprintf(stderr, "zone2kdb: %s is not a stream that starts with HELLO\n", path);
        return 2;
    }
    FILE *out = fopen(outp, "wb");
    if (!out || fwrite(a + m[0].len, 1, n - m[0].len, out) != n - m[0].len || fclose(out) != 0) {
        fprintf(stderr, "zone2kdb: cannot write %s\n", outp);
        return 2;
    }
    free(m);
    free(a);
    return 0;
}

static bool zone_begin_name(const uint8_t *msg, size_t len, char *name, size_t cap) {
    static uint8_t body[KDB_MAX_BODY];
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_LOADER, body, sizeof(body));
    kdb_frame_t fr;
    kdb_msg_t m;
    char why[KDB_REASON_LEN];
    if (kdb_framer_feed(&f, msg, len) != KDB_OK || kdb_framer_next(&f, &fr) != KDB_OK ||
        kdb_decode(&fr, KDB_VIEWS_ANY, &m, why, sizeof(why)) != KDB_OK || m.type != KDB_T_ZONE_BEGIN)
        return false;
    snprintf(name, cap, "%s", m.u.zone_begin.name);
    return true;
}

static bool same_zone(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 1 && a[la - 1] == '.') la--;
    if (lb > 1 && b[lb - 1] == '.') lb--;
    return la == lb && strncasecmp(a, b, la) == 0;
}

static int cmd_extract(const char *path, const char *want) {
    size_t n = 0;
    uint8_t *a = read_all(path, &n);
    if (!a) {
        fprintf(stderr, "zone2kdb: cannot read %s\n", path);
        return 2;
    }
    enum { MAXM = 1 << 20 };
    msg_t *m = malloc(MAXM * sizeof(msg_t));
    size_t nm = split(a, n, m, MAXM);
    if (nm == (size_t)-1) {
        fprintf(stderr, "zone2kdb: %s is not a well framed stream\n", path);
        return 2;
    }
    for (size_t i = 0; i < nm; i++) {
        char name[DNS_NAME_TEXT_SIZE];
        if (m[i].type != KDB_T_ZONE_BEGIN || !zone_begin_name(a + m[i].off, m[i].len, name, sizeof(name)) || !same_zone(name, want))
            continue;
        for (size_t j = i; j < nm; j++) {
            fwrite(a + m[j].off, 1, m[j].len, stdout);
            if (m[j].type == KDB_T_ZONE_END) return 0;
        }
        return 1;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--compare") == 0) return cmd_compare(argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "--extract") == 0) return cmd_extract(argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "--strip-hello") == 0) return cmd_strip_hello(argv[2], argv[3]);
    const char *out = NULL, *list = NULL;
    uint32_t ttl = 0;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "--ref") == 0 && i + 1 < argc) out = argv[++i];
        else if (strcmp(argv[i], "--list") == 0 && i + 1 < argc) list = argv[++i];
        else if (strcmp(argv[i], "--default-ttl") == 0 && i + 1 < argc) ttl = (uint32_t)strtoul(argv[++i], NULL, 10);
        else break;
    }
    if (!out || !list || i >= argc) {
        fprintf(stderr, "usage: zone2kdb --ref OUT --list LIST [--default-ttl N] zonefile...\n"
                        "       zone2kdb --compare A B\n"
                        "       zone2kdb --extract STREAM ZONE\n"
                        "       zone2kdb --strip-hello STREAM OUT\n");
        return 2;
    }
    return cmd_ref(out, list, ttl, argc - i, argv + i);
}
