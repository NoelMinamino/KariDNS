/*
 * test_zone_image.c - S5 Phase B-0: the compact zone image (dns_zone_image.c).
 *
 * Checks, for every zone file under tests/zones/ and for synthetic zones (one RR of as many types as the parser
 * accepts, mixed-case owners, NSEC / NSEC3 chains, tinydns time stamps and locations):
 *  - builder -> image -> image_serialize_rr() is byte-equal to serialize_dns_record() for the same RR sequence in
 *    the same message with the same compress_ctx_t: status, offset, bytes and the compression table after every RR,
 *    with and without a context, with an owner override and with TTL overrides, for 512 / 1232 / 65535 octet
 *    messages (full messages start a new one), and for every message size from "header only" to "one octet more
 *    than needed" (so the -1 / fits decision is the same at every boundary), also behind a primed context;
 *  - the decoding accessors agree with the text fields of the builder record;
 *  - name lookup, canonical order, NSEC order, NSEC3 chains and the glue list equal what build_zone_index() made;
 *  - thaw(freeze(x)) holds records equal to x (compare_records and field by field), and freezing the thawed builder
 *    gives the same RRs, RDATA, extras and answer bytes.
 * Expected values come from the builder (the code the image replaces) and from the RFCs, never from the image.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../dns_wire.h"
#include "../dns_utils.h"
#include "../dns_zone_parser.h"
#include "../dns_zone_image.h"
#include "../dns_tsig_acl.h"
#include "../dns_cidr.h"
#include "zone_image_walk.h"
#include <sys/wait.h>

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s  (%s)\n", __FILE__, __LINE__, #cond, g_label); } } while (0)
static const char *g_label = "";

/* ------------------------------------------------------------------------------------------------ loading */
typedef struct {
    zone_arena_t a;
    bool ok;
    char *root_ttl, *root_ecs, *root_loc;
} zone_t;

static char *load_file_cb(parse_context_t *ctx, const char *path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    if (out_dev) *out_dev = st.st_dev;
    if (out_ino) *out_ino = st.st_ino;
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[n] = '\0';
    return buf;
}

static char *read_whole(const char *path) {
    return load_file_cb(NULL, path, NULL, NULL);
}

static void silent_report(const dns_record_t *rec, void *ud) { (void)rec; (void)ud; }

/* Load like reload_master_zone(): parse, drop out-of-zone and unencodable records, shrink, index. */
static bool load_zone(zone_t *z, const char *text, const char *origin, const char *base_dir, bool tinydns) {
    memset(z, 0, sizeof(*z));
    zone_arena_init(&z->a);
    char *visited_paths[16] = { 0 };
    dev_t visited_devs[16] = { 0 };
    ino_t visited_inos[16] = { 0 };
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base_dir = base_dir ? base_dir : ".";
    ctx.default_origin = origin;
    ctx.is_standalone_mode = true;
    ctx.err_out = &err;
    ctx.visited_paths = visited_paths;
    ctx.visited_devs = visited_devs;
    ctx.visited_inos = visited_inos;
    ctx.visited_cap = 16;
    ctx.load_file_cb = load_file_cb;
    ctx.shared_ttl_io = &z->root_ttl;
    ctx.shared_ecs_tag_io = &z->root_ecs;
    ctx.shared_loc_tag_io = &z->root_loc;
    char *buf = arena_strdup(&z->a, text);
    if (!buf) return false;
    int rc = tinydns ? parse_tinydns_data(buf, strlen(buf), &z->a, &ctx) : parse_zone_fast(buf, strlen(buf), &z->a, &ctx);
    if (rc < 0) { zone_arena_destroy(&z->a); return false; }
    zone_arena_drop_out_of_zone(&z->a, origin, silent_report, NULL);
    zone_arena_drop_unencodable(&z->a, silent_report, NULL);
    zone_arena_shrink_records(&z->a);
    if (build_zone_index(&z->a, true) != 0) { zone_arena_destroy(&z->a); return false; }
    z->ok = true;
    return true;
}

static void free_zone(zone_t *z) {
    if (z->ok || z->a.records) zone_arena_destroy(&z->a);
    z->ok = false;
}

/* ------------------------------------------------------------------------------------------------ reference values */
static uint16_t ref_class(const dns_record_t *r) {
    uint16_t c = r->class_val;
    if (c == 0) {
        c = 1;
        if (r->class_str) {
            if (strcasecmp(r->class_str, "CH") == 0) c = 3;
            else if (strcasecmp(r->class_str, "NONE") == 0) c = 254;
            else if (strcasecmp(r->class_str, "ANY") == 0) c = 255;
        }
    }
    return c;
}
static uint32_t ref_ttl(const dns_record_t *r) {
    uint32_t t = r->ttl_value;
    if (t == 0 && r->ttl && *r->ttl) t = parse_ttl_value(r->ttl);
    if (t > 0x7FFFFFFF) t = 0x7FFFFFFF;
    return t;
}

/* record index -> image RR index: the contract is "RRs of one owner contiguous, in builder (file) order" */
static uint32_t *map_records(const zone_arena_t *a, const zone_image_t *img) {
    uint32_t *map = malloc((a->count ? a->count : 1) * sizeof(uint32_t));
    uint32_t *used = calloc(img->n_names ? img->n_names : 1, sizeof(uint32_t));
    if (!map || !used) { free(map); free(used); return NULL; }
    for (size_t i = 0; i < a->count; i++) {
        map[i] = ZONE_IMAGE_NONE;
        const dns_record_t *r = &a->records[i];
        if (!r->name) continue;
        uint32_t id = zone_image_find_name(img, r->name);
        if (id == ZONE_IMAGE_NONE) { CHECK(!"owner not found"); continue; }
        uint32_t k = zone_image_name_first_rr(img, id) + used[id]++;
        if (used[id] > zone_image_name_rr_count(img, id)) { CHECK(!"too many RRs for the owner"); continue; }
        map[i] = k;
    }
    free(used);
    return map;
}

/* ------------------------------------------------------------------------------------------------ serialization parity */
typedef struct {
    uint8_t buf[65536];
    compress_ctx_t ctx;
    uint16_t off;
} msg_t;

static msg_t g_A, g_B;

static void msg_reset(msg_t *m) {
    memset(m->buf, 0, 12);
    m->off = 12;
    compress_ctx_init_packet(&m->ctx);
}

enum { MODE_PLAIN, MODE_OWNER, MODE_NOCTX, MODE_TTL, MODE_TTLMIN };

static const char *OWNER_OVERRIDE = "Qn.Wild.Example.Org.";

/* One RR through both writers; true when both agreed. */
static bool step_rr(const zone_image_t *img, const dns_record_t *rec, uint32_t k, size_t max, int mode, unsigned salt) {
    msg_t *A = &g_A, *B = &g_B;
    compress_ctx_t *ca = A->ctx.current_generation ? &A->ctx : NULL;
    compress_ctx_t *cb = B->ctx.current_generation ? &B->ctx : NULL;
    if (mode == MODE_NOCTX) { ca = NULL; cb = NULL; }
    const char *owner = (mode == MODE_OWNER) ? OWNER_OVERRIDE : NULL;
    dns_record_t cp = *rec;
    uint32_t ovr = 0xFFFFFFFFu;
    uint32_t ttl_img = zone_image_rr_ttl(img, k);
    if (mode == MODE_TTL) {
        cp.ttl_value = 1 + (salt * 7919u) % 100000u;
        ttl_img = cp.ttl_value;
    } else if (mode == MODE_TTLMIN) {
        ovr = 30 + salt % 5000u;
        if (ovr < ttl_img) ttl_img = ovr;
    }
    for (int attempt = 0; attempt < 2; attempt++) {
        uint16_t oa = A->off, ob = B->off;
        if (mode == MODE_NOCTX) { oa = ob = 12; }
        int ra = serialize_dns_record(A->buf, max, &oa, &cp, ca, owner, ovr);
        int rb = image_serialize_rr(img, k, B->buf, max, &ob, cb, owner, ttl_img);
        if (ra != rb) {
            CHECK(ra == rb);
            printf("    rr %u type %u owner %s: serialize=%d image=%d max=%zu\n", k, rec->type_code, rec->name, ra, rb, max);
            return false;
        }
        if (ra == 0) {
            uint16_t start = (mode == MODE_NOCTX) ? 12 : A->off;
            CHECK(oa == ob);
            bool same = oa == ob && memcmp(A->buf + start, B->buf + start, (size_t)(oa - start)) == 0;
            CHECK(same);
            if (!same) {
                printf("    rr %u type %u owner %s differs\n", k, rec->type_code, rec->name);
                return false;
            }
            if (ca && cb) {
                bool t = memcmp(A->ctx.table, B->ctx.table, sizeof(A->ctx.table)) == 0;
                CHECK(t);
                if (!t) return false;
            }
            if (mode != MODE_NOCTX) { A->off = oa; B->off = ob; }
            return true;
        }
        /* did not fit (or cannot be written): both agreed; start a new message and try once more */
        if (mode == MODE_NOCTX) return true;
        msg_reset(A);
        msg_reset(B);
        ca = &A->ctx;
        cb = &B->ctx;
    }
    return true;
}

static void pass_sequence(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map, size_t max, int mode) {
    msg_reset(&g_A);
    msg_reset(&g_B);
    for (size_t i = 0; i < a->count; i++) {
        if (map[i] == ZONE_IMAGE_NONE) continue;
        if (!step_rr(img, &a->records[i], map[i], max, mode, (unsigned)i)) break;
    }
}

/* Every message size around one RR: the fits / does-not-fit decision and the bytes must agree, also when the
 * context already holds the names of the RR written before it (compression pointers). */
static void pass_boundary(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map, size_t limit) {
    static uint8_t ra_buf[65536], rb_buf[65536];
    static compress_ctx_t ca, cb;
    size_t done = 0, prev = (size_t)-1;
    for (size_t i = 0; i < a->count && done < limit; i++) {
        if (map[i] == ZONE_IMAGE_NONE) continue;
        const dns_record_t *rec = &a->records[i];
        uint32_t k = map[i];
        for (int primed = 0; primed < 2; primed++) {
            if (primed && prev == (size_t)-1) continue;
            /* reference length at a large size */
            compress_ctx_init(&ca);
            uint16_t base = 12, tmp;
            if (primed) {
                tmp = base;
                if (serialize_dns_record(ra_buf, 65535, &tmp, &a->records[prev], &ca, NULL, 0xFFFFFFFFu) != 0) continue;
                base = tmp;
            }
            uint16_t full = base;
            if (serialize_dns_record(ra_buf, 65535, &full, rec, &ca, NULL, 0xFFFFFFFFu) != 0) continue;
            size_t len = (size_t)(full - base);
            if (len > 700) continue;
            for (size_t m = (size_t)base; m <= (size_t)full + 1; m++) {
                compress_ctx_init(&ca);
                compress_ctx_init(&cb);
                uint16_t oa = 12, ob = 12;
                if (primed) {
                    CHECK(serialize_dns_record(ra_buf, 65535, &oa, &a->records[prev], &ca, NULL, 0xFFFFFFFFu) == 0);
                    CHECK(image_serialize_rr(img, map[prev], rb_buf, 65535, &ob, &cb, NULL, zone_image_rr_ttl(img, map[prev])) == 0);
                }
                uint16_t sa = oa, sb = ob;
                int x = serialize_dns_record(ra_buf, m, &oa, rec, &ca, NULL, 0xFFFFFFFFu);
                int y = image_serialize_rr(img, k, rb_buf, m, &ob, &cb, NULL, zone_image_rr_ttl(img, k));
                CHECK(x == y);
                /* exact fit: the RR is written in a message of exactly its size and in none one octet smaller
                 * (no padding allowance in either implementation) */
                CHECK((x == 0) == (m >= (size_t)full));
                if (x != y || (x == 0) != (m >= (size_t)full)) {
                    printf("    boundary: rr %u type %u size %zu (%zu..%zu): serialize=%d image=%d\n", k, rec->type_code, m,
                           (size_t)base, (size_t)full, x, y);
                    return;
                }
                if (x == 0) {
                    CHECK(oa == ob && memcmp(ra_buf + sa, rb_buf + sb, (size_t)(oa - sa)) == 0);
                    CHECK(memcmp(ca.table, cb.table, sizeof(ca.table)) == 0);
                }
            }
        }
        prev = i;
        done++;
    }
}

/* ------------------------------------------------------------------------------------------------ accessors */
static void check_name_eq(const char *got, const char *want) {
    CHECK(got != NULL && want != NULL && domain_names_match_ci(got, want));
}

static bool bitmap_matches_text(const zone_image_t *img, uint32_t k, const dns_record_t *r, int first_text) {
    /* every listed type is in the bitmap; the bitmap has no other type */
    bool seen[65536];
    memset(seen, 0, sizeof(seen));
    for (int i = first_text; i < r->rdata_count; i++) {
        if (!r->rdata[i]) continue;
        uint16_t code = get_type_code(r->rdata[i]);
        if (code == 0) continue;
        seen[code] = true;
        if (!zone_image_rr_bitmap_has(img, k, code)) return false;
    }
    for (unsigned t = 1; t < 65536; t++)
        if (!seen[t] && zone_image_rr_bitmap_has(img, k, (uint16_t)t)) return false;
    return true;
}

static void check_accessors(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map) {
    char buf[DNS_NAME_TEXT_SIZE], buf2[DNS_NAME_TEXT_SIZE];
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (map[i] == ZONE_IMAGE_NONE) continue;
        uint32_t k = map[i];
        CHECK(zone_image_rr_type(img, k) == r->type_code);
        CHECK(zone_image_rr_class(img, k) == ref_class(r));
        CHECK(zone_image_rr_ttl(img, k) == ref_ttl(r));
        check_name_eq(zone_image_name_text(img, zone_image_rr_name(img, k)), r->name);
        bool has_text = r->rdata_count > 0;
        switch (r->type_code) {
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 23: case 39:
            if (!has_text) break;
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
            check_name_eq(buf, r->rdata[0]);
            break;
        case 15: {
            if (r->rdata_count < 2) break;
            uint16_t pref = 0;
            CHECK(zone_image_mx_pref(img, k, &pref) == 0 && pref == (uint16_t)strtoul(r->rdata[0], NULL, 10));
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
            check_name_eq(buf, r->rdata[1]);
            break;
        }
        case 33: {
            if (r->rdata_count < 4) break;
            uint16_t p, w, po;
            CHECK(zone_image_srv(img, k, &p, &w, &po) == 0);
            CHECK(p == strtoul(r->rdata[0], NULL, 10) && w == strtoul(r->rdata[1], NULL, 10) &&
                  po == strtoul(r->rdata[2], NULL, 10));
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
            check_name_eq(buf, r->rdata[3]);
            break;
        }
        case 6: {
            if (r->rdata_count < 7) break;
            zone_image_soa_t n;
            CHECK(zone_image_soa(img, k, buf, sizeof(buf), buf2, sizeof(buf2), &n) == 0);
            check_name_eq(buf, r->rdata[0]);
            check_name_eq(buf2, r->rdata[1]);
            CHECK(n.serial == strtoul(r->rdata[2], NULL, 10));
            CHECK(n.refresh == parse_ttl_value(r->rdata[3]) && n.retry == parse_ttl_value(r->rdata[4]) &&
                  n.expire == parse_ttl_value(r->rdata[5]) && n.minimum == parse_ttl_value(r->rdata[6]));
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
            check_name_eq(buf, r->rdata[0]);
            break;
        }
        case 24: case 46: {
            if (r->rdata_count < 9) break;
            uint16_t tc = 0;
            CHECK(zone_image_rrsig_covered(img, k, &tc) == 0 && tc == get_type_code(r->rdata[0]));
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
            check_name_eq(buf, r->rdata[7]);
            break;
        }
        case 47: {
            if (r->rdata_count < 1) break;
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
            check_name_eq(buf, r->rdata[0]);
            CHECK(bitmap_matches_text(img, k, r, 1));
            break;
        }
        case 50: case 51: {
            if (r->rdata_count < (r->type_code == 50 ? 5 : 4)) break;
            zone_image_nsec3_t v;
            CHECK(zone_image_nsec3(img, k, &v) == 0);
            CHECK(v.algorithm == strtoul(r->rdata[0], NULL, 10) && v.flags == strtoul(r->rdata[1], NULL, 10) &&
                  v.iterations == strtoul(r->rdata[2], NULL, 10));
            uint8_t salt[255];
            size_t sl = hex_to_bytes(r->rdata[3], salt, sizeof(salt));
            CHECK(sl == v.salt_len && (sl == 0 || memcmp(salt, v.salt, sl) == 0));
            if (r->type_code == 50) {
                char b32[128];
                dns_base32hex_encode(v.next, v.next_len, b32, sizeof(b32));
                CHECK(strcasecmp(b32, r->rdata[4]) == 0);
                CHECK(bitmap_matches_text(img, k, r, 5));
            }
            break;
        }
        default:
            break;
        }
        /* the layout table says the names of the types in it are uncompressed and complete */
        const dns_rdata_name_layout_t *lay = dns_rdata_name_layout(r->type_code);
        if (lay && zone_image_rr_rdlen(img, k) > lay->skip) {
            CHECK(zone_image_rr_target(img, k, buf, sizeof(buf)) == 0);
        }
    }
}

/* ------------------------------------------------------------------------------------------------ indexes */
static void check_names(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map) {
    size_t live = 0;
    for (size_t i = 0; i < a->count; i++) if (a->records[i].name) live++;
    CHECK(img->n_rrs == live);
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (!r->name) continue;
        uint32_t id = zone_image_find_name(img, r->name);
        CHECK(id != ZONE_IMAGE_NONE);
        if (id == ZONE_IMAGE_NONE) continue;
        /* case-insensitive, with and without the root dot */
        char up[DNS_NAME_TEXT_SIZE];
        size_t n = strlen(r->name);
        if (n < sizeof(up) - 2) {
            for (size_t j = 0; j <= n; j++) up[j] = (char)((r->name[j] >= 'a' && r->name[j] <= 'z') ? r->name[j] - 32 : r->name[j]);
            CHECK(zone_image_find_name(img, up) == id);
            size_t bare = dns_name_len_no_root(r->name, n);
            if (bare != n && bare > 0) {
                char t[DNS_NAME_TEXT_SIZE];
                memcpy(t, r->name, bare);
                t[bare] = '\0';
                CHECK(zone_image_find_name(img, t) == id);
            } else if (bare == n) {
                memcpy(up, r->name, n);
                up[n] = '.';
                up[n + 1] = '\0';
                CHECK(zone_image_find_name(img, up) == id);
            }
        }
        CHECK(zone_image_rr_name(img, map[i]) == id);
    }
    CHECK(zone_image_find_name(img, "this-name-is-not-in-the-zone.invalid.") == ZONE_IMAGE_NONE);
    /* RRset iteration: the RRs of (name, type) in file order (a sample on big zones: the count is quadratic) */
    size_t stride = a->count > 20000 ? a->count / 200 : 1;
    for (size_t i = 0; i < a->count; i += stride) {
        const dns_record_t *r = &a->records[i];
        if (!r->name || map[i] == ZONE_IMAGE_NONE) continue;
        uint32_t id = zone_image_rr_name(img, map[i]);
        uint32_t it = zone_image_rrset_next(img, id, r->type_code, zone_image_name_first_rr(img, id));
        size_t want = 0, got = 0;
        for (size_t j = 0; j < a->count; j++)
            if (a->records[j].name && a->records[j].type_code == r->type_code && domain_names_match_ci(a->records[j].name, r->name)) want++;
        while (it != ZONE_IMAGE_NONE) { got++; it = zone_image_rrset_next(img, id, r->type_code, it + 1); }
        CHECK(got == want);
    }
    /* flags */
    for (uint32_t id = 0; id < img->n_names; id++) {
        const char *t = zone_image_name_text(img, id);
        bool wc = t[0] == '*' && t[1] == '.';
        CHECK(((zone_image_name_flags(img, id) & ZONE_IMAGE_NAME_WILDCARD) != 0) == wc);
        CHECK(((zone_image_name_flags(img, id) & ZONE_IMAGE_NAME_APEX) != 0) == (id == img->apex_name));
    }
}

/* how many probes a quadratic scan may run: at most 400, and about 5 million comparisons in total */
static size_t scan_budget(size_t n) { size_t b = n ? 5000000 / n : 400; return b > 400 ? 400 : (b < 8 ? 8 : b); }

static void check_canon(const zone_arena_t *a, const zone_image_t *img) {
    CHECK(img->n_canon == a->sorted_unique_count);
    for (size_t i = 0; i < a->sorted_unique_count && i < img->n_canon; i++)
        CHECK(compare_canonical_name(a->sorted_unique_names[i], zone_image_name_text(img, zone_image_canon_name(img, (uint32_t)i))) == 0);
    for (uint32_t pos = 0; pos < img->n_canon; pos++)
        CHECK(zone_image_names(img)[zone_image_canon_name(img, pos)].canon_rank == pos);
    /* floor against a linear scan of the builder's order */
    static const char *probes[] = { "a.", "zzzz.zzzz.", "0.", "*.", "\\000.", "mail.", "www.", "_tcp.", "~." };
    const size_t scan_cap = scan_budget(a->sorted_unique_count);
    for (size_t i = 0; i < a->sorted_unique_count; i++) {
        char probe[DNS_NAME_TEXT_SIZE];
        for (int v = 0; v < 4; v++) {
            const char *base = a->sorted_unique_names[i];
            if (v == 0) snprintf(probe, sizeof(probe), "%s", base);
            else if (v == 1) snprintf(probe, sizeof(probe), "a.%s", base);
            else if (v == 2) snprintf(probe, sizeof(probe), "zz.%s", base);
            else snprintf(probe, sizeof(probe), "%s", probes[i % (sizeof(probes) / sizeof(probes[0]))]);
            uint32_t want = ZONE_IMAGE_NONE;
            bool want_exact = false;
            for (size_t j = 0; j < a->sorted_unique_count; j++) {
                int c = compare_canonical_name(a->sorted_unique_names[j], probe);
                if (c <= 0) { want = (uint32_t)j; want_exact = (c == 0); }
            }
            bool exact = false;
            uint32_t got = zone_image_canon_floor(img, probe, &exact);
            CHECK(got == want);
            CHECK(exact == want_exact);
        }
        if (i >= scan_cap) break; /* the scan is quadratic */
    }
}

static void check_nsec(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map) {
    (void)map;
    CHECK(img->n_nsec == a->nsec_count);
    for (size_t i = 0; i < a->nsec_count && i < img->n_nsec; i++) {
        uint32_t rr = zone_image_nsec_rr(img, (uint32_t)i);
        CHECK(zone_image_rr_type(img, rr) == 47);
        check_name_eq(zone_image_name_text(img, zone_image_rr_name(img, rr)), a->nsec_records[i]->name);
    }
    for (size_t i = 0; i < a->nsec_count && i < (size_t)scan_budget(a->nsec_count); i++) {
        char probe[DNS_NAME_TEXT_SIZE];
        for (int v = 0; v < 3; v++) {
            if (v == 0) snprintf(probe, sizeof(probe), "%s", a->nsec_records[i]->name);
            else if (v == 1) snprintf(probe, sizeof(probe), "a.%s", a->nsec_records[i]->name);
            else snprintf(probe, sizeof(probe), "\\000.%s", a->nsec_records[i]->name);
            uint32_t want = ZONE_IMAGE_NONE;
            for (size_t j = 0; j < a->nsec_count; j++)
                if (compare_canonical_name(a->nsec_records[j]->name, probe) <= 0) want = (uint32_t)j;
            CHECK(zone_image_nsec_floor(img, probe) == want);
        }
    }
}

static void check_nsec3(const zone_arena_t *a, const zone_image_t *img) {
    CHECK(img->n_n3chains == a->nsec3_chain_count);
    for (size_t c = 0; c < a->nsec3_chain_count && c < img->n_n3chains; c++) {
        const nsec3_chain_t *ch = &a->nsec3_chains[c];
        const zone_image_n3chain_t *ic = zone_image_n3chain(img, (uint32_t)c);
        CHECK(ic->algorithm == ch->algorithm && ic->iterations == ch->iterations && ic->count == ch->count);
        uint8_t salt[255];
        size_t sl = hex_to_bytes(ch->salt, salt, sizeof(salt));
        CHECK(sl == ic->salt_len && (sl == 0 || memcmp(salt, zone_image_bytes(img, ic->salt_off), sl) == 0));
        CHECK(zone_image_n3chain_find(img, ch->algorithm, ch->iterations, salt, sl) == c);
        for (size_t e = 0; e < ch->count && e < ic->count; e++) {
            size_t hl;
            const char *h = zone_image_n3chain_hash(img, (uint32_t)c, (uint32_t)e, &hl);
            CHECK(hl == ch->entries[e].hash_len && strncasecmp(h, ch->entries[e].hash, hl) == 0);
            uint32_t rr = zone_image_n3chain_rr(img, (uint32_t)c, (uint32_t)e);
            check_name_eq(zone_image_name_text(img, zone_image_rr_name(img, rr)), ch->entries[e].rec->name);
            CHECK(zone_image_rr_type(img, rr) == 50);
        }
        /* lower bound against a linear scan, for every owner hash and for hashes between them */
        for (size_t e = 0; e < ch->count && e < (size_t)scan_budget(ch->count); e++) {
            char target[80];
            for (int v = 0; v < 3; v++) {
                memcpy(target, ch->entries[e].hash, ch->entries[e].hash_len);
                target[ch->entries[e].hash_len] = '\0';
                if (v == 1 && ch->entries[e].hash_len > 0) target[ch->entries[e].hash_len - 1] = 'V';
                if (v == 2) strcat(target, "0");
                size_t tl = strlen(target), want = ch->count;
                for (size_t j = 0; j < ch->count; j++) {
                    size_t mn = ch->entries[j].hash_len < tl ? ch->entries[j].hash_len : tl;
                    int cm = strncasecmp(ch->entries[j].hash, target, mn);
                    if (cm == 0) cm = ch->entries[j].hash_len < tl ? -1 : (ch->entries[j].hash_len > tl ? 1 : 0);
                    if (cm >= 0) { want = j; break; }
                }
                CHECK(zone_image_n3chain_lower_bound(img, (uint32_t)c, target, tl) == want);
            }
        }
    }
    /* the parameters the denial proofs use */
    const nsec3_params_t *p = &a->nsec3_active;
    if (!p->param) {
        CHECK(img->n3_param_rr == ZONE_IMAGE_NONE);
    } else {
        CHECK(img->n3_param_rr != ZONE_IMAGE_NONE);
        if (img->n3_param_rr != ZONE_IMAGE_NONE) {
            CHECK(zone_image_rr_type(img, img->n3_param_rr) == 51);
            check_name_eq(zone_image_name_text(img, zone_image_rr_name(img, img->n3_param_rr)), p->param->name);
        }
        CHECK(img->n3_algorithm == p->algorithm && img->n3_iterations == p->iterations && img->n3_salt_len == p->salt_len);
        CHECK(p->salt_len == 0 || memcmp(zone_image_bytes(img, img->n3_salt_off), p->salt, p->salt_len) == 0);
        CHECK((p->chain == NULL) == (img->n3_chain == ZONE_IMAGE_NONE));
        if (p->chain) CHECK(img->n3_chain == (uint32_t)(p->chain - a->nsec3_chains));
    }
}

static void check_glue(const zone_arena_t *a, const zone_image_t *img) {
    if (a->count > 20000) return; /* quadratic */
    /* in-zone addresses of the NS / MX / SRV targets, in order of first appearance */
    uint32_t *want = malloc((a->count + 1) * sizeof(uint32_t));
    size_t nw = 0;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        const char *tgt = NULL;
        if (!r->name) continue;
        if (r->type_code == 2 && r->rdata_count >= 1) tgt = r->rdata[0];
        else if (r->type_code == 15 && r->rdata_count >= 2) tgt = r->rdata[1];
        else if (r->type_code == 33 && r->rdata_count >= 4) tgt = r->rdata[3];
        if (!tgt || !*tgt) continue;
        uint32_t id = zone_image_find_name(img, tgt);
        if (id == ZONE_IMAGE_NONE) continue;
        bool dup = false, addr = false;
        for (size_t j = 0; j < nw; j++) if (want[j] == id) dup = true;
        for (size_t j = 0; j < a->count; j++)
            if (a->records[j].name && (a->records[j].type_code == 1 || a->records[j].type_code == 28) &&
                domain_names_match_ci(a->records[j].name, tgt)) addr = true;
        if (!dup && addr) want[nw++] = id;
    }
    CHECK(img->n_glue == nw);
    for (size_t i = 0; i < nw && i < img->n_glue; i++) CHECK(zone_image_glue_name(img, (uint32_t)i) == want[i]);
    free(want);
}

/* B-1 engine hints: ZONE_IMAGE_F_WILDCARD / F_DNAME and the per-name ZONE_IMAGE_NAME_GLUE (the owners of the first 256
 * distinct NS / MX / SRV targets, as prelink_zone_additional_glue() collects them, that have A or AAAA RRs here). */
static void check_flags(const zone_arena_t *a, const zone_image_t *img) {
    bool wild = false, dname = false;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (!r->name) continue;
        if (r->name[0] == '*' && r->name[1] == '.') wild = true;
        if (r->type_code == 39) dname = true;
    }
    CHECK(((img->flags & ZONE_IMAGE_F_WILDCARD) != 0) == wild);
    CHECK(((img->flags & ZONE_IMAGE_F_DNAME) != 0) == dname);
    /* E3: ZONE_IMAGE_F_CUT iff some RR other than the apex's own has type NS */
    bool cut = false;
    for (uint32_t k = 0; k < img->n_rrs; k++)
        if (zone_image_rr_type(img, k) == 2 && zone_image_rr_name(img, k) != img->apex_name) cut = true;
    CHECK(((img->flags & ZONE_IMAGE_F_CUT) != 0) == cut);
    for (uint32_t id = 0; id < img->n_names; id++)
        CHECK(((zone_image_name_flags(img, id) & ZONE_IMAGE_NAME_WILDCARD) != 0) ==
              (zone_image_name_text(img, id)[0] == '*' && zone_image_name_text(img, id)[1] == '.'));
    if (a->count > 20000) return; /* quadratic */
    uint8_t *want = calloc(img->n_names + 1, 1);
    const char *prelink[256];
    int np = 0;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        const char *tgt = NULL;
        if (!r->name) continue;
        if (r->type_code == 2 && r->rdata_count >= 1) tgt = r->rdata[0];
        else if (r->type_code == 15 && r->rdata_count >= 2) tgt = r->rdata[1];
        else if (r->type_code == 33 && r->rdata_count >= 4) tgt = r->rdata[3];
        if (!tgt || !*tgt) continue;
        bool dup = false;
        for (int k = 0; k < np; k++) if (domain_names_match_ci(prelink[k], tgt)) dup = true;
        if (dup || np >= 256) continue;
        prelink[np++] = tgt;
        uint32_t id = zone_image_find_name(img, tgt);
        if (id == ZONE_IMAGE_NONE) continue;
        for (uint32_t k = zone_image_name_first_rr(img, id), e = k + zone_image_name_rr_count(img, id); k < e; k++)
            if (zone_image_rr_type(img, k) == 1 || zone_image_rr_type(img, k) == 28) want[id] = 1;
    }
    for (uint32_t id = 0; id < img->n_names; id++)
        CHECK(((zone_image_name_flags(img, id) & ZONE_IMAGE_NAME_GLUE) != 0) == (want[id] != 0));
    free(want);
}

static void check_ext(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map) {
    /* ZONE_IMAGE_F_VIEW: set iff some RR is restricted (an ext[] entry that only keeps an owner spelling does not count; a
     * standard IXFR of such a zone stays incremental) */
    bool restricted = false;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (map[i] != ZONE_IMAGE_NONE && (r->tinydns_ttd || r->tinydns_ttl_countdown || r->tinydns_loc[0] || r->tinydns_loc[1] ||
                                          r->ecs_subnet_tag || r->bind_location_tag))
            restricted = true;
    }
    CHECK(((img->flags & ZONE_IMAGE_F_VIEW) != 0) == restricted);
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (map[i] == ZONE_IMAGE_NONE) continue;
        const zone_image_ext_t *e = zone_image_rr_ext(img, map[i]);
        bool alt = strcmp(r->name, zone_image_name_text(img, zone_image_rr_name(img, map[i]))) != 0;
        bool need = alt || r->tinydns_ttd || r->tinydns_ttl_countdown || r->tinydns_loc[0] || r->tinydns_loc[1] ||
                    r->ecs_subnet_tag || r->bind_location_tag;
        CHECK((e != NULL) == need);
        if (!e || !need) continue;
        CHECK(e->ttd == (int64_t)r->tinydns_ttd);
        CHECK(((e->flags & ZONE_IMAGE_EXT_COUNTDOWN) != 0) == r->tinydns_ttl_countdown);
        CHECK(e->loc[0] == r->tinydns_loc[0] && e->loc[1] == r->tinydns_loc[1]);
        CHECK((e->ecs_tag_off != 0) == (r->ecs_subnet_tag != NULL));
        if (e->ecs_tag_off && r->ecs_subnet_tag) CHECK(strcmp(zone_image_str(img, e->ecs_tag_off), r->ecs_subnet_tag) == 0);
        CHECK((e->loc_tag_off != 0) == (r->bind_location_tag != NULL));
        if (e->loc_tag_off && r->bind_location_tag) CHECK(strcmp(zone_image_str(img, e->loc_tag_off), r->bind_location_tag) == 0);
        CHECK((e->alt_text_off != 0) == alt);
        if (alt) CHECK(strcmp(zone_image_str(img, e->alt_text_off), r->name) == 0);
    }
}

/* ------------------------------------------------------------------------------------------------ thaw */
static bool str_eq(const char *x, const char *y) { return (x == NULL && y == NULL) || (x && y && strcmp(x, y) == 0); }

static void check_tags(const ecs_tag_def_t *x, int nx, const ecs_tag_def_t *y, int ny) {
    CHECK(nx == ny);
    for (int i = 0; i < nx && i < ny; i++) {
        CHECK(str_eq(x[i].tag, y[i].tag));
        CHECK(x[i].cidr_count == y[i].cidr_count);
        for (int j = 0; j < x[i].cidr_count && j < y[i].cidr_count; j++) {
            CHECK(str_eq(x[i].cidrs[j].cidr, y[i].cidrs[j].cidr));
            CHECK(memcmp(&x[i].cidrs[j].parsed, &y[i].cidrs[j].parsed, sizeof(cidr_entry_t)) == 0);
        }
    }
}

static void check_thaw(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map, const char *apex) {
    zone_arena_t b;
    zone_arena_init(&b);
    int rc = zone_image_thaw(img, &b);
    CHECK(rc == 0);
    if (rc != 0) { zone_arena_destroy(&b); return; }
    CHECK(b.count == img->n_rrs);
    size_t seq = 0; /* S5 B-2: thaw gives the records back in file order (tombstones leave no gap) */
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *x = &a->records[i];
        if (map[i] == ZONE_IMAGE_NONE) continue;
        if (seq >= b.count) { CHECK(false); break; }
        const dns_record_t *y = &b.records[seq++];
        CHECK(compare_records(x, y, true));
        CHECK(str_eq(x->name, y->name));
        CHECK(y->type_code == x->type_code && y->class_val == ref_class(x) && y->ttl_value == ref_ttl(x));
        CHECK(y->tinydns_ttd == x->tinydns_ttd && y->tinydns_ttl_countdown == x->tinydns_ttl_countdown &&
              y->tinydns_loc[0] == x->tinydns_loc[0] && y->tinydns_loc[1] == x->tinydns_loc[1]);
        CHECK(str_eq(y->ecs_subnet_tag, x->ecs_subnet_tag) && str_eq(y->bind_location_tag, x->bind_location_tag));
        /* the same answer bytes */
        static uint8_t ba[8192], bb[8192];
        uint16_t oa = 0, ob = 0;
        int ra = serialize_dns_record(ba, sizeof(ba), &oa, x, NULL, NULL, 0xFFFFFFFFu);
        int rb = serialize_dns_record(bb, sizeof(bb), &ob, y, NULL, NULL, 0xFFFFFFFFu);
        CHECK(ra == rb && oa == ob && memcmp(ba, bb, oa) == 0);      /* D17-4: every type keeps the case as written, MINFO too */
        compress_ctx_t c1, c2;
        compress_ctx_init(&c1);
        compress_ctx_init(&c2);
        oa = ob = 12;
        ra = serialize_dns_record(ba, sizeof(ba), &oa, x, &c1, NULL, 0xFFFFFFFFu);
        rb = serialize_dns_record(bb, sizeof(bb), &ob, y, &c2, NULL, 0xFFFFFFFFu);
        CHECK(ra == rb && oa == ob && memcmp(ba, bb, oa) == 0);
    }
    CHECK(b.is_tinydns_format == a->is_tinydns_format);
    CHECK(b.location_count == a->location_count);
    if (b.location_count == a->location_count && a->location_count > 0)
        CHECK(memcmp(b.locations, a->locations, sizeof(tinydns_location_entry_t) * (size_t)a->location_count) == 0);
    check_tags(a->bind_location_tags, a->bind_location_tag_count, b.bind_location_tags, b.bind_location_tag_count);
    check_tags(a->bind_ecs_tags, a->bind_ecs_tag_count, b.bind_ecs_tags, b.bind_ecs_tag_count);
    CHECK(a->bind_ecs_trusted_resolver_count == b.bind_ecs_trusted_resolver_count);
    for (int i = 0; i < a->bind_ecs_trusted_resolver_count && i < b.bind_ecs_trusted_resolver_count; i++)
        CHECK(str_eq(a->bind_ecs_trusted_resolvers[i], b.bind_ecs_trusted_resolvers[i]));
    CHECK((a->bind_ecs_trusted_resolvers_parsed == NULL) == (b.bind_ecs_trusted_resolvers_parsed == NULL));
    /* the thawed builder has the same indexes */
    CHECK(b.sorted_unique_count == a->sorted_unique_count);
    CHECK(b.nsec_count == a->nsec_count);
    CHECK(b.nsec3_chain_count == a->nsec3_chain_count);
    CHECK((b.nsec3_active.param == NULL) == (a->nsec3_active.param == NULL));

    /* freeze again: same RRs, RDATA, extras and answer bytes */
    zone_image_t *img2 = zone_image_freeze(&b, apex);
    CHECK(img2 != NULL);
    if (img2) {
        CHECK(zone_image_validate(img2, img2->total_size, NULL, 0) == 0);   /* what thaw + freeze make is an image too */
        CHECK(img2->n_names == img->n_names && img2->n_rrs == img->n_rrs && img2->n_ext == img->n_ext &&
              img2->n_canon == img->n_canon && img2->n_nsec == img->n_nsec && img2->n_n3chains == img->n_n3chains &&
              img2->n_n3entries == img->n_n3entries && img2->n_glue == img->n_glue);
        for (uint32_t k = 0; k < img->n_rrs && k < img2->n_rrs; k++) {
            CHECK(zone_image_rr_type(img, k) == zone_image_rr_type(img2, k) && zone_image_rr_class(img, k) == zone_image_rr_class(img2, k) &&
                  zone_image_rr_ttl(img, k) == zone_image_rr_ttl(img2, k));
            CHECK(zone_image_rr_rdlen(img, k) == zone_image_rr_rdlen(img2, k) &&
                  (zone_image_rr_rdlen(img, k) == 0 || memcmp(zone_image_rr_rdata(img, k), zone_image_rr_rdata(img2, k), zone_image_rr_rdlen(img, k)) == 0));
            CHECK(strcmp(zone_image_name_text(img, zone_image_rr_name(img, k)), zone_image_name_text(img2, zone_image_rr_name(img2, k))) == 0);
            const zone_image_ext_t *e1 = zone_image_rr_ext(img, k), *e2 = zone_image_rr_ext(img2, k);
            CHECK((e1 == NULL) == (e2 == NULL));
            if (e1 && e2) {
                CHECK(e1->ttd == e2->ttd && e1->flags == e2->flags && e1->loc[0] == e2->loc[0] && e1->loc[1] == e2->loc[1]);
                CHECK(str_eq(zone_image_str(img, e1->ecs_tag_off), zone_image_str(img2, e2->ecs_tag_off)));
                CHECK(str_eq(zone_image_str(img, e1->loc_tag_off), zone_image_str(img2, e2->loc_tag_off)));
                CHECK(str_eq(zone_image_str(img, e1->alt_text_off), zone_image_str(img2, e2->alt_text_off)));
            }
        }
        for (uint32_t p = 0; p < img->n_canon && p < img2->n_canon; p++)
            CHECK(strcasecmp(zone_image_name_text(img, zone_image_canon_name(img, p)), zone_image_name_text(img2, zone_image_canon_name(img2, p))) == 0);
        for (uint32_t i = 0; i < img->n_nsec && i < img2->n_nsec; i++)
            CHECK(zone_image_nsec_rr(img, i) == zone_image_nsec_rr(img2, i));
        for (uint32_t i = 0; i < img->n_glue && i < img2->n_glue; i++)
            CHECK(zone_image_glue_name(img, i) == zone_image_glue_name(img2, i));
        CHECK(img2->apex_name == img->apex_name && img2->flags == img->flags && img2->zattr_len == img->zattr_len);
        /* answers from the two images are the same bytes */
        msg_reset(&g_A);
        msg_reset(&g_B);
        for (uint32_t k = 0; k < img->n_rrs && k < img2->n_rrs; k++) {
            uint16_t oa = g_A.off, ob = g_B.off;
            int ra = image_serialize_rr(img, k, g_A.buf, 1232, &oa, &g_A.ctx, NULL, zone_image_rr_ttl(img, k));
            int rb = image_serialize_rr(img2, k, g_B.buf, 1232, &ob, &g_B.ctx, NULL, zone_image_rr_ttl(img2, k));
            CHECK(ra == rb && oa == ob && memcmp(g_A.buf + g_A.off, g_B.buf + g_B.off, (size_t)(oa - g_A.off)) == 0);
            if (ra != 0) { msg_reset(&g_A); msg_reset(&g_B); } else { g_A.off = oa; g_B.off = ob; }
        }
        zone_image_free(img2);
    }
    zone_arena_destroy(&b);
}

/* S5 B-2: the zone level tables read in place from the image (accessors) equal the builder's */
static void check_zattr(const zone_arena_t *a, const zone_image_t *img) {
    int n = 0;
    const tinydns_location_entry_t *l = zone_image_locations(img, &n);
    CHECK(n == (a->locations ? a->location_count : 0));
    if (n > 0 && n == a->location_count) CHECK(memcmp(l, a->locations, (size_t)n * sizeof(*l)) == 0);
    CHECK(zone_image_has_zattr(img) == (a->location_count > 0 || a->bind_location_tag_count > 0 || a->bind_ecs_tag_count > 0 ||
                                        a->bind_ecs_trusted_resolver_count > 0));
    for (int kind = 0; kind < 2; kind++) {
        const ecs_tag_def_t *tags = kind == 0 ? a->bind_location_tags : a->bind_ecs_tags;
        int nt = tags ? (kind == 0 ? a->bind_location_tag_count : a->bind_ecs_tag_count) : 0;
        zone_image_tags_t it;
        zone_image_tags_open(img, kind == 0 ? ZONE_IMAGE_TAGS_LOCATION : ZONE_IMAGE_TAGS_ECS, &it);
        CHECK((int)it.left == nt);
        zone_image_tag_t t;
        int i = 0;
        while (zone_image_tags_next(&it, &t)) {
            CHECK(i < nt);
            if (i >= nt) break;
            CHECK(str_eq(t.tag, tags[i].tag) && (int)t.cidr_count == tags[i].cidr_count);
            const char *c;
            cidr_entry_t p;
            int j = 0;
            while (zone_image_tag_next_cidr(&t, &c, &p)) {
                CHECK(j < tags[i].cidr_count);
                if (j >= tags[i].cidr_count) break;
                CHECK(str_eq(c, tags[i].cidrs[j].cidr) && memcmp(&p, &tags[i].cidrs[j].parsed, sizeof(p)) == 0);
                j++;
            }
            CHECK(j == tags[i].cidr_count);
            i++;
        }
        CHECK(i == nt);
    }
    int ntr = 0;
    const acl_entry_t *acl = zone_image_ecs_trusted(img, &ntr);
    CHECK(ntr == (a->bind_ecs_trusted_resolvers ? a->bind_ecs_trusted_resolver_count : 0));
    CHECK((acl != NULL) == (ntr > 0) && ((uintptr_t)acl % 8) == 0);
}

/* S5 B-2: file order (zone_image_seq_rr) = the builder's record order, tombstones left out */
static void check_seq(const zone_arena_t *a, const zone_image_t *img, const uint32_t *map) {
    uint32_t seq = 0;
    for (size_t i = 0; i < a->count; i++) {
        if (map[i] == ZONE_IMAGE_NONE) continue;
        CHECK(seq < img->n_rrs && zone_image_seq_rr(img, seq) == map[i]);
        seq++;
    }
    CHECK(seq == img->n_rrs);
    CHECK(((img->flags & ZONE_IMAGE_F_PERM) != 0) == (img->off_perm != 0));
}


/* ------------------------------------------------------------------------------------------------ zone_image_validate()
 * The store reads images back from disk and the readers dereference offsets unchecked, so a block that validates must be
 * safe to read.  Three kinds of test:
 *  - every image zone_image_freeze() makes validates (check_zone() calls check_validate() for every zone of this file);
 *  - hand-made damage (one field at a time, see val_targeted()) is rejected; each case asserts that the block is not
 *    accepted, whatever the reader would have done with it;
 *  - a sweep of single byte changes and cut-off copies: a mutant is rejected or, when accepted, walked by every reader
 *    in walk_image() (under ASan the exact-size copy makes any read outside the block an error) and its lookups must
 *    still find every name where the hash table says it is. */
static unsigned long g_val_rejected, g_val_accepted, g_val_images, g_val_cases;

static uint8_t *dup_block(const void *p, size_t n) {
    uint8_t *m = malloc(n ? n : 1);   /* exactly n octets: ASan sees a read past the end */
    if (m && n) memcpy(m, p, n);
    return m;
}

static unsigned long walk_image(const zone_image_t *img) {
    unsigned bad = 0;
    unsigned long sink = zimg_walk(img, &bad);
    CHECK(bad == 0);
    return sink;
}

/* one damaged copy: not accepted (the original is put back) */
typedef struct { uint8_t *orig, *m; size_t n; const char *label; } vt_t;
static void vt_reject(vt_t *t, const char *what, unsigned long idx) {
    char why[200] = "";
    int r = zone_image_validate(t->m, t->n, why, sizeof(why));
    g_checks++;
    g_val_cases++;
    if (r == 0) {
        g_failed++;
        printf("  [FAIL] damaged image is accepted: %s %lu  (%s)\n", what, idx, t->label);
    } else {
        g_val_rejected++;
        if (why[0] == '\0') { g_failed++; printf("  [FAIL] no reason for: %s %lu  (%s)\n", what, idx, t->label); }
    }
    memcpy(t->m, t->orig, t->n);
}
#define MUT(what, idx, ...) do { __VA_ARGS__; vt_reject(&t, what, (unsigned long)(idx)); } while (0)

static void val_targeted(const zone_image_t *img) {
    const size_t n = img->total_size;
    vt_t t = { dup_block(img, n), dup_block(img, n), n, g_label };
    if (!t.orig || !t.m) { free(t.orig); free(t.m); CHECK(!"memory"); return; }
    uint8_t *m = t.m;
    zone_image_t *H = (zone_image_t *)(void *)m;
#define SEC(type, off) ((type *)(void *)(m + (off)))
    zone_image_name_t *N = SEC(zone_image_name_t, H->off_names);
    zone_image_rr_t *R = SEC(zone_image_rr_t, H->off_rrs);
    zone_image_ext_t *E = SEC(zone_image_ext_t, H->off_ext);
    zone_image_n3chain_t *C3 = SEC(zone_image_n3chain_t, H->off_n3chains);
    uint32_t *HT = SEC(uint32_t, H->off_hash), *CA = SEC(uint32_t, H->off_canon), *NS = SEC(uint32_t, H->off_nsec);
    uint32_t *N3E = SEC(uint32_t, H->off_n3entries), *GL = SEC(uint32_t, H->off_glue);
    uint32_t *PM = H->off_perm ? SEC(uint32_t, H->off_perm) : NULL;
    uint8_t *Z = m + H->off_zattr;
    const size_t slen = n - H->off_strings;
    const uint32_t nn = H->n_names, nr = H->n_rrs;
    const uint32_t ids[3] = { 0, nn / 2, nn ? nn - 1 : 0 };
    const uint32_t rids[3] = { 0, nr / 2, nr ? nr - 1 : 0 };

    /* header */
    MUT("magic", 0, H->magic ^= 1);
    MUT("version", 0, H->version = 2);
    MUT("total_size+8", 0, H->total_size += 8);
    MUT("total_size-8", 0, H->total_size -= 8);
    MUT("reserved", 0, H->reserved_ = 1);
    MUT("unknown flag", 0, H->flags |= 0x200);
    MUT("unknown flag 31", 0, H->flags |= 0x80000000u);
    for (unsigned b = 1; b < 9; b++) MUT("image flag toggled", b, H->flags ^= 1u << b);
    {
        uint32_t *cnt[] = { &H->n_names, &H->n_rrs, &H->n_ext, &H->n_canon, &H->n_n3chains, &H->hash_size, &H->zattr_len };
        for (size_t i = 0; i < sizeof(cnt) / sizeof(cnt[0]); i++) {
            MUT("count+1", i, *cnt[i] += 1);
            MUT("count+8", i, *cnt[i] += 8);
            if (*cnt[i]) MUT("count-1", i, *cnt[i] -= 1);
            MUT("count huge", i, *cnt[i] = 0xFFFFFFFFu);
        }
        uint32_t *small[] = { &H->n_nsec, &H->n_n3entries, &H->n_glue };   /* +-1 can stay inside the 8-byte padding */
        for (size_t i = 0; i < sizeof(small) / sizeof(small[0]); i++) {
            MUT("count+8", i, *small[i] += 8);
            MUT("count huge", i, *small[i] = 0xFFFFFFFFu);
            MUT("count 0x7FFFFFFF", i, *small[i] = 0x7FFFFFFFu);
        }
        uint32_t *offs[] = { &H->off_names, &H->off_rrs, &H->off_ext, &H->off_hash, &H->off_canon, &H->off_nsec, &H->off_n3chains,
                             &H->off_n3entries, &H->off_glue, &H->off_zattr, &H->off_strings };
        for (size_t i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
            MUT("offset+8", i, *offs[i] += 8);
            MUT("offset-8", i, *offs[i] -= 8);
            MUT("offset 0", i, *offs[i] = 0);
            MUT("offset huge", i, *offs[i] = 0xFFFFFFF8u);
        }
        MUT("off_perm set", 0, H->off_perm = H->off_perm ? 0 : H->off_zattr; H->flags ^= ZONE_IMAGE_F_PERM);
        MUT("off_perm only", 0, H->off_perm = H->off_perm ? 0 : H->off_zattr);
    }
    MUT("apex_name out of range", 0, H->apex_name = nn);
    if (nn > 1) MUT("apex_name elsewhere", 0, H->apex_name = H->apex_name == 0 ? 1 : 0);
    if (nn && H->apex_name == ZONE_IMAGE_NONE) MUT("apex_name from none", 0, H->apex_name = 0);
    if (H->n3_param_rr == ZONE_IMAGE_NONE) {
        MUT("n3_chain without param", 0, H->n3_chain = 0);
        MUT("n3 iterations without param", 0, H->n3_iterations = 1);
        MUT("n3 salt without param", 0, H->n3_salt_off = 8);
    } else {
        MUT("n3_param_rr range", 0, H->n3_param_rr = nr);
        MUT("n3 iterations", 0, H->n3_iterations ^= 1);
        MUT("n3 algorithm", 0, H->n3_algorithm ^= 1);
        MUT("n3 salt_len", 0, H->n3_salt_len ^= 1);
        MUT("n3_chain range", 0, H->n3_chain = H->n_n3chains);
        if (H->n3_salt_len) MUT("n3 salt_off", 0, H->n3_salt_off = (uint32_t)slen);
        if (H->n3_chain != ZONE_IMAGE_NONE) MUT("n3_chain none", 0, H->n3_chain = H->n3_chain == 0 && H->n_n3chains > 1 ? 1 : H->n_n3chains);
    }

    /* names */
    for (int q = 0; q < 3 && nn; q++) {
        uint32_t i = ids[q];
        MUT("name first_rr+1", i, N[i].first_rr += 1);
        MUT("name first_rr huge", i, N[i].first_rr = 0xFFFFFFFFu);
        MUT("name count+1", i, N[i].rr_count_flags += 1);
        MUT("name count 0", i, N[i].rr_count_flags &= ~ZONE_IMAGE_NAME_COUNT_MASK);
        MUT("name count huge", i, N[i].rr_count_flags |= ZONE_IMAGE_NAME_COUNT_MASK);
        MUT("name flag 31", i, N[i].rr_count_flags |= 0x80000000u);
        for (unsigned b = 24; b < 31; b++)
            if (b != 29) MUT("name flag toggled", i * 100 + b, N[i].rr_count_flags ^= 1u << b);
        if (!(N[i].rr_count_flags & ZONE_IMAGE_NAME_GLUE) ) {
            /* a name that is not a glue target cannot be flagged unless it has an address RR and is in the list: a name
             * without an address RR is rejected for sure */
            bool has_addr = false;
            for (uint32_t k = N[i].first_rr; k < N[i].first_rr + (N[i].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK); k++)
                if (R[k].type == 1 || R[k].type == 28) has_addr = true;
            if (!has_addr) MUT("glue flag without address", i, N[i].rr_count_flags |= ZONE_IMAGE_NAME_GLUE);
        }
        MUT("name text_off 0", i, N[i].text_off = 0);
        MUT("name text_off padding", i, N[i].text_off = 4);
        MUT("name text_off end", i, N[i].text_off = (uint32_t)slen);
        MUT("name text_off huge", i, N[i].text_off = 0xFFFFFFFFu);
        MUT("name wire_off padding", i, N[i].wire_off = 4);
        MUT("name wire_off huge", i, N[i].wire_off = 0xFFFFFFFFu);
        MUT("name wire_off = text", i, N[i].wire_off = N[i].text_off);
        MUT("name hash", i, N[i].hash ^= 1);
        MUT("name canon_rank", i, N[i].canon_rank = nn);
        MUT("name canon_rank none", i, N[i].canon_rank = ZONE_IMAGE_NONE);
        MUT("name text edited", i, m[H->off_strings + N[i].text_off] ^= 0x05);   /* another letter: the hash no longer fits */
        {
            /* the text without its terminator: the NUL of the name becomes a letter (the next string runs into it) */
            size_t tl = strlen((const char *)m + H->off_strings + N[i].text_off);
            MUT("name text unterminated", i, m[H->off_strings + N[i].text_off + tl] = 'x');
        }
    }
    /* RRs */
    for (int q = 0; q < 3 && nr; q++) {
        uint32_t k = rids[q];
        MUT("rr name_id+1", k, R[k].name_id += 1);
        MUT("rr name_id range", k, R[k].name_id = nn);
        MUT("rr name_id huge", k, R[k].name_id = 0xFFFFFFFFu);
        MUT("rr ttl", k, R[k].ttl = 0x80000000u);
        MUT("rr flags", k, R[k].flags |= 0x4);
        MUT("rr rdata_len max", k, R[k].rdata_len = 65535);
        MUT("rr rdata_off huge", k, R[k].rdata_off = 0xFFFFFFFFu);
        if (R[k].rdata_len) {
            MUT("rr rdata_off 0", k, R[k].rdata_off = 0);
            MUT("rr rdata_off padding", k, R[k].rdata_off = 4);
            MUT("rr rdata past the end", k, R[k].rdata_off = (uint32_t)(slen - R[k].rdata_len + 1));
        } else {
            MUT("rr rdata_off without length", k, R[k].rdata_off = 8);
        }
        MUT("rr ext_idx past n_ext", k, R[k].ext_idx = H->n_ext + 1);
        MUT("rr ext_idx huge", k, R[k].ext_idx = 0xFFFFFFFFu);
        if (R[k].ext_idx == 0) MUT("rr ext_idx unexpected", k, R[k].ext_idx = 1; );
    }
    for (uint32_t k = 0; k < nr && k < 400; k++) {
        /* a name the RR types write one by one: NS, CNAME, PTR, MX end with the name, so cutting a byte leaves no whole name */
        if ((R[k].flags & ZONE_IMAGE_RR_RAW) || R[k].rdata_len < 2) continue;
        if (R[k].type == 2 || R[k].type == 5 || R[k].type == 12 || R[k].type == 15) {
            MUT("rr name cut off", k, R[k].rdata_len -= 1);
            break;
        }
    }
    /* ext[] */
    if (H->n_ext) {
        MUT("ext flags", 0, E[0].flags |= 0x80);
        MUT("ext pad", 0, E[0].pad = 1);
        MUT("ext ecs_tag_off end", 0, E[0].ecs_tag_off = (uint32_t)slen);
        MUT("ext loc_tag_off padding", 0, E[0].loc_tag_off = 4);
        MUT("ext alt_text_off end", 0, E[0].alt_text_off = (uint32_t)slen);
        MUT("ext alt_text_off huge", 0, E[0].alt_text_off = 0xFFFFFFFFu);
        if (!E[0].alt_text_off) MUT("ext alt_wire_off alone", 0, E[0].alt_wire_off = 8);
        if (!E[0].ecs_tag_off) MUT("ext ecs_tag_off text unterminated", 0, E[0].ecs_tag_off = (uint32_t)slen - 1; m[n - 1] = 'x');
    }
    /* the hash table */
    if (nn) {
        size_t a = 0, b = 0;
        for (size_t i = 0; i < H->hash_size; i++) if (HT[i]) { if (!a) a = i + 1; else if (!b) b = i + 1; }
        MUT("hash slot emptied", a - 1, HT[a - 1] = 0);
        MUT("hash slot out of range", a - 1, HT[a - 1] = nn + 1);
        if (b) {
            MUT("hash name twice", b - 1, HT[b - 1] = HT[a - 1]);
        }
        MUT("hash table full", 0, for (size_t i = 0; i < H->hash_size; i++) if (!HT[i]) HT[i] = 1);
        MUT("hash table without names", 0, memset(HT, 0, (size_t)H->hash_size * 4));
    }
    /* canonical order */
    if (nn) {
        MUT("canon out of range", 0, CA[0] = nn);
        MUT("canon huge", 0, CA[nn - 1] = 0xFFFFFFFFu);
    }
    if (nn > 1) {
        MUT("canon swapped", 0, uint32_t x = CA[0]; CA[0] = CA[1]; CA[1] = x);
        MUT("canon twice", 0, CA[1] = CA[0]);
        /* the ranks agree with the swap, the order does not */
        MUT("canon out of order", 0, uint32_t x = CA[0]; CA[0] = CA[1]; CA[1] = x; N[CA[0]].canon_rank = 0; N[CA[1]].canon_rank = 1);
        MUT("canon last two out of order", 0, uint32_t x = CA[nn - 2]; CA[nn - 2] = CA[nn - 1]; CA[nn - 1] = x;
            N[CA[nn - 2]].canon_rank = nn - 2; N[CA[nn - 1]].canon_rank = nn - 1);
    }
    /* NSEC index */
    if (H->n_nsec) {
        MUT("nsec range", 0, NS[0] = nr);
        MUT("nsec huge", 0, NS[0] = 0xFFFFFFFFu);
        for (uint32_t k = 0; k < nr; k++)
            if (R[k].type != 47) { MUT("nsec is no NSEC", k, NS[0] = k); break; }
    }
    if (H->n_nsec > 1) {
        const char *s0 = (const char *)m + H->off_strings + N[R[NS[0]].name_id].text_off;
        const char *s1 = (const char *)m + H->off_strings + N[R[NS[H->n_nsec - 1]].name_id].text_off;
        if (strcasecmp(s0, s1) != 0) MUT("nsec reversed", 0, uint32_t x = NS[0]; NS[0] = NS[H->n_nsec - 1]; NS[H->n_nsec - 1] = x);
    }
    /* NSEC3 chains and entries */
    if (H->n_n3chains) {
        MUT("n3 chain count+1", 0, C3[0].count += 1);
        MUT("n3 chain count 0", 0, C3[0].count = 0);
        MUT("n3 chain first+1", 0, C3[0].first += 1);
        MUT("n3 chain algorithm", 0, C3[0].algorithm ^= 1);
        MUT("n3 chain iterations", 0, C3[0].iterations ^= 1);
        MUT("n3 chain salt_len", 0, C3[0].salt_len ^= 1);
        MUT("n3 chain salt_off huge", 0, C3[0].salt_off = 0xFFFFFFFFu);
        MUT("n3 chain salt_off end", 0, C3[0].salt_off = (uint32_t)slen; C3[0].salt_len = 4);
        if (C3[0].salt_len) MUT("n3 chain salt bytes", 0, m[H->off_strings + C3[0].salt_off] ^= 0x10);
        MUT("n3 entry range", 0, N3E[0] = nr);
        for (uint32_t k = 0; k < nr; k++)
            if (R[k].type != 50) { MUT("n3 entry is no NSEC3", k, N3E[0] = k); break; }
        if (C3[0].count > 1) {
            const char *l0 = (const char *)m + H->off_strings + N[R[N3E[0]].name_id].text_off;
            const char *l1 = (const char *)m + H->off_strings + N[R[N3E[1]].name_id].text_off;
            if (strncasecmp(l0, l1, strcspn(l0, ".")) != 0) MUT("n3 entries out of order", 0, uint32_t x = N3E[0]; N3E[0] = N3E[1]; N3E[1] = x);
        }
    }
    /* glue */
    if (H->n_glue) {
        MUT("glue range", 0, GL[0] = nn);
        for (uint32_t id = 0; id < nn; id++) {
            bool has_addr = false;
            for (uint32_t k = N[id].first_rr; k < N[id].first_rr + (N[id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK); k++)
                if (R[k].type == 1 || R[k].type == 28) has_addr = true;
            if (!has_addr) { MUT("glue without address", id, GL[0] = id); break; }
        }
    }
    if (H->n_glue > 1) MUT("glue twice", 0, GL[1] = GL[0]);
    /* file order */
    if (PM) {
        MUT("perm range", 0, PM[0] = nr);
        MUT("perm twice", 0, PM[1] = PM[0]);
        MUT("perm huge", 0, PM[nr - 1] = 0xFFFFFFFFu);
    }
    /* zone level tables */
    if (H->zattr_len) {
        MUT("zattr nloc huge", 0, memset(Z, 0xFF, 4));
        MUT("zattr empty", 0, memset(Z, 0, H->zattr_len));
        int nloc = 0;
        const tinydns_location_entry_t *loc = zone_image_locations(img, &nloc);
        if (nloc > 0) {
            size_t at = (size_t)((const uint8_t *)loc - (const uint8_t *)img) - H->off_zattr;
            MUT("location prefix_bits", 0, Z[at + offsetof(tinydns_location_entry_t, prefix_bits)] = 33);
        }
        /* the first parsed CIDR of a tag: find its bytes in the area */
        for (int kind = 0; kind < 2; kind++) {
            zone_image_tags_t it;
            zone_image_tag_t tg;
            zone_image_tags_open(img, kind, &it);
            bool done = false;
            while (!done && zone_image_tags_next(&it, &tg)) {
                const char *cidr;
                cidr_entry_t parsed;
                while (!done && zone_image_tag_next_cidr(&tg, &cidr, &parsed)) {
                    if (!parsed.valid || parsed.is_any) continue;
                    uint8_t *p = memmem(Z, H->zattr_len, &parsed, sizeof(parsed));
                    if (!p) continue;
                    size_t at = (size_t)(p - Z);
                    MUT("cidr valid is no bool", kind, Z[at + offsetof(cidr_entry_t, valid)] = 2);
                    MUT("cidr is_any is no bool", kind, Z[at + offsetof(cidr_entry_t, is_any)] = 7);
                    MUT("cidr prefix too long", kind, Z[at + offsetof(cidr_entry_t, prefix)] = parsed.family == AF_INET ? 33 : 129);
                    int fam = 99;
                    MUT("cidr family", kind, memcpy(Z + at + offsetof(cidr_entry_t, family), &fam, sizeof(fam)));
                    done = true;
                }
            }
        }
        int ntr = 0;
        const acl_entry_t *acl = zone_image_ecs_trusted(img, &ntr);
        if (ntr > 0) {
            size_t at = (size_t)((const uint8_t *)acl - (const uint8_t *)img) - H->off_zattr;
            MUT("acl is_deny is no bool", 0, Z[at + offsetof(acl_entry_t, is_deny)] = 2);
            MUT("acl cidr valid is no bool", 0, Z[at + offsetof(acl_entry_t, cidr) + offsetof(cidr_entry_t, valid)] = 9);
            MUT("acl padding not zero", 0, Z[at - 1] = 1; (void)0);
        }
    }
#undef SEC
    free(t.orig);
    free(t.m);
}

/* cut-off, extended and misaligned copies */
static void val_truncate(const zone_image_t *img) {
    const size_t n = img->total_size;
    char why[120];
    size_t cuts[] = { 0, 1, 4, 7, 8, sizeof(zone_image_t) - 8, sizeof(zone_image_t) - 1, sizeof(zone_image_t), sizeof(zone_image_t) + 8,
                      n / 2, n > 16 ? n - 16 : 0, n - 8, n - 1 };
    for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        if (cuts[i] >= n) continue;
        uint8_t *c = dup_block(img, cuts[i]);
        CHECK(c && zone_image_validate(c, cuts[i], why, sizeof(why)) != 0);
        free(c);
    }
    uint8_t *big = calloc(1, n + 16);
    if (big) {
        memcpy(big, img, n);
        CHECK(zone_image_validate(big, n + 8, why, sizeof(why)) != 0);    /* longer than total_size */
        CHECK(zone_image_validate(big + 1, n, why, sizeof(why)) != 0);    /* not 8-aligned */
        memmove(big + 8, big, n);
        CHECK(zone_image_validate(big + 8, n, why, sizeof(why)) == 0);    /* any 8-aligned address is fine */
        free(big);
    }
    CHECK(zone_image_validate(NULL, n, why, sizeof(why)) != 0);
    CHECK(zone_image_validate(img, n, NULL, 0) == 0);
}

/* single byte changes everywhere: rejected, or read by every reader without a fault */
static void val_sweep(const zone_image_t *img, size_t max_positions) {
    const size_t n = img->total_size;
    uint8_t *m = dup_block(img, n);
    if (!m) { CHECK(!"memory"); return; }
    size_t step = n / max_positions;
    if (step == 0) step = 1;
    static const uint8_t pat[] = { 0x01, 0x20, 0x80, 0xFF };
    char why[120];
    for (size_t pos = 0; pos < n; pos += step) {
        for (size_t p = 0; p < sizeof(pat); p++) {
            m[pos] ^= pat[p];
            if (zone_image_validate(m, n, why, sizeof(why)) == 0) {
                g_val_accepted++;
                (void)walk_image((const zone_image_t *)(const void *)m);
            } else {
                g_val_rejected++;
            }
            m[pos] ^= pat[p];
        }
    }
    free(m);
}

static void check_validate(const zone_image_t *img) {
    char why[200] = "";
    int r = zone_image_validate(img, img->total_size, why, sizeof(why));
    if (r != 0) printf("  [validate] %s: %s\n", g_label, why);
    CHECK(r == 0);
    if (r != 0) return;
    g_val_images++;
    val_truncate(img);
    val_targeted(img);
    val_sweep(img, img->n_rrs > 20000 ? 150 : 700);
}

/* ------------------------------------------------------------------------------------------------ 0.7 M3 step 1
 * deterministic freeze, zone_image_validate_ex() (the rules of the zone and of the stream), zone_image_check_limits() */

/* the same bytes whenever and wherever the image is made: a zone with every kind of zone level table, frozen twice in this process with the stack and
 * the heap dirtied in between, and in two children of a fork (another heap, another stack) */
static const char *M3_PLAIN =
    "$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.2\nwww IN TXT \"x\"\n";

static const char *M3_TEXT =
    "$ORIGIN ex.test.\n$TTL 300\n"
    "@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
    "$LOCATION-TAG office 192.0.2.0/24 198.51.100.0/24\n$ECS-SUBNET-TAG far 203.0.113.0/24 2001:db8::/32\n"
    "$LOCATION office\nwww IN A 192.0.2.10\n$LOCATION \"\"\n$ECS-SUBNET far\nwww IN A 192.0.2.20\n$ECS-SUBNET \"\"\nwww IN A 192.0.2.30\n"
    "www IN TXT \"x\"\nmail IN MX 10 www\n";

static void __attribute__((noinline)) dirty_stack(void) {
    volatile unsigned char junk[16384];
    for (size_t i = 0; i < sizeof(junk); i++) junk[i] = (unsigned char)(0xA5 ^ i);
}

static void dirty_heap(void) {
    void *p[64];
    for (int i = 0; i < 64; i++) {
        p[i] = malloc(32 + (size_t)i * 8);
        if (p[i]) memset(p[i], 0xC3, 32 + (size_t)i * 8);
    }
    for (int i = 0; i < 64; i++) free(p[i]);
}

/* the zone of M3_TEXT with ECS trusted resolvers (the list the builder of an Extended AXFR has) */
static zone_image_t *m3_det_image(void) {
    zone_t z;
    if (!load_zone(&z, M3_TEXT, "ex.test.", NULL, false)) return NULL;
    z.a.bind_ecs_trusted_resolvers = calloc(2, sizeof(char *));
    if (z.a.bind_ecs_trusted_resolvers) {
        z.a.bind_ecs_trusted_resolvers[0] = strdup("192.0.2.0/24");
        z.a.bind_ecs_trusted_resolvers[1] = strdup("!2001:db8::/32");
        z.a.bind_ecs_trusted_resolver_count = 2;
    }
    dirty_stack();
    dirty_heap();
    zone_image_t *img = zone_image_freeze(&z.a, "ex.test.");
    free_zone(&z);
    return img;
}

static void m3_determinism(void) {
    g_label = "determinism";
    zone_image_t *a = m3_det_image();
    zone_image_t *b = m3_det_image();
    CHECK(a && b && a->total_size == b->total_size && a->zattr_len > 0);
    if (a && b && a->total_size == b->total_size) CHECK(memcmp(a, b, a->total_size) == 0);
    /* every zone of the corpus, twice */
    for (int k = 0; k < 2; k++) {
        zone_t z;
        if (!load_zone(&z, M3_TEXT, "ex.test.", NULL, false)) break;
        zone_image_t *c = zone_image_freeze(&z.a, "ex.test."), *d = zone_image_freeze(&z.a, "ex.test.");
        CHECK(c && d && c->total_size == d->total_size && memcmp(c, d, c->total_size) == 0);
        zone_image_free(c);
        zone_image_free(d);
        free_zone(&z);
    }
    /* two processes */
    int fd[2];
    if (a && pipe(fd) == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            close(fd[0]);
            zone_image_t *c = m3_det_image();
            size_t n = c ? c->total_size : 0, off = 0;
            while (c && off < n) {
                ssize_t w = write(fd[1], (const uint8_t *)c + off, n - off);
                if (w <= 0) _exit(2);
                off += (size_t)w;
            }
            _exit(c ? 0 : 1);
        }
        close(fd[1]);
        uint8_t *got = malloc(a->total_size + 8);
        size_t have = 0;
        ssize_t r;
        while (got && have < a->total_size + 8 && (r = read(fd[0], got + have, a->total_size + 8 - have)) > 0) have += (size_t)r;
        close(fd[0]);
        int st = 0;
        if (pid > 0) waitpid(pid, &st, 0);
        CHECK(pid > 0 && st == 0 && got && have == a->total_size && memcmp(got, a, a->total_size) == 0);
        free(got);
    }
    zone_image_free(a);
    zone_image_free(b);
}

/* ---- zone_image_validate_ex() ---- */
static uint8_t *m3_copy(const zone_image_t *img) { return dup_block(img, img->total_size); }

static zone_image_policy_t m3_pol(const zone_image_t *img, const char *apex, uint32_t serial) {
    zone_image_policy_t p;
    memset(&p, 0, sizeof(p));
    p.apex = apex;
    p.serial = serial;
    p.rr_count = img->n_rrs;
    p.announced_size = img->total_size;
    p.extended = true;
    p.tinydns = (img->flags & ZONE_IMAGE_F_TINYDNS) != 0;
    return p;
}

static int m3_vex(const void *buf, size_t len, const zone_image_policy_t *p, char *why, size_t wl) {
    why[0] = '\0';
    return zone_image_validate_ex(buf, len, p, why, wl);
}

/* the image is refused and the reason names `what` */
#define M3_NEG(buf, len, polp, what) do { char w_[300]; int r_ = m3_vex((buf), (len), (polp), w_, sizeof(w_)); \
    CHECK(r_ != 0 && strstr(w_, (what)) != NULL); \
    if (r_ == 0 || !strstr(w_, (what))) printf("    [%s] wanted '%s', got %d '%s'\n", g_label, (what), r_, w_); } while (0)
#define M3_POS(buf, len, polp) do { char w_[300]; int r_ = m3_vex((buf), (len), (polp), w_, sizeof(w_)); \
    CHECK(r_ == 0); if (r_ != 0) printf("    [%s] refused: %s\n", g_label, w_); } while (0)

/* freeze text; origin = the apex.  keep_out_of_zone: the records outside the zone are kept (the zone parser would drop them) */
static zone_image_t *m3_image_of(const char *text, const char *apex, bool tinydns, bool keep_out_of_zone) {
    zone_t z;
    memset(&z, 0, sizeof(z));
    zone_arena_init(&z.a);
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base_dir = ".";
    ctx.default_origin = apex;
    ctx.is_standalone_mode = true;
    ctx.err_out = &err;
    ctx.shared_ttl_io = &z.root_ttl;
    ctx.shared_ecs_tag_io = &z.root_ecs;
    ctx.shared_loc_tag_io = &z.root_loc;
    char *buf = arena_strdup(&z.a, text);
    int rc = buf ? (tinydns ? parse_tinydns_data(buf, strlen(buf), &z.a, &ctx) : parse_zone_fast(buf, strlen(buf), &z.a, &ctx)) : -1;
    zone_image_t *img = NULL;
    if (rc >= 0) {
        if (!keep_out_of_zone) zone_arena_drop_out_of_zone(&z.a, apex, silent_report, NULL);
        zone_arena_drop_unencodable(&z.a, silent_report, NULL);
        zone_arena_shrink_records(&z.a);
        if (build_zone_index(&z.a, true) == 0) img = zone_image_freeze(&z.a, apex);
    }
    zone_arena_destroy(&z.a);
    return img;
}

static void m3_validate_ex(void) {
    g_label = "validate_ex";
    char why[300];
    zone_image_t *img = m3_image_of(M3_PLAIN, "ex.test.", false, false);
    CHECK(img != NULL);
    if (!img) return;
    zone_image_policy_t p = m3_pol(img, "ex.test.", 7);
    p.extended = false;
    M3_POS(img, img->total_size, &p);
    CHECK(zone_image_validate_ex(img, img->total_size, NULL, why, sizeof(why)) == 0);            /* no policy: zone_image_validate() */
    p.apex = "EX.TEST";                                                                      /* the apex: any case, with or without the root dot */
    M3_POS(img, img->total_size, &p);
    p.apex = "ex.test.";

    /* the size: announced and the limit of max-zone-bytes (also when the image is damaged: the size is looked at first) */
    zone_image_policy_t q = p;
    q.announced_size = img->total_size + 8;
    M3_NEG(img, img->total_size, &q, "announced");
    q = p; q.max_bytes = img->total_size - 8;
    M3_NEG(img, img->total_size, &q, "max-zone-bytes");
    q = p; q.max_bytes = img->total_size;
    M3_POS(img, img->total_size, &q);
    q = p; q.rr_count = img->n_rrs + 1;
    M3_NEG(img, img->total_size, &q, "declared");
    q = p; q.max_records = img->n_rrs - 1;
    M3_NEG(img, img->total_size, &q, "max-zone-records");
    q = p; q.max_records = img->n_rrs;
    M3_POS(img, img->total_size, &q);
    {   /* a damaged image is the validator's: the policy is not reached */
        uint8_t *m = m3_copy(img);
        if (m) {
            m[0] ^= 1;
            M3_NEG(m, img->total_size, &p, "magic");
            free(m);
        }
    }

    /* the zone: the apex, the owners, the class, the type */
    q = p; q.apex = "other.test.";
    M3_NEG(img, img->total_size, &q, "apex");
    q = p; q.apex = "sub.ex.test.";
    M3_NEG(img, img->total_size, &q, "apex");
    q = p; q.serial = 8;
    M3_NEG(img, img->total_size, &q, "serial");
    q = p; q.tinydns = true;
    M3_NEG(img, img->total_size, &q, "tinydns");
    {
        zone_image_t *o = m3_image_of("$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nx.other.test. IN A 192.0.2.9\n",
                                      "ex.test.", false, true);
        CHECK(o != NULL);
        if (o) {
            zone_image_policy_t po = m3_pol(o, "ex.test.", 7);
            M3_NEG(o, o->total_size, &po, "outside the zone");
            zone_image_free(o);
        }
        o = m3_image_of("$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nex.test.x. IN A 192.0.2.9\n",
                        "ex.test.", false, true);     /* "x.ex.test" is below the apex, "ex.test.x." is not (a label boundary decides) */
        CHECK(o != NULL);
        if (o) {
            zone_image_policy_t po = m3_pol(o, "ex.test.", 7);
            M3_NEG(o, o->total_size, &po, "outside the zone");
            zone_image_free(o);
        }
        o = m3_image_of("$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nsub IN SOA ns1 host 7 7200 3600 1209600 300\n",
                        "ex.test.", false, false);
        CHECK(o != NULL);
        if (o) {
            zone_image_policy_t po = m3_pol(o, "ex.test.", 7);
            M3_NEG(o, o->total_size, &po, "SOA outside the apex");
            zone_image_free(o);
        }
        o = m3_image_of("$ORIGIN ex.test.\n$TTL 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n", "ex.test.", false, false);
        CHECK(o != NULL);
        if (o) {
            zone_image_policy_t po = m3_pol(o, "ex.test.", 7);
            M3_NEG(o, o->total_size, &po, "no SOA");
            zone_image_free(o);
        }
        o = m3_image_of("$ORIGIN ex.test.\n$TTL 300\nns1 IN A 192.0.2.1\n", "ex.test.", false, false);
        CHECK(o != NULL);
        if (o) {
            zone_image_policy_t po = m3_pol(o, "ex.test.", 7);
            M3_NEG(o, o->total_size, &po, "apex");           /* no data at the apex at all */
            zone_image_free(o);
        }
        o = m3_image_of("$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nch IN CH TXT \"x\"\n",
                        "ex.test.", false, false);
        if (o) {                                     /* (whatever the parser makes of a CH record, an image with one is refused) */
            bool has_ch = false;
            for (uint32_t k = 0; k < o->n_rrs; k++) if (zone_image_rr_class(o, k) != 1) has_ch = true;
            if (has_ch) {
                zone_image_policy_t po = m3_pol(o, "ex.test.", 7);
                M3_NEG(o, o->total_size, &po, "class");
            }
            zone_image_free(o);
        }
    }
    {   /* the class and the type are read from the RR: a CHAOS RR and an ANY RR (meta type) in an otherwise valid image */
        uint8_t *m = m3_copy(img);
        const zone_image_t *mi = (const zone_image_t *)(const void *)m;
        if (m) {
            zone_image_rr_t *rr = (zone_image_rr_t *)(void *)(m + mi->off_rrs);
            uint32_t txt = ZONE_IMAGE_NONE;
            for (uint32_t k = 0; k < mi->n_rrs; k++) if (rr[k].type == 16) txt = k;
            CHECK(txt != ZONE_IMAGE_NONE);
            if (txt != ZONE_IMAGE_NONE) {
                rr[txt].class_val = 3;
                M3_NEG(m, img->total_size, &p, "class");
                rr[txt].class_val = 1;
                rr[txt].type = 255;
                M3_NEG(m, img->total_size, &p, "cannot be zone data");
                rr[txt].type = 41;
                M3_NEG(m, img->total_size, &p, "cannot be zone data");
                rr[txt].type = 0;
                M3_NEG(m, img->total_size, &p, "cannot be zone data");
                rr[txt].type = 16;
                M3_POS(m, img->total_size, &p);
            }
            free(m);
        }
    }
    zone_image_free(img);

    /* the SOA RRs: several need the extended encoding, one serial, different clients, no DNSSEC beside them */
    {
        static const char *SET =
            "%in:127.0.0.1\n%ex:10.0.0.0/8\n"
            "Zss.test:ns1.in.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300::in\n"
            "Zss.test:ns1.ex.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300::ex\n"
            "Zss.test:ns1.all.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300:\n"
            "&ss.test::ns1.ss.test:300\n+ns1.ss.test:192.0.2.1:300\n'tx.ss.test:x:300\n";
        zone_image_t *s = m3_image_of(SET, "ss.test.", true, false);
        CHECK(s != NULL);
        if (s) {
            zone_image_policy_t ps = m3_pol(s, "ss.test.", 5);
            M3_POS(s, s->total_size, &ps);
            zone_image_policy_t pq = ps;
            pq.extended = false;
            M3_NEG(s, s->total_size, &pq, "extended");
            pq = ps; pq.serial = 6;
            M3_NEG(s, s->total_size, &pq, "serial");
            pq = ps; pq.tinydns = false;
            M3_NEG(s, s->total_size, &pq, "tinydns");
            /* one SOA of the set at another serial */
            uint8_t *m = m3_copy(s);
            const zone_image_t *mi = (const zone_image_t *)(const void *)m;
            if (m) {
                zone_image_rr_t *rr = (zone_image_rr_t *)(void *)(m + mi->off_rrs);
                for (uint32_t k = 0; k < mi->n_rrs; k++) {
                    if (rr[k].type != 6) continue;
                    uint8_t *rd = m + mi->off_strings + rr[k].rdata_off;
                    rd[rr[k].rdata_len - 20 + 3] ^= 1;       /* the last octet of the serial of this SOA */
                    M3_NEG(m, s->total_size, &ps, "serial");
                    rd[rr[k].rdata_len - 20 + 3] ^= 1;
                    break;
                }
                M3_POS(m, s->total_size, &ps);
                /* a signature beside the set: the signature of the SOA RRset would not hold for every client */
                for (uint32_t k = 0; k < mi->n_rrs; k++)
                    if (rr[k].type == 16) { rr[k].type = 46; break; }          /* (an RRSIG with the RDATA of a TXT: the policy looks at the type) */
                M3_NEG(m, s->total_size, &ps, "DNSSEC");
                free(m);
            }
            zone_image_free(s);
        }
        /* two SOA RRs that the same clients see */
        static const char *SAME =
            "Zdd.test:ns1.a.dd.test.:h.dd.test.:5:7200:3600:1209600:300:300:\n"
            "Zdd.test:ns1.b.dd.test.:h.dd.test.:5:7200:3600:1209600:300:300:\n"
            "&dd.test::ns1.dd.test:300\n+ns1.dd.test:192.0.2.1:300\n";
        s = m3_image_of(SAME, "dd.test.", true, false);
        if (s) {
            zone_image_policy_t ps = m3_pol(s, "dd.test.", 5);
            if (zone_image_rrset_next(s, s->apex_name, 6, zone_image_name_first_rr(s, s->apex_name)) != ZONE_IMAGE_NONE) {
                uint32_t nsoa = 0;
                for (uint32_t k = 0; k < s->n_rrs; k++) if (zone_image_rr_type(s, k) == 6) nsoa++;
                if (nsoa > 1) M3_NEG(s, s->total_size, &ps, "same clients");
            }
            zone_image_free(s);
        }
    }

    {   /* more SOA records than a zone may have (the limit of the SOA set of the Extended AXFR) */
        const size_t cap = 4200u * 100u;
        char *txt = malloc(cap);
        size_t n = 0;
        for (int i = 0; txt && i < 4097; i++) n += (size_t)snprintf(txt + n, cap - n, "Zbig.test:ns%d.big.test.:h.big.test.:5:7200:3600:1209600:300:300:\n", i);
        if (txt) n += (size_t)snprintf(txt + n, cap - n, "&big.test::ns1.big.test:300\n+ns1.big.test:192.0.2.1:300\n");
        zone_image_t *s = txt ? m3_image_of(txt, "big.test.", true, false) : NULL;
        if (s) {
            zone_image_policy_t ps = m3_pol(s, "big.test.", 5);
            M3_NEG(s, s->total_size, &ps, "more than 4096 SOA");
            zone_image_free(s);
        } else {
            printf("  [note] the tinydns parser does not take 4097 SOA lines: the limit is not reached through it\n");
        }
        free(txt);
    }

    /* tinydns and tag attributes, the zone level tables, trusted resolvers */
    {
        zone_image_t *t = m3_image_of(M3_TEXT, "ex.test.", false, false);
        CHECK(t != NULL && t->zattr_len > 0);
        if (t) {
            zone_image_policy_t pt = m3_pol(t, "ex.test.", 7);
            M3_POS(t, t->total_size, &pt);
            pt.extended = false;
            M3_NEG(t, t->total_size, &pt, "extended");
            zone_image_free(t);
        }
        static const char *TD =
            "%in:127.0.0.1\n%ex:10.0.0.0/8\n"
            ".tiny.test:127.0.0.1:ns1.tiny.test:2560\n"
            "+act.tiny.test:192.168.1.10:300:40000000b2d05e00\n+www.tiny.test:192.168.1.10:300::in\n";
        t = m3_image_of(TD, "tiny.test.", true, false);
        CHECK(t != NULL);
        if (t) {
            zone_image_policy_t pt = m3_pol(t, "tiny.test.", 0);
            char w2[200];
            uint32_t ser = 0;
            zone_image_soa_t sn;
            if (zone_image_soa(t, zone_image_apex_soa(t), NULL, 0, NULL, 0, &sn) == 0) ser = sn.serial;
            pt.serial = ser;
            M3_POS(t, t->total_size, &pt);
            pt.extended = false;
            M3_NEG(t, t->total_size, &pt, "extended");
            pt.extended = true; pt.tinydns = false;
            M3_NEG(t, t->total_size, &pt, "tinydns");
            (void)w2;
            zone_image_free(t);
        }
        /* an owner spelled in two cases is an ext[] entry too, but no attribute: no extended encoding needed */
        static const char *CASE = "$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1 host 7 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nWww IN A 192.0.2.2\nwww IN TXT \"x\"\n";
        t = m3_image_of(CASE, "ex.test.", false, false);
        CHECK(t != NULL && t->n_ext > 0);
        if (t) {
            zone_image_policy_t pt = m3_pol(t, "ex.test.", 7);
            pt.extended = false;
            M3_POS(t, t->total_size, &pt);
            zone_image_free(t);
        }
        /* ECS trusted resolvers in the image: they would stand in for the zone's own list and pass the acl-ceiling */
        zone_t z;
        CHECK(load_zone(&z, M3_TEXT, "ex.test.", NULL, false));
        if (z.ok) {
            z.a.bind_ecs_trusted_resolvers = calloc(1, sizeof(char *));
            z.a.bind_ecs_trusted_resolvers[0] = strdup("192.0.2.0/24");
            z.a.bind_ecs_trusted_resolver_count = 1;
            t = zone_image_freeze(&z.a, "ex.test.");
            CHECK(t != NULL);
            if (t) {
                zone_image_policy_t pt = m3_pol(t, "ex.test.", 7);
                M3_NEG(t, t->total_size, &pt, "trusted");
                zone_image_free(t);
            }
            free_zone(&z);
        }
        /* counts: tag definitions, their CIDRs, tinydns locations */
        struct { const char *what; int kind; } cases[] = { { "tag definitions", 0 }, { "tag definitions", 1 }, { "CIDRs", 2 }, { "tinydns locations", 3 } };
        for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            for (int over = 0; over < 2; over++) {                 /* at the limit: accepted, one more: refused */
                CHECK(load_zone(&z, M3_PLAIN, "ex.test.", NULL, false));
                if (!z.ok) continue;
                int kind = cases[c].kind;
                if (kind <= 1) {
                    int n = XFR_TAGDEF_MAX + over;
                    ecs_tag_def_t *defs = calloc((size_t)n, sizeof(*defs));
                    for (int i = 0; i < n; i++) {
                        char nm[24];
                        snprintf(nm, sizeof(nm), "t%d", i);
                        defs[i].tag = strdup(nm);
                    }
                    if (kind == 0) { z.a.bind_location_tags = defs; z.a.bind_location_tag_count = n; }
                    else { z.a.bind_ecs_tags = defs; z.a.bind_ecs_tag_count = n; }
                } else if (kind == 2) {
                    int n = (int)XFR_TAGDEF_CIDR_MAX + over;
                    ecs_tag_def_t *defs = calloc(1, sizeof(*defs));
                    defs[0].tag = strdup("big");
                    defs[0].cidrs = calloc((size_t)n, sizeof(ecs_cidr_entry_t));
                    defs[0].cidr_count = n;
                    for (int i = 0; i < n; i++) {
                        defs[0].cidrs[i].cidr = strdup("192.0.2.0/24");
                        cidr_entry_parse(&defs[0].cidrs[i].parsed, "192.0.2.0/24");
                    }
                    z.a.bind_ecs_tags = defs;
                    z.a.bind_ecs_tag_count = 1;
                } else {
                    int n = 4096 + over;
                    z.a.locations = calloc((size_t)n, sizeof(tinydns_location_entry_t));
                    for (int i = 0; i < n; i++) { z.a.locations[i].code[0] = 'a'; z.a.locations[i].code[1] = (char)('a' + i % 26); z.a.locations[i].prefix_bits = 32; }
                    z.a.location_count = n;
                }
                t = zone_image_freeze(&z.a, "ex.test.");
                CHECK(t != NULL);
                if (t) {
                    zone_image_policy_t pt = m3_pol(t, "ex.test.", 7);
                    if (over) M3_NEG(t, t->total_size, &pt, cases[c].what);
                    else M3_POS(t, t->total_size, &pt);
                    zone_image_free(t);
                }
                free_zone(&z);
            }
        }
    }
}

/* ---- zone_image_check_limits() against zone_arena_check_limits() ---- */
static uint64_t g_lim_cases, g_lim_refused;

static void m3_limits_cmp(const zone_arena_t *a, const zone_image_t *img, const zone_limits_t *lim) {
    char e1[300] = "", e2[300] = "";
    int r1 = zone_arena_check_limits(a, lim, e1, sizeof(e1));
    int r2 = zone_image_check_limits(img, lim, e2, sizeof(e2));
    g_lim_cases++;
    if (r1 < 0) g_lim_refused++;
    int ok = (r1 < 0) == (r2 < 0);
    CHECK(ok);
    if (!ok) printf("    [%s] limits %llu/%u/%u/%u: arena %d '%s', image %d '%s'\n", g_label, (unsigned long long)lim->max_records, lim->max_per_type,
                    lim->max_types_per_name, lim->max_zone_ttl, r1, e1, r2, e2);
    if (r1 < 0 && r2 < 0 && ((lim->max_records != 0) + (lim->max_per_type != 0) + (lim->max_types_per_name != 0) + (lim->max_zone_ttl != 0)) == 1) {
        /* one limit set: both name it */
        const char *key = lim->max_records ? "max-records " : lim->max_per_type ? "max-records-per-type" : lim->max_types_per_name ? "max-types-per-name" : "max-zone-ttl";
        CHECK(strstr(e1, key) != NULL && strstr(e2, key) != NULL);
    }
}

/* the limits that matter for a zone of this size and shape, one at a time and together */
static void m3_limits_all(const zone_arena_t *a, const zone_image_t *img) {
    zone_limits_t lim;
    const uint64_t n = a->count;
    const uint64_t recs[] = { 0, 1, n > 1 ? n - 1 : 1, n, n + 1 };
    const uint32_t per[] = { 0, 1, 2, 3, 10 }, types[] = { 0, 1, 2, 3, 6, 20 }, ttls[] = { 0, 1, 60, 300, 3600, 86400, 2147483647u };
    for (size_t i = 0; i < sizeof(recs) / sizeof(recs[0]); i++) {
        memset(&lim, 0, sizeof(lim));
        lim.max_records = recs[i];
        m3_limits_cmp(a, img, &lim);
    }
    for (size_t i = 0; i < sizeof(per) / sizeof(per[0]); i++)
        for (size_t j = 0; j < sizeof(types) / sizeof(types[0]); j++) {
            memset(&lim, 0, sizeof(lim));
            lim.max_per_type = per[i];
            lim.max_types_per_name = types[j];
            m3_limits_cmp(a, img, &lim);
        }
    for (size_t i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
        memset(&lim, 0, sizeof(lim));
        lim.max_zone_ttl = ttls[i];
        m3_limits_cmp(a, img, &lim);
        lim.max_records = n;
        lim.max_per_type = 2;
        lim.max_types_per_name = 3;
        m3_limits_cmp(a, img, &lim);
    }
}

static uint64_t g_prng = 88172645463325252ull;
static uint32_t prng(void) { g_prng ^= g_prng << 13; g_prng ^= g_prng >> 7; g_prng ^= g_prng << 17; return (uint32_t)(g_prng >> 11); }

static void m3_limits_generated(void) {
    g_label = "limits";
    for (int iter = 0; iter < 400; iter++) {
        char *text = malloc(1 << 20);
        if (!text) return;
        size_t len = (size_t)snprintf(text, 1 << 20, "$ORIGIN g.test.\n$TTL 300\n@ IN SOA ns1 host 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n");
        unsigned owners = 1 + prng() % 30;
        for (unsigned o = 0; o < owners && len < (1 << 20) - 512; o++) {
            unsigned nrr = 1 + prng() % 12;
            for (unsigned k = 0; k < nrr && len < (1 << 20) - 512; k++) {
                unsigned t = prng() % 6;
                unsigned ttl = (unsigned[]){ 60, 300, 3600, 86400, 300, 300 }[prng() % 6];
                switch (t) {
                case 0: len += (size_t)snprintf(text + len, 512, "o%u %u IN A 192.0.2.%u\n", o, ttl, prng() % 250); break;
                case 1: len += (size_t)snprintf(text + len, 512, "o%u %u IN AAAA 2001:db8::%x\n", o, ttl, prng() % 4000); break;
                case 2: len += (size_t)snprintf(text + len, 512, "o%u %u IN TXT \"v%u\"\n", o, ttl, prng() % 1000); break;
                case 3: len += (size_t)snprintf(text + len, 512, "o%u %u IN MX %u mx%u\n", o, ttl, prng() % 50, prng() % 9); break;
                case 4: len += (size_t)snprintf(text + len, 512, "o%u %u IN NS ns%u.g.test.\n", o, ttl, prng() % 9); break;
                default: len += (size_t)snprintf(text + len, 512, "o%u %u IN TXT \"w%u\"\n", o, ttl, prng() % 1000); break;
                }
            }
        }
        zone_t z;
        if (load_zone(&z, text, "g.test.", NULL, false)) {
            zone_image_t *img = zone_image_freeze(&z.a, "g.test.");
            CHECK(img != NULL);
            if (img) {
                m3_limits_all(&z.a, img);
                zone_image_free(img);
            }
            free_zone(&z);
        }
        free(text);
    }
}

static void run_m3_step1(void) {
    printf("[TEST] M3: the image is the same bytes whenever and wherever it is made\n");
    m3_determinism();
    printf("[TEST] M3: zone_image_validate_ex(): every rule of the zone and of the stream\n");
    m3_validate_ex();
    printf("[TEST] M3: zone_image_check_limits() against zone_arena_check_limits() on generated zones\n");
    m3_limits_generated();
    printf("  limits: %llu cases, %llu refused\n", (unsigned long long)g_lim_cases, (unsigned long long)g_lim_refused);
    CHECK(g_lim_cases > 15000 && g_lim_refused > 1000);
}

/* ------------------------------------------------------------------------------------------------ driver per zone */
static int g_zones_checked = 0;
static unsigned long g_rrs_checked = 0;
static unsigned g_types_seen[65536 / 32];

static void check_zone(const char *label, zone_t *z, const char *apex) {
    g_label = label;
    zone_arena_t *a = &z->a;
    zone_image_t *img = zone_image_freeze(a, apex);
    CHECK(img != NULL);
    if (!img) return;
    uint32_t *map = map_records(a, img);
    CHECK(map != NULL);
    if (!map) { zone_image_free(img); return; }
    g_zones_checked++;
    g_rrs_checked += img->n_rrs;
    for (size_t i = 0; i < a->count; i++) if (a->records[i].name) g_types_seen[a->records[i].type_code / 32] |= 1u << (a->records[i].type_code % 32);
    bool big = a->count > 20000;

    check_names(a, img, map);
    check_accessors(a, img, map);
    check_canon(a, img);
    check_nsec(a, img, map);
    check_nsec3(a, img);
    check_glue(a, img);
    check_flags(a, img);
    check_ext(a, img, map);
    check_zattr(a, img);
    check_seq(a, img, map);
    check_validate(img);
    if (!big) m3_limits_all(a, img);

    pass_sequence(a, img, map, 65535, MODE_PLAIN);
    if (!big) {
        pass_sequence(a, img, map, 512, MODE_PLAIN);
        pass_sequence(a, img, map, 1232, MODE_PLAIN);
        pass_sequence(a, img, map, 4096, MODE_OWNER);
        pass_sequence(a, img, map, 65535, MODE_NOCTX);
        pass_sequence(a, img, map, 1232, MODE_TTL);
        pass_sequence(a, img, map, 65535, MODE_TTLMIN);
        pass_boundary(a, img, map, 400);
        check_thaw(a, img, map, apex);
    }
    free(map);
    zone_image_free(img);
}

/* ------------------------------------------------------------------------------------------------ zone files */
static void run_zone_files(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) { printf("  (no %s)\n", dir); return; }
    struct dirent *de;
    int n = 0;
    while ((de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l < 6 || strcmp(de->d_name + l - 5, ".zone") != 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        char *text = read_whole(path);
        if (!text) continue;
        /* the zone name: the first $ORIGIN of the file, else a default */
        char origin_buf[256];
        const char *origin = strncmp(de->d_name, "example.com", 11) == 0 ? "example.com." : "example.";
        for (const char *p = text; (p = strstr(p, "$ORIGIN")) != NULL; p += 7) {
            if (p != text && p[-1] != '\n') continue;
            p += 7;
            while (*p == ' ' || *p == '\t') p++;
            size_t n = 0;
            while (p[n] && p[n] != ' ' && p[n] != '\t' && p[n] != '\r' && p[n] != '\n' && p[n] != ';' && n < sizeof(origin_buf) - 2) n++;
            if (n == 0) break;
            memcpy(origin_buf, p, n);
            if (origin_buf[n - 1] != '.') origin_buf[n++] = '.';
            origin_buf[n] = '\0';
            origin = origin_buf;
            break;
        }
        zone_t z;
        bool ok = load_zone(&z, text, origin, dir, false);
        free(text);
        if (!ok) { printf("  skip %s (does not load)\n", de->d_name); continue; }
        if (z.a.count == 0) { free_zone(&z); continue; }
        printf("  %s: %zu records\n", de->d_name, z.a.count);
        /* the apex is the owner of the first SOA, like the server's zone name */
        const char *apex = origin;
        for (size_t i = 0; i < z.a.count; i++) if (z.a.records[i].type_code == 6 && z.a.records[i].name) { apex = z.a.records[i].name; break; }
        check_zone(de->d_name, &z, apex);
        free_zone(&z);
        n++;
    }
    closedir(d);
    CHECK(n >= 10);
}

/* ------------------------------------------------------------------------------------------------ synthetic zones */
static const char *ZONE_HEAD =
    "$ORIGIN img.example.\n$TTL 3600\n"
    "@ IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 300\n"
    "@ IN NS ns1\n"
    "@ IN NS NS2.Img.Example.\n"
    "ns1 IN A 192.0.2.53\n"
    "NS2 IN AAAA 2001:db8::53\n";

/* one line per RR type; lines the parser rejects are skipped (and counted) */
static const char *TYPE_LINES[] = {
    "a IN A 192.0.2.1",
    "aaaa IN AAAA 2001:db8::1",
    "cn IN CNAME Target.Img.Example.",
    "cnx IN CNAME elsewhere.other.test.",
    "md IN MD md.img.example.",
    "mf IN MF mf.img.example.",
    "mb IN MB Mbox.Img.Example.",
    "mg IN MG mg.img.example.",
    "mr IN MR mr.img.example.",
    "ptr IN PTR Host.Img.Example.",
    "mx IN MX 10 MAIL.Img.Example.",
    "mx IN MX 20 mail2.other.test.",
    "minfo IN MINFO Rmail.Img.Example. EMAILS.img.example.",
    "rp IN RP Mbox.Img.Example. txt.IMG.example.",
    "afsdb IN AFSDB 1 Host.Img.Example.",
    "rt IN RT 5 Relay.Img.Example.",
    "kx IN KX 10 Kx.Img.Example.",
    "px IN PX 10 Map822.Img.Example. MAPX400.img.example.",
    "_sip._tcp IN SRV 10 60 5060 SIP.Img.Example.",
    "dn IN DNAME Elsewhere.Example.Test.",
    "txt IN TXT \"hello\" \"world\"",
    "txt2 IN TXT \"\"",
    "hinfo IN HINFO \"x86\" \"linux\"",
    "naptr IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@img.example!\" .",
    "naptr2 IN NAPTR 100 10 \"\" \"\" \"\" Replace.Img.Example.",
    "caa IN CAA 0 issue \"ca.example\"",
    "sshfp IN SSHFP 1 1 123456789abcdef67890123456789abcdef67890",
    "_443._tcp IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "_ftp._tcp IN URI 10 1 \"ftp://ftp1.example/\"",
    "loc IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
    "svcb IN SVCB 1 Svc.Img.Example. alpn=h2 port=8443",
    "https IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1",
    "https2 IN HTTPS 0 Alias.Img.Example.",
    "ds IN DS 12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "cds IN CDS 12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "dnskey IN DNSKEY 257 3 8 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jDaC/BNVI7NzXAWz2sMz1+",
    "cdnskey IN CDNSKEY 257 3 8 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jDaC/BNVI7NzXAWz2sMz1+",
    "key IN KEY 256 3 8 AwEAAQ==",
    "rrsig IN RRSIG A 8 2 3600 20300101000000 20200101000000 12345 img.example. c2lnbmF0dXJlYnl0ZXM=",
    "rrsig2 IN RRSIG MX 13 3 3600 20300101000000 20200101000000 54321 Signer.Img.Example. c2lnbmF0dXJlYnl0ZXM=",
    "nsec IN NSEC next.img.example. A MX RRSIG NSEC TYPE1234",
    "nsecb IN NSEC Next.Img.Example. A TYPE65534",
    "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM IN NSEC3 1 1 12 aabbccdd 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG",
    "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR IN NSEC3 1 1 12 aabbccdd 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM NS SOA MX RRSIG DNSKEY NSEC3PARAM",
    "@ IN NSEC3PARAM 1 0 12 aabbccdd",
    "csync IN CSYNC 66 3 A NS AAAA",
    "openpgpkey IN OPENPGPKEY c2lnbmF0dXJlYnl0ZXM=",
    "smimea IN SMIMEA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "zonemd IN ZONEMD 2024010101 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "unk IN TYPE65280 \\# 4 DEADBEEF",
    "unk0 IN TYPE65281 \\# 0",
    "apl IN APL 1:192.0.2.0/24 !2:2001:db8::/32",
    "x25 IN X25 \"311061700956\"",
    "isdn IN ISDN \"150862028003217\" \"004\"",
    "gpos IN GPOS -32.6882 116.8652 10.0",
    "ipseckey IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "ipseckey2 IN IPSECKEY 10 3 2 Gw.Img.Example. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "amtrelay IN AMTRELAY 10 0 3 Relay.Img.Example.",
    "nid IN NID 10 0014:4fff:ff20:ee64",
    "l32 IN L32 10 10.1.2.0",
    "l64 IN L64 10 2001:0DB8:1140:1000",
    "lp IN LP 10 L64-Subnet1.Img.Example.",
    "eui48 IN EUI48 00-00-5e-90-01-2b",
    "eui64 IN EUI64 00-00-5e-ef-10-00-00-2b",
    "ninfo IN NINFO \"zs\"",
    "spf IN SPF \"v=spf1 -all\"",
    "dhcid IN DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
    "cert IN CERT 1 2 3 c2lnbmF0dXJlYnl0ZXM=",
    "hip IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs.Img.Example.",
    "wks IN WKS 192.0.2.1 TCP 25 80",
    "nsap IN NSAP 0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00",
    "atma IN ATMA +358400000000",
    "doa IN DOA 1 2 3 text/plain AAAA",
    "dsync IN DSYNC CDS NOTIFY 5359 scanner.img.example.",
    "wild.* IN A 192.0.2.77",
    "*.wc IN A 192.0.2.78",
    "*.wc IN TXT \"wildcard\"",
    "sub IN NS ns.sub.img.example.",
    "ns.sub IN A 192.0.2.60",
    "sub IN DS 1 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "MixedCase IN A 192.0.2.50",
    "mixedcase IN A 192.0.2.51",
    "MIXEDCASE IN TXT \"t\"",
    "mixedcase IN MX 5 MailHost.Img.Example.",
    "UPPER.Sub.Img.Example. IN A 192.0.2.52",
    "esc\\.dot IN A 192.0.2.54",
    "sp\\032ace IN TXT \"with space owner\"",
    "long IN TXT \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
    "ttl1 300 IN A 192.0.2.80",
    "ttl2 1h IN A 192.0.2.81",
    "ttl3 0 IN A 192.0.2.82",
};
#define N_TYPE_LINES (sizeof(TYPE_LINES) / sizeof(TYPE_LINES[0]))

static void run_type_lines(void) {
    static char big[1 << 20];
    size_t bl = 0;
    bl += (size_t)snprintf(big + bl, sizeof(big) - bl, "%s", ZONE_HEAD);
    int accepted = 0;
    for (size_t i = 0; i < N_TYPE_LINES; i++) {
        char text[4096];
        snprintf(text, sizeof(text), "%s%s\n", ZONE_HEAD, TYPE_LINES[i]);
        zone_t z;
        if (!load_zone(&z, text, "img.example.", NULL, false) || z.a.count <= 5) {
            printf("  parser rejects: %s\n", TYPE_LINES[i]);
            if (z.ok) free_zone(&z);
            continue;
        }
        accepted++;
        char label[96];
        snprintf(label, sizeof(label), "line %zu", i);
        check_zone(label, &z, "img.example.");
        free_zone(&z);
        bl += (size_t)snprintf(big + bl, sizeof(big) - bl, "%s\n", TYPE_LINES[i]);
    }
    printf("  %d of %zu type lines accepted by the parser\n", accepted, N_TYPE_LINES);
    CHECK(accepted >= 60);
    /* all accepted lines in one zone: shared compression state across many names and types */
    zone_t z;
    if (load_zone(&z, big, "img.example.", NULL, false)) {
        printf("  combined zone: %zu records\n", z.a.count);
        check_zone("combined", &z, "img.example.");
        free_zone(&z);
    } else {
        CHECK(!"combined zone loads");
    }
}

/* tinydns: time stamps (RFC-less djbdns extension), countdown TTLs, locations */
static void run_tinydns(void) {
    static const char *DATA =
        "%in:127.0.0.1\n%ex:10.0.0.0/8\n%lo:192.168\n"
        ".tiny.test:127.0.0.1:ns1.tiny.test:2560\n"
        "+act-future.tiny.test:192.168.1.10:300:40000000b2d05e00\n"
        "+act-past.tiny.test:192.168.1.20:300:400000003b9aca00\n"
        "+cnt-valid.tiny.test:192.168.1.30:0:4000000099999999\n"
        "+cnt-expired.tiny.test:192.168.1.40:0:400000003b9aca00\n"
        "+normal.tiny.test:192.168.1.50:600\n"
        "+www.tiny.test:192.168.1.10:300::in\n"
        "+www.tiny.test:10.0.0.10:300::ex\n"
        "+www.tiny.test:192.0.2.4:300\n"
        "+Mixed.Tiny.Test:192.0.2.9:300::lo\n"
        "@tiny.test:192.168.1.30:mx1.tiny.test:10:1800\n"
        "'txt.tiny.test:Hello\\040World:300\n"
        "^ptr.tiny.test:target.tiny.test:600\n"
        "Calias.tiny.test:www.tiny.test:1200\n"
        "Zcustom.tiny.test:ns1.custom.tiny.test:admin.custom.tiny.test:2026090201:7200:3600:1209600:300:600\n"
        ":ssh.tiny.test:44:\\002\\001\\001\\012\\023\\045:3600\n"
        "&sub.tiny.test:192.0.2.61:ns.sub.tiny.test:259200\n";
    zone_t z;
    if (!load_zone(&z, DATA, "tiny.test.", NULL, true)) { CHECK(!"tinydns data loads"); return; }
    printf("  tinydns: %zu records, %d locations\n", z.a.count, z.a.location_count);
    CHECK(z.a.is_tinydns_format);
    bool has_ttd = false, has_loc = false, has_cd = false;
    for (size_t i = 0; i < z.a.count; i++) {
        if (z.a.records[i].tinydns_ttd) has_ttd = true;
        if (z.a.records[i].tinydns_loc[0] || z.a.records[i].tinydns_loc[1]) has_loc = true;
        if (z.a.records[i].tinydns_ttl_countdown) has_cd = true;
    }
    CHECK(has_ttd && has_loc && has_cd);
    check_zone("tinydns", &z, "tiny.test.");
    zone_image_t *img = zone_image_freeze(&z.a, "tiny.test.");
    CHECK(img != NULL && (img->flags & ZONE_IMAGE_F_TINYDNS) && (img->flags & ZONE_IMAGE_F_EXT));
    if (img) {
        /* the extras are only for the RRs that use them */
        CHECK(img->n_ext > 0 && img->n_ext < img->n_rrs);
        zone_image_free(img);
    }
    free_zone(&z);
}

/* $LOCATION / $ECS-SUBNET tags in the BIND format (tests/zones/example.com.location.zone covers the file forms) */
static void run_tags(void) {
    static const char *TEXT =
        "$ORIGIN tag.test.\n$TTL 300\n"
        "@ IN SOA ns1 host 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
        "$LOCATION-TAG office 192.0.2.0/24 198.51.100.0/24\n"
        "$ECS-SUBNET-TAG far 203.0.113.0/24 2001:db8::/32\n"
        "$LOCATION office\n"
        "www IN A 192.0.2.10\n"
        "$LOCATION \"\"\n"
        "$ECS-SUBNET far\n"
        "www IN A 192.0.2.20\n"
        "$ECS-SUBNET \"\"\n"
        "www IN A 192.0.2.30\n";
    zone_t z;
    if (!load_zone(&z, TEXT, "tag.test.", NULL, false)) { printf("  tags: parser rejects the tag syntax, skipped\n"); return; }
    bool lt = false, et = false;
    for (size_t i = 0; i < z.a.count; i++) { if (z.a.records[i].bind_location_tag) lt = true; if (z.a.records[i].ecs_subnet_tag) et = true; }
    printf("  tags: %zu records, location tags %d, ecs tags %d (rec tags: loc=%d ecs=%d)\n", z.a.count, z.a.bind_location_tag_count,
           z.a.bind_ecs_tag_count, lt, et);
    CHECK(lt && et);
    check_zone("tags", &z, "tag.test.");
    free_zone(&z);
}

/* S5 B-2: owners interleaved in the file keep their file order in AXFR out and thaw (perm[]), a contiguous zone has none */
static void run_perm(void) {
    g_label = "perm";
    static const char *INTER =
        "$ORIGIN perm.test.\n$TTL 300\n"
        "@ IN SOA ns1 host 1 7200 3600 1209600 300\n"
        "www IN A 192.0.2.1\n@ IN NS ns1\nwww IN AAAA 2001:db8::1\nns1 IN A 192.0.2.53\n@ IN MX 10 www\nwww IN TXT \"x\"\n";
    static const char *CONTIG =
        "$ORIGIN perm.test.\n$TTL 300\n"
        "@ IN SOA ns1 host 1 7200 3600 1209600 300\n@ IN NS ns1\n@ IN MX 10 www\nns1 IN A 192.0.2.53\nwww IN A 192.0.2.1\nwww IN AAAA 2001:db8::1\n";
    zone_t z;
    CHECK(load_zone(&z, INTER, "perm.test.", NULL, false));
    zone_image_t *img = zone_image_freeze(&z.a, "perm.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK((img->flags & ZONE_IMAGE_F_PERM) && img->off_perm != 0);
        uint32_t *map = map_records(&z.a, img);
        CHECK(map != NULL);
        if (map) { check_seq(&z.a, img, map); free(map); }
        /* thaw restores the file order */
        zone_arena_t b;
        zone_arena_init(&b);
        CHECK(zone_image_thaw(img, &b) == 0 && b.count == z.a.count);
        for (size_t i = 0; i < b.count && i < z.a.count; i++)
            CHECK(strcasecmp(b.records[i].name, z.a.records[i].name) == 0 && b.records[i].type_code == z.a.records[i].type_code);
        zone_arena_destroy(&b);
        /* apex SOA is the first SOA in file order */
        uint32_t soa = zone_image_apex_soa(img);
        CHECK(soa != ZONE_IMAGE_NONE && zone_image_rr_type(img, soa) == 6);
        zone_image_free(img);
    }
    free_zone(&z);
    CHECK(load_zone(&z, CONTIG, "perm.test.", NULL, false));
    img = zone_image_freeze(&z.a, "perm.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK(!(img->flags & ZONE_IMAGE_F_PERM) && img->off_perm == 0);
        zone_image_free(img);
    }
    free_zone(&z);
}

/* B8t-1: several apex SOA RRs with attributes: the reference SOA, the SOA a client sees, ZONE_IMAGE_F_SOA_ATTR, the serial rule */
static bool soa_mname_is(const zone_image_t *img, uint32_t rr, const char *mname) {
    char m[DNS_NAME_TEXT_SIZE];
    return rr != ZONE_IMAGE_NONE && zone_image_soa(img, rr, m, sizeof(m), NULL, 0, NULL) == 0 && strcasecmp(m, mname) == 0;
}

static void run_soa_set(void) {
    g_label = "soa set";
    static const char *DATA =
        "%in:127.0.0.1\n%ex:10.0.0.0/8\n"
        "Zss.test:ns1.in.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300::in\n"
        "Zss.test:ns1.ex.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300::ex\n"
        "Zss.test:ns1.all.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300:\n"
        "&ss.test::ns1.ss.test:300\n+ns1.ss.test:192.0.2.1:300\n";
    zone_t z;
    CHECK(load_zone(&z, DATA, "ss.test.", NULL, true));
    if (!z.ok) return;
    char err[256];
    CHECK(zone_arena_check_soa_set(&z.a, "ss.test.", err, sizeof(err)) == 0);
    const dns_record_t *ref = zone_arena_reference_soa(&z.a, "ss.test.");
    CHECK(ref && strcasecmp(ref->rdata[0], "ns1.all.ss.test.") == 0 && !dns_record_is_restricted(ref));
    zone_image_t *img = zone_image_freeze(&z.a, "ss.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK(img->flags & ZONE_IMAGE_F_SOA_ATTR);
        /* the reference SOA is the one for everybody although it is the last in file order */
        CHECK(soa_mname_is(img, zone_image_apex_soa(img), "ns1.all.ss.test."));
        zone_image_view_t v = { {'i', 'n'}, NULL, NULL, 0 };
        uint32_t ttl = 0;
        CHECK(soa_mname_is(img, zone_image_visible_soa(img, &v, &ttl), "ns1.in.ss.test.") && ttl == 300);
        v.loc[0] = 'e'; v.loc[1] = 'x';
        CHECK(soa_mname_is(img, zone_image_visible_soa(img, &v, NULL), "ns1.ex.ss.test."));
        v.loc[0] = 'z'; v.loc[1] = 'z';
        CHECK(soa_mname_is(img, zone_image_visible_soa(img, &v, NULL), "ns1.all.ss.test."));    /* the unrestricted SOA is seen by all */
        zone_image_free(img);
    }
    free_zone(&z);

    /* every SOA restricted: the reference is the first in file order; a client of no listed location sees none */
    static const char *ALL_R =
        "%in:127.0.0.1\n%ex:10.0.0.0/8\n%zz:192.0.2\n"
        "Zrr.test:ns1.in.rr.test.:h.rr.test.:5:7200:3600:1209600:300:300::in\n"
        "Zrr.test:ns1.ex.rr.test.:h.rr.test.:5:7200:3600:1209600:300:300::ex\n"
        "&rr.test::ns1.rr.test:300\n+ns1.rr.test:192.0.2.1:300\n";
    CHECK(load_zone(&z, ALL_R, "rr.test.", NULL, true));
    if (!z.ok) return;
    img = zone_image_freeze(&z.a, "rr.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK(soa_mname_is(img, zone_image_apex_soa(img), "ns1.in.rr.test."));
        zone_image_view_t v = { {'z', 'z'}, NULL, NULL, 0 };
        CHECK(zone_image_visible_soa(img, &v, NULL) == ZONE_IMAGE_NONE);
        v.loc[0] = 0; v.loc[1] = 0;
        CHECK(zone_image_visible_soa(img, &v, NULL) == ZONE_IMAGE_NONE);
        zone_image_free(img);
    }
    free_zone(&z);

    /* a time stamp is an attribute too: a countdown SOA is visible until it runs out (TTL 2..3600), an activation stamp
     * in the future hides it until then */
    static const char *TS =
        "Ztt.test:ns1.cd.tt.test.:h.tt.test.:5:7200:3600:1209600:300:0:4000000099999999:\n"
        "Ztt.test:ns1.old.tt.test.:h.tt.test.:5:7200:3600:1209600:300:0:400000003b9aca00:\n"
        "Ztt.test:ns1.fut.tt.test.:h.tt.test.:5:7200:3600:1209600:300:300:40000000b2d05e00:\n"
        "&tt.test::ns1.tt.test:300\n+ns1.tt.test:192.0.2.1:300\n";
    CHECK(load_zone(&z, TS, "tt.test.", NULL, true));
    if (!z.ok) return;
    img = zone_image_freeze(&z.a, "tt.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK(img->flags & ZONE_IMAGE_F_SOA_ATTR);
        time_t cd_end = (time_t)0x99999999LL;
        zone_image_view_t v = { {0, 0}, NULL, NULL, cd_end - 100 };
        uint32_t ttl = 0;
        CHECK(soa_mname_is(img, zone_image_visible_soa(img, &v, &ttl), "ns1.cd.tt.test.") && ttl == 100);
        v.now = cd_end + 5;                                 /* the countdown is over, the old one too, the future one is not active */
        CHECK(zone_image_visible_soa(img, &v, NULL) == ZONE_IMAGE_NONE);
        v.now = (time_t)0xb2d05e00LL + 1;                   /* after the activation of the last */
        CHECK(soa_mname_is(img, zone_image_visible_soa(img, &v, NULL), "ns1.fut.tt.test."));
        zone_image_free(img);
    }
    free_zone(&z);

    /* BIND $LOCATION on the SOA */
    static const char *TAGGED =
        "$ORIGIN tg.test.\n$TTL 300\n"
        "$LOCATION-TAG office 192.0.2.0/24\n$LOCATION-TAG far 198.51.100.0/24\n"
        "$LOCATION office\n@ IN SOA ns1.office.tg.test. h 4 7200 3600 1209600 300\n"
        "$LOCATION far\n@ IN SOA ns1.far.tg.test. h 4 7200 3600 1209600 300\n"
        "$LOCATION none\n@ IN NS ns1\nns1 IN A 192.0.2.1\n";
    CHECK(load_zone(&z, TAGGED, "tg.test.", NULL, false));
    if (!z.ok) return;
    CHECK(zone_arena_check_soa_set(&z.a, "tg.test.", err, sizeof(err)) == 0);
    img = zone_image_freeze(&z.a, "tg.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK(img->flags & ZONE_IMAGE_F_SOA_ATTR);
        zone_image_view_t v = { {0, 0}, "far", NULL, 0 };
        CHECK(soa_mname_is(img, zone_image_visible_soa(img, &v, NULL), "ns1.far.tg.test."));
        v.loc_tag = "none-such";
        CHECK(zone_image_visible_soa(img, &v, NULL) == ZONE_IMAGE_NONE);
        v.loc_tag = NULL;
        CHECK(zone_image_visible_soa(img, &v, NULL) == ZONE_IMAGE_NONE);
        zone_image_free(img);
    }
    free_zone(&z);

    /* the serial rule (RFC 2181 s6.1) and the DNSSEC rule */
    static const char *MISMATCH =
        "%in:127.0.0.1\n"
        "Zmm.test:ns1.a.mm.test.:h.mm.test.:1:7200:3600:1209600:300:300::in\n"
        "Zmm.test:ns1.b.mm.test.:h.mm.test.:2:7200:3600:1209600:300:300:\n&mm.test::ns1.mm.test:300\n";
    CHECK(load_zone(&z, MISMATCH, "mm.test.", NULL, true));
    err[0] = 0;
    CHECK(zone_arena_check_soa_set(&z.a, "mm.test.", err, sizeof(err)) == -1 && strstr(err, "different serials") && strstr(err, "1 and 2"));
    free_zone(&z);
    static const char *SIGNED =
        "$ORIGIN sg.test.\n$TTL 300\n"
        "$LOCATION-TAG office 192.0.2.0/24\n"
        "$LOCATION office\n@ IN SOA ns1 h 4 7200 3600 1209600 300\n$LOCATION none\n"
        "@ IN NS ns1\nns1 IN A 192.0.2.1\n"
        "@ IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n";
    CHECK(load_zone(&z, SIGNED, "sg.test.", NULL, false));
    err[0] = 0;
    CHECK(zone_arena_check_soa_set(&z.a, "sg.test.", err, sizeof(err)) == -1 && strstr(err, "DNSSEC"));
    free_zone(&z);

    /* a zone with one plain SOA is unchanged: no flag, the SOA is the reference and the visible one */
    static const char *PLAIN = "$ORIGIN pl.test.\n$TTL 300\n@ IN SOA ns1 h 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n";
    CHECK(load_zone(&z, PLAIN, "pl.test.", NULL, false));
    img = zone_image_freeze(&z.a, "pl.test.");
    CHECK(img != NULL);
    if (img) {
        CHECK(!(img->flags & ZONE_IMAGE_F_SOA_ATTR));
        zone_image_view_t v = { {0, 0}, NULL, NULL, 0 };
        CHECK(zone_image_apex_soa(img) != ZONE_IMAGE_NONE && zone_image_apex_soa(img) == zone_image_visible_soa(img, &v, NULL));
        zone_image_free(img);
    }
    free_zone(&z);
}

/* B-1: more than 256 distinct targets (some without addresses, some used twice) and wildcard / DNAME owners */
static void run_glue_flags(void) {
    g_label = "glue flags";
    static char text[64 * 1024];
    size_t o = (size_t)snprintf(text, sizeof(text), "%s", ZONE_HEAD);
    for (int i = 0; i < 300; i++) {
        o += (size_t)snprintf(text + o, sizeof(text) - o, "m%03d MX 10 t%03d.img.example.\n", i, i);
        if (i % 7 != 3) o += (size_t)snprintf(text + o, sizeof(text) - o, "t%03d AAAA 2001:db8::%x\nt%03d A 192.0.2.%d\n", i, i + 1, i, i % 250 + 1);
        if (i % 11 == 0) o += (size_t)snprintf(text + o, sizeof(text) - o, "n%03d NS t%03d.img.example.\n", i, i);   /* a target used twice */
    }
    o += (size_t)snprintf(text + o, sizeof(text) - o, "*.w A 192.0.2.250\ndn DNAME img.example.\nx.out MX 10 mail.elsewhere.example.\n");
    zone_t z;
    CHECK(load_zone(&z, text, "img.example.", NULL, false));
    if (!z.ok) return;
    check_zone("glue flags", &z, "img.example.");
    zone_image_t *img = zone_image_freeze(&z.a, "img.example.");
    CHECK(img != NULL);
    if (img) {
        CHECK((img->flags & ZONE_IMAGE_F_WILDCARD) && (img->flags & ZONE_IMAGE_F_DNAME));
        int flagged = 0, below = 0;
        for (int i = 0; i < 300; i++) {
            char nm[64];
            snprintf(nm, sizeof(nm), "t%03d.img.example.", i);
            uint32_t id = zone_image_find_name(img, nm);
            bool has_addr = i % 7 != 3;
            CHECK((id != ZONE_IMAGE_NONE) == has_addr);
            if (id == ZONE_IMAGE_NONE) continue;
            bool f = (zone_image_name_flags(img, id) & ZONE_IMAGE_NAME_GLUE) != 0;
            if (f) flagged++;
            /* the 256 slots are taken in record order by targets with or without addresses: the two NS targets of
             * ZONE_HEAD first, then t000.. */
            CHECK(f == (i < 254));
            if (i >= 254 && !f) below++;
        }
        CHECK(flagged > 200 && flagged < 256 && below > 30);
        zone_image_free(img);
    }
    /* no wildcard and no DNAME: neither flag */
    zone_t z2;
    char small[2048];
    snprintf(small, sizeof(small), "%swww A 192.0.2.1\n", ZONE_HEAD);
    CHECK(load_zone(&z2, small, "img.example.", NULL, false));
    if (z2.ok) {
        zone_image_t *i2 = zone_image_freeze(&z2.a, "img.example.");
        CHECK(i2 && !(i2->flags & (ZONE_IMAGE_F_WILDCARD | ZONE_IMAGE_F_DNAME)));
        zone_image_free(i2);
        free_zone(&z2);
    }
    free_zone(&z);
}

/* D15-1 (RFC 3597 5: zero-length RDATA is legal).  A secondary reads every RR with parse_resource_record(); an RR of a type
 * that has no dedicated decoder and RDLENGTH 0 used to come out with generic_data == NULL: nothing to write, so it was
 * dropped as unencodable (a primary serving "x TYPE65534 \# 0" answered it, its secondary said NXDOMAIN).  It must be an
 * empty blob that survives dropping, indexing, freeze, thaw, comparison (IXFR diff) and serialization. */
static void run_empty_rdata_wire(void) {
    g_label = "empty RDATA";
    static const char *text =
        "$ORIGIN e.test.\n$TTL 300\n@ IN SOA ns1 hm 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
        "empty IN TYPE65534 \\# 0\nempty IN TYPE65534 \\# 2 0102\nnul IN NULL \\# 0\nx25 IN X25 \\# 0\nlast IN TXT \"z\"\n";
    zone_t a;
    CHECK(load_zone(&a, text, "e.test.", ".", false));
    if (!a.ok) return;
    size_t n_empty = 0;
    for (size_t i = 0; i < a.a.count; i++)
        if (a.a.records[i].generic_data && a.a.records[i].generic_len == 0) n_empty++;
    CHECK(n_empty == 3);

    /* the secondary: every RR written to the wire and read back the way AXFR-in does it */
    zone_arena_t b;
    zone_arena_init(&b);
    b.records = calloc(a.a.count, sizeof(dns_record_t));
    b.records_cap = a.a.count;
    CHECK(b.records != NULL);
    static uint8_t wire[65535];
    size_t n_empty_b = 0;
    for (size_t i = 0; b.records && i < a.a.count; i++) {
        uint16_t off = 0;
        CHECK(serialize_dns_record(wire, sizeof(wire), &off, &a.a.records[i], NULL, NULL, 0xFFFFFFFFu) == 0);
        dns_record_t rec;
        memset(&rec, 0, sizeof(rec));
        size_t pos = 0;
        uint16_t t = 0;
        CHECK(parse_resource_record(wire, off, &pos, &b, &rec, &t) == 0 && pos == off);
        b.records[b.count++] = rec;
        if (a.a.records[i].generic_data && a.a.records[i].generic_len == 0) {
            CHECK(rec.generic_data != NULL && rec.generic_len == 0 && rec.rdata_count == 0);   /* an empty blob, not "no blob" */
            n_empty_b++;
        }
        CHECK(compare_records(&a.a.records[i], &rec, false));
        uint8_t canon[64];
        CHECK(dns_record_canonical_rdata(&rec, canon, sizeof(canon)) >= 0);
        /* and it is written back byte for byte */
        uint8_t wire2[65535];
        uint16_t off2 = 0;
        CHECK(serialize_dns_record(wire2, sizeof(wire2), &off2, &rec, NULL, NULL, 0xFFFFFFFFu) == 0 && off2 == off &&
              memcmp(wire, wire2, off) == 0);
    }
    CHECK(n_empty_b == 3);
    CHECK(zone_arena_drop_unencodable(&b, silent_report, NULL) == 0);       /* nothing is dropped any more */
    CHECK(b.count == a.a.count);
    /* an IXFR diff sees empty == empty and empty != a one-record-different RDATA */
    dns_record_t *e0 = NULL, *e2 = NULL;
    for (size_t i = 0; i < b.count; i++) {
        if (b.records[i].type_code == 65534 && b.records[i].generic_len == 0) e0 = &b.records[i];
        if (b.records[i].type_code == 65534 && b.records[i].generic_len == 2) e2 = &b.records[i];
    }
    CHECK(e0 && e2 && !compare_records(e0, e2, false) && compare_records(e0, e0, false));
    CHECK(build_zone_index(&b, true) == 0);
    zone_image_t *img = zone_image_freeze(&b, "e.test.");
    CHECK(img != NULL);
    if (img) {
        size_t raw_empty = 0;
        for (uint32_t k = 0; k < img->n_rrs; k++) {
            uint16_t ty = zone_image_rr_type(img, k);
            if ((ty == 65534 || ty == 10 || ty == 19) && zone_image_rr_rdlen(img, k) == 0) raw_empty++;
        }
        CHECK(raw_empty == 3);
        zone_arena_t c;
        zone_arena_init(&c);
        CHECK(zone_image_thaw(img, &c) == 0 && c.count == b.count);
        size_t found = 0;
        for (size_t i = 0; i < b.count; i++)
            if (record_exists_in_arena(&c, &b.records[i])) found++;
        CHECK(found == b.count);
        zone_arena_destroy(&c);
        zone_image_free(img);
    }
    zone_arena_destroy(&b);
    free_zone(&a);
}

/* an empty zone, a zone of one RR, and the builder contract */
static void run_edges(void) {
    g_label = "edges";
    zone_arena_t a;
    zone_arena_init(&a);
    CHECK(zone_image_freeze(&a, "x.") == NULL); /* not indexed */
    CHECK(build_zone_index(&a, false) == 0);
    zone_image_t *img = zone_image_freeze(&a, "x.");
    CHECK(img != NULL);
    if (img) {
        CHECK(img->n_names == 0 && img->n_rrs == 0 && zone_image_find_name(img, "x.") == ZONE_IMAGE_NONE);
        CHECK(zone_image_canon_floor(img, "x.", NULL) == ZONE_IMAGE_NONE && zone_image_nsec_floor(img, "x.") == ZONE_IMAGE_NONE);
        check_validate(img);   /* the empty image: no names, an all-empty hash table */
        zone_arena_t b;
        zone_arena_init(&b);
        CHECK(zone_image_thaw(img, &b) == 0 && b.count == 0);
        zone_arena_destroy(&b);
        zone_image_free(img);
    }
    zone_arena_destroy(&a);
}

/* B9a: ALIAS (TYPE 65401, CLASS IN) marks the image and its owner; an ALIAS beside A / AAAA or DNSSEC records is not published; the
 * Extended AXFR record of the same number (CLASS 65302) is no ALIAS */
static void run_b9a_alias(void) {
    g_label = "alias";
    static const char *OK =
        "$ORIGIN al.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n"
        "a ALIAS t.target.test.\na TXT \"x\"\nl LUA A \"c\"\nb A 192.0.2.2\n";
    zone_t z;
    CHECK(load_zone(&z, OK, "al.test.", NULL, false));
    if (z.ok) {
        zone_image_t *img = zone_image_freeze(&z.a, "al.test.");
        CHECK(img != NULL);
        if (img) {
            CHECK(img->flags & ZONE_IMAGE_F_ALIAS);
            uint32_t a = zone_image_find_name(img, "a.al.test.");
            uint32_t b = zone_image_find_name(img, "b.al.test.");
            uint32_t l = zone_image_find_name(img, "l.al.test.");
            CHECK(a != ZONE_IMAGE_NONE && (zone_image_name_flags(img, a) & ZONE_IMAGE_NAME_ALIAS));
            CHECK(b != ZONE_IMAGE_NONE && !(zone_image_name_flags(img, b) & ZONE_IMAGE_NAME_ALIAS));
            CHECK(l != ZONE_IMAGE_NONE && !(zone_image_name_flags(img, l) & ZONE_IMAGE_NAME_ALIAS));   /* LUA is no ALIAS */
            uint32_t rr = zone_image_rrset_next(img, a, 65401, zone_image_name_first_rr(img, a));
            CHECK(rr != ZONE_IMAGE_NONE && zone_image_rr_class(img, rr) == 1 && zone_image_rr_rdlen(img, rr) == 15);
            /* thaw gives the same records back */
            zone_arena_t t;
            zone_arena_init(&t);
            CHECK(zone_image_thaw(img, &t) == 0);
            size_t n_alias = 0, n_lua = 0;
            for (size_t i = 0; i < t.count; i++) {
                n_alias += t.records[i].type_code == 65401 && t.records[i].class_val == 1;
                n_lua += t.records[i].type_code == 65402 && t.records[i].class_val == 1;
            }
            CHECK(n_alias == 1 && n_lua == 1);
            zone_arena_destroy(&t);
            zone_image_free(img);
        }
        free_zone(&z);
    }
    /* no ALIAS: no flag */
    CHECK(load_zone(&z, "$ORIGIN na.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n", "na.test.", NULL, false));
    if (z.ok) {
        zone_image_t *img = zone_image_freeze(&z.a, "na.test.");
        CHECK(img && !(img->flags & ZONE_IMAGE_F_ALIAS));
        zone_image_free(img);
        free_zone(&z);
    }
    /* refused: the image is not made */
    static const char *const BAD[] = {
        "$ORIGIN bad.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\na ALIAS t.target.test.\na A 192.0.2.1\n",
        "$ORIGIN bad.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\na ALIAS t.target.test.\nA AAAA 2001:db8::1\n",
        "$ORIGIN bad.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\na ALIAS t.target.test.\n@ DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n",
        "$ORIGIN bad.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\nx TYPE65401 \\# 2 0161\n",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        CHECK(load_zone(&z, BAD[i], "bad.test.", NULL, false));
        if (!z.ok) continue;
        CHECK(zone_image_freeze(&z.a, "bad.test.") == NULL);
        free_zone(&z);
    }
}

/* Regression (fuzz_zone_image found it): a zone that parses but has two different CNAMEs on one name is refused at freeze (BIND:
 * DNS_R_SINGLETON), tinydns data and zone file text alike; the same RR twice is one RR and is published. */
static void run_singleton_refused(void) {
    g_label = "singleton";
    zone_t z;
    CHECK(load_zone(&z, "Calias.fuzz.local:a.example.:300\nCalias.fuzz.local:b.example.:300\n", "fuzz.local.", NULL, true));
    if (z.ok) {
        CHECK(zone_image_freeze(&z.a, "fuzz.local.") == NULL);
        free_zone(&z);
    }
    CHECK(load_zone(&z, "$ORIGIN fuzz.local.\n$TTL 60\nalias CNAME a.example.\nalias CNAME b.example.\n", "fuzz.local.", NULL, false));
    if (z.ok) {
        CHECK(zone_image_freeze(&z.a, "fuzz.local.") == NULL);
        free_zone(&z);
    }
    CHECK(load_zone(&z, "$ORIGIN fuzz.local.\n$TTL 60\nalias CNAME a.example.\nalias CNAME a.example.\n", "fuzz.local.", NULL, false));
    if (z.ok) {
        zone_image_t *img = zone_image_freeze(&z.a, "fuzz.local.");
        CHECK(img != NULL);
        if (img) zone_image_free(img);
        free_zone(&z);
    }
}

int main(void) {
    printf("=== test_zone_image ===\n");
    run_m3_step1();
    printf("[TEST] two CNAMEs on one name are refused at freeze\n");
    run_singleton_refused();
    printf("[TEST] synthetic zones: one line per RR type\n");
    run_type_lines();
    printf("[TEST] tinydns time stamps, countdown TTLs, locations\n");
    run_tinydns();
    printf("[TEST] BIND $LOCATION / $ECS-SUBNET tags\n");
    run_tags();
    printf("[TEST] engine hints: wildcard / DNAME flags, prelinked glue targets (B-1)\n");
    run_glue_flags();
    printf("[TEST] file order of interleaved owners (B-2)\n");
    run_perm();
    printf("[TEST] several / restricted apex SOA records (B8t-1)\n");
    run_soa_set();
    printf("[TEST] zero-length RDATA read from the wire (D15-1)\n");
    run_empty_rdata_wire();
    printf("[TEST] B9a: ALIAS flag and the zone rules at freeze\n");
    run_b9a_alias();
    printf("[TEST] empty zone\n");
    run_edges();
    printf("[TEST] tests/zones/*.zone\n");
    const char *dirs[] = { getenv("KARIDNS_TEST_ZONES"), "tests/zones", "zones", "../tests/zones" };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (!dirs[i]) continue;
        DIR *d = opendir(dirs[i]);
        if (!d) continue;
        closedir(d);
        run_zone_files(dirs[i]);
        break;
    }
    unsigned types = 0;
    for (size_t i = 0; i < sizeof(g_types_seen) / sizeof(g_types_seen[0]); i++) types += (unsigned)__builtin_popcount(g_types_seen[i]);
    printf("zones checked: %d, RRs: %lu, distinct RR types: %u, checks: %d, failed: %d\n", g_zones_checked, g_rrs_checked, types,
           g_checks, g_failed);
    CHECK(types >= 40);
    printf("validate: %lu images, %lu damaged copies refused (targeted: %lu), %lu byte changes accepted and read through every accessor\n", g_val_images, g_val_rejected, g_val_cases, g_val_accepted);
    CHECK(g_val_images >= 40 && g_val_cases >= 2000 && g_val_rejected > g_val_accepted);
    if (g_failed) { printf("FAILED (%d)\n", g_failed); return 1; }
    printf("ALL PASSED\n");
    return 0;
}
