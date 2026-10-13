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
                if (x != y) {
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
        if (x->type_code != 14) { /* MINFO is lowercased without a context in both; compare with a context below */
            CHECK(ra == rb && oa == ob && memcmp(ba, bb, oa) == 0);
        }
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
        zone_arena_t b;
        zone_arena_init(&b);
        CHECK(zone_image_thaw(img, &b) == 0 && b.count == 0);
        zone_arena_destroy(&b);
        zone_image_free(img);
    }
    zone_arena_destroy(&a);
}

int main(void) {
    printf("=== test_zone_image ===\n");
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
    if (g_failed) { printf("FAILED (%d)\n", g_failed); return 1; }
    printf("ALL PASSED\n");
    return 0;
}
