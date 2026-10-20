/*
 * dns_presigned.c - rebuild of the NSEC3 / NSEC RRs of a presigned PowerDNS zone.  See dns_presigned.h for the rules
 * and the RFC sections (RFC 5155 s3.2.1 s4.1.2 s5 s7.1, RFC 4034 s3.1.4 s4.1.2 s6.1, RFC 9077 s3).
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <openssl/evp.h>

#include "dns_presigned.h"
#include "dns_utils.h"

#define T_NS 2
#define T_SOA 6
#define T_DS 43
#define T_RRSIG 46
#define T_NSEC 47
#define T_NSEC3 50
#define T_NSEC3PARAM 51

/* ------------------------------------------------------------------------------------------------------------- */
/* small helpers                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { char *p; size_t len, cap; bool oom; } ps_sb_t;

static void sb_put(ps_sb_t *b, const char *s, size_t n) {
    if (b->oom) return;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void sb_puts(ps_sb_t *b, const char *s) { sb_put(b, s, strlen(s)); }

static void sb_printf(ps_sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_printf(ps_sb_t *b, const char *fmt, ...) {
    char tmp[64];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < sizeof(tmp)) sb_put(b, tmp, (size_t)n);
    else b->oom = true;          /* callers only format short numbers */
}

static bool parse_u32(const char *s, uint32_t *v) {
    if (!s || !*s) return false;
    uint64_t x = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        x = x * 10 + (uint64_t)(*p - '0');
        if (x > 0xFFFFFFFFull) return false;
    }
    *v = (uint32_t)x;
    return true;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool presigned_parse_n3param(const char *s, presigned_n3param_t *p, const char **why) {
    static const char *dummy;
    if (!why) why = &dummy;
    memset(p, 0, sizeof(*p));
    char buf[600];
    if (!s || strlen(s) >= sizeof(buf)) {
        *why = "NSEC3PARAM is empty or too long";
        return false;
    }
    snprintf(buf, sizeof(buf), "%s", s);
    char *tok[6];
    int nt = 0;
    for (char *q = strtok(buf, " \t"); q; q = strtok(NULL, " \t")) {
        if (nt == 5) break;
        tok[nt++] = q;
    }
    if (nt > 4) {
        *why = "NSEC3PARAM has more than four fields";
        return false;
    }
    if (nt != 4) {
        *why = "NSEC3PARAM needs four fields: algorithm flags iterations salt";
        return false;
    }
    uint32_t alg, flags, iter;
    if (!parse_u32(tok[0], &alg) || !parse_u32(tok[1], &flags) || !parse_u32(tok[2], &iter)) {
        *why = "NSEC3PARAM algorithm, flags and iterations must be decimal numbers";
        return false;
    }
    if (alg != 1) {                      /* RFC 5155 s11: only SHA-1 is defined */
        *why = "NSEC3PARAM hash algorithm is not 1 (SHA-1; RFC 5155 s11)";
        return false;
    }
    if (flags > 1) {                     /* RFC 5155 s3.1.2: only the Opt-Out bit is defined; s7.2: 0 or 1 */
        *why = "NSEC3PARAM flags must be 0 or 1 (Opt-Out; RFC 5155 s3.1.2)";
        return false;
    }
    if (iter > PRESIGNED_MAX_ITERATIONS) {
        *why = "NSEC3PARAM iterations exceed 2500 (RFC 5155 s10.3, RFC 9276 s3)";
        return false;
    }
    p->alg = (uint8_t)alg;
    p->flags = (uint8_t)flags;
    p->iterations = (uint16_t)iter;
    if (strcmp(tok[3], "-") != 0) {
        size_t hl = strlen(tok[3]);
        if (hl % 2 != 0 || hl / 2 > 255) {
            *why = "NSEC3PARAM salt is not an even number of hex digits (at most 255 octets; RFC 5155 s3.1.5)";
            return false;
        }
        for (size_t i = 0; i < hl / 2; i++) {
            int hi = hexval(tok[3][2 * i]), lo = hexval(tok[3][2 * i + 1]);
            if (hi < 0 || lo < 0) {
                *why = "NSEC3PARAM salt is not hexadecimal";
                return false;
            }
            p->salt[i] = (uint8_t)(hi * 16 + lo);
        }
        p->salt_len = (uint8_t)(hl / 2);
    }
    return true;
}

static void salt_text(const presigned_n3param_t *p, char *out /* >= 511 */) {
    if (p->salt_len == 0) {
        strcpy(out, "-");
        return;
    }
    for (size_t i = 0; i < p->salt_len; i++) sprintf(out + 2 * i, "%02x", p->salt[i]);
}

/* RFC 5155 s5: IH(salt, x, 0) = H(x || salt); IH(salt, x, k) = H(IH(salt, x, k-1) || salt).  The owner name x is in
 * canonical wire form (RFC 4034 s6.2: lower case, uncompressed). */
static bool nsec3_hash_ctx(EVP_MD_CTX *md, const char *name, const presigned_n3param_t *p, char out[33]) {
    uint8_t wire[256 + 2];
    long wl = write_uncompressed_name_ext(wire, 0, 256, name, true);
    if (wl <= 0) return false;
    uint8_t dg[EVP_MAX_MD_SIZE];
    unsigned dl = 0;
    if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) != 1 || EVP_DigestUpdate(md, wire, (size_t)wl) != 1 ||
        (p->salt_len && EVP_DigestUpdate(md, p->salt, p->salt_len) != 1) || EVP_DigestFinal_ex(md, dg, &dl) != 1 || dl != 20)
        return false;
    for (unsigned i = 0; i < p->iterations; i++) {
        if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) != 1 || EVP_DigestUpdate(md, dg, 20) != 1 ||
            (p->salt_len && EVP_DigestUpdate(md, p->salt, p->salt_len) != 1) || EVP_DigestFinal_ex(md, dg, &dl) != 1 || dl != 20)
            return false;
    }
    char b32[40];
    dns_base32hex_encode(dg, 20, b32, sizeof(b32));
    size_t n = strlen(b32);
    if (n != 32) return false;
    for (size_t i = 0; i < n; i++) out[i] = (char)tolower((unsigned char)b32[i]);
    out[32] = '\0';
    return true;
}

bool presigned_nsec3_hash(const char *name, const presigned_n3param_t *p, char out[33]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return false;
    bool ok = nsec3_hash_ctx(md, name, p, out);
    EVP_MD_CTX_free(md);
    return ok;
}

/* name without its first label (NULL for the root / a one-label name) */
static const char *parent_of(const char *name) {
    const char *dot = strchr_unescaped(name, '.');
    if (!dot || dot[1] == '\0') return NULL;
    return dot + 1;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* nodes: the distinct owner names of the parsed rows                                                             */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { const char *name; size_t idx; } ps_rec_t;

static int rec_cmp(const void *a, const void *b) {
    const ps_rec_t *x = a, *y = b;
    int c = compare_canonical_name(x->name, y->name);
    if (c) return c;
    return x->idx < y->idx ? -1 : x->idx > y->idx;
}

typedef struct {
    const char *name;
    size_t first, count;        /* records of the name: order[first .. first+count) */
    uint32_t sig_ttl;           /* Original TTL of the RRSIG(NSEC3 / NSEC) at the name */
    bool have_ttl, chain, has_ns, has_ds, occluded, is_apex, required;
    char hash[33];              /* NSEC3: hash of the name (chain: the owner's label) */
    bool hashed;
} ps_node_t;

typedef struct {
    const char *name;           /* ENT name: a suffix of the owner it was derived from */
    bool required;
    char hash[33];
} ps_ent_t;

typedef struct {
    char hash[33];
    int kind;                   /* 0 node, 1 ENT */
    size_t ref;
} ps_he_t;

typedef struct {
    const zone_arena_t *arena;
    const char *apex;
    ps_rec_t *order;
    ps_node_t *nodes;
    size_t n_nodes;
    uint16_t *cov;              /* RRSIG: covered type; 0 otherwise */
    uint32_t *orig;             /* RRSIG: Original TTL */
    ps_ent_t *ents;
    size_t n_ents, cap_ents;
    EVP_MD_CTX *md;
} ps_ctx_t;

static ps_node_t *find_node(const ps_ctx_t *c, const char *name) {
    size_t lo = 0, hi = c->n_nodes;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int r = compare_canonical_name(name, c->nodes[mid].name);
        if (r == 0) return &c->nodes[mid];
        if (r < 0) hi = mid;
        else lo = mid + 1;
    }
    return NULL;
}

static bool is_apex_name(const ps_ctx_t *c, const char *name) { return domain_names_match_ci(name, c->apex); }

/* RRSIG RDATA as the zone parser keeps it: type-covered, algorithm, labels, original TTL, expiration, inception,
 * key tag, signer, signature (RFC 4034 s3.1) */
static void rrsig_fields(const dns_record_t *r, uint16_t *covered, uint32_t *orig) {
    *covered = 0;
    *orig = 0;
    if (r->generic_data || r->rdata_count < 9) return;
    uint16_t t = get_type_code(r->rdata[0]);
    uint32_t o;
    if (t == 0 || !parse_u32(r->rdata[3], &o)) return;
    *covered = t;
    *orig = o;
}

static int build_nodes(ps_ctx_t *c, char *err, size_t errlen) {
    const zone_arena_t *a = c->arena;
    c->order = malloc((a->count ? a->count : 1) * sizeof(ps_rec_t));
    c->cov = calloc(a->count ? a->count : 1, sizeof(uint16_t));
    c->orig = calloc(a->count ? a->count : 1, sizeof(uint32_t));
    c->nodes = calloc(a->count ? a->count : 1, sizeof(ps_node_t));
    if (!c->order || !c->cov || !c->orig || !c->nodes) goto oom;
    for (size_t i = 0; i < a->count; i++) {
        c->order[i].name = a->records[i].name;
        c->order[i].idx = i;
        if (a->records[i].type_code == T_RRSIG) rrsig_fields(&a->records[i], &c->cov[i], &c->orig[i]);
    }
    qsort(c->order, a->count, sizeof(ps_rec_t), rec_cmp);
    for (size_t i = 0; i < a->count;) {
        size_t j = i + 1;
        while (j < a->count && compare_canonical_name(c->order[j].name, c->order[i].name) == 0) j++;
        ps_node_t *n = &c->nodes[c->n_nodes++];
        n->name = c->order[i].name;
        n->first = i;
        n->count = j - i;
        n->is_apex = is_apex_name(c, n->name);
        if (!domain_name_is_at_or_below(n->name, c->apex)) {
            snprintf(err, errlen, "owner '%.200s' is outside the zone", n->name);
            return -1;
        }
        for (size_t k = i; k < j; k++) {
            const dns_record_t *r = &a->records[c->order[k].idx];
            if (r->type_code == T_NS) n->has_ns = true;
            if (r->type_code == T_DS) n->has_ds = true;
        }
        i = j;
    }
    /* occluded: strictly below a delegation point (a non-apex name with NS), RFC 1034 s4.2.1; glue lives there */
    for (size_t i = 0; i < c->n_nodes; i++) {
        ps_node_t *n = &c->nodes[i];
        if (n->is_apex) continue;
        for (const char *p = parent_of(n->name); p && !is_apex_name(c, p); p = parent_of(p)) {
            const ps_node_t *anc = find_node(c, p);
            if (anc && anc->has_ns) {
                n->occluded = true;
                break;
            }
        }
    }
    return 0;
oom:
    snprintf(err, errlen, "out of memory");
    return -1;
}

/* the first stored RRSIG row of the node that covers `covered` (arena index), SIZE_MAX if there is none */
static size_t first_sig_idx(const ps_ctx_t *c, const ps_node_t *n, uint16_t covered) {
    size_t best = (size_t)-1;
    for (size_t k = 0; k < n->count; k++) {
        size_t ri = c->order[n->first + k].idx;
        if (c->arena->records[ri].type_code == T_RRSIG && c->cov[ri] == covered && ri < best) best = ri;
    }
    return best;
}

static ps_node_t *apex_node(ps_ctx_t *c) {
    for (size_t i = 0; i < c->n_nodes; i++)
        if (c->nodes[i].is_apex) return &c->nodes[i];
    return NULL;
}

static int cmp_u16(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
    return x < y ? -1 : x > y;
}

/* " TYPEnnn" for the distinct types of the records of a node (ascending), the type bit map of RFC 5155 s7.1 / RFC 4034 s4.1.2:
 * at a delegation only NS, DS and RRSIG (s4.1.2); add1 / add2 are types added whatever the node holds (the NSEC3PARAM of
 * the apex, the NSEC of an NSEC chain); add_rrsig_always adds RRSIG; NSEC3 is never listed (s7.1). */
static void put_types(ps_sb_t *sb, const ps_ctx_t *c, const ps_node_t *n, bool delegation, uint16_t add1, uint16_t add2,
                      bool add_rrsig_always, bool node_has_types) {
    uint16_t *t = malloc((n ? n->count + 3 : 3) * sizeof(uint16_t));
    size_t nt = 0;
    if (!t) {
        sb->oom = true;
        return;
    }
    if (n && node_has_types) {
        for (size_t k = 0; k < n->count; k++) {
            uint16_t ty = c->arena->records[c->order[n->first + k].idx].type_code;
            if (ty == T_NSEC3 || ty == 0) continue;
            if (delegation && ty != T_NS && ty != T_DS && ty != T_RRSIG) continue;
            t[nt++] = ty;
        }
    }
    if (add_rrsig_always) t[nt++] = T_RRSIG;
    if (add1) t[nt++] = add1;
    if (add2) t[nt++] = add2;
    qsort(t, nt, sizeof(uint16_t), cmp_u16);
    uint16_t prev = 0;
    bool first = true;
    for (size_t i = 0; i < nt; i++) {
        if (!first && t[i] == prev) continue;
        sb_printf(sb, " TYPE%u", (unsigned)t[i]);
        prev = t[i];
        first = false;
    }
    free(t);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* NSEC order names                                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

/* the ordername PowerDNS writes for NSEC zones: labels of the name relative to the apex, reversed, joined by a blank.
 * false: not comparable (the name has an escape) */
static bool nsec_ordername(const char *name, const char *apex, char *out, size_t cap) {
    out[0] = '\0';
    if (strchr(name, '\\')) return false;
    size_t nl = dns_name_len_no_root(name, strlen(name)), al = dns_name_len_no_root(apex, strlen(apex));
    if (nl < al) return false;
    if (nl == al) return true;
    size_t rl = nl - al - 1;                        /* the part before ".apex" */
    if (rl + 1 > cap) return false;
    size_t o = 0;
    size_t end = rl;
    while (end > 0) {
        size_t st = end;
        while (st > 0 && name[st - 1] != '.') st--;
        if (o) out[o++] = ' ';
        memcpy(out + o, name + st, end - st);
        o += end - st;
        end = st > 0 ? st - 1 : 0;
    }
    out[o] = '\0';
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the two rebuilds                                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

static int soa_minimum(const ps_ctx_t *c, uint32_t *v) {
    for (size_t i = 0; i < c->arena->count; i++) {
        const dns_record_t *r = &c->arena->records[i];
        if (r->type_code == T_SOA && !r->generic_data && r->rdata_count >= 7 && is_apex_name(c, r->name)) {
            *v = parse_ttl_value(r->rdata[6]);
            return 0;
        }
    }
    return -1;
}

static int he_cmp(const void *a, const void *b) {
    const ps_he_t *x = a, *y = b;
    return strcmp(x->hash, y->hash);
}

static int chain_cmp(const void *a, const void *b) {
    const ps_node_t *x = *(const ps_node_t *const *)a, *y = *(const ps_node_t *const *)b;
    return strcmp(x->hash, y->hash);
}

/* validates a <hash>.<apex> owner and copies the lower-case hash; false = not such a name */
static bool chain_label(const ps_ctx_t *c, const char *name, char out[33]) {
    const char *dot = strchr_unescaped(name, '.');
    if (!dot || (size_t)(dot - name) != 32) return false;
    const char *rest = dot + 1;
    if (!domain_names_match_ci(rest, c->apex)) return false;
    for (size_t i = 0; i < 32; i++) {
        char ch = (char)tolower((unsigned char)name[i]);
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'v'))) return false;
        out[i] = ch;
    }
    out[32] = '\0';
    return true;
}

static int add_ent(ps_ctx_t *c, const char *name) {
    if (c->n_ents == c->cap_ents) {
        size_t nc = c->cap_ents ? c->cap_ents * 2 : 64;
        ps_ent_t *ne = realloc(c->ents, nc * sizeof(*ne));
        if (!ne) return -1;
        c->ents = ne;
        c->cap_ents = nc;
    }
    memset(&c->ents[c->n_ents], 0, sizeof(ps_ent_t));
    c->ents[c->n_ents++].name = name;
    return 0;
}

static int rebuild_nsec3(ps_ctx_t *c, const presigned_n3param_t *np, const char *const *ordernames,
                         const presigned_ent_t *ents_in, size_t n_ents_in, presigned_out_t *out, char *err,
                         size_t errlen) {
    const zone_arena_t *a = c->arena;
    int rc = -1;
    ps_he_t *he = NULL;
    const ps_node_t **chain = NULL;
    size_t n_chain = 0, n_he = 0;
    size_t *chain_ref = NULL;               /* per chain entry: index into he[] of the entity it belongs to */
    size_t *stack = NULL;
    ps_sb_t sb = {0};
    bool optout = (np->flags & 1) != 0;

    /* 1. chain owners: nodes that hold RRSIG(NSEC3) */
    for (size_t i = 0; i < c->n_nodes; i++) {
        ps_node_t *n = &c->nodes[i];
        for (size_t k = 0; k < n->count; k++) {
            size_t ri = c->order[n->first + k].idx;
            const dns_record_t *r = &a->records[ri];
            if (r->type_code == T_RRSIG && c->cov[ri] == T_NSEC3) {
                if (!n->chain) {
                    n->chain = true;
                    n->sig_ttl = c->orig[ri];
                    n->have_ttl = true;
                } else if (n->sig_ttl != c->orig[ri]) {
                    snprintf(err, errlen, "RRSIG(NSEC3) rows at '%.200s' have different Original TTLs", n->name);
                    goto out;
                }
            }
        }
        if (!n->chain) continue;
        for (size_t k = 0; k < n->count; k++) {
            size_t ri = c->order[n->first + k].idx;
            if (!(a->records[ri].type_code == T_RRSIG && c->cov[ri] == T_NSEC3)) {
                snprintf(err, errlen, "'%.200s' holds RRSIG(NSEC3) and other data", n->name);
                goto out;
            }
        }
        if (!chain_label(c, n->name, n->hash)) {
            snprintf(err, errlen, "RRSIG(NSEC3) owner '%.200s' is not a hashed owner name directly below the zone apex",
                     n->name);
            goto out;
        }
        n->hashed = true;
        n_chain++;
    }
    if (n_chain == 0) {
        snprintf(err, errlen, "NSEC3PARAM metadata given but the zone has no RRSIG(NSEC3) rows");
        goto out;
    }

    /* 2. hash every name that is not occluded; ENTs through a depth first walk in canonical order */
    chain = malloc(n_chain * sizeof(*chain));
    stack = malloc(130 * sizeof(size_t));            /* ENT ancestors of one name: at most 127 labels (RFC 1035 s2.3.4) */
    if (!chain || !stack) goto oom;
    size_t n_stack = 0;
    const ps_node_t *prev = NULL;
    size_t nc = 0;
    for (size_t i = 0; i < c->n_nodes; i++) {
        ps_node_t *n = &c->nodes[i];
        if (n->chain) {
            chain[nc++] = n;
            continue;
        }
        bool need_hash = !n->occluded;
        if (!need_hash && ordernames)
            for (size_t k = 0; k < n->count && !need_hash; k++) need_hash = ordernames[c->order[n->first + k].idx] != NULL;
        if (need_hash) {
            if (!nsec3_hash_ctx(c->md, n->name, np, n->hash)) {
                snprintf(err, errlen, "cannot hash '%.200s'", n->name);
                goto out;
            }
            n->hashed = true;
        }
        /* ordername must be this hash (all rows of the name; RRSIG rows are NULL in PowerDNS but are checked too) */
        if (ordernames && n->hashed) {
            for (size_t k = 0; k < n->count; k++) {
                const char *on = ordernames[c->order[n->first + k].idx];
                if (on && strcasecmp(on, n->hash) != 0) {
                    snprintf(err, errlen, "ordername '%.64s' of '%.200s' is not its NSEC3 hash %s", on, n->name, n->hash);
                    goto out;
                }
            }
        }
        if (n->occluded) continue;
        bool optional = optout && !n->is_apex && n->has_ns && !n->has_ds;      /* unsigned delegation */
        n->required = !optional;
        /* ENT ancestors that are new since the previous name (RFC 5155 s7.1 step 4) */
        while (n_stack > 0 && !(domain_name_is_at_or_below(n->name, c->ents[stack[n_stack - 1]].name) &&
                                !domain_names_match_ci(n->name, c->ents[stack[n_stack - 1]].name)))
            n_stack--;
        size_t first_new = c->n_ents;
        for (const char *p = parent_of(n->name); !n->is_apex && p && !is_apex_name(c, p); p = parent_of(p)) {
            if (prev && domain_name_is_at_or_below(prev->name, p)) break;
            if (find_node(c, p)) continue;
            if (add_ent(c, p) != 0) goto oom;
        }
        /* new ENTs were found deepest first; the stack wants shallowest first */
        for (size_t lo = first_new, hi = c->n_ents; lo + 1 < hi; lo++, hi--) {
            ps_ent_t tmp = c->ents[lo];
            c->ents[lo] = c->ents[hi - 1];
            c->ents[hi - 1] = tmp;
        }
        for (size_t e = first_new; e < c->n_ents; e++) stack[n_stack++] = e;
        if (n->required)
            for (size_t s = 0; s < n_stack; s++) c->ents[stack[s]].required = true;
        prev = n;
    }
    for (size_t e = 0; e < c->n_ents; e++) {
        if (!nsec3_hash_ctx(c->md, c->ents[e].name, np, c->ents[e].hash)) {
            snprintf(err, errlen, "cannot hash '%.200s'", c->ents[e].name);
            goto out;
        }
    }
    /* ordername of the ENT rows of the DB */
    for (size_t i = 0; i < n_ents_in; i++) {
        char h[33];
        if (!ents_in[i].ordername) continue;
        if (!nsec3_hash_ctx(c->md, ents_in[i].name, np, h)) continue;
        if (strcasecmp(ents_in[i].ordername, h) != 0) {
            snprintf(err, errlen, "ordername '%.64s' of the empty non-terminal '%.200s' is not its NSEC3 hash %s",
                     ents_in[i].ordername, ents_in[i].name, h);
            goto out;
        }
    }

    /* 3. entities (names and ENTs) in hash order, chain in hash order, merge */
    {
        size_t cap = c->n_nodes + c->n_ents;
        he = malloc((cap ? cap : 1) * sizeof(*he));
        if (!he) goto oom;
        for (size_t i = 0; i < c->n_nodes; i++)
            if (!c->nodes[i].chain && !c->nodes[i].occluded) {
                memcpy(he[n_he].hash, c->nodes[i].hash, 33);
                he[n_he].kind = 0;
                he[n_he++].ref = i;
            }
        for (size_t e = 0; e < c->n_ents; e++) {
            memcpy(he[n_he].hash, c->ents[e].hash, 33);
            he[n_he].kind = 1;
            he[n_he++].ref = e;
        }
    }
    qsort(he, n_he, sizeof(*he), he_cmp);
    qsort(chain, n_chain, sizeof(*chain), chain_cmp);
    for (size_t i = 1; i < n_he; i++)
        if (strcmp(he[i].hash, he[i - 1].hash) == 0) {
            snprintf(err, errlen, "NSEC3 hash collision %s between two names of the zone", he[i].hash);
            goto out;
        }
    chain_ref = malloc(n_chain * sizeof(size_t));
    if (!chain_ref) goto oom;
    {
        size_t i = 0, j = 0;
        while (i < n_he || j < n_chain) {
            int cmp;
            if (i >= n_he) cmp = 1;
            else if (j >= n_chain) cmp = -1;
            else cmp = strcmp(he[i].hash, chain[j]->hash);
            if (cmp == 0) {
                chain_ref[j] = i;
                i++;
                j++;
            } else if (cmp < 0) {                 /* a name without an NSEC3 RR */
                bool required = he[i].kind == 0 ? c->nodes[he[i].ref].required : c->ents[he[i].ref].required;
                if (!optout || required) {
                    const char *nm = he[i].kind == 0 ? c->nodes[he[i].ref].name : c->ents[he[i].ref].name;
                    snprintf(err, errlen, "no RRSIG(NSEC3) owner for '%.200s' (hash %s)%s", nm, he[i].hash,
                             he[i].kind ? " (empty non-terminal)" : "");
                    goto out;
                }
                i++;
            } else {                              /* a chain owner that is no name of the zone */
                snprintf(err, errlen, "RRSIG(NSEC3) owner %s matches no name or empty non-terminal of the zone",
                         chain[j]->hash);
                goto out;
            }
        }
    }

    /* 4. the text */
    {
        char salt[512];
        uint32_t ttl_param = 0;
        bool have_param_ttl = false;
        const ps_node_t *ap = apex_node(c);
        if (!ap) {
            snprintf(err, errlen, "no records at the zone apex");
            goto out;
        }
        for (size_t k = 0; k < ap->count; k++) {
            size_t ri = c->order[ap->first + k].idx;
            if (a->records[ri].type_code == T_RRSIG && c->cov[ri] == T_NSEC3PARAM) {
                if (!have_param_ttl) {
                    ttl_param = c->orig[ri];
                    have_param_ttl = true;
                } else if (ttl_param != c->orig[ri]) {
                    snprintf(err, errlen, "RRSIG(NSEC3PARAM) rows have different Original TTLs");
                    goto out;
                }
            }
        }
        if (!have_param_ttl && soa_minimum(c, &ttl_param) != 0) {
            snprintf(err, errlen, "no SOA record at the zone apex");
            goto out;
        }
        salt_text(np, salt);
        out->anchor = malloc((n_chain + 1) * sizeof(size_t));
        if (!out->anchor) goto oom;
        out->anchor[0] = first_sig_idx(c, ap, T_NSEC3PARAM);
        sb_puts(&sb, "$ORIGIN .\n");
        sb_puts(&sb, c->apex);
        sb_printf(&sb, " %u IN NSEC3PARAM %u 0 %u ", (unsigned)ttl_param, (unsigned)np->alg, (unsigned)np->iterations);
        sb_puts(&sb, salt);
        sb_puts(&sb, "\n");
        out->n_records = 1;
        for (size_t j = 0; j < n_chain; j++) {
            const ps_node_t *own = chain[j];
            const ps_node_t *nxt = chain[(j + 1) % n_chain];
            const ps_he_t *h = &he[chain_ref[j]];
            out->anchor[out->n_records] = first_sig_idx(c, own, T_NSEC3);
            sb_puts(&sb, own->name);
            sb_printf(&sb, " %u IN NSEC3 %u %u %u ", (unsigned)own->sig_ttl, (unsigned)np->alg, (unsigned)np->flags,
                      (unsigned)np->iterations);
            sb_puts(&sb, salt);
            sb_puts(&sb, " ");
            sb_puts(&sb, nxt->hash);
            if (h->kind == 0) {
                const ps_node_t *n = &c->nodes[h->ref];
                bool deleg = !n->is_apex && n->has_ns;
                /* RRSIG: when the name has RRSIG rows; the RRSIG(NSEC3) rows are at the hashed owners, not here */
                bool has_sig = false;
                for (size_t k = 0; k < n->count; k++)
                    if (a->records[c->order[n->first + k].idx].type_code == T_RRSIG) has_sig = true;
                put_types(&sb, c, n, deleg, n->is_apex ? T_NSEC3PARAM : 0, 0, has_sig, true);
            }
            sb_puts(&sb, "\n");
            out->n_records++;
        }
    }
    if (sb.oom) goto oom;
    out->mode = PS_NSEC3;
    out->text = sb.p;
    out->text_len = sb.len;
    sb.p = NULL;
    rc = 0;
    goto out;
oom:
    snprintf(err, errlen, "out of memory");
out:
    free(sb.p);
    free(he);
    free(chain);
    free(chain_ref);
    free(stack);
    return rc;
}

static int rebuild_nsec(ps_ctx_t *c, const char *const *ordernames, const presigned_ent_t *ents_in, size_t n_ents_in,
                        presigned_out_t *out, char *err, size_t errlen) {
    const zone_arena_t *a = c->arena;
    int rc = -1;
    ps_sb_t sb = {0};
    size_t *chain = NULL, n_chain = 0;
    char exp[1100];

    chain = malloc((c->n_nodes + 1) * sizeof(size_t));
    if (!chain) goto oom;
    for (size_t i = 0; i < c->n_nodes; i++) {
        ps_node_t *n = &c->nodes[i];
        for (size_t k = 0; k < n->count; k++) {
            size_t ri = c->order[n->first + k].idx;
            if (a->records[ri].type_code == T_RRSIG && c->cov[ri] == T_NSEC) {
                if (!n->chain) {
                    n->chain = true;
                    n->sig_ttl = c->orig[ri];
                } else if (n->sig_ttl != c->orig[ri]) {
                    snprintf(err, errlen, "RRSIG(NSEC) rows at '%.200s' have different Original TTLs", n->name);
                    goto out;
                }
            }
        }
        if (ordernames) {
            for (size_t k = 0; k < n->count; k++) {
                const char *on = ordernames[c->order[n->first + k].idx];
                if (!on) continue;
                if (!nsec_ordername(n->name, c->apex, exp, sizeof(exp))) continue;
                if (strcasecmp(on, exp) != 0) {
                    snprintf(err, errlen, "ordername '%.64s' of '%.200s' is not '%.64s'", on, n->name, exp);
                    goto out;
                }
            }
        }
        if (n->chain && n->occluded) {
            snprintf(err, errlen, "RRSIG(NSEC) at '%.200s', which is below a delegation (RFC 4034 s4.1.2)", n->name);
            goto out;
        }
        if (!n->chain && !n->occluded) {
            snprintf(err, errlen, "no RRSIG(NSEC) for '%.200s'", n->name);
            goto out;
        }
        if (n->chain) chain[n_chain++] = i;
    }
    for (size_t i = 0; i < n_ents_in; i++) {
        if (!ents_in[i].ordername || !nsec_ordername(ents_in[i].name, c->apex, exp, sizeof(exp))) continue;
        if (strcasecmp(ents_in[i].ordername, exp) != 0) {
            snprintf(err, errlen, "ordername '%.64s' of the empty non-terminal '%.200s' is not '%.64s'",
                     ents_in[i].ordername, ents_in[i].name, exp);
            goto out;
        }
    }
    const ps_node_t *ap = apex_node(c);
    if (!ap || !ap->chain) {
        snprintf(err, errlen, "the zone apex has no RRSIG(NSEC)");
        goto out;
    }
    /* the apex is the smallest name in canonical order (RFC 4034 s6.1), so chain[0] is the apex */
    sb_puts(&sb, "$ORIGIN .\n");
    out->anchor = malloc((n_chain + 1) * sizeof(size_t));
    if (!out->anchor) goto oom;
    for (size_t j = 0; j < n_chain; j++) {
        const ps_node_t *n = &c->nodes[chain[j]];
        out->anchor[j] = first_sig_idx(c, n, T_NSEC);
        const ps_node_t *nx = &c->nodes[chain[(j + 1) % n_chain]];
        bool deleg = !n->is_apex && n->has_ns;
        sb_puts(&sb, n->name);
        sb_printf(&sb, " %u IN NSEC ", (unsigned)n->sig_ttl);
        sb_puts(&sb, nx->name);
        put_types(&sb, c, n, deleg, T_NSEC, 0, true, true);
        sb_puts(&sb, "\n");
    }
    if (sb.oom) goto oom;
    out->mode = PS_NSEC;
    out->n_records = n_chain;
    out->text = sb.p;
    out->text_len = sb.len;
    sb.p = NULL;
    rc = 0;
    goto out;
oom:
    snprintf(err, errlen, "out of memory");
out:
    free(sb.p);
    free(chain);
    return rc;
}

int presigned_rebuild(const zone_arena_t *arena, const char *apex, const char *nsec3param,
                      const char *const *ordernames, const presigned_ent_t *ents, size_t n_ents,
                      presigned_out_t *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    err[0] = '\0';
    size_t n_nsec = 0, n_nsec3 = 0, n_param = 0, n_rs_nsec = 0, n_rs_nsec3 = 0;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        switch (r->type_code) {
        case T_NSEC: n_nsec++; break;
        case T_NSEC3: n_nsec3++; break;
        case T_NSEC3PARAM: n_param++; break;
        case T_RRSIG: {
            uint16_t cv;
            uint32_t og;
            rrsig_fields(r, &cv, &og);
            if (cv == T_NSEC) n_rs_nsec++;
            else if (cv == T_NSEC3) n_rs_nsec3++;
            break;
        }
        default: break;
        }
    }
    presigned_mode_t mode = PS_NONE;
    presigned_n3param_t np;
    if (nsec3param) {
        const char *why = "";
        if (!presigned_parse_n3param(nsec3param, &np, &why)) {
            snprintf(err, errlen, "NSEC3PARAM metadata '%.80s': %s", nsec3param, why);
            return -1;
        }
        if (n_nsec3 || n_param || n_nsec || n_rs_nsec) {
            snprintf(err, errlen, "NSEC3PARAM metadata together with stored %s rows: a presigned zone is either rebuilt "
                     "from the metadata or stored as is", n_nsec3 ? "NSEC3" : n_param ? "NSEC3PARAM" : n_nsec ? "NSEC" : "RRSIG(NSEC)");
            return -1;
        }
        mode = PS_NSEC3;
    } else if (n_rs_nsec3 && !n_nsec3) {
        snprintf(err, errlen, "RRSIG(NSEC3) rows but no NSEC3 rows and no NSEC3PARAM metadata");
        return -1;
    } else if (n_rs_nsec && !n_nsec) {
        if (n_nsec3 || n_rs_nsec3 || n_param) {
            snprintf(err, errlen, "RRSIG(NSEC) rows without NSEC rows together with NSEC3 data");
            return -1;
        }
        mode = PS_NSEC;
    }
    if (mode == PS_NONE) return 0;

    ps_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.arena = arena;
    c.apex = apex;
    c.md = EVP_MD_CTX_new();
    int rc = -1;
    if (!c.md) {
        snprintf(err, errlen, "out of memory");
    } else if (build_nodes(&c, err, errlen) == 0) {
        if (!apex_node(&c)) snprintf(err, errlen, "no records at the zone apex");
        else if (mode == PS_NSEC3) rc = rebuild_nsec3(&c, &np, ordernames, ents, n_ents, out, err, errlen);
        else rc = rebuild_nsec(&c, ordernames, ents, n_ents, out, err, errlen);
    }
    EVP_MD_CTX_free(c.md);
    free(c.order);
    free(c.cov);
    free(c.orig);
    free(c.nodes);
    free(c.ents);
    if (rc != 0) presigned_out_free(out);
    return rc;
}

void presigned_out_free(presigned_out_t *out) {
    free(out->text);
    free(out->anchor);
    memset(out, 0, sizeof(*out));
}
