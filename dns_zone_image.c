/*
 * dns_zone_image.c - S5 Phase B: the compact immutable zone image (see dns_zone_image.h).
 *
 * Byte parity with serialize_dns_record() (CLAUDE.md Rule 3/4):
 *  - freeze asks serialize_dns_record() itself for the RDATA (no compress_ctx_t, so every name is expanded and
 *    nothing depends on what was written before) and stores those bytes. The only type whose uncompressed output
 *    differs in case from the compressed one is MINFO (write_dns_name_str() lowercases without a context), so it
 *    is rebuilt from the text with the case kept.
 *  - image_serialize_rr() copies the stored bytes and sends the domain names at the places listed in
 *    dns_rdata_name_layout() through compress_name(), the function serialize_dns_record() uses, in the same order,
 *    so the bytes, the status and the compress_ctx_t table are those of serialize_dns_record().
 *  - the owner is written from the stored wire form (case as written) exactly as serialize_dns_record() writes
 *    rec->name_wire, or through write_dns_name_str() for an override name.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <syslog.h>
#include <assert.h>

#include "dns_zone_image.h"
#include "dns_utils.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"

_Static_assert(sizeof(zone_image_name_t) == 24, "zone_image_name_t");
_Static_assert(sizeof(zone_image_rr_t) == 24, "zone_image_rr_t");
_Static_assert(sizeof(zone_image_ext_t) == 32, "zone_image_ext_t");
_Static_assert(sizeof(zone_image_n3chain_t) == 16, "zone_image_n3chain_t");
_Static_assert(sizeof(zone_image_t) % 8 == 0, "zone_image_t alignment");

#define IMG_MAX_RDLEN 65524u /* 65535 - 11: a root owner and the fixed fields precede the RDATA when captured */
#define IMG_FAIL() do { syslog(LOG_ERR, "[Image] freeze failed at dns_zone_image.c:%d", __LINE__); goto out; } while (0)

/* ------------------------------------------------------------------------------------------------------------
 * growable byte buffer
 * ------------------------------------------------------------------------------------------------------------ */
typedef struct {
    uint8_t *p;
    size_t len, cap;
    bool oom;
} sbuf_t;

static bool sb_reserve(sbuf_t *sb, size_t extra) {
    if (sb->oom) return false;
    if (sb->len + extra < sb->len) { sb->oom = true; return false; }
    if (sb->len + extra <= sb->cap) return true;
    size_t ncap = sb->cap ? sb->cap : 1024;
    while (ncap < sb->len + extra) ncap *= 2;
    uint8_t *np = realloc(sb->p, ncap);
    if (!np) { sb->oom = true; return false; }
    sb->p = np;
    sb->cap = ncap;
    return true;
}

/* append; returns the offset of the first byte */
static uint32_t sb_add(sbuf_t *sb, const void *data, size_t n) {
    if (!sb_reserve(sb, n)) return 0;
    uint32_t off = (uint32_t)sb->len;
    if (n) memcpy(sb->p + sb->len, data, n);
    sb->len += n;
    return off;
}

static void sb_u32(sbuf_t *sb, uint32_t v) { sb_add(sb, &v, sizeof(v)); }

/* a NUL terminated copy of s (without s's NUL) at the returned offset; 0 for NULL */
static uint32_t sb_str(sbuf_t *sb, const char *s) {
    if (!s) return 0;
    return sb_add(sb, s, strlen(s) + 1);
}

/* ------------------------------------------------------------------------------------------------------------
 * wire name helpers
 * ------------------------------------------------------------------------------------------------------------ */

/* Length (with the root label) of the uncompressed name at p, -1 if it does not end within avail octets or has a
 * compression pointer / reserved label type. */
static int wire_name_len(const uint8_t *p, size_t avail) {
    size_t i = 0;
    while (i < avail) {
        uint8_t l = p[i];
        if (l == 0) return (int)(i + 1);
        if (l > 63 || i + 1 + l > avail) return -1;
        i += 1 + (size_t)l;
    }
    return -1;
}

/* ------------------------------------------------------------------------------------------------------------
 * freeze
 * ------------------------------------------------------------------------------------------------------------ */
typedef struct {
    const char *text;
    uint32_t hash;
    uint32_t count;
    uint32_t first_rec;
    uint32_t cursor;
} tmp_name_t;

typedef struct {
    uint32_t *tab;      /* name id + 1, 0 = empty */
    size_t mask;
    tmp_name_t *names;
    uint32_t n_names;
} tmp_index_t;

static uint32_t tmp_find(const tmp_index_t *ix, const char *name, uint32_t hash) {
    size_t s = hash & ix->mask;
    for (;;) {
        uint32_t v = ix->tab[s];
        if (v == 0) return ZONE_IMAGE_NONE;
        const tmp_name_t *tn = &ix->names[v - 1];
        if (tn->hash == hash && domain_names_match_ci(tn->text, name)) return v - 1;
        s = (s + 1) & ix->mask;
    }
}

/* the owner wire the record serializes with: its preparsed name_wire, else what the text encodes to; 0 = none */
static int rec_owner_wire(const dns_record_t *rec, const uint8_t **wire, uint8_t *tmp /* 256 */) {
    if (rec->name_wire && rec->name_wire_len > 0) {
        *wire = rec->name_wire;
        return rec->name_wire_len;
    }
    long w = write_uncompressed_name_ext(tmp, 0, 256, rec->name, false);
    if (w <= 0) return 0;
    *wire = tmp;
    return (int)w;
}

static uint16_t rec_class(const dns_record_t *rec) {
    uint16_t class_val = rec->class_val;
    if (class_val == 0) {
        class_val = 1;
        if (rec->class_str) {
            if (strcasecmp(rec->class_str, "CH") == 0) class_val = 3;
            else if (strcasecmp(rec->class_str, "NONE") == 0) class_val = 254;
            else if (strcasecmp(rec->class_str, "ANY") == 0) class_val = 255;
        }
    }
    return class_val;
}

/* the TTL serialize_dns_record() writes for rec with no override */
static uint32_t rec_ttl(const dns_record_t *rec) {
    uint32_t ttl = rec->ttl_value;
    if (ttl == 0 && rec->ttl && *rec->ttl) ttl = parse_ttl_value(rec->ttl);
    if (ttl > 0x7FFFFFFF) ttl = 0x7FFFFFFF;
    return ttl;
}

static size_t round8(size_t v) { return (v + 7) & ~(size_t)7; }

/* zone level tables (tinydns locations, $LOCATION-TAG / $ECS-SUBNET-TAG definitions, ECS trusted resolvers) */
static void put_str(sbuf_t *sb, const char *s) {
    if (!s) { sb_u32(sb, 0xFFFFFFFFu); return; }
    size_t n = strlen(s);
    sb_u32(sb, (uint32_t)n);
    sb_add(sb, s, n);
}

static void put_tags(sbuf_t *sb, const ecs_tag_def_t *tags, int count) {
    sb_u32(sb, (uint32_t)(count > 0 && tags ? count : 0));
    if (count <= 0 || !tags) return;
    for (int i = 0; i < count; i++) {
        put_str(sb, tags[i].tag);
        int nc = (tags[i].cidrs && tags[i].cidr_count > 0) ? tags[i].cidr_count : 0;
        sb_u32(sb, (uint32_t)nc);
        for (int j = 0; j < nc; j++) {
            put_str(sb, tags[i].cidrs[j].cidr);
            cidr_entry_t parsed = tags[i].cidrs[j].parsed;
            sb_add(sb, &parsed, sizeof(parsed));
        }
    }
}

static void build_zattr(sbuf_t *sb, const zone_arena_t *a) {
    int nloc = (a->locations && a->location_count > 0) ? a->location_count : 0;
    sb_u32(sb, (uint32_t)nloc);
    for (int i = 0; i < nloc; i++) {
        tinydns_location_entry_t e = a->locations[i];
        sb_add(sb, &e, sizeof(e));
    }
    put_tags(sb, a->bind_location_tags, a->bind_location_tag_count);
    put_tags(sb, a->bind_ecs_tags, a->bind_ecs_tag_count);
    int ntr = (a->bind_ecs_trusted_resolvers && a->bind_ecs_trusted_resolver_count > 0) ? a->bind_ecs_trusted_resolver_count : 0;
    sb_u32(sb, (uint32_t)ntr);
    for (int i = 0; i < ntr; i++) put_str(sb, a->bind_ecs_trusted_resolvers[i]);
}

static bool rec_in_arena(const zone_arena_t *a, const dns_record_t *r, size_t *idx) {
    if (!r || r < a->records || r >= a->records + a->count) return false;
    *idx = (size_t)(r - a->records);
    return true;
}

zone_image_t *zone_image_freeze(const zone_arena_t *a, const char *apex) {
    if (!a || !a->hash_table) {
        syslog(LOG_ERR, "[Image] freeze: the builder has no index (build_zone_index() not run)");
        return NULL;
    }
    const size_t n = a->count;
    if (n >= 0x7FFFFFFFu) return NULL;

    zone_image_t *img = NULL;
    tmp_index_t ix = { 0 };
    uint32_t *rec_rr = NULL;     /* record index -> image RR index (ZONE_IMAGE_NONE: tombstone) */
    uint32_t *rr_rec = NULL;     /* image RR index -> record index */
    zone_image_name_t *names = NULL;
    zone_image_rr_t *rrs = NULL;
    zone_image_ext_t *exts = NULL;
    size_t n_ext = 0, cap_ext = 0;
    uint32_t *canon = NULL, *nsec = NULL, *n3entries = NULL, *glue = NULL, *hashtab = NULL;
    zone_image_n3chain_t *n3chains = NULL;
    uint8_t *cap = NULL;
    uint8_t *seen = NULL;
    sbuf_t sb = { 0 }, za = { 0 };
    uint32_t n_names = 0, n_rrs = 0;
    uint32_t n_glue = 0, n_n3ch = 0, n_n3e = 0;
    bool ok = false;

    /* strings area: offset 0 is "none", so the first 8 octets are padding */
    { uint8_t pad[8] = { 0 }; sb_add(&sb, pad, sizeof(pad)); }

    size_t tab_size = 8;
    while (tab_size < n * 2 + 2) tab_size <<= 1;
    ix.tab = calloc(tab_size, sizeof(uint32_t));
    ix.mask = tab_size - 1;
    ix.names = malloc((n ? n : 1) * sizeof(tmp_name_t));
    uint32_t *rec_name = malloc((n ? n : 1) * sizeof(uint32_t));
    rec_rr = malloc((n ? n : 1) * sizeof(uint32_t));
    cap = malloc(65535);
    uint8_t *chk = malloc(65540);
    if (!ix.tab || !ix.names || !rec_name || !rec_rr || !cap || !chk) IMG_FAIL();

    /* 1. owners: one name id per owner (case-insensitive, with or without the root dot), first appearance order */
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = &a->records[i];
        rec_name[i] = ZONE_IMAGE_NONE;
        rec_rr[i] = ZONE_IMAGE_NONE;
        if (!r->name) continue;
        uint32_t h = dns_name_hash_ci(r->name);
        uint32_t id = tmp_find(&ix, r->name, h);
        if (id == ZONE_IMAGE_NONE) {
            id = ix.n_names++;
            ix.names[id] = (tmp_name_t){ r->name, h, 0, (uint32_t)i, 0 };
            size_t s = h & ix.mask;
            while (ix.tab[s]) s = (s + 1) & ix.mask;
            ix.tab[s] = id + 1;
        }
        ix.names[id].count++;
        rec_name[i] = id;
        n_rrs++;
    }
    n_names = ix.n_names;
    if (n_names >= 0x7FFFFFFFu) IMG_FAIL();

    /* 2. place the RRs: names in first-appearance order, file order within a name */
    {
        uint32_t run = 0;
        for (uint32_t id = 0; id < n_names; id++) {
            if (ix.names[id].count > ZONE_IMAGE_NAME_COUNT_MASK) {
                syslog(LOG_ERR, "[Image] freeze: more than %u RRs at one owner", ZONE_IMAGE_NAME_COUNT_MASK);
                IMG_FAIL();
            }
            ix.names[id].cursor = run;
            run += ix.names[id].count;
        }
    }
    names = calloc(n_names ? n_names : 1, sizeof(*names));
    rrs = calloc(n_rrs ? n_rrs : 1, sizeof(*rrs));
    rr_rec = malloc((n_rrs ? n_rrs : 1) * sizeof(uint32_t));
    if (!names || !rrs || !rr_rec) IMG_FAIL();
    {
        uint32_t run = 0;
        for (uint32_t id = 0; id < n_names; id++) {
            names[id].first_rr = run;
            names[id].rr_count_flags = ix.names[id].count;
            names[id].canon_rank = ZONE_IMAGE_NONE;
            names[id].hash = ix.names[id].hash;
            run += ix.names[id].count;
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (rec_name[i] == ZONE_IMAGE_NONE) continue;
        uint32_t idx = ix.names[rec_name[i]].cursor++;
        rec_rr[i] = idx;
        rr_rec[idx] = (uint32_t)i;
    }

    /* 3. owner strings (first record of each name) */
    for (uint32_t id = 0; id < n_names; id++) {
        const dns_record_t *r = &a->records[ix.names[id].first_rec];
        names[id].text_off = sb_str(&sb, r->name);
        const uint8_t *w;
        uint8_t wtmp[256];
        int wl = rec_owner_wire(r, &w, wtmp);
        names[id].wire_off = wl > 0 ? sb_add(&sb, w, (size_t)wl) : 0;
    }

    /* the apex, for the name flags */
    uint32_t apex_id = apex ? tmp_find(&ix, apex, dns_name_hash_ci(apex)) : ZONE_IMAGE_NONE;

    /* 4. RRs */
    for (uint32_t k = 0; k < n_rrs; k++) {
        const dns_record_t *r = &a->records[rr_rec[k]];
        zone_image_rr_t *rr = &rrs[k];
        uint32_t id = rec_name[rr_rec[k]];
        rr->name_id = id;
        rr->type = r->type_code;
        rr->class_val = rec_class(r);
        rr->ttl = rec_ttl(r);
        bool raw = r->generic_data != NULL || r->class_val == DNS_CLASS_KARIDNS_EXT;
        if (raw) rr->flags |= ZONE_IMAGE_RR_RAW;
        if (!(r->name_wire && r->name_wire_len > 0)) rr->flags |= ZONE_IMAGE_RR_NO_NAMEWIRE;

        /* RDATA: what serialize_dns_record() writes with no compression context */
        uint16_t len = 0;
        if (r->class_val == DNS_CLASS_KARIDNS_EXT && !r->generic_data) memset(cap, 0, 65535);
        if (serialize_dns_record(cap, 65535, &len, r, NULL, ".", 0xFFFFFFFFu) != 0 || len < 11 || cap[0] != 0) {
            syslog(LOG_ERR, "[Image] freeze: '%s' type %u cannot be written in wire format", r->name, r->type_code);
            IMG_FAIL();
        }
        size_t rdlen = ((size_t)cap[9] << 8) | cap[10];
        if (11 + rdlen != len || rdlen > IMG_MAX_RDLEN) IMG_FAIL();
        const uint8_t *rd = cap + 11;
        uint8_t minfo[512];
        if (!raw && r->type_code == 14) {
            /* serialize_dns_record() lowercases a MINFO name without a context but keeps its case with one */
            if (r->rdata_count < 2) IMG_FAIL();
            long w1 = write_uncompressed_name_ext(minfo, 0, sizeof(minfo), r->rdata[0], false);
            if (w1 < 0) IMG_FAIL();
            long w2 = write_uncompressed_name_ext(minfo, (size_t)w1, sizeof(minfo), r->rdata[1], false);
            if (w2 < 0) IMG_FAIL();
            rd = minfo;
            rdlen = (size_t)(w1 + w2);
        }
        /* room serialize_dns_record() wants beyond the RDATA (base64 fields: it checks the padded size first) */
        if (!raw && rdlen > 0 && r->type_code != 14 && len <= 65533) {
            unsigned slack = 0;
            for (; slack <= 2; slack++) {
                uint16_t l2 = 0;
                if (serialize_dns_record(chk, (size_t)len + slack, &l2, r, NULL, ".", 0xFFFFFFFFu) == 0) break;
            }
            if (slack > 2) IMG_FAIL();
            rr->flags = (uint16_t)(rr->flags | (slack << ZONE_IMAGE_RR_SLACK_SHIFT));
        }
        rr->rdata_len = (uint16_t)rdlen;
        rr->rdata_off = rdlen ? sb_add(&sb, rd, rdlen) : 0;

        /* extras */
        const uint8_t *rw;
        uint8_t wtmp[256];
        int rwl = rec_owner_wire(r, &rw, wtmp);
        bool alt = strcmp(r->name, ix.names[id].text) != 0;
        if (!alt) {
            /* same spelling: the wire form must agree too (it does when name_wire was derived from name) */
            const uint8_t *ew = names[id].wire_off ? sb.p + names[id].wire_off : NULL;
            if ((ew != NULL) != (rwl > 0)) alt = true;
            else if (ew && wire_name_len(ew, 256) != rwl) alt = true;
            else if (ew && memcmp(ew, rw, (size_t)rwl) != 0) alt = true;
        }
        bool need_ext = alt || r->tinydns_ttd != 0 || r->tinydns_ttl_countdown || r->tinydns_loc[0] || r->tinydns_loc[1] ||
                        r->ecs_subnet_tag || r->bind_location_tag;
        if (need_ext) {
            if (n_ext == cap_ext) {
                size_t ncap = cap_ext ? cap_ext * 2 : 8;
                zone_image_ext_t *ne = realloc(exts, ncap * sizeof(*exts));
                if (!ne) IMG_FAIL();
                exts = ne;
                cap_ext = ncap;
            }
            zone_image_ext_t *e = &exts[n_ext];
            memset(e, 0, sizeof(*e));
            e->ttd = (int64_t)r->tinydns_ttd;
            if (r->tinydns_ttl_countdown) e->flags |= ZONE_IMAGE_EXT_COUNTDOWN;
            e->loc[0] = r->tinydns_loc[0];
            e->loc[1] = r->tinydns_loc[1];
            e->ecs_tag_off = sb_str(&sb, r->ecs_subnet_tag);
            e->loc_tag_off = sb_str(&sb, r->bind_location_tag);
            if (alt) {
                e->alt_text_off = sb_str(&sb, r->name);
                e->alt_wire_off = rwl > 0 ? sb_add(&sb, rw, (size_t)rwl) : 0;
            }
            n_ext++;
            rr->ext_idx = (uint32_t)n_ext;
        }
    }
    if (sb.oom || sb.len > 0xFFFFF000u) IMG_FAIL();

    /* 5. name flags */
    for (uint32_t k = 0; k < n_rrs; k++) {
        uint32_t id = rrs[k].name_id;
        if (rrs[k].type == 2 && id != apex_id) names[id].rr_count_flags |= ZONE_IMAGE_NAME_CUT;
        else if (rrs[k].type == 39) names[id].rr_count_flags |= ZONE_IMAGE_NAME_DNAME;
        else if (rrs[k].type == 47) names[id].rr_count_flags |= ZONE_IMAGE_NAME_NSEC;
    }
    for (uint32_t id = 0; id < n_names; id++) {
        const char *t = ix.names[id].text;
        if (t[0] == '*' && t[1] == '.') names[id].rr_count_flags |= ZONE_IMAGE_NAME_WILDCARD;
        if (id == apex_id) {
            names[id].rr_count_flags |= ZONE_IMAGE_NAME_APEX;
            names[id].rr_count_flags &= ~ZONE_IMAGE_NAME_CUT;
        }
    }

    /* 6. canonical order, from the builder's sorted_unique_names */
    if (a->sorted_unique_count > 0) {
        canon = malloc(a->sorted_unique_count * sizeof(uint32_t));
        if (!canon) IMG_FAIL();
        for (size_t i = 0; i < a->sorted_unique_count; i++) {
            const char *t = a->sorted_unique_names[i];
            uint32_t id = t ? tmp_find(&ix, t, dns_name_hash_ci(t)) : ZONE_IMAGE_NONE;
            if (id == ZONE_IMAGE_NONE) {
                syslog(LOG_ERR, "[Image] freeze: canonical name '%s' has no RR", t ? t : "?");
                IMG_FAIL();
            }
            canon[i] = id;
            names[id].canon_rank = (uint32_t)i;
        }
    } else if (n_names > 0) {
        syslog(LOG_ERR, "[Image] freeze: the builder's canonical index is empty");
        IMG_FAIL();
    }

    /* 7. NSEC index */
    if (a->nsec_count > 0) {
        nsec = malloc(a->nsec_count * sizeof(uint32_t));
        if (!nsec) IMG_FAIL();
        for (size_t i = 0; i < a->nsec_count; i++) {
            size_t ri;
            if (!rec_in_arena(a, a->nsec_records[i], &ri) || rec_rr[ri] == ZONE_IMAGE_NONE) IMG_FAIL();
            nsec[i] = rec_rr[ri];
        }
    }

    /* 8. NSEC3 chains and parameters */
    uint32_t n3_param_rr = ZONE_IMAGE_NONE, n3_chain = ZONE_IMAGE_NONE, n3_salt_off = 0;
    if (a->nsec3_chain_count > 0) {
        size_t total = 0;
        for (size_t c = 0; c < a->nsec3_chain_count; c++) total += a->nsec3_chains[c].count;
        n3chains = calloc(a->nsec3_chain_count, sizeof(*n3chains));
        n3entries = malloc((total ? total : 1) * sizeof(uint32_t));
        if (!n3chains || !n3entries) IMG_FAIL();
        for (size_t c = 0; c < a->nsec3_chain_count; c++) {
            const nsec3_chain_t *ch = &a->nsec3_chains[c];
            /* the salt as the first RR of the chain carries it on the wire (the chain was grouped by its text) */
            size_t ri0;
            if (ch->count == 0 || !rec_in_arena(a, ch->entries[0].rec, &ri0) || rec_rr[ri0] == ZONE_IMAGE_NONE) IMG_FAIL();
            const zone_image_rr_t *r0 = &rrs[rec_rr[ri0]];
            const uint8_t *rd0 = sb.p + r0->rdata_off;
            if (r0->rdata_len < 5 || (size_t)rd0[4] + 5 > r0->rdata_len) IMG_FAIL();
            const uint8_t *salt = rd0 + 5;
            size_t sl = rd0[4];
            n3chains[c].first = n_n3e;
            n3chains[c].count = (uint32_t)ch->count;
            n3chains[c].algorithm = ch->algorithm;
            n3chains[c].iterations = ch->iterations;
            n3chains[c].salt_len = (uint8_t)sl;
            { uint8_t keep[255]; memcpy(keep, salt, sl); n3chains[c].salt_off = sl ? sb_add(&sb, keep, sl) : 0; }
            for (size_t e = 0; e < ch->count; e++) {
                size_t ri;
                if (!rec_in_arena(a, ch->entries[e].rec, &ri) || rec_rr[ri] == ZONE_IMAGE_NONE) IMG_FAIL();
                n3entries[n_n3e++] = rec_rr[ri];
            }
        }
        n_n3ch = (uint32_t)a->nsec3_chain_count;
    }
    if (a->nsec3_active.param) {
        size_t ri;
        if (!rec_in_arena(a, a->nsec3_active.param, &ri) || rec_rr[ri] == ZONE_IMAGE_NONE) IMG_FAIL();
        n3_param_rr = rec_rr[ri];
        if (a->nsec3_active.chain) {
            ptrdiff_t ci = a->nsec3_active.chain - a->nsec3_chains;
            if (ci < 0 || (size_t)ci >= a->nsec3_chain_count) IMG_FAIL();
            n3_chain = (uint32_t)ci;
        }
        if (a->nsec3_active.salt_len) n3_salt_off = sb_add(&sb, a->nsec3_active.salt, a->nsec3_active.salt_len);
    }

    /* 9. glue targets: names NS / MX / SRV RRs point to that have A / AAAA RRs here (first appearance order) */
    seen = calloc(n_names ? n_names : 1, 1);
    glue = malloc((n_names ? n_names : 1) * sizeof(uint32_t));
    if (!seen || !glue) IMG_FAIL();
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = &a->records[i];
        const char *tgt = NULL;
        if (!r->name) continue;
        if (r->type_code == 2 && r->rdata_count >= 1) tgt = r->rdata[0];
        else if (r->type_code == 15 && r->rdata_count >= 2) tgt = r->rdata[1];
        else if (r->type_code == 33 && r->rdata_count >= 4) tgt = r->rdata[3];
        if (!tgt || *tgt == '\0') continue;
        uint32_t id = tmp_find(&ix, tgt, dns_name_hash_ci(tgt));
        if (id == ZONE_IMAGE_NONE || seen[id]) continue;
        seen[id] = 1;
        bool has_addr = false;
        for (uint32_t k = names[id].first_rr, e = k + (names[id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK); k < e; k++)
            if (rrs[k].type == 1 || rrs[k].type == 28) { has_addr = true; break; }
        if (has_addr) glue[n_glue++] = id;
    }

    /* 10. name hash table, load factor <= 0.75 */
    size_t hash_size = 4;
    while (hash_size * 3 < (size_t)n_names * 4) hash_size <<= 1;
    hashtab = calloc(hash_size, sizeof(uint32_t));
    if (!hashtab) IMG_FAIL();
    for (uint32_t id = 0; id < n_names; id++) {
        size_t s = names[id].hash & (hash_size - 1);
        while (hashtab[s]) s = (s + 1) & (hash_size - 1);
        hashtab[s] = id + 1;
    }

    /* 11. zone level tables */
    build_zattr(&za, a);
    if (sb.oom || za.oom) IMG_FAIL();

    /* 12. assemble */
    {
        size_t n_canon = a->sorted_unique_count;
        size_t off = sizeof(zone_image_t);
        size_t o_names = off;  off = round8(off + (size_t)n_names * sizeof(zone_image_name_t));
        size_t o_rrs = off;    off = round8(off + (size_t)n_rrs * sizeof(zone_image_rr_t));
        size_t o_ext = off;    off = round8(off + n_ext * sizeof(zone_image_ext_t));
        size_t o_n3c = off;    off = round8(off + (size_t)n_n3ch * sizeof(zone_image_n3chain_t));
        size_t o_hash = off;   off = round8(off + hash_size * sizeof(uint32_t));
        size_t o_canon = off;  off = round8(off + n_canon * sizeof(uint32_t));
        size_t o_nsec = off;   off = round8(off + a->nsec_count * sizeof(uint32_t));
        size_t o_n3e = off;    off = round8(off + (size_t)n_n3e * sizeof(uint32_t));
        size_t o_glue = off;   off = round8(off + (size_t)n_glue * sizeof(uint32_t));
        size_t o_zattr = off;  off = round8(off + za.len);
        size_t o_str = off;    off = round8(off + sb.len);
        if (off > 0xFFFFF000u) {
            syslog(LOG_ERR, "[Image] freeze: the image would exceed 4 GiB");
            IMG_FAIL();
        }
        img = calloc(1, off);
        if (!img) IMG_FAIL();
        uint8_t *b = (uint8_t *)img;
        img->magic = ZONE_IMAGE_MAGIC;
        img->version = ZONE_IMAGE_VERSION;
        img->total_size = (uint32_t)off;
        img->flags = (a->is_tinydns_format ? ZONE_IMAGE_F_TINYDNS : 0) | (n_ext ? ZONE_IMAGE_F_EXT : 0);
        img->n_names = n_names; img->n_rrs = n_rrs; img->n_ext = (uint32_t)n_ext;
        img->n_canon = (uint32_t)n_canon; img->n_nsec = (uint32_t)a->nsec_count;
        img->n_n3chains = n_n3ch; img->n_n3entries = n_n3e; img->n_glue = n_glue; img->hash_size = (uint32_t)hash_size;
        img->off_names = (uint32_t)o_names; img->off_rrs = (uint32_t)o_rrs; img->off_ext = (uint32_t)o_ext;
        img->off_hash = (uint32_t)o_hash; img->off_canon = (uint32_t)o_canon; img->off_nsec = (uint32_t)o_nsec;
        img->off_n3chains = (uint32_t)o_n3c; img->off_n3entries = (uint32_t)o_n3e; img->off_glue = (uint32_t)o_glue;
        img->off_zattr = (uint32_t)o_zattr; img->off_strings = (uint32_t)o_str;
        img->zattr_len = (uint32_t)za.len;
        img->apex_name = apex_id;
        img->n3_param_rr = n3_param_rr; img->n3_chain = n3_chain; img->n3_salt_off = n3_salt_off;
        img->n3_iterations = a->nsec3_active.param ? a->nsec3_active.iterations : 0;
        img->n3_algorithm = a->nsec3_active.param ? a->nsec3_active.algorithm : 0;
        img->n3_salt_len = a->nsec3_active.param ? a->nsec3_active.salt_len : 0;
        if (n_names) memcpy(b + o_names, names, (size_t)n_names * sizeof(*names));
        if (n_rrs) memcpy(b + o_rrs, rrs, (size_t)n_rrs * sizeof(*rrs));
        if (n_ext) memcpy(b + o_ext, exts, n_ext * sizeof(*exts));
        if (n_n3ch) memcpy(b + o_n3c, n3chains, (size_t)n_n3ch * sizeof(*n3chains));
        memcpy(b + o_hash, hashtab, hash_size * sizeof(uint32_t));
        if (n_canon) memcpy(b + o_canon, canon, n_canon * sizeof(uint32_t));
        if (a->nsec_count) memcpy(b + o_nsec, nsec, a->nsec_count * sizeof(uint32_t));
        if (n_n3e) memcpy(b + o_n3e, n3entries, (size_t)n_n3e * sizeof(uint32_t));
        if (n_glue) memcpy(b + o_glue, glue, (size_t)n_glue * sizeof(uint32_t));
        if (za.len) memcpy(b + o_zattr, za.p, za.len);
        memcpy(b + o_str, sb.p, sb.len);
    }
    ok = true;

out:
    if (!ok) {
        free(img);
        img = NULL;
    }
    free(ix.tab); free(ix.names); free(rec_name); free(rec_rr); free(rr_rec); free(names); free(rrs); free(exts);
    free(canon); free(nsec); free(n3chains); free(n3entries); free(glue); free(hashtab); free(cap); free(chk); free(seen);
    free(sb.p); free(za.p);
    return img;
}

void zone_image_free(zone_image_t *img) { free(img); }

/* ------------------------------------------------------------------------------------------------------------
 * lookups
 * ------------------------------------------------------------------------------------------------------------ */
uint32_t zone_image_find_name(const zone_image_t *img, const char *name) {
    if (!img || !name || img->n_names == 0) return ZONE_IMAGE_NONE;
    uint32_t h = dns_name_hash_ci(name);
    const uint32_t *tab = zone_image_u32s(img, img->off_hash);
    const zone_image_name_t *names = zone_image_names(img);
    size_t mask = (size_t)img->hash_size - 1;
    for (size_t s = h & mask;; s = (s + 1) & mask) {
        uint32_t v = tab[s];
        if (v == 0) return ZONE_IMAGE_NONE;
        if (names[v - 1].hash == h && domain_names_match_ci(zone_image_str(img, names[v - 1].text_off), name)) return v - 1;
    }
}

uint32_t zone_image_rrset_next(const zone_image_t *img, uint32_t name_id, uint16_t type, uint32_t from) {
    const zone_image_name_t *nm = &zone_image_names(img)[name_id];
    uint32_t end = nm->first_rr + (nm->rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
    const zone_image_rr_t *rrs = zone_image_rrs(img);
    if (from < nm->first_rr) from = nm->first_rr;
    for (uint32_t k = from; k < end; k++)
        if (rrs[k].type == type) return k;
    return ZONE_IMAGE_NONE;
}

uint32_t zone_image_canon_floor(const zone_image_t *img, const char *name, bool *exact) {
    if (exact) *exact = false;
    if (!img || !name || img->n_canon == 0) return ZONE_IMAGE_NONE;
    uint32_t lo = 0, hi = img->n_canon, best = ZONE_IMAGE_NONE;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = compare_canonical_name(zone_image_name_text(img, zone_image_canon_name(img, mid)), name);
        if (c <= 0) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (exact && best != ZONE_IMAGE_NONE)
        *exact = compare_canonical_name(zone_image_name_text(img, zone_image_canon_name(img, best)), name) == 0;
    return best;
}

uint32_t zone_image_nsec_floor(const zone_image_t *img, const char *name) {
    if (!img || !name || img->n_nsec == 0) return ZONE_IMAGE_NONE;
    uint32_t lo = 0, hi = img->n_nsec, best = ZONE_IMAGE_NONE;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t rr = zone_image_nsec_rr(img, mid);
        if (compare_canonical_name(zone_image_name_text(img, zone_image_rr_name(img, rr)), name) <= 0) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return best;
}

const char *zone_image_n3chain_hash(const zone_image_t *img, uint32_t c, uint32_t i, size_t *len) {
    uint32_t rr = zone_image_n3chain_rr(img, c, i);
    const char *t = zone_image_name_text(img, zone_image_rr_name(img, rr));
    const char *dot = strchr(t, '.');
    if (len) *len = dot ? (size_t)(dot - t) : strlen(t);
    return t;
}

uint32_t zone_image_n3chain_find(const zone_image_t *img, uint8_t algorithm, uint16_t iterations,
                                 const uint8_t *salt, size_t salt_len) {
    for (uint32_t c = 0; c < img->n_n3chains; c++) {
        const zone_image_n3chain_t *ch = &zone_image_n3chains(img)[c];
        if (ch->algorithm == algorithm && ch->iterations == iterations && ch->salt_len == salt_len &&
            (salt_len == 0 || memcmp(zone_image_bytes(img, ch->salt_off), salt, salt_len) == 0))
            return c;
    }
    return ZONE_IMAGE_NONE;
}

uint32_t zone_image_n3chain_lower_bound(const zone_image_t *img, uint32_t c, const char *hash, size_t hash_len) {
    uint32_t lo = 0, hi = zone_image_n3chains(img)[c].count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        size_t el;
        const char *eh = zone_image_n3chain_hash(img, c, mid, &el);
        int cmp = strncasecmp(eh, hash, el < hash_len ? el : hash_len);
        if (cmp == 0) cmp = el < hash_len ? -1 : (el > hash_len ? 1 : 0);
        if (cmp < 0) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/* ------------------------------------------------------------------------------------------------------------
 * writing an RR
 * ------------------------------------------------------------------------------------------------------------ */
int image_serialize_rr(const zone_image_t *img, uint32_t rr_idx, uint8_t *res, size_t max_res_len, uint16_t *offset_ptr,
                       compress_ctx_t *comp_ctx, const char *owner_name, uint32_t ttl) {
    const zone_image_rr_t *rr = &zone_image_rrs(img)[rr_idx];
    const zone_image_name_t *nm = &zone_image_names(img)[rr->name_id];
    const zone_image_ext_t *ext = zone_image_rr_ext(img, rr_idx);
    uint16_t offset = *offset_ptr;
    uint16_t rec_type = rr->type;

    if (is_meta_rrtype(rec_type)) return -1;
    if ((size_t)offset + DNS_HEADER_SIZE > max_res_len) return -1;

    /* owner */
    {
        bool alt = ext && ext->alt_text_off;
        uint32_t woff = alt ? ext->alt_wire_off : nm->wire_off;
        if (!owner_name && woff && (comp_ctx || !(rr->flags & ZONE_IMAGE_RR_NO_NAMEWIRE))) {
            const uint8_t *w = zone_image_bytes(img, woff);
            if (!comp_ctx) {
                int wl = wire_name_len(w, 256);
                if (wl < 0 || (size_t)(offset + wl) > max_res_len) return -1;
                memcpy(&res[offset], w, (size_t)wl);
                offset = (uint16_t)(offset + wl);
            } else if (compress_name(res, &offset, w, comp_ctx, max_res_len) != 0) {
                return -1;
            }
        } else {
            const char *text = owner_name ? owner_name
                             : (alt ? zone_image_str(img, ext->alt_text_off) : zone_image_str(img, nm->text_off));
            if (write_dns_name_str(res, &offset, text, comp_ctx, max_res_len) != 0) return -1;
        }
    }

    if ((size_t)offset + 10 > max_res_len) return -1;
    res[offset++] = rec_type >> 8; res[offset++] = rec_type & 0xFF;
    res[offset++] = rr->class_val >> 8; res[offset++] = rr->class_val & 0xFF;
    if (ttl > 0x7FFFFFFF) ttl = 0x7FFFFFFF;
    res[offset++] = ttl >> 24; res[offset++] = (ttl >> 16) & 0xFF; res[offset++] = (ttl >> 8) & 0xFF; res[offset++] = ttl & 0xFF;
    uint16_t rdlength_idx = offset;
    offset += 2;

    const uint8_t *rd = zone_image_bytes(img, rr->rdata_off);
    size_t len = rr->rdata_len;
    const dns_rdata_name_layout_t *lay = (rr->flags & ZONE_IMAGE_RR_RAW) ? NULL : dns_rdata_name_layout(rec_type);
    if (!lay || !lay->compress) {
        if (len > 0) {
            if ((size_t)offset + len > max_res_len) return -1;
            memcpy(&res[offset], rd, len);
            offset = (uint16_t)(offset + len);
        }
    } else {
        /* RFC 1035 §4.1.4: the names of these types go through the compression table, in order */
        size_t pos = 0;
        if (lay->skip) {
            if (len < lay->skip || (size_t)offset + lay->skip > max_res_len) return -1;
            memcpy(&res[offset], rd, lay->skip);
            offset = (uint16_t)(offset + lay->skip);
            pos = lay->skip;
        }
        for (unsigned k = 0; k < lay->nnames; k++) {
            int wl = pos < len ? wire_name_len(rd + pos, len - pos) : -1;
            if (wl < 0) return -1;
            if (comp_ctx) {
                if (compress_name(res, &offset, rd + pos, comp_ctx, max_res_len) != 0) return -1;
            } else {
                if ((size_t)offset + (size_t)wl > max_res_len) return -1;
                memcpy(&res[offset], rd + pos, (size_t)wl);
                if (rec_type == 14) dns_canonical_downcase_rdata(2 /* one name */, &res[offset], (size_t)wl);
                offset = (uint16_t)(offset + wl);
            }
            pos += (size_t)wl;
        }
        if (pos < len) {
            if ((size_t)offset + (len - pos) > max_res_len) return -1;
            memcpy(&res[offset], rd + pos, len - pos);
            offset = (uint16_t)(offset + (len - pos));
        }
    }

    unsigned slack = (rr->flags & ZONE_IMAGE_RR_SLACK_MASK) >> ZONE_IMAGE_RR_SLACK_SHIFT;
    if (slack && (size_t)offset + slack > max_res_len) return -1;
    uint16_t rdlength = (uint16_t)(offset - rdlength_idx - 2);
    res[rdlength_idx] = rdlength >> 8; res[rdlength_idx + 1] = rdlength & 0xFF;
    *offset_ptr = offset;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------
 * decoding accessors
 * ------------------------------------------------------------------------------------------------------------ */
int zone_image_rr_target(const zone_image_t *img, uint32_t rr, char *buf, size_t cap) {
    const dns_rdata_name_layout_t *lay = dns_rdata_name_layout(zone_image_rr_type(img, rr));
    size_t len = zone_image_rr_rdlen(img, rr);
    if (!lay || lay->skip >= len) return -1;
    size_t next;
    return expand_wire_name_to_buffer(zone_image_rr_rdata(img, rr), len, lay->skip, &next, buf, cap) < 0 ? -1 : 0;
}

int zone_image_soa(const zone_image_t *img, uint32_t rr, char *mname, size_t mcap, char *rname, size_t rcap,
                   zone_image_soa_t *nums) {
    if (zone_image_rr_type(img, rr) != 6) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    size_t len = zone_image_rr_rdlen(img, rr), p = 0, next;
    char tmp[DNS_NAME_TEXT_SIZE];
    if (len == 0) return -1;
    if (expand_wire_name_to_buffer(rd, len, p, &next, mname ? mname : tmp, mname ? mcap : sizeof(tmp)) < 0) return -1;
    p = next;
    if (p >= len) return -1;
    if (expand_wire_name_to_buffer(rd, len, p, &next, rname ? rname : tmp, rname ? rcap : sizeof(tmp)) < 0) return -1;
    p = next;
    if (p + 20 != len) return -1;
    if (nums) {
        uint32_t v[5];
        for (int j = 0; j < 5; j++)
            v[j] = ((uint32_t)rd[p + 4 * j] << 24) | ((uint32_t)rd[p + 4 * j + 1] << 16) |
                   ((uint32_t)rd[p + 4 * j + 2] << 8) | rd[p + 4 * j + 3];
        nums->serial = v[0]; nums->refresh = v[1]; nums->retry = v[2]; nums->expire = v[3]; nums->minimum = v[4];
    }
    return 0;
}

int zone_image_mx_pref(const zone_image_t *img, uint32_t rr, uint16_t *pref) {
    if (zone_image_rr_type(img, rr) != 15 || zone_image_rr_rdlen(img, rr) < 3) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    *pref = (uint16_t)((rd[0] << 8) | rd[1]);
    return 0;
}

int zone_image_srv(const zone_image_t *img, uint32_t rr, uint16_t *priority, uint16_t *weight, uint16_t *port) {
    if (zone_image_rr_type(img, rr) != 33 || zone_image_rr_rdlen(img, rr) < 7) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    if (priority) *priority = (uint16_t)((rd[0] << 8) | rd[1]);
    if (weight) *weight = (uint16_t)((rd[2] << 8) | rd[3]);
    if (port) *port = (uint16_t)((rd[4] << 8) | rd[5]);
    return 0;
}

int zone_image_rrsig_covered(const zone_image_t *img, uint32_t rr, uint16_t *type_covered) {
    uint16_t t = zone_image_rr_type(img, rr);
    if ((t != 46 && t != 24) || zone_image_rr_rdlen(img, rr) < 18) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    *type_covered = (uint16_t)((rd[0] << 8) | rd[1]);
    return 0;
}

/* RFC 4034 §4.1.2: windows of (block number, length 1-32, bitmap) in ascending block order */
static bool bitmap_has(const uint8_t *bm, size_t len, uint16_t type) {
    size_t p = 0;
    while (p + 2 <= len) {
        unsigned win = bm[p], blen = bm[p + 1];
        if (blen == 0 || blen > 32 || p + 2 + blen > len) return false;
        if (win == (unsigned)(type >> 8)) {
            unsigned bit = type & 0xFF;
            return bit / 8 < blen && (bm[p + 2 + bit / 8] & (0x80 >> (bit % 8))) != 0;
        }
        if (win > (unsigned)(type >> 8)) return false;
        p += 2 + blen;
    }
    return false;
}

bool zone_image_rr_bitmap_has(const zone_image_t *img, uint32_t rr, uint16_t type) {
    uint16_t t = zone_image_rr_type(img, rr);
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    size_t len = zone_image_rr_rdlen(img, rr);
    if (t == 47) {
        int wl = len ? wire_name_len(rd, len) : -1;
        if (wl < 0) return false;
        return bitmap_has(rd + wl, len - (size_t)wl, type);
    }
    if (t == 50) {
        zone_image_nsec3_t v;
        if (zone_image_nsec3(img, rr, &v) != 0) return false;
        size_t consumed = (size_t)(v.next + v.next_len - rd);
        return bitmap_has(rd + consumed, len - consumed, type);
    }
    return false;
}

int zone_image_nsec3(const zone_image_t *img, uint32_t rr, zone_image_nsec3_t *out) {
    uint16_t t = zone_image_rr_type(img, rr);
    if (t != 50 && t != 51) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    size_t len = zone_image_rr_rdlen(img, rr);
    if (len < 5) return -1;
    size_t sl = rd[4], p = 5 + sl;
    if (p > len) return -1;
    memset(out, 0, sizeof(*out));
    out->algorithm = rd[0];
    out->flags = rd[1];
    out->iterations = (uint16_t)((rd[2] << 8) | rd[3]);
    out->salt = rd + 5;
    out->salt_len = (uint8_t)sl;
    if (t == 51) return p == len ? 0 : -1;
    if (p >= len || rd[p] == 0 || p + 1 + rd[p] > len) return -1;
    out->next_len = rd[p];
    out->next = rd + p + 1;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------
 * thaw
 * ------------------------------------------------------------------------------------------------------------ */
typedef struct {
    const uint8_t *p;
    size_t len, pos;
    bool bad;
} cursor_t;

static uint32_t get_u32(cursor_t *c) {
    uint32_t v = 0;
    if (c->bad || c->len - c->pos < 4) { c->bad = true; return 0; }
    memcpy(&v, c->p + c->pos, 4);
    c->pos += 4;
    return v;
}

static char *get_str(cursor_t *c) {
    uint32_t n = get_u32(c);
    if (c->bad || n == 0xFFFFFFFFu) return NULL;
    if (c->len - c->pos < n) { c->bad = true; return NULL; }
    char *s = malloc((size_t)n + 1);
    if (!s) { c->bad = true; return NULL; }
    memcpy(s, c->p + c->pos, n);
    s[n] = '\0';
    c->pos += n;
    return s;
}

static ecs_tag_def_t *get_tags(cursor_t *c, int *count_out) {
    uint32_t n = get_u32(c);
    *count_out = 0;
    if (c->bad || n == 0) return NULL;
    if (n > c->len) { c->bad = true; return NULL; }
    ecs_tag_def_t *tags = calloc(n, sizeof(*tags));
    if (!tags) { c->bad = true; return NULL; }
    *count_out = (int)n;
    for (uint32_t i = 0; i < n && !c->bad; i++) {
        tags[i].tag = get_str(c);
        uint32_t nc = get_u32(c);
        if (c->bad) break;
        if (nc > c->len) { c->bad = true; break; }
        if (nc) {
            tags[i].cidrs = calloc(nc, sizeof(ecs_cidr_entry_t));
            if (!tags[i].cidrs) { c->bad = true; break; }
            tags[i].cidr_count = (int)nc;
            for (uint32_t j = 0; j < nc && !c->bad; j++) {
                tags[i].cidrs[j].cidr = get_str(c);
                if (c->len - c->pos < sizeof(cidr_entry_t)) { c->bad = true; break; }
                memcpy(&tags[i].cidrs[j].parsed, c->p + c->pos, sizeof(cidr_entry_t));
                c->pos += sizeof(cidr_entry_t);
            }
        }
    }
    return tags;
}

static int thaw_zattr(const zone_image_t *img, zone_arena_t *a) {
    cursor_t c = { (const uint8_t *)img + img->off_zattr, img->zattr_len, 0, false };
    uint32_t nloc = get_u32(&c);
    if (!c.bad && nloc) {
        if ((size_t)nloc > c.len / sizeof(tinydns_location_entry_t)) return -1;
        a->locations = calloc(nloc, sizeof(tinydns_location_entry_t));
        if (!a->locations) return -1;
        for (uint32_t i = 0; i < nloc; i++) {
            memcpy(&a->locations[i], c.p + c.pos, sizeof(tinydns_location_entry_t));
            c.pos += sizeof(tinydns_location_entry_t);
        }
        a->location_count = (int)nloc;
    }
    a->bind_location_tags = get_tags(&c, &a->bind_location_tag_count);
    a->bind_ecs_tags = get_tags(&c, &a->bind_ecs_tag_count);
    uint32_t ntr = get_u32(&c);
    if (!c.bad && ntr) {
        if (ntr > c.len) return -1;
        a->bind_ecs_trusted_resolvers = calloc(ntr, sizeof(char *));
        if (!a->bind_ecs_trusted_resolvers) return -1;
        a->bind_ecs_trusted_resolver_count = (int)ntr;
        for (uint32_t i = 0; i < ntr && !c.bad; i++) a->bind_ecs_trusted_resolvers[i] = get_str(&c);
        if (!c.bad) a->bind_ecs_trusted_resolvers_parsed = acl_list_parse(a->bind_ecs_trusted_resolvers, (int)ntr);
    }
    return c.bad ? -1 : 0;
}

int zone_image_thaw(const zone_image_t *img, zone_arena_t *a) {
    if (!img || !a || img->magic != ZONE_IMAGE_MAGIC || a->count != 0 || a->records) return -1;
    const uint32_t n = img->n_rrs;
    size_t hint = (size_t)img->total_size * 2 + 4096;
    a->first_pool_cap = hint > (16u << 20) ? (16u << 20) : hint;
    a->records = calloc(n ? n : 1, sizeof(dns_record_t));
    a->records_cap = n ? n : 1;
    if (!a->records) return -1;
    uint8_t *pkt = malloc(255 + 10 + 65535);
    uint8_t *chk = malloc(65535);
    if (!pkt || !chk) { free(pkt); free(chk); return -1; }
    int rc = -1;
    for (uint32_t k = 0; k < n; k++) {
        const zone_image_rr_t *rr = &zone_image_rrs(img)[k];
        const zone_image_name_t *nm = &zone_image_names(img)[rr->name_id];
        const zone_image_ext_t *ext = zone_image_rr_ext(img, k);
        const char *text = zone_image_str(img, ext && ext->alt_text_off ? ext->alt_text_off : nm->text_off);
        uint32_t woff = ext && ext->alt_text_off ? ext->alt_wire_off : nm->wire_off;
        /* a synthetic RR in message form: owner, TYPE, CLASS, TTL, RDLENGTH, RDATA */
        size_t p = 0;
        if (woff) {
            const uint8_t *w = zone_image_bytes(img, woff);
            int wl = wire_name_len(w, 256);
            if (wl < 0) goto out;
            memcpy(pkt, w, (size_t)wl);
            p = (size_t)wl;
        } else {
            pkt[p++] = 0;
        }
        pkt[p++] = rr->type >> 8; pkt[p++] = rr->type & 0xFF;
        pkt[p++] = rr->class_val >> 8; pkt[p++] = rr->class_val & 0xFF;
        pkt[p++] = rr->ttl >> 24; pkt[p++] = (rr->ttl >> 16) & 0xFF; pkt[p++] = (rr->ttl >> 8) & 0xFF; pkt[p++] = rr->ttl & 0xFF;
        pkt[p++] = rr->rdata_len >> 8; pkt[p++] = rr->rdata_len & 0xFF;
        if (rr->rdata_len) memcpy(pkt + p, zone_image_rr_rdata(img, k), rr->rdata_len);
        p += rr->rdata_len;

        dns_record_t rec;
        memset(&rec, 0, sizeof(rec));
        size_t off = 0;
        uint16_t t = 0;
        bool raw = (rr->flags & ZONE_IMAGE_RR_RAW) != 0;
        const dns_rdata_name_layout_t *rlay = dns_rdata_name_layout(rr->type);
        /* A raw RR keeps its RDATA as it is (never compressed, RDATA of any shape): even for a type whose text form
         * exists, decoding it would make the record compressible (tinydns ":fqdn:4:...:" generic data). */
        bool decoded = !(raw && rlay && rlay->compress) && parse_resource_record(pkt, p, &off, a, &rec, &t) == 0;
        if (!decoded) {
            if (!raw) {
                syslog(LOG_ERR, "[Image] thaw: RR %u (type %u) cannot be decoded", k, rr->type);
                goto out;
            }
            memset(&rec, 0, sizeof(rec));
            rec.name = arena_strdup(a, text);
            char ttlbuf[16];
            snprintf(ttlbuf, sizeof(ttlbuf), "%u", rr->ttl);
            rec.ttl = arena_strdup(a, ttlbuf);
            rec.ttl_value = rr->ttl;
            rec.class_val = rr->class_val;
            rec.class_str = rr->class_val == 1 ? "IN" : (rr->class_val == DNS_CLASS_KARIDNS_EXT ? "KARIDNS" : "CH");
            rec.type = (char *)get_type_str(rr->type, a);
            rec.type_code = rr->type;
            rec.next_record = -1;
            uint8_t *keep = rr->rdata_len ? arena_alloc(a, rr->rdata_len) : (uint8_t *)"";
            if (!rec.name || !rec.ttl || !rec.type || !keep) goto out;
            if (rr->rdata_len) memcpy(keep, zone_image_rr_rdata(img, k), rr->rdata_len);
            rec.generic_data = keep;
            rec.generic_len = rr->rdata_len;
        }
        if (!rec.name || strcmp(rec.name, text) != 0) {
            rec.name = arena_strdup(a, text);
            if (!rec.name) goto out;
            dns_record_preparse_cache(a, &rec);
        }
        /* a record that is raw in the image stays raw even when its RDATA is empty */
        if ((rr->flags & ZONE_IMAGE_RR_RAW) && !rec.generic_data) {
            rec.generic_data = (uint8_t *)"";
            rec.generic_len = 0;
        }
        if (ext) {
            rec.tinydns_ttd = (time_t)ext->ttd;
            rec.tinydns_ttl_countdown = (ext->flags & ZONE_IMAGE_EXT_COUNTDOWN) != 0;
            rec.tinydns_loc[0] = ext->loc[0];
            rec.tinydns_loc[1] = ext->loc[1];
            if (ext->ecs_tag_off) {
                rec.ecs_subnet_tag = arena_strdup(a, zone_image_str(img, ext->ecs_tag_off));
                if (!rec.ecs_subnet_tag) goto out;
            }
            if (ext->loc_tag_off) {
                rec.bind_location_tag = arena_strdup(a, zone_image_str(img, ext->loc_tag_off));
                if (!rec.bind_location_tag) goto out;
            }
        }
        /* the text form must write the same RDATA: types whose text form cannot hold some RDATA (a NUL octet in a
         * character-string, more strings than MAX_RDATA) fall back to the wire form kept as it is */
        uint16_t clen = 0;
        bool same = serialize_dns_record(chk, 65535, &clen, &rec, NULL, ".", 0xFFFFFFFFu) == 0 && clen == 11 + rr->rdata_len &&
                    (rr->rdata_len == 0 || memcmp(chk + 11, zone_image_rr_rdata(img, k), rr->rdata_len) == 0);
        if (!same && rec.type_code == 14 && rec.rdata_count >= 2) same = true; /* MINFO: lowercased without a context */
        if (!same) {
            const dns_rdata_name_layout_t *lay = dns_rdata_name_layout(rr->type);
            if (lay && lay->compress) {
                syslog(LOG_ERR, "[Image] thaw: RR %u (type %u) does not round-trip", k, rr->type);
                goto out;
            }
            uint8_t *keep = rr->rdata_len ? arena_alloc(a, rr->rdata_len) : (uint8_t *)"";
            if (rr->rdata_len && !keep) goto out;
            if (rr->rdata_len) memcpy(keep, zone_image_rr_rdata(img, k), rr->rdata_len);
            rec.generic_data = keep;
            rec.generic_len = rr->rdata_len;
        }
        a->records[a->count++] = rec;
    }
    a->is_tinydns_format = (img->flags & ZONE_IMAGE_F_TINYDNS) != 0;
    if (thaw_zattr(img, a) != 0) goto out;
    if (build_zone_index(a, false) != 0) goto out;
    rc = 0;
out:
    free(pkt);
    free(chk);
    return rc;
}
