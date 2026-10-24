/*
 * dns_db_stream.c - KDB1 stream codec and Backend-side state machine (see dns_db_stream.h).
 *
 * No I/O.  The decoder and the state machine never allocate; only the encoder (malloc) does.
 * All counts and sums that depend on the stream are 64-bit and compared against limits by subtraction.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_db_stream.h"
#include "dns_utils.h"

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint64_t be64(const uint8_t *p) { return ((uint64_t)be32(p) << 32) | be32(p + 4); }
static inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }
static inline void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }

#define FAIL(why, wl, rc, ...) do { snprintf((why), (wl), __VA_ARGS__); return (rc); } while (0)

/* ------------------------------------------------------------------ tag tables */
enum { KT_U8, KT_U16, KT_U32, KT_U64, KT_I64, KT_STR, KT_TEXT, KT_BYTES, KT_NAME, KT_NEST, KT_PATH };
#define KS_REQ 1u      /* required */
#define KS_MAXV 2u     /* integer: value <= max */
#define KS_NE 4u       /* str / text: at least one byte */
#define KS_EXACT 8u    /* bytes: length == max */
#define KS_MUL8 16u    /* bytes: length a multiple of 8 */
#define KS_VIEW 32u    /* u16: view index, < view count */

#define KDB_MAX_TAGS 16

typedef struct kdb_tdef kdb_tdef_t;
typedef struct { uint8_t type; uint8_t flags; uint32_t max; const kdb_tdef_t *sub; } kdb_tspec_t;
/* spec[i] describes tag i+1: tags are dense from 1 */
struct kdb_tdef { const char *name; uint8_t n; const kdb_tspec_t *spec; };

#define S(t, f, m) { (t), (f), (m), NULL }
#define TDEF(var, nm, arr) static const kdb_tdef_t var = { nm, (uint8_t)(sizeof(arr) / sizeof((arr)[0])), arr }

static const kdb_tspec_t sp_hello[] = { S(KT_U16, KS_REQ, 0), S(KT_STR, KS_REQ, 64), S(KT_STR, KS_REQ, 32), S(KT_U32, KS_REQ, 0) };
static const kdb_tspec_t sp_batch_begin[] = { S(KT_U64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 4), S(KT_U64, KS_REQ, 0), S(KT_U64, 0, 0) };
static const kdb_tspec_t sp_zone_begin[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 2),
    S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ | KS_MAXV, KDB_ZF_PRESIGNED | KDB_ZF_EXTENDED), S(KT_U64, KS_REQ, 0),
    S(KT_BYTES, KS_REQ | KS_EXACT, KDB_DIGEST_LEN), S(KT_TEXT, 0, 65535), S(KT_STR, KS_NE, 255) };
static const kdb_tspec_t sp_zone_end[] = { S(KT_U64, KS_REQ, 0) };
static const kdb_tspec_t sp_zone_abort[] = { S(KT_STR, KS_REQ, 255) };
static const kdb_tspec_t sp_zone_failed[] = { S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0), S(KT_STR, KS_REQ, 255) };
static const kdb_tspec_t sp_zone_delete[] = { S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0) };
static const kdb_tspec_t sp_profile[] = { S(KT_STR, KS_REQ | KS_NE, 255), S(KT_TEXT, KS_REQ, 65535) };
static const kdb_tspec_t sp_batch_end[] = { S(KT_U64, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0) };
TDEF(td_hello, "HELLO", sp_hello);
TDEF(td_batch_begin, "BATCH_BEGIN", sp_batch_begin);
TDEF(td_zone_begin, "ZONE_BEGIN", sp_zone_begin);
TDEF(td_zone_end, "ZONE_END", sp_zone_end);
TDEF(td_zone_abort, "ZONE_ABORT", sp_zone_abort);
TDEF(td_zone_failed, "ZONE_FAILED", sp_zone_failed);
TDEF(td_zone_delete, "ZONE_DELETE", sp_zone_delete);
TDEF(td_profile, "PROFILE", sp_profile);
TDEF(td_batch_end, "BATCH_END", sp_batch_end);

static const kdb_tspec_t sp_cfg_view[] = {
    S(KT_U16, KS_REQ, 0), S(KT_STR, KS_REQ | KS_NE, 255), S(KT_PATH, KS_NE, 1023), S(KT_PATH, KS_NE, 1023),
    S(KT_U8, KS_REQ | KS_MAXV, 1), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U64, KS_REQ, 0), S(KT_U64, KS_REQ, 0),
    S(KT_U8, KS_MAXV, 1) };
TDEF(td_cfg_view, "CONFIG.VIEW", sp_cfg_view);
static const kdb_tspec_t sp_config[] = {
    S(KT_U64, KS_REQ, 0), S(KT_STR, KS_REQ | KS_NE, 32), S(KT_STR, 0, 64),
    { KT_NEST, 0, KDB_MAX_CONFIG_VIEWS, &td_cfg_view },
    S(KT_U32, KS_MAXV, 2147483647u), S(KT_U8, KS_MAXV, 100), S(KT_U32, KS_MAXV, 16) };
TDEF(td_config, "CONFIG", sp_config);
static const kdb_tspec_t sp_reload_req[] = {
    S(KT_U64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 1), S(KT_U16, KS_VIEW, 0), S(KT_NAME, 0, 0), S(KT_U8, KS_REQ | KS_MAXV, 1) };
TDEF(td_reload_req, "RELOAD_REQ", sp_reload_req);
static const kdb_tspec_t sp_inv_entry[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0), S(KT_U32, KS_REQ, 0),
    S(KT_BYTES, KS_REQ | KS_EXACT, KDB_DIGEST_LEN) };
TDEF(td_inv_entry, "INVENTORY.ENTRY", sp_inv_entry);
static const kdb_tspec_t sp_inventory[] = { { KT_NEST, 0, 65535, &td_inv_entry } };
TDEF(td_inventory, "INVENTORY", sp_inventory);
static const kdb_tspec_t sp_inventory_end[] = { S(KT_U64, KS_REQ, 0), S(KT_U64, KS_REQ, 0) };
TDEF(td_inventory_end, "INVENTORY_END", sp_inventory_end);
static const kdb_tspec_t sp_zone_result[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 4), S(KT_STR, 0, 255) };
TDEF(td_zone_result, "ZONE_RESULT", sp_zone_result);
static const kdb_tspec_t sp_batch_result[] = {
    S(KT_U64, KS_REQ, 0), S(KT_BYTES, KS_MUL8, 2048), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0),
    S(KT_U32, KS_REQ, 0) };
TDEF(td_batch_result, "BATCH_RESULT", sp_batch_result);

_Static_assert(sizeof(sp_zone_begin) / sizeof(sp_zone_begin[0]) <= KDB_MAX_TAGS, "kdb_val_t arrays are KDB_MAX_TAGS long");
_Static_assert(sizeof(sp_cfg_view) / sizeof(sp_cfg_view[0]) <= KDB_MAX_TAGS, "kdb_val_t arrays are KDB_MAX_TAGS long");

/* INVENTORY_REQ has no tags: any tag is unknown */
static const kdb_tdef_t td_empty = { "INVENTORY_REQ", 0, NULL };

typedef struct {
    uint16_t type; const char *name; kdb_dir_t dir; bool raw; uint32_t maxlen; const kdb_tdef_t *td;
} kdb_mdef_t;

static const kdb_mdef_t mdefs[] = {
    { KDB_T_HELLO, "HELLO", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_hello },
    { KDB_T_INVENTORY_REQ, "INVENTORY_REQ", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_empty },
    { KDB_T_BATCH_BEGIN, "BATCH_BEGIN", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_batch_begin },
    { KDB_T_ZONE_BEGIN, "ZONE_BEGIN", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_begin },
    { KDB_T_ZONE_DATA, "ZONE_DATA", KDB_FROM_LOADER, true, KDB_MAX_ZONE_DATA, NULL },
    { KDB_T_ZONE_END, "ZONE_END", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_end },
    { KDB_T_ZONE_ABORT, "ZONE_ABORT", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_abort },
    { KDB_T_ZONE_FAILED, "ZONE_FAILED", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_failed },
    { KDB_T_ZONE_DELETE, "ZONE_DELETE", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_delete },
    { KDB_T_PROFILE, "PROFILE", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_profile },
    { KDB_T_BATCH_END, "BATCH_END", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_batch_end },
    { KDB_T_CONFIG, "CONFIG", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_config },
    { KDB_T_RELOAD_REQ, "RELOAD_REQ", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_reload_req },
    { KDB_T_INVENTORY, "INVENTORY", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_inventory },
    { KDB_T_INVENTORY_END, "INVENTORY_END", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_inventory_end },
    { KDB_T_ZONE_RESULT, "ZONE_RESULT", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_zone_result },
    { KDB_T_BATCH_RESULT, "BATCH_RESULT", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_batch_result },
};
#define NMDEFS (sizeof(mdefs) / sizeof(mdefs[0]))

static const kdb_mdef_t *mdef_find(uint16_t type) {
    for (size_t i = 0; i < NMDEFS; i++)
        if (mdefs[i].type == type) return &mdefs[i];
    return NULL;
}

const char *kdb_type_name(uint16_t type) {
    const kdb_mdef_t *m = mdef_find(type);
    return m ? m->name : "?";
}

const char *kdb_rc_name(kdb_rc_t rc) {
    switch (rc) {
    case KDB_OK: return "ok";
    case KDB_MORE: return "more";
    case KDB_E_MAGIC: return "bad magic";
    case KDB_E_TYPE: return "unknown type";
    case KDB_E_FLAGS: return "bad flags";
    case KDB_E_LENGTH: return "bad length";
    case KDB_E_TLV_TRUNC: return "truncated TLV";
    case KDB_E_TLV_DUP: return "duplicate tag";
    case KDB_E_TLV_UNKNOWN: return "unknown tag";
    case KDB_E_TLV_MISSING: return "missing tag";
    case KDB_E_TLV_LEN: return "bad value length";
    case KDB_E_TLV_STR: return "bad string";
    case KDB_E_TLV_NAME: return "bad name";
    case KDB_E_RANGE: return "value out of range";
    case KDB_E_STATE: return "message not allowed in this state";
    case KDB_E_VERSION: return "protocol version mismatch";
    case KDB_E_DNSHDR: return "bad ZONE_DATA DNS header";
    case KDB_E_OPT: return "OPT outside the first ZONE_DATA";
    case KDB_E_COUNT: return "RR count mismatch";
    case KDB_E_SEQ: return "batch mismatch";
    case KDB_E_LIMIT_BYTES: return "zone byte limit exceeded";
    case KDB_E_LIMIT_RECORDS: return "zone record limit exceeded";
    case KDB_E_LIMIT_PROFILES: return "profile limit exceeded";
    }
    return "?";
}

/* ------------------------------------------------------------------ TLV parser */
typedef struct { bool present; uint64_t u; const uint8_t *p; uint32_t len; } kdb_val_t;

/* A canonical absolute presentation-format name: dns_name_normalize() returns it unchanged. */
static bool name_ok(const uint8_t *p, size_t n) {
    if (n == 0 || n > DNS_NAME_TEXT_SIZE - 1) return false;
    for (size_t i = 0; i < n; i++)   /* canonical text is graphic ASCII only (space, controls, >= 0x7F are \DDD) */
        if (p[i] < 0x21 || p[i] > 0x7E) return false;
    char in[DNS_NAME_TEXT_SIZE], out[DNS_NAME_TEXT_SIZE];
    memcpy(in, p, n);
    in[n] = '\0';
    size_t r = dns_name_normalize(in, out, sizeof(out));
    if (r != n || memcmp(in, out, n) != 0) return false;
    return dns_name_len_no_root(in, n) != n;   /* ends with an unescaped '.' (or is the root) */
}

/* File paths and schema names (KT_PATH): any valid UTF-8 (RFC 3629 §3/§4: shortest form only, no surrogates
 * U+D800..U+DFFF, nothing above U+10FFFF) without control characters (C0, DEL, C1 U+0080..U+009F). The bytes are
 * used as they are: no decoding of '%XX', '\' or anything else, so "a%65.sqlite3" names that file literally (the
 * loader opens SQLite files without SQLITE_OPEN_URI). */
static bool path_ok(const uint8_t *p, size_t n) { return dns_path_is_valid_utf8(p, n); }

static bool str_ok(const uint8_t *p, size_t n, bool text) {
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (c >= 0x20 && c <= 0x7E) continue;
        if (text && (c == '\t' || c == '\n')) continue;
        return false;
    }
    return true;
}

/* Parse the TLV list b[0..n) against d.  vals[0..d->n) receive the values.  *nrep (may be NULL) the number of
 * entries of the repeatable nested tag; nested entries are validated and not kept. */
static kdb_rc_t tlv_parse(const kdb_tdef_t *d, const uint8_t *b, size_t n, uint32_t vc, kdb_val_t *vals,
                          uint32_t *nrep, char *why, size_t wl) {
    memset(vals, 0, sizeof(*vals) * d->n);
    if (nrep) *nrep = 0;
    size_t off = 0;
    while (off < n) {
        if (n - off < 4) FAIL(why, wl, KDB_E_TLV_TRUNC, "%s: truncated TLV header", d->name);
        uint16_t tag = be16(b + off), len = be16(b + off + 2);
        off += 4;
        if (len > n - off) FAIL(why, wl, KDB_E_TLV_TRUNC, "%s: tag %u length %u exceeds the body", d->name, tag, len);
        if (tag == 0 || tag > d->n) FAIL(why, wl, KDB_E_TLV_UNKNOWN, "%s: unknown tag %u", d->name, tag);
        const kdb_tspec_t *s = &d->spec[tag - 1];
        const uint8_t *v = b + off;
        off += len;
        if (s->type == KT_NEST) {
            if (!nrep || *nrep >= s->max) FAIL(why, wl, KDB_E_RANGE, "%s: too many entries (tag %u)", d->name, tag);
            kdb_val_t sv[KDB_MAX_TAGS];
            kdb_rc_t rc = tlv_parse(s->sub, v, len, vc, sv, NULL, why, wl);
            if (rc != KDB_OK) return rc;
            (*nrep)++;
            continue;
        }
        kdb_val_t *x = &vals[tag - 1];
        if (x->present) FAIL(why, wl, KDB_E_TLV_DUP, "%s: duplicate tag %u", d->name, tag);
        x->p = v;
        x->len = len;
        switch (s->type) {
        case KT_U8: case KT_U16: case KT_U32: case KT_U64: case KT_I64: {
            static const uint8_t want[] = { 1, 2, 4, 8, 8 };
            if (len != want[s->type]) FAIL(why, wl, KDB_E_TLV_LEN, "%s: tag %u length %u, want %u", d->name, tag, len, want[s->type]);
            x->u = (len == 1) ? v[0] : (len == 2) ? be16(v) : (len == 4) ? be32(v) : be64(v);
            if ((s->flags & KS_MAXV) && x->u > s->max) FAIL(why, wl, KDB_E_RANGE, "%s: tag %u value out of range", d->name, tag);
            if ((s->flags & KS_VIEW) && vc != KDB_VIEWS_ANY && x->u >= vc)
                FAIL(why, wl, KDB_E_RANGE, "%s: view index %u >= %u views", d->name, (unsigned)x->u, vc);
            break;
        }
        case KT_STR: case KT_TEXT:
            if (len > s->max || ((s->flags & KS_NE) && len == 0)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u string length %u", d->name, tag, len);
            if (!str_ok(v, len, s->type == KT_TEXT)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u has a non-printable byte", d->name, tag);
            break;
        case KT_BYTES:
            if (((s->flags & KS_EXACT) ? len != s->max : len > s->max) || ((s->flags & KS_MUL8) && (len % 8) != 0))
                FAIL(why, wl, KDB_E_TLV_LEN, "%s: tag %u bytes length %u", d->name, tag, len);
            break;
        case KT_PATH:
            if (len > s->max || ((s->flags & KS_NE) && len == 0)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u path length %u", d->name, tag, len);
            if (!path_ok(v, len)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u is not valid UTF-8 or has a control character", d->name, tag);
            break;
        case KT_NAME:
            if (!name_ok(v, len)) FAIL(why, wl, KDB_E_TLV_NAME, "%s: tag %u is not a canonical absolute name", d->name, tag);
            break;
        default:
            FAIL(why, wl, KDB_E_TLV_UNKNOWN, "%s: internal table error", d->name);
        }
        x->present = true;
    }
    for (unsigned i = 0; i < d->n; i++)
        if ((d->spec[i].flags & KS_REQ) && !vals[i].present)
            FAIL(why, wl, KDB_E_TLV_MISSING, "%s: missing required tag %u", d->name, i + 1);
    return KDB_OK;
}

#define V(i) (vals[(i) - 1])
static kdb_str_t gstr(const kdb_val_t *v) {
    kdb_str_t s = { NULL, 0 };
    if (v->present) { s.p = (const char *)v->p; s.len = v->len; }
    return s;
}
static void gname(char *out, const kdb_val_t *v) {   /* validated: <= DNS_NAME_TEXT_SIZE - 1 bytes */
    memcpy(out, v->p, v->len);
    out[v->len] = '\0';
}

/* ------------------------------------------------------------------ decoder */
kdb_rc_t kdb_decode(const kdb_frame_t *fr, uint32_t vc, kdb_msg_t *m, char *why, size_t wl) {
    const kdb_mdef_t *md = mdef_find(fr->type);
    if (!md) FAIL(why, wl, KDB_E_TYPE, "unknown message type %u", fr->type);
    if (fr->len > md->maxlen) FAIL(why, wl, KDB_E_LENGTH, "%s: body length %u above the limit", md->name, fr->len);
    memset(m, 0, sizeof(*m));
    m->type = fr->type;
    m->view_count = vc;

    if (md->raw) {   /* ZONE_DATA: DNS header checks without parsing RRs (RFC 1035 4.1.1, RFC 5936 2.2) */
        const uint8_t *b = fr->body;
        if (fr->len < DNS_HEADER_SIZE) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: %u bytes, shorter than a DNS header", fr->len);
        uint16_t fl = be16(b + 2), qd = be16(b + 4), an = be16(b + 6), ns = be16(b + 8), ar = be16(b + 10);
        if (!(fl & 0x8000)) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: QR is not set");
        if ((fl >> 11) & 0xF) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: opcode is not QUERY");
        if (!(fl & 0x0400)) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: AA is not set (RFC 5936 2.2.1)");
        if (fl & 0x0200) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: TC is set (RFC 5936 2.2.1)");
        if (fl & 0x000F) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: RCODE is not 0");
        if (qd != 0) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: QDCOUNT is not 0");
        if (ns != 0) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: NSCOUNT is not 0 (RFC 5936 2.2.4)");
        if (ar > 1) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: ARCOUNT above 1");
        if (an == 0) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: no answer RR");
        m->u.zone_data.body = b;
        m->u.zone_data.len = fr->len;
        m->u.zone_data.ancount = an;
        m->u.zone_data.arcount = ar;
        return KDB_OK;
    }

    kdb_val_t vals[KDB_MAX_TAGS];
    uint32_t nrep = 0;
    kdb_rc_t rc = tlv_parse(md->td, fr->body, fr->len, vc, vals, &nrep, why, wl);
    if (rc != KDB_OK) return rc;

    switch (fr->type) {
    case KDB_T_HELLO:
        m->u.hello.proto = (uint16_t)V(1).u;
        m->u.hello.loader_version = gstr(&V(2));
        m->u.hello.driver = gstr(&V(3));
        m->u.hello.pid = (uint32_t)V(4).u;
        break;
    case KDB_T_INVENTORY_REQ:
        break;
    case KDB_T_BATCH_BEGIN:
        m->u.batch_begin.batch_id = V(1).u;
        m->u.batch_begin.kind = (uint8_t)V(2).u;
        m->u.batch_begin.change_seq = V(3).u;
        m->u.batch_begin.request_id = V(4).present ? V(4).u : 0;
        break;
    case KDB_T_ZONE_BEGIN: {
        kdb_zone_begin_t *z = &m->u.zone_begin;
        z->view = (uint16_t)V(1).u;
        gname(z->name, &V(2));
        z->source_id = (int64_t)V(3).u;
        z->zone_kind = (uint8_t)V(4).u;
        z->serial = (uint32_t)V(5).u;
        z->flags = (uint32_t)V(6).u;
        z->rr_count = V(7).u;
        memcpy(z->digest, V(8).p, KDB_DIGEST_LEN);
        z->settings = gstr(&V(9));
        z->profile = gstr(&V(10));
        break;
    }
    case KDB_T_ZONE_END:
        m->u.zone_end.rr_count = V(1).u;
        break;
    case KDB_T_ZONE_ABORT:
        m->u.zone_abort.reason = gstr(&V(1));
        break;
    case KDB_T_ZONE_FAILED:
        m->u.zone_failed.view = (uint16_t)V(1).u;
        gname(m->u.zone_failed.name, &V(2));
        m->u.zone_failed.source_id = (int64_t)V(3).u;
        m->u.zone_failed.reason = gstr(&V(4));
        break;
    case KDB_T_ZONE_DELETE:
        m->u.zone_delete.view = (uint16_t)V(1).u;
        gname(m->u.zone_delete.name, &V(2));
        m->u.zone_delete.source_id = (int64_t)V(3).u;
        break;
    case KDB_T_PROFILE:
        m->u.profile.name = gstr(&V(1));
        m->u.profile.settings = gstr(&V(2));
        break;
    case KDB_T_BATCH_END:
        m->u.batch_end.batch_id = V(1).u;
        m->u.batch_end.n_zones = (uint32_t)V(2).u;
        m->u.batch_end.n_failed = (uint32_t)V(3).u;
        m->u.batch_end.n_deleted = (uint32_t)V(4).u;
        break;
    case KDB_T_CONFIG:
        m->u.config.generation = V(1).u;
        m->u.config.driver = gstr(&V(2));
        m->u.config.server_id = gstr(&V(3));
        m->u.config.default_ttl = V(5).present ? (uint32_t)V(5).u : 0;
        m->u.config.bulk_threshold = V(6).present ? (int)V(6).u : -1;
        m->u.config.loader_threads = V(7).present ? (uint32_t)V(7).u : 0;
        m->u.config.n_views = nrep;
        m->u.config.body = fr->body;
        m->u.config.body_len = fr->len;
        break;
    case KDB_T_RELOAD_REQ: {
        kdb_reload_req_t *r = &m->u.reload_req;
        r->request_id = V(1).u;
        r->scope = (uint8_t)V(2).u;
        r->force = (uint8_t)V(5).u;
        bool hv = V(3).present, hz = V(4).present;
        if (r->scope == 1 && !(hv && hz)) FAIL(why, wl, KDB_E_TLV_MISSING, "RELOAD_REQ: scope 1 needs view and zone");
        if (r->scope == 0 && (hv || hz)) FAIL(why, wl, KDB_E_RANGE, "RELOAD_REQ: scope 0 takes no view or zone");
        if (hv) r->view = (uint16_t)V(3).u;
        if (hz) { gname(r->zone, &V(4)); r->has_zone = true; }
        break;
    }
    case KDB_T_INVENTORY:
        m->u.inventory.n_entries = nrep;
        m->u.inventory.body = fr->body;
        m->u.inventory.body_len = fr->len;
        break;
    case KDB_T_INVENTORY_END:
        m->u.inventory_end.last_change_seq = V(1).u;
        m->u.inventory_end.n_zones = V(2).u;
        break;
    case KDB_T_ZONE_RESULT:
        m->u.zone_result.view = (uint16_t)V(1).u;
        gname(m->u.zone_result.name, &V(2));
        m->u.zone_result.status = (uint8_t)V(3).u;
        m->u.zone_result.reason = gstr(&V(4));
        break;
    case KDB_T_BATCH_RESULT:
        m->u.batch_result.batch_id = V(1).u;
        if (V(2).present) {
            m->u.batch_result.request_ids = V(2).p;
            m->u.batch_result.n_request_ids = V(2).len / 8;
        }
        m->u.batch_result.n_applied = (uint32_t)V(3).u;
        m->u.batch_result.n_unchanged = (uint32_t)V(4).u;
        m->u.batch_result.n_rejected = (uint32_t)V(5).u;
        m->u.batch_result.n_deleted = (uint32_t)V(6).u;
        break;
    default:
        FAIL(why, wl, KDB_E_TYPE, "unknown message type %u", fr->type);
    }
    return KDB_OK;
}

/* ------------------------------------------------------------------ iterators */
static bool nest_next(kdb_iter_t *it, uint16_t tag, const kdb_tdef_t *sub, kdb_val_t *vals) {
    while (it->left >= 4) {
        uint16_t t = be16(it->p), l = be16(it->p + 2);
        if ((size_t)l > it->left - 4) break;
        const uint8_t *v = it->p + 4;
        it->p += 4 + (size_t)l;
        it->left -= 4 + (size_t)l;
        if (t != tag) continue;
        char why[KDB_REASON_LEN];
        if (tlv_parse(sub, v, l, it->view_count, vals, NULL, why, sizeof(why)) != KDB_OK) break;
        return true;
    }
    it->left = 0;
    return false;
}

void kdb_config_views(const kdb_msg_t *m, kdb_iter_t *it) {
    bool ok = m->type == KDB_T_CONFIG;
    it->p = ok ? m->u.config.body : NULL;
    it->left = ok ? m->u.config.body_len : 0;
    it->view_count = KDB_VIEWS_ANY;
}

bool kdb_config_views_next(kdb_iter_t *it, kdb_config_view_t *o) {
    kdb_val_t vals[KDB_MAX_TAGS];
    if (!nest_next(it, 4, &td_cfg_view, vals)) return false;
    o->index = (uint16_t)V(1).u;
    o->name = gstr(&V(2));
    o->source = gstr(&V(3));
    o->conninfo_file = gstr(&V(4));
    o->auto_reload = (uint8_t)V(5).u;
    o->poll_interval = (uint32_t)V(6).u;
    o->coalesce_ms = (uint32_t)V(7).u;
    o->max_zone_records = V(8).u;
    o->max_zone_bytes = V(9).u;
    o->shared_source = V(10).present ? (uint8_t)V(10).u : 0;
    return true;
}

void kdb_inventory_entries(const kdb_msg_t *m, kdb_iter_t *it) {
    bool ok = m->type == KDB_T_INVENTORY;
    it->p = ok ? m->u.inventory.body : NULL;
    it->left = ok ? m->u.inventory.body_len : 0;
    it->view_count = m->view_count;
}

bool kdb_inventory_entries_next(kdb_iter_t *it, kdb_inventory_entry_t *o) {
    kdb_val_t vals[KDB_MAX_TAGS];
    if (!nest_next(it, 1, &td_inv_entry, vals)) return false;
    o->view = (uint16_t)V(1).u;
    gname(o->name, &V(2));
    o->source_id = (int64_t)V(3).u;
    o->serial = (uint32_t)V(4).u;
    memcpy(o->digest, V(5).p, KDB_DIGEST_LEN);
    return true;
}

/* ------------------------------------------------------------------ framer */
enum { PH_HDR = 0, PH_BODY, PH_DONE };

void kdb_framer_init(kdb_framer_t *f, kdb_dir_t dir, uint8_t *buf, size_t cap) {
    memset(f, 0, sizeof(*f));
    f->dir = dir;
    f->buf = buf;
    f->cap = cap;
}

kdb_rc_t kdb_framer_feed(kdb_framer_t *f, const uint8_t *p, size_t n) {
    if (f->fail != KDB_OK) return f->fail;
    if (f->in_len != 0) return KDB_E_STATE;
    f->in = p;
    f->in_len = n;
    return KDB_OK;
}

#define FRFAIL(f, code, ...) do { (f)->fail = (code); snprintf((f)->reason, sizeof((f)->reason), __VA_ARGS__); \
    (f)->in_len = 0; return (code); } while (0)

kdb_rc_t kdb_framer_next(kdb_framer_t *f, kdb_frame_t *out) {
    if (f->fail != KDB_OK) return f->fail;
    if (f->phase == PH_DONE) {
        f->phase = PH_HDR;
        f->hdr_have = 0;
        f->body_have = 0;
    }
    if (f->phase == PH_HDR) {
        size_t take = KDB_HEADER_LEN - f->hdr_have;
        if (take > f->in_len) take = f->in_len;
        if (take) memcpy(f->hdr + f->hdr_have, f->in, take);
        f->hdr_have += take;
        f->in += take;
        f->in_len -= take;
        if (f->hdr_have < KDB_HEADER_LEN) return KDB_MORE;
        if (memcmp(f->hdr, KDB_MAGIC, 4) != 0) FRFAIL(f, KDB_E_MAGIC, "bad magic");
        uint16_t type = be16(f->hdr + 4), flags = be16(f->hdr + 6);
        uint32_t len = be32(f->hdr + 8);
        const kdb_mdef_t *md = mdef_find(type);
        if (!md || md->dir != f->dir) FRFAIL(f, KDB_E_TYPE, "unknown message type %u", type);
        if (flags != 0) FRFAIL(f, KDB_E_FLAGS, "flags %u, must be 0", flags);
        if (len > md->maxlen) FRFAIL(f, KDB_E_LENGTH, "%s body length %u above the limit of the type", md->name, len);
        if (len > f->cap) FRFAIL(f, KDB_E_LENGTH, "%s body length %u above the receive buffer", md->name, len);
        f->type = type;
        f->body_len = len;
        f->body_have = 0;
        f->phase = PH_BODY;
    }
    /* PH_BODY */
    size_t take = f->body_len - f->body_have;
    if (take > f->in_len) take = f->in_len;
    if (take) memcpy(f->buf + f->body_have, f->in, take);
    f->body_have += (uint32_t)take;
    f->in += take;
    f->in_len -= take;
    if (f->body_have < f->body_len) return KDB_MORE;
    f->phase = PH_DONE;
    out->type = f->type;
    out->body = f->buf;
    out->len = f->body_len;
    return KDB_OK;
}

/* ------------------------------------------------------------------ encoder */
void kdb_enc_init(kdb_enc_t *e) { memset(e, 0, sizeof(*e)); }
void kdb_enc_free(kdb_enc_t *e) { free(e->buf); memset(e, 0, sizeof(*e)); }
void kdb_enc_reset(kdb_enc_t *e) { e->len = 0; e->open = e->nested = e->err = false; }

static int enc_room(kdb_enc_t *e, size_t n) {
    if (e->err) return -1;
    if (n > SIZE_MAX - e->len) { e->err = true; return -1; }
    size_t need = e->len + n;
    if (need <= e->cap) return 0;
    size_t nc = e->cap ? e->cap : 256;
    while (nc < need) {
        if (nc > SIZE_MAX / 2) { e->err = true; return -1; }
        nc *= 2;
    }
    uint8_t *nb = realloc(e->buf, nc);
    if (!nb) { e->err = true; return -1; }
    e->buf = nb;
    e->cap = nc;
    return 0;
}

int kdb_enc_begin(kdb_enc_t *e, uint16_t type) {
    if (e->err || e->open || !mdef_find(type)) { e->err = true; return -1; }
    if (enc_room(e, KDB_HEADER_LEN) != 0) return -1;
    e->msg_start = e->len;
    memcpy(e->buf + e->len, KDB_MAGIC, 4);
    put16(e->buf + e->len + 4, type);
    put16(e->buf + e->len + 6, 0);
    put32(e->buf + e->len + 8, 0);
    e->len += KDB_HEADER_LEN;
    e->cur_type = type;
    e->open = true;
    return 0;
}

static int enc_tlv(kdb_enc_t *e, uint16_t tag, const void *p, size_t n) {
    if (e->err || !e->open || n > 65535) { e->err = true; return -1; }
    if (enc_room(e, 4 + n) != 0) return -1;
    put16(e->buf + e->len, tag);
    put16(e->buf + e->len + 2, (uint16_t)n);
    if (n) memcpy(e->buf + e->len + 4, p, n);
    e->len += 4 + n;
    return 0;
}

int kdb_enc_u8(kdb_enc_t *e, uint16_t tag, uint8_t v) { return enc_tlv(e, tag, &v, 1); }
int kdb_enc_u16(kdb_enc_t *e, uint16_t tag, uint16_t v) { uint8_t b[2]; put16(b, v); return enc_tlv(e, tag, b, 2); }
int kdb_enc_u32(kdb_enc_t *e, uint16_t tag, uint32_t v) { uint8_t b[4]; put32(b, v); return enc_tlv(e, tag, b, 4); }
int kdb_enc_u64(kdb_enc_t *e, uint16_t tag, uint64_t v) { uint8_t b[8]; put64(b, v); return enc_tlv(e, tag, b, 8); }
int kdb_enc_i64(kdb_enc_t *e, uint16_t tag, int64_t v) { return kdb_enc_u64(e, tag, (uint64_t)v); }
int kdb_enc_bytes(kdb_enc_t *e, uint16_t tag, const void *p, size_t n) { return enc_tlv(e, tag, p, n); }
int kdb_enc_str(kdb_enc_t *e, uint16_t tag, const char *s) { return enc_tlv(e, tag, s, strlen(s)); }
int kdb_enc_name(kdb_enc_t *e, uint16_t tag, const char *name) { return enc_tlv(e, tag, name, strlen(name)); }

int kdb_enc_nest_begin(kdb_enc_t *e, uint16_t tag) {
    if (e->err || !e->open || e->nested) { e->err = true; return -1; }
    if (enc_tlv(e, tag, NULL, 0) != 0) return -1;
    e->nest_start = e->len - 4;
    e->nested = true;
    return 0;
}

int kdb_enc_nest_end(kdb_enc_t *e) {
    if (e->err || !e->nested) { e->err = true; return -1; }
    size_t n = e->len - e->nest_start - 4;
    if (n > 65535) { e->err = true; return -1; }
    put16(e->buf + e->nest_start + 2, (uint16_t)n);
    e->nested = false;
    return 0;
}

int kdb_enc_end(kdb_enc_t *e) {
    if (e->err || !e->open || e->nested) { e->err = true; return -1; }
    const kdb_mdef_t *md = mdef_find(e->cur_type);
    size_t body = e->len - e->msg_start - KDB_HEADER_LEN;
    if (!md || body > md->maxlen) { e->err = true; return -1; }
    put32(e->buf + e->msg_start + 8, (uint32_t)body);
    e->open = false;
    return 0;
}

int kdb_enc_raw_msg(kdb_enc_t *e, uint16_t type, const void *body, size_t n) {
    if (e->err || e->open || n > UINT32_MAX || n > SIZE_MAX - KDB_HEADER_LEN) { e->err = true; return -1; }
    if (enc_room(e, KDB_HEADER_LEN + n) != 0) return -1;
    memcpy(e->buf + e->len, KDB_MAGIC, 4);
    put16(e->buf + e->len + 4, type);
    put16(e->buf + e->len + 6, 0);
    put32(e->buf + e->len + 8, (uint32_t)n);
    if (n) memcpy(e->buf + e->len + KDB_HEADER_LEN, body, n);
    e->len += KDB_HEADER_LEN + n;
    return 0;
}

/* ------------------------------------------------------------------ state machine */
void kdb_sm_init(kdb_sm_t *sm, const kdb_limits_t *lim) {
    memset(sm, 0, sizeof(*sm));
    if (lim) {
        sm->lim = *lim;
    } else {
        sm->lim.max_zone_records = KDB_DEFAULT_MAX_ZONE_RECORDS;
        sm->lim.max_zone_bytes = KDB_DEFAULT_MAX_ZONE_BYTES;
        sm->lim.view_count = KDB_VIEWS_ANY;
    }
    sm->state = KDB_S_AWAIT_HELLO;
}

static bool sm_legal(const kdb_sm_t *sm, uint16_t t) {
    switch (sm->state) {
    case KDB_S_AWAIT_HELLO: return t == KDB_T_HELLO;
    case KDB_S_READY:
        return (t == KDB_T_INVENTORY_REQ && !sm->inventory_req_seen && !sm->batch_seen) || t == KDB_T_BATCH_BEGIN;
    case KDB_S_IN_BATCH:
        return t == KDB_T_ZONE_BEGIN || t == KDB_T_ZONE_FAILED || t == KDB_T_ZONE_DELETE || t == KDB_T_PROFILE ||
               t == KDB_T_BATCH_END;
    case KDB_S_IN_ZONE: return t == KDB_T_ZONE_DATA || t == KDB_T_ZONE_END || t == KDB_T_ZONE_ABORT;
    case KDB_S_ERROR: break;
    }
    return false;
}

#define SMFAIL(sm, rc, ...) do { (sm)->state = KDB_S_ERROR; (sm)->fail = (rc); \
    snprintf((sm)->reason, sizeof((sm)->reason), __VA_ARGS__); return (rc); } while (0)

kdb_rc_t kdb_sm_accept(kdb_sm_t *sm, const kdb_frame_t *fr, kdb_msg_t *m) {
    if (sm->state == KDB_S_ERROR) return sm->fail;
    if (!sm_legal(sm, fr->type)) SMFAIL(sm, KDB_E_STATE, "%s not allowed in state %d", kdb_type_name(fr->type), (int)sm->state);
    kdb_rc_t rc = kdb_decode(fr, sm->lim.view_count, m, sm->reason, sizeof(sm->reason));
    if (rc != KDB_OK) { sm->state = KDB_S_ERROR; sm->fail = rc; return rc; }

    switch (fr->type) {
    case KDB_T_HELLO:
        if (m->u.hello.proto != KDB_VERSION) SMFAIL(sm, KDB_E_VERSION, "HELLO: protocol version %u, want %u", m->u.hello.proto, KDB_VERSION);
        sm->state = KDB_S_READY;
        break;
    case KDB_T_INVENTORY_REQ:
        sm->inventory_req_seen = true;
        break;
    case KDB_T_BATCH_BEGIN:
        sm->batch_seen = true;
        sm->batch_id = m->u.batch_begin.batch_id;
        sm->n_zones = sm->n_failed = sm->n_deleted = 0;
        sm->n_profiles = 0;
        sm->state = KDB_S_IN_BATCH;
        break;
    case KDB_T_PROFILE:
        if (sm->n_profiles >= KDB_MAX_PROFILES) SMFAIL(sm, KDB_E_LIMIT_PROFILES, "PROFILE: more than %u profiles in a batch", KDB_MAX_PROFILES);
        sm->n_profiles++;
        break;
    case KDB_T_ZONE_FAILED:
        sm->n_failed++;
        break;
    case KDB_T_ZONE_DELETE:
        sm->n_deleted++;
        break;
    case KDB_T_ZONE_BEGIN: {
        uint64_t n = m->u.zone_begin.rr_count;
        uint8_t zk = m->u.zone_begin.zone_kind;
        if (zk == KDB_ZK_PRIMARY) {
            if (n < 2) SMFAIL(sm, KDB_E_COUNT, "ZONE_BEGIN: rr_count %llu, an AXFR has at least two SOAs (RFC 5936 2.2)", (unsigned long long)n);
        } else if (n != 0) {
            /* B7b: a secondary / catalog consumer zone carries no data (the Backend transfers it from the masters in the settings) */
            SMFAIL(sm, KDB_E_COUNT, "ZONE_BEGIN: a secondary zone has rr_count 0, not %llu", (unsigned long long)n);
        }
        if (n > sm->lim.max_zone_records) SMFAIL(sm, KDB_E_LIMIT_RECORDS, "ZONE_BEGIN: rr_count above max-zone-records");
        sm->zone_rr_declared = n;
        sm->zone_rr_sum = 0;
        sm->zone_bytes = 0;
        sm->zone_data_msgs = 0;
        sm->state = KDB_S_IN_ZONE;
        break;
    }
    case KDB_T_ZONE_DATA: {
        uint32_t len = m->u.zone_data.len;
        /* zone_bytes <= max_zone_bytes and zone_rr_sum <= zone_rr_declared hold here: subtract, never add */
        if ((uint64_t)len > sm->lim.max_zone_bytes - sm->zone_bytes) SMFAIL(sm, KDB_E_LIMIT_BYTES, "ZONE_DATA: zone above max-zone-bytes");
        if (m->u.zone_data.arcount != 0 && sm->zone_data_msgs != 0)
            SMFAIL(sm, KDB_E_OPT, "ZONE_DATA: ARCOUNT in a message after the first of the zone");
        if ((uint64_t)m->u.zone_data.ancount > sm->zone_rr_declared - sm->zone_rr_sum)
            SMFAIL(sm, KDB_E_COUNT, "ZONE_DATA: more RRs than ZONE_BEGIN declared");
        sm->zone_bytes += len;
        sm->zone_rr_sum += m->u.zone_data.ancount;
        if (sm->zone_data_msgs < UINT32_MAX) sm->zone_data_msgs++;
        break;
    }
    case KDB_T_ZONE_END:
        if (m->u.zone_end.rr_count != sm->zone_rr_declared) SMFAIL(sm, KDB_E_COUNT, "ZONE_END: count differs from ZONE_BEGIN");
        if (sm->zone_rr_sum != sm->zone_rr_declared) SMFAIL(sm, KDB_E_COUNT, "ZONE_END: ANCOUNT sum differs from the declared count");
        sm->n_zones++;
        sm->state = KDB_S_IN_BATCH;
        break;
    case KDB_T_ZONE_ABORT:
        sm->state = KDB_S_IN_BATCH;
        break;
    case KDB_T_BATCH_END: {
        const kdb_batch_end_t *b = &m->u.batch_end;
        if (b->batch_id != sm->batch_id) SMFAIL(sm, KDB_E_SEQ, "BATCH_END: batch id differs from BATCH_BEGIN");
        if (b->n_zones != sm->n_zones || b->n_failed != sm->n_failed || b->n_deleted != sm->n_deleted)
            SMFAIL(sm, KDB_E_COUNT, "BATCH_END: counts differ from the messages seen");
        sm->state = KDB_S_READY;
        break;
    }
    default:
        SMFAIL(sm, KDB_E_STATE, "%s not allowed from the loader", kdb_type_name(fr->type));
    }
    return KDB_OK;
}
