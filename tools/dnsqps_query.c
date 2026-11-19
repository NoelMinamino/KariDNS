/* dnsqps: the encoder of a query and the query table.
 * A table holds the wire form of every name once and, per entry, the type and the number of an option set (a profile: the flag bytes and the OPT record,
 * built once).  A query is then a few memcpy()s into the send buffer, with no allocation; the caller sets the ID.  The table comes from a query file
 * (one "name type [+option ...]" per line, the format dnsperf reads, with per-line options) or is generated from a list of names: a Zipf-like popularity,
 * a share of names that do not exist (NXDOMAIN) and a mix of types. */
#include "dnsqps.h"
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---------------------------------------------------------------- options (dig spelling) */
void dq_qopts_default(dq_qopts_t *o) {
    memset(o, 0, sizeof *o);
    o->rd = true;
    o->bufsize = 1232;
    o->qclass = 1;
}

static void seterr(char *err, size_t n, const char *fmt, const char *a) {
    if (err && n) snprintf(err, n, fmt, a);
}

/* a +subnet value: "192.0.2.0/24", "2001:db8::/32", or an address alone (the full length); the address is cut to the prefix (RFC 7871 6) */
static bool parse_subnet(dq_qopts_t *o, const char *v) {
    char buf[80];
    if (strlen(v) >= sizeof buf) return false;
    strcpy(buf, v);
    char *slash = strchr(buf, '/');
    int fam = 0;
    if (slash) *slash = '\0';
    uint8_t ip[16];
    if (!dq_parse_ip(buf, ip, &fam)) return false;
    unsigned maxp = fam == 1 ? 32 : 128, prefix = maxp;
    if (slash) {
        uint64_t p;
        if (!dq_parse_u64(slash + 1, &p, maxp)) return false;
        prefix = (unsigned)p;
    }
    size_t bytes = fam == 1 ? 4 : 16;
    memset(o->sn_addr, 0, sizeof o->sn_addr);
    memcpy(o->sn_addr, ip, bytes);
    for (size_t i = 0; i < bytes; i++) {
        unsigned keep = prefix > i * 8 ? prefix - (unsigned)i * 8 : 0;
        if (keep >= 8) continue;
        o->sn_addr[i] = keep ? (uint8_t)(o->sn_addr[i] & (0xFFu << (8 - keep))) : 0;
    }
    o->sn_family = (uint8_t)fam;
    o->sn_prefix = (uint8_t)prefix;
    o->subnet = true;
    return true;
}

static bool *bool_field(dq_qopts_t *o, const char *k) {
    if (!strcmp(k, "edns")) return &o->edns;
    if (!strcmp(k, "dnssec")) return &o->dnssec;
    if (!strcmp(k, "nsid")) return &o->nsid;
    if (!strcmp(k, "cookie")) return &o->cookie;
    if (!strcmp(k, "rd") || !strcmp(k, "recurse")) return &o->rd;
    if (!strcmp(k, "cd") || !strcmp(k, "cdflag")) return &o->cd;
    if (!strcmp(k, "ad") || !strcmp(k, "adflag")) return &o->ad;
    if (!strcmp(k, "aa") || !strcmp(k, "aaflag")) return &o->aa;
    return NULL;
}

int dq_qopts_parse_tok(dq_qopts_t *o, const char *tok, char *err, size_t errlen) {
    char key[24];
    const char *val = NULL;
    if (tok[0] != '+') { seterr(err, errlen, "'%s' is not a +option", tok); return -1; }
    tok++;
    const char *eq = strchr(tok, '=');
    size_t kl = eq ? (size_t)(eq - tok) : strlen(tok);
    if (kl == 0 || kl >= sizeof key) { seterr(err, errlen, "unknown option '+%s'", tok); return -1; }
    memcpy(key, tok, kl);
    key[kl] = '\0';
    if (eq) val = eq + 1;
    bool neg = false;
    const char *k = key;
    if (!strncmp(k, "no", 2) && k[2]) { neg = true; k += 2; }

    bool *bf = bool_field(o, k);
    if (bf) {
        if (val && strcmp(k, "edns") != 0) { seterr(err, errlen, "'+%s' takes no value", k); return -1; }
        *bf = !neg;
        /* dig: these ask for EDNS */
        if (!neg && (bf == &o->dnssec || bf == &o->nsid || bf == &o->cookie)) o->edns = true;
        return 0;
    }
    if (!strcmp(k, "bufsize")) {
        uint64_t v;
        if (neg || !val || !dq_parse_u64(val, &v, 65535)) { seterr(err, errlen, "'+%s' needs a size 0-65535", "bufsize"); return -1; }
        o->bufsize = (uint16_t)v;
        o->edns = true;
        return 0;
    }
    if (!strcmp(k, "padding")) {
        uint64_t v = 0;
        if (neg) { o->padding = 0; return 0; }
        if (!val || !dq_parse_u64(val, &v, 512) || v == 0) { seterr(err, errlen, "'+%s' needs a block size 1-512", "padding"); return -1; }
        o->padding = (uint16_t)v;
        o->edns = true;
        return 0;
    }
    if (!strcmp(k, "subnet")) {
        if (neg) { o->subnet = false; return 0; }
        if (!val || !parse_subnet(o, val)) { seterr(err, errlen, "'+%s' needs address[/prefix]", "subnet"); return -1; }
        o->edns = true;
        return 0;
    }
    if (!strcmp(k, "opcode")) {
        uint64_t v;
        if (neg || !val || !dq_parse_u64(val, &v, 15)) { seterr(err, errlen, "'+%s' needs 0-15", "opcode"); return -1; }
        o->opcode = (uint8_t)v;
        return 0;
    }
    if (!strcmp(k, "class")) {
        uint64_t v;
        if (neg || !val) { seterr(err, errlen, "'+%s' needs IN, CH, HS or a number", "class"); return -1; }
        if (!strcasecmp(val, "IN")) v = 1;
        else if (!strcasecmp(val, "CH")) v = 3;
        else if (!strcasecmp(val, "HS")) v = 4;
        else if (!dq_parse_u64(val, &v, 65535)) { seterr(err, errlen, "'+%s' needs IN, CH, HS or a number", "class"); return -1; }
        o->qclass = (uint16_t)v;
        return 0;
    }
    seterr(err, errlen, "unknown option '+%s'", tok);
    return -1;
}

bool dq_prof_make(dq_prof_t *p, const dq_qopts_t *o) {
    memset(p, 0, sizeof *p);
    p->flags[0] = (uint8_t)((o->opcode << 3) | (o->aa ? 0x04 : 0) | (o->rd ? 0x01 : 0));
    p->flags[1] = (uint8_t)((o->ad ? 0x20 : 0) | (o->cd ? 0x10 : 0));
    p->qclass = o->qclass;
    if (!o->edns) return true;
    uint8_t *t = p->tail;
    size_t n = 0;
    t[n++] = 0;                                   /* the root name */
    t[n++] = 0; t[n++] = 41;                      /* OPT (RFC 6891 6.1.2) */
    t[n++] = (uint8_t)(o->bufsize >> 8); t[n++] = (uint8_t)o->bufsize;   /* the class field: the UDP payload size */
    t[n++] = 0; t[n++] = 0;                       /* extended RCODE, version */
    t[n++] = o->dnssec ? 0x80 : 0; t[n++] = 0;    /* DO (RFC 3225) */
    size_t rdlen_at = n;
    n += 2;
    size_t start = n;
    if (o->nsid) { t[n++] = 0; t[n++] = 3; t[n++] = 0; t[n++] = 0; }   /* RFC 5001 */
    if (o->cookie) {                                                     /* RFC 7873: a client cookie */
        t[n++] = 0; t[n++] = 10; t[n++] = 0; t[n++] = 8;
        memcpy(t + n, o->cookie_val, 8);
        n += 8;
    }
    if (o->subnet) {                                                     /* RFC 7871 6 */
        size_t ab = ((size_t)o->sn_prefix + 7) / 8;
        if (n + 8 + ab > DQ_TAILMAX) return false;
        t[n++] = 0; t[n++] = 8; t[n++] = 0; t[n++] = (uint8_t)(4 + ab);
        t[n++] = 0; t[n++] = o->sn_family; t[n++] = o->sn_prefix; t[n++] = 0;
        memcpy(t + n, o->sn_addr, ab);
        n += ab;
    }
    t[rdlen_at] = (uint8_t)((n - start) >> 8);
    t[rdlen_at + 1] = (uint8_t)(n - start);
    p->tail_len = (uint16_t)n;
    p->padding = o->padding;
    return true;
}

size_t dq_compose(uint8_t *out, size_t cap, const dq_prof_t *p, const uint8_t *wname, size_t nlen, uint16_t qtype) {
    size_t q = 12 + nlen + 4, padopt = 0, padlen = 0;
    size_t need = q + p->tail_len;
    if (p->tail_len && p->padding) {   /* RFC 7830, RFC 8467: pad the whole message to a multiple of the block */
        size_t r = (need + 4) % p->padding;
        padlen = r ? p->padding - r : 0;
        padopt = 4 + padlen;
    }
    if (need + padopt > cap) return 0;
    out[0] = out[1] = 0;
    out[2] = p->flags[0];
    out[3] = p->flags[1];
    out[4] = 0; out[5] = 1;
    out[6] = out[7] = out[8] = out[9] = 0;
    out[10] = 0; out[11] = p->tail_len ? 1 : 0;
    memcpy(out + 12, wname, nlen);
    out[12 + nlen] = (uint8_t)(qtype >> 8); out[13 + nlen] = (uint8_t)qtype;
    out[14 + nlen] = (uint8_t)(p->qclass >> 8); out[15 + nlen] = (uint8_t)p->qclass;
    if (p->tail_len) {
        memcpy(out + q, p->tail, p->tail_len);
        if (padopt) {
            size_t rd = ((size_t)out[q + 9] << 8) | out[q + 10];
            rd += padopt;
            out[q + 9] = (uint8_t)(rd >> 8); out[q + 10] = (uint8_t)rd;
            uint8_t *o = out + need;
            o[0] = 0; o[1] = 12; o[2] = (uint8_t)(padlen >> 8); o[3] = (uint8_t)padlen;
            memset(o + 4, 0, padlen);
        }
    }
    return need + padopt;
}

/* ---------------------------------------------------------------- names */
size_t dq_name_to_wire(const char *s, uint8_t *out, size_t cap) {
    if (s[0] == '\0' || (s[0] == '.' && s[1] == '\0')) {
        if (cap < 1) return 0;
        out[0] = 0;
        return 1;
    }
    if (cap < 2) return 0;
    size_t pos = 1, lab = 0, llen = 0;
    out[0] = 0;
    for (const char *p = s; *p;) {
        if (*p == '.') {
            if (llen == 0) return 0;
            out[lab] = (uint8_t)llen;
            if (pos >= cap) return 0;
            lab = pos;
            out[pos++] = 0;
            llen = 0;
            p++;
            continue;
        }
        uint8_t ch;
        if (*p == '\\') {
            p++;
            if (p[0] >= '0' && p[0] <= '9' && p[1] >= '0' && p[1] <= '9' && p[2] >= '0' && p[2] <= '9') {
                unsigned v = (unsigned)(p[0] - '0') * 100 + (unsigned)(p[1] - '0') * 10 + (unsigned)(p[2] - '0');
                if (v > 255) return 0;
                ch = (uint8_t)v;
                p += 3;
            } else if (*p) {
                ch = (uint8_t)*p++;
            } else {
                return 0;
            }
        } else {
            ch = (uint8_t)*p++;
        }
        if (llen >= 63 || pos >= cap) return 0;
        out[pos++] = ch;
        llen++;
    }
    if (llen > 0) {
        out[lab] = (uint8_t)llen;
        if (pos >= cap) return 0;
        out[pos++] = 0;
    }
    return pos <= 255 ? pos : 0;
}

/* ---------------------------------------------------------------- the table */
void dq_qtab_free(dq_qtab_t *t) {
    free(t->names);
    free(t->ents);
    memset(t, 0, sizeof *t);
}

static void *grow(void *p, size_t *cap, size_t need, size_t esz) {
    if (need <= *cap) return p;
    size_t nc = *cap ? *cap : 1024;
    while (nc < need) {
        if (nc > SIZE_MAX / 2 / esz) return NULL;
        nc *= 2;
    }
    void *q = realloc(p, nc * esz);
    if (q) *cap = nc;
    return q;
}

static int add_ent(dq_qtab_t *t, const uint8_t *wire, size_t nlen, uint16_t qtype, uint8_t prof) {
    if (t->names_len + nlen > UINT32_MAX) return -1;
    uint8_t *nn = grow(t->names, &t->names_cap, t->names_len + nlen, 1);
    if (!nn) return -1;
    t->names = nn;
    dq_ent_t *ne = grow(t->ents, &t->cap, t->n + 1, sizeof(dq_ent_t));
    if (!ne) return -1;
    t->ents = ne;
    memcpy(t->names + t->names_len, wire, nlen);
    t->ents[t->n].name_off = (uint32_t)t->names_len;
    t->ents[t->n].qtype = qtype;
    t->ents[t->n].prof = prof;
    t->ents[t->n].nlen = (uint8_t)nlen;
    t->n++;
    t->names_len += nlen;
    return 0;
}

static int find_prof(dq_qtab_t *t, const dq_prof_t *p) {
    for (unsigned i = 0; i < t->nprof; i++)
        if (memcmp(t->profs[i].flags, p->flags, 2) == 0 && t->profs[i].qclass == p->qclass && t->profs[i].padding == p->padding &&
            t->profs[i].tail_len == p->tail_len && memcmp(t->profs[i].tail, p->tail, p->tail_len) == 0)
            return (int)i;
    if (t->nprof >= DQ_MAXPROF) return -1;
    t->profs[t->nprof] = *p;
    return (int)t->nprof++;
}

/* one line of the query file (modified in place) */
static int add_line(dq_qtab_t *t, const dq_cfg_t *c, char *line, size_t lineno, char *err, size_t errlen) {
    char *toks[24];
    int nt = 0;
    char *p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        if (nt == 0 && (*p == '#' || *p == ';')) return 0;
        if (nt >= 24) { snprintf(err, errlen, "line %zu: too many fields", lineno); return -1; }
        toks[nt++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        if (*p) *p++ = '\0';
    }
    if (nt == 0) return 0;
    uint8_t wire[256];
    size_t nlen = dq_name_to_wire(toks[0], wire, sizeof wire);
    if (!nlen) { snprintf(err, errlen, "line %zu: bad name '%.60s'", lineno, toks[0]); return -1; }
    uint16_t qtype = 1;
    int first_opt = 1;
    if (nt > 1 && toks[1][0] != '+') {
        qtype = get_type_code(toks[1]);
        if (!qtype) { snprintf(err, errlen, "line %zu: unknown type '%.30s'", lineno, toks[1]); return -1; }
        first_opt = 2;
    }
    dq_qopts_t o = c->qo;
    for (int i = first_opt; i < nt; i++) {
        char e2[120];
        if (dq_qopts_parse_tok(&o, toks[i], e2, sizeof e2) < 0) { snprintf(err, errlen, "line %zu: %s", lineno, e2); return -1; }
    }
    dq_prof_t pr;
    if (!dq_prof_make(&pr, &o)) { snprintf(err, errlen, "line %zu: the options do not fit", lineno); return -1; }
    int pi = find_prof(t, &pr);
    if (pi < 0) { snprintf(err, errlen, "line %zu: more than %d different option sets", lineno, DQ_MAXPROF); return -1; }
    if (add_ent(t, wire, nlen, qtype, (uint8_t)pi) < 0) { snprintf(err, errlen, "line %zu: out of memory or table too large", lineno); return -1; }
    return 0;
}

int dq_qtab_from_lines(dq_qtab_t *t, const dq_cfg_t *c, const char *text, size_t len, char *err, size_t errlen) {
    memset(t, 0, sizeof *t);
    size_t lineno = 0, i = 0;
    char buf[1024];
    while (i < len) {
        size_t j = i;
        while (j < len && text[j] != '\n') j++;
        lineno++;
        if (j - i >= sizeof buf) { snprintf(err, errlen, "line %zu: too long", lineno); dq_qtab_free(t); return -1; }
        memcpy(buf, text + i, j - i);
        buf[j - i] = '\0';
        if (add_line(t, c, buf, lineno, err, errlen) < 0) { dq_qtab_free(t); return -1; }
        i = j + 1;
    }
    if (t->n == 0) { snprintf(err, errlen, "no query in the text"); dq_qtab_free(t); return -1; }
    return 0;
}

static int read_file(dq_qtab_t *t, const dq_cfg_t *c, const char *path, bool names_only, char *err, size_t errlen) {
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, errlen, "cannot open %.200s", path); return -1; }
    char line[1024];
    size_t lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        size_t l = strlen(line);
        if (l == sizeof line - 1 && line[l - 1] != '\n' && !feof(f)) { snprintf(err, errlen, "%.100s line %zu: too long", path, lineno); fclose(f); return -1; }
        if (names_only) {   /* a list of names: the first field of each line */
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == ';' || *p == '\r' || *p == '\n' || !*p) continue;
            char *e = p;
            while (*e && *e != ' ' && *e != '\t' && *e != '\r' && *e != '\n') e++;
            *e = '\0';
            uint8_t wire[256];
            size_t nlen = dq_name_to_wire(p, wire, sizeof wire);
            if (!nlen) { snprintf(err, errlen, "%.100s line %zu: bad name '%.60s'", path, lineno, p); fclose(f); return -1; }
            if (add_ent(t, wire, nlen, 0, 0) < 0) { snprintf(err, errlen, "%.100s: out of memory or table too large", path); fclose(f); return -1; }
        } else if (add_line(t, c, line, lineno, err, errlen) < 0) {
            char tmp[200];
            snprintf(tmp, sizeof tmp, "%.80s: %.100s", path, err);
            snprintf(err, errlen, "%s", tmp);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

static uint64_t splitmix(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static int gen_table(dq_qtab_t *t, const dq_cfg_t *c, char *err, size_t errlen) {
    if (read_file(t, c, c->zfile, true, err, errlen) < 0) return -1;
    if (t->n == 0) { snprintf(err, errlen, "%.200s holds no name", c->zfile); return -1; }
    t->gen = true;
    t->nhit = t->n;
    dq_prof_t pr;
    if (!dq_prof_make(&pr, &c->qo)) { snprintf(err, errlen, "the options do not fit"); return -1; }
    t->profs[0] = pr;
    t->nprof = 1;
    uint16_t types[DQ_MAXTYPES];
    uint32_t w[DQ_MAXTYPES];
    int nt = dq_parse_qtypes(c->qtypes[0] ? c->qtypes : "A", types, w, err, errlen);
    if (nt < 0) return -1;
    uint64_t sum = 0, acc = 0;
    for (int i = 0; i < nt; i++) sum += w[i];
    for (int i = 0; i < nt; i++) {
        acc += w[i];
        t->types[i] = types[i];
        t->cum[i] = (uint32_t)((acc * 4294967295.0) / (double)sum);
    }
    t->cum[nt - 1] = UINT32_MAX;
    t->ntypes = (unsigned)nt;
    t->zipf_s = c->zipf;
    t->zipf_pow = pow((double)t->nhit + 1.0, 1.0 - c->zipf);
    if (c->miss > 0) {
        uint64_t seed = c->seed;
        size_t pool = c->miss_pool ? c->miss_pool : 65536;
        t->miss_thr = c->miss >= 1.0 ? UINT32_MAX : (uint32_t)(c->miss * 4294967296.0);
        size_t base_n = t->nhit;
        for (size_t i = 0; i < pool; i++) {
            /* nx<i>.<a name of the list>: a label that is not in the zone, under a zone that is */
            const dq_ent_t *b = &t->ents[splitmix(&seed) % base_n];
            uint8_t wire[256 + 16], base[256];
            memcpy(base, t->names + b->name_off, b->nlen);   /* the table may move when it grows */
            char lab[24];
            int ll = snprintf(lab, sizeof lab, "nx%zu", i);
            size_t total = 1 + (size_t)ll + b->nlen;
            if (b->nlen == 1 || total > 255) { memcpy(wire, base, b->nlen); total = b->nlen; }   /* the root, or too long: the name itself */
            else {
                wire[0] = (uint8_t)ll;
                memcpy(wire + 1, lab, (size_t)ll);
                memcpy(wire + 1 + ll, base, b->nlen);
            }
            if (add_ent(t, wire, total, 0, 0) < 0) { snprintf(err, errlen, "out of memory"); return -1; }
            t->nmiss++;
        }
    }
    return 0;
}

int dq_qtab_load(dq_qtab_t *t, const dq_cfg_t *c, char *err, size_t errlen) {
    memset(t, 0, sizeof *t);
    int rc;
    if (c->zfile[0]) rc = gen_table(t, c, err, errlen);
    else if (c->qfile[0]) {
        rc = read_file(t, c, c->qfile, false, err, errlen);
        if (rc == 0 && t->n == 0) { snprintf(err, errlen, "%.200s holds no query", c->qfile); rc = -1; }
    } else {
        snprintf(err, errlen, "no queries: give a query file (-d FILE) or a name list (-z FILE)");
        rc = -1;
    }
    if (rc < 0) dq_qtab_free(t);
    return rc;
}

void dq_cur_init(dq_cur_t *c, const dq_qtab_t *t, unsigned worker, unsigned nworkers, uint64_t seed) {
    (void)t;
    uint64_t s = seed + (uint64_t)worker * 0x9E3779B97F4A7C15ull;
    c->rng = splitmix(&s) | 1;
    c->pos = worker;
    c->stride = nworkers ? nworkers : 1;
    c->runs_done = 0;
}

static inline uint64_t rng_next(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

size_t dq_next_query(const dq_qtab_t *t, dq_cur_t *c, uint8_t *out, size_t cap, uint64_t max_runs) {
    if (!t->gen) {
        if (c->pos >= t->n) {   /* the end of a pass over this worker's share */
            c->runs_done++;
            if (max_runs && c->runs_done >= max_runs) return 0;
            c->pos %= c->stride;
            if (c->pos >= t->n) return 0;
        }
        const dq_ent_t *e = &t->ents[c->pos];
        c->pos += c->stride;
        return dq_compose(out, cap, &t->profs[e->prof], t->names + e->name_off, e->nlen, e->qtype);
    }
    uint64_t r1 = rng_next(&c->rng), r2 = rng_next(&c->rng), r3 = rng_next(&c->rng);
    size_t idx;
    if (t->nmiss && (uint32_t)r1 < t->miss_thr) {
        idx = t->nhit + (size_t)((r1 >> 32) % t->nmiss);
    } else {
        double u = (double)((r2 >> 11) + 1) * (1.0 / 9007199254740993.0), x;   /* (0,1) */
        if (t->zipf_s == 1.0) x = pow((double)t->nhit + 1.0, u);
        else x = pow(u * (t->zipf_pow - 1.0) + 1.0, 1.0 / (1.0 - t->zipf_s));
        size_t k = x >= 1.0 ? (size_t)x : 1;
        k--;
        if (k >= t->nhit) k = t->nhit - 1;
        idx = t->nhit > 1 ? (size_t)(((uint64_t)k * 0x9E3779B97F4A7C15ull) % t->nhit) : 0;   /* the popular names are spread over the list */
    }
    uint32_t q = (uint32_t)(r3 >> 32);
    unsigned ti = 0;
    while (ti + 1 < t->ntypes && q > t->cum[ti]) ti++;
    const dq_ent_t *e = &t->ents[idx];
    return dq_compose(out, cap, &t->profs[0], t->names + e->name_off, e->nlen, t->types[ti]);
}
