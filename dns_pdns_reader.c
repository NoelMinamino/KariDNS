/*
 * dns_pdns_reader.c - PowerDNS 5.1 reader core (beta design 3.1-3.5).  See dns_pdns_reader.h for the rules.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>

#include "dns_pdns_reader.h"
#include "dns_config_parser.h"   /* option ranges (NOTIFY_RETRIES_MAX, IXFR_HISTORY_MAX, KARIDNS_*_MIN/MAX) */
#include "dns_cidr.h"
#include "dns_utils.h"

#define PDNS_DEFAULT_MAX_TEXT (4ull << 30)
#define PDNS_MAX_LIST 1024
#define PDNS_MAX_NAME_TEXT 1024

static void ext_free(pdns_zone_t *z);

/* ------------------------------------------------------------------------------------------------------------- */
/* diagnostics                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

/* Messages are logged and sent to the operator: text that came from the DB (a domainmetadata kind or value, an owner)
 * must not carry control characters or line breaks into a log (log injection).  Done once, here, for every message. */
static void sanitize_msg(char *s) {
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7E) *s = '?';
}

static void zfail(pdns_zone_t *z, bool has_row, int64_t id, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void zfail(pdns_zone_t *z, bool has_row, int64_t id, const char *fmt, ...) {
    if (z->failed) return;
    char why[PDNS_ERR_LEN / 2];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, sizeof(why), fmt, ap);
    va_end(ap);
    sanitize_msg(why);
    z->failed = true;
    z->error_has_row = has_row;
    z->error_row_id = id;
    if (has_row)
        snprintf(z->error, sizeof(z->error), "zone '%s' records.id %lld: %s", z->name, (long long)id, why);
    else
        snprintf(z->error, sizeof(z->error), "zone '%s': %s", z->name, why);
}

static void zwarn(pdns_zone_t *z, bool has_row, int64_t id, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void zwarn(pdns_zone_t *z, bool has_row, int64_t id, const char *fmt, ...) {
    if (z->n_warnings >= PDNS_MAX_WARNINGS) {
        z->warnings_dropped++;
        return;
    }
    char why[PDNS_ERR_LEN / 2], line[PDNS_ERR_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, sizeof(why), fmt, ap);
    va_end(ap);
    sanitize_msg(why);
    if (has_row)
        snprintf(line, sizeof(line), "zone '%s' records.id %lld: %s", z->name, (long long)id, why);
    else
        snprintf(line, sizeof(line), "zone '%s': %s", z->name, why);
    char **nw = realloc(z->warnings, (z->n_warnings + 1) * sizeof(char *));
    if (!nw) return;
    z->warnings = nw;
    char *dup = strdup(line);
    if (!dup) return;
    z->warnings[z->n_warnings++] = dup;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* line safety (RFC 1035 5.1 and the tokenizer of dns_zone_parser.c)                                              */
/* ------------------------------------------------------------------------------------------------------------- */

const char *pdns_text_check(const char *s, size_t len, bool is_owner) {
    /* pass 1: characters that can end or hide a line, whatever the quoting */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0) return "contains a NUL byte";
        if (c == '\n' || c == '\r') return "contains a line break";
        if (c == '\t' || c == ' ') {
            if (is_owner) return "contains whitespace";
            continue;
        }
        if (c < 0x20 || c == 0x7F) return "contains a control character";
    }
    /* first non-blank character: '$' makes the line a directive */
    size_t first = 0;
    while (first < len && (s[first] == ' ' || s[first] == '\t')) first++;
    if (first < len && s[first] == '$') return "starts with '$' (zone file directive)";

    /* pass 2: follow the tokenizer.  '\' takes the next character literally, '"' toggles quoting, outside quotes
     * ';' starts a comment and '(' ')' open / close a group. */
    bool inq = false;
    int depth = 0;
    size_t tok_start = 0, tok_n = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '\\') {
            if (i + 1 >= len) return "ends with a lone backslash";
            if (tok_n == 0) tok_start = i;
            tok_n += 2;
            i++;
            continue;
        }
        if (c == '"') {
            if (is_owner) return "contains a double quote";
            inq = !inq;
            if (tok_n == 0) tok_start = i;
            tok_n++;
            continue;
        }
        if (!inq) {
            bool boundary = false;
            if (c == ';') return "contains ';' outside quotes (comment)";
            if (c == '(') {
                if (is_owner) return "contains '('";
                if (depth) return "contains nested parentheses";
                depth = 1;
                boundary = true;
            } else if (c == ')') {
                if (is_owner) return "contains ')'";
                if (!depth) return "contains ')' without '('";
                depth = 0;
                boundary = true;
            } else if (c == ' ' || c == '\t') {
                boundary = true;
            }
            if (boundary) {
                if (tok_n == 1 && s[tok_start] == '@') return "contains a bare '@' token";
                tok_n = 0;
                continue;
            }
        }
        if (tok_n == 0) tok_start = i;
        tok_n++;
    }
    if (inq) return "has an unbalanced double quote";
    if (depth) return "has an unbalanced parenthesis";
    if (tok_n == 1 && s[tok_start] == '@') return "contains a bare '@' token";
    return NULL;
}

/* number of blank-separated fields (quotes and escapes as the tokenizer sees them); the text passed pdns_text_check() */
static int count_fields(const char *s, size_t len) {
    int n = 0;
    bool inq = false, in_tok = false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!inq && c != '\\' && c != '"' && (c == ' ' || c == '\t' || c == '(' || c == ')')) {
            in_tok = false;
            continue;
        }
        if (!in_tok) {
            in_tok = true;
            n++;
        }
        if (c == '\\')
            i++;
        else if (c == '"')
            inq = !inq;
    }
    return n;
}

bool pdns_soa_serial(const char *content, uint32_t *serial) {
    if (!content) return false;
    const char *p = content;
    for (int field = 0; field < 3; field++) {
        while (*p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (p == start) return false;
        if (field < 2) continue;
        uint64_t v = 0;
        for (const char *d = start; d < p; d++) {
            if (*d < '0' || *d > '9') return false;
            v = v * 10 + (uint64_t)(*d - '0');
            if (v > 0xFFFFFFFFull) return false;
        }
        if (serial) *serial = (uint32_t)v;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* names                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

/* raw (as stored, usually without the trailing dot) -> canonical absolute name.  false: not a name. */
static bool name_to_absolute(const char *raw, size_t len, char *out, size_t cap) {
    if (len == 0 || len > PDNS_MAX_NAME_TEXT) return false;
    char tmp[PDNS_MAX_NAME_TEXT + 2];
    memcpy(tmp, raw, len);
    tmp[len] = '\0';
    if (dns_name_len_no_root(tmp, len) == len) {   /* no unescaped trailing dot */
        tmp[len] = '.';
        tmp[len + 1] = '\0';
    }
    if (strcmp(tmp, ".") == 0) return false;       /* the root is not a record owner here */
    size_t n = dns_name_normalize(tmp, out, cap);
    return n != (size_t)-1 && n > 0 && out[n - 1] == '.';
}

/* ------------------------------------------------------------------------------------------------------------- */
/* zone object                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

pdns_zone_t *pdns_zone_new(const char *zone_name, const pdns_opts_t *opts) {
    pdns_zone_t *z = calloc(1, sizeof(*z));
    if (!z) return NULL;
    if (opts) z->opts = *opts;
    if (z->opts.default_ttl == 0) z->opts.default_ttl = PDNS_DEFAULT_TTL;
    if (z->opts.default_ttl > PDNS_MAX_TTL) z->opts.default_ttl = PDNS_MAX_TTL;
    if (z->opts.max_records == 0) z->opts.max_records = KDB_DEFAULT_MAX_ZONE_RECORDS;
    if (z->opts.max_text_bytes == 0) z->opts.max_text_bytes = PDNS_DEFAULT_MAX_TEXT;
    if (z->opts.max_zone_bytes == 0) z->opts.max_zone_bytes = KDB_DEFAULT_MAX_ZONE_BYTES;

    const char *zn = zone_name ? zone_name : "";
    const char *why = NULL;
    size_t zl = strlen(zn);
    if (zl == 0 || strcmp(zn, ".") == 0)
        why = "the root zone is not supported";
    else if ((why = pdns_text_check(zn, zl, true)) == NULL && !name_to_absolute(zn, zl, z->name, sizeof(z->name)))
        why = "not a valid zone name (bad escape, empty label, or name too long)";
    if (why) {
        /* keep a printable name for the message: printable ASCII only, at most 200 characters */
        size_t k = 0;
        for (; k < zl && k < 200; k++)
            z->name[k] = (zn[k] >= 0x20 && zn[k] < 0x7F) ? zn[k] : '?';
        z->name[k] = '\0';
        zfail(z, false, 0, "%s", why);
        return z;
    }
    const char *hdr = "$ORIGIN .\n";
    z->text_cap = 4096;
    z->text = malloc(z->text_cap);
    if (!z->text) {
        free(z);
        return NULL;
    }
    z->text_len = strlen(hdr);
    memcpy(z->text, hdr, z->text_len);
    return z;
}

/* B7b: make the zone a secondary (KDB_ZK_SECONDARY, a SLAVE) or a catalog consumer (KDB_ZK_CATALOG, a CONSUMER) whose masters are
 * domains.master.  Records are ignored; pdns_zone_finish() converts the metadata only. */
int pdns_zone_set_secondary(pdns_zone_t *z, uint8_t kind, const char *master) {
    char *m = master ? strdup(master) : NULL;
    if (master && !m) return -1;
    free(z->master);
    z->master = m;
    z->zkind = kind;
    return 0;
}

/* The canonical absolute name pdns_zone_new() would give a zone called dbname; false when it would be a failed zone. */
bool pdns_canonical_zone_name(const char *dbname, char out[DNS_NAME_TEXT_SIZE]) {
    if (!dbname) return false;
    size_t zl = strlen(dbname);
    if (zl == 0 || strcmp(dbname, ".") == 0) return false;
    if (pdns_text_check(dbname, zl, true) != NULL) return false;
    return name_to_absolute(dbname, zl, out, DNS_NAME_TEXT_SIZE);
}

void pdns_zone_free(pdns_zone_t *z) {
    if (!z) return;
    if (z->arena_ready) zone_arena_destroy(&z->arena);
    free(z->text);
    free(z->line_off);
    free(z->line_id);
    free(z->ord_off);
    free(z->ord_pool);
    free(z->text2);
    for (size_t i = 0; i < z->n_meta; i++) free(z->meta[i].content);
    free(z->meta);
    for (size_t i = 0; i < z->n_ents; i++) {
        free(z->ents[i].name);
        free(z->ents[i].ordername);
    }
    free(z->ents);
    free(z->settings);
    free(z->master);
    ext_free(z);
    free(z->nsec3param);
    for (size_t i = 0; i < z->n_warnings; i++) free(z->warnings[i]);
    free(z->warnings);
    free(z);
}

/* 0 = room made; 1 = over the size limit; -1 = out of memory */
static int text_reserve(pdns_zone_t *z, size_t extra) {
    if (extra > z->opts.max_text_bytes || z->text_len > z->opts.max_text_bytes - extra) return 1;
    size_t need = z->text_len + extra + 1;
    if (need <= z->text_cap) return 0;
    size_t nc = z->text_cap;
    while (nc < need) {
        if (nc > SIZE_MAX / 2) return -1;
        nc *= 2;
    }
    char *nt = realloc(z->text, nc);
    if (!nt) return -1;
    z->text = nt;
    z->text_cap = nc;
    return 0;
}

static bool rows_reserve(pdns_zone_t *z) {
    if (z->n_rows < z->rows_cap) return true;
    if (z->rows_cap > SIZE_MAX / 2 / sizeof(int64_t)) return false;
    size_t nc = z->rows_cap ? z->rows_cap * 2 : 64;
    size_t *lo = realloc(z->line_off, nc * sizeof(size_t));
    if (!lo) return false;
    z->line_off = lo;
    int64_t *li = realloc(z->line_id, nc * sizeof(int64_t));
    if (!li) return false;
    z->line_id = li;
    size_t *oo = realloc(z->ord_off, nc * sizeof(size_t));
    if (!oo) return false;
    z->ord_off = oo;
    z->rows_cap = nc;
    return true;
}

static bool type_token_ok(const char *t) {
    size_t n = t ? strlen(t) : 0;
    if (n == 0 || n > PDNS_MAX_TYPE_LEN) return false;
    if (!isalpha((unsigned char)t[0])) return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)t[i]) && t[i] != '-') return false;
    return true;
}

/* The ordername of the row about to become row z->n_rows (presigned checks, dns_presigned.h).  The rows of one owner
 * carry the same value, so a value equal to the previous row's is stored once.  A value longer than the column
 * (255) is replaced by a marker that matches no hash and no name. */
static int store_ordername(pdns_zone_t *z, const char *on) {
    size_t i = z->n_rows;
    if (!on) {
        z->ord_off[i] = 0;
        return 0;
    }
    if (strlen(on) > 255) on = "\x01too-long";
    if (i > 0 && z->ord_off[i - 1] && strcmp(z->ord_pool + z->ord_off[i - 1] - 1, on) == 0) {
        z->ord_off[i] = z->ord_off[i - 1];
        return 0;
    }
    size_t n = strlen(on) + 1;
    if (z->ord_len + n > z->ord_cap) {
        size_t nc = z->ord_cap ? z->ord_cap : 1024;
        while (nc < z->ord_len + n) nc *= 2;
        char *np = realloc(z->ord_pool, nc);
        if (!np) return -1;
        z->ord_pool = np;
        z->ord_cap = nc;
    }
    memcpy(z->ord_pool + z->ord_len, on, n);
    z->ord_off[i] = z->ord_len + 1;
    z->ord_len += n;
    return 0;
}

int pdns_zone_add_record(pdns_zone_t *z, const db_record_row_t *row) {
    if (z->failed) return -1;
    if (z->finished) {
        zfail(z, false, 0, "internal error: record added after pdns_zone_finish()");
        return -1;
    }
    if (row->disabled) return 0;                                   /* rule 1 */
    int64_t id = row->id;
    if (++z->n_seen > z->opts.max_records) {
        zfail(z, true, id, "more than %llu rows (max-zone-records)", (unsigned long long)z->opts.max_records);
        return -1;
    }

    /* owner: needed by ENT rows and normal rows alike */
    size_t nlen = row->name ? strlen(row->name) : 0;
    char owner[DNS_NAME_TEXT_SIZE];
    if (nlen == 0) {
        zfail(z, true, id, "empty owner name");
        return -1;
    }
    const char *why = pdns_text_check(row->name, nlen, true);
    if (why) {
        zfail(z, true, id, "owner name %s", why);
        return -1;
    }
    if (!name_to_absolute(row->name, nlen, owner, sizeof(owner))) {
        zfail(z, true, id, "owner name is not a valid domain name (bad escape, empty label, or too long)");
        return -1;
    }
    if (!domain_name_is_at_or_below(owner, z->name)) {
        zfail(z, true, id, "owner name '%.200s' is outside the zone", owner);
        return -1;
    }

    if (!row->type) {                                              /* rule 2: empty non-terminal */
        if (z->n_ents >= z->ents_cap) {
            size_t nc = z->ents_cap ? z->ents_cap * 2 : 16;
            pdns_ent_t *ne = z->ents_cap > SIZE_MAX / 2 / sizeof(*ne) ? NULL : realloc(z->ents, nc * sizeof(*ne));
            if (!ne) {
                zfail(z, true, id, "out of memory");
                return -1;
            }
            z->ents = ne;
            z->ents_cap = nc;
        }
        pdns_ent_t *e = &z->ents[z->n_ents];
        e->row_id = id;
        e->name = strdup(owner);
        e->ordername = row->ordername ? strdup(row->ordername) : NULL;
        if (!e->name || (row->ordername && !e->ordername)) {
            free(e->name);
            free(e->ordername);
            zfail(z, true, id, "out of memory");
            return -1;
        }
        z->n_ents++;
        return 0;
    }

    /* rule 3: type token */
    if (!type_token_ok(row->type)) {
        zfail(z, true, id, "bad record type token (letters, digits and '-' only, starting with a letter)");
        return -1;
    }
    char type[PDNS_MAX_TYPE_LEN + 1];
    size_t tl = strlen(row->type);
    for (size_t i = 0; i <= tl; i++) type[i] = (char)toupper((unsigned char)row->type[i]);
    if (strcmp(type, "ALIAS") == 0) {                              /* B9a replaces this */
        zfail(z, true, id, "ALIAS records are not supported yet (milestone B9a)");
        return -1;
    }
    if (strcmp(type, "LUA") == 0) {                                /* B9a replaces this */
        zfail(z, true, id, "LUA records are not supported yet (milestone B9a)");
        return -1;
    }

    /* rule 5: ttl */
    uint32_t ttl;
    if (row->ttl_null) {
        ttl = z->opts.default_ttl;
        if (z->n_null_ttl++ == 0) z->first_null_ttl_id = id;
    } else if (row->ttl < 0 || row->ttl > (int64_t)PDNS_MAX_TTL) {
        zfail(z, true, id, "ttl %lld is outside 0..%u", (long long)row->ttl, PDNS_MAX_TTL);
        return -1;
    } else {
        ttl = (uint32_t)row->ttl;
    }

    /* rule 7: content */
    size_t clen = row->content ? strlen(row->content) : 0;
    if (clen > PDNS_MAX_CONTENT) {
        zfail(z, true, id, "content is longer than %u bytes", PDNS_MAX_CONTENT);
        return -1;
    }
    size_t cstart = 0;
    while (cstart < clen && (row->content[cstart] == ' ' || row->content[cstart] == '\t')) cstart++;
    if (cstart == clen) {
        zfail(z, true, id, "empty content");
        return -1;
    }
    why = pdns_text_check(row->content, clen, false);
    if (why) {
        zfail(z, true, id, "content %s", why);
        return -1;
    }

    /* rule 6: prio */
    bool is_mx = strcmp(type, "MX") == 0, is_srv = strcmp(type, "SRV") == 0;
    bool prepend = false;
    unsigned prio_val = 0;
    bool prio_nz = !row->prio_null && row->prio != 0;
    if (is_mx || is_srv) {
        int nf = count_fields(row->content, clen);
        int have_prio_fields = is_mx ? 2 : 4;
        if (nf == have_prio_fields - 1) {
            if (!row->prio_null && (row->prio < 0 || row->prio > 65535)) {
                zfail(z, true, id, "prio %lld is outside 0..65535", (long long)row->prio);
                return -1;
            }
            prepend = true;
            prio_val = row->prio_null ? 0 : (unsigned)row->prio;
        } else if (nf == have_prio_fields && prio_nz) {
            zfail(z, true, id, "%s content already has a %s and prio is %lld: ambiguous", type,
                  is_mx ? "preference" : "priority", (long long)row->prio);
            return -1;
        }
    } else if (prio_nz) {
        if (z->n_prio_ignored++ == 0) z->first_prio_ignored_id = id;
    }

    /* SOA: at the apex, with a serial.  B8t-1: several rows are allowed (a tinydns zone has one SOA per location, a tagged zone one per
     * tag); they must have one serial (checked with the records in pdns_zone_finish()) */
    if (strcmp(type, "SOA") == 0) {
        if (!domain_names_match_ci(owner, z->name)) {
            zfail(z, true, id, "SOA record at '%.200s', not at the zone apex", owner);
            return -1;
        }
        if (z->n_soa++ == 0) {
            z->soa_row_id = id;
            z->soa_row_index = z->n_rows;     /* the row about to be added */
        }
        if (!pdns_soa_serial(row->content, NULL)) {
            zfail(z, true, id, "SOA serial is not a decimal number up to 4294967295");
            return -1;
        }
    }

    /* ZONE_BEGIN rr_count counts both SOAs (RFC 5936 2.2) and the Backend refuses a count above max-zone-records: the
     * RRs of this zone plus the closing SOA must stay within it, or the loader would send a zone that kills the stream */
    if ((uint64_t)z->n_rows + 2 > z->opts.max_records) {
        zfail(z, true, id, "more than %llu records (max-zone-records; the SOA counts twice)", (unsigned long long)z->opts.max_records);
        return -1;
    }

    /* the line.  The canonical owner unescapes ';' '"' '(' ')' '$' '@' that the row escaped (pdns_text_check() saw them
     * escaped); written as they are they would start a comment or a directive in the line (RFC 1035 5.1) */
    char otok[2 * DNS_NAME_TEXT_SIZE];
    size_t olen = dns_name_zone_token(owner, otok, sizeof(otok));
    if (olen == (size_t)-1) {
        zfail(z, true, id, "owner name is too long");
        return -1;
    }
    int tr = text_reserve(z, olen + clen + tl + 64);
    if (tr == 0 && !rows_reserve(z)) tr = -1;
    if (tr != 0) {
        zfail(z, true, id, "%s", tr > 0 ? "zone text exceeds the size limit (max-text-bytes)" : "out of memory");
        return -1;
    }
    if (store_ordername(z, row->ordername) != 0) {
        zfail(z, true, id, "out of memory");
        return -1;
    }
    z->line_off[z->n_rows] = z->text_len;
    z->line_id[z->n_rows] = id;
    z->n_rows++;
    char *w = z->text + z->text_len;
    memcpy(w, otok, olen);
    w += olen;
    w += sprintf(w, " %u IN %s ", ttl, type);
    if (prepend) w += sprintf(w, "%u ", prio_val);
    memcpy(w, row->content, clen);
    w += clen;
    *w++ = '\n';
    *w = '\0';
    z->text_len = (size_t)(w - z->text);
    return 0;
}

int pdns_zone_add_meta(pdns_zone_t *z, const db_meta_row_t *row) {
    if (z->failed) return -1;
    if (z->finished) {
        zfail(z, false, 0, "internal error: metadata added after pdns_zone_finish()");
        return -1;
    }
    if (!row->kind || !*row->kind) return 0;
    size_t kl = strlen(row->kind);
    size_t cl = row->content ? strlen(row->content) : 0;
    if (kl > 64) {
        zwarn(z, false, 0, "domainmetadata kind longer than 64 bytes ignored");
        return 0;
    }
    if (cl > PDNS_MAX_META_CONTENT) {
        zwarn(z, false, 0, "domainmetadata %.64s content longer than %u bytes ignored", row->kind, PDNS_MAX_META_CONTENT);
        return 0;
    }
    if (z->n_meta >= PDNS_MAX_META_ROWS) {
        zfail(z, false, 0, "more than %u domainmetadata rows", PDNS_MAX_META_ROWS);
        return -1;
    }
    if (z->n_meta >= z->meta_cap) {
        size_t nc = z->meta_cap ? z->meta_cap * 2 : 16;
        pdns_meta_t *nm = realloc(z->meta, nc * sizeof(*nm));
        if (!nm) {
            zfail(z, false, 0, "out of memory");
            return -1;
        }
        z->meta = nm;
        z->meta_cap = nc;
    }
    pdns_meta_t *m = &z->meta[z->n_meta];
    memcpy(m->kind, row->kind, kl + 1);
    m->content = malloc(cl + 1);
    if (!m->content) {
        zfail(z, false, 0, "out of memory");
        return -1;
    }
    if (cl) memcpy(m->content, row->content, cl);
    m->content[cl] = '\0';
    z->n_meta++;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* B8: Extended AXFR attributes (design 3.6a, 3.7)                                                                */
/* ------------------------------------------------------------------------------------------------------------- */

#define PDNS_MAX_TAG 63             /* a tag state record carries at most 63 octets (axfr_session_t.current_*_tag) */
#define PDNS_MAX_TDNS_LOCS 4096     /* the limit of the tinydns data parser */

/* a tag name: 1-63 printable characters, no blank; "none" and "default" clear a tag in a zone file ($LOCATION none) */
static bool tag_name_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > PDNS_MAX_TAG) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x21 || (unsigned char)s[i] > 0x7E) return false;
    return strcasecmp(s, "none") != 0 && strcasecmp(s, "default") != 0;
}

/* a tinydns location code: 1-2 printable characters (the data file takes any octet but the colon; the database keeps text) */
static bool tdns_code_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 2) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x21 || (unsigned char)s[i] > 0x7E) return false;
    return true;
}

static int ext_prep(pdns_zone_t *z, const char *what) {
    if (z->failed) return -1;
    if (z->finished) {
        zfail(z, false, 0, "internal error: %s added after pdns_zone_finish()", what);
        return -1;
    }
    return 0;
}

static bool ext_grow(void **v, size_t *cap, size_t n, size_t esz) {
    if (n < *cap) return true;
    size_t nc = *cap ? *cap * 2 : 16;
    void *nv = realloc(*v, nc * esz);
    if (!nv) return false;
    *v = nv;
    *cap = nc;
    return true;
}

int pdns_zone_add_tags(pdns_zone_t *z, const db_tag_row_t *row) {
    if (ext_prep(z, "record tags") != 0) return -1;
    const char *loc = row->location_tag && *row->location_tag ? row->location_tag : NULL;
    const char *ecs = row->ecs_tag && *row->ecs_tag ? row->ecs_tag : NULL;
    if (!loc && !ecs) return 0;
    if (loc && !tag_name_ok(loc)) {
        zfail(z, true, row->record_id, "karidns_record_tags.location_tag is not a tag name (1-63 printable characters without blanks; none and default are reserved)");
        return -1;
    }
    if (ecs && !tag_name_ok(ecs)) {
        zfail(z, true, row->record_id, "karidns_record_tags.ecs_tag is not a tag name (1-63 printable characters without blanks; none and default are reserved)");
        return -1;
    }
    if (z->n_tags >= z->opts.max_records) {
        zfail(z, false, 0, "more karidns_record_tags rows than max-zone-records");
        return -1;
    }
    char *l = loc ? strdup(loc) : NULL, *e = ecs ? strdup(ecs) : NULL;
    if ((loc && !l) || (ecs && !e) || !ext_grow((void **)&z->tags, &z->tags_cap, z->n_tags, sizeof(*z->tags))) {
        free(l);
        free(e);
        zfail(z, false, 0, "out of memory");
        return -1;
    }
    z->tags[z->n_tags++] = (struct pdns_tagrow){ row->record_id, l, e };
    return 0;
}

int pdns_zone_add_tinydns(pdns_zone_t *z, const db_tinydns_row_t *row) {
    if (ext_prep(z, "tinydns attributes") != 0) return -1;
    const char *loc = row->loc && *row->loc ? row->loc : NULL;
    int64_t ttd = row->ttd_null ? 0 : row->ttd;
    if (loc && !tdns_code_ok(loc)) {
        zfail(z, true, row->record_id, "karidns_record_tinydns.loc is not a location code (1 or 2 printable characters)");
        return -1;
    }
    if (ttd < 0) {
        zfail(z, true, row->record_id, "karidns_record_tinydns.ttd is negative");
        return -1;
    }
    if (row->countdown && ttd == 0) {
        zfail(z, true, row->record_id, "karidns_record_tinydns: countdown without a ttd");
        return -1;
    }
    if (!loc && ttd == 0) return 0;
    if (z->n_tdns >= z->opts.max_records) {
        zfail(z, false, 0, "more karidns_record_tinydns rows than max-zone-records");
        return -1;
    }
    if (!ext_grow((void **)&z->tdns, &z->tdns_cap, z->n_tdns, sizeof(*z->tdns))) {
        zfail(z, false, 0, "out of memory");
        return -1;
    }
    struct pdns_tdrow *t = &z->tdns[z->n_tdns++];
    t->id = row->record_id;
    t->ttd = ttd;
    t->loc[0] = loc ? loc[0] : 0;
    t->loc[1] = loc && loc[1] ? loc[1] : 0;
    t->countdown = row->countdown;
    return 0;
}

static void defs_free(ecs_tag_def_t *d, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < d[i].cidr_count; j++) free(d[i].cidrs[j].cidr);
        free(d[i].cidrs);
        free(d[i].tag);
    }
    free(d);
}

/* a $LOCATION-TAG / $ECS-SUBNET-TAG line of a zone file is one definition (one tag, several CIDRs, first match wins); the
 * database has one CIDR per row, so the consecutive rows of one tag are one definition.  -1: out of memory */
static int defs_add(ecs_tag_def_t **defs, int *n, const char *tag, const char *cidr) {
    if (*n > 0 && strcmp((*defs)[*n - 1].tag, tag) == 0) {
        ecs_tag_def_t *d = &(*defs)[*n - 1];
        ecs_cidr_entry_t *nc = realloc(d->cidrs, (size_t)(d->cidr_count + 1) * sizeof(*nc));
        if (!nc) return -1;
        d->cidrs = nc;
        char *c = strdup(cidr);
        if (!c) return -1;
        memset(&nc[d->cidr_count], 0, sizeof(*nc));
        nc[d->cidr_count].cidr = c;
        cidr_entry_parse(&nc[d->cidr_count].parsed, c);
        d->cidr_count++;
        return 0;
    }
    ecs_tag_def_t *nd = realloc(*defs, (size_t)(*n + 1) * sizeof(*nd));
    if (!nd) return -1;
    *defs = nd;
    ecs_tag_def_t *d = &nd[*n];
    memset(d, 0, sizeof(*d));
    d->tag = strdup(tag);
    d->cidrs = calloc(1, sizeof(*d->cidrs));
    if (d->cidrs) d->cidrs[0].cidr = strdup(cidr);
    if (!d->tag || !d->cidrs || !d->cidrs[0].cidr) {
        free(d->tag);
        if (d->cidrs) free(d->cidrs[0].cidr);
        free(d->cidrs);
        return -1;
    }
    cidr_entry_parse(&d->cidrs[0].parsed, d->cidrs[0].cidr);
    d->cidr_count = 1;
    (*n)++;
    return 0;
}

int pdns_zone_add_tagdef(pdns_zone_t *z, const db_tagdef_row_t *row) {
    if (ext_prep(z, "tag definitions") != 0) return -1;
    const char *kind = row->kind ? row->kind : "";
    const char *tag = row->tag ? row->tag : "";
    const char *cidr = row->cidr ? row->cidr : "";
    int k;
    if (strcasecmp(kind, "location") == 0) k = 0;
    else if (strcasecmp(kind, "ecs") == 0) k = 1;
    else if (strcasecmp(kind, "tinydns") == 0) k = 2;
    else {
        zwarn(z, false, 0, "karidns_zone_tagdefs row of kind '%.20s' ignored (location, ecs or tinydns)", kind);
        return 0;
    }
    if (z->n_def_rows >= z->opts.max_records) {
        zfail(z, false, 0, "more karidns_zone_tagdefs rows than max-zone-records");
        return -1;
    }
    cidr_entry_t ce;
    if (strlen(cidr) > 64 || !cidr_entry_parse(&ce, cidr) || ce.is_any) {
        zfail(z, false, 0, "karidns_zone_tagdefs (%.20s '%.40s'): '%.70s' is not an address or prefix", kind, tag, cidr);
        return -1;
    }
    z->n_def_rows++;
    if (k == 2) {
        if (!tdns_code_ok(tag)) {
            zfail(z, false, 0, "karidns_zone_tagdefs (tinydns): '%.40s' is not a location code (1 or 2 printable characters)", tag);
            return -1;
        }
        if (ce.family != AF_INET) {
            zfail(z, false, 0, "karidns_zone_tagdefs (tinydns '%.4s'): '%.70s' is not an IPv4 prefix (tinydns locations are IPv4 only)", tag, cidr);
            return -1;
        }
        if (z->n_locs >= PDNS_MAX_TDNS_LOCS) {
            zfail(z, false, 0, "more than %d tinydns location definitions", PDNS_MAX_TDNS_LOCS);
            return -1;
        }
        tinydns_location_entry_t *nl = realloc(z->locs, (size_t)(z->n_locs + 1) * sizeof(*nl));
        if (!nl) {
            zfail(z, false, 0, "out of memory");
            return -1;
        }
        z->locs = nl;
        tinydns_location_entry_t *e = &nl[z->n_locs++];
        memset(e, 0, sizeof(*e));
        e->code[0] = tag[0];
        e->code[1] = tag[1] ? tag[1] : 0;
        e->prefix_bits = ce.prefix;
        for (int i = 0; i < 4; i++) e->prefix[i] = (uint8_t)(ce.addr[i] & ce.mask[i]);     /* the network part only, as the data file parser does */
        return 0;
    }
    if (!tag_name_ok(tag)) {
        zfail(z, false, 0, "karidns_zone_tagdefs (%.20s): '%.70s' is not a tag name (1-63 printable characters without blanks; none and default are reserved)", kind, tag);
        return -1;
    }
    if (k == 0 ? defs_add(&z->loc_defs, &z->n_loc_defs, tag, cidr) : defs_add(&z->ecs_defs, &z->n_ecs_defs, tag, cidr)) {
        zfail(z, false, 0, "out of memory");
        return -1;
    }
    return 0;
}

static void ext_free(pdns_zone_t *z) {
    for (size_t i = 0; i < z->n_tags; i++) {
        free(z->tags[i].loc);
        free(z->tags[i].ecs);
    }
    free(z->tags);
    free(z->tdns);
    defs_free(z->loc_defs, z->n_loc_defs);
    defs_free(z->ecs_defs, z->n_ecs_defs);
    free(z->locs);
}

typedef struct { int64_t id; size_t idx; } id_idx_t;

static int id_idx_cmp(const void *a, const void *b) {
    const id_idx_t *x = a, *y = b;
    if (x->id != y->id) return x->id < y->id ? -1 : 1;
    return x->idx < y->idx ? -1 : x->idx > y->idx;
}

/* the arena index of the row with records.id id, (size_t)-1 if no enabled non-ENT row has it */
static size_t id_find(const id_idx_t *v, size_t n, int64_t id) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v[mid].id < id) lo = mid + 1;
        else hi = mid;
    }
    return lo < n && v[lo].id == id ? v[lo].idx : (size_t)-1;
}

/* Attach the attributes to the parsed records (one row = one line = one record, so arena.records[i] is the row z->line_id[i]) and
 * hand the zone level tables to the arena.  Before the presigned rebuild: the arena holds the rows only.  0, or -1 (zone failed). */
static int ext_apply(pdns_zone_t *z) {
    zone_arena_t *a = &z->arena;
    if (z->n_tags || z->n_tdns) {
        id_idx_t *v = malloc((a->count ? a->count : 1) * sizeof(*v));
        if (!v) {
            zfail(z, false, 0, "out of memory");
            return -1;
        }
        for (size_t i = 0; i < a->count; i++) {
            v[i].id = z->line_id[i];
            v[i].idx = i;
        }
        qsort(v, a->count, sizeof(*v), id_idx_cmp);
        size_t stale = 0;
        int64_t first_stale = 0;
        for (size_t t = 0; t < z->n_tags && !z->failed; t++) {
            size_t i = id_find(v, a->count, z->tags[t].id);
            if (i == (size_t)-1) {
                if (!stale++) first_stale = z->tags[t].id;
                continue;
            }
            dns_record_t *r = &a->records[i];
            if (r->bind_location_tag || r->ecs_subnet_tag) {
                zfail(z, true, z->tags[t].id, "two rows in karidns_record_tags for this record");
                break;
            }
            if ((z->tags[t].loc && !(r->bind_location_tag = arena_strdup(a, z->tags[t].loc))) ||
                (z->tags[t].ecs && !(r->ecs_subnet_tag = arena_strdup(a, z->tags[t].ecs)))) {
                zfail(z, false, 0, "out of memory");
                break;
            }
        }
        for (size_t t = 0; t < z->n_tdns && !z->failed; t++) {
            size_t i = id_find(v, a->count, z->tdns[t].id);
            if (i == (size_t)-1) {
                if (!stale++) first_stale = z->tdns[t].id;
                continue;
            }
            dns_record_t *r = &a->records[i];
            if (r->tinydns_ttd || r->tinydns_loc[0] || r->tinydns_loc[1]) {
                zfail(z, true, z->tdns[t].id, "two rows in karidns_record_tinydns for this record");
                break;
            }
            r->tinydns_ttd = (time_t)z->tdns[t].ttd;
            r->tinydns_ttl_countdown = z->tdns[t].countdown;
            r->tinydns_loc[0] = z->tdns[t].loc[0];
            r->tinydns_loc[1] = z->tdns[t].loc[1];
        }
        free(v);
        if (z->failed) return -1;
        if (stale)
            zwarn(z, true, first_stale, "%zu row(s) of karidns_record_tags / karidns_record_tinydns belong to no enabled record of the zone (first shown)", stale);
    }
    a->bind_location_tags = z->loc_defs;
    a->bind_location_tag_count = z->n_loc_defs;
    a->bind_ecs_tags = z->ecs_defs;
    a->bind_ecs_tag_count = z->n_ecs_defs;
    a->locations = z->locs;
    a->location_count = z->n_locs;
    z->loc_defs = z->ecs_defs = NULL;
    z->n_loc_defs = z->n_ecs_defs = 0;
    z->locs = NULL;
    z->n_locs = 0;
    if (z->flags & PDNS_F_TINYDNS) a->is_tinydns_format = true;
    z->has_ext = a->bind_location_tag_count || a->bind_ecs_tag_count || a->location_count;
    for (size_t i = 0; i < a->count && !z->has_ext; i++) {
        const dns_record_t *r = &a->records[i];
        if (r->bind_location_tag || r->ecs_subnet_tag || r->tinydns_ttd || r->tinydns_loc[0] || r->tinydns_loc[1]) z->has_ext = true;
    }
    if (z->n_soa > 1) z->has_ext = true;       /* B8t-2: several SOA rows travel in the version 3 encoding (SOA_SET) */
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* metadata -> flags, profile, settings text (design 3.5)                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { char **v; size_t n, cap; } strlist_t;

static void strlist_free(strlist_t *l) {
    for (size_t i = 0; i < l->n; i++) free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

/* adds s (copied) unless already present; false on out of memory */
static bool strlist_add(strlist_t *l, const char *s, bool *dup) {
    *dup = false;
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i], s) == 0) {
            *dup = true;
            return true;
        }
    if (l->n >= l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 8;
        char **nv = realloc(l->v, nc * sizeof(char *));
        if (!nv) return false;
        l->v = nv;
        l->cap = nc;
    }
    char *d = strdup(s);
    if (!d) return false;
    l->v[l->n++] = d;
    return true;
}

typedef struct { char *buf; size_t len, cap; bool oom; } sbuf_t;

static void sb_add(sbuf_t *b, const char *s) {
    size_t n = strlen(s);
    if (b->oom) return;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 128;
        while (nc < b->len + n + 1) nc *= 2;
        char *nb = realloc(b->buf, nc);
        if (!nb) {
            b->oom = true;
            return;
        }
        b->buf = nb;
        b->cap = nc;
    }
    memcpy(b->buf + b->len, s, n + 1);
    b->len += n;
}

static void trim_blanks(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
    size_t lead = 0;
    while (s[lead] == ' ' || s[lead] == '\t') lead++;
    if (lead) memmove(s, s + lead, strlen(s + lead) + 1);
}

static bool charset_ok(const char *s, size_t maxlen, const char *extra) {
    size_t n = strlen(s);
    if (n == 0 || n > maxlen) return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && !strchr(extra, s[i])) return false;
    return true;
}

/* address or CIDR prefix for an ACL: only characters that cannot change the syntax of the statement are let through,
 * then the real parser of the server decides */
static bool acl_addr_ok(const char *s) {
    if (!charset_ok(s, 64, ":./")) return false;
    for (const char *p = s; *p; p++)
        if (isalpha((unsigned char)*p) && !isxdigit((unsigned char)*p)) return false;
    cidr_entry_t e;
    return cidr_entry_parse(&e, s) && !e.is_any;
}

/* A TSIG key name.  In allow-update a key is kept in the ACL list as a bare name, and the config parser reads such an
 * entry as the built-in ACL names (any / none / localhost / localnets, any case) or as an address before it tries a
 * key: a key called "any" or "192.0.2.1" would be refused or, worse, turn into an address entry.  Such names are not
 * accepted here, so a key reference can never mean something else. */
static bool key_name_ok(const char *s) {
    if (!charset_ok(s, 255, "._-")) return false;
    size_t n = strlen(s);
    if (s[n - 1] == '.') n--;
    static const char *const builtin[] = { "any", "none", "localhost", "localnets" };
    for (size_t i = 0; i < sizeof(builtin) / sizeof(builtin[0]); i++)
        if (n == strlen(builtin[i]) && strncasecmp(s, builtin[i], n) == 0) return false;
    cidr_entry_t e;
    return !cidr_entry_parse(&e, s);
}

/* also-notify: ip, ip:port, [ip]:port or a bare IPv6 address -> "ip" / "ip port N" */
static bool notify_entry(const char *s, char *out, size_t cap) {
    char ip[64];
    long port = 0;
    size_t n = strlen(s);
    if (n == 0 || n > 80) return false;
    if (s[0] == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb - s - 1 <= 0 || rb - s - 1 >= (long)sizeof(ip)) return false;
        memcpy(ip, s + 1, (size_t)(rb - s - 1));
        ip[rb - s - 1] = '\0';
        if (rb[1] == ':') {
            char *end;
            port = strtol(rb + 2, &end, 10);
            if (end == rb + 2 || *end || port < 1 || port > 65535) return false;
        } else if (rb[1] != '\0') {
            return false;
        }
        struct in6_addr a6;
        if (inet_pton(AF_INET6, ip, &a6) != 1) return false;
    } else {
        size_t colons = 0;
        for (const char *p = s; *p; p++) colons += (*p == ':');
        if (colons == 1) {
            const char *c = strchr(s, ':');
            if ((size_t)(c - s) >= sizeof(ip)) return false;
            memcpy(ip, s, (size_t)(c - s));
            ip[c - s] = '\0';
            char *end;
            port = strtol(c + 1, &end, 10);
            if (end == c + 1 || *end || port < 1 || port > 65535) return false;
            struct in_addr a4;
            if (inet_pton(AF_INET, ip, &a4) != 1) return false;
        } else {
            if (n >= sizeof(ip)) return false;
            memcpy(ip, s, n + 1);
            struct in_addr a4;
            struct in6_addr a6;
            if (inet_pton(AF_INET, ip, &a4) != 1 && inet_pton(AF_INET6, ip, &a6) != 1) return false;
        }
    }
    if (port) snprintf(out, cap, "%s port %ld", ip, port);
    else snprintf(out, cap, "%s", ip);
    return true;
}

/* value of an X-KARIDNS-<option>; on success *out is the text to emit */
typedef enum { OPT_INT, OPT_INT_SUFFIX, OPT_BACKOFF, OPT_AFA, OPT_BOOL } opt_kind_t;
static const struct { const char *name; opt_kind_t kind; long long lo, hi; } k_options[] = {
    { "notify-retries", OPT_INT, 0, NOTIFY_RETRIES_MAX },
    { "notify-retry-interval", OPT_INT, 1, NOTIFY_RETRY_INTERVAL_MAX },
    { "notify-retry-backoff", OPT_BACKOFF, 0, 0 },
    { "ixfr-history", OPT_INT, 0, IXFR_HISTORY_MAX },
    { "additional-from-auth", OPT_AFA, 0, 0 },
    { "disable-auto-tc-flag", OPT_BOOL, 0, 0 },
    { "zone-udp-bufsize", OPT_INT, KARIDNS_UDP_BUFSIZE_MIN, KARIDNS_UDP_BUFSIZE_MAX },
    { "zone-tcp-mss", OPT_INT, KARIDNS_TCP_MSS_MIN, KARIDNS_TCP_MSS_MAX },
    { "zone-tcp-window", OPT_INT_SUFFIX, KARIDNS_TCP_BUF_MIN, KARIDNS_TCP_BUF_MAX },
    { "zone-tcp-sndbuf", OPT_INT_SUFFIX, KARIDNS_TCP_BUF_MIN, KARIDNS_TCP_BUF_MAX },
};
#define N_OPTIONS (sizeof(k_options) / sizeof(k_options[0]))

/* same acceptance rules as parse_transport_param() / parse_additional_from_auth() / parse_config_bool() in
 * dns_config_parser.c: the generated text must always be accepted by it */
static bool option_value_ok(size_t oi, const char *v) {
    switch (k_options[oi].kind) {
    case OPT_INT:
    case OPT_INT_SUFFIX: {
        size_t n = strlen(v);
        size_t dn = n;
        long long mult = 1;
        if (k_options[oi].kind == OPT_INT_SUFFIX && n > 1) {
            char s = v[n - 1];
            if (s == 'k' || s == 'K') { mult = 1024; dn = n - 1; }
            else if (s == 'm' || s == 'M') { mult = 1024 * 1024; dn = n - 1; }
        }
        if (dn == 0 || dn > 10) return false;
        long long x = 0;
        for (size_t i = 0; i < dn; i++) {
            if (v[i] < '0' || v[i] > '9') return false;
            x = x * 10 + (v[i] - '0');
        }
        if (x > k_options[oi].hi / mult) return false;
        x *= mult;
        return x >= k_options[oi].lo && x <= k_options[oi].hi;
    }
    case OPT_BACKOFF:
        return strcasecmp(v, "fixed") == 0 || strcasecmp(v, "exponential") == 0;
    case OPT_AFA:
        if (strcasecmp(v, "in-domain") == 0 || strcasecmp(v, "in-zone") == 0) return true;
        /* fallthrough */
    case OPT_BOOL:
        return strcasecmp(v, "yes") == 0 || strcasecmp(v, "true") == 0 || strcmp(v, "1") == 0 ||
               strcasecmp(v, "no") == 0 || strcasecmp(v, "false") == 0 || strcmp(v, "0") == 0;
    }
    return false;
}

static bool kind_answer_changing(const char *k) {
    static const char *const exact[] = { "ENABLE-LUA-RECORDS", "LUA-AXFR-SCRIPT", "NSEC3NARROW", "PUBLISH-CDS",
                                         "PUBLISH-CDNSKEY" };
    /* SOA-EDIT changes the SOA in answers and transfers; SOA-EDIT-API and SOA-EDIT-DNSUPDATE only act when the API or an UPDATE edits the zone (pdnsutil adds SOA-EDIT-API to every new zone: no warning) */
    if (strcasecmp(k, "SOA-EDIT") == 0) return true;
    for (size_t i = 0; i < sizeof(exact) / sizeof(exact[0]); i++)
        if (strcasecmp(k, exact[i]) == 0) return true;
    return false;
}

/* B7b: domains.master of a SLAVE / CONSUMER zone -> "masters { ip; ip port N; }; ".  PowerDNS writes the addresses separated by
 * commas (blanks are tolerated), each ip, ip:port, [ip]:port or a bare IPv6 address; a host name is not supported (the Backend
 * connects to addresses only).  An entry that is none of these fails the zone: a transfer from a wrong master is worse than none. */
#define PDNS_MAX_MASTERS 16
#define MASTER_SEP ", \t\r\n"

static bool build_masters(pdns_zone_t *z, sbuf_t *sb) {
    strlist_t l = {0};
    char *copy = z->master ? strdup(z->master) : NULL;
    bool ok = true;
    if (z->master && !copy) {
        zfail(z, false, 0, "out of memory");
        return false;
    }
    for (char *save = NULL, *tok = copy ? strtok_r(copy, MASTER_SEP, &save) : NULL; tok && ok; tok = strtok_r(NULL, MASTER_SEP, &save)) {
        char ent[160];
        bool dup;
        if (!notify_entry(tok, ent, sizeof(ent))) {
            zfail(z, false, 0, "domains.master entry '%.64s' is not an IP address[:port] (host names are not supported)", tok);
            ok = false;
        } else if (l.n >= PDNS_MAX_MASTERS) {
            zwarn(z, false, 0, "domains.master has more than %d entries, the rest is ignored", PDNS_MAX_MASTERS);
            break;
        } else if (!strlist_add(&l, ent, &dup)) {
            zfail(z, false, 0, "out of memory");
            ok = false;
        }
    }
    free(copy);
    if (ok && l.n == 0) {
        zfail(z, false, 0, "domains.master is %s: a %s zone needs at least one master address", z->master ? "empty" : "NULL",
              z->zkind == KDB_ZK_CATALOG ? "CONSUMER" : "SLAVE");
        ok = false;
    }
    if (ok) {
        sb_add(sb, "masters {");
        for (size_t i = 0; i < l.n; i++) {
            sb_add(sb, " ");
            sb_add(sb, l.v[i]);
            sb_add(sb, ";");
        }
        sb_add(sb, " }; ");
    }
    strlist_free(&l);
    return ok;
}

static bool build_settings(pdns_zone_t *z) {
    strlist_t axfr_from = {0}, axfr_keys = {0}, notify = {0}, upd_from = {0}, upd_keys = {0}, trusted = {0};
    bool have_axfr = false, have_upd = false, have_notify = false, have_nsec3param = false, have_presigned = false,
         have_format = false, have_profile = false, have_tsig = false;
    char tsig_key[256] = "";
    char opt_val[N_OPTIONS][34];
    bool opt_set[N_OPTIONS];
    memset(opt_val, 0, sizeof(opt_val));
    memset(opt_set, 0, sizeof(opt_set));
    char *warned[32];
    size_t n_warned = 0;
    bool ok = true;

    for (size_t i = 0; i < z->n_meta && ok; i++) {
        const char *kind = z->meta[i].kind;
        char *content = z->meta[i].content;
        trim_blanks(content);
        bool dup;
        if (strcasecmp(kind, "PRESIGNED") == 0) {
            if (have_presigned) continue;
            have_presigned = true;
            if (strcmp(content, "1") == 0) z->flags |= PDNS_F_PRESIGNED;
            else if (strcmp(content, "0") != 0 && *content)
                zwarn(z, false, 0, "PRESIGNED metadata value '%.32s' is not 1: zone treated as not presigned", content);
        } else if (strcasecmp(kind, "X-KARIDNS-FORMAT") == 0) {
            if (have_format) continue;
            have_format = true;
            if (strcasecmp(content, "tinydns") == 0) z->flags |= PDNS_F_TINYDNS;
            else if (strcasecmp(content, "bind") != 0 && strcasecmp(content, "zone") != 0)
                zwarn(z, false, 0, "X-KARIDNS-FORMAT value '%.32s' unknown, ignored", content);
        } else if (strcasecmp(kind, "NSEC3PARAM") == 0) {
            if (have_nsec3param) continue;
            have_nsec3param = true;
            z->nsec3param = strdup(content);
            if (!z->nsec3param) ok = false;
        } else if (strcasecmp(kind, "X-KARIDNS-PROFILE") == 0) {
            if (have_profile) continue;
            have_profile = true;
            if (charset_ok(content, 64, "._-")) snprintf(z->profile, sizeof(z->profile), "%s", content);
            else zwarn(z, false, 0, "X-KARIDNS-PROFILE value is not a valid profile name, ignored");
        } else if (strcasecmp(kind, "ALLOW-AXFR-FROM") == 0 || strcasecmp(kind, "ALLOW-DNSUPDATE-FROM") == 0) {
            bool upd = strcasecmp(kind, "ALLOW-DNSUPDATE-FROM") == 0;
            if (upd) have_upd = true;
            else have_axfr = true;
            strlist_t *l = upd ? &upd_from : &axfr_from;
            if (!acl_addr_ok(content)) {
                zwarn(z, false, 0, "%.40s entry '%.64s' is not an address or prefix (AUTO-NS and the like are not supported), ignored",
                      kind, content);
            } else if (l->n >= PDNS_MAX_LIST) {
                zwarn(z, false, 0, "%.40s has more than %d entries, rest ignored", kind, PDNS_MAX_LIST);
            } else if (!strlist_add(l, content, &dup)) {
                ok = false;
            }
        } else if (strcasecmp(kind, "TSIG-ALLOW-AXFR") == 0 || strcasecmp(kind, "TSIG-ALLOW-DNSUPDATE") == 0) {
            bool upd = strcasecmp(kind, "TSIG-ALLOW-DNSUPDATE") == 0;
            if (upd) have_upd = true;
            else have_axfr = true;
            strlist_t *l = upd ? &upd_keys : &axfr_keys;
            if (!key_name_ok(content)) {
                zwarn(z, false, 0, "%.40s key name is not valid (letters, digits, '.', '_', '-'), ignored", kind);
            } else if (l->n >= PDNS_MAX_LIST) {
                zwarn(z, false, 0, "%.40s has more than %d entries, rest ignored", kind, PDNS_MAX_LIST);
            } else if (!strlist_add(l, content, &dup)) {
                ok = false;
            }
        } else if (strcasecmp(kind, "ALSO-NOTIFY") == 0) {
            have_notify = true;
            char ent[160];
            if (!notify_entry(content, ent, sizeof(ent))) {
                zwarn(z, false, 0, "ALSO-NOTIFY entry '%.64s' is not an address[:port], ignored", content);
            } else if (notify.n >= PDNS_MAX_LIST) {
                zwarn(z, false, 0, "ALSO-NOTIFY has more than %d entries, rest ignored", PDNS_MAX_LIST);
            } else if (!strlist_add(&notify, ent, &dup)) {
                ok = false;
            }
        } else if (strcasecmp(kind, "AXFR-MASTER-TSIG") == 0) {
            if (have_tsig) {
                zwarn(z, false, 0, "AXFR-MASTER-TSIG has more than one row, the first is used");
                continue;
            }
            have_tsig = true;
            if (key_name_ok(content)) snprintf(tsig_key, sizeof(tsig_key), "%s", content);
            else zwarn(z, false, 0, "AXFR-MASTER-TSIG key name is not valid, ignored");
        } else if (strcasecmp(kind, "X-KARIDNS-ECS-TRUSTED-RESOLVERS") == 0) {
            /* B8 (design 3.5): the resolvers whose EDNS Client Subnet option is believed (zone option ecs-trusted-resolvers): addresses / prefixes,
             * blank or comma separated, one or several rows, a leading '!' excludes (first match decides).  An entry that is not an address
             * or prefix fails the zone: dropping a '!' entry would trust more than the operator wrote.  The Backend bounds the list by
             * acl-ceiling when the query is answered (dns_edns_ecs.c). */
            char *copy = strdup(content);
            if (!copy) {
                ok = false;
                break;
            }
            for (char *save = NULL, *tok = strtok_r(copy, ", \t", &save); tok && ok; tok = strtok_r(NULL, ", \t", &save)) {
                if (!acl_addr_ok(tok[0] == '!' ? tok + 1 : tok)) {
                    zfail(z, false, 0, "X-KARIDNS-ECS-TRUSTED-RESOLVERS entry '%.64s' is not an address or prefix (a leading ! excludes)", tok);
                    ok = false;
                } else if (trusted.n >= PDNS_MAX_LIST) {
                    zwarn(z, false, 0, "X-KARIDNS-ECS-TRUSTED-RESOLVERS has more than %d entries, rest ignored", PDNS_MAX_LIST);
                    break;
                } else if (!strlist_add(&trusted, tok, &dup)) {
                    ok = false;
                }
            }
            free(copy);
        } else if (strncasecmp(kind, "X-KARIDNS-", 10) == 0) {
            size_t oi;
            for (oi = 0; oi < N_OPTIONS; oi++)
                if (strcasecmp(kind + 10, k_options[oi].name) == 0) break;
            if (oi == N_OPTIONS) {
                zwarn(z, false, 0, "unknown zone option %.60s, ignored", kind);
            } else if (opt_set[oi]) {
                zwarn(z, false, 0, "%.60s given more than once, the first is used", kind);
            } else if (strlen(content) > 32 || !option_value_ok(oi, content)) {
                zwarn(z, false, 0, "%.60s has an invalid value '%.32s', ignored", kind, content);
                opt_set[oi] = true;     /* a later row must not override the invalid first one */
            } else {
                opt_set[oi] = true;
                snprintf(opt_val[oi], sizeof(opt_val[oi]), "%s", content);
                opt_val[oi][33] = '\0';
            }
        } else if (kind_answer_changing(kind)) {
            bool seen = false;
            for (size_t w = 0; w < n_warned; w++)
                if (strcasecmp(warned[w], kind) == 0) seen = true;
            if (!seen) {
                zwarn(z, false, 0, "PowerDNS metadata %.60s changes answers in PowerDNS and has no effect here", kind);
                if (n_warned < sizeof(warned) / sizeof(warned[0])) warned[n_warned++] = z->meta[i].kind;
            }
        }
        /* any other kind: ignored */
    }

    sbuf_t sb = {0};
    if (ok) {
        char tmp[512];
        if (z->zkind != KDB_ZK_PRIMARY && !build_masters(z, &sb)) ok = false;
        if (ok && tsig_key[0]) {
            snprintf(tmp, sizeof(tmp), "tsig-key \"%s\"; ", tsig_key);
            sb_add(&sb, tmp);
        }
        if (have_axfr) {
            sb_add(&sb, "allow-transfer {");
            if (!axfr_from.n && !axfr_keys.n) sb_add(&sb, " none;");
            for (size_t i = 0; i < axfr_from.n; i++) { sb_add(&sb, " "); sb_add(&sb, axfr_from.v[i]); sb_add(&sb, ";"); }
            for (size_t i = 0; i < axfr_keys.n; i++) { sb_add(&sb, " key \""); sb_add(&sb, axfr_keys.v[i]); sb_add(&sb, "\";"); }
            sb_add(&sb, " }; ");
            /* D14 (B7a): PowerDNS allows an AXFR when ALLOW-AXFR-FROM matches or the request is signed with a
             * TSIG-ALLOW-AXFR key; karidns.conf's allow-transfer would need both.  transfer-acl-match says "either". */
            if (axfr_from.n && axfr_keys.n) sb_add(&sb, "transfer-acl-match any; ");
        }
        if (have_notify && notify.n) {
            sb_add(&sb, "also-notify {");
            for (size_t i = 0; i < notify.n; i++) { sb_add(&sb, " "); sb_add(&sb, notify.v[i]); sb_add(&sb, ";"); }
            sb_add(&sb, " }; ");
        }
        if (have_upd) {
            sb_add(&sb, "allow-update {");
            if (!upd_from.n && !upd_keys.n) {
                sb_add(&sb, " none;");
            } else {
                for (size_t i = 0; i < upd_from.n; i++) { sb_add(&sb, " "); sb_add(&sb, upd_from.v[i]); sb_add(&sb, ";"); }
                for (size_t i = 0; i < upd_keys.n; i++) { sb_add(&sb, " key \""); sb_add(&sb, upd_keys.v[i]); sb_add(&sb, "\";"); }
            }
            sb_add(&sb, " }; ");
            /* D14 (B7a): PowerDNS needs the address AND the TSIG key for an update; allow-update alone would take either */
            if (upd_from.n && upd_keys.n) sb_add(&sb, "update-acl-match all; ");
        }
        if (trusted.n) {
            sb_add(&sb, "ecs-trusted-resolvers {");
            for (size_t i = 0; i < trusted.n; i++) { sb_add(&sb, " "); sb_add(&sb, trusted.v[i]); sb_add(&sb, ";"); }
            sb_add(&sb, " }; ");
        }
        for (size_t oi = 0; oi < N_OPTIONS; oi++) {
            if (!opt_val[oi][0]) continue;
            snprintf(tmp, sizeof(tmp), "%s %s; ", k_options[oi].name, opt_val[oi]);
            sb_add(&sb, tmp);
        }
        if (sb.len > 0 && sb.buf[sb.len - 1] == ' ') sb.buf[--sb.len] = '\0';   /* no trailing blank */
    }
    strlist_free(&axfr_from);
    strlist_free(&axfr_keys);
    strlist_free(&notify);
    strlist_free(&upd_from);
    strlist_free(&upd_keys);
    strlist_free(&trusted);
    if (!ok || sb.oom) {
        free(sb.buf);
        zfail(z, false, 0, "out of memory");
        return false;
    }
    if (sb.len > PDNS_MAX_SETTINGS) {
        free(sb.buf);
        zfail(z, false, 0, "settings text from the metadata is longer than %u bytes", PDNS_MAX_SETTINGS);
        return false;
    }
    z->settings = sb.buf ? sb.buf : strdup("");
    if (!z->settings) {
        zfail(z, false, 0, "out of memory");
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* finish: parse, check, index                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct { const pdns_zone_t *z; size_t first_idx; bool any; } unenc_ud_t;

static void unenc_report(const dns_record_t *rec, void *ud) {
    unenc_ud_t *u = ud;
    size_t idx = (size_t)(rec - u->z->arena.records);
    if (!u->any) u->first_idx = idx;
    u->any = true;
}

/* The Backend reads the stream with parse_xfr_packet() (parse_resource_record()): a record it refuses rejects the
 * whole zone message.  The zone file parser used to accept some RDATA the wire decoder refuses (D15-2; the RFC 3597 generic form
 * "\# 0" of a PTR, "\# 3 010203" of an NS, ...).  Every record is therefore written the way ZONE_DATA writes it and read
 * back by the decoder here, so such a row fails the zone with its records.id instead of the whole zone failing later at
 * the Backend.  0 = all records accepted; 1 = *bad is the first refused one (*why says how); -1 = out of memory. */
static int wire_check_all(const pdns_zone_t *z, size_t *bad, const char **why) {
    uint8_t *buf = malloc(KDB_MAX_ZONE_DATA);
    if (!buf) return -1;
    zone_arena_t tmp;
    zone_arena_init(&tmp);
    int rc = 0;
    for (size_t i = 0; i < z->arena.count && rc == 0; i++) {
        uint16_t off = DNS_HEADER_SIZE;
        memset(buf, 0, DNS_HEADER_SIZE);
        if (serialize_dns_record(buf, KDB_MAX_ZONE_DATA, &off, &z->arena.records[i], NULL, NULL, 0xFFFFFFFFu) != 0) {
            *bad = i;
            *why = "RR does not fit a ZONE_DATA message";
            rc = 1;
            break;
        }
        dns_record_t back;
        memset(&back, 0, sizeof(back));
        size_t pos = DNS_HEADER_SIZE;
        uint16_t type = 0;
        if (parse_resource_record(buf, off, &pos, &tmp, &back, &type) != 0 || pos != off) {
            *bad = i;
            *why = "RDATA is not valid wire data for the record type (the Backend would refuse the zone)";
            rc = 1;
        }
        if ((i & 511) == 511) zone_arena_free_builder(&tmp);     /* the decoded copies are not needed */
    }
    zone_arena_destroy(&tmp);
    free(buf);
    return rc;
}

/* index of the row whose line holds byte offset off; (size_t)-1 if off is in the header line */
static size_t row_at_offset(const pdns_zone_t *z, size_t off) {
    if (z->n_rows == 0 || off < z->line_off[0]) return (size_t)-1;
    size_t lo = 0, hi = z->n_rows;     /* last i with line_off[i] <= off */
    while (hi - lo > 1) {
        size_t mid = lo + (hi - lo) / 2;
        if (z->line_off[mid] <= off) lo = mid;
        else hi = mid;
    }
    return lo;
}

/* Presigned zones (design 3.6, dns_presigned.h): the NSEC3 / NSEC RRs PowerDNS does not store are rebuilt from the rows,
 * written as zone-file lines and parsed into the same arena after the rows (so the stream order is: rows in records.id
 * order; each synthesized RR right before the stored RRSIG row that covers it, the order of a signer's output). */
typedef struct { size_t anchor, line; } synth_pos_t;

static int synth_pos_cmp(const void *a, const void *b) {
    const synth_pos_t *x = a, *y = b;
    if (x->anchor != y->anchor) return x->anchor < y->anchor ? -1 : 1;
    return x->line < y->line ? -1 : x->line > y->line;
}

static int apply_presigned(pdns_zone_t *z) {
    const char **ord = NULL;
    presigned_ent_t *pe = NULL;
    presigned_out_t out;
    memset(&out, 0, sizeof(out));
    int rc = -1;
    if (z->n_rows) {
        ord = malloc(z->n_rows * sizeof(*ord));
        if (!ord) goto oom;
        for (size_t i = 0; i < z->n_rows; i++) ord[i] = z->ord_off[i] ? z->ord_pool + z->ord_off[i] - 1 : NULL;
    }
    if (z->n_ents) {
        pe = malloc(z->n_ents * sizeof(*pe));
        if (!pe) goto oom;
        for (size_t i = 0; i < z->n_ents; i++) {
            pe[i].name = z->ents[i].name;
            pe[i].ordername = z->ents[i].ordername;
        }
    }
    char err[PDNS_ERR_LEN / 2];
    if (presigned_rebuild(&z->arena, z->name, z->nsec3param, ord, pe, z->n_ents, &out, err, sizeof(err)) != 0) {
        zfail(z, false, 0, "presigned zone: %s", err);
        goto done;
    }
    z->presigned_mode = out.mode;
    if (out.mode == PS_NSEC3 && z->nsec3param) {      /* open item 3: the cap stays 2500 (RFC 5155 s10.3); RFC 9276 s3.1 says 0 */
        presigned_n3param_t np;
        const char *why = NULL;
        if (presigned_parse_n3param(z->nsec3param, &np, &why) && np.iterations > 0)
            zwarn(z, false, 0, "NSEC3PARAM metadata: iterations %u; the iteration count MUST be 0 (RFC 9276 section 3.1)",
                  (unsigned)np.iterations);
    }
    if (out.mode == PS_NONE) {
        rc = 0;
        goto done;
    }
    z->text2 = out.text;                                     /* the arena keeps pointers into it */
    size_t before = z->arena.count;
    parse_error_t perr = {0};
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = ".";
    ctx.err_out = &perr;
    if (parse_zone_fast(z->text2, out.text_len, &z->arena, &ctx) < 0 || z->arena.count != before + out.n_records) {
        zfail(z, false, 0, "internal error: the rebuilt NSEC/NSEC3 records were not accepted by the parser (%s)",
              perr.error_message ? perr.error_message : "record count");
        goto done;
    }
    int64_t *li = realloc(z->line_id, z->arena.count * sizeof(int64_t));
    if (!li) goto oom;
    z->line_id = li;
    for (size_t i = before; i < z->arena.count; i++) z->line_id[i] = 0;
    z->n_synth = out.n_records;
    /* every synthesized RR goes right before the stored RRSIG row that covers it (the signer's order of RRsets) */
    {
        size_t total = z->arena.count, ns = out.n_records;
        dns_record_t *tmp = malloc(total * sizeof(*tmp));
        int64_t *tid = malloc(total * sizeof(int64_t));
        synth_pos_t *srt = malloc(ns * sizeof(*srt));
        if (!tmp || !tid || !srt) {
            free(tmp);
            free(tid);
            free(srt);
            goto oom;
        }
        for (size_t i = 0; i < ns; i++) {                       /* lines ordered by (anchor, line) */
            srt[i].anchor = out.anchor[i];
            srt[i].line = i;
        }
        qsort(srt, ns, sizeof(*srt), synth_pos_cmp);
        size_t w = 0, s = 0;
        for (size_t i = 0; i < before; i++) {
            while (s < ns && srt[s].anchor == i) {
                tmp[w] = z->arena.records[before + srt[s].line];
                tid[w++] = 0;
                s++;
            }
            tmp[w] = z->arena.records[i];
            tid[w++] = z->line_id[i];
        }
        for (; s < ns; s++) {
            tmp[w] = z->arena.records[before + srt[s].line];
            tid[w++] = 0;
        }
        memcpy(z->arena.records, tmp, total * sizeof(*tmp));
        memcpy(z->line_id, tid, total * sizeof(int64_t));
        free(tmp);
        free(tid);
        free(srt);
        for (size_t i = 0; i < total; i++)
            if (z->arena.records[i].type_code == 6) z->soa_index = i;        /* the apex SOA moved if a line went before it */
    }
    rc = 0;
    goto done;
oom:
    zfail(z, false, 0, "out of memory");
done:
    free(ord);
    free(pe);
    free(out.anchor);
    return rc;
}

int pdns_zone_finish(pdns_zone_t *z) {
    if (z->failed) return -1;
    if (z->finished) {
        zfail(z, false, 0, "internal error: pdns_zone_finish() called twice");
        return -1;
    }
    z->finished = true;

    if (!build_settings(z)) return -1;
    if (z->zkind != KDB_ZK_PRIMARY) {      /* B7b: a secondary zone has no rows to convert; the settings text is all of it */
        z->serial = 0;
        return 0;
    }
    if (z->n_null_ttl)
        zwarn(z, true, z->first_null_ttl_id, "%llu record(s) have a NULL ttl; default-ttl %u used (first shown)",
              (unsigned long long)z->n_null_ttl, z->opts.default_ttl);
    if (z->n_prio_ignored)
        zwarn(z, true, z->first_prio_ignored_id, "%llu record(s) of a type other than MX/SRV have prio != 0; ignored (first shown)",
              (unsigned long long)z->n_prio_ignored);
    if (z->n_soa == 0) {
        zfail(z, false, 0, "no enabled SOA record at the apex");
        return -1;
    }

    zone_arena_init(&z->arena);
    z->arena_ready = true;
    z->text[z->text_len] = '\0';
    parse_error_t err = {0};
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = ".";
    ctx.err_out = &err;
    int rc = parse_zone_fast(z->text, z->text_len, &z->arena, &ctx);
    if (rc < 0) {
        size_t r = (size_t)-1;
        if (err.error_message && err.error_offset > 0) r = row_at_offset(z, err.error_offset);
        if (r == (size_t)-1 && z->arena.count > 0) r = z->arena.count - 1;    /* the record being filled in */
        if (r != (size_t)-1 && r >= z->n_rows) r = z->n_rows ? z->n_rows - 1 : (size_t)-1;
        const char *msg = err.error_message ? err.error_message : "record rejected by the zone file parser";
        if (r != (size_t)-1) zfail(z, true, z->line_id[r], "%s", msg);
        else zfail(z, false, 0, "%s", msg);
        return -1;
    }
    if (z->arena.count != z->n_rows) {
        zfail(z, false, 0, "internal error: %zu rows gave %zu records", z->n_rows, z->arena.count);
        return -1;
    }
    /* a record the wire format cannot carry (X-32) fails the row, like any other parser rejection (design D7) */
    unenc_ud_t ud = { z, 0, false };
    zone_arena_drop_unencodable(&z->arena, unenc_report, &ud);
    if (ud.any) {
        zfail(z, true, z->line_id[ud.first_idx < z->n_rows ? ud.first_idx : 0],
              "RDATA does not fit the record type (cannot be encoded in wire format)");
        return -1;
    }
    {
        size_t bad = 0;
        const char *why = "";
        int wr = wire_check_all(z, &bad, &why);
        if (wr < 0) {
            zfail(z, false, 0, "out of memory");
            return -1;
        }
        if (wr > 0) {
            zfail(z, true, z->line_id[bad < z->n_rows ? bad : 0], "%s", why);
            return -1;
        }
    }
    /* every record must be the row it was written from: owner inside the zone, SOA records exactly where the SOA rows are */
    size_t nsoa_rec = 0;
    for (size_t i = 0; i < z->arena.count; i++) {
        const dns_record_t *r = &z->arena.records[i];
        if (!r->name || !domain_name_is_at_or_below(r->name, z->name)) {
            zfail(z, true, z->line_id[i], "internal error: parsed owner '%.200s' is outside the zone", r->name ? r->name : "");
            return -1;
        }
        if (r->type_code == 6) {
            if (!domain_names_match_ci(r->name, z->name)) {
                zfail(z, true, z->line_id[i], "SOA record is not an apex SOA row");
                return -1;
            }
            nsoa_rec++;
        }
    }
    if (nsoa_rec != z->n_soa) {
        zfail(z, true, z->soa_row_id, "an SOA row did not produce an SOA record");
        return -1;
    }
    if (ext_apply(z) != 0) return -1;
    /* B8t-1: the reference SOA (the SOA without location, time stamp or tag if there is one, else the first row) gives the zone
     * serial; every SOA must carry it (RFC 2181 s6.1), and a presigned zone cannot have several or restricted SOA RRs: the
     * signature of the SOA RRset would not hold for every client */
    {
        char serr[320];
        if (zone_arena_check_soa_set(&z->arena, z->name, serr, sizeof(serr)) < 0) {
            zfail(z, true, z->soa_row_id, "%s", serr);
            return -1;
        }
        const dns_record_t *ref = zone_arena_reference_soa(&z->arena, z->name);
        if (!ref) {
            zfail(z, true, z->soa_row_id, "SOA record has too few fields");
            return -1;
        }
        z->soa_index = (size_t)(ref - z->arena.records);
        if ((z->flags & PDNS_F_PRESIGNED) && (z->n_soa > 1 || dns_record_is_restricted(ref))) {
            zfail(z, true, z->soa_row_id, "a presigned zone cannot have several or restricted (location, time stamp, tag) SOA records");
            return -1;
        }
        char sb[64];
        snprintf(sb, sizeof(sb), "0 0 %.40s", ref->rdata[2] ? ref->rdata[2] : "");
        if (!pdns_soa_serial(sb, &z->serial)) {
            zfail(z, true, z->soa_row_id, "SOA serial is not a decimal number up to 4294967295");
            return -1;
        }
    }
    if ((z->flags & PDNS_F_PRESIGNED) && apply_presigned(z) != 0) return -1;
    if (z->flags & PDNS_F_PRESIGNED) (void)presigned_upper_hash_owners(&z->arena);   /* open item 1: BIND's spelling */
    if (build_zone_index(&z->arena, false) != 0) {
        zfail(z, false, 0, "out of memory building the zone index");
        return -1;
    }
    parse_error_t verr = {0};
    if (validate_zone_dname(&z->arena, &verr) < 0 || validate_zone_name_lengths(&z->arena, &verr) < 0) {
        zfail(z, false, 0, "%s", verr.error_message ? verr.error_message : "zone check failed");
        return -1;
    }
    return 0;
}

int pdns_zone_convert(pdns_zone_t *z, const db_record_row_t *rows, size_t n_rows,
                      const db_meta_row_t *meta, size_t n_meta) {
    for (size_t i = 0; i < n_rows; i++)
        if (pdns_zone_add_record(z, &rows[i]) != 0) return -1;
    for (size_t i = 0; i < n_meta; i++)
        if (pdns_zone_add_meta(z, &meta[i]) != 0) return -1;
    return pdns_zone_finish(z);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* KDB1 encoding                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

typedef int (*body_sink_t)(void *ud, const uint8_t *body, size_t len);

/* The ZONE_DATA bodies of the zone, in stream order, each handed to sink.  *rr_total = RRs written.
 *
 * Plain zone: SOA, the other rows in records.id order, SOA.  A zone with Extended AXFR attributes (z->has_ext, B8) is written
 * the way Extended AXFR out writes a zone (dns_axfr_ixfr.c send_axfr_response(), one shared encoder: xext_* in dns_wire.c): the SOA,
 * the tag definitions (location, ECS) and the tinydns location definitions, then the rows with the state records in front
 * of the row that changes the tag in force (a tinydns row with a time stamp or a location as a TINYDNS_WRAP record), the
 * resetting state records, the SOA.  The marker and definition records are RRs of the stream: they count in rr_count.
 *
 * B8t-2: a zone with several SOA rows, or a SOA row with a location, time stamp or tag, is written in the version 3 encoding: the
 * frame is the reference SOA, SOA_SET (the number of SOA rows) follows it, and every SOA row is a body RR in a TINYDNS_WRAP
 * record (also with no tinydns attribute), with the state records of its tags in front. */
typedef struct {
    const pdns_zone_t *z;
    uint8_t *buf;
    uint16_t off, an;
    body_sink_t sink;
    void *ud;
    char *err;
    size_t errlen;
    size_t cur;                     /* arena index of the row being written */
    uint64_t total;
    bool sink_failed;
} gen_t;

static int gen_flush(gen_t *g) {
    g->buf[6] = (uint8_t)(g->an >> 8);
    g->buf[7] = (uint8_t)g->an;
    if (g->sink(g->ud, g->buf, g->off) != 0) {
        g->sink_failed = true;
        return -1;
    }
    g->off = DNS_HEADER_SIZE;
    g->an = 0;
    return 0;
}

/* one RR into the current message (a new message when it does not fit); xext_emit_fn */
static int gen_put(void *ud, const dns_record_t *rec) {
    gen_t *g = ud;
    for (int attempt = 0;; attempt++) {
        uint16_t o2 = g->off;
        if (serialize_dns_record(g->buf, KDB_MAX_ZONE_DATA, &o2, rec, NULL, NULL, 0xFFFFFFFFu) == 0) {
            g->off = o2;
            g->an++;
            g->total++;
            return 0;
        }
        if (g->an == 0 || attempt > 0) {
            snprintf(g->err, g->errlen, "zone '%s' records.id %lld: RR does not fit a ZONE_DATA message", g->z->name,
                     (long long)g->z->line_id[g->cur]);
            return -1;
        }
        if (gen_flush(g) != 0) return -1;
    }
}

static int gen_bodies(const pdns_zone_t *z, body_sink_t sink, void *ud, uint64_t *rr_total, char *err, size_t errlen) {
    const bool soa_set = z->n_soa > 1 || dns_record_is_restricted(&z->arena.records[z->soa_index]);
    if (soa_set && z->n_soa > KARIDNS_SOA_SET_MAX) {
        snprintf(err, errlen, "zone '%s': more than %u SOA records", z->name, (unsigned)KARIDNS_SOA_SET_MAX);
        return -1;
    }
    gen_t g = { z, malloc(KDB_MAX_ZONE_DATA), DNS_HEADER_SIZE, 0, sink, ud, err, errlen, z->soa_index, 0, false };
    if (!g.buf) {
        snprintf(err, errlen, "zone '%s': out of memory", z->name);
        return -1;
    }
    xext_t x;
    xext_init(&x, z->name, gen_put, &g);
    const dns_record_t *recs = z->arena.records;
    int rc = -1;
    memset(g.buf, 0, DNS_HEADER_SIZE);
    g.buf[2] = 0x84;                              /* QR=1 AA=1, opcode QUERY, RCODE 0 */

    if (gen_put(&g, &recs[z->soa_index]) != 0) goto out;                 /* SOA first (RFC 5936 2.2) */
    if (soa_set && xext_emit_soa_set(&x, (uint16_t)z->n_soa) != 0) {
        snprintf(err, errlen, "zone '%s': the SOA set marker could not be written", z->name);
        goto out;
    }
    if (z->has_ext) {
        const zone_arena_t *a = &z->arena;
        for (int i = 0; i < a->bind_location_tag_count; i++)
            if (xext_emit_tagdef(&x, false, &a->bind_location_tags[i]) != 0) goto defs_failed;
        for (int i = 0; i < a->bind_ecs_tag_count; i++)
            if (xext_emit_tagdef(&x, true, &a->bind_ecs_tags[i]) != 0) goto defs_failed;
        for (int i = 0; i < a->location_count; i++)
            if (xext_emit_locdef(&x, a->locations[i].code, a->locations[i].prefix_bits, a->locations[i].prefix) != 0) goto defs_failed;
    }
    for (size_t idx = 0; idx < z->arena.count; idx++) {
        if (idx == z->soa_index && !soa_set) continue;
        const dns_record_t *r = &recs[idx];
        g.cur = idx;
        if (!z->has_ext) {
            if (gen_put(&g, r) != 0) goto out;
            continue;
        }
        if (xext_select(&x, r->bind_location_tag, r->ecs_subnet_tag) != 0) goto out;
        if (xext_rr_is_tinydns(r->tinydns_loc, (int64_t)r->tinydns_ttd) || (soa_set && r->type_code == 6)) {
            dns_record_t wrap;
            uint8_t wbuf[4096];
            if (!wrap_tinydns_record(r, &wrap, wbuf, sizeof(wbuf))) {
                snprintf(err, errlen, "zone '%s' records.id %lld: RR with tinydns attributes is too large to be wrapped", z->name,
                         (long long)z->line_id[idx]);
                goto out;
            }
            if (gen_put(&g, &wrap) != 0) goto out;
        } else if (gen_put(&g, r) != 0) {
            goto out;
        }
    }
    g.cur = z->soa_index;
    if (z->has_ext && xext_finish(&x) != 0) goto out;
    if (gen_put(&g, &recs[z->soa_index]) != 0) goto out;                 /* SOA last */
    if (g.an && gen_flush(&g) != 0) goto out;
    *rr_total = g.total;
    rc = 0;
    goto out;
defs_failed:
    snprintf(err, errlen, "zone '%s': a tag or location definition does not fit one RR (or out of memory)", z->name);
out:
    if (rc != 0 && g.sink_failed) snprintf(err, errlen, "zone '%s': output stopped or size limit exceeded", z->name);
    xext_free(&x);
    free(g.buf);
    return rc;
}

typedef struct { EVP_MD_CTX *md; uint64_t bytes, limit; } digest_ud_t;

static int digest_sink(void *ud, const uint8_t *body, size_t len) {
    digest_ud_t *d = ud;
    d->bytes += len;
    if (d->bytes > d->limit) return -1;
    return EVP_DigestUpdate(d->md, body, len) == 1 ? 0 : -1;
}

typedef struct { kdb_enc_t *enc; pdns_emit_fn emit; void *emit_ud; } emit_ud_t;

static int emit_msg(emit_ud_t *e) {
    if (e->enc->err) return -1;
    int rc = e->emit(e->emit_ud, e->enc->buf, e->enc->len);
    kdb_enc_reset(e->enc);
    return rc;
}

static int data_sink(void *ud, const uint8_t *body, size_t len) {
    emit_ud_t *e = ud;
    if (kdb_enc_raw_msg(e->enc, KDB_T_ZONE_DATA, body, len) != 0) return -1;
    return emit_msg(e);
}

int pdns_zone_encode_kdb(const pdns_zone_t *z, const pdns_kdb_params_t *p, pdns_emit_fn emit, void *ud,
                         char *err, size_t errlen) {
    char dummy[8];
    if (!err || errlen == 0) { err = dummy; errlen = sizeof(dummy); }
    const bool sec = z->zkind != KDB_ZK_PRIMARY;         /* B7b: no rows, the settings text is the zone */
    if (z->failed || !z->finished || (!z->arena_ready && !sec)) {
        snprintf(err, errlen, "zone '%s': not converted", z->name);
        return -1;
    }
    uint64_t rr_count = 0;       /* every RR of the stream: both SOAs, the rows, and the Extended AXFR records (B8); known after pass 1 */

    /* pass 1: digest over the bodies */
    uint8_t digest[KDB_DIGEST_LEN];
    unsigned dlen = 0;
    digest_ud_t dd = { EVP_MD_CTX_new(), 0, z->opts.max_zone_bytes };
    if (!dd.md || EVP_DigestInit_ex(dd.md, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(dd.md);
        snprintf(err, errlen, "zone '%s': out of memory", z->name);
        return -1;
    }
    const char *profile = p->profile ? p->profile : z->profile;
    int rc = sec ? 0 : gen_bodies(z, digest_sink, &dd, &rr_count, err, errlen);
    if (rc == 0 && rr_count > z->opts.max_records) {
        snprintf(err, errlen, "zone '%s': %llu records exceed max-zone-records", z->name, (unsigned long long)rr_count);
        rc = -1;
    }
    /* B8: the tinydns flag is part of what the Backend serves (time-dependent TTLs, no response cache) also when no RR carries a time
     * stamp or a location; the attributes themselves are in the bodies */
    if (rc == 0 && !sec && (z->flags & PDNS_F_TINYDNS)) {
        static const uint8_t ftag[] = "KDB1-TINYDNS";
        if (EVP_DigestUpdate(dd.md, ftag, sizeof(ftag)) != 1) rc = -1;
    }
    /* B7a: a metadata-only edit (the settings text, the profile that is named, the text of that profile) must change the
     * digest, or the diff would find the zone up to date.  Zones without settings and profile keep the digest of the data
     * alone.  Every field is length-prefixed, so two different splits cannot give the same input. */
    if (rc == 0 && ((z->settings && *z->settings) || (profile && *profile))) {
        const char *parts[3] = { z->settings ? z->settings : "", profile ? profile : "", p->profile_text ? p->profile_text : "" };
        static const uint8_t tag[] = "KDB1-SETTINGS";
        if (EVP_DigestUpdate(dd.md, tag, sizeof(tag)) != 1) rc = -1;
        if (sec && EVP_DigestUpdate(dd.md, &z->zkind, 1) != 1) rc = -1;       /* SLAVE and CONSUMER with the same masters differ */
        for (int k = 0; rc == 0 && k < 3; k++) {
            uint64_t n = strlen(parts[k]);
            uint8_t lb[8];
            for (int b = 0; b < 8; b++) lb[b] = (uint8_t)(n >> (56 - 8 * b));
            if (EVP_DigestUpdate(dd.md, lb, 8) != 1 || EVP_DigestUpdate(dd.md, parts[k], (size_t)n) != 1) rc = -1;
        }
        if (rc != 0) snprintf(err, errlen, "zone '%s': digest failed", z->name);
    }
    if (rc == 0 && (EVP_DigestFinal_ex(dd.md, digest, &dlen) != 1 || dlen != KDB_DIGEST_LEN)) {
        snprintf(err, errlen, "zone '%s': digest failed", z->name);
        rc = -1;
    }
    EVP_MD_CTX_free(dd.md);
    if (rc != 0) return -1;
    if (p->gate && p->gate(p->gate_ud, z->serial, digest) != 0) return 1;        /* the loader has this version already */

    /* pass 2: the messages */
    kdb_enc_t enc;
    kdb_enc_init(&enc);
    emit_ud_t eu = { &enc, emit, ud };
    rc = -1;
    if (kdb_enc_begin(&enc, KDB_T_ZONE_BEGIN) != 0 ||
        kdb_enc_u16(&enc, 1, p->view) != 0 || kdb_enc_name(&enc, 2, z->name) != 0 ||
        kdb_enc_i64(&enc, 3, p->source_id) != 0 || kdb_enc_u8(&enc, 4, sec ? z->zkind : p->zone_kind) != 0 ||
        kdb_enc_u32(&enc, 5, sec ? 0 : z->serial) != 0 ||
        kdb_enc_u32(&enc, 6, sec ? 0 : ((z->flags & PDNS_F_PRESIGNED ? KDB_ZF_PRESIGNED : 0) | (z->has_ext ? KDB_ZF_EXTENDED : 0) |
                                  (z->flags & PDNS_F_TINYDNS ? KDB_ZF_TINYDNS : 0))) != 0 ||
        kdb_enc_u64(&enc, 7, rr_count) != 0 || kdb_enc_bytes(&enc, 8, digest, KDB_DIGEST_LEN) != 0 ||
        (z->settings && *z->settings && kdb_enc_str(&enc, 9, z->settings) != 0) ||
        (profile && *profile && kdb_enc_str(&enc, 10, profile) != 0) || kdb_enc_end(&enc) != 0 ||
        emit_msg(&eu) != 0) {
        snprintf(err, errlen, "zone '%s': ZONE_BEGIN could not be encoded or sent", z->name);
        goto out;
    }
    if (!sec) {
        uint64_t again = 0;
        if (gen_bodies(z, data_sink, &eu, &again, err, errlen) != 0) goto out;
        if (again != rr_count) {
            snprintf(err, errlen, "zone '%s': internal error: the second pass wrote %llu RRs, the first %llu", z->name,
                     (unsigned long long)again, (unsigned long long)rr_count);
            goto out;
        }
    }
    if (kdb_enc_begin(&enc, KDB_T_ZONE_END) != 0 || kdb_enc_u64(&enc, 1, rr_count) != 0 || kdb_enc_end(&enc) != 0 ||
        emit_msg(&eu) != 0) {
        snprintf(err, errlen, "zone '%s': ZONE_END could not be encoded or sent", z->name);
        goto out;
    }
    rc = 0;
out:
    kdb_enc_free(&enc);
    return rc;
}
