/*
 * dns_diag.c - the diagnostic sink (see dns_diag.h): the text path that prints what has always been printed, and the JSON mode of
 * karicheck --json.
 */
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dns_diag.h"

/* ------------------------------------------------------------------------------------------------------------- */
/* the code table                                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

static const struct { const char *name; char sev; bool retired; const char *desc; } k_codes[DC__COUNT] = {
    [DC_NONE] = { "", 'E', false, "" },
#define X(id, name, sev, desc) [DC_##id] = { name, sev, false, desc },
#define XR(id, name, sev, desc) [DC_##id] = { name, sev, true, desc },
#include "dns_diag_codes.h"
#undef X
#undef XR
};

const char *dns_diag_code_name(dns_diag_code_t code) {
    return (unsigned)code < (unsigned)DC__COUNT ? k_codes[code].name : "";
}

dns_diag_code_t dns_diag_code_find(const char *name) {
    if (!name || !*name) return DC_NONE;
    for (int i = 1; i < (int)DC__COUNT; i++)
        if (strcmp(k_codes[i].name, name) == 0) return (dns_diag_code_t)i;
    return DC_NONE;
}

char dns_diag_code_severity(dns_diag_code_t code) {
    return (unsigned)code < (unsigned)DC__COUNT ? k_codes[code].sev : 'E';
}

const char *dns_diag_code_desc(dns_diag_code_t code) {
    return (unsigned)code < (unsigned)DC__COUNT ? k_codes[code].desc : "";
}

bool dns_diag_code_retired(dns_diag_code_t code) {
    return (unsigned)code < (unsigned)DC__COUNT && k_codes[code].retired;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* JSON string escaping                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    void (*put)(void *ud, const char *s, size_t n);
    void *ud;
} esc_sink_t;

/* the length of the valid UTF-8 sequence at s[0..n) (RFC 3629: no overlong forms, no surrogates, nothing above U+10FFFF), or 0 */
static size_t utf8_seq_len(const unsigned char *s, size_t n) {
    unsigned char c = s[0];
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) return n >= 2 && (s[1] & 0xC0) == 0x80 ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (n < 3 || (s[2] & 0xC0) != 0x80) return 0;
        unsigned char lo = c == 0xE0 ? 0xA0 : 0x80, hi = c == 0xED ? 0x9F : 0xBF;
        return s[1] >= lo && s[1] <= hi ? 3 : 0;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (n < 4 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        unsigned char lo = c == 0xF0 ? 0x90 : 0x80, hi = c == 0xF4 ? 0x8F : 0xBF;
        return s[1] >= lo && s[1] <= hi ? 4 : 0;
    }
    return 0;
}

static void esc_core(const unsigned char *s, size_t n, const esc_sink_t *k) {
    static const char hex[] = "0123456789abcdef";
    size_t i = 0, run = 0;
    while (i < n) {
        unsigned char c = s[i];
        if (c >= 0x20 && c != 0x7F && c != '"' && c != '\\' && c < 0x80) {
            i++;
            continue;
        }
        size_t l = c < 0x80 ? 1 : utf8_seq_len(s + i, n - i);
        if (c >= 0x80 && l > 0) {
            i += l;                                              /* a valid sequence is part of the plain run */
            continue;
        }
        if (i > run) k->put(k->ud, (const char *)s + run, i - run);
        if (c < 0x80) {
            if (c == '"') k->put(k->ud, "\\\"", 2);
            else if (c == '\\') k->put(k->ud, "\\\\", 2);
            else {
                char u[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] };
                k->put(k->ud, u, 6);
            }
            i++;
            run = i;
            continue;
        }
        k->put(k->ud, "\xEF\xBF\xBD", 3);                     /* U+FFFD for a byte that starts no valid sequence */
        i++;
        run = i;
    }
    if (i > run) k->put(k->ud, (const char *)s + run, i - run);
}

typedef struct { char *out; size_t cap, len; } esc_buf_t;

static void esc_put_buf(void *ud, const char *s, size_t n) {
    esc_buf_t *b = ud;
    if (b->cap > 0 && b->len < b->cap - 1) {
        size_t room = b->cap - 1 - b->len;
        memcpy(b->out + b->len, s, n < room ? n : room);
    }
    b->len += n;
}

size_t dns_diag_json_escape(char *out, size_t cap, const char *in, size_t n) {
    esc_buf_t b = { out, cap, 0 };
    esc_sink_t k = { esc_put_buf, &b };
    esc_core((const unsigned char *)in, n, &k);
    if (cap > 0) out[b.len < cap - 1 ? b.len : cap - 1] = '\0';
    return b.len;
}

static void esc_put_file(void *ud, const char *s, size_t n) {
    (void)!fwrite(s, 1, n, (FILE *)ud);
}

/* "text" (or null for NULL) */
static void json_str(FILE *fp, const char *s) {
    if (!s) {
        fputs("null", fp);
        return;
    }
    esc_sink_t k = { esc_put_file, fp };
    fputc('"', fp);
    esc_core((const unsigned char *)s, strlen(s), &k);
    fputc('"', fp);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the state of JSON mode                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    int sev;                    /* DIAG_ERROR .. DIAG_INFO */
    dns_diag_code_t code;
    char *text, *file, *zone, *view;
    long line;
} diag_msg_t;

typedef struct {
    char *zone, *view, *file;
    const char *format;         /* a string literal of the caller */
    size_t errors, warnings;
} diag_zone_t;

#define CTX_ZONE_MAX 512
#define CTX_VIEW_MAX 256
#define CTX_FILE_MAX 4096

static struct {
    bool json, suspended;
    char tool[24];              /* the first key of the document: "karicheck", or the tool that called dns_diag_json_tool() */
    char command[16], version[32];
    diag_msg_t *msgs;
    size_t nmsgs, cmsgs, dropped;
    size_t errors, warnings;                    /* all messages, also the dropped ones */
    diag_zone_t *zones;
    size_t nzones, czones, zones_dropped;
    unsigned checked, skipped;
    char extra_key[24], *extra_val;             /* dns_diag_json_extra(): one more key at the end of the document */
    char ctx_zone[CTX_ZONE_MAX], ctx_view[CTX_VIEW_MAX], ctx_file[CTX_FILE_MAX];
    long ctx_line;
} g;

#ifdef KARIDNS_DIAG_CODELOG
static FILE *g_codelog;
#endif

bool dns_diag_json_enabled(void) {
    return g.json && !g.suspended;
}

bool dns_diag_suspend_json(bool suspend) {
    bool prev = g.suspended;
    g.suspended = suspend;
    return prev;
}

#ifdef KARIDNS_DIAG_CODELOG
void dns_diag_code_log(const char *path) {
    if (g_codelog) fclose(g_codelog);
    g_codelog = NULL;
    if (!path) return;
    /* a test hook that karicheck may run as root: never follow a symbolic link, never widen a mode */
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || !(g_codelog = fdopen(fd, "a")))) close(fd);
}
#endif

void dns_diag_json_start(const char *command, const char *version) {
    dns_diag_json_reset();
    g.json = true;
    snprintf(g.tool, sizeof(g.tool), "karicheck");
    snprintf(g.command, sizeof(g.command), "%s", command ? command : "");
    snprintf(g.version, sizeof(g.version), "%s", version ? version : "");
}

static void msg_free(diag_msg_t *m) {
    free(m->text);
    free(m->file);
    free(m->zone);
    free(m->view);
}

void dns_diag_json_reset(void) {
    for (size_t i = 0; i < g.nmsgs; i++) msg_free(&g.msgs[i]);
    free(g.msgs);
    for (size_t i = 0; i < g.nzones; i++) {
        free(g.zones[i].zone);
        free(g.zones[i].view);
        free(g.zones[i].file);
    }
    free(g.zones);
    free(g.extra_val);
    memset(&g, 0, sizeof(g));
}

void dns_diag_json_extra(const char *key, const char *json_value) {
    char *v = strdup(json_value);
    if (!v) return;
    free(g.extra_val);
    g.extra_val = v;
    snprintf(g.extra_key, sizeof(g.extra_key), "%s", key);
}

void dns_diag_json_tool(const char *tool) {
    snprintf(g.tool, sizeof(g.tool), "%s", tool ? tool : "karicheck");
}

void dns_diag_set_file(const char *file) {
    snprintf(g.ctx_file, sizeof(g.ctx_file), "%s", file ? file : "");
}

void dns_diag_set_zone(const char *zone, const char *view) {
    snprintf(g.ctx_zone, sizeof(g.ctx_zone), "%s", zone ? zone : "");
    snprintf(g.ctx_view, sizeof(g.ctx_view), "%s", view ? view : "");
}

void dns_diag_set_line(long line) {
    g.ctx_line = line;
}

dns_diag_mark_t dns_diag_mark(void) {
    dns_diag_mark_t m = { g.errors, g.warnings };
    return m;
}

void dns_diag_counts(unsigned checked, unsigned skipped) {
    g.checked = checked;
    g.skipped = skipped;
}

static char *dup_or_null(const char *s) {
    return s && *s ? strdup(s) : NULL;
}

void dns_diag_zone_result(const char *zone, const char *view, const char *file, const char *format, dns_diag_mark_t since) {
    if (!dns_diag_json_enabled()) return;
    if (g.nzones >= DIAG_MAX_ZONES) {
        g.zones_dropped++;
        return;
    }
    if (g.nzones == g.czones) {
        size_t nc = g.czones ? g.czones * 2 : 16;
        diag_zone_t *nz = realloc(g.zones, nc * sizeof(*nz));
        if (!nz) {
            g.zones_dropped++;
            return;
        }
        g.zones = nz;
        g.czones = nc;
    }
    diag_zone_t *z = &g.zones[g.nzones++];
    z->zone = strdup(zone ? zone : "");        /* always a string */
    z->view = dup_or_null(view);
    z->file = dup_or_null(file);
    z->format = format;
    z->errors = g.errors - since.errors;
    z->warnings = g.warnings - since.warnings;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the messages                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static const char *const k_tags[] = { "ERROR", "WARNING", "NOTE", "INFO" };
static const char *const k_sev_names[] = { "error", "warning", "note", "info" };

#ifdef KARIDNS_DIAG_CODELOG
void dns_diag_code_note(dns_diag_code_t code) {
    if (g_codelog) {
        fprintf(g_codelog, "%s\n", dns_diag_code_name(code));
        fflush(g_codelog);
    }
}
#endif

/* the text of a message without its final line feeds, cut at DIAG_TEXT_MAX */
static char *text_dup(const char *fmt, va_list ap) {
    char buf[DIAG_TEXT_MAX + 8];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0) n = 0;
    bool cut = (size_t)n > DIAG_TEXT_MAX;
    size_t l = cut ? DIAG_TEXT_MAX : (size_t)n;
    while (!cut && l > 0 && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) l--;
    if (cut) {
        memcpy(buf + l, "...", 4);
        l += 3;
    }
    buf[l] = '\0';
    return strdup(buf);
}

static void json_store(int sev, dns_diag_code_t code, const char *file, long line, const char *fmt, va_list ap) {
    int s = sev & DIAG_SEV_MASK;
    if (s > DIAG_INFO) s = DIAG_INFO;
    if (s == DIAG_ERROR) g.errors++;
    else if (s == DIAG_WARNING) g.warnings++;
    if (g.nmsgs >= DIAG_MAX_MESSAGES) {
        g.dropped++;
        return;
    }
    if (g.nmsgs == g.cmsgs) {
        size_t nc = g.cmsgs ? g.cmsgs * 2 : 64;
        diag_msg_t *nm = realloc(g.msgs, nc * sizeof(*nm));
        if (!nm) {
            g.dropped++;
            return;
        }
        g.msgs = nm;
        g.cmsgs = nc;
    }
    diag_msg_t *m = &g.msgs[g.nmsgs++];
    m->sev = s;
    m->code = code;
    m->text = text_dup(fmt, ap);
    m->file = dup_or_null(file && *file ? file : g.ctx_file);
    m->zone = dup_or_null(g.ctx_zone);
    m->view = dup_or_null(g.ctx_view);
    m->line = line > 0 ? line : g.ctx_line;
}

void dns_vdiag(int sev, dns_diag_code_t code, const char *file, long line, const char *fmt, va_list ap) {
    dns_diag_code_note(code);
    if (dns_diag_json_enabled()) {
        json_store(sev, code, file, line, fmt, ap);
        return;
    }
    int s = sev & DIAG_SEV_MASK;
    if (s > DIAG_INFO) s = DIAG_INFO;
    FILE *fp = s == DIAG_INFO && !(sev & DIAG_STDERR) ? stdout : stderr;
    /* the line goes out in one write when it fits (as the single fprintf of the old code did), so that another process that shares the
     * stream cannot put its text between the tag and the message */
    char buf[2048];
    int h = (sev & DIAG_UNTAGGED) ? 0 : snprintf(buf, sizeof(buf), "[%s] ", k_tags[s]);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(buf + h, sizeof(buf) - (size_t)h, fmt, ap2);
    va_end(ap2);
    if (n >= 0 && (size_t)(h + n) < sizeof(buf)) {
        fwrite(buf, 1, (size_t)(h + n), fp);
        return;
    }
    if (h) fwrite(buf, 1, (size_t)h, fp);
    vfprintf(fp, fmt, ap);
}

void dns_diag(int sev, dns_diag_code_t code, const char *file, long line, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    dns_vdiag(sev, code, file, line, fmt, ap);
    va_end(ap);
}

/* "file:line" (the file may hold ':'), "line N", or anything else (no place) */
static void loc_split(const char *loc, char *file, size_t cap, long *line) {
    file[0] = '\0';
    *line = 0;
    if (!loc) return;
    if (strncmp(loc, "line ", 5) == 0) {
        char *end;
        long v = strtol(loc + 5, &end, 10);
        if (end != loc + 5 && *end == '\0') *line = v;
        return;
    }
    const char *colon = strrchr(loc, ':');
    if (!colon || colon == loc || !colon[1]) return;
    char *end;
    long v = strtol(colon + 1, &end, 10);
    if (*end != '\0' || v < 0) return;
    size_t fl = (size_t)(colon - loc);
    if (fl >= cap) fl = cap - 1;
    memcpy(file, loc, fl);
    file[fl] = '\0';
    *line = v;
}

void dns_vdiag_at(int sev, dns_diag_code_t code, const char *loc, const char *fmt, va_list ap) {
    char file[CTX_FILE_MAX];
    long line;
    loc_split(dns_diag_json_enabled() ? loc : NULL, file, sizeof(file), &line);
    dns_vdiag(sev, code, file[0] ? file : NULL, line, fmt, ap);
}

void dns_diag_at(int sev, dns_diag_code_t code, const char *loc, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    dns_vdiag_at(sev, code, loc, fmt, ap);
    va_end(ap);
}

void dns_vdiag_detail(const char *fmt, va_list ap) {
    if (!dns_diag_json_enabled()) {
        vfprintf(stderr, fmt, ap);
    } else if (g.nmsgs > 0 && g.dropped == 0) {
        diag_msg_t *m = &g.msgs[g.nmsgs - 1];
        char *add = text_dup(fmt, ap);
        if (add) {
            size_t a = strlen(m->text), b = strlen(add);
            char *nt = a + b + 2 <= DIAG_TEXT_MAX + 64 ? realloc(m->text, a + b + 2) : NULL;
            if (nt) {
                nt[a] = '\n';
                memcpy(nt + a + 1, add, b + 1);
                m->text = nt;
            }
            free(add);
        }
    }
}

void dns_diag_detail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    dns_vdiag_detail(fmt, ap);
    va_end(ap);
}

void dns_vdiag_plain(FILE *fp, const char *fmt, va_list ap) {
    if (!dns_diag_json_enabled()) vfprintf(fp, fmt, ap);
}

void dns_vdiag_ok(const char *fmt, va_list ap) {
    if (dns_diag_json_enabled()) return;
    fprintf(stdout, "[%s] ", "OK");
    vfprintf(stdout, fmt, ap);
}

void dns_diag_plain(FILE *fp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    dns_vdiag_plain(fp, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the document                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static void json_int_or_null(FILE *fp, long v) {
    if (v > 0) fprintf(fp, "%ld", v);
    else fputs("null", fp);
}

int dns_diag_json_finish(FILE *fp, int status) {
    const char *result = status == 0 ? "ok" : status == 2 ? "usage" : "fail";
    fputs("{\n  ", fp);
    json_str(fp, g.tool[0] ? g.tool : "karicheck");
    fputs(": 1,\n  \"version\": ", fp);
    json_str(fp, g.version);
    fputs(",\n  \"command\": ", fp);
    json_str(fp, g.command[0] ? g.command : NULL);
    fprintf(fp, ",\n  \"result\": \"%s\",\n", result);
    fprintf(fp, "  \"counts\": { \"error\": %zu, \"warning\": %zu, \"checked\": %u, \"skipped\": %u, \"dropped\": %zu },\n", g.errors, g.warnings,
            g.checked, g.skipped, g.dropped);
    fprintf(fp, "  \"truncated\": %s,\n", g.dropped > 0 || g.zones_dropped > 0 ? "true" : "false");
    fputs("  \"messages\": [", fp);
    for (size_t i = 0; i < g.nmsgs; i++) {
        const diag_msg_t *m = &g.msgs[i];
        fprintf(fp, "%s\n    { \"severity\": \"%s\", \"code\": ", i ? "," : "", k_sev_names[m->sev]);
        json_str(fp, m->code == DC_NONE ? NULL : dns_diag_code_name(m->code));
        fputs(", \"text\": ", fp);
        json_str(fp, m->text);
        fputs(", \"file\": ", fp);
        json_str(fp, m->file);
        fputs(", \"line\": ", fp);
        json_int_or_null(fp, m->line);
        fputs(", \"zone\": ", fp);
        json_str(fp, m->zone);
        fputs(", \"view\": ", fp);
        json_str(fp, m->view);
        fputs(" }", fp);
    }
    fputs(g.nmsgs ? "\n  ],\n" : "],\n", fp);
    fputs("  \"zones\": [", fp);
    for (size_t i = 0; i < g.nzones; i++) {
        const diag_zone_t *z = &g.zones[i];
        fprintf(fp, "%s\n    { \"zone\": ", i ? "," : "");
        json_str(fp, z->zone);
        fputs(", \"view\": ", fp);
        json_str(fp, z->view);
        fputs(", \"file\": ", fp);
        json_str(fp, z->file);
        fputs(", \"format\": ", fp);
        json_str(fp, z->format);
        fprintf(fp, ", \"result\": \"%s\", \"errors\": %zu, \"warnings\": %zu }", z->errors ? "fail" : "ok", z->errors, z->warnings);
    }
    fputs(g.nzones ? "\n  ]" : "]", fp);
    if (g.extra_val) {
        fputs(",\n  ", fp);
        json_str(fp, g.extra_key);
        fprintf(fp, ": %s", g.extra_val);
    }
    fputs("\n}\n", fp);
    return fflush(fp) == 0 && !ferror(fp) ? 0 : -1;
}
