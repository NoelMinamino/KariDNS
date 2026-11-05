/*
 * test_dns_diag.c - the diagnostic sink (dns_diag.c): the code table, the JSON string escaping, the text path that must print what the
 * parser and karicheck have always printed, and the JSON document of karicheck --json.
 *
 * Expectations are written by hand from the rules (RFC 8259 for the escapes, RFC 3629 for valid UTF-8, the text lines of the old
 * fprintf calls), not taken from the output of the code.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* the code log is a test-build feature of dns_diag.c: this test takes the source in with it switched on (one object, so the hook's own
 * test runs in the unit-test builds and under ASan) */
#define KARIDNS_DIAG_CODELOG 1
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../dns_diag.c"
#include "test_tmpdir.h"

static int g_fail;
static char g_dir[512];

#define CHECK(cond) do { if (!(cond)) { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_STR(got, want) do { if (strcmp((got), (want)) != 0) { g_fail++; fprintf(stderr, "FAIL %s:%d: got \"%s\" want \"%s\"\n", __FILE__, __LINE__, (got), (want)); } } while (0)

/* ---- capture what goes to fd 1 / fd 2 ---- */
typedef struct { int fd, saved, tmp; } cap_t;

static void cap_begin(cap_t *c, int fd) {
    char path[600];
    fflush(stdout);
    fflush(stderr);
    snprintf(path, sizeof(path), "%s/cap.%d", g_dir, fd);
    c->fd = fd;
    c->saved = dup(fd);
    c->tmp = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (c->saved < 0 || c->tmp < 0) {
        perror("capture");
        exit(2);
    }
    dup2(c->tmp, fd);
}

static void cap_end(cap_t *c, char *out, size_t cap) {
    fflush(stdout);
    fflush(stderr);
    dup2(c->saved, c->fd);
    close(c->saved);
    off_t n = lseek(c->tmp, 0, SEEK_CUR);
    lseek(c->tmp, 0, SEEK_SET);
    ssize_t r = n > 0 ? read(c->tmp, out, cap - 1) : 0;
    out[r > 0 ? r : 0] = '\0';
    close(c->tmp);
}

/* ---- is s (the content of a JSON string) valid: no raw control character, '"' or lone '\\', only \" \\ \u00XX, valid UTF-8 ---- */
static bool json_content_ok(const char *s, size_t n) {
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F || c == '"') return false;
        if (c == '\\') {
            if (i + 1 < n && (s[i + 1] == '"' || s[i + 1] == '\\')) {
                i += 2;
                continue;
            }
            if (i + 6 <= n && s[i + 1] == 'u' && s[i + 2] == '0' && s[i + 3] == '0' && strchr("0123456789abcdef", s[i + 4]) &&
                strchr("0123456789abcdef", s[i + 5])) {
                i += 6;
                continue;
            }
            return false;
        }
        if (c < 0x80) {
            i++;
            continue;
        }
        size_t l = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 0;
        if (l == 0 || i + l > n) return false;
        for (size_t k = 1; k < l; k++)
            if (((unsigned char)s[i + k] & 0xC0) != 0x80) return false;
        unsigned cp = l == 2 ? (c & 0x1F) : l == 3 ? (c & 0x0F) : (c & 0x07);
        for (size_t k = 1; k < l; k++) cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3F);
        if ((l == 2 && cp < 0x80) || (l == 3 && cp < 0x800) || (l == 4 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += l;
    }
    return true;
}

static void expect_esc(const char *in, size_t n, const char *want) {
    char out[512];
    size_t len = dns_diag_json_escape(out, sizeof(out), in, n);
    CHECK(len == strlen(want));
    CHECK_STR(out, want);
    CHECK(json_content_ok(out, strlen(out)));
}

static void test_escape(void) {
    expect_esc("", 0, "");
    expect_esc("plain text 123", 14, "plain text 123");
    expect_esc("say \"hi\"", 8, "say \\\"hi\\\"");
    expect_esc("a\\b", 3, "a\\\\b");
    expect_esc("\\\"", 2, "\\\\\\\"");
    expect_esc("a\nb\tc\rd", 7, "a\\u000ab\\u0009c\\u000dd");
    expect_esc("\x01\x1f", 2, "\\u0001\\u001f");
    expect_esc("\x7f", 1, "\\u007f");
    expect_esc("a\0b", 3, "a\\u0000b");                                    /* an explicit length can hold a NUL */
    /* valid UTF-8 stays as it is: U+00E9, U+65E5 U+672C, U+1F600, U+10FFFF, U+D7FF, U+E000 */
    expect_esc("\xC3\xA9", 2, "\xC3\xA9");
    expect_esc("\xE6\x97\xA5\xE6\x9C\xAC", 6, "\xE6\x97\xA5\xE6\x9C\xAC");
    expect_esc("\xF0\x9F\x98\x80", 4, "\xF0\x9F\x98\x80");
    expect_esc("\xF4\x8F\xBF\xBF", 4, "\xF4\x8F\xBF\xBF");
    expect_esc("\xED\x9F\xBF", 3, "\xED\x9F\xBF");
    expect_esc("\xEE\x80\x80", 3, "\xEE\x80\x80");
    /* invalid UTF-8: each bad byte becomes U+FFFD (EF BF BD) */
    expect_esc("\x80", 1, "\xEF\xBF\xBD");                                  /* a continuation byte alone */
    expect_esc("\xC3", 1, "\xEF\xBF\xBD");                                  /* a sequence cut at the end */
    expect_esc("\xC3(", 2, "\xEF\xBF\xBD(");                                /* a lead byte and a plain byte */
    expect_esc("\xC0\x80", 2, "\xEF\xBF\xBD\xEF\xBF\xBD");                  /* overlong NUL */
    expect_esc("\xC1\xBF", 2, "\xEF\xBF\xBD\xEF\xBF\xBD");                  /* overlong '?' */
    expect_esc("\xE0\x80\x80", 3, "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");  /* overlong 3-byte form */
    expect_esc("\xED\xA0\x80", 3, "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");  /* U+D800, a surrogate */
    expect_esc("\xF4\x90\x80\x80", 4, "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");   /* above U+10FFFF */
    expect_esc("\xF8\x88\x80\x80\x80", 5, "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");   /* a 5-byte form */
    expect_esc("\xFF\xFE", 2, "\xEF\xBF\xBD\xEF\xBF\xBD");
    expect_esc("a\xE6\x97" "b", 4, "a\xEF\xBF\xBD\xEF\xBF\xBD" "b");        /* a 3-byte form cut after two bytes */
    expect_esc("\xF0\x9F\x98", 3, "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");  /* a 4-byte form cut after three */
    expect_esc("\xE6\x97\xA5\x80", 4, "\xE6\x97\xA5\xEF\xBF\xBD");          /* valid, then a stray continuation byte */

    /* snprintf semantics: the result is cut to cap - 1 bytes with a NUL, and the length is the full one */
    char small[8];
    size_t len = dns_diag_json_escape(small, sizeof(small), "0123456789", 10);
    CHECK(len == 10);
    CHECK_STR(small, "0123456");
    len = dns_diag_json_escape(small, 4, "\x01\x01", 2);
    CHECK(len == 12);
    CHECK(small[3] == '\0');
    len = dns_diag_json_escape(NULL, 0, "abc", 3);
    CHECK(len == 3);
    char one[1] = { 'x' };
    len = dns_diag_json_escape(one, 1, "abc", 3);
    CHECK(len == 3 && one[0] == '\0');

    /* every single byte, alone and between letters, gives valid JSON content */
    for (int b = 1; b < 256; b++) {
        char in[3] = { 'a', (char)b, 'z' }, out[64];
        size_t n = dns_diag_json_escape(out, sizeof(out), in, 3);
        CHECK(n < sizeof(out) && json_content_ok(out, n));
    }
}

static void test_table(void) {
    CHECK_STR(dns_diag_code_name(DC_NONE), "");
    CHECK_STR(dns_diag_code_name((dns_diag_code_t)DC__COUNT), "");
    CHECK_STR(dns_diag_code_name((dns_diag_code_t)-1), "");
    CHECK_STR(dns_diag_code_name(DC_ZONE_SOA_MISSING), "zone.soa.missing");
    CHECK(dns_diag_code_find("zone.soa.missing") == DC_ZONE_SOA_MISSING);
    CHECK(dns_diag_code_find("zone.soa.nothing") == DC_NONE);
    CHECK(dns_diag_code_find("") == DC_NONE);
    CHECK(dns_diag_code_find(NULL) == DC_NONE);
    CHECK(dns_diag_code_severity(DC_ZONE_SOA_MISSING) == 'E');
    CHECK(dns_diag_code_severity(DC_CONF_ECS_DISABLED) == 'W');
    CHECK(dns_diag_code_severity(DC_CONF_LOADING) == 'I');
    CHECK(dns_diag_code_severity(DC_CONF_STARTUP_NOTIFY_RATE) == 'N');
    CHECK(dns_diag_code_severity((dns_diag_code_t)DC__COUNT) == 'E');
    CHECK_STR(dns_diag_code_desc((dns_diag_code_t)-1), "");
    CHECK(!dns_diag_code_retired(DC_ZONE_SOA_MISSING));
    CHECK(!dns_diag_code_retired((dns_diag_code_t)DC__COUNT));

    static const char *const areas[] = { "usage.", "io.", "conf.", "zone.", "db.", "internal." };
    for (int c = 1; c < (int)DC__COUNT; c++) {
        const char *name = dns_diag_code_name((dns_diag_code_t)c);
        const char *desc = dns_diag_code_desc((dns_diag_code_t)c);
        if (!name[0] || !desc[0]) {
            g_fail++;
            fprintf(stderr, "FAIL: code %d has no name or no description\n", c);
            continue;
        }
        CHECK(strchr("EWNI", dns_diag_code_severity((dns_diag_code_t)c)) != NULL);
        bool area = false;
        for (size_t a = 0; a < sizeof(areas) / sizeof(areas[0]); a++)
            if (strncmp(name, areas[a], strlen(areas[a])) == 0) area = true;
        if (!area) {
            g_fail++;
            fprintf(stderr, "FAIL: code %s is in no known area\n", name);
        }
        for (const char *p = name; *p; p++)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-')) {
                g_fail++;
                fprintf(stderr, "FAIL: code %s has a character outside a-z 0-9 . -\n", name);
                break;
            }
        if (dns_diag_code_find(name) != (dns_diag_code_t)c) {            /* also: no two codes share a name */
            g_fail++;
            fprintf(stderr, "FAIL: code %s is not found under its own name\n", name);
        }
        (void)dns_diag_code_retired((dns_diag_code_t)c);
    }
}

/* the lines the old fprintf calls printed, byte for byte */
static void test_text_mode(void) {
    char out[2048], err[2048];
    cap_t co, ce;
    CHECK(!dns_diag_json_enabled());
    cap_begin(&co, 1);
    cap_begin(&ce, 2);
    dns_diag(DIAG_ERROR, DC_CONF_SYNTAX, "f.conf", 3, "zone '%s': bad %d\n", "a.test.", 7);
    dns_diag(DIAG_WARNING, DC_CONF_WARNING, NULL, 0, "careful\n");
    dns_diag(DIAG_NOTE, DC_CONF_STARTUP_NOTIFY_RATE, NULL, 0, "a note\n");
    dns_diag(DIAG_INFO, DC_CONF_LOADING, NULL, 0, "Loading config %s...\n", "x.conf");
    dns_diag(DIAG_INFO | DIAG_STDERR, DC_CONF_ZONE_FORWARD, NULL, 0, "info on stderr\n");
    dns_diag(DIAG_ERROR | DIAG_UNTAGGED, DC_IO_STAT, NULL, 0, "Failed to stat root zone file: %s\n", "/z");
    dns_diag_at(DIAG_ERROR, DC_CONF_SYNTAX, "f.conf:9", "%s: at\n", "f.conf:9");
    dns_diag_detail("Reason: %s\n\n", "because");
    dns_diag_plain(stdout, "[OK] %s is valid.\n", "Zone");
    dns_diag_plain(stderr, "[FAIL] %s\n", "bad");
    dns_diag_set_file("ignored.zone");                                    /* the context is kept for JSON mode only */
    dns_diag_set_zone("ignored.test.", "v");
    dns_diag_set_line(5);
    dns_diag_zone_result("a.test.", NULL, NULL, "bind", dns_diag_mark());   /* no zones[] outside JSON mode */
    dns_diag_counts(1, 2);
    cap_end(&ce, err, sizeof(err));
    cap_end(&co, out, sizeof(out));
    CHECK_STR(out, "[INFO] Loading config x.conf...\n[OK] Zone is valid.\n");
    CHECK_STR(err,
              "[ERROR] zone 'a.test.': bad 7\n"
              "[WARNING] careful\n"
              "[NOTE] a note\n"
              "[INFO] info on stderr\n"
              "Failed to stat root zone file: /z\n"
              "[ERROR] f.conf:9: at\n"
              "Reason: because\n\n"
              "[FAIL] bad\n");
    dns_diag_set_file(NULL);
    dns_diag_set_zone(NULL, NULL);
    dns_diag_set_line(0);

    /* a line that does not fit the buffer of one write comes out whole as well, and a tagged one with the tag */
    char big[5000], want[5100], got[6000];
    memset(big, 'y', 2500);
    big[2500] = '\0';
    cap_begin(&ce, 2);
    dns_diag(DIAG_WARNING, DC_CONF_WARNING, NULL, 0, "%s\n", big);
    dns_diag(DIAG_NOTE | DIAG_UNTAGGED, DC_CONF_WARNING, NULL, 0, "%s\n", big);
    cap_end(&ce, got, sizeof(got));
    snprintf(want, sizeof(want), "[WARNING] %s\n%s\n", big, big);
    CHECK_STR(got, want);
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *buf = malloc(1 << 22);
    size_t n = buf ? fread(buf, 1, (1 << 22) - 1, f) : 0;
    if (buf) buf[n] = '\0';
    fclose(f);
    return buf;
}

static char *finish_to_string(int status) {
    char path[600];
    snprintf(path, sizeof(path), "%s/doc.json", g_dir);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    CHECK(dns_diag_json_finish(f, status) == 0);
    fclose(f);
    return slurp(path);
}

static void test_json_document(void) {
    dns_diag_json_start("zone", "9.9.9");
    CHECK(dns_diag_json_enabled());
    dns_diag_set_file("db/ex.zone");
    dns_diag_set_zone("ex.test.", "__default__");
    dns_diag_mark_t m0 = dns_diag_mark();
    dns_diag(DIAG_ERROR, DC_ZONE_SYNTAX, NULL, 0, "line \"12\": bad\\value\n");
    dns_diag_set_line(40);
    dns_diag(DIAG_WARNING, DC_ZONE_SOA_EXPIRED, "other.zone", 7, "x\x01y \xC3\x28 z\n");   /* a control byte and invalid UTF-8 */
    dns_diag(DIAG_INFO, DC_ZONE_ALIAS_PRESENT, NULL, 0, "five ALIAS\n");               /* the line context applies */
    dns_diag_set_line(0);
    dns_diag_detail("  Expected: %s\n", "abc");
    dns_diag_at(DIAG_ERROR, DC_CONF_SYNTAX, "/etc/k:v/karidns.conf:77", "at\n");        /* the file may hold ':' */
    dns_diag_at(DIAG_ERROR, DC_CONF_SYNTAX, "line 5", "no file\n");
    dns_diag_at(DIAG_NOTE, DC_CONF_STARTUP_NOTIFY_RATE, "configuration", "no place\n");
    dns_diag_at(DIAG_NOTE, DC_CONF_STARTUP_NOTIFY_RATE, "a:b", "not a line\n");
    dns_diag_at(DIAG_NOTE, DC_CONF_STARTUP_NOTIFY_RATE, "a:12x", "not a line either\n");
    dns_diag_at(DIAG_NOTE, DC_CONF_STARTUP_NOTIFY_RATE, "line x", "no number\n");
    dns_diag_at(DIAG_NOTE, DC_CONF_STARTUP_NOTIFY_RATE, NULL, "no loc\n");
    dns_diag_plain(stdout, "[OK] dropped in JSON mode\n");
    dns_diag_zone_result("ex.test.", "__default__", "db/ex.zone", "bind", m0);
    dns_diag_zone_result("clean.test.", NULL, NULL, "tinydns", dns_diag_mark());
    dns_diag_counts(2, 1);
    char *doc = finish_to_string(1);
    CHECK(doc != NULL);
    if (doc) {
        CHECK(strstr(doc, "\"karicheck\": 1,") != NULL);
        CHECK(strstr(doc, "\"version\": \"9.9.9\"") != NULL);
        CHECK(strstr(doc, "\"command\": \"zone\"") != NULL);
        CHECK(strstr(doc, "\"result\": \"fail\"") != NULL);
        CHECK(strstr(doc, "\"counts\": { \"error\": 3, \"warning\": 1, \"checked\": 2, \"skipped\": 1, \"dropped\": 0 }") != NULL);
        CHECK(strstr(doc, "\"truncated\": false") != NULL);
        CHECK(strstr(doc, "{ \"severity\": \"error\", \"code\": \"zone.syntax\", \"text\": \"line \\\"12\\\": bad\\\\value\", \"file\": \"db/ex.zone\", "
                          "\"line\": null, \"zone\": \"ex.test.\", \"view\": \"__default__\" }") != NULL);
        CHECK(strstr(doc, "\"text\": \"x\\u0001y \xEF\xBF\xBD" "( z\", \"file\": \"other.zone\", \"line\": 7,") != NULL);
        CHECK(strstr(doc, "\"code\": \"zone.alias.present\", \"text\": \"five ALIAS\\u000a  Expected: abc\", \"file\": \"db/ex.zone\", \"line\": 40,") != NULL);
        CHECK(strstr(doc, "\"text\": \"at\", \"file\": \"/etc/k:v/karidns.conf\", \"line\": 77,") != NULL);
        CHECK(strstr(doc, "\"text\": \"no file\", \"file\": \"db/ex.zone\", \"line\": 5,") != NULL);
        CHECK(strstr(doc, "\"text\": \"no place\", \"file\": \"db/ex.zone\", \"line\": null,") != NULL);
        CHECK(strstr(doc, "\"text\": \"not a line\", \"file\": \"db/ex.zone\", \"line\": null,") != NULL);
        CHECK(strstr(doc, "\"text\": \"not a line either\", \"file\": \"db/ex.zone\", \"line\": null,") != NULL);
        CHECK(strstr(doc, "\"text\": \"no number\", \"file\": \"db/ex.zone\", \"line\": null,") != NULL);
        CHECK(strstr(doc, "\"text\": \"no loc\", \"file\": \"db/ex.zone\", \"line\": null,") != NULL);
        CHECK(strstr(doc, "dropped in JSON mode") == NULL);
        CHECK(strstr(doc, "{ \"zone\": \"ex.test.\", \"view\": \"__default__\", \"file\": \"db/ex.zone\", \"format\": \"bind\", \"result\": \"fail\", "
                          "\"errors\": 3, \"warnings\": 1 }") != NULL);
        CHECK(strstr(doc, "{ \"zone\": \"clean.test.\", \"view\": null, \"file\": null, \"format\": \"tinydns\", \"result\": \"ok\", "
                          "\"errors\": 0, \"warnings\": 0 }") != NULL);
        free(doc);
    }
    dns_diag_json_reset();
    CHECK(!dns_diag_json_enabled());

    /* a document without any message, a usage error without a command, and a successful run */
    dns_diag_json_start(NULL, "1");
    doc = finish_to_string(0);
    CHECK(doc && strstr(doc, "\"command\": null") && strstr(doc, "\"result\": \"ok\"") && strstr(doc, "\"messages\": [],") && strstr(doc, "\"zones\": []"));
    free(doc);
    dns_diag_detail("no message to continue\n");                         /* nothing to append to: ignored */
    dns_diag(DIAG_ERROR, DC_USAGE_COMMAND_MISSING, NULL, 0, "no command given\n");
    doc = finish_to_string(2);
    CHECK(doc && strstr(doc, "\"result\": \"usage\"") && strstr(doc, "\"code\": \"usage.command.missing\"") && !strstr(doc, "no message to continue"));
    free(doc);
    dns_diag(DIAG_WARNING, DC_NONE, NULL, 0, "a message without a code\n");
    doc = finish_to_string(1);
    CHECK(doc && strstr(doc, "\"code\": null, \"text\": \"a message without a code\""));
    free(doc);
    dns_diag_json_reset();
}

static void test_limits(void) {
    dns_diag_json_start("conf", "1");
    for (int i = 0; i < DIAG_MAX_MESSAGES + 5; i++) dns_diag(i % 2 ? DIAG_ERROR : DIAG_WARNING, DC_CONF_SYNTAX, NULL, 0, "message %d\n", i);
    dns_diag_detail("after the cap\n");                                   /* the last stored message is not the last one: ignored */
    for (int i = 0; i < DIAG_MAX_ZONES + 3; i++) dns_diag_zone_result("z.test.", NULL, NULL, "bind", dns_diag_mark());
    char *doc = finish_to_string(1);
    CHECK(doc != NULL);
    if (doc) {
        CHECK(strstr(doc, "\"truncated\": true") != NULL);
        CHECK(strstr(doc, "\"dropped\": 5 }") != NULL);
        CHECK(strstr(doc, "\"error\": 5002, \"warning\": 5003,") != NULL);        /* the dropped ones are counted */
        CHECK(strstr(doc, "message 9999\"") != NULL);
        CHECK(strstr(doc, "message 10000\"") == NULL);
        CHECK(strstr(doc, "after the cap") == NULL);
        free(doc);
    }
    dns_diag_json_reset();

    /* a long message is cut, and says so */
    dns_diag_json_start("conf", "1");
    char big[DIAG_TEXT_MAX + 400];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    dns_diag(DIAG_ERROR, DC_CONF_SYNTAX, NULL, 0, "%s\n", big);
    doc = finish_to_string(1);
    CHECK(doc != NULL);
    if (doc) {
        char *p = strstr(doc, "\"text\": \"");
        CHECK(p != NULL);
        char *q = p ? strstr(p + 9, "\"") : NULL;
        CHECK(q && (size_t)(q - (p + 9)) == DIAG_TEXT_MAX + 3);
        CHECK(q && strncmp(q - 3, "...", 3) == 0);
        free(doc);
    }
    /* a detail that does not fit is ignored, one that fits is appended */
    dns_diag_json_reset();
    dns_diag_json_start("conf", "1");
    dns_diag(DIAG_ERROR, DC_CONF_SYNTAX, NULL, 0, "%s\n", big);
    dns_diag_detail("%s\n", big);
    doc = finish_to_string(1);
    CHECK(doc != NULL);
    free(doc);
    dns_diag_json_reset();
}

static void test_suspend_and_log(void) {
    char err[256];
    cap_t ce;
    dns_diag_json_start("db", "1");
    CHECK(!dns_diag_suspend_json(true));
    CHECK(!dns_diag_json_enabled());
    cap_begin(&ce, 2);
    dns_diag(DIAG_ERROR, DC_CONF_SYNTAX, NULL, 0, "printed while suspended\n");
    dns_diag_detail("and its detail\n");
    cap_end(&ce, err, sizeof(err));
    CHECK_STR(err, "[ERROR] printed while suspended\nand its detail\n");
    CHECK(dns_diag_suspend_json(false));
    CHECK(dns_diag_json_enabled());
    char *doc = finish_to_string(0);
    CHECK(doc && strstr(doc, "printed while suspended") == NULL && strstr(doc, "\"error\": 0"));
    free(doc);
    dns_diag_json_reset();

    /* the code log of the test builds: the code of every message is appended to the file, in text and in JSON mode */
    char path[600];
    snprintf(path, sizeof(path), "%s/codes.txt", g_dir);
    dns_diag_code_log(path);
    cap_begin(&ce, 2);
    dns_diag(DIAG_ERROR, DC_ZONE_SOA_MISSING, NULL, 0, "x\n");
    cap_end(&ce, err, sizeof(err));
    dns_diag_json_start("zone", "1");
    dns_diag(DIAG_WARNING, DC_CONF_ECS_DISABLED, NULL, 0, "y\n");
    dns_diag_json_reset();
    dns_diag_code_log(NULL);
    cap_begin(&ce, 2);
    dns_diag(DIAG_ERROR, DC_ZONE_NS_MISSING, NULL, 0, "z\n");              /* not logged: the log is closed */
    cap_end(&ce, err, sizeof(err));
    char *log = slurp(path);
    CHECK(log && strcmp(log, "zone.soa.missing\nconf.ecs.disabled\n") == 0);
    free(log);
}

int main(void) {
    const char *base = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/test_dns_diag.XXXXXX", base && *base ? base : "/tmp");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        return 2;
    }
    test_table();
    test_escape();
    test_text_mode();
    test_json_document();
    test_limits();
    test_suspend_and_log();
    if (g_fail) {
        fprintf(stderr, "test_dns_diag: %d check(s) FAILED (files in %s)\n", g_fail, g_dir);
        return 1;
    }
    tmpdir_remove(g_dir);
    printf("test_dns_diag: all checks passed\n");
    return 0;
}
