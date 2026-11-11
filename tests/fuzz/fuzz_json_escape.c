/*
 * fuzz_json_escape.c - the JSON writer of karicheck --json (dns_diag.c).
 *
 * Every string in the document comes from a file or from the database loader, so any byte may arrive.  The input goes through
 * dns_diag_json_escape() (the result must be valid JSON string content and valid UTF-8, and the length must agree with a second call into
 * a buffer of that size), and through the whole writer: the input is the text, the file name and the zone of messages, with and without
 * a line number and a detail line.  The document must be well formed: strings end where they should, escapes are the legal ones, no raw
 * control character, nothing but valid UTF-8.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* the fuzz object flags define it too */
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../dns_diag.h"

/* the content of a JSON string (without the quotes): only legal escapes, no raw control character or quote, valid UTF-8 (RFC 3629) */
static bool content_ok(const unsigned char *s, size_t n) {
    for (size_t i = 0; i < n;) {
        unsigned char c = s[i];
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
        unsigned cp = l == 2 ? (c & 0x1Fu) : l == 3 ? (c & 0x0Fu) : (c & 0x07u);
        for (size_t k = 1; k < l; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (s[i + k] & 0x3Fu);
        }
        if ((l == 2 && cp < 0x80) || (l == 3 && cp < 0x800) || (l == 4 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        i += l;
    }
    return true;
}

/* the document: outside strings only structure characters, every string passes content_ok() */
static bool doc_ok(const unsigned char *d, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = d[i];
        if (c == '"') {
            size_t j = i + 1;
            while (j < n && d[j] != '"') j += d[j] == '\\' ? 2 : 1;       /* an escaped character is skipped as a pair */
            if (j >= n || !content_ok(d + i + 1, j - i - 1)) return false;
            i = j + 1;
        } else if (c == '\n' || c == ' ' || c == '{' || c == '}' || c == '[' || c == ']' || c == ',' || c == ':' || (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'z')) {
            i++;
        } else {
            return false;
        }
    }
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;

    size_t need = dns_diag_json_escape(NULL, 0, (const char *)data, size);
    char *esc = malloc(need + 1);
    if (!esc) return 0;
    size_t got = dns_diag_json_escape(esc, need + 1, (const char *)data, size);
    if (got != need || strlen(esc) != need) abort();
    if (!content_ok((const unsigned char *)esc, need)) abort();
    char small[16];                                                        /* a cut result is still a prefix of the full one */
    if (dns_diag_json_escape(small, sizeof(small), (const char *)data, size) != need) abort();
    if (strncmp(small, esc, sizeof(small) - 1) != 0) abort();
    free(esc);

    /* the writer: the input as C strings (it holds no NUL after the first one is cut off) */
    char *text = malloc(size + 1);
    if (!text) return 0;
    memcpy(text, data, size);
    text[size] = '\0';
    const char *part2 = text + (size ? data[0] % (strlen(text) + 1) : 0);
    dns_diag_json_start(size && (data[0] & 1) ? "zone" : NULL, text);
    dns_diag_set_file(part2);
    dns_diag_set_zone(text, part2);
    dns_diag(DIAG_ERROR, DC_ZONE_SYNTAX, NULL, 0, "%s", text);
    dns_diag(DIAG_WARNING, DC_ZONE_SOA_EXPIRED, part2, 12, "%s\n", part2);
    dns_diag_detail("%s", part2);
    dns_diag_at(DIAG_NOTE, DC_CONF_SYNTAX, text, "%s", part2);
    dns_diag_set_line(3);
    dns_diag(DIAG_INFO, DC_CONF_LOADING, text, 0, "%s", text);
    dns_diag_zone_result(text, part2, text, "bind", (dns_diag_mark_t){ 0, 0 });
    char *doc = NULL;
    size_t doclen = 0;
    FILE *f = open_memstream(&doc, &doclen);
    if (!f) {
        free(text);
        dns_diag_json_reset();
        return 0;
    }
    if (dns_diag_json_finish(f, 1) != 0) abort();
    fclose(f);
    if (!doc_ok((const unsigned char *)doc, doclen)) abort();
    free(doc);
    free(text);
    dns_diag_json_reset();
    return 0;
}
