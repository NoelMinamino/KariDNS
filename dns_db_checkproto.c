/*
 * dns_db_checkproto.c - the line protocol of `karidns-dbloader --check` (see dns_db_checkproto.h).
 */
#include <string.h>
#include "dns_db_checkproto.h"

size_t chk_escape(const char *in, size_t n, char *out, size_t cap, bool *trunc) {
    size_t o = 0;
    size_t i = 0;
    if (trunc) *trunc = false;
    if (cap == 0) return 0;
    for (; i < n; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch >= 0x20 && ch < 0x7F && ch != '\\') {
            if (o + 1 >= cap) break;
            out[o++] = (char)ch;
        } else {
            if (o + 4 >= cap) break;
            out[o++] = '\\';
            out[o++] = (char)('0' + ch / 100);
            out[o++] = (char)('0' + ch / 10 % 10);
            out[o++] = (char)('0' + ch % 10);
        }
    }
    out[o] = '\0';
    if (trunc && i < n) *trunc = true;
    return o;
}

size_t chk_unescape(const char *in, size_t n, char *out, size_t cap) {
    size_t o = 0;
    if (cap == 0) return (size_t)-1;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch == '\\') {
            if (n - i < 4) return (size_t)-1;                   /* a backslash and three digits */
            unsigned char d0 = (unsigned char)in[i + 1], d1 = (unsigned char)in[i + 2], d2 = (unsigned char)in[i + 3];
            if (d0 < '0' || d0 > '9' || d1 < '0' || d1 > '9' || d2 < '0' || d2 > '9') return (size_t)-1;
            unsigned v = (unsigned)(d0 - '0') * 100 + (unsigned)(d1 - '0') * 10 + (unsigned)(d2 - '0');
            if (v > 255) return (size_t)-1;
            if (o + 1 >= cap) return (size_t)-1;
            out[o++] = (char)v;
            i += 3;
        } else if (ch >= 0x20 && ch < 0x7F) {
            if (o + 1 >= cap) return (size_t)-1;
            out[o++] = (char)ch;
        } else {
            return (size_t)-1;
        }
    }
    out[o] = '\0';
    return o;
}

int chk_split(char *line, char **fields, int max) {
    int n = 0;
    char *p = line;
    for (;;) {
        if (n >= max) return -1;
        fields[n++] = p;
        for (; *p && *p != '\t'; p++)
            if ((unsigned char)*p < 0x20) return -1;
        if (!*p) return n;
        *p++ = '\0';
    }
}

void chk_printable(char *s) {
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7E) *s = '?';
}
