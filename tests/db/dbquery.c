/*
 * dbquery.c - a small DNS query client for tests/run_db_file_diff_test.sh (beta design 8.4): it sends the queries of
 * a list to one server and writes the exact response bytes, so the answers of two servers can be compared with the
 * message ID masked (dag output has times and servers in it).
 *
 *   dbquery -p PORT [-s ADDR] [-t SECONDS] LIST OUT
 *
 * LIST: one query per line, "name TYPE MODE"; MODE is
 *   p   plain query (no EDNS: the 512 byte limit applies)
 *   e   EDNS0, UDP size 1232, DO = 0
 *   d   EDNS0, UDP size 1232, DO = 1
 * Lines starting with '#' and empty lines are ignored.  TYPE is a mnemonic (A NS CNAME SOA PTR MX TXT AAAA SRV
 * NAPTR DS DNSKEY RRSIG NSEC NSEC3 NSEC3PARAM TLSA SVCB HTTPS CAA ANY, ...) or TYPEnnn.
 *
 * OUT: one line per query, "key<TAB>strict<TAB>folded", the key being the list line.  strict is the response as
 * lower-case hex with the 16-bit ID zeroed; folded is the same with ASCII letters of the question name and of the
 * owner names of the RRs folded to lower case (PowerDNS stores owners in lower case, a zone file may not).  A query
 * that gets no answer (timeout) writes "TIMEOUT" in both columns.  The UDP answer is taken as it is, truncated or not.
 *
 * Exit status 0 when every query was answered, 1 on timeouts, 2 on usage or I/O errors.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static const struct { const char *name; uint16_t code; } k_types[] = {
    { "A", 1 }, { "NS", 2 }, { "CNAME", 5 }, { "SOA", 6 }, { "PTR", 12 }, { "HINFO", 13 }, { "MX", 15 },
    { "TXT", 16 }, { "AAAA", 28 }, { "LOC", 29 }, { "SRV", 33 }, { "NAPTR", 35 }, { "DNAME", 39 }, { "DS", 43 },
    { "SSHFP", 44 }, { "RRSIG", 46 }, { "NSEC", 47 }, { "DNSKEY", 48 }, { "NSEC3", 50 }, { "NSEC3PARAM", 51 },
    { "TLSA", 52 }, { "CDS", 59 }, { "CDNSKEY", 60 }, { "ZONEMD", 63 }, { "SVCB", 64 }, { "HTTPS", 65 },
    { "URI", 256 }, { "CAA", 257 }, { "ANY", 255 }, { "AXFR", 252 },
};

static int parse_type(const char *s, uint16_t *out) {
    for (size_t i = 0; i < sizeof(k_types) / sizeof(k_types[0]); i++) {
        if (strcasecmp(s, k_types[i].name) == 0) {
            *out = k_types[i].code;
            return 0;
        }
    }
    if (strncasecmp(s, "TYPE", 4) == 0 && s[4]) {
        char *end;
        unsigned long v = strtoul(s + 4, &end, 10);
        if (*end == '\0' && v < 65536) {
            *out = (uint16_t)v;
            return 0;
        }
    }
    return -1;
}

/* presentation name -> wire; handles \DDD and \X escapes.  Returns the length, or 0 on error. */
static size_t name_to_wire(const char *name, uint8_t *out, size_t cap) {
    size_t n = 0, lp = 0;
    if (strcmp(name, ".") == 0) {
        out[0] = 0;
        return 1;
    }
    lp = n++;
    out[lp] = 0;
    for (const char *p = name; *p; p++) {
        if (*p == '.') {
            if (out[lp] == 0 || out[lp] > 63) return 0;
            if (n >= cap) return 0;
            lp = n++;
            out[lp] = 0;
            continue;
        }
        uint8_t c = (uint8_t)*p;
        if (c == '\\') {
            if (isdigit((unsigned char)p[1]) && isdigit((unsigned char)p[2]) && isdigit((unsigned char)p[3])) {
                c = (uint8_t)((p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0'));
                p += 3;
            } else if (p[1]) {
                c = (uint8_t)p[1];
                p++;
            }
        }
        if (n >= cap - 1) return 0;
        out[n++] = c;
        out[lp]++;
    }
    if (out[lp] == 0) {            /* a trailing dot: the last length byte is the root */
        return n;
    }
    if (n >= cap) return 0;
    out[n++] = 0;
    return n;
}

static void hex(const uint8_t *p, size_t n, FILE *f) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        fputc(d[p[i] >> 4], f);
        fputc(d[p[i] & 15], f);
    }
}

/* fold ASCII letters of the labels of the name at *off to lower case in place and advance past the name.  Compression
 * pointers end the name (their target is folded where it stands, as owner or question name; a target inside RDATA is
 * left alone).  Returns false on a malformed name. */
static bool fold_name(uint8_t *m, size_t len, size_t *off) {
    size_t o = *off;
    for (;;) {
        if (o >= len) return false;
        uint8_t l = m[o];
        if (l == 0) {
            *off = o + 1;
            return true;
        }
        if ((l & 0xC0) == 0xC0) {
            *off = o + 2;
            return o + 2 <= len;
        }
        if ((l & 0xC0) != 0 || o + 1 + l > len) return false;
        for (size_t i = 0; i < l; i++) m[o + 1 + i] = (uint8_t)tolower(m[o + 1 + i]);
        o += 1 + l;
    }
}

static void fold_owners(uint8_t *m, size_t len) {
    if (len < 12) return;
    size_t off = 12;
    unsigned qd = (m[4] << 8) | m[5];
    unsigned rrs = ((m[6] << 8) | m[7]) + ((m[8] << 8) | m[9]) + ((m[10] << 8) | m[11]);
    for (unsigned i = 0; i < qd; i++) {
        if (!fold_name(m, len, &off)) return;
        off += 4;
    }
    for (unsigned i = 0; i < rrs; i++) {
        if (!fold_name(m, len, &off)) return;
        if (off + 10 > len) return;
        size_t rdlen = (m[off + 8] << 8) | m[off + 9];
        off += 10 + rdlen;
        if (off > len) return;
    }
}

int main(int argc, char **argv) {
    int port = 0, tmo = 2;
    const char *addr = "127.0.0.1";
    int opt;
    while ((opt = getopt(argc, argv, "p:s:t:")) != -1) {
        if (opt == 'p') port = atoi(optarg);
        else if (opt == 's') addr = optarg;
        else if (opt == 't') tmo = atoi(optarg);
        else return 2;
    }
    if (port <= 0 || optind + 2 != argc) {
        fprintf(stderr, "usage: dbquery -p PORT [-s ADDR] [-t SECONDS] LIST OUT\n");
        return 2;
    }
    FILE *in = fopen(argv[optind], "r");
    FILE *out = fopen(argv[optind + 1], "w");
    if (!in || !out) {
        perror("open");
        return 2;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad address %s\n", addr);
        return 2;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("socket/connect");
        return 2;
    }
    char line[2048];
    int timeouts = 0;
    unsigned id = 1;
    while (fgets(line, sizeof(line), in)) {
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll - 1] == '\n' || line[ll - 1] == '\r')) line[--ll] = '\0';
        if (ll == 0 || line[0] == '#') continue;
        char name[1500], type[64], mode[8];
        if (sscanf(line, "%1499s %63s %7s", name, type, mode) != 3) {
            fprintf(stderr, "bad line: %s\n", line);
            return 2;
        }
        uint16_t qt;
        if (parse_type(type, &qt) != 0) {
            fprintf(stderr, "bad type in: %s\n", line);
            return 2;
        }
        uint8_t q[1600];
        size_t n = 0;
        memset(q, 0, 12);
        q[0] = (uint8_t)(id >> 8);
        q[1] = (uint8_t)id;
        id++;
        q[5] = 1;
        n = 12;
        size_t nl = name_to_wire(name, q + n, sizeof(q) - n - 16);
        if (nl == 0) {
            fprintf(stderr, "bad name in: %s\n", line);
            return 2;
        }
        n += nl;
        q[n++] = (uint8_t)(qt >> 8); q[n++] = (uint8_t)qt; q[n++] = 0; q[n++] = 1;
        if (mode[0] == 'e' || mode[0] == 'd') {
            q[11] = 1;
            q[n++] = 0;                                  /* root */
            q[n++] = 0; q[n++] = 41;                     /* OPT */
            q[n++] = 0x04; q[n++] = 0xD0;                /* UDP size 1232 */
            q[n++] = 0; q[n++] = 0;                      /* extended rcode, version */
            q[n++] = mode[0] == 'd' ? 0x80 : 0;          /* DO */
            q[n++] = 0;
            q[n++] = 0; q[n++] = 0;                      /* RDLEN */
        }
        uint8_t r[65536];
        ssize_t rn = -1;
        for (int attempt = 0; attempt < 3 && rn < 0; attempt++) {
            if (send(fd, q, n, 0) < 0) {
                perror("send");
                return 2;
            }
            struct pollfd p = { fd, POLLIN, 0 };
            int pr = poll(&p, 1, tmo * 1000 / 3 + 1);
            if (pr > 0) {
                ssize_t got = recv(fd, r, sizeof(r), 0);
                if (got >= 12 && r[0] == q[0] && r[1] == q[1]) rn = got;
            }
        }
        fprintf(out, "%s\t", line);
        if (rn < 0) {
            timeouts++;
            fprintf(out, "TIMEOUT\tTIMEOUT\n");
            continue;
        }
        r[0] = r[1] = 0;
        hex(r, (size_t)rn, out);
        fputc('\t', out);
        fold_owners(r, (size_t)rn);
        hex(r, (size_t)rn, out);
        fputc('\n', out);
    }
    fclose(out);
    fclose(in);
    return timeouts ? 1 : 0;
}
