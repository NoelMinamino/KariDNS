/*
 * xfrdump.c - dumps the messages of a zone transfer, for tests that compare two servers byte for byte (B8: Extended
 * AXFR out of a zone file and of a database zone).
 *
 *   xfrdump -p PORT [-s ADDR] [-x] [-b ADDR] ZONE > out
 *
 * Sends one AXFR request over TCP (message ID 0x4B44, no TSIG) and writes every response message as one line of
 * lower-case hex (the message ID is part of the line: the request ID is fixed).  -x asks for the KariDNS Extended AXFR
 * (EDNS option 65153, version 2, FNV-1a hash of the zone name, as the secondary's request in dns_axfr_ixfr.c), -b
 * binds the source address.  The transfer ends when the server closes the connection or after 10 seconds without
 * data.  Exit status 0 when at least one message arrived, 1 otherwise, 2 on usage errors.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint32_t fnv1a_lower(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        uint8_t c = (uint8_t)*s;
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

static int read_full(int fd, uint8_t *p, size_t n) {
    while (n) {
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, 10000) <= 0) return -1;
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1", *bind_addr = NULL, *zone = NULL;
    int port = 0;
    int ext = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) addr = argv[++i];
        else if (!strcmp(argv[i], "-b") && i + 1 < argc) bind_addr = argv[++i];
        else if (!strcmp(argv[i], "-x")) ext = 1;
        else if (argv[i][0] != '-') zone = argv[i];
        else { port = 0; break; }
    }
    if (port <= 0 || !zone) {
        fprintf(stderr, "usage: xfrdump -p PORT [-s ADDR] [-b SRC] [-x] ZONE\n");
        return 2;
    }
    uint8_t req[600];
    size_t n = 2 + 12;
    memset(req, 0, sizeof(req));
    req[2] = 0x4B; req[3] = 0x44; req[7] = 1; req[13] = 1;          /* ID, QDCOUNT 1, ARCOUNT 1 */
    /* QNAME */
    const char *p = zone;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63) { fprintf(stderr, "xfrdump: bad zone name\n"); return 2; }
        req[n++] = (uint8_t)l;
        memcpy(req + n, p, l);
        n += l;
        if (!dot) break;
        p = dot + 1;
    }
    req[n++] = 0;
    req[n++] = 0; req[n++] = 252; req[n++] = 0; req[n++] = 1;       /* AXFR IN */
    uint8_t opt_ext[9] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    (void)opt_ext;
    uint32_t h = fnv1a_lower(zone);
    /* OPT: root, type 41, size 4096, TTL 0, RDLEN; option EXPIRE (9, empty) and, with -x, option 65153 */
    req[n++] = 0; req[n++] = 0; req[n++] = 41; req[n++] = 0x10; req[n++] = 0; req[n++] = 0; req[n++] = 0; req[n++] = 0; req[n++] = 0;
    size_t rdlen_pos = n;
    n += 2;
    req[n++] = 0; req[n++] = 9; req[n++] = 0; req[n++] = 0;
    if (ext) {
        req[n++] = 0xFE; req[n++] = 0x81; req[n++] = 0; req[n++] = 5;      /* 65153 */
        req[n++] = 2;                                                      /* KARIDNS_EXT_VERSION */
        req[n++] = (uint8_t)(h >> 24); req[n++] = (uint8_t)(h >> 16); req[n++] = (uint8_t)(h >> 8); req[n++] = (uint8_t)h;
    }
    size_t rdlen = n - rdlen_pos - 2;
    req[rdlen_pos] = (uint8_t)(rdlen >> 8);
    req[rdlen_pos + 1] = (uint8_t)rdlen;
    req[0] = (uint8_t)((n - 2) >> 8);
    req[1] = (uint8_t)(n - 2);

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
    s4->sin_family = AF_INET;
    s4->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr, &s4->sin_addr) != 1) { fprintf(stderr, "xfrdump: bad address\n"); return 2; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    if (bind_addr) {
        struct sockaddr_in b;
        memset(&b, 0, sizeof(b));
        b.sin_family = AF_INET;
        if (inet_pton(AF_INET, bind_addr, &b.sin_addr) != 1 || bind(fd, (struct sockaddr *)&b, sizeof(b)) != 0) {
            fprintf(stderr, "xfrdump: cannot bind %s\n", bind_addr);
            return 2;
        }
    }
    if (connect(fd, (struct sockaddr *)s4, sizeof(*s4)) != 0) { fprintf(stderr, "xfrdump: connect: %s\n", strerror(errno)); return 1; }
    if (write(fd, req, n) != (ssize_t)n) return 1;
    int got = 0;
    static uint8_t msg[65536];
    for (;;) {
        uint8_t lb[2];
        if (read_full(fd, lb, 2) != 0) break;
        size_t l = ((size_t)lb[0] << 8) | lb[1];
        if (l == 0 || read_full(fd, msg, l) != 0) break;
        for (size_t i = 0; i < l; i++) printf("%02x", msg[i]);
        printf("\n");
        got++;
    }
    close(fd);
    return got ? 0 : 1;
}
