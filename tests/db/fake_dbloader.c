/*
 * fake_dbloader.c - a stand-in for karidns-dbloader that speaks KDB1 wrongly (tests/run_db_loader_lifecycle_test.sh).
 *
 *   fake_dbloader -s FD [bad-magic | bad-order | bad-view | silent]
 *
 * It sends a correct HELLO (version 1, driver sqlite3), reads the CONFIG, and then breaks the protocol:
 *   bad-magic  a message whose magic is not "KDB1"
 *   bad-order  ZONE_END without BATCH_BEGIN / ZONE_BEGIN (a message type that is not legal in the state)
 *   bad-view   BATCH_BEGIN followed by a ZONE_BEGIN naming a view index beyond the configured views
 *   silent     nothing more (the Backend must keep waiting without harm)
 * Then it waits until the Backend closes the stream and exits 0.  Hand-made bytes, no library: the encoder of
 * dns_db_stream.c would only make correct messages.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }

static size_t tlv(uint8_t *b, uint16_t tag, const void *v, uint16_t n) {
    put16(b, tag);
    put16(b + 2, n);
    memcpy(b + 4, v, n);
    return 4u + n;
}

static void send_msg(int fd, const char *magic, uint16_t type, const uint8_t *body, size_t n) {
    uint8_t buf[2048];
    memcpy(buf, magic, 4);
    put16(buf + 4, type);
    put16(buf + 6, 0);
    put32(buf + 8, (uint32_t)n);
    memcpy(buf + 12, body, n);
    size_t off = 0, len = 12 + n;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w <= 0) exit(0);
        off += (size_t)w;
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "-s") != 0) return 2;
    int fd = atoi(argv[2]);
    const char *mode = argc > 3 ? argv[3] : "bad-magic";
    uint8_t b[512];
    size_t n = 0;
    uint8_t v16[2] = { 0, 1 }, pid[4];
    put32(pid, (uint32_t)getpid());
    n += tlv(b + n, 1, v16, 2);
    n += tlv(b + n, 2, "fake", 4);
    n += tlv(b + n, 3, "sqlite3", 7);
    n += tlv(b + n, 4, pid, 4);
    send_msg(fd, "KDB1", 1, b, n);

    uint8_t rbuf[4096];                      /* the CONFIG */
    ssize_t r = read(fd, rbuf, sizeof(rbuf));
    (void)r;
    uint8_t one[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
    n = 0;
    if (strcmp(mode, "bad-magic") == 0) {
        send_msg(fd, "XXXX", 2, b, 0);
    } else if (strcmp(mode, "bad-order") == 0) {
        n += tlv(b + n, 1, one, 8);
        send_msg(fd, "KDB1", 6, b, n);       /* ZONE_END in READY */
    } else if (strcmp(mode, "bad-view") == 0) {
        uint8_t kind = 0, zero8[8] = { 0 };
        n += tlv(b + n, 1, one, 8);
        n += tlv(b + n, 2, &kind, 1);
        n += tlv(b + n, 3, zero8, 8);
        send_msg(fd, "KDB1", 3, b, n);       /* BATCH_BEGIN */
        uint8_t view[2] = { 0x12, 0x34 }, serial[4] = { 0, 0, 0, 1 }, flags[4] = { 0 }, rrs[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };
        uint8_t digest[32] = { 0 }, src[8] = { 0 }, zk = 0;
        n = 0;
        n += tlv(b + n, 1, view, 2);
        n += tlv(b + n, 2, "bad.test.", 9);
        n += tlv(b + n, 3, src, 8);
        n += tlv(b + n, 4, &zk, 1);
        n += tlv(b + n, 5, serial, 4);
        n += tlv(b + n, 6, flags, 4);
        n += tlv(b + n, 7, rrs, 8);
        n += tlv(b + n, 8, digest, 32);
        send_msg(fd, "KDB1", 4, b, n);       /* ZONE_BEGIN with view 0x1234 */
    }
    for (;;) {                                /* until the Backend closes the stream */
        ssize_t k = read(fd, rbuf, sizeof(rbuf));
        if (k == 0) return 0;
        if (k < 0) sleep(1);
    }
}
