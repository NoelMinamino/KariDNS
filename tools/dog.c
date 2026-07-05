/*
 * dog - DNS test client
 *
 * Usage: dog <name> <type> @<server> [-p <port>]
 *
 * Builds a single DNS query using dns_wire.h functions,
 * sends it over UDP to the specified server, and hexdumps the response.
 * This is a skeleton to verify that dns_wire.c links correctly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "../dns_wire.h"

/* Minimal arena for dog: use a static buffer */
#define DOG_ARENA_SIZE (64 * 1024)
static char g_arena_buf[DOG_ARENA_SIZE];
static size_t g_arena_pos = 0;

struct zone_arena_s {
    /* dog uses only the arena_alloc path */
    char pad[1];
};

void *arena_alloc(zone_arena_t *arena, size_t size) {
    (void)arena;
    if (g_arena_pos + size > DOG_ARENA_SIZE) return NULL;
    void *p = &g_arena_buf[g_arena_pos];
    g_arena_pos += size;
    return p;
}



/* -------------------------------------------------------------------------- */

static uint16_t parse_qtype(const char *s) {
    if (strcasecmp(s, "A") == 0)    return 1;
    if (strcasecmp(s, "NS") == 0)   return 2;
    if (strcasecmp(s, "CNAME") == 0) return 5;
    if (strcasecmp(s, "SOA") == 0)  return 6;
    if (strcasecmp(s, "PTR") == 0)  return 12;
    if (strcasecmp(s, "MX") == 0)   return 15;
    if (strcasecmp(s, "TXT") == 0)  return 16;
    if (strcasecmp(s, "AAAA") == 0) return 28;
    if (strcasecmp(s, "SRV") == 0)  return 33;
    if (strcasecmp(s, "ANY") == 0)  return 255;
    return (uint16_t)atoi(s);
}

static void hexdump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%04zx  ", i);
        printf("%02x ", buf[i]);
        if (i % 16 == 7) printf(" ");
        if (i % 16 == 15 || i + 1 == len) {
            size_t pad = 15 - (i % 16);
            for (size_t j = 0; j < pad; j++) printf("   ");
            if ((i % 16) < 7) printf(" ");
            printf(" |");
            size_t row_start = i - (i % 16);
            for (size_t j = row_start; j <= i; j++) {
                unsigned char c = buf[j];
                printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            }
            printf("|\n");
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: dog <name> <type> @<server> [-p <port>]\n");
        return 1;
    }

    const char *qname  = argv[1];
    const char *qtype_s = argv[2];
    const char *server_arg = argv[3];
    int port = 53;

    if (server_arg[0] != '@') {
        fprintf(stderr, "Server must start with '@', e.g. @192.0.2.1\n");
        return 1;
    }
    const char *server = server_arg + 1;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
    }

    uint16_t qtype = parse_qtype(qtype_s);

    /* ---- Build query packet ---- */
    static uint8_t pkt[512];
    memset(pkt, 0, 12);

    uint16_t id = (uint16_t)(time(NULL) & 0xFFFF);
    pkt[0] = id >> 8; pkt[1] = id & 0xFF;
    pkt[2] = 0x01; /* RD=1 */
    pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT=1 */

    uint16_t offset = 12;
    compress_ctx_t comp_ctx;
    compress_ctx_init_packet(&comp_ctx);

    if (write_dns_name_str(pkt, &offset, qname, &comp_ctx) != 0) {
        fprintf(stderr, "write_dns_name_str failed\n");
        return 1;
    }
    pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
    pkt[offset++] = 0x00; pkt[offset++] = 0x01; /* QCLASS IN */

    size_t pkt_len = offset;

    printf("Query (%zu bytes):\n", pkt_len);
    hexdump(pkt, pkt_len);
    printf("\n");

    /* ---- Send UDP ---- */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server, &dest.sin_addr) != 1) {
        fprintf(stderr, "Invalid server address: %s\n", server);
        close(sock);
        return 1;
    }

    if (sendto(sock, pkt, pkt_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    /* ---- Receive response ---- */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    static uint8_t resp[65536];
    ssize_t n = recv(sock, resp, sizeof(resp), 0);
    close(sock);

    if (n < 0) {
        perror("recv");
        return 1;
    }

    printf("Response (%zd bytes):\n", n);
    hexdump(resp, (size_t)n);

    return 0;
}
