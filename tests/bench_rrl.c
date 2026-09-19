#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include "../dns_config_parser.h"
#include "../dns_rrl.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

#define NUM_QUERIES 10000000

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(void) {
    rrl_init();

    rate_limit_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.configured = true;
    cfg.responses_per_second = 100000000;
    cfg.window_seconds = 15;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    inet_pton(AF_INET, "192.0.2.1", &sin.sin_addr);

    struct sockaddr_storage ss;
    memcpy(&ss, &sin, sizeof(sin));

    bool slip = false;

    // Warmup
    for (int i = 0; i < 100000; i++) {
        rrl_check(&ss, RRL_RESP_NOERROR, &cfg, &slip);
    }

    uint64_t t0 = get_time_ns();
    int allowed = 0;
    for (int i = 0; i < NUM_QUERIES; i++) {
        sin.sin_addr.s_addr = htonl(0xC0000200 + (i % 256));
        memcpy(&ss, &sin, sizeof(sin));
        if (rrl_check(&ss, RRL_RESP_NOERROR, &cfg, &slip)) {
            allowed++;
        }
    }
    uint64_t t1 = get_time_ns();

    double elapsed_sec = (double)(t1 - t0) / 1e9;
    double qps = (double)NUM_QUERIES / elapsed_sec;
    double ns_per_call = (double)(t1 - t0) / NUM_QUERIES;

    printf("==================================================\n");
    printf("RRL Throughput & Latency Benchmark\n");
    printf("==================================================\n");
    printf("Total checks  : %d\n", NUM_QUERIES);
    printf("Time elapsed  : %.4f s\n", elapsed_sec);
    printf("Throughput    : %.2f M checks/sec\n", qps / 1e6);
    printf("Avg Latency   : %.2f ns / check\n", ns_per_call);
    printf("Allowed count : %d\n", allowed);
    printf("==================================================\n");

    rrl_shutdown();
    return 0;
}
