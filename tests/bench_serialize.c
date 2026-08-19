#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../dns_wire.h"
static uint32_t bench_parse_dnssec_time(const char *str) {
    int year, month, day, hour, min, sec;
    if (sscanf(str, "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &min, &sec) != 6) {
        return 0;
    }
    int64_t y = year;
    if (month <= 2) y -= 1;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned mp = (unsigned)((month + 9) % 12);
    unsigned doy = (153 * mp + 2) / 5 + (unsigned)day - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days_since_epoch = era * 146097 + (int64_t)doe - 719468;
    int64_t total_seconds = days_since_epoch * 86400LL + hour * 3600LL + min * 60LL + sec;
    return (uint32_t)total_seconds;
}
#include "../dns_zone_parser.h" // For parse_dnssec_time

#include <openssl/evp.h>

#define NUM_RECORDS 500000
#define NUM_RUNS 7

dns_record_t records[NUM_RECORDS];

// Helper to get monotonic time in nanoseconds
static uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Dummy compress_ctx
compress_ctx_t dummy_comp_ctx;
zone_arena_t bench_arena;
static char name_pool[NUM_RECORDS][64];

// Prepare records with realistic distribution
void prepare_records() {
    zone_arena_init(&bench_arena);
    for (int i = 0; i < NUM_RECORDS; i++) {
        dns_record_t *rec = &records[i];
        snprintf(name_pool[i], sizeof(name_pool[i]), "host%d.example.com.", i);
        rec->name = name_pool[i];
        rec->class_val = 1;
        rec->ttl_value = 3600;
        
        int r = rand() % 100;
        if (r < 40) {
            // A record
            rec->type_code = 1;
            rec->rdata[0] = "192.168.1.100";
            rec->rdata_count = 1;
        } else if (r < 80) {
            // AAAA record
            rec->type_code = 28;
            rec->rdata[0] = "2001:db8::1234:5678";
            rec->rdata_count = 1;
        } else if (r < 90) {
            // RRSIG record
            rec->type_code = 46;
            rec->rdata[0] = "A";
            rec->rdata[1] = "8"; // RSASHA256
            rec->rdata[2] = "2"; // labels
            rec->rdata[3] = "3600"; // orig_ttl
            rec->rdata[4] = "20261231235959"; // sig_exp
            rec->rdata[5] = "20260101000000"; // sig_inc
            rec->rdata[6] = "12345"; // key_tag
            rec->rdata[7] = "example.com."; // signer
            rec->rdata[8] = "YWJjZGVmZ2hpamtsbW5vcA=="; // valid base64
            rec->rdata_count = 9;
        } else if (r < 95) {
            // MX record
            rec->type_code = 15;
            rec->rdata[0] = "10";
            rec->rdata[1] = "mail.example.com.";
            rec->rdata_count = 2;
        } else if (r < 99) {
            // NS record
            rec->type_code = 2;
            rec->rdata[0] = "ns1.example.com.";
            rec->rdata_count = 1;
        } else {
            // SOA record
            rec->type_code = 6;
            rec->rdata[0] = "ns1.example.com.";
            rec->rdata[1] = "hostmaster.example.com.";
            rec->rdata[2] = "2026081801"; // serial
            rec->rdata[3] = "3600"; // refresh
            rec->rdata[4] = "1800"; // retry
            rec->rdata[5] = "604800"; // expire
            rec->rdata[6] = "86400"; // minimum
            rec->rdata_count = 7;
        }
        dns_record_preparse_cache(&bench_arena, rec);
    }
}

// Measure (a) full serialize_dns_record
uint64_t bench_full_serialize() {
    uint8_t res[8192];
    uint64_t start = get_time_ns();
    
    uint16_t offset = 12; // DNS header size
    compress_ctx_init_packet(&dummy_comp_ctx);

    for (int i = 0; i < NUM_RECORDS; i++) {
        if (offset > 6000) {
            // Simulate starting a new packet
            offset = 12;
            compress_ctx_init_packet(&dummy_comp_ctx);
        }
        int w = serialize_dns_record(res, sizeof(res), &offset, &records[i], &dummy_comp_ctx, NULL, 0xFFFFFFFF);
        if (w < 0) {
            printf("Error: serialize_dns_record failed at record %d (type %d)!\n", i, records[i].type_code);
            exit(1);
        }
    }
    
    uint64_t end = get_time_ns();
    return end - start;
}

// Dummy variables to prevent optimization of the conversion benchmark
volatile uint32_t dummy_sink = 0;

// Measure (b) only the conversion parts
uint64_t bench_conversions_only() {
    uint64_t start = get_time_ns();
    
    for (int i = 0; i < NUM_RECORDS; i++) {
        dns_record_t *rec = &records[i];
        uint32_t sink = 0;
        
        switch (rec->type_code) {
            case 1: { // A
                struct in_addr addr;
                inet_pton(AF_INET, rec->rdata[0], &addr);
                sink += addr.s_addr;
                break;
            }
            case 28: { // AAAA
                struct in6_addr addr;
                inet_pton(AF_INET6, rec->rdata[0], &addr);
                sink += addr.s6_addr[0];
                break;
            }
            case 46: { // RRSIG
                sink += atoi(rec->rdata[1]);
                sink += atoi(rec->rdata[2]);
                sink += strtoul(rec->rdata[3], NULL, 10);
                sink += bench_parse_dnssec_time(rec->rdata[4]);
                sink += bench_parse_dnssec_time(rec->rdata[5]);
                sink += atoi(rec->rdata[6]);
                uint8_t dummy_sig[1024];
                int declen = EVP_DecodeBlock(dummy_sig, (const unsigned char *)rec->rdata[8], strlen(rec->rdata[8]));
                sink += declen;
                break;
            }
            case 15: { // MX
                sink += atoi(rec->rdata[0]);
                break;
            }
            case 6: { // SOA
                for (int j = 2; j < 7; j++) {
                    sink += strtoul(rec->rdata[j], NULL, 10);
                }
                break;
            }
        }
        dummy_sink = sink;
    }
    
    uint64_t end = get_time_ns();
    return end - start;
}

int main() {
    printf("Preparing records...\n");
    srand(42); // Deterministic
    prepare_records();
    compress_ctx_init_packet(&dummy_comp_ctx);
    
    printf("Warming up...\n");
    bench_full_serialize();
    bench_conversions_only();
    
    printf("\nRunning benchmark (%d iterations)...\n", NUM_RUNS);
    
    uint64_t a_times[NUM_RUNS];
    uint64_t b_times[NUM_RUNS];
    
    for (int run = 0; run < NUM_RUNS; run++) {
        a_times[run] = bench_full_serialize();
        b_times[run] = bench_conversions_only();
    }
    
    // Simple median (sort array)
    for (int i = 0; i < NUM_RUNS - 1; i++) {
        for (int j = i + 1; j < NUM_RUNS; j++) {
            if (a_times[i] > a_times[j]) { uint64_t t = a_times[i]; a_times[i] = a_times[j]; a_times[j] = t; }
            if (b_times[i] > b_times[j]) { uint64_t t = b_times[i]; b_times[i] = b_times[j]; b_times[j] = t; }
        }
    }
    uint64_t med_a = a_times[NUM_RUNS / 2];
    uint64_t med_b = b_times[NUM_RUNS / 2];
    
    double ns_per_rec_a = (double)med_a / NUM_RECORDS;
    double ns_per_rec_b = (double)med_b / NUM_RECORDS;
    double ratio = (ns_per_rec_b / ns_per_rec_a) * 100.0;
    
    printf("\n=== Benchmark Results ===\n");
    printf("(a) Full serialize_dns_record: %.2f ns/record\n", ns_per_rec_a);
    printf("(b) Conversion only:           %.2f ns/record\n", ns_per_rec_b);
    printf("Conversion overhead ratio:     %.2f%%\n", ratio);
    
    if (ratio < 10.0) {
        printf("\nConclusion: Overhead is negligible (< 10%%).\n");
    } else if (ratio >= 20.0) {
        printf("\nConclusion: Overhead is significant (>= 20%%). Optimization recommended.\n");
    } else {
        printf("\nConclusion: Overhead is moderate (10-20%%).\n");
    }
    
    return 0;
}
