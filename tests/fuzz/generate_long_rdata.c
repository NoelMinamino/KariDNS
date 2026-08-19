#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main() {
    FILE *f = fopen("tests/fuzz/corpus/dag_long_rdata.bin", "wb");
    if (!f) return 1;

    // DNS Header
    uint8_t header[12] = {
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: Response
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x01, // NSCOUNT: 1
        0x00, 0x01  // ARCOUNT: 1
    };
    fwrite(header, 1, 12, f);

    // Question: example.com A
    uint8_t qname[] = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    fwrite(qname, 1, sizeof(qname), f);
    uint8_t qtype_class[] = {0x00, 0x01, 0x00, 0x01}; // A, IN
    fwrite(qtype_class, 1, 4, f);

    // Answer: A record with spoofed long RDATA (65 bytes)
    uint8_t ans_name[] = {0xc0, 0x0c}; // pointer to example.com
    fwrite(ans_name, 1, 2, f);
    uint8_t ans_type_class_ttl[] = {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff}; // A, IN, TTL 255
    fwrite(ans_type_class_ttl, 1, 8, f);
    uint8_t ans_rdlen[] = {0x00, 0x41}; // 65 bytes
    fwrite(ans_rdlen, 1, 2, f);
    uint8_t ans_rdata[65];
    memset(ans_rdata, 'A', 65);
    fwrite(ans_rdata, 1, 65, f);

    // Authority: NS record with spoofed long RDATA (260 bytes, longer than 255)
    fwrite(ans_name, 1, 2, f);
    uint8_t ns_type_class_ttl[] = {0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff}; // NS, IN, TTL 255
    fwrite(ns_type_class_ttl, 1, 8, f);
    uint8_t ns_rdlen[] = {0x01, 0x04}; // 260 bytes
    fwrite(ns_rdlen, 1, 2, f);
    uint8_t ns_rdata[260];
    memset(ns_rdata, 'N', 260); // invalid domain name but it is long
    fwrite(ns_rdata, 1, 260, f);
    
    // Additional: A record with spoofed long RDATA
    fwrite(ans_name, 1, 2, f);
    uint8_t ar_type_class_ttl[] = {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff}; // A, IN, TTL 255
    fwrite(ar_type_class_ttl, 1, 8, f);
    uint8_t ar_rdlen[] = {0x00, 0x41}; // 65 bytes
    fwrite(ar_rdlen, 1, 2, f);
    uint8_t ar_rdata[65];
    memset(ar_rdata, 'X', 65);
    fwrite(ar_rdata, 1, 65, f);

    fclose(f);
    return 0;
}
